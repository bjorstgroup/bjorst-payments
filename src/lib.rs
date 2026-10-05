//! Provider-neutral payment checkout for Bjorst services.
//!
//! One shape for every provider: a [`PaymentIntent`] goes in, a hosted
//! [`Checkout`] comes out, the payer is sent to its `authorization_url`, and on
//! their return (or on the provider's webhook) the caller asks [`Provider::verify`]
//! what actually happened. The answer is a [`Verification`] that has already
//! been held against the amount and currency the caller expected — a payment
//! for less than the bill, or in another currency, is [`PaymentStatus::Failed`]
//! with a reason, never [`PaymentStatus::Succeeded`].
//!
//! Providers, each behind its own feature:
//!
//! | Feature       | Type                             |
//! | ------------- | -------------------------------- |
//! | `paystack`    | [`paystack::Paystack`]           |
//! | `flutterwave` | [`flutterwave::Flutterwave`]     |
//! | `remita`      | [`remita::Remita`]               |
//! | `webhook`     | [`Provider::verify_webhook`]     |
//!
//! [`Gateway`] holds whichever one a deployment configured, so a caller that
//! chooses the provider at run time (per tenant, say) needs no trait objects.
//!
//! Secrets are held in [`Secret`], whose `Debug` prints `[redacted]`, and never
//! appear in an [`Error`].

// With no provider feature on, the shared plumbing has no caller yet.
#![cfg_attr(
    not(any(feature = "paystack", feature = "flutterwave", feature = "remita")),
    allow(dead_code, unused_macros)
)]

use std::fmt;
use std::future::Future;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[cfg(feature = "flutterwave")]
pub mod flutterwave;
#[cfg(feature = "paystack")]
pub mod paystack;
#[cfg(feature = "remita")]
pub mod remita;

pub use reqwest::header::HeaderMap;

// ── Money ────────────────────────────────────────────────────────────────────

/// An amount in the currency's minor unit (kobo for NGN), with its ISO 4217
/// code. Integer minor units, so no amount is ever a float.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Money {
    /// Minor units: `150_000` is NGN 1,500.00.
    pub minor: i64,
    /// Upper-case ISO 4217 code, `NGN` unless said otherwise.
    pub currency: String,
}

impl Money {
    /// An amount in `currency`'s minor unit.
    #[must_use]
    pub fn new(minor: i64, currency: &str) -> Self {
        Self {
            minor,
            currency: currency.trim().to_ascii_uppercase(),
        }
    }

    /// An amount in kobo.
    #[must_use]
    pub fn ngn(kobo: i64) -> Self {
        Self::new(kobo, "NGN")
    }

    /// The amount in major units with two decimals, `"1500.00"` — what
    /// Flutterwave and Remita take. Every currency the three providers settle
    /// in for Bjorst's markets (NGN, GHS, KES, ZAR, USD, GBP, EUR) has two
    /// decimal places.
    #[must_use]
    pub fn major_string(&self) -> String {
        let sign = if self.minor < 0 { "-" } else { "" };
        let abs = self.minor.unsigned_abs();
        format!("{sign}{}.{:02}", abs / 100, abs % 100)
    }
}

impl Default for Money {
    fn default() -> Self {
        Self::ngn(0)
    }
}

impl fmt::Display for Money {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.currency, self.major_string())
    }
}

/// A provider's major-unit amount (`1500`, `1500.5`, `"1500.00"`) in minor
/// units. Rounded to the nearest minor unit: providers send these as JSON
/// numbers, which are floats on the wire.
#[cfg(any(feature = "flutterwave", feature = "remita"))]
#[must_use]
pub(crate) fn minor_from_major(value: &serde_json::Value) -> Option<i64> {
    let major = match value {
        serde_json::Value::Number(n) => n.as_f64()?,
        serde_json::Value::String(s) => s.trim().parse::<f64>().ok()?,
        _ => return None,
    };
    if !major.is_finite() {
        return None;
    }
    // ponytail: f64 is exact to the kobo below ~NGN 90 trillion.
    #[allow(clippy::cast_possible_truncation)]
    Some((major * 100.0).round() as i64)
}

// ── Secrets ──────────────────────────────────────────────────────────────────

/// A credential. `Debug` and `Display` print `[redacted]`; read it with
/// [`Secret::expose`] at the one place it is sent.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    /// Wrap a credential.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The credential itself.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl From<&str> for Secret {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for Secret {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

/// Test (sandbox) or live credentials. Paystack and Flutterwave tell the two
/// apart by the key itself; Remita by host, so [`remita::RemitaConfig`] reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Sandbox: no real money moves.
    #[default]
    Test,
    /// Real money.
    Live,
}

// ── The neutral shapes ───────────────────────────────────────────────────────

/// What the caller wants paid.
#[derive(Debug, Clone, Default)]
pub struct PaymentIntent {
    /// The caller's own reference for this attempt. It is the idempotency key
    /// at every provider: it must be unique per attempt, and verifying it twice
    /// answers the same thing twice. 6-100 characters of `[A-Za-z0-9._=-]` is
    /// accepted by all three providers.
    pub reference: String,
    /// What to charge.
    pub amount: Money,
    /// The payer's email (Paystack requires it).
    pub customer_email: String,
    /// The payer's name.
    pub customer_name: Option<String>,
    /// The payer's phone (Remita asks for it; optional elsewhere).
    pub customer_phone: Option<String>,
    /// Free text on the provider's page and statement.
    pub description: Option<String>,
    /// Passed through to the provider's metadata field.
    pub metadata: serde_json::Value,
    /// Where the provider returns the payer after the attempt.
    pub callback_url: String,
}

/// Where to send the payer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkout {
    /// The provider's hosted payment page for this attempt.
    pub authorization_url: String,
    /// The provider's own id for the attempt (Paystack's access code,
    /// Remita's RRR); the caller's reference when the provider has none yet.
    pub provider_reference: String,
}

/// The outcome of an attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PaymentStatus {
    /// Paid, for the expected amount and currency.
    Succeeded,
    /// Declined, reversed, or paid for the wrong amount or currency.
    Failed,
    /// Still in flight at the provider; ask again later.
    Pending,
    /// The payer left without paying.
    Abandoned,
}

/// What the provider says happened, held against what was expected.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Verification {
    /// The caller's reference this answers.
    pub reference: String,
    /// The outcome. `Succeeded` only when the provider said paid **and** the
    /// amount and currency match what was expected.
    pub status: PaymentStatus,
    /// What the provider says was paid (or asked for).
    pub amount: Money,
    /// When it was paid, as the provider wrote it (ISO 8601 for Paystack and
    /// Flutterwave, Remita's own format for Remita).
    pub paid_at: Option<String>,
    /// How it was paid — `card`, `bank`, `ussd`, … as the provider names it.
    pub channel: Option<String>,
    /// The provider's id for the transaction.
    pub provider_reference: Option<String>,
    /// Why it is not `Succeeded`, in a sentence a payer can read.
    pub reason: Option<String>,
    /// The provider's response body, for the record.
    pub raw: serde_json::Value,
}

impl Verification {
    /// Hold a provider's "paid" against the expected amount: anything else is
    /// `Failed` with the reason. Every provider's `verify` ends here.
    #[must_use]
    pub(crate) fn checked(mut self, expected: &Money) -> Self {
        if self.status != PaymentStatus::Succeeded {
            return self;
        }
        if self.amount.currency != expected.currency {
            self.status = PaymentStatus::Failed;
            self.reason = Some(format!(
                "The provider reports a payment in {}, but {} was expected.",
                self.amount.currency, expected.currency
            ));
        } else if self.amount.minor != expected.minor {
            self.status = PaymentStatus::Failed;
            self.reason = Some(format!(
                "The provider reports {} paid, but {expected} was expected.",
                self.amount
            ));
        }
        self
    }
}

/// A webhook delivery whose signature (where the provider signs) checked out.
///
/// Treat it as a prompt, not as proof of payment: call [`Provider::verify`] with
/// `reference` and act on that answer, which also holds the amount against
/// the bill.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WebhookEvent {
    /// The provider's event name (`charge.success`, `charge.completed`, …).
    pub event: String,
    /// The caller's reference the event is about.
    pub reference: String,
    /// The provider's id for the transaction, when the event carries one.
    pub provider_reference: Option<String>,
    /// The parsed body.
    pub raw: serde_json::Value,
}

/// A refund the provider accepted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Refund {
    /// The provider's id for the refund.
    pub provider_reference: String,
    /// The provider's status word (`pending`, `processed`, `completed`, …).
    pub status: String,
    /// The provider's response body.
    pub raw: serde_json::Value,
}

// ── Errors ───────────────────────────────────────────────────────────────────

/// Why a call failed. Never carries a credential.
#[derive(Debug, Error)]
pub enum Error {
    /// The HTTP request itself failed (DNS, connection, TLS, timeout).
    #[error("{provider}: request failed: {source}")]
    Request {
        /// Which provider.
        provider: &'static str,
        /// The transport error (reqwest strips no headers from its message,
        /// but it never prints them either).
        #[source]
        source: reqwest::Error,
    },
    /// The provider answered with an error.
    #[error("{provider}: API returned {status}: {message}")]
    Api {
        /// Which provider.
        provider: &'static str,
        /// The HTTP status.
        status: u16,
        /// The provider's own message, or the body.
        message: String,
    },
    /// The provider's answer could not be read.
    #[error("{provider}: unexpected response: {message}")]
    Decode {
        /// Which provider.
        provider: &'static str,
        /// What was missing or malformed.
        message: String,
    },
    /// The intent is not one this provider can take.
    #[error("{provider}: {message}")]
    Invalid {
        /// Which provider.
        provider: &'static str,
        /// What is wrong with it.
        message: String,
    },
    /// The webhook delivery's signature is absent or does not verify.
    #[error("{provider}: webhook signature missing or invalid")]
    BadSignature {
        /// Which provider.
        provider: &'static str,
    },
    /// The provider does not offer this operation.
    #[error("{provider}: {operation} is not supported")]
    Unsupported {
        /// Which provider.
        provider: &'static str,
        /// What was asked.
        operation: &'static str,
    },
}

/// The result type of this crate.
pub type Result<T> = std::result::Result<T, Error>;

// ── The trait ────────────────────────────────────────────────────────────────

/// One payment provider.
pub trait Provider {
    /// `paystack`, `flutterwave` or `remita`.
    fn name(&self) -> &'static str;

    /// Open a hosted checkout for `intent`.
    fn initialize(&self, intent: &PaymentIntent) -> impl Future<Output = Result<Checkout>> + Send;

    /// Ask the provider what happened to `reference`, and hold the answer
    /// against `expected`.
    fn verify(
        &self,
        reference: &str,
        expected: &Money,
    ) -> impl Future<Output = Result<Verification>> + Send;

    /// Check a webhook delivery's signature over the **raw** body and read the
    /// reference out of it.
    ///
    /// # Errors
    ///
    /// [`Error::BadSignature`] when the provider's signature is absent or wrong.
    #[cfg(feature = "webhook")]
    fn verify_webhook(&self, headers: &HeaderMap, body: &[u8]) -> Result<WebhookEvent>;

    /// Refund a transaction in full (`amount: None`) or in part.
    /// `provider_reference` is [`Verification::provider_reference`].
    fn refund(
        &self,
        provider_reference: &str,
        amount: Option<&Money>,
    ) -> impl Future<Output = Result<Refund>> + Send;
}

/// Whichever provider a deployment configured, chosen at run time.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Gateway {
    /// Paystack.
    #[cfg(feature = "paystack")]
    Paystack(paystack::Paystack),
    /// Flutterwave.
    #[cfg(feature = "flutterwave")]
    Flutterwave(flutterwave::Flutterwave),
    /// Remita.
    #[cfg(feature = "remita")]
    Remita(remita::Remita),
}

/// Forward a call to whichever provider the gateway holds.
macro_rules! each {
    ($self:ident, $p:ident => $call:expr) => {
        match $self {
            #[cfg(feature = "paystack")]
            Gateway::Paystack($p) => $call,
            #[cfg(feature = "flutterwave")]
            Gateway::Flutterwave($p) => $call,
            #[cfg(feature = "remita")]
            Gateway::Remita($p) => $call,
        }
    };
}

#[cfg(any(feature = "paystack", feature = "flutterwave", feature = "remita"))]
impl Provider for Gateway {
    fn name(&self) -> &'static str {
        each!(self, p => p.name())
    }

    async fn initialize(&self, intent: &PaymentIntent) -> Result<Checkout> {
        each!(self, p => p.initialize(intent).await)
    }

    async fn verify(&self, reference: &str, expected: &Money) -> Result<Verification> {
        each!(self, p => p.verify(reference, expected).await)
    }

    #[cfg(feature = "webhook")]
    fn verify_webhook(&self, headers: &HeaderMap, body: &[u8]) -> Result<WebhookEvent> {
        each!(self, p => p.verify_webhook(headers, body))
    }

    async fn refund(&self, provider_reference: &str, amount: Option<&Money>) -> Result<Refund> {
        each!(self, p => p.refund(provider_reference, amount).await)
    }
}

// ── Shared plumbing ──────────────────────────────────────────────────────────

/// One HTTP client per provider value; `reqwest::Client` is a cheap handle.
pub(crate) fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_default()
}

/// Send, and read the body as JSON whatever the status — every provider puts
/// its error message in the body.
pub(crate) async fn send_json(
    provider: &'static str,
    request: reqwest::RequestBuilder,
) -> Result<(u16, serde_json::Value)> {
    let response = request
        .send()
        .await
        .map_err(|source| Error::Request { provider, source })?;
    let status = response.status().as_u16();
    let text = response
        .text()
        .await
        .map_err(|source| Error::Request { provider, source })?;
    let body = serde_json::from_str(&text).unwrap_or(serde_json::Value::String(text));
    Ok((status, body))
}

/// The provider's error sentence, out of its usual `message` field.
pub(crate) fn api_error(provider: &'static str, status: u16, body: &serde_json::Value) -> Error {
    let message = body
        .get("message")
        .and_then(serde_json::Value::as_str)
        .map_or_else(|| body.to_string(), str::to_owned);
    Error::Api {
        provider,
        status,
        message,
    }
}

/// A string field, or a decode error naming it.
#[cfg(any(feature = "paystack", feature = "flutterwave"))]
pub(crate) fn str_field<'a>(
    provider: &'static str,
    value: &'a serde_json::Value,
    pointer: &str,
) -> Result<&'a str> {
    value
        .pointer(pointer)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| Error::Decode {
            provider,
            message: format!("missing {pointer}"),
        })
}

/// A field as a string whether the provider sent a string or a number.
pub(crate) fn loose_string(value: &serde_json::Value, pointer: &str) -> Option<String> {
    match value.pointer(pointer)? {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Percent-encode a path segment. References are documented as
/// `[A-Za-z0-9._=-]`, so this only matters for a caller who strays.
pub(crate) fn urlencode(segment: &str) -> String {
    segment
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// Constant-time equality of two byte strings.
#[cfg(all(feature = "webhook", any(feature = "paystack", feature = "flutterwave")))]
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn major_string_has_two_decimals() {
        assert_eq!(Money::ngn(150_000).major_string(), "1500.00");
        assert_eq!(Money::ngn(5).major_string(), "0.05");
        assert_eq!(Money::ngn(-250).major_string(), "-2.50");
    }

    #[test]
    fn currency_is_normalised() {
        assert_eq!(Money::new(1, " ngn ").currency, "NGN");
    }

    #[cfg(any(feature = "flutterwave", feature = "remita"))]
    #[test]
    fn minor_from_major_reads_numbers_and_strings() {
        assert_eq!(minor_from_major(&serde_json::json!(1500)), Some(150_000));
        assert_eq!(minor_from_major(&serde_json::json!(19.99)), Some(1_999));
        assert_eq!(
            minor_from_major(&serde_json::json!("1500.50")),
            Some(150_050)
        );
        assert_eq!(minor_from_major(&serde_json::json!(null)), None);
    }

    #[test]
    fn secret_never_prints() {
        let s = Secret::new("sk_live_abc");
        assert_eq!(format!("{s:?} {s}"), "[redacted] [redacted]");
    }

    fn paid(minor: i64, currency: &str) -> Verification {
        Verification {
            reference: "ref".into(),
            status: PaymentStatus::Succeeded,
            amount: Money::new(minor, currency),
            paid_at: None,
            channel: None,
            provider_reference: None,
            reason: None,
            raw: serde_json::Value::Null,
        }
    }

    #[test]
    fn a_matching_payment_stays_succeeded() {
        let v = paid(100, "NGN").checked(&Money::ngn(100));
        assert_eq!(v.status, PaymentStatus::Succeeded);
    }

    #[test]
    fn a_short_payment_is_failed_with_a_reason() {
        let v = paid(99, "NGN").checked(&Money::ngn(100));
        assert_eq!(v.status, PaymentStatus::Failed);
        assert!(v.reason.unwrap().contains("NGN 1.00 was expected"));
    }

    #[test]
    fn a_payment_in_another_currency_is_failed() {
        let v = paid(100, "USD").checked(&Money::ngn(100));
        assert_eq!(v.status, PaymentStatus::Failed);
    }
}
