//! Paystack (the `paystack` feature).
//!
//! * `POST /transaction/initialize` — amount in the currency's subunit (kobo),
//!   answers `data.authorization_url`, `data.access_code`, `data.reference`.
//! * `GET /transaction/verify/:reference` — `data.status` is one of `success`,
//!   `failed`, `abandoned`, `reversed`, or an in-flight word (`ongoing`,
//!   `pending`, `processing`, `queued`).
//! * Webhooks: `x-paystack-signature` is the hex HMAC-SHA512 of the raw body,
//!   keyed with the **secret key** (there is no separate webhook secret).
//! * `POST /refund` — `transaction` (id or reference) and an optional subunit
//!   `amount`.
//!
//! Test and live are told apart by the key (`sk_test_…` / `sk_live_…`); the
//! host is the same.

use serde_json::json;

use crate::{
    api_error, http_client, loose_string, send_json, str_field, Checkout, Error, Money,
    PaymentIntent, PaymentStatus, Provider, Refund, Result, Secret, Verification,
};
#[cfg(feature = "webhook")]
use crate::{HeaderMap, WebhookEvent};

const NAME: &str = "paystack";

/// Paystack's API host.
pub const BASE_URL: &str = "https://api.paystack.co";

/// The header Paystack signs webhook deliveries in.
pub const SIGNATURE_HEADER: &str = "x-paystack-signature";

/// A Paystack account.
#[derive(Debug, Clone)]
pub struct Paystack {
    secret_key: Secret,
    base_url: String,
    client: reqwest::Client,
}

impl Paystack {
    /// A client for the account whose secret key is `secret_key`.
    #[must_use]
    pub fn new(secret_key: impl Into<Secret>) -> Self {
        Self {
            secret_key: secret_key.into(),
            base_url: BASE_URL.to_owned(),
            client: http_client(),
        }
    }

    /// Point at another host — a mock server in tests.
    #[must_use]
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into().trim_end_matches('/').to_owned();
        self
    }

    fn post(&self, path: &str) -> reqwest::RequestBuilder {
        self.client
            .post(format!("{}{path}", self.base_url))
            .bearer_auth(self.secret_key.expose())
    }

    /// The signature Paystack would put on `body`: hex HMAC-SHA512 under the
    /// secret key. For tests and for relays that re-sign.
    #[cfg(feature = "webhook")]
    #[must_use]
    pub fn sign(&self, body: &[u8]) -> String {
        use hmac::{Hmac, Mac};
        let mut mac = Hmac::<sha2::Sha512>::new_from_slice(self.secret_key.expose().as_bytes())
            .expect("HMAC takes a key of any length");
        mac.update(body);
        hex::encode(mac.finalize().into_bytes())
    }
}

/// Paystack's status word as the neutral outcome.
fn status(word: &str) -> PaymentStatus {
    match word {
        "success" => PaymentStatus::Succeeded,
        "failed" | "reversed" => PaymentStatus::Failed,
        "abandoned" => PaymentStatus::Abandoned,
        _ => PaymentStatus::Pending,
    }
}

impl Provider for Paystack {
    fn name(&self) -> &'static str {
        NAME
    }

    async fn initialize(&self, intent: &PaymentIntent) -> Result<Checkout> {
        if intent.amount.minor <= 0 {
            return Err(Error::Invalid {
                provider: NAME,
                message: "amount must be positive".into(),
            });
        }
        let mut body = json!({
            "email": intent.customer_email,
            "amount": intent.amount.minor.to_string(),
            "currency": intent.amount.currency,
            "reference": intent.reference,
            "callback_url": intent.callback_url,
        });
        if !intent.metadata.is_null() {
            // Paystack stores `metadata` as given; a string is the documented
            // form, an object is accepted and returned as an object.
            body["metadata"] = intent.metadata.clone();
        }
        let (code, res) = send_json(NAME, self.post("/transaction/initialize").json(&body)).await?;
        if !(200..300).contains(&code) || res.get("status") != Some(&json!(true)) {
            return Err(api_error(NAME, code, &res));
        }
        Ok(Checkout {
            authorization_url: str_field(NAME, &res, "/data/authorization_url")?.to_owned(),
            provider_reference: str_field(NAME, &res, "/data/access_code")?.to_owned(),
        })
    }

    async fn verify(&self, reference: &str, expected: &Money) -> Result<Verification> {
        let url = format!(
            "{}/transaction/verify/{}",
            self.base_url,
            crate::urlencode(reference)
        );
        let request = self.client.get(url).bearer_auth(self.secret_key.expose());
        let (code, res) = send_json(NAME, request).await?;
        if !(200..300).contains(&code) || res.get("status") != Some(&json!(true)) {
            return Err(api_error(NAME, code, &res));
        }
        let data = &res["data"];
        let returned = str_field(NAME, &res, "/data/reference")?;
        if returned != reference {
            return Err(Error::Decode {
                provider: NAME,
                message: "verification answered for another reference".into(),
            });
        }
        let word = str_field(NAME, &res, "/data/status")?;
        let minor = data["amount"].as_i64().ok_or_else(|| Error::Decode {
            provider: NAME,
            message: "missing /data/amount".into(),
        })?;
        let currency = data["currency"].as_str().unwrap_or("NGN");
        let outcome = status(word);
        let reason = match outcome {
            PaymentStatus::Succeeded => None,
            PaymentStatus::Pending => {
                Some("The payment is still being processed by Paystack.".into())
            }
            PaymentStatus::Abandoned => Some("The payment was not completed.".into()),
            PaymentStatus::Failed => Some(
                data["gateway_response"]
                    .as_str()
                    .map_or_else(|| "Paystack declined the payment.".into(), str::to_owned),
            ),
        };
        Ok(Verification {
            reference: reference.to_owned(),
            status: outcome,
            amount: Money::new(minor, currency),
            paid_at: data["paid_at"].as_str().map(str::to_owned),
            channel: data["channel"].as_str().map(str::to_owned),
            provider_reference: loose_string(&res, "/data/id"),
            reason,
            raw: res,
        }
        .checked(expected))
    }

    #[cfg(feature = "webhook")]
    fn verify_webhook(&self, headers: &HeaderMap, body: &[u8]) -> Result<WebhookEvent> {
        let bad = || Error::BadSignature { provider: NAME };
        let given = headers
            .get(SIGNATURE_HEADER)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(bad)?;
        let expected = self.sign(body);
        if !crate::constant_time_eq(
            given.trim().to_ascii_lowercase().as_bytes(),
            expected.as_bytes(),
        ) {
            return Err(bad());
        }
        let raw: serde_json::Value = serde_json::from_slice(body).map_err(|e| Error::Decode {
            provider: NAME,
            message: e.to_string(),
        })?;
        Ok(WebhookEvent {
            event: raw["event"].as_str().unwrap_or_default().to_owned(),
            reference: str_field(NAME, &raw, "/data/reference")?.to_owned(),
            provider_reference: loose_string(&raw, "/data/id"),
            raw,
        })
    }

    async fn refund(&self, provider_reference: &str, amount: Option<&Money>) -> Result<Refund> {
        let mut body = json!({ "transaction": provider_reference });
        if let Some(amount) = amount {
            body["amount"] = json!(amount.minor.to_string());
        }
        let (code, res) = send_json(NAME, self.post("/refund").json(&body)).await?;
        if !(200..300).contains(&code) || res.get("status") != Some(&json!(true)) {
            return Err(api_error(NAME, code, &res));
        }
        Ok(Refund {
            provider_reference: loose_string(&res, "/data/id")
                .or_else(|| loose_string(&res, "/data/transaction/id"))
                .unwrap_or_default(),
            status: res
                .pointer("/data/status")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("pending")
                .to_owned(),
            raw: res,
        })
    }
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    const KEY: &str = "sk_test_bjorst";

    fn intent() -> PaymentIntent {
        PaymentIntent {
            reference: "gk-ref-1".into(),
            amount: Money::ngn(150_000),
            customer_email: "payer@example.com".into(),
            callback_url: "https://school.example/pay/return".into(),
            metadata: json!({ "invoice": "INV-1" }),
            ..PaymentIntent::default()
        }
    }

    fn verified(status: &str, amount: i64, currency: &str) -> serde_json::Value {
        json!({
            "status": true,
            "message": "Verification successful",
            "data": {
                "id": 4_099_260_516_u64,
                "status": status,
                "reference": "gk-ref-1",
                "amount": amount,
                "currency": currency,
                "paid_at": "2026-10-05T10:00:00.000Z",
                "channel": "card",
                "gateway_response": "Successful"
            }
        })
    }

    async fn server_answering(status: &str, amount: i64, currency: &str) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/transaction/verify/gk-ref-1"))
            .and(header("authorization", format!("Bearer {KEY}").as_str()))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(verified(status, amount, currency)),
            )
            .mount(&server)
            .await;
        server
    }

    #[tokio::test]
    async fn initialize_sends_kobo_and_returns_the_hosted_page() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/transaction/initialize"))
            .and(header("authorization", format!("Bearer {KEY}").as_str()))
            .and(body_partial_json(json!({
                "email": "payer@example.com",
                "amount": "150000",
                "currency": "NGN",
                "reference": "gk-ref-1",
                "callback_url": "https://school.example/pay/return"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "status": true,
                "message": "Authorization URL created",
                "data": {
                    "authorization_url": "https://checkout.paystack.com/0peioxfhpn",
                    "access_code": "0peioxfhpn",
                    "reference": "gk-ref-1"
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let paystack = Paystack::new(KEY).with_base_url(server.uri());
        let checkout = paystack.initialize(&intent()).await.unwrap();
        assert_eq!(
            checkout.authorization_url,
            "https://checkout.paystack.com/0peioxfhpn"
        );
        assert_eq!(checkout.provider_reference, "0peioxfhpn");
    }

    #[tokio::test]
    async fn initialize_surfaces_the_providers_message() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(400).set_body_json(
                json!({ "status": false, "message": "Duplicate Transaction Reference" }),
            ))
            .mount(&server)
            .await;
        let err = Paystack::new(KEY)
            .with_base_url(server.uri())
            .initialize(&intent())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Duplicate Transaction Reference"));
        assert!(!err.to_string().contains(KEY));
    }

    #[tokio::test]
    async fn a_paid_transaction_verifies() {
        let server = server_answering("success", 150_000, "NGN").await;
        let v = Paystack::new(KEY)
            .with_base_url(server.uri())
            .verify("gk-ref-1", &Money::ngn(150_000))
            .await
            .unwrap();
        assert_eq!(v.status, PaymentStatus::Succeeded);
        assert_eq!(v.channel.as_deref(), Some("card"));
        assert_eq!(v.provider_reference.as_deref(), Some("4099260516"));
    }

    #[tokio::test]
    async fn an_amount_mismatch_is_refused() {
        let server = server_answering("success", 100, "NGN").await;
        let v = Paystack::new(KEY)
            .with_base_url(server.uri())
            .verify("gk-ref-1", &Money::ngn(150_000))
            .await
            .unwrap();
        assert_eq!(v.status, PaymentStatus::Failed);
        assert!(v.reason.is_some());
    }

    #[tokio::test]
    async fn a_failed_and_an_abandoned_transaction_are_not_succeeded() {
        for (word, want) in [
            ("failed", PaymentStatus::Failed),
            ("abandoned", PaymentStatus::Abandoned),
            ("ongoing", PaymentStatus::Pending),
            ("reversed", PaymentStatus::Failed),
        ] {
            let server = server_answering(word, 150_000, "NGN").await;
            let v = Paystack::new(KEY)
                .with_base_url(server.uri())
                .verify("gk-ref-1", &Money::ngn(150_000))
                .await
                .unwrap();
            assert_eq!(v.status, want, "{word}");
        }
    }

    #[cfg(feature = "webhook")]
    mod webhook {
        use super::*;
        use reqwest::header::HeaderValue;

        const BODY: &[u8] =
            br#"{"event":"charge.success","data":{"id":302961,"reference":"gk-ref-1","amount":150000}}"#;

        /// A known vector, computed independently:
        /// `printf '%s' "$BODY" | openssl dgst -sha512 -hmac sk_test_bjorst`.
        const VECTOR: &str = "9466b0574aa5e3c84ca00dc74af4b10234c86270950406485bfd4115b76f2e7c4ddefb2775ac797952d5e210279f20043ab7d9faf68891745ad45aefaa1c1f83";

        fn headers(signature: &str) -> HeaderMap {
            let mut h = HeaderMap::new();
            h.insert(SIGNATURE_HEADER, HeaderValue::from_str(signature).unwrap());
            h
        }

        #[test]
        fn the_signature_matches_an_independent_vector() {
            assert_eq!(Paystack::new(KEY).sign(BODY), VECTOR);
        }

        #[test]
        fn a_signed_delivery_is_admitted() {
            let event = Paystack::new(KEY)
                .verify_webhook(&headers(VECTOR), BODY)
                .unwrap();
            assert_eq!(event.event, "charge.success");
            assert_eq!(event.reference, "gk-ref-1");
            assert_eq!(event.provider_reference.as_deref(), Some("302961"));
        }

        #[test]
        fn a_tampered_body_is_refused() {
            let tampered = br#"{"event":"charge.success","data":{"id":302961,"reference":"gk-ref-1","amount":999999}}"#;
            assert!(matches!(
                Paystack::new(KEY).verify_webhook(&headers(VECTOR), tampered),
                Err(Error::BadSignature { .. })
            ));
        }

        #[test]
        fn another_keys_signature_is_refused() {
            let forged = Paystack::new("sk_test_other").sign(BODY);
            assert!(Paystack::new(KEY)
                .verify_webhook(&headers(&forged), BODY)
                .is_err());
        }

        #[test]
        fn an_unsigned_delivery_is_refused() {
            assert!(Paystack::new(KEY)
                .verify_webhook(&HeaderMap::new(), BODY)
                .is_err());
        }
    }
}
