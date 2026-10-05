//! Flutterwave, API v3 (the `flutterwave` feature).
//!
//! * `POST /v3/payments` (Flutterwave Standard) — `tx_ref`, `amount` in
//!   **major** units, `currency`, `redirect_url`, `customer{email,name}`,
//!   `meta`; answers `data.link`, the hosted page.
//! * `GET /v3/transactions/verify_by_reference?tx_ref=` — `data.status` is
//!   `successful` when paid; `data.id` is the transaction id refunds take.
//! * Webhooks (v3): the `verif-hash` header carries the **secret hash** set on
//!   the dashboard, verbatim. It is compared in constant time. v4 accounts sign
//!   with `flutterwave-signature` instead; this module speaks v3 only.
//! * `POST /v3/transactions/:id/refund` — optional `amount` in major units.
//!
//! Test and live are told apart by the key (`FLWSECK_TEST-…`); the host is the
//! same.

use serde_json::json;

use crate::{
    api_error, http_client, loose_string, minor_from_major, send_json, str_field, Checkout, Error,
    Money, PaymentIntent, PaymentStatus, Provider, Refund, Result, Secret, Verification,
};
#[cfg(feature = "webhook")]
use crate::{HeaderMap, WebhookEvent};

const NAME: &str = "flutterwave";

/// Flutterwave's API host.
pub const BASE_URL: &str = "https://api.flutterwave.com";

/// The v3 webhook header that carries the secret hash.
pub const HASH_HEADER: &str = "verif-hash";

/// A Flutterwave account.
#[derive(Debug, Clone)]
pub struct Flutterwave {
    secret_key: Secret,
    secret_hash: Option<Secret>,
    base_url: String,
    client: reqwest::Client,
}

impl Flutterwave {
    /// A client for the account whose secret key is `secret_key`.
    #[must_use]
    pub fn new(secret_key: impl Into<Secret>) -> Self {
        Self {
            secret_key: secret_key.into(),
            secret_hash: None,
            base_url: BASE_URL.to_owned(),
            client: http_client(),
        }
    }

    /// The webhook secret hash set on the dashboard. Without it every webhook
    /// is refused.
    #[must_use]
    pub fn with_secret_hash(mut self, secret_hash: impl Into<Secret>) -> Self {
        self.secret_hash = Some(secret_hash.into());
        self
    }

    /// Point at another host — a mock server in tests.
    #[must_use]
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into().trim_end_matches('/').to_owned();
        self
    }

    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.client
            .request(method, format!("{}{path}", self.base_url))
            .bearer_auth(self.secret_key.expose())
    }
}

fn ok(code: u16, res: &serde_json::Value) -> bool {
    (200..300).contains(&code) && res.get("status") == Some(&json!("success"))
}

fn status(word: &str) -> PaymentStatus {
    match word {
        "successful" => PaymentStatus::Succeeded,
        "failed" => PaymentStatus::Failed,
        "cancelled" => PaymentStatus::Abandoned,
        _ => PaymentStatus::Pending,
    }
}

impl Provider for Flutterwave {
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
        let mut customer = json!({ "email": intent.customer_email });
        if let Some(name) = &intent.customer_name {
            customer["name"] = json!(name);
        }
        if let Some(phone) = &intent.customer_phone {
            customer["phonenumber"] = json!(phone);
        }
        let mut body = json!({
            "tx_ref": intent.reference,
            "amount": intent.amount.major_string(),
            "currency": intent.amount.currency,
            "redirect_url": intent.callback_url,
            "customer": customer,
        });
        if !intent.metadata.is_null() {
            body["meta"] = intent.metadata.clone();
        }
        if let Some(description) = &intent.description {
            body["customizations"] = json!({ "description": description });
        }
        let request = self
            .request(reqwest::Method::POST, "/v3/payments")
            .json(&body);
        let (code, res) = send_json(NAME, request).await?;
        if !ok(code, &res) {
            return Err(api_error(NAME, code, &res));
        }
        Ok(Checkout {
            authorization_url: str_field(NAME, &res, "/data/link")?.to_owned(),
            // Flutterwave assigns its transaction id only once the payer pays.
            provider_reference: intent.reference.clone(),
        })
    }

    async fn verify(&self, reference: &str, expected: &Money) -> Result<Verification> {
        let request = self
            .request(reqwest::Method::GET, "/v3/transactions/verify_by_reference")
            .query(&[("tx_ref", reference)]);
        let (code, res) = send_json(NAME, request).await?;
        if !ok(code, &res) {
            // A reference the payer never paid against has no transaction.
            let message = res["message"].as_str().unwrap_or_default();
            if message.to_ascii_lowercase().contains("no transaction") {
                return Ok(Verification {
                    reference: reference.to_owned(),
                    status: PaymentStatus::Abandoned,
                    amount: expected.clone(),
                    paid_at: None,
                    channel: None,
                    provider_reference: None,
                    reason: Some("The payment was not completed.".into()),
                    raw: res,
                });
            }
            return Err(api_error(NAME, code, &res));
        }
        let data = &res["data"];
        if str_field(NAME, &res, "/data/tx_ref")? != reference {
            return Err(Error::Decode {
                provider: NAME,
                message: "verification answered for another reference".into(),
            });
        }
        let minor = minor_from_major(&data["amount"]).ok_or_else(|| Error::Decode {
            provider: NAME,
            message: "missing /data/amount".into(),
        })?;
        let outcome = status(str_field(NAME, &res, "/data/status")?);
        let reason = match outcome {
            PaymentStatus::Succeeded => None,
            PaymentStatus::Pending => {
                Some("The payment is still being processed by Flutterwave.".into())
            }
            PaymentStatus::Abandoned => Some("The payment was cancelled.".into()),
            PaymentStatus::Failed => data["processor_response"]
                .as_str()
                .map(str::to_owned)
                .or_else(|| Some("Flutterwave declined the payment.".into())),
        };
        Ok(Verification {
            reference: reference.to_owned(),
            status: outcome,
            amount: Money::new(minor, data["currency"].as_str().unwrap_or("NGN")),
            paid_at: data["created_at"].as_str().map(str::to_owned),
            channel: data["payment_type"].as_str().map(str::to_owned),
            provider_reference: loose_string(&res, "/data/id"),
            reason,
            raw: res,
        }
        .checked(expected))
    }

    #[cfg(feature = "webhook")]
    fn verify_webhook(&self, headers: &HeaderMap, body: &[u8]) -> Result<WebhookEvent> {
        let bad = || Error::BadSignature { provider: NAME };
        let expected = self
            .secret_hash
            .as_ref()
            .filter(|h| !h.expose().is_empty())
            .ok_or_else(bad)?;
        let given = headers
            .get(HASH_HEADER)
            .map(reqwest::header::HeaderValue::as_bytes)
            .ok_or_else(bad)?;
        if !crate::constant_time_eq(given, expected.expose().as_bytes()) {
            return Err(bad());
        }
        let raw: serde_json::Value = serde_json::from_slice(body).map_err(|e| Error::Decode {
            provider: NAME,
            message: e.to_string(),
        })?;
        Ok(WebhookEvent {
            // v3 deliveries name the event in `event`; some older ones in
            // `event.type`.
            event: raw["event"]
                .as_str()
                .or_else(|| raw["event.type"].as_str())
                .unwrap_or_default()
                .to_owned(),
            reference: str_field(NAME, &raw, "/data/tx_ref")?.to_owned(),
            provider_reference: loose_string(&raw, "/data/id"),
            raw,
        })
    }

    async fn refund(&self, provider_reference: &str, amount: Option<&Money>) -> Result<Refund> {
        let mut body = json!({});
        if let Some(amount) = amount {
            body["amount"] = json!(amount.major_string());
        }
        let request = self
            .request(
                reqwest::Method::POST,
                &format!(
                    "/v3/transactions/{}/refund",
                    crate::urlencode(provider_reference)
                ),
            )
            .json(&body);
        let (code, res) = send_json(NAME, request).await?;
        if !ok(code, &res) {
            return Err(api_error(NAME, code, &res));
        }
        Ok(Refund {
            provider_reference: loose_string(&res, "/data/id").unwrap_or_default(),
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
    use wiremock::matchers::{body_partial_json, header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    const KEY: &str = "FLWSECK_TEST-bjorst";

    fn intent() -> PaymentIntent {
        PaymentIntent {
            reference: "gk-ref-2".into(),
            amount: Money::ngn(150_050),
            customer_email: "payer@example.com".into(),
            customer_name: Some("Ada Payer".into()),
            callback_url: "https://school.example/pay/return".into(),
            ..PaymentIntent::default()
        }
    }

    async fn server_answering(status: &str, amount: serde_json::Value) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v3/transactions/verify_by_reference"))
            .and(query_param("tx_ref", "gk-ref-2"))
            .and(header("authorization", format!("Bearer {KEY}").as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "status": "success",
                "message": "Transaction fetched successfully",
                "data": {
                    "id": 288_200_108,
                    "tx_ref": "gk-ref-2",
                    "flw_ref": "FLW-MOCK-1",
                    "amount": amount,
                    "currency": "NGN",
                    "charged_amount": amount,
                    "status": status,
                    "payment_type": "card",
                    "created_at": "2026-10-05T10:00:00.000Z"
                }
            })))
            .mount(&server)
            .await;
        server
    }

    #[tokio::test]
    async fn initialize_sends_major_units_and_returns_the_link() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v3/payments"))
            .and(body_partial_json(json!({
                "tx_ref": "gk-ref-2",
                "amount": "1500.50",
                "currency": "NGN",
                "redirect_url": "https://school.example/pay/return",
                "customer": { "email": "payer@example.com", "name": "Ada Payer" }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "status": "success",
                "message": "Hosted Link",
                "data": { "link": "https://checkout.flutterwave.com/v3/hosted/pay/abc" }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let checkout = Flutterwave::new(KEY)
            .with_base_url(server.uri())
            .initialize(&intent())
            .await
            .unwrap();
        assert_eq!(
            checkout.authorization_url,
            "https://checkout.flutterwave.com/v3/hosted/pay/abc"
        );
    }

    #[tokio::test]
    async fn a_successful_transaction_verifies() {
        let server = server_answering("successful", json!(1500.5)).await;
        let v = Flutterwave::new(KEY)
            .with_base_url(server.uri())
            .verify("gk-ref-2", &Money::ngn(150_050))
            .await
            .unwrap();
        assert_eq!(v.status, PaymentStatus::Succeeded);
        assert_eq!(v.provider_reference.as_deref(), Some("288200108"));
    }

    #[tokio::test]
    async fn an_amount_mismatch_is_refused() {
        let server = server_answering("successful", json!(100)).await;
        let v = Flutterwave::new(KEY)
            .with_base_url(server.uri())
            .verify("gk-ref-2", &Money::ngn(150_050))
            .await
            .unwrap();
        assert_eq!(v.status, PaymentStatus::Failed);
    }

    #[tokio::test]
    async fn a_failed_transaction_is_failed() {
        let server = server_answering("failed", json!(1500.5)).await;
        let v = Flutterwave::new(KEY)
            .with_base_url(server.uri())
            .verify("gk-ref-2", &Money::ngn(150_050))
            .await
            .unwrap();
        assert_eq!(v.status, PaymentStatus::Failed);
    }

    #[tokio::test]
    async fn a_reference_never_paid_is_abandoned() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                "status": "error",
                "message": "No transaction was found for this id",
                "data": null
            })))
            .mount(&server)
            .await;
        let v = Flutterwave::new(KEY)
            .with_base_url(server.uri())
            .verify("gk-ref-2", &Money::ngn(150_050))
            .await
            .unwrap();
        assert_eq!(v.status, PaymentStatus::Abandoned);
    }

    #[cfg(feature = "webhook")]
    mod webhook {
        use super::*;
        use reqwest::header::HeaderValue;

        const BODY: &[u8] = br#"{"event":"charge.completed","data":{"id":285959875,"tx_ref":"gk-ref-2","status":"successful"}}"#;

        fn headers(hash: &str) -> HeaderMap {
            let mut h = HeaderMap::new();
            h.insert(HASH_HEADER, HeaderValue::from_str(hash).unwrap());
            h
        }

        fn provider() -> Flutterwave {
            Flutterwave::new(KEY).with_secret_hash("bjorst-hash")
        }

        #[test]
        fn the_right_hash_is_admitted() {
            let event = provider()
                .verify_webhook(&headers("bjorst-hash"), BODY)
                .unwrap();
            assert_eq!(event.event, "charge.completed");
            assert_eq!(event.reference, "gk-ref-2");
            assert_eq!(event.provider_reference.as_deref(), Some("285959875"));
        }

        #[test]
        fn a_wrong_hash_is_refused() {
            assert!(provider()
                .verify_webhook(&headers("bjorst-hasx"), BODY)
                .is_err());
            assert!(provider().verify_webhook(&headers("bjorst"), BODY).is_err());
        }

        #[test]
        fn no_configured_hash_refuses_everything() {
            assert!(Flutterwave::new(KEY)
                .verify_webhook(&headers(""), BODY)
                .is_err());
        }
    }
}
