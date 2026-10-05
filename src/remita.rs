//! Remita, the RRR (Remita Retrieval Reference) e-channel API (the `remita`
//! feature).
//!
//! * Generate an RRR: `POST {echannelsvc}/merchant/api/paymentinit`, header
//!   `Authorization: remitaConsumerKey=<merchantId>,remitaConsumerToken=<apiHash>`
//!   with `apiHash = SHA512(merchantId + serviceTypeId + orderId + amount + apiKey)`.
//!   The answer may come wrapped as JSONP (`jsonp ({...})`); `statuscode`
//!   `025` carries the `RRR`.
//! * Status by order id: `GET {echannelsvc}/{merchantId}/{orderId}/{hash}/orderstatus.reg`
//!   with `hash = SHA512(orderId + apiKey + merchantId)`. `status` `00` and
//!   `01` mean paid; `021` and `045` pending; `012` aborted by the payer; `02`
//!   failed.
//! * The payer pays on Remita's page:
//!   `{host}/remita/ecomm/finalize.reg?merchantId=&hash=&rrr=&responseurl=`
//!   with `hash = SHA512(merchantId + rrr + apiKey)`. **Not in Remita's current
//!   documentation** — see the README.
//! * Payment notifications are **not signed**. [`Provider::verify_webhook`]
//!   only reads the order id out of one; act on [`Provider::verify`].
//! * There is no refund API.
//!
//! The caller's reference is Remita's `orderId`. Remita settles in NGN only.

use serde_json::json;
use sha2::{Digest, Sha512};

use crate::{
    api_error, http_client, loose_string, minor_from_major, send_json, Checkout, Error, Mode,
    Money, PaymentIntent, PaymentStatus, Provider, Refund, Result, Secret, Verification,
};
#[cfg(feature = "webhook")]
use crate::{HeaderMap, WebhookEvent};

const NAME: &str = "remita";

/// The demo (test) host.
pub const DEMO_URL: &str = "https://demo.remita.net";
/// The live host.
pub const LIVE_URL: &str = "https://login.remita.net";

const ECHANNEL: &str = "/remita/exapp/api/v1/send/api/echannelsvc";

/// A Remita merchant's credentials.
#[derive(Debug, Clone)]
pub struct RemitaConfig {
    /// The merchant id.
    pub merchant_id: String,
    /// The service type (the product being paid for) on the merchant profile.
    pub service_type_id: String,
    /// The API key the hashes are made with.
    pub api_key: Secret,
    /// Demo or live host.
    pub mode: Mode,
}

/// A Remita merchant.
#[derive(Debug, Clone)]
pub struct Remita {
    config: RemitaConfig,
    base_url: String,
    client: reqwest::Client,
}

fn sha512_hex(parts: &[&str]) -> String {
    let mut hasher = Sha512::new();
    for part in parts {
        hasher.update(part.as_bytes());
    }
    hex::encode(hasher.finalize())
}

/// Remita sometimes answers `jsonp ({...})`: read the object inside.
fn unwrap_jsonp(body: serde_json::Value) -> serde_json::Value {
    let serde_json::Value::String(text) = &body else {
        return body;
    };
    match (text.find('{'), text.rfind('}')) {
        (Some(start), Some(end)) if end > start => {
            serde_json::from_str(&text[start..=end]).unwrap_or(body)
        }
        _ => body,
    }
}

impl Remita {
    /// A client for the merchant; the host follows `config.mode`.
    #[must_use]
    pub fn new(config: RemitaConfig) -> Self {
        let base_url = match config.mode {
            Mode::Test => DEMO_URL,
            Mode::Live => LIVE_URL,
        }
        .to_owned();
        Self {
            config,
            base_url,
            client: http_client(),
        }
    }

    /// Point at another host — a mock server in tests.
    #[must_use]
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into().trim_end_matches('/').to_owned();
        self
    }

    /// `apiHash` for generating an RRR.
    #[must_use]
    pub fn init_hash(&self, order_id: &str, amount: &str) -> String {
        let c = &self.config;
        sha512_hex(&[
            &c.merchant_id,
            &c.service_type_id,
            order_id,
            amount,
            c.api_key.expose(),
        ])
    }

    /// The hash a status query by `id` (an RRR or an order id) carries.
    #[must_use]
    pub fn status_hash(&self, id: &str) -> String {
        let c = &self.config;
        sha512_hex(&[id, c.api_key.expose(), &c.merchant_id])
    }

    /// The hash on the hosted payment page's URL.
    #[must_use]
    pub fn page_hash(&self, rrr: &str) -> String {
        let c = &self.config;
        sha512_hex(&[&c.merchant_id, rrr, c.api_key.expose()])
    }

    fn auth(&self, hash: &str) -> String {
        format!(
            "remitaConsumerKey={},remitaConsumerToken={hash}",
            self.config.merchant_id
        )
    }
}

fn status(code: &str) -> PaymentStatus {
    match code {
        "00" | "01" => PaymentStatus::Succeeded,
        "02" => PaymentStatus::Failed,
        "012" => PaymentStatus::Abandoned,
        _ => PaymentStatus::Pending,
    }
}

impl Provider for Remita {
    fn name(&self) -> &'static str {
        NAME
    }

    async fn initialize(&self, intent: &PaymentIntent) -> Result<Checkout> {
        if intent.amount.currency != "NGN" {
            return Err(Error::Invalid {
                provider: NAME,
                message: "Remita takes NGN only".into(),
            });
        }
        if intent.amount.minor <= 0 {
            return Err(Error::Invalid {
                provider: NAME,
                message: "amount must be positive".into(),
            });
        }
        let amount = intent.amount.major_string();
        let hash = self.init_hash(&intent.reference, &amount);
        let body = json!({
            "serviceTypeId": self.config.service_type_id,
            "amount": amount,
            "orderId": intent.reference,
            "payerName": intent.customer_name.clone().unwrap_or_default(),
            "payerEmail": intent.customer_email,
            "payerPhone": intent.customer_phone.clone().unwrap_or_default(),
            "description": intent.description.clone().unwrap_or_default(),
        });
        let request = self
            .client
            .post(format!(
                "{}{ECHANNEL}/merchant/api/paymentinit",
                self.base_url
            ))
            .header("Authorization", self.auth(&hash))
            .json(&body);
        let (code, res) = send_json(NAME, request).await?;
        let res = unwrap_jsonp(res);
        let rrr = loose_string(&res, "/RRR").filter(|r| !r.trim().is_empty());
        let (true, Some(rrr)) = ((200..300).contains(&code), rrr) else {
            let message = res["status"].as_str().unwrap_or_default().to_owned();
            return Err(Error::Api {
                provider: NAME,
                status: code,
                message: if message.is_empty() {
                    res.to_string()
                } else {
                    message
                },
            });
        };
        let rrr = rrr.trim().to_owned();
        let page = format!(
            "{}/remita/ecomm/finalize.reg?merchantId={}&hash={}&rrr={}&responseurl={}",
            self.base_url,
            crate::urlencode(&self.config.merchant_id),
            self.page_hash(&rrr),
            crate::urlencode(&rrr),
            crate::urlencode(&intent.callback_url),
        );
        Ok(Checkout {
            authorization_url: page,
            provider_reference: rrr,
        })
    }

    async fn verify(&self, reference: &str, expected: &Money) -> Result<Verification> {
        let hash = self.status_hash(reference);
        let url = format!(
            "{}{ECHANNEL}/{}/{}/{hash}/orderstatus.reg",
            self.base_url,
            crate::urlencode(&self.config.merchant_id),
            crate::urlencode(reference),
        );
        let request = self
            .client
            .get(url)
            .header("Authorization", self.auth(&hash));
        let (code, res) = send_json(NAME, request).await?;
        let res = unwrap_jsonp(res);
        if !(200..300).contains(&code) {
            return Err(api_error(NAME, code, &res));
        }
        let word = loose_string(&res, "/status").ok_or_else(|| Error::Decode {
            provider: NAME,
            message: "missing /status".into(),
        })?;
        let outcome = status(&word);
        let minor = minor_from_major(&res["amount"]).unwrap_or(0);
        let reason = match outcome {
            PaymentStatus::Succeeded => None,
            _ => Some(
                res["message"]
                    .as_str()
                    .map_or_else(|| format!("Remita status {word}."), str::to_owned),
            ),
        };
        Ok(Verification {
            reference: reference.to_owned(),
            status: outcome,
            amount: Money::ngn(minor),
            paid_at: res["paymentDate"].as_str().map(str::to_owned),
            channel: None,
            provider_reference: loose_string(&res, "/RRR"),
            reason,
            raw: res,
        }
        .checked(expected))
    }

    #[cfg(feature = "webhook")]
    fn verify_webhook(&self, _headers: &HeaderMap, body: &[u8]) -> Result<WebhookEvent> {
        // Remita does not sign notifications: nothing here proves the sender.
        // The event names an order id; `verify` asks Remita itself.
        let raw: serde_json::Value = serde_json::from_slice(body).map_err(|e| Error::Decode {
            provider: NAME,
            message: e.to_string(),
        })?;
        let first = raw
            .as_array()
            .and_then(|a| a.first())
            .unwrap_or(&raw)
            .clone();
        let reference = loose_string(&first, "/orderId")
            .or_else(|| loose_string(&first, "/orderRef"))
            .filter(|r| !r.is_empty())
            .ok_or_else(|| Error::Decode {
                provider: NAME,
                message: "notification names no orderId".into(),
            })?;
        Ok(WebhookEvent {
            event: "payment.notification".into(),
            reference,
            provider_reference: loose_string(&first, "/rrr"),
            raw,
        })
    }

    async fn refund(&self, _provider_reference: &str, _amount: Option<&Money>) -> Result<Refund> {
        Err(Error::Unsupported {
            provider: NAME,
            operation: "refund",
        })
    }
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn remita(server: &MockServer) -> Remita {
        Remita::new(RemitaConfig {
            merchant_id: "2547916".into(),
            service_type_id: "4430731".into(),
            api_key: "1946".into(),
            mode: Mode::Test,
        })
        .with_base_url(server.uri())
    }

    fn intent() -> PaymentIntent {
        PaymentIntent {
            reference: "gk-ref-3".into(),
            amount: Money::ngn(2_100_000),
            customer_email: "payer@example.com".into(),
            customer_name: Some("Ada Payer".into()),
            callback_url: "https://school.example/pay/return".into(),
            ..PaymentIntent::default()
        }
    }

    /// Known vectors, computed independently with
    /// `printf %s <merchantId><serviceTypeId><orderId><amount><apiKey> | shasum -a 512`.
    #[test]
    fn hashes_match_independent_vectors() {
        let r = Remita::new(RemitaConfig {
            merchant_id: "2547916".into(),
            service_type_id: "4430731".into(),
            api_key: "1946".into(),
            mode: Mode::Test,
        });
        assert_eq!(r.init_hash("gk-ref-3", "21000.00"), "4dc7aad11b958d42776d93f98f3e9d5662db42a8b1c01afdd2a2ca9e114035d152c678eb9507e151d0eadeaa87c847ec120398dacfaec56a07e4343956319388");
        assert_eq!(r.status_hash("gk-ref-3"), "d3ca690a43fd51120fd190c64725f698b219bcb663be6b3b5f9eedfd66674e73ac518b6a5eda9106d1840b8b7e83b0c9d1d6cfdeedb390eaaf50f7389ec15f25");
    }

    #[test]
    fn the_api_key_never_prints() {
        let r = Remita::new(RemitaConfig {
            merchant_id: "2547916".into(),
            service_type_id: "4430731".into(),
            api_key: "1946".into(),
            mode: Mode::Live,
        });
        assert!(!format!("{r:?}").contains("1946"));
    }

    #[tokio::test]
    async fn initialize_generates_an_rrr_and_the_hosted_page() {
        let server = MockServer::start().await;
        let r = remita(&server);
        let hash = r.init_hash("gk-ref-3", "21000.00");
        Mock::given(method("POST"))
            .and(path(format!("{ECHANNEL}/merchant/api/paymentinit")))
            // wiremock's `header` splits values on commas, and this one has one.
            .and(move |req: &wiremock::Request| {
                req.headers.get("authorization").and_then(|v| v.to_str().ok())
                    == Some(format!("remitaConsumerKey=2547916,remitaConsumerToken={hash}").as_str())
            })
            .and(body_partial_json(json!({
                "serviceTypeId": "4430731",
                "amount": "21000.00",
                "orderId": "gk-ref-3",
                "payerEmail": "payer@example.com"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"jsonp ({"statuscode":"025","RRR":"280007982070","status":"Payment Reference generated"})"#,
            ))
            .expect(1)
            .mount(&server)
            .await;
        let checkout = r.initialize(&intent()).await.unwrap();
        assert_eq!(checkout.provider_reference, "280007982070");
        assert!(checkout
            .authorization_url
            .contains("/remita/ecomm/finalize.reg?"));
        assert!(checkout.authorization_url.contains("rrr=280007982070"));
        assert!(!checkout.authorization_url.contains("1946"));
    }

    async fn server_answering(code: &str, amount: serde_json::Value) -> MockServer {
        let server = MockServer::start().await;
        let r = remita(&server);
        let hash = r.status_hash("gk-ref-3");
        Mock::given(method("GET"))
            .and(path(format!(
                "{ECHANNEL}/2547916/gk-ref-3/{hash}/orderstatus.reg"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "amount": amount,
                "RRR": "280007982070",
                "orderId": "gk-ref-3",
                "message": "Approved",
                "paymentDate": "2026-10-05 10:00:00 AM",
                "status": code
            })))
            .mount(&server)
            .await;
        server
    }

    #[tokio::test]
    async fn a_paid_order_verifies() {
        let server = server_answering("00", json!(21000)).await;
        let v = remita(&server)
            .verify("gk-ref-3", &Money::ngn(2_100_000))
            .await
            .unwrap();
        assert_eq!(v.status, PaymentStatus::Succeeded);
        assert_eq!(v.provider_reference.as_deref(), Some("280007982070"));
    }

    #[tokio::test]
    async fn an_amount_mismatch_is_refused() {
        let server = server_answering("01", json!(100)).await;
        let v = remita(&server)
            .verify("gk-ref-3", &Money::ngn(2_100_000))
            .await
            .unwrap();
        assert_eq!(v.status, PaymentStatus::Failed);
    }

    #[tokio::test]
    async fn pending_failed_and_aborted_are_not_succeeded() {
        for (code, want) in [
            ("021", PaymentStatus::Pending),
            ("02", PaymentStatus::Failed),
            ("012", PaymentStatus::Abandoned),
        ] {
            let server = server_answering(code, json!(21000)).await;
            let v = remita(&server)
                .verify("gk-ref-3", &Money::ngn(2_100_000))
                .await
                .unwrap();
            assert_eq!(v.status, want, "{code}");
        }
    }

    #[tokio::test]
    async fn refund_is_unsupported() {
        let server = MockServer::start().await;
        assert!(matches!(
            remita(&server).refund("280007982070", None).await,
            Err(Error::Unsupported { .. })
        ));
    }

    #[cfg(feature = "webhook")]
    #[test]
    fn a_notification_names_the_order() {
        let body = br#"[{"rrr":"280007982070","orderRef":"gk-ref-3","orderId":"gk-ref-3","amount":21000,"type":"PY"}]"#;
        let r = Remita::new(RemitaConfig {
            merchant_id: "2547916".into(),
            service_type_id: "4430731".into(),
            api_key: "1946".into(),
            mode: Mode::Test,
        });
        let event = r.verify_webhook(&HeaderMap::new(), body).unwrap();
        assert_eq!(event.reference, "gk-ref-3");
        assert_eq!(event.provider_reference.as_deref(), Some("280007982070"));
    }
}
