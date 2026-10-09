# bjorst-payments

Provider-neutral payment checkout shared across Bjorst services, with
integrations for **Paystack**, **Flutterwave** (API v3) and **Remita** (RRR).

One shape for every provider: a `PaymentIntent` goes in, a hosted `Checkout`
comes out, the payer is sent to its `authorization_url`, and on their return —
or when the provider's webhook arrives — the caller asks `verify` what actually
happened. The answer has already been held against the amount and currency
the caller expected: a payment for less than the bill, or in another currency,
is `Failed` with a reason, never `Succeeded`.

Choosing a provider, storing keys and recording the outcome stay in the caller;
this crate only owns the conversation with the provider.

## Features

| Feature       | Adds                                                        |
| ------------- | ----------------------------------------------------------- |
| `paystack`    | `paystack::Paystack`                                        |
| `flutterwave` | `flutterwave::Flutterwave`                                  |
| `remita`      | `remita::Remita`                                            |
| `webhook`     | `Provider::verify_webhook` for every enabled provider       |

No feature is on by default. `Gateway` is an enum over the enabled providers,
so a service that picks the provider per tenant at run time needs no trait
objects.

## Usage

```rust,no_run
use bjorst_payments::{paystack::Paystack, Gateway, Money, PaymentIntent, PaymentStatus, Provider};

async fn pay() -> bjorst_payments::Result<()> {
    let gateway = Gateway::Paystack(Paystack::new("sk_test_…"));
    let expected = Money::ngn(150_000); // NGN 1,500.00, in kobo

    let checkout = gateway
        .initialize(&PaymentIntent {
            reference: "inv-42-attempt-1".into(),
            amount: expected.clone(),
            customer_email: "payer@example.com".into(),
            callback_url: "https://app.example/pay/return".into(),
            ..Default::default()
        })
        .await?;
    // Redirect the payer to checkout.authorization_url …

    // … and when they come back (or the webhook arrives):
    let v = gateway.verify("inv-42-attempt-1", &expected).await?;
    if v.status == PaymentStatus::Succeeded {
        // settle the bill — once; key it on the reference
    }
    Ok(())
}
```

## The neutral API

| Item                                | Behaviour                                                                 |
| ----------------------------------- | ------------------------------------------------------------------------- |
| `Money { minor, currency }`         | Integer minor units (kobo), ISO code; `Money::ngn(kobo)`.                 |
| `PaymentIntent`                     | reference, amount, customer email/name/phone, description, metadata, callback URL. |
| `initialize(&intent)`               | `Checkout { authorization_url, provider_reference }`.                     |
| `verify(reference, &expected)`      | `Verification { status, amount, paid_at, channel, provider_reference, reason, raw }`. |
| `verify_webhook(&headers, body)`    | `WebhookEvent { event, reference, provider_reference, raw }` (feature `webhook`). |
| `refund(provider_reference, amount)`| Paystack and Flutterwave; Remita answers `Error::Unsupported`.            |
| `Secret`                            | Wraps every credential; `Debug`/`Display` print `[redacted]`.             |

`PaymentStatus` is `Succeeded`, `Failed`, `Pending` or `Abandoned`.

**A webhook is a prompt, not proof.** `verify_webhook` checks the provider's
signature where there is one and reads the reference out of the delivery; act
on `verify(reference, &expected)`, which asks the provider directly and checks
the amount. Remita's notifications are not signed at all, so for Remita this is
the only safe order.

**References are the idempotency key.** Use a fresh reference per attempt
(each provider refuses a reused one at initialize), store it before redirecting,
and make "settle the bill" idempotent on it: the payer's return and the webhook
will race, and both will verify `Succeeded`.

## Configuration per provider

| Provider    | Constructor                                                        | Test vs live |
| ----------- | ------------------------------------------------------------------ | ------------ |
| Paystack    | `Paystack::new(secret_key)`                                        | The key: `sk_test_…` / `sk_live_…`. One host, `https://api.paystack.co`. |
| Flutterwave | `Flutterwave::new(secret_key).with_secret_hash(hash)`              | The key: `FLWSECK_TEST-…` / `FLWSECK-…`. One host, `https://api.flutterwave.com`. |
| Remita      | `Remita::new(RemitaConfig { merchant_id, service_type_id, api_key, mode })` | `Mode::Test` → `https://demo.remita.net`, `Mode::Live` → `https://login.remita.net`. |

Every provider has `.with_base_url(url)` for pointing at a mock server.

## Webhook setup

| Provider    | Register                         | How a delivery is checked |
| ----------- | -------------------------------- | ------------------------- |
| Paystack    | Dashboard → Settings → API Keys & Webhooks → Webhook URL | `x-paystack-signature` = hex HMAC-SHA512 of the **raw** body under the secret key, compared in constant time. Deliveries come from `52.31.139.75`, `52.49.173.169`, `52.214.14.220`. |
| Flutterwave | Dashboard → Settings → Webhooks: URL and a **secret hash** you choose | v3: the `verif-hash` header equals the secret hash, compared in constant time. |
| Remita      | Merchant profile → notification URL | Not signed. Read the order id, then `verify`. Remita expects the text `Ok` back. |

Pass the body **byte for byte as received** — re-serialised JSON will not
match Paystack's signature.

## Test-mode keys

- **Paystack:** test secret key from the dashboard (`sk_test_…`); test cards on the
  Paystack test-payments page.
- **Flutterwave:** test keys from the dashboard in test mode (`FLWSECK_TEST-…`).
- **Remita:** demo credentials come from Remita on registration. The long-quoted
  public demo profile (merchant `2547916`, service type `4430731`, key `1946`)
  appears in the unit tests as a fixture but is **no longer in Remita's
  documentation**; do not assume it still works.

## Sources

Checked on 2026-10-05.

- Paystack — transactions: <https://docs-v2.paystack.com/docs/api/transaction/>,
  verify: <https://docs-v2.paystack.com/docs/payments/verify-payments/>,
  webhooks: <https://docs-v2.paystack.com/docs/payments/webhooks/>,
  refunds: <https://docs-v2.paystack.com/docs/api/refund/>
  (`paystack.com/docs` sits behind a bot challenge; `docs-v2` is Paystack's own mirror).
- Flutterwave v3 — Standard: <https://developer.flutterwave.com/v3.0.0/docs/flutterwave-standard-1>,
  verify by reference: <https://developer.flutterwave.com/v3.0.0/reference/verify-transaction-with-tx_ref>,
  webhooks: <https://developer.flutterwave.com/v3.0.0/docs/webhooks>,
  refunds: <https://developer.flutterwave.com/reference/transaction-refund>,
  v4 webhooks (for contrast): <https://developer.flutterwave.com/v4.0/docs/webhooks>.
- Remita — official API collection: <https://api.remita.net/> (section "Invoice
  Generation": RRR generation, status by RRR and by order id, payment
  notification); live host as used in Remita's own plugin:
  <https://github.com/RemitaNet/remita-woocommerce>.

## Where the documentation is ambiguous

These are stated rather than guessed. Each is a place to look first if a live
integration misbehaves.

1. **Paystack transaction statuses.** The API reference lists `success`,
   `failed`, `abandoned`; the verify guide adds `ongoing`, `pending`,
   `processing`, `queued`, `reversed`. This crate treats only `success` as paid,
   `failed`/`reversed` as failed, `abandoned` as abandoned, everything else as
   pending.
2. **Paystack `metadata`.** Documented as "stringified JSON", sent as an object
   in the examples. This crate sends what the caller gives it.
3. **Paystack signature input.** The sample code signs `JSON.stringify(req.body)`;
   this crate signs the raw body, which is what Paystack sends.
4. **Flutterwave statuses.** Only `successful` is documented on verify; this crate
   maps `failed` → failed, `cancelled` → abandoned, anything else → pending, and
   a "No transaction was found" answer → abandoned.
5. **Flutterwave `amount`.** Examples send a string; verify returns a number.
   This crate sends `"1500.50"` and reads either.
6. **Flutterwave v3 vs v4.** v4 signs webhooks with `flutterwave-signature`
   (HMAC-SHA256, base64) and uses OAuth. An account runs one version at a time;
   this crate speaks v3. v3 is, per Flutterwave, not scheduled for deprecation.
7. **Remita hosted page.** `/remita/ecomm/finalize.reg` (merchantId, rrr,
   responseurl, hash = SHA512(merchantId + rrr + apiKey)) is used by Remita's
   integrations but is no longer in the current docs, which show only the inline
   JS widget and a newer "connect-gateway" charge API. This crate builds the
   finalize URL as a GET; **confirm it against a Remita demo profile before
   going live.**
8. **Remita hosts.** The collection mixes `demo.remita.net` and `remitademo.net`
   for the demo; the live host `login.remita.net` is taken from Remita's own
   plugin, not the API reference.
9. **Remita status `01`.** "Successful" in the status endpoint's notes,
   "ACTIVATED" in one status table. This crate treats `00` and `01` as paid, as
   the endpoint's notes say.
10. **Remita amount format.** Examples send whole naira (`"21000"`); this crate
    sends two decimals (`"21000.00"`) and hashes the same string it sends.

## Tests

`cargo test --all-features` — every provider against a local mock HTTP server
(`wiremock`), no network: request shape, response parsing, signature checks
against independently computed vectors, tampered bodies refused, amount and
currency mismatches refused.

## License

MIT

## Paystack subscriptions

Create the plan once in the dashboard (Products → Plans; one per currency). Then:

- `PaymentIntent { plan: Some("PLN_…".into()), .. }` starts the plan on the first payment. Paystack charges the plan's own amount; `amount` is still what `verify` holds that first charge against. Later charges arrive as `charge.success` webhooks.
- Subscription webhooks (`subscription.create`, `subscription.disable`, `subscription.not_renew`, `invoice.payment_failed`) carry no transaction reference: `WebhookEvent::reference` is empty and the details are in `raw`.
- `Paystack::subscription(code)`, `disable_subscription(code, email_token)` and `manage_link(code)` read, stop and hand the payer a page to update their card.
