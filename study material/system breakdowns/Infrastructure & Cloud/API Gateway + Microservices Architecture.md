# API Gateway + Microservices Architecture — Internal Engineering & Security Document

**Classification:** Internal Engineering Reference  
**Audience:** All Engineers (Beginner to Senior), Security Engineers, Platform Architects  
**Scope:** Complete breakdown of a production API Gateway sitting in front of multiple microservices — covering every layer from DNS to database and back  
**System Topology:** Client → CDN → API Gateway (Kong/AWS API GW/nginx) → Service Mesh (Istio/Envoy) → Microservices → Databases

---

## A Beginner's Orientation

**What is a monolith vs. microservices?**

A monolith is one large application — everything (user management, orders, payments, notifications) lives in one codebase and one deployable unit. Simple to start, but as the team and codebase grow, it becomes hard to deploy, scale specific parts, or let different teams work independently.

Microservices splits that monolith into many small, independently deployable services. Each service owns its own data, runs its own process, and communicates over a network. The user-service only handles users; the order-service only handles orders.

**What is an API Gateway?**

The API Gateway is the single entry point that all external clients talk to. Instead of clients knowing about 20 different microservice addresses, they only know one: `api.example.com`. The gateway:
- Authenticates requests (validates JWTs)
- Routes requests to the right microservice
- Rate limits abusive callers
- Logs everything
- Can transform requests/responses

Think of it as the front desk receptionist of a large office building. You don't wander into every department yourself — you check in at the front desk, they verify your ID, and they route you to the right department.

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

### The Scenario

Alice uses an e-commerce mobile app to place an order. The app talks to an API Gateway that sits in front of: a User Service, an Order Service, an Inventory Service, a Payment Service, and a Notification Service.

**Request:** `POST https://api.example.com/v1/orders`  
**What it does:** Creates a new order, validates inventory, charges Alice's saved card, and sends a confirmation email.

---

### Phase 1: Before the Request Leaves Alice's Phone

Alice taps "Place Order" in the mobile app. The app has:
- A valid JWT access token (issued 5 minutes ago, expires in 15 minutes)
- The order payload: item IDs, quantities, shipping address

```javascript
// What the mobile app does:
const response = await fetch('https://api.example.com/v1/orders', {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${accessToken}`,
    'Content-Type': 'application/json',
    'X-Request-ID': uuidv4(),           // Unique ID for this request
    'X-App-Version': '3.2.1',
    'X-Device-ID': deviceFingerprint
  },
  body: JSON.stringify({
    items: [{sku: 'PROD-123', qty: 2}, {sku: 'PROD-456', qty: 1}],
    shippingAddress: {...},
    paymentMethodId: 'pm_saved_card_abc'
  })
});
```

**What Alice sees:** A loading spinner. Maybe "Processing your order..."

---

### Phase 2: Request Travels Through the Network (T+0ms to T+~100ms)

- **T+0ms:** DNS lookup for `api.example.com` → returns CDN edge IP
- **T+30ms:** TCP + TLS handshake with CDN (or reuses existing connection from the keep-alive pool)
- **T+60ms:** HTTP/2 request received at CDN edge
- **T+70ms:** CDN determines this is an API request (non-cacheable POST) → forwards to origin API Gateway
- **T+80ms:** API Gateway receives the request

---

### Phase 3: API Gateway Processing (T+80ms to T+~150ms)

The API Gateway runs multiple plugins/middleware in sequence:

**Step 1 — Request ID attachment:** Gateway reads the `X-Request-ID` from the app. If missing, generates one. Attaches it to all downstream calls. This is the thread connecting all log lines for this request.

**Step 2 — Rate limiting check (T+81ms):** Gateway checks Redis: "How many requests has this user (from the JWT sub) made in the last minute?" If under limit, increments counter. If over limit: immediate 429 response.

**Step 3 — JWT validation (T+82ms):**
```
Extract Bearer token from Authorization header
base64url-decode the header → {"alg": "RS256", "kid": "key-2024-01"}
Fetch public key from JWKS cache (keyed by kid)
RSA-verify the signature
Check: exp > now, aud matches "api.example.com", iss = "https://auth.example.com"
Extract claims: sub = "user_alice_123", roles = ["customer"]
Attach to request context
```

**Step 4 — Route matching (T+83ms):** `POST /v1/orders` → routes to the Order Service cluster. The gateway rewrites the upstream URL: `http://order-service.internal:8080/orders`

**Step 5 — Request transformation (T+83ms):**
- Strip the `Authorization` header (don't forward the user's JWT to internal services — use internal service identity instead)
- Add internal headers: `X-User-ID: user_alice_123`, `X-User-Roles: customer`, `X-Forwarded-For`, `X-Correlation-ID`
- The internal services trust these headers ONLY because they come from the gateway (internal network trust)

---

### Phase 4: Order Service Processing (T+150ms to T+~400ms)

The Order Service receives the request and orchestrates:

**T+150ms — Order validation:**
- Parse and validate the request body (schema validation)
- Check that item SKUs exist and are valid

**T+170ms — Inventory check (synchronous gRPC call to Inventory Service):**
```
Order Service → Inventory Service:
  CheckInventory({items: [{sku: "PROD-123", qty: 2}, {sku: "PROD-456", qty: 1}]})
Response: {available: true, reservedUntil: 1700000300}
```

**T+190ms — Payment processing (synchronous gRPC call to Payment Service):**
```
Order Service → Payment Service:
  ChargeCard({
    userId: "user_alice_123",
    paymentMethodId: "pm_saved_card_abc",
    amountCents: 4997,
    currency: "USD",
    idempotencyKey: "order-request-uuid-abc123"
  })
Response: {chargeId: "ch_xyz789", status: "succeeded"}
```

**T+250ms — Write order to database:**
```sql
BEGIN;
INSERT INTO orders (id, user_id, status, total_cents, charge_id, ...)
VALUES ('ord_abc123', 'user_alice_123', 'confirmed', 4997, 'ch_xyz789', ...);

INSERT INTO order_items (order_id, sku, quantity, price_cents)
VALUES ('ord_abc123', 'PROD-123', 2, 1999), ('ord_abc123', 'PROD-456', 1, 999);
COMMIT;
```

**T+280ms — Async event published:**
```
Order Service → Kafka topic "order.created":
  {orderId: "ord_abc123", userId: "user_alice_123", ...}

This is fire-and-forget. The Notification Service will consume this
asynchronously and send Alice a confirmation email.
The Order Service does NOT wait for the email to be sent.
```

**T+290ms — Response returned:**
```json
{
  "orderId": "ord_abc123",
  "status": "confirmed",
  "estimatedDelivery": "2024-11-20",
  "total": {"amount": 49.97, "currency": "USD"}
}
```

---

### Phase 5: Response Returns to Alice (T+290ms to T+~400ms)

```
Order Service → API Gateway (T+290ms)
API Gateway:
  - Log the response code and duration
  - Add response headers: X-Request-ID, X-RateLimit-Remaining
  - Forward to CDN edge
CDN → Alice's phone (T+350ms)
```

**What Alice sees:** "Order placed! Order #ord_abc123 confirmed. You'll receive an email shortly."

**What happened after Alice saw the confirmation (async):**
- Notification Service consumed the Kafka event
- Notification Service called SendGrid API to send the email
- Inventory Service committed the reservation (removing stock from available pool)
- Analytics pipeline consumed the event to update sales dashboards
- Fraud detection service analyzed the order asynchronously

**Total time Alice waited: ~350-400ms**

---

## 2. Network Layer Flow

### DNS Resolution

When the mobile app first contacts `api.example.com`:

```
Mobile App
   |
   | DNS Query: "api.example.com → what IP?"
   v
Device's configured DNS resolver (e.g., 8.8.8.8 or ISP DNS)
   |
   | If cache miss:
   v
Recursive Resolution Process:
  1. Ask root nameserver: "Who handles .com?"
     Answer: "Ask g.gtld-servers.net (Verisign TLD server)"
  2. Ask .com TLD server: "Who handles example.com?"
     Answer: "Ask ns1.example.com (your authoritative NS)"
  3. Ask ns1.example.com: "What's the A/AAAA record for api.example.com?"
     Answer: "152.195.19.97" (a Cloudflare anycast IP)
     TTL: 300 seconds

DNS record types relevant here:
  api.example.com.  300  IN  A     152.195.19.97   (IPv4)
  api.example.com.  300  IN  AAAA  2606:4700::6810 (IPv6)
  api.example.com.  300  IN  CNAME api.cdn.cloudflare.net (if using CNAME flattening)
```

**Why anycast for the CDN IP?** The same IP (152.195.19.97) is advertised from data centers in New York, London, Singapore, etc. BGP routing automatically sends Alice's DNS query to the nearest Cloudflare edge. A user in Sydney resolves to the same IP as a user in London, but they connect to different physical servers — both get low latency.

**DNSSEC:** If enabled, the answer includes RRSIG records (cryptographic signatures). The resolver validates the chain: root's signature → .com TLD signature → example.com's signature. An attacker who poisons the DNS cache with a false IP would need to forge these signatures, which requires the zone's private key. DNSSEC makes cache poisoning effectively impossible.

---

### TCP 3-Way Handshake

The mobile app opens a TCP connection to port 443 of the resolved IP:

```
Mobile App (10.0.1.15:54321)           Cloudflare Edge (152.195.19.97:443)
           |                                        |
           |  SYN [seq=1000]                        |
           |  MSS=1360 (mobile typically uses       |
           |  smaller MSS to avoid fragmentation)   |
           |--------------------------------------->|
           |                                        |
           |  SYN-ACK [seq=5000, ack=1001]          |
           |<---------------------------------------|
           |                                        |
           |  ACK [ack=5001]                        |
           |--------------------------------------->|
           |  [Connection open — 1 RTT elapsed]     |
           |  [TLS handshake begins immediately]    |
```

**HTTP/2 connection multiplexing:** For subsequent requests (within the same app session), the mobile app reuses this same TCP connection. HTTP/2 multiplexes multiple streams over it — if Alice browses products and then places an order, these two requests can share one connection, each as a separate HTTP/2 stream.

**QUIC / HTTP/3:** Modern mobile apps increasingly use QUIC (the transport for HTTP/3). QUIC runs over UDP, combines TCP's reliability guarantees with TLS's security in a single round-trip. No separate TCP handshake + TLS handshake — connection establishment takes 0-1 RTT. Especially beneficial on mobile where network switches (WiFi → cellular) would reset TCP connections; QUIC connections survive through Connection IDs.

---

### TLS 1.3 Handshake

```
Mobile App                                    Cloudflare Edge (CDN)
     |                                              |
     | ClientHello                                  |
     | - version: TLS 1.3                           |
     | - random: 32 random bytes (client nonce)     |
     | - cipher_suites:                             |
     |     TLS_AES_256_GCM_SHA384                   |
     |     TLS_AES_128_GCM_SHA256                   |
     |     TLS_CHACHA20_POLY1305_SHA256             |
     | - key_share: X25519 ephemeral pub key (32B)  |
     | - SNI extension: "api.example.com"           |
     |   (tells server which cert to present)       |
     | - ALPN: ["h2", "h3", "http/1.1"]            |
     |   (preferred HTTP versions)                  |
     |--------------------------------------------->|
     |                                              |
     | ServerHello                                  |
     | - cipher: TLS_AES_256_GCM_SHA384            |
     | - key_share: server's X25519 ephemeral key  |
     |                                              |
     | {EncryptedExtensions}                        |
     | - ALPN selected: "h2"                        |
     |                                              |
     | {Certificate}                                |
     | - Leaf: api.example.com                      |
     |   (issued by DigiCert or Let's Encrypt)      |
     | - Intermediate CA cert                       |
     | - OCSP staple (revocation proof)             |
     | - SCTs from 2+ CT logs                       |
     |   (Certificate Transparency proof)           |
     |                                              |
     | {CertificateVerify}                          |
     | - Signature over handshake using cert privkey|
     |                                              |
     | {Finished}                                   |
     |<---------------------------------------------|
     |                                              |
     | [App validates certificate chain]            |
     | [Both sides derive same session keys         |
     |  using HKDF on the ECDH shared secret]       |
     |                                              |
     | {Finished}                                   |
     | [Application data flows — HTTP/2 requests]  |
     |--------------------------------------------->|
```

**Certificate pinning in mobile apps:**

Production mobile apps implement certificate pinning. The app has the expected certificate hash (or CA public key hash) hardcoded:

```java
// Android TrustKit / OkHttp CertificatePinner
CertificatePinner pinner = new CertificatePinner.Builder()
    .add("api.example.com",
         "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",  // leaf cert hash
         "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=")  // backup/intermediate
    .build();
```

If the TLS handshake presents a certificate whose public key hash doesn't match, the connection is terminated immediately. This defeats MITM attacks even if the attacker has a certificate signed by a trusted CA (e.g., corporate proxies with root CA installed on devices, or a compromised/coerced CA).

**The "internal" TLS leg:** Between Cloudflare and the origin API Gateway, there's also TLS. Cloudflare can be configured in "Full (Strict)" mode, which means it validates the origin's certificate. Without this, Cloudflare → origin might be plain HTTP or TLS with an unvalidated cert — a MITM opportunity.

---

### Full Network Flow Diagram

```
ALICE'S PHONE             CDN (Cloudflare)         API GATEWAY           MICROSERVICES
      |                         |                        |                     |
 DNS: api.example.com           |                        |                     |
 →[anycast route]→ CDN IP       |                        |                     |
      |                         |                        |                     |
 TCP SYN ─────────────────────> |                        |                     |
 TCP SYN-ACK <───────────────── |                        |                     |
 TCP ACK ─────────────────────> |                        |                     |
      |                         |                        |                     |
 TLS ClientHello ──────────────>|                        |                     |
 TLS ServerHello+Cert+Fin <─────|                        |                     |
 TLS Finished ─────────────────>|                        |                     |
      |    [Encrypted channel]   |                        |                     |
      |                         |                        |                     |
 POST /v1/orders ──────────────>|                        |                     |
 {Authorization,                |                        |                     |
  X-Request-ID,                 |   TLS (Full Strict)    |                     |
  body: {items,...}}            |──────────────────────→ |                     |
      |                         |                        | Rate limit check     |
      |                         |                        | (Redis INCR+TTL)    |
      |                         |                        | JWT validate        |
      |                         |                        | Route match         |
      |                         |                        | Header rewrite      |
      |                         |                        |                     |
      |                         |      mTLS (service mesh)| gRPC               |
      |                         |                        |──Inventory Check──> |
      |                         |                        |<── Available ─────  |
      |                         |                        |                     |
      |                         |                        |──Payment Charge───> |
      |                         |                        |<── Succeeded ─────  |
      |                         |                        |                     |
      |                         |                        |──DB Write (Postgres)──→
      |                         |                        |<── OK ──────────────
      |                         |                        |                     |
      |                         |                        |──Kafka publish ────>|
      |                         |                        |   (order.created)   |
      |                         |                        |                     |
      |                         | 201 {orderId, status}  |                     |
      |<────────────────────────|<──────────────────────  |                     |
 [Order confirmed!]             |                        |                     |
      |                         |                        |  [Async consumers]  |
      |                         |                        |  Notification Svc   |
      |                         |                        |  → SendGrid email   |
      |                         |                        |  Analytics Svc      |
      |                         |                        |  → Update dashboards|
```

### Latency Budget

| Phase | Time | Component |
|---|---|---|
| DNS resolution (cold) | 20–80ms | Device → recursive resolver → NS chain |
| DNS (warm cache) | 0ms | Device DNS cache hit |
| TCP handshake (CDN) | 1× RTT | ~30ms to nearest CDN PoP |
| TLS 1.3 handshake | 1× RTT | ~30ms additional |
| CDN → Origin API GW | 10–40ms | Cloudflare → your data center |
| API Gateway processing | 5–20ms | Rate limit, JWT, route match |
| Order Service gRPC to Inventory | 5–15ms | Internal gRPC call |
| Order Service gRPC to Payment | 50–200ms | External payment API call |
| Database write | 5–30ms | PostgreSQL INSERT + commit |
| **Total** | **~160–500ms** | End-to-end for Alice |

---

## 3. Application Layer Flow

### The API Gateway as an HTTP Reverse Proxy

The API Gateway is fundamentally an HTTP reverse proxy with additional intelligence. Let's trace what Kong (a popular open-source API gateway) does with the incoming request.

**Incoming request at the gateway:**

```http
POST /v1/orders HTTP/2
Host: api.example.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleS0yMDI0LTAxIn0.eyJzdWIiOiJ1c2VyX2FsaWNlXzEyMyJ9.SIGNATURE
Content-Type: application/json
Accept: application/json
X-Request-ID: 550e8400-e29b-41d4-a716-446655440000
X-App-Version: 3.2.1
X-Device-ID: sha256-device-fingerprint-hash
Content-Length: 247

{"items":[{"sku":"PROD-123","qty":2},{"sku":"PROD-456","qty":1}],"shippingAddress":{"street":"123 Main St","city":"Springfield","zip":"12345"},"paymentMethodId":"pm_saved_card_abc"}
```

**Gateway plugin execution order (Kong uses a priority-based plugin chain):**

```
Phase 1: access (runs before proxying)
  Priority 2000: bot-detection plugin
  Priority 1100: jwt plugin (validates JWT, extracts claims)
  Priority 1000: rate-limiting plugin
  Priority  900: cors plugin
  Priority  800: request-size-limiting plugin
  Priority  700: ip-restriction plugin
  Priority  600: key-auth plugin (if API key auth used)
  Priority  500: acl plugin (checks consumer groups)

Phase 2: rewrite (modifies the request)
  Priority 1000: request-transformer plugin
    - Strips Authorization header
    - Adds X-Consumer-ID: user_alice_123
    - Adds X-Consumer-Groups: customer
    - Adds X-Forwarded-Host: api.example.com

Phase 3: proxy (sends request upstream)
  Sends modified request to selected upstream target

Phase 4: response (runs after receiving upstream response)
  Priority 1000: response-transformer plugin
  Priority  900: rate-limiting (updates headers)

Phase 5: log (runs after response sent to client)
  Priority 1000: file-log plugin (writes access log)
  Priority  900: datadog-plugin (sends metrics)
  Priority  800: http-log plugin (sends to logging aggregator)
```

**What the gateway sends to the Order Service:**

```http
POST /orders HTTP/1.1
Host: order-service.internal:8080
Content-Type: application/json
X-Request-ID: 550e8400-e29b-41d4-a716-446655440000
X-Consumer-ID: user_alice_123
X-Consumer-Groups: customer
X-Forwarded-For: 10.0.1.15
X-Forwarded-Host: api.example.com
X-Forwarded-Proto: https
X-Real-IP: 10.0.1.15
Content-Length: 247

{"items":[{"sku":"PROD-123","qty":2},...],"paymentMethodId":"pm_saved_card_abc"}
```

Note: The `Authorization: Bearer` header was STRIPPED by the gateway. The Order Service does NOT receive Alice's JWT. Instead, it receives `X-Consumer-ID` which the Order Service trusts because it can only be set by the API gateway on the internal network.

---

### HTTP Methods and Their Semantics in a Microservices Context

```
Method  | Safe? | Idempotent? | Use case at API Gateway
--------|-------|-------------|--------------------------------
GET     | Yes   | Yes         | Read resources; cacheable at CDN/gateway
POST    | No    | No          | Create; NOT cacheable; requires idempotency keys
PUT     | No    | Yes         | Replace resource; idempotent if same payload
PATCH   | No    | No          | Partial update; NOT idempotent by default
DELETE  | No    | Yes         | Delete; second delete = 404 but same outcome
OPTIONS | Yes   | Yes         | CORS preflight; handled by gateway, not microservice
HEAD    | Yes   | Yes         | Like GET but no body; for cache checking
```

**Idempotency at the gateway level:**

```javascript
// Mobile app generates idempotency key ONCE per intent
// Stored persistently on device for this order
const idempotencyKey = await getOrCreateOrderKey(cart);
// On first creation: idempotencyKey = uuid-v4
// On retry: same idempotencyKey

// Sent as header:
'Idempotency-Key': idempotencyKey

// Gateway passes to Order Service:
'Idempotency-Key': idempotencyKey

// Order Service checks Redis:
const existing = await redis.get(`idem:${idempotencyKey}`);
if (existing) return existing; // Return cached response, don't process again

// On first processing: store result in Redis for 24 hours
await redis.setex(`idem:${idempotencyKey}`, 86400, JSON.stringify(response));
```

---

### Response Construction at the Gateway

When the Order Service returns a successful response, the gateway:

1. **Receives the upstream response:**
   ```http
   HTTP/1.1 201 Created
   Content-Type: application/json
   X-Order-ID: ord_abc123
   X-Service-Version: order-service/2.3.1
   
   {"orderId":"ord_abc123","status":"confirmed",...}
   ```

2. **Applies response transformer plugin:**
   - Removes internal headers: `X-Service-Version` (don't expose internal version info)
   - Adds: `X-Request-ID: 550e8400-...` (for client-side correlation)
   - Adds: `X-RateLimit-Limit: 100`, `X-RateLimit-Remaining: 87`
   - Adds: `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`

3. **Constructs final response to client:**
   ```http
   HTTP/2 201 Created
   Content-Type: application/json
   X-Request-ID: 550e8400-e29b-41d4-a716-446655440000
   X-RateLimit-Limit: 100
   X-RateLimit-Remaining: 87
   X-RateLimit-Reset: 1700000060
   Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
   X-Content-Type-Options: nosniff
   Cache-Control: no-store
   
   {"orderId":"ord_abc123","status":"confirmed","estimatedDelivery":"2024-11-20"}
   ```

---

## 4. Backend Architecture

### The Complete Service Map

```
                     ┌─────────────────────────────────────────────────────────┐
                     │              EXTERNAL ZONE                              │
                     │  Mobile App, Web App, Third-Party Partners              │
                     └──────────────────────┬──────────────────────────────────┘
                                            │ HTTPS
                     ┌──────────────────────▼──────────────────────────────────┐
                     │              CDN LAYER (Cloudflare)                     │
                     │  TLS termination, DDoS, WAF, static asset cache         │
                     └──────────────────────┬──────────────────────────────────┘
                                            │ HTTPS (Full Strict TLS)
                     ┌──────────────────────▼──────────────────────────────────┐
                     │           API GATEWAY CLUSTER (Kong / AWS API GW)       │
                     │  Auth │ Rate Limiting │ Routing │ Logging │ Transform   │
                     │  Multiple instances, AWS ALB in front                   │
                     └──┬─────────┬─────────┬───────────────┬──────────────────┘
                        │         │         │               │ mTLS (Istio service mesh)
          ┌─────────────▼─┐  ┌────▼────┐  ┌▼─────────┐  ┌─▼──────────┐
          │  User Service  │  │ Order   │  │Inventory │  │ Payment    │
          │  Port: 8080   │  │ Service │  │ Service  │  │ Service    │
          │  Go           │  │ Node.js │  │ Java     │  │ Python     │
          └───────┬────────┘  └────┬────┘  └────┬─────┘  └─────┬──────┘
                  │               │             │               │
          ┌───────▼───┐    ┌──────▼──┐   ┌─────▼─────┐  ┌──────▼──────┐
          │ Users DB  │    │Orders DB│   │Inventory  │  │Payment Vault│
          │ PostgreSQL│    │ Postgres│   │   DB      │  │  (Stripe    │
          │ (primary  │    │ + Redis │   │  MySQL    │  │   API +     │
          │ +replicas)│    │ (cache) │   │  + Redis  │  │  Secrets    │
          └───────────┘    └─────────┘   └───────────┘  │  Manager)  │
                                                          └────────────┘
                               │
          ┌────────────────────▼─────────────────────────────────────────────┐
          │                   KAFKA MESSAGE BUS                              │
          │  Topics: order.created, order.cancelled, payment.success, ...   │
          └────┬──────────────────┬──────────────────────┬───────────────────┘
               │                  │                      │
          ┌────▼────┐        ┌────▼────────┐       ┌────▼────────────┐
          │Notifica-│        │  Analytics  │       │ Fraud Detection │
          │tion Svc │        │  Pipeline   │       │   Service       │
          │(email/  │        │(ClickHouse/ │       │  (ML model,     │
          │ SMS/    │        │ Snowflake)  │       │  async scoring) │
          │ push)   │        └─────────────┘       └─────────────────┘
          └─────────┘
```

---

### Service Communication Patterns

**Synchronous communication (gRPC over service mesh):**

Why gRPC between microservices?
- Strong typing (Protocol Buffers define the schema)
- HTTP/2 multiplexing
- Efficient binary serialization (smaller payloads than JSON)
- Bidirectional streaming support
- Auto-generated client/server code from .proto definitions

```protobuf
// inventory.proto
syntax = "proto3";

service InventoryService {
  rpc CheckAndReserve(ReserveRequest) returns (ReserveResponse);
  rpc Release(ReleaseRequest) returns (ReleaseResponse);
}

message ReserveRequest {
  string request_id = 1;
  repeated ItemRequest items = 2;
  int32 hold_seconds = 3;  // How long to hold reservation
}

message ItemRequest {
  string sku = 1;
  int32 quantity = 2;
}

message ReserveResponse {
  bool success = 1;
  string reservation_id = 2;  // Use this to commit or release
  string failure_reason = 3;  // If success=false
}
```

**Asynchronous communication (Kafka events):**

When Order Service publishes `order.created`:

```json
{
  "eventId": "evt_abc123",
  "eventType": "order.created",
  "eventVersion": "1.0",
  "timestamp": "2024-11-15T10:30:45.123Z",
  "source": "order-service",
  "data": {
    "orderId": "ord_abc123",
    "userId": "user_alice_123",
    "items": [{"sku": "PROD-123", "qty": 2}, {"sku": "PROD-456", "qty": 1}],
    "totalCents": 4997,
    "currency": "USD"
  },
  "metadata": {
    "correlationId": "550e8400-e29b-41d4-a716-446655440000",
    "schemaVersion": "v1.0"
  }
}
```

Each downstream service subscribes to this topic independently:
- Notification Service: sends email confirmation
- Analytics Service: updates revenue metrics
- Fraud Service: retroactively scores the order
- Warehouse Service: triggers pick-and-pack workflow

The Order Service doesn't know about any of these consumers. Adding a new consumer (e.g., a loyalty points service) requires zero changes to the Order Service.

---

### Database Interactions Per Service

**Each service has its own database (Database-per-Service pattern):**

```
User Service        → PostgreSQL users DB
Order Service       → PostgreSQL orders DB + Redis cache
Inventory Service   → MySQL inventory DB + Redis reservation cache
Payment Service     → No DB of its own (delegates to Stripe) + Secrets Manager
Notification Service → PostgreSQL notification log DB
```

**Why separate databases?**
- Services can be deployed and scaled independently
- Schema changes in one service don't affect others
- Service teams own their own data model
- Different services can use different DB technologies optimized for their access patterns

**The cross-service data challenge:**

When you need to display an order with product details (from Inventory Service) and user details (from User Service):

```
Option 1: API Composition (at the gateway or BFF layer)
  GET /v1/orders/ord_abc123
  Gateway makes parallel calls:
    → Order Service: GET order data
    → User Service: GET user display name
    → Inventory Service: GET product details
  Gateway merges results and returns

Option 2: Event-driven denormalization
  When order is created: Order Service stores a snapshot of user/product data
  Order table contains: user_name, product_names, etc. (denormalized)
  Tradeoff: data can become stale if user/product changes
  Benefit: no cross-service reads at query time

Option 3: CQRS (Command Query Responsibility Segregation)
  A separate "read model" database that aggregates data from multiple services
  Updated via events
  Optimized for complex queries across service boundaries
```

---

### Caching Architecture

```
Cache Layer 1: CDN (Cloudflare Cache)
  - Cache public GET responses (product catalog, static data)
  - Key: URL + Accept-Language header
  - TTL: 5 minutes for product data
  - NOT used for authenticated requests (vary by auth token → no cache)

Cache Layer 2: API Gateway Cache
  - Kong's response caching plugin
  - Cache safe (GET) responses that are public
  - Not used for POST/PUT/DELETE
  - Strategy: Cache-Control headers from upstream dictate TTL

Cache Layer 3: Service-level Redis Cache
  Order Service Redis:
    - key: "order:{orderId}" → serialized order object, TTL=3600s
    - key: "user_orders:{userId}:{page}" → paginated list, TTL=300s
    - key: "idem:{idempotencyKey}" → response cache, TTL=86400s

  Inventory Service Redis:
    - key: "stock:{sku}" → current stock count, TTL=10s (short — inventory changes fast)
    - key: "reservation:{reservationId}" → expiring reservation, TTL=hold_seconds

Cache Layer 4: Application-level in-process cache
  - JWT JWKS public keys: Cached in memory, refreshed every 1 hour
  - Service routing tables: Local copy, refreshed from service registry
  - Feature flags: Local copy from LaunchDarkly/etc., refreshed every 30s
```

---

## 5. Authentication & Authorization Flow

### The Complete Auth Stack

```
Layer 1: CDN (Cloudflare)
  - Bot score (Cloudflare's bot detection score)
  - IP reputation check (known abusive IPs)
  - WAF rules (SQL injection, XSS patterns)
  - DDoS protection
  - Passes X-Forwarded-For, X-Cloudflare-Bot-Score to origin

Layer 2: API Gateway (Kong)
  - JWT validation (signature, expiry, claims)
  - Rate limiting (per user, per API key, per IP)
  - API key validation (for third-party partners)
  - CORS enforcement
  - Consumer-to-route authorization (ACL plugin)

Layer 3: Service Mesh (Istio/Envoy)
  - mTLS between all services (transport-level auth)
  - Service identity (SPIFFE/SPIRE: each service has a cryptographic identity)
  - Network policies (Order Service can only talk to allowed services)
  - Request-level authorization policies

Layer 4: Application Level (each microservice)
  - Business logic authorization
  - "Can this user access this specific resource?"
  - "Can Order Service A call endpoint B of Inventory Service?"
```

---

### JWT Deep Dive — What's Actually in the Token

Alice's JWT payload (after RS256 decoding):

```json
{
  "sub": "user_alice_123",
  "iss": "https://auth.example.com",
  "aud": ["api.example.com"],
  "iat": 1700000000,
  "exp": 1700000900,
  "jti": "unique-token-id-for-revocation",
  "email": "alice@example.com",
  "roles": ["customer"],
  "tenantId": "tenant_retail_main",
  "subscriptionTier": "premium",
  "deviceId": "device_abc123",
  "scope": "orders:write orders:read profile:read"
}
```

**The `scope` field is critical for fine-grained access:**

```
"scope": "orders:write orders:read profile:read"

Gateway checks:
  Route: POST /v1/orders → requires scope: "orders:write"
  Token has "orders:write" → ALLOWED

  Route: DELETE /v1/admin/users → requires scope: "admin:write"
  Token does NOT have "admin:write" → 403 FORBIDDEN (at gateway level)
```

**JWKS endpoint for key rotation:**

```
GET https://auth.example.com/.well-known/jwks.json

Response:
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "key-2024-01",      // Key ID — matches JWT header's kid
      "n": "base64url-modulus",  // RSA public key modulus
      "e": "AQAB"               // RSA public exponent (65537)
    },
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "key-2024-02",      // New key (for rotation)
      "n": "base64url-modulus-2",
      "e": "AQAB"
    }
  ]
}
```

API Gateway caches this response and uses the `kid` from each JWT header to look up the right public key. During key rotation, both old and new keys are in the JWKS — tokens signed by either key are accepted for a transition period.

---

### Service-to-Service Authentication (mTLS + SPIFFE)

Within the service mesh, services don't use JWTs. They use **mTLS with SPIFFE certificates**.

**SPIFFE (Secure Production Identity Framework For Everyone):**

Each service gets a unique SPIFFE ID:
```
spiffe://cluster.local/ns/production/sa/order-service
spiffe://cluster.local/ns/production/sa/inventory-service
spiffe://cluster.local/ns/production/sa/payment-service
```

These IDs are embedded in X.509 certificates issued by the SPIRE server. When Order Service calls Inventory Service:
- Order Service presents its certificate with SPIFFE ID `order-service`
- Inventory Service validates the certificate
- Istio Authorization Policy says: "ALLOW requests from `order-service` to endpoint `/CheckInventory`"
- Istio DENIES unauthorized cross-service calls even if they're on the internal network

**Why this matters:** If a service is compromised or an attacker gains access to the internal network, they can't freely call any service. Each service only accepts calls from explicitly authorized peers.

---

### Authorization Policies (OPA/Rego)

Open Policy Agent (OPA) can be integrated with the API Gateway or service mesh to enforce complex authorization rules:

```rego
# policy.rego
package orders

# Default deny
default allow = false

# Allow users to read their own orders
allow {
  input.method == "GET"
  input.path[0] == "orders"
  input.path[1] == input.user.sub  # orderId must match userId context
  "orders:read" in input.user.scopes
}

# Allow users to create orders
allow {
  input.method == "POST"
  input.path[0] == "orders"
  "orders:write" in input.user.scopes
  input.user.roles[_] == "customer"
  not is_suspended(input.user.sub)  # Check account status
}

# Admins can access any order
allow {
  input.user.roles[_] == "admin"
  "admin:*" in input.user.scopes
}

# Helper: check if account is suspended
is_suspended(userId) {
  suspended_accounts[userId]  # Loaded from policy data bundle
}
```

---

### Trust Boundaries

```
ZONE 1: External/Public (Zero Trust)
  - Mobile app, web browser, third-party API clients
  - NEVER trusted for anything
  - Must present valid JWT or API key to every request
  - Rate limited aggressively

ZONE 2: CDN/Edge (Low Trust)
  - Cloudflare sits here
  - Trust: Receives untrusted client requests
  - We trust Cloudflare's DDoS mitigation and WAF
  - Origin validates that requests come from Cloudflare IPs
  - Secret: Cloudflare Origin Certificate + IP allowlisting

ZONE 3: API Gateway (Medium Trust)
  - Has been validated by CDN
  - Runs authentication and authorization
  - Sets trusted headers (X-Consumer-ID) for downstream
  - Downstream services MUST trust these headers ONLY from this zone's IPs

ZONE 4: Service Mesh (High Trust)
  - All traffic between services is mTLS-encrypted
  - Service identities cryptographically verified
  - Authorization policies enforced at Envoy proxy level
  - Still: services should validate inputs — defense in depth

ZONE 5: Data Layer (Highest Trust, Most Restricted)
  - Databases only reachable from their owning service
  - No other service can directly read another service's DB
  - Credentials from Secrets Manager, rotated automatically
  - Audit logging on all privileged operations
```

---

## 6. Data Flow

### Request Data Transformation Pipeline

```
Alice's Phone
  │
  │ Sends: JSON body + JWT (raw bytes, TLS encrypted)
  │
  ▼
CDN Edge
  │ TLS decrypt / re-encrypt
  │ Adds: X-Cloudflare-Bot-Score: 30, X-Real-IP: <alice's IP>
  │
  ▼
API Gateway
  │ Parse JWT: base64url-decode → verify RS256 signature → extract claims
  │ Rate limit: check Redis counter
  │ Transform request:
  │   - REMOVE Authorization header (strip JWT)
  │   - ADD X-Consumer-ID: user_alice_123
  │   - ADD X-Consumer-Groups: customer
  │   - ADD X-Correlation-ID: 550e8400-...
  │   - ADD X-Request-Start-Time: 1700000000.123
  │ Forward to Order Service (upstream)
  │
  ▼
Order Service (Node.js)
  │ Parse: JSON.parse(requestBody)
  │ Validate: Joi/Zod schema validation
  │   - items: array, non-empty
  │   - each item: {sku: string, qty: positive integer}
  │   - shippingAddress: all required fields present
  │   - paymentMethodId: matches "pm_" prefix pattern
  │ Enrich: Add computed fields (tax, calculated total)
  │ Transform for DB: camelCase → snake_case
  │
  ▼
PostgreSQL
  │ Stores: order_items with individual prices, status = 'pending'
  │ Returns: Auto-generated order ID and created_at timestamp
  │
  ▼
Order Service builds response
  │ Transform DB result: snake_case → camelCase
  │ Remove internal fields: charge_reference_id, etc.
  │ Add computed fields: estimatedDelivery based on shipping tier
  │ JSON.stringify()
  │
  ▼
API Gateway
  │ Receive upstream response
  │ Remove internal headers (X-Service-Version, X-Internal-*)
  │ Add response headers (X-Request-ID, X-RateLimit-*)
  │ Forward to CDN
  │
  ▼
CDN
  │ Check Cache-Control: no-store → do not cache
  │ Forward to Alice
  │
  ▼
Alice's Phone
  │ TLS decrypt → HTTP/2 frames → JSON response body
  │ JSON.parse() → render order confirmation UI
```

---

### Serialization Formats by Layer

| Layer | Wire Format | Why |
|---|---|---|
| Client ↔ API Gateway | JSON over HTTPS/HTTP2 | Human readable, universal support |
| Gateway ↔ Services | JSON over HTTP/1.1 (if REST) | Simple, widely supported |
| Service ↔ Service | Protobuf over gRPC/HTTP2 | Compact, typed, fast serialization |
| Service ↔ Kafka | Avro with Schema Registry | Schema evolution, compact binary |
| Service ↔ PostgreSQL | PostgreSQL wire protocol (binary) | Typed, efficient |
| Service ↔ Redis | RESP (Redis Serialization Protocol) | Simple key-value commands |
| Audit logs | JSON lines | Structured, greppable, ingestible |
| Metrics | OpenMetrics (Prometheus format) | Pull-based scraping by Prometheus |
| Traces | OpenTelemetry (OTLP/Protobuf) | Distributed tracing standard |

---

### Schema Evolution and Backward Compatibility

When a microservice team changes their API, they must not break existing consumers:

**API versioning at the gateway:**
```
/v1/orders → routes to order-service v1.x pods
/v2/orders → routes to order-service v2.x pods
```

Both versions run simultaneously during migration. The gateway routes based on the URL prefix or `Accept: application/vnd.api.v2+json` header.

**Protobuf backward compatibility rules:**
```protobuf
// Adding fields is safe (new clients can use them, old clients ignore them)
message Order {
  string order_id = 1;       // Field 1 — never remove or reuse
  string user_id = 2;        // Field 2 — stable
  int32 total_cents = 3;     // Field 3 — stable
  string promo_code = 4;     // Field 4 — newly added, optional
}

// NEVER do:
// - Remove a field (old clients may still send it)
// - Change a field type (breaks serialization)
// - Reuse a field number (misinterpretation of old data)
```

**Kafka message schema evolution (Avro with Schema Registry):**
```json
// Schema v1:
{
  "type": "record",
  "name": "OrderCreated",
  "fields": [
    {"name": "orderId", "type": "string"},
    {"name": "userId", "type": "string"},
    {"name": "totalCents", "type": "int"}
  ]
}

// Schema v2 (added optional field — backward compatible):
{
  "type": "record",
  "name": "OrderCreated",
  "fields": [
    {"name": "orderId", "type": "string"},
    {"name": "userId", "type": "string"},
    {"name": "totalCents", "type": "int"},
    {"name": "currency", "type": ["null", "string"], "default": null}  // Optional
  ]
}
```

---

## 7. Security Controls

### Network-Level Security

**CDN WAF Rules (Cloudflare example):**
```
Rule 1: Block requests with SQL injection patterns in URL/body
  - Pattern: SELECT.*FROM, UNION.*SELECT, INSERT.*INTO, etc.
  - Action: Block (return 403)

Rule 2: Block requests from known bad IP ranges
  - Source: Cloudflare threat intelligence + custom blocklist
  - Action: Block

Rule 3: Rate limit by country
  - If X-Forwarded-Country in HIGH_RISK_COUNTRIES and request is to /auth/*
  - Action: Challenge (CAPTCHA or JS challenge)

Rule 4: Block oversized request bodies
  - If Content-Length > 1MB
  - Action: Block (return 413)
  - Exception: /v1/uploads/* endpoints

Rule 5: Block suspicious user agents
  - If User-Agent contains known scanner fingerprints
  - Action: Log + Challenge
```

**API Gateway mTLS from CDN:**
```
The API Gateway only accepts TLS connections where the client certificate
is Cloudflare's Origin CA certificate.

nginx config:
  ssl_client_certificate /etc/nginx/cloudflare_origin_ca.crt;
  ssl_verify_client on;
  # Any connection not presenting Cloudflare's cert is rejected
  # This means if an attacker bypasses Cloudflare and tries to hit
  # the origin directly with a random IP, they'll get a TLS error
```

---

### Input Validation at the Service Level

```javascript
// Order Service: Zod schema validation
const CreateOrderSchema = z.object({
  items: z.array(z.object({
    sku: z.string()
      .min(1).max(50)
      .regex(/^[A-Z0-9\-]+$/, 'SKU must be uppercase alphanumeric'),
    qty: z.number()
      .int('Quantity must be a whole number')
      .min(1, 'Minimum quantity is 1')
      .max(100, 'Maximum 100 items per SKU')
  })).min(1, 'Order must have at least one item').max(50, 'Maximum 50 distinct SKUs'),

  shippingAddress: z.object({
    street: z.string().min(1).max(200),
    city: z.string().min(1).max(100),
    state: z.string().length(2).regex(/^[A-Z]{2}$/),
    zip: z.string().regex(/^\d{5}(-\d{4})?$/, 'Invalid ZIP code'),
    country: z.enum(['US', 'CA', 'GB', 'AU'])  // Explicit allowlist
  }),

  paymentMethodId: z.string()
    .regex(/^pm_[a-zA-Z0-9]+$/, 'Invalid payment method ID format')
    .max(100),

  notes: z.string().max(500).optional()
    .transform(s => s?.trim().replace(/[<>]/g, ''))  // Basic sanitization
});

// Usage:
const parseResult = CreateOrderSchema.safeParse(req.body);
if (!parseResult.success) {
  return res.status(400).json({
    error: 'Validation Error',
    details: parseResult.error.issues.map(i => ({
      path: i.path.join('.'),
      message: i.message
    }))
  });
}
const validatedData = parseResult.data;
```

---

### Secrets Management

```
Secret Lifecycle in Microservices:

1. Developer never has access to production secrets
   (Least privilege: only CI/CD pipeline and pods have access)

2. Secrets stored in AWS Secrets Manager or HashiCorp Vault

3. Each service has a specific IAM role with narrow permissions:
   order-service-role → can read:
     prod/order-service/postgres-password
     prod/order-service/stripe-webhook-secret
   order-service-role → CANNOT read:
     prod/payment-service/stripe-api-key  (different service's secret)

4. Secrets injected at pod startup via Kubernetes External Secrets:
   apiVersion: external-secrets.io/v1beta1
   kind: ExternalSecret
   spec:
     secretStoreRef:
       name: aws-secretsmanager
     target:
       name: order-service-secrets
     data:
     - secretKey: POSTGRES_PASSWORD
       remoteRef:
         key: prod/order-service/postgres-password
   # This creates a Kubernetes Secret that is mounted as env var
   # The actual value never appears in code, config, or git

5. Automatic rotation:
   AWS Secrets Manager rotates DB passwords every 90 days
   The rotation Lambda updates both Secrets Manager AND the DB user's password
   Services pick up the new secret on the next pod restart or via hot-reload

6. Audit: every secret access is logged in CloudTrail
   Who accessed what secret, when, from which role
```

---

### Encryption Controls

**At rest:**
```
PostgreSQL:
  - EBS volume encrypted with AWS KMS (AES-256)
  - Application-level encryption for PII columns:
    phone_number = AES_GCM_ENCRYPT(raw_phone, KMS_DATA_KEY)
    The KMS data key itself is encrypted with a KMS master key
    (Envelope encryption pattern)

Redis (ElastiCache):
  - Encryption at rest enabled (AES-256)
  - Session data and cache contain user context — must be protected

S3 (for event archives, exports):
  - SSE-KMS with customer-managed key
  - Bucket policy: deny any requests without HTTPS (deny:aws:SecureTransport false)
```

**In transit:**
```
External:
  - TLS 1.3 only between clients and CDN
  - TLS 1.2+ between CDN and API Gateway (strict mode)

Internal service mesh:
  - Istio mTLS: STRICT mode (all traffic between pods is mTLS)
  - No plaintext HTTP between services allowed
  - Certificate rotation every 24 hours (Istio handles automatically)

Database connections:
  - SSL required on PostgreSQL connections (ssl_mode=verify-full)
  - Redis TLS connections
  - All DB credentials over TLS to Secrets Manager API

Kafka:
  - TLS encryption between producers/consumers and brokers
  - SASL/SCRAM authentication for producer/consumer auth
```

---

## 8. Attack Surface Mapping

### All Entry Points

```
EXTERNAL ENTRY POINTS (Internet-accessible):
─────────────────────────────────────────────
[E1] Public API Endpoints (via CDN → API Gateway)
  GET/POST/PUT/DELETE /v1/*
  Threats: Auth bypass, injection, brute force, data exfil

[E2] Authentication Endpoints
  POST /v1/auth/login
  POST /v1/auth/refresh
  POST /v1/auth/register
  Threats: Credential stuffing, account enumeration, token forgery

[E3] Webhook Endpoints
  POST /v1/webhooks/stripe    (payment events)
  POST /v1/webhooks/github    (if CI/CD uses webhooks)
  Threats: Forged webhooks, webhook replay, spoofing

[E4] Partner API (if applicable)
  Uses API keys instead of JWTs
  Threats: API key theft, key rotation failures

[E5] Admin Console (if web-accessible)
  Should be VPN-only, but sometimes exposed
  Threats: Admin credential theft, privilege escalation

INTERNAL ENTRY POINTS:
─────────────────────────────────────────────
[I1] Service-to-Service APIs (via service mesh)
  Order Service → Inventory Service gRPC
  Order Service → Payment Service gRPC
  Threats: Service impersonation if mTLS misconfigured, SSRF

[I2] Kafka (message bus)
  Services publish and consume messages
  Threats: Message injection, unauthorized consumption, topic poisoning

[I3] Database endpoints
  Only reachable from owning service's pods
  Threats: SQL injection, connection credential theft

[I4] Kubernetes API Server
  Used by CI/CD, operators, developers
  Threats: Privilege escalation, pod breakout, secret access

[I5] Monitoring stack (Prometheus, Grafana, Jaeger)
  Should be internal-only but often exposed for convenience
  Threats: Metric scraping reveals service topology, data leaks

[I6] Development/debug endpoints
  /metrics, /health, /debug/pprof (Go services)
  Should be internal-only
  Threats: If exposed, reveal memory dumps, goroutine stacks, internal data
```

### Attack Surface Diagram

```
                        ┌────────────────────────────────────────────────────┐
                        │            EXTERNAL ATTACK SURFACE                 │
                        │  [E1]API  [E2]Auth  [E3]Webhooks  [E4]Partner    │
                        └──────────────────────┬─────────────────────────────┘
                                               │ Internet (Untrusted)
                                               │
                        ┌──────────────────────▼─────────────────────────────┐
                        │   Cloudflare CDN / WAF [TB-1]                     │
                        │   Bot score, IP reputation, WAF rules, DDoS       │
                        │   Certificate pinning from mobile apps             │
                        └──────────────────────┬─────────────────────────────┘
                                               │ HTTPS + Origin Certificate
                        ┌──────────────────────▼─────────────────────────────┐
                        │   API Gateway Cluster [TB-2]                       │
                        │   JWT validation, Rate limiting, Route matching    │
                        │   Consumer isolation, Request transformation       │
                        │   Exposed: 443 (HTTPS) only via CDN               │
                        └──────┬──────────────────────────────┬──────────────┘
                               │                              │
                    ┌──────────▼───────────────────┐        │
                    │ Service Mesh (Istio) [TB-3]  │        │
                    │ mTLS: all traffic encrypted   │        │
                    │ AuthorizationPolicy enforced  │        │
                    │                               │        │
                    │  ┌─────────┐   ┌──────────┐  │        │
                    │  │  Order  │──▶│Inventory │  │        │
                    │  │ Service │   │ Service  │  │        │
                    │  └────┬────┘   └──────────┘  │        │
                    │       │                       │        │
                    │  ┌────▼────┐                 │   ┌────▼──────────┐
                    │  │Payment  │                 │   │  Auth Service  │
                    │  │ Service │                 │   │  (OIDC/OAuth2) │
                    │  └─────────┘                 │   └───────────────┘
                    └──────────────────────────────┘
                               │
                    ┌──────────▼──────────────────────────────────────────────┐
                    │   Data Layer [TB-4]                                     │
                    │   PostgreSQL (private subnet, TLS)                     │
                    │   Redis (private subnet, TLS)                          │
                    │   Kafka (internal, SASL+TLS)                           │
                    │   S3 (VPC endpoint, bucket policies)                   │
                    └─────────────────────────────────────────────────────────┘

TRUST BOUNDARY LEGEND:
  [TB-1] CDN: Filters and routes. Zero client trust.
  [TB-2] API GW: Authenticates and authorizes. Trusts CDN headers.
  [TB-3] Service mesh: mTLS identity. Trusts gateway-injected headers only from GW IPs.
  [TB-4] Data: Each service owns its data. Strict access per DB user/IAM role.

ATTACK PATHS:
  External → [TB-1] → [TB-2] → bypass auth → [TB-3] → lateral movement
  External → webhook forgery → [TB-2] → fake payment events
  [I1] Compromised service → abuse mTLS cert → lateral movement to other services
  [I4] K8s API abuse → create privileged pod → read all secrets
```

---

## 9. Attack Scenarios (Very Detailed)

### 9.1 — JWT Algorithm Confusion: "none" or RS256→HS256 Attack

**For beginners:** A JWT has a header that says which algorithm was used to sign it. If a server trusts this header blindly, an attacker can forge tokens by changing the algorithm.

**Attacker Assumptions:**
- API Gateway uses a JWT library that reads `alg` from the token header
- The library accepts `alg: none` (no signature required) or allows switching from RS256 to HS256
- Attacker has obtained (or guessed) any valid JWT token

**Step-by-Step Execution:**

**Variant A — `alg: none`:**
1. Attacker takes any JWT and decodes the header: `{"alg":"RS256","kid":"key-2024-01"}`
2. Attacker creates a new header: `{"alg":"none"}`
3. Attacker creates a forged payload: `{"sub":"user_alice_123","roles":["admin"],"exp":9999999999}`
4. Attacker constructs: `base64url(forged_header).base64url(forged_payload).` (empty signature)
5. Sends request with this token: `Authorization: Bearer FORGED.TOKEN.`

**Variant B — RS256→HS256 Key Confusion:**
1. API Gateway validates RS256 tokens using a public key (which is... public)
2. Attacker gets the RS256 public key from `/.well-known/jwks.json`
3. Attacker signs a forged token using HMAC-SHA256 with the PUBLIC KEY as the HMAC secret
4. Changes `alg` in the token header to `HS256`
5. Library, if not restricting algorithms, tries to verify HS256 using the stored "public key" as the HMAC key → it matches because that's what the attacker used

**Why This Works:** Some JWT libraries (historically jose, jsonwebtoken with old configs) use the `alg` field from the token header to decide HOW to verify it. An attacker controls the header.

**Detection Points:**
- Alert: JWT `alg` value is anything other than `RS256` (or your configured algorithm)
- Alert: JWT without a `kid` field (key ID)
- Alert: JWT with `kid` not found in JWKS → this is normal on key rotation but should be rare

**Mitigation:**
```javascript
// WRONG — library-level algorithm flexibility:
jwt.verify(token, secretOrPublicKey);  // Algorithm from token header

// CORRECT — explicit algorithm restriction:
jwt.verify(token, publicKey, { algorithms: ['RS256'] });
// Library will reject ANYTHING not RS256, including "none" and "HS256"
```

---

### 9.2 — Gateway Bypass: Attacking Microservices Directly

**Attacker Assumptions:**
- Microservices are exposed on internal ports that are not properly firewalled
- Maybe a misconfigured security group allows port 8080 from anywhere
- Attacker has found the internal IP through SSRF or information disclosure

**Step-by-Step Execution:**

1. During reconnaissance, attacker finds a reference to internal service URLs in a public API error message: "upstream connect error or disconnect/reset before headers. upstream: http://order-service.internal:8080"

2. Through SSRF vulnerability in another service (e.g., a URL preview feature), attacker makes the vulnerable service contact order-service:8080

3. Order Service sees the request as coming from an internal IP — but: **if it trusts `X-Consumer-ID` header from anyone**, the attacker sets `X-Consumer-ID: admin_user_999` in the SSRF request

4. Order Service processes the request as admin_user_999 without any authentication

5. Attacker can create orders, cancel orders, access any user's order history

**Why This Works:** The service relies on the gateway to strip/set the consumer ID header. If the service can be reached directly, there's no gateway to enforce this.

**Detection Points:**
- Alert: requests to internal service ports that don't come from expected IP ranges (gateway IPs)
- Alert: unusual source IPs in service logs (should only see gateway and other services)
- Alert: `X-Consumer-ID` header with admin roles during off-hours

**Mitigation:**
1. Security groups / network policies: internal services only accept traffic from the API gateway's subnet and other services' subnets (not from the internet)
2. Services should NOT trust gateway-injected headers (`X-Consumer-ID`) unless the request comes from the gateway's known IP range. Or: remove this trust entirely and use mTLS + service mesh authorization.
3. Defense in depth: even if a service is reached directly, it should validate tokens or at minimum reject requests without a valid SPIFFE identity (mTLS)

---

### 9.3 — Service Mesh SSRF: One Service Calling Another Inappropriately

**Attacker Assumptions:**
- Attacker has found a Server-Side Request Forgery (SSRF) vulnerability in the Order Service
- The Order Service has mTLS credentials (legitimate service identity)
- The mTLS policy only restricts which services can talk to which services, but the SSRF bypasses this

**Step-by-Step Execution:**

1. Order Service has an endpoint: `POST /v1/orders/preview` that fetches a product image URL for rendering previews:
   ```json
   {"imageUrl": "https://cdn.example.com/products/PROD-123.jpg"}
   ```

2. Attacker sends: `{"imageUrl": "http://payment-service.internal:8080/admin/export-all-transactions"}`

3. Order Service fetches this URL. The request originates FROM the Order Service process — which has a valid mTLS certificate that Payment Service trusts.

4. Istio Authorization Policy says "ALLOW order-service to call payment-service" — so the mTLS connection succeeds.

5. Payment Service returns all transaction data. Order Service dutifully returns it to the attacker as the "preview image."

**Why This Works:** Service mesh authorization allows order-service → payment-service communication (for legitimate order processing). The SSRF abuses this legitimate authorization to make unauthorized data access.

**Detection:**
- Alert: Order Service making unusual HTTP calls to internal payment endpoints (not the expected `/ChargeCard` path)
- Alert: Response body from Order Service containing payment data patterns
- Network policies: restrict not just service-to-service but specific endpoint paths (Istio's `AuthorizationPolicy` supports path-based restrictions)

**Prevention:**
```yaml
# Istio AuthorizationPolicy — path-level restriction
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
spec:
  selector:
    matchLabels:
      app: payment-service
  rules:
  - from:
    - source:
        principals: ["cluster.local/ns/production/sa/order-service"]
  to:
  - operation:
      methods: ["POST"]
      paths: ["/payments.PaymentService/ChargeCard",
               "/payments.PaymentService/RefundCard"]
      # ONLY these paths are allowed — /admin/* is blocked
```

```python
# Also: validate and restrict URLs in the Order Service
def validate_image_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    # Allowlist external CDN domains only
    if parsed.hostname not in ALLOWED_IMAGE_HOSTS:
        raise ValueError(f"Image URL hostname not allowed: {parsed.hostname}")
    # Block all private IP ranges
    if is_private_ip(parsed.hostname):
        raise ValueError("Cannot fetch from private IP ranges")
    return url
```

---

### 9.4 — Kafka Message Injection

**Attacker Assumptions:**
- Attacker has compromised a microservice that produces to Kafka
- The compromised service produces fraudulent events to a topic consumed by the Payment Service

**Step-by-Step Execution:**

1. Attacker compromises the Notification Service (lower-privilege service that reads order events)

2. Notification Service has a valid Kafka producer credential (SASL/SCRAM username/password)

3. Attacker configures the compromised Notification Service to PRODUCE to the `payment.process` topic instead of just consuming from `order.created`

4. Attacker produces a message: `{"userId": "user_attacker", "amount": 0, "action": "refund_all"}` or `{"orderId": "fake_ord_999", "amount": 100000, "action": "payout"}`

5. Payment Service consumes this message and processes a refund/payout to the attacker

**Why This Works (without proper controls):** If any service with a valid Kafka credential can produce to any topic, a compromised service can inject fraudulent financial events.

**Detection:**
- Alert: Notification Service (or any non-payment service) producing to payment-related Kafka topics
- Kafka audit logs: show which client IDs produce/consume which topics
- Anomaly: payment amounts much larger than typical orders
- Duplicate event IDs: attacker replaying a captured legitimate event

**Prevention:**
```
Kafka ACLs (fine-grained access control):
  notification-service → PRODUCE to: notifications.*
  notification-service → CONSUME from: order.created, order.cancelled
  notification-service → CANNOT produce to: payment.*, financial.*

  payment-service → CONSUME from: payment.process
  payment-service → PRODUCE to: payment.result, payment.audit
  payment-service → CANNOT produce to: order.* (separation of concerns)

Message signing:
  Each service signs Kafka messages with its mTLS private key
  Consumer validates signature before processing
  Payment Service only processes messages signed by authorized producers
```

---

### 9.5 — Distributed Denial of Service: Cascading Service Failure

**Attacker Assumptions:**
- Attacker can send many requests to the API (doesn't even need authentication for some endpoints)
- The architecture has cascading dependencies without proper circuit breakers

**Step-by-Step Execution:**

1. Attacker sends 100,000 requests/second to `GET /v1/products/search?q=*` (search is often less protected)

2. This triggers the Product/Search Service to query Elasticsearch with expensive wildcard queries

3. Elasticsearch becomes overloaded, query times increase from 50ms to 5000ms

4. Product Service's connection pool fills up (all threads waiting for Elasticsearch responses)

5. Other services that call Product Service (Order Service fetches product details during order creation) now hang waiting for Product Service

6. Order Service's thread pool fills up waiting for Product Service responses

7. API Gateway's request queue grows → all requests start timing out

8. The entire system is degraded, not just the Product Service

**Why This Works (cascade failure):** Microservices have dependencies. If a downstream service is slow, the upstream caller's threads are blocked. Without circuit breakers, the slowness propagates up.

**Detection:**
- Alert: Elasticsearch query p99 latency > 500ms (early warning)
- Alert: Product Service connection pool utilization > 80%
- Alert: Order Service response time p99 > 1000ms (cascade beginning)
- Alert: API Gateway error rate > 1%

**Prevention — Circuit Breaker Pattern:**

```javascript
// Using circuit-breaker-js in the Order Service
const circuitBreaker = new CircuitBreaker(callProductService, {
  timeout: 500,       // Fail fast if call takes > 500ms
  errorThresholdPercentage: 50,  // Open circuit if 50% of calls fail
  resetTimeout: 30000,           // Try again after 30 seconds
  fallback: () => ({             // Return cached/default data instead
    products: cachedProductData,
    source: 'cache'
  })
});

// This prevents Order Service threads from blocking indefinitely
// When Product Service is struggling, Order Service fails fast and uses cache
```

---

### 9.6 — API Gateway Rate Limit Bypass via Distributed Attack

**Attacker Assumptions:**
- Rate limiting is per IP (not per JWT/user ID)
- Attacker has access to a botnet of 10,000 IPs

**Step-by-Step Execution:**

1. API gateway is configured: "100 requests/minute per IP"

2. Attacker distributes attack: 100 IPs × 99 requests/minute = 9,900 requests/minute bypassing all IP rate limits

3. Attacker can brute-force login endpoint, enumerate users, or DDoS specific endpoints that IP-based limiting can't stop

**Why This Works:** IP-based rate limiting is easily defeated by IP rotation.

**Detection:**
- Alert: Single email address getting >5 failed login attempts per 15 minutes (across any IP)
- Alert: Single JWT's sub making 10x normal request volume
- Alert: 90%+ requests to /v1/auth/login across many IPs with high failure rate

**Mitigation:**
```javascript
// Multi-dimensional rate limiting:
async function rateLimitMiddleware(req, res, next) {
  const userId = req.auth?.sub;
  const ip = req.ip;

  // Check all dimensions
  const checks = await Promise.all([
    checkLimit(`rl:ip:${ip}`, 100, 60),           // 100/min per IP
    userId && checkLimit(`rl:user:${userId}`, 50, 60), // 50/min per user
    checkLimit(`rl:global:${req.path}`, 10000, 60), // Global endpoint limit
  ]);

  const exceeded = checks.find(c => c?.exceeded);
  if (exceeded) {
    return res.status(429).json({
      error: 'Rate limit exceeded',
      retryAfter: exceeded.resetAt
    });
  }
  next();
}
```

---

## 10. Failure Points

### Under Load

**API Gateway as a single chokepoint:**

All traffic flows through the API gateway. If the gateway is undersized:
- JWT validation (RSA verification): ~1-2ms each at scale becomes significant
- Plugin chain: each plugin adds ~0.5ms; 10 plugins = 5ms overhead
- Redis calls for rate limiting: every request hits Redis → Redis becomes hot

At 50,000 req/sec:
```
JWT validation: 50,000 × 2ms = 100 CPU-seconds/second (need 100 cores just for JWT)
Redis rate limit: 50,000 Redis operations/sec → Redis needs to be distributed cluster
```

**Mitigation:**
- Horizontal scaling: multiple gateway instances behind ALB
- JWT verification with pre-cached JWKS (in-memory key store, no Redis for JWT)
- Local rate limit counters with periodic sync to Redis (trade-off: slightly inaccurate counts but much lower Redis load)
- JWKS pre-warming at startup

**Database connection exhaustion cascading:**

```
At 1,000 concurrent requests to Order Service:
  Each request needs a PostgreSQL connection
  Pool size: 20 connections
  20 connections × 20ms avg query time = 400 requests/second max throughput
  At 1,000/second → queue builds up → requests timeout → errors spike
```

**The "upstream slow" cascade:**

When one service slows down, all services that depend on it slow down. Without timeouts and circuit breakers, a 1-second slowdown at the database level can cause the entire API to become unresponsive within seconds.

---

### Under Attack

**JWT brute force (if HMAC-signed tokens with weak secret):**

If tokens are signed with HS256 and a weak secret ("secret", "password", etc.):
- An attacker who captures a valid token can brute-force the signing secret offline
- With the secret, they can forge tokens for any user ID
- This is why RS256 (asymmetric) is required: private key is never transmitted

**Service mesh certificate compromise:**

If a pod's mTLS private key is leaked (e.g., written to a log file, stored in environment variable, accessible from a container escape):
- Attacker has a valid service identity certificate
- Can communicate with any service that trusts this service identity
- Can receive responses meant for this service (if attacker is intercepting traffic)

**Kafka consumer group attack:**

If an attacker creates a consumer group with the same consumer group ID as a legitimate service:
- Kafka distributes partitions between the two consumers
- Attacker receives a portion of messages intended for the legitimate service
- Messages (events, possibly containing PII or financial data) are delivered to attacker

---

### Common Misconfigurations

| Misconfiguration | Impact | Fix |
|---|---|---|
| Gateway not enforcing HTTPS upstream | MITM between gateway and services | TLS verify-full on upstream connections |
| Services accessible without gateway (no security group) | Auth bypass entirely | Strict security groups: only gateway IPs can reach services |
| JWKS cache with no expiry | Key rotation has no effect (old revoked keys still accepted) | JWKS cache TTL ≤ 1 hour, background refresh |
| JWT without `aud` claim enforcement | Token from auth.example.com used at api2.example.com | Always verify `aud` claim matches expected audience |
| mTLS in PERMISSIVE mode (not STRICT) | Traffic can flow without mTLS (plaintext) | Set STRICT mode in Istio PeerAuthentication |
| Kafka without ACLs | Any service can produce to any topic | Enable ACLs and assign minimum required permissions |
| `/metrics` endpoint exposed externally | Service topology, performance data leakage | Only accessible from monitoring namespace pods |
| `X-Consumer-ID` header trusted from any source | Auth bypass if service is directly accessible | Services must only trust headers from gateway IPs |
| DB credentials in environment variables | Visible in `kubectl describe pod`, CI logs | AWS Secrets Manager + External Secrets Operator |
| No circuit breakers on service calls | Cascade failures | Implement circuit breakers with sensible timeouts and fallbacks |
| Same mTLS certificate for all services | One compromised service = compromised identity for all | Per-service SPIFFE identity with SPIRE |

---

## 11. Mitigations

### Defense-in-Depth Architecture

```
Layer 1: Network Perimeter
  → CDN with WAF and DDoS protection
  → Allowlist CDN's IPs at the gateway level
  → All internal traffic via private subnets

Layer 2: API Gateway
  → Mandatory JWT or API key validation
  → Multi-dimensional rate limiting (per IP AND per user AND per endpoint)
  → Request size limits
  → Schema validation for common content types
  → Explicit algorithm restrictions on JWT

Layer 3: Service Mesh
  → STRICT mTLS (no plaintext between services)
  → Per-service SPIFFE identity
  → Path-level AuthorizationPolicy (not just service-level)
  → Egress policies (services can only call approved external domains)

Layer 4: Application Level
  → Input validation with allowlists (not blocklists)
  → Parameterized queries for all database operations
  → Output encoding for all user-derived data
  → Business logic authorization checks (not just gateway-level)
  → Circuit breakers on all service calls
  → Idempotency keys for all mutations

Layer 5: Data Layer
  → Principle of least privilege for DB users (SELECT-only where possible)
  → Encrypted at rest and in transit
  → Audit logging for sensitive operations
  → Regular backup with tested restore procedures

Layer 6: Secrets Management
  → Secrets Manager for all credentials
  → Automatic rotation
  → Audit trail on all secret accesses
  → No secrets in code, config files, or environment variables

Layer 7: Monitoring and Response
  → Centralized logging (all services to same log aggregator)
  → Distributed tracing (every request has a trace ID through all services)
  → Security alerting (on authentication failures, rate limit spikes, unusual patterns)
  → Incident response playbooks for each attack type
```

---

### Circuit Breaker Implementation

```javascript
// Using Cockatiel (Node.js resilience library)
const { CircuitBreaker, ExponentialBackoff, RetryPolicy } = require('cockatiel');

const retryPolicy = RetryPolicy.handleAll()
  .retry()
  .exponential(new ExponentialBackoff())
  .attempts(3);

const inventoryCircuitBreaker = new CircuitBreaker({
  halfOpenAfter: 10000,  // Try again after 10 seconds
  threshold: { consecutive: 5 },  // Open after 5 consecutive failures
});

async function checkInventory(items) {
  try {
    return await inventoryCircuitBreaker.execute(async () => {
      return await retryPolicy.execute(async () => {
        return await inventoryGrpcClient.checkAndReserve({
          items,
          hold_seconds: 300
        });
      });
    });
  } catch (err) {
    if (err instanceof BrokenCircuitError) {
      // Circuit is open — inventory service is unhealthy
      // Return a graceful degradation response
      logger.warn('Inventory service circuit open, allowing order with verification flag');
      return {
        success: true,
        reservation_id: null,
        requires_manual_verification: true
      };
    }
    throw err;
  }
}
```

---

## 12. Observability

### The Three Pillars for Microservices

**What makes microservices observability hard:**

In a monolith, you have one log file, one set of metrics, one stack trace. In microservices, one user request may touch 10 services. Without correlation, you have 10 separate log files with no way to connect them.

The solution: **trace ID propagation**. Every request gets a unique trace ID at the API Gateway. Every service that handles part of this request logs with that trace ID. You can search for one trace ID and see all log lines from all services for that specific request.

---

### Structured Logging

Each service logs structured JSON to stdout, collected by a sidecar (Fluentd/Vector) and forwarded to Elasticsearch/Loki:

```json
// API Gateway access log:
{
  "timestamp": "2024-11-15T10:30:45.123Z",
  "level": "info",
  "event": "gateway.request",
  "traceId": "550e8400-e29b-41d4-a716-446655440000",
  "spanId": "abc123",
  "method": "POST",
  "path": "/v1/orders",
  "pathPattern": "/v1/orders",
  "consumerId": "user_alice_123",
  "consumerGroups": ["customer"],
  "upstreamService": "order-service",
  "upstreamTarget": "10.0.2.45:8080",
  "status": 201,
  "duration_ms": 312,
  "requestBytes": 247,
  "responseBytes": 156,
  "rateLimitRemaining": 87,
  "jwtKid": "key-2024-01",
  "jwtExp": 1700000900
}

// Order Service application log:
{
  "timestamp": "2024-11-15T10:30:45.180Z",
  "level": "info",
  "event": "order.created",
  "traceId": "550e8400-e29b-41d4-a716-446655440000",
  "spanId": "def456",
  "parentSpanId": "abc123",
  "orderId": "ord_abc123",
  "userId": "user_alice_123",
  "itemCount": 2,
  "totalCents": 4997,
  "currency": "USD",
  "inventoryReservationId": "res_xyz789",
  "chargeId": "ch_stripe_789",
  "dbDuration_ms": 18,
  "inventoryDuration_ms": 12,
  "paymentDuration_ms": 143,
  "totalDuration_ms": 185
}

// What NEVER appears in logs:
// - JWT token values
// - Payment card numbers or CVVs
// - Passwords or credentials
// - Full PII (truncate or hash email addresses, phone numbers)
// - Internal service IP addresses in external-facing logs
```

---

### Metrics

```
# Prometheus metrics from API Gateway
gateway_requests_total{method, path_pattern, status, upstream_service}
gateway_request_duration_seconds{method, path_pattern, upstream_service} # histogram
gateway_rate_limit_hits_total{consumer_tier, limit_type}
gateway_auth_failures_total{reason}  # "jwt_expired", "jwt_invalid", "missing_token"

# From each microservice
service_request_duration_seconds{service_name, method, endpoint}  # histogram
service_upstream_calls_total{service_name, upstream, status}
service_upstream_duration_seconds{service_name, upstream}  # histogram
service_circuit_breaker_state{service_name, upstream}  # 0=closed, 1=open, 2=half-open
service_db_pool_connections{service_name, state}  # active, idle, waiting
service_db_query_duration_seconds{service_name, operation}

# Kafka
kafka_consumer_lag{consumer_group, topic, partition}
kafka_messages_produced_total{topic, service}
kafka_messages_consumed_total{topic, consumer_group, service}

# Business metrics
orders_created_total{currency, payment_method}
order_value_cents{} # histogram - for revenue monitoring
order_failures_total{reason}  # inventory_unavailable, payment_failed, etc.
payment_success_rate  # derived metric
```

---

### Distributed Traces

Using OpenTelemetry with Jaeger or Tempo:

```
Trace: POST /v1/orders (TraceID: 550e8400...)
│
├── [0ms] API Gateway: JWT validate + rate limit + route [12ms]
│         Attributes: consumer_id=user_alice_123, route=order-service
│
├── [12ms] Order Service: POST /orders handler [300ms]
│    ├── [12ms] Zod validation [1ms]
│    │
│    ├── [13ms] gRPC: Inventory.CheckAndReserve [15ms]
│    │         → Inventory Service: query MySQL [8ms]
│    │         → Inventory Service: write Redis reservation [2ms]
│    │         Attributes: items=2, reservation_id=res_xyz789
│    │
│    ├── [28ms] gRPC: Payment.ChargeCard [145ms]
│    │         → Payment Service: Stripe API call [140ms]
│    │         Attributes: charge_id=ch_stripe_789, amount=4997
│    │
│    ├── [173ms] PostgreSQL: INSERT order + items [18ms]
│    │
│    ├── [191ms] Kafka: Publish order.created [3ms]
│    │
│    └── [194ms] Build + serialize response [2ms]
│
└── [314ms] API Gateway: Add response headers + log [2ms]

Total: 316ms
```

**Trace propagation across services:**

```http
# API Gateway injects trace headers:
traceparent: 00-550e8400e29b41d4a716446655440000-abc123def456-01
tracestate: vendor=specific-data

# Each downstream service:
# 1. Reads traceparent header
# 2. Creates a new SPAN with the incoming span as parent
# 3. Propagates traceparent to its own downstream calls (with its span ID as parent)
# 4. Reports spans to the trace collector (Jaeger/Tempo)
```

---

### Alerting Rules

| Metric/Condition | Severity | Threshold | Action |
|---|---|---|---|
| Gateway `auth_failures_total` rate spike | HIGH | >500/min spike | Security team alert |
| JWT `alg` ≠ RS256 in any request | CRITICAL | Any occurrence | Immediate security page |
| Circuit breaker OPEN for >60s | HIGH | >60s | On-call engineer |
| Kafka consumer lag >10,000 messages | MEDIUM | >10K messages | Alert engineering |
| Gateway error rate (5xx) >1% | HIGH | >1% over 5min | On-call page |
| Service p99 latency >2s | MEDIUM | >2s over 5min | Alert engineering |
| DB connection pool >90% utilized | HIGH | >90% | Alert, scale review |
| Rate limit hits >5% of requests | MEDIUM | >5% sustained | Possible attack |
| New service identity cert from unknown SA | CRITICAL | Any | Security alert |
| Secrets Manager access from unusual role | HIGH | Any | Security alert |
| Order failure rate >2% | MEDIUM | >2% over 5min | Business + engineering |

**What should NOT alert:**
- Individual 4xx errors (user errors, expected)
- Single request latency spikes (transient)
- Normal rate limit hits (a few per minute is normal)
- Cache misses (expected behavior)
- Successful JWT validations (expected)

---

## 13. Scaling Considerations

### API Gateway Scaling

The API gateway is the first scaling challenge because ALL traffic flows through it.

**Horizontal scaling:**

```
ALB (Layer 7)
  ├── Gateway Instance 1 (Kong pod)
  ├── Gateway Instance 2 (Kong pod)
  ├── Gateway Instance 3 (Kong pod)
  └── ... auto-scaled based on CPU/requests-per-second

Each gateway instance is stateless (JWT validation uses in-memory cached keys,
rate limiting state is in Redis cluster).
Kubernetes HPA (Horizontal Pod Autoscaler) scales based on RPS:
  - Target: 5,000 req/sec per gateway instance
  - Min: 3 instances (high availability)
  - Max: 50 instances (cost ceiling)
```

**Rate limiting at scale with Redis:**

```
Problem: At 100,000 req/sec, each hitting Redis for rate limit:
  100,000 Redis operations/second → single Redis node limit

Solution: Redis Cluster with hash slots
  Rate limit key: "rl:user:user_alice_123"
  Key hash: CRC16("rl:user:user_alice_123") % 16384 = slot 7823
  Slot 7823 is on Redis node 2 (of 6 nodes)
  All rate limit checks for user_alice_123 → Redis node 2
  Parallel traffic for other users → distributed across nodes

At 100,000 req/sec with 6-node Redis cluster:
  ~16,667 operations/sec per node → manageable
```

---

### Microservice Scaling Patterns

**Each service scales independently based on its own metrics:**

```
Order Service:
  - Scales on: req/sec and p95 latency
  - Bottleneck: PostgreSQL connection pool
  - Scale strategy: horizontal (stateless Node.js pods)
  - At extreme scale: read replicas for order history; primary for writes

Inventory Service:
  - Scales on: reservation check throughput
  - Bottleneck: MySQL at high reservation rates
  - Scale strategy: Read from MySQL replica, write reservations to Redis
  - Redis reservation: SET "reservation:{sku}" qty NX EX 300 (atomic compare-and-set)
    This allows thousands of reservation checks per second without hitting MySQL

Payment Service:
  - Bottleneck: Stripe API rate limits (not your service)
  - Stripe rate limits: 100 req/second per API key (standard)
  - Scale strategy: Multiple Stripe accounts for different regions
    Or: queue payments and process with rate-limiting worker pool

Notification Service:
  - Scales on: Kafka consumer lag
  - Bottleneck: SendGrid API rate limits
  - Scale strategy: Multiple consumer instances + bounded parallelism
  - If email provider is down: messages stay in Kafka, processed when it recovers
```

---

### Consistency Tradeoffs at Scale

**The CAP Theorem in practice:**

```
Scenario: Two Order Service instances, one PostgreSQL primary

Instance A: Writes order to PostgreSQL (committed)
Instance B: Immediately reads from PostgreSQL read replica
  → Replica has 50ms replication lag
  → Instance B reads stale data (order not yet visible)
  → Returns "Order not found" for a just-created order

This is "read-your-writes" problem

Solutions:
  1. Read from primary after write (lose replica's read scaling benefit for this query)
  2. Session consistency: route reads to primary for 1 second after a write
  3. Event sourcing: after write, publish to Redis pub/sub
     Client subscribes to "order_created" events instead of polling
  4. Wait-for-replication: PostgreSQL synchronous_commit=on
     Primary waits for replica ACK before returning (slower writes, consistent reads)
```

**Distributed saga for multi-service transactions:**

```
Problem: Order creation touches 3 services (Inventory, Payment, Order DB).
  If Payment succeeds but Order DB write fails → money taken, no order.
  This is the "partial failure" problem in distributed systems.

Solution: Choreography-based Saga

Step 1: Order Service starts saga, writes "pending" order to DB
Step 2: Publishes "order.pending" event

Step 3: Inventory Service consumes event → reserves inventory → publishes "inventory.reserved"
Step 4: Payment Service consumes "inventory.reserved" → charges card → publishes "payment.succeeded"
Step 5: Order Service consumes "payment.succeeded" → updates order status to "confirmed"

Compensating transactions (if something fails):
  If Step 4 fails (payment declined):
    → Payment Service publishes "payment.failed"
    → Inventory Service consumes "payment.failed" → releases reservation
    → Order Service consumes "payment.failed" → updates order to "payment_failed"

Each step is idempotent:
  - If "inventory.reserved" is consumed twice → Inventory Service checks if already reserved
  - If "payment.succeeded" is consumed twice → Order Service checks if already confirmed
```

**The consistency spectrum:**

```
STRONG CONSISTENCY                            EVENTUAL CONSISTENCY
(Higher latency, lower availability)       (Lower latency, higher availability)
       |                                           |
       │  Account balance checks                  │  User profile data
       │  Payment processing                      │  Product view counts
       │  Inventory reservation                   │  Recommendation data
       │  Order status transitions                │  Analytics dashboards
       │                                          │  Search index freshness
       │                                          │
       v                                          v
 PostgreSQL with                           Cassandra / DynamoDB
 synchronous replication                   with eventual consistency
```

---

## 14. Interview Questions

### Q1: "What is an API Gateway and why would you use one instead of having clients talk directly to microservices?"

**Answer:**

An API Gateway is a reverse proxy that acts as the single entry point for all client requests in a microservices architecture. Without it:
- Clients need to know the addresses of every microservice (tight coupling)
- Each microservice must implement authentication, rate limiting, logging independently
- When you add a new microservice, clients need to learn its address
- Cross-cutting concerns (auth, rate limiting, CORS) are duplicated across every service
- Service topology changes (new instances, different ports) require client updates

With an API Gateway:
- Clients only know one address: `api.example.com`
- Auth, rate limiting, logging are implemented once at the gateway
- The gateway can route `GET /v1/users` to the User Service and `POST /v1/orders` to the Order Service — clients don't know or care about this routing
- Services can change their internal addresses, be scaled up/down, or be replaced — the gateway abstracts this

**Why-variant:** "Why not put auth logic in each microservice?"

Each microservice implementing its own JWT validation creates duplicate code, different implementations that may have different bugs, and a maintenance burden. A centralized gateway means one place to update the JWT library, one place to handle key rotation, one place to change the auth policy. Additionally, the gateway validates the token ONCE and translates it into trusted identity headers that services can use without re-validating.

---

### Q2: "Explain the difference between authentication and authorization in this architecture. Where does each happen?"

**Answer:**

**Authentication** = "Who are you?" — Verifying identity.
**Authorization** = "What are you allowed to do?" — Checking permissions.

In this architecture:

**Authentication happens at:**
1. **CDN layer:** IP reputation and bot detection (rough pre-authentication)
2. **API Gateway:** JWT signature verification, expiry check, issuer validation. This is the primary authentication boundary. Once the JWT is validated, the gateway attaches the consumer identity to the request.
3. **Service mesh (Istio):** mTLS authentication between services. Each service cryptographically proves its identity when calling another service. This is machine-to-machine authentication.

**Authorization happens at:**
1. **API Gateway:** Scope checking ("does this JWT have `orders:write` scope to call `POST /v1/orders`?"), consumer group restrictions ("only `partner_tier_2` can call this endpoint").
2. **OPA/Rego:** Complex policy decisions ("can this user in this tenant access this resource at this time?")
3. **Service mesh (Istio AuthorizationPolicy):** "Is Order Service allowed to call Payment Service's `/ChargeCard` endpoint?"
4. **Application business logic:** "Can user_123 access order_456?" (IDOR prevention — the gateway can't know which specific resource the user owns)

**Why both layers?** Defense in depth. The gateway catches "this user has no orders scope at all." The application catches "this user has orders scope but this specific order belongs to a different user."

---

### Q3: "How does request correlation work across multiple microservices? How would you debug a failed order that touched 5 services?"

**Answer:**

**The mechanism: Trace ID propagation.**

When a request arrives at the API Gateway, it gets (or generates) an `X-Request-ID` / trace ID. Every service that processes any part of this request:
1. Reads the trace ID from the incoming request headers
2. Includes the trace ID in all log statements for this request
3. Passes the trace ID to any downstream service it calls (in outgoing request headers)
4. Reports a "span" (a named time interval representing one unit of work) to the distributed trace collector (Jaeger/Zipkin/Tempo)

**Debugging a failed order:**

1. Find the trace ID from the error response or from the mobile app's log: `X-Request-ID: 550e8400-...`

2. Search Elasticsearch/Loki for this trace ID across all services:
   ```
   traceId: "550e8400-..." AND service: "order-service"
   ```
   → See the Order Service started, called Inventory (succeeded), called Payment (returned error)

3. Search for the trace ID in Payment Service logs:
   ```
   traceId: "550e8400-..." AND service: "payment-service"
   ```
   → See: `"event": "stripe.charge_failed", "reason": "card_declined", "code": "insufficient_funds"`

4. Open the trace in Jaeger UI: see a visual timeline of all spans across all services, with exact timing of each call

5. Identify: the Stripe API call took 2,000ms but timed out at the Order Service's circuit breaker timeout of 1,500ms → Order Service got a timeout error, not the Stripe decline code → logged as "upstream timeout" instead of "payment declined"

**Without trace IDs:** You'd have to manually correlate timestamps across 5 different log streams, try to figure out which requests in each service's logs correspond to this specific user's specific order at this specific time.

---

### Q4: "What happens when the Inventory Service is down during an order placement? Walk through the failure handling."

**Answer:**

This is a multi-stage failure scenario that tests circuit breakers, fallbacks, and graceful degradation.

**Without any resilience patterns (bad):**
1. Order Service calls Inventory Service gRPC
2. gRPC connection times out after 30 seconds (TCP connection times out or TCP RST received)
3. Order Service throws UnhandledException
4. Client gets 500 Internal Server Error
5. If many requests are waiting for Inventory Service timeouts: Order Service thread pool exhausts
6. Order Service becomes unresponsive → cascade failure

**With resilience patterns (good):**

```
First call to Inventory Service fails:
  Retry #1 (immediate) → also fails
  Retry #2 (100ms delay, exponential backoff) → also fails
  Circuit breaker: 3 consecutive failures → OPEN state

Subsequent requests hit the open circuit immediately (fail fast, no network call):
  Circuit breaker fallback executes:
    Option A: Return "temporarily allow order, verify stock later"
      → Order placed with status "pending_inventory_verification"
      → Warehouse worker reviews before picking
    Option B: Return "service unavailable, try again in N seconds"
      → 503 with Retry-After header
    Option C: Check cache for last known inventory state
      → "PROD-123 had 50 units in stock 5 minutes ago; allow order"
      → Accept risk of overselling; compensate with backorder notification

After 30 seconds: Circuit breaker enters HALF-OPEN state
  → Allows one test request through
  → If it succeeds: circuit closes, normal operation resumes
  → If it fails: circuit opens again for another 30 seconds

When Inventory Service recovers:
  → All orders in "pending_inventory_verification" status processed
  → If some items actually out of stock: customer notified, order cancelled
  → If all fine: orders confirmed normally
```

**The key insight:** "Failing fast is better than failing slow." Users get an immediate response (even if degraded) instead of waiting 30 seconds for a timeout.

---

### Q5: "Explain the service mesh. Why use it instead of having services call each other directly over plain HTTP?"

**Answer:**

A service mesh (like Istio with Envoy sidecar proxies) adds a proxy container alongside every service container. All network traffic goes through these proxies.

**Without a service mesh (direct service-to-service HTTP):**
- Traffic is plaintext (HTTP, not HTTPS) on the internal network
- Services must trust network-level security entirely
- If one service is compromised, it can freely call any other service
- Retry logic, circuit breakers, load balancing must be implemented in each service's code
- Observability requires each service to report its own metrics/traces

**With a service mesh:**

**Security:**
- All traffic is mTLS (encrypted + mutually authenticated) automatically
- No code changes needed in services — the proxy handles TLS
- Cryptographic service identity (SPIFFE): Order Service provably is Order Service
- Policy enforcement at the proxy: "Payment Service only accepts calls from Order Service and Refund Service" — even if a compromised service tries to call Payment Service, the proxy rejects it

**Observability:**
- Every service-to-service call is logged by the proxy (without code changes)
- Metrics: req/sec, error rate, latency for every service pair
- Traces: spans automatically created and propagated

**Traffic management:**
- Canary deployments: send 5% of traffic to the new version, 95% to old
- Circuit breaking: configured in mesh policy, not in application code
- Retry policies: defined centrally, applied transparently
- Load balancing: round-robin, least-requests, random — configured per route

**The tradeoff:** Each proxy adds 1-5ms latency to every call and has CPU/memory overhead. For 10 services each making 3 calls per request, that's 60ms added overhead. This is acceptable for most applications but can be significant for very low-latency requirements.

---

### Q6: "How would you roll out a breaking change to an internal API (e.g., renaming a field in the Inventory Service gRPC API) without causing downtime?"

**Answer:**

This is the "zero-downtime deployment" problem for internal APIs. Key strategies:

**Strategy 1: Expand-Contract (Add then Remove)**

```
Step 1 - Expand (backward compatible):
  Inventory Service v2: returns BOTH old and new field name
  // Old: {available_qty: 50}
  // New: {available_qty: 50, stock_count: 50}
  Both fields present, both have the same value
  Deploy Inventory Service v2

Step 2 - Migrate consumers:
  Order Service: update to read from stock_count instead of available_qty
  All consumers updated over the next sprint

Step 3 - Contract (remove old field):
  After all consumers migrated:
  Inventory Service v3: returns only stock_count (removes available_qty)
  No consumers are using available_qty anymore → safe to remove
```

**Strategy 2: API Versioning at the service level**

```
// Inventory Service serves two gRPC versions simultaneously:
grpc.service.inventory.v1.InventoryService → old API
grpc.service.inventory.v2.InventoryService → new API

// Clients migrate at their own pace
// Once all clients use v2: remove v1
```

**Strategy 3: Protobuf field deprecation**

```protobuf
message ReserveResponse {
  bool success = 1;
  int32 available_qty = 2 [deprecated = true];  // Old field, kept for compat
  int32 stock_count = 3;                          // New field, use this
}
// Old consumers still work (get both fields)
// New consumers use stock_count
// deprecated=true is documentation; backward compatibility is maintained
```

**Strategy 4: Feature flags for the cutover**

```
// Use a feature flag to control which consumers read which field
// LaunchDarkly / Unleash: order-service.use-stock-count-field: true/false

// When all consumers have the flag enabled:
//   → Remove the flag and old field from code
//   → Remove the field from Inventory Service
```

The key: never make a breaking change in a single deployment. Always use an intermediate state where both old and new consumers can work.

---

### Q7: "What is the difference between synchronous and asynchronous communication in microservices? When do you use each?"

**Answer:**

**Synchronous communication (gRPC, REST HTTP):**

The caller WAITS for the response before continuing. Both services are "coupled in time" — if the downstream service is slow or down, the upstream service is directly affected.

Use when:
- The result is needed to continue processing (Order Service needs inventory confirmation before charging the card)
- Immediate consistency is required (checking available credit before approving purchase)
- The operation is fast (<500ms expected)
- You need to return the result to the user immediately

**Asynchronous communication (Kafka, SQS, RabbitMQ):**

The producer publishes a message and continues immediately. The consumer processes it at its own pace. Services are "decoupled in time" — the consumer can be down and messages will wait in the queue.

Use when:
- The result is NOT needed immediately (sending a confirmation email doesn't block the order response)
- The downstream service might be slow (analytics processing can take minutes)
- You need to fan out to multiple consumers (one order event → notification, analytics, fraud, warehouse)
- Ordering/consistency of events matters across services
- You want to buffer load spikes (Kafka absorbs a traffic spike; consumers process at steady rate)

**The hybrid in this architecture:**

```
Synchronous:
  POST /orders:
    → gRPC to Inventory (SYNC: must know if stock is available)
    → gRPC to Payment (SYNC: must know if charge succeeded)
    → DB write (SYNC: must persist before returning)
    → Return 201 to user

Asynchronous (after the 201 is returned):
    → Kafka: order.created (ASYNC: email, analytics, fraud — user doesn't wait)
    → Kafka: inventory.commit (ASYNC: deduct from inventory count permanently)
    → Kafka: order.fulfillment (ASYNC: trigger warehouse workflow)
```

**What if you made everything synchronous?**

Order creation would wait for: email sending (~200ms) + analytics write (~100ms) + fraud scoring (~500ms) = extra 800ms of latency the user has to wait. And if SendGrid is down, orders can't be created.

**What if you made everything asynchronous?**

You can't return "your order is confirmed" until you know the payment succeeded. If you do everything async, you'd have to return "we're processing your order" and have the user poll for the result — terrible UX.

---

### Q8: "How does the API Gateway handle JWT key rotation without causing downtime for existing sessions?"

**Answer:**

JWT key rotation is a critical operational procedure that must be handled without invalidating all existing user sessions.

**The problem:**
- Current setup: Auth Service signs tokens with `key-2024-01` (RSA private key)
- API Gateway validates tokens using `key-2024-01` (RSA public key, from JWKS)
- Tokens are valid for 15 minutes; refresh tokens valid for 30 days
- If we rotate keys immediately: all in-flight tokens (signed by old key) become invalid → all users get 401 and are logged out

**The solution: Overlapping key rotation**

```
Phase 1: Generate new key pair
  - Auth Service: generate new RSA key pair (key-2024-02)
  - Keep key-2024-01 for signing existing tokens

Phase 2: Publish both keys to JWKS (2 keys in the JWKS endpoint)
  {
    "keys": [
      {"kid": "key-2024-01", "n": "...", "e": "AQAB"},  // Old key still here
      {"kid": "key-2024-02", "n": "...", "e": "AQAB"}   // New key added
    ]
  }
  API Gateway refreshes its JWKS cache → now has both keys

Phase 3: Switch signing to new key
  - Auth Service: new tokens are signed with key-2024-02
  - Existing tokens (signed by key-2024-01) are still valid because JWKS has both
  - Gateway uses the JWT's "kid" header to look up which key to use

Phase 4: Wait for old tokens to expire
  - Access tokens: 15-minute TTL → after 15 minutes, no token signed by key-2024-01 remains valid
  - Wait 15 minutes (or the JWT TTL, whichever is longer)

Phase 5: Remove old key from JWKS
  - Remove key-2024-01 from JWKS endpoint
  - API Gateway refreshes cache → only key-2024-02 remains
  - Any remaining token with "kid": "key-2024-01" → key not found → rejected

No users were logged out during this process!
```

**The API Gateway's JWKS cache behavior:**

```javascript
class JWKSCache {
  constructor() {
    this.keys = {};     // kid → public key
    this.lastRefresh = 0;
    this.TTL = 3600 * 1000;  // Refresh every 1 hour
  }

  async getKey(kid) {
    // If key not found in cache, try refreshing immediately
    // (handles case where new key was just added)
    if (!this.keys[kid]) {
      await this.refresh();
    }
    return this.keys[kid];
  }

  async refresh() {
    const jwks = await fetch('https://auth.example.com/.well-known/jwks.json');
    const { keys } = await jwks.json();
    this.keys = {};
    for (const key of keys) {
      this.keys[key.kid] = await importPublicKey(key);
    }
    this.lastRefresh = Date.now();
  }
}
```

**Revocation (more complex):**

If you need to immediately invalidate a specific token (e.g., user reports their account is compromised):
- Store the `jti` (JWT ID) in a Redis blocklist with TTL = token's remaining lifetime
- Gateway checks this blocklist on every request
- Small Redis overhead but enables immediate revocation

---

### Q9: "If we wanted to add a new microservice to this architecture, what are the operational steps and considerations?"

**Answer:**

Adding a new service (e.g., a "Recommendations Service") involves:

**1. Service design:**
- Define its domain boundary: what data does it own? What does it expose?
- Define its API contract (gRPC .proto file or REST OpenAPI spec)
- Identify its data store and access patterns
- Identify events it will produce and consume from Kafka

**2. Infrastructure provisioning:**
- Create Kubernetes Deployment and Service manifests
- Create the service's dedicated namespace
- Configure its Istio sidecar injection and PeerAuthentication (STRICT mTLS)
- Provision its database (new PostgreSQL schema or separate RDS instance)
- Create its IAM role and Secrets Manager secrets
- Configure its Kafka consumer groups and ACLs (which topics it can produce/consume)

**3. Service mesh authorization:**
```yaml
# Who can call the new Recommendations Service?
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
spec:
  selector:
    matchLabels:
      app: recommendations-service
  rules:
  - from:
    - source:
        principals: ["cluster.local/ns/production/sa/api-gateway"]
    to:
    - operation:
        methods: ["GET"]
        paths: ["/recommendations.RecommendationsService/*"]
```

**4. API Gateway route configuration:**
```yaml
# New Kong route:
- name: recommendations-route
  paths: ["/v1/recommendations"]
  methods: ["GET"]
  plugins:
    - name: jwt        # Validate JWT
    - name: rate-limiting
      config:
        minute: 100
  upstream:
    targets:
      - target: recommendations-service.production.svc.cluster.local:8080
```

**5. Observability:**
- Add the service to Grafana dashboards
- Configure its log pipeline (add to FluentD config)
- Create service-specific alerts
- Ensure it propagates trace IDs

**6. Deployment and testing:**
- Start with a canary deployment: 10% of traffic to new service, 90% to old behavior
- Monitor error rates, latency, and business metrics
- Gradually increase traffic percentage
- Feature flag: enable recommendations only for specific users/experiments initially

**7. Documentation:**
- Update API docs (Swagger/OpenAPI for REST, proto files for gRPC)
- Update architecture diagrams
- Document the service's operational runbook (how to restart, how to scale, what to do if DB is full)

The key principle: **each new service must not require changes to existing services** (unless it's consuming their events or being called by them). Adding a Recommendations Service shouldn't require touching the Order Service at all.

---

*Document version: 1.0 | Classification: Internal Engineering | Author: Platform Engineering Team*  
*This document describes production API Gateway + Microservices patterns. Adapt specifics to your technology stack and scale requirements.*
