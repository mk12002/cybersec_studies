# Password Reset Flow — Internal Engineering & Security Document

**Classification:** Internal Engineering Reference  
**Audience:** Senior Engineers, Security Engineers, Systems Architects  
**Scope:** Full-stack breakdown of a production Password Reset Flow  
**Architecture assumed:** Multi-service web application with React SPA frontend, Node.js/Python API backend, PostgreSQL user database, Redis for token storage and rate limiting, and a transactional email provider (SendGrid/SES/Postmark).

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

### System Topology

```
Browser -> CDN (static assets) -> nginx (TLS termination + reverse proxy)
       -> API Server (auth service)
       -> Redis (reset token store + rate limits)
       -> PostgreSQL (user records)
       -> Email Queue (async)
       -> Email Provider (SendGrid / SES / Postmark)
       -> User's Email Client
       -> Browser (reset link click)
       -> API Server (token validation + password update)
```

The password reset flow spans two separate HTTP sessions separated by an out-of-band channel (email). The security model depends entirely on treating the user's email inbox as a second factor — access to the email = authorization to reset the password.

---

### Phase 1: Reset Request

#### T+0ms — User navigates to "Forgot Password"

User clicks "Forgot your password?" link on the login page. The SPA client-side routes to `/forgot-password` — no server request for this navigation (it's a React route change). The browser renders a form with a single email input field.

**What the user sees:** A simple form: "Enter your email address and we'll send you a reset link."

**What actually happens:** Nothing on the server. Pure client-side navigation. The browser has not contacted the API at all.

---

#### T+~200ms — User submits their email

User types their email address and clicks "Send Reset Link." The JavaScript intercepts the form submit and fires:

```http
POST https://api.example.com/auth/password/reset/request
Content-Type: application/json
{"email": "user@example.com"}
```

This triggers DNS resolution, TCP handshake, and TLS negotiation (detailed in Section 2). The entire network stack activates for the first time in this flow.

---

#### T+~300ms — API receives and processes the request

The API's rate limiting middleware fires first (before any business logic):

1. Check Redis: `GET ratelimit:password_reset:ip:203.0.113.42` — how many reset requests has this IP made in the last 15 minutes?
2. Check Redis: `GET ratelimit:password_reset:email:sha256(user@example.com)` — how many resets has this specific email received?
3. If either limit exceeded: return `429 Too Many Requests` with `Retry-After` header. Stop processing.

If rate limits pass:

4. Validate email format: basic regex and length check.
5. Query PostgreSQL: `SELECT id, email, is_active FROM users WHERE email = $1 LIMIT 1`.
6. **Critical: regardless of whether the user exists, the response will be identical.** This is enumeration prevention. The server does NOT reveal whether the email is registered.
7. If user exists AND account is active: proceed to token generation.
8. If user doesn't exist OR account is inactive: silently proceed — the response will look identical. No token is generated. No email is sent. But the API returns 200 with the same message.

---

#### T+~310ms — Reset token generation (user exists path)

The server generates the reset token. This is the most security-critical operation in the entire flow.

```
raw_token  = CSPRNG(32 bytes)
           → base64url encoding (URL-safe, no padding)
           → e.g., "dGhpcyBpcyBhIHNlY3VyZSByZXNldCB0b2tlbg"

token_hash = SHA-256(raw_token)
           → stored in DB, never the raw token
```

**Why hash the token before storage?**

The token stored in the database is a SHA-256 hash of the actual token sent to the user. If the database is compromised, the attacker has hashes, not raw tokens. SHA-256 without a salt is acceptable here — unlike passwords, reset tokens are already high-entropy (256 bits of CSPRNG output), so rainbow tables are computationally infeasible. The attacker would need to find the preimage of a SHA-256 hash with 2^256 possible inputs.

The token record written to PostgreSQL (or Redis, depending on architecture):

```sql
INSERT INTO password_reset_tokens (
  id,
  user_id,
  token_hash,   -- SHA-256(raw_token) in hex
  created_at,   -- NOW()
  expires_at,   -- NOW() + INTERVAL '1 hour'
  used_at,      -- NULL initially
  ip_hash,      -- SHA-256(client_ip) -- for audit, not validation
  user_agent_hash -- SHA-256(user_agent)
)
VALUES ($1, $2, $3, NOW(), NOW() + INTERVAL '1 hour', NULL, $4, $5);
```

**Simultaneously**, any existing unused, unexpired tokens for this user are invalidated:

```sql
UPDATE password_reset_tokens
SET used_at = NOW()  -- or: status = 'superseded'
WHERE user_id = $1
  AND used_at IS NULL
  AND expires_at > NOW();
```

This ensures only one active reset token exists per user at any time. A new reset request invalidates the previous one — preventing token accumulation attacks.

---

#### T+~315ms — Email queued for delivery

The API does NOT wait for the email to be delivered. Email delivery is asynchronous. The API:

1. Constructs the reset URL: `https://app.example.com/reset-password?token=<raw_token>`
2. Publishes a message to the email queue (SQS/Kafka/Redis List/BullMQ):
   ```json
   {
     "type": "password_reset",
     "to": "user@example.com",
     "template_id": "d-abc123",
     "dynamic_data": {
       "reset_url": "https://app.example.com/reset-password?token=<raw_token>",
       "expiry_minutes": 60,
       "user_display_name": "Jane",
       "request_ip_geo": "US-CA"
     },
     "idempotency_key": "<uuid>"
   }
   ```
3. Returns `200 OK` immediately to the browser.

**What the user sees:** "If an account with that email exists, we've sent a reset link. Check your inbox." (Generic message — same for both existing and non-existing accounts.)

---

#### T+~315ms to T+~60s — Email delivery (async, out-of-band)

A background email worker dequeues the job and calls the email provider's API (SendGrid/SES):

```http
POST https://api.sendgrid.com/v3/mail/send
Authorization: Bearer SG.xxx...
Content-Type: application/json

{
  "to": [{"email": "user@example.com"}],
  "from": {"email": "noreply@example.com", "name": "Example App"},
  "template_id": "d-abc123",
  "dynamic_template_data": {
    "reset_url": "https://app.example.com/reset-password?token=dGhpcyBpcyBhIHNlY3VyZSByZXNldCB0b2tlbg",
    "expiry_minutes": 60
  }
}
```

The email is queued by SendGrid, routed through their MTA (Mail Transfer Agent), and delivered to the user's email provider (Gmail, Outlook, etc.) via SMTP over TLS (STARTTLS or SMTPS on port 465). Delivery time: typically 5–30 seconds, sometimes minutes for rate-limited providers.

**DKIM signing:** The email is signed by SendGrid using the domain's DKIM private key. This authenticates the email's origin. The user's email provider (Gmail) verifies the DKIM signature against the public key published in DNS (`TXT _domainkey.example.com`).

**SPF check:** Gmail checks the sending IP against example.com's SPF record to verify the email came from an authorized sender.

**DMARC policy:** example.com's DMARC record instructs receiving servers what to do if SPF or DKIM fails.

---

#### Phase 2: Reset Link Click (separate browser session, potentially different device)

#### T+unknown — User opens email and clicks reset link

The user clicks the link in their email client. The browser navigates to:

```
https://app.example.com/reset-password?token=dGhpcyBpcyBhIHNlY3VyZSByZXNldCB0b2tlbg
```

This may be a different browser, a different device, or even the same browser minutes or hours later. The token in the URL is the complete authentication credential for this operation.

**What the user sees:** A form with two fields: "New Password" and "Confirm New Password."

**What actually happens:** The SPA JavaScript extracts the `token` parameter from the URL query string (`new URLSearchParams(window.location.search).get('token')`). It may:
- Store the token in a JavaScript variable.
- Optionally make a lightweight validation request to verify the token hasn't expired (UX improvement — show an error immediately rather than after password entry).

---

#### T+~form fill — User submits new password

User types a new password, clicks "Reset Password." The SPA fires:

```http
POST https://api.example.com/auth/password/reset/confirm
Content-Type: application/json

{
  "token": "dGhpcyBpcyBhIHNlY3VyZSByZXNldCB0b2tlbg",
  "new_password": "new-secure-password-here"
}
```

---

#### T+~N+100ms — API validates token and updates password

1. **Rate limiting:** Same IP-based check as the request phase.
2. **Token extraction:** The raw token is extracted from the JSON body.
3. **Token hashing:** `token_hash = SHA-256(submitted_token)`.
4. **Database lookup:**
   ```sql
   SELECT id, user_id, expires_at, used_at
   FROM password_reset_tokens
   WHERE token_hash = $1
   LIMIT 1;
   ```
5. **Validation checks (ALL must pass):**
   - Row exists → token is known.
   - `used_at IS NULL` → token hasn't been used.
   - `expires_at > NOW()` → token hasn't expired.
   - (Optional) IP check or user-agent check for anomaly detection.
6. **Password validation:**
   - Minimum length (e.g., 12 characters).
   - Maximum length (e.g., 1024 characters — bcrypt/Argon2 DoS prevention).
   - Breach check via HaveIBeenPwned k-anonymity API.
7. **Mark token as used** (BEFORE updating password — prevents race conditions):
   ```sql
   UPDATE password_reset_tokens
   SET used_at = NOW()
   WHERE id = $1 AND used_at IS NULL;  -- atomic check-and-set
   ```
   If this UPDATE affects 0 rows: another request has used the token concurrently — return 400.
8. **Hash new password** with Argon2id (200–300ms).
9. **Update user record:**
   ```sql
   UPDATE users
   SET password_hash = $1,
       updated_at = NOW(),
       password_changed_at = NOW()
   WHERE id = $2;
   ```
10. **Invalidate all active sessions** for this user:
    ```
    DEL all "session:<session_id>" keys for this user_id
    ```
    This forces re-authentication from all devices.
11. **Invalidate all other reset tokens** for this user (defensive cleanup).
12. **Publish audit event** (async): `{event: "password_changed", user_id, ip, timestamp}`.
13. **Send confirmation email** (async): "Your password was just changed. If this wasn't you, contact support."
14. **Return 200 OK.** The SPA redirects the user to `/login` with a success message.

---

## 2. Network Layer Flow

### DNS Resolution

```
Browser cache -> OS stub resolver -> Recursive resolver
     |                                      |
     |                          +-----------+-----------+
     |                          |                       |
     |                    Root NS lookup          (cached result)
     |                          |
     |                    .com TLD NS lookup
     |                          |
     |                    api.example.com authoritative NS
     |                          |
     |                    A record: 203.0.113.1 (nginx)
     |<-- IP returned -----------+
```

**Two DNS lookups occur in this flow:**

1. `api.example.com` — for the REST API calls (reset request + confirm).
2. `app.example.com` — for the SPA page load (reset form rendering).

These may resolve to the same IP (monolith) or different IPs (separate frontend/backend). Both need DNS entries. If using a CDN (CloudFront/Fastly) for the SPA: `app.example.com` resolves to a CDN edge IP, not the origin. API calls bypass the CDN (or use a separate origin).

**TTL considerations:** Short TTLs (60-300s) for API endpoints allow rapid IP changes for failover but increase DNS query volume. During the password reset flow, the user must successfully resolve both hostnames — a DNS failure at any point means the flow breaks.

**DNSSEC:** If enabled, the recursive resolver validates RRSIG records against the DNSKEY chain anchored at the root. Validation failure = SERVFAIL = user can't initiate or complete the reset.

---

### TCP 3-Way Handshake

For each HTTPS connection (reset request, token validation, confirm submit):

```
Client (browser)                     nginx (203.0.113.1:443)
       |                                       |
       |  SYN [seq=x, MSS=1460,               |
       |        SACK_OK, WS=7, TSval=t]       |
       |-------------------------------------->|
       |                                       |
       |  SYN-ACK [seq=y, ack=x+1,            |
       |           MSS=1460, SACK_OK, WS=9]   |
       |<--------------------------------------|
       |                                       |
       |  ACK [ack=y+1]                        |
       |-------------------------------------->|
       |  [TCP established -- 1 RTT]           |
```

**HTTP/2 connection reuse:** The SPA's API calls (reset request AND reset confirm) may reuse the same HTTP/2 connection if they occur in the same browser tab and the connection hasn't been closed. This is transparent to the application but means only one TCP handshake for both API calls. HTTP/2 streams (HEADERS frame + DATA frame) multiplex over this connection.

**Connection pooling on the backend:** The API server maintains a connection pool to PostgreSQL (PgBouncer) and Redis (connection pool). TCP handshakes to these internal services happen at application startup or on-demand, not on each request. The per-request cost to these services is query latency, not connection establishment.

---

### TLS 1.3 Handshake

```
Client                                              nginx
  |                                                   |
  |  ClientHello                                      |
  |  - supported_versions: [TLS 1.3]                 |
  |  - cipher_suites:                                 |
  |      TLS_AES_256_GCM_SHA384                       |
  |      TLS_AES_128_GCM_SHA256                       |
  |      TLS_CHACHA20_POLY1305_SHA256                 |
  |  - key_share: X25519 ephemeral pub key (32B)      |
  |  - SNI: "api.example.com"                         |
  |  - ALPN: ["h2", "http/1.1"]                       |
  |  - session_ticket (for 0-RTT if available)        |
  |-------------------------------------------------->|
  |                                                   |
  |  ServerHello                                      |
  |  - cipher: TLS_AES_256_GCM_SHA384                 |
  |  - key_share: server's X25519 ephemeral pub key   |
  |                                                   |
  |  {EncryptedExtensions}                            |
  |  - ALPN: "h2"                                     |
  |                                                   |
  |  {Certificate}                                    |
  |  - api.example.com cert (RSA-2048 or ECDSA P-256) |
  |  - intermediate CA cert                           |
  |  - OCSP staple (revocation proof)                 |
  |  - SCTs from CT logs                              |
  |                                                   |
  |  {CertificateVerify}                              |
  |  - sig over handshake transcript                  |
  |  - proves server owns the private key             |
  |                                                   |
  |  {Finished}                                       |
  |<--------------------------------------------------|
  |                                                   |
  |  {Finished}                                       |
  |  [First HTTP/2 request can be sent now]           |
  |-------------------------------------------------->|
```

**Key derivation (HKDF):**
Both sides compute the same X25519 ECDH shared secret (client_priv * server_pub = server_priv * client_pub). HKDF derives separate keys for each direction and purpose (handshake traffic keys, application traffic keys). AES-256-GCM provides AEAD — each record is encrypted and authenticated. The nonce is a per-record counter XOR'd with the traffic key's base IV.

**Why this matters for password reset:** The reset token is transmitted in the POST body to the API. If TLS is misconfigured or downgraded to plaintext, the token travels in the clear and is interceptable. HSTS (`Strict-Transport-Security`) prevents the browser from ever attempting HTTP to this domain, even if a redirect is served.

**Certificate validation:** The browser validates that `api.example.com` is in the certificate's SAN list, the certificate chain chains to a trusted root CA, the certificate is not expired, and the OCSP staple (or online OCSP response) confirms it's not revoked.

---

### Full Network Flow — Password Reset

```
USER BROWSER               NGINX/CDN          API SERVER         REDIS       POSTGRESQL      EMAIL PROVIDER
      |                        |                    |               |               |                |
 [Phase 1: Reset Request]      |                    |               |               |                |
      |                        |                    |               |               |                |
  DNS: api.example.com         |                    |               |               |                |
  ---> [Recursive resolver] -->|                    |               |               |                |
  <--- 203.0.113.1 -----------|                    |               |               |                |
      |                        |                    |               |               |                |
  TCP SYN ---------------------->                   |               |               |                |
  TCP SYN-ACK <-------------------|                  |               |               |                |
  TCP ACK ----------------------->|                  |               |               |                |
      |                        |                    |               |               |                |
  TLS ClientHello -------------->|                   |               |               |                |
  TLS ServerHello+Cert+Fin <-----|                   |               |               |                |
  TLS Finished ----------------->|                   |               |               |                |
      |                        |                    |               |               |                |
  POST /auth/password/reset -----> proxy ---------> |               |               |                |
  {"email":"user@example.com"}  |                   |--INCR ratelimit:ip-->         |                |
      |                        |                    |<-- count: 1 --|               |                |
      |                        |                    |--INCR ratelimit:email-->      |                |
      |                        |                    |<-- count: 1 --|               |                |
      |                        |                    |                               |                |
      |                        |                    |--SELECT user WHERE email=?-->|                |
      |                        |                    |<-- {user_id, is_active} -----|                |
      |                        |                    |                               |                |
      |                        |                    |  [CSPRNG(32B) -> raw_token]  |                |
      |                        |                    |  [SHA-256(raw_token) -> hash] |                |
      |                        |                    |                               |                |
      |                        |                    |--UPDATE supersede old tokens-->               |
      |                        |                    |--INSERT new token record ----->               |
      |                        |                    |<-- OK ----------------------- |               |
      |                        |                    |                               |                |
      |                        |                    |--LPUSH email_queue {job} -> [REDIS QUEUE]      |
      |                        |                    |<-- OK ----------------------->|               |
      |                        |                    |                               |                |
  <-- 200 OK "Check your email" ---- 200 OK -------|               |               |                |
      |                        |                    |               |               |                |
      |                        |         [Email Worker (async)]     |               |                |
      |                        |                    |--BRPOP email_queue -----------|                |
      |                        |                    |<-- {job} --------------------|                |
      |                        |                    |--- POST /v3/mail/send -------------------------------->|
      |                        |                    |<-- 202 Accepted --------------------------------------|
      |                        |                    |                               |                |
  [Email arrives in inbox ~5-30s]                   |               |               |                |
      |                        |                    |               |               |                |
 [Phase 2: Reset Confirmation -- potentially different browser session]              |                |
      |                        |                    |               |               |                |
  [User clicks link in email]  |                    |               |               |                |
  DNS: app.example.com ------->|                    |               |               |                |
      |  [TCP + TLS handshake] |                    |               |               |                |
  GET /reset-password?token=X ->                    |               |               |                |
  <-- SPA HTML/JS -------------|                    |               |               |                |
      |                        |                    |               |               |                |
  [SPA renders new password form]                   |               |               |                |
      |                        |                    |               |               |                |
  POST /auth/password/reset/confirm                 |               |               |                |
  {token, new_password} ------> proxy -----------> |               |               |                |
      |                        |                    |--INCR ratelimit:ip-->         |                |
      |                        |                    |--SHA-256(token) -> hash       |                |
      |                        |                    |--SELECT token WHERE hash=? -->|                |
      |                        |                    |<-- {id, user_id, expires_at}--|                |
      |                        |                    |  [validate: not used, not expired]             |
      |                        |                    |--UPDATE token SET used_at=NOW()-->             |
      |                        |                    |  [Argon2id hash new_password ~200ms]           |
      |                        |                    |--UPDATE users SET password_hash=? -->         |
      |                        |                    |--DEL all user sessions -------->|              |
      |                        |                    |<-- OK ----------------------->|               |
      |                        |                    |                               |                |
  <-- 200 OK "Password reset!" ---- 200 OK --------|               |               |                |
      |                        |                    |                               |                |
  [Redirect to /login]         |                    |--LPUSH email_queue {confirm_job}->             |
```

### Latency Budget

| Step | Latency |
|---|---|
| DNS resolution (cold) | 30–100ms |
| TCP handshake | 1x RTT (~20–60ms) |
| TLS 1.3 handshake | 1x RTT |
| Redis rate limit check | 0.5–2ms |
| PostgreSQL user lookup | 2–10ms |
| CSPRNG token generation | <1ms |
| PostgreSQL token insert | 3–8ms |
| Email queue publish | 0.5–2ms (Redis) |
| **Total Phase 1 API response** | **~100–200ms** |
| Email delivery (async) | 5s–2min |
| Argon2id hash (Phase 2) | 100–300ms |
| PostgreSQL password update | 3–8ms |
| **Total Phase 2 API response** | **~150–400ms** |

---

## 3. Application Layer Flow

### Phase 1: Reset Request Endpoint

**Endpoint:** `POST /auth/password/reset/request`

**Inbound request:**

```http
POST /auth/password/reset/request HTTP/2
Host: api.example.com
Content-Type: application/json
Content-Length: 30
Origin: https://app.example.com
X-Request-ID: req-uuid-abc123
X-Forwarded-For: 203.0.113.42 (set by nginx)

{"email": "user@example.com"}
```

**Header validation:**
- `Content-Type` must be `application/json`. If `text/plain` or `multipart/form-data`: reject 415. This prevents CSRF attacks via form submission from a different origin that bypasses CORS preflight.
- `Origin` header validated against allowed origins list. Cross-origin requests from unauthorized origins get a CORS rejection (no response body, browser blocks the response).
- `Content-Length` validated against actual body size.

**CORS preflight (OPTIONS) — occurs before the actual POST:**
```http
OPTIONS /auth/password/reset/request HTTP/2
Origin: https://app.example.com
Access-Control-Request-Method: POST
Access-Control-Request-Headers: Content-Type, X-Request-ID
```

Server responds:
```http
HTTP/2 204
Access-Control-Allow-Origin: https://app.example.com
Access-Control-Allow-Methods: POST
Access-Control-Allow-Headers: Content-Type, X-Request-ID
Access-Control-Max-Age: 86400
Vary: Origin
```

**Body parsing:**
JSON parsed. The `email` field is extracted. Validation:
- Type: must be a string.
- Format: regex match `^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`
- Length: 5–254 characters (RFC 5321 maximum).
- No null bytes, no control characters.
- Normalize: lowercase, trim whitespace.

**Response construction:**

The response is identical whether the email exists or not. This is the most important security property of the response:

```http
HTTP/2 200
Content-Type: application/json
Cache-Control: no-store
X-Content-Type-Options: nosniff
X-Request-ID: req-uuid-abc123

{"message": "If an account with that email exists, you'll receive a reset link shortly."}
```

**Why 200 instead of 404 for unknown emails?** A 404 response for an unregistered email and 200 for a registered email leaks whether the email is in the system. An attacker can enumerate all users by checking which emails return 200 vs 404. Always return 200 with the same message regardless.

**Timing normalization:** The code path for "user not found" must take approximately the same time as "user found." If "not found" returns in 5ms and "found" returns in 300ms (due to DB write + Redis operations), a timing side channel exists. Solution: if the user is not found, still perform a dummy wait or a constant-time comparison operation. Some frameworks provide `timingSafeEqual` or similar helpers. Minimum: always perform the DB query (don't short-circuit before it).

---

### Phase 2: Password Reset Confirmation Endpoint

**Endpoint:** `POST /auth/password/reset/confirm`

```http
POST /auth/password/reset/confirm HTTP/2
Host: api.example.com
Content-Type: application/json
Content-Length: 95

{
  "token": "dGhpcyBpcyBhIHNlY3VyZSByZXNldCB0b2tlbg",
  "new_password": "my-new-secure-password-2024"
}
```

**Parameter parsing:**
- `token`: string, 43–44 chars (base64url of 32 bytes), no whitespace, URL-decode if URL-encoded.
- `new_password`: string, 12–1024 chars.
- Both fields required. Missing fields → 400 with generic error (don't specify which field — don't leak token existence).

**Response on success:**

```http
HTTP/2 200
Content-Type: application/json
Cache-Control: no-store
Set-Cookie: session_id=; Max-Age=0; Path=/; HttpOnly; Secure
  (Clear any existing session cookie — force re-login)

{"message": "Password reset successful. Please log in with your new password."}
```

**Response on failure (all failure cases return the same response):**

```http
HTTP/2 400
Content-Type: application/json
Cache-Control: no-store

{"error": "Invalid or expired reset token."}
```

This single error message covers: token not found, token expired, token already used, token format invalid. Never reveal which condition triggered it.

---

### Token URL — Anatomy

The reset URL sent in the email:

```
https://app.example.com/reset-password?token=dGhpcyBpcyBhIHNlY3VyZSByZXNldCB0b2tlbg
```

**URL parameter vs. path segment:**
- `?token=...` (query parameter): Token appears in HTTP server access logs (`/reset-password?token=...`). May appear in browser history and the browser's built-in form autocomplete for URLs. Also appears in the `Referer` header if the user clicks any link from the reset page.
- `/reset-password/dGhpcyBpcyBhIHNlY3VyZSByZXNldCB0b2tlbg` (path segment): Also appears in logs and history. Same risks.

**Mitigation for log exposure:** Configure nginx to strip or redact query parameters on the `/reset-password` endpoint before logging. Use `$request_uri` filtering in nginx log format. Set `Referrer-Policy: no-referrer` on the reset page response headers so the token doesn't leak in the `Referer` header to any embedded third-party scripts.

---

## 4. Backend Architecture

### Services Involved

```
+-----------------------------------------------------------+
|                    PASSWORD RESET FLOW                     |
+-----------------------------------------------------------+
|                                                           |
|  [1] API Server (Auth Service)                            |
|      - Rate limiting (reads/writes Redis)                 |
|      - Input validation                                   |
|      - Token generation (CSPRNG)                          |
|      - Database operations (read/write PostgreSQL)        |
|      - Email job publishing (writes to Redis queue)       |
|      - Password hashing (Argon2id - CPU intensive)        |
|      - Session invalidation (writes to Redis)             |
|                                                           |
|  [2] Redis                                                |
|      - Rate limit counters (INCR + EXPIRE, per IP/email)  |
|      - Email job queue (LPUSH/BRPOP or BullMQ)            |
|      - Session store (DEL on password change)             |
|      - (Optional) Token store instead of PostgreSQL        |
|                                                           |
|  [3] PostgreSQL                                           |
|      - users table (SELECT + UPDATE)                      |
|      - password_reset_tokens table (INSERT + UPDATE)      |
|                                                           |
|  [4] Email Worker (background service)                    |
|      - Subscribes to email job queue                      |
|      - Calls email provider API (SendGrid/SES)            |
|      - Handles retries with exponential backoff           |
|      - Idempotency via idempotency_key                    |
|                                                           |
|  [5] Email Provider (SendGrid / SES / Postmark)           |
|      - Transactional email delivery                       |
|      - DKIM signing                                       |
|      - Delivery status webhooks                           |
+-----------------------------------------------------------+
```

### Sync vs. Async Decision Breakdown

**Synchronous (on the request critical path):**
- Rate limit check (Redis): Must happen before processing — blocking is intentional.
- User existence check (PostgreSQL): Needed to determine if token should be generated.
- Token insert (PostgreSQL): Must complete before response — the token must be stored before the email is sent (or else the link arrives before the token exists).
- Token validation (PostgreSQL): Must be synchronous — can't return a "success" to the user until we know the token is valid and has been marked used.
- Token marking as used (PostgreSQL): MUST be synchronous and BEFORE password update — prevents race conditions.
- Password hash computation (Argon2id): Must be synchronous — must complete before DB update.
- Password update (PostgreSQL): Must be synchronous — the operation the user is waiting for.
- Session invalidation (Redis): Should be synchronous — users of the old sessions should be logged out immediately.

**Asynchronous (off the critical path):**
- Email delivery: 100% async. The API should not wait for email delivery. Email providers are external services with unpredictable latency. User gets the "check your inbox" message immediately; email arrives whenever.
- Confirmation email after reset: Async. The user has already seen the "success" screen.
- Audit log publishing: Async. Non-blocking.
- Analytics events: Async. Non-blocking.

---

### Database Schema

**password_reset_tokens table:**

```sql
CREATE TABLE password_reset_tokens (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash    CHAR(64) NOT NULL,    -- SHA-256 hex of the raw token (64 hex chars)
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at    TIMESTAMPTZ NOT NULL,
  used_at       TIMESTAMPTZ,          -- NULL = active/unused
  superseded_at TIMESTAMPTZ,          -- NULL = not superseded by a new request
  ip_hash       CHAR(64),             -- SHA-256(client_ip) for audit
  ua_hash       CHAR(64),             -- SHA-256(user_agent) for audit
  UNIQUE(token_hash)
);

CREATE INDEX idx_prt_token_hash   ON password_reset_tokens(token_hash);
CREATE INDEX idx_prt_user_id      ON password_reset_tokens(user_id);
CREATE INDEX idx_prt_expires_at   ON password_reset_tokens(expires_at);
  -- For cleanup job: find and delete expired tokens
```

**Rationale for table vs. Redis for token storage:**

| Property | PostgreSQL | Redis |
|---|---|---|
| Durability | Full (WAL-backed) | RDB/AOF (can lose data on crash) |
| Audit trail | Full row history | Ephemeral |
| Complex queries | Easy (user_id index, status) | Limited |
| TTL management | Background job required | Native EXPIRE |
| Atomic mark-as-used | Yes (UPDATE WHERE used_at IS NULL) | Yes (Lua script or transaction) |
| Speed | 5–15ms | 0.5–2ms |

For security-critical tokens with audit requirements: PostgreSQL. For speed with acceptable durability loss (e.g., MFA codes): Redis.

---

### Email Queue Architecture

```
API Server
   |
   | LPUSH email_queue <JSON job>
   v
Redis List: "email_queue"
   |
   | BRPOP email_queue (blocking pop, 0 timeout)
   v
Email Worker Process(es)
   |
   | POST https://api.sendgrid.com/v3/mail/send
   v
SendGrid / SES
   |
   | SMTP (port 587 STARTTLS or 465 SMTPS)
   v
User's email provider (Gmail, Outlook, etc.)
   |
   | Delivery status webhook (async)
   v
Webhook handler -> DB: UPDATE email_deliveries SET status = 'delivered'
```

**Retry logic in the email worker:**

```python
MAX_RETRIES = 3
BACKOFF_BASE = 2  # seconds

def process_email_job(job):
    for attempt in range(MAX_RETRIES):
        try:
            response = sendgrid.send(job)
            if response.status_code in (200, 202):
                return  # success
            if response.status_code == 400:
                # Permanent failure (invalid email, etc.) -- do not retry
                log_permanent_failure(job, response)
                return
        except (ConnectionError, TimeoutError):
            if attempt < MAX_RETRIES - 1:
                sleep(BACKOFF_BASE ** attempt + random.uniform(0, 1))
            else:
                log_exhausted_retries(job)
                dead_letter_queue.push(job)
```

**Idempotency:** Each email job has an `idempotency_key` (UUID). If the worker crashes after sending but before removing the job from the queue, the job will be re-processed. The email provider's idempotency key prevents double-sending.

---

### Alternative Token Storage in Redis

If using Redis instead of PostgreSQL for token storage:

```python
# Token creation
token_key = f"pwreset:{token_hash}"
token_data = {
    "user_id": user_id,
    "created_at": now_iso,
    "ip_hash": sha256(client_ip),
}
redis.setex(token_key, 3600, json.dumps(token_data))  # 1 hour TTL

# Token validation and atomic mark-as-used
# Use Lua script for atomicity:
lua_script = """
local data = redis.call('GET', KEYS[1])
if not data then return nil end
local deleted = redis.call('DEL', KEYS[1])
if deleted == 0 then return nil end  -- someone else just used it
return data
"""
result = redis.eval(lua_script, 1, token_key)
# If result is nil: token not found or race condition
# If result is data: token claimed atomically
```

The Lua script is executed atomically in Redis — no other command can execute between the GET and DEL. This is the Redis equivalent of PostgreSQL's `UPDATE WHERE used_at IS NULL` atomic pattern.

---

## 5. Authentication & Authorization Flow

### The Reset Token AS the Authentication Credential

In the password reset flow, there is no session-based or JWT-based authentication. The reset token IS the authentication credential. Understanding this is fundamental.

**Trust model:**

```
Physical access to email inbox
    => Ability to read the reset token
    => Ability to set a new password
    => Ability to access the account
```

This is why:
1. The email channel must be secure (TLS on SMTP delivery).
2. The token must have sufficient entropy (256 bits — unforgeable).
3. The token must expire (1 hour — limits the theft window).
4. The token must be single-use (prevents replay).
5. All active sessions must be invalidated when the token is used (ensures the attacker — if there was one — loses access).

---

### Token Entropy Analysis

```
raw_token = CSPRNG(32 bytes) = 256 bits of entropy

Probability of guessing: 1 / 2^256 ≈ 8.6 x 10^-78

At 1 billion guesses per second:
  Time to exhaust search space: 2^256 / 10^9 seconds
  ≈ 1.16 x 10^68 seconds
  ≈ 3.67 x 10^60 years

This is computationally infeasible.
```

**Minimum acceptable token size:** 128 bits (16 bytes). At this size, the search space is still 2^128 — sufficient. Many systems use 32 bytes (256 bits) as a safety margin.

**What's NOT acceptable:**
- UUID v4 as reset token: UUID v4 has only 122 bits of entropy (6 bits are fixed version/variant bits). Technically sufficient but using a UUID is a code smell — UUIDs were not designed as security tokens.
- Timestamp + user_id hash: Predictable input → predictable output. Completely broken.
- MD5 or SHA-1 of any predictable data: Same issue.
- PRNG (not CSPRNG): `Math.random()` in JavaScript, `random.random()` in Python — these are NOT cryptographically secure. Predictable from observable outputs.

---

### Trust Boundaries in the Reset Flow

```
TRUST BOUNDARY 1: Internet -> API
  - All input is untrusted
  - Rate limiting enforced here
  - Input validation here

TRUST BOUNDARY 2: Token in Email
  - The email channel is semi-trusted
  - DKIM/SPF/DMARC authenticate the email
  - TLS encrypts the email in transit (SMTP over TLS)
  - The email inbox is the trust anchor
    (assumed: only the legitimate user can read their inbox)

TRUST BOUNDARY 3: Token submission -> API
  - The submitted token is untrusted until validated
  - SHA-256(submitted_token) compared to DB-stored hash
  - All token properties validated before any side effects

TRUST BOUNDARY 4: API -> Database
  - Trusted internal channel (private subnet + TLS)
  - DB user has only necessary permissions (SELECT/INSERT/UPDATE on specific tables)
  - No DROP, no TRUNCATE, no superuser

TRUST BOUNDARY 5: API -> Email Provider
  - API key authentication (bearer token in header)
  - TLS transport to email provider
  - The email provider is a trusted third party
    (but: a compromised email provider API key = ability to send phishing emails)
```

---

### What Happens After Successful Reset: Session Invalidation

When a password is successfully reset, all existing sessions for that user must be invalidated. This covers the scenario where:
- An attacker has an active session (they know the old password).
- A legitimate user wants to force a logout of all devices after suspecting compromise.

**Implementation (Redis-based sessions):**

```python
# Get all session IDs for this user
session_ids = redis.smembers(f"user_sessions:{user_id}")

# Delete all sessions (pipeline for efficiency)
pipe = redis.pipeline()
for session_id in session_ids:
    pipe.delete(f"session:{session_id}")
pipe.delete(f"user_sessions:{user_id}")
pipe.execute()
```

**Implementation (JWT-based sessions with blacklist):**

```python
# Increment the user's token version
new_version = db.execute(
    "UPDATE users SET token_version = token_version + 1 WHERE id = $1 RETURNING token_version",
    user_id
).fetchone().token_version

# Any JWT with version < new_version is now invalid
# The JWT validator checks: if jwt.version < db.token_version: reject
```

**If neither mechanism is implemented:** An attacker who had the old session retains access indefinitely until the session expires. This is a critical security gap — password reset must include session invalidation.

---

## 6. Data Flow

### Complete Data Transformation Pipeline

```
Phase 1 (Request side):

[User input: "user@example.com"]
    |
    v [HTTP body parse]
[Raw string: "user@example.com"]
    |
    v [Normalize: lowercase, trim]
["user@example.com"]
    |
    v [Validate: format, length]
[Valid email string]
    |
    v [PostgreSQL parameterized query]
[DB row: {id: UUID, email: string, is_active: bool}]
    |
    v [CSPRNG]
[raw_token: 32 random bytes]
    |
    v [base64url encode]
[token_string: "dGhpcyBpcyBhIHNlY3VyZSByZXNldCB0b2tlbg"]
    |
    v [SHA-256]
[token_hash: "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"]
    |
    +--> [Stored in PostgreSQL as token_hash] (never the raw token)
    |
    v [Embed in reset URL]
["https://app.example.com/reset-password?token=dGhpcyBpcyBhIHNlY3VyZSByZXNldCB0b2tlbg"]
    |
    v [Email job JSON]
[{"to": "user@...", "reset_url": "https://...", ...}]
    |
    v [Redis LPUSH]
[In email queue]
    |
    v [Email worker: SendGrid API call]
[In email provider's delivery queue]
    |
    v [SMTP over TLS]
[In user's email inbox]

Phase 2 (Confirmation side):

[User input: token from URL + new password]
    |
    v [HTTP body parse]
[{token: "dGhpcyBpcyBhIHNlY3VyZSByZXNldCB0b2tlbg", new_password: "..."}]
    |
    v [SHA-256(token)]
[token_hash: "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"]
    |
    v [PostgreSQL lookup by token_hash]
[{id: UUID, user_id: UUID, expires_at: timestamp, used_at: null}]
    |
    v [Validation: not used, not expired]
[validated token record]
    |
    v [PostgreSQL UPDATE: mark used_at = NOW() -- atomic]
[Token consumed]
    |
    v [Argon2id hash new_password]
[password_hash: "$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>"]
    |
    v [PostgreSQL UPDATE users SET password_hash = ?]
[Password updated]
    |
    v [Redis DEL: invalidate all sessions]
[Sessions invalidated]
    |
    v [Async: confirmation email + audit event]
[Flow complete]
```

---

### Serialization Formats

| Stage | Format | Encoding | Notes |
|---|---|---|---|
| HTTP request body | JSON | UTF-8 | Content-Type: application/json |
| Email in transit | MIME | Base64/QP | HTML email body |
| Token (user-facing) | Raw bytes | base64url | URL-safe, no padding |
| Token (database) | Hash | Hex string (SHA-256 = 64 chars) | Never plaintext |
| Email job (queue) | JSON | UTF-8 | Published to Redis/SQS |
| Password hash | PHC string | ASCII | `$argon2id$v=19$...` |
| Audit events | JSON or Protobuf | UTF-8 | Published to Kafka |
| Session invalidation | Redis key deletion | - | Key: `session:<id>` |

---

### What's Never Stored

The raw reset token is **never** written to persistent storage. It exists in memory:
1. In the CSPRNG output buffer (briefly, in the API server process).
2. In the email job JSON (briefly, in Redis queue — consumed and deleted by worker).
3. In the email body (persisted in the email provider's systems and user's inbox — this is unavoidable and acceptable; the email IS the delivery channel).
4. In the URL query parameter (in the browser's address bar and potentially history).
5. In the POST body of the confirm request (transmitted to the API, then immediately hashed and discarded).

The token hash is stored in PostgreSQL for validation purposes only.

---

## 7. Security Controls

### Token Security Properties (Required)

The reset token must satisfy ALL of these properties simultaneously:

| Property | Requirement | Implementation |
|---|---|---|
| Unpredictability | Must not be guessable | CSPRNG (not PRNG) |
| Sufficient entropy | 128-bit minimum, 256-bit recommended | `secrets.token_urlsafe(32)` |
| Uniqueness | Must not collide with existing tokens | UUID-level uniqueness via CSPRNG |
| Single-use | Can only be used once | Mark used_at before password update |
| Time-limited | Must expire | expires_at = created_at + 1 hour |
| User-bound | Can only reset one specific user's password | Stored with user_id; validated on use |
| Invalidatable | Can be revoked (new request supersedes old) | Supersede old tokens on new request |

---

### Encryption in Transit

**Browser → API:**
TLS 1.3 minimum. The reset token, new password, and email address are all transmitted in the encrypted TLS payload. Plain HTTP access must be impossible — enforced via:
- `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` header.
- nginx configuration: `listen 443 ssl;` — no port 80 listener.
- HSTS preload list submission.

**API → Email Provider:**
HTTPS (TLS 1.2/1.3) to the SendGrid/SES API. The reset URL (containing the raw token) is transmitted here.

**Email Provider → User's Email Server:**
SMTP over TLS (STARTTLS, negotiated, or SMTPS port 465). This is NOT end-to-end encryption. The email is decrypted at each hop. If the receiving email server doesn't support TLS, the email may fall back to plaintext SMTP — the token would be in the clear. Mitigation: configure `RequireTLS` mode on the email provider (rejects delivery if TLS is not available, rather than falling back to plaintext). SendGrid supports `require_tls: true` in the API call.

**API → PostgreSQL:**
TLS (SSL mode `verify-full`). The token hash, user data, and password hash are encrypted in transit to the database.

**API → Redis:**
TLS on the Redis connection. Session data and rate limit counters encrypted in transit.

---

### Encryption at Rest

**PostgreSQL:**
- Database-level encryption (LUKS on-disk or cloud-managed: AWS RDS with KMS).
- The `token_hash` is a SHA-256 hash — it is not the token, so disclosure of the database exposes only hashes that require finding a SHA-256 preimage (computationally infeasible with 256-bit entropy input).
- The `password_hash` is an Argon2id hash — designed to be computationally expensive to crack.

**Redis:**
- AWS ElastiCache encryption-at-rest (AES-256).
- The email queue contains raw reset tokens in the job payload (the email body URL). If Redis is compromised at this exact moment, tokens can be extracted. Mitigation: minimize the time window (email worker should dequeue immediately), and encrypt sensitive fields within the job JSON using the application layer before enqueuing.

---

### Input Validation — Complete Checklist

**Phase 1 (email input):**
- [ ] Type check: must be a string.
- [ ] Length: 5–254 characters (RFC 5321).
- [ ] Format: RFC-compliant email regex.
- [ ] No null bytes (`\x00`).
- [ ] No control characters.
- [ ] Normalize: lowercase, trim whitespace.
- [ ] No HTML/script content (email is not executed, but defense-in-depth).

**Phase 2 (token + new password input):**
- [ ] Token type: must be a string.
- [ ] Token length: exactly 43–44 characters (base64url of 32 bytes).
- [ ] Token format: base64url character set only `[A-Za-z0-9_\-]`.
- [ ] Token: no whitespace, no URL encoding of the already-URL-safe value.
- [ ] Password type: must be a string.
- [ ] Password minimum length: 12 characters (NIST SP 800-63B guidance).
- [ ] Password maximum length: 1024 characters (prevent bcrypt/Argon2 DoS).
- [ ] Password: check against HaveIBeenPwned k-anonymity API.
- [ ] Password: not equal to the email address.
- [ ] Password: confirm password matches (if two-field form).

---

### Access Control

The password reset flow is intentionally unauthenticated — no valid session is required. The reset token IS the authorization credential. This makes access control unusual compared to other endpoints:

- **No session required** for either endpoint.
- **No authentication header** required.
- **Rate limiting** is the primary access control mechanism preventing abuse.
- **Token validity** is the authorization check in Phase 2.

**Who can trigger a reset for any email?** Anyone who knows the email address. This is unavoidable — the reset initiation is public. The protection is: only the email recipient can complete the reset (they need the token from the email). Enumeration prevention (same response regardless of email existence) limits the information gained from triggering resets.

---

### Secrets Handling

**Secrets involved in the password reset flow:**

1. **Database connection string** (including password): Retrieved from AWS Secrets Manager / HashiCorp Vault at startup. Never in environment variables, config files, or code.
2. **Redis connection password**: Same — secrets manager.
3. **Email provider API key** (SendGrid API key / AWS access key for SES): Retrieved from secrets manager. The email worker needs this; the API server only needs it if calling the provider directly (vs. publishing to a queue).
4. **SMTP credentials** (if self-hosted): Secrets manager.
5. **Argon2id parameters** (not a secret, but a configuration): `m=65536, t=3, p=4`. These are public. Security comes from the computational cost, not the algorithm secrecy.

**Secret NOT involved:** The reset token itself is ephemeral — it's not a system secret but a user credential. It is never stored and never retrieved from secrets management.

---

## 8. Attack Surface Mapping

### Entry Points

```
EXTERNAL (internet-accessible) ATTACK SURFACE
============================================================

Phase 1 Endpoints:
  POST /auth/password/reset/request
    Input: email address
    Threats: account enumeration, spam/bombing, DoS
    Protection: rate limiting, enumeration prevention

Phase 2 Endpoints:
  POST /auth/password/reset/confirm
    Input: reset token + new password
    Threats: token guessing, brute force, replay, race conditions
    Protection: entropy, rate limiting, single-use, expiry

Optional Endpoint:
  GET /auth/password/reset/validate?token=...
    Input: reset token (for UX pre-validation)
    Threats: token exposure in logs, enumeration
    Protection: rate limiting, same-response-on-miss

The Email Link Itself:
  GET https://app.example.com/reset-password?token=...
    Input: token in URL
    Threats: token in logs, in Referer header, in browser history
    Protection: Referrer-Policy, log redaction, short TTL

INDIRECT SURFACES:
  - Email provider API key (stolen -> send phishing emails)
  - DNS (hijacking -> redirect to attacker-controlled server)
  - TLS CA (mis-issuance -> MitM on reset submission)
  - Email provider (compromised -> read reset emails)
  - User's email account (compromised -> attacker uses reset)
  - Browser extensions (can read page content, including token in URL)

INTERNAL SURFACES:
  - Redis (rate limit bypass, token theft from queue)
  - PostgreSQL (token_hash extraction -> offline attack)
  - Email worker (compromise -> exfiltrate tokens before sending)
```

### Attack Surface Diagram

```
                              INTERNET
                                 |
                   +-------------+-------------+
                   |                           |
          +--------v-------+         +---------v--------+
          |  WAF / CDN     |         | Email Provider   |
          | (rate limit,   |         | (SendGrid / SES) |
          |  DDoS protect) |         |                  |
          +--------+-------+         +---------+--------+
                   |                           |
          +--------v---------------------------v--------+
          |              nginx (TLS termination)        |
          |                                             |
          | ATTACK: TLS downgrade, cert issues,         |
          |         host header injection               |
          +--------+------------------------------------+
                   |
          +--------v-----------------+
          |   Auth API Service       |
          |                          |
          | ATTACK:                  |
          | - Email enumeration      |
          | - Rate limit bypass      |
          | - Token parameter attack |
          | - Password DoS (Argon2)  |
          | - Race condition (use)   |
          | - Timing oracle          |
          +---+----------+----------+
              |          |
    +---------v---+  +---v---------+
    |  Redis      |  | PostgreSQL  |
    | (rate limit,|  | (users,     |
    |  sessions,  |  |  tokens)    |
    |  email Q)   |  |             |
    |             |  | ATTACK:     |
    | ATTACK:     |  | - SQLi      |
    | - Auth      |  | - Token     |
    |   bypass    |  |   dump      |
    | - Token     |  | - User      |
    |   theft     |  |   enumerat. |
    |   from Q    |  |             |
    +-------------+  +-------------+
              |
    +---------v-----------+
    |   Email Worker      |
    |                     |
    | ATTACK:             |
    | - Token exfil       |
    |   (between dequeue  |
    |    and send)        |
    | - Bounce/complaint  |
    |   abuse             |
    +---------------------+

TRUST BOUNDARIES:
  [TB-1] Internet -> nginx: Zero trust. All input untrusted.
  [TB-2] nginx -> Auth API: Semi-trusted. Internal network.
  [TB-3] Auth API -> Redis: Trusted. Private subnet + auth.
  [TB-4] Auth API -> PostgreSQL: Trusted. Private subnet + auth.
  [TB-5] Auth API -> Email Worker: Trusted. Same VPC / in-process.
  [TB-6] Email Worker -> Email Provider: Authenticated (API key). External.
  [TB-7] Email -> User Inbox: Trusted once delivered (DKIM verified).
```

---

## 9. Attack Scenarios (Very Detailed)

### 9.1 — Account Enumeration via Response Differentiation

**Attacker Assumptions:**
- Attacker wants to know which email addresses are registered in the system.
- The attacker has a list of 1 million email addresses to check.
- The application returns different responses for registered vs. unregistered emails.

**Step-by-Step Execution:**

1. Attacker scripts POST requests to `/auth/password/reset/request`:
   ```python
   import requests
   emails = load_email_list("emails.txt")  # 1 million emails
   for email in emails:
       r = requests.post("https://api.example.com/auth/password/reset/request",
                         json={"email": email})
       if r.status_code == 200 and "check your inbox" in r.text:
           print(f"REGISTERED: {email}")
       elif r.status_code == 404:
           print(f"NOT REGISTERED: {email}")
   ```

2. If the API returns 404 for unregistered emails and 200 for registered: attacker learns which emails are accounts.

3. **Timing variant:** Even if both paths return 200, if the response time differs (200ms for registered due to DB write, 5ms for unregistered with early return), a timing attack reveals registration status:
   ```python
   import time
   start = time.time()
   r = requests.post(...)
   duration = time.time() - start
   if duration > 0.1:  # 100ms threshold
       print(f"LIKELY REGISTERED: {email}")
   ```

**Why This Works (Without Mitigation):**
Different code paths have different execution times. A registered-user path (DB write, token generation, queue publish) takes 200–300ms. An unregistered-user path (early return after DB SELECT returns empty) takes 5–10ms. The 300ms difference is easily measurable over a network.

**Where Detection Could Happen:**
- Rate limiting by IP: if the attacker fires 1000 requests per minute from one IP, rate limiting triggers.
- Alert on high request rate to `/auth/password/reset/request` from a single IP.
- Alert on a large proportion of requests that are for emails NOT in the database.

**Mitigation:**
- Return the identical response body regardless of email existence.
- Normalize response time: if user doesn't exist, still perform a dummy Argon2id hash or sleep for a randomized duration matching the average "user found" response time.
- Per-endpoint rate limiting that triggers regardless of outcome.

---

### 9.2 — Reset Token Theft via Referrer Header Leakage

**Attacker Assumptions:**
- The reset page (`/reset-password?token=...`) loads third-party scripts (Google Analytics, Intercom, Hotjar, etc.).
- The page does not set `Referrer-Policy: no-referrer`.
- These third-party scripts make requests to their own servers.

**Step-by-Step Execution:**

1. User clicks reset link. Browser navigates to:
   ```
   https://app.example.com/reset-password?token=dGhpcyBpcyBhIHNlY3VyZSByZXNldCB0b2tlbg
   ```

2. The SPA page loads. It includes a Google Analytics script tag.

3. Google Analytics makes a request to its servers:
   ```http
   GET https://www.google-analytics.com/collect?...
   Referer: https://app.example.com/reset-password?token=dGhpcyBpcyBhIHNlY3VyZSByZXNldCB0b2tlbg
   ```

4. The full reset URL, including the token, appears in the Referer header sent to Google Analytics. This is logged in Google Analytics event data.

5. **If the app owner has malicious actors with analytics access** (or if Google Analytics is breached), the reset token is exposed.

6. Attacker uses the token immediately (before the user does):
   ```
   POST /auth/password/reset/confirm
   {"token": "dGhpcyBpcyBhIHNlY3VyZSByZXNldCB0b2tlbg", "new_password": "attacker_password"}
   ```

7. Attacker now controls the account.

**Variants of the same attack:**
- nginx access logs: The GET `/reset-password?token=...` is logged in the web server access log. Anyone with log access can extract tokens.
- Browser history: The URL is saved in the browser's history. Physical access to the device, or a malicious extension, can read history.
- Proxy logs: Corporate proxy servers that inspect HTTPS traffic (TLS inspection) log the URL including query parameters.

**Detection:**
- Token used from a different IP/device than the one that clicked the link (soft signal — could be legitimate e.g. mobile vs. desktop).
- Token used within seconds of being clicked: unusually fast.

**Mitigation:**
1. Set `Referrer-Policy: no-referrer` on the reset page response: the browser omits the Referer header entirely.
2. Strip query parameters in nginx access logs: `$uri` instead of `$request_uri` in log format.
3. Use `Content-Security-Policy: default-src 'self'` on the reset page — no third-party scripts can load.
4. Consider POST-based token submission instead of URL parameter (token in POST body instead of URL). But this doesn't eliminate the access log risk for the initial GET.
5. Token-in-fragment: `#token=...` — the fragment is never sent to the server and never appears in the Referer header. But JavaScript reads `window.location.hash`. This is a reasonable approach that eliminates server-side log exposure.

---

### 9.3 — Email Bombing / Reset Spam

**Attacker Assumptions:**
- The attacker knows the target's email address.
- The attacker wants to either: (a) harass the victim with constant reset emails, or (b) trigger so many resets that the email provider rate-limits or blocks the application's sending domain.

**Step-by-Step Execution:**

1. Attacker sends 1000 POST requests to `/auth/password/reset/request` with the victim's email:
   ```python
   while True:
       requests.post("https://api.example.com/auth/password/reset/request",
                     json={"email": "victim@example.com"})
   ```

2. **Without rate limiting:** The application generates 1000 reset tokens, queues 1000 emails, the email provider sends 1000 emails. Victim's inbox is flooded with reset emails.

3. **Side effects:**
   - The sending domain accumulates spam complaints from the victim (if they mark as spam → domain reputation damage → future legitimate emails go to spam for ALL users).
   - The email provider rate-limits or suspends the account.
   - Database fills with 1000 `password_reset_tokens` rows (usually harmless at this scale but a DoS vector).

4. **Without token supersession:** Each of the 1000 tokens is valid. The attacker doesn't know which one the victim clicked — but all 1000 are still active, creating unnecessary exposure.

**Why This Is Serious Even Without Credential Compromise:**
Email bombing is a common tactic to hide other malicious emails. The attacker triggers hundreds of reset emails to flood the victim's inbox, then sneaks a phishing email into the deluge. The victim, overwhelmed, misses the actual attack.

**Detection:**
- Alert: same email receives >3 reset requests within 1 hour.
- Alert: global reset request rate exceeds baseline by 10x.
- Monitor email provider complaint rate.

**Mitigation:**
1. **Per-email rate limiting:** Max 3 reset emails per email address per hour. Return 200 with generic message even when rate-limited (don't reveal that the email is rate-limited — that's enumeration).
2. **Per-IP rate limiting:** Max 10 reset requests per IP per 15 minutes.
3. **CAPTCHA after first failure:** On subsequent reset requests from the same IP within 15 minutes.
4. **Token supersession:** New request automatically invalidates old tokens. Only 1 active token at any time, regardless of how many requests were made.

---

### 9.4 — Race Condition: Double-Use of Reset Token

**Attacker Assumptions:**
- Attacker has stolen a valid reset token (e.g., from email interception or Referer leakage).
- The application processes token validation and token invalidation in a non-atomic way.

**Step-by-Step Execution:**

1. Attacker has the reset token: `TOKEN_VALUE`.

2. The victim and attacker both submit the token at the exact same millisecond:
   - Thread A (legitimate user): `POST /reset/confirm {token: TOKEN_VALUE, new_password: "user_pass"}`
   - Thread B (attacker): `POST /reset/confirm {token: TOKEN_VALUE, new_password: "attacker_pass"}`

3. **Vulnerable code flow (non-atomic):**
   ```python
   # Thread A and Thread B both execute these steps concurrently:
   token_data = db.query("SELECT * FROM tokens WHERE token_hash = ?", hash(token))
   # Both see: used_at = NULL (valid!)
   if token_data.used_at is None and token_data.expires_at > now:
       # Both threads pass this check
       db.execute("UPDATE users SET password_hash = ?", new_hash)
       db.execute("UPDATE tokens SET used_at = NOW()", token_id)
       # Last write wins -- one sets user_pass, one sets attacker_pass
   ```

4. If Thread B's UPDATE executes last, the attacker's password is set. The victim's reset "succeeded" but the attacker's password is now in effect.

**Why This Works:**
Without an atomic "check-and-set" pattern, two concurrent requests can both pass the "is the token valid?" check before either of them marks it as used.

**Mitigation — Atomic mark-as-used:**
```sql
-- The UPDATE only affects a row if used_at IS NULL
-- If 0 rows affected: token was already used by a concurrent request
UPDATE password_reset_tokens
SET used_at = NOW()
WHERE token_hash = $1
  AND used_at IS NULL
  AND expires_at > NOW()
RETURNING id, user_id;

-- If this returns 0 rows: ABORT with "invalid or expired token" error
-- If this returns 1 row: proceed with password update for that user_id
```

The `WHERE used_at IS NULL` condition makes this atomic at the database level. PostgreSQL's row-level locking ensures only one transaction can win the race. The other transaction gets 0 rows back and must abort.

**Detection:**
- Alert on duplicate token submission attempts (same token submitted twice, even milliseconds apart).
- Log: `token_double_use_attempt` event with both request IDs.

---

### 9.5 — Subdomain Takeover + Cookie Injection for Token Theft

**Attacker Assumptions:**
- `app.example.com` is the reset link destination.
- `static.example.com` was previously used for a third-party service (e.g., GitHub Pages) and its CNAME still points to GitHub Pages infrastructure.
- The attacker can claim the GitHub Pages site at `static.example.com`.

**Step-by-Step Execution:**

1. Attacker identifies a dangling CNAME:
   ```
   static.example.com -> someproject.github.io
   ```
   The GitHub Pages project no longer exists.

2. Attacker creates a GitHub Pages project at `someproject.github.io` and claims `static.example.com`.

3. From `static.example.com`, the attacker can set cookies for `.example.com` (if the session/CSRF cookie is scoped to `.example.com` rather than `app.example.com`):
   ```javascript
   // Attacker's page on static.example.com:
   document.cookie = "tracking_id=attacker_value; domain=.example.com; path=/";
   ```

4. This is a cookie injection — not directly stealing the reset token, but:
   - If the reset page uses CSRF tokens stored in cookies, the attacker can override the CSRF token.
   - If the application accepts a `session_id` cookie value it doesn't recognize and creates a new session for it (session fixation), the attacker fixes the session before the reset completes.

5. **More targeted attack:** The attacker registers a service worker on `static.example.com` (if it shares the registration scope with `app.example.com`). Service workers can intercept requests from pages on the same site. The attacker's service worker intercepts the reset confirmation POST and exfiltrates the token.

**Detection:**
- DNS monitoring: Alert when `CNAME` targets change or when a previously-404 subdomain starts returning 200.
- CSP: `Content-Security-Policy` on the reset page can restrict service worker registration scope.

**Mitigation:**
- Scope cookies to the specific host: `Domain=app.example.com` (NOT `.example.com`).
- Or use the `__Host-` cookie prefix: `Set-Cookie: __Host-session=...; Secure; Path=/; HttpOnly` — cannot be set for any domain scope, only the exact host.
- Monitor and clean up DNS records for abandoned subdomains.
- Set `Content-Security-Policy` on the reset page: `default-src 'self'` — limits what third-party resources can load.

---

### 9.6 — Argon2 DoS on Password Reset Confirmation

**Attacker Assumptions:**
- The `/auth/password/reset/confirm` endpoint hashes the new password with Argon2id (200ms, 64MB per operation).
- Rate limiting on this endpoint is weak or only IP-based.
- The attacker has a botnet of 10,000 IPs.

**Step-by-Step Execution:**

1. Attacker generates valid-looking (but invalid) reset tokens: `base64url(random(32 bytes))` — 43-char strings that pass format validation.

2. Attacker distributes requests across 10,000 IPs:
   ```python
   # Each IP sends one request per minute:
   POST /auth/password/reset/confirm
   {"token": "random_43_char_base64url", "new_password": "a" * 1024}
   ```

3. The API:
   a. Passes format validation (token looks valid, password is 1024 chars).
   b. Hashes the token: `SHA-256(random_token)` — fast.
   c. Queries DB: `SELECT ... WHERE token_hash = ?` — miss (token not in DB).

4. **Wait** — if the implementation hashes the password BEFORE querying the DB for the token:
   ```python
   # WRONG ORDER:
   new_hash = argon2.hash(new_password)  # 200ms, 64MB -- runs for INVALID tokens!
   token_data = db.query("SELECT ... WHERE token_hash = ?", hash(token))
   if not token_data: raise InvalidToken()  # too late -- already did Argon2
   ```

5. With 10,000 IPs sending 1 request per minute each: 10,000/60 ≈ 167 Argon2id operations per second. A 4-core server handling ~20 Argon2 operations per second is saturated. CPU and memory consumed by invalid token requests.

**Why This Works:**
Placing the computationally expensive operation BEFORE the cheap validation check creates an amplified DoS vector. An attacker with a small botnet can exhaust a backend server.

**Mitigation:**
1. **Always validate the token BEFORE hashing the password:**
   ```python
   # CORRECT ORDER:
   token_data = db.query("SELECT ... WHERE token_hash = ?", hash(token))
   if not token_data: raise InvalidToken()  # fast fail
   # Only now do the expensive operation:
   new_hash = argon2.hash(new_password)  # 200ms, 64MB
   ```

2. **Password length limit BEFORE hashing:** Check `len(new_password) <= 1024` before calling Argon2id. A 10MB password would take seconds to hash even with Argon2.

3. **Rate limit on confirm endpoint:** Even with distributed IPs, apply a global rate limit on the confirm endpoint based on token format/hash prefix.

---

### 9.7 — SMTP Interception / Token in Transit

**Attacker Assumptions:**
- Attacker is a malicious employee at the email provider (SendGrid internal access).
- OR: The receiving email server (`example.com` email provider) doesn't support TLS.
- OR: The attacker is a network-level eavesdropper between the email provider's MTA and the recipient's email server.

**Step-by-Step Execution:**

1. Attacker intercepts the SMTP connection between SendGrid's MTA and the victim's email server (e.g., Gmail). Without TLS, this is plaintext:
   ```
   From: noreply@example.com
   To: victim@example.com
   Subject: Reset your password
   
   Click here to reset your password:
   https://app.example.com/reset-password?token=dGhpcyBpcyBhIHNlY3VyZSByZXNldCB0b2tlbg
   
   This link expires in 1 hour.
   ```

2. Attacker extracts the reset URL and uses the token immediately.

3. If the attacker acts before the victim opens the email: account takeover.

**Why This Is Partially Mitigated by Design:**
- Major email providers (Gmail, Outlook) support TLS (STARTTLS) — the SMTP connection to them will be encrypted.
- SendGrid's SMTP sends use STARTTLS when available.
- The token has a 1-hour TTL — the window is limited.

**Why It's Still a Risk:**
- Some corporate email servers don't support TLS (legacy infrastructure).
- The email is stored at the email provider indefinitely — a future email provider breach exposes old reset links (though those are expired).

**Mitigation:**
- `RequireTLS: true` in SendGrid API — refuse delivery if TLS is unavailable.
- Use SES with `StartTlsPolicy: Require`.
- Token TTL of 1 hour limits the exposure window.
- Send a notification: "A password reset was requested." If the user didn't request it, they should contact support immediately.

---

## 10. Failure Points

### Under Load

**Email queue backup:**
If the email provider is slow or the email worker pool is undersized, the email queue (Redis List or SQS) grows. Reset emails arrive late (minutes or hours instead of seconds). The API response is still instant (async), but the user experience degrades.

- **Detection:** Queue depth metric > threshold. Email delivery latency > 60 seconds.
- **Mitigation:** Auto-scale email worker pool based on queue depth. Use SQS (managed queue) with dead-letter queue for failed jobs.

**Argon2id under high login/reset load:**
If password resets surge simultaneously (e.g., after a security breach notification pushes millions of users to reset), the Argon2id computation on the confirm endpoint saturates CPU.

- **Detection:** API server CPU > 90%, p99 latency on `/reset/confirm` > 5s.
- **Mitigation:** Separate auth service instances from API instances. Rate limit the confirm endpoint. Auto-scale on CPU.

**PostgreSQL connection exhaustion:**
The reset flow requires two DB operations in the confirm path (token lookup + two UPDATEs). Under high concurrency, connection pool exhaustion causes requests to wait for a connection.

- **Detection:** DB connection wait time > 100ms. PgBouncer queue depth > 0.
- **Mitigation:** PgBouncer in transaction-mode pooling. Increase max_connections carefully.

### Under Attack

**Redis rate limit bypass:**
An attacker with a distributed botnet (one IP per request) bypasses per-IP rate limiting entirely. The per-email rate limiting is the only remaining defense.

- **Mitigation:** Per-email rate limiting is more effective than per-IP for this attack. Additionally: behavioral rate limiting (detect and block IPs sending only reset requests, no other traffic — anomalous for legitimate users).

**Token brute force against the confirm endpoint:**
Attacker guesses 43-character base64url strings. With 256-bit entropy, this is computationally infeasible. But if rate limiting on the confirm endpoint is absent and the token length is short (e.g., 6-digit numeric codes), brute force is viable.

- **Mitigation:** 256-bit token entropy. Rate limit confirm endpoint (5 attempts per minute per IP globally, 1 attempt per token_prefix).

**PostgreSQL DoS via reset token table growth:**
An attacker triggers 1 million reset requests for 1 million different email addresses (using email addresses they own or that don't exist). If the application inserts a token row for non-existent accounts (don't!), the table grows unboundedly.

- **Mitigation:** Only insert token rows when the user exists AND is active. The rate limit prevents this at scale. Run a cleanup job: delete expired tokens older than 24 hours.

### Common Misconfigurations

| Misconfiguration | Impact | Fix |
|---|---|---|
| Token stored in plaintext in DB | DB breach = all reset tokens usable | Store SHA-256(token); return raw token in email only |
| No token expiry | Stolen token valid indefinitely | 1-hour expiry. Enforce at application layer AND DB column. |
| No single-use enforcement | Token can be reused after first use | Atomic mark-as-used before password update |
| No session invalidation on reset | Attacker retains active sessions | DEL all sessions for user on password change |
| Timing difference between user-found and user-not-found | Email enumeration | Constant-time response: normalize timing, same response |
| Token in URL + no Referrer-Policy | Token leaks to third-party scripts via Referer header | `Referrer-Policy: no-referrer` + CSP on reset page |
| Hashing password before token validation | Argon2 DoS via invalid tokens | Validate token first; hash password second |
| No rate limiting on email field | Email bombing a specific address | Per-email rate limit (3 resets per hour per email) |
| Short token (6 digits, numeric) | Brute-forceable in seconds with no rate limit | 256-bit CSPRNG token minimum |
| Using PRNG not CSPRNG | Predictable token | `secrets` module in Python; `crypto.randomBytes()` in Node |
| Reset link sent via HTTP (not HTTPS) | Token in plaintext on network | HTTPS always; HSTS preload |
| No token supersession | Multiple valid tokens accumulate | New reset request supersedes all old tokens for that user |
| Email enumeration via response code | Account existence leak | Always return 200 with identical response |
| Resetting inactive/deleted accounts | May reactivate accounts | Check `is_active` before generating token |

---

## 11. Mitigations

### Defense-in-Depth Strategy

**Layer 1 — Token Cryptographic Strength:**
- 256-bit CSPRNG token. Non-negotiable.
- SHA-256 hash stored in DB. Raw token never persisted.
- Token bound to specific user_id at creation time.
- Token expires in 1 hour (absolute, not sliding).
- Token is single-use (atomic mark-as-used).
- New request supersedes all old tokens for the user.

**Layer 2 — Email Channel Security:**
- SMTP requires TLS (`RequireTLS: true`).
- DKIM signing on all outbound email.
- SPF and DMARC configured.
- `Referrer-Policy: no-referrer` on reset page.
- No third-party scripts on the reset page (strict CSP).
- Token in URL: strip from nginx logs, short TTL limits exposure.

**Layer 3 — Rate Limiting (Multi-Dimensional):**
- Per-IP: 10 requests to `/reset/request` per 15 minutes.
- Per-email: 3 reset emails per email per hour.
- Per-IP on `/reset/confirm`: 5 attempts per minute.
- Global: alert and throttle if reset volume exceeds 10x baseline.
- All rate limits return 200 with generic message (don't reveal the rate limit was hit — that's information).

**Layer 4 — Enumeration Prevention:**
- Identical response (status code, body, headers) for existing and non-existing emails.
- Constant-time response (normalize timing between code paths).
- Rate limiting applied before user lookup (so the limit applies equally to all).

**Layer 5 — Session Management:**
- All active sessions invalidated on password change.
- All active reset tokens for the user invalidated on password change.
- Confirmation email sent after password change: "Your password was changed. If this wasn't you, contact support."

**Layer 6 — Input Validation:**
- Email: format, length, normalize.
- Token: length, format (base64url charset), no whitespace.
- Password: min length, max length (Argon2 DoS prevention), breach check.
- Token validation BEFORE password hashing.

**Layer 7 — Observability and Response:**
- Alert on: high reset request rate per email, timing anomalies, race condition detection, token used twice.
- Incident response playbook: if mass account compromise detected, revoke all active reset tokens (`UPDATE password_reset_tokens SET used_at = NOW() WHERE used_at IS NULL`).

### Engineering Tradeoffs

| Decision | Security Benefit | Engineering Cost |
|---|---|---|
| Argon2id for password hashing | GPU-resistant; brute-force-resistant | 200ms + 64MB per operation; CPU-intensive |
| SHA-256(token) in DB | Mitigates DB compromise token theft | Extra computation on validation; lookup by hash |
| 1-hour token expiry | Limits theft window | Users who don't act within 1 hour must re-request |
| Token supersession | Limits active token count | Complicates UX (old links stop working) |
| Per-email rate limiting | Prevents bombing | Requires Redis storage of email-keyed counters |
| Same response for all cases | Prevents enumeration | Complicates user support (can't tell users "we didn't find that email") |
| Token in URL (vs. POST body) | Simpler implementation | Exposure in logs, history, Referer |
| RequireTLS on SMTP | Prevents interception | May cause delivery failures to legacy servers |

---

## 12. Observability

### Structured Log Events

```json
// Reset request initiated
{
  "timestamp": "2024-11-15T10:23:45.123Z",
  "event": "password_reset.request.initiated",
  "request_id": "req-uuid-abc123",
  "ip_hash": "sha256:a1b2c3...",
  "email_hash": "sha256:d4e5f6...",   // NEVER log plaintext email in high-volume logs
  "email_domain": "gmail.com",         // domain is less sensitive, useful for debugging
  "user_found": true,                  // be careful: this could be an enumeration log oracle
  // Better: don't log user_found at all, or only in encrypted audit logs
  "rate_limit_remaining": 2,
  "duration_ms": 145
}

// IMPORTANT: The above "user_found" field should NOT go to general logs
// It belongs only in encrypted, access-controlled audit logs

// Token generated and email queued
{
  "event": "password_reset.token.created",
  "request_id": "req-uuid-abc123",
  "user_id": "uuid-xyz",
  "token_id": "token-uuid",            // DB primary key, not the token itself
  "token_hash_prefix": "a665a4...",    // first 8 chars of hash for correlation
  "expires_at": "2024-11-15T11:23:45Z",
  "email_job_id": "job-uuid-def456"
}

// Email delivered (from webhook)
{
  "event": "password_reset.email.delivered",
  "job_id": "job-uuid-def456",
  "provider": "sendgrid",
  "delivery_latency_ms": 4230,
  "provider_message_id": "sg-msg-id-xyz"
}

// Token validation attempt
{
  "event": "password_reset.confirm.attempt",
  "request_id": "req-uuid-ghi789",
  "ip_hash": "sha256:...",
  "token_hash_prefix": "a665a4...",    // for correlation -- not enough to reconstruct
  "validation_result": "success",      // or: "not_found", "expired", "already_used"
  "duration_ms": 312,
  "argon2_ms": 289
}

// Password successfully reset
{
  "event": "password_reset.complete",
  "request_id": "req-uuid-ghi789",
  "user_id": "uuid-xyz",
  "ip_hash": "sha256:...",
  "sessions_invalidated": 3,
  "token_id": "token-uuid"
}

// Security events -- always log, never sample
{
  "event": "password_reset.token.double_use_attempt",
  "token_hash_prefix": "a665a4...",
  "first_use_request_id": "req-uuid-ghi789",
  "second_use_request_id": "req-uuid-jkl012",
  "ip_hash_second": "sha256:...",
  "severity": "HIGH"
}

{
  "event": "password_reset.rate_limit.exceeded",
  "type": "per_email",                 // or "per_ip"
  "ip_hash": "sha256:...",
  "email_domain": "gmail.com",         // not full email
  "limit": 3,
  "window_seconds": 3600,
  "severity": "MEDIUM"
}
```

**What NEVER appears in logs:**
- The raw reset token (it's a credential — equivalent to a password).
- The plaintext new password (obviously).
- The plaintext email address in high-volume logs (PII — hash it).
- The full token hash (128-char string — could be used for DB lookup if token not yet expired at log time). Use only the first 8–16 chars as a correlation ID.

---

### Metrics (Prometheus / CloudWatch)

```
# Counters
password_reset_requests_total{outcome="success|rate_limited|invalid_email"}
password_reset_emails_sent_total{provider="sendgrid|ses"}
password_reset_emails_delivered_total
password_reset_emails_bounced_total{reason="invalid_address|spam|other"}
password_reset_confirm_attempts_total{outcome="success|invalid_token|expired|already_used"}
password_reset_tokens_created_total
password_reset_tokens_superseded_total

# Histograms
password_reset_request_duration_seconds          # Phase 1 API latency
password_reset_confirm_duration_seconds          # Phase 2 API latency
password_reset_argon2_duration_seconds           # Password hashing time specifically
password_reset_email_delivery_latency_seconds    # From API response to delivery webhook
password_reset_token_lifetime_seconds            # How long tokens live before use/expiry

# Gauges
password_reset_email_queue_depth                 # Alert if > threshold
password_reset_active_tokens_count               # All non-expired, non-used tokens
password_reset_token_age_at_use_seconds          # How old was the token when used

# Error rates
password_reset_email_provider_errors_total{type="timeout|auth|rate_limit"}
password_reset_db_errors_total{operation="insert|update|select"}
```

---

### Distributed Traces

OpenTelemetry trace for Phase 1 (reset request):

```
HTTP POST /auth/password/reset/request [145ms total]
  ├── middleware.rate_limit_ip [1.2ms]
  │     └── redis.INCR ratelimit:ip:... [0.9ms]
  ├── middleware.rate_limit_email [1.1ms]
  │     └── redis.INCR ratelimit:email:... [0.8ms]
  ├── middleware.body_parse [0.3ms]
  ├── handler.reset_request [142ms]
  │     ├── db.query.user_lookup [6.5ms]
  │     │     └── postgres.SELECT [6.1ms]
  │     ├── crypto.csprng_generate [0.1ms]
  │     ├── crypto.sha256_hash [0.1ms]
  │     ├── db.query.supersede_old_tokens [4.2ms]
  │     ├── db.query.insert_token [5.3ms]
  │     ├── queue.email.publish [0.9ms]
  │     │     └── redis.LPUSH [0.7ms]
  │     └── audit.event.publish [0.2ms] (async)
  └── middleware.set_headers [0.05ms]
```

OpenTelemetry trace for Phase 2 (reset confirm):

```
HTTP POST /auth/password/reset/confirm [365ms total]
  ├── middleware.rate_limit_ip [1.1ms]
  ├── middleware.body_parse [0.3ms]
  ├── handler.reset_confirm [363ms]
  │     ├── crypto.sha256_hash_token [0.1ms]
  │     ├── db.query.token_lookup [5.8ms]
  │     │     └── postgres.SELECT [5.4ms]
  │     ├── validation.token_check [0.05ms]    # fast, in-memory
  │     ├── db.query.mark_token_used [4.1ms]   # atomic UPDATE
  │     ├── validation.password_check [2.3ms]  # including hibp check
  │     ├── crypto.argon2id_hash [289ms]       # dominant cost
  │     ├── db.query.update_password [4.7ms]
  │     ├── redis.session_invalidation [1.8ms]
  │     │     ├── redis.SMEMBERS user_sessions [0.6ms]
  │     │     └── redis.DEL x3 [1.2ms]
  │     └── audit.event.publish [0.2ms] (async)
  └── middleware.set_headers [0.05ms]
```

---

### Alerting Rules

| Metric / Condition | Alert? | Severity | Reason |
|---|---|---|---|
| `password_reset_requests_total` rate > 100/min per email | YES | HIGH | Email bombing attack |
| `password_reset_requests_total` rate > 1000/min globally | YES | CRITICAL | Large-scale attack |
| `password_reset.token.double_use_attempt` any event | YES | HIGH | Token theft suspected |
| `password_reset_confirm_attempts_total{outcome="invalid_token"}` spike | YES | HIGH | Token brute-force attempt |
| `password_reset_email_queue_depth` > 1000 | YES | MEDIUM | Email worker backed up |
| `password_reset_email_provider_errors_total` > 0 sustained | YES | HIGH | Email delivery broken |
| `password_reset_argon2_duration_seconds` p99 > 1s | YES | MEDIUM | Server overloaded |
| `password_reset_db_errors_total` > 0 | YES | CRITICAL | DB connection issue |
| Token used more than 30 minutes after creation | NO | -- | Normal (user slow to act) |
| Token expired without use | NO | -- | Normal (user didn't follow through) |
| Single reset request from known user | NO | -- | Expected |
| Email delivery latency 30–60s | NO | -- | Normal provider behavior |
| Email delivery latency > 5 minutes | YES | MEDIUM | Provider degradation |

---

## 13. Scaling Considerations

### Bottlenecks

**1. Argon2id on the confirm endpoint:**
This is the primary compute bottleneck. Each password reset confirmation consumes 200ms + 64MB RAM. A single app server instance with 4 cores and 8GB RAM can handle:

```
8GB RAM / 64MB per Argon2 = 125 concurrent Argon2 operations max
4 cores / 200ms per op = 20 ops/second sustained throughput
```

At 20 password reset completions per second, the server is saturated (CPU and RAM). For most applications this is fine — password resets are infrequent. But after a security incident requiring mass forced password resets, this becomes a bottleneck.

**Mitigation:** Horizontal scaling of the auth service. Argon2id work can be distributed across instances. Auto-scale based on CPU utilization (target 60%).

**2. Email queue worker throughput:**
Email providers have rate limits. SendGrid's free tier: 100 emails/day. Pro tier: up to 1.5 million/month. If millions of users need to reset simultaneously (after a breach disclosure), the email queue backs up.

**Mitigation:**
- SendGrid's dedicated IP: higher throughput.
- SES: much higher throughput with domain verification.
- Email worker pool: scale horizontally. Each worker pulls from the queue and sends.
- Priority queue: fresh reset tokens get higher priority than stale ones.

**3. PostgreSQL token table write contention:**
During a mass reset event, thousands of concurrent INSERT + UPDATE operations on `password_reset_tokens`. PostgreSQL can handle this (MVCC), but:
- Table bloat from expired tokens not yet cleaned up.
- Index maintenance on high write volume.

**Mitigation:**
- Partitioning `password_reset_tokens` by `expires_at` (range partitioning). Drop old partitions instead of DELETE (instant, no table scan).
- Cleanup job: `DELETE FROM password_reset_tokens WHERE expires_at < NOW() - INTERVAL '24 hours'`. Run hourly.
- BRIN index on `expires_at` for efficient cleanup queries.

**4. Redis rate limit key contention:**
Under an email bombing attack, a single email's rate limit key receives many INCR operations. Redis is single-threaded — this is fine, but the key should be short (hash the email, not store it as plaintext in the key).

---

### Horizontal vs. Vertical Scaling

**Auth service (stateless for reset flow):**
The reset request handler is fully stateless — it reads from DB, writes to DB, publishes to queue. Horizontally scalable. 10 instances handle 10x the load. nginx or an ALB distributes requests across instances.

**Email workers (consumer group):**
Multiple email worker instances can pull from the same queue (SQS or Redis List with BRPOP). Each worker atomically claims a job (SQS: message invisibility timeout; Redis: BRPOP gives one worker one job exclusively). Scale workers to match queue depth.

**Redis (rate limiting + queue):**
- Rate limiting: Redis single-node is sufficient for moderate scale (~100K requests/second). Redis Cluster for extreme scale.
- Email queue: For high throughput, migrate from Redis List to SQS (managed, highly scalable). SQS handles millions of messages per second.

**PostgreSQL:**
- Token table writes: Primary only (writes can't go to replicas). PgBouncer for connection pooling.
- User table reads (lookup by email on reset request): Can go to read replicas. Replication lag ~10ms — acceptable for this use case (we don't need real-time consistency for user lookup during reset).
- Partitioned token table: Allows efficient cleanup without full table scans.

---

### Consistency Tradeoffs

**Token creation must be durable before email is sent:**

```
WRONG order:
  1. Publish email job to queue
  2. Insert token to DB
  Problem: If DB insert fails after email is sent,
           the user receives a link that can never work.

CORRECT order:
  1. Insert token to DB (synchronous, durable)
  2. Publish email job to queue
  3. Return 200 to user
```

**Token mark-as-used before password update:**

```
WRONG order:
  1. Update password in DB
  2. Mark token as used
  Problem: If the process crashes between step 1 and 2,
           the token is still "valid" but the password has changed.
           The old token can be replayed to reset the password again.

CORRECT order:
  1. Mark token as used (atomic UPDATE WHERE used_at IS NULL)
     -- If 0 rows affected: race condition, abort
  2. Hash new password (Argon2id)
  3. Update password in DB
```

**Session invalidation consistency:**
After password reset, sessions in Redis must be deleted. If Redis is temporarily unavailable:
- Option A: Fail the password reset (return 500). Too strict — the password was already updated.
- Option B: Continue, log the session invalidation failure, queue a retry.
- Option C: Increment the user's `token_version` in PostgreSQL. Sessions check this on each request — even without Redis DEL, sessions with stale `token_version` are rejected on next use.

Option C is the most resilient: session invalidation doesn't depend on Redis availability.

---

## 14. Interview Questions

### Q1: Why do you return the same response (HTTP 200 with a generic message) for both registered and unregistered email addresses in the reset request? What specific attack does this prevent, and what are the edge cases?

**What it prevents:** User account enumeration. If the API returns 200 for registered emails and 404 (or a different message) for unregistered ones, an attacker can script thousands of requests to determine which email addresses have accounts. This user list is valuable for:
- Targeted phishing attacks (attacker knows the victim uses your service).
- Credential stuffing (attacker focuses on emails with known accounts).
- Harassment (attacker knows specific individuals use the service).

**The mechanism:** The server queries the database regardless of the result. The application proceeds as if the user exists (generating a token, publishing an email job) or silently does nothing (if the user doesn't exist). The response is identical in both cases: `200 OK {"message": "If an account..."}`.

**Edge cases and how to handle them:**

1. **Timing side-channel:** The "user exists" path takes longer (DB write, token generation, Redis publish) than the "user doesn't exist" path (DB read only, early return). An attacker can distinguish them by measuring response time. Fix: normalize timing by performing a dummy operation (fixed sleep, or a constant-time dummy hash) on the "not found" path.

2. **Rate limiting reveals information:** If you rate-limit per-email and return 429 for a rate-limited email, the attacker can infer that this specific email has been requested before (meaning it exists and someone requested a reset). Fix: return 200 with the generic message even when rate-limited.

3. **User support complications:** Support agents can't tell users "we didn't find that email" — which is actually fine for security. Support flow: "Please try the email you signed up with, or create a new account."

4. **Deactivated accounts:** Should a deactivated account receive a reset email? Security argument: No — don't reactivate accounts through reset. Return the same generic 200 but don't send the email and don't generate a token.

---

### Q2: Walk through the exact atomic operation that prevents race conditions when two concurrent requests try to use the same reset token simultaneously. What database primitive makes this safe?

**The problem:** Without atomicity, two concurrent requests can both pass the validity check (`used_at IS NULL`) before either marks the token as used. Both proceed, and the last-write-wins on the password update. An attacker who submits the stolen token simultaneously with the victim wins half the time.

**The solution — PostgreSQL row-level locking with conditional UPDATE:**

```sql
UPDATE password_reset_tokens
SET used_at = NOW()
WHERE token_hash = $1
  AND used_at IS NULL
  AND expires_at > NOW()
RETURNING id, user_id;
```

**How this is atomic:**

1. PostgreSQL processes this statement within a transaction (auto-commit if not explicit).
2. PostgreSQL places a row-level exclusive lock on the matching row when it processes the UPDATE.
3. Only ONE concurrent transaction can hold an exclusive lock on a specific row at a time. The second transaction blocks until the first releases the lock (on COMMIT or ROLLBACK).
4. The first transaction's UPDATE matches the row (used_at IS NULL) and sets used_at = NOW(). It commits. The lock is released.
5. The second transaction unblocks, re-evaluates the WHERE clause, and finds `used_at IS NOT NULL` (the first transaction set it). The UPDATE affects 0 rows.
6. The application checks `rowcount == 0` → returns 400 "Invalid or expired token."

**Why this is safe:** The `WHERE used_at IS NULL` condition is evaluated INSIDE the lock. There is no gap between "check" and "set" where another transaction can sneak in.

**Redis equivalent (Lua script):**

```lua
local data = redis.call('GET', KEYS[1])
if not data then return nil end
local deleted = redis.call('DEL', KEYS[1])
if deleted == 0 then return nil end
return data
```

Lua scripts in Redis are atomic — no other commands execute between the GET and DEL. This is the Redis equivalent of the PostgreSQL conditional UPDATE.

---

### Q3: The reset token is stored as SHA-256(token) in the database. If the database is compromised, can an attacker use the stored hashes to reset user accounts? Why or why not?

**Short answer:** No. The attacker cannot use stored hashes to complete a password reset.

**Why:**

The `/reset/confirm` endpoint requires the **raw token**, not the hash. The raw token is:
- 32 bytes of CSPRNG output = 256 bits of entropy.
- Base64url-encoded to 43 characters.
- Never stored anywhere (except transiently in the email body).

The lookup process is:
```
submitted_token -> SHA-256(submitted_token) -> DB lookup by hash -> match
```

An attacker with the database has SHA-256(raw_token). To submit a valid reset, they need raw_token such that SHA-256(raw_token) == stored_hash. This is the SHA-256 preimage problem — computationally infeasible with 256-bit entropy input:

```
Probability of finding preimage: 1 / 2^256
At 10^18 hash operations/second (current fastest hardware):
Time to find one preimage: 2^256 / 10^18 ≈ 3.67 x 10^58 years
```

**What the attacker CAN do with the database (different attacks):**
- Crack the password hashes (Argon2id makes this expensive but not impossible for weak passwords).
- Read user emails and other PII.
- Extract the token table structure to understand the schema.

**What they CANNOT do:**
- Reconstruct the raw token from its SHA-256 hash.
- Submit a reset using the stored hash (the endpoint hashes the submission and compares — `SHA-256(hash)` ≠ `hash` unless SHA-256(x) = x, which never happens).

**When would storing hashes NOT be sufficient?** If the token were derived from predictable input (e.g., SHA-256(user_id + timestamp)), the attacker could generate candidate inputs, hash them, and compare to the stored hashes. This is why the token MUST come from a CSPRNG, not any deterministic function.

---

### Q4: What is the correct order of operations in the reset confirmation flow, and what security vulnerability exists if the order is wrong?

**Correct order:**

```
1. Rate limit check
2. Parse and validate input format (token, password)
3. Hash the submitted token: SHA-256(token)
4. Lookup token record in DB by hash
5. Validate: token exists, not used, not expired
6. ATOMICALLY mark token as used (UPDATE WHERE used_at IS NULL)
   -- If 0 rows affected: abort with "invalid token"
7. Validate new password (length, breach check)
8. Hash new password with Argon2id
9. Update user's password_hash in DB
10. Invalidate all active sessions for this user
11. Return 200 success
```

**What goes wrong with wrong order:**

**Password hashed before token validated (steps 8 before 4):**
- An attacker submits thousands of random tokens with a long password (`"a" * 1024`).
- Each request: format validation passes → Argon2id runs (200ms + 64MB) → DB lookup fails (token not found) → abort.
- The Argon2id computation ran for nothing. CPU and memory saturated.
- This is the **Argon2 DoS vulnerability** — computationally expensive operation triggered by unauthenticated input.
- Fix: Always validate the token BEFORE hashing the password.

**Token marked as used AFTER password update (step 6 after step 9):**
- Attacker submits the stolen token simultaneously with the victim.
- Thread A updates the password to victim's choice. Thread B updates to attacker's choice.
- After both threads complete the password update, THEN both mark the token as used.
- Result: Last write wins for the password. First-to-reach-the-used-marking wins for the token status check in future.
- In some implementations this means the token can be "undeleted" (if the UPDATE racing means one thread doesn't see the other's used_at write).
- Fix: Mark as used FIRST (atomically). Only proceed to password update if the mark-as-used succeeded.

**New password written to DB before session invalidation (step 9 before 10):**
- If the process crashes between step 9 and 10, the password is changed but old sessions remain valid.
- An attacker who had the old session retains access indefinitely.
- Fix: Invalidate sessions immediately after password update. If session invalidation fails: fail gracefully, log, queue retry, or use the `token_version` approach.

---

### Q5: How would you implement a password reset flow that works correctly even if the email delivery fails completely? What guarantees can you provide to the user?

**The challenge:** The API returns 200 before the email is delivered (because email is async). If email delivery fails, the user sees "Check your inbox" but receives nothing.

**Guarantees you CAN provide:**
- The reset token is created and stored — it's valid and usable for 1 hour.
- If the user requests another reset, they can get a fresh token.
- The failure is logged and monitored.

**Guarantees you CANNOT provide:**
- That the email will definitely arrive (email is inherently unreliable).
- That the email will arrive within a specific time frame.

**Implementation for resilience:**

**1. Dead-letter queue (DLQ) + retry:**
If the email job fails after MAX_RETRIES attempts, it goes to a DLQ:
```python
sqs.send_message(
    QueueUrl=DEAD_LETTER_QUEUE_URL,
    MessageBody=job.serialize(),
    MessageAttributes={
        "failure_reason": "provider_error",
        "original_request_id": job.request_id,
        "retry_count": MAX_RETRIES
    }
)
```
Operations team monitors DLQ depth. Failed jobs can be manually re-processed or the user can be notified via another channel.

**2. Email status tracking + UX feedback:**
When the email job is processed, the worker updates a DB/Redis record:
```python
db.execute("UPDATE password_resets SET email_status = $1 WHERE job_id = $2",
           email_status, job_id)
```

The SPA can poll (or use websockets) to show: "Email sent ✓" or "Email delivery in progress..." or "Email delivery failed — please try again."

**3. Resend capability:**
Allow the user to request a resend: "Didn't receive the email? Click to resend." This creates a new token (superseding the old one) and queues a new email job.

**4. Alternative delivery:**
For users with a verified phone number: offer SMS as a fallback delivery channel for the reset token (or a numeric OTP). This is a secondary channel, not the primary.

**5. What to say in the UI:**
"If you don't receive an email within 5 minutes, check your spam folder or click 'Resend.' The link expires in 1 hour."

---

### Q6: Describe the email channel as a "trust anchor" for password reset. What attacks against the email channel would compromise the reset flow, and how do you mitigate them?

**Email as trust anchor:** The security model of password reset is: "only the person who can read the email at this address should be able to reset the account." The email inbox IS the second factor.

**Attacks against the email channel:**

**1. Email account compromise (most common):**
Attacker gains access to the victim's email account (phishing, credential stuffing, weak email password). From inside the inbox, the attacker can trigger and complete a password reset on any account using that email. Mitigation: outside the scope of the reset flow — email account security is the user's responsibility. Best practice: encourage users to enable 2FA on their email account.

**2. SMTP interception:**
Attacker intercepts the SMTP connection between the email provider and the receiving mail server. Without TLS, the email (including the reset URL) is in plaintext. Mitigation: `RequireTLS: true` on the sending side — refuse delivery to servers that don't support TLS.

**3. DNS hijacking of the email domain:**
Attacker modifies the MX records for `example.com` to point to their mail server. Reset emails are delivered to the attacker instead. Mitigation: DNSSEC on the domain. Monitor DNS records for unexpected changes.

**4. Email provider compromise:**
The email provider (SendGrid) is breached. Attacker can read outbound emails before delivery. Mitigation: short token TTL (1 hour) limits the window. Immediate notification to users about security incidents.

**5. Email address recycling:**
Some email providers recycle email addresses of deleted accounts. A previous owner's account email, recycled to a new person, could be used to reset the original account. Mitigation: When an email change is detected or an account is deleted, immediately revoke all active reset tokens for that email.

**6. Email forwarding abuse:**
User has set up email forwarding from their primary address to multiple addresses (e.g., to a shared inbox). The reset email goes to all forwarding destinations. Anyone with access to the shared inbox can complete the reset. Mitigation: UX — warn users that the reset link should be private. Application-level mitigation: bind the token to IP/device fingerprint (soft binding — reject if drastically different).

---

### Q7: A user reports they received a password reset email they didn't request. What are the possible causes, and what should the system do for each?

**Cause 1: Attacker is probing the account (reconnaissance):**
An attacker submits the victim's email to the reset flow to confirm the account exists. The victim receives a reset email out of nowhere.
- System response: The reset token is valid and will expire in 1 hour. The victim should do nothing — the token is useless without clicking the link.
- Correct behavior: Alert the user ("Someone requested a password reset for your account. If this wasn't you, you can ignore this email or contact support. Your account is still secure.")
- The email already says this. No further action needed unless the user reports it.

**Cause 2: Another user entered the wrong email address:**
User A meant to reset their own password but typed the victim's email by mistake.
- Same result as Cause 1 from the system's perspective.
- No action needed.

**Cause 3: An attacker is attempting account takeover:**
Attacker has the victim's email. They request a reset, then attempt to intercept the email (email compromise, SMTP interception).
- If successful: attacker uses the token to change the password.
- System response: Upon successful reset, NOTIFY the victim: "Your password was just changed from IP X in location Y. If this wasn't you, contact support immediately." Include a one-click "This wasn't me" link that locks the account.

**Cause 4: Mass reset event (security incident):**
The system detected a breach and triggered password resets for all users.
- The notification email should explain this: "Due to a security event, we're requiring all users to reset their passwords."

**What the system should do proactively:**

1. Include in the reset-request email: "If you didn't request this, no action is needed. Your account is secure. The link expires in 1 hour."
2. Include in the reset-success email: "Your password was changed from [location]. If this wasn't you, contact support at [link]. We've logged you out of all devices."
3. Allow users to report "This wasn't me" in both emails — triggers immediate account lockout and security review.
4. After N reset request emails without completion: alert the security team (someone is targeting this account).

---

### Q8: How would you design the password reset flow to be resilient to a complete Redis outage? What functionality breaks and what can continue?

**What uses Redis in the reset flow:**
1. Rate limiting counters (INCR/EXPIRE per IP and per email).
2. Email job queue (LPUSH/BRPOP — if Redis-based queue).
3. Session store (DEL on password change).

**What breaks with Redis down:**

**Rate limiting:** Cannot increment or check counters. Two options:
- **Fail open:** Assume not rate-limited, proceed normally. Risk: during outage, rate limiting is disabled. An attacker can hammer the endpoint. Short outages (minutes) are acceptable; prolonged outages are risky.
- **Fail closed:** Assume rate-limited, return 429 to all users. Completely blocks password reset functionality. Worse UX for a potentially low-security-risk window.
- **Recommended:** Fail open for the reset request endpoint (low risk — can't do damage without the email); fail closed for the confirm endpoint (higher risk — someone might brute-force tokens without rate limiting).

**Email queue (if Redis-based):** Cannot publish new email jobs. Options:
- Fall back to synchronous email delivery (call SendGrid directly in the request handler). Slower (adds ~200ms of provider API latency), but functional.
- Queue jobs in-memory (in-process queue) with a warning that jobs may be lost on process restart.
- Use SQS instead of Redis for the email queue — SQS is a fully managed, highly available service that doesn't go down like Redis.

**Session invalidation:** Cannot delete sessions from Redis. Options:
- **PostgreSQL fallback:** Increment `users.token_version` in PostgreSQL. Session middleware checks this on each authenticated request. Even without Redis DEL, the session will be rejected on next use (token_version mismatch).
- This approach makes session invalidation dependent only on PostgreSQL, not Redis.

**Summary — continued functionality during Redis outage:**
- Token generation: YES (PostgreSQL only).
- Email queue: YES (if SQS) or degraded (synchronous fallback).
- Token validation: YES (PostgreSQL only).
- Password update: YES (PostgreSQL only).
- Rate limiting: Degraded (fail open).
- Session invalidation: YES (via token_version in PostgreSQL).

---

### Q9: What is the security risk of allowing users to validate a token before submitting a new password (the "pre-validation" GET endpoint)? How do you implement it safely?

**The use case:** The SPA navigates to `/reset-password?token=...`. Before showing the password form, it makes a GET request to validate the token:
```
GET /auth/password/reset/validate?token=...
```
This allows showing "This link has expired" immediately rather than after the user types their new password.

**Security risks:**

**1. Token enumeration via the validate endpoint:**
An attacker can query the validate endpoint with random tokens and determine, based on the response (200 vs 400), whether a valid token exists. If the validate endpoint is less rate-limited than the confirm endpoint, it becomes an easier enumeration surface.

**2. Token exposure in GET request logs:**
The token is in the URL query parameter of a GET request — it appears in nginx access logs, CDN logs, and any WAF logs. A legitimate validate request leaks the token into server-side logs.

**3. SSRF (Server-Side Request Forgery) if poorly implemented:**
If the validate endpoint makes upstream requests using user-controlled input, SSRF is possible. This isn't specific to password reset but is a risk for any endpoint that processes URLs from user input.

**Safe implementation:**

```http
GET /auth/password/reset/validate HTTP/2
Host: api.example.com
X-Reset-Token: dGhpcyBpcyBhIHNlY3VyZSByZXNldCB0b2tlbg
```

Put the token in a custom header instead of the URL parameter — it won't appear in nginx access logs (only request line and URL are logged by default; headers are not).

**Rate limiting on validate:**
Apply the same rate limiting as on the confirm endpoint. The validate endpoint must never be more permissive.

**Minimal information in response:**
The validate response should ONLY confirm "valid" or "invalid/expired." It should not reveal:
- How much time is left before expiry.
- The user's email address.
- Any other token metadata.

**Validate does NOT consume the token:**
The validate endpoint is read-only. It does not mark the token as used. This is intentional — the token must remain valid for the actual confirm submission.

**Consider not implementing pre-validation:**
The UX benefit is marginal (user saves the time of typing a password before seeing the error). The security cost (additional attack surface, token in request path) may outweigh it. An alternative: show the form always, and only show the error after submission if the token is invalid. For expired tokens: if the link is more than 1 hour old, the SPA can parse the JWT expiry locally... but wait, the token is opaque (not a JWT). The SPA cannot determine expiry without a server call.

**Pragmatic recommendation:** Implement the validate endpoint with the token in a custom header, apply identical rate limiting as the confirm endpoint, and cache the "valid" result for the token's lifetime using Redis (`SETEX validate_cache:{hash} 300 "valid"`).

---

### Q10: How do you handle the case where a user changes their email address and then tries to use a reset token that was issued to their old email address?

**Scenario:**
1. User requests a password reset. Token is generated and sent to `old@example.com`. Token is bound to `user_id=123`.
2. Before using the token, the user (or an attacker who controls the user's account) changes their email from `old@example.com` to `new@example.com`.
3. The token was issued to `old@example.com` but is stored in the DB bound to `user_id=123` (not to the email string).

**Is the old token still valid?**

By default, YES — the token is bound to `user_id`, not to the email address. The email is only the delivery vehicle. The token lookup is:

```sql
SELECT * FROM password_reset_tokens
WHERE token_hash = SHA256($1)
  AND used_at IS NULL
  AND expires_at > NOW();
```

This returns a row for `user_id=123` regardless of whether the email has changed.

**Is this a security issue?**

Depends on WHO changed the email:

- **Legitimate user changed their own email:** Old token is still valid for their account. This is probably fine — the user legitimately owns both the old inbox and the account.
- **Attacker changed the email (after compromising the session):** The attacker has changed the email to `attacker@evil.com`. Now the reset token was sent to `old@example.com` (the victim's inbox). The victim still has the token in their old inbox and can use it to reclaim the account. This is actually GOOD for the victim — they can reset the password back.

**When to invalidate tokens on email change:**

If your threat model includes "attacker with a stolen session changes the email to lock the legitimate user out, then resets the password":
- On email change: invalidate ALL active reset tokens for the user.
- On email change: send a notification to BOTH the old and new email: "Your email was changed. If this wasn't you, contact support."
- This ensures:
  a) The attacker can't use old tokens that were sent to the victim's inbox.
  b) The victim is notified of the unauthorized email change.
  c) The attacker must request a NEW reset token (which goes to the NEW email they control).

**Implementation:**
```sql
-- On email change:
UPDATE password_reset_tokens
SET superseded_at = NOW()
WHERE user_id = $1
  AND used_at IS NULL;
```

And in the validation logic, add: `AND superseded_at IS NULL`.

---

### Q11: What happens if a user's reset token is stolen after they've already used it to successfully set a new password? What does your system expose?

**Scenario:**
1. User requests a password reset. Token T is generated.
2. User successfully uses token T to set a new password. Token T is marked `used_at = NOW()`.
3. Attacker now has token T (e.g., from nginx access logs after the fact, or from an email forward).
4. Attacker submits token T to the confirm endpoint.

**What happens:**

```sql
SELECT * FROM password_reset_tokens
WHERE token_hash = $1
  AND used_at IS NULL  -- This condition fails! used_at is set.
  AND expires_at > NOW();
```

The query returns 0 rows. The endpoint returns: `400 Bad Request: "Invalid or expired reset token."`

**What the attacker learns:**
Only that the token is invalid. They don't learn:
- When it was used.
- That it was used (vs. expired, vs. never existed).
- The user's identity.

**Is there any remaining risk?**

Yes, one subtle risk: **timing side-channel on already-used tokens.**

The "token not found" path takes X ms (DB query returns 0 rows quickly). The "token found but used" path... also returns 0 rows quickly. So this should be timing-equivalent. But if the implementation splits the query:

```python
# VULNERABLE:
token = db.query("SELECT * FROM tokens WHERE hash = ?", hash(submitted))
if not token:
    return 400  # path A: 5ms
if token.used_at:
    return 400  # path B: also 5ms
if token.expires_at < now:
    return 400  # path C: also 5ms
```

All paths return the same error. But if a DIFFERENT branch takes different time (e.g., DB query for existing rows is slower than for non-existent rows due to cache hits vs. cache misses on the index), a statistical timing attack could reveal:
- "This token exists in the DB but is used" vs. "This token never existed."

This is a very advanced attack requiring many requests to average out noise. The practical risk is low but theoretically present.

**Defense:** Return a single uniform error for all invalid token conditions. Ensure DB query timing is similar for "found" and "not found" cases (use a covering index on `token_hash` to ensure both cases hit the index efficiently).

---

### Q12: How would you completely redesign the password reset flow for a high-security system (e.g., a bank) where email alone is insufficient?

**The problem with email-only reset:**
- Email accounts can be compromised.
- Email is delivered over SMTP, which has security limitations.
- No geographic or device binding — anyone with the email can complete the reset.
- No proof of physical possession of the registered phone or device.

**Enhanced multi-factor reset flow for high-security systems:**

**Factor 1: Email (as before)**
Token sent to registered email. Must be clicked within 15 minutes (shorter TTL).

**Factor 2: SMS OTP or TOTP**
After clicking the email link, before being shown the password form, the user must enter:
- A 6-digit OTP sent via SMS to the phone number on file.
- OR: A TOTP code from their authenticator app.

This requires the attacker to control BOTH the email account AND the phone/authenticator app.

**Factor 3: Identity verification (for highest security)**
For forgotten credentials where MFA is also unavailable (e.g., lost phone):
- Video identity verification (match face to government ID on file).
- Support-assisted verification with knowledge-based authentication questions (less secure).
- In-person branch verification (for banks).

**Additional controls for high-security reset:**

**Device binding:**
Associate the reset token with the browser fingerprint / device ID at click time. If the confirm submission comes from a significantly different device (different browser, different OS, different country), step up to another verification factor.

**Geographic anomaly detection:**
If the reset request comes from Russia and the account's history shows all logins from the US: require additional verification before proceeding.

**Cooling-off period:**
After a successful password reset, block high-risk operations (large transfers, account changes) for 24 hours. This limits the damage if the reset was attacker-initiated.

**Notifications on all channels:**
SMS + email notification: "Your password was changed. If this wasn't you, call [fraud hotline] immediately." Include a one-click "Freeze my account" link.

**Auditability:**
Store: reset request IP, email click IP (from email tracking pixel), confirm submission IP, device fingerprints at each step. If the reset is later disputed, this audit trail supports forensic analysis.

---

*Document version: 1.0 | Classification: Internal Engineering | Author: Security Engineering*  
*Contains security-sensitive architectural details. Handle as CONFIDENTIAL.*  
*Do not distribute externally or commit to public repositories.*
