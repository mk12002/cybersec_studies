# OTP Authentication (SMS & Email) — Internal Engineering & Security Document

**Classification:** Internal Engineering Reference  
**Audience:** Senior Engineers, Security Engineers, Systems Architects  
**Scope:** Full-stack breakdown of OTP-based Authentication covering both SMS (TOTP-style numeric codes via carrier) and Email OTP delivery  
**Architecture assumed:** Multi-service application with React SPA, Node.js/Python API, PostgreSQL, Redis, Twilio (SMS), SendGrid/SES (Email), and a dedicated OTP service.

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

### System Context and OTP Variants

This document covers two OTP delivery channels — **SMS** and **Email** — and two primary use cases:

1. **MFA (Multi-Factor Authentication):** User has already authenticated with password; OTP is the second factor.
2. **Passwordless login:** OTP is the sole authentication factor — user enters their phone/email, receives a code, enters it, and is authenticated.

The OTP itself is a **short-lived, single-use numeric code** (typically 6 digits). It is NOT a TOTP (Time-based OTP per RFC 6238 using HMAC-SHA1 — that is the authenticator app variant). This is a server-generated, server-stored, delivery-dependent OTP.

---

### Phase 1: OTP Request (User Initiates)

#### T+0ms — User triggers OTP flow

**MFA context:** User has just successfully entered their password. The system determines MFA is required. The API returns a partial authentication state:

```http
HTTP/2 200
{"status": "mfa_required", "method": "sms", "masked_destination": "+1 (***) ***-5678", "session_token": "partial_auth_token_xyz"}
```

**Passwordless context:** User enters their phone number or email address and clicks "Send Code."

In both cases the browser either automatically fires the OTP request (MFA) or waits for user confirmation (passwordless).

---

#### T+~50ms — OTP request sent to API

```http
POST /auth/otp/request HTTP/2
Host: api.example.com
Content-Type: application/json
Authorization: Bearer partial_auth_token_xyz   (MFA context)
  OR
(no Authorization header)                       (passwordless context)

{
  "channel": "sms",         // or "email"
  "destination": "+14155551234"  // phone or email (passwordless)
                                 // omitted if derived from partial auth token (MFA)
}
```

---

#### T+~60ms — API processes OTP request

The API executes the following synchronous operations on the critical path:

1. **Rate limiting check** (Redis): has this phone/email received too many OTPs recently?
2. **User lookup** (PostgreSQL, MFA): validate the partial auth token → get user_id → get verified phone number.
3. **Concurrent OTP invalidation**: any existing, unused, non-expired OTP for this user+channel is marked superseded.
4. **OTP generation**: `CSPRNG → 6-digit integer` (described in detail in Section 7).
5. **OTP storage** (Redis with TTL): store the hashed OTP with metadata.
6. **Delivery job queued** (async): publish to SMS/Email queue.
7. **Response returned immediately** (before delivery): `200 OK {"status": "sent", "expires_in": 300}`.

Total time on critical path: ~20–50ms. The OTP delivery (SMS: 2–15 seconds; Email: 2–60 seconds) happens asynchronously.

---

#### T+2–15s (SMS) / T+2–60s (Email) — OTP arrives

**SMS path:** Twilio receives the API request from the SMS worker, routes the message through the carrier network, and delivers an SMS to the user's handset. The user sees a notification and a 6-digit code.

**Email path:** The email worker calls SendGrid/SES. The message is queued, delivered via SMTP to the user's email provider (Gmail, Outlook), and appears in the inbox. The user opens the email and reads the code.

**What the user sees (SMS):** A native SMS notification: "Your Example App code is: 847291. Valid for 5 minutes. Do not share this code."

**What the user sees (Email):** An HTML email with the code prominently displayed.

---

#### T+user input — User enters the OTP

User types `847291` into the OTP entry form (web or mobile). The SPA validates input format client-side (6 digits, numeric only) and fires:

```http
POST /auth/otp/verify HTTP/2
Host: api.example.com
Content-Type: application/json
Authorization: Bearer partial_auth_token_xyz  (MFA context)

{
  "otp": "847291",
  "channel": "sms"
}
```

---

#### T+~N+50ms — API validates OTP and completes authentication

1. **Rate limiting check**: max N attempts per OTP per session.
2. **Partial auth token validation**: extract user_id from the token.
3. **OTP record retrieval** (Redis): fetch the stored OTP record by `user_id:channel`.
4. **Hash comparison** (constant-time): `SHA-256(submitted_otp)` vs stored hash.
5. **Validity checks**: not used, not expired, not superseded.
6. **Attempt counter check**: if too many wrong attempts on this specific OTP, lock the OTP (not the account).
7. **Mark OTP as used** (atomic Redis DEL or flag).
8. **Issue full session**: delete partial auth token, create full session.
9. **Return authenticated session cookie + response**.

**What the user sees:** They are now fully authenticated. Redirected to the application.

---

#### Failure path: Expired or Wrong Code

User enters the wrong code or waits too long. The API returns:

```http
HTTP/2 400
{"error": "invalid_otp", "attempts_remaining": 2}
```

After 3 failed attempts on the same OTP: the OTP is locked (not just invalidated — the user must request a new one). The partial auth session may also be revoked after too many total MFA failures, requiring a fresh login.

---

## 2. Network Layer Flow

### DNS Resolution

The OTP flow involves multiple DNS lookups:

```
For API calls (browser -> api.example.com):
Browser cache -> OS resolver -> Recursive resolver -> Root NS -> .com TLD -> example.com authoritative NS -> A record

For SMS delivery (API server -> api.twilio.com):
API server OS resolver -> Twilio's authoritative NS -> Twilio edge IP

For Email delivery (email worker -> api.sendgrid.com):
Email worker OS resolver -> SendGrid authoritative NS -> SendGrid edge IP
```

**Twilio DNS specifics:** Twilio uses GeoDNS — `api.twilio.com` resolves to different IPs based on the requester's geographic location. An API server in AWS us-east-1 gets a US-East Twilio edge. This minimizes latency for the outbound API call but means the carrier routing (Twilio to the mobile network) has its own latency separate from API call latency.

**Critical failure mode:** If the API server's DNS resolver is misconfigured or unavailable, the server cannot resolve `api.twilio.com` or `api.sendgrid.com`. OTP delivery fails silently (the queue job fails). The user sees "code sent" but the code never arrives. Always monitor DNS resolution failures from the email/SMS workers.

---

### TCP 3-Way Handshake

**Browser → API (OTP request/verify):**

```
Client (browser)                         nginx (api.example.com:443)
       |                                              |
       | SYN [seq=x, MSS=1460, SACK, WS=7]           |
       |--------------------------------------------->|
       |                                              |
       | SYN-ACK [seq=y, ack=x+1, MSS=1460]          |
       |<---------------------------------------------|
       |                                              |
       | ACK [ack=y+1]                                |
       |--------------------------------------------->|
       |  [TCP established -- 1 RTT]                  |
```

**API server → Twilio (SMS delivery, from backend worker):**

```
API Server                               Twilio Edge (api.twilio.com:443)
       |                                              |
       | SYN                                          |
       |--------------------------------------------->|
       | SYN-ACK                                      |
       |<---------------------------------------------|
       | ACK                                          |
       |--------------------------------------------->|
       |  [TCP established]                           |
       |  [TLS handshake follows]                     |
```

The API server maintains a connection pool to Twilio and SendGrid — TCP connections are reused across multiple OTP delivery requests. Without connection pooling, each OTP delivery requires a fresh TCP + TLS handshake (~80–200ms overhead). With connection pooling, subsequent deliveries use an established connection (~5–20ms for the API call only).

---

### TLS 1.3 Handshake

**Browser → API:**

```
Client                                              nginx
  |                                                   |
  | ClientHello                                       |
  | - cipher_suites: [TLS_AES_256_GCM_SHA384,        |
  |                   TLS_AES_128_GCM_SHA256,         |
  |                   TLS_CHACHA20_POLY1305_SHA256]   |
  | - key_share: X25519 pub key (32B)                 |
  | - SNI: "api.example.com"                          |
  | - ALPN: ["h2", "http/1.1"]                        |
  |-------------------------------------------------->|
  |                                                   |
  | ServerHello + {Certificate} + {Finished}          |
  | - selected cipher: TLS_AES_256_GCM_SHA384         |
  | - key_share: server X25519 pub key                |
  | - Certificate: api.example.com cert chain        |
  | - CertificateVerify: sig over transcript          |
  |<--------------------------------------------------|
  |                                                   |
  | {Finished} + [first HTTP/2 request]               |
  |-------------------------------------------------->|
```

**API server → Twilio (backend TLS):**
The API server acts as a TLS CLIENT when calling Twilio. It validates Twilio's certificate chain against the system trust store. The API server's HTTP client library (axios, requests, etc.) performs certificate validation — if this is misconfigured to skip validation (`verify=False`, `rejectUnauthorized: false`), an MITM attack against the Twilio connection is possible. Never disable certificate validation on outbound connections from the auth service.

**Cipher suite selection:** Both TLS connections should negotiate AES-256-GCM (or ChaCha20-Poly1305 as fallback). These are AEAD ciphers — each record is encrypted and authenticated in one pass. The OTP code itself travels in the TLS application data — completely protected from passive interception.

---

### Full Network Flow Diagram

```
USER BROWSER       NGINX/CDN      API SERVER       REDIS      POSTGRESQL    SMS WORKER    TWILIO      CARRIER    USER PHONE
     |                 |               |               |              |           |            |            |           |
     |  [OTP REQUEST PHASE]            |               |              |           |            |            |           |
     |                 |               |               |              |           |            |            |           |
  DNS: api.example.com |               |               |              |           |            |            |           |
  -->[resolver]-------->               |               |              |           |            |            |           |
  <-- 203.0.113.1 ------|               |               |              |           |            |            |           |
     |                 |               |               |              |           |            |            |           |
  TCP+TLS SYN+HS ------>               |               |              |           |            |            |           |
  <-- TLS established --|               |               |              |           |            |            |           |
     |                 |               |               |              |           |            |            |           |
  POST /auth/otp/request               |               |              |           |            |            |           |
  {channel: "sms"} ---->-- proxy ----->|               |              |           |            |            |           |
     |                 |               |--INCR rl:sms:+1415...->      |           |            |            |           |
     |                 |               |<-- count: 1 --|               |           |            |            |           |
     |                 |               |--validate partial token ------>           |            |            |           |
     |                 |               |<-- user_id: uuid-xyz -------->           |            |            |           |
     |                 |               |--DEL otp:sms:uuid-xyz ------->|           |            |            |           |
     |                 |               |--SETEX otp:sms:uuid-xyz ----->|           |            |            |           |
     |                 |               |   {hash, attempts, exp}       |           |            |            |           |
     |                 |               |--LPUSH sms_queue {job}------->|           |            |            |           |
  <-- 200 {status:sent} -- 200 --------|               |              |           |            |            |           |
     |                 |               |               |              |  [ASYNC]  |            |            |           |
     |                 |               |               |--BRPOP sms_q->|          |            |            |           |
     |                 |               |               |              |--POST /Messages-------->|            |           |
     |                 |               |               |              |  {To, From, Body}       |            |           |
     |                 |               |               |              |<-- 201 {sid} -----------|            |           |
     |                 |               |               |              |           |--[SMPP/SS7]------------>|           |
     |                 |               |               |              |           |            |--SMS------->           |
     |                 |               |               |              |           |            |            |--notify-->|
     |                 |               |               |              |           |            |            |           |
     | [USER SEES CODE, TYPES IT]      |               |              |           |            |            |           |
     |                 |               |               |              |           |            |            |           |
  POST /auth/otp/verify                |               |              |           |            |            |           |
  {otp: "847291"} ----->-- proxy ----->|               |              |           |            |            |           |
     |                 |               |--INCR rl:verify:uuid-------->|           |            |            |           |
     |                 |               |--GET otp:sms:uuid-xyz------->|           |            |            |           |
     |                 |               |<-- {hash, attempts=0, exp}---|           |            |            |           |
     |                 |               | [SHA256("847291") == stored?] |           |            |            |           |
     |                 |               |--DEL otp:sms:uuid-xyz------->|           |            |            |           |
     |                 |               |--DEL partial_token:xyz ------>|           |            |            |           |
     |                 |               |--SET session:new_id-------->|           |            |            |           |
     |                 |               |--UPDATE users SET last_otp_at [async]->  |            |            |           |
  <-- 200 {session} ----<-- 200 --------|               |              |           |            |            |           |
     |                 |               |               |              |           |            |            |           |
  [Authenticated]      |               |               |              |           |            |            |           |
```

### Latency Budget

| Step | Latency |
|---|---|
| DNS (cold, browser) | 30–100ms |
| TCP handshake (browser→API) | 1x RTT (~20–60ms) |
| TLS 1.3 handshake | 1x RTT |
| Rate limit check (Redis) | 0.5–2ms |
| Partial token validation (Redis) | 0.5–2ms |
| OTP generation (CSPRNG) | <1ms |
| Redis SETEX (OTP store) | 0.5–2ms |
| SMS queue publish (Redis) | 0.5–2ms |
| **Total Phase 1 API response** | **~30–80ms** |
| SMS worker → Twilio API call | 50–200ms |
| Twilio → Carrier routing | 100ms–2s |
| Carrier → Handset delivery | 1s–30s (typical 2–5s) |
| **Total SMS delivery (async)** | **2–30 seconds** |
| Email delivery | **5–120 seconds** |
| OTP verification API call | **~10–30ms** (no Argon2, just SHA-256) |

---

## 3. Application Layer Flow

### OTP Request Endpoint

**Endpoint:** `POST /auth/otp/request`

**Inbound request handling:**

```http
POST /auth/otp/request HTTP/2
Host: api.example.com
Content-Type: application/json
Authorization: Bearer eyJhbGci...   (partial auth JWT for MFA context)
X-Forwarded-For: 203.0.113.42      (set by nginx, client real IP)
X-Request-ID: req-uuid-abc123
Origin: https://app.example.com

{
  "channel": "sms"
}
```

**Middleware stack execution (in order):**

1. **Request logger**: log method, path, request ID, IP hash.
2. **Body size limiter**: reject bodies > 1KB (this request is tiny; large bodies are an attack).
3. **Body parser**: JSON parse. Extract `channel`.
4. **CORS middleware**: validate Origin header.
5. **Rate limit middleware** (Redis): IP-based + destination-based checks.
6. **Auth middleware**: validate partial auth JWT (for MFA context) OR extract destination from request body (passwordless).
7. **Route handler**: OTP generation and storage.

**Parameter parsing — `channel` field:**
```python
ALLOWED_CHANNELS = {"sms", "email"}
channel = body.get("channel")
if channel not in ALLOWED_CHANNELS:
    raise ValidationError("Invalid channel")
```

Never pass the channel value to string formatting or SQL without validation. An attacker setting `"channel": "'; DROP TABLE otps; --"` must be rejected at validation, not reach the DB.

**Response construction:**

```http
HTTP/2 200
Content-Type: application/json
Cache-Control: no-store
X-Request-ID: req-uuid-abc123
X-Content-Type-Options: nosniff

{
  "status": "sent",
  "channel": "sms",
  "masked_destination": "+1 (***) ***-5678",
  "expires_in": 300,
  "resend_available_in": 60
}
```

`masked_destination` shows enough to confirm the right destination without fully revealing it (important for MFA — confirms which number without exposing it fully).

**Enumeration prevention:** The response is IDENTICAL whether the destination is registered or not (passwordless context). Do not reveal "phone number not found."

---

### OTP Verify Endpoint

**Endpoint:** `POST /auth/otp/verify`

```http
POST /auth/otp/verify HTTP/2
Host: api.example.com
Content-Type: application/json
Authorization: Bearer eyJhbGci...  (partial auth JWT)

{
  "otp": "847291",
  "channel": "sms"
}
```

**OTP field parsing:**
```python
otp_raw = body.get("otp")
# Validate: must be a string
if not isinstance(otp_raw, str):
    raise ValidationError("OTP must be a string")
# Validate: 6 digits exactly, numeric only
if not re.fullmatch(r'\d{6}', otp_raw):
    raise ValidationError("OTP must be 6 digits")
# Normalize: strip any whitespace (defensive)
otp_normalized = otp_raw.strip()
```

**Why enforce string type on OTP?**

Some implementations use integer comparison: `if submitted_otp == stored_otp`. If the OTP is `"007291"`, an integer parse gives `7291` (drops leading zero). The attacker could submit `7291` and have it match `"007291"`. Always compare as zero-padded strings.

**Response on success:**

```http
HTTP/2 200
Content-Type: application/json
Cache-Control: no-store
Set-Cookie: session_id=...; HttpOnly; Secure; SameSite=Lax; Max-Age=86400

{"status": "authenticated", "user_id": "uuid-xyz"}
```

**Response on failure (all failure modes — same response):**

```http
HTTP/2 400
Content-Type: application/json
Cache-Control: no-store

{"error": "invalid_otp", "attempts_remaining": 2}
```

Revealing `attempts_remaining` is a debated design decision. It improves UX (user knows they're about to be locked out) but tells an attacker exactly how many guesses remain. For a 6-digit OTP with max 3 attempts, the information gain is minimal — the attacker knew they had at most 3 tries. Hiding it would just be security theater.

---

### Resend Endpoint

**Endpoint:** `POST /auth/otp/resend`

Rate-limited independently. Enforces a minimum interval between resends (e.g., 60 seconds) stored in Redis:

```
Key: "otp_resend_cooldown:{user_id}:{channel}"
Value: "1"
TTL: 60 seconds
```

If the key exists, return `429 Too Early` with `Retry-After: 60`. If the key doesn't exist, proceed with a new OTP request (same flow as `/otp/request`) and set the cooldown key.

---

## 4. Backend Architecture

### OTP Service Architecture

```
+------------------------------------------------------------------+
|                        OTP SERVICE                               |
|                                                                  |
|  [1] API Layer (nginx + App Server)                              |
|      POST /auth/otp/request                                      |
|      POST /auth/otp/verify                                       |
|      POST /auth/otp/resend                                       |
|                                                                  |
|  [2] OTP Store (Redis)                                           |
|      Key: otp:{channel}:{user_id}                                |
|      Value: {otp_hash, attempts, issued_at, channel, user_id}    |
|      TTL: 300 seconds (5 minutes)                                |
|                                                                  |
|  [3] Rate Limit Store (Redis)                                    |
|      Key: rl:otp_request:{channel}:{destination_hash}           |
|      Key: rl:otp_verify:{user_id}                                |
|      Key: otp_resend_cooldown:{user_id}:{channel}                |
|                                                                  |
|  [4] Partial Auth Token Store (Redis)                            |
|      Key: partial_auth:{token_id}                                |
|      Value: {user_id, auth_level, mfa_method, exp}               |
|      TTL: 600 seconds (10 minutes to complete MFA)               |
|                                                                  |
|  [5] SMS Queue (Redis List or SQS)                               |
|      Jobs: {user_id, phone, otp_plain, idempotency_key, exp}     |
|                                                                  |
|  [6] Email Queue (Redis List or SQS)                             |
|      Jobs: {user_id, email, otp_plain, template_id, exp}         |
|                                                                  |
|  [7] SMS Worker (background service)                             |
|      Consumes SMS queue                                          |
|      Calls Twilio API                                            |
|      Handles retries + dead-letter                               |
|                                                                  |
|  [8] Email Worker (background service)                           |
|      Consumes Email queue                                        |
|      Calls SendGrid/SES API                                      |
|      Handles retries + dead-letter                               |
|                                                                  |
|  [9] PostgreSQL (users, audit, OTP delivery logs)                |
|      users: phone_number, email, mfa_methods, is_active          |
|      otp_deliveries: delivery audit trail (async write)          |
+------------------------------------------------------------------+
```

### OTP Storage in Redis — Data Structure

```
Key:   "otp:sms:user-uuid-abc123"
Type:  Redis Hash (HSET)
Fields:
  otp_hash:   "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
              (HMAC-SHA256(otp_plaintext, per_user_salt) -- discussed in Section 7)
  attempts:   "0"          (incremented on each wrong guess)
  issued_at:  "1700000000" (Unix timestamp)
  channel:    "sms"
  superseded: "0"          (set to "1" if a new OTP was requested before this expired)
TTL:  300 seconds
```

**Why a Redis Hash instead of a JSON string?**
Individual fields can be updated atomically. `HINCRBY otp:sms:user-abc attempts 1` increments only the attempts counter without reading and rewriting the entire record. This is important for the attempt counting mechanism — it must be atomic to prevent race conditions.

**Why Redis instead of PostgreSQL for OTP storage?**
- TTL management is native. Redis automatically deletes expired OTPs. No cleanup job needed.
- Read/write latency: ~0.5ms vs 5–15ms for PostgreSQL.
- OTP data is ephemeral — losing it on Redis restart just means users must request a new OTP (acceptable).
- PostgreSQL is used for the audit trail (async write after verification), not the live OTP state.

---

### Sync vs. Async Decision Matrix

| Operation | Sync/Async | Reason |
|---|---|---|
| Rate limit check | Sync | Must block before processing |
| Partial token validation | Sync | Must know user identity before proceeding |
| OTP generation (CSPRNG) | Sync | Fast (<1ms), required immediately |
| Redis SETEX (store OTP) | Sync | Must complete before returning "sent" to user |
| SMS/Email queue publish | Sync (publish) / Async (delivery) | Publish is fast (Redis LPUSH); actual delivery is async |
| OTP verification | Sync | User is waiting; fast (Redis GET + hash compare) |
| Session creation after verify | Sync | Must complete before response |
| Audit log write (PostgreSQL) | Async | Non-critical path; latency-free |
| Confirmation email/SMS | Async | Non-critical |
| Analytics event | Async | Non-critical |

**Why make the queue publish synchronous but delivery asynchronous?**

Synchronous queue publish: ensures the OTP job is durably queued before we tell the user "we sent your code." If the queue publish fails, we return an error and the user knows to retry. If we returned "sent" and then failed to queue, the user would wait forever.

Asynchronous delivery: the SMS/email provider (Twilio/SendGrid) has external latency (50ms–5s for the API call, then separate carrier/SMTP latency). Making the user wait for this would degrade UX from ~50ms to several seconds. The user sees the "sent" message immediately; the code arrives asynchronously.

---

### SMS Delivery Worker — Detailed Flow

```python
class SMSWorker:
    def __init__(self, twilio_client, redis, db):
        self.twilio = twilio_client
        self.redis = redis
        self.db = db

    def process_job(self, job):
        # Idempotency: check if this job was already processed
        idempotency_key = job["idempotency_key"]
        if self.redis.exists(f"sms_sent:{idempotency_key}"):
            logger.info("Duplicate job, skipping", key=idempotency_key)
            return

        # Verify OTP hasn't expired before sending
        otp_key = f"otp:sms:{job['user_id']}"
        otp_data = self.redis.hgetall(otp_key)
        if not otp_data:
            logger.info("OTP expired before delivery", user_id=job['user_id'])
            return  # OTP already expired -- no point sending

        # Send via Twilio
        try:
            message = self.twilio.messages.create(
                body=f"Your Example App code is: {job['otp_plain']}. "
                     f"Valid for 5 minutes. Do not share this code.",
                from_=TWILIO_PHONE_NUMBER,
                to=job['phone']
            )
            # Mark as sent (idempotency)
            self.redis.setex(f"sms_sent:{idempotency_key}", 3600, message.sid)

            # Audit log (async DB write)
            self.db.execute_async(
                "INSERT INTO otp_deliveries (user_id, channel, status, provider_sid, sent_at)"
                " VALUES ($1, 'sms', 'sent', $2, NOW())",
                job['user_id'], message.sid
            )
        except TwilioRestException as e:
            if e.code in PERMANENT_FAILURE_CODES:  # e.g., invalid phone number
                logger.error("Permanent SMS failure", error=e.code, user_id=job['user_id'])
                # Do not retry -- move to dead letter
                self.dead_letter_queue.push(job)
            else:
                raise  # Re-raise for retry logic
```

**OTP plain text in the queue:** The queue contains the plaintext OTP (for SMS body construction). This is a deliberate tradeoff — we need the plaintext to build the SMS message. The hash is stored in Redis for verification; the plaintext is in the queue for delivery. The queue should be encrypted at rest (Redis encryption) and the job should be consumed and deleted promptly.

An alternative: store the plaintext OTP in Redis separately (with the same TTL) and have the worker retrieve it. The queue then contains only the job metadata (user_id, idempotency_key) — no sensitive data. The worker fetches `GET otp_plain:sms:{user_id}` and assembles the message. This requires an additional Redis GET but eliminates sensitive data from the queue.

---

## 5. Authentication & Authorization Flow

### The Partial Authentication State Machine

OTP in MFA context introduces a three-phase authentication state:

```
[Unauthenticated]
    |
    | POST /auth/login {email, password} -- success
    v
[Partially Authenticated]   <-- partial_auth_token valid here
    |
    | POST /auth/otp/request
    | POST /auth/otp/verify -- success
    v
[Fully Authenticated]        <-- full session valid here
    |
    | Time passes / logout
    v
[Unauthenticated]
```

**Partial auth token:**
A JWT or opaque token issued after password verification that represents "identity proven but MFA pending":

```json
{
  "sub": "user-uuid-abc123",
  "type": "partial_auth",
  "mfa_method": "sms",
  "iat": 1700000000,
  "exp": 1700000600,    // 10-minute window to complete MFA
  "jti": "partial-uuid-xyz"
}
```

This token is signed with the server's private key (RS256) or an HMAC secret. It is stored in Redis as well:

```
Key: "partial_auth:{jti}"
Value: {user_id, exp, mfa_method}
TTL: 600 seconds
```

Both the JWT signature and the Redis entry must be valid. Even if the JWT hasn't expired, if the Redis entry is deleted (e.g., on logout), the partial auth is invalidated. This is the same "stateful JWT" pattern used in session management.

**Why store partial auth in Redis AND use a signed JWT?**

JWT alone: cannot be revoked mid-flight. If the user closes the browser and opens a new tab, the partial auth JWT (if stored in localStorage or sessionStorage) could be reused.

Redis entry alone: stateful, but the server can revoke it immediately (logout before completing MFA invalidates the partial state).

JWT + Redis: the JWT is validated cryptographically (fast, no Redis call) and the Redis entry provides revocability. Both must be valid.

---

### OTP as an Authentication Factor — Trust Model

```
SMS OTP trust chain:
  Phone number ownership (SIM card)
    -> Carrier network (SS7 routing)
      -> Twilio MSISDN
        -> OTP delivery
          -> Physical device access
            -> OTP entry
              -> API validation
                -> Full authentication

Email OTP trust chain:
  Email address ownership
    -> Email account credentials
      -> Email provider (Gmail/Outlook)
        -> Inbox access
          -> OTP reading
            -> OTP entry
              -> API validation
                -> Full authentication
```

**SMS vs Email security trade-off:**

| Property | SMS OTP | Email OTP |
|---|---|---|
| Interception risk | SS7 attacks, SIM swap | Email account compromise |
| Delivery speed | 2–15 seconds | 5–120 seconds |
| Phishing resistance | Low (OTP can be phished) | Low (same) |
| User experience | Excellent (native notifications) | Good (email familiarity) |
| Cost | ~$0.0075/SMS (Twilio) | ~$0.001/email (SES) |
| Carrier dependencies | HIGH | LOW |
| Regulatory (HIPAA, PCI) | Varies | Generally compliant |

Both SMS and Email OTP are considered **weak second factors** — both are susceptible to phishing (a fake login page can relay the OTP in real-time). They are significantly better than no MFA but weaker than TOTP apps or hardware keys. The NIST SP 800-63B document has deprecated SMS OTP as a second factor for high-assurance authentication but allows it for level-of-assurance 2 (LoA-2) scenarios.

---

### Session Issuance After Successful OTP

After OTP verification:

1. **Delete partial auth token** from Redis: `DEL partial_auth:{jti}`
2. **Generate session ID**: `CSPRNG(32 bytes)` → base64url
3. **Store full session** in Redis:
   ```
   Key: "session:{session_id}"
   Value: {user_id, roles, permissions, mfa_completed: true, mfa_method: "sms", created_at, last_activity_at}
   TTL: 86400 (or sliding TTL)
   ```
4. **Register session** in user's session set: `SADD user_sessions:{user_id} {session_id}`
5. **Set session cookie**: `Set-Cookie: session_id=...; HttpOnly; Secure; SameSite=Lax; Max-Age=86400`
6. **Return 200** with user profile data.

**The `mfa_completed` flag in the session** is critical. Protected routes that require MFA must check this flag — not just that a session exists. Otherwise, a user who bypasses MFA (e.g., via an API bug that issues a session without MFA) could access MFA-protected routes.

---

## 6. Data Flow

### OTP Generation and Storage Pipeline

```
[1] CSPRNG Generate
    secrets.token_bytes(4)  -- Python
    OR crypto.randomBytes(4)  -- Node.js
    = 4 bytes of random data
    = 32 bits

[2] Reduce to 6-digit integer
    otp_int = int.from_bytes(random_bytes, 'big') % 1_000_000
    otp_str = str(otp_int).zfill(6)  -- zero-pad to 6 digits
    -- e.g.: 847291

    Why 4 bytes? 2^32 = 4,294,967,296 >> 1,000,000
    The modulo operation introduces slight bias
    (4,294,967,296 % 1,000,000 = 967,296 "extra" values)
    This means codes 000000-967295 are slightly more likely
    than 967296-999999 (by ~0.02%). Negligible for 6-digit OTPs.
    For unbiased generation: rejection sampling (re-generate if
    random_int >= 4,294,000,000 to eliminate the biased range).

[3] Hash for storage
    HMAC-SHA256(key=user_secret, msg=otp_str)
    OR
    SHA-256(otp_str + user_specific_salt)

    The user_specific_salt (or HMAC key) is stored in the users table:
    users.otp_salt = CSPRNG(32 bytes) at account creation time.

    This means two users with the same OTP code have DIFFERENT hashes.
    Prevents a DB dump from revealing "all users currently have code X".

[4] Store in Redis
    HSET "otp:sms:{user_id}"
         otp_hash <HMAC value in hex>
         attempts 0
         issued_at <unix_ts>
         channel sms
    EXPIREAT "otp:sms:{user_id}" <unix_ts + 300>

[5] Queue for delivery (plaintext OTP needed here)
    Job payload: {user_id, phone, otp_plain: "847291", exp: <unix_ts+300>}
    LPUSH "sms_queue" <JSON serialized job>
    -- otp_plain is needed ONLY in the queue for SMS body construction
    -- After the worker consumes and sends the job, otp_plain is gone
```

### OTP Verification Pipeline

```
[1] Receive submitted OTP
    Request body: {"otp": "847291", "channel": "sms"}

[2] Validate format
    regex: ^\d{6}$ -- must be exactly 6 digits

[3] Retrieve OTP record from Redis
    HGETALL "otp:{channel}:{user_id}"
    -- Returns: {otp_hash, attempts, issued_at, channel, superseded}

[4] Check: record exists
    If nil: return "invalid_otp" (expired or never existed)

[5] Check: not superseded
    If superseded == "1": return "invalid_otp" (user requested new code)

[6] Check: attempts
    If attempts >= MAX_ATTEMPTS (3): return "otp_locked" (request new code)

[7] Increment attempts counter FIRST (before comparing)
    HINCRBY "otp:{channel}:{user_id}" attempts 1
    -- This is done FIRST to prevent a race where two requests both
    -- see attempts=2 and both try the last guess

[8] Compute hash of submitted OTP
    submitted_hash = HMAC-SHA256(key=user_secret, msg=submitted_otp)

[9] Constant-time comparison
    hmac.compare_digest(submitted_hash, stored_otp_hash)
    -- NEVER use == for hash comparison; timing attack risk

[10a] If match:
    DEL "otp:{channel}:{user_id}"  -- consume the OTP
    [Create full session, delete partial auth]
    Return 200

[10b] If no match:
    -- Attempt was already incremented in step 7
    -- Check if attempts now >= MAX_ATTEMPTS: if so, lock (don't DEL yet, let TTL expire)
    Return 400 {"error": "invalid_otp", "attempts_remaining": max - current}
```

### Data Serialization at Each Stage

| Stage | Format | Encoding | Notes |
|---|---|---|---|
| HTTP request body | JSON | UTF-8 | `application/json` |
| OTP value (user-facing) | String | Numeric characters | Zero-padded, always 6 chars |
| OTP hash (Redis) | HMAC-SHA256 | Hex string (64 chars) | Never store plaintext |
| OTP job (queue) | JSON | UTF-8 | Contains otp_plain temporarily |
| SMS body (Twilio) | String | UTF-8 | "Your code is: 847291" |
| Email body (HTML) | MIME multipart | Base64 or QP | Rendered OTP in HTML |
| Partial auth token | JWT or opaque | base64url | RS256 signed |
| Session data (Redis) | JSON | UTF-8 | Structured session object |
| Audit records | PostgreSQL rows | Native types | Permanent record |

---

## 7. Security Controls

### OTP Generation — Cryptographic Requirements

**CSPRNG requirement:**

```python
# WRONG -- not cryptographically secure
import random
otp = str(random.randint(0, 999999)).zfill(6)

# CORRECT -- cryptographically secure
import secrets
otp = str(secrets.randbelow(1_000_000)).zfill(6)
```

`secrets.randbelow` in Python uses the OS CSPRNG (`/dev/urandom` on Linux, `CryptGenRandom` on Windows). This produces uniformly distributed integers with cryptographic quality.

**Node.js equivalent:**
```javascript
const crypto = require('crypto');
const otp = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
```

`crypto.randomInt` (Node.js 14.10+) is specifically designed for this — uses CSPRNG and handles the modulo bias with rejection sampling internally.

**Length analysis:**

```
6-digit OTP: 10^6 = 1,000,000 possible values
With 3 attempts: 3/1,000,000 = 0.0003% chance of guessing
With 10 attempts: 10/1,000,000 = 0.001% chance

With rate limiting (5 OTPs per hour per user):
  Attacker can try 5 OTPs per hour × 10 attempts = 50 guesses
  In 24 hours: 1,200 guesses
  P(success in 24 hours) = 1,200/1,000,000 = 0.12%
  P(success in 1 week) = 8,400/1,000,000 = 0.84%

This is why rate limiting, attempt limits, and short TTLs are ALL required.
Any single control alone is insufficient.
```

**8-digit OTP consideration:** 10^8 = 100 million possibilities. At 3 attempts, the probability is 3/100,000,000 = 0.000003%. Significantly more secure but worse UX (harder to type correctly).

---

### OTP Storage — Why Hash Instead of Plaintext

If the OTP is stored in plaintext in Redis, a Redis breach (lateral movement from a compromised app server, Redis exposed on the network) gives the attacker all active OTPs. They can immediately use every user's current code.

**SHA-256 is sufficient here (unlike passwords):** OTPs are high-entropy only when combined with the rate limiting and attempt limiting controls. The hash itself doesn't need to be brute-force-resistant (like Argon2 for passwords) because:
1. The OTP expires in 5 minutes — there's no time for offline cracking.
2. The hash is never returned to the client — there's no way to perform an offline dictionary attack.
3. Even if Redis is breached, the OTP expires in 300 seconds and can't be cracked in time.

**HMAC-SHA256 with per-user salt** is better than plain SHA-256:
- Two users with the same OTP code (`"123456"`) have different hashes.
- Even if two hashes from different users are leaked, they can't be correlated to show "same OTP was issued."
- The HMAC key is derived from the user's `otp_salt` (stored in PostgreSQL) — an attacker needs BOTH the Redis hash AND the PostgreSQL salt to crack it.

---

### Encryption Controls

**In transit:**
- TLS 1.3 between browser and API. The OTP code is in the HTTP request body — fully encrypted.
- TLS between API server and Twilio/SendGrid. The OTP plaintext (in the message body for SMS or email content) is encrypted in transit to the provider.
- TLS between SMS worker and Redis. The queue job (containing OTP plaintext) is encrypted in transit.

**At rest:**
- Redis: AWS ElastiCache encryption-at-rest (AES-256). The OTP hash and the queue job (with plaintext OTP) are encrypted on disk.
- PostgreSQL: Database-level encryption. Audit logs of OTP deliveries are encrypted at rest.
- The OTP plaintext never persists — it exists in memory (API process, SMS worker process) and transiently in the queue (consumed and deleted by the worker).

**End-to-end gap:** The OTP plaintext exists at the SMS provider (Twilio) and the email provider (SendGrid) in their logs. These providers have access to the OTP values. Trusting these providers is a prerequisite for using them. For extremely high-security requirements, this is why hardware security keys (FIDO2/WebAuthn) are preferred — the credential never leaves the user's device.

---

### Rate Limiting — Multi-Dimensional

```
Dimension 1: Per-IP OTP request rate
  Key: "rl:otp_req:ip:{ip_hash}"
  Limit: 10 requests per 15 minutes
  Action: 429 Too Many Requests

Dimension 2: Per-destination OTP request rate
  Key: "rl:otp_req:dest:{sha256(phone_or_email)}"
  Limit: 3 OTP requests per hour
  Action: 429 (same generic response -- don't reveal which limit hit)

Dimension 3: Per-user OTP verification attempts
  Key: "rl:otp_verify:{user_id}"
  Limit: 10 verify attempts per 15 minutes
  Action: 429

Dimension 4: Per-OTP attempt limit (stored in OTP record)
  Field: attempts in Redis Hash
  Limit: 3 wrong attempts per specific OTP code
  Action: OTP locked (must request new code)

Dimension 5: Resend cooldown
  Key: "otp_resend_cooldown:{user_id}:{channel}"
  TTL: 60 seconds
  Action: 429 with Retry-After: 60
```

**Why multi-dimensional?** A single IP-based limit can be bypassed by a distributed botnet. A single per-user limit doesn't protect against someone hammering the system with different users. A single per-OTP attempt limit doesn't prevent the attacker from continuously requesting new OTPs (rotating codes) and guessing each. All dimensions together create overlapping coverage.

---

### Input Validation — Complete Controls

```python
# OTP field validation
def validate_otp(otp_raw):
    if not isinstance(otp_raw, str):
        raise ValidationError("OTP must be a string, not a number")
        # Reason: integer type loses leading zeros (007291 -> 7291)

    if len(otp_raw) != 6:
        raise ValidationError("OTP must be exactly 6 characters")

    if not otp_raw.isdigit():
        raise ValidationError("OTP must contain only digits")

    # Reject whitespace (defensive -- some clients send " 847291")
    if otp_raw != otp_raw.strip():
        raise ValidationError("OTP must not contain whitespace")

    return otp_raw  # validated

# Phone number validation (for passwordless SMS)
import phonenumbers
def validate_phone(phone_raw):
    try:
        parsed = phonenumbers.parse(phone_raw, None)
        if not phonenumbers.is_valid_number(parsed):
            raise ValidationError("Invalid phone number")
        # Normalize to E.164 format: +14155551234
        return phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    except phonenumbers.NumberParseException:
        raise ValidationError("Invalid phone number format")

# Email validation
def validate_email(email_raw):
    if not isinstance(email_raw, str):
        raise ValidationError("Email must be a string")
    normalized = email_raw.strip().lower()
    if len(normalized) > 254:
        raise ValidationError("Email too long")
    if not EMAIL_REGEX.fullmatch(normalized):
        raise ValidationError("Invalid email format")
    return normalized
```

---

### Secrets Management

**Secrets used in the OTP flow:**

1. **Twilio Account SID + Auth Token**: Retrieved from AWS Secrets Manager at SMS worker startup. Never in code or environment variables.
2. **SendGrid API Key**: Retrieved from Secrets Manager at email worker startup.
3. **Partial auth token signing key** (HMAC secret or RSA private key): Retrieved from Secrets Manager. Rotated annually.
4. **User OTP salts** (`users.otp_salt`): Generated at account creation, stored in PostgreSQL. Never in application code.
5. **Redis connection password**: Secrets Manager. Rotated periodically.

**Critical: the Twilio Auth Token**
If the Twilio Auth Token is compromised, an attacker can:
- Send arbitrary SMS messages from your Twilio numbers (phishing attacks appearing to come from your number).
- Read message logs (seeing historical OTP codes — though expired, this could reveal patterns).
- Exhaust SMS budget, causing legitimate OTP delivery failures.

Mitigation:
- Rotate the Auth Token immediately upon any suspected compromise.
- Restrict Twilio IP allowlisting (restrict the Twilio console to specific IPs).
- Use Twilio API Keys (scoped, revocable) instead of the master Auth Token.
- Monitor Twilio usage for anomalous sending patterns.

---

## 8. Attack Surface Mapping

### All Entry Points

```
EXTERNAL ATTACK SURFACE
=========================================================

OTP Endpoints:
  POST /auth/otp/request     -- phone/email, channel
  POST /auth/otp/verify      -- otp code, partial auth token
  POST /auth/otp/resend      -- partial auth token

Indirect Surfaces:
  - SMS delivery: carrier network, SS7 vulnerabilities
  - Email delivery: SMTP, email account security
  - Twilio webhook (delivery status): /webhooks/twilio/status
  - SendGrid webhook (delivery events): /webhooks/sendgrid/events
  - DNS (for api.example.com resolution)

INTERNAL ATTACK SURFACE
=========================================================

  Redis (OTP store, rate limits, queues)
    -- port 6380 (TLS)
    -- OTP hashes, plaintext in delivery queue

  PostgreSQL (users, audit)
    -- port 5432
    -- user OTP salts, delivery logs

  SMS Worker process
    -- reads from Redis queue (plaintext OTPs)
    -- calls Twilio API

  Email Worker process
    -- reads from Redis queue (plaintext OTPs)
    -- calls SendGrid API

  Twilio API credentials (in worker process memory and Secrets Manager)
  SendGrid API key (in worker process memory and Secrets Manager)
```

### Attack Surface Diagram

```
                              INTERNET
                                 |
                   +-------------+-------------+
                   |                           |
          +--------v--------+       +----------v-------+
          |  WAF / DDoS     |       |  Carrier Network  |
          |  Protection     |       |  (SS7, SMPP)      |
          +--------+--------+       +----------+-------+
                   |                           |
          +--------v--------+       +----------v-------+
          |  nginx (TLS)    |       |  Twilio MTA       |
          |  Rate limiting  |       |  SMS routing      |
          |  WAF rules      |       +------------------+
          +--------+--------+
                   |
          +--------v------------------+
          |    Auth API Service       |
          |                           |
          | ATTACK:                   |
          | - OTP brute force         |
          | - Destination enumeration |
          | - Rate limit bypass       |
          | - Partial token theft     |
          | - OTP interception (URL)  |
          | - Replay attack           |
          | - SIM swap (via SMS)      |
          +---+----------+-----------+
              |          |
    +---------v---+  +---v-----------+
    |  Redis      |  |  PostgreSQL   |
    | (OTP store  |  | (users, audit)|
    |  rate lim)  |  |               |
    | ATTACK:     |  | ATTACK:       |
    | - OTP hash  |  | - User enum   |
    |   dump      |  | - Salt extract|
    | - Plaintext |  |               |
    |   from Q    |  +---------------+
    +------+------+
           |
    +------v---------+    +----------------+
    |  SMS Worker    |    |  Email Worker  |
    |                |    |                |
    | ATTACK:        |    | ATTACK:        |
    | - OTP exfil    |    | - OTP exfil    |
    |   (in memory)  |    |   (in memory)  |
    | - Twilio key   |    | - SG API key   |
    |   theft        |    |   theft        |
    +------+---------+    +--------+-------+
           |                       |
    +------v-------+     +---------v------+
    |  Twilio API  |     | SendGrid / SES |
    | ATTACK:      |     | ATTACK:        |
    | - SIM swap   |     | - Inbox access |
    | - SS7 intercept    | - Email account|
    +--------------+     +----------------+

TRUST BOUNDARIES:
  [TB-1] Internet -> nginx: Zero trust. All input untrusted.
  [TB-2] nginx -> API: Semi-trusted (same VPC). nginx adds real IP.
  [TB-3] API -> Redis: Trusted (private subnet + auth + TLS).
  [TB-4] API -> PostgreSQL: Trusted (private subnet + auth + TLS).
  [TB-5] Worker -> Twilio/SendGrid: Authenticated (API key). External.
  [TB-6] Carrier network -> User phone: Physical/radio. Outside app control.
  [TB-7] Email provider -> User inbox: Outside app control.
```

---

## 9. Attack Scenarios (Very Detailed)

### 9.1 — OTP Brute Force Attack

**Attacker Assumptions:**
- Attacker has compromised a user's password (phase 1 is done).
- The system issues a partial auth token and sends an SMS OTP to the registered phone.
- Attacker does NOT have access to the phone but wants to complete the MFA.
- The system has a 3-attempt limit per OTP code, but the attacker plans to request multiple codes.

**Step-by-Step Execution:**

1. Attacker completes Phase 1 (password login). Receives partial auth token T1.
2. OTP1 is sent to the victim's phone. Attacker doesn't know OTP1.
3. Attacker immediately requests a new OTP:
   ```
   POST /auth/otp/request {channel: "sms"}
   Authorization: Bearer T1
   ```
4. OTP2 is now the active code. OTP1 is superseded.
5. Attacker tries 3 guesses against OTP2:
   - Attempt 1: `847291` → wrong.
   - Attempt 2: `153042` → wrong.
   - Attempt 3: `999999` → wrong.
6. OTP2 is locked. Attacker requests new OTP (OTP3).
7. Repeat.

**Attack math:**
```
3 guesses per OTP × max_resends_per_session = total guesses
With 10 resends allowed per session: 30 guesses per session
P(success) per session = 30 / 1,000,000 = 0.003%
```

**Rate limiting intersection:**
The resend cooldown (60 seconds between resends) and per-destination rate limit (3 OTPs per hour) directly constrain this attack. With 3 OTPs per hour × 3 guesses each = 9 guesses per hour.

```
9 guesses/hour / 1,000,000 codes = 0.0009% per hour
Time to 50% probability = 693 hours (29 days)
```

With this rate, the attack is not practically feasible IF rate limits are enforced correctly.

**Where detection could happen:**
- Alert: >3 OTP requests for the same user within 10 minutes.
- Alert: failed OTP verification attempts exceeding 80% of the attempt limit.
- Alert: OTP requests with no subsequent successful verification (pattern of request-fail-request-fail).

**Why this works (without proper rate limits):**
Without the per-destination rate limit (only IP-based), an attacker using a single IP can request 10 OTPs per minute. 10 OTPs × 3 guesses = 30 guesses per minute. At 30/min, cracking a 6-digit code takes on average 16,666 minutes (11.5 days) — impractical but not impossible with high value targets.

---

### 9.2 — SIM Swap Attack

**Attacker Assumptions:**
- Target's phone number is known.
- Attacker can perform social engineering against the carrier (pretend to be the victim, claim phone was lost/stolen, request number ported to new SIM).
- OR: Attacker bribes/compromises a carrier employee.

**Step-by-Step Execution:**

1. Attacker calls the carrier (Verizon/AT&T) pretending to be the victim. Uses stolen PII (SSN, billing address from a data breach) to pass carrier identity verification.
2. Carrier ports the victim's phone number to a new SIM controlled by the attacker.
3. Attacker initiates password reset OR has the victim's password (from a phish or breach).
4. Attacker triggers the SMS OTP flow. The OTP is now delivered to the attacker's SIM.
5. Attacker receives the OTP and enters it.
6. Full account takeover achieved.

**This attack requires:**
- Victim's phone number (often publicly available or easily found).
- Sufficient PII to pass carrier verification (data breaches make this easier).
- OR: A carrier employee willing to perform the swap for payment.

**Where detection could happen:**
- Carrier-level: SIM swap detection APIs. Twilio provides a "SIM Swap" API (`/v1/PhoneNumbers/{PhoneNumber}/SIMSwap`) that returns whether the SIM was recently swapped. The application can query this BEFORE sending the OTP:
  ```python
  sim_swap_data = twilio.phone_numbers(phone).sim_swap.fetch()
  if sim_swap_data.last_sim_swap.swapped_in_period:
      # SIM was recently swapped -- require alternative verification
      return require_alternative_mfa()
  ```
- Account-level: Login from a new IP/device immediately after a SIM swap is anomalous. Alert on rapid geographic IP change (login from US, OTP verified from Nigeria within 5 minutes).
- User notification: Send an out-of-band notification (email if SMS is the MFA channel) when a new device or location is detected.

**Why this attack is particularly dangerous:**
The OTP system is designed to verify phone number ownership. A SIM swap transfers that ownership temporarily. The OTP system has no way to distinguish a SIM swap from legitimate use — the code is delivered to whoever holds the number, period.

---

### 9.3 — SS7 Interception (Advanced Nation-State / Carrier-Level)

**Attacker Assumptions:**
- Attacker has access to SS7 (Signaling System 7) infrastructure — the telecommunications protocol used by carriers worldwide for call and SMS routing.
- This requires nation-state capability, a rogue carrier/telecom company, or access to an SS7 node.
- The target's phone number is known.

**Step-by-Step Execution:**

1. Attacker positions themselves on the SS7 network.
2. Victim's OTP is sent via Twilio. Twilio routes the message through the PSTN (Public Switched Telephone Network) to the victim's carrier.
3. Attacker sends an SS7 `SendRoutingInfoForSM` request, requesting the routing information for the victim's phone number. Legitimate carriers return the routing info.
4. Attacker sends an SS7 `ForwardShortMessage` to the carrier, claiming they are the SMS Home Router (HLR) for the victim. The carrier routes the SMS to the attacker instead.
5. Attacker receives the OTP plaintext. Enters it in the web application.
6. Account takeover.

**Why this is relevant but rare:**
- Requires nation-state-level or rogue-carrier access to SS7 infrastructure.
- Not available to typical attackers.
- The attack has been demonstrated publicly (e.g., the 2017 German bank heist).
- Modern carriers increasingly deploy SS7 firewalls (filtering invalid routing requests from unauthorized nodes).

**Mitigation at the application level (limited):**
- Application cannot directly defend against SS7 attacks.
- Mitigation: offer hardware security keys (FIDO2/WebAuthn) as a stronger alternative.
- Detection: impossible from the application side — the SMS appears delivered normally (Twilio reports delivery success).
- Accept the risk: SS7 attacks are extremely targeted and require significant capability. SMS MFA is still far better than no MFA for 99.9% of threat models.

---

### 9.4 — Real-Time Phishing Relay (OTP Phishing)

**Attacker Assumptions:**
- Attacker has set up a fake login page that looks identical to the real application.
- Victim is social-engineered to visit the fake site.
- The attacker's proxy relays credentials and OTPs in real time.

**Step-by-Step Execution:**

1. Attacker creates `evil-example.com` (pixel-perfect copy of `app.example.com`).
2. Victim visits `evil-example.com` (via phishing email/SMS link).
3. Victim enters their email + password. Attacker's proxy immediately relays this to the real `app.example.com`. Real login succeeds. Real OTP is sent to the victim's phone.
4. Fake site shows victim: "We've sent you a verification code. Please enter it below."
5. Victim enters the real OTP on the fake site. Attacker's proxy immediately relays the OTP to `app.example.com`.
6. Real site accepts the OTP. Issues a session. Attacker captures the session cookie.
7. Victim sees "login failed" on the fake site. Attacker has full access on the real site.

**This is the fundamental weakness of OTP (SMS and Email both):**
OTPs are phishable. The entire OTP is transmitted by the user to whatever page they think they're on. A relay attack operates in real time (the OTP is valid for 5 minutes — more than enough time to relay).

**Where detection could happen:**
- The real application notices: login from IP X (user's computer connecting to fake site → proxy → real app). OTP verification from the same proxy IP within seconds.
- Browser-based signals: different browser fingerprint, different IP geolocation.
- Impossible-travel detection: user's known location is New York; proxy is in another country.

**Why OTP does NOT prevent this:**
OTP proves you have access to the registered phone/email at the time of the request. It does NOT prove you are communicating directly with the legitimate server. A transparent proxy can relay everything in real time.

**Mitigation:**
- FIDO2/WebAuthn hardware keys: the credential is bound to the origin (`app.example.com`). A phishing site on `evil-example.com` cannot complete the WebAuthn challenge — the browser refuses because the origin doesn't match the key's registration. This is the only MFA method that defeats real-time phishing.
- OTP binds cannot prevent relay attacks, but can limit their window (short OTP TTL, OTP bound to partial auth session that is also IP-bound).

---

### 9.5 — Destination Enumeration via Masked Display

**Attacker Assumptions:**
- The OTP request endpoint returns `masked_destination: "+1 (***) ***-5678"`.
- The attacker wants to confirm whether a specific phone number is registered in the system.

**Step-by-Step Execution:**

1. Attacker initiates the login flow for `victim@example.com`. Password succeeds (attacker has the password from a breach).
2. The MFA screen shows: `"Sending code to +1 (***) ***-5678"`.
3. Attacker already knows the victim's phone number is `+14155555678`.
4. Attacker confirms: the last 4 digits match. The phone number `+14155555678` is registered to this account. Attacker also confirms the phone is still registered (useful intel even if they don't complete the MFA).

**This reveals:**
- That MFA is enabled on this account.
- What type of MFA (SMS, email).
- Partial destination (useful confirmation if attacker has a candidate number).

**Where detection could happen:**
- Alert: successful password login followed by MFA abandon (no OTP requested/verified) — could indicate probing.
- Alert: multiple login attempts to one account with password success but no MFA completion.

**Mitigation:**
- Consider not showing the masked destination at all, or showing only a very generic indicator ("SMS to your registered phone").
- For high-security systems: show only the channel type, not even the masked number.
- Trade-off: UX value of confirming "yes, that's my phone" vs. information disclosure to attackers who have the password.

---

### 9.6 — Redis OTP Queue Poisoning

**Attacker Assumptions:**
- Attacker has gained access to the Redis instance (lateral movement from a compromised app server, misconfigured Redis without AUTH exposed on an internal port).
- Attacker can write to the Redis queue.

**Step-by-Step Execution:**

1. Attacker gains Redis access. Reads queue:
   ```
   LRANGE sms_queue 0 -1
   ```
   Sees pending SMS jobs including `{"user_id": "uuid-xyz", "phone": "+14155551234", "otp_plain": "847291"}`.

2. **Attack variant A (steal OTP):** Attacker reads `otp_plain` for target user. Immediately submits `847291` to the verify endpoint for the target user's partial auth session.
   - But wait: attacker also needs the partial auth token to call `/verify`. If they have Redis access, they can read the partial auth token too.
   - `GET partial_auth:{some_jti}` → gets `{user_id: uuid-xyz, ...}`.
   - Attacker crafts a request: `POST /auth/otp/verify {otp: "847291"} Authorization: Bearer {reconstructed partial auth JWT or looked up session}`.

3. **Attack variant B (inject fake OTP job):** Attacker inserts a new job into the queue for a different user:
   ```
   LPUSH sms_queue '{"user_id": "victim-uuid", "phone": "+19995551234", "otp_plain": "000000"}'
   ```
   The SMS worker sends "000000" to the victim's phone. The attacker already knows the code is `000000`. But the Redis OTP store for the victim has a different hash (the real OTP hash from when the legitimate request was made). The attacker's injected job sends a known code but the stored hash won't match — verification will fail.

   **This only works if** the attacker also modifies the OTP hash in Redis:
   ```
   HSET "otp:sms:victim-uuid" otp_hash SHA256("000000") + victim_otp_salt
   ```
   But to compute the correct HMAC, the attacker needs the victim's `otp_salt` from PostgreSQL. With only Redis access, they can't get the salt.

4. **Attack variant C (mass OTP theft):** Attacker dumps the entire SMS queue:
   ```
   LRANGE sms_queue 0 -1
   ```
   Gets plaintext OTPs for all pending deliveries. Immediately attempts verification for multiple users.

**Why this is catastrophic:**
A Redis compromise with write access to the OTP store allows an attacker to:
- Read plaintext OTPs from the delivery queue.
- Potentially override OTP hashes (if they can also get salts from PostgreSQL).
- Perform massive credential theft.

**Detection:**
- Redis AUTH failure logs (brute-force attempt).
- Unusual Redis command patterns: `KEYS *`, `LRANGE sms_queue 0 -1` — these are anomalous for normal app behavior.
- Network egress from Redis (data exfiltration).

---

### 9.7 — Concurrent Request Race Condition on OTP Verification

**Attacker Assumptions:**
- Attacker has a valid partial auth token and a valid OTP (e.g., they have access to both the password AND the SMS via SIM swap).
- The application has 3 wrong attempts before locking, but the attacker is trying to exploit a race condition to use an OTP after it should have been consumed.

**Step-by-Step Execution:**

1. Attacker submits the correct OTP from two concurrent requests simultaneously:
   - Thread A: `POST /verify {otp: "847291"}`
   - Thread B: `POST /verify {otp: "847291"}`

2. **Vulnerable implementation (non-atomic):**
   ```python
   # Thread A and B both execute:
   otp_data = redis.hgetall("otp:sms:user")  # Both see: {hash, attempts: 0}
   if hmac(submitted_otp) == otp_data["otp_hash"]:  # Both match
       redis.delete("otp:sms:user")  # Last delete "wins" (both execute)
       create_session()  # Both create sessions
   ```
   Result: Two full sessions created. The attacker has two valid sessions (parallel logins).

3. **Atomic mitigation:**
   ```python
   # Use Redis transaction or Lua script:
   lua_script = """
   local data = redis.call('HGETALL', KEYS[1])
   if #data == 0 then return nil end  -- OTP not found
   local deleted = redis.call('DEL', KEYS[1])
   if deleted == 0 then return nil end  -- Another request got here first
   return data  -- Return the OTP data for verification
   """
   otp_data = redis.eval(lua_script, 1, "otp:sms:user")
   if otp_data is None: raise OTPConsumed()
   # Now verify hash -- outside the Lua script is OK since OTP is consumed
   ```

**Practical impact:** Double-session creation is low severity (attacker gets two sessions instead of one). But the correct atomic implementation is required to prevent any form of race exploitation.

**Detection:** Two successful OTP verifications from the same partial auth token (impossible normally — the first should consume the OTP). Alert on duplicate OTP consumption events.

---

## 10. Failure Points

### Under Load

**Redis rate limit key contention:**
At high OTP request volume (e.g., mass account login after a marketing push), multiple workers simultaneously INCR the same rate limit key. Redis is single-threaded — this is fine for correctness (INCR is atomic) but creates hot keys. A rate limit key for a popular destination (e.g., a test phone number in automated tests) can receive thousands of INCR operations per second.

**SMS worker queue backup:**
If Twilio is experiencing degraded performance, SMS delivery takes longer. Queue depth grows. OTPs expire before delivery. Users request resends, creating more queue depth. Spiral failure.

**Detection:** Queue depth metric > threshold (alert at 100 jobs, page at 1000 jobs). Twilio delivery success rate drops below 95% → alert.

**Partial auth token TTL mismatch:**
If the partial auth token has a 10-minute TTL but the SMS takes 5 minutes to deliver (carrier congestion), the user has only 5 minutes to read the code and enter it. Under load, carrier latency increases. If SMS delivery takes 8 minutes, the 10-minute partial auth TTL is nearly consumed before the user even sees the code.

**Mitigation:** Make the partial auth token TTL longer than the maximum expected SMS delivery time + a reasonable user input time. 15–20 minutes is safer than 10 minutes, with the trade-off that abandoned flows hold a partial auth state longer.

### Under Attack

**Twilio/SendGrid API key abuse:**
If the Twilio API key is leaked, an attacker sends mass SMS from your number. This is a financial attack (bills) and a reputation attack (spam complaints). Twilio rate-limit alerts and billing alerts must be configured.

**Email bombing via OTP requests:**
Attacker sends thousands of OTP requests for the same email. Each generates an OTP delivery job. Without per-destination rate limiting, the email provider sends thousands of emails to the victim. This triggers spam complaints, potentially getting your sending domain blacklisted.

**Per-destination rate limiting is mandatory** — not just per-IP.

### Common Misconfigurations

| Misconfiguration | Impact | Fix |
|---|---|---|
| OTP stored in plaintext in Redis | Redis breach = all OTPs compromised | HMAC-SHA256(otp, user_salt) before storage |
| No attempt limit per OTP | Brute force of 6-digit code feasible | Max 3 attempts per OTP; lock after |
| No resend rate limit | Email/SMS bombing, brute force by rotation | 3 resends per hour per destination |
| OTP comparison with `==` not constant-time | Timing attack reveals hash prefix matches | `hmac.compare_digest()` |
| Integer type for OTP | Leading zeros lost (007291 becomes 7291) | Always string type, zero-padded |
| Using PRNG not CSPRNG | OTP is predictable | `secrets.randbelow()` / `crypto.randomInt()` |
| No partial auth token expiry | Attacker can wait indefinitely to guess OTP | 10-minute TTL on partial auth state |
| Certificate verification disabled on Twilio/SendGrid HTTP client | MITM on outbound OTP delivery | Always verify TLS certificates on outbound calls |
| OTP in email subject line | Email subjects appear in notification previews (lock screen) without opening email | Put OTP in email body only; subject: "Your verification code" |
| No OTP supersession | Multiple valid codes accumulate | New request invalidates old OTP atomically |
| Partial auth token stored in localStorage | XSS theft of partial auth token | Store in memory or HttpOnly cookie |
| Twilio/SG credentials in environment variables | Visible in Docker inspect, process list | AWS Secrets Manager |

---

## 11. Mitigations

### Defense-in-Depth Strategy

**Layer 1 — OTP Cryptographic Strength:**
- CSPRNG for OTP generation (`secrets.randbelow` / `crypto.randomInt`).
- HMAC-SHA256 with per-user salt for storage (never plaintext).
- Constant-time comparison for hash verification.
- 300-second (5 minute) TTL — enforced at both Redis and application layer.
- 3-attempt limit per OTP code — atomic increment before comparison.
- Single-use: atomic DEL on successful verification (Lua script for concurrency safety).

**Layer 2 — Rate Limiting (Multi-Dimensional):**
- Per-IP: 10 OTP requests per 15 minutes.
- Per-destination: 3 OTPs per destination per hour.
- Per-user verify: 10 attempts per 15 minutes.
- Per-OTP: 3 wrong guesses before lock.
- Resend cooldown: 60 seconds minimum between resends.

**Layer 3 — Channel Security:**
- SMS: Monitor for SIM swaps before sending (Twilio SIM Swap API).
- Email: SPF + DKIM + DMARC. OTP in body, not subject.
- Both: Require TLS on delivery (`RequireTLS` for email, default TLS for Twilio).

**Layer 4 — Session Security:**
- Partial auth tokens stored in Redis (revocable) + signed JWT (integrity).
- Full session created ONLY after successful OTP verification.
- `mfa_completed: true` flag in session — checked by MFA-protected routes.
- Session invalidation on password change, suspicious activity, logout.

**Layer 5 — Delivery Queue Security:**
- Redis queue encrypted at rest.
- Workers consume and delete jobs immediately (minimize window of plaintext OTP in queue).
- Consider storing only job metadata in queue; retrieve OTP plaintext from Redis separately.
- Separate Redis instance for OTP queue (blast radius reduction).

**Layer 6 — Observability and Response:**
- Alert on OTP brute force patterns (request-fail-request-fail cycles).
- Alert on SIM swap detection.
- Alert on impossible travel (IP geolocation change between password login and OTP verify).
- Incident response: bulk OTP invalidation (`DEL` all `otp:*` keys) if mass compromise suspected.

### Engineering Tradeoffs

| Control | Security Benefit | Cost |
|---|---|---|
| HMAC-SHA256 storage | Mitigates Redis breach token theft | Extra complexity: per-user salt in PostgreSQL |
| 3 attempts per OTP | Limits brute force | Poor UX if user misreads a digit three times (rare) |
| 60s resend cooldown | Limits OTP rotation attacks | Frustrated users who "didn't receive" code |
| SIM swap check per OTP | Detects SIM swap attack | 50–100ms additional latency; Twilio API cost |
| Lua script for atomic verify | Prevents race conditions | Redis Lua complexity; harder to debug |
| Short OTP TTL (5 min) | Limits theft window | Users who take >5 min to retrieve code must resend |
| 6-digit vs 8-digit OTP | 8-digit: 100x harder to brute force | 8-digit: worse UX (harder to type, more errors) |

---

## 12. Observability

### Structured Log Events

```json
// OTP requested
{
  "timestamp": "2024-11-15T10:23:45.123Z",
  "event": "otp.requested",
  "request_id": "req-uuid-abc123",
  "user_id": "uuid-xyz",
  "channel": "sms",
  "destination_hash": "sha256:a1b2c3...",  // NEVER log phone/email plaintext
  "destination_masked": "+1 (***) ***-5678",  // OK to log masked form
  "ip_hash": "sha256:d4e5f6...",
  "ip_geo": "US-CA",
  "rate_limit_remaining": 2,
  "superseded_existing_otp": true,
  "otp_job_id": "job-uuid-def456",
  "duration_ms": 38
}

// OTP delivery status (from worker after provider response)
{
  "event": "otp.delivery.sent",
  "job_id": "job-uuid-def456",
  "user_id": "uuid-xyz",
  "channel": "sms",
  "provider": "twilio",
  "provider_sid": "SM1234567890abcdef",
  "delivery_latency_ms": 145
}

// OTP delivery webhook (from Twilio callback)
{
  "event": "otp.delivery.delivered",
  "provider_sid": "SM1234567890abcdef",
  "status": "delivered",  // or "failed", "undelivered"
  "error_code": null,
  "timestamp": "2024-11-15T10:23:50.456Z"
}

// OTP verification attempt
{
  "event": "otp.verify.attempt",
  "request_id": "req-uuid-ghi789",
  "user_id": "uuid-xyz",
  "channel": "sms",
  "ip_hash": "sha256:...",
  "ip_geo": "US-CA",
  "result": "success",  // or "wrong_code", "expired", "locked", "rate_limited"
  "attempt_number": 1,
  "otp_age_seconds": 12,  // how long since OTP was issued
  "duration_ms": 8
}

// Security events (always log, never sample)
{
  "event": "otp.security.brute_force_detected",
  "user_id": "uuid-xyz",
  "pattern": "request_fail_request_fail",
  "requests_in_window": 5,
  "window_seconds": 300,
  "severity": "HIGH"
}

{
  "event": "otp.security.sim_swap_detected",
  "user_id": "uuid-xyz",
  "destination_hash": "sha256:...",
  "swap_period_hours": 2,
  "action_taken": "blocked_otp_delivery",
  "severity": "HIGH"
}
```

**What NEVER appears in logs:**
- OTP plaintext values ("847291") — these are credentials.
- Full phone numbers or email addresses in high-volume logs.
- Partial auth token values.
- Full IP addresses (PII in some jurisdictions — hash them).
- Twilio/SendGrid API keys or any credentials.

---

### Metrics

```
# Counters
otp_requests_total{channel="sms|email", outcome="success|rate_limited"}
otp_deliveries_total{channel="sms|email", provider="twilio|sendgrid", status="sent|failed"}
otp_deliveries_delivered_total{channel="sms|email"}  # from webhook
otp_verify_attempts_total{channel="sms|email", result="success|wrong_code|expired|locked"}
otp_sessions_created_total{channel="sms|email", context="mfa|passwordless"}

# Histograms
otp_request_duration_seconds              # API response latency for /otp/request
otp_verify_duration_seconds               # API response latency for /otp/verify
otp_delivery_latency_seconds{channel}     # Time from queue publish to delivery webhook
otp_age_at_verification_seconds           # How old was OTP when correctly entered

# Gauges
otp_sms_queue_depth                       # Jobs waiting to be processed
otp_email_queue_depth
otp_active_otps_count                     # All non-expired OTPs in Redis
otp_locked_otps_count                     # OTPs locked due to too many attempts

# Error rates
otp_delivery_failure_rate{channel, provider}
otp_worker_errors_total{worker_type, error_type}
```

---

### Distributed Traces

```
HTTP POST /auth/otp/request [38ms total]
  ├── middleware.rate_limit_ip [1.1ms]
  │     └── redis.INCR rl:otp_req:ip:... [0.8ms]
  ├── middleware.rate_limit_dest [1.0ms]
  │     └── redis.INCR rl:otp_req:dest:... [0.7ms]
  ├── middleware.validate_partial_token [1.5ms]
  │     └── redis.GET partial_auth:... [0.9ms]
  ├── handler.otp_request [34ms]
  │     ├── redis.DEL otp:sms:user (supersede old) [0.6ms]
  │     ├── crypto.csprng_generate [0.05ms]
  │     ├── crypto.hmac_sha256 [0.1ms]
  │     ├── redis.HSET + EXPIREAT otp:sms:user [0.8ms]
  │     ├── redis.LPUSH sms_queue [0.7ms]
  │     ├── redis.SETEX resend_cooldown [0.5ms]
  │     └── audit.event.publish [0.2ms] (async)
  └── middleware.set_headers [0.05ms]

HTTP POST /auth/otp/verify [8ms total]
  ├── middleware.rate_limit_verify [1.0ms]
  │     └── redis.INCR rl:otp_verify:user [0.7ms]
  ├── middleware.validate_partial_token [1.2ms]
  ├── handler.otp_verify [5.5ms]
  │     ├── redis.eval (Lua: atomic get+del) [1.2ms]
  │     ├── crypto.hmac_sha256 (submitted) [0.1ms]
  │     ├── crypto.compare_digest [0.05ms]
  │     ├── redis.DEL partial_auth:... [0.6ms]
  │     ├── redis.SETEX session:new [0.8ms]
  │     └── audit.event.publish [0.2ms] (async)
  └── middleware.set_cookie + headers [0.1ms]
```

The OTP verify path is dramatically faster than a password login (8ms vs 300ms) because there is no Argon2 computation — just a SHA-256 hash comparison. This is by design: OTPs are not long-lived secrets, so Argon2's brute-force resistance is unnecessary. Rate limiting + short TTL + attempt limits provide equivalent protection.

---

### Alerting Rules

| Metric / Condition | Alert? | Severity | Reason |
|---|---|---|---|
| OTP brute force pattern (request-fail cycle >3/10min) | YES | HIGH | Active attack on account |
| OTP verify failure rate > 20% sustained | YES | MEDIUM | Possible attack or UX issue |
| `otp_delivery_failure_rate` > 5% for SMS | YES | HIGH | Twilio degradation |
| `otp_delivery_failure_rate` > 5% for email | YES | MEDIUM | SendGrid degradation |
| `otp_sms_queue_depth` > 100 | YES | MEDIUM | Worker backed up |
| `otp_sms_queue_depth` > 1000 | YES | HIGH | Worker down or Twilio outage |
| `otp.security.sim_swap_detected` any event | YES | HIGH | SIM swap attempt |
| OTP delivery webhook reports "failed" for > 1% of messages | YES | MEDIUM | Carrier routing issue |
| `otp_age_at_verification_seconds` > 240 (80% of TTL) | YES (low) | LOW | Users receiving codes slowly |
| Successful OTP verify with different IP than OTP request | YES (conditional) | MEDIUM | Possible relay attack |
| Single IP triggering rate limits across >100 users | YES | CRITICAL | Distributed credential stuffing |
| Normal OTP request during business hours | NO | -- | Expected |
| Single failed OTP verification | NO | -- | Mistyped digit |
| OTP not verified (TTL expires without use) | NO | -- | Normal user abandonment |

---

## 13. Scaling Considerations

### Bottlenecks

**1. Redis OTP store contention under high login volume:**

At peak, if 100,000 users log in simultaneously, 100,000 OTP SETEX operations and 100,000 HGETALL operations occur within minutes. Redis handles ~100,000 ops/sec per node comfortably. The bottleneck is not Redis operations but the delivery queue.

**2. SMS delivery queue and Twilio rate limits:**

Twilio has per-account and per-phone-number rate limits. A single long-code Twilio number can send ~1 SMS/second (3,600/hour). For high volume, you need:
- **Twilio Messaging Service** (multiple long codes in a pool — automatic distribution).
- **Short codes** (dedicated 5-6 digit numbers, higher throughput: ~100 SMS/second per short code).
- **Alpha Sender IDs** (for international sending, where supported by carriers).

For 100,000 simultaneous logins requiring SMS OTP, with a 1 SMS/second per number limit, you'd need 100,000 numbers to deliver all simultaneously — clearly infeasible. Realistic delivery: 100,000 messages with a Twilio Messaging Service pool might take 10–30 minutes. Rate limiting on OTP requests prevents this scenario from cascading.

**3. Email delivery throughput:**

SendGrid and SES can handle millions of emails per day. Email OTP is typically not a throughput bottleneck unless the application goes viral. SES allows up to 14 million emails/day on sending limits (after warm-up).

**4. Partial auth token expiry management:**

Each partial auth token is a Redis key with a 10-minute TTL. At 100,000 concurrent MFA flows: 100,000 Redis keys (trivial). But if users abandon MFA flows (leave the browser without logging in), these keys accumulate until TTL expiry. Not a significant concern — Redis handles this automatically.

---

### Horizontal Scaling

**Auth API service:** Stateless (session/OTP state is in Redis, not local). Horizontally scalable. Each instance reads/writes the same Redis. nginx distributes requests round-robin.

**SMS workers:** Multiple workers can consume from the same Redis queue (BRPOP is atomic — each job is claimed by exactly one worker). Scale workers horizontally to increase delivery throughput. Monitor queue depth — add workers when depth grows.

**Email workers:** Same pattern as SMS workers.

**Redis:** Single node is sufficient for most scales (millions of OTPs per day). For extreme scale:
- Redis Cluster: shard OTP keys by user_id hash.
- Redis Sentinel: HA for single-shard deployments.
- **Critical:** OTP keys must be on the same shard as their rate limit keys if Lua scripts access both. Use Redis hash tags: `otp:{user_id}` and `rl:verify:{user_id}` should route to the same shard if the Lua script accesses both. Use `{user_id}` as the hash tag: `{uuid-xyz}:otp` and `{uuid-xyz}:verify`.

---

### Consistency Tradeoffs

**OTP store vs. delivery queue consistency:**

```
Scenario: OTP is stored in Redis (SETEX), then queue publish fails.
Result: OTP exists in Redis; no delivery job in queue.
User experience: "We've sent your code" -- but nothing arrives.

Mitigation: Transactional outbox pattern.
  1. Write OTP to Redis.
  2. Write delivery job to PostgreSQL outbox table (synchronous, durable).
  3. Return 200 to user.
  4. Background poller reads outbox and publishes to queue.
  5. Delete from outbox after queue publish confirmed.

This is more complex but ensures no lost delivery jobs.
For OTP use case: the simpler approach (accept occasional lost jobs, allow resend) is usually sufficient.
```

**OTP state consistency during Redis failover:**

If the Redis primary fails and fails over to a replica (10–30 second window), some OTP writes may be lost (async replication). Users who requested an OTP during the failover window will have their OTP in limbo — no Redis record exists on the new primary.

Result: Their OTP "works" (SMS delivered) but verify returns "not found/expired." User must request a new OTP.

Mitigation: Redis Sentinel with synchronous replication (`WAIT 1 0`) for OTP writes — ensures at least one replica has the data before returning success. Adds ~1ms latency. For MFA/security-critical OTPs, this is worth it.

**Rate limit counter consistency:**

Rate limit counters can be lost on Redis failover. After failover, counters reset to zero — briefly, all rate limits are removed. An attacker who can trigger/time a Redis failover could bypass rate limits. This is an advanced attack; for most threat models, accept the brief rate limit loss during failover.

For extreme security: store rate limit counters in PostgreSQL (durable but slower, ~10ms vs 0.5ms). Use PostgreSQL advisory locks for atomicity. The latency trade-off is significant for high-volume endpoints.

---

## 14. Interview Questions

### Q1: Why is a 6-digit numeric OTP with only 3 attempts secure? Walk through the math and explain what fails if you remove each control.

**The security argument:**

6-digit OTP = 10^6 = 1,000,000 possible codes. With 3 attempts, the probability of guessing a specific OTP is 3/1,000,000 = 0.0003%. This is very low for a single attempt.

But the controls are mutually dependent — remove any one and the system degrades:

**Remove attempt limit:**
An attacker can try all 1,000,000 codes. At 1 request/second (typical API rate without rate limiting): 1,000,000 seconds = 11.6 days. Feasible with automated tooling. A 6-digit code without attempt limits is effectively no security.

**Remove OTP TTL (no expiry):**
The OTP is valid indefinitely. An attacker who can eventually obtain the OTP (email breach, physical access) can use it months later. Also, without TTL, rate-limited brute force attacks (3 codes/hour) become viable over weeks.

**Remove rate limiting (keep attempt limit + TTL):**
With 5-minute TTL and 3 attempts per code: 3 guesses per 5 minutes = 36 guesses/hour. At 36 guesses/hour against 1,000,000 codes: expected time to crack = 13,889 hours = 578 days. Still infeasible. But if an attacker can request new codes rapidly (no resend rate limit), they can rotate codes: 3 guesses per code × many codes per hour. At 10 codes/minute × 3 guesses = 30 guesses/minute = 1,800 guesses/hour. Expected crack time: 277 hours = 11.5 days. Now feasible.

**Remove OTP supersession (keep all other controls):**
An attacker who gets 3 wrong guesses on OTP1 can request OTP2, OTP3, etc. With resend rate limit of 3/hour × 3 guesses = 9 guesses/hour. If no supersession, they also have OTP1, OTP2, OTP3 all still valid (if not expired). This creates a widening attack window.

**Conclusion:** All three controls (attempt limit + TTL + rate limiting + supersession) are individually insufficient but together create a robust defense. The multiplicative combination is what makes 6 digits secure in practice.

---

### Q2: What is the difference between TOTP (RFC 6238, authenticator app) and server-generated SMS/Email OTP? Which is more secure and why?

**TOTP (RFC 6238):**
- **Generation:** HOTP(K, T) where K is a shared secret and T is the current time-step (typically 30 seconds). Computed using HMAC-SHA1.
- **Storage:** The shared secret K is stored on BOTH the server (in the database) and the client (in the authenticator app). The secret never needs to be transmitted after initial setup.
- **Validation:** Server independently computes the expected OTP for the current time window (and ±1 window for clock skew). No network call needed.
- **Delivery:** No external delivery channel. The code is generated locally on the user's device.

**Server-generated SMS/Email OTP:**
- **Generation:** Server generates a random code using CSPRNG.
- **Storage:** Server stores the hash. Client receives the plaintext via delivery channel.
- **Validation:** Client submits the code; server compares to stored hash.
- **Delivery:** Dependent on SMS carrier network or email provider.

**Security comparison:**

| Property | TOTP | SMS/Email OTP |
|---|---|---|
| Phishing resistance | NOT resistant (code can be relayed in real time) | NOT resistant (same) |
| Interception risk | None (no delivery channel) | HIGH (SS7 for SMS, email compromise for email) |
| Delivery dependency | None | HIGH (carrier/provider failures) |
| SIM swap vulnerability | None | HIGH (SMS) / None (email) |
| Shared secret exposure | Server DB breach exposes K | No persistent secret (hash only) |
| User UX | Requires authenticator app setup | No setup; any phone/email works |
| Offline generation | Yes (no internet needed) | No (must receive delivery) |

**Which is more secure?** TOTP is generally more secure than SMS OTP because:
1. No delivery channel = no interception risk (no SS7, no email compromise).
2. No SIM swap vulnerability.
3. Higher entropy than SMS OTP in practice (TOTP is 6 digits from HMAC-SHA1 of a 160-bit secret; SMS OTP is 6 digits from CSPRNG — both are 6 digits but TOTP's time-based window is better coordinated).

TOTP's weakness: the shared secret K stored on the server is a high-value target. If the secrets database is breached, an attacker can compute all TOTP codes for all users. SMS OTP has no such shared secret (the OTP is ephemeral).

The gold standard remains **FIDO2/WebAuthn** — it eliminates the phishability of both TOTP and OTP by binding credentials to the origin.

---

### Q3: How do you make the OTP verification step atomic to prevent race conditions? Describe the exact Redis Lua script and why it's necessary.

**The race condition:**

Without atomicity, two concurrent verify requests both see `attempts: 0` and `otp_hash: X`. Both compute `HMAC(submitted_otp) == X` = true. Both delete the OTP. Both create sessions. The user now has two full sessions from one OTP — a security anomaly.

More critically: if the attempt counter is incremented (to prevent brute force) as a separate step from the OTP deletion, a race could allow both "attacker" and "legitimate user" to submit the correct OTP simultaneously — both see it as valid before either consumes it.

**Lua script solution:**

```lua
-- KEYS[1] = OTP hash key, e.g., "otp:sms:user-uuid"
-- ARGV[1] = submitted OTP hash to compare
-- ARGV[2] = max attempts allowed

local data = redis.call('HMGET', KEYS[1], 'otp_hash', 'attempts', 'superseded')
local stored_hash = data[1]
local attempts = tonumber(data[2]) or 0
local superseded = data[3]

-- Check: OTP exists
if stored_hash == false then
    return {0, 'not_found'}
end

-- Check: not superseded
if superseded == '1' then
    return {0, 'superseded'}
end

-- Check: not too many attempts
if attempts >= tonumber(ARGV[2]) then
    return {0, 'locked'}
end

-- Increment attempts BEFORE comparing (prevent concurrent guesses)
redis.call('HINCRBY', KEYS[1], 'attempts', 1)

-- Compare hashes
if stored_hash == ARGV[1] then
    -- Success: consume the OTP atomically
    redis.call('DEL', KEYS[1])
    return {1, 'success'}
else
    -- Failed: attempts already incremented
    return {0, 'wrong_code'}
end
```

**Why Lua is necessary:**
Lua scripts in Redis execute atomically — no other Redis commands can interleave between the script's commands. The GET, increment, and DEL all happen within one atomic operation. Without Lua:

```
Thread A: HGET otp:sms:user -> {hash: X, attempts: 0}  -- sees valid
Thread B: HGET otp:sms:user -> {hash: X, attempts: 0}  -- also sees valid
Thread A: Compare hash -> match!
Thread B: Compare hash -> match!
Thread A: DEL otp:sms:user                              -- consumes OTP
Thread B: DEL otp:sms:user                              -- already gone, but both matched
Thread A: create_session()
Thread B: create_session()
-- Two sessions created from one OTP
```

The Lua script prevents this: only one execution can check-and-delete atomically. The second concurrent execution finds the key gone (returns `not_found`).

---

### Q4: A user reports they never received their SMS OTP. Walk through your debugging process, naming each component that could have failed.

**Debugging path (in order of likelihood):**

**Step 1: Check audit logs.**
Look for `otp.requested` event: was the request received? Was a job queued? Was the delivery attempted?

```sql
SELECT * FROM otp_deliveries
WHERE user_id = 'user-uuid'
  AND created_at > NOW() - INTERVAL '10 minutes'
ORDER BY created_at DESC;
```

**Step 2: Check Twilio delivery status.**
If the job was sent to Twilio (`otp.delivery.sent` event exists with a `provider_sid`), query Twilio:

```python
message = twilio.messages(provider_sid).fetch()
print(message.status)  # sent, delivered, failed, undelivered
print(message.error_code)  # if failed
```

Twilio statuses and what they mean:
- `sent`: message sent to carrier; awaiting handset confirmation.
- `delivered`: carrier confirmed handset received (US domestic with most carriers).
- `failed`: Twilio couldn't send (invalid phone format, Twilio error).
- `undelivered`: Twilio sent to carrier; carrier reports non-delivery.

**Step 3: Check carrier-specific error codes.**
Twilio error codes:
- `30003`: Unreachable destination handset (phone off, no signal).
- `30004`: Message blocked (by carrier spam filter or user has blocked the number).
- `30005`: Unknown destination handset (phone number doesn't exist or is ported).
- `30006`: Landline or unreachable carrier (can't receive SMS).
- `30007`: Carrier violation (message content filtered).

**Step 4: Check for rate limiting.**
Was the phone number rate-limited?
```python
limit_key = f"rl:otp_req:dest:{sha256(phone)}"
count = redis.get(limit_key)
print(f"Rate limit count: {count}")
```

**Step 5: Check Twilio number status.**
Is the sending number blocked by the carrier or in use by too many messages?
- Check Twilio Messaging Service pool status.
- Check if the from number has been flagged as spam by carriers (check carrier logs in Twilio dashboard).

**Step 6: Phone-specific issues.**
- Does the phone have SMS capabilities? (WiFi-only tablets, VoIP numbers).
- Is the device in an area with no carrier coverage?
- Has the user blocked the short code or long code number?
- Is the carrier filtering A2P (Application-to-Person) SMS? Some international carriers require pre-registration.

**Step 7: SMS worker health.**
Is the worker running? Is the queue being consumed?
```
LLEN sms_queue  -> queue depth
```

If queue depth is growing and not decreasing: worker is down or Twilio is rejecting all messages.

**Resolution path:**
- Temporary failure: advise user to request a new code.
- Persistent failure: offer email OTP as an alternative.
- Invalid phone number: flag for user to update their phone number.

---

### Q5: Why is it important to hash the OTP before storing it in Redis, and why is SHA-256 acceptable here when it's not acceptable for password storage?

**Why hash at all:**
If the OTP is stored in plaintext in Redis and Redis is compromised (lateral movement, misconfigured network access, stolen credentials), an attacker can read every user's current OTP and immediately use them all. With hashing, the attacker reads only hashes — they can't directly use these.

**Why SHA-256 is acceptable here (not bcrypt/Argon2):**

For passwords, bcrypt/Argon2 is required because:
1. Passwords are low-entropy (humans choose them; common passwords exist in rainbow tables).
2. Passwords are long-lived — an attacker can perform an offline brute-force attack over days/weeks after a DB breach.
3. GPU-accelerated cracking can try billions of SHA-256 hashes per second.

For OTPs, the threat model is different:
1. OTPs are **high-entropy random values** (6 digits from CSPRNG = 1 million possibilities). There's no rainbow table for CSPRNG output.
2. OTPs expire in **5 minutes** — an attacker who breaches Redis has 5 minutes to crack a 6-digit code using SHA-256. At 10^10 SHA-256 hashes/second (GPU): 1,000,000 / 10^10 = 0.0001 seconds to try all possibilities. The OTP IS crackable within the TTL.
3. BUT: the attacker also needs to submit the cracked OTP through the API, which is rate-limited. Even if they crack the OTP hash offline in 0.0001 seconds, they can only make 3 API attempts before the OTP is locked.

**The additional protection: HMAC with per-user salt:**
```
HMAC-SHA256(key=user_otp_salt, msg=otp_plaintext)
```
The `user_otp_salt` is a 32-byte random value stored in PostgreSQL. To crack the OTP hash, the attacker needs:
1. The SHA-256 hash (from Redis).
2. The user's `otp_salt` (from PostgreSQL).

A Redis-only breach is insufficient — they need both Redis AND PostgreSQL. This defense-in-depth significantly raises the bar even though SHA-256 alone would be breakable.

**When would you use Argon2 for OTPs?**
Never — the combination of short TTL, rate limiting, and per-user HMAC salt provides equivalent protection with much lower computational cost (important for sub-10ms verification latency).

---

### Q6: What is the "OTP rotation" attack and how do your rate limiting controls prevent it?

**The attack:**

The attacker knows a victim's OTP is a 6-digit code. Instead of brute-forcing a single code (3 attempts then locked), they:

1. Request OTP1 for the victim. Get 3 guesses.
2. Request OTP2 (new code, OTP1 superseded). Get 3 more guesses.
3. Request OTP3. 3 more guesses.
4. Continue indefinitely, rotating codes.

With no rate limit on requests: 3 guesses × unlimited codes = unlimited total guesses. This reduces the problem to "guess in which of my infinite guesses does the random number match?" — equivalent to a brute force attack.

**Why this attack matters:**

Without per-destination rate limiting (only per-OTP attempt limits), the attacker bypasses the attempt limit by never using all 3 attempts on the same code:
- Guess OTP1 with 1 wrong answer.
- Request new code. OTP1 is superseded.
- Guess OTP2 with 1 wrong answer.
- Repeat.

At 1 new code per second: 60 codes/minute × 1 guess each = 60 guesses/minute. Expected time to crack: 1,000,000 / 60 / 60 = 4.6 hours. Feasible for high-value targets.

**Rate limiting controls that prevent it:**

1. **Resend cooldown (60 seconds):** Between each OTP request, 60 seconds must pass. Now: 1 code/minute × 3 guesses = 3 guesses/minute. Expected crack time: 1,000,000 / 3 / 60 / 24 = 231 days.

2. **Per-destination hourly limit (3 OTPs/hour):** Even if resend cooldown is bypassed (e.g., by doing 1 request per 60 seconds for multiple users), this hard cap limits total codes per destination to 3/hour. 3 codes/hour × 3 guesses = 9 guesses/hour. Expected crack time: 1,000,000 / 9 / 24 = 4,629 days (12.7 years).

3. **Partial auth token TTL (10 minutes):** After 10 minutes, the partial auth state expires. The attacker must re-enter the password (which they have) and restart the OTP flow. But the per-destination rate limit persists in Redis — they still face the 3 OTPs/hour limit.

4. **Cumulative wrong answer tracking:** In addition to per-OTP attempt limits, track total failed MFA attempts per user in a sliding window. After 10 total failures across multiple OTPs in 1 hour: lock MFA for this user temporarily and require support intervention.

---

### Q7: How would you architect the OTP system to maintain functionality during a full Redis outage? What are the security tradeoffs?

**The problem:** Redis stores OTPs, rate limits, partial auth tokens, and sessions. A Redis outage means:
- Can't store new OTPs → OTP request fails.
- Can't validate OTPs → OTP verify fails.
- Can't check rate limits → rate limits bypassed.
- Can't create sessions after OTP verify.

**Option A: Fall back to PostgreSQL for OTP storage.**

```python
class OTPStore:
    def store_otp(self, user_id, channel, otp_hash):
        try:
            self.redis.hset(...)
            self.redis.expireat(...)
        except RedisException:
            # Fall back to PostgreSQL
            self.db.execute(
                "INSERT INTO otp_fallback (user_id, channel, otp_hash, expires_at)"
                " VALUES ($1, $2, $3, NOW() + INTERVAL '5 minutes')",
                user_id, channel, otp_hash
            )

    def get_otp(self, user_id, channel):
        try:
            return self.redis.hgetall(...)
        except RedisException:
            return self.db.fetchone(
                "SELECT otp_hash, attempts FROM otp_fallback"
                " WHERE user_id=$1 AND channel=$2 AND used_at IS NULL AND expires_at>NOW()",
                user_id, channel
            )
```

**Security tradeoff:** PostgreSQL is slower (5–15ms vs 0.5ms) and less suited for atomic operations. The Lua-based atomic verify must be reimplemented as a PostgreSQL transaction with `SELECT FOR UPDATE`. The PostgreSQL approach also requires a cleanup job for expired OTP records.

**Option B: Circuit breaker with degraded mode.**

```python
if redis.is_available():
    # Normal flow
    store_in_redis()
    rate_limit_via_redis()
else:
    # Degraded mode:
    # - Accept OTP flow without rate limiting (security risk)
    # - Use PostgreSQL for OTP storage only
    # - Log that rate limiting is degraded (alert team)
    store_in_postgresql()
    # Skip rate limiting -- log security alert
    metrics.increment("otp.degraded_mode.rate_limits_disabled")
```

**Security tradeoff:** Disabling rate limits during Redis outage opens a window for brute force attacks. The outage window is typically short (seconds to minutes for Redis Sentinel failover). An attacker who can time or trigger a Redis outage could disable rate limits on demand — a significant attack vector.

**Option C: Dual-write (Redis primary + PostgreSQL secondary).**

Write to both Redis and PostgreSQL synchronously. Reads from Redis normally; fall back to PostgreSQL on Redis miss/error. This provides full durability but doubles write latency.

**Recommendation:** Use Redis Sentinel (automatic failover in <30 seconds) and accept the brief disruption window during failover. The outage window is short enough that the security risk is minimal. Implement alerting on Redis unavailability to minimize response time.

---

### Q8: What is the security difference between storing the partial auth token in a cookie vs. localStorage vs. sessionStorage? What should the application use?

**Partial auth token storage options:**

**localStorage:**
- Persists across browser tabs and browser restarts.
- Accessible to JavaScript: `localStorage.getItem('partial_auth_token')`.
- XSS vulnerability: malicious script reads token and sends to attacker server.
- Risk: Token persists even after the tab is closed — if the user abandons an MFA flow, the token remains until JS explicitly removes it or it's manually cleared.

**sessionStorage:**
- Same as localStorage but cleared when the tab is closed.
- Still accessible to JavaScript — XSS can read it.
- Better than localStorage for partial auth (cleared when user closes tab).
- Still XSS-vulnerable.

**Memory (JavaScript variable):**
- Best XSS protection — not accessible from outside the module that sets it.
- Lost on page reload. If user reloads the MFA page, they must restart the flow (minor UX issue).
- Cannot be accessed by `document.cookie` or `localStorage` getters.

**HttpOnly Cookie:**
- Cannot be read by JavaScript at all (HttpOnly flag).
- Automatically sent with every request to the domain (including the `/otp/verify` endpoint).
- Protected against XSS token theft.
- Vulnerable to CSRF: if `SameSite=None`, a cross-site POST could include the cookie.
- Use `SameSite=Lax` or `SameSite=Strict` to prevent CSRF.

**Recommended approach:**
Store the partial auth token as an `HttpOnly; Secure; SameSite=Strict` cookie. This provides:
- No XSS access.
- No CSRF risk (SameSite=Strict).
- Automatic transmission to `/otp/verify` without JavaScript handling.

The cookie name should use the `__Host-` prefix for maximum security:
```
Set-Cookie: __Host-partial_auth=eyJhbGci...; Secure; HttpOnly; SameSite=Strict; Path=/
```

This scopes the cookie to the exact host (not subdomains) and requires HTTPS.

---

### Q9: Why do email OTPs have different security properties than SMS OTPs? In what scenarios would you choose one over the other?

**Fundamental security difference:**

SMS OTP security depends on:
- Physical possession of the SIM card (can be swapped).
- Carrier network integrity (SS7 vulnerabilities).
- No prior relationship with the communication channel.

Email OTP security depends on:
- Access to the email account (protected by email provider's security: password + potentially MFA on the email account itself).
- Email account not being compromised.
- Email provider's delivery infrastructure integrity.

**SMS advantage over email:**
- Faster delivery (seconds vs. minutes).
- No prior relationship needed — any valid phone number works.
- Phone possession is physically harder to remotely compromise than email credentials.
- SMS is delivered to the registered SIM — harder to redirect without physical SIM access.

**Email advantage over SMS:**
- No SS7 vulnerability.
- No SIM swap risk.
- Email account can have strong security (2FA on email itself).
- Lower cost (~100x cheaper than SMS).
- Works internationally without carrier complications.
- No regulatory issues (some countries restrict A2P SMS without pre-registration).

**When to choose SMS:**
- When the target demographic predominantly uses mobile phones.
- When real-time delivery is critical (SMS is faster).
- When the user's phone is already registered and verified.
- When the account value is high enough to justify the cost.

**When to choose email:**
- When SMS delivery is unreliable (international users, VoIP numbers).
- When cost sensitivity is high (email is ~100x cheaper).
- When the user's email account has its own MFA (Gmail with TOTP = email OTP is effectively 2FA-protected).
- When the application already requires email verification.

**When to offer both:**
Many applications offer a choice or automatic fallback. If SMS delivery fails (carrier error, invalid number), fall back to email OTP. User preference settings allow choosing the preferred channel.

---

### Q10: How would you detect and respond to a coordinated OTP bombing campaign targeting 10,000 user accounts simultaneously?

**Detection phase:**

**Signal 1: Global OTP request rate spike.**
Normal baseline: 100 OTP requests/minute. Attack: 10,000 requests in 60 seconds = 167 requests/second. A rate spike of 100x normal triggers an immediate alert.

```python
# Prometheus rule
- alert: OTPRequestSpike
  expr: rate(otp_requests_total[1m]) > 100 * avg_over_time(otp_requests_total[1m:1h])[1d]
  severity: critical
```

**Signal 2: Distributed source pattern.**
Normal requests come from a distribution of IPs matching the user base geolocation. Attack: 10,000 different IPs, possibly concentrated in one region (botnet).

**Signal 3: Low conversion rate.**
In a bombing attack, no OTPs will be verified (the attacker's goal is email/SMS flooding, not account takeover). Track `otp_requests_total` vs `otp_verify_success_total`. If >90% of OTPs are never verified, this is anomalous.

**Signal 4: Per-destination repetition at scale.**
Each target receives 3 OTPs (per-hour limit) in quick succession. Monitor for "same destination hash receiving max rate limit" events across thousands of destinations simultaneously.

**Response actions (escalating):**

**Level 1: Automatic (trigger on 10x spike):**
- Enable CAPTCHA on the OTP request endpoint (add a CAPTCHA verification step before processing).
- Increase per-IP rate limits temporarily (reduce from 10 to 3 requests per 15 minutes).
- Alert the on-call team.

**Level 2: Manual (if Level 1 insufficient):**
- Identify source IP ranges (likely botnet ASNs). Block at the WAF/CDN level (Cloudflare firewall rule).
- Temporarily reduce global OTP rate limit.
- Notify email/SMS provider of elevated volume (avoid being flagged as spammer).

**Level 3: Emergency (if attack continues):**
- Temporarily suspend OTP endpoint (return 503 with retry-after).
- This locks out legitimate users for the duration but stops the bombing.
- Communicate via status page: "We are experiencing a service disruption. Please try again in X minutes."

**Post-incident:**
- Analyze attack patterns: what IPs, what time, what rate.
- Implement fingerprint-based detection (devices making only OTP requests, no other app traffic).
- Add behavioral rate limiting: if a user's account has received max OTPs in the last hour with no successful verification, block further OTP requests for 24 hours (suspicious abandonment pattern).

---

### Q11: What happens to a user's authentication state if the OTP expires between the request and their verification attempt? What is the correct behavior and what should the error handling communicate?

**The scenario:**
1. User requests an OTP at T=0. OTP is valid for 5 minutes (expires at T=300s).
2. User is slow to act (distracted, slow email delivery, searching for the code). At T=305s, they submit the OTP.
3. The Redis key `otp:{channel}:{user_id}` has expired. Redis returns nil on the HGETALL.

**What happens in the backend:**

```python
otp_data = redis.hgetall(f"otp:{channel}:{user_id}")
if not otp_data:
    # OTP not found -- could be:
    # 1. Expired (most common after 5 minutes)
    # 2. Already used (user submitted twice)
    # 3. Superseded (user requested a new code)
    # 4. Never existed (forged request)
    # All return the same error message
    return error("invalid_otp")
```

**What the user sees:**

```json
{"error": "invalid_otp", "attempts_remaining": null}
```

**What the system should communicate (good UX):**

The API cannot distinguish "expired" from "wrong code" from the client's perspective (same error message for enumeration prevention). But we CAN provide a hint:

If the partial auth token was issued more than 5 minutes ago (the OTP TTL), the API can infer the code likely expired and include a resend prompt:

```json
{
  "error": "invalid_otp",
  "hint": "Your code may have expired. Request a new one.",
  "can_resend": true
}
```

This is acceptable information disclosure — it doesn't confirm the code was correct but expired (it just says the user might want to resend).

**The correct error handling flow:**

1. OTP verify returns `invalid_otp`.
2. SPA checks: is the partial auth token still valid? (`exp` from the JWT claim). If the partial auth token is also expired: show "Your session expired. Please start over." with a link to the login page.
3. If the partial auth token is still valid but OTP verification failed: show "Invalid code. Request a new one?" with a resend button (if resend cooldown has elapsed).
4. The user should NOT be forced back to the login page just because the OTP expired — the partial auth token gives them a window to request a new OTP without re-entering their password.

**Edge case: partial auth token expires during OTP entry:**
The user enters their OTP at T=601s (1 second after the 10-minute partial auth token TTL). The OTP verification fails because the partial auth token is invalid. The error should be: "Your session has expired. Please log in again." The user must restart the full login flow.

---

### Q12: A security researcher discovers that your OTP delivery logs contain plaintext OTP values due to a misconfigured email worker. What is the incident response process and what data was exposed?

**Initial assessment:**

**What data was logged:**
- Plaintext OTP values (6-digit codes) for all deliveries processed by the misconfigured worker.
- Associated user IDs (or email addresses/phone numbers, depending on log format).
- Timestamps of OTP delivery.

**Who could access these logs:**
- Anyone with read access to the logging system (Splunk, Elasticsearch, CloudWatch Logs, etc.).
- Depends on IAM/RBAC controls on the logging system.

**What an attacker with these logs could do:**
- For OTPs issued in the last 5 minutes: attempt to use them to complete MFA flows (if they also have the user's password and partial auth session).
- For OTPs older than 5 minutes: useless (they've expired). But historical patterns could be analyzed (though the codes are random, so there's no useful pattern).

**The exposure is time-limited:** OTPs are only valid for 5 minutes. Log access more than 5 minutes after the incident has no direct exploit value for completing MFA. However:
- If the logs contain partial auth tokens (they should not — these should also never be logged), those could be exploited.
- The phone numbers/emails in the logs are PII — a data breach.

**Immediate response (first 30 minutes):**

1. **Rotate the worker configuration** immediately. Redeploy the email worker without the OTP logging.
2. **Mass OTP invalidation**: Delete all active OTP records in Redis. All current MFA flows are disrupted (users must request new codes). This is a hard protection: even if someone has a plaintext OTP from the logs, the Redis record is gone and the code can't be verified.
   ```python
   # Emergency invalidation
   for key in redis.scan_iter("otp:email:*"):
       redis.delete(key)
   ```
3. **Rotate Twilio/SendGrid credentials**: If the logs were exposed to an attacker, they may have seen API credentials as well (if workers log credentials — another misconfiguration to check).
4. **Notify the security team and legal/compliance**: Potential PII exposure (email addresses) requires GDPR breach notification within 72 hours if EU data subjects are affected.

**Log remediation:**
1. Revoke log access immediately while investigation is ongoing.
2. Identify the time window of misconfiguration.
3. Delete or redact affected log entries (if GDPR/CCPA requires deletion).
4. Audit who accessed the logs during the window.

**Longer-term fixes:**
1. Add a code review check: no sensitive fields (OTP values, tokens, credentials) should ever be passed to logging functions.
2. Implement log scrubbing middleware: any log entry matching `\d{6}` pattern or known token formats is redacted before writing.
3. Add secrets detection to CI/CD pipeline (git-secrets, truffleHog for code; custom rules for log content).
4. Separate the log aggregation IAM role: narrower access so not all engineers have access to OTP delivery logs.

---

*Document version: 1.0 | Classification: Internal Engineering | Author: Security Engineering*  
*This document contains security-sensitive architectural details. Handle as CONFIDENTIAL.*  
*Do not distribute externally or commit to public repositories.*
