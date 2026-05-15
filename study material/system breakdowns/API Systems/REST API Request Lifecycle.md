# REST API Request Lifecycle — Internal Engineering & Security Document

**Classification:** Internal Engineering Reference  
**Audience:** All Engineers (Beginner to Senior), Security Engineers, Platform Architects  
**Scope:** Complete breakdown of what happens — at every layer — when a client makes a REST API request  
**System:** A production-grade REST API (e.g., `GET https://api.example.com/v1/users/42/profile`)

---

## A Beginner's Orientation

**What is a REST API?**

REST (Representational State Transfer) is an architectural style for building networked applications. A REST API is a server that receives structured requests (over HTTP) and returns structured responses (usually JSON). Think of it as a waiter at a restaurant: you (the client) give your order (the request) using a standardized menu format (HTTP), and the waiter brings back your food (the response) — or tells you why they can't.

**What "request lifecycle" means:**

Every single API call — from the moment you call `fetch()` in JavaScript or `requests.get()` in Python — triggers an enormous chain of events across multiple systems. Most engineers only see the beginning ("I sent a GET") and the end ("I got a 200 OK"). This document explains every step in between: how bytes travel through cables, how cryptography protects your data, how servers parse and route your request, how databases are queried, how responses are built and sent back, and where every failure and attack vector lives.

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

A React.js web application makes an authenticated REST API call to fetch a user's profile. The frontend runs in the browser. The backend is a Node.js/Express API server sitting behind an nginx reverse proxy and an AWS Application Load Balancer.

```
Request: GET https://api.example.com/v1/users/42/profile
Headers: Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
```

We trace every microsecond.

---

### Step 1: The JavaScript Call (T+0ms)

The developer wrote:

```javascript
const response = await fetch('https://api.example.com/v1/users/42/profile', {
  method: 'GET',
  headers: {
    'Authorization': `Bearer ${accessToken}`,
    'Accept': 'application/json',
    'X-Request-ID': crypto.randomUUID()
  }
});
const data = await response.json();
```

**What the user sees:** Nothing yet. The UI might show a loading spinner.

**What actually happens at T+0ms:**

The browser's JavaScript engine executes `fetch()`. This is not a simple function call — it triggers the browser's networking subsystem through a series of internal browser APIs:

1. `fetch()` creates a `Request` object with the URL, method, and headers
2. The browser checks if this is a same-origin or cross-origin request
   - `api.example.com` is different from `app.example.com` → cross-origin
   - The browser prepares to send a **CORS preflight** (OPTIONS request) first
3. The browser's network stack looks up `api.example.com` in its DNS cache
4. Everything below this point is "invisible" to the JavaScript — it's happening in the browser's C++ networking layer

---

### Step 2: CORS Preflight (T+0ms to T+~50ms)

Because this is a cross-origin request with a custom header (`Authorization`), the browser automatically sends an HTTP OPTIONS request first:

```http
OPTIONS /v1/users/42/profile HTTP/2
Host: api.example.com
Origin: https://app.example.com
Access-Control-Request-Method: GET
Access-Control-Request-Headers: authorization, x-request-id
```

**Why this exists:** A website at `evil.com` should not be able to silently make authenticated requests to `bank.com` using your cookies/tokens. The preflight asks the server: "Will you accept a cross-origin GET request with these headers?" The server's response tells the browser whether to proceed.

**Server responds:**

```http
HTTP/2 204
Access-Control-Allow-Origin: https://app.example.com
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
Access-Control-Allow-Headers: Authorization, Content-Type, X-Request-ID
Access-Control-Max-Age: 86400
Access-Control-Allow-Credentials: false
```

`Access-Control-Max-Age: 86400` means the browser caches this preflight response for 24 hours — subsequent requests from the same origin don't need a new preflight.

---

### Step 3: DNS Resolution (T+50ms to T+~100ms)

The browser needs the IP address for `api.example.com`. Full DNS flow is covered in Section 2.

**What the user sees:** Still the loading spinner.

**What happens:** DNS lookup returns `52.14.200.42` (an AWS ALB IP). This answer is cached for the duration of the DNS TTL (e.g., 60 seconds).

---

### Step 4: TCP Connection (T+100ms to T+~150ms)

The browser establishes a TCP connection to `52.14.200.42:443`. The TCP 3-way handshake completes in one round-trip time (~30-60ms for a US user to a US server).

**HTTP/2 connection reuse:** If the browser has an existing HTTP/2 connection to `api.example.com` from a previous request (within the same browser tab/session), it reuses that connection and skips TCP + TLS entirely. Only the first request to a new origin pays these costs.

---

### Step 5: TLS Handshake (T+150ms to T+~200ms)

TLS 1.3 requires one round-trip. The browser and server negotiate encryption keys and verify the server's identity. Full details in Section 2.

---

### Step 6: The Actual HTTP Request (T+200ms)

Now the actual GET request is sent, encrypted inside TLS:

```http
GET /v1/users/42/profile HTTP/2
Host: api.example.com
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyXzEyMyJ9.signature
Accept: application/json
X-Request-ID: 550e8400-e29b-41d4-a716-446655440000
Accept-Encoding: gzip, deflate, br
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
```

---

### Step 7: The Request Travels Through the Stack (T+200ms to T+~250ms)

The request hits the AWS Application Load Balancer → nginx reverse proxy → Node.js API server. At each hop:

1. **ALB:** Terminates TCP (not TLS in this setup — nginx does TLS), routes to a healthy nginx instance based on load
2. **nginx:** Terminates TLS, validates Host header, applies rate limiting, proxies to Node.js app at `localhost:3000`
3. **Node.js Express app:** Middleware chain executes (logging → CORS → auth → rate limiting → route handler)

---

### Step 8: Business Logic Execution (T+250ms to T+~350ms)

The route handler:
1. Validates the JWT token (verify signature, check expiry, check claims)
2. Checks authorization: "Can user_123 (from JWT) access user_42's profile?"
3. Queries PostgreSQL: `SELECT * FROM users WHERE id = 42`
4. Possibly fetches from Redis cache first
5. Builds the response object
6. Serializes to JSON
7. Sends HTTP response

---

### Step 9: Response Travels Back (T+350ms to T+~400ms)

```http
HTTP/2 200
Content-Type: application/json; charset=utf-8
X-Request-ID: 550e8400-e29b-41d4-a716-446655440000
Cache-Control: private, max-age=60
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 987
X-RateLimit-Reset: 1700000060
ETag: "a1b2c3d4"
Content-Encoding: gzip

{"id": 42, "username": "alice", "email": "alice@example.com", ...}
```

The browser decompresses the gzip response, parses the JSON, and the JavaScript's `await` resolves with the data. The loading spinner disappears and the user's profile data renders.

**Total time from click to render: ~400ms** (varies widely: 50ms locally, 2s+ on slow mobile networks)

---

## 2. Network Layer Flow

### DNS Resolution — Complete Mechanics

DNS translates human-readable names (`api.example.com`) into machine-readable IP addresses (`52.14.200.42`).

**The full resolution chain for a cold lookup:**

```
Browser DNS Cache → OS DNS Cache → OS Stub Resolver
  → Recursive Resolver (e.g., 8.8.8.8 or ISP's resolver)
    → Root Nameserver (one of 13 logical roots, anycast)
    → .com TLD Nameserver (Verisign)
    → example.com Authoritative Nameserver
    → Returns A/AAAA record
```

**Recursive vs. Authoritative — what's the difference?**

- **Recursive resolver** (e.g., Google's 8.8.8.8): Does the legwork of asking multiple servers to find the answer. It doesn't know the answer itself — it asks around on your behalf. Think of it as a research librarian who checks multiple libraries.
- **Authoritative nameserver**: Has the definitive answer for its zone. For `api.example.com`, example.com's authoritative nameserver is the final authority. Think of it as the library that actually owns the book.

**What gets returned:**

```
Query:  api.example.com. IN A
Answer: api.example.com. 60 IN A 52.14.200.42
        (TTL of 60 seconds — cached for 60s at each layer)
```

**Additional records that matter:**

```
; CAA record — which CAs can issue certs for this domain
api.example.com. 3600 IN CAA 0 issue "letsencrypt.org"
api.example.com. 3600 IN CAA 0 issue "digicert.com"

; MX — mail servers (not relevant for API, but show zone structure)
; TXT — SPF, DKIM, verification records

; HTTPS record (newer) — hints for HTTP/3 and ALPN
api.example.com. 3600 IN HTTPS 1 . alpn="h3,h2" ipv4hint="52.14.200.42"
```

**DNS over HTTPS (DoH) / DNS over TLS (DoT):**

Modern browsers (Chrome, Firefox) use DoH by default. Instead of sending DNS queries over UDP port 53 (visible to ISPs and network observers), they send encrypted HTTPS queries to a configured resolver (e.g., Cloudflare's `1.1.1.1` or Google's `8.8.8.8` via HTTPS). This hides which domains you're resolving from network observers. The resolution logic is identical — only the transport changes.

**Where DNS can fail:**
- Recursive resolver is down: browser falls back to OS stub resolver or fails
- Authoritative NS is unreachable: recursive resolver retries, eventually times out (~15-30s)
- TTL expired + NS temporarily down: stale cached response served (usually the right behavior)
- DNS cache poisoning: attacker injects false records (mitigated by DNSSEC)
- Wrong A record returned: misconfiguration sends traffic to wrong IP

---

### TCP 3-Way Handshake

**For beginners:** TCP (Transmission Control Protocol) is the protocol that ensures reliable delivery of data. Before sending HTTP data, TCP must establish a connection between the two computers.

```
CLIENT (Browser, 10.0.0.5:54321)          SERVER (ALB, 52.14.200.42:443)
           |                                          |
           |  SYN [seq=1000, mss=1460, sack, ws=256] |
           |  "Hi, I want to connect.                 |
           |   My starting sequence number is 1000"   |
           |----------------------------------------->|
           |                                          |
           |  SYN-ACK [seq=5000, ack=1001, mss=1460] |
           |  "OK! My sequence is 5000.               |
           |   I acknowledge your byte 1000"          |
           |<-----------------------------------------|
           |                                          |
           |  ACK [ack=5001]                          |
           |  "Acknowledged. Connection open."        |
           |----------------------------------------->|
           |                                          |
           |  [Connection established — 1 RTT]        |
           |  [TLS handshake begins immediately]      |
```

**MSS (Maximum Segment Size):** 1460 bytes. This comes from: Ethernet MTU (1500 bytes) - IP header (20 bytes) - TCP header (20 bytes) = 1460 bytes of payload per packet. Larger payloads are fragmented across multiple packets.

**Sequence numbers:** Each byte of data has a sequence number. If packet with bytes 1000-2460 is lost, the receiver asks only for those bytes to be resent (SACK — Selective Acknowledgment). Without SACK, everything after the lost packet would need retransmission.

**Window scaling:** The TCP window size controls flow — how many bytes can be in-flight before acknowledgment. Without window scaling (capped at 65535 bytes), a 100Mbps connection with 50ms RTT could only use ~1.3Mbps. Window scaling allows much larger windows.

**Where TCP can fail:**
- SYN flood: attacker sends millions of SYN packets, exhausting server's half-open connection table
- Network congestion: window shrinks, throughput drops, latency spikes
- MTU black hole: path MTU discovery fails, large packets are silently dropped
- NAT timeout: firewall/NAT device forgets the connection after idle period (TCP keepalives prevent this)

---

### TLS 1.3 Handshake — Complete Mechanics

**For beginners:** TLS (Transport Layer Security) creates an encrypted tunnel. After the TCP connection is open, TLS negotiates encryption before any HTTP data is sent. This prevents eavesdroppers from reading your Authorization token or response data.

```
CLIENT                                              SERVER (nginx)
  |                                                      |
  | ClientHello                                          |
  | ─ TLS version: 1.3                                   |
  | ─ Cipher suites (in preference order):               |
  |     TLS_AES_256_GCM_SHA384                           |
  |     TLS_AES_128_GCM_SHA256                           |
  |     TLS_CHACHA20_POLY1305_SHA256                     |
  | ─ key_share extension:                               |
  |     X25519 ephemeral public key (32 bytes)           |
  |     This enables the server to compute shared secret |
  |     without another round trip                        |
  | ─ SNI: "api.example.com"                             |
  |   (which virtual host to connect to — critical for   |
  |    shared IP hosting of multiple domains)            |
  | ─ ALPN: ["h2", "http/1.1"]                          |
  |   (which protocol version to use)                    |
  | ─ session_ticket: [cached ticket for 0-RTT]         |
  |---------------------------------------------------->|
  |                                                      |
  | ServerHello                                          |
  | ─ Selected cipher: TLS_AES_256_GCM_SHA384           |
  | ─ key_share: server's X25519 ephemeral pub key      |
  | ─ ALPN selected: "h2" (HTTP/2)                      |
  |                                                      |
  | {EncryptedExtensions}  ← encrypted from here on    |
  |                                                      |
  | {Certificate}                                        |
  | ─ api.example.com leaf cert                         |
  | ─ Intermediate CA cert                               |
  | ─ OCSP staple (revocation proof)                    |
  | ─ SCTs (Certificate Transparency proofs)            |
  |                                                      |
  | {CertificateVerify}                                  |
  | ─ Signature over the entire handshake transcript    |
  | ─ Proves server has the private key for the cert    |
  |                                                      |
  | {Finished}                                           |
  | ─ HMAC over handshake transcript                    |
  |<----------------------------------------------------|
  |                                                      |
  | [Client verifies certificate chain]                  |
  | [Client checks OCSP staple or queries OCSP]         |
  | [Client verifies signature and Finished HMAC]       |
  |                                                      |
  | {Finished}                                           |
  | [Application data can now flow]                     |
  |---------------------------------------------------->|
```

**The key exchange math (simplified):**

Both sides contribute random values:
- Client: `client_private_key`, `client_public_key` (X25519 key pair, ephemeral)
- Server: `server_private_key`, `server_public_key` (X25519 key pair, ephemeral)

Shared secret: `client_private_key * server_public_key = server_private_key * client_public_key`

This is Diffie-Hellman. The beauty: even if someone records all the traffic and later steals the server's long-term private key (from the certificate), they **cannot** decrypt past sessions. Why? Because the shared secret was derived from ephemeral X25519 keys, which were discarded after the handshake. This property is called **Perfect Forward Secrecy (PFS)**.

**Session resumption (0-RTT):**
If the client has a session ticket from a previous connection to this server, TLS 1.3 allows sending application data in the first packet (0 additional round trips). The risk: 0-RTT data is **replayable** (no protection against an attacker replaying the same 0-RTT request). Safe for idempotent GETs, dangerous for POST/PUT/DELETE. Servers should treat 0-RTT requests as potentially replayed.

**Certificate validation chain:**
```
Root CA (built into browser/OS trust store)
    ↓ (Root signs Intermediate's public key)
Intermediate CA (e.g., "DigiCert TLS RSA SHA256 2020 CA1")
    ↓ (Intermediate signs Leaf's public key)
Leaf Certificate (api.example.com)
    - Subject: CN=api.example.com, SAN=*.example.com
    - Public Key: P-256 ECDSA (256-bit elliptic curve)
    - Not Before: 2024-01-01, Not After: 2025-01-01
    - OCSP URL: http://ocsp.digicert.com
    - CT logs: proof of logging in at least 2 CT logs
```

The browser validates: signature chain → not expired → hostname matches → not revoked (OCSP) → CT proof exists.

**Cipher suite deep dive:**

`TLS_AES_256_GCM_SHA384` means:
- `AES_256_GCM`: AES-256 in Galois/Counter Mode — the symmetric encryption algorithm for application data. GCM is an AEAD mode: encrypts + authenticates in one pass
- `SHA384`: The hash function used for the key derivation function (HKDF)

`TLS_CHACHA20_POLY1305_SHA256`: 
- `CHACHA20`: Stream cipher, faster than AES on devices without hardware AES acceleration (mobile phones)
- `POLY1305`: Authentication tag generation
- Better for mobile/IoT; similar security to AES-GCM

---

### Full Network Flow Diagram

```
BROWSER                ALB              NGINX            NODE.JS        POSTGRESQL
   |                    |                 |                 |               |
   | DNS: api.example.com                 |                 |               |
   |---->[DNS Resolver]-------> IP        |                 |               |
   |<---- 52.14.200.42 ----------------  |                 |               |
   |                    |                 |                 |               |
   | TCP SYN ---------> |                 |                 |               |
   | TCP SYN-ACK <----- |                 |                 |               |
   | TCP ACK ---------> |                 |                 |               |
   |                    |                 |                 |               |
   | TLS ClientHello -> |                 |                 |               |
   | TLS ServerHello <- |                 |                 |               |
   | TLS Finished ----> |                 |                 |               |
   |                    |                 |                 |               |
   | OPTIONS /v1/...    |                 |                 |               |
   | (CORS Preflight) ->|-- route to --> |                 |               |
   |                    |                 | CORS check      |               |
   | 204 No Content <---|<--- 204 --------|                 |               |
   |                    |                 |                 |               |
   | GET /v1/users/42/profile             |                 |               |
   | Authorization: Bearer {jwt} ------> |                 |               |
   |                    |    proxy_pass   |                 |               |
   |                    |----local:3000-->|                 |               |
   |                    |                 | middleware chain|               |
   |                    |                 | → logging       |               |
   |                    |                 | → rate limit    |               |
   |                    |                 | → auth (JWT)    |               |
   |                    |                 | → route handler |               |
   |                    |                 |                 | Redis GET     |
   |                    |                 |                 |--cache check->|
   |                    |                 |                 | (miss)        |
   |                    |                 |                 |               |
   |                    |                 |                 | SELECT query  |
   |                    |                 |                 |-------------->|
   |                    |                 |                 |<-- row data --|
   |                    |                 |                 |               |
   |                    |                 |                 | Redis SET     |
   |                    |                 |                 |-- cache write>|
   |                    |                 |                 |               |
   |                    |                 | serialize JSON  |               |
   |                    |                 | set headers     |               |
   |                    |                 | gzip compress   |               |
   |                    |<-- 200 OK ------|                 |               |
   | 200 OK <-----------| {profile data}  |                 |               |
   | {JSON body}        |                 |                 |               |
   |                    |                 |                 |               |
   | [Parse JSON]       |                 |                 |               |
   | [Update UI]        |                 |                 |               |
```

### Latency Budget for a Typical API Call

| Phase | Latency | Notes |
|---|---|---|
| DNS (cold) | 20–100ms | Cached after first lookup |
| DNS (warm) | 0ms | Browser cache hit |
| TCP handshake | 1× RTT (~30–60ms) | Once per new connection |
| TLS 1.3 (cold) | 1× RTT | Once per new connection |
| TLS 1.3 (0-RTT) | 0ms | Session resumption |
| CORS preflight | 1× RTT + server processing | Cached for `Max-Age` seconds |
| HTTP request in-flight | 1× RTT | Network transit |
| Server processing | 10–500ms | Varies by endpoint complexity |
| Database query | 1–100ms | Indexed query vs. full scan |
| Cache hit | 0.1–1ms | Redis local to app server |
| HTTP response in-flight | Variable (depends on size) | ~1ms per 150KB on 100Mbps |
| **Total (new connection)** | **~200–800ms** | |
| **Total (warm connection)** | **~50–200ms** | No TCP/TLS overhead |

---

## 3. Application Layer Flow

### The HTTP/2 Request On-the-Wire

After TLS is established, the HTTP/2 protocol takes over. HTTP/2 differs from HTTP/1.1 in several important ways:

**HTTP/2 framing:**

```
HTTP/2 HEADERS Frame (stream 1):
  +-----------------------------------------------+
  |                  Length (24-bit)               |
  +---------------+---------------+---------------+
  |   Type (0x1 = HEADERS)        |   Flags        |
  +---------------+---------------+---------------+
  |R|              Stream Identifier               |
  +=+=============+================================+
  |                 Header Block Fragment          |
  | :method = GET                                  |
  | :path = /v1/users/42/profile                   |
  | :scheme = https                                |
  | :authority = api.example.com                   |
  | authorization = Bearer eyJhbGci...             |
  | accept = application/json                      |
  | x-request-id = 550e8400-e29b-41d4-a716-...   |
  +-----------------------------------------------+
```

**HTTP/2 header compression (HPACK):**

If you make 100 requests to the same API, headers like `authorization` and `accept` repeat. HTTP/2 uses HPACK compression: a dynamic table is maintained at both ends. After the first request, repeated header names and values are replaced by a small integer index.

Example:
- First request: `authorization: Bearer eyJhbGci...` → sent in full (40 bytes)
- Subsequent requests: index 32 → 1 byte represents the same header/value pair

This is why HTTP/2 is significantly faster than HTTP/1.1 for API-heavy applications that make many small requests.

**HTTP/2 multiplexing:**

HTTP/1.1 has head-of-line blocking: if you make 6 API calls, they queue (you can open 6 TCP connections to parallelize, but that wastes resources). HTTP/2 opens one TCP connection and multiplexes all 6 requests as separate streams, interleaving their frames. Each stream has a unique Stream ID (1, 3, 5, 7... odd numbers for client-initiated).

---

### The Complete HTTP Request Structure

```http
GET /v1/users/42/profile HTTP/2
Host: api.example.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleS0yMDI0LTAxIn0.eyJzdWIiOiJ1c2VyXzEyMyIsImF1ZCI6WyJhcGkuZXhhbXBsZS5jb20iXSwiaXNzIjoiaHR0cHM6Ly9hdXRoLmV4YW1wbGUuY29tIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjE3MDAwMDM2MDAsInJvbGVzIjpbInVzZXIiXX0.SIGNATURE_HERE
Accept: application/json
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cache-Control: no-cache
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0
X-Request-ID: 550e8400-e29b-41d4-a716-446655440000
```

**Header breakdown:**

`Authorization: Bearer [JWT]` — The most important header. Contains the user's JWT access token. The `Bearer` scheme means "the bearer of this token is authenticated." The token itself is base64url-encoded JSON.

`Accept: application/json` — Client preference for response format. If the API serves multiple formats (JSON, XML, MessagePack), this header drives content negotiation. Missing this header is common; well-designed APIs default to JSON anyway.

`Accept-Encoding: gzip, deflate, br` — Client can decompress gzip, deflate, and brotli. `br` (Brotli) is more efficient than gzip for text (API JSON). Server should prefer Brotli when client supports it.

`Cache-Control: no-cache` — "Don't serve me a cached response without checking with the origin server." This is different from `no-store` (which means don't cache at all). With `no-cache`, a proxy can cache the response but must revalidate with the server before serving it.

`X-Request-ID: [UUID]` — Custom header for distributed tracing. This UUID travels through every service and appears in every log line, allowing you to trace a single request across nginx logs, app logs, database logs, and external service logs.

---

### How the Server Parses the Request

At the nginx level:

```nginx
# nginx.conf relevant sections
server {
    listen 443 ssl http2;
    server_name api.example.com;

    # nginx parses: method, URI, HTTP version, headers
    # URI: /v1/users/42/profile
    # nginx extracts: path = /v1/users/42/profile

    location /v1/ {
        # Rate limiting (see ngx_http_limit_req_module)
        limit_req zone=api_limit burst=50 nodelay;

        # Proxy to upstream
        proxy_pass http://nodejs_upstream;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

At the Express.js level (simplified):

```javascript
// Middleware chain (executes in order for every request)
app.use(requestLogger);          // 1. Log the incoming request
app.use(cors(corsOptions));      // 2. Handle CORS headers
app.use(helmet());               // 3. Set security headers
app.use(rateLimiter);            // 4. Rate limit check
app.use(express.json({           // 5. Parse JSON body (for POST/PUT)
  limit: '1mb',                  //    Limit body size
  strict: true                   //    Only accept objects/arrays
}));
app.use(authMiddleware);         // 6. Validate JWT

// Route-specific handler
app.get('/v1/users/:userId/profile', [
  authorize('user:read'),        // 7. Check specific permission
  validateParams,                // 8. Validate :userId format
  getUserProfile                 // 9. Business logic handler
]);
```

**How Express parses `/v1/users/42/profile`:**

Express uses path-to-regexp to match URL patterns. The route `/v1/users/:userId/profile`:
- `/v1/users/` → literal string match
- `:userId` → captures `42` as `req.params.userId`
- `/profile` → literal string match

After parsing: `req.params = { userId: '42' }` (always a string — must be coerced to number if needed)

---

### How Responses Are Constructed

```javascript
async function getUserProfile(req, res) {
  const { userId } = req.params;
  const requestingUserId = req.user.sub; // from validated JWT

  // 1. Authorization check
  if (parseInt(userId) !== requestingUserId && !req.user.roles.includes('admin')) {
    return res.status(403).json({
      error: 'Forbidden',
      message: 'You cannot access another user\'s profile'
    });
  }

  // 2. Try cache first
  const cacheKey = `user:profile:${userId}`;
  const cached = await redis.get(cacheKey);
  if (cached) {
    return res
      .set('X-Cache', 'HIT')
      .set('Cache-Control', 'private, max-age=60')
      .set('ETag', `"${hash(cached)}"`)
      .json(JSON.parse(cached));
  }

  // 3. Database query
  const user = await db.query(
    'SELECT id, username, email, created_at, bio FROM users WHERE id = $1',
    [userId]
  );

  if (!user.rows.length) {
    return res.status(404).json({ error: 'User not found' });
  }

  // 4. Build response object (deliberately exclude sensitive fields)
  const profile = {
    id: user.rows[0].id,
    username: user.rows[0].username,
    email: user.rows[0].email,
    createdAt: user.rows[0].created_at,
    bio: user.rows[0].bio
  };
  // Note: password_hash, mfa_secret, etc. are NOT included

  // 5. Store in cache
  await redis.setex(cacheKey, 60, JSON.stringify(profile));

  // 6. Send response
  res
    .status(200)
    .set('Content-Type', 'application/json')
    .set('X-Cache', 'MISS')
    .set('Cache-Control', 'private, max-age=60')
    .set('ETag', `"${hash(JSON.stringify(profile))}"`)
    .json(profile);
}
```

**The JSON serialization step:**

`res.json(profile)` calls `JSON.stringify(profile)` and:
- Sets `Content-Type: application/json`
- Serializes the object to a UTF-8 JSON string
- Express doesn't auto-gzip — nginx's `gzip_proxied any` directive gzips the response before sending to the client

**ETag generation:**

The ETag (`"a1b2c3d4"`) is a hash of the response body. If the client sends `If-None-Match: "a1b2c3d4"` on the next request, the server can respond with `304 Not Modified` (no body) if the resource hasn't changed — saving bandwidth.

---

## 4. Backend Architecture

### Complete Service Topology

```
                          INTERNET
                             |
                    +--------v--------+
                    |  CloudFront CDN  |  (caches GET responses for non-sensitive)
                    |  (or Cloudflare) |  WAF rules, DDoS protection, TLS offload
                    +--------+--------+
                             |
                    +--------v--------+
                    |   AWS ALB       |  TCP/HTTP load balancing
                    |   (Layer 7)     |  Health checks, routing rules
                    +--+------+-------+
                       |      |
             +---------+      +----------+
             |                           |
    +--------v--------+        +--------v--------+
    |  nginx Instance  |        |  nginx Instance  |
    |  (Reverse Proxy) |        |  (Reverse Proxy) |
    |  TLS Termination |        |  TLS Termination |
    |  Rate Limiting   |        |  Rate Limiting   |
    |  Gzip, Headers  |        |  Gzip, Headers  |
    +---+------+-------+        +---+------+-------+
        |      |                    |      |
    +---+  +---+                +---+  +---+
    |      |                    |      |
 +--v--+ +--v--+             +--v--+ +--v--+
 |App 1| |App 2|             |App 3| |App 4|
 |Node | |Node |             |Node | |Node |
 |:3000| |:3001|             |:3002| |:3003|
 +--+--+ +--+--+             +--+--+ +--+--+
    |      |                    |      |
    +--+---+--------------------+--+---+
       |                           |
  +----v----+                 +----v----+
  |  Redis  |                 |  Redis  |
  | Primary |                 | Replica |
  | (Writes)|                 | (Reads) |
  +---------+                 +---------+
       |
  +----v-----------+
  |   PostgreSQL   |
  |   Primary      |
  +----+-----------+
       |
  +----v-----------+
  |   PostgreSQL   |
  |   Replica(s)   |
  +----------------+
```

### Services and Their Responsibilities

**CloudFront / CDN:**
- Caches static assets (API docs, SDK files)
- Can cache API responses for public, non-sensitive GET endpoints with appropriate Cache-Control headers
- WAF rules: block SQL injection patterns, known bad IPs, oversized payloads
- Does NOT cache responses with `Authorization` headers unless explicitly configured (and this is usually wrong)

**AWS Application Load Balancer (ALB):**
- Layer 7 load balancing: routes HTTP requests based on URL path, host, headers
- Health checks: sends `GET /health` every 10 seconds to each target; removes unhealthy targets
- Connection draining: when a target is removed, allows in-flight requests to complete (default 300s)
- Sticky sessions: can route a user to the same target using a cookie (needed for stateful apps, but REST APIs should be stateless — avoid this)
- NOT doing TLS termination in this architecture (nginx does it)

**nginx (Reverse Proxy):**
- TLS termination: handles the expensive cryptography, forwards plaintext HTTP to Node.js
- Rate limiting: `limit_req_zone` module, per-IP or per-key rate limits
- Request buffering: nginx buffers slow client uploads before forwarding to Node.js (protects against slow-loris attacks against the app)
- Gzip compression of responses
- Access logging: per-request log line (request ID, timing, status code, bytes sent)
- Static file serving (if any API serves static files — rare)
- Upstream health: marks Node.js instances as unavailable after N failed health checks

**Node.js Express Application:**
- JWT validation middleware
- Business logic
- Database queries
- Cache interactions
- Response serialization

---

### Sync vs. Async Flows

**Synchronous (user waits for response):**

```
GET /v1/users/42/profile
→ Auth middleware validates JWT (in-process, ~1ms)
→ Redis cache check (~0.5ms)
→ Database query if cache miss (~5-50ms)
→ Response serialization (~0.1ms)
→ Gzip compression in nginx (~0.5ms)
Total: 10-100ms of server processing
```

**Asynchronous (returns immediately, work continues in background):**

```
POST /v1/users/42/avatar
→ Upload the image file
→ Server stores raw image, returns 202 Accepted immediately
→ Background job (Bull queue) processes image:
    Resize to multiple dimensions
    Convert to WebP
    Upload to S3
    Update database record
→ Client polls GET /v1/jobs/{jobId}/status
  OR receives webhook callback when complete
```

**Why async for heavy operations:**
- Image/video processing can take 10-60 seconds
- Making the user wait that long causes timeouts and poor UX
- The web server's worker thread is tied up doing nothing useful (waiting for ffmpeg)
- Async frees the worker thread immediately; a separate worker process handles the heavy lifting

**Event-driven async (Kafka/SQS):**

```
POST /v1/orders (place an order)
→ Validate request
→ Write to database (order created, status=pending)
→ Publish event to Kafka topic "order.created"
→ Return 201 Created {orderId: 789}

Downstream consumers (running in separate services):
  - inventory-service: consume "order.created" → reserve inventory
  - payment-service: consume "order.created" → charge card
  - email-service: consume "order.created" → send confirmation email
  - analytics-service: consume "order.created" → update dashboards
```

Each consumer processes independently. If the email service crashes, orders still process — they just won't send confirmation emails until the email service recovers and catches up.

---

### Database Interactions — The Details

**Connection pooling (critical for performance):**

```javascript
// BAD: New connection per request (terrible performance)
app.get('/users/:id', async (req, res) => {
  const client = new pg.Client(connectionString);
  await client.connect(); // NEW TCP connection: 50-200ms overhead
  const result = await client.query('SELECT...');
  await client.end();
  res.json(result.rows[0]);
});

// GOOD: Pool of reusable connections
const pool = new pg.Pool({
  max: 20,           // Max 20 connections to PostgreSQL
  min: 5,            // Keep 5 warm (don't drop to 0)
  idleTimeoutMillis: 30000, // Remove idle connections after 30s
  connectionTimeoutMillis: 5000, // Fail if can't get connection in 5s
});

app.get('/users/:id', async (req, res) => {
  const client = await pool.connect(); // Reuse existing TCP connection
  try {
    const result = await client.query('SELECT...');
    res.json(result.rows[0]);
  } finally {
    client.release(); // Return to pool, not closed
  }
});
```

**Why connection pooling matters:** Each new TCP connection to PostgreSQL takes 50-200ms. At 1000 req/sec, creating a new connection per request would spend all your time on connection overhead. A pool of 20 connections can handle 1000+ queries/second by reusing them.

**Read replicas:**

```javascript
// Route reads to replicas, writes to primary
const primaryPool = new pg.Pool({ host: 'postgres-primary' });
const replicaPool = new pg.Pool({ host: 'postgres-replica-1' });

// GET requests: can tolerate slight staleness (replica is ~100ms behind)
app.get('/v1/users/:id', async (req, res) => {
  const result = await replicaPool.query('SELECT...', [req.params.id]);
  // Replica may be 100ms behind primary — acceptable for profile reads
});

// POST/PUT/DELETE: must go to primary (no replication lag)
app.post('/v1/users', async (req, res) => {
  const result = await primaryPool.query('INSERT INTO users...', [...]);
  // Primary is authoritative, immediately consistent
});
```

---

### Caching Strategy

**Cache-aside pattern (most common for APIs):**

```
1. Request comes in for user 42's profile
2. Check Redis: GET user:profile:42
3. If HIT: return cached value (avoid DB entirely)
4. If MISS:
   a. Query PostgreSQL
   b. Store result in Redis with TTL: SETEX user:profile:42 60 {data}
   c. Return result to client

Cache invalidation:
  When user 42 updates their profile:
  - Update PostgreSQL (primary)
  - Delete Redis key: DEL user:profile:42
  - Next request fetches fresh from DB and re-caches
```

**What to cache and what not to:**

```
Cache-friendly:
  ✓ User profiles (low churn, high read rate)
  ✓ Product catalog data (hours TTL)
  ✓ Lookup tables (currencies, countries)
  ✓ Aggregated statistics (monthly revenue — refresh hourly)

Cache-hostile:
  ✗ Financial balances (stale data = wrong balance shown)
  ✗ Authentication decisions (user's role changed? cached decision says old role)
  ✗ Inventory counts (over-sold if cache is stale)
  ✗ Real-time data by definition
```

**CDN caching for API responses:**

Only cache public, non-personalized data at the CDN edge:
```
Cache: GET /v1/products/catalog         → CDN caches for 5 minutes
Don't: GET /v1/users/42/profile         → Has Authorization header, personalized
Don't: GET /v1/orders/789              → User-specific, sensitive
```

Response headers that control CDN caching:
```http
# Cache at CDN for 5 minutes, at browser for 1 minute
Cache-Control: public, s-maxage=300, max-age=60

# Never cache (authentication-required responses)
Cache-Control: private, no-store

# Cache but must revalidate (use ETags)
Cache-Control: private, no-cache
ETag: "a1b2c3d4"
```

---

## 5. Authentication & Authorization Flow

### The Full JWT Validation Pipeline

A JWT (JSON Web Token) has three parts, base64url-encoded and dot-separated:

```
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleS0yMDI0LTAxIn0
.
eyJzdWIiOiJ1c2VyXzEyMyIsImF1ZCI6WyJhcGkuZXhhbXBsZS5jb20iXSwiaXNzIjoiaHR0cHM6Ly9hdXRoLmV4YW1wbGUuY29tIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjE3MDAwMDM2MDAsInJvbGVzIjpbInVzZXIiXX0
.
SIGNATURE

Decoded header:
{
  "alg": "RS256",     // RSA signature with SHA-256
  "typ": "JWT",
  "kid": "key-2024-01" // Which key was used to sign this
}

Decoded payload:
{
  "sub": "user_123",                    // Subject: who this token is about
  "aud": ["api.example.com"],           // Audience: who should accept this token
  "iss": "https://auth.example.com",   // Issuer: who created this token
  "iat": 1700000000,                    // Issued At (Unix timestamp)
  "exp": 1700003600,                    // Expires At (1 hour from iat)
  "roles": ["user"],                    // Custom claims: user's roles
  "jti": "unique-token-id-xyz"          // JWT ID (for revocation)
}
```

**The validation pipeline in the middleware:**

```javascript
async function authMiddleware(req, res, next) {
  // Step 1: Extract token
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid Authorization header' });
  }
  const token = authHeader.slice(7); // Remove "Bearer "

  // Step 2: Decode header (without verification — just to get the key ID)
  let header;
  try {
    header = JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString());
  } catch {
    return res.status(401).json({ error: 'Malformed token' });
  }

  // Step 3: Reject non-RS256 (CRITICAL — prevents algorithm confusion attacks)
  if (header.alg !== 'RS256') {
    return res.status(401).json({ error: 'Invalid algorithm' });
  }

  // Step 4: Get the correct public key by key ID
  const publicKey = await keyCache.getKey(header.kid);
  if (!publicKey) {
    // Unknown kid — might be a rotated key, fetch from JWKS endpoint
    await keyCache.refresh('https://auth.example.com/.well-known/jwks.json');
    publicKey = await keyCache.getKey(header.kid);
    if (!publicKey) {
      return res.status(401).json({ error: 'Unknown signing key' });
    }
  }

  // Step 5: Verify signature and all standard claims
  let claims;
  try {
    claims = jwt.verify(token, publicKey, {
      algorithms: ['RS256'],                      // Whitelist (critical!)
      audience: 'api.example.com',               // Must match
      issuer: 'https://auth.example.com',        // Must match
      clockTolerance: 30                         // Allow 30s clock skew
    });
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired' });
    }
    return res.status(401).json({ error: 'Invalid token' });
  }

  // Step 6: Check revocation list (optional but important for logout)
  const isRevoked = await tokenRevocationCache.isRevoked(claims.jti);
  if (isRevoked) {
    return res.status(401).json({ error: 'Token revoked' });
  }

  // Step 7: Attach claims to request for downstream use
  req.user = claims;
  next();
}
```

**RS256 vs. HS256 — why it matters:**

- `HS256` (HMAC-SHA256): Symmetric — the same secret key is used to sign AND verify. Any service that can verify tokens can also forge them. If your API server is compromised, the attacker can forge tokens.
- `RS256` (RSA-SHA256): Asymmetric — the auth server signs with the private key; API servers verify with the public key. A compromised API server cannot forge tokens (they don't have the private key). Always use RS256 (or ES256) for JWTs in production.

---

### Authorization — RBAC Implementation

```javascript
function authorize(...requiredPermissions) {
  return (req, res, next) => {
    const userRoles = req.user.roles; // From validated JWT

    // Load permissions for this user's roles
    const userPermissions = getPermissionsForRoles(userRoles);
    // e.g., role "user" → ["user:read", "user:update"]
    //       role "admin" → ["user:read", "user:update", "user:delete", "admin:*"]

    // Check if user has ALL required permissions
    const hasAll = requiredPermissions.every(p => userPermissions.includes(p));

    if (!hasAll) {
      return res.status(403).json({
        error: 'Forbidden',
        required: requiredPermissions,
        message: 'You do not have permission to perform this action'
      });
    }

    next();
  };
}

// Usage:
app.get('/v1/users/:id/profile', authorize('user:read'), getUserProfile);
app.delete('/v1/users/:id', authorize('admin:user:delete'), deleteUser);
app.get('/v1/admin/dashboard', authorize('admin:view'), getAdminDashboard);
```

**The difference between 401 and 403:**
- `401 Unauthorized`: "I don't know who you are." — Missing or invalid credentials. The client should re-authenticate.
- `403 Forbidden`: "I know who you are, but you're not allowed to do this." — Valid credentials but insufficient permissions. Re-authenticating won't help.

---

### Token Storage and Rotation

**Where to store tokens (browser):**

```
localStorage:
  + Persists across browser tabs and restarts
  - Accessible to JavaScript on the same origin
  - XSS can steal tokens
  - Verdict: OK for non-sensitive apps; not for banking/healthcare

sessionStorage:
  + Only persists for the current tab/session
  - Still accessible to JavaScript (XSS risk)
  - Verdict: Slightly better than localStorage; same XSS risk

HttpOnly Cookie:
  + NOT accessible to JavaScript (XSS cannot steal)
  + Automatically sent with every request to the domain
  - CSRF attack surface (but mitigated with SameSite=Strict/Lax)
  - Verdict: Best option for web apps; use with SameSite attribute

Memory (JavaScript variable):
  + Not accessible by other scripts
  - Lost on page refresh (need to re-authenticate)
  - Verdict: Best security, worst UX; suitable for SPAs with refresh token flow
```

**Refresh token rotation:**

```
Initial login:
  POST /auth/login
  → Access token (short TTL: 15 minutes)
  → Refresh token (long TTL: 30 days, stored in HttpOnly cookie)

When access token expires:
  POST /auth/refresh
  Cookie: refresh_token=rt_xyz
  → New access token (15 minutes)
  → New refresh token (30 days) — old one is invalidated
  → If the old refresh token is presented again: THEFT DETECTED
    → Invalidate ALL tokens for this user (force full re-login)

Why rotate refresh tokens?
  If a refresh token is stolen, the attacker can use it to get new access tokens.
  With rotation, as soon as the legitimate user does a refresh:
    - They get a new refresh token
    - The stolen (old) refresh token becomes invalid
    - If the attacker tries to use the stolen token: DETECTED (already invalidated)
    - System invalidates all tokens for this user — both attacker and user must re-login
  This limits the window of compromise to a maximum of one refresh interval.
```

---

### Key Rotation (JWKS)

```javascript
// Auth server exposes public keys at well-known URL
GET https://auth.example.com/.well-known/jwks.json

Response:
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "key-2024-01",    // Current active key
      "n": "base64url-modulus",
      "e": "AQAB"
    },
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "key-2023-12",    // Previous key (still valid for existing tokens)
      "n": "base64url-modulus-old",
      "e": "AQAB"
    }
  ]
}
```

**API server JWKS caching:**

```javascript
class JWKSCache {
  constructor() {
    this.keys = {};          // kid → public key object
    this.lastFetch = 0;
    this.TTL = 3600000;      // Refresh JWKS every hour
  }

  async getKey(kid) {
    // If cache is expired, refresh
    if (Date.now() - this.lastFetch > this.TTL) {
      await this.refresh();
    }
    return this.keys[kid];
  }

  async refresh(url = 'https://auth.example.com/.well-known/jwks.json') {
    const response = await fetch(url);
    const jwks = await response.json();
    this.keys = {};
    for (const key of jwks.keys) {
      this.keys[key.kid] = jwkToPem(key); // Convert JWK format to PEM
    }
    this.lastFetch = Date.now();
  }
}
```

**Key rotation process (zero-downtime):**

```
Step 1: Generate new key pair (key-2024-02)
Step 2: Add new public key to JWKS endpoint (two keys now: 2024-01 and 2024-02)
Step 3: API servers refresh their JWKS cache (they now trust both keys)
Step 4: Start issuing new tokens signed with key-2024-02
Step 5: Wait for all tokens signed with key-2024-01 to expire (15 minutes)
Step 6: Remove key-2024-01 from JWKS endpoint
Result: All tokens now use key-2024-02; no service disruption
```

---

## 6. Data Flow

### Request Transformation at Each Layer

```
CLIENT                          NGINX                           NODE.JS                     DB
  |                               |                               |                          |
  | HTTPS (TLS encrypted)         |                               |                          |
  | Binary TCP bytes              |                               |                          |
  |-----------------------------> |                               |                          |
  |                               | Decrypt TLS                   |                          |
  |                               | Parse HTTP/2 frames           |                          |
  |                               | Decompress HPACK headers      |                          |
  |                               | Apply rate limit              |                          |
  |                               | Add X-Real-IP header          |                          |
  |                               | Forward as plain HTTP/1.1    |                          |
  |                               |-----------------------------> |                          |
  |                               |                               | Parse HTTP headers        |
  |                               |                               | Match route pattern       |
  |                               |                               | Execute middleware chain  |
  |                               |                               | Parse/validate JWT        |
  |                               |                               | Check Redis cache         |
  |                               |                               |                          |
  |                               |                               | Parameterized query       |
  |                               |                               | [userId] → $1            |
  |                               |                               |------------------------> |
  |                               |                               |                          | Parse SQL
  |                               |                               |                          | Execute
  |                               |                               |                          | Return rows
  |                               |                               | <----------------------- |
  |                               |                               |                          |
  |                               |                               | Map rows → JS object     |
  |                               |                               | Remove sensitive fields  |
  |                               |                               | JSON.stringify()          |
  |                               |                               | Set response headers     |
  |                               |                               |------------------------------>
  |                               | Receive response              |
  |                               | Gzip compress body            |
  |                               | Send HTTP/2 HEADERS frame    |
  |                               | Send HTTP/2 DATA frame       |
  | <---------------------------- |
  | TLS encrypted response        |
  | Browser decompresses gzip     |
  | JSON.parse()                  |
  | Update DOM                    |
```

### Serialization Formats

**Request body (for POST/PUT):**

```javascript
// JSON (most common for APIs):
Content-Type: application/json
{"username": "alice", "email": "alice@example.com"}

// Form-encoded (legacy, some authentication flows):
Content-Type: application/x-www-form-urlencoded
username=alice&email=alice%40example.com

// Multipart (file uploads):
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryxxx
------WebKitFormBoundaryxxx
Content-Disposition: form-data; name="file"; filename="photo.jpg"
Content-Type: image/jpeg
[binary image data]

// Protobuf (high-performance, schema-enforced):
Content-Type: application/protobuf
[binary protobuf-encoded bytes]
```

**Why Protobuf over JSON for high-performance systems:**

```
JSON:     {"userId": 42, "username": "alice", "createdAt": "2024-01-15T10:30:00Z"}
          89 bytes, text parsing required

Protobuf: Binary encoded
          ~20 bytes, direct memory deserialization
          ~3-5x smaller, ~5-10x faster to parse
          Requires: schema (.proto file), generated code
          Tradeoff: not human-readable, harder to debug
```

**Database data types and JavaScript type coercion:**

```javascript
// PostgreSQL → JavaScript type mapping:
// INTEGER → number (safe for values < 2^53)
// BIGINT → string (avoid precision loss for large IDs)
// TIMESTAMPTZ → string (ISO 8601 format) or Date object
// BOOLEAN → boolean
// JSONB → object (PostgreSQL does JSON deserialization)
// NULL → null

// Common bug: auto-increment BIGINT primary key
// ID: 9007199254740993 (larger than Number.MAX_SAFE_INTEGER)
// JSON.stringify: 9007199254740992 (WRONG! Last digit truncated)
// Fix: Return IDs as strings, or use UUID (string by default)

// Example with pg driver:
const { rows } = await db.query('SELECT id, name FROM users WHERE id = $1', [42]);
// rows[0].id is a JavaScript number if INT, or a string if BIGINT
// Configure pg to return bigints as strings:
const types = require('pg').types;
types.setTypeParser(20, (val) => val); // 20 = OID for bigint, return as string
```

---

### Where Data Is Validated

```
Layer 1: Network (nginx)
  - Request body size: reject if > 10MB (configurable)
  - Malformed HTTP: reject immediately
  - Rate limit: reject if over threshold

Layer 2: Express middleware (JSON body parser)
  - Valid JSON syntax (reject if malformed)
  - Content-Type matches body format
  - Body size limit enforced again (belt-and-suspenders)

Layer 3: Auth middleware
  - JWT signature valid
  - JWT claims valid (exp, aud, iss)
  - JWT not revoked

Layer 4: Input validation middleware (Joi/Zod/class-validator)
  - URL parameters: userId must be a positive integer
  - Query parameters: page must be 1-100, limit must be 1-100
  - Request body: required fields present, types correct, values in range

Layer 5: Business logic
  - Authorization: can this user access this resource?
  - Business rules: e.g., can only have 5 payment methods

Layer 6: Database
  - Column type constraints (INTEGER, VARCHAR(255))
  - NOT NULL constraints
  - UNIQUE constraints
  - Foreign key constraints
  - CHECK constraints
  (These are the last line of defense — should never be the primary defense)
```

---

## 7. Security Controls

### Defense in Depth for REST APIs

**Transport security (TLS):**

```nginx
# nginx TLS hardening
ssl_protocols TLSv1.2 TLSv1.3;  # No TLS 1.0 or 1.1
ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:
            ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:
            ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
ssl_prefer_server_ciphers off;  # TLS 1.3 sets its own preferences
ssl_session_tickets off;        # Disables session tickets (no forward secrecy concern)
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 1d;

# HSTS: Force HTTPS for 2 years, including subdomains, preload-ready
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

# OCSP stapling (server checks revocation, not client — faster)
ssl_stapling on;
ssl_stapling_verify on;
```

**Security headers:**

```javascript
// Helmet.js — security headers in Express
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'none'"],
      // For API responses: no scripts, no frames, no media
      // Pure JSON APIs don't need CSP beyond this
    }
  },
  referrerPolicy: { policy: 'no-referrer' },
  hsts: {
    maxAge: 63072000,        // 2 years
    includeSubDomains: true,
    preload: true
  },
  noSniff: true,             // X-Content-Type-Options: nosniff
  frameguard: { action: 'deny' },  // X-Frame-Options: DENY
  hidePoweredBy: true,       // Remove X-Powered-By: Express
  xssFilter: false           // X-XSS-Protection is deprecated; use CSP instead
}));
```

**Input validation (Zod schema):**

```typescript
import { z } from 'zod';

const getUserProfileParams = z.object({
  userId: z
    .string()
    .regex(/^\d+$/, 'Must be a positive integer')
    .transform(Number)
    .refine(n => n > 0 && n < 2147483647, 'Out of range')
});

const getUserProfileQuery = z.object({
  includePrivate: z.enum(['true', 'false']).optional().default('false'),
  fields: z.string().max(200).optional()
    .transform(s => s?.split(',').filter(f => ALLOWED_FIELDS.has(f)))
});

// Middleware:
function validateRequest(schema) {
  return (req, res, next) => {
    const result = schema.safeParse({
      params: req.params,
      query: req.query,
      body: req.body
    });
    if (!result.success) {
      return res.status(400).json({
        error: 'Validation Error',
        details: result.error.issues
      });
    }
    req.validated = result.data;
    next();
  };
}
```

**Parameterized queries (SQL injection prevention):**

```javascript
// NEVER DO THIS — SQL injection vulnerability:
const query = `SELECT * FROM users WHERE username = '${username}'`;
// If username = "'; DROP TABLE users; --"  → catastrophic

// ALWAYS USE PARAMETERIZED QUERIES:
const { rows } = await db.query(
  'SELECT id, username, email FROM users WHERE username = $1 AND is_active = $2',
  [username, true]
);
// The database driver escapes parameters at the protocol level
// No amount of clever input can break out of the parameter
```

**Rate limiting implementation:**

```javascript
const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis');

// Global rate limit (all endpoints)
const globalLimiter = rateLimit({
  windowMs: 60 * 1000,  // 1 minute window
  max: 100,             // 100 requests per minute per IP
  standardHeaders: true, // Return rate limit info in X-RateLimit-* headers
  legacyHeaders: false,
  store: new RedisStore({
    client: redis,
    // Store key format: rl_global_IP
  }),
  handler: (req, res) => {
    res.status(429).json({
      error: 'Too Many Requests',
      retryAfter: res.getHeader('Retry-After')
    });
  }
});

// Per-API-key rate limit (for authenticated users)
const apiKeyLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 1000,  // Authenticated users get more requests
  keyGenerator: (req) => req.user?.sub || req.ip,
  // Uses user ID as key, not IP (allows multiple IPs for same user)
});

// Specific endpoint rate limit (sensitive operations)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 5,                     // 5 login attempts per 15 minutes
  skipSuccessfulRequests: true  // Don't count successful logins
});
```

---

### Encryption at Rest

**Database encryption:**

```
PostgreSQL level:
  - Tablespace-level encryption (pgcrypto extension for column encryption)
  - AWS RDS: AES-256 TDE (Transparent Data Encryption) at EBS level
  - This protects against physical disk theft — if someone steals the EBS volume,
    data is encrypted

Application-level encryption (more granular):
  - Sensitive fields encrypted BEFORE writing to DB
  - Key stored in AWS KMS (not in the application or database)
  - Only the fields that need extra protection: SSN, payment info, PII

Example:
  -- Stored in DB (cipher text, useless without key):
  secret_field = AES_GCM_ENCRYPT(plaintext, kms_data_key)
  kms_envelope  = ENCRYPTED(kms_data_key, kms_master_key)
  -- KMS Master Key never leaves AWS KMS hardware
```

---

### Secrets Handling

```python
# NEVER DO THIS:
DATABASE_PASSWORD = "super_secret_password123"  # Hardcoded = terrible
DATABASE_PASSWORD = os.environ["DB_PASSWORD"]   # Env var = better but visible in process list

# DO THIS:
import boto3
from functools import lru_cache

@lru_cache(maxsize=1)  # Cache the result (expensive to call KMS repeatedly)
def get_secret(secret_name: str) -> str:
    client = boto3.client('secretsmanager', region_name='us-east-1')
    response = client.get_secret_value(SecretId=secret_name)
    return response['SecretString']

# Usage:
db_password = get_secret('prod/api/database_password')
# Secret is fetched at runtime, not baked into the image
# IAM role controls which secrets this service can access
# Secret value is never in source code, config files, or environment variables
```

**Secrets rotation:**

```
AWS Secrets Manager automatic rotation:
  - Database password: rotated every 90 days automatically
  - Rotation Lambda function updates both Secrets Manager AND the database
  - Application fetches the new secret on the next cache miss
  - Zero-downtime rotation (brief period where both old and new passwords valid)
```

---

## 8. Attack Surface Mapping

### All Entry Points

```
EXTERNAL ENTRY POINTS (accessible from internet):
═══════════════════════════════════════════════════════

[E1] API Endpoints (every URL path)
  GET  /v1/users/:id/profile
  POST /v1/users
  PUT  /v1/users/:id
  DELETE /v1/users/:id
  GET  /v1/users  (list endpoint — often forgotten)
  ...and every other route

  Attack surface: Every parameter (path, query, body, header)

[E2] File Upload Endpoints
  POST /v1/users/:id/avatar
  POST /v1/documents

  Attack surface: File type, content, size, filename

[E3] Authentication Endpoints
  POST /auth/login
  POST /auth/refresh
  POST /auth/logout
  POST /auth/register
  POST /auth/password-reset

  Attack surface: Credential brute force, account enumeration, token replay

[E4] Webhook Callback Endpoints
  POST /webhooks/stripe
  POST /webhooks/github

  Attack surface: Forged payloads without signature validation

[E5] Admin/Internal Endpoints (if not properly isolated)
  GET /admin/users
  GET /health (may leak version info)
  GET /metrics (Prometheus — may expose internal state)
  GET /debug (should NEVER be in production)

INTERNAL ENTRY POINTS (should not be internet-accessible):
═══════════════════════════════════════════════════════════

[I1] Service-to-service APIs
  auth-service → user-service
  order-service → inventory-service

[I2] Message queues (if compromised)
  SQS, Kafka, RabbitMQ

[I3] Database (if misconfigured)
  PostgreSQL should NEVER be on a public subnet

[I4] Admin interfaces
  pgAdmin, Redis Commander, Grafana, Kibana
```

### Attack Surface Diagram

```
                            ┌─────────────────────────────────────────────┐
                            │           EXTERNAL ATTACK SURFACE           │
                            │  [E1] API  [E2] Upload  [E3] Auth  [E4] WH │
                            └──────────────┬──────────────────────────────┘
                                           │ Internet (Untrusted)
                                           │
                          ┌────────────────▼───────────────────────────────┐
                          │  CDN / WAF (Cloudflare)                         │
                          │  [TB-0] DDoS protection, IP reputation,         │
                          │         WAF rules (SQLi, XSS patterns)          │
                          └────────────────┬───────────────────────────────┘
                                           │
                          ┌────────────────▼───────────────────────────────┐
                          │  AWS Application Load Balancer                  │
                          │  [TB-1] TLS termination option, health checks   │
                          │         Routing rules, access logs              │
                          └────────┬──────────────────────┬────────────────┘
                                   │                      │
                    ┌──────────────▼──────┐  ┌──────────▼──────────────────┐
                    │  nginx Instance 1    │  │  nginx Instance 2            │
                    │  [TB-2] TLS term.    │  │  TLS term.                   │
                    │  Rate limiting       │  │  Rate limiting               │
                    │  Header validation   │  │  Header validation           │
                    └──────────┬──────────┘  └──────────┬──────────────────┘
                               │                        │
                ┌──────────────▼──┐  ┌──────────────────▼────────────────────┐
                │  Node App 1     │  │  Node App 2                            │
                │  [TB-3] JWT     │  │  JWT validation                        │
                │  validation     │  │  RBAC enforcement                      │
                │  RBAC           │  │  Input validation                      │
                │  Business logic │  │  Business logic                        │
                └───┬──────────┬──┘  └───┬────────────────────────────────────┘
                    │          │          │
             ┌──────▼─┐   ┌───▼──────────▼──┐
             │ Redis  │   │  PostgreSQL       │
             │ [TB-4] │   │  [TB-4]           │
             │ Cache  │   │  Private subnet   │
             │ Sessions   │  Encrypted at rest│
             └────────┘   └──────────────────┘

TRUST BOUNDARIES:
  [TB-0] Internet → CDN: ZERO TRUST. Drop known bad, rate limit.
  [TB-1] CDN → ALB: SEMI-TRUSTED. ALB validates Host header.
  [TB-2] ALB → nginx: TRUSTED network. nginx still validates headers.
  [TB-3] nginx → App: TRUSTED (same host or VPC). App does full auth.
  [TB-4] App → Data: AUTHENTICATED. DB user has minimum privileges.

ATTACK PATHS:
  E1 → TB-0 → TB-1 → TB-2 → TB-3 → SQL Injection attempt
  E3 → TB-0 → TB-1 → TB-2 → TB-3 → Credential brute force
  I3 → DIRECT DB ACCESS if misconfigured security group (catastrophic)
```

---

## 9. Attack Scenarios (Very Detailed)

### 9.1 — JWT Algorithm Confusion Attack (`alg: none`)

**Background for beginners:** JWTs have a header that says which algorithm was used to sign them. If a library trusts this header without validation, an attacker can forge any token.

**Attacker Assumptions:**
- The API server uses a JWT library that accepts the `alg` field from the token header
- The server does not explicitly restrict allowed algorithms

**Step-by-Step Execution:**

1. Attacker observes a legitimate JWT header: `{"alg": "RS256", "typ": "JWT", "kid": "key-2024-01"}`

2. Attacker creates a forged JWT header: `{"alg": "none", "typ": "JWT"}`

3. Attacker creates a payload with elevated privileges:
   ```json
   {"sub": "user_999", "roles": ["admin"], "exp": 9999999999}
   ```

4. Attacker base64url-encodes both parts, appends an empty signature:
   ```
   eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.PAYLOAD.
   ```
   (Note the trailing dot — empty signature)

5. Sends request: `Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.PAYLOAD.`

6. **Vulnerable server code:**
   ```javascript
   // WRONG: Uses algorithm from token header
   const claims = jwt.verify(token, publicKey); // No algorithm restriction!
   // Library reads alg=none → skips signature verification entirely
   // Claims are trusted without any cryptographic validation
   ```

7. Server accepts the forged token. Attacker has admin access.

**Why This Works:**
Many JWT libraries (especially older versions) accepted `alg: none` as a signal to skip verification. Even with modern libraries, if you don't restrict algorithms, an attacker can switch from RS256 to HS256 and sign the token with the *public key* as the HMAC secret (since the public key is... public).

**Where Detection Could Happen:**
- Logs: `alg` field in incoming JWTs is a non-RS256 value
- Anomaly: user_999 (admin) accessing endpoints they haven't before
- API usage pattern: sudden admin operations from a user with no admin history

**Correct Code:**
```javascript
jwt.verify(token, publicKey, { algorithms: ['RS256'] });
// Library will reject ANYTHING not RS256, including "none" and HS256
```

---

### 9.2 — IDOR (Insecure Direct Object Reference)

**Background:** IDOR means the API uses a predictable ID in the URL and doesn't verify that the requesting user is authorized to access that specific resource.

**Attacker Assumptions:**
- Attacker has a valid account and JWT token (sub: "user_123")
- Attacker wants to access user 42's profile (not their own)
- The server only validates the JWT, not ownership of the requested resource

**Step-by-Step Execution:**

1. Attacker logs in legitimately. Gets JWT with `"sub": "user_123"`.

2. Attacker observes: when they access their own profile, the URL is `/v1/users/123/profile`.

3. Attacker modifies the URL: `GET /v1/users/42/profile`

4. **Vulnerable server code:**
   ```javascript
   app.get('/v1/users/:userId/profile', authMiddleware, async (req, res) => {
     const user = await db.query(
       'SELECT * FROM users WHERE id = $1',
       [req.params.userId]  // WRONG: Uses attacker-supplied userId directly
     );
     res.json(user.rows[0]);
     // No check: "does req.user.sub === req.params.userId?"
   });
   ```

5. Server returns user 42's profile to attacker (user 123).

**The vulnerability:** The server validates "you are authenticated" (valid JWT) but not "you are authorized to access THIS resource."

**Correct Code:**
```javascript
app.get('/v1/users/:userId/profile', authMiddleware, async (req, res) => {
  const requestedUserId = parseInt(req.params.userId);
  const requestingUserId = req.user.sub;

  // CRITICAL: Check ownership or admin role
  if (requestedUserId !== requestingUserId && !req.user.roles.includes('admin')) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const user = await db.query('SELECT * FROM users WHERE id = $1', [requestedUserId]);
  res.json(user.rows[0]);
});
```

**Where Detection Could Happen:**
- Log analysis: user_123 accessing many different user IDs in rapid succession
- Anomaly detection: user accessing resources they've never accessed before
- Alert: any user accessing more than 5 distinct user IDs per hour (outside admin workflow)

---

### 9.3 — SQL Injection via API Parameter

**Attacker Assumptions:**
- The API has a search endpoint: `GET /v1/users/search?name=alice`
- The backend concatenates the query parameter directly into SQL

**Step-by-Step Execution:**

1. Attacker discovers the search endpoint from API docs or enumeration.

2. Attacker sends: `GET /v1/users/search?name=alice' OR '1'='1`

3. **Vulnerable backend code:**
   ```javascript
   const name = req.query.name;
   // WRONG: String concatenation into SQL
   const query = `SELECT id, username FROM users WHERE username = '${name}'`;
   // Resulting query: SELECT id, username FROM users WHERE username = 'alice' OR '1'='1'
   // This returns ALL users (1=1 is always true)
   ```

4. Attacker can now enumerate all users. But they want more. They escalate:

5. `GET /v1/users/search?name=alice' UNION SELECT table_name, column_name FROM information_schema.columns--`
   - Gets the database schema (table names, column names)

6. `GET /v1/users/search?name=alice' UNION SELECT username, password_hash FROM users--`
   - Dumps usernames and password hashes

7. `GET /v1/users/search?name=alice'; DROP TABLE orders;--`
   - If they have write privileges: destroys data

**Where Detection Could Happen:**
- WAF: SQL keywords in URL parameters (`UNION`, `SELECT`, `DROP`, quotes)
- Database monitoring: unusual query patterns, queries joining system tables
- Application error logs: database query errors (attacker often gets errors while probing)
- Rate limiting: many rapid requests from same IP

**Defense:**
```javascript
// CORRECT: Parameterized query — impossible to inject
const { rows } = await db.query(
  'SELECT id, username FROM users WHERE username ILIKE $1 LIMIT 20',
  [`%${name}%`]  // name is a parameter, never part of the SQL string
);
```

---

### 9.4 — SSRF (Server-Side Request Forgery)

**Background:** SSRF occurs when an attacker can make the API server send requests to internal network resources that should not be accessible from the internet.

**Attacker Assumptions:**
- The API has an endpoint that fetches a URL provided by the user
- The server doesn't validate what URLs are allowed

**Step-by-Step Execution:**

1. Attacker finds an endpoint: `POST /v1/profile/import-avatar` that accepts a URL to fetch an avatar image from.

2. **Vulnerable code:**
   ```javascript
   app.post('/v1/profile/import-avatar', authMiddleware, async (req, res) => {
     const { imageUrl } = req.body;
     // WRONG: Fetches whatever URL the user provides
     const imageResponse = await fetch(imageUrl);
     const imageData = await imageResponse.buffer();
     await saveAvatar(req.user.sub, imageData);
     res.json({ success: true });
   });
   ```

3. Attacker sends: `POST /v1/profile/import-avatar` with `{"imageUrl": "http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-role"}`

4. The server is on AWS EC2. `169.254.169.254` is the AWS metadata service — accessible only from inside the EC2 instance. The server fetches it on behalf of the attacker.

5. The response contains AWS IAM credentials: access key, secret key, session token.

6. Attacker uses these credentials to access all AWS resources the EC2 role can access: S3 buckets, RDS databases, other services.

**Other SSRF targets:**
- `http://localhost:5432` → Try to access PostgreSQL admin interface
- `http://redis:6379` → Try Redis commands via HTTP (if Redis doesn't require auth)
- `http://kubernetes.default.svc/api/v1/secrets` → K8s secret access
- `file:///etc/passwd` → Local file read (if scheme filtering not done)

**Mitigation:**
```javascript
const { URL } = require('url');
const ipRanges = require('ip-range-check');

const BLOCKED_RANGES = [
  '127.0.0.0/8',      // Localhost
  '10.0.0.0/8',       // Private network
  '172.16.0.0/12',    // Private network
  '192.168.0.0/16',   // Private network
  '169.254.0.0/16',   // Link-local (AWS metadata!)
  '::1/128',          // IPv6 localhost
  'fc00::/7',         // IPv6 private
];

async function validateSSRFSafeUrl(urlString) {
  const url = new URL(urlString); // Throws if malformed

  // Whitelist allowed schemes
  if (!['https:'].includes(url.protocol)) {
    throw new Error('Only HTTPS URLs allowed');
  }

  // Resolve to IP and check against blocked ranges
  const addresses = await dns.promises.lookup(url.hostname, { all: true });
  for (const addr of addresses) {
    if (ipRanges(addr.address, BLOCKED_RANGES)) {
      throw new Error('URL resolves to a blocked IP range');
    }
  }

  return urlString;
}
```

---

### 9.5 — Rate Limit Bypass and Brute Force

**Attacker Assumptions:**
- The login endpoint `POST /auth/login` has a rate limit of 5 attempts per IP per 15 minutes
- Attacker wants to brute force a user's password

**Step-by-Step Execution (bypassing IP-based rate limiting):**

1. Attacker has a list of 10,000 residential proxy IPs.

2. Each proxy sends one or two login attempts:
   ```
   Proxy 1 (IP: 1.2.3.4): POST /auth/login {"email": "alice@example.com", "password": "password1"}
   Proxy 2 (IP: 5.6.7.8): POST /auth/login {"email": "alice@example.com", "password": "password2"}
   ...
   ```

3. Each IP sends only 2 attempts → never hits the 5-attempt-per-IP limit.

4. But from Alice's account perspective, there have been thousands of login attempts.

5. Eventually, the correct password is found if it's in a common password list.

**Why IP-based rate limiting is insufficient:**
- Attackers use residential proxy networks (hard to block without blocking real users)
- IPv6 gives virtually unlimited IPs
- Legitimate users may share IPs (NAT, corporate proxies)

**Better approach — per-account rate limiting:**

```javascript
async function loginHandler(req, res) {
  const { email, password } = req.body;

  // Rate limit by EMAIL (account), not IP
  const accountKey = `login_attempts:${email}`;
  const attempts = await redis.incr(accountKey);
  if (attempts === 1) {
    await redis.expire(accountKey, 15 * 60); // 15-minute window
  }

  if (attempts > 5) {
    // Account is locked for 15 minutes
    return res.status(429).json({
      error: 'Too many login attempts. Try again in 15 minutes.',
      // Don't reveal whether the account exists (enumeration prevention)
    });
  }

  const user = await db.query('SELECT * FROM users WHERE email = $1', [email]);

  // Constant-time response whether user exists or not
  const isValid = user.rows.length > 0 &&
    await bcrypt.compare(password, user.rows[0].password_hash);

  if (!isValid) {
    // Return same error regardless of whether email exists (enumeration prevention)
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Reset attempt counter on success
  await redis.del(accountKey);

  // Issue tokens...
}
```

**Where Detection Could Happen:**
- Alert: single email address receiving >3 failed login attempts in 15 minutes
- Alert: 1000+ failed login attempts per hour globally (distributed attack)
- Alert: IP addresses with >90% failed request rate (proxy networks)
- Block: ASNs known to be proxy/VPN providers (tradeoff: false positives for legitimate VPN users)

---

### 9.6 — Race Condition (Time-of-Check-Time-of-Use / TOCTOU)

**Background:** A race condition in APIs occurs when two requests arrive simultaneously and both pass a check that should have only allowed one through.

**Attacker Assumptions:**
- A user has $100 balance
- The API allows withdrawing money
- The check and the withdrawal are not atomic

**Step-by-Step Execution:**

1. **Vulnerable code:**
   ```javascript
   async function withdraw(req, res) {
     const { amount } = req.body;
     const userId = req.user.sub;

     // Step 1: Check balance
     const user = await db.query('SELECT balance FROM users WHERE id = $1', [userId]);
     const balance = user.rows[0].balance;  // $100

     if (balance < amount) {
       return res.status(400).json({ error: 'Insufficient funds' });
     }

     // [GAP: attacker sends second request here]

     // Step 2: Deduct balance (separate query — not atomic with check!)
     await db.query('UPDATE users SET balance = balance - $1 WHERE id = $2', [amount, userId]);

     res.json({ success: true, newBalance: balance - amount });
   }
   ```

2. Attacker writes a script sending two simultaneous `POST /v1/withdraw {amount: 100}` requests.

3. Both requests arrive within microseconds of each other.

4. Request A checks balance: $100. Check passes.
5. Request B checks balance: $100. Check passes (Request A hasn't updated yet).
6. Request A deducts $100. Balance → $0.
7. Request B deducts $100. Balance → -$100 (OVERDRAFT).

**Mitigation — Atomic database operations:**

```javascript
async function withdraw(req, res) {
  const { amount } = req.body;
  const userId = req.user.sub;

  // Atomic: check AND update in one query
  // Only succeeds if balance >= amount at the time of the UPDATE
  const result = await db.query(`
    UPDATE users
    SET balance = balance - $1
    WHERE id = $2 AND balance >= $1
    RETURNING balance
  `, [amount, userId]);

  if (result.rows.length === 0) {
    return res.status(400).json({ error: 'Insufficient funds' });
  }

  res.json({ success: true, newBalance: result.rows[0].balance });
}
```

The single SQL statement atomically checks and updates. PostgreSQL's row-level locking ensures only one concurrent update succeeds.

**Alternative: Pessimistic locking:**
```sql
BEGIN;
SELECT balance FROM users WHERE id = $1 FOR UPDATE;  -- Locks the row
-- [Check balance in application code]
UPDATE users SET balance = balance - $2 WHERE id = $1;
COMMIT;
```

---

## 10. Failure Points

### Under Load

**Database connection pool exhaustion:**

```
Scenario: 1000 requests arrive simultaneously
Connection pool max: 20 connections
Each request holds connection for: 50ms (DB query)
Maximum throughput: 20 connections / 0.05s = 400 req/sec

At 1000 req/sec → requests queue waiting for connections
Queue fills up → requests rejected with connection timeout errors
→ Users see 503 errors despite the database being fine
```

**Fix:**
- Increase pool size carefully (PostgreSQL has its own connection overhead — too many is bad)
- Add read replicas to distribute query load
- Use PgBouncer (connection pooler) between app and DB — can pool thousands of app connections into 20 DB connections
- Reduce query duration (indexes, query optimization)

**Redis as a single point of failure:**

If your application code does:
```javascript
const token = await redis.get(`session:${sessionId}`);
if (!token) return res.status(401).json({ error: 'Session expired' });
```

And Redis goes down: EVERY request fails with a 401 error. All users are logged out effectively.

**Fix: Redis failure modes:**
```javascript
const token = await redis.get(`session:${sessionId}`).catch(err => {
  logger.error('Redis unavailable', { err });
  return null; // Fail gracefully
});

if (!token) {
  // Redis miss or Redis down — fall back to DB session lookup
  const dbSession = await db.query('SELECT * FROM sessions WHERE id = $1', [sessionId]);
  if (!dbSession.rows.length) {
    return res.status(401).json({ error: 'Session expired' });
  }
  // Cache miss: store in Redis if it comes back
  await redis.setex(`session:${sessionId}`, 3600, JSON.stringify(dbSession.rows[0]))
    .catch(() => {}); // Best-effort cache write
}
```

---

### Under Attack

**Slow loris attack:**

An attacker opens thousands of HTTP connections but sends data incredibly slowly — just enough to prevent the connection from timing out. nginx's worker processes are tied up waiting for slow clients.

```
Attacker: POST /v1/users
Content-Length: 10000
[sends 1 byte every 30 seconds]
[connection stays open for hours]
```

**nginx config to prevent slow loris:**
```nginx
client_header_timeout 10s;    # Close if headers not received in 10s
client_body_timeout 10s;      # Close if body transmission stalls > 10s
send_timeout 10s;             # Close if client doesn't receive response
keepalive_timeout 65s;        # HTTP keepalive connection timeout
```

**Amplification attacks against your API:**

Endpoints that do expensive operations:
- `GET /v1/users/search?name=a` → returns 10,000 users
- `POST /v1/reports/generate` → runs a 30-second DB aggregation

An attacker hammering these endpoints uses minimal bandwidth to cause maximum server load. These are natural DDoS amplifiers.

**Fix:** Expensive operations must be:
1. Rate-limited (1 report per minute per user)
2. Paginated (max 100 results per search page)
3. Cached (report computed once, cached for 5 minutes)
4. Async (queue the work, return immediately)

---

### Common Misconfigurations

| Misconfiguration | Impact | Fix |
|---|---|---|
| `CORS: Access-Control-Allow-Origin: *` with credentials | Any website can make authenticated requests as any user | Specific origin whitelist; never `*` with cookies |
| JWT `alg` not restricted | Algorithm confusion attack | `algorithms: ['RS256']` in verify() |
| `Authorization` header logged in plaintext | Token theft from logs | Log only token hash or first/last 8 chars |
| Stack traces in error responses | Exposes internal paths, library versions | Generic error messages in production |
| HTTP allowed (not redirected to HTTPS) | Plaintext transmission of tokens | 301 redirect to HTTPS + HSTS |
| Debug endpoints in production (`/debug`, `/phpinfo`) | Info exposure, RCE risk | Never deploy debug endpoints to production |
| No request body size limit | Memory exhaustion | `limit: '1mb'` in body-parser |
| Verbose error messages (`username not found`) | Account enumeration | Generic: "Invalid credentials" for all auth failures |
| PostgreSQL on public subnet | Direct DB access from internet | DB only in private subnet |
| Missing `Retry-After` header on 429 | Clients retry immediately (thundering herd) | Include retry timing |
| Soft deletes not filtered | Deleted resources still accessible | `WHERE deleted_at IS NULL` in all queries |

---

## 11. Mitigations

### Defense-in-Depth Layers

```
Layer 1: External Perimeter (CDN / WAF)
  → Block known malicious IPs and ASNs
  → WAF rules: SQL injection patterns, XSS patterns, known exploit signatures
  → DDoS mitigation: rate limit by IP at CDN level (cheap to apply at edge)
  → TLS: only accept TLS 1.2+, strong cipher suites
  → Certificate validation: ensure no expired/revoked certs

Layer 2: Load Balancer / Reverse Proxy (nginx)
  → Rate limiting: per-IP request rate
  → Request size limits: reject giant payloads before they reach app
  → Timeout controls: prevent slow loris and slow reads
  → Security headers: HSTS, X-Content-Type-Options, etc.
  → Hide internal information: remove Server header, error details

Layer 3: Application (Express Middleware)
  → Authentication: verify JWT signature, algorithm, expiry, audience, issuer
  → Authorization: RBAC check for every protected endpoint
  → Input validation: type, format, range, length for every parameter
  → CORS: strict origin whitelist
  → Rate limiting: per-user/account (not just per-IP)
  → Idempotency: prevent double-processing of mutations

Layer 4: Business Logic
  → Resource ownership verification (IDOR prevention)
  → Amount validation (server-side, not client-side)
  → State machine enforcement (can't transition from A to C without going through B)
  → Audit logging of all sensitive operations

Layer 5: Data Layer
  → Parameterized queries (SQL injection prevention)
  → Minimal DB user privileges (SELECT/INSERT only, never DROP)
  → Encryption at rest
  → Connection over TLS
  → Secrets via secrets manager (not env vars or config files)
```

---

### Engineering Tradeoffs

| Control | Security Benefit | Engineering Cost | UX Impact |
|---|---|---|---|
| Short JWT TTL (5 min) | Limits stolen token window | Frequent refresh calls | Transparent if refresh is smooth |
| Strict CORS | Prevents unauthorized cross-origin requests | Must maintain origin whitelist | None for legitimate clients |
| Rate limiting per endpoint | Prevents abuse of expensive operations | Per-endpoint configuration | Legitimate high-volume users need higher limits |
| HTTPS-only | Prevents plaintext token transmission | Certificate management | None (users don't notice) |
| Response field filtering | Prevents data leakage | Extra code per endpoint | None |
| DB query pagination | Prevents large data exfiltration | Client must implement paging | More requests needed |
| Timing-constant auth responses | Prevents username enumeration | Deliberate delay on failure | Slightly slower failed logins |

---

## 12. Observability

### Structured Logging

Every API request should produce a structured log line:

```json
{
  "timestamp": "2024-11-15T10:30:45.123Z",
  "level": "info",
  "event": "api.request",
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "method": "GET",
  "path": "/v1/users/42/profile",
  "path_pattern": "/v1/users/:userId/profile",
  "status_code": 200,
  "duration_ms": 87,
  "user_id": "user_123",
  "ip_hash": "sha256:a1b2c3d4",
  "ip_geo": "US-CA",
  "user_agent_class": "browser/chrome",
  "cache_status": "MISS",
  "db_query_count": 1,
  "db_duration_ms": 12,
  "redis_duration_ms": 1,
  "response_bytes": 342,
  "request_bytes": 0
}
```

**What NEVER goes in logs:**
```
- JWT tokens (Authorization header value)
- Passwords (even failed login attempts — log the email, not the password)
- Credit card numbers
- SSNs or government IDs
- Full session IDs (log first 8 chars + hash of full value)
- Raw query parameters if they might contain secrets
```

**Error log:**
```json
{
  "timestamp": "2024-11-15T10:30:45.456Z",
  "level": "error",
  "event": "api.error",
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "error_type": "DatabaseError",
  "error_message": "connection timeout",
  "error_code": "ETIMEDOUT",
  "stack_trace": "[only in development, never in production logs sent to external systems]"
}
```

---

### Metrics (Prometheus-Style)

```
# Request rate (requests per second)
http_requests_total{method="GET", path="/v1/users/:userId/profile", status="200"}

# Latency histograms (p50, p95, p99)
http_request_duration_ms{method="GET", path="/v1/users/:userId/profile"}

# Error rate
http_errors_total{status="4xx|5xx", path="..."}

# Authentication events
auth_jwt_validations_total{result="success|failure|expired|invalid_algorithm"}
auth_rate_limit_hits_total{endpoint="/auth/login"}

# Database performance
db_query_duration_ms{operation="SELECT|INSERT|UPDATE|DELETE", table="users"}
db_connection_pool_usage{pool="read|write", metric="active|idle|waiting"}

# Cache performance
cache_hit_rate{cache="redis", key_prefix="user:profile"}
cache_operation_duration_ms{operation="GET|SET", cache="redis"}

# Business metrics
api_requests_by_user_tier{tier="free|paid|enterprise"}
feature_usage_total{feature="search|export|webhook"}
```

---

### Distributed Tracing

Using OpenTelemetry, every request generates a trace that spans multiple services:

```
Trace: GET /v1/users/42/profile [87ms total]
  │
  ├── nginx [3ms]
  │   └── upstream proxy to Node.js
  │
  ├── Express Middleware [15ms]
  │   ├── logging [0.1ms]
  │   ├── CORS [0.1ms]
  │   ├── JWT validation [2ms]
  │   │   └── JWKS key fetch [0ms — cache hit]
  │   ├── rate limit check [0.5ms]
  │   │   └── redis.GET [0.3ms]
  │   └── route matching [0.1ms]
  │
  ├── Route Handler [67ms]
  │   ├── Redis cache check [1ms]
  │   │   └── redis.GET user:profile:42 [0.6ms] → MISS
  │   ├── PostgreSQL query [12ms]
  │   │   └── SELECT * FROM users WHERE id = 42 [11ms]
  │   ├── Response serialization [0.2ms]
  │   └── Redis cache write [0.8ms]
  │       └── redis.SETEX user:profile:42 [0.6ms]
  │
  └── Response [2ms]
      └── gzip compression [1.5ms]
```

The `X-Request-ID` header is the glue — the same UUID appears in:
- nginx access log
- Node.js application log
- PostgreSQL `application_name` (query log)
- Redis `MONITOR` output (if enabled)
- External service logs (if you forward the header as `X-Correlation-ID`)

---

### Alerting Rules

| Condition | Severity | Action |
|---|---|---|
| Error rate (5xx) > 1% over 5 minutes | HIGH | Page on-call engineer |
| p99 latency > 2s over 5 minutes | MEDIUM | Alert engineering team |
| Database connection pool exhaustion | HIGH | Immediate: scale up or shed load |
| Authentication failure rate > 10% | HIGH | Possible credential stuffing attack |
| JWT `alg != RS256` in any request | CRITICAL | Security team immediately |
| Any SQL syntax error in DB logs | HIGH | Possible injection attempt |
| Redis unavailability | MEDIUM | Alert: fallback to DB mode |
| CORS preflight from unexpected origin | MEDIUM | Log for review |
| Rate limit hits > 100/min globally | MEDIUM | Possible DDoS |
| Any access to `/admin` by non-admin JWT | HIGH | Security alert |
| Normal successful requests | No alert | Expected |
| Individual 4xx errors | No alert | Expected (user errors) |
| DNS resolution latency spikes | LOW | Info only |

---

## 13. Scaling Considerations

### Identifying and Resolving Bottlenecks

**Step 1: Measure, don't assume**

The bottleneck is never where you think it is until you measure. Use distributed tracing to find where time is actually being spent.

```bash
# Generate load and observe
wrk -t12 -c400 -d30s https://api.example.com/v1/users/42/profile

# Measure with percentiles
# p50: 45ms, p95: 210ms, p99: 1200ms
# The p99 being 5x the p95 suggests:
# - Occasional slow queries (not cached, hitting DB under load)
# - GC pauses in Node.js (check GC metrics)
# - Network timeout to database (connection pool exhaustion)
```

**Common bottlenecks and solutions:**

```
Bottleneck: Database reads
  Symptoms: DB query duration p99 > 100ms
  Solutions:
    1. Add indexes for common query patterns
    2. Add Redis cache (cache-aside pattern)
    3. Add read replicas for read-heavy endpoints
    4. Denormalize frequently-joined data
    5. Use materialized views for complex aggregations

Bottleneck: Node.js single-threaded CPU
  Symptoms: CPU 100% on one core, other cores idle
  Solutions:
    1. Scale horizontally (more Node.js instances behind nginx upstream)
    2. Move CPU-intensive work to worker threads
    3. Move heavy computation to a separate Python/Go microservice
    4. Cache expensive computation results in Redis

Bottleneck: External API calls (payment processor, email service)
  Symptoms: Request duration = external API's latency
  Solutions:
    1. Make external calls async (queue the work, return 202)
    2. Implement circuit breaker (don't wait for a failing service)
    3. Use connection pooling to the external API
    4. Implement retry with exponential backoff

Bottleneck: Network bandwidth
  Symptoms: Response time grows with response size
  Solutions:
    1. Enable gzip/Brotli compression
    2. Implement pagination (don't return 10,000 records at once)
    3. Use field filtering (client specifies which fields they need)
    4. GraphQL (clients specify exactly what data they need)
    5. Use CDN for large static responses
```

---

### Horizontal vs. Vertical Scaling

**Vertical scaling (bigger machine):**
- Upgrade from 4-core/8GB to 32-core/64GB
- Works until you hit the machine size limit
- Single point of failure (one machine fails → full outage)
- No code changes required (just restart on bigger machine)
- Best for: databases (especially write-heavy — hard to distribute writes)

**Horizontal scaling (more machines):**
- Add from 2 API servers to 20 API servers
- Theoretically unlimited scale
- Requires stateless design (no in-process session state)
- Load balancer distributes requests
- Best for: stateless API servers, read-heavy workloads

**Why REST APIs are naturally horizontally scalable:**
- No session state in process (JWT carries state; Redis holds session state)
- Every request is independent
- Any API server can handle any request
- Add servers behind the load balancer → linear capacity increase

```
2 API servers × 500 req/sec = 1000 req/sec
10 API servers × 500 req/sec = 5000 req/sec
(roughly linear, assuming DB is not the bottleneck)
```

---

### Database Scaling Patterns

**Read scaling (easy):**

```
App Server ─── [write: INSERT/UPDATE] ──── Primary DB
App Server ─── [read: SELECT] ────────────┬─ Read Replica 1
                                           └─ Read Replica 2
```

Replicas are kept in sync via streaming replication (usually <1ms lag). Reads can go to replicas; writes go to primary.

**Write scaling (hard):**

```
Option 1: Vertical scaling (single primary, just bigger)
  Pros: Simple, consistent
  Cons: Hard ceiling on size

Option 2: Sharding by user_id
  User IDs 1-1M → Shard 1
  User IDs 1M-2M → Shard 2
  Pros: Unlimited write scale
  Cons: Cross-shard queries are complex; resharding is painful

Option 3: CQRS + Event Sourcing
  Write path: Event store (append-only log)
  Read path: Materialized views built from events
  Pros: Unlimited scale for both
  Cons: High complexity; eventual consistency

Option 4: Cloud-native distributed DB (PlanetScale, CockroachDB, Spanner)
  Pros: Horizontal writes + strong consistency
  Cons: Cost, operational complexity, feature set differences from PostgreSQL
```

---

### Consistency Tradeoffs

**Strong consistency (every read sees the latest write):**
- Single database primary
- All reads from primary
- Guaranteed correct data
- Bottleneck: primary's write throughput

**Eventual consistency (reads might be slightly stale):**
- Reads from replicas (100ms behind primary)
- Writes to primary, propagate asynchronously
- Higher throughput
- Risk: user writes profile, immediately reads profile, gets old data

**The read-your-writes problem:**

```javascript
// User updates their email, then immediately fetches their profile
await db.primaryPool.query('UPDATE users SET email = $1 WHERE id = $2', ['new@example.com', userId]);
// Primary is updated

// 50ms later:
const user = await db.replicaPool.query('SELECT * FROM users WHERE id = $1', [userId]);
// Replica might still show old email (replication lag!)

// Solution: After write, read from primary (not replica)
// OR: After write, invalidate the Redis cache
// OR: After write, update the Redis cache with new data
// OR: Use stale-while-revalidate pattern (serve stale, refresh async)
```

**Cache consistency:**

```javascript
// Write-through cache: update DB and cache atomically
async function updateUserEmail(userId, newEmail) {
  await db.query('UPDATE users SET email = $1 WHERE id = $2', [newEmail, userId]);
  await redis.del(`user:profile:${userId}`);  // Invalidate cache
  // Next read will populate cache from DB with fresh data
}

// Why invalidate rather than update cache?
// Concurrent writes: if two updates happen simultaneously,
// updating the cache might set stale data from the slower write.
// Invalidation + lazy re-population avoids this race condition.
```

---

## 14. Interview Questions

### Q1: "What happens when you type `https://api.example.com/v1/users/42` and hit Enter? Walk me through the entire lifecycle."

**Answer:**

Start from the browser:

1. **URL parsing:** The browser parses the URL — scheme (https), host (api.example.com), path (/v1/users/42).

2. **HSTS check:** Browser checks its HSTS preload list and HSTS cache — if `api.example.com` is HSTS-registered, skip HTTP entirely.

3. **DNS resolution:** Browser checks its DNS cache → OS cache → stub resolver → recursive resolver → root NS → .com TLD NS → example.com authoritative NS → A record: 52.14.200.42. Result cached per TTL.

4. **TCP connection:** Browser opens TCP to 52.14.200.42:443. Three-way handshake: SYN → SYN-ACK → ACK. Cost: 1 RTT (~30-60ms for same continent).

5. **TLS handshake:** ClientHello (cipher suites, X25519 key share, SNI) → ServerHello + Certificate + Finished (in TLS 1.3). Browser validates certificate chain, OCSP staple, CT proofs. ECDH key exchange derives session keys. Cost: 1 RTT.

6. **HTTP/2 request:** Browser sends HEADERS frame with method, path, headers. The Authorization header carries the Bearer JWT.

7. **nginx receives:** nginx decrypts (TLS termination), parses HTTP/2 frames, applies rate limiting, proxies to Node.js via HTTP/1.1 on localhost.

8. **Express middleware chain:** Logging → CORS → Helmet (security headers) → JWT validation (verify RS256 signature, check exp/aud/iss, optional revocation check) → Rate limiting → Route matching.

9. **Route handler:** Validates `:userId` = 42 (integer, positive). Checks authorization (can requesting user access user 42?). Checks Redis cache — MISS. Queries PostgreSQL: `SELECT ... FROM users WHERE id = 42`. Maps DB row to response object, filtering sensitive fields. Sets in Redis cache.

10. **Response:** Express serializes JSON. nginx gzip-compresses. HTTP/2 HEADERS + DATA frames sent over TLS.

11. **Browser:** Decompresses gzip, parses JSON, renders in DOM.

**"What if" variants:**
- "What if the DNS TTL has expired?" → Full DNS resolution cycle (new recursive lookup)
- "What if there's already an HTTP/2 connection open?" → Reuses existing connection, skip TCP + TLS
- "What if the Redis cache has the data?" → DB query skipped, response from cache
- "What if the JWT is expired?" → 401 returned at auth middleware, DB never queried

---

### Q2: "Explain the difference between authentication and authorization. How are they implemented in a REST API?"

**Answer:**

**Authentication** = "Who are you?" — Verifying identity.
**Authorization** = "What are you allowed to do?" — Checking permissions.

**Authentication in REST APIs:**

The most common mechanism is JWT Bearer tokens. The token is issued at login (after verifying password/OTP), signed with the server's private key (RS256), and included in every subsequent request in the `Authorization: Bearer` header.

At each request, the server:
1. Extracts the token from the header
2. Verifies the signature using the auth server's public key (from JWKS endpoint)
3. Checks standard claims: `exp` (not expired), `aud` (correct audience), `iss` (correct issuer)
4. Optionally checks a revocation list (for logout support)

If any check fails → 401 Unauthorized.

**Authorization in REST APIs:**

After authentication, we know WHO the user is. Authorization determines WHAT they can do. Common patterns:

*RBAC (Role-Based Access Control):*
```javascript
// JWT payload: { "sub": "user_123", "roles": ["editor", "viewer"] }
// Route requires "admin" role
if (!req.user.roles.includes('admin')) return res.status(403).json({...});
```

*ABAC (Attribute-Based Access Control):*
```javascript
// More fine-grained: user can edit their OWN resources but not others'
if (req.user.sub !== req.params.userId && !req.user.roles.includes('admin')) {
  return res.status(403).json({ error: 'Forbidden' });
}
```

**Key distinction:** 401 = authentication failure (re-authenticate). 403 = authorization failure (re-authenticating won't help — you don't have permission).

**What if → the user's role changes after the JWT is issued?**
JWTs are stateless — the server doesn't track active tokens. If a user is demoted from admin to user, their JWT still says `"roles": ["admin"]` until it expires. Solutions:
1. Short JWT TTL (15 minutes) — reduces the window
2. Version field in JWT + Redis check: `redis.get('user_version:${sub}')` compared to `jwt.version`
3. Revocation list in Redis (check on every request)
4. Opaque reference tokens (not self-contained; server looks up permissions from DB each time)

---

### Q3: "What is CORS and why does the browser enforce it? Explain the preflight mechanism."

**Answer:**

**What is CORS?**

CORS (Cross-Origin Resource Sharing) is a browser security mechanism that restricts cross-origin HTTP requests made by JavaScript. The "origin" is the combination of scheme + host + port: `https://app.example.com` is a different origin from `https://api.example.com`.

**Why does the browser enforce it?**

Without CORS, any website could make AJAX requests to any other website using your cookies and authentication tokens. Imagine: you visit `evil.com`, and its JavaScript makes requests to `bank.com/api/transfer?to=attacker&amount=1000` — and since your bank session cookie is automatically sent with the request, the transfer succeeds. This is CSRF (Cross-Site Request Forgery).

CORS is the browser-enforced policy that says: "I will only allow `evil.com`'s JavaScript to talk to `bank.com` if `bank.com` explicitly says `evil.com` is allowed." Banks obviously don't allow `evil.com`.

**The preflight mechanism:**

Simple requests (GET/HEAD/POST with only simple headers) might not get a preflight — the browser just sends them but may block the response based on CORS headers.

For non-simple requests (custom headers like `Authorization`, methods like PUT/DELETE, or Content-Type: application/json for some reason in older specs), the browser automatically sends an HTTP OPTIONS preflight first:

```http
OPTIONS /v1/users/42 HTTP/2
Host: api.example.com
Origin: https://app.example.com
Access-Control-Request-Method: DELETE
Access-Control-Request-Headers: authorization, content-type
```

Server responds with what it allows:
```http
HTTP/2 204
Access-Control-Allow-Origin: https://app.example.com
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
Access-Control-Allow-Headers: Authorization, Content-Type
Access-Control-Max-Age: 86400
```

The browser caches this preflight response for `Max-Age` seconds. During that time, same-origin requests skip the preflight.

**Common CORS mistakes:**

1. `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true` — browsers reject this combination. Credentials (cookies/Authorization headers) require a specific origin, not `*`.

2. Reflecting the `Origin` header without validation:
   ```javascript
   // WRONG: Allows ANY origin
   res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
   ```
   An attacker's site can make authenticated requests.

3. Not setting `Vary: Origin` on responses — CDN might cache the response for one origin and serve it to another.

---

### Q4: "How would you design a rate limiting system for a REST API that handles 1 million requests per minute?"

**Answer:**

At 1M req/min ≈ 16,667 req/sec, a simple in-memory counter on one server won't work (multiple servers, each with its own counter, would allow 16,667 × N servers worth of requests to slip through).

**Centralized counter with Redis:**

Redis is the natural choice — it's extremely fast (~100K operations/sec), supports atomic INCR operations, and is accessible from all API server instances.

**Algorithm — Sliding Window Counter (best for API rate limiting):**

```javascript
async function checkRateLimit(key, limit, windowSeconds) {
  const now = Math.floor(Date.now() / 1000);

  // Lua script for atomicity (no race conditions between INCR and GET)
  const luaScript = `
    local key = KEYS[1]
    local limit = tonumber(ARGV[1])
    local window = tonumber(ARGV[2])
    local now = tonumber(ARGV[3])

    -- Increment counter
    local count = redis.call('INCR', key)

    -- Set expiry on first increment
    if count == 1 then
      redis.call('EXPIRE', key, window)
    end

    return count
  `;

  const count = await redis.eval(luaScript, 1, key, limit, windowSeconds, now);

  return {
    allowed: count <= limit,
    current: count,
    limit: limit,
    resetAt: now + windowSeconds
  };
}

// Usage:
const result = await checkRateLimit(`rl:${req.ip}`, 100, 60);
if (!result.allowed) {
  res.set('X-RateLimit-Limit', result.limit);
  res.set('X-RateLimit-Remaining', Math.max(0, result.limit - result.current));
  res.set('X-RateLimit-Reset', result.resetAt);
  res.set('Retry-After', result.resetAt - Date.now() / 1000);
  return res.status(429).json({ error: 'Too Many Requests' });
}
```

**Multi-tier rate limiting:**

```
Tier 1: Global (CDN level) — 10,000 req/sec per IP — drops volumetric attacks early
Tier 2: nginx level — 100 req/sec per IP — protects app servers
Tier 3: API key level (Redis) — 1000 req/min per authenticated user
Tier 4: Endpoint-specific — 5 login attempts per 15 min per account
```

**Handling distributed Redis:**

At 16,667 req/sec, even Redis can become a bottleneck if every request makes a Redis call. Optimizations:
1. Local in-process counter (Sliding window) + periodic sync to Redis: Accept ±1-5% accuracy for better throughput
2. Redis Cluster: shard rate limit keys across multiple Redis nodes
3. Token bucket with local refill: each server maintains a local bucket, periodically refills from Redis

**What if → a user needs higher limits?**
Tiered access: `X-API-Key` lookup returns user's tier (free/paid/enterprise), each tier has different limits. Paid tiers stored in a fast lookup (Redis or in-memory with periodic refresh from DB).

---

### Q5: "What is the difference between `401` and `403`? What about `400` vs `422`?"

**Answer:**

**401 vs 403:**

- `401 Unauthorized` (despite the name — should be "Unauthenticated"): The request lacks valid credentials. The user is not identified. The response must include a `WWW-Authenticate` header telling the client HOW to authenticate. Example: no JWT, expired JWT, invalid JWT signature.
- `403 Forbidden`: The request's credentials are valid (we know who you are), but this identity is not authorized for this resource. Re-authenticating won't help — they just don't have permission. Example: regular user trying to access `/admin` endpoint.

**Practical test:** "Would sending valid credentials change the outcome?"
- YES → 401 (they should authenticate properly)
- NO → 403 (even valid credentials won't grant access)

**400 vs 422:**

- `400 Bad Request`: The request is syntactically malformed. The server couldn't parse it. Examples: invalid JSON syntax, missing required header, URL is malformed.
- `422 Unprocessable Entity`: The request is syntactically valid (properly formed JSON) but semantically wrong — the server understands the format but can't process the content. Examples: `{"age": -5}` (valid JSON, invalid age value), `{"email": "not-an-email"}` (valid JSON, invalid email format).

**In practice:** Many APIs use `400` for both. `422` is technically more correct for validation failures on well-formed requests. Express.js validation libraries like Joi/Zod usually recommend `400` for validation errors (treating syntax and semantics the same for simplicity).

**Other useful status codes:**
- `404 Not Found`: Resource doesn't exist
- `409 Conflict`: Request conflicts with current state (e.g., duplicate unique key)
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Unexpected server-side error
- `503 Service Unavailable`: Server intentionally unavailable (maintenance, overloaded)

---

### Q6: "Explain idempotency in REST APIs. Which HTTP methods should be idempotent and why?"

**Answer:**

**Idempotency definition:** An operation is idempotent if performing it multiple times has the same effect as performing it once. `f(f(x)) = f(x)`.

**Why it matters for REST APIs:**

Network requests can fail in ways where you don't know if the server processed the request:
- Request sent, server processed it, response lost → client retries → double processing?
- Network timeout → did the server get the request or not?

For safe retry behavior, your mutations must be idempotent.

**HTTP method idempotency:**

```
GET — Idempotent (should be): Reading data doesn't change state
  GET /users/42 → always returns user 42's profile
  Safe to retry: Yes

PUT — Idempotent: Replace the entire resource with the given data
  PUT /users/42 {name: "Alice"} → user 42's name is now "Alice"
  Retry: Still just Alice. Same result.

DELETE — Idempotent: Resource is deleted
  DELETE /users/42 → user 42 is deleted
  Retry: User 42 is still deleted (server returns 200 or 404, either is fine)

POST — NOT idempotent by default: Creates a new resource
  POST /users {name: "Alice"} → creates user 43
  Retry: Creates user 44 (DUPLICATE!)
  Solution: Idempotency keys

PATCH — NOT idempotent by default (depends on operation):
  PATCH /users/42 {name: "Alice"} → idempotent (just sets name)
  PATCH /orders/1 {amount: "+10"} → NOT idempotent (increments each call)
```

**Implementing idempotency for POST:**

```javascript
// Client generates a unique key per intent (not per retry)
const idempotencyKey = crypto.randomUUID();
// Store this key with the order/intent before sending

// First attempt:
await fetch('/v1/payments', {
  method: 'POST',
  headers: {
    'Idempotency-Key': idempotencyKey,
    'Authorization': `Bearer ${token}`
  },
  body: JSON.stringify({ amount: 1000, currency: 'usd' })
});

// Server implementation:
async function createPayment(req, res) {
  const key = req.headers['idempotency-key'];

  // Check if we've seen this key before
  const cached = await redis.get(`idem:${key}`);
  if (cached) {
    const { status, body } = JSON.parse(cached);
    return res.status(status).json(body); // Return original response
  }

  // Acquire lock to prevent concurrent processing of same key
  const locked = await redis.set(`idem_lock:${key}`, '1', 'NX', 'EX', 30);
  if (!locked) {
    return res.status(409).json({ error: 'Concurrent request with same idempotency key' });
  }

  // Process the payment
  const payment = await processPayment(req.body);

  // Cache the response (24 hours)
  await redis.setex(`idem:${key}`, 86400, JSON.stringify({ status: 201, body: payment }));

  res.status(201).json(payment);
}
```

**"What if" variant: "What if the client sends a different request body with the same idempotency key?"**

Best practice: If the request body differs from the first request with that key, return a 422 or 409 error. The idempotency key is bound to specific parameters — changing the parameters with the same key indicates a client bug.

---

### Q7: "How does HTTP/2 improve upon HTTP/1.1? What are its limitations?"

**Answer:**

**HTTP/1.1 problems:**

1. **Head-of-line blocking at HTTP level:** Only one request at a time per connection. Solution: open up to 6 connections per origin. But 6 × connection overhead per site × many tabs = hundreds of TCP+TLS connections.

2. **Redundant headers:** Every request repeats headers like `User-Agent`, `Accept`, `Cookie` — potentially 1000 bytes of repeated text per request.

3. **No server push:** Server must wait for client to request each resource.

4. **Text protocol:** HTTP/1.1 headers are ASCII text, slower to parse than binary.

**HTTP/2 improvements:**

1. **Multiplexing:** Multiple streams over one TCP connection. 100 API calls share 1 TCP+TLS connection. No more browser limitation of 6 connections per host.

2. **HPACK header compression:** Dynamic table compresses repeated headers to 1-byte references. Saves 80-90% on header size for API calls.

3. **Server push:** Server can preemptively send resources (e.g., push CSS and JS before browser requests them). Rarely used for APIs.

4. **Binary framing:** HTTP/2 frames are binary, faster to parse, less error-prone than text.

5. **Stream prioritization:** Client can tell server which streams are more important.

**HTTP/2 limitations:**

1. **TCP head-of-line blocking:** HTTP/2 fixed HTTP-level blocking, but TCP-level blocking remains. If one TCP packet is lost, all streams on that connection stall while waiting for retransmission. (This is why HTTP/3 uses QUIC over UDP — each stream is independent at the transport layer too)

2. **Header compression state:** HPACK requires both sides to maintain identical dynamic tables. If one side gets confused (connection reset, packet loss), the tables diverge and must be rebuilt.

3. **Server push complexity:** Correctly implementing server push without sending already-cached resources is hard. Most deployments don't use it.

4. **Debugging complexity:** Binary frames are harder to inspect with tools like Wireshark (though Wireshark does decode HTTP/2 given the TLS keys).

**HTTP/3 (QUIC) improvements over HTTP/2:**
- Transport: UDP instead of TCP (no OS-level TCP stack, QUIC handles retransmission)
- Connection establishment: 0-RTT or 1-RTT (combines TLS and transport handshake)
- No TCP head-of-line blocking: lost UDP packet only affects its own stream
- Connection migration: QUIC connections survive IP changes (mobile handoff between WiFi and cellular)

---

### Q8: "What is the purpose of an ETag and how does conditional caching work?"

**Answer:**

**What is an ETag?**

An ETag (Entity Tag) is a unique identifier for a specific version of a resource. It's typically a hash of the response body or a version number.

```http
HTTP/1.1 200 OK
ETag: "abc123def456"
Last-Modified: Thu, 15 Nov 2024 10:30:00 GMT
Cache-Control: private, max-age=60

{"id": 42, "name": "Alice", ...}
```

**How conditional caching works:**

**Scenario 1: Client has cached data and ETag**

```http
GET /v1/users/42 HTTP/2
If-None-Match: "abc123def456"
```

Server checks: has the resource changed since this ETag was issued?
- If unchanged: `304 Not Modified` (no body — save bandwidth!)
- If changed: `200 OK` with new body and new ETag

**Scenario 2: Optimistic concurrency control (prevent lost updates)**

```http
PUT /v1/users/42 HTTP/2
If-Match: "abc123def456"
Content-Type: application/json

{"name": "Alice Updated"}
```

Server checks: is the current ETag still "abc123def456"?
- If yes: apply the update, return `200 OK` with new ETag
- If no (someone else updated meanwhile): `412 Precondition Failed` — don't overwrite concurrent change

This is **optimistic locking** — no pessimistic row-level database lock required; the ETag carries the version.

**ETag implementation:**

```javascript
// Generate ETag from response body
const body = JSON.stringify(user);
const etag = `"${crypto.createHash('md5').update(body).digest('hex')}"`;

// Check If-None-Match header
const clientEtag = req.headers['if-none-match'];
if (clientEtag === etag) {
  return res.status(304).end(); // Not Modified — don't send body
}

res.set('ETag', etag);
res.json(user);
```

**When to use ETags vs. Last-Modified:**
- ETags: when the response content can change without a timestamp change (reorder of fields, equivalent data)
- Last-Modified: simpler, but 1-second granularity and requires server clock synchronization
- Both together: belt-and-suspenders approach

---

### Q9: "Walk me through how you would debug a REST API endpoint that returns 200 OK but clients report 'wrong data' intermittently."

**Answer:**

"Intermittent wrong data" with a 200 status is usually one of: stale cache, race condition, or a bug in query logic.

**Step 1: Reproduce with request tracing**

Ask: can clients provide a request ID? Check if `X-Request-ID` is being logged. If yes, look at the logs for a request that returned wrong data. Compare `cache_status` in the log:

- `MISS` + wrong data from DB → database query bug or data corruption
- `HIT` + wrong data → stale cache (invalidation bug)

**Step 2: Check cache behavior**

Add temporary logging:
```javascript
const cached = await redis.get(cacheKey);
if (cached) {
  logger.debug('Cache HIT', {
    key: cacheKey,
    value_preview: JSON.stringify(JSON.parse(cached)).slice(0, 100),
    ttl: await redis.ttl(cacheKey)
  });
}
```

If cache contains wrong data, the write path isn't invalidating properly:
```javascript
// Find all places that WRITE to the user record
// Ensure each one DEL's the cache key
await db.query('UPDATE users SET email = $1...', [newEmail, userId]);
await redis.del(`user:profile:${userId}`); // Is this missing anywhere?
```

**Step 3: Check for race conditions**

If the data is the correct shape but an old version: check if multiple writers are competing:
```sql
-- Check PostgreSQL logs for concurrent UPDATE statements
-- Look for the modified_at timestamp — is it inconsistent?
SELECT id, email, updated_at FROM users WHERE id = 42;
```

**Step 4: Check read replica lag**

If using read replicas:
```javascript
const replicaUser = await replicaPool.query('SELECT updated_at FROM users WHERE id = $1', [42]);
const primaryUser = await primaryPool.query('SELECT updated_at FROM users WHERE id = $1', [42]);
if (replicaUser.rows[0].updated_at < primaryUser.rows[0].updated_at) {
  console.log('Replication lag: ', primaryUser.rows[0].updated_at - replicaUser.rows[0].updated_at, 'ms');
}
```

**Step 5: Check for query bugs**

Is the query correct? Does it handle edge cases (deleted users, special characters, NULL values)?

**Step 6: Check serialization**

Is the JavaScript → JSON serialization losing data?
```javascript
// BigInt precision loss:
JSON.stringify({ id: 9007199254740993 }) // → '{"id":9007199254740992}' (WRONG!)
```

**Step 7: Add observability before deploying a fix**

```javascript
// Structured log that captures everything needed for debugging
logger.info('profile.fetched', {
  userId,
  requestingUserId: req.user.sub,
  cacheStatus: cached ? 'HIT' : 'MISS',
  cacheAge: cached ? await redis.ttl(cacheKey) : null,
  dbQueryDurationMs: queryEnd - queryStart,
  replicaLagMs: await redis.get(`replica_lag:${dbReplicaId}`) || 0, // Captured via background heartbeat metric
  resultHash: crypto.createHash('md5').update(JSON.stringify(result)).digest('hex')
});
```

Tracking the `resultHash` across requests lets you correlate which requests return wrong data with cache hits/misses, DB query timing, and user identity.

---

*Document version: 1.0 | Classification: Internal Engineering | Author: Platform Engineering Team*  
*This document describes standard REST API architecture patterns. Adapt specifics to your technology stack.*
