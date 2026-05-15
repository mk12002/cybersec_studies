# CDN-Based File Delivery System — Engineering & Security Breakdown

**Classification:** Internal Engineering Reference  
**Audience:** Engineers, Security Analysts, Architects  
**Assumed Reader:** Will be interviewed on this system. Every claim here is defensible.

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
9. [Attack Scenarios](#9-attack-scenarios)
10. [Failure Points](#10-failure-points)
11. [Mitigations](#11-mitigations)
12. [Observability](#12-observability)
13. [Scaling Considerations](#13-scaling-considerations)
14. [Interview Questions](#14-interview-questions)

---

## 1. User Journey (Narrative)

### The Setup

A user wants to download a file — say, `report_q4_2025.pdf` — from a SaaS platform backed by a CDN. The file is stored in S3, fronted by CloudFront (or Fastly/Akamai/Cloudflare — the mechanics are equivalent). The user is authenticated via a JWT in a cookie. The file is access-controlled: only members of `org_id=4421` can download it.

### Step-by-Step Story

**T=0ms — User clicks "Download"**

The browser fires a JavaScript `fetch()` or a plain `<a href>` navigation. The browser checks its DNS cache. If the hostname (`cdn.example.com`) is not cached, a DNS resolution chain begins. If it is cached, we skip straight to TCP.

**T=0–50ms — DNS Resolution**

The OS resolver checks:
1. `/etc/hosts` (or Windows HOSTS file) — local override, checked first.
2. The OS DNS cache (TTL-based, populated from prior lookups).
3. If not found: forwards to the configured stub resolver (usually the router or a configured DNS like `8.8.8.8`).

The stub resolver checks its own cache. On cache miss, it performs **recursive resolution**:

- Queries a root nameserver for `com.`
- Root nameserver returns NS records for `.com.` — the TLD nameservers.
- Queries the `.com.` TLD nameserver for `example.com.`
- TLD returns NS records pointing to `example.com.`'s authoritative nameserver.
- Queries the authoritative NS for `cdn.example.com.`
- Authoritative NS returns a CNAME like `cdn.example.com. → d123.cloudfront.net.` plus CloudFront's A/AAAA records.
- The resolver returns the final IP with the TTL.

CDN providers keep TTLs low (60–300s) so they can reroute traffic quickly when PoPs change. Low TTL = more DNS load on authoritative servers. This is a deliberate tradeoff.

The **GeoDNS** component at this step is critical: the authoritative DNS doesn't return the same IP to everyone. It inspects the EDNS0 Client Subnet extension (the resolver forwards the client's /24 subnet) and returns the IP of the nearest CDN PoP. A user in Mumbai gets a Mumbai PoP IP; a user in Frankfurt gets a Frankfurt PoP IP. This is the entire basis for CDN geographic distribution.

**T=50ms — TCP 3-Way Handshake to CDN PoP**

The browser opens a TCP connection to the CDN PoP's IP on port 443:
- `SYN` — client → server (with a random initial sequence number, ISN)
- `SYN-ACK` — server → client (server's ISN + ack of client's ISN+1)
- `ACK` — client → server

This is ~1 RTT (~10–40ms for a nearby PoP). For HTTP/2 and HTTP/3 (QUIC), connection reuse eliminates this cost on subsequent requests.

**T=80ms — TLS Handshake**

TLS 1.3 (the current standard) takes 1 RTT after TCP is established:

- Client sends `ClientHello`: TLS version, list of supported cipher suites, random nonce, list of supported groups (X25519, P-256), **Server Name Indication (SNI)** extension (so the server knows which cert to present for multi-tenant CDNs).
- Server responds with `ServerHello` + Certificate + `CertificateVerify` + `Finished` — all in one flight.
- Client verifies the certificate chain against its trust store, derives session keys, sends `Finished`.
- Data can flow immediately after server's first response.

Key derivation uses ECDHE (Elliptic Curve Diffie-Hellman Ephemeral). Ephemeral means a new key pair is generated per session — forward secrecy. If the server's long-term private key is stolen later, past sessions cannot be decrypted.

**T=110ms — HTTP Request Arrives at CDN Edge**

The CDN edge receives the full HTTP request. At this point, the CDN evaluates its **cache**:

- Constructs a cache key from: hostname + path + selected headers/cookies (if configured).
- Checks the edge cache (in-memory + SSD).
- If HIT: returns file immediately from edge. **Origin is never contacted.** This is 99% of CDN traffic for popular public files.
- If MISS: CDN makes a backend request to the origin (your servers or S3).

For **authenticated/private files**, the CDN typically cannot cache the response (because cache-control headers say `private` or `no-store`). The CDN acts purely as a TLS terminator + DDoS buffer + network path optimizer, not a content cache.

**T=120ms — Origin Request (on cache miss)**

The CDN PoP opens a persistent (keep-alive) TCP connection to the origin (or uses an already-open connection from its connection pool). This connection may be TLS-encrypted as well (CDN → origin mTLS). The CDN forwards the request with:

- Original request headers (path, method, query params)
- `X-Forwarded-For` with the client's real IP
- `X-Forwarded-Proto: https`
- Custom headers the CDN adds (`CF-Ray`, `X-Amz-Cf-Id`, etc.)

**T=130ms — Authentication & Authorization at Origin**

The origin API server receives the request. It:
1. Extracts the `Authorization` header or session cookie.
2. Validates the JWT (signature, expiry, issuer).
3. Extracts `user_id` and `org_id` from the token.
4. Queries the database (or cache) to confirm the user has `READ` permission on `file_id=abc123`.
5. If authorized, generates a **pre-signed S3 URL** (valid for 60 seconds) or streams the S3 object directly.

**T=160ms — S3 Object Fetch & Stream**

The origin fetches from S3 (same region, low latency, ~5–15ms). It streams the bytes back to the CDN, which streams them back to the client. For large files, this is chunked transfer encoding — bytes flow before the file is fully fetched.

**T=200ms+ — Client Receives File**

The browser receives bytes. For a `Content-Disposition: attachment` header, the browser triggers a file download dialog. For inline content (PDF, image), it may render in-browser.

**What the User Sees vs What Actually Happens**

| User Perception | Reality |
|---|---|
| "I clicked Download and it started immediately" | DNS + TCP + TLS + auth check took 150–300ms before byte 1 arrived |
| "The download was fast" | Either CDN cache hit (edge delivery) or S3 streaming over optimized CDN backbone |
| "It just worked" | JWT was validated, ACL was checked, S3 presigned URL was generated and consumed — all invisible |
| "My download failed" | Any of: DNS NXDOMAIN, TLS cert mismatch, 401 from expired token, 403 from ACL denial, S3 outage, timeout |

---

## 2. Network Layer Flow

### DNS Resolution — Deep Mechanics

```
User's Browser
     |
     | (1) Check /etc/hosts — not found
     | (2) Check OS DNS cache — TTL expired or not present
     v
Stub Resolver (127.0.0.53 on Linux / 127.0.0.1 on macOS)
     |
     | (3) Forward to recursive resolver
     v
Recursive Resolver (8.8.8.8 or ISP resolver)
     |
     | Cache miss? Start iterative resolution:
     |
     | (4) Query root (.) nameserver
     |     → "I don't know cdn.example.com, ask .com TLD"
     |     Response: NS records for .com TLD
     |
     | (5) Query .com TLD nameserver
     |     → "I don't know, ask example.com's NS"
     |     Response: NS records for example.com
     |
     | (6) Query example.com authoritative NS
     |     → CNAME: cdn.example.com → d123.cloudfront.net
     |     → A: 13.35.12.45 (GeoDNS-selected PoP IP)
     |
     | (7) Return IP to stub resolver
     v
OS DNS Cache (stores with TTL=60s)
     |
     v
Browser (stores with TTL, initiates TCP to 13.35.12.45:443)
```

**EDNS0 Client Subnet (ECS):** Recursive resolvers that support RFC 7871 include the client's /24 prefix in the query. The authoritative DNS uses this to make geo-routing decisions. Without ECS, the authoritative server only sees the resolver's IP (often centralized — Google, Cloudflare), breaking geo-routing accuracy. This is why some CDNs recommend using their own DNS resolvers.

**DNS Failure Modes:**
- `NXDOMAIN`: The domain doesn't exist. Common during CDN migration if CNAME isn't propagated yet.
- `SERVFAIL`: The authoritative server is unreachable or misbehaving.
- `Timeout`: No response within the OS timeout (typically 5s with 2 retries). Causes full DNS resolution failure.
- **DNS Cache Poisoning**: Attacker injects a forged DNS response, redirecting traffic to a malicious IP. DNSSEC mitigates this by signing records cryptographically. CDNs rarely sign with DNSSEC — it's a gap.
- **TTL too high**: A CDN failover takes effect, but users still have the old IP cached for the TTL duration. Users can't reach the new PoP.

### TCP 3-Way Handshake

```
Client                              CDN PoP (13.35.12.45:443)
  |                                          |
  |  SYN (seq=X, flags=SYN)                 |
  |---------------------------------------->|
  |                                          |
  |  SYN-ACK (seq=Y, ack=X+1, flags=SYN+ACK)|
  |<----------------------------------------|
  |                                          |
  |  ACK (ack=Y+1, flags=ACK)               |
  |---------------------------------------->|
  |                                          |
  | [Connection Established — 1 RTT elapsed] |
```

**SYN Flood Attack**: Attacker sends SYN packets with spoofed source IPs. Server allocates state for each half-open connection (syn_backlog). When the queue fills, legitimate connections are dropped. CDNs absorb this — they have SYN cookies enabled, which encodes connection state into the SYN-ACK sequence number, so no state is stored until the ACK arrives.

**TCP Fast Open (TFO)**: Allows data to be sent in the SYN packet (requires prior TLS session). Reduces handshake latency. Not universally deployed — some middleboxes strip TFO cookies.

### TLS Handshake (TLS 1.3)

```
Client                                        CDN Edge (TLS Termination)
  |                                                     |
  | ClientHello:                                        |
  |   - TLS 1.3                                        |
  |   - Cipher suites: TLS_AES_256_GCM_SHA384,        |
  |                    TLS_CHACHA20_POLY1305_SHA256     |
  |   - Key share: X25519 ephemeral public key (g^a)   |
  |   - SNI: cdn.example.com                           |
  |   - Random nonce (32 bytes)                        |
  |---------------------------------------------------->|
  |                                                     |
  | ServerHello + Certificate + CertificateVerify       |
  | + Finished (encrypted with derived key):            |
  |   - Chosen cipher: TLS_AES_256_GCM_SHA384          |
  |   - Key share: server ephemeral X25519 (g^b)       |
  |   - Certificate: cdn.example.com (DV or OV)        |
  |   - Signature over handshake transcript            |
  |<----------------------------------------------------|
  |                                                     |
  | [Both derive shared secret: g^(a*b) via ECDHE]     |
  | [Key material: HKDF-expanded into multiple keys]   |
  |   - client_write_key (client → server encryption)  |
  |   - server_write_key (server → client encryption)  |
  |   - client_write_iv, server_write_iv               |
  |                                                     |
  | Finished (client confirms handshake integrity)      |
  |---------------------------------------------------->|
  |                                                     |
  | [Application data — encrypted — begins flowing]    |
```

**Certificate Chain of Trust:**
The CDN presents a certificate signed by an intermediate CA (e.g., Amazon Trust Services → DigiCert Root). The browser validates:
1. The leaf cert's CN or SAN matches `cdn.example.com`.
2. The signature on the leaf cert is valid using the intermediate's public key.
3. The intermediate's signature is valid using the root CA's public key.
4. The root CA is in the browser's trust store (a hard-coded list, updated via OS/browser updates).
5. The cert is not revoked (OCSP stapling or CRL check).
6. The cert is not expired.

**Certificate Transparency (CT):** All publicly trusted certs must be logged in CT logs. Browsers check for SCTs (Signed Certificate Timestamps) in the TLS handshake. This lets anyone audit all certs ever issued for a domain. CDNs automatically submit certs to CT logs.

**SNI Privacy Concern:** The SNI field (hostname) is sent in plaintext in ClientHello, before encryption. Network observers (ISPs, government firewalls) can see which domains you're connecting to. **Encrypted Client Hello (ECH)** is the IETF draft that encrypts the SNI — not yet widely deployed.

**Where Latency Occurs:**
| Phase | Typical Latency | Cause |
|---|---|---|
| DNS | 20–100ms (cold) / 0ms (cached) | Recursive resolution chain |
| TCP Handshake | 10–40ms | 1 RTT to nearest PoP |
| TLS 1.3 Handshake | 10–40ms | 1 RTT (server sends cert + keys together) |
| TLS 1.2 (legacy) | 20–80ms | 2 RTTs (extra round trip for key exchange) |
| TTFB (Time to First Byte) | 50–200ms | Auth check + origin fetch |
| File Transfer | Variable | File size / bandwidth |

### Full Packet-Level ASCII Diagram

```
 Client (203.0.113.5)                               CDN PoP (13.35.12.45)
        |                                                     |
        |====[ DNS Resolution — UDP port 53 ]================>| (Recursive resolver, not CDN)
        |<====[ A record: 13.35.12.45, TTL=60 ]=============|
        |                                                     |
        |----[ TCP SYN, seq=1000 ]--------------------------->|
        |<---[ TCP SYN-ACK, seq=2000, ack=1001 ]------------|
        |----[ TCP ACK, ack=2001 ]--------------------------->|
        |                                                     |
        |----[ TLS ClientHello ]----------------------------->|
        |<---[ TLS ServerHello + Cert + CertVerify + Fin ]---|
        |----[ TLS Finished ]-------------------------------->|
        |                                                     |
        |====[ ENCRYPTED CHANNEL ESTABLISHED ]===============|
        |                                                     |
        |----[ HTTP/2 GET /files/report_q4_2025.pdf ]------->|
        |      Headers:                                       |
        |        :authority: cdn.example.com                  |
        |        :path: /files/report_q4_2025.pdf             |
        |        cookie: session=eyJhbGci...                  |
        |        accept: application/pdf                      |
        |                                                     |
        |        [CDN Edge: Cache Miss]                       |
        |        [CDN forwards to Origin: 10.0.1.5:443]       |
        |                              |                      |
        |                              |--[ GET + Auth ]----->| Origin
        |                              |<--[ 200 + Bytes ]----|
        |                              |                      |
        |<---[ HTTP/2 200 OK ]--------|                      |
        |      Content-Type: application/pdf                  |
        |      Content-Disposition: attachment                |
        |      Content-Length: 4194304                        |
        |      Cache-Control: private, no-store               |
        |      [DATA FRAMES stream...]                        |
        |<---[ ... ]------------------------------------------|
        |                                                     |
        |----[ TCP FIN ]------------------------------------->|
        |<---[ TCP FIN-ACK ]----------------------------------|
```

---

## 3. Application Layer Flow

### HTTP Request Lifecycle

When the CDN edge receives the HTTP request, it processes it in a strict pipeline. Understanding each stage is critical for debugging and security.

**Stage 1: Request Parsing**

The HTTP/2 or HTTP/3 framing is decoded. For HTTP/2:
- Headers arrive in a HEADERS frame (HPACK-compressed).
- Body (for POST/PUT) arrives in DATA frames.
- Pseudo-headers (`:method`, `:path`, `:authority`, `:scheme`) are extracted first.

The CDN normalizes the path:
- URL-decoding: `%2F` → `/`, `%20` → ` `
- Path normalization: `/files/../files/report.pdf` → `/files/report.pdf`
- Trailing slash normalization

**This normalization step is a security-critical path.** If the CDN normalizes differently from the origin, a path traversal attack may bypass CDN WAF rules but reach the origin. For example, CDN sees `/files/safe.pdf`, origin sees `/etc/passwd` if normalization is inconsistent.

**Stage 2: CDN Cache Evaluation**

Cache key construction (for CloudFront):
```
cache_key = hash(
  host,                          // cdn.example.com
  path,                          // /files/report_q4_2025.pdf
  query_string_params_allowlist, // ?version=2 (if configured)
  header_allowlist,              // Accept-Language (if configured)
  cookie_allowlist               // (nothing, or specific cookies)
)
```

For private files, the CDN is configured to **not cache** (via `Cache-Control: private` from origin, or explicit CDN no-cache rules). If misconfigured, private files may be cached and served to other users — a catastrophic data leak.

**Stage 3: Request Forwarding to Origin**

The CDN adds:
- `X-Forwarded-For: 203.0.113.5` — client's real IP (original header may be spoofed by client — CDN should overwrite, not append)
- `X-Forwarded-Proto: https`
- `CF-Connecting-IP` (Cloudflare) or `CloudFront-Viewer-Country` (CloudFront) — geo data
- `X-Request-ID` or `CF-Ray` — unique request identifier for tracing

**Stage 4: Origin Request Processing**

The application server (Node.js, Python, Go, Java — doesn't matter) receives the request:

```
[Request arrives on port 443 (or 8443)]
         |
         v
[TLS Termination — nginx/envoy/load balancer]
         |
         v
[Web Framework Router — matches /files/:file_id]
         |
         v
[Middleware chain (order matters!)]
  1. Request ID injection (generates UUID, adds to request context)
  2. Rate limiter (check Redis: user_id or IP bucket)
  3. Authentication (validate JWT from Authorization header or session cookie)
  4. Authorization (check ACL: does user have READ on this file?)
  5. Input validation (is file_id a valid UUID? Is it URL-safe?)
  6. Business logic (fetch file metadata, generate presigned URL or stream)
         |
         v
[Response construction]
  - Set appropriate headers
  - Stream body (chunked transfer or presigned redirect)
```

**HTTP Methods in Context:**

| Method | Use Case | Body | Idempotent | Safe |
|---|---|---|---|---|
| GET | Fetch file | None | Yes | Yes |
| HEAD | Check if file exists / get metadata | None | Yes | Yes |
| OPTIONS | CORS preflight | None | Yes | Yes |
| PUT | Upload file | Binary | Yes | No |
| DELETE | Delete file | None | Yes | No |
| POST | Initiate multipart upload | JSON | No | No |

**Critical Header Behaviors:**

`Range: bytes=0-1048575` — Partial content request. Server must respond with `206 Partial Content` and `Content-Range: bytes 0-1048575/4194304`. This enables download resumption and parallel chunked downloads. If the server doesn't handle Range requests, large files can't be resumed after interruption.

`If-None-Match: "abc123"` — Conditional GET using ETag. If the file hasn't changed (ETag matches), server returns `304 Not Modified` with no body. Saves bandwidth for repeat downloads of unchanged files.

`Accept-Encoding: gzip, br` — Client signals compression support. Server may respond with `Content-Encoding: gzip`. **Never compress already-compressed files (PDFs, ZIPs, images)** — you waste CPU and sometimes increase size.

**Cookie Handling:**

The browser sends cookies matching the domain and path. For `cdn.example.com`, it sends all cookies for `example.com` with `SameSite` policies allowing cross-site transmission:
- `session=<JWT>; HttpOnly; Secure; SameSite=Lax`
- `HttpOnly` — JS cannot access this cookie (XSS mitigation)
- `Secure` — only sent over HTTPS
- `SameSite=Lax` — sent on top-level navigations, but not cross-site sub-requests

The origin extracts the cookie: `request.cookies['session']` → JWT string → decode → validate.

**Parameter Parsing:**

Query parameters (`?file_id=abc&version=2`) are parsed by the framework into a dictionary. Security concern: parameter pollution. If the server receives `?file_id=abc&file_id=xyz`, which one wins? In PHP: last wins. In Express: array. In ASP.NET: first wins. This inconsistency between WAF parsing and application parsing is exploited to bypass filters.

**Response Construction:**

```
HTTP/2 200 OK
Content-Type: application/pdf
Content-Disposition: attachment; filename="report_q4_2025.pdf"
Content-Length: 4194304
Content-Security-Policy: default-src 'none'
X-Content-Type-Options: nosniff
Cache-Control: private, no-store, must-revalidate
ETag: "sha256:abc123def456..."
X-Request-ID: 550e8400-e29b-41d4-a716-446655440000
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
```

Each of these headers has a security function. Missing any is a finding.

---

## 4. Backend Architecture

### Services Involved

```
                        ┌─────────────────────────────────────────────┐
                        │             CDN Layer (CloudFront/Fastly)    │
                        │  PoP1(Mumbai) PoP2(Frankfurt) PoP3(Virginia) │
                        └──────────────────┬──────────────────────────┘
                                           │ Cache miss → origin request
                                           │ (persistent connection pool)
                        ┌──────────────────▼──────────────────────────┐
                        │           API Gateway / Load Balancer        │
                        │     (nginx/ALB — TLS termination, routing)   │
                        └──────────────────┬──────────────────────────┘
                                           │
                    ┌──────────────────────▼──────────────────────────┐
                    │                 Application Tier                  │
                    │                                                   │
                    │  ┌──────────────┐    ┌──────────────────────┐   │
                    │  │  File API    │    │   Auth Service        │   │
                    │  │  Service     │◄───│  (JWT validation,     │   │
                    │  │  (Go/Python) │    │   session mgmt)       │   │
                    │  └──────┬───────┘    └──────────────────────┘   │
                    │         │                                         │
                    │  ┌──────▼───────┐    ┌──────────────────────┐   │
                    │  │ Permission   │    │   Audit Log Service   │   │
                    │  │ Service      │    │   (async, Kafka)      │   │
                    │  │ (ACL check)  │    └──────────────────────┘   │
                    │  └──────┬───────┘                                │
                    └─────────┼───────────────────────────────────────┘
                              │
          ┌───────────────────┼──────────────────────┐
          │                   │                       │
  ┌───────▼──────┐   ┌────────▼──────┐   ┌──────────▼─────────┐
  │  PostgreSQL  │   │  Redis Cache  │   │  Amazon S3          │
  │  (file meta, │   │  (sessions,   │   │  (actual file bytes)│
  │   ACLs,      │   │   rate limits,│   │                     │
  │   audit logs)│   │   presigned   │   │  KMS-encrypted      │
  │              │   │   URL cache)  │   │  SSE-S3 or SSE-KMS  │
  └──────────────┘   └───────────────┘   └────────────────────┘
```

### File API Service — Internal Logic

**Synchronous path (request/response):**
1. Parse and validate request (middleware).
2. Call Auth Service to validate JWT (gRPC, ~2ms local network).
3. Call Permission Service to check ACL (gRPC, possibly cached in Redis, ~1ms).
4. Fetch file metadata from PostgreSQL (file size, S3 key, content-type, virus scan status).
5. If file is virus-scan-pending: return `202 Accepted` — file not yet safe to serve.
6. Generate S3 presigned GET URL (AWS SDK, local operation, ~0ms).
7. Option A: Redirect client to presigned URL (`302 Found`).
8. Option B: Stream S3 bytes through origin to CDN to client (proxy mode).

**Option A vs Option B tradeoff:**

| | Presigned URL Redirect | Proxy Stream |
|---|---|---|
| Bandwidth cost | S3 serves directly (cheaper) | Origin pays bandwidth |
| Auth control | URL is valid for 60s (window for theft) | Auth enforced on every byte |
| Audit granularity | Can't track byte-level download | Full control |
| CDN cacheability | CDN can cache S3 response (if public) | CDN can cache if headers allow |
| Client experience | Two TCP connections (one to CDN, one to S3) | Single connection |

**Asynchronous path (audit logging):**

Every file download event is published to a Kafka topic (`file.access.events`) with:
```json
{
  "event_id": "uuid",
  "timestamp": "2025-05-15T10:23:45Z",
  "user_id": "u_123",
  "org_id": "org_4421",
  "file_id": "f_abc123",
  "action": "DOWNLOAD",
  "ip": "203.0.113.5",
  "user_agent": "Mozilla/5.0...",
  "result": "SUCCESS",
  "bytes_served": 4194304,
  "cdn_pop": "MUM-01",
  "request_id": "550e8400..."
}
```

Kafka consumers write this to PostgreSQL (audit log table) and optionally to a SIEM (Splunk, Datadog, Elastic). This is decoupled — the HTTP response doesn't wait for Kafka acknowledgment (fire-and-forget, at-least-once delivery).

**Worker services:**

- **Virus Scanner Worker**: Subscribes to `file.upload.events`, fetches file from S3, runs ClamAV or a cloud AV API, updates `files.scan_status` in PostgreSQL. Duration: seconds to minutes. File is blocked for download until scan completes.
- **Thumbnail Generator Worker**: For images/PDFs, generates preview thumbnails, uploads to a separate S3 prefix, updates metadata.
- **Expiry Worker**: Cron job that marks files past retention policy as deleted, removes from S3 (soft delete first, hard delete after 30 days), invalidates CDN cache.

### Database Schema (Simplified)

```sql
-- Core file metadata
CREATE TABLE files (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID NOT NULL,
    uploaded_by  UUID NOT NULL,
    s3_key       TEXT NOT NULL,       -- e.g., orgs/4421/files/abc123/report.pdf
    filename     TEXT NOT NULL,       -- original filename (user-supplied, sanitized)
    content_type TEXT NOT NULL,
    size_bytes   BIGINT NOT NULL,
    checksum_sha256 CHAR(64) NOT NULL,
    scan_status  TEXT DEFAULT 'PENDING', -- PENDING, CLEAN, INFECTED
    deleted_at   TIMESTAMPTZ,         -- soft delete
    created_at   TIMESTAMPTZ DEFAULT NOW(),
    updated_at   TIMESTAMPTZ DEFAULT NOW()
);

-- Access control
CREATE TABLE file_permissions (
    id           UUID PRIMARY KEY,
    file_id      UUID REFERENCES files(id),
    grantee_id   UUID NOT NULL,       -- user_id or org_id or group_id
    grantee_type TEXT NOT NULL,       -- USER, ORG, GROUP
    permission   TEXT NOT NULL,       -- READ, WRITE, ADMIN
    granted_by   UUID NOT NULL,
    granted_at   TIMESTAMPTZ DEFAULT NOW(),
    expires_at   TIMESTAMPTZ          -- NULL = never
);

-- Indexes: file lookups by org, by user, by scan status
CREATE INDEX idx_files_org ON files(org_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_perms_file_grantee ON file_permissions(file_id, grantee_id);
```

### Caching Strategy

**CDN Edge Cache (L1):** Public files cached by path + ETag. Hit rate target: 80%+. TTL: configured per content type (PDF: 1 hour, JS/CSS: 1 year with content hash in filename).

**Redis Cache (L2):**
- Session tokens (key: `session:{token_hash}`, value: user object, TTL=session_expiry)
- Permission results (key: `perm:{user_id}:{file_id}`, value: `{READ: true}`, TTL=5min)
- Rate limit counters (key: `ratelimit:{user_id}:download`, value: count, TTL=1min)
- Presigned URL cache (key: `presign:{file_id}:{user_id}`, value: URL, TTL=50s — shorter than URL validity)

**Redis failure mode:** If Redis is down, the application must decide: fail open (serve files without permission cache) or fail closed (return 503). For security-critical systems: fail closed. This degrades availability but protects data.

**Application-level cache (L3):** In-process LRU cache for file metadata (org_id, content_type, size). Very short TTL (30s) to avoid stale data. Only appropriate for immutable metadata (content type won't change after upload).

---

## 5. Authentication & Authorization Flow

### Authentication — JWT Deep Dive

JWTs used in this system are RS256-signed (asymmetric — auth server holds private key, all services hold public key). This means:
- Auth service signs tokens with its RSA-2048 or EC P-256 private key.
- Any service can verify tokens using the public key (fetched from `https://auth.example.com/.well-known/jwks.json`).
- Services cache the JWKS. They rotate it when a key ID (`kid`) in the token header is not found in the cache.

**JWT Structure:**
```
Header (base64url-encoded):
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "key-2025-01"    ← identifies which public key to use for verification
}

Payload (base64url-encoded):
{
  "sub": "u_123",           ← subject (user ID)
  "org_id": "org_4421",
  "roles": ["member"],
  "iss": "https://auth.example.com",
  "aud": "https://api.example.com",
  "iat": 1747294800,        ← issued at (Unix timestamp)
  "exp": 1747298400,        ← expires at (iat + 1 hour)
  "jti": "uuid"             ← JWT ID (for revocation tracking)
}

Signature (base64url-encoded):
RSASSA-PKCS1-v1_5(
  SHA-256(base64url(header) + "." + base64url(payload)),
  private_key
)
```

**Validation steps (in exact order — order matters):**
1. Split on `.` — must produce exactly 3 parts.
2. Decode header — check `alg` is RS256 (reject `none` algorithm — classic vulnerability).
3. Look up `kid` in JWKS — fetch and cache if not found.
4. Verify signature using the public key.
5. Check `iss` matches expected issuer.
6. Check `aud` includes this service's audience.
7. Check `exp` > current time (token not expired).
8. Check `iat` < current time (token not issued in the future — clock skew tolerance: ±30s).
9. Optionally: check `jti` against revocation list (Redis set of revoked JTI values).

**Step 9 is often skipped** (performance cost) — this means logout doesn't truly invalidate tokens until expiry. Acceptable if token TTL is short (15min). Unacceptable for long-lived tokens.

### Authorization — ACL Check

```
[Permission Service receives: user_id=u_123, file_id=f_abc123, action=READ]
         |
         v
[Check Redis: perm:u_123:f_abc123 → HIT: {READ: true}]
         |
         | (on miss)
         v
[Query PostgreSQL file_permissions table]

SELECT EXISTS (
  SELECT 1 FROM file_permissions fp
  JOIN files f ON f.id = fp.file_id
  WHERE fp.file_id = $1           -- f_abc123
    AND fp.grantee_id IN (
      $2,                          -- user_id directly
      (SELECT org_id FROM users WHERE id = $2),  -- user's org
      (SELECT unnest(group_ids) FROM users WHERE id = $2)  -- user's groups
    )
    AND fp.permission = 'READ'
    AND (fp.expires_at IS NULL OR fp.expires_at > NOW())
    AND f.deleted_at IS NULL
    AND f.org_id = (SELECT org_id FROM users WHERE id = $2)  -- org isolation
);
```

**This query has a multi-tenant safety net:** The last condition (`f.org_id = user's org_id`) ensures that even if an attacker crafts a request for a file from another org, the query will return false because the org_ids don't match. This is defense-in-depth for IDOR.

**Trust Boundaries in Auth:**

```
[Internet — UNTRUSTED]
         |
         ▼
[CDN Edge — UNTRUSTED for auth purposes, trusted for TLS termination]
         |
         ▼
[Load Balancer — SEMI-TRUSTED: terminates TLS, adds X-Forwarded-For]
         |
         ▼
[API Gateway — TRUSTED: validates that requests came through the LB]
  (IP allowlist: only accept traffic from known CDN CIDR ranges)
         |
         ▼
[Auth Middleware — validates JWT before any business logic]
         |
         ▼
[Internal Services — TRUSTED: communicate over mTLS]
         |
         ▼
[Database — TRUSTED: connection from app service only, no internet exposure]
```

**Session vs Token:**

| | Session Cookie | JWT |
|---|---|---|
| Storage | Server-side (Redis) | Stateless (client-side) |
| Revocation | Immediate (delete from Redis) | Delayed (until expiry) |
| Scalability | Redis must be available | Any node can verify |
| Size | Small (session ID only) | Larger (claims embedded) |
| This system uses | Hybrid: JWT stored in HttpOnly cookie | — |

The hybrid approach: JWT is the token format, but it's stored in an HttpOnly cookie (not localStorage), preventing XSS token theft. The cookie is sent automatically by the browser, so CSRF is a concern — mitigated by SameSite=Strict/Lax and CSRF tokens on state-changing requests.

### Token Storage and Rotation

**Access Token:** JWT, 15-min expiry, stored in HttpOnly Secure cookie.  
**Refresh Token:** Opaque random string (128-bit), 30-day expiry, stored in HttpOnly Secure cookie with path=/auth/refresh (so it's only sent to the refresh endpoint).  
**Rotation:** On refresh, old refresh token is invalidated and a new one is issued. Refresh token rotation with family tracking: if an old (already-rotated) refresh token is presented, it indicates theft — all tokens for that user are revoked.

---

## 6. Data Flow

### Upload Path (File Enters the System)

```
Client Browser
    |
    | (1) POST /api/upload/init
    |     Body: { filename, content_type, size }
    |     Auth: JWT
    v
API Server
    |
    | (2) Validate: filename (sanitize), content_type (allowlist),
    |               size (max 5GB), user has WRITE permission on org
    |
    | (3) Generate S3 key: orgs/{org_id}/files/{uuid}/{sanitized_filename}
    |     Create DB record: files row with status=UPLOADING
    |
    | (4) Generate S3 presigned PUT URL (15-min expiry)
    |     Include: Content-Type restriction, max size (Content-Length-Range condition)
    |
    | (5) Return: { upload_url, file_id }
    v
Client Browser
    |
    | (6) PUT {upload_url}  ← Direct to S3, not through API server
    |     Content-Type: application/pdf
    |     Body: raw bytes
    v
Amazon S3
    |
    | (7) S3 validates presigned URL signature
    |     Checks: not expired, Content-Type matches, size within bounds
    |     Stores object in encrypted form (SSE-KMS)
    |
    | (8) S3 Event Notification → SQS → Lambda (or worker service)
    v
File Processing Worker
    |
    | (9) Worker pulls event from SQS
    |     Fetches file metadata from DB (file_id)
    |     Downloads file from S3 (to /tmp, ephemeral)
    |
    | (10) Compute SHA-256 checksum
    |      Compare with client-provided checksum (if any)
    |
    | (11) Run virus scan (ClamAV)
    |      If INFECTED: update DB status=INFECTED, delete from S3, notify user
    |      If CLEAN: update DB status=ACTIVE
    |
    | (12) Generate thumbnails (for PDFs/images)
    |      Upload to s3://{bucket}/thumbs/{file_id}/thumb.png
    |
    | (13) Publish to Kafka: file.upload.complete event
    v
Audit Log Consumer
    | Writes to PostgreSQL audit_logs table
    v
Notification Service
    | Sends email/webhook to user: "Your file is ready"
```

### Download Path (File Leaves the System)

```
Client → CDN → API Server → Permission Service → S3 → Client

Data transformations at each hop:
  - CDN: Decrypts TLS, re-encrypts for client; may decompress/recompress
  - API Server: Decodes HTTP request, validates auth, fetches metadata
  - S3: Decrypts SSE-KMS, streams plaintext to API Server
  - API Server: Re-encrypts in TLS to CDN (CDN→Origin TLS)
  - CDN: Re-encrypts in TLS to client
```

**Serialization Formats:**
- Client ↔ API: JSON (application/json) for metadata, binary for file bytes
- API ↔ Auth Service: Protocol Buffers over gRPC (efficient, schema-enforced)
- API ↔ Redis: RESP protocol (Redis Serialization Protocol)
- API ↔ PostgreSQL: PostgreSQL wire protocol (binary encoding for binary types)
- API ↔ S3: AWS Signature V4-signed HTTP requests, XML responses (S3 API)
- Events: JSON in Kafka (or Avro with schema registry for strict contracts)

**Data Validation at Each Boundary:**

| Boundary | What's Validated |
|---|---|
| Client → CDN | TLS cert, HTTP syntax |
| CDN → API | JWT signature, request schema, rate limits |
| API → Permission Service | user_id is a valid UUID, file_id is a valid UUID |
| API → S3 | S3 key format, IAM permissions |
| API → Database | Parameterized queries (no string interpolation), type constraints |
| API → Kafka | JSON schema validation before publish |

---

## 7. Security Controls

### Encryption in Transit

**Client ↔ CDN:** TLS 1.3 mandatory. TLS 1.0 and 1.1 disabled (PCI DSS and general hygiene). Cipher suites: only AEAD (AES-GCM, ChaCha20-Poly1305). RSA-only cipher suites disabled (no forward secrecy). HSTS with long max-age and preloading.

**CDN ↔ Origin:** TLS 1.2+ with certificate pinning (CDN validates origin cert). Origin uses an internal CA-signed cert, not a public CA. mTLS optional but recommended: origin verifies that requests come from the CDN (using CDN client cert).

**Origin ↔ S3:** TLS 1.2+ (AWS enforces). Requests signed with AWS Signature V4 (HMAC-SHA256 of the canonical request).

**Internal services:** mTLS via service mesh (Istio/Envoy). Each service has a cert issued by an internal CA (SPIFFE/SPIRE for workload identity). Certs rotate every 24 hours automatically.

### Encryption at Rest

**S3 objects:** SSE-KMS (Server-Side Encryption with AWS KMS). Each object is encrypted with a unique data encryption key (DEK). The DEK is encrypted with a KMS CMK (Customer Master Key). The CMK never leaves KMS. S3 never stores plaintext. Key rotation: KMS CMK rotates annually (or on-demand).

**PostgreSQL:** Transparent data encryption (TDE) via encrypted EBS volumes. Sensitive columns (if any) can use `pgcrypto` for field-level encryption.

**Redis:** Encrypted at rest (ElastiCache encryption enabled). In-transit encryption (TLS between app and Redis).

**Backup encryption:** RDS automated backups encrypted with the same KMS key. S3 lifecycle backups encrypted independently.

### Input Validation

**Filename sanitization (upload):**
```python
import unicodedata
import re

def sanitize_filename(filename: str) -> str:
    # Normalize unicode (prevent homoglyph attacks)
    filename = unicodedata.normalize('NFKC', filename)
    # Remove null bytes and control characters
    filename = re.sub(r'[\x00-\x1f\x7f]', '', filename)
    # Remove path components (path traversal)
    filename = os.path.basename(filename)
    # Remove leading dots (hidden files on Unix)
    filename = filename.lstrip('.')
    # Allowlist characters
    filename = re.sub(r'[^a-zA-Z0-9._\-\s]', '_', filename)
    # Truncate
    return filename[:255]
```

**File type validation (upload):**
- Don't trust `Content-Type` header (client-controlled).
- Read magic bytes (file header) to determine actual type.
- Only allow configured types: PDF, DOCX, XLSX, PNG, JPG, MP4, etc.
- Store content-type based on magic bytes, not user input.

**UUID validation (all IDs):**
```python
import uuid

def validate_uuid(value: str) -> bool:
    try:
        uuid.UUID(value, version=4)
        return True
    except ValueError:
        return False
```

**SQL injection prevention:** Parameterized queries everywhere. ORM doesn't guarantee safety if raw queries are used. Audit all raw SQL. Use `pg_stat_statements` to find unusual query patterns.

### Access Control

**Principle of Least Privilege:**
- The File API service's IAM role: `s3:GetObject` on `arn:aws:s3:::my-bucket/orgs/*` only. No `s3:ListBucket`, no `s3:DeleteObject` (those go to separate services).
- The Virus Scanner role: `s3:GetObject` only (read-only).
- The Upload Worker role: `s3:PutObject` only.
- Database users: `file_api_user` has `SELECT, INSERT, UPDATE` on specific tables. No `DELETE` (soft-delete only). No DDL.

**Network segmentation:** Application tier in private subnets. No direct internet access. Egress through NAT gateway (for outbound-only). Database in isolated subnet with no inbound from internet.

### Secrets Handling

**Secret storage:** AWS Secrets Manager or HashiCorp Vault. Never in environment variables (process list is readable by other processes). Never in code. Never in config files committed to Git.

**Secret injection:** At container startup, the entrypoint script fetches secrets from Secrets Manager and exports them to environment variables (in-memory only). The ECS task role has permission to call `secretsmanager:GetSecretValue` for specific secret ARNs.

**Secret rotation:** Database passwords rotate every 90 days (automated via Secrets Manager). API keys rotate on any suspicion of compromise. JWT signing keys: rotation procedure requires deploying new public key to JWKS endpoint, then rotating the private key, with a 5-minute overlap to allow in-flight tokens to remain valid.

**GitGuardian / truffleHog:** Run as pre-commit hook and in CI. Scans for patterns resembling API keys, passwords, private keys before they reach the repo.

---

## 8. Attack Surface Mapping

### All Entry Points

```
╔══════════════════════════════════════════════════════════════════════════╗
║                         ATTACK SURFACE MAP                              ║
╠══════════════════════════════════════════════════════════════════════════╣
║  EXTERNAL SURFACE (Internet-facing)                                     ║
║                                                                          ║
║  ┌─────────────────────────────────────────────────────────────────┐   ║
║  │  CDN EDGE (Highest exposure — receives all traffic)             │   ║
║  │                                                                  │   ║
║  │  Entry Points:                                                  │   ║
║  │  • HTTP/HTTPS on port 80/443 (file download endpoint)           │   ║
║  │  • DNS (GeoDNS manipulation, DNS hijacking)                     │   ║
║  │  • SNI (information leakage — hostname visible in TLS)          │   ║
║  │                                                                  │   ║
║  │  Attack Vectors:                                                 │   ║
║  │  • DDoS (volumetric, slowloris, HTTP flood)                     │   ║
║  │  • Cache poisoning (manipulate cached content)                  │   ║
║  │  • Cache deception (trick CDN into caching private responses)   │   ║
║  │  • TLS downgrade (force TLS 1.0 if misconfigured)               │   ║
║  │  • HTTP request smuggling (CDN ↔ Origin desync)                 │   ║
║  └─────────────────────────────────────────────────────────────────┘   ║
║                              │                                          ║
║                              ▼                                          ║
║  ┌─────────────────────────────────────────────────────────────────┐   ║
║  │  API LAYER (Filtered by CDN/WAF, but still exposed)             │   ║
║  │                                                                  │   ║
║  │  Entry Points:                                                  │   ║
║  │  • POST /api/upload/init                                        │   ║
║  │  • GET /api/files/:file_id (download)                           │   ║
║  │  • GET /api/files/:file_id/metadata                             │   ║
║  │  • DELETE /api/files/:file_id                                   │   ║
║  │  • GET /api/files (list, with pagination params)                │   ║
║  │  • POST /auth/login (credential submission)                     │   ║
║  │  • POST /auth/refresh                                           │   ║
║  │  • POST /auth/logout                                            │   ║
║  │                                                                  │   ║
║  │  Attack Vectors:                                                 │   ║
║  │  • IDOR (access another user's files by guessing IDs)           │   ║
║  │  • Broken auth (JWT alg=none, weak signing keys)                │   ║
║  │  • Rate limit bypass (IP rotation, header manipulation)         │   ║
║  │  • SQLi (if parameterized queries not used)                     │   ║
║  │  • Path traversal (in filename or file_id params)               │   ║
║  │  • File upload abuse (malware, polyglots, large files)          │   ║
║  │  • SSRF via filename redirect                                   │   ║
║  └─────────────────────────────────────────────────────────────────┘   ║
╠══════════════════════════════════════════════════════════════════════════╣
║  TRUST BOUNDARY: CDN → Origin                                           ║
║  (CDN IPs should be allowlisted at origin; CDN can be misconfigured)   ║
╠══════════════════════════════════════════════════════════════════════════╣
║  INTERNAL SURFACE (Private network — but not safe from insider threats) ║
║                                                                          ║
║  ┌─────────────────────────────────────────────────────────────────┐   ║
║  │  INTERNAL SERVICES                                               │   ║
║  │  • Permission Service (gRPC, mTLS) — IDOR if grantee_id not    │   ║
║  │    validated against caller's org                               │   ║
║  │  • Auth Service (JWKS endpoint) — key confusion attacks         │   ║
║  │  • Kafka (topic ACLs, consumer group isolation)                 │   ║
║  │  • Redis (no auth if misconfigured — lateral movement pivot)    │   ║
║  └─────────────────────────────────────────────────────────────────┘   ║
║                                                                          ║
║  ┌─────────────────────────────────────────────────────────────────┐   ║
║  │  DATA STORES                                                     │   ║
║  │  • PostgreSQL — SQL injection, privilege escalation              │   ║
║  │  • S3 — public bucket misconfiguration, pre-signed URL leakage  │   ║
║  │  • Secrets Manager — IAM over-permissioning                     │   ║
║  └─────────────────────────────────────────────────────────────────┘   ║
╠══════════════════════════════════════════════════════════════════════════╣
║  SUPPLY CHAIN SURFACE                                                   ║
║  • Docker base images (malicious packages)                             ║
║  • npm/pip dependencies (dependency confusion, typosquatting)          ║
║  • CI/CD pipeline (secret exposure in build logs)                      ║
║  • Third-party CDN provider (compromise of CDN control plane)          ║
╚══════════════════════════════════════════════════════════════════════════╝
```

### Trust Boundaries (Explicit)

| Boundary | From (Less Trusted) | To (More Trusted) | Control |
|---|---|---|---|
| TB-1 | Internet | CDN Edge | DDoS protection, TLS, WAF |
| TB-2 | CDN Edge | Origin API | IP allowlist, shared secret header, mTLS |
| TB-3 | API Server | Auth Service | mTLS, service-to-service JWT |
| TB-4 | API Server | S3 | IAM roles, VPC endpoint, bucket policy |
| TB-5 | API Server | PostgreSQL | DB credentials, SSL, network ACL |
| TB-6 | API Server | Redis | Redis AUTH, TLS, network ACL |
| TB-7 | Workers | S3/DB | Separate IAM roles (minimal permissions) |
| TB-8 | CDN Control Plane | CDN Edge | CDN provider's own auth (API keys) |

---

## 9. Attack Scenarios

### Scenario 1: Cache Deception Attack

**Attacker Assumptions:**
- Attacker has a valid account on the same platform.
- Victim is logged in and will click an attacker-crafted URL.
- The CDN is misconfigured: it strips query parameters from cache keys but caches based on path extension.

**Step-by-Step Execution:**

1. Attacker crafts a URL: `https://cdn.example.com/api/files/profile?attacker.css`
2. Attacker sends this URL to the victim (phishing, shared link, etc.).
3. Victim (authenticated) clicks the link. Their browser sends a GET request to the URL with their session cookie.
4. The CDN strips the query string from the cache key and looks up the cache for path `/api/files/profile` — cache miss.
5. CDN forwards to origin. Origin's router matches `/api/files/profile` (ignoring `?attacker.css`). The API returns the victim's private file listing as JSON, with auth headers `Cache-Control: private`.
6. **If CDN is misconfigured:** CDN sees the URL ends in `.css` and overrides `Cache-Control: private` with a cache-able policy (common CDN misconfig — some cache based on extension regardless of headers).
7. CDN stores the response in the cache under key `/api/files/profile?attacker.css`.
8. Attacker navigates to the same URL (unauthenticated). CDN returns the cached victim response.

**Where Detection Could Happen:**
- Anomalous cache HIT ratio on auth-required endpoints.
- CDN logs showing cache HITs for API paths.
- Rate of unique users receiving the same cached response for authenticated paths.

**Why This Works:**
- CDN extension-based caching rules override HTTP cache headers.
- Cache key does not include session information (correct for normal caching, fatal here).
- The response was cached with victim's data, served to attacker anonymously.

**Fix:** Explicitly configure CDN to never cache responses from `/api/*`. Only cache from `/static/*`, `/public/*`. Use Vary header correctly. Use `Cache-Control: no-store` unconditionally from API responses.

---

### Scenario 2: IDOR (Insecure Direct Object Reference)

**Attacker Assumptions:**
- Attacker has a valid account in org A.
- Target file belongs to org B.
- File IDs are UUIDs (random, not sequential) — but the attacker has obtained a valid file_id from org B (perhaps via a shared link, log leak, or brute-force of a short-lived presigned URL).

**Step-by-Step Execution:**

1. Attacker observes a file_id in their browser's network requests: `f_abc123` (their own org's file).
2. Attacker changes the file_id to `f_xyz789` (a file from org B, ID learned from a shared link).
3. Sends: `GET /api/files/f_xyz789` with their own valid JWT (org A user).
4. If the authorization check only validates "does the user have a READ permission record for this file" without cross-checking that the file belongs to the user's org: the query may return false (no explicit permission), but if there's a fallback or the query is wrong, access is granted.

**More likely failure mode:**
The permission check passes because org B accidentally granted "any authenticated user" access. Or the permission check is in the application but the S3 key is directly derived from the file_id, and the application generates a presigned URL without the org-isolation check.

**Step 4 (actual vulnerable code path):**
```python
# VULNERABLE: No org_id check
def get_file(file_id, user):
    file = db.query("SELECT * FROM files WHERE id = %s", file_id)
    if has_permission(user.id, file_id, 'READ'):  # Only checks permission table
        return generate_presigned_url(file.s3_key)
    raise Forbidden()
```

```python
# SECURE: Adds org isolation
def get_file(file_id, user):
    file = db.query(
        "SELECT * FROM files WHERE id = %s AND org_id = %s AND deleted_at IS NULL",
        file_id, user.org_id  # ← org boundary enforced at data layer
    )
    if not file:
        raise NotFound()  # Not Forbidden — don't leak file existence
    if has_permission(user.id, file_id, 'READ'):
        return generate_presigned_url(file.s3_key)
    raise Forbidden()
```

**Why Return 404 Instead of 403?**
If you return 403, you've confirmed the file exists, just that the user can't access it. This leaks existence. Return 404 for both "doesn't exist" and "exists but belongs to another org." The attacker learns nothing.

**Detection:** Anomalous pattern of 403/404 responses for file endpoints from a single user_id. Automated scanning behavior: sequential UUID enumeration (rare for UUIDs, but possible with leaked IDs).

---

### Scenario 3: JWT Algorithm Confusion (alg:none / RS256→HS256)

**Attacker Assumptions:**
- Attacker has a valid (now-expired or low-privilege) JWT.
- The application uses a library that accepts multiple algorithms or doesn't pin the algorithm.

**Step-by-Step Execution (alg:none):**

1. Attacker takes a valid JWT: `eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1XzEyMyIsInJvbGVzIjpbIm1lbWJlciJdfQ.{sig}`
2. Modifies the payload: changes `"roles": ["member"]` to `"roles": ["admin"]`.
3. Changes the header: `"alg": "none"`.
4. Sets the signature to empty string.
5. Sends: `eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1XzEyMyIsInJvbGVzIjpbImFkbWluIl19.`
6. If the library naively accepts `alg:none` and skips signature verification: attacker is now admin.

**RS256 → HS256 Confusion:**

1. The auth server's RSA public key is known (it's public — from JWKS endpoint).
2. Attacker creates a token signed with **HS256** using the **RSA public key as the HMAC secret**.
3. If the library auto-selects algorithm from the token header (instead of pinning to RS256): the server treats the RSA public key as an HMAC secret and successfully verifies the signature.

**Detection:** Unusual `alg` values in JWT headers (monitor for `none`, `HS256` where RS256 is expected). Failed signature verification attempts.

**Why This Works (historically):** JWT libraries before 2016 often auto-detected the algorithm. Pinning the algorithm on the verification side was not the default.

**Fix:**
```python
# ALWAYS pin the algorithm — never trust the header's alg claim
jwt.decode(token, public_key, algorithms=["RS256"])  # Only RS256 accepted
```

---

### Scenario 4: HTTP Request Smuggling (CDN ↔ Origin Desync)

**Attacker Assumptions:**
- CDN and origin interpret the HTTP/1.1 `Content-Length` and `Transfer-Encoding` headers differently.
- The system uses HTTP/1.1 between CDN and origin (common — HTTP/2 eliminates this, but CDN→origin is often HTTP/1.1).

**Step-by-Step:**

1. Attacker sends a single request to the CDN with both `Content-Length` and `Transfer-Encoding: chunked` headers — contradictory.
2. CDN interprets length via `Content-Length: 13` and forwards `\r\n0\r\n\r\nGET /admin...` as a full request body.
3. Origin strips `Content-Length`, processes via chunked encoding, sees `0\r\n\r\n` as end of first request body, then sees `GET /admin...` as the **beginning of a new request** — prepended to the next user's legitimate request.
4. The poisoned prefix (`GET /admin`) is prepended to the next victim's request. The origin sees it as: `GET /admin HTTP/1.1\r\nHost: example.com\r\n{victim's headers}` and serves admin content to the victim — or more cleverly, to the attacker who timed the next request.

**Detection:** Unusual `400 Bad Request` or `500` errors at origin for endpoints the CDN should have properly formed. Request timing anomalies. WAF detecting malformed chunked encoding.

**Fix:** Normalize all requests at the CDN (remove ambiguous headers). Use HTTP/2 for CDN→origin connections (eliminates the desync — HTTP/2 has unambiguous framing). Enable origin request normalization in CDN settings.

---

### Scenario 5: Presigned URL Leakage

**Attacker Assumptions:**
- The system uses Option A (presigned URL redirect) for file downloads.
- Presigned URLs have a 60-minute validity window.
- The URL is accessible to anyone who has it (no auth required by S3 — auth is in the URL signature).

**Step-by-Step:**

1. Legitimate user downloads a file. Their browser is redirected to: `https://my-bucket.s3.amazonaws.com/orgs/4421/files/abc123/report.pdf?X-Amz-Signature=...&X-Amz-Expires=3600`.
2. This URL appears in: browser history, HTTP referrer headers (if the user later visits another site), server-side logs at the user's ISP, corporate proxy logs, browser extensions, analytics platforms (if the redirect page fires analytics).
3. Attacker with access to any of these logs extracts the URL.
4. Attacker downloads the file directly from S3 using the URL — no authentication required.

**Why This Is a Real Problem:** Slack, GitHub, JIRA all use presigned URLs for attachments. They've all had leakage incidents. In 2022, a major SaaS provider had presigned URLs in their Support ticket system's HTML — accessible to all support agents, not just the file owner's account.

**Detection:** S3 server access logs showing downloads from unexpected IPs or geographies for the same presigned URL. Multiple distinct IPs accessing the same signed URL.

**Fix:**
- Short expiry (60 seconds, not 60 minutes).
- Use proxy mode (stream through origin) for sensitive files — no S3 URL ever reaches client.
- Use S3 VPC endpoints so presigned URLs can only be resolved within VPC (for internal-only files).
- Log all S3 presigned URL accesses with CloudTrail.

---

### Scenario 6: Malicious File Upload (Polyglot)

**Attacker Assumptions:**
- The system allows PDF uploads.
- The file is served back to other users (e.g., a shared document).
- The system validates content-type by magic bytes.

**Step-by-Step:**

1. Attacker creates a **polyglot file**: a file that is simultaneously a valid PDF and a valid JavaScript file (or HTML file). This is possible because PDF structure allows arbitrary data before the `%PDF-1.x` header is optional in many PDF parsers — or because the polyglot is crafted as `%PDF-1.4\n...{PDF content}...<!--{HTML+JS}-->`.
2. Attacker uploads the file. Magic byte check sees `%PDF` — passes.
3. The file is stored in S3 as `content-type: application/pdf`.
4. When a user downloads and the browser opens it, the browser's PDF renderer handles it correctly.
5. **However**: If the file is served with `Content-Type: text/html` (misconfigured, or served from a domain that shares cookies), the browser renders it as HTML and executes the embedded JavaScript.
6. The JS exfiltrates session cookies (if not HttpOnly) or performs CSRF actions.

**Another vector:** A malicious PDF exploiting PDF renderer vulnerabilities (CVE-style — PDF parsers have had many RCE bugs). The attacker uploads a weaponized PDF, a victim opens it in their browser's built-in PDF reader, RCE occurs.

**Detection:** Antivirus scan would catch known malware. Behavioral detection (sandbox execution of uploaded files) catches novel malware. Content Security Policy prevents JS execution if misconfigured.

**Fix:**
- Serve user-uploaded files from an **isolated domain** (`user-content.example.com`) that shares no cookies with `example.com`. This prevents cookie theft even if XSS occurs.
- Set `Content-Disposition: attachment` (force download, don't render in browser).
- Set `X-Content-Type-Options: nosniff` (prevents browser MIME-sniffing).
- Re-encode/transcode uploaded files (convert PDF→PDF via a PDF library — strips embedded active content, breaks polyglots).
- Run in a sandbox (AWS Lambda + LibreOffice headless to re-render PDFs — output is a clean PDF).

---

## 10. Failure Points

### Under Load

**CDN origin shield overwhelmed:** When CDN cache hit rate drops (large file set, many unique files, bust of cache by deployment), all requests miss and slam the origin. Origin can't keep up. This is called a **cache stampede** or **thundering herd**.

Specifically: 1000 users simultaneously request a popular file that just expired from cache. All 1000 requests go to origin simultaneously. Origin does 1000 DB reads, 1000 S3 fetches. If each takes 200ms, origin queues fill, latency spikes, timeouts start.

**Fix:** **Request coalescing (also called request collapsing):** CDN holds the first request that misses, queues the other 999, serves them all from the single origin response. All major CDNs support this. At origin: stale-while-revalidate (serve stale content while fetching fresh — for non-auth content).

**Database connection exhaustion:** Each application server process holds a connection pool (e.g., pgBouncer with 10 connections per process). Under high load, all connections are busy. New requests queue. Queue fills. Requests fail with 503.

**Fix:** PgBouncer in transaction-pooling mode. Connection pool per service, not per process. Alert on connection pool saturation.

**Redis memory exhaustion:** If Redis is used without an eviction policy and fill up, writes fail. All operations that try to write rate-limit counters or session data will error. The application must handle this gracefully (fail open or fail closed — design decision).

**S3 throttling (prefix hot-spots):** S3 has per-prefix TPS limits (3,500 PUT/POST/DELETE, 5,500 GET per second per prefix). If all files are stored under a single prefix (`/files/{file_id}`), you're limited to 5,500 downloads/second across the entire bucket. Distributing files across a hashed prefix structure (`/{hash[0:2]}/{hash[2:4]}/{file_id}`) spreads load across S3 partitions.

### Under Attack

**DDoS:** Volumetric attacks (UDP floods, amplification via DNS/NTP) are absorbed by CDN anycast network. HTTP floods (Layer 7) are harder — they complete valid TLS handshakes and send valid requests, consuming CPU on the origin. CDN rate limiting and challenge pages (CAPTCHA, JS challenge) mitigate but don't eliminate.

**Credential stuffing:** Automated login attempts with breached credential lists. If no rate limiting or MFA: accounts are compromised. Signature: high volume of login requests, geographically distributed, low success rate.

**Token farming (presigned URL abuse):** Attacker with a compromised account bulk-generates presigned URLs, sells them. Signature: one user generating hundreds of presigned URLs rapidly.

### Common Misconfigurations

| Misconfiguration | Impact | Detection |
|---|---|---|
| S3 bucket public | All files publicly accessible | AWS Config rule, S3 Block Public Access |
| CDN caching auth responses | Private data served to wrong user | CDN cache HIT rate on auth endpoints |
| JWT `alg:none` accepted | Token forgery | Any JWT with `alg:none` in production |
| `X-Forwarded-For` trusted blindly | IP-based rate limits bypassable | Requests with spoofed XFF headers |
| TLS 1.0/1.1 enabled | POODLE, BEAST, downgrade attacks | TLS version in access logs |
| CORS `*` on download endpoint | Any origin can trigger download | OPTIONS response headers |
| Missing Content-Disposition | Files render in browser | Inspect response headers |
| Redis no auth | Lateral movement, data theft | Redis INFO auth stats |
| Debug endpoints exposed | Info leakage (stack traces, configs) | /debug, /metrics, /actuator, /__debug__ |
| Secrets in env vars | Container escape = secret exposure | Secret scanning in container images |

---

## 11. Mitigations

### Defense-in-Depth Strategy

The goal: no single failure should result in a breach. Each layer should assume the previous layer was compromised.

**Layer 1 — CDN/Network (Perimeter)**
- DDoS protection: CDN handles volumetric, WAF handles application-layer.
- WAF rules: OWASP Core Rule Set + custom rules for this application.
- Rate limiting: IP-based (100 req/min), token-based (1000 req/min per user), endpoint-specific (10 login attempts/min per IP).
- Geo-blocking: If the business doesn't operate in certain countries, block at CDN (reduces attack surface, not a security control on its own).
- Bot management: Behavioral fingerprinting to detect automated tools (headless browsers, curl patterns).

**Layer 2 — API Gateway**
- IP allowlist: Only accept traffic from known CDN CIDR ranges (CloudFront publishes these). Direct-to-origin attempts rejected.
- Shared secret header: CDN adds `X-CDN-Secret: {rotating_secret}` to all forwarded requests. Origin validates this. Prevents bypassing CDN by hitting origin directly.
- Request size limits: Max 100MB for uploads to init endpoint. Max 4KB for JSON bodies.
- Timeout: 30-second request timeout. Prevents slowloris at origin.

**Layer 3 — Application**
- Authentication: JWT RS256, pinned algorithm, short expiry, revocation tracking.
- Authorization: Per-request ACL check, org isolation, least privilege.
- Input validation: Strict allowlisting, not denylisting.
- Parameterized queries: Zero raw string interpolation.
- Output encoding: JSON encoder handles special characters.
- Error handling: Generic error messages to client, detailed errors to internal logs only.

**Layer 4 — Data**
- Encryption at rest: SSE-KMS with CMK rotation.
- Encryption in transit: TLS everywhere, mTLS internal.
- Backup encryption: Separate key from production.
- Soft delete: 30-day window to recover accidentally deleted files.
- Immutable audit log: Kafka → S3 (with Object Lock — WORM) for tamper-proof audit trail.

**Engineering Tradeoffs:**

| Control | Security Gain | Cost / Tradeoff |
|---|---|---|
| mTLS internal | Prevents MITM between services | Cert rotation complexity, debugging harder |
| Short JWT TTL (15min) | Limits damage from token theft | More refresh requests, worse UX |
| Proxy mode (stream through origin) | Full audit, no presigned URL leak | 2x bandwidth cost, higher origin load |
| Re-encode uploaded files | Eliminates polyglot malware | Slow, may alter file metadata |
| fail-closed on Redis down | Protects data | Availability impact during Redis failure |
| Separate upload domain | Prevents cookie theft from uploaded content | Additional domain, TLS cert to manage |

---

## 12. Observability

### Logs

**What to log (structured JSON, all fields indexed):**

```json
{
  "timestamp": "2025-05-15T10:23:45.123Z",
  "level": "INFO",
  "service": "file-api",
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "user_id": "u_123",
  "org_id": "org_4421",
  "method": "GET",
  "path": "/api/files/f_abc123",
  "status": 200,
  "duration_ms": 87,
  "file_id": "f_abc123",
  "bytes_served": 4194304,
  "cdn_pop": "MUM-01",
  "client_ip": "203.0.113.5",
  "user_agent": "Mozilla/5.0...",
  "cache_status": "MISS",
  "s3_duration_ms": 45,
  "db_duration_ms": 12,
  "auth_duration_ms": 3,
  "perm_cache_hit": true
}
```

**What NOT to log:**
- JWT tokens (even partial — hash them if you need to trace a specific token).
- Passwords or credential values.
- Full file content.
- PII beyond what's necessary for audit (consider GDPR — log user_id, not email).
- Request bodies containing sensitive data (use selective field logging).

**Log levels and routing:**
- `ERROR`: Application errors, unexpected exceptions → PagerDuty alert.
- `WARN`: Recoverable issues (cache miss after retry, slow DB query) → Datadog monitor.
- `INFO`: All request completions → Datadog / Elasticsearch.
- `DEBUG`: Disabled in production. Can be toggled per-request via feature flag.

**Audit logs (separate pipeline):** Every auth event (login, logout, token refresh, failed auth), every file access (download, upload, delete, share), every permission change → immutable Kafka topic → S3 with Object Lock. Cannot be deleted by any application process. Retained for 7 years (regulatory compliance).

### Metrics

**Golden Signals (per service, per endpoint):**

| Metric | Type | Alert Threshold |
|---|---|---|
| Request rate (rps) | Counter | > 2x baseline (sudden spike) |
| Error rate (4xx, 5xx) | Gauge | 5xx > 1% over 5min |
| Latency p50, p95, p99 | Histogram | p99 > 2000ms |
| Cache hit rate | Gauge | < 60% for static content |
| Auth failures | Counter | > 100/min per IP |
| Active DB connections | Gauge | > 80% of pool |
| Redis memory usage | Gauge | > 80% of max |
| S3 request errors | Counter | > 0 for 5xx class |
| Kafka consumer lag | Gauge | > 1000 messages |

**What should NOT alert:**
- Normal 404s (user typos, bots scanning).
- 401s from users with expired tokens (normal after timeout).
- Cache misses on first request to a new file.
- Individual slow DB queries (alert on P99, not individual events).

### Traces

**Distributed tracing (OpenTelemetry / Jaeger / Datadog APM):**

Every request carries a trace ID (`X-Trace-ID` header, propagated internally). Each service creates a span:

```
[Trace ID: abc123]
  [Span: CDN Edge] 0ms - 5ms
    [Span: Origin API] 5ms - 92ms
      [Span: Auth validate JWT] 5ms - 8ms
      [Span: Redis perm lookup] 8ms - 9ms    ← cache HIT
      [Span: DB file metadata] 9ms - 21ms
      [Span: S3 generate presigned URL] 21ms - 21ms  ← local operation
      [Span: Response write] 21ms - 92ms     ← streaming bytes
```

Traces help diagnose: "Why is p99 high?" — Look at the slowest traces. Which span is slow? DB? S3? Auth? This is impossible with metrics alone.

**Sampling:** 100% trace sampling in dev, 10% in production (reduced to 1% under load). Always sample errors (100%). Always sample slow requests (> 500ms).

### Alerting Philosophy

**Page (wake someone up):**
- 5xx error rate > 5% for > 2 minutes.
- Complete service unavailability (health check failing).
- Auth service down.
- Database unreachable.
- Security event: mass auth failure (credential stuffing detected).

**Ticket (fix next business day):**
- p99 latency > 1 second sustained.
- Cache hit rate below 50%.
- Kafka consumer lag > 5000 (audit log behind).
- Certificate expiry < 30 days.
- Disk usage > 80% on any host.

**Log only (don't alert):**
- Individual 4xx errors.
- Single slow DB queries.
- Individual presigned URL fetches from CDN.

---

## 13. Scaling Considerations

### Bottlenecks and Where They Appear First

**Under increased read load (downloads):**

1. **CDN edge** scales automatically (CDN providers have essentially unlimited capacity). Not a bottleneck.
2. **CDN→Origin bandwidth** becomes a bottleneck when cache miss rate is high (new files, expired cache). Origin link becomes saturated.
3. **API server** CPU (auth validation, JWT verification, presigned URL signing). Horizontal scaling: add more instances behind the load balancer. Stateless services scale trivially.
4. **Permission Service + Redis**: Redis is typically single-threaded per instance. Under extreme load, Redis CPU becomes the bottleneck. Solution: Redis Cluster (shards permissions by file_id hash). Or: in-process permission cache (LRU, 30-second TTL) to reduce Redis calls.
5. **PostgreSQL**: Read replicas for ACL checks. Primary for writes. Read queries routed to replicas via PgBouncer. Under extreme load, connection pooling and read replicas are the answer. Eventually: sharding (shard by org_id — each shard owns a subset of orgs).
6. **S3**: Rarely a bottleneck (S3 scales to millions of requests/second at the bucket level with proper prefix distribution). Can be bottleneck if prefix is hot.

**Under increased write load (uploads):**

1. API server: scales horizontally.
2. S3 uploads: direct client→S3 via presigned URL — origin not involved. S3 handles the bandwidth.
3. Virus scan workers: must scale to match upload rate. This is the first bottleneck. Workers consume from SQS — adding more worker instances scales scan throughput linearly.
4. PostgreSQL writes: bulk upload events can saturate the primary. Solution: batch inserts, write-ahead log tuning, or async writes through a queue.

### Horizontal vs Vertical Scaling

| Component | Horizontal | Vertical | Notes |
|---|---|---|---|
| API servers | ✅ Trivial (stateless) | ✅ Easy | Prefer horizontal |
| CDN | ✅ Automatic | N/A | CDN handles this |
| Redis | ✅ Cluster mode | ✅ Bigger instance | Cluster for write throughput, vertical for read |
| PostgreSQL primary | ⚠️ Complex (sharding) | ✅ Up to a point | Vertical first, then read replicas, then sharding |
| PostgreSQL reads | ✅ Read replicas | ✅ | Both — read replicas preferred |
| S3 | ✅ Automatic | N/A | AWS manages |
| Kafka | ✅ Add partitions, brokers | ✅ | Both |
| Virus scanner | ✅ Add workers | ⚠️ | Horizontal preferred |

### Consistency Tradeoffs

**Permission cache (Redis, 5-min TTL):** A user's permission is revoked (admin removes access). For up to 5 minutes, the user can still download the file because their permission is cached as `{READ: true}`. This is **eventual consistency for authorization** — a deliberate tradeoff for performance.

If this is unacceptable (medical records, financial documents), options:
- Reduce TTL to 30 seconds (more DB load, near-real-time revocation).
- Use Redis pub/sub to invalidate specific cache entries on revocation (complex, but immediate).
- Use no cache for high-sensitivity files (always DB check — highest DB load).

**Session revocation:** When a user is forcibly logged out (admin action, account compromise), their JWT remains valid until expiry. If TTL is 15 minutes, the user has a 15-minute window. Check JTI against a Redis revocation list on every request for immediate revocation (adds one Redis read per request — ~1ms).

**Audit log delivery:** Kafka is at-least-once. If a consumer crashes after consuming a message but before writing to PostgreSQL, the message will be redelivered. The consumer must be **idempotent** (use `event_id` as an upsert key to avoid duplicate audit records).

---

## 14. Interview Questions

### Q1: Walk me through what happens when a CDN cache miss occurs for a private, authenticated file. What are all the systems involved, and what could go wrong?

**Why asked:** Tests depth of understanding of CDN-origin interaction, auth flow, and failure modes.

**Answer direction:** CDN forwards to origin (with X-Forwarded-For), origin validates JWT, checks ACL, fetches metadata from DB, generates presigned URL or proxies S3 bytes. Failures: origin overloaded (cache stampede), DB slow (permission lookup), S3 throttled, JWT expired mid-request, presigned URL window expires before client uses it.

---

### Q2: A user complains that after an admin revoked their file access, they could still download the file for several minutes. How would you debug this, and what are the architectural causes?

**Why asked:** Tests understanding of caching layers and consistency tradeoffs.

**Answer direction:** Multiple caching layers: CDN edge cache (has the response cached? but should be Cache-Control: private), Redis permission cache (5-min TTL → permission still cached as ALLOW), application-level in-process cache. Debug by checking cache TTLs at each layer, tracing the request_id, checking Redis key expiry. Fix: implement cache invalidation on permission revocation events, or reduce TTL.

---

### Q3: How would you prevent an attacker from brute-forcing file IDs, even if they're UUIDs?

**Why asked:** Tests understanding of IDOR, UUID entropy, and layered controls.

**Answer direction:** UUIDs v4 are 122 bits of entropy — brute force is computationally infeasible. But the real risk is: file IDs leaked via referrer headers, logs, shared links, or scan of web responses. Mitigations: return 404 (not 403) for unauthorized files, rate limit download attempts per user, use org isolation in queries (so cross-org file_ids never hit the ACL check), monitor for access pattern anomalies (user accessing many file_ids they didn't create).

---

### Q4: Explain HTTP request smuggling. How could it affect this file delivery system, and how would you test for it?

**Why asked:** Tests advanced HTTP knowledge, CDN-origin interaction understanding.

**Answer direction:** CL.TE vs TE.CL desync between CDN and origin. An attacker could prepend a malicious request fragment to another user's request. In this system: could be used to hijack another user's file download request, or inject headers (like X-Forwarded-For) to bypass IP-based controls. Test: use `smuggler.py` or Burp Suite's HTTP Request Smuggler extension. Fix: use HTTP/2 for CDN→Origin (eliminates the problem), enable strict mode on origin HTTP server.

---

### Q5: What happens to in-flight downloads if you deploy a new version of the File API service with rolling restart? How do you ensure zero data loss and zero broken downloads?

**Why asked:** Tests deployment and operational knowledge.

**Answer direction:** Rolling restart: old pods die while new ones come up. In-flight streaming downloads on old pods will be interrupted when the pod dies. Fix: connection draining — on SIGTERM, the load balancer stops sending new connections to the dying pod, existing connections are allowed to finish (grace period of 60–120 seconds). For very large files, even 120 seconds may not be enough. Solution: redirect mode (client downloads from S3 directly) — the origin pod only generates the presigned URL, so pod restart doesn't interrupt the transfer.

---

### Q6: A security researcher reports that they can access files by manipulating the `X-Forwarded-For` header to bypass IP-based rate limiting. How does this work, and how do you fix it?

**Why asked:** Tests understanding of header trust and proxy chains.

**Answer direction:** If the application trusts the X-Forwarded-For header to determine client IP, an attacker can set `X-Forwarded-For: 127.0.0.1` or any IP to bypass IP-based rate limits. Fix: at the CDN/Load Balancer, overwrite (not append) X-Forwarded-For with the real client IP. The application should only trust the leftmost IP in the chain up to the number of trusted proxies. Use `CF-Connecting-IP` (Cloudflare) or equivalent CDN header that cannot be spoofed by clients.

---

### Q7: You need to serve a 10GB video file to 100,000 simultaneous users. Walk me through the architecture and where each component breaks down.

**Why asked:** Tests real-scale reasoning.

**Answer direction:** CDN cache is essential — the file must be cached at edge PoPs. With 100K users: CDN handles download bandwidth (CDNs are built for this). The challenge is: first request populates cache (one origin hit per PoP), so cache warm-up may result in 50–200 simultaneous origin requests (one per PoP). S3 can handle this. For authenticated video: use HLS/DASH chunked streaming — each chunk is a separate cacheable request with its own auth (signed cookie covering a path prefix). Never proxy a 10GB file through origin — it saturates bandwidth. The byte-range / CDN chunking approach: CDN fetches the file in chunks from S3 (using Range requests) and caches each chunk independently.

---

### Q8: How would you implement file-level encryption where even the storage provider (AWS/S3) cannot read the files?

**Why asked:** Tests cryptographic depth and client-side encryption.

**Answer direction:** Client-side encryption (CSE): the browser/client encrypts the file before upload using a key derived from the user's password (or a key stored in a key management service the cloud provider can't access). S3 stores ciphertext. The origin API never sees plaintext. Key management: use a dedicated KMS that the client controls (or use the Web Crypto API in the browser to encrypt with a key derived from a user passphrase, never sent to the server). The tradeoff: no server-side processing (no virus scanning, no thumbnail generation, no full-text search) because the server only ever sees ciphertext. This is a significant architectural constraint.

---

### Q9: What is cache deception, and write me a specific test case for it against this system.

**Why asked:** Tests web security depth.

**Answer direction:** Cache deception tricks the CDN into caching a private, user-specific response. Test case: 1) Login as User A. 2) Navigate to `https://cdn.example.com/api/files/list.css` (the CDN might cache this because of the `.css` extension). 3) Open an incognito browser (no cookies). 4) Navigate to the same URL. 5) If you see User A's file list: the attack succeeded. What to check in the CDN config: are extension-based cache rules overriding `Cache-Control: private`? The fix: configure CDN to respect Cache-Control headers unconditionally, or set up path-based cache rules that explicitly `no-cache` all `/api/*` paths.

---

### Q10: Walk me through how you'd design the JWT key rotation for this system with zero downtime.

**Why asked:** Tests understanding of key management, zero-downtime deployments.

**Answer direction:** The JWKS endpoint publishes multiple keys simultaneously. Rotation procedure: 1) Generate new key pair (kid=`key-2025-06`). 2) Publish both old (`key-2025-01`) and new key to JWKS endpoint — both valid simultaneously. 3) Services caching JWKS will re-fetch when they see an unknown `kid` in an incoming token. 4) Configure auth server to sign NEW tokens with the new key immediately. 5) Existing tokens signed with `key-2025-01` remain valid until their `exp`. 6) After all old tokens expire (max 15 minutes), remove `key-2025-01` from JWKS. Zero downtime: achieved by the overlap period. If step 6 happens before all old tokens expire, users with valid old tokens get 401 — this is the mistake to avoid.

---

### Q11: You're seeing a spike in 403 errors at 3 AM with source IPs from 50 different countries. What's your incident response?

**Why asked:** Tests both technical analysis and security incident handling.

**Answer direction:** Likely credential stuffing or IDOR scanning. Immediate: check if it's targeting auth endpoints (credential stuffing) or file endpoints (IDOR scan). Check rate limiting — is it kicking in or being bypassed? Look at the user agents (might be identical — botnet). Check if any successful 200s are in the same traffic. If yes: active compromise. Immediate actions: enable CAPTCHA/JS challenge at CDN, block ASNs (Tor exit nodes, cloud hosting ranges used by botnets), force-rotate tokens for affected accounts. Post-incident: implement IP reputation scoring, velocity checks per user_id across IPs, add honeypot file IDs to trigger alerts when accessed.

---

### Q12: What's the difference between encrypting at the CDN layer vs encrypting at the application layer, and when would you use each?

**Why asked:** Tests understanding of encryption boundaries and threat models.

**Answer direction:** CDN-layer encryption (TLS termination at CDN edge): protects data in transit between client and CDN. The CDN decrypts and re-encrypts for the CDN→origin leg. This means the CDN provider can see your data in plaintext. Threat model: protects against network eavesdroppers; does NOT protect against a compromised CDN provider. Application-layer (end-to-end) encryption: data is encrypted at the client, decrypted only at the final recipient. The CDN and origin API never see plaintext. Protects against CDN provider, origin server compromise. But breaks: CDN caching (can't cache ciphertext that varies per user), server-side processing, WAF inspection. For most systems: CDN TLS termination is acceptable (you trust your CDN provider contractually). For highly sensitive data (medical, legal, financial): consider envelope encryption with client-held keys.

---

*Document Version: 1.0 | Last Updated: May 2026 | Classification: Internal Engineering*
