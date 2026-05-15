# Image Processing Pipeline: Deep Engineering & Security Breakdown

> **Document Type:** Internal Engineering / Security Reference  
> **Classification:** Internal — Engineering & Security Teams  
> **Scope:** End-to-end system analysis — packets to pixels, trust boundaries to attack trees  
> **Audience:** Engineers, security reviewers, interview candidates  

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

### The Story: "Upload Profile Photo"

This is a concrete example: a user uploads a 4MB JPEG profile photo on a SaaS platform. The pipeline must validate, resize, strip metadata, store, and serve the image via CDN — while blocking malicious uploads, enforcing quotas, and maintaining availability.

---

### Step-by-step Sequence

**T=0ms — User selects a file in the browser**

The user clicks "Upload Photo" and selects `selfie.jpg` (4.2 MB) from their filesystem. The browser calls `FileReader.readAsArrayBuffer()` on the selected file. The file is read entirely into browser memory (RAM, not disk). No network traffic yet. The browser checks the file's MIME type from the OS file extension — **not from the file's actual bytes**. This is important: the browser's declared MIME type cannot be trusted.

**T=5ms — JavaScript pre-validation (client-side)**

A JavaScript handler fires `change` on the `<input type="file">` element. The client-side code does:
- File size check: `file.size > MAX_UPLOAD_BYTES` — rejects if oversized
- Extension whitelist: checks `.jpg`, `.png`, `.gif`, `.webp`
- (Optional) Image dimension pre-check: draws to a canvas, reads width/height

This is a UX affordance only. **It is not a security control.** Any of this can be bypassed by a malicious client.

**T=10ms — Browser constructs the HTTP request**

JavaScript calls `fetch('/api/v1/upload', { method: 'POST', body: formData })`. The browser:
1. Resolves DNS for the apex domain (likely cached — see §2)
2. Reuses an existing TLS/HTTP2 connection if one is open (connection pool)
3. Constructs a `multipart/form-data` request body with a boundary string
4. Adds session cookie or Authorization header from browser storage
5. Adds `Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxk...`

The 4.2 MB file is segmented into TCP segments and streamed over the wire.

**T=10ms–150ms — Network transit**

Packets travel from the user's machine to the CDN/load balancer edge. If the connection already exists (HTTP/2 multiplexed), there's no new handshake cost. If it's a fresh connection, ~50–120ms for TLS 1.3 (1-RTT). The raw bytes of the JPEG travel across the internet, segment by segment. Each TCP segment is ~1460 bytes (MSS). A 4.2MB file = ~2,877 segments at minimum. At any network hop, segments can be reordered; the OS TCP stack reassembles them.

**T=150ms — API Gateway receives request**

The load balancer (e.g., AWS ALB or nginx) terminates TLS. It decrypts the traffic. The raw HTTP request — headers + multipart body — is now in plaintext inside the datacenter/VPC. The LB applies routing rules (path-based), sends request to the Upload API service on an internal port.

**T=155ms — Upload API: request parsing begins**

The upload service receives the raw HTTP stream. It does NOT buffer the entire 4MB into memory immediately. It uses streaming multipart parsing (e.g., `busboy` in Node.js or `python-multipart`). It:
1. Reads headers (Content-Type boundary), extracts field names
2. Begins streaming the file bytes to a temporary location (temp file on disk or directly to object storage via streaming PUT)
3. Applies size limits mid-stream — if the stream exceeds `MAX_SIZE`, it aborts and returns `413 Payload Too Large`

This stream approach is critical: it prevents memory exhaustion from large uploads.

**T=155–400ms — Authentication & authorization check**

Before storing anything, the service validates:
1. JWT/session token (extracted from `Authorization` header or `Cookie`)
2. Checks user identity from token claims
3. Checks upload quota from Redis: `GET quota:user:{userId}` — has this user exceeded their limit?
4. Checks RBAC: is this user allowed to upload images?

If any check fails, the in-progress upload stream is aborted, the temp file is deleted, and an error is returned. **Auth must happen before significant resource consumption.** Some systems incorrectly authenticate after the full upload — that allows unauthenticated large uploads to exhaust disk.

**T=400ms — File lands in temporary staging location**

After streaming completes, the file is fully written to a staging area:
- `s3://uploads-staging/{userId}/{uuid}.tmp` (AWS)
- OR `/tmp/{uuid}` on the upload pod's local disk (riskier)

The upload service emits a message to an async processing queue:
```
Queue: image-processing-jobs
Message: { jobId, userId, stagingKey, originalFilename, declaredMimeType, uploadedAt }
```

The service responds to the user with `202 Accepted` and a `jobId`. The user's browser receives this response and shows a "Processing..." state. **The image is not yet ready.** The user does not wait for processing — this is async.

**T=400ms — Image processing worker picks up the job**

A pool of worker processes (e.g., Celery workers, AWS Lambda, or k8s Job pods) pulls from the queue. One worker claims the job. It fetches the staged file from object storage.

Worker actions in sequence:
1. **Magic byte validation**: Read first 16 bytes — confirm file signature matches declared type. JPEG must start with `FF D8 FF`. PNG: `89 50 4E 47`. If mismatch → reject.
2. **Safe image parsing**: Load image through a hardened parser (e.g., libvips, ImageMagick with strict policy, or a sandboxed process). This is where polyglot file attacks and decompression bombs are detected.
3. **Metadata stripping**: Remove all EXIF data (GPS coordinates, device info, software versions). Rebuild image from raw pixels — this is the only safe way to guarantee clean metadata.
4. **Dimension validation**: Reject images with pathological dimensions (e.g., 1px wide × 500,000px tall — valid JPEG, causes memory explosions in naive parsers).
5. **Variant generation**: Resize to required output sizes (e.g., 48×48 thumbnail, 256×256 medium, 1024×1024 large). Each variant is a separate file.
6. **Re-encoding**: Re-encode as WebP or JPEG with defined quality settings. This rebuilds the binary from decoded pixel data — it's the nuclear option for sanitization.
7. **Upload variants to final storage**: `s3://media-cdn/{userId}/profile/{size}.webp`
8. **Update database**: Write final URLs to user profile record
9. **Invalidate CDN cache**: If user had a previous profile photo, send cache purge to CDN
10. **Emit completion event**: Publish to `image-processing-complete` topic

**T=1500ms–4000ms — Processing complete**

The frontend polls `GET /api/v1/jobs/{jobId}` or receives a WebSocket push notification. It fetches the new image URL and updates the UI. The image is now served from the CDN edge, not the origin. First request to CDN causes an origin fetch. Subsequent requests are served from edge cache. Latency drops from ~150ms (origin) to ~10ms (edge).

**What the user sees vs. what actually happens:**

```
User sees:                          What actually happens:
─────────────────────────────────   ──────────────────────────────────────────────
"Uploading..." progress bar         TCP stream of 4.2MB in ~2877 segments
"Processing..." spinner             Worker: magic bytes, libvips decode, EXIF strip,
                                    resize, re-encode, 3 variant writes to S3
"Upload complete!" + new photo      CDN cache populated, DB record updated,
                                    job record marked complete, WebSocket push sent
```

---

## 2. Network Layer Flow

### DNS Resolution

Before a single byte of image data moves, the browser must resolve the hostname to an IP address.

**Resolution sequence:**

```
Browser                OS Resolver         Recursive Resolver       Authoritative NS
   │                       │                      │                        │
   │──DNS query (cached?)──▶│                      │                        │
   │◀──cache miss───────────│                      │                        │
   │                       │──query 8.8.8.8:53────▶│                        │
   │                       │                      │──query root NS──────────▶│
   │                       │                      │◀─TLD NS address──────────│
   │                       │                      │──query TLD NS───────────▶│
   │                       │                      │◀─authoritative NS addr───│
   │                       │                      │──query auth NS──────────▶│
   │                       │                      │◀─A record: 203.0.113.10──│
   │◀──IP: 203.0.113.10────│◀─────────────────────│                        │
```

**Key mechanics:**
- **TTL matters**: A TTL of 60s means during a failover event, clients hold stale IPs for up to 60 seconds. For image upload endpoints, a TTL of 60–300s is typical.
- **DNS over HTTPS (DoH)**: Modern browsers bypass the OS resolver entirely and query a DoH server (Cloudflare 1.1.1.1 or Google 8.8.8.8) over HTTPS. This defeats local DNS-based filtering.
- **Negative caching**: NXDOMAIN responses are cached for the negative TTL. A DNS misconfiguration that briefly returns NXDOMAIN can have cascading effects lasting minutes.
- **Geographic routing**: The authoritative NS may return different A records based on the client's IP (Anycast/GeoDNS). The CDN edge closest to the user is returned.

---

### TCP 3-Way Handshake

```
Client (user)                    Server (LB/CDN edge)
    │                                    │
    │──SYN (seq=x) ──────────────────────▶│  Client initiates
    │◀── SYN-ACK (seq=y, ack=x+1) ────────│  Server acknowledges, sends own seq
    │──ACK (ack=y+1) ────────────────────▶│  Connection established
    │                                    │
    │  [TLS handshake begins here]       │
```

**What each flag carries:**
- `SYN`: Client's initial sequence number (ISN), chosen randomly (OS-level randomization). SYN packets are the primary vector for SYN flood attacks.
- `SYN-ACK`: Server's ISN + ack of client's ISN+1. Server allocates a half-open connection entry. Under SYN flood, these entries fill the backlog queue.
- `ACK`: Completes the handshake. Connection moves from `SYN_RCVD` to `ESTABLISHED`.

**Latency contribution:** One full RTT. For a client 50ms away from the server, this costs 50ms. With TLS on top, add another 0.5–1 RTT (TLS 1.3) or 1–2 RTT (TLS 1.2).

---

### TLS Handshake (TLS 1.3)

TLS 1.3 reduces the handshake to 1-RTT (vs. 1.3's 2-RTT). 0-RTT is possible for resumed sessions but carries replay risks.

```
Client                                      Server
  │                                            │
  │── ClientHello ─────────────────────────────▶│
  │   [TLS version, supported cipher suites,    │
  │    key_share (client public key for ECDHE), │
  │    SNI (server name: upload.example.com)]   │
  │                                            │
  │◀── ServerHello ─────────────────────────────│
  │   [chosen cipher: TLS_AES_256_GCM_SHA384,   │
  │    server's ECDHE public key,               │
  │    session ticket for resumption]           │
  │◀── Certificate ─────────────────────────────│
  │   [server's X.509 cert chain]               │
  │◀── CertificateVerify ───────────────────────│
  │   [signature over handshake transcript]     │
  │◀── Finished ────────────────────────────────│
  │   [HMAC of entire handshake]                │
  │                                            │
  │── [Client derives session keys via HKDF] ──│
  │── Finished ────────────────────────────────▶│
  │   [HMAC of entire handshake]                │
  │                                            │
  │══ Encrypted application data begins ════════│
```

**Key details:**
- **ECDHE key exchange**: Both sides generate ephemeral Diffie-Hellman keypairs (e.g., X25519 curve). The shared secret is derived without the private key ever crossing the wire. This provides **Perfect Forward Secrecy (PFS)** — compromise of the server's long-term private key does NOT decrypt past sessions.
- **Certificate validation**: Client checks: (1) cert chain terminates at a trusted root CA, (2) hostname matches the SAN in the cert, (3) cert is not expired, (4) cert is not revoked (OCSP/CRL — often skipped or soft-failed, a known weakness).
- **Cipher suite `TLS_AES_256_GCM_SHA384`**: AES-256-GCM for AEAD encryption (confidentiality + integrity), SHA-384 for the HMAC-based PRF.
- **SNI exposure**: The server name (SNI) in `ClientHello` is **unencrypted** in TLS 1.2. TLS 1.3 with ECH (Encrypted Client Hello) hides it. Without ECH, a network observer knows which hostname you're connecting to even if they can't read the payload.

---

### Full Network Flow Diagram

```
USER MACHINE                  INTERNET                 DATACENTER / CLOUD
┌──────────────┐              ┌────────┐               ┌──────────────────────────────────────┐
│              │              │        │               │                                      │
│  Browser     │  TCP+TLS     │  ISP   │               │   CDN Edge / Load Balancer           │
│  ─────────   │─────────────▶│  ──    │──────────────▶│   ┌──────────────────┐               │
│  JS Engine   │              │  BGP   │               │   │  nginx / ALB     │               │
│  File API    │              │  hops  │               │   │  TLS termination │               │
│  FormData    │              │        │               │   │  Rate limiting   │               │
│              │◀─────────────│        │◀──────────────│   │  WAF rules       │               │
└──────────────┘              └────────┘               │   └───────┬──────────┘               │
                                                       │           │ plain HTTP (internal)     │
                                                       │           ▼                           │
                                                       │   ┌──────────────────┐               │
                                                       │   │  Upload API Pod  │               │
                                                       │   │  (Go / Node.js)  │               │
                                                       │   └──────────────────┘               │
                                                       └──────────────────────────────────────┘

Packet-level view of a 4.2MB upload:
┌────────────────────────────────────────────────────────────────────────┐
│  IP header (20B) │ TCP header (20B) │ TLS record header (5B) │ DATA   │
│  src: 192.168.1.5│ src_port: 55123  │ content_type: 0x17     │ ~1430B │
│  dst: 203.0.113.1│ dst_port: 443    │ version: 0x0303        │        │
│                  │ seq: 1000        │ length: 1430           │ (enc.) │
└────────────────────────────────────────────────────────────────────────┘
  × ~2877 segments to transmit 4.2MB

Latency budget (typical):
  DNS (cached):          0ms   (or 50–100ms if uncached recursive lookup)
  TCP handshake:        50ms   (1 RTT, 25ms one-way to edge)
  TLS 1.3 handshake:   50ms   (1 RTT for new, 0 for resumed)
  Upload transfer:     200ms   (4.2MB at 20Mbps uplink)
  Server processing:   150ms   (parsing, auth, staging write)
  ─────────────────────────
  Total to 202 response: ~450ms
```

**Where latency and failures occur:**

| Point | Failure Mode | Detection |
|---|---|---|
| DNS | NXDOMAIN from misconfigured record | Spike in DNS SERVFAIL metrics |
| TCP SYN | SYN flood exhausts backlog | SYN cookie mitigation; `netstat -s` |
| TLS | Cert expired/mismatch → browser error | Certificate monitoring / expiry alerts |
| TLS | Weak cipher negotiated (TLS 1.0) | SSLLabs scan; cipher telemetry |
| Upload transfer | Client disconnects mid-upload | TCP RST received; partial file in staging |
| MTU mismatch | Packet blackholing (PMTUD failure) | Asymmetric TCP retransmit metrics |
| Upload API | OOM from buffering large file | Container OOM kill; pod restart |

---

## 3. Application Layer Flow

### HTTP Request Structure

A multipart upload request looks like this on the wire (after TLS decryption):

```
POST /api/v1/images/upload HTTP/2
Host: api.example.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxk
Content-Length: 4404234
Cookie: session_id=abc123; _csrf=def456
X-Request-ID: 550e8400-e29b-41d4-a716-446655440000
X-Forwarded-For: 203.0.113.42
Accept: application/json
Origin: https://app.example.com

------WebKitFormBoundary7MA4YWxk
Content-Disposition: form-data; name="image"; filename="selfie.jpg"
Content-Type: image/jpeg

[raw binary bytes of JPEG here — 4.2MB]
------WebKitFormBoundary7MA4YWxk
Content-Disposition: form-data; name="purpose"

profile_photo
------WebKitFormBoundary7MA4YWxk--
```

**Header-by-header analysis:**

`Content-Type: multipart/form-data; boundary=...`
The boundary string separates form fields. The server's multipart parser reads until it finds `--{boundary}`, then parses each part's sub-headers. The boundary is user-controlled — an attacker can craft boundaries that confuse naive parsers (boundary injection). A proper parser handles this strictly.

`Content-Length: 4404234`
This is a hint, not a guarantee. Servers that allocate a buffer of exactly `Content-Length` bytes before reading are vulnerable if the actual body is larger. A correct server enforces its own `MAX_BODY_SIZE` limit regardless of `Content-Length`.

`Authorization: Bearer <JWT>`
The raw JWT is a Base64url-encoded JSON header + payload + signature. Middleware extracts this, verifies the signature against the public key, and checks `exp` (expiry) claim. This happens before request routing to the handler.

`X-Forwarded-For: 203.0.113.42`
Set by the load balancer with the client's original IP. Do NOT trust this header from external clients — it's trivially spoofable. Only trust it if it's set by a known trusted proxy (LB), and even then, take the rightmost IP added by your own infrastructure.

`Origin: https://app.example.com`
CORS pre-flight mechanism. The server must validate this matches an allowed origin. If the Origin is not allowlisted, the server must return a `403` or omit the CORS headers. Incorrect wildcard (`Access-Control-Allow-Origin: *`) on an authenticated endpoint is a critical security flaw.

---

### Request Parsing

**Multipart boundary parsing (detailed):**

```python
# Pseudocode: what a streaming multipart parser does

boundary = extract_boundary(content_type_header)
# boundary = "----WebKitFormBoundary7MA4YWxk"

stream = request.body_stream()
for part in parse_multipart(stream, boundary, max_size=10*1024*1024):
    if part.name == "image":
        # DO NOT read entire part into memory
        # Stream it to temp storage
        with temp_file() as f:
            for chunk in part.stream(chunk_size=65536):
                f.write(chunk)
                if f.tell() > MAX_FILE_SIZE:
                    f.close()
                    raise FileTooLargeError()
    elif part.name == "purpose":
        purpose = part.read_text(max_bytes=256)  # Small fields: limit bytes
```

**Parameter parsing risks:**
- `filename` in Content-Disposition is attacker-controlled. Never use it directly as a filesystem path. Strip path separators, null bytes, and use a UUID for actual storage keys.
- `Content-Type` per part is attacker-controlled. Never trust it to determine file type. Read the bytes.
- Field ordering is not guaranteed. A parser that assumes `purpose` always comes before `image` is fragile.

---

### HTTP Response Construction

On successful staging:

```
HTTP/2 202 Accepted
Content-Type: application/json
X-Request-ID: 550e8400-e29b-41d4-a716-446655440000
Cache-Control: no-store
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Content-Security-Policy: default-src 'none'

{
  "jobId": "job_8f4a2c1e",
  "status": "queued",
  "estimatedCompletionMs": 3000,
  "pollUrl": "/api/v1/jobs/job_8f4a2c1e"
}
```

**Why 202 and not 200?** The work is not done. 200 implies the resource is ready. 202 means the request was accepted for asynchronous processing. This is semantically correct and prevents the client from caching the response as a final result.

**Security headers:**
- `X-Content-Type-Options: nosniff`: Prevents browsers from MIME-sniffing responses — e.g., prevents a returned HTML error page from being executed as a script.
- `Cache-Control: no-store`: The 202 response contains job state that must not be cached.
- `Strict-Transport-Security`: Forces HTTPS for all future connections, preloading eliminates the first-visit downgrade attack.

---

## 4. Backend Architecture

### Service Map

```
                         ┌─────────────────────────────────────────────────┐
                         │              API GATEWAY / LB LAYER              │
                         │  nginx / AWS ALB — TLS termination, rate limits  │
                         └───────────────────────┬─────────────────────────┘
                                                 │
                    ┌────────────────────────────▼──────────────────────────┐
                    │                    UPLOAD API SERVICE                  │
                    │   - Stream multipart to staging S3                    │
                    │   - Auth check (JWT validation)                       │
                    │   - Quota check (Redis)                               │
                    │   - Emit job to queue                                 │
                    │   - Return 202 + jobId                                │
                    └────────────────────┬──────────────────────────────────┘
                                         │ publish
                                         ▼
                              ┌──────────────────────┐
                              │   Message Queue       │
                              │   (SQS / RabbitMQ /  │
                              │    Kafka)             │
                              │   Topic: img-jobs     │
                              └──────────┬───────────┘
                                         │ consume
                         ┌───────────────▼───────────────┐
                         │     IMAGE PROCESSING WORKERS   │
                         │  (pool of containers/lambdas)  │
                         │                                │
                         │  1. Fetch from staging S3      │
                         │  2. Magic byte check           │
                         │  3. libvips decode             │
                         │  4. EXIF strip                 │
                         │  5. Resize to variants         │
                         │  6. Re-encode as WebP          │
                         │  7. Write to CDN-origin S3     │
                         │  8. Update DB                  │
                         │  9. Publish completion event   │
                         └───────────────────────────────┘
                                 │           │           │
                    ┌────────────▼──┐  ┌─────▼────┐  ┌──▼──────────────┐
                    │   PostgreSQL  │  │  Redis   │  │  S3 (CDN Origin) │
                    │   (user data) │  │  (cache) │  │  (final images)  │
                    └───────────────┘  └──────────┘  └────────┬─────────┘
                                                              │ CloudFront/Fastly pull
                                                              ▼
                                                      ┌───────────────┐
                                                      │   CDN Edge    │
                                                      │   (serve to   │
                                                      │   end users)  │
                                                      └───────────────┘
```

---

### Sync vs. Async Decision

**Why async?**

Image processing is CPU and I/O intensive. A 4MB JPEG processed through libvips (decode → resize × 3 → re-encode) takes 500ms–2000ms of CPU. Doing this synchronously inside the HTTP request handler means:
- The HTTP connection is held open for the full duration
- The API server is CPU-bound during processing, blocking other requests
- Scaling the API tier forces scaling the processing tier at the same ratio
- A single slow image stalls the thread/goroutine (depends on runtime)

With async queuing:
- The API server is lightweight (I/O + auth + staging write)
- Processing workers scale independently based on queue depth
- A crashed worker doesn't affect the upload path
- Failed jobs can be retried without client involvement
- You can prioritize queues (premium users, batch jobs, etc.)

**The tradeoff:** Clients must poll or use WebSockets/SSE for completion. Simpler clients want synchronous behavior. The design choice has UX implications.

---

### Queue Design (SQS as example)

```
Message schema:
{
  "jobId":           "job_8f4a2c1e",
  "userId":          "usr_4a2b1c",
  "tenantId":        "tenant_99",
  "stagingKey":      "staging/usr_4a2b1c/job_8f4a2c1e.tmp",
  "declaredMime":    "image/jpeg",
  "originalName":    "selfie.jpg",   // NOT used as path — informational only
  "uploadedAt":      "2024-05-15T12:00:00Z",
  "purpose":         "profile_photo",
  "variants":        ["48x48", "256x256", "1024x1024"],
  "callbackUrl":     null            // or webhook URL for enterprise
}

Queue properties:
  Visibility timeout:    300s (max processing time)
  Message retention:     4 days (allows retry window)
  Dead-letter queue:     after 3 failures → DLQ → alert
  FIFO vs Standard:      Standard (at-least-once, no ordering need)
```

**At-least-once delivery:** A worker may crash after processing but before deleting the message. The message becomes visible again after the visibility timeout. The worker must be **idempotent**: if the same `jobId` is processed twice, the second run must not corrupt data. Strategies: write final S3 objects with deterministic keys (idempotent PUT), check job status in DB before writing.

---

### Database Interactions

**PostgreSQL schema (relevant tables):**

```sql
-- Jobs table
CREATE TABLE image_jobs (
  job_id        UUID PRIMARY KEY,
  user_id       UUID NOT NULL REFERENCES users(id),
  status        VARCHAR(20) NOT NULL DEFAULT 'queued',
  -- queued → processing → complete → failed
  staging_key   TEXT NOT NULL,
  purpose       VARCHAR(50) NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at  TIMESTAMPTZ,
  error_message TEXT,
  retry_count   INT NOT NULL DEFAULT 0
);

-- Images table
CREATE TABLE images (
  image_id      UUID PRIMARY KEY,
  user_id       UUID NOT NULL REFERENCES users(id),
  job_id        UUID REFERENCES image_jobs(job_id),
  purpose       VARCHAR(50),
  variants      JSONB NOT NULL,
  -- {"48x48": "https://cdn.example.com/...", "256x256": "..."}
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at    TIMESTAMPTZ,
  is_deleted    BOOLEAN DEFAULT FALSE
);
```

**Critical DB access patterns:**

1. `SELECT FOR UPDATE` on job row when worker claims it — prevents two workers processing the same job simultaneously (though idempotency is also needed as a belt-and-suspenders).
2. Job status update is a state machine transition: `queued → processing → complete`. The UPDATE must be conditional: `UPDATE image_jobs SET status='processing' WHERE job_id=? AND status='queued'`. If 0 rows affected, another worker claimed it — abort.
3. Final image insert + job status update must be in a single transaction. If the transaction fails, the job can be retried and will re-write the same S3 objects.

---

### Caching Layers

**Redis usage:**

```
Key: quota:user:{userId}
Value: integer (bytes uploaded this billing period)
TTL: set to end of billing period
Operation: INCR by file size before upload; check against limit
Pattern: check-then-act is NOT atomic — use INCR and check the return value, or use Lua script for check+increment atomically
```

```
Key: job:status:{jobId}
Value: {"status": "processing", "progress": 0.6}
TTL: 300s
Purpose: allows polling endpoint to not hit DB every request
Updated: by worker as it completes stages
```

**CDN caching (CloudFront/Fastly):**

Final image URLs are structured with immutable cache headers:
```
Cache-Control: public, max-age=31536000, immutable
```

URL includes content hash or version:
```
https://cdn.example.com/images/usr_4a2b1c/profile/256x256/v3_a1b2c3d4.webp
```

When a user updates their photo, a **new URL** is generated. The old URL remains cached at CDN edges (it's still valid and correct — it's just the old photo). The DB is updated to point to the new URL. No cache invalidation needed for the new object. The old objects expire naturally or are deleted via lifecycle policy.

**Why this matters for security:** If you use a predictable/sequential URL scheme, an attacker can enumerate other users' photos by guessing adjacent IDs. Content-hash or UUID-in-URL prevents this (though it's not a substitute for access controls on sensitive images).

---

## 5. Authentication & Authorization Flow

### Token Architecture (JWT + Sessions)

Most production systems use a hybrid: JWTs for stateless API authentication, with session-based refresh.

**JWT structure:**

```
Header:  { "alg": "RS256", "typ": "JWT", "kid": "key-2024-05" }
Payload: {
  "sub": "usr_4a2b1c",
  "iss": "https://auth.example.com",
  "aud": "https://api.example.com",
  "exp": 1716000000,
  "iat": 1715996400,
  "jti": "jwt_unique_id_abc",   ← Unique ID for revocation
  "scope": ["image:write", "image:read"],
  "tenant": "tenant_99",
  "plan": "pro"
}
Signature: RS256(base64(header) + "." + base64(payload), private_key)
```

**Why RS256 and not HS256?** With HS256 (HMAC), the same secret signs and verifies — every service that needs to verify tokens must hold the secret. With RS256 (RSA asymmetric), the auth service holds the private key for signing; all other services hold the public key for verification only. Compromise of the image service does not compromise the ability to forge tokens.

---

### Where Validation Happens

```
Request flow:
────────────────────────────────────────────────────────────────────

1. LB/WAF layer:
   - Does the Authorization header exist?
   - Is it structurally a JWT (three dot-separated base64 segments)?
   - WAF may check for obviously malicious patterns in the token
   - NO signature verification at this layer (too expensive at LB scale)

2. API Gateway / Auth middleware (upload service, first thing):
   a. Decode header → extract "kid" (key ID)
   b. Fetch public key for "kid" from local JWKS cache
      (JWKS: JSON Web Key Set, fetched from auth.example.com/.well-known/jwks.json)
   c. Verify RS256 signature with the public key
   d. Check "exp" (expiry) — reject if in the past
   e. Check "iss" — reject if not "https://auth.example.com"
   f. Check "aud" — reject if doesn't include "https://api.example.com"
   g. Check "scope" — does it include "image:write"?
   h. (Optional) Check "jti" against revocation list in Redis

3. Business logic layer:
   - Check user's plan allows image uploads (from "plan" claim or DB lookup)
   - Check quota (Redis: INCR quota:user:{userId})
   - Check that userId in token matches resource being accessed

4. Worker layer:
   - Job message contains userId from the token (set at upload time)
   - Worker uses userId for all S3 paths, DB writes — no re-auth needed
   - Worker does NOT process jobs for deleted/suspended users (checks DB)
```

---

### Trust Boundaries

```
TRUST ZONE 1: Internet (untrusted)
─────────────────────────────────────────────────────────────
Any client. Zero trust. Everything must be validated.
Entry point: HTTPS on port 443 to LB.

TRUST ZONE 2: DMZ / Load Balancer
─────────────────────────────────────────────────────────────
TLS-terminated traffic. Rate-limited. WAF-filtered.
Trust level: known network path, but still not authenticated.

TRUST ZONE 3: Internal VPC — API Services
─────────────────────────────────────────────────────────────
Reachable only from within VPC. mTLS or service mesh (e.g., Istio).
Traffic here carries already-parsed, partially-validated requests.
Auth validation happens here. JWT must be verified.
Service-to-service calls use short-lived service tokens, not user JWTs.

TRUST ZONE 4: Internal VPC — Workers and Data Stores
─────────────────────────────────────────────────────────────
Workers run in isolated namespaces. Access to S3 via IAM role
(instance profile), not embedded credentials.
DB access via connection pool with service account, least privilege.
Redis access via VPC-internal endpoint, auth token required.

TRUST ZONE 5: Cloud Provider IAM / Control Plane
─────────────────────────────────────────────────────────────
AWS/GCP/Azure control plane. If an attacker reaches this layer,
they own your infrastructure. Protected by MFA, SCPs, org policies.
```

---

### Token Storage and Rotation

**Access token (JWT):** Short-lived (15 minutes). Stored in memory (JavaScript variable) or `Authorization` header. **Never** in `localStorage` (XSS-accessible). The tradeoff: in-memory tokens are lost on page refresh.

**Refresh token:** Long-lived (30 days). Stored in an `HttpOnly; Secure; SameSite=Strict` cookie. This means:
- JavaScript cannot read it (XSS protection)
- Only sent to same site (CSRF protection with SameSite)
- Only sent over HTTPS (Secure flag)

**Rotation:** When the access token expires, the client sends the refresh token to `/auth/refresh`. The auth service:
1. Validates the refresh token (checks DB or Redis for validity)
2. Issues a new access token (JWT)
3. Issues a new refresh token (refresh token rotation — old one invalidated)
4. Returns both tokens

**Refresh token rotation** means that if a refresh token is stolen and used, the original user's next refresh will fail (the stolen token will have been rotated). The system can detect reuse of an already-rotated token (RT reuse detection) and revoke the entire session.

---

## 6. Data Flow

### Data Movement Diagram

```
CLIENT BROWSER
│  File bytes (raw JPEG)
│  User metadata (filename, purpose)
│  Auth token
│
▼ HTTPS (TLS encrypted)
API GATEWAY / LB
│  Decrypts TLS
│  Extracts headers (Authorization, Content-Type)
│  Passes raw HTTP to Upload API
│
▼ Internal HTTP (VPC)
UPLOAD API SERVICE
│  Streams file bytes → S3 staging (multipart S3 upload)
│  Metadata → Job message (JSON, SQS)
│  Auth token claims → embedded in job message (userId, tenantId)
│  No PII stored beyond userId in job record
│
▼ S3 (SSE-S3 or SSE-KMS encrypted at rest)
STAGING BUCKET
│  Raw binary: original file, untouched, potentially malicious
│
▼ SQS (in-transit encrypted, at-rest encrypted via KMS)
MESSAGE QUEUE
│  Job metadata (JSON)
│  No file bytes in queue — only the S3 key reference
│
▼ Internal compute
IMAGE PROCESSING WORKER
│  Fetch raw bytes from staging S3
│  Decode → raw pixel array in RAM (RGBA, 32bpp)
│  Transform (resize, normalize) → new pixel array
│  Re-encode → clean WebP binary
│  Strip: NO EXIF, NO ICC profile leakage, NO embedded thumbnails
│
▼ S3 (SSE-KMS encrypted, CDN-origin bucket)
FINAL STORAGE
│  Multiple variant files
│  Immutable once written (object versioning or separate key per version)
│
▼ PostgreSQL (encrypted at rest, TDE or volume encryption)
DATABASE
│  URL pointers only — not raw bytes
│  Indexed by userId, imageId, purpose
│
▼ CDN (edge cache)
END USER BROWSER
│  Served over HTTPS
│  Cache-Control: immutable
```

---

### Serialization Formats and Transformation Points

**JSON in queue messages:** Must be validated against a schema on the consumer side. A producer bug or malicious message injection could send malformed JSON or unexpected fields. Workers should use strict schema validation (not just JSON.parse).

**Pixel data in memory (worker):** After decoding, the image exists as a raw pixel array. At this point it's just numbers — no format-specific attack surface. This is why re-encoding from pixels is the gold standard for sanitization.

**EXIF stripping:** EXIF data lives in JPEG APP1 markers. libvips can strip it during export. But a truly safe approach is to decode to pixels (discarding all metadata), then encode fresh. This guarantees EXIF is gone even if the stripping logic has a bug.

**Content negotiation for variants:** If the requesting client sends `Accept: image/webp`, serve WebP. If not, serve JPEG. This negotiation happens at CDN edge or origin server level. Variant selection must be server-driven — don't accept a `variant` query parameter that selects arbitrary file paths.

---

## 7. Security Controls

### Encryption In Transit

- All external traffic: TLS 1.2 minimum, TLS 1.3 preferred. Enforce at LB level. Disable SSLv3, TLS 1.0, TLS 1.1.
- Internal VPC traffic: mTLS enforced via service mesh (Istio/Linkerd). Service identity via SPIFFE/SPIRE X.509 SVIDs.
- SQS: In-transit encryption enforced via queue policy `aws:SecureTransport` condition.
- S3: All requests must use HTTPS (bucket policy `aws:SecureTransport: true`).

### Encryption At Rest

- S3 staging bucket: SSE-KMS with a dedicated KMS key. Key policy restricts access to Upload API role and Worker role only.
- S3 CDN-origin bucket: SSE-KMS. Different key than staging. Workers have write access; CDN distribution has read access via Origin Access Control (OAC).
- PostgreSQL: Volume encryption (AWS RDS encrypted storage). Encryption key managed via KMS. TDE-level encryption where supported.
- Redis: ElastiCache with at-rest encryption. Encryption key via KMS.
- SQS: Server-side encryption via KMS.

### Input Validation

**File validation layers (defense in depth — every layer independently enforced):**

```
Layer 1: Client-side (UX only, not security)
  - Extension check, size check, MIME type check
  - Bypassed by: curl, any HTTP client, browser devtools

Layer 2: HTTP layer (LB/WAF)
  - Max body size enforcement (e.g., 20MB hard limit)
  - Content-Type header check (rejects non-multipart)
  - Rate limiting on upload endpoint

Layer 3: Upload API
  - Content-Length sanity check (reject > MAX, even before reading)
  - Streaming body size limit (abort if stream exceeds limit)
  - Filename sanitization (UUID replacement)
  - Declared MIME type logged but not trusted

Layer 4: Processing Worker (the real validation)
  - Magic byte check (first N bytes match expected format)
  - Parser-level validation (libvips decode — fails on invalid files)
  - Dimension check (reject pathological W×H, e.g., > 20000px in any dimension)
  - File size post-decode check (decompression bomb detection: if decoded size >> compressed size by factor > 100, reject)
  - Re-encode from pixels (nuclear sanitization)
```

**Decompression bomb example:**
A valid PNG can be 1KB compressed but decode to 4GB of pixel data. A naive processor loads the whole image into RAM → OOM → crash. Defense: check decoded pixel count before allocating. `width × height × channels > MAX_PIXELS` → reject before decoding.

### Access Control

- Upload endpoint requires authenticated session (JWT with `image:write` scope)
- Workers access S3 via IAM instance profile — no hardcoded credentials
- Final images are public (profile photos) or private (authenticated URL via presigned S3)
- For private images: presigned S3 URLs with 15-minute expiry, generated on-demand
- S3 bucket ACLs: staging bucket has `BlockPublicAccess: true`. CDN-origin bucket: public access blocked, only CDN OAC allowed.

### Secrets Handling

- Database credentials: AWS Secrets Manager, auto-rotated every 30 days. Fetched at pod startup, cached in memory. Secret ARNs in environment variables (not the secrets themselves).
- API keys for external services: same pattern — Secrets Manager.
- KMS key ARNs: in environment variables or Terraform config. Not secrets themselves but restrict access.
- JWT private key: HSM-backed KMS key. Auth service calls KMS Sign API — the private key bytes never leave the HSM.
- No secrets in: Docker images, environment variable plaintext in CI/CD logs, source code, S3 objects.

---

## 8. Attack Surface Mapping

### Full Attack Surface Diagram

```
                         ╔══════════════════════════════════╗
                         ║     EXTERNAL ATTACK SURFACE      ║
                         ╚══════════════════════════════════╝

INTERNET                 ╔═════════════════════════════════════════════════╗
──────────────────────── ║  ENTRY POINTS (all internet-facing)             ║
                         ║                                                 ║
[Any attacker]  ────────▶║  1. HTTPS :443 — Upload API                    ║
                         ║     /api/v1/images/upload (POST)                ║
                         ║     /api/v1/jobs/{id} (GET — polling)           ║
                         ║     Auth: JWT required                          ║
                         ║                                                 ║
[Authenticated user] ───▶║  2. HTTPS :443 — Auth Endpoints                ║
                         ║     /auth/login, /auth/refresh                  ║
                         ║     /auth/logout                                ║
                         ║                                                 ║
[Anyone]  ──────────────▶║  3. CDN Edge — Image Serving                   ║
                         ║     https://cdn.example.com/images/...          ║
                         ║     No auth (public images)                     ║
                         ║     Auth via presigned URL (private images)     ║
                         ║                                                 ║
[Anyone]  ──────────────▶║  4. DNS — domain resolution                    ║
                         ║     Typosquatting, BGP hijack                   ║
                         ║                                                 ║
[SSRF if exploited] ────▶║  5. S3 staging bucket (should be private)      ║
                         ║     Only accessible via AWS SDK from VPC        ║
                         ╚═════════════════════════════════════════════════╝

                         ╔══════════════════════════════════════════════════╗
                         ║     INTERNAL ATTACK SURFACE                      ║
                         ║  (reachable only from within VPC or             ║
                         ║   via compromised internal service)              ║
                         ║                                                  ║
                         ║  6. Upload API → SQS                            ║
                         ║     Message injection if SQS policy is open     ║
                         ║                                                  ║
                         ║  7. SQS → Worker                                ║
                         ║     Worker processes any message from queue     ║
                         ║     Malicious message = malformed job           ║
                         ║                                                  ║
                         ║  8. Worker → S3 staging                         ║
                         ║     Fetches arbitrary S3 keys from message     ║
                         ║     (path traversal if key not validated)       ║
                         ║                                                  ║
                         ║  9. Worker → PostgreSQL                         ║
                         ║     SQL injection if queries not parameterized  ║
                         ║                                                  ║
                         ║  10. Worker → Redis                             ║
                         ║     Command injection if user input hits Redis  ║
                         ║                                                  ║
                         ║  11. Image parser (libvips/ImageMagick)         ║
                         ║     CVEs, parser bugs, library vulnerabilities  ║
                         ║     Sandbox escape via native code              ║
                         ║                                                  ║
                         ║  12. Metadata/EXIF parser                       ║
                         ║     Embedded malicious scripts in EXIF         ║
                         ║     (if metadata is displayed without escaping) ║
                         ╚══════════════════════════════════════════════════╝

TRUST BOUNDARY MAP:

[Internet] ──TLS:443──▶ [LB] ──HTTP/mTLS──▶ [Upload API] ──IAM──▶ [S3 Staging]
                                                   │
                                                   │ SQS publish (IAM)
                                                   ▼
                                             [SQS Queue]
                                                   │
                                                   │ SQS consume (IAM)
                                                   ▼
                                           [Worker Pool]
                                          /      |       \
                                   [S3]  [PostgreSQL]  [Redis]
                                         (IAM)  (creds)  (token)
```

---

## 9. Attack Scenarios

### Scenario 1: Malicious File Upload (Polyglot / Parser Attack)

**Attacker assumptions:**
- Has a valid user account
- Wants to exploit the image processing pipeline to achieve RCE or denial-of-service
- Has knowledge of the target library (e.g., ImageMagick CVE)

**Step-by-step execution:**

1. Attacker crafts a polyglot file: a valid JPEG that also contains an embedded SVG with `<image href="http://attacker.com/ssrf">` or a crafted JPEG comment section that triggers a heap overflow in ImageMagick's JPEG decoder (e.g., CVE-2022-44268 — arbitrary file read via PNG profile).

2. Attacker authenticates normally, obtains a JWT with `image:write` scope.

3. Attacker uploads the crafted file to `/api/v1/images/upload`. File passes:
   - Client-side checks (valid JPEG magic bytes)
   - Size limits (4KB crafted file)
   - Staging write (stored as-is)
   - Returns 202 with jobId

4. Worker picks up the job. Calls libvips or ImageMagick to decode.

5. **If vulnerable parser:** 
   - File read: Worker reads `/proc/self/environ` or AWS credential file via SSRF in profile field, exfiltrates to attacker server
   - RCE: Crafted pixel data triggers buffer overflow → shellcode executes with worker process privileges

6. **Impact:** Worker has IAM role with S3 write access. Attacker's shell can: read all staged images, write malicious content to CDN-origin bucket, access DB credentials from environment, pivot to other internal services.

**Where detection could happen:**
- Anomalous outbound connection from worker pod (to `attacker.com`) — network egress monitoring catches this
- Worker process spawning unexpected child processes — seccomp/AppArmor violation
- EXIF field values containing URL-like strings — could be flagged by WAF or parser

**Why this works (without mitigations):** Image parsers are complex, written in C/C++, historically buggy. `ImageMagick` has had 100+ CVEs. Running it with full network access and no sandbox is the root cause.

**Mitigation:** Run image processing in a gVisor/Kata container or dedicated subprocess with no network access, read-only filesystem except temp dir, seccomp filter blocking `execve`, `socket`, etc.

---

### Scenario 2: Decompression Bomb (DoS)

**Attacker assumptions:**
- Has a valid user account (or can create many cheap accounts)
- Goal: exhaust worker memory, cause denial of service to other users' uploads

**Step-by-step execution:**

1. Attacker creates a crafted PNG: 1px × 1px header, but the IDAT chunk contains an IDAT stream that decompresses to 1GB of zeros. The zlib compression ratio of repetitive data is enormous — a 10KB file can represent 1GB decompressed.

2. Attacker uploads this file. It passes size checks (`10KB < 20MB limit`). Magic bytes are valid PNG.

3. Worker begins decoding. libvips calls libpng. libpng begins decompressing IDAT. RAM usage of the worker process spikes from 50MB to 1GB+ in seconds.

4. **Without a memory limit:** Worker OOM kill. The job is retried (it's in the queue). The new worker also OOM kills. Repeat. All workers in the pool are OOM-cycling. The queue backs up. Legitimate user jobs are not processed.

5. **At scale:** With 10 concurrent uploads from 10 accounts, all worker pods crash simultaneously. k8s restarts them, they immediately pull the next bomb job from the queue. Effective cluster DoS.

**Where detection could happen:**
- Worker pod memory usage metric spike — alert at >80% container memory limit
- DLQ fills up with repeatedly-failing jobs — alert on DLQ depth > threshold
- Dimension check failure rate spike

**Why this works:** `Content-Length` only tells you compressed size. Decompressed size is unknown until you start decompressing. Without pre-checking declared dimensions (from IHDR for PNG) against a `max_pixels` limit before decoding, you decompress first and die.

**Mitigation:**
- For PNG: Read IHDR header (first 33 bytes) to get declared dimensions before decoding
- Set `width × height > MAX_PIXELS` rejection threshold (e.g., 50 megapixels = 50,000,000)
- Enforce container memory limits (`resources.limits.memory: 512Mi`)
- Set libvips memory limit: `vips_cache_set_max_mem(256 * 1024 * 1024)`

---

### Scenario 3: SSRF via SVG Upload

**Attacker assumptions:**
- Can upload files with an SVG MIME type (if SVGs are accepted)
- Goal: access internal AWS metadata service or internal services

**Step-by-step execution:**

1. Attacker crafts an SVG file:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image href="http://169.254.169.254/latest/meta-data/iam/security-credentials/upload-worker-role" 
         x="0" y="0" width="100" height="100"/>
</svg>
```

2. Attacker uploads this as `image/svg+xml`. If SVGs are accepted and processed through a library like Inkscape/rsvg/ImageMagick's SVG renderer:

3. The SVG renderer executes `href` — makes an HTTP request FROM THE WORKER to `169.254.169.254` (AWS IMDS).

4. AWS IMDS returns temporary credentials for the worker's IAM role (Access Key ID, Secret Access Key, Session Token).

5. Worker renders the credentials as pixels in the output image. Attacker downloads their "processed" image, reads the pixel values, reconstructs the credential string.

6. **Impact:** Attacker has valid AWS IAM credentials with the worker role's permissions. Can exfiltrate all S3 buckets, all staged images, push malicious objects, etc.

**Where detection could happen:**
- Outbound HTTP from worker to 169.254.169.254 — blocked by IMDSv2 (requires PUT first), but IMDSv1 is vulnerable
- Network monitoring for internal IP access from compute nodes
- AWS GuardDuty credential exfiltration findings

**Why this works:** SVG is XML. SVG supports external references. Image processing libraries that render SVG honor those references. The worker runs with an IAM role that has real AWS permissions.

**Mitigation:**
- Do NOT accept SVG in image upload pipeline if not required. SVG is a document format, not a raster image.
- If SVG must be accepted: sanitize the XML (strip all `href`, `xlink:href`, `<script>`, `<use>`, `<foreignObject>`, `<image>` tags referencing external URLs) before rendering.
- Enforce IMDSv2 on all EC2/ECS instances (PUT-based token required, eliminates SSRF to IMDS).
- Run workers in a network namespace with no egress to RFC 1918 addresses.

---

### Scenario 4: Insecure Direct Object Reference (IDOR) on Private Images

**Attacker assumptions:**
- Authenticated user (User A)
- Knows or can guess the image ID or URL of User B's private image
- Private images use presigned S3 URLs

**Step-by-step execution:**

1. User A uploads an image. Receives the CDN/storage URL: `https://cdn.example.com/images/usr_AAAA/private/job_1111.webp`

2. Attacker observes the URL structure. Guesses User B's URL: `https://cdn.example.com/images/usr_BBBB/private/job_2222.webp`

3. **Scenario A (no auth on image serving):** The CDN serves the image directly. No check that the requester is User B. Attacker downloads User B's private image.

4. **Scenario B (presigned URL, but ID is guessable):** The client fetches a presigned URL from `/api/v1/images/usr_BBBB/private/job_2222/url`. The API returns a presigned URL without checking if User A is authorized to access User B's image. Attacker gets the presigned URL and downloads the image.

**Where detection could happen:**
- Access log anomaly: User A's auth token accessing User B's resources repeatedly
- ABAC policy audit revealing missing ownership checks

**Why this works:** IDOR happens when authorization checks the authentication (is user logged in?) but not the authorization (is this user allowed to access this specific resource?).

**Mitigation:**
- Never use sequential or predictable IDs for private resources. Use UUIDs v4 (128-bit random).
- Enforce ownership check: `SELECT * FROM images WHERE image_id = ? AND user_id = ?` — reject if no row.
- For presigned URL generation endpoint: verify requesting user owns the resource before generating the URL.
- For truly sensitive images: don't use CDN at all — proxy through your own API, which enforces auth on every request.

---

### Scenario 5: JWT Algorithm Confusion Attack

**Attacker assumptions:**
- Knows the system uses JWTs with RS256
- Can obtain the server's public key (often published at `/.well-known/jwks.json`)
- Server has a vulnerability: it accepts both RS256 and HS256

**Step-by-step execution:**

1. Attacker fetches the public key from `https://api.example.com/.well-known/jwks.json`. This is intentionally public.

2. Attacker crafts a forged JWT:
   - Header: `{"alg": "HS256", "typ": "JWT"}` (changed from RS256 to HS256)
   - Payload: `{"sub": "usr_ADMIN", "scope": ["admin"], "exp": [future]}`
   - Signature: `HMAC-SHA256(base64(header) + "." + base64(payload), public_key_bytes)`

3. Attacker sends this token to the API. A vulnerable implementation:
   - Reads the `alg` field from the JWT header (attacker-controlled!)
   - Says "alg is HS256, I'll verify with HMAC"
   - Uses the RSA public key bytes as the HMAC secret
   - Computes HMAC(payload, public_key_bytes) — matches the forged signature
   - Token passes validation!

4. Attacker is now authenticated as `usr_ADMIN` with admin scopes.

**Where detection could happen:**
- If HS256 is not on the allowed algorithm list, the middleware should reject it immediately
- Log unusual `alg` values in incoming tokens

**Why this works:** The public key is public — by design. The vulnerability is accepting the algorithm from the token itself rather than hardcoding the expected algorithm.

**Mitigation:**
- **Hardcode the expected algorithm:** Never read `alg` from the JWT header. Your validator must only accept RS256 (or ES256). This is one line of code: `if header.alg != "RS256": reject`.
- Use a well-maintained JWT library (e.g., `jose` in Go, `python-jose`, `jsonwebtoken` in Node with `algorithms: ['RS256']` explicitly set).
- Rotate keys regularly. Expose JWKS, not raw PEM.

---

## 10. Failure Points

### What Fails Under Load

**Upload API — memory exhaustion:**
If the multipart parser buffers entire files into memory (common mistake in frameworks), at N concurrent uploads of 4MB each, memory usage = N × 4MB. At N=500 (moderate traffic), that's 2GB just for buffers. The pod OOM-kills. The load balancer routes to remaining pods. They also OOM-kill. Cascading failure.

Fix: Stream-to-storage. The file bytes touch memory only in transit, in chunk-sized buffers (64KB). Memory usage is O(chunk_size), not O(file_size).

**SQS queue — worker starvation:**
If workers are slow (libvips processing takes 2s per image) and upload rate spikes, queue depth grows. Visibility timeout (300s) must exceed processing time. If it doesn't, a slow worker's job becomes visible again and is picked up by another worker — duplicate processing. Both workers write to S3 (idempotent) and update DB (last-write-wins — usually OK, but check your state machine).

**PostgreSQL — connection exhaustion:**
Workers open DB connections. At 100 workers × 5 connections each = 500 connections. PostgreSQL's default `max_connections` is 100. At 500, new connections are refused. Use PgBouncer (connection pooler) in front of PostgreSQL. Workers connect to PgBouncer's pool; PgBouncer multiplexes onto a smaller set of real DB connections.

**Redis — quota check race condition:**
Two workers for the same user's simultaneous uploads both read `quota:user:X = 95MB`, both determine "under limit," both proceed. Both add 10MB. Quota is now 115MB — 15MB over limit. Fix: use Redis `INCR` and check the returned value atomically. Or use a Lua script.

**CDN origin stampede:**
If all CDN edges simultaneously lose their cache for a popular image (TTL expiry + cache purge), they all forward requests to the origin S3 simultaneously. S3 request rates can be throttled (S3 has per-prefix rate limits). Fix: staggered cache expiry (add jitter to TTL), use request coalescing at CDN (only one origin request per cache miss, others wait).

---

### What Fails Under Attack

**DDoS on upload endpoint:** Upload endpoints are expensive (disk I/O, compute). A volumetric DDoS targeting `/api/v1/images/upload` can exhaust:
- Network bandwidth (saturate the LB's uplink)
- Socket file descriptors on API pods (too many concurrent connections)
- Disk I/O on staging writes

**ImageMagick CVE exploitation:** A single crafted file processed by a vulnerable version of ImageMagick could compromise the entire worker fleet. Worker pods all run the same image. If one is exploited, the attacker has a foothold in the VPC.

**Auth service failure:** If the auth service is down or the JWKS endpoint is unreachable, the upload API cannot verify JWTs. The upload API should cache the JWKS public keys locally (with a reasonable refresh interval). If the cache is warm, auth continues without the auth service. If cold (first request, or cache expired), auth fails → all uploads fail. Design the JWKS cache to be pre-warmed at startup.

---

### Common Misconfigurations

| Misconfiguration | Impact |
|---|---|
| `Access-Control-Allow-Origin: *` on authenticated upload endpoint | CSRF-like cross-origin upload attacks |
| ImageMagick policy.xml not restricting `url:` delegate | SSRF from within image processing |
| S3 staging bucket `BlockPublicAccess: false` | Staged (potentially sensitive) raw uploads publicly accessible |
| Refresh token stored in `localStorage` | XSS exfiltrates refresh token → full account takeover |
| Worker IAM role allows `s3:*` on all buckets | Compromise of worker = access to all S3 data |
| `kid` in JWT not validated before JWKS lookup | JWKS injection — attacker controls which key is used to verify their own token |
| No visibility timeout on SQS = default 30s | Slow jobs are reprocessed every 30s (duplicate processing, resource waste) |
| No DLQ configured | Failed jobs silently disappear; no alerting |

---

## 11. Mitigations

### Concrete Fixes by Layer

**Network / Ingress:**
- Enforce TLS 1.2+ minimum; disable all weak cipher suites (RC4, DES, 3DES, NULL, EXPORT)
- Enable HSTS with preloading: `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`
- Rate limit upload endpoint: 10 requests/minute per user, 100 requests/minute per IP
- WAF rules: block files with magic bytes mismatching declared MIME type (though WAF can't fully parse binary — this is a hint, not a guarantee)
- Enable IMDSv2 on all compute instances (prevents SSRF to IMDS)
- Egress filtering: worker pods have no route to internet, no route to 169.254.0.0/16

**Image Processing (most critical layer):**

```
Defense-in-depth for image processing:

1. Run processor in sandboxed container:
   - gVisor (runsc) runtime — syscalls intercepted by Go-based kernel
   - OR Kata Containers — full VM isolation
   - seccomp profile: allowlist only read, write, mmap, exit, futex, clock_gettime
   - No network interface inside sandbox (network namespace isolation)
   - Read-only filesystem except /tmp
   - Memory limit: 512MB per job

2. Use libvips over ImageMagick:
   - libvips has a significantly better security track record
   - Parse with `--fail-on-error` equivalent
   - Set: VIPS_MAX_COORD (max dimension), no SVG, no PDF, no EPS loaders

3. Re-encode from pixels:
   - After decode, write pixels to a new image object from scratch
   - Never pass the original binary through to output
   - This is the only way to guarantee metadata is stripped and format is clean

4. Dimension guard before decode:
   if header_width > 10000 or header_height > 10000:
       reject("Image dimensions too large")
   if header_width * header_height > 50_000_000:  # 50 megapixels
       reject("Image pixel count too large")

5. Keep image processing library pinned and patched:
   - Subscribe to security advisories for libvips, libpng, libjpeg-turbo
   - Automated dependency scanning in CI (Dependabot, Snyk)
   - Image rebuild triggered on library CVE
```

**Authentication:**
- Hardcode expected JWT algorithm — never read `alg` from token header
- Validate `iss`, `aud`, `exp`, `nbf` on every request
- Implement refresh token rotation with reuse detection
- Use short-lived access tokens (15 minutes max)
- Implement JTI (JWT ID) tracking for high-value token revocation
- Store public keys (JWKS) in memory with background refresh; don't block requests on refresh

**IAM / Cloud:**
- Least-privilege IAM roles: Upload API role can only PUT to staging bucket prefix, publish to specific SQS queue. Nothing else.
- Worker role can only GET from staging prefix, PUT to CDN-origin prefix, consume from specific SQS queue, write to specific DynamoDB/RDS table.
- Use IAM condition keys: `s3:prefix` condition to restrict to `staging/` prefix.
- Enable S3 server access logging + AWS CloudTrail for all API calls.
- S3 Object Lock on CDN-origin bucket: WORM mode prevents overwriting of existing images (ransomware protection).

**Defense-in-Depth Strategy:**

```
Layer 1: Prevent (WAF, input validation, auth, rate limiting)
Layer 2: Detect (logging, anomaly detection, CSPM)
Layer 3: Contain (network segmentation, IAM least-privilege, sandboxing)
Layer 4: Recover (backups, DLQ, retry logic, disaster recovery plan)
```

No single control is sufficient. The goal is that compromising one layer does not compromise the system. Assume breach in each zone and ask: "what is the blast radius?"

---

## 12. Observability

### Logs

**What to log at each service:**

Upload API:
```json
{
  "timestamp": "2024-05-15T12:00:00.123Z",
  "level": "INFO",
  "event": "upload_received",
  "requestId": "550e8400-e29b-41d4-a716-446655440000",
  "userId": "usr_4a2b1c",
  "tenantId": "tenant_99",
  "fileSize": 4404234,
  "declaredMime": "image/jpeg",
  "stagingKey": "staging/usr_4a2b1c/job_8f4a2c1e.tmp",
  "jobId": "job_8f4a2c1e",
  "durationMs": 380,
  "clientIp": "203.0.113.42",  // from X-Forwarded-For, rightmost trusted hop
  "userAgent": "Mozilla/5.0..."
}
```

**Critical: do NOT log:**
- Raw JWT tokens (log only the `sub` claim after verification)
- Full file content or binary data
- Passwords, secrets, PII beyond userId
- Presigned URL tokens

Worker:
```json
{
  "event": "job_processing_complete",
  "jobId": "job_8f4a2c1e",
  "userId": "usr_4a2b1c",
  "magicBytesValid": true,
  "detectedMime": "image/jpeg",
  "originalDimensions": "4032x3024",
  "variants": ["48x48", "256x256", "1024x1024"],
  "processingDurationMs": 1823,
  "libvipsVersion": "8.15.1",
  "exifStripped": true,
  "workerInstanceId": "i-0abc123"
}
```

**Log what you need to reconstruct an incident:** For a security incident (e.g., suspicious file upload), you must be able to determine: who uploaded it, when, from where, what the file contained (enough to re-examine), what the worker did with it, what it wrote to S3.

---

### Metrics

**Key metrics to track (Prometheus/CloudWatch):**

```
# Upload path
upload_requests_total{status="success|error", error_type="auth|quota|size|parse"}
upload_file_size_bytes (histogram, buckets: 100KB, 1MB, 5MB, 10MB, 20MB)
upload_duration_seconds (histogram)
active_uploads_concurrent (gauge)

# Queue health
sqs_queue_depth{queue="image-processing-jobs"} (gauge)
sqs_dlq_depth{queue="image-processing-dlq"} (alert if > 0)
sqs_message_age_seconds (how long messages wait — consumer latency)

# Worker health
worker_jobs_processed_total{status="success|failed|rejected"}
worker_job_duration_seconds (histogram)
worker_memory_usage_bytes (gauge — watch for bomb files)
worker_rejection_reason_total{reason="magic_bytes|dimensions|mime_mismatch|decompression_bomb"}

# Security metrics
auth_failures_total{reason="expired|invalid_sig|wrong_aud|missing"}
rate_limit_triggered_total{endpoint, user_id}
file_rejection_total{stage="magic_bytes|dimensions|parser|re-encode"}
```

---

### Traces

Use distributed tracing (OpenTelemetry → Jaeger/Honeycomb/X-Ray):

```
Trace: upload_image
  Span: http_request (Upload API)
    Span: jwt_validation (2ms)
    Span: quota_check_redis (1ms)
    Span: stream_to_staging_s3 (340ms)
    Span: sqs_publish (5ms)
  [async — traced via jobId correlation]
  Span: worker_process_job
    Span: s3_fetch_staging (80ms)
    Span: magic_byte_check (0.1ms)
    Span: libvips_decode (250ms)
    Span: exif_strip (10ms)
    Span: resize_48x48 (30ms)
    Span: resize_256x256 (120ms)
    Span: resize_1024x1024 (400ms)
    Span: s3_write_variants (3 × 50ms = 150ms parallel)
    Span: db_update (8ms)
    Span: sqs_delete_message (3ms)
```

Traces connect the async boundary (upload API → queue → worker) via a `jobId` injected as a trace context carrier in the SQS message.

---

### What Should Alert vs. What Should Not

**Alert (page/wake someone up):**
- DLQ depth > 0 (any job failing after all retries)
- Worker pod OOM kill rate > 0
- Auth failure rate > 5% of requests for 5 minutes
- SQS queue age (time of oldest message) > 10 minutes (workers stuck)
- File rejection rate for magic_byte mismatch spike (possible attack)
- Any job processing duration > 30 seconds (possible bomb or stuck)
- Redis quota check error rate > 1% (quota bypass risk)
- S3 staging bucket public access enabled (SCPs + Config rule)

**Log but don't alert (noise):**
- Individual auth failures (normal for expired tokens, refreshed clients)
- Files rejected for being too large (normal user mistake)
- Slow uploads (network variability)
- Individual queue message redeliveries (normal at-least-once delivery)

---

## 13. Scaling Considerations

### Bottlenecks

**Upload API:** This is I/O bound (streaming bytes to S3). Each upload holds a connection open for the transfer duration. Scales horizontally — add more pods. Stateless (auth is in the JWT, staging key is in the response). LB can distribute freely.

**Image Processing Workers:** CPU bound (decode/encode). GPU-accelerated libraries (libvips with GPU backends, NVJPEG) can help for very high throughput. Scales horizontally — add more workers. Each worker is independent. Scale based on SQS queue depth metric.

**PostgreSQL:** Classic vertical + connection pooling bottleneck. Write bottleneck at very high throughput (job inserts + updates). Solutions:
- PgBouncer for connection pooling
- Partition the `image_jobs` table by `created_at` (range partition by month)
- Read replicas for polling queries (`GET /jobs/{id}` reads)
- At extreme scale: replace job status tracking with DynamoDB (single-digit ms, scales to millions of writes/second)

**S3 Staging Bucket:** S3 has per-prefix rate limits (~3,500 PUT/s, 5,500 GET/s per prefix). With all uploads to `staging/{userId}/{jobId}`, the first path component is `staging` — all uploads share the same prefix. At high throughput, this throttles. Fix: shard the staging prefix: `staging/{hash(userId)[0:2]}/{userId}/{jobId}` (256 prefix shards).

**SQS:** Essentially unlimited throughput. Not a bottleneck. Up to 120,000 messages in-flight simultaneously for standard queues.

---

### Horizontal vs. Vertical Scaling

| Component | Strategy | Why |
|---|---|---|
| Upload API | Horizontal (more pods) | Stateless, I/O bound, connection-per-upload |
| Workers | Horizontal (more pods/lambdas) | CPU bound, independent jobs, scale to queue depth |
| PostgreSQL | Vertical + read replicas | Stateful, ACID required; vertical for write throughput |
| Redis | Cluster mode horizontal | Partition quota keys across shards |
| S3 | Inherently distributed | No action needed; shard prefix at high volume |
| CDN | Horizontal by design | Edge nodes are globally distributed, add edge PoPs |

---

### Consistency Tradeoffs

**Job status tracking:** You want the polling endpoint to return accurate job status. Options:

1. **Always read from DB (strong consistency):** Accurate, but DB is hammered by polling. 1000 users polling every 2s = 500 reads/second just for status checks.

2. **Cache in Redis (eventual consistency):** Status updated in Redis by worker. Polling reads Redis. DB is source of truth. Risk: Redis can be up to 5s stale if worker crashes between DB write and Redis update.

3. **WebSocket push (no polling):** Worker publishes completion event; a notification service pushes to the client's WebSocket. Near-real-time, no polling overhead. Complexity: WebSocket connection management, reconnection logic, missed-event handling.

**Image URL consistency:** The DB is updated with the final URLs. Between the DB write and the CDN cache population, there's a brief window where the URL in the DB 404s (file doesn't exist on CDN yet because it hasn't been fetched from origin). Fix: write to S3 first, then write to DB. The image exists before the URL is recorded. Worst case: the URL is in DB but CDN doesn't have it yet — the first CDN request triggers an origin fetch, no 404.

---

## 14. Interview Questions

### Q1: Why do we stream the upload to S3 instead of buffering it in memory first?

**Direct answer:** Buffering N concurrent uploads of size F requires N × F memory. At 500 concurrent 4MB uploads, that's 2GB of buffer memory — this OOM-kills the pod and cascades. Streaming passes chunks directly from the network socket to the S3 multipart upload API. Memory usage is O(chunk_size) — about 64KB per upload regardless of file size.

**Follow-up — what if:** What if S3 is temporarily unavailable? The stream has already begun. You need to either (a) abort the S3 multipart upload and return an error, or (b) buffer locally to disk as fallback. Design choice: fail fast (return 503, user retries) vs. local buffer (increases disk pressure, adds complexity).

---

### Q2: Why is magic byte checking not sufficient as the only file validation?

**Direct answer:** Magic bytes are the first N bytes of a file. A JPEG starts with `FF D8 FF`. An attacker can take any file (e.g., a PHP script) and prepend `FF D8 FF` to it. The magic byte check passes. But the actual content is malicious. Magic byte checking confirms the file begins with the right signature. It does not prove the entire file is a valid image.

**Why it still matters:** It's a cheap, fast first filter. It catches trivially wrong files (a `.txt` file accidentally uploaded). It raises the bar for attackers — they must craft a file that starts correctly. Combined with parser-level validation (full parse by libvips), you get defense in depth.

---

### Q3: What's the difference between authentication and authorization in this pipeline, and where does each happen?

**Direct answer:**
- **Authentication:** Who are you? Verifying the JWT signature + claims proves the request comes from a known user with a valid session. Happens in middleware before any handler code runs.
- **Authorization:** What are you allowed to do? After authentication, we check: does this user have the `image:write` scope? Does this user's plan allow image uploads? Does this userId own the image being accessed? Happens in handler code after auth middleware.

**Why they're separate:** You can be authenticated (valid JWT) but not authorized (free plan, image upload not allowed). You can be authorized to read images but not to delete them. Mixing the two leads to IDOR vulnerabilities (authed but accessing someone else's resource).

---

### Q4: Explain the security implications of using `X-Forwarded-For` for rate limiting. What can go wrong?

**Direct answer:** `X-Forwarded-For` is set by proxies to carry the original client IP. However:
1. The header is **attacker-controlled** if not set by a trusted proxy. A client can send `X-Forwarded-For: 127.0.0.1` and if the server naively reads this, rate limiting sees "localhost" — completely bypassed.
2. Even when set by a trusted LB, the format is a comma-separated chain: `client_ip, proxy1_ip, proxy2_ip`. The server must extract only the **first** IP (leftmost) as the client's, but only if the entire chain comes from trusted infrastructure.

**Correct approach:** Configure your LB to always overwrite (not append to) the XFF header with its own view of the client IP. Then trust only what your LB sets. If using AWS ALB, use `X-Forwarded-For` only from the ALB, and ensure the ALB's security group blocks direct access to the Upload API (forces traffic through ALB).

---

### Q5: A user uploads an image. 30 seconds later they complain their new profile photo isn't showing. What could be happening?

**Systematically work through the pipeline:**
1. Job still in queue? Check queue depth — is there a worker bottleneck?
2. Worker processing failed? Check DLQ — is the job in DLQ?
3. Worker succeeded but DB not updated? Check `image_jobs.status` for the jobId.
4. DB updated but CDN serving stale content? If the user had a previous photo, did the CDN cache get purged? Check CDN purge logs.
5. CDN purged but browser caching? Old image cached in browser. Hard-refresh?
6. New image URL generated but frontend not updated? WebSocket/polling didn't deliver the completion event?

**What if:** What if you're in an interview and asked "how would you debug this in production?" → Check the jobId from the 202 response. Query `image_jobs` table with that jobId. Check `status`, `error_message`, `retry_count`. Follow the log trail with the `requestId`.

---

### Q6: Why is TLS termination at the load balancer a security tradeoff, and how do you mitigate it?

**Direct answer:** TLS termination at the LB means traffic inside the VPC (LB → API servers) is decrypted and travels in plaintext (or re-encrypted with a different cert). An adversary who compromises an internal network device sees plaintext data. The LB operator can read all traffic.

**Tradeoffs:**
- **Benefit:** LB can inspect L7 content (WAF, routing, header manipulation)
- **Risk:** Extends the trust boundary. Plaintext inside VPC.

**Mitigations:**
- Re-encrypt between LB and backend (LB to EC2 with a self-signed or internal CA cert) — sometimes called "end-to-end TLS"
- Use a service mesh (Istio mTLS) between all internal services — even if LB terminates, pod-to-pod traffic is encrypted
- Keep VPC internal network segmented — backend services unreachable from other VPC segments

---

### Q7: How would you implement idempotent image processing to handle SQS at-least-once delivery?

**Direct answer:** At-least-once means a job message may be delivered multiple times (e.g., worker crashes after processing but before deleting the message). Two workers must not corrupt the state when both process the same job.

**Implementation:**
1. Use `UPDATE image_jobs SET status='processing' WHERE job_id=? AND status='queued'` — only one worker can succeed this CAS (compare-and-swap) operation. The second one gets 0 rows affected and aborts.
2. S3 writes: use the same deterministic key for each variant (e.g., `images/{userId}/profile/{jobId}/256x256.webp`). Overwriting with the same content is a no-op from the user's perspective.
3. DB final update: wrap in a transaction; use `ON CONFLICT DO UPDATE` for upsert semantics.
4. SQS delete: only delete the message after all writes succeed. If the worker crashes before deleting, the message reappears — the idempotent logic handles it.

**What if:** What if two workers both pass the status CAS (race condition in the DB)? Ensure the UPDATE + SELECT FOR UPDATE is done within a transaction with appropriate isolation level (at least `READ COMMITTED` for the CAS pattern).

---

### Q8: Explain decompression bomb attacks and how to prevent them at each layer.

**Direct answer:** A decompression bomb is a file that is small when compressed but expands to a huge size when decoded. A 45KB zip file can expand to 4.5 petabytes (the "42.zip" bomb). For images: a 10KB PNG with an IDAT chunk that decompresses to 4GB of zeros.

**Why naive code fails:** `image.open(file).load()` — the library decompresses the entire file into RAM before returning. The process OOM-kills.

**Prevention layers:**
1. **Header inspection (before decode):** For PNG, read the IHDR chunk (first 33 bytes) to get declared W × H. Reject if W × H > MAX_PIXELS. Cost: near-zero.
2. **Library-level limits:** libvips: `VIPS_MAX_COORD` env var limits max dimension. libpng: `png_set_user_limits()` call. Set before decode.
3. **Container memory limits:** Even if the library starts decompressing, the container hits its memory limit and is OOM-killed cleanly (not the whole host).
4. **Ratio check:** If decoded size / compressed size > 100 (or configured ratio), abort. Needs partial decode though — less clean.
5. **Process isolation:** Run the decoder in a subprocess with `ulimit -v` (virtual memory limit). If it exceeds, the subprocess exits; the parent handles it cleanly.

---

### Q9: What are the security implications of logging image processing events, and what should never appear in logs?

**Direct answer:**

**Should be in logs:** jobId, userId, tenantId, file size, detected MIME type, declared MIME type, processing result, rejection reason, worker version, processing duration, S3 key paths (not signed URLs).

**Must NOT be in logs:**
- Raw file bytes or base64-encoded content (potential data exfiltration, PII in EXIF)
- Full JWT tokens (contains user identity, must be secret)
- Presigned S3 URLs (a logged presigned URL is a time-limited credential; anyone reading logs gets access)
- AWS access keys or session tokens (from instance metadata — if SSRF succeeds and credentials are logged, that's doubly bad)
- Passwords, payment info, or any PII from EXIF (GPS coordinates, device serial numbers)

**Why EXIF is PII:** A JPEG taken on a smartphone contains GPS coordinates to ~10m accuracy, device make/model, timestamp, sometimes the user's name from camera settings. Processing this without stripping it — and especially logging it — is a GDPR/privacy violation.

**Operational consideration:** Logs are often stored less securely than primary data. Logs may flow to a centralized SIEM where many engineers have read access. Design logging as if logs are semi-public.

---

### Q10: A new CVE is published for libvips with a CVSS score of 9.8. What do you do in the next 4 hours?

**Systematic response:**

**First 15 minutes — assess:**
- Read the CVE. What's the attack vector? (Network? Local? Image parsing?) What's the trigger? (Specific file format? Specific operation?)
- Is it a CVSS 9.8 with "image decoding" as the trigger? That means it's exploitable via a crafted image — directly in your pipeline.
- Are our workers running the vulnerable version? `vips --version` in the deployed container image.

**Next 30 minutes — contain:**
- Can you disable the specific vulnerable operation? If CVE is in SVG loader and you don't process SVGs, disable the SVG loader in libvips policy (`--vips-leak` and loader restrictions) — buys time.
- Increase worker isolation immediately: if workers don't have seccomp profiles, add a restrictive one that blocks `execve` — limits blast radius of RCE.
- Enable enhanced network egress monitoring: alert on any outbound connection from worker pods to non-allowlisted destinations.
- Consider halting processing of new jobs temporarily if severity warrants.

**Next 2 hours — remediate:**
- Update the base container image to a version of libvips with the patch. If no patch exists, pin to the last safe version and test.
- Rebuild and re-deploy the worker container images.
- Rolling deployment to workers — drain running jobs first.
- Run a canary (one worker with the new image) against non-production traffic.

**Parallel — investigate:**
- Review the last 72 hours of worker logs for anomalous outbound connections, unusual process spawning, or high-memory jobs.
- Check DLQ for jobs that failed in a way consistent with exploitation.
- If you find evidence of exploitation: invoke incident response plan, isolate affected workers, preserve forensic evidence, notify security team.

---

### Q11: Design an image upload rate limiter that prevents both per-user abuse and coordinated abuse across many accounts.

**Direct answer:**

**Single-user rate limit (per userId, Redis):**
```
INCR rate:upload:user:{userId}:{window}
EXPIRE rate:upload:user:{userId}:{window} 3600  // 1-hour window
if value > USER_UPLOAD_LIMIT_PER_HOUR:
    return 429 Too Many Requests
```

Problem: attacker creates 1000 accounts, each under the limit. Coordinated abuse.

**IP-based limit (additional Redis key):**
```
INCR rate:upload:ip:{ip}:{window}
if value > IP_UPLOAD_LIMIT:
    return 429
```

Problem: shared NAT (corporate network, Tor exit node) — too aggressive blocks legitimate users. Also bypassed by rotating IPs (botnet, residential proxies).

**Composite signals (defense-in-depth rate limiting):**
1. Per-user limit (primary control)
2. Per-IP limit (catches stolen-account scenarios, multiple accounts from one IP)
3. Per-tenant/org limit (catches compromised tenants)
4. Global rate limit with circuit breaker (if total upload rate across all users exceeds N × expected_baseline, engage global throttle)
5. Behavioral scoring: account age < 24h + uploading at maximum rate → flag for review, not hard block
6. Fingerprinting: TLS fingerprint (JA3 hash), HTTP/2 settings fingerprint — botnets often share identical client stacks

**Tradeoff:** More signals = higher accuracy = more complexity = more maintenance. Start with per-user + per-IP. Add behavioral signals when you have evidence of coordinated abuse patterns.

---

### Q12: Why is re-encoding images from raw pixels the "nuclear option" for sanitization, and when is it not sufficient?

**Direct answer:** After a library decodes a JPEG/PNG, the result is raw pixel data: a width × height × channels array of unsigned integers. This array contains absolutely no JPEG or PNG format information — no EXIF, no comments, no embedded thumbnails, no ICC profiles, no custom chunks. It's just colors. Re-encoding this to a new JPEG/WebP produces a file that contains only what you explicitly put in: the pixels, the compression settings you specify, and nothing else.

This defeats:
- EXIF-based metadata attacks (GPS, serial numbers, embedded scripts)
- Steganographic payloads hidden in specific DCT coefficients (mostly defeated, depending on encoder)
- Embedded thumbnail attacks (EXIF-embedded thumbnails can differ from main image — used to hide CSAM)
- Format polyglots (a file that is simultaneously a valid JPEG and a valid ZIP — re-encoding from pixels produces a pure JPEG)

**When re-encoding is NOT sufficient:**
1. **Steganography in pixel values:** Subtle steganographic techniques (LSB steganography) store data in the least-significant bits of pixel values. Re-encoding from pixels preserves the pixel values → the hidden data survives. Counter: quantization during re-encoding (lossy JPEG compression) destroys LSB data. But lossless re-encoding (PNG, lossless WebP) does not.
2. **Filename / URL-based metadata:** Re-encoding doesn't change the S3 key or DB record. If the filename contains injection payloads and it's ever rendered in an HTML context, XSS is still possible. The S3 key must be UUID-based, never derived from user input.
3. **Timing side-channels:** Processing time varies by image content (complex images take longer). An attacker with upload feedback timing can infer information about image content. Not typically a concern for image pipelines, but relevant in some contexts.

---

*End of document. This breakdown should be revisited whenever the image processing library, cloud provider, or auth architecture changes. Security properties derived from architectural assumptions are invalidated by architectural changes.*
