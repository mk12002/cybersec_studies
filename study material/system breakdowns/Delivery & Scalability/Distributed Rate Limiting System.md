# Distributed Rate Limiting System — Internal Engineering & Security Document

**Classification:** Internal Engineering Reference  
**Audience:** All Engineers (Beginner to Senior), Security Engineers, Platform Architects  
**Scope:** Complete breakdown of a production distributed rate limiting system — from packet arrival to decision, including all algorithms, failure modes, and attack vectors  
**System Context:** Rate limiter deployed across multiple API Gateway instances, backed by Redis Cluster, protecting a suite of microservices

---

## A Beginner's Orientation: What Is Rate Limiting and Why Does It Exist?

**The core problem:** Imagine your API is like a highway. Rate limiting is the on-ramp metering light — it controls how many cars can enter per minute to prevent gridlock (system overload). Without it:

- One misbehaving client can consume all available capacity, starving everyone else
- Scrapers can extract your entire database in minutes
- Brute force attacks can try millions of password combinations
- A bug in a client can send thousands of requests per second accidentally
- Your infrastructure costs explode unpredictably

**What "distributed" means here:** When you run multiple API server instances (for high availability and scale), a simple in-memory counter on each server doesn't work. If you allow 100 requests/minute per user and you have 10 servers, a user could make 1000 requests/minute (100 to each server). The rate limit state must be shared across all server instances — that's the "distributed" part, and it's the core engineering challenge.

**The three main challenges of distributed rate limiting:**
1. **Correctness:** All server instances must see the same counter state
2. **Performance:** Every API request must wait for the rate limit check — it must be sub-millisecond
3. **Availability:** If the rate limiting service goes down, do you block all traffic (safe but unavailable) or allow all traffic (available but unprotected)?

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

A developer (let's call them Alex) is using the `api.example.com` REST API to build a mobile app. Alex's app makes authenticated API calls using an API key. We trace what happens in three situations:

1. **Happy path:** Normal API usage within limits
2. **First rate limit hit:** Alex's app has a bug causing excessive calls
3. **Sustained abuse:** Alex deliberately (or accidentally) hammers the API

---

### Situation 1: Happy Path Request (T+0ms)

Alex's mobile app makes a legitimate API call:

```
GET https://api.example.com/v1/products?category=electronics
Authorization: Bearer eyJhbGci...
X-API-Key: ak_prod_1a2b3c4d5e6f
```

**What Alex's app sees:** A response in ~150ms with the product list. Nothing unusual.

**What actually happens (full sequence):**

**T+0ms** — Request arrives at CDN/edge (e.g., Cloudflare)  
**T+5ms** — CDN forwards to a load balancer, which selects API server instance #3 of 8  
**T+6ms** — API server's rate limiting middleware intercepts the request BEFORE any business logic runs

The rate limiting middleware executes a Redis Lua script (atomic — explained in depth in Section 4):

```lua
-- Executed atomically on Redis
local key = "rl:user:user_alex_123:minute"
local limit = 1000
local current = redis.call("INCR", key)
if current == 1 then
  redis.call("EXPIRE", key, 60)
end
return {current, limit}
```

Redis executes this in ~0.3ms. Returns: `[47, 1000]` — meaning Alex has made 47 requests this minute, limit is 1000.

**T+6.3ms** — Rate limit check passes (47 < 1000). Middleware attaches headers to the downstream request context.

**T+6.4ms** — Business logic executes: query database, fetch products, serialize response

**T+145ms** — Response returned to Alex's app:

```http
HTTP/2 200 OK
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 953
X-RateLimit-Reset: 1700000060
X-RateLimit-Policy: sliding-window-60s

{...product data...}
```

**Alex sees:** Product data. The rate limit headers are informational — his app currently ignores them (bad practice, but common).

---

### Situation 2: Rate Limit Hit (T+10 minutes later)

Alex's app has a bug. An infinite loop starts calling the API. Within 30 seconds, Alex's counter reaches 1000.

**The 1001st request:**

**T+0ms** — Request arrives at API server instance #7 (different server than before)

**T+0.3ms** — Redis Lua script executes:

```lua
local current = redis.call("INCR", key)  -- Returns 1001
return {current, limit}  -- {1001, 1000}
```

**T+0.4ms** — Middleware sees 1001 > 1000. The request is REJECTED immediately — the business logic never runs. No database query, no processing.

**T+0.5ms** — Response constructed and sent:

```http
HTTP/2 429 Too Many Requests
Content-Type: application/json
Retry-After: 23
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1700000083
X-RateLimit-Policy: sliding-window-60s

{
  "error": "rate_limit_exceeded",
  "message": "You have exceeded 1000 requests per minute.",
  "retry_after": 23,
  "documentation_url": "https://docs.example.com/rate-limits"
}
```

**What Alex sees:** His app starts getting 429 errors. The logs show rapid failures. Alex investigates and finds the infinite loop bug.

**What the rate limiter did:** It rejected the request in 0.5ms total — the API server didn't query the database, didn't do any work. At 10,000 rejected requests/second, the server stays healthy because it's doing almost nothing for each rejected request.

---

### Situation 3: What Happens Over Time (Rate Limit Window Expiry)

Alex fixes the bug. 60 seconds pass. The Redis key `rl:user:user_alex_123:minute` expires (TTL runs out). The counter resets to 0.

Alex makes a new request:
- Redis INCR on non-existent key: returns 1
- EXPIRE sets TTL to 60 seconds
- Request proceeds normally

**From Alex's perspective:** The rate limit "reset" — he can make 1000 more requests.

---

### Multi-Dimensional Rate Limiting (What Actually Happens)

In production, there's not just one rate limit. There are multiple, checked in cascade:

```
Request arrives
  ↓
Check 1: Global rate limit (all traffic)
  - Too high? → 503 Service Unavailable (protect entire system)
  ↓
Check 2: IP-based rate limit
  - 10,000 requests/hour per IP
  - Catches bots using multiple API keys
  ↓
Check 3: API Key rate limit
  - 1,000 requests/minute per API key (Alex's case)
  ↓
Check 4: Endpoint-specific rate limit
  - POST /v1/auth/login: 10 requests/minute (brute force protection)
  - POST /v1/orders: 60 requests/minute per user
  ↓
Check 5: User tier rate limit
  - Free tier: 100 requests/minute
  - Pro tier: 1,000 requests/minute
  - Enterprise tier: 10,000 requests/minute
  ↓
All checks passed → proceed to business logic
```

The first check to fail returns a 429 (or 503 for global). Each check is a separate Redis operation, but they're pipelined — sent in a single network round-trip.

---

## 2. Network Layer Flow

### DNS Resolution for the Rate Limiting Infrastructure

Rate limiting sits inside the API server layer, so the DNS flow is the same as any API request. What matters is how the rate limiting component itself discovers and connects to Redis:

```
API Server Instance (running rate limiting middleware)
  |
  | DNS query: "redis.internal.cluster.example.com"
  |   (internal DNS, not public internet)
  v
Internal DNS Server (AWS Route53 Private Zone / CoreDNS in Kubernetes)
  |
  | This is an AUTHORITATIVE lookup — no recursion needed
  | for internal service discovery
  v
Returns: Redis Cluster endpoints
  redis-node-1.example.com → 10.0.1.10
  redis-node-2.example.com → 10.0.1.11
  redis-node-3.example.com → 10.0.1.12

TTL: 5 seconds (short — allows fast failover when nodes change)
```

**Why short TTL for Redis cluster DNS:** If a Redis node fails and is replaced, API servers must discover the new IP quickly. A 5-second TTL means discovery happens within 5 seconds of node replacement (assuming the Redis client isn't caching the DNS resolution itself).

**Service discovery in Kubernetes (alternative):**
In Kubernetes, Redis is often accessed via a Service (e.g., `redis-cluster.rate-limiter-ns.svc.cluster.local`). The kube-proxy maintains iptables rules that load-balance connections to pod IPs. No DNS resolution per connection — the first resolution is cached by the runtime.

---

### TCP Connection to Redis (Internal Network)

For internal services, the TCP handshake is within the same data center — latency is 0.1–2ms (not 30–60ms like internet round-trips):

```
API Server (10.0.2.5)                Redis Primary (10.0.1.10:6380)
     |                                        |
     | SYN [seq=1000]                         |
     |--------------------------------------->|
     | SYN-ACK [seq=5000, ack=1001]           |
     |<---------------------------------------|
     | ACK [ack=5001]                         |
     |--------------------------------------->|
     | [Connection pool: keep-alive]          |
     | [This connection persists             |
     |  across thousands of Redis calls]      |
```

**Connection pooling is critical:** Without connection pooling, each rate limit check would require a new TCP handshake (~1ms). With pooling, the connection is established once at startup and reused. The rate limit check's network overhead is just the round-trip for the Redis commands (~0.3–0.5ms within a data center).

**Redis Sentinel vs Cluster connection:**
- **Sentinel:** API server connects to Sentinel first, gets primary address, then connects to primary. Connection pool maintained to primary.
- **Cluster:** API server connects to any cluster node. If the key is on a different shard, Redis returns a MOVED redirect. The client then connects to the correct shard. Redis Cluster clients (redis-py, ioredis) handle this transparently.

---

### TLS for Redis Connections

Redis connections should use TLS in production (Redis 6.0+ native TLS, or stunnel wrapper for older versions):

```
API Server                                   Redis Primary
     |                                            |
     | TLS ClientHello                            |
     | - SNI: redis-primary.internal             |
     | - Cipher suites: [TLS_AES_256_GCM_SHA384, |
     |     TLS_AES_128_GCM_SHA256]               |
     |------------------------------------------>|
     | TLS ServerHello + Certificate             |
     | - Internal CA-issued cert                 |
     | - Subject: redis-primary.internal         |
     |<------------------------------------------|
     | TLS Finished                              |
     |------------------------------------------>|
     | [Encrypted Redis RESP protocol]           |
     | SET key value EX 60                       |
     |------------------------------------------>|
     | +OK                                       |
     |<------------------------------------------|
```

**Client certificate authentication (mutual TLS):** In high-security environments, Redis requires clients to present certificates too (mTLS). Only API servers with valid internal certificates can connect to Redis. This prevents a rogue process from connecting to Redis directly if it somehow gains network access to the Redis port.

---

### Network Flow for an Incoming User Request

```
CLIENT (Alex's App)         CDN (Cloudflare)          API SERVER             REDIS
      |                           |                         |                   |
      | HTTPS GET /products        |                         |                   |
      |-------------------------->|                         |                   |
      |                           | [WAF check passed]      |                   |
      |                           | [Not cached — forward]  |                   |
      |                           | TCP to API server       |                   |
      |                           |------------------------>|                   |
      |                           |                         |  TCP (persistent   |
      |                           |                         |  pool connection)  |
      |                           |                         |----→ (existing connection)
      |                           |                         |                   |
      |                           |                         | EVALSHA lua_script|
      |                           |                         | "rl:user:alex:min"|
      |                           |                         | 1000 (limit)       |
      |                           |                         |------------------>|
      |                           |                         |                   | [Execute Lua]
      |                           |                         |                   | [INCR counter]
      |                           |                         |                   | [Check limit]
      |                           |                         |   [47, 1000]      |
      |                           |                         |<------------------|
      |                           |                         |                   |
      |                           |                         | [Allowed]         |
      |                           |                         | [Run business logic]
      |                           |                         | [DB query, etc.]  |
      |                           | 200 OK {products}       |                   |
      |                           |<------------------------|                   |
      | 200 OK {products}          |                         |                   |
      |<--------------------------|                         |                   |

Timings:
  Client to CDN: 30-80ms (internet)
  CDN to API Server: 1-5ms (internal network)
  API Server to Redis: 0.3-0.8ms (same datacenter)
  Business logic: 10-500ms (depends on endpoint)
  Total: ~50-600ms
```

---

## 3. Application Layer Flow

### The HTTP Request Lifecycle with Rate Limiting

Rate limiting middleware sits at the very beginning of the request processing pipeline — before authentication, before authorization, before business logic. This ordering is intentional and important.

**Why rate limit before authentication?**

```
Scenario: Attacker tries to brute-force authentication
  Option A: Authenticate first, then rate limit
    → Attacker must send valid auth headers
    → Auth system processes millions of bad auth requests
    → Auth service (database) gets hammered
    → The thing we're protecting is the thing doing the work

  Option B: Rate limit first, then authenticate
    → Reject after N attempts per IP/endpoint
    → Auth system never sees excessive load
    → Rate limiter does ~0.5ms of work per request
    → The thing we're protecting is shielded from load
```

**The middleware stack execution order:**

```javascript
// Express.js example - middleware registration order matters
app.use(requestId);              // 1. Assign request ID for tracing
app.use(basicHeaders);           // 2. Security headers, CORS pre-check
app.use(ipRateLimiter);          // 3. IP-based rate limit (FIRST security check)
app.use(globalRateLimiter);      // 4. Global/system-wide rate limit
app.use(authMiddleware);         // 5. Validate auth token (only if not rate limited)
app.use(userRateLimiter);        // 6. Per-user rate limit (needs auth to know user ID)
app.use(endpointRateLimiter);    // 7. Per-endpoint rate limit
app.use(router);                 // 8. Business logic (only reaches here if all pass)
```

**Why IP rate limit is checked before user rate limit:** An unauthenticated request has no user ID, so user-level rate limiting can't apply. IP-based rate limiting is the only defense against unauthenticated flood attacks (e.g., credential stuffing from many addresses, attempting to discover valid API keys).

---

### HTTP Methods, Headers, and Rate Limit Key Construction

Different HTTP methods get different treatment:

```
GET /v1/products           → Read operation, higher limit (1000/min)
POST /v1/orders            → Write operation, lower limit (60/min)
POST /v1/auth/login        → Authentication endpoint, very low limit (10/min)
DELETE /v1/account         → Destructive operation, very low limit (5/hour)
OPTIONS /v1/*              → CORS preflight, not rate limited (purely informational)
HEAD /v1/products          → Like GET but no body, same limit as GET
```

**Rate limit key construction (how the middleware identifies "who is making this request"):**

```python
def construct_rate_limit_key(request):
    keys = []

    # Always: IP-based key
    ip = get_real_ip(request)  # Handle X-Forwarded-For carefully
    keys.append(f"rl:ip:{ip}:{request.window}")

    # If authenticated: user/API key based
    if request.api_key:
        keys.append(f"rl:apikey:{request.api_key}:{request.window}")
    elif request.user_id:
        keys.append(f"rl:user:{request.user_id}:{request.window}")

    # Endpoint-specific
    endpoint = normalize_path(request.path)
    # /v1/users/123/profile → /v1/users/{id}/profile (parameterized)
    keys.append(f"rl:endpoint:{endpoint}:{request.window}")

    # Combined user + endpoint (most granular)
    if request.user_id:
        keys.append(f"rl:user:{request.user_id}:endpoint:{endpoint}:{request.window}")

    return keys

def get_real_ip(request):
    """
    Be careful with X-Forwarded-For — it can be spoofed.
    Trust only the headers your infrastructure sets.
    """
    # If behind Cloudflare, use CF-Connecting-IP (set by Cloudflare, not the client)
    if TRUST_CLOUDFLARE_HEADERS:
        return request.headers.get('CF-Connecting-IP')

    # If behind ALB or nginx, X-Real-IP is set by the proxy
    if TRUST_X_REAL_IP:
        return request.headers.get('X-Real-IP')

    # Fall through to direct connection IP
    return request.remote_addr
```

**The IP spoofing risk:** If your rate limiter uses `X-Forwarded-For` directly, an attacker can set `X-Forwarded-For: 1.2.3.4` and pretend to be a different IP. Always use the rightmost IP in X-Forwarded-For (the one added by YOUR proxy), or a header your trusted proxy sets that clients cannot set themselves (like Cloudflare's `CF-Connecting-IP`).

---

### Response Construction for Rate-Limited Requests

A well-formed 429 response contains specific headers that clients can use to back off gracefully:

```http
HTTP/2 429 Too Many Requests
Content-Type: application/json; charset=utf-8
Retry-After: 23
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1700000083
X-RateLimit-Reset-After: 23
X-RateLimit-Policy: 1000;w=60
RateLimit-Limit: 1000         (standardized header per RFC 6585 + draft-ietf-httpapi-ratelimit-headers)
RateLimit-Remaining: 0
RateLimit-Reset: 23           (seconds until reset, preferred over absolute timestamp)
Cache-Control: no-store
Content-Length: 187

{
  "error": "rate_limit_exceeded",
  "type": "https://docs.example.com/errors/rate-limit",
  "title": "Too Many Requests",
  "status": 429,
  "detail": "You have exceeded 1000 requests per 60-second window.",
  "retry_after": 23,
  "limit": 1000,
  "reset_at": "2024-11-15T10:30:23Z"
}
```

**The `Retry-After` header is required** (RFC 6585). It tells the client when to retry. Without it, a well-behaved client has no idea when to try again and might use exponential backoff that undershoots or overshoots the reset time.

**Why two header formats (`X-RateLimit-*` AND `RateLimit-*`):**
- `X-RateLimit-*` (de-facto standard): Used by GitHub, Twitter, Stripe — not standardized but widely understood
- `RateLimit-*` (emerging standard): Defined in IETF draft, standardizing the format
- Include both during the transition period

---

## 4. Backend Architecture

### Rate Limiting Algorithms — Deep Dive

There are five main algorithms. Understanding when to use each is crucial for interviews.

---

#### Algorithm 1: Fixed Window Counter

**Concept:** Divide time into fixed windows (e.g., 0:00-0:01, 0:01-0:02). Count requests in the current window. Reset at window boundary.

```
Time:  0:00    0:01    0:02    0:03
       |-------|-------|-------|
       [window1][window2][window3]

Window 1: requests = 0, 0, 100, 100... → limit is 100, window resets at 0:01

Window boundary spike problem:
  0:00:59 - 0:01:00: 100 requests (window 1 — allowed, counter reaches 100)
  0:01:00 - 0:01:01: 100 requests (window 2 — allowed, new counter starts at 0)

In that 2-second span: 200 requests slip through — double the limit!
```

**Redis implementation:**

```python
def fixed_window(key, limit, window_seconds):
    # Key includes window timestamp
    window_start = int(time.time() / window_seconds) * window_seconds
    window_key = f"{key}:{window_start}"

    pipe = redis.pipeline()
    pipe.incr(window_key)
    pipe.expire(window_key, window_seconds)
    current, _ = pipe.execute()

    return current <= limit, limit - current
```

**Pros:** Simple, O(1) time and space, easy to understand  
**Cons:** The "boundary spike" allows 2x the limit at window boundaries  
**Use when:** Soft limits are acceptable, simplicity matters, exact precision isn't critical

---

#### Algorithm 2: Sliding Window Log

**Concept:** For each user, maintain a log (sorted set) of all request timestamps. For each new request, count how many timestamps are within the last N seconds.

```
User's request log (Redis Sorted Set, score = timestamp):
  Score=1700000001.0: request
  Score=1700000023.5: request
  Score=1700000045.2: request
  Score=1700000058.9: request  ← current request

For a 60-second window at T=1700000059:
  Remove all entries older than T-60 = 1700000000 - 1 = 1699999999 (none to remove here)
  Count remaining entries: 4
  Compare to limit: 4 < 100 → allowed
```

**Redis implementation:**

```lua
-- Atomic Lua script for sliding window log
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local request_id = ARGV[4]  -- unique ID for this request (prevents duplicate entries)

-- Remove old entries outside the window
redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window)

-- Count current entries
local count = redis.call('ZCARD', key)

if count < limit then
    -- Add this request to the log
    redis.call('ZADD', key, now, request_id)
    redis.call('EXPIRE', key, window + 1)  -- TTL slightly > window
    return {1, count + 1, limit}  -- {allowed, new_count, limit}
else
    return {0, count, limit}  -- {denied, current_count, limit}
end
```

**Memory concern:** Each request adds one entry to the sorted set. A user making 1,000 requests/minute uses 1,000 entries in Redis. For 10 million active users → 10 billion entries. This doesn't scale.

**Pros:** Perfectly precise (no boundary spike), smooth enforcement  
**Cons:** Memory usage proportional to request count × users  
**Use when:** Precision matters, number of users is manageable, request rate is reasonable

---

#### Algorithm 3: Sliding Window Counter (Best for Most Cases)

**Concept:** Compromise between fixed window (memory efficient) and sliding window log (precise). Keep counts for two adjacent fixed windows. Interpolate based on position within the current window.

```
Time →  [Previous Window: 60s]  [Current Window: 60s]
        [count = 600]           [count = 200]
                                    ↑
                               Current position: 30s into window

Estimated requests in "sliding" 60-second window:
  From previous window: 600 × (60-30)/60 = 600 × 0.5 = 300
  From current window: 200
  Total estimate: 300 + 200 = 500

If limit is 600: 500 < 600 → allowed
```

**Why this is an approximation:** We're assuming previous window requests were uniformly distributed. In reality, they might have all come in the first second. But at scale, uniform distribution is a reasonable approximation.

**Redis implementation (production-grade):**

```lua
-- Sliding window counter (atomic Lua script)
local current_key = KEYS[1]   -- e.g., "rl:user:alex:2024111510"  (current minute)
local prev_key = KEYS[2]      -- e.g., "rl:user:alex:2024111509"  (previous minute)
local limit = tonumber(ARGV[1])
local window = tonumber(ARGV[2])    -- window size in seconds (e.g., 60)
local sub_window = tonumber(ARGV[3])  -- current position in window (e.g., 23 seconds)

-- Get counts for both windows
local prev_count = tonumber(redis.call('GET', prev_key) or 0)
local curr_count = tonumber(redis.call('GET', current_key) or 0)

-- Calculate weighted estimate
-- Weight of previous window decreases as we move through current window
local prev_weight = (window - sub_window) / window
local estimated_count = math.floor(prev_count * prev_weight) + curr_count

if estimated_count >= limit then
    return {0, estimated_count, limit}  -- denied
end

-- Increment current window counter
local new_curr = redis.call('INCR', current_key)
if new_curr == 1 then
    redis.call('EXPIRE', current_key, window * 2)  -- TTL for 2 windows
end

return {1, estimated_count + 1, limit}  -- allowed, new estimated count
```

**Pros:** O(1) space (only 2 counters per user per window), low error rate (typically <1% over-counting at boundaries)  
**Cons:** Slightly inaccurate (approximation)  
**Use when:** High-scale production systems, memory efficiency matters, slight approximation acceptable

---

#### Algorithm 4: Token Bucket

**Concept:** Each user has a "bucket" with capacity N tokens. Tokens refill at a constant rate R per second. Each request consumes one token. If bucket is empty, request is rejected.

```
Bucket capacity: 100 tokens
Refill rate: 10 tokens/second
Starting state: full (100 tokens)

Scenario: Burst then pause
  t=0s: 80 requests → bucket: 20 tokens remain
  t=2s: bucket refills to 40 tokens (2s × 10 tokens/s)
  t=2s: 30 requests → bucket: 10 tokens remain
  t=5s: bucket refills to 40 tokens (but capped at 100)

Burst allowance: A user can "save up" tokens and then burst.
Rate enforcement: Average rate cannot exceed R tokens/second.
```

**Redis implementation (using Lua for atomicity):**

```lua
-- Token bucket algorithm
local key = KEYS[1]
local capacity = tonumber(ARGV[1])  -- max bucket size
local rate = tonumber(ARGV[2])      -- tokens per second refill
local now = tonumber(ARGV[3])       -- current timestamp (milliseconds)

-- Get current bucket state
local bucket = redis.call('HMGET', key, 'tokens', 'last_refill')
local tokens = tonumber(bucket[1]) or capacity
local last_refill = tonumber(bucket[2]) or now

-- Calculate tokens added since last refill
local elapsed_seconds = (now - last_refill) / 1000.0
local new_tokens = math.min(capacity, tokens + (elapsed_seconds * rate))

-- Try to consume one token
if new_tokens >= 1 then
    new_tokens = new_tokens - 1
    redis.call('HSET', key, 'tokens', new_tokens, 'last_refill', now)
    redis.call('EXPIRE', key, math.ceil(capacity / rate) + 1)
    return {1, math.floor(new_tokens), capacity}  -- allowed
else
    -- Update refill timestamp even on rejection
    redis.call('HSET', key, 'tokens', new_tokens, 'last_refill', now)
    redis.call('EXPIRE', key, math.ceil(capacity / rate) + 1)
    return {0, 0, capacity}  -- denied
end
```

**Pros:** Allows controlled bursting (smooth for legitimate users with burst patterns), intuitive mental model  
**Cons:** Slightly complex implementation, state requires two fields per user  
**Use when:** Users have bursty but average-bounded traffic patterns (e.g., a user processes a batch of documents all at once, then is idle)

---

#### Algorithm 5: Leaky Bucket

**Concept:** Requests enter a queue (the bucket). They're processed at a constant rate. If the queue is full, new requests are rejected.

```
Queue capacity: 100 requests
Processing rate: 10 requests/second

Requests arrive: 50 burst requests at t=0
  → Queue fills to 50 (capacity allows it)
  → Processing at 10/second → queue empties at t=5s

80 more arrive at t=3s:
  → Queue has 20 remaining (50 original - 30 processed)
  → Can only add 80 more: 20 + 80 = 100 (at capacity)
  → No more requests accepted until queue processes some
```

**Key difference from token bucket:** Leaky bucket enforces a CONSTANT output rate. Token bucket allows bursts (as long as tokens are available). Leaky bucket makes bursty clients wait in queue rather than being rejected.

**Pros:** Enforces constant request rate to backend, smooths out bursty traffic  
**Cons:** Adds latency (requests must wait in queue), complex in distributed setting  
**Use when:** Protecting a backend that truly cannot handle variable rates (e.g., legacy system with fixed processing capacity)

---

### The Rate Limiting Architecture Overview

```
                        INCOMING REQUESTS (all API traffic)
                                      |
                           +----------v----------+
                           |  Load Balancer (ALB) |
                           +----------+----------+
                                      |
                +----------+----------+----------+
                |          |          |          |
         +------v--+  +----v----+  +--v------+  +--v------+
         |  API    |  |  API    |  |  API    |  |  API    |
         |  Svr 1  |  |  Svr 2  |  |  Svr 3  |  |  Svr N  |
         | [RL MW] |  | [RL MW] |  | [RL MW] |  | [RL MW] |
         +----+----+  +----+----+  +----+----+  +----+----+
              |            |            |            |
              |     ALL connect to SAME Redis Cluster
              |            |            |            |
         +----v------------v------------v------------v----+
         |                Redis Cluster                    |
         |   Shard 0      Shard 1      Shard 2            |
         |  (slots 0-5460)(5461-10922)(10923-16383)        |
         |                                                  |
         | Rate limit keys distributed by hash of user_id  |
         | Key: "rl:user:alex_123:minute"                  |
         |  → CRC16("rl:user:alex_123:minute") % 16384    |
         |  → slot 8432 → Shard 1                          |
         +--------------------------------------------------+

RL MW = Rate Limiting Middleware
```

**Why Redis Cluster instead of single Redis?**
- Single Redis: bottleneck at ~100,000 operations/second
- Redis Cluster (6 nodes): ~600,000 operations/second
- Each user's key goes to exactly one shard (based on hash)
- All API servers make atomic operations against the same shard for each user
- One shard per user = distributed across shards = horizontal scale

**Local cache within each API server (optional optimization):**

```python
class LocalRateLimitCache:
    """
    Optionally cache NEGATIVE rate limit decisions locally.
    If Redis says user X is rate limited, don't re-check Redis for 1 second.
    This reduces Redis load during abuse scenarios.
    """
    def __init__(self, ttl=1):
        self.cache = TTLCache(maxsize=10000, ttl=ttl)

    def is_blocked(self, key):
        return key in self.cache

    def mark_blocked(self, key):
        self.cache[key] = True

# During rate limiting:
if local_cache.is_blocked(rate_limit_key):
    return 429  # Don't even hit Redis

result = check_redis_rate_limit(rate_limit_key)
if result.denied:
    local_cache.mark_blocked(rate_limit_key)
    return 429
```

**Trade-off:** A blocked user might be unblocked in Redis (window reset) but still blocked locally for up to 1 second. Acceptable for most use cases.

---

### Sync vs Async Rate Limiting

**Synchronous (blocking) — default:**
- Rate limit check happens inline with request processing
- Request waits for Redis response before proceeding
- Adds ~0.5ms to every request
- 100% of requests are rate limited

**Asynchronous (non-blocking) — for extreme performance:**
- Rate limit check fires off asynchronously
- Request proceeds without waiting for Redis response
- Redis callback updates counters
- PROBLEM: If request is over limit, response has already been sent!
- Solution: Pre-check estimated count locally, do async precise check, accept slight over-limit

```python
# Async approach (approximation only, not recommended for strict enforcement)
async def handler(request):
    # Optimistic check against local approximate counter
    if local_counter.estimate_allowed(user_id):
        # Fire-and-forget async Redis update
        asyncio.create_task(redis_increment(user_id))
        # Process request immediately
        return await business_logic()
    else:
        return 429

# This allows up to ~10ms of over-limit requests before Redis confirms block
# Acceptable for performance-sensitive low-security endpoints
# NOT acceptable for security-critical endpoints (login, payments)
```

---

## 5. Authentication & Authorization Flow

### How Auth and Rate Limiting Interact

Rate limiting and authentication are intertwined but distinct:

```
Phase 1: Pre-auth rate limiting (before we know who the user is)
  Key: IP address
  Limit: Strict (e.g., 1000 requests/hour per IP)
  Purpose: Protect auth endpoints from enumeration and brute force

Phase 2: Auth validation
  Validate JWT or API key
  Extract user_id, tier, permissions

Phase 3: Post-auth rate limiting (now we know who the user is)
  Key: user_id or api_key
  Limit: Based on subscription tier
  Purpose: Fair usage enforcement, cost control

Phase 4: Permission-based rate limiting
  Key: user_id + endpoint + action
  Limit: Endpoint-specific business rules
  Purpose: Protect specific operations (e.g., limit bulk exports)
```

**The JWT claims used for rate limit tier determination:**

```json
{
  "sub": "user_alex_123",
  "iss": "https://auth.example.com",
  "aud": ["api.example.com"],
  "exp": 1700000900,
  "iat": 1700000000,
  "tier": "pro",
  "rate_limit_override": null,
  "org_id": "org_456",
  "org_tier": "enterprise"
}
```

The rate limiting middleware reads `tier` from the JWT claims and looks up the limit in a configuration table:

```python
TIER_LIMITS = {
    "free": {
        "requests_per_minute": 100,
        "requests_per_hour": 1000,
        "requests_per_day": 5000,
        "max_burst": 20
    },
    "pro": {
        "requests_per_minute": 1000,
        "requests_per_hour": 20000,
        "requests_per_day": 100000,
        "max_burst": 200
    },
    "enterprise": {
        "requests_per_minute": 10000,
        "requests_per_hour": 500000,
        "requests_per_day": 5000000,
        "max_burst": 2000
    }
}

def get_limit_for_request(request):
    tier = request.auth_claims.get('tier', 'free')
    # Enterprise orgs might have custom limits
    org_id = request.auth_claims.get('org_id')
    if org_id:
        custom_limit = db.get_org_custom_limit(org_id)  # Cached in Redis
        if custom_limit:
            return custom_limit
    return TIER_LIMITS.get(tier, TIER_LIMITS['free'])
```

---

### API Key Authentication vs. JWT for Rate Limiting

**API Keys (for server-to-server integrations):**
```
API Key: ak_prod_1a2b3c4d5e6f7g8h9i0j
Rate limit key: "rl:apikey:ak_prod_1a2b3c4d5e6f7g8h9i0j:minute"

Advantages:
- No expiry concerns (API keys persist)
- Simple to implement
- Easy to audit (which key made which request)

Disadvantages:
- If key is leaked, it stays valid until rotated
- Each key lookup requires a database/cache hit to get the associated user/org/tier
- Keys must be stored securely (encrypted in DB, masked in logs)
```

**Rate limiting by API key vs. by user ID:**

```python
def get_rate_limit_subject(request):
    # API Key: rate limit by key (allows multiple keys per user)
    if request.api_key:
        # Scenario: Same user has 3 API keys for different apps
        # Rate limit per key → each key gets full quota
        # OR: rate limit by user → all keys share one quota
        
        key_data = get_api_key_data(request.api_key)  # From Redis cache
        
        if key_data.rate_limit_scope == "KEY":
            return f"apikey:{request.api_key}"  # Per-key limit
        else:
            return f"user:{key_data.user_id}"   # Per-user (shared across keys)

    # JWT: rate limit by user ID
    if request.jwt_claims:
        return f"user:{request.jwt_claims['sub']}"

    # Unauthenticated: rate limit by IP
    return f"ip:{get_real_ip(request)}"
```

---

### Trust Boundaries for Rate Limit Bypass

**Scenarios where rate limiting should be bypassed (and how to do it safely):**

```
Scenario 1: Internal services calling the API
  Problem: Internal batch jobs might legitimately need >1000 req/min
  Solution: Internal service tokens (JWTs with "internal": true claim)
  Implementation: Rate limit middleware checks for internal claim → skip rate limit
  Risk: If an attacker forges an internal JWT → bypass
  Mitigation: Internal JWTs signed with separate key, only issued to internal services

Scenario 2: Health checks and monitoring
  Problem: Load balancer health checks would consume rate limit quota
  Solution: Health check endpoints (/health, /ready) are excluded from rate limiting
  Implementation: Middleware allowlist for specific paths
  Risk: Attacker uses /health path to bypass rate limit
  Mitigation: Health endpoints return 200 but have NO business logic to exploit

Scenario 3: Admin operations
  Problem: Support engineers need to process bulk user data operations
  Solution: Admin API on a different subdomain (admin.example.com) with different limits
  Implementation: Completely separate rate limiting configuration
  Risk: Admin API is a higher-value target
  Mitigation: Admin API requires MFA, IP allowlist, separate audit logging
```

---

## 6. Data Flow

### How Rate Limit State Flows Through the System

```
Request arrives at API Server
          |
          v
Middleware reads request metadata:
  - IP address (from X-Real-IP or CF-Connecting-IP)
  - User ID (from validated JWT sub claim)
  - API Key (from Authorization header)
  - Requested endpoint (URL path, normalized)
  - HTTP method
          |
          v
Key construction (happens in-process, no I/O):
  keys = [
    f"rl:ip:{ip}:minute",
    f"rl:user:{user_id}:minute",
    f"rl:user:{user_id}:endpoint:{endpoint}:minute",
    f"rl:global:minute"
  ]
          |
          v
Redis pipeline (single TCP write, single read):
  PIPELINE:
    EVALSHA {lua_script_hash} 4 key1 key2 key3 key4 limit1 limit2 limit3 limit4 now window
  
  Redis executes atomically for each key
  Returns: [{allowed, count, limit, ttl}, ...]
          |
          v
Middleware evaluates results:
  Any denied? → Return 429 immediately
  All allowed? → Proceed to business logic
          |
          v
Response includes rate limit headers:
  X-RateLimit-Limit: 1000
  X-RateLimit-Remaining: 953
  X-RateLimit-Reset: 1700000060
```

---

### Redis Data Structures by Algorithm

```
Algorithm: Sliding Window Counter
Data structure: String (integer)
Redis key: "rl:user:alex_123:2024111510"  (minute-precision timestamp)
Value: "47"
TTL: 120 seconds (2 windows worth)
Memory per user per window: ~50 bytes

Algorithm: Token Bucket
Data structure: Hash
Redis key: "rl:tb:user:alex_123"
Fields: {tokens: "89.5", last_refill: "1700000045.123"}
TTL: Set based on refill time (capacity / rate)
Memory per user: ~80 bytes

Algorithm: Sliding Window Log
Data structure: Sorted Set (ZSET)
Redis key: "rl:log:user:alex_123"
Members: request UUIDs, Score: timestamp
TTL: Window duration + buffer
Memory per user: ~50 bytes per request entry

Algorithm: Fixed Window
Data structure: String (integer)
Redis key: "rl:fw:user:alex_123:1700000000"  (window start timestamp)
Value: "47"
TTL: Window duration
Memory per user per window: ~40 bytes
```

### Serialization and Data Format

Rate limit configuration is stored in Redis (for dynamic updates) and serialized as:

```json
{
  "policy_id": "pro_tier_v2",
  "tier": "pro",
  "windows": [
    {"duration_seconds": 60, "limit": 1000, "algorithm": "sliding_window_counter"},
    {"duration_seconds": 3600, "limit": 20000, "algorithm": "fixed_window"},
    {"duration_seconds": 86400, "limit": 100000, "algorithm": "fixed_window"}
  ],
  "endpoints": {
    "/v1/auth/login": {"override_limit": 10, "override_window": 60},
    "/v1/bulk/*": {"override_limit": 5, "override_window": 60}
  },
  "burst_multiplier": 1.5,
  "updated_at": "2024-11-15T10:00:00Z"
}
```

This is stored in Redis at `config:rate_limit:pro` and cached in-process for 60 seconds. When the config is updated, the old cached value stays in effect for up to 60 seconds, then refreshes. For immediate updates, publish to a Redis pub/sub channel:

```python
# On config update:
redis.set(f"config:rate_limit:{tier}", json.dumps(new_config))
redis.publish("rate_limit_config_updated", tier)

# In each API server:
def on_config_update_message(tier):
    local_config_cache.invalidate(f"config:rate_limit:{tier}")
    logger.info(f"Rate limit config refreshed for tier: {tier}")
```

---

## 7. Security Controls

### Encryption

**In transit:**
```
External:
  Client → CDN/API Gateway: TLS 1.3, AES-256-GCM
  (Rate limit headers returned encrypted to client)

Internal:
  API Server → Redis: TLS 1.2+ with Redis TLS support
  Redis → Redis (cluster replication): TLS
  Config management → Redis: TLS
```

**At rest:**
```
Redis RDB snapshots (periodic dumps): Encrypted with AWS KMS
Redis AOF logs (append-only file): Encrypted at EBS/filesystem level
Rate limit configuration: Encrypted in Redis using application-layer encryption
  - Sensitive values (API keys, user IDs) stored as HMAC-SHA256 hashes
  - Never store plaintext API keys in rate limit keys
    BAD:  "rl:apikey:sk_prod_abcdef123456:minute"
    GOOD: "rl:apikey:sha256_hash_of_key:minute"
```

**Why hash the API key in the Redis key:**
If Redis is compromised, the attacker can list all rate limit keys. If the key contains the raw API key, they've extracted all active API keys. If it contains only the SHA-256 hash, they have hashes — computationally infeasible to reverse to the original key.

---

### Input Validation for Rate Limiting Parameters

The rate limiting system itself has attack surface:

```python
def validate_rate_limit_inputs(request):
    # IP address validation
    ip = request.headers.get('X-Real-IP', request.remote_addr)
    try:
        parsed_ip = ipaddress.ip_address(ip)
        # Reject: localhost, private ranges (if not expected)
        if parsed_ip.is_private and not ALLOW_PRIVATE_IPS:
            # This might indicate header injection
            raise ValueError(f"Unexpected private IP in rate limit key: {ip}")
    except ValueError:
        # Malformed IP — use a fallback or reject
        logger.warning("Malformed IP in request", ip=ip)
        ip = "0.0.0.0"  # Safe fallback

    # Path normalization (prevent cache key injection)
    path = request.path
    # Normalize: /v1/users/../admin → /admin (path traversal attempt)
    normalized_path = posixpath.normpath(path)
    # Only allow alphanumeric, /, -, _, {, } in paths
    if not re.fullmatch(r'[a-zA-Z0-9/_\-{}\[\]]+', normalized_path):
        raise ValueError(f"Invalid characters in path: {normalized_path}")

    # Limit key length (prevent Redis key injection)
    user_id = request.auth_claims.get('sub', '')
    if len(user_id) > 128 or not re.fullmatch(r'[a-zA-Z0-9_\-]+', user_id):
        raise ValueError(f"Invalid user_id format: {user_id}")
```

**Redis key injection attack:** If user_id is `admin_123:*` and you construct the key as `rl:user:admin_123:*:minute`, an attacker using a KEYS pattern in their user ID could potentially interfere with Redis operations (though modern Redis configurations restrict dangerous commands).

---

### Access Control for Rate Limit Administration

```
Who can change rate limits?

Role: Rate Limit Admin
  - Can modify tier limits
  - Can whitelist specific user IDs or API keys
  - Can trigger temporary rate limit bypass for an org
  - Requires: 2FA + senior engineer approval (via internal change management)
  - Audit: Every change logged with who/what/when/why

Role: Support Engineer
  - Can view current rate limit status for a user
  - Can reset a user's rate limit counter (emergency)
  - Cannot modify global limits
  - Audit: All admin API calls logged

Role: Developer
  - No rate limit admin access
  - Can view their own rate limit status via API
  - Cannot view other users' rate limits

Implementation: Separate admin API with stricter auth
  - API Key with admin scope: separate from regular API keys
  - IP allowlist: admin operations only from office IPs + VPN
  - Audit trail: immutable log of all admin operations
```

---

## 8. Attack Surface Mapping

### All Entry Points

```
EXTERNAL ENTRY POINTS:
────────────────────────────────────────────────────────────────────────

[E1] Public API Endpoints
  Every HTTP endpoint has a rate limit applied
  Attack surface: endpoint path parameters, query parameters, request body
  Rate limit keys: IP, API key, user ID, endpoint combination

[E2] Rate Limit Headers (Response)
  Attackers read X-RateLimit-* headers to learn your limits precisely
  Use to calibrate attacks: know exact when windows reset, stay just under limits

[E3] Admin Rate Limit API
  POST /admin/rate-limits/reset/{userId}    ← reset a user's counter
  GET  /admin/rate-limits/status/{userId}   ← view a user's current state
  PUT  /admin/rate-limits/config/tier       ← modify tier limits
  Attack surface: Admin credential theft, privilege escalation

[E4] Rate Limit Configuration (indirect)
  If config is loaded from environment or config files accessible to attackers
  Attacker reads limits, crafts requests at exactly limit-1 rate

INTERNAL ENTRY POINTS:
────────────────────────────────────────────────────────────────────────

[I1] Redis Cluster
  Accessible from all API servers
  If compromised: attacker can read all rate limit counters, modify counters,
    create fake rate limit data, delete keys to reset all limits

[I2] Rate Limit Configuration Storage
  Redis keys: config:rate_limit:*
  If compromised: change limits to 0 (deny all traffic) or infinity (allow all)

[I3] Lua Scripts in Redis
  Loaded into Redis via SCRIPT LOAD → returns SHA1 hash
  Called via EVALSHA → executes atomically
  If attacker can load malicious Lua: arbitrary code execution in Redis context

[I4] Message Queue / Config Pub/Sub
  Redis pub/sub channel for config updates
  If attacker can publish to this channel: force all servers to reload config
    from attacker-controlled values

[I5] Internal Metrics Endpoints
  Prometheus /metrics endpoint (if exposed)
  Reveals: current rate limit state, which users are being limited, Redis health
  Should be internal-only
```

### Attack Surface Diagram

```
                    ┌─────────────────────────────────────────────────────┐
                    │              EXTERNAL ATTACK SURFACE                │
                    │  [E1] All API Endpoints  [E2] Response Headers      │
                    │  [E3] Admin Rate Limit API  [E4] Config Endpoints   │
                    └───────────────────────────┬─────────────────────────┘
                                                │
                    ┌───────────────────────────▼─────────────────────────┐
                    │  CDN / WAF Layer [TB-1]                             │
                    │  DDoS protection, IP reputation, TLS termination    │
                    │  Can rate limit by IP at edge (before API servers)  │
                    └───────────────────────────┬─────────────────────────┘
                                                │
                    ┌───────────────────────────▼─────────────────────────┐
                    │  API Server Cluster [TB-2]                          │
                    │  Rate Limiting Middleware runs here                  │
                    │  ┌──────────┐  ┌──────────┐  ┌──────────┐          │
                    │  │ API Svr1 │  │ API Svr2 │  │ API SvrN │          │
                    │  │ [RL MW]  │  │ [RL MW]  │  │ [RL MW]  │          │
                    │  └────┬─────┘  └────┬─────┘  └────┬─────┘          │
                    │       └─────────────┴─────────────┘                │
                    │                     │                               │
                    │         All servers share state via Redis           │
                    └─────────────────────┬───────────────────────────────┘
                                          │
                    ┌─────────────────────▼───────────────────────────────┐
                    │  Redis Cluster [TB-3] — CRITICAL TRUST BOUNDARY     │
                    │  [I1] Counter storage  [I2] Config storage          │
                    │  [I3] Lua scripts      [I4] Pub/Sub channels        │
                    │                                                     │
                    │  Compromise here → bypass all rate limits           │
                    │  Security: TLS, mTLS, VPC-only, Redis AUTH          │
                    └─────────────────────────────────────────────────────┘

                    ┌─────────────────────────────────────────────────────┐
                    │  Admin API (separate surface) [TB-4]                │
                    │  [E3] Rate limit management                         │
                    │  Protected by: 2FA, IP allowlist, admin JWTs        │
                    │  Audit log: all changes immutably logged             │
                    └─────────────────────────────────────────────────────┘

TRUST BOUNDARIES:
  [TB-1] Internet → CDN: Zero trust, DDoS mitigation first
  [TB-2] CDN → API Servers: Trusted CDN headers, rate limit by verified IP
  [TB-3] API Servers → Redis: High trust, TLS + mTLS, VPC isolation
  [TB-4] Admin API: Strictest controls, separate network segment
```

---

## 9. Attack Scenarios (Very Detailed)

### 9.1 — Distributed Rate Limit Bypass (Most Common)

**Attacker Assumptions:**
- Rate limiting is per-IP only (no user/API-key dimension)
- Attacker has access to a botnet of 10,000 IP addresses
- Target: excessively call an expensive API endpoint to exhaust the service

**Step-by-Step Execution:**

1. Attacker probes the API: `GET /v1/products` from single IP → gets 429 after N requests. Learns limit is 100 requests/minute per IP.

2. Attacker acquires 10,000 residential proxy IPs (many services sell these for ~$0.01/IP).

3. Each IP sends 99 requests/minute (just under the limit).

4. Total throughput: 10,000 × 99 = 990,000 requests/minute — essentially unlimited.

5. The expensive backend (database, ML inference, search) gets overwhelmed.

**Where Detection Could Happen:**
- Total request volume metric: global requests/minute spikes to 990,000 (from baseline of 10,000)
- Multiple IPs in the same /24 subnet (residential proxies often come from the same subnet ranges)
- All IPs requesting the SAME endpoint (no variation — not organic traffic)
- Request patterns identical (same User-Agent, same Accept headers, no Cookie variation)

**Why This Works:**
The defender is playing defense per-IP. The attacker is attacking globally. The attacker's dimensionality (IP space) is larger than the defender's measurement dimension.

**Why Pure IP Rate Limiting Always Fails:**
An IP address is not a reliable proxy for identity. Multiple users share IPs (NAT, IPv6 sharing). Attackers rotate IPs. The cardinality of IPs is much larger than the cardinality of API keys or user IDs.

**Mitigation:**
1. Rate limit by user/API key as the primary dimension (not IP)
2. Add global rate limiting (e.g., max 100,000 requests/minute total regardless of IPs)
3. Anomaly detection: alert when requests to a single endpoint from >100 distinct IPs spike simultaneously
4. Require authentication for expensive endpoints (can't bypass with IP rotation if you need a valid API key)

---

### 9.2 — Rate Limit Precision Attack (Staying Just Under the Limit)

**Attacker Assumptions:**
- API returns `X-RateLimit-Remaining` header
- Attacker wants to call the API at maximum possible rate without triggering 429
- Target: scrape user data at maximum speed

**Step-by-Step Execution:**

1. Attacker reads the rate limit headers from any response: `X-RateLimit-Limit: 1000`, `X-RateLimit-Reset: 1700000060`.

2. Attacker calculates optimal call rate: 1000 requests per 60 seconds = 16.67 requests/second.

3. Attacker implements a precise client:
   ```python
   while True:
       response = api_call()
       remaining = int(response.headers['X-RateLimit-Remaining'])
       reset_time = int(response.headers['X-RateLimit-Reset'])
       
       if remaining < 5:
           # Nearly at limit — wait for reset
           sleep_seconds = max(0, reset_time - time.time())
           time.sleep(sleep_seconds)
       else:
           # Continue at optimal rate
           time.sleep(1 / 16.67)  # ~60ms between calls
   ```

4. The attacker scrapes data at maximum allowed rate: 1000 requests/minute continuously, 24/7.

5. In 24 hours: 1,440,000 requests → extracts 1.44 million data points.

**Where Detection Could Happen:**
- Consistent 999 requests/minute, never 1001 (too perfect — organic traffic has variance)
- Same data accessed in sequential order (user IDs 1, 2, 3, 4... not random)
- Requests every 60 seconds exactly (window reset exploitation)

**Why This Is Hard to Stop:**
The attacker IS within the rate limit. This is legitimate API usage from the API's perspective. The issue is the INTENT (scraping), not the mechanism.

**Mitigation:**
1. **Progressive delays:** After 80% of limit used, add 50ms artificial latency to responses. Legal users rarely notice; scrapers are slowed significantly.
2. **Adaptive limits:** If a user consistently hits 95-99% of their limit for 5+ consecutive windows, automatically lower their limit or flag for review.
3. **Behavioral analytics:** Detect sequential ID access patterns — legitimate users access data they care about (random access), scrapers access everything sequentially.
4. **CAPTCHA for suspicious patterns:** When pattern matches known scraping behavior, require CAPTCHA before continuing.
5. **Data access policies:** Separate API for bulk data access, requiring agreement and audit.

---

### 9.3 — Redis Compromise → Rate Limit Nullification

**Attacker Assumptions:**
- Attacker has gained network access to the Redis port (e.g., via SSRF vulnerability in an application, or misconfigured security group)
- Redis is not protected with authentication
- Attacker wants to remove rate limiting for all users

**Step-by-Step Execution:**

1. Attacker discovers Redis at `10.0.1.10:6379` via SSRF or reconnaissance.

2. Attacker connects directly: `redis-cli -h 10.0.1.10 -p 6379` (no password required — misconfigured).

3. Attacker can now:
   ```
   # Delete all rate limit counters (resets everyone's limits)
   redis-cli FLUSHDB  # Deletes ALL keys in the database

   # Or selectively reset one user's limit
   redis-cli DEL "rl:user:attacker_user:minute"

   # Or modify the limit configuration
   redis-cli SET "config:rate_limit:free" '{"limit": 1000000}'

   # Or inject a malicious Lua script
   redis-cli SCRIPT LOAD "return redis.call('FLUSHALL')"
   # Returns SHA1, which can then be called via EVALSHA
   ```

4. Attacker removes their own rate limit: `DEL "rl:user:attacker_user:*"` (SCAN-based deletion of all their keys).

5. Attacker can now make unlimited requests without being rate limited.

**Where Detection Could Happen:**
- Redis `AUTH` failure logs (if authentication is enabled and attacker doesn't have the password)
- Redis MONITOR command output logged by a monitoring agent: `FLUSHDB` command appears in logs
- Alert: Redis DBSIZE drops suddenly from 50,000 keys to 0 (FLUSHDB detected)
- Alert: Direct connection to Redis port from IP not in API server subnet
- Alert: `SCRIPT LOAD` command executed (should only happen at deployment time, not runtime)

**Why Redis Is Critical:**
Redis is the ground truth for all rate limit state. If Redis is compromised, the entire rate limiting system is compromised simultaneously — not just for one user, for everyone.

**Mitigation:**
1. **Redis AUTH:** Always require password (`requirepass` in redis.conf). Use 64+ character random password.
2. **TLS + client certificate:** Only allow connections with valid client certificates.
3. **VPC security groups:** Redis port (6379 or 6380) only accessible from API server security group IDs — not from the internet, not from other services.
4. **Rename/disable dangerous commands:** `rename-command FLUSHALL ""` (disables it), `rename-command FLUSHDB ""`, `rename-command SCRIPT ""`
5. **Redis ACLs (Redis 6+):** Per-user command restrictions
   ```
   ACL SETUSER api_server on >password123 ~rl:* +EVALSHA +EXPIRE +GET +SET +INCR
   # api_server user can only access keys starting with "rl:" and only specific commands
   ```

---

### 9.4 — Race Condition: Atomic Operation Bypass

**Attacker Assumptions:**
- Rate limiting uses non-atomic operations (separate GET and SET instead of Lua script)
- Attacker can send many requests simultaneously from different connections

**The Vulnerable Code (what NOT to do):**

```python
# VULNERABLE: Non-atomic implementation
def check_rate_limit_WRONG(user_id, limit):
    count = redis.get(f"rl:{user_id}")  # Step 1: GET
    count = int(count or 0)
    if count >= limit:
        return False  # Rate limited

    redis.incr(f"rl:{user_id}")        # Step 2: INCR
    # GAP BETWEEN STEP 1 AND STEP 2 ← race condition here
    return True
```

**Attack:**

1. Rate limit is 100 requests/minute. Current count is 99.

2. Attacker opens 200 simultaneous connections, all sending requests at the same instant.

3. All 200 connections execute Step 1 (GET) concurrently — all see count = 99.

4. All 200 connections pass the `count >= 100` check (99 < 100).

5. All 200 connections execute Step 2 (INCR) — counter becomes 299.

6. 200 requests executed against a limit of 100.

**Why This Works:**
Redis is single-threaded for command execution, but between the GET and INCR in the Python code, other Redis commands from other connections execute. The rate limit check and the counter increment are NOT atomic.

**Atomic Solution:**

```lua
-- This Lua script executes atomically — no other Redis command runs between these operations
local key = KEYS[1]
local limit = tonumber(ARGV[1])
local window = tonumber(ARGV[2])

local count = redis.call('INCR', key)  -- INCR and check in one operation

if count == 1 then
    redis.call('EXPIRE', key, window)
end

if count > limit then
    return {0, count, limit}  -- denied
end
return {1, count, limit}  -- allowed
```

**Why Lua scripts are atomic in Redis:**
Redis executes Lua scripts with the interpreter blocked. No other Redis commands can run while a Lua script is executing. This is guaranteed by Redis's single-threaded architecture. The INCR + check + EXPIRE sequence is treated as one indivisible operation.

**Where Detection Could Happen:**
- Counter value significantly exceeds configured limit (count = 299 when limit = 100)
- Many requests from the same user_id in the same millisecond (time-clustering)

---

### 9.5 — Amplification Attack Using Rate Limit Headers

**Attacker Assumptions:**
- Attacker can see rate limit response headers (including for other users, if headers are misconfigured)
- Target: extract information about other users' API usage patterns

**Step-by-Step Execution:**

1. Attacker notices that the rate limit key is based on the `user_id` from the JWT, which is `user_123`.

2. If the API has a "check rate limit status" endpoint: `GET /v1/rate-limit-status?user_id=user_456`

3. If the response reveals user_456's remaining requests, the attacker learns:
   - Is user_456 currently active? (If remaining = limit, they haven't used the API recently)
   - How many requests has user_456 made? (Can infer activity patterns)
   - Is user_456 making a burst? (Remaining drops rapidly = they're actively using the API)

4. This is an information disclosure — rate limit state as a side channel.

**Why This Works:**
Rate limit state can reveal behavioral information. An attacker monitoring a competitor's API usage can correlate rate limit consumption with business activity (e.g., "Company B's API usage spiked by 500% before their product launch announcement").

**Mitigation:**
1. Rate limit status endpoint only reveals the requesting user's own status, never another user's
2. Never include identifiable information (user ID, email) in rate limit keys visible to users
3. Consider not exposing `X-RateLimit-Remaining` at all (trade-off: less user-friendly but less information disclosure)
4. Audit access to rate limit status endpoints

---

## 10. Failure Points

### Under Load

**Redis connection pool exhaustion:**

```
At 50,000 requests/second:
  Each request needs one Redis round-trip (~0.5ms)
  Concurrent Redis connections needed: 50,000 × 0.0005s = 25 connections

But if Redis is slow (1ms instead of 0.5ms):
  50,000 × 0.001s = 50 connections needed
  Connection pool limit: 50 → requests WAIT for connections
  Queue builds up → latency spikes → timeouts → 503 errors

The rate limiter, designed to protect the API, itself fails and takes the API down.
```

**Redis cluster rebalancing during high load:**

When a Redis Cluster node fails and is replaced, the cluster rebalances hash slots. During rebalancing (can take 1-5 minutes for large clusters), some rate limit keys may be temporarily inaccessible:

```
Key "rl:user:alex_123:minute" is on Shard 1 (slots 5461-10922)
Shard 1 fails → Failover to replica (promotion takes 10-30 seconds)

During failover:
  API server tries to access key → CLUSTERDOWN error
  
Options:
  1. Fail open: allow request (rate limit not enforced for ~30 seconds)
  2. Fail closed: reject all requests with 503 (no rate limit info = deny all)
  3. Fail partial: use local in-memory approximation during Redis outage
```

**Lua script eviction from Redis script cache:**

```
Redis caches compiled Lua scripts by their SHA1 hash.
The cache can be flushed (by SCRIPT FLUSH or Redis restart).

If API server calls EVALSHA with a hash that's no longer cached:
  Redis returns: NOSCRIPT No matching script
  API server must call EVAL to re-register the script
  If EVAL is disabled (rename-command EVAL ""), this fails permanently

Solution: Script cache warm-up at deployment
  API servers call SCRIPT LOAD at startup
  If NOSCRIPT error received, automatically reload script
  Never rely on EVALSHA without fallback to EVAL
```

---

### Under Attack

**Redis slow operations blocking rate limit checks:**

```
Attacker sends KEYS * to Redis (if they have access)
  KEYS * is O(N) where N is the number of keys
  With 10 million rate limit keys, KEYS takes 2-5 seconds
  During those 2-5 seconds, ALL Redis commands block
  All API servers' rate limit checks fail

Solution:
  - Disable KEYS command: rename-command KEYS ""
  - Use SCAN instead of KEYS (non-blocking, iterates in chunks)
```

**Memory exhaustion via key proliferation:**

```
Attack: Create millions of unique API keys → each makes 1 request → creates millions of Redis keys

Each rate limit key: ~50 bytes
10 million keys: 500 MB (exceeds Redis maxmemory)
Redis hits maxmemory → starts evicting keys using LRU policy

If rate limit keys get evicted:
  → User's counter is lost
  → Redis INCR on non-existent key starts at 1
  → Rate limit is effectively reset for users whose keys were evicted
  → Attacker's keys are never evicted (they keep using them) but legitimate users lose their state

Solution:
  - Set Redis maxmemory to a value with headroom above expected key count
  - Use maxmemory-policy: volatile-lru (evict keys with TTL set — rate limit keys have TTL)
  - Set appropriate TTLs on ALL rate limit keys
  - Alert at 70% memory usage before hitting maxmemory
```

---

### Common Misconfigurations

| Misconfiguration | Impact | Fix |
|---|---|---|
| Rate limiting by `X-Forwarded-For` directly | IP spoofing bypass — attacker sets any IP | Use only `X-Real-IP` set by your trusted proxy |
| No authentication on Redis | Anyone on the network resets all rate limits | `requirepass` + VPC security groups |
| `FLUSHALL` / `FLUSHDB` commands enabled | Attacker or accident resets all counters | `rename-command FLUSHALL ""` |
| Non-atomic GET+SET instead of Lua | Race condition allows exceeding limits | Use INCR or Lua scripts for atomicity |
| Fail-closed without fallback | Redis outage → 100% of traffic blocked | Implement fail-open with local estimation |
| Rate limit key includes plaintext API key | API key enumeration from Redis | Hash all sensitive values in keys |
| Same Redis instance for rate limiting and sessions | Rate limit Lua script blocks session reads | Separate Redis instances per function |
| No per-endpoint limits, only per-user | Expensive endpoint DDoS'd while user is under limit | Add endpoint-specific limits for expensive operations |
| `X-RateLimit-Remaining` shows other users' data | Privacy violation, information disclosure | Enforce user can only see their own rate limit status |
| Rate limit config hot-reloaded without validation | Bad config input disables all limits | Validate config schema before applying |
| Clock skew between API servers | Window boundaries differ per server | Use Redis server time (TIME command) not local clock |

---

## 11. Mitigations

### Defense-in-Depth Strategy

**Layer 1: Edge / CDN (Cheapest to apply)**
```
Cloudflare Rate Limiting:
  - 10 rules per zone free, more with paid plan
  - Rate limit by: IP, ASN, country, user agent, URL path
  - Runs at edge (200+ global PoPs) before traffic hits your servers
  - Can absorb millions of requests/second at the edge
  - Cost: fractions of a cent per 10,000 requests checked

Actions: Challenge (CAPTCHA), Block (429), Log
Use for: Volumetric DDoS, known bad IP ranges, obvious bots
```

**Layer 2: API Gateway / Load Balancer**
```
nginx rate limiting (ngx_http_limit_req_module):
  limit_req_zone $binary_remote_addr zone=api:10m rate=100r/m;
  limit_req zone=api burst=20 nodelay;

This provides:
  - 100 requests/minute per IP
  - Burst of 20 (can exceed briefly)
  - nodelay: don't queue burst requests, process immediately or reject

Kong/AWS API Gateway built-in rate limiting:
  - Policy-based limits
  - Redis-backed for distributed enforcement
  - Configurable per route, per consumer
```

**Layer 3: Application Middleware (Most Granular)**
```
Multi-dimensional limits:
  Per IP → catch bots without accounts
  Per API key → fair usage enforcement
  Per user → subscription tier enforcement
  Per endpoint → protect expensive operations
  Per user+endpoint → most granular control

Algorithm choice by use case:
  Login endpoints: Fixed Window (simple, prevent brute force)
  General API: Sliding Window Counter (memory efficient, accurate enough)
  Streaming/uploads: Token Bucket (allow bursts, control average)
```

**Layer 4: Business Logic**
```
Even if rate limit checks pass, business logic can enforce additional constraints:
  - Pagination: never return more than 100 results per page
  - Search: limit to simple queries (no wildcard expansion)
  - Export: rate limit exports separately, require background job for large exports
  - Webhooks: limit failed retry attempts
```

---

### Engineering Tradeoffs

| Approach | Pro | Con |
|---|---|---|
| Fixed Window | Simple, O(1) space | Boundary spike allows 2x limit |
| Sliding Window Log | Perfectly accurate | O(limit) space per user |
| Sliding Window Counter | Accurate enough, O(1) | ~5% error at boundaries |
| Token Bucket | Allows controlled bursts | More complex state (2 fields) |
| Leaky Bucket | Constant output rate | Adds latency for queued requests |
| Fail-open | High availability | Attackers exploit outages |
| Fail-closed | No bypass during outage | Legitimate traffic blocked |
| Local cache + Redis | Lower Redis load | 1-2 second inconsistency window |
| Redis only | Consistent | Higher latency, Redis SPOF |
| Per-IP limiting | Simple, no auth needed | Easily bypassed with IP rotation |
| Per-user limiting | Hard to bypass | Requires authentication first |

---

## 12. Observability

### Structured Logging

```json
// Rate limit check log (every request, sampled at 1% for non-429)
{
  "timestamp": "2024-11-15T10:30:45.123Z",
  "event": "rate_limit.check",
  "level": "info",
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "user_id": "user_alex_123",
  "ip_hash": "sha256:a1b2c3...",  // Hashed for privacy
  "api_key_prefix": "ak_prod_1a2b",
  "endpoint": "/v1/products",
  "method": "GET",
  "result": "allowed",
  "checks": [
    {
      "key": "rl:ip:hash:minute",
      "limit": 10000,
      "count": 47,
      "remaining": 9953,
      "ttl_seconds": 23
    },
    {
      "key": "rl:user:user_alex_123:minute",
      "limit": 1000,
      "count": 47,
      "remaining": 953,
      "ttl_seconds": 23
    }
  ],
  "redis_duration_ms": 0.8,
  "algorithm": "sliding_window_counter"
}

// Rate limit exceeded log (always logged, never sampled)
{
  "timestamp": "2024-11-15T10:30:46.456Z",
  "event": "rate_limit.exceeded",
  "level": "warn",
  "request_id": "a1b2c3d4-e5f6-...",
  "user_id": "user_alex_123",
  "ip_hash": "sha256:a1b2c3...",
  "endpoint": "/v1/products",
  "method": "GET",
  "result": "denied",
  "violated_check": {
    "key": "rl:user:user_alex_123:minute",
    "limit": 1000,
    "count": 1001,
    "remaining": 0,
    "reset_at": "2024-11-15T10:31:00Z"
  },
  "response_code": 429,
  "consecutive_violations": 47,
  "severity": "ABUSE_SUSPECTED"
}

// Redis error log (circuit breaker / failover)
{
  "event": "rate_limit.redis_error",
  "level": "error",
  "error_type": "ConnectionError",
  "redis_node": "10.0.1.10:6380",
  "fallback_used": "fail_open",
  "requests_allowed_without_check": 1,
  "alert": true
}
```

**What NEVER appears in logs:**
- Raw API keys (use hashed prefix: `ak_prod_1a2b...` → log only first 8 chars)
- Raw user IDs in high-volume logs (hash them for privacy)
- Rate limit Redis keys with sensitive data embedded
- User IP addresses in plain text (GDPR concern — hash or partially mask)

---

### Metrics

```
# Prometheus-style metrics for rate limiting

# Counter: Total rate limit checks by outcome
rate_limit_checks_total{result="allowed|denied", algorithm="sliding_window_counter|fixed_window|token_bucket", tier="free|pro|enterprise"}

# Counter: Total rate limit violations by dimension
rate_limit_violations_total{dimension="ip|user|api_key|endpoint|global", tier="free|pro|enterprise"}

# Histogram: Redis operation latency
rate_limit_redis_duration_seconds{operation="evalsha|eval|get|set"} # histogram with buckets

# Gauge: Current rate limit utilization (sampled per user)
rate_limit_utilization_ratio{user_id="*"}  # percentage of limit consumed
# Alert if many users are consistently above 80%

# Counter: Redis errors and fallback activations
rate_limit_redis_errors_total{error_type="timeout|connection_refused|noscript|oom"}
rate_limit_fallback_activations_total{fallback_type="fail_open|local_cache|degraded"}

# Gauge: Redis memory usage
rate_limit_redis_memory_used_bytes{shard="0|1|2|3|4|5"}
rate_limit_redis_key_count{type="rl|config|script"}

# Histogram: Rate limit check impact on request latency
rate_limit_added_latency_seconds  # Time added to each request for rate limit check

# Business metrics
rate_limit_top_violators_requests_per_minute  # Top 10 users by violation count
rate_limit_false_positives_reported  # When users report legitimate requests blocked
```

---

### Distributed Traces

```
Trace: GET /v1/products [user_alex_123] [150ms total]
├── Middleware: RequestID Assignment [0.1ms]
├── Middleware: IP Rate Limit Check [0.5ms]
│   ├── Span: Redis EVALSHA (ip check) [0.3ms]
│   │   - redis.host: 10.0.1.11
│   │   - redis.key_count: 1
│   │   - redis.result: allowed
│   └── Result: allowed (47/10000 used)
├── Middleware: Auth Validation [2ms]
│   ├── Span: JWT Verification [1.5ms]
│   └── Span: JWKS Key Fetch (cache hit) [0ms]
├── Middleware: User Rate Limit Check [0.5ms]
│   ├── Span: Redis EVALSHA (user check) [0.4ms]
│   │   - redis.host: 10.0.1.12
│   │   - redis.key_count: 3  (minute + hour + endpoint)
│   │   - redis.result: allowed
│   └── Result: allowed (47/1000 used)
├── Handler: Get Products [146ms]
│   ├── Span: Cache Check (Redis) [0.3ms] → MISS
│   ├── Span: Database Query [120ms]
│   ├── Span: Cache Write (Redis) [0.3ms]
│   └── Span: Response Serialization [5ms]
└── Middleware: Rate Limit Header Injection [0.1ms]
    - X-RateLimit-Remaining: 953
    - X-RateLimit-Reset: 1700000060
```

---

### Alerting Rules

| Metric / Condition | Severity | Threshold | Action |
|---|---|---|---|
| `rate_limit_redis_errors_total` rate > 0 | HIGH | Any sustained errors | PagerDuty — Redis health check |
| `rate_limit_redis_duration_seconds` p99 > 5ms | MEDIUM | > 5ms p99 | Alert — Redis overloaded |
| `rate_limit_violations_total` spike > 10x baseline | HIGH | 10x in 5 minutes | Alert — possible DDoS |
| `rate_limit_redis_memory_used_bytes` > 80% of max | HIGH | > 80% | Alert — approaching OOM |
| `rate_limit_fallback_activations_total` > 0 | HIGH | Any fallback used | Alert — Redis connectivity issue |
| Single user violating limit > 1000 times in 1 minute | CRITICAL | > 1000 violations/min | Block user + security alert |
| Global `rate_limit_checks_total` drops to 0 | CRITICAL | 0 checks processed | Middleware failed entirely — alert |
| IP with > 100 distinct users all being rate limited | HIGH | 100+ users from one IP | NAT detection or coordinated attack |
| Redis master election (failover) | MEDIUM | Any failover | Alert — verify rate limits resumed |
| Normal rate limit violations (user hit limit) | No alert | — | Log only |
| `rate_limit_remaining` headers being served | No alert | — | Expected behavior |

---

## 13. Scaling Considerations

### The Fundamental Scaling Tension

Rate limiting introduces a new component (Redis) on the critical path of every API request. The challenge:

- Too few Redis nodes → bottleneck, high latency
- Too many Redis nodes → complexity, shard rebalancing overhead
- Local-only → can't do distributed rate limiting
- Remote-only → adds latency to every request

**The math:**

```
At 100,000 requests/second:
  Rate limit check: 1 Redis round-trip per request = 0.5ms each
  Total Redis throughput: 100,000 × 1 = 100,000 operations/second

Single Redis node capacity: ~100,000-200,000 simple operations/second
  → At 100,000 req/s, a single Redis node is near capacity

But: Lua script is not a simple operation
  Lua scripts take longer to execute than simple GET/SET
  Realistic capacity per node: ~50,000 Lua evaluations/second

→ At 100,000 req/s, need 2+ Redis nodes for rate limiting alone
→ At 1,000,000 req/s, need 20+ Redis nodes
```

---

### Redis Cluster Sharding Strategy

```
6-node Redis Cluster (3 masters, 3 replicas):
  Master 0: slots 0-5460    (33% of keyspace)
  Master 1: slots 5461-10922 (33% of keyspace)
  Master 2: slots 10923-16383 (34% of keyspace)

Key distribution:
  "rl:user:alice_123:minute"
  → CRC16("rl:user:alice_123:minute") % 16384
  → 3847 → Master 0

  "rl:user:bob_456:minute"
  → CRC16("rl:user:bob_456:minute") % 16384
  → 8901 → Master 1

Each user's rate limit key goes to exactly one master.
All API servers' checks for user alice_123 go to Master 0.
No coordination needed between masters for a given user's rate limit.
```

**Hash tags for related keys on the same shard:**

```python
# When you want multiple keys on the same shard (for multi-key Lua atomicity):
# Use hash tags: {content_in_braces} determines the slot

# These all go to the same shard (slot determined by "user_alex_123"):
"rl:{user_alex_123}:minute"
"rl:{user_alex_123}:hour"
"rl:{user_alex_123}:day"

# Without hash tags, these might be on different shards:
"rl:user_alex_123:minute" → shard 0
"rl:user_alex_123:hour"   → shard 1  ← different shard!
"rl:user_alex_123:day"    → shard 2  ← different shard again!

# A multi-key Lua script across different shards fails with:
# CROSSSLOT Keys in request don't hash to the same slot
```

---

### Horizontal Scaling of API Servers (Rate Limiting Perspective)

When you add more API servers, the rate limiting system scales naturally:

```
Initial: 4 API servers, 100,000 req/s total = 25,000 req/s per server
  Redis load: 100,000 operations/second (rate limit checks)

Scale to: 20 API servers, 500,000 req/s total = 25,000 req/s per server
  Redis load: 500,000 operations/second (rate limit checks)
  → Must scale Redis proportionally

Scale Redis too:
  Expand from 3-master cluster to 6-master cluster
  Capacity: doubles
  Rebalancing time: ~30-60 minutes (online, no downtime)
  Rate limit keys migrate between masters during rebalancing
```

**What happens during Redis cluster expansion:**

```
Before: 3 masters (slots 0-5460, 5461-10922, 10923-16383)
Adding master 3:

Step 1: Add master 3 as empty node (slots: none)
Step 2: Migrate slots 0-1820 from master 0 to master 3
  During migration, slot 0 requests:
    → Sent to master 0
    → Master 0 returns MOVED 3 <master3_ip>:<port>
    → Client reconnects to master 3
    → No requests dropped, latency spike (extra redirect)
Step 3: Migrate slots 5461-7281 from master 1 to master 3
Step 4: Migrate slots 10923-13742 from master 2 to master 3

After: 4 masters (0-3639, 3640-7280, 7281-10922, 10923-16383)
```

The rate limiting keys during migration: counters are migrated with their TTLs intact. No counter loss. But there's a brief period of extra latency (one additional network hop for the MOVED redirect).

---

### Consistency Tradeoffs

**Strong consistency (all API servers agree on the count):**
```
Every rate limit check goes to Redis → always consistent
But: Redis becomes single point of failure for consistency
     If Redis is slow (GC pause, network latency), every request is slow
     Typical: 0.5ms overhead per request

Tradeoff: Perfectly consistent, but performance-sensitive to Redis health
```

**Approximate consistency (local + Redis hybrid):**
```
Each API server maintains a local counter:
  Every 100ms: push local counter to Redis ("+N")
  Pull global counter from Redis
  Use: local_estimate = redis_count + local_pending

Trade-off:
  10 API servers, each waiting 100ms between syncs
  In 100ms at 10,000 req/s: 1,000 requests per server
  Local pending: 1,000
  Possible over-limit: 10 × 1,000 = 10,000 extra requests before sync
  
  For a limit of 1,000/minute: 10x overshoot possible
  
Benefit: If Redis is down, can operate for 100ms on local state
Benefit: Much lower Redis throughput (batch updates vs per-request)
Cost: Rate limits are soft (can exceed by up to 10x temporarily)
```

**The practical recommendation:**
- Login and payment endpoints: Strong consistency (NEVER use approximate)
- General API endpoints: Approximate is acceptable (a user briefly exceeding 5% over limit is not catastrophic)
- Monitoring/health endpoints: No rate limiting needed

---

## 14. Interview Questions

### Q1: "Explain the race condition in a distributed rate limiter and how to solve it atomically."

**Answer:**

The race condition occurs when the check (GET) and increment (INCR) are separate Redis operations:

```
Thread A: GET counter → 99 (below 100 limit)
Thread B: GET counter → 99 (below 100 limit, sees same stale value)
Thread A: INCR → 100 ✓
Thread B: INCR → 101 ← exceeded limit, but Thread B already decided to allow it
```

Both threads saw count=99 and decided to proceed, but the actual count is now 101.

**Solutions:**

1. **Use INCR then check:** Atomic increment first, then check the result:
   ```lua
   count = redis.call('INCR', key)
   if count > limit then return denied end
   return allowed
   ```
   INCR is always atomic in Redis. If count > limit after increment, deny AND decrement (or just deny and let the count be slightly high — the key expires anyway).

2. **Lua script for multi-step atomicity:** If you need read-modify-write with multiple steps (e.g., check AND update a token bucket with two fields), use a Lua script. Redis executes Lua scripts atomically — no other command can interleave.

3. **Redis GETSET / SET with NX and GET:** For more complex state, Redis 6.2+ added `GETDEL` and `GETEX` for atomic compound operations.

**Why if you INCR first then check, you'll over-decrement:**
```lua
local count = redis.call('INCR', key)
if count > limit then
    redis.call('DECR', key)  -- Undo the increment
    return denied
end
```
This is still slightly wrong — between INCR and DECR, another thread could see count > limit and also decide to DECR, resulting in the count going negative. Lua script avoids this entirely.

---

### Q2: "Why use a Sliding Window Counter instead of a Sliding Window Log? When would you choose each?"

**Answer:**

**Sliding Window Log:**
- Stores every request's timestamp in a sorted set
- Memory: O(requests_per_user × window_duration) — potentially millions of entries
- Accuracy: Perfect — counts exact timestamps
- Redis data structure: ZSET (sorted set)

**Sliding Window Counter:**
- Stores only two counters: previous window count and current window count
- Memory: O(1) per user — two integer keys
- Accuracy: Approximation (~5% error at window boundaries)
- Redis data structure: Two strings (integers)

**Choose Sliding Window Log when:**
- You have a small number of users (< 10,000 active simultaneously)
- Each user has a low request rate (< 100/window)
- Perfect accuracy is required (billing, compliance)
- Memory is not a constraint

**Choose Sliding Window Counter when:**
- You have millions of users (memory efficiency critical)
- High request rates per user (thousands/window)
- ~5% error at boundaries is acceptable
- This is the typical production choice

**The math on why:**
- 1 million users × 100 requests/window in Sliding Window Log: 100M Redis entries × 50 bytes = 5GB
- 1 million users × Sliding Window Counter: 2M Redis keys × 30 bytes = 60MB

---

### Q3: "What happens when Redis is unavailable? Explain the fail-open vs fail-closed tradeoff in detail."

**Answer:**

When the rate limiting Redis cluster is unreachable from API servers, you have two choices:

**Fail Closed (deny all uncertain requests):**
```
Redis unavailable → treat all requests as rate-limited → return 503

Pros: Never allows an attacker to bypass rate limits during outage
      Safer for security-critical endpoints (payments, auth)
Cons: Legitimate users can't use the API during Redis outage
      Even a 10-second Redis blip = 10 seconds of downtime

When to use: Login endpoints, payment operations, any endpoint where
             unlimited access is catastrophic
```

**Fail Open (allow all requests during outage):**
```
Redis unavailable → allow all requests through → log the uncertainty

Pros: Service remains available even when rate limiting fails
      Users can still use the product
Cons: Attacker can trigger Redis issues to bypass rate limits
      Could overwhelm backends during the outage window

When to use: Read endpoints (GET products, GET profile), endpoints where
             temporary unlimited access is acceptable
```

**Hybrid approach (production recommendation):**

```python
def check_rate_limit(user_id, limit):
    try:
        result = redis.evalsha(lua_hash, 1, key, limit, window)
        return result
    except RedisError as e:
        logger.error("Redis unavailable for rate limit", error=e)
        metrics.increment('rate_limit.redis_error')

        if is_security_critical_endpoint(request.path):
            # Fail closed for sensitive endpoints
            return RateLimitResult(allowed=False, count=None, limit=limit,
                                   reason="rate_limit_unavailable")
        else:
            # Fail open for regular endpoints, use local memory estimate
            local_count = local_counter.get_and_increment(user_id, window)
            if local_count > limit * FAIL_OPEN_MULTIPLIER:  # e.g., 2x limit locally
                return RateLimitResult(allowed=False, ...)
            return RateLimitResult(allowed=True, count=local_count, limit=limit,
                                   uncertain=True)  # Flag as uncertain
```

The `uncertain=True` flag allows monitoring to detect how often the fallback is activated. If it's activated for >1% of requests over 5 minutes, that's an alert-worthy event.

---

### Q4: "Describe Token Bucket vs Leaky Bucket. When would a burst-tolerant API prefer Token Bucket?"

**Answer:**

**Token Bucket:**
- Bucket has capacity C tokens
- Tokens refill at rate R per second (up to capacity C)
- Each request consumes 1 token
- If bucket is empty: reject request
- Key property: **allows bursting** up to capacity C

**Leaky Bucket:**
- Requests enter a queue
- Queue is processed at constant rate R per second
- If queue is full (capacity C): reject new arrivals
- Key property: **enforces constant output rate**, smooths bursts

**Burst-tolerant scenario (token bucket wins):**

```
Use case: Mobile app user syncs offline changes when reconnecting to WiFi

Offline for 2 hours → 120 pending operations
Reconnects → App bursts 120 requests in 5 seconds to sync

Token Bucket (capacity=200, refill=10/s):
  Bucket accumulated during idle time: min(200, 2hr × 10/s) = 200 tokens
  5-second burst of 120 requests: uses 120 tokens → allowed ✓
  After burst: 80 tokens remain, refill at 10/s
  
Leaky Bucket (queue_size=200, rate=10/s):
  120 requests enter queue
  Processed at 10/s → takes 12 seconds for all to complete
  User waits 12 seconds for sync to complete instead of 5 ✗

Result: Token bucket gives the user immediate sync with their 2 hours of saved tokens.
        Leaky bucket adds artificial delay even though the backend could handle the burst.
```

**Constant-output scenario (leaky bucket wins):**

```
Use case: Sending webhooks to a customer's endpoint that can only handle 10/s

Token Bucket: Customer has large burst capacity, can spike to 500/s momentarily
  → Customer's endpoint gets overwhelmed, webhooks fail

Leaky Bucket: Always delivers exactly 10 webhooks/second
  → Customer's endpoint is protected, all webhooks delivered reliably

Result: Leaky bucket is correct here — you're protecting a downstream consumer.
```

**Practical note:** Token bucket is more commonly used in API rate limiting because it provides better UX (bursts are natural) while still enforcing average rate. Leaky bucket is used for outgoing rate limiting (protecting external services you call, or third-party webhook consumers).

---

### Q5: "How would you implement rate limiting for an API that serves both individual users and enterprise organizations where the whole org shares a limit?"

**Answer:**

This is the "hierarchical rate limiting" problem. The structure:

```
Global limit
  ↓ (subset of global)
Organization limit (e.g., 50,000 req/min for Org A)
  ↓ (subset of org limit)
Individual user limit (e.g., 1,000 req/min per user in Org A)

Constraints:
1. A single user cannot exceed their individual limit (1,000/min)
2. All users in an org combined cannot exceed the org limit (50,000/min)
3. The org limit is distinct from and not a multiple of individual limits
   (Org might have 200 users × 1,000 = 200,000 theoretical max, but org limit is 50,000)
```

**Implementation with hierarchical key checking:**

```python
def check_hierarchical_rate_limit(request):
    user_id = request.auth.user_id
    org_id = request.auth.org_id

    # All keys to check in one pipeline
    checks = []

    # Level 1: Individual user limit
    checks.append({
        "key": f"rl:user:{user_id}:minute",
        "limit": get_user_limit(user_id),
        "dimension": "user"
    })

    # Level 2: Organization limit (if user is in an org)
    if org_id:
        checks.append({
            "key": f"rl:org:{org_id}:minute",
            "limit": get_org_limit(org_id),
            "dimension": "org"
        })

    # Level 3: Global limit (system-wide protection)
    checks.append({
        "key": "rl:global:minute",
        "limit": GLOBAL_LIMIT,
        "dimension": "global"
    })

    # Execute all checks atomically in Redis pipeline
    # Use Lua script that checks ALL limits before incrementing ANY
    lua_result = redis.eval(hierarchical_lua_script,
                            len(checks),
                            *[c["key"] for c in checks],
                            *[c["limit"] for c in checks])

    # Find the first denied dimension
    for i, (result, check) in enumerate(zip(lua_result, checks)):
        allowed, count, limit = result
        if not allowed:
            return RateLimitResult(
                allowed=False,
                violated_dimension=check["dimension"],
                count=count,
                limit=limit
            )

    return RateLimitResult(allowed=True)
```

**The hierarchical Lua script (atomic across all limits):**

```lua
-- Check ALL limits before incrementing ANY
-- If any limit is exceeded, do nothing and return which one failed
local num_checks = tonumber(ARGV[1])
local keys = {}
local limits = {}

for i = 1, num_checks do
    keys[i] = KEYS[i]
    limits[i] = tonumber(ARGV[i + 1])
end

-- First pass: check all current values
local counts = {}
for i = 1, num_checks do
    counts[i] = tonumber(redis.call('GET', keys[i]) or 0)
end

-- Check all limits
for i = 1, num_checks do
    if counts[i] >= limits[i] then
        return {0, i, counts[i], limits[i]}  -- {denied, which_key, count, limit}
    end
end

-- All checks passed: increment all counters
for i = 1, num_checks do
    local new_count = redis.call('INCR', keys[i])
    if new_count == 1 then
        redis.call('EXPIRE', keys[i], 60)
    end
end

return {1, 0, 0, 0}  -- {allowed, _, _, _}
```

**Edge case — the "last request" race:** If the org limit is 50,000 and 1,000 users each send their 1,000th request simultaneously (all checking when org count is 49,000), they all pass the check and all INCR, getting to 50,000 + 1,000 = 51,000. The hierarchical Lua script above handles this correctly because it checks first (all 1,000 might see count=49,000 < 50,000) and then increments, but the INCR of 1,000 simultaneous requests will each atomically increment — there's still a race here.

**Better solution for high-concurrency:** Use a "reservation" pattern with Lua:

```lua
-- Increment first, then check
-- If over limit, decrement and return denied
local count = redis.call('INCR', keys[1])
if count > limits[1] then
    redis.call('DECR', keys[1])
    return {0, count, limits[1]}
end
-- ... same for other keys
```

This ensures at most `limit + num_concurrent_requests` requests get through during a burst — bounded overshoot, not unbounded.

---

### Q6: "What are the memory implications of different rate limiting algorithms at scale? How would you design a system for 100 million users?"

**Answer:**

**Memory analysis at scale:**

```
100 million users, each with:
  - 3 time windows: minute, hour, day
  - 2 dimensions: user ID + endpoint

Fixed Window Counter (simplest):
  - 2 keys per user per window: "rl:user:{id}:minute", "rl:user:{id}:hour"
  - Total keys: 100M × 2 dimensions × 3 windows = 600M keys
  - Per key: ~60 bytes (key name + value + Redis overhead)
  - Total: 600M × 60 bytes = 36 GB

  But: Not all 100M users are active simultaneously
  Active users (1% of 100M = 1M active):
  Total: 6M keys × 60 bytes = 360 MB

Sliding Window Log:
  - 1,000 requests/user/window (max), stored as ZSET entries
  - Each entry: ~50 bytes (UUID + timestamp)
  - Per user, per window: 1,000 × 50 bytes = 50 KB
  - 1M active users: 1M × 50 KB = 50 GB
  IMPOSSIBLE at this scale.

Sliding Window Counter (production choice):
  - 2 counter keys per user per window: ~30 bytes each
  - 1M active users × 3 windows × 2 keys = 6M keys × 30 bytes = 180 MB
  FEASIBLE.

Token Bucket:
  - 1 hash per user (2 fields: tokens + last_refill): ~80 bytes
  - 1M active users: 80 MB
  VERY FEASIBLE.
```

**Design for 100M users:**

1. **Use Sliding Window Counter or Token Bucket** — proven to fit in memory.

2. **Redis Cluster sizing:**
   - 180 MB for rate limit data across 1M active users
   - Typical Redis node: 32-128 GB RAM
   - Single large Redis node could hold this
   - But: for availability and throughput, use 6-node cluster minimum
   - 6 nodes × 32 GB = 192 GB capacity → can handle 1B+ active users

3. **TTL discipline:**
   - Every key MUST have a TTL (set in the Lua script)
   - Keys for inactive users expire → memory reclaimed automatically
   - Without TTLs: 100M users' keys would accumulate even if they never return
   - With 60s TTL on minute counters: only active-in-last-60s users consume memory

4. **Key design for minimal memory:**
   ```
   User IDs as compact integers, not UUIDs:
     UUID key: "rl:user:550e8400-e29b-41d4-a716-446655440000:minute" = 65 bytes
     Integer key: "rl:u:12345678:m" = 15 bytes
     Savings: 77% reduction in key name storage
   ```

5. **Compression of inactive data:**
   - Actively used keys: in Redis memory (fast access)
   - Keys with low TTL (expiring soon): Redis will evict these first anyway
   - Consider tiering: very recent counters in Redis, historical in a cheap store (if needed for analytics)

---

### Q7: "How does clock skew between API servers affect rate limiting? How do you handle this?"

**Answer:**

**The problem:**

```
API Server 1 (clock: 10:00:59.999)
API Server 2 (clock: 10:01:00.001)

For a fixed window rate limiting with 1-minute windows:
  Server 1 thinks current window is "10:00:00" → key: "rl:user_alex:2024111510:00"
  Server 2 thinks current window is "10:01:00" → key: "rl:user_alex:2024111510:01"

They're using DIFFERENT keys!

User Alex sends 100 requests to Server 1: counter A = 100 (at limit)
User Alex sends 100 more requests to Server 2: counter B = 100 (at limit)
Actual total: 200 requests, but each server thinks only 100 happened.

Even a 1ms clock skew can cause a window boundary mismatch.
```

**Solutions:**

**Solution 1: Use Redis server time (not local server time):**

```lua
-- At the start of the Lua script, get Redis's own clock
local redis_time = redis.call('TIME')
-- redis.call('TIME') returns [seconds, microseconds] of Redis server's clock
local now_seconds = tonumber(redis_time[1])
local window_start = now_seconds - (now_seconds % window_size)
local key = prefix .. ':' .. window_start
```

Since all API servers use the Redis server's clock (via the TIME command in Lua), they all compute the same window_start regardless of their local clock drift. Redis's clock is the single source of truth for time.

**Caveat:** Redis server's clock can also drift, but it's one clock (consistent) rather than N clocks (potentially divergent). NTP must be configured for the Redis servers.

**Solution 2: Sliding Window Counter eliminates the window boundary problem:**

The sliding window counter doesn't have discrete windows — it continuously estimates. A 1ms clock difference causes at most a 1ms difference in the "current position in the window" calculation, leading to ~0.001% error in the estimated count. Negligible.

**Solution 3: Use monotonic clocks and synchronized NTP:**

Ensure all API servers sync to the same NTP source. AWS, GCP, and Azure provide reliable NTP via their instance metadata services. Clock skew of <1ms is achievable. For fixed window rate limiting, keys are typically minute-granularity — 1ms skew is negligible at minute granularity.

**Solution 4: Overlap window transitions:**

```python
# When near a window boundary, use conservative counting
def near_boundary(now, window_size, threshold=2):
    """Return True if we're within `threshold` seconds of a window boundary."""
    position_in_window = now % window_size
    return position_in_window < threshold or position_in_window > (window_size - threshold)

if near_boundary(time.time(), window_size=60, threshold=2):
    # Within 2 seconds of boundary: count against BOTH windows
    check_both_current_and_next_window(key)
```

---

*Document version: 1.0 | Classification: Internal Engineering | Author: Platform Engineering Team*  
*Covers production-grade distributed rate limiting from algorithm theory to operational practices.*
