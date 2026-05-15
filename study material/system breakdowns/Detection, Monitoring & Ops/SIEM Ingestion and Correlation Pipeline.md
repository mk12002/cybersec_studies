# SIEM Ingestion and Correlation Pipeline: Deep Engineering & Security Breakdown

> **Document Type:** Internal Engineering / Security Reference
> **Classification:** Internal — Engineering & Security Teams
> **Scope:** End-to-end system analysis — raw log bytes to correlated alert, trust boundaries to attack trees
> **Audience:** Engineers, security analysts, architects, interview candidates

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

### The Story: "An SSH brute-force attack triggers a P1 alert"

This document traces a complete operational scenario: 500 failed SSH login attempts against a production Linux host over 60 seconds. The SIEM must ingest raw syslog, parse and normalize each event, correlate them into a pattern, generate an alert, and surface it to an analyst — all before the attacker succeeds on attempt 501.

---

### Step-by-Step Sequence

**T=0s — Attack begins. First SSH failure logged.**

An attacker begins an automated SSH brute-force against `prod-web-01.internal`. OpenSSH writes to syslog:

```
May 15 12:00:01 prod-web-01 sshd[12345]: Failed password for invalid user admin
  from 203.0.113.45 port 54321 ssh2
May 15 12:00:01 prod-web-01 sshd[12345]: Failed password for invalid user root
  from 203.0.113.45 port 54321 ssh2
```

The OS writes these to `/var/log/auth.log` (Debian/Ubuntu) or to the kernel's syslog ring buffer, which rsyslog/syslog-ng reads via a Unix domain socket at `/dev/log`.

**T=0s–1s — Log collector on the host picks up the event**

A log collector agent (Filebeat, Fluentd, or Splunk UF) is running on `prod-web-01`. It:
1. Tails `/var/log/auth.log` via inotify kernel notifications (NOT polling — polling adds latency and wastes CPU)
2. Detects new lines appended to the file
3. Reads the raw line bytes
4. Applies a minimal local transform: add metadata fields (`hostname`, `agent.version`, `source.file`, `timestamp_collected`)
5. Buffers the event locally (in memory or on disk depending on config) before shipping

**The agent does NOT parse the syslog message format yet.** It ships raw or lightly enriched bytes to the ingestion pipeline. Parsing happens centrally — this is intentional. If parsing logic changes, you update the central parser, not 10,000 agents.

**T=1s — Agent ships event to log aggregator/collector tier**

The agent establishes a TLS connection to a Logstash/Kafka/Fluentd aggregator node. The raw syslog line is encoded in the agent's wire format (Lumberjack protocol for Beats, HTTP/JSON for Fluentd, Kafka protocol for direct Kafka producers) and sent with an acknowledgment flow:

- Agent sends event batch
- Aggregator acknowledges receipt (writes to Kafka or its own buffer)
- Agent marks events as shipped, advances its file read position (cursor/offset)
- If the network is down, the agent holds the cursor and buffers locally (backpressure handling)

This at-least-once delivery guarantee is fundamental. Events must not be lost if the network fails. The agent persists its offset file (`/var/lib/filebeat/registry`) — if the agent restarts, it reads from the last committed offset.

**T=1s–3s — Event enters Kafka ingestion topic**

The aggregator publishes the raw event to Kafka topic `logs.raw` partition determined by hash of `hostname` (ensures all events from one host go to the same partition — important for ordering within a host). The raw event in Kafka looks like:

```json
{
  "kafka_offset": 8823419,
  "kafka_partition": 4,
  "received_at": "2024-05-15T12:00:01.123Z",
  "agent_host": "prod-web-01",
  "agent_type": "filebeat",
  "raw_message": "May 15 12:00:01 prod-web-01 sshd[12345]: Failed password for invalid user admin from 203.0.113.45 port 54321 ssh2",
  "source_file": "/var/log/auth.log"
}
```

**T=3s–5s — Parsing and normalization pipeline**

A stream processing worker (Logstash pipeline, Kafka Streams app, or Flink job) consumes from `logs.raw`. For this syslog event, it applies:

1. **Syslog RFC 3164 parser:** Extract `timestamp`, `hostname`, `program` (sshd), `pid` (12345), `message`
2. **SSH failure pattern match:** Regex or grok pattern matches "Failed password for (invalid user )? `<user>` from `<ip>` port `<port>`"
3. **Field extraction:** `user=admin`, `src_ip=203.0.113.45`, `src_port=54321`, `auth_method=password`, `outcome=failure`
4. **ECS normalization (Elastic Common Schema):** Map extracted fields to standard schema:
   - `source.ip = "203.0.113.45"`
   - `user.name = "admin"`
   - `event.outcome = "failure"`
   - `event.category = ["authentication"]`
   - `event.type = ["start"]`
   - `event.action = "ssh-login-failure"`
5. **GeoIP enrichment:** Look up `source.ip` in MaxMind GeoLite2 database (embedded in worker): `source.geo.country_iso_code = "RU"`, `source.geo.city_name = "Moscow"`
6. **Threat intel enrichment:** Check `source.ip` against threat intelligence feed (Redis lookup, TTL 1 hour): `threat.indicator.type = "brute_force"` (if IP is in threat feed)
7. **Host context enrichment:** Look up `prod-web-01` in CMDB (asset database): `host.role = "web_server"`, `host.environment = "production"`, `host.criticality = "high"`

The normalized event is published to Kafka topic `logs.normalized`.

**T=5s–8s — Event written to hot storage (Elasticsearch)**

An Elasticsearch indexing worker consumes from `logs.normalized` and bulk-indexes events into time-based indices (e.g., `logs-2024.05.15`). The event is now searchable by analysts in the SIEM UI.

**Simultaneously (T=0s–60s):** 499 more failed SSH events from the same source IP are processed through the same pipeline.

**T=60s–62s — Correlation engine fires**

The correlation engine (a stateful stream processor — Flink, Spark Streaming, or a dedicated SIEM correlation service) processes the `logs.normalized` stream. It maintains a stateful window:

```
Rule: SSH_BRUTE_FORCE_001
  Window: 60 seconds (sliding)
  Group by: (destination_host, source_ip)
  Condition: count(event.action == "ssh-login-failure") >= 10
  Action: generate ALERT
```

The state store for this rule maintains a count per (host, source_ip) tuple, incremented for each failure event. At count=10 (or 500 in this scenario), the rule fires.

**T=62s — Alert generated and written**

The correlation engine generates an alert event:

```json
{
  "alert_id": "alert_8f4a2c1e",
  "rule_id": "SSH_BRUTE_FORCE_001",
  "severity": "high",
  "title": "SSH Brute Force Detected",
  "description": "500 failed SSH login attempts from 203.0.113.45 to prod-web-01 in 60s",
  "source_ip": "203.0.113.45",
  "destination_host": "prod-web-01",
  "attack_count": 500,
  "window_start": "2024-05-15T12:00:01Z",
  "window_end": "2024-05-15T12:01:01Z",
  "mitre_tactic": "TA0006",
  "mitre_technique": "T1110.001",
  "risk_score": 85,
  "supporting_event_ids": ["evt_001", "evt_002", "..."]
}
```

The alert is written to `alerts` Elasticsearch index AND published to `siem.alerts` Kafka topic for downstream consumers (SOAR, ticketing, notification service).

**T=62s–65s — Analyst receives notification**

The notification service consumes from `siem.alerts` and:
- Sends PagerDuty webhook (P1 alert → on-call analyst paged immediately)
- Sends Slack message to `#security-alerts` channel
- Creates a Jira ticket
- (Optional) Triggers SOAR playbook: automatically run an IP reputation check, pull the firewall's existing rules for this IP, query whether this IP has hit other hosts

**T=65s — Analyst opens SIEM dashboard**

The analyst clicks the alert in the SIEM UI. The UI makes an API call to fetch:
1. Alert details (from `alerts` index)
2. Supporting events (the 500 raw events — from `logs` index)
3. Timeline view (all events from/to this IP in the last 24 hours)
4. Threat intelligence summary (enrichment data)
5. Related assets (other hosts the source IP has touched)

The analyst sees a complete picture — without this pipeline, they'd be looking at individual log lines with no correlation.

**What the user (analyst) sees vs. what actually happens:**

```
Analyst sees:                           What actually happened:
──────────────────────────────────────  ─────────────────────────────────────────────────────
PagerDuty alert at T+65s               500 syslog lines → inotify → Filebeat → TLS →
                                        Kafka → stream processor → grok parse → GeoIP lookup
                                        → threat intel Redis lookup → CMDB lookup →
                                        Elasticsearch index → sliding window counter →
                                        alert event → Kafka → 3 notification channels
                                        → SOAR playbook triggered

"500 attempts in 60 seconds"           Stateful Flink window with 60s tumbling/sliding
                                        boundary, count aggregation keyed by (host, src_ip)

Threat intel badge "Known bad IP"       Redis lookup against STIX/TAXII feed pulled 47 min
                                        ago, result cached with 1-hour TTL

"Viewing supporting events"            Elasticsearch query: filter by alert_id or
                                        (source.ip AND destination.host AND time_range)
                                        — returns 500 raw normalized events from hot index

MITRE technique "T1110.001"            Hard-coded in rule definition; correlation engine
                                        attaches MITRE tags from rule metadata
```

---

## 2. Network Layer Flow

### Overview of Network Paths in a SIEM

A SIEM has multiple distinct network paths, unlike most systems. Understanding which path you're analyzing matters:

1. **Log ingestion path:** Source host agent → Kafka/Logstash collector (high volume, unidirectional data flow)
2. **API path:** Analyst browser → SIEM UI backend → Elasticsearch (interactive queries)
3. **Alert notification path:** SIEM → PagerDuty/Slack/SOAR (outbound webhooks)
4. **Threat intel pull path:** SIEM → external TAXII/STIX servers (periodic sync)

This section focuses on **Path 1 (log ingestion)** as it is the highest-volume, most critical path.

---

### DNS Resolution for Log Ingestion

```
Log Agent (prod-web-01)           Corporate DNS           Auth NS (SIEM zone)
        │                               │                         │
        │── query: kafka.siem.internal ─▶│                         │
        │                               │── query auth NS ────────▶│
        │                               │◀─ A: 10.0.50.10 ─────────│
        │◀─ 10.0.50.10, TTL=30 ─────────│                         │
```

**SIEM-specific DNS considerations:**

- Log collector endpoints use internal DNS (`kafka.siem.internal`, `logstash.siem.internal`) — never public DNS
- TTL of 30–60 seconds allows rapid failover to backup collectors without requiring agent reconfiguration
- Agents should be configured with static IP fallbacks in case DNS is unavailable — DNS failure must not stop log collection (logs are security evidence; loss is unacceptable)
- DNS-over-TLS or DNS-over-HTTPS is NOT typically used for internal DNS in most enterprise environments — the internal DNS server itself is trusted (VPC DNS resolver at the VPC base address)

---

### TCP 3-Way Handshake (Agent to Kafka Broker)

```
Log Agent (prod-web-01)                 Kafka Broker (10.0.50.10:9093)
        │                                               │
        │── SYN (seq=ISN_a) ────────────────────────────▶│
        │   [TCP options: MSS=1460, SACK, Timestamps]    │
        │                                               │
        │◀── SYN-ACK (seq=ISN_k, ack=ISN_a+1) ──────────│
        │                                               │
        │── ACK (ack=ISN_k+1) ──────────────────────────▶│
        │                                               │
        │   [TLS handshake begins]                      │
        │                                               │
        │   [Long-lived connection established]         │
        │   [Filebeat/Kafka producer reuses this        │
        │    connection for thousands of log events     │
        │    — NOT one TCP connection per log line]     │
```

**Critical SIEM networking behavior:**

Log agents maintain **persistent, long-lived TCP connections** to collectors. Unlike web browsers that may open many short-lived connections, a Filebeat agent typically has 1–3 persistent connections to its Kafka or Logstash endpoints. All log events from that agent flow through those connections.

**Implications:**
- Connection establishment cost is amortized across millions of events
- A TCP connection reset (RST) causes a brief gap in log delivery — the agent reconnects and resumes from its persisted offset
- Long-lived connections can be silently dropped by firewalls/NAT (idle timeout). TCP keepalive must be configured: `net.ipv4.tcp_keepalive_time=60` on the agent OS. Without keepalive, a firewall may silently drop the connection after 30 minutes of inactivity; the agent discovers this only when it tries to write the next event — potentially hours later.

---

### TLS Handshake (Mutual TLS for Log Ingestion)

The log ingestion path uses **mutual TLS (mTLS)** — both the agent and the Kafka broker present certificates. This is critically important: without mTLS, a compromised host could inject fabricated logs into the SIEM.

```
Log Agent (Filebeat)                         Kafka Broker
        │                                         │
        │── ClientHello ──────────────────────────▶│
        │   TLS 1.3, X25519 key share              │
        │   ALPN: kafka                            │
        │   SNI: kafka.siem.internal               │
        │                                         │
        │◀── ServerHello ─────────────────────────│
        │    Chosen: TLS_AES_256_GCM_SHA384        │
        │    Server's X25519 key share             │
        │                                         │
        │◀── {Certificate} ───────────────────────│  ← encrypted
        │    Subject: CN=kafka-broker-01           │
        │    Issuer: SIEM Internal CA              │
        │    SAN: kafka.siem.internal              │
        │                                         │
        │◀── {CertificateRequest} ────────────────│  ← server requests client cert
        │    Acceptable CAs: [SIEM Internal CA]   │
        │                                         │
        │◀── {Finished} ──────────────────────────│
        │                                         │
        │── {Certificate} ────────────────────────▶│  ← agent presents its cert
        │   Subject: CN=prod-web-01.internal       │
        │   Issuer: SIEM Internal CA               │
        │   Extensions: hostname, agent_type        │
        │                                         │
        │── {CertificateVerify} ──────────────────▶│
        │   Signature over handshake transcript    │
        │                                         │
        │── {Finished} ───────────────────────────▶│
        │                                         │
        │══ Kafka protocol over TLS begins ════════│
```

**Why mTLS for log ingestion:**

Without client certificate validation, anyone on the network who can reach the Kafka broker can inject arbitrary log messages. This is catastrophic for a SIEM — an attacker who can inject logs can:
- Flood the SIEM with noise to hide their actual activity
- Inject fake "clean" events to overwrite evidence of their attack
- Trigger false alerts to distract the SOC team

With mTLS, the Kafka broker validates that the agent's certificate was issued by the SIEM's internal CA. Only hosts with a valid cert (provisioned by the cert management system at host enrollment) can publish logs.

**Certificate lifecycle:**

Agent certificates are issued with a 90-day validity by the SIEM Internal CA. The cert management system (HashiCorp Vault PKI, or AWS ACM Private CA) auto-renews 30 days before expiry. If auto-renewal fails and the cert expires, the agent cannot connect to Kafka — logs stop flowing from that host silently. Cert expiry monitoring (alert at 30 days before expiry) is non-optional.

---

### Full Network Architecture Diagram

```
SOURCE HOSTS (thousands)               COLLECTION TIER             PROCESSING TIER
┌────────────────────────┐            ┌──────────────────────────────────────────────────┐
│                        │            │                                                  │
│  prod-web-01           │  mTLS/9093 │  ┌────────────────────────────────────────────┐  │
│  [Filebeat agent]      │───────────▶│  │  Kafka Cluster                             │  │
│  reads: /var/log/      │            │  │  ┌──────────┐ ┌──────────┐ ┌───────────┐  │  │
│  auth.log via inotify  │            │  │  │ Broker 1 │ │ Broker 2 │ │ Broker 3  │  │  │
│                        │            │  │  │ 9093(TLS)│ │ 9093(TLS)│ │ 9093(TLS) │  │  │
│  prod-db-01            │            │  │  └────┬─────┘ └──────────┘ └───────────┘  │  │
│  [Filebeat agent]      │───────────▶│  │       │                                    │  │
│                        │            │  │  Topics:                                   │  │
│  corp-fw-01            │  syslog/   │  │    logs.raw (RF=3, 10 partitions)          │  │
│  [syslog UDP/514]      │──514 UDP──▶│  │    logs.normalized (RF=3, 10 partitions)   │  │
│  (legacy device)       │            │  │    siem.alerts (RF=3, 3 partitions)        │  │
│                        │            │  └────────┬───────────────────────────────────┘  │
│  k8s-cluster-01        │            │           │                                      │
│  [Fluentd DaemonSet]   │───────────▶│  ┌────────▼──────────────────────────────────┐  │
│                        │            │  │  Stream Processing (Flink / Kafka Streams) │  │
└────────────────────────┘            │  │  - Parse + normalize                       │  │
                                      │  │  - GeoIP / threat intel enrichment         │  │
SYSLOG UDP PATH (legacy):             │  │  - Correlation rules engine                │  │
  Syslog forwarder converts UDP →     │  │  - Alert generation                        │  │
  Kafka (with deduplication          │  └────────┬──────────────────────────────────┘  │
  and sequence numbering)             │           │                                      │
                                      │  ┌────────▼──────────────────────────────────┐  │
                                      │  │  Elasticsearch Cluster (hot/warm/cold)     │  │
                                      │  │  - Hot: SSD, last 7 days                   │  │
                                      │  │  - Warm: HDD, 8–90 days                   │  │
                                      │  │  - Cold: S3/object store, 90d–2 years     │  │
                                      │  └────────┬──────────────────────────────────┘  │
                                      └───────────┼──────────────────────────────────────┘
                                                  │
                         ANALYST TIER             │
                         ┌────────────────────────▼──────────────────┐
                         │                                            │
                         │  SIEM UI (React SPA)  ←→  SIEM API        │
                         │                       (REST + WebSocket)   │
                         │  - Dashboard                               │
                         │  - Alert queue                             │
                         │  - Event search                            │
                         │  - Investigation workspace                 │
                         │                                            │
                         │  Notification Service                      │
                         │  - PagerDuty webhook                       │
                         │  - Slack bot                               │
                         │  - SOAR integration                        │
                         └────────────────────────────────────────────┘

Packet flow for a single SSH failure event:
┌──────────────────────────────────────────────────────────────────────────────┐
│  Filebeat (prod-web-01) → Kafka Broker (10.0.50.10:9093)                    │
│                                                                              │
│  Physical: Ethernet frame (1514 bytes max)                                   │
│  Network:  IP header (20B) + TCP header (20B) + TLS record header (5B)      │
│  Transport: TLS 1.3 encrypted Kafka protocol frame                           │
│  Kafka:    ProduceRequest API (v9)                                           │
│  Payload:  JSON-encoded log event (~300 bytes)                               │
│            Batched: 100 events per ProduceRequest (30KB)                     │
│  ACK:      acks=all (leader + all ISR must acknowledge before proceeding)    │
└──────────────────────────────────────────────────────────────────────────────┘

Latency budget (log event: source to Elasticsearch):
  inotify notification:            0.1ms
  Filebeat read + batch:           500ms   (batch.timeout=500ms)
  TLS write to Kafka:              1ms
  Kafka replication (acks=all):    5ms     (within same AZ)
  Stream processor consume:        50ms    (poll interval)
  Parsing + enrichment:            10ms
  Elasticsearch bulk index:        100ms   (bulk buffer 5s or 5MB)
  ────────────────────────────────────────
  Total (cold path):               ~5-6 seconds end-to-end
  (warm path with batching):       ~500ms–2s typical
```

**Where latency and failure occur:**

| Location | Failure Type | Impact | Detection |
|---|---|---|---|
| Agent inotify | Log rotation races | Missed log lines | Agent monitoring, log gap detection |
| Agent → Kafka TLS | Cert expiry | Silent log gap from host | Cert expiry monitoring |
| Kafka broker crash | Partition leader election | 10–30s ingestion pause | Kafka under-replicated partitions metric |
| Stream processor | Processing lag | Alert delay | Consumer group lag metric |
| Elasticsearch | Index rejection (mapping conflict) | Logs lost | Index rejection rate metric |
| Elasticsearch | Disk full | Index blocked, events discarded | Disk usage alert at 80% |

---

## 3. Application Layer Flow

### SIEM has Two Distinct Application-Layer Paths

**Path A: Log ingestion (Kafka protocol, not HTTP)**

Log agents use the Kafka binary protocol over TCP/TLS — not HTTP. This is a persistent, connection-oriented binary protocol with its own framing, versioning, and authentication (SASL or mTLS). HTTP REST is used for Elasticsearch and for the SIEM API (analyst-facing). The ingestion path does NOT use HTTP.

**Path B: Analyst API (HTTPS/REST)**

The analyst-facing SIEM UI and API are standard HTTPS with REST and WebSocket.

---

### Analyst HTTP Request: Fetching Alert Details

```
GET /api/v1/alerts/alert_8f4a2c1e HTTP/2
Host: siem.example.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
Accept: application/json
X-Request-ID: 7f3a9b2c-1234-4321-abcd-ef0123456789
Cookie: siem_session=httponly_session_token_here
```

**Header analysis for SIEM context:**

`Authorization: Bearer <JWT>`: The analyst's JWT contains their identity, roles (`analyst`, `admin`, `readonly`), and the tenants/organizations they have access to. Multi-tenancy is a core SIEM requirement — a managed SOC analyst for Customer A must not see Customer B's alerts, ever.

`Cookie: siem_session=...`: In addition to the stateless JWT, many SIEMs also maintain a server-side session (hybrid model). The session allows immediate revocation: when an analyst leaves the company or their credentials are compromised, their session is deleted server-side. JWT-only systems cannot revoke tokens until they expire.

---

### WebSocket for Real-Time Alert Streaming

The SIEM dashboard shows live alerts as they arrive. This uses WebSocket:

```
Initial HTTP Upgrade:
GET /api/v1/alerts/stream HTTP/1.1
Host: siem.example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Authorization: Bearer eyJ...

Server response:
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=

[WebSocket connection established]

Server pushes alert frames as they arrive:
{opcode: 0x01 (text), payload: {"type": "alert", "alert": {...}}}
```

**WebSocket authentication challenge:** The `Authorization` header in the upgrade request is NOT included in subsequent WebSocket frames. Authentication is performed once at upgrade time. If the JWT expires during a long WebSocket session, the server must detect this and close the connection, forcing a re-auth. Implement: periodic JWT re-validation by the WebSocket server against the token's expiry claim.

---

### Query Parameter Handling: Elasticsearch Search via SIEM API

The analyst searches for events: `GET /api/v1/events?ip=203.0.113.45&start=2024-05-15T12:00:00Z&end=2024-05-15T12:05:00Z&limit=500`

The SIEM API:
1. Validates and parses query parameters (strict type checking)
2. Applies the analyst's ACL to constrain which indices/tenants are queried
3. Constructs an Elasticsearch DSL query (typed query builder — never string concatenation)
4. Executes against Elasticsearch
5. Applies post-filter to strip any fields the analyst's role cannot see (e.g., PII masking for lower-privilege analysts)
6. Returns paginated JSON results

**Critical:** The analyst's query input (`ip=203.0.113.45`) must never be directly interpolated into the Elasticsearch query DSL. Use the Elasticsearch client library's typed query objects.

---

### Response Construction: Alert API Response

```json
HTTP/2 200 OK
Content-Type: application/json
Cache-Control: no-store
X-Request-ID: 7f3a9b2c-1234-4321-abcd-ef0123456789
X-Rate-Limit-Remaining: 47
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload

{
  "alert": {
    "id": "alert_8f4a2c1e",
    "severity": "high",
    "status": "open",
    "title": "SSH Brute Force Detected",
    "created_at": "2024-05-15T12:01:02Z",
    "rule": {
      "id": "SSH_BRUTE_FORCE_001",
      "name": "SSH Brute Force",
      "mitre_tactic": "TA0006",
      "mitre_technique": "T1110.001"
    },
    "entities": {
      "source_ip": "203.0.113.45",
      "destination_host": "prod-web-01",
      "source_geo": {"country": "Russia", "city": "Moscow"},
      "threat_intel": {"is_known_bad": true, "confidence": 85}
    },
    "event_count": 500,
    "supporting_events_url": "/api/v1/events?alert_id=alert_8f4a2c1e",
    "assigned_to": null,
    "investigation_notes": []
  }
}
```

**Security-relevant response headers:**

`Cache-Control: no-store`: Alert details contain sensitive security information. Must not be cached by proxy, CDN, or browser cache. An analyst on a shared workstation should not have another analyst's alert details retrievable from browser cache.

`X-Rate-Limit-Remaining`: Analysts can generate expensive Elasticsearch queries (e.g., fetch all events for all IPs in the last 30 days). Rate limiting protects the cluster from accidental or deliberate resource exhaustion.

---

## 4. Backend Architecture

### Full Service Map

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                         SIEM BACKEND ARCHITECTURE                                 │
├──────────────────────────────────────────────────────────────────────────────────┤
│                                                                                   │
│  INGESTION TIER                                                                   │
│  ┌─────────────────────────────────────────────────────────────────────────────┐ │
│  │  Log Collectors (Kafka Brokers × 3+)                                        │ │
│  │  - Accept: Beats/Lumberjack, Kafka protocol, syslog (TCP/UDP relay)         │ │
│  │  - Partition strategy: key=sha256(host+source), ensures host ordering       │ │
│  │  - Retention: 7 days (replay window for reprocessing)                       │ │
│  │  - Replication factor: 3 (min ISR: 2 — tolerate 1 broker loss)             │ │
│  └─────────────────────────────────────────────────────────────────────────────┘ │
│                                    │ Kafka: logs.raw                              │
│  PROCESSING TIER                   ▼                                              │
│  ┌─────────────────────────────────────────────────────────────────────────────┐ │
│  │  Parser Workers (Flink / Kafka Streams)                                     │ │
│  │  Consumer group: parsers                                                    │ │
│  │  - Grok/dissect parsing per log source type                                 │ │
│  │  - ECS field mapping                                                        │ │
│  │  - Deduplication (exactly-once via Kafka transactions)                      │ │
│  │  - Dead letter queue for unparseable events                                 │ │
│  └──────────────────────────────┬──────────────────────────────────────────────┘ │
│                                 │ Kafka: logs.normalized                         │
│  ┌──────────────────────────────▼──────────────────────────────────────────────┐ │
│  │  Enrichment Workers                                                         │ │
│  │  - GeoIP (MaxMind embedded, updated weekly)                                 │ │
│  │  - Threat Intel (Redis, TTL 1h — fed by TAXII/STIX consumers)              │ │
│  │  - CMDB enrichment (asset database — host role, owner, criticality)        │ │
│  │  - User context (LDAP/AD — user department, manager, last logon)           │ │
│  └──────────────────────────────┬──────────────────────────────────────────────┘ │
│                                 │ Kafka: logs.enriched                           │
│  ┌──────────────────────────────▼──────────────────────────────────────────────┐ │
│  │  Correlation Engine (Flink Stateful Stream Processing)                      │ │
│  │  - Stateful sliding/tumbling windows per rule                               │ │
│  │  - State backend: RocksDB (local) + S3 (checkpointed)                      │ │
│  │  - Rules loaded from rules DB (PostgreSQL), hot-reloaded without restart   │ │
│  │  - Multi-event correlation (sequence detection)                             │ │
│  │  - Risk scoring (additive model per entity)                                 │ │
│  └──────────────────────────────┬──────────────────────────────────────────────┘ │
│                                 │ Kafka: siem.alerts                             │
│  STORAGE TIER                   ▼                                                 │
│  ┌──────────────────────────────────────────────────────────────────────────────┐ │
│  │  Elasticsearch Cluster (ILM — Index Lifecycle Management)                   │ │
│  │                                                                              │ │
│  │  HOT tier: 3× SSD nodes (7 days)                                            │ │
│  │  Index: logs-{date} (daily rollover when >50GB or >24h)                    │ │
│  │  Shards: 3 primary × 1 replica                                              │ │
│  │                                                                              │ │
│  │  WARM tier: 6× HDD nodes (8–90 days)                                       │ │
│  │  Indices migrated from hot, replica count reduced to 0                      │ │
│  │  (cost optimization — warm data queried rarely)                             │ │
│  │                                                                              │ │
│  │  COLD tier: S3 via Searchable Snapshots (90d–2 years)                       │ │
│  │  No local storage — S3 fetched on demand                                    │ │
│  │  Latency: seconds per query (acceptable for forensic investigation)         │ │
│  └──────────────────────────────────────────────────────────────────────────────┘ │
│                                                                                   │
│  ALERT & WORKFLOW TIER                                                            │
│  ┌──────────────────────────────────────────────────────────────────────────────┐ │
│  │  Alert Store (PostgreSQL + Elasticsearch alerts index)                      │ │
│  │  - PostgreSQL: alert status, assignments, investigation notes (ACID needed)  │ │
│  │  - Elasticsearch: alert search, timeline queries                            │ │
│  │                                                                              │ │
│  │  Notification Service                                                        │ │
│  │  - PagerDuty, Slack, email, SOAR webhooks                                   │ │
│  │  - Rate limiting and deduplication (don't send 500 alerts for 500 events)   │ │
│  │                                                                              │ │
│  │  SOAR Integration (Cortex XSOAR / Splunk SOAR / custom)                    │ │
│  │  - Automated playbooks triggered by alert type                              │ │
│  └──────────────────────────────────────────────────────────────────────────────┘ │
│                                                                                   │
│  CACHE TIER                                                                       │
│  ┌──────────────────────────────────────────────────────────────────────────────┐ │
│  │  Redis Cluster                                                               │ │
│  │  - Threat intel lookups (key: threat:{ip}, TTL: 3600s)                     │ │
│  │  - GeoIP cache (key: geo:{ip}, TTL: 86400s — IPs don't move often)         │ │
│  │  - Rate limit counters (key: rl:{source}:{window}, TTL: window_size)       │ │
│  │  - Analyst session data                                                     │ │
│  │  - Correlation state cache (frequently-accessed window state)               │ │
│  └──────────────────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────────────┘
```

---

### Sync vs. Async Flows

**Synchronous (blocking) — analyst-facing operations:**
- JWT validation per analyst request
- Elasticsearch query for alert details
- Alert status update (PostgreSQL transaction)
- Rate limit check (Redis)

**Asynchronous (non-blocking) — data pipeline:**
- All log ingestion: source → Kafka → parser → enrichment → correlation → storage
- Alert notifications: correlation engine writes alert to Kafka; notification service consumes independently
- SOAR playbook triggering: notification service calls SOAR webhook asynchronously; SIEM does not wait for SOAR response
- Threat intel feed sync: scheduled job pulls TAXII feeds every hour, writes to Redis + PostgreSQL

**Why the pipeline is entirely async:**

A log event from `prod-web-01` at T=0s is not blocking `prod-web-01` waiting for the SIEM to process it. The agent fires-and-forgets to Kafka. This decouples source hosts from SIEM processing capacity. If the SIEM has a processing outage, `prod-web-01` continues generating logs that queue in Kafka (retained for 7 days). When the SIEM recovers, it replays from the last committed offset — zero log loss.

---

### Correlation Engine: Stateful Stream Processing Deep Dive

The correlation engine is the intellectual heart of the SIEM. It's a stateful Flink application that processes the `logs.enriched` stream.

**Sliding vs. Tumbling windows:**

```
Tumbling window (non-overlapping):
  [0s──────60s] [60s──────120s] [120s──────180s]
  Event at 59s: counted in window 1
  Event at 61s: counted in window 2
  Problem: events that straddle the boundary are split
  → An attack spanning 59s–61s might not trigger a 60s threshold

Sliding window (overlapping):
  [0s────────60s]
     [10s──────────70s]
          [20s───────────80s]
  Event at any point within a 60s period is counted continuously
  → More sensitive, catches attacks regardless of window alignment
  → More expensive: N windows in flight simultaneously (N = window_size / slide_interval)
  → For 60s window sliding every 10s: 6 concurrent windows per (host, ip) pair

Session window (gap-based):
  Window stays open as long as events arrive within [gap_timeout]
  No fixed duration — grows with attacker activity
  → Ideal for attacks that slow down and speed up
  → Hard to bound resource usage (windows can grow indefinitely)
```

**Rule state machine (sequence detection):**

For complex attacks (multi-step kill chain), the correlation engine uses event sequence detection:

```
Rule: LATERAL_MOVEMENT_001
  Step 1: authentication failure from external IP (0–∞ occurrences)
  Step 2: authentication success from same IP within 5 minutes of last failure
  Step 3: remote process execution on the newly-authenticated host within 10 minutes

State:
  WAITING_FOR_FAILURE → FAILURE_SEEN (on step 1)
  FAILURE_SEEN → SUCCESS_SEEN (on step 2 within 5m)
  SUCCESS_SEEN → ALERT_FIRED (on step 3 within 10m)
  Any state → WAITING_FOR_FAILURE (on timeout or reset)

State key: (source_ip, destination_host)
State store: RocksDB (local disk) + checkpointed to S3 every 60s

Recovery: if Flink crashes and restarts, it restores state from checkpoint
  → Events between checkpoint and crash are replayed from Kafka
  → State is rebuilt accurately (at-least-once or exactly-once depending on config)
```

---

### Database Interactions

**PostgreSQL usage:**
- Alert metadata (status, assignee, resolution, notes): ACID required — two analysts updating the same alert simultaneously must not corrupt state
- Correlation rules store: rules, versions, enabled/disabled status
- Analyst accounts, roles, permissions
- Audit log of analyst actions (who viewed what, who changed what)

**Elasticsearch usage:**
- Primary log storage and search (the "data lake" for security events)
- Alert index (secondary — searchable alerts with full event context)
- Aggregations for dashboards (event counts, top source IPs, etc.)

**Redis usage:**
- Threat intel cache (frequently queried during enrichment — Redis at sub-millisecond latency vs. PostgreSQL at 2–10ms)
- Session tokens (server-side session store — allows immediate invalidation)
- Rate limiting counters
- Correlation state cache (frequently accessed small state objects — faster than RocksDB for hot paths)

---

## 5. Authentication & Authorization Flow

### Analyst Authentication

**Session + JWT hybrid (production-grade SIEM):**

```
Browser                    SIEM Auth Service           PostgreSQL/Redis
    │                              │                         │
    │── POST /auth/login ─────────▶│                         │
    │   {username, password,       │                         │
    │    mfa_token}                │── validate creds ──────▶│
    │                              │◀─ user record ──────────│
    │                              │                         │
    │                              │── CREATE session ───────▶│
    │                              │   session_id=uuid        │
    │                              │   user_id, roles,        │
    │                              │   expires=8h             │
    │                              │◀─ OK ────────────────────│
    │                              │                         │
    │                              │── SIGN JWT ─────────────│
    │                              │   sub=user_id            │
    │                              │   roles=[analyst]        │
    │                              │   tenants=[tenant_A]     │
    │                              │   exp=now+15min          │
    │                              │   session_ref=uuid       │
    │◀── 200 OK ──────────────────│                         │
    │    Set-Cookie:               │                         │
    │      session_id=uuid;        │                         │
    │      HttpOnly; Secure;       │                         │
    │      SameSite=Strict         │                         │
    │    Body: {access_token: JWT} │                         │
```

**MFA is mandatory for SIEM access.** A SIEM contains your organization's entire security posture. Analysts with access to SIEM can: see all security events, modify alert statuses, access investigation notes, and potentially discover your detection gaps (what you don't log). An analyst's compromised credentials without MFA = complete security intelligence breach.

**Why short JWT TTL (15 minutes) for SIEM?**

Standard web apps use 15–60 minute JWT TTLs. A SIEM should use 15 minutes or less. Reason: analyst accounts are high-value targets. A stolen JWT valid for 4 hours gives an attacker 4 hours of undetected SIEM access. With 15-minute JWTs and server-side sessions, the session can be revoked instantly (delete from Redis) regardless of JWT remaining validity.

---

### Multi-Tenancy Authorization

A managed SOC SIEM serves multiple customer tenants from a single infrastructure. Authorization is the hardest problem:

```
JWT claims for a managed SOC analyst:
{
  "sub": "analyst_bob",
  "roles": ["soc_analyst"],
  "tenants": ["tenant_A", "tenant_B"],    ← Bob manages these two customers
  "data_classification_clearance": "confidential",
  "exp": 1716000900
}

JWT claims for a customer analyst (direct access):
{
  "sub": "alice@customerA.com",
  "roles": ["customer_analyst"],
  "tenants": ["tenant_A"],               ← Alice can only see her own tenant
  "exp": 1716000900
}
```

Every Elasticsearch query made on behalf of an analyst MUST include a tenant filter:

```json
{
  "query": {
    "bool": {
      "must": [/* analyst's query */],
      "filter": [
        {"terms": {"tenant_id": ["tenant_A"]}}  ← injected by API from JWT claims
      ]
    }
  }
}
```

This filter is added by the SIEM API middleware — never by the client. If the API fails to inject this filter, tenant isolation breaks. This is the highest-severity bug class in a multi-tenant SIEM.

**Defense:** Integration tests that:
1. Create events for tenant_A and tenant_B
2. Authenticate as tenant_A analyst
3. Query for ALL events (no tenant filter in client request)
4. Assert that ZERO tenant_B events are returned

These tests must run on every deployment. Tenant isolation failure is not recoverable from a customer trust perspective.

---

### Trust Boundaries for Authentication

```
ZONE 1: Internet (analyst browser)
  → JWT presented on every API request
  → Session cookie presented alongside JWT
  → Both must be valid — neither alone is sufficient (defense in depth)

ZONE 2: API Gateway / Load Balancer
  → Terminates TLS
  → Validates JWT structure (not signature — too slow at LB scale)
  → Forwards trusted headers to API service

ZONE 3: SIEM API Service
  → Full JWT validation (signature, exp, iss, aud, scopes)
  → Session validation (lookup in Redis — is this session still active?)
  → Injects tenant filter from JWT claims into all downstream queries
  → NEVER trusts X-User-ID or X-Tenant-ID headers from external clients

ZONE 4: Elasticsearch
  → Only accessible from within VPC
  → API service authenticates with service account (not analyst credentials)
  → All queries include mandatory tenant filter (from Zone 3)
  → Elasticsearch's own security (xpack.security) enforces index-level permissions

ZONE 5: Kafka Brokers
  → Only accessible from within VPC
  → Log agents authenticate via mTLS (client certificates)
  → Processing services authenticate via SASL/SCRAM
  → Each service has minimum required permissions (produce OR consume, specific topics only)

ZONE 6: Kafka Ingestion (Agent trust)
  → Agent mTLS cert = identity of source host
  → Agent cert CN MUST match hostname in log events
  → Mismatch: events tagged as "unverified_source" and lower trust score
```

---

## 6. Data Flow

### The Three Data Planes of a SIEM

**Plane 1: Hot path (ingestion → alerting)**
Raw logs → parse → enrich → correlate → alert. Must complete within seconds to minutes. Latency matters for detection speed.

**Plane 2: Warm path (ingestion → analyst search)**
Raw logs → parse → enrich → index. Must complete within minutes. Analysts need recent events to be searchable quickly.

**Plane 3: Cold path (historical analysis)**
Indexed logs → aggregation → reports → threat hunting. Can take hours. Analyst runs a hunt query across 30 days of data.

---

### Data Transformation Pipeline

```
RAW SYSLOG (before any processing)
─────────────────────────────────────────────────────────────────────────────
"May 15 12:00:01 prod-web-01 sshd[12345]: Failed password for invalid user
 admin from 203.0.113.45 port 54321 ssh2\n"

Plain ASCII/UTF-8 text. No structure. 117 bytes.

AFTER AGENT COLLECTION (Filebeat adds metadata)
─────────────────────────────────────────────────────────────────────────────
{
  "message": "May 15 12:00:01 prod-web-01 sshd[12345]: Failed password...",
  "@timestamp": "2024-05-15T12:00:01.000Z",   ← agent local time
  "host.name": "prod-web-01",
  "agent.type": "filebeat",
  "agent.version": "8.12.0",
  "log.file.path": "/var/log/auth.log"
}
~350 bytes JSON, UTF-8

AFTER KAFKA TRANSIT (broker adds Kafka metadata)
─────────────────────────────────────────────────────────────────────────────
{
  // Kafka envelope metadata (not in message payload, in Kafka headers):
  kafka_offset: 8823419
  kafka_partition: 4
  kafka_timestamp: 1715774401500  // broker receive time
  kafka_headers: { "source_host": "prod-web-01", "agent_version": "8.12.0" }
  // Original JSON payload unchanged
}

AFTER PARSING (grok/dissect extracts structure)
─────────────────────────────────────────────────────────────────────────────
{
  // Original fields preserved:
  "message": "May 15 12:00:01 prod-web-01 sshd[12345]: Failed password...",
  "@timestamp": "2024-05-15T12:00:01.000Z",
  
  // Syslog parsed fields:
  "syslog.facility": "auth",
  "syslog.severity": "notice",
  "process.name": "sshd",
  "process.pid": 12345,
  
  // SSH-specific parsed fields (ECS normalized):
  "event.action": "ssh-login-failure",
  "event.category": ["authentication"],
  "event.type": ["start"],
  "event.outcome": "failure",
  "source.ip": "203.0.113.45",
  "source.port": 54321,
  "user.name": "admin",
  "host.name": "prod-web-01"
}
~600 bytes JSON

AFTER ENRICHMENT (GeoIP + threat intel + CMDB)
─────────────────────────────────────────────────────────────────────────────
{
  // All previous fields +
  
  // GeoIP enrichment (from MaxMind embedded):
  "source.geo.country_iso_code": "RU",
  "source.geo.country_name": "Russia",
  "source.geo.city_name": "Moscow",
  "source.geo.location": {"lat": 55.7558, "lon": 37.6173},
  "source.as.number": 12345,
  "source.as.organization.name": "Example ISP",
  
  // Threat intel enrichment (from Redis):
  "threat.indicator.type": "brute_force",
  "threat.indicator.confidence": 85,
  "threat.feed.name": "CISA_KNOWN_BAD",
  
  // CMDB enrichment (from asset database):
  "host.role": "web_server",
  "host.environment": "production",
  "host.criticality": "high",
  "host.owner_team": "platform-engineering",
  
  // Risk scoring:
  "event.risk_score": 72   // composite score from enrichment signals
}
~1200 bytes JSON

AFTER INDEXING IN ELASTICSEARCH
─────────────────────────────────────────────────────────────────────────────
{
  // All above + Elasticsearch-internal metadata:
  "_index": "logs-2024.05.15",
  "_id": "AX8m2I4B5lnH-xk4ABCD",
  "_score": null,  // null in non-search context
  "_version": 1,
  "alert_id": "alert_8f4a2c1e"  // added by correlation engine after alert fires
}
~1400 bytes stored (before compression; Elasticsearch LZ4 compresses to ~400 bytes)
```

---

### Serialization Formats

**Wire format: Kafka messages**

Kafka messages are byte arrays — no inherent format. The SIEM pipeline uses:
- **JSON**: Human-readable, universal tooling, but verbose. Used for logs.raw and logs.normalized.
- **Avro** (with Schema Registry): Compact binary, schema-enforced. Used for structured alert events (siem.alerts). Schema evolution supported — add fields with defaults without breaking consumers.
- **Protobuf**: Alternative to Avro. Used in some SIEMs for high-volume paths where every byte matters.

**At-rest format: Elasticsearch**

Elasticsearch stores documents as compressed JSON with an inverted index alongside. The `_source` field stores the original JSON document. Field data and doc_values store indexed forms for fast aggregations.

**Syslog formats (multiple incompatible standards exist):**
- **RFC 3164 (BSD syslog):** `<priority>timestamp host program[pid]: message` — unstructured message field
- **RFC 5424 (syslog protocol):** `<priority>VERSION timestamp hostname app-name procid msgid STRUCTURED-DATA message` — has a structured data section
- **CEF (ArcSight Common Event Format):** `CEF:version|device vendor|device product|device version|signature id|name|severity|extension`
- **LEEF (IBM QRadar LEEF):** Tab-delimited key=value pairs
- **JSON/NDJSON:** Modern applications (cloud services, Kubernetes) often log in JSON directly

A production SIEM must handle all of these. The parser tier maintains a library of parsers, one per log source type, identified by a combination of: source IP/hostname, syslog facility/severity, or content pattern matching.

---

## 7. Security Controls

### Encryption In Transit

**Log ingestion path (mTLS everywhere):**
- Agent → Kafka: TLS 1.3, mutual authentication (client certs from SIEM CA)
- Kafka inter-broker: TLS 1.3 (prevents eavesdropping on replicated data)
- Kafka → Processing workers: TLS 1.3 with SASL/SCRAM authentication
- Processing workers → Elasticsearch: TLS 1.3 with SASL auth
- All SIEM internal services: mTLS via service mesh (Istio/Linkerd with SPIFFE/SPIRE identity)

**UDP syslog — the unavoidable exception:**
Legacy network devices (firewalls, routers, switches) often only support UDP syslog (RFC 3164). UDP syslog is:
- Unencrypted (plaintext over the network)
- Unauthenticated (any host can send syslog to UDP/514)
- Unreliable (UDP — no delivery guarantee)

Mitigation: run a syslog relay (rsyslog with `imudp` input → `omkafka` output) in the same network segment as the devices. The relay accepts UDP/514 locally and forwards to Kafka over TLS. Never expose UDP/514 across untrusted network segments.

### Encryption At Rest

**Elasticsearch:**
- Node disk encryption: AWS EBS with KMS (volume-level). Elasticsearch-level field encryption (x-pack) for PII fields (usernames, email addresses in logs).
- Index-level encryption at rest enforced via ILM policies — all indices use encrypted storage.

**Kafka:**
- Broker EBS volumes: KMS-encrypted.
- Message-level encryption (rare, but possible for highest-sensitivity data): encrypt the message payload before producing to Kafka; decrypt after consuming. This protects data from Kafka broker operators.

**S3 (cold tier / snapshots):**
- SSE-KMS on all S3 buckets.
- Separate KMS key for SIEM data (not shared with other services).
- S3 Object Lock (WORM) for compliance: once a log snapshot is written, it cannot be modified or deleted for 2 years (regulatory requirement for security log retention).
- S3 Glacier for oldest archives (7+ years for compliance-heavy industries).

### Input Validation — SIEM-Specific Challenges

SIEM input validation has a unique inversion: the SIEM MUST accept malicious content in logs (because logs contain attacker activity) without that content compromising the SIEM itself.

```
Attack scenario without proper validation:
  Attacker sends HTTP request to web server:
    GET /<script>alert(document.cookie)</script> HTTP/1.1
  
  Web server logs: "GET /<script>alert(...)...</script> HTTP/1.1 404"
  Log is ingested into SIEM
  SIEM analyst views this log in the UI
  If the SIEM UI renders the log message as HTML: XSS fires
  Attacker has compromised the SIEM UI via a log entry

This is called "log injection" or "SIEM XSS via log data"
```

**Defense:**
- Log message fields are always rendered as text, never as HTML (use `textContent`, not `innerHTML`)
- Any field displayed in SIEM UI passes through an HTML escaping function
- CSP: `script-src 'self'; object-src 'none'` — even if HTML appears in log display, inline scripts blocked
- Log message fields stored in Elasticsearch as `keyword` (exact match) or `text` with `index_options: offsets` — never executed

**Log injection:**
An attacker can also inject fake log lines by embedding newlines in HTTP parameters:
```
GET /?q=normal_query%0aMay 15 12:00:01 prod-web-01 sshd[1]: Accepted password for root
```

If the web server logs the raw URI, this creates a fake "Accepted password for root" line in the same log file. Defense: at the parser level, validate that each parsed syslog line's hostname matches the agent's hostname from the TLS certificate CN. If they don't match, flag the event as `source.spoofed: true`.

### Secrets Handling

SIEM services have access to extremely sensitive credentials:
- Elasticsearch service account (can read ALL logs)
- Kafka service accounts (can produce/consume log data)
- LDAP/AD bind account (can enumerate users)
- Threat intel API keys (paid, revocable)
- SOAR and ticketing webhooks

All secrets: HashiCorp Vault or AWS Secrets Manager. Services authenticate to Vault via AWS IAM roles (instance profiles) — no static credentials anywhere.

**Kubernetes secrets encryption:** If running in Kubernetes, `etcd` must have encryption at rest enabled with a KMS provider. Default k8s secret storage in etcd is base64 (not encrypted) — a common misconfiguration.

---

## 8. Attack Surface Mapping

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║                    SIEM ATTACK SURFACE MAP                                    ║
╚═══════════════════════════════════════════════════════════════════════════════╝

EXTERNAL SURFACES (internet-facing)
══════════════════════════════════════════════════════════════════════════════
ENTRY 1: SIEM Web UI / API — HTTPS :443
  Auth: MFA + JWT + session
  Roles: analyst, admin, readonly, api_service_account
  Risk: credential theft, session hijacking, analyst account takeover
  Attack value: access to ALL security telemetry, detection logic

ENTRY 2: Log Agent API Endpoint — mTLS :9093 (Kafka) or :5044 (Beats)
  Auth: mTLS client certificate
  Risk: cert theft from agent host, injection of fake logs
  Attack value: blind the SIEM, inject fake events, destroy evidence

ENTRY 3: Threat Intel Feed Endpoints (outbound from SIEM)
  SIEM → external TAXII/STIX servers, VirusTotal API, MISP
  Risk: SSRF (SIEM fetches attacker-controlled URL as a threat feed)
  DNS rebinding attacks against TAXII feed URLs

ENTRY 4: Webhook Receivers (inbound from SOAR/ticketing)
  Auth: HMAC signature verification on webhook payload
  Risk: replay attacks, HMAC bypass if key weak or reused

INTERNAL SURFACES (VPC — reachable only from compromised internal systems)
══════════════════════════════════════════════════════════════════════════════
ENTRY 5: Elasticsearch HTTP API — :9200 (MUST be private)
  Auth: xpack.security + TLS
  Risk if exposed: full read/write to ALL security logs, alert manipulation
  Attack value: exfiltrate all logs, delete alert evidence, inject false events

ENTRY 6: Kafka Brokers — :9093 (MUST be private)
  Auth: SASL/SCRAM or mTLS
  Risk if exposed: inject arbitrary log events, read raw log stream (PII)
  Attack value: same as #2 above, at wire speed

ENTRY 7: Correlation Engine REST API (rule management)
  Auth: internal service token
  Risk: modify/disable detection rules, add backdoor rules
  Attack value: neuter the SIEM's detection capability

ENTRY 8: Log Agent itself (on source host)
  NOT a SIEM network surface, but: compromise of a monitored host
  gives attacker ability to write fake logs, delete real logs
  Attacker controls the log source — can forge or suppress evidence

ENTRY 9: Flink / Spark Web UI (cluster management)
  Default port: 8081 (Flink), 4040 (Spark)
  Auth: often none in default config
  Risk if exposed: kill processing jobs, submit malicious JARs

ENTRY 10: Zookeeper / KRaft (Kafka metadata)
  Default port: 2181 (Zookeeper)
  Auth: none in default Zookeeper config
  Risk if exposed: full Kafka admin access (delete topics, alter ACLs)

TRUST BOUNDARY MAP:
═══════════════════

[Internet]──TLS:443──▶[SIEM LB/WAF]──HTTP──▶[SIEM API]──TLS──▶[Elasticsearch]
                                                  │                    │
                                                  │ TLS                │ (private VPC)
                                                  ▼                    ▼
[Source Hosts]──mTLS:9093──▶[Kafka]──SASL──▶[Flink]──TLS──▶[Redis]
      │                         │
      │ (mTLS identity          │ (private VPC only)
      │  = host identity)       │
      ▼                         ▼
[Log Agent]               [Zookeeper/KRaft]
(on host)                 (private VPC only)

CRITICAL EXPOSURE RISK MATRIX:
═════════════════════════════════════════════════════════════════════════
Component          Should be exposed   Risk if exposed to internet
─────────────────────────────────────────────────────────────────────
SIEM API/UI        Internet (HTTPS)    Normal - designed for this
Kafka :9093        VPC only            CRITICAL - full log injection
Elasticsearch :9200 VPC only           CRITICAL - full data breach
Flink UI :8081     VPC only            HIGH - job manipulation
Zookeeper :2181    VPC only            CRITICAL - Kafka admin takeover
Redis :6379        VPC only            HIGH - cache poisoning, data leak
```

---

## 9. Attack Scenarios

### Scenario 1: Log Injection to Hide Attack Activity

**Attacker assumptions:**
- Has RCE on `prod-web-01` (the monitored host)
- SIEM is monitoring this host via Filebeat agent
- Goal: prevent the SIEM from detecting their attack activity by manipulating logs

**Step-by-step execution:**

1. Attacker achieves RCE on `prod-web-01` via a web application vulnerability.

2. Attacker inspects the Filebeat configuration:
```bash
cat /etc/filebeat/filebeat.yml
# Finds: inputs path /var/log/auth.log
```

3. **Approach A — Direct log deletion:**
```bash
# Attacker clears the auth log
cat /dev/null > /var/log/auth.log
# or
shred -u /var/log/auth.log
```
Filebeat was reading from byte offset 45,000. The file now has 0 bytes. Filebeat detects the inode changed (file was truncated or replaced) and either:
- Reports a log gap (offset mismatch alert fires in SIEM — attacker detected)
- Or silently resets offset to 0 and begins reading new content

4. **Approach B — Log injection (more sophisticated):**
The attacker writes fake log lines directly to the log file:
```bash
# Inject a fake "Accepted password" to cancel out a real failure
echo 'May 15 12:00:01 prod-web-01 sshd[99999]: Accepted password for attacker from 127.0.0.1 port 22 ssh2' >> /var/log/auth.log

# Inject noise to overwhelm the SIEM
for i in $(seq 1 100000); do
    echo "May 15 12:00:0$((i%9)) prod-web-01 kernel: [12345.678] INFO: normal event $i" >> /var/log/auth.log
done
```
This floods the SIEM with 100,000 fake "normal" events, potentially burying real alerts in noise.

5. **Approach C — Stop Filebeat:**
```bash
systemctl stop filebeat
# Now no logs flow to SIEM from this host
# Attacker has 0 visibility into this host's activity
```

**Where detection could happen:**
- Approach A: SIEM detects log gap (Filebeat reports inode change or offset regression). Alert: "Log source prod-web-01 auth.log gap detected — last event 5 minutes ago"
- Approach B: Noise injection triggers anomaly detection on event volume from this host (100,000 events in 60 seconds vs. normal 100 events/minute)
- Approach C: SIEM heartbeat monitoring — Filebeat sends a heartbeat event every 60 seconds. If heartbeat is absent for >5 minutes: "Log source prod-web-01 offline — no events for 5 minutes"
- All approaches: If attacker stops auditd (kernel audit daemon) or modifies /etc/audit/rules.d/, the auditd stop event itself is logged before the agent dies

**Why this works (without mitigations):**
The SIEM is dependent on the monitored host to provide honest logs. Any attacker with sufficient privilege on the host can tamper with the log source.

**Mitigation:**
- Immutable logging: use Linux audit daemon (auditd) with `--immutable` flag — prevents auditd from being stopped without a reboot
- Write-forward only: configure rsyslog to write to a write-only pipe; the file cannot be read back or truncated by the application user
- Remote syslog first: have sshd log directly to a remote syslog server (over TLS) in addition to local disk — the remote copy is tamper-resistant from the source host
- Heartbeat monitoring: alert when a log source stops sending events
- Privileged activity monitoring: monitor for `systemctl stop filebeat`, `> /var/log/auth.log` via auditd's syscall monitoring — these are high-privilege operations that should alert

---

### Scenario 2: Fake Alert Injection via Stolen Agent Certificate

**Attacker assumptions:**
- Has obtained the private key for `prod-web-01`'s Filebeat TLS certificate (from the host they compromised)
- Can reach the Kafka broker on port 9093 from another host (internal network access)
- Goal: inject fabricated security events to trigger false alerts, distract the SOC, or cover their tracks

**Step-by-step execution:**

1. Attacker extracts the agent certificate and private key from `prod-web-01`:
```bash
# Filebeat stores certs here by default:
cp /etc/filebeat/certs/prod-web-01.crt /tmp/stolen.crt
cp /etc/filebeat/certs/prod-web-01.key /tmp/stolen.key
# Exfiltrate to attacker-controlled system
```

2. Attacker configures a custom Kafka producer on their machine with the stolen cert:
```python
from kafka import KafkaProducer
import ssl

context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.load_cert_chain('/path/to/stolen.crt', '/path/to/stolen.key')
context.load_verify_locations('/path/to/siem_ca.crt')

producer = KafkaProducer(
    bootstrap_servers=['kafka.siem.internal:9093'],
    security_protocol='SSL',
    ssl_context=context,
    value_serializer=lambda v: json.dumps(v).encode()
)
```

3. Attacker crafts and sends fabricated log events:
```python
# Fabricate: "root login succeeded from CEO's laptop"
fake_event = {
    "message": "May 15 12:00:01 prod-db-01 sshd[1]: Accepted password for root from 10.0.1.5 port 22 ssh2",
    "@timestamp": "2024-05-15T12:00:01.000Z",
    "host.name": "prod-db-01",  # Impersonating a different host!
    "agent.type": "filebeat"
}
producer.send('logs.raw', value=fake_event)
```

4. The fabricated event flows through the SIEM pipeline. It's parsed as a legitimate SSH success event from `prod-db-01`. The correlation engine triggers a "Privileged SSH login" alert. The SOC investigates `prod-db-01` — a host the attacker hasn't actually touched — wasting analyst time.

**Where detection could happen:**
- **Certificate CN mismatch:** The mTLS cert presents as `CN=prod-web-01` but the event's `host.name` claims `prod-db-01`. The SIEM pipeline should validate: `event.host.name == tls_client_cert_cn`. Mismatch → flag as `source.spoofed: true`.
- **Certificate revocation:** Once `prod-web-01` is known compromised, revoke its certificate in the SIEM CA. New connections from that cert are rejected within seconds (no CRL TTL issue since SIEM controls the CA).
- **Anomalous event timing:** The fabricated events claim a timestamp of T=12:00:01 but the Kafka broker received them at T=12:05:30 (5 minutes later). Events with `event_time` significantly older than `broker_receive_time` are flagged as time-skew anomalies.

**Why this works (without mitigations):**
The SIEM trusts any event signed by a valid cert from its CA. Once a cert's private key is compromised, the attacker is as trusted as the original host.

**Mitigation:**
- Enforce CN-to-hostname binding: pipeline middleware validates `tls_peer_cn == event.host.name`
- Certificate pinning per host: each Kafka topic partition accepts only specific CNs (overkill but possible in high-security environments)
- Short-lived agent certificates (24-hour certs, auto-renewed by Vault agent): a stolen cert is valid for at most 24 hours
- OCSP/CRL check on every new TLS connection — if the cert is revoked, the connection is rejected
- Anomaly detection on per-source event volume and timing patterns

---

### Scenario 3: Correlation Rule Bypass (SIEM Evasion)

**Attacker assumptions:**
- Has studied the target organization's detection rules (from public SIEM vendor documentation, open-source rule sets, or intelligence from a previous breach)
- Goal: perform an SSH brute-force attack without triggering `SSH_BRUTE_FORCE_001`

**Step-by-step execution:**

The rule fires at: `count(failures) >= 10 in 60 seconds from same source IP to same destination`.

1. **Attack vector 1 — Rate manipulation:**
Attacker slows their brute-force to 9 attempts per 60 seconds: 1 attempt every 7 seconds. The rule's 60-second window never reaches 10 failures from this IP. The attack takes 10× longer but evades the threshold.

2. **Attack vector 2 — IP rotation:**
Attacker distributes 500 attempts across 500 different source IPs (residential proxy/botnet). Each IP sends exactly 1 attempt. No single (src_ip, dst_host) tuple ever exceeds 1 failure. The threshold rule never fires.

3. **Attack vector 3 — Destination rotation:**
Attacker sends 9 attempts to `prod-web-01`, 9 to `prod-web-02`, 9 to `prod-db-01`... cycling through all hosts. Each individual (src_ip, dst_host) tuple stays under threshold.

4. **Attack vector 4 — Protocol diversity:**
Attacker alternates between SSH, RDP, SMB, and LDAP authentication failures — each targeting different rules with separate thresholds. No single rule fires, but the aggregate picture is a coordinated credential attack.

**Where detection could happen:**
- **Sliding window with lower threshold:** If the rule used a 300-second window with threshold=20 failures, attack vector 1 would be caught (20 attempts over 5 minutes).
- **Global threshold rule:** A separate rule monitoring total failures across ALL destinations from a single source IP: `count(failures, any_dest) >= 50 in 600 seconds`. Catches vectors 1 and 3.
- **Distributed attack rule (vector 2):** Count unique source IPs that have ≥1 failure against the same destination: `count(distinct(src_ip) with failures to prod-web-01) >= 20 in 600 seconds`. This is a set-based correlation, harder to implement but catches distributed brute force.
- **Behavioral baseline:** ML-based detection compares current failure rate to historical baseline. 9 failures/minute vs. baseline of 0.1 failures/minute is a 90× deviation — anomaly detected even if the threshold rule doesn't fire.

**Why this works:**
Threshold-based rules are brittle and bypassable by anyone who knows the thresholds. Attackers can time their attacks to stay under any static threshold.

**Mitigation:**
- Layered thresholds: fast rules (10 in 60s) + slow rules (50 in 600s) + ultra-slow (200 in 3600s) — different time windows catch different attack speeds
- Entity-centric rules: group by `source.ip` alone (ignoring destination) to catch distributed destination attacks
- Probabilistic matching: instead of exact thresholds, use statistical anomaly detection
- Honeypots: deploy fake SSH servers with no legitimate users. ANY authentication attempt → alert (zero false positive rate, cannot be threshold-evaded)
- Threat intel integration: flag known brute-force IPs regardless of volume

---

### Scenario 4: SIEM Platform Compromise via Elasticsearch Exposure

**Attacker assumptions:**
- Has network access to the SIEM's internal network segment (e.g., via a compromised internal host, VPN, or misconfigured cloud security group)
- Elasticsearch port 9200 or 9300 is accessible
- Goal: exfiltrate all security logs, delete evidence, manipulate alerts

**Step-by-step execution:**

1. Attacker scans internal network: `nmap -p 9200,9300 10.0.50.0/24`
   Finds: `10.0.50.20:9200 open`

2. Attacker queries Elasticsearch directly (bypassing all SIEM API authentication):
```bash
# Get list of all indices
curl -s http://10.0.50.20:9200/_cat/indices?v

# Read logs from a specific date (no auth, no tenant filtering)
curl -s http://10.0.50.20:9200/logs-2024.05.15/_search \
  -H "Content-Type: application/json" \
  -d '{"query": {"match_all": {}}, "size": 10000}'

# Read ALL alerts
curl -s http://10.0.50.20:9200/alerts/_search \
  -d '{"query": {"match_all": {}}, "size": 10000}'
```

3. Attacker deletes all logs for a date range (destroying forensic evidence):
```bash
curl -X DELETE http://10.0.50.20:9200/logs-2024.05.15
```

4. Attacker deletes specific alerts pointing to their activity:
```bash
curl -X DELETE http://10.0.50.20:9200/alerts/_doc/alert_8f4a2c1e
```

5. Attacker injects false "investigated and closed" status for alerts they want suppressed:
```bash
curl -X POST http://10.0.50.20:9200/alerts/_update/alert_8f4a2c1e \
  -d '{"doc": {"status": "closed", "resolution": "false_positive"}}'
```

**Where detection could happen:**
- Network security group should block 9200/9300 from all sources except the SIEM API service's security group. If this is enforced, the attacker can't reach Elasticsearch at all.
- Elasticsearch audit log (xpack.security) logs every query, every delete, every index modification. If the audit log is shipped to a separate, append-only store, the attacker's actions are recorded.
- Anomalous access pattern: direct Elasticsearch queries (not through the SIEM API) from an unusual source IP — detectable if Elasticsearch access patterns are monitored.

**Why this works:**
Elasticsearch, in its default configuration (pre-version 8.0), ships with security disabled. Even with security enabled, if the 9200 port is reachable without authentication (common in older clusters), there is no protection. The entire security posture of the SIEM depends on Elasticsearch never being reachable by untrusted clients.

**Mitigation:**
- Security groups: Elasticsearch security group only allows inbound from the SIEM API's security group. No exceptions.
- Elasticsearch xpack.security enabled with HTTPS and SASL auth (default in ES 8.0+)
- Elasticsearch audit log shipped to a separate, immutable store (not Elasticsearch itself — that's circular)
- Write-once (WORM) S3 snapshots: even if an attacker deletes the Elasticsearch index, the S3 snapshot is immutable and can restore the data
- Principle of least privilege: SIEM API service account has `read` and `write` to specific indices. It does NOT have `delete index` or `delete document` privileges. Only an ops admin role (MFA-protected) can delete indices.

---

### Scenario 5: Alert Fatigue Attack (Noise Flooding)

**Attacker assumptions:**
- Has network access to a monitored system (or can trigger external events that generate logs)
- Goal: overwhelm the SOC with false positives so that real alerts are buried or ignored

**Step-by-step execution:**

1. Attacker triggers millions of low-severity events that each individually match a detection rule:
```bash
# Trigger auth failure rule by hammering a public-facing login page
for i in $(seq 1 1000000); do
    curl -s -X POST https://app.example.com/login \
         -d '{"username":"test","password":"wrong"}' &
done
```

2. Each failed login generates a log event. The brute-force rule fires almost immediately. The SOC receives 1,000 alerts in the first hour — far beyond human investigation capacity.

3. While the SOC is overwhelmed investigating fake brute-force alerts, the attacker conducts their real attack (e.g., spear phishing, supply chain attack) using a different technique that would generate a single, subtler alert — which is buried in the noise.

**Where detection could happen:**
- Alert deduplication: multiple alerts for the same (rule, source_ip, destination) within 10 minutes → merged into one alert with increasing event count
- Alert suppression: once an alert for a known-bad IP fires, subsequent alerts from that IP for the same rule within 1 hour are suppressed (show as "+500 more events" on the original alert)
- Rate limiting at the alert level: if a rule fires >100 times in 10 minutes, pause the rule and page a rule tuning engineer — something is wrong with the rule or there's an active noise attack
- Threshold auto-tuning: ML model increases rule thresholds during abnormal traffic periods

**Why this works:**
The human analyst is the bottleneck. Alert volume doesn't harm the SIEM infrastructure (it has capacity), but it saturates human attention. The real alert for the real attack gets P5 priority when the analyst queue has 1,000 P3 alerts ahead of it.

---

## 10. Failure Points

### What Fails Under Load

**Kafka consumer lag (processing pipeline can't keep up):**

At normal volume: 100,000 events/minute. At spike (DDoS against monitored applications): 10,000,000 events/minute. The parser workers consume from `logs.raw` at 500,000 events/minute (their max throughput). Kafka consumer lag grows: 10M - 0.5M per minute = 9.5M events behind after the first minute. After 10 minutes, the pipeline is 95M events behind. Alert latency grows from 5 seconds to 10 minutes.

**Impact:** An active intrusion is generating alerts, but the alerts are stuck in the processing backlog. The analyst doesn't see them until 10 minutes after the attack events — by then, the attacker may have pivoted.

**Mitigation:** Horizontal scale of processing workers (add Flink task slots). Auto-scale based on consumer group lag metric. Kafka lag > 1M events → scale out. Also: shed load by applying sampling during extreme peaks (process 10% of events from known-noisy sources during a DDoS, 100% from high-value sources).

**Elasticsearch indexing pressure:**

Elasticsearch can index approximately 100,000–500,000 events/second per cluster (depending on hardware). At the same DDoS spike, if Elasticsearch receives bulk index requests it can't process, it returns HTTP 429 (too many requests) and the indexing workers back off with exponential backoff. Events queue in memory, then spill to disk on the workers. If the spike lasts long enough, the disk buffer fills and events are dropped.

**Circuit breakers:** Elasticsearch's built-in circuit breakers protect against OOM by rejecting queries/indexing when heap exceeds thresholds. This is necessary but means events are dropped rather than causing a crash. Log loss under extreme load is a real risk.

**Correlation engine state store explosion:**

The Flink correlation engine maintains state per (src_ip, dst_host) tuple for every active rule. In a distributed brute-force with 1M source IPs targeting 1000 hosts, the state store has 1M × 1000 = 1 billion state entries. RocksDB on local SSD can hold this (tens of GB), but:
- Checkpoint time (state → S3) grows to hours
- Recovery from checkpoint takes hours
- GC overhead grows

Mitigation: set state retention (evict state entries after the rule's maximum window × 2). An SSH brute-force rule with 60s window: evict state entries that haven't been updated in 120 seconds. Caps state at ~2× the active attack surface.

---

### What Fails Under Attack

**Kafka topic deletion (if Kafka admin API is exposed):**

An attacker with Kafka admin access can delete the `logs.raw` topic. All buffered messages (7 days retention) are gone. The SIEM has no replay capability for this period. All in-flight events are dropped.

**Flink job manipulation:**

If the Flink web UI (port 8081) is accessible, an attacker can: cancel running jobs (stops all correlation), submit malicious JAR files (RCE on Flink cluster with access to all internal services), modify job configuration.

**Redis flushdb:**

`FLUSHDB` on the threat intel Redis instance clears all threat intel lookups. Every IP temporarily appears as "clean" for up to 1 hour (until the next feed sync). During this window, known-malicious IPs are not flagged.

---

### Common Misconfigurations

| Misconfiguration | Impact |
|---|---|
| Elasticsearch port 9200 in public security group | Full data breach, alert manipulation |
| No Elasticsearch xpack.security | Any network-accessible client has full admin access |
| Kafka without authentication | Any internal host can inject logs or consume log stream |
| Filebeat without mTLS (plain TCP) | Log injection from any host on same network |
| Kafka `acks=1` instead of `acks=all` | Log loss if leader crashes before replica replication |
| No agent heartbeat monitoring | Silent log gaps go undetected for hours |
| Flink web UI without auth on internal network | Correlation jobs manipulable by any compromised internal host |
| Elasticsearch ILM not configured | Hot indices grow indefinitely → disk full → indexing blocked |
| Log retention < regulatory requirement | Compliance violation for PCI-DSS, HIPAA, SOC2 |
| Single Kafka AZ deployment | AZ failure = total SIEM blindness |
| Short-lived alert suppression TTL | Attacker re-triggers same alert after suppression expires |
| Admin access to SIEM API without MFA | Stolen credentials → full SIEM admin access |
| etcd secrets unencrypted (k8s) | All SIEM service credentials extractable from etcd |

---

## 11. Mitigations

### Defense-in-Depth for SIEM

**Layer 1: Source integrity**

```
Goal: make it as hard as possible to tamper with logs at the source

1. auditd with --immutable flag:
   - auditd loaded with AUDIT_IMMUTABLE rule (requires reboot to change)
   - sshd PAM module logs via auditd directly to kernel buffer
   - Kernel buffer → remote syslog server via TLS BEFORE writing to local disk
   - Remote syslog server is append-only (no SSH access from source hosts)

2. Immutable file attributes (for log files):
   chattr +a /var/log/auth.log
   - +a = append-only: file can only be opened for appending
   - root cannot truncate or overwrite — only append new content
   - Breaking: requires removing the immutable attr, which itself generates an audit event

3. eBPF-based log collection (advanced):
   - Run Falco or Tetragon to capture sshd events at the kernel syscall level
   - sshd cannot hide events from kernel-level instrumentation
   - Tamper-resistance: an attacker would need a kernel exploit to suppress kernel events

4. Multiple collection paths:
   - syslog local → Filebeat → SIEM
   - syslog remote → central syslog server → SIEM
   - If one path is compromised, the other provides validation
```

**Layer 2: Transport integrity**

```
1. mTLS mandatory:
   - Short-lived certs (24h, Vault PKI auto-renewed)
   - CA trust pinned in Kafka broker config
   - CRL checked on connection

2. Event signing (optional, high security):
   - Agent signs each event batch with its private key
   - Correlation engine validates signatures before processing
   - Prevents injection even if the mTLS CA is compromised

3. Sequence numbers:
   - Agent attaches monotonic sequence number per log line
   - Pipeline detects gaps: sequence 1,2,3,5 → missing event 4 → alert
   - Prevents deletion of individual log lines from the stream
```

**Layer 3: SIEM platform hardening**

```
1. Elasticsearch:
   - xpack.security enabled, HTTPS enforced
   - Separate service accounts per SIEM component
     - indexer: write to specific indices only, no delete
     - api_service: read specific indices, no write
     - ops_admin: full access, MFA-gated, audit-logged
   - Index lifecycle policies prevent index deletion by non-admin accounts
   - S3 WORM snapshots: immutable backups

2. Kafka:
   - SASL/SCRAM per service account
   - Producer permissions: specific topics only (logs.raw only for agents)
   - Consumer permissions: specific topics and consumer groups only
   - No admin API access for service accounts
   - Zookeeper / KRaft in isolated subnet, firewall from application tier

3. Flink:
   - Web UI disabled in production (enable only for active debugging via SSH tunnel)
   - Jobs submitted via CI/CD only (GitOps model)
   - Network policy: Flink task managers cannot make outbound connections except to Kafka + Redis + S3

4. Redis:
   - requirepass set (auth token from Vault)
   - rename-command FLUSHDB "" (disable dangerous commands)
   - rename-command FLUSHALL ""
   - rename-command CONFIG ""
   - bind to specific IP (not 0.0.0.0)
   - protected-mode yes
```

**Layer 4: Detection coverage for the SIEM itself**

A SIEM that doesn't monitor itself is a blind spot:

```
Monitor the SIEM platform with itself (and with a separate SIEM if possible):

Events to alert on:
- Elasticsearch: DELETE index operation (any)
- Elasticsearch: DELETE document operation in alerts index
- Elasticsearch: query from unexpected source IP (not SIEM API's IP range)
- Kafka: topic deletion
- Kafka: consumer group position reset (could be used to replay or skip events)
- Flink: job cancellation
- Redis: FLUSHDB command execution
- Agent: certificate renewal failure (cert approaching expiry)
- Agent: heartbeat gap > 5 minutes from any monitored host
- SIEM API: failed admin login (brute force on SIEM admin accounts)
- SIEM API: JWT with unexpected alg (algorithm confusion attack)
- Rule store: correlation rule modified (who modified it, what changed)
```

---

## 12. Observability

### Logs

**SIEM meta-logs (logs about the SIEM itself):**

```json
// Parser worker: event successfully parsed
{
  "event": "log_parsed",
  "source_host": "prod-web-01",
  "source_file": "/var/log/auth.log",
  "parser": "sshd_auth",
  "input_bytes": 117,
  "fields_extracted": 8,
  "duration_us": 450,
  "kafka_offset": 8823419,
  "kafka_partition": 4
}

// Parser worker: event failed to parse (dead letter queue)
{
  "event": "parse_failed",
  "source_host": "legacy-fw-01",
  "raw_message": "[TRUNCATED_TO_200B]...",
  "parser_attempted": ["syslog_rfc3164", "syslog_rfc5424", "cef"],
  "error": "no matching parser for message format",
  "dlq_topic": "logs.parse_failed",
  "kafka_offset": 123456
}

// Correlation engine: alert fired
{
  "event": "alert_generated",
  "rule_id": "SSH_BRUTE_FORCE_001",
  "alert_id": "alert_8f4a2c1e",
  "window_start": "2024-05-15T12:00:01Z",
  "window_end": "2024-05-15T12:01:01Z",
  "event_count": 500,
  "state_key": "prod-web-01:203.0.113.45",
  "processing_lag_ms": 4800,
  "rule_evaluation_duration_us": 230
}
```

**Critical: What NOT to log from SIEM internal systems:**
- Raw log event content in SIEM meta-logs (that's stored in Elasticsearch, not duplicated)
- Analyst query details in application logs (privacy — what analysts search for is sensitive)
- JWT token values (log the `sub` claim only after validation)
- Elasticsearch query DSL (may contain field names revealing internal schema)

---

### Metrics

```
# Ingestion pipeline health
kafka_consumer_lag_records{topic="logs.raw", consumer_group="parsers"}
  ALERT if > 1,000,000 (10 minutes at normal rate)

kafka_consumer_lag_records{topic="logs.normalized", consumer_group="enrichers"}
  ALERT if > 500,000

# Parser health
events_parsed_total{parser="sshd_auth", status="success|failure"}
parse_failure_rate = events_parsed_total{status="failure"} / events_parsed_total
  ALERT if parse_failure_rate > 5% (parser regression or new log format)

events_in_dlq_total  # events in dead letter queue
  ALERT if > 10,000 (significant portion of logs unprocessable)

# Enrichment health
enrichment_lookup_duration_ms{enricher="geoip|threat_intel|cmdb", quantile="0.99"}
  ALERT if geoip p99 > 1ms (embedded DB, should be <1ms)
  ALERT if threat_intel p99 > 5ms (Redis lookup, should be <5ms)

threat_intel_cache_hit_rate
  ALERT if < 70% (cache not warm, too many Redis misses → latency spike)

# Correlation engine health
flink_job_uptime_seconds  # how long the correlation job has been running
  ALERT if drops to 0 (job crashed)

correlation_rule_evaluation_duration_ms{rule_id, quantile="0.99"}
  ALERT if any rule takes > 100ms (performance regression)

alerts_generated_per_minute{rule_id}
  ALERT if > 100/minute for a single rule (alert storm — rule needs tuning or attack)
  ALERT if = 0 for > 1 hour for high-priority rules (rule broken or data not flowing)

# Elasticsearch health
elasticsearch_index_documents_total{index}
elasticsearch_bulk_reject_rate
  ALERT if > 0 (indexing pressure — events being dropped)

elasticsearch_shard_count{state="unassigned"}
  ALERT if > 0 (data loss risk)

elasticsearch_disk_usage_percent{node}
  ALERT at 70% (warning), 85% (critical — indexing will be blocked at 90%)

elasticsearch_jvm_heap_used_percent
  ALERT if > 75% (GC pressure approaching)

# Agent health
agent_heartbeat_age_seconds{host}
  ALERT if > 300 (5 min) — agent offline, log gap in progress

agent_cert_expiry_seconds{host}
  ALERT if < 2592000 (30 days)

# Security metrics
failed_analyst_logins_total
  ALERT if > 10 in 5 minutes (analyst brute force attempt)

elasticsearch_direct_access_from_non_api{source_ip}
  ALERT immediately (Elasticsearch accessed without going through SIEM API)

rule_modification_events_total
  ALERT on any modification (correlation rule changes must be reviewed)
```

---

### Distributed Traces

```
Trace: log_event_processing (traceId: abc123)
  Span: filebeat_read (0.1ms)
    event: inotify trigger → file read
  
  Span: kafka_produce (1ms)
    kafka.topic: logs.raw
    kafka.partition: 4
    kafka.offset: 8823419
  
  Span: parser_consume (8ms)
    parser.name: sshd_auth
    fields.extracted: 8
    span: grok_match (2ms)
    span: ecs_normalize (1ms)
  
  Span: enrichment_pipeline (12ms)
    span: geoip_lookup (0.3ms) ← embedded
    span: threat_intel_lookup_redis (0.8ms) ← cache hit
    span: cmdb_lookup (9ms) ← database lookup (slowest)
  
  Span: kafka_produce_normalized (1ms)
    kafka.topic: logs.normalized
  
  Span: correlation_engine_evaluate (230us)
    rule.id: SSH_BRUTE_FORCE_001
    window.state_key: prod-web-01:203.0.113.45
    window.current_count: 500 → THRESHOLD REACHED
  
  Span: alert_generate (2ms)
  
  Span: elasticsearch_index (100ms)
    index: logs-2024.05.15
    bulk_batch_size: 1000

TOTAL: ~125ms for this event's full processing
(correlation trigger adds: +62s for the window to fill)
```

**Trace propagation:** Each log event carries a `trace_id` from the moment it's read by the agent. This `trace_id` is embedded in the Kafka message headers, propagated through all processing stages, and stored with the final Elasticsearch document. This allows reconstructing the complete processing journey of any specific log event — invaluable for debugging parser failures or enrichment issues.

---

### What Should Alert vs. What Should Not

**Alert (P1 — page on-call immediately):**
- Kafka consumer lag > 1M events (events are backing up, alert delay growing)
- Any Flink job in FAILED state (correlation engine down — no new alerts possible)
- Elasticsearch disk > 85% (indexing will stop at 90% — log loss imminent)
- Direct Elasticsearch access from non-API source
- Any correlation rule modification (potential SIEM sabotage)
- Agent offline > 30 minutes for a critical host (log gap on high-value target)

**Alert (P2 — respond within 1 hour):**
- Parse failure rate > 5% (many events unprocessable)
- Threat intel cache hit rate < 50% (enrichment degraded)
- Any unassigned Elasticsearch shards
- Agent cert expiry < 14 days

**Alert (P3 — respond within 4 hours):**
- Consumer lag > 100K (normal variance, but growing trend needs watching)
- Individual enrichment latency p99 > 10ms
- Failed analyst logins > 5 in 10 minutes

**Log, do not alert:**
- Individual parse failures (noise if new log format — log for parser tuning)
- Individual cache misses (expected on cold start)
- Individual Elasticsearch slow queries (normal variance)
- Correlation rules that haven't fired in 24 hours (may be working correctly — no attacks)

---

## 13. Scaling Considerations

### The Fundamental Scaling Challenge

A SIEM has a unique scaling property: **the data volume is not user-driven — it's attacker-driven and infrastructure-driven.** A DDoS against your applications simultaneously generates massive log volume AND demands fast SIEM response. You need MORE processing capacity precisely when you're under the most stress.

```
Normal day:    1 GB/hour logs     → 100,000 events/minute
Incident day: 100 GB/hour logs    → 10,000,000 events/minute

You need 100× processing capacity for incident response
but you can't afford to run 100× capacity idle on normal days.
```

**Solution: elastic scaling (burst capacity)**
- Kafka absorbs the burst (7-day retention = buffer)
- Processing workers auto-scale on consumer lag metric (k8s HPA)
- Flink can dynamically scale task slots (in newer versions)
- Elasticsearch has pre-provisioned warm capacity that can be temporarily repurposed

---

### Bottlenecks by Component

**Kafka — not the bottleneck (usually):**
Kafka can handle millions of messages per second per broker. With 3 brokers, horizontal scale is straightforward: add brokers, increase partition count. The Kafka tier almost never bottlenecks a SIEM. The bottleneck is almost always either the parsers or Elasticsearch.

**Parser workers — CPU bottleneck:**
Regex-based grok parsing is CPU-intensive. A single Flink task slot can parse ~50,000 events/second (depending on complexity). To handle 10M events/second, you need 200 task slots. Each Flink task manager provides 4–16 task slots. So ~13–50 Flink task manager pods. Scale horizontally.

The simplest optimization: replace complex grok patterns with `dissect` (a linear-time parsing algorithm) for common log formats. Dissect is 10× faster than grok for well-structured formats like syslog.

**Enrichment — I/O bottleneck:**
GeoIP (embedded) is fast. Threat intel (Redis) is fast (0.5ms). CMDB (PostgreSQL) is the bottleneck (2–10ms per lookup). At 1M events/minute, if every event needs a CMDB lookup: 16,666 DB queries/second. A primary PostgreSQL can handle ~10,000 simple queries/second. Database becomes saturated.

Solutions:
- Cache CMDB results aggressively: most hosts don't change (cache TTL 30 minutes)
- Only enrich new unique hostnames (if host was already enriched in the last 30 min, use cached value)
- Pre-load all known hosts into Redis at startup (full CMDB in-memory)
- Async enrichment: index events without CMDB data, enrich asynchronously via a separate process

**Elasticsearch — the hardest bottleneck to address:**

```
Indexing limits (approximate, highly configuration-dependent):
  Single hot node (32-core, NVMe): ~100,000 events/second
  Three-node hot cluster: ~300,000 events/second
  Ten-node hot cluster: ~1,000,000 events/second

Query limits:
  Concurrent analyst queries: limited by JVM heap (more analysts → more query concurrency → GC)
  Aggregation queries (dashboard data): very expensive — cache aggressively

Storage growth:
  Average event: 1200 bytes JSON → 400 bytes stored (LZ4 compression)
  1M events/minute = 60M events/hour = 24GB/day (compressed)
  7 days hot tier: ~168GB (comfortably on SSD)
  90 days warm tier: ~2.1TB (HDDs)
  2 years cold tier: ~17TB (S3, ~$400/month at S3 standard)
```

**ILM (Index Lifecycle Management) is non-negotiable:**
Without ILM, indices grow forever. A single index with 365 days of data is unmanageable — queries scan the entire index, shard sizes grow beyond Elasticsearch's sweet spot (50GB), and there's no cost-tiering. ILM automates: rollover → move to warm → reduce replicas → move to cold (S3 Searchable Snapshots) → delete.

---

### Horizontal vs. Vertical Scaling

| Component | Strategy | Notes |
|---|---|---|
| Kafka | Horizontal (more brokers, more partitions) | Add brokers; rebalance partitions |
| Parser workers | Horizontal (more Flink task slots/pods) | Stateless — trivial to scale |
| Enrichment workers | Horizontal (more pods) | I/O bound — scale by Redis/DB capacity |
| Correlation engine | Horizontal (more Flink task slots) | Stateful — state partitioned by key |
| Elasticsearch hot | Horizontal (more nodes) | Shard rebalancing needed; plan for growth |
| Elasticsearch warm | Horizontal | HDDs — cost-optimized |
| Redis | Horizontal (Redis Cluster) | Partition threat intel by IP prefix |
| PostgreSQL | Vertical + read replicas | Alert status writes are serialized |
| SIEM API | Horizontal (more pods) | Stateless (session in Redis) |

---

### Consistency Tradeoffs

**Exactly-once processing in Kafka Streams / Flink:**

Standard Kafka consumer semantics are at-least-once: a message may be processed more than once if the consumer crashes between processing and committing the offset. For log events, duplicate events in Elasticsearch are annoying (inflated counts) but not catastrophic. For alerts, duplicate alerts are a significant problem — two PagerDuty pages for the same attack saturates the on-call analyst.

**Exactly-once via Kafka transactions:**
- Flink uses Kafka's transaction API (two-phase commit) to atomically: consume input offsets + produce output messages + commit state.
- If Flink crashes mid-transaction, the transaction is aborted and rolled back.
- On restart, Flink replays from the last committed checkpoint.
- Result: exactly-once semantics — no duplicate processing.
- Cost: ~10% throughput reduction, ~50ms additional latency per checkpoint.

**Alert deduplication (belt-and-suspenders for exactly-once):**

Even with exactly-once processing, alert deduplication is implemented at the storage layer:

```sql
-- Idempotent alert upsert (PostgreSQL)
INSERT INTO alerts (alert_id, rule_id, source_ip, destination_host, created_at, ...)
VALUES (?, ?, ?, ?, ?, ...)
ON CONFLICT (alert_id) DO NOTHING;
-- If alert_id already exists, ignore the duplicate. Safe for at-least-once delivery.
```

**State consistency after Flink restart:**

Flink checkpoints its state (RocksDB snapshots) to S3 every 60 seconds. On restart, it restores from the latest successful checkpoint and replays Kafka events from the checkpoint's committed offset.

- Events between the last checkpoint and crash: re-processed (at-least-once without transactions, exactly-once with transactions)
- State (window counts, sequence states): restored from S3 checkpoint — correlation continues seamlessly
- Kafka events: retained for 7 days — always replayable even if Flink is down for days

---

## 14. Interview Questions

### Q1: Explain the difference between a tumbling window and a sliding window in a SIEM correlation engine. When would you use each? What are the resource implications?

**Direct answer:**

**Tumbling windows** divide time into fixed, non-overlapping buckets. Events fall into exactly one bucket. A 60-second tumbling window: [0–60s], [60–120s], [180–240s]. At T=59s, you need 10 failures to trigger. At T=61s, the count resets — the same 9 failures from window 1 are forgotten. An attack that puts 9 events in window 1 and 9 events in window 2 never triggers a 10-event threshold rule.

**Sliding windows** move continuously. A 60-second sliding window evaluated every 10 seconds: [0–60s], [10–70s], [20–80s]... At any point in time, the count covers the last 60 seconds. An attack that's 9 events per minute for 3 minutes eventually accumulates 9+9+9=27 events in a 60-second window — it will trigger. But it also means the system maintains 6 concurrent windows per state key (60s / 10s slide = 6).

**Use tumbling when:** You want to count events in discrete, non-overlapping periods (e.g., hourly event count for compliance reporting). You explicitly want the window to reset. Rate is more important than sensitivity.

**Use sliding when:** You want to detect sustained patterns regardless of when they start relative to a clock boundary. Attack detection almost always requires sliding windows. Sensitivity is more important than resource efficiency.

**Resource implications:**
- Tumbling: 1 state entry per state key. Memory = N_keys × state_size. For SSH brute force: N_keys = unique(src_ip, dst_host) pairs.
- Sliding: S = window_size / slide_interval concurrent windows per state key. S=6 means 6× the memory of tumbling. The trade-off for better sensitivity.
- Session windows: unbounded — a state key can have one window that started when the first event arrived and is still open. For attacker-controlled traffic, attackers can hold windows open indefinitely by sending events at exactly the gap_timeout interval, exhausting state memory.

---

### Q2: An analyst reports that the SIEM showed no alerts during a confirmed breach that lasted 3 hours. Walk through every possible reason and how you'd diagnose each.

**Systematic approach:**

**Category 1: Log collection failure (logs never reached SIEM)**

Diagnosis:
- Check agent heartbeat: `SELECT * FROM agent_heartbeat WHERE host='prod-web-01' AND last_seen > (now() - 4h)` — gap in heartbeat = agent was offline
- Check Kafka consumer lag metrics at T-4h: was there a spike in lag suggesting agent was buffering and couldn't deliver?
- Check agent logs on the source host: `journalctl -u filebeat --since "4 hours ago"` — authentication failures, network errors?
- Check cert validity: did the agent's mTLS cert expire during the breach window?

**Category 2: Parsing failure (logs reached SIEM but weren't parsed)**

Diagnosis:
- Check dead letter queue: `SELECT COUNT(*) FROM logs_dlq WHERE created_at BETWEEN ? AND ?` — unparsed events here?
- Check parse failure rate metric at T-4h: spike indicates new log format or parser regression
- Check if a deployment happened during the breach window: new log format from a recently deployed application?

**Category 3: Enrichment failure (logs parsed but enrichment delayed)**

Diagnosis:
- Check Redis availability at T-4h: was threat intel Redis down?
- Check CMDB enrichment latency: was the PostgreSQL CMDB overloaded?
- Enrichment failure shouldn't prevent indexing (enrichment is additive, not blocking) — but check if your pipeline is configured to require enrichment before indexing

**Category 4: Correlation engine failure (events indexed but rules didn't fire)**

Diagnosis:
- Was the Flink job running? Check Flink job uptime metric — was there a restart?
- Was the relevant rule enabled? Check rule store: `SELECT * FROM rules WHERE id='SSH_BRUTE_FORCE_001'` — was it disabled?
- Did the attack match the rule's conditions? Maybe the attacker used a technique not covered by existing rules (new attack pattern requiring new rule)
- Did the attack stay below thresholds? 9 attempts per 60 seconds with 10-attempt threshold

**Category 5: Alert was generated but analyst didn't see it**

Diagnosis:
- Check alerts table: `SELECT * FROM alerts WHERE created_at BETWEEN ? AND ?` — were there alerts?
- Check PagerDuty: did notifications fire but get silenced (maintenance window, schedule gap)?
- Check analyst queue: was the alert buried in noise (alert fatigue scenario)?
- Check alert suppression: was a suppression rule matching this alert's rule_id active?

**Category 6: SIEM was under attack during the breach**

Diagnosis:
- Were any SIEM platform components restarted during the window (Elasticsearch restarts, Flink restarts)?
- Were logs deleted from Elasticsearch for this time range (index exists but has fewer documents than expected given normal event rates)?
- Were correlation rules modified during the breach window?

The last category is the most concerning — if the attacker also attacked the SIEM, the absence of alerts may be evidence, not an oversight.

---

### Q3: A new log source — a SaaS application that only exports logs in an undocumented proprietary JSON format — needs to be onboarded to the SIEM. Walk through the full process.

**Direct answer:**

**Step 1: Log format discovery**

Collect a representative sample: 10,000 log events covering different event types (login, logout, admin action, error, data access). Store in a staging area.

Analyze the structure:
```python
# Find all unique top-level keys and their value types
import json
from collections import defaultdict

schema = defaultdict(set)
for line in open('sample.json'):
    event = json.loads(line)
    for k, v in event.items():
        schema[k].add(type(v).__name__)
print(schema)
```

Identify: timestamp field (what format? Unix epoch? ISO 8601? Custom?), event type field, user identity field, source IP field, action/outcome fields.

**Step 2: Parser development**

Write a dissect or grok pattern for each event type. Test against the sample:
```
Pattern for login event:
{
  "timestamp": "%{ts}",
  "event_type": "user_login",
  "user": "%{user.name}",
  "ip": "%{source.ip}",
  "success": "%{event.outcome_raw}"
}
ECS mapping: event.outcome_raw == true → "success", false → "failure"
```

**Step 3: Dead letter queue analysis**

Run parser against 10K sample events. For any event that fails to parse: analyze why, fix the parser or create a separate parser for edge cases. Aim for >99% parse rate before production.

**Step 4: ECS normalization**

Map every extracted field to an ECS field:
- `user` → `user.name`
- `ip` → `source.ip` (or `destination.ip` depending on semantics)
- `action` → `event.action`
- Invent new fields (in a custom namespace) only if no ECS field exists

**Step 5: Correlation rule review**

Once the parser is deployed, review existing correlation rules: do any apply to this new source? An SSH brute-force rule watching `event.action=ssh-login-failure` won't catch SaaS login failures unless the rule also covers `event.action=saas-login-failure`. Update rule conditions.

**Step 6: Test in staging**

Deploy parser to staging. Feed synthetic attack scenarios. Verify alerts fire correctly.

**Step 7: Production rollout**

Deploy parser alongside existing parsers (parser selection by source type field). Monitor parse failure rate for 24 hours. If >1% failure: investigate and fix before declaring success.

---

### Q4: How would you detect an attacker who is deleting their tracks from a Linux system's audit log, and how does the SIEM play a role?

**Direct answer:**

**What the attacker does:**
```bash
# Clear bash history
history -c && unset HISTFILE
# Clear auth log
> /var/log/auth.log
# Stop auditd
systemctl stop auditd
# Delete audit log
> /var/log/audit/audit.log
# Clear last login records
> /var/log/wtmp && > /var/log/btmp && > /var/run/utmp
```

**How the SIEM detects this:**

The key insight: in a well-configured environment, log tampering generates its own logs before the tampering completes — and those logs are already shipped to the SIEM.

**Detection method 1 — auditd IMMUTABLE mode:**
If auditd has the `-e 2` (IMMUTABLE) flag set, the audit configuration cannot be changed without a reboot. `systemctl stop auditd` will fail. The attempt to stop auditd is itself audited.

**Detection method 2 — Kernel audit syscall monitoring:**

auditd rules that detect log tampering:
```
# Monitor file opens with write intent for log files
-w /var/log/auth.log -p wa -k auth_log_write
-w /var/log/audit/audit.log -p wa -k audit_log_write
-w /var/log/wtmp -p wa -k wtmp_write

# Monitor auditd stop attempts
-a always,exit -F arch=b64 -S kill -F a1=SIGTERM -F exe=/usr/bin/systemctl -k stop_auditd
```

These generate auditd events BEFORE the log is cleared. The auditd event is shipped to the SIEM in real-time via the remote logging path (Filebeat reading `/var/log/audit/audit.log` and shipping to Kafka). The clearing of auth.log generates an auditd event for the open+truncate syscalls.

**Detection method 3 — Log gap detection:**

The SIEM monitors the rate of log events per source. If `prod-web-01` goes from 200 events/minute to 0 events/minute (not even heartbeat), within 5 minutes an alert fires: "Log source gap detected for prod-web-01." Even if all local logs are cleared, this alert already fired.

**Detection method 4 — Remote syslog path:**

If sshd sends events to both local syslog AND a remote syslog server (configured in `/etc/rsyslog.d/remote.conf`), clearing the local auth.log does NOT clear the remote copy. The attacker would need to compromise the remote syslog server too.

**Detection method 5 — Filesystem integrity monitoring:**

Tools like AIDE or Tripwire take cryptographic hashes of log files. A scheduled check detects truncation: expected size > 0 bytes, found 0 bytes. Alert.

**The SIEM's role:** Centralize ALL of these detection signals. The SIEM doesn't just wait for alarms — it correlates: "auditd stopped on host X" + "log gap from host X" + "prior SSH failures to host X" = "active compromise with evidence destruction in progress."

---

### Q5: Explain exactly how a SIEM can suffer from false negative rates due to event sampling, and why sampling is sometimes necessary.

**Direct answer:**

**Why sampling happens:**

At extreme log volumes (100M events/minute across 50,000 hosts), full event processing may exceed the SIEM's processing capacity. Rather than dropping events randomly (which creates unpredictable blind spots), the SIEM applies intelligent sampling:

1. **Head-based sampling:** Sample X% of events from high-volume, low-value sources. Example: 100% of authentication events (high security value), 10% of web access logs (low individual value, high volume).

2. **Tail-based sampling:** Collect all events, but only retain/process a fraction for detailed analysis. Retain 100% of events that match any alert condition; retain 1% of non-alerted events.

**How false negatives arise from sampling:**

Scenario: Brute-force rule requires 10 failures in 60 seconds. Web access log sampling is set to 10%.

Attacker sends 100 authentication failures via the web login (logged to web access log). Expected behavior: 100 events → trigger alert at count=10.

With 10% sampling: only 10 events reach the correlation engine. Expected: count=10 → alert fires.
But sampling is probabilistic. In this instance, only 8 events were sampled. Alert threshold of 10 is NOT reached. False negative.

**The compounding effect:**

In a distributed attack (100 source IPs × 5 failures each = 500 total failures), with 10% sampling, you expect 50 events. But each individual (src_ip, dst_host) state key receives only ~0.5 events on average. No per-IP rule fires. A global rule (aggregate across all source IPs) might still fire if the counting correctly aggregates the sampled events — but the count would be 50 instead of 500, so any threshold > 50 would miss it.

**Why sampling is sometimes necessary:**

For a 1TB/day SIEM indexing all events, storing all historical data on SSD is cost-prohibitive. Sampling 10% reduces storage by 90%. For compliance: you may be required to retain all authentication events but can sample network flow data. Sampling is a cost-vs-completeness trade-off.

**Mitigation — smart sampling:**

1. Never sample event types that correlation rules depend on. Maintain a dependency map: rule → event types. If `SSH_BRUTE_FORCE_001` depends on `event.action=ssh-login-failure`, those events are NEVER sampled.
2. Per-entity sampling, not per-event: if an entity (IP, user, host) has matched a rule in the last 24 hours, apply 0% sampling for that entity. Entities in investigation have full coverage.
3. Sample on storage, not on correlation: process ALL events through the correlation engine, but only store a sample in Elasticsearch for analyst review. This gives 0% false negative rate in detection with 90% storage savings.

---

### Q6: How does the SIEM handle clock skew between source systems, and why does it matter for correlation?

**Direct answer:**

**The problem:**

A correlation rule: "SSH failure within 60 seconds of port scan." The port scan happens at T=0 (by real-time clock). The port scanner's system clock is 90 seconds behind. It logs the event with timestamp T-90s. The SSH failure (on a correctly-synced server) is logged at T=30s.

In the event stream, the correlation engine sees:
- Event A: SSH failure, timestamp T=30s
- Event B: port scan, timestamp T-90s (arrives after Event A due to processing delay)

If the correlation engine uses event timestamps for window ordering:
- Event A at T=30s
- Event B at T-90s → 120 seconds before Event A → outside the 60-second window → rule doesn't fire. False negative.

**SIEM timestamp fields:**

A correctly designed SIEM maintains multiple timestamps:
- `@timestamp` / `event.created`: when the event was CREATED by the source system (potentially skewed)
- `event.ingested`: when the event was RECEIVED by the SIEM pipeline (from Kafka broker receive time)
- `event.start/end`: event duration (for multi-moment events)

For correlation, the question is: which timestamp to use?

**Using event time (`event.created`):**
- Correct for detecting attack sequences that happened in order
- Vulnerable to clock skew — events from misconfigured hosts create false windows
- Requires watermarking (Flink's event-time processing with watermarks): the engine knows to wait for late-arriving events up to a configurable bound

**Using processing time (`event.ingested`):**
- Immune to clock skew — all events ordered by when they arrived at the SIEM
- May miss sequences where fast events took longer to process than slow events
- Simpler to implement correctly

**Production approach — event-time with watermarks:**

Flink event-time processing:
1. Order all events by `@timestamp` (event time)
2. Define a watermark: the SIEM won't fire a rule for window [T, T+60s] until it has received events with timestamp T+90s (allowing 30 seconds of late arrivals)
3. Events arriving more than 30 seconds late (by event time vs. current processing time): counted as late events, sent to a separate late-event stream for analysis

This means the SIEM waits up to 30 seconds before finalizing a window. A 60-second brute-force window isn't fired until T+90s processing time. This adds 30 seconds of correlation latency but dramatically reduces false negatives from clock skew.

**Clock synchronization as the real fix:** Deploy NTP (or PTP for microsecond accuracy) on all monitored hosts. Alert when clock offset > 1 second for any host. Most environments tolerate <100ms clock skew with NTP. Clock skew > 5 seconds should alert as a potential misconfiguration or active attack (desynchronizing clocks to evade time-based correlation).

---

### Q7: Describe the architecture of a multi-tenant SIEM where tenants are competitors and data isolation is contractually guaranteed. What are the risks and mitigations?

**Direct answer:**

**The fundamental tension:** Multi-tenancy maximizes infrastructure efficiency (shared Kafka, shared Elasticsearch, shared Flink). But competitors may not accept shared infrastructure for their security data. True data isolation may require logical isolation (within shared infrastructure) or physical isolation (dedicated infrastructure per tenant).

**Tier 1: Logical isolation (most efficient, lower isolation)**

```
Single Kafka cluster:
  - Separate topics per tenant: logs.raw.tenant_A, logs.raw.tenant_B
  - Topic ACLs: Tenant A's agents can only publish to logs.raw.tenant_A
  - Kafka authorization: SASL ACL `Allow:tenantA_producers:WRITE:logs.raw.tenant_A`

Single Elasticsearch cluster:
  - Separate indices per tenant: logs-tenant_A-2024.05.15
  - Index-level permissions: tenant_A service account → Read/Write logs-tenant_A-* only
  - No cross-index queries possible (enforced by xpack.security)
  - Document-level security as backup: every document has tenant_id field, security filter applied

Single Flink cluster:
  - Separate Flink jobs per tenant (one job per tenant, not one job for all)
  - Job-level isolation: Tenant A's job processes only logs.raw.tenant_A
  - State isolation: each job's RocksDB is in a separate directory

Risks of logical isolation:
  - Software bug (missing tenant filter) → cross-tenant data access
  - Noisy neighbor (Tenant B's DDoS fills Kafka → Tenant A's events drop)
  - Elasticsearch co-location: heap pressure from Tenant B's queries → GC → Tenant A's queries slow
  - Administrative access: SIEM admin can read all tenants (requires contractual controls)
```

**Tier 2: Physical isolation (most isolation, least efficient)**

```
Separate Kafka cluster per tenant (or per group of non-competing tenants)
Separate Elasticsearch cluster per tenant
Separate Flink deployment per tenant
Separate VPC per tenant (cloud networking isolation)

Cost: 10× the infrastructure
Isolation: true physical separation — software bugs can't cross tenants
Operational complexity: 50 tenants = 50 clusters to manage
```

**Tier 3: Hybrid (recommended)**

Group competing tenants into separate cluster pools. Non-competing tenants in the same industry (or same parent company) can share. Direct competitors get separate clusters.

**Key security controls regardless of tier:**
1. Encryption at rest with tenant-specific KMS keys: even if Elasticsearch data is exfiltrated, Tenant A's data is encrypted with Tenant A's key
2. Separate admin accounts per tenant: SIEM admin for Tenant A cannot access Tenant B's cluster
3. Audit log of every cross-tenant admin action
4. Automated compliance testing: weekly test verifying Tenant A cannot access Tenant B's data

---

### Q8: What happens to in-flight log events when the SIEM's stream processing (Flink) cluster crashes? Describe the full recovery scenario with no data loss.

**Direct answer:**

**State at crash moment (T=0):**
- Kafka: logs.raw contains 10M unconsumed events (Flink consumer group offset is at position X)
- Flink: has processed up to Kafka offset X+500,000 and produced events to logs.normalized (last checkpoint was at offset X+100,000, saved to S3 60 seconds ago)
- Flink state: RocksDB snapshot at checkpoint (offset X+100,000) saved to S3
- Events X+100,001 to X+500,000: processed by Flink, produced to logs.normalized, but this Kafka produce was part of a Kafka transaction that was not committed before the crash

**Recovery sequence:**

**Step 1: Flink detects failure (T=1s–30s)**
- Flink job manager detects task manager heartbeat failures
- Job manager initiates recovery: restores last successful checkpoint from S3
- Checkpointed state: Flink consumer group offset = X+100,000
- Checkpointed Flink state: all window states (correlation counts, sequence states) as of T-60s

**Step 2: Kafka transaction rollback (T=30s)**
- The Kafka transactions started by Flink (produce to logs.normalized) were not committed before crash
- Kafka broker automatically aborts uncommitted transactions after transaction.timeout.ms (default 60s)
- Events X+100,001 to X+500,000 that were "produced" to logs.normalized are rolled back — they are NOT visible to downstream consumers
- Consumers of logs.normalized (enrichers, Elasticsearch indexers) never see these events

**Step 3: Flink restarts and replays (T=30s–90s)**
- Flink resumes consuming from Kafka offset X+100,001 (the checkpoint's committed offset)
- Events X+100,001 to X+500,000 are re-processed (at-least-once behavior)
- With Kafka transactions + exactly-once semantics: each event is processed exactly once despite the replay
- Window states are restored from checkpoint: correlation engine has state as of T-60s, and replays the last 60 seconds of events to bring state back to current

**Step 4: Normal operation resumes (T=90s)**
- Flink catches up on the 10M events that queued in Kafka during the outage
- Consumer lag peaks (visible in metrics) then decreases as Flink catches up
- Alert: consumer lag spiked but recovered — operational incident closed

**Result: zero data loss.** Events X+100,001 onward were all re-processed correctly. The S3 checkpoint is the safety net. Kafka's 7-day retention is the recovery window — even if Flink is down for 7 days, no data is lost (though 7 days of catch-up would take significant time).

**What if the S3 checkpoint is corrupted?**
Fall back to the previous checkpoint (S3 keeps the last N checkpoints, configurable). If all checkpoints are corrupted, fall back to the beginning of the Kafka topic (full replay from 7 days ago). This is slow but achieves eventual consistency.

---

*End of document. This breakdown should be revisited when the streaming framework version, ingestion protocol, Elasticsearch major version, or tenant isolation model changes. Security properties in a SIEM are especially critical — an insecure SIEM is worse than no SIEM, as it provides false confidence while potentially providing attackers with a map of your detection coverage.*
