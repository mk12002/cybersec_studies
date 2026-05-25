# Graph-Based Fraud & Bot Detection — Internal Engineering & Security Document

**Classification:** Internal Engineering Reference
**Audience:** Detection Engineers, ML Engineers, SOC Analysts, Data Architects
**Scope:** Complete breakdown of a production graph-based fraud and bot detection system — from raw telemetry ingestion to ML inference, alert correlation, and SOAR integration
**System Context:** A fintech platform detecting account takeover, synthetic identity fraud, coordinated bot rings, and payment fraud across 50M users processing 200,000 events/second

---

## A Beginner's Orientation: Why Graph-Based Detection?

**The core insight:** Fraudsters don't operate in isolation. They share infrastructure:
- 500 fake accounts all created from the same /24 IP subnet
- A bot ring where every account uses the same mobile device fingerprint
- A fraud ring where "John Smith" at address A connects to "Jane Doe" at address B through a shared phone number, shared device, and shared shipping address

**Why traditional ML fails here:** A classifier that scores each account in isolation cannot see these connections. Account 12345 might look completely legitimate individually — but it shares a phone number with 400 other accounts, all created in the same 72-hour window, all making similar purchases. That pattern only emerges when you model the *relationships* between entities, not just the entities themselves.

**What a graph captures:**

```
Traditional view:
  Account_12345 → [age: 3 days, location: NYC, purchase: $299]
  Looks fine in isolation.

Graph view:
  Account_12345 ──shares_phone──► Phone_555-1234
                                       |
                                       ├──shared_by──► Account_99801
                                       ├──shared_by──► Account_77623
                                       ├──shared_by──► Account_54321
                                       └──shared_by──► ... (397 more)

All 400 accounts created within 72 hours → FRAUD RING DETECTED
```

---

## Table of Contents

1. [Threat Detection Narrative](#1-threat-detection-narrative)
2. [Telemetry & Ingestion Flow](#2-telemetry--ingestion-flow)
3. [Feature Engineering Pipeline](#3-feature-engineering-pipeline)
4. [Inference Engine Architecture](#4-inference-engine-architecture)
5. [Correlation & Alerting Flow](#5-correlation--alerting-flow)
6. [Attack Scenarios — Evasion Tactics](#6-attack-scenarios--evasion-tactics)
7. [Failure Points & Scaling](#7-failure-points--scaling)
8. [Mitigations & Defense-in-Depth](#8-mitigations--defense-in-depth)
9. [Observability](#9-observability)
10. [Interview Questions](#10-interview-questions)

---

## 1. Threat Detection Narrative

### Story: Synthetic Identity Fraud Ring

**The attacker's perspective — what they think they're doing:**

A fraud operator has purchased a database of 500 real Social Security Numbers from a data breach. They use these SSNs with fictional names and addresses to create synthetic identities — combinations of real and fake PII that pass basic identity verification because the SSNs are legitimate.

Their operational playbook:

```
Day 1-3: Create 500 accounts spread across 3 days (166/day — plausible volume)
  - Each account: real SSN, fake name, fake address, real prepaid phone
  - Accounts created via residential proxy network (40 different IPs)
  - Device fingerprint rotation: different browser user agent per account
  - Each account passes KYC (SSN is real, just misused)

Day 4-14: Account warming
  - Log in 2-3 times per week (scripted, randomized intervals)
  - Make small purchases ($10-50) — legitimate-looking behavior
  - Leave positive reviews (builds trust score on platform)
  - Verify email addresses (aged email accounts from underground market)

Day 15: Cash-out at 2 AM UTC (low analyst activity)
  - Each account attempts maximum daily withdrawal ($500)
  - Total: 500 × $500 = $250,000
```

**The attacker thinks:** "I've been careful. Each account looks legitimate. I've spread the activity, used residential proxies, warmed the accounts. This will work."

---

**The telemetry being generated — what the systems see:**

Each action generates structured events flowing into the detection pipeline:

```json
// Account creation event (one of 500 over 3 days)
{
  "event": "account.created",
  "account_id": "ACC_001",
  "timestamp": "2024-11-01T09:14:22Z",
  "ip": "45.33.12.87",
  "device_fingerprint": "df_A7B2",
  "ssn_hash": "hash_SSN_001",
  "phone_hash": "hash_PHONE_001",
  "user_agent": "Chrome/120"
}

// Cash-out event (Day 15, 2 AM, one of 500 within 47 minutes)
{
  "event": "withdrawal.initiated",
  "account_id": "ACC_001",
  "amount": 500.00,
  "destination_bank": "ROUTING_112233"
}
```

---

**What the SOC analyst sees — the graph alert:**

```
ALERT: Fraud Ring Detection
Severity: CRITICAL
Risk Score: 94/100
Alert ID: ALERT_2024_1115_00342

Entity: CLUSTER_7821 (detected 2024-11-15 02:23:47 UTC)

Graph Properties:
  Nodes: 500 account nodes, 40 IP nodes, 12 phone-prefix nodes
  Edges:
    500 "account → IP" edges (residential proxy patterns)
    500 "account → phone" edges (prepaid SIM cluster)
    500 "account → SSN" edges (SSN co-occurrence cluster)

Anomaly Indicators:
  [CRITICAL] SSN velocity: 500 unique SSNs onboarded from 40 IPs in 72h
             Expected: 3.2 unique SSNs per IP per 72h
             Observed: 12.5 per IP — 3.9x anomaly

  [CRITICAL] Withdrawal synchrony: 500 withdrawal.initiated events in 47 min
             Max-withdrawal-amount in 98.6% of events
             Temporal clustering: Gini coefficient = 0.94

  [HIGH] Phone numbers: Same area code prefix, prepaid SIM carrier on 94%
  [HIGH] GNN community score: 0.89 (densely connected component)
  [HIGH] IP ASNs: 40 IPs across 6 known residential proxy providers

Recommended Action:
  BLOCK all 500 accounts pending manual review
  FREEZE withdrawal transactions
  SUBMIT SSN list to fraud consortium

Confidence: 94% (ensemble: GNN + Isolation Forest + velocity heuristics)
```

**The critical insight:** No individual account was anomalous in isolation. The graph connected 500 accounts through shared infrastructure signals that made the ring visible. The simultaneous cash-out was the trigger, but the graph had been building evidence for 15 days.

---

## 2. Telemetry & Ingestion Flow

### Event Sources and Volumes

```
EVENT SOURCE              DAILY VOLUME      PEAK EVENTS/SEC
Authentication logs       150M events/day   8,500/sec
Payment transactions       80M events/day   4,500/sec
Account lifecycle          40M events/day   2,300/sec
Device/session telemetry  200M events/day  11,500/sec
API call logs             500M events/day  30,000/sec
CDN/WAF logs                1B events/day  60,000/sec
Third-party signals        20M events/day   1,200/sec
─────────────────────────────────────────────────────────
TOTAL                      ~2B events/day  ~120,000 avg
                                           ~250,000 peak
```

### The Ingestion Architecture

```
TELEMETRY INGESTION AND PROCESSING PIPELINE
═══════════════════════════════════════════════════════════════════════

APPLICATION TIER              INGESTION TIER              STORAGE/COMPUTE TIER

┌──────────────┐              ┌───────────────────────────────────────────┐
│ Auth Service │──logs──►┐    │  KAFKA CLUSTER (3 regions)                │
└──────────────┘         │    │                                           │
                         │    │  auth-events      [32 partitions, RF=3]   │
┌──────────────┐         │    │  payment-events   [32 partitions, RF=3]   │
│ Payment Svc  │──logs──►├───►│  account-events   [16 partitions, RF=3]   │
└──────────────┘         │    │  device-telemetry [64 partitions, RF=3]   │
                         │    │  graph-edges-raw  [32 partitions, RF=3]   │
┌──────────────┐         │    │  fraud-scores     [16 partitions, RF=3]   │
│ Account Svc  │──CDC───►│    │  alerts           [ 8 partitions, RF=3]   │
│ (Postgres)   │         │    └──────────────────────┬────────────────────┘
└──────────────┘         │                           │
                         │          ┌────────────────┼────────────────┐
┌──────────────┐         │          │                │                │
│ CDN/WAF Logs │──logs──►┘          ▼                ▼                ▼
└──────────────┘             ┌───────────┐   ┌──────────┐   ┌──────────────┐
                             │  Kafka    │   │  Flink   │   │  Spark Batch │
┌──────────────┐             │  Streams  │   │  Jobs    │   │  (EMR)       │
│ 3P Signals   │──API───────►│  Normaliz │   │  Graph   │   │  Historical  │
│ (MaxMind,    │             │  Enrich   │   │  Builder │   │  Recompute   │
│  ThreatIntel)│             │  Router   │   │          │   │  Retraining  │
└──────────────┘             └─────┬─────┘   └────┬─────┘   └──────┬───────┘
                                   │              │                 │
                          ┌────────▼──────────────▼─────────────────▼───────┐
                          │  DOWNSTREAM CONSUMERS                            │
                          │                                                  │
                          │  TigerGraph / Neo4j  (live graph DB)            │
                          │  Redis               (feature cache)             │
                          │  S3                  (archival, training data)   │
                          │  OpenSearch/Kibana   (log exploration)           │
                          └──────────────────────────────────────────────────┘

LATENCY BUDGET (end-to-end):
  Raw event → Kafka:              2-5ms
  Kafka → Normalizer:             5-15ms
  Normalization (with enrichment):3-8ms
  Kafka → Graph DB write:         20-50ms
  Feature extraction:             5-50ms
  ML inference:                   10-100ms
  Alert generation:               5-20ms
  ─────────────────────────────────────
  TOTAL:                          50-250ms (real-time path)
  SLA target:                     < 500ms at p95
```

### Log Parsing and Normalization

Raw application logs are unstructured or semi-structured. The normalization layer standardizes them:

```python
# RAW LOG (from authentication service):
# "2024-11-15 02:14:22.331 INFO auth: User acc_12345 logged in from
#  45.33.12.87 ua=Mozilla/5.0 Chrome/120 df=7a3b9c1d2e4f latency=234ms"

# NORMALIZED EVENT (after parsing):
{
    "event_type": "session.login",
    "timestamp": "2024-11-15T02:14:22.331Z",   # ISO 8601 UTC always
    "event_id": "evt_8f3a9c1d",
    "account_id": "acc_12345",
    "ip_address": "45.33.12.87",
    "ip_asn": "AS14061",                         # Enriched via MaxMind local DB
    "ip_country": "US",
    "ip_is_proxy": True,                         # Via IPQualityScore local DB
    "ip_is_residential_proxy": True,
    "device_fingerprint": "7a3b9c1d2e4f",
    "device_os": "Windows 10",
    "device_browser": "Chrome 120",
    "device_is_known": True,                     # Seen before for this account
    "auth_latency_ms": 234,
    # Enrichments added by normalization layer:
    "account_age_days": 14,
    "account_risk_tier": "new",
    "login_count_24h": 1,
}
```

**Normalization pipeline stages:**

```python
class EventNormalizer:
    """
    Kafka Streams processor: raw event → normalized event.
    Target throughput: 250,000 events/second peak.
    Target latency: < 5ms per event.
    """
    def normalize(self, raw_event):
        # Stage 1: Parse raw log format (regex or structured JSON parse)
        parsed = self.parser.parse(raw_event)

        # Stage 2: Type coercion and field standardization
        parsed["timestamp"] = to_utc_iso8601(parsed["timestamp"])
        parsed["account_id"] = normalize_account_id(parsed["account_id"])

        # Stage 3: IP enrichment (MaxMind local database — no API call, < 1ms)
        if parsed.get("ip_address"):
            geo = self.maxmind_reader.city(parsed["ip_address"])
            parsed["ip_country"] = geo.country.iso_code
            parsed["ip_asn"] = get_asn(parsed["ip_address"])
            parsed["ip_is_proxy"] = self.proxy_db.is_proxy(parsed["ip_address"])

        # Stage 4: Device fingerprint resolution
        parsed["device_os"] = parse_ua(parsed.get("user_agent", ""))

        # Stage 5: Context enrichment from Redis (hot lookup, < 1ms)
        account_ctx = self.redis.hgetall(f"acct_ctx:{parsed['account_id']}")
        if account_ctx:
            parsed["account_age_days"] = account_ctx.get("age_days")
            parsed["account_risk_tier"] = account_ctx.get("risk_tier")

        return parsed
```

### Where Latency and Dropped Events Occur

```
FAILURE POINT  LOCATION                 SYMPTOM                    MITIGATION
───────────────────────────────────────────────────────────────────────────────
F1  Producer   Log agent (fluentd)      Events arrive in bursts    Disk buffering
    side       buffers when Kafka slow  after backpressure clears  not memory-only

F2  Kafka      Replication lag during   Latency spike 5ms → 500ms  Monitor ISR size
    broker     broker restart           producers block            Alert if ISR < 2

F3  Normalizer IP enrichment during     50ms spikes during         Hot/cold swap of
               MaxMind DB reload        DB reload                  GeoIP database

F4  Graph DB   Write throughput limit   Not every event becomes    Write only
               ~50k writes/sec          a graph edge               meaningful edges

F5  Consumer   Fraud spike = 5x volume  Alerts arrive 10-30 min    Auto-scale workers
    lag        inference can't keep up  after fraud event          on consumer lag

KEY ALERT THRESHOLDS:
  fluentd_output_queue_length > 10,000 for > 30s    → investigate producer
  kafka_consumer_group_lag > 100,000 messages        → scale consumers
  graph_write_queue_depth > 50,000                   → scale graph writers
  inference_queue_lag_seconds > 30                   → scale GPU workers
```

---

## 3. Feature Engineering Pipeline

### Two Categories of Features

```
STATELESS FEATURES:
  Computed from a single event — no external state needed.
  - ip_is_tor:              lookup in local Tor exit node list
  - user_agent_is_bot:      pattern match against known bot strings
  - email_domain_disposable: check known disposable email list
  Speed: < 1ms, purely local, no network calls
  Scale: trivially horizontal (workers are independent)

STATEFUL FEATURES:
  Require historical context aggregated over a time window.
  - ip_accounts_created_24h:  accounts created from this IP in 24 hours
  - account_unique_devices_30d: unique devices used by this account in 30 days
  - txn_max_daily_limit_rate:  fraction of transactions at maximum daily limit
  Speed: 1-50ms, requires Redis lookup
  Scale: HARD — shared state at 250,000 events/second needs careful design
```

### Sliding Window Feature Computation

```python
class SlidingWindowFeatureEngine:
    """
    Computes velocity and count features over sliding time windows.
    Uses Redis Sorted Sets (ZSET) for O(log N) window queries.

    REDIS PATTERN for "accounts created per IP":
      Key:   velocity:ip_account_create:{ip_hash}
      Type:  ZSET (score = unix timestamp, member = account_id)

    Adding an event:
      ZADD velocity:ip_account_create:{ip_hash} {timestamp} {account_id}

    Querying last 24 hours:
      ZCOUNT velocity:ip_account_create:{ip_hash} {now-86400} {now}
    """

    def compute_ip_velocity_features(self, event):
        ip_hash = hash_ip(event["ip_address"])
        now = event["timestamp"]

        pipe = self.redis.pipeline()
        window_key = f"vel:ip_acct_create:{ip_hash}"
        pipe.zadd(window_key, {event["account_id"]: now})
        pipe.expire(window_key, 86400 * 7)  # 7-day max window TTL

        # Query multiple time windows atomically in one pipeline
        for window_seconds in [3600, 21600, 86400, 604800]:
            pipe.zcount(window_key, now - window_seconds, now)

        results = pipe.execute()
        _, _, count_1h, count_6h, count_24h, count_7d = results

        return {
            "ip_accounts_created_1h": count_1h,
            "ip_accounts_created_6h": count_6h,
            "ip_accounts_created_24h": count_24h,
            "ip_accounts_created_7d": count_7d,
            # Velocity ratio: >0.5 means >50% of daily activity in last hour = spike
            "ip_velocity_ratio_1h_24h": count_1h / max(count_24h, 1),
        }

    def compute_account_behavioral_features(self, account_id):
        pipe = self.redis.pipeline()
        pipe.scard(f"devices:{account_id}:30d")           # Unique device count
        pipe.lrange(f"txn_amounts:{account_id}:7d", 0, -1)  # Recent txn amounts
        pipe.hgetall(f"session_hours:{account_id}")        # Hour-bucket distribution
        results = pipe.execute()
        device_count, txn_amounts_raw, hour_buckets = results

        txn_amounts = [float(x) for x in txn_amounts_raw]

        return {
            "unique_devices_30d": device_count,
            "txn_count_7d": len(txn_amounts),
            "txn_amount_mean_7d": float(np.mean(txn_amounts)) if txn_amounts else 0,
            "txn_amount_std_7d": float(np.std(txn_amounts)) if txn_amounts else 0,
            # max_daily_limit_rate: Fraction of txns at exactly the $500 limit
            # Legitimate users rarely hit the exact maximum — high rate is suspicious
            "txn_max_daily_limit_rate": sum(
                1 for a in txn_amounts if a >= 499.99
            ) / max(len(txn_amounts), 1),
            # Session timing entropy: bots have LOW entropy (always 2 AM)
            # Humans have HIGH entropy (random hours)
            "session_hour_entropy": compute_entropy(
                list(hour_buckets.values()) if hour_buckets else [1]
            ),
        }
```

### Graph-Based Feature Extraction

```python
class GraphFeatureEngine:
    """
    Extracts features from the graph database.
    These capture relationship signals invisible to per-entity models.
    Queries cached in Redis for 5 minutes (graph queries cost 5-200ms each).
    """

    def compute_account_graph_features(self, account_id):
        cache_key = f"graph_features:{account_id}"
        cached = self.redis.get(cache_key)
        if cached:
            return json.loads(cached)

        # Query 1: How many other accounts share this account's IP addresses?
        # Neo4j Cypher:
        shared_ip_result = self.graph.run("""
            MATCH (a:Account {id: $id})-[:LOGGED_IN_FROM]->(ip:IP)
                  <-[:LOGGED_IN_FROM]-(other:Account)
            WHERE other.id <> $id
            RETURN count(DISTINCT other) as shared_ip_count,
                   avg(other.account_age_days) as avg_peer_age
        """, id=account_id).data()[0]

        # Query 2: Connected component size (how large is the fraud ring?)
        component_result = self.graph.run("""
            MATCH (a:Account {id: $id})
            CALL gds.wcc.stream('account-graph')
            YIELD nodeId, componentId
            WHERE gds.util.asNode(nodeId) = a
            WITH componentId
            MATCH (other:Account)
            WHERE gds.util.nodeId(other) IN
                  [n IN gds.wcc.stream.stream('account-graph') WHERE n.componentId = componentId | n.nodeId]
            RETURN count(other) as component_size
        """, id=account_id).data()[0]

        # Query 3: 2-hop suspicious neighbors
        suspicious_result = self.graph.run("""
            MATCH (a:Account {id: $id})-[*1..2]-(neighbor:Account)
            WHERE neighbor.fraud_score > 0.7
            RETURN count(DISTINCT neighbor) as suspicious_count
        """, id=account_id).data()[0]

        features = {
            "shared_ip_account_count": shared_ip_result["shared_ip_count"],
            "avg_peer_account_age_days": shared_ip_result["avg_peer_age"] or 0,
            "connected_component_size": component_result["component_size"],
            "suspicious_2hop_neighbors": suspicious_result["suspicious_count"],
            "is_in_large_component": component_result["component_size"] > 50,
        }

        self.redis.setex(cache_key, 300, json.dumps(features))  # Cache 5 min
        return features
```

### Behavioral Sequence Embeddings

```python
class BehaviorSequenceEmbedder:
    """
    Converts user action sequences into dense vector embeddings.
    Uses a Transformer/LSTM trained on historical session data.

    Each action is a token:
      "session.start"          → token_id: 1
      "page.view.products"     → token_id: 2
      "search.query"           → token_id: 3
      "add.to.cart"            → token_id: 4
      "purchase.initiated"     → token_id: 5
      "withdrawal.initiated"   → token_id: 6
      ... (200 unique action types total)

    Normal session:  [1, 2, 3, 4, 5] → browse → purchase (entropy: high)
    Fraud session:   [1, 6]          → login → withdraw immediately (entropy: low)

    The embedding captures WHAT the user did AND IN WHAT ORDER.
    """

    def embed_session(self, account_id, current_session_actions):
        # Tokenize and embed current session
        token_ids = [self.action_vocab[a] for a in current_session_actions
                     if a in self.action_vocab]
        current_embedding = self.model.encode(token_ids)  # shape: (128,)

        # Retrieve historical session embeddings from Redis
        historical_raw = self.redis.lrange(f"session_embs:{account_id}", 0, 9)
        historical = [np.frombuffer(h, dtype=np.float32) for h in historical_raw]

        if historical:
            similarities = [
                float(np.dot(current_embedding, h) /
                      (np.linalg.norm(current_embedding) * np.linalg.norm(h)))
                for h in historical
            ]
            features = {
                "mean_historical_similarity": float(np.mean(similarities)),
                "min_historical_similarity": float(np.min(similarities)),
                # Low similarity to own history = sudden behavior change = ATO signal
                "is_behavioral_anomaly": float(np.min(similarities)) < 0.30,
            }
        else:
            features = {
                "mean_historical_similarity": None,
                "min_historical_similarity": None,
                "is_behavioral_anomaly": False,
            }

        # Store current embedding for future comparisons
        self.redis.lpush(f"session_embs:{account_id}", current_embedding.tobytes())
        self.redis.ltrim(f"session_embs:{account_id}", 0, 9)  # Keep last 10

        return features
```

### Complete Feature Vector — All 35 Dimensions

```python
FEATURE_VECTOR = {
    # IP velocity (4 features)
    "ip_accounts_created_1h": int,
    "ip_accounts_created_24h": int,
    "ip_accounts_created_7d": int,
    "ip_velocity_ratio_1h_24h": float,

    # IP reputation (6 features)
    "ip_is_proxy": bool,
    "ip_is_residential_proxy": bool,
    "ip_is_tor": bool,
    "ip_is_datacenter": bool,
    "ip_fraud_score": float,           # 0-100 from IPQualityScore
    "ip_asn_known_fraud": bool,

    # Account history (8 features)
    "account_age_days": int,
    "unique_devices_30d": int,
    "txn_count_7d": int,
    "txn_amount_mean_7d": float,
    "txn_amount_std_7d": float,
    "txn_max_daily_limit_rate": float,
    "session_hour_entropy": float,
    "failed_login_count_24h": int,

    # Graph features (7 features)
    "shared_ip_account_count": int,
    "connected_component_size": int,
    "suspicious_2hop_neighbors": int,
    "avg_peer_account_age_days": float,
    "is_in_large_component": bool,
    "shared_ip_density": float,
    "peer_asn_diversity": int,

    # Behavioral sequence (3 features)
    "mean_historical_similarity": float,
    "min_historical_similarity": float,
    "is_behavioral_anomaly": bool,

    # Device (5 features)
    "device_is_known": bool,
    "device_new_for_account": bool,
    "device_accounts_count_7d": int,   # How many accounts use this device?
    "device_automation_detected": bool, # Selenium/Appium signals
    "device_font_entropy": float,

    # Session (2 features)
    "session_action_count": int,
    "session_duration_seconds": int,
}
# TOTAL: 35 features per event (after all stateful and stateless computation)
```

---

## 4. Inference Engine Architecture

### Three-Layer Ensemble Design

```
LAYER 1: DETERMINISTIC RULES        (< 1ms, no ML, binary output)
  Catches known-bad patterns with certainty.
  Zero false negatives for patterns in the rule set.
  Example: IP in confirmed-fraud blocklist → AUTO_BLOCK immediately.

LAYER 2: ISOLATION FOREST          (< 5ms, unsupervised anomaly detection)
  Catches individual account anomalies without labels.
  Works on raw feature vectors.
  Fails for coordinated rings (scores each account independently).

LAYER 3: GRAPH NEURAL NETWORK      (5-100ms, supervised, relationship-aware)
  Catches coordinated fraud rings.
  Requires graph structure to be populated.
  Trained on labeled fraud samples with neighborhood context.

ENSEMBLE COMBINER:
  final_score = (
    0.30 × rule_score +
    0.20 × isolation_forest_score +
    0.35 × gnn_score +
    0.15 × behavior_sequence_score
  )
  Weights learned from validation set; reviewed monthly.
```

### Layer 2: Isolation Forest — Mechanics

```python
"""
HOW ISOLATION FOREST WORKS:

Build 100 random binary trees. In each tree, randomly select a feature
and randomly select a split value between the feature's min and max.
Repeat until each data point is in its own leaf node.

Anomaly score formula:
  s(x) = 2^( -E[h(x)] / c(n) )

  E[h(x)] = average isolation depth across all 100 trees
  c(n)    = expected depth of a binary search tree with n nodes
             c(n) = 2*H(n-1) - 2*(n-1)/n   where H = harmonic number

  s(x) → 1.0: anomalous (isolated in very few splits — sparse region)
  s(x) → 0.5: normal (average isolation depth)
  s(x) → 0.0: deeply normal (takes many splits to isolate — dense cluster)

WHY it works for individual anomalies:
  An account that logged in from 3 continents in 1 day, used Tor, and attempted
  10 withdrawals is easy to isolate — it's in a very sparse region of feature space.

WHY it FAILS for fraud rings:
  Each ring member is designed to look normal individually.
  Features: [age=15days, ip_velocity=10, device_known=True] — unremarkable.
  Isolation Forest scores this: 0.55 (below alert threshold).
  Problem: it cannot see that 500 accounts share these same unremarkable features
  AND the same SSN breach batch AND the same phone carrier.
  That pattern is relational, not individual-feature-based.
  → This is exactly why we need the GNN layer.
"""
from sklearn.ensemble import IsolationForest
import joblib, numpy as np

class IsolationForestInference:
    def __init__(self, model_path):
        self.model = joblib.load(model_path)
        self.scaler = joblib.load(f"{model_path}_scaler")

    def score(self, feature_vector):
        X = np.array(feature_vector).reshape(1, -1)
        X_scaled = self.scaler.transform(X)
        # sklearn returns: negative for anomalous, positive for normal
        raw_score = self.model.score_samples(X_scaled)[0]
        # Convert to [0,1] where 1 = most anomalous
        normalized = float(np.clip(1 - (raw_score + 0.5), 0, 1))
        return normalized
```

### Layer 3: Graph Neural Network — GraphSAGE Architecture

```python
"""
WHY GraphSAGE over other GNNs:

GCN (Graph Convolutional Network):
  Requires the FULL graph at training and inference time.
  Can't handle new nodes without retraining.
  → UNUSABLE in production (fraud rings form daily with new accounts)

GAT (Graph Attention Network):
  Better, but attention over all neighbors is expensive for large graphs.

GraphSAGE (Hamilton et al., 2017):
  Inductively learns embeddings by SAMPLING a fixed neighborhood.
  Works on UNSEEN nodes at inference time.
  → PRODUCTION CHOICE: scalable and inductive.

FORWARD PASS MECHANICS for account node v:

  Step 1: Sample neighbors
    N1(v) = random_sample(neighbors(v), k=25)    # 1-hop: 25 neighbors
    N2(v) = random_sample(neighbors(N1), k=10)   # 2-hop: 10 per 1-hop

  Step 2: Layer 1 — aggregate 2-hop neighborhoods into 1-hop embeddings
    For each u in N1(v):
      agg_u = MEAN( [features(w) for w in N2(u)] )
      h_u^1 = ReLU( W1 × concat(features(u), agg_u) )

  Step 3: Layer 2 — aggregate 1-hop embeddings into target embedding
    agg_v = MEAN( [h_u^1 for u in N1(v)] )
    h_v^2 = ReLU( W2 × concat(features(v), agg_v) )

  Step 4: Classify
    fraud_score = sigmoid( W_out × h_v^2 )

  h_v^2 is 128-dimensional and encodes BOTH v's own features AND
  what its neighborhood looks like up to 2 hops away.

  Key: Two accounts might have identical individual features.
  But if one is connected to 400 fraud accounts in its neighborhood,
  the GNN embedding reflects this → score goes from 0.55 to 0.89.
"""
import torch
import torch.nn.functional as F
from torch_geometric.nn import SAGEConv

class FraudGNN(torch.nn.Module):
    def __init__(self, input_dim=35, hidden_dim=128):
        super().__init__()
        self.conv1 = SAGEConv(input_dim, hidden_dim, aggr="mean")
        self.conv2 = SAGEConv(hidden_dim, hidden_dim, aggr="mean")
        self.bn1 = torch.nn.BatchNorm1d(hidden_dim)
        self.bn2 = torch.nn.BatchNorm1d(hidden_dim)
        self.classifier = torch.nn.Sequential(
            torch.nn.Linear(hidden_dim, 64),
            torch.nn.ReLU(),
            torch.nn.Dropout(0.3),
            torch.nn.Linear(64, 1),
            torch.nn.Sigmoid()
        )

    def forward(self, x, edge_index):
        """
        x: Node feature matrix [num_nodes × 35]
        edge_index: Graph connectivity [2 × num_edges]
        """
        h1 = F.dropout(F.relu(self.bn1(self.conv1(x, edge_index))), p=0.2, training=self.training)
        h2 = F.relu(self.bn2(self.conv2(h1, edge_index)))
        return self.classifier(h2)

    def score_account(self, account_id, graph_loader):
        self.eval()
        with torch.no_grad():
            # Load 2-hop subgraph around this account (avoids loading full graph)
            subgraph = graph_loader.load_subgraph(account_id, hops=2, max_neighbors=25)
            x = torch.tensor(subgraph.node_features, dtype=torch.float32)
            edge_index = torch.tensor(subgraph.edge_index, dtype=torch.long)
            scores = self.forward(x, edge_index)
            return float(scores[subgraph.target_node_idx])
```

### Inference Modes: Streaming vs Micro-Batch vs Scheduled

```
MODE 1: STREAMING INFERENCE (real-time, per-event)
  Trigger:   account.created, withdrawal.initiated, password.change
  Latency:   < 200ms
  Models:    Rules + Isolation Forest (fast)
             GNN: serve from cache (expensive; cached score up to 10 min old)
  Use case:  Block/allow at the moment of the action

MODE 2: MICRO-BATCH INFERENCE (near-real-time, grouped)
  Trigger:   Every 30 seconds, accumulated events form a mini-graph
  Latency:   < 60 seconds end-to-end
  Models:    Full GNN on the 30-second event mini-graph
  Use case:  Detect rings forming across multiple events in the window

MODE 3: SCHEDULED BATCH RE-SCORING (hourly)
  Trigger:   Cron job, every hour
  Latency:   Up to 1 hour acceptable
  Models:    Full GNN on entire account graph
  Output:    Updated risk scores for all accounts → Redis cache
  Use case:  Catch low-and-slow attackers; update risk tiers

ROUTING LOGIC:
  HIGH_RISK_EVENTS = {'withdrawal.initiated', 'password.change', 'email.change'}
  if event_type in HIGH_RISK_EVENTS:
      use STREAMING (must decide now — money at risk)
  elif event_type in MEDIUM_RISK_EVENTS:
      use MICRO_BATCH (aggregate context matters more than instant decision)
  else:
      use SCHEDULED_BATCH (account creation, browsing — decision not urgent)
```

### Redis Caching Layer

```python
class InferenceCacheLayer:
    """
    Two-level cache to avoid expensive graph queries on every event.
    L1: In-process dict (< 0.1ms, 30s TTL)
    L2: Redis (< 1ms, feature-specific TTL)
    """
    TTLS = {
        "ip_fraud_score": 300,         # 5 min — can change if IP added to blocklist
        "account_risk_tier": 900,      # 15 min — changes slowly
        "graph_neighborhood": 300,     # 5 min — ring membership changes rarely
        "gnn_embedding": 600,          # 10 min — expensive, stable
        "isolation_forest_score": 120, # 2 min — changes with new behavior
    }

    def get_or_compute(self, cache_key, compute_fn, ttl_key):
        # L1: in-process
        if cache_key in self.l1 and time.time() - self.l1[cache_key]["ts"] < 30:
            return self.l1[cache_key]["value"]

        # L2: Redis
        cached = self.redis.get(cache_key)
        if cached:
            value = json.loads(cached)
            self.l1[cache_key] = {"value": value, "ts": time.time()}
            return value

        # Cache miss: compute
        value = compute_fn()
        self.redis.setex(cache_key, self.TTLS[ttl_key], json.dumps(value))
        self.l1[cache_key] = {"value": value, "ts": time.time()}
        return value
```

---

## 5. Correlation & Alerting Flow

### From ML Score to SOC Alert

```python
class AlertCorrelationEngine:

    def compute_risk_score(self, event, scores):
        """Weighted ensemble of model scores."""
        weights = {
            "rule_engine_score": 0.30,
            "isolation_forest_score": 0.20,
            "gnn_score": 0.35,
            "behavior_sequence_score": 0.15,
        }
        composite = sum(
            scores.get(m, 0) * w for m, w in weights.items()
        )
        # Boost for high-risk event types
        MULTIPLIERS = {
            "withdrawal.initiated": 1.3,
            "password.change": 1.2,
            "email.change": 1.2,
            "payment_method.added": 1.1,
        }
        multiplier = MULTIPLIERS.get(event["event_type"], 1.0)
        return float(min(composite * multiplier, 100))

    def compute_severity(self, risk_score, event):
        if risk_score >= 90 and event["event_type"] in HIGH_VALUE_EVENTS:
            return "CRITICAL"    # Auto-block, page on-call analyst
        elif risk_score >= 80:
            return "HIGH"        # Alert SOC, action within 15 minutes
        elif risk_score >= 65:
            return "MEDIUM"      # SOC review within 4 hours
        elif risk_score >= 50:
            return "LOW"         # Investigate next business day
        else:
            return "INFO"        # Log only

    def correlate_with_recent_alerts(self, account_id, new_alert):
        """Escalate when multiple alerts form a pattern."""
        recent = self.redis.lrange(f"recent_alerts:{account_id}", 0, 9)
        for past_json in recent:
            past = json.loads(past_json)
            time_gap = new_alert["timestamp"] - past["timestamp"]
            # ATO pattern: password change + withdrawal within 10 minutes
            if (time_gap < 600
                and past["event_type"] == "password.change"
                and new_alert["event_type"] == "withdrawal.initiated"):
                new_alert["severity"] = "CRITICAL"
                new_alert["correlation_reason"] = "ATO_PATTERN"
                new_alert["correlated_alert_id"] = past["alert_id"]
        return new_alert

    def enrich_alert(self, alert, account_id, event):
        """Add investigative context so SOC can act immediately."""
        alert["evidence"] = {
            "account_age_days": event.get("account_age_days"),
            "ip_is_proxy": event.get("ip_is_proxy"),
            "ip_fraud_score": event.get("ip_fraud_score"),
            "device_first_seen": self.redis.get(
                f"device_first:{event['device_fingerprint']}"
            ),
            "connected_accounts": event.get("shared_ip_account_count"),
            "fraud_ring_size": event.get("connected_component_size"),
            "suspicious_neighbors": event.get("suspicious_2hop_neighbors"),
            "score_breakdown": event.get("scores"),
            # Deep-dive links for SOC analyst
            "raw_events_link": f"https://kibana.internal/account/{account_id}",
            "graph_link": f"https://graph.internal/explore?node={account_id}",
            "soar_case_link": f"https://soar.internal/cases?entity={account_id}",
        }
        return alert
```

### SOAR Integration

```python
class SOARIntegration:
    PLAYBOOKS = {
        "CRITICAL_FRAUD_RING": {
            "actions": [
                "block_all_accounts_in_component",
                "freeze_pending_withdrawals",
                "alert_on_call_analyst",
                "submit_to_fraud_consortium",
            ],
            "requires_approval": False,  # Auto-execute for CRITICAL
        },
        "HIGH_ATO_PATTERN": {
            "actions": [
                "lock_account",
                "require_step_up_auth",
                "alert_soc_queue",
            ],
            "requires_approval": False,
        },
        "MEDIUM_SUSPICIOUS_LOGIN": {
            "actions": [
                "flag_account_for_review",
                "increase_monitoring_sensitivity",
                "create_soc_case",
            ],
            "requires_approval": True,  # SOC analyst must approve action
        },
    }

    def dispatch_alert(self, alert):
        playbook_name = self.select_playbook(alert)
        playbook = self.PLAYBOOKS.get(playbook_name)

        if not playbook:
            return self.create_manual_case(alert)

        if not playbook["requires_approval"]:
            for action in playbook["actions"]:
                self.execute_action(action, alert)

        # Always create SOAR case for audit trail
        return self.soar_api.create_case({
            "title": f"{alert['severity']}: {alert['alert_type']} - {alert['entity_id']}",
            "severity": alert["severity"],
            "source": "fraud_detection_system",
            "evidence": alert["evidence"],
            "playbook": playbook_name,
            "risk_score": alert["risk_score"],
        })
```

### Threshold Tuning

```
COST-BASED THRESHOLD OPTIMIZATION:

  Cost of FALSE NEGATIVE (missed fraud):    $500 average loss
  Cost of FALSE POSITIVE (blocked user):    ~$21 (lost purchase + CS + churn probability)

  Optimal threshold: FP_cost × FP_rate = FN_cost × FN_rate

  At threshold=0.50: Precision=0.71, Recall=0.91
    → Too many FPs. SOC overwhelmed, starts ignoring alerts → worse outcomes

  At threshold=0.70: Precision=0.89, Recall=0.73
    → Good balance. SOC manageable. 73% of fraud caught.

  At threshold=0.85: Precision=0.97, Recall=0.54
    → FPs near zero but 46% of fraud slips through → financial losses exceed benefit

  PRODUCTION THRESHOLDS:
  ┌──────────────────────┬────────────────────┬────────────────────────┐
  │ Model                │ Alert Threshold    │ Auto-Action Threshold  │
  ├──────────────────────┼────────────────────┼────────────────────────┤
  │ Rule Engine          │ Any match = block  │ Any match = block      │
  │ Isolation Forest     │ 0.75               │ 0.90                   │
  │ GNN                  │ 0.65               │ 0.85                   │
  │ Behavior Sequence    │ 0.70               │ 0.88                   │
  │ ENSEMBLE (final)     │ 0.70               │ 0.85                   │
  └──────────────────────┴────────────────────┴────────────────────────┘

  Review cycle: Monthly evaluation against 30-day holdout.
  SOC capacity constraint: If alert volume > 100 HIGH/day, raise threshold.
```

---

## 6. Attack Scenarios — Evasion Tactics

### Evasion 1: Low-and-Slow (Velocity Threshold Evasion)

**The attacker's reasoning:** "The system uses velocity features — accounts per IP per 24h. If I stay below 50, I'm invisible."

**Step-by-step execution:**

```
Detection threshold:  50 accounts per IP per 24h
Attacker's plan:      10 accounts per IP per 24h (20% of threshold)

Week 1 cadence:
  IP_001: 10 accounts on Day 1, 10 on Day 2, ... → 70 total in 7 days
  IP_002: Same pattern
  IP_003: Same pattern
  IP_004: Same pattern

  Per-IP velocity: 10/24h → BELOW threshold → NO ALERT
  Across 4 IPs × 7 days: 280 accounts created in 1 week

  Each account still uses the SAME SSN breach batch.

Week 2:
  280 warmed accounts attempt maximum withdrawals simultaneously.
```

**What attacker thinks:** "I was below velocity thresholds the whole time."

**Why the graph still catches it:**

```python
# The graph builds evidence across 7 days even though per-day velocity is low:

# Day 1: 40 accounts → 4 IPs → same SSN batch prefix detected
#   GNN community score: 0.72
#   Alert: MEDIUM (score 68) — SOC queued for review

# Day 4: 160 accounts → same 4 IPs → tighter SSN co-occurrence cluster
#   GNN community score: 0.81
#   Alert: HIGH (score 78) — SOC action within 15 minutes

# Day 7 cash-out: 280 simultaneous withdrawal.initiated events
#   Gini coefficient of withdrawal timing: 0.92 (nearly synchronized)
#   Alert: CRITICAL (score 94) — auto-block, freeze withdrawals

# The per-IP velocity feature missed it.
# The SSN co-occurrence in the graph caught it on Day 1.
# The simultaneous cash-out confirmed it on Day 7.
```

**Why it might still evade detection (true false negative scenario):**

```
If attacker ALSO:
  - Uses 3 separate SSN breach databases (no SSN co-occurrence)
  - Infrastructure spread across 6 proxy networks (no ASN concentration)
  - Cash out over 3 days, varying amounts $100-300 each

  Result:
    Per-IP velocity: 10/24h → BELOW threshold
    SSN co-occurrence: NONE detected (different breach batches)
    GNN community score: 0.51 (barely connected — no shared infra)
    MISSED by detection system

  Total haul: 280 × $200 average = $56,000 (lower yield but undetected)
  Attack cost: 3 SSN databases + 6 proxy networks → likely negative ROI at small scale
```

---

### Evasion 2: Feature Mimicking (Behavioral Camouflage)

**The attacker's reasoning:** "If I make my bots behave like real users, ML scores will be low."

**Step-by-step execution:**

```python
# Attacker studies legitimate user behavior first:
# - Real users browse 4-7 pages before purchasing
# - session_hour_entropy > 0.7 (login at various times)
# - unique_devices_30d: 1-3 devices
# - Transactions: varied amounts $20-300

class CamouflageBotSession:
    def run(self):
        # Mimic browsing — realistic page count and dwell time
        for _ in range(random.randint(4, 7)):
            api.view_page(random.choice(PRODUCT_CATEGORIES))
            time.sleep(random.uniform(10, 45))   # Human-like reading time

        api.search(Faker().word())               # Search like a human
        time.sleep(random.uniform(5, 20))

        # Warm-up purchases before cash-out
        api.purchase(amount=random.uniform(20, 80))

        # Schedule sessions across random hours over 14 days
        # This raises session_hour_entropy above the detection threshold

# After 14 days of warming:
# session_hour_entropy: 0.74 → PASSES (mimicked human hour distribution)
# txn_amount_std_7d: 28.3   → PASSES (varied purchase amounts)
# unique_devices_30d: 1.1   → PASSES (mostly one device)
```

**Why the graph is harder to fool:**

```
The mimicked features pass individual scoring:
  session_hour_entropy: 0.74 → OK
  txn_amount_std_7d: 28.3   → OK
  unique_devices_30d: 1.1   → OK
  IF score: 0.58             → below alert threshold

BUT the graph and device signals still reveal the ring:
  - All 500 accounts still created from residential proxy ASNs
  - Device fingerprints show Puppeteer/Playwright traces in HTTP headers
    (the automation framework leaves subtle signals: navigator.webdriver=true,
    missing certain browser plugins, consistent canvas fingerprint)
  - Page view SEQUENCES look random but share the SAME DISTRIBUTION
    (bots randomize within ranges; the distribution itself is identical)
  - All 500 accounts share the SAME COOKIE CONSENT flow fingerprint
    (the bot framework handles consent identically every time)

GNN neighborhood still sees: 500 accounts in the same connected component
(they still share proxy ASNs even if not the same IPs)
```

**True evasion — what would actually work:**

```
Requirements to fully evade the system:
  1. Real browsers (not headless) on cloud VMs with genuine browser profiles
  2. Residential IPs from different providers (no ASN concentration)
  3. Multiple non-overlapping SSN databases
  4. Cash-out spread over weeks in small amounts ($50-100/day per account)
  5. Different phone carriers

Result: System miss rate ~40% for this attack (red team validated)
Cost: Extremely expensive to operate. Economic return is negative for most actors.

Countermeasure: Behavioral biometrics (mouse movement patterns, typing cadence,
scroll velocity). These are very hard to fake and require real humans or
sophisticated generative models that are prohibitively expensive to deploy at scale.
```

---

### Evasion 3: Account Takeover with Stolen Sessions

**The attacker's reasoning:** "If I use a stolen session cookie, I'm already authenticated. Detection systems trust authenticated sessions."

**Step-by-step execution:**

```
Step 1: Phishing captures Alice's session token
  Alice clicks a phishing link → session_token=eyJhbGci... captured

Step 2: Attacker uses session from different IP and device
  Alice's normal login: NYC (72.48.12.33), Chrome on MacBook M1
  Attacker's session use: Moscow (185.220.x.x), Firefox on Windows 10

Step 3: Attacker immediately: changes password → adds new bank account → initiates $50,000 wire
```

**How the system catches it:**

```python
# SIGNAL 1: IMPOSSIBLE TRAVEL DETECTION
def detect_impossible_travel(account_id, new_event):
    last_login = self.redis.hgetall(f"last_login:{account_id}")
    if not last_login:
        return False

    distance_km = geoip_distance(last_login["ip"], new_event["ip_address"])
    time_hours = (new_event["timestamp"] - float(last_login["timestamp"])) / 3600

    # Max realistic travel speed (accounting for airport time): 600 km/h
    if time_hours > 0 and distance_km / time_hours > 600:
        return {
            "detected": True,
            "distance_km": distance_km,
            "speed_kmh": distance_km / time_hours,
            "from_country": geoip_country(last_login["ip"]),
            "to_country": geoip_country(new_event["ip_address"])
        }
    return False

# Alice logged in from NYC 4 hours ago.
# Session used from Moscow now.
# Distance: 7,510 km in 4 hours = 1,877 km/h → IMPOSSIBLE TRAVEL DETECTED
# → CRITICAL alert generated even before ML scoring

# SIGNAL 2: BEHAVIORAL SEQUENCE ANOMALY
# Alice's normal session: [browse, search, add_to_cart, checkout] (typical user)
# Attacker's session:     [login, password.change, bank_account.add, wire.transfer]
# Sequence similarity to Alice's history: 0.08 (threshold: 0.30)
# → BEHAVIORAL ANOMALY flagged

# SIGNAL 3: DEVICE FINGERPRINT CHANGE
# Alice: always Chrome/MacBook M1 (fingerprint: df_ALICE_001)
# Attacker: Firefox/Windows 10 (fingerprint: df_ATTACKER_XYZ)
# df_ATTACKER_XYZ has NEVER been associated with this account
# device_new_for_account = True → +30 to risk score

# SIGNAL 4: ACTION VELOCITY
# password.change + email.change + bank_account.add within 4 minutes
# → ACCOUNT_CHANGES_VELOCITY rule fires: CRITICAL regardless of ML score
```

---

## 7. Failure Points & Scaling

### Failure 1: Log Flood Under Coordinated DDoS

**Scenario:** Attacker generates 2M events/second (10x peak) to overwhelm detection and slip real fraud through the disruption.

```
WHAT FAILS AT 2M EVENTS/SECOND:

Kafka:
  32 partitions × ~100k events/sec per partition = 3.2M/sec max
  → Kafka itself survives, but consumers fall behind

Normalization layer:
  MaxMind local DB: 800k IP lookups/sec (8 cores)
  At 2M events/sec: enrichment queue builds up
  Resolution: Skip enrichment for overflow (degrade gracefully)

Graph DB writes:
  TigerGraph: ~100k writes/sec sustained
  At 2M events/sec: graph update queue grows
  At 5 min backlog: graph is stale by 5 minutes → GNN uses stale edges

Inference workers:
  GNN: 500 events/sec per A10G GPU
  10 GPUs: 5,000 events/sec capacity
  At 2M: scoring queue = 400x capacity → alerts delayed by hours

TIERED GRACEFUL DEGRADATION:

  < 300k/sec: NORMAL
    Full pipeline: Rules + IF + GNN + Sequence Model

  300k-1M/sec: ELEVATED
    Drop Sequence Model (save 20% capacity)
    Increase GNN cache TTL to 10 min (serve slightly stale scores)

  1M-2M/sec: HIGH LOAD
    Drop GNN (most expensive)
    Run: Rules + Isolation Forest + cached GNN scores from last hour

  > 2M/sec: FLOOD
    Activate DDoS mode: Rule engine only
    Sample 1% of traffic for ML (extrapolate scores cluster-wide)
    Alert: "DEGRADED MODE — ML at 1% coverage, rules-only active"

TRADEOFF: During flood, sophisticated fraud may slip through.
BUT: A DDoS + simultaneous fraud ring is still visible to rules,
     and the graph accumulates events for the hourly batch catch.
```

### Failure 2: Concept Drift

```
DRIFT TYPE 1: GRADUAL (weeks/months)
  Example: Crypto payments go mainstream.
  Before: "large payment to unknown merchant" = fraud signal
  After: normal users make these payments
  Symptom: Precision slowly degrades (more false positives)
  Detection: PSI (Population Stability Index) computed daily

  PSI = Σ (Actual% - Expected%) × ln(Actual%/Expected%)
  PSI < 0.10: No significant drift
  PSI 0.10-0.25: Monitor closely
  PSI > 0.25: RETRAIN — distribution shift is severe

DRIFT TYPE 2: SUDDEN (overnight)
  Example: New fraud tool defeats device fingerprinting.
  "device_is_known=True" was a strong negative fraud signal.
  After drift: it's neutral or slightly positive signal.
  Symptom: Model recall drops 15% in one week.
  Detection: Weekly evaluation against labeled holdout set.

DRIFT TYPE 3: SEASONAL (predictable)
  Example: Holiday shopping season (November-December).
  Purchase amounts spike; unusual merchants become common.
  Model: Over-scores legitimate holiday shoppers.
  Mitigation: Pre-computed seasonal models; lower thresholds during holidays.

RETRAINING PIPELINE:
  Trigger:   PSI > 0.25 on any feature OR recall drops > 10% week-over-week
  Data:      Last 90 days labeled events + synthetic oversampling for rare types
  Duration:  4-6 hours for full GNN retraining
  Validation: Must achieve: precision ≥ 0.87 AND recall ≥ 0.70 on holdout
  Deploy:    Blue-green (5% traffic to new model, compare metrics, then promote)
```

### Failure 3: False Positive Spike During Product Launch

```
SCENARIO: International product launch
  2M new accounts in 48 hours (normally 50k/day — 40x spike)
  New accounts from unusual locations
  Bulk purchases from first-time buyers
  Velocity features hit maximum → ALL new accounts flagged suspicious

IMPACT:
  200,000 false positive alerts in 48 hours
  SOC team: completely overwhelmed (200 analysts × 1,000 alerts each)
  Auto-block: 50,000 legitimate users can't check out
  Business: $2M in lost revenue, social media backlash

DETECTIONS OF THE SPIKE:
  Alert rate: 20x normal → "ML system FP spike detected"
  Block rate: 25x normal → "Automated block rate anomaly"
  Customer support tickets: 500% surge in "account blocked" complaints

MITIGATIONS:
  1. PRE-FLAGGED LAUNCH WINDOWS:
     Ops team marks launch dates in system.
     Relax auto-block threshold: 0.90 (instead of 0.85) during window.

  2. GEOLOCATION CONTEXT:
     New country launch → whitelist new country IPs for 72 hours.
     Still block Tor, known-bad ASNs (non-negotiable signals).

  3. COHORT BASELINE:
     Compare new accounts to EACH OTHER, not to all-time baseline.
     If 1M new accounts look similar → they ARE the new normal, not fraud.

  4. DYNAMIC BASELINE WINDOW:
     Isolation Forest: use partial_fit() with new data in real time.
     Rolling 24-hour baseline for velocity features (not 30-day historical).

  5. HUMAN-IN-THE-LOOP:
     During FP spike: pause auto-block, require human approval.
     Sample 10% of flagged accounts; analyst review determines if spike is real.
```

---

## 8. Mitigations & Defense-in-Depth

### Hybrid Detection: ML + Deterministic Rules

```python
class HybridDetectionEngine:
    """
    Rules handle KNOWN bad patterns with certainty (high precision).
    ML handles NOVEL patterns probabilistically (high recall).
    Together: better than either alone.
    """

    DETERMINISTIC_RULES = [
        {
            "name": "tor_high_value",
            "condition": lambda e: (e.get("ip_is_tor") == True and
                                    e["event_type"] in ["withdrawal.initiated",
                                                         "password.change"]),
            "action": "AUTO_BLOCK",
            "score": 100,
            "reason": "Tor exit node on high-value action",
        },
        {
            "name": "known_fraud_ip",
            "condition": lambda e: e.get("ip_address") in FRAUD_IP_BLOCKLIST,
            "action": "AUTO_BLOCK",
            "score": 100,
            "reason": "IP in confirmed fraud blocklist",
        },
        {
            "name": "extreme_velocity",
            "condition": lambda e: e.get("ip_accounts_created_1h", 0) > 200,
            "action": "AUTO_BLOCK",
            "score": 100,
            "reason": "Extreme account creation velocity (>200/hour from one IP)",
        },
        {
            "name": "ssn_multi_account",
            "condition": lambda e: e.get("ssn_account_count", 0) > 5,
            "action": "AUTO_BLOCK",
            "score": 100,
            "reason": "SSN used for >5 accounts (synthetic identity signal)",
        },
        {
            "name": "automation_detected",
            "condition": lambda e: (e.get("headless_browser_detected") == True and
                                    e["event_type"] == "account.created"),
            "action": "CHALLENGE",  # CAPTCHA — not immediate block
            "score": 80,
            "reason": "Headless browser detected during account creation",
        },
        {
            "name": "account_changes_velocity",
            "condition": lambda e: (e.get("changes_count_5min", 0) >= 3 and
                                    e["event_type"] == "withdrawal.initiated"),
            "action": "AUTO_BLOCK",
            "score": 100,
            "reason": "3+ account changes + withdrawal within 5 minutes (ATO pattern)",
        },
    ]

    def evaluate(self, event, feature_vector):
        # STEP 1: Deterministic rules first (< 1ms, highest confidence)
        for rule in self.DETERMINISTIC_RULES:
            if rule["condition"](event):
                return {
                    "score": rule["score"],
                    "action": rule["action"],
                    "decision_source": "DETERMINISTIC_RULE",
                    "rule_name": rule["name"],
                    "reason": rule["reason"],
                }

        # STEP 2: ML ensemble (5-100ms, probabilistic)
        ml_scores = {
            "isolation_forest_score": self.iso_forest.score(feature_vector),
            "gnn_score": self.gnn.score_account(event["account_id"], self.graph_loader),
            "behavior_score": self.seq_model.score(
                event["account_id"], event.get("session_actions", [])
            ),
        }
        composite = self.compute_risk_score(event, ml_scores)

        # STEP 3: Rule boosts (rules modify ML score but don't override)
        composite = self.apply_contextual_boosts(event, composite)

        return {
            "score": composite,
            "action": self.determine_action(composite, event),
            "decision_source": "ML_ENSEMBLE",
            "model_scores": ml_scores,
        }

    def apply_contextual_boosts(self, event, base_score):
        """Rules that add to ML score without overriding it."""
        boost = 0
        # New account + high-value action: +15 points
        if event.get("account_age_days", 999) < 30 and \
           event["event_type"] in ["withdrawal.initiated"]:
            boost += 15
        # New device for this account: +10 points
        if event.get("device_new_for_account"):
            boost += 10
        # Multiple failed logins before success: +20 points
        if event.get("failed_login_count_24h", 0) > 5:
            boost += 20
        return min(base_score + boost, 100)
```

### Graph Hardening — Indirect Edge Inference

```python
"""
MAKING THE GRAPH HARDER TO EVADE:

Even when attackers use different IPs and different phones,
we can infer connections from HARDER-TO-FAKE signals:

1. BROWSER FINGERPRINT COMPONENTS (not just the hash):
   - Canvas fingerprint: same GPU → identical canvas rendering
   - WebGL renderer string: "ANGLE (NVIDIA GeForce RTX 3060...)" → same VM
   - Font list hash: same OS image → same installed fonts
   - AudioContext fingerprint: hardware-specific
   
   If 500 accounts share the same canvas fingerprint despite different IPs:
   → Add SHARES_CANVAS_FP edges → GNN detects the ring

2. TIMING-BASED EDGE INFERENCE:
   If two accounts are created within 1 second of each other
   (same automation loop iteration):
   → Add CREATED_SIMULTANEOUS edge between these accounts
   
   Detects attackers who carefully separate all other infrastructure
   but can't hide the timing of their automation.

3. BEHAVIORAL SEQUENCE SIMILARITY:
   Account A sessions: [login, browse, search, buy, logout] (always same order)
   Account B sessions: [login, browse, search, buy, logout] (same distribution)
   
   If cosine similarity of session sequences > 0.90 AND no direct infra overlap:
   → Add SIMILAR_BEHAVIOR edge
   
   Catches sophisticated bots that use different infrastructure
   but produce similar action sequences.

4. WITHDRAWAL PATTERN GRAPH EDGES:
   If Account A and Account B both withdraw $347.50 on the same day to the same bank:
   → Strong co-occurrence signal even without any infrastructure overlap
   → Add CORRELATED_WITHDRAWAL edge
"""
```

---

## 9. Observability

### What to Monitor — ML-Ops vs SOC

```python
ML_OPS_METRICS = {
    # Model performance (computed daily against labeled holdout)
    "precision_at_threshold_0_70": {
        "formula": "confirmed_fraud_alerts / total_high_alerts",
        "target": "> 0.85",
        "alert_if": "< 0.80",
    },
    "recall_on_labeled_holdout": {
        "formula": "detected_fraud / total_known_fraud",
        "target": "> 0.70",
        "alert_if": "< 0.60",
    },

    # Feature drift (computed daily for all 35 features)
    "psi_per_feature": {
        "formula": "Σ(Actual% - Expected%) × ln(Actual%/Expected%)",
        "alert_if": "PSI > 0.25 for any feature",
        "action": "Evaluate model retraining",
    },
    "feature_null_rate": {
        "target": "< 1% null per required feature",
        "alert_if": "> 5% — indicates upstream pipeline failure",
    },

    # Inference health (real-time)
    "inference_latency_p99": {"target": "< 500ms", "alert_if": "> 1000ms for 5 min"},
    "kafka_consumer_lag": {"target": "< 10k messages", "alert_if": "> 50k messages"},
    "gnn_cache_hit_rate": {"target": "> 0.60", "alert_if": "< 0.30"},
    "gpu_utilization": {"target": "60-85%", "alert_if": "> 95% sustained"},
}

SOC_METRICS = {
    # Alert quality (daily review)
    "false_positive_rate": {
        "formula": "SOC_closed_not_fraud / total_HIGH_alerts",
        "target": "< 0.15",
        "alert_if": "> 0.25 for 3 consecutive days",
    },
    "alert_volume_by_severity": {
        "target": "CRITICAL < 20/day, HIGH < 100/day",
        "alert_if": "> 3x normal volume for any severity",
    },
    "mean_time_to_action_critical": {
        "target": "< 5 minutes",
        "alert_if": "> 15 minutes — SOC backlog or alert fatigue",
    },
    "fraud_loss_prevented_daily": {
        "target": "Track trend — significant sustained drop = model degradation",
    },
}
```

### Tracing an Alert to Raw Events

```
INVESTIGATION PATH: ALERT → GRAPH → FEATURES → RAW EVENTS

1. SOC receives alert ALERT_2024_1115_00342 in SOAR:
   "CRITICAL: Fraud Ring — CLUSTER_7821 — Risk Score 94"

2. SOAR case links to:
   - Graph visualization: https://graph.internal/explore?cluster=7821
     Shows: 500 accounts, their shared IPs, phones, SSNs (hashed)
   - Feature explanation (SHAP values):
     Feature                   | Value | SHAP Contribution
     ─────────────────────────────────────────────────────
     connected_component_size  | 500   | +0.28 (most important)
     ip_accounts_created_24h   |  47   | +0.19
     txn_max_daily_limit_rate  | 0.94  | +0.16
     account_age_days          |  15   | +0.09
     session_hour_entropy      | 0.41  | +0.07
     ...

3. Graph exploration: click on edge between acc_12345 and acc_99801
   Shows: Shared IP 45.33.12.87, both logged in from it, 14 times and 11 times

4. Raw events in Kibana:
   https://kibana.internal/discover?account_id=acc_12345
   Shows all 47 log lines: account creation, 3 logins, 2 purchases, withdrawal

5. Correlation query across all accounts in the cluster:
   SELECT account_id, event_type, ip_address, timestamp
   FROM events
   WHERE account_id IN (SELECT account_id FROM cluster_membership WHERE cluster=7821)
   ORDER BY timestamp;
   → Shows the full timeline: 500 accounts created over 3 days, all warming up,
     all withdrawing within 47 minutes

6. Evidence preservation:
   Case automatically logs: content hashes, IP list, SSN hash list, timeline
   Submitted to fraud consortium for cross-industry blocking
```

### Alerting Rules: Who Gets Alerted for What

```
ML-OPS TEAM ALERTS:
══════════════════════════════════════════════════════════
CRITICAL (page immediately):
  Model serving DOWN (no scores produced for > 2 min)
  Kafka consumer lag > 500k messages (hours behind)
  Feature pipeline stale (last feature computed > 5 min ago)

HIGH (respond within 1 hour):
  PSI > 0.25 on any feature (significant distribution shift)
  Precision drops below 0.80 (too many false positives)
  Recall drops below 0.60 (too much fraud slipping through)
  GNN inference p99 > 2 seconds
  Redis cache hit rate < 30%

MEDIUM (review next business day):
  Feature null rate > 5% (upstream data issue)
  Model score mean drift > 0.03 without corresponding FP/FN change
  Training pipeline ran > 30 min late

DO NOT ALERT ML-OPS:
  Individual fraud cases (SOC's domain)
  Normal alert volume day-of-week fluctuations
  Single outlier feature values for individual events


SOC TEAM ALERTS:
══════════════════════════════════════════════════════════
CRITICAL (immediate action required):
  Fraud ring detected (GNN score > 0.85, component size > 100)
  Active ATO: impossible travel + high-value action
  Fraud loss rate > 3x normal (something large-scale is happening)
  Withdrawal > $10,000 to new bank account (first-time large wire)

HIGH (action within 15 minutes):
  HIGH alert with withdrawal pending (money at risk right now)
  Account flagged by 3+ independent detection methods simultaneously
  Known-fraud-network IP used on any new account

MEDIUM (action within 4 hours):
  Account risk tier escalation
  Suspicious behavior pattern, no immediate financial risk

DO NOT ALERT SOC:
  ML-Ops infrastructure issues (route to ML-Ops)
  LOW severity flags (queue for next-day review)
  Duplicate alerts for same entity within 1 hour (dedup in SOAR)
  Successfully auto-remediated CRITICAL alerts (log only)
  False positive confirmed and closed (log for model feedback)
```

---

## 10. Interview Questions

### Q1: "Explain how a Graph Neural Network detects fraud rings differently from a traditional classifier. Walk through the mathematical intuition."

**Answer:**

A traditional classifier (XGBoost, Random Forest) takes one account's feature vector and outputs a score. Account 12345 has features `[age=3days, ip_velocity=10, device_known=False]` → score: 0.55. The classifier sees one account, in isolation.

A GNN propagates information across graph structure. For a 2-layer GraphSAGE model:

```
For target account v:
  Sample N1(v) = 25 1-hop neighbors (accounts sharing IP, device, SSN, etc.)
  Sample N2(v) = 10 2-hop neighbors per 1-hop neighbor

Layer 1 (2-hop → 1-hop embeddings):
  For each u in N1(v):
    agg_u = MEAN(features(w) for w in N2(u))
    h_u^1 = ReLU( W1 × concat(features(u), agg_u) )

Layer 2 (1-hop → target embedding):
  agg_v = MEAN(h_u^1 for u in N1(v))
  h_v^2 = ReLU( W2 × concat(features(v), agg_v) )

Score(v) = sigmoid(W_out × h_v^2)
```

The 128-dimensional embedding `h_v^2` encodes both v's own features AND what v's 2-hop neighborhood looks like. Two accounts might have identical individual features, but if one is surrounded by 400 fraud accounts in its neighborhood, the GNN embedding reflects this — score goes from 0.55 (isolated) to 0.89 (with neighborhood context).

**What-if:** "What if the fraud ring has no direct connections — all different IPs?" Then there are no edges between ring members in the graph, and the GNN gains no benefit. You need edges to form first. This is why indirect edge inference (Section 8) — timing-based edges, canvas fingerprint edges — is critical. Finding connections even when attackers use completely separate infrastructure is the ongoing arms race.

---

### Q2: "How does the system handle concept drift? What's the difference between gradual vs. sudden drift, and how do you detect each?"

**Answer:**

**Gradual drift** occurs when user behavior evolves over weeks. Example: Crypto payments become mainstream. Features like "large payment to unknown merchant" stop being strong fraud signals. Precision slowly degrades.

Detection: Population Stability Index (PSI) computed daily:
```
PSI = Σ (Actual% - Expected%) × ln(Actual%/Expected%)
PSI < 0.10: No drift
PSI 0.10-0.25: Monitor
PSI > 0.25: Retrain
```

PSI compares the current distribution of each feature to the training-time distribution. Gradual drift shows slowly increasing PSI values across weeks.

**Sudden drift** occurs overnight when a new attack technique emerges. Example: A new tool defeats device fingerprinting. `device_is_known=True` was a strong negative fraud signal — now it's neutral. Model recall drops 15% in one week.

Detection: Hold a labeled test set from 2 weeks ago. Evaluate the current model against it weekly. If recall drops >10% week-over-week, something changed.

**Response:**
- Gradual: Retrain on recent 90-day data, validate, blue-green deploy
- Sudden: Emergency retrain, manual feature engineering for new signals, temporary threshold tightening while model is retrained

**What-if:** "What if your training labels themselves are wrong?" Label quality is critical. Mitigation: Multiple labeling sources (chargebacks, manual reviews, consortium data). Disagreement-based filtering — if two sources disagree, discard that label. Audit a random sample of labels manually every quarter.

---

### Q3: "A low-and-slow attacker creates 10 accounts per day per IP, well below your velocity threshold of 50. How does the system still catch them?"

**Answer:**

The velocity feature is evaded. But three mechanisms remain:

**1. SSN co-occurrence across the graph:** Even at 10 accounts/IP, if the attacker uses 50 IPs over 30 days, they've created 1,500 accounts — all from the same SSN breach batch. The GNN observes a 1,500-node connected component (accounts connected through shared SSN batch prefix in the breach intelligence database). `is_in_large_component=True` for all of them, regardless of per-IP velocity.

**2. Temporal clustering at cash-out:** No matter how patient the setup, the attacker needs to cash out. If 1,500 accounts initiate maximum withdrawals within 24 hours, the Gini coefficient of withdrawal timing across the component is 0.9+ — legitimate users don't withdraw their maximum simultaneously, even over 24 hours.

**3. SSN breach intelligence cross-reference:** The system cross-references submitted SSNs against breach intelligence. If a SSN appeared in a known breach AND is being used for account creation, that's a high-signal independent indicator before the graph even builds.

**What the attacker must do to fully evade:** Multiple non-overlapping SSN databases + completely separate proxy providers + stagger cash-out over weeks in small amounts. The economic return becomes negative ROI at most fraud operation scales.

---

### Q4: "Walk me through Isolation Forest. Why does it work for individual anomaly detection but fail for coordinated fraud rings?"

**Answer:**

**Isolation Forest mechanics:**

Build 100 random binary trees by repeatedly selecting a random feature and a random split value between the feature's min and max. Repeat until every data point is isolated in its own leaf.

Anomaly score:
```
s(x) = 2^( -E[h(x)] / c(n) )

E[h(x)] = average isolation depth across all 100 trees
c(n) = 2*H(n-1) - 2*(n-1)/n   (expected depth in a BST of n nodes)

s(x) → 1.0: anomalous (isolated quickly — in sparse feature space region)
s(x) → 0.5: normal (average depth)
s(x) → 0.0: very normal (deep in dense cluster)
```

**Why it works for individuals:** An account that logged in from 3 continents in 1 day, used Tor, and attempted 10 withdrawals is in a very sparse region of the 35-dimensional feature space. Very few random splits needed to isolate it → anomaly score near 1.0.

**Why it fails for coordinated rings:** Each ring member is designed to look normal individually. Features `[age=15days, ip_velocity=10, device_known=True]` are unremarkable. The Isolation Forest scores it 0.55 — slightly anomalous, below alert threshold. The problem: Isolation Forest treats each account as a point in feature space. It has no concept of "500 accounts that look similar to each other" forming a relational pattern. The ring is a *graph anomaly* (500 accounts with identical infrastructure), not a *feature-space anomaly* (one account with unusual features). GNN is required to capture this.

---

### Q5: "How do you tune detection thresholds? What metrics matter and what's the cost model?"

**Answer:**

Threshold tuning requires quantifying the cost asymmetry:

```
False Negative (missed fraud): $500 average fraud loss per case
False Positive (blocking good user):
  Direct cost: $15 lost purchase + $5 CS cost
  Indirect: 0.3% churn probability × $300 LTV = $0.90 expected loss
  Total: ~$21 per false positive
```

FN costs 24x FP. This means we want to bias toward catching fraud even at the cost of some false positives. But there's a hard constraint: SOC capacity. At threshold 0.50, we generate 5,000 HIGH alerts/day. SOC can handle 200/day. Alert fatigue means analysts stop investigating → precision metric becomes meaningless.

**Metrics used for tuning:**

1. **Precision-Recall curve:** Plot at every threshold. PR-AUC measures overall model quality independent of threshold.

2. **F-beta score with β=2:** Penalizes false negatives twice as much as false positives. Optimal threshold maximizes F2.

3. **Business simulation:** For each threshold, simulate: `(precision × alerts × $500) - ((1-precision) × alerts × $21)`. Find threshold that maximizes net prevented loss.

4. **SOC capacity constraint:** Alert volume ≤ 100 HIGH alerts/day (our SOC can handle this). This constrains the minimum threshold regardless of the F2 optimal.

Result: threshold 0.70 for alerting, 0.85 for auto-block (much higher bar for automated action to avoid legitimate user friction).

---

### Q6: "Describe a specific sophisticated attack that would evade your system. What would you add to catch it?"

**Answer:**

**The attack that evades graph detection — B2B ATO (single high-value account):**

Instead of creating many accounts (creates graph edges), attacker targets ONE legitimate company account with a $50,000 wire transfer limit via:
1. Spear phishing the CFO's email account
2. Waiting and observing email for 2 weeks (no system activity)
3. Logging into the account during the CFO's vacation (using normal work hours)
4. Making a $3,000 purchase (within normal range) to warm the session
5. Two days later: changing the registered phone, adding a new bank account, initiating a $45,000 wire

**Why this evades detection:**
- Only one account → no connected component
- Legitimate account (3 years old, normal history) → Isolation Forest: 0.48
- IP is a corporate VPN (not a proxy) → IP features pass
- Time between actions is plausible (not automation-fast)
- Amount is below the account's historical maximum (they've wired $40,000 before)

**What additional signals would catch it:**

1. **Change velocity rule:** phone.change + bank_account.add within 24 hours, followed by a wire > $10,000 → CRITICAL regardless of ML score. Legitimate users almost never change authentication factors and initiate a large wire in the same day.

2. **Out-of-band verification:** Any first-time wire > $10,000 to a NEW bank account → automated phone call to the registered number before execution. Completely defeats this attack regardless of ML scores.

3. **Email account compromise signal:** Integration with email security tooling. If the CFO's email account was recently compromised (detected by the email security vendor), that's an input signal to the fraud system.

4. **Behavioral biometrics:** Typing cadence and mouse movement during the session. The attacker is not the CFO — their biometrics don't match the registered profile. This is the hardest signal to fake and the most robust against this attack type.

---

*Document version: 1.0 | Classification: Internal Engineering*
*Author: Detection Engineering Team*
*Covers production-grade graph-based fraud detection system design.*