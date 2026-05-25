# Autonomous Cyber Defense (Reinforcement Learning): Internal Engineering & Security Breakdown

> **Classification:** Internal Engineering / Security Document  
> **Audience:** Detection Engineers, RL Researchers, SOC Architects, ML Engineers, Interview Candidates  
> **Scope:** Full-stack autonomous cyber defense — RL agent design, telemetry ingestion, state representation, action spaces, reward engineering, policy deployment, evasion mechanics, and observability  
> **Version:** 1.0

---

## Table of Contents

1. [Threat Detection Narrative](#1-threat-detection-narrative)
2. [Telemetry & Ingestion Flow](#2-telemetry--ingestion-flow)
3. [Feature Engineering Pipeline](#3-feature-engineering-pipeline)
4. [Inference Engine Architecture](#4-inference-engine-architecture)
5. [Correlation & Alerting Flow](#5-correlation--alerting-flow)
6. [Attack Scenarios (Evasion Tactics)](#6-attack-scenarios-evasion-tactics)
7. [Failure Points & Scaling](#7-failure-points--scaling)
8. [Mitigations & Defense-in-Depth](#8-mitigations--defense-in-depth)
9. [Observability](#9-observability)
10. [Interview Questions](#10-interview-questions)

---

## Foundational Framing: What Autonomous Cyber Defense Actually Is

Autonomous Cyber Defense (ACD) applies Reinforcement Learning (RL) to have a software agent make sequential defensive decisions — blocking IPs, isolating hosts, rerouting traffic, deploying honeypots — with the goal of minimizing attacker impact while maximizing operational continuity.

This is distinct from both:
- **ML-based detection** (UEBA, anomaly detection): these classify/score but do not *act*
- **Scripted SOAR playbooks**: these execute predefined rules but do not *learn* from outcomes

An RL-based ACD agent learns a **policy** — a mapping from observed network state to defensive action — through repeated interaction with an environment (real network or simulation). It optimizes for cumulative reward over time, not just immediate threat mitigation.

**The Markov Decision Process (MDP) formulation:**

```
State S:    Current representation of network security state
            (active connections, host anomaly scores, alert history, topology)

Action A:   Defensive moves available to the agent
            (block IP, isolate host, rate-limit service, deploy decoy, escalate to human)

Transition: T(s, a, s') = P(next_state = s' | state = s, action = a)
            How the network state changes when the agent takes action a

Reward R:   R(s, a, s') = scalar feedback signal
            Positive: attacker dwell time decreasing, lateral movement blocked
            Negative: false positive containment of legitimate host, SLA violation

Policy π:   π(a | s) = probability of taking action a in state s
            Learned to maximize: E[Σ γᵗ R(sₜ, aₜ, sₜ₊₁)] (discounted cumulative reward)
            γ = 0.99 (discount factor: future rewards matter almost as much as immediate)
```

The key properties that make RL appropriate here:
1. **Sequential decisions:** One defensive action changes the state, requiring subsequent decisions
2. **Delayed consequences:** Blocking a host early may have long-term security benefits invisible immediately
3. **Exploration tradeoff:** Sometimes the agent should try novel defenses to learn what works
4. **Adversarial dynamics:** The attacker adapts, so the defender must adapt — RL learns over time

---

## 1. Threat Detection Narrative

### 1.1 The Attacker's Perspective

**Setting:** A sophisticated threat actor (APT) targeting a financial services firm. The attacker has already achieved initial access via a phished credential. They are now conducting lateral movement toward the payment processing servers.

**What the attacker thinks they're doing:**

```
Day 1, 14:23: Logged in via VPN using stolen credential for jdoe (John Doe, IT helpdesk)
              Goal: blend in during business hours, move slowly
              Believes: VPN login looks normal; John is an IT guy who accesses many systems

Day 1, 14:30 - 17:00: Internal reconnaissance via PowerShell WMI queries
              Believes: WMI is a legitimate admin tool; this is what IT does

Day 1, 17:15: Found DB-PAYMENT-01 in network map; high value target
              Plan: RDP from jdoe's workstation to DB-PAYMENT-01

Day 2, 09:04: RDP attempt to DB-PAYMENT-01 — access denied (no privileges)
              Plan B: Find a privileged account on the helpdesk system (HLPDSK-01)

Day 2, 09:10: Credential dumping from HLPDSK-01 LSASS
              Found: svc_dba (database service account with DBA privileges)

Day 2, 09:18: Connected to DB-PAYMENT-01 using svc_dba credentials
              Believes: Service account activity is normal; DBAs connect all the time
```

**The RL agent's view of the same events:**

At each timestep, the RL agent receives the current state vector and must decide on a defensive action.

**T=14:23 — State update on VPN login**

```
State vector update:
  node_jdoe:
    auth_anomaly_score: 0.71  (new VPN IP, residential proxy, slight time anomaly)
    active_sessions: 1
    alert_history_24h: 0
    
Agent evaluates state: risk_score = 0.71 (below action threshold of 0.80)
Policy output: π("monitor" | s) = 0.72 (monitor and continue observing)
               π("block" | s) = 0.04
               π("mfa_challenge" | s) = 0.24

Action taken: MONITOR (with elevated logging rate — 10x normal event sampling for jdoe)
```

**T=14:30 - 17:00 — WMI reconnaissance accumulates**

```
47 WMI queries in 147 minutes.
jdoe's baseline: 0-2 WMI queries per session (IT helpdesk, primarily GUI-based)

State vector update:
  node_jdoe:
    auth_anomaly_score: 0.71
    wmi_query_rate_z_score: +4.2 (4.2 standard deviations above baseline)
    distinct_targets_1h: 23 (23 unique hosts queried via WMI)
    graph_new_edges_1h: 19 (new entity-relationship edges)
    recon_pattern_score: 0.89 (LSTM sequence score: matches known recon sequence)
    
Policy output: π("isolate" | s) = 0.41
               π("mfa_challenge" | s) = 0.38
               π("monitor" | s) = 0.21

Confidence threshold not met for autonomous action (< 0.80 for host isolation)
Action taken: ESCALATE_TO_SOC + deploy honeypot (HLPDSK-FAKE-01 appears in WMI scan results)
```

**T=17:15 — RDP attempt to payment server**

```
This action crosses a deterministic policy rule:
  ANY host in the PAYMENT_ZONE attempting RDP from HELPDESK_ZONE
  → Minimum action: block + alert (not ML-dependent)

State vector update:
  edge_jdoe_to_PAYMENT-01:
    first_time_edge: TRUE
    dest_zone: PAYMENT (critical)
    protocol: RDP (allowed only for sysadmin role — jdoe is helpdesk)
    lateral_movement_score: 0.94

Policy output: π("block_edge" | s) = 0.91
              π("isolate_source" | s) = 0.09

Action taken: BLOCK RDP from jdoe's workstation to PAYMENT zone
              LOG: "Blocked lateral movement attempt: jdoe → DB-PAYMENT-01"
              ALERT: SOC P1 ticket created
```

**T=09:10 Day 2 — LSASS dump attempt**

```
EDR telemetry: comsvcs.dll MiniDump of lsass.exe on HLPDSK-01
Source process: powershell.exe (parent: winrm.exe — indicating remote execution)

Deterministic rule fires:
  LSASS_DUMP_DETECTED → CRITICAL (no ML score required)
  
RL agent receives critical event:
State: HLPDSK-01 is now COMPROMISED_SUSPECTED
  policy_action_confidence: 0.97 for ISOLATE_HOST

Action taken (AUTONOMOUS — threshold met):
  1. ISOLATE HLPDSK-01 from network (VLAN reassignment → quarantine VLAN)
  2. Revoke all active sessions for jdoe
  3. Reset svc_dba password (via AD API call)
  4. Page SOC analyst: "Autonomous isolation of HLPDSK-01 — LSASS dump detected"
  5. Preserve forensic disk image (trigger EDR forensic collection)
  
Total time from LSASS dump to isolation: 4.2 seconds
Human response time (historical): 6-45 minutes
```

**T=09:18 — svc_dba connection attempt (defeated)**

```
svc_dba password was reset at T=09:14.
Connection attempt at T=09:18 fails with authentication error.
Attacker sees: access denied.

RL agent action:
  svc_dba invalid login from HLPDSK-01 (isolated) and new host (WKSTN-IT-03):
  → Both HLPDSK-01 and WKSTN-IT-03 flagged as potentially attacker-controlled
  → Ripple isolation: WKSTN-IT-03 moved to quarantine VLAN
  → All svc_dba connections globally suspended pending investigation
```

**What the SOC analyst sees when they wake up:**

```
[AUTONOMOUS ACTION REPORT] — Generated at 09:14:22
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CAMPAIGN SUMMARY: Active Lateral Movement — Detected and Contained
Attack Vector: Compromised credential (jdoe) → Helpdesk server → Payment zone attempt

Timeline (all autonomous):
  14:23 Day 1: Anomalous VPN login for jdoe — monitoring elevated
  14:30-17:00: 47 WMI reconnaissance queries — honeypot deployed
  17:15: RDP blocked: jdoe → DB-PAYMENT-01 (payment zone, first-time access)
  09:10 Day 2: LSASS dump on HLPDSK-01 — HOST ISOLATED (autonomous, 4.2s)
  09:14: svc_dba password reset (autonomous)
  09:18: svc_dba auth attempt blocked (password already rotated)

Actions taken autonomously:
  ✓ HLPDSK-01 isolated (quarantine VLAN)
  ✓ WKSTN-IT-03 isolated (associated with failed svc_dba attempt)
  ✓ jdoe sessions revoked globally
  ✓ svc_dba suspended pending review
  ✓ Forensic image collection initiated on HLPDSK-01

Collateral impact:
  ✗ 3 legitimate users on WKSTN-IT-03 lost connectivity (collateral FP)
  → Recommend: restore WKSTN-IT-03 after verifying no compromise (estimated 45 min)
  
Analyst actions required:
  1. Verify jdoe credential compromise (call John Doe)
  2. Review forensic image from HLPDSK-01
  3. Determine if attacker exfiltrated anything before 09:10
  4. Restore WKSTN-IT-03 after investigation
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

**The gap between attacker assumptions and reality:**

| Attacker Assumed | RL Agent's Reality |
|-----------------|-------------------|
| VPN login blends in | Elevated monitoring activated immediately |
| WMI is normal admin behavior | 47 queries in 147 min = 4.2σ anomaly; recon pattern matched |
| RDP to payment = just trying something | Deterministic zone rule + RL lateral movement score = blocked |
| LSASS dump via legitimate tool = undetected | EDR telemetry → CRITICAL → isolated in 4.2 seconds |
| Stolen svc_dba credential = persistent access | Password rotated before attacker could use it |

---

## 2. Telemetry & Ingestion Flow

### 2.1 Telemetry Sources for ACD

The RL agent's state depends entirely on telemetry quality. Missing or delayed telemetry = blind spots in the state space = poor policy decisions.

```
TIER 1 — CRITICAL (pipeline failure = agent loses essential state):
  Authentication events (AD, Okta, VPN, PAM)
  EDR process/network events (CrowdStrike, SentinelOne, Defender)
  Firewall/NGFW allow/deny logs
  Network flow records (NetFlow/IPFIX from core switches)

TIER 2 — HIGH (impacts detection quality significantly):
  DNS query logs (Pi-hole, BIND, Infoblox)
  Web proxy logs (Zscaler, Bluecoat, Squid)
  Database audit logs (PostgreSQL, Oracle)
  Cloud API logs (CloudTrail, GCP Audit, Azure Activity)

TIER 3 — SUPPLEMENTAL (enrichment; pipeline failure degrades but doesn't break detection):
  Email gateway logs (spam filters, attachment analysis)
  DHCP leases (IP-to-host mapping — critical for inventory)
  Certificate transparency logs
  Threat intelligence feeds (MISP, commercial TI)
  
TIER 4 — ACD-SPECIFIC (enables RL but not needed for detection):
  Network topology snapshots (node/edge inventory for graph state)
  Asset inventory (CMDB: host criticality, function, owner)
  Active response API endpoints (AD API, firewall API, EDR API)
  SLA metrics (what constitutes "collateral damage" from defensive actions)
```

### 2.2 High-Throughput Ingestion Architecture

```
┌──────────────────────────────────────────────────────────────────────────────────────┐
│  TELEMETRY PRODUCERS                                                                  │
│                                                                                      │
│  [EDR Agents]  [AD/DC]  [Firewalls]  [NetFlow]  [DNS]  [VPN]  [Cloud APIs]          │
│      │            │          │           │         │       │         │               │
└──────┼────────────┼──────────┼───────────┼─────────┼───────┼─────────┼───────────────┘
       │            │          │           │         │       │         │
       │ gRPC/TLS   │WEC/WinRM │ Syslog    │ IPFIX   │ DNS  │ HTTPS   │ REST/HTTPS
       ▼            ▼          ▼           ▼         ▼       ▼         ▼
┌──────────────────────────────────────────────────────────────────────────────────────┐
│  COLLECTION LAYER                                                                    │
│                                                                                      │
│  ┌────────────────────────────────────────────────────────────────────────────────┐  │
│  │  Vector / Fluent Bit (per network segment, per datacenter)                    │  │
│  │  • Priority queuing: Tier 1 events never dropped; Tier 3 sampled under load  │  │
│  │  • Buffer: 2GB memory + 20GB disk spill (handles 15-min Kafka outage)        │  │
│  │  • Format conversion: syslog → JSON, WEF XML → JSON, IPFIX binary → JSON    │  │
│  │  • Deduplication: hash-based within 30s window (prevents duplicate counts)   │  │
│  │  • Compression: LZ4 (fast) on the wire → 4-6x size reduction                │  │
│  └────────────────────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────┬─────────────────────────────────────────┘
                                             │ mTLS + LZ4 compressed batches
                                             ▼
┌──────────────────────────────────────────────────────────────────────────────────────┐
│  KAFKA CLUSTER (3+ brokers, racks: A, B, C)                                         │
│                                                                                      │
│  Topics and their purpose:                                                           │
│  ┌──────────────────────────────────────────────────────────────────────────────┐   │
│  │  acd.raw.auth       (32 partitions, 7d retention, keyed by actor_id)        │   │
│  │  acd.raw.endpoint   (64 partitions, 7d retention, keyed by host_id)        │   │
│  │  acd.raw.network    (128 partitions, 3d retention, keyed by src_ip+dst_ip)  │   │
│  │  acd.raw.cloud      (16 partitions, 14d retention, keyed by account_id)    │   │
│  │                                                                              │   │
│  │  acd.normalized     (128 partitions, 30d retention, keyed by entity_id)    │   │
│  │  acd.state          (64 partitions, keyed by entity_id — compacted topic)  │   │
│  │  acd.rewards        (16 partitions, 90d retention — RL training signal)    │   │
│  │  acd.actions        (16 partitions, 90d retention — agent decisions)       │   │
│  │  acd.observations   (64 partitions, 7d retention — agent state snapshots)  │   │
│  └──────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                      │
│  Config: replication.factor=3, min.insync.replicas=2, acks=all                      │
│          linger.ms=5, batch.size=131072, compression.type=lz4                        │
│          Throughput per broker: 800MB/s sustained, 1.5GB/s burst                    │
└────────────────────────────────────────────┬─────────────────────────────────────────┘
                                             │
            ┌────────────────────────────────┼──────────────────────────┐
            │                               │                           │
            ▼                               ▼                           ▼
┌───────────────────────┐    ┌──────────────────────────┐  ┌────────────────────────┐
│  STREAM PROCESSOR      │    │  STATE STORE             │  │  RAW LOG ARCHIVE       │
│  Apache Flink          │    │  Apache Flink + RocksDB  │  │                        │
│                        │    │                          │  │  Elasticsearch (hot:   │
│  • Normalization        │    │  Per-entity state:       │  │   30d searchable)      │
│  • Feature computation │    │    Sliding window counts  │  │  S3 Parquet (cold:     │
│  • Graph edge updates  │    │    Baseline statistics   │  │   7yr retention)       │
│  • State vector build  │    │    Alert history         │  │  Athena (ad-hoc query) │
│  • Reward computation  │    │    Graph adjacency       │  │  Immutable audit chain │
└───────────────────────┘    └──────────────────────────┘  └────────────────────────┘
            │
            ▼
┌──────────────────────────────────────────────────────────────────────────────────────┐
│  RL INFERENCE ENGINE                                                                 │
│                                                                                      │
│  State vector (per entity) → Policy Network → Action probabilities → Decision       │
│                                                                                      │
│  Decision router:                                                                    │
│    If max(action_prob) > 0.90 AND action_risk = LOW → AUTONOMOUS                   │
│    If max(action_prob) > 0.80 AND action_risk = MEDIUM → AUTONOMOUS + ALERT        │
│    If action_risk = HIGH (host isolation, network block) → HUMAN_IN_LOOP            │
│    If max(action_prob) < 0.70 → ESCALATE TO SOC (model uncertain)                  │
└──────────────────────────────────────────────────────────────────────────────────────┘
            │
            ▼
┌──────────────────────────────────────────────────────────────────────────────────────┐
│  ACTION EXECUTION LAYER                                                              │
│                                                                                      │
│  NETWORK:    Firewall API (Palo Alto, Fortinet) → block/allow rules                 │
│  IDENTITY:   AD API / Okta API → disable account, reset password, revoke sessions  │
│  HOST:       EDR API (CrowdStrike, SentinelOne) → isolate host, kill process       │
│  DECEPTION:  Honeypot orchestrator → deploy/remove decoys                           │
│  HUMAN:      SOAR platform → create ticket, page analyst                            │
└──────────────────────────────────────────────────────────────────────────────────────┘
```

### 2.3 Log Parsing and Normalization for ACD State

The RL agent needs a consistent state representation regardless of the telemetry source. Normalization produces a **unified entity event** format:

```json
{
  "ue_id": "evt-9f3a2b1c",
  "timestamp": "2024-01-15T14:30:22.431Z",
  "entity_id": "jdoe",
  "entity_type": "user_account",
  "host_id": "HLPDSK-01",
  "event_category": "process_execution",
  "event_action": "wmi_query",
  "target_entity_id": "WKSTN-FIN-042",
  "risk_indicators": {
    "is_first_time_edge": true,
    "dest_is_sensitive": false,
    "lateral_movement_indicator": 0.62
  },
  "state_delta": {
    "entity_jdoe": {
      "wmi_count_1h": "+1 → 23",
      "new_graph_edges": 1
    }
  },
  "source": {
    "type": "windows_event_log",
    "event_id": 4688,
    "collector": "wef-dc02"
  }
}
```

**Why the `state_delta` field is critical:**

The RL agent's state is built incrementally. Rather than recomputing the full state vector from scratch on every event (expensive), the normalization layer computes the *delta* — what changed. The Flink stateful processor applies deltas to the running state in RocksDB. This reduces state computation latency from ~50ms (full recompute) to ~2ms (delta apply).

### 2.4 Where Latency and Dropped Events Occur

```
Stage                     Normal Latency    Degraded Latency    Drop Risk
──────────────────────────────────────────────────────────────────────────────
EDR agent → syslog        10-50ms           500ms (disk I/O)     Very Low
Collection agent buffer   < 1ms             5ms                  Low (disk backup)
Kafka write               5-15ms            100ms (leader elect)  Medium (rebalance)
Kafka → Flink consumer    0ms (streaming)   60s (rebalance)      None (at-least-once)
Normalization             2-8ms             50ms (lookup fail)    None (retry)
GeoIP enrichment          < 1ms             < 1ms                None (in-memory)
Threat intel lookup       1-5ms             500ms (API timeout)   Low (cache hit)
State update (RocksDB)    1-3ms             20ms (compaction)     None
Feature computation       5-15ms            50ms (complex graph)  None
RL inference              10-30ms           100ms (GPU load)      None
Action execution          50-500ms          5s (API timeout)      Medium (retry)
Total critical path       ~100ms            ~800ms                Target: < 200ms
```

**Critical latency failure mode — network flow records:**

NetFlow records are emitted every 60 seconds (or at flow termination) by default. This means a scanning attack that completes in 30 seconds may not be visible in NetFlow until 60-90 seconds after it finished. For ACD, this is unacceptable. Configuration required:

```
Cisco IOS NetFlow active timeout: 30s (default 60s → reduce to 30s)
inactive timeout: 10s (default 15s → reduce to 10s)
template refresh rate: 20 packets (send template frequently for parse reliability)

Impact: 2x more NetFlow export volume, but lateral movement visible within 30s
        instead of potentially 90s
```

---

## 3. Feature Engineering Pipeline

### 3.1 The State Vector Architecture

The RL agent's policy network takes a **state vector** as input. This vector must capture the security-relevant properties of the entire monitored environment in a fixed-dimensional format the neural network can process.

**Multi-level state hierarchy:**

```
Global State (network-wide):
  active_incident_count              ← how many ongoing incidents
  mean_network_anomaly_score         ← average anomaly across all entities
  bandwidth_utilization_pct          ← network health indicator
  threat_intel_alert_rate_1h         ← external threat context
  
Host-level State (per node, top-N most anomalous):
  [node_id_embedding,                ← 16-dim embedding (host identity)
   anomaly_score,                    ← 0 to 1 (current anomaly)
   criticality_score,                ← 0 to 1 (from CMDB: payment server = 1.0)
   active_connections,               ← count
   process_anomaly_score,            ← 0 to 1 (from EDR)
   auth_events_1h,                   ← count
   lateral_movement_score,           ← 0 to 1 (from GNN)
   is_isolated,                      ← 0/1 (currently quarantined)
   is_honeypot,                      ← 0/1 (is this a decoy?)
   alert_count_24h]                  ← count

Edge-level State (recent anomalous connections):
  [src_entity_embedding,             ← 16-dim
   dst_entity_embedding,             ← 16-dim
   first_time_edge,                  ← 0/1
   edge_frequency_z_score,           ← how unusual is this connection volume
   protocol,                         ← one-hot encoded
   bytes_transferred,                ← log-scaled
   dst_zone_criticality]             ← 0 to 1

Agent History State (recent actions and their outcomes):
  [last_5_actions_encoded,           ← 5 × 8-dim action embeddings
   last_5_rewards,                   ← 5 floats
   time_since_last_action_s,         ← scalar
   consecutive_fp_count]             ← count of recent false positive isolations
```

**Total state vector dimension:** ~512 floats, carefully designed to be:
- Fixed-size (RL neural networks require fixed input dimensions)
- Informative (encodes the most security-relevant aspects of the environment)
- Stable (doesn't change meaning when a new host joins the network)

### 3.2 Stateless Feature Extraction

```python
class StatelessFeatureExtractor:
    """
    Features computable from a single event with no historical context.
    These run as Flink stateless map() operations.
    Extremely fast: < 1ms per event.
    """
    
    def extract(self, event: NormalizedEvent) -> StatelessFeatures:
        return StatelessFeatures(
            # Temporal features (cyclic encoding avoids discontinuity)
            hour_sin = math.sin(2 * math.pi * event.timestamp.hour / 24),
            hour_cos = math.cos(2 * math.pi * event.timestamp.hour / 24),
            is_weekend = event.timestamp.weekday() >= 5,
            is_business_hours = 8 <= event.timestamp.hour <= 18,
            
            # Geographic/network features
            is_tor = event.geo.is_tor,
            is_datacenter_ip = event.geo.is_datacenter,
            is_vpn_ip = event.geo.is_vpn,
            asn_risk_score = self.asn_risk_table.get(event.geo.asn, 0.5),
            
            # Protocol features
            protocol_risk = self.PROTOCOL_RISK_MAP.get(event.network.protocol, 0.3),
            # RDP=0.7, SMB=0.6, SSH=0.4, HTTPS=0.1, HTTP=0.2
            
            # Authentication features
            auth_method_score = self.AUTH_RISK.get(event.auth.method, 0.5),
            # Password-only = 0.6, NTLM = 0.7, Kerberos = 0.2, MFA = 0.1
            mfa_absent = int(not event.auth.mfa_used),
            logon_type_risk = self.LOGON_RISK.get(event.auth.logon_type, 0.3),
            
            # Zone features (from CMDB)
            src_zone_criticality = self.cmdb.get_criticality(event.src_host),
            dst_zone_criticality = self.cmdb.get_criticality(event.dst_host),
            zone_boundary_crossed = (self.cmdb.get_zone(event.src_host) != 
                                     self.cmdb.get_zone(event.dst_host)),
        )
```

### 3.3 Stateful Feature Extraction

```python
class StatefulFeatureExtractor:
    """
    Maintains per-entity state in Flink RocksDB.
    Keyed by entity_id — all events for a given entity go to the same Flink task.
    
    State is checkpointed to S3 every 60 seconds for fault tolerance.
    """
    
    def process(self, event: NormalizedEvent, state: EntityState) -> StatefulFeatures:
        # === VELOCITY FEATURES (sliding window counts) ===
        auth_count_1h = state.increment_and_get('auth_count', bucket_seconds=3600)
        auth_count_24h = state.sum_buckets('auth_count', hours=24)
        
        failed_auth_1h = state.increment_and_get('failed_auth', bucket_seconds=3600,
                                                   condition=event.auth.failed)
        
        # === DEVIATION FROM BASELINE (z-scores) ===
        baseline = state.get_baseline()  # 90-day rolling statistics
        
        wmi_z_score = (event.wmi_queries - baseline.wmi_queries_mean) / (
                       baseline.wmi_queries_std + 1e-9)
        
        bytes_z_score = (event.bytes_transferred - baseline.bytes_mean) / (
                         baseline.bytes_std + 1e-9)
        
        # === GRAPH NOVELTY FEATURES ===
        edge_key = f"{event.src_entity}:{event.dst_entity}"
        is_new_edge = edge_key not in state.seen_edges
        
        if is_new_edge:
            state.seen_edges.add(edge_key)
            # Compare to peer group
            peer_edge_prevalence = self.peer_graph.prevalence(
                event.src_entity_role, event.dst_entity_id
            )
            edge_anomaly = 1.0 - peer_edge_prevalence
        else:
            edge_anomaly = 0.0
        
        new_hosts_1h = state.count_new_targets(window_hours=1)
        new_hosts_24h = state.count_new_targets(window_hours=24)
        
        # === SEQUENCE FEATURES (using mini-LSTM for pattern detection) ===
        # Append event type to user's recent event sequence
        event_type_id = self.EVENT_TYPE_VOCAB[event.event_action]
        state.event_sequence.append(event_type_id)
        if len(state.event_sequence) > 50:
            state.event_sequence.pop(0)
        
        # Run sequence through recon pattern detector
        if len(state.event_sequence) >= 10:
            recon_score = self.sequence_classifier.score(state.event_sequence[-20:])
        else:
            recon_score = 0.0
        
        # === IMPOSSIBLE TRAVEL ===
        last_auth = state.last_auth_event
        if last_auth and event.event_category == 'authentication':
            distance_km = haversine(last_auth.location, event.location)
            time_hours = (event.timestamp - last_auth.timestamp).seconds / 3600
            impossible = distance_km > (900 * time_hours)  # 900 km/h = max aircraft
        else:
            impossible = False
        
        # Update state
        state.last_auth_event = event if event.event_category == 'authentication' else last_auth
        
        return StatefulFeatures(
            auth_count_1h=auth_count_1h,
            auth_count_24h=auth_count_24h,
            failed_auth_1h=failed_auth_1h,
            wmi_query_z_score=wmi_z_score,
            bytes_z_score=bytes_z_score,
            is_new_edge=int(is_new_edge),
            edge_anomaly_score=edge_anomaly,
            new_hosts_1h=new_hosts_1h,
            new_hosts_24h=new_hosts_24h,
            recon_sequence_score=recon_score,
            impossible_travel=int(impossible)
        )
```

### 3.4 Graph Neural Network Features (Lateral Movement Scoring)

The entity graph is a first-class component of the ACD state. Graph features capture structural anomalies that point-in-time features miss:

```python
class EntityGraphFeatureExtractor:
    """
    Computes graph-based features for lateral movement detection.
    Graph backend: Neo4j (persistent, 30-day history)
                   Redis (hot graph, 24-hour edges, fast for real-time queries)
    
    GNN model: Graph Attention Network (GAT) trained on labeled lateral movement
               campaigns from CyberBench, MITRE ATT&CK simulations, and
               red team exercise data.
    """
    
    def compute_graph_features(self, entity_id: str, event: NormalizedEvent) -> dict:
        # === LOCAL GRAPH STRUCTURE ===
        # Fan-out: how many distinct targets is this entity connecting to?
        distinct_targets_1h = self.redis_graph.count_distinct_targets(entity_id, hours=1)
        distinct_targets_24h = self.redis_graph.count_distinct_targets(entity_id, hours=24)
        
        # PageRank-style importance of accessed nodes
        # Accessing high-centrality nodes = higher risk
        target_centrality_mean = self.neo4j.mean_centrality(entity_id, hours=24)
        
        # === PATH ANALYSIS ===
        # How many hops from this entity to the nearest high-value target?
        distance_to_payment_zone = self.neo4j.shortest_path_length(
            entity_id, "PAYMENT_ZONE"
        )
        # Shorter distance = closer to crown jewels = higher risk
        proximity_score = max(0, 1.0 - distance_to_payment_zone / 10)
        
        # === GRAPH ANOMALY DETECTION (GNN) ===
        # Get subgraph: entity + 2-hop neighborhood
        subgraph = self.neo4j.get_subgraph(entity_id, hops=2)
        
        # Run GNN inference on this subgraph
        node_features = self._build_node_features(subgraph)  # Entity attributes
        edge_features = self._build_edge_features(subgraph)  # Connection attributes
        
        gnn_anomaly_score = self.gnn_model.forward(
            node_features, 
            edge_features,
            focus_node=entity_id
        )
        # GNN captures: "Is this subgraph pattern consistent with historical legitimate
        # access patterns, or does it look like a lateral movement campaign?"
        
        # === COMMUNITY DETECTION ===
        # Is this entity now connecting across community boundaries?
        # (Communities = natural clusters in the org's access graph)
        community_boundary_crossings = self.neo4j.count_community_crossings(
            entity_id, hours=24
        )
        
        return {
            'distinct_targets_1h': distinct_targets_1h,
            'distinct_targets_24h': distinct_targets_24h,
            'target_centrality_mean': target_centrality_mean,
            'payment_zone_proximity': proximity_score,
            'gnn_anomaly_score': gnn_anomaly_score,
            'community_crossings_24h': community_boundary_crossings
        }
```

### 3.5 Sequence Embedding for Attack Pattern Recognition

A key insight in ACD: attackers follow procedural patterns (MITRE ATT&CK tactics/techniques). The sequence of events a compromised account generates often follows a recognizable pattern: `recon → privilege_escalation → lateral_movement → data_access → exfiltration`.

```python
class AttackSequenceEmbedder:
    """
    Transforms event sequences into dense vectors capturing attack patterns.
    
    Architecture: Transformer encoder (BERT-style, but trained on security events)
    Pretraining: Masked event prediction on 500M unlabeled security events
    Finetuning: Binary classification (attack/benign) on labeled incidents
    """
    
    EVENT_VOCABULARY = {
        # Authentication
        "vpn_login": 1, "vpn_login_fail": 2,
        "ad_login": 3, "ad_login_fail": 4,
        "mfa_success": 5, "mfa_fail": 6,
        # Reconnaissance
        "wmi_query": 10, "net_share_enum": 11, "port_scan": 12,
        "ldap_query": 13, "dns_zone_transfer": 14,
        # Lateral movement
        "rdp_connect": 20, "smb_connect": 21, "psexec": 22,
        "wmi_exec": 23, "ssh_connect": 24, "winrm_exec": 25,
        # Privilege escalation
        "lsass_access": 30, "token_impersonation": 31,
        "scheduled_task_create": 32, "service_create": 33,
        # Data access
        "db_query_large": 40, "file_read_bulk": 41, "share_read": 42,
        # Exfiltration
        "large_upload_external": 50, "dns_tunneling": 51, "https_exfil": 52,
        # Normal
        "email_send": 100, "web_browse": 101, "app_login": 102,
        # Padding
        "PAD": 0
    }
    
    def embed_sequence(self, event_sequence: list[str], max_len: int = 64) -> np.ndarray:
        """
        Convert a sequence of event types to a 256-dimensional embedding.
        This embedding captures the behavioral pattern regardless of timing.
        """
        # Tokenize
        token_ids = [self.EVENT_VOCABULARY.get(e, 0) for e in event_sequence[-max_len:]]
        
        # Pad to max_len
        padded = [0] * (max_len - len(token_ids)) + token_ids
        
        # Run through transformer encoder
        input_tensor = torch.tensor(padded).unsqueeze(0)  # (1, max_len)
        with torch.no_grad():
            embedding = self.transformer_encoder(input_tensor)
        
        # Use [CLS] token embedding as sequence representation
        return embedding[0, 0, :].numpy()  # 256-dimensional
    
    def classify_sequence(self, sequence_embedding: np.ndarray) -> float:
        """
        Binary classifier on top of sequence embedding.
        Output: P(attack | sequence) in [0, 1]
        """
        return self.attack_classifier(sequence_embedding)
```

---

## 4. Inference Engine Architecture

### 4.1 The RL Policy Network Architecture

**Algorithm: Proximal Policy Optimization (PPO) — the workhorse of production RL**

PPO is chosen over other RL algorithms because:
- **Stable training:** Clipped surrogate objective prevents catastrophically large policy updates
- **Sample efficient enough:** Can be trained on both simulated environments and real incident data
- **Continuous and discrete actions:** Handles mixed action spaces (continuous rate limits + discrete block/allow)
- **Well-understood failure modes:** Extensive literature on PPO in security applications

```python
import torch
import torch.nn as nn
import torch.nn.functional as F

class ACDPolicyNetwork(nn.Module):
    """
    PPO Actor-Critic network for autonomous cyber defense.
    
    Input: State vector (512 floats)
    Actor output: Action probability distribution over 32 possible actions
    Critic output: State value estimate V(s) for PPO update
    """
    
    def __init__(self, state_dim=512, action_dim=32, hidden_dim=256):
        super().__init__()
        
        # Shared backbone (processes state into useful representations)
        self.backbone = nn.Sequential(
            nn.Linear(state_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),  # LayerNorm (not BatchNorm) for RL stability
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.LayerNorm(hidden_dim // 2),
            nn.ReLU()
        )
        
        # Actor head: outputs logits for each action
        self.actor = nn.Sequential(
            nn.Linear(hidden_dim // 2, hidden_dim // 4),
            nn.ReLU(),
            nn.Linear(hidden_dim // 4, action_dim)
            # Note: no softmax here — we compute log_softmax separately for numerical stability
        )
        
        # Critic head: estimates state value
        self.critic = nn.Sequential(
            nn.Linear(hidden_dim // 2, hidden_dim // 4),
            nn.ReLU(),
            nn.Linear(hidden_dim // 4, 1)  # Scalar value estimate
        )
    
    def forward(self, state: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
        """
        Returns (action_logits, state_value)
        """
        shared_features = self.backbone(state)
        action_logits = self.actor(shared_features)
        state_value = self.critic(shared_features)
        return action_logits, state_value
    
    def get_action(self, state: torch.Tensor, deterministic: bool = False):
        """
        Sample an action from the policy (or take the argmax for deployment).
        
        During training: stochastic (sample from distribution for exploration)
        During deployment: deterministic = True (take highest-probability action)
        """
        action_logits, state_value = self.forward(state)
        action_probs = F.softmax(action_logits, dim=-1)
        
        if deterministic:
            action = torch.argmax(action_probs, dim=-1)
        else:
            action_dist = torch.distributions.Categorical(action_probs)
            action = action_dist.sample()
        
        return action, action_probs, state_value
```

**The action space (what the agent can do):**

```python
ACTIONS = {
    # Low-impact actions (autonomous, no human approval needed)
    0: "MONITOR_ELEVATED",       # Increase logging rate, no network change
    1: "DEPLOY_HONEYPOT",        # Create a decoy resource visible to this entity
    2: "RATE_LIMIT_ENTITY",      # Throttle API/connection rate for entity
    3: "MFA_CHALLENGE",          # Force MFA re-authentication for account
    4: "SESSION_NOTIFY",         # Alert entity's manager (out-of-band notification)
    
    # Medium-impact actions (autonomous with immediate SOC notification)
    5: "BLOCK_SPECIFIC_EDGE",    # Block entity A → entity B connection
    6: "DISABLE_ACCOUNT_30M",    # Temporarily disable account (30-minute auto-restore)
    7: "REVOKE_SESSIONS",        # Kill all active sessions for entity
    8: "BLOCK_SRC_IP",           # Block source IP at firewall
    9: "RESTRICT_TO_ALLOWED_LIST",  # Allow only pre-approved destinations for entity
    10: "ENABLE_CANARY_TOKENS",  # Place monitoring tokens in accessible resources
    11: "DNS_SINKHOLE",          # Sinkhole suspicious DNS queries for entity
    
    # High-impact actions (require human confirmation OR very high confidence)
    12: "ISOLATE_HOST",          # Network isolation (VLAN quarantine) — auto at 0.90+
    13: "DISABLE_ACCOUNT_PERM",  # Permanent disable — always requires human approval
    14: "EMERGENCY_SEGMENT",     # Isolate entire network segment — requires human
    15: "RESET_CREDENTIALS",     # Force password reset for account
    16: "KILL_PROCESS",          # EDR kill specific process — auto at 0.90+
    17: "BLOCK_ENTIRE_ASN",      # Block entire AS number (aggressive) — requires human
    
    # Deception actions (intelligence gathering)
    18: "REDIRECT_TO_HONEYPOT",  # Make attack seem to succeed, redirect to decoy
    19: "INJECT_FAKE_CREDENTIALS",  # Plant fake credentials that alert on use
    20: "THROTTLE_RESPONSE",     # Slow responses to attacker (breakpoint engagement)
    
    # Escalation actions
    21: "ESCALATE_P1",           # Page on-call analyst immediately
    22: "ESCALATE_P2",           # Add to analyst queue (non-urgent)
    23: "WAIT",                  # Do nothing (explicit action, not absence of action)
}

# Risk classification for human-in-loop decisions
ACTION_RISK = {
    **{i: "LOW" for i in range(5)},
    **{i: "MEDIUM" for i in range(5, 12)},
    **{i: "HIGH" for i in range(12, 21)},
    **{i: "ESCALATE" for i in range(21, 24)}
}
```

### 4.2 Reward Function Engineering

**The reward function is the most critical design decision in the entire ACD system.** A poorly designed reward function produces an agent that optimizes for the wrong thing.

```python
class RewardCalculator:
    """
    Computes the reward signal for the RL agent after each action.
    
    Key design principles:
    1. Penalize missed attacks heavily (false negatives cost more than FPs in security)
    2. Penalize collateral damage from false positives (maintains trust in the system)
    3. Reward proportional to asset criticality (saving payment server > saving test server)
    4. Reward timeliness (catching attacker early = higher reward than late)
    5. Reward intelligence gathered (honeypot interaction = positive signal)
    """
    
    def compute(self, 
                prev_state: NetworkState,
                action: int,
                next_state: NetworkState,
                outcome: Outcome) -> float:
        reward = 0.0
        
        # === THREAT NEUTRALIZATION REWARDS ===
        if outcome.attacker_progress_halted:
            # Blocked a confirmed attacker action
            asset_value = self.cmdb.get_value(outcome.protected_asset)
            time_bonus = max(0, 1.0 - outcome.time_in_network_hours / 24)  # Faster = better
            reward += 10.0 * asset_value * (1 + time_bonus)
        
        if outcome.lateral_movement_blocked:
            dest_criticality = self.cmdb.get_criticality(outcome.blocked_destination)
            reward += 5.0 * dest_criticality  # More reward for protecting critical assets
        
        if outcome.credential_misuse_prevented:
            reward += 3.0
        
        if outcome.exfiltration_prevented:
            reward += 8.0  # Exfiltration prevention is extremely valuable
        
        if outcome.honeypot_interaction:
            reward += 2.0  # Intelligence gathered without tipping off attacker
        
        # === MISSED ATTACK PENALTIES ===
        if outcome.confirmed_false_negative:
            # We didn't act when we should have
            asset_value = self.cmdb.get_value(outcome.compromised_asset)
            reward -= 15.0 * asset_value  # Heavy penalty for missed attacks
        
        if outcome.data_exfiltration_occurred:
            gb_exfiltrated = outcome.bytes_exfiltrated / 1e9
            reward -= 20.0 * min(gb_exfiltrated, 10)  # Cap at 10GB equivalent
        
        # === COLLATERAL DAMAGE PENALTIES (false positive penalties) ===
        if outcome.confirmed_false_positive:
            # We isolated/blocked a legitimate user or system
            operational_impact = outcome.affected_users * 0.5   # Per user affected
            sla_penalty = outcome.sla_violation_cost             # From SLA contracts
            reward -= 2.0 * (1 + operational_impact + sla_penalty)
        
        if outcome.unnecessary_escalation:
            # Paged an analyst for something that didn't need it
            reward -= 0.5  # Small penalty for analyst time waste
        
        # === INFORMATION GATHERING REWARDS ===
        if outcome.attacker_ttp_identified:
            reward += 1.0  # Identified attacker techniques = future detections better
        
        # === ACTION CONSISTENCY REWARDS ===
        # Small reward for taking proportionate action
        # (don't nuke a network segment for a suspicious login)
        proportionality = self._compute_proportionality(action, next_state.threat_level)
        reward += 0.2 * proportionality
        
        return float(reward)
    
    def _compute_proportionality(self, action: int, threat_level: float) -> float:
        """
        Returns 1.0 if action is proportionate to threat level.
        Returns negative if action is wildly disproportionate.
        """
        action_impact = ACTION_IMPACT_SCORE[action]  # 0.0 (monitor) to 1.0 (segment)
        expected_impact = threat_level
        disparity = abs(action_impact - expected_impact)
        return max(-1.0, 1.0 - 2 * disparity)  # -1 to +1
```

**Why reward shaping is dangerous and how to avoid it:**

A common mistake is adding too many small "guiding" rewards (e.g., reward for every suspicious event flagged). This causes the agent to optimize for the shaped reward rather than the actual security objective. The PPO agent will learn to flag everything as suspicious to maximize reward even if this means drowning analysts in false positives. Rules for reward design:

1. **Rewards should reflect real business value** (cost of breach, SLA violations, analyst time)
2. **Sparse rewards are acceptable** — PPO can handle delayed rewards over many timesteps
3. **Don't reward intermediate steps** (rewarding "flagged as suspicious" trains a P(flag) maximizer)
4. **Always include both positive and negative rewards** — positive-only reward = agent learns to always act

### 4.3 Training: Simulation + Real-World Fine-Tuning

**Phase 1: Simulation environment training (offline, before production deployment)**

```python
class CyberSimEnvironment:
    """
    Simulated network environment for RL training.
    Uses MITRE ATT&CK attack patterns + realistic benign traffic.
    
    Based on:
    - CybORG (CSIRO research cyber gym)
    - CAGE Challenge (AI Cyber Challenge) scenarios
    - Internal red team exercise recordings
    """
    
    NETWORK_TOPOLOGY = {
        "internet": {},
        "dmz": {"web_server_01", "web_server_02", "email_gateway"},
        "internal": {"wkstn_01..200", "hlpdsk_01..10"},
        "sensitive": {"ad_dc_01", "ad_dc_02", "hr_server"},
        "payment": {"payment_db", "payment_app", "payment_gateway"},
    }
    
    ATTACKER_STRATEGIES = [
        APTLateralMovement(ttps=["T1566.001", "T1078", "T1021.001", "T1003.001"]),
        InsiderThreats(user_roles=["finance", "hr", "it"]),
        BruteForce(target_services=["ssh", "rdp", "smb"]),
        DataExfiltration(staging_methods=["dns_tunneling", "https_upload"]),
    ]
    
    def step(self, action: int) -> tuple[np.ndarray, float, bool, dict]:
        """
        Apply defender action, advance attacker, compute new state and reward.
        Returns (observation, reward, done, info)
        """
        # Apply defender action (may modify network state)
        self._apply_defender_action(action)
        
        # Advance attacker one step (attacker has its own policy)
        attacker_action = self.attacker_policy.act(self.attacker_observation())
        attacker_result = self._apply_attacker_action(attacker_action)
        
        # Generate realistic telemetry from the simulated actions
        telemetry = self._generate_telemetry(attacker_result)
        
        # Build new observation state
        observation = self._build_observation(telemetry)
        
        # Compute reward
        reward = self.reward_calculator.compute(
            self.prev_state, action, self.current_state, attacker_result
        )
        
        # Episode ends when: attacker exfiltrates data, defender contains attacker,
        # or max_steps reached
        done = attacker_result.exfiltration_complete or self.attacker_contained or self.step_count >= 1000
        
        return observation, reward, done, {"attacker_progress": attacker_result}
```

**Phase 2: Transfer learning to real environment**

```
Simulation → Pre-trained policy (trained for 10M environment steps, ~48 hours of GPU time)
                │
                ▼ Fine-tuning on real environment (conservative policy updates only)
Production → Shadow mode (agent observes real network, computes actions but doesn't execute)
                │ After 4 weeks of shadow mode: compare agent decisions to analyst decisions
                ▼ If agreement > 85%: advance to constrained deployment
Constrained → Agent can execute LOW-risk actions autonomously
              MEDIUM-risk actions require SOC approval
              HIGH-risk actions always require approval
                │ After 8 weeks: review FP rate, FN rate, collateral damage
                ▼ If metrics acceptable: advance to supervised autonomous
Supervised  → Agent autonomous for LOW and MEDIUM actions
              HIGH-risk still requires approval
              Continue online learning (PPO updates every night from collected experience)
```

### 4.4 Streaming Inference with Redis Caching

```python
class ACDInferenceEngine:
    """
    Real-time RL policy inference with Redis-backed caching.
    Target: < 50ms from event receipt to action decision.
    """
    
    def __init__(self, policy_model, redis_client):
        self.policy = policy_model
        self.redis = redis_client
        self.policy.eval()
        self.policy.half()  # FP16 inference: 2x faster, same quality for this task
    
    def get_action(self, entity_id: str, new_event: NormalizedEvent) -> ActionDecision:
        # === FAST PATH: Check if entity is in "high alert" mode ===
        # If we've already identified this entity as compromised, take immediate action
        alert_mode = self.redis.get(f"acd:alert:{entity_id}")
        if alert_mode == b"CRITICAL":
            return ActionDecision(action=ISOLATE_HOST, confidence=0.99, fast_path=True)
        
        # === STATE RETRIEVAL (from Redis, < 1ms) ===
        # Current entity state is maintained in Redis (updated by Flink after each event)
        state_bytes = self.redis.get(f"acd:state:{entity_id}")
        if state_bytes is None:
            # New entity: use default "unknown" state vector
            state_vector = self.default_state_vector
        else:
            state_vector = np.frombuffer(state_bytes, dtype=np.float32)
        
        # === APPLY NEW EVENT DELTA ===
        # Apply the delta from this new event to the cached state
        delta = self.feature_extractor.compute_delta(new_event, state_vector)
        updated_state = state_vector + delta
        
        # === RL INFERENCE (< 10ms on GPU, < 20ms on CPU) ===
        state_tensor = torch.from_numpy(updated_state).float().unsqueeze(0)
        with torch.no_grad():
            action, action_probs, value_estimate = self.policy.get_action(
                state_tensor, deterministic=True
            )
        
        action_idx = action.item()
        confidence = action_probs[0, action_idx].item()
        
        # === UPDATE STATE IN REDIS ===
        self.redis.set(
            f"acd:state:{entity_id}",
            updated_state.astype(np.float32).tobytes(),
            ex=7*24*3600  # 7-day TTL (state expires if entity is inactive)
        )
        
        # === CONFIDENCE THRESHOLDING ===
        action_risk = ACTION_RISK[action_idx]
        
        if action_risk == "HIGH" and confidence < 0.90:
            # Not confident enough to take high-impact autonomous action
            return ActionDecision(
                action=ESCALATE_P2,  # Downgrade to analyst escalation
                original_action=action_idx,
                confidence=confidence,
                reason="confidence_below_threshold_for_high_risk_action"
            )
        
        if confidence < 0.70:
            # Model is uncertain: always escalate when uncertain
            return ActionDecision(
                action=ESCALATE_P2,
                original_action=action_idx,
                confidence=confidence,
                reason="model_uncertainty"
            )
        
        return ActionDecision(
            action=action_idx,
            confidence=confidence,
            value_estimate=value_estimate.item(),
            action_probabilities=action_probs[0].numpy()
        )
```

---

## 5. Correlation & Alerting Flow

### 5.1 Translating RL Decisions to SOC Alerts

The RL agent makes sequential decisions, but the SOC analyst needs a narrative — a coherent story of what happened and why the agent acted.

```python
class AlertNarrativeBuilder:
    """
    Transforms RL agent decisions into human-readable SOC alerts.
    The narrative connects multiple RL steps into a campaign story.
    """
    
    def build_narrative(self, action_history: list[ActionDecision],
                        state_history: list[NetworkState]) -> AlertNarrative:
        
        # Detect campaign (multiple related actions)
        campaign = self._detect_campaign(action_history)
        
        # Build timeline
        timeline = []
        for action in campaign.actions:
            timeline.append(TimelineEntry(
                timestamp=action.timestamp,
                entity=action.entity_id,
                event=action.trigger_event,
                anomaly_score=action.trigger_state.max_anomaly_score,
                agent_action=ACTIONS[action.action],
                action_confidence=action.confidence,
                outcome=action.outcome
            ))
        
        # Attribute to ATT&CK framework
        ttp_attribution = self.attck_mapper.map_events(campaign.observed_events)
        
        # Assess business impact
        impact = self._assess_impact(campaign, state_history)
        
        return AlertNarrative(
            title=f"[ACD] {campaign.severity} — {campaign.attack_pattern} Detected and {campaign.status}",
            campaign_id=campaign.id,
            affected_entities=campaign.entities,
            attack_phase=campaign.estimated_kill_chain_phase,
            timeline=timeline,
            att_ck_ttps=ttp_attribution,
            autonomous_actions=campaign.autonomous_actions_taken,
            collateral_impact=impact.collateral,
            security_impact=impact.security,
            recommended_analyst_actions=self._generate_recommendations(campaign),
            evidence_links=self._collect_evidence_uris(campaign)
        )
```

### 5.2 Multi-Stage Threshold Architecture

Different actions require different confidence thresholds. A tiered threshold system balances autonomy with safety:

```
TIER 1 — DETECTION ONLY (threshold: > 0.50 confidence):
  Action: Log + Elevate monitoring
  No network change; zero operational risk
  Rationale: Better to log everything suspicious than miss context

TIER 2 — SOFT CONTAINMENT (threshold: > 0.70 confidence):
  Actions: Honeypot, MFA challenge, rate limit, canary tokens
  Reversible, low operational impact
  Analyst notified but not required to approve

TIER 3 — HARD CONTAINMENT (threshold: > 0.85 confidence):
  Actions: Block specific edge, revoke sessions, block IP
  Irreversible in the short term, moderate operational impact
  Analyst notified, 15-minute auto-review window

TIER 4 — HOST ISOLATION (threshold: > 0.90 confidence OR deterministic rule):
  Actions: VLAN quarantine, account disable, credential reset
  Significant operational impact (legitimate users may lose access)
  Analyst paged immediately; must confirm or restore within 30 minutes

TIER 5 — HUMAN ONLY (requires analyst approval regardless of confidence):
  Actions: Permanent account disable, segment isolation, block entire ASN
  These have irreversible or massive-scale consequences
  Agent presents recommendation; human approves

Note: Confidence thresholds can be LOWERED for high-criticality assets:
  If dst_asset.criticality == "PAYMENT_CRITICAL":
    tier_4_threshold = 0.80 (lower requirement because stakes are higher)
    tier_5_actions can auto-execute at 0.95 for imminent payment zone threats
```

### 5.3 SOAR Integration for Human-in-the-Loop Decisions

```python
class SOARIntegration:
    """
    When the RL agent escalates (uncertain or high-risk action needed),
    the SOAR platform manages the human workflow.
    """
    
    def submit_for_approval(self, decision: ActionDecision, context: AlertContext) -> str:
        """
        Creates an approval request in SOAR with full context.
        Returns approval_request_id for tracking.
        """
        approval_request = {
            "request_type": "ACD_ACTION_APPROVAL",
            "urgency": self._compute_urgency(decision, context),
            "agent_recommendation": {
                "action": ACTIONS[decision.action],
                "confidence": decision.confidence,
                "value_estimate": decision.value_estimate,
                "alternative_actions": [
                    {"action": ACTIONS[i], "probability": p}
                    for i, p in enumerate(decision.action_probabilities)
                    if p > 0.05
                ]
            },
            "context": {
                "affected_entity": context.entity_id,
                "entity_type": context.entity_type,
                "entity_criticality": context.cmdb_data.criticality,
                "triggering_events": context.recent_events[-10:],  # Last 10 events
                "anomaly_scores": context.current_state.anomaly_breakdown,
                "att_ck_mapping": context.ttp_attribution,
                "similar_past_incidents": self._find_similar_incidents(context, top_n=3)
            },
            "time_sensitivity": {
                "recommended_decision_within_minutes": 15,
                "auto_timeout_action": "ESCALATE_P1",  # If no response in 15 min, page harder
                "auto_timeout_at": (datetime.utcnow() + timedelta(minutes=15)).isoformat()
            },
            "one_click_actions": [
                {"label": "APPROVE - Isolate Host", "action_id": 12, "color": "red"},
                {"label": "APPROVE - Rate Limit Only", "action_id": 2, "color": "yellow"},
                {"label": "FALSE POSITIVE - Restore", "action_id": 23, "color": "green"},
                {"label": "NEED MORE INFO", "escalates": True, "color": "blue"}
            ]
        }
        
        # Submit to SOAR (Palo Alto XSOAR, IBM Resilient, Splunk SOAR, etc.)
        response = self.soar_api.create_incident(approval_request)
        
        # Set up callback: if human approves, execute the action
        self.redis.set(
            f"acd:pending_approval:{response['incident_id']}",
            json.dumps({"decision": decision.to_dict(), "context": context.to_dict()}),
            ex=15*60  # 15-minute expiry
        )
        
        return response['incident_id']
```

---

## 6. Attack Scenarios (Evasion Tactics)

### 6.1 Evasion Tactic 1: RL Policy Probing (Adversarial RL)

**The attack:** A sophisticated attacker who knows the defender is using RL can probe the environment to infer the policy's decision boundary, then operate below the action-triggering threshold.

**Step-by-step execution:**

```
Phase 1: Policy Reconnaissance (attacker has long-term access, e.g., via insider)
  
  Week 1: Take Action A, observe defender response
    → Run WMI query to Host X → no response from defender
    → Run WMI query to Host Y (near payment zone) → MFA challenge fired
    
  Week 2: Vary intensity and observe thresholds
    → 5 WMI queries in 1h → no response
    → 10 WMI queries in 1h → rate limiting applied
    → 8 WMI queries in 1h → no response
    Conclusion: threshold is between 8 and 10 queries per hour
    
  Week 3: Map the action space
    → Connecting to Host X via RDP → blocked
    → Connecting to Host X via SMB → allowed
    Conclusion: RL policy treats these protocols differently
    
Phase 2: Exploitation below thresholds
  
  Rate-limited reconnaissance:
    Only 7 WMI queries per hour (below 8-10 threshold)
    Wait 72 hours between sessions
    Use 4 different accounts (stay below per-account thresholds)
    
  Protocol switching:
    Where RDP is blocked, use WinRM (port 5985) instead
    Where SMB triggers alert, use RDP with legitimate admin credentials
    
  Distributed movement (swarming):
    Instead of one account touching many hosts (triggers fan-out detection):
    Use 10 accounts, each touching 2-3 hosts (below new_targets_1h threshold per account)
    
Phase 3: Final movement (after 6 weeks of mapping)
  All paths to payment zone mapped
  Protocol and rate thresholds known
  Execute final access below every detected threshold
```

**Why the RL model misses it:**

The RL agent's policy was trained on attack simulations that don't include meta-level adversaries who probe the policy itself. The agent's state representation includes entity-level features but not "number of threshold probes in last 30 days" — this meta-pattern is invisible to the current state representation.

**Detection via meta-feature:**

```python
class PolicyProbingDetector:
    """
    Detects when an entity is systematically probing the RL policy's thresholds.
    This is a meta-level detector on top of the base RL agent.
    """
    
    def detect_probing(self, entity_id: str, action_history: list) -> float:
        """
        Signs of policy probing:
        1. Entity receives defender responses (MFA challenge, rate limit)
           and then slightly reduces its activity
        2. Entity systematically tests different protocols/paths
        3. Activity patterns show step-function increases to just below thresholds
        """
        defender_responses = [a for a in action_history if a.was_defender_response]
        
        # Check: did entity reduce activity after each defender response?
        deceleration_after_response = self._check_deceleration_pattern(
            entity_id, defender_responses
        )
        
        # Check: systematic protocol/path variation after each block
        systematic_variation = self._check_protocol_variation_after_block(
            entity_id, action_history
        )
        
        # Check: activity level tracks just below recent response thresholds
        threshold_tracking = self._check_threshold_tracking(entity_id)
        
        probing_score = (
            0.4 * deceleration_after_response +
            0.3 * systematic_variation +
            0.3 * threshold_tracking
        )
        
        return probing_score
```

### 6.2 Evasion Tactic 2: Reward Hacking via False Positive Induction

**The attack:** Force the RL agent to falsely isolate many legitimate hosts, creating such a high false positive rate that the security team reduces the agent's autonomy or disables it.

```
Phase 1: Understand the FP penalty structure
  The defender's RL agent has a reward penalty for isolating legitimate hosts.
  After many FPs, the agent's threshold rises (or humans reduce its autonomy).
  
Phase 2: Manufacture false positives from attacker-controlled accounts
  Log in as attacker-controlled account (svc_monitoring) during business hours
  Generate traffic patterns identical to known attack patterns:
    - Port scan from monitoring_server to internal hosts (monitoring tool behavior)
    - Large data queries (backup job behavior)
    - Multiple admin connections (IT deployment behavior)
    
  These LOOK like attacks but actually come from legitimate-looking service accounts.
  
Phase 3: RL agent's dilemma
  Agent sees pattern: isolate_host, confidence=0.88
  Agent isolates monitoring_server
  Monitoring breaks → legitimate alerts flood SOC → IT complains → FP confirmed
  Reward signal: negative (FP penalty applied)
  
  After 20 FP events: agent's effective threshold rises from 0.80 to 0.87
  After 50 FP events: security team reduces agent autonomy level
  After 100 FP events: "ACD system creates too many false positives, disable it"

Phase 4: Attack under reduced defense
  With ACD disabled or hamstrung: conduct actual lateral movement
  No autonomous response, only human analysts (who are overwhelmed from FP storm)
```

**Why this is effective:**

The RL agent's reward function includes FP penalties. In adversarial settings, these penalties can be exploited to cause the agent to raise thresholds or reduce autonomy. This is a form of **reward poisoning** — the attacker corrupts the reward signal experienced by the agent.

**Detection:**

```
Monitor: Time-correlation between FP events
  If N FP events per day AND all FPs share an attacker-controlled source host:
    → FP events are not independent → potential FP manufacturing campaign
    
Monitor: FP rate by SOURCE entity (not just target)
  Normal: FP events are distributed across many source entities
  Attack: FP events all originate from same ASN, same subnets, or known compromised hosts
    
Response: Separate FP penalty for attacks vs. non-attacks
  If SOC confirms: "this was a legitimate host doing legitimate things" → standard FP penalty
  If SOC confirms: "this was an attacker manufacturing a false positive" → NO penalty applied
  Requires analyst to specify FP reason code when dismissing alerts
```

### 6.3 Evasion Tactic 3: GNN Graph Poisoning

**The attack:** The RL agent uses a GNN to detect lateral movement by modeling the expected network graph. If the attacker can slowly "normalize" unusual graph edges before exploiting them, the GNN won't flag them as anomalous.

```
Normal state:
  jdoe → HLPDSK-01 (frequent, normal)
  jdoe → DB-PAYMENT-01 (NEVER, high anomaly for GNN)

Attacker's graph poisoning strategy (over 8 weeks):
  
  Week 1: jdoe pings DB-PAYMENT-01 (ICMP, not unusual for IT)
    Edge: jdoe → DB-PAYMENT-01 appears with count=5, type=ICMP
    GNN anomaly: 0.71 (first-time edge, but ICMP is low-risk protocol)
    Agent action: MONITOR_ELEVATED (below action threshold)
    
  Week 2: jdoe connects to DB-PAYMENT-01 via HTTP/8080 (monitoring port)
    Edge: count=10 (growing, but slowly)
    GNN anomaly: 0.52 (edge now exists in graph, ICMP + monitoring seen)
    Agent action: MONITOR_ELEVATED (decreasing anomaly score — working!)
    
  Week 4: jdoe connects to DB-PAYMENT-01 via HTTPS (443)
    Edge: count=25 (established relationship in GNN's view)
    GNN anomaly: 0.38 (jdoe → DB-PAYMENT-01 is now "normal" in graph)
    Agent action: nothing (below monitoring threshold)
    
  Week 8: jdoe connects to DB-PAYMENT-01 via RDP (3389)
    Edge: same pair, graph considers it established
    GNN anomaly: 0.41 (RDP slightly anomalous but edge is normalized)
    Agent action: MONITOR_ELEVATED (not blocked!)
    
  Attacker has successfully normalized the payment server connection over 8 weeks.
```

**Why the model misses it:**

The GNN's training data assumes edges are either genuinely normal (high frequency, all protocols) or anomalous (new edge, unusual protocol). It doesn't model the gradual transition from "first ever" to "normalized" as an attack pattern itself. The edge existence feature (has this edge been seen before?) decreases in anomaly contribution as the edge accumulates history.

**Detection — protocol transition anomaly:**

```python
class EdgeProtocolProgressionDetector:
    """
    Detects when an entity-to-entity edge is "normalizing" through protocol escalation.
    Pattern: ICMP → HTTP → HTTPS → RDP (attacker escalating privileges on established edge)
    """
    
    def analyze_edge_evolution(self, src: str, dst: str) -> float:
        edge_history = self.neo4j.get_edge_protocol_history(src, dst, days=90)
        
        if len(edge_history) < 3:
            return 0.0  # Not enough history
        
        # Compute protocol risk trajectory
        risk_sequence = [self.PROTOCOL_RISK[e.protocol] for e in edge_history]
        
        # Is risk monotonically increasing? (gradual escalation pattern)
        monotone_increases = sum(
            1 for i in range(1, len(risk_sequence))
            if risk_sequence[i] > risk_sequence[i-1]
        )
        
        escalation_ratio = monotone_increases / (len(risk_sequence) - 1)
        
        # High escalation ratio + current high-risk protocol = suspicious normalization
        current_risk = risk_sequence[-1]
        
        normalization_score = escalation_ratio * current_risk
        
        return normalization_score  # 0.0 to 1.0
```

---

## 7. Failure Points & Scaling

### 7.1 Failures Under DDoS / Log Flood

**The specific risk for ACD systems:** A log flood doesn't just degrade detection — it corrupts the RL agent's state representation, causing it to make incorrect decisions based on incomplete information.

```
Scenario: Attacker generates 100M events/minute (vs. normal 5M/min)
         by triggering network scanning from 10,000 compromised hosts

Impact cascade:

T+0: Log flood begins
  Event rate: 20x normal
  Kafka ingress: 20x normal throughput → approaches broker saturation

T+2min: Flink normalization lag
  Consumer lag grows: 20M events behind
  Feature computation is 2 minutes stale
  RL agent state vectors are 2+ minutes old
  
T+3min: State corruption begins
  New events cannot be applied to stale state vectors fast enough
  Per-entity state in RocksDB is increasingly outdated
  RL agent decisions based on outdated state = wrong policy output

T+5min: False negatives surge
  A lateral movement event at T+3 is buried in the log flood
  Its state delta never gets applied before TTL expires
  RL agent never "sees" the lateral movement event
  → BLIND SPOT CREATED BY THE LOG FLOOD

T+7min: RL agent becomes incoherent
  State vectors are now so stale they don't represent real network state
  Policy outputs are effectively random relative to actual security state
  Agent starts making incorrect autonomous decisions
  
T+10min: Alert storm from stale state actions
  Agent finally processes 10 minutes of backed-up events simultaneously
  Multiple threshold crossings simultaneously → mass alert fire
  SOC overwhelmed (same problem as log flood's intended effect)
```

**ACD-specific resilience mechanisms:**

```python
class StateStalenessSafetySystem:
    """
    Monitors state vector freshness and degrades gracefully when state is stale.
    An RL agent with stale state should NOT make autonomous high-impact decisions.
    """
    
    def get_action_with_staleness_check(self, entity_id: str, 
                                         event: NormalizedEvent) -> ActionDecision:
        state_age_seconds = self.get_state_age(entity_id)
        
        if state_age_seconds > 300:  # State is 5+ minutes old
            # State is too stale for confident action
            # Fall through to deterministic rules only
            return self.deterministic_rules_only(event)
        
        elif state_age_seconds > 60:  # State is 1-5 minutes old
            # Partial staleness: only allow low-impact autonomous actions
            decision = self.rl_agent.get_action(entity_id, event)
            if ACTION_RISK[decision.action] in ["MEDIUM", "HIGH"]:
                # Downgrade to lower-impact action
                return ActionDecision(
                    action=ESCALATE_P2,
                    original_action=decision.action,
                    reason="state_staleness_downgrade"
                )
            return decision
        
        else:  # State is fresh (< 60 seconds)
            return self.rl_agent.get_action(entity_id, event)
    
    def deterministic_rules_only(self, event: NormalizedEvent) -> ActionDecision:
        """
        When state is too stale for RL, fall back to deterministic rules.
        These rules require no historical state.
        """
        if event.geo.is_tor and event.auth.success:
            return ActionDecision(action=BLOCK_SRC_IP, confidence=1.0, 
                                  method="deterministic_rule")
        if event.event_action == "lsass_dump":
            return ActionDecision(action=ISOLATE_HOST, confidence=1.0,
                                  method="deterministic_rule")
        # ... other high-confidence deterministic rules
        return ActionDecision(action=MONITOR_ELEVATED, confidence=0.5,
                              method="fallback_safe_default")
```

### 7.2 Concept Drift in the RL Policy

**The specific challenge for RL:** Unlike supervised ML (where you retrain a model on new data), RL involves a policy that was trained on a simulation of the environment. The environment changes, but the policy doesn't know it.

```
Types of environment drift relevant to ACD:

1. NETWORK TOPOLOGY DRIFT
   New subnets added, hosts decommissioned, firewall rules changed
   Impact: RL agent's graph-based state features no longer reflect real topology
   Example: Agent blocks "unusual" lateral movement to a new DMZ host
            that was added 2 months after policy training
            Agent thinks it's payment zone; it's actually a new CDN node
   
2. BEHAVIORAL DRIFT (users/services changing patterns)
   Remote work adoption changes baseline telemetry patterns
   New business application generates unusual-looking logs
   Impact: Agent's anomaly scores drift upward (FP rate increases)
   
3. ATTACKER TTP DRIFT
   Attacker starts using new techniques not seen in training simulations
   Impact: Agent's sequence classifier doesn't recognize new attack patterns
   
4. ORGANIZATIONAL DRIFT
   Acquisition integrates new subsidiary with different security posture
   Impact: New entity types with no training analogs appear in state
```

**Online learning with safety constraints:**

```python
class SafeOnlineLearning:
    """
    Continues to improve the RL policy in production using real experience.
    But: safety constraints prevent catastrophic policy degradation.
    """
    
    def collect_experience(self, observation, action, reward, next_observation, done):
        """
        Store experience in replay buffer for periodic policy updates.
        Note: reward must come from confirmed outcomes, not immediate signals.
        Reward is computed 24-48 hours later when analyst confirms TP/FP.
        """
        self.replay_buffer.add({
            'obs': observation,
            'action': action,
            'reward': reward,
            'next_obs': next_observation,
            'done': done,
            'timestamp': time.time()
        })
    
    def update_policy(self):
        """
        Called nightly: update policy on last 24h of experience.
        Uses PPO's clipped objective to prevent large policy changes.
        """
        if len(self.replay_buffer) < 10000:
            return  # Not enough new experience
        
        batch = self.replay_buffer.sample(batch_size=4096)
        
        # Compute policy gradient update
        loss = self.ppo_loss(batch)
        
        # SAFETY CHECK: Compute KL divergence between new policy and current policy
        kl_divergence = self.compute_kl(batch, self.current_policy, self.new_policy)
        
        if kl_divergence > 0.02:  # More than 2% policy change
            # Safety constraint: don't update (change is too large)
            logger.warning(f"Policy update rejected: KL={kl_divergence:.4f} > 0.02 max")
            self.alert_mlops_team("Large policy update blocked — review replay buffer")
            return
        
        # Safe update: apply gradients
        self.optimizer.step()
        
        # Validate updated policy on held-out safety scenarios
        safety_score = self.evaluate_safety_scenarios(self.new_policy)
        if safety_score < 0.95:
            # Policy fails safety tests (e.g., it now isolates the domain controller)
            self.rollback_policy()
            self.alert_mlops_team("Policy update rolled back — safety test failure")
            return
        
        # Accept update
        self.current_policy = self.new_policy
        logger.info(f"Policy updated successfully. KL={kl_divergence:.4f}")
```

### 7.3 False Positive Storms from RL Decisions

**ACD-specific FP failure mode:** The RL agent isolates a host, which disrupts a service that many users depend on. The service disruption causes those users to do unusual things (reconnect from different devices, call IT, access systems they don't normally use) — which the RL agent then also flags as anomalous. A self-reinforcing FP cascade.

```
T=0: RL agent isolates HLPDSK-01 (suspected compromise)
T+2min: 50 employees can't access helpdesk → call IT on phones
T+5min: IT staff access helpdesk tickets via backup system (unusual access pattern)
T+7min: RL agent sees IT staff on unusual systems → flags them
T+10min: 10 more hosts flagged → RL agent wants to isolate more
T+12min: RL agent isolates AD jump server (unusual admin access triggered)
T+15min: AD connectivity degraded → authentication failures everywhere
T+17min: Authentication failures look like brute force → more flags
T+20min: Network-wide FP cascade → SOC overwhelmed → real attacker can operate freely

This is a "defender-induced incident" caused by the RL agent's own actions.
```

**Circuit breaker for autonomous action storms:**

```python
class AutonomousActionCircuitBreaker:
    """
    Prevents runaway autonomous action storms.
    Inspired by Netflix Hystrix circuit breaker pattern.
    """
    
    STATE = "CLOSED"  # Normal operation
    # "OPEN" = circuit broken (RL agent suspended, deterministic-only mode)
    # "HALF_OPEN" = testing if situation has resolved
    
    def check_action_rate(self, proposed_action: ActionDecision) -> bool:
        """
        Returns False (block action) if circuit is open or rate limits exceeded.
        """
        # Rate limits (per 5-minute window)
        isolations_5min = self.redis.get("acd:circuit:isolations_5min") or 0
        
        if int(isolations_5min) >= 5:  # More than 5 isolations in 5 minutes
            # Something unusual is happening
            self.open_circuit("rapid_isolation_rate")
            return False
        
        if self.STATE == "OPEN":
            # Circuit is open: only allow deterministic rules
            if proposed_action.method != "deterministic_rule":
                return False
        
        if self.STATE == "HALF_OPEN":
            # Allow one action, monitor outcome before fully closing
            if proposed_action.action not in [MONITOR_ELEVATED, DEPLOY_HONEYPOT]:
                return False
        
        return True  # Circuit closed, action allowed
    
    def open_circuit(self, reason: str):
        self.STATE = "OPEN"
        self.redis.set("acd:circuit:state", "OPEN", ex=300)  # Open for 5 minutes
        
        # Alert immediately
        self.pagerduty.create_incident(
            title="ACD Circuit Breaker Opened",
            description=f"Reason: {reason}. RL autonomous actions suspended. Falling back to deterministic rules.",
            severity="HIGH"
        )
        
        # Automatically try to close after 5 minutes
        self.schedule_half_open(delay_seconds=300)
```

---

## 8. Mitigations & Defense-in-Depth

### 8.1 Combining RL with Deterministic Signatures

The RL agent is powerful but can be evaded or malfunction. Deterministic signatures (Sigma rules, Yara rules, known IOCs) provide a hardened, evasion-resistant baseline that doesn't degrade with concept drift.

```
ARCHITECTURE: Two-layer detection

Layer 1 — DETERMINISTIC (always runs, never bypassed):
  Input: Raw normalized events
  Rules: Sigma rules, IOC matching, hardcoded TTPs
  Output: CRITICAL alerts that trigger immediate action regardless of RL decision
  
  Examples:
    "LSASS dump via comsvcs.dll" → ISOLATE_HOST (no ML required)
    "IP matches known C2 server" → BLOCK_SRC_IP (no ML required)  
    "Process hollowing technique detected" → KILL_PROCESS (no ML required)
    "DNS query to known DGA domain" → DNS_SINKHOLE (no ML required)

Layer 2 — RL-BASED (learns and adapts, catches novel attacks):
  Input: Feature vectors from normalized events + entity state
  Model: PPO policy network
  Output: Probability distribution over action space
  
  Used for: Novel attack patterns, behavioral anomalies, campaign correlation,
            prioritization of limited response resources

Layer 3 — COMBINATION (when layers disagree):
  If deterministic = HIGH risk AND RL = low risk:
    → Trust deterministic (it's hardcoded for a reason)
    → Log disagreement for RL policy review
    → Alert detection engineering team (policy may need improvement)
  
  If deterministic = no match AND RL = HIGH risk:
    → Trust RL but require higher confidence threshold (0.90 instead of 0.80)
    → RL has found something deterministic rules haven't seen before
    → Log for human review and potential sigma rule creation
  
  If both agree: Maximum confidence, act immediately
```

### 8.2 Counter-Probing Defenses

To defeat RL policy probing (Section 6.1), the agent's effective thresholds should appear inconsistent to an outside observer:

```python
class StochasticThresholdManager:
    """
    Adds calibrated randomness to RL action thresholds.
    Makes the policy harder to reverse-engineer through probing.
    
    CRITICAL: The randomness must not degrade actual security effectiveness.
    We randomize response TIMING and INTENSITY, not the fundamental decision.
    """
    
    def get_action_threshold(self, action_type: str, base_threshold: float) -> float:
        """
        Returns a threshold that includes calibrated noise.
        The noise is seeded by a rotating secret key (changes every 24h).
        
        This means:
        - Today: MFA challenge threshold = 0.68 (randomly below base)
        - Tomorrow: MFA challenge threshold = 0.74 (randomly above base)
        - Attacker cannot determine the threshold by probing because it changes daily
        """
        # Noise: ±10% around base threshold
        daily_seed = hashlib.sha256(f"{self.daily_key}:{action_type}".encode()).digest()
        noise_fraction = (int.from_bytes(daily_seed[:4], 'big') / 2**32 - 0.5) * 0.2
        
        return base_threshold + noise_fraction
    
    def add_response_timing_jitter(self, action: ActionDecision) -> int:
        """
        Delay responses by a random amount (0-30 seconds).
        Prevents attacker from measuring exact threshold by observing response time.
        """
        if action.confidence > 0.95:
            return 0  # Critical: respond immediately
        else:
            return random.randint(0, 30)  # Non-critical: up to 30s jitter
```

### 8.3 Deception Integration (Honeypots as RL Actions)

Honeypots are a first-class action in the ACD system, not just a passive detection mechanism:

```python
class DeceptionOrchestrator:
    """
    Manages honeypot deployment and the RL agent's ability to use deception.
    
    Deception is particularly effective when:
    1. Attacker is in reconnaissance phase (let them "find" decoys)
    2. Attacker is about to move laterally (redirect them to decoy target)
    3. The agent needs more information before taking hard containment action
    """
    
    def deploy_contextual_honeypot(self, attacker_entity: str, 
                                    reconnaissance_targets: list) -> HoneypotConfig:
        """
        Deploy honeypots that appear valuable to this specific attacker.
        Based on what they've been looking at during recon.
        """
        # What has the attacker shown interest in?
        recon_patterns = self.analyze_recon_targets(reconnaissance_targets)
        
        honeypot_config = HoneypotConfig(
            # Make the honeypot look like what the attacker wants
            hostname=f"DB-{recon_patterns.target_type.upper()}-PROD-03",
            services=recon_patterns.discovered_services,
            fake_credentials=self.generate_canary_credentials(attacker_entity),
            # Fake data that alerts on access
            data_fixtures=self.create_canary_data(recon_patterns.data_type),
            # Deliberately slow down responses (buys time for human response)
            response_delay_ms=random.randint(100, 500)
        )
        
        # Deploy via container orchestration
        self.k8s_client.create_honeypot_pod(honeypot_config)
        
        # Register canary tokens — when fake credentials are used anywhere:
        # we immediately know the attacker's footprint and tools
        self.canary_manager.register_credential(
            honeypot_config.fake_credentials,
            alert_target=f"acd:canary_hit:{attacker_entity}"
        )
        
        return honeypot_config
    
    def redirect_to_honeypot(self, attacker_entity: str, 
                              real_target: str,
                              honeypot: HoneypotConfig):
        """
        When attacker tries to connect to real_target, silently redirect to honeypot.
        Attacker believes they've succeeded; they're actually in a sandbox.
        
        Implementation: 
        - Firewall rule: redirect attacker's IP + dst_port to honeypot
        - NAT rule: make honeypot respond as if it were real_target
        - DNS: attacker's DNS queries for real_target return honeypot IP
        
        Security note: this requires extremely careful implementation to avoid
        redirecting legitimate traffic. Always verify the src_ip is confirmed
        as attacker-controlled before enabling redirection.
        """
        # Only redirect if high confidence the source is attacker-controlled
        if self.attacker_confidence(attacker_entity) < 0.95:
            raise InsufficientConfidenceError(
                "Redirect is too high-impact for uncertain attacker attribution"
            )
        
        self.firewall_api.add_nat_rule(
            src_ip=self.get_attacker_ip(attacker_entity),
            dst_ip=self.get_host_ip(real_target),
            redirect_to=honeypot.ip,
            duration_minutes=60
        )
        
        logger.info(f"DECEPTION: Redirecting {attacker_entity} from {real_target} to honeypot")
```

---

## 9. Observability

### 9.1 Monitoring the RL Policy's Health

The RL policy is not static — it evolves through online learning. Monitoring the policy itself is as important as monitoring the alerts it generates.

```yaml
# Prometheus metrics for ACD RL system

# === POLICY HEALTH ===
acd_policy_version: current deployed policy version string
acd_policy_age_hours: hours since last policy update
acd_policy_kl_divergence: KL from last update (should be < 0.02)
acd_policy_safety_score: score on safety test suite (should be > 0.95)

# === INFERENCE HEALTH ===
acd_inference_latency_ms{quantile="0.99"}: p99 inference latency (target: < 50ms)
acd_inference_latency_ms{quantile="0.999"}: p99.9 latency (alert if > 200ms)
acd_state_staleness_seconds{quantile="0.99"}: p99 state age (alert if > 60s)
acd_state_miss_rate: fraction of entities with no cached state (alert if > 5%)
acd_inference_errors_total{error_type}: count of inference failures

# === ACTION DISTRIBUTION ===
acd_actions_taken_total{action_type, tier}: counts by action type and tier
acd_autonomous_action_rate: actions taken without human approval (target: < 80%)
acd_human_approval_rate: fraction of decisions requiring human (target: 20-30%)
acd_circuit_breaker_open_total: number of circuit breaker openings (alert if > 3/day)

# === OUTCOME METRICS (lagged 24-48h, from analyst feedback) ===
acd_true_positive_rate_rolling_7d: TP/(TP+FN) rolling 7 days
acd_false_positive_rate_rolling_7d: FP/(FP+TN) rolling 7 days
acd_collateral_damage_users_total: users disrupted by FP autonomous actions
acd_mean_time_to_contain_seconds: from first detection to attacker contained

# === REWARD SIGNAL HEALTH ===
acd_mean_episode_reward_rolling: mean reward per RL episode (rising = improving policy)
acd_reward_variance: variance of rewards (high variance = unstable policy)
acd_analyst_feedback_lag_hours: how long before RL agent gets feedback (target: < 48h)

# === ENVIRONMENT DRIFT ===
acd_state_distribution_kl: KL divergence of current state distributions from training
acd_new_entity_types_seen: count of entity types not seen in training (alert if > 0)
acd_action_space_coverage: fraction of actions used in last 7d (alert if < 0.5)
```

**Policy evaluation framework — continuous A/B testing:**

```python
class PolicyABTestManager:
    """
    Runs champion (current) vs challenger (updated) policy in shadow mode.
    Safe way to evaluate policy improvements without risking production security.
    """
    
    def run_shadow_comparison(self, state: NetworkState) -> ComparisonResult:
        # Run both policies
        champion_action = self.champion_policy.get_action(state, deterministic=True)
        challenger_action = self.challenger_policy.get_action(state, deterministic=True)
        
        # Only champion action is executed
        # Challenger action is logged for analysis
        self.comparison_log.append(ComparisonEntry(
            state=state,
            champion=champion_action,
            challenger=challenger_action,
            agreed=(champion_action.action == challenger_action.action),
            challenger_confidence=challenger_action.confidence
        ))
        
        # After 2 weeks of shadow mode:
        # Analyze: does challenger agree with champion more often?
        # Does challenger have higher confidence on same decisions?
        # Does challenger recommend more proportionate actions?
        
        return champion_action  # Always execute champion in production
```

### 9.2 Tracing an RL Decision Back to Raw Events

Every autonomous action must be traceable. If the RL agent isolates a host and it turns out to be a false positive, the analyst must understand why the agent made that decision.

```
DECISION AUDIT TRAIL:

ACD Autonomous Action: ISOLATE_HOST(HLPDSK-01)
Timestamp: 2024-01-15T09:10:14Z
Confidence: 0.97
Policy Version: acd-policy-v2.3.1-2024-01-10

↓ What triggered this action?

State vector at decision time (key features, full vector in S3):
  entity_jdoe:
    recon_sequence_score:     0.89  ← HIGH (LSTM sequence matched recon pattern)
    wmi_query_z_score:        4.2   ← HIGH (4.2σ above baseline)
    new_targets_1h:           23    ← HIGH (23 unique hosts in 1 hour)
  entity_HLPDSK-01:
    anomaly_score:            0.91  ← HIGH
    lsass_access_detected:    1     ← CRITICAL
    process_anomaly_score:    0.94  ← HIGH
  edge_jdoe_HLPDSK-01:
    privilege_escalation:     0.88  ← HIGH
  edge_jdoe_PAYMENT-01:
    blocked_attempt:          1     ← HIGH (prior blocked RDP attempt)

↓ What triggered the state update?

Triggering event: evt-8f3a2b1c
  Raw event: Windows Event ID 10 (Process Access) on HLPDSK-01
    Process: powershell.exe (PID 4821)
    Target: lsass.exe (PID 612)
    Access: 0x1410 (PROCESS_VM_READ | PROCESS_QUERY_INFORMATION)
  Normalized to: acd.normalized/_doc/8f3a2b1c
  Raw log: s3://acd-raw-logs/2024/01/15/09/wef-dc02-hlpdsk01-20240115090000.gz

↓ What contributed to jdoe's prior high state?

Contributing events (last 2 hours):
  1. [09:04] evt-7e2a1b1c: RDP attempt jdoe → DB-PAYMENT-01 → BLOCKED
     Raw: acd.raw.network/_doc/7e2a1b1c
  2. [14:30-17:00] 47x evt-6d1a0b2d: WMI queries from jdoe's session
     Query example: s3://acd-raw-logs/.../wef-dc01-20240115143022.gz#offset:14392

↓ How would the analyst replay this decision?

CLI: acd-replay --entity HLPDSK-01 --timestamp 2024-01-15T09:10:14Z
  → Loads policy v2.3.1, loads state vector from S3 snapshot
  → Re-runs inference with the exact state at that timestamp
  → Shows: action_probabilities, value_estimate, and per-feature SHAP attribution
  → SHAP shows: lsass_access_detected contributed 0.41 of the isolation decision
               prior_payment_zone_attempt contributed 0.28
               recon_sequence_score contributed 0.19
               (adds up to 0.88 of total score, remaining 0.12 from other features)
```

### 9.3 What Should Alert MLOps vs. SOC

**MLOps / Detection Engineering alerts:**

```yaml
IMMEDIATE (page MLOps on-call):
  - acd_circuit_breaker_open: RL agent suspended (→ security coverage degraded)
  - acd_policy_safety_score < 0.90: policy fails safety tests (→ may take dangerous actions)
  - acd_state_staleness > 300s for > 10% entities: state is too old to trust
  - acd_inference_errors_total rising: inference service degraded
  - Policy update KL divergence > 0.05: abnormally large policy change attempted
  - acd_replay_buffer_corruption: training data may be compromised

ALERT (Slack, next business day):
  - acd_false_positive_rate_rolling_7d > 25%: model degrading, retrain needed
  - acd_new_entity_types_seen > 0: policy encounters unknown entity types
  - acd_action_space_coverage < 0.4: policy is only using a few actions (possibly stuck)
  - acd_policy_age_hours > 720 (30 days): overdue for policy review
  - Any feature PSI > 0.25: significant environment drift detected
```

**SOC alerts:**

```yaml
CRITICAL (page on-call immediately):
  - Any AUTONOMOUS ISOLATION decision (SOC must confirm within 30 minutes)
  - Deterministic rule fire (LSASS dump, known IOC)
  - RL confidence > 0.90 for any MEDIUM+ action (RL very confident of threat)
  - ACD circuit breaker OPEN: RL suspended, security coverage reduced (SOC must compensate)

HIGH (Slack notification, respond within 1 hour):
  - RL escalation of MEDIUM risk action (RL saw something worth human eyes)
  - Multiple entities flagged in same time window (potential campaign)
  - Payment zone proximity score > 0.8 for any entity
  - Honeypot interaction detected (attacker found decoy)

NOT an alert (log only):
  - RL selects MONITOR_ELEVATED (this is low-impact and expected frequently)
  - MFA challenges issued (SOC bulk review weekly, not per-event)
  - Routine rate limiting actions
  - Policy updates that pass safety tests (MLOps internal only)
  - RL model retraining events (MLOps internal only)
```

---

## 10. Interview Questions

### Q1: Why is Reinforcement Learning specifically suited for autonomous cyber defense, compared to supervised ML or rule-based systems? What fundamental properties of the problem make RL the right tool?

**Answer:**

Three properties of cyber defense make RL uniquely suitable:

**1. Sequential decision-making with temporal dependencies**

A cyber attack is a multi-step campaign, not a single event. The defender's action at step 1 changes the environment at step 2. If you isolate a host at step 1, the attacker must route differently at step 2 — but the attacker still tries. The defender then needs to make a step-2 decision based on a state that was modified by step 1.

Supervised ML treats each event independently. It classifies: "is this event malicious?" But it doesn't model: "given that I already blocked this path, what will the attacker do next, and what should I do in response?" RL is designed exactly for this: policy π(action | state) where state encodes the history of what's happened and what actions have already been taken.

**2. Delayed reward signals**

The value of isolating a host at T=09:10 (before the attacker uses it) is not knowable at T=09:10. You learn the value 6 hours later when the forensic analysis confirms the host was compromised and the isolation prevented lateral movement to the payment server. Supervised ML requires labels at the time of prediction. RL uses Bellman equations to propagate future reward signals backward through time: the isolation action at T=09:10 receives partial credit for the successful defense of the payment server at T=15:00 because the trajectory from T=09:10 to T=15:00 was favorable.

**3. Adversarial adaptation**

The attacker adapts to the defender's behavior. A rule-based system has fixed behavior — a sophisticated attacker maps the rules and routes around them. A supervised ML model doesn't change its predictions based on what the attacker has learned. An RL agent, through online learning, updates its policy based on outcomes — if the attacker learns to evade tactic A, the agent's experience with tactic A failures updates the policy toward tactic B. This is the arms-race dynamic, and RL is designed for it.

**Why not supervised ML?** Supervised ML needs labels. In cyber defense, most events are unlabeled (you rarely know for certain whether an event was malicious until after investigation). RL doesn't need per-event labels — it needs outcome signals (did the attacker succeed? Did we cause collateral damage?), which are more readily available.

**Why not rules?** Rules require the rule author to enumerate all possible attack patterns. The rule space is infinite and attackers constantly invent novel techniques. RL generalizes from patterns seen in training (simulation + red team exercises) to novel situations by learning the underlying structure of what looks like an attack, not a specific attack signature.

---

### Q2: Explain the credit assignment problem in ACD's RL system. How does PPO handle it, and what happens if the reward signal is delayed by 48 hours?

**Answer:**

**The credit assignment problem:** When an agent takes a sequence of actions and eventually receives a reward, how does it determine which actions *caused* the reward? If the agent isolates a host at step 5 of a 100-step episode, and receives a positive reward at step 100 (attack contained), the credit for the reward must be assigned backward across all 95 intermediate steps.

**The mathematical framework (Bellman equation):**

The value of a state s is defined recursively:
```
V(s) = E[R(s,a) + γ * V(s')]

Where:
  R(s,a) = immediate reward for action a in state s
  γ = 0.99 = discount factor (future rewards worth 99% of immediate rewards)
  V(s') = value of next state
```

This creates a propagation chain: V(s_100) is known (episode over, total reward observed). V(s_99) can then be estimated from R(s_99, a_99) + γ*V(s_100). And so on backward to V(s_5) — the value of the host isolation decision.

**How PPO handles this:**

PPO uses the **Generalized Advantage Estimator (GAE)** to compute a bias-variance tradeoff in credit assignment:

```
Advantage at timestep t:
  A_t = Σ_{l=0}^{∞} (γλ)^l * δ_{t+l}
  
Where:
  δ_t = r_t + γ*V(s_{t+1}) - V(s_t)  (TD error at step t)
  λ = 0.95 (GAE lambda: how far to look ahead)
  γ = 0.99 (discount factor)
  
λ close to 1: look far ahead (low bias, high variance — trust long-horizon credit)
λ close to 0: use only one-step lookahead (high bias, low variance — conservative)
```

PPO's clipped surrogate objective prevents large policy updates that would overcorrect:
```
L_CLIP = E[min(ratio * A_t, clip(ratio, 1-ε, 1+ε) * A_t)]

ratio = π_new(a|s) / π_old(a|s)  (how much the policy changed for this state-action)
ε = 0.2 (clip range: policy can change by at most 20% probability ratio)
```

**What happens with 48-hour delayed rewards?**

This is a real operational challenge. The reward for "did we correctly identify this attacker?" comes when the analyst closes the ticket with TP/FP designation — 24-48 hours later. The RL training loop needs this signal.

Impact: With 48-hour delay, the replay buffer contains experiences with no reward signal yet. The agent cannot learn from them immediately. We handle this via:

1. **Retroactive reward injection:** When the analyst designates TP/FP, we retrieve the original (s, a, s') tuple from the replay buffer and add the reward. The experience is then ready for training.

2. **Asymmetric discount:** We use γ=0.99 for security-relevant rewards (delayed is fine) but γ=0.5 for operational disruption rewards (collateral damage is immediate — we want the agent to learn quickly from FP costs).

3. **Synthetic immediate rewards:** We add small shaped rewards for intermediate signals (e.g., if attacker slowed down = +0.1, if attacker retreated = +0.5) to provide faster feedback before the analyst's delayed signal arrives. Care is taken not to over-weight these shaped rewards vs the true delayed outcome.

---

### Q3: The RL agent is deployed in production and starts generating an unusually high false positive rate. Walk through your complete debugging process.

**Answer:**

This is a systems debugging problem. The root cause could be at any layer. I work top-down:

**Step 1: Characterize the FP pattern (< 30 minutes)**

```
Query: SELECT action, entity_type, trigger_feature, analyst_verdict
       FROM acd_actions
       WHERE analyst_verdict = 'FALSE_POSITIVE'
       AND timestamp > NOW() - INTERVAL '24 hours'
       ORDER BY timestamp

Questions to answer:
  - Are FPs concentrated in one action type (e.g., all MFA challenges)?
  - Are they from one entity type (e.g., all service accounts)?
  - Do they share a common trigger feature (e.g., all high wmi_query_z_score)?
  - What time window did they start? (correlate with deployments, network changes)
```

**Step 2: Check for environment changes (< 1 hour)**

If FPs started at a specific time:
- Was there a network change (new subnet, new firewall rules)?
- Was there a new application deployed that generates unusual logs?
- Was there an org change (new team, new service accounts)?
- Was there a policy update in the last 48 hours?

If FPs are distributed randomly: likely model drift, not a point change.

**Step 3: Feature distribution analysis (< 2 hours)**

```python
# For each feature in the FP events, compute PSI vs training distribution
for feature in trigger_features_in_fps:
    current_dist = get_current_distribution(feature)
    training_dist = get_training_distribution(feature)
    psi = compute_psi(current_dist, training_dist)
    if psi > 0.10:
        print(f"DRIFT DETECTED: {feature} PSI={psi:.3f}")
```

A feature with PSI > 0.25 that's also the top trigger for FPs is the root cause of model drift.

**Step 4: Policy replay on FP events (< 1 hour)**

```bash
acd-replay --event-ids [fp_event_ids] --show-shap --policy-version current
```

This shows which features contributed most to the incorrect isolation decision. If SHAP shows `wmi_query_z_score: +0.45` as the top contributor, and we know WMI activity increased due to a new monitoring tool, we've found the cause.

**Step 5: Remediation based on root cause:**

- **New application generating unusual logs:** Add this application to the feature normalization pipeline; exclude its traffic from WMI count features for its service account.
- **Model drift from behavior change:** Retrain on recent data that includes the new normal behavior. Verify retraining with held-out recent labeled data.
- **Policy update introduced regression:** Roll back to previous policy version immediately.
- **Training-production skew (simulation vs real):** Update simulation environment to include the new behavior pattern.

**Step 6: Prevention going forward:**

Add monitoring for the FP root cause so it's detected automatically next time:
- If new app: add automated application classification that excludes monitoring tools from behavioral baselines
- If drift: lower the PSI alert threshold for this feature class

---

### Q4: How do you design the reward function to prevent the agent from developing a policy of "always isolate everything that looks suspicious," which would technically maximize expected security reward but would be operationally catastrophic?

**Answer:**

This is the **reward hacking** / **Goodhart's Law** problem in RL: "When a measure becomes a target, it ceases to be a good measure."

If you reward only security outcomes (blocks attacker = +10, misses attacker = -15), the agent learns: "the safest strategy is to isolate everything suspicious immediately." This maximizes security reward but destroys operations.

**Multi-objective reward with binding constraints:**

The key insight is that operational impact is not just a secondary consideration — it's a **hard constraint** that the agent must never violate, regardless of security reward gains:

```python
def compute_reward(action, outcome):
    security_reward = compute_security_reward(outcome)
    
    # HARD CONSTRAINTS (turn these into large penalties, not just costs)
    if outcome.isolated_domain_controller:
        return -1000.0  # Catastrophic penalty, dominates everything
    
    if outcome.isolated_payment_system and not outcome.confirmed_compromise:
        return -500.0   # Very large penalty for unconfirmed FP on critical system
    
    if outcome.sla_violation_count > 0:
        sla_penalty = -5.0 * outcome.sla_violation_count * outcome.sla_penalty_usd / 1000
        
        # Cap total security reward by SLA penalty (prevents optimization over SLA)
        security_reward = min(security_reward, -sla_penalty + 1.0)
    
    # PROPORTIONALITY CONSTRAINT
    # High-impact action for low-confidence detection = penalty
    if ACTION_IMPACT[action] > 0.7 and outcome.was_false_positive:
        disproportionality_penalty = -3.0 * (ACTION_IMPACT[action] - 0.3)
        return security_reward + disproportionality_penalty
    
    return security_reward
```

**Constitutional constraints via Lagrangian relaxation:**

Rather than encoding constraints in the reward function (which can be hacked), use constrained RL with Lagrangian multipliers:

```
Objective: max_π E[Σ γᵗ R(s,a)]
Subject to: E[collateral_damage_per_episode] ≤ 2.0 users
            E[sla_violation_rate] ≤ 0.005
            P(critical_system_isolated_incorrectly) ≤ 0.001

Lagrangian: L = E[Σ γᵗ R(s,a)] 
              - λ₁ * max(0, E[collateral] - 2.0)
              - λ₂ * max(0, E[sla_rate] - 0.005)
              - λ₃ * max(0, P(critical_fP) - 0.001)

Update: π is updated to maximize L
        λ multipliers are updated to enforce constraints (dual ascent)
```

This guarantees the agent cannot violate the operational constraints even if doing so would improve security reward.

**Evaluation on safety scenarios:**

After every policy update, run the agent against a suite of "safety scenario" test cases that include:
- A domain controller that appears compromised but isn't
- A payment server with legitimate but unusual activity
- A hospital endpoint with life-critical functionality
- A network segment containing 1,000+ users

The agent must NOT isolate these systems with high confidence on flimsy evidence. If it does, the policy update is rejected. This safety testing is a hard gate, not a soft metric.

---

### Q5: Explain exactly how the Graph Neural Network (GNN) in your ACD system detects lateral movement, and why a standard feedforward neural network would fail at this task.

**Answer:**

**Why a feedforward network fails:**

A feedforward network takes a fixed-size feature vector and produces an output. For a cyber defense problem, you'd have to manually engineer graph features: "number of hops from entry point," "degree of destination node," etc. But manually engineered graph features:
1. Can't capture complex structural patterns (triangles, cycles, specific topological motifs)
2. Are fragile to graph size changes (new hosts = feature computation changes)
3. Don't capture the relative positions of nodes in the graph structure

A feedforward network also treats each prediction independently — it can't learn that "connecting to Host X is anomalous because it's structurally similar to hosts that were lateral movement targets in past attacks, not because of its individual attributes."

**How the GNN (specifically, a Graph Attention Network) works:**

**Message passing:** The GNN operates through multiple rounds of information aggregation across graph edges:

```
Round 1 (1-hop neighborhood):
  For each node v, aggregate information from its direct neighbors:
  h_v^(1) = AGGREGATE({h_u^(0) : u ∈ N(v)})  (N(v) = neighbors of v)
  
  Each node's representation now encodes: "what are my direct neighbors like?"
  
Round 2 (2-hop neighborhood):
  h_v^(2) = AGGREGATE({h_u^(1) : u ∈ N(v)})
  
  Each node's representation now encodes: "what are my neighbors' neighbors like?"
  This captures 2-hop structural patterns.
```

**Attention mechanism (why GAT is better than simple GCN):**

Not all neighbors are equally informative. In a cyber network, a connection to the domain controller is more informative about potential privilege escalation than a connection to a printer. GAT learns to weigh neighbors by relevance:

```
Attention weight: α_uv = softmax_u( LeakyReLU( a^T [W*h_v || W*h_u] ) )

Aggregation: h_v^(l) = σ( Σ_{u ∈ N(v)} α_uv * W^(l) * h_u^(l-1) )
```

The attention weights α_uv are learned — the GNN learns that "connections to high-criticality nodes deserve more attention weight." This is implicitly learning the security relevance of graph topology.

**What lateral movement looks like in the GNN's representation:**

A legitimate user (jdoe) connects to help desk systems, ticketing tools, a few servers relevant to their work. Their ego-graph (2-hop neighborhood) forms a tight cluster: all their connections are in the same organizational community, with high internal edge density.

A lateral movement pattern looks different in the GNN's feature space:
- Rapid new edge creation (jdoe now connects to nodes outside their community)
- New connections to high-centrality nodes (domain controller, databases)
- The ego-graph expands rapidly across community boundaries
- The new edges have low frequency (first-time or rare connections)

The GNN's message passing captures: "the structural pattern of jdoe's graph neighborhood looks increasingly like the graph neighborhood of entities we've seen during past lateral movement campaigns."

**Why this is more powerful than hand-crafted graph features:**

The GNN learns which structural patterns correlate with lateral movement from training data. It discovers patterns a human analyst might not enumerate: e.g., "when a user first connects to exactly 3 hosts that form a triangle in the graph within 1 hour, this is a strong lateral movement signal." This triangular motif pattern emerges from data rather than being manually specified.

---

### Q6: What is the explore-exploit dilemma in the ACD context, and how do you configure the agent to handle it safely when wrong exploration choices have real security consequences?

**Answer:**

**The fundamental tension:**

In standard RL exploration-exploitation, the agent sometimes tries suboptimal actions to learn whether they lead to better outcomes. In a video game, this means occasionally dying. In cyber defense, "exploration" might mean NOT isolating a host that the agent is slightly uncertain about — and the host turns out to be the attacker's staging point.

The cost of wrong exploration is a real security breach.

**Standard RL exploration mechanisms (and why they're dangerous in ACD):**

```
ε-greedy: With probability ε=0.1, take a random action
Problem: 10% of decisions are random → occasionally block legitimate traffic,
         occasionally fail to isolate an actively-compromised host
         This is a real operational and security risk in production

Entropy regularization: Encourage exploration by adding H(π) to the reward
Problem: Incentivizes the agent to maintain uncertainty — in security, uncertainty
         should always default to MORE defense, not to exploration
         
Thompson sampling: Sample from posterior distribution of policy parameters
Problem: Hard to implement correctly for deep RL, and still leads to
         suboptimal actions during high-stakes security events
```

**The ACD solution: Asymmetric exploration**

Exploration only happens in contexts where the consequences are bounded:

```python
class AsymmetricExplorer:
    """
    Exploration strategy that constrains the cost of exploration:
    - Explore only on LOW-impact actions (honeypot, monitor, rate-limit)
    - NEVER explore on HIGH-impact actions (isolation, permanent disable)
    - Exploration happens in low-threat contexts (anomaly_score < 0.5)
    - Zero exploration during active incidents (anomaly_score > 0.8)
    """
    
    def get_action(self, state: NetworkState, exploration_rate: float = 0.1) -> int:
        threat_level = state.max_entity_anomaly_score
        
        if threat_level > 0.80:
            # High threat: no exploration, use deterministic best action
            return self.policy.get_best_action(state)
        
        elif threat_level > 0.50:
            # Medium threat: very limited exploration, only within tier-1 actions
            if random.random() < 0.03:  # 3% exploration rate
                return random.choice(TIER_1_ACTIONS)  # Low-impact only
            return self.policy.get_best_action(state)
        
        else:
            # Low threat: moderate exploration, only within tier-1 and tier-2 actions
            if random.random() < exploration_rate:  # 10% exploration rate
                return random.choice(TIER_1_ACTIONS + TIER_2_ACTIONS)
            return self.policy.get_best_action(state)
```

**The safer alternative: Simulation-first exploration**

Rather than exploring in production, the ACD system explores extensively in simulation:

1. The simulation environment runs at 1,000× real-time speed
2. The agent tries thousands of different exploration strategies in simulation
3. Only the well-validated policy is deployed to production
4. Production receives only the deterministic best policy (no exploration in production)
5. New experiences from production (with real outcomes) are fed back to simulation for the next training iteration

This decouples exploration (simulation, safe) from exploitation (production, deterministic). The agent never "tries random things" in the real network — it only applies learned knowledge. The randomness stays in the training environment.

**What If:** "But what if the production environment has situations the simulation never encountered?"

This is addressed via the confidence threshold mechanism: when the agent encounters a state unlike anything in training (low confidence < 0.70 across all actions), it escalates to a human analyst rather than making a potentially wrong autonomous decision. Uncertainty is not exploration — it's a graceful fallback to human expertise.

---

### Q7: How do you validate that the RL agent is actually safer than a well-tuned rule-based system, and what metrics would you use for this comparison?

**Answer:**

This is the key evaluation question, and it requires careful experimental design. A naive comparison (RL vs rules on total incidents detected) is misleading.

**Evaluation framework:**

**1. Held-out simulation benchmark (CAGE Challenge scenarios)**

Both systems evaluated on identical attack scenarios from a held-out benchmark:

```
Metrics:
  Mean dwell time to detection (hours): lower is better
  Dwell time until containment (hours): lower is better
  Fraction of attacks where lateral movement was blocked before payment zone
  Fraction of attacks where exfiltration was prevented
  False positive rate on benign scenarios
  Collateral users disrupted per attack episode
  Mean time to full recovery (all containment actions reversed correctly)
```

The benchmark must include attack types the RL agent was NOT trained on (novel TTPs) — this tests generalization, not memorization.

**2. Red team exercise comparison**

Red team conducts identical attack scenarios against:
- Environment A: rule-based detection + human response
- Environment B: ACD with RL agent

Metrics measured:
```
Dwell time (T): RL target = ≤ 50% of rule-based baseline
Exfiltration rate: RL target = ≤ 20% of rule-based baseline  
FP rate: RL target = ≤ 150% of rule-based baseline (some FP increase acceptable for better TP)
Analyst time: RL target = ≤ 50% of rule-based (should reduce workload)
```

**3. Production shadow mode with labeled outcomes**

Both systems run against real production traffic (RL in shadow mode — observes but doesn't act):

After 4 weeks, a security analyst reviews a random sample of 200 events where the systems disagreed:
- RL agreed with rule-based, analyst confirms: both correct or both wrong
- RL recommended something rule-based didn't: analyst assesses correctness

**4. The killer metric: Precison-recall tradeoff across confidence thresholds**

Plot precision-recall curves for both systems by varying their decision thresholds. If the RL system's PR curve dominates the rule-based system's PR curve (sits above it everywhere), the RL system is unambiguously better. If curves cross: RL is better at one end of the tradeoff, rules are better at the other end — choose based on your organizational tolerance.

**5. The adversarial generalization test**

Subject both systems to attacks specifically designed to evade each:
- Attacks crafted to evade rule-based detection (novel TTPs, LOL techniques)
- Attacks crafted to evade the RL agent (policy probing, threshold gaming)

Measure: cross-evasion resistance
  - How well does the RL agent detect attacks designed to evade rules?
  - How well do the rules detect attacks designed to evade the RL agent?
  
A combined system should handle both classes of attacks.

**The honest caveat for this interview:** In practice, many organizations find that a well-tuned UEBA + rule-based system catches 85-90% of attacks, and the RL agent adds value only in the tail of novel, targeted attacks. The question becomes whether the cost (engineering complexity, training data, simulation environment) is justified by the incremental detection improvement. The answer is yes for high-value targets (financial services, critical infrastructure) but may not be for organizations with less sophisticated threat models.

---

*Document ends. Coverage: complete RL-based ACD system — MDP formulation, PPO policy network architecture, reward engineering with hard constraints, simulation training, action space design, multi-tier confidence thresholds, SOAR integration, evasion mechanics (policy probing, reward hacking, graph poisoning), circuit breakers, staleness safety systems, deception orchestration, comprehensive observability, and 7 deep technical interview questions with mathematical detail.*