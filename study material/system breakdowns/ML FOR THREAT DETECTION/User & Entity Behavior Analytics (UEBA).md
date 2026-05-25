# User & Entity Behavior Analytics (UEBA): Internal Engineering & Security Breakdown

> **Classification:** Internal Engineering / Security Document  
> **Audience:** Detection Engineers, Data Engineers, SOC Analysts, ML Engineers, Interview Candidates  
> **Scope:** Full-stack UEBA system — telemetry ingestion, feature engineering, ML inference, alerting, SOAR integration, evasion mechanics, and observability  
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

## What Is UEBA and Why Does It Exist

UEBA is a category of security analytics that builds statistical and behavioral baselines for every user and entity (hosts, service accounts, applications) in an environment, then flags deviations from those baselines as anomalies worth investigating.

The problem UEBA solves: signature-based detection (SIEM rules, IDS signatures) cannot detect threats it has never seen before, and cannot distinguish malicious behavior from legitimate behavior that superficially matches a rule. A user downloading 5GB of data may be a data exfiltration attempt or a legitimate developer pulling a large dataset. UEBA answers: "Is this consistent with how THIS specific user has behaved historically?"

The three threat categories UEBA is specifically designed to detect:
1. **Insider threats** — legitimate users abusing their access (disgruntled employees, compromised credentials)
2. **Compromised accounts** — attackers operating under stolen credentials who don't know the legitimate user's behavioral patterns
3. **Lateral movement** — attackers pivoting between systems in ways that deviate from normal entity-to-entity communication patterns

---

## 1. Threat Detection Narrative

### 1.1 The Attacker's Perspective

**Day 1 — Initial access**

Marcus, a threat actor working for a nation-state APT group, successfully phishes a credential from Alice Chen, a senior financial analyst at a Fortune 500 company. Alice's credentials: domain account `achen`, member of the Finance and Analytics AD groups, access to SharePoint, the data warehouse, and internal BI dashboards.

**What Marcus thinks:** He has valid credentials. He will log in and operate "as Alice." He believes his actions are indistinguishable from legitimate activity because he is using her real account.

**What Marcus does:**

```
Day 1, 02:13 AM:
  VPN login from IP 185.220.101.14 (Tor exit node, AS45102)
  Login to corporate SSO with Alice's credentials
  RDP into workstation WKSTN-FIN-042
  
Day 1, 02:15 AM - 03:40 AM:
  Browse internal SharePoint sites (reconnaissance)
  85 GET requests to SharePoint in 85 minutes
  (Alice normally generates 12-15 SharePoint requests per day)
  
Day 2, 01:58 AM:
  Login again from 185.220.101.91 (different Tor exit node)
  Begin querying the data warehouse
  Query 1: SELECT * FROM customer_data LIMIT 100
  Query 2: SELECT * FROM customer_data  (no LIMIT — full table)
  Data returned: 4.7GB
  
Day 2, 03:22 AM:
  Data staged in C:\Users\achen\AppData\Local\Temp\data_export_final.zip
  Upload to external file sharing service
```

**What Marcus believes at each step:**
- "2 AM logins look like an overtime worker"
- "SharePoint browsing is normal employee behavior"
- "Querying the data warehouse is Alice's job"
- "A large data export from a finance analyst isn't suspicious"

Marcus is wrong. Every one of these actions is profoundly anomalous when measured against Alice's behavioral baseline.

---

### 1.2 What the UEBA System Sees

**T=0: Day 1, 02:13 AM — VPN authentication event**

The UEBA system receives a Syslog event from the VPN concentrator within 800ms of the connection:

```json
{
  "event_type": "vpn_auth_success",
  "user": "achen",
  "src_ip": "185.220.101.14",
  "timestamp": "2024-01-15T02:13:47Z",
  "device_id": null,
  "auth_method": "password",
  "geo_country": "NL",
  "geo_city": "Amsterdam",
  "as_number": 45102,
  "as_name": "Tor Project"
}
```

**Feature computation (happens within 2 seconds of event receipt):**

```
User profile for achen (30-day baseline):
  typical_login_hours:         08:00 - 19:00 (business hours)
  typical_login_locations:     [US-CA, US-NY]
  typical_login_asns:          [7922 (Comcast), 15169 (Google Fi), 701 (AT&T)]
  avg_daily_vpn_logins:        1.2
  device_fingerprints_seen:    [macOS_device_A, iOS_device_B]

Anomaly scores for this event:
  time_anomaly:                0.97  (2 AM, 99th percentile for this user)
  geo_anomaly:                 0.99  (Netherlands, never seen for this user)
  asn_anomaly:                 1.00  (Tor exit node, never seen for ANY user in org)
  device_anomaly:              0.88  (unknown device fingerprint)
  auth_method_anomaly:         0.62  (password auth — MFA not triggered, unusual)
```

**T+2s: Risk score computed**

```
composite_risk_score = weighted_combination(time_anomaly, geo_anomaly, asn_anomaly, device_anomaly)
                     = 0.25*0.97 + 0.30*0.99 + 0.35*1.00 + 0.10*0.88
                     = 0.243 + 0.297 + 0.350 + 0.088
                     = 0.978

Alert threshold: 0.75 → TRIGGERED
Alert severity: HIGH
Reason codes: ["tor_exit_node", "off_hours_login", "new_geo", "unknown_device"]
```

**T+3s: SOAR playbook fires**

```
Action 1: Create alert ticket in ServiceNow (P2 — Security Incident)
Action 2: Push to SOC analyst queue
Action 3: Enrich with threat intelligence
  → IP 185.220.101.14 confirmed in threat intel feed as Tor exit node
  → IP has 12 previous abuse reports
Action 4: Send real-time notification to on-call analyst
Action 5: Flag achen's subsequent actions with elevated monitoring (monitoring_mode=HIGH)
```

**What the SOC analyst sees (T+5 minutes after event):**

```
[ALERT] HIGH SEVERITY — Anomalous Login: achen
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Risk Score: 97.8/100
User: Alice Chen (achen) | Finance Analyst | 6yr tenure
Time: 2024-01-15 02:13 AM UTC (3 hours outside normal window)
Source IP: 185.220.101.14
  → Tor Exit Node (confirmed)
  → Geo: Netherlands (user's first Netherlands login in 6 years)
  → ASN: AS45102 (never seen in org)
Device: Unknown (not in Alice's registered device list)
Auth: Password only (MFA was not challenged — policy gap)

Baseline context:
  Last 30 logins: All from California or New York
  Typical hours: 8 AM - 7 PM Pacific
  Normal ASNs: Comcast, AT&T, Google Fi

Recommended actions:
  [1] Terminate active session immediately
  [2] Force MFA re-enrollment
  [3] Contact Alice via phone to verify
  [4] Review all activity from this session
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

**T+10 minutes: Analyst investigates, calls Alice**

Alice is asleep. She did not initiate a VPN session. Incident confirmed. Session terminated. Marcus's access is cut off. He achieved only reconnaissance (SharePoint browsing) before detection.

**Day 2 attempt:** Marcus comes back with a different IP. The UEBA system correlates:
- New IP (185.220.101.91), different ASN, same Tor fingerprint characteristics
- Same user account being accessed from Tor again (policy: 0 tolerance for Tor logins after prior incident flag)
- Session terminated automatically (SOAR playbook auto-response: block and notify)
- Marcus never reaches the data warehouse.

**The gap between what Marcus thought and what happened:**

| Marcus's Assumption | Reality |
|---------------------|---------|
| "2 AM looks like overtime" | Specific user's 99th percentile login time triggers time anomaly = 0.97 |
| "I'm using a valid credential" | Credential authenticity ≠ behavioral authenticity |
| "Netherlands is just VPN" | UEBA doesn't see "Netherlands" — it sees "first-ever login from this country for this specific user" |
| "SharePoint browsing is normal" | 85 requests/hour vs. baseline 12-15/day triggers access velocity anomaly |
| "Tor is anonymous" | Tor ASN is explicitly tracked; first-ever Tor login for ANY user → maximum anomaly |

---

## 2. Telemetry & Ingestion Flow

### 2.1 Telemetry Sources

A production UEBA system ingests from dozens of sources. Each has distinct formats, delivery mechanisms, latency, and reliability characteristics:

```
IDENTITY & ACCESS MANAGEMENT:
  - Active Directory / LDAP: user logins, group changes, password resets
  - Azure AD / Okta: SSO events, MFA challenges, application access
  - PAM (CyberArk/BeyondTrust): privileged session recordings, vault access
  
NETWORK:
  - VPN concentrators: authentication, session duration, bytes transferred
  - Firewall logs (Palo Alto, Fortinet): allow/deny, src/dst IP, port, bytes
  - DNS: queries per host, NX domain rates, unusual TLDs, query frequency
  - NetFlow/IPFIX: flow records (src, dst, port, protocol, bytes, packets, duration)
  - Web proxy: URLs visited, categories, MIME types, upload/download volumes
  
ENDPOINT:
  - EDR (CrowdStrike, SentinelOne): process creation, file operations, network connections
  - Windows Event Logs (4624, 4625, 4648, 4688, 4698, 4732...): auth, process, service
  - Linux auditd: syscalls, file access, network, privilege escalation
  - macOS Unified Log: process activity, network, file system
  
APPLICATION:
  - Web application logs (Apache, nginx, Cloudflare): HTTP method, URI, status, user, size
  - Database query logs (PostgreSQL, Oracle, MSSQL): queries, tables, result rows, duration
  - SaaS APIs (Salesforce, GitHub, Jira): API calls, exported data, config changes
  - Email gateway: sender, recipient, attachment types, external domains
  
CLOUD:
  - AWS CloudTrail: API calls, assumed roles, policy changes, S3 access
  - Azure Activity Log: resource operations, role assignments
  - GCP Audit Logs: IAM changes, data access, admin activity
```

### 2.2 Ingestion Architecture

```
┌────────────────────────────────────────────────────────────────────────────────────┐
│  TELEMETRY PRODUCERS                                                               │
│                                                                                    │
│  [AD/LDAP] [VPN] [Firewall] [EDR] [DB Logs] [Web Proxy] [CloudTrail] [SaaS]      │
│     │          │       │        │        │          │           │         │        │
└─────┼──────────┼───────┼────────┼────────┼──────────┼───────────┼─────────┼────────┘
      │          │       │        │        │          │           │         │
      │ syslog/  │ HTTPS │ syslog │ API    │ JDBC/    │ Squid log │ HTTPS   │ REST
      │ WEC      │       │        │ push   │ syslog   │           │ API     │ webhook
      ▼          ▼       ▼        ▼        ▼          ▼           ▼         ▼
┌────────────────────────────────────────────────────────────────────────────────────┐
│  COLLECTION LAYER                                                                  │
│                                                                                    │
│  ┌──────────────────────────────────────────────────────────────────────────────┐ │
│  │  Fluentd / Logstash agents (per network segment)                            │ │
│  │  • Parse raw syslog, CEF, LEEF, JSON formats                               │ │
│  │  • Apply field extraction (Grok patterns for syslog, jq for JSON)          │ │
│  │  • Add collection metadata: received_at, collector_id, source_type         │ │
│  │  • Buffer to disk (if Kafka backpressure): 500MB ring buffer               │ │
│  └──────────────────────────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────┬───────────────────────────────────────┘
                                             │ compressed batch (LZ4)
                                             │ over TLS 1.3
                                             ▼
┌────────────────────────────────────────────────────────────────────────────────────┐
│  TRANSPORT LAYER: Apache Kafka Cluster                                             │
│                                                                                    │
│  Topics (partitioned by entity hash):                                             │
│  ┌──────────────────────────────────────────────────────────────────────────────┐ │
│  │  ueba.raw.auth          (32 partitions, 7d retention, ~500K events/min)     │ │
│  │  ueba.raw.network       (64 partitions, 3d retention, ~2M events/min)      │ │
│  │  ueba.raw.endpoint      (48 partitions, 7d retention, ~1M events/min)      │ │
│  │  ueba.raw.application   (32 partitions, 7d retention, ~300K events/min)    │ │
│  │  ueba.raw.cloud         (16 partitions, 14d retention, ~100K events/min)   │ │
│  │                                                                             │ │
│  │  ueba.normalized        (128 partitions, 30d retention — ALL normalized)   │ │
│  │  ueba.features          (64 partitions, 7d retention — computed features)  │ │
│  │  ueba.scores            (32 partitions, 30d retention — ML scores)         │ │
│  │  ueba.alerts            (16 partitions, 90d retention — fired alerts)      │ │
│  └──────────────────────────────────────────────────────────────────────────────┘ │
│                                                                                    │
│  Kafka config:                                                                     │
│  replication.factor=3, min.insync.replicas=2, acks=all                            │
│  compression.type=lz4, batch.size=65536, linger.ms=10                            │
└────────────────────────────────────────────┬───────────────────────────────────────┘
                                             │
                    ┌────────────────────────┼─────────────────────┐
                    │                        │                      │
                    ▼                        ▼                      ▼
┌───────────────────────────┐  ┌─────────────────────┐  ┌──────────────────────────┐
│  NORMALIZATION LAYER      │  │  STREAM PROCESSING  │  │  RAW STORAGE             │
│                           │  │  (Apache Flink)     │  │                          │
│  Schema normalization     │  │  • Windowed aggs    │  │  Elasticsearch (30d hot) │
│  Field mapping to UES     │  │  • Join streams     │  │  S3 Parquet (1yr cold)  │
│  (Common Schema)          │  │  • Stateful compute │  │  Athena for ad-hoc query │
│  Timestamp deduplication  │  │  • Feature compute  │  │  Immutable audit chain   │
└───────────────────────────┘  └─────────────────────┘  └──────────────────────────┘
```

### 2.3 Log Parsing and Normalization

**The problem:** Every telemetry source has its own format. A Windows login event looks completely different from a Cisco VPN auth event:

```
Windows Security Event 4624 (raw):
Security,2024-01-15 02:13:47,Microsoft-Windows-Security-Auditing,4624,
An account was successfully logged on.
Subject: Security ID: SYSTEM, Account Name: WKSTN-FIN-042$
Logon Information: Logon Type: 3, Impersonation Level: Impersonation
New Logon: Security ID: CORP\achen, Account Name: achen, Account Domain: CORP
Network Information: Workstation Name: ATTACKER-PC, Source Network Address: 185.220.101.14

Cisco ASA VPN (raw):
Jan 15 02:13:45 vpn-gw-01 %ASA-6-113019: Group=SplitTunnelVPN, Username=achen, 
IP=185.220.101.14, Session disconnected. Session Type: WebVPN, Duration: 0h:00m:02s,
Bytes xmt: 1024, Bytes rcv: 2048, Reason: User Requested
```

**After normalization to a Common Schema (UES — Unified Event Schema):**

```json
{
  "event_id": "uuid-8f3a1b2c",
  "event_category": "authentication",
  "event_action": "login_success",
  "timestamp": "2024-01-15T02:13:47.000Z",
  "received_at": "2024-01-15T02:13:48.123Z",
  "ingest_latency_ms": 1123,
  
  "actor": {
    "type": "user",
    "id": "achen",
    "display_name": "Alice Chen",
    "domain": "CORP",
    "department": "Finance",
    "manager": "jsmith",
    "ad_groups": ["Finance", "Analytics", "VPN-Users"]
  },
  
  "target": {
    "type": "system",
    "id": "WKSTN-FIN-042",
    "hostname": "WKSTN-FIN-042.corp.example.com",
    "ip": "10.0.5.42",
    "os": "Windows 10"
  },
  
  "network": {
    "src_ip": "185.220.101.14",
    "src_port": 55234,
    "dst_ip": "10.0.1.5",
    "dst_port": 443,
    "protocol": "TCP",
    "bytes_in": 2048,
    "bytes_out": 1024
  },
  
  "geo": {
    "country": "NL",
    "city": "Amsterdam",
    "latitude": 52.3676,
    "longitude": 4.9041,
    "asn": 45102,
    "asn_name": "Tor Project",
    "is_vpn": false,
    "is_tor": true,
    "is_datacenter": false
  },
  
  "auth": {
    "method": "password",
    "mfa_used": false,
    "logon_type": "network",
    "failure_reason": null
  },
  
  "source": {
    "system": "windows_security_log",
    "collector": "fluentd-dc01",
    "raw_event_id": "4624"
  },
  
  "tags": ["off_hours", "tor_exit_node", "no_mfa", "new_source_ip"]
}
```

**Normalization mechanics:**

```python
class EventNormalizer:
    """
    Transforms source-specific formats into the UES Common Schema.
    Each source has a dedicated parser with field mapping rules.
    """
    
    PARSERS = {
        "windows_security": WindowsSecurityParser(),
        "cisco_asa": CiscoASAParser(),
        "crowdstrike_edr": CrowdStrikeParser(),
        "cloudtrail": CloudTrailParser(),
        # ... 40+ more parsers
    }
    
    def normalize(self, raw_event: dict, source_type: str) -> UESEvent:
        parser = self.PARSERS.get(source_type)
        if not parser:
            raise UnknownSourceError(f"No parser for source: {source_type}")
        
        # Step 1: Parse source-specific fields
        parsed = parser.parse(raw_event)
        
        # Step 2: Enrich with entity resolution
        actor_id = self.entity_resolver.resolve(parsed.actor_raw)
        # Maps "CORP\\achen", "achen@corp.example.com", "alice.chen" → canonical "achen"
        
        # Step 3: GeoIP enrichment
        geo = self.geoip.lookup(parsed.src_ip)  # MaxMind GeoIP2 + Tor exit list
        
        # Step 4: Timestamp normalization (all to UTC)
        ts = self.timestamp_parser.to_utc(parsed.timestamp, source_tz=parser.source_tz)
        
        # Step 5: Tag enrichment
        tags = self.tagger.compute_tags(parsed, geo)
        
        # Step 6: Map to UES fields
        return UESEvent(
            event_id=str(uuid4()),
            actor=actor_id,
            timestamp=ts,
            geo=geo,
            tags=tags,
            **self._map_fields(parsed, parser.field_mapping)
        )
```

### 2.4 Where Latency and Dropped Events Occur

```
Failure Point 1: Collection agents
  Problem: Agent buffer fills when network/Kafka is slow
  Ring buffer: 500MB (covers ~15min of normal load)
  If Kafka is down > 15min: events start dropping
  Detection: agent_buffer_utilization_pct metric
  Mitigation: disk-backed spill buffer (up to 5GB), retry with backoff

Failure Point 2: Kafka partition rebalance
  When a broker fails, leader election takes 10-30 seconds
  During rebalance: producer writes back up, consumer reads stall
  Impact: 30-second gap in telemetry (queries may miss events in this window)
  Detection: kafka_consumer_lag metric, partition_leader_election_rate
  Mitigation: increase replica count, pre-configure ISR to 2-of-3

Failure Point 3: Timestamp skew
  Source systems can have clocks out of sync by minutes or hours
  Example: a remote site's syslog shows events 2 hours "in the past"
  Impact: windowed feature computation misses events (they land in wrong window)
  Detection: compare event.timestamp to received_at; alert if delta > 5 minutes
  Mitigation: NTP enforcement on all log sources; use received_at as fallback for
              windowed computations when skew > threshold

Failure Point 4: GeoIP enrichment latency
  MaxMind database lookup: < 1ms (in-memory)
  RDAP/WHOIS lookup (for ASN details): 50-500ms (external call)
  If WHOIS is slow: events queue up in normalization pipeline
  Mitigation: cache ASN data aggressively (TTL=24h, LRU cache)

Failure Point 5: Entity resolution collision
  "jsmith" might be John Smith (Finance) OR Jane Smith (Engineering)
  Incorrect entity resolution → features computed on wrong user baseline
  Impact: false negatives (anomaly masked by wrong profile) or FPs (wrong baseline)
  Detection: entity_resolution_confidence_score < 0.7 → flag for manual review
  Mitigation: HR system as authoritative source (username + employee_id), not name
```

---

## 3. Feature Engineering Pipeline

### 3.1 The Feature Taxonomy

Raw events are useless for ML. A single login event tells you almost nothing. What matters is the **pattern of events over time, relative to a baseline**. Features in UEBA fall into four categories:

```
TYPE 1: TEMPORAL FEATURES (time-based patterns)
  When does this user typically do things?
  Examples:
    hour_of_day_sin/cos (cyclic encoding of hour)
    days_since_last_login
    login_count_last_1h, login_count_last_24h
    is_weekend
    time_deviation_from_median (how far from this user's median login time)

TYPE 2: MAGNITUDE FEATURES (how much?)
  How much data, how many events, how long?
  Examples:
    bytes_transferred_last_1h, bytes_transferred_last_24h
    query_result_rows_last_1h
    distinct_files_accessed_last_24h
    distinct_hosts_accessed_last_24h (lateral movement signal)
    
TYPE 3: IDENTITY/GEOGRAPHY FEATURES (from where, as whom?)
  Where is the user connecting from? Is the device known?
  Examples:
    is_new_source_ip (never seen for this user in 90 days)
    is_new_country (never seen for this user)
    is_tor_exit_node
    is_datacenter_ip
    device_trust_score (0=unknown, 1=managed, 0.5=registered personal)
    distance_km_from_last_login (impossible travel detection)
    
TYPE 4: GRAPH/RELATIONSHIP FEATURES (who talks to what?)
  What entities is this user/host connecting to?
  Examples:
    new_peer_hosts_accessed (hosts never accessed before)
    peer_host_risk_score (average risk score of hosts accessed)
    lateral_movement_score (graph distance from entry point)
    shared_resource_access_breadth (how many distinct shared resources accessed)
```

### 3.2 Stateful vs. Stateless Feature Extraction

**Stateless features** can be computed from a single event with no memory of past events:

```python
def extract_stateless_features(event: UESEvent) -> dict:
    """
    These features require only the current event — no historical state.
    Can be computed in a pure Flink stateless map() operation.
    """
    return {
        # Temporal
        'hour_sin': math.sin(2 * math.pi * event.timestamp.hour / 24),
        'hour_cos': math.cos(2 * math.pi * event.timestamp.hour / 24),
        'is_weekend': event.timestamp.weekday() >= 5,
        
        # Geographic
        'is_tor': event.geo.is_tor,
        'is_datacenter': event.geo.is_datacenter,
        'is_new_country': event.geo.country not in USER_COUNTRY_CACHE[event.actor],
        # (country cache is a broadcast variable — refreshed hourly, not stateful stream)
        
        # Identity
        'auth_method_encoded': AUTH_METHOD_ENCODING[event.auth.method],
        'mfa_used': int(event.auth.mfa_used),
        'logon_type_risk': LOGON_TYPE_RISK[event.auth.logon_type],
    }
```

**Stateful features** require memory of past events and are much more complex:

```python
class StatefulFeatureExtractor:
    """
    Maintains per-user state across events.
    Implemented as a Flink Keyed Process Function (keyed by user_id).
    State stored in RocksDB (Flink's embedded state backend).
    """
    
    def __init__(self):
        # Flink state descriptors
        # State is automatically checkpointed every 60 seconds
        self.login_times_state = ListState(dtype=float, ttl=90*24*3600)    # 90 days
        self.source_ips_state = SetState(dtype=str, ttl=90*24*3600)        # 90 days
        self.accessed_hosts_state = SetState(dtype=str, ttl=30*24*3600)    # 30 days
        self.bytes_per_hour_state = MapState(key_type=int, val_type=float)  # last 24 buckets
        
    def process_event(self, event: UESEvent) -> dict:
        """
        Called for every event for a specific user (due to keying by actor.id).
        Returns dictionary of stateful features.
        """
        user_id = event.actor.id
        
        # === LOGIN TIME ANALYSIS ===
        login_times = self.login_times_state.get()  # All login timestamps for this user
        current_hour = event.timestamp.hour + event.timestamp.minute / 60.0
        
        if len(login_times) >= 30:  # Enough data for baseline
            login_hours = [datetime.fromtimestamp(t).hour for t in login_times]
            median_hour = np.median(login_hours)
            std_hour = np.std(login_hours)
            time_deviation = abs(current_hour - median_hour)
            if time_deviation > 12:  # Handle midnight wraparound
                time_deviation = 24 - time_deviation
            time_anomaly_score = min(1.0, time_deviation / (3 * std_hour + 0.01))
        else:
            time_anomaly_score = 0.5  # Neutral score when insufficient baseline
        
        # Update state
        self.login_times_state.add(event.timestamp.timestamp())
        
        # === IP NOVELTY ANALYSIS ===
        seen_ips = self.source_ips_state.get()
        is_new_ip = event.network.src_ip not in seen_ips
        ip_novelty_score = 1.0 if is_new_ip else 0.0
        self.source_ips_state.add(event.network.src_ip)
        
        # === ACCESS VELOCITY (sliding window counts) ===
        now_bucket = int(event.timestamp.timestamp() // 3600)  # Hour bucket
        
        # Count events in last 1h, 4h, 24h
        bytes_by_hour = self.bytes_per_hour_state.get()
        bytes_last_1h = bytes_by_hour.get(now_bucket, 0)
        bytes_last_24h = sum(bytes_by_hour.get(now_bucket - i, 0) for i in range(24))
        
        # Update byte counter
        self.bytes_per_hour_state.put(
            now_bucket,
            bytes_by_hour.get(now_bucket, 0) + event.network.bytes_out
        )
        # Evict old buckets (> 25h old)
        for old_bucket in list(bytes_by_hour.keys()):
            if old_bucket < now_bucket - 25:
                self.bytes_per_hour_state.remove(old_bucket)
        
        # === IMPOSSIBLE TRAVEL DETECTION ===
        # Get last seen location, compute distance, compare to time delta
        last_login = self.get_last_login()
        if last_login:
            distance_km = haversine(
                (last_login.geo.latitude, last_login.geo.longitude),
                (event.geo.latitude, event.geo.longitude)
            )
            time_delta_hours = (event.timestamp - last_login.timestamp).seconds / 3600
            max_possible_speed_kmh = 900  # Commercial aircraft
            impossible_travel = distance_km > (max_possible_speed_kmh * time_delta_hours)
        else:
            impossible_travel = False
        
        return {
            'time_anomaly_score': time_anomaly_score,
            'ip_novelty_score': ip_novelty_score,
            'bytes_transferred_last_1h': bytes_last_1h,
            'bytes_transferred_last_24h': bytes_last_24h,
            'impossible_travel': int(impossible_travel),
            'distinct_ips_last_30d': len(seen_ips),
        }
```

### 3.3 Sliding Window Implementations

**Tumbling windows vs. sliding windows — the UEBA choice:**

```
Tumbling window (non-overlapping, fixed size):
  [00:00-01:00] [01:00-02:00] [02:00-03:00]
  
  Problem: An event at 01:59 and 02:01 are in different windows.
  The rate between them is not captured by a single window count.
  
Sliding window (overlapping):
  Every minute, compute the count for the last 60 minutes.
  Window at 02:13 covers [01:13-02:13]
  Window at 02:14 covers [01:14-02:14]
  
  Problem: Computationally expensive (must recompute for every event)
  
UEBA solution: Approximate sliding window using time-bucketed counters
  Divide time into 5-minute buckets
  Maintain counts in each bucket (Ring buffer of 12 buckets = 1 hour)
  Sliding count = sum of all 12 buckets
  Error: up to 1 bucket period (5 min) of error
  This is acceptable for UEBA (5-min granularity is fine for behavior analysis)

Implementation (Redis):
  Key: "user:achen:auth_count:bucket:20240115_0210"  (bucket = 5-min interval)
  INCR by 1 on each auth event
  EXPIRE 3600  (1 hour TTL for 1-hour sliding window)
  
  To get 1-hour count:
    buckets = [0200, 0205, 0210, 0215, 0220, ..., 0255]  (12 buckets)
    total = sum(MGET all 12 bucket keys)
    
  Computation: 1 MGET (12 keys) = ~0.5ms in Redis
```

### 3.4 Graph Feature Extraction (Entity Graph)

Graph features capture lateral movement and access relationship anomalies:

```python
class EntityGraphFeatureExtractor:
    """
    Maintains a bipartite graph of (user/host → resources accessed)
    and (host → host communication patterns).
    
    Graph backend: Redis for hot graph (last 7 days)
                   Neo4j for deep graph queries (30 days)
    """
    
    def update_and_score(self, event: UESEvent) -> dict:
        src = event.actor.id  # e.g., "achen"
        dst = event.target.id  # e.g., "DB-FINANCE-01"
        edge_key = f"graph:edge:{src}:{dst}"
        
        # Check if this is a new edge (user → resource never seen before)
        is_new_edge = not self.redis.exists(edge_key)
        
        if is_new_edge:
            # New edge: compute peer comparison
            # "How many other users in Alice's peer group also access this resource?"
            peer_group = self.get_peer_group(src)  # e.g., all Finance users
            peer_access_count = self._count_peer_accesses(peer_group, dst)
            peer_access_ratio = peer_access_count / len(peer_group)
            # If 80% of Finance users access DB-FINANCE-01: new edge, but low anomaly
            # If 0% of Finance users access DB-ADMIN-01: new edge, HIGH anomaly
            edge_anomaly_score = 1.0 - peer_access_ratio
        else:
            edge_anomaly_score = 0.0
            
        # Update graph
        self.redis.set(edge_key, int(time.time()), ex=7*24*3600)
        
        # Count distinct new targets in last 1 hour (lateral movement)
        new_targets_1h = self._count_new_targets_window(src, window_hours=1)
        new_targets_24h = self._count_new_targets_window(src, window_hours=24)
        
        # Shortest path from known entry point (if compromise suspected)
        # "How many hops is this host from the VPN concentrator?"
        path_length = self._graph_distance(src, "VPN-GATEWAY-01")
        
        return {
            'new_edge_anomaly': edge_anomaly_score,
            'new_targets_1h': new_targets_1h,
            'new_targets_24h': new_targets_24h,
            'graph_distance_from_entry': path_length,
            'peer_access_ratio': peer_access_ratio if is_new_edge else None
        }
```

### 3.5 Sequence Embeddings for Behavioral DNA

For sophisticated behavioral modeling, event sequences are transformed into dense embeddings. The sequence of event types a user generates represents their behavioral "fingerprint":

```
Alice's typical daily event sequence:
  [vpn_login, web_proxy, email, sharepoint_read, db_query(small), 
   db_query(small), web_proxy, email, vpn_logout]

Attacker's sequence (using Alice's credential):
  [vpn_login, sharepoint_read, sharepoint_read, sharepoint_read,
   sharepoint_read, db_query(large), file_download, file_upload_external]

Step 1: Event type vocabulary (128 distinct event types)
  Each event type mapped to a one-hot vector of dimension 128

Step 2: Sequence encoding using Event2Vec (Word2Vec on event sequences)
  Train: collect all user event sequences over 90 days
  Model: Skip-gram, window=5, embedding_dim=64
  Result: each event type has a 64-dimensional embedding vector
  Events that tend to co-occur (like "db_query" and "file_download") are close in embedding space

Step 3: Session embedding using LSTM
  Input: sequence of Event2Vec embeddings for a user session
  LSTM hidden_dim=128, 2 layers
  Output: 128-dimensional session embedding vector

Step 4: Anomaly scoring using baseline sessions
  Collect Alice's last 90 days of session embeddings → create a convex hull
  or use a Gaussian mixture model on her session embeddings
  Score new session: P(session_embedding | Alice's GMM)
  Low probability → this session is unlike Alice's historical sessions
```

---

## 4. Inference Engine Architecture

### 4.1 The Multi-Model Ensemble

UEBA does not use one model. It uses an ensemble of models, each specialized for a specific threat category:

```
Model 1: Isolation Forest (per-user)
  Input: 47 features per event
  Purpose: Point anomaly detection (single event is unusual)
  Latency: < 2ms per inference
  Retrain: weekly (on each user's last 90 days of events)

Model 2: LSTM Autoencoder (per-user)
  Input: Sequence of 20 events (sliding window)
  Purpose: Sequence anomaly detection (unusual pattern of events)
  Latency: 15-30ms per inference (GPU-accelerated)
  Retrain: weekly

Model 3: Graph Neural Network (global — all entities)
  Input: Entity graph (user → resource edges, host → host edges)
  Purpose: Lateral movement detection (unusual access graph patterns)
  Latency: 100-500ms (graph traversal + GNN inference)
  Retrain: daily

Model 4: Peer Group Comparison (statistical baseline)
  Input: User's behavior metrics vs peer group metrics
  Purpose: Insider threat (user accessing more than peers, doing unusual things for their role)
  Latency: < 5ms (Redis lookup of precomputed peer stats)
  Retrain: continuous (rolling 30-day window)

Model 5: Time Series Anomaly (Prophet-based)
  Input: Per-user hourly event counts (30 days of history)
  Purpose: Unusual activity volume patterns (e.g., 3AM spike, weekend activity)
  Latency: < 5ms (precomputed forecast, compare to actuals)
  Retrain: daily (Prophet model retrained per user)
```

### 4.2 Isolation Forest — Deep Mechanics

**Training phase (offline, per-user, weekly):**

```python
from sklearn.ensemble import IsolationForest
import joblib

class UserIsolationForest:
    """
    One Isolation Forest per user, trained on their last 90 days of events.
    """
    
    def train(self, user_id: str, feature_matrix: np.ndarray):
        """
        feature_matrix: shape (n_events, 47)
        n_events: typically 2000-50000 events per user per 90 days
        """
        self.model = IsolationForest(
            n_estimators=200,    # 200 trees (more = better but slower)
            max_samples=256,     # Each tree uses 256 random samples
                                 # This is the key: anomalies are isolated in
                                 # fewer splits because they're in sparse regions
            contamination=0.01,  # Assume 1% of training data is anomalous
                                 # (benign anomalies: vacations, oncall shifts)
            random_state=42,
            n_jobs=-1            # Parallel tree building
        )
        self.model.fit(feature_matrix)
        
        # Calibrate scores to [0, 1] range
        # Raw IF score: -1 to 1 (negative = anomalous, positive = normal)
        train_scores = self.model.score_samples(feature_matrix)
        self.score_min = train_scores.min()
        self.score_max = train_scores.max()
    
    def score(self, feature_vector: np.ndarray) -> float:
        """
        Returns anomaly score in [0, 1] where 1 = most anomalous.
        """
        raw_score = self.model.score_samples(feature_vector.reshape(1, -1))[0]
        # Normalize: raw_score is negative for anomalies, positive for normal
        # Flip and normalize to [0, 1]
        normalized = (raw_score - self.score_min) / (self.score_max - self.score_min)
        return float(1.0 - normalized)  # Higher score = more anomalous
    
    def explain(self, feature_vector: np.ndarray, feature_names: list) -> dict:
        """
        Approximate feature importance for this anomaly score.
        Not exact SHAP (too slow), but a useful approximation.
        Uses mean depth per feature across all trees.
        """
        importances = {}
        for i, feat_name in enumerate(feature_names):
            # Perturb feature i, measure score change
            perturbed = feature_vector.copy()
            perturbed[i] = self.feature_means[i]  # Replace with mean (neutral)
            score_without = self.score(perturbed)
            score_with = self.score(feature_vector)
            importances[feat_name] = score_with - score_without
        
        return dict(sorted(importances.items(), key=lambda x: abs(x[1]), reverse=True)[:10])
```

**Why Isolation Forest works well for UEBA:**

Unlike KNN or density estimation (which require storing all training points), IF only stores 200 trees of ~log2(256) ≈ 8 nodes each. Memory per user: 200 trees × 256 nodes × few bytes = ~400KB. With 100,000 users: 40GB total — manageable.

IF is also robust to the "curse of dimensionality" in a way that distance-based methods are not. In high dimensions, all points become equidistant (distance concentration). IF avoids this by measuring isolation depth rather than distance.

### 4.3 LSTM Autoencoder — Sequence Anomaly Detection

```python
import torch
import torch.nn as nn

class SessionLSTMAutoencoder(nn.Module):
    """
    Encodes a session (sequence of events) into a latent vector,
    then decodes back to the original sequence.
    High reconstruction error = anomalous session.
    """
    
    def __init__(self, event_embedding_dim=64, hidden_dim=128, latent_dim=32, sequence_len=20):
        super().__init__()
        
        # Encoder: sequence → latent
        self.encoder_lstm = nn.LSTM(
            input_size=event_embedding_dim,
            hidden_size=hidden_dim,
            num_layers=2,
            batch_first=True,
            dropout=0.2
        )
        self.encoder_fc = nn.Linear(hidden_dim, latent_dim)
        
        # Decoder: latent → sequence reconstruction
        self.decoder_fc = nn.Linear(latent_dim, hidden_dim)
        self.decoder_lstm = nn.LSTM(
            input_size=hidden_dim,
            hidden_size=hidden_dim,
            num_layers=2,
            batch_first=True,
            dropout=0.2
        )
        self.output_fc = nn.Linear(hidden_dim, event_embedding_dim)
        
        self.sequence_len = sequence_len
    
    def forward(self, x):
        # x shape: (batch, sequence_len, event_embedding_dim)
        
        # Encode
        _, (h_n, _) = self.encoder_lstm(x)
        # h_n shape: (num_layers, batch, hidden_dim)
        latent = self.encoder_fc(h_n[-1])  # Take last layer's hidden state
        # latent shape: (batch, latent_dim)
        
        # Decode
        decoder_input = self.decoder_fc(latent).unsqueeze(1).repeat(1, self.sequence_len, 1)
        decoded, _ = self.decoder_lstm(decoder_input)
        reconstruction = self.output_fc(decoded)
        
        return reconstruction, latent
    
    def anomaly_score(self, x):
        """
        Compute per-session anomaly score from reconstruction error.
        """
        reconstruction, _ = self.forward(x)
        mse = nn.MSELoss(reduction='none')(reconstruction, x)
        # Per-event reconstruction error, then mean over sequence
        return mse.mean(dim=-1).mean(dim=-1)  # Shape: (batch,)
```

**Training:** The LSTM autoencoder is trained on Alice's last 90 days of sessions (batches of 20 sequential events). It learns to reconstruct normal sessions with low MSE. At inference time, an attacker's session (different event sequence) has high reconstruction error — the model can't compress it well because it's outside the distribution it learned.

### 4.4 Micro-Batching vs. Streaming Inference

**Streaming inference (for real-time alerts):**

```
Trigger: each authentication event → immediate Isolation Forest inference
Latency target: < 5ms from event receipt to score output
Implementation:
  Flink stateful stream processor
  On each keyed event:
    1. Extract stateless features (0.1ms)
    2. Load user's stateful state from RocksDB (0.5ms)
    3. Compute stateful features (1ms)
    4. Run Isolation Forest scoring (1.5ms)
    5. Write score to ueba.scores topic (0.3ms)
  Total: ~3.5ms wall time

Limitation: LSTM autoencoder and GNN cannot run in pure streaming
  (need sequence context / graph traversal)
  Solution: Run these on a delayed micro-batch
```

**Micro-batching for sequence models (every 60 seconds):**

```
Every 60 seconds:
  1. Flink collects all events from last 60 seconds per user
  2. For each user with ≥ 5 new events:
     a. Retrieve last 20 events (including new ones) from state
     b. Build event sequence embeddings
     c. Run LSTM autoencoder
     d. If score > threshold: emit to ueba.scores
  
Latency: up to 60 seconds of delay for LSTM-based detection
Tradeoff: Acceptable for sequence detection (sequences need context)
          Not acceptable for real-time auth blocking (use IF scores for that)
```

**Redis caching for fast lookups:**

```python
class FeatureCacheLayer:
    """
    Redis cache for frequently-accessed user profiles and precomputed features.
    Avoids database roundtrips during hot-path inference.
    """
    
    def get_user_profile(self, user_id: str) -> UserProfile:
        cache_key = f"ueba:profile:{user_id}"
        cached = self.redis.get(cache_key)
        
        if cached:
            return UserProfile.from_json(cached)
        
        # Cache miss: load from PostgreSQL
        profile = self.db.load_profile(user_id)
        self.redis.set(cache_key, profile.to_json(), ex=3600)  # 1-hour TTL
        return profile
    
    def get_peer_group_stats(self, department: str, role: str) -> PeerStats:
        cache_key = f"ueba:peers:{department}:{role}"
        cached = self.redis.get(cache_key)
        
        if cached:
            return PeerStats.from_json(cached)
        
        # Expensive: aggregate all users in this peer group
        stats = self.db.compute_peer_group_stats(department, role)
        # Cache for 1 hour (peer stats are stable)
        self.redis.set(cache_key, stats.to_json(), ex=3600)
        return stats
    
    def get_threat_intel(self, ip: str) -> ThreatIntelResult:
        cache_key = f"ueba:ti:{ip}"
        cached = self.redis.get(cache_key)
        
        if cached:
            return ThreatIntelResult.from_json(cached)
        
        # Query threat intelligence platform
        result = self.threat_intel_api.lookup(ip)
        # Cache for 4 hours (threat intel changes slowly)
        self.redis.set(cache_key, result.to_json(), ex=4*3600)
        return result
```

---

## 5. Correlation & Alerting Flow

### 5.1 From Raw ML Score to Actionable Alert

A single ML score of 0.89 is meaningless to a SOC analyst. The correlation layer transforms it into an actionable alert with context.

**The risk scoring pipeline:**

```
Individual Model Scores (per event):
  isolation_forest_score:    0.978   (login event)
  time_anomaly_score:        0.97
  geo_anomaly_score:         0.99
  tor_exit_node:             1.00    (deterministic rule)
  
  → Session risk score: max(0.978, weighted combination)
  
Session-Level Aggregation (per login session):
  session_scores = [0.978, 0.82, 0.91, 0.88]  (multiple events in session)
  session_risk = 0.60 * max(session_scores) + 0.40 * mean(session_scores)
              = 0.60 * 0.978 + 0.40 * 0.8975 = 0.947
  
User-Level Aggregation (rolling 24h):
  If user has multiple high-risk sessions in 24h:
    user_risk_24h = 1 - (1 - s1) * (1 - s2) * ... (probabilistic combination)
    If s1=0.947, s2=0.72: user_risk_24h = 1 - (0.053 * 0.28) = 0.985
  
  Sustained high risk escalates severity (not just a one-time spike)
```

**Alert severity tiers:**

```
SEVERITY MATRIX:
┌──────────────────────────────────────────────────────────────────────┐
│  Risk Score    │  Tier    │  Action                                 │
├──────────────────────────────────────────────────────────────────────┤
│  0.90 - 1.00   │  CRITICAL │  Auto-session-terminate + page on-call │
│                │           │  SLA: analyst response < 15 min        │
├──────────────────────────────────────────────────────────────────────┤
│  0.75 - 0.90   │  HIGH     │  Alert in SOC queue + Slack notify     │
│                │           │  SLA: analyst response < 1 hour        │
├──────────────────────────────────────────────────────────────────────┤
│  0.60 - 0.75   │  MEDIUM   │  Add to SOC queue                      │
│                │           │  SLA: analyst review < 4 hours         │
├──────────────────────────────────────────────────────────────────────┤
│  0.40 - 0.60   │  LOW      │  Log and monitor; batch daily review   │
├──────────────────────────────────────────────────────────────────────┤
│  0.00 - 0.40   │  INFO     │  Baseline data; no alert               │
└──────────────────────────────────────────────────────────────────────┘

Special rules (deterministic overrides):
  is_tor_exit_node AND auth_success → minimum severity: HIGH (regardless of score)
  impossible_travel = true → minimum severity: HIGH
  admin_account AND off_hours AND new_ip → minimum severity: HIGH
  first_ever_failed_logins > 10 in 5min → minimum severity: HIGH (brute force)
```

### 5.2 Threshold Tuning

**The precision-recall tradeoff in UEBA:**

Setting a threshold too low generates excessive false positives, causing "alert fatigue" — analysts stop investigating because they're overwhelmed with noise. Setting it too high misses real attacks.

**Tuning methodology:**

```python
def optimize_threshold(scores_benign, scores_malicious, target_fpr=0.01):
    """
    Find the threshold that achieves the target false positive rate
    while maximizing true positive rate.
    
    scores_benign: array of risk scores from known-benign events (from labeled dataset)
    scores_malicious: array of risk scores from known-malicious events
    target_fpr: maximum acceptable false positive rate (1% = 1 FP per 100 benign events)
    """
    # Sort threshold candidates
    thresholds = np.linspace(0, 1, 1000)
    
    best_threshold = None
    best_tpr = 0
    
    for t in thresholds:
        fpr = np.mean(scores_benign >= t)   # FP rate at this threshold
        tpr = np.mean(scores_malicious >= t) # TP rate at this threshold
        
        if fpr <= target_fpr and tpr > best_tpr:
            best_threshold = t
            best_tpr = tpr
    
    return best_threshold, best_tpr

# Typical results in enterprise UEBA deployment:
# threshold=0.75, FPR=0.8%, TPR=94.2%
# This means: 99.2% of benign events don't trigger alerts
#             94.2% of actual attacks generate an alert
```

**Per-user threshold adaptation:**

One threshold doesn't fit all users. A developer who often works late at 2 AM should have a different time-anomaly threshold than an executive who strictly works 9-5:

```python
class AdaptiveThreshold:
    """
    Per-user threshold adaptation based on historical FP rate.
    If a user generates many false positives: raise their threshold slightly.
    """
    
    def get_user_threshold(self, user_id: str, base_threshold: float = 0.75) -> float:
        # Count analyst-confirmed false positives for this user (last 90 days)
        fp_rate = self.db.get_fp_rate(user_id, days=90)
        
        # Adjust threshold: high FP rate → higher threshold for this user
        adjustment = min(0.15, fp_rate * 0.5)  # Max 0.15 upward adjustment
        
        return min(0.95, base_threshold + adjustment)  # Cap at 0.95
```

### 5.3 SOAR Integration

**Security Orchestration, Automation, and Response (SOAR) playbooks triggered by UEBA:**

```python
class SOARPlaybook:
    """
    Triggered by UEBA high-severity alert.
    Runs automated enrichment and containment actions before human review.
    """
    
    def execute_compromised_account_playbook(self, alert: UEBAAlert):
        """
        Playbook: Potential Account Compromise
        Steps run in parallel where possible.
        """
        results = {}
        
        # Parallel enrichment (all run simultaneously)
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = {
                'threat_intel': executor.submit(
                    self.threat_intel.enrich, alert.src_ip
                ),
                'ad_info': executor.submit(
                    self.active_directory.get_user_info, alert.user_id
                ),
                'recent_activity': executor.submit(
                    self.elasticsearch.get_recent_activity, alert.user_id, hours=24
                ),
                'open_tickets': executor.submit(
                    self.servicenow.get_open_tickets, alert.user_id
                ),
                'hr_status': executor.submit(
                    self.hr_system.get_employee_status, alert.user_id
                )
            }
            results = {k: v.result() for k, v in futures.items()}
        
        # Auto-containment for CRITICAL severity
        if alert.severity == "CRITICAL":
            # Terminate active sessions
            self.active_directory.disable_account(alert.user_id, reason="UEBA Auto-Contain")
            self.okta.revoke_all_sessions(alert.user_id)
            self.vpn.terminate_session(alert.session_id)
            
            # Notify user's manager
            manager = results['ad_info'].manager_email
            self.email.send(manager, subject=f"Security alert: {alert.user_id} account suspended")
        
        # Create enriched ticket
        ticket = self.servicenow.create_incident(
            title=f"[UEBA] {alert.severity} - {alert.user_id} - {alert.reason_codes}",
            priority=self.SEVERITY_PRIORITY_MAP[alert.severity],
            description=self._build_ticket_description(alert, results),
            assignment_group="Tier2-SOC",
            ueba_alert_id=alert.alert_id
        )
        
        return ticket
    
    def _build_ticket_description(self, alert, results) -> str:
        return f"""
UEBA ALERT SUMMARY
==================
User: {alert.user_id} ({results['ad_info'].display_name})
Department: {results['ad_info'].department}
Manager: {results['ad_info'].manager}
Risk Score: {alert.risk_score:.2f}
Anomaly Reasons: {', '.join(alert.reason_codes)}

THREAT INTELLIGENCE
===================
Source IP: {alert.src_ip}
TI Verdict: {results['threat_intel'].verdict}
TI Categories: {', '.join(results['threat_intel'].categories)}
Previous Reports: {results['threat_intel'].abuse_report_count}

RECENT ACTIVITY (24h)
=====================
{self._format_recent_activity(results['recent_activity'])}

HR STATUS
=========
Employee Active: {results['hr_status'].is_active}
On Leave: {results['hr_status'].on_leave}
Termination Notice: {results['hr_status'].termination_pending}
Note: Termination-pending employees are HIGH RISK for insider threats

RECOMMENDED ACTIONS
===================
1. Verify with user via out-of-band communication (phone/physical)
2. Review full session activity in Elasticsearch (link: {self.elastic_url}/...}})
3. If confirmed compromise: initiate IR playbook IR-001
4. If false positive: mark ticket and tune UEBA threshold for this user
"""
```

---

## 6. Attack Scenarios (Evasion Tactics)

### 6.1 Evasion Tactic 1: Low-and-Slow Data Exfiltration

**Attacker goal:** Exfiltrate 100GB of customer data without triggering volume anomalies.

**What Marcus knows from recon:** UEBA flags data transfers significantly above a user's baseline. Alice normally transfers 2-5GB/day. He needs to stay under the detection threshold.

**Step-by-step evasion execution:**

```
Week 1: Establish baseline contamination
  Marcus logs in during Alice's normal working hours (8 AM - 6 PM PT)
  Uses Alice's legitimate VPN from an IP in the US (not Tor)
  He uses a residential proxy in Alice's city: 73.170.x.x (Comcast, California)
  Activity: minimal (just monitoring, no data access)
  Result: UEBA sees normal-looking logins, no alert

Week 2: Begin slow exfiltration
  Rate: 3GB/day (within Alice's normal 2-5GB range)
  Method: SQL queries at normal Alice-like times with small result sets
    8:30 AM: SELECT * FROM customers WHERE state='CA' LIMIT 10000 → 450MB
    10:15 AM: SELECT * FROM customers WHERE state='TX' LIMIT 10000 → 380MB
    1:30 PM: SELECT * FROM customers WHERE state='FL' LIMIT 10000 → 370MB
    4:00 PM: SELECT * FROM transactions WHERE date='2024-01-01' LIMIT 5000 → 210MB
  Total: 1.41GB/day → well within Alice's baseline
  
Weeks 3-5: 70GB extracted in 35 days (2GB/day average)

Week 6: Attacker becomes greedy
  Increases to 8GB/day (above baseline, triggers volumetric alert)
  → Detection!
```

**Why the model might miss it (false negatives):**

```
1. Baseline contamination problem:
   If Alice's UEBA baseline was collected during a period when Marcus was
   already inside (Week 1-2), the baseline is "poisoned" with attacker behavior.
   The model's normal distribution now includes the attacker's pattern.
   The attacker IS the baseline. Detection rate: ~30% (only gross deviations caught)

2. Individual event scores are too low:
   Each individual query looks legitimate (within Alice's normal query patterns)
   The cumulative extraction is only visible by summing across 5 weeks
   No single event has a high enough risk score to trigger an alert
   → Solution: long-window aggregate features (7-day, 30-day rolling)

3. Time window problem:
   If UEBA uses 30-day windows and the attacker resets every 28 days
   (stops, waits 2 days, restarts), the window never captures the full volume
   → Solution: overlapping windows at multiple granularities

4. Peer group masking:
   If several Finance users are legitimately doing data exports this month
   (e.g., for year-end financial reporting), the peer group baseline rises
   and Marcus's extraction looks proportional
```

### 6.2 Evasion Tactic 2: Feature Mimicry (Credential Stuffing with Profile Study)

**Attacker goal:** Perfectly impersonate a user's behavior to avoid ALL behavioral anomaly scores.

**Step-by-step execution:**

```
Phase 1: Reconnaissance (2-4 weeks before attack)
  Marcus has access to LinkedIn (knows Alice's work hours from activity patterns)
  Marcus has stolen email (knows Alice's office: San Francisco, CA)
  Marcus purchases a residential proxy in San Francisco ZIP 94107
  Proxy provider: legitimate ISP (AT&T, Comcast) — not datacenter, not Tor
  Marcus also acquires Alice's device fingerprint from malware on her personal laptop
  
Phase 2: Profile Study (using phished credentials on non-critical systems)
  Log into external, non-monitored systems first (cloud file storage she uses)
  Study: what does Alice access? When? From where?
  
Phase 3: Operational Attack
  Connect Monday-Friday, 8:30 AM - 5:30 PM PT (Alice's normal hours)
  Use San Francisco residential proxy (same ASN, same geo as Alice)
  Spoof Alice's device fingerprint (User-Agent, TLS fingerprint, cookie pool)
  Begin by accessing the same applications Alice uses first thing (email, Slack)
  Then move to high-value targets (slowly, over several sessions)
```

**What the UEBA system sees:**

```
Time anomaly: 0.12 (within normal hours) ✓ low
Geo anomaly: 0.08 (California, normal) ✓ low
ASN anomaly: 0.04 (Comcast, normal ASN) ✓ low  
Device anomaly: 0.15 (fingerprint matches) ✓ low
IP novelty: 0.22 (this IP not seen before, but same ASN) — slight elevation
Access pattern: starts with email + Slack → matches Alice's morning pattern ✓ low

Isolation Forest score: 0.34 (below 0.75 threshold — no alert!)
```

**Why the model fails:**

```
1. The attacker has neutralized the strongest signals:
   - Time: matched ✓
   - Geo: matched ✓  
   - Device: matched (fingerprint spoofed) ✓
   - ASN: matched ✓

2. The remaining signals are too weak individually:
   - New specific IP (0.22): not enough alone
   - Minor access pattern differences (typing speed, mouse movements)
     → Behavioral biometrics can catch this! (see Section 8)

3. The model doesn't know about:
   - Alice's exact typing patterns (not captured in network logs)
   - Alice's natural pause patterns between events
   - Subtle timing differences in how Alice navigates vs the attacker

Why this is hard to prevent at the telemetry level:
  The attacker has correctly identified that UEBA is based on network-level telemetry.
  They have matched all network-observable attributes.
  Without endpoint-level behavioral biometrics (typing dynamics, mouse movement),
  this attack may evade detection.
```

### 6.3 Evasion Tactic 3: Living-off-the-Land (LOL) Lateral Movement

**Attacker goal:** Move laterally through the environment using legitimate system tools so that no individual action appears anomalous.

```
Standard lateral movement (detected by EDR signatures):
  Install tool: psexec.exe, mimikatz.exe → EDR alert: malicious binary

Living-off-the-Land approach:
  Use: PowerShell, WMI, RDP, Admin$ shares, Scheduled Tasks
  All are legitimate Windows tools, used daily by IT admins
  
Step 1: Initial foothold on WKSTN-FIN-042
  PsExec signature: BLOCKED by EDR
  
  Alternative: WMI execution (legitimate admin tool)
    wmic.exe /node:DB-FINANCE-01 process call create "cmd.exe /c whoami > C:\output.txt"
    
Step 2: Credential harvest using legitimate tools
  Not mimikatz (blocked), instead:
    comsvcs.dll LSASS dump:
    tasklist /FI "IMAGENAME eq lsass.exe"  → get PID
    rundll32.exe comsvcs.dll, MiniDump [PID] C:\Windows\Temp\lsass.dmp full
    
Step 3: Lateral movement using pass-the-hash
  Net use to admin shares: net use \\DB-ADMIN-01\admin$ /user:admin_svc [NTLM_HASH]
  
Step 4: Persistence via Scheduled Tasks
  schtasks /create /tn "Windows Update Helper" /tr "cmd.exe /c [payload]" /sc daily
```

**What UEBA sees for each step:**

```
Step 1 - WMI execution to remote host:
  Source: WKSTN-FIN-042 (achen's workstation)
  Target: DB-FINANCE-01 (finance DB server)
  Event: WMIC remote process creation
  
  Features:
    first_ever_wmic_to_this_target: TRUE (Alice's workstation never WMI'd to DB servers)
    graph_edge_novelty: 0.94 (new edge in entity graph)
    peer_wmic_usage_rate: 0.02 (2% of Finance users use WMIC — rare)
  
  → Elevated score: 0.71 (below threshold, but logged)

Step 2 - LSASS dump via comsvcs.dll:
  Event: DLL execution → MiniDump of lsass.exe
  
  Features:
    lsass_dump_attempt: TRUE → deterministic rule: CRITICAL alert regardless of ML score!
    This rule is NOT bypassed by LOL — the behavior itself is intrinsically suspicious
    regardless of what tool performs it
  
  → CRITICAL alert (deterministic rule overrides ML threshold)

Step 3 - Pass-the-hash lateral movement:
  Logon event type 3 (network) to admin share from atypical source
  
  Features:
    logon_type_network_to_admin_share: TRUE
    source_host_first_access_to_dest: TRUE (WKSTN-FIN-042 never accessed DB-ADMIN-01)
    admin_share_access: TRUE (\\admin$ share access)
    time_since_lsass_event: 4 minutes (correlated with lsass dump!)
  
  → ML score: 0.87 (HIGH) + temporal correlation with Step 2 = escalation to CRITICAL
```

### 6.4 Why Models Fail: False Negative Root Causes

```
Root Cause 1: Sparse training data
  Rare but legitimate behaviors (employee working a night shift once, overseas travel)
  have very few training examples
  Model hasn't seen enough examples to set a well-calibrated baseline
  Attacker exploiting these sparse regions: high false negative rate
  Fix: use hierarchical baselines (department → job family → individual) when
       individual data is sparse

Root Cause 2: Correlated attacks
  If multiple users are simultaneously compromised (supply chain attack, credential dump),
  their "anomalous" behavior becomes the new "normal" in peer group comparisons
  The peer group baseline is poisoned
  Fix: isolate peer group comparison from real-time scoring; use a stable 30-day lag

Root Cause 3: Delayed telemetry
  If EDR events arrive 10 minutes late (common for cloud-based EDR agents),
  correlation with authentication events doesn't happen in the same time window
  The attack spans the detection window boundary
  Fix: widen correlation windows (15 min), store events for late-join correlation

Root Cause 4: Feature staleness
  User goes on 3-week vacation; returns to find the model has forgotten their baseline
  Some models' 30-day rolling windows fill with "no activity" = silent period
  When they return: all activity looks anomalous (returning from vacation FP storm)
  Fix: separate active-day baseline from calendar-day baseline;
       pause baseline updates during extended absence periods
```

---

## 7. Failure Points & Scaling

### 7.1 Failures Under a Log Flood (DDoS or Log Storm)

**Scenario:** An attacker launches a network-layer DDoS generating 500M events/minute vs. normal 3.5M/minute. Or: a misconfigured logging agent enters a loop and sends 10M duplicate events per minute.

```
Impact cascade:

T+0: DDoS begins, 500M events/min hitting Kafka producers
  → Kafka ingress: 500M * 500 bytes avg = 250GB/min = 4.2GB/sec
  → Normal Kafka capacity: 10GB/sec across 3 brokers → SATURATED at 42% capacity
  → So far OK (just barely)

T+5min: Normalization workers can't keep up
  → Flink normalization throughput: 50M events/min (10x normal, but 10x short of flood)
  → Kafka consumer lag grows: 500M - 50M = 450M events/min accumulating
  → Consumer lag growth rate: 450M events/min × 500 bytes = 225GB/min accumulating
  → At 7.5 minutes: Kafka disk full (if 1.5TB allocation)
  → Kafka starts dropping messages (if disk-full policy = delete oldest)

T+7.5min: Events dropping
  → Real attack activity buried in flood
  → UEBA detection capability: severely degraded (missing telemetry)
  → This is a smokescreen DDoS: attacker generates noise to hide their lateral movement

T+10min: Feature computation state corruption
  → Flink RocksDB state backends overwhelmed
  → Checkpoint failures (can't write 500GB of state to S3 in 60s)
  → Flink job restarts from last good checkpoint (60 seconds ago)
  → 60-second gap in stateful feature computation
  → All users' sliding window counts are 60 seconds stale
```

**Resilience mechanisms:**

```
Mechanism 1: Per-source rate limiting at the Kafka producer
  Max events/second per source IP: 10,000
  (Even during DDoS, each firewall/IDS/EDR source sends from known IPs)
  Any single source exceeding rate limit: events sampled (5% kept, 95% dropped)
  
  Why sampling: Better to have 5% of events from all sources than 100% from a few.
  The sampled 5% still gives statistically meaningful behavioral signals.

Mechanism 2: Backpressure signaling
  If Kafka consumer lag > 10 minutes of normal throughput:
    → All non-critical consumers (cold storage, search indexing) pause
    → Only real-time scoring consumers continue
    → Free up Kafka I/O bandwidth for critical path

Mechanism 3: Event prioritization
  Not all events are equal. During high-load, prioritize:
    Priority 1 (always process): Authentication events (login, MFA, sudo)
    Priority 2 (always process): Alert-related events (LSASS dump, mimikatz, etc.)
    Priority 3 (sample at 50%): Network flow records
    Priority 4 (sample at 10%): Web proxy logs (very high volume, low-per-event signal)
    Priority 5 (drop during overload): Verbose debug logs, heartbeat events

Mechanism 4: Emergency snapshot
  When DDoS detected: take snapshot of all user behavioral profiles to S3
  This preserves baseline state even if Flink crashes
  On recovery: restore from snapshot rather than replaying events from kafka
```

### 7.2 Concept Drift: When Benign Behavior Changes

**Problem:** Organizations change. What was anomalous 6 months ago may be normal today.

```
Examples of legitimate concept drift:
  Company acquires a startup → 200 new employees with completely different work patterns
  COVID-19 → entire company switches to work-from-home → ALL location features drift
  New database deployed → data analysts start accessing a system they never used
  Org restructuring → user moves from Finance to Engineering → peer group is wrong

Impact without handling:
  Post-acquisition: wave of "anomalous" logins from new network ranges
  Post-COVID: everyone's WFH IP is "new location" for the first week
  → False positive storm: 500+ alerts per day from legitimate behavior change
  → SOC overwhelmed, alert fatigue sets in, real attacks missed
```

**Concept drift detection and adaptation:**

```python
class ConceptDriftHandler:
    
    def detect_population_drift(self, feature_name: str, window_days: int = 7):
        """
        Population Stability Index (PSI) measures if the overall population
        distribution for a feature has shifted significantly.
        PSI > 0.25: major drift — must retrain
        PSI 0.10-0.25: moderate drift — monitor closely
        PSI < 0.10: stable
        """
        current_distribution = self.db.get_feature_distribution(
            feature_name, days=window_days, end='now'
        )
        reference_distribution = self.db.get_feature_distribution(
            feature_name, days=window_days, end='30 days ago'
        )
        
        psi = sum(
            (cur - ref) * math.log(cur / ref)
            for cur, ref in zip(current_distribution, reference_distribution)
            if cur > 0 and ref > 0
        )
        
        return psi
    
    def handle_drift(self, drifted_features: list[str], drift_cause: str):
        """
        Automated responses to detected drift.
        """
        if drift_cause == "org_restructuring":
            # Mass re-baselining: wipe all user profiles, start fresh
            self.schedule_mass_rebaseline(start_date=event_date)
            self.suppress_alerts_globally(duration_days=14)  # 2-week grace period
        
        elif drift_cause == "new_application_rollout":
            # Targeted re-baselining: only for users affected
            affected_users = self.get_users_with_new_app_access()
            for user in affected_users:
                self.suppress_application_features(user, new_app, duration_days=7)
        
        elif drift_cause == "unknown_gradual":
            # Gradual drift: automatically retrain all models this week
            self.trigger_emergency_retraining()
    
    def adaptive_baselining(self, user_id: str):
        """
        Use exponentially-weighted moving average instead of fixed 30-day window.
        Recent events count more than older events.
        This allows the baseline to naturally adapt to changing behavior.
        """
        # EWMA decay factor (0.95 = yesterday is worth 95% of today; 30 days ≈ 1% weight)
        alpha = 0.05
        
        current_profile = self.get_profile(user_id)
        for feature in current_profile.features:
            current_profile[feature] = (
                alpha * self.get_today_value(user_id, feature) +
                (1 - alpha) * current_profile[feature]
            )
        
        self.save_profile(user_id, current_profile)
```

### 7.3 False Positive Storms

**Anatomy of a false positive storm:**

```
Trigger: Monday morning after a 3-day weekend
  Everyone returns to work after 4 days of no activity
  Half the organization logs in from new home IPs (moved router, new ISP, etc.)
  Many people catch up on work: higher-than-normal data access volumes
  
UEBA without FP suppression:
  2,000 employees × average risk score 0.82 = 1,640 HIGH alerts
  SOC team capacity: 50 alerts/day
  Result: SOC is 32 days behind on alerts before they finish
  
Real attacks during this window: hidden in noise, missed
```

**FP suppression mechanisms:**

```
Mechanism 1: Organizational context injection
  HR system announces: "3-day weekend ending Monday"
  UEBA automatically:
    - Raises all thresholds by 0.10 for Monday morning (8 AM - 12 PM)
    - Suppresses "new IP" alerts for 4 hours (VPN reconnection period)
    - Suppresses "high volume" alerts for 2 hours (catch-up period)
  
Mechanism 2: Peer group baseline (population-level FP filtering)
  If > 30% of peer group is triggering the same alert type simultaneously:
    → This is a population event, not individual anomaly
    → Alert suppressed for this feature, logged as "population event"
    → Example: if 200 Finance users all access a new SharePoint site on same day
      → The UEBA correctly identifies this as a new site deployment, not 200 anomalies

Mechanism 3: SOC feedback loop
  Analyst marks alert as "false positive" with reason code
  System learns: user_id + feature_combination + context → FP
  Next time same pattern: risk score reduced by 0.15 for this user

Mechanism 4: Correlation filtering
  An alert is only emitted if MULTIPLE anomaly signals fire simultaneously
  Single-signal alerts (just "new IP" alone): suppressed, logged only
  Dual-signal alerts (new IP + off-hours): emit LOW priority
  Triple-signal alerts (new IP + off-hours + Tor): emit CRITICAL
  Reduces alert volume by 70% with < 5% reduction in true positive rate
```

---

## 8. Mitigations & Defense-in-Depth

### 8.1 Combining ML with Deterministic Signatures

**The fundamental tradeoff:**

ML-only UEBA misses attacks with scores below threshold (false negatives). Rule-only UEBA misses novel attacks that don't match any rule. The correct architecture uses both, with the ML score enriching deterministic rules:

```python
class HybridDetectionEngine:
    """
    Combines ML anomaly scores with deterministic sigma rules.
    Neither alone is sufficient.
    """
    
    SIGMA_RULES = [
        # Deterministic: high confidence, low false positive rate
        SigmaRule(
            id="LSASS_DUMP_VIA_COMSVCS",
            condition="CommandLine CONTAINS 'comsvcs.dll' AND CommandLine CONTAINS 'MiniDump'",
            base_severity="CRITICAL",
            ml_score_required=False  # Fire regardless of ML score
        ),
        SigmaRule(
            id="TOR_EXIT_NODE_AUTH",
            condition="is_tor == True AND event_action == 'login_success'",
            base_severity="HIGH",
            ml_score_required=False  # Deterministic: Tor + auth = always alert
        ),
        
        # ML-assisted: requires both rule AND elevated ML score
        SigmaRule(
            id="LARGE_DATA_EXPORT_ELEVATED",
            condition="bytes_transferred > 1000000000",  # 1GB
            base_severity="MEDIUM",
            ml_score_required=True,  # Only alert if ML score also elevated (>0.60)
            ml_score_threshold=0.60  # Avoid FP from legitimate large exports
        ),
        SigmaRule(
            id="OFF_HOURS_DB_QUERY",
            condition="event_type == 'db_query' AND is_weekend == True",
            base_severity="LOW",
            ml_score_required=True,
            ml_score_threshold=0.70
        ),
    ]
    
    def evaluate(self, event: UESEvent, ml_scores: dict) -> list[Alert]:
        alerts = []
        
        for rule in self.SIGMA_RULES:
            if rule.matches(event):
                if rule.ml_score_required:
                    composite_score = ml_scores.get('composite', 0)
                    if composite_score >= rule.ml_score_threshold:
                        alerts.append(Alert(
                            rule=rule,
                            severity=rule.base_severity,
                            ml_score=composite_score,
                            detection_method="hybrid"
                        ))
                else:
                    # Deterministic rule: fire regardless
                    alerts.append(Alert(
                        rule=rule,
                        severity=rule.base_severity,
                        ml_score=ml_scores.get('composite', 0),
                        detection_method="deterministic"
                    ))
        
        return alerts
```

### 8.2 Behavioral Biometrics as an Anti-Evasion Layer

For the feature-mimicry attack (Section 6.2), network-layer telemetry is insufficient. Behavioral biometrics add endpoint-level signals:

```
Keyboard dynamics:
  - Keystroke timing (dwell time per key, flight time between keys)
  - Typing speed distribution
  - Error/correction patterns
  - These form a unique per-user fingerprint
  
  Data source: EDR agent or custom JavaScript in web applications
  Feature: 
    keystroke_rhythm_similarity_score: cos_similarity(current_session_rhythms, baseline_rhythms)
    If score < 0.60: typing pattern doesn't match this user
    
Mouse dynamics:
  - Mouse movement velocity and acceleration patterns
  - Click timing
  - Scroll behavior
  
  Data source: Browser JavaScript telemetry
  
Session pacing:
  - Inter-event timing (time between mouse clicks, page loads)
  - Session cadence (work pattern within a session)
  
  Feature: Are the PAUSES between events consistent with this user?
  An attacker navigating manually will have different pause patterns
  than the legitimate user's automated workflows

Why this catches the feature-mimicry attack:
  The attacker matched all NETWORK-observable features
  But they cannot match Alice's unconscious typing dynamics or mouse movements
  These are extremely difficult to spoof even with access to Alice's physical device
```

### 8.3 Long-Window Aggregate Features for Low-and-Slow Detection

```python
class LongWindowFeatureExtractor:
    """
    Computes features over 7-day, 30-day windows to catch slow exfiltration.
    These run as batch jobs (nightly), not streaming.
    Output stored in Redis for use in real-time inference.
    """
    
    def compute_7day_profile(self, user_id: str) -> dict:
        # Total data transferred in last 7 days
        bytes_7d = self.db.sum_bytes(user_id, days=7)
        queries_7d = self.db.count_queries(user_id, days=7)
        distinct_tables_7d = self.db.count_distinct_tables(user_id, days=7)
        
        # Compare to their 90-day historical average for 7-day windows
        historical_mean_bytes = self.db.historical_mean(user_id, window='7d')
        historical_std_bytes = self.db.historical_std(user_id, window='7d')
        
        bytes_z_score = (bytes_7d - historical_mean_bytes) / (historical_std_bytes + 1e-9)
        
        # Compare to peer group
        peer_bytes_7d = self.db.peer_group_mean_bytes(user_id, days=7)
        peer_comparison_ratio = bytes_7d / (peer_bytes_7d + 1e-9)
        
        return {
            'bytes_7d': bytes_7d,
            'bytes_7d_zscore': bytes_z_score,       # How many std devs above THEIR baseline
            'bytes_7d_vs_peers': peer_comparison_ratio,  # How many times more than peers
            'queries_7d': queries_7d,
            'distinct_tables_7d': distinct_tables_7d,
            'exfil_risk_score_7d': self._compute_exfil_risk(bytes_z_score, peer_comparison_ratio)
        }
    
    def _compute_exfil_risk(self, z_score: float, peer_ratio: float) -> float:
        """
        High risk when: z-score is high (above OWN baseline)
                   AND: peer ratio is high (above PEERS' behavior)
        Both conditions required to reduce false positives from:
          - Power users who always transfer more than peers (high peer ratio, low z-score)
          - Brief spikes due to legitimate projects (high z-score, normal peer ratio)
        """
        return min(1.0, (max(0, z_score) / 3.0) * min(1.0, peer_ratio / 3.0))
```

---

## 9. Observability

### 9.1 Monitoring Model Accuracy and Drift

**The UEBA-specific observability challenge:** You rarely know ground truth in real-time. An alert fires; you don't know if it's a true positive until an analyst investigates (or a breach is confirmed). Most ML observability metrics require ground truth labels. UEBA must use proxy metrics:

```
Proxy Metric 1: Analyst feedback rate
  Track what fraction of alerts are confirmed TP vs. marked FP by analysts
  
  true_positive_rate = confirmed_incidents / total_investigated_alerts
  false_positive_rate = false_positive_dismissals / total_investigated_alerts
  
  Target: FPR < 15% (85% of investigated alerts should be actionable)
  Alert if: FPR > 30% for 7-day rolling window (model has drifted)

Proxy Metric 2: Alert volume trend
  If alert volume spikes 3× in 24h without a known cause:
    → Either a real attack campaign, or model has drifted
    → Investigate: are the new alerts from same users? Same features?
    
Proxy Metric 3: Score distribution stability
  The distribution of risk scores across all events should be stable day-to-day
  
  Monitor: daily histogram of risk scores across all events
  Expected: heavy right-skew (most events low score, very few high score)
  Alert if: distribution shape changes (KS-test p-value < 0.01)
    → Indicates feature distribution shift → model performance may have changed

Proxy Metric 4: Feature drift monitoring
  For each feature (47 features), compute daily:
    current_distribution vs. 30-day-ago_distribution
    PSI (Population Stability Index)
  Alert if: PSI > 0.25 for any feature (significant drift)
  Warning if: PSI > 0.10 for any feature (moderate drift, monitor)
```

**Model health dashboard metrics:**

```yaml
# Prometheus metrics for UEBA model health

# Per-model performance
ueba_model_inference_latency_ms{model="isolation_forest", quantile="0.99"}
ueba_model_inference_latency_ms{model="lstm_autoencoder", quantile="0.99"}
ueba_model_inference_errors_total{model, error_type}

# Alert quality metrics
ueba_alerts_total{severity, detection_method}
ueba_analyst_feedback_total{verdict}  # true_positive, false_positive, escalated
ueba_mean_time_to_investigate_seconds{severity}
ueba_mean_time_to_contain_seconds  # After CRITICAL alert: how fast is response?

# Data pipeline health
ueba_kafka_consumer_lag_events{topic, consumer_group}
ueba_normalization_failures_total{source_type, error_type}
ueba_events_processed_per_second{stage}
ueba_events_dropped_total{stage, reason}

# Drift metrics
ueba_feature_psi{feature_name}  # Population Stability Index per feature
ueba_model_score_distribution_ks_statistic  # Kolmogorov-Smirnov test stat
ueba_baseline_coverage_pct  # % of users with sufficient data for baseline (target > 85%)
ueba_model_age_days{model}  # How old is each model (alert if > 30 days without retrain)

# False positive tracking
ueba_fp_rate_rolling_7d
ueba_fp_rate_by_user  # Per-user FP rate (identify users whose threshold needs tuning)
ueba_alert_storm_events_total  # Events where > 100 alerts fired in 1 hour
```

### 9.2 Tracing an Alert Back to Raw Logs

**The audit trail from alert to raw event:**

```
Alert: ueba-alert-8f3a1b2c (HIGH severity, user: achen)
  │
  ├── alert_id: ueba-alert-8f3a1b2c
  ├── trigger_event_id: ueba-event-7d9e2f1a
  ├── model: isolation_forest, score: 0.978
  ├── contributing_features: [time_anomaly, geo_anomaly, tor_exit_node]
  │
  └── link to Elasticsearch: query by trigger_event_id
        → Normalized event: ueba.normalized index, doc_id: 7d9e2f1a
            ├── link to raw event: raw_event_id: "windows-4624-01152024-021347"
            ├── raw source: windows_security_log on DC01
            └── raw log: raw Elasticsearch document in ueba.raw.auth
        
        → All events for this session: query by session_id (derived field)
            → Timeline: all events from VPN login to last activity
            
        → All events for this user, last 24h: query by actor.id="achen"
            → Full context of what happened before and after the alert
```

**Kibana query chain for alert investigation:**

```
Step 1: Start with the alert
  GET ueba-alerts/_doc/ueba-alert-8f3a1b2c
  
Step 2: Get the triggering event and all session events
  GET ueba-normalized/_search
  {
    "query": {
      "bool": {
        "must": [
          { "term": { "actor.id": "achen" } },
          { "range": { "@timestamp": {
            "gte": "2024-01-15T02:00:00Z",
            "lte": "2024-01-15T04:00:00Z"
          }}}
        ]
      }
    },
    "sort": [{ "@timestamp": "asc" }],
    "size": 1000
  }
  
Step 3: Get raw events for any suspicious event
  GET ueba-raw-auth/_doc/{raw_event_id}
  → Original syslog/Windows event log entry, unmodified

Step 4: Replay feature computation for the alert event
  → UEBA provides a "feature replay" API: given an event_id,
    re-compute all features that were active at that moment
  → Shows analyst exactly what the model saw and why it scored 0.978
  → Critically: this uses the HISTORICAL model and feature state from that time,
    not today's model (which may have been retrained since)
```

### 9.3 What Should Alert MLOps vs. SOC

**Alerts that should go to the MLOps/Detection Engineering team:**

```
1. Model age > 30 days without retraining
   → Detection engineering: schedule emergency retraining
   → NOT SOC: this is infrastructure, not a security incident

2. Feature PSI > 0.25 for any feature
   → Detection engineering: investigate drift cause, retrain or recalibrate
   → NOT SOC: unless drift is caused by an attack (which requires further investigation)

3. False positive rate > 30% (7-day rolling)
   → Detection engineering: model is generating too much noise
   → SOC should be notified (they're the ones overwhelmed) but DE owns the fix

4. Kafka consumer lag > 10 minutes for real-time scoring topic
   → Platform/SRE team: infrastructure scaling needed
   → NOT SOC: unless the lag was caused by an attack-related log flood

5. Normalization failures > 1% for any source
   → Detection engineering: parser may be broken (source format changed)
   → NOT SOC: missed events from a broken parser = blind spot, must be fixed fast

6. Score distribution KS-statistic > 0.15
   → Detection engineering: model behavior has shifted significantly
   → Investigate before deciding whether SOC needs to know
```

**Alerts that should go to the SOC:**

```
1. Any alert with severity HIGH or CRITICAL
   → SOC owns investigation and response
   → MLOps should not interfere with SOC's assessment of security severity

2. Alert volume spike (> 3× normal in 1 hour)
   → SOC: potential attack campaign
   → MLOps: assess simultaneously if it's model drift (check feature distributions)

3. Alert storm suspected as smokescreen DDoS
   → Both: SOC investigates the suspected attacker; MLOps monitors pipeline health

4. Zero alerts for > 4 hours during business hours
   → Both: Could be pipeline failure (MLOps) or attacker suppressing telemetry (SOC)
   → This is a dead-man's switch: always alert if the pipeline goes quiet
```

---

## 10. Interview Questions

### Q1: What is the fundamental difference between a SIEM and a UEBA system, and why can't you just add more rules to your SIEM to achieve UEBA's detection capability?

**Answer:**

A SIEM is a **rule-matching engine** with event correlation. It looks for events that match pre-defined patterns: "5 failed logins in 5 minutes for the same user = brute force." The rule author must know the attack pattern in advance to write the rule. The SIEM answers: "Did event X happen?" It cannot answer: "Is event X normal for this specific user, given their history?"

UEBA is a **behavioral baseline system**. It creates a statistical model of what is normal for each specific user, then flags deviations. It answers: "Is event X consistent with how this user has historically behaved?" The fundamental capability difference: UEBA can detect attacks that look exactly like normal activity from an average user — but are anomalous for this specific user.

**Why you can't add more rules:**

Rules are discrete (match/no-match) and context-free. To catch "Alice logging in at 2 AM as anomalous" with a rule, you'd need: `IF user == "achen" AND hour == 2 AND ... THEN alert`. You'd need custom rules for all 10,000 users, for every behavior dimension. This doesn't scale, becomes unmaintainable, and still misses novel attack patterns not anticipated by the rule author.

UEBA's ML models learn the continuous, multi-dimensional behavioral distribution for each user. The decision boundary for "anomalous" emerges from the data, not from a rule author's imagination. The model also adapts as behavior changes — rules don't.

**What If:** "What if an attacker knows the specific rules and evades them deliberately?"

Rules are brittle. An attacker who knows the brute-force rule does 4 failed logins (never hits 5), waits 6 minutes, tries 4 more. Rule evaded. UEBA's ML model still catches this: the sum of failed logins across a 24-hour window is elevated, and the timing pattern of 4-pause-4-pause is itself anomalous relative to legitimate users. ML models don't have hard thresholds that can be stepped around — they compute multi-dimensional probabilities.

---

### Q2: Walk through exactly how an Isolation Forest score is computed for a single event, from raw event to anomaly score.

**Answer:**

**Step 1: Feature extraction**

Raw event (Windows login 4624) → normalized UES event → feature engineering produces a 47-dimensional feature vector:
```
x = [hour_sin, hour_cos, is_tor, geo_anomaly, bytes_transferred_1h, 
     time_z_score, ip_novelty, ... ] = 47 floats
```

**Step 2: Forest traversal (the actual IF computation)**

An Isolation Forest has T=200 trees. Each tree was built by:
1. Taking a random sample of 256 training events
2. Recursively splitting on random feature + random threshold until each sample is isolated

For input x, traverse each of the 200 trees:
```
Tree 1:
  Root: hour_cos < 0.32?  YES → go left
  Level 2: geo_anomaly < 0.5? YES → go left
  Level 3: ip_novelty < 0.8? NO → go right
  Level 4: is_tor == 0? NO → go right
  Level 5: Leaf node reached
  Path length = 5

Tree 2:
  Root: bytes_transferred_1h < 500MB? NO → go right
  Level 2: time_z_score < 2.0? NO → go right
  Level 3: Leaf node reached
  Path length = 3

... (200 trees total)

Average path length E[h(x)] = mean([5, 3, 4, 2, 7, ...]) = 3.8
```

**Why short path length = anomalous:** Normal points are in dense regions of the feature space. To isolate a point in a dense region, you need many splits (many partitions to separate it from neighbors). Anomalous points are in sparse regions — far from other points. A random split quickly separates them (few partitions needed). Short path length → isolated quickly → anomaly.

**Step 3: Score normalization**

```
E[h(x)] = 3.8  (our point's average path length)
c(n) = 2*(H(255) - 255/256) = 2*(ln(255) + 0.5772 - 255/256) = 11.35
  (expected path length for random BST of size 256 — normalization factor)

raw_score = 2^(-E[h(x)] / c(n)) = 2^(-3.8 / 11.35) = 2^(-0.335) = 0.793

Interpretation:
  raw_score ≈ 1.0: anomaly (path length << c(n))
  raw_score ≈ 0.5: normal (path length ≈ c(n))
  raw_score ≈ 0.0: very normal (path length >> c(n))
```

**Step 4: Calibration to user baseline**

The raw Isolation Forest score is global — it compares this event to Alice's training data, but the training data itself was calibrated assuming 1% contamination. We further calibrate to produce a final score in [0, 1]:

```
# Map raw score to normalized anomaly score using min-max from training
normalized_score = (raw_score - score_min_training) / (score_max_training - score_min_training)
final_anomaly_score = normalized_score  # 0 = most normal, 1 = most anomalous

For our event: final_anomaly_score = 0.978
```

---

### Q3: How do you handle the "cold start" problem for new users or entities in UEBA?

**Answer:**

The cold start problem: a new employee joins on their first day. The UEBA system has no behavioral history. Every action is "first time" — their first login, first IP, first application access. Without a baseline, everything scores anomalously high (false positive storm) or the user is excluded from monitoring (coverage gap).

**Three-tiered baseline hierarchy:**

**Tier 1: Peer group baseline (immediate)**
- On hire date: user is assigned to a peer group (department + role + seniority level)
- Use the aggregate behavior of 50-200 peers as an initial baseline
- "Finance Analyst, 2-5 years experience" → all users matching this profile form the baseline
- Accuracy: moderate (captures broad patterns but misses individual quirks)
- Coverage: immediate (day 1)

**Tier 2: Individual onboarding baseline (2-4 weeks)**
- Disable individual anomaly detection for first 14 days
- Relying instead on Tier 1 peer baseline + hard deterministic rules (Tor, impossible travel, known bad IPs — always trigger)
- Actively record all behavior during this period as "training data"
- Flag but do not alert for mildly anomalous events (log only, no tickets)
- At 14 days: compute initial personal baseline from recorded behavior

**Tier 3: Full individual baseline (30+ days)**
- After 30 days: switch from Tier 1 (peer group) to Tier 3 (individual)
- Gradually blend: week 2-4 = 70% peer + 30% individual; week 5-8 = 30% peer + 70% individual
- After 60 days: 100% individual baseline
- This blending prevents the cold start cliff (sudden model switch causes alert spike)

**Special case: service accounts and machine entities**
- Service accounts often never have a "person" establishing patterns
- They should have extremely rigid, rule-based expectations (not ML):
  - Service account for backup: only runs during 2-4 AM window
  - Any deviation from expected behavior → CRITICAL alert (no ML score needed)
  - These entities should have near-zero behavioral variation in normal operation

**What If:** "A new threat actor compromises an account on day 3, before individual baseline is established?"

During the 14-day onboarding window, deterministic rules still catch high-confidence indicators: Tor exit nodes, impossible travel, known malicious IPs, LSASS dumps. The peer group baseline catches behaviors that are anomalous for the user's role (a new Finance Analyst shouldn't be accessing Engineering systems, even on day 1). The coverage gap is real but bounded — the hardest attacks to detect are those that look like legitimate activity for ANY Finance Analyst, which the peer baseline catches.

---

### Q4: Explain the exact mechanism by which an attacker can poison a UEBA baseline, and what controls prevent or detect this.

**Answer:**

**The poisoning mechanism:**

UEBA baseline = statistical model trained on the user's historical activity. If the attacker can insert events into the training window before the detection is sophisticated enough to catch them, they become part of "normal":

```
Attack timeline:
  Week 1: Attacker accesses system during business hours with residential proxy
          Activity: minimal, just like legitimate user
          Effect: UEBA records these as "normal" events → added to training data
          
  Week 2: Attacker increases activity slightly (still within 2σ of new "normal")
          The baseline has been shifted upward by Week 1's activity
          Week 2 activity is now within the contaminated baseline
          
  Week 3: Attacker can now perform significantly more activity than before
          because the baseline has been progressively shifted upward
          The exfiltration threshold is now much higher than it was before the attack
```

**Mathematical description:**

```
Normal distribution of bytes_transferred for Alice:
  Before contamination: μ = 2GB/day, σ = 0.5GB
  Alert threshold: μ + 3σ = 3.5GB/day
  
After 4 weeks of contaminated baseline (attacker averaging 4GB/day):
  New μ = 0.7 * 2GB + 0.3 * 4GB = 2.6GB  (assuming 30% contamination)
  σ ≈ 0.7 (slightly increased due to attacker's behavior)
  New alert threshold: 2.6 + 3*0.7 = 4.7GB/day
  
Attacker has raised the detection threshold from 3.5GB to 4.7GB by 34%
```

**Controls to prevent and detect baseline poisoning:**

**Control 1: Lag-validated baseline**

Don't train on events from the last 7 days. Use events from 7-37 days ago as training data. This means even if an attacker is active today, they're not in the training data yet. The lag also means: if the attacker's behavior IS detected and labeled as anomalous, those events are removed from the training set before they can poison it.

**Control 2: Poisoning-resistant training (anomaly-exclusion)**

Before computing the baseline, run a pre-screening pass using the EXISTING baseline to remove events that score anomalously under the old model:

```python
def compute_clean_baseline(user_id, events_30d):
    # Get old baseline
    old_model = model_registry.get(user_id, version='previous')
    
    # Score all training events under old model
    scores = [old_model.score(event) for event in events_30d]
    
    # Remove anomalous events from training set (they may be attacker activity)
    clean_events = [e for e, s in zip(events_30d, scores) if s < 0.7]
    
    # Train new baseline on clean events only
    new_model = IsolationForest().fit(clean_events)
    return new_model
```

**Control 3: Peer group anchoring**

The individual baseline is never allowed to drift more than 2σ away from the peer group baseline. If Alice's baseline has drifted to "normal" for 10GB/day, but no Finance Analyst peer has ever exceeded 4GB/day, this discrepancy flags the baseline itself as potentially poisoned.

**Control 4: Behavioral consistency audit**

Weekly: run an audit that examines whether any user's baseline has shifted more than expected given no organizational changes. Unexplained baseline drift > 30% from 6-month-ago baseline triggers a manual review of whether the shift is legitimate.

---

### Q5: How do you architect UEBA to handle real-time lateral movement detection using graph analytics, and what are the computational challenges at scale?

**Answer:**

**The detection problem:**

Lateral movement is by definition a relationship between entities — host A connects to host B, then host B connects to host C, then C to the domain controller. Each hop may look legitimate in isolation. The anomaly is the chain.

**The entity graph structure:**

```
Bipartite graph G = (U ∪ H, E)
  U = set of user accounts (200K in enterprise)
  H = set of hosts/resources (50K hosts, 1K shared resources)
  E = edges: (user → host) with timestamp, protocol, byte count
  
Time-windowed graph:
  G_30d = all edges observed in last 30 days
  G_7d = all edges observed in last 7 days
  G_1d = all edges observed in last 24 hours
  
Anomalous pattern (lateral movement):
  New path in G_1d that doesn't exist in G_30d
  Path that traverses into the "high-value target zone" (DC, backup servers, HR systems)
  Rapid fan-out: one user suddenly accessing many hosts (worm-like spread)
```

**Graph Neural Network (GNN) for lateral movement detection:**

```python
class LateralMovementGNN(torch.nn.Module):
    """
    Graph Attention Network (GAT) for detecting anomalous access patterns.
    Input: Entity graph G at time T
    Output: Anomaly score for each edge (user → host connection)
    """
    
    def __init__(self, node_features=32, hidden_dim=64, output_dim=16, heads=4):
        super().__init__()
        # Graph Attention layers: each node aggregates information from its neighbors
        # weighted by attention scores (some neighbors are more informative than others)
        self.gat1 = GATConv(node_features, hidden_dim, heads=heads)
        self.gat2 = GATConv(hidden_dim * heads, output_dim, heads=1)
        
        # Edge anomaly scorer: takes source and destination node embeddings
        self.edge_scorer = nn.Sequential(
            nn.Linear(output_dim * 2, 32),
            nn.ReLU(),
            nn.Linear(32, 1),
            nn.Sigmoid()
        )
    
    def forward(self, x, edge_index, edge_attr):
        """
        x: node features (user/host attributes) [N_nodes, node_features]
        edge_index: connectivity [2, N_edges] (src, dst pairs)
        edge_attr: edge features (frequency, bytes, novelty) [N_edges, edge_features]
        """
        # Two rounds of message passing: nodes learn from their neighbors
        x = F.elu(self.gat1(x, edge_index))
        x = self.gat2(x, edge_index)
        # x is now a 16-dimensional embedding per node that encodes
        # not just the node's own features but its neighborhood structure
        
        # Score each edge
        src, dst = edge_index
        edge_features = torch.cat([x[src], x[dst]], dim=-1)
        anomaly_scores = self.edge_scorer(edge_features)
        
        return anomaly_scores.squeeze()
```

**Computational challenges:**

**Challenge 1: Graph size**

50K hosts × 200K users = potentially 10 billion possible edges. Even the realized edges (actual connections in 30 days) may be 100M+. Full graph operations at this scale are infeasible.

Solution: **Graph partitioning and hierarchical analysis**
- Partition into sub-graphs by network segment (DMZ, internal, HR, Finance)
- Run GNN on each sub-graph independently (parallelizable)
- Cross-segment edges get special treatment (any crossing = elevated suspicion)

**Challenge 2: Incremental graph updates**

The graph changes with every new connection. Retraining the GNN on every event is computationally infeasible (GNN training takes minutes to hours).

Solution: **Transductive inference on evolving graphs**
- Train GNN nightly on yesterday's graph
- During the day: run inference only (no training) as new edges arrive
- New edges that are not in yesterday's graph are automatically "novel" → score them using both the trained embeddings and a novelty score based on graph distance from existing edges

**Challenge 3: Temporal ordering**

Lateral movement has a temporal component — the attacker moves from A → B → C in sequence. Static graph GNN doesn't capture this.

Solution: **Temporal Graph Network (TGN)**
- Each edge has a timestamp
- TGN uses temporal attention to weight recent edges more than old edges
- LSTM over the sequence of edges for each entity captures the temporal ordering
- Allows detection of: "user account now accessing systems in the order: VPN → workstation → database → domain controller" — a classic lateral movement chain

---

### Q6: Describe how you would architect a UEBA system to handle 50,000 simultaneous remote workers generating 50 million events per hour. What are the key design decisions at each layer?

**Answer:**

**Back-of-envelope sizing:**

```
50,000 users × 50M events/hr = 50M events/hr = 833K events/min = ~14K events/second
Average event size: 500 bytes
Ingestion throughput: 14K * 500 bytes = 7MB/second = 25GB/hour = 600GB/day
```

**Collection layer:**

Deploy Fluent Bit (lightweight, 5MB memory footprint) on all endpoints. Use Fluent Bit's built-in forward protocol to regional aggregators (one aggregator per 5,000 endpoints). Aggregators run Fluentd (heavier but more feature-rich) for batching, compression (LZ4, 5× reduction = 120GB/day), and regional failure isolation. With 10 regional aggregators: each handles 1,400 events/second — very manageable.

**Transport layer (Kafka sizing):**

```
Throughput: 7MB/s sustained, peak 3× = 21MB/s
Kafka brokers: 6 brokers (3 for availability, 2 for throughput headroom)
Each broker: 2Gbps network, 10K IOPS NVMe
Replication factor: 3, min.insync.replicas: 2
Partitions: 128 per topic (allows 128 parallel consumers)
Retention: 3 days raw (600GB/day × 3 = 1.8TB) — manageable
```

**Normalization and feature computation (Flink):**

```
Flink cluster: 16 TaskManagers, 8 CPU cores each, 64GB RAM each
TaskSlots per TM: 4 (parallelism = 64)
Throughput per slot: 1,000 events/second
Total throughput: 64,000 events/second >> 14,000 events/second required
Headroom: 4.6× (handles 3× traffic spikes easily)

State backend: RocksDB (on local NVMe), checkpointed to S3 every 60s
State size: 50,000 users × 50KB per user state = 2.5GB per TaskManager
  (well within 64GB RAM; 96% of state in RocksDB on NVMe, hot data in RAM)
```

**Model serving:**

```
Isolation Forest inference: 2ms per event
At 14K events/second: 14K × 2ms = 28 CPU-seconds/second of computation needed
CPUs required: 28 cores
With 4× headroom: 112 cores total = 14 × 8-core servers or 4 × 32-core servers

Models stored: 50,000 Isolation Forest models × 400KB each = 20GB
Store in: Redis (20GB, fits in memory) for hot path
  Key: "model:{user_id}:{model_type}" → serialized model bytes
  Load on first inference, cache in serving process memory (LRU cache, 1000 models)
  Most servers serve 1,000 users' models from in-process cache (avoid Redis roundtrip)

LSTM autoencoder: runs on 16 GPU-accelerated servers (micro-batch every 60 seconds)
  Each server handles 3,125 users
  Batch 60 seconds of sessions per user: 3,125 users × 20 events = 62,500 sequences/batch
  GPU (T4): processes 50,000 sequences/second → batch completes in 1.25 seconds ✓
```

**Key design decisions:**

1. **Event prioritization first:** Partition Kafka topics by event criticality. Authentication events on a dedicated high-priority topic with 2× consumer replicas — never drop auth events even under load.

2. **Stateful computation locality:** Key all Flink operations by user_id. All stateful feature computation for a given user runs on the same Flink task (no cross-task state joins). Eliminates cross-network state access latency.

3. **Model per-user, not per-request:** Pre-train and cache all 50,000 user models. Inference is a lookup + CPU computation, not a training operation. Model freshness: refresh weekly in background, zero-downtime swap.

4. **Tiered alerting to control noise:** At 50M events/hour, even a 0.001% alert rate = 50,000 alerts/hour. Enforce minimum dual-signal requirement (at least two independent anomaly signals before alerting). Aggressive peer group FP filtering. Target: < 50 HIGH/CRITICAL alerts per hour for a team of 10 SOC analysts.

---

### Q7: Why is "is_new_ip" a feature rather than a rule, and what does this teach us about UEBA feature design in general?

**Answer:**

If "new IP" were a rule: `IF new_ip_never_seen_before THEN alert`. For an average enterprise user who uses corporate VPN (one IP), home internet (one IP), and mobile hotspot (one IP): they would generate an alert every time they switch networks — dozens of alerts per month. Alert fatigue, usefulness = zero.

As a feature in a model, "is_new_ip" contributes a fractional amount to an overall risk score. Alone (is_new_ip = True, everything else normal), the score might be 0.22 — far below the 0.75 alert threshold. Combined with other signals (is_new_ip AND 2 AM AND Tor exit node AND 5x normal data volume), the composite score is 0.97 — high confidence alert.

This illustrates the central philosophy of UEBA feature design:

**1. Features capture signals, not decisions.** A feature is not an alarm — it's a piece of evidence. The ML model weighs all features simultaneously to assess overall anomaly.

**2. Features should be continuous, not binary, where possible.** Instead of "is_new_ip" (1 or 0), use "ip_novelty_score" (0 to 1, based on how long since this IP was last seen, how many times it's been seen, how many other users share this IP). This gives the model more signal to work with.

**3. Features should be user-relative, not absolute.** A 10-hour workday is normal for a vice president, anomalous for a part-time contractor. "is_long_session" without context is noise. "session_duration_z_score_vs_user_baseline" is a meaningful feature.

**4. Features should be redundant but independent.** Multiple features can measure similar things (e.g., geo_anomaly AND asn_anomaly both capture "unusual network location") but through different mechanisms. If an attacker defeats one (uses a residential proxy in the right country), the other may still fire (the ISP is slightly different). Defense in depth at the feature level.

**5. Features should have explicit handling for missing values.** Bureau API down: ip_threat_intel_score = None → use -1 (a trained special value). Model was trained to handle -1 as a "data unavailable" indicator, which itself has a mild anomaly contribution (if threat intel is unavailable, we know slightly less about this IP).

---

### Q8: How would you design the UEBA system to detect a compromised service account that is being used for lateral movement, given that service accounts often have very consistent, automated behavior?

**Answer:**

Service accounts are actually easier to baseline than human accounts because of their consistency — and this becomes their strength in detection.

**Baseline characteristics of service accounts:**

```
backup_svc account:
  Runs at: 02:00 - 04:30 AM (always)
  Connects to: backup_server_01 only
  Protocol: SMB
  Bytes: 50-200GB per night (varies with data size)
  Source host: backup_agent_01 only (single origin)
  Day of week: every night (including weekends)
  
Expected behavioral entropy: VERY LOW (near-deterministic)
```

**Why this makes anomalies extremely obvious:**

For a service account with low behavioral entropy, ANY deviation is a high-confidence anomaly:

```python
class ServiceAccountPolicy:
    """
    Service accounts are treated differently from user accounts.
    Their expected behavior is codified as policy, not learned from data.
    Any deviation from policy → CRITICAL alert immediately.
    No ML scoring needed — behavioral entropy is near zero.
    """
    
    POLICIES = {
        "backup_svc": ServiceAccountPolicy(
            allowed_hours=[(2, 4.5)],      # 2:00 AM - 4:30 AM only
            allowed_source_hosts=["backup_agent_01"],
            allowed_dest_hosts=["backup_server_01", "backup_server_02"],
            allowed_protocols=["SMB"],
            max_bytes_per_night=250_000_000_000,  # 250GB
            allowed_days=[0,1,2,3,4,5,6],         # Every day
        ),
        "db_replication_svc": ServiceAccountPolicy(
            allowed_hours=[(0, 24)],    # 24/7
            allowed_source_hosts=["db-primary-01"],
            allowed_dest_hosts=["db-replica-01", "db-replica-02"],
            allowed_protocols=["PostgreSQL", "MySQL"],
            max_bytes_per_hour=50_000_000_000,  # 50GB/hr
        )
    }
    
    def evaluate(self, event: UESEvent) -> PolicyViolation:
        if event.actor.id not in self.POLICIES:
            return None  # Not a managed service account
        
        policy = self.POLICIES[event.actor.id]
        violations = []
        
        # Check each policy dimension
        if not policy.is_hour_allowed(event.timestamp.hour):
            violations.append(f"OFF_POLICY_HOUR: {event.timestamp.hour}")
        
        if event.network.src_ip not in policy.allowed_source_ips:
            violations.append(f"NEW_SOURCE: {event.network.src_ip}")
            
        if event.target.id not in policy.allowed_dest_hosts:
            violations.append(f"NEW_DESTINATION: {event.target.id}")  # CRITICAL for SA
        
        if violations:
            return PolicyViolation(
                account=event.actor.id,
                violations=violations,
                severity="CRITICAL",  # Any deviation from SA policy = CRITICAL
                auto_contain=True     # Service account should be automatically disabled
            )
```

**Detecting credential theft of service accounts:**

The most dangerous attack on a service account is using its credentials from a different source:

```
Normal: backup_svc connects from backup_agent_01 (always)
Attack: Attacker extracts backup_svc NTLM hash via pass-the-hash
        Uses credential from: WKSTN-FIN-042 (attacker's foothold)
        
Detection:
  source_host_deviation: backup_svc never connects from WKSTN-FIN-042
  → Immediate CRITICAL alert (SA source host change = always critical)
  → Auto-disable backup_svc account
  → Alert: "Service account backup_svc used from unexpected host: WKSTN-FIN-042
            This host is associated with compromised user: achen (see alert ueba-alert-8f3a1b2c)"
            
The UEBA system correlates the two alerts (achen compromise + backup_svc misuse)
because both involve WKSTN-FIN-042 → links the two incidents into a single campaign
```

**The correlation engine for lateral movement campaign detection:**

```python
class LateralMovementCorrelator:
    """
    Links individual anomaly alerts into a campaign narrative.
    An individual alert may be ambiguous; a chain of related alerts is high confidence.
    """
    
    def correlate_alerts(self, new_alert: UEBAAlert, recent_alerts: list[UEBAAlert]) -> Campaign:
        related = []
        
        for past_alert in recent_alerts:
            # Connect alerts that share: user, host, IP, or time proximity
            if self._are_related(new_alert, past_alert):
                related.append(past_alert)
        
        if len(related) >= 2:
            # Campaign: multiple related alerts in sequence
            campaign = Campaign(
                alerts=[*related, new_alert],
                severity=self._escalate_severity(related, new_alert),
                attack_chain=self._reconstruct_attack_chain(related, new_alert),
                confidence=min(1.0, 0.3 + 0.2 * len(related))  # More links = more confidence
            )
            return campaign
    
    def _are_related(self, a: UEBAAlert, b: UEBAAlert) -> bool:
        # Same user account
        if a.user_id == b.user_id: return True
        # Same source host
        if a.source_host == b.source_host: return True
        # Same source IP
        if a.src_ip == b.src_ip: return True
        # Sequential hosts (b's host is a's target)
        if b.source_host == a.target_host: return True
        # Time proximity (within 2 hours)
        if abs((a.timestamp - b.timestamp).seconds) < 7200: return True
        return False
```

This campaign correlation transforms the detection from "we saw an anomalous login" to "we are observing an active lateral movement campaign: achen account compromised → pivot to WKSTN-FIN-042 → service account credential theft → now attempting to access backup servers via stolen backup_svc credential." The SOC analyst sees the full attack chain, not disconnected alerts.

---

*Document ends. Coverage: complete UEBA system lifecycle from telemetry collection through Kafka, normalization to UES schema, stateful and stateless feature engineering, Isolation Forest mechanics with score derivation, LSTM autoencoder architecture, micro-batch vs. streaming inference, SOAR integration, evasion tactics (low-and-slow, feature mimicry, living-off-the-land) with detection mechanics, log flood resilience, concept drift handling, behavioral biometrics, hybrid ML+sigma rule architecture, complete observability stack, and 8 deep technical interview questions.*