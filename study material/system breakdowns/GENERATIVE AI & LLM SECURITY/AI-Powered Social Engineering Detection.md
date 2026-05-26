# AI-Powered Social Engineering Detection — Internal Engineering & Security Document

**Classification:** Internal Engineering Reference
**Audience:** SOC Architects, Detection Engineers, Red Team Leads, Security Platform Engineers
**Scope:** Complete breakdown of an AI-powered social engineering detection system — from telemetry ingestion through ML-based detection, SOAR orchestration, authorized red team simulation, and the platform's own security controls
**System Context:** A enterprise SOC platform protecting 50,000 employees against phishing, vishing, business email compromise (BEC), and AI-generated spear phishing campaigns

---

## A Beginner's Orientation: Why Social Engineering Is Hard to Detect Automatically

**What social engineering is:** Attacks that manipulate people rather than breaking technical controls. An attacker doesn't need to exploit a vulnerability in your firewall — they convince an employee to wire money, click a link, or reveal credentials.

**Why it evades traditional security:**

```
Traditional security signatures are binary:
  - This IP is bad → block it
  - This URL is malicious → block it
  - This file has malware hash → block it

Social engineering attacks:
  - Use legitimate email infrastructure (no bad IP to block)
  - Link to legitimate file-sharing services (no bad URL signature)
  - Contain no malware (no file hash to detect)
  - The "exploit" is the text — convincing the recipient to act

What makes detection hard:
  "Your invoice is overdue, please pay by clicking here"
    → Could be legitimate from a real vendor
    → Could be a BEC attack impersonating a vendor
  
  The difference is CONTEXT:
    - Has this sender emailed us before?
    - Does this match the real vendor's email patterns?
    - Is the timing consistent with known business cycles?
    - Has the vendor confirmed this via out-of-band channel?
  
  Humans miss these signals under time pressure.
  AI can evaluate all signals simultaneously, consistently, at scale.
```

---

## Table of Contents

1. [Operational Narrative](#1-operational-narrative)
2. [Data Ingestion & Telemetry Architecture](#2-data-ingestion--telemetry-architecture)
3. [Automation & Orchestration Engine](#3-automation--orchestration-engine)
4. [Execution Mechanics](#4-execution-mechanics)
5. [Adversarial Counter-Measures & Bypasses](#5-adversarial-counter-measures--bypasses)
6. [Security Controls & System Integrity](#6-security-controls--system-integrity)
7. [Attack Surface Mapping](#7-attack-surface-mapping)
8. [Failure Points & Edge Cases](#8-failure-points--edge-cases)
9. [Mitigations & Observability](#9-mitigations--observability)
10. [Interview Questions](#10-interview-questions)

---

## 1. Operational Narrative

### Scenario A: Defensive — BEC Attack Detected and Contained

**T+0s — Attack initiated (attacker's perspective)**

An attacker has been monitoring Acme Corp's LinkedIn and public filings for three weeks. They've identified:
- The CFO: Janet Liu, email jliu@acme.com
- The accounting manager: Bob Chen, email bchen@acme.com
- A real vendor: Apex Supplies, usual contact apex-billing@apexsupplies.com
- Recent 10-K disclosure: Acme pays ~$2.3M/quarter to Apex

The attacker registers `apexsuppIies.com` (capital I instead of lowercase L — visually identical in many fonts), creates a professional email account, and sends:

```
From: billing@apexsuppIies.com
To: bchen@acme.com
Subject: URGENT: Updated banking details for upcoming payment

Dear Mr. Chen,

Due to our recent bank migration, please use the following wire details 
for our next invoice payment due Nov 15th:

Bank: First National Trust
Account: 847291037
Routing: 021000089
Reference: Invoice AP-2024-Q4-0891

Please confirm receipt of these instructions. Our previous account 
closes November 12th so prompt action is required.

Best regards,
Michael Torres
Accounts Receivable
Apex Supplies
```

**T+0s to T+15s — Email ingestion and initial processing**

```
Email arrives at Acme's email gateway (Microsoft 365):
  Google/Microsoft email infrastructure validates:
    SPF: PASS (attacker correctly set up SPF for apexsuppIies.com)
    DKIM: PASS (signed with attacker's legitimate DKIM key)
    DMARC: PASS (attacker set up DMARC for their domain)
  
  Technical email security: ALL GREEN ← This is why BEC is so effective.
  The attack uses legitimate infrastructure. No technical red flags.
  
  Email is queued for delivery to bchen@acme.com.
  Simultaneously: Email metadata is exported via Microsoft Graph API to SIEM.
```

**T+15s to T+45s — SIEM ingestion and feature extraction**

```
SIEM receives email telemetry:
  {
    "message_id": "CAL3E7Hm...",
    "from_address": "billing@apexsuppIies.com",
    "from_display": "Apex Supplies Billing",
    "to": ["bchen@acme.com"],
    "subject": "URGENT: Updated banking details for upcoming payment",
    "timestamp": "2024-11-15T09:14:22Z",
    "spf": "PASS",
    "dkim": "PASS",
    "dmarc": "PASS",
    "body_text": "[extracted text]",
    "links": [],
    "attachments": [],
    "sender_ip": "198.51.100.45",
    "sending_infrastructure": "Google Workspace"
  }

AI Feature Extraction Pipeline runs:
  Feature 1: Domain similarity analysis
    actual_vendor_domain:    "apexsupplies.com"
    sender_domain:           "apexsupplies.com" ← Looks identical
    unicode_analysis:        "apexsupp[I]ies.com" ← Capital I detected!
    homoglyph_score:         0.97 (nearly identical to known vendor)
    domain_age:              3 days ← Registered 3 days ago
    
  Feature 2: Sender relationship history
    query: SELECT * FROM email_history WHERE sender LIKE '%apexsupplies%'
    known_senders: ["billing@apexsupplies.com", "ap_billing@apexsupplies.com"]
    history_with_this_exact_sender: 0 emails in 24 months
    history_with_legitimate_domain: 847 emails over 24 months
    
  Feature 3: NLP content analysis
    urgency_signals:        ["URGENT", "closes November 12th", "prompt action required"]
    financial_indicators:   ["wire", "banking details", "routing", "account"]
    action_demand:          REQUEST_FINANCIAL_ACTION (confidence: 0.94)
    authority_appeal:       VENDOR_IMPERSONATION (confidence: 0.89)
    
  Feature 4: Behavioral baseline
    bob_chen_receives_finance_emails_baseline: 3.2/week
    bob_chen_wire_instruction_emails_30d: 0
    financial_wire_change_requests_this_month: 1 (this one)
    
  Feature 5: Threat intelligence
    apexsuppIies.com in TI feeds: NOT YET (domain is 3 days old)
    198.51.100.45 reputation: CLEAN (Google Workspace IP)
    
  COMPOSITE RISK SCORE:
    Homoglyph domain match: +35 points
    Domain age < 7 days: +20 points
    No prior relationship with this sender: +15 points
    Financial action request + urgency language: +25 points
    Wire instructions in body: +20 points
    TOTAL: 115/100 → CRITICAL (capped at 100)
```

**T+45s — SOAR playbook triggers automatically**

```
SOAR Event:
  Alert: BEC_FINANCIAL_HIGH_CONFIDENCE
  Score: 100/100
  Playbook: PLAYBOOK_BEC_FINANCIAL_CRITICAL

Automated Actions (no human approval required at this tier):
  
  Action 1: QUARANTINE EMAIL (T+47s)
    API call to Microsoft Graph:
    POST https://graph.microsoft.com/v1.0/users/bchen@acme.com/messages/{id}/move
    Body: {"destinationId": "quarantine_folder_id"}
    Result: Email removed from Bob's inbox before he reads it
  
  Action 2: BLOCK SENDER DOMAIN (T+48s)
    API call to Exchange Online Protection:
    New-BlockedSenderAddress -Address "*@apexsuppIies.com"
    Result: All future emails from this domain blocked
  
  Action 3: SUBMIT TO THREAT INTELLIGENCE (T+49s)
    Share IOC via STIX 2.1:
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--[uuid]",
      "pattern": "[domain-name:value = 'apexsuppIies.com']",
      "pattern_type": "stix",
      "indicator_types": ["malicious-activity"],
      "name": "BEC Homoglyph Domain",
      "confidence": 90
    }
    Published to: Internal TAXII server + FS-ISAC share
  
  Action 4: ALERT BOB CHEN (T+50s)
    Send automated message to Bob's Slack:
    "SECURITY ALERT: An email pretending to be from Apex Supplies was
    blocked and quarantined. This appears to be a fraud attempt. Do NOT
    respond to any wire transfer requests via email without calling 
    Apex Supplies at their verified number: [known good number from CRM].
    Ticket: SOC-2024-8821"
  
  Action 5: ALERT FINANCE TEAM LEAD (T+51s)
    Send to finance manager and CFO:
    "BEC attempt targeting Bob Chen (Accounting). Wire fraud attempted
    via homoglyph domain apexsuppIies[.]com. Email quarantined.
    Please verify no payment has been initiated. Ticket: SOC-2024-8821"
  
  Action 6: CREATE SOC TICKET (T+52s)
    Ticket: SOC-2024-8821
    Priority: CRITICAL
    Assigned to: SOC Tier 2 Analyst
    SLA: 30 minutes first response
    
  Action 7: PRESERVE EVIDENCE (T+53s)
    Archive full email with headers to evidence store (S3 + immutable lock)
    Screenshot sender domain WHOIS + DNS records (domain age evidence)
    Submit domain to VirusTotal, urlscan.io, urlhaus
```

**T+53s to T+15min — Human analyst review (Tier 2)**

```
Analyst Sarah receives the ticket.
Dashboard shows: automated actions already taken.
Analyst tasks (manual, requiring human judgment):

  Task 1: Verify the real Apex Supplies is not affected
    Call Apex Supplies' known number (from CRM, not from the email)
    Confirm: They did NOT send a banking change request
    Confirm: Their bank account has not changed
    Update ticket: CONFIRMED FRAUD, not legitimate change request
  
  Task 2: Assess if Bob acted on the email before quarantine
    Query: Was the email opened before quarantine? (T+15s delay — did Bob read it?)
    Query: Did Bob initiate any wire transfers in the last 30 minutes?
    Query: Did Bob reply to the email?
    Result: Email delivered at T+0s, quarantined at T+47s. 47-second window.
    Bob's calendar: In a meeting during T+0s to T+47s window. Did not read.
    
  Task 3: Threat hunt — did others receive similar emails?
    Query all email logs for last 48 hours:
      WHERE sender_domain SIMILAR TO '%apexsuppl%'
      OR sender_domain SIMILAR TO '%apexsupp%'
    Results: Only Bob received this specific domain.
    Expand search: Any other wire instruction emails received this week?
    Results: 2 additional suspicious emails to AR team → open new tickets
    
  Task 4: Executive notification decision (human judgment required)
    This crossed a financial threshold ($2.3M potential loss)
    Decision: Yes, notify VP Finance and General Counsel per policy
    Action: Send executive brief (authored by AI, reviewed by analyst)
```

---

### Scenario B: Authorized Red Team — AI-Assisted Spear Phishing Simulation

*Note: This describes an authorized security assessment with written authorization, using the organization's own red team against its own employees, for the purpose of testing defenses and training employees.*

```
CONTEXT: Authorized Red Team Exercise
  Authorization: Signed Rules of Engagement document
  Scope: All Acme Corp employees except C-suite (separate approval required)
  Duration: 2 weeks
  Goal: Test detection rate of social engineering defenses
  Out-of-scope: ANY actual compromise or data access

Red Team Platform: Internal tool running on air-gapped red team network
AI Model: Fine-tuned LLM for phishing simulation (internal, no cloud)

Phase 1: OSINT Collection (Automated)
  The platform ingests publicly available data:
    LinkedIn: Employee list, roles, connections, recent posts
    Company website: Org chart, press releases, leadership team
    Job postings: Technology stack, vendors, current projects
    Recent news: M&A activity, product launches, financial reports
    Conference attendance: Speaking engagements, topics of interest
  
  AI synthesizes a target profile for each employee:
    {
      "target": "alice.johnson@acme.com",
      "title": "Senior Engineer, Infrastructure",
      "interests": ["Kubernetes", "FinOps", "AWS"],
      "recent_linkedin_posts": ["Excited about our new K8s migration!"],
      "known_colleagues": ["bob.smith@acme.com", "carol.jones@acme.com"],
      "vendor_relationships": ["AWS", "HashiCorp", "Datadog"],
      "conference": "KubeCon 2024 speaker",
      "pretext_score": {  // Which pretext would be most convincing?
        "aws_cost_alert": 0.85,
        "kubernetes_cve": 0.91,
        "colleague_request": 0.78
      }
    }

Phase 2: Pretext Generation (AI-Assisted)
  Human red teamer reviews AI-generated pretexts and selects one.
  HUMAN APPROVAL REQUIRED before any email is sent.
  
  AI suggests (human reviews and approves before sending):
  "Subject: [SECURITY] Critical Kubernetes CVE affecting your cluster
   
   Hi Alice,
   
   Following up on your KubeCon talk — our security team identified that
   the Kubernetes version you mentioned in your presentation is affected
   by CVE-2024-XXXX. This is rated CRITICAL (CVSS 9.8).
   
   I've attached the internal remediation guide our team prepared.
   Can you confirm your cluster version so I can flag if you're impacted?
   
   [Red team tracking link — not real malware, just beacon]
   
   Best,
   David Park
   Security Operations"
  
  Human red teamer decision: APPROVE with modification
  [Red teamer edits pretext to increase realism, removes inaccuracies]

Phase 3: Send and Track (Within Authorized Scope)
  Email sent from authorized red team domain (not spoofing)
  Tracking pixel embedded (logs if email opened)
  Tracking link embedded (logs if clicked — goes to training page, not attack)
  
  Metrics collected:
    Open rate: Did Alice open the email?
    Click rate: Did Alice click the link?
    Credential submission rate: Did Alice enter credentials at the training page?
    Report rate: Did Alice report to the SOC?
    
  SOC is in DETECTION MODE (knows exercise is running, tests their detection)
  Goal: Can the SOC detect this as an authorized phishing simulation?
```

---

## 2. Data Ingestion & Telemetry Architecture

### STIX/TAXII Threat Intelligence Ingestion

```
STIX 2.1 DATA MODEL (Structured Threat Information Expression):

Core objects relevant to social engineering:
  
  Indicator: A pattern that identifies malicious activity
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--[uuid]",
      "name": "BEC Domain Homoglyph Pattern",
      "pattern": "[domain-name:value MATCHES '^apex[^a-z]*suppl']",
      "pattern_type": "stix",
      "valid_from": "2024-11-15T00:00:00Z",
      "labels": ["malicious-activity", "bec", "homoglyph"],
      "confidence": 85,
      "indicator_types": ["malicious-activity"]
    }
  
  Threat Actor: An adversary group
    {
      "type": "threat-actor",
      "id": "threat-actor--[uuid]",
      "name": "TA4231",
      "threat_actor_types": ["criminal"],
      "sophistication": "advanced",
      "resource_level": "criminal-infrastructure",
      "primary_motivation": "financial-gain"
    }
  
  Campaign: A coordinated attack series
    {
      "type": "campaign",
      "id": "campaign--[uuid]",
      "name": "Q4-2024-BEC-Campaign",
      "description": "BEC campaign targeting finance teams via homoglyph domains",
      "first_seen": "2024-10-01T00:00:00Z"
    }
  
  Relationship: Links between objects
    {
      "type": "relationship",
      "relationship_type": "uses",
      "source_ref": "threat-actor--[uuid]",
      "target_ref": "indicator--[uuid]"
    }

TAXII 2.1 PROTOCOL (Trusted Automated eXchange of Intelligence Information):
  
  Collections: Named sets of STIX objects
  Discovery endpoint: GET /taxii/  → lists available API roots
  Collection endpoint: GET /api1/collections/  → lists collections
  Objects endpoint: GET /api1/collections/{id}/objects/  → get STIX objects
  
  Authentication: OAuth 2.0 or API key
  Transport: HTTPS only
  Format: application/stix+json;version=2.1
  
  Polling pattern (pull):
    Platform polls TAXII server every 5 minutes for new IOCs
    Incremental fetch: GET /objects/?added_after={last_fetch_timestamp}
    
  Publishing pattern (push):
    When we detect new IOC: POST to our TAXII server
    Partner organizations pull from our server
    FS-ISAC integration: Automatic sharing with financial sector
```

### Email Telemetry Parsing Pipeline

```python
"""
EMAIL FEATURE EXTRACTION PIPELINE:

Input: Raw email with headers
Output: Feature vector for ML model

Key features extracted:
"""

class EmailFeatureExtractor:
    
    def extract_domain_features(self, sender_email: str, known_vendors: dict) -> dict:
        """
        Detect homoglyph domains, typosquatting, cousin domains.
        """
        sender_domain = sender_email.split("@")[1]
        features = {}
        
        # Normalize: Map visually similar Unicode characters to ASCII
        normalized = self.unicode_normalize(sender_domain)
        # Example: "apexsupp[I]ies.com" → "apexsuppIies.com" → detect I vs l
        
        for vendor_name, vendor_domain in known_vendors.items():
            # Edit distance (Levenshtein) between sender and known vendor
            edit_distance = levenshtein(normalized, vendor_domain)
            features[f"edit_dist_{vendor_name}"] = edit_distance
            
            # Jaro-Winkler similarity (better for short strings, prefix-weighted)
            jaro_sim = jaro_winkler(normalized, vendor_domain)
            features[f"jaro_sim_{vendor_name}"] = jaro_sim
            
            # Homoglyph detection: Check for visually identical but different Unicode
            homoglyph_score = self.homoglyph_compare(sender_domain, vendor_domain)
            features[f"homoglyph_{vendor_name}"] = homoglyph_score
        
        # Domain registration age
        whois_data = self.whois_lookup(sender_domain)
        features["domain_age_days"] = (datetime.now() - whois_data.creation_date).days
        
        # MX record analysis (does domain have valid mail infrastructure?)
        mx_records = self.get_mx_records(sender_domain)
        features["has_valid_mx"] = len(mx_records) > 0
        
        return features
    
    def extract_nlp_features(self, email_body: str) -> dict:
        """
        NLP analysis for social engineering patterns.
        """
        features = {}
        
        # Urgency language detection
        urgency_patterns = [
            r"\b(urgent|immediately|asap|right away)\b",
            r"\b(today|by end of day|by tomorrow)\b",
            r"\b(deadline|closes|expires)\b"
        ]
        features["urgency_score"] = sum(
            len(re.findall(p, email_body, re.IGNORECASE)) 
            for p in urgency_patterns
        ) / len(email_body.split())
        
        # Financial action keywords
        financial_patterns = [
            r"\b(wire transfer|bank account|routing number|swift)\b",
            r"\b(payment|invoice|overdue|outstanding)\b",
            r"\b(updated.*banking|new.*account|changed.*details)\b"
        ]
        features["financial_action_score"] = sum(
            len(re.findall(p, email_body, re.IGNORECASE))
            for p in financial_patterns
        )
        
        # Authority appeals
        authority_patterns = [
            r"\b(CEO|CFO|president|director|management)\b",
            r"\b(legal|compliance|audit|regulatory)\b",
            r"\b(confidential|do not forward|sensitive)\b"
        ]
        features["authority_appeal_score"] = sum(
            len(re.findall(p, email_body, re.IGNORECASE))
            for p in authority_patterns
        )
        
        # Use LLM for semantic understanding (fine-tuned classifier)
        llm_classification = self.llm_classifier.classify(
            email_body,
            categories=["LEGITIMATE", "PHISHING", "BEC", "VISHING_FOLLOWUP", "PRETEXTING"]
        )
        features["llm_category"] = llm_classification.top_category
        features["llm_confidence"] = llm_classification.confidence
        
        return features
    
    def extract_relationship_features(self, sender: str, recipient: str, 
                                      org_email_history: list) -> dict:
        """
        Historical relationship analysis.
        """
        sender_domain = sender.split("@")[1]
        
        # Count historical emails from this domain
        domain_history = [e for e in org_email_history 
                         if e["sender_domain"] == sender_domain]
        
        # Count from this exact address
        address_history = [e for e in org_email_history 
                          if e["sender"] == sender]
        
        return {
            "prior_emails_domain": len(domain_history),
            "prior_emails_address": len(address_history),
            "first_contact_with_address": len(address_history) == 0,
            "first_contact_with_domain": len(domain_history) == 0,
            "avg_email_volume_weekly": len(domain_history) / 52 if domain_history else 0,
            "recipient_has_responded": any(
                e["sender"] == recipient for e in domain_history
            )
        }
```

### Multi-Source Telemetry Correlation

```
TELEMETRY SOURCES AND CORRELATION:

Source 1: Email gateway (Microsoft 365 / Google Workspace)
  Data: Full headers, body, attachments, delivery metadata
  Latency: 5-30 seconds
  Volume: 500K emails/day for a 50K employee org

Source 2: DNS logs (passive DNS)
  Data: All DNS queries from corporate network
  Correlation: Did someone click a link? Did DNS resolve a suspicious domain?
  Detection: If "apexsuppIies.com" resolves → someone may have clicked
  
Source 3: Web proxy logs
  Data: HTTP/HTTPS connections from corporate devices
  Correlation: Did someone visit the suspicious domain?
  Note: HTTPS is encrypted but hostname visible via SNI

Source 4: Endpoint telemetry (EDR)
  Data: Process creation, file writes, network connections, registry changes
  Correlation: After clicking a link, did a process launch?
  
Source 5: Identity and authentication logs (Azure AD / Okta)
  Data: Login events, MFA responses, token issuance
  Correlation: Did the target's account show unusual access after the email?
  Detection: Password reset after phishing → likely compromise

Source 6: DLP (Data Loss Prevention) logs
  Data: File access, email attachments, clipboard activity
  Correlation: Did the target share sensitive files after phishing?

CORRELATION ENGINE (Elasticsearch/Splunk):

  Correlated alert: "BEC + Click + Authentication Change"
  
  Query:
  {
    "query": {
      "bool": {
        "must": [
          {"match": {"alert_type": "BEC_HIGH_CONFIDENCE"}},
          {"range": {"@timestamp": {"gte": "now-30m"}}}
        ]
      }
    }
  }
  
  Join with DNS logs:
  SELECT * FROM dns_logs 
  WHERE query_domain LIKE '%apexsupp%'
  AND timestamp BETWEEN [alert_time] AND [alert_time + 1h]
  AND source_ip IN (SELECT ip FROM recipients_of_this_email)
  
  Join with auth logs:
  SELECT * FROM auth_logs
  WHERE user IN (SELECT recipients FROM alert)
  AND event_type IN ('PASSWORD_RESET', 'MFA_CHANGE', 'NEW_DEVICE_LOGIN')
  AND timestamp BETWEEN [alert_time] AND [alert_time + 4h]
```

---

## 3. Automation & Orchestration Engine

### SOAR Platform Architecture

```
SOAR PLATFORM COMPONENTS:

1. TRIGGER LAYER: What initiates a playbook?
   - SIEM alert (score threshold exceeded)
   - Threat intel feed update (new IOC matching existing indicators)
   - Manual analyst trigger (analyst thinks something looks suspicious)
   - Scheduled tasks (daily threat hunt queries)
   - Webhook (external service callback)

2. DECISION ENGINE: What playbook runs?
   - Alert type mapping: Each alert type → one or more candidate playbooks
   - Risk scoring: High-score alerts → more aggressive automated response
   - Context enrichment: Before decisions, collect additional context
   - Approval routing: High-impact actions → human approval queue

3. ACTION LAYER: What does the playbook DO?
   - Email platform API: quarantine, block, redirect
   - Identity provider API: suspend account, require MFA re-enrollment
   - Firewall/proxy API: block domains, IPs, URLs
   - Ticket system API: create/update/close incidents
   - Notification API: Slack, email, PagerDuty
   - SIEM API: create watchlists, search logs
   - Threat intel API: submit IOCs, query reputation

4. STATE MANAGEMENT: How is progress tracked?
   - Playbook execution log: Every action, result, timestamp
   - Human approval queue: Pending decisions with context
   - Rollback log: For every automated action, record how to undo it
   - Evidence store: Preserved artifacts for forensics
```

### Playbook State Machine

```
BEC FINANCIAL CRITICAL PLAYBOOK STATE MACHINE:
════════════════════════════════════════════════════════════════════

TRIGGER: BEC_FINANCIAL alert, score ≥ 85

                        ┌─────────────────┐
                        │   ALERT_RECEIVED │
                        └────────┬─────────┘
                                 │
                                 ▼
                   ┌─────────────────────────────┐
                   │  ENRICH                       │
                   │  - WHOIS domain age           │
                   │  - Email history query        │
                   │  - Threat intel lookup        │
                   │  - Recipient risk profile     │
                   └─────────────────────────────┬─┘
                                                  │ Enrichment complete
                                                  ▼
                                    ┌─────────────────────┐
                                    │  SCORE_DECISION      │
                                    └──────────┬──────────┘
                                               │
                    ┌──────────────────────────┼──────────────────────────┐
                    │ Score 85-94              │ Score 95-100             │ Score <85
                    ▼                          ▼                          ▼
          ┌──────────────────┐    ┌────────────────────────┐   ┌─────────────────┐
          │  AUTO_QUARANTINE │    │  AUTO_QUARANTINE +      │   │   MONITOR       │
          │  + HUMAN_REVIEW  │    │  AUTO_BLOCK +           │   │   (no action)   │
          │                  │    │  INSTANT_ALERT          │   └─────────────────┘
          │  SLA: 30min      │    │                         │
          │  human response  │    │  No human approval      │
          └────────┬─────────┘    │  required               │
                   │              └───────────────┬──────────┘
                   │                              │
                   ▼                              ▼
          ┌──────────────────┐    ┌────────────────────────┐
          │  HUMAN_DECISION  │    │  PARALLEL_ACTIONS       │
          │                  │    │  [executed concurrently]│
          │  Options:        │    │                         │
          │  - CONFIRM_BEC   │    │  A: Quarantine email   │
          │  - FALSE_POSITIVE│    │  B: Block domain       │
          │  - ESCALATE      │    │  C: Alert recipient    │
          │  - INVESTIGATE   │    │  D: Alert finance mgr  │
          └───────┬──────────┘    │  E: Share TI feed      │
                  │               │  F: Create ticket       │
                  │               │  G: Preserve evidence   │
                  ▼               └───────────────┬──────────┘
          ┌──────────────────┐                    │
          │  IF CONFIRMED_BEC│                    ▼
          │  → EXECUTE_FULL  │    ┌────────────────────────┐
          │    BLOCK         │    │  HUMAN_VALIDATION       │
          │  IF FALSE_POS    │    │  (Tier 2 analyst)       │
          │  → ROLLBACK_ALL  │    │  SLA: 30 minutes        │
          │    LOG_FP        │    └───────────────┬──────────┘
          └──────────────────┘                    │
                                                  ▼
                                   ┌────────────────────────┐
                                   │  CLOSE_OR_ESCALATE     │
                                   │                        │
                                   │  IF resolved: Close    │
                                   │  IF unresolved:        │
                                   │    Escalate to Tier 3  │
                                   │    + Executive brief   │
                                   └────────────────────────┘
```

### Orchestration Architecture Diagram

```
AI-POWERED SOCIAL ENGINEERING DETECTION — ORCHESTRATION ARCHITECTURE
═══════════════════════════════════════════════════════════════════════════════

EXTERNAL SOURCES                        INGESTION LAYER
┌─────────────────┐                ┌───────────────────────────────────────┐
│ Email Gateways  │──Graph API────►│  Telemetry Normalization              │
│ (M365, GSuite)  │                │  - Email feature extraction           │
├─────────────────┤                │  - NLP classification (fine-tuned LLM)│
│ STIX/TAXII Feeds│──HTTPS────────►│  - Threat intel enrichment            │
│ (FS-ISAC,       │                │  - Domain/IP reputation               │
│  MITRE ATT&CK)  │                │  - Relationship history query         │
├─────────────────┤                └───────────────────┬───────────────────┘
│ Passive DNS     │──Splunk API───►                    │
├─────────────────┤                                    ▼
│ Web Proxy Logs  │──Syslog───────►    ┌───────────────────────────────┐
├─────────────────┤                    │  SIEM CORRELATION ENGINE      │
│ EDR Platform    │──API──────────►    │  (Splunk/Elastic)             │
│ (CrowdStrike)   │                    │  - Multi-source correlation    │
├─────────────────┤                    │  - Behavioral baseline         │
│ Identity Provider│─SCIM/API─────►    │  - Anomaly scoring             │
│ (Okta/Azure AD) │                    │  - Alert deduplication         │
└─────────────────┘                    └───────────────┬───────────────┘
                                                       │ Alert (score, context)
                                                       ▼
                          ┌────────────────────────────────────────────────┐
                          │       SOAR ORCHESTRATION PLATFORM              │
                          │       (Splunk SOAR / Palo Alto XSOAR)          │
                          │                                                 │
                          │  ┌─────────────┐    ┌──────────────────────┐  │
                          │  │  Playbook   │    │  AI Decision Engine  │  │
                          │  │  Engine     │◄───│  - Risk scoring      │  │
                          │  │             │    │  - Action selection  │  │
                          │  │  State      │    │  - False pos. filter │  │
                          │  │  machine    │    │  - Confidence bound  │  │
                          │  └──────┬──────┘    └──────────────────────┘  │
                          │         │                                       │
                          │         ▼                                       │
                          │  ┌─────────────────────────────────────────┐  │
                          │  │  ACTION ROUTER                           │  │
                          │  │                                          │  │
                          │  │  High confidence (auto):                │  │
                          │  │  → Email quarantine API                 │  │
                          │  │  → Domain block API                     │  │
                          │  │                                          │  │
                          │  │  Medium confidence (human-in-loop):     │  │
                          │  │  → Analyst approval queue              │  │
                          │  │  → Present evidence, request decision  │  │
                          │  │                                          │  │
                          │  │  Low confidence (observe):              │  │
                          │  │  → Add to watchlist                    │  │
                          │  │  → Increase monitoring sensitivity     │  │
                          │  └──────┬─────────────────────────────────┘  │
                          └─────────┼──────────────────────────────────────┘
                                    │
          ┌─────────────────────────┼──────────────────────────────────┐
          │                         │                                    │
          ▼                         ▼                                    ▼
┌──────────────────┐    ┌────────────────────────┐         ┌──────────────────────┐
│  SECURITY TOOLS  │    │  COMMUNICATION TOOLS    │         │  EVIDENCE & AUDIT   │
│                  │    │                         │         │                      │
│  M365 Graph API  │    │  Slack/Teams API        │         │  Immutable S3 store  │
│  (email control) │    │  (analyst alerts)       │         │  (email + metadata)  │
│                  │    │                         │         │                      │
│  Exchange Online │    │  PagerDuty API          │         │  Ticket system       │
│  Protection API  │    │  (on-call escalation)   │         │  (ServiceNow/Jira)   │
│  (block rules)   │    │                         │         │                      │
│                  │    │  Email API              │         │  Audit log           │
│  Palo Alto PA    │    │  (executive brief)      │         │  (every action,      │
│  Firewall API    │    │                         │         │  who, what, when)    │
│  (URL block)     │    │  Analyst dashboard      │         │                      │
│                  │    │  (case management)      │         │  TAXII publish       │
│  Okta API        │    │                         │         │  (IOC sharing)       │
│  (account lock)  │    └────────────────────────┘         └──────────────────────┘
└──────────────────┘
```

---

## 4. Execution Mechanics

### Defense: SOAR API Integration Details

```python
"""
SOAR PLAYBOOK ACTION IMPLEMENTATIONS:
"""

class EmailQuarantineAction:
    """
    Quarantine an email from a user's mailbox via Microsoft Graph API.
    """
    
    def __init__(self, graph_client):
        self.client = graph_client
        self.rollback_registry = RollbackRegistry()
    
    def execute(self, message_id: str, user_id: str) -> ActionResult:
        # Step 1: Move message to quarantine folder
        try:
            result = self.client.post(
                f"/v1.0/users/{user_id}/messages/{message_id}/move",
                json={"destinationId": "quarantine"},
                headers={"Authorization": f"Bearer {self.get_token()}"}
            )
            
            if result.status_code != 201:
                return ActionResult(
                    success=False, 
                    error=f"API returned {result.status_code}: {result.text}"
                )
            
            moved_message_id = result.json()["id"]
            
            # Step 2: Register rollback action (in case of false positive)
            self.rollback_registry.register(
                action_id=uuid4(),
                rollback_fn=self.rollback,
                rollback_args={
                    "user_id": user_id,
                    "message_id": moved_message_id,
                    "destination": "inbox"
                },
                ttl_hours=48  # Rollback available for 48 hours
            )
            
            # Step 3: Log action for audit
            audit_log.write({
                "action": "EMAIL_QUARANTINE",
                "message_id": message_id,
                "user_id": user_id,
                "executed_by": "SOAR_PLAYBOOK_BEC_CRITICAL",
                "timestamp": datetime.utcnow().isoformat(),
                "result": "SUCCESS",
                "rollback_available": True
            })
            
            return ActionResult(success=True, data={"moved_to": "quarantine"})
        
        except Exception as e:
            audit_log.write({"action": "EMAIL_QUARANTINE", "result": "FAILED", "error": str(e)})
            return ActionResult(success=False, error=str(e))
    
    def rollback(self, user_id: str, message_id: str, destination: str):
        """Restore email to inbox if action was incorrect."""
        self.client.post(
            f"/v1.0/users/{user_id}/messages/{message_id}/move",
            json={"destinationId": destination}
        )


class DomainBlockAction:
    """
    Block a domain in Exchange Online Protection and Palo Alto firewall.
    Implements dry-run mode for testing.
    """
    
    PROTECTED_DOMAINS = [
        "microsoft.com", "google.com", "amazonaws.com",
        # List of business-critical domains that should NEVER be auto-blocked
    ]
    
    def execute(self, domain: str, dry_run: bool = False) -> ActionResult:
        # Safety check: Never auto-block critical infrastructure
        if domain in self.PROTECTED_DOMAINS or self._is_critical_tld(domain):
            return ActionResult(
                success=False,
                error=f"SAFETY HALT: {domain} is on protected domain list",
                requires_human_approval=True
            )
        
        # Check if domain serves any current legitimate traffic
        traffic_check = self.check_current_traffic(domain)
        if traffic_check.active_sessions > 100:
            # More than 100 active sessions → likely a legitimate shared service
            return ActionResult(
                success=False,
                error=f"SAFETY HALT: {domain} has {traffic_check.active_sessions} active sessions",
                requires_human_approval=True
            )
        
        if dry_run:
            return ActionResult(success=True, data={"mode": "dry_run", "would_block": domain})
        
        # Execute block in Exchange Online Protection
        eop_result = self._block_in_eop(domain)
        
        # Execute block in Palo Alto firewall
        palo_result = self._block_in_firewall(domain)
        
        # Log for audit trail
        audit_log.write({
            "action": "DOMAIN_BLOCK",
            "domain": domain,
            "eop_result": eop_result.status,
            "firewall_result": palo_result.status,
            "active_sessions_at_block": traffic_check.active_sessions,
            "timestamp": datetime.utcnow().isoformat()
        })
        
        return ActionResult(success=True, data={
            "domain": domain,
            "blocked_in": ["exchange_online", "palo_alto_firewall"]
        })
```

### Red Team: AI-Assisted Pretext Generation (Authorized Testing)

```python
"""
AUTHORIZED RED TEAM PRETEXT GENERATION SYSTEM:

This system is used ONLY for authorized security assessments.
Requirements: Signed Rules of Engagement document, written authorization,
              out-of-scope list, emergency stop procedures, legal review.

All simulated attacks:
  - Use clearly marked red team domains (not spoofed real domains)
  - Link to training pages, not actual attack infrastructure
  - Do not collect real credentials (training page only shows educational content)
  - Are immediately disclosed to participants who report them
"""

class AuthorizedRedTeamPretextEngine:
    """
    Generates realistic but clearly-scoped social engineering pretexts
    for authorized security awareness testing.
    REQUIRES: Signed authorization before any generation.
    """
    
    def __init__(self, authorization_doc: str):
        self.verify_authorization(authorization_doc)
        self.authorized = True
        self.scope = self.parse_scope(authorization_doc)
    
    def generate_pretext(self, target_profile: dict, pretext_type: str) -> Pretext:
        """
        Generate a realistic pretext for security awareness testing.
        Returns pretext for HUMAN REVIEW before any use.
        """
        assert self.authorized, "Authorization verification failed"
        assert target_profile["email"] in self.scope["targets"], \
            f"Target {target_profile['email']} not in authorized scope"
        
        # AI generates contextually relevant pretext
        # Using internal fine-tuned model (not external API — keeps data internal)
        prompt = f"""
        Generate a realistic social engineering pretext for authorized security testing.
        
        Target context:
        - Name: {target_profile["name"]}
        - Role: {target_profile["title"]}
        - Known interests: {target_profile["interests"]}
        - Recent activities: {target_profile["recent_activities"]}
        
        Pretext type: {pretext_type}
        
        Requirements:
        - Realistic but uses our authorized testing domain, not spoofed domains
        - Tracking link must go to security awareness training page
        - Must not collect actual credentials
        - Must be technically plausible for this target's role
        
        The pretext will be REVIEWED BY A HUMAN before any use.
        """
        
        generated = self.llm.generate(prompt, max_tokens=500)
        
        # MANDATORY: Every pretext requires human approval
        pretext = Pretext(
            content=generated,
            target=target_profile["email"],
            type=pretext_type,
            status="PENDING_HUMAN_APPROVAL",  # Cannot send without this changing
            generated_at=datetime.utcnow(),
            authorization_doc=authorization_doc
        )
        
        # Store in approval queue — human must review and click APPROVE
        self.approval_queue.add(pretext)
        
        return pretext  # Returns in PENDING state — cannot be sent yet
    
    def human_approve(self, pretext_id: str, approver: str, modifications: str = None):
        """Human approval gate — required before any pretext can be sent."""
        pretext = self.approval_queue.get(pretext_id)
        
        if approver not in self.scope["authorized_approvers"]:
            raise PermissionError(f"{approver} not authorized to approve pretexts")
        
        if modifications:
            pretext.content = modifications  # Allow human to edit/improve
        
        pretext.status = "APPROVED"
        pretext.approved_by = approver
        pretext.approved_at = datetime.utcnow()
        
        audit_log.write({
            "event": "RED_TEAM_PRETEXT_APPROVED",
            "pretext_id": pretext_id,
            "approver": approver,
            "target": pretext.target,
            "timestamp": pretext.approved_at.isoformat()
        })
        
        return pretext
```

---

## 5. Adversarial Counter-Measures & Bypasses

### How Attackers Evade Automated Detection

```
EVASION TECHNIQUE 1: TIMING-BASED BYPASS

Problem for attacker: Email arrives → detection system quarantines in 47 seconds.
Solution: If victim reads email before 47 seconds, attack succeeds.

Attacker optimization:
  - Send at peak email volume times (Monday 9 AM, Friday 4 PM)
  - Recipient has 200+ emails in inbox → checks quickly → 30% open rate in first 30 seconds
  - Title of email: Matches recipient's expected email flow ("Invoice from Apex")
  - Victim opens → phone call immediately: "Hi, I sent you updated payment details, 
    did you get my email?" → Victim confirms → higher success rate before quarantine

Detection failure mode:
  Static quarantine timing does not adapt to how quickly recipients read emails.
  For high-risk financial emails: consider HOLD-THEN-RELEASE instead of quarantine
  (Hold email for 60 seconds, allow scanning, then deliver if clean)

EVASION TECHNIQUE 2: POLYMORPHIC IOC ROTATION

Problem for attacker: Domain blocked → all future attacks from that domain fail.
Solution: Rotate infrastructure faster than it can be blocked.

Attacker infrastructure:
  - Pre-register 100 homoglyph domains across multiple registrars
  - Automate switching: If domain appears in VirusTotal → switch to next
  - Each domain used for 1-3 emails maximum → never triggers velocity detection

Detection failure mode:
  Static blocklists cannot keep up with rotating domains.
  Requires behavior-based detection (does this email LOOK like a BEC attempt?)
  regardless of whether the domain is on a blocklist.

EVASION TECHNIQUE 3: BENIGN CONTENT + HUMAN FOLLOW-UP

Problem for attacker: NLP detects financial action keywords.
Solution: First email contains no suspicious keywords.

Phase 1 email (no flags):
  "Hi Bob, just wanted to check in on our Q4 invoice timing.
   Still working on the details — will follow up soon.
   -Michael Torres, Apex"
  
  Detection score: 15/100 (not flagged — plausible vendor check-in)
  But: Seeds the relationship, trains the model that this sender is "known"

Phase 2 email (1 week later, after history established):
  "Following up on my previous email — we've updated our banking details.
   Please use the new account for the Q4 payment."
  
  Detection score: Now has 1 prior email from this sender → lower "first contact" penalty
  The attacker manufactured a relationship to reduce detection confidence.

EVASION TECHNIQUE 4: THREAT INTELLIGENCE POISONING

Problem for attacker: Detection system uses threat intel feeds.
Solution: Contaminate the feeds with false positives.

Attack: Attacker submits STIX IOCs for LEGITIMATE domains to threat intel feeds:
  {domain: "microsoft.com", indicator_type: "malicious-activity"}
  
  If the feed is consumed without validation:
    → Detection system learns "microsoft.com" is malicious
    → All Microsoft emails blocked
    → Legitimate business communication disrupted
    → SOC overwhelmed with false positive investigation
    → Real attacks slip through during confusion
  
  Defense:
    - Weight STIX feeds by source reputation (not all feeds equal)
    - Validate IOCs against known-good lists before importing
    - Never auto-block domains with Alexa top 1M ranking (unless very specific)
    - Require IOC corroboration from multiple independent sources

EVASION TECHNIQUE 5: AI DETECTOR AWARENESS

Problem for attacker: NLP classifier detects urgency + financial language.
Solution: Write phishing content that evades classifiers.

AI-generated "low-perplexity" phishing:
  Attacker uses an LLM to generate phishing content that:
    - Scores low on urgency metrics (no "URGENT", "IMMEDIATELY")
    - Avoids direct financial action requests (asks to "confirm" not "send")
    - Uses language consistent with legitimate business communication
    - Is semantically equivalent but lexically different from training examples
  
  "As discussed in our vendor review, I'm reaching out regarding 
   our upcoming quarterly payment. Our financial team has coordinated 
   a new account effective this month — please confirm receipt 
   of the attached details so our reconciliation team can proceed."
  
  vs traditional (detected):
  "URGENT: Updated banking details — please wire payment immediately"
  
  The semantic intent is identical. The lexical signature is very different.
  This is the "adversarial example" problem applied to text.
```

---

## 6. Security Controls & System Integrity

### Protecting the SOAR Platform Itself

```
SOAR PLATFORM IS A HIGH-VALUE TARGET:
  - Has API access to quarantine emails platform-wide
  - Has API access to block domains and IPs
  - Has API access to lock user accounts
  - Knows all IOCs (valuable intelligence)
  - Has access to all investigation data
  
  If SOAR is compromised: Attacker can DISABLE all automated defenses.
  Or: Attacker can block legitimate critical domains (sabotage).

SECURITY CONTROLS:

1. LEAST PRIVILEGE FOR API CREDENTIALS:
  
  Email quarantine credential:
    Scope: MailboxSettings.ReadWrite for USER's own mailbox messages
    NOT: Org-wide admin; NOT: Mail.ReadWrite (reads all mail)
    
  Domain block credential:
    Scope: Exchange.ManageAsApp for block rules only
    NOT: Organization.ReadWrite.All
    
  Firewall API credential:
    Scope: URL category update only
    NOT: Admin access to firewall config
    
  Credential storage: HashiCorp Vault (dynamic short-lived secrets)
    SOAR requests a 1-hour token on demand
    No long-lived credentials stored in SOAR config
    All credential access audited in Vault

2. API RATE LIMITING AND BLAST RADIUS CONTROLS:
  
  Per-action limits:
    Email quarantine: max 100/hour without human approval
    Domain block: max 10/hour without human approval
    Account lock: max 5/hour without human approval
    
  Rationale: If SOAR is compromised or malfunctions,
    these limits cap the damage before humans notice.
  
  Exceeding limits → human approval required → auto-actions halt.

3. IMMUTABLE AUDIT LOG:
  
  Every SOAR action writes to:
    - Local Elasticsearch (for fast search)
    - S3 with Object Lock WORM (immutable, 7-year retention)
    - SIEM (for real-time monitoring of SOAR itself)
  
  Any attempt to delete or modify audit logs → immediate alert.

4. NETWORK ISOLATION:
  
  SOAR platform: Dedicated network segment
  Only inbound connections: From analysts (VPN + MFA required)
  Only outbound connections: To explicitly allowlisted API endpoints
    microsoft.com:443 (M365 APIs)
    splunk-internal.acme.com:8089 (SIEM queries)
    vault.acme-internal.com:8200 (secrets)
    [no general internet access]

5. HUMAN-IN-THE-LOOP GATES:
  
  Actions that ALWAYS require human approval regardless of confidence:
    - Blocking any domain with current active traffic > 100 users
    - Locking any VIP/executive account
    - Any action affecting more than 50 users simultaneously
    - Any action on a domain in the allowlist
    - Any rollback of a previous action
  
  High-confidence actions that are auto-executed:
    - Quarantine single email to non-executive user
    - Block freshly-registered (< 7 day) domain with no legitimate traffic
    - Submit IOC to threat intel (publishing, not blocking)
    - Create incident ticket and notify analyst
```

### Guardrails for Authorized AI Red Team Tools

```
AUTHORIZED RED TEAM AI GUARDRAILS:

1. SCOPE ENFORCEMENT (TECHNICAL):
  
  The red team system maintains a signed scope document:
  {
    "engagement_id": "RT-2024-Q4-001",
    "authorized_targets": ["*@acme.com"],  # All Acme employees
    "excluded_targets": ["ceo@acme.com", "coo@acme.com"],  # No exec attacks without separate auth
    "authorized_pretexts": ["phishing", "vishing_simulation", "usb_drop"],
    "out_of_scope": ["actual_malware", "credential_theft", "data_exfil"],
    "authorized_from": "2024-11-01",
    "authorized_until": "2024-11-30",
    "emergency_stop_contact": "redteam-stop@acme.com",
    "document_hash": "sha256:abc123...",
    "signature": "[cryptographic signature from security leadership]"
  }
  
  System enforces: Cannot send to excluded_targets.
  System enforces: Cannot use pretexts not in authorized list.
  System enforces: All links go to training domain, not attacker infrastructure.
  System enforces: No real credential collection.

2. KILL SWITCH:
  
  Email to redteam-stop@acme.com → immediately halts ALL campaign activities.
  No ongoing simulations survive a kill switch activation.
  Any team member can trigger the kill switch.

3. REAL-TIME SOC NOTIFICATION:
  
  SOC knows the exercise is running (tests detection, not SOC knowledge).
  SOC gets real-time feed of what's being sent and to whom.
  If a simulated email causes actual user distress: SOC can intervene immediately.
  
  Red team visibility feed:
  {
    "type": "AUTHORIZED_SIMULATION",
    "timestamp": "2024-11-15T10:00:00Z",
    "target": "alice.johnson@acme.com",
    "pretext_type": "it_security_cve",
    "from_domain": "acme-sectest.com",  # Clearly labeled test domain
    "tracking_link": "https://acme-sectest.com/track/abc123"
  }
```

---

## 7. Attack Surface Mapping

### Attack Surface of the Detection Platform Itself

```
SOAR/THREAT INTEL PLATFORM ATTACK SURFACE
══════════════════════════════════════════════════════════════════════

EXTERNAL ATTACK SURFACE:
════════════════════════
[E1] SOAR Web Interface (analyst dashboard)
  Port: 443 (HTTPS)
  Auth: SSO + MFA required
  Threats: Credential theft, session hijacking, XSS
           Compromised analyst account → full SOAR access

[E2] SOAR REST API (for integrations)
  Port: 443 (HTTPS)
  Auth: API keys (should be rotated monthly)
  Threats: API key exfiltration, unauthorized playbook execution
           Key in code repository → attacker can execute actions

[E3] Inbound Webhooks (for alerts from external sources)
  Example: VirusTotal webhook when a URL matches
  Port: 443 (HTTPS), dedicated endpoint
  Threats: Webhook forgery → inject fake alerts → trigger incorrect actions
  Control: Shared secret HMAC validation on all webhooks

[E4] STIX/TAXII Ingest (threat intelligence)
  Protocol: HTTPS to TAXII server
  Threats: Compromised threat feed → inject false IOCs
           Poison STIX data → cause legitimate services to be blocked
  Control: Feed reputation scoring, corroboration requirements

[E5] Email submission portal (analysts submit suspicious emails)
  Threats: Malicious attachments submitted for analysis
           Analysis infrastructure compromised by malicious email content
  Control: Sandboxed email analysis (no direct execution), static analysis only

INTERNAL ATTACK SURFACE:
════════════════════════
[I1] SOAR-to-API integrations (all outbound API calls)
  Credential store (Vault)
  If Vault is compromised → all API credentials exposed

[I2] Analyst workstations (humans who use the SOAR platform)
  Compromised analyst → legitimate SOAR access for attacker
  Social engineering of analysts → the defenders become the attack vector

[I3] ML models used for detection
  If models can be poisoned → detection quality degrades silently
  Gradual model drift → false negative rate increases → attacks succeed more

[I4] Threat intelligence database
  Historical IOCs, attack patterns, actor TTPs
  If exfiltrated → attacker knows what detection signatures exist
  Can avoid known-bad indicators and patterns

[I5] Playbook logic and configurations
  If attacker reads playbooks → knows exactly how long to wait for automation
  Knows which actions trigger human review vs automatic blocking
  Can optimize attack timing to avoid detection windows

TRUST BOUNDARY DIAGRAM:
═══════════════════════

INTERNET (Zero Trust)
    │
    │ [E1][E2] Analyst access (SSO + MFA)
    │ [E3] Webhooks (HMAC validated)
    │ [E4] STIX/TAXII ingest (reputation-weighted)
    ▼
┌────────────────────────────────────────────────────────┐
│ DMZ / API Gateway [TB-1]                              │
│ WAF, rate limiting, auth validation                   │
│ TLS termination, certificate pinning for integrations │
└──────────────────────────┬─────────────────────────────┘
                           │
┌──────────────────────────▼─────────────────────────────┐
│ SOAR PLATFORM NETWORK [TB-2]                          │
│ [I1] API credential vault (Vault, short-lived tokens) │
│ [I2] Analyst authenticated sessions                   │
│ [I3] ML inference servers (isolated from internet)    │
│ Outbound: Allowlisted endpoints only                  │
│ Inbound: Only from authenticated analysts + gateway   │
└──────────────────────────┬─────────────────────────────┘
                           │
┌──────────────────────────▼─────────────────────────────┐
│ DATA LAYER [TB-3]                                     │
│ [I4] Threat intel DB (encrypted, access logged)       │
│ [I5] Playbook config (signed, change-controlled)      │
│ Audit logs (immutable WORM storage)                   │
│ Evidence archive (immutable WORM storage)             │
└────────────────────────────────────────────────────────┘
```

---

## 8. Failure Points & Edge Cases

### Automation Run Amok — Cascading False Positives

```
FAILURE SCENARIO: Domain Block Cascade

Trigger: Attacker sends BEC email spoofing "Microsoft Azure billing"
         from a domain similar to "azure.microsoft.com"
         
Detection: Email flagged as BEC (correct)
Automated action: Block domain "microsoft.com" ← CATASTROPHIC ERROR

Why this could happen:
  - Domain extraction logic error: extracted "microsoft.com" instead of attacker domain
  - Operator misconfigured the blocklist (no allowlist protection)
  - SOAR bug: Used sender display name domain instead of actual sender domain
  
Impact if it happened:
  - All Microsoft 365 email blocked
  - SharePoint inaccessible
  - Teams blocked
  - Azure portal inaccessible
  - Depending on firewall integration: Potentially ALL Microsoft-owned IPs blocked
  
PREVENTION:
  Allowlist of NEVER-BLOCK domains:
    microsoft.com, google.com, amazon.com, salesforce.com, [business-critical list]
    + All domains in SOAR's own integration endpoints
    
  Pre-block validation:
    1. Does the domain match any entry in the allowlist? → HALT, human required
    2. Is the domain in the Alexa top 100K? → HALT, human required
    3. Does the domain currently have > 100 active sessions from internal users? → HALT
    4. Is the domain on any external "no-block" threat intel? → HALT

FAILURE SCENARIO: Account Lock Loop

  Attacker triggers false positive that locks an executive's account.
  Executive cannot work. IT unlocks the account.
  Attacker triggers false positive again. Account locked again.
  Loop: Executive's workday is disrupted by repeated lockouts.
  
  This is a DoS attack using the security system as the weapon.
  
  Prevention:
    VIP accounts: ALERT ONLY — never auto-lock executive accounts
    Require voice confirmation from IT or HR before executive account lockout
    Rate limit account lock actions: max 1 lock per account per 24 hours
    After 2 false-positive locks: EXEMPT from auto-lock, require manual only

FAILURE SCENARIO: AI Hallucination in Investigation

  Tier 2 analyst asks AI assistant to summarize investigation context:
  
  AI response: "This email is from TA4231, a known North Korean APT group
               that has conducted similar campaigns against financial firms
               in Q3 2024, including an attack on [Specific Bank]."
  
  Reality: The AI hallucinated the attribution. There is no evidence linking
           this email to TA4231 or North Korea. The similarity to that group's
           TTPs is superficial.
  
  Risk: Analyst reports to CISO that there's a North Korean APT attack.
        CISO briefs board. Legal team notified. FBI contacted.
        All based on hallucinated attribution.
  
  Prevention:
    - AI investigation summaries must include source citations for every claim
    - Confidence levels required: "HIGH/MEDIUM/LOW evidence for each assertion"
    - Attribution claims specifically: REQUIRE human analyst to verify before inclusion
    - AI output labeled: "AI-ASSISTED DRAFT — NOT VALIDATED INTELLIGENCE"
    - Before any external reporting: Senior analyst sign-off required
```

---

## 9. Mitigations & Observability

### Deployment Strategy: Monitor vs Blocking Mode

```
PHASED DEPLOYMENT APPROACH:

PHASE 1: MONITOR ONLY (Weeks 1-4)
  All detection runs in shadow mode:
  - Emails are analyzed and scored
  - Automated actions are LOGGED but NOT EXECUTED
  - Analysts see what WOULD have happened
  - Tune false positive rate to acceptable level (< 1%)
  
  Metrics tracked:
  - Would-have-quarantined: How many emails would have been quarantined?
  - Would-have-blocked: How many domains would have been blocked?
  - False positive analysis: Manual review of all would-have-quarantined emails
  
  Exit criteria for Phase 1:
  - False positive rate < 1% (< 1 in 100 flagged emails is legitimate)
  - True positive rate > 70% (catch > 70% of test phishing emails)
  - No business-critical domains in would-have-blocked list

PHASE 2: AUTO-QUARANTINE ONLY (Weeks 5-8)
  Email quarantine is automated (high confidence only, > 90 score)
  All other actions still manual
  
  Metrics:
  - Actual false positive rate (how many emails did users report as wrongly quarantined?)
  - MTTR for false positives: How quickly can analyst unquarantine legitimate emails?
  - User satisfaction: Are false positives causing business disruption?

PHASE 3: FULL AUTOMATION WITH HUMAN-IN-LOOP (Week 9+)
  All automated actions enabled with the safety gates described in Section 6
  Human-in-loop required for: domain blocks, account locks, executive-related actions
  
  SLA:
  - High confidence (>95): Automated actions within 60 seconds
  - Medium confidence (70-95): Human review within 30 minutes
  - Low confidence (<70): Flagged for next-day review

PHASE 4: CONTINUOUS IMPROVEMENT
  Monthly model retraining with new labeled data (including false positives)
  Quarterly red team exercise to test detection rates
  Annual playbook review and update
```

### Key Metrics to Track

```python
"""
METRICS DASHBOARD FOR AI SOCIAL ENGINEERING DETECTION:
"""

SOC_METRICS = {
    # Detection Quality
    "true_positive_rate": {
        "description": "Fraction of actual phishing caught",
        "target": "> 0.80",
        "alert_threshold": "< 0.60",
        "measurement": "confirmed_phishing_caught / total_confirmed_phishing",
        "frequency": "daily"
    },
    "false_positive_rate": {
        "description": "Fraction of legitimate emails incorrectly flagged",
        "target": "< 0.01",
        "alert_threshold": "> 0.05",
        "measurement": "false_pos_confirmed / total_flagged",
        "frequency": "daily"
    },
    
    # Response Speed
    "MTTR_phishing": {
        "description": "Mean Time to Respond for phishing emails",
        "target": "< 5 minutes (email to quarantine)",
        "alert_threshold": "> 15 minutes",
        "measurement": "avg(quarantine_time - email_delivery_time)",
        "frequency": "hourly"
    },
    "MTTR_BEC": {
        "description": "Mean Time to Respond for BEC attempts",
        "target": "< 10 minutes (email to analyst notified)",
        "alert_threshold": "> 30 minutes",
        "frequency": "daily"
    },
    
    # Coverage
    "social_eng_attempts_detected": {
        "description": "Attempted vs detected social engineering",
        "target": "Track trend (rising = more attacks OR better detection)",
        "frequency": "weekly"
    },
    "click_rate_on_phishing_simulations": {
        "description": "Employee susceptibility (from authorized exercises)",
        "target": "< 5% click rate",
        "alert_threshold": "> 15% click rate (training required)",
        "frequency": "per_exercise"
    },
    
    # Platform Health
    "soar_action_error_rate": {
        "description": "Fraction of automated actions that fail or error",
        "target": "< 0.1%",
        "alert_threshold": "> 1%",
        "frequency": "hourly"
    },
    "threat_intel_feed_freshness": {
        "description": "Age of most recent TI feed update",
        "target": "< 1 hour",
        "alert_threshold": "> 6 hours",
        "frequency": "continuous"
    },
    "playbook_execution_time": {
        "description": "Time from alert to all automated actions complete",
        "target": "< 60 seconds",
        "alert_threshold": "> 5 minutes",
        "frequency": "per_execution"
    },
    
    # AI Model Health
    "detection_model_drift": {
        "description": "Statistical drift in model confidence scores",
        "target": "PSI < 0.1 vs baseline",
        "alert_threshold": "PSI > 0.25 (significant drift, retrain needed)",
        "frequency": "weekly"
    },
    "reward_score_vs_human_agreement": {
        "description": "Agreement between AI detection and human review",
        "target": "Cohen's kappa > 0.8",
        "alert_threshold": "< 0.6 (model and humans disagree too often)",
        "frequency": "monthly"
    }
}
```

---

## 10. Interview Questions

### Q1: "Walk me through how an AI-powered system detects a business email compromise that passes all email authentication checks (SPF, DKIM, DMARC). What signals does it use that traditional email security misses?"

**Answer:**

Traditional email security (email authentication, blocklists, attachment scanning) fails against BEC precisely because BEC uses legitimate infrastructure. SPF, DKIM, and DMARC validate that the email came from the claimed domain and wasn't modified in transit — but they say nothing about whether that domain is itself fraudulent.

AI-based detection uses contextual signals that don't appear in the email headers:

**Domain similarity analysis:** We compute string similarity between the sender domain and known vendor domains. A human reading "apexsuppIies.com" may not notice the capital I, but Unicode normalization and homoglyph detection algorithms flag this immediately. We also check domain registration age — a vendor domain registered 3 days ago is suspicious regardless of its email authentication status.

**Relationship history:** We query our historical email database for all prior communications from this domain and this specific address. A legitimate vendor who has billed us for 24 months should have hundreds of prior emails. Zero prior emails from this exact address is a strong signal, especially combined with a financial action request.

**Content semantics:** Fine-tuned NLP classifiers detect the combination of financial action request plus urgency language plus first-contact sender — this combination is rare in legitimate business email and common in BEC. We don't rely on keyword matching; we use semantic classification that is more robust to attacker wordsmithing.

**Behavioral baseline:** The recipient's pattern of receiving wire instruction emails is part of the baseline. If Bob in accounting receives an average of zero wire instruction emails per month and suddenly receives one, that's anomalous. We correlate the email with the recipient's normal patterns, not just global patterns.

**Cross-channel correlation:** Has anyone called pretending to be this vendor recently (vishing, logged by the phone system)? Did anyone visit an unusual website yesterday that could be attacker reconnaissance? These corroborating signals increase confidence.

---

### Q2: "Explain the difference between a state machine-based SOAR playbook and an AI agent-based orchestration approach. What are the security tradeoffs?"

**Answer:**

**State machine playbooks** are explicit, deterministic decision trees. Each possible state and transition is predefined. "If alert score > 90 AND domain age < 7 days AND no email history → execute quarantine and block." The behavior is predictable, auditable, and testable. You can enumerate every path the playbook might take.

Security advantages: You can formally verify that a state machine playbook can never take an action outside its defined transitions. Audit trails are clear — every action has a specific state that triggered it. Testing is comprehensive because the state space is finite.

Security disadvantages: Novel attacks that don't match any predefined state may receive no response. State machines are brittle when attackers vary their tactics in ways that don't trigger thresholds. Maintaining playbooks requires expert knowledge and becomes complex as the threat landscape evolves.

**AI agent orchestration** uses an LLM or reinforcement learning agent to make decisions dynamically. The agent receives context (the alert, enrichment data, prior actions) and decides what to investigate or remediate next. It can chain tools flexibly, handle novel situations, and adapt to attacker behavior within a conversation.

Security advantages: Can reason about novel attack patterns. Can ask clarifying questions before acting. Can synthesize multiple weak signals into a coordinated response that no individual rule would trigger.

Security disadvantages: Behavior is not fully predictable or formally verifiable. The agent could theoretically be manipulated by data in its context (prompt injection — attacker plants instructions in the email being analyzed that redirect the agent's behavior). Agent hallucinations can lead to incorrect actions. Testing completeness is impossible (unlike state machines, the decision space is infinite).

**The right approach in production:** Use state machines for the high-confidence, high-impact automated actions (email quarantine, domain block) where predictability and auditability are essential. Use AI agents for investigation and recommendation tasks where flexibility matters but consequences of errors are limited. Apply human-in-the-loop to any AI agent recommendation that triggers a consequential action.

---

### Q3: "How would you detect and respond to an attacker who is poisoning your threat intelligence feeds to cause legitimate domains to be blocked?"

**Answer:**

Threat intel feed poisoning is an insider-perspective attack on the detection system itself. The goal is to weaponize the defender's automation against them — get the security system to block legitimate services, causing disruption.

**Detection mechanisms:**

First, we track the IOC performance of each feed. For every domain blocked based on each feed, we track: How many of those blocks were validated as true threats? How many were reversed as false positives? Feeds with high false positive rates get their confidence scores down-weighted. A sudden spike in a feed's false positive rate — especially for high-reputation domains — triggers a feed integrity alert.

Second, we require corroboration for high-impact actions. Blocking a domain that currently serves 1000 active sessions requires the IOC to appear in at least two independent feeds from different organizations. Single-source IOCs for well-known domains are held for human review.

Third, we maintain a tiered allowlist. Domains in the Alexa top 100,000 are never auto-blocked regardless of IOC data. The threat intel score is still tracked and surfaced to analysts, but the automated block action is suppressed.

**Response to a poisoning event:**

If we detect that a feed submitted false IOCs for legitimate domains: immediately suspend all actions based on that feed while maintaining existing blocks based on other feeds. Notify the feed provider's security team. Retroactively review all actions taken based on that feed in the past 30 days. For any actions that appear driven by the poisoned feed, investigate whether rollback is appropriate.

The key lesson: threat intelligence feeds are themselves an attack surface. Apply the same skepticism to external security data that you apply to external code.

---

### Q4: "Describe how an AI red team simulation (authorized) differs architecturally from actual malicious infrastructure. What prevents the simulation platform from being weaponized?"

**Answer:**

An authorized red team simulation is distinguished from actual attack infrastructure by both technical controls and governance controls that are enforced by the platform.

**Technical distinctions:**

The simulation platform sends all emails from a declared red team domain (e.g., `acme-security-test.com`) rather than spoofed or look-alike domains. This domain is registered by the organization itself and known to the email gateway. The platform does not deploy actual malware — tracking links redirect to an internal training page that simply displays an educational message. There is no credential harvesting — the "login" page on the training site does not store anything. All simulation activity is logged in real-time to a feed visible to the SOC.

**Governance controls:**

Every simulation requires a signed Rules of Engagement document before any capability is available. The platform's scope enforcement is cryptographically linked to this document — you cannot add targets outside the signed scope without modifying the document, which breaks the signature verification. Human approval gates sit between AI-generated content and any actual sending. A kill switch is available to any team member and immediately halts all campaigns.

**What prevents weaponization:**

The platform is air-gapped from production email infrastructure and can only send from its registered domain, not from arbitrary domains. API credentials for simulation are scoped to the test environment only. The LLM used for pretext generation runs internally — no prompts or outputs go to external cloud APIs that could be inspected. All outputs require human approval before sending. The system cannot send to external addresses (enforced at the network level — only internal company domains are routable from the simulation network).

Even if an adversary compromised the red team platform, they could only send emails from `acme-security-test.com` to internal employees — useful for disruption, not for stealthy credential theft at scale.

---

*Document version: 1.0 | Classification: Internal Engineering*
*Author: SOC Architecture & Red Team Lead*
*This document covers defensive AI-powered social engineering detection, SOAR architecture, and authorized security testing simulation.*
*All red team mechanics described are for authorized security assessments only.*