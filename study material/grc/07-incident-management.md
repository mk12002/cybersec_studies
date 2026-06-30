# Module 7 — Incident Management

Incident management is the discipline of detecting, responding to, and recovering from events that disrupt normal operations or compromise security — and, critically for audit purposes, demonstrating that the organization learns from incidents rather than just firefighting them repeatedly.

## 1. The Incident Lifecycle

```
Identification → Logging → Categorization → Prioritization → Escalation
        → Containment → Recovery → Closure → Post Incident Review → RCA → CAPA
```

### 1.1 Identification

The moment an incident is first detected — via automated monitoring/alerting (SIEM, IDS/IPS, application monitoring), a user report, a third-party notification, or proactive threat hunting.

**Audit/security note:** "Time to detect" (mean time to detect, MTTD) is itself a tracked metric — the longer an incident goes undetected, the greater the potential damage, especially for security incidents involving data exfiltration.

### 1.2 Logging

The incident is formally recorded in an incident management system (ServiceNow, Jira, a dedicated SOAR/SIEM case management tool) with a unique identifier, timestamp, initial description, and reporter.

### 1.3 Categorization

The incident is classified by type (e.g., security breach, system outage, data integrity issue, performance degradation) and affected system/service — this drives which team owns the response and which playbook/procedure applies.

### 1.4 Prioritization

Severity is assigned, typically based on a combination of **impact** (how many users/systems affected, business criticality) and **urgency** (how quickly it's getting worse or needs to be resolved). Most organizations use a P1-P4 or Sev1-Sev4 scale:

| Severity | Typical Definition | Example |
|---|---|---|
| P1/Sev1 (Critical) | Complete service outage or active security breach with major business/data impact | Production financial system down; confirmed ransomware execution |
| P2/Sev2 (High) | Significant degradation or contained security incident | Partial outage affecting a subset of users; malware found and isolated on one endpoint |
| P3/Sev3 (Medium) | Limited impact, workaround available | Non-critical feature broken |
| P4/Sev4 (Low) | Minimal impact, cosmetic or informational | Minor UI bug, low-risk informational security alert |

### 1.5 Escalation

Routing the incident to the appropriate team/individual with the authority and expertise to act, scaling up involvement as severity increases (e.g., a P1 typically triggers automatic notification to senior leadership, legal, and possibly external parties like a cyber insurance provider or regulators, depending on the nature of the incident).

### 1.6 Containment

Actions taken to **limit the scope and impact** of the incident before full resolution — stopping the bleeding. In security incidents, this commonly means isolating affected systems from the network, disabling compromised accounts, or blocking malicious IPs/domains, while preserving evidence for forensic investigation.

- **Short-term containment** — immediate, often temporary measures (e.g., network isolation of an infected host).
- **Long-term containment** — more durable measures while a permanent fix is prepared (e.g., temporary firewall rules while a patched system image is built).

### 1.7 Recovery

Restoring affected systems to normal operation, validated to ensure the underlying issue is actually resolved (not just masked) before systems are returned to production/live status.

### 1.8 Closure

Formal confirmation the incident is fully resolved, all stakeholders notified, and documentation completed.

### 1.9 Post Incident Review (PIR) / Post-Mortem

A structured review conducted after closure (typically for higher-severity incidents) to understand what happened, why, how effectively the response worked, and what should change going forward. Best practice (especially in mature security/SRE cultures) is a **blameless post-mortem** — focused on systemic/process causes rather than individual blame, because blame-focused reviews suppress honest reporting in future incidents.

### 1.10 Root Cause Analysis (RCA)

A structured technique to identify the **underlying, systemic cause** of an incident, not just its immediate trigger.

#### Common RCA Techniques
- **5 Whys** — repeatedly asking "why" to drill from the symptom to the root cause (e.g., "Why did the system go down?" → "The database connection pool was exhausted" → "Why?" → "A runaway query held connections open" → "Why?" → "No query timeout was configured" → "Why?" → "Timeout configuration wasn't part of the standard deployment template" — *that's* the actual root cause to fix).
- **Fishbone/Ishikawa Diagram** — categorizes potential causes (People, Process, Technology, Environment) to systematically explore contributing factors rather than fixating on the first plausible explanation.
- **Fault Tree Analysis** — a more formal, top-down logical decomposition often used for complex/high-stakes incidents.

### 1.11 CAPA (Corrective and Preventive Action)

The formal output of RCA — documented actions to (a) **correct** the immediate issue and (b) **prevent recurrence** of the root cause.

- **Corrective action** — fixes the specific instance (e.g., patch the vulnerable system).
- **Preventive action** — addresses the systemic gap so the same class of issue doesn't recur elsewhere (e.g., add the missing query timeout to the standard deployment template across ALL systems, not just the one that broke).

CAPA items should be tracked to completion with owners and due dates — an RCA that identifies a root cause but produces no tracked, completed CAPA is, from an audit perspective, an incomplete control (the organization learned the lesson but didn't act on it).

## 2. Evidence (Incident Management Specific)

- Incident ticket with full timeline (detection, escalation, containment, recovery, closure timestamps).
- Communications log (who was notified, when).
- Containment/remediation actions taken, with technical evidence (logs, screenshots).
- RCA documentation.
- CAPA tracker with completion status.
- For security incidents specifically: forensic evidence (preserved logs, memory/disk images if applicable), chain of custody documentation if the incident may involve legal/regulatory action.

## 3. Why Incident Management Matters for SOX/ITGC Audit

While incident management might seem purely operational/security-focused rather than financial-reporting-focused, it connects to ICFR in specific ways:
- A security incident affecting a financially-relevant system is itself evidence relevant to evaluating whether ITGC controls (access, change) were operating effectively — an incident is sometimes the *discovery mechanism* for a control failure that testing alone hadn't caught.
- Incident response failures (e.g., an incident not properly contained, leading to broader data integrity issues in financial systems) can directly create a material weakness in ICFR if the underlying financial data's reliability is called into question.
- Regulatory regimes increasingly require **timely incident disclosure** (e.g., SEC's 2023 cybersecurity disclosure rules requiring material cybersecurity incidents to be disclosed, generally within 4 business days of determining materiality) — meaning incident management process maturity is now directly tied to public company disclosure obligations, not just operational hygiene.

## 4. Incident Management vs. Change Management vs. Problem Management — Don't Confuse These (ITIL Terminology)

This is a common source of confusion, especially in exam/interview contexts, since these are related but distinct ITIL (IT Infrastructure Library) disciplines:

| Discipline | Focus | Goal |
|---|---|---|
| **Incident Management** | Restoring normal service ASAP | Speed — get things working again |
| **Problem Management** | Identifying and eliminating the underlying root cause of one or more incidents | Prevent recurrence (this is where RCA/CAPA formally live in ITIL terms, sometimes as a distinct "Problem Record" linked to the Incident) |
| **Change Management** | Controlling how changes are introduced to the environment (Module 6) | Risk control over modifications, including the changes made AS A RESULT of incident remediation |

In practice: an incident happens → it's resolved quickly (Incident Management) → if the root cause isn't obvious or a permanent fix requires more investigation, a **Problem Record** is opened to investigate further (Problem Management) → the permanent fix, once identified, goes through standard or emergency **Change Management** (Module 6) to actually be deployed. CAPA items frequently are the trigger that creates a formal change request.

---
**Quick Self-Check Questions**
1. Walk through the full incident lifecycle from identification to CAPA, in order.
2. What's the difference between a corrective action and a preventive action in a CAPA?
3. Why is a "blameless" post-mortem culture considered best practice rather than holding individuals accountable for incidents?
4. Distinguish Incident Management, Problem Management, and Change Management, and explain how a single real-world incident might flow through all three.
5. Why might an incident be relevant evidence in a SOX ITGC audit, even if it wasn't a "financial" incident on its face?
6. Apply the "5 Whys" technique to a hypothetical access-control-related incident (e.g., a terminated employee's account was used after termination) — what's a plausible root cause four or five "whys" deep?
