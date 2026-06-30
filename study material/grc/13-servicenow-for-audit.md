# Module 13 — ServiceNow for Audit

ServiceNow is the dominant enterprise ITSM (IT Service Management) platform and, for audit purposes, is often the **primary evidence source** for change management, incident management, and access request workflows (Module 8). This module covers it specifically through an audit/evidence lens, not as a general admin training.

## 1. Incident (Module within ServiceNow)

The Incident module manages the lifecycle described in Module 7 — from logging through closure.

### Key Fields/Data Auditors Pull From Incident Records
- **Number** (unique ticket ID, e.g., INC0012345) — used to reference specific evidence precisely in workpapers.
- **Opened/Created date-time** — when the incident was logged (corroborates the "Identification/Logging" stage timestamp).
- **Priority/Severity** — corroborates the prioritization stage (Module 7); auditors check this was assigned per the documented severity matrix, not arbitrarily.
- **Assignment Group/Assigned To** — corroborates escalation/ownership.
- **State** (New, In Progress, On Hold, Resolved, Closed) — and critically, the **state transition history/audit log**, not just the current state, to confirm the sequence and timing of the lifecycle actually followed policy (e.g., time-to-resolve SLA compliance).
- **Resolution notes/Close notes** — should reflect actual root cause (Module 7) for higher-severity incidents, not just "fixed."

### Common Audit Test Using Incident Data
"For a sample of P1 incidents in the period, confirm escalation to senior leadership occurred within the policy-defined window (e.g., 30 minutes), using the incident's audit log/activity timestamps as evidence."

## 2. Change (ServiceNow Change Management Module)

Directly implements Module 6's change management process.

### Key Fields/Data
- **Change Request number** (e.g., CHG0034521).
- **Type** — Normal, Standard, Emergency (Module 6) — auditors specifically verify the type classification was appropriate, not used to avoid review.
- **Risk** — the assigned risk tier; ServiceNow often auto-calculates a suggested risk score from a risk assessment questionnaire embedded in the change form, but auditors check whether overrides of that suggested score were justified and approved.
- **CAB Approval** — recorded electronically in many configurations (an "Approvals" related list showing each approver, their decision, and timestamp) — this is strong system-generated evidence (Module 8) versus relying on separately-stored meeting minutes.
- **Planned Start/End** vs. **Actual Start/End** — used to confirm the change was deployed within its approved window (a deployment outside the approved window without a new approval is itself a finding).
- **Backout Plan field** — directly evidences the rollback plan requirement (Module 6).
- **Test Plan/Test Results field** — evidences the testing requirement.

### Common Audit Test Using Change Data
"For a sample of Normal changes, confirm CAB approval timestamp precedes the actual deployment start timestamp, and that a backout plan was documented prior to deployment."

## 3. Request (ServiceNow Request/Service Catalog Module)

Manages access requests and other service catalog items — directly relevant to JML/access provisioning evidence (Module 4/5).

### Key Fields/Data
- **Requested Item (RITM)** and parent **Request (REQ)** numbers.
- **Requested For** vs. **Requested By** (distinguishes the access recipient from who submitted the request — relevant for confirming the correct approval chain, e.g., that a manager, not the recipient themselves, approved their own access).
- **Approval workflow** — similar to Change's approval related list, showing each required approver and their decision/timestamp.
- **Fulfillment/Provisioning task** — the actual technical fulfillment record, which should be evidenced separately from the approval (approval ≠ provisioning; both steps need their own evidence per the Joiner process in Module 4).

## 4. CMDB (Configuration Management Database)

ServiceNow's CMDB maintains an inventory of **Configuration Items (CIs)** — servers, applications, network devices, and their relationships/dependencies.

### Why CMDB Matters for Audit
- **Scoping accuracy** — the CMDB is often used as a starting point to confirm the completeness of the "in-scope systems" population for ITGC testing (Module 11's scoping phase) — if a financially-relevant application isn't accurately reflected in the CMDB, it risks being missed from audit scope entirely.
- **Change-to-CI linkage** — changes in the Change module should be linked to the specific CI(s) they affect, which lets auditors trace "how many changes affected this specific financially-relevant application this year" for sampling purposes.
- **CMDB accuracy itself can be an audit finding** — a CMDB with significant data quality gaps (orphaned CIs, missing relationships, outdated ownership) undermines the reliability of any control testing that relies on it as a population source, so CMDB accuracy/completeness is sometimes tested as its own ITGC-adjacent control.

## 5. Tasks

Generic units of work that can be spawned from Incidents, Changes, or Requests (e.g., a Change Task representing one specific implementation step within a larger change). Auditors use task-level granularity when a single Change record represents a complex, multi-step deployment and evidence needs to be traced to the specific step relevant to the test.

## 6. Reports

ServiceNow's native reporting module allows extraction of structured data (e.g., "all changes in Q2 with Risk = High") — auditors generally prefer pulling reports directly themselves (or having a system administrator pull them with the auditor specifying exact filter criteria) over receiving a pre-filtered list from the process owner, to maintain independence over what's included.

## 7. Evidence (ServiceNow-Specific Considerations)

- **Audit Log/History related list** — present on virtually every ServiceNow record, showing every field change with old value, new value, who made the change, and when. This is **the single most valuable piece of evidence ServiceNow provides** for proving sequence/timing claims (e.g., "was this approved before or after deployment" is answered definitively by the audit log, not by the current-state view of the record).
- **Export formats** — auditors typically request exports as PDF or Excel with the audit log/activity stream included, not just a screenshot of the current ticket view, for the reasons discussed in Module 8.

## 8. Approval (ServiceNow Approval Engine)

ServiceNow's approval workflows are typically configured with specific approval rules (e.g., "Changes with Risk = High require both the application owner and the CISO's delegate to approve"). Auditors test:
- Whether the approval **rule configuration itself** matches policy (a design effectiveness test — Module 9).
- Whether actual approvals **followed** that configured rule for a sample of instances (operating effectiveness).

A common and important audit/security finding: someone with **admin access to ServiceNow itself** could theoretically alter an approval record after the fact (e.g., backdate an approval, or approve on someone else's behalf if account controls are weak) — this is why **access to ServiceNow's own admin functions** is itself in scope for ITGC testing (the tool that provides evidence for other controls must itself be subject to access controls, or its evidence can't be trusted — this is the same "ITGC reliance" concept from Module 2 applied recursively to the evidence-generating tool itself).

---
**Quick Self-Check Questions**
1. Why is the Audit Log/History related list generally stronger evidence than the current-state view of a ServiceNow ticket?
2. What's the difference between "Requested For" and "Requested By" on a Request record, and why does that distinction matter for approval testing?
3. Why might CMDB data quality itself become an audit finding, separate from any specific Change or Incident finding?
4. Explain why ServiceNow admin access is itself in-scope for ITGC testing, using the "ITGC reliance" concept from Module 2.
5. For a Normal change, name three specific ServiceNow fields/records you would inspect to test compliance with Module 6's change management requirements.
