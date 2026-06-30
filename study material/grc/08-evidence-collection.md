# Module 8 — Evidence Collection

This module covers what will likely be your single most frequent daily activity in an audit/compliance/GRC role. Understanding evidence deeply — what counts, what doesn't, and why — is the practical skill that separates someone who merely "knows the frameworks" from someone who can actually execute audit work.

## 1. What Counts as Evidence?

Evidence is anything that **objectively demonstrates a control operated as designed**, for a specific instance or population, independently verifiable by someone who wasn't involved in performing the control.

### The Core Evidence Test
Before accepting anything as evidence, ask:
1. **Does it show the control actually happened** (not just that it *should* have happened, or that a policy says it *should* happen)?
2. **Is it tied to a specific, identifiable instance** (a timestamp, a transaction ID, a named individual) rather than being generic/aggregate?
3. **Could someone independent of the control performer verify it's genuine** (not self-reported with no corroborating system trail)?
4. **Does it cover the full period/population in scope**, or at minimum a properly-drawn sample (Module 9)?

A screenshot of a policy document describing how access reviews *should* work is NOT evidence that an access review *happened*. This distinction — between **design evidence** and **operating evidence** — is one of the most fundamental concepts in this entire field and maps directly to the Module 9 distinction between design effectiveness and operating effectiveness.

## 2. Evidence Sources (Detailed by Type)

### 2.1 Emails
Used when a process step is approved/communicated via email rather than a structured workflow tool. Evidence value requires: sender, recipient, timestamp, and clear content showing the specific approval/decision (a vague "looks good" email replying to an unclear thread is weak evidence; a clear email explicitly approving a named request with relevant details is strong evidence).

**Limitation auditors watch for:** Emails are easy to fabricate or selectively provide; where possible, system-generated evidence (workflow tool logs) is preferred over email because it's harder to tamper with and includes immutable timestamps.

### 2.2 Access Reports
System-generated listings of users and their entitlements — the foundational evidence type for all access-related testing (Modules 4-5). Must be **system-generated**, not manually compiled in Excel by the control owner (manually compiled lists are vulnerable to accidental or deliberate omission, and an auditor generally cannot independently verify a manually-built list is complete without separately pulling from the source system anyway).

### 2.3 AD Screenshots
Screenshots of Active Directory showing account status, group membership, or last logon — useful evidence, but auditors typically prefer **exported reports/logs with timestamps embedded in the file metadata or content** over screenshots alone, since a screenshot can be taken at any time and its capture date isn't inherently verifiable from the image itself. Best practice: screenshots should include the system clock/timestamp visible in the captured image, or be supplemented with an exported log.

### 2.4 ServiceNow / Jira (Ticketing Systems)
Primary evidence source for change management, incident management, and access request workflows — tickets typically capture requestor, approver, timestamps at each status change, and attached documentation, providing a natural audit trail. Auditors will often pull a **ticket history/audit log** (showing every state change with timestamp) rather than just the current ticket state, since the current state alone doesn't prove the sequence of events was correct (e.g., it won't show if approval happened *after* implementation).

### 2.5 SAP / Oracle (ERP Systems)
Source systems for financial transaction evidence and, importantly, for **role/authorization evidence** specific to these platforms (e.g., SAP transaction codes assigned to a user, used to test SoD conflicts via tools like SAP GRC Access Control). Change logs within these systems (e.g., SAP's table change logging) are also critical evidence for configuration change testing.

### 2.6 Database Reports
Direct extracts from underlying databases, used when application-layer reporting is insufficient or when independently verifying application-reported numbers against the underlying data (a higher level of audit rigor — "trust but verify" against the raw data rather than relying solely on a report the client's own system generated).

### 2.7 IAM Logs
Logs from identity governance platforms (SailPoint, Saviynt, Entra ID Governance) showing provisioning/deprovisioning actions, access review campaign results, and SoD violation detections — central evidence for the JML and access certification testing in Modules 4-5.

### 2.8 Approval Workflows
System-captured approval chains (e.g., a ServiceNow approval record, an Entra ID PIM activation approval) — generally considered strong evidence because the system itself enforces and timestamps the approval step, removing reliance on a human accurately reporting that approval occurred.

### 2.9 System Logs / Audit Trails
Native logging from operating systems, applications, network devices, or cloud platforms (e.g., Azure Activity Log, AWS CloudTrail) — these are often the **most trustworthy evidence category** because they're typically automatically generated, difficult to alter without leaving additional trace evidence (especially if log integrity controls like write-once storage or centralized SIEM forwarding are in place), and comprehensive (not subject to a human remembering to document something).

**Security engineering note:** This is exactly why SIEM log retention and integrity (tamper-evidence, centralized forwarding before a compromised host could be used to delete local logs) is itself a security control with direct audit evidence implications — if logs can be selectively deleted by an attacker (or a fraudulent insider) before forensic/audit review, the evidentiary value collapses.

### 2.10 Policy Documents
Establish the **expected design** of a control (what *should* happen) — necessary as a baseline for design assessment (Module 9) but never sufficient alone as operating evidence.

### 2.11 Screenshots (General)
Useful supplementary evidence, especially for configuration settings that don't have a clean exportable report (e.g., a specific security setting toggle in a console). Best practice: include the full browser/console window with URL/system name visible, system date/time visible where possible, and the specific setting clearly legible — a cropped, ambiguous screenshot is weak evidence.

### 2.12 HR Reports / Termination Lists
The **independent source of truth** for JML testing (Module 4), since IT's own records of "who we terminated" can't be self-verified against IT's own records of "who we terminated" — auditors specifically obtain the termination list from HR/payroll systems (independent of the IT/IAM team being tested) precisely to catch gaps that wouldn't show up if you only looked at the IT team's self-reported population.

### 2.13 Manager Approval (as Evidence Category)
Distinct from "approval workflow" evidence in that this specifically refers to capturing that the **correct, authorized individual** (matching the org chart/delegation of authority at the time) provided the approval — auditors sometimes specifically test whether the approver listed actually had the authority to approve (e.g., was that person actually the requestor's manager at that time, not someone who happened to click approve).

### 2.14 CAB Minutes
Covered in Module 6 — meeting minutes/records showing what was discussed, who attended, and the explicit decision per change.

### 2.15 Deployment Logs
System/pipeline-generated records of what was actually deployed, when, and by whom — critical for change management testing, ideally cross-referenced against the change ticket to confirm the deployed change matches what was approved (not something additional or different).

### 2.16 Monitoring Logs
Evidence of ongoing detective controls operating (e.g., uptime monitoring, performance dashboards, alert history) — relevant for IT operations control testing (Module 4's "computer operations" control objective).

### 2.17 SIEM (Security Information and Event Management)
Centralized security log aggregation and correlation platform — increasingly a primary evidence source not just for security incident investigation but for broader control testing, since SIEM tools often retain and can query historical authentication, access, and configuration change events across many source systems in one place.

### 2.18 Ticket History
As distinguished from a single point-in-time ticket view (2.4 above) — the full chronological audit trail of every status/field change on a ticket, essential for proving sequence and timing (e.g., proving approval preceded implementation).

## 3. The Evidence Lifecycle in Practice (Daily Workflow)

A typical day-to-day evidence collection workflow for an IT/SOX audit analyst:

1. **Receive the testing requirement** from the RCM (Module 2) — e.g., "for a sample of 25 terminations in Q2, confirm access was disabled within 24 hours."
2. **Identify the correct independent source** — HR termination list (not IT's own log) for the population; IAM/AD logs for the disablement timestamp.
3. **Request evidence** from the control owner/system owner, being specific about exactly what's needed (system-generated export, not a manual summary) and the exact date range/sample needed.
4. **Validate evidence completeness** — does what was provided actually answer the question? (A common real-world friction point: stakeholders provide partial or tangential evidence, and part of the analyst's job is recognizing the gap and following up before testing can proceed — this connects directly to Module 12's stakeholder communication skills.)
5. **Perform the test** (re-performance/inspection — Module 9) against the evidence.
6. **Document the conclusion** — pass/fail, with the specific evidence referenced supporting the conclusion.
7. **Retain evidence** per the engagement's documentation standards (typically a structured workpaper folder structure, often standardized by control ID and testing period).

## 4. Evidence Quality Hierarchy (General Audit Principle)

Not all evidence is equally reliable. A widely-used general hierarchy (consistent with auditing standards like those from the PCAOB/AICPA):

1. **Auditor's direct, independent observation/re-performance** — strongest.
2. **Evidence from an independent third party** (e.g., a bank confirmation, an independent system log not controlled by the process owner being tested).
3. **System-generated evidence from a well-controlled IT environment** (assuming ITGC over that system is itself reliable — this is the ITGC-reliance concept from Module 2 again).
4. **Documentary evidence created by the client/process owner** (tickets, screenshots, manually compiled reports) — weaker, especially if manually compiled.
5. **Verbal evidence/inquiry alone** — weakest; inquiry is never sufficient evidence on its own and must always be corroborated by another evidence type (Module 9 covers this explicitly).

## 5. Common Evidence-Related Findings

| Finding | Description |
|---|---|
| Evidence not retained | Control may have operated, but no proof exists — treated as a failure regardless of whether the control "actually" worked |
| Evidence doesn't cover full population/period | Partial evidence provided when full population was requested |
| Evidence is manually compiled, not system-generated | Reliability concern — cannot independently verify completeness/accuracy |
| Evidence timestamp inconsistent with claimed sequence | E.g., approval evidence dated after implementation evidence |
| Evidence provided is for the wrong control/period | Stakeholder misunderstanding of the request — common, requires clear re-communication |
| Screenshot lacks identifying context (date, system, user) | Cannot be relied upon as conclusive proof |

---
**Quick Self-Check Questions**
1. What is the difference between "design evidence" and "operating evidence," and why does a policy document alone never satisfy operating evidence requirements?
2. Why do auditors specifically prefer to obtain the termination population from HR rather than from the IT/IAM team being tested?
3. Rank the following from strongest to weakest evidence: a manually compiled Excel list from the control owner; a system-generated audit log; a verbal confirmation in an interview; an independent third-party confirmation.
4. Why is a screenshot generally considered weaker evidence than an exported, timestamped system log, even if both show the same underlying fact?
5. Walk through the full daily evidence collection workflow from receiving a testing requirement to documenting a conclusion.
