# Module 2 — SOX & JSOX (Extremely Detailed)

## 1. History — Why SOX Was Created

The Sarbanes-Oxley Act of 2002 (SOX) was enacted by the US Congress in direct response to a wave of major corporate accounting scandals in the early 2000s that destroyed investor trust in financial markets.

### The Enron Scandal

Enron, once the 7th largest company in the US by revenue, collapsed in late 2001 after it was revealed that executives had used complex off-balance-sheet special purpose entities (SPEs) to hide billions in debt and inflate profits. Key failures:

- Executives (Kenneth Lay, Jeffrey Skilling, Andrew Fastow) knowingly misrepresented the company's financial health.
- **Arthur Andersen**, Enron's external auditor (one of the "Big 5" at the time), was found to have shredded documents related to the audit and was complicit in approving misleading accounting practices — Arthur Andersen collapsed as a firm shortly after, leaving only the "Big 4."
- Employees' retirement savings (heavily invested in Enron stock via 401(k)) were wiped out, while executives sold shares before the collapse became public.
- The audit committee and board failed to ask hard questions despite red flags.

### WorldCom and Other Contributing Scandals

WorldCom (2002) inflated profits by improperly capitalizing billions of dollars in ordinary operating expenses as capital expenditures, again with auditor failure to catch it. Combined with Enron, Tyco, and others, these scandals revealed systemic weaknesses: auditor independence conflicts (auditors also selling lucrative consulting services to the same clients), weak board oversight, and no personal accountability for executives signing off on financials.

### Financial Fraud — The Underlying Pattern

Across these scandals, a consistent pattern emerges that SOX was designed to break:
1. Executives had incentive (stock price, bonuses) to misstate earnings.
2. Internal controls were either absent or deliberately overridden.
3. External auditors had conflicts of interest or insufficient independence.
4. No individual was personally and legally accountable for false statements.
5. Whistleblowers had no protection and feared retaliation.

SOX directly addresses each of these five failure points with specific legal provisions.

## 2. SOX Sections (The Critical Ones)

SOX has 11 Titles and dozens of sections, but IT/security auditors overwhelmingly focus on a handful that have direct operational impact.

### Section 302 — Corporate Responsibility for Financial Reports

Requires the CEO and CFO to **personally certify**, on a quarterly and annual basis, that:
- They have reviewed the report.
- The report does not contain material misstatements or omissions.
- The financial statements fairly present the company's financial condition.
- They are responsible for establishing and maintaining internal controls and have evaluated their effectiveness within the prior 90 days.
- They have disclosed any significant deficiencies or fraud to the auditors and audit committee.

**Why this matters operationally:** Section 302 is what creates the cascading certification chain — CEO/CFO certify to the board, which means business unit and IT leaders must certify up to them, which means YOU (as an analyst gathering evidence) are part of the chain that makes that certification defensible.

### Section 404 — Management Assessment of Internal Controls

The most operationally significant section for IT and security audit teams. Section 404 has two parts:

- **404(a)** — Management must issue a report stating its responsibility for internal control over financial reporting (ICFR) and assess the effectiveness of those controls.
- **404(b)** — The external auditor must independently attest to and report on management's assessment (applies to "accelerated filers" — generally larger public companies; smaller reporting companies are often exempt from 404(b) but not 404(a)).

This is the section that directly creates the demand for ITGC testing, access reviews, change management evidence, and everything in Modules 4-11 of this guide. **When someone says "we're doing SOX testing," they almost always mean Section 404 ICFR testing.**

### Other Notable Sections (Brief)

- **Section 401** — Disclosures in periodic reports (off-balance-sheet transactions must be disclosed).
- **Section 409** — Real-time disclosure of material changes in financial condition.
- **Section 802** — Criminal penalties for destroying/altering records to impede an investigation (direct response to Arthur Andersen's document shredding).
- **Section 806** — Whistleblower protection for employees of publicly traded companies.
- **Section 906** — Criminal penalties (fines up to $5M, imprisonment up to 20 years) for knowingly certifying a false financial report.

## 3. JSOX — Japan's Version, and the Differences

JSOX (Financial Instruments and Exchange Act, effective 2008) is Japan's equivalent regulatory framework, modeled closely on SOX but with notable differences relevant if you work with Japan-headquartered clients or subsidiaries.

| Aspect | SOX (US) | JSOX (Japan) |
|---|---|---|
| Legal basis | Sarbanes-Oxley Act 2002 | Financial Instruments and Exchange Act |
| Scope of entity testing | Often broader, risk-based scoping | Tends to require coverage of entities representing ~2/3 of consolidated revenue |
| External auditor attestation | Required for accelerated filers (404b) | Required, but historically with somewhat more emphasis on management's own assessment |
| Documentation style | Narrative + matrices, flexible | Traditionally more rigid, standardized templates (often the "3 documents": flowchart, RCM, process narrative) |
| IT controls emphasis | Strong ITGC focus | Equally strong, often even more rigorously templated for IT application controls |
| Penalty severity | Criminal penalties can be severe (906) | Penalties exist but enforcement culture differs |
| Reporting frequency | Quarterly certifications (302) + annual (404) | Primarily annual assessment cycle |

**Practical implication:** If you're supporting a JSOX-scoped client/subsidiary, expect more standardized, templated documentation requirements (the classic Japanese "3点セット" / three-document set: Flowchart, Risk Control Matrix, and Process Narrative) and less room for "we'll explain it in a memo" flexibility compared to a typical US SOX engagement.

## 4. Internal Control over Financial Reporting (ICFR)

ICFR is the umbrella term for the entire system of controls designed to provide reasonable assurance regarding the reliability of financial reporting.

### What ICFR Covers

ICFR is not just "accounting controls." It explicitly includes:
- **Entity-level controls** — tone at the top, code of conduct, whistleblower hotline, board oversight.
- **Process-level controls** — controls embedded in specific business processes (Order-to-Cash, Procure-to-Pay, Record-to-Report, etc.).
- **IT General Controls (ITGC)** — because nearly every financial process today runs through IT systems, and if access/change/operations controls over those systems are broken, you cannot rely on any control that depends on that system (this is the **ITGC reliance** concept — Module 4 exists because of this dependency).
- **Application Controls** — automated or IT-dependent controls embedded inside specific applications (three-way match, system-enforced approval workflows, automated calculations).

### The "Reasonable Assurance" Standard

ICFR is explicitly NOT a guarantee against all error or fraud — it provides *reasonable*, not *absolute*, assurance, because controls have inherent limitations (collusion, management override, human error, cost-benefit tradeoffs in control design).

## 5. Process Walkthrough

A walkthrough is the technique auditors use to understand and validate a process from start to finish, tracing a single transaction through the entire process.

### How a Walkthrough Works

1. **Inquiry** — interview the process owner about how the process works.
2. **Observation** — watch the process actually being performed (or watch a screen-share demonstration).
3. **Inspection** — examine the documentation/system evidence the process produces.
4. **Re-performance** — trace one actual transaction through the system end-to-end, confirming each control point fires as described.

### Example Walkthrough: New Employee Access Provisioning (a JML "Joiner" process)

1. HR creates a new hire record in the HRIS → auditor inspects the HR ticket.
2. System auto-generates an access request based on role/department → auditor confirms the request matches the approved role mapping.
5. Manager approves the request → auditor inspects the approval (email, ServiceNow approval log, or workflow tool timestamp).
6. IAM team provisions access in Active Directory/target systems → auditor inspects AD logs/screenshots showing the account creation timestamp matches the approval timestamp (or postdates it).
7. Auditor confirms evidence is retained and matches what the policy requires.

A walkthrough's purpose is **design assessment** — does the control, as designed, actually address the risk? (Operating effectiveness, whether it works every time, is tested separately — see Module 9.)

## 6. Risk Control Matrix (RCM)

The RCM is the central working document of SOX/ITGC audit work — essentially a structured table mapping risks to the controls that mitigate them.

### Typical RCM Columns

| Column | Description |
|---|---|
| Risk ID | Unique identifier |
| Risk Description | What could go wrong (e.g., "Unauthorized access to financial systems could result in unauthorized transactions") |
| Control ID | Unique identifier |
| Control Description | What is done to mitigate the risk |
| Control Owner | Who performs/is accountable for the control |
| Control Frequency | Continuous, daily, monthly, quarterly, annual, event-driven |
| Control Type | Preventive/Detective; Manual/Automated/IT-dependent manual |
| Financial Assertion(s) Addressed | See below |
| Testing Approach | Inquiry, Observation, Inspection, Re-performance |
| Sample Size | How many instances will be tested |
| Evidence Required | What documentation proves the control operated |

### Example RCM Row

> **Risk:** Terminated employees retain access to financial systems, enabling unauthorized transactions or data exfiltration.
> **Control:** IT disables system access within 24 hours of an employee's termination date, triggered automatically by an HR termination event in Workday feeding to the IAM platform.
> **Owner:** IAM Team Lead
> **Frequency:** Continuous/event-driven
> **Type:** Preventive, IT-dependent automated
> **Assertion:** Existence/Occurrence (prevents unauthorized transactions from being recorded)
> **Testing:** Inspect HR termination list for the period; for a sample, inspect AD/IAM logs to confirm disablement timestamp is within 24 hours of termination date.

## 7. Financial Assertions

Financial statement assertions are claims embedded in financial statements that management implicitly makes, and that controls/audit testing exist to validate. Standard assertion categories (per PCAOB/COSO):

- **Existence/Occurrence** — assets/transactions recorded actually exist/occurred (did this revenue transaction really happen?).
- **Completeness** — all transactions that should be recorded, are recorded (no revenue or liabilities left out).
- **Accuracy/Valuation** — amounts are recorded correctly and at appropriate values.
- **Rights and Obligations** — the entity actually owns the assets/owes the liabilities recorded.
- **Presentation and Disclosure** — items are properly classified, described, and disclosed in the financial statements.
- **Cutoff** — transactions are recorded in the correct accounting period.

**Why ITGC auditors care about assertions:** Every ITGC control you test should be traceable to at least one assertion. For example, access controls primarily support **Existence/Occurrence** (preventing unauthorized/fictitious transactions) and **Completeness** (ensuring authorized transactions aren't deleted/blocked). Change management controls support **Accuracy** (preventing unauthorized code changes that could miscalculate figures). This traceability is exactly what an RCM documents.

## 8. Control Objectives

A control objective is a statement of the desired result or purpose to be achieved by implementing control activities in a particular process. Control objectives sit one level above individual controls — multiple controls might satisfy a single objective.

### Standard ITGC Control Objectives (these map almost directly to Module 4's structure)

1. **Access to programs and data is appropriately restricted** (logical access management — least privilege, segregation of duties).
2. **Changes to programs/systems are authorized, tested, and approved before migration to production** (change management).
3. **New systems/programs are developed, configured, and implemented to meet business objectives** (SDLC controls).
4. **Computer operations are managed to ensure complete, accurate, and timely processing** (job scheduling, batch processing, backup/recovery).

Nearly every ITGC testing engagement is structured around exactly these four objectives, often abbreviated as **Access**, **Change**, **SDLC/Development**, and **Operations**.

---
**Quick Self-Check Questions**
1. What specific governance failure did Section 302 (CEO/CFO certification) directly address?
2. Why does 404(b) attestation apply only to certain filers, and what's the practical difference vs. 404(a)?
3. Name the "three-document set" commonly required in JSOX engagements.
4. Walk through, in order, the four steps of a process walkthrough.
5. Pick any ITGC control and identify which financial assertion(s) it most directly supports.
6. What are the four standard ITGC control objectives, and which module of this guide expands each one?
