# Module 10 — Audit Findings

This module covers how to write up the results of control testing (Module 9) into a formal, defensible, actionable finding — arguably the highest-leverage *writing* skill in this entire field, since findings are what leadership, audit committees, and regulators actually read.

## 1. The Anatomy of a Well-Written Finding

A professional audit finding consistently contains these structural elements, often called the "5 C's" or similar mnemonics across firms (the exact label varies, but the components below are universal):

### 1.1 Observation (Condition)
A clear, factual, objective statement of **what was found** — strictly what the evidence showed, with no interpretation or judgment mixed in yet.

> **Weak:** "Access management is broken and nobody cares about security."
> **Strong:** "Of 25 sampled terminations during Q1-Q3 FY24, 3 instances (12%) showed Active Directory account disablement occurring more than 24 hours after the HR-recorded termination date, with delays ranging from 3 to 11 business days."

Notice the strong version is specific, quantified, time-bound, and free of editorializing.

### 1.2 Criteria
What the standard/expectation was — what *should* have happened, with reference to the specific policy, control, or framework requirement.

> "Per [Company] Access Management Policy v3.2, Section 4.1, system access for terminated employees must be disabled within 24 hours of the recorded termination date."

### 1.3 Risk (Effect/Impact)
**Why this matters** — the actual business/financial/security consequence if the gap isn't addressed. This is where many junior auditors write weak findings, either overstating risk dramatically or understating it by simply restating the observation.

> "Delayed access termination increases the risk of unauthorized access to financial systems by former employees, including the ability to view, modify, or extract sensitive financial data, which could result in unauthorized transactions, data integrity issues, or fraud. This directly impacts the Existence/Occurrence assertion for transactions processed in the affected systems."

Notice this ties back explicitly to the financial assertion (Module 2) — connecting an IT finding to its actual financial reporting relevance is what makes a finding credible to a SOX-focused audience versus reading as generic "best practice" commentary.

### 1.4 Root Cause
**Why** the gap occurred — the underlying process/system reason, not just the symptom (this draws directly on Module 7's RCA/5-Whys technique).

> "Root cause: the termination notification from HR's system (Workday) to the IAM provisioning queue relies on a manual daily batch export reviewed by a single analyst; during the period in question, this analyst was on leave for 2 weeks with no backup coverage assigned, causing termination notifications to be processed late."

A good root cause statement points directly toward an effective remediation — if you can't tell what should be fixed just from reading the root cause, it's probably not specific enough yet.

### 1.5 Recommendation
A specific, actionable, and realistic suggestion for remediation — addressed at the root cause, not just the symptom.

> "Recommend automating the HR-to-IAM termination feed to eliminate dependency on manual daily processing, and/or implementing a backup coverage protocol with monitoring/alerting for any termination notification not processed within 4 hours of receipt."

### 1.6 Management Response
The process owner's formal reply — agree/disagree with the finding, and their planned remediation action with a committed timeline. This is a **required** component in formal audit reporting (especially internal audit/SOX reporting to an audit committee) because it documents management's accountability and commitment, and gives the audit function something concrete to follow up on at the next testing cycle.

> "Management agrees with the finding. The IAM team will implement an automated real-time HR-to-IAM termination feed by [date], eliminating the manual batch dependency. Interim compensating control: a designated backup reviewer has been assigned effective immediately, with daily monitoring of the termination queue."

### 1.7 Residual Risk
After the recommended remediation is implemented, what risk remains? Very few controls eliminate risk entirely — residual risk should be explicitly acknowledged and, ideally, shown to be within the organization's risk appetite (Module 1).

## 2. Severity Rating

Every finding is assigned a severity rating, which drives urgency of remediation, who needs to be informed, and (for SOX-relevant findings specifically) potential public disclosure obligations.

### Standard Severity Scale

| Severity | General Definition | Typical Escalation |
|---|---|---|
| **Low** | Minor gap, limited/no real financial or security impact, isolated instance | Tracked, remediated in normal course, reported in summary |
| **Medium** | Moderate impact, more than isolated but not pervasive, compensating controls partially mitigate | Reported to process owner and audit management, remediation tracked with defined timeline |
| **High** | Significant impact, pervasive or affecting a control objective directly tied to financial reporting reliability or significant security exposure | Escalated to senior management, often audit committee visibility, expedited remediation expected |
| **Critical** | Severe — equivalent to or bordering on a Material Weakness (Module 9); immediate risk to financial statement integrity, active security compromise, or regulatory exposure | Immediate escalation to executive leadership/audit committee/board; may trigger regulatory disclosure obligations; often requires an interim compensating control implemented immediately while permanent remediation is underway |

**Important nuance:** Severity rating should reflect the **risk of the gap itself**, not merely how many instances were found. A single instance of a Critical-risk control failure (e.g., one terminated privileged user retaining domain admin access for 3 weeks, later found to have actually logged in during that window) can warrant a higher severity than a 30% exception rate on a low-risk control.

## 3. Connecting Severity to Module 9's Deficiency Pipeline

Recall Module 9's escalation: **Control Deficiency → Significant Deficiency → Material Weakness.** This SOX-specific terminology and the general Low/Medium/High/Critical severity scale used above are related but serve different audiences and purposes:

- The **Low/Medium/High/Critical** scale is typically used for operational/internal audit findings tracking and management reporting broadly (including non-SOX findings, like general security audit findings).
- The **Control/Significant Deficiency/Material Weakness** classification is the specific SOX/ICFR vocabulary used when a finding's severity is being formally evaluated for its impact on the company's overall internal control opinion and public disclosure obligations.

A High or Critical operational finding in a SOX-in-scope control will typically be evaluated against the Significant Deficiency/Material Weakness criteria as a parallel, more formal classification exercise — they're not strictly the same scale, but a Critical finding is very likely to also be evaluated as at least a Significant Deficiency candidate.

## 4. Writing Findings That Actually Drive Change (Practical Craft)

Beyond the formal structure, a few practical principles distinguish findings that lead to real remediation from ones that get noted and forgotten:

- **Be specific, not vague.** "Improve access controls" is not actionable. "Implement automated SLA monitoring on the HR-to-IAM termination feed with alerting for any record unprocessed after 4 hours" is actionable.
- **Quantify wherever possible.** Numbers (sample size, exception rate, dollar exposure, days of delay) make findings credible and harder to dismiss or minimize.
- **Avoid inflammatory or judgmental language.** "Nobody is paying attention to security" undermines credibility and invites defensiveness; factual, evidence-based language ("the control did not operate within the defined SLA in 3 of 25 sampled instances") is more persuasive precisely because it's unemotional and verifiable.
- **Tie every finding back to a real risk**, not just "this isn't best practice." Stakeholders (and especially senior leadership) push back hardest on findings that read as theoretical/checkbox-driven rather than connected to genuine business risk.
- **Always test management's proposed remediation for adequacy** before accepting it — a remediation that only addresses the specific instance found (not the systemic root cause) should itself be challenged before the finding is closed.

## 5. Common Mistakes in Findings (and How They're Perceived)

| Mistake | Why It's a Problem |
|---|---|
| Conflating observation with risk (stating the risk as if it were the fact found) | Loses precision; reader can't distinguish "what we saw" from "why it matters" |
| No root cause, or root cause that just restates the observation | Recommendation ends up generic and unlikely to actually fix anything |
| Severity inflated to get attention | Erodes trust in the audit function over time ("audit cries wolf") |
| Severity deflated to avoid conflict with the process owner | Defeats the entire purpose of independent assurance; a serious integrity issue for an auditor |
| No quantification (sample size, exception rate) | Makes the finding feel anecdotal rather than evidence-based |
| Recommendation too vague to action ("strengthen controls") | Management response will likely be equally vague, and the finding won't meaningfully close |

---
**Quick Self-Check Questions**
1. Write a one-sentence Observation and a one-sentence Risk statement for a hypothetical finding, making sure you don't blend the two together.
2. Why must a finding's recommendation address the root cause rather than just the specific instance discovered?
3. What's the relationship (and the difference) between the Low/Medium/High/Critical severity scale and the Control/Significant Deficiency/Material Weakness SOX classification?
4. Why is inflating a finding's severity just as much an integrity problem as deflating it?
5. What is "residual risk" in the context of a finding, and why should it be explicitly stated even after a strong recommendation is implemented?
