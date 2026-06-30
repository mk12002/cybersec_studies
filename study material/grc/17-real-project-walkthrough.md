# Module 17 — Real Project Walkthrough

This module synthesizes everything from Modules 1-16 into a single, continuous, realistic end-to-end audit case study. Rather than abstract concepts, you'll follow one engagement from receipt through final report — the same shape as the audit lifecycle in Module 11, but populated with concrete, realistic detail at every stage so you can see how all prior modules connect in practice.

## The Scenario

You're an analyst on the ITGC audit team. The annual SOX audit plan (Module 11, Planning) has scoped in **Logical Access Management** for the company's core financial ERP system (a SAP environment) as part of this quarter's testing cycle. This is one of the four standard ITGC control objectives (Module 2).

---

## Step 1 — Receive Audit / Understand Scope

You receive the assignment: test the **Joiner-Mover-Leaver process and quarterly access review** controls over the SAP financial system for the period January 1 – September 30 (an interim testing period, common in SOX engagements, with a roll-forward procedure planned for Q4 closer to year-end).

You review:
- The current **RCM** (Module 2) entries for this control area, including control descriptions, owners, and the financial assertions they map to (primarily Existence/Occurrence and Completeness).
- **Prior year workpapers** — were there findings last cycle? (There was: a Medium-severity finding last year on Mover process gaps — privilege creep not consistently revoked. You note this as an area warranting extra scrutiny this cycle, since repeat findings escalate in severity per most firms' methodology, Module 10.)
- The relevant **policy document** — the company's Access Management Policy, defining the 24-hour Leaver SLA, the quarterly access review requirement, and role-based provisioning standards.

## Step 2 — Identify Controls

From the RCM, three specific controls are in scope:

- **AC-01 (Joiner):** New SAP access is provisioned only after documented manager approval matching a pre-defined role template.
- **AC-02 (Leaver):** SAP access is disabled within 24 hours of an employee's termination date.
- **AC-03 (Quarterly Access Review):** The SAP application owner reviews all user access quarterly and certifies appropriateness; identified excess access is revoked within 10 business days.

## Step 3 — Request Evidence (Building the PBC List, Module 11)

You build a PBC list and send formal requests:

1. To **HR**: complete employee population data for the period — all new hires, role changes, and terminations (the **independent source population**, Module 8) for the in-scope SAP user base.
2. To the **IAM team**: SAP provisioning/deprovisioning logs (system-generated, not manually compiled) covering the same period.
3. To the **SAP Application Owner**: evidence of the three completed Q1/Q2/Q3 access review campaigns, including reviewer certifications and any revocation actions taken.
4. To **IT Security**: the current SAP role template documentation (used to test whether granted access matched approved role definitions).

You set due dates and track status, following up per Module 12's guidance when responses lag.

## Step 4 — Validate Evidence

The IAM team's first submission is a manually compiled Excel summary, not a system export. Per Module 8's evidence quality hierarchy, you push back:

> "Thanks for this — for testing purposes I'll need the system-generated provisioning log directly exported from SailPoint, rather than a manually compiled summary, so I can independently verify completeness. Could you also include the full date range Jan 1–Sep 30 rather than just Q1-Q2?"

This is a real, common friction point (Module 12) — handled factually and specifically, not accusatorially, and you get the corrected export within two business days.

## Step 5 — Perform Testing

### AC-01 (Joiner) — Design + Operating Effectiveness

**Walkthrough (design):** You schedule a call with the IAM lead, observe a live demonstration of a new-hire request moving through the role-template-based provisioning workflow in SailPoint, and confirm the design matches the documented process (Module 2's walkthrough steps).

**Sampling (operating):** Population = 38 new hires into SAP-relevant roles during the period (reconciled from HR data). Using stratified-by-risk Excel sampling (Module 15) — slightly over-sampling privileged SAP roles given their higher risk — you select 20 samples.

**Testing technique:** Inspection (Module 9) — for each sample, you trace the approval ticket, confirm the approver was the documented manager at that time, confirm the granted role matches the approved role template (no excess), and confirm provisioning timestamp is on/after the approval timestamp.

**Result:** 19/20 pass. 1 exception — a user was granted an additional, unapproved role alongside their approved role template.

### AC-02 (Leaver) — Operating Effectiveness

**Population:** 27 terminations during the period from the **HR termination list** (not IT's own log, per Module 8's independence principle).

**Sample:** Given the higher inherent risk of this control (a known prior-year-adjacent risk area) and reasonably small population, you test the full population rather than a partial sample — appropriate per Module 9's guidance that small annual/quarterly-frequency-adjacent populations are often tested in full.

**Testing technique:** Re-performance-adjacent inspection — cross-reference each HR termination date against the SAP/AD disable timestamp (Active Directory Event ID 4725, Module 14) pulled directly from the centralized SIEM log (strong, hard-to-tamper evidence per Module 8's hierarchy).

**Result:** 25/27 pass within the 24-hour SLA. 2 exceptions: one disabled at 31 hours (slightly late), one disabled at 9 days late — this second one is a **contractor**, not a standard employee, and you discover the contractor offboarding process runs through a completely separate, manual workflow outside the standard HR-driven feed (this maps directly to the "contractors excluded from JML" systemic pattern from Module 16).

### AC-03 (Quarterly Access Review) — Operating Effectiveness

**Population:** All 3 completed review campaigns (Q1, Q2, Q3), each covering the full SAP user population (~340 users at the time of each review).

**Sample:** 25 individual certification decisions sampled across the 3 campaigns, with intentional over-sampling of "revoke" decisions specifically (since "revoke" is where the control's actual risk-reduction action happens, and where the 10-business-day execution SLA can fail even if the review itself was performed on time).

**Result:** All reviews were completed on schedule by the correct application owner (design + timing pass). However, of 8 sampled "revoke" decisions, 2 were not technically executed (access remained active in SAP) until 14 and 16 business days after certification — exceeding the 10-day SLA.

## Step 6 — Find Gaps (Synthesizing Exceptions Into Findings)

You now have three sets of exceptions across three controls. Following Module 9's guidance, you investigate root cause for each before concluding severity (Module 10):

**AC-01 exception root cause:** The single unapproved-role instance traces to a manual, undocumented "quick fix" where IT granted temporary additional access to help the new hire meet an urgent deadline, intending to remove it later — and never did. This looks like an **isolated** instance on its face, but you note it as a pattern worth flagging for next cycle's testing, since "temporary access that becomes permanent" is a classic precursor to broader privilege creep (Module 5).

**AC-02 exceptions root cause:** Two distinct root causes — the 31-hour delay is a minor, isolated processing delay (likely not pervasive); the contractor exception reveals a **systemic** gap — the entire contractor population sits outside the standard automated JML pipeline. This is the more serious finding.

**AC-03 exceptions root cause:** Both late-revocation instances trace to the same root cause — a manual handoff between the access review tool and the actual SAP provisioning team, with no automated trigger or SLA monitoring (directly matching Module 16's "manual processes with no automated enforcement" systemic pattern, and connecting back to the prior-year Mover finding you flagged in Step 1).

## Step 7 — Discuss With Stakeholders (Issue Discussion, Module 11/12)

You schedule issue discussion calls with each control owner before finalizing anything, per the "no surprises" principle:

- With the **IAM lead**, you discuss the AC-01 finding — they confirm it was indeed an undocumented manual override and propose tightening the exception process.
- With the **SAP application owner / contractor management team**, you discuss the AC-02 contractor gap — this generates genuine useful pushback: they explain contractor offboarding is contractually tied to the vendor management system, not HR, which is new context that sharpens (but doesn't eliminate) the finding — the recommendation needs to account for this distinct trigger source rather than naively suggesting "just connect it to the HR feed."
- With the **SAP application owner**, you discuss AC-03 — they agree readily, noting they've raised the same manual-handoff friction internally before without resourcing to fix it; this becomes useful context for the finding's risk narrative (a known, previously-unaddressed gap carries more weight than a brand-new surprise).

## Step 8 — Document Findings (Module 10 structure applied)

**Finding 1 (AC-02 — Severity: High):**
- *Observation:* 1 of 27 sampled terminations (a contractor) was not disabled in SAP until 9 business days post-termination, against a 24-hour policy SLA.
- *Criteria:* Access Management Policy §4.1.
- *Risk:* Unauthorized contractor access to the financial ERP system post-engagement, risking unauthorized transactions or data exposure; directly impacts Existence/Occurrence assertion.
- *Root Cause:* Contractor offboarding is managed through the vendor management system, entirely outside the standard HR-driven JML automation pipeline, with no equivalent automated trigger to IAM.
- *Recommendation:* Extend automated deprovisioning triggers to include vendor management system offboarding events, not just HR terminations; in the interim, implement a manual reconciliation control between active contractor rosters and active SAP access, performed at least monthly until automation is complete.
- *Management Response:* Agreed; IAM and Vendor Management teams to scope an automated integration by [date], with monthly manual reconciliation as an interim compensating control starting immediately.

**Finding 2 (AC-03 — Severity: Medium, noted as a repeat/escalating issue from prior year):**
- Structured the same way, explicitly referencing that this is the second consecutive cycle the manual-handoff root cause has surfaced — which, per most firms' escalation methodology, typically bumps severity relative to a first-time finding of similar nature.

**AC-01** exception, after root cause discussion, is concluded as isolated rather than systemic, documented as a **Low severity** observation rather than a formal finding requiring full escalation — but still tracked, since "isolated today" doesn't mean "irrelevant," especially given its similarity to known privilege-creep risk patterns.

## Step 9 — Final Report

The findings above, structured per Module 10/11, are compiled into the formal report with an overall conclusion on this control area's effectiveness for the period, distributed to the audit committee (for the High finding particularly, per standard escalation norms, Module 10) and process owners, with remediation due dates tracked into the next testing cycle.

## Step 10 — Closure and Forward Loop

The engagement closes, but per Module 11's "loop, not a line" principle: the Finding 1 and Finding 2 remediation commitments become **tracked open items**, and the elevated risk this area now carries (two consecutive cycles with related findings) directly informs **next cycle's risk assessment and scoping** — likely resulting in continued, possibly expanded, testing of this control area rather than a reduced-scope "clean area" treatment next year.

---

## What This Walkthrough Demonstrates

Notice how nearly every module in this guide showed up naturally within a single realistic engagement: governance/risk framing (Module 1) shaped why this area was even in scope; SOX/RCM structure (Module 2) defined the controls being tested; ITGC and access concepts (Modules 4-5) defined what "good" looks like; change/incident concepts didn't directly appear here but would in a parallel engagement testing those objectives; evidence principles (Module 8) drove every evidence request and the pushback on the manually-compiled Excel file; testing technique and severity concepts (Module 9-10) shaped every conclusion; stakeholder communication (Module 12) shaped how issues were surfaced and discussed; and the common-findings patterns (Module 16) appeared almost exactly as cataloged (contractor JML gap, manual-handoff-with-no-automation gap).

This is the actual shape of real audit work — not a sequence of isolated facts to memorize, but one continuous, interlocking practice. If you can mentally re-run this walkthrough and explain *why* each step happened the way it did (not just *what* happened), you have genuinely internalized this material rather than just read it.

---
**Quick Self-Check Questions**
1. Why was the AC-02 population tested in full rather than via partial sampling, while AC-01 used a 20-sample stratified approach?
2. Explain why the contractor termination exception was treated as more severe (systemic) than the 31-hour delay exception, even though both were "late" under the same control.
3. Why does a repeat finding from the prior year typically escalate in severity versus an identical first-time finding?
4. Walk through why the AC-01 exception was concluded as Low/isolated rather than a formal High/Medium finding — what specific investigation step justified that conclusion?
5. How did the issue discussion conversations (Step 7) change or sharpen the eventual recommendations, beyond what testing alone revealed?
