# Module 9 — Control Testing

This module covers the actual mechanics of *how* auditors determine whether a control is good. It ties together Module 2's RCM, Module 8's evidence, and feeds directly into Module 10's findings.

## 1. Design Effectiveness vs. Operating Effectiveness

This is the single most important conceptual distinction in control testing, and it's worth fully internalizing before anything else in this module.

- **Design Effectiveness** — Is the control, *as designed*, capable of preventing or detecting the risk it's meant to address, **if it operates as intended**? This is assessed once (or whenever the control/process changes), typically via a walkthrough (Module 2).
- **Operating Effectiveness** — Did the control **actually operate consistently as designed**, throughout the period under review, in practice? This requires testing actual instances across the testing period, not just understanding the theoretical process.

### Why Both Matter — and Why You Test Them Separately
A control can be **well-designed but poorly operated** (e.g., a good access review process exists, but the Q3 review was simply never performed due to a staffing gap) — design effectiveness would pass, operating effectiveness would fail. Conversely, a control can be **operating exactly as designed, but the design itself is inadequate** (e.g., access reviews are performed perfectly every quarter, but the review only covers a subset of in-scope systems) — here design effectiveness fails even though everyone is doing exactly what the (flawed) procedure says.

**You cannot conclude a control is effective unless BOTH design and operating effectiveness pass.**

## 2. Sampling

Testing the entire population of control instances (e.g., every single access request all year) is usually impractical, so auditors use statistically/professionally justified **sampling** to draw conclusions about the full population from a representative subset.

### Key Sampling Concepts

- **Population** — the complete set of instances the control applies to during the testing period (e.g., all 450 new hires in the fiscal year).
- **Sample** — the subset actually selected and tested (e.g., 25 of those 450).
- **Sample size determination** — typically based on control frequency and risk:
  - **Annual controls** — test all instances (population = sample, since there are so few, e.g., 1).
  - **Quarterly controls** — typically test all 4 instances (again, population is small).
  - **Monthly controls** — commonly sample 2-4 of the 12 instances depending on risk rating.
  - **Daily/continuous/high-volume controls** (e.g., individual access provisioning events) — sample sizes commonly range from 25-60 depending on the auditor's risk assessment, firm methodology, and whether reliance is being placed by an external auditor (external audit standards like AICPA/PCAOB guidance often drive specific minimum sample sizes for higher-risk, high-volume IT-dependent controls).
- **Sample selection method** — should be such that every item in the population has a chance of being selected (random selection, or systematic/haphazard selection that avoids bias) — **auditors should never let the client choose which samples to provide**, as this defeats the purpose of independent testing.

### Negative Outcomes from Sampling

If even **one exception is found** in a sample, the standard response is **NOT** simply to note "1 out of 25 failed, 96% pass rate, good enough." Instead, auditors typically:
1. Investigate the exception's root cause.
2. Determine if it's an **isolated incident** or indicates a **systemic** problem.
3. Often **expand the sample** (test additional instances) to determine the true extent of the issue.
4. If the issue appears pervasive, conclude the control failed operating effectiveness, regardless of the original sample's pass percentage.

This is a frequently misunderstood point even by people newer to audit — there's no "passing percentage" threshold like a school exam; **a single well-substantiated exception can be enough to fail a control**, depending on its nature and pervasiveness.

## 3. Evidence Validation

Covered extensively in Module 8 — the process of confirming evidence is sufficient, reliable, and actually answers the test question before relying on it for a conclusion.

## 4. The Five Core Testing Techniques

These five techniques (sometimes grouped slightly differently across firms/standards, but consistently these five core ideas) are the actual mechanical tools auditors use to test both design and operating effectiveness.

### 4.1 Walkthrough
Covered fully in Module 2 — tracing one transaction/instance through the entire process to understand and validate the design. Primarily a **design effectiveness** tool, though it can surface early operating-effectiveness concerns.

### 4.2 Re-performance
**The strongest testing technique.** The auditor independently redoes the control themselves and compares their own result against the control owner's reported/recorded result.

**Example:** For a control stating "the system automatically calculates depreciation," the auditor independently recalculates depreciation for a sample of assets using the same inputs and formula, and compares their answer to the system's output. If they match, strong evidence the control operates correctly; if they don't, that's a finding requiring investigation.

### 4.3 Inquiry
Asking the control owner/performer to describe how the control works and confirm it operated.

**Critical limitation: Inquiry alone is NEVER sufficient evidence.** It must always be corroborated by at least one other technique (inspection, observation, or re-performance), because inquiry relies entirely on the interviewee's memory, honesty, and understanding — none of which is independently verifiable on its own.

### 4.4 Observation
Watching the control being performed in real time (live or via recorded screen-share) rather than relying on after-the-fact documentation.

**Limitation:** Observation only confirms the control operated correctly **at the specific moment observed** — it says nothing about whether it operated correctly at other times during the testing period (this is why observation is often paired with inspection of historical evidence to cover the full period).

### 4.5 Inspection
Examining documentation/evidence (Module 8) to confirm a control operated — the most commonly used technique for operating effectiveness testing across a sample, since it can be applied retrospectively across the full testing period without needing to "catch" the control in the act.

### Technique Strength Summary (General Rule of Thumb)

```
Strongest  →  Re-performance
              Inspection (of strong/system-generated evidence)
              Observation
              Inquiry (corroborating only — never standalone)
Weakest    →  (Inquiry alone is treated as essentially no evidence)
```

## 5. Population, Exceptions, Deviation, Deficiency — Precise Definitions

These terms are used precisely in audit work and are frequently confused by newcomers, so it's worth being exact:

- **Population** — the complete set of instances/transactions the control applies to during the period (already defined above).
- **Exception** — an instance, found during testing, where the control did **not** operate as expected (e.g., one termination where access was disabled 4 days late instead of within 24 hours).
- **Deviation** — closely related to "exception," often used interchangeably, but more specifically refers to a departure from the *prescribed procedure* (the control didn't follow its documented process), whereas "exception" is the broader/more commonly used term for any failed test instance. In practice, most teams use these terms interchangeably; know that some methodologies distinguish them, but don't over-engineer the distinction if your organization uses them as synonyms.
- **Deficiency** — the **conclusion** drawn from one or more exceptions: a deficiency exists when the design or operation of a control does not allow management or employees, in the normal course of performing their assigned functions, to prevent or detect misstatements on a timely basis. A deficiency is the formal audit/SOX term that then gets severity-rated (Module 10):
  - **Control Deficiency** — the base-level finding.
  - **Significant Deficiency** — a deficiency, or combination of deficiencies, that is less severe than a material weakness but important enough to merit attention by those responsible for oversight (e.g., the audit committee).
  - **Material Weakness** — a deficiency, or combination of deficiencies, such that there is a **reasonable possibility** that a material misstatement of the financial statements will not be prevented or detected on a timely basis. This is the most severe classification and has direct, public disclosure implications for SOX-covered companies (a material weakness must be disclosed in the company's public filings).

### The Exception → Deficiency → Severity Pipeline

```
Test finds 1+ Exceptions
        ↓
Root cause investigated; is it isolated or pervasive?
        ↓
If the exception(s) indicate the control didn't achieve its objective →
        Deficiency is concluded
        ↓
Deficiency severity is assessed (Module 10 covers this in depth):
   Control Deficiency  →  Significant Deficiency  →  Material Weakness
        ↓
Findings documented, remediation tracked (Module 10)
```

## 6. Putting It Together — A Worked Example

**Control:** "Quarterly user access reviews are performed by application owners for all financially-relevant systems; identified excess access is revoked within 10 business days."

**Design Effectiveness Test (Walkthrough):**
- Inquire with the IAM governance team about how the campaign is configured (inquiry — needs corroboration).
- Observe a live walkthrough of the access review tool, watching a reviewer actually certify a test account (observation).
- Inspect the tool's configuration to confirm all in-scope financial systems are actually included in the campaign scope (inspection) — this is where design gaps are often found (e.g., a newly added financial system was never added to the review tool's scope).

**Operating Effectiveness Test:**
- Obtain the full population: all 4 quarterly campaigns for the year, with the list of all reviewers and their certification status (inspection of system-generated campaign reports).
- Sample selection: select, e.g., 25 individual reviewer certifications across the 4 quarters (sampling).
- For each sampled item: inspect that the review was completed by the correct, authorized reviewer (inspection), and for any item where access was marked "revoke," inspect IAM logs to confirm the revocation was technically executed within 10 business days (inspection/re-performance — independently checking the actual disablement timestamp against the certification timestamp).

**Exception Found:** 2 of 25 sampled "revoke" decisions were not executed in AD until 15 and 18 business days after certification, exceeding the 10-day SLA.

**Conclusion:** Root cause investigated — found to be a manual handoff step between the access review tool and the IAM provisioning team with no automated trigger, and a finding of this nature in 2/25 (8%) sampled items, combined with the systemic root cause (manual handoff, not isolated human error) suggests the issue could affect a meaningful portion of the population. This would typically be escalated to at least a **Significant Deficiency** pending further evaluation of financial statement impact, and would generate a formal audit finding (Module 10) with a remediation recommendation (e.g., automate the handoff, or add a detective control to catch SLA breaches faster).

---
**Quick Self-Check Questions**
1. Explain, with an original example, how a control could pass design effectiveness but fail operating effectiveness, and vice versa.
2. Why is inquiry alone never sufficient evidence, no matter how senior or credible the person being interviewed is?
3. If 1 exception is found in a sample of 25, why is "96% pass rate, that's fine" the wrong way to think about the result?
4. Rank re-performance, observation, inspection, and inquiry from strongest to weakest as standalone testing techniques.
5. Define the escalation pipeline from Control Deficiency → Significant Deficiency → Material Weakness, and explain what distinguishes each tier.
6. Using the worked example above, explain why the auditor needed to determine whether the root cause was "isolated" vs. "systemic" before concluding on severity.
