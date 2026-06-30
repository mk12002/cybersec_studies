# Module 1 — Enterprise IT Governance

## 1. What is Corporate Governance?

Corporate governance is the system of rules, practices, and processes by which a company is directed and controlled. It defines how responsibility and authority flow from shareholders down to the board, to executive management, and through the organization to operational staff.

At its core, governance exists to answer one question: **how do we know the people running the company are acting in the interest of the people who own it (and the stakeholders affected by it)?**

Key components:

- **Board of Directors** — ultimate oversight body, sets strategic direction, hires/fires the CEO, approves major decisions.
- **Executive Management (C-suite)** — runs day-to-day operations, executes strategy, accountable to the board.
- **Shareholders/Owners** — provide capital, vote on major matters, elect the board.
- **Stakeholders** — employees, customers, regulators, communities — parties affected by company decisions even without formal ownership.

Governance failures (Enron, WorldCom, Satyam, Wirecard) typically share a pattern: concentrated power, weak board oversight, conflicted auditors, and a culture that punished bad news. This is why modern governance frameworks insist on **independence** (independent directors, independent audit committees) and **segregation** of who sets policy, who executes it, and who checks it.

**Why this matters for IT/security audit:** IT governance is a subset of corporate governance. When you test an access control or a change management process, you are really testing whether corporate governance principles (accountability, segregation of duties, oversight) have been implemented correctly at the technical layer.

## 2. Risk Management

Risk management is the discipline of identifying, assessing, treating, and monitoring events that could prevent an organization from achieving its objectives.

### The Risk Management Lifecycle

1. **Risk Identification** — what could go wrong? (threat sources, vulnerabilities, scenarios)
2. **Risk Assessment** — how likely, and how severe? Usually scored as `Risk = Likelihood × Impact`
3. **Risk Treatment** — four classic options:
   - **Avoid** — stop doing the risky activity
   - **Mitigate** — implement controls to reduce likelihood/impact
   - **Transfer** — insurance, outsourcing, contractual risk-shifting
   - **Accept** — formally acknowledge and accept the residual risk (must be signed off by someone with authority)
4. **Risk Monitoring** — ongoing tracking via KRIs (Key Risk Indicators), dashboards, periodic reassessment.

### Inherent Risk vs. Residual Risk

- **Inherent risk**: the risk level *before* any controls are applied.
- **Residual risk**: the risk level *after* controls are applied.
- `Residual Risk = Inherent Risk − Control Effectiveness`

This distinction is critical in audit. An auditor's job is often to evaluate whether residual risk is within the organization's **risk appetite** (how much risk leadership is willing to tolerate) and **risk tolerance** (acceptable variation around that appetite).

### Risk Register

A central artifact most organizations maintain, listing each identified risk with: description, owner, likelihood, impact, current controls, residual risk rating, and treatment plan. Auditors frequently request the risk register as a starting point for scoping.

**Security engineering angle:** In AppSec/security architecture, this is the same logic behind a threat model — you identify assets, threats, likelihood, impact, and existing/needed controls. STRIDE, DREAD, and FAIR (Factor Analysis of Information Risk) are formalized versions of this same risk lifecycle applied to systems.

## 3. Internal Controls

Internal controls are the specific mechanisms — policies, procedures, and technical safeguards — that an organization puts in place to ensure objectives are met, including reliable financial reporting, operational efficiency, and regulatory compliance.

### Categories of Controls (by function)

- **Preventive controls** — stop an error/fraud/incident before it happens (e.g., access provisioning approval, segregation of duties, firewall rules).
- **Detective controls** — identify that something already happened (e.g., log monitoring, reconciliation, access reviews).
- **Corrective controls** — fix the issue after detection (e.g., incident response, patching, account disablement).

### Categories of Controls (by nature)

- **Manual controls** — performed by a human (e.g., a manager reviewing and approving a report).
- **Automated/IT-dependent controls** — performed by a system, sometimes with a manual trigger (e.g., a system auto-locking an account after 90 days of inactivity).
- **IT General Controls (ITGC)** — controls over the IT environment itself (access, change, operations) that other controls depend on. Covered in depth in Module 4.
- **Application controls** — controls embedded within a specific business application (e.g., a three-way match in SAP before a payment is released).

### The Control Triangle

Every well-designed control should answer:
1. **What** is being controlled (the objective/risk)?
2. **Who** performs it (and is that person independent of the risk)?
3. **How** is it evidenced (so an auditor can verify it actually happened)?

A control that exists on paper but produces no evidence is, from an audit perspective, indistinguishable from a control that doesn't exist.

## 4. Why Companies Need Audits

Audits exist to provide **independent assurance** that financial statements, processes, or controls are accurate, complete, and operating as intended. Without independent verification, management's self-reported assurances carry an inherent conflict of interest (they are grading their own work).

### Types of Audits

- **External (Statutory) Audit** — performed by an independent firm (e.g., Big 4) to opine on financial statement accuracy, required by law for public companies.
- **Internal Audit** — performed by an in-house (or outsourced-but-internal-facing) team, reporting to the Audit Committee, evaluating risk management, controls, and governance broadly.
- **IT Audit** — focused specifically on technology controls supporting business and financial processes (this is where ITGC, access management, and change management testing live).
- **Regulatory/Compliance Audit** — conducted by or for a regulator to verify compliance with specific laws (RBI audits in India, FDA audits, PCI-DSS assessments).
- **Third-Party/Vendor Audit** — verifying that vendors/service providers meet contractual or regulatory security obligations (e.g., SOC 2 audits of SaaS vendors).

### Why They Matter Practically

- They protect investors and the public from fraud (Enron, Satyam).
- They create accountability — when people know controls will be tested, behavior changes (the "audit effect").
- They satisfy regulatory and legal requirements (SOX, JSOX, RBI, SEBI, GDPR-adjacent obligations).
- They surface operational weaknesses before they become incidents.

## 5. Three Lines of Defense

A foundational governance model describing how risk and control responsibilities are distributed across an organization.

### First Line — Operational Management
The business units and process owners who **own and manage risk directly**. They design and execute day-to-day controls (e.g., the IT team that provisions access, the developer who deploys code).

### Second Line — Risk Management & Compliance Functions
Functions that **oversee and support** the first line — setting policy, monitoring compliance, providing risk expertise. Examples: Information Security/GRC team, Compliance department, Enterprise Risk Management. They do not own the risk directly but ensure the first line is managing it properly.

### Third Line — Internal Audit
**Independent assurance** that both the first and second lines are functioning effectively. Internal Audit reports directly to the Audit Committee/Board (not to management) to preserve independence.

```
        BOARD / AUDIT COMMITTEE
                  |
   -----------------------------------
   |              |                  |
1st LINE       2nd LINE          3rd LINE
(Operations)   (Risk/Compliance) (Internal Audit)
Owns & manages  Oversees &        Provides independent
risk directly   monitors risk     assurance
```

A common interview/exam trap: confusing where Information Security sits. Depending on the organization, an InfoSec **operations** team (e.g., SOC analysts actually blocking threats) is first line; an InfoSec **governance/policy** team setting standards is second line. Know the distinction.

External auditors and regulators are sometimes referred to as a conceptual "fourth line," external to the organization entirely.

## 6. COBIT (Control Objectives for Information and Related Technologies)

COBIT, maintained by ISACA, is a framework for IT governance and management. It bridges the gap between business goals and IT processes, helping organizations ensure IT delivers value while managing risk.

### Key Concepts

- **Governance vs. Management** — COBIT explicitly separates these. Governance (Board-level) sets direction and monitors performance; Management (Executive-level) plans, builds, runs, and monitors activities in line with that direction.
- **COBIT 2019 Governance/Management Objectives** are grouped into domains:
  - **EDM** (Evaluate, Direct, Monitor) — governance domain
  - **APO** (Align, Plan, Organize)
  - **BAI** (Build, Acquire, Implement)
  - **DSS** (Deliver, Service, Support)
  - **MEA** (Monitor, Evaluate, Assess)

### Why Auditors Use COBIT

COBIT provides a structured catalog of control objectives that map directly to common ITGC domains: access management, change management, IT operations, vendor management. When an audit team builds a Risk Control Matrix (RCM) for ITGC testing, COBIT objectives are frequently the underlying reference framework, especially for SOX ITGC scoping.

## 7. COSO Framework (Committee of Sponsoring Organizations)

COSO is the dominant framework for **internal control over financial reporting** and enterprise risk management, and it underpins SOX compliance work directly.

### COSO Internal Control – Integrated Framework: 5 Components

1. **Control Environment** — the tone at the top; ethics, integrity, board oversight, organizational structure, competence.
2. **Risk Assessment** — how the organization identifies and analyzes risks to objectives.
3. **Control Activities** — the actual policies and procedures (this is where ITGC and application controls live).
4. **Information & Communication** — ensuring relevant information flows to the right people at the right time.
5. **Monitoring Activities** — ongoing or periodic evaluations to ensure controls are present and functioning (this is literally what internal audit does).

### The 17 Principles

Each of the 5 components is broken into specific principles (17 total) that must all be present and functioning for an entity to conclude its internal control system is effective. For exam/interview purposes, know that COSO is **principle-based**, not prescriptive — it tells you *what* must be true, not exactly *how* to implement it (that's where COBIT and ITGC frameworks fill in technical specifics).

### COSO ERM (Enterprise Risk Management) Framework

A complementary, broader framework (updated 2017) addressing strategy and performance, with 5 components: Governance & Culture, Strategy & Objective-Setting, Performance, Review & Revision, Information/Communication/Reporting.

**Relationship to SOX:** Public companies in the US almost universally use COSO as the control framework referenced in their SOX 404 management assessment. When a 10-K says "management used the COSO framework to assess internal control effectiveness," this is what they mean.

## 8. ISO 27001 Overview

ISO/IEC 27001 is the international standard for an **Information Security Management System (ISMS)** — a systematic approach to managing sensitive company information so that it remains secure.

### Core Structure

- **ISMS** — the overarching management system: policies, risk assessments, objectives, and continual improvement, not just a list of technical controls.
- **Annex A Controls** — (114 controls in the 2013 revision, reorganized into 93 controls across 4 themes in ISO 27001:2022): Organizational, People, Physical, Technological controls.
- **Risk-based approach** — organizations are required to perform a formal risk assessment and select controls (a "Statement of Applicability") justified by that risk assessment, not apply every control blindly.
- **Plan-Do-Check-Act (PDCA) cycle** — the continual improvement engine behind the ISMS.

### Certification

Organizations can be formally certified against ISO 27001 by an accredited certification body, which involves a **Stage 1** (documentation review) and **Stage 2** (implementation effectiveness) audit, followed by annual surveillance audits and 3-year recertification.

**Relevance to your career direction:** ISO 27001 is the most internationally recognized security management certification standard, and is frequently referenced alongside SOC 2 in vendor risk assessments and client security questionnaires — directly relevant to the discovery questionnaires you've been building at ITC Infotech.

## 9. NIST CSF Overview (Cybersecurity Framework)

Developed by the US National Institute of Standards and Technology, NIST CSF is a voluntary, outcome-based framework for managing cybersecurity risk, widely adopted even outside the US.

### NIST CSF 2.0 Functions

1. **Govern** — (new in 2.0) establishes and monitors the organization's cybersecurity risk management strategy, expectations, and policy.
2. **Identify** — understand assets, risks, and the business context.
3. **Protect** — implement safeguards (access control, awareness training, data security).
4. **Detect** — implement activities to identify cybersecurity events (monitoring, anomaly detection).
5. **Respond** — take action regarding a detected incident.
6. **Recover** — restore capabilities/services impaired by an incident.

### NIST CSF vs. ISO 27001 vs. COBIT — Quick Comparison

| Framework | Primary Focus | Mandatory? | Best For |
|---|---|---|---|
| COBIT | IT governance & management alignment to business goals | No (best practice) | IT governance structure, SOX ITGC scoping |
| COSO | Internal control over financial reporting & ERM | Effectively yes for US public companies (SOX) | Financial reporting controls |
| ISO 27001 | Information security management system | No (certifiable) | Formal ISMS, international security certification |
| NIST CSF | Cybersecurity risk management | No (but often referenced by regulators) | Cybersecurity program maturity, threat-driven |

Auditors and security architects often **cross-map** these frameworks since most controls overlap conceptually (e.g., "access control" exists in some form in all four). Crosswalks/mappings between frameworks are common deliverables in GRC work.

## 10. Relationship Between Governance, Risk, and Compliance (GRC)

GRC describes the integrated approach organizations use to align IT with business objectives while managing risk and meeting compliance obligations.

- **Governance** sets the direction — who decides what, and how decisions get made and overseen.
- **Risk Management** identifies and treats the things that could derail those objectives.
- **Compliance** ensures the organization operates within the boundaries set by laws, regulations, and internal policy.

These three are deeply interdependent: governance defines the risk appetite that risk management operationalizes; compliance requirements often *are* a primary input to the risk register; and audit (acting on behalf of governance) tests whether risk management and compliance are functioning as designed.

### Why This Module Matters Going Forward

Every subsequent module in this guide is, in effect, a more granular instantiation of GRC:
- Module 2 (SOX/JSOX) = a specific **compliance** regime requiring specific **governance** (Section 302/404 certifications) over specific **risks** (financial misstatement).
- Module 4 (ITGC) = the **control activities** (COSO component 3) that make financial reporting risk manageable.
- Module 9–11 (Testing, Findings, Audit Lifecycle) = the **monitoring** (COSO component 5) and **third line of defense** mechanics that close the GRC loop.

Understanding this module deeply means you'll never be lost about *why* a control exists — you can always trace it back to: which framework requires it, which risk it mitigates, and which line of defense owns it.

---
**Quick Self-Check Questions**
1. What's the difference between inherent risk and residual risk?
2. Which COSO component does "internal audit" itself belong to?
3. Name the three lines of defense and one example function in each.
4. Why does ISO 27001 require a Statement of Applicability rather than mandating all Annex A controls?
5. How does COBIT's EDM domain differ from its APO/BAI/DSS/MEA domains?
