# Module 4 — ITGC (IT General Controls)

This is the single most important module for day-to-day audit/cybersecurity-practice work. ITGC controls are the foundation everything else depends on: if access, change, or operations controls are broken, no automated application control or financial report relying on that system can be trusted, no matter how well-designed it looks on paper. This is called **ITGC reliance** — auditors cannot rely on application controls without first concluding the underlying IT environment is controlled.

## Part A — Logical Access Management

### A.1 Authentication

Authentication answers the question **"are you who you claim to be?"** It is the first gate in any access control system.

- **Something you know** — password, PIN.
- **Something you have** — hardware token, smartphone (push notification, OTP app), smart card.
- **Something you are** — biometrics (fingerprint, face).
- **Somewhere you are** — geolocation/network-based context (less common as a standalone factor, more used for risk scoring).

**Single-Factor vs. Multi-Factor Authentication (MFA):** Single-factor (password only) is now considered an audit finding by default for any privileged or financially-relevant system access — password-only authentication is trivially defeated by phishing, credential stuffing, and password reuse. MFA combining at least two independent factor categories is the modern minimum control expectation.

**Audit testing angle:** Auditors test authentication by inspecting system configuration (is MFA enforced at the policy/group level, not just "available"?) and by inspecting password policy settings (minimum length, complexity, expiration, lockout threshold) against the organization's documented policy.

### A.2 Authorization

Authorization answers **"what are you allowed to do, now that we know who you are?"** This is distinct from authentication and is where most access-related audit findings actually live (a user can be correctly authenticated as themselves, yet still hold *authorization* far beyond what their role requires).

Authorization is implemented through models like RBAC and ABAC (detailed in Module 5), and is governed by the principles below.

### A.3 Least Privilege

The principle that every user, account, and process should be granted the **minimum level of access necessary** to perform its function — nothing more.

- **Why it matters:** Excess privilege is the single biggest amplifier of both insider risk and external attacker impact. If an attacker compromises a low-privilege account, least privilege limits the "blast radius" of that compromise.
- **Audit testing angle:** Auditors sample user access listings and compare actual granted permissions against the documented role/job function, looking for "privilege creep" — access accumulated over time (e.g., via role changes / "Mover" events, Part B below) that was never revoked.

### A.4 Need-to-Know

A closely related but distinct principle, originating in classified/intelligence contexts, focused on **data** rather than system function: even if you have the *authorization level* to access a category of information, you should only access the *specific* information you need for your current task.

- Least privilege = limiting **what actions/systems** you can access.
- Need-to-know = limiting **which specific data** within an authorized system you can/should access.
- Example: a DBA might have least-privilege authorization to administer a customer database (a system-level grant), but need-to-know would still restrict them from browsing individual customer PII records without a business reason — often enforced via logging + detective review rather than a hard technical block, since DBAs often need broad technical access to do their job.

### A.5 Separation/Segregation of Duties (SoD)

SoD is the principle that no single individual should control all phases of a sensitive transaction or process — specifically, the ability to **initiate**, **approve**, and **record/reconcile** a transaction should be split across different people.

#### Classic SoD Conflict Examples

- A person who can **create a vendor** in the system should not also be able to **approve payments** to that vendor (classic fraud vector — create a fake vendor, approve payment to yourself).
- A developer who can **write code** should not also be able to **deploy it to production** unreviewed (change management SoD — Module 6).
- An IAM administrator who **provisions access** should not be the same person who **approves the access request**.
- A payroll administrator who can **add employees** should not also **approve payroll runs**.

#### SoD in IT Systems Specifically

In modern ERP/financial systems (SAP, Oracle), SoD conflicts are often defined at the **transaction code / role** level and tested using automated SoD analysis tools (e.g., SAP GRC Access Control) that flag when a single user's combined roles create a toxic combination, even if no individual role looks risky alone.

**Compensating controls:** When SoD cannot be fully achieved (common in smaller organizations or small IT teams), organizations implement compensating controls — typically a detective control such as independent review/monitoring of the conflicted user's activity logs by someone else.

### A.6 Privileged Access Management (PAM)

Privileged accounts (admin, root, domain admin, database admin, cloud IAM admin) carry outsized risk because compromise of even one provides broad system control. PAM is the discipline and toolset for securing, monitoring, and limiting privileged access.

#### Key PAM Concepts

- **Just-in-Time (JIT) Access** — privileged access is granted only for a defined, time-bound window when needed, then automatically revoked, rather than being "standing" (always-on) access.
- **Credential Vaulting** — privileged credentials (passwords, SSH keys) are stored in an encrypted vault and checked out/rotated automatically rather than known/memorized by humans.
- **Session Recording/Monitoring** — privileged sessions are recorded for after-the-fact review and forensic capability.
- **Privileged Access Workstations (PAWs)** — dedicated, hardened workstations used only for privileged administrative tasks, isolated from general email/web browsing risk.

#### Shared Accounts

Accounts used by multiple people simultaneously (e.g., a generic "admin" or "sa" database account). These are a major audit and security red flag because:
- Actions cannot be attributed to an individual (breaks accountability/non-repudiation).
- Password rotation/offboarding becomes nearly impossible to manage cleanly (when one user who knows the shared password leaves, you'd need to rotate the password and notify everyone else who legitimately uses it).

**Audit expectation:** Shared accounts should be eliminated wherever technically feasible; where unavoidable (e.g., certain legacy system constraints), they require compensating controls — typically a check-out/check-in log via a PAM tool that creates individual accountability even over a shared credential.

#### Service Accounts

Non-human accounts used by applications/systems/scripts to authenticate to other systems (e.g., an application's account used to connect to a database).

- **Risks:** Often over-privileged "by default," passwords rarely rotated (because rotating breaks the application if not coordinated), and frequently excluded from standard JML processes since "no human owns it" — yet they absolutely need an accountable human owner.
- **Audit expectation:** Service accounts should have a documented business owner, restricted permissions scoped to only what the application needs, regular password rotation (or certificate-based/managed identity authentication where the platform supports it), and should be included in periodic access reviews just like human accounts.

#### Emergency Access ("Break-Glass" Accounts)

Pre-provisioned, normally-disabled privileged accounts reserved for use during emergencies/outages when normal access processes would be too slow.

- **Controls required:** Tightly restricted (often requiring two-person knowledge to use, e.g., one person knows half the password), every use must trigger an automatic alert, every use must be logged and followed by a mandatory after-the-fact review/justification within a defined window (e.g., 24-48 hours).

## Part B — User Lifecycle (Joiner-Mover-Leaver / JML)

The JML process is one of the most heavily tested ITGC areas because it directly determines whether "access matches need" stays true over time. This is the area Mohit's prior modules on Access Management (Module 5) will build on further.

### B.1 Joiner — The Full Process

```
HR Creates New Hire Record
        ↓
Manager Approval (role/access requested matches job function)
        ↓
Access Request Generated (manual ticket or automated via role-based template)
        ↓
IAM Team Reviews Request
        ↓
Provisioning (account created, access granted in target systems)
        ↓
Verification (confirm provisioned access matches what was approved — no more, no less)
        ↓
Evidence Captured & Retained
```

**Detailed breakdown of each stage:**

1. **HR Initiation** — The system of record (Workday, SAP SuccessFactors, etc.) creates the new hire record with role, department, manager, and start date. This record is frequently the authoritative trigger for everything downstream — auditors will reconcile the HR new-hire list against IAM provisioning records to find gaps (someone provisioned without a corresponding HR record = a major red flag; someone in HR with no provisioned access by day 1 = an operational/SLA issue).

2. **Manager Approval** — The hiring manager (or a role-based access matrix) determines exactly what access is appropriate. Best practice: access requested should map to a pre-approved **role template** (standard access bundle for a given job title) rather than ad-hoc requests, since ad-hoc requests are harder to audit and more prone to over-provisioning.

3. **Access Request** — Formal ticket (ServiceNow, Jira Service Management, etc.) capturing what's being requested, by whom, and the approval.

4. **IAM Team Review** — IAM validates the request is properly approved and doesn't violate SoD rules before provisioning (a second checkpoint, not just rubber-stamping the manager's approval).

5. **Provisioning** — Technical creation of accounts and assignment of access in Active Directory, applications, cloud platforms, etc. Often partially or fully automated via identity governance tools (SailPoint, Saviynt, Microsoft Entra ID Governance) that read the approved role and auto-provision corresponding access.

6. **Verification** — A check (ideally independent of the person who provisioned) that what was actually granted matches what was approved.

7. **Evidence** — Screenshots, system logs, ticket records, timestamps — retained per policy for audit testing.

### B.2 Mover — Department/Role Change

When an employee changes roles, departments, or managers, their access needs change — and this is **the single most common source of "privilege creep"** in real organizations, because:
- New access for the new role is often granted promptly (the business needs it to function).
- **Old access from the previous role is frequently NOT revoked**, because no one's incentive is tied to removing access, and the "Mover" process is structurally weaker than Joiner/Leaver in most organizations.

#### Mover Process Requirements

- Role change in HR system should trigger an **access re-certification**, not just new grants — i.e., a structured review of ALL existing access (old + new) to determine what should be kept, modified, or revoked.
- Evidence should show both the new access granted AND the old access explicitly revoked (or a documented, approved exception for why it was retained).
- **Testing focus:** Auditors specifically sample "Mover" events and check whether old-role access was removed within the defined SLA (commonly the same 24-48hr-style window as terminations, though sometimes a longer window is policy-defined, e.g., 5-10 business days).

### B.3 Leaver — Termination

The highest-risk JML event from a pure security perspective, because a delay here means a former employee retains active access to company systems.

```
Employee Resigns / Is Terminated
        ↓
HR Logs Termination Date (sometimes immediate, sometimes future-dated for notice periods)
        ↓
Disable Account (system access)
        ↓
Delete/Revoke Access (across ALL systems, not just primary directory)
        ↓
Collect Company Assets (laptop, badge, tokens)
        ↓
Audit Trail Captured
        ↓
Evidence Retained
        ↓
Testing (sample-based verification by IA/external audit)
        ↓
Gap Identification (any terminated user found with active access = a "finding")
```

#### Key Nuances

- **Voluntary vs. involuntary termination:** Involuntary/for-cause terminations typically require **immediate** access disablement (often within the hour, sometimes even before the termination conversation happens, to prevent data destruction/sabotage), whereas voluntary resignations with a notice period may have access reduced progressively or disabled at end-of-notice — but financially-sensitive or privileged access is still commonly disabled immediately regardless of termination type as a baseline control.
- **"All systems" is the hard part:** Disabling the primary Active Directory/SSO account often doesn't actually revoke access everywhere — local accounts on individual servers, VPN access, cloud platform IAM, third-party SaaS tools with separate logins, and physical badge access all need to be covered. This is exactly why "orphan accounts" (Module 5) exist — accounts in secondary systems that were never connected to the central JML process.
- **Evidence chain:** Auditors want to see the HR termination date, the timestamp access was disabled, and confirmation this falls within policy SLA — and they typically sample this against the **complete termination population** for the audit period (often pulled directly from HR/payroll records as the independent source of truth, since you can't sample for "people who left and we never even processed" by looking only at IT's own termination log).

### B.4 Common JML Testing/Evidence/Gap Patterns (tying B.1–B.3 together)

| JML Stage | Most Common Audit Finding |
|---|---|
| Joiner | Access granted before approval was obtained (provisioning outpaced approval) |
| Joiner | Access granted exceeds the approved role template (over-provisioning) |
| Mover | Old access never revoked after role change (privilege creep) |
| Mover | No re-certification triggered by the role change event at all |
| Leaver | Access disabled later than policy SLA |
| Leaver | Access disabled in primary directory but still active in a secondary/local system |
| Leaver | No HR-to-IT termination feed exists at all for certain employee types (contractors are a frequent gap) |

## Part C — Tying ITGC Back to Control Objectives (Module 2 Recap)

Recall from Module 2 that ITGC is structured around four control objectives. Logical Access Management (this module) satisfies Objective 1 ("Access to programs and data is appropriately restricted"). Modules 6 (Change Management) and the operations-focused parts of Module 4's broader scope satisfy Objectives 2-4.

When you build or test a Risk Control Matrix entry for any access control, always be able to answer:
1. **Which control objective** does this satisfy?
2. **Which financial assertion(s)** does it ultimately protect (usually Existence/Occurrence and Completeness for access controls)?
3. **Is it preventive or detective**, and is there a compensating control if it's not airtight?
4. **Who is the control owner**, and is that person independent of the risk they're controlling (SoD)?

## Part D — Security Engineering Perspective (Preview of Module 18 Lens Applied Here)

Since your stated trajectory is toward AppSec/security architecture, it's worth explicitly translating ITGC access concepts into security engineering terms now rather than waiting for Module 18:

- **Least privilege** in audit language = **principle of least privilege (PoLP)** in security architecture — the same concept underlies zero-trust architecture, IAM policy design (AWS IAM least-privilege policies, Azure RBAC custom roles), and microsegmentation.
- **SoD** in audit language = a control that, if violated, creates a **single point of compromise** for fraud; in security terms, this is directly analogous to **why CI/CD pipelines separate "who can merge code" from "who can deploy to prod"** — the exact same SoD logic, just applied to a DevSecOps pipeline instead of a financial transaction.
- **JML process gaps** are, from a pure attack-surface perspective, literally **how real breaches happen** — a huge proportion of real-world incidents trace back to either an orphaned/leaver account that was never disabled, or a service account with excessive standing privilege that was compromised (this is precisely the kind of control gap your Agentic AI Email Security Platform's risk fusion logic would want to flag as an anomaly: access activity from an account that HR records show should be terminated).
- **PAM's "Just-in-Time" access model** is the audit/GRC-world's name for what's increasingly called **Zero Standing Privilege (ZSP)** in modern cloud security architecture — eliminating always-on admin rights entirely in favor of ephemeral, approved, time-boxed elevation.

---
**Quick Self-Check Questions**
1. Explain the difference between authentication and authorization with a concrete example.
2. Why is "Mover" typically the weakest link in JML compared to Joiner and Leaver?
3. What specific risk does a shared account create that a service account does not (and vice versa)?
4. Walk through the full Joiner process from HR record creation to evidence retention.
5. Why must "Leaver" access removal be tested against the complete HR termination population rather than just IT's own termination log?
6. How does Just-in-Time privileged access map to the concept of Zero Standing Privilege in modern cloud security?
7. Give an example of an SoD conflict in a DevOps/CI-CD context, parallel to the classic "create vendor / approve payment" finance example.
