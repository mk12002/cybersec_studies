# Module 16 — Common Audit Findings

This module is a focused, practical catalog of the findings you will encounter constantly in real ITGC/IT audit work — what causes them, how they're typically tested, and how they're typically remediated. Treat this as your "pattern recognition" reference, synthesizing concepts from Modules 4-10 into the specific recurring findings that show up across virtually every audit engagement and every organization, regardless of industry.

## 1. Late Access Removal

**Pattern:** Terminated or role-changed employees retain access beyond the policy-defined SLA (Module 4, Leaver/Mover).

**Typical Root Causes:**
- Manual handoff steps between HR and IT/IAM with no automated trigger or SLA monitoring.
- Contractors/non-employee workers excluded from the standard HR-driven termination feed (a very common and often-overlooked gap, since contractor offboarding is frequently managed by a different, less rigorous process than employee offboarding).
- Access existing in secondary/local systems not connected to the central identity governance platform (the "all systems" problem from Module 4).

**Typical Remediation:** Automate the HR-to-IAM feed; implement SLA monitoring/alerting; extend JML process coverage explicitly to contractors/non-employees; complete an inventory of all systems with local/non-federated authentication and bring them into the central provisioning/deprovisioning process.

## 2. Missing Approvals

**Pattern:** Access granted, or a change deployed, with no evidence of required approval — or approval evidenced but timestamped after the fact (Module 6, Module 8).

**Typical Root Causes:** Process bypassed under time pressure; approval obtained verbally/informally and never captured in the system of record; approval workflow misconfigured to not actually require the approval step it's supposed to enforce.

**Typical Remediation:** System-enforced approval gates (so the action literally cannot proceed without a recorded approval) rather than relying on a documented-but-optional process step; periodic configuration testing of approval workflow rules (a design effectiveness check, Module 9) to confirm the system actually enforces what policy requires.

## 3. Inactive/Dormant Users

**Pattern:** Accounts unused for an extended period remain enabled (Module 5).

**Typical Root Causes:** No automated dormancy detection; access reviews don't specifically flag/require justification for dormant accounts even when general access reviews occur; accounts for employees on extended leave not handled with a clear policy (these are legitimately "dormant" but not necessarily inappropriate — auditors need a defined exception process for genuinely valid cases like medical/parental leave).

**Typical Remediation:** Automated dormancy detection with auto-disable after a defined threshold (with a defined exception/reactivation process for legitimate leave cases); inclusion of dormancy status as a specific data point surfaced during access reviews.

## 4. Shared IDs

**Pattern:** Multiple individuals use a single set of credentials (Module 4, Part A.6).

**Typical Root Causes:** Legacy system technical limitations (doesn't support individual accounts); operational convenience (a team "shares" an admin account rather than each member having individually provisioned, appropriately-scoped access); cost (some licensing models charge per named user, creating a perverse incentive to share accounts).

**Typical Remediation:** Eliminate where technically feasible; where unavoidable, implement PAM-based check-out/check-in logging to restore individual accountability, with mandatory password rotation after each use.

## 5. No MFA

**Pattern:** Single-factor (password-only) authentication on systems that should require MFA, especially privileged or financially-relevant access (Module 5).

**Typical Root Causes:** Legacy systems with no native MFA support; MFA available but not enforced (configured as optional rather than mandatory at the policy/Conditional Access level); inconsistent enforcement across different access paths to the same system (e.g., MFA enforced for the web portal but not for a legacy API/direct database connection achieving the same access).

**Typical Remediation:** Enforce MFA at the identity provider/Conditional Access layer (Module 5) for all access paths, not just the primary one; for legacy systems without native MFA support, implement a compensating control such as a PAM gateway/jump host that enforces MFA before granting the legacy system connection.

## 6. Weak Passwords

**Pattern:** Password policy configuration doesn't meet organizational standard, or — more subtly — meets the *configured* standard but the configured standard itself is outdated/insufficient (Module 14).

**Typical Root Causes:** Legacy Group Policy settings never updated as standards evolved; Fine-Grained Password Policies inconsistently applied across different OUs; service/application accounts excluded from standard password policy enforcement entirely.

**Typical Remediation:** Update Group Policy/Conditional Access password requirements to current organizational standard; extend coverage explicitly to service accounts (with appropriate rotation mechanisms given they can't simply "re-enter" a new password manually); breach-database screening (checking new passwords against known-compromised password lists) per modern guidance.

## 7. Missing CAB

**Pattern:** A change classified as Normal (requiring CAB review) was deployed without evidence of actual CAB approval, OR a change that should have been classified Normal was misclassified as Standard/pre-approved to bypass review (Module 6).

**Typical Root Causes:** Time pressure leading to deliberate or accidental misclassification; CAB process itself too slow/bureaucratic, creating incentive to route around it; unclear or overly broad criteria for what qualifies as a "Standard" pre-approved change.

**Typical Remediation:** Tighten and clearly document Standard change criteria to prevent ambiguous misclassification; streamline CAB process (e.g., asynchronous approval for lower-risk Normal changes rather than requiring a full weekly meeting) to reduce the underlying incentive to bypass it; periodic reconciliation of all production deployments against the Change module to catch any deployment with no corresponding change record at all.

## 8. No Rollback

**Pattern:** A deployed change had no documented rollback/backout plan (Module 6).

**Typical Root Causes:** Rollback plan treated as a formality/checkbox rather than genuinely prepared and validated; some change types (e.g., database schema changes, certain irreversible data migrations) genuinely lack a clean technical rollback path, but this should be explicitly acknowledged and risk-assessed, not simply omitted from documentation.

**Typical Remediation:** Make rollback plan a mandatory, validated field in the change ticket before CAB approval can be granted; for genuinely irreversible changes, require an explicit risk acceptance and enhanced testing/staging validation in lieu of rollback capability.

## 9. No Incident RCA

**Pattern:** Root Cause Analysis not performed (or not adequately performed) for significant incidents (Module 7).

**Typical Root Causes:** Organizational pressure to "move on" after resolution rather than invest in post-incident analysis; RCA performed informally/verbally but never documented; RCA performed but no resulting CAPA tracked to completion (so even where the root cause was identified, nothing actually changed).

**Typical Remediation:** Make RCA a mandatory, tracked step for all Sev1/Sev2 (or equivalent) incidents before closure is permitted; implement blameless post-mortem culture (Module 7) to reduce the organizational incentive to skip honest RCA; track CAPA items in a system separate from the incident ticket itself, with its own ownership and due-date tracking, so CAPA completion doesn't get lost once the incident ticket is closed.

## 10. Expired Certificates

**Pattern:** TLS/SSL certificates (or other digital certificates used for authentication/encryption) expire without renewal, causing outages or, more subtly, creating security gaps if expired-certificate warnings train users/systems to click through/ignore certificate errors.

**Typical Root Causes:** No centralized certificate inventory/expiration tracking; certificate renewal owned by an individual rather than a team/automated process (single point of failure if that individual leaves or is unavailable — itself a form of the "bus factor" risk relevant to operational resilience); manual renewal processes prone to being deprioritized against other work until the certificate has already expired.

**Typical Remediation:** Centralized certificate inventory with automated expiration alerting (well in advance, e.g., 30/60/90-day warnings); automated certificate renewal/rotation where technically feasible (e.g., via ACME protocol/Let's Encrypt-style automation, or cloud-native certificate management services); explicit team (not individual) ownership of certificate management as a process, fitting the same "control owner, not just control performer" principle from Module 3.

## 11. Cross-Cutting Pattern Recognition

Looking across all eleven findings above, a small number of **systemic root cause categories** repeat constantly:

1. **Manual processes with no automated enforcement or monitoring** (late access removal, missing approvals, no MFA enforcement consistency).
2. **Incomplete scope/coverage** — a control exists and works, but doesn't cover everything it should (contractors excluded from JML, legacy systems excluded from MFA, secondary systems excluded from central deprovisioning).
3. **Individual ownership where team/systemic ownership is needed** (certificate management bus-factor risk, RCA/CAPA follow-through).
4. **Process designed correctly but bypassed under pressure** (missing CAB, no rollback, skipped RCA) — almost always traceable to either genuine time pressure or a process perceived as too slow/bureaucratic relative to the business need.
5. **Evidence not retained even when the control may have actually operated** (this connects every finding above back to Module 8 — many "control failures" are, on closer root-cause investigation, actually "evidence failures": the control happened, but nothing proves it).

Recognizing these five systemic patterns is genuinely more valuable long-term than memorizing the eleven specific findings individually — almost any new, unfamiliar finding you encounter in real audit work will trace back to one (or more) of these same five underlying patterns, and recognizing which pattern you're looking at will immediately point you toward the kind of remediation likely to actually work.

---
**Quick Self-Check Questions**
1. For "Late Access Removal," name two distinct root causes and explain why they require different remediations.
2. Why is contractor/non-employee offboarding a particularly common gap in JML processes, structurally?
3. Explain the difference between "no rollback plan documented" due to oversight versus a genuinely irreversible change — how should each be handled differently?
4. Walk through why "No Incident RCA" often isn't really about skipping the analysis, but about CAPA follow-through failing afterward.
5. Pick any two of the five cross-cutting systemic patterns and explain, in your own words, how they each connect to at least three of the eleven specific findings listed.
