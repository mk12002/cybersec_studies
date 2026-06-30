# Module 6 — Change Management

Change management is the second pillar of ITGC (Control Objective 2 from Module 2: "Changes to programs/systems are authorized, tested, and approved before migration to production"). It exists to ensure that changes to systems supporting financial reporting (or, in security terms, any production system) don't introduce errors, fraud opportunities, or vulnerabilities without proper oversight.

## 1. Types of Change

### Normal Change
A change that follows the **full standard process**: request → risk assessment → review/approval (typically via a Change Advisory Board) → testing → scheduled deployment → post-implementation review. This is the default path for most changes — new features, configuration updates, infrastructure modifications.

### Standard Change
A **pre-approved**, low-risk, well-understood, and repeatable change (e.g., routine patching of a non-critical system following a documented, tested procedure). Because the risk and procedure are already well-established and reviewed in advance (often once, at a template level), individual instances don't need to go through full CAB review each time — they're executed under a blanket pre-approval, but still logged and tracked.

### Emergency Change
A change required **urgently** to resolve an active incident or prevent imminent harm (e.g., a critical security patch for an actively-exploited vulnerability, or a fix for a production outage). Emergency changes bypass the normal full advance-approval cycle out of necessity, but require:
- Expedited approval (often a smaller, empowered emergency-approval group, sometimes a single authorized senior approver, rather than full CAB).
- **Mandatory retroactive review** — the change must be reviewed after the fact (commonly within 24-72 hours) to confirm it was appropriate, properly tested even under time pressure, and to capture lessons learned.
- Clear documentation of why normal process couldn't be followed.

**Audit angle:** Emergency changes are a frequent area of audit findings precisely because the urgency creates pressure to skip controls. Auditors specifically test: was the change actually an emergency (not just convenient to label as one to skip review)? Was the required retroactive review actually performed and evidenced?

## 2. CAB (Change Advisory Board)

A formal governance body — typically composed of representatives from IT operations, security, business stakeholders, and relevant subject-matter experts — that reviews and approves significant (Normal) changes before they're scheduled for deployment.

### CAB Responsibilities
- Assess the risk and business impact of proposed changes.
- Confirm adequate testing has been performed.
- Confirm a rollback plan exists.
- Check for scheduling conflicts (e.g., avoid deploying multiple high-risk changes simultaneously, avoid deploying during peak business periods like financial close).
- Formally approve, reject, or request modification before the change can proceed.

### CAB Evidence
Meeting minutes, attendee lists, the specific changes discussed, and the explicit approval/rejection decision per change — this minutes documentation is a primary audit evidence artifact (explicitly called out in Module 8's evidence list).

## 3. Risk Assessment (within Change Management)

Before approval, every change should be assessed for:
- **Impact** — what breaks if this goes wrong? (scope of affected systems/users/data)
- **Likelihood of failure** — how well-tested/understood is this change?
- **Reversibility** — how easily can this be rolled back if something goes wrong?
- **Timing risk** — does this coincide with a sensitive business period (financial close, peak transaction volume, holiday freeze periods)?

Many organizations formally classify changes by risk tier (Low/Medium/High/Critical), with the approval rigor scaling accordingly — a Low-risk standard change needs far less scrutiny than a High-risk change to core financial systems.

## 4. Rollback Plan

A documented, tested procedure to **revert a change** and restore the prior working state if the deployment fails or causes unexpected issues.

### Why Rollback Plans Are Mandatory (Not Optional)
Without a tested rollback plan, a failed change can turn a planned, controlled maintenance window into an extended, uncontrolled outage — and from a financial reporting control perspective, an uncontrolled, undocumented "fix it live" response to a failed change is itself a control failure (it bypasses change management entirely at the exact moment risk is highest).

**Audit testing angle:** For a sample of changes, auditors will check whether a rollback plan was documented *before* deployment (not improvised after something broke), and ideally whether it was actually tested/validated rather than just theoretically written.

## 5. Testing (within Change Management)

Changes should be tested in a **non-production environment** that adequately represents production before deployment. Common testing stages:

- **Unit testing** — individual component/code-level testing (developer-performed).
- **Integration testing** — confirming the change works correctly with other connected systems/components.
- **User Acceptance Testing (UAT)** — business users confirm the change meets requirements and doesn't break expected functionality, performed in a UAT environment separate from both development and production.
- **Regression testing** — confirming the change hasn't broken previously-working functionality elsewhere in the system.

### SoD in Testing
A critical control: **the person who tests/approves a change should be independent of the person who developed it.** A developer testing and approving their own code violates segregation of duties and is a very common audit finding, especially in smaller teams.

## 6. Production Deployment

The actual release of the tested, approved change into the live environment.

### Key Controls at Deployment
- **Deployment should only be performed by authorized personnel**, ideally different from both the developer and the approver (three-way SoD: develop / approve / deploy).
- **Access to deploy to production should be restricted** — this is itself an access control (Module 4/5) intersecting with change management; most audit frameworks specifically test "who has the technical ability to push to production" as a standalone access review.
- Deployment should occur during an approved change window, following the approved plan exactly as reviewed (any deviation from what was approved should itself trigger a new review, not silent "while I'm in there" scope creep).

## 7. Approvals

Multiple approval checkpoints typically exist across the change lifecycle:
1. **Business/requirements approval** — confirming the change is needed and correctly scoped.
2. **Technical/architecture review approval** — confirming the technical approach is sound.
3. **CAB/change approval** — the formal go/no-go decision.
4. **Post-deployment sign-off** — confirming the change was deployed successfully and performs as expected.

Each approval should be **evidenced with a timestamp and the approver's identity**, and should occur in the correct sequence (e.g., an approval timestamped *after* deployment already happened is a significant finding — it indicates the change was deployed without prior authorization, with approval sought retroactively, which defeats the entire purpose of the control).

## 8. Evidence (Change Management Specific)

Typical evidence package for a single change, tied directly to the lifecycle above:
- Change request ticket (ServiceNow/Jira) with description, risk classification, and requestor.
- Risk assessment documentation.
- Test plan and test results (UAT sign-off).
- Rollback plan.
- CAB approval (minutes or system-recorded approval with timestamp).
- Deployment record/log (who deployed, when, what was deployed — ideally with a change ticket number tied to the actual deployment pipeline log for traceability).
- Post-implementation review (for emergency changes especially, but good practice for all significant changes).

## 9. Examples

### Example: Normal Change
> A bank wants to update its loan interest calculation logic to reflect a new regulatory requirement. This goes through full CAB review given its direct financial reporting impact: business requirements documented and approved, code developed, peer-reviewed, tested in UAT by business users (separate from the developer), rollback plan documented (revert to prior calculation version), CAB approves the deployment window, change deployed by a release engineer (not the developer), and a post-deployment validation confirms calculations are correct on a sample of test accounts before being considered complete.

### Example: Standard Change
> Monthly OS security patching of non-critical application servers, following a documented and previously-CAB-approved patching procedure. Each instance is logged but doesn't require individual CAB review since the procedure itself was reviewed and pre-approved.

### Example: Emergency Change
> A critical zero-day vulnerability is actively being exploited in a public-facing web application. The security team needs to deploy a WAF rule and a code-level fix within hours. An emergency change is raised, approved by an authorized emergency approver (e.g., the CISO or designated on-call change manager) rather than waiting for the next scheduled CAB meeting, deployed immediately, and then reviewed retroactively at the next CAB meeting (or a dedicated emergency-change review) to confirm appropriateness and capture any process improvements.

## 10. Audit Findings (Common Change Management Findings)

| Finding | Why It Happens | Risk |
|---|---|---|
| No documented approval for a change found in production | Process bypassed, or evidence not retained | Unauthorized/unreviewed changes could introduce errors or fraud |
| Developer also approved/deployed their own change | SoD not enforced, often in small teams | No independent check on code correctness or malicious intent |
| Emergency change retroactive review not performed | Treated as "exception" and forgotten after the fire is out | Emergency process becomes a backdoor to bypass controls routinely |
| Approval timestamp postdates deployment | Process followed "for show" after the fact | Change effectively happened without real prior authorization |
| No rollback plan documented | Time pressure, or rollback considered "obvious"/unnecessary | Failed changes become uncontrolled incidents |
| Standard change template used for what was actually a high-risk change | Misclassification (deliberate or accidental) to skip CAB scrutiny | High-risk changes proceed without adequate review |

---

## Security Engineering Cross-Reference (DevSecOps Lens)

Change management is the audit/GRC name for what security engineers call the **Software Development Lifecycle (SDLC) and CI/CD governance**:

- **CAB approval** ≈ a required **pull request review/approval gate** before merge, or a manual deployment approval gate in a CI/CD pipeline (e.g., GitHub Actions environment protection rules, Azure DevOps release approvals).
- **SoD between developer and deployer** ≈ branch protection rules requiring a different reviewer than the author, and deployment credentials/permissions scoped separately from developer commit access.
- **Rollback plan** ≈ blue-green deployments, canary releases, and automated rollback triggers in modern DevOps pipelines — the same control objective (revert safely if something breaks) implemented with more automation.
- **Emergency change** ≈ a hotfix process, frequently with the same tension between speed and governance that exists in financial-systems emergency changes — and the same control requirement: retroactive review, even when bypassing normal gates was justified.
- **Testing requirement** ≈ automated test suites (unit/integration) gating merge/deploy in CI/CD, functionally identical in purpose to UAT/regression testing requirements here, just automated rather than manual.

This is directly relevant to your SecureLoop AI and AOCE pipeline work — any agentic system that can autonomously trigger deployments or configuration changes needs equivalent change-management guardrails (approval gates, audit logging, rollback capability) baked into its architecture, or it becomes an unaudited, ungoverned change path that would fail exactly the kind of control testing described in this module.

---
**Quick Self-Check Questions**
1. What's the structural difference between a Standard change and a Normal change, given both can be relatively low-risk?
2. Why must an emergency change still go through retroactive review, even though it bypassed normal advance approval?
3. Identify the three-way SoD that should ideally exist across develop/approve/deploy, and explain why combining any two of these roles in one person is risky.
4. What does it mean if an approval timestamp postdates the deployment timestamp, and why is this considered a significant (not minor) finding?
5. Map "CAB approval" and "rollback plan" to their DevSecOps/CI-CD equivalents.
