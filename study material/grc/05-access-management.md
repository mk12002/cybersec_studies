# Module 5 — Access Management

This module goes deeper into the technical identity and access concepts that Module 4 referenced at a process level. Where Module 4 covers the *governance process* (JML, SoD, least privilege as audit concepts), this module covers the *technical systems and protocols* that implement them.

## 1. Identity Management

Identity Management is the broader discipline of creating, maintaining, and governing digital identities (the "who") across an organization's systems — the foundation that authentication and authorization (Module 4) operate on top of.

A digital identity typically includes: a unique identifier, attributes (department, title, manager, employment status), and the entitlements/access tied to that identity over its lifecycle.

## 2. IAM (Identity and Access Management)

IAM is the umbrella technical and organizational function combining identity management, authentication, authorization, and access governance into a coherent system.

### Core IAM Functions
- **Identity lifecycle management** (provisioning/deprovisioning — the technical execution of JML)
- **Authentication services** (login, MFA, SSO)
- **Authorization/entitlement management** (what access maps to what identity)
- **Access governance** (reviews, certifications, SoD analysis, reporting)
- **Privileged access management** (Module 4, Part A.6)

## 3. Active Directory (AD)

Microsoft Active Directory is the most widely deployed enterprise directory service, used to centrally manage users, computers, and security policy across a Windows-based network.

### Key AD Concepts
- **Domain** — a logical grouping of objects (users, computers, groups) sharing a common directory database and security policy.
- **Domain Controller (DC)** — the server hosting the AD database and authenticating logon requests.
- **Objects** — users, computers, groups, and other manageable entities within AD.
- **Schema** — the definition of what types of objects and attributes can exist in the directory.

AD is the system auditors most frequently pull evidence from for access testing (user lists, group memberships, last logon timestamps, account status) because it's typically the central authentication point for a Windows enterprise environment, even when downstream applications have their own authorization layers.

## 4. LDAP (Lightweight Directory Access Protocol)

LDAP is the open, vendor-neutral protocol used to query and modify directory services — Active Directory itself is queried via LDAP under the hood, and many non-Microsoft systems (Linux authentication, network devices, various enterprise applications) integrate with AD or other directories via LDAP.

- **LDAP bind** — the authentication step where a client connects and authenticates to the directory.
- **Distinguished Name (DN)** — the unique path identifying an object in the directory tree (e.g., `CN=John Doe,OU=Finance,DC=company,DC=com`).
- **LDAPS** — LDAP over TLS/SSL, the encrypted version; auditors/security reviewers should flag plain unencrypted LDAP as a finding since credentials can be intercepted in transit.

## 5. Azure AD (now Microsoft Entra ID)

Microsoft's cloud-based identity platform — note that Microsoft rebranded "Azure Active Directory" to **Microsoft Entra ID** in 2023, though "Azure AD" remains in extremely common use in documentation, job postings, and casual conversation, so know both names.

### Key Differences from On-Prem AD
- Cloud-native, designed for SaaS/cloud app authentication (vs. AD's traditional on-prem Windows domain focus).
- Native support for modern protocols: SAML, OAuth 2.0, OpenID Connect (vs. AD's traditional Kerberos/NTLM).
- **Conditional Access Policies** — Entra ID's signature capability: dynamic, context-aware access rules (e.g., "require MFA if logging in from outside the corporate network" or "block access entirely from specific high-risk countries").
- **Hybrid identity** — many enterprises run **Azure AD Connect** (now Entra Connect) to synchronize on-prem AD identities to Entra ID, maintaining a single identity across both environments during cloud migration.

This is directly relevant to your background, given your Azure AI Engineer and Azure-native pipeline work — Entra ID Governance (entitlement management, access reviews, PIM) is the modern equivalent of the legacy SailPoint/Saviynt identity governance tools, increasingly common in Azure-centric enterprises.

## 6. SSO (Single Sign-On)

SSO allows a user to authenticate once and gain access to multiple independent systems/applications without re-entering credentials for each one.

### Why SSO Matters for Both Security and Audit
- **Security benefit:** Reduces password fatigue (fewer passwords = less reuse/weak passwords), centralizes authentication enforcement (MFA enforced once at the identity provider, not per-app), and provides a single point for revoking access across many systems at once (directly strengthens the Leaver process in Module 4 — disable the SSO identity, and access to every federated app is cut simultaneously).
- **Audit benefit:** A single, centralized authentication log becomes the primary evidence source for access testing, rather than chasing logs across dozens of disparate applications.
- **Risk to flag:** SSO also means a single compromised identity becomes a single point of failure across many systems — which is exactly why MFA enforcement at the SSO/Identity Provider layer is treated as a Tier 1 mandatory control (Module 3) in virtually every mature MICS framework.

## 7. SAML (Security Assertion Markup Language)

An XML-based open standard for exchanging authentication and authorization data between an **Identity Provider (IdP)** and a **Service Provider (SP)** — the classic enterprise SSO protocol, especially common for browser-based web app federation.

### SAML Flow (Simplified)
1. User attempts to access a Service Provider (e.g., Salesforce).
2. SP redirects the user to the configured Identity Provider (e.g., Okta, Entra ID).
3. User authenticates at the IdP (potentially with MFA).
4. IdP issues a signed SAML **assertion** (a digitally signed XML document confirming identity and attributes).
5. SP validates the assertion's signature and grants access.

SAML is widely used for enterprise B2B and internal app federation; it predates and is somewhat more "enterprise/legacy-flavored" than OAuth/OIDC, though all three remain in active concurrent use across most enterprises.

## 8. OAuth 2.0

OAuth is an **authorization** framework (not primarily an authentication protocol, despite common confusion) that allows a third-party application to access resources on a user's behalf, without the user sharing their actual credentials with that third party.

### Key OAuth Concepts
- **Resource Owner** — the user who owns the data.
- **Client** — the application requesting access.
- **Authorization Server** — issues access tokens after the resource owner approves.
- **Resource Server** — hosts the protected resource and validates the access token.
- **Access Token** — a credential representing the granted authorization, typically short-lived.
- **Refresh Token** — used to obtain new access tokens without requiring the user to re-authenticate.
- **Scopes** — granular permissions the client is requesting (e.g., "read your calendar" vs. "send email as you").

### Why "OAuth alone isn't authentication"
OAuth confirms "this app is authorized to access X resource," but does not itself reliably tell the relying party "this is definitely User Y" — that's what OpenID Connect adds on top.

## 9. OpenID Connect (OIDC)

OIDC is an **authentication** layer built on top of OAuth 2.0. It adds a standardized **ID Token** (a signed JWT containing identity claims like user ID, email, and issuance/expiry times) so applications can reliably establish *who* the user is, not just *what they're authorized to access*.

**OAuth vs. OIDC, in one line:** OAuth answers "can this app act on my behalf for X?"; OIDC answers "who is this user, verified by a trusted identity provider?" Modern SSO implementations (Google Sign-In, "Sign in with Microsoft") are typically OIDC built on OAuth 2.0 under the hood.

## 10. MFA (Multi-Factor Authentication)

Covered at a concept level in Module 4; technically, modern MFA implementations include:
- **Push notifications** (Microsoft Authenticator, Okta Verify, Duo) — most common in enterprise today, balancing security and usability.
- **TOTP (Time-based One-Time Password)** — app-generated 6-digit codes (Google Authenticator-style), still phishable via real-time relay attacks but stronger than SMS.
- **SMS OTP** — weakest common MFA factor (vulnerable to SIM-swapping); auditors increasingly flag SMS-only MFA as a finding for privileged/financial access.
- **FIDO2/WebAuthn (hardware security keys, passkeys)** — phishing-resistant, the current gold-standard, increasingly mandated for high-privilege accounts.

**Audit/security note — "MFA fatigue" attacks:** A well-known modern attack pattern where an attacker with stolen credentials repeatedly triggers push notifications until the user accidentally approves one. This has led to control evolution toward **number matching** (user must enter a displayed number, not just tap "approve") as the current best-practice MFA configuration — worth knowing for both audit testing criteria and for your security architecture work.

## 11. RBAC (Role-Based Access Control)

Access is granted based on a user's assigned **role**, which bundles a predefined set of permissions appropriate to that job function — rather than granting permissions individually per user.

### Why RBAC Is the Dominant Model in Enterprises
- Easier to audit (verify the role's permission set once, then verify users are assigned the correct role, rather than auditing every individual permission per user).
- Scales cleanly with the JML process (Module 4) — onboarding/role changes become "assign/reassign role" rather than rebuilding permissions from scratch.
- Directly supports least privilege and SoD when role definitions are well-designed and don't contain conflicting permission bundles.

### RBAC Risks
- **Role explosion** — over time, organizations accumulate hundreds/thousands of overly-specific roles, defeating the simplicity RBAC was meant to provide.
- **Role contains SoD conflict by design** — if a role bundles "create vendor" + "approve payment" permissions together, every single user assigned that role inherits the SoD violation.

## 12. ABAC (Attribute-Based Access Control)

A more granular, dynamic model where access decisions are made based on **attributes** of the user, resource, action, and environment/context — evaluated against policy rules at access time, rather than a static pre-assigned role.

### Example ABAC Policy
> "Allow READ access to documents classified 'Confidential-Finance' IF user.department == 'Finance' AND user.clearance_level >= 'L3' AND request.time is within business hours AND request.device is a managed corporate device."

### RBAC vs. ABAC — Comparison

| Aspect | RBAC | ABAC |
|---|---|---|
| Decision basis | Static role assignment | Dynamic attribute evaluation at request time |
| Simplicity | Easier to understand/audit | More complex, requires policy engine |
| Granularity | Coarser (role-level) | Fine-grained (per-attribute combination) |
| Best for | Stable organizational structures | Dynamic, context-sensitive, zero-trust environments |
| Common implementation | AD groups, application roles | Azure ABAC conditions, AWS IAM policy conditions, OPA (Open Policy Agent) |

Many modern enterprises use a **hybrid model** — RBAC as the primary structure, with ABAC-style conditional policies layered on top for sensitive resources (this is effectively what Entra ID Conditional Access does — RBAC determines baseline permissions, Conditional Access adds attribute-based runtime conditions like device compliance and location).

## 13. PAM (Privileged Access Management) — Technical Deep Dive

Building on Module 4's process-level coverage, the technical PAM toolchain typically includes:

- **Password/Credential Vault** — encrypted central storage; privileged credentials are checked out on demand and often auto-rotated after each use.
- **Session Broker/Proxy** — routes privileged sessions through a controlled gateway that can record, monitor, and even terminate sessions in real time.
- **PIM (Privileged Identity Management)** — Microsoft's specific Entra ID capability for **Just-in-Time role activation**: a user holds *eligible* (not active) assignment to a privileged role, and must explicitly request activation (often with justification, approval, and time-bound expiry) to actually use it.

## 14. JML Process (Cross-Reference)

Fully covered in Module 4, Part B. The technical systems in this module (AD, Entra ID, IAM platforms) are the tools that *execute* the JML process described there. Worth re-reading Module 4 Part B alongside this module to connect process and technology.

## 15. Access Reviews / Access Certification

A periodic (commonly quarterly or semi-annual) process where managers/system owners formally review and re-attest that each user's current access is still appropriate.

### How Access Reviews Work
1. The IAM/governance platform generates a list of all users and their current entitlements for a given system/application.
2. The list is routed to the appropriate reviewer (typically the user's manager, or the application/data owner).
3. The reviewer must explicitly certify each entitlement: **Approve (keep)**, **Revoke (remove)**, or sometimes **Modify**.
4. Revocations are tracked through to actual technical removal, and that removal itself becomes evidence.
5. The entire campaign (who reviewed what, when, and the outcome) is retained as audit evidence.

### Why This Is One of the Most Heavily Tested ITGC Controls
Access reviews are the **detective control** that catches everything the preventive JML controls missed — especially "Mover" privilege creep (Module 4, B.2) and any access that fell through the cracks of automated provisioning. Auditors test: (a) did the review actually occur on schedule, (b) did the reviewer appear to meaningfully review (not just "approve all" with no apparent scrutiny — auditors sometimes flag suspiciously fast 100%-approval reviews as a red flag warranting further inquiry), and (c) were revocations actually executed technically, not just marked "revoke" in the tool with no follow-through.

## 16. Dormant Accounts

Accounts that have not been used (no successful login) for an extended period (commonly 60-90 days, policy-dependent) but remain enabled.

- **Risk:** A dormant account is an unmonitored, unnecessary attack surface — if compromised, unusual activity is less likely to stand out against a baseline of "normal use" since there is none.
- **Control:** Automated detection and either disablement or mandatory re-justification after the dormancy threshold.

## 17. Orphan Accounts

Accounts that exist in a system but have **no identifiable, currently-employed human owner** — typically because the employee left and the Leaver process (Module 4, B.3) didn't reach every system, or because the account was never properly linked to an HR identity record in the first place (common with accounts created directly in an application rather than through central IAM provisioning).

- **Risk:** Functionally invisible to standard access reviews (since there's no manager to certify it) and to the Leaver process (since there's no HR record triggering disablement) — orphan accounts can persist indefinitely.
- **Audit testing:** Compare the full population of accounts across all in-scope systems against the active HR employee roster; any account not matching an active employee (or a documented, owned service account) is an orphan and a finding.

## 18. Ghost Accounts

A closely related term, sometimes used interchangeably with "orphan," but more specifically referring to accounts that exist for people who **never should have had standing access in the first place**, or accounts created for testing/temporary purposes that were never cleaned up. The distinguishing audit question for ghost accounts is usually "why does this account exist at all," versus orphan accounts where the question is "this clearly should have been removed — why wasn't it."

## 19. Shared IDs / Privileged IDs (Cross-Reference)

Covered in Module 4, Part A.6. Worth noting here specifically in the context of access reviews: shared and privileged IDs require **more frequent** review cycles than standard user access (often monthly rather than quarterly) given their elevated risk profile, and the reviewer should specifically be someone independent of the account's regular users to maintain meaningful oversight.

---
**Quick Self-Check Questions**
1. Explain the practical difference between OAuth 2.0 and OpenID Connect using the "can this app act on my behalf" vs. "who is this user" framing.
2. Why is SMS-based OTP increasingly flagged as a finding for privileged access, and what's the recommended alternative?
3. Compare RBAC and ABAC — when would a security architect choose ABAC over RBAC for a sensitive resource?
4. What specific privilege creep risk does an access review (certification) catch that the Joiner/Mover/Leaver process by itself might miss?
5. What is the key distinguishing test an auditor uses to identify an orphan account?
6. How does Microsoft Entra PIM implement the "Just-in-Time" privileged access concept technically?
7. Why is "100% approved, no revocations" in an access certification campaign itself sometimes treated as a red flag rather than a clean result?
