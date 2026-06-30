# Module 14 — Active Directory (Practical Audit-Focused Deep Dive)

This module builds on Module 5's conceptual AD overview with the specific, hands-on knowledge needed to actually pull and interpret AD evidence during testing.

## 1. Users

The AD object representing an individual identity, with attributes including: `sAMAccountName` (logon name), `userPrincipalName` (UPN, often the email-format login), `distinguishedName`, `description`, `department`, `manager`, `accountExpires`, `userAccountControl` (a bitmask encoding account status flags including whether the account is disabled), and `lastLogonTimestamp`.

### Key Audit-Relevant User Attributes

| Attribute | Audit Relevance |
|---|---|
| `userAccountControl` | Determines if the account is enabled/disabled — directly relevant to Leaver testing (Module 4) |
| `lastLogonTimestamp` | Identifies dormant accounts (Module 5) — note this attribute replicates across domain controllers with some delay/imprecision by design, so for precise testing, auditors sometimes need to check the most recent value across all DCs, not just one |
| `whenCreated` | Account creation date — used to corroborate Joiner timing |
| `pwdLastSet` | When the password was last changed — relevant to password policy compliance testing |
| `manager` | Used to corroborate the approval chain (does the recorded manager match who actually approved the access request?) |
| `memberOf` | Group memberships — the actual access grants, covered below |

## 2. Groups

AD uses groups to bundle permissions and simplify access assignment (the technical implementation of RBAC, Module 5) — rather than assigning permissions to each user individually, permissions are assigned to a group, and users are added/removed from that group.

### Group Types
- **Security Groups** — used to assign permissions/access rights (the primary type relevant to access control testing).
- **Distribution Groups** — used purely for email distribution lists, with no inherent access/permission implications (auditors generally exclude these from access testing scope unless a specific reason exists to include them).

### Group Scope
- **Domain Local** — can be granted permissions only within the domain where it's defined (often used to assign actual resource permissions).
- **Global** — can contain users from the same domain, and can be used across domains in a forest (often used to organize users by role/department).
- **Universal** — can contain members from any domain in the forest, and is usable forest-wide (often used in larger, multi-domain enterprises).

Knowing the difference matters for understanding **nested groups** (below) and for correctly scoping an access review (a Universal group might grant access across far more of the environment than a Domain Local group with a similar-sounding name).

## 3. OU (Organizational Unit)

A container within AD used to organize objects (users, computers, groups) hierarchically, primarily for **administrative delegation and Group Policy application** — distinct from Groups, which are about permissions/access, not organizational structure or administrative delegation.

### Why OU Structure Matters for Audit
- **Delegation of administrative control** is often configured at the OU level (e.g., "the Finance IT team can manage user accounts within the Finance OU but nothing else") — this is itself a segregation of duties control worth testing (does delegated OU permission match what's documented? Can someone outside Finance IT modify Finance OU objects?).
- **Group Policy Objects (GPOs)** — covered below — are linked to OUs, meaning OU structure directly determines which security policies (password policy, login restrictions, etc.) apply to which users/computers.

## 4. Nested Groups

A group that is itself a **member of another group** — common in larger enterprises to build layered permission structures (e.g., a "Finance-All-Access" group might contain the nested groups "Finance-AP," "Finance-AR," and "Finance-GL," each with their own further nested membership).

### Why Nested Groups Are an Audit Risk Area
Nested groups can obscure the **true effective access** a user holds — a straightforward query of "what groups is User X directly a member of" can dramatically understate their actual access if that direct group is itself nested inside several other groups with broader permissions. Auditors testing access must account for **effective/transitive group membership**, not just direct membership, or risk significantly understating a user's actual access during testing. Tools like `Get-ADGroupMember -Recursive` (PowerShell) or dedicated IAM governance platforms (Module 5) are used specifically to resolve this transitive membership accurately.

## 5. Access Reports (AD-Specific)

Common AD-derived reports pulled for audit evidence:
- **User listing with account status** — all users, enabled/disabled flag, last logon, department.
- **Group membership listing** — for a specific group, who is currently a member (direct and, ideally, effective/nested).
- **Privileged group membership** — specifically for high-risk built-in groups: **Domain Admins, Enterprise Admins, Schema Admins, Account Operators, Backup Operators** — these groups warrant heightened scrutiny and more frequent review given the extensive access they confer.
- **Stale/dormant account report** — users with `lastLogonTimestamp` beyond the dormancy threshold (Module 5) who remain enabled.

## 6. Account Disable

The actual technical mechanism behind Leaver testing (Module 4) — disabling an account sets a specific bit in the `userAccountControl` attribute, immediately preventing successful authentication, while preserving the account object itself (as opposed to deletion, which removes the object entirely).

**Disable vs. Delete — why disable first:** Best practice is to **disable** an account immediately upon termination, then **delete** it only after a defined retention period (allowing for any final access needs like e-discovery/legal hold, or in case the termination needs to be reversed administratively) — this is itself often a documented MICS-style control (Module 3), with the retention window specified by policy.

## 7. Password Policy

Configured via **Group Policy** (often the Default Domain Policy, though Fine-Grained Password Policies can apply different rules to different groups). Key settings auditors check against organizational policy:

- **Minimum password length** (commonly 12-14+ characters in modern guidance, a meaningful increase from older 8-character standards as computing power for brute-force/cracking has increased).
- **Complexity requirements** (mix of character types — though note that modern security guidance, including NIST SP 800-63B, has shifted away from mandatory complexity/frequent rotation toward length and breach-database screening as more effective controls; auditors should test against the **organization's actual documented policy**, not assume one universal "correct" standard, since legitimate policy approaches vary).
- **Account lockout threshold** (number of failed attempts before lockout — balances brute-force protection against denial-of-service risk from an attacker deliberately locking out legitimate users).
- **Password history** (preventing immediate reuse of recent passwords).
- **Maximum password age** (forced rotation interval — again, subject to the modern guidance shift noted above).

## 8. Group Policy (GPO - Group Policy Objects)

The mechanism for centrally enforcing configuration settings (security settings, software restrictions, login scripts, and much more) across users/computers within an OU, domain, or site.

### Audit Relevance of GPOs
- GPOs are where many **technical security control configurations** actually live (password policy as above, but also screen lock timeout, USB device restrictions, audit logging configuration, and far more) — when an audit finding says "the organization's policy requires X," the corresponding GPO setting is the technical evidence proving that policy is actually enforced (versus existing only as an unenforced written document).
- **GPO changes are themselves subject to Change Management** (Module 6) — a GPO modification affecting security settings across the domain is a high-impact change and should go through appropriate CAB review, not be made ad-hoc by any admin with edit rights.

## 9. Audit Logs (AD-Specific)

Windows/AD generates Security Event Logs that, when properly configured (Advanced Audit Policy Configuration, often forwarded to a centralized SIEM per Module 8), capture events highly relevant to audit testing:

- **Event ID 4720** — A user account was created.
- **Event ID 4722** — A user account was enabled.
- **Event ID 4725** — A user account was disabled.
- **Event ID 4726** — A user account was deleted.
- **Event ID 4728/4732/4756** — A member was added to a security-enabled global/domain-local/universal group, respectively.
- **Event ID 4624/4625** — Successful/failed logon.
- **Event ID 4738** — A user account was changed (useful for detecting attribute modifications, including potentially suspicious privilege changes).

**Why specific Event IDs matter for your career direction:** This is precisely the layer where ITGC audit evidence and SOC/SIEM detection engineering converge — the same Event IDs that prove a Leaver control operated correctly for audit purposes are also the foundational telemetry a SOC analyst or detection engineer would alert on for anomalous account behavior (e.g., an Event ID 4728 adding a user to Domain Admins outside of a documented, approved change — exactly the kind of signal an agentic security platform's risk-fusion logic should weight heavily).

---
**Quick Self-Check Questions**
1. Why must auditors test "effective" group membership rather than just direct membership when nested groups are in use?
2. Distinguish Domain Local, Global, and Universal group scopes, and explain why this distinction matters for scoping an access review.
3. Why does best practice call for disabling an account immediately but deleting it only after a retention period?
4. Name three specific Windows Security Event IDs relevant to JML testing and what each one evidences.
5. Why should auditors test AD password/account lockout policy against the organization's own documented policy, rather than a single universal standard?
6. Explain why a GPO change affecting domain-wide security settings should itself be subject to formal change management review.
