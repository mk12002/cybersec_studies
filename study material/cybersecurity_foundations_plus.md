# CYBERSECURITY FOUNDATIONS+ (META-FOUNDATION STUDY MATERIAL)
Version: May 2026
Goal: This document acts as the definitive capstone layer. It covers the "missing foundations" that make AppSec/CloudSec/IR work click in real companies. It synthesizes theoretical concepts into actionable, architectural realities.

This document stitches together:
- OS/Networking/Protocols/Python security fundamentals
- Web/App/API security principles
- Cloud architecture security (AWS/Azure/GCP)
- Cryptography (applied in modern systems)

---

## 📋 Table of Contents
1. [F+1: Secure Engineering & Secure SDLC](#f1-secure-engineering--secure-sdlc)
2. [F+2: Enterprise Identity & Auth (Windows/AD + Modern)](#f2-enterprise-identity--auth-windowsad--modern)
3. [F+3: Logging, Telemetry & Detection Engineering](#f3-logging-telemetry--detection-engineering)
4. [F+4: Databases, Data Access & Race Conditions](#f4-databases-data-access--race-conditions)
5. [F+5: Containers, Kubernetes & Runtime Security](#f5-containers-kubernetes--runtime-security)
6. [F+6: CI/CD Pipeline & Supply Chain Security](#f6-cicd-pipeline--supply-chain-security)
7. [F+7: Infrastructure as Code (IaC) & Cloud Architecture Security](#f7-infrastructure-as-code-iac--cloud-architecture-security)
8. [F+8: The Finish Line Checklist](#f8-the-finish-line-checklist)

---

## F+1: Secure Engineering & Secure SDLC
### Why Context is Everything
Security vulnerabilities rarely exist because a developer simply forgot to filter an input. They exist because of fundamental architectural disconnects. Secure Systems Development Lifecycle (SSDLC) is about inserting friction exactly where it provides value, without halting velocity.

### Threat Modeling: DFDs and STRIDE in Practice
Threat modeling is a design-time activity, not a post-deployment audit.
*   **Data Flow Diagrams (DFDs):** You must map exactly where data originates, processes, and rests. Trust boundaries (e.g., Internet -> API Gateway -> Internal Service) are where attacks happen.
*   **STRIDE Breakdown:**
    *   **Spoofing:** Can the caller fake their identity? (Mitigated by MFA, mutual TLS, strong session tokens).
    *   **Tampering:** Can the data be modified over the wire or at rest? (Mitigated by TLS, digital signatures, HMACs, file integrity hashes).
    *   **Repudiation:** Can a user deny performing an action? (Mitigated by non-modifiable audit logs, WORM storage, digital signatures).
    *   **Information Disclosure:** Can data leak out to unauthorized parties? (Mitigated by strict RBAC, data masking, encryption at rest/transit).
    *   **Denial of Service:** Can the system be brought down? (Mitigated by rate-limiting, WAFs, load balancers, auto-scaling).
    *   **Elevation of Privilege:** Can an unprivileged user do admin things? (Mitigated by proper AuthZ checks at the object level, principle of least privilege).

### Minimum Secure SDLC Pipeline
Integrating security into the pipeline requires automated guardrails.
1.  **Code Commit (IDE/Pre-commit):** 
    *   Secret scanning (e.g., detect AWS keys via regex BEFORE they hit the repo using Git hooks/Trufflehog).
    *   Linting for unsafe functions (e.g., blocking eval() in JavaScript, pickle in Python).
2.  **Pull Request (CI):** 
    *   SAST (Static Application Security Testing) like Semgrep or CodeQL checks for injection flaws and outdated crypto.
    *   SCA (Software Composition Analysis) like Dependabot alerts on CVEs in package.json or 
equirements.txt.
3.  **Build/Deploy (CD):** 
    *   Artifact signing (e.g., using Sigstore or Cosign) to ensure the deployed binary is the exact one built by CI.
    *   DAST (Dynamic Application Security Testing) runs against staging to find runtime flaws like reflected XSS or misconfigured headers.
4.  **Runtime:** 
    *   RASP (Runtime Application Self-Protection) and continuous SIEM ingestion.

**Practical Exercise:**
*Take a basic 3-tier web app (Frontend, Node.js API, PostgreSQL). Draw a DFD, map the trust boundaries, and apply the STRIDE methodology to the connection between the API and the Database.*

---

## F+2: Enterprise Identity & Auth (Windows/AD + Modern)
### The Perimeter is Dead; Identity is the Perimeter
Firewalls are secondary. If an attacker has valid credentials, they are logged in. Identity management bridges legacy systems (Active Directory) and modern cloud systems (Entra ID / Okta).

### Active Directory Deep Dive (Kerberos & NTLM)
*   **NTLM (Legacy):** Relies on challenge/response mechanisms. Vulnerable to 'Pass-the-Hash' where an attacker steals the NTLM hash from memory (via tools like Mimikatz) and authenticates without ever knowing the plaintext password. Also vulnerable to NTLM Relay attacks.
*   **Kerberos (Modern AD standard):** Uses tickets.
    1.  User authenticates to the Key Distribution Center (KDC) to get a Ticket Granting Ticket (TGT).
    2.  User presents the TGT to request a Ticket Granting Service (TGS) ticket for a specific service (like a file share).
    *   *Attacks:* Golden Ticket (forging a TGT by compromising the KRBTGT hash), Silver Ticket (forging a TGS), and Kerberoasting (requesting TGS tickets for service accounts and brute-forcing them offline).

### Modern Identity Architecture (OIDC, OAuth 2.0, SAML)
*   **OIDC / OAuth 2.0:** Modern architectures rely on JWTs (JSON Web Tokens). Security depends entirely on:
    *   **Token lifespans:** Short-lived access tokens (15-60 mins), tightly controlled refresh tokens.
    *   **Proper scope mapping:** Giving tokens over-broad scopes allows lateral privilege escalation.
    *   **Redirect URI validation:** Failing to validate redirect loops allows attackers to steal tokens.
*   **SAML (Security Assertion Markup Language):** XML-based SSO mechanism widely used in enterprise logic. Vulnerabilities usually stem from XML Signature Wrapping (XSW) attacks or improper validation of the assertions by the Service Provider.

### Privileged Access Management (PAM)
Admin accounts should be ephemeral. 
*   **Just-In-Time (JIT) access:** Elevating a normal user to admin for exactly 2 hours to fix a production issue, automatically revoking it afterward.
*   **Break-glass accounts:** Emergency accounts with maximal privilege, monitored heavily, with passwords kept in secure physical vaults.

---

## F+3: Logging, Telemetry & Detection Engineering
### "You cannot defend what you cannot observe."
Debug logs are useless for security. "Failed to query DB: timeout" helps developers; it does not help SOC analysts.

### High-Signal Security Logging (The "5 Ws")
Every critical action in your system must log:
1.  **Who:** The precise user ID, tenant ID, and IP address.
2.  **When:** UTC timestamp (ISO 8601 formatting strictly).
3.  **What:** The action performed (e.g., user.password.reset, document.read).
4.  **Where:** The resource targeted (e.g., doc_id_12345).
5.  **With outcome:** Success, Failure, or Denied (Authorization block).

### Detection Engineering Workflow
Instead of writing generic rules, detection engineering treats alerts like code.
*   **Hypothesis:** Attackers will attempt to bypass MFA using session hijacking.
*   **Log Source:** Entra ID Sign-in logs, CloudTrail.
*   **Logic (Sigma/Splunk):** Detect a successful login where the IP address ASN belongs to a known VPN/Tor provider, immediately followed by the registration of a new MFA device.
*   **Tuning:** Reduce false positives by whitelisting corporate VPN IPs.

**Detection Rule Pseudo-code (BOLA Detection):**
`yaml
title: Potential Insecure Direct Object Reference (IDOR/BOLA)
logsource:
  product: webapp
  service: api_gateway
detection:
  selection:
    event_type: "data_read"
    http_status_code: 200
  timeframe: 5m
  condition: selection | count(distinct target_object_owner_id) by actor_id > 10
falsepositives:
  - Admin/support roles executing broad searches
level: high
`

*Rule of Thumb:* If an alert fires and a human analyst says "oh, that's just the backup script doing its daily run," your detection is broken. False positives cause alert fatigue, leading to missed breaches.

---

## F+4: Databases, Data Access & Race Conditions
### Why "Safe" Languages Still Have DB Flaws
Memory-safe languages (Rust, Go) or frameworks (Django, Rails) do not prevent basic business logic or data isolation flaws.

### ORM Vulnerabilities
Object-Relational Mappers abstract SQL, but they can be misused.
*   *Safe:* users = User.objects.filter(name=input_name)
*   *Unsafe:* users = User.objects.raw(f"SELECT * FROM user WHERE name = '{input_name}'")
But beyond SQLi, ORMs often cause **Insecure Direct Object Reference (IDOR/BOLA)**. If your DB query is SELECT * FROM receipts WHERE receipt_id = 55, you failed. It MUST be SELECT * FROM receipts WHERE receipt_id = 55 AND owner_id = current_user_id.

### Race Conditions (TOCTOU: Time-Of-Check to Time-Of-Use)
These occur in high-concurrency systems (markets, payments, inventory, coupons) where execution threads interleave unexpectedly.
1.  Thread A checks if Wallet > . (Returns True).
2.  Thread B checks if Wallet > . (Returns True).
3.  Thread A deducts  and transfers it.
4.  Thread B deducts  and transfers it.
*Result:* Double spend.
*Mitigation:* 
*   **Pessimistic Locking:** Database-level row locking (SELECT ... FOR UPDATE).
*   **Atomic Decrements:** Instructing the DB to perform the operation directly (UPDATE wallet SET balance = balance - 50 WHERE balance >= 50).
*   **Distributed Locks:** Using Redis or Zookeeper.

---

## F+5: Containers, Kubernetes & Runtime Security
### Escaping the Matrix
Containers are just Linux processes restricted by 
amespaces (what they can see) and cgroups (what they can use). They are NOT virtual machines. If the kernel has an escalation vulnerability (e.g., Dirty COW), the attacker breaks out.

### Container Hardening Baseline (Dockerfile & Runtime)
1.  **Stop running as root:** Add USER 10001 at the end of the Dockerfile. Root inside the container has a high chance of becoming root on the host if a container escape vulnerability exists.
2.  **Read-only Root Filesystem:** Mount the container filesystem as read-only (--read-only), using 	mpfs mounts only for necessary directories like /tmp. This stops attackers from downloading malware payloads or altering executables.
3.  **Drop Capabilities:** Containers start with a default set of Linux capabilities. Drop all (--cap-drop=ALL) and strictly add back only what is necessary (e.g., CAP_NET_BIND_SERVICE to bind to port 80).
4.  **No New Privileges:** Set securityContext.allowPrivilegeEscalation=false to prevent processes from gaining more privileges than their parent.

### Kubernetes (K8s) Attack Surface
K8s is a massive distributed API. Securing it requires layers:
1.  **API Server Auth:** Who is calling the kubectl endpoint?
2.  **RBAC (Role-Based Access Control):** Ensure ServiceAccounts mounted into pods do not have cluster-wide read/write permissions. A compromised pod with cluster-admin means the whole cluster falls.
3.  **Network Policies:** By default, any pod can talk to any pod in a K8s cluster. Network Policies restrict this (e.g., Frontend pod can ONLY talk to Backend pod, Database pod only accepts traffic from Backend pod).
4.  **Admission Controllers:** Tools like Kyverno or OPA Gatekeeper that block insecure pods from even spinning up (e.g., "Reject pod if it asks to run as root or asks for hostPath mounts").

---

## F+6: CI/CD Pipeline & Supply Chain Security
### The Pipeline IS Production
If an attacker compromises your Jenkins or GitHub Actions pipeline, they compel your own infrastructure to securely sign and deploy their malware to production. SolarWinds and Codecov are prominent examples of this vector.

### Attack Vectors in CI/CD
*   **Poisoned Dependencies:** Attackers buy expired NPM domains or typosquat popular packages (
ecact instead of 
eact). When CI builds the app, it pulls the malicious package. Mitigated by dependency lockfiles (package-lock.json), internal artifact repositories (Artifactory), and SCA tools.
*   **Exposed CI Secrets:** Hardcoding pipeline secrets. If a developer logs a pipeline variable wrongly, it leaks AWS keys to the build logs. Use short-lived, fetched credentials (OIDC) rather than permanent keys.
*   **Unsafe Runner Environments:** Executing untrusted code (like PRs from external forks) on self-hosted runners that possess persistent IAM roles. Code runs inside the trusted boundary before it is approved.

### SLSA Framework (Supply-chain Levels for Software Artifacts)
A Google-backed framework for ensuring software integrity from source to deployment:
- **Level 1:** Unambiguous provenance (What was built? How?).
- **Level 2:** Hosted build service and signed provenance.
- **Level 3:** Ephemeral, isolated build environments preventing cross-build contamination.
- **Level 4:** Hermetic builds and two-person review for all source code modifications.

---

## F+7: Infrastructure as Code (IaC) & Cloud Architecture Security
### Automating Infrastructure Security
ClickOps (configuring AWS via the web console) is an anti-pattern. Infrastructure must be defined in code (Terraform, CloudFormation, Pulumi) for auditability, versioning, and rapid rebuilding.

### IaC Security Scanning
Scan Terraform files the same way you scan application code. Tools like 	fsec or checkov can instantly identify if an S3 bucket is public, an RDS database is unencrypted, or an IAM role uses * permissions *before* deployment.

### Immutable Infrastructure & Drift Detection
*   **Drift:** When the real-world deployed state differs from the Terraform code state (e.g., an engineer manually changing an RDS setting). Drift must log an immediate security alert.
*   **Immutability:** Servers should never be patched in place. If an OS update is required, build a new AMI, deploy new instances, and terminate the old ones. This naturally clears out entrenched attackers.

---

## F+8: The Finish Line Checklist
You are prepared for real-world Security/CloudSec engineering meta-foundations when you can confidently:
- [ ] Diagram a cloud microservice architecture and label 4 distinct trust boundaries.
- [ ] Explain the difference between OAuth 2.0 (Authorization) and OIDC (Authentication) to a developer.
- [ ] Detail a 3-step mitigation for a TOCTOU race condition in a node.js/Postgres API.
- [ ] Review a Dockerfile and identify at least 5 security anti-patterns.
- [ ] Explain why a leaked Kerberos krbtgt hash requires completely rebuilding an Active Directory domain.
- [ ] Write a structured JSON logging format suitable for SIEM ingestion.
- [ ] Map out an incident response playbook for a suspected compromised developer laptop containing valid AWS credentials.
- [ ] Implement an OIDC-based CI/CD pipeline to deploy code to AWS without storing access keys.

---
*Last Updated: May 2026 | Status: Complete / Meta-Foundation Capstone*
