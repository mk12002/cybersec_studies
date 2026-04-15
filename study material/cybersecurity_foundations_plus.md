# CYBERSECURITY FOUNDATIONS+ (META-FOUNDATION STUDY MATERIAL)
Version: April 2026
Goal: cover the “missing foundations” that make AppSec/CloudSec/IR work click in real companies.

This document is NOT meant to repeat your existing texts. It stitches together:
- [cybersecurity_fundamentals_study_material.md](cybersecurity_fundamentals_study_material.md) (OS/Networking/Protocols/Python security)
- [appsec_study_material.md](appsec_study_material.md) (web/app/API security)
- [cloudsec_study_material.md](cloudsec_study_material.md) (cloud security)
- [cryptography_study_material.md](cryptography_study_material.md) (crypto)

Use this as a capstone foundation layer.



## Generated Table of Contents
- [F+0) How to use this document (the efficient way)](#f0-how-to-use-this-document-the-efficient-way)
- [For each module:](#for-each-module)
- [F+1) Secure engineering & Secure SDLC (the foundation of AppSec + CloudSec)](#f1-secure-engineering-secure-sdlc-the-foundation-of-appsec-cloudsec)
- [Why this matters](#why-this-matters)
- [F+2) Identity & enterprise auth (Windows/AD + modern identity)](#f2-identity-enterprise-auth-windowsad-modern-identity)
- [Why this matters](#why-this-matters)
- [F+3) Logging, telemetry, and detection engineering (blue-team foundation)](#f3-logging-telemetry-and-detection-engineering-blue-team-foundation)
- [Why this matters](#why-this-matters)
- [F+4) Databases & data access (what makes injection and logic bugs easier)](#f4-databases-data-access-what-makes-injection-and-logic-bugs-easier)
- [Why this matters](#why-this-matters)
- [F+5) Containers & Kubernetes security (modern baseline)](#f5-containers-kubernetes-security-modern-baseline)
- [Why this matters](#why-this-matters)
- [F+6) Supply chain & CI/CD security (foundation)](#f6-supply-chain-cicd-security-foundation)
- [Why this matters](#why-this-matters)
- [F+7) “Finish line” checklist (foundation complete)](#f7-finish-line-checklist-foundation-complete)
- [You are foundation-complete when you can do these without guessing:](#you-are-foundation-complete-when-you-can-do-these-without-guessing)

---

## F+0) How to use this document (the efficient way)
## For each module:
1) Read the “Core ideas” section.
2) Do the labs/exercises.
3) Produce 1 short write-up:
   - threat model
   - root cause
   - fix
   - what to log + what to alert

Portfolio rule
- 12 write-ups total from this doc = a very strong foundation portfolio.


## F+1) Secure engineering & Secure SDLC (the foundation of AppSec + CloudSec)
## Why this matters
- Most security work is not “find a bug”. It is building systems that avoid bugs.

Core ideas (memorize)
1) Threat modeling is a design skill
- Build a DFD, mark trust boundaries, list assets.
- Apply STRIDE to each boundary.

2) Security is an engineering constraint
- Like latency or cost: you design around it.

3) Security requirements beat “best practices”
- Use OWASP ASVS as a requirement checklist.

4) Defense-in-depth is layering, not redundancy
- Example: AuthZ checks + logging + rate limits + segmentation.

5) You need a “fix pipeline”
- Findings without fixes don’t matter.

Minimum Secure SDLC pipeline (practical)
- Code:
  - code review checklist
  - secret scanning
  - dependency scanning
- CI:
  - SAST (pattern-based)
  - unit tests for security controls
- CD:
  - artifact signing (or provenance)
- Runtime:
  - monitoring, alerts, incident playbooks

What to log (minimum)
- authentication success/failure
- authorization denials
- admin actions
- secrets access
- high-risk business flows

Exercises / labs
- Pick one small web API you built (or a lab app).
- Write an ASVS-inspired checklist for it:
  - authentication
  - access control
  - input validation
  - error handling
  - logging

Resources
- OWASP ASVS: [https://owasp.org/www-project-application-security-verification-standard/](https://owasp.org/www-project-application-security-verification-standard/)
- OWASP Cheat Sheets: [https://cheatsheetseries.owasp.org/](https://cheatsheetseries.owasp.org/)
- OWASP Proactive Controls: [https://top10proactive.owasp.org/](https://top10proactive.owasp.org/)
- Threat Modeling (Shostack) (book)


## F+2) Identity & enterprise auth (Windows/AD + modern identity)
## Why this matters
- In enterprise environments, identity is often the real perimeter.

Core ideas
- Authentication vs authorization
- Kerberos vs NTLM (high level)
- Tokens/claims/roles and how they map to permissions
- Privileged access models:
  - least privilege
  - just-in-time admin
  - break-glass accounts

What you should be able to explain
- Why “admin everywhere” leads to total compromise.
- How attackers persist via identity changes.

Hands-on practice (safe)
- Build an identity map for any environment:
  - users
  - groups
  - privileged roles
  - service accounts
  - where secrets live

Resources
- Microsoft Entra fundamentals: [https://learn.microsoft.com/entra/fundamentals/](https://learn.microsoft.com/entra/fundamentals/)
- MITRE ATT&CK (Credential Access, Persistence): [https://attack.mitre.org/](https://attack.mitre.org/)

Link back
- For OS internals and Windows/Linux basics: see [cybersecurity_fundamentals_study_material.md](cybersecurity_fundamentals_study_material.md)


## F+3) Logging, telemetry, and detection engineering (blue-team foundation)
## Why this matters
- You can’t defend what you can’t observe.

Core ideas
1) Security events vs debug logs
- Security logs are structured, high-signal, and designed for detection.

2) Detection is about behavior, not strings
- Example: “many denied access attempts on object IDs” rather than “SQLi payload contains ' OR 1=1”.

3) Good logs answer:
- who did it
- what they did
- to which resource
- when
- from where

4) Alert quality
- false positives waste teams
- false negatives allow breaches

Starter detection patterns
- IAM/RBAC changes
- new public exposure
- abnormal data access volume
- repeated authorization failures
- token abuse anomalies

Detection engineering workflow:
```
1. Identify threat (ATT&CK technique or custom scenario)
2. Determine data sources needed
3. Write detection logic (query/rule)
4. Test against:
   - known-bad samples (should fire)
   - known-good samples (should NOT fire)
5. Tune thresholds based on environment
6. Document and deploy to SIEM
7. Monitor for FP/FN and iterate
```

Example detection rule (IDOR/BOLA pattern):
```yaml
# Pseudo-Sigma rule
title: Potential IDOR - Cross-User Object Access
description: User accessing many different user objects in short time
logsource:
  product: webapp
  service: api
detection:
  selection:
    event_type: "object_access"
    http_status: 200
  timeframe: 5m
  condition: selection | count(distinct object_owner_id) by actor_id > 10
falsepositives:
  - Admin users with legitimate broad access
  - Batch processing service accounts
level: medium
```

Exercises
- For 3 AppSec vulns (IDOR, SSRF, brute force): write
  - what to log
  - what alert would look like
  - what metric baseline you'd use

Resources
- Sigma rules (community detections): [https://github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)
- MITRE ATT&CK: [https://attack.mitre.org/](https://attack.mitre.org/)
- Elastic Detection Rules: [https://github.com/elastic/detection-rules](https://github.com/elastic/detection-rules)

Link back
- Cloud logging specifics: see [cloudsec_study_material.md](cloudsec_study_material.md)
- App logging specifics: see [appsec_study_material.md](appsec_study_material.md)


## F+4) Databases & data access (what makes injection and logic bugs easier)
## Why this matters
- Many severe bugs are “data access bugs”: injection, over-broad queries, missing tenant scoping.

Core ideas
- Parameterization vs string concatenation
- ORM pitfalls (raw queries, dynamic filters, unsafe order-by)
- Multi-tenant isolation:
  - every query must include tenant boundary

Race conditions / TOCTOU
- security bugs can be timing bugs (coupon reuse, double spend, inventory)

Exercises
- Take one endpoint (e.g., /orders/{id}):
  - write the intended authorization rule
  - write the intended DB query
  - list how it could fail

Resources
- PortSwigger (SQLi/NoSQL): [https://portswigger.net/web-security](https://portswigger.net/web-security)

Link back
- Injection checklists: see [appsec_study_material.md](appsec_study_material.md)


## F+5) Containers & Kubernetes security (modern baseline)
## Why this matters
- Many companies deploy via containers and Kubernetes.

Core ideas
- Image supply chain:
  - trusted base images
  - scanning
  - signatures/provenance
- Runtime isolation:
  - least privilege
  - no root
  - minimal capabilities
- Kubernetes:
  - RBAC
  - namespaces
  - network policies
  - admission policies

Common failure modes
- cluster admin granted too widely
- secrets treated as “safe” (they are not)
- dashboards exposed

Exercises
- Write a “container hardening checklist” you can apply to any Dockerfile.
- For K8s, write a minimal RBAC policy for a read-only service.

Resources
- Kubernetes security docs: [https://kubernetes.io/docs/concepts/security/](https://kubernetes.io/docs/concepts/security/)
- CIS Benchmarks: [https://www.cisecurity.org/cis-benchmarks/](https://www.cisecurity.org/cis-benchmarks/)

Link back
- Cloud-native workload security: see [cloudsec_study_material.md](cloudsec_study_material.md)


## F+6) Supply chain & CI/CD security (foundation)
## Why this matters
- Modern compromises often target build pipelines and dependencies.

Core ideas
- SCA (dependency vulnerabilities)
- Secret scanning
- Build provenance / signing
- Least privilege for CI tokens

Exercises
- Pick a sample repo:
  - list dependencies
  - define a policy: pin versions, scan, patch cadence

Resources
- SLSA: [https://slsa.dev/](https://slsa.dev/)
- OWASP Dependency-Check: [https://owasp.org/www-project-dependency-check/](https://owasp.org/www-project-dependency-check/)


## F+7) “Finish line” checklist (foundation complete)
## You are foundation-complete when you can do these without guessing:
- Threat model a simple system and propose mitigations.
- Explain identity boundaries (human vs workload identity) and least privilege.
- Design logging that supports incident investigation.
- Review an API endpoint for AuthZ + injection + business logic.
- Explain how cloud guardrails prevent common incidents.
- Explain why AEAD + key management matters (not just algorithms).


END OF FOUNDATIONS+ STUDY MATERIAL

---

# FOUNDATIONS+ DEEP DIVE ADDENDUM

## FD1) Database Security Deep Dive

### FD1.1 Parameterization Explained
```python
# VULNERABLE: String concatenation
query = f"SELECT * FROM users WHERE id = {user_input}"
# If user_input = "1 OR 1=1", returns ALL users

# SAFE: Parameterized query
query = "SELECT * FROM users WHERE id = %s"
cursor.execute(query, (user_input,))
```

### FD1.2 ORM Pitfalls
```python
# VULNERABLE in Django
User.objects.raw(f"SELECT * FROM users WHERE name = '{user_input}'")

# SAFE
User.objects.filter(name=user_input)
```

### FD1.3 Race Conditions (TOCTOU)
```python
# VULNERABLE: Check then use
if coupon.uses_remaining > 0:  # CHECK
    coupon.uses_remaining -= 1  # USE - race!

# SAFE: Atomic operation
Coupon.objects.filter(uses_remaining__gt=0).update(
    uses_remaining=F('uses_remaining') - 1
)
```

## FD2) Container Security Checklist
```yaml
image:
  - Pin versions (not :latest)
  - Scan for CVEs
  - Use minimal base images
runtime:
  - Run as non-root
  - Drop capabilities
  - Read-only filesystem
  - Set resource limits
```

## FD3) K8s Security Layers
```
Layer 1: API Authentication (who is calling?)
Layer 2: RBAC (what can they do?)
Layer 3: Admission Controllers (should this be allowed?)
Layer 4: Network Policies (what can talk to what?)
Layer 5: Pod Security (how secure are pods?)
Layer 6: Runtime Security (what's happening inside?)
```

## FD4) CI/CD Security Checklist
```yaml
secrets:
  - Store in secret manager
  - Scope to specific jobs
  - Rotate regularly
builds:
  - Use lockfiles
  - Scan dependencies
  - Sign artifacts
permissions:
  - Least privilege CI tokens
  - Require approval for prod
```

## FD5) IR First 60 Minutes
```
Minutes 0-15: TRIAGE
  - Confirm real incident
  - Assess severity
  - Notify IR lead
  - Start incident log

Minutes 15-30: CONTAIN
  - Identify affected systems
  - Isolate if needed
  - Preserve evidence

Minutes 30-60: INVESTIGATE
  - Gather logs
  - Build timeline
  - Identify scope
```

