# CLOUD SECURITY STUDY MATERIAL (TEXTBOOK-STYLE)
Version: April 2026
Audience: final-year undergrad / security intern; strong fundamentals; wants CloudSec track
Prereqs: see [cybersecurity_fundamentals_study_material.md](cybersecurity_fundamentals_study_material.md) (networking, OS, crypto, identity, logging)


## Generated Table of Contents
- [HOW TO USE THIS DOCUMENT](#how-to-use-this-document)
- [This is a “read + practice” Cloud Security reference.](#this-is-a-read-practice-cloud-security-reference)
- [CS0) CloudSec mental model (the 10 ideas that make it “click”)](#cs0-cloudsec-mental-model-the-10-ideas-that-make-it-click)
- [1) Shared Responsibility Model (SRM)](#1-shared-responsibility-model-srm)
- [CS0A) Cloud basics primer (clear definitions + examples)](#cs0a-cloud-basics-primer-clear-definitions-examples)
- [If cloud terms feel fuzzy, start here. Most CloudSec confusion is vocabulary.](#if-cloud-terms-feel-fuzzy-start-here-most-cloudsec-confusion-is-vocabulary)
- [CS1) Threat model for cloud (what attackers actually do)](#cs1-threat-model-for-cloud-what-attackers-actually-do)
- [Typical cloud attack chain (high-level, defensive framing)](#typical-cloud-attack-chain-high-level-defensive-framing)
- [CS2) Shared responsibility by service model (IaaS / PaaS / SaaS)](#cs2-shared-responsibility-by-service-model-iaas-paas-saas)
- [IaaS (VMs, VPC/VNet)](#iaas-vms-vpcvnet)
- [CS3) Asset inventory (the foundation of cloud security)](#cs3-asset-inventory-the-foundation-of-cloud-security)
- [You cannot secure what you cannot see.](#you-cannot-secure-what-you-cannot-see)
- [CS4) IAM (the core of CloudSec)](#cs4-iam-the-core-of-cloudsec)
- [4.1 Concepts you must master](#41-concepts-you-must-master)
  - [4.2 Common IAM failure modes](#42-common-iam-failure-modes)
  - [4.3 Defensive patterns](#43-defensive-patterns)
  - [4.4 IAM logging and detection (must-have)](#44-iam-logging-and-detection-must-have)
  - [4.5 Concrete IAM examples (AWS + Azure)](#45-concrete-iam-examples-aws-azure)
- [CS5) Network security (VPC/VNet) in cloud terms](#cs5-network-security-vpcvnet-in-cloud-terms)
- [5.1 Concepts](#51-concepts)
  - [5.2 Core controls](#52-core-controls)
  - [5.3 Common misconfigurations](#53-common-misconfigurations)
  - [5.4 Defensive patterns](#54-defensive-patterns)
  - [5.5 Concrete network example (3-tier web app)](#55-concrete-network-example-3-tier-web-app)
- [CS6) Storage & data security (object storage, disks, backups)](#cs6-storage-data-security-object-storage-disks-backups)
- [6.1 Object storage (buckets/containers)](#61-object-storage-bucketscontainers)
  - [6.2 Disks and snapshots](#62-disks-and-snapshots)
  - [6.3 Backups](#63-backups)
- [CS7) Compute security (VMs, containers, serverless)](#cs7-compute-security-vms-containers-serverless)
- [7.1 VMs](#71-vms)
  - [7.2 Containers](#72-containers)
  - [7.3 Serverless](#73-serverless)
- [CS8) Kubernetes / orchestration security (cloud-native reality)](#cs8-kubernetes-orchestration-security-cloud-native-reality)
- [8.1 Why K8s is a CloudSec topic](#81-why-k8s-is-a-cloudsec-topic)
  - [8.2 Core concepts](#82-core-concepts)
  - [8.3 Common failure modes](#83-common-failure-modes)
- [CS9) Secrets & key management (KMS/HSM, rotation, envelopes)](#cs9-secrets-key-management-kmshsm-rotation-envelopes)
- [9.1 Basics](#91-basics)
  - [9.2 Failure modes](#92-failure-modes)
  - [9.3 Defensive patterns](#93-defensive-patterns)
  - [9.4 Envelope encryption (simple explanation)](#94-envelope-encryption-simple-explanation)
  - [9.5 Rotation examples (what “good” looks like)](#95-rotation-examples-what-good-looks-like)
- [CS10) Logging, detection, and cloud forensics](#cs10-logging-detection-and-cloud-forensics)
- [10.1 The must-have logs (control plane)](#101-the-must-have-logs-control-plane)
  - [10.2 Data plane logs (examples)](#102-data-plane-logs-examples)
  - [10.3 Detection engineering basics](#103-detection-engineering-basics)
  - [10.4 Forensics mindset](#104-forensics-mindset)
  - [10.5 Simple investigation workflow (works on AWS and Azure)](#105-simple-investigation-workflow-works-on-aws-and-azure)
- [CS11) Governance, compliance, and posture management](#cs11-governance-compliance-and-posture-management)
- [11.1 Policy as code](#111-policy-as-code)
  - [11.2 Posture management (CSPM)](#112-posture-management-cspm)
  - [11.3 Reference frameworks](#113-reference-frameworks)
- [CS12) Cloud incident response (IR) playbooks](#cs12-cloud-incident-response-ir-playbooks)
- [Minimum playbooks to build](#minimum-playbooks-to-build)
- [CS13) Hands-on labs (structured path)](#cs13-hands-on-labs-structured-path)
- [Lab safety](#lab-safety)
- [CS14) Case studies (templates)](#cs14-case-studies-templates)
- [CS14.1 Public bucket incident](#cs141-public-bucket-incident)
- [CS15) Resource index (complete set)](#cs15-resource-index-complete-set)
- [Foundations](#foundations)
- [CS16) AWS CloudSec appendix (services, guardrails, labs)](#cs16-aws-cloudsec-appendix-services-guardrails-labs)
- [Goal: translate the generic CloudSec model into concrete AWS actions.](#goal-translate-the-generic-cloudsec-model-into-concrete-aws-actions)
- [CS17) Azure CloudSec appendix (services, guardrails, labs)](#cs17-azure-cloudsec-appendix-services-guardrails-labs)
- [Goal: translate the generic CloudSec model into concrete Azure actions.](#goal-translate-the-generic-cloudsec-model-into-concrete-azure-actions)
- [CS18) AWS ↔ Azure quick mapping cheat sheet](#cs18-aws-azure-quick-mapping-cheat-sheet)
- [Identity and governance](#identity-and-governance)
- [CS19) AWS-first quickstart runbook (minimum secure baseline)](#cs19-aws-first-quickstart-runbook-minimum-secure-baseline)
- [Outcome: in 60–120 minutes you have a cloud account that is (1) auditable, (2) least-privilege oriented, and (3) protected against the most common “oops” misconfigs.](#outcome-in-60120-minutes-you-have-a-cloud-account-that-is-1-auditable-2-least-privilege-oriented-and-3-protected-against-the-most-common-oops-misconfigs)
- [CS20) Azure-first quickstart runbook (minimum secure baseline)](#cs20-azure-first-quickstart-runbook-minimum-secure-baseline)
- [Outcome: in 60–120 minutes you have an Azure subscription that is (1) auditable, (2) protected by identity best practices, and (3) has policy guardrails.](#outcome-in-60120-minutes-you-have-an-azure-subscription-that-is-1-auditable-2-protected-by-identity-best-practices-and-3-has-policy-guardrails)
- [CS21) “What good looks like” (universal cloud checklist)](#cs21-what-good-looks-like-universal-cloud-checklist)
- [Identity](#identity)
- [CS22) Common rookie mistakes (AWS + Azure) and how to prevent them](#cs22-common-rookie-mistakes-aws-azure-and-how-to-prevent-them)
- [Read this section whenever you feel lost. Most real cloud incidents are a small set of repeated mistakes.](#read-this-section-whenever-you-feel-lost-most-real-cloud-incidents-are-a-small-set-of-repeated-mistakes)
  - [CS22.1 Mistakes that happen everywhere (provider-agnostic)](#cs221-mistakes-that-happen-everywhere-provider-agnostic)
  - [1) No control-plane logs enabled](#1-no-control-plane-logs-enabled)
  - [CS22.2 AWS-specific rookie mistakes](#cs222-aws-specific-rookie-mistakes)
  - [1) Root account used routinely](#1-root-account-used-routinely)
  - [CS22.3 Azure-specific rookie mistakes](#cs223-azure-specific-rookie-mistakes)
  - [1) Too many permanent Owners / no PIM](#1-too-many-permanent-owners-no-pim)
  - [CS22.4 Fast self-check (5 questions)](#cs224-fast-self-check-5-questions)
  - [1) Can I answer “who changed this” for IAM/network/storage?](#1-can-i-answer-who-changed-this-for-iamnetworkstorage)

---

## HOW TO USE THIS DOCUMENT
## This is a “read + practice” Cloud Security reference.
- Read: each module explains concepts, failure modes, and defensive patterns.
- Practice: each module includes hands-on labs and verification checklists.
- Output: produce a portfolio of short write-ups (root cause → fix → detection).

Assumptions
- You will touch at least one cloud (AWS or Azure or GCP). Provider doesn’t matter at first.
- You will build small, safe labs (free tier / local emulators) and learn secure-by-default patterns.


## CS0) CloudSec mental model (the 10 ideas that make it “click”)
## 1) Shared Responsibility Model (SRM)
- Cloud provider secures: physical, core infrastructure, hypervisor (varies by service model).
- You secure: identity, data, configurations, network policy, app-level security.
- SRM changes per service: IaaS vs PaaS vs SaaS.

2) Identity is the new perimeter
- Cloud breaches are often: credential theft + overly-permissive IAM.
- Network isolation helps, but IAM mistakes dominate blast radius.

3) APIs are the control plane
- “Cloud” is a set of APIs. Attacks and defenses both happen via APIs.
- Logging the control plane is non-negotiable.

4) Everything is configuration
- Many incidents are misconfiguration, not software bugs.
- Config review, policy-as-code, and drift detection are key.

5) Blast radius is the primary design variable
- Design for least privilege, segmentation, and fast revocation.

6) Defaults are not enough
- “Default secure” is rare; you must explicitly set logging, encryption, and guardrails.

7) Availability is security
- Cost/DoS (“resource consumption”) is a frequent cloud risk.

8) Supply chain is part of cloud
- CI/CD, images, registries, IaC, managed services: the chain is long.

9) Data is everywhere
- Backups, logs, snapshots, object storage, caches—data leaks often come from “secondary” copies.

10) Observability is the difference between an incident and a disaster
- You need: logs, metrics, traces, asset inventory, and alerting.


## CS0A) Cloud basics primer (clear definitions + examples)
## If cloud terms feel fuzzy, start here. Most CloudSec confusion is vocabulary.

Link to fundamentals (when needed)
- Networking (TCP/IP, DNS, TLS): see [cybersecurity_fundamentals_study_material.md](cybersecurity_fundamentals_study_material.md)
- OS basics (Linux/Windows processes, permissions, logs): see [cybersecurity_fundamentals_study_material.md](cybersecurity_fundamentals_study_material.md)
- Web/AppSec concepts (SSRF, auth): see [appsec_study_material.md](appsec_study_material.md)

CS0A.1 “Cloud is an API”: control plane vs data plane
- Control plane: management actions (create VM, change firewall rule, attach policy).
  - Security consequence: attackers can change your environment without touching your app.
- Data plane: your application traffic and data operations (HTTP requests, DB queries, object reads).
  - Security consequence: data exfil often happens here.

Example
- You open a database to the internet:
  - control plane event: someone changed a security group / NSG rule
  - data plane impact: scans and login attempts hit the DB

CS0A.2 Regions, Availability Zones, and “why they matter for security”
- Region: a geographic area containing multiple AZs.
- AZ: isolated datacenter group within a region.

Security relevance
- Availability: design to survive an AZ outage.
- Compliance/data residency: choose regions intentionally.
- Detection: “new region use” can be a strong compromise signal.

CS0A.3 Accounts / subscriptions / projects (the real security boundary)
- AWS: Account (strong isolation); Organizations groups accounts.
- Azure: Subscription is a billing + management boundary; Management Groups organize subscriptions.

Security relevance
- Putting dev and prod in separate accounts/subscriptions is one of the best “blast radius” controls.

CS0A.4 Resource exposure basics (public vs private)
Common exposures
- Public IP on a VM/load balancer
- Public object storage
- Public database endpoint

Simple rule
- If it’s reachable from the public internet, treat it like a production web service:
  - authentication
  - authorization
  - rate limiting
  - logging

CS0A.5 “Default deny” mental model for cloud
- Inbound: default deny; allow only what you need.
- Outbound: default allow is common, but sensitive workloads should restrict egress.
- Identity: default deny; allow only necessary actions on necessary resources.

CS0A.6 A tiny end-to-end example (secure-by-default web app)
Goal: a simple web app that stores files.

Insecure design (common)
- App is public.
- Storage bucket is public.
- VM has admin ports open to world.
- No control-plane logs.

Secure baseline design
- App behind a load balancer; only 80/443 exposed.
- App runs in private subnet; no public IP.
- Storage is private; app accesses it via a workload identity (no embedded secrets).
- Control-plane logs enabled and protected.

What you should be able to explain
- “Who can reach what?” (network)
- “Who can do what?” (IAM)
- “How do we detect changes?” (logging)


## CS1) Threat model for cloud (what attackers actually do)
## Typical cloud attack chain (high-level, defensive framing)
1) Gain initial access
- phished credentials
- leaked access keys/tokens
- exposed instance metadata via SSRF (app vulnerability becomes cloud credential theft)
- exposed management endpoints (e.g., dashboards) or misconfigured CI secrets

2) Privilege escalation
- overly permissive IAM roles
- role chaining / assume-role abuse
- service identities with broad permissions

3) Lateral movement
- pivot through managed services
- move across projects/subscriptions/accounts if trust relationships are weak

4) Persistence
- create new access keys/service principals
- add OAuth apps/integrations
- modify IAM policies
- create hidden workloads

5) Impact
- data exfiltration (object storage, DB snapshots, exports)
- crypto mining / cost blow-up
- ransomware-style deletion/encryption of backups and buckets

Defender focus
- Stop initial credential theft and limit permissions.
- Inventory + logging + alerting on identity and control-plane events.


## CS2) Shared responsibility by service model (IaaS / PaaS / SaaS)
## IaaS (VMs, VPC/VNet)
- You own: OS hardening, patching, EDR, host firewall, app security.
- Cloud owns: physical, core infra.

PaaS (managed DBs, managed app platforms)
- You own: identity, data classification, network exposure, encryption choices, configuration.
- Cloud owns: OS patching for the service (usually).

SaaS (email, CRM)
- You own: identity, access policies, tenant configuration, data governance.
- Cloud owns: most infrastructure.

Practice
- For any cloud service you use, write down:
  - who patches what
  - what logs exist and who controls them
  - where keys live (KMS/HSM vs provider-managed)


## CS3) Asset inventory (the foundation of cloud security)
## You cannot secure what you cannot see.

Inventory requirements
- Accounts/subscriptions/projects (org structure)
- Identity objects (users, groups, roles, service identities)
- Compute (VMs, containers, serverless)
- Data stores (object storage, DBs, queues)
- Network boundaries (VPC/VNet, subnets, SG/NSG rules, gateways)
- External exposure (public IPs, load balancers, API gateways)
- CI/CD and registries (pipelines, image registries)

Minimum baseline
- Tagging or labeling strategy (owner, environment, data sensitivity)
- Central inventory view (cloud-native inventory or CSPM)


## CS4) IAM (the core of CloudSec)
## 4.1 Concepts you must master
- Principals: users, service identities, roles
- Policies: allow/deny statements; conditions
- Authentication vs authorization
- Temporary credentials (preferred) vs long-lived keys (avoid)
- Trust policies (who can assume a role)
- Resource-based policies vs identity-based policies (varies by provider)

### 4.2 Common IAM failure modes
- wildcard permissions (e.g., "*:*" or broad service permissions)
- missing conditions (no constraints on source IP, MFA, device posture)
- overly permissive service roles (compute roles can read all storage)
- poor separation of environments (dev/test/prod share permissions)
- orphaned accounts / unused keys

### 4.3 Defensive patterns
- Least privilege: start from deny-by-default; grant minimal actions.
- Use roles + short-lived tokens.
- Require MFA for admins.
- Break-glass accounts stored securely.
- Separate duties: deploy vs operate vs security.
- Strong org structure: separate accounts/subscriptions per environment.

### 4.4 IAM logging and detection (must-have)
- Alert on:
  - new keys/credentials created
  - policy changes
  - role assumption anomalies
  - disabling MFA / weakening auth policies
  - access from impossible travel/new regions

### 4.5 Concrete IAM examples (AWS + Azure)
AWS example: “App can read only one S3 prefix” (conceptual)
- Intent: allow read of s3://company-prod-assets/app1/* only.
- What to internalize:
  - scope permissions to a specific bucket AND prefix
  - avoid wildcard action/resource unless justified

Example policy shape (simplified)
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": ["arn:aws:s3:::company-prod-assets/app1/*"]
    }
  ]
}

Azure example: “Function reads one blob container” (conceptual)
- Use a Managed Identity.
- Grant a Storage role at the narrowest scope possible (container if supported; otherwise storage account or resource group).
- Key idea: scope matters (subscription > resource group > resource).

Reading IAM like an attacker
- If a workload identity can list all buckets/containers, it’s a discovery tool.
- If it can read secrets or assume more roles, it’s a privilege escalation path.

Hands-on lab ideas (safe)
- Build a minimal role with read-only access to one bucket/container.
- Gradually tighten permissions and verify what breaks.
- Create an “admin” role and add MFA/conditional access.

Checklist (printable)
- [ ] No long-lived keys for humans in daily use
- [ ] MFA for privileged users
- [ ] Admin actions logged and alerted
- [ ] Least privilege roles for workloads
- [ ] Separate prod from dev


## CS5) Network security (VPC/VNet) in cloud terms
## 5.1 Concepts
- Cloud networks are software-defined; security is mostly policy.
- East-west traffic matters as much as north-south.

### 5.2 Core controls
- Security groups / NSGs: stateful rules on workloads
- NACLs (if applicable): stateless subnet-level rules
- Private endpoints / service endpoints: reduce public exposure
- Load balancers + WAF: protect internet-facing apps
- DNS security: controlled zones, logging

### 5.3 Common misconfigurations
- 0.0.0.0/0 on admin ports
- exposed databases
- overly permissive egress
- no segmentation between tiers

### 5.4 Defensive patterns
- Default deny inbound; minimal allowed ports.
- Separate subnets for public vs private.
- Use private connectivity to managed services.
- Egress filtering for sensitive workloads.

### 5.5 Concrete network example (3-tier web app)
Goal: internet users access only the load balancer; DB is private.

Desired reachability
- Internet -> Load balancer (443)
- Load balancer -> App (443 or 8080)
- App -> DB (DB port only)
- Internet -> App (blocked)
- Internet -> DB (blocked)

Common mistake
- “Temporarily” opening DB to 0.0.0.0/0 for debugging.

What to verify
- No public IP on app/db resources.
- Security group/NSG rules allow only expected flows.
- Flow logs show only the intended paths.

Logs to enable
- Flow logs (VPC/VNet flow logs)
- WAF logs
- DNS query logs (where available)

Lab ideas
- Build a 3-tier network (public LB, private app, private DB).
- Prove DB is unreachable from internet.
- Enable flow logs and inspect allowed/blocked patterns.


## CS6) Storage & data security (object storage, disks, backups)

### 6.1 Object storage (buckets/containers)
Why object storage is high-risk:
- Often contains sensitive data (backups, logs, exports, ML datasets)
- Easy to misconfigure (public access is one checkbox away)
- Commonly targeted in breaches (Capital One, various S3 leaks)

Common misconfigurations:
```
❌ Bucket policy allows s3:* to Principal: "*"
❌ Public access block disabled
❌ ACL grants READ to AllUsers/AuthenticatedUsers
❌ No encryption (data at rest)
❌ No versioning (ransomware risk)
❌ No access logging
```

Secure baseline configuration:
```
✓ Block all public access (account-level + bucket-level)
✓ Encryption enabled (SSE-S3 minimum, SSE-KMS for sensitive data)
✓ Versioning enabled (ransomware recovery)
✓ Access logging to separate bucket
✓ Lifecycle policies for cost and compliance
✓ Bucket policies use least privilege + conditions
✓ No ACLs (use IAM policies only)
```

AWS S3 secure bucket policy example (conceptual):
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::mybucket", "arn:aws:s3:::mybucket/*"],
      "Condition": {"Bool": {"aws:SecureTransport": "false"}}
    },
    {
      "Sid": "DenyUnencryptedUploads",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::mybucket/*",
      "Condition": {"Null": {"s3:x-amz-server-side-encryption": "true"}}
    }
  ]
}
```

Azure Storage secure configuration:
- Disable public blob access at storage account level
- Use Private Endpoints for network isolation
- Enable soft delete and versioning
- Use customer-managed keys (CMK) for sensitive data
- Enable diagnostic logging to Log Analytics
Common failure modes
- public read/write
- misconfigured ACLs or policies
- sensitive data in logs and backups

Defensive patterns
- block public access (provider feature) and enforce policy.
- least-privilege bucket policies
- encryption at rest + key management policy
- versioning + object lock/immutability for ransomware resistance

6.1A Example: what “public bucket” really means
Typical failure
- Bucket policy or ACL allows anyone (anonymous) to read.

Clear test you can do
- Can you fetch an object without credentials?
- Can you list objects?

Defensive baseline
- Use “block public access” features AND enforce with org policies (SCP/Azure Policy).
- Prefer private access + workload identity.

### 6.2 Disks and snapshots
Risks
- snapshots copied across accounts
- orphaned disks
- unencrypted volumes

Controls
- default encryption on
- restrict snapshot sharing
- inventory orphaned resources

### 6.3 Backups
- Treat backups as production data.
- Protect backup deletion (separate account/role).

Checklist
- [ ] Public access blocked
- [ ] Encryption enabled and enforced
- [ ] Logging for access events
- [ ] Backups protected from deletion


## CS7) Compute security (VMs, containers, serverless)
## 7.1 VMs
- baseline hardening (CIS)
- patch management
- EDR/telemetry
- IMDS/metadata hardening (protect against SSRF credential theft)

7.1A Example: SSRF becomes Cloud compromise via metadata
Scenario (very common)
- App has an SSRF bug: attacker can make the server fetch a URL.
- Server can access instance metadata.
- Metadata returns credentials or tokens.

Result
- Attacker steals cloud credentials and uses the control plane API to enumerate/exfiltrate.

Defenses (layered)
- App-level SSRF prevention (allowlist, block private ranges).
- Metadata hardening:
  - AWS: require IMDSv2
  - Azure: managed identity endpoints still exist; protect outbound and reduce what identity can do
- Least privilege workload identity (even if stolen, permissions are small).
- Egress controls + monitoring for unusual outbound calls.

### 7.2 Containers
- image provenance and scanning
- least privilege (no root, minimal capabilities)
- secrets management (no secrets baked into images)
- runtime controls

7.2A Container example: “why root is dangerous”
- If the container runs as root and escapes (or abuses host mounts), host compromise is easier.
- Good baseline: run as non-root, read-only filesystem where possible, minimal capabilities.

### 7.3 Serverless
- IAM is the perimeter (function role permissions)
- event injection risks (untrusted events)
- dependency supply chain in function packages

7.3A Serverless example: least privilege is everything
Scenario
- A function handles file uploads and writes to storage.
Bad role
- The function role can read/write all buckets/containers.
Good role
- The function role can write only to one specific bucket/container + prefix.

Security consequence
- If the function is exploited, the attacker can only impact a narrow slice of data.


## CS8) Kubernetes / orchestration security (cloud-native reality)
## 8.1 Why K8s is a CloudSec topic
- Many “cloud” orgs run workloads on managed Kubernetes.
- Misconfigurations lead to cluster compromise and data exposure.

### 8.2 Core concepts
- RBAC, namespaces, service accounts
- admission control / policies
- network policies
- secrets (and their limitations)

### 8.3 Common failure modes
- overly permissive cluster roles
- exposed dashboards
- workloads running privileged
- no network policies (flat network)

Defensive patterns
- least privilege RBAC
- pod security standards / policies
- restrict API server access
- audit logging

Resources
- Kubernetes docs security overview: [https://kubernetes.io/docs/concepts/security/](https://kubernetes.io/docs/concepts/security/)
- CIS Kubernetes Benchmark (reference via CIS Benchmarks site): [https://www.cisecurity.org/cis-benchmarks/](https://www.cisecurity.org/cis-benchmarks/)


## CS9) Secrets & key management (KMS/HSM, rotation, envelopes)
## 9.1 Basics
- Secrets: passwords, tokens, API keys
- Keys: cryptographic keys for encryption/signing

### 9.2 Failure modes
- secrets in source control
- secrets in environment variables with broad access
- weak rotation and no revocation path

### 9.3 Defensive patterns
- use managed secret stores
- rotate secrets; revoke when leaked
- envelope encryption with KMS
- least privilege access to secrets

### 9.4 Envelope encryption (simple explanation)
- You encrypt data with a data key.
- You encrypt (wrap) the data key with a master key in KMS.

Why it’s used
- KMS keys don’t have to directly encrypt huge data.
- You can rotate the master key and keep data manageable.

Concrete example
- You store customer documents in object storage.
- Each document is encrypted with a unique data key.
- Only a service role can ask KMS to unwrap keys.

### 9.5 Rotation examples (what “good” looks like)
- Human credentials: short sessions + MFA; avoid long-lived keys.
- Workload credentials:
  - prefer managed identity / role-based access
  - if you must use secrets: rotate automatically and alert on use from new locations.

Reference
- OWASP Secrets Management Cheat Sheet: [https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)


## CS10) Logging, detection, and cloud forensics
## 10.1 The must-have logs (control plane)
- AWS: CloudTrail
- Azure: Activity Logs
- GCP: Cloud Audit Logs

10.1A What a control-plane incident looks like (examples)
Example A: “DB exposed to the internet”
- Control plane: someone modified a security group / NSG rule.
- Data plane: port scans and login attempts start.

Example B: “persistence via identity”
- Control plane: new access key created, new role assignment granted.
- Data plane: unusual reads from object storage.

What to capture in any alert
- who (principal identity)
- what (action)
- where (resource)
- when (timestamp)
- from where (IP/region)

### 10.2 Data plane logs (examples)
- object storage access logs
- load balancer logs
- WAF logs
- flow logs
- database audit logs (where feasible)

### 10.3 Detection engineering basics
- Alert on IAM changes and unusual role assumptions.
- Alert on new public exposures.
- Alert on impossible travel / new geos.
- Alert on anomalous data access patterns (bulk reads, export jobs).

### 10.4 Forensics mindset
- Preserve logs first.
- Snapshot affected systems carefully.
- Use timelines:
  - identity events
  - network events
  - data access

### 10.5 Simple investigation workflow (works on AWS and Azure)
1) Identify the suspicious control-plane action
- e.g., “security group opened”, “new key created”, “role assignment changed”.
2) Identify the actor identity
- user/role/service principal; check whether it’s expected.
3) Identify blast radius
- list resources that identity could access (permissions) and what it actually touched (logs).
4) Contain
- revoke/rotate creds; remove rogue policies; isolate workloads.
5) Prevent recurrence
- guardrails (SCP/Azure Policy), least privilege, alerts.


## CS11) Governance, compliance, and posture management
## 11.1 Policy as code
- Enforce org guardrails (deny public buckets, require encryption, require logging).

11.1A Example guardrail: “deny public storage”
What you want
- No storage account/bucket should be publicly readable.

How it works in practice
- AWS: SCP prevents making a bucket public (even if a user tries).
- Azure: Azure Policy denies creating a storage account with public access.

Why this matters
- It turns a common incident class into an impossible action.

### 11.2 Posture management (CSPM)
- Detect misconfigurations continuously.
- Track drift from baseline.

### 11.3 Reference frameworks
- CSA Cloud Controls Matrix (CCM): [https://cloudsecurityalliance.org/research/cloud-controls-matrix](https://cloudsecurityalliance.org/research/cloud-controls-matrix)
- NIST CSF: [https://www.nist.gov/cyberframework](https://www.nist.gov/cyberframework)
- CIS Benchmarks: [https://www.cisecurity.org/cis-benchmarks/](https://www.cisecurity.org/cis-benchmarks/)


## CS12) Cloud incident response (IR) playbooks
## Minimum playbooks to build
1) Credential leak
- rotate/revoke keys, invalidate sessions
- analyze access logs, identify blast radius

2) Public data exposure
- remove public access, rotate credentials
- identify accessed objects, notify per policy

3) Crypto mining / cost spike
- isolate workloads, kill malicious resources
- tighten IAM and egress

4) Ransomware-style destruction
- protect backups, use immutability
- separate backup accounts


## CS13) Hands-on labs (structured path)
## Lab safety
- Use a dedicated cloud account/subscription.
- Set budgets/alerts.
- Never use real production data.

Lab path (repeatable)
L1) Identity baseline
- create least-priv roles and test
- enable control plane logging

L2) Storage baseline
- create bucket/container with blocked public access
- enforce encryption
- test access logs

L3) Network baseline
- private subnet workload
- flow logs + WAF (if possible)

L4) Detection baseline
- alerts on IAM policy changes
- alerts on public exposure

Local/cheap practice options
- kind (Kubernetes in Docker): [https://kind.sigs.k8s.io/](https://kind.sigs.k8s.io/)
- Terraform (IaC): [https://www.terraform.io/](https://www.terraform.io/)


## CS14) Case studies (templates)
## CS14.1 Public bucket incident
- Asset exposed:
- Root cause:
- Fix:
- Detection:
- Prevention guardrail:

CS14.2 Leaked access keys in repo
- How discovered:
- Rotation/revocation steps:
- Audit timeline:
- Preventive controls:

CS14.3 SSRF → metadata creds → data exfil
- App entry point:
- Cloud identity abused:
- Data accessed:
- Fix layers:
- Detection/logs:


## CS15) Resource index (complete set)
## Foundations
- CSA CCM: [https://cloudsecurityalliance.org/research/cloud-controls-matrix](https://cloudsecurityalliance.org/research/cloud-controls-matrix)
- NIST CSF: [https://www.nist.gov/cyberframework](https://www.nist.gov/cyberframework)
- CIS Benchmarks: [https://www.cisecurity.org/cis-benchmarks/](https://www.cisecurity.org/cis-benchmarks/)
- MITRE ATT&CK (Cloud): [https://attack.mitre.org/](https://attack.mitre.org/)

Cloud fundamentals (structured learning)
- AWS Skill Builder: [https://skillbuilder.aws/](https://skillbuilder.aws/)
- Microsoft Learn (Azure training): [https://learn.microsoft.com/training/](https://learn.microsoft.com/training/)

Provider security reference (choose one cloud first)
- AWS Well-Architected Framework (Security Pillar): [https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)
- Azure Cloud Adoption Framework (Security): [https://learn.microsoft.com/azure/cloud-adoption-framework/](https://learn.microsoft.com/azure/cloud-adoption-framework/)
- Google Cloud security foundations (start point): [https://cloud.google.com/security](https://cloud.google.com/security)

Architected-practice (practical guidance)
- AWS Well-Architected Labs (Security): [https://www.wellarchitectedlabs.com/](https://www.wellarchitectedlabs.com/)
- Azure Well-Architected Framework (overview): [https://learn.microsoft.com/azure/well-architected/](https://learn.microsoft.com/azure/well-architected/)

Provider “security services” overviews
- AWS Security Hub: [https://docs.aws.amazon.com/securityhub/latest/userguide/what-is-securityhub.html](https://docs.aws.amazon.com/securityhub/latest/userguide/what-is-securityhub.html)
- AWS GuardDuty: [https://docs.aws.amazon.com/guardduty/latest/ug/what-is-guardduty.html](https://docs.aws.amazon.com/guardduty/latest/ug/what-is-guardduty.html)
- Microsoft Defender for Cloud: [https://learn.microsoft.com/azure/defender-for-cloud/](https://learn.microsoft.com/azure/defender-for-cloud/)

Logging/monitoring
- AWS CloudTrail: [https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html)
- Azure Activity Log: [https://learn.microsoft.com/azure/azure-monitor/essentials/activity-log](https://learn.microsoft.com/azure/azure-monitor/essentials/activity-log)
- Google Cloud Audit Logs: [https://cloud.google.com/logging/docs/audit](https://cloud.google.com/logging/docs/audit)
- Azure Monitor (overview): [https://learn.microsoft.com/azure/azure-monitor/](https://learn.microsoft.com/azure/azure-monitor/)

IAM and authorization references
- AWS IAM: [https://docs.aws.amazon.com/IAM/latest/UserGuide/introduction.html](https://docs.aws.amazon.com/IAM/latest/UserGuide/introduction.html)
- AWS Organizations: [https://docs.aws.amazon.com/organizations/latest/userguide/orgs_introduction.html](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_introduction.html)
- Azure RBAC: [https://learn.microsoft.com/azure/role-based-access-control/overview](https://learn.microsoft.com/azure/role-based-access-control/overview)
- Microsoft Entra ID overview: [https://learn.microsoft.com/entra/fundamentals/what-is-entra](https://learn.microsoft.com/entra/fundamentals/what-is-entra)
- Azure PIM (privileged access): [https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-configure](https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-configure)

Network references
- AWS VPC: [https://docs.aws.amazon.com/vpc/](https://docs.aws.amazon.com/vpc/)
- Azure Virtual Network: [https://learn.microsoft.com/azure/virtual-network/virtual-networks-overview](https://learn.microsoft.com/azure/virtual-network/virtual-networks-overview)
- Azure Private Link / Private Endpoint: [https://learn.microsoft.com/azure/private-link/private-endpoint-overview](https://learn.microsoft.com/azure/private-link/private-endpoint-overview)

Storage and data protection
- AWS S3 Block Public Access: [https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
- AWS KMS: [https://docs.aws.amazon.com/kms/latest/developerguide/overview.html](https://docs.aws.amazon.com/kms/latest/developerguide/overview.html)
- Azure Storage security guide: [https://learn.microsoft.com/azure/storage/common/storage-security-guide](https://learn.microsoft.com/azure/storage/common/storage-security-guide)
- Azure Key Vault: [https://learn.microsoft.com/azure/key-vault/general/overview](https://learn.microsoft.com/azure/key-vault/general/overview)
- Azure Managed Identities: [https://learn.microsoft.com/entra/identity/managed-identities-azure-resources/overview](https://learn.microsoft.com/entra/identity/managed-identities-azure-resources/overview)

Compute identity hardening
- AWS EC2 instance metadata service (IMDSv2): [https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)

Governance benchmarks
- Microsoft cloud security benchmark: [https://learn.microsoft.com/security/benchmark/azure/](https://learn.microsoft.com/security/benchmark/azure/)

Kubernetes security
- Kubernetes security docs: [https://kubernetes.io/docs/concepts/security/](https://kubernetes.io/docs/concepts/security/)

Hands-on labs (intentionally vulnerable training)
- CloudGoat (AWS): [https://github.com/RhinoSecurityLabs/cloudgoat](https://github.com/RhinoSecurityLabs/cloudgoat)
- Flaws.cloud (AWS): [https://flaws.cloud/](https://flaws.cloud/)
- Azure Goat: [https://github.com/ine-labs/AzureGoat](https://github.com/ine-labs/AzureGoat)

OWASP (relevant because cloud incidents often start as AppSec)
- SSRF Cheat Sheet: [https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- Secrets management cheat sheet: [https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)


## CS16) AWS CloudSec appendix (services, guardrails, labs)
## Goal: translate the generic CloudSec model into concrete AWS actions.

CS16.1 AWS “service map”
- Identity: IAM, AWS Organizations, IAM Identity Center (SSO)
- Network: VPC, Security Groups, NACLs, Route Tables, IGW/NAT, VPC Endpoints/PrivateLink
- Storage: S3 (object), EBS (block), EFS (file)
- Keys/secrets: KMS, Secrets Manager, SSM Parameter Store
- Logging: CloudTrail (control plane), CloudWatch Logs, VPC Flow Logs
- Governance: SCPs (Organizations), AWS Config (posture), tagging
- Threat detection: GuardDuty, Security Hub, IAM Access Analyzer, Macie
- Compute: EC2; containers: ECS/EKS; serverless: Lambda

CS16.2 AWS “must-enable” baseline
Identity
- Prefer roles + short-lived creds; avoid long-lived access keys for humans.
- Enforce MFA for privileged access.
- Separate prod vs dev via multi-account (AWS Organizations).

Control-plane logging
- Enable CloudTrail broadly; store logs in a protected location (ideally a dedicated log archive account).
- Consider CloudTrail data events for high-risk data planes (notably S3, Lambda) when appropriate.

Posture and drift
- Enable AWS Config for configuration history and compliance checks.
- Use SCPs to enforce guardrails (deny public S3, require encryption, restrict regions).

Threat detection
- Enable GuardDuty.
- Enable Security Hub to centralize findings.
- Use IAM Access Analyzer to detect unintended public/cross-account access.

Network
- Default deny inbound; no 0.0.0.0/0 on admin ports.
- Private subnets for app/db tiers.
- Prefer VPC endpoints for managed services when possible.

Storage
- S3 Block Public Access ON (account + bucket).
- SSE-KMS for sensitive data; enforce via policy.
- Versioning + (optionally) Object Lock for ransomware resistance.

Compute
- Prefer SSM Session Manager over SSH where possible.
- Harden instance metadata access (require IMDSv2 on EC2).

CS16.3 AWS detections (high-signal)
- IAM policy/role changes (especially admin grants)
- new access key creation
- unusual role assumptions
- S3 public policy/ACL changes
- security group opens to world
- sudden compute creation (crypto-mining/cost anomalies)

CS16.4 AWS labs (portfolio-friendly)
Lab A: Logging-first
- Enable CloudTrail; prove you can answer: “who changed this security group?”

Lab B: S3 secure baseline
- Create a bucket with public access blocked; enforce encryption; enable versioning.

Lab C: Least privilege role
- Create a role that can read exactly one bucket prefix; verify everything else fails.

Lab D: Network segmentation
- Build VPC with public LB and private app tier; verify app tier has no public IP.

CS16.5 AWS official references
- CloudTrail: [https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html)
- AWS Config: [https://docs.aws.amazon.com/config/latest/developerguide/WhatIsConfig.html](https://docs.aws.amazon.com/config/latest/developerguide/WhatIsConfig.html)
- GuardDuty: [https://docs.aws.amazon.com/guardduty/latest/ug/what-is-guardduty.html](https://docs.aws.amazon.com/guardduty/latest/ug/what-is-guardduty.html)
- Security Hub: [https://docs.aws.amazon.com/securityhub/latest/userguide/what-is-securityhub.html](https://docs.aws.amazon.com/securityhub/latest/userguide/what-is-securityhub.html)
- IAM Access Analyzer: [https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html](https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html)


## CS17) Azure CloudSec appendix (services, guardrails, labs)
## Goal: translate the generic CloudSec model into concrete Azure actions.

CS17.1 Azure “service map”
- Identity: Microsoft Entra ID, Azure RBAC, PIM (Privileged Identity Management)
- Org structure: Management Groups → Subscriptions → Resource Groups
- Network: VNet, NSG, route tables, Azure Firewall, Private Endpoint/Private Link
- Storage: Storage Accounts (Blob/File/Queue/Table), Managed Disks
- Keys/secrets: Key Vault, Managed Identities
- Logging: Activity Log (control plane), Azure Monitor Logs (Log Analytics), Diagnostic settings
- Governance: Azure Policy, tagging
- Threat detection/posture: Microsoft Defender for Cloud
- SIEM/SOAR (optional): Microsoft Sentinel
- Compute: VMs; containers: AKS; serverless: Azure Functions; PaaS: App Service

CS17.2 Azure “must-enable” baseline
Identity
- Prefer group-based RBAC; minimize direct user assignments.
- Use PIM for just-in-time privileged access.
- Use Conditional Access for admins (MFA and policy constraints).
- Prefer Managed Identities for workloads.

Control-plane logging
- Ensure Activity Logs are available with sufficient retention.
- Turn on Diagnostic settings for critical resources into Log Analytics.

Posture and drift
- Use Azure Policy initiatives to enforce encryption, private access, required diagnostics, allowed regions.
- Use Defender for Cloud for posture and workload protections.

Network
- Default deny inbound; restrict management exposure.
- Prefer Private Endpoints for data services.
- Control outbound traffic for sensitive workloads.

Storage
- Restrict public access; use private endpoints/firewalls where possible.
- Monitor access patterns via diagnostics.

CS17.3 Azure detections (high-signal)
- RBAC role assignment changes (Owner/Contributor grants)
- Key Vault access/role changes
- storage account network rule changes
- NSG rule opens to the internet
- sudden compute creation (cost anomalies)

CS17.4 Azure labs (portfolio-friendly)
Lab A: Logging-first
- Use Activity Log and diagnostics; prove you can answer: “who changed this NSG rule?”

Lab B: Storage secure baseline
- Create a Storage Account with restricted public access; configure diagnostics.

Lab C: Managed identity + least privilege
- Give a managed identity minimal access to one storage container.

Lab D: Policy guardrail
- Assign a policy that denies public storage; verify non-compliant deploy is blocked.

CS17.5 Azure official references
- Activity Log: [https://learn.microsoft.com/azure/azure-monitor/essentials/activity-log](https://learn.microsoft.com/azure/azure-monitor/essentials/activity-log)
- Azure Monitor: [https://learn.microsoft.com/azure/azure-monitor/](https://learn.microsoft.com/azure/azure-monitor/)
- Azure Policy: [https://learn.microsoft.com/azure/governance/policy/](https://learn.microsoft.com/azure/governance/policy/)
- Defender for Cloud: [https://learn.microsoft.com/azure/defender-for-cloud/](https://learn.microsoft.com/azure/defender-for-cloud/)
- Private Endpoint: [https://learn.microsoft.com/azure/private-link/private-endpoint-overview](https://learn.microsoft.com/azure/private-link/private-endpoint-overview)


## CS18) AWS ↔ Azure quick mapping cheat sheet
## Identity and governance
- AWS IAM / Organizations / SCPs  ~  Entra ID + Azure RBAC + Management Groups + Azure Policy

Control-plane audit logs
- CloudTrail  ~  Activity Log (plus resource diagnostic logs)

Posture/drift
- AWS Config  ~  Azure Policy (+ Defender for Cloud recommendations)

Threat detection
- GuardDuty + Security Hub  ~  Defender for Cloud (optionally Sentinel)

Network
- VPC + Security Groups  ~  VNet + NSG

Private connectivity
- VPC Endpoints / PrivateLink  ~  Private Endpoint / Private Link

Keys and secrets
- KMS + Secrets Manager  ~  Key Vault + Managed Identities


## CS19) AWS-first quickstart runbook (minimum secure baseline)
## Outcome: in 60–120 minutes you have a cloud account that is (1) auditable, (2) least-privilege oriented, and (3) protected against the most common “oops” misconfigs.

Safety first
- Use a dedicated AWS account (not personal “main” account).
- Set a budget and cost alerts.

CS19.1 Day-0 identity and account structure
1) Root account
- Use a strong password manager.
- Enable MFA on root.
- Lock down root usage (root should be break-glass only).

2) Admin identity
- Create an admin role/user used only for admin.
- Enforce MFA for privileged access.
- Prefer SSO (IAM Identity Center) when feasible.

3) Split environments (recommended)
- At minimum: dev account + prod account.
- Put logs/security in a separate “log archive” or “security” account when you scale.

What good looks like
- Root has MFA.
- Humans don’t use long-lived access keys daily.
- Admin actions are separated from normal work.

CS19.2 Day-0 control-plane logging (non-negotiable)
1) Enable CloudTrail
- Ensure management events are captured.
- Ensure logs are stored centrally in S3.
- Protect the log bucket (no public access; limited write; versioning recommended).

2) Decide retention
- Keep enough history to investigate incidents.

What good looks like
- You can answer: “Who changed this IAM policy / security group / bucket policy?”

CS19.3 Day-0 threat detection and posture
1) GuardDuty
- Enable it.

2) AWS Config
- Enable it to record changes.

3) Security Hub (optional but helpful)
- Aggregate findings in one place.

4) IAM Access Analyzer
- Use it to detect public/cross-account access paths.

What good looks like
- You get findings when something becomes public.
- You have a “configuration timeline” for key resources.

CS19.4 Day-0 guardrails (prevent the top incidents)
1) S3
- Enable S3 Block Public Access at account level.
- Use bucket policies (not ad-hoc ACLs) and keep them minimal.

2) Network
- No inbound 0.0.0.0/0 to admin ports.
- Default deny inbound; only expose load balancers.

3) Metadata
- Require IMDSv2 on EC2.

CS19.5 One-week AWS lab checklist (with expected evidence)
Day 1: CloudTrail + “who changed what”
- Action: change a security group rule.
- Evidence: CloudTrail event showing actor, source IP, time.

Day 2: S3 secure-by-default
- Action: create bucket; try to make it public; confirm blocked.
- Evidence: policy denial or analyzer finding; bucket not publicly accessible.

Day 3: Least privilege role
- Action: role can read only s3://bucket/app1/*.
- Evidence: allowed access works; other prefixes fail.

Day 4: Network segmentation
- Action: private app tier (no public IP) behind a public load balancer.
- Evidence: connectivity works via LB; direct access to app blocked.

Day 5: Detection drill
- Action: intentionally create a risky config (in a safe way) and see which service flags it (Config/GuardDuty/Security Hub).
- Evidence: finding appears, you document mitigation.

Portfolio output
- Write 5 short reports: “misconfig → impact → fix → detection”.


## CS20) Azure-first quickstart runbook (minimum secure baseline)
## Outcome: in 60–120 minutes you have an Azure subscription that is (1) auditable, (2) protected by identity best practices, and (3) has policy guardrails.

Safety first
- Use a dedicated subscription if possible.
- Set budgets and cost alerts.

CS20.1 Day-0 identity and tenant hygiene
1) Admin access model
- Prefer least privilege via Azure RBAC.
- Prefer group-based role assignments.
- Use PIM for just-in-time elevation to Owner/Contributor.

2) MFA / Conditional Access
- Enforce MFA for admins.
- Use Conditional Access to reduce risk (where available).

What good looks like
- No permanent “Owner” grants for daily work.
- Admin actions require JIT elevation.

CS20.2 Day-0 control-plane logging (non-negotiable)
1) Activity Log
- Ensure Activity Logs are available and retained.

2) Diagnostic settings
- Create a Log Analytics workspace.
- Send diagnostics from critical resources (Storage, Key Vault, public endpoints) into Log Analytics.

What good looks like
- You can answer: “Who changed this NSG / RBAC assignment / Key Vault policy?”

CS20.3 Day-0 posture and guardrails
1) Defender for Cloud
- Enable it for posture visibility and recommendations.

2) Azure Policy
- Assign initiatives to enforce:
  - no public storage
  - required encryption
  - required diagnostics
  - allowed regions

What good looks like
- Non-compliant resources are denied at create time.

CS20.4 Day-0 workload identity
- Prefer Managed Identities for apps.
- Avoid storing secrets in code or pipelines.

CS20.5 One-week Azure lab checklist (with expected evidence)
Day 1: Activity Log + “who changed what”
- Action: change an NSG rule.
- Evidence: Activity Log entry with actor/time.

Day 2: Storage secure-by-default
- Action: create Storage Account; restrict public access; add diagnostics.
- Evidence: logs in Log Analytics; no public exposure.

Day 3: Managed identity least privilege
- Action: VM/Function uses managed identity to access one container.
- Evidence: access works; broader access fails.

Day 4: Policy guardrail
- Action: policy denies public storage; attempt non-compliant deploy.
- Evidence: deployment denied with policy reason.

Day 5: Detection drill
- Action: create a known risky setting (safe) and confirm Defender for Cloud flags it.
- Evidence: recommendation/finding + your mitigation notes.

Portfolio output
- Write 5 short reports: “misconfig → impact → fix → detection”.


## CS21) “What good looks like” (universal cloud checklist)
## Identity
- [ ] Admin access is gated (MFA, JIT where possible)
- [ ] Workloads use roles/managed identities (not embedded secrets)

Logging
- [ ] Control-plane logs enabled and protected
- [ ] Critical resource diagnostics enabled

Guardrails
- [ ] Public storage prevented by policy
- [ ] Default deny inbound; no world-open admin ports

Detection
- [ ] Alerts on IAM/RBAC changes
- [ ] Alerts on new public exposures


## CS22) Common rookie mistakes (AWS + Azure) and how to prevent them
## Read this section whenever you feel lost. Most real cloud incidents are a small set of repeated mistakes.

How to use
- If you find one of these mistakes in a lab/project, write a mini report:
  - what was wrong
  - what an attacker can do
  - the smallest safe fix
  - the guardrail that prevents it from happening again
  - what logs/alerts should fire

### CS22.1 Mistakes that happen everywhere (provider-agnostic)
### 1) No control-plane logs enabled
- Impact: you can’t answer “who did what”; attackers win by default.
- Detect: missing/disabled audit logs; retention too short.
- Prevent: mandatory logging policy + separate log storage + alert on log disable.

2) Dev and prod share the same boundary
- Impact: dev compromise becomes prod compromise.
- Detect: same account/subscription contains both; cross-env role bindings.
- Prevent: separate accounts/subscriptions + deny cross-env by policy.

3) Overly permissive workload identities
- Impact: one compromised app reads everything.
- Detect: wildcard permissions; broad roles at subscription/account scope.
- Prevent: least privilege; scope to specific resource/prefix; continuous permission review.

4) Public-by-accident data exposure
- Impact: data leak from object storage or public endpoints.
- Detect: public access flags, “allow anonymous”, broad ACLs.
- Prevent: deny-public policies (SCP/Azure Policy) + analyzers + posture alerts.

5) Secrets stored in code/CI variables without governance
- Impact: repo leak or pipeline compromise gives cloud access.
- Detect: secret scanning hits; long-lived creds used by humans.
- Prevent: managed identities/roles; secret stores; rotation; secret scanning.

6) “Temporary” network exceptions that never get reverted
- Impact: admin ports/DB exposure; brute force and scanning.
- Detect: security group/NSG rules with 0.0.0.0/0; drift from baseline.
- Prevent: IaC + drift detection + deny rules in policy.

7) Missing egress controls for sensitive workloads
- Impact: exfil becomes easy; malware phones home.
- Detect: unusual outbound destinations; spikes in bytes out.
- Prevent: egress restrictions, proxy, and alerting on unusual destinations.

8) Backup and recovery not treated as security
- Impact: ransomware-style deletion/encryption; no recovery.
- Detect: backup deletion actions; missing immutability.
- Prevent: protected backups (separate roles/accounts), immutability, tested restores.


### CS22.2 AWS-specific rookie mistakes
### 1) Root account used routinely
- Detect: root activity in CloudTrail.
- Prevent: MFA on root; break-glass only; alert on root usage.

2) Long-lived access keys for humans
- Detect: access keys created; keys used from new IP/region.
- Prevent: IAM Identity Center/SSO; short sessions; key rotation policies.

3) S3 bucket becomes public (ACL/policy)
- Detect: bucket policy/ACL changes; Access Analyzer findings.
- Prevent: S3 Block Public Access + SCP deny + continuous checks.

4) Over-broad IAM policies (Action: * / Resource: *)
- Detect: policy review; IAM Access Analyzer; unusual API calls.
- Prevent: least privilege; conditions; permission boundaries.

5) Security groups open admin ports to the world
- Detect: SG change events + config rules.
- Prevent: IaC + AWS Config rules + approvals + deny-by-policy patterns.

6) No IMDS hardening (IMDSv1 allowed)
- Detect: instance metadata settings; SSRF incidents.
- Prevent: require IMDSv2 + least privilege instance roles.

7) CloudTrail logs not protected
- Detect: bucket public settings; delete attempts.
- Prevent: dedicated log bucket/account; versioning; restricted write; alert on changes.


### CS22.3 Azure-specific rookie mistakes
### 1) Too many permanent Owners / no PIM
- Detect: role assignments at subscription scope.
- Prevent: PIM JIT elevation + group-based RBAC.

2) Broad role assignments at subscription scope
- Detect: RBAC grants at high scope; unexpected service principals.
- Prevent: scope down (resource group/resource); least privilege roles.

3) Diagnostic settings not enabled on key resources
- Detect: missing diagnostic settings; empty Log Analytics tables.
- Prevent: Azure Policy to require diagnostics + central workspace.

4) Storage account public access / weak network rules
- Detect: storage firewall changes; public access settings.
- Prevent: Azure Policy deny + private endpoints + restricted networks.

5) Key Vault too open or not monitored
- Detect: Key Vault access policy/role changes; unusual secret reads.
- Prevent: RBAC + least privilege + diagnostics + alerting on secret access spikes.

6) NSG rules open management ports broadly
- Detect: Activity Log for NSG rule changes.
- Prevent: policy guardrails + baseline templates.

7) Managed identities granted broad permissions
- Detect: role assignments to managed identities at high scope.
- Prevent: scope down; restrict to specific resources; periodic review.


### CS22.4 Fast self-check (5 questions)
### 1) Can I answer “who changed this” for IAM/network/storage?
2) If one workload is compromised, what is the blast radius?
3) Can anything become public without a policy denial?
4) Are secrets eliminated (managed identity/roles) or at least governed and rotated?
5) If I lose a region/AZ or get hit by deletion, can I recover?


END OF CLOUD SECURITY STUDY MATERIAL


---

# CLOUDSEC DEEP DIVE ADDENDUM

## CSD1) GCP Cloud Security Appendix

### CSD1.1 GCP Core Security Concepts

**GCP Hierarchy:**
```
Organization
+-- Folders (optional grouping)
�   +-- Projects (primary security boundary)
�       +-- Resources
```

**Key Services Mapping:**
| Purpose | AWS | Azure | GCP |
|---------|-----|-------|-----|
| IAM | IAM | Azure AD + RBAC | Cloud IAM |
| Audit Logs | CloudTrail | Activity Log | Cloud Audit Logs |
| Object Storage | S3 | Blob Storage | Cloud Storage |
| Secrets | Secrets Manager | Key Vault | Secret Manager |
| KMS | KMS | Key Vault | Cloud KMS |
| Guardrails | SCPs + Config | Azure Policy | Org Policies |
| Security Posture | Security Hub | Defender for Cloud | Security Command Center |

### CSD1.2 GCP IAM Model

**IAM Principals:**
```yaml
google_account: user@gmail.com              # Human user
service_account: name@project.iam.gserviceaccount.com  # Workload identity
group: group@domain.com                      # Group of users
domain: domain.com                           # All users in domain
allUsers: (public)                           # DANGEROUS
allAuthenticatedUsers: (any Google account)  # Still DANGEROUS
```

**IAM Binding Structure:**
```yaml
# Role bindings connect principals to roles on resources
binding:
  role: roles/storage.objectViewer
  members:
    - serviceAccount:myapp@myproject.iam.gserviceaccount.com
  condition:  # Optional - add restrictions
    expression: resource.name.startsWith("projects/myproject/buckets/allowed-bucket")
```

### CSD1.3 GCP Logging and Detection

**Cloud Audit Logs Types:**
```yaml
log_types:
  admin_activity:    # Always on, free
    - Resource creation/deletion
    - IAM changes
    - Settings changes
    
  data_access:       # Must be enabled per service
    - Read operations
    - Data access
    
  system_event:      # Always on, free
    - GCP internal operations
    
  policy_denied:     # Always on
    - VPC Service Controls denials
    - Org Policy denials
```

**Log Query Example (Cloud Logging):**
```
# Find IAM changes
protoPayload.methodName="SetIamPolicy"

# Find who accessed a bucket
protoPayload.serviceName="storage.googleapis.com"
protoPayload.methodName=~"storage.objects.(get|list)"
resource.labels.bucket_name="my-sensitive-bucket"
```

### CSD1.4 GCP Security Best Practices

**Day-0 GCP Baseline:**
```yaml
organization_setup:
  - Set up Organization (not just standalone projects)
  - Enable Cloud Identity for user management
  - Configure Organization Policy constraints
  - Set up centralized logging (org-level sink)
  
identity:
  - Require 2FA for all users
  - Use groups for access (not individual bindings)
  - Prefer service accounts for workloads
  - Enable Workload Identity for GKE
  
logging:
  - Admin Activity logs -> central bucket/BigQuery
  - Enable Data Access logs for sensitive services
  - Set appropriate retention
  - Alert on log export changes
```

**Critical Org Policy Constraints:**
```yaml
# Deny public access to storage
constraints/storage.publicAccessPrevention: enforced

# Restrict where resources can be created
constraints/gcp.resourceLocations:
  allowedValues:
    - us-central1
    - europe-west1

# Require VPC for Cloud Functions/Run
constraints/cloudfunctions.requireVPCConnector: enforced
```


## CSD2) Cloud Incident Response Deep Dive

### CSD2.1 IR Playbook - Compromised IAM Credentials

**Scenario:** Access keys or credentials suspected stolen

**Immediate Actions (First 15 minutes):**
```yaml
step_1_contain:
  aws:
    - Disable the access key (don't delete - preserve evidence)
    - aws iam update-access-key --access-key-id AKIA... --status Inactive
    
  azure:
    - Revoke user sessions
    - Disable/reset service principal credentials
    - az ad sp credential reset --id sp-id
    
  gcp:
    - Disable service account key
    - gcloud iam service-accounts keys disable key-id
    
step_2_assess_scope:
  - What role/permissions did this identity have?
  - What resources could it access?
  - When was it potentially compromised?
```

**Investigation (Next 30 minutes):**
```yaml
log_queries:
  aws:
    - CloudTrail - filter by userIdentity.accessKeyId
    - Look for unusual regions, times, API calls
    
  azure:
    - Activity Log - filter by caller
    - Sign-in logs - look for anomalous locations
    
  gcp:
    - Cloud Audit Logs - filter by principalEmail
    - Look for data access, IAM changes, new resources
    
what_to_look_for:
  - API calls not normally made by this workload
  - Access from unexpected IP/region
  - Creation of new credentials (persistence)
  - Data access (exfiltration)
  - Resource creation (cryptomining)
```

**Recovery:**
```yaml
actions:
  - Generate new credentials (if legitimate workload)
  - Review and tighten permissions
  - Check for persistence:
    - New users/service accounts created?
    - New access keys created?
    - New role assignments?
  - Review data access:
    - What was read?
    - What was modified/deleted?
  - Update secrets that this identity had access to
```

### CSD2.2 IR Playbook - Public Data Exposure

**Scenario:** Data discovered to be publicly accessible

**Immediate Actions:**
```yaml
step_1_confirm_and_contain:
  - Verify the exposure (check ACLs/policies)
  - Remove public access immediately
  - Don't delete data yet (preserve evidence)
  
  aws_s3:
    aws s3api put-public-access-block --bucket BUCKET --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
      
  azure_storage:
    az storage account update -n ACCOUNT -g RG --allow-blob-public-access false
    
  gcp_storage:
    gsutil iam ch -d allUsers gs://BUCKET
    gsutil iam ch -d allAuthenticatedUsers gs://BUCKET
```

**Investigation:**
```yaml
questions_to_answer:
  - When did the exposure start? (log timeline)
  - How did it become public? (who changed settings)
  - What data was exposed? (data classification)
  - Was it accessed? (data access logs)
  - By whom? (IP addresses, user agents)
```

### CSD2.3 IR Playbook - Cryptomining Detection

**Indicators:**
```yaml
detection_signals:
  compute:
    - Unusual CPU utilization (sustained high)
    - New instances in unusual regions
    - GPU instances appearing
    - Instances with no known purpose
    
  billing:
    - Unexpected cost spikes
    - Compute costs in regions you don't use
    
  network:
    - Connections to mining pools
    - Unusual outbound traffic patterns
```

**Response:**
```yaml
immediate:
  - Isolate/stop suspicious instances
  - Preserve disk/memory for forensics
  - Identify how attacker got in
  
investigation:
  - Check for compromised credentials
  - Check for exposed keys/tokens in code
  - Review all recent IAM changes
  - Look for persistence mechanisms
  
prevention:
  - Budget alerts
  - Region restrictions
  - Instance type restrictions
  - Monitoring for unusual compute patterns
```


## CSD3) Multi-Cloud Security Patterns

### CSD3.1 Common Multi-Cloud Challenges

```yaml
challenges:
  identity:
    - Different IAM models
    - No native federation between clouds
    - Service accounts work differently
    
  logging:
    - Different log formats
    - Different retention defaults
    - Correlation across clouds is hard
    
  policy:
    - Different policy languages
    - Different enforcement points
    - Governance complexity increases
```

### CSD3.2 Universal Cloud Security Checklist (Extended)

```yaml
identity:
  - Single source of truth for human identities
  - MFA required for all admin access
  - Workloads use native identity (not long-lived keys)
  - Regular access reviews across all clouds
  - Privileged access is time-limited

logging:
  - All control-plane logs enabled
  - Logs centralized (or at least indexed together)
  - Retention meets compliance requirements
  - Logs protected from deletion
  - Alert on logging changes

network:
  - Default deny inbound
  - No admin ports open to internet
  - Private connectivity for sensitive data
  - Egress filtering for sensitive workloads
  - Cross-cloud connectivity secured

data:
  - Data classified by sensitivity
  - Encryption at rest (customer-managed keys for sensitive)
  - No public data stores without explicit approval
  - Backup/DR tested and protected

guardrails:
  - Preventive controls (deny public, require encryption)
  - Detective controls (CSPM, anomaly detection)
  - Corrective controls (auto-remediation where safe)

incident_response:
  - IR playbooks for each cloud
  - Contact info for cloud provider security
  - Forensic capabilities (disk/memory capture)
  - Tested recovery procedures
```


## CSD4) Kubernetes Security Deep Dive

### CSD4.1 K8s Attack Surface

```yaml
attack_vectors:
  control_plane:
    - API server exposure
    - etcd access
    - Kubelet API
    
  workload:
    - Container escapes
    - Pod-to-pod lateral movement
    - Service account token theft
    
  supply_chain:
    - Malicious images
    - Compromised base images
    - Vulnerable dependencies
    
  network:
    - Unrestricted pod communication
    - Exposed services
    - Ingress misconfigurations
```

### CSD4.2 K8s Security Controls

**Pod Security Standards:**
```yaml
# Restricted policy (most secure)
apiVersion: v1
kind: Namespace
metadata:
  name: secure-app
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/audit: restricted
```

**Network Policy Example:**
```yaml
# Deny all ingress by default
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
spec:
  podSelector: {}
  policyTypes:
  - Ingress
```

**Service Account Best Practices:**
```yaml
# Disable automount of service account token
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-app
automountServiceAccountToken: false

# In pod spec, explicitly mount only if needed
spec:
  serviceAccountName: my-app
  automountServiceAccountToken: false  # or true if actually needed
```

### CSD4.3 K8s Security Checklist

```yaml
cluster_hardening:
  - API server not exposed to internet
  - RBAC enabled and configured
  - etcd encrypted at rest
  - Audit logging enabled
  - Node OS hardened

workload_security:
  - Pod Security Standards enforced
  - No privileged containers
  - Read-only root filesystem
  - Resource limits set
  - Security contexts defined

network_security:
  - Network policies defined
  - Ingress controller hardened
  - mTLS between services (service mesh)
  - Egress filtering

supply_chain:
  - Image scanning in CI/CD
  - Signed images required
  - Private registry
  - Regular vulnerability patching
```


## CSD5) Container Security

### CSD5.1 Dockerfile Security

**Secure Dockerfile Example:**
```dockerfile
# Use specific version, not latest
FROM python:3.11-slim-bookworm

# Create non-root user
RUN groupadd -r appgroup && useradd -r -g appgroup appuser

# Set working directory
WORKDIR /app

# Copy and install dependencies first (better caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY --chown=appuser:appgroup . .

# Switch to non-root user
USER appuser

# Use ENTRYPOINT for the main command
ENTRYPOINT ["python", "app.py"]
```

**Container Security Checklist:**
```yaml
image_building:
  - Use minimal base images (alpine, distroless, slim)
  - Pin image versions (sha256 digest best)
  - Don't install unnecessary packages
  - Remove build tools after use
  - Scan for vulnerabilities before pushing

runtime:
  - Run as non-root
  - Drop all capabilities, add only needed
  - Read-only filesystem where possible
  - No privileged mode
  - Resource limits defined

secrets:
  - Never bake secrets into images
  - Use secret management (K8s secrets, Vault, cloud KMS)
  - Environment variables visible in process list - be careful
```

### CSD5.2 Container Runtime Security

```yaml
runtime_protections:
  seccomp:
    - Filter system calls
    - Default Docker profile blocks ~44 syscalls
    
  apparmor:
    - Mandatory access control
    - Restricts file/network/capability access
    
  selinux:
    - Label-based access control
    - Alternative to AppArmor
    
  capabilities:
    - Drop ALL, add only needed
    - Common needed: NET_BIND_SERVICE, SETUID, SETGID
```


ENHANCED END OF CLOUD SECURITY STUDY MATERIAL


---

## CSD6) AWS Attack Scenarios Deep Dive

### CSD6.1 Lambda/Serverless Security

**Attack Surface:**
```yaml
lambda_threats:
  code_injection:
    - Untrusted input in event data
    - Environment variable manipulation
    - Dependency vulnerabilities
    
  privilege_escalation:
    - Over-permissioned execution role
    - iam:PassRole abuse
    - Resource-based policy misconfig
    
  data_exposure:
    - /tmp persistence between invocations
    - Logging sensitive data
    - Return value exposure
    
  denial_of_service:
    - Reserved concurrency exhaustion
    - Timeout manipulation
    - Recursive invocation
```

**Secure Lambda Checklist:**
```yaml
code_security:
  - [ ] Input validation on all event sources
  - [ ] No secrets in environment variables (use Secrets Manager)
  - [ ] Dependencies scanned and minimal
  - [ ] No sensitive data in logs
  
iam_security:
  - [ ] Least privilege execution role
  - [ ] No wildcard permissions
  - [ ] Resource-based policies reviewed
  - [ ] No iam:PassRole unless required
  
runtime_security:
  - [ ] /tmp cleaned between invocations if sensitive
  - [ ] Timeouts set appropriately
  - [ ] Reserved concurrency configured
  - [ ] Dead letter queue for failures
```

### CSD6.2 S3 Attack Patterns

**Common S3 Misconfigurations:**
```yaml
public_access:
  bucket_acl_public:
    risk: "Anyone can list/read objects"
    detect: "aws s3api get-bucket-acl"
    fix: "Block public access at account level"
    
  bucket_policy_public:
    risk: "Policy allows Principal: *"
    detect: "aws s3api get-bucket-policy"
    fix: "Remove public principal, add conditions"
    
  object_acl_public:
    risk: "Individual objects world-readable"
    detect: "aws s3api get-object-acl"
    fix: "Bucket-level ACL enforcement"

data_exposure:
  versioning_disabled:
    risk: "No recovery from deletion/overwrite"
    detect: "aws s3api get-bucket-versioning"
    fix: "Enable versioning + MFA delete"
    
  no_encryption:
    risk: "Data at rest unencrypted"
    detect: "aws s3api get-bucket-encryption"
    fix: "SSE-S3 minimum, SSE-KMS for sensitive"
    
  logging_disabled:
    risk: "No visibility into access"
    detect: "aws s3api get-bucket-logging"
    fix: "Enable server access logging"
```

**S3 Privilege Escalation Paths:**
```yaml
attack_chains:
  bucket_takeover:
    - Find dangling S3 reference (CNAME, CloudFront)
    - Create bucket with same name
    - Serve malicious content
    
  policy_manipulation:
    - Attacker has s3:PutBucketPolicy
    - Add policy granting themselves access
    - Exfiltrate data
    
  presigned_url_abuse:
    - Leaked/stolen presigned URL
    - Access objects without credentials
    - May persist beyond credential rotation
```

### CSD6.3 IAM Privilege Escalation Techniques

**High-Risk IAM Permissions:**
```yaml
critical_permissions:
  # Direct escalation
  iam:CreateUser: "Create new identity"
  iam:CreateAccessKey: "Get persistent creds for any user"
  iam:AttachUserPolicy: "Grant any permissions"
  iam:PutUserPolicy: "Inline policy to grant permissions"
  iam:CreateLoginProfile: "Enable console access"
  iam:UpdateLoginProfile: "Reset password"
  
  # Indirect escalation
  iam:PassRole: "Assume permissions of passed role"
  sts:AssumeRole: "Become another role"
  lambda:CreateFunction: "Run code as Lambda role"
  lambda:UpdateFunctionCode: "Inject code into existing"
  ec2:RunInstances: "Launch with instance profile"
  cloudformation:CreateStack: "Deploy with service role"
  
  # Persistence
  iam:CreateRole: "Create backdoor role"
  iam:UpdateAssumeRolePolicy: "Add trust to existing role"
```

**Escalation Detection Queries (CloudTrail):**
```json
{
  "eventSource": "iam.amazonaws.com",
  "eventName": [
    "CreateUser",
    "CreateAccessKey", 
    "AttachUserPolicy",
    "PutUserPolicy",
    "CreateLoginProfile",
    "UpdateAssumeRolePolicy"
  ]
}
```


## CSD7) Azure Attack Scenarios

### CSD7.1 Azure AD/Entra ID Attacks

**Common Attack Vectors:**
```yaml
identity_attacks:
  password_spray:
    target: "Azure AD authentication endpoint"
    technique: "Common passwords across many accounts"
    detection: "Sign-in logs: many accounts, few passwords"
    defense: "Smart lockout, password protection"
    
  consent_phishing:
    target: "OAuth app consent flow"
    technique: "Trick user into granting app permissions"
    detection: "Audit logs: high-risk app consent"
    defense: "Admin consent required, app governance"
    
  token_theft:
    target: "Access/refresh tokens"
    technique: "Steal from browser, token cache"
    detection: "Sign-in anomalies, impossible travel"
    defense: "CAE, token binding, session policies"
    
  directory_enumeration:
    target: "Azure AD Graph/MS Graph"
    technique: "Enumerate users, groups, apps"
    detection: "Audit large read operations"
    defense: "Restrict user enumeration settings"
```

### CSD7.2 Azure Resource Attacks

**Storage Account Attacks:**
```yaml
blob_storage_misconfig:
  anonymous_access:
    - Container set to Blob or Container access
    - Storage account allows public access
    - Defense: Disable at account level
    
  shared_key_exposure:
    - Storage account keys leaked
    - Full access to all data
    - Defense: Disable shared key, use Azure AD
    
  sas_token_abuse:
    - Over-permissioned SAS tokens
    - Long-lived tokens
    - Defense: Stored access policies, short expiry
```

**Key Vault Attacks:**
```yaml
key_vault_risks:
  overly_permissive_access:
    - Too many users with Get secret
    - No access reviews
    - Defense: RBAC, just-in-time access
    
  soft_delete_disabled:
    - Secrets permanently deleted
    - No recovery possible
    - Defense: Enable soft-delete + purge protection
    
  no_monitoring:
    - Secret access not logged
    - Exfiltration undetected
    - Defense: Diagnostic settings, alerts
```


## CSD8) Detection Engineering for Cloud

### CSD8.1 CloudTrail Detection Rules

**High-Fidelity Detections:**
```yaml
# Rule 1: Root account usage
root_account_login:
  source: CloudTrail
  condition: |
    userIdentity.type = "Root" AND
    eventType = "AwsConsoleSignIn"
  severity: CRITICAL
  response: Immediate investigation

# Rule 2: IAM user created
new_iam_user:
  source: CloudTrail
  condition: |
    eventSource = "iam.amazonaws.com" AND
    eventName = "CreateUser"
  severity: HIGH
  response: Verify with change management

# Rule 3: Security group opened to internet
sg_opened_to_world:
  source: CloudTrail
  condition: |
    eventSource = "ec2.amazonaws.com" AND
    eventName IN ("AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress") AND
    requestParameters.cidrIp = "0.0.0.0/0"
  severity: HIGH
  response: Review and restrict

# Rule 4: S3 bucket made public
s3_public_access:
  source: CloudTrail
  condition: |
    eventSource = "s3.amazonaws.com" AND
    eventName IN ("PutBucketAcl", "PutBucketPolicy") AND
    (requestParameters contains "AllUsers" OR 
     requestParameters contains "AuthenticatedUsers")
  severity: CRITICAL
  response: Immediate remediation

# Rule 5: CloudTrail stopped
cloudtrail_stopped:
  source: CloudTrail
  condition: |
    eventSource = "cloudtrail.amazonaws.com" AND
    eventName IN ("StopLogging", "DeleteTrail")
  severity: CRITICAL
  response: Immediate investigation - possible attacker covering tracks
```

### CSD8.2 Azure Sentinel/KQL Detection Queries

**Identity Threats:**
```kql
// Brute force detection
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType != 0
| summarize FailedAttempts = count(), 
            DistinctUsers = dcount(UserPrincipalName)
  by IPAddress, bin(TimeGenerated, 5m)
| where FailedAttempts > 10

// Impossible travel
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == 0
| project UserPrincipalName, Location, TimeGenerated
| order by UserPrincipalName, TimeGenerated
| serialize
| extend PrevLocation = prev(Location), 
         PrevTime = prev(TimeGenerated),
         PrevUser = prev(UserPrincipalName)
| where UserPrincipalName == PrevUser
| extend TimeDiff = datetime_diff('minute', TimeGenerated, PrevTime)
| where Location != PrevLocation and TimeDiff < 60

// High-risk app consent
AuditLogs
| where OperationName == "Consent to application"
| where Result == "success"
| extend AppName = tostring(TargetResources[0].displayName)
| extend Permissions = tostring(TargetResources[0].modifiedProperties)
| where Permissions contains "ReadWrite" or Permissions contains "All"
```

**Resource Threats:**
```kql
// Storage account key access
AzureActivity
| where OperationNameValue == "MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION"
| project TimeGenerated, Caller, ResourceGroup, _ResourceId

// Key Vault secret access spike
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where OperationName == "SecretGet"
| summarize AccessCount = count() by CallerIPAddress, bin(TimeGenerated, 1h)
| where AccessCount > 100

// Public IP created
AzureActivity
| where OperationNameValue == "MICROSOFT.NETWORK/PUBLICIPADDRESSES/WRITE"
| where ActivityStatusValue == "Success"
```


## CSD9) Cloud Security Architecture Patterns

### CSD9.1 Zero Trust Network Architecture

```
                    ZERO TRUST CLOUD ARCHITECTURE
===========================================================================

                         +---------------------+
                         �   Identity Provider �
                         �   (Azure AD/Okta)   �
                         +---------------------+
                                    � Verify Identity
                                    ?
+-------------+    +-------------------------------------+
�   User      �---?�         Policy Engine              �
�   Device    �    �  - Check identity                   �
+-------------+    �  - Check device compliance          �
                   �  - Check location/context           �
                   �  - Determine access level           �
                   +-------------------------------------+
                                  �
              +-------------------+-------------------+
              ?                   ?                   ?
    +-----------------+ +-----------------+ +-----------------+
    �  Micro-segment  � �  Micro-segment  � �  Micro-segment  �
    �   (Web Tier)    � �   (App Tier)    � �   (Data Tier)   �
    �                 � �                 � �                 �
    � +-------------+ � � +-------------+ � � +-------------+ �
    � �  Workload   � � � �  Workload   � � � �  Database   � �
    � �  Identity   � � � �  Identity   � � � �  Identity   � �
    � +-------------+ � � +-------------+ � � +-------------+ �
    +-----------------+ +-----------------+ +-----------------+
           �                    �                    �
           +-----------------------------------------+
                               �
                    +---------------------+
                    �    Logging/SIEM     �
                    �  (Every request     �
                    �   logged & analyzed)�
                    +---------------------+

Key Principles:
1. Never trust, always verify
2. Assume breach
3. Verify explicitly
4. Least privilege access
5. Micro-segmentation
```

### CSD9.2 Landing Zone Security Pattern

```yaml
aws_landing_zone:
  management_account:
    - CloudTrail (org-wide)
    - AWS Config (org-wide)
    - SCPs for guardrails
    - Billing/cost management
    
  security_account:
    - Security Hub aggregation
    - GuardDuty delegated admin
    - Centralized logging
    - IR tooling
    
  log_archive_account:
    - Immutable log storage
    - Long-term retention
    - Cross-account access controls
    
  shared_services_account:
    - DNS (Route 53)
    - Directory services
    - Shared networking (Transit Gateway)
    
  workload_accounts:
    - Development
    - Staging
    - Production
    - (Separate accounts per workload)

azure_landing_zone:
  management_groups:
    root:
      - platform (connectivity, identity, management)
      - landing_zones (corp, online)
      - decommissioned
      - sandbox
      
  key_components:
    - Hub VNet for connectivity
    - Azure Firewall/NVA
    - Log Analytics workspace
    - Azure Policy assignments
    - Microsoft Defender for Cloud
```


FINAL END OF CLOUD SECURITY STUDY MATERIAL
