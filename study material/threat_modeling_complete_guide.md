# Threat Modeling — The Complete, Detailed Study Guide

> **Classification:** Study reference / educational.
> **Audience:** Engineers, security engineers, architects, and anyone preparing for security interviews or doing hands-on threat modeling of real systems.
> **Scope:** What threat modeling *is*, why it works, and every major methodology, technique, diagram, and tool — with worked examples end to end. Vendor-neutral; grounded in the industry-standard frameworks (STRIDE, PASTA, LINDDUN, attack trees, MITRE ATT&CK, OWASP).
> **Companion guides:** [web_security_attacks_complete_guide.md](web_security_attacks_complete_guide.md) and [mobile_security_attacks_complete_guide.md](mobile_security_attacks_complete_guide.md) enumerate the concrete threats you will be reasoning about; this guide is the *method* for finding, prioritising, and mitigating them systematically.

---

## How to read this guide

Threat modeling is not a document you produce once — it is a **structured way of thinking** you apply repeatedly. The whole discipline collapses to four questions (Shostack's framing):

1. **What are we working on?** (model the system)
2. **What can go wrong?** (find the threats)
3. **What are we going to do about it?** (decide mitigations)
4. **Did we do a good enough job?** (validate)

Everything else — STRIDE, DFDs, attack trees, risk scoring — is machinery that helps you answer those four questions well and repeatably. Read Part A for the vocabulary, Part B for the process, Part C for the methodologies (this is the bulk), Part D for diagramming, Part E for fully worked examples, Part F for fitting it into how software actually gets built, and Part G for tooling. Appendices give you a STRIDE-per-element chart, a one-page cheat sheet, and curated external links.

---

## The one idea that makes threat modeling work

Security bugs are cheapest to fix *before they are built*. A design flaw found on a whiteboard costs a conversation; the same flaw found in production costs an incident. Threat modeling is **anticipating how a system will be attacked while it is still a design**, so you can build the defences in rather than bolt them on. It is the only security activity that operates on the *design* rather than the artifact — which is why it catches an entire class of flaws (missing trust boundaries, confused-deputy designs, absent authorization) that no scanner, linter, or pen test reliably finds, because those tools test what you built, not what you *should* have built.

Two distinctions to hold onto from the start:

- **Flaw vs. bug.** A *bug* is an implementation mistake (an off-by-one, a missing escape). A *flaw* is a design mistake (the password reset token is emailed but never expires; the mobile client is trusted to enforce the price). Threat modeling is the primary defence against **flaws**. Roughly half of real security defects are design flaws, and they are exactly the half that code review and SAST miss.
- **Threat vs. vulnerability vs. risk.** A *threat* is something bad that *could* happen (an attacker forges a token). A *vulnerability* is a weakness that lets it happen (the token isn't signed). *Risk* is the threat weighted by likelihood and impact. You model threats to discover vulnerabilities so you can reduce risk.

---

## Table of contents

**Part A — Foundations**
1. [What threat modeling is (and is not)](#1-what-threat-modeling-is-and-is-not)
2. [Core vocabulary: asset, threat actor, attack surface, trust boundary, risk](#2-core-vocabulary)
3. [When and how often to threat model](#3-when-and-how-often-to-threat-model)
4. [Who is in the room](#4-who-is-in-the-room)

**Part B — The process (the four questions in practice)**
5. [Step 1 — Scope and set objectives](#5-step-1--scope-and-set-objectives)
6. [Step 2 — Model the system (decomposition & DFDs)](#6-step-2--model-the-system)
7. [Step 3 — Identify threats](#7-step-3--identify-threats)
8. [Step 4 — Rank and prioritise (risk)](#8-step-4--rank-and-prioritise)
9. [Step 5 — Decide mitigations (respond)](#9-step-5--decide-mitigations)
10. [Step 6 — Validate, document, and iterate](#10-step-6--validate-document-and-iterate)

**Part C — Methodologies (the toolbox)**
11. [STRIDE — the workhorse](#11-stride--the-workhorse)
12. [STRIDE-per-element and STRIDE-per-interaction](#12-stride-per-element-and-stride-per-interaction)
13. [Attack trees](#13-attack-trees)
14. [PASTA — risk-centric, business-driven](#14-pasta)
15. [LINDDUN — privacy threat modeling](#15-linddun--privacy-threat-modeling)
16. [DREAD and the problem of scoring](#16-dread-and-the-problem-of-scoring)
17. [CVSS for prioritisation](#17-cvss-for-prioritisation)
18. [MITRE ATT&CK, CAPEC, and kill chains](#18-mitre-attck-capec-and-kill-chains)
19. [VAST, Trike, OCTAVE, hTMM, and the rest](#19-vast-trike-octave-htmm-and-the-rest)
20. [Choosing a methodology](#20-choosing-a-methodology)

**Part D — Diagramming**
21. [Data flow diagrams (DFDs) in depth](#21-data-flow-diagrams-in-depth)
22. [Trust boundaries — the most important lines you draw](#22-trust-boundaries)
23. [Sequence diagrams and other views](#23-sequence-diagrams-and-other-views)

**Part E — Worked examples**
24. [Worked example 1 — a web application](#24-worked-example-1--a-web-application)
25. [Worked example 2 — a cloud / microservices system](#25-worked-example-2--a-cloud--microservices-system)
26. [Worked example 3 — a mobile app + API](#26-worked-example-3--a-mobile-app--api)

**Part F — Threat modeling in the real world**
27. [Threat modeling in the SDLC / DevSecOps](#27-threat-modeling-in-the-sdlc--devsecops)
28. [Threat modeling in Agile & at scale](#28-threat-modeling-in-agile--at-scale)
29. [Threat modeling as code](#29-threat-modeling-as-code)
30. [Common pitfalls and anti-patterns](#30-common-pitfalls-and-anti-patterns)

**Part G — Tooling**
31. [Tools and threat libraries](#31-tools-and-threat-libraries)

**Appendices**
- [Appendix A — STRIDE-per-element quick chart](#appendix-a--stride-per-element-quick-chart)
- [Appendix B — Threat modeling cheat sheet](#appendix-b--threat-modeling-cheat-sheet)
- [Appendix C — Further reading & external resources](#appendix-c--further-reading--external-resources)

---

# Part A — Foundations

## 1. What threat modeling is (and is not)

**Threat modeling is a structured, repeatable process for analysing the security of a system by identifying what could go wrong and deciding what to do about it — ideally during design, and revisited as the system evolves.** It is fundamentally an act of *structured imagination*: you deliberately adopt the attacker's perspective against your own design and enumerate the ways it can be abused, before an actual attacker does it for you.

**What it is:**
- A **design-time** activity (though valuable at any stage). It reasons about architecture, data flows, and trust — not lines of code.
- A **collaborative** activity. Its biggest value is often the shared understanding it forces across developers, architects, and security.
- A **living** activity. A model is a snapshot; systems change, so models must be revisited.
- **Methodical.** The point of a methodology (STRIDE et al.) is to make threat discovery *systematic* rather than dependent on the cleverness of whoever is in the room that day.

**What it is not:**
- **Not a pen test.** Pen testing attacks the *built* system to confirm exploitable vulnerabilities; threat modeling analyses the *design* to prevent them. They are complementary — a threat model tells the pen tester where to look.
- **Not a vulnerability scan or SAST/DAST.** Automated tools find known *implementation* bug patterns; threat modeling finds *design* flaws that tools cannot reason about.
- **Not a one-time compliance checkbox.** A model produced once and filed away rots as the system changes.
- **Not only for "high-security" systems.** Any system with a trust boundary and something worth protecting benefits.

**Why it pays off:** finding and fixing a flaw at design time is dramatically cheaper than after release; it produces a prioritised, rationalised set of security requirements; it builds a shared mental model of the system's security posture; and it creates documentation auditors and new team members can use.

## 2. Core vocabulary

Precise terms prevent muddled models. Learn these cold.

| Term | Definition | Example |
|---|---|---|
| **Asset** | Something of value worth protecting. | User PII, session tokens, funds, availability, reputation, a signing key. |
| **Threat** | A potential undesirable event that could harm an asset. | "An attacker reads another user's messages." |
| **Threat actor / agent** | Who might carry out a threat, and their capability & motivation. | Script kiddie, organised crime, insider, nation-state, an automated bot. |
| **Vulnerability / weakness** | A flaw or gap that a threat can exploit. | Missing authorization check; unsigned token; no rate limit. |
| **Attack / attack vector** | The path/technique used to realise a threat. | IDOR via an incrementing `id` parameter. |
| **Attack surface** | The sum of all points where an attacker can interact with the system. | Every endpoint, input, port, file parser, dependency, admin console. |
| **Trust boundary** | A line where the level of trust changes; data crossing it must be validated/authorised. | Internet ↔ web server; app ↔ database; user process ↔ kernel. |
| **Entry / exit point** | Where data enters or leaves the system, especially across a trust boundary. | An HTTP endpoint, a message queue consumer, a file upload. |
| **Control / mitigation / countermeasure** | A measure that reduces the likelihood or impact of a threat. | Input validation, MFA, output encoding, least privilege, encryption. |
| **Risk** | Threat weighted by likelihood × impact; what you actually prioritise. | "High: unauthenticated RCE on the payment service." |
| **Residual risk** | The risk that remains after mitigations are applied. | "Low: DoS still possible but rate-limited and monitored." |
| **Threat actor capability** | The resources/skill a given actor can bring. | A nation-state can burn a 0-day; a bot cannot. |
| **Attack tree / kill chain** | Structured representations of how a goal is achieved through steps. | See §13, §18. |

Two relationships to internalise:

- **Risk = f(likelihood, impact).** You cannot fix everything, so you rank by risk and spend effort where it counts. Most of Part B step 4 is about estimating this honestly.
- **Trust boundaries generate threats.** The highest-value threats almost always live where data crosses a trust boundary — that is where an attacker's input meets your trust. If you get only one thing right in a model, get the trust boundaries right.

## 3. When and how often to threat model

**The best time is early — during design, before code exists** — because that is when changing the architecture is cheap. But "shift left" does not mean "do it once."

- **New feature / new system:** during design, as a gate before build.
- **Significant architectural change:** a new trust boundary, a new data store, a new third-party integration, a new authentication mechanism, exposure of a previously internal service.
- **New class of data:** you start handling payments, health data, or credentials.
- **Periodically:** revisit critical systems on a cadence (e.g. annually) even absent changes, because the *threat landscape* changes (new attacker techniques, new dependencies with new CVEs).
- **After an incident:** incorporate what you learned; the model missed something, so improve it.
- **In the pipeline:** lightweight, continuous threat modeling on each meaningful change (see Part F).

A useful maturity progression: from *"we threat model big projects once"* → *"every project threat models at design"* → *"threat modeling is continuous and partly automated in the pipeline."*

## 4. Who is in the room

Threat modeling is a team sport; the model is only as good as the perspectives feeding it.

- **The system's engineers/architects** — they know how it actually works (essential; a model built without them is fiction).
- **A security specialist / champion** — brings the attacker mindset and knowledge of threat taxonomies. In mature orgs this is a facilitator, not the sole author.
- **Product owner / business stakeholder** — knows what the *assets* really are and what impact matters to the business (crucial for risk ranking and for PASTA, §14).
- **QA / ops / SRE** — know failure modes, deployment topology, and monitoring reality.

**Roles in the session:** a **facilitator** (drives the process, keeps it on the four questions), a **scribe** (captures the diagram and threats), and **contributors** (everyone). Keep groups small enough to be productive (often 3–6). The cultural goal is a **blameless, curious** atmosphere: "how could this be abused?" is a design question, not an accusation. Democratising threat modeling — teaching every engineer to do a lightweight version — scales far better than a central team modeling everything.

---

# Part B — The Process (the four questions in practice)

Every methodology is a variation on the same loop. This part is the vendor-neutral spine; Part C swaps different engines into steps 2–3.

## 5. Step 1 — Scope and set objectives

*Answering the pre-question: "what are we protecting, and why?"*

Before diagramming anything, decide **what system, what boundaries, and what you care about.** An unscoped threat model either boils the ocean or misses the point.

- **Define the scope.** One service? A whole product? A single new feature? Draw the box. Everything inside is what you'll decompose; everything outside is context (but note the interfaces to it).
- **Identify the assets.** What is worth attacking here? Data (PII, secrets, financial), functionality (money movement, admin actions), and qualities (availability, integrity, reputation, compliance). Assets anchor your risk ranking later.
- **Identify the security objectives.** Often framed as **CIA** (Confidentiality, Integrity, Availability) plus **authentication, authorization, non-repudiation, and privacy**. What must be true for this system to be "secure enough"? Include compliance drivers (PCI-DSS, HIPAA, GDPR) as objectives.
- **Characterise the threat actors** you care about (§2). Modeling against a nation-state and against a script kiddie yields different priorities. Be explicit about which you're defending against — you rarely defend equally against all.
- **Set the depth.** A quick 1-hour model of a small feature and a multi-day model of a payment platform are both valid; agree the investment up front.

**Output of this step:** a one-paragraph scope statement, an asset list, security objectives, and the in-scope threat actors.

## 6. Step 2 — Model the system

*Answering question 1: "What are we working on?"*

You cannot find threats in a system you cannot see. **Decompose the system into its elements and draw how data flows between them, marking where trust changes.** The dominant tool is the **Data Flow Diagram (DFD)** (covered in depth in §21), but sequence diagrams, architecture diagrams, and even a whiteboard sketch all work — the point is a *shared, explicit model.*

Identify and enumerate:

- **External entities** — users, third-party services, other systems that interact but are outside your control.
- **Processes** — your code that transforms data (services, functions, apps).
- **Data stores** — databases, caches, file systems, queues, secrets stores.
- **Data flows** — the arrows: what data moves where, over what protocol.
- **Trust boundaries** — the lines where trust changes (§22). *Draw these explicitly;* they are where most threats live.

Also inventory the **entry and exit points** (every place data crosses a boundary), the **assets** located on the diagram (so you can see what each flow touches), and the **technologies** in play (they carry technology-specific threats — a SQL database implies SQLi; a deserialization library implies deserialization attacks).

**A good model is at the right altitude:** detailed enough that trust boundaries and data flows are visible, abstract enough to fit on one page and be reasoned about. If your diagram needs a magnifying glass, split it.

## 7. Step 3 — Identify threats

*Answering question 2: "What can go wrong?"*

This is the heart of the exercise. You systematically walk the model and enumerate threats. **Do it methodically, not by free association** — that's what the methodologies in Part C are for. The dominant approaches:

- **Mnemonic-driven (STRIDE, §11):** for each element/interaction, ask "could there be Spoofing? Tampering? Repudiation? Information disclosure? Denial of service? Elevation of privilege?" This is the most common and most teachable approach.
- **Attacker-goal-driven (attack trees, §13; kill chains, §18):** start from what an attacker wants ("steal funds") and decompose the ways to achieve it.
- **Checklist/library-driven (CAPEC, ATT&CK, OWASP Top 10s):** walk a catalogue of known attack patterns against your system.
- **Privacy-driven (LINDDUN, §15):** the STRIDE equivalent for privacy harms.

Regardless of engine, techniques that boost coverage:

- **Focus on trust boundaries first** — the highest-yield threats cross them.
- **Follow the data** — trace each sensitive data flow end to end and ask what an attacker at each hop could do.
- **"What could go wrong" per element** — go component by component so nothing is skipped.
- **Think in terms of the attacker's capabilities and goals**, not just abstract categories.
- **Capture every plausible threat now; filter later.** Don't self-censor during discovery — quantity, then quality. Record each as: *threat description, the element/flow it targets, the STRIDE (or other) category, and a plausible attack scenario.*

**Output:** a list of concrete, described threats, each tied to a part of the model.

## 8. Step 4 — Rank and prioritise

*Beginning to answer question 3: "What are we going to do about it?"*

You will always find more threats than you can fix at once. **Rank by risk so you spend effort where it matters.** Risk ≈ **likelihood × impact**.

- **Impact:** how bad if it happens? (Data breach of all users vs. one user; full account takeover vs. a cosmetic bug; regulatory exposure; financial loss; safety.)
- **Likelihood:** how easy/probable? (Attacker skill required, whether it's remotely reachable and unauthenticated, whether exploit tooling exists, how exposed the surface is.)

Scoring approaches (detailed in Part C):
- **Qualitative High/Medium/Low** — fast, good enough for most sessions; plot on a simple risk matrix.
- **DREAD (§16)** — a numeric model; widely taught but criticised for subjectivity.
- **CVSS (§17)** — standardised scoring, better for concrete vulnerabilities than for design threats.
- **Business-impact-driven (PASTA, §14)** — ties each threat to quantified business risk.

Beware two biases: **over-weighting exotic threats** (the clever nation-state attack) while **under-weighting the boring, likely ones** (no rate limit, missing authz), and **anchoring on impact alone** without considering likelihood. Prioritise the high-likelihood-high-impact quadrant first.

**Output:** threats sorted into a priority order (e.g. a ranked list or a risk matrix), with a rationale for each rating.

## 9. Step 5 — Decide mitigations (respond)

*Completing question 3.*

For each prioritised threat, choose a response. The four classic options:

1. **Mitigate** — add a control that reduces likelihood or impact (the usual choice). Map the threat to a concrete countermeasure: authentication/MFA for spoofing, integrity checks/signing for tampering, logging for repudiation, encryption/access control for disclosure, rate limiting/quotas for DoS, least privilege/authorization for elevation. OWASP Cheat Sheets and the ASVS are excellent sources of *specific* controls.
2. **Eliminate** — remove the feature or the risky design entirely (the strongest fix; no feature, no threat). E.g. don't store the data you don't need.
3. **Transfer** — shift the risk to someone better placed to handle it (use a managed identity provider instead of rolling your own auth; insurance; a payment processor that owns card data).
4. **Accept** — consciously accept the residual risk when the cost of mitigation outweighs it. This must be a *documented, owned decision*, not an oversight — record who accepted it and why.

Turn mitigations into **security requirements / actionable tickets** with owners and priorities, so the model produces engineering work rather than a shelf document. Prefer **mitigations by design** (make the whole class of bug impossible — e.g. an ORM with parameterised queries kills SQLi structurally) over spot fixes. Then consider **defence in depth**: layer controls so one failure isn't catastrophic.

**Output:** a decision (mitigate/eliminate/transfer/accept) and, where mitigating, a concrete control + ticket for each prioritised threat.

## 10. Step 6 — Validate, document, and iterate

*Answering question 4: "Did we do a good enough job?"*

- **Validate the model:** does the diagram match reality? Did we cover every element and every trust boundary? Did we consider all STRIDE categories per element? Were the assumptions correct? A quick review against the model catches gaps.
- **Validate the mitigations:** are the chosen controls actually sufficient and implementable? Later, confirm they were *actually built* (a mitigation on paper is not a mitigation) — this is where pen testing and security test cases close the loop, verifying the threat model's assumptions against the real system.
- **Document** the model, the threats, the decisions, and the residual/accepted risks. This artifact feeds audits, onboarding, pen-test scoping, and the *next* iteration.
- **Iterate.** The model is a living document. Revisit it on the triggers in §3. Feed incidents and pen-test findings back in ("our model didn't predict this — why, and what do we change?").

A healthy threat model ends with: an updated diagram, a threat register with dispositions, a set of security requirements/tickets, and a list of explicitly accepted residual risks.

---

# Part C — Methodologies (the toolbox)

There is no single "correct" methodology. They differ in *what they start from* (system, attacker, asset, or business risk), how heavyweight they are, and what they optimise for. This part explains each in enough depth to actually use it, then §20 helps you choose.

## 11. STRIDE — the workhorse

**STRIDE is the most widely used threat-identification framework.** Developed at Microsoft (Loren Kohnfelder and Praerit Garg, 1999) and popularised by Adam Shostack, it is a **mnemonic of six threat categories**. You walk your model and, for each element, ask "is this element vulnerable to each of these six?" Its power is that each category is the **violation of a specific security property**, so STRIDE is really a checklist of the properties you want to hold.

| Threat | Violates (desired property) | Definition | Canonical examples | Typical mitigations |
|---|---|---|---|---|
| **S — Spoofing** | Authentication | Pretending to be someone/something you are not. | Stolen credentials, forged tokens, IP/email spoofing, phishing, a fake service impersonating a real one. | Strong authentication, MFA, signed/verified tokens, mutual TLS, session management. |
| **T — Tampering** | Integrity | Unauthorised modification of data or code. | Modifying data in transit or at rest, altering a request parameter, poisoning a cache, changing a binary. | Integrity checks (HMAC/signatures), TLS, input validation, access controls, code signing, WORM/audit logs. |
| **R — Repudiation** | Non-repudiation | Denying having performed an action, with no proof otherwise. | A user denies making a transaction; an attacker covers tracks because there are no logs. | Secure, tamper-evident audit logging; timestamps; digital signatures; log integrity protection. |
| **I — Information disclosure** | Confidentiality | Exposing information to those not authorised to see it. | Data breach, verbose errors leaking internals, unencrypted traffic, IDOR reading others' data, metadata leaks. | Encryption in transit & at rest, access controls, least privilege, careful error handling, data minimisation. |
| **D — Denial of service** | Availability | Making a system unavailable or degraded. | Resource exhaustion, flooding, algorithmic complexity attacks, filling a disk, locking accounts. | Rate limiting, quotas, input size limits, autoscaling, load balancing, timeouts, CDNs/DDoS protection. |
| **E — Elevation of privilege** | Authorization | Gaining capabilities you should not have. | Vertical (user→admin) or horizontal (user→other user) privilege escalation, sandbox escape, RCE, IDOR performing others' actions. | Authorization checks on every action, least privilege, deny-by-default, input validation, sandboxing, patching. |

### How to apply STRIDE

1. Build the DFD with trust boundaries (§6, §21).
2. For each **element** (or each **interaction** — see §12), go through S-T-R-I-D-E and ask "does this apply here? how?" Record every plausible threat.
3. Note that **elements have characteristic threats** (this is the basis of STRIDE-per-element, §12): external entities can *spoof* and *repudiate*; processes are subject to all six; data stores are especially subject to *tampering, information disclosure, DoS,* and *repudiation* (they hold the logs); data flows are subject to *tampering, information disclosure, and DoS.*

### STRIDE worked micro-example — a login endpoint

- **S:** Can an attacker submit someone else's credentials (credential stuffing)? Forge a session token? → MFA, rate limiting, signed tokens.
- **T:** Can the request be tampered in transit? Can the "remember me" cookie be modified? → TLS, signed/`HttpOnly` cookies.
- **R:** If an account is compromised, can we prove what happened? → auth audit logs.
- **I:** Does a failed login reveal whether the *username* exists (user enumeration)? Do errors leak stack traces? → uniform error messages.
- **D:** Can an attacker lock out users by triggering account lockout, or exhaust the auth service? → careful lockout design, rate limiting.
- **E:** After login, is authorization enforced, or can a normal user reach admin functions? → server-side authz on every action.

### Strengths & limits

- **Strengths:** systematic, teachable, comprehensive across the classic categories, tool-supported (Microsoft Threat Modeling Tool, OWASP Threat Dragon), and it maps cleanly to controls.
- **Limits:** it is **developer/system-centric**, not business-risk-centric; it can produce a *lot* of threats (needs good prioritisation, §8); it is weak on **privacy** (use LINDDUN, §15) and doesn't inherently rank by business impact (use PASTA, §14, or add DREAD/CVSS). It can also over-focus on the six categories and miss threats that don't fit neatly.

## 12. STRIDE-per-element and STRIDE-per-interaction

STRIDE comes in two application styles:

- **STRIDE-per-element:** for each *element type* you only consider the threats that typically apply to it, using a lookup chart (Appendix A). An external entity → consider S, R. A data store → consider T, I, D, R. A process → consider all six. A data flow → T, I, D. This makes the exercise tractable and is how the Microsoft tool guides you. **Best for coverage and teachability.**
- **STRIDE-per-interaction:** you consider threats against each *interaction* (a tuple of source, destination, and the flow between them, crossing a boundary) rather than each element in isolation. This better captures threats that only exist in the *relationship* between components (e.g. spoofing arises specifically at the point where A trusts B). **Fewer, more relevant threats, but slightly more abstract.**

Both are valid; per-element is the common teaching default. See Appendix A for the mapping chart.

## 13. Attack trees

**Attack trees** (popularised by Bruce Schneier) model threats from the **attacker's goal downward**. The *root* is the attacker's objective; *child nodes* are the sub-goals or methods to achieve the parent; leaves are concrete attacks. Nodes are combined with **AND** (all children required) and **OR** (any child suffices).

```
GOAL: Steal money from a user's account
├── OR ── Compromise the user's credentials
│        ├── OR ── Phish the user
│        ├── OR ── Credential-stuff from a breach dump
│        └── AND ─ Bypass MFA
│                  ├── SIM-swap to intercept SMS OTP
│                  └── (requires) obtain the user's phone number
├── OR ── Hijack an authenticated session
│        ├── Steal a session cookie via XSS
│        └── Session fixation
└── OR ── Abuse a server-side flaw
         ├── IDOR to move funds from another account
         └── Business-logic flaw in the transfer API
```

You can annotate leaves with attributes — **cost, skill required, probability, detectability** — and propagate them up the tree (an OR node takes the *cheapest/easiest* child; an AND node takes the *sum/hardest*) to find the **path of least resistance**, which is where you should focus defences.

- **Strengths:** excellent for reasoning about a *specific critical asset or goal* in depth; makes AND/OR logic and the cheapest attack path explicit; great for communicating risk to non-specialists; complements STRIDE (use STRIDE to enumerate breadth, attack trees to go deep on the scariest goals).
- **Limits:** doesn't by itself enumerate *all* goals (you must know what to build a tree for); can become large; more effort per tree.

**Attack–defense trees** extend the idea by adding defender nodes (countermeasures) interleaved with attacker nodes, letting you model the attacker/defender interplay.

## 14. PASTA

**PASTA — Process for Attack Simulation and Threat Analysis** — is a **risk-centric, business-driven** methodology (Tony UcedaVélez and Marco Morana). Where STRIDE starts from the system, PASTA starts from **business objectives** and works toward attacker simulation, producing threats prioritised by *business impact*. It is heavyweight and thorough — well suited to high-stakes systems and organisations that need to tie security to business risk. It has **seven stages**:

1. **Define objectives** — business objectives, security & compliance requirements, and a preliminary business-impact analysis. (What matters to the business?)
2. **Define the technical scope** — enumerate the architecture, infrastructure, dependencies, and the attack surface. (What are we actually running?)
3. **Application decomposition** — DFDs, trust boundaries, data flows, entry points, assets; map how the app works and where trust changes.
4. **Threat analysis** — analyse the threat landscape and threat intelligence relevant to this system; what are real attackers doing against systems like this?
5. **Vulnerability & weakness analysis** — correlate known vulnerabilities/weaknesses (CVE, CWE) with the assets and flows; where are we actually weak?
6. **Attack modeling** — simulate attacks (attack trees, ATT&CK, abuse cases) to see how a threat actor would chain weaknesses to reach objectives.
7. **Risk & impact analysis** — quantify residual risk, prioritise, and recommend countermeasures tied back to the business objectives from stage 1.

- **Strengths:** aligns security with business risk; evidence-based (uses real threat intel and vuln data); thorough; output speaks to executives. Integrates other techniques (DFDs, attack trees, ATT&CK) inside its stages.
- **Limits:** **resource-intensive** and requires cross-functional buy-in and expertise; overkill for a small feature. Best reserved for critical systems or as an org-level program.

## 15. LINDDUN — privacy threat modeling

STRIDE targets *security*; **LINDDUN** is the equivalent systematic framework for **privacy** threats (from KU Leuven). Increasingly essential given GDPR/CCPA and privacy-by-design mandates. Its seven categories:

| Category | Meaning | Example |
|---|---|---|
| **L — Linking** | Associating data items or actions to learn more than intended. | Correlating two "anonymous" datasets to re-identify a person. |
| **I — Identifying** | Learning the identity of a person from data. | De-anonymising a user from supposedly anonymous logs. |
| **N — Non-repudiation** | The *inability to deny* — a privacy harm (the mirror image of security's desire for it). | A whistleblower cannot plausibly deny an action; forced accountability. |
| **D — Detecting** | Inferring something from the mere observability of data/communication. | Learning a user has an account because a "reset password" reveals it (§ user enumeration). |
| **D — Data disclosure** | Excessive collection, processing, storage, or sharing of personal data. | Collecting more PII than needed; leaking it to third parties/SDKs. |
| **U — Unawareness / Unintervenability** | Users unaware of, or unable to control, processing of their data. | No consent, no access/deletion, dark patterns. |
| **N — Non-compliance** | Failing to meet privacy laws, policies, or standards. | Violating GDPR data-subject rights or retention limits. |

You apply LINDDUN much like STRIDE — map data flows (with special attention to *personal* data), walk each element/flow against the seven categories, then choose **privacy-enhancing** mitigations (data minimisation, anonymisation/pseudonymisation, consent, encryption, transparency, user controls). LINDDUN ships variants (**LINDDUN GO**, a lightweight card-deck version; and a full methodology) and a catalogue of privacy threat trees. **Use LINDDUN alongside STRIDE** whenever personal data is involved — security and privacy threat models are complementary, not substitutes.

## 16. DREAD and the problem of scoring

**DREAD** is a *risk-rating* model (not a threat-discovery one) — you use it in step 4 to score threats you already found. Rate each threat 1–10 (or 1–3) on five factors and combine:

| Factor | Question |
|---|---|
| **D — Damage** | How bad is the impact if exploited? |
| **R — Reproducibility** | How reliably can it be reproduced? |
| **E — Exploitability** | How much effort/skill to exploit? |
| **A — Affected users** | How many users/how much of the system is affected? |
| **D — Discoverability** | How easy is it to discover the flaw? |

Score = sum (or average) of the five; rank threats by score.

**The problem:** DREAD is **notoriously subjective** — two analysts routinely produce very different scores for the same threat, and the numbers imply a false precision. Microsoft itself deprecated DREAD internally. **Discoverability** is especially problematic (assuming a flaw is safe because it's hard to find is "security through obscurity"; many teams drop the factor or always rate it maximum). It survives because it's simple and quick. If you use it, **calibrate** with agreed definitions for each score, and treat the output as a rough sort, not a truth. For many teams, a plain **High/Medium/Low likelihood × impact matrix** is just as useful and less falsely precise.

## 17. CVSS for prioritisation

The **Common Vulnerability Scoring System (CVSS)** is the industry standard for scoring the severity of *concrete vulnerabilities* (0.0–10.0, from metrics like attack vector, complexity, privileges required, user interaction, and CIA impact). It's what NVD uses for CVEs.

- **When it fits threat modeling:** once a threat corresponds to a specific, concrete vulnerability, CVSS gives a standardised, defensible severity that everyone recognises and that maps to SLAs ("fix all Critical within X days").
- **When it doesn't:** CVSS scores *vulnerabilities*, not abstract design *threats*, and it deliberately ignores *your* business context (a Medium CVSS on your crown-jewel service may be your top priority). Use **environmental metrics** to adjust for context, and don't let a raw base score override business judgement.
- **Practical stance:** use qualitative H/M/L or PASTA-style business risk during design-time threat modeling; use CVSS to prioritise the concrete vulnerabilities that show up later (from scans, pen tests, dependency CVEs). They operate at different stages.

## 18. MITRE ATT&CK, CAPEC, and kill chains

These are **knowledge bases and models of real-world attacker behaviour** — invaluable inputs to "what can go wrong?" because they're grounded in how attacks actually happen.

- **MITRE ATT&CK** — a curated matrix of adversary **Tactics** (the *why*: Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Exfiltration, Impact, etc.) and **Techniques** (the *how*, e.g. T1566 Phishing, T1078 Valid Accounts). Use it to (a) sanity-check your model against real TTPs, (b) map threats to detections, and (c) think about the *chain* an attacker follows post-compromise, not just the initial bug. There are matrices for Enterprise, Mobile, ICS, and Cloud.
- **CAPEC (Common Attack Pattern Enumeration and Classification)** — a catalogue of **attack patterns** (e.g. "SQL Injection", "Session Fixation") linked to the **CWE** weaknesses they exploit. Excellent as a *checklist/library* for the threat-identification step: walk relevant CAPEC patterns against your components. CAPEC ↔ CWE ↔ CVE form a chain from *attack pattern* → *weakness type* → *specific vulnerability*.
- **Cyber Kill Chain (Lockheed Martin)** — a linear model of an intrusion's phases: Reconnaissance → Weaponization → Delivery → Exploitation → Installation → Command & Control → Actions on Objectives. Useful for reasoning about *defence in depth* — you can break the chain at any stage — and for structuring detection/response thinking. (ATT&CK is the more granular, modern successor for most purposes.)

**How they fit:** STRIDE/attack trees help you *generate* threats from your design; ATT&CK/CAPEC help you *validate coverage* against known real-world techniques and think about attacker chains and detection. Use both.

## 19. VAST, Trike, OCTAVE, hTMM, and the rest

A tour of the other named methodologies you'll encounter:

- **VAST (Visual, Agile, and Simple Threat modeling)** — designed to **scale across an enterprise** and integrate with Agile/DevOps. It distinguishes **application threat models** (technical, for dev teams, often via process-flow diagrams) from **operational threat models** (infrastructure, for ops/security), and emphasises automation and consistency across hundreds of models. It's the methodology behind the ThreatModeler tool. Best when you need threat modeling as a *repeatable, automatable program* rather than a boutique exercise.
- **Trike** — a **risk-management-focused, requirements-based** methodology built around a **requirements model** and **actor-asset-action matrices** (who is allowed to do what to which asset), from which it derives threats (primarily *elevation of privilege* and *denial of service* against the intended permissions). Strong on ensuring the system does *only* what's intended; has open tooling but a smaller community.
- **OCTAVE (Operationally Critical Threat, Asset, and Vulnerability Evaluation)** — a **CERT/SEI, organisation-level, risk-based** methodology focused on *operational* and *organisational* risk rather than a single application's technical design. Heavyweight; suited to enterprise risk assessment and building an internal risk-management practice. Variants: OCTAVE-S (small orgs), OCTAVE Allegro (streamlined, information-asset-focused).
- **hTMM (hybrid Threat Modeling Method)** — a **CERT/SEI** method combining **SQUARE** (security requirements engineering), **Security Cards** (a brainstorming card deck to broaden thinking about attackers and impacts), and **PnG (Persona non Grata** — modeling specific attacker archetypes). It aims for *few false positives, few overlooked threats,* and consistent results, by blending structured requirements with creative attacker brainstorming.
- **Security Cards** — a University of Washington **card deck** used to spark broad, creative threat brainstorming along dimensions of *human impact, adversary motivations, adversary resources, and adversary methods.* Good for teams new to threat modeling or to escape the tunnel vision of a pure checklist.
- **Persona non Grata (PnG)** — modeling threats by building out **attacker personas** (their motivations, skills, and goals) and reasoning about what each would target. Complements structured methods by grounding them in *who* is attacking and *why*.
- **NIST guidance** — **NIST SP 800-154** ("Guide to Data-Centric System Threat Modeling") frames threat modeling around *protecting specific data*, and NIST's SSDF (SP 800-218) and RMF reference threat modeling as an SDLC practice. Useful when you need to align with a compliance/standards vocabulary.

## 20. Choosing a methodology

There is no universal winner; pick based on your goal, scale, and maturity. A practical decision guide:

| If you want… | Use… |
|---|---|
| A teachable default for per-system technical threats | **STRIDE** (+ STRIDE-per-element) |
| Deep analysis of a specific critical goal/asset | **Attack trees** |
| Business-risk-driven, evidence-based, executive-facing | **PASTA** |
| Privacy threats (personal data involved) | **LINDDUN** (alongside STRIDE) |
| To scale threat modeling across many teams/Agile | **VAST** (and "threat modeling as code", §29) |
| Requirements/permission-correctness focus | **Trike** |
| Organisational/operational risk, not one app | **OCTAVE** |
| Structured + creative, few misses | **hTMM** (SQUARE + Security Cards + PnG) |
| To validate coverage vs. real attacker behaviour | **MITRE ATT&CK / CAPEC** (as a cross-check on any of the above) |
| To score/prioritise what you found | **H/M/L matrix** (default), **CVSS** (concrete vulns), **DREAD** (with caution) |

**In practice, teams combine them:** STRIDE to enumerate threats on a DFD, attack trees to go deep on the scariest ones, LINDDUN for privacy, ATT&CK/CAPEC to check coverage, and a simple risk matrix to prioritise — all inside a PASTA- or VAST-shaped program if you need scale and business alignment. **The methodology matters far less than actually doing it, doing it early, and iterating.** A "good enough" model consistently applied beats a perfect methodology applied once.

---

# Part D — Diagramming

You cannot threat model what you cannot see. The diagram is the shared model everyone reasons over. This part covers the notations that matter most.

## 21. Data flow diagrams (DFDs) in depth

The **DFD** is the canonical threat-modeling diagram because it shows exactly what threat modeling cares about: **where data goes and where trust changes.** It uses a small, standard vocabulary:

| Symbol | Element | Meaning |
|---|---|---|
| **Rectangle / square** | **External entity** | An actor or system outside your control (user, third-party API, browser). |
| **Circle (or rounded rect)** | **Process** | Your code that acts on data (a service, function, app). A "complex process" (double circle) expands into its own sub-DFD. |
| **Two parallel lines (or open rectangle)** | **Data store** | Where data rests (DB, cache, file, queue, S3 bucket, secrets manager). |
| **Arrow** | **Data flow** | Data moving between elements; label it with *what* data and *what* protocol. |
| **Dashed line** | **Trust boundary** | Where the trust level changes (§22). |

### Building a good DFD

1. **Start with the external entities and the main process**, then add the data stores and the flows between everything.
2. **Label the flows** — "login credentials over HTTPS", "SQL query", "JWT". The label tells you the data's sensitivity and the protocol's protections.
3. **Draw the trust boundaries last** and deliberately — internet/DMZ/internal, process/OS, container/host, tenant A/tenant B, user-space/kernel. Every arrow crossing a dashed line is a place to concentrate.
4. **Decompose to the right level.** Level-0 (context) DFD: the whole system as one process with its external entities. Level-1: the major components. Go deeper only where a component is complex or high-risk. Keep any single diagram to roughly one page.
5. **Number elements** so you can reference them in the threat register ("Threat 7 targets flow 3, DB write").

### Example DFD (text form) — a simple web app

```
                 ┌───────────────── Trust boundary: Internet | DMZ ─────────────────┐
   (External)    │                                                                    │
  ┌────────┐  HTTPS: creds, requests   ┌──────────────┐   SQL: queries   ╔═════════╗ │
  │ Browser│ ────────────────────────► │ Web/App      │ ───────────────► ║ App DB  ║ │
  │ (user) │ ◄──────────────────────── │ Server (proc)│ ◄─────────────── ║ (store) ║ │
  └────────┘   HTTPS: pages, cookies   └──────┬───────┘   rows            ╚═════════╝ │
                 │                             │                                       │
                 └───────────────┬────────────┼───────────────────────────────────────┘
                                 │ HTTPS: token│                Trust boundary: App | 3rd party
                                 ▼             ▼
                          ┌──────────────┐  ┌──────────────┐
                          │ Auth provider│  │ Payment API  │   (External entities, 3rd party)
                          └──────────────┘  └──────────────┘
```

Now the trust boundaries are visible: Browser→Web server (untrusted internet input — validate everything), Web server→DB (SQLi surface), Web server→third parties (SSRF, secret handling, data sharing). That is where STRIDE gets applied first.

Modern practice also uses **process-flow diagrams (PFDs)** — favoured by VAST/Agile tooling — which follow the *user/feature flow* through the app rather than pure data movement, because developers often think more naturally in flows/features. Either works; the DFD's strength is making *trust boundaries* explicit.

## 22. Trust boundaries

**A trust boundary is a line across which the level of trust changes** — and it is the single most important concept in the diagram. Data crossing *into* a higher-trust zone from a lower-trust one is *untrusted input* and must be validated, authenticated, and authorised. The classic boundaries:

- **Internet ↔ your perimeter** (the big one — everything from the internet is hostile).
- **DMZ ↔ internal network.**
- **Application ↔ database / cache / queue.**
- **Your code ↔ third-party service / SDK / dependency.**
- **Between tenants** in a multi-tenant system (tenant isolation).
- **Between microservices** (does service A really trust service B's claims about the caller?).
- **User space ↔ kernel; container ↔ host; VM ↔ hypervisor.**
- **Between privilege levels** (normal user ↔ admin).
- **Client ↔ server** — especially for web and mobile: *the client is on the attacker's side of a trust boundary.* (This is the central theme of the companion [mobile guide](mobile_security_attacks_complete_guide.md).)

**Why they dominate threat discovery:** an attacker's entire job is to get malicious input or actions across a trust boundary and have the higher-trust side act on them. Spoofing happens at boundaries (who is really on the other side?), tampering happens to flows crossing them, elevation of privilege *is* crossing a boundary you shouldn't. When you apply STRIDE, **start at every dashed line.** If your diagram has no trust boundaries, you've either got a trivial system or (far more likely) you haven't looked hard enough.

## 23. Sequence diagrams and other views

DFDs show structure; sometimes you need to see **order and timing**.

- **Sequence diagrams** show the ordered message exchange between components over time. They're excellent for **protocol/authentication flows** (OAuth dances, password reset, payment authorisation) where the *sequence* is where the vulnerability lives — e.g. TOCTOU/race conditions, missing state validation, steps that can be skipped or replayed. If a threat depends on "what if the attacker does step 3 before step 2?", draw a sequence diagram.
- **Architecture / deployment diagrams** add infrastructure context (load balancers, networks, cloud services, IAM) that pure DFDs abstract away — useful for infrastructure and cloud threat modeling.
- **State diagrams** help where security depends on state machines (session lifecycle, order/payment status) and illegal transitions are the threat.

Use whatever view best exposes the threats for the system at hand; most models are primarily a DFD with trust boundaries, supplemented by a sequence diagram for the trickiest flows. Diagrams-as-code (Mermaid, PlantUML) keep these in version control next to the design (§29).

---

# Part E — Worked Examples

Three end-to-end examples applying the process (Part B) with STRIDE (Part C). These show the *shape* of a finished analysis, condensed.

## 24. Worked example 1 — a web application

**System:** An online notes app. Users register/login, create private notes, and share notes by link. React SPA → REST API → PostgreSQL; auth via JWT; file attachments in S3; email via a third-party provider.

**Step 1 — Scope & assets.** Scope: the API and its data stores. Assets: users' private notes (confidentiality + integrity), credentials/sessions, account availability. Objectives: only owners (and explicitly shared users) can read/write notes; auth is robust; PII protected (GDPR). Actors: opportunistic external attackers, malicious registered users, bots.

**Step 2 — Model.** External entities: browser, email provider, S3. Process: API server. Stores: PostgreSQL, S3, JWT signing key. Trust boundaries: internet↔API, API↔DB, API↔S3/email. Key flows: login (creds→API→DB), create/read note (request→API→DB), share link generation, attachment upload (browser→API→S3).

**Step 3 — Threats (STRIDE, per element/boundary; abbreviated):**

| # | Element/flow | STRIDE | Threat | 
|---|---|---|---|
| 1 | Login flow | S | Credential stuffing / weak passwords → account takeover. |
| 2 | JWT | S/T | `alg:none` or weak-secret forgery; unverified signature → impersonate any user. |
| 3 | Read-note endpoint | E/I | **IDOR**: `GET /notes/{id}` without ownership check → read others' notes. |
| 4 | Note content | T/I | **Stored XSS** in note body rendered to sharer/viewer. |
| 5 | DB query | T/I | **SQL injection** in search/filter params. |
| 6 | Share link | I | Predictable/guessable share tokens → enumerate private notes. |
| 7 | Attachment upload | E/T | Unrestricted file upload / SSRF via S3 pre-sign; content-type spoofing. |
| 8 | Password reset | S/I | Token doesn't expire / user enumeration on "forgot password". |
| 9 | API | D | No rate limit → brute force & resource exhaustion. |
| 10 | Errors/logs | I/R | Verbose errors leak internals; no audit log of sensitive actions (repudiation). |

**Step 4 — Prioritise.** Highest risk: #3 IDOR and #2 JWT forgery (unauth/low-effort, full-account impact), #5 SQLi, #4 stored XSS. Medium: #1, #6, #7, #8. Lower/monitored: #9, #10.

**Step 5 — Mitigate.**
- #3: ownership check *in the query* (`WHERE owner_id = :current_user`) on every object access; deny by default.
- #2: pin the JWT algorithm, verify signature with a strong secret/key, validate `exp/aud/iss` (see web guide §37).
- #5: parameterised queries / ORM everywhere.
- #4: context-aware output encoding + CSP; sanitise rich text.
- #6: 128-bit random, unguessable share tokens; optional expiry.
- #7: validate content (not extension), scan, store outside web root, lock down S3, avoid user-controlled URLs in server-side fetches (SSRF).
- #8: single-use, short-TTL reset tokens; uniform "if an account exists…" responses.
- #9: per-account and per-IP rate limiting.
- #10: generic error messages; tamper-evident audit logging of auth and sharing events.

**Step 6 — Validate.** Confirm each control is implemented; add security test cases (an IDOR test, a JWT-tamper test); scope the pen test to #2–#7; record any accepted residual risk (e.g. "share links are unauthenticated by design — accepted, mitigated by unguessable tokens + expiry"). Re-model when the sharing feature or auth changes.

## 25. Worked example 2 — a cloud / microservices system

**System:** A microservices platform on Kubernetes: an API gateway, several services (orders, payments, inventory), a message queue, a managed database per service, secrets in a cloud secrets manager, all in one cloud account, multi-tenant.

**New trust boundaries beyond the web example:** internet↔gateway; gateway↔service mesh; **service↔service** (does `orders` trust a caller claiming to be `payments`?); **tenant↔tenant**; pod↔pod/node; workload↔cloud control plane (IAM); CI/CD↔production.

**Representative threats (STRIDE + ATT&CK cloud thinking):**

- **S (service identity):** one service spoofs another / an attacker who lands in the mesh calls internal services directly (no mTLS, flat trust). → **mTLS + workload identity (SPIFFE/service accounts); authorize service-to-service calls; zero-trust, don't rely on network position.**
- **E (IAM):** over-broad IAM roles → a compromised `inventory` pod can read the `payments` database or the whole secrets manager (privilege escalation / lateral movement). → **least-privilege IAM per workload; scoped secrets access; no wildcard permissions.**
- **I (tenant isolation):** a bug lets tenant A read tenant B's data (broken tenant isolation / IDOR at scale). → **enforce tenant scoping in every query and at the data layer; test isolation explicitly.**
- **T/I (queue):** unauthenticated/unencrypted message queue → tamper with or read others' messages. → **authn/authz on the broker; encrypt; validate message provenance.**
- **S/T (supply chain & CI/CD):** compromised dependency or CI pipeline pushes a malicious image to prod (see web guide §50). → **signed images, admission control, SBOMs, pinned deps, least-privilege CI, protected branches.**
- **D:** one tenant exhausts shared resources (noisy neighbour / DoS). → **per-tenant quotas & rate limits; resource limits on pods.**
- **I (secrets/metadata):** SSRF in a service reaches the **cloud metadata endpoint** to steal credentials. → **IMDSv2/hardened metadata, egress controls, block link-local from workloads.**
- **R:** insufficient centralised, tamper-evident logging across services → can't reconstruct an incident. → **centralised, integrity-protected audit logs; correlation IDs across services.**

**Lesson:** in distributed/cloud systems, the threats shift from "the app" to the **boundaries between services, tenants, and the cloud control plane.** Model *identity* (who is calling whom) and *blast radius* (what a single compromised component can reach) explicitly; assume any one component can be compromised and design so that doesn't cascade (zero trust + least privilege + segmentation).

## 26. Worked example 3 — a mobile app + API

**System:** A banking mobile app (iOS + Android) talking to a backend API; local biometric unlock; stores a session token on device.

**The defining trust boundary:** the **client runs on the attacker's device** (the whole thesis of the [mobile guide](mobile_security_attacks_complete_guide.md)). So the model splits cleanly:

- **On-device threats (assume a hostile, possibly rooted device):**
  - **I:** sensitive data in insecure local storage / logs / screenshots. → Keystore/Keychain + Secure Enclave; `FLAG_SECURE`; no secrets in logs (mobile §4–§8, §26).
  - **S/E:** biometric unlock implemented as a bypassable UI gate; hardcoded API keys extracted from the binary. → key-bound biometrics; no client secrets; broker via backend (mobile §13, §14).
  - **T:** reverse engineering / Frida hooking / repackaging to disable controls. → obfuscation + **server-verified attestation (Play Integrity / App Attest)**; treat client checks as friction (mobile §16–§20).
  - **S (network):** MITM / no cert pinning. → TLS + pinning with backup pins; but *never rely on pinning alone* (mobile §9–§11).
- **Server-side threats (the real security boundary — identical to the web example):**
  - **E/I:** the API must authorize every request from *identity derived server-side*, never from client claims (IDOR, mobile §12 ↔ web §30).
  - All the web guide's API threats apply, because a reverse-engineered client can call the API directly.

**Lesson & the unifying principle across all three examples:** *the client and the network are untrusted; the server is where security decisions must live.* Threat modeling makes this concrete by forcing you to draw the boundary between attacker-controlled and defender-controlled, and to push every real check to the defender's side. Client-side controls (pinning, root detection, obfuscation) raise cost; server-side authorization, validation, and attestation-verification create the boundary.

---

# Part F — Threat Modeling in the Real World

A methodology no one runs is worthless. This part is about making threat modeling actually happen, repeatedly, in how software gets built.

## 27. Threat modeling in the SDLC / DevSecOps

Threat modeling is a **design-phase** activity in the SDLC, but its outputs ripple through every later phase:

- **Requirements/design:** the primary home. Threat modeling turns "build feature X" into "build feature X *with these security requirements*." Its outputs become security acceptance criteria.
- **Implementation:** developers build the mitigations; secure-coding standards address the implementation-level (bug) risks the model flagged.
- **Testing:** the threat register drives **security test cases** and **abuse cases** ("try to read another user's note"), and scopes the **pen test** (the pen tester attacks exactly the high-risk threats the model identified).
- **Deployment/ops:** the model informs monitoring/detection (log the events that would reveal the modeled attacks — tie to ATT&CK), incident response, and config hardening.
- **Maintenance:** re-model on change; feed incidents and findings back in.

In **DevSecOps**, the goal is to make threat modeling **continuous and low-friction** rather than a heavyweight gate. Techniques: lightweight per-story threat modeling, threat modeling triggered by risky changes, "threat modeling as code" in the pipeline (§29), and treating the threat model as a living artifact in the repo. The **OWASP SAMM** and **BSIMM** maturity models both track threat modeling as a core practice; NIST's **SSDF (SP 800-218)** lists it as a recommended practice. Maturity looks like: *design reviews for big things* → *every team threat models* → *automated, continuous, integrated into CI/CD.*

## 28. Threat modeling in Agile & at scale

Classic threat modeling can feel too heavy for two-week sprints. Adaptations that make it Agile-compatible:

- **Incremental modeling.** Maintain a living model of the system and update it per feature/story rather than re-doing it wholesale. Threat model the *delta*.
- **Lightweight, timeboxed sessions.** A 30–60 minute "threat modeling whiteboard" on a new feature, focused on the four questions, beats a 3-day formal exercise no one has time for.
- **Evil user stories / abuse cases.** Write security requirements in the team's existing language: "As an attacker, I want to read another user's data, so…" — and add the mitigating story to the backlog.
- **Threat modeling as a definition-of-ready/done item** for stories that touch trust boundaries, auth, or sensitive data (a *risk-based* trigger, not every story).
- **Security champions.** Embed a trained developer in each team to facilitate lightweight modeling, so it scales without a central bottleneck. **Democratise** the skill.
- **Card decks & fast methods** (Security Cards, LINDDUN GO, OWASP Cornucopia, Elevation of Privilege — the EoP card game) make sessions engaging and accessible to non-specialists.
- **The Threat Modeling Manifesto's values** apply here: *a culture of finding and fixing design issues* over checkbox compliance; *people and collaboration* over processes and tools; *doing threat modeling* over talking about it; *continuous refinement* over a single delivery.

At **enterprise scale**, consistency and coverage matter more than depth-per-model: standard templates, reusable threat libraries, tooling with shared component libraries (VAST/ThreatModeler, IriusRisk), and automation (§29) let hundreds of teams model consistently.

## 29. Threat modeling as code

The pipeline-native evolution: express the system model **as a text/code artifact** in version control, and generate (or check) threats automatically.

- **`pytm`** (OWASP) — define elements, data flows, and boundaries in **Python**; it generates DFDs, sequence diagrams, and a STRIDE-based threat report. Because it's code, it lives in the repo, diffs in PRs, and runs in CI.
- **Threagile** — define the architecture in a **YAML** file; it runs a rule engine and outparts risks, a data-flow diagram, and reports. Good for automated, repeatable analysis in pipelines.
- **Threatspec** — annotate threats/mitigations **inline in source-code comments**; it aggregates them into a model and report, keeping the model next to the code it describes.
- **Diagrams-as-code** (Mermaid, PlantUML) — keep DFDs/sequence diagrams versioned as text alongside the design docs.
- **IriusRisk / SD Elements / ThreatModeler** — commercial platforms with APIs, component libraries, and CI integration that can auto-generate draft threat models from an architecture description or a questionnaire, then track mitigations as tickets.

**Benefits:** the model stays in sync with the system (it's reviewed in PRs), threats are re-evaluated automatically on change, and coverage becomes consistent and auditable. **Caveat:** automation generates *candidate* threats from patterns — it cannot replace human reasoning about business logic and novel design flaws. Use it to handle the repetitive breadth so humans focus on the subtle, high-value threats.

## 30. Common pitfalls and anti-patterns

- **Boiling the ocean.** Trying to model everything at once, or too deep, so it never finishes. → Scope tightly; iterate.
- **Doing it once and filing it away.** A stale model is worse than none (false confidence). → Make it living; re-model on change.
- **No trust boundaries on the diagram.** Then you're not really threat modeling. → Always draw them; start STRIDE there.
- **A model that doesn't match reality.** Built without the engineers, or from an idealised diagram. → Involve the people who built it; validate the model against the running system.
- **Threats without dispositions.** A big list of threats and no decisions/tickets. → Every threat gets mitigate/eliminate/transfer/accept, with an owner.
- **Analysis paralysis / false precision.** Endless DREAD debates. → Prefer H/M/L; move to action.
- **Security team owns everything.** Doesn't scale; disconnects from design. → Democratise; security *facilitates*, teams *own*.
- **Only technical, never business.** Missing what actually matters to the org. → Anchor on assets and business impact (PASTA thinking).
- **Ignoring privacy.** STRIDE alone misses privacy harms. → Add LINDDUN when personal data is involved.
- **Treating the tool as the method.** A tool draws diagrams and suggests threats; it doesn't think. → The value is the structured thinking and the conversation.
- **No feedback loop.** Incidents and pen-test findings never improve the model. → Close the loop: every miss is a lesson for the next model.

---

# Part G — Tooling

## 31. Tools and threat libraries

**Dedicated threat-modeling tools**
- **OWASP Threat Dragon** — free, open-source; draw DFDs and record STRIDE/LINDDUN threats; desktop and web; models stored as JSON (version-controllable). Great starting point.
- **Microsoft Threat Modeling Tool** — free; DFD-based with STRIDE-per-element guidance and a threat template engine; Windows. The classic teaching tool.
- **pytm** (OWASP) — threat modeling *as code* in Python (§29).
- **Threagile** — YAML-defined, rule-engine, pipeline-friendly (§29).
- **IriusRisk** — commercial; questionnaire/architecture-driven auto-generation, large control/threat libraries, ALM integration, compliance mapping.
- **ThreatModeler** — commercial; VAST methodology, process-flow diagrams, enterprise scale and automation.
- **SD Elements (Security Compass)** — commercial; turns a survey of the system into security requirements/countermeasures and tickets.
- **Cairis** — open-source, requirements/risk-focused platform (aligns with Trike-style thinking).

**Threat libraries & knowledge bases (inputs to identification and coverage-checking)**
- **MITRE ATT&CK** — adversary tactics & techniques (§18) — https://attack.mitre.org/
- **MITRE CAPEC** — attack patterns (§18) — https://capec.mitre.org/
- **MITRE CWE** — weakness types (what attack patterns exploit) — https://cwe.mitre.org/
- **OWASP Top 10 / API Top 10 / Mobile Top 10** — prioritised risk checklists to walk against your model.
- **OWASP ASVS** and the **Cheat Sheet Series** — the *mitigation* side: concrete controls for the threats you find.

**Games & decks (for sessions and training)**
- **Elevation of Privilege (EoP)** — Microsoft's STRIDE card game; the original gamified threat modeling.
- **OWASP Cornucopia** — card deck for web-app security requirements.
- **Security Cards** (UW) and **LINDDUN GO** — brainstorming decks (§19, §15).

**How to choose:** start free (Threat Dragon or the Microsoft tool) to learn the mechanics; adopt "as code" (pytm/Threagile) when you want pipeline integration; buy a platform (IriusRisk/ThreatModeler/SD Elements) when you need to scale consistent modeling across many teams with libraries, tracking, and compliance mapping. **The tool is an aid to the thinking, never a substitute for it.**

---

# Appendix A — STRIDE-per-element quick chart

Which STRIDE threats *typically* apply to each DFD element type. Use it to drive coverage: for each element, consider the ✓ categories. (Absence of a ✓ means "less common", not "impossible" — judgement still applies.)

| Element | **S**poofing | **T**ampering | **R**epudiation | **I**nfo disclosure | **D**oS | **E**oP |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **External entity** (user, 3rd-party) | ✓ | | ✓ | | | |
| **Process** (your service/app) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| **Data flow** (arrow) | | ✓ | | ✓ | ✓ | |
| **Data store** (DB, file, queue) | | ✓ | ✓* | ✓ | ✓ | |

\* Repudiation applies to data stores especially when they hold the logs/audit trail (tampering with or missing logs enables repudiation).

**Reading it:** *external entities* mainly spoof (who are they really?) and repudiate (did they really do it?); *processes* are exposed to everything; *data flows* get tampered/read/flooded in transit; *data stores* get tampered, read, flooded, and are where repudiation is won or lost. Apply mitigations from the STRIDE table in §11.

---

# Appendix B — Threat modeling cheat sheet

**The four questions (memorise these):**
1. What are we working on? → *model it (DFD + trust boundaries)*
2. What can go wrong? → *find threats (STRIDE / attack trees / ATT&CK / LINDDUN)*
3. What are we going to do about it? → *mitigate / eliminate / transfer / accept*
4. Did we do a good enough job? → *validate & iterate*

**STRIDE ↔ property ↔ mitigation:**
| Threat | Property | First mitigation to reach for |
|---|---|---|
| Spoofing | Authentication | Strong auth / MFA / signed tokens / mTLS |
| Tampering | Integrity | TLS, signatures/HMAC, input validation, access control |
| Repudiation | Non-repudiation | Tamper-evident audit logging |
| Information disclosure | Confidentiality | Encryption, access control, least privilege, data minimisation |
| Denial of service | Availability | Rate limits, quotas, timeouts, scaling |
| Elevation of privilege | Authorization | Authz on every action, least privilege, deny-by-default |

**Where threats live:** at **trust boundaries.** Start there. Follow the data. Assume the client and network are hostile; put real decisions on the server.

**Risk:** `risk ≈ likelihood × impact`. Prefer High/Medium/Low over false-precision scores. Fix high-likelihood × high-impact first.

**Response options:** Mitigate · Eliminate · Transfer · Accept (and *document* acceptances with an owner).

**Pick a method:** STRIDE (default) · attack trees (deep on a goal) · PASTA (business risk) · LINDDUN (privacy) · VAST (scale) · ATT&CK/CAPEC (coverage cross-check). *Doing it beats choosing perfectly.*

**Make it stick:** do it early, keep it living, involve the builders, produce tickets not documents, and close the loop from incidents/pen tests back into the model.

---

# Appendix C — Further reading & external resources

**Foundational frameworks & manifestos**
- Threat Modeling Manifesto (values & principles) — https://www.threatmodelingmanifesto.org/
- OWASP Threat Modeling project — https://owasp.org/www-community/Threat_Modeling
- OWASP Threat Modeling Process — https://owasp.org/www-community/Threat_Modeling_Process
- OWASP Threat Modeling Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html

**Methodologies**
- STRIDE (Microsoft) — https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats
- Microsoft "Threat Modeling" guidance — https://learn.microsoft.com/en-us/security/engineering/threat-modeling
- PASTA (overview, VerSprite) — https://versprite.com/blog/what-is-pasta-threat-modeling/
- LINDDUN privacy threat modeling — https://linddun.org/
- Attack trees (Schneier) — https://www.schneier.com/academic/archives/1999/12/attack_trees.html
- Carnegie Mellon SEI — "Threat Modeling: 12 Available Methods" — https://insights.sei.cmu.edu/blog/threat-modeling-12-available-methods/
- NIST SP 800-154 (Data-Centric System Threat Modeling, draft) — https://csrc.nist.gov/pubs/sp/800/154/ipd

**Attacker knowledge bases**
- MITRE ATT&CK — https://attack.mitre.org/
- MITRE CAPEC (attack patterns) — https://capec.mitre.org/
- MITRE CWE (weaknesses) — https://cwe.mitre.org/
- Lockheed Martin Cyber Kill Chain — https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html

**Scoring**
- CVSS (FIRST) — https://www.first.org/cvss/
- On DREAD's problems (background) — https://en.wikipedia.org/wiki/DREAD_(risk_assessment_model)

**Tools**
- OWASP Threat Dragon — https://owasp.org/www-project-threat-dragon/
- Microsoft Threat Modeling Tool — https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool
- OWASP pytm — https://github.com/OWASP/pytm
- Threagile — https://threagile.io/
- IriusRisk — https://www.iriusrisk.com/
- Elevation of Privilege card game — https://github.com/adamshostack/eop

**Programs, maturity & books**
- OWASP SAMM (Software Assurance Maturity Model) — https://owaspsamm.org/
- BSIMM — https://www.bsimm.com/
- NIST SSDF (SP 800-218) — https://csrc.nist.gov/pubs/sp/800/218/final
- *Threat Modeling: Designing for Security* — Adam Shostack (the standard text)
- *Threat Modeling: A Practical Guide for Development Teams* — Izar Tarandach & Matthew Coles

**Practice & learning**
- OWASP Threat Modeling learning & talks — https://owasp.org/www-project-threat-modeling/
- PortSwigger Web Security Academy (the concrete threats to model) — https://portswigger.net/web-security

**Companion guides in this repo:** [web_security_attacks_complete_guide.md](web_security_attacks_complete_guide.md) and [mobile_security_attacks_complete_guide.md](mobile_security_attacks_complete_guide.md) — the catalogue of concrete threats this method helps you find and prioritise. For architecture-level context, see the `system breakdowns/` directory.

---

*End of guide. Threat modeling is not a document or a tool — it is the habit of asking, of every design, "what are we building, what can go wrong, what will we do about it, and did we do enough?" Do it early, keep it alive, and let it produce decisions, not just diagrams.*

