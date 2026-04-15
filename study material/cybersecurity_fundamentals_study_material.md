# CYBERSECURITY FUNDAMENTALS — DETAILED STUDY MATERIAL (2026)
Audience: final-year undergrad + current intern (strong ML background)
Purpose: deep fundamentals before specializing (AppSec / CloudSec / AISec)

How to use this document
### This is NOT a roadmap. It is study material: explanations, examples, exercises,
mini-quizzes, and resources.

Study loop (use for every chapter):
1) Read and take notes (definitions + why it matters)
2) Reproduce in a SAFE lab (VM/CTF platform) 
3) Write a 1–2 page “teach-back” (root cause, attack/defense, evidence)
4) Self-test (mini-quiz)

Safety & ethics (mandatory)
### - Only practice offensive techniques in legal environments:
  - your own machines and apps
  - official training labs (PortSwigger, TryHackMe, HTB, WebGoat/Juice Shop)
  - authorized internship scope (written approval)
- Do NOT scan, exploit, or test anything without permission.
- Your career depends on judgment; cultivate it early.



## Generated Table of Contents
  - [This is NOT a roadmap. It is study material: explanations, examples, exercises,](#this-is-not-a-roadmap-it-is-study-material-explanations-examples-exercises)
  - [- Only practice offensive techniques in legal environments:](#only-practice-offensive-techniques-in-legal-environments)
- [Table of Contents](#table-of-contents)
  - [PART 0: Orientation](#part-0-orientation)
  - [0.1 Threat thinking and security vocabulary](#01-threat-thinking-and-security-vocabulary)
  - [0.2 Security outcomes (CIA+) and the “control stack”](#02-security-outcomes-cia-and-the-control-stack)
  - [0.3 The security learning stack (systems → network → app → cloud → AI)](#03-the-security-learning-stack-systems-network-app-cloud-ai)
- [PART 1: Systems Fundamentals](#part-1-systems-fundamentals)
  - [1.1 Computer architecture for security (CPU, memory, privilege)](#11-computer-architecture-for-security-cpu-memory-privilege)
  - [1.2 Operating system fundamentals (processes, syscalls, filesystems)](#12-operating-system-fundamentals-processes-syscalls-filesystems)
  - [1.3 Linux fundamentals for security (admin + auditing)](#13-linux-fundamentals-for-security-admin-auditing)
  - [1.4 Windows fundamentals for security (internals + telemetry)](#14-windows-fundamentals-for-security-internals-telemetry)
  - [1.5 Identity fundamentals: Active Directory (high-level but job-critical)](#15-identity-fundamentals-active-directory-high-level-but-job-critical)
- [PART 2: Programming Foundations for Security](#part-2-programming-foundations-for-security)
  - [2.1 Python for security automation](#21-python-for-security-automation)
  - [2.2 Bash fundamentals (safe scripting)](#22-bash-fundamentals-safe-scripting)
  - [2.3 PowerShell fundamentals (defender-grade)](#23-powershell-fundamentals-defender-grade)
  - [2.4 C/memory model fundamentals (for vuln intuition)](#24-cmemory-model-fundamentals-for-vuln-intuition)
  - [2.5 Reading assembly (enough for reversing)](#25-reading-assembly-enough-for-reversing)
  - [2.6 Coding for security (Python): secure coding + security tooling](#26-coding-for-security-python-secure-coding-security-tooling)
- [PART 3: Networking Fundamentals](#part-3-networking-fundamentals)
  - [3.1 OSI/TCP-IP with practical mapping](#31-ositcp-ip-with-practical-mapping)
  - [3.2 Ethernet & ARP](#32-ethernet-arp)
  - [3.3 IP, routing, NAT](#33-ip-routing-nat)
  - [3.4 TCP and UDP](#34-tcp-and-udp)
  - [3.5 DNS (deep fundamentals)](#35-dns-deep-fundamentals)
  - [3.6 HTTP and proxies](#36-http-and-proxies)
  - [3.7 TLS/PKI (network view)](#37-tlspki-network-view)
  - [3.8 Packet analysis workflow (Wireshark/tcpdump)](#38-packet-analysis-workflow-wiresharktcpdump)
  - [3.9 Email security fundamentals (SPF/DKIM/DMARC)](#39-email-security-fundamentals-spfdkimdmarc)
- [PART 4: Applied Cryptography Fundamentals](#part-4-applied-cryptography-fundamentals)
  - [4.1 What crypto does and does NOT do](#41-what-crypto-does-and-does-not-do)
  - [4.2 Hashing vs encryption vs signatures](#42-hashing-vs-encryption-vs-signatures)
  - [4.3 Password storage and authentication](#43-password-storage-and-authentication)
  - [4.4 Symmetric encryption and AEAD concepts](#44-symmetric-encryption-and-aead-concepts)
  - [4.5 PKI and certificate validation](#45-pki-and-certificate-validation)
  - [4.6 Common crypto failures in real systems](#46-common-crypto-failures-in-real-systems)
- [PART 5: Web + API Security Fundamentals](#part-5-web-api-security-fundamentals)
  - [5.1 The web platform as a security boundary](#51-the-web-platform-as-a-security-boundary)
  - [5.2 Sessions, cookies, SameSite, CSRF](#52-sessions-cookies-samesite-csrf)
  - [5.3 XSS and browser execution](#53-xss-and-browser-execution)
  - [5.4 Injection (SQL/NoSQL/command) root causes](#54-injection-sqlnosqlcommand-root-causes)
  - [5.5 Access control (IDOR) and authorization thinking](#55-access-control-idor-and-authorization-thinking)
  - [5.6 SSRF and why cloud makes it worse](#56-ssrf-and-why-cloud-makes-it-worse)
  - [5.7 OAuth 2.0 + OpenID Connect basics](#57-oauth-20-openid-connect-basics)
  - [5.8 Secure API design fundamentals](#58-secure-api-design-fundamentals)
- [PART 6: Defensive Security Fundamentals](#part-6-defensive-security-fundamentals)
  - [6.1 Logging fundamentals (what to log, how to reason)](#61-logging-fundamentals-what-to-log-how-to-reason)
  - [6.2 Detection engineering basics (signals, baselines, FP/FN)](#62-detection-engineering-basics-signals-baselines-fpfn)
  - [6.3 Incident response fundamentals (first hour, containment)](#63-incident-response-fundamentals-first-hour-containment)
  - [6.4 Vulnerability management fundamentals (CVE/CVSS, prioritization)](#64-vulnerability-management-fundamentals-cvecvss-prioritization)
- [PART 7: Forensics Fundamentals](#part-7-forensics-fundamentals)
  - [7.1 Evidence thinking: facts vs interpretations](#71-evidence-thinking-facts-vs-interpretations)
  - [7.2 Disk forensics overview](#72-disk-forensics-overview)
  - [7.3 Memory forensics overview](#73-memory-forensics-overview)
  - [7.4 Network forensics overview](#74-network-forensics-overview)
  - [7.5 Writing a forensic report](#75-writing-a-forensic-report)
- [PART 8: Malware & Reverse Engineering Fundamentals](#part-8-malware-reverse-engineering-fundamentals)
  - [8.1 Safe analysis environment](#81-safe-analysis-environment)
  - [8.2 Static triage](#82-static-triage)
  - [8.3 Dynamic triage](#83-dynamic-triage)
  - [8.4 Intro reversing (Ghidra/x64dbg)](#84-intro-reversing-ghidrax64dbg)
  - [8.5 Reporting: behavior, IOCs, confidence](#85-reporting-behavior-iocs-confidence)
- [PART 9: Security Engineering Fundamentals](#part-9-security-engineering-fundamentals)
  - [9.1 Threat modeling (DFD + STRIDE)](#91-threat-modeling-dfd-stride)
  - [9.2 Secure design principles (least privilege, defense in depth)](#92-secure-design-principles-least-privilege-defense-in-depth)
  - [9.3 Secure SDLC (SAST/DAST, deps, secrets, SBOM)](#93-secure-sdlc-sastdast-deps-secrets-sbom)
  - [9.4 Supply chain security basics](#94-supply-chain-security-basics)
- [PART 10: Cloud + Container Fundamentals (pre-CloudSec)](#part-10-cloud-container-fundamentals-pre-cloudsec)
  - [10.1 Shared responsibility model](#101-shared-responsibility-model)
  - [10.2 Cloud identity fundamentals](#102-cloud-identity-fundamentals)
  - [10.3 Cloud networking fundamentals](#103-cloud-networking-fundamentals)
  - [10.4 Storage + secrets fundamentals](#104-storage-secrets-fundamentals)
  - [10.5 Containers vs VMs and image supply chain](#105-containers-vs-vms-and-image-supply-chain)
  - [10.6 Kubernetes vocabulary (very high-level)](#106-kubernetes-vocabulary-very-high-level)
- [PART 11: AI/ML Security Fundamentals (pre-AISec)](#part-11-aiml-security-fundamentals-pre-aisec)
  - [11.1 AI for security vs security of AI](#111-ai-for-security-vs-security-of-ai)
  - [11.2 Threats: poisoning, evasion, extraction, privacy leakage](#112-threats-poisoning-evasion-extraction-privacy-leakage)
  - [11.3 Defenses: pipeline integrity, monitoring, rate limiting](#113-defenses-pipeline-integrity-monitoring-rate-limiting)
  - [11.4 How to evaluate ML defenses honestly](#114-how-to-evaluate-ml-defenses-honestly)
  - [You asked for “very good texts to study from.” Use this as a curated library.](#you-asked-for-very-good-texts-to-study-from-use-this-as-a-curated-library)
- [PART 0 — ORIENTATION](#part-0-orientation)
  - [0.1 Threat thinking and security vocabulary](#01-threat-thinking-and-security-vocabulary)
  - [Security is NOT “using tools.” Security is: controlling risk under adversarial](#security-is-not-using-tools-security-is-controlling-risk-under-adversarial)
  - [0.2 Security outcomes (CIA+) and the control stack](#02-security-outcomes-cia-and-the-control-stack)
  - [CIA triad:](#cia-triad)
  - [0.3 The security learning stack (why the order matters)](#03-the-security-learning-stack-why-the-order-matters)
  - [You cannot do deep AppSec or CloudSec without:](#you-cannot-do-deep-appsec-or-cloudsec-without)
- [PART 1 — SYSTEMS FUNDAMENTALS](#part-1-systems-fundamentals)
  - [1.1 Computer architecture for security](#11-computer-architecture-for-security)
  - [Why it matters: many high-impact bugs are “low-level behaviors made unsafe.”](#why-it-matters-many-high-impact-bugs-are-low-level-behaviors-made-unsafe)
  - [1.2 Operating system fundamentals](#12-operating-system-fundamentals)
  - [Core building blocks](#core-building-blocks)
  - [1.3 Linux fundamentals for security (admin + auditing)](#13-linux-fundamentals-for-security-admin-auditing)
  - [Linux is the language of servers, cloud, and security appliances.](#linux-is-the-language-of-servers-cloud-and-security-appliances)
  - [1.3.1 Filesystem landmarks](#131-filesystem-landmarks)
  - [1.3.2 Users, groups, and permissions](#132-users-groups-and-permissions)
  - [1.3.3 Service management and logs](#133-service-management-and-logs)
  - [1.4 Windows fundamentals for security (internals + telemetry)](#14-windows-fundamentals-for-security-internals-telemetry)
  - [Windows dominates enterprise endpoints, and its logging surface is huge.](#windows-dominates-enterprise-endpoints-and-its-logging-surface-is-huge)
  - [1.4.1 Core concepts (security view)](#141-core-concepts-security-view)
  - [1.4.2 Telemetry fundamentals](#142-telemetry-fundamentals)
  - [1.5 Identity fundamentals: Active Directory (high-level, job-critical)](#15-identity-fundamentals-active-directory-high-level-job-critical)
  - [AD is not “advanced.” It’s the center of enterprise security.](#ad-is-not-advanced-its-the-center-of-enterprise-security)
- [PART 2 — PROGRAMMING FOUNDATIONS FOR SECURITY](#part-2-programming-foundations-for-security)
  - [2.1 Python for security automation](#21-python-for-security-automation)
  - [Goal: turn messy evidence into structured insight.](#goal-turn-messy-evidence-into-structured-insight)
  - [2.2 Bash fundamentals (safe scripting)](#22-bash-fundamentals-safe-scripting)
  - [What to learn](#what-to-learn)
  - [2.3 PowerShell fundamentals (defender-grade)](#23-powershell-fundamentals-defender-grade)
  - [What to learn](#what-to-learn)
  - [2.4 C/memory model fundamentals](#24-cmemory-model-fundamentals)
  - [Purpose: understand why memory bugs exist and how mitigations work.](#purpose-understand-why-memory-bugs-exist-and-how-mitigations-work)
  - [2.5 Reading assembly (enough for reversing)](#25-reading-assembly-enough-for-reversing)
  - [What to learn](#what-to-learn)
  - [2.6 Coding for security (Python): secure coding + security tooling](#26-coding-for-security-python-secure-coding-security-tooling)
  - [Goal: write Python that is safe by default, resilient to untrusted input, and useful for security work.](#goal-write-python-that-is-safe-by-default-resilient-to-untrusted-input-and-useful-for-security-work)
  - [2.6.1 Secure coding principles (Python-specific)](#261-secure-coding-principles-python-specific)
  - [2.6.2 Input validation and normalization](#262-input-validation-and-normalization)
  - [2.6.3 Safe file handling](#263-safe-file-handling)
  - [2.6.4 Subprocess and command execution safety](#264-subprocess-and-command-execution-safety)
  - [2.6.5 Safe serialization and parsing](#265-safe-serialization-and-parsing)
  - [2.6.6 Authentication, authorization, and sessions (coding view)](#266-authentication-authorization-and-sessions-coding-view)
  - [2.6.7 Cryptography in Python (use, don’t invent)](#267-cryptography-in-python-use-dont-invent)
  - [2.6.8 Network programming for defenders (safe)](#268-network-programming-for-defenders-safe)
  - [2.6.9 Logging, telemetry, and evidence quality](#269-logging-telemetry-and-evidence-quality)
  - [2.6.10 Dependency security for Python projects](#2610-dependency-security-for-python-projects)
  - [2.6.11 Secure coding toolchain (recommended)](#2611-secure-coding-toolchain-recommended)
  - [2.6.12 Mini-projects (portfolio-grade, legal)](#2612-mini-projects-portfolio-grade-legal)
- [PART 3 — NETWORKING FUNDAMENTALS](#part-3-networking-fundamentals)
  - [3.1 OSI/TCP-IP with practical mapping](#31-ositcp-ip-with-practical-mapping)
  - [Most networking confusion is “layer confusion.”](#most-networking-confusion-is-layer-confusion)
  - [3.2 Ethernet & ARP](#32-ethernet-arp)
  - [ARP answers: “what MAC address has this IP on my local network?”](#arp-answers-what-mac-address-has-this-ip-on-my-local-network)
  - [3.3 IP, routing, NAT](#33-ip-routing-nat)
  - [Key concepts](#key-concepts)
  - [3.4 TCP and UDP](#34-tcp-and-udp)
  - [TCP](#tcp)
  - [3.5 DNS (deep fundamentals)](#35-dns-deep-fundamentals)
  - [DNS is both infrastructure and an attacker playground.](#dns-is-both-infrastructure-and-an-attacker-playground)
  - [3.6 HTTP and proxies](#36-http-and-proxies)
  - [HTTP basics](#http-basics)
  - [3.7 TLS/PKI (network view)](#37-tlspki-network-view)
  - [TLS goals](#tls-goals)
  - [3.8 Packet analysis workflow (Wireshark/tcpdump)](#38-packet-analysis-workflow-wiresharktcpdump)
  - [A practical workflow](#a-practical-workflow)
  - [3.9 Email security fundamentals (SPF/DKIM/DMARC)](#39-email-security-fundamentals-spfdkimdmarc)
  - [Email is still the #1 initial access vector.](#email-is-still-the-1-initial-access-vector)
- [PART 4 — APPLIED CRYPTOGRAPHY FUNDAMENTALS](#part-4-applied-cryptography-fundamentals)
  - [4.1 What crypto does and does NOT do](#41-what-crypto-does-and-does-not-do)
  - [Crypto is math that enforces properties, but only if used correctly.](#crypto-is-math-that-enforces-properties-but-only-if-used-correctly)
  - [4.2 Hashing vs encryption vs signatures](#42-hashing-vs-encryption-vs-signatures)
  - [Hashing](#hashing)
  - [4.3 Password storage and authentication](#43-password-storage-and-authentication)
  - [The correct pattern](#the-correct-pattern)
  - [4.4 Symmetric encryption and AEAD concepts](#44-symmetric-encryption-and-aead-concepts)
  - [Key concept](#key-concept)
  - [4.5 PKI and certificate validation](#45-pki-and-certificate-validation)
  - [What must be validated](#what-must-be-validated)
  - [4.6 Common crypto failures in real systems](#46-common-crypto-failures-in-real-systems)
  - [- “roll your own crypto”](#roll-your-own-crypto)
- [PART 5 — WEB + API SECURITY FUNDAMENTALS](#part-5-web-api-security-fundamentals)
  - [5.1 The web platform as a security boundary](#51-the-web-platform-as-a-security-boundary)
  - [Web is multi-layered:](#web-is-multi-layered)
  - [5.2 Sessions, cookies, SameSite, CSRF](#52-sessions-cookies-samesite-csrf)
  - [Sessions](#sessions)
  - [5.3 XSS and browser execution](#53-xss-and-browser-execution)
  - [XSS is “untrusted data becomes code.”](#xss-is-untrusted-data-becomes-code)
  - [5.4 Injection root causes](#54-injection-root-causes)
  - [SQL injection](#sql-injection)
  - [5.5 Access control (IDOR) and authorization thinking](#55-access-control-idor-and-authorization-thinking)
  - [AuthN vs AuthZ](#authn-vs-authz)
  - [5.6 SSRF and why cloud makes it worse](#56-ssrf-and-why-cloud-makes-it-worse)
  - [SSRF: server fetches attacker-controlled URLs.](#ssrf-server-fetches-attacker-controlled-urls)
  - [5.7 OAuth 2.0 + OpenID Connect basics](#57-oauth-20-openid-connect-basics)
  - [OAuth](#oauth)
  - [5.8 Secure API design fundamentals](#58-secure-api-design-fundamentals)
  - [- input validation](#input-validation)
- [PART 6 — DEFENSIVE SECURITY FUNDAMENTALS](#part-6-defensive-security-fundamentals)
  - [6.1 Logging fundamentals](#61-logging-fundamentals)
  - [Good logs are: structured, timestamped, correlated.](#good-logs-are-structured-timestamped-correlated)
  - [6.2 Detection engineering basics](#62-detection-engineering-basics)
  - [Key tradeoffs](#key-tradeoffs)
  - [6.3 Incident response fundamentals](#63-incident-response-fundamentals)
  - [First hour mindset](#first-hour-mindset)
  - [6.4 Vulnerability management fundamentals](#64-vulnerability-management-fundamentals)
  - [CVE](#cve)
- [PART 7 — FORENSICS FUNDAMENTALS](#part-7-forensics-fundamentals)
  - [7.1 Evidence thinking](#71-evidence-thinking)
  - [Separate:](#separate)
  - [7.2 Disk forensics overview](#72-disk-forensics-overview)
  - [- file timelines](#file-timelines)
  - [7.3 Memory forensics overview](#73-memory-forensics-overview)
  - [- running processes](#running-processes)
  - [7.4 Network forensics overview](#74-network-forensics-overview)
  - [- PCAP analysis](#pcap-analysis)
  - [7.5 Writing a forensic report](#75-writing-a-forensic-report)
  - [Report structure](#report-structure)
- [PART 8 — MALWARE & REVERSE ENGINEERING FUNDAMENTALS](#part-8-malware-reverse-engineering-fundamentals)
  - [8.1 Safe analysis environment](#81-safe-analysis-environment)
  - [- isolated VM](#isolated-vm)
  - [8.2 Static triage](#82-static-triage)
  - [- hash](#hash)
  - [8.3 Dynamic triage](#83-dynamic-triage)
  - [- process tree](#process-tree)
  - [8.4 Intro reversing](#84-intro-reversing)
  - [- find main logic](#find-main-logic)
  - [8.5 Reporting](#85-reporting)
  - [- behavior summary](#behavior-summary)
- [PART 9 — SECURITY ENGINEERING FUNDAMENTALS](#part-9-security-engineering-fundamentals)
  - [9.1 Threat modeling (DFD + STRIDE)](#91-threat-modeling-dfd-stride)
  - [Steps](#steps)
  - [9.2 Secure design principles](#92-secure-design-principles)
  - [- least privilege](#least-privilege)
  - [9.3 Secure SDLC](#93-secure-sdlc)
  - [- threat modeling in design](#threat-modeling-in-design)
  - [9.4 Supply chain security basics](#94-supply-chain-security-basics)
  - [- dependency trust](#dependency-trust)
- [PART 10 — CLOUD + CONTAINER FUNDAMENTALS](#part-10-cloud-container-fundamentals)
  - [10.1 Shared responsibility model](#101-shared-responsibility-model)
  - [Cloud provider vs customer responsibilities.](#cloud-provider-vs-customer-responsibilities)
  - [10.2 Cloud identity fundamentals](#102-cloud-identity-fundamentals)
  - [- roles/policies](#rolespolicies)
  - [10.3 Cloud networking fundamentals](#103-cloud-networking-fundamentals)
  - [- private networks](#private-networks)
  - [10.4 Storage + secrets](#104-storage-secrets)
  - [- public access pitfalls](#public-access-pitfalls)
  - [10.5 Containers vs VMs](#105-containers-vs-vms)
  - [- container isolation concepts](#container-isolation-concepts)
  - [10.6 Kubernetes vocabulary](#106-kubernetes-vocabulary)
  - [- cluster, node, pod](#cluster-node-pod)
- [PART 11 — AI/ML SECURITY FUNDAMENTALS](#part-11-aiml-security-fundamentals)
  - [11.1 AI for security vs security of AI](#111-ai-for-security-vs-security-of-ai)
  - [- AI for security: ML models help detect anomalies, classify malware/phishing](#ai-for-security-ml-models-help-detect-anomalies-classify-malwarephishing)
  - [11.2 Threats](#112-threats)
  - [- poisoning (training data compromised)](#poisoning-training-data-compromised)
  - [11.3 Defenses](#113-defenses)
  - [- provenance and integrity checks for data](#provenance-and-integrity-checks-for-data)
  - [11.4 Evaluate defenses honestly](#114-evaluate-defenses-honestly)
  - [- define threat model](#define-threat-model)
- [APPENDIX A — GLOSSARY (STARTER)](#appendix-a-glossary-starter)
- [AuthN / AuthZ](#authn-authz)
- [APPENDIX B — QUICK COMMAND REFERENCE (STARTER)](#appendix-b-quick-command-reference-starter)
- [Linux](#linux)
- [APPENDIX C — MINI-QUIZ ANSWER KEYS](#appendix-c-mini-quiz-answer-keys)
- [(Write your answers first. Only then check references. Keep answers in your notes.)](#write-your-answers-first-only-then-check-references-keep-answers-in-your-notes)
- [APPENDIX D — CURATED RESOURCES (COURSES, YOUTUBE, LABS, DATASETS)](#appendix-d-curated-resources-courses-youtube-labs-datasets)
- [Core references](#core-references)
  - [Core Python docs (read these like reference manuals)](#core-python-docs-read-these-like-reference-manuals)
- [APPENDIX E — PORTFOLIO ARTIFACTS (EVIDENCE OF FUNDAMENTALS)](#appendix-e-portfolio-artifacts-evidence-of-fundamentals)
- [Create 6 artifacts (these prove fundamentals better than certificates):](#create-6-artifacts-these-prove-fundamentals-better-than-certificates)
- [EXTENDED CHAPTER NOTES (DEEP DIVE)](#extended-chapter-notes-deep-dive)
- [This section turns the earlier chapters into “study notes” you can read like a textbook.](#this-section-turns-the-earlier-chapters-into-study-notes-you-can-read-like-a-textbook)
  - [X1) Linux deep dive: investigation-first Linux](#x1-linux-deep-dive-investigation-first-linux)
  - [Mindset: Linux for security is about answering questions quickly with evidence.](#mindset-linux-for-security-is-about-answering-questions-quickly-with-evidence)
  - [X2) Windows deep dive: telemetry-first Windows](#x2-windows-deep-dive-telemetry-first-windows)
  - [Mindset: Windows security work is usually “evidence-driven.” You don’t just suspect; you prove.](#mindset-windows-security-work-is-usually-evidence-driven-you-dont-just-suspect-you-prove)
  - [X3) Active Directory deep dive (high-level, but precise)](#x3-active-directory-deep-dive-high-level-but-precise)
  - [AD is where identity becomes operational.](#ad-is-where-identity-becomes-operational)
  - [X4) Networking deep dive: how to read traffic like a story](#x4-networking-deep-dive-how-to-read-traffic-like-a-story)
  - [Packet analysis skill is a career multiplier.](#packet-analysis-skill-is-a-career-multiplier)
  - [X5) Applied crypto deep dive: use it safely, recognize broken designs](#x5-applied-crypto-deep-dive-use-it-safely-recognize-broken-designs)
  - [Crypto is easy to misuse. Your job is to know the standard safe patterns.](#crypto-is-easy-to-misuse-your-job-is-to-know-the-standard-safe-patterns)
  - [X6) Web security deep dive: root causes + evidence + mitigation](#x6-web-security-deep-dive-root-causes-evidence-mitigation)
  - [Web security is mostly about trust boundaries + parsing.](#web-security-is-mostly-about-trust-boundaries-parsing)
  - [X7) Defensive operations deep dive: what employers expect](#x7-defensive-operations-deep-dive-what-employers-expect)
  - [Most entry-level security roles reward:](#most-entry-level-security-roles-reward)
  - [X8) Forensics deep dive: report writing](#x8-forensics-deep-dive-report-writing)
  - [Forensics is as much writing as it is tooling.](#forensics-is-as-much-writing-as-it-is-tooling)
  - [X9) Malware/reversing deep dive: safe workflow and triage](#x9-malwarereversing-deep-dive-safe-workflow-and-triage)
  - [Do not begin with “full reverse engineering.” Start with triage.](#do-not-begin-with-full-reverse-engineering-start-with-triage)
- [FULL COVERAGE MODULES (TEXTBOOK-STYLE)](#full-coverage-modules-textbook-style)
- [These modules go deeper than the earlier chapters. Use them as your main reading.](#these-modules-go-deeper-than-the-earlier-chapters-use-them-as-your-main-reading)
- [MODULE A — SECURITY FOUNDATIONS (MENTAL MODELS)](#module-a-security-foundations-mental-models)
  - [Most security failures happen at boundaries:](#most-security-failures-happen-at-boundaries)
  - [When you describe an attack, always specify:](#when-you-describe-an-attack-always-specify)
  - [Preventive controls:](#preventive-controls)
- [MODULE B — COMPUTER ARCHITECTURE & OS INTERNALS (SECURITY VIEW)](#module-b-computer-architecture-os-internals-security-view)
  - [Core idea: modern OS security is built on privilege separation.](#core-idea-modern-os-security-is-built-on-privilege-separation)
  - [Definitions you must be able to explain:](#definitions-you-must-be-able-to-explain)
  - [Concepts:](#concepts)
  - [The syscall boundary is a critical security boundary.](#the-syscall-boundary-is-a-critical-security-boundary)
  - [Key ideas:](#key-ideas)
  - [Concepts](#concepts)
  - [IPC exists because processes need to cooperate.](#ipc-exists-because-processes-need-to-cooperate)
  - [Time](#time)
- [MODULE C — LINUX FUNDAMENTALS (ADMIN + AUDITING)](#module-c-linux-fundamentals-admin-auditing)
  - [Key structures:](#key-structures)
  - [systemd basics:](#systemd-basics)
  - [Key skills:](#key-skills)
  - [DAC (traditional permissions)](#dac-traditional-permissions)
  - [Why it matters](#why-it-matters)
- [MODULE D — WINDOWS FUNDAMENTALS (INTERNALS + TELEMETRY)](#module-d-windows-fundamentals-internals-telemetry)
  - [Core objects:](#core-objects)
  - [Common autostart categories:](#common-autostart-categories)
  - [Sysmon produces events; it does not “detect malware” by itself.](#sysmon-produces-events-it-does-not-detect-malware-by-itself)
  - [Goal: know what kinds of events exist and what questions they answer.](#goal-know-what-kinds-of-events-exist-and-what-questions-they-answer)
  - [- NTLM vs Kerberos: where each is used and why Kerberos is preferred.](#ntlm-vs-kerberos-where-each-is-used-and-why-kerberos-is-preferred)
- [MODULE E — ACTIVE DIRECTORY (FOUNDATIONAL ENTERPRISE IDENTITY)](#module-e-active-directory-foundational-enterprise-identity)
  - [LDAP is a directory protocol (query objects). Kerberos is authentication (prove identity).](#ldap-is-a-directory-protocol-query-objects-kerberos-is-authentication-prove-identity)
  - [Kerberos is ticket-based.](#kerberos-is-ticket-based)
  - [- Users: human or service identities](#users-human-or-service-identities)
  - [When investigating AD-centric incidents, ask:](#when-investigating-ad-centric-incidents-ask)
  - [Goal: make OS knowledge measurable. This checklist focuses on “questions you can answer with evidence.”](#goal-make-os-knowledge-measurable-this-checklist-focuses-on-questions-you-can-answer-with-evidence)
  - [I can answer, with evidence:](#i-can-answer-with-evidence)
  - [I can answer, with evidence:](#i-can-answer-with-evidence)
  - [I can answer, with evidence:](#i-can-answer-with-evidence)
  - [High confidence:](#high-confidence)
- [MODULE F — NETWORKING FUNDAMENTALS (FULL COVERAGE)](#module-f-networking-fundamentals-full-coverage)
  - [By the end of networking fundamentals, you should be able to:](#by-the-end-of-networking-fundamentals-you-should-be-able-to)
  - [You should be able to explain each in one paragraph:](#you-should-be-able-to-explain-each-in-one-paragraph)
  - [Devices](#devices)
  - [Core concepts](#core-concepts)
  - [Concepts](#concepts)
  - [Ethernet](#ethernet)
  - [ICMP](#icmp)
  - [IPv4](#ipv4)
  - [NAT hides internal addresses behind a public IP.](#nat-hides-internal-addresses-behind-a-public-ip)
  - [Core concepts](#core-concepts)
  - [TCP essentials](#tcp-essentials)
  - [Core concepts](#core-concepts)
  - [You must understand](#you-must-understand)
  - [What to understand](#what-to-understand)
  - [Why VPNs matter](#why-vpns-matter)
  - [You should recognize and be able to discuss hardening/telemetry for:](#you-should-recognize-and-be-able-to-discuss-hardeningtelemetry-for)
  - [Wi‑Fi matters because it is often the “real perimeter” in offices and campuses.](#wifi-matters-because-it-is-often-the-real-perimeter-in-offices-and-campuses)
  - [Common telemetry sources](#common-telemetry-sources)
- [MODULE P — PROTOCOL ENCYCLOPEDIA (PURPOSE, DEFAULT PORTS, RISKS, TELEMETRY)](#module-p-protocol-encyclopedia-purpose-default-ports-risks-telemetry)
- [This section is a quick reference. Memorize purpose + failure modes; keep ports as “familiar,” not holy.](#this-section-is-a-quick-reference-memorize-purpose-failure-modes-keep-ports-as-familiar-not-holy)
  - [For each protocol, learn:](#for-each-protocol-learn)
  - [LDAP (389/TCP,UDP; LDAPS 636/TCP)](#ldap-389tcpudp-ldaps-636tcp)
  - [WebSockets (typically over 443/TCP)](#websockets-typically-over-443tcp)
  - [These frequently appear in real environments and incidents.](#these-frequently-appear-in-real-environments-and-incidents)
  - [Use this checklist for EACH protocol you study. If you can’t answer these, you don’t “own” the protocol yet.](#use-this-checklist-for-each-protocol-you-study-if-you-cant-answer-these-you-dont-own-the-protocol-yet)
- [MODULE G — APPLIED CRYPTOGRAPHY (FULL COVERAGE)](#module-g-applied-cryptography-full-coverage)
  - [Before choosing crypto, specify:](#before-choosing-crypto-specify)
  - [Correct design:](#correct-design)
  - [In transit: TLS](#in-transit-tls)
- [MODULE H — WEB + API SECURITY (FULL COVERAGE)](#module-h-web-api-security-full-coverage)
  - [Data sources you must always treat as untrusted:](#data-sources-you-must-always-treat-as-untrusted)
  - [This is the #1 most important web security concept.](#this-is-the-1-most-important-web-security-concept)
  - [Same-Origin Policy](#same-origin-policy)
  - [Broken Access Control (OWASP A01)](#broken-access-control-owasp-a01)
  - [You should be able to draw:](#you-should-be-able-to-draw)
- [MODULE I — DEFENSIVE SECURITY (SOC, DETECTION, IR)](#module-i-defensive-security-soc-detection-ir)
  - [Good defenders:](#good-defenders)
  - [If you log only one thing, log authentication events.](#if-you-log-only-one-thing-log-authentication-events)
  - [Write detections as:](#write-detections-as)
  - [Phases:](#phases)
  - [What CVSS doesn’t capture well:](#what-cvss-doesnt-capture-well)
- [MODULE J — FORENSICS (DISK, MEMORY, NETWORK)](#module-j-forensics-disk-memory-network)
  - [Your output is a narrative supported by evidence.](#your-output-is-a-narrative-supported-by-evidence)
  - [- Disk: what was stored and executed](#disk-what-was-stored-and-executed)
  - [- Summary](#summary)
- [MODULE K — MALWARE & REVERSE ENGINEERING](#module-k-malware-reverse-engineering)
  - [Don’t start with deep reversing.](#dont-start-with-deep-reversing)
  - [- isolate the VM](#isolate-the-vm)
  - [- a clean behavior report](#a-clean-behavior-report)
- [MODULE L — SECURITY ENGINEERING & SECURE SDLC](#module-l-security-engineering-secure-sdlc)
  - [Deliverable:](#deliverable)
  - [Design:](#design)
- [MODULE M — CLOUD & CONTAINERS (PRE-CLOUDSEC)](#module-m-cloud-containers-pre-cloudsec)
  - [Always ask:](#always-ask)
  - [Most cloud breaches are identity and misconfiguration.](#most-cloud-breaches-are-identity-and-misconfiguration)
  - [- image supply chain](#image-supply-chain)
- [MODULE N — AI/ML SECURITY (PRE-AISEC)](#module-n-aiml-security-pre-aisec)
  - [Pipeline components:](#pipeline-components)
- [MODULE O — CODING FOR SECURITY WITH PYTHON (FULL COVERAGE)](#module-o-coding-for-security-with-python-full-coverage)
  - [Security bugs are rarely “missing a library.” They’re usually:](#security-bugs-are-rarely-missing-a-library-theyre-usually)
  - [This pattern prevents many bug classes.](#this-pattern-prevents-many-bug-classes)
  - [Rules](#rules)
  - [Common failure mode](#common-failure-mode)
  - [Rules](#rules)
  - [Things that cause real breaches](#things-that-cause-real-breaches)
  - [Security-relevant logging should include](#security-relevant-logging-should-include)
  - [Security is reliability under adversarial input.](#security-is-reliability-under-adversarial-input)
  - [Checklist](#checklist)
  - [Minimum](#minimum)
- [END OF STUDY MATERIAL](#end-of-study-material)

---

## Table of Contents
### PART 0: Orientation
### 0.1 Threat thinking and security vocabulary
### 0.2 Security outcomes (CIA+) and the “control stack”
### 0.3 The security learning stack (systems → network → app → cloud → AI)

## PART 1: Systems Fundamentals
### 1.1 Computer architecture for security (CPU, memory, privilege)
### 1.2 Operating system fundamentals (processes, syscalls, filesystems)
### 1.3 Linux fundamentals for security (admin + auditing)
### 1.4 Windows fundamentals for security (internals + telemetry)
### 1.5 Identity fundamentals: Active Directory (high-level but job-critical)

## PART 2: Programming Foundations for Security
### 2.1 Python for security automation
### 2.2 Bash fundamentals (safe scripting)
### 2.3 PowerShell fundamentals (defender-grade)
### 2.4 C/memory model fundamentals (for vuln intuition)
### 2.5 Reading assembly (enough for reversing)
### 2.6 Coding for security (Python): secure coding + security tooling

## PART 3: Networking Fundamentals
### 3.1 OSI/TCP-IP with practical mapping
### 3.2 Ethernet & ARP
### 3.3 IP, routing, NAT
### 3.4 TCP and UDP
### 3.5 DNS (deep fundamentals)
### 3.6 HTTP and proxies
### 3.7 TLS/PKI (network view)
### 3.8 Packet analysis workflow (Wireshark/tcpdump)
### 3.9 Email security fundamentals (SPF/DKIM/DMARC)

## PART 4: Applied Cryptography Fundamentals
### 4.1 What crypto does and does NOT do
### 4.2 Hashing vs encryption vs signatures
### 4.3 Password storage and authentication
### 4.4 Symmetric encryption and AEAD concepts
### 4.5 PKI and certificate validation
### 4.6 Common crypto failures in real systems

## PART 5: Web + API Security Fundamentals
### 5.1 The web platform as a security boundary
### 5.2 Sessions, cookies, SameSite, CSRF
### 5.3 XSS and browser execution
### 5.4 Injection (SQL/NoSQL/command) root causes
### 5.5 Access control (IDOR) and authorization thinking
### 5.6 SSRF and why cloud makes it worse
### 5.7 OAuth 2.0 + OpenID Connect basics
### 5.8 Secure API design fundamentals

## PART 6: Defensive Security Fundamentals
### 6.1 Logging fundamentals (what to log, how to reason)
### 6.2 Detection engineering basics (signals, baselines, FP/FN)
### 6.3 Incident response fundamentals (first hour, containment)
### 6.4 Vulnerability management fundamentals (CVE/CVSS, prioritization)

## PART 7: Forensics Fundamentals
### 7.1 Evidence thinking: facts vs interpretations
### 7.2 Disk forensics overview
### 7.3 Memory forensics overview
### 7.4 Network forensics overview
### 7.5 Writing a forensic report

## PART 8: Malware & Reverse Engineering Fundamentals
### 8.1 Safe analysis environment
### 8.2 Static triage
### 8.3 Dynamic triage
### 8.4 Intro reversing (Ghidra/x64dbg)
### 8.5 Reporting: behavior, IOCs, confidence

## PART 9: Security Engineering Fundamentals
### 9.1 Threat modeling (DFD + STRIDE)
### 9.2 Secure design principles (least privilege, defense in depth)
### 9.3 Secure SDLC (SAST/DAST, deps, secrets, SBOM)
### 9.4 Supply chain security basics

## PART 10: Cloud + Container Fundamentals (pre-CloudSec)
### 10.1 Shared responsibility model
### 10.2 Cloud identity fundamentals
### 10.3 Cloud networking fundamentals
### 10.4 Storage + secrets fundamentals
### 10.5 Containers vs VMs and image supply chain
### 10.6 Kubernetes vocabulary (very high-level)

## PART 11: AI/ML Security Fundamentals (pre-AISec)
### 11.1 AI for security vs security of AI
### 11.2 Threats: poisoning, evasion, extraction, privacy leakage
### 11.3 Defenses: pipeline integrity, monitoring, rate limiting
### 11.4 How to evaluate ML defenses honestly

APPENDICES
  A) Glossary (must-know terms)
  B) Quick command reference (Linux/Windows/network)
  C) Mini-quiz answer keys
  D) Curated resources (Coursera, YouTube, labs, datasets)
  E) Portfolio artifacts (what employers actually value)


PRIMARY TEXTS (THE “BEST BOOKS” LIST) + HOW TO READ THEM
### You asked for “very good texts to study from.” Use this as a curated library.
You do NOT need to read everything cover-to-cover; the point is to have the
right references when you go deep.

Systems & OS fundamentals
- Operating Systems: Three Easy Pieces (OSTEP) — free online textbook
  [https://pages.cs.wisc.edu/~remzi/OSTEP/](https://pages.cs.wisc.edu/~remzi/OSTEP/)
- Computer Systems: A Programmer’s Perspective (CS:APP) — for processes, memory, linking
  (Paid book; widely used in top universities)
- Windows Internals (Parts 1 & 2) — the definitive Windows internals reference
  (Paid book)

Networking
- Computer Networking: A Top-Down Approach (Kurose/Ross) — best structured networking book
  (Paid book)

Applied cryptography
- Cryptography and Network Security (Stallings) — strong systems + protocol view
  (Paid book)
- “Cryptography” (Katz) — foundations-level course/text alignment
  (Often paired with the Coursera course)

Web security
- OWASP Cheat Sheet Series — practical defensive guidance
  [https://cheatsheetseries.owasp.org/](https://cheatsheetseries.owasp.org/)
- OWASP ASVS — requirements-oriented view of web security
  [https://owasp.org/www-project-application-security-verification-standard/](https://owasp.org/www-project-application-security-verification-standard/)

Malware / reversing
- Practical Malware Analysis — excellent workflow for triage and reversing
  (Paid book)

Incident response & logging
- NIST SP 800-61 Rev. 3 — Incident Handling Guide
  [https://csrc.nist.gov/pubs/sp/800/61/r3/final](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- NIST SP 800-92 — Log Management
  [https://csrc.nist.gov/publications/detail/sp/800-92/final](https://csrc.nist.gov/publications/detail/sp/800-92/final)

How to read effectively (important)
1) Read one chapter.
2) Produce one artifact (PCAP write-up, detection note, or threat model).
3) Summarize the chapter in 10 bullet points.
4) Write 5 flashcards.
5) Do the end-of-chapter questions in this document.


## PART 0 — ORIENTATION

### 0.1 Threat thinking and security vocabulary
### Security is NOT “using tools.” Security is: controlling risk under adversarial
pressure.

Core idea: every system has
- assets (what matters),
- entry points (where inputs come from),
- trust boundaries (where assumptions change),
- attackers (capabilities and goals),
- controls (what reduces risk),
- telemetry (what proves what happened).

Key definitions (write these in your own words):
- Threat: a potential cause of an unwanted incident.
- Vulnerability: a weakness that could be exploited.
- Exploit: a method that triggers a vulnerability to achieve impact.
- Risk: likelihood × impact (but also consider exposure and detectability).
- Control: a safeguard (preventive/detective/corrective).

Example (simple):
Asset: user accounts
Entry point: login form
Trust boundary: internet → app server
Threat: credential stuffing
Vulnerability: weak rate-limiting + password reuse
Impact: account takeover
Controls: MFA, rate limiting, anomaly detection, password hashing
Telemetry: auth logs, IP reputation, device fingerprint

Mini-quiz (0.1)
- Q1: Give one example where there is a threat but no vulnerability.
- Q2: Explain why “no logs” is a security problem.


### 0.2 Security outcomes (CIA+) and the control stack
### CIA triad:
- Confidentiality: prevent unauthorized disclosure
- Integrity: prevent unauthorized modification
- Availability: keep systems usable

CIA+ outcomes you must care about:
- Authenticity: data is from who it claims
- Accountability/Non-repudiation: actions can be traced
- Privacy: appropriate use of personal data
- Safety: physical harm avoidance (IoT/critical systems)

Control stack (think layers):
- Governance: policy, training, risk management
- Identity: authN/authZ, least privilege
- Endpoint: hardening, patching, EDR
- Network: segmentation, firewalling, monitoring
- Application: input validation, secure design, SDLC
- Data: encryption, key mgmt, backups
- Detection/Response: logs, SIEM, IR playbooks

Mini-quiz (0.2)
- Q1: Give one control that improves integrity but not confidentiality.
- Q2: Give one control that improves availability but may reduce confidentiality.


### 0.3 The security learning stack (why the order matters)
### You cannot do deep AppSec or CloudSec without:
- networking (packet-level intuition)
- OS fundamentals (processes, permissions, logs)
- identity fundamentals (auth boundaries)

This is why tools-first learning creates “fragile knowledge.”


## PART 1 — SYSTEMS FUNDAMENTALS

### 1.1 Computer architecture for security
### Why it matters: many high-impact bugs are “low-level behaviors made unsafe.”

Concepts
- User mode vs kernel mode
  - User mode: apps run with limited privileges
  - Kernel mode: OS core runs with hardware privileges
  - Security boundary: syscalls

- CPU basics (security view)
  - Instruction pointer: where execution continues
  - Registers: hold operands and addresses
  - Calling conventions: how functions pass args/return

- Memory model
  - Stack: function call frames, local variables
  - Heap: dynamic allocation
  - Virtual memory: processes see “virtual addresses” mapped to physical pages

Security implications
- Memory corruption can redirect execution.
- Isolation is partly enforced by virtual memory + privilege.

Hands-on exercises (safe)
- In Linux VM: run a benign program and observe syscalls using strace.
- In Windows VM: watch a program’s file/registry behavior using Procmon.

Mini-quiz (1.1)
- Q1: Why does ASLR help against exploitation?
- Q2: Why does NX/DEP help?


### 1.2 Operating system fundamentals
### Core building blocks
- Processes & threads
  - Process: resource container + address space
  - Thread: execution within a process

- System calls
  - The API boundary from application to kernel

- Filesystems
  - Files + metadata + permissions
  - Links: hard vs symbolic

- Permissions vs privileges
  - Permissions: what objects allow you to do
  - Privileges: special rights (e.g., debug privilege)

Exercise
- Map “open a file → read it → send it over network” as:
  application call → OS API → syscall → kernel action.

Mini-quiz (1.2)
- Q1: What is a “handle” (Windows) or “file descriptor” (Linux)?
- Q2: Why do we care about parent/child processes?


### 1.3 Linux fundamentals for security (admin + auditing)
### Linux is the language of servers, cloud, and security appliances.
You want “operational fluency”: the ability to answer investigation questions.

### 1.3.1 Filesystem landmarks
- /etc: configuration
- /var: variable data (logs!)
- /home: user homes
- /proc: process and kernel info (virtual)
- /tmp: temporary files (often abused)

### 1.3.2 Users, groups, and permissions
- /etc/passwd: user entries
- /etc/shadow: password hashes (root only)
- sudoers: who can run privileged commands

Permissions model
- rwx for user/group/others
- setuid/setgid bits (risk hotspots)
- sticky bit on shared dirs
- ACLs: fine-grained permissions

### 1.3.3 Service management and logs
- systemd units (services)
- journald logs: journalctl queries

Investigation questions you must answer
- What processes are running? What started them?
- What ports are listening, and which process owns them?
- Who logged in? When? From where?
- What changed on disk recently?

Exercises
- Build a baseline audit script (bash) that prints:
  - users with login shells
  - members of sudo group
  - listening ports and owning processes
  - last 50 auth events
  - cron jobs for users and system

Mini-quiz (1.3)
- Q1: Why is /proc useful during an incident?
- Q2: What is the security risk of setuid binaries?


### 1.4 Windows fundamentals for security (internals + telemetry)
### Windows dominates enterprise endpoints, and its logging surface is huge.

### 1.4.1 Core concepts (security view)
- Processes and services
- Registry (configuration + persistence)
- SIDs and security descriptors (conceptual)
- Access tokens and integrity levels (conceptual)
- UAC: reduces accidental elevation, not a full security boundary

### 1.4.2 Telemetry fundamentals
- Windows Event Logs
  - Security log: authentication and privilege events (key for IR)

- Sysmon (System Monitor)
  - Adds high-value events: process creation with command line, network
    connections, file/registry changes (depending on config)

- Sysinternals suite
  - Process Explorer: process tree + handles
  - Autoruns: persistence locations
  - Procmon: file/registry/process activity

Exercises (VM recommended)
- Install Sysmon and generate activity:
  - start processes, open browser, download a file
  - find and explain the corresponding events
- Use Procmon:
  - filter for a process, identify file writes and registry reads

Mini-quiz (1.4)
- Q1: What question does Sysmon Event ID 1 help you answer?
- Q2: Why is command line logging valuable?


### 1.5 Identity fundamentals: Active Directory (high-level, job-critical)
### AD is not “advanced.” It’s the center of enterprise security.

AD concepts
- Domain: administrative boundary
- Domain Controller (DC): runs directory + authentication services
- LDAP: directory protocol (query and manage objects)
- Kerberos: primary auth protocol in AD
- NTLM: older auth protocol (riskier; still exists)

Objects
- users, groups, computers
- OUs (organizational units)
- GPOs (Group Policy Objects)

Common security failure modes (defensive view)
- Over-privileged groups (too many admins)
- Weak service account practices
- Poor logging and auditing
- Credential reuse and lateral movement opportunities

Exercise (optional AD lab)
- Build DC + workstation lab and observe:
  - login events
  - group membership changes
  - scheduled task creation

Mini-quiz (1.5)
- Q1: What is the difference between directory queries (LDAP) and authentication (Kerberos)?
- Q2: Why is time synchronization important for Kerberos?


## PART 2 — PROGRAMMING FOUNDATIONS FOR SECURITY

### 2.1 Python for security automation
### Goal: turn messy evidence into structured insight.

What to learn
- Files: read/write safely, rotate outputs
- Parsing: JSON/CSV, regular expressions
- Networking: HTTP clients, basic sockets
- Subprocess: run commands safely (avoid shell injection)
- Logging: structured logs (JSON lines)

Exercises
- Build a log parser:
  - input: auth log sample (Linux) or exported Windows events
  - output: top IPs, failure spikes, unusual login times
- Build a tiny “PCAP metadata extractor” (optional):
  - read tshark output and summarize flows

Mini-quiz (2.1)
- Q1: Why is calling shell=True risky?
- Q2: What is the difference between parsing and “string searching” for investigation?


### 2.2 Bash fundamentals (safe scripting)
### What to learn
- quoting rules (single vs double quotes)
- pipes and exit codes
- safe flags: set -euo pipefail
- safe temp files

Exercise
- Write a system audit script that produces a single report file.

Mini-quiz (2.2)
- Q1: What does “word splitting” mean in bash and why is it dangerous?


### 2.3 PowerShell fundamentals (defender-grade)
### What to learn
- objects vs strings in pipeline
- Get-WinEvent filtering
- exporting results for evidence

Exercise
- Query logon events and summarize:
  - users, machines, timestamps

Mini-quiz (2.3)
- Q1: Why is PowerShell object output useful for investigations?


### 2.4 C/memory model fundamentals
### Purpose: understand why memory bugs exist and how mitigations work.

What to learn
- pointers and arrays
- stack frames
- heap allocation/free
- integer overflow basics

Safe lab idea
- Use intentionally vulnerable training binaries in a VM.

Mini-quiz (2.4)
- Q1: Why can an out-of-bounds write lead to code execution?


### 2.5 Reading assembly (enough for reversing)
### What to learn
- how functions are called in x64
- stack usage
- common patterns (loops, comparisons)

Mini-quiz (2.5)
- Q1: What is the purpose of function prologue/epilogue?


### 2.6 Coding for security (Python): secure coding + security tooling
### Goal: write Python that is safe by default, resilient to untrusted input, and useful for security work.

Two complementary skills
1) Secure coding: prevent vulnerabilities in software you build.
2) Security tooling: write scripts/tools that analyze, detect, and audit systems.

### 2.6.1 Secure coding principles (Python-specific)
- Treat ALL external data as untrusted:
  - CLI args, env vars, files, HTTP requests, headers, DB rows, message queues
- Validate at the boundary:
  - parse → validate → normalize → then use
- Avoid “stringly-typed” security decisions:
  - avoid splitting strings to infer identity/roles; prefer explicit fields
- Make security visible:
  - log security events (auth failures, admin actions, suspicious input)
- Fail closed when unsure:
  - default to deny/stop when validation or authorization is uncertain

### 2.6.2 Input validation and normalization
Why it matters: injection, path traversal, SSRF, and logic bugs often begin here.

Core patterns
- Parse into a structured type early:
  - URLs: use urllib.parse
  - IPs/subnets: ipaddress
  - JSON: json.loads (then validate schema)
- Normalize once:
  - normalize paths before checks
  - normalize case/whitespace rules explicitly
- Prefer allowlists over denylists when possible.

Practice exercises (safe)
- Write a Python function that validates:
  - email addresses (basic sanity)
  - URLs allowed to be fetched (block internal IP ranges)
  - file paths allowed under a root directory
Then write tests for both expected inputs and tricky edge cases.

### 2.6.3 Safe file handling
Common pitfalls
- trusting user-provided filenames
- writing to predictable temp paths
- unsafe permissions for secrets

Best practices
- Use tempfile for temp files/dirs.
- For secrets/config: use least-privilege permissions and avoid world-readable files.
- When parsing untrusted files, enforce size limits and timeouts (where applicable).

### 2.6.4 Subprocess and command execution safety
Why it matters: command injection is one of the most dangerous bug classes.

Rules
- Avoid invoking shells; prefer direct argument arrays.
- Never build commands by string concatenation with untrusted input.
- If you must call external tools:
  - validate inputs
  - use explicit argument lists
  - capture output safely
  - enforce timeouts

### 2.6.5 Safe serialization and parsing
Avoid
- pickle for untrusted data (code execution risk)

Prefer
- JSON with schema validation
- well-defined formats with strict parsing

### 2.6.6 Authentication, authorization, and sessions (coding view)
Key distinctions
- AuthN: establishing identity
- AuthZ: enforcing permissions

Common implementation pitfalls
- trusting client-side claims (e.g., “role=admin”)
- missing object-level authorization checks
- insecure password reset flows

Exercise (design)
- Write a mini spec for an API endpoint:
  - inputs
  - auth requirement
  - authorization rules
  - logging
  - rate limiting
Then implement a small toy service locally (Flask/FastAPI optional) and test it.

### 2.6.7 Cryptography in Python (use, don’t invent)
Rules
- Do not implement crypto primitives yourself.
- Use widely-reviewed libraries (e.g., `cryptography`) and standard patterns.
- Separate keys from code:
  - use environment variables or a secret manager (in real systems)
  - rotate keys

Exercise (safe)
- Implement file integrity verification using:
  - hashes (sha256) for integrity checks
  - HMAC for authenticity (shared secret)
Then demonstrate tampering detection.

### 2.6.8 Network programming for defenders (safe)
Build “observation tools,” not exploitation.

Ideas
- DNS resolver audit: resolve domains, record TTLs and IPs
- HTTP header analyzer: fetch safe URLs and report security headers
- Log normalizer: ingest many log formats and emit JSON lines

### 2.6.9 Logging, telemetry, and evidence quality
Goals
- make investigations possible
- avoid leaking secrets

Rules
- Do not log secrets (passwords, tokens, private keys).
- Log identifiers needed for correlation:
  - timestamp (UTC), request ID, user ID, source IP, action, outcome
- Prefer structured logs.

### 2.6.10 Dependency security for Python projects
Why it matters: supply chain failures are common.

Practices
- Pin dependencies (requirements with versions) when appropriate.
- Audit dependencies for known vulnerabilities.
- Use a virtual environment.

### 2.6.11 Secure coding toolchain (recommended)
- Formatting: black
- Linting: ruff
- Type checking: mypy (optional but high ROI)
- Testing: pytest
- Security linting: bandit
- Dependency vulnerability scan: pip-audit
- Pattern scanning: semgrep (security rules)

### 2.6.12 Mini-projects (portfolio-grade, legal)
Pick 3 and do them well (clean README + tests + sample data):
1) Log parser + anomaly summaries
2) PCAP metadata summarizer (wrap tshark output)
3) URL fetch allowlist validator (SSRF-safe fetcher)
4) “Security headers” scanner for your own local apps
5) Password hashing demo (Argon2/bcrypt) + rate limiting simulation

Mini-quiz (2.6)
- Q1: Why is `pickle` unsafe for untrusted input?
- Q2: What’s the difference between validation and normalization?
- Q3: Why should you avoid logging tokens?
- Q4: Name 3 ways dependency risk shows up in Python projects.


## PART 3 — NETWORKING FUNDAMENTALS

### 3.1 OSI/TCP-IP with practical mapping
### Most networking confusion is “layer confusion.”

Practical mapping
- Link layer: Ethernet frames, MAC addresses
- Network layer: IP, routing
- Transport layer: TCP/UDP
- Application layer: HTTP, DNS, SMTP, SSH

Mini-quiz (3.1)
- Q1: At which layer does NAT operate conceptually?


### 3.2 Ethernet & ARP
### ARP answers: “what MAC address has this IP on my local network?”

Security relevance
- ARP spoofing enables man-in-the-middle on local networks (conceptual)
- Defenders watch for ARP anomalies and unexpected gateway changes

Exercise
- In your lab, capture ARP traffic and identify:
  - who asks, who answers


### 3.3 IP, routing, NAT
### Key concepts
- IP addressing and CIDR
- routing tables: where packets go
- NAT: many internal hosts share one public IP

Security relevance
- attribution challenges (NAT hides internal origin)
- segmentation reduces lateral movement

Exercise
- Use traceroute (or Windows tracert) and explain each hop.


### 3.4 TCP and UDP
### TCP
- handshake: SYN → SYN/ACK → ACK
- reliable: retransmissions, windowing
- teardown: FIN/ACK or RST

UDP
- connectionless
- used by DNS, some streaming, QUIC (conceptual)

Security relevance
- scanning fingerprints (SYN scans conceptually)
- session reconstruction in PCAPs

Exercise
- Capture a TCP handshake and annotate it.


### 3.5 DNS (deep fundamentals)
### DNS is both infrastructure and an attacker playground.

Core concepts
- recursive resolver vs authoritative server
- record types: A/AAAA, CNAME, MX, TXT, NS
- caching and TTL

Security relevance
- DNS used for C2, phishing, and exfil patterns
- defenders use DNS logs for early warning

Exercise
- Capture DNS queries for visiting a domain and explain:
  - which query happens, what response means


### 3.6 HTTP and proxies
### HTTP basics
- request line: method + path
- headers: Host, User-Agent, Authorization, Cookie
- response: status, headers, body

Proxies/caches/CDNs
- can change where secrets leak
- can cause cache-related vulnerabilities

Exercise
- Use browser devtools or Burp (legal lab) to observe:
  - cookies and headers


### 3.7 TLS/PKI (network view)
### TLS goals
- confidentiality + integrity in transit

Certificate chain
- server cert signed by intermediate(s) signed by a root CA

SNI
- server name indication (helps hosting multiple domains)

Exercise
- Use openssl s_client to inspect certificate chain.


### 3.8 Packet analysis workflow (Wireshark/tcpdump)
### A practical workflow
1) Identify endpoints (IPs) and timeline
2) Identify protocols
3) Follow streams (HTTP/TCP)
4) Look for anomalies:
   - repeated beacons
   - unusual DNS
   - odd TLS SNI
   - rare ports

Exercise
- Download a safe training PCAP and write a 1-page report:
  - who talked to whom, when, why it is suspicious (or not)


### 3.9 Email security fundamentals (SPF/DKIM/DMARC)
### Email is still the #1 initial access vector.

Threats
- phishing, credential harvesting
- malicious attachments
- BEC (business email compromise)

SPF/DKIM/DMARC (conceptual)
- SPF: which IPs are allowed to send for a domain
- DKIM: cryptographic signature of message parts
- DMARC: policy that ties SPF/DKIM alignment + reporting

Exercise
- Take a training phishing email, analyze headers:
  - Received chain
  - From vs Return-Path
  - SPF/DKIM results (if present)


## PART 4 — APPLIED CRYPTOGRAPHY FUNDAMENTALS

### 4.1 What crypto does and does NOT do
### Crypto is math that enforces properties, but only if used correctly.

- Encryption protects confidentiality
- Hashing protects integrity (tamper evidence)
- Signatures protect authenticity/integrity (depending on protocol)

Crypto DOES NOT automatically:
- secure your application logic
- prevent malware on endpoints
- fix broken access control


### 4.2 Hashing vs encryption vs signatures
### Hashing
- one-way function
- used for integrity checks and password storage (with KDF)

Encryption
- reversible with key

Signatures
- private key signs, public key verifies

Exercise
- Use OpenSSL to:
  - hash a file
  - sign a file
  - verify the signature


### 4.3 Password storage and authentication
### The correct pattern
- Store only salted, slow hashes (bcrypt/scrypt/Argon2)
- Never store plaintext passwords
- Rate-limit login attempts
- Add MFA

Common failures
- fast hashing (SHA256 alone)
- unsalted hashes
- weak password reset flows

Mini-quiz (4.3)
- Q1: Why do we use a salt?
- Q2: Why do we want password hashes to be slow?


### 4.4 Symmetric encryption and AEAD concepts
### Key concept
- Encryption without authentication can be malleable.
- AEAD modes (conceptually) provide confidentiality + integrity.

Common failure
- nonce reuse


### 4.5 PKI and certificate validation
### What must be validated
- chain to a trusted root
- hostname matches
- validity dates

Failure modes
- accepting self-signed certs blindly
- skipping hostname verification


### 4.6 Common crypto failures in real systems
### - “roll your own crypto”
- weak randomness
- nonce reuse
- using ECB mode
- not verifying signatures properly


## PART 5 — WEB + API SECURITY FUNDAMENTALS

### 5.1 The web platform as a security boundary
### Web is multi-layered:
- browser
- network
- app server
- database
- identity provider

Trust boundaries
- user input crossing into server logic
- server calling external services (SSRF risk)
- identity tokens and sessions


### 5.2 Sessions, cookies, SameSite, CSRF
### Sessions
- server stores session state, client stores session identifier

Cookie attributes
- Secure: only sent over HTTPS
- HttpOnly: JS cannot read it
- SameSite: mitigates some CSRF patterns

CSRF
- attacker causes victim browser to send authenticated request
- typical defense: anti-CSRF tokens + SameSite + origin checks

Exercise
- In a local lab app, observe cookie attributes.


### 5.3 XSS and browser execution
### XSS is “untrusted data becomes code.”

Types
- Stored
- Reflected
- DOM-based

Defenses
- output encoding
- CSP
- input validation (helps but not enough)


### 5.4 Injection root causes
### SQL injection
- root cause: building queries via string concatenation
- defense: parameterized queries + least privilege DB accounts

Command injection
- root cause: untrusted input in shell commands
- defense: avoid shell, use safe APIs, validate input


### 5.5 Access control (IDOR) and authorization thinking
### AuthN vs AuthZ
- AuthN: who are you?
- AuthZ: what can you do?

IDOR
- user can access object they should not because server checks are missing.

Defense
- server-side authorization checks per request


### 5.6 SSRF and why cloud makes it worse
### SSRF: server fetches attacker-controlled URLs.

Why cloud increases risk
- metadata endpoints
- internal services reachable from server

Defenses
- allowlists
- block internal IP ranges
- network egress controls


### 5.7 OAuth 2.0 + OpenID Connect basics
### OAuth
- authorization delegation

OIDC
- authentication layer on top of OAuth

Common mistakes
- redirect URI flaws
- token audience/issuer not validated


### 5.8 Secure API design fundamentals
### - input validation
- auth and least privilege scopes
- rate limiting
- logging (auth events, admin actions)
- avoid leaking sensitive errors


## PART 6 — DEFENSIVE SECURITY FUNDAMENTALS

### 6.1 Logging fundamentals
### Good logs are: structured, timestamped, correlated.

Must-log events
- authentication events
- privilege changes
- admin actions
- process starts (where possible)
- network egress


### 6.2 Detection engineering basics
### Key tradeoffs
- false positives vs false negatives
- detection coverage vs noise

Baselines
- understand “normal” first

Map detections to MITRE ATT&CK


### 6.3 Incident response fundamentals
### First hour mindset
- confirm scope
- contain spread
- preserve evidence
- communicate clearly


### 6.4 Vulnerability management fundamentals
### CVE
- identifier for publicly known vulnerabilities

CVSS
- severity scoring (useful but incomplete)

Prioritization factors
- internet exposure
- exploit availability
- privilege required
- asset importance


## PART 7 — FORENSICS FUNDAMENTALS

### 7.1 Evidence thinking
### Separate:
- Observations (facts)
- Interpretations (hypotheses)
- Conclusions (with confidence)


### 7.2 Disk forensics overview
### - file timelines
- browser artifacts
- download history


### 7.3 Memory forensics overview
### - running processes
- loaded modules
- network connections


### 7.4 Network forensics overview
### - PCAP analysis
- DNS and proxy logs


### 7.5 Writing a forensic report
### Report structure
- executive summary
- timeline
- evidence
- analysis
- conclusion + confidence
- recommended actions


## PART 8 — MALWARE & REVERSE ENGINEERING FUNDAMENTALS

### 8.1 Safe analysis environment
### - isolated VM
- snapshots
- no shared folders
- careful networking


### 8.2 Static triage
### - hash
- strings
- imports
- entropy (packer suspicion)


### 8.3 Dynamic triage
### - process tree
- network connections
- file drops
- persistence


### 8.4 Intro reversing
### - find main logic
- identify suspicious functions


### 8.5 Reporting
### - behavior summary
- IOCs (within lab context)
- confidence and limitations


## PART 9 — SECURITY ENGINEERING FUNDAMENTALS

### 9.1 Threat modeling (DFD + STRIDE)
### Steps
1) Draw a data flow diagram
2) Identify assets
3) Mark trust boundaries
4) Enumerate threats (STRIDE)
5) Map mitigations


### 9.2 Secure design principles
### - least privilege
- defense in depth
- secure defaults
- minimize attack surface
- fail securely


### 9.3 Secure SDLC
### - threat modeling in design
- code review checklists
- dependency and secret scanning
- SAST/DAST concepts
- SBOM concept


### 9.4 Supply chain security basics
### - dependency trust
- build integrity
- signing and verification


## PART 10 — CLOUD + CONTAINER FUNDAMENTALS

### 10.1 Shared responsibility model
### Cloud provider vs customer responsibilities.


### 10.2 Cloud identity fundamentals
### - roles/policies
- least privilege
- token-based auth


### 10.3 Cloud networking fundamentals
### - private networks
- security groups / NSGs
- outbound controls


### 10.4 Storage + secrets
### - public access pitfalls
- secrets managers


### 10.5 Containers vs VMs
### - container isolation concepts
- image supply chain scanning


### 10.6 Kubernetes vocabulary
### - cluster, node, pod
- service, ingress
(High-level only until fundamentals are solid.)


## PART 11 — AI/ML SECURITY FUNDAMENTALS

### 11.1 AI for security vs security of AI
### - AI for security: ML models help detect anomalies, classify malware/phishing
- Security of AI: threats against ML pipelines and models


### 11.2 Threats
### - poisoning (training data compromised)
- evasion (adversarial examples)
- extraction (model stealing via API)
- privacy leakage (membership inference)


### 11.3 Defenses
### - provenance and integrity checks for data
- monitoring drift and abuse
- rate limiting and anomaly detection for model APIs


### 11.4 Evaluate defenses honestly
### - define threat model
- measure false positives
- document failure modes


## APPENDIX A — GLOSSARY (STARTER)
## AuthN / AuthZ
CIA triad
CVE / CVSS
EDR
IOC
Kerberos
LDAP
NAT
OWASP
PKI
SAST / DAST
SIEM
Sysmon
TLS
Trust boundary
(Extend this glossary as you learn.)


## APPENDIX B — QUICK COMMAND REFERENCE (STARTER)
## Linux
- process list: ps
- network sockets: ss
- logs: journalctl
- open files: lsof

Windows
- Event Viewer / Get-WinEvent
- Sysinternals: Procmon, Autoruns, Process Explorer

Networking
- ping, traceroute/tracert
- tcpdump/Wireshark


## APPENDIX C — MINI-QUIZ ANSWER KEYS
## (Write your answers first. Only then check references. Keep answers in your notes.)


## APPENDIX D — CURATED RESOURCES (COURSES, YOUTUBE, LABS, DATASETS)
## Core references
- MITRE ATT&CK: [https://attack.mitre.org/](https://attack.mitre.org/)
- OWASP Top 10 (2025): [https://owasp.org/Top10/2025/](https://owasp.org/Top10/2025/)
- OWASP Cheat Sheets: [https://cheatsheetseries.owasp.org/](https://cheatsheetseries.owasp.org/)
- OWASP ASVS: [https://owasp.org/www-project-application-security-verification-standard/](https://owasp.org/www-project-application-security-verification-standard/)
- CIS Benchmarks: [https://www.cisecurity.org/cis-benchmarks](https://www.cisecurity.org/cis-benchmarks)
- Sysinternals: [https://learn.microsoft.com/sysinternals/](https://learn.microsoft.com/sysinternals/)
- Sysmon: [https://learn.microsoft.com/sysinternals/downloads/sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon)
- NIST SP 800-61 Rev. 3 (IR): [https://csrc.nist.gov/pubs/sp/800/61/r3/final](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- NIST SP 800-92 (Logs): [https://csrc.nist.gov/publications/detail/sp/800-92/final](https://csrc.nist.gov/publications/detail/sp/800-92/final)

Primary texts for protocols (authoritative references)
- RFC Editor (official RFC archive): [https://www.rfc-editor.org/](https://www.rfc-editor.org/)
- IANA service names and port numbers registry (ground truth for defaults):
  [https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml)

Packet analysis references
- Wireshark user guide: [https://www.wireshark.org/docs/](https://www.wireshark.org/docs/)
- Wireshark sample captures: [https://wiki.wireshark.org/SampleCaptures](https://wiki.wireshark.org/SampleCaptures)

OS primary references
- Linux man pages (online): [https://man7.org/linux/man-pages/](https://man7.org/linux/man-pages/)
- Microsoft Learn: Windows security auditing (starting point):
  [https://learn.microsoft.com/windows/security/](https://learn.microsoft.com/windows/security/)

Coursera
- Google Cybersecurity Professional Certificate:
  [https://www.coursera.org/professional-certificates/google-cybersecurity](https://www.coursera.org/professional-certificates/google-cybersecurity)
- Introduction to Cyber Security Specialization (NYU):
  [https://www.coursera.org/specializations/intro-cyber-security](https://www.coursera.org/specializations/intro-cyber-security)
- The Bits and Bytes of Computer Networking:
  [https://www.coursera.org/learn/computer-networking](https://www.coursera.org/learn/computer-networking)
- Operating Systems and You: Becoming a Power User:
  [https://www.coursera.org/learn/os-power-user](https://www.coursera.org/learn/os-power-user)
- Cryptography (Jonathan Katz):
  [https://www.coursera.org/learn/cryptography](https://www.coursera.org/learn/cryptography)

Python for cybersecurity automation (Coursera course inside the Google program)
- Automate Cybersecurity Tasks with Python:
  [https://www.coursera.org/learn/automate-cybersecurity-tasks-with-python](https://www.coursera.org/learn/automate-cybersecurity-tasks-with-python)

Python general fundamentals (optional if you already code confidently)
- Python for Everybody (University of Michigan):
  [https://www.coursera.org/specializations/python](https://www.coursera.org/specializations/python)

Web security (best free curriculum)
- PortSwigger Web Security Academy:
  [https://portswigger.net/web-security](https://portswigger.net/web-security)

Local vulnerable apps (run in your lab)
- OWASP WebGoat:
  [https://owasp.org/www-project-webgoat/](https://owasp.org/www-project-webgoat/)
- OWASP Juice Shop:
  [https://owasp.org/www-project-juice-shop/](https://owasp.org/www-project-juice-shop/)

Hands-on platforms
- TryHackMe: [https://tryhackme.com/](https://tryhackme.com/)
- Hack The Box: [https://www.hackthebox.com/](https://www.hackthebox.com/)
- OverTheWire: [https://overthewire.org/wargames/](https://overthewire.org/wargames/)
- Blue Team Labs Online: [https://blueteamlabs.online/](https://blueteamlabs.online/)
- CyberDefenders: [https://cyberdefenders.org/](https://cyberdefenders.org/)

PCAPs and IR write-ups
- Malware Traffic Analysis: [https://www.malware-traffic-analysis.net/](https://www.malware-traffic-analysis.net/)
- The DFIR Report: [https://thedfirreport.com/](https://thedfirreport.com/)
- Wireshark sample captures: [https://wiki.wireshark.org/SampleCaptures](https://wiki.wireshark.org/SampleCaptures)

Python coding for security (docs + tooling + libraries)
### Core Python docs (read these like reference manuals)
- Python 3 docs (start page): [https://docs.python.org/3/](https://docs.python.org/3/)
- `logging` (structured logging mindset): [https://docs.python.org/3/library/logging.html](https://docs.python.org/3/library/logging.html)
- `secrets` (secure randomness for tokens): [https://docs.python.org/3/library/secrets.html](https://docs.python.org/3/library/secrets.html)
- `hashlib` (hashes): [https://docs.python.org/3/library/hashlib.html](https://docs.python.org/3/library/hashlib.html)
- `hmac` (authenticity/integrity with shared secret): [https://docs.python.org/3/library/hmac.html](https://docs.python.org/3/library/hmac.html)
- `ssl` (TLS basics from Python): [https://docs.python.org/3/library/ssl.html](https://docs.python.org/3/library/ssl.html)
- `subprocess` (avoid shell injection; use safely): [https://docs.python.org/3/library/subprocess.html](https://docs.python.org/3/library/subprocess.html)
- `urllib.parse` (URL parsing/normalization): [https://docs.python.org/3/library/urllib.parse.html](https://docs.python.org/3/library/urllib.parse.html)
- `ipaddress` (safe IP/subnet parsing): [https://docs.python.org/3/library/ipaddress.html](https://docs.python.org/3/library/ipaddress.html)
- `pathlib` + `tempfile` (safe file/path handling):
  - [https://docs.python.org/3/library/pathlib.html](https://docs.python.org/3/library/pathlib.html)
  - [https://docs.python.org/3/library/tempfile.html](https://docs.python.org/3/library/tempfile.html)

Security libraries (use these; don’t reinvent)
- `cryptography` (recommended Python crypto library): [https://cryptography.io/](https://cryptography.io/)
- `requests` (HTTP client): [https://requests.readthedocs.io/](https://requests.readthedocs.io/)
- `httpx` (modern HTTP client, async friendly): [https://www.python-httpx.org/](https://www.python-httpx.org/)
- `scapy` (packet crafting/analysis in labs): [https://scapy.net/](https://scapy.net/)

Secure coding guidance (high ROI)
- OWASP Cheat Sheet Series (pick relevant sheets per topic): [https://cheatsheetseries.owasp.org/](https://cheatsheetseries.owasp.org/)
- OWASP Secure Coding Practices (quick reference):
  [https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)

Security tooling for Python projects (recommended defaults)
- `pytest` (tests): [https://docs.pytest.org/](https://docs.pytest.org/)
- `ruff` (fast linter): [https://docs.astral.sh/ruff/](https://docs.astral.sh/ruff/)
- `black` (formatter): [https://black.readthedocs.io/](https://black.readthedocs.io/)
- `mypy` (type checking, optional but strong): [https://mypy.readthedocs.io/](https://mypy.readthedocs.io/)
- `bandit` (Python security linter): [https://bandit.readthedocs.io/](https://bandit.readthedocs.io/)
- `pip-audit` (dependency vulnerability scanning): [https://pypi.org/project/pip-audit/](https://pypi.org/project/pip-audit/)
- Semgrep (SAST patterns, includes security rules): [https://semgrep.dev/](https://semgrep.dev/)
- pre-commit (run checks automatically on commits): [https://pre-commit.com/](https://pre-commit.com/)

Practice datasets and projects (use for coding exercises)
- Wireshark Sample Captures (PCAPs): [https://wiki.wireshark.org/SampleCaptures](https://wiki.wireshark.org/SampleCaptures)
- Malware Traffic Analysis (PCAPs + explanations): [https://www.malware-traffic-analysis.net/](https://www.malware-traffic-analysis.net/)

Project ideas (portfolio-grade, safe)
- Build a log normalizer that converts many log formats to JSON lines.
- Build an IOC matcher (domains/IPs/hashes) with unit tests and safe parsing.
- Build a “security headers” analyzer for local URLs only.
- Build a DNS audit tool that records changes (TTL/IP drift) over time.

Detection engineering practice
- Sigma rules: [https://github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)
- Atomic Red Team: [https://github.com/redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team)

Reverse engineering tools
- Ghidra: [https://ghidra-sre.org/](https://ghidra-sre.org/)
- x64dbg: [https://x64dbg.com/](https://x64dbg.com/)
- FLARE-VM: [https://github.com/mandiant/flare-vm](https://github.com/mandiant/flare-vm)
- REMnux: [https://remnux.org/](https://remnux.org/)

YouTube
- Sysinternals Update playlist:
  [https://www.youtube.com/playlist?list=PLhFhDWFYccZ_GvdJ11NZwaBAhwDCWmni_](https://www.youtube.com/playlist?list=PLhFhDWFYccZ_GvdJ11NZwaBAhwDCWmni_)
- PortSwigger playlists:
  [https://www.youtube.com/@PortSwigger/playlists](https://www.youtube.com/@PortSwigger/playlists)
- OWASP Global:
  [https://www.youtube.com/user/OWASPGLOBAL](https://www.youtube.com/user/OWASPGLOBAL)
- Wireshark channel:
  [https://www.youtube.com/@Wireshark](https://www.youtube.com/@Wireshark)
- LiveOverflow playlists:
  [https://www.youtube.com/@LiveOverflow/playlists](https://www.youtube.com/@LiveOverflow/playlists)
- John Hammond playlists:
  [https://www.youtube.com/@JohnHammond010/playlists](https://www.youtube.com/@JohnHammond010/playlists)
- Professor Messer playlists:
  [https://www.youtube.com/@professormesser/playlists](https://www.youtube.com/@professormesser/playlists)


## APPENDIX E — PORTFOLIO ARTIFACTS (EVIDENCE OF FUNDAMENTALS)
## Create 6 artifacts (these prove fundamentals better than certificates):
1) PCAP report (DNS)
2) PCAP report (HTTP)
3) PCAP report (TLS)
4) Windows investigation report (Sysmon + Sysinternals)
5) Linux baseline audit script + write-up
6) Threat model of a small app + mitigations

Quality bar for each artifact
- Repro steps
- Evidence (logs/PCAP/screens)
- Root cause
- Fix + prevention
- Detection ideas



## EXTENDED CHAPTER NOTES (DEEP DIVE)
## This section turns the earlier chapters into “study notes” you can read like a textbook.
Use it when you feel you understand the outline but can’t confidently explain details.


### X1) Linux deep dive: investigation-first Linux
### Mindset: Linux for security is about answering questions quickly with evidence.

Core investigation questions → where to look
1) “What is running right now?”
  - Process list: ps/top
  - Service list: systemctl
  - Tree view (if available): pstree

2) “What network exposure exists?”
  - Listening sockets: ss -lntup (TCP/UDP + processes)
  - Open files/sockets: lsof
  - Firewall rules (conceptual reading): nft/iptables

3) “Who logged in and how?”
  - SSH auth logs (varies by distro):
    - Debian/Ubuntu: /var/log/auth.log
    - RHEL/CentOS: /var/log/secure
  - journalctl can also contain auth events depending on setup.

4) “What changed on disk?”
  - Look at:
    - /etc (config drift)
    - /usr/local/bin (custom binaries)
    - /tmp and user home dirs (downloads/execution)
    - cron configs
  - If you have a baseline, diff against it.

Linux persistence locations (defender knowledge)
- systemd:
  - /etc/systemd/system/
  - ~/.config/systemd/user/
- cron:
  - /etc/crontab
  - /etc/cron.*
  - /var/spool/cron/
- shell profiles:
  - ~/.bashrc, ~/.profile, ~/.bash_profile
- SSH:
  - ~/.ssh/authorized_keys

Common Linux misconfigurations to recognize
- World-writable directories on PATH
- Over-broad sudoers (NOPASSWD for everything)
- SSH password authentication on internet-facing hosts
- Services running as root unnecessarily

Mini lab (safe): “baseline vs drift”
Goal: learn to detect changes.
Steps:
1) Snapshot your VM.
2) Record a baseline:
  - list users/groups
  - list enabled services
  - list listening ports
  - list cron jobs
3) Make controlled changes:
  - add a user
  - add a service
  - open a local port (run a simple dev server)
4) Re-run baseline and write:
  - what changed
  - which log sources recorded the change

Self-check questions
- Can you explain the difference between “user created” and “user used” from logs?
- Can you identify a suspicious process by parent-child context?


### X2) Windows deep dive: telemetry-first Windows
### Mindset: Windows security work is usually “evidence-driven.” You don’t just suspect; you prove.

Windows investigation questions → tools
1) “What launched this process?”
  - Process Explorer: parent process, command line
  - Sysmon Event ID 1 (process creation)

2) “Which process made this network connection?”
  - Sysmon Event ID 3 (network connection, if enabled)
  - Resource Monitor / netstat (supporting, less context)

3) “Where is persistence configured?”
  - Autoruns (highest ROI tool)
  - Scheduled Tasks
  - Services
  - Registry Run keys

4) “What changed on disk/registry?”
  - Procmon (great for live observation)
  - Sysmon file/registry events (depending on config)

Sysmon overview (what it gives you)
- Process creation with command line (context)
- Network connections tied to a process (attribution)
- File creation in sensitive locations (dropper behavior)
- Registry autostarts (persistence)

Safe lab: “build a process story”
Goal: answer: Who launched what, and what did it do?
Steps:
1) In a Windows VM, enable Sysmon with a reasonable config.
2) Perform benign actions:
  - open PowerShell
  - download a file
  - run a program
3) Collect evidence:
  - process tree in Process Explorer
  - matching Sysmon events
4) Write a narrative:
  - Process A spawned Process B with command line X
  - Process B wrote file Y and connected to domain Z

Self-check questions
- Can you explain why “command line logging” is a major detection advantage?
- Can you show evidence that a binary executed from Downloads vs Program Files?


### X3) Active Directory deep dive (high-level, but precise)
### AD is where identity becomes operational.

What to understand conceptually
- Authentication vs authorization:
  - Auth: prove identity (Kerberos/NTLM)
  - AuthZ: decide access (groups, ACLs)

Kerberos intuition (high-level)
- A ticket proves you authenticated; services trust tickets.
- Time matters because tickets have validity windows.

Defender lens: AD attack surfaces (conceptual)
- Password spraying and credential stuffing
- Privilege escalation via group membership or misconfig
- Lateral movement using credentials

Self-check questions
- What are the “crown jewels” in AD (what accounts or systems matter most)?
- What is the biggest risk of service accounts?


### X4) Networking deep dive: how to read traffic like a story
### Packet analysis skill is a career multiplier.

Wireshark basics you must master
- Display filters vs capture filters
- Following a TCP stream
- Exporting objects (HTTP) in a training PCAP
- Identifying DNS queries and answers
- Identifying TLS handshake and certificate details

Practical “PCAP narrative” template
1) Summary
  - timeframe
  - key endpoints
  - top protocols
2) Timeline (5–15 bullet points)
3) Evidence
  - DNS queries
  - connection attempts
  - HTTP requests
  - TLS SNI/certs
4) Hypotheses
5) Conclusion + confidence

DNS checklist
- Are domains newly registered / unusual / random-looking?
- Are there repeated beacon-like queries?
- Are there many NXDOMAINs?

HTTP checklist
- Look for:
  - suspicious user agents
  - unusual paths
  - high-entropy query strings
  - exfil patterns (large POSTs)

TLS checklist
- Look for:
  - SNI mismatch
  - unusual certificate issuer
  - repeated short connections (beaconing)

Safe practice sources
- Malware Traffic Analysis: [https://www.malware-traffic-analysis.net/](https://www.malware-traffic-analysis.net/)
- Wireshark Sample Captures: [https://wiki.wireshark.org/SampleCaptures](https://wiki.wireshark.org/SampleCaptures)


### X5) Applied crypto deep dive: use it safely, recognize broken designs
### Crypto is easy to misuse. Your job is to know the standard safe patterns.

Mental model: “What property do I need?”
- Confidentiality: encryption
- Integrity: hashes/MACs
- Authenticity: signatures (or MACs in shared-secret settings)
- Password verification: KDF + compare

Hashing vs encryption (the interview explanation)
- Hashing: one-way; used to check “same input?”
- Encryption: reversible with key; used to keep data secret

Password storage best practice
- Use Argon2/bcrypt/scrypt
- Unique salt per password
- Rate limit
- MFA

TLS best practice intuition
- The client must validate:
  - certificate chain
  - hostname
  - validity

Common crypto disasters to recognize
- “We wrote our own crypto”
- “We encrypt passwords” (wrong goal; should hash for verification)
- “We used AES but without authentication”
- “We reused IV/nonce”


### X6) Web security deep dive: root causes + evidence + mitigation
### Web security is mostly about trust boundaries + parsing.

Core web questions
- Where does input come from?
  - query params, path params, headers, body, cookies
- Where does it go?
  - HTML rendering, SQL queries, templates, OS commands, internal HTTP calls
- What identity is used?
  - session cookie, JWT, API key, mTLS

Vulnerability → root cause → fix (high-level map)
1) SQL injection
  - root cause: string-built SQL queries
  - fix: parameterized queries + least privilege DB creds
  - evidence: suspicious queries in DB logs; unusual error messages

2) XSS
  - root cause: untrusted data rendered as executable JS/HTML
  - fix: output encoding + CSP + safe templating
  - evidence: payload in stored content; script execution in browser

3) CSRF
  - root cause: state-changing endpoints accept cookie auth without anti-CSRF
  - fix: CSRF tokens + SameSite + origin checks

4) IDOR / broken access control
  - root cause: server fails to check object ownership/permissions
  - fix: enforce authZ on server for every request
  - evidence: access logs show cross-user object reads

5) SSRF
  - root cause: server fetches attacker-controlled URL
  - fix: allowlist + block internal ranges + egress control + metadata protections
  - evidence: server outbound requests to unusual internal endpoints

Best free lab curriculum
- PortSwigger Academy: [https://portswigger.net/web-security](https://portswigger.net/web-security)

How to learn web vulns safely
- Do NOT test random websites.
- Use PortSwigger labs or local OWASP apps.


### X7) Defensive operations deep dive: what employers expect
### Most entry-level security roles reward:
- strong fundamentals
- clear written communication
- evidence-based reasoning

Logging fundamentals: what to log (practical)
- Authentication:
  - login success/fail
  - MFA challenges
  - password reset events
- Privileged actions:
  - admin group changes
  - policy changes
  - service/scheduled task creation
- Execution:
  - process starts with command lines
  - new binaries in temp/download directories
- Network:
  - outbound connections from endpoints/servers
  - DNS queries (if possible)

Detection engineering fundamentals
- A detection is:
  - hypothesis + signal + evidence source
- Always specify:
  - what you alert on
  - expected false positives
  - how to tune

IR fundamentals: first hour checklist
1) Confirm severity and scope
2) Stop the bleeding (containment)
3) Preserve evidence
4) Communicate status and next steps

Vulnerability management fundamentals
- Learn to say:
  - “This CVE is high severity, but low exposure”
  - “This is medium severity but internet-exposed and exploitable”


### X8) Forensics deep dive: report writing
### Forensics is as much writing as it is tooling.

A good report separates:
- Observations
- Inferences
- Conclusions

Confidence levels
- High: multiple independent evidence sources
- Medium: one strong source + assumptions
- Low: weak signals only


### X9) Malware/reversing deep dive: safe workflow and triage
### Do not begin with “full reverse engineering.” Start with triage.

Static triage checklist
- hash (for tracking)
- strings (URLs/domains)
- imports (what APIs it might use)
- packer suspicion (high entropy)

Dynamic triage checklist
- process tree
- file writes
- registry writes
- network connections

Output: behavioral summary
- persistence? network? credential access? encryption?


## FULL COVERAGE MODULES (TEXTBOOK-STYLE)
## These modules go deeper than the earlier chapters. Use them as your main reading.


## MODULE A — SECURITY FOUNDATIONS (MENTAL MODELS)

A1) The “security boundary” model
### Most security failures happen at boundaries:
- boundary between user and kernel
- boundary between two services
- boundary between internal network and internet
- boundary between authenticated and authorized
- boundary between trusted and untrusted data

Rule of thumb:
- Any time data crosses a boundary, you must validate + authorize + log.

Practical exercise:
- Take any app you use (even a simple TODO app) and list:
  - entry points
  - assets
  - trust boundaries
  - top 5 threats

A2) Threat models: attacker capabilities
### When you describe an attack, always specify:
- attacker position (internet user, internal user, compromised endpoint)
- attacker knowledge (source code? API docs? none?)
- attacker constraints (rate limits? MFA? network segmentation?)

This prevents “hand-wavy security.”

A3) Common control types
### Preventive controls:
- input validation, least privilege, patching, hardening
Detective controls:
- logging, alerting, anomaly detection, integrity monitoring
Corrective controls:
- backups, incident response playbooks, automated isolation

End-of-module questions (A)
1) Give an example of a preventive control that can fail silently.
2) Give an example of a detective control that is useless without context.
3) Describe one trust boundary in your internship product (if permitted) or a personal project.


## MODULE B — COMPUTER ARCHITECTURE & OS INTERNALS (SECURITY VIEW)

B0) Privilege, rings, and isolation (conceptual)
### Core idea: modern OS security is built on privilege separation.
- User mode: most applications run here.
- Kernel mode: OS core and drivers run here.

Why it matters
- Many severe vulnerabilities are “user input reaches kernel/privileged component.”
- Defensive telemetry often needs to answer: “did this cross a privilege boundary?”

B0.1 CPU privilege (high-level)
- Privilege rings exist to restrict what instructions/code can do.
- System calls are the controlled gateway into privileged operations.

B0.2 Virtualization (high-level)
- Hypervisors introduce another privilege layer.
- Security features (e.g., VBS-like concepts) use virtualization to isolate secrets.

B1) Processes, threads, and isolation
### Definitions you must be able to explain:
- Process: isolated virtual address space + resources (handles/fds) + identity context
- Thread: execution path inside a process

Why it matters:
- Compromise often starts in one process, then expands via:
  - spawning child processes
  - injecting into another process (conceptual)
  - abusing privileges

Evidence you should collect (defender mindset):
- parent process
- command line
- user identity context
- network connections
- file and registry modifications

Practice (safe):
- Build a “process story” on both Linux and Windows:
  - start a terminal
  - run a python script
  - make a network request
  - prove each step from logs/telemetry

B2) Virtual memory and why memory bugs become exploits
### Concepts:
- Virtual memory allows each process to believe it has a private contiguous memory space.
- Pages map virtual addresses to physical frames.
- Page faults occur when pages are missing or permissions disallow access.

Stack vs heap (security view):
- Stack:
  - stores return addresses, saved registers, local variables
  - corruption can redirect control flow
- Heap:
  - dynamic allocations
  - corruption can modify pointers/metadata leading to control-flow or data corruption

Mitigations you must understand conceptually:
- NX/DEP: non-executable memory regions
- ASLR: randomizes memory locations
- stack canaries: detect stack corruption
- control-flow hardening (platform-specific): attempts to prevent jumps to unexpected targets

What this does NOT mean:
- mitigations reduce exploitability; they do not remove the bug.

B3) Syscalls and the kernel boundary
### The syscall boundary is a critical security boundary.
Example flows:
- read a file: open → read → close
- network: socket → connect → send/recv

Defender thinking:
- if you can attribute actions to syscalls or OS events, you can detect behavior.

B4) Filesystems as an attack and defense surface
### Key ideas:
- Permissions are enforced at the filesystem boundary.
- Misconfigurations are vulnerabilities.

Linux specifics:
- SUID/SGID can elevate privileges if used incorrectly.
- world-writable directories enable persistence or privilege escalation in misconfigured paths.

Windows specifics:
- NTFS ACLs define who can read/write/execute.
- Many persistence mechanisms rely on writable autostart locations.

B5) Scheduling and concurrency (why “race conditions” exist)
### Concepts
- Scheduling decides when threads run.
- Concurrency introduces time-of-check/time-of-use (TOCTOU) classes of bugs.

Security relevance
- Race conditions can create authorization bypasses or unsafe file writes.

B6) Inter-process communication (IPC) (conceptual)
### IPC exists because processes need to cooperate.
Common IPC families (conceptual):
- pipes / named pipes
- sockets
- shared memory
- RPC mechanisms

Security relevance
- IPC endpoints are attack surfaces.
- Authentication/authorization for IPC matters in enterprise environments.

B7) Time, randomness, and security
### Time
- many protocols depend on accurate time (Kerberos, certificates)

Randomness
- secure token generation requires cryptographically strong randomness
- weak randomness breaks security properties even if algorithms are strong

End-of-module questions (B)
1) Explain ASLR in one paragraph and one example.
2) Explain why “command line logging” changes detection quality.
3) Give 5 high-value fields you want for every process creation event.
4) Explain TOCTOU in one paragraph and why it matters.
5) Name 3 IPC mechanisms and one security risk for each.


## MODULE C — LINUX FUNDAMENTALS (ADMIN + AUDITING)

C1) Linux identity & privilege
### Key structures:
- /etc/passwd: user identity and metadata
- /etc/shadow: password hashes (root-only)
- /etc/group: group memberships

Privilege escalation (defender view):
- users gain privilege via:
  - sudo rules
  - SUID binaries
  - misconfigured services

Study notes:
- Learn to read sudoers safely: least privilege commands, explicit binaries, avoid broad wildcards.

C2) Service management and persistence
### systemd basics:
- a service unit defines:
  - what runs
  - under what user
  - restart behavior
  - dependencies

Persistence patterns (defensive):
- new unit files
- modified existing unit files
- cron entries
- shell profile modifications

C3) Logging and timelines
### Key skills:
- know where auth logs are
- know how to filter journalctl by service and time

Practical rule:
- In IR, time is everything. Make sure you understand time zones and UTC.

C4) Linux access control beyond rwx (high-level)
### DAC (traditional permissions)
- owner/group/other permissions and ACLs

Capabilities (conceptual)
- some privileges can be split into fine-grained capabilities

MAC (Mandatory Access Control)
- SELinux/AppArmor constrain what processes can access even if user permissions allow it

Security relevance
- MAC can limit blast radius of compromised services

C5) Package management and trust
### Why it matters
- supply chain failures often start with untrusted packages or repos

Concepts
- signed repositories and trusted sources
- patching cadence
- minimizing installed software reduces attack surface

End-of-module questions (C)
1) Why is /tmp frequently abused?
2) Name 6 persistence locations on Linux.
3) What is one safe hardening change you can make to SSH in a lab, and how do you validate it?
4) What’s the difference between DAC and MAC?
5) Why is “minimize attack surface” practical advice on Linux servers?


## MODULE D — WINDOWS FUNDAMENTALS (INTERNALS + TELEMETRY)

D1) Windows security model (conceptual)
### Core objects:
- user accounts and groups
- SIDs
- access tokens
- integrity levels

What you must be able to explain clearly:
- Permissions (ACLs) vs privileges (token rights)

D2) Windows persistence (defender knowledge)
### Common autostart categories:
- Registry Run keys
- Scheduled tasks
- Services
- Startup folders
- WMI event subscriptions (conceptual)

Tooling:
- Autoruns is the best starting point in many investigations.

D3) Sysmon: what it gives you and how to use it
### Sysmon produces events; it does not “detect malware” by itself.
Your job is to build narratives and detections from events.

High-value events to understand:
- Process creation
- Network connections
- File creation (especially in user-writable dirs)
- Registry modifications (autostarts)

Practice:
- Write 10 detection hypotheses like:
  - “Process started from Downloads directory and immediately makes outbound TLS connections.”
  - “Office app spawns command shell.”
Then decide what logs prove/disprove it.

D4) Windows auditing and evidence (high-level)
### Goal: know what kinds of events exist and what questions they answer.

High-value event categories (conceptual)
- authentication and logon events
- privilege use and group membership changes
- service and scheduled task creation
- process creation (via Sysmon or other telemetry)
- script execution (PowerShell logging)

Evidence mindset
- One event rarely proves an incident.
- Correlate across:
  - endpoint telemetry
  - identity logs
  - network/proxy logs

D5) Windows identity protocols (conceptual)
### - NTLM vs Kerberos: where each is used and why Kerberos is preferred.
- Domain vs local accounts: different trust boundaries.

End-of-module questions (D)
1) Why is “parent process” critical in endpoint investigations?
2) What is the difference between “persistence” and “privilege escalation”?
3) If you can collect only 3 Windows telemetry sources, what would you pick and why?
4) Give an example of a conclusion you cannot safely draw from a single log source.
5) Why does time synchronization matter for Windows enterprise security?


## MODULE E — ACTIVE DIRECTORY (FOUNDATIONAL ENTERPRISE IDENTITY)

E1) Directory vs authentication
### LDAP is a directory protocol (query objects). Kerberos is authentication (prove identity).

E2) Kerberos intuition (high-level)
### Kerberos is ticket-based.
You should know conceptually:
- there are time-limited tickets
- services trust tickets issued by the domain
- time drift breaks authentication

E3) AD objects and why they matter
### - Users: human or service identities
- Groups: authorization
- Computers: endpoints/servers
- OUs and GPOs: centralized policy and configuration

E4) Defender thinking
### When investigating AD-centric incidents, ask:
- Which identities are involved?
- Which privileges changed?
- Which machine performed the action?
- Is lateral movement occurring?

End-of-module questions (E)
1) Why are service accounts risky when mismanaged?
2) What are two signals that might indicate lateral movement?
3) What is a “crown jewel” identity in a typical enterprise?

OS Mastery Checklist (printable)
### Goal: make OS knowledge measurable. This checklist focuses on “questions you can answer with evidence.”

How to use
- For each question, write down:
  - the primary evidence source
  - a secondary evidence source
  - what would convince you (confidence criteria)

Minimum lab telemetry (recommended)
- Linux: system logs (journald/auth), process list, listening sockets
- Windows: Event Logs + Sysmon + Sysinternals (Procmon/Autoruns/Process Explorer)
- Identity: domain controller logs (if you have an AD lab) or simulated identity logs


Linux (investigation questions)
### I can answer, with evidence:
1) Who logged in, when, and from where?
  - Evidence: auth logs + sshd logs + journalctl queries

2) What new users/groups were created or modified?
  - Evidence: /etc/passwd,/etc/group changes + logs (where available)

3) What processes are running and what started them?
  - Evidence: ps output + service manager + parent-child relationships

4) What network services are listening, and which process owns each port?
  - Evidence: ss + lsof

5) What persistence mechanisms exist on the host?
  - Evidence locations: systemd units, cron, shell profiles, SSH keys

6) What changed on disk in sensitive paths?
  - Evidence: file timestamps + package manager logs + baseline diffs

Linux minimum skills
- Understand permissions, sudoers, file ownership, SUID/SGID risks
- Understand where logs live and how to filter by time/service


Windows (investigation questions)
### I can answer, with evidence:
1) Who logged on (interactive/remote), when, and from where?
  - Evidence: Security Event Logs + RDP gateway logs (if present)

2) What processes executed, with what command line, and what spawned them?
  - Evidence: Sysmon process creation + Process Explorer

3) Which process opened a network connection to a given IP/domain?
  - Evidence: Sysmon network events (if enabled) + supporting endpoint/network logs

4) What persistence mechanisms are present?
  - Evidence: Autoruns + scheduled tasks + services + Run keys

5) What scripts ran (PowerShell) and what did they do?
  - Evidence: PowerShell logging + script block logs (where configured)

6) What files were created/modified in suspicious locations?
  - Evidence: Sysmon file events (if configured) + filesystem artifacts

Windows minimum skills
- Use Sysinternals to build a process story
- Understand tokens/privileges conceptually and why admin actions stand out in logs


Active Directory / Enterprise identity (investigation questions)
### I can answer, with evidence:
1) Which accounts are high-privilege and how is privilege granted?
  - Evidence: group memberships, role assignments, GPO scope

2) What authentication patterns look abnormal?
  - Evidence: failed logon spikes, unusual logon types, unusual source machines

3) What group membership or policy changes occurred?
  - Evidence: directory change logs + admin action logs

4) Is there evidence of lateral movement?
  - Evidence: same account authenticating across many machines + new remote sessions

Identity minimum skills
- Explain Kerberos at a high level and why time sync matters
- Explain why service accounts are a common enterprise risk


Confidence rubric (use in reports)
### High confidence:
- at least two independent sources corroborate (e.g., Sysmon + network/proxy logs)
Medium confidence:
- one strong source + consistent context
Low confidence:
- weak or ambiguous evidence only


## MODULE F — NETWORKING FUNDAMENTALS (FULL COVERAGE)

F0) What you must be able to do (practical outcomes)
### By the end of networking fundamentals, you should be able to:
- explain how a request travels: laptop → switch/AP → router → ISP → server
- explain the difference between addressing (IP) and naming (DNS)
- explain where TLS “lives” (between transport and application) and what it protects
- read a PCAP and reconstruct a session narrative
- map a connection to a process on a host (endpoint + network correlation)
- reason about segmentation and why it limits blast radius

F1) Protocol and service map (baseline)
### You should be able to explain each in one paragraph:
- ARP: local IP→MAC mapping / neighbor discovery (IPv4)
- ICMP: diagnostics and network error signaling
- DHCP: host configuration (IP/gateway/DNS)
- DNS: name resolution
- HTTP: web application protocol
- TLS: confidentiality + integrity in transit
- SMTP/IMAP: email transport and retrieval
- SSH: secure remote admin

F2) Network devices and where controls live
### Devices
- Switch (L2): forwards frames by MAC; VLANs often exist here
- Router (L3): forwards packets by IP; routing and NAT often exist here
- Firewall: policy enforcement (stateful filtering, sometimes L7)
- Proxy: mediates HTTP(S) traffic (visibility + policy)
- Load balancer: traffic distribution; can terminate TLS and inject headers
- IDS/IPS: detects or blocks suspicious traffic

Control placement matters
- “Where can you see what?” depends on where traffic is decrypted/terminated.

F3) Addressing and subnetting (must-have math)
### Core concepts
- IPv4 private ranges (RFC1918 concept)
- CIDR notation (e.g., /24, /16): how many addresses are “local”
- Subnet mask meaning and broadcast domains
- Default gateway: where non-local traffic goes

Practical competency
- Given an address like 10.20.30.40/22, you should be able to:
  - reason about approximate subnet size
  - determine if another IP is on-link or routed

F4) Ports, sockets, and service identification
### Concepts
- A socket is (IP, port, protocol)
- Default ports are conventions, not guarantees

Defender tip
- Don’t assume protocol by port alone; confirm via:
  - traffic behavior
  - server banners (where appropriate)
  - application logs

F5) Link layer: Ethernet, switching, VLANs, STP
### Ethernet
- Frames have MAC addresses + EtherType (IPv4/IPv6/ARP)

Switching
- Switches learn MAC→port mappings
- Broadcast behavior matters (ARP is broadcast)

VLANs
- VLANs create separate L2 broadcast domains
- Inter-VLAN routing requires L3 routing (router/firewall/L3 switch)

STP (conceptual)
- Prevents L2 loops (availability risk if misconfigured)

Security relevance
- VLANs/subnets are the foundation of segmentation

F6) Core infrastructure protocols: ICMP, DHCP, ARP
### ICMP
- echo request/reply (ping), time exceeded (traceroute behavior)

DHCP
- DORA flow (Discover → Offer → Request → Ack)

ARP (IPv4)
- local IP→MAC mapping; anomalies can indicate redirection/MITM behavior

What to log/monitor
- gateway MAC changes
- rogue DHCP indicators
- unexpected ICMP spikes

F7) IP fundamentals (IPv4 + IPv6)
### IPv4
- TTL, fragmentation concepts

IPv6 (do not ignore)
- dual-stack visibility gaps can bypass controls
- neighbor discovery replaces ARP conceptually

What to log/monitor
- AAAA lookups and unexpected IPv6 traffic

F8) NAT and attribution
### NAT hides internal addresses behind a public IP.
Implication:
- external logs may show one public IP for many internal devices

Security implications
- NAT is not a security control by itself
- correlation requires internal telemetry (endpoint + NAT logs)

F9) Routing concepts (and why they matter)
### Core concepts
- routing table: destination prefix → next hop
- default route
- asymmetric routing (visibility issues)

Routing protocols (very high-level)
- OSPF: common for internal networks
- BGP: internet routing between networks

Security relevance
- misroutes can cause outages or traffic misdirection

F10) Transport layer: TCP and UDP
### TCP essentials
- handshake, reliability, retransmits

UDP essentials
- no built-in connection state
- used by DNS and QUIC (HTTP/3)

Defender observation
- identify initiator vs responder
- identify periodic, short-lived connections

F11) DNS (deep fundamentals)
### Core concepts
- recursive resolver vs authoritative server
- record types: A/AAAA/CNAME/MX/TXT/NS
- caching and TTL

Encrypted DNS (conceptual)
- DoH/DoT shifts visibility: network sensors may see less; endpoint/proxy sees more

What to log/monitor
- rare domains, NXDOMAIN spikes, beacon-like periodic queries

F12) HTTP fundamentals (security view)
### You must understand
- methods, status codes, headers, cookies
- redirects and caching behaviors

HTTP versions (conceptual)
- HTTP/1.1 vs HTTP/2 vs HTTP/3 (QUIC/UDP)

Security relevance
- TLS termination points (proxy/LB) change where you can observe plaintext headers

What to log/monitor
- auth failures, unusual user agents, spikes in 4xx/5xx, rate limiting triggers

F13) TLS and PKI (network perspective)
### What to understand
- certificate chains, hostname validation, SNI

TLS handshake (high-level)
- client hello (SNI/ALPN)
- server certificate
- key agreement
- encrypted application data

Practice
- Inspect certs for 5 sites and record issuer/expiry/SAN

F14) VPNs and secure tunnels (conceptual)
### Why VPNs matter
- remote access and site-to-site links

Common families (high-level)
- IPsec, WireGuard, OpenVPN

Security relevance
- VPN logs are identity + network gold

F15) Recognize common enterprise protocols (conceptual)
### You should recognize and be able to discuss hardening/telemetry for:
- SMB (445/TCP), RDP (3389/TCP)
- LDAP/LDAPS (389/636), Kerberos (88)
- SNMP (161/162), NTP (123)
- SMTP/IMAP (25/587/465, 143/993)

F16) Wireless basics (Wi‑Fi) (conceptual)
### Wi‑Fi matters because it is often the “real perimeter” in offices and campuses.

Core concepts
- SSID vs BSSID
- WPA2 vs WPA3 (high-level)
- Enterprise Wi‑Fi (802.1X/EAP) vs shared-password Wi‑Fi (PSK)

Security relevance
- Shared passwords (PSK) don’t scale and are hard to revoke safely.
- Enterprise auth (802.1X) ties access to identity and can be logged.

What to log/monitor
- authentication events at the Wi‑Fi controller/AP
- rogue AP detection (where available)
- unusual device churn on secure SSIDs

F17) Network telemetry: what defenders actually use
### Common telemetry sources
- firewall logs (allowed/blocked flows)
- proxy logs (URLs, methods, status)
- DNS logs
- VPN logs
- flow logs (NetFlow/IPFIX/VPC flow logs) (conceptual): who talked to whom and how much

Security relevance
- You often can’t inspect payloads (encryption). Metadata still catches a lot.

End-of-module questions (F)
1) Why can DNS logs detect threats earlier than endpoint logs?
2) Explain how cookies relate to authentication in HTTP.
3) Explain what a certificate chain is.
4) Why is segmentation (VLANs/subnets) a primary defense against lateral movement?
5) What changes when an org moves from HTTP/1.1 to HTTP/2 or HTTP/3 (visibility-wise)?
6) Why is 802.1X (enterprise Wi‑Fi) preferable to PSK for organizations?
7) Name 3 network telemetry sources that remain useful even when traffic is encrypted.


## MODULE P — PROTOCOL ENCYCLOPEDIA (PURPOSE, DEFAULT PORTS, RISKS, TELEMETRY)
## This section is a quick reference. Memorize purpose + failure modes; keep ports as “familiar,” not holy.

P1) How to use this encyclopedia
### For each protocol, learn:
- Purpose (what problem it solves)
- Trust model (who is allowed to talk?)
- Default ports
- Common failures/misconfigurations
- What to log/monitor

P2) Core protocols

DNS (53/UDP,TCP)
- Purpose: name → IP resolution.
- Common failures: open resolvers, weak logging, visibility gaps with encrypted DNS.
- Telemetry: DNS query logs, NXDOMAIN rates, rare domains.

DHCP (67/UDP server, 68/UDP client)
- Purpose: automatic host configuration.
- Common failures: rogue DHCP, poor segmentation.
- Telemetry: DHCP server logs, lease assignments.

HTTP (80/TCP) and HTTPS (443/TCP)
- Purpose: web and API transport.
- Common failures: weak auth/authZ, insecure cookies, missing rate limits.
- Telemetry: access logs, auth logs, proxy/WAF logs.

TLS/HTTPS (443/TCP)
- Purpose: confidentiality/integrity in transit.
- Common failures: misvalidation, outdated configs.
- Telemetry: TLS termination logs, cert inventory, SNI observations.

SSH (22/TCP)
- Purpose: secure remote administration.
- Common failures: exposed password auth, weak key hygiene.
- Telemetry: auth logs, failed login spikes, new keys added.

SMTP (25/TCP; submission often 587/TCP; SMTPS 465/TCP)
- Purpose: email transport.
- Common failures: spoofing without SPF/DKIM/DMARC enforcement.
- Telemetry: mail gateway logs, DMARC reports.

IMAP (143/TCP) / IMAPS (993/TCP)
- Purpose: mail retrieval.
- Common failures: legacy auth, poor MFA.
- Telemetry: auth logs, impossible travel.

NTP (123/UDP)
- Purpose: time synchronization.
- Common failures: drift breaks Kerberos; exposed NTP misuse.
- Telemetry: NTP drift alerts.

SNMP (161/UDP queries, 162/UDP traps)
- Purpose: device monitoring.
- Common failures: default community strings; exposed SNMP.
- Telemetry: SNMP configs and trap logs.

P3) Enterprise identity + Windows protocols
### LDAP (389/TCP,UDP; LDAPS 636/TCP)
- Purpose: directory queries.
- Common failures: unprotected binds; over-broad directory exposure.
- Telemetry: directory service logs.

Kerberos (88/TCP,UDP)
- Purpose: authentication.
- Common failures: time drift, weak service account hygiene.
- Telemetry: domain controller auth logs.

RDP (3389/TCP)
- Purpose: remote desktop.
- Common failures: exposed RDP, weak MFA.
- Telemetry: logon events, RDP gateway logs.

SMB (445/TCP)
- Purpose: file sharing and Windows remote management primitives.
- Common failures: excessive share permissions, lateral movement paths.
- Telemetry: file share access logs, authentication patterns.

P4) Modern app protocols
### WebSockets (typically over 443/TCP)
- Purpose: bidirectional app communication.
- Common failures: auth mishandling, message validation.
- Telemetry: app logs + rate limiting.

gRPC (often 443/TCP)
- Purpose: RPC over HTTP/2.
- Common failures: authZ mistakes, exposure of internal methods.
- Telemetry: service logs and metrics.

QUIC / HTTP/3 (443/UDP)
- Purpose: modern web transport.
- Common failures: visibility gaps if tooling assumes TCP-only.
- Telemetry: endpoint/proxy visibility.

P5) Other common enterprise protocols (know they exist)
### These frequently appear in real environments and incidents.

Syslog (514/UDP, sometimes 514/TCP)
- Purpose: log transport.
- Common failures: UDP loss, unauthenticated ingestion, weak parsing.
- Telemetry: central log collector health + drop rates.

WinRM (5985/TCP HTTP, 5986/TCP HTTPS)
- Purpose: Windows remote management.
- Common failures: overly broad access, poor credential hygiene.
- Telemetry: management logs + authentication events.

MSRPC/DCOM (conceptual; ports vary)
- Purpose: Windows distributed component and RPC mechanisms.
- Common failures: unnecessary exposure; weak segmentation.
- Telemetry: endpoint logs + network flow logs; restrict exposure where possible.

NFS (2049/TCP/UDP)
- Purpose: Unix/Linux network file sharing.
- Common failures: over-broad exports; weak identity mapping.
- Telemetry: file server logs + access patterns.

FTP (21/TCP) / FTPS (explicit over 21, implicit often 990)
- Purpose: file transfer.
- Common failures: plaintext credentials in FTP; weak hardening.
- Telemetry: authentication logs; prefer SFTP/HTTPS alternatives.

Telnet (23/TCP)
- Purpose: remote shell (legacy).
- Common failures: plaintext credentials.
- Telemetry: should be rare; presence is often a finding.

MQTT (1883/TCP; 8883/TCP for TLS)
- Purpose: lightweight messaging (IoT).
- Common failures: no auth/TLS; weak topic ACLs.
- Telemetry: broker logs, auth events.

AMQP (5672/TCP; 5671/TCP for TLS)
- Purpose: message queues.
- Common failures: exposed brokers, weak auth.
- Telemetry: broker auth + publish/consume patterns.

Databases (common)
- PostgreSQL (5432/TCP), MySQL (3306/TCP), MS SQL Server (1433/TCP)
- Purpose: data storage.
- Common failures: exposed internet DBs, weak auth, over-privileged app accounts.
- Telemetry: DB auth logs, slow query logs, anomalous query patterns.

End-of-module questions (P)
1) Why are “default ports” helpful but not sufficient for identification?
2) Which protocols become especially important when investigating identity-based breaches?
3) Name 5 protocol log sources you’d want in an enterprise and why.

Protocol Mastery Checklist (printable)
### Use this checklist for EACH protocol you study. If you can’t answer these, you don’t “own” the protocol yet.

For a given protocol X, I can explain:
- Purpose: what problem it solves
- Placement: what layer(s) it operates at and what it runs over (TCP/UDP)
- Participants: who is client, who is server
- Auth model: how identity is established (if applicable)
- Default ports: the common defaults (and that ports can vary)
- Normal traffic shape: what “healthy” looks like

I can identify common failures/misconfigurations:
- exposure failures (internet-facing when it shouldn’t be)
- auth failures (weak/legacy/no MFA)
- encryption failures (plaintext or broken validation)
- authorization failures (over-broad permissions)
- logging failures (no evidence)

I know what to log/monitor (minimum viable telemetry):
- Network side:
  - DNS queries (if relevant)
  - firewall/proxy decisions (allowed/blocked)
  - flow logs (who talked to whom, volume)
- Host/app side:
  - authentication events
  - authorization failures
  - administrative actions
  - error rates and unusual spikes

I can prove it in evidence (lab):
- Capture a PCAP that includes protocol X
- Annotate 5–10 key packets/events and explain them in plain English
- Produce a 1-page write-up:
  - what happened
  - what would be suspicious variants
  - what logs would confirm/deny suspicion

Suggested practice sequence (repeat per protocol):
1) Generate normal traffic (client performs normal action)
2) Capture PCAP + identify protocol handshake/requests
3) Locate corresponding host/app logs
4) Write detection hypotheses (2–3) and required telemetry

Protocol quick self-test prompts
- “If this breaks, what symptoms appear?”
- “If this is abused, what evidence appears?”
- “What control would stop abuse with the least collateral damage?”


## MODULE G — APPLIED CRYPTOGRAPHY (FULL COVERAGE)

G1) Properties and threat models
### Before choosing crypto, specify:
- attacker can read traffic?
- attacker can modify traffic?
- attacker can replay traffic?

G2) Passwords: the most common real-world failure
### Correct design:
- store slow salted hashes
- rate limit and monitor
- MFA

Common failure modes:
- weak reset flows (account takeover)
- credential stuffing (reuse)
- poor secrets handling (tokens in logs)

G3) Encryption at rest vs in transit
### In transit: TLS
At rest: disk/database encryption
Key management is usually the hard part.

End-of-module questions (G)
1) Why is “encrypting passwords” a red flag?
2) Why is key management often harder than choosing algorithms?
3) Give one example where integrity matters more than confidentiality.


## MODULE H — WEB + API SECURITY (FULL COVERAGE)

H1) The web trust boundary map
### Data sources you must always treat as untrusted:
- URL path and query parameters
- request body
- headers (including Host)
- cookies
- uploaded files

H2) Authentication vs authorization
### This is the #1 most important web security concept.
AuthN:
- sessions, cookies
- tokens
AuthZ:
- object-level checks
- role checks

H3) Browser security model
### Same-Origin Policy
- limits how scripts from one origin access another.

CORS
- controlled relaxation of SOP for cross-origin requests.
- important: CORS is not an authorization system.

CSP
- reduces XSS impact by restricting script sources.

H4) Vulnerability classes: deeper notes
### Broken Access Control (OWASP A01)
- focus: IDOR
- defense: server-side checks every time

Security Misconfiguration (OWASP A02)
- focus: insecure defaults, exposed admin endpoints
- defense: hardening, secure defaults, environment separation

Supply Chain Failures (OWASP A03)
- focus: dependencies, build pipeline integrity
- defense: pin versions, scan deps, SBOM, signing

Cryptographic Failures (OWASP A04)
- focus: using crypto wrong
- defense: standard libs, correct modes, strong key management

Injection (OWASP A05)
- focus: unsafe concatenation
- defense: parameterization, safe APIs

Insecure Design (OWASP A06)
- focus: missing threat model
- defense: threat modeling and secure patterns

Authentication Failures (OWASP A07)
- focus: weak login/reset/MFA
- defense: rate limits, MFA, secure resets, monitoring

Integrity Failures (OWASP A08)
- focus: insecure deserialization, pipeline integrity

Logging/Alerting Failures (OWASP A09)
- focus: no visibility

Exceptional Condition Handling (OWASP A10)
- focus: crashes, error paths, DoS patterns

H5) OAuth/OIDC: safe understanding
### You should be able to draw:
- client
- authorization server
- resource server
- user

Common mistakes (conceptual)
- redirect URI issues
- audience/issuer not validated
- confusing “authentication” with “authorization”

Best lab curriculum
- PortSwigger Academy: [https://portswigger.net/web-security](https://portswigger.net/web-security)

End-of-module questions (H)
1) Why is CORS not an authorization control?
2) Explain CSRF in one paragraph.
3) Give 3 mitigations for XSS and how they complement each other.


## MODULE I — DEFENSIVE SECURITY (SOC, DETECTION, IR)

I1) Evidence-driven security
### Good defenders:
- collect evidence
- state hypotheses
- test hypotheses
- communicate clearly

I2) Telemetry design (what to log)
### If you log only one thing, log authentication events.

High-value categories:
- auth: success/fail, MFA events, resets
- admin actions: policy changes, role changes
- execution: process starts, script execution
- network: outbound connections, DNS
- data access: sensitive object reads/writes

I3) Detection engineering fundamentals
### Write detections as:
- goal
- data source
- logic
- expected false positives
- response steps

Practice:
- Write 10 detections and map to MITRE ATT&CK.
- Implement one detection as a query (even if only conceptual).

I4) Incident response fundamentals
### Phases:
- Preparation
- Detection/analysis
- Containment
- Eradication
- Recovery
- Lessons learned

First-hour playbook (simplified)
1) Identify affected assets.
2) Contain further spread.
3) Preserve evidence.
4) Communicate.

I5) Vulnerability management fundamentals
### What CVSS doesn’t capture well:
- internet exposure
- exploit availability
- business criticality

Prioritization heuristic:
- Internet-exposed + exploitable + high privilege = urgent

End-of-module questions (I)
1) What are the first 3 actions in an incident and why?
2) Give an example of a detection that is “high value but noisy.”
3) How would you prioritize patching: CVSS 9.8 internal vs CVSS 7.5 internet-exposed?


## MODULE J — FORENSICS (DISK, MEMORY, NETWORK)

J1) Forensics is story + proof
### Your output is a narrative supported by evidence.

J2) Disk vs memory vs network
### - Disk: what was stored and executed
- Memory: what is currently running and loaded
- Network: what communicated with what

J3) Reporting template
### - Summary
- Scope
- Evidence
- Analysis
- Conclusion + confidence
- Recommendations

End-of-module questions (J)
1) Why is time normalization essential?
2) Give an example where memory evidence matters more than disk evidence.


## MODULE K — MALWARE & REVERSE ENGINEERING

K1) Triage before reverse
### Don’t start with deep reversing.
Start with:
- static indicators
- behavior

K2) Safe lab rules
### - isolate the VM
- snapshot
- avoid sharing host resources

K3) What employers want
### - a clean behavior report
- IOCs in a training context
- clear confidence and limitations

End-of-module questions (K)
1) What is the difference between static and dynamic analysis?
2) Why do packers complicate static analysis?


## MODULE L — SECURITY ENGINEERING & SECURE SDLC

L1) Threat modeling (practical)
### Deliverable:
- DFD
- trust boundaries
- threats
- mitigations

L2) Secure SDLC checklist
### Design:
- threat model
- security requirements
Build:
- code review
- secrets scanning
- dependency scanning
Test:
- basic security tests
Release:
- signed builds, SBOM concept
Operate:
- monitoring + incident readiness

End-of-module questions (L)
1) Why is “secure defaults” a design principle?
2) What is an SBOM and why does it matter?


## MODULE M — CLOUD & CONTAINERS (PRE-CLOUDSEC)

M1) Shared responsibility model
### Always ask:
- what does the provider secure?
- what do we secure?

M2) Identity is the perimeter
### Most cloud breaches are identity and misconfiguration.

M3) Containers (fundamentals)
### - image supply chain
- runtime isolation
- least privilege

End-of-module questions (M)
1) Why is identity considered the new perimeter?
2) Give one cloud misconfiguration that commonly causes breaches.


## MODULE N — AI/ML SECURITY (PRE-AISEC)

N1) Threat model the ML pipeline
### Pipeline components:
- data collection
- labeling
- training
- evaluation
- deployment/API

Threats map
- poisoning hits data/training
- evasion hits inference
- extraction hits the API
- privacy leakage hits the model outputs

Defender posture
- provenance
- monitoring and abuse detection
- rate limiting

End-of-module questions (N)
1) Give one defense that helps against model extraction.
2) What is the difference between data poisoning and evasion?


## MODULE O — CODING FOR SECURITY WITH PYTHON (FULL COVERAGE)

O1) The secure-coding mindset
### Security bugs are rarely “missing a library.” They’re usually:
- missing validation at a boundary
- wrong authorization logic
- unsafe composition (strings into SQL/OS commands/HTML)
- secrets leakage
- unsafe defaults

Your goal as a security-minded engineer:
- make unsafe states hard to reach
- make failures obvious and logged
- make your code easy to review


O2) Data lifecycle: parse → validate → normalize → use
### This pattern prevents many bug classes.

Parse
- Convert input into types (URL/IP/path/date) as early as possible.

Validate
- Check constraints (allowed domains, allowed directories, allowed ranges).

Normalize
- Normalize once (e.g., canonical paths, lowercased hostnames) BEFORE comparisons.

Use
- Only after parse+validate+normalize.

Practice
- Write validators for:
  - URL allowlist fetcher (SSRF prevention)
  - path resolver under a root dir (path traversal prevention)
  - JSON schema validation (reject unknown fields if needed)


O3) Avoiding command injection
### Rules
- Prefer Python APIs over shell commands.
- If you must call a command:
  - pass args as a list
  - never concatenate untrusted strings
  - set timeouts
  - capture output for evidence

Practice
- Write a wrapper that calls an OS command safely with:
  - explicit args
  - timeout
  - structured result object


O4) Safe file handling and path traversal defense
### Common failure mode
- User provides filename/path and code trusts it.

Defensive patterns
- Create a dedicated storage root.
- Resolve final path and verify it stays under the root.
- Enforce filename allowlists for uploads.
- Enforce maximum file sizes.


O5) Secrets management fundamentals (coding view)
### Rules
- Do not commit secrets to git.
- Do not log secrets.
- Separate secrets from code via environment variables or secret stores.

Practice
- Build a configuration loader that:
  - reads from env vars
  - supports `.env` in local dev only
  - refuses to start if required secrets are missing


O6) Authentication and authorization pitfalls (coding view)
### Things that cause real breaches
- treating authentication as authorization
- missing object-level checks
- trusting client-side role claims

Practice
- Design an API endpoint that reads a document:
  - show how you enforce object ownership
  - show what you log
  - show how you handle errors without leaking sensitive details


O7) Logging and observability for security
### Security-relevant logging should include
- timestamp (UTC)
- actor identity (user/service)
- action
- target object
- outcome (success/failure)
- correlation ID

Avoid logging
- passwords
- access tokens
- private keys

Practice
- Implement JSON logs and write a script that summarizes:
  - auth failures
  - denied actions
  - suspicious rates


O8) Testing as security work
### Security is reliability under adversarial input.
Testing you should do:
- unit tests for validators
- property-based tests for parsers (optional)
- regression tests for fixed bugs


O9) Dependency and supply chain hygiene (Python)
### Checklist
- use venv
- pin versions where appropriate
- run pip-audit
- keep dependencies minimal


O10) Python security toolchain (recommended baseline)
### Minimum
- black + ruff + pytest

Recommended
- bandit + pip-audit + semgrep + pre-commit


End-of-module questions (O)
1) What’s the difference between validation and normalization? Give an example.
2) Why is `shell=True` risky?
3) What must you never log?
4) List 5 fields in a good security log event.
5) How do you prevent path traversal in a file download endpoint?


## END OF STUDY MATERIAL

