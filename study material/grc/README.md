# Enterprise IT Governance, SOX/ITGC, and Security Audit — Complete Study Guide

A comprehensive 19-module study guide covering enterprise IT governance, SOX/JSOX compliance, ITGC, access management, change management, incident management, evidence collection, control testing, audit findings, the full audit lifecycle, stakeholder communication, practical tooling (ServiceNow, Active Directory, Excel), common findings patterns, a full realistic case-study walkthrough, a security-engineering reframing of every major control area, and interview preparation.

## How to Use This Guide

Each module is a standalone `.md` file but builds on prior modules — concepts introduced in early modules (Module 1's COSO/risk language, Module 2's RCM/financial assertions, Module 4's JML process) are referenced by shorthand in later modules rather than re-explained, so reading roughly in order the first time through will make later modules click faster. Every module ends with **Quick Self-Check Questions** — these are the single highest-value study tool here. Try answering them out loud, unaided, before checking back against the module content.

If your goal is interview readiness specifically, Module 19 is built as the consolidated final review layer and references back to every other module by number.

If your goal is connecting this material to your security engineering/AppSec trajectory specifically, Module 18 is written as a direct synthesis layer — read it after you're comfortable with Modules 1-17, since it assumes and builds on that foundation rather than re-teaching it.

## Module Index

| # | Module | Core Focus |
|---|---|---|
| 01 | [Enterprise IT Governance](modules/01-enterprise-it-governance.md) | Corporate governance, risk management, COSO, COBIT, ISO 27001, NIST CSF, GRC |
| 02 | [SOX & JSOX](modules/02-sox-jsox.md) | Enron/WorldCom history, Section 302/404, JSOX differences, RCM, financial assertions |
| 03 | [MICS](modules/03-mics.md) | Minimum Internal Control Standards, control tiers, ownership, real-world failure patterns |
| 04 | [ITGC](modules/04-itgc.md) | Logical access, least privilege, SoD, PAM, full Joiner/Mover/Leaver process |
| 05 | [Access Management](modules/05-access-management.md) | IAM, AD, LDAP, Entra ID, SSO, SAML, OAuth, OIDC, MFA, RBAC, ABAC, access reviews |
| 06 | [Change Management](modules/06-change-management.md) | Normal/Standard/Emergency change, CAB, rollback, DevSecOps parallels |
| 07 | [Incident Management](modules/07-incident-management.md) | Full incident lifecycle, RCA (5 Whys), CAPA, ITIL discipline distinctions |
| 08 | [Evidence Collection](modules/08-evidence-collection.md) | Every evidence type, evidence quality hierarchy, daily workflow |
| 09 | [Control Testing](modules/09-control-testing.md) | Design vs. operating effectiveness, sampling, the 5 testing techniques, deficiency pipeline |
| 10 | [Audit Findings](modules/10-audit-findings.md) | Finding structure, severity rating, writing findings that drive change |
| 11 | [Audit Lifecycle](modules/11-audit-lifecycle.md) | Planning through closure, PBC lists, the lifecycle as a continuous loop |
| 12 | [Stakeholder Communication](modules/12-stakeholder-communication.md) | Running calls, difficult stakeholders, escalation, documentation |
| 13 | [ServiceNow for Audit](modules/13-servicenow-for-audit.md) | Incident/Change/Request modules, CMDB, audit logs as evidence |
| 14 | [Active Directory](modules/14-active-directory.md) | Users, groups, OUs, nested groups, GPOs, key Windows Event IDs |
| 15 | [Excel for Auditors](modules/15-excel-for-auditors.md) | Pivot tables, XLOOKUP/VLOOKUP, sampling techniques, Power Query |
| 16 | [Common Audit Findings](modules/16-common-audit-findings.md) | The 11 recurring findings catalog plus 5 cross-cutting systemic patterns |
| 17 | [Real Project Walkthrough](modules/17-real-project-walkthrough.md) | One full realistic engagement, start to finish, synthesizing Modules 1-16 |
| 18 | [Security Perspective](modules/18-security-perspective.md) | Every control area reframed through AppSec/DevSecOps/SOC lens |
| 19 | [Interview Preparation](modules/19-interview-preparation.md) | Expected questions, scenarios, terminology drills, final checklist |

## Suggested Study Sequence

**First pass (build the foundation):** Modules 1 → 4, in order. This establishes the governance/risk vocabulary and the core ITGC access process everything else depends on.

**Second pass (broaden the technical base):** Modules 5 → 8. Technical identity systems, change process, incident process, and evidence — the practical machinery.

**Third pass (the audit craft itself):** Modules 9 → 12. This is where you go from "knowing what controls are" to "knowing how to actually test and report on them."

**Fourth pass (tooling fluency):** Modules 13 → 15. Hands-on, reference-style — revisit these as needed rather than memorizing linearly.

**Fifth pass (synthesis):** Modules 16 → 19. Pattern recognition, a full case study, the security-engineering translation layer, and interview readiness — these tie everything together and are best read once the foundation is solid.

## A Note on Depth vs. Memorization

This guide is deliberately written to explain *why* each concept/control exists, not just *what* it is — because in real audit and security work (and in interviews), the "why" is what lets you reason through unfamiliar situations rather than only recognizing memorized patterns. When studying, prioritize being able to explain the reasoning behind a control or finding in your own words over reciting definitions verbatim.
