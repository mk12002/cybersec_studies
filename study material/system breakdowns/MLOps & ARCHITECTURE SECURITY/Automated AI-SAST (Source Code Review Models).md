# Automated AI-SAST (Source Code Review Models): Internal Engineering & Security Breakdown

> **Classification:** Internal Engineering / Security Document  
> **Audience:** Security Engineers, AppSec Teams, ML Engineers, DevSecOps Architects, Interview Candidates  
> **Scope:** Full-stack AI-powered Static Application Security Testing — code ingestion, AST analysis, ML models, vulnerability detection, CI/CD integration, evasion mechanics, and observability  
> **Version:** 1.0

---

## Table of Contents

1. [Threat Detection Narrative](#1-threat-detection-narrative)
2. [Telemetry & Ingestion Flow](#2-telemetry--ingestion-flow)
3. [Feature Engineering Pipeline](#3-feature-engineering-pipeline)
4. [Inference Engine Architecture](#4-inference-engine-architecture)
5. [Correlation & Alerting Flow](#5-correlation--alerting-flow)
6. [Attack Scenarios (Evasion Tactics)](#6-attack-scenarios-evasion-tactics)
7. [Failure Points & Scaling](#7-failure-points--scaling)
8. [Mitigations & Defense-in-Depth](#8-mitigations--defense-in-depth)
9. [Observability](#9-observability)
10. [Interview Questions](#10-interview-questions)

---

## Foundational Framing: What AI-SAST Actually Is

Traditional SAST (Static Application Security Testing) uses pattern matching and dataflow analysis with hand-crafted rules to find vulnerabilities in source code. Tools like Semgrep, Checkmarx, and SonarQube operate this way. Their core limitations:

- **False positive rate:** 40-70% of findings are not real vulnerabilities (analyst fatigue)
- **Novel vulnerability classes:** Rules must be written for known patterns; new vulnerability classes are missed
- **Context blindness:** A rule for SQL injection will flag `db.query(user_input)` whether or not `user_input` is sanitized three function calls up the call stack
- **Configuration blindness:** Cannot detect when a secure function is misconfigured, only when an insecure function is used

**AI-SAST** augments or replaces these hand-crafted rules with ML models that:

1. **Learn from vulnerable code corpora** (NVD, CVE databases, bug bounty reports, internal incident history)
2. **Model code semantics** (not just syntax) using AST-aware transformers and GNNs
3. **Track taint flow** across function boundaries using learned program analysis
4. **Rank findings by exploitability** using severity prediction models
5. **Reduce FP rate** by learning what "actually dangerous" looks like vs. superficially dangerous

The system covered here is a production AI-SAST pipeline deployed in the CI/CD pipeline of a large software organization, scanning all pull requests before merge to `main`.

---

## 1. Threat Detection Narrative

### 1.1 The Attacker's Perspective: Supply Chain Attack via Dependency Confusion

**Scenario:** An attacker (Alex) wants to achieve code execution in the target organization's production infrastructure. Rather than attacking externally, Alex targets the software supply chain. The goal is to get malicious code into the production codebase by contributing a pull request that appears to be a security fix but contains a subtle backdoor.

**What Alex submits:**

Alex creates a PR that purports to fix a reported SQL injection vulnerability in the user authentication module. The "fix" adds input sanitization but also embeds a subtle vulnerability:

```python
# Claimed fix for SQLi in authentication module
def authenticate_user(username: str, password: str) -> Optional[User]:
    """
    Fixed SQL injection vulnerability reported in issue #4821.
    Now uses parameterized queries.
    """
    # Sanitize username (new code)
    username = username.strip()
    if not re.match(r'^[a-zA-Z0-9_]{3,50}$', username):
        raise ValueError("Invalid username format")
    
    # Use parameterized query (fixing the SQL injection)
    query = "SELECT * FROM users WHERE username = %s"
    result = db.execute(query, (username,))
    
    if result:
        user = User.from_row(result[0])
        # Verify password
        if verify_password(password, user.password_hash):
            # Log successful auth for audit trail
            _log_auth_event(username, "success", request.headers.get('X-Forwarded-For'))
            return user
    return None

def _log_auth_event(username: str, event_type: str, client_ip: str):
    """Log authentication events for security monitoring."""
    # The backdoor: format string injection into log query
    log_entry = f"INSERT INTO auth_log (user, event, ip, ts) VALUES ('{username}', '{event_type}', '{client_ip}', NOW())"
    db.execute(log_entry)  # ← SQL injection via X-Forwarded-For header (unparameterized)
    
    # Also send telemetry - with a subtle SSRF in the URL construction
    telemetry_url = f"https://metrics.internal.corp/{username}/auth_events"
    requests.get(telemetry_url, timeout=0.1)  # ← SSRF via username in URL path
```

**What Alex thinks:** The PR appears legitimate — it genuinely fixes the reported SQLi. The backdoors are subtle:
1. The `_log_auth_event` function introduces a new SQL injection via the `X-Forwarded-For` header (attacker-controlled HTTP header → direct string interpolation → SQL injection)
2. The `telemetry_url` construction creates a Server-Side Request Forgery (SSRF) via username in the URL path

**Alex's assumptions:**
- Human code reviewers will focus on the main `authenticate_user` function (which is now correctly parameterized)
- The helper `_log_auth_event` will receive less scrutiny ("just logging")
- The SSRF in the telemetry URL looks like an internal metrics call (harmless)
- The SQL injection is in the logging path (not the authentication path — reviewers focus on auth)

---

### 1.2 What the AI-SAST System Sees

**T=0: Pull request opened, GitHub webhook fires**

The PR triggers the AI-SAST pipeline. The system receives the diff and the full repository context.

**T+2s: Ingestion and parsing**

The changed files are ingested, parsed into Abstract Syntax Trees (ASTs), and analyzed:

```
Files changed: auth/authentication.py (47 lines added, 12 lines removed)
Functions added: _log_auth_event() — NEW FUNCTION
Functions modified: authenticate_user() — MODIFIED

AST analysis begins:
  authenticate_user(): 
    → Uses parameterized query db.execute(query, (username,)) ✓
    → Calls _log_auth_event() with username, event_type, request.headers.get(...)
    → The third argument (X-Forwarded-For header) is TAINT SOURCE

  _log_auth_event():
    → Parameter client_ip is a TAINT SINK candidate
    → log_entry = f"INSERT...VALUES ('{username}', '{event_type}', '{client_ip}', NOW())"
    → db.execute(log_entry) — UNPARAMETERIZED QUERY with TAINTED DATA
    → TAINT PATH: request.headers.get('X-Forwarded-For') → _log_auth_event(client_ip) → log_entry → db.execute()
```

**T+5s: Taint flow analysis completes**

The ML-powered taint tracker follows the data from source to sink:

```
VULNERABILITY 1 DETECTED: SQL Injection (High Severity)
  CWE: CWE-89 (Improper Neutralization of Special Elements in SQL Command)
  
  Taint Source: request.headers.get('X-Forwarded-For')
    → Authentication.py:28 — HTTP header value (user-controlled)
    → No sanitization applied to this value
    
  Taint Propagation:
    → authenticate_user() passes to _log_auth_event(client_ip=request.headers.get('X-Forwarded-For'))
    → _log_auth_event() receives as parameter client_ip
    → client_ip embedded in f-string: f"...'{client_ip}'"
    → Result passed to db.execute() without parameterization
    
  Taint Sink: db.execute(log_entry) at authentication.py:41
    → SQL query constructed by string formatting with tainted data
    → db.execute() called with raw string (single argument, not parameterized)
    
  Confidence: 0.94
  Exploitability: HIGH (X-Forwarded-For is trivially controllable by any HTTP client)
  
VULNERABILITY 2 DETECTED: Server-Side Request Forgery (Medium Severity)
  CWE: CWE-918 (Server-Side Request Forgery)
  
  Taint Source: username parameter (validated, but only for alphanumeric + underscore)
    → regex: r'^[a-zA-Z0-9_]{3,50}$' DOES sanitize for SQL injection
    → BUT: username still contains user-controlled data
    → Alphanumeric username can still cause SSRF by encoding attack paths
    
  Taint Sink: requests.get(telemetry_url) at authentication.py:44
    → URL: f"https://metrics.internal.corp/{username}/auth_events"
    → username appears in URL PATH — can navigate to internal endpoints
    → username "admin%2F..%2Finternal%2Fsecret" or similar bypasses may be possible
    
  Confidence: 0.71 (lower — username IS partially sanitized)
  Exploitability: MEDIUM (depends on internal service architecture)
```

**T+8s: Deception detection — the "looks like a fix" pattern**

The AI-SAST model also runs a **review evasion classifier** — a model trained on historical examples of vulnerabilities hidden inside security fixes:

```
Review Evasion Classifier:
  Features:
    PR description mentions: "fixes SQL injection" (security-related fix)
    Main function uses parameterized query (security improvement)
    Helper function introduced in same commit (new code in security-sensitive path)
    Helper function contains vulnerability (contradiction)
    Vulnerability in helper is of same class as claimed fix (SQL injection)
    
  Pattern matches: "Trojan Fix" — vulnerability introduced while appearing to fix vulnerability
  
  Evasion confidence: 0.83
  Alert: "This PR claims to fix a SQL injection but introduces a new SQL injection
          in a helper function added in the same commit. This pattern is consistent
          with supply chain attack via code review evasion."
```

**T+12s: Full alert generated, PR blocked**

```
[AI-SAST ALERT] PR #4821 — BLOCKED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CRITICAL: SQL Injection (CWE-89) — authentication.py:41
HIGH: Potential SSRF (CWE-918) — authentication.py:44  
WARNING: Review Evasion Pattern Detected — "Trojan Fix"

Summary: This PR introduces 2 security vulnerabilities while claiming to fix 1.
The SQL injection vulnerability is exploitable via the X-Forwarded-For HTTP header,
which is trivially controllable by any client. An attacker can inject arbitrary SQL
into the authentication log table, potentially escalating to data extraction or
database corruption depending on DB user privileges.

Taint path (SQL Injection):
  request.headers.get('X-Forwarded-For')  [authentication.py:28]
  → _log_auth_event(client_ip=...)         [authentication.py:31]
  → f"...'{client_ip}'..."                 [authentication.py:38]
  → db.execute(log_entry)                   [authentication.py:41]

Required actions:
  □ Use parameterized query in _log_auth_event(): db.execute("...", (username, event_type, client_ip))
  □ Review SSRF risk in telemetry URL construction
  □ Security review: determine if this PR represents an intentional supply chain attack
  
Merge blocked until all HIGH/CRITICAL findings are resolved.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

**What the SOC analyst sees:**

Beyond the standard vulnerability alert, the supply chain attack flag goes to the security team:

```
[SUPPLY CHAIN ALERT] P1 — Potential Trojan Fix in PR #4821
Author: alex_external_contributor (first PR in this repository)
Repository: payment-service (CRITICAL — contains payment processing code)
Pattern: Vulnerability introduced in security fix PR (83% confidence)

Background:
  Author joined GitHub organization 3 days ago
  No previous contributions to this repository
  PR opened immediately after issue #4821 was made public (18 minutes later)
  Issue #4821 was classified as HIGH severity (publicly visible)

Recommendation: Treat this PR as potentially adversarial. Do not merge.
Review the contributor's other open PRs across all repositories.
Consider revoking repository access pending investigation.
```

---

## 2. Telemetry & Ingestion Flow

### 2.1 Code Events as Telemetry

Unlike runtime security systems that ingest logs, AI-SAST ingests **code artifacts**:

```
SOURCE CODE EVENTS (triggers for AI-SAST):
  ├── Pull Request Opened (most common — scan diff + context)
  ├── Pull Request Synchronized (new commits pushed to existing PR)
  ├── Branch Push (for branch protection scanning)
  ├── Scheduled Full Repository Scan (nightly, for drift detection)
  ├── Dependency Lock File Changed (for dependency vulnerability scanning)
  ├── CI/CD Pipeline File Changed (.github/workflows, Jenkinsfile, etc.)
  └── Security Patch Applied (verify fix actually resolves the vulnerability)

ARTIFACT TYPES INGESTED:
  Source code files (.py, .js, .go, .java, .ts, .rb, .php, ...)
  Infrastructure as Code (Terraform, CloudFormation, Helm charts, Kubernetes YAML)
  Container definitions (Dockerfile, docker-compose.yml)
  Dependency manifests (requirements.txt, package.json, go.mod, pom.xml)
  Secret scanning targets (all files — look for hardcoded credentials)
  Configuration files (nginx.conf, application.yml, .env files)
```

### 2.2 Ingestion Architecture

```
┌────────────────────────────────────────────────────────────────────────────────────┐
│  CODE EVENT TRIGGERS                                                               │
│                                                                                    │
│  [GitHub/GitLab]   [Bitbucket]   [Azure DevOps]   [Custom Git Hooks]             │
│       │                │                │                   │                     │
└───────┼────────────────┼────────────────┼───────────────────┼─────────────────────┘
        │                │                │                   │
        │ Webhook POST   │ Webhook POST   │ Service Hook      │ pre-receive hook
        │ (application/  │                │                   │
        │  json)         │                │                   │
        ▼                ▼                ▼                   ▼
┌────────────────────────────────────────────────────────────────────────────────────┐
│  WEBHOOK INGESTION SERVICE                                                         │
│                                                                                    │
│  • Validates webhook signature (HMAC-SHA256 with shared secret)                   │
│  • Rate limits per repository (prevent webhook flood attacks)                     │
│  • Extracts: repo URL, commit SHA, PR number, changed file list                   │
│  • Prioritizes: CRITICAL repos skip queue → immediate processing                  │
│  • Deduplication: same commit SHA already in flight? Skip.                        │
│                                                                                    │
│  POST /webhook/github → validate → enqueue scan job                               │
└────────────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌────────────────────────────────────────────────────────────────────────────────────┐
│  JOB QUEUE (Apache Kafka / AWS SQS)                                               │
│                                                                                    │
│  Topics:                                                                           │
│  sast.jobs.critical     (CRITICAL repos — SLA: 2 minutes end-to-end)             │
│  sast.jobs.high         (HIGH repos — SLA: 5 minutes)                             │
│  sast.jobs.standard     (Standard repos — SLA: 15 minutes)                        │
│  sast.jobs.scheduled    (Nightly full scans — best effort)                        │
│                                                                                    │
│  Job schema:                                                                       │
│  {                                                                                 │
│    "job_id": "uuid",                                                               │
│    "trigger": "pull_request",                                                      │
│    "repo": "org/payment-service",                                                  │
│    "repo_criticality": "CRITICAL",                                                 │
│    "pr_number": 4821,                                                              │
│    "base_commit": "abc123",                                                        │
│    "head_commit": "def456",                                                        │
│    "changed_files": ["auth/authentication.py"],                                    │
│    "languages": ["python"],                                                        │
│    "scan_mode": "diff",  // or "full"                                              │
│    "enqueued_at": "2024-01-15T09:10:14Z"                                          │
│  }                                                                                 │
└────────────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌────────────────────────────────────────────────────────────────────────────────────┐
│  WORKER POOL (Kubernetes Pods, autoscaling)                                       │
│                                                                                    │
│  ┌──────────────────────────────────────────────────────────────────────────────┐ │
│  │  CODE FETCHER                                                                │ │
│  │  • Clone repository (shallow clone: depth=1 for diff scans, full for daily)  │ │
│  │  • Verify git commit signature if GPG signing required                       │ │
│  │  • Fetch only changed files for diff mode (git show HEAD:filename)           │ │
│  │  • Fetch full context files (files that import changed files)                │ │
│  └──────────────────────────────────────────────────────────────────────────────┘ │
│                                     │                                              │
│  ┌──────────────────────────────────▼───────────────────────────────────────────┐ │
│  │  LANGUAGE DETECTION & ROUTING                                                │ │
│  │  • Detect language from file extension + magic bytes + content               │ │
│  │  • Route to appropriate parser: Python → tree-sitter-python                  │ │
│  │  • Multi-language files: JSX, PHP with embedded HTML, etc.                   │ │
│  └──────────────────────────────────────────────────────────────────────────────┘ │
│                                     │                                              │
│  ┌──────────────────────────────────▼───────────────────────────────────────────┐ │
│  │  AST PARSER (tree-sitter or language-specific parsers)                       │ │
│  │  • Parse source code → Abstract Syntax Tree                                  │ │
│  │  • Handle parse errors gracefully (partial AST is better than no analysis)   │ │
│  │  • Normalize AST to intermediate representation (IR)                         │ │
│  │  • Compute call graphs within the changed files + context files              │ │
│  └──────────────────────────────────────────────────────────────────────────────┘ │
│                                     │                                              │
│  ┌──────────────────────────────────▼───────────────────────────────────────────┐ │
│  │  FEATURE EXTRACTION                                                          │ │
│  │  • Build graph representations (call graph, data flow, control flow)         │ │
│  │  • Compute taint flows (source-to-sink paths)                                │ │
│  │  • Generate code embeddings (CodeBERT / UniXcoder)                           │ │
│  │  • Extract structural features (function depth, complexity, API patterns)    │ │
│  └──────────────────────────────────────────────────────────────────────────────┘ │
│                                     │                                              │
│  ┌──────────────────────────────────▼───────────────────────────────────────────┐ │
│  │  ML INFERENCE                                                                │ │
│  │  • Vulnerability classifier (per code region)                                │ │
│  │  • Severity predictor                                                        │ │
│  │  • False positive ranker                                                     │ │
│  │  • Exploit likelihood scorer                                                 │ │
│  │  • Review evasion detector                                                   │ │
│  └──────────────────────────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌────────────────────────────────────────────────────────────────────────────────────┐
│  RESULTS STORE                                                                     │
│                                                                                    │
│  • PostgreSQL: findings with full metadata, taint paths, model scores             │
│  • Elasticsearch: full-text searchable findings across all repositories            │
│  • S3: raw ASTs, feature vectors, model inputs (for debugging and retraining)     │
│  • GitHub/GitLab API: post PR comments, set commit status checks                  │
└────────────────────────────────────────────────────────────────────────────────────┘
```

### 2.3 Where Latency and Dropped Events Occur

```
FAILURE POINT 1: Webhook delivery reliability
  GitHub/GitLab retries webhooks for up to 72 hours on failure
  If the ingestion service is down for > 72h: webhook events are lost
  Mitigation: Polling fallback (check GitHub API for new PRs every 60 seconds)
  Mitigation: Dead letter queue (capture failed webhooks for replay)

FAILURE POINT 2: Repository access / clone failures
  If git credentials expire or permissions change: clone fails silently
  Worker sees: "clone failed" → job fails → no scan result
  From PR author's perspective: CI check stays "pending" forever
  Detection: Monitor clone failure rate per repository; alert on > 5%
  Mitigation: Credential refresh automation; fallback to GitHub API file content

FAILURE POINT 3: Parse failures (malformed or obfuscated code)
  Some code is unparseable (broken syntax, intentional obfuscation)
  Partial parse still analyzed; completely unparseable → falls back to regex patterns
  Risk: Obfuscated code that's unparseable evades ML analysis entirely
  Mitigation: Separate obfuscation detector runs BEFORE attempting parse

FAILURE POINT 4: Large monorepos exceeding time limits
  Repository with 5M lines of code — full scan takes 2+ hours
  CI/CD SLA: 15 minutes → scan times out, PR blocked waiting for result
  Solution: Diff-only scanning for PRs; full scan nightly with higher time budget
  Edge case: diff touches a central utility used by 10,000 files
            → transitive analysis must limit depth to avoid exponential explosion

FAILURE POINT 5: Queue congestion during mass deployment events
  Company-wide dependency update PRs: 200 repos get PRs simultaneously
  sast.jobs.standard floods; SLA violated
  Solution: Back-pressure mechanism; dynamically promote standard → high priority
            based on queue depth monitoring

FAILURE POINT 6: Model inference timeout
  Complex code with deeply nested function calls → large graph → GNN times out
  Mitigation: 30-second inference timeout; fall back to rule-based scan
  Mitigation: Graph size limit (prune to top-50 most anomalous nodes if graph > threshold)
```

### 2.4 Normalization: From Source Code to Analysis Units

Unlike log normalization (mapping different log formats to a common schema), code normalization involves:

```python
class CodeNormalizer:
    """
    Transforms raw source code into analysis units suitable for ML processing.
    Normalization reduces variance from coding style without losing semantic meaning.
    """
    
    def normalize_python(self, source_code: str) -> NormalizedAnalysisUnit:
        # Step 1: Parse to AST
        tree = ast.parse(source_code)
        
        # Step 2: Strip comments and docstrings
        # (Comments are noise for vulnerability detection; processed separately for context)
        tree = CommentStripper().visit(tree)
        
        # Step 3: Variable name normalization
        # "user_input", "input_data", "request_body" → all normalized to "VAR_0"
        # This helps the model learn patterns regardless of developer naming conventions
        # Exception: keep names that carry semantic meaning (db, conn, cursor, request)
        tree = VariableNormalizer(preserve_semantic=SEMANTIC_KEYWORDS).visit(tree)
        
        # Step 4: Literal normalization
        # String literals: "SELECT * FROM users WHERE id = '" → "SELECT_SQL_FRAGMENT"
        # Integer literals: 1234, 9999, 0xDEAD → "INT_LITERAL"
        # Keep: URL patterns (identify external calls), format strings (injection signals)
        tree = LiteralNormalizer().visit(tree)
        
        # Step 5: Extract analysis units (function-level granularity)
        functions = FunctionExtractor().extract(tree)
        
        # Step 6: Build analysis unit for each function
        units = []
        for func in functions:
            unit = NormalizedAnalysisUnit(
                function_name=func.name,
                normalized_code=ast.unparse(func),  # Reconstruct from normalized AST
                ast_nodes=func,
                parameters=[p.arg for p in func.args.args],
                called_functions=CallExtractor().extract(func),
                return_type=TypeAnnotation.extract(func),
                taint_sources=TaintSourceFinder().find(func),
                taint_sinks=TaintSinkFinder().find(func)
            )
            units.append(unit)
        
        return units
```

---

## 3. Feature Engineering Pipeline

### 3.1 The Feature Hierarchy for AI-SAST

Raw source code must become numerical representations the ML models can process. The features fall into four categories:

```
LEVEL 1 — SYNTAX FEATURES (from AST nodes):
  Function call patterns: which functions are called, in what order
  Operator patterns: string concatenation with user-controlled data (+, format, f-string)
  Control flow: if/else conditions gating sensitive operations
  Exception handling: bare except clauses that hide errors
  API usage patterns: which security-sensitive APIs are used

LEVEL 2 — SEMANTIC FEATURES (from data flow analysis):
  Taint flows: paths from user-controlled input to security-sensitive sinks
  Sanitization presence: is there validation/encoding between source and sink?
  Authorization checks: is there a permission check before sensitive operations?
  Cryptographic patterns: key sizes, algorithm selection, random seed handling

LEVEL 3 — STRUCTURAL FEATURES (from graph representations):
  Call graph topology: which functions call which (circular calls, deep nesting)
  Data flow graph: how data moves between variables and functions
  Control flow graph: branching and looping complexity
  Cross-file dependencies: how this function relates to imported modules

LEVEL 4 — CONTEXTUAL FEATURES (from surrounding code, git history):
  File purpose: authentication.py vs utils.py (different risk context)
  Developer history: has this author introduced vulnerabilities before?
  Change size: small targeted change vs. large refactor (different risk profiles)
  PR context: description, referenced issues, test coverage of changed code
```

### 3.2 Abstract Syntax Tree Feature Extraction

```python
class ASTFeatureExtractor:
    """
    Extracts numerical features from Python ASTs for vulnerability detection.
    These are stateless features — computable from a single function's AST.
    """
    
    # Taint sources: values that may be attacker-controlled
    TAINT_SOURCES = {
        'request.args', 'request.form', 'request.json', 'request.data',
        'request.headers', 'request.cookies', 'request.files',
        'os.environ', 'sys.argv', 'input()',
        'socket.recv', 'socket.recvfrom',
    }
    
    # Taint sinks: functions that are dangerous with attacker-controlled input
    TAINT_SINKS = {
        # SQL injection sinks
        ('db', 'execute'): 'sql_injection',
        ('cursor', 'execute'): 'sql_injection',
        ('connection', 'execute'): 'sql_injection',
        # Command injection sinks
        ('os', 'system'): 'command_injection',
        ('subprocess', 'call'): 'command_injection',
        ('subprocess', 'run'): 'command_injection',
        ('subprocess', 'Popen'): 'command_injection',
        # SSRF sinks
        ('requests', 'get'): 'ssrf',
        ('requests', 'post'): 'ssrf',
        ('urllib', 'urlopen'): 'ssrf',
        # Path traversal sinks
        ('open',): 'path_traversal',
        ('os.path', 'join'): 'path_traversal',
        # Deserializaton sinks
        ('pickle', 'loads'): 'deserialization',
        ('yaml', 'load'): 'deserialization',
        ('eval',): 'code_injection',
        ('exec',): 'code_injection',
    }
    
    def extract(self, func_ast: ast.FunctionDef) -> dict:
        return {
            # Direct taint source presence
            'has_taint_source': self._has_taint_source(func_ast),
            'taint_source_count': self._count_taint_sources(func_ast),
            
            # Direct taint sink presence
            'has_taint_sink': self._has_taint_sink(func_ast),
            'taint_sink_types': self._get_sink_types(func_ast),
            
            # f-string with parameter (classic injection pattern)
            'fstring_with_param': self._has_fstring_with_parameter(func_ast),
            
            # String concatenation in potentially dangerous context
            'string_concat_in_sql_context': self._check_sql_concat(func_ast),
            
            # Sanitization presence
            'has_input_validation': self._has_input_validation(func_ast),
            'has_sql_parameterization': self._has_parameterized_query(func_ast),
            'has_html_escaping': self._has_html_escape(func_ast),
            
            # Structural features
            'function_complexity': self._cyclomatic_complexity(func_ast),
            'max_nesting_depth': self._max_nesting_depth(func_ast),
            'parameter_count': len(func_ast.args.args),
            'line_count': func_ast.end_lineno - func_ast.lineno,
            
            # Exception handling patterns
            'bare_except': self._has_bare_except(func_ast),
            'swallows_exceptions': self._swallows_exceptions(func_ast),
            
            # Dangerous patterns
            'uses_eval': self._calls_eval(func_ast),
            'uses_pickle': self._calls_pickle(func_ast),
            'has_hardcoded_credential': self._has_hardcoded_secret(func_ast),
        }
    
    def _has_fstring_with_parameter(self, node: ast.AST) -> bool:
        """
        Detect f-strings that include function parameters (potential injection).
        Example: f"SELECT * FROM {table} WHERE id = {user_input}"
        """
        for child in ast.walk(node):
            if isinstance(child, ast.JoinedStr):  # f-string node
                for value in child.values:
                    if isinstance(value, ast.FormattedValue):
                        # Check if the embedded expression includes a parameter name
                        expr = value.value
                        if self._involves_external_data(expr, node):
                            return True
        return False
    
    def _has_parameterized_query(self, node: ast.AST) -> bool:
        """
        Detect if db.execute() calls use parameterized form.
        db.execute(query, params) → True (parameterized)
        db.execute(f"...{var}") → False (vulnerable)
        """
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if self._is_db_execute(child):
                    # Parameterized if: execute(query_string, parameters_tuple)
                    return len(child.args) == 2 and isinstance(child.args[1], (ast.Tuple, ast.List))
        return False
```

### 3.3 Taint Flow Analysis (Interprocedural)

The hardest feature engineering challenge in SAST: **interprocedural taint tracking** — following attacker-controlled data across function calls.

```python
class TaintFlowAnalyzer:
    """
    Tracks tainted data from sources to sinks across function boundaries.
    Uses a fixed-point analysis algorithm:
      1. Initialize: mark taint sources as tainted
      2. Propagate: if a tainted value is passed to a function, the corresponding
                    parameter is tainted in that function
      3. Summarize: a function that returns tainted data is itself a taint propagator
      4. Repeat until no new taint facts are discovered (fixed point)
    
    This is the analysis that traditional SAST does symbolically.
    AI-SAST learns to approximate this analysis from examples.
    """
    
    def analyze_call_graph(self, 
                            changed_functions: list[FunctionUnit],
                            context_functions: list[FunctionUnit]) -> list[TaintPath]:
        """
        Build interprocedural taint paths across function boundaries.
        
        changed_functions: functions in the diff (what was added/modified)
        context_functions: functions that call or are called by changed functions
        """
        all_functions = {f.name: f for f in changed_functions + context_functions}
        
        # Phase 1: Identify taint sources (function parameters from external calls)
        taint_facts = {}  # function_name → set of tainted parameters
        
        for func in all_functions.values():
            for source in func.taint_sources:
                taint_facts.setdefault(func.name, set()).add(source.parameter)
        
        # Phase 2: Fixed-point propagation across function boundaries
        changed = True
        while changed:
            changed = False
            for func in all_functions.values():
                for call in func.calls:
                    callee_name = call.function_name
                    if callee_name not in all_functions:
                        continue  # External library call — use library taint model
                    
                    callee = all_functions[callee_name]
                    
                    # Check: are any arguments to this call tainted?
                    for arg_idx, arg in enumerate(call.arguments):
                        if self._is_tainted(arg, taint_facts.get(func.name, set())):
                            # The corresponding parameter in callee is now tainted
                            callee_param = callee.parameters[arg_idx]
                            if callee_param not in taint_facts.get(callee_name, set()):
                                taint_facts.setdefault(callee_name, set()).add(callee_param)
                                changed = True  # New taint fact → continue iteration
        
        # Phase 3: Find paths from tainted parameters to dangerous sinks
        taint_paths = []
        for func in all_functions.values():
            func_taints = taint_facts.get(func.name, set())
            for sink in func.taint_sinks:
                if self._sink_receives_tainted_data(sink, func_taints, func):
                    path = TaintPath(
                        source=self._find_original_source(func, func_taints, all_functions),
                        sink=sink,
                        vulnerability_type=sink.vulnerability_type,
                        path_functions=[func.name],
                        sanitizers=self._find_sanitizers_on_path(func, func_taints, sink)
                    )
                    taint_paths.append(path)
        
        return taint_paths
```

### 3.4 Graph Features for the GNN

The code's call graph, data flow graph, and control flow graph are processed by a Graph Neural Network. Nodes and edges need feature representations:

```python
class CodeGraphBuilder:
    """
    Builds heterogeneous graphs from code analysis for GNN input.
    
    Node types:
      FUNCTION: a function definition
      VARIABLE: a variable assignment
      CALL_SITE: a point where a function is called
      TAINT_SOURCE: a node identified as receiving external input
      TAINT_SINK: a node identified as a dangerous operation
    
    Edge types:
      CALLS: function A calls function B
      PASSES_DATA: variable X is passed to function Y
      DATA_FLOW: variable X's value is used in computing variable Y
      CONTROL_FLOW: execution path from node A to node B
      TAINT_FLOW: tainted data flows from A to B
    """
    
    def build_function_graph(self, analysis_unit: FunctionUnit) -> HeteroGraph:
        nodes = {}
        edges = []
        
        # Add function node
        func_node_id = self._add_node(nodes, 'FUNCTION', {
            'complexity': analysis_unit.cyclomatic_complexity,
            'parameter_count': len(analysis_unit.parameters),
            'line_count': analysis_unit.line_count,
            'is_modified': analysis_unit.is_in_diff,  # Was this function changed?
            'is_new': analysis_unit.is_new,
            'has_security_annotation': analysis_unit.has_security_decorator,
        })
        
        # Add variable nodes
        for var in analysis_unit.variables:
            var_node_id = self._add_node(nodes, 'VARIABLE', {
                'is_parameter': var.is_parameter,
                'is_tainted': var.is_tainted,
                'assignment_count': var.assignment_count,
                'usage_count': var.usage_count,
            })
            # Edge: function defines this variable
            edges.append(('DEFINES', func_node_id, var_node_id))
        
        # Add call site nodes
        for call in analysis_unit.calls:
            call_node_id = self._add_node(nodes, 'CALL_SITE', {
                'is_dangerous_sink': call.is_taint_sink,
                'sink_type': SINK_ENCODING.get(call.sink_type, 0),
                'is_external': call.is_external_library,
                'argument_count': len(call.arguments),
                'has_parameterized_args': call.uses_parameterized_form,
            })
            # Edge: function contains this call site
            edges.append(('CONTAINS', func_node_id, call_node_id))
            # Edge: data flows from variables to call arguments
            for arg_var in call.argument_variables:
                if arg_var in nodes:
                    edges.append(('DATA_FLOW', nodes[arg_var], call_node_id))
        
        # Add taint source nodes
        for source in analysis_unit.taint_sources:
            src_node_id = self._add_node(nodes, 'TAINT_SOURCE', {
                'source_type': TAINT_SOURCE_ENCODING[source.type],
                'is_http_input': source.is_http_input,
                'is_file_input': source.is_file_input,
                'has_sanitizer_downstream': source.has_downstream_sanitizer,
            })
            edges.append(('TAINT_ORIGINATES', src_node_id, nodes.get(source.variable, func_node_id)))
        
        return HeteroGraph(nodes=nodes, edges=edges)
```

### 3.5 Code Embeddings (Transformer-Based Features)

For the vulnerability classifier, we use CodeBERT-style token embeddings:

```python
class CodeEmbeddingExtractor:
    """
    Uses a pretrained code language model to embed code snippets into dense vectors.
    These embeddings capture semantic similarity — functions with similar logic
    patterns have similar embeddings, regardless of variable naming.
    
    Base model: UniXcoder (unified cross-modal pre-training for code representation)
    Fine-tuned on: vulnerability detection (CWE classification task)
    
    Input: Normalized source code (up to 512 tokens after BPE tokenization)
    Output: 768-dimensional vector per code unit
    """
    
    MODEL_CHECKPOINT = "microsoft/unixcoder-base"
    MAX_LENGTH = 512
    
    def __init__(self):
        self.tokenizer = AutoTokenizer.from_pretrained(self.MODEL_CHECKPOINT)
        self.model = AutoModel.from_pretrained(self.MODEL_CHECKPOINT)
        self.model.eval()  # Inference mode
        self.model.half()  # FP16 for memory efficiency
    
    def embed_function(self, function_code: str) -> np.ndarray:
        """
        Embed a single function into a 768-dimensional vector.
        """
        # Add special tokens for vulnerability detection task
        input_text = f"<vulnerability_detection> {function_code}"
        
        # Tokenize
        tokens = self.tokenizer(
            input_text,
            max_length=self.MAX_LENGTH,
            padding='max_length',
            truncation=True,
            return_tensors='pt'
        )
        
        # Get embedding
        with torch.no_grad():
            outputs = self.model(**tokens)
        
        # Use [CLS] token embedding as function representation
        # (trained to capture the "meaning" of the entire input sequence)
        embedding = outputs.last_hidden_state[:, 0, :].squeeze().numpy()
        
        return embedding  # shape: (768,)
    
    def embed_batch(self, function_codes: list[str]) -> np.ndarray:
        """
        Batch embedding — much more efficient than individual calls.
        On GPU: processes 64 functions simultaneously in ~100ms.
        """
        # Batch tokenize
        tokens = self.tokenizer(
            function_codes,
            max_length=self.MAX_LENGTH,
            padding=True,
            truncation=True,
            return_tensors='pt'
        )
        
        with torch.no_grad():
            outputs = self.model(**tokens)
        
        embeddings = outputs.last_hidden_state[:, 0, :].numpy()
        return embeddings  # shape: (batch_size, 768)
```

---

## 4. Inference Engine Architecture

### 4.1 The Multi-Model Ensemble

AI-SAST uses multiple specialized models rather than one general model. Each model excels at a different vulnerability detection task:

```
MODEL 1: Taint Flow Classifier (Graph Neural Network)
  Input: Code data flow graph (heterogeneous nodes + edges)
  Purpose: Detect SQL injection, command injection, SSRF, path traversal
           (all require tracking data from source to dangerous sink)
  Architecture: Relational Graph Convolutional Network (RGCN)
  Training data: 450K labeled taint flows from NVD + internal incidents
  Precision: 0.87, Recall: 0.83 (on held-out test set)

MODEL 2: Vulnerability Pattern Classifier (Transformer Fine-tuned)
  Input: Code embedding (768-dim from UniXcoder) + AST features (47-dim)
  Purpose: Classify CWE type (SQL injection, XSS, path traversal, etc.)
  Architecture: CodeBERT fine-tuned on vulnerability classification
  Training data: CodeXGLUE vulnerability detection + 180K CVE-linked code samples
  AUC: 0.93

MODEL 3: Severity and Exploitability Predictor (Gradient Boosted Trees)
  Input: 38 structured features (complexity metrics, taint path length, context)
  Purpose: Predict CVSS score and likelihood of active exploitation
  Architecture: LightGBM
  Training data: 12K CVEs with CVSS scores and exploit availability data
  MAE on CVSS score: 0.8 (close enough for severity bucketing)

MODEL 4: False Positive Reducer (Random Forest + Calibration)
  Input: Finding metadata + code context + developer/repo history
  Purpose: Estimate P(false_positive | finding) to rank findings by actionability
  Architecture: Random Forest + Platt scaling calibration
  Training data: 280K analyst-labeled findings (TP/FP feedback loop)
  FP Rate reduction: 43% (from baseline 52% FPR to 29.6% FPR)

MODEL 5: Review Evasion Detector (Siamese Network + Rule Hybrid)
  Input: PR description + changed code + claimed vulnerability fix
  Purpose: Detect when PR introduces vulnerabilities while appearing to fix them
  Architecture: Siamese network comparing "claimed behavior" vs "actual behavior"
  Training data: 340 confirmed supply chain attacks + 8K normal security fix PRs
  Precision: 0.79 (high FP acceptable here — human review required anyway)
```

### 4.2 GNN for Taint Flow Detection — Deep Mechanics

**Why GNN over standard ML for taint flow:**

A vulnerability exists when a taint path connects a source to a sink. A taint path is a graph structure — the GNN naturally processes graph structures. A standard feedforward network would require manually enumerated features about the path (length, nodes, has_sanitizer) and can't capture the full topological context.

```python
import torch
import torch.nn as nn
from torch_geometric.nn import RGCNConv, global_mean_pool

class TaintFlowGNN(nn.Module):
    """
    Relational Graph Convolutional Network for vulnerability detection.
    
    Uses R-GCN because our code graph has multiple edge types (CALLS, DATA_FLOW,
    TAINT_FLOW, CONTROL_FLOW) — each edge type gets its own weight matrix.
    
    Architecture:
      3 R-GCN layers with 128 hidden units
      Message passing: each node aggregates information from its neighbors,
                       weighted by edge type
      Global pooling: convert variable-size graph to fixed-size vector
      MLP head: classify the graph as vulnerable or not
    """
    
    NUM_EDGE_TYPES = 6  # CALLS, DEFINES, DATA_FLOW, TAINT_FLOW, CONTROL_FLOW, CONTAINS
    NODE_FEAT_DIM = 24  # Number of node features (complexity, is_tainted, etc.)
    HIDDEN_DIM = 128
    NUM_CLASSES = 2  # vulnerable / not vulnerable
    
    def __init__(self):
        super().__init__()
        
        # 3 rounds of R-GCN message passing
        self.conv1 = RGCNConv(self.NODE_FEAT_DIM, self.HIDDEN_DIM, 
                               num_relations=self.NUM_EDGE_TYPES)
        self.conv2 = RGCNConv(self.HIDDEN_DIM, self.HIDDEN_DIM, 
                               num_relations=self.NUM_EDGE_TYPES)
        self.conv3 = RGCNConv(self.HIDDEN_DIM, self.HIDDEN_DIM // 2, 
                               num_relations=self.NUM_EDGE_TYPES)
        
        # MLP classifier on graph-level representation
        self.classifier = nn.Sequential(
            nn.Linear(self.HIDDEN_DIM // 2, 64),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Linear(32, self.NUM_CLASSES)
        )
        
        self.dropout = nn.Dropout(0.2)
    
    def forward(self, x, edge_index, edge_type, batch):
        """
        x: node features [N_nodes, NODE_FEAT_DIM]
        edge_index: connectivity [2, N_edges]
        edge_type: edge type for each edge [N_edges]
        batch: which graph each node belongs to [N_nodes] (for batched processing)
        """
        # 3 rounds of message passing
        # After each round: each node's representation encodes its neighborhood
        x = torch.relu(self.conv1(x, edge_index, edge_type))
        x = self.dropout(x)
        
        x = torch.relu(self.conv2(x, edge_index, edge_type))
        x = self.dropout(x)
        
        x = torch.relu(self.conv3(x, edge_index, edge_type))
        
        # Global mean pooling: condense graph to fixed-size vector
        # Each graph (function's code graph) becomes a single 64-dim vector
        graph_embedding = global_mean_pool(x, batch)
        
        # Classify: is this graph (code function) vulnerable?
        logits = self.classifier(graph_embedding)
        
        return logits  # [batch_size, 2]
    
    def explain_prediction(self, x, edge_index, edge_type, batch):
        """
        GNNExplainer: identify which nodes and edges contributed most to the prediction.
        This produces the "taint path" explanation shown to developers.
        """
        # Use GNNExplainer from torch_geometric for attribution
        from torch_geometric.explain import GNNExplainer
        explainer = GNNExplainer(self, epochs=200)
        node_mask, edge_mask = explainer.explain_graph(x, edge_index, edge_type)
        
        # Top-k most important nodes = the vulnerability path
        important_nodes = torch.argsort(node_mask, descending=True)[:10]
        important_edges = torch.argsort(edge_mask, descending=True)[:10]
        
        return important_nodes, important_edges
```

### 4.3 Micro-Batching vs. Streaming Inference

**The specific tradeoff for AI-SAST:**

Unlike runtime security systems that process events in real-time streams, AI-SAST processes discrete code units (files, functions) triggered by git events. The optimal strategy differs by model:

```
PER-FUNCTION ANALYSIS (streaming — process each function independently):
  Use when: function has isolated analysis (stateless check)
  Models: Taint source/sink detection (single function), hardcoded secret detection
  Latency: < 100ms per function
  Implementation: Individual inference calls, no batching needed

PER-FILE BATCH (micro-batch — batch all functions in a file):
  Use when: analysis is file-scoped (all functions in one file analyzed together)
  Models: File-level vulnerability classifier, intra-file taint flow
  Latency: 200-500ms per file
  Implementation: Collect all functions from a file, batch inference

PER-PR BATCH (full batch — batch all changed files in a PR):
  Use when: analysis requires cross-file context (interprocedural taint flow)
  Models: GNN over call graph (requires whole-PR graph construction)
  Latency: 2-10 seconds per PR
  Implementation: Build full PR graph, single GNN inference pass
  Optimization: Pre-compute embeddings for unchanged files (Redis cache)

FULL REPO SCAN (offline batch — nightly):
  Use when: comprehensive analysis with full interprocedural context
  Models: All models with full depth analysis
  Latency: Minutes to hours depending on repo size
  Implementation: Distributed workers, Spark for large repos
  Priority: Lower than PR scans (no blocking SLA)
```

### 4.4 Redis Caching for Incremental Analysis

A key optimization: most files in a PR haven't changed. Caching function-level analysis results avoids re-analyzing 99% of the codebase on each PR:

```python
class IncrementalAnalysisCache:
    """
    Cache analysis results at function granularity.
    Cache key: hash(function_source_code)
    
    Why function granularity (not file)?
    A file with 20 functions that changes one function:
      - File-level cache: invalidated entirely → re-analyze 20 functions
      - Function-level cache: invalidate 1 function → re-analyze 1 function
      
    Why hash of source (not function name + file)?
    A function renamed or moved has the same source → same analysis result.
    We care about what the code DOES, not where it lives.
    """
    
    CACHE_TTL = 7 * 24 * 3600  # 7-day TTL (analysis results stable while code stable)
    
    def get_cached_analysis(self, function_code: str) -> Optional[FunctionAnalysis]:
        """
        Cache hit: function was analyzed before, same source code.
        Returns None on cache miss.
        """
        cache_key = f"sast:func:{hashlib.sha256(function_code.encode()).hexdigest()}"
        cached = self.redis.get(cache_key)
        
        if cached is None:
            self.metrics.increment('cache.miss')
            return None
        
        self.metrics.increment('cache.hit')
        return FunctionAnalysis.from_json(cached)
    
    def cache_analysis(self, function_code: str, analysis: FunctionAnalysis):
        cache_key = f"sast:func:{hashlib.sha256(function_code.encode()).hexdigest()}"
        self.redis.set(cache_key, analysis.to_json(), ex=self.CACHE_TTL)
    
    def cache_embedding(self, function_code: str, embedding: np.ndarray):
        """
        Cache the code embedding separately (expensive to compute — model inference).
        Embeddings are more expensive than AST analysis, so cache them separately
        with a longer TTL.
        """
        cache_key = f"sast:embed:{hashlib.sha256(function_code.encode()).hexdigest()}"
        self.redis.set(
            cache_key, 
            embedding.astype(np.float16).tobytes(),  # FP16 to save memory
            ex=30 * 24 * 3600  # 30-day TTL for embeddings
        )
    
    def get_cached_embedding(self, function_code: str) -> Optional[np.ndarray]:
        cache_key = f"sast:embed:{hashlib.sha256(function_code.encode()).hexdigest()}"
        cached_bytes = self.redis.get(cache_key)
        if cached_bytes is None:
            return None
        return np.frombuffer(cached_bytes, dtype=np.float16).astype(np.float32)
```

**Cache hit rates in production:**
- For incremental PR scans (typical 10-file change on 1000-file repo): ~98% cache hit rate
- For the 2% cache misses (new or modified functions): full analysis runs
- Result: PR scan that would take 45 seconds takes 3 seconds (95% from cache, 5% from inference)

---

## 5. Correlation & Alerting Flow

### 5.1 Finding Deduplication and Ranking

A single PR might generate dozens of raw findings. Before presenting to developers or security engineers, findings go through a deduplication and ranking pipeline:

```python
class FindingProcessor:
    """
    Transforms raw model findings into ranked, deduplicated, actionable findings.
    """
    
    def process(self, raw_findings: list[RawFinding], pr_context: PRContext) -> list[Finding]:
        # Step 1: Deduplicate (same vulnerability, different model detected it)
        deduplicated = self._deduplicate(raw_findings)
        
        # Step 2: Enrich each finding with context
        enriched = [self._enrich(f, pr_context) for f in deduplicated]
        
        # Step 3: False positive reduction
        for finding in enriched:
            finding.fp_probability = self.fp_reducer.predict(finding, pr_context)
            finding.actionable_score = 1.0 - finding.fp_probability
        
        # Step 4: Severity computation
        for finding in enriched:
            finding.severity = self._compute_severity(finding)
        
        # Step 5: Rank by: severity × actionability × exploitability
        ranked = sorted(enriched, 
                        key=lambda f: f.severity_score * f.actionable_score * f.exploit_score,
                        reverse=True)
        
        # Step 6: Apply blocking policy
        for finding in ranked:
            finding.is_blocking = self._is_blocking(finding, pr_context)
        
        return ranked
    
    def _compute_severity(self, finding: Finding) -> Severity:
        """
        Combine model severity prediction with CVSS-like scoring.
        """
        # Model-predicted CVSS score (0-10)
        model_cvss = self.severity_model.predict(finding)
        
        # Contextual adjustments
        context_multiplier = 1.0
        
        # Adjustment: asset criticality
        if finding.repository.criticality == 'PAYMENT':
            context_multiplier *= 1.5
        
        # Adjustment: auth-related code is higher severity
        if 'auth' in finding.file_path or 'login' in finding.file_path:
            context_multiplier *= 1.3
        
        # Adjustment: taint path length (shorter path = more directly exploitable)
        if finding.taint_path_length <= 2:
            context_multiplier *= 1.2
        elif finding.taint_path_length >= 8:
            context_multiplier *= 0.8
        
        # Adjustment: has external exploit been published
        if self.nvd_checker.has_known_exploit(finding.cwe):
            context_multiplier *= 1.4
        
        adjusted_cvss = min(10.0, model_cvss * context_multiplier)
        return Severity.from_cvss(adjusted_cvss)
    
    def _is_blocking(self, finding: Finding, pr_context: PRContext) -> bool:
        """
        Determines if this finding should block the PR from merging.
        """
        # ALWAYS block: critical findings in critical repos
        if finding.severity == Severity.CRITICAL and pr_context.repo.is_critical:
            return True
        
        # ALWAYS block: any finding with known PoC exploit
        if self.exploit_tracker.has_poc(finding.cwe, finding.vulnerability_type):
            return True
        
        # ALWAYS block: supply chain attack patterns
        if finding.is_evasion_attack:
            return True
        
        # BLOCK: high severity in security-sensitive files
        if finding.severity >= Severity.HIGH and finding.file_is_security_sensitive:
            return True
        
        # WARN but don't block: medium severity
        if finding.severity == Severity.MEDIUM:
            return pr_context.repo.strict_mode  # Block only if strict mode enabled
        
        # LOW: never block
        return False
```

### 5.2 Developer-Facing Alert Format

Developers are the primary consumers of AI-SAST alerts. The alert must be actionable and precise:

```markdown
## 🚨 Critical Security Finding: SQL Injection (CWE-89)

**File:** `auth/authentication.py` | **Line:** 41 | **Function:** `_log_auth_event`

### What was found

The `client_ip` parameter, which comes from the `X-Forwarded-For` HTTP header, 
is embedded directly into a SQL query using f-string formatting. An attacker can 
control this header value and inject arbitrary SQL.

### Taint Path (how the vulnerability works)

```
request.headers.get('X-Forwarded-For')  [line 28, authenticate_user]
         ↓ passed as argument
_log_auth_event(client_ip=...)           [line 31]
         ↓ embedded in f-string
f"INSERT INTO auth_log...'{client_ip}'"  [line 38]
         ↓ executed without parameterization
db.execute(log_entry)                    [line 41]  ← VULNERABLE SINK
```

### Attack example

An attacker sends:
```
X-Forwarded-For: 1.2.3.4', 'admin', LOAD_FILE('/etc/passwd'))-- 
```

This results in the SQL:
```sql
INSERT INTO auth_log (user, event, ip, ts) 
VALUES ('admin', 'success', '1.2.3.4', LOAD_FILE('/etc/passwd'))--', NOW())
```

### Fix

Replace f-string with parameterized query:

```python
# VULNERABLE (current code)
log_entry = f"INSERT INTO auth_log (user, event, ip, ts) VALUES ('{username}', '{event_type}', '{client_ip}', NOW())"
db.execute(log_entry)

# FIXED
db.execute(
    "INSERT INTO auth_log (user, event, ip, ts) VALUES (%s, %s, %s, NOW())",
    (username, event_type, client_ip)
)
```

### AI Confidence: 94% | Severity: CRITICAL | Exploit Likelihood: HIGH
*This finding blocks PR merge until resolved.*
```

### 5.3 SOAR Integration for Security Team Alerts

When AI-SAST detects supply chain attacks or critical findings in critical repositories, it escalates to the security team via SOAR:

```python
class SASTSOARIntegration:
    
    def escalate_supply_chain_finding(self, finding: Finding, pr_context: PRContext):
        """
        Supply chain attack patterns require immediate security team attention.
        The SOAR playbook investigates the contributor and other open PRs.
        """
        incident = {
            "type": "SUPPLY_CHAIN_ATTACK_SUSPECTED",
            "severity": "P1",
            "repository": pr_context.repo.full_name,
            "repository_criticality": pr_context.repo.criticality,
            "pr_number": pr_context.pr_number,
            "pr_url": pr_context.pr_url,
            
            "contributor": {
                "username": pr_context.author,
                "account_age_days": pr_context.author_account_age_days,
                "total_prs": pr_context.author_total_prs,
                "this_repo_prior_prs": pr_context.author_prior_prs_this_repo,
                "time_to_pr_after_issue_public": pr_context.issue_to_pr_minutes
            },
            
            "finding": {
                "pattern": finding.evasion_pattern,
                "confidence": finding.evasion_confidence,
                "vulnerability_type": finding.vulnerability_type,
                "vulnerability_location": f"{finding.file}:{finding.line}",
                "vulnerability_in_helper_of_fix": finding.is_helper_vuln
            },
            
            "automated_actions_taken": [
                "PR_BLOCKED",
                "MERGE_DISABLED",
                "DEVELOPER_NOTIFIED_VIA_PR_COMMENT"
            ],
            
            "recommended_actions": [
                "Verify contributor identity via out-of-band channel",
                "Review all open PRs from this contributor",
                "Audit any PRs from this contributor that were already merged",
                "Consider revoking repository access pending investigation",
                "Report to GitHub Trust and Safety if confirmed attack"
            ]
        }
        
        # Create SOAR incident
        incident_id = self.soar.create_incident(incident)
        
        # Page security on-call
        self.pagerduty.trigger_alert(
            title=f"Supply Chain Attack: {pr_context.repo.name} PR #{pr_context.pr_number}",
            details=incident,
            severity="critical"
        )
        
        return incident_id
```

---

## 6. Attack Scenarios (Evasion Tactics)

### 6.1 Evasion Tactic 1: Semantic-Preserving Obfuscation

**Attacker goal:** Make vulnerable code look innocuous to ML models trained on canonical vulnerability patterns.

**The canonical pattern the model recognizes:**
```python
# CANONICAL SQL injection — high model confidence
query = f"SELECT * FROM users WHERE name = '{user_input}'"
db.execute(query)
```

**Obfuscated version that preserves the vulnerability but changes the surface form:**

```python
# Obfuscated: same vulnerability, different appearance
def _build_auth_query(creds):
    # Split and rejoin to avoid obvious f-string pattern
    parts = [
        "SELECT * FROM ",
        table_name,   # ← table_name is a "constant" but user-controlled
        " WHERE username = '",
        creds[0],     # ← user input via list indexing
        "' AND token = '",
        creds[1],
        "'"
    ]
    return "".join(parts)

# Usage
user_data = [request.form['u'], request.form['t']]
query = _build_auth_query(user_data)
db_conn.execute(query)  # ← same vulnerability, very different code structure
```

**Step-by-step evasion execution:**

```
1. The string is built via "".join(parts) instead of f-string
   → Model trained on f-string pattern may not recognize this as string concatenation
   
2. The user input arrives as creds[0], creds[1] (list element access)
   → Taint propagation must track through list membership, harder than direct variable
   
3. The query building is split from the execution
   → _build_auth_query() and db.execute() are in different functions
   → Cross-function taint tracking may lose the path if context is limited
   
4. table_name appears to be a constant (defined elsewhere in the file)
   → But it's actually set from an API parameter earlier in the request flow
   → Model sees "table_name" as a local variable, not tainted input
```

**Why the model might miss it:**

- The token-level embedding model sees `"".join(parts)` — this pattern appears frequently in non-vulnerable code (building HTML, building log messages)
- The taint tracker must follow: `request.form['u']` → `user_data[0]` (list element) → `creds[0]` (passed as list) → `parts[3]` (list element) → `"".join(parts)` → returned string → `query` → `db_conn.execute(query)` — this is a 6-hop taint path through list membership, which pushes the limits of the taint analyzer

**Detection improvement:**

Train the taint tracker on examples that include list-based taint propagation. Add a rule: any string passed to `db.execute()` that was constructed by `str.join()` is treated as a potential injection vector and checked for taint.

---

### 6.2 Evasion Tactic 2: Timing the Submission (Low-and-Slow)

**The attack:** Instead of one clearly malicious PR, the attacker makes many small PRs over months, building trust and incrementally expanding their footprint.

```
Month 1: PR #1 — Trivial documentation fix
         "Update README.md with correct API endpoint"
         → No code change, no security risk
         → SAST: passes immediately
         → Contributor gains "legitimate contributor" status
         
Month 2: PR #2 — Genuine bug fix
         "Fix null pointer exception in error handling"
         → Small, correct code change
         → SAST: passes
         → Contributor gains more trust, maintainer marks as "known good contributor"
         
Month 3: PR #3 — "Performance optimization"
         "Cache database connections to reduce latency"
         → Introduces a shared connection pool without proper isolation
         → NOT a traditional vulnerability pattern
         → SAST: passes (this is a design flaw, not a code-level injection pattern)
         → Lays groundwork: shared connection = cross-request data leakage possible
         
Month 4: PR #4 — "Fix memory leak in connection pool"
         → Modifies the connection pool introduced in PR #3
         → Introduces connection pool shared state corruption under race conditions
         → SAST: might flag as thread safety issue (medium confidence)
         → Human reviewers: "same contributor, same feature, makes sense"
         → Gets merged after quick review
         
Month 5: The payoff — PR #5 uses the connection pool design flaw
         → The design flaw in PR #3+4 enables PR #5 to exploit the issue
         → PR #5 itself is clean (no injection patterns)
         → The vulnerability requires understanding the full history
```

**Why the model misses it:**

- AI-SAST analyzes code in isolation (single PR at a time)
- The vulnerability is distributed across 3 PRs submitted over 3 months
- No single PR contains a recognizable vulnerability pattern
- The model has no mechanism for "analyze this PR in the context of all previous PRs from this author"

**Detection requirement:**

A contributor-history-aware analysis that:
1. Tracks all code changes by a contributor over time
2. Builds a "contributor intent graph" (what data flows has this contributor modified?)
3. Analyzes whether the cumulative changes create a vulnerability even if no individual change does

This is significantly harder than single-PR analysis and requires a different architecture (RAG-style retrieval of contributor history + reasoning over the full timeline).

---

### 6.3 Evasion Tactic 3: Model-Specific Adversarial Examples

**The attack:** An attacker who has access to an open-source or leaked version of the AI-SAST model can craft code that scores low on the vulnerability classifier while remaining functionally exploitable.

**The technique (gradient-based adversarial attack on code):**

```python
# Attacker wants to insert this SQL injection but have the model score it as safe:
vulnerable_code = """
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)
"""

# Model scores: P(vulnerable) = 0.94 (correctly flagged)
# Attack goal: find a semantically equivalent version with P(vulnerable) < 0.30

# Adversarial transformation strategy:
# 1. Find variable names / comment patterns that correlate with SAFE code in training data
# 2. Add those patterns to the vulnerable code
# 3. The model may anchor on the "safe" surface patterns and lower its vulnerability score

adversarial_code = """
def get_user(validated_user_id: int) -> Optional[User]:
    '''
    Retrieves user by ID.
    Input validation: user_id must be an integer (enforced by type annotation).
    Security note: Uses ORM-compatible query pattern.
    '''
    # Type-checked parameter ensures safety (mypy validated)
    _safe_id = int(validated_user_id)  # Redundant cast but signals intent
    
    # Build query using validated integer parameter
    # Note: integer parameters cannot contain SQL injection
    query = f"SELECT * FROM users WHERE id = {_safe_id}"  # ← STILL VULNERABLE
    return db.execute(query)
"""

# Attacker's reasoning:
# - Parameter name "validated_user_id" signals sanitization to the model
# - Type annotation "-> Optional[User]" looks like a well-written function
# - Comment claiming "type-checked parameter ensures safety"
# - Variable name "_safe_id" signals safety
# - Comment "integer parameters cannot contain SQL injection" (partially true but misleading)
# - The f-string STILL uses _safe_id, which was cast from user-controlled input
```

**Why the model might be fooled:**

If the model's code embedding was trained on millions of functions where:
- Functions with descriptive names like "validated_" are mostly safe
- Functions with security comments are mostly safe
- Functions with type annotations are somewhat safer

...then the adversarial code may land in the "safe" region of the embedding space even though the execution is still vulnerable.

**The actual exploitability:**

`int(validated_user_id)` does NOT prevent SQL injection if the integer value is already injected:
- `db.execute(f"SELECT * FROM users WHERE id = {_safe_id}")` where `_safe_id = 1 OR 1=1`
- Wait, `int("1 OR 1=1")` would raise `ValueError`...
- But if `user_id` comes from a format that can pass `int()`: `user_id = 1; DROP TABLE users--`
- `int("1")` = 1, but the `; DROP TABLE users--` is silently truncated by `int()`
- Actually in this specific case, the attack vector is limited — the attacker was right that integers are harder to inject through

**The subtle lesson:** Adversarial examples against AI-SAST might incidentally reduce the actual vulnerability (int() does limit the attack). This is a strange property — adversarial examples might create "less vulnerable" but still vulnerable code.

**Detection improvement:** Don't rely only on surface features (variable names, comments) — root the analysis in the actual data flow. The GNN-based taint analysis is more resistant to this attack because it operates on the AST/data flow graph, not the surface text.

---

### 6.4 Evasion Tactic 4: Hiding Vulnerability in Generated Code

**The attack:** Commit a code generator, not the vulnerable code itself. The generator is clean; it generates vulnerable code at runtime.

```python
# COMMITTED CODE (appears clean to SAST):
def build_query_template(table: str, condition_field: str) -> str:
    """
    Builds a parameterized query template.
    Template will be used with safe parameter binding.
    """
    # This looks like it's building a parameterized query template
    return f"SELECT * FROM {table} WHERE {condition_field} = %s"

# USAGE AT RUNTIME (also appears clean individually):
template = build_query_template("users", request.args.get("field"))  # ← field is user-controlled
query = template % (value,)  # ← the %s is being used for the value, but "field" is tainted
db.execute(query)  # Second-order injection: table and field names are not parameterized
```

**Why the model misses it:**

- `build_query_template()` generates a string that CONTAINS `%s` — the model may classify this as "uses parameterized queries" even though the `table` and `condition_field` are not parameterized
- The function returns a template, not a final query — the model analyzing this function in isolation sees it returns a string, which is a common pattern
- The vulnerability is assembled across multiple lines and function calls
- "Second-order injection" (where the injected value is the column name, not the value) is less common in training data

---

## 7. Failure Points & Scaling

### 7.1 Failures Under Load (Mass PR Events)

**Scenario:** An organization announces a major dependency upgrade (e.g., moving from Python 3.9 to 3.11). Automated tooling opens 800 dependency-update PRs simultaneously across all repositories.

```
Impact cascade:

T+0: 800 PR webhook events arrive in 30 seconds
  → sast.jobs.standard: 800 new jobs
  → Normal throughput: 60 jobs/minute (15 minutes SLA)
  → Time to process all 800 jobs at normal rate: 13 minutes
  → Actually OK for this case, but...

T+5min: Each dependency PR triggers transitive analysis
  → Updating requirements.txt → check new versions for known CVEs
  → But also: re-analyze all files that IMPORT the updated packages
  → For a package like `requests`: 200 files import it
  → 800 PRs × 200 files = 160,000 file analyses triggered
  → Time to process at normal rate: 44 HOURS

Failure: CI checks on all 800 PRs stay "pending" for hours
  → Developers can't merge anything
  → Engineering velocity collapses
  → Ops team manually overrides CI checks ("we trust the automated dep upgrade")
  → SAST effectively bypassed due to overload
```

**Scaling mechanisms:**

```python
class LoadSheddingManager:
    """
    Implements graceful degradation under load.
    Under high load: prioritize high-risk analysis, skip low-risk.
    """
    
    def should_run_deep_analysis(self, job: ScanJob) -> AnalysisDepth:
        current_queue_depth = self.queue_monitor.get_depth('sast.jobs.standard')
        
        if current_queue_depth < 100:
            return AnalysisDepth.FULL  # Full interprocedural analysis
        
        elif current_queue_depth < 500:
            # Reduced depth: only analyze directly changed functions
            # Skip transitive impact analysis
            return AnalysisDepth.CHANGED_FILES_ONLY
        
        elif current_queue_depth < 2000:
            # Minimal: only run fast deterministic rules, skip ML models
            # Reserve for: critical repos only
            return AnalysisDepth.RULES_ONLY if job.repo.is_critical else AnalysisDepth.SKIP
        
        else:
            # Emergency: only block on deterministic CRITICAL rules
            # ML models suspended until queue drains
            return AnalysisDepth.DETERMINISTIC_CRITICAL_ONLY if job.repo.is_critical else AnalysisDepth.SKIP
    
    def should_run_transitive_analysis(self, job: ScanJob) -> bool:
        """
        Transitive analysis (analyzing callers of changed functions) is expensive.
        Skip it during high load — risk-based decision.
        """
        if self.is_under_high_load():
            # Transitive analysis for critical repos only when under load
            return job.repo.is_critical
        return True
```

### 7.2 Concept Drift in AI-SAST

**The specific challenge:** The vulnerability landscape changes. New vulnerability classes emerge (prototype pollution in JavaScript, SSRF via AWS IMDS, desync attacks). The model trained on 2020-era vulnerabilities doesn't recognize 2024-era patterns.

```
Example: HTTP Request Smuggling
  2019: Very few examples in training data
  2020: Major vulnerabilities discovered → NVD gets 50 CVEs
  2021: Model still doesn't reliably detect it (training data from 2018-2020 predates the flood)
  
Model behavior: 
  HTTP request smuggling code → P(vulnerable) = 0.23 (below threshold)
  Correctly written suspicious HTTP header handling → flagged at P(vulnerable) = 0.71
  
The model has learned a proxy for "suspicious HTTP code" but not the specific
semantic pattern of request smuggling (CL.TE vs TE.CL header conflicts).
```

**Drift detection and adaptation:**

```python
class VulnerabilityConceptDriftDetector:
    """
    Monitors AI-SAST model for concept drift using two signals:
    1. CWE distribution shift: are we seeing more/different vulnerability types?
    2. Analyst feedback: FP/FN rate changes over time
    """
    
    def check_cwe_distribution_drift(self) -> DriftReport:
        # Current 30-day distribution of CWEs in findings
        current_dist = self.db.get_cwe_distribution(days=30)
        
        # Baseline distribution (from model training period)
        baseline_dist = self.model_registry.get_training_cwe_distribution()
        
        # Compute KL divergence
        kl_div = self._kl_divergence(current_dist, baseline_dist)
        
        # Check for new CWE types appearing (zero in training, nonzero now)
        new_cwes = set(current_dist.keys()) - set(baseline_dist.keys())
        
        return DriftReport(
            kl_divergence=kl_div,
            new_cwe_types=new_cwes,
            alert_if_kl_above=0.15,
            alert_if_new_cwes=len(new_cwes) > 2
        )
    
    def adapt_to_new_vulnerability_class(self, new_cwe: str, examples: list[CodeSample]):
        """
        When a new vulnerability class is identified:
        1. Add the examples to a rapid fine-tuning dataset
        2. Fine-tune the model on new examples (LoRA fine-tuning for speed)
        3. Test on held-out examples before deploying
        4. Deploy with A/B traffic split (10% new model, 90% old)
        """
        # Fine-tune using Low-Rank Adaptation (LoRA) — only fine-tune 1% of parameters
        # Full fine-tune would take weeks; LoRA takes hours on the same GPU
        fine_tuned_model = self.lora_fine_tuner.fine_tune(
            base_model=self.current_model,
            new_examples=examples,
            epochs=3,
            lora_rank=8  # Update only 8-dimensional subspace of each weight matrix
        )
        
        # Validate on existing CWEs: does the fine-tuned model still detect old patterns?
        regression_results = self.evaluate_on_regression_suite(fine_tuned_model)
        if regression_results.any_degradation_above_threshold():
            raise ModelRegressionError("Fine-tuning degraded existing detection quality")
        
        # Deploy to staging
        self.model_registry.deploy_to_staging(fine_tuned_model, cwe=new_cwe)
```

### 7.3 False Positive Storms

**The developer experience failure:** If the FP rate spikes (e.g., after a rule update that's too aggressive), developers begin ignoring findings. "Alert fatigue" in the developer audience is as dangerous as alert fatigue in the SOC.

**FP storm triggers in AI-SAST:**

```
Trigger 1: New language version introduces a pattern that looks like a vulnerability
  Example: Python 3.12 introduced match/case statements
           AI-SAST model trained before Python 3.12 incorrectly flags match statements
           as "obfuscated switch statements that bypass input validation"
           → FP spike: 400 false positives on day 1 of Python 3.12 adoption
           
Trigger 2: New internal framework introduces safe abstractions the model doesn't know
  Example: Company builds internal ORM with safe query construction
           Internally: safe_query = orm.build("users", user_id)
           Model sees: a string passed to a db function → SQL injection?
           → FP spike: every ORM usage flagged

Trigger 3: Model update introduces regression
  Example: Fine-tuning for request smuggling accidentally changes the feature
           weights for "string passed to execute()" → now everything with execute() is flagged
           → FP spike: 10x normal false positive rate
```

**FP mitigation system:**

```python
class FalsePositiveManagementSystem:
    
    def register_safe_pattern(self, pattern: SafePattern, justification: str):
        """
        Security team can register safe patterns:
        - Safe internal library calls that look like sinks
        - Code patterns that are always sanitized by surrounding framework
        - Language-specific patterns that are structurally safe
        """
        # Register in the FP suppression database
        self.db.insert_safe_pattern(pattern, justification, approved_by=current_user())
        
        # Retroactively dismiss existing findings that match this pattern
        dismissed = self.db.dismiss_findings_matching_pattern(pattern)
        
        # Update the false positive training data (for next model retraining)
        self.training_data_manager.add_false_positive_examples(
            findings=dismissed,
            reason=justification
        )
        
        # Trigger re-scoring of recent findings
        self.queue_rescoring(pattern, lookback_days=7)
    
    def monitor_fp_rate(self) -> FPRateReport:
        # Compare analyst FP dismissal rate vs historical baseline
        current_fp_rate = self.analytics.get_fp_rate(days=7, lookback_window=30)
        baseline_fp_rate = self.analytics.get_baseline_fp_rate()
        
        fp_rate_change = (current_fp_rate - baseline_fp_rate) / baseline_fp_rate
        
        if fp_rate_change > 0.5:  # FP rate increased by 50%
            # Trigger investigation
            self.alert_mlops_team(
                f"FP rate spike: {current_fp_rate:.1%} vs baseline {baseline_fp_rate:.1%}",
                severity="HIGH"
            )
            # Check if recent model update caused this
            recent_model_updates = self.model_registry.get_recent_updates(days=7)
            if recent_model_updates:
                self.flag_for_rollback_consideration(recent_model_updates[-1])
        
        return FPRateReport(current=current_fp_rate, baseline=baseline_fp_rate, 
                            change_pct=fp_rate_change * 100)
```

---

## 8. Mitigations & Defense-in-Depth

### 8.1 Hybrid Architecture: ML + Deterministic Rules

Neither pure ML nor pure rules is sufficient. The optimal architecture layers both:

```
LAYER 1 — DETERMINISTIC (always runs, high precision):
  Semgrep rules: handcrafted patterns for known vulnerability types
  Regex patterns: hardcoded secrets, dangerous function calls
  AST rules: specific AST patterns that are always dangerous
  
  Properties:
    - Near-zero false negative for patterns they cover
    - Fully explainable (analyst can see exactly which rule fired)
    - No drift: rules don't change unless humans change them
    - Bias toward precision (fewer FPs, possibly more FNs)

LAYER 2 — ML TAINT ANALYSIS (interprocedural, catches what rules miss):
  GNN taint flow analysis
  Transformer-based semantic analysis
  
  Properties:
    - Catches novel patterns not covered by rules
    - Handles interprocedural taint (cross-function vulnerability)
    - Some FP rate (handled by FP reducer)
    - Can drift (requires monitoring)

LAYER 3 — CONTEXTUAL SCORING (ranking and prioritization):
  FP reducer (Random Forest)
  Severity predictor
  Exploit likelihood scorer
  
  Properties:
    - Doesn't detect new vulnerabilities
    - Improves signal-to-noise ratio of what's surfaced to humans
    - Reduces alert fatigue

LAYER 4 — BEHAVIORAL ANALYSIS (meta-level threat detection):
  Supply chain attack detector
  Contributor behavioral analysis
  Review evasion classifier
  
  Properties:
    - Not a code analysis layer — analyzes the PR process itself
    - Catches sophisticated attackers who evade code-level analysis
    - Highest false positive tolerance (human review required anyway)
```

### 8.2 Adversarial Hardening

To counter the adversarial example attacks described in Section 6.3:

```python
class AdversarialRobustnessTrainer:
    """
    Trains the AI-SAST model to be robust against adversarial transformations.
    
    Adversarial training: generate adversarial examples during training,
    train the model to still classify them correctly.
    
    Key insight for AI-SAST: adversarial examples in code must be
    "semantics-preserving" — the code must still COMPILE and RUN the same way.
    This constraint limits the attacker's options.
    """
    
    SEMANTIC_PRESERVING_TRANSFORMS = [
        # Variable renaming (model should not rely on variable names)
        lambda code: rename_variables_randomly(code),
        
        # Add security-looking comments that are misleading
        lambda code: add_misleading_security_comments(code),
        
        # Change string concatenation method (f-string → %.format → "".join())
        lambda code: transform_string_concatenation(code),
        
        # Add type annotations (may make model think code is more validated)
        lambda code: add_type_annotations(code),
        
        # Wrap in extra function calls (deeper call stack to obscure pattern)
        lambda code: wrap_in_helper_function(code),
        
        # Add dead code that looks like sanitization
        lambda code: add_dummy_sanitization_that_is_never_called(code),
    ]
    
    def generate_adversarial_examples(self, 
                                        vulnerable_code: str,
                                        n_transforms: int = 5) -> list[str]:
        """
        Apply random combinations of semantic-preserving transforms.
        Verify the code is still vulnerable after transformation.
        Add to training set with "vulnerable" label.
        """
        adversarial_examples = []
        
        for _ in range(n_transforms):
            transformed = vulnerable_code
            # Apply 2-4 random transforms
            n = random.randint(2, 4)
            selected_transforms = random.sample(self.SEMANTIC_PRESERVING_TRANSFORMS, n)
            
            for transform in selected_transforms:
                transformed = transform(transformed)
            
            # Verify: does the transformed code still contain the vulnerability?
            # (Some transforms might accidentally remove the vulnerability)
            if self.oracle.is_still_vulnerable(transformed):
                adversarial_examples.append((transformed, "vulnerable"))
        
        return adversarial_examples
    
    def train_with_adversarial_augmentation(self, model, dataset):
        """
        Augment training data with adversarial examples.
        Forces model to learn semantic features (taint flow) rather than
        surface features (variable names, comments).
        """
        augmented_dataset = list(dataset)
        
        for code, label in dataset:
            if label == "vulnerable":
                # Generate adversarial versions of vulnerable code
                adversarial = self.generate_adversarial_examples(code)
                augmented_dataset.extend(adversarial)
        
        # Train on augmented dataset
        return self.train(model, augmented_dataset)
```

### 8.3 Supply Chain Attack-Specific Defenses

```python
class SupplyChainDefenseLayer:
    """
    Meta-level analysis targeting supply chain attacks specifically.
    Analyzes contributor behavior, not just code.
    """
    
    def analyze_contributor(self, username: str, pr: PullRequest) -> ContributorRisk:
        risk_score = 0.0
        risk_factors = []
        
        # Account age risk
        account_age_days = self.github_api.get_account_age(username)
        if account_age_days < 30:
            risk_score += 0.4
            risk_factors.append(f"New account ({account_age_days} days old)")
        
        # Repository history
        prior_prs_this_repo = self.github_api.get_pr_count(username, pr.repo)
        if prior_prs_this_repo == 0:
            risk_score += 0.3
            risk_factors.append("First PR to this repository")
        
        # Timing: PR opened shortly after sensitive issue went public
        if pr.references_issue:
            issue = self.github_api.get_issue(pr.references_issue)
            if issue.is_security_related:
                time_delta = (pr.created_at - issue.published_at).total_seconds() / 60
                if time_delta < 60:  # Within 1 hour of issue going public
                    risk_score += 0.5
                    risk_factors.append(f"PR opened {time_delta:.0f} min after security issue published")
        
        # Simultaneous PRs across repos (fraud ring pattern)
        simultaneous_prs = self.github_api.get_simultaneous_prs(username, hours=24)
        if len(simultaneous_prs) > 5:
            risk_score += 0.4
            risk_factors.append(f"Submitting to {len(simultaneous_prs)} repos simultaneously")
        
        # Email domain risk
        email = self.github_api.get_email(username)
        if email and self.disposable_email_checker.is_disposable(email):
            risk_score += 0.3
            risk_factors.append("Disposable email domain")
        
        # Code quality inconsistency (sophisticated attacker indicator)
        # Attacker writes excellent code in most functions but inserts one subtle vulnerability
        if self.code_quality_analyzer.has_suspicious_quality_inconsistency(pr):
            risk_score += 0.25
            risk_factors.append("Code quality inconsistency: one function significantly lower quality")
        
        return ContributorRisk(
            score=min(1.0, risk_score),
            factors=risk_factors,
            recommendation="BLOCK" if risk_score > 0.7 else "REVIEW" if risk_score > 0.4 else "ALLOW"
        )
```

---

## 9. Observability

### 9.1 Monitoring Model Accuracy and Drift

```yaml
# Prometheus metrics for AI-SAST system

# === PIPELINE HEALTH ===
sast_scan_jobs_queued_total{priority}: count of queued jobs by priority
sast_scan_jobs_completed_total{status}: completed, failed, timed_out
sast_scan_duration_seconds{quantile, depth}: p50/p99 scan time by analysis depth
sast_cache_hit_rate: fraction of function analyses served from Redis cache
sast_clone_failure_rate: fraction of repo clone operations that failed
sast_parse_failure_rate{language}: fraction of parse operations that failed

# === FINDING METRICS ===
sast_findings_total{severity, cwe, detection_method}: findings by type
sast_findings_blocked_prs_total: PRs blocked due to findings
sast_findings_false_positive_rate_rolling_7d: analyst-labeled FP rate
sast_findings_false_negative_rate_rolling_30d: missed vulnerabilities (from post-incident review)
sast_findings_per_pr{repo_criticality}: mean findings per PR (drift indicator)

# === MODEL HEALTH ===
sast_model_inference_latency_ms{model, quantile}: per-model p99 latency
sast_model_inference_errors_total{model, error_type}: inference failures
sast_model_confidence_distribution{model}: histogram of confidence scores
sast_model_age_days{model}: days since last model update
sast_cwe_distribution_kl_divergence: KL divergence from training CWE distribution
sast_embedding_cache_staleness_days: mean age of cached embeddings

# === DEVELOPER EXPERIENCE ===
sast_developer_dismissed_findings_total{reason}: manually dismissed by dev
sast_developer_override_prs_total: PRs where CI check was overridden by admin
sast_time_to_fix_minutes{severity}: time between finding reported and fix committed
sast_finding_actionability_score_distribution: distribution of actionability scores
```

**Alert thresholds:**

```yaml
# MLOps team alerts:
- alert: SASTModelAgeExceedsThreshold
  expr: sast_model_age_days > 90
  severity: WARNING
  
- alert: SASTFalsepositiveRateSpike
  expr: sast_findings_false_positive_rate_rolling_7d > 0.40
  for: 2h
  severity: HIGH

- alert: SASTCWEDistributionDrift
  expr: sast_cwe_distribution_kl_divergence > 0.15
  severity: MEDIUM

- alert: SASTInferenceSLAViolation
  expr: sast_scan_duration_seconds{quantile="0.99", priority="critical"} > 120
  severity: HIGH

# SOC team alerts:
- alert: SASTSupplyChainAttackDetected
  expr: sast_supply_chain_findings_total > 0
  severity: CRITICAL
  annotations:
    summary: "Supply chain attack pattern detected in PR"
    
- alert: SASTCriticalVulnerabilityInCriticalRepo
  expr: sast_findings_total{severity="CRITICAL", repo_criticality="PAYMENT"} > 0
  severity: HIGH

- alert: SASTDeveloperOverridingCIChecks
  expr: increase(sast_developer_override_prs_total[1h]) > 5
  severity: MEDIUM
  annotations:
    summary: "Multiple CI override events — possible security control bypass attempt"
```

### 9.2 Tracing an Alert Back to Raw Code

Every finding has a complete audit trail:

```
Finding: sast-finding-a1b2c3d4 (SQL Injection, CWE-89, CRITICAL)
  ↓
PR: github.com/org/payment-service/pull/4821
  ↓
Commit: def456 (head commit of PR branch)
  ↓
Changed File: auth/authentication.py (line 38-41)
  ↓
Raw Source Code: git show def456:auth/authentication.py
  (stored in S3: s3://sast-artifacts/org/payment-service/def456/auth_authentication.py)
  ↓
AST Representation: stored as JSON
  (s3://sast-artifacts/org/payment-service/def456/asts/auth_authentication.py.ast.json)
  ↓
Feature Vector: stored as NPY
  (s3://sast-artifacts/org/payment-service/def456/features/_log_auth_event.npy)
  ↓
GNN Graph: stored as GraphML
  (s3://sast-artifacts/org/payment-service/def456/graphs/_log_auth_event.graphml)
  ↓
Model Input + Output: stored for debugging
  (s3://sast-artifacts/org/payment-service/def456/inference/_log_auth_event_gnn.json)
  Contains: {
    "input_graph": {...},
    "model_version": "taint-gnn-v3.2.1-2024-01-10",
    "output_logits": [0.06, 0.94],
    "prediction": "vulnerable",
    "confidence": 0.94,
    "explanation_nodes": [12, 7, 18, 3],  // GNNExplainer important nodes
    "explanation_edges": [24, 31, 7]       // GNNExplainer important edges
  }
  ↓
Replay: acd-replay --finding-id sast-finding-a1b2c3d4
  → Loads the exact model version from registry
  → Loads the exact feature vector from S3
  → Reruns inference, shows same output (reproducible)
  → Shows GNNExplainer attribution (which graph nodes drove the decision)
```

### 9.3 What Should Alert MLOps vs. Security Team

**Alert routing:**

| Event | Routes To | Rationale |
|-------|-----------|-----------|
| FP rate > 40% | MLOps | Model degradation, not a security incident |
| Model age > 90 days | MLOps | Scheduled maintenance needed |
| New CWE type appearing | MLOps + Security | May indicate emerging attack class |
| Supply chain attack pattern | Security (P1) | Immediate human response needed |
| Critical finding in payment repo | Security (P1) | Immediate fix or PR block |
| Developer CI override spike | Security (P2) | Possible control bypass |
| Pipeline failure rate > 5% | MLOps + Engineering | Infrastructure issue |
| Inference latency spike | MLOps | Model serving issue |
| Clone failure rate > 10% | MLOps | Git credential or network issue |
| Model confidence distribution shift | MLOps | Model may be encountering OOD inputs |

---

## 10. Interview Questions

### Q1: How does AI-SAST's taint flow analysis differ from traditional SAST's taint flow analysis, and what specific problems does the ML approach solve?

**Answer:**

**Traditional SAST taint analysis** is symbolic and rule-driven:

```
Algorithm (classical):
1. Define sources: a hand-crafted list of functions/variables that introduce tainted data
   (e.g., request.form, os.environ, sys.argv)
2. Define sinks: a hand-crafted list of dangerous operations
   (e.g., db.execute, os.system, subprocess.call)
3. Define sanitizers: a hand-crafted list of functions that clean data
   (e.g., html.escape, re.sub for input validation)
4. Run fixed-point analysis: propagate taint from sources, stop at sanitizers
5. If taint reaches a sink without a sanitizer: flag as vulnerability
```

**Problems with traditional approaches:**

1. **Hand-crafted source/sink lists are incomplete.** Custom frameworks have custom sinks (e.g., `company_db.safe_execute()` is safe, but the tool doesn't know this). New libraries introduce new sinks that aren't in the tool's database. Result: false negatives for uncatalogued sinks, or false positives if the tool flags safe custom abstractions.

2. **Cannot reason about sanitization strength.** Traditional tools know that `re.sub()` is called but can't assess whether the regex is correct. `re.sub(r"[^a-z]", "", input)` for a SQL query field is insufficient (alphanumeric injection is still possible in some contexts). The tool either trusts any regex (FN) or trusts none (FP).

3. **Cannot handle compound patterns.** A vulnerability might require: tainted input + specifically configured function + wrong branch of an if-statement + specific library version. Symbolic analysis can in principle handle this but becomes computationally intractable.

4. **High false positive rate** (40-70%) from context-blind rule application. The tool sees `db.execute(query)` and flags SQL injection without knowing whether `query` was built from constants only, or whether there are sanitizers earlier in the call chain.

**What ML-based AI-SAST adds:**

1. **Learned source/sink detection:** The GNN learns from examples which function calls are dangerous sinks based on their features (call to external library, argument structure, surrounding code patterns). It can generalize to new sinks it hasn't explicitly seen by recognizing the pattern.

2. **Learned sanitization recognition:** The model learns from labeled examples what constitutes effective sanitization. A regex that covers special characters for SQL is recognized as effective for SQL (but flagged as insufficient for XSS). This requires understanding context, which ML can approximate.

3. **False positive reduction through context:** The ML model sees the full function context. A sink that's called with only constants (zero taint in the training examples for this pattern) is learned to be a false positive pattern. The FP reducer learns "db.execute(constant_string) → almost always a FP."

4. **Interprocedural reasoning across file boundaries:** The GNN builds the call graph across the changed files and their context files, learning which cross-file patterns correlate with vulnerabilities.

**The fundamental limitation that remains:** ML models approximate taint analysis, they don't do it exactly. A sufficiently clever obfuscation (Section 6.1) can fool the model by occupying a "safe" region of the embedding space even when the code is vulnerable. This is why the hybrid architecture (ML + deterministic rules) is essential — rules provide the hard guarantee for known patterns, ML extends coverage to novel patterns.

---

### Q2: Explain the specific architecture and training procedure for the Code Transformer used in AI-SAST vulnerability detection. Why is CodeBERT/UniXcoder better than a standard NLP BERT for this task?

**Answer:**

**Why standard BERT fails for code:**

Standard BERT was pretrained on natural language (Wikipedia, BookCorpus). Code is fundamentally different from natural language:

1. **Syntactic structure matters:** In English, word order is flexible with similar meaning. In code, `a = b + c` is completely different from `c = a + b`. BERT's attention mechanism must learn to handle code's rigid syntax.

2. **Token distribution is different:** Code has many tokens not in BERT's vocabulary (operators, brackets, indentation tokens). BERT would fragment `request.form.get('user_id')` into tokens like `request`, `.`, `form`, `.`, `get`, `(`, `'user_id'`, `)` — BERT's vocabulary may handle some but its pretraining didn't prepare it for code's unique token patterns.

3. **Long-range dependencies are different:** In code, a function definition at line 1 may be critical context for understanding a vulnerability at line 200. Standard BERT's 512-token limit and pretraining didn't specifically optimize for these long-range code dependencies.

**CodeBERT architecture:**

CodeBERT (Feng et al., Microsoft Research, 2020) is pretrained on 6.4M code-documentation pairs from GitHub in 6 languages. It uses two pretraining objectives:

1. **Masked Language Modeling (MLM):** Same as BERT — mask 15% of code tokens, predict them. Applied to both code and documentation separately.

2. **Replaced Token Detection (RTD):** Like ELECTRA — a generator creates plausible token replacements, the discriminator (CodeBERT) detects which tokens were replaced. This is more efficient than MLM because EVERY token is labeled (replaced/not), not just the 15% masked.

The critical advantage: training on code-documentation pairs forces the model to learn semantic representations — the same code pattern in Python, Java, and JavaScript should have similar representations because their documentation is similar.

**UniXcoder (additional capabilities):**

UniXcoder adds a third pretraining objective relevant to SAST:

3. **Masked Code Completion (MCC):** Given partial code, predict the completion. This forces the model to learn code structure and completion patterns — highly relevant for understanding what a function is "supposed to do" vs. what it "actually does."

**Fine-tuning for vulnerability detection:**

```python
# Fine-tuning procedure:
class VulnerabilityDetectionFineTuning:
    """
    Fine-tune UniXcoder on vulnerability detection.
    Two-stage: first on CWE classification, then on binary (vuln/safe).
    """
    
    def stage_1_cwe_classification(self, model, cwe_labeled_dataset):
        """
        Stage 1: Multi-class CWE classification
        Input: code snippet
        Output: P(CWE-89), P(CWE-79), P(CWE-918), ... (one per CWE type)
        
        Why first: Forces model to learn what SQL injection looks like
                   (specific patterns, not just "suspicious code")
        Training data: 450K CVE-linked code samples with CWE labels
        """
        # Add classification head
        model.classifier = nn.Linear(768, len(CWE_CLASSES))
        
        # Fine-tune: update all parameters (not just classification head)
        # Lower learning rate for transformer body, higher for head
        optimizer = AdamW([
            {'params': model.transformer.parameters(), 'lr': 1e-5},
            {'params': model.classifier.parameters(), 'lr': 5e-5}
        ])
        
        for epoch in range(3):
            for batch in cwe_labeled_dataset:
                outputs = model(batch.code_tokens)
                loss = F.cross_entropy(outputs, batch.cwe_labels)
                loss.backward()
                optimizer.step()
    
    def stage_2_binary_vulnerability(self, model, binary_labeled_dataset):
        """
        Stage 2: Binary classification (vulnerable / not vulnerable)
        Input: code snippet
        Output: P(vulnerable)
        
        Why second: More general than CWE-specific; benefits from Stage 1's
                    learned CWE representations as features
        Training data: 280K analyst-labeled findings (TP/FP feedback loop)
                       plus CodeXGLUE vulnerability detection dataset
        """
        # Replace CWE head with binary head
        model.classifier = nn.Linear(768, 2)
        
        # Use focal loss to handle class imbalance
        # (Most code is safe, few samples are vulnerable)
        # Focal loss: downweights easy examples, upweights hard ones
        loss_fn = FocalLoss(alpha=0.25, gamma=2.0)
        
        for epoch in range(5):
            for batch in binary_labeled_dataset:
                outputs = model(batch.code_tokens)
                loss = loss_fn(outputs, batch.labels)
                loss.backward()
                optimizer.step()
```

**What if you used a general LLM (GPT-4) instead?**

GPT-4 and similar general LLMs can perform surprisingly well at vulnerability detection in studies (Cheshkov et al., 2023 found GPT-4 achieves ~70% accuracy on certain benchmarks). However:

1. **Cost:** GPT-4 API costs make it infeasible for scanning millions of functions. Fine-tuned CodeBERT inference is ~$0.0001 per function vs. ~$0.01 for GPT-4.

2. **Latency:** GPT-4 API latency (500ms-2s) vs. local CodeBERT (10-50ms on GPU).

3. **Reproducibility:** GPT-4 outputs are non-deterministic. Security findings must be reproducible — re-scanning the same code must yield the same results.

4. **Confidentiality:** Sending proprietary source code to an external API is a significant data governance concern.

5. **Specialized performance:** Fine-tuned CodeBERT on 450K vulnerability examples outperforms general GPT-4 on vulnerability detection at much lower cost, while GPT-4 with few-shot prompting excels at reasoning about vulnerabilities it's asked to explain.

**The optimal architecture:** Fine-tuned CodeBERT/UniXcoder for classification (fast, cheap, specialized) + LLM for explanation generation (what exactly is wrong, how to fix it) + human review for supply chain attacks. This combines each approach's strengths.

---

### Q3: Describe the complete taint flow analysis for a multi-file SQL injection. What are the edge cases that cause false negatives?

**Answer:**

**The scenario:**

```python
# File 1: api/routes.py
@app.route('/search')
def search():
    query_term = request.args.get('q')     # TAINT SOURCE
    results = SearchService.execute(query_term)
    return jsonify(results)

# File 2: services/search_service.py
class SearchService:
    @staticmethod
    def execute(term):
        # 'term' is now the tainted parameter
        sanitized = term.strip()  # strip() does NOT sanitize SQL injection
        return DatabaseService.search(sanitized)

# File 3: database/db_service.py
class DatabaseService:
    @staticmethod
    def search(query_term):
        # 'query_term' is still tainted (strip() doesn't help for SQL)
        sql = f"SELECT * FROM products WHERE name LIKE '%{query_term}%'"
        return db.execute(sql)  # TAINT SINK
```

**The analysis steps:**

```
Step 1: Build call graph across all three files
  routes.py::search() → SearchService.execute()
  SearchService.execute() → DatabaseService.search()
  DatabaseService.search() → db.execute()

Step 2: Identify taint sources in routes.py
  TAINT: query_term = request.args.get('q')
  Source type: HTTP request parameter (CWE source)

Step 3: Propagate taint through function calls (interprocedural)
  routes.py::search()
    query_term → TAINTED
    → SearchService.execute(query_term)
      SearchService.execute.term → TAINTED (parameter receives tainted value)
      sanitized = term.strip() → TAINTED (strip() doesn't remove taint)
      → DatabaseService.search(sanitized)
        DatabaseService.search.query_term → TAINTED
        sql = f"...{query_term}..." → TAINTED
        db.execute(sql) → TAINT SINK reached with tainted data

Step 4: Check for sanitizers on the path
  term.strip() — strip() removes whitespace, NOT SQL-relevant characters
  → strip() is NOT a SQL injection sanitizer
  → Taint NOT removed

Step 5: Report: CONFIRMED SQL INJECTION
  CWE: CWE-89
  Taint path: routes.py:3 → search_service.py:6 → db_service.py:6 → db_service.py:7
  Sanitizer: strip() (ineffective for SQL injection)
```

**Edge cases causing false negatives:**

**Edge case 1: Taint through data structures (list/dict/object)**

```python
# Taint stored in dict: many trackers lose taint through dict
user_data = {'query': request.args.get('q')}  # Taint stored in dict
# ... many lines later
db.execute(f"SELECT * FROM t WHERE name = '{user_data['query']}'")  # Taint via dict lookup
```

Fix: Taint must propagate through dict/list membership. When a tainted value is stored as a dict value under key K, retrieving dict[K] must return a tainted value.

**Edge case 2: Taint through class attributes**

```python
class SearchRequest:
    def __init__(self, term):
        self.term = term  # Taint stored as object attribute

req = SearchRequest(request.args.get('q'))  # Taint in req.term
# ... later
db.execute(f"SELECT * FROM t WHERE name = '{req.term}'")  # Taint via attribute access
```

Fix: Taint must propagate through object attribute assignments and accesses.

**Edge case 3: Taint through return values of external functions**

```python
# External library enriches tainted data (taint survives external call)
import external_lib
enriched = external_lib.process(request.args.get('q'))  # Does this strip taint?
```

If `external_lib.process()` is not in the taint model: the analyzer doesn't know if it sanitizes. Most tools make a conservative assumption: external functions pass taint through (don't sanitize). But if the tool models `external_lib.process()` as a sanitizer (because its name includes "process" and it's in a trusted library): false negative.

**Edge case 4: Conditional sanitization**

```python
if user.is_admin:
    query_term = user_input  # Skips sanitization for admins
else:
    query_term = sanitize(user_input)

db.execute(f"SELECT * FROM t WHERE name = '{query_term}'")
```

The analyzer must model that `query_term` is tainted if `user.is_admin` is true. This requires reasoning about conditional taint — harder than unconditional taint. Many tools assume either: (a) always tainted (FP when is_admin = False) or (b) always sanitized (FN when is_admin = True).

**Edge case 5: Taint through callbacks and closures**

```python
def make_query_func(user_input):
    def query():
        return db.execute(f"SELECT * FROM t WHERE name = '{user_input}'")
    return query

# ... later
query_func = make_query_func(request.args.get('q'))
query_func()  # Taint captured in closure
```

Taint through closures requires the analyzer to model the captured environment. Most static analyzers handle this poorly.

---

### Q4: How would you handle a large monorepo (10M+ lines of code) in AI-SAST? What are the specific engineering challenges, and how do you maintain SLA?

**Answer:**

**The core challenge:** A monorepo has highly complex transitive dependency relationships. Changing one utility function can propagate through hundreds of downstream callers. Full interprocedural analysis of the changed function requires traversing the entire call graph, which could be millions of nodes.

**The naive approach fails:**

```
PR changes: util/string_helpers.py::sanitize_sql()
           (a utility used by 2,000 functions across the codebase)

Full analysis requirement:
  - Find all callers of sanitize_sql() (2,000 functions)
  - For each caller, check if user input reaches sanitize_sql() (taint analysis)
  - For each such path: is the sanitization now different? Still sufficient?
  
Analysis time: 2,000 functions × 50ms each = 100 seconds
But: each caller may have its own callers → transitive explosion
     If depth = 3: 2,000 × average_fan_out^3 = potentially millions of functions
```

**Engineering approach: Bounded impact analysis**

```python
class MonorepoImpactAnalyzer:
    """
    Determines the impact scope of a change in a large codebase.
    Prioritizes analysis based on security relevance and computational budget.
    """
    
    def analyze_changed_file(self, 
                              changed_file: str,
                              changed_functions: list[str],
                              budget_seconds: int = 60) -> AnalysisScope:
        
        # Step 1: Compute direct callers (1-hop impact)
        direct_callers = self.call_graph.get_callers(changed_functions)
        
        # Step 2: Prioritize by security relevance
        priority_callers = self._prioritize_by_security_relevance(direct_callers)
        
        # Step 3: Apply budget-constrained analysis
        # Process callers in priority order, stop when budget exhausted
        analyzed = []
        remaining_budget = budget_seconds
        
        for caller in priority_callers:
            if remaining_budget <= 0:
                break
            
            start_time = time.time()
            
            # Check if caller is security-sensitive
            is_sensitive = self._is_security_sensitive(caller)
            
            if is_sensitive:
                # Full analysis for security-sensitive callers
                analysis = self.full_analyzer.analyze(caller)
                analyzed.append(analysis)
            else:
                # Lightweight check: just verify the call pattern hasn't changed
                # (is the sanitization still called in the same way?)
                analysis = self.lightweight_checker.check_call_pattern(caller, changed_functions)
                analyzed.append(analysis)
            
            remaining_budget -= (time.time() - start_time)
        
        # Step 4: For unanalyzed callers (budget exhausted): flag for nightly full scan
        unanalyzed = [c for c in direct_callers if c not in analyzed]
        self.nightly_scan_queue.add(unanalyzed, priority="HIGH")
        
        return AnalysisScope(
            analyzed=analyzed,
            unanalyzed=unanalyzed,
            coverage_pct=len(analyzed) / len(direct_callers) * 100,
            warning="Incomplete analysis due to size — nightly scan scheduled"
        )
    
    def _is_security_sensitive(self, function: str) -> bool:
        """
        Heuristic: is this function security-sensitive?
        If yes: full analysis. If no: lightweight check.
        """
        # Check file path
        if any(p in function.file_path for p in ['auth', 'payment', 'crypto', 'session']):
            return True
        
        # Check function annotations
        if function.has_annotation('@requires_auth') or function.has_annotation('@protected'):
            return True
        
        # Check if function has taint sinks
        if function.taint_sinks:
            return True
        
        # Check criticality from CMDB
        if self.cmdb.get_criticality(function.service) in ['CRITICAL', 'HIGH']:
            return True
        
        return False
```

**Pre-computed call graph (the key optimization):**

For a monorepo, maintain an always-current call graph index:

```python
class MonorepoCallGraphIndex:
    """
    Maintains a pre-computed call graph for the entire monorepo.
    Updated incrementally as PRs are merged.
    
    Storage: Neo4j (graph database, 10M node graph, < 5ms query for 1-hop callers)
    Size: ~20GB for a large monorepo (function nodes + call edges)
    Update time: < 30 seconds per merged PR (incremental update, not full rebuild)
    """
    
    def update_on_merge(self, merged_pr: MergedPR):
        """
        When a PR is merged, update the call graph incrementally.
        Only update edges affected by the changed functions.
        """
        for changed_function in merged_pr.changed_functions:
            # Remove old edges for this function
            self.neo4j.delete_outgoing_edges(changed_function)
            
            # Re-extract call graph for the function (fast: just parse one function)
            new_calls = self.parser.extract_calls(changed_function.new_source)
            
            # Add new edges
            self.neo4j.add_edges(changed_function, new_calls)
        
        # This entire operation takes < 1 second for a typical PR
    
    def get_security_impact_path(self, changed_function: str, max_depth: int = 5):
        """
        Query: can a change to changed_function affect a security-sensitive function?
        Returns all paths from changed_function to security sinks within max_depth hops.
        
        Cypher query (Neo4j):
        MATCH p = (start:Function {name: $func})-[:CALLS*1..5]->(end:SecuritySensitiveFunction)
        RETURN p, length(p) ORDER BY length(p)
        """
        return self.neo4j.run_cypher(
            """
            MATCH p = (start:Function {name: $func})
                      -[:CALLS*1..{max_depth}]->
                      (end:Function {is_security_sensitive: true})
            RETURN p, length(p) ORDER BY length(p)
            """,
            func=changed_function, max_depth=max_depth
        )
```

**SLA maintenance strategy:**

| Repo Size | Analysis Mode | SLA Target | Tradeoff |
|-----------|--------------|------------|---------|
| < 100K LOC | Full interprocedural | 2 minutes | No tradeoff |
| 100K - 1M LOC | Diff + direct callers | 5 minutes | Miss deep transitive impact |
| 1M - 10M LOC | Diff only + security-sensitive callers | 15 minutes | Miss impact in non-sensitive callers |
| > 10M LOC | Diff only + pre-computed impact cache | 15 minutes | Nightly full rescan for comprehensive coverage |

---

### Q5: How do you prevent the AI-SAST system from itself becoming a supply chain attack vector? What are the security risks of running arbitrary code scanning infrastructure?

**Answer:**

The AI-SAST system is a high-privilege component: it clones repositories, parses code, and has access to potentially sensitive codebases across the entire organization. It's a valuable target for supply chain attacks against itself.

**Attack surface of the AI-SAST system:**

```
1. Code execution during parsing
   Parsers process untrusted code from PRs. A maliciously crafted Python file
   could exploit a bug in the Python parser (tree-sitter, ast module) to achieve
   code execution inside the scanning container.
   
   Example: A specially crafted Python file that triggers a buffer overflow
   in the C-based tree-sitter Python parser. Attacker gets code execution
   inside the SAST worker container.

2. Malicious Jupyter notebooks or build files
   Build systems (Makefile, CMakeLists.txt) and Jupyter notebooks can contain
   executable content. If the SAST system tries to "run" these to understand
   the build context, it executes attacker code.

3. Dependency confusion in the SAST system itself
   The SAST system has its own requirements.txt / package.json.
   If an attacker can inject a package into those dependencies (dependency
   confusion, typosquatting), they compromise the SAST system itself.

4. GitOps credential exposure
   The SAST system needs a GitHub token to clone private repositories.
   If the token has too broad permissions, a compromised SAST worker can
   exfiltrate code from all repositories.
   
5. AST/Feature vector exfiltration
   The features extracted from sensitive code (cryptographic algorithms,
   authentication logic) are stored in S3. If S3 is misconfigured, this
   is a code exfiltration vector.
```

**Defense in depth for the AI-SAST system:**

```
ISOLATION:
  - Each scan job runs in an ephemeral container (not a long-lived worker)
  - Container has NO network access except to: GitHub API, S3 (output), Redis
  - Container runs as non-root user with read-only root filesystem
  - No write access to the repository being scanned (read-only clone mount)
  - Seccomp profile: block dangerous syscalls (execve for most processes,
    socket creation to unauthorized IPs)

PARSER SANDBOXING:
  - Language parsers run in a separate sandbox process (not the main container)
  - Parser sandbox has even more restrictive permissions (no network, no file write)
  - Parser timeout: 30 seconds (prevents infinite loops in malformed code)
  - Parse errors return partial AST, don't crash the main container

GIT CREDENTIAL SCOPING:
  - GitHub token: read-only, scoped to specific repositories
  - Token per repository (not one token for all repos)
  - Token rotation: every 24 hours
  - Token never logged (webhook payloads, logs sanitized to remove tokens)
  - GitLab/GitHub fine-grained PATs (read:code only, not read:secrets)

SUPPLY CHAIN DEFENSE FOR SAST ITSELF:
  - Requirements.txt pinned to exact hashes (not versions):
    cryptography==41.0.7 \
        --hash=sha256:6b1e... (pip verify hash before install)
  - Container image signed (Sigstore/Cosign): verify image signature before running
  - No internet access in container except approved domains (allowlist via egress proxy)
  - Regular dependency audit (SAST scans SAST's own codebase — recursive!)

OUTPUT SECURITY:
  - AST/feature files never contain raw source code (only transformed representations)
  - S3 bucket: separate from production data, SSE-KMS encryption, no public access
  - Findings visible only to authorized users (RBAC based on repository access)
  - GDPR/privacy: findings about developer behavior treated as personnel data
```

**Why recursive SAST (scanning the SAST codebase) is important:**

The SAST system processes millions of lines of code. Its parsers are in C (tree-sitter), its ML inference in Python (PyTorch), its git clone logic in Go. A vulnerability in any of these components could be exploited by a malicious repository. The SAST system must scan itself and treat its own findings with the same urgency as production code findings.

**The privilege escalation risk:**

If an attacker achieves code execution inside a SAST container:
- Container has GitHub token → can exfiltrate code from all scanned repositories
- Container has S3 access → can read/write AST files (planting fake "safe" analysis results)
- Container has Redis access → can poison the analysis cache (return fake "safe" results for vulnerable code)

Mitigation: Network policy (Kubernetes NetworkPolicy) restricting container egress to exactly the endpoints needed. Audit logs for all S3 and Redis operations from SAST containers. Alert if SAST container makes any unexpected outbound connection.

---

*Document ends. Coverage: AI-SAST full architecture — code ingestion pipeline, multi-model ensemble (GNN, Transformer, LightGBM), taint flow analysis with interprocedural tracking, supply chain attack detection (Trojan Fix pattern), evasion mechanics (obfuscation, low-and-slow, adversarial examples), monorepo scaling with call graph indexing, complete observability stack, developer-facing alert format, SOAR integration, and 5 deep technical interview questions covering transformer architecture, taint analysis edge cases, monorepo engineering, and self-supply-chain defense.*