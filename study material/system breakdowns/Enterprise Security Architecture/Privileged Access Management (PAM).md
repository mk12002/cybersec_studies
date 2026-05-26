# Privileged Access Management (PAM): Internal Engineering & Security Breakdown

> **Classification:** Internal Engineering / Security Document  
> **Audience:** IAM Architects, Security Engineers, Platform Engineers, Interview Candidates  
> **Scope:** Full-stack PAM — authentication cryptography, session architecture, JIT access, secret vaulting, attack vectors, and observability  
> **Version:** 1.0

---

## Table of Contents

1. [Authentication/Access Narrative](#1-authenticationaccess-narrative)
2. [Cryptographic Flow & Hardware Integration](#2-cryptographic-flow--hardware-integration)
3. [Server-Side Validation & Session Architecture](#3-server-side-validation--session-architecture)
4. [Access Control & Authorization (PAM/DLP Context)](#4-access-control--authorization-pamdlp-context)
5. [Bypass & Attack Mechanics](#5-bypass--attack-mechanics)
6. [Security Controls & Defensive Mechanics](#6-security-controls--defensive-mechanics)
7. [Attack Surface Mapping](#7-attack-surface-mapping)
8. [Failure Points & Edge Cases](#8-failure-points--edge-cases)
9. [Mitigations & Observability](#9-mitigations--observability)
10. [Interview Questions](#10-interview-questions)

---

## Foundational Framing: What PAM Actually Is

Privileged Access Management is not just password vaulting. It is a set of architectural controls that enforce the principle of least privilege for privileged operations — system administration, infrastructure changes, database access, cloud control planes — and creates a complete audit trail of every privileged action.

The core threat PAM defends against: **credential compromise**. If an attacker steals an admin's username and password, what can they do? In an environment without PAM: everything, permanently. In a well-designed PAM environment: nothing useful — the credential alone is insufficient, all privileged access is brokered, just-in-time, time-limited, and fully audited.

**The three pillars of PAM:**

```
VAULT: Credentials never known to humans
  Passwords for privileged accounts are randomly generated, stored in vault,
  rotated automatically, and injected into sessions without human knowledge.
  A human never sees the password for root@prod-db-01.

PROXY: All privileged sessions brokered through PAM
  Admin never connects directly to prod-db-01.
  Admin connects to the PAM proxy, which authenticates the admin,
  then establishes a separate session to the target using vaulted credentials.
  The PAM proxy records everything.

JUST-IN-TIME: Privileges granted only when needed, for bounded time
  Standing privileges (permanent admin rights) eliminated.
  Admin requests access: PAM grants for 2 hours, auto-revokes, audits.
```

---

## 1. Authentication/Access Narrative

### 1.1 User Registration: Privileged User Onboarding

The PAM enrollment flow differs from standard identity systems because it must establish:
1. Who the user is (identity verification)
2. What their hardware context is (device attestation)
3. What their risk level is (background check, approval chain)

**Step 1: Identity Verification (out of band)**

```
HR initiates: "John Smith hired as Senior SysAdmin, needs PAM access"
  → Ticket opened in ServiceNow: IDAM-004821
  → Manager approval: VP Engineering (2-person rule for admin onboarding)
  → HR confirms identity documents verified at hire
  → Security team reviews: background check passed, clearance approved
  
PAM system receives approved request:
  → Creates principal: john.smith@corp.example.com
  → Assigns initial permission set: "sysadmin-tier1" (limited scope)
  → Generates enrollment token (PKCE-protected, 24h TTL):
    enrollment_token = base64(HMAC-SHA256(
      key=enrollment_signing_key,
      message=join(user_id, timestamp, random_nonce)
    ))
```

**Step 2: Authenticator Registration (FIDO2/WebAuthn)**

John receives an enrollment link. On his managed corporate device (Managed Windows with TPM, macOS with Secure Enclave, or a hardware security key):

```
User opens: https://pam.corp.example.com/enroll?token=eyJhbGci...

Browser executes WebAuthn registration:
  navigator.credentials.create({
    publicKey: {
      challenge: server_generated_challenge,  // 32 random bytes
      rp: { id: "pam.corp.example.com", name: "Corp PAM" },
      user: { id: user_id_bytes, name: "john.smith", displayName: "John Smith" },
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },    // ECDSA P-256
        { type: "public-key", alg: -257 }   // RS256 (RSA-PKCS1v1.5)
      ],
      authenticatorSelection: {
        authenticatorAttachment: "platform",     // Use device's built-in authenticator
        // OR: "cross-platform" for hardware key
        userVerification: "required",            // Biometric or PIN mandatory
        residentKey: "required"                  // Store credential on device
      },
      attestation: "direct",   // Request attestation certificate chain
      timeout: 60000
    }
  });
```

**Step 3: What Happens Inside the Authenticator (TPM/Secure Enclave)**

On Windows with TPM 2.0:

```
1. TPM generates ECDSA P-256 key pair:
   - Private key: stored in TPM hierarchy (never exported to OS)
   - Public key: returned to browser
   
2. TPM creates Authenticator Data:
   authenticatorData = {
     rpIdHash:         SHA256("pam.corp.example.com"),  // 32 bytes
     flags:            UP=1, UV=1, AT=1,  // user presence, verification, attestation
     signCount:        0,  // Monotonically increasing counter
     aaguid:           TPM vendor GUID (identifies authenticator model)
     credentialId:     random bytes bound to this credential
     credentialPublicKey: CBOR-encoded ECDSA P-256 public key
   }
   
3. TPM signs: 
   signature = ECDSA_Sign(private_key, SHA256(authenticatorData || clientDataHash))
   clientDataHash = SHA256(clientDataJSON)
   clientDataJSON = {"type":"webauthn.create", "challenge":"base64_challenge", 
                     "origin":"https://pam.corp.example.com"}
   
4. TPM creates attestation statement (proves it's a genuine TPM):
   attestation = {
     fmt: "tpm",
     attStmt: {
       ver: "2.0",
       alg: -257,  // RS256 (TPM's attestation key)
       sig: TPM_Sign(attestation_key, certInfo),
       x5c: [leaf_cert, intermediate_cert]  // TPM manufacturer cert chain
     }
   }
```

**Step 4: Server Registration**

```
PAM server receives:
  - attestationObject (contains authenticatorData + attestation statement)
  - clientDataJSON
  - enrollmentToken (proves this is an authorized enrollment)

Server validates:
  1. Verify enrollment token: HMAC matches, not expired, not previously used
  2. Verify clientDataJSON:
     - type = "webauthn.create" ✓
     - challenge matches server-issued challenge ✓
     - origin = "https://pam.corp.example.com" ✓ (origin binding!)
  3. Verify authenticatorData:
     - rpIdHash = SHA256("pam.corp.example.com") ✓
     - flags.UP = 1 (user was present) ✓
     - flags.UV = 1 (user was verified with biometric/PIN) ✓
  4. Verify attestation (enterprise requirement):
     - Verify TPM manufacturer cert chain → root CA in server trust store
     - Verify TPM attestation key is certified by the manufacturer
     - Check aaguid against approved authenticator list
     - Verify signature over certInfo using attestation key
  5. Store in PAM credential database:
     credential_store.insert({
       user_id: "john.smith",
       credential_id: credential_id_bytes,
       public_key: ecdsa_p256_public_key,
       sign_count: 0,
       aaguid: tpm_aaguid,
       device_id: device_fingerprint,
       registered_at: now(),
       attestation_verified: true,
       authenticator_model: "TPM 2.0 - Dell Latitude 7520"
     })
  6. Invalidate enrollment token (one-time use)
```

---

### 1.2 Authentication: Requesting a Privileged Session

**What the user sees:** John opens the PAM portal, types his corporate email, and his Yubikey (or Windows Hello) prompts him for a touch/biometric. Within seconds, he's authenticated.

**What happens under the hood — the full authentication flow:**

**Phase 1: Identity assertion (primary authentication)**

```
User submits: username=john.smith@corp.example.com

Server looks up:
  1. Retrieve user's registered credentials (may have multiple: phone, Yubikey, laptop TPM)
  2. Generate authentication challenge:
     challenge = crypto.getRandomValues(new Uint8Array(32))  // 32 random bytes
     challenge_id = UUID()
     
  3. Store challenge in server-side session:
     challenge_store.set(challenge_id, {
       challenge: challenge_bytes,
       user_id: "john.smith",
       created_at: now(),
       expires_at: now() + 5_minutes,
       ip: "10.0.1.45"
     })
     
  4. Return to browser:
     PublicKeyCredentialRequestOptions {
       challenge: challenge_bytes,
       timeout: 60000,
       rpId: "pam.corp.example.com",
       allowCredentials: [{
         id: credential_id_bytes,  // Only the user's registered credentials
         type: "public-key"
       }],
       userVerification: "required"
     }
```

**Phase 2: Authenticator signature (on device, in TPM/Secure Enclave)**

```
TPM receives the authentication request:
  1. Find credential by credentialId (stored in TPM's NV storage or key hierarchy)
  2. Prompt user: biometric sensor or PIN
  3. If user verified:
  
  authenticatorData = {
    rpIdHash: SHA256("pam.corp.example.com"),
    flags: UP=1, UV=1,
    signCount: 47  // Increment from last use (47→48 would be next)
  }
  
  clientDataJSON = {
    type: "webauthn.get",
    challenge: base64url(challenge_bytes),
    origin: "https://pam.corp.example.com",
    crossOrigin: false
  }
  
  signature = ECDSA_Sign(
    private_key,
    SHA256(authenticatorData || SHA256(clientDataJSON))
  )
  
  // Private key NEVER leaves the TPM
  // Signature computation happens inside TPM
  // Browser receives: authenticatorData, clientDataJSON, signature, credentialId
```

**Phase 3: Server assertion verification**

```
Server receives:
  - credentialId: identifies which key was used
  - clientDataJSON: {"type":"webauthn.get", "challenge":"...", "origin":"..."}
  - authenticatorData: rpIdHash + flags + signCount
  - signature: ECDSA signature over the above

Verification steps:
  1. Retrieve stored credential using credentialId
  2. Verify clientDataJSON:
     - type = "webauthn.get" ✓
     - challenge: base64decode and compare with stored challenge ✓
       (retrieve from challenge_store, verify not expired, mark used)
     - origin = "https://pam.corp.example.com" ✓  ← PHISHING RESISTANCE
       (if user was tricked to fake-pam.evil.com, origin would differ → FAIL)
  3. Verify rpIdHash = SHA256("pam.corp.example.com") ✓
  4. Verify flags.UV = 1 (biometric completed on device) ✓
  5. CRITICAL: Verify sign count:
     stored_count = 46
     received_count = 47
     If received > stored: UPDATE to 47, continue ✓
     If received ≤ stored: CLONED AUTHENTICATOR ALERT → reject, notify security team
  6. Verify ECDSA signature:
     verify_ecdsa(
       public_key=stored_credential.public_key,
       message=SHA256(authenticatorData || SHA256(clientDataJSON)),
       signature=received_signature
     )
     → True ✓
  7. Delete challenge from challenge_store (one-time use)
```

---

## 2. Cryptographic Flow & Hardware Integration

### 2.1 Key Generation and Storage Hierarchy

```
HARDWARE SECURITY MODULE (HSM) — Thales/Entrust/AWS CloudHSM
  Purpose: Root key material for PAM infrastructure
  
  Master Key (HSM-resident, never exported):
    ├── Credential Encryption Key (CEK)
    │     → Encrypts all vaulted credentials at rest
    │     → AES-256-GCM with HSM-generated IV per record
    │
    ├── Session Signing Key (SSK)
    │     → Signs all PAM session tokens (RSA-4096 or ECDSA P-384)
    │     → Used for token issuance and verification
    │
    ├── Password Generation Key (PGK)
    │     → DRBG seed for deterministic password generation
    │     → Ensures generated passwords are reproducible for audit
    │
    └── Audit Log Signing Key (ALK)
          → Signs all audit log entries (tamper evidence)
          → Archive keys rotated annually, old signatures remain valid

TPM 2.0 (per endpoint, for user credentials):
  Storage Root Key (SRK) — created at TPM manufacturing
    └── Platform Hierarchy — OS-controlled
          └── User Keys (created during enrollment)
                → ECDSA P-256 key pair
                → Private key: sealed to PCR values (boot integrity)
                → Sealed: only decryptable if OS boot chain matches enrollment state
                → If disk re-imaged or OS modified: key inaccessible (TPM seal check fails)

Secure Enclave (Apple devices):
  UID Key — fused into silicon at manufacture
    → Never exported, used only inside SEP
    └── Derived keys for Keychain operations
          └── WebAuthn credential private keys
                → ECDSA P-256
                → Bound to: device hardware, biometric enrollment
                → Data Protection Class: WhenPasscodeSetThisDeviceOnly
```

### 2.2 Challenge-Response: The Cryptographic Handshake in Detail

**Why nonces matter:** Every authentication requires a fresh, unpredictable challenge from the server. This prevents replay attacks — recording a valid authentication response and replaying it later.

```
NONCE PROPERTIES:
  Length: 256 bits (32 bytes) minimum for security
  Entropy source: CSPRNG (Cryptographically Secure Pseudo-Random Number Generator)
  - Windows: BCryptGenRandom()
  - Linux: /dev/urandom (kernel CSPRNG, feeds from hardware noise)
  - Cloud HSM: hardware RNG
  
  Storage: server-side session store (Redis/database), keyed by session_id
  Lifetime: 60 seconds (authentication window)
  Single use: immediately invalidated after use
  
CHALLENGE-RESPONSE SEQUENCE:
  
  Server → Client: challenge = CSPRNG(32 bytes)
                   Note: challenge is PUBLIC — sent in plaintext
                         Security comes from the SIGNATURE, not secrecy of challenge
  
  Client → TPM: "sign this challenge"
  
  TPM computes:
    signedData = SHA256(authenticatorData || SHA256(clientDataJSON))
    Where clientDataJSON contains: {challenge, origin, type}
    signature = ECDSA_Sign(private_key, signedData)
  
  Client → Server: signature, authenticatorData, clientDataJSON
  
  Server verifies:
    1. challenge in clientDataJSON matches what server sent (freshness)
    2. origin in clientDataJSON matches server's origin (phishing resistance)
    3. ECDSA signature valid against stored public key (authenticity)
    4. signCount incremented (anti-cloning)
    
  What attacker can't do:
    - Replay: challenge is single-use
    - Forge: no private key → cannot produce valid ECDSA signature
    - Phish: wrong origin in clientDataJSON → server rejects
    - Intercept and modify: clientDataJSON is signed; modification breaks signature
```

### 2.3 Vaulted Credential Cryptography

PAM vaults store credentials that privileged accounts use to access target systems. These credentials must be:
- Never visible to human administrators in plaintext
- Rotatable without service disruption
- Auditable (who accessed what, when)

```
CREDENTIAL ENCRYPTION AT REST:

For each vaulted credential:
  1. HSM generates per-credential data encryption key (DEK):
     DEK = AES-256 random key (generated inside HSM)
  
  2. DEK is encrypted with the master Credential Encryption Key (CEK):
     encrypted_DEK = AES-256-GCM(key=CEK, plaintext=DEK, aad=credential_id)
     
  3. Credential encrypted with DEK:
     ciphertext = AES-256-GCM(key=DEK, plaintext=credential_bytes, 
                               iv=random_12_bytes, aad=credential_id)
  
  4. Stored in vault database:
     {
       credential_id: UUID,
       account: "root@prod-db-01",
       target: "prod-db-01.internal",
       encrypted_DEK: base64(encrypted_DEK),
       ciphertext: base64(ciphertext),
       iv: base64(iv_12_bytes),
       last_rotated: timestamp,
       rotation_policy: "30d",
       accessed_by: [],  // Audit trail
       checksum: SHA256(ciphertext)  // Integrity verification
     }
  
  CEK ROTATION (annual, HSM-enforced):
    1. New CEK generated in HSM
    2. Each encrypted_DEK: re-encrypted with new CEK
    3. Plaintext DEKs never leave HSM during rotation
    4. Old CEK archived (needed to decrypt old audit logs)
    
  CREDENTIAL RETRIEVAL (for session launch):
    1. PAM proxy requests credential for session
    2. PAM server verifies: requester authorized for this account
    3. Audit: log request with requester identity
    4. HSM decrypts: encrypted_DEK → DEK (inside HSM)
    5. DEK decrypts: ciphertext → credential (inside PAM server's secured memory)
    6. Credential injected into session: SSH subsystem uses it directly
    7. DEK zeroed from memory immediately after use
    8. Credential NEVER displayed to human (injected programmatically)
```

---

## 3. Server-Side Validation & Session Architecture

### 3.1 Token Architecture: PAM Session Tokens

After authentication, the PAM system issues session tokens that govern access to the privileged access proxy:

```
PAM SESSION TOKEN (JWT-like but signed by HSM key):
  
  Header:
  {
    "alg": "ES384",          // ECDSA P-384 (stronger than P-256 for long-lived sessions)
    "kid": "pam-ssk-2024-01" // Key ID for signature verification key lookup
    "typ": "PAM+JWT"
  }
  
  Payload:
  {
    "sub": "john.smith@corp.example.com",  // Subject (authenticated user)
    "sid": "sess-8f3a2b1c-...",            // Session ID (for revocation lookup)
    "iss": "https://pam.corp.example.com", // Issuer
    "aud": "pam-proxy.corp.internal",      // Audience (only the PAM proxy accepts this)
    "iat": 1705328601,                     // Issued at
    "exp": 1705332201,                     // Expires (1 hour)
    "nbf": 1705328601,                     // Not before
    "jti": "jwt-unique-id-abc123",         // JWT ID (unique, prevents replay)
    
    // PAM-specific claims
    "auth_time": 1705328601,               // When authentication occurred
    "amr": ["hwk", "pin", "mfa"],          // Authentication methods: hardware key + PIN + MFA
    "acr": "urn:corp:pam:phishing-resistant", // Authentication context
    
    // Risk and context
    "device_id": "device-fingerprint-hash",
    "device_health": "compliant",           // MDM compliance check result
    "risk_score": 12,                       // 0-100, lower is safer
    "ip": "10.0.1.45",
    "geo": "US-CA",
    
    // Authorization scope
    "allowed_accounts": ["tier1-sysadmin"],
    "allowed_targets": ["prod-web-*", "prod-app-*"],  // NOT prod-db (needs tier2)
    "session_type": "interactive"           // vs "service-account"
  }
  
  Signature: ES384(HSM_private_key, base64url(header) + "." + base64url(payload))
```

**Why custom claims rather than standard OAuth2 scopes for PAM:**

PAM sessions require much richer context than standard OAuth. A scope like `read:servers` doesn't capture: which specific servers (wildcards with exceptions), what session type (interactive vs automated), what risk score is acceptable, whether MFA was completed within N minutes. The PAM token payload encodes all of this per-session context that the proxy evaluates on every request.

### 3.2 Session State Management and Revocation

```
PAM uses THREE layers of session state:

LAYER 1: Token claims (stateless validation)
  → Proxy can validate most claims without calling back to PAM server
  → Signature verification: fast (ECDSA verify with local public key cache)
  → Expiry check: compare exp vs current time
  → Risk: cannot revoke token before expiry without state lookup
  
LAYER 2: Session database (stateful validation) — required for PAM
  Redis cluster stores:
    session:{sid} = {
      user_id: "john.smith",
      status: "active",  // active, suspended, revoked
      token_hash: SHA256(access_token),  // Bind token to session
      last_activity: timestamp,
      idle_timeout: 1800,  // 30 min idle = revoke
      commands_executed: 0,
      bytes_transferred: 0,
      alert_count: 0
    }
  
  Proxy checks on EVERY request:
    1. Validate token signature (fast, local)
    2. Look up session:{sid} in Redis (< 1ms with Redis cluster)
    3. If status != "active": reject
    4. Update: last_activity = now()
  
LAYER 3: Audit log (append-only, HSM-signed)
  Every session operation appended to immutable log:
    {
      timestamp: ...,
      session_id: ...,
      user_id: ...,
      action: "command_executed",
      command: "cat /etc/passwd",
      target: "prod-web-01",
      account: "root",
      duration_ms: 145,
      exit_code: 0,
      signature: HSM_Sign(log_entry_bytes)  // Tamper evidence
    }

REVOCATION FLOW (immediate, < 2 seconds from trigger to enforcement):
  Trigger: admin revokes session in PAM console
           OR: anomaly detection triggers auto-revocation
           OR: user session times out
  
  1. PAM server: UPDATE session:{sid} status='revoked' in Redis
  2. If active SSH/RDP connection: send signal to PAM proxy
  3. PAM proxy: check Redis on next request → revoked → terminate connection
  4. If immediate (active session): PAM proxy kills TCP connection
  
  The gap: between database update and proxy enforcement ≤ 100ms
  (Redis latency + proxy check frequency)
```

### 3.3 Authentication Pipeline Diagram

```
┌────────────────────────────────────────────────────────────────────────────────────┐
│  PAM AUTHENTICATION PIPELINE                                                       │
└────────────────────────────────────────────────────────────────────────────────────┘

User Device (Managed, MDM-enrolled)
  ┌──────────────────────────────────────────────────────────────────────────────┐
  │  Browser / PAM Desktop Client                                                │
  │  ┌─────────────────────────┐    ┌─────────────────────────────────────────┐ │
  │  │  WebAuthn API           │    │  Conditional Access Checks              │ │
  │  │  navigator.credentials  │    │  - Device compliance (MDM)              │ │
  │  │  .create / .get         │    │  - OS version, patch level              │ │
  │  └────────────┬────────────┘    │  - Disk encryption, firewall            │ │
  │               │                 └─────────────────────────────────────────┘ │
  │  ┌────────────▼────────────┐                                                │
  │  │  TPM / Secure Enclave   │                                                │
  │  │  Key Gen: ECDSA P-256   │                                                │
  │  │  Sign: in hardware      │                                                │
  │  │  Private key: NEVER     │                                                │
  │  │  leaves hardware        │                                                │
  │  └─────────────────────────┘                                                │
  └──────────────────────────────────────────────────────────────────────────────┘
           │  HTTPS/TLS 1.3 (with Certificate Transparency verification)
           ▼
┌────────────────────────────────────────────────────────────────────────────────────┐
│  PAM AUTHENTICATION SERVER                                                         │
│                                                                                    │
│  ┌──────────────────────────────────────────────────────────────────────────────┐ │
│  │  FIDO2/WebAuthn Validator                                                    │ │
│  │    1. Challenge freshness check (Redis lookup, TTL 60s)                     │ │
│  │    2. Origin verification: "https://pam.corp.example.com" ← ANTI-PHISHING   │ │
│  │    3. RPID verification: SHA256("pam.corp.example.com")                     │ │
│  │    4. ECDSA signature verification (stored public key)                      │ │
│  │    5. Sign count monotonicity check → CLONE DETECTION                      │ │
│  │    6. Attestation verification (TPM cert chain → trusted root)              │ │
│  └────────────────────────────────────┬─────────────────────────────────────────┘ │
│                                       │ Auth success                               │
│  ┌────────────────────────────────────▼─────────────────────────────────────────┐ │
│  │  Risk Engine                                                                 │ │
│  │    - GeoIP: normal location? new country?                                   │ │
│  │    - Velocity: 3rd login attempt in 10 min?                                │ │
│  │    - Device: known/managed? new device fingerprint?                         │ │
│  │    - Time: business hours? off-hours access = elevated risk                 │ │
│  │    - Threat intel: IP on blocklist? TOR exit node?                         │ │
│  │    → Risk score: 0-100 (>70: require step-up MFA)                          │ │
│  └────────────────────────────────────┬─────────────────────────────────────────┘ │
│                                       │ Risk accepted                              │
│  ┌────────────────────────────────────▼─────────────────────────────────────────┐ │
│  │  Token Issuance (HSM-backed signing)                                        │ │
│  │    - Construct JWT payload (claims, scope, expiry)                          │ │
│  │    - Sign with Session Signing Key (in HSM, ES384)                         │ │
│  │    - Write session to Redis                                                 │ │
│  │    - Write auth event to audit log                                         │ │
│  └────────────────────────────────────┬─────────────────────────────────────────┘ │
└───────────────────────────────────────┼────────────────────────────────────────────┘
                                        │  Signed PAM session token
                                        ▼
┌────────────────────────────────────────────────────────────────────────────────────┐
│  PAM PROXY (Bastion / Jump Host equivalent, but intelligent)                      │
│                                                                                    │
│  On every request:                                                                 │
│    1. Validate token signature (local public key, fast)                           │
│    2. Check session status in Redis (active/revoked)                              │
│    3. Evaluate authorization: is this user allowed THIS account on THIS target?   │
│    4. Record to session recording buffer (keystrokes, commands, screen)           │
│    5. Inspect content: DLP rules applied to commands/data                        │
│                                                                                    │
│  Session termination:                                                              │
│    - Token expiry      - Idle timeout    - Manual revocation                      │
│    - DLP policy trigger - Anomaly detection - Session recording quota             │
└────────────────────────────────────────────────────────────────────────────────────┘
           │  SSH (using vaulted credential, injected by proxy)
           │  RDP (credential injected into NLA authentication)
           ▼
┌────────────────────────────────────────────────────────────────────────────────────┐
│  TARGET SYSTEMS (prod-web-01, prod-db-01, etc.)                                   │
│  Admin account credentials: only known to PAM vault                               │
│  Direct SSH/RDP from admin workstation: BLOCKED at network level                  │
│  All access: only via PAM proxy                                                   │
└────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Access Control & Authorization (PAM/DLP Context)

### 4.1 Just-In-Time (JIT) Access Architecture

**The problem with standing privileges:** If an admin account has permanent root access to all production servers, and that account is compromised, the attacker has unlimited time to move laterally. JIT eliminates this.

```
JIT ACCESS FLOW:

Step 1: Access Request
  John opens PAM portal → clicks "Request Access"
  Request form:
    Account:  root (or svc_deployment)
    Target:   prod-web-01
    Duration: 2 hours
    Reason:   "Deploying security patch for CVE-2024-1234"
    Ticket:   INCIDENT-8821 (linked to change management system)

Step 2: Approval Workflow
  Policy engine evaluates:
    - Is this a self-approval situation? (Require 2nd approval)
    - Is this during change window? (Pre-approved)
    - Is this emergency? (Break-glass flow)
  
  For routine access:
    → Auto-approved if: matches existing change ticket + within change window
    
  For out-of-window access:
    → Notify: john's manager + system owner
    → 15-minute approval timeout → escalate
    → Approver clicks "Approve" in PAM portal OR Slack bot

Step 3: JIT Account/Permission Creation
  On approval:
  
  Option A: Temporary group membership
    - ADD john.smith to sudo-limited group on prod-web-01
    - Sudo rule: john.smith ALL=(root) /usr/sbin/service *, /usr/bin/journalctl
    - Schedule: REMOVE from group at T+2h
    
  Option B: Ephemeral account creation
    - CREATE account jsmith_temp_20240115_1023 on target
    - Set: password = vault-generated, SSH key = session-specific keypair
    - Schedule: DELETE account at T+2h
    
  Option C: Credential checkout (most common)
    - Retrieve vaulted root password from vault
    - Inject into PAM proxy for this session only
    - At T+2h: rotate the password (regardless of whether session is active)
    - Active sessions using old password: gracefully terminated

Step 4: Session Launch
  John clicks "Connect" in PAM portal
  PAM proxy:
    1. Retrieves vaulted credential (from vault, not John)
    2. Opens SSH connection to prod-web-01 using that credential
    3. Proxies John's SSH connection through
    4. Starts session recording (keystroke logging + screen recording)
    5. Activates DLP monitoring for this session

Step 5: Auto-Expiry
  At T+2h (or when John disconnects + 0 active sessions):
    1. Rotate root password on prod-web-01 (random 64-char)
    2. Store new password in vault
    3. Remove any temp group memberships
    4. Generate session summary: commands executed, data accessed
    5. Notify: John, his manager (summary), audit log
```

### 4.2 Secret Vaulting and Rotation

**Automatic password rotation mechanics:**

```python
# Simplified rotation logic (pseudo-code showing real mechanics)

class PAMVaultRotator:
    
    def rotate_credential(self, target_account: VaultedAccount):
        # Step 1: Generate new credential (in HSM-backed RNG)
        new_password = self.hsm.generate_secure_password(
            length=64,
            charset="A-Za-z0-9!@#$%^&*()",
            exclude_ambiguous=True  # Avoid 0/O, 1/l/I confusion
        )
        
        # Step 2: Verify current credential still works (pre-flight check)
        if not self.verify_credential(target_account):
            self.alert_and_escalate(target_account, "PRE_ROTATION_VERIFY_FAILED")
            return RotationResult.FAILED
        
        # Step 3: Change password on target system
        result = self.connector.change_password(
            target=target_account.host,
            account=target_account.username,
            current_password=self.retrieve_current(target_account),
            new_password=new_password,
            # Connection uses service account credential (different from rotated account)
        )
        
        if result != RotationResult.SUCCESS:
            self.alert_and_escalate(target_account, "ROTATION_FAILED_ON_TARGET")
            # IMPORTANT: Do NOT store new password — old one still works
            return RotationResult.FAILED
        
        # Step 4: Store new credential in vault (encrypt with HSM)
        encrypted_new = self.vault.encrypt_and_store(
            account=target_account,
            credential=new_password,
            previous_credential_archived=True  # Keep old for rollback window
        )
        
        # Step 5: Verify new credential works on target
        if not self.verify_credential(target_account, use_new=True):
            # CRITICAL: new password stored but doesn't work → rollback
            self.rollback_credential(target_account)
            self.alert_critical("POST_ROTATION_VERIFY_FAILED")
            return RotationResult.FAILED
        
        # Step 6: Zero old password from memory, archive or delete
        self.vault.archive_old_credential(target_account)
        
        # Step 7: Audit log
        self.audit.log_rotation(target_account, 
                                new_password_hash=SHA256(new_password),
                                rotation_triggered_by="schedule")
        
        return RotationResult.SUCCESS
```

**Credential dependencies and rotation ordering:**

```
Problem: Account A's password is used by services B, C, and D.
If you rotate A without updating B, C, D: those services break.

Solution: Dependency graph tracking in vault:

account: svc_database_reader
  used_by:
    - service: app-server-01:/etc/config/db.conf
      update_method: "restart service after file update"
    - service: app-server-02:/etc/config/db.conf
    - secret: k8s/prod/database-credentials (Kubernetes secret)
      update_method: "kubectl patch secret → rolling restart deployment"
    - service: datadog-agent:/etc/datadog/conf.d/mysql.yaml
      update_method: "restart datadog-agent"

Rotation sequence:
  1. Generate new password
  2. Change on target (MySQL server)
  3. Push to all dependent locations (in parallel where safe, sequential where ordered)
  4. Verify each consumer can connect with new password
  5. Complete rotation if all verified
  6. Rollback if any consumer fails after 5-minute validation window
```

### 4.3 DLP — Data Loss Prevention in PAM Sessions

PAM captures everything in a privileged session. The DLP engine inspects content to prevent data exfiltration and detect policy violations:

```
DLP INSPECTION ENGINE

Input sources:
  - Keystrokes typed in SSH session
  - Screen content (OCR on session recording frames)
  - File transfer content (SCP/SFTP intercepted)
  - Command output (terminal output buffer)

Detection methods:

1. REGEX PATTERNS:
   Credit card numbers:    \b4[0-9]{12}(?:[0-9]{3})?\b (Visa)
   SSNs:                   \b(?!219-09-9999|078-05-1120)\d{3}-\d{2}-\d{4}\b
   AWS access keys:        AKIA[0-9A-Z]{16}
   Private keys:           -----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----
   
2. EXACT DATA MATCHING (EDM):
   Pre-loaded: hashed sensitive data sets
   Example: SHA256 of each record in customer PII table
   On data transfer: hash chunks of transferred data
   If hash matches any stored hash → DLP alert
   
   Technical detail: uses locality-sensitive hashing to catch partial matches
   and obfuscated data (attacker scrambles PII before exfiltrating)

3. DOCUMENT FINGERPRINTING:
   Sensitive documents (financial reports, API keys, config files): 
   fingerprinted at rest using shingling:
   Shingle = rolling 5-word window over document text
   Store: set of SHA-1(shingle) values
   On outbound file transfer: compute shingles of transferred content
   If >20% shingle overlap with any fingerprinted doc → ALERT (document identified)
   
4. MACHINE LEARNING (behavioral DLP):
   Train on: normal session command patterns for each role
   Detect: anomalous command sequences
   
   Normal sysadmin: systemctl status, journalctl, nginx -t, service restart
   Anomalous: mysqldump, SELECT * FROM customers, curl | bash, base64 -d
   
   Model: LSTM sequence classifier
   Alert threshold: P(anomalous) > 0.85

ACTION FLOW ON DLP TRIGGER:
  Severity LOW: log event, continue session
  Severity MEDIUM: alert to SOC, continue session with enhanced monitoring
  Severity HIGH: suspend session immediately (user cannot type), alert SOC
  Severity CRITICAL: terminate session, alert SOC + manager + CISO
```

---

## 5. Bypass & Attack Mechanics

### 5.1 Adversary-in-the-Middle (AiTM) Phishing — Why Legacy MFA Fails

**The attack:** AiTM phishing targets MFA-protected accounts where MFA is not phishing-resistant (TOTP, push notifications). It does NOT work against FIDO2/WebAuthn.

```
ATTACKER SETUP:
  Evil Proxy Server (EvilProxy/Modlishka/Evilginx):
    - Registered domain: pam-corp-secure.com (looks like the real thing)
    - SSL certificate: Let's Encrypt wildcard for *.pam-corp-secure.com
    - Proxy: transparently forwards requests to real PAM server
    - Intercepts: cookies and tokens from the response stream

ATTACK FLOW:

Step 1: Phishing email
  "John, urgent security alert: login to https://pam-corp-secure.com 
  to review your privileged access expiring tonight"
  
Step 2: John visits the proxy
  John's browser → pam-corp-secure.com (attacker's server)
  Attacker's server → https://pam.corp.example.com (real PAM server)
  
  User sees: exact copy of PAM login page
  Browser shows: green lock (valid cert for pam-corp-secure.com)
  Browser shows: "pam-corp-secure.com" in address bar — NOT the real domain
  (This is the phishing indicator, but users often miss it)

Step 3: Credential capture (OTP/TOTP-based PAM — LEGACY)
  John enters username + OTP code from phone authenticator app
  Attacker's proxy forwards to real server → receives Session Token (cookie)
  Attacker CAPTURES the session cookie from the HTTP response
  Attacker now has: a valid, authenticated session cookie
  
  WHY THIS WORKS AGAINST TOTP:
    TOTP generates a 6-digit code based on time + shared secret
    The code is INDEPENDENT of where it's entered
    The same code works on the legitimate site OR the attacker's proxy
    The site issues a session cookie → attacker intercepts that cookie
    No binding between cookie and browser/client

Step 4: Cookie reuse (Pass-the-Cookie)
  Attacker imports stolen cookie into their browser:
  document.cookie = "pam_session=stolen_value; domain=pam.corp.example.com"
  (If cookie has HttpOnly: import via browser devtools → Application → Cookies)
  
  Attacker navigates to pam.corp.example.com with stolen cookie
  → Full access to John's PAM session
  
  Why it works: Session cookie authentication is stateless at the cookie level
    The server sees a valid cookie, issues a session
    The server cannot verify: is this John's actual browser?
```

**Why FIDO2/WebAuthn is immune to AiTM:**

```
FIDO2 AUTHENTICATION WITH ATTACKER PROXY:

Step 1: Same phishing setup as above
Step 2: John visits pam-corp-secure.com (attacker proxy)
Step 3: Server sends authentication challenge

Step 4: WebAuthn signs with ORIGIN BINDING:
  The challenge is signed over a clientDataJSON that includes:
  {
    "type": "webauthn.get",
    "challenge": "base64_challenge",
    "origin": "https://pam-corp-secure.com"  // ← THE ATTACKER'S DOMAIN
  }

Step 5: Real PAM server receives assertion
  Server verifies origin: "https://pam-corp-secure.com"
  Expected: "https://pam.corp.example.com"
  MISMATCH → Authentication REJECTED → John cannot log in (from attacker's proxy)
  
The attacker's proxy CANNOT lie about the origin:
  - The clientDataJSON is signed by John's TPM
  - Attacker cannot forge the signature (no private key)
  - Attacker cannot modify clientDataJSON (breaks signature)
  - Result: FIDO2 is mathematically immune to AiTM phishing
```

---

### 5.2 Pass-the-Cookie and Session Hijacking

```
PREREQUISITES:
  - Session cookie exfiltrated (via AiTM, malware, XSS, backup restore)
  - Session token stolen from: browser memory, log files, clipboard
  - Physical access to unlocked browser with active PAM session

EXECUTION:
  1. Identify cookie name: "pam_session", "JSESSIONID", "_Host-pam-token"
     (Note: _Host- prefix means: cookie must be sent only to HTTPS, 
      no path restrictions needed — slightly harder to steal)
  
  2. Import cookie:
     Option A: Browser devtools: Application → Cookies → Add entry
     Option B: Puppeteer: await page.setCookie({name: ..., value: ..., domain: ...})
     Option C: curl: curl -H "Cookie: pam_session=stolen_value" https://pam.corp.example.com/api
  
  3. Access privileged sessions:
     GET /api/sessions → shows John's active privileged sessions
     POST /api/sessions/{id}/connect → initiate VNC/SSH through PAM proxy
  
WHY STANDARD CONTROLS FAIL:
  - IP binding: enterprise VPN means legitimate users have varied IPs
    Most systems cannot enforce strict IP binding (breaks travel, VPN changes)
  - User-Agent: trivially spoofable header
  - Session expiry: if session is 8 hours, attacker has 8 hours
  - CSRF tokens: protect state changes but not cookie theft

DEFENSES THAT WORK:
  - Token Binding (deprecated, but Chrome supported)
  - DPOP (Demonstrating Proof of Possession): JWT bound to key pair
  - mTLS for the session: client certificate bound to session
  - Continuous authentication: step-up auth every 15 minutes for high-privilege ops
```

### 5.3 Credential Vault Attacks

```
ATTACK: Extracting credentials from PAM vault via privileged access to vault backend

Scenario: Attacker compromises the PAM server OS (as root)

Step 1: What attacker can access:
  - Vault database: /var/lib/vault/vault.db (encrypted)
  - Config files: /etc/vault/config.hcl (shows HSM connection details)
  - Memory: /proc/vault_pid/mem (if vault has credentials in memory)
  - Network: can intercept vault API calls from applications

Step 2: Memory attack
  gcore $(pgrep vault)  # Dump vault process memory
  strings core.vault | grep -E "BEGIN|password|secret|key"
  → May find: recently decrypted credentials in heap
  
  Defense: vault should zero memory after use, use mlock() to prevent swap

Step 3: API replay attack
  vault agent generates API tokens with short TTL
  If attacker can capture an API token:
    curl -H "X-Vault-Token: captured_token" https://vault.internal/v1/secret/data/prod-db
    → Returns plaintext credential if token has permission
  
  Defense: vault tokens tied to specific IP or entity identity

Step 4: HSM key extraction attempt
  HSM is FIPS 140-2 Level 3 or 4 certified — physically tamper-resistant
  Physical attacks on HSM: destroy the HSM (it zeroes keys on tamper detection)
  Software attacks: HSM only executes authorized operations, no key export
  
  The fundamental defense: HSM key export is architecturally prevented
    → Attacker can make the HSM ENCRYPT or DECRYPT but cannot extract raw key bytes
    → Without the HSM or its key, vault database ciphertext is useless
```

### 5.4 Downgrade Attacks on Authentication

```
DOWNGRADE ATTACK: Force fallback to weaker authentication method

Context: PAM requires FIDO2, but also supports "legacy fallback" for old devices

Step 1: Attacker identifies fallback mechanism
  GET /api/auth/methods?user=john.smith
  Response: ["fido2", "totp_backup"]  // Backup TOTP still configured!

Step 2: Request TOTP flow instead of FIDO2
  POST /api/auth/initiate
  { "user": "john.smith", "method": "totp_backup" }
  
  Response: 200 OK — TOTP challenge presented
  
  Why server allows this: admin configured TOTP as backup for users who lost their key
  Policy gap: backup method is weaker than primary

Step 3: AiTM is now viable
  FIDO2 would have blocked this → TOTP doesn't → attacker can intercept
  
DEFENSES:
  - Eliminate weaker backup methods OR restrict them to break-glass only
  - Require out-of-band approval to use backup method (email + manager approval)
  - Log backup method usage prominently, alert immediately
  - Block backup methods from high-risk contexts (new IP, new device, off-hours)

DOWNGRADE AT TLS LEVEL:
  PAM systems must enforce TLS 1.2+ minimum
  TLS 1.0/1.1 downgrade: POODLE, BEAST attacks → decrypt session tokens
  
  Enforce in nginx/haproxy:
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
  ssl_prefer_server_ciphers off;  // Allow client-preferred TLS 1.3 suites
```

---

## 6. Security Controls & Defensive Mechanics

### 6.1 Phishing-Resistant Authentication Properties

**The four properties that make FIDO2/WebAuthn phishing-resistant:**

```
PROPERTY 1: ORIGIN BINDING
  The signature covers the origin (scheme + host + port)
  clientDataJSON.origin = "https://pam.corp.example.com"
  If phishing proxy sits between user and server:
    → User's authenticator signs with the PROXY's origin
    → Real server checks: does signed origin match expected?
    → NO → Authentication rejected
  → Even intercepted, credentials are useless to attacker

PROPERTY 2: PRIVATE KEY BINDING TO HARDWARE
  Private key generated inside TPM/Secure Enclave
  Private key never exported to OS, process, or network
  Attacker cannot steal the private key without physical hardware access
  → The credential is hardware-bound, not software-extractable

PROPERTY 3: REPLAY PREVENTION (NONCE + SIGN COUNT)
  Each authentication signs a fresh server-issued challenge (nonce)
  Captured authentication assertion = specific to THAT challenge
  Cannot be replayed for a different challenge
  Sign count increments per use → cloning detection

PROPERTY 4: SCOPE LIMITATION (CREDENTIAL ID PER RELYING PARTY)
  Credential registered at https://pam.corp.example.com
  Cannot be used at https://pam-corp-secure.com (attacker domain)
  Different RP ID → different key → wrong signature
  Cross-RP credential reuse: cryptographically impossible
```

### 6.2 Continuous Authentication and Risk-Based Step-Up

```
CONTINUOUS AUTHENTICATION ENGINE:

During an active PAM session, the risk engine continuously evaluates:
  
  Real-time signals (every 60 seconds):
    - Keyboard dynamics: typing speed, rhythm (unique per user — behavioral biometric)
    - Mouse movement patterns: does this look like the enrolled user?
    - Command patterns: normal behavior for this role?
    - Network: IP address changed? (VPN reconnect vs. new location)
    - Time-of-day: expected hours for this user?
  
  Risk score update:
    risk_delta = RiskEngine.evaluate(current_signals, user_baseline)
    current_session.risk_score += risk_delta
  
  Thresholds:
    risk_score < 30: continue normally
    30 ≤ risk_score < 60: log, increase monitoring frequency
    60 ≤ risk_score < 80: STEP-UP AUTH REQUIRED
      → Present FIDO2 authentication prompt within session
      → User must re-authenticate (biometric tap)
      → If no response in 2 minutes: suspend session
    risk_score ≥ 80: IMMEDIATELY suspend session
      → Alert SOC
      → Require SOC + manager approval to resume
    
  STEP-UP AUTH DURING ACTIVE SSH SESSION:
    PAM proxy injects terminal prompt:
    ~~~ PAM Security Check: Touch your security key to continue ~~~
    
    [User touches FIDO2 key — new WebAuthn assertion generated]
    
    → PAM proxy validates assertion (same as login validation)
    → Session restored with risk_score reset to base
    → Logged as: step_up_authentication_completed
```

### 6.3 Session Recording and Tamper Evidence

```
SESSION RECORDING ARCHITECTURE:

What is recorded:
  SSH: keystrokes, terminal output (character-by-character)
  RDP: video stream (compressed, encrypted), keystrokes, clipboard
  Web-based sessions (SSH-over-HTTPS): same as SSH

Recording format:
  asciicast v2 format for terminal (open standard, replayable)
  H.264/VP9 for RDP sessions
  
Tamper evidence:
  Each recording segment (1 minute):
    chunk_hash = SHA256(recording_chunk_bytes)
    chunk_signature = HSM_Sign(chunk_hash || session_id || chunk_number || timestamp)
    
  Chain: each chunk references the hash of the previous chunk
    chunk[n].prev_hash = chunk[n-1].hash  → blockchain-like chain
  
  If attacker deletes part of recording:
    Chain breaks at the deletion point
    Integrity verification detects gap
  
  If attacker modifies chunk:
    ECDSA signature fails
  
  If attacker replaces the recording with different session data:
    session_id embedded in signature doesn't match stored session ID
  
STORAGE:
  Recordings: S3/Azure Blob (immutable bucket with object lock)
    WORM (Write Once Read Many): 7-year retention (compliance)
    Cannot be deleted even by administrator (only by S3 root account + MFA delete)
  
  Audit log entries: append-only database (CockroachDB with immutable audit table)
    Row deletion disabled at DB level
    Periodic export to WORM storage
```

---

## 7. Attack Surface Mapping

### 7.1 Complete Attack Surface Diagram

```
╔══════════════════════════════════════════════════════════════════════════════════════╗
║  EXTERNAL ATTACK SURFACE                                                             ║
╠══════════════════════════════════════════════════════════════════════════════════════╣
║                                                                                      ║
║  [A] PAM Portal Web Interface (HTTPS, public-facing or VPN-gated)                  ║
║      Entry points:                                                                   ║
║        POST /api/auth/initiate — username submission, user enumeration risk         ║
║        POST /api/auth/verify — credential submission (FIDO2/TOTP)                  ║
║        GET /api/auth/recovery — account recovery flow (HIGHEST RISK)               ║
║        POST /api/auth/enrollment — new authenticator registration                   ║
║      Trust boundary: user must be on approved IP range OR authenticated to VPN      ║
║                                                                                      ║
║  [B] PAM API Endpoints (used by agents, integrations)                              ║
║        GET /api/v1/credentials/{id} — requires API token, logs all access          ║
║        POST /api/v1/sessions — launch privileged session                            ║
║        PUT /api/v1/accounts/{id}/rotate — trigger credential rotation              ║
║      Trust boundary: mutual TLS (client certificates required)                      ║
║                                                                                      ║
║  [C] Deep Link / SSO Federation                                                     ║
║        SAML IdP-initiated SSO: assertion can be forged if signing key compromised  ║
║        OAuth2 redirect: redirect_uri validation must be exact (no wildcards)       ║
║        OIDC: nonce validation prevents replay of stolen ID tokens                  ║
╚══════════════════════════════════════════════════════════════════════════════════════╝

╔══════════════════════════════════════════════════════════════════════════════════════╗
║  ENROLLMENT AND RECOVERY — HIGHEST RISK PHASE                                       ║
╠══════════════════════════════════════════════════════════════════════════════════════╣
║                                                                                      ║
║  [D] Enrollment Flow                                                                ║
║      Enrollment tokens: single-use, time-limited — but delivery is a risk          ║
║      Enrollment via email link: email compromise = account compromise               ║
║      No hardware: enrollment may fall back to software authenticator (weaker)      ║
║      Social engineering: attacker calls IT desk, claims "lost key, need to enroll" ║
║                                                                                      ║
║  [E] Account Recovery Flow                                                          ║
║      "Lost my hardware key" → recovery must be rigorous but usable                 ║
║      Recovery via email + backup codes: email compromise → full compromise         ║
║      Manager-approval recovery: social engineering of manager                      ║
║      In-person verification: only fully secure method, but high friction           ║
╚══════════════════════════════════════════════════════════════════════════════════════╝

╔══════════════════════════════════════════════════════════════════════════════════════╗
║  INTERNAL ATTACK SURFACE                                                             ║
╠══════════════════════════════════════════════════════════════════════════════════════╣
║                                                                                      ║
║  [F] PAM Proxy (Bastion Host)                                                       ║
║      SSH/RDP forwarding logic: injection attacks on session metadata                ║
║      Session recording buffer: if attacker can write here, can tamper with audit   ║
║      Credential injection: memory containing vaulted creds (transient)             ║
║                                                                                      ║
║  [G] Vault Backend                                                                  ║
║      HSM API: authenticated but high-value — HSM key compromise = total loss       ║
║      Vault DB: encrypted but high-value — requires HSM to decrypt                  ║
║      Rotation service: credentials briefly in memory during rotation               ║
║                                                                                      ║
║  [H] Session Recording Storage                                                      ║
║      Recording files: contain every keystroke + screen → confidential              ║
║      Audit logs: tampering = evidence destruction (criminal offense)               ║
║                                                                                      ║
║  [I] Target Systems (prod servers reached via PAM)                                 ║
║      Network policy: should block direct admin access → enforce PAM-only           ║
║      Service accounts on targets: credentials managed by PAM rotation              ║
╚══════════════════════════════════════════════════════════════════════════════════════╝

TRUST BOUNDARIES:

 Internet     │  VPN/Zero-Trust   │  PAM Zone        │  Target Zone
 (untrusted)  │  (identity-auth)  │  (MFA+hardware)  │  (PAM-proxied only)
              │                   │                  │
 Phisher      │  Enrolled user    │  PAM proxy       │  prod-db-01
 AiTM proxy   │  with FIDO2 key   │  Vault service   │  prod-web-01
              │                   │  HSM             │  AD/LDAP
              │                   │                  │
────────────────────────────────────────────────────────────────────
              │                   │                  │
              Firewall+VPN/ZTNA   PKI+Auth           Firewall: only
              identity check      validation         PAM proxy source IP allowed
```

---

## 8. Failure Points & Edge Cases

### 8.1 The Account Recovery Paradox

**The fundamental tension:** Strong authentication is only as strong as its weakest recovery path. If hardware key + biometric is required for login, but email-based recovery can bypass this, then email security = PAM security.

```
THE PARADOX:
  Goal: Prevent unauthorized access (strong auth)
  vs.
  Goal: Restore access when hardware lost (usability)
  
  The recovery path is an authentication path
  If recovery is weaker than primary auth: it becomes the attack vector
  Example: FIDO2 required for login, but SMS OTP resets the account
    → Attacker SIM-swaps the user → triggers recovery → bypasses FIDO2

RECOVERY TIER SYSTEM (security vs. availability tradeoff):

Tier 1 — Standard Users:
  Recovery = Manager approval + IT desk ticket + 24h wait
  Security: high (requires social knowledge + access to manager's email)
  Speed: 24-48 hours to restore access
  Risk: manager social engineering

Tier 2 — Privileged Users (PAM users):
  Recovery = 2-manager approval + Security team sign-off + in-person verification
  Security: very high (physical identity verification)
  Speed: 2-5 business days (intentionally slow — prevents social engineering)
  Risk: travel/emergency situations where user cannot be present

Tier 3 — Super-Admins / Break-Glass:
  Recovery = Quorum approval (e.g., 3 of 5 C-suite must approve)
  + Video conference with identity verification
  + Hardware delivery of new key to verified address
  Security: highest
  Speed: 1-2 weeks (extreme cases only)
  Risk: quorum members unavailable simultaneously

BACKUP KEY STRATEGY:
  Every privileged user has: primary FIDO2 key (daily use)
                              backup FIDO2 key (locked in physical safe)
                              break-glass code (sealed envelope, witness-required)
  
  Backup key stored in: company physical vault (not in user's control)
  Backup key access requires: manager + security team + physical retrieval log
  
  This prevents single hardware failure from causing recovery paradox
  (user's laptop dies = use backup key from company vault)
```

### 8.2 Cross-Device Sync and Passkey Complications

```
PASSKEYS (synced FIDO2 credentials) — the convenience vs. security tradeoff:

Traditional FIDO2 (hardware key, device-bound):
  - Credential lives on one physical device/key
  - Cannot be synced across devices
  - If device lost: credential lost (see recovery above)
  - Security: HIGH — requires physical possession

Passkeys (platform credentials with cloud sync):
  - Credential synced: iPhone → iCloud Keychain → iPad, Mac
  - Android: Google Password Manager sync
  - Benefit: multi-device access without hardware keys
  - RISK: Cloud account compromise = passkey compromise
  
  For PAM: passkeys are INSUFFICIENT as primary auth
    - iCloud compromise → all passkeys compromised
    - PAM should require: device-bound, enterprise-managed hardware
    - Passkeys acceptable for: low-privilege apps, consumer services
    - Passkeys unacceptable for: privileged access, crown-jewel systems

ENTERPRISE PASSKEY POLICY:
  Allow passkeys:  company-managed devices (MDM-enrolled)
                   → Corporate-managed iCloud/Google accounts
                   → Sync only within corporate-controlled accounts
  Prohibit passkeys: personal devices (BYOD) where sync goes to personal cloud

CROSS-DEVICE COMPATIBILITY ISSUES:
  
  Windows Hello for Business + non-Windows systems:
    - Credential registered on Windows (Trusted Platform Module)
    - Device-bound: works only on THAT Windows machine
    - SSH from that machine: must use PAM Windows client
    - SSH from macOS: different authenticator → different credential → works if enrolled
    - Issue: user enrolled only on Windows laptop, travels with MacBook → locked out
    - Solution: require enrollment of at least 2 device types + hardware backup key
  
  YubiKey cross-platform compatibility:
    - USB-A, USB-C, NFC variants: ensure user has correct physical connector
    - NFC works: iOS, recent Android, NFC-enabled laptops
    - No NFC: Yubikey 5 Nano (USB only) doesn't work on phone
    - Enterprise procurement: issue USB-C YubiKey 5C NFC to cover all cases
```

### 8.3 Vault Unavailability and Session Continuity

```
SCENARIO: PAM vault service goes down during active sessions

What's in flight:
  - 150 active privileged sessions (SSH/RDP connections)
  - Session tokens: JWT-based, stateless for basic validation
  - Vault: not needed for ongoing sessions (creds already injected)
  
  FOR ACTIVE SESSIONS:
    Ongoing SSH/RDP sessions: continue (credential already in use)
    Session recording: buffer locally if recording service unavailable
    Session revocation: CANNOT revoke during outage → security gap
    New session launches: BLOCKED (cannot retrieve vaulted credentials)
    
  For session revocation during vault outage:
    Option A (fail-open): allow sessions to continue, cannot revoke
      → Higher risk (cannot respond to active threat)
    Option B (fail-closed): terminate ALL sessions on vault unavailability
      → Operations disruption (all admins lose access)
    
    Real-world choice: fail-open for sessions already established (< 30s lag)
                       fail-closed for new session launches (cannot grant new access)
                       Manual revocation via firewall rule if urgent

HIGH AVAILABILITY ARCHITECTURE:
  Vault: active-active with Raft consensus (HashiCorp Vault cluster)
    3 nodes (or 5 for larger deployments)
    Quorum: 2 of 3 must be healthy for write operations
    Read operations: any node (eventual consistency OK for reads)
  
  HSM: active-passive HSM cluster
    Primary HSM: handles all signing operations
    Secondary HSM: hot standby, synced state
    Failover: < 5 seconds (automatic detection + switch)
  
  Redis session store: Redis Cluster
    6 nodes (3 primary, 3 replica)
    Automatic failover: Redis Sentinel
```

---

## 9. Mitigations & Observability

### 9.1 Deployment Tradeoffs: Security vs. UX

```
TRADEOFF 1: Session lifetime

  Short sessions (15 min):
    Pro: Stolen cookie usable for maximum 15 min
    Con: Admin working on a 2-hour deployment must re-authenticate 8 times
    UX impact: severe → admins find workarounds (leave sessions open)
    
  Long sessions (8 hours):
    Pro: Acceptable UX for full workday
    Con: Stolen cookie usable for up to 8 hours
    
  RECOMMENDED: Sliding window with continuous auth
    Base: 8-hour maximum session lifetime
    Idle timeout: 30 minutes (re-auth required after inactivity)
    Continuous: if risk score exceeds threshold, step-up auth mid-session
    Result: Good UX for active users, short effective window for stolen cookies

TRADEOFF 2: Attestation strictness

  Require enterprise attestation (strict):
    Allows only: TPM-backed, MDM-enrolled devices
    Blocks: BYOD, contractors with personal devices
    Pro: High confidence in device security posture
    Con: Excludes contractors, remote workers with personal Mac
    
  Accept self-attestation or software authenticators:
    Allows: any FIDO2 authenticator, including software-based
    Pro: Works for everyone, good coverage
    Con: Software authenticator (iCloud Keychain) is phishing-resistant
         but not hardware-bound → iCloud compromise = credential compromise
    
  RECOMMENDED: Tiered by privilege level
    Production access: require enterprise hardware attestation
    Dev/staging access: accept platform authenticators (software OK)
    Read-only access: even TOTP acceptable (lower risk)

TRADEOFF 3: JIT approval friction

  Fully automated JIT (no approval needed):
    Pro: Zero friction, developers love it
    Con: Attacker who compromises account gets immediate privileged access
    
  Always require human approval:
    Pro: Second human in the loop catches suspicious requests
    Con: Emergency access requires someone to be available to approve
         (3 AM production incident → manager not answering)
    
  RECOMMENDED: Policy-based approval
    During change windows: auto-approved if ticket exists
    Off-hours + no ticket: require manager approval
    Emergency flag: auto-approved + immediate notification + enhanced monitoring
    Elevated targets (payment systems, HSM admin): always require approval
```

### 9.2 Critical Metrics to Log and Alert On

```yaml
# AUTHENTICATION EVENTS

auth_attempt:
  log: always
  fields: [user_id, method, success/fail, ip, device_id, timestamp, geo]
  alert_if: failure_count > 3 in 5_minutes AND same user (brute force)
  alert_if: success from new country within 1 hour of previous auth from different country
  alert_if: backup method used (TOTP fallback instead of FIDO2)

auth_clone_detection:
  log: always, CRITICAL severity
  trigger: sign_count in assertion ≤ stored sign_count
  alert: immediate, page security team
  action: suspend credential, require re-enrollment

# SESSION EVENTS

session_launched:
  log: always
  fields: [session_id, user_id, target_account, target_host, approval_id, 
           jit_duration, session_type, ip, risk_score]
  alert_if: target is crown_jewel_tier AND no change ticket
  alert_if: user has not previously accessed this target (first access)
  alert_if: off-hours access for this user (statistical anomaly)

session_terminated:
  log: always
  fields: [session_id, duration, commands_executed, bytes_transferred, 
           termination_reason]

session_revoked_by_admin:
  log: always, HIGH severity
  alert: notify user, manager, and SOC team

# VAULT EVENTS

credential_accessed:
  log: always
  fields: [credential_id, account, target, accessed_by_session, accessed_by_user,
           timestamp, access_type]
  alert_if: accessed outside of active session (direct API access = suspicious)
  alert_if: access frequency > 10x historical average for this credential

credential_rotation_failed:
  log: always, HIGH severity
  alert: immediate (credential may be out of sync with vault)
  
credential_rotation_succeeded:
  log: always
  fields: [credential_id, account, previous_rotation_age_days]

# DLP EVENTS

dlp_trigger:
  log: always
  fields: [session_id, trigger_type, severity, matched_pattern_category, 
           action_taken, file_name_if_applicable]
  alert_if: severity >= HIGH (immediate SOC notification)
  do_not_log: actual matched content (PII/sensitive data in logs = new risk)
  
# ANOMALY EVENTS

unusual_command_sequence:
  log: always
  fields: [session_id, anomaly_score, command_category, ml_model_version]
  alert_if: anomaly_score > 0.85

impossible_travel:
  log: always, HIGH severity
  trigger: auth from location_A, then auth from location_B within time < travel_time
  alert: immediate (session compromise or credential theft)

# INFRASTRUCTURE EVENTS

vault_seal_broken:
  log: always, CRITICAL severity
  alert: page entire security team
  
hsm_operation_failed:
  log: always, HIGH severity
  alert: page on-call security engineer + infrastructure

session_recording_integrity_failed:
  log: always, HIGH severity
  trigger: chain hash verification fails on any chunk
  alert: possible tampering with audit record → page compliance + legal
```

### 9.3 PAM Deployment Maturity Model

```
LEVEL 1 (Basic): Credential Vaulting
  ✓ Admin passwords stored in PAM vault
  ✓ Passwords rotated on checkout or schedule
  ✓ Basic audit log of who accessed what
  ✗ No session recording, no JIT, no FIDO2

LEVEL 2 (Intermediate): Proxy + Recording
  ✓ All above
  ✓ PAM proxy for all privileged sessions
  ✓ Session recording (keystrokes + screen)
  ✓ Basic approval workflow for access requests
  ✗ Still allows standing privileges

LEVEL 3 (Advanced): JIT + Strong Auth
  ✓ All above
  ✓ Phishing-resistant authentication (FIDO2/WebAuthn)
  ✓ JIT access (no standing privileges)
  ✓ Conditional access (device compliance, risk scoring)
  ✓ DLP on session content
  ✗ Limited behavioral analytics

LEVEL 4 (Mature): Continuous Auth + Intelligence
  ✓ All above
  ✓ Continuous authentication (behavioral biometrics)
  ✓ Risk-based step-up authentication
  ✓ ML-based anomaly detection on session behavior
  ✓ Full SIEM integration and automated response
  ✓ Attestation-required (enterprise hardware only)
  ✓ Immutable audit logs with cryptographic integrity
```

---

## 10. Interview Questions

### Q1: Explain exactly why FIDO2/WebAuthn is phishing-resistant at the cryptographic level. Why can't an attacker simply forward the WebAuthn challenge from a proxy to the victim's device?

**Answer:**

The attacker CAN forward the challenge — and the victim's authenticator WILL sign it. But the signature will be wrong for the attacker's purposes.

Here's why: the WebAuthn specification requires that the signing operation include the `clientDataJSON`, which contains the `origin` field — the exact scheme + hostname + port of the website where the browser thinks the user is authenticating. When a user visits the attacker's proxy at `https://fake-pam.evil.com`, the browser constructs `clientDataJSON` with `"origin": "https://fake-pam.evil.com"`. The authenticator signs this entire structure.

When the proxy forwards this assertion to the real PAM server, the server verifies it against its configured Relying Party ID (`pam.corp.example.com`). The server computes `SHA256("pam.corp.example.com")` and compares it to the `rpIdHash` in the authenticatorData — but more critically, it checks that the origin in `clientDataJSON` matches its expected origin. `"https://fake-pam.evil.com"` ≠ `"https://pam.corp.example.com"` → assertion rejected.

The attacker can't fix this because:
1. The `clientDataJSON` is protected by the ECDSA signature made inside the hardware (TPM/Secure Enclave). If the attacker modifies it (changes the origin), the signature becomes invalid.
2. The attacker doesn't have the private key (it never left the TPM), so they can't re-sign with the correct origin.
3. This is enforced by the client browser — the browser generates `clientDataJSON` with the ACTUAL origin the user is on, not a spoofable one.

The fundamental guarantee: the authenticator binds signatures to the actual origin observed by the browser, and this binding is cryptographically enforced. A MITM proxy observing this exchange gets a perfectly valid-looking assertion that is nonetheless useless for any other origin.

---

### Q2: Walk through the exact cryptographic operations when a PAM vault rotates a privileged account password. Where does the plaintext credential exist, and for how long?

**Answer:**

The plaintext credential exists in exactly three places during rotation, each briefly:

**Step 1: Generation (inside HSM)**

The new password is generated inside the HSM using its hardware DRBG (Deterministic Random Bit Generator). The HSM generates random bytes, applies a character-set mapping to meet password policy requirements, and returns the plaintext to the vault service over a secure channel (mTLS connection to HSM API). The plaintext is now in the vault service's process memory as a Go/Java string or byte array.

**Step 2: Transmission to target system**

The vault service opens a connection to the target (SSH or vendor API) using the current credential (retrieved by decrypting from vault → another brief plaintext moment). It sends the new password to the target's password change API. The plaintext travels over TLS (for SSH: Diffie-Hellman-encrypted channel). During transmission: in network buffers (encrypted), in the target OS's password change handler (briefly in memory).

**Step 3: Encryption for vault storage**

Back in the vault service, the new password is immediately encrypted: the vault requests the HSM to encrypt the new password using the current AES-256 data encryption key (DEK) for this credential. The HSM wraps the plaintext with AES-256-GCM and returns ciphertext. The plaintext is then zeroed from memory using `SecureZeroMemory()` (Windows) or `memset_s()` / explicit_bzero (Linux).

The vault stores only the ciphertext + encrypted DEK (DEK itself encrypted with the HSM master key).

**Lifetime of plaintext exposure:**
- In vault service memory: < 500 milliseconds (generate → encrypt → zero)
- In network: milliseconds per packet, within TLS encryption
- In target system: seconds (password change handler), then stored as hash (for OS accounts) or used directly (for service accounts)

**Residual risks:**
- Swap/paging: `mlock()` should pin vault service memory to prevent swap
- Core dumps: vault process should set `PR_SET_DUMPABLE=0` on Linux
- Memory forensics: attacker with root access can dump process memory in that window

---

### Q3: A user's FIDO2 hardware key is stolen. Walk through why this isn't immediately a security crisis, what the risk window is, and exactly what the attacker can and cannot do.

**Answer:**

**What the attacker has:** A physical FIDO2 hardware key containing an ECDSA P-256 private key for the PAM credential.

**Why they can't immediately use it:** FIDO2 hardware keys (YubiKey, Titan Key) require user verification for PAM — specifically `userVerification: "required"` in our configuration. This means the key alone is insufficient; the attacker must also provide the PIN (for PIN-protected YubiKeys) or biometric (for device-bound platform authenticators). Without the PIN:

- YubiKey without PIN configured: YES, stolen key = immediate credential (this is a misconfiguration — enterprise deployment MUST require PIN on all PAM hardware keys)
- YubiKey with PIN: 8 consecutive wrong PINs → key self-locks permanently → no access
- YubiKey with fingerprint (Bio series): biometric required → physical finger required

**Assuming PIN is known (worst case):** The attacker has key + PIN. The risk window is:

```
T=0: Key stolen, attacker knows PIN
T=15 min: User notices key missing, reports to IT/security
T=20 min: Security admin revokes credential in PAM (deletes credential_id from trusted store)
T=20 min: All subsequent authentication attempts with this key: REJECTED
          (credential_id lookup fails: "unknown credential")

Risk window: ~20 minutes (faster if user immediately reports)
```

**What attacker can do in 20 minutes:**
- Authenticate to PAM (if no anomaly detection)
- Request JIT access (requires approval workflow → more friction)
- Access sessions already approved and initiated

**What attacker cannot do:**
- Access vaulted credentials directly (need authorized session + specific target access)
- Bypass JIT approval workflow (still requires manager/automated policy approval)
- Access sessions on targets they're not authorized for (authorization is per account, not just authenticated)

**Detection signals the attacker will trip:**
- Authentication from a new/different IP address than user's typical office IP → risk score elevated
- Authentication time anomaly (user typically works 9-5, theft might occur off-hours)
- If user's laptop (with a second authenticator) is NOT being used simultaneously → possible key theft
- User reports key missing → immediate revocation

**Post-revocation:** The credential is permanently revoked in the PAM database. The physical key is now a useless piece of hardware — the private key on the key is correct but the public key is no longer trusted. The user re-enrolls with a new key.

**Why sign count matters here:** If the attacker uses the key BEFORE the user (who also has the key briefly after theft, e.g., key was pickpocketed from bag), the sign count increments. When the legitimate user later tries to use it, their sign count will be lower than stored → CLONE DETECTION alert fires → credential locked → security team notified.

---

### Q4: What is the "Secret Zero" problem in PAM automation, and how do solutions like HashiCorp Vault's AppRole, Kubernetes auth, or AWS IAM role solve it without fully solving it?

**Answer:**

The Secret Zero problem: a service needs a secret to get a secret. To call the vault API and retrieve a database password, the application must first authenticate to the vault. What credentials does it use? If those credentials are also stored somewhere (config file, environment variable), you've just moved the problem.

**AppRole approach:**
The application is given a RoleID (not secret, like a username) and a SecretID (secret, like a password). The SecretID is injected at deployment time (by an orchestrator, not stored in the app itself). AppRole solves Secret Zero by making the SecretID:
- Short-lived (configurable: 24 hours, one-time-use, or permanent)
- Delivered dynamically (CI/CD system injects it during deployment)
- Bound to CIDR IP ranges (only your app server's IP range can use it)

**The remaining problem:** The SecretID must come from somewhere. If a human operator generates it and puts it in a config file: the human is Secret Zero. If the CI/CD system generates it: the CI/CD system's auth to Vault is Secret Zero. It's turtles all the way down — eventually you hit a root of trust.

**Kubernetes auth:**
The Kubernetes service account JWT token (mounted at `/var/run/secrets/kubernetes.io/serviceaccount/token`) authenticates the pod to Vault. Vault calls the Kubernetes API to verify the JWT is legitimate and from the right service account. Secret Zero is now: who controls the Kubernetes cluster? Kubernetes cluster credentials ARE the root of trust.

**AWS IAM role:**
The EC2 instance's IAM role is granted access to Vault (or directly to AWS Secrets Manager). The instance metadata service (`http://169.254.169.254/latest/meta-data/iam/security-credentials/`) provides temporary credentials without any explicit secret. Secret Zero is now: who can launch EC2 instances with this role? IAM permissions are the root of trust.

**The genuine solution**: Ground the trust in hardware attestation. AWS Nitro Attestation, TPM attestation during enrollment, or GCP Confidential VMs can cryptographically prove "this is the exact software stack I expect running on the exact hardware I trust." This makes the root of trust hardware-rooted rather than configuration-rooted — an attacker cannot forge the hardware attestation without physical device access.

**Why none fully solves it:** You always end up trusting some root — hardware manufacturer, cloud provider, physical access control. The goal isn't to eliminate trust but to make the root of trust physically tangible (hardware) rather than logically copyable (secrets in files).

---

### Q5: Explain how session recording creates tamper-evident audit trails. If a privileged user (with OS root on the PAM server) wanted to delete or modify their session recording, what technical controls would prevent or detect this?

**Answer:**

**What a malicious privileged user has access to:**
- Operating system root on the PAM server (assume worst case)
- Can read/write any file on the PAM server filesystem
- Can kill any process
- Cannot access HSM directly (requires authenticated API call with controlled audit trail)

**Control 1: Cryptographic chaining (detect but not prevent)**

Each recording chunk is signed by the HSM using the Audit Log Signing Key (ALK). If the attacker deletes chunk #47 of a recording:
- The chain reference in chunk #48 (`prev_hash = hash of chunk #47`) becomes invalid
- Integrity verification (run periodically or on request) detects the break
- Detection lag: up to the verification frequency (configured: 15 minutes)

If attacker modifies chunk #47 content:
- The ECDSA signature over that chunk (made with HSM key) fails verification
- Cannot be forged without the HSM private key

**Control 2: Real-time streaming to separate storage**

The PAM proxy streams session recordings in real time to object storage (S3/Azure Blob) on a separate infrastructure component:
- Segments uploaded every 30 seconds as they're generated
- PAM server never holds the "canonical" recording — it's immediately pushed out
- Even with root on PAM server: segments already in S3 cannot be modified on the PAM server (they're no longer there)
- S3 Object Lock (WORM): even the S3 bucket admin cannot delete objects within retention period

**Control 3: Immutable storage (prevent modification)**

S3 Object Lock in COMPLIANCE mode:
- Object cannot be deleted or overwritten before retention period expires
- Even the AWS root account cannot delete it (must use MFA Delete + special process)
- Only mitigable by: compromising the AWS account root credentials

**Control 4: Distributed Audit Log**

Audit log entries (metadata, not the full recording) are:
- Forwarded to a SIEM (Splunk/Elastic) in real time — separate infrastructure
- Forwarded to a compliance-managed system (often third-party)
- The SIEM ingestion is typically unidirectional (PAM → SIEM, not the reverse)

**What the attacker can actually do:**
- Delete local copies on the PAM server (but S3 WORM copy persists)
- Attempt to stop the recording service (but already-uploaded segments are in S3)
- Kill the session recording process during a session (gap in recording is itself logged: "recording_interrupted" event)
- Mess with the chain hash file on the PAM server (doesn't affect S3 objects)

**The gap:** If the attacker acts within the 30-second streaming window, they might prevent a segment from being uploaded. This creates a detectable gap (the session_recording_started event exists, but segments are missing). A missing segment is suspicious on its own.

**Forensic note:** Even if a segment is missing, all other signals remain:
- Authentication logs (who logged in, when, from where)
- Command logs (independently captured by the OS's auditd on the target)
- Network flow records
- JIT access approval records

---

*Document ends. Coverage: complete PAM architecture — FIDO2/WebAuthn cryptography, TPM hardware integration, HSM key hierarchy, JIT access workflows, DLP mechanisms, AiTM attack mechanics and FIDO2 immunity, session recording with tamper evidence, account recovery paradox, complete observability stack, and 5 deep interview questions with full cryptographic and architectural explanations.*