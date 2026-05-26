# Passkeys / WebAuthn / FIDO2 — IAM Security Engineering Breakdown

**Classification:** Internal Engineering Reference  
**Audience:** Identity Architects, Security Engineers, Platform Teams, Product Security  
**Assumed Reader:** Will be interviewed on this system. Every claim is grounded in the W3C WebAuthn Level 3 specification and FIDO2 CTAP2 protocol.  
**Key References:** W3C WebAuthn Level 3 Spec, FIDO Alliance CTAP2 Specification, RFC 8471 (Token Binding), NIST SP 800-63B (Digital Identity Guidelines), CISA "More Than a Password" guidance, Apple/Google Passkey developer documentation.

---

## Table of Contents

1. [Authentication/Access Narrative](#1-authenticationaccess-narrative)
2. [Cryptographic Flow & Hardware Integration](#2-cryptographic-flow--hardware-integration)
3. [Server-Side Validation & Session Architecture](#3-server-side-validation--session-architecture)
4. [Access Control & Authorization](#4-access-control--authorization)
5. [Bypass & Attack Mechanics](#5-bypass--attack-mechanics)
6. [Security Controls & Defensive Mechanics](#6-security-controls--defensive-mechanics)
7. [Attack Surface Mapping](#7-attack-surface-mapping)
8. [Failure Points & Edge Cases](#8-failure-points--edge-cases)
9. [Mitigations & Observability](#9-mitigations--observability)
10. [Interview Questions](#10-interview-questions)

---

## 1. Authentication/Access Narrative

### Terminology First (Precision Matters)

Before the narrative, lock down the terms because they are frequently conflated:

| Term | Precise Meaning |
|---|---|
| **FIDO2** | The umbrella standard: WebAuthn (W3C) + CTAP2 (FIDO Alliance) |
| **WebAuthn** | The browser/platform JavaScript API and server protocol (W3C spec) |
| **CTAP2** | Client-to-Authenticator Protocol v2 — how the browser talks to a hardware key or platform authenticator |
| **Passkey** | A FIDO2 credential that is synced across devices (as opposed to device-bound). Passkeys ARE WebAuthn credentials — "passkey" is a UX marketing term for synced FIDO2 credentials |
| **Authenticator** | The entity that holds the private key: platform (phone biometrics, Windows Hello) or roaming (YubiKey, Titan) |
| **Relying Party (RP)** | The server/service that trusts the authenticator and validates assertions |
| **RPID** | The Relying Party ID — a domain name (e.g., `example.com`) that scopes the credential |

---

### Story 1: First-Time Registration

**Actors:** Alice (user), her iPhone 15 (authenticator), `bank.example.com` (relying party).

**T=0 — User initiates registration**

Alice logs in with username/password (legacy path) and goes to Security Settings → "Add a passkey." The browser JavaScript calls:

```javascript
// Relying Party's web page calls the WebAuthn API:
const credential = await navigator.credentials.create({
  publicKey: {
    // Options sent from the server:
    challenge: Uint8Array [0x3a, 0xf2, 0xb1, ...],  // 32 random bytes from server
    rp: {
      name: "Example Bank",
      id: "bank.example.com"           // RPID — scopes the credential
    },
    user: {
      id: Uint8Array([0x01, 0x02, ...]), // Opaque user handle (not username)
      name: "alice@example.com",         // Display only
      displayName: "Alice Smith"
    },
    pubKeyCredParams: [
      { type: "public-key", alg: -7 },  // ES256 (ECDSA with P-256, SHA-256)
      { type: "public-key", alg: -257 } // RS256 (RSA-PKCS1v15, SHA-256) — fallback
    ],
    authenticatorSelection: {
      authenticatorAttachment: "platform",  // or "cross-platform" for YubiKey
      userVerification: "required",         // Biometric/PIN required
      residentKey: "required"               // Store on authenticator (enables passkey)
    },
    attestation: "direct",   // Server wants authenticator attestation cert
    timeout: 60000,          // 60 seconds for user to respond
    excludeCredentials: [...]  // List of already-registered credentials (prevent duplicates)
  }
});
```

**What Alice sees:** iOS prompts "Do you want to save a passkey for bank.example.com? Face ID will be used to verify you." Alice looks at the camera.

**What actually happens (in ~200ms):**

1. iOS checks the `rpId` (`bank.example.com`) against the current page origin. The page must be on `https://bank.example.com` or a subdomain. This check happens in the operating system, not JavaScript — the browser passes the origin, the OS validates. This is the **origin binding** that prevents phishing.

2. Face ID authenticates Alice locally. The result is never sent to any server. It unlocks access to the Secure Enclave.

3. The Secure Enclave generates a new ECDSA P-256 key pair:
   - Private key: stays in Secure Enclave, never extractable.
   - Public key: will be sent to the server.

4. The authenticator creates a **credential ID**: a randomly generated identifier (16–64 bytes) that uniquely identifies this key pair.

5. The authenticator constructs **authenticatorData**:
   ```
   authenticatorData = [
     rpIdHash (32 bytes),         // SHA-256("bank.example.com")
     flags (1 byte),              // UP=1 (user present), UV=1 (user verified), AT=1 (attested)
     signCount (4 bytes),         // 0 for new credential
     aaguid (16 bytes),           // Authenticator model identifier
     credentialIdLength (2 bytes),
     credentialId (variable),     // The random credential ID
     publicKeyBytes (CBOR)        // The ECDSA P-256 public key, COSE-encoded
   ]
   ```

6. The authenticator constructs **clientDataJSON**:
   ```json
   {
     "type": "webauthn.create",
     "challenge": "OvKx...",    // Base64url of the server's challenge
     "origin": "https://bank.example.com",
     "crossOrigin": false
   }
   ```

7. The authenticator signs: `signature = ECDSA_P256_Sign(privateKey, SHA256(authenticatorData || SHA256(clientDataJSON)))`

8. For attestation (`attestation: "direct"`): The authenticator also includes its attestation certificate chain, proving what model of hardware was used.

9. All of this is returned to the browser, which sends it to the server.

**Server receives and stores:**
```
{
  credentialId: <base64url>,
  publicKey: <COSE-encoded P-256 public key>,
  signCount: 0,
  rpId: "bank.example.com",
  userId: <user handle>,
  attestation: { ... }  // Optional: validate authenticator model
}
```

**What the server does NOT store:** the private key, any biometric data, any secret.

---

### Story 2: Subsequent Authentication

Two weeks later, Alice returns to `bank.example.com` and clicks "Sign in with passkey."

**T=0 — Server issues a challenge**

```javascript
// Server generates and sends:
{
  challenge: Uint8Array [0x9c, 0x3a, 0xf7, ...],  // NEW fresh random bytes
  timeout: 60000,
  rpId: "bank.example.com",
  userVerification: "required",
  allowCredentials: [
    // Optional: if server knows which user, can hint at specific credential ID
    // If empty: browser/OS shows all passkeys for this RP
    { type: "public-key", id: <credentialId> }
  ]
}
```

**T=200ms — Authenticator signs**

1. iOS shows "Sign in to bank.example.com with passkey?"
2. Face ID verifies Alice.
3. Secure Enclave retrieves the private key for `bank.example.com` (looked up by rpIdHash).
4. Constructs authenticatorData (increments signCount: 0 → 1).
5. Constructs clientDataJSON with `"type": "webauthn.get"` and the current challenge.
6. Signs: `signature = ECDSA_P256_Sign(privateKey, SHA256(authenticatorData || SHA256(clientDataJSON)))`
7. Returns the assertion to the browser.

**What Alice sees:** Face ID prompt, then she's logged in.

**What the server sees:**

```
{
  credentialId: <identifies which key pair>,
  clientDataJSON: {
    type: "webauthn.get",
    challenge: "nDr3...",    // Must match what server issued
    origin: "https://bank.example.com"
  },
  authenticatorData: <rpIdHash + flags + signCount + ...>,
  signature: <ECDSA signature>
}
```

**Server validation (full detail in Section 3):**
1. Verify `type == "webauthn.get"`.
2. Verify `origin == "https://bank.example.com"` (or allowlisted variant).
3. Verify `challenge` matches the one the server issued for this session (and consume it — one-time use).
4. Verify `rpIdHash == SHA256("bank.example.com")`.
5. Retrieve stored public key for this credentialId.
6. Verify signature using the stored public key.
7. Verify `signCount > stored_signCount` (replay detection).
8. Update stored `signCount`.
9. Issue session.

**What the server does NOT send:** the user's password, any secret, any long-term credential.

---

## 2. Cryptographic Flow & Hardware Integration

### Key Generation and Hardware Binding

```
PLATFORM AUTHENTICATOR ARCHITECTURE (Apple Secure Enclave):

┌──────────────────────────────────────────────────────────────────────┐
│  Application Processor (iOS/macOS)                                   │
│                                                                       │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │  WebAuthn Platform API (ASAuthorization framework)           │    │
│  │  - Receives create/get request from browser                  │    │
│  │  - Validates origin and rpId                                 │    │
│  │  - Displays system UI (Face ID prompt)                       │    │
│  └──────────────────────────────────┬─────────────────────────────┘  │
│                                     │  Secure API call                 │
│  ┌──────────────────────────────────▼─────────────────────────────┐  │
│  │  SECURE ENCLAVE (separate processor, isolated memory)           │  │
│  │                                                                  │  │
│  │  Neural Engine (Face ID biometric matching):                    │  │
│  │  - Template stored encrypted in Secure Enclave                  │  │
│  │  - Match result: binary (match/no match) — never leaves enclave │  │
│  │  - If match: grants access to protected key operations          │  │
│  │                                                                  │  │
│  │  Key Generation:                                                 │  │
│  │  - NIST P-256 elliptic curve key pair generated                │  │
│  │  - Private key: wrapped with Enclave's UID key                  │  │
│  │  - Wrapped private key: stored in keychain (on-disk)           │  │
│  │  - Public key: returned to application processor                │  │
│  │                                                                  │  │
│  │  Signing:                                                        │  │
│  │  - Input: authenticatorData || SHA256(clientDataJSON)           │  │
│  │  - Private key unwrapped by UID key (never plaintext outside)   │  │
│  │  - ECDSA signature computed in Secure Enclave                   │  │
│  │  - Signature: returned to application processor                 │  │
│  │                                                                  │  │
│  │  NEVER ACCESSIBLE TO:                                           │  │
│  │  - Application code                                             │  │
│  │  - iOS kernel                                                   │  │
│  │  - Physical probing (dedicated bus, encrypted internally)       │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────┘
```

### The P-256 ECDSA Cryptography

**Key pair structure:**
```
Private key: d ∈ [1, n-1]  where n is the P-256 curve order
             (256-bit secret scalar)

Public key: Q = d × G
             G = generator point on P-256 curve (fixed, public constant)
             Q = (x, y) point on the curve (512 bits, or 257 bits compressed)
```

**Signing operation (what happens in Secure Enclave):**
```
Input: message m = SHA256(authenticatorData || SHA256(clientDataJSON))

1. Generate ephemeral random k ∈ [1, n-1]  (critical: k must be unique per signature)
2. Compute R = k × G
3. r = R.x mod n
4. s = k⁻¹(m + r·d) mod n
5. Signature = (r, s)  [64 bytes total for P-256]
```

**Why k uniqueness is critical:** If k is reused across two signatures with the same private key, the private key can be recovered algebraically. This is the Sony PS3 cryptographic failure (they used a fixed k, not random). The Secure Enclave uses a hardware TRNG (True Random Number Generator) to generate k, making this deterministic — Sony's mistake is impossible.

**Verification (server side):**
```
Input: message m, signature (r, s), public key Q

1. Verify r, s ∈ [1, n-1]
2. w = s⁻¹ mod n
3. u₁ = m·w mod n
4. u₂ = r·w mod n
5. Point P = u₁·G + u₂·Q
6. Valid if P.x mod n == r
```

### Hardware Security Key (CTAP2 Protocol)

For roaming authenticators (YubiKey, Titan Key), the protocol between browser and hardware key:

```
Browser <──── USB HID / NFC / BLE ────> Hardware Security Key

Registration (CTAP2 authenticatorMakeCredential):
  Browser sends:
  {
    clientDataHash:     SHA256(clientDataJSON),  // 32 bytes
    rp:                 {id: "example.com", name: "Example"},
    user:               {id: ..., name: ..., displayName: ...},
    pubKeyCredParams:   [{alg: -7}],  // ES256
    options:            {rk: true, uv: true}  // residentKey, userVerification
  }

  Key responds (after user touches the key):
  {
    fmt: "packed",              // Attestation format
    attStmt: {
      alg: -7,
      sig: <signature over auth data using attestation key>,
      x5c: [<attestation cert>, <CA cert>]
    },
    authData: <authenticatorData bytes>
  }

Authentication (CTAP2 authenticatorGetAssertion):
  Browser sends:
  {
    rpId: "example.com",
    clientDataHash: SHA256(clientDataJSON),  // Contains the server's challenge
    allowList: [...],  // Credential IDs to use
    options: {up: true, uv: true}  // userPresence, userVerification
  }

  Key responds (after user touches):
  {
    credential: {id: <credentialId>, type: "public-key"},
    authData: <authenticatorData>,
    signature: <ECDSA signature>
  }
```

### The Nonce/Challenge Mechanism: Why It's Replay-Proof

```
Server state machine for challenge issuance:

T=0:   Server generates challenge = crypto.getRandomValues(32 bytes)
       = [0x9c, 0x3a, 0xf7, 0x12, ...]  // 256 bits of entropy
       
       Server stores: {
         challengeId: uuid,
         challengeBytes: <32 bytes>,
         userId: <user>,
         issuedAt: timestamp,
         expiresAt: timestamp + 5 minutes,  // Narrow window
         used: false
       }
       
       Server returns challenge to browser.

T=1s:  User completes biometric. Authenticator signs over:
       SHA256(authenticatorData || SHA256(clientDataJSON))
       
       clientDataJSON includes: "challenge": <base64url of the 32 bytes>
       
       The challenge is now BOUND to the signature.

T=2s:  Browser returns assertion to server.

T=2s:  Server validates:
       1. Look up challenge by the value in clientDataJSON.challenge
       2. Check: used == false → if true: REJECT (replay)
       3. Check: expiresAt > now → if false: REJECT (expired)
       4. Mark: used = true (atomic update — prevents race condition replay)
       5. Verify signature → confirms challenge is in the signed data

Why replay is impossible:
  - Challenge is random: 2^256 values — cannot be predicted
  - Challenge is one-time: marked used after first valid assertion
  - Challenge expires: narrow window prevents delayed replay
  - Challenge is signed: cannot be stripped without breaking signature
```

### Passkey Sync: iCloud Keychain / Google Password Manager

For synced passkeys (as opposed to device-bound), the private key leaves the secure enclave:

```
Passkey Sync Architecture (Apple iCloud Keychain):

  Device A (iPhone):
    1. Generate P-256 key pair in Secure Enclave
    2. Export wrapped key: AES-256-GCM encrypt(private_key, iCloud key)
    3. iCloud key = derived from user's iCloud account password + HSM
    4. Encrypted key blob → iCloud Keychain servers
    
  Device B (iPad) - First sync:
    1. Authenticate with iCloud (password + Apple ID MFA)
    2. iCloud delivers encrypted key blob
    3. iCloud key available after iCloud auth → decrypt key blob
    4. Private key imported into iPad's Secure Enclave
    5. Now both devices have the same P-256 private key

Security model of synced passkeys:
  - The private key is encrypted in transit and at rest in iCloud
  - iCloud servers never see the plaintext private key (E2E encryption)
  - iCloud key itself is secured by the user's iCloud account + device security
  
  Tradeoff vs device-bound:
    Device-bound (YubiKey, TPM-bound): private key never leaves hardware
    Synced passkey: private key is reproducible on new devices but encrypted E2E
    
  Enterprise consideration:
    FIDO2 with authenticatorAttachment: "cross-platform" (hardware key) = device-bound
    FIDO2 with authenticatorAttachment: "platform" + sync enabled = synced passkey
    Enterprise can require device-bound by enforcing attestation policy
```

---

## 3. Server-Side Validation & Session Architecture

### Full Validation Pipeline

```
┌─────────────────────────────────────────────────────────────────────────────┐
│              WEBAUTHN AUTHENTICATION VALIDATION PIPELINE                    │
│                                                                              │
│  STEP 1: Structural Validation                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │  Input: {credentialId, clientDataJSON, authenticatorData, signature}  │ │
│  │                                                                        │ │
│  │  - Verify none of these fields are null/empty                         │ │
│  │  - Verify clientDataJSON is valid UTF-8 JSON                          │ │
│  │  - Verify authenticatorData is at least 37 bytes                      │ │
│  │    (rpIdHash[32] + flags[1] + signCount[4] = minimum 37 bytes)        │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                              │                                               │
│                              ▼                                               │
│  STEP 2: clientDataJSON Validation                                          │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │  Parse clientDataJSON:                                                 │ │
│  │  {                                                                     │ │
│  │    "type": "webauthn.get",           ← Must be "webauthn.get"         │ │
│  │    "challenge": "nDr3...",           ← Must match server-issued        │ │
│  │    "origin": "https://bank.example.com",  ← Must be expected origin  │ │
│  │    "crossOrigin": false              ← If true: flag for review       │ │
│  │  }                                                                     │ │
│  │                                                                        │ │
│  │  - type check: reject if not "webauthn.get" (prevents create reuse)  │ │
│  │  - origin check: exact string match against allowlist                 │ │
│  │  - challenge check: retrieve from server state, verify match,        │ │
│  │                     mark as consumed (atomic)                         │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                              │                                               │
│                              ▼                                               │
│  STEP 3: authenticatorData Validation                                       │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │  Parse authenticatorData (binary format):                              │ │
│  │  [0..31]:  rpIdHash — SHA256(rpId as UTF-8)                          │ │
│  │  [32]:     flags byte                                                  │ │
│  │              bit 0 (UP): User Present — must be 1                     │ │
│  │              bit 2 (UV): User Verified — must be 1 if UV required     │ │
│  │              bit 6 (AT): Attested credential data present             │ │
│  │              bit 7 (ED): Extension data present                       │ │
│  │  [33..36]: signCount (uint32, big-endian)                             │ │
│  │                                                                        │ │
│  │  - rpIdHash == SHA256("bank.example.com") ← Must match                │ │
│  │  - UP flag == 1 ← User must have been present                        │ │
│  │  - UV flag check: if userVerification == "required", UV must == 1    │ │
│  │  - signCount > stored_signCount ← Replay/clone detection              │ │
│  │    Exception: if both == 0 (some platform authenticators don't count)│ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                              │                                               │
│                              ▼                                               │
│  STEP 4: Signature Verification                                             │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │  Retrieve: stored public key for credentialId                         │ │
│  │  Compute:  verificationData = authenticatorData || SHA256(clientDataJSON)│
│  │  Verify:   ECDSA_P256_Verify(publicKey, verificationData, signature)  │ │
│  │                                                                        │ │
│  │  If verification FAILS:                                               │ │
│  │    → Log failed assertion (credentialId, origin, timestamp, IP)      │ │
│  │    → Increment failure counter for this credentialId                 │ │
│  │    → Return 401 Unauthorized                                          │ │
│  │    → Do NOT reveal WHY verification failed (prevents oracle attack)   │ │
│  │                                                                        │ │
│  │  If verification PASSES:                                              │ │
│  │    → Update stored signCount                                          │ │
│  │    → Update last_used timestamp                                       │ │
│  │    → Proceed to session issuance                                      │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                              │                                               │
│                              ▼                                               │
│  STEP 5: Session Issuance                                                   │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │  Generate session token: crypto.randomBytes(32) → base64url           │ │
│  │  Store in session database:                                            │ │
│  │  {                                                                     │ │
│  │    sessionId: <token>,                                                 │ │
│  │    userId: <userId>,                                                   │ │
│  │    credentialId: <which passkey was used>,                            │ │
│  │    issuedAt: now(),                                                    │ │
│  │    expiresAt: now() + 8h,                                             │ │
│  │    ipAddress: <client IP>,                                             │ │
│  │    userAgent: <client UA>,                                             │ │
│  │    authStrength: "passkey-uv"  // High assurance                      │ │
│  │  }                                                                     │ │
│  │  Set-Cookie: sessionId=<token>; HttpOnly; Secure; SameSite=Strict     │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Session Architecture and Revocation

```
SESSION STATE MACHINE:

  ISSUED → ACTIVE → EXPIRED (time-based)
    ↓
  REVOKED (explicit — password change, account recovery, admin action)
    ↓
  COMPROMISED (detected anomaly — IP change, impossible travel)

Session database schema (PostgreSQL example):
  CREATE TABLE sessions (
    session_id      BYTEA PRIMARY KEY,          -- 32 random bytes
    user_id         UUID NOT NULL,
    credential_id   BYTEA NOT NULL,             -- Which passkey was used
    auth_level      TEXT NOT NULL,              -- 'passkey-uv', 'passkey-up', 'password'
    issued_at       TIMESTAMPTZ NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    last_active     TIMESTAMPTZ,
    ip_address      INET,
    user_agent      TEXT,
    revoked         BOOLEAN DEFAULT FALSE,
    revoke_reason   TEXT,
    revoked_at      TIMESTAMPTZ
  );

  CREATE INDEX idx_sessions_user ON sessions(user_id) WHERE NOT revoked;
  CREATE INDEX idx_sessions_expiry ON sessions(expires_at) WHERE NOT revoked;

Revocation triggers:
  1. User clicks "Sign out all devices" → UPDATE sessions SET revoked=true WHERE user_id=?
  2. Admin account lock → same
  3. Password reset → same (all passkeys + sessions invalidated? Policy decision)
  4. Passkey deletion → revoke sessions that used that specific credentialId
  5. Anomaly detection → revoke specific session (not all)

Credential revocation (separate from session):
  When a passkey is deleted by the user:
    - Delete from credentials table
    - Revoke all sessions that used that credentialId
    - Cannot revoke the key on the authenticator itself (no mechanism)
      → Attacker who exported the private key still has it
      → Short-lived session tokens limit damage window

The missing CRL problem:
  WebAuthn has no equivalent of TLS Certificate Revocation Lists.
  If a hardware key is stolen: no way to tell the authenticator to reject the key.
  The only revocation mechanism is server-side: delete the credential record.
  If server deletes the credential: subsequent auth attempts fail (unknown credentialId).
  The private key on the stolen device: still valid cryptographically, but useless
  because the server no longer accepts assertions from it.
```

---

## 4. Access Control & Authorization

### Just-in-Time Access with Passkey Step-Up

Passkeys enable **continuous re-authentication** without friction — a key capability for JIT access systems:

```
JIT Access Architecture with Passkey Step-Up:

User has active session (auth_level: "passkey-uv", issued 6 hours ago)
User tries to access: /admin/delete-user (high-privilege operation)

Server-side policy engine evaluates:
  - Operation risk: HIGH (irreversible delete)
  - Session age: 6 hours (stale)
  - Current auth_level: "passkey-uv" (strong, but stale)
  - Policy: high-risk operations require re-auth within 15 minutes
  
  → Decision: REQUIRE STEP-UP

Step-up flow:
  1. Server returns 401 with WWW-Authenticate: WebAuthn challenge
  2. Browser JavaScript: navigator.credentials.get({...}) 
  3. User completes Face ID (2 seconds)
  4. Server validates assertion
  5. Server updates session: {last_stepup: now(), operation_allowed: ["admin-delete"]}
  6. Operation proceeds

This is MUCH better than TOTP step-up:
  - TOTP: attacker can phish the 6-digit code in real-time (AiTM)
  - WebAuthn: challenge includes the origin — phishing site gets a signature
    bound to the WRONG origin, which the legitimate server rejects
```

### Vaulting and Privileged Access

For systems requiring credential vaulting (PAM — Privileged Access Management):

```
Passkey + PAM Integration:

Architecture: Passkey authenticates the HUMAN, PAM vaults the SECRET

Step 1: Human authenticates via passkey (WebAuthn)
  → Establishes: identity assertion with AAL3 (highest NIST assurance level)
  
Step 2: PAM system receives identity assertion
  → Validates session token: auth_level must be "passkey-uv" + recent step-up
  → Checks authorization: is this identity authorized for requested privilege?
  
Step 3: PAM issues time-limited credential
  → SSH certificate: valid for 1 hour, scoped to specific target host
  → Database password: rotated, stored in vault, delivered for this session only
  → Cloud API key: temporary STS token with limited permissions
  
Step 4: Credential used, session ends, credential revoked
  → SSH cert: expired, cannot be reused
  → Database password: rotated on return, previous password invalid
  → Cloud STS: token expired

Comparison to legacy PAM (TOTP + shared password vault):
  Legacy: User authenticates with password + TOTP → vault releases SSH key
    Attack: phish password + TOTP in real-time → AiTM → get vault access
  
  WebAuthn PAM: User authenticates with passkey → vault releases SSH cert
    Attack attempt: phish passkey → fails (origin binding prevents it)
    The vault is protected by a phishing-resistant credential
```

---

## 5. Bypass & Attack Mechanics

### Why This Section Exists

Understanding HOW attacks work against WebAuthn is essential for understanding WHY WebAuthn's properties are significant defenses. Most attacks described here are attacks on legacy systems that WebAuthn *defeats* — understanding the attack clarifies why the defense matters. Where WebAuthn itself has residual attack surface, it is noted precisely.

---

### Attack 1: Adversary-in-the-Middle (AiTM) Phishing — How WebAuthn Defeats It

**Context:** AiTM is the attack that compromises Microsoft 365 accounts at scale (Evilginx2, Modlishka, Muraena frameworks). With passwords + TOTP, AiTM succeeds. With WebAuthn, it fundamentally fails.

**How AiTM works against passwords + TOTP:**

```
Classic AiTM Attack (Legacy MFA):

Attacker stands up: https://micros0ft-login.phishing.com
                    (reverse proxy to real Microsoft)

User visits phishing site:
  Browser ──── HTTPS ────> Phishing Proxy ──── HTTPS ────> Real Microsoft

Proxy intercepts:
  - User enters password → proxy captures it, forwards to real Microsoft
  - Real Microsoft sends TOTP challenge → proxy forwards to user
  - User enters TOTP code (6 digits, 30-second window) → proxy captures + forwards
  - Real Microsoft issues session cookie → proxy captures it
  - User gets a fake success page

Attacker has: Real session cookie = authenticated access to Microsoft 365
Timeline: This happens in REAL TIME (< 30 seconds)
TOTP window: attacker has 30 seconds to replay the code
Result: Microsoft 365 fully compromised, passkeys not needed for attacker
```

**Why WebAuthn/Passkey defeats AiTM:**

```
AiTM Attempt Against WebAuthn:

Setup: Same phishing proxy at https://micros0ft-login.phishing.com

Step 1: Real Microsoft sends WebAuthn challenge to user via proxy
  Challenge: {challenge: <32 bytes>, rpId: "microsoft.com"}
  Proxy forwards to user's browser. ← The challenge reaches the real browser.

Step 2: Browser constructs clientDataJSON:
  {
    "type": "webauthn.get",
    "challenge": "...",
    "origin": "https://micros0ft-login.phishing.com"  ← PHISHING ORIGIN!
  }
  
  The browser fills in the ACTUAL page origin, not the destination.
  This is done by the browser itself, not by JavaScript that the attacker controls.

Step 3: Authenticator signs over clientDataJSON including the phishing origin.

Step 4: Proxy forwards the assertion to Real Microsoft.

Step 5: Real Microsoft validates:
  clientDataJSON.origin == "https://microsoft.com"?
  ACTUAL VALUE: "https://micros0ft-login.phishing.com"
  RESULT: VALIDATION FAILS → 401 Unauthorized

The assertion is cryptographically bound to the phishing origin.
It cannot be used on the real origin. AiTM is fundamentally broken.

Why the attacker cannot fix this:
  - The origin in clientDataJSON is set by the browser (trusted code)
  - JavaScript running on the phishing page cannot override this
  - The authenticator signs over the origin — forging it breaks the signature
  - There is NO way to make an authenticator sign over a different origin
    while the user is on the phishing page

This is the single most important security property of WebAuthn.
```

**The mathematical impossibility:**

For AiTM to work against WebAuthn, the attacker needs a signature where:
```
clientDataJSON = {"origin": "https://microsoft.com", "challenge": "correct_challenge"}
```
But the authenticator will sign:
```
clientDataJSON = {"origin": "https://phishing.com", "challenge": "correct_challenge"}
```
The attacker would need to forge a signature over the modified clientDataJSON. This requires breaking ECDSA P-256 — computationally infeasible (equivalent to solving the elliptic curve discrete log problem).

---

### Attack 2: Pass-the-Cookie — Why Sessions Are the Residual Risk

**WebAuthn secures authentication. It does NOT secure the resulting session.**

```
Pass-the-Cookie Attack:

Scenario: User authenticates via WebAuthn. Browser stores session cookie.
Attacker has: XSS vulnerability, malicious browser extension, or malware.

Attack:
  - XSS reads document.cookie (if cookie is not HttpOnly)
    OR: Extension reads cookies via chrome.cookies API
    OR: Malware reads browser's SQLite cookie database from disk

  Result: Attacker has the session cookie.
  
  Attacker imports cookie into their browser:
    document.cookie = "sessionId=<stolen_value>"
  
  Now authenticated as victim, without needing the passkey at all.

Why WebAuthn doesn't prevent this:
  WebAuthn proves: "the user with this passkey authenticated right now"
  Session cookie: long-lived opaque token that represents that authentication
  
  WebAuthn's phishing resistance protects the AUTHENTICATION EVENT.
  It does NOT protect the SESSION that results from authentication.
  The session is a bearer token — whoever has it is treated as authenticated.

Mitigations (layered):
  1. HttpOnly cookie: JavaScript cannot read it (blocks XSS path)
  2. SameSite=Strict: Cookie not sent in cross-site requests (CSRF protection)
  3. Secure flag: HTTPS only (prevents network sniffing)
  4. Short session lifetime: stolen cookie expires quickly
  5. IP binding: reject session if IP changes (breaks mobility, tradeoff)
  6. Device fingerprint binding: subtle, bypassable but raises bar
  7. Token Binding (RFC 8471): cryptographically bind session token to TLS channel
     (abandoned by browsers — not a viable option currently)
  8. Continuous re-authentication: require passkey re-assertion for sensitive ops
     (stolen cookie can't be used for high-value actions without the passkey)
```

---

### Attack 3: Account Takeover via Recovery Flow Weakness

**The weakest link in a WebAuthn deployment is almost always the account recovery mechanism.**

```
Recovery Flow Attack:

Scenario: Service supports WebAuthn but also has email-based recovery.
Attacker has: access to victim's email account (or can compromise it).

Attack:
  1. Go to login page: "I forgot my passkey" / "I don't have access to my device"
  2. Click: "Send recovery email"
  3. Email arrives at victim's inbox
  4. Attacker reads the recovery email (via email compromise, mail server access)
  5. Click recovery link: one-time token in URL
  6. Recovery page: allows registering a NEW passkey
  7. Attacker registers THEIR device as a new passkey
  8. Full account access achieved — without ever touching the victim's passkey

Why this works:
  Recovery flows are intentionally designed to bypass normal authentication.
  They exist because users DO lose their devices. 
  This creates a paradox: robust recovery makes the account recoverable by attackers too.
  
The recovery flow is ONLY as secure as the recovery credential (email, phone, etc.)
If email is weak (no MFA): WebAuthn on the main login is theater.
The attacker attacks the weaker credential, not the WebAuthn.

Mitigations:
  Enterprise: No self-service recovery. Recovery requires:
    - Identity verification (video call with ID, in-person)
    - Approval from IT security team
    - Re-enrollment of new authenticator with logging and alert
    - Immediate notification to primary email AND phone
  
  Consumer: Tiered recovery:
    - Multiple passkeys required for recovery (M-of-N)
    - Recovery codes: high-entropy one-time codes stored offline
    - Trusted recovery contacts (Apple's model)
    - Mandatory waiting period (Google's recovery: 3-day delay)
```

---

### Attack 4: Authenticator Cloning (Device-Bound vs Synced)

**Two different threat models for device-bound vs synced passkeys:**

```
Device-Bound Key (YubiKey, TPM-bound):
  Private key: generated in hardware, non-exportable
  Clone attack: cryptographically impossible
    - Cannot copy the key from the hardware
    - Can steal the physical device (then you have the key AND you "are" the device)
    - Signal: signCount will match between stolen key usage and legitimate usage
    
  SignCount mechanism:
    Each signature increments a counter stored on the authenticator.
    If server sees signCount from stolen key <= stored_signCount:
    Indicates: either clone or key was used from two places.
    Action: flag for investigation (can't determine which is the attacker).

Synced Passkey (iCloud Keychain, Google Password Manager):
  Private key: E2E encrypted in cloud
  Clone attack: possible if cloud account is compromised
    - Attacker compromises iCloud account (phishing iCloud credentials + MFA)
    - Attacker exports passkey to attacker's device
    - Attacker has full authenticator capability
    
  SignCount for synced passkeys:
    Synced passkeys often set signCount = 0 on every assertion (not incremented).
    FIDO spec allows this for synced credentials (sync makes counter management hard).
    This means signCount-based clone detection doesn't work for synced passkeys.
    
  Detection fallback for synced passkeys:
    - Geolocation anomaly (new device, new location)
    - New device enrollment alert
    - Risk-based step-up auth (unusual activity → require re-auth or admin review)
```

---

### Attack 5: Downgrade Attack — Forcing Legacy Authentication

```
Downgrade Attack Against WebAuthn Deployments:

Scenario: Service supports BOTH passkeys AND password+TOTP.
          (Common during migration periods.)

Attacker's goal: Use AiTM phishing (which works against password+TOTP).

Step 1: Attacker's phishing page intercepts the authentication flow.
Step 2: Phishing page's reverse proxy detects the browser is trying WebAuthn.
Step 3: Proxy strips the WebAuthn challenge from the server response.
Step 4: Proxy injects a password prompt instead.
Step 5: User sees a password prompt (not the expected passkey dialog).
Step 6: User enters password (they have it, they just prefer passkeys).
Step 7: Proxy captures password + TOTP in real-time.
Step 8: Successful AiTM compromise.

Why the default configuration fails:
  If the server allows ANY authentication method, including password:
  The attacker forces the weaker method. WebAuthn doesn't help.

Mitigation — Passkey-only policy:
  Account settings: allow_password_auth = false
  Enforce: server rejects any non-passkey authentication attempt
  Result: attacker's phishing proxy cannot offer password auth
  
  For high-security accounts: this is the correct policy.
  For consumer: requires recovery mechanism to not involve password.

Detecting downgrade attempts:
  Monitor: authentication_method != "webauthn" for accounts
  that have passkeys registered.
  Alert: legacy auth used on passkey-registered account → investigate.
```

---

## 6. Security Controls & Defensive Mechanics

### Attestation: Verifying Authenticator Integrity

Attestation allows the relying party to verify not just THAT a key was generated, but WHERE — on what specific hardware model.

```
Attestation Chain of Trust:

  FIDO Alliance (Root CA)
          │
          │ Signs:
          ▼
  Authenticator Vendor CA (e.g., Yubico CA, Apple CA)
          │
          │ Signs:
          ▼
  Per-model Attestation Certificate (batch — same cert for all units of a model)
          │
          │ Used to sign:
          ▼
  Attestation Statement in registration response
  (Proves: "this key was generated by a YubiKey 5 NFC")

AAGUID (Authenticator Attestation GUID):
  16-byte identifier in authenticatorData
  Identifies the MODEL of authenticator (not the specific unit)
  FIDO Alliance maintains the MDS (Metadata Service):
    URL: https://mds.fidoalliance.org/
    Contents: AAGUID → {vendor, model, security characteristics, certification level}

Server-side attestation verification:
  1. Check attestation statement format: "packed", "tpm", "android-key", "none", etc.
  2. Verify attestation certificate chain to a trusted root
  3. Verify attestation statement signature over authenticatorData
  4. Look up AAGUID in FIDO MDS
  5. Accept or reject based on policy:
     - Accept only FIDO Certified Level 2+ authenticators
     - Reject "none" attestation for high-security registrations
     - Accept platform authenticators from known vendors (Apple, Google, Microsoft)
     - Reject any authenticator from unapproved vendors

Enterprise attestation policy example:
  {
    "allowed_aaguids": [
      "2fc0579f-8113-47ea-b116-bb5a8db9202a",  // YubiKey 5 Series
      "d8522d9f-575b-4866-88a9-ba99fa02f35b",  // Apple passkeys
      "08987058-cadc-4b81-b6e1-30de50dcbe96"   // Windows Hello
    ],
    "require_attestation_verification": true,
    "reject_none_attestation": true,
    "require_fido_certification_level": 2
  }
```

### Continuous Authentication and Risk-Based Step-Up

```python
# Risk scoring engine for each request:
class WebAuthnRiskEngine:
    
    def evaluate(self, request: Request, session: Session) -> RiskDecision:
        score = 0
        
        # IP-based signals
        if request.ip != session.ip_address:
            if self.is_vpn_or_tor(request.ip):
                score += 30  # VPN/Tor: moderate risk
            elif self.is_different_country(request.ip, session.ip_address):
                score += 60  # Different country: high risk
            else:
                score += 10  # Different IP, same country: low risk
        
        # Session age
        session_age_hours = (now() - session.issued_at).hours
        if session_age_hours > 8:
            score += 20
        if session_age_hours > 24:
            score += 40
        
        # Operation sensitivity
        if request.path.startswith('/admin'):
            score += 50
        if request.path.startswith('/payment'):
            score += 30
        if request.method in ['DELETE', 'PUT']:
            score += 20
        
        # Device signals
        if request.user_agent != session.user_agent:
            score += 25
        
        # Time-based anomaly
        if self.is_outside_normal_hours(session.user_id, now()):
            score += 20
        
        # Decision
        if score >= 80:
            return RiskDecision.REQUIRE_PASSKEY_REAUTH
        elif score >= 50:
            return RiskDecision.REQUIRE_STEP_UP_NOTIFICATION  # Push to phone
        elif score >= 30:
            return RiskDecision.FLAG_FOR_REVIEW               # Log, alert
        else:
            return RiskDecision.ALLOW
```

---

## 7. Attack Surface Mapping

```
╔══════════════════════════════════════════════════════════════════════════════════╗
║                    WEBAUTHN/PASSKEY ATTACK SURFACE MAP                          ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║                                                                                  ║
║  PHYSICAL ATTACK SURFACE                                                         ║
║  ┌──────────────────────────────────────────────────────────────────────────┐  ║
║  │  Roaming Authenticator (YubiKey, Titan Key)                              │  ║
║  │  - Physical theft: attacker has the key (plus needs PIN if set)         │  ║
║  │  - Side-channel on hardware key: EM analysis of key operations          │  ║
║  │  - Supply chain: fake hardware key (no attestation verification)        │  ║
║  │  Defense: Require PIN on hardware keys, attestation verification         │  ║
║  │                                                                          │  ║
║  │  Platform Device (phone, laptop)                                         │  ║
║  │  - Stolen device: attacker needs biometric/PIN to use passkey            │  ║
║  │  - Biometric spoofing: high-quality fingerprint/photo for Face ID       │  ║
║  │  - Rubber hose: coerce user to authenticate (law enforcement too)       │  ║
║  └──────────────────────────────────────────────────────────────────────────┘  ║
║                                                                                  ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║  TRUST BOUNDARY 1: Physical World → Authenticator Hardware                      ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║                                                                                  ║
║  ENROLLMENT ATTACK SURFACE (registration phase)                                  ║
║  ┌──────────────────────────────────────────────────────────────────────────┐  ║
║  │  - Registering under false identity (before auth is passkey-based)      │  ║
║  │  - Weak identity proofing at initial account creation                   │  ║
║  │  - Social engineering helpdesk to add attacker's passkey                │  ║
║  │  - API endpoint: POST /webauthn/register-begin (rate limit, require auth)│  ║
║  │  - Challenge endpoint: challenge value predictable (PRNG weakness)      │  ║
║  │  - excludeCredentials bypass: server doesn't exclude existing credentials│  ║
║  └──────────────────────────────────────────────────────────────────────────┘  ║
║                                                                                  ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║  TRUST BOUNDARY 2: Enrollment = Identity Binding. Errors here are permanent.    ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║                                                                                  ║
║  AUTHENTICATION ATTACK SURFACE (login phase)                                     ║
║  ┌──────────────────────────────────────────────────────────────────────────┐  ║
║  │  - Downgrade: force password auth on passkey-capable accounts           │  ║
║  │  - Confused deputy: cross-origin iframe with different rpId             │  ║
║  │  - Challenge replay: server doesn't mark challenge as used              │  ║
║  │  - signCount bypass: server accepts signCount ≤ stored (clone allowed)  │  ║
║  │  - API endpoints:                                                        │  ║
║  │    GET  /webauthn/auth-begin  (generates challenge — must rate limit)   │  ║
║  │    POST /webauthn/auth-finish (validates assertion — must rate limit)   │  ║
║  │  - Timing oracle: error messages reveal WHY assertion failed            │  ║
║  └──────────────────────────────────────────────────────────────────────────┘  ║
║                                                                                  ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║  TRUST BOUNDARY 3: Authentication = Identity Assertion. Session is Bearer Token.║
╠══════════════════════════════════════════════════════════════════════════════════╣
║                                                                                  ║
║  SESSION ATTACK SURFACE                                                           ║
║  ┌──────────────────────────────────────────────────────────────────────────┐  ║
║  │  - Cookie theft: XSS, malicious extension, malware (pass-the-cookie)    │  ║
║  │  - Session fixation: attacker sets session ID before auth               │  ║
║  │  - CSRF: cross-site request with existing session cookie                │  ║
║  │  - Session database compromise: all sessions exposed                    │  ║
║  └──────────────────────────────────────────────────────────────────────────┘  ║
║                                                                                  ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║  TRUST BOUNDARY 4: Session = Weakest Link. Must be protected independently.     ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║                                                                                  ║
║  RECOVERY ATTACK SURFACE (highest risk surface)                                   ║
║  ┌──────────────────────────────────────────────────────────────────────────┐  ║
║  │  - Email recovery: compromised email → compromised account              │  ║
║  │  - SMS recovery: SIM swap → bypass passkey entirely                     │  ║
║  │  - Support social engineering: impersonate user to helpdesk             │  ║
║  │  - Recovery codes: stored in same compromised location as passwords     │  ║
║  └──────────────────────────────────────────────────────────────────────────┘  ║
╚══════════════════════════════════════════════════════════════════════════════════╝
```

---

## 8. Failure Points & Edge Cases

### The Account Recovery Paradox

```
The Paradox:
  Strong authentication via passkey requires a recovery mechanism.
  Any recovery mechanism that works when you've lost your device
  can be exploited by an attacker who has compromised your recovery channel.

No perfect solution exists. The tradeoffs:

Option 1: No recovery (maximum security)
  - If you lose ALL authenticators: permanent account lockout
  - Used by: ultra-high-security accounts (root keys, crypto cold storage)
  - Tradeoff: catastrophic usability failure, guaranteed support cost

Option 2: Backup codes (high security)
  - User generates 10 one-time recovery codes at enrollment
  - Store offline (printed, physical safe)
  - Security: codes are random (128 bits), one-time use, offline
  - Failure: user stores backup codes in password manager → same risk as password
  - Failure: user loses backup codes → same as Option 1

Option 3: Multiple passkeys (recommended for enterprise)
  - Register 2+ passkeys from different devices/authenticators
  - If one device lost: use another
  - Policy: require minimum 2 passkeys before enabling passkey-only mode
  - Failure: all devices lost simultaneously (house fire, travel incident)

Option 4: Trusted recovery contacts (Apple model)
  - Designate 2-3 trusted contacts
  - Recovery requires M-of-N contacts to approve (e.g., 2 of 3)
  - Security: attacker must compromise multiple independent contacts
  - Failure: colluding recovery contacts → account takeover

Option 5: Delayed recovery (Google model)
  - Recovery request submitted → 3-day waiting period
  - Account owner notified via all channels → can cancel recovery
  - Security: honest owner will cancel fraudulent recovery in 3 days
  - Failure: account owner unreachable for 3 days (hospitalization, travel)

Best practice for enterprise:
  Tier 1 users (executives, engineers): 
    - Multiple hardware keys (YubiKey), no self-service recovery
    - Recovery: IT-verified identity + approval workflow + logging
  
  Tier 2 users (all others):
    - Platform passkeys (synced) + backup codes
    - Self-service recovery with 24-hour delay and multi-channel notification
```

### Cross-Device Compatibility and Sync Failures

```
Cross-Platform Passkey Status (as of 2025):

  Apple ecosystem: iCloud Keychain (iOS 16+, macOS Ventura+, Safari)
    - Syncs across: iPhone, iPad, Mac (same Apple ID)
    - NOT accessible from: Android, Chrome on Windows
    - Cross-device use: use a different device's passkey via proximity
      (QR code scan → CTAP2 over Bluetooth → other phone does Face ID)

  Google ecosystem: Google Password Manager (Android, Chrome)
    - Syncs across: Android devices (same Google account)
    - Accessible from: Chrome on any OS via Google Password Manager
    - Cross-device: Bluetooth proximity (same as Apple)

  Windows: Windows Hello
    - Device-bound by default (TPM-bound, no sync)
    - Roamable passkeys: supported in Windows 11 via ecosystem managers

  Cross-ecosystem usage:
    User has iPhone passkeys, tries to log in on Windows Chrome:
      Option A: Chrome shows QR code → scan with iPhone → iPhone Bluetooth
                proximity authenticates → Chrome completes login
      Option B: Register a separate passkey on Windows Hello (best UX)
    
    Failure mode: user is at a kiosk or shared device:
      - Cannot use iPhone passkey (Bluetooth proximity may not work reliably)
      - May fall back to password (downgrade risk)
      - Enterprise: provide hardware security keys for shared device scenarios

Sync failure scenario:
  User's iCloud Keychain sync is blocked (corporate MDM policy):
    - New passkeys registered on iPhone
    - Not synced to Mac (same Apple ID but MDM blocks iCloud)
    - User goes to Mac: passkey not available
    - Falls back to password or is locked out
    
  Fix: Enterprise must explicitly allow iCloud Keychain sync for passkeys
  OR: Require hardware keys instead of platform passkeys
  OR: Deploy enterprise passkey management (1Password, Dashlane Enterprise)
```

---

## 9. Mitigations & Observability

### Deployment Tradeoffs: Security vs UX

```
Decision matrix for enterprise WebAuthn deployment:

SETTING                  SECURE CHOICE           UX IMPACT
─────────────────────────────────────────────────────────────────────
userVerification         required                Biometric on every login
                         (UV=1 enforced)          No impact if biometrics available
                                                  High impact if biometrics fail often

authenticatorAttachment  cross-platform           Requires hardware key (cost, distribution)
                         (hardware key only)       Cannot use phone (friction)

residentKey              required                 Passkey stored on authenticator
                         (discoverable)           Enables "sign in without username"
                                                  Requires compatible authenticators

attestation              direct or indirect       Rejects cheap/unverified authenticators
                                                  May reject some consumer devices

Auth method              passkey-only             Cannot fall back to password
                         (no fallback)            Recovery must be robust

Session lifetime         8 hours                  Re-auth after 8h (acceptable)
                         (enterprise standard)

Step-up frequency        high-risk ops only       Minimal friction for routine access
                                                  Re-auth for admin, payments, exports
```

### Critical Metrics and Alerting

```
AUTHENTICATION EVENTS TO LOG (every event, no sampling):

{
  "event": "webauthn_assertion",
  "timestamp": "2025-05-15T10:23:45.123Z",
  "result": "success|failure|error",
  "failure_reason": "invalid_signature|challenge_mismatch|origin_mismatch|expired_challenge|signcount_error",
  "user_id": "<hash — not raw ID in logs>",
  "credential_id": "<base64url>",
  "authenticator_aaguid": "<16-byte UUID>",  // What device type
  "user_verification": true|false,
  "sign_count_previous": 42,
  "sign_count_received": 43,
  "client_origin": "https://bank.example.com",
  "client_ip": "203.0.113.5",
  "user_agent": "Mozilla/5.0...",
  "session_id_hash": "<SHA256 of session for correlation>",
  "risk_score": 15
}

ALERTS TO CONFIGURE:

1. Invalid signatures (immediate alert):
   - Single invalid signature: LOG (can be buggy client)
   - 3 invalid signatures in 1 hour for same credential: ALERT (key may be cloned or tampered)
   - Invalid signature from new IP + new UA: HIGH ALERT

2. signCount anomaly (clone detection):
   - received_signCount <= stored_signCount AND both non-zero: ALERT
   - This means: either the authenticator was used from a different device
     that has an older signCount, OR the authenticator was cloned

3. Origin mismatch (phishing detection):
   - ANY request where clientDataJSON.origin != expected: HIGH ALERT
   - This means: someone is trying to use a passkey on a different site
   - Could be: accidental (misconfigured RP) or attacker testing

4. Challenge replay attempt:
   - Request with an already-consumed challenge: HIGH ALERT
   - Indicates: replay attack attempt or timing race condition

5. Recovery flow triggered:
   - Account recovery initiated: ALERT + notify user on ALL channels
   - Recovery completed (new passkey added): ALERT + notify + require confirmation

6. Passkey enrollment from new device:
   - Alert user (email/push) with details: device type, location, time
   - User can revoke in account security settings

7. Anomalous authentication geography:
   - Authentication from country not seen in last 30 days: ALERT
   - Authentication within 1 hour of prior authentication from different country: CRITICAL

METRICS DASHBOARD (real-time):
  - webauthn_authentications_total{result="success|failure"}
  - webauthn_authentications_by_aaguid{aaguid="..."}  // Track authenticator type distribution
  - webauthn_challenge_expiry_before_use_total  // Challenges that expired unused (UX metric)
  - webauthn_signcount_anomaly_total  // Clone detection events
  - webauthn_origin_mismatch_total  // Phishing probe attempts
  - webauthn_recovery_initiated_total  // Recovery flow usage (high = possible attack)
  - webauthn_session_theft_risk{signal="ip_change|ua_change|geo_anomaly"}
```

### IaC Configuration for Secure WebAuthn Server

```python
# WebAuthn server configuration (py_webauthn library example):
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    ResidentKeyRequirement,
    UserVerificationRequirement,
    AttestationConveyancePreference,
    PublicKeyCredentialDescriptor,
    AuthenticatorAttachment,
)

# Registration options (security-hardened):
registration_options = generate_registration_options(
    rp_id="bank.example.com",
    rp_name="Example Bank",
    user_id=user.id_bytes,
    user_name=user.email,
    user_display_name=user.display_name,
    
    # Require biometric verification (not just presence):
    authenticator_selection=AuthenticatorSelectionCriteria(
        authenticator_attachment=AuthenticatorAttachment.PLATFORM,  # or CROSS_PLATFORM
        resident_key=ResidentKeyRequirement.REQUIRED,
        user_verification=UserVerificationRequirement.REQUIRED,  # Biometric mandatory
    ),
    
    # Request attestation for device verification:
    attestation=AttestationConveyancePreference.DIRECT,
    
    # Prevent duplicate registrations:
    exclude_credentials=[
        PublicKeyCredentialDescriptor(id=cred.credential_id)
        for cred in existing_credentials_for_user
    ],
    
    # Narrow timeout:
    timeout=60000,  # 60 seconds max
)

# Verification (security-critical parameters):
verification = verify_registration_response(
    credential=response,
    expected_challenge=stored_challenge,
    expected_rp_id="bank.example.com",
    expected_origin="https://bank.example.com",  # Exact match
    require_user_verification=True,  # UV flag must be set
    
    # For attestation verification (enterprise):
    # supported_pub_key_algs=[COSEAlgorithmIdentifier.ECDSA_SHA_256],  # ES256 only
)

# Post-verification storage:
if verification.verified:
    store_credential(
        user_id=user.id,
        credential_id=verification.credential_id,
        public_key=verification.credential_public_key,
        sign_count=verification.sign_count,  # Store for replay detection
        aaguid=verification.aaguid,
        attestation_type=verification.attestation_type,
        credential_device_type=verification.credential_device_type,  # single_device vs multi_device
        credential_backed_up=verification.credential_backed_up,  # Is it synced?
        registered_at=now(),
    )
```

---

## 10. Interview Questions

### Q1: Explain origin binding in WebAuthn. Why does it fundamentally prevent AiTM phishing attacks, and at what layer is this enforcement happening?

**Why asked:** Tests understanding of the most important WebAuthn security property.

**Answer direction:**

Origin binding works at three layers simultaneously:

**Layer 1 — clientDataJSON:** The browser (trusted platform code, not the page's JavaScript) inserts the current page's origin into `clientDataJSON`. This is set by the browser's WebAuthn platform API implementation, which the page's JavaScript cannot override. The page JS can only call `navigator.credentials.get()` — the browser fills in the origin from the actual page context.

**Layer 2 — The signature:** The authenticator signs over `SHA256(clientDataJSON)`. If the origin in clientDataJSON is a phishing domain, the signature is over the phishing domain's origin. This signature cannot be retroactively changed — ECDSA signatures are unforgeable without the private key.

**Layer 3 — Server validation:** The server explicitly verifies `clientDataJSON.origin == expected_origin` before accepting the assertion. The server knows its own legitimate origin. A phishing origin doesn't match.

For AiTM to succeed: The attacker's phishing proxy would need to produce an assertion where `clientDataJSON.origin == "https://bank.example.com"` while the user is on `https://phishing.com`. This requires:
- Controlling what the browser writes into clientDataJSON (impossible — browser is the trusted party).
- OR forging the signature over a modified clientDataJSON (impossible — requires breaking ECDSA P-256).

This is why WebAuthn is the ONLY credential type that is phishing-resistant by construction, not by policy.

---

### Q2: What is the signCount field in authenticatorData, what security property does it provide, and why does it fail for synced passkeys?

**Why asked:** Tests deep understanding of authenticator state and its limitations.

**Answer direction:**

`signCount` is a monotonically increasing counter that the authenticator increments on each signing operation. The server stores the last-seen value and compares it on each assertion.

**Security property:** If the server receives a `signCount` that is less than or equal to the stored value, it indicates either:
1. The authenticator was physically cloned (which is impossible for TPM/Secure Enclave hardware, but possible if software stores the private key).
2. The response was replayed (but challenge validation should catch this independently).

**Why it fails for synced passkeys:** When a passkey is synced from iPhone to iPad, both devices have the same private key. If the user authenticates from the iPhone (signCount = 5), then later authenticates from the iPad (which may have synCount = 3 from when it last synced the state), the server receives 3 which is less than the stored 5 → clone detection false positive.

Apple and Google's implementation: synced passkeys often report signCount = 0 on every assertion. The WebAuthn spec explicitly allows this (section 6.1: "If the authenticator does not implement a counter, it MUST set the count to 0"). When signCount is 0, servers MUST NOT flag it as a clone — they must accept it.

The consequence: for synced passkeys, clone detection via signCount is not possible. Risk mitigation shifts to: cloud account security (protecting the iCloud/Google account), device enrollment detection, and behavioral anomaly detection (geolocation, new device alerts).

---

### Q3: Walk me through the RPID validation. What happens if a subdomain registers a passkey, and why does this matter for multi-tenant platforms?

**Why asked:** Tests understanding of RPID scoping and multi-tenant security isolation.

**Answer direction:**

The RPID (Relying Party ID) must be an "effective domain" — it must be a suffix match of the current page's origin's host (or equal). Rules:
- If page is `https://login.bank.example.com`: valid RPIDs = `login.bank.example.com`, `bank.example.com`, `example.com` (but NOT `com`).
- The RPID cannot be more specific than the page's host.
- The RPID CANNOT be a different domain entirely.

**Multi-tenant implication:** If a SaaS platform (`saas.com`) hosts customer apps at `tenant-a.saas.com` and `tenant-b.saas.com`:
- If both tenants use RPID `saas.com`: a passkey registered on `tenant-a.saas.com` is usable on `tenant-b.saas.com` (same RPID). This is a cross-tenant access vulnerability.
- Correct design: each tenant gets RPID = `tenant-a.saas.com`, `tenant-b.saas.com` respectively. The authenticator stores passkeys per RPID, so they're isolated.

In authenticatorData, `rpIdHash = SHA256(rpId)`. The authenticator computes this hash from the RPID it received from the platform API (which validates it against the page origin). The server verifies that the `rpIdHash` in the response matches `SHA256` of its own RPID. If the authenticator produced a hash for the wrong RPID, the server would see a mismatch.

---

### Q4: A user authenticates with a passkey, and the server receives an assertion where signCount went from 42 to 41 (decreased). What do you do, and what are the false positive risks?

**Why asked:** Tests operational reasoning about security signals with real-world nuance.

**Answer direction:**

**What the spec says:** The server SHOULD flag this as "SHOULD-level risk" but not necessarily terminate the session. RFC language: "the authenticator may be cloned, i.e., at least two copies of the credential private key may exist."

**Practical options:**
1. **Reject immediately:** Terminate authentication, lock credential, alert user. High security, possible false positive.
2. **Accept with high-risk flag:** Allow the authentication but set a risk flag that triggers step-up on any sensitive operation. Log and alert. Investigate.
3. **Alert and let user decide:** Notify user: "We detected a potential clone of your security key. Was this you?" If user confirms: reset signCount. If user denies: revoke credential.

**False positive scenarios:**
- Hardware key was restored from backup (new unit, old signCount state).
- Some authenticator implementations don't correctly persist signCount across power cycles.
- Clock skew causing replay vs. legitimate use race condition (unlikely with counters).
- YubiKey enterprise batch replacement: new hardware, same credential ID, signCount starts at 0.

**Recommended approach for enterprise:**
1. Log the anomaly with full detail.
2. Allow the authentication but upgrade session risk score to HIGH.
3. Require step-up (re-auth via passkey) before any sensitive operation.
4. Alert the user AND security team.
5. Automatically initiate "which device are you using?" flow.
6. If user confirms they are on a legitimate device: accept and reset stored signCount to max(received, stored). 
7. If anomaly recurs: revoke the credential, require re-enrollment.

---

### Q5: What is the "confused deputy" attack against WebAuthn, and how does the crossOrigin field in clientDataJSON relate to it?

**Why asked:** Tests understanding of iframe-based attacks and WebAuthn's frame context security.

**Answer direction:**

The confused deputy attack in WebAuthn context: an attacker embeds the legitimate bank's login page in an iframe on `attacker.com`. The bank's login page calls `navigator.credentials.get()`. What RPID is used?

The WebAuthn spec requires: the `rpId` must be a "registrable domain suffix of or equal to" the origin of the document calling the API. If the iframe on `attacker.com` contains `bank.example.com`, and `bank.example.com`'s JavaScript calls `navigator.credentials.get({publicKey: {rpId: "bank.example.com"}})`, the browser checks:
- Is the IFRAME's origin (`https://bank.example.com`) a suffix of itself? Yes → allowed.
- BUT: the `crossOrigin` field in `clientDataJSON` is set to `true` if the calling document is in a cross-origin context.

The server MUST check `clientDataJSON.crossOrigin`. If `crossOrigin: true` and the server doesn't expect cross-origin usage → reject. This prevents the iframe embedding attack.

Additionally: modern browsers block WebAuthn from iframes unless the frame has `allow="publickey-credentials-get"` permission policy. The top-level document (attacker.com) would need to add this to the iframe tag — which a legitimate attacker page wouldn't do (it would alert the user).

---

### Q6: Compare the security model of a platform passkey vs a FIDO2 hardware key for an enterprise deploying to 10,000 employees. What are the key threat model differences?

**Why asked:** Tests ability to make architectural recommendations with concrete security reasoning.

**Answer direction:**

| Threat | Platform Passkey | Hardware FIDO2 Key |
|---|---|---|
| Private key extraction | Impossible (Secure Enclave) | Impossible (hardware) |
| Key cloning | Possible (synced to cloud) | Impossible (device-bound) |
| Cloud account compromise | Catastrophic (exposes passkeys) | No impact |
| Device theft | Protected by biometric | Protected by PIN (and physical possession) |
| Lost device | Use synced copy on another device | Keys are gone; need replacement |
| Roaming authentication | iPhone/iPad, same ecosystem | Any platform with USB/NFC/BLE |
| Cross-platform | Limited (ecosystem-bound) | Universal |
| Initial cost | Zero (phone already exists) | $30-50 per key × 2 employees |
| Distribution complexity | None (employee uses own phone) | Logistics, shipping, replacement |
| Attestation | Vendor-specific (Apple, Google) | Strong (FIDO certified hardware) |
| Audit trail | Limited (Apple controls) | Full control (server-side) |

**Recommendation:** 

For 10,000 employees with a mixed threat model:
- Tier 1 (executives, engineers, finance): Hardware keys (YubiKey 5 series) — provide 2 each, one as backup. Zero syncing, maximum assurance. Justifies the cost ($100/employee) for accounts that are high-value targets.
- Tier 2 (general employees): Platform passkeys (platform attachment) — sync enabled, backed by corporate identity provider (Okta, Azure AD). Require iCloud/Google account to be linked to corporate SSO (so cloud account is also corporate-controlled).
- Shared devices (call center, retail): Hardware keys stored in a secure location at the physical site. PIN-protected, checked out and returned. No sync possible.

The critical insight: for enterprises, the cloud account security is as important as the passkey security for synced passkeys. Corporate control of the iCloud/Google account used for sync = corporate control of the passkey.

---

*Document Version: 1.0 | Last Updated: May 2026 | Classification: Internal Engineering*  
*Key References: W3C WebAuthn Level 3 Specification (w3.org/TR/webauthn-3/), FIDO Alliance CTAP2 Specification, NIST SP 800-63B Digital Identity Guidelines, CISA "Implementing Phishing-Resistant MFA" (2022), Apple Platform Security Guide, Google Security Blog: "Passkeys."*