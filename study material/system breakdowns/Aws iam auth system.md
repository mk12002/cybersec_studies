# AWS IAM Authentication & Authorization Flow — Engineering & Security Breakdown

**Classification:** Internal Engineering Reference  
**Audience:** Engineers, Security Analysts, Cloud Architects  
**Assumed Reader:** Will be interviewed on this system. Every claim here is defensible and mechanically precise.

---

## Table of Contents

1. [User Journey (Narrative)](#1-user-journey-narrative)
2. [Network Layer Flow](#2-network-layer-flow)
3. [Application Layer Flow](#3-application-layer-flow)
4. [Backend Architecture](#4-backend-architecture)
5. [Authentication & Authorization Flow](#5-authentication--authorization-flow)
6. [Data Flow](#6-data-flow)
7. [Security Controls](#7-security-controls)
8. [Attack Surface Mapping](#8-attack-surface-mapping)
9. [Attack Scenarios](#9-attack-scenarios)
10. [Failure Points](#10-failure-points)
11. [Mitigations](#11-mitigations)
12. [Observability](#12-observability)
13. [Scaling Considerations](#13-scaling-considerations)
14. [Interview Questions](#14-interview-questions)

---

## 1. User Journey (Narrative)

### The Setup: Three Distinct Personas, One System

AWS IAM covers three fundamentally different auth scenarios that share underlying infrastructure but differ in credential type, trust chain, and attack surface. All three are covered in this document:

1. **Human user (IAM User):** A developer authenticates to the AWS Console or CLI using long-term credentials (access key + secret key, or username + password + MFA).
2. **Machine identity (IAM Role):** An EC2 instance, Lambda function, or ECS task assumes a role and receives short-lived credentials via the Instance Metadata Service (IMDS).
3. **Federated identity (IAM Identity Center / AssumeRoleWithWebIdentity):** A corporate SSO user authenticates through an external Identity Provider (Okta, Azure AD) and exchanges a SAML assertion or OIDC token for temporary AWS credentials.

### Persona 1: Developer CLI Authentication (IAM User)

**T=0ms — Developer runs a CLI command**

```
$ aws s3 ls s3://my-bucket
```

The AWS CLI reads credentials from the credential chain in strict priority order:
1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`)
2. AWS CLI config file (`~/.aws/credentials`)
3. AWS SSO token cache
4. Container credentials (ECS task role via `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`)
5. Instance metadata (IMDS at 169.254.169.254)

If `~/.aws/credentials` contains:
```ini
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

The CLI uses these. These are **long-term credentials** — they never expire unless explicitly rotated or deactivated.

**T=0–50ms — Request Construction and Signing**

The CLI does not simply forward the access key. Instead, it performs **AWS Signature Version 4 (SigV4)** signing — a HMAC-SHA256-based signing protocol. The signature process:

1. **Create a canonical request** — a normalized, deterministic string representing the request:
```
GET
/
list-type=2
host:s3.amazonaws.com
x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
x-amz-date:20250515T102345Z

host;x-amz-content-sha256;x-amz-date
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

2. **Create a string-to-sign:**
```
AWS4-HMAC-SHA256
20250515T102345Z
20250515/us-east-1/s3/aws4_request
[SHA256 hash of canonical request]
```

3. **Derive the signing key** (key derivation chain):
```
kSecret  = "AWS4" + secret_access_key
kDate    = HMAC-SHA256(kSecret, "20250515")
kRegion  = HMAC-SHA256(kDate, "us-east-1")
kService = HMAC-SHA256(kRegion, "s3")
kSigning = HMAC-SHA256(kService, "aws4_request")
```

4. **Compute the signature:**
```
signature = HMAC-SHA256(kSigning, string_to_sign)
```

5. **Add Authorization header:**
```
Authorization: AWS4-HMAC-SHA256
  Credential=AKIAIOSFODNN7EXAMPLE/20250515/us-east-1/s3/aws4_request,
  SignedHeaders=host;x-amz-content-sha256;x-amz-date,
  Signature=<hex signature>
```

**What this achieves:** SigV4 binds the request to: the specific credentials, the date, the region, the service, and the exact request content. A replay attack with the same signature on a different day, different region, or modified request body will fail. The signature window is 15 minutes from the `x-amz-date` timestamp.

**T=50ms — DNS and Network**

The CLI resolves `s3.amazonaws.com` → IP address, establishes a TLS connection, and sends the signed HTTP request. AWS receives it at the S3 service endpoint.

**T=60ms — IAM Authorization**

Every AWS API call — regardless of which service receives it — goes through IAM authorization. S3 receives the request and makes an internal call to IAM to validate the credentials and authorize the action. This is invisible to the caller.

IAM does the following in a single synchronous evaluation:
1. Authenticates the identity (validates the SigV4 signature using the secret stored in IAM's credential database).
2. Identifies the principal: `arn:aws:iam::123456789012:user/developer`.
3. Evaluates all applicable policies (identity-based, resource-based, SCPs, permission boundaries, session policies).
4. Returns Allow or Deny.

**T=70ms — Response**

If authorized: S3 returns the bucket listing. The developer sees the list of objects. Total wall clock time: 200–500ms (mostly network).

**What the developer sees vs what actually happened:**

| Developer sees | Reality |
|---|---|
| "It listed my bucket" | SigV4 computed, IAM evaluated 6+ policy types, CloudTrail logged the event |
| "It said AccessDenied" | IAM evaluated policies, explicit deny or no allow found, S3 returned 403 |
| "It failed with InvalidClientTokenId" | Access key doesn't exist in IAM (deleted, wrong region, typo) |
| "It failed with SignatureDoesNotMatch" | Secret key wrong, clock skew > 15 min, body was modified in transit |

---

### Persona 2: EC2 Instance Role (Assumed via IMDS)

**T=0 — Application code running on EC2 runs an AWS SDK call**

```python
import boto3
s3 = boto3.client('s3')
s3.list_objects_v2(Bucket='my-bucket')
```

The SDK looks up the credential chain. It finds no env vars, no config file. It falls through to **IMDS**.

**T=1ms — IMDS Request (Inside the Instance)**

The SDK makes an HTTP GET to `http://169.254.169.254/latest/meta-data/iam/security-credentials/`. This is a **link-local address** — routable only within the EC2 instance, not from outside. The EC2 hypervisor intercepts this traffic and routes it to the IMDS service.

For IMDSv2 (required in secure configurations), the SDK first gets a session token:
```
PUT http://169.254.169.254/latest/api/token
Headers: X-aws-ec2-metadata-token-ttl-seconds: 21600
Response: AQAAAOj...TOKEN...
```

Then uses the token to get credentials:
```
GET http://169.254.169.254/latest/meta-data/iam/security-credentials/my-ec2-role
Headers: X-aws-ec2-metadata-token: AQAAAOj...TOKEN...
```

Response:
```json
{
  "Code": "Success",
  "LastUpdated": "2025-05-15T09:00:00Z",
  "Type": "AWS-HMAC",
  "AccessKeyId": "ASIAIOSFODNN7EXAMPLE",
  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "Token": "AQoDYXdzEJr...<session_token>...",
  "Expiration": "2025-05-15T15:00:00Z"
}
```

Note the `AccessKeyId` begins with `ASIA` (not `AKIA`). This is the prefix for **temporary credentials** (STS-issued), as opposed to `AKIA` (long-term IAM user credentials).

**T=2ms — SDK Caches Credentials**

The SDK caches these in memory. It monitors the `Expiration` field and proactively refreshes ~5 minutes before expiry. This is automatic — application code doesn't manage this.

**T=3ms — Request is Signed and Sent**

Same SigV4 process as above, but includes `X-Amz-Security-Token` header (the session token), required for STS-issued temporary credentials.

---

### Persona 3: Federated Identity (OIDC / AssumeRoleWithWebIdentity)

**Used by:** EKS pods (IRSA), GitHub Actions, external workloads.

**T=0 — Kubernetes pod starts**

The pod has a projected ServiceAccount token mounted at `/var/run/secrets/eks.amazonaws.com/serviceaccount/token`. This is a signed OIDC JWT issued by the EKS cluster's OIDC provider.

**T=1ms — SDK reads the OIDC token**

Environment variable `AWS_WEB_IDENTITY_TOKEN_FILE` points to the token file. The SDK reads it.

**T=2ms — AssumeRoleWithWebIdentity API call**

```
POST https://sts.amazonaws.com/
Action=AssumeRoleWithWebIdentity
&RoleArn=arn:aws:iam::123456789012:role/my-pod-role
&RoleSessionName=my-pod-session
&WebIdentityToken=eyJhbGci...  (the OIDC JWT)
&DurationSeconds=3600
```

**STS receives this, validates the OIDC token:**
1. Fetches the OIDC provider's public keys from the JWKS endpoint (e.g., `https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE/.well-known/openid-configuration`).
2. Verifies the JWT signature.
3. Checks `iss` (issuer), `aud` (audience must be `sts.amazonaws.com`), `exp`.
4. Extracts the subject (`sub` = `system:serviceaccount:default:my-sa`).
5. Checks that an IAM OIDC Identity Provider is configured in the account for this issuer.
6. Checks the role's trust policy allows this identity to assume it:

```json
{
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE"},
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE:sub": "system:serviceaccount:default:my-sa",
        "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE:aud": "sts.amazonaws.com"
      }
    }
  }]
}
```

**T=50ms — STS returns temporary credentials**

```json
{
  "Credentials": {
    "AccessKeyId": "ASIAEXAMPLE",
    "SecretAccessKey": "...",
    "SessionToken": "...",
    "Expiration": "2025-05-15T11:00:00Z"
  },
  "AssumedRoleUser": {
    "AssumedRoleId": "AROAEXAMPLE:my-pod-session",
    "Arn": "arn:aws:sts::123456789012:assumed-role/my-pod-role/my-pod-session"
  }
}
```

The pod now has temporary credentials scoped to the role's permissions. The OIDC token (which proves Kubernetes identity) has been exchanged for AWS credentials.

---

## 2. Network Layer Flow

### DNS Resolution for AWS Endpoints

```
Developer machine / EC2 instance
       |
       | (1) Resolve: sts.amazonaws.com
       |     or: s3.us-east-1.amazonaws.com
       |     or: iam.amazonaws.com
       v
OS Stub Resolver (/etc/resolv.conf → usually VPC DNS at x.x.x.2)
       |
       | (2) Query VPC DNS (Route 53 Resolver)
       |     Route 53 Resolver checks cache
       |     On miss: recursive resolution to Route 53 authoritative NS
       v
Route 53 Authoritative Nameserver (for amazonaws.com zone)
       |
       | Returns:
       |   sts.amazonaws.com → A records (multiple IPs, anycast/GeoDNS)
       |   s3.us-east-1.amazonaws.com → multiple A records (S3 fleet)
       |   iam.amazonaws.com → A records (global IAM endpoint)
       v
VPC DNS cache (TTL typically 5–60s for AWS endpoints)
       |
       v
SDK / CLI connects to resolved IP on port 443

Special cases:
  - VPC Endpoints: sts.amazonaws.com resolves to PRIVATE IP (10.x.x.x) if
    interface VPC endpoint for STS is configured. Traffic stays in VPC —
    never traverses internet. Route 53 Private Hosted Zone overrides the
    public DNS resolution inside the VPC.

  - IMDS (169.254.169.254): NOT resolved via DNS. Link-local.
    The hypervisor intercepts packets destined to this IP at the
    network layer. No DNS involved. No route outside the host.
```

**VPC DNS Resolver (169.254.169.253 or x.x.x.2):** Every VPC has a Route 53 Resolver at the second IP of the VPC CIDR (e.g., 10.0.0.2 for a 10.0.0.0/16 VPC). All DNS queries from instances in the VPC go here by default. This resolver handles both:
- AWS-internal hostnames (resolves to internal IPs for services in the same region).
- Public DNS (forwards to Route 53 public resolvers).

**Split-horizon DNS for VPC Endpoints:** When you create an interface VPC endpoint for STS, AWS automatically creates a private hosted zone that overrides `sts.amazonaws.com` inside the VPC. Instances resolve `sts.amazonaws.com` to a private ENI IP in your VPC. Traffic never leaves AWS network. Packet never reaches the internet.

### TCP Handshake to AWS Endpoints

AWS service endpoints (STS, S3, IAM) are behind AWS's global Anycast load balancing. The IP returned by DNS is a frontend in the AWS network — traffic is routed via BGP Anycast to the nearest AWS POP, then internally to the regional service endpoint.

```
Client (10.0.1.5)                    AWS STS Endpoint (52.x.x.x)
     |                                          |
     |  SYN (seq=X, sport=54321, dport=443)    |
     |---------------------------------------->|
     |                                          |
     |  SYN-ACK (seq=Y, ack=X+1)              |
     |<----------------------------------------|
     |                                          |
     |  ACK (ack=Y+1)                          |
     |---------------------------------------->|
     |                                          |
     | [TCP established — ~10-40ms to nearest]  |

Failure modes at this layer:
  - SYN timeout: Security group blocks outbound 443 (misconfigured SG)
  - RST received: NACL blocking TCP to endpoint
  - VPC endpoint not configured: traffic attempted over internet from
    private subnet with no NAT → blackholed
  - Route table misconfiguration: no route to internet or VPC endpoint
```

**AWS SDK retry behavior:** The SDK implements exponential backoff with jitter for connection failures. Default: 3 retries. For transient TCP failures: immediate retry. For throttling (429): exponential backoff starting at 1s, max 20s, with ±25% jitter.

### TLS Handshake to AWS Endpoints

AWS endpoints use certificates issued by Amazon Trust Services (ATS) — Amazon's own CA hierarchy. The root CAs (`Amazon Root CA 1` through `Amazon Root CA 4`) are embedded in the AWS SDK's CA bundle and the OS trust store.

```
Client                                    AWS STS (52.x.x.x:443)
  |                                                |
  | ClientHello:                                   |
  |   TLS 1.3                                      |
  |   Supported ciphers:                           |
  |     TLS_AES_256_GCM_SHA384                     |
  |     TLS_CHACHA20_POLY1305_SHA256               |
  |     TLS_AES_128_GCM_SHA256                     |
  |   Key share: X25519 ephemeral public key       |
  |   SNI: sts.amazonaws.com                       |
  |----------------------------------------------->|
  |                                                |
  | ServerHello + Certificate + CertVerify + Fin:  |
  |   Chosen: TLS_AES_256_GCM_SHA384               |
  |   Certificate chain:                           |
  |     sts.amazonaws.com (leaf)                   |
  |       ↑ signed by: Amazon RSA 2048 M02 (intermediate) |
  |         ↑ signed by: Amazon Root CA 1 (root)   |
  |   Signature over transcript using ECDSA        |
  |<-----------------------------------------------|
  |                                                |
  | [Derive session keys via ECDHE X25519]         |
  | [HKDF-expand into client_write_key,            |
  |  server_write_key, IVs]                        |
  |                                                |
  | Finished (encrypted)                           |
  |----------------------------------------------->|
  |                                                |
  | [Encrypted application data]                   |
  | POST / HTTP/1.1                                |
  | Host: sts.amazonaws.com                        |
  | Authorization: AWS4-HMAC-SHA256 ...            |
  |----------------------------------------------->|
```

**AWS SDK certificate validation:** The SDK uses a bundled CA cert store (not the OS trust store by default in some SDK versions). This is intentional — AWS controls which CAs are trusted for their endpoints. If you bring a custom HTTP client, ensure it trusts the Amazon Root CA bundle.

**TLS mutual authentication (mTLS):** Standard AWS API calls do not require client certificates — authentication is via SigV4, not TLS client certs. Exception: AWS IoT Core uses mTLS with device certificates. AWS PrivateLink (VPC endpoints) can be configured with endpoint policies but not mTLS.

### Where Latency and Failure Occur

| Layer | Failure Mode | Typical Root Cause |
|---|---|---|
| DNS | NXDOMAIN | VPC DNS resolver blocked (SG port 53 blocked) |
| DNS | Slow resolution | DNSSEC validation on custom resolver; external forwarder |
| TCP | Connection timeout | Security group blocks 443 outbound, no NAT gateway |
| TCP | Connection refused | VPC endpoint policy rejects the request |
| TLS | cert error | Custom proxy intercepts TLS (corporate proxy with root cert not in SDK bundle) |
| TLS | Handshake timeout | TLS inspection appliance delay under load |
| SigV4 | SignatureDoesNotMatch | Clock skew > 15min, proxy modifying headers, wrong secret key |
| IAM | ThrottlingException | Too many IAM API calls per second (IAM is rate-limited globally per account) |
| STS | RequestExpired | Clock drift > 15 minutes between client and AWS |

---

## 3. Application Layer Flow

### HTTP Request Structure for AWS APIs

AWS APIs are primarily **REST over HTTPS** or **Query protocol over HTTPS** (older services like STS, IAM, SQS use query protocol). Understanding both is essential.

**Query Protocol (STS, IAM, SQS):**

```
POST https://sts.amazonaws.com/ HTTP/1.1
Host: sts.amazonaws.com
Content-Type: application/x-www-form-urlencoded; charset=utf-8
X-Amz-Date: 20250515T102345Z
X-Amz-Security-Token: AQoDYXdz... (only for temp credentials)
Authorization: AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/20250515/us-east-1/sts/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=abc123...
Content-Length: 189

Action=AssumeRole
&Version=2011-06-15
&RoleArn=arn%3Aaws%3Aiam%3A%3A123456789012%3Arole%2FMyRole
&RoleSessionName=my-session
&DurationSeconds=3600
```

**Key points about Query protocol:**
- Body is `application/x-www-form-urlencoded` (not JSON).
- `Action` parameter selects the API operation.
- `Version` specifies the API version (frozen — IAM API version is 2010-05-08, STS is 2011-06-15).
- All parameters are URL-encoded in the body.
- The body hash (`x-amz-content-sha256`) is included in the canonical request. Any modification to the body changes the hash, invalidates the signature.

**REST Protocol (S3, EC2, newer services):**

```
GET /my-bucket?list-type=2&prefix=logs%2F HTTP/1.1
Host: s3.us-east-1.amazonaws.com
X-Amz-Date: 20250515T102345Z
X-Amz-Content-SHA256: e3b0c44298fc1c149afbf4c8996fb924...  (SHA256 of empty body)
Authorization: AWS4-HMAC-SHA256 ...

[No body for GET]
```

**JSON/REST Protocol (newer services — DynamoDB, Lambda, etc.):**

```
POST https://lambda.us-east-1.amazonaws.com/2015-03-31/functions/my-function/invocations HTTP/1.1
Host: lambda.us-east-1.amazonaws.com
Content-Type: application/json
X-Amz-Invocation-Type: RequestResponse
X-Amz-Date: 20250515T102345Z
X-Amz-Content-SHA256: b94f6f125c79e3a5ffaa826f584c10d52501c01000000...
Authorization: AWS4-HMAC-SHA256 ...

{"key": "value"}
```

### Response Construction

**Successful response (S3 ListObjectsV2):**
```
HTTP/1.1 200 OK
x-amz-request-id: EXAMPLE123456789
x-amz-id-2: EXAMPLE+ID+FOR+DEBUG
Content-Type: application/xml
Date: Wed, 15 May 2025 10:23:45 GMT
Server: AmazonS3

<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>my-bucket</Name>
  <Prefix/>
  <KeyCount>2</KeyCount>
  ...
</ListBucketResult>
```

**Access denied response:**
```
HTTP/1.1 403 Forbidden
x-amz-request-id: EXAMPLEREQID
x-amz-id-2: EXAMPLEID2

<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>AccessDenied</Code>
  <Message>Access Denied</Message>
  <RequestId>EXAMPLEREQID</RequestId>
  <HostId>EXAMPLEHOSTID</HostId>
</Error>
```

**Critical observation:** AWS AccessDenied responses are intentionally vague. The response does not tell you WHY access was denied (which policy, which condition failed). This is deliberate — leaking policy details would help attackers enumerate your permission structure. The full denial reason is only visible in **CloudTrail logs** and **IAM policy simulator**.

**IAM-specific error codes:**

| Error | HTTP Code | Meaning |
|---|---|---|
| `InvalidClientTokenId` | 403 | Access key doesn't exist |
| `SignatureDoesNotMatch` | 403 | Wrong secret key or clock skew |
| `ExpiredTokenException` | 400 | STS token expired |
| `AccessDenied` | 403 | Valid identity, but no permission |
| `UnauthorizedOperation` | 403 | EC2-specific access denied |
| `NoCredentialProviders` | Client-side | SDK found no credentials in chain |
| `ThrottlingException` | 400 | IAM API rate limit hit |

### Parameter Parsing and Canonical Request Security

The canonical request construction is security-critical. Two vulnerabilities arise from parser inconsistencies:

**Header injection in signed headers:** If a proxy adds a header that was NOT included in `SignedHeaders`, AWS ignores the added header during validation — the signature remains valid even with the injected header. The injected header could be `X-Forwarded-For` to manipulate IP-based conditions, or custom headers that influence routing.

**URL normalization:** SigV4 requires specific URL normalization (RFC 3986). Path segments are URI-encoded, `/` is preserved. If a proxy normalizes the URL differently (e.g., decodes `%2F` → `/`), the canonical request computed by AWS won't match the one computed by the client. Result: `SignatureDoesNotMatch`. This is why S3 paths with slashes in key names require careful handling.

---

## 4. Backend Architecture

### AWS IAM Architecture (What AWS Runs Internally)

This is what AWS has publicly described and what can be inferred from its behavior:

```
┌─────────────────────────────────────────────────────────────────────┐
│                    AWS SERVICE ENDPOINTS                             │
│                                                                      │
│   IAM (iam.amazonaws.com)     STS (sts.amazonaws.com)              │
│   [Global, us-east-1]         [Global + Regional endpoints]         │
│                                                                      │
│   EC2, S3, Lambda, etc.       [Each service has its own endpoint]   │
│   [Regional endpoints]                                               │
└──────────────────┬─────────────────────┬────────────────────────────┘
                   │                     │
                   ▼                     ▼
┌─────────────────────────────────────────────────────────────────────┐
│                   IAM AUTHORIZATION ENGINE                           │
│                                                                      │
│   Every AWS API call passes through this, co-located with           │
│   each service (not a separate network hop for most services)        │
│                                                                      │
│   Components:                                                        │
│   ┌─────────────────────────────────────────────────────────────┐  │
│   │ 1. CREDENTIAL VALIDATOR                                      │  │
│   │    - Validates SigV4 signature                               │  │
│   │    - Looks up access key → secret key (credential store)     │  │
│   │    - Checks token expiry for temporary credentials           │  │
│   └─────────────────────────────────────────────────────────────┘  │
│   ┌─────────────────────────────────────────────────────────────┐  │
│   │ 2. POLICY EVALUATOR                                          │  │
│   │    - Fetches all applicable policies                          │  │
│   │    - Evaluates in order (SCP → permission boundary →         │  │
│   │      session policy → identity policy → resource policy)     │  │
│   │    - Returns: Allow, Deny, or implicit Deny                  │  │
│   └─────────────────────────────────────────────────────────────┘  │
│   ┌─────────────────────────────────────────────────────────────┐  │
│   │ 3. CONTEXT BUILDER                                           │  │
│   │    - Assembles condition context (IP, MFA, time, tags, etc.) │  │
│   │    - Populates aws:* condition keys                          │  │
│   └─────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    IAM DATA STORE                                    │
│                                                                      │
│   - Users, groups, roles, policies stored in IAM's internal DB      │
│   - Globally replicated (changes propagate with eventual             │
│     consistency — typically <1s but up to minutes in rare cases)    │
│   - Access keys indexed by key ID for fast lookup                   │
│   - Policy documents stored as JSON, parsed at evaluation time      │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                       AWS CLOUDTRAIL                                 │
│                                                                      │
│   Every API call (success or failure) is recorded:                  │
│   - Who made it (principal ARN)                                     │
│   - What they called (action, resource)                             │
│   - From where (IP, user agent)                                     │
│   - When (timestamp)                                                │
│   - Was it authorized? What was the error?                         │
│   - Delivered to S3 within ~15 minutes                             │
│   - Management events vs Data events (separate configuration)       │
└─────────────────────────────────────────────────────────────────────┘
```

### STS (Security Token Service) Internal Architecture

STS is the engine that issues temporary credentials. It operates as:

```
┌─────────────────────────────────────────────────────────────┐
│                    STS SERVICE                               │
│                                                              │
│  API Operations:                                            │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ AssumeRole          - Role assumption (internal)       │ │
│  │ AssumeRoleWithSAML  - Federated (SAML 2.0)             │ │
│  │ AssumeRoleWithWebIdentity - Federated (OIDC)           │ │
│  │ GetSessionToken     - MFA enforcement for IAM users    │ │
│  │ GetFederationToken  - Legacy federation                │ │
│  │ GetCallerIdentity   - "Who am I?" (no auth required    │ │
│  │                        beyond valid credentials)       │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  Credential issuance:                                        │
│  - Generates ephemeral access key (ASIA prefix)             │
│  - Generates ephemeral secret key                           │
│  - Generates session token (opaque, encrypted blob)         │
│  - Session token encodes: role ARN, session name,           │
│    expiry, principal, external ID (if used)                 │
│                                                              │
│  Validation on each subsequent API call:                    │
│  - SigV4 validated against ephemeral key                   │
│  - Session token decrypted, expiry checked                  │
│  - No database lookup per call — token is self-contained    │
│    (like a JWT — the token itself carries the claims)       │
└─────────────────────────────────────────────────────────────┘
```

**Critical insight about STS session tokens:** The session token is an encrypted, self-contained blob. AWS does not need to query a database to validate it on every API call — it decrypts the token using an internal key and reads the embedded claims. This is why STS credentials cannot be revoked mid-session (until the token expires) — there's no central registry to update. The token IS the credential.

**Exception:** AWS does maintain a revocation list for tokens associated with compromised credentials. When you call `iam:UpdateAccessKey` to deactivate a key, subsequent API calls with that key are immediately rejected even if valid STS tokens were issued from it. AWS matches the access key ID embedded in the session token against the revocation list.

### IMDS Architecture (EC2-specific)

```
┌───────────────────────────────────────────────────────────┐
│                  EC2 HYPERVISOR LAYER                     │
│                                                           │
│  ┌─────────────────────┐   ┌─────────────────────────┐  │
│  │  Guest VM (your EC2) │   │  IMDS Service (Nitro)   │  │
│  │                      │   │                         │  │
│  │  App → 169.254.169.254│→ │  Hypervisor intercepts  │  │
│  │  (link-local request) │  │  at network layer       │  │
│  │                      │   │                         │  │
│  │  IMDSv2 PUT/GET flow │   │  Returns instance       │  │
│  │  ↓                   │   │  metadata, credentials  │  │
│  │  Token → GET w/ token │  │  from IAM role attached │  │
│  └─────────────────────┘   │  to the instance        │  │
│                             └─────────────────────────┘  │
│                                         │                 │
│                                         ▼                 │
│                             ┌──────────────────────────┐ │
│                             │  IAM Role Credential      │ │
│                             │  Refresh Service          │ │
│                             │                           │ │
│                             │  Proactively refreshes   │ │
│                             │  credentials ~5min before │ │
│                             │  expiry using AssumeRole  │ │
│                             │  on behalf of instance    │ │
│                             └──────────────────────────┘ │
└───────────────────────────────────────────────────────────┘

IMDSv1 vs IMDSv2:
  IMDSv1: Simple GET to 169.254.169.254 — any process on the instance
          (including SSRF exploit code) can make this request.
  
  IMDSv2: Requires PUT first to get a session token (TTL-limited).
          PUT requires the X-aws-ec2-metadata-token-ttl-seconds header.
          Crucially: PUT response does NOT follow HTTP redirects.
          → SSRF via 301/302 redirect cannot obtain IMDSv2 token.
          → SSRF is blocked if the vulnerable app follows redirects
            (all HTTP clients do by default — the PUT is what breaks it).
```

### Caching in IAM

**IAM policy cache:** When a service evaluates an IAM policy, it may cache the evaluation result for a brief period (seconds). This is an internal AWS optimization. Consequence: if you attach or detach a policy, it takes up to a few seconds to propagate. The AWS documentation states "eventual consistency" but in practice it's sub-second for most policy changes.

**Notable exception — eventual consistency risk:** If you create a new IAM role, attach a policy, and immediately call an API with that role's credentials (within <10 seconds), you may get `AccessDenied` because the policy hasn't propagated. AWS recommends a retry loop with exponential backoff when doing this in automation (CloudFormation handles this internally).

**STS credential caching:** AWS SDKs cache STS credentials in memory and refresh proactively. The SDK checks the expiry time and triggers a refresh when `now > expiry - 5 minutes`. This means credentials are refreshed before they expire — application code never sees an expired credential under normal operation.

---

## 5. Authentication & Authorization Flow

### The Policy Evaluation Logic (Full Detail)

This is the most important section. IAM authorization is a deterministic algorithm. Understanding the exact evaluation order is required to correctly reason about any "why is access denied?" question.

```
┌─────────────────────────────────────────────────────────────────────┐
│              IAM POLICY EVALUATION ORDER                             │
│                                                                      │
│  Input: Principal, Action, Resource, Context (IP, MFA, tags, etc.) │
│                                                                      │
│  STEP 1: EXPLICIT DENY CHECK                                        │
│  ─────────────────────────────                                       │
│  Evaluate ALL policies (identity + resource + SCP + boundary).      │
│  If ANY policy contains an explicit "Effect": "Deny" that matches   │
│  this request → DENY immediately. No further evaluation.            │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────┐      │
│  │  AWS ORGANIZATIONS SCP (Service Control Policy)          │      │
│  │  - Applied to the entire account/OU                      │      │
│  │  - Acts as a MAXIMUM permission boundary                 │      │
│  │  - Even account root cannot exceed SCP limits            │      │
│  │  - NOT a grant — a ceiling                               │      │
│  └──────────────────────────────────────────────────────────┘      │
│                   ↓ (if SCP allows)                                 │
│  ┌──────────────────────────────────────────────────────────┐      │
│  │  RESOURCE-BASED POLICIES                                 │      │
│  │  - S3 bucket policies, KMS key policies, SQS policies   │      │
│  │  - Can grant cross-account access WITHOUT role assumption│      │
│  │  - For same-account access: resource policy + identity  │      │
│  │    policy BOTH evaluated — either allow is sufficient   │      │
│  │  - For cross-account: BOTH resource policy AND identity  │      │
│  │    policy must allow                                     │      │
│  └──────────────────────────────────────────────────────────┘      │
│                   ↓                                                 │
│  ┌──────────────────────────────────────────────────────────┐      │
│  │  IAM PERMISSION BOUNDARY                                 │      │
│  │  - Optional managed policy attached to user/role         │      │
│  │  - Acts as maximum permissions for the principal         │      │
│  │  - Identity policy must ALSO allow — both must           │      │
│  │    independently allow for access                        │      │
│  └──────────────────────────────────────────────────────────┘      │
│                   ↓ (if boundary allows)                           │
│  ┌──────────────────────────────────────────────────────────┐      │
│  │  SESSION POLICIES                                         │      │
│  │  - Passed inline during AssumeRole call                  │      │
│  │  - Further restricts the role's permissions              │      │
│  │  - Cannot grant MORE than role's identity policies       │      │
│  └──────────────────────────────────────────────────────────┘      │
│                   ↓ (if session policy allows)                     │
│  ┌──────────────────────────────────────────────────────────┐      │
│  │  IDENTITY-BASED POLICIES                                 │      │
│  │  - Managed policies (AWS-managed or customer-managed)    │      │
│  │  - Inline policies (embedded in user/role/group)         │      │
│  │  - All policies are evaluated together (union)           │      │
│  └──────────────────────────────────────────────────────────┘      │
│                   ↓                                                 │
│  STEP 2: IMPLICIT DENY                                              │
│  ─────────────────────                                              │
│  If no explicit allow was found in any applicable policy →         │
│  DENY. This is the default. "Deny everything not explicitly         │
│  allowed."                                                          │
│                                                                      │
│  Final answer: ALLOW only if:                                        │
│    - At least one policy has explicit ALLOW                         │
│    - AND no policy has explicit DENY                                │
│    - AND all applicable policy types allow (SCP, boundary, etc.)   │
└─────────────────────────────────────────────────────────────────────┘
```

### Cross-Account Access — Deep Mechanics

This is a frequent source of confusion. The rules differ based on whether the resource has a resource-based policy.

**Scenario: Account A user accessing Account B S3 bucket**

**Without resource-based policy:**
- Account A user needs: `s3:GetObject` allow in their identity policy for the bucket in Account B.
- Account B bucket needs: bucket policy allowing Account A's user or role.
- **Both** must allow. Neither alone is sufficient for cross-account.

**With resource-based policy (same-account):**
- Account A user in Account A accessing Account A's S3 bucket.
- Only the identity policy OR the resource policy needs to allow — not both.
- Explicit deny in either still denies.

**Role assumption cross-account (the standard pattern):**
1. Account B creates a role with a trust policy allowing Account A's principal:
```json
{
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::ACCOUNT_A_ID:root"},
    "Action": "sts:AssumeRole",
    "Condition": {
      "StringEquals": {"sts:ExternalId": "shared-secret-id"}
    }
  }]
}
```
2. Account A user calls `AssumeRole` on Account B's role.
3. Account A user needs `sts:AssumeRole` allow in their identity policy for this role ARN.
4. The resulting temporary credentials have Account B's role permissions — they can now access Account B resources as if they were in Account B.
5. **ExternalId** — the "confused deputy" problem mitigation. Required when a third party assumes your role, to prevent an attacker from tricking the third party into assuming the role with their (attacker's) data.

### MFA Enforcement — Mechanics

**How MFA works in IAM:**

MFA is a condition on policy statements, not an account-wide setting. To enforce MFA, you write a policy condition:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "Bool": {"aws:MultiFactorAuthPresent": "true"},
        "NumericLessThan": {"aws:MultiFactorAuthAge": "3600"}
      }
    },
    {
      "Effect": "Deny",
      "Action": ["iam:*", "sts:*"],
      "Resource": "*",
      "Condition": {
        "BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}
      }
    }
  ]
}
```

The `aws:MultiFactorAuthPresent` condition key is set to `true` in the request context only if the API call was made using credentials obtained via `GetSessionToken` with MFA, or via Console login with MFA completed.

**Important nuance:** For IAM user API calls (long-term access keys), `aws:MultiFactorAuthPresent` is **absent** from the context — not false, but absent. Use `BoolIfExists` rather than `Bool` to handle this correctly:
- `Bool: {aws:MultiFactorAuthPresent: false}` → matches when key is absent OR false. 
- `BoolIfExists: {aws:MultiFactorAuthPresent: false}` → only matches when key exists and is false. Correct for MFA enforcement.

### Token Storage and Rotation in Practice

**Long-term credentials (IAM User):**
- Stored in `~/.aws/credentials` — plaintext. Anyone with filesystem access can read these.
- Rotation: manual. AWS best practice: rotate every 90 days. IAM Access Analyzer surfaces unused credentials.
- **These should almost never be used in production.** Use roles. Long-term keys sitting in config files are a leading cause of credential leakage.

**Temporary credentials (STS):**
- Stored in memory by the SDK. Never persisted to disk in production patterns.
- Maximum duration: 1 hour for role-to-role chains, 12 hours for direct role assumption from console, 36 hours for some federation scenarios.
- **Cannot be rotated mid-session** — you must wait for expiry and then assume the role again.
- **Cannot be revoked** individually — except by deactivating the source access key or the role, which affects ALL sessions from that principal.

**IAM Identity Center (SSO) tokens:**
- Stored in `~/.aws/sso/cache/` — JSON files with OIDC tokens.
- Short-lived (1–8 hours, configurable).
- Refresh via `aws sso login` — triggers a browser-based OAuth 2.0 authorization code flow.

---

## 6. Data Flow

### Credential Chain Resolution (Complete Data Flow)

```
Application Code
    │
    │ Calls: boto3.client('s3') or new S3Client()
    ▼
SDK Credential Provider Chain
    │
    ├─── Check: AWS_ACCESS_KEY_ID env var set?
    │           Yes → use env vars → STOP
    │
    ├─── Check: AWS_CONTAINER_CREDENTIALS_RELATIVE_URI env var set?
    │           Yes → GET http://169.254.170.2/{path} (ECS task role)
    │           Response: {AccessKeyId, SecretAccessKey, Token, Expiration}
    │           → STOP
    │
    ├─── Check: AWS_WEB_IDENTITY_TOKEN_FILE env var set?
    │           Yes → read OIDC token from file
    │           → call STS:AssumeRoleWithWebIdentity
    │           → return STS credentials → STOP
    │
    ├─── Check: ~/.aws/credentials file exists?
    │           Yes → read [profile] stanza
    │           If role_arn present → call STS:AssumeRole
    │           If sso_start_url present → read SSO cache
    │           → return credentials → STOP
    │
    ├─── Check: EC2 IMDS available?
    │           PUT 169.254.169.254/latest/api/token (IMDSv2)
    │           → GET 169.254.169.254/latest/meta-data/iam/security-credentials/
    │           → GET .../security-credentials/{role-name}
    │           → return {AccessKeyId, SecretAccessKey, Token, Expiration}
    │           → STOP
    │
    └─── No credentials found → raise NoCredentialsError
```

### SigV4 Signing — Complete Data Transformation

Every signed request goes through this data transformation pipeline:

```
[Raw Request]
   Method: GET
   URL: https://s3.us-east-1.amazonaws.com/my-bucket?list-type=2
   Headers: Host, Accept, Content-Type
   Body: (empty)
          │
          ▼
[Canonical Request Construction]
   1. HTTPRequestMethod: "GET"
   2. CanonicalURI: "/" (or "/key" for specific object)
   3. CanonicalQueryString: "list-type=2" (sorted, URL-encoded)
   4. CanonicalHeaders: "host:s3.us-east-1.amazonaws.com\nx-amz-date:20250515T102345Z\n"
   5. SignedHeaders: "host;x-amz-date"
   6. HashedPayload: SHA256("") = "e3b0c44298fc1c149afbf4c8996fb924..."
   Concatenated canonical string → SHA256 hash
          │
          ▼
[String to Sign]
   "AWS4-HMAC-SHA256\n"
   + "20250515T102345Z\n"                 (timestamp)
   + "20250515/us-east-1/s3/aws4_request\n"  (credential scope)
   + "<SHA256 of canonical request>"
          │
          ▼
[Signing Key Derivation]
   kSecret  = b"AWS4" + secret_access_key.encode()
   kDate    = HMAC_SHA256(kSecret, "20250515")
   kRegion  = HMAC_SHA256(kDate, "us-east-1")
   kService = HMAC_SHA256(kRegion, "s3")
   kSigning = HMAC_SHA256(kService, "aws4_request")
          │
          ▼
[Signature]
   signature = HMAC_SHA256(kSigning, string_to_sign).hex()
          │
          ▼
[Authorization Header]
   AWS4-HMAC-SHA256
   Credential=AKIAEXAMPLE/20250515/us-east-1/s3/aws4_request,
   SignedHeaders=host;x-amz-date,
   Signature=<hex>
```

**Why the key derivation chain?** Deriving a service/region/date-specific signing key means:
- The same secret key produces different signing keys for different services, regions, and days.
- A signing key for S3 in us-east-1 on 2025-05-15 cannot be used to sign STS calls or calls on 2025-05-16.
- Even if someone extracts the derived signing key from memory, it's valid only for that service/region/date combination and expires at midnight UTC.

### Policy Document Serialization

IAM policies are JSON documents stored internally by AWS. When you attach a managed policy, AWS stores the ARN reference, not the full policy document. At authorization time, AWS fetches and deserializes all applicable policy documents.

Policy evaluation involves:
1. Parse each policy JSON.
2. For each statement, evaluate: Effect, Action (may be wildcards), Resource (may be wildcards), Condition.
3. Condition evaluation: all conditions in a statement must match (AND). Multiple values in a condition are OR-ed. Multiple keys in a condition are AND-ed.

**Condition key data types:**

| Operator Type | Example | Notes |
|---|---|---|
| `StringEquals` | exact string match | Case-sensitive |
| `StringLike` | wildcard match (`*`, `?`) | Use for prefix matching |
| `ArnLike` | ARN wildcard matching | Handles ARN structure |
| `IpAddress` | CIDR range match | `aws:SourceIp` |
| `Bool` | true/false | `aws:MultiFactorAuthPresent` |
| `DateLessThan` | timestamp comparison | Access time windows |
| `NumericLessThan` | integer comparison | `aws:MultiFactorAuthAge` |

**Tag-based conditions (ABAC — Attribute-Based Access Control):**

```json
{
  "Condition": {
    "StringEquals": {
      "aws:ResourceTag/Environment": "${aws:PrincipalTag/Environment}"
    }
  }
}
```

This allows a principal to access only resources where the `Environment` tag matches the principal's own `Environment` tag. The principal tag is evaluated from the principal's tags in IAM — not the request. The resource tag is evaluated from the actual resource's tags.

---

## 7. Security Controls

### Encryption in Transit

All AWS API calls use TLS 1.2 minimum (TLS 1.3 preferred, offered by all AWS endpoints). AWS enforces this — attempts to connect with SSL 3.0, TLS 1.0, or TLS 1.1 are rejected. The AWS SDK enforces TLS by default; plaintext HTTP to AWS APIs is not supported except for IMDS (intentional — link-local only).

**SigV4 as a second layer of protection:** Even if TLS were somehow broken, the SigV4 signature still protects against request tampering. An attacker who intercepts the TLS channel (via a compromised CA or a MITM appliance) could replay requests but could not modify them without invalidating the signature. And replay is limited to the 15-minute window.

### IAM Credential Encryption at Rest

**Access keys:** AWS stores the secret access key as a one-way hash (not reversible). When AWS validates a SigV4 signature, it recomputes the HMAC using the stored key material — it doesn't need to decrypt and compare the raw key. The key is never returned after initial creation. If you lose it, you must create a new one.

**STS session tokens:** Encrypted using an AWS internal key. Opaque to callers. Not stored in an accessible database — the encryption itself is the storage.

**IAM passwords (Console login):** Stored as bcrypt hash with salt. AWS enforces a minimum password policy (configurable: length, complexity, rotation, reuse prevention).

### Input Validation by AWS

**Action validation:** AWS validates that the requested `Action` (e.g., `s3:GetObject`) is a valid action for the service. Unknown actions are rejected before policy evaluation.

**ARN validation:** Resource ARNs are validated for format (`arn:partition:service:region:account-id:resource`). Malformed ARNs are rejected.

**Parameter sanitization:** Query parameters in policy conditions are evaluated server-side; there is no "injection" in the traditional sense because IAM doesn't evaluate policies as code — it evaluates them as data structures.

**Maximum sizes:** Policy document: 6,144 characters (managed) or 2,048 characters (inline). Role name: 64 characters. Session name: 64 characters. Too-large policies are rejected at creation time.

### Secrets Handling

**IAM access keys are not secrets management.** Do not use them for application secrets. For application secrets, use:
- **AWS Secrets Manager:** Versioned, rotatable, KMS-encrypted secret store. Rotation can be automated via Lambda.
- **AWS Systems Manager Parameter Store:** Hierarchical key-value store. SecureString type uses KMS encryption.

**Key ID as a non-secret:** The access key ID (`AKIAEXAMPLE`) is not secret — it appears in CloudTrail logs, in signed requests, and can be derived from the Authorization header by anyone intercepting a request. Only the secret access key is secret. The key ID is just an identifier used to look up the correct secret for verification.

**Secrets in EC2 UserData:** A common mistake. UserData is passed to instances at launch and is visible via IMDS to anyone on the instance. Never put secrets in UserData. Use IAM roles + Secrets Manager instead.

---

## 8. Attack Surface Mapping

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║                    AWS IAM ATTACK SURFACE MAP                                ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  EXTERNAL SURFACE                                                             ║
║                                                                               ║
║  ┌──────────────────────────────────────────────────────────────────────┐   ║
║  │  CREDENTIAL EXPOSURE SURFACE                                          │   ║
║  │                                                                        │   ║
║  │  Entry Points:                                                        │   ║
║  │  • GitHub repos (hardcoded credentials in code)                      │   ║
║  │  • Docker images (ENV vars with keys baked in)                       │   ║
║  │  • EC2 UserData (visible via IMDS and EC2 console)                   │   ║
║  │  • CloudFormation template parameters (if logged)                    │   ║
║  │  • CI/CD pipeline logs (keys printed during build)                   │   ║
║  │  • Public S3 buckets (config files, .env files, .aws/credentials)    │   ║
║  │  • Application error messages (stack traces with env vars)           │   ║
║  │  • Package registries (npm, PyPI) with credentials                   │   ║
║  └──────────────────────────────────────────────────────────────────────┘   ║
║                                                                               ║
║  ┌──────────────────────────────────────────────────────────────────────┐   ║
║  │  API SURFACE (Internet-facing AWS endpoints)                          │   ║
║  │                                                                        │   ║
║  │  • sts.amazonaws.com (AssumeRole, GetCallerIdentity)                 │   ║
║  │  • iam.amazonaws.com (CreateUser, AttachPolicy, etc.)                │   ║
║  │  • *.console.aws.amazon.com (Console login)                          │   ║
║  │  • All service endpoints (S3, EC2, Lambda, etc.)                     │   ║
║  │                                                                        │   ║
║  │  Attack vectors:                                                      │   ║
║  │  • Credential stuffing (stolen key + secret pairs)                   │   ║
║  │  • Brute force (not possible — access keys are random)               │   ║
║  │  • Session token replay (within 15-min window)                       │   ║
║  │  • Malformed request attacks (fuzzing SigV4 parser)                  │   ║
║  └──────────────────────────────────────────────────────────────────────┘   ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  TRUST BOUNDARY: Internet → AWS Control Plane                                ║
║  SigV4 + TLS provides authentication; IAM policies provide authorization     ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  INTERNAL / INSTANCE SURFACE                                                  ║
║                                                                               ║
║  ┌──────────────────────────────────────────────────────────────────────┐   ║
║  │  IMDS (169.254.169.254) — within EC2 instance                        │   ║
║  │                                                                        │   ║
║  │  • Any process on the EC2 instance can call IMDS                     │   ║
║  │  • SSRF vulnerabilities in applications → IMDS credential theft      │   ║
║  │  • Privileged containers (--privileged) can access host IMDS         │   ║
║  │  • IMDSv1 has no SSRF protection (stateless GET requests)            │   ║
║  └──────────────────────────────────────────────────────────────────────┘   ║
║                                                                               ║
║  ┌──────────────────────────────────────────────────────────────────────┐   ║
║  │  ROLE ASSUMPTION CHAIN                                                │   ║
║  │                                                                        │   ║
║  │  • Overpermissive trust policies (who can assume the role)           │   ║
║  │  • Missing ExternalId (confused deputy)                               │   ║
║  │  • Missing session policy (assume-then-do pattern too broad)         │   ║
║  │  • Role chaining depth (max 1-hour sessions for chained roles)       │   ║
║  └──────────────────────────────────────────────────────────────────────┘   ║
║                                                                               ║
║  ┌──────────────────────────────────────────────────────────────────────┐   ║
║  │  POLICY CONFIGURATION SURFACE                                         │   ║
║  │                                                                        │   ║
║  │  • Wildcard actions (Action: "*") — too broad                        │   ║
║  │  • Wildcard resources (Resource: "*") — no resource scoping          │   ║
║  │  • Missing condition keys (no MFA, no IP restriction)                │   ║
║  │  • Public resource policies (S3 bucket policy, KMS key policy)       │   ║
║  │  • Unintended cross-account access in trust policies                 │   ║
║  └──────────────────────────────────────────────────────────────────────┘   ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  TRUST BOUNDARY: Instance Boundary (IMDS is instance-local)                  ║
║  IMDSv2 + token requirement limits SSRF exploitation                         ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  SUPPLY CHAIN / CONTROL PLANE SURFACE                                         ║
║                                                                               ║
║  • IAM Role trust policy modifications (who can assume your roles)           ║
║  • Managed policy modifications (AWS-managed policies are updated by AWS)    ║
║  • OIDC provider configuration (JWKS URL, audiences, issuers)               ║
║  • SCPs (can be loosened by Organizations admin)                             ║
║  • CloudTrail disabling (attacker covers tracks)                             ║
║  • GuardDuty disabling (attacker silences detection)                         ║
╚═══════════════════════════════════════════════════════════════════════════════╝
```

---

## 9. Attack Scenarios

### Scenario 1: SSRF to IMDS Credential Theft (IMDSv1)

**Attacker Assumptions:**
- Target application runs on EC2 with an IAM role attached.
- Application has an SSRF vulnerability (e.g., a URL-fetching feature: `GET /fetch?url=...`).
- IMDSv1 is enabled (unfortunately common in older deployments).
- The EC2 role has overpermissive policies (common).

**Step-by-Step Execution:**

1. Attacker identifies the SSRF endpoint through recon: `GET /api/fetch?url=https://example.com` returns page content.

2. Attacker tests SSRF to internal addresses: `GET /api/fetch?url=http://169.254.169.254/latest/meta-data/`
   - If the application follows the redirect and fetches the URL, it receives EC2 instance metadata.
   - Response: `ami-id`, `instance-id`, `iam/`

3. Attacker escalates: `GET /api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/`
   - Response: `my-ec2-role` (the role name)

4. Attacker fetches credentials: `GET /api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/my-ec2-role`
   - Response (full JSON):
   ```json
   {
     "AccessKeyId": "ASIAEXAMPLE",
     "SecretAccessKey": "SECRET",
     "Token": "LONGSESSIONTOKEN",
     "Expiration": "2025-05-15T15:00:00Z"
   }
   ```

5. Attacker configures AWS CLI with stolen credentials locally:
   ```
   export AWS_ACCESS_KEY_ID=ASIAEXAMPLE
   export AWS_SECRET_ACCESS_KEY=SECRET
   export AWS_SESSION_TOKEN=LONGSESSIONTOKEN
   ```

6. Attacker calls `aws sts get-caller-identity` — confirms they are now acting as the EC2 role.

7. Attacker enumerates permissions: `aws iam list-attached-role-policies`, `aws s3 ls`, `aws ec2 describe-instances`.

8. Attacker exfiltrates data, creates backdoor IAM user (if allowed), or pivots to other accounts via role assumption.

**Where Detection Could Happen:**
- CloudTrail: API calls from the role with a new `sourceIPAddress` (the attacker's IP, not the EC2 instance IP). `GetCallerIdentity` calls from a new IP are a strong signal.
- GuardDuty: `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` — fires when STS-issued credentials for an EC2 role are used from an IP not associated with the instance.
- VPC Flow Logs: Outbound HTTP request to 169.254.169.254 from the application process (visible if the application runs in a container with network monitoring).

**Why This Works:**
- IMDSv1 requires no authentication — any HTTP GET to the link-local address from within the instance works.
- The SSRF vulnerability gives the attacker a primitive to make HTTP requests from within the instance.
- The IAM role's credentials are valid immediately and work from any IP.

**IMDSv2 breaks this at step 2:**
- IMDSv2 requires a PUT request first (to get a session token) with `X-aws-ec2-metadata-token-ttl-seconds` header.
- The PUT response does NOT follow HTTP redirects — this is the key. An SSRF via redirect cannot complete the PUT exchange.
- However: if the SSRF allows arbitrary HTTP methods and headers (not just GET via redirect), IMDSv2 is not a complete protection against SSRF. The PUT must be made directly, not via redirect.

---

### Scenario 2: Privilege Escalation via IAM Misconfigurations

**Attacker Assumptions:**
- Attacker has compromised an IAM user or role with limited permissions.
- The initial access has `iam:CreatePolicyVersion` or `iam:AttachUserPolicy` or several other IAM write permissions.

**The 22 IAM Privilege Escalation Methods (selected examples):**

**Method A — CreatePolicyVersion:**
```bash
# Attacker has iam:CreatePolicyVersion
# They create a new version of an existing managed policy with Admin permissions
aws iam create-policy-version \
  --policy-arn arn:aws:iam::123456789012:policy/LimitedPolicy \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' \
  --set-as-default
# Now LimitedPolicy grants full admin. Anyone with this policy attached is now admin.
```

**Method B — PassRole + EC2:**
```bash
# Attacker has: iam:PassRole + ec2:RunInstances + ec2:DescribeInstances
# They launch an EC2 instance with an admin role attached:
aws ec2 run-instances \
  --image-id ami-12345 \
  --instance-type t2.micro \
  --iam-instance-profile Name=AdminProfile  # The admin role
# Then SSH into the instance, access IMDS, get admin credentials
```

**Method C — Lambda privilege escalation:**
```bash
# Attacker has: iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction
# Creates a Lambda function with an admin role:
aws lambda create-function \
  --function-name escalate \
  --runtime python3.12 \
  --role arn:aws:iam::123456789012:role/AdminRole \
  --handler index.handler \
  --zip-file fileb://escalate.zip
# escalate.zip contains code that calls iam:CreateUser and attaches AdministratorAccess
# Invokes it:
aws lambda invoke --function-name escalate /tmp/out
# Now has a backdoor admin user
```

**Step-by-Step Detection Chain:**

1. `iam:CreatePolicyVersion` call → CloudTrail logs it with the new policy document.
2. `IAMPolicyChange` EventBridge rule fires → sends to SNS → alerts security team.
3. AWS Config rule `iam-policy-no-statements-with-admin-access` evaluates the new policy version → NON_COMPLIANT → triggers Config remediation (e.g., Lambda that reverts the policy version).
4. GuardDuty: `Policy:IAMUser/RootCredentialUsage` or privilege escalation findings (in preview/experimental).

**Why This Works:**
- IAM has many "write" permissions that indirectly grant the ability to escalate.
- Most IAM permission audits focus on `iam:CreateUser` and `iam:AttachPolicy` but miss `iam:PassRole` + `ec2:RunInstances` combinations.
- Automated tools like Pacu, Cloudsplaining, and PMapper enumerate these chains systematically.

---

### Scenario 3: Role Trust Policy Misconfiguration (Confused Deputy / Open Assumption)

**Attacker Assumptions:**
- A cross-account role exists with an overly permissive trust policy.
- The trust policy allows any principal in the account (or uses a wildcard).

**Vulnerable trust policy:**
```json
{
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::VENDOR_ACCOUNT:root"},
    "Action": "sts:AssumeRole"
  }]
}
```

This allows ANY principal in `VENDOR_ACCOUNT` to assume this role — not just the specific vendor service. If the vendor account is breached, or if the vendor has a misconfigured role that allows unintended parties to assume it (confused deputy), the attacker can chain role assumptions.

**Step-by-Step:**

1. Attacker compromises an IAM user in `VENDOR_ACCOUNT` (credential leak, phishing, etc.).
2. Calls `AssumeRole` on the victim account's role:
   ```bash
   aws sts assume-role \
     --role-arn arn:aws:iam::VICTIM_ACCOUNT:role/VendorAccessRole \
     --role-session-name attacker-session
   ```
3. Receives valid temporary credentials for the victim account.
4. Has all permissions the VendorAccessRole grants.

**Missing ExternalId — The Confused Deputy:**

The confused deputy occurs when:
- You give Vendor the role ARN: `arn:aws:iam::YOUR_ACCOUNT:role/VendorRole`.
- Vendor builds a multi-tenant service and uses this ARN when you send data to them.
- Attacker is also a vendor customer. They send Vendor data but reference YOUR role ARN (not theirs).
- Vendor assumes YOUR role (confused into acting as the deputy you didn't authorize) when processing the attacker's data.

**Fix:** ExternalId — a shared secret that must be present in the AssumeRole call. The trust policy requires it:
```json
"Condition": {"StringEquals": {"sts:ExternalId": "unique-secret-per-customer"}}
```

The attacker knows the role ARN but not your ExternalId, so they cannot trigger the assumption.

**Detection:** CloudTrail: `AssumeRole` events with unexpected `userIdentity.arn` (the assuming principal). Alert on role assumptions from principals not matching expected patterns.

---

### Scenario 4: CloudTrail Evasion and Log Tampering

**Attacker Assumptions:**
- Attacker has obtained admin-level IAM credentials.
- Attacker wants to cover their tracks before exfiltrating data.

**Step-by-Step:**

1. Check if CloudTrail is enabled:
   ```bash
   aws cloudtrail describe-trails
   aws cloudtrail get-trail-status --name my-trail
   ```

2. Stop CloudTrail logging:
   ```bash
   aws cloudtrail stop-logging --name my-trail
   # CloudTrail stops recording new events immediately
   # Existing logs in S3 remain, but no new events are logged
   ```

3. Perform malicious actions (data exfiltration, resource creation) — these are NOT logged.

4. Optionally delete existing CloudTrail log files from S3 (if S3 delete is not blocked by Object Lock).

5. Re-enable CloudTrail to avoid detection by monitoring:
   ```bash
   aws cloudtrail start-logging --name my-trail
   ```

**Where Detection Could Happen:**

- **EventBridge rule:** `StopLogging` and `DeleteTrail` API calls trigger an alert immediately. This is a one-liner CloudFormation setup and should be in every account.
- **AWS Config:** `cloud-trail-enabled` rule fires as NON_COMPLIANT the moment CloudTrail is disabled.
- **GuardDuty:** `Stealth:IAMUser/CloudTrailLoggingDisabled` finding fires within minutes.
- **S3 Object Lock:** If the CloudTrail S3 bucket has Object Lock (WORM) enabled, log files cannot be deleted even by the root user for the lock duration. This is the correct defense.
- **AWS Security Hub:** Aggregates findings from Config, GuardDuty, and Access Analyzer. High-severity findings escalate to the security team.

**Why This Works (and doesn't completely):**

Stopping CloudTrail does prevent new events from being logged. But:
- GuardDuty uses its own independent data sources (VPC Flow Logs, DNS logs, S3 data events) and does NOT depend on CloudTrail being active. It continues detecting anomalies.
- The `StopLogging` API call itself is logged by CloudTrail BEFORE it takes effect.
- If CloudTrail is configured to deliver to a separate account (security/audit account) with a bucket policy preventing the source account from deleting logs, the attacker cannot tamper with existing logs even with admin access in the source account.

---

### Scenario 5: STS Token Replay Attack

**Attacker Assumptions:**
- Attacker is positioned to intercept network traffic (rogue internal endpoint, compromised network device, or malicious insider).
- TLS is terminated by a proxy in the corporate network (common in enterprises) — the proxy has a trusted root cert installed on endpoints.

**Step-by-Step:**

1. Attacker operates a TLS inspection proxy (they control the CA cert trusted by enterprise endpoints).
2. Developer's AWS CLI request is intercepted by the proxy. Proxy decrypts TLS, reads the plaintext HTTP request including:
   - `Authorization` header (contains the SigV4 signature)
   - `X-Amz-Date` header
   - `X-Amz-Security-Token` (if using temp credentials)
   - Full request body

3. Attacker captures the complete HTTP request.

4. Attacker replays the exact same request within 15 minutes (the SigV4 window):
   ```bash
   # Attacker sends the exact intercepted request bytes to AWS
   curl -v https://s3.amazonaws.com/my-bucket?list-type=2 \
     -H "Authorization: AWS4-HMAC-SHA256 ..." \
     -H "X-Amz-Date: 20250515T102345Z"
   ```

5. AWS accepts the replay — the signature is still valid (timestamp within 15-min window).

**Limitations of the attack:**
- The attacker can only replay the exact request (same action, same resource, same parameters). They cannot modify it (signature would be invalid).
- Window is 15 minutes — tight for a practical attack.
- S3 GET operations are idempotent — replaying a GET is the same as just doing a GET. No additional damage beyond information disclosure.
- For non-idempotent operations (PUT, DELETE): replaying within 15 minutes is dangerous. AWS does NOT maintain a nonce registry — replayed requests succeed.

**Detection:** Identical `X-Amz-Date` + same signature in CloudTrail from two different source IPs. Unusual for the same signed request to come from two different locations.

**Why SigV4 doesn't fully prevent replay:**
SigV4 binds the request to a 15-minute window, not to a specific TCP connection or session. There is no per-request nonce or sequence number that AWS tracks across calls. This is a design choice for scalability — maintaining a nonce registry for billions of API calls is infeasible.

---

### Scenario 6: Credential Exfiltration via Public S3 Bucket

**This is the most common real-world credential compromise vector.**

**Attacker Assumptions:**
- The target has a public S3 bucket (misconfigured, or intentionally public for some assets but mixed with private files).
- Developers committed `.env` files, `~/.aws/credentials` exports, or terraform state files with credentials to a repository backed by S3.

**Step-by-Step:**

1. Attacker uses automated scanning tools (e.g., `truffleHog`, `git-secrets`, `Gitleaks`, or custom scrapers for S3 bucket indexes) to scan public S3 buckets for credential patterns.

2. Pattern matched in a terraform state file (`terraform.tfstate` stored in a public bucket):
   ```json
   {
     "outputs": {
       "access_key_id": {"value": "AKIAEXAMPLE"},
       "secret_access_key": {"value": "SECRETEXAMPLE"}
     }
   }
   ```

3. Attacker calls `aws sts get-caller-identity` with the found credentials:
   - If it responds: credentials are valid.
   - Error `InvalidClientTokenId`: key has been rotated or deactivated.

4. Attacker notes the account ID and user ARN from `get-caller-identity`.

5. Enumerates permissions using low-noise techniques (avoid IAM read calls that are monitored):
   - Try specific actions rather than `iam:ListPolicies` (which creates a large CloudTrail event).
   - Use `--dry-run` for EC2 operations (tests permission without executing).
   - Use `aws s3 ls` (List all buckets) — broad but quick.

6. Identifies high-value targets (data buckets, RDS snapshots, Lambda functions with embedded secrets).

7. Exfiltrates data, establishes persistence (creates a new IAM user or role with admin access), and goes quiet.

**Detection:**
- GitHub secret scanning (GitHub automatically scans all public repos for AWS key patterns and notifies AWS, which deactivates the key within minutes for `AKIA`-prefixed keys in public repos).
- GuardDuty: `UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B` or anomalous API calls from new IPs.
- CloudTrail Insights: unusual API call volume from the compromised principal.
- AWS Access Analyzer: flags publicly accessible resources.

---

## 10. Failure Points

### Under Load

**IAM throttling:** IAM API calls are rate-limited per AWS account. The limits are:
- `GetUser`, `GetRole`: 30 TPS
- `ListPolicies`: 20 TPS
- `SimulatePrincipalPolicy`: 1 TPS

In large organizations doing automated provisioning (Terraform running in parallel across many pipelines), IAM throttling is a common failure. Symptoms: `ThrottlingException` in CloudTrail, pipeline failures, inconsistent deployments.

**STS throttling:** `AssumeRole` is throttled at the account level. In a Kubernetes cluster with many pods assuming roles simultaneously (e.g., during a cluster restart), STS can be overwhelmed. The fix: SDK retry with exponential backoff + jitter, and spread role assumption timing (not all pods starting simultaneously).

**IAM eventual consistency under fast automation:**
Race condition in automated role creation:
```bash
aws iam create-role --role-name my-role --assume-role-policy-document ...
aws iam attach-role-policy --role-name my-role --policy-arn ...
aws iam get-role --role-name my-role  # Exists
# Immediately:
aws sts assume-role --role-arn ... # May fail with "Role does not exist" for ~10 seconds
```
This is not a bug — it's IAM's global replication latency. Fix: Add a retry loop or a 10-second sleep in automation.

**IMDS under heavy load:**
In large EC2 instances with many containers, IMDS can be a bottleneck if containers are all requesting credentials simultaneously. IMDSv2 token requests are also rate-limited per instance (1,000 simultaneous connections max). Fix: SDK caching (SDKs cache credentials in memory — don't call IMDS on every API call).

### Under Attack

**Credential stuffing against the Console:** The `signin.aws.amazon.com` endpoint accepts username/password + optional MFA. No native CAPTCHA in the IAM console login flow (though AWS does implement rate limiting and bot detection internally). Attackers with a list of account IDs and IAM user credentials can attempt console logins.

**API call flooding (making the account reach limits):** An attacker with limited IAM credentials can make API calls that consume account-level quotas (S3 ListBuckets, EC2 DescribeInstances), degrading availability for legitimate operations. This is a denial of service within the account.

**GuardDuty suppression rules abuse:** If an attacker gains access to the security account and can modify GuardDuty suppression rules, they can silence findings for the compromised account. Fix: GuardDuty delegated administrator in a separate security account with limited access from source accounts.

### Common Misconfigurations

| Misconfiguration | Impact | Detection |
|---|---|---|
| `AdministratorAccess` attached to application roles | Full account takeover if role is compromised | IAM Access Analyzer, AWS Config |
| IMDSv1 enabled | SSRF → credential theft | EC2 console shows IMDSv1 "Optional" — should be "Required" (v2 only) |
| No SCP in Organizations | No guardrails on account actions | AWS Config `organizations-policy-attached` |
| CloudTrail not logging data events | S3 object access not recorded | AWS Config `cloudtrail-s3-dataevents-enabled` |
| No MFA on IAM users | Single factor compromise = full access | IAM credential report, `mfa-enabled-for-iam-console-access` Config rule |
| Wildcard resource in policies | Allows access to all resources, not just intended ones | IAM Access Analyzer, Cloudsplaining |
| Long-term access keys in production | Key leak = persistent access | IAM credential report, `access-keys-rotated` Config rule |
| Trust policy with `"AWS": "*"` | Allows any AWS principal to assume the role | IAM Access Analyzer external access findings |
| No permission boundaries on delegated admin | Admin of sub-account can create admin roles | Policy analysis, manual review |
| CloudTrail S3 bucket without Object Lock | Attacker can delete evidence | S3 console, Config rule |
| Resource policy with `"Principal": "*"` | Anyone can access (public access) | IAM Access Analyzer, S3 Block Public Access |

---

## 11. Mitigations

### Defense-in-Depth Strategy for IAM

**Layer 1 — Identity Hygiene**

- **No long-term access keys for human users:** Use IAM Identity Center (SSO) with short-lived credentials. Humans should never have long-term `AKIA` keys. Enforce this with an SCP:
```json
{
  "Statement": [{
    "Effect": "Deny",
    "Action": "iam:CreateAccessKey",
    "Resource": "*",
    "Condition": {
      "StringNotEquals": {"aws:PrincipalType": "Service"}
    }
  }]
}
```

- **MFA everywhere for console access:** Hardware MFA (YubiKey) for root and privileged users. Virtual MFA (TOTP) minimum for all IAM users.

- **Root account lockdown:** No access keys on root. MFA on root. SCP that prevents any root access except through break-glass procedures. Root credentials stored in a physical safe.

**Layer 2 — Role Design**

- **Least privilege, verified:** Use IAM Access Analyzer to generate least-privilege policies from CloudTrail activity (access-based policy generation).
- **Session duration limits:** Short-lived role sessions for sensitive operations (1 hour max). 
- **Permission boundaries on all delegated roles:** When creating roles in sub-accounts, always attach a permission boundary that caps maximum permissions.
- **Condition keys in all policies:** IP restriction, MFA requirement, time-based access, resource tag matching.

Example — enforcing VPC-only access for an S3 role:
```json
{
  "Statement": [{
    "Effect": "Deny",
    "Action": "s3:*",
    "Resource": "*",
    "Condition": {
      "StringNotEquals": {
        "aws:SourceVpc": "vpc-1234567890abcdef0"
      }
    }
  }]
}
```

**Layer 3 — Detection**

- **GuardDuty:** Enable in every account and every region. It's the most effective single control for detecting compromised credentials. Enable S3 Protection, EKS Protection, Lambda Protection add-ons.
- **IAM Access Analyzer:** Enable for every account. Enables detection of external access (resources accessible outside your account or organization).
- **CloudTrail + EventBridge alerts** for:
  - `StopLogging`, `DeleteTrail`
  - `CreateUser`, `AttachUserPolicy`, `CreateAccessKey`
  - `AssumeRole` from unusual principals or IPs
  - `GetCallerIdentity` (attacker fingerprinting)
  - Root account usage (any API call as root)
  - `AuthorizeSecurityGroupIngress` (opening firewall)

**Layer 4 — Blast Radius Limitation**

- **AWS Organizations + SCPs:** Define the maximum possible permissions in each OU. Even if a role is compromised, the SCP prevents the attacker from doing things outside the SCP boundary.
- **Separate accounts per environment:** Dev/staging/prod in separate accounts. Compromise of dev doesn't affect prod.
- **VPC Endpoints with endpoint policies:** Restrict which roles/users can use the VPC endpoint. Force all traffic through VPC endpoints (prevents exfiltration over internet).
- **S3 Block Public Access (account level):** Prevents any bucket or object from being made public, regardless of bucket policy.

**Engineering Tradeoffs:**

| Control | Security Gain | Cost / Tradeoff |
|---|---|---|
| No long-term access keys | Eliminates most static credential leaks | Requires SSO setup, more complex onboarding |
| IMDSv2 required | Blocks SSRF credential theft | Old SDKs (pre-2019) don't support IMDSv2 → need SDK update |
| Short session durations (1hr) | Limits window of compromised creds | More frequent STS calls, more latency for long jobs |
| SCP deny on region lockdown | Prevents resource creation in unmonitored regions | May break legitimate use cases in those regions |
| VPC Endpoints for all services | Keeps traffic off internet | Per-endpoint cost, DNS configuration complexity |
| Permission boundaries everywhere | Limits privilege escalation | Adds policy management overhead |
| Object Lock on CloudTrail bucket | Tamper-proof audit logs | Cannot delete logs even for legitimate reasons; cost of retention |

---

## 12. Observability

### CloudTrail — The Ground Truth

CloudTrail is the primary observability mechanism for IAM. Every IAM and STS API call generates a CloudTrail event — management events by default. Data events (S3 object access, Lambda invocations, DynamoDB operations) require explicit enablement and generate much higher volume.

**CloudTrail event structure (critical fields):**

```json
{
  "eventVersion": "1.09",
  "eventTime": "2025-05-15T10:23:45Z",
  "eventSource": "sts.amazonaws.com",
  "eventName": "AssumeRole",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.5",
  "userAgent": "aws-cli/2.13.0 Python/3.11.0",
  "requestParameters": {
    "roleArn": "arn:aws:iam::123456789012:role/my-role",
    "roleSessionName": "my-session",
    "durationSeconds": 3600
  },
  "responseElements": {
    "credentials": {
      "accessKeyId": "ASIAEXAMPLE",
      "expiration": "2025-05-15T11:23:45Z"
    },
    "assumedRoleUser": {
      "arn": "arn:aws:sts::123456789012:assumed-role/my-role/my-session"
    }
  },
  "userIdentity": {
    "type": "IAMUser",
    "principalId": "AIDAEXAMPLE",
    "arn": "arn:aws:iam::123456789012:user/developer",
    "accountId": "123456789012"
  },
  "requestID": "EXAMPLE-REQUEST-ID",
  "eventID": "EXAMPLE-EVENT-ID",
  "errorCode": null,
  "errorMessage": null
}
```

**Key fields for security analysis:**

- `sourceIPAddress`: If this changes for a principal unexpectedly → compromised credential.
- `userAgent`: `Boto3` from a Lambda → expected. `curl` or `python-requests` → unusual.
- `errorCode`: High rate of `AccessDenied` from one principal → permission misconfiguration or enumeration.
- `requestParameters.roleArn`: AssumeRole to an unusual role → lateral movement.

### Logs

**What to log:**

| Event | Reason | Alert Level |
|---|---|---|
| Root account API call | Root should never be used day-to-day | Page immediately |
| `CreateUser` | New IAM user created — backdoor risk | Ticket |
| `CreateAccessKey` | New long-term credential created | Ticket |
| `AttachUserPolicy` / `AttachRolePolicy` | Permission escalation | Ticket |
| `CreatePolicyVersion` | Policy change — possible escalation | Alert |
| `StopLogging` / `DeleteTrail` | Evidence tampering | Page immediately |
| `AssumeRole` from external account | Cross-account access | Alert |
| `GetCallerIdentity` at high rate | Attacker fingerprinting | Monitor |
| `ConsoleLogin` with `MFAUsed: No` | MFA bypassed or not enforced | Alert |
| Access Denied at high rate from one principal | Enumeration or misconfiguration | Monitor |
| `UpdateAssumeRolePolicy` | Trust policy modified | Alert |
| `DeleteUser` / `DeleteRole` | Cleanup or sabotage | Alert |
| `PutUserPolicy` with `Action: *` | Potential admin grant | Page |

**What NOT to alert on:**
- Normal `AssumeRole` events from known service principals (Lambda, EC2) with expected role ARNs.
- `GetCallerIdentity` at startup of applications (SDK initialization pattern).
- CloudTrail lookup events during normal operations.
- `DescribeRoles`, `ListPolicies` from known automation accounts.

### Metrics (CloudWatch)

Key metrics from CloudTrail + CloudWatch:

```
Namespace: CloudTrailMetrics

1. RootAccountUsage
   Metric Filter: { $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }
   Alert: Count > 0 → CRITICAL

2. IAMPolicyChanges
   Metric Filter: { ($.eventName = DeleteGroupPolicy) || ($.eventName = DeleteRolePolicy) || ($.eventName = DeleteUserPolicy) || ($.eventName = PutGroupPolicy) || ($.eventName = PutRolePolicy) || ($.eventName = PutUserPolicy) || ($.eventName = CreatePolicy) || ($.eventName = DeletePolicy) || ($.eventName = CreatePolicyVersion) || ($.eventName = DeletePolicyVersion) || ($.eventName = SetDefaultPolicyVersion) || ($.eventName = AttachRolePolicy) || ($.eventName = DetachRolePolicy) || ($.eventName = AttachUserPolicy) || ($.eventName = DetachUserPolicy) || ($.eventName = AttachGroupPolicy) || ($.eventName = DetachGroupPolicy) }
   Alert: Count > 5 in 5 minutes → Warning

3. ConsoleLoginFailures
   Metric Filter: { ($.eventName = ConsoleLogin) && ($.errorMessage = "Failed authentication") }
   Alert: Count > 10 in 5 minutes → Warning (possible brute force)

4. CloudTrailChanges
   Metric Filter: { ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }
   Alert: Count > 0 → CRITICAL

5. AssumeRoleByExternalPrincipal
   Custom metric from Lambda analyzing CloudTrail
   Alert: AssumeRole where assumedBy.account != own account → Warning
```

### Traces (Distributed Tracing in IAM Context)

IAM doesn't expose traditional distributed traces, but X-Ray can be used at the application level. The **`x-amz-request-id`** header in every AWS API response is the equivalent of a trace ID — use it to correlate CloudTrail events with application behavior.

**Request correlation pattern:**
1. Application generates a UUID for each incoming request.
2. Application stores this UUID in a thread/context-local variable.
3. When making AWS API calls, pass it as `RoleSessionName` in AssumeRole calls (up to 64 chars).
4. CloudTrail records `RoleSessionName` → you can correlate the app request ID with the IAM event.

**AWS X-Ray + IAM:**
X-Ray automatically instruments AWS SDK calls and records them as trace segments. A Lambda function's X-Ray trace will show:
- The Lambda invocation (root segment)
- Each SDK call as a subsegment: which service, which operation, duration, error
- The `requestId` for each call (correlates to CloudTrail)

---

## 13. Scaling Considerations

### IAM — Inherently Global, Inherently Scaled

IAM is a globally replicated service. There is one IAM data store per account, replicated across AWS's global infrastructure. You don't horizontally scale IAM — it scales internally. But there are account-level limits that matter.

**Service quotas (hard limits):**

| Resource | Default Limit |
|---|---|
| IAM users per account | 5,000 |
| IAM roles per account | 1,000 |
| Managed policies per account | 1,500 |
| Policy versions per managed policy | 5 |
| Groups per account | 300 |
| Attached managed policies per user/role | 10 |
| Characters in managed policy | 6,144 |
| Inline policy characters per user/role | 2,048 |
| STS API calls per second (AssumeRole) | ~1,000 (soft) |

**5,000 user limit gotcha:** This limit seems high but is a real constraint for large organizations. Modern solution: don't create IAM users for humans. Use IAM Identity Center (SSO) — it has no user limit (users are in the external IdP). IAM users are for service accounts (machine identities) only.

### STS — Regional vs Global

STS has both global (`sts.amazonaws.com`) and regional (`sts.us-east-1.amazonaws.com`) endpoints. 

**Use regional STS endpoints:** 
- Regional endpoints are closer → lower latency.
- They avoid single-region dependency on us-east-1.
- If us-east-1 has an incident, regional STS endpoints in other regions still work (assuming your role's metadata has been replicated, which it has, since IAM is global).
- Configure in AWS CLI: `aws configure set sts_regional_endpoints regional`.

### Horizontal Scaling of Workloads Using IAM

**EKS at scale with IRSA (IAM Roles for Service Accounts):**

Problem: 1,000 pods all need to assume roles at startup. STS cannot handle 1,000 simultaneous `AssumeRoleWithWebIdentity` calls without throttling.

Solution patterns:
1. **Stagger pod startups:** Don't restart all pods simultaneously. Use rolling updates with `maxSurge` and `maxUnavailable` limits.
2. **Credential refresh aware startup:** Pod SDKs cache credentials and refresh proactively. The initial assumption is the bottleneck — cache it.
3. **IRSA Pod Identity (EKS Pod Identity):** Newer mechanism where EKS manages credential vending internally (a sidecar proxy), reducing direct STS calls from application pods.
4. **Prefetch credentials:** Initialize the SDK before the pod is ready to serve traffic. SDK will have credentials by the time the pod accepts requests.

### Consistency Tradeoffs in IAM

**IAM policy changes and eventual consistency:**

When you make an IAM change (attach a policy, create a role), it replicates across all AWS regions and availability zones. This typically takes milliseconds but can take seconds to a minute in rare cases during AWS events.

**Implication for automation:**
- Terraform, CDK, CloudFormation all add retries internally for this.
- Custom automation that directly calls IAM APIs and immediately calls other APIs with the new role must handle `AccessDenied` due to propagation lag by retrying.
- The `iam:CreateRole` → `iam:AttachRolePolicy` → `sts:AssumeRole` pattern is the most common failure. Add `time.sleep(10)` or a retry loop.

**STS token revocation is eventually effective:**
When you deactivate an access key (`iam:UpdateAccessKey` with `Status=Inactive`), STS tokens derived from that key are revoked. But because the token validation is distributed (no central database lookup), there may be a brief window (seconds) where in-flight requests with a revoked token's session credentials are still honored at some endpoints before the revocation propagates.

---

## 14. Interview Questions

### Q1: Explain SigV4. Why does AWS use it instead of just sending the secret key over TLS?

**Why asked:** Tests deep understanding of authentication vs authorization, and the design rationale for a signing protocol.

**Answer direction:** 
TLS provides confidentiality (the key can't be stolen in transit). But SigV4 provides additional guarantees TLS alone can't:
- **Request integrity:** The signature covers the request body and headers. A MITM who intercepts and decrypts TLS (via a corporate proxy with a trusted root cert) can see the request but cannot modify it without invalidating the signature.
- **Request binding:** The signature includes the service, region, date, and resource. A stolen signature cannot be replayed against a different service or on a different day.
- **Non-repudiation:** If AWS accepts the request, it proves the caller had the secret key at the time. The secret key never traverses the network — only the derived signature does.
- **Replay window:** The 15-minute window limits replay attacks without requiring AWS to maintain a nonce registry (which would be a massive scalability problem at AWS's scale).

Sending the raw secret over TLS would be simpler, but would mean: any TLS interception (intentional or accidental) exposes the long-term secret directly. A stolen secret is valid indefinitely. SigV4 means even a stolen signed request can only be replayed for 15 minutes.

---

### Q2: What is the difference between an IAM role's trust policy and its permission policy? Can you have a role that someone can assume but that grants no permissions? What happens?

**Why asked:** Tests understanding of IAM dual-policy structure.

**Answer direction:**
- **Trust policy** (also called the "assume role policy document"): Defines WHO can assume the role. It's a resource-based policy on the role itself. Contains `sts:AssumeRole` (or `sts:AssumeRoleWithWebIdentity` etc.) allow statements.
- **Permission policy:** Defines WHAT the role can do after it's assumed. Identity-based policies attached to the role.

Yes, you can have a role with a trust policy that allows assumption but no permission policies attached. The `AssumeRole` call succeeds — the caller gets temporary credentials. But when they try to use those credentials to call any AWS API, they get `AccessDenied` because no permission policies grant anything. This is sometimes intentional — a "placeholder" role that exists for future use, or a role used only for its identity (STS GetCallerIdentity reveals the assumed role ARN, which can be used in conditions of other accounts' resource policies).

---

### Q3: Walk me through what happens when an EC2 instance role's credentials expire while a long-running process is using them. Does the process fail?

**Why asked:** Tests understanding of SDK credential refresh behavior and what happens without it.

**Answer direction:**
- **With a modern AWS SDK (v2 and later):** The SDK's credential provider for IMDS proactively refreshes credentials ~5 minutes before expiry. The SDK holds the credentials in memory, monitors `Expiration`, and fetches new credentials from IMDS in the background before the old ones expire. The running process sees no interruption — new credentials replace old ones in memory. This is transparent.
- **With a naive implementation (manually fetching credentials once at startup and storing them):** When `Expiration` is reached, subsequent API calls with the old credentials return `ExpiredTokenException`. The process fails unless it handles this error and re-fetches from IMDS.
- **Edge case:** If IMDS is unreachable during the refresh window (e.g., network issue, IMDS is misconfigured), the SDK exhausts retries and raises a `CredentialRetrievalError`. The next AWS API call fails. This is a real failure mode in containerized environments where network policies may block IMDS access for certain container types.
- **For ECS/Fargate:** Credentials come from a local credential endpoint (not IMDS) — same SDK behavior, but the endpoint URL is in `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`.

---

### Q4: An engineer says "We set our IAM role to allow `Action: *` but restricted it with `aws:SourceIp` condition to only our office IP. Is this secure?" What's wrong with this?

**Why asked:** Tests understanding of condition evaluation and escape hatches.

**Answer direction — multiple problems:**

1. **IP conditions don't apply to all services:** The `aws:SourceIp` condition key is NOT present in the context for API calls made **through** AWS services. For example, if a Lambda function in your VPC calls S3, the source IP is a VPC internal IP, not the calling user's IP. If an EC2 instance makes API calls, the source IP is the instance's public NAT IP, not a user's IP. IP-based conditions only work reliably for direct IAM user/role API calls from known fixed IPs.

2. **Action wildcard is permanent:** Restricting with IP gives a false sense of security. If the attacker is in the office network, on a VPN, or can spoof the source IP (via a compromised internal machine), they have full access. The `Action: *` means any future AWS service or action is also granted.

3. **VPC NAT Gateway IPs change:** If the office adds a NAT Gateway or the ISP changes the IP, the condition fails and production breaks. This creates operational pressure to either loosen the condition or remove it.

4. **Better approach:** Use `aws:SourceVpc` instead of `aws:SourceIp` for VPC-originated traffic. Use MFA conditions for human access. Use specific Action lists, not wildcards. Separate roles for different functions.

---

### Q5: What is the "confused deputy" problem in AWS, and how does ExternalId solve it — and fail to solve it?

**Why asked:** Tests deep understanding of cross-account trust and a specific IAM security pattern.

**Answer direction:**

**The problem:** You give Vendor Inc. a role ARN to access your account: `arn:aws:iam::YOUR_ACCOUNT:role/VendorRole`. Vendor builds a service where multiple customers send data for processing. An attacker, also a Vendor customer, sends data but includes YOUR role ARN as the target. Vendor's service (the "deputy") assumes YOUR role when processing the attacker's request — it's confused about who authorized what.

**ExternalId solution:** Your trust policy requires `"StringEquals": {"sts:ExternalId": "YOUR_SECRET_ID"}`. Vendor must pass this value in the `AssumeRole` call. The attacker doesn't know your ExternalId — they can only exploit Vendor's service if they know both your role ARN AND your ExternalId. You share ExternalId with Vendor through a separate channel.

**Why ExternalId fails:**
- If Vendor stores your ExternalId in their system and their system is breached, the attacker learns it.
- ExternalId is not rotatable (changing it breaks the integration).
- ExternalId provides no protection if the attacker IS a Vendor employee or can access Vendor's data.
- Many cloud service providers use the same ExternalId format for all customers (e.g., their account ID), making it guessable.
- The REAL fix is: Vendor should have their own unique IAM role per customer, not a shared role that assumes customer roles. Each customer grants trust to Vendor's specific role, not a broad account trust.

---

### Q6: What happens to STS tokens issued from a role if you delete the role? Can the tokens still be used?

**Why asked:** Tests understanding of STS token lifecycle and revocation mechanics.

**Answer direction:**
When you delete an IAM role, AWS immediately invalidates all STS tokens that were issued from that role. Unlike token expiry (which is baked into the token and checked on each call), role deletion triggers an active revocation mechanism.

Technically: when an API call is made with STS credentials, AWS decrypts the session token, reads the embedded role ARN, and checks whether that role still exists and is active. If the role has been deleted, the call fails with `InvalidClientTokenId` or `ExpiredTokenException`.

**Contrast with access key deactivation:** Deactivating (`UpdateAccessKey status=Inactive`) is immediate and propagates quickly. Deleting an access key is also immediate. Both revoke all STS tokens derived from that key.

**Contrast with expiry:** If you want to revoke a token without deleting the role, you cannot do it directly (no token revocation API). Options:
- Delete and recreate the role (drastic).
- Use a condition in the role's permission policy: `aws:TokenIssueTime` — add a policy that denies all actions if `aws:TokenIssueTime` is before the current time (this effectively invalidates all tokens issued before a certain moment).

---

### Q7: Your security team says "We require IMDSv2 in all our EC2 instances." A developer says "Our application still works but sometimes gets 401 errors from S3 when starting up." What's happening?

**Why asked:** Tests understanding of IMDSv2 mechanics and common implementation issues.

**Answer direction:**
This is a classic SDK version / IMDSv2 compatibility issue. Several possible causes:

1. **Old SDK version:** AWS SDKs before certain versions (boto3 < 1.9.4, Java SDK < 1.11.678, etc.) don't support IMDSv2. They make IMDSv1-style GET requests, which are rejected if IMDSv2 is required. The SDK falls through to the next credential provider in the chain (which may find nothing), resulting in no credentials → 401.

2. **Hop limit configuration:** IMDSv2 requires the PUT request to receive a session token. The EC2 instance metadata hop limit determines how many network hops the IMDSv2 token request can traverse. For containers inside EC2, the default hop limit of 1 means the request doesn't reach the IMDS from inside a container. Fix: increase the hop limit to 2 in the EC2 instance metadata configuration:
   ```bash
   aws ec2 modify-instance-metadata-options \
     --instance-id i-1234567890abcdef0 \
     --http-put-response-hop-limit 2 \
     --http-endpoint enabled \
     --http-tokens required
   ```

3. **Container without host networking:** If the container uses bridge networking, the IMDS hop limit of 1 is exhausted by the bridge. Setting `--http-put-response-hop-limit 2` allows the container to reach IMDS.

4. **Race condition on startup:** The application starts and makes an S3 call before the SDK completes the IMDSv2 flow (PUT → GET → parse credentials → cache). This is unusual but can happen with SDK initialization patterns.

---

### Q8: What is the maximum privilege an SCP can grant? What is the minimum?

**Why asked:** Tests understanding of SCP as a "ceiling" control, not a grant.

**Answer direction:**

**SCPs cannot grant any permissions.** This is a fundamental SCP principle. SCPs define the maximum permissions available to accounts in the OU — they never add permissions that don't already exist via identity or resource policies. Even if an SCP says `"Effect": "Allow", "Action": "*", "Resource": "*"`, it grants nothing. It just means the SCP doesn't restrict anything (the default SCP `FullAWSAccess` does exactly this).

**Minimum — full restriction:** An SCP with `"Effect": "Deny", "Action": "*", "Resource": "*"` would deny every action in the account — including the account root user. Wait — the account root user? YES. SCPs apply to account root. If you apply this SCP to an account, not even root can perform actions. This is the nuclear option and can brick an account if done incorrectly. The parent account (organization management account) must remove the SCP.

**Exception to SCP scope:** SCPs do NOT apply to the AWS Organization management account (the root account). SCPs also do not apply to service-linked roles (roles created by AWS services on your behalf, like the AWSServiceRoleForSupport). These are exempted to prevent breaking core AWS functionality.

**Practical implication:** Many teams think "I attached the SCP, so I've blocked it." But if they attached it to the wrong OU, or if the account is the management account, it has no effect. Always verify SCP application with `aws organizations list-policies-for-target`.

---

### Q9: A lambda function uses a role with `s3:GetObject` on a specific bucket. An engineer adds a bucket policy that denies `s3:GetObject` from all principals except a specific VPC. The Lambda function is in a VPC. Does it work? What if it's NOT in a VPC?

**Why asked:** Tests understanding of same-account policy evaluation and VPC condition keys.

**Answer direction:**

**Lambda in VPC:** 
- The Lambda function's network requests originate from the VPC.
- The `aws:SourceVpc` condition key in the bucket policy evaluates to the Lambda's VPC ID.
- If the bucket policy allows `aws:SourceVpc = vpc-1234`, the Lambda's request matches → allowed by bucket policy.
- IAM role policy also allows `s3:GetObject`.
- Same-account rule: either identity policy OR resource policy must allow → allowed.
- Result: **SUCCESS.**

**Lambda NOT in VPC:**
- Lambda's network traffic originates from AWS-managed infrastructure (not in your VPC).
- `aws:SourceVpc` is not set (no VPC), so the bucket policy's explicit deny applies.
- Explicit deny in resource policy → **DENIED**, regardless of identity policy.
- Result: **ACCESS DENIED.**

**Subtlety:** The bucket policy uses `Deny` for principals not in the VPC (not just `Allow` for the VPC). An explicit Deny in a resource policy is evaluated first and overrides any Allow in the identity policy (for same-account access). The only exception is resource-based policies that grant cross-account access — in that case, the identity policy in the source account must ALSO allow, and the resource-based policy allow is necessary but not sufficient alone.

---

### Q10: What is role chaining? What unique limitation does it introduce, and why?

**Why asked:** Tests understanding of a non-obvious STS behavior with real operational impact.

**Answer direction:**

**Role chaining** is when you assume a role, and then use those temporary credentials to assume another role.

Example:
- User assumes RoleA → gets temporary credentials A.
- With credentials A, user calls AssumeRole on RoleB → gets temporary credentials B.
- With credentials B, user calls API.

**The limitation:** When role chaining occurs, the maximum session duration for ALL roles in the chain is capped at **1 hour**, regardless of the role's configured maximum session duration. Even if RoleB is configured with `MaxSessionDuration=12h`, a chained assumption will always produce a 1-hour session.

**Why?** This is an AWS security design decision. Role chaining increases the complexity of trust evaluation (who ultimately authorized this?). By limiting chained session durations, AWS limits the blast radius of a chain that was unintentionally long or that allowed transitional trust relationships to create overly long-lived credentials.

**Real-world impact:** An automation pipeline that does User → AssumeRole(DevRole) → AssumeRole(ProdRole) to access production resources will get 1-hour prod credentials, not 12-hour ones. A long-running deployment that takes > 1 hour will fail mid-way. Fix: Use the originating role to directly assume the final role (don't chain through intermediate roles), or refresh the role assumption in the automation at the 50-minute mark.

**CloudTrail clue:** Chained role sessions have a `userIdentity.sessionContext.sessionIssuer` that shows the intermediate role, not the original user.

---

### Q11: Describe a real attack scenario where an AWS account is compromised without any IAM user, role, or access key being compromised. Is this possible?

**Why asked:** Tests creative thinking about AWS trust model and attack vectors beyond credential compromise.

**Answer direction — YES, possible:**

**Scenario — Overpermissive resource-based policy:**

1. An S3 bucket has a misconfigured bucket policy with `"Principal": "*"` and no `Condition`. No IAM user or role is compromised — the bucket itself is publicly accessible.
2. Attacker accesses the bucket without any AWS credentials at all (unsigned requests to a public bucket work). This is purely a resource-based policy misconfiguration.

**Scenario — Supply chain / AWS service abuse:**

1. A Lambda function has code that reads from an environment variable: `TRUSTED_BUCKET`. An attacker finds the Lambda's code in a public GitHub repo.
2. The Lambda's execution role has `s3:GetObject` on `arn:aws:s3:::*` (wildcard). The Lambda's logic writes data to an attacker-controlled bucket if a certain API parameter is set.
3. Attacker calls the Lambda's URL (if it's a Lambda Function URL or API Gateway without auth) with the crafted parameter.
4. Lambda writes the data to the attacker's bucket. No IAM compromise — just abusing the Lambda's permissions and code logic.

**Scenario — Cognito / Federation misconfiguration:**

1. A Cognito Identity Pool is misconfigured with unauthenticated access enabled and the unauthenticated role has `s3:GetObject` on sensitive buckets.
2. Attacker calls Cognito's `GetId` and `GetCredentialsForIdentity` APIs without any authentication → receives valid AWS credentials → accesses S3.
3. No IAM user or role was "compromised" — the configuration was simply wrong.

The common thread: AWS authorization has multiple entry points (identity-based policies, resource-based policies, resource-level public access settings, Cognito, federation). A secure IAM configuration can be undermined by resource-based policy mistakes, public access settings, or overly permissive federation configurations.

---

### Q12: What is `aws:PrincipalOrgID`, and why is it more secure than listing individual account IDs in a resource policy?

**Why asked:** Tests understanding of Organizations-level controls and their operational advantages.

**Answer direction:**

`aws:PrincipalOrgID` is a condition key that evaluates to the AWS Organizations ID of the principal making the request. It allows you to write a resource policy that grants access to ALL principals within your organization, without listing individual account IDs.

**Example — S3 bucket policy allowing all organization members:**
```json
{
  "Statement": [{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::my-bucket/*",
    "Condition": {
      "StringEquals": {
        "aws:PrincipalOrgID": "o-exampleorgid111"
      }
    }
  }]
}
```

**Why more secure than listing account IDs:**

1. **Automatic scope:** When you add a new account to the organization, it automatically gets access (if intended). When you remove an account (or the account leaves the org), it immediately loses access — no manual update needed.

2. **No account ID leakage:** AWS account IDs in resource policies can expose your organizational structure. Using OrgID hides individual account counts/IDs from the policy (though OrgID itself is observable).

3. **No maintenance burden:** If you have 200 accounts and list them all in a resource policy, adding account 201 requires a policy update. With OrgID, it's automatic.

4. **Guardrails alignment:** If an account is not in your organization (e.g., a forgotten test account, a vendor's account), the OrgID condition correctly excludes them. An account ID list requires you to know which accounts to exclude.

**Limitation:** It's all-or-nothing for the organization. You can't use OrgID to grant access to a specific OU (use `aws:PrincipalOrgPaths` condition for OU-level scoping, which was added later). And OrgID doesn't distinguish between accounts with different trust levels — a development account and a production account both satisfy the OrgID condition.

---

*Document Version: 1.0 | Last Updated: May 2026 | Classification: Internal Engineering*  
*All behavior described is based on publicly documented AWS functionality and observed system behavior.*
