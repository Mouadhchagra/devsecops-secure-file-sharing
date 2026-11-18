# Threat Model – SecureShare

> Method: **STRIDE** (Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege).
> This is a living document: updated when features are added (status column).

## 1. What is the system?

A web app where a user registers, uploads a file (encrypted with AES-256-GCM), shares it through an
expiring link (optional password, max downloads), and every action is written to an audit log.

```
 [Browser / React]  --HTTPS-->  [FastAPI backend]  --SQL-->  [PostgreSQL]
       ▲                              │
 [Anonymous user with                 └--S3 API-->  [MinIO: encrypted blobs]
  a share link]
```

**Trust boundaries** (where an attacker can send data to us):
1. Internet → backend API (everything the user sends is untrusted: body, headers, file, filename)
2. Backend → PostgreSQL / MinIO (internal; must not be reachable from outside)
3. Developer → GitHub / CI pipeline (code, dependencies, images, secrets)

## 2. Assets (what we protect)

| Asset | Why it matters |
|---|---|
| Uploaded files (content) | Confidential user data, the core of the product |
| `MASTER_KEY` | Unwraps every file key → leak = all files readable |
| Per-file keys | Decrypt one file each |
| User passwords | Account takeover, reused on other sites |
| JWT secret / tokens | Forge or steal sessions |
| Share link tokens | Anyone with the token can download the file |
| Audit logs | Proof of who did what (forensics, accountability) |
| Infrastructure credentials (DB, MinIO) | Direct access to data |

## 3. Attackers

| Attacker | Access | Goal |
|---|---|---|
| Anonymous internet user | Public API, share link page | Read files, take over accounts, crash the service |
| Malicious registered user | Valid account | Read/delete **other users'** files (IDOR), upload malware |
| Someone who got a share link | One token | Download more than allowed, after expiry, guess other links |
| Attacker with a DB dump (SQLi, backup leak) | Database content | Passwords, keys, tokens |
| Attacker with RCE in a container | Shell inside a container | Privesc, escape to host, steal secrets |
| Supply-chain attacker | Malicious dependency / image | Run code in our app or CI |
| Careless developer (me) | Repo | Commits a secret, ships a vulnerable dependency |

## 4. Threats and mitigations

Risk = Likelihood × Impact (H/M/L).

| ID | STRIDE | Threat (attack scenario) | Risk | Mitigation | Day | Status |
|---|---|---|---|---|---|---|
| T1 | **E / I** | **IDOR**: user B changes the id in `/api/files/{id}` to download or delete user A's file | H | Central ownership check reused on every file endpoint; UUIDv4 ids; return 404 (not 403) to avoid confirming the file exists; tests user A vs user B | 4 | Planned |
| T2 | **S** | **Brute force / credential stuffing** on `/api/login` | H | Rate limiting (slowapi); argon2/bcrypt slow hashing; generic message "invalid credentials" (no user enumeration); log failed logins | 2 | Planned |
| T3 | **S / E** | **JWT forgery**: `alg=none`, weak secret cracked offline (hashcat), tampered payload | H | Long random `JWT_SECRET` from env; algorithm fixed server-side (HS256 only); 15 min expiry; tests for tampered/expired tokens | 2 | Planned |
| T4 | **I** | **Share link guessing / brute force**: enumerate tokens or brute-force the link password | M | `secrets.token_urlsafe(32)` (256 bits); only SHA-256 of the token in DB; hashed link password; rate limit on share endpoints | 5, 11 | Planned |
| T5 | **E / T** | **Share link limits bypass**: race condition with parallel requests to exceed `max_downloads`, or use after expiry/revoke | M | Atomic `UPDATE ... WHERE download_count < max_downloads`; server-side expiry check (TIMESTAMPTZ); `revoked_at` check | 5 | Planned |
| T6 | **T / E** | **Malicious upload**: `.exe` renamed to `.pdf`, path traversal in filename (`../../etc/passwd`), huge file | H | Real type from magic bytes (python-magic) + denylist; filename sanitized and never used as storage path (random `object_name`); 100 MB limit; optional ClamAV | 3 | Planned |
| T7 | **I** | **Master key / secret leak**: `.env` committed to GitHub, secret in logs or Docker image layers | H | `.env` in `.gitignore` from day 1; `.env.example` with fake values; `SecretStr` in settings; Gitleaks in CI on full history; `.dockerignore` | 1, 8, 9 | **Partly done** (gitignore, SecretStr) |
| T8 | **I** | **Database dump** (SQLi, stolen backup) | H | ORM with parameterized queries; only hashes for passwords and tokens; file keys wrapped with `MASTER_KEY` (not in DB); DB port bound to 127.0.0.1 / internal network only | 1, 2, 3 | **Partly done** (schema, port binding) |
| T9 | **I** | **Storage breach**: attacker reads MinIO bucket directly | M | Files stored encrypted (AES-256-GCM); random object names; MinIO not exposed publicly; strong credentials | 1, 3, 8 | **Partly done** (bound to 127.0.0.1) |
| T10 | **R / T** | **Repudiation / log tampering**: user denies an action, attacker deletes their traces | M | Append-only `audit_logs` (no update/delete API, DB role without UPDATE/DELETE); logs kept when user/file deleted (`ON DELETE SET NULL`); log denied attempts too | 6 | **Partly done** (schema) |
| T11 | **I** | **Sensitive data in logs** / log injection (fake lines via `\n` in user input) | M | Never log passwords, tokens, keys (automated test); structured JSONB `details`; escape user input | 6 | Planned |
| T12 | **E** | **RCE in a container → privesc / container escape** (reverse shell lands as root) | M | Non-root containers (MinIO already runs as uid 65532 via Chainguard); minimal images (no sudo, few SUID binaries); no `--privileged`, no docker.sock mount; Trivy scan | 1, 8, 10 | **Partly done** (MinIO non-root) |
| T13 | **T** | **Supply-chain attack**: vulnerable or malicious dependency / image | M | Pinned versions (`requirements.txt`, image digests); pip-audit, npm audit, Trivy, Dependabot; GitHub Actions pinned by SHA | 1, 9, 10 | **Partly done** (pinning) |
| T14 | **D** | **Denial of service**: flood uploads, huge files, login spam | M | Upload size limit; streaming/chunked reads (no full file in RAM); rate limiting | 2, 3, 4 | Planned |
| T15 | **S / I** | **XSS / token theft in the browser**, CORS misconfiguration | M | Token in memory or httpOnly cookie (not localStorage); CORS limited to frontend origin; CSP and security headers | 7, 11 | Planned |

## 5. Known limitations (accepted for this project)

- `MASTER_KEY` lives in an environment variable, not in a real KMS/HSM (AWS KMS, Vault). Anyone with access to the backend host/env can read it.
- No key rotation yet.
- Single node, no backups or high availability.
- TLS (HTTPS) is not configured for local development; it would be done by a reverse proxy in production.

## 6. Mapping to OWASP Top 10 (2021)

| OWASP | Threats |
|---|---|
| A01 Broken Access Control | T1, T5 |
| A02 Cryptographic Failures | T3, T7, T8, T9 |
| A03 Injection | T8 (SQLi), T11 (log injection), T15 (XSS) |
| A04 Insecure Design | T4, T5 |
| A05 Security Misconfiguration | T12, T15 |
| A06 Vulnerable Components | T13 |
| A07 Identification & Authentication Failures | T2, T3 |
| A08 Software & Data Integrity Failures | T13 |
| A09 Security Logging & Monitoring Failures | T10, T11 |
