# SecureShare – DevSecOps Project: Week 1 – Build the secure app (Days 1–7)

> 🎯 **Goal:** a secure file-sharing platform (encrypted files, expiring links, audit trail) with a full DevSecOps pipeline, solo, in 14 days. For your CV and GitHub.
> 🚀 **Week 1 goal:** a working app where a user registers, uploads an encrypted file, shares it through an expiring link, and every action is logged.

## 🧰 Stack

| Layer | Choice | Why |
|---|---|---|
| Backend | Python + FastAPI (or ASP.NET Core if you prefer) | Fast to build, great docs |
| DB | PostgreSQL + SQLAlchemy + Alembic | Users, files, shares, audit logs |
| File storage | MinIO (S3-compatible) | Real S3 API, runs in Docker |
| Encryption | AES-256-GCM, envelope encryption (per-file key wrapped by a master key) | GCM is authenticated; the guide's CBC example is weaker |
| Frontend | React + Vite (minimal) | Only 1 day budgeted |
| CI/CD | GitHub Actions (guide uses GitLab, same concepts) | |
| Scanners | Gitleaks, Semgrep, Bandit, pip-audit, npm audit, Hadolint, Trivy, OWASP ZAP | |

## 📌 Rules for the 14 days

- Budget: 6–8 h/day. If you have less, drop stretch items first (2FA, ClamAV), never the pipeline.
- Commit every day.
- Each day ends with a checkpoint. If it fails, fix it before moving on.
- Write one paragraph per day in /docs as you go.
- Never commit secrets. .env stays in .gitignore from day 1.

---

## 📅 Day 1 – Setup, threat model, database

### 📋 Tasks

- [ ] Create GitHub repo devsecops-secure-file-sharing with the guide's folders (frontend, backend, database, docker, docs)
- [ ] Add .gitignore (.env, __pycache__, node_modules, storage) and a .env.example
- [ ] docker-compose.yml with PostgreSQL + MinIO, check both start
- [ ] FastAPI skeleton with a /health endpoint
- [ ] Design the DB schema (ERD): users, files, share_links, audit_logs (use the audit_logs SQL from the guide)
- [ ] SQLAlchemy models + Alembic, run the first migration
- [ ] Write docs/threat-model.md: assets (files, keys, passwords), attackers, 8–10 threats (IDOR, brute force, link guessing, malicious upload, key leak...) with the planned mitigation for each

### 📚 Learn today

- OWASP Top 10 (focus on A01 Broken Access Control, A02 Cryptographic Failures, A03 Injection)
- What a threat model is (STRIDE in 30 min is enough)
- Docker Compose basics, Alembic migrations

> ✅ **🎯 CHECKPOINT:** docker compose up starts Postgres + MinIO, /health returns 200, tables exist in the DB, threat model has at least 8 threats. First commit pushed.

---

## 📅 Day 2 – Authentication

### 📋 Tasks

- [ ] POST /api/register: email validation, password policy (min 12 chars), hash with bcrypt or argon2
- [ ] POST /api/login: returns a short-lived JWT (15 min) signed with a secret from env
- [ ] GET /api/profile protected by a JWT dependency
- [ ] Generic error messages ("invalid credentials", never "user not found")
- [ ] Basic rate limiting on login (slowapi) against brute force
- [ ] Pydantic schemas for all inputs
- [ ] pytest: register, login ok, login wrong password, expired/tampered token rejected

### 📚 Learn today

- How JWT works (header.payload.signature), why alg=none and weak secrets are dangerous
- bcrypt vs argon2, salt, cost factor
- Authentication vs authorization

> ✅ **🎯 CHECKPOINT:** 5+ passing auth tests. A tampered JWT returns 401. 10 wrong logins in a row get throttled. DB contains only hashes.

---

## 📅 Day 3 – Upload + AES-256 encryption

### 📋 Tasks

- [ ] POST /api/files: multipart upload, max size 100 MB
- [ ] Validate real file type with magic bytes (python-magic), not the extension; block a denylist (.exe, .bat, .sh...); sanitize the filename (no path traversal)
- [ ] Envelope encryption: random 256-bit key per file, AES-256-GCM with a random nonce, encrypt the file, wrap the file key with a master key (from env) and store the wrapped key in DB
- [ ] Save the encrypted blob in MinIO under a random object name (never the original name)
- [ ] Store metadata in DB (original name, size, mime, owner_id, wrapped key, nonce)
- [ ] Unit tests: encrypt then decrypt returns the same bytes; flipping one byte makes decryption fail

### 📚 Learn today

- AES modes: why GCM (authenticated) beats CBC; why a nonce must never repeat with the same key
- Envelope encryption and what a KMS does (master key in env is your KMS stand-in, mention this limit in the doc)
- Python cryptography library (AESGCM)

> ✅ **🎯 CHECKPOINT (guide's Test 1):** upload a text file with a recognizable sentence, open the stored object in MinIO, content is unreadable. No plaintext key in the DB.

---

## 📅 Day 4 – Download, list, delete, access control

### 📋 Tasks

- [ ] GET /api/files: list only the current user's files
- [ ] GET /api/files/{id}/download: check ownership, fetch from MinIO, decrypt, return
- [ ] DELETE /api/files/{id}: remove the blob and the metadata
- [ ] One central ownership check function reused everywhere (avoid IDOR)
- [ ] UUIDs for file IDs
- [ ] Tests: user B cannot download, delete or see user A's file (403/404)
- [ ] Handle large files without loading everything in RAM (chunked read)

### 📚 Learn today

- IDOR / Broken Access Control, the #1 OWASP risk
- Streaming responses in FastAPI
- Why 404 vs 403 matters (information leak)

> ✅ **🎯 CHECKPOINT (guide's Test 4):** user A uploads, user B gets 403/404 on every endpoint touching that file. Downloaded file is byte-identical to the original (compare sha256).

---

## 📅 Day 5 – Share links

### 📋 Tasks

- [ ] POST /api/files/{id}/share: options expires_at, optional password, max_downloads
- [ ] Token = secrets.token_urlsafe(32); store only a hash of the token if you can
- [ ] GET /api/share/{token}: check expiry, password (hashed), download count, then decrypt and stream
- [ ] Increment the download counter atomically (UPDATE ... WHERE downloads < max) so parallel requests can't bypass the limit
- [ ] DELETE /api/share/{token}: revoke
- [ ] Optional: share with a specific registered user (permission table)
- [ ] Tests for expiry, wrong password, limit reached, revoked link

### 📚 Learn today

- Cryptographically secure randomness vs random()
- Race conditions and atomic DB updates
- Timing-safe comparison

> ✅ **🎯 CHECKPOINT (guide's Test 2):** link with 1-minute expiry works now and is refused after 2 minutes. A link with max_downloads=2 refuses the third try. Wrong password refused.

---

## 📅 Day 6 – Audit logs and activity API

### 📋 Tasks

- [ ] log_action() writing to audit_logs (user_id, action, file_id, ip, user_agent, timestamp, details JSONB)
- [ ] Log: register, login success/fail, upload, share created, download (including via public link), delete, denied access
- [ ] Make logging automatic with a FastAPI middleware/dependency so you can't forget it
- [ ] GET /api/activity: current user's logs, paginated, filterable by action
- [ ] Never log passwords, tokens or keys (add a test for it)
- [ ] Keep the audit table append-only (no update/delete endpoint; DB role without UPDATE/DELETE if you have time)

### 📚 Learn today

- What a good audit trail contains (who, what, when, from where, result)
- Log injection, and why sensitive data must stay out of logs
- Basic PostgreSQL roles and privileges

> ✅ **🎯 CHECKPOINT (guide's Test 3):** after a scripted scenario, audit_logs shows every action with timestamp, user_id, IP, including denied attempts. grep for a password in the logs finds nothing.

---

## 📅 Day 7 – Frontend + integration + buffer

### 📋 Tasks

- [ ] React + Vite: login/register page, dashboard (file list), drag-and-drop upload, file page (create link, see logs, delete), public share page
- [ ] Axios client that attaches the JWT; on 401 redirect to login
- [ ] Keep the UI plain (Tailwind defaults), one day max
- [ ] Token in memory or httpOnly cookie, avoid localStorage if you can; note your choice in the docs
- [ ] CORS limited to the frontend origin
- [ ] Run the whole flow by hand once, fix what is broken
- [ ] Use leftover time to catch up on earlier days

### 📚 Learn today

- XSS and where tokens should live in a SPA
- CORS, what it really protects

> ✅ **🎯 CHECKPOINT (end of Week 1):** from the browser you can register, upload, share with expiry, open the link in a private window, download, and see the activity list. Tag v0.1.0 in Git.

---

## 🏁 Week 1 review

- [ ] All mandatory features from the guide work (2FA/ClamAV are optional)
- [ ] Tests pass locally
- [ ] docs/ has: threat model, ERD, 1 paragraph per day
- [ ] Note 3 things that were hard (they go in the final doc)
