# SecureShare – DevSecOps Project: Week 2 – DevSecOps pipeline, hardening, docs (Days 8–14)

> 🚀 **Week goal:** every push is automatically scanned (secrets, code, dependencies, container, running app), findings are fixed with before/after proof, and the project is documented and demo-ready. This week is what makes it a DevSecOps project on your CV.

---

## 📅 Day 8 – Secure containers

### 📋 Tasks

- [ ] Dockerfile for backend: multi-stage build, slim base image with pinned version, non-root user, no dev tools in final image, HEALTHCHECK
- [ ] Dockerfile for frontend (build, then serve static with nginx unprivileged)
- [ ] .dockerignore (no .env, .git, tests)
- [ ] Full docker-compose: frontend, backend, Postgres, MinIO; secrets via env file, not in the image; internal network so DB and MinIO are not published to the host
- [ ] Lint Dockerfiles with Hadolint, fix warnings
- [ ] Run Trivy locally on both images and read the report

### 📚 Learn today

- Container security basics: least privilege, non-root, minimal images, secrets leaking in layers
- Reading a CVE/CVSS entry
- Hadolint rules, Trivy output

> ✅ **🎯 CHECKPOINT:** docker compose up runs the whole stack from scratch; whoami inside the backend container is not root; Trivy report saved in docs/reports/ (your "before").

---

## 📅 Day 9 – CI pipeline: build, test, SAST, secrets, dependencies

### 📋 Tasks

- [ ] .github/workflows/ci.yml with stages: build, test, security
- [ ] Jobs: install and pytest (with coverage), frontend build
- [ ] Gitleaks job (secret scanning) on full history
- [ ] SAST: Semgrep and Bandit
- [ ] Dependency scan: pip-audit and npm audit --audit-level=high
- [ ] Enable Dependabot (pip, npm, docker, actions)
- [ ] Pin GitHub Actions to a version/SHA, set a least-privilege permissions: block
- [ ] Optional: SonarCloud (or SonarQube in Docker) for the dashboard screenshot the guide asks for

### 📚 Learn today

- CI/CD concepts: stages, jobs, artifacts, secrets in CI
- SAST vs SCA vs secret scanning, what each catches
- Supply chain risk (why pin versions)

> ✅ **🎯 CHECKPOINT:** pipeline runs on push and is visible in the Actions tab; at least one real finding appears in Semgrep/Bandit/pip-audit (don't fix it yet, it's your "before"). Badges added to README.

---

## 📅 Day 10 – Image scan + DAST (ZAP) in CI

### 📋 Tasks

- [ ] Job: build images, Trivy scan (fail on CRITICAL, report HIGH), upload results as SARIF to GitHub Security tab
- [ ] Job: start the stack with docker compose in the runner, wait for health, run ZAP baseline (ghcr.io/zaproxy/zaproxy:stable, zap-baseline.py) against it, save the HTML report as an artifact
- [ ] Optional: ZAP API scan using your OpenAPI spec (zap-api-scan.py)
- [ ] Add a manual deploy job, only on main (as in the guide)
- [ ] Make gates explicit: which scanners block the merge, which only warn; write it in docs/pipeline.md

### 📚 Learn today

- DAST vs SAST: black-box testing of a running app
- What ZAP baseline checks (headers, cookies, info leaks) and what it can't (business logic)
- SARIF format and GitHub code scanning

> ✅ **🎯 CHECKPOINT:** full pipeline green or failing for real reasons; ZAP HTML report and Trivy report downloadable from the run. Screenshot the pipeline graph.

---

## 📅 Day 11 – Fix findings and harden

### 📋 Tasks

- [ ] Triage every finding: true positive, false positive (document why, suppress with a comment), or accepted risk
- [ ] Fix criticals/highs: upgrade vulnerable dependencies, rebase image, fix code issues
- [ ] Add security headers (CSP, X-Content-Type-Options, X-Frame-Options, HSTS, Referrer-Policy) and re-run ZAP to see warnings drop
- [ ] Tighten CORS and cookie flags (HttpOnly, Secure, SameSite) if you use cookies
- [ ] Rate limiting on share links and downloads
- [ ] Branch protection on main: PR required, pipeline must pass
- [ ] Save the "after" reports next to the "before" ones in docs/reports/

### 📚 Learn today

- How to triage a vulnerability report (severity vs real exploitability)
- HTTP security headers
- Branch protection and shift-left in practice

> ✅ **🎯 CHECKPOINT:** no CRITICAL left in Trivy, no unexplained HIGH in the others, ZAP warnings reduced, and a before/after table in docs/reports/summary.md (great for the CV and interviews).

---

## 📅 Day 12 – Security tests (manual + automated)

### 📋 Tasks

- [ ] Run the guide's 5 tests and record evidence (screenshots, commands): encryption, link expiry, logs, unauthorized access, SQL injection (' OR '1'='1)
- [ ] Extra tests: IDOR with other users' IDs, tampered/expired JWT, path traversal in filename (../../etc/passwd), renamed .exe upload, oversized upload, brute-forcing a share token/password
- [ ] Turn the important ones into pytest tests so CI keeps them
- [ ] Measure for the doc: encryption time for 1 MB / 50 MB / 100 MB, number of users/files in test data
- [ ] Stretch (only if on time): ClamAV scan on upload (+5 bonus) or TOTP 2FA with pyotp (+5 bonus)

### 📚 Learn today

- Writing security test cases (abuse cases, not only happy paths)
- SQL injection, why ORMs/parameterized queries stop it
- Basic pentest mindset

> ✅ **🎯 CHECKPOINT:** 5/5 guide tests pass with evidence; at least 5 new security tests run in CI; results recorded in docs/test-results.md.

---

## 📅 Day 13 – Documentation

### 📋 Tasks

- [ ] README: what it is, architecture diagram, features, quick start (clone, copy .env.example, docker compose up), how to run tests, pipeline badges, screenshots
- [ ] Technical doc following the guide's 6 sections: presentation, architecture (encryption flow, ERD), security features, DevSecOps pipeline diagram + results, tests and metrics, lessons learned and future work
- [ ] Honest Limitations section: master key in env instead of a real KMS, no key rotation, single node, etc.
- [ ] Export the doc to PDF (15–20 pages target, don't pad)
- [ ] Clean the repo: remove dead code, run Gitleaks on all commits

### 📚 Learn today

- Architecture diagrams (draw.io or Mermaid in the README)
- How to write limitations and future work

> ✅ **🎯 CHECKPOINT:** someone who never saw the project can run it from the README alone in under 10 minutes (test on a clean clone). PDF exported.

---

## 📅 Day 14 – Demo, slides, CV, release

### 📋 Tasks

- [ ] Slides following the guide's 15–20 min structure: context (2), live demo (7), architecture (3), DevSecOps (4), conclusion and Q&A (4)
- [ ] Record a 3–5 min demo video: upload, encrypted blob in MinIO, share link, expiry refusal, audit logs, pipeline run with scans
- [ ] Prepare answers to likely questions (why GCM, where is the key, how do you stop IDOR, what does each scanner catch, what would you do with a real KMS)
- [ ] Tag v1.0.0, pin the repo on GitHub, add topics (devsecops, owasp, aes-256, fastapi, github-actions)
- [ ] Add the project to your CV

**CV bullets (adapt with your real numbers)**

- Built a secure file-sharing platform (FastAPI, PostgreSQL, MinIO, React) with AES-256-GCM envelope encryption, expiring/password-protected links and a full audit trail
- Designed a DevSecOps CI/CD pipeline (GitHub Actions) with Gitleaks, Semgrep, Bandit, pip-audit, Trivy and OWASP ZAP; reduced findings from X to Y (0 critical)
- Hardened containers (non-root, multi-stage, pinned images) and covered OWASP Top 10 risks with automated security tests

> ✅ **🎯 CHECKPOINT (project done):** v1.0.0 released, pipeline green, doc + slides + video ready, CV updated. You can explain every design choice without notes.

---

## ⚠️ If you fall behind

Cut in this order: frontend polish, share-with-specific-user, SonarCloud, ClamAV/2FA. Never cut: encryption, access-control tests, the CI scans, before/after reports.
