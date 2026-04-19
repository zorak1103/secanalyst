---
name: secanalyst
description: Scan a codebase (local path, GitHub URL, or GitLab URL) for OWASP Top 10 vulnerabilities, hardcoded secrets, and dependency CVEs. Produces an /audit/<date>/ report with verified findings, risk score, and static exploit proof-of-concept code.
---

# Security Analyst Skill

Automated security scanning workflow for software projects, grounded in OWASP Top 10 and dependency vulnerability databases. Findings are triaged through an adversarial challenger loop to minimize false positives before reporting.

## When to Activate

- A project needs a security audit before deployment or a compliance review.
- A new open-source dependency has been added and CVE exposure is unknown.
- A GitHub or GitLab repository URL is provided as a scan target.
- A developer asks "is this repo secure?" or "what vulnerabilities does this have?".
- After a security incident, to characterize the attack surface.

## Inputs

| Input type | Format | Example |
|---|---|---|
| Local directory | Absolute or relative path | `D:/projects/myapp` |
| GitHub repository | HTTPS URL | `https://github.com/owner/repo` |
| GitLab repository | HTTPS URL | `https://gitlab.com/owner/repo` |

The scan target is passed as the first argument to `/secanalyst`.

## Prerequisites

All CLIs below must be available on `$PATH`. Check and install as needed before running a scan.

```bash
# Repository cloning
gh --version          # GitHub CLI — https://cli.github.com
glab --version        # GitLab CLI — https://gitlab.com/gitlab-org/cli

# Primary vulnerability scanners (at least one required)
osv-scanner --version # Google OSV — https://google.github.io/osv-scanner
semgrep --version     # Static analysis — https://semgrep.dev

# Ecosystem-native fallbacks (used when osv-scanner unavailable)
npm audit --version   # Node.js — bundled with npm ≥ 6
pip-audit --version   # Python — pip install pip-audit
govulncheck -h        # Go — go install golang.org/x/vuln/cmd/govulncheck@latest
cargo audit --version # Rust — cargo install cargo-audit
```

Optional but expands secret detection:
```bash
trivy --version       # Aqua — https://aquasecurity.github.io/trivy
```

Windows Git Bash notes:
- Always clone with `-c core.autocrlf=false` to prevent line-ending changes that skew line-number reporting.
- Ensure `git config --global core.longpaths true` for repos with deep `node_modules`.

## Scan Procedure

### Phase 1 — Intake

Determine the target type:

```bash
# GitHub URL
if echo "$TARGET" | grep -qE '^https://github\.com/'; then
  REPO_NAME=$(echo "$TARGET" | sed 's|https://github.com/||' | tr '/' '-')
  gh repo clone "$TARGET" "./workdir/$REPO_NAME" -- \
    -c core.autocrlf=false -c core.eol=lf \
    --depth 1 --single-branch
  TARGET="./workdir/$REPO_NAME"

# GitLab URL
elif echo "$TARGET" | grep -qE '^https://gitlab\.com/'; then
  REPO_NAME=$(echo "$TARGET" | sed 's|https://gitlab.com/||' | tr '/' '-')
  glab repo clone "$TARGET" "./workdir/$REPO_NAME" -- \
    -c core.autocrlf=false -c core.eol=lf \
    --depth 1 --single-branch
  TARGET="./workdir/$REPO_NAME"
fi
```

Fail fast if workdir already exists (`[ -e "./workdir/$REPO_NAME" ] && exit 1`).

### Phase 2 — Scope guard

```bash
FILE_COUNT=$(find "$TARGET" \
  -not \( -path "*/node_modules/*" -o -path "*/.git/*" \
         -o -path "*/vendor/*" -o -path "*/dist/*" \
         -o -path "*/build/*" \) \
  -type f | wc -l)

DIR_SIZE_MB=$(du -sm "$TARGET" | cut -f1)

if [ "$FILE_COUNT" -gt 10000 ] || [ "$DIR_SIZE_MB" -gt 500 ]; then
  echo "Scan aborted: target exceeds scope cap ($FILE_COUNT files, ${DIR_SIZE_MB}MB)."
  echo "Narrow the target directory or exclude large subtrees with .semgrepignore."
  exit 1
fi
```

Skip patterns apply to all subsequent phases: `node_modules`, `.git`, `vendor`, `dist`, `build`, `__pycache__`, `.tox`, `target/` (Maven/Cargo).

### Phase 3 — Inventory

Identify languages, frameworks, and package manifests to focus scanning:

```bash
# Detect package manifests
ls "$TARGET"/package.json "$TARGET"/package-lock.json  2>/dev/null  # Node
ls "$TARGET"/requirements*.txt "$TARGET"/Pipfile.lock   2>/dev/null  # Python
ls "$TARGET"/go.sum                                      2>/dev/null  # Go
ls "$TARGET"/Cargo.lock                                  2>/dev/null  # Rust
ls "$TARGET"/pom.xml "$TARGET"/build.gradle              2>/dev/null  # Java
```

Use Glob (`**/*.{js,ts,py,go,java,rb,php,cs,rs,cpp}`) to identify source-language distribution before choosing semgrep rulesets.

### Phase 4 — Static analysis (SAST)

Run semgrep with OWASP-aligned rulesets. Map to the categories in `references/`:

```bash
semgrep scan \
  --config "p/owasp-top-ten" \
  --config "p/secrets" \
  --config "p/sql-injection" \
  --config "p/command-injection" \
  --config "p/insecure-crypto" \
  --json \
  --exclude "node_modules,vendor,.git,dist,build" \
  "$TARGET" \
  > semgrep-results.json
```

If semgrep is unavailable, fall back to Grep patterns from each `references/owasp-a0*.md` document. Apply them as Grep tool calls rather than shell-level `grep` — this is more portable across harnesses.

### Phase 5 — Secret detection

Priority order:

```bash
# Option A — trivy (if installed)
trivy fs --scanners secret --format json "$TARGET" > secrets-results.json

# Option B — regex sweep (always available)
# Patterns listed in references/hardcoded-secrets.md
```

Use the regex patterns in `references/hardcoded-secrets.md` as the authoritative list regardless of which tool runs first.

### Phase 6 — Dependency scanning

```bash
# Primary: osv-scanner covers all lockfiles in one pass
osv-scanner --recursive "$TARGET" --format json > osv-results.json

# Fallback chain (run only if osv-scanner not found)
[ -f "$TARGET/package-lock.json" ] && npm audit --json > npm-audit.json
[ -f "$TARGET/requirements.txt" ]  && pip-audit --requirement "$TARGET/requirements.txt" -f json > pip-audit.json
[ -f "$TARGET/go.sum" ]            && (cd "$TARGET" && govulncheck ./... 2>&1) > govulncheck.json
[ -f "$TARGET/Cargo.lock" ]        && (cd "$TARGET" && cargo audit --json) > cargo-audit.json
```

### Phase 7 — Triage loop

For each candidate finding from Phases 4–6:

1. Extract: category, file path, line range, code snippet (±10 lines of context).
2. Dispatch to the Challenger with the full finding context.
3. Challenger returns: `confirmed` | `false_positive` | `needs_more_context` + reasoning.
4. If `needs_more_context`: gather the requested context and repeat (max 3 total rounds).
5. After 3 rounds without consensus: classify as `disputed`.

**Verdict mapping:**

| Challenger verdict | Classification | Include in report? |
|---|---|---|
| `confirmed` | Verified vulnerability | Yes — main findings |
| `false_positive` | Discarded | Appendix B only |
| `disputed` (3 rounds) | Disputed | Appendix A + both arguments |

### Phase 8 — Exploit drafting

For each `confirmed` finding, draft a static proof-of-concept. The PoC is written to `audit/<YYYY-MM-DD>/exploits/<finding-id>.<ext>` and **never executed**. See `references/` docs for language-appropriate exploit templates per category.

PoC files must include a header comment block:

```
# PROOF OF CONCEPT — NOT EXECUTED
# Finding: <finding-id>
# Category: <OWASP category>
# Target file: <file>:<line>
# How to test: <manual steps for a security engineer to reproduce safely>
# Remediation: <one-line fix>
```

### Phase 9 — Report generation

Write the following output structure:

```
<target>/audit/<YYYY-MM-DD>/
├── report.md
├── findings.json
├── exploits/
│   └── <finding-id>.<ext>
└── scan-metadata.json
```

## Severity & Risk Score

**Severity grades:**

| Grade | CVSS range | Criteria |
|---|---|---|
| Critical | 9.0–10 | Remote code execution, unauthenticated auth bypass, data exfiltration |
| High | 7.0–8.9 | SQLi, XSS with session theft, hardcoded prod secrets, SSRF to internal |
| Medium | 4.0–6.9 | Stored XSS (limited impact), insecure direct object reference, weak crypto |
| Low | 0.1–3.9 | Information disclosure, verbose error messages, non-exploitable misconfig |

**Overall Risk Score formula** (0–10, two decimal places):

```
score = min(10, (Critical×10 + High×7 + Medium×4 + Low×1) / max(1, total_verified))
```

Include in the report summary alongside a plain-English label: `Critical` (≥8), `High` (≥6), `Medium` (≥4), `Low` (≥2), `Minimal` (<2).

## Report Layout

### `report.md`

```markdown
# Security Audit Report
Target: <target name>
Date: <YYYY-MM-DD>
Risk Score: <N.NN> / 10 (<label>)

## Summary
<2-3 sentence executive summary>

## Severity Breakdown
| Severity | Count |
|---|---|
| Critical | N |
| High | N |
| Medium | N |
| Low | N |
| Total verified | N |
| Disputed | N |
| False positives | N |

## Verified Findings
### <finding-id>: <title>
- **Category**: <OWASP category>
- **Severity**: <Critical/High/Medium/Low>
- **File**: `<path>:<line>`
- **Code snippet**: (fenced block)
- **Security claim**: <one sentence>
- **Challenger response**: <one sentence>
- **Final verdict**: Confirmed
- **Remediation**: <concrete fix>
- **Exploit**: `exploits/<finding-id>.<ext>` (static PoC, not executed)

## Dependency CVEs
| Package | Version | CVE | CVSS | Fix version |
|---|---|---|---|---|

## Appendix A: Disputed Findings
## Appendix B: False Positives
```

### `findings.json`

Machine-readable array with fields: `id`, `category`, `severity`, `file`, `line_start`, `line_end`, `title`, `verdict`, `remediation`, `cve` (if applicable), `exploit_file`.

### `scan-metadata.json`

Fields: `scan_date`, `target`, `file_count`, `size_mb`, `tool_versions` (object), `duration_seconds`, `skill_version: "1.0"`.

## Anti-Patterns

```
# BAD: Reporting without challenger triage
→ bloats the report with noise; developers stop trusting it

# BAD: Running the PoC exploit automatically
→ may trigger real network calls, write files, or hit production APIs

# BAD: Including only "confirmed" findings and silently dropping disputes
→ hides grey-area issues that a human security engineer should review

# BAD: Scanning without --depth 1 clone
→ downloads full git history; slow and irrelevant for runtime analysis

# BAD: Forgetting -c core.autocrlf=false on Windows
→ line numbers in the report will not match what the developer sees in their editor
```

## Checklist

Before marking a scan complete:

- [ ] Target resolved to a local path (cloned if remote)
- [ ] Scope guard passed (<10k files, <500 MB)
- [ ] semgrep ran (or Grep fallback documented in scan-metadata.json)
- [ ] Secret detection ran (trivy or regex)
- [ ] Dependency scan ran (osv-scanner or ecosystem fallbacks)
- [ ] Every candidate finding went through at least 1 Challenger round
- [ ] Findings classified: confirmed / disputed / false_positive
- [ ] Exploit PoCs written for all confirmed findings
- [ ] Risk Score computed and present in summary
- [ ] `audit/<YYYY-MM-DD>/` directory written inside target root
- [ ] `scan-metadata.json` records tool versions actually used

## Reference Documents

See `references/` directory alongside this skill for per-category OWASP guides:

| File | Covers |
|---|---|
| `owasp-a01-broken-access-control.md` | A01 Broken Access Control |
| `owasp-a02-cryptographic-failures.md` | A02 Cryptographic Failures |
| `owasp-a03-injection.md` | A03 Injection (SQLi, OS Cmd, Code Exec) |
| `owasp-a04-insecure-design.md` | A04 Insecure Design |
| `owasp-a05-security-misconfiguration.md` | A05 Security Misconfiguration |
| `owasp-a06-vulnerable-components.md` | A06 Vulnerable and Outdated Components |
| `owasp-a07-identification-authentication-failures.md` | A07 Identification & Auth Failures |
| `owasp-a08-software-data-integrity-failures.md` | A08 Software & Data Integrity Failures |
| `owasp-a09-logging-monitoring-failures.md` | A09 Logging & Monitoring Failures |
| `owasp-a10-ssrf.md` | A10 Server-Side Request Forgery |
| `hardcoded-secrets.md` | Hardcoded secrets & credential exposure |
