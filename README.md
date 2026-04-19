# secanalyst — Claude Code Security Scanner Plugin

Automated OWASP Top 10 security audit for software projects. Accepts a local directory, a GitHub URL, or a GitLab URL — produces a structured report with verified findings, a Risk Score, and static proof-of-concept exploit code.

## What it does

1. **Clones** remote repos via `gh` or `glab` (shallow, LF-safe)
2. **Guards scope** — aborts above 10 000 files / 500 MB to protect context window
3. **Scans** with semgrep SAST + secret-detection + osv-scanner dependency CVEs
4. **Triages** every candidate finding through an adversarial **Challenger agent** (≤ 3 rounds) to weed out false positives
5. **Drafts static PoC exploits** for confirmed findings — written to disk, never executed
6. **Writes** `audit/<YYYY-MM-DD>/report.md` with Risk Score, severity table, remediation guidance, and dispute appendices

## Installation

### Requires Claude Code ≥ 1.x with plugin support

```bash
# Direkt aus GitHub
/plugin install zorak1103/secanalyst

# Oder via lokalem Clone
git clone https://github.com/zorak1103/secanalyst.git
/plugin install ./secanalyst
```

## Prerequisites

These CLIs must be on `PATH` before running a scan:

| Tool | Required for | Install |
|---|---|---|
| `gh` | Cloning GitHub URLs | https://cli.github.com |
| `glab` | Cloning GitLab URLs | https://gitlab.com/gitlab-org/cli |
| `semgrep` | SAST scanning | `pip install semgrep` |
| `osv-scanner` | Dependency CVEs | https://google.github.io/osv-scanner |
| `npm` | Node dep fallback | bundled with Node.js |
| `pip-audit` | Python dep fallback | `pip install pip-audit` |
| `govulncheck` | Go dep fallback | `go install golang.org/x/vuln/cmd/govulncheck@latest` |
| `cargo audit` | Rust dep fallback | `cargo install cargo-audit` |

`gh` and `glab` are only needed when scanning remote URLs, not local paths.

### Reduce permission prompts (recommended)

Add to your `~/.claude/settings.json` `permissions.allow` array:

```json
"Bash(gh repo clone:*)",
"Bash(glab repo clone:*)",
"Bash(osv-scanner:*)",
"Bash(semgrep:*)",
"Bash(npm audit:*)",
"Bash(pip-audit:*)",
"Bash(govulncheck:*)",
"Bash(cargo audit:*)"
```

Or run `/update-config` and ask Claude to add the scan tool permissions.

## Usage

```
/secanalyst <target>
```

| Target type | Example |
|---|---|
| Local directory | `/secanalyst D:/projects/myapp` |
| GitHub URL | `/secanalyst https://github.com/OWASP/NodeGoat` |
| GitLab URL | `/secanalyst https://gitlab.com/owner/repo` |

## Output

```
<target>/audit/<YYYY-MM-DD>/
├── report.md            ← human-readable report with Risk Score
├── findings.json        ← machine-readable findings + triage logs
├── exploits/
│   └── <finding-id>.py  ← static PoC (NOT executed)
└── scan-metadata.json   ← tool versions, scope stats, duration
```

### Risk Score

Weighted formula (0–10):

```
score = min(10, (Critical×10 + High×7 + Medium×4 + Low×1) / verified_count)
```

Label: **Critical** ≥ 8 · **High** ≥ 6 · **Medium** ≥ 4 · **Low** ≥ 2 · **Minimal** < 2

## Architecture

Three cooperating agents — no agent modifies source files:

| Agent | Model | Role |
|---|---|---|
| `security-scanner` | Opus | Orchestrator: runs all scan phases, dispatches sub-agents, writes report |
| `security-challenger` | Sonnet | Adversarial reviewer — disproves each finding (read-only) |
| `security-exploit` | Opus | Writes static PoC exploit files |

The **`secanalyst` skill** (`skills/secanalyst/SKILL.md`) contains the portable OWASP knowledge base — no Claude-specific tool references, reusable in other LLM harnesses.

Reference documents in `skills/secanalyst/references/` cover all OWASP A01–A10 categories plus hardcoded secrets, each with Problem / Prevention / Attack Scenarios / Detection Patterns sections.

## Covered vulnerability categories

| OWASP ID | Category |
|---|---|
| A01 | Broken Access Control |
| A02 | Cryptographic Failures |
| A03 | Injection (SQL, OS command, code eval) |
| A04 | Insecure Design |
| A05 | Security Misconfiguration |
| A06 | Vulnerable and Outdated Components |
| A07 | Identification & Authentication Failures |
| A08 | Software & Data Integrity Failures |
| A09 | Security Logging & Monitoring Failures |
| A10 | Server-Side Request Forgery (SSRF) |
| — | Hardcoded Secrets |

## Recommended test targets

```bash
# Small deliberately vulnerable Node.js app
/secanalyst https://github.com/OWASP/NodeGoat

# Deliberately vulnerable Python app
/secanalyst https://github.com/WebGoat/WebGoat
```

## License

MIT — see [LICENSE](LICENSE).
