# /secanalyst

Run a full OWASP Top 10 security audit on a codebase.

## Usage

```
/secanalyst <target>
```

Where `<target>` is one of:
- A local directory path: `D:/projects/myapp`
- A GitHub URL: `https://github.com/owner/repo`
- A GitLab URL: `https://gitlab.com/owner/repo`

## What Happens

This command activates the `security-scanner` agent, which:

1. Resolves the target (clones if remote using `gh` or `glab`)
2. Checks scope limits (<10k files, <500 MB)
3. Runs semgrep SAST + secret detection + dependency scanning (osv-scanner / ecosystem fallbacks)
4. Triages each candidate finding through the `security-challenger` agent (max 3 rounds)
5. Writes static exploit PoC files via the `security-exploit` agent for confirmed findings
6. Produces an audit report at `<target>/audit/<YYYY-MM-DD>/report.md`

## Prerequisites

The following tools must be on `PATH` before running:
- `gh` (GitHub CLI) and/or `glab` (GitLab CLI) — required only for remote URLs
- `semgrep` — primary SAST scanner
- `osv-scanner` — primary dependency scanner
- Ecosystem fallbacks: `npm`, `pip-audit`, `govulncheck`, `cargo audit` — used when osv-scanner unavailable

## Examples

```bash
/secanalyst D:/projects/myapi
/secanalyst https://github.com/OWASP/NodeGoat
/secanalyst https://gitlab.com/gitlab-org/gitlab-foss
```

## Output

```
<target>/audit/<YYYY-MM-DD>/
├── report.md          — Human-readable audit report with Risk Score
├── findings.json      — Machine-readable findings with triage logs
├── exploits/
│   └── <id>.py        — Static PoC exploit per confirmed finding
└── scan-metadata.json — Tool versions, scope stats, duration
```

---

Activate the `security-scanner` agent now with the provided target: $ARGUMENTS
