# A06 — Vulnerable and Outdated Components

## Problem

Components such as libraries, frameworks, and other software modules run with the same privileges as the application. If a vulnerable component is exploited, such an attack can facilitate serious data loss or server takeover.

Common manifestations:
- Using components with known CVEs (check NVD, OSV, Snyk).
- Not knowing the versions of all components you use (direct and transitive).
- Not fixing or upgrading underlying platforms, frameworks, and dependencies in a timely fashion.
- Not securing the component configurations (see A05).
- Fetching dependencies without integrity verification (no lockfile, no `--frozen-lockfile`).

## Prevention

1. Maintain an inventory of all components (direct and transitive) with their versions.
2. Use `osv-scanner`, `trivy`, `Dependabot`, or `Renovate` to receive automated vulnerability alerts.
3. Only obtain components from official sources over secure channels; prefer signed packages.
4. Remove unused dependencies, unnecessary features, components, files, and documentation.
5. Monitor for components that are unmaintained or don't create security patches for older versions.

## Dependency Scanner Commands

```bash
# Google OSV — multi-ecosystem, single command
osv-scanner --recursive .

# Node.js
npm audit --audit-level=moderate

# Python
pip-audit -r requirements.txt

# Go
govulncheck ./...

# Rust
cargo audit

# Java (Maven)
mvn dependency-check:check

# Container images
trivy image myapp:latest
```

## Typical Attack Scenarios

- An app uses log4j 2.14.1 with the `log4j-core` package. The CVE-2021-44228 (Log4Shell) JNDI injection vulnerability allows remote code execution via a crafted log message — exploited at massive scale in December 2021.
- A Node.js app's transitive dependency `event-stream` was compromised by a supply-chain attack injecting cryptocurrency-stealing code.
- An outdated version of `struts2` with an OGNL injection bug (CVE-2017-5638) was exploited to breach Equifax.

## Detection Patterns

- Look for lockfiles (`package-lock.json`, `yarn.lock`, `poetry.lock`, `go.sum`, `Cargo.lock`) — their absence means version pinning is not enforced.
- Check if `Dependabot` or `Renovate` configuration files are present (`.github/dependabot.yml`, `renovate.json`) — absence suggests no automated dependency updates.
- Check that lockfiles are committed to version control (not in `.gitignore`).
