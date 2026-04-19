# Hardcoded Secrets

## Problem

Credentials, API keys, tokens, and private keys embedded in source code are discoverable by anyone with repository access — including public GitHub forks, former employees, and automated scanners. Unlike environment-variable leaks, code-embedded secrets persist in git history even after deletion.

## Prevention

1. Store all credentials in environment variables, a secrets manager (Vault, AWS Secrets Manager, GCP Secret Manager), or a `.env` file that is `.gitignore`-d.
2. Never commit `.env` files, even for local development.
3. Use pre-commit hooks (`git-secrets`, `gitleaks`, `detect-secrets`) to block commits containing secret patterns.
4. Rotate any credential that has appeared in a commit, even briefly.
5. Use short-lived tokens (OAuth, OIDC) over long-lived static credentials wherever possible.

## Typical Attack Scenarios

- Attacker clones a public repo, runs `git log -p | grep -i 'api_key\|password\|secret\|token'` and extracts a working AWS key within minutes.
- A developer accidentally commits `.env.local` containing a Stripe live secret key; the commit is reverted but the key lives in history.
- A CI pipeline prints `export DB_PASSWORD=...` to logs; a log-monitoring tool indexes and exposes it.

## Detection Regex Patterns (Grep)

Use these patterns in the Grep tool (or as fallback when `trivy`/`semgrep` unavailable).  
Apply to all source files, configuration files, and IaC templates; skip binary files.

```
# Generic high-entropy assignments
["\']([A-Za-z0-9+/]{32,})["\']                              # base64-looking value ≥32 chars
(?i)(password|passwd|secret|api_key|apikey|auth_token)\s*=\s*["'][^"']{8,}["']

# Provider-specific patterns
sk-[A-Za-z0-9]{48}                                           # OpenAI
sk_live_[A-Za-z0-9]{24}                                      # Stripe live
sk_test_[A-Za-z0-9]{24}                                      # Stripe test
AKIA[0-9A-Z]{16}                                             # AWS Access Key ID
AIza[0-9A-Za-z-_]{35}                                        # Google API key
ya29\.[0-9A-Za-z-_]+                                         # Google OAuth token
xox[bp]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-f0-9]{32}          # Slack token
ghp_[A-Za-z0-9]{36}                                          # GitHub Personal Access Token
glpat-[A-Za-z0-9-_]{20}                                      # GitLab PAT
-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----             # Private key block
```

## Exploit Template

```python
# PROOF OF CONCEPT — NOT EXECUTED
# Finding: secrets-001
# Category: Hardcoded Secrets
# Target file: <file>:<line>
# How to test: Extract the value at the indicated line and attempt to authenticate
#              against the target service (e.g., `curl -H "Authorization: Bearer <token>" <api_endpoint>`).
#              Verify the credential is live before reporting.
# Remediation: Move to env var; rotate the credential immediately.

import os
import requests

# Extracted credential (replace before testing)
SECRET = "REDACTED"
ENDPOINT = "https://api.example.com/v1/whoami"

# Example probe — run manually in an isolated environment
response = requests.get(ENDPOINT, headers={"Authorization": f"Bearer {SECRET}"})
print(f"Status: {response.status_code}")
print(f"Body: {response.text[:500]}")
```
