# A09 — Security Logging and Monitoring Failures

## Problem

Without logging and monitoring, breaches cannot be detected. Insufficient logging, detection, monitoring, and active response occur when: auditable events (logins, failed logins, high-value transactions) are not logged; warnings and errors generate no, inadequate, or unclear log messages; logs are not monitored for suspicious activity; and logs are only stored locally.

Common manifestations:
- Login failures, password reset requests, and access control violations not logged.
- Logs stored only on the application server, lost when the instance is replaced.
- No alerting on repeated authentication failures (brute force goes undetected for hours/days).
- Log entries contain sensitive data (passwords, session tokens, full PII) in plaintext.
- Application exceptions swallowed silently with no logging.
- No distributed tracing or correlation IDs across microservices.

## Prevention

1. Ensure all login, access control, and server-side input validation failures can be logged with sufficient user context to identify suspicious or malicious accounts.
2. Ensure logs are generated in a format that can be easily consumed by centralized log management solutions.
3. Ensure high-value transactions have an audit trail with integrity controls to prevent tampering or deletion.
4. Establish effective monitoring and alerting so suspicious activities are detected and responded to quickly.
5. Establish an incident response and recovery plan.
6. Never log raw credentials, session tokens, full payment card numbers, or unmasked PII.

## What Should Be Logged

| Event | Required fields |
|---|---|
| Login (success/failure) | timestamp, user, IP, user-agent, result |
| Password change | timestamp, user, IP, method |
| Admin action | timestamp, admin, target, action, reason |
| Access control failure | timestamp, user, resource, HTTP method |
| Input validation failure | timestamp, endpoint, field name (not value) |
| Dependency CVE detected | timestamp, package, version, CVE ID |

## Typical Attack Scenarios

- An attacker performs credential stuffing against a login endpoint at 1,000 req/min. No logs exist for authentication failures. The breach is only discovered three months later when customer accounts show unusual activity.
- A SQL injection attack extracts a complete user table over 8 hours. Because database query times and error responses are not logged, no anomaly was detected.
- Sensitive PII is logged in full as part of request body logging. The log file is later exposed, constituting a separate breach.

## Detection Patterns (Grep)

- Authentication routes (`/login`, `/auth`) with no adjacent logging call (`log.warn`, `logger.info`, etc.)
- Catch blocks that are empty or contain only `pass` / `// ignored` comments
- Logging statements that interpolate request body or user-supplied values directly into the message string (risk of PII leakage)
- Absence of a centralized logging import (`winston`, `logback`, `structlog`, `zap`) in server entry points
