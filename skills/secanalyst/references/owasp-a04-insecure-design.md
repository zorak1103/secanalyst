# A04 — Insecure Design

## Problem

Insecure design represents missing or ineffective security controls — flaws in the architecture and design phase that cannot be fixed by a perfect implementation. It differs from insecure implementation (e.g., a coding bug) in that the design itself is the vulnerability.

Common manifestations:
- Business logic that allows unlimited retries on OTP/PIN entry (no rate limiting or lockout).
- Password reset flows that rely on predictable tokens or security questions.
- Lack of tenant isolation in multi-tenant SaaS — one customer's query can touch another's data.
- No step-up authentication for sensitive operations (e.g., transferring funds, changing email).
- Reliance on client-side validation only (no server-side enforcement).
- Absence of audit trails for sensitive operations.

## Prevention

1. Use threat modeling (STRIDE, PASTA) during design reviews for every new feature.
2. Enforce rate limits and exponential backoff on all authentication and OTP endpoints.
3. Require server-side validation — never trust client-supplied data for authorization decisions.
4. Design multi-tenancy with hard database-level isolation (schemas or row-level security), not filter-level isolation.
5. Mandate step-up authentication (re-auth, MFA challenge) for high-value operations.
6. Write misuse-case tests alongside use-case tests to verify security properties.

## Typical Attack Scenarios

- An attacker brute-forces a 6-digit SMS OTP in <1 hour because there is no lockout after failed attempts.
- A "forgot password" link sends a reset URL containing the user's email base64-encoded — trivially predictable.
- In a SaaS app, query parameters include `company_id` — removing it exposes cross-tenant data because the server only filters, not isolates.

## Detection Patterns (Grep)

Look for absence of patterns rather than presence of bad patterns. Flag code that:

```
# No rate limiting on auth endpoints
app\.(post|get)\(['"](/auth|/login|/reset|/otp|/verify)['"]\)
# Followed by handler that lacks: rate_limit|rateLimit|throttle|limiter

# Client-only validation hint
# Look for validation in frontend JS with no corresponding server check:
onSubmit|handleSubmit   # in React/Vue/Angular files
# then grep server route for same input — if no validate/schema/parse: flag

# Insecure reset token generation (non-cryptographic)
reset_token.*=.*str(.*time\.|uuid\.uuid1|random\.random)
token.*=.*Date\.now\(\)
```
