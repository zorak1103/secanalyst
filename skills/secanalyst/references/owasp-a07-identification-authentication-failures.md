# A07 — Identification and Authentication Failures

## Problem

Confirmation of the user's identity, authentication, and session management is critical to protect against authentication-related attacks. This category covers weaknesses in session tokens, password policies, credential exposure, and broken authentication flows.

Common manifestations:
- Permits brute force or automated credential stuffing attacks (no rate limiting, no lockout).
- Permits default, weak, or well-known passwords.
- Uses weak or ineffective credential recovery mechanisms (security questions, predictable tokens).
- Uses plain text, encrypted, or weakly hashed passwords (see A02).
- Exposes session tokens in URLs.
- Session tokens not invalidated on logout or after a period of inactivity.
- Long-lived JWT tokens without server-side revocation.
- Missing or ineffective multi-factor authentication.

## Prevention

1. Where possible, implement MFA to prevent automated credential stuffing, brute force, and stolen credential reuse.
2. Do not deploy with default credentials, especially for admin users.
3. Implement weak password checks against a list of the top 10,000 worst passwords (NIST SP 800-63B).
4. Align password length, complexity, and rotation policies with NIST SP 800-63B (prefer length over complexity rules).
5. Limit or increasingly delay failed login attempts; log all failures and alert admins on suspicious patterns.
6. Use a server-side, secure, built-in session manager that generates a new random session ID with high entropy after login.
7. Invalidate session IDs on logout.

## Typical Attack Scenarios

- **Credential stuffing**: An attacker takes a list of 100K email/password pairs from a previous breach and tests them against a login endpoint with no rate limiting. 1-2% typically still work.
- **Session fixation**: An attacker obtains an unauthenticated session ID and tricks a victim into authenticating with it. If the server does not rotate the session ID on login, the attacker's session becomes authenticated.
- **Insecure "remember me"**: A persistent cookie contains the user's username and hashed password in base64. An attacker who obtains the cookie can authenticate without knowing the plaintext.

## Detection Patterns (Grep)

Search for these patterns:

- Login endpoints (`/login`, `/auth`, `/signin`) without adjacent rate-limit or throttle middleware
- `remember_me` or `remember_token` cookie values derived from non-cryptographic sources
- Session ID appearing in URL query strings: `?session=`, `?PHPSESSID=`, `?JSESSIONID=`
- JWT libraries with `alg: none` accepted, or `verify: false` in JWT configuration
- Password reset tokens generated from timestamps or sequential IDs rather than `secrets.token_urlsafe()` / `crypto.randomBytes()`
- Absence of session invalidation (`.destroy()`, `.invalidate()`, `del session[key]`) in logout handlers
