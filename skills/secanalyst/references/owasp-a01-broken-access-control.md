# A01 — Broken Access Control

## Problem

Access control enforces policy so that users cannot act outside their intended permissions. Failures typically result in unauthorized information disclosure, modification, or destruction of data, or performing business functions outside the user's limits. It is the most prevalent vulnerability class in the OWASP Top 10.

Common manifestations:
- Insecure Direct Object References (IDOR): incrementing an ID in a URL (`/orders/1001`, `/orders/1002`) exposes other users' resources.
- Missing function-level access control: an admin endpoint is hidden from the UI but not protected server-side.
- CORS misconfiguration: `Access-Control-Allow-Origin: *` on authenticated APIs.
- Privilege escalation via JWT manipulation: altering `role` claim when the signature is not verified.
- Path traversal: `../../../etc/passwd` via unvalidated user input.

## Prevention

1. Deny by default — access should be explicitly granted, not explicitly denied.
2. Implement access control once (a shared module), not per-endpoint.
3. Log access control failures and alert on repeated failures (brute-force detection).
4. Invalidate JWTs and session tokens server-side on logout.
5. Rate-limit API endpoints to reduce the window for automated IDOR enumeration.
6. Use UUIDs instead of sequential integer IDs to make enumeration harder (not a substitute for authorization checks).

## Typical Attack Scenarios

- **IDOR**: `GET /api/v1/invoices/5543` — the authenticated user is customer #42, but invoice 5543 belongs to customer #99. No ownership check in the controller.
- **Vertical privilege escalation**: `POST /admin/users/delete` has no `requireRole('admin')` middleware. Any authenticated user can hit it.
- **JWT role tampering**: Token payload `{"sub":"u1","role":"user"}` is base64-decoded, `role` changed to `"admin"`, and re-encoded. If the server uses `alg: none` or doesn't verify, the forgery succeeds.

## Detection Patterns (Grep)

```
# Missing authorization check (generic)
(?i)router\.(get|post|put|delete|patch)\([^)]+\)\s*\{[^}]*(?!auth|role|permission|authorize|require)
# IDOR — numeric ID from user-controlled input without ownership check
req\.(params|query|body)\.(id|userId|orderId|accountId)
# CORS wildcard
Access-Control-Allow-Origin:\s*\*
# JWT none algorithm
alg.*none
```
