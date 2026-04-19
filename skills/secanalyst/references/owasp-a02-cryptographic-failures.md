# A02 — Cryptographic Failures

## Problem

Failures related to cryptography often lead to exposure of sensitive data. This includes data in transit (not using TLS) and data at rest (not encrypting at all, or using weak/outdated algorithms). Previously called "Sensitive Data Exposure".

Common manifestations:
- Passwords stored with MD5/SHA-1 (fast hashes, trivially crackable with rainbow tables).
- Symmetric encryption using ECB mode (identical plaintext blocks produce identical ciphertext — patterns leak).
- Hardcoded or static IV/nonce in AES-CBC or AES-CTR.
- TLS 1.0/1.1 still accepted (BEAST, POODLE vulnerabilities).
- Certificates not validated (`verify=False` in Python requests, `InsecureSkipVerify: true` in Go).
- Random number generation using `Math.random()` or `rand()` for security tokens.

## Prevention

1. Use bcrypt, scrypt, Argon2, or PBKDF2 for password hashing — never SHA-2 or MD5 for passwords.
2. Use AES-256-GCM (authenticated encryption) — not ECB, not CBC without MAC.
3. Generate IVs/nonces randomly per encryption operation; never reuse.
4. Enforce TLS 1.2+ and use HSTS headers.
5. Use `secrets` (Python), `crypto.randomBytes()` (Node.js), or `crypto/rand` (Go) for token generation.
6. Never disable certificate validation outside of local development.

## Typical Attack Scenarios

- Database dump exposed: passwords stored as unsalted MD5 hashes are cracked within hours using a GPU wordlist attack.
- CBC padding oracle: an API endpoint reveals whether decryption padding was valid, allowing byte-by-byte plaintext recovery without the key.
- Weak PRNG: session tokens generated with `Math.random()` are predictable — an attacker can enumerate valid session IDs.

## Detection Patterns (Grep)

```
# Weak hash functions for passwords
(?i)(md5|sha1|sha-1)\s*\(
hashlib\.md5|hashlib\.sha1
MessageDigest\.getInstance\("(MD5|SHA-1)"\)

# Disabled TLS verification
verify\s*=\s*False
InsecureSkipVerify\s*:\s*true
NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']0["']

# ECB mode (Java/Python)
AES/ECB
Cipher\.getInstance\("AES"\)         # Java default is ECB if mode not specified
AES\.new\(.*AES\.MODE_ECB

# Insecure PRNG for security context
Math\.random\(\).*token
Math\.random\(\).*session
Math\.random\(\).*secret
```
