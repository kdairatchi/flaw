# FLAW009 — Weak Hash for Security

**Severity:** high · **Tag:** crypto · **CWE:** [CWE-328](https://cwe.mitre.org/data/definitions/328.html)

## What

MD5 or SHA1 used near a security-sensitive name (password, signature, hmac, digest). Both are collision-broken and unfit for password hashing.

## Fix

- **Passwords:** `Crypto::Bcrypt::Password.create(pw, cost: 12)`
- **Integrity:** `Digest::SHA256.hexdigest(body)` (or SHA-384/512)
- **MACs:** `OpenSSL::HMAC.hexdigest(:sha256, key, body)`
