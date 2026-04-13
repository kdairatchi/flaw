# FLAW021 — Hardcoded IV / nonce / salt

**Severity:** high · **Tag:** crypto · CWE-329

## What
Reusing an IV with a stream or AEAD cipher leaks plaintext XOR pairs. With GCM, nonce reuse lets an attacker recover the authentication key.

## Fix
Generate a fresh `Random::Secure.random_bytes(12)` (GCM) or `random_bytes(16)` (salt) per message and prepend it to the ciphertext.
