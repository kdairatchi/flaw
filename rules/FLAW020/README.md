# FLAW020 — ECB cipher mode

**Severity:** high · **Tag:** crypto · CWE-327

## What
ECB encrypts identical plaintext blocks to identical ciphertext — the "ECB penguin". It also provides no authentication.

## Fix
Use an AEAD mode: `aes-256-gcm` or `chacha20-poly1305`, with a fresh per-message IV.
