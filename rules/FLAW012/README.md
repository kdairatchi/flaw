# FLAW012 — Non-constant-time secret comparison

**Severity:** medium · **Tag:** crypto · CWE-208

## What
`==` on strings short-circuits on the first differing byte, leaking length and prefix through timing. Given enough samples, an attacker recovers the secret byte-by-byte.

## Fix
Use `Crypto::Subtle.constant_time_compare(a, b)` for any equality check on tokens, HMACs, session IDs, or API keys.
