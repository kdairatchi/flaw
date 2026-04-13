# FLAW004 — Weak Randomness for Security Value

**Severity:** high · **Tag:** crypto · **CWE:** [CWE-338](https://cwe.mitre.org/data/definitions/338.html)

## What

Security-sensitive values (tokens, OTPs, nonces, session IDs, reset codes, API keys) generated with non-cryptographic RNG (`rand`, `Random.new`, `Random::DEFAULT`). These are predictable from prior outputs given enough samples.

## Fix

Use `Random::Secure` — Crystal's stdlib CSPRNG backed by the OS entropy source.

```crystal
# bad
token = Random.new.hex(16)

# good
token = Random::Secure.hex(16)
```
