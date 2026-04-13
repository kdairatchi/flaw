# FLAW023 — JWT alg:none / verify:false

**Severity:** critical · **Tag:** auth · CWE-347

## What
Accepting `{"alg":"none"}` or passing `verify: false` means any attacker-forged token is trusted.

## Fix
Always decode with a pinned algorithm (`HS256`, `RS256`, `ES256`) and a key. Reject tokens whose header `alg` differs.
