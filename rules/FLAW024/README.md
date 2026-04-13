# FLAW024 — CORS wildcard + credentials

**Severity:** high · **Tag:** cors · CWE-942

## What
`Allow-Origin: *` with `Allow-Credentials: true` is rejected by browsers when the wildcard is literal, but echoing back the request `Origin` achieves the same effect and is routinely shipped.

## Fix
Maintain an allowlist, match the request `Origin` exactly, and only then echo it back with `Credentials: true`.
