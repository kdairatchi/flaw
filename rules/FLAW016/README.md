# FLAW016 — Weak TLS version

**Severity:** medium · **Tag:** crypto · CWE-326

## What
Pinning TLS minimum to SSLv3 / TLSv1.0 / TLSv1.1 keeps clients in protocols with known attacks (POODLE, BEAST, Lucky13).

## Fix
Require TLS 1.2 or 1.3. On modern OpenSSL the default is already TLS 1.2+ — don't lower it.
