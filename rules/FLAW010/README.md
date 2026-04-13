# FLAW010 — TLS Verification Disabled

**Severity:** high · **Tag:** crypto · **CWE:** [CWE-295](https://cwe.mitre.org/data/definitions/295.html)

## What

`OpenSSL::SSL::VerifyMode::NONE` or `verify_mode = ...NONE` silences certificate validation. Any network attacker can MITM with a self-signed cert.

## Fix

Leave verification at default. If a dev / test server has a self-signed cert, trust the specific CA explicitly rather than disabling verification globally.

```crystal
ctx = OpenSSL::SSL::Context::Client.new
ctx.ca_certificates = "/etc/ssl/my-dev-ca.pem"
```
