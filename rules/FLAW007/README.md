# FLAW007 — Open Redirect

**Severity:** medium · **Tag:** redirect · **CWE:** [CWE-601](https://cwe.mitre.org/data/definitions/601.html)

## What

A redirect is issued to a URL taken from user input. Phishing pages and OAuth `redirect_uri` bypasses rely on this exact pattern.

## Fix

Either:
- Accept only relative paths that start with `/` (and not `//`, which browsers treat as protocol-relative), or
- Parse the URL and match its host against an allowlist before redirecting.

```crystal
if raw.starts_with?("/") && !raw.starts_with?("//")
  env.redirect(raw)
end
```
