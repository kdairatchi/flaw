# FLAW014 — XML external entity (XXE)

**Severity:** high · **Tag:** injection · CWE-611

## What
Crystal's `XML` wraps libxml2, which resolves external entities by default. Parsing attacker-controlled XML allows file disclosure (`file:///etc/passwd`) and SSRF (`http://internal/`).

## Fix
Pass `XML::ParserOptions::NONET` and validate the payload structure out-of-band. Reject any XML containing `<!DOCTYPE` / `<!ENTITY` unless required.
