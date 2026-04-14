# FLAW114 — Insecure http:// download

**Severity:** medium · **Tag:** security · CWE-494

## What
Fetching installers, archives, or scripts over plain http:// exposes the supply chain to MITM tampering. Always use https:// and, where possible, verify checksums or signatures.

## Fix
See the rule description and the detector at `src/rules/insecure_download.cr`.
