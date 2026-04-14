# FLAW141 — Large base64 blob

**Severity:** medium · **Tag:** security · CWE-506

## What
A 500+ character base64 string literal is rarely legitimate source code. It is the dominant signature of payload smuggling, embedded malware, and encoded configuration blobs. Move to an external asset or mark intent with `# pragma: base64-allow`.

## Fix
See the rule description and the detector at `src/rules/base64_blob.cr`.
