# FLAW139 — Remote script piped to shell

**Severity:** high · **Tag:** security · CWE-494

## What
`curl URL | bash` (and variants) executes whatever the server returns with no hash pinning and no TLS failure stop. A one-time MITM or a compromised CDN becomes RCE. Download, verify a known SHA-256, then execute.

## Fix
See the rule description and the detector at `src/rules/curl_pipe_shell.cr`.
