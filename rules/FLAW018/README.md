# FLAW018 — Secret leaked into logs

**Severity:** high · **Tag:** logging · CWE-532

## What
A credential-named value was interpolated into `Log.*`, `puts`, or `STDERR.puts`. Logs are commonly shipped to third-party pipelines (Datadog, Loggly, CloudWatch) and searched — one leaked token can compromise everything the token reaches.

## Fix
Log a prefix (`token[0, 8]`), a hash, or just existence. Never log the raw value.
