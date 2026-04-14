# FLAW135 — PII in log

**Severity:** medium · **Tag:** security · CWE-532

## What
Logging email addresses, credentials, tokens, or other PII ends up in log sinks that usually have weaker access controls than the database. Redact or hash before emitting.

## Fix
See the rule description and the detector at `src/rules/pii_in_log.cr`.
