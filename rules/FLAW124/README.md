# FLAW124 — Log injection

**Severity:** low · **Tag:** security · CWE-117

## What
Writing raw user input into log messages lets an attacker inject CRLF sequences to forge log entries, poison log aggregators, or break JSON log parsers. Use structured logging and pass untrusted values as fields, not format args.

## Fix
See the rule description and the detector at `src/rules/log_injection.cr`.
