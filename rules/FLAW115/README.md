# FLAW115 — Permissive file mode

**Severity:** medium · **Tag:** security · CWE-732

## What
World- or group-writable file modes (e.g. 0666, 0777) let any local account modify the file. Limit writability to the owner; use 0600, 0640, 0644, 0700, 0750, or 0755 as appropriate.

## Fix
See the rule description and the detector at `src/rules/permissive_chmod.cr`.
