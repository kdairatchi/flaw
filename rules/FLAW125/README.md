# FLAW125 — TOCTOU race

**Severity:** medium · **Tag:** security · CWE-367

## What
Checking if a path exists and then opening it later is racy — an attacker can swap the path for a symlink between the two calls. Open the file directly and handle the error, or use openat with O_NOFOLLOW / Crystal File.open rescue pattern.

## Fix
See the rule description and the detector at `src/rules/toctou_race.cr`.
