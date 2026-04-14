# FLAW131 — FLAW131

**Severity:** low · **Tag:** a11y · CWE-1390

## What
Setting autocomplete="off" on a password / email / username / tel input breaks password managers, which hurts both accessibility and security (users reuse weaker passwords when managers can't help). Modern browsers ignore autocomplete="off" on password fields, so this only succeeds at harming legitimate use. Remove the attribute or use a specific token like "new-password" / "current-password".

## Fix
See the rule description and the detector at `src/rules/autocomplete_off.cr`.
