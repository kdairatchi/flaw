# FLAW132 — Log4Shell JNDI payload

**Severity:** critical · **Tag:** security · CWE-917

## What
The ${jndi:...} payload string is the Log4Shell exploit trigger (CVE-2021-44228). Finding it in source usually means either a test fixture, an embedded exploit, or a deny-list regex. All three are worth eyeballing.

## Fix
See the rule description and the detector at `src/rules/log4shell_jndi.cr`.
