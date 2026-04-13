# FLAW104 — Broad swallow rescue

**Severity:** low · **Tag:** ai-slop · CWE-390

## What
`rescue Exception`, `rescue Object`, or an empty `rescue; end` catches everything and drops it on the floor. Hides real faults — including security-relevant ones like TLS verify failures.

## Fix
Catch the specific exception type. At minimum, log the error and re-raise if you can't handle it meaningfully.
