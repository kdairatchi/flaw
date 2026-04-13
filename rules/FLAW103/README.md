# FLAW103 — Unfinished stub

**Severity:** medium · **Tag:** ai-slop · CWE-1163

## What
A method body is `raise NotImplementedError`, or a `# TODO: implement` / `# implement this` / `# stub` comment is the only thing in the body. Common AI scaffolding that ships to prod if review misses it.

## Fix
Replace with a real implementation, or delete the stub entirely.
