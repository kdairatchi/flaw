# FLAW129 — Inline event handler attribute

**Severity:** low · **Tag:** security · CWE-79

## What
Inline event handler attributes (onclick=, onload=, etc.) force a relaxed Content-Security-Policy — either 'unsafe-inline' on script-src or explicit unsafe-hashes. Any injected HTML can then execute script. Move handlers to addEventListener in a separate file and tighten CSP.

## Fix
See the rule description and the detector at `src/rules/inline_event_handler.cr`.
