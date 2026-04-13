# FLAW105 — Commented-out auth check

**Severity:** high · **Tag:** ai-slop · CWE-862

## What
A line that looks like an auth guard (`before_action :authenticate`, `authorize!`, `require_admin`, `halt 401`) was commented out rather than replaced. Classic "make the test pass" anti-pattern, especially from AI assistants.

## Fix
Restore the guard. If authorization really isn't needed, delete the commented line and add a comment explaining why.
