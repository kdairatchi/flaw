# FLAW022 — Zip-slip

**Severity:** high · **Tag:** path-traversal · CWE-22

## What
Writing `entry.name` / `entry.filename` directly under a destination directory lets a malicious archive escape with `../../etc/passwd`-style names.

## Fix
`expand_path` the resolved target and verify it still starts with the destination root before opening.
