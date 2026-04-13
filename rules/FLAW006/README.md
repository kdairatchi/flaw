# FLAW006 — Path Traversal

**Severity:** high · **Tag:** path · **CWE:** [CWE-22](https://cwe.mitre.org/data/definitions/22.html)

## What

A file operation receives a path built from user input. Without normalisation and an allowed-root check, an attacker sends `../../../etc/passwd` and reads anything your process can.

## Fix

1. Join the user input with a fixed root.
2. Call `File.expand_path` to collapse `..` segments.
3. Verify the result still starts with the allowed root.
4. Check the file exists and is a regular file.

```crystal
candidate = File.expand_path(File.join(ROOT, name))
raise "forbidden" unless candidate.starts_with?(ROOT + "/")
```
