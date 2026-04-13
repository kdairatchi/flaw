# FLAW001 — Command Injection

**Severity:** critical · **Tag:** injection · **CWE:** [CWE-78](https://cwe.mitre.org/data/definitions/78.html)

## What

Calls to `system`, backticks, or `Process.run` built using string interpolation. If any interpolated value is attacker-controlled, the attacker can inject arbitrary shell commands.

## Why it matters

OS command injection is rated A03:2021 in the OWASP Top 10 and is typically catastrophic — attackers reach RCE from a single request.

## Fix

Use `Process.run(command, [arg1, arg2])` with an argv array. Crystal will not invoke a shell, and arguments cannot be reinterpreted as separate commands.

```crystal
# bad
system("cat #{filename}")

# good
Process.run("cat", [filename])
```

If you genuinely need a shell pipeline, pass a hardcoded template and interpolate only values you have already validated against an allowlist.
