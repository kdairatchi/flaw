# FLAW005 — Unsafe YAML Load

**Severity:** medium · **Tag:** deserialization · **CWE:** [CWE-502](https://cwe.mitre.org/data/definitions/502.html)

## What

`YAML.parse` is called with data from an untrusted source — STDIN, ARGV, an HTTP request body, or a file path the user controls.

## Why it matters

Even Crystal's YAML (which does not instantiate arbitrary types) can be abused for DoS via billion-laughs, gigantic document nesting, or unexpected schema mismatches that crash downstream code.

## Fix

- Parse only trusted file paths.
- Use `YAML::Serializable` with a typed struct so unexpected keys are handled.
- Validate size limits before reading.

```crystal
struct AppConfig
  include YAML::Serializable
  getter name : String
end

AppConfig.from_yaml(File.read("/etc/app/config.yml"))
```
