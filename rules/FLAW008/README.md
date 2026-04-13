# FLAW008 — Unsafe Deserialization

**Severity:** high · **Tag:** deserialization · **CWE:** [CWE-502](https://cwe.mitre.org/data/definitions/502.html)

## What

JSON or MessagePack is parsed from an untrusted source (request body, cookie, STDIN, ARGV) without a typed schema.

## Why it matters

Even without instantiation gadgets, unschemed parsing lets attackers smuggle unexpected shapes that crash or confuse downstream code — auth bypasses have been built from exactly this.

## Fix

Use `JSON::Serializable` on a struct that declares the exact shape you accept.

```crystal
struct CreateUser
  include JSON::Serializable
  getter name : String
  getter email : String
end

user = CreateUser.from_json(body)
```
