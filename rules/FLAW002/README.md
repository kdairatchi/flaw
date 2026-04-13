# FLAW002 — Hardcoded Secret

**Severity:** high · **Tag:** secrets · **CWE:** [CWE-798](https://cwe.mitre.org/data/definitions/798.html)

## What

A credential or API key is embedded directly in source. flaw matches known formats (AWS, GitHub, Stripe, Slack, Google, private-key PEM headers) and high-entropy values assigned to secret-named variables (`api_key`, `token`, `password`, …).

## Why it matters

Secrets in source leak through git history, forks, and mirrors even after removal. They also bypass secret-rotation workflows since the value is baked into builds.

## Fix

Read from environment variables, a secret manager (1Password, Vault, AWS Secrets Manager), or an untracked config file loaded at startup.

```crystal
# bad
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"

# good
aws_key = ENV["AWS_ACCESS_KEY"]? || raise "AWS_ACCESS_KEY missing"
```

If a secret is already in git history, rotate it — do not rely on removal alone.
