# FLAW102 — Placeholder Value

**Severity:** medium · **Tag:** ai-slop

## What

String literals like `"your-api-key-here"`, `"REPLACE_ME"`, `"<YOUR_TOKEN>"`, `"changeme"`, or long runs of `x` that were never replaced with real configuration.

## Why it matters

At best it's a dead config path that will `nil`-fail in production. At worst the placeholder is the value the code actually uses in production, and the app silently points at the wrong endpoint, fails authentication in a way that looks intentional, or serves a visible placeholder to users.

## Fix

Read from `ENV` with a real fallback or a hard raise so missing config is loud, not silent.

```crystal
API_KEY = ENV["APP_API_KEY"]? || raise "APP_API_KEY missing"
```
