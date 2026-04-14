# FLAW137 — Possible provider token

**Severity:** high · **Tag:** security · CWE-798

## What
Detects modern provider credentials (OpenAI, Anthropic, HuggingFace, npm, PyPI, Vault, Telegram, Discord, Twilio, SendGrid, Mailgun) in source. Rotate any match immediately and move to a secret manager.

## Fix
See the rule description and the detector at `src/rules/extended_secrets.cr`.
