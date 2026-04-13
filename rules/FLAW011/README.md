# FLAW011 — SSRF via user-controlled URL

**Severity:** high · **Tag:** security · CWE-918

## What
Building an outbound URL from user input without validating the host lets an attacker pivot to internal services — AWS/GCP metadata, localhost admin panels, RFC1918 IPs.

## Fix
Parse the URL, extract the host, check it against an allowlist, and reject loopback/link-local/private ranges before issuing the request.
