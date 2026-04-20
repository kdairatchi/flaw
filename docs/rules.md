---
title: Rules
nav_order: 4
permalink: /rules/
---

# Rules
{: .no_toc }

flaw ships **83 rules** across two ID ranges. Each lives in its own
folder under [`rules/`](https://github.com/kdairatchi/flaw/tree/main/rules)
with the detector, fixtures, metadata, and per-rule docs. The
[per-rule README for each rule](https://github.com/kdairatchi/flaw/tree/main/rules)
goes deeper on *what*, *why*, and *how to fix*.

1. TOC
{:toc}

---

## Security — `FLAW0xx` (24 rules)

Real vulnerabilities. Default severity is medium+; designed for
`--fail-on high` in CI.

| ID | Severity | Flaw |
|---|---|---|
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW001/README.md">FLAW001</a> | <span class="sev sev-critical">critical</span> | Command built from string interpolation |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW002/README.md">FLAW002</a> | <span class="sev sev-high">high</span> | Hardcoded secret literal |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW003/README.md">FLAW003</a> | <span class="sev sev-high">high</span> | SQL built via interpolation or concatenation |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW004/README.md">FLAW004</a> | <span class="sev sev-high">high</span> | Non-cryptographic RNG for security-sensitive value |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW005/README.md">FLAW005</a> | <span class="sev sev-medium">medium</span> | YAML parsed from untrusted input |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW006/README.md">FLAW006</a> | <span class="sev sev-high">high</span> | File access with user-controlled path |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW007/README.md">FLAW007</a> | <span class="sev sev-medium">medium</span> | Redirect to user-supplied URL without allowlist |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW008/README.md">FLAW008</a> | <span class="sev sev-high">high</span> | Deserialization of untrusted data |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW009/README.md">FLAW009</a> | <span class="sev sev-high">high</span> | Weak hash (MD5/SHA1) for password or integrity |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW010/README.md">FLAW010</a> | <span class="sev sev-high">high</span> | TLS certificate verification disabled |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW011/README.md">FLAW011</a> | <span class="sev sev-high">high</span> | Outbound HTTP to user-controlled URL (SSRF) |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW012/README.md">FLAW012</a> | <span class="sev sev-medium">medium</span> | Secret compared with `==` (timing attack) |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW013/README.md">FLAW013</a> | <span class="sev sev-medium">medium</span> | Tempfile created without atomic `O_EXCL` |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW014/README.md">FLAW014</a> | <span class="sev sev-high">high</span> | XML parsed without disabling external entities (XXE) |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW015/README.md">FLAW015</a> | <span class="sev sev-medium">medium</span> | Privilege field exposed through Serializable |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW016/README.md">FLAW016</a> | <span class="sev sev-medium">medium</span> | TLS minimum version set to a deprecated protocol |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW017/README.md">FLAW017</a> | <span class="sev sev-low">low</span> | Regex with nested quantifiers (ReDoS) |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW018/README.md">FLAW018</a> | <span class="sev sev-high">high</span> | Secret-named value written to log or stdout |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW019/README.md">FLAW019</a> | <span class="sev sev-medium">medium</span> | Cookie without Secure / HttpOnly / SameSite |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW020/README.md">FLAW020</a> | <span class="sev sev-high">high</span> | ECB cipher mode used |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW021/README.md">FLAW021</a> | <span class="sev sev-high">high</span> | Hardcoded IV / nonce / salt |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW022/README.md">FLAW022</a> | <span class="sev sev-high">high</span> | Archive entry extracted without normalization (zip-slip) |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW023/README.md">FLAW023</a> | <span class="sev sev-critical">critical</span> | JWT with `alg:none` or verification disabled |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW024/README.md">FLAW024</a> | <span class="sev sev-high">high</span> | CORS wildcard / echoed origin with credentials |

---

## AI-slop hygiene — `FLAW100`–`FLAW108`

Detect unedited LLM paste-through. Novel territory: no other linter
looks for these. Low/medium severity, meant for `--fail-on medium` in
CI once the codebase is clean.

| ID | Severity | Flaw |
|---|---|---|
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW100/README.md">FLAW100</a> | <span class="sev sev-low">low</span> | Explanatory narration comment ("This function does X") |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW101/README.md">FLAW101</a> | <span class="sev sev-medium">medium</span> | AI assistant boilerplate in strings or comments |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW102/README.md">FLAW102</a> | <span class="sev sev-medium">medium</span> | Placeholder value left in source (`your-api-key-here`) |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW103/README.md">FLAW103</a> | <span class="sev sev-medium">medium</span> | Unfinished stub (`raise NotImplementedError`) |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW104/README.md">FLAW104</a> | <span class="sev sev-low">low</span> | Broad swallow rescue (`rescue Exception; nil`) |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW105/README.md">FLAW105</a> | <span class="sev sev-high">high</span> | Commented-out authorization / auth check |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW108/README.md">FLAW108</a> | <span class="sev sev-low">low</span> | AI-slop marker left in source |

---

## Design &amp; accessibility

Token drift and a11y — these catch regressions in token files,
Tailwind, and semantic HTML. Low/info severity; run on design system
repos with `--include-tag design` or `--include-tag a11y`.

| ID | Severity | Flaw |
|---|---|---|
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW106/README.md">FLAW106</a> | <span class="sev sev-low">low</span> | Raw color literal outside token file |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW109/README.md">FLAW109</a> | <span class="sev sev-low">low</span> | Low color contrast (WCAG AA fail) |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW111/README.md">FLAW111</a> | <span class="sev sev-low">low</span> | Mixed CSS units within one property family |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW118/README.md">FLAW118</a> | <span class="sev sev-low">low</span> | `<img>` without `alt` attribute |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW119/README.md">FLAW119</a> | <span class="sev sev-info">info</span> | Overuse of `!important` in stylesheet |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW120/README.md">FLAW120</a> | <span class="sev sev-low">low</span> | Positive `tabindex` breaks tab order |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW121/README.md">FLAW121</a> | <span class="sev sev-low">low</span> | Conflicting Tailwind utilities on same element |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW127/README.md">FLAW127</a> | <span class="sev sev-low">low</span> | `<html>` without `lang` attribute |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW128/README.md">FLAW128</a> | <span class="sev sev-low">low</span> | Click handler on non-interactive element |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW130/README.md">FLAW130</a> | <span class="sev sev-low">low</span> | Hardcoded `font-family` outside token file |

---

## Cross-language security sinks — `FLAW1xx`

Vulnerabilities found in web/JS/Python/YAML/config files beyond Crystal.
Default severity is medium+; `--include-tag security` if you want to
cut to just these.

| ID | Severity | Flaw |
|---|---|---|
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW107/README.md">FLAW107</a> | <span class="sev sev-low">low</span> | Hardcoded external URL or IP in source |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW110/README.md">FLAW110</a> | <span class="sev sev-info">info</span> | Magic number — name it as a constant |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW112/README.md">FLAW112</a> | <span class="sev sev-high">high</span> | Dynamic code execution sink (`eval`, `Function()`) |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW113/README.md">FLAW113</a> | <span class="sev sev-high">high</span> | DOM XSS sink (`innerHTML`, `document.write`) |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW114/README.md">FLAW114</a> | <span class="sev sev-medium">medium</span> | Insecure `http://` download |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW115/README.md">FLAW115</a> | <span class="sev sev-medium">medium</span> | Permissive file mode (`chmod 0777`) |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW116/README.md">FLAW116</a> | <span class="sev sev-high">high</span> | Unsafe deserialization sink (cross-language) |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW117/README.md">FLAW117</a> | <span class="sev sev-low">low</span> | `target="_blank"` without `rel="noopener"` |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW122/README.md">FLAW122</a> | <span class="sev sev-high">high</span> | Server-side template injection |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW123/README.md">FLAW123</a> | <span class="sev sev-high">high</span> | Prototype pollution sink |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW124/README.md">FLAW124</a> | <span class="sev sev-low">low</span> | Log injection |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW125/README.md">FLAW125</a> | <span class="sev sev-medium">medium</span> | TOCTOU race condition |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW126/README.md">FLAW126</a> | <span class="sev sev-high">high</span> | Shell execution with string interpolation |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW129/README.md">FLAW129</a> | <span class="sev sev-low">low</span> | Inline event-handler attribute (`onclick=`) |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW132/README.md">FLAW132</a> | <span class="sev sev-critical">critical</span> | Log4Shell JNDI payload |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW133/README.md">FLAW133</a> | <span class="sev sev-high">high</span> | NoSQL injection sink |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW134/README.md">FLAW134</a> | <span class="sev sev-medium">medium</span> | Debug enabled in production config |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW135/README.md">FLAW135</a> | <span class="sev sev-medium">medium</span> | PII written to log |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW136/README.md">FLAW136</a> | <span class="sev sev-medium">medium</span> | Cloud metadata endpoint access |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW137/README.md">FLAW137</a> | <span class="sev sev-high">high</span> | Possible provider token literal |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW138/README.md">FLAW138</a> | <span class="sev sev-high">high</span> | PowerShell encoded / hidden command |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW139/README.md">FLAW139</a> | <span class="sev sev-high">high</span> | Remote script piped to shell (`curl \| bash`) |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW140/README.md">FLAW140</a> | <span class="sev sev-high">high</span> | LOLBIN abuse signature |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW141/README.md">FLAW141</a> | <span class="sev sev-medium">medium</span> | Large base64 blob (opaque payload) |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW142/README.md">FLAW142</a> | <span class="sev sev-high">high</span> | Obfuscated code-execution chain |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW143/README.md">FLAW143</a> | <span class="sev sev-high">high</span> | Docker socket mounted into container |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW146/README.md">FLAW146</a> | <span class="sev sev-high">high</span> | Kubernetes security boundary disabled |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW147/README.md">FLAW147</a> | <span class="sev sev-high">high</span> | Security-group `0.0.0.0/0` ingress |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW148/README.md">FLAW148</a> | <span class="sev sev-medium">medium</span> | Source map shipped in production artifact |

---

## CI/CD &amp; GitHub Actions — `FLAW144`, `FLAW145`

Workflow and supply-chain hazards.

| ID | Severity | Flaw |
|---|---|---|
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW144/README.md">FLAW144</a> | <span class="sev sev-high">high</span> | `pull_request_target` + PR-head checkout |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW145/README.md">FLAW145</a> | <span class="sev sev-high">high</span> | Unsafe `github.event` expression in workflow |

---

## LLM / MCP app security — `FLAW149`–`FLAW157`

AI-stack footguns. These exist because the LLM-app ecosystem shipped
before the security patterns did. Run with `--include-tag security`
on any repo that uses an MCP server, builds prompts, or calls an LLM
with user input.

| ID | Severity | Flaw |
|---|---|---|
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW149/README.md">FLAW149</a> | <span class="sev sev-high">high</span> | Unpinned MCP / agent source |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW150/README.md">FLAW150</a> | <span class="sev sev-high">high</span> | Project-local config grants execution |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW151/README.md">FLAW151</a> | <span class="sev sev-high">high</span> | User input interpolated into system / assistant role |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW152/README.md">FLAW152</a> | <span class="sev sev-medium">medium</span> | Tool result appended to prompt without fence |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW153/README.md">FLAW153</a> | <span class="sev sev-medium">medium</span> | Model output rendered with images enabled |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW154/README.md">FLAW154</a> | <span class="sev sev-high">high</span> | Prefix check without canonicalization |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW155/README.md">FLAW155</a> | <span class="sev sev-medium">medium</span> | User-controlled LLM `max_tokens` without clamp |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW156/README.md">FLAW156</a> | <span class="sev sev-high">high</span> | Tool handler outbound request to non-literal URL |
| <a class="flaw-chip" href="https://github.com/kdairatchi/flaw/blob/main/rules/FLAW157/README.md">FLAW157</a> | <span class="sev sev-medium">medium</span> | AI-tool project config committed to repo |
