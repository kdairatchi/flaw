# Rules

This directory is the single source of truth for every rule `flaw` ships with. Each subdirectory holds one rule, and must contain:

```
rules/FLAWNNN/
├── rule.yml    # id, title, severity, tags, owasp, cwe, detector, references
├── bad.cr      # code that MUST fire this rule
├── good.cr     # the fixed version — MUST NOT fire this rule
└── README.md   # human docs: what, why, how to fix
```

`flaw lint-rules` enforces the contract. It validates every folder name, every `rule.yml` schema, every `detector` pointer, and runs each rule against its own `bad.cr` + `good.cr` — build fails if any drifts.

## Add a rule

```bash
flaw init rule FLAW011 my-new-rule
# scaffolds rules/FLAW011/ and src/rules/my_new_rule.cr
```

Implement the detector (it auto-registers via `Rule.inherited`), fill in `bad.cr` and `good.cr`, run `flaw lint-rules`, open a PR.

## Categories

**Security rules (`FLAW0xx`)** — real vulnerabilities, exit-code-1 in CI.

| ID | Severity | Tag | Flaw |
|---|---|---|---|
| [FLAW001](FLAW001/README.md) | critical | injection       | Command built from string interpolation |
| [FLAW002](FLAW002/README.md) | high     | secrets         | Hardcoded secret literal |
| [FLAW003](FLAW003/README.md) | high     | injection       | SQL built via interpolation/concat |
| [FLAW004](FLAW004/README.md) | high     | crypto          | Weak RNG near security-sensitive name |
| [FLAW005](FLAW005/README.md) | medium   | deserialization | YAML parsed from untrusted input |
| [FLAW006](FLAW006/README.md) | high     | path            | Path traversal via user-controlled path |
| [FLAW007](FLAW007/README.md) | medium   | redirect        | Open redirect from user-supplied URL |
| [FLAW008](FLAW008/README.md) | high     | deserialization | Unsafe deserialization of untrusted bytes |
| [FLAW009](FLAW009/README.md) | high     | crypto          | Weak hash (MD5/SHA1) for password or integrity |
| [FLAW010](FLAW010/README.md) | high     | crypto          | TLS certificate verification disabled |
| [FLAW011](FLAW011/README.md) | high     | ssrf            | Outbound HTTP request to user-controlled URL |
| [FLAW012](FLAW012/README.md) | medium   | crypto          | Secret compared with `==` (timing attack) |
| [FLAW013](FLAW013/README.md) | medium   | filesystem      | Tempfile created without atomic O_EXCL |
| [FLAW014](FLAW014/README.md) | high     | injection       | XML parsed without disabling external entities |
| [FLAW015](FLAW015/README.md) | medium   | access-control  | Privilege field exposed through Serializable |
| [FLAW016](FLAW016/README.md) | medium   | crypto          | TLS minimum version set to a deprecated protocol |
| [FLAW017](FLAW017/README.md) | low      | dos             | Regex with nested quantifiers (ReDoS) |
| [FLAW018](FLAW018/README.md) | high     | logging         | Secret-named value written to log or stdout |
| [FLAW019](FLAW019/README.md) | medium   | cookie          | Cookie without Secure / HttpOnly / SameSite flags |
| [FLAW020](FLAW020/README.md) | high     | crypto          | ECB cipher mode used |
| [FLAW021](FLAW021/README.md) | high     | crypto          | Hardcoded IV / nonce / salt |
| [FLAW022](FLAW022/README.md) | high     | path-traversal  | Archive entry extracted without normalization (zip-slip) |
| [FLAW023](FLAW023/README.md) | critical | auth            | JWT with alg:none or verify disabled |
| [FLAW024](FLAW024/README.md) | high     | cors            | CORS wildcard / echoed origin with credentials |

**AI-slop rules (`FLAW1xx`)** — code hygiene: detect unedited LLM paste-through. Low/medium severity, meant for `--fail-on medium` in CI after the codebase is clean.

| ID | Severity | Tag | Flaw |
|---|---|---|---|
| [FLAW100](FLAW100/README.md) | low      | ai-slop  | Explanatory narration comment ("This function does X") |
| [FLAW101](FLAW101/README.md) | medium   | ai-slop  | AI assistant boilerplate in strings or comments |
| [FLAW102](FLAW102/README.md) | medium   | ai-slop  | Placeholder value never replaced (`your-api-key-here`, `REPLACE_ME`) |
| [FLAW103](FLAW103/README.md) | medium   | ai-slop  | Unfinished stub (`raise NotImplementedError`, `# TODO: implement`) |
| [FLAW104](FLAW104/README.md) | low      | ai-slop  | Broad swallow rescue (`rescue Exception; nil`) |
| [FLAW105](FLAW105/README.md) | high     | ai-slop  | Commented-out authorization / authentication check |
| [FLAW108](FLAW108/README.md) | low      | ai-slop  | AI slop marker in source (leftover LLM scaffolding) |

**Design / a11y rules** — token drift and accessibility.

| ID | Severity | Tag | Flaw |
|---|---|---|---|
| [FLAW106](FLAW106/README.md) | low      | design   | Raw color literal outside token file |
| [FLAW109](FLAW109/README.md) | low      | design   | Low color contrast (WCAG AA fail) |
| [FLAW111](FLAW111/README.md) | low      | design   | Mixed CSS units within one property family |
| [FLAW118](FLAW118/README.md) | low      | a11y     | `<img>` without `alt` attribute |
| [FLAW119](FLAW119/README.md) | info     | design   | Overuse of `!important` in stylesheet |
| [FLAW120](FLAW120/README.md) | low      | a11y     | Positive `tabindex` breaks tab order |
| [FLAW121](FLAW121/README.md) | low      | design   | Conflicting Tailwind utilities on same element |
| [FLAW127](FLAW127/README.md) | low      | a11y     | `<html>` without `lang` attribute |
| [FLAW128](FLAW128/README.md) | low      | a11y     | Click handler on non-interactive element |
| [FLAW130](FLAW130/README.md) | low      | design   | Hardcoded `font-family` outside token file |

**Security sinks (`FLAW1xx`)** — vulnerabilities found in web/LLM/CI landscapes beyond Crystal.

| ID | Severity | Tag | Flaw |
|---|---|---|---|
| [FLAW107](FLAW107/README.md) | low      | hygiene  | Hardcoded external URL or IP in source |
| [FLAW110](FLAW110/README.md) | info     | hygiene  | Magic number — name it as a constant |
| [FLAW112](FLAW112/README.md) | high     | security | Dynamic code execution sink (`eval`, `Function()`) |
| [FLAW113](FLAW113/README.md) | high     | security | DOM XSS sink (`innerHTML`, `document.write`) |
| [FLAW114](FLAW114/README.md) | medium   | security | Insecure `http://` download |
| [FLAW115](FLAW115/README.md) | medium   | security | Permissive file mode (`chmod 0777`) |
| [FLAW116](FLAW116/README.md) | high     | security | Unsafe deserialization sink (cross-language) |
| [FLAW117](FLAW117/README.md) | low      | security | `target="_blank"` without `rel="noopener"` |
| [FLAW122](FLAW122/README.md) | high     | security | Server-side template injection |
| [FLAW123](FLAW123/README.md) | high     | security | Prototype pollution sink |
| [FLAW124](FLAW124/README.md) | low      | security | Log injection |
| [FLAW125](FLAW125/README.md) | medium   | security | TOCTOU race condition |
| [FLAW126](FLAW126/README.md) | high     | security | Shell execution with string interpolation |
| [FLAW129](FLAW129/README.md) | low      | security | Inline event-handler attribute (`onclick=`) |
| [FLAW132](FLAW132/README.md) | critical | security | Log4Shell JNDI payload |
| [FLAW133](FLAW133/README.md) | high     | security | NoSQL injection sink |
| [FLAW134](FLAW134/README.md) | medium   | security | Debug enabled in production config |
| [FLAW135](FLAW135/README.md) | medium   | security | PII written to log |
| [FLAW136](FLAW136/README.md) | medium   | security | Cloud metadata endpoint access |
| [FLAW137](FLAW137/README.md) | high     | security | Possible provider token literal |
| [FLAW138](FLAW138/README.md) | high     | security | PowerShell encoded / hidden command |
| [FLAW139](FLAW139/README.md) | high     | security | Remote script piped to shell (`curl \| bash`) |
| [FLAW140](FLAW140/README.md) | high     | security | LOLBIN abuse signature |
| [FLAW141](FLAW141/README.md) | medium   | security | Large base64 blob (opaque payload) |
| [FLAW142](FLAW142/README.md) | high     | security | Obfuscated code-execution chain |
| [FLAW143](FLAW143/README.md) | high     | security | Docker socket mounted into container |
| [FLAW146](FLAW146/README.md) | high     | security | Kubernetes security boundary disabled |
| [FLAW147](FLAW147/README.md) | high     | security | Security-group `0.0.0.0/0` ingress |
| [FLAW148](FLAW148/README.md) | medium   | security | Source map shipped in production artifact |

**CI/CD & GitHub Actions** — workflow and supply-chain hazards.

| ID | Severity | Tag | Flaw |
|---|---|---|---|
| [FLAW144](FLAW144/README.md) | high     | security | `pull_request_target` + PR-head checkout |
| [FLAW145](FLAW145/README.md) | high     | security | Unsafe `github.event` expression in workflow |

**LLM / MCP app security (`FLAW149`–`FLAW157`)** — AI-stack footguns.

| ID | Severity | Tag | Flaw |
|---|---|---|---|
| [FLAW149](FLAW149/README.md) | high     | security | Unpinned MCP / agent source |
| [FLAW150](FLAW150/README.md) | high     | security | Project-local config grants execution |
| [FLAW151](FLAW151/README.md) | high     | security | User input interpolated into system / assistant role |
| [FLAW152](FLAW152/README.md) | medium   | security | Tool result appended to prompt without fence |
| [FLAW153](FLAW153/README.md) | medium   | security | Model output rendered with images enabled |
| [FLAW154](FLAW154/README.md) | high     | security | Prefix check without canonicalization |
| [FLAW155](FLAW155/README.md) | medium   | security | User-controlled LLM `max_tokens` without clamp |
| [FLAW156](FLAW156/README.md) | high     | security | Tool handler makes outbound request to non-literal URL |
| [FLAW157](FLAW157/README.md) | medium   | security | AI-tool project config committed to repo |
