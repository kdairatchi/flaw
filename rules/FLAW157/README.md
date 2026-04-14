# FLAW157 — AI-tool project config committed to repo

**Severity:** medium · **Tag:** security · CWE-1357

## What
A project-local AI/tool config file is part of the repo tree (`.claude/`, `.cursor/`, `.mcp.json`, `.windsurfrules`, `.continuerc`). On `git clone`, anyone opening the repo in the corresponding tool inherits the hooks, prompts, and permissions. Keep these local and gitignored unless the repo is explicitly a template (baseline this rule in that case).

## Fix
See the rule description and the detector at `src/rules/dotclaude_in_repo.cr`.
