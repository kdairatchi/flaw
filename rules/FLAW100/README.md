# FLAW100 — Explanatory Narration Comment (AI-Slop)

**Severity:** low · **Tag:** ai-slop

## What

Comments that restate what the code plainly does (`# Loop through the array`, `# This function initializes...`, `# First, we check if...`). Classic unedited LLM output.

## Why it matters

Narration comments rot the codebase:
- They go stale the moment the code changes.
- They train maintainers to ignore comments entirely.
- They signal the author didn't read / edit what was pasted.

## Fix

Delete them. A well-named function and clean code explain the *what* on their own. Keep comments only for the *why* — hidden constraints, non-obvious invariants, bug workarounds.

```crystal
# bad
# This function iterates over the users array and prints each name.
def print(users)
  users.each { |u| puts u.name }
end

# good
def print_user_names(users : Array(User))
  users.each { |u| puts u.name }
end
```
