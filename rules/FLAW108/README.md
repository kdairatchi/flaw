# FLAW108 — AI slop marker in source

**Severity:** low · **Tag:** ai-slop · CWE-1164

## What
Source contains decorative emoji, leaked Markdown code fences, placeholder identifiers (foo/bar/do_something), or sycophantic openers ("Certainly!", "Sure!") — hallmarks of un-reviewed LLM output. Clean the code before committing.

## Fix
See the rule description and the detector at `src/rules/ai_slop_markers.cr`.
