# FLAW101 — AI Assistant Boilerplate

**Severity:** medium · **Tag:** ai-slop

## What

LLM meta-phrases pasted into source — refusals (`I cannot`, `I apologize for the confusion`), self-references (`As an AI language model`, `As of my last knowledge update`), opener filler (`Certainly!`, `Absolutely!`).

## Why it matters

This text ships to end users. It's embarrassing at best, misleading at worst (users see `As of my last knowledge update` and wonder what the product actually knows). It's also the loudest possible signal that the author did not read what they pasted.

## Fix

Delete it. Replace with text that describes the product, not the assistant.
