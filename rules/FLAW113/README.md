# FLAW113 — DOM XSS sink

**Severity:** high · **Tag:** security · CWE-79

## What
Writing to innerHTML/outerHTML/document.write/insertAdjacentHTML or framework equivalents (dangerouslySetInnerHTML, v-html, {@html ...}) interprets the assigned value as HTML. Unless the source is a static literal under your control, it's an XSS vector. Prefer textContent, createElement, or a sanitizer (DOMPurify).

## Fix
See the rule description and the detector at `src/rules/dom_xss_sink.cr`.
