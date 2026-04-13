# Contributing to flaw

Thanks for wanting to make Crystal code safer.

## Adding a rule

1. Pick the next ID (`FLAWNNN`).
2. Add `src/rules/your_rule.cr` subclassing `Flaw::Rule`.
3. Add a passing and a failing fixture under `spec/fixtures/`.
4. Add a spec under `spec/rules/`.
5. Document it in `README.md` rule table and `CHANGELOG.md`.
6. Open a PR — include the real-world footgun the rule catches.

## Reporting a false positive

Open an issue with:
- The smallest Crystal snippet that triggers it
- The rule ID
- Why you believe it's a false positive

False positives are treated as bugs.

## Dev loop

```bash
shards install
crystal spec
shards build
./bin/flaw scan examples/bad/
```

## Code style

- No AI-generated filler. Write code a human would write.
- Prefer stdlib over deps. v0.1 has zero runtime deps and we'd like to keep it slim.
- Every rule's `description` must explain the *why*, not just the *what*.
