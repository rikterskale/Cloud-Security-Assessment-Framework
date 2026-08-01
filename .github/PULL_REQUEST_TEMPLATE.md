<!-- Thanks for contributing to CSAF. Keep changes focused and backward-compatible. -->

## Summary

<!-- What does this change do, and why? -->

## Safety scope (required for a security tool)

- [ ] This change does **not** introduce a mutating cloud call (read-only preserved).
- [ ] It does **not** weaken engagement authorization, scope, window, or signing.
- [ ] It does **not** affect release, packaging, or CI trust boundaries — or, if it does, that is called out below.
- [ ] No secrets, credentials, or customer data are added to code, tests, or examples.

Notes on scope (cloud access / authorization / release), if any:

## Tests

- [ ] Added or updated unit tests for the new behavior.
- [ ] `ruff check`, `ruff format --check`, and the full unittest suite pass locally.
- [ ] Coverage remains at or above 90%.

## Documentation

- [ ] README updated for any new CLI option (a contract test enforces this).
- [ ] Novice guides / other docs updated if user-facing behavior changed.

## Backward compatibility

<!-- State any breaking change and the agreed justification, or confirm none. -->
