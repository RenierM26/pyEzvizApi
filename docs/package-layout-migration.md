# Package layout migration (historical PR #413 plan)

The preservation rules below describe PR #413, not the subsequent alias cleanup.
Current supported paths are documented in [HA compatibility](ha-compatibility.md).

Baseline: `bfa5aa5349a87a30bea5de0ff616d4dd17572b2d` (after PR #412).

This is a structural-only migration. Public client methods, legacy module
imports and wildcard exports, CLI options/defaults, status keys, exception
categories, authentication, packet formats, clocks, budgets, cancellation and
session ownership remain unchanged. Media and Home Assistant stay optional.

## Delivery stages

1. **navigation** — Code map, architecture rules and baseline compatibility inventory.
2. **cli** — CLI arguments, commands and thin executable entry points.
3. **domains** — Cloud, devices, push, streaming and shared domain packages.
4. **decomposition** — Split client operations, SDK helpers and local media responsibilities.
5. **tests** — Mirror domain layout while preserving fixtures, sibling helpers and CI selection.
6. **qualification** — Full tests, type/lint, installed wheel, exact-head CI and Codex review.

## Architecture rules

- Implementations belong to `cloud`, `devices`, `push`, `streaming`, `cli`, or
  narrowly shared `_shared` packages. Package initializers do not eagerly import
  their entire domain.
- Root modules are compatibility boundaries. Existing identity aliases stay
  aliases so a patch through a legacy path reaches the actual implementation.
- Split operations by responsibility, not arbitrary line counts. Runtime hook
  dependencies must remain explicit and retain their existing owner.
- Keep baseline import and recursive argparse inventories. Compare moved
  implementation ASTs, then run affected controls and the complete suite.
- Group tests by domain, and make repository/fixture paths independent of the
  number of parent directories. Preserve cross-test helper references.
- Add a short README to each domain and maintain `docs/code-map.md`.
- No real device tests are required for structural qualification. Review, merge,
  release and deployment are distinct stages.

## Review checkpoints

Each implementation stage gets its own commit. The final proposal includes all
stages so it can be tested as one consistent tree; review status is recorded
against the exact published head, never inferred from an earlier green commit.
