# Maintenance implementation plan

> **Pinned historical evidence / proposal.** Retained for its recorded revisions and
> reproducibility, not current installation or deployment status. Start with the
> [documentation index](README.md) and [current HA status](home-assistant.md).


Baseline: `7b26386038995f7172c20a6bd9cde597f120ecee`.

Implement small, independently reviewable corrections before structural moves.
Keep stable client methods, import paths, status keys, exception categories,
optional-dependency laziness, cryptographic wire formats, original media clocks,
finite capture policies and queue budgets. No real device commands are needed
for the maintenance regression suite. Merge, release and deployment are separate
operations from preparing a change.

## Corrections

- F01: Check application-level success for lock, unlock and PTZ responses.
- F02: Validate that configured packet/byte counts are usable finite bounds.
- F03: Preserve status zero and handle malformed device payload boundaries.
- F04: Make tolerant numeric/time helpers finite-safe and offset parsing explicit.
- F05: Validate API envelope shapes and keep error messages credential-safe.
- F06: Give the RTSP authentication probe bounded framing and socket ownership.
- F07: Validate image padding without changing the proprietary cipher format.
- F08: Define and enforce the required bootstrap/body deadline contract.
- F09: Honor zero/negative character limits in bounded diagnostic tails.

## Refactors and contracts

- R01: Extract implementation responsibilities from the large HCNetSDK, local
  stream, client and CLI modules, not merely another import facade.
- R02: Organize utility families and correct documentation while retaining
  existing tolerant, strict and protocol-specific conversion semantics.
- R03: Share small device-payload helpers instead of adding a large base class.
- R04: Make preview/configuration channel, codec and clock namespaces explicit.
- R05: Collect pagelists iteratively with bounded progress checks.
- R06: Make bounded resolver-service ownership/lifecycle explicit or injectable.
- R07: Retain negative response, malformed input, fragmentation, cancellation and
  export/import compatibility tests throughout the extractions.

## Delivery order

1. Control responses.
2. Finite/count/numeric guardrails.
3. Device-record and response-envelope robustness.
4. Time/mapping/diagnostic/image utilities.
5. RTSP framing and ownership.
6. Deadline behavior and pagination.
7. Incremental implementation extraction, shared helpers and CLI separation.
8. Full compatibility, packaging and review closure.

Each change records its regression-before result, affected checks and exact
commit. Application-level acceptance must not be described as physical action
completion. Passing encoded-media checks must not be described as client
playback or measured physical A/V synchronization.
