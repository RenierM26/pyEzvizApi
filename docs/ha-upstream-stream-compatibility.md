# Upstream HA stream compatibility and review boundary

> **Pinned historical evidence / proposal.** Retained for its recorded revisions and
> reproducibility, not current installation or deployment status. Start with the
> [documentation index](README.md) and [current HA status](home-assistant.md).


The isolated external proposals now apply to actual HA2026.10.4 commit
`357cae5c598dfcd7a0ea7dc5b1facccd4ec6037b` and pass its complete stream component
suite using upstream root fixtures/helpers. This is not full HA CI or a runtime
change to pyezvizapi, PR397, installed HA, or the prior host candidate808667e.

## Checks

- Unmodified release:80existing tests pass; same80case IDs pass on the candidate.
- Clock policy alone:98cases pass, including18added regressions.
- Intermediate finite completion:130cases pass before3version/revoke controls.
- Combined normalized review series:133cases pass (80existing+53added).
- The53added cases also pass with actual source-built FFmpeg9.0.2/PyAV19 and no
  diagnostic preload. These overlap133, not additional distinct behaviors.
- Extracted handoff:98/133/53cases pass again using its exact patches and runner;
  every one of20resulting runtime/test source hashes matches the expected tree.
- Existing worker test functions/classes retain their original AST. All10runtime
  files remain byte-identical to host candidate808667e. All9installed baseline
  stream files match the release and remain unchanged.
- Pinned Ruff0.16.9 and formatting pass for all20stream runtime/test files using
  the actual repository's nested configuration. New tests have parameter/return
  types; revocation cases use explicit state factories instead of test branching.

The80/133component runs use the official PyAV19 wheel and its x264/x265 fixture
encoders. The separate source-built retained-media HTTP acceptance remains the
proof of actual normal-entry delivery without interposition; neither test scope
substitutes for the other.

## Review structure

Keep two external HA changes separate:

1. Default-off complete initial PTS/DTS preservation policy, with missing-clock
   refusal and no unknown FFmpeg option.
2. Versioned opaque finite completion/revoke API, independently confirmed selected
   unit counts plus receivingEOF, one attempt, atomic final bytes/ENDLIST and
   bounded retention. This depends on1; it contains no proprietary/source logic.

The handoff includes both patches, full-template unchecked draft descriptions,
source/config provenance, a validation helper and the dependency review matrix.
It contains no media, credential, SDK, preload, relay or compiled dependency.
These are uncommitted local review inputs, not public contributions or signoff.

Full all-files pre-commit was attempted in a disposable duplicate but is not
green: development dependencies/tools, sparse generator/template inputs and a
security-hook empty-token setting need a complete development setup. No full CI,
platform, official wheel or maintainer-acceptance claim is made. HA's repository
requires script/setup before committing and human understanding/review before
submission. No upstream issue, PR, comment or commit was submitted.

Remaining: full setup/CI and current-dev review, maintained FFmpeg/PyAV/HA/relay
support, Windows/ARM/hardware coverage, actual HEVC frontend, broader source
startup/topology, and separately bounded attended hardware/physical A/V tests.
PR397 and library runtime72c8a5645a38 stay separate and unchanged.

[Full findings and source review handoff](https://bookstack.home.moor.co.za/books/home-infrastructure/page/ezviz-upstream-ha-compatibility-and-review-handoff-2026-11-01).

## Full-development follow-up

[Development qualification and publication fixes](ha-development-qualification.md)
now records complete isolated setup,137cases, scoped Mypy/Pylint and13CI-style
hooks. It also fixes publication/unknown-duration handling, so the earlier808667e
runtime identity and133-case evidence above remain historical, not the updated
host source fingerprint. Full-repository/platform and maintained-host gates stay
separate.
