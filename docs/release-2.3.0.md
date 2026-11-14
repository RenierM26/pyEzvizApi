# pyEzvizApi 2.3.0 release notes

Prepared from merged main through PR #439 on 2026-11-14. Preparation is not
publication or deployment; check [GitHub releases](https://github.com/RenierM26/pyEzvizApi/releases/tag/v2.3.0)
and [PyPI](https://pypi.org/project/pyezvizapi/2.3.0/) for actual availability.

## Why a minor release

This release adds public, application-independent device helper APIs (#438),
then organizes them into focused compatible modules (#439). Python 3.12+
remains required. Existing controls import paths and call signatures remain
available; this does not add a new device command or install an HA integration.
Users upgrading from 1.x still need the [2.0 migration](release-2.0.0.md).

## New device helper APIs

- `devices.audio`: chime, voice and microphone capability/range readers and
  field-preserving setters. Keep distinct chime versus voice/microphone rules.
- `devices.capabilities`, `metadata`, `ports`, `tracking` and `lens`: vendor
  metadata, SupportExt matching, port read/modify/write, linked tracking,
  intelligent apps and lens-defog helpers. `devices.controls` re-exports the
  same public objects for compatibility.
- `devices.images`: concatenated JPEG extraction and stacked multi-lens image
  processing. Install `pyezvizapi[images]==2.3.0` for Pillow. Calls are synchronous;
  async applications must own worker execution and lifecycle.

See the [feature boundary guide](ha-feature-boundary.md) for contracts. Consumers
continue to own credential storage, command serialization, refresh/caching,
entity IDs and presentation. No live device support is implied by offline tests.

## Corrections and refactoring

Microphone writes retain speaker/unknown sibling fields rather than inventing
speaker volume 100. Missing reported microphone configuration and non-finite
writes fail before IO. Port updates retain enclosing enable flags and unknown
fields in fresh/cached payloads without mutating inputs. JPEG marker-length
parsing preserves EXIF thumbnails within their containing frame.

Shared port traversal retains decoded containers so reused object IDs do not
hide later encoded siblings as false cycles. Normalized read and lossless write
projections retain their distinct ordering and output contracts. Audio operations
decode configuration once; legacy coercion behavior is retained. Source and
cropped Pillow images are closed on success and failure, without changing
Pillow's global truncated-image policy. Undecodable composites pass through;
crop/encoding errors propagate.

## Home Assistant boundary

The companion custom-integration migration is [ha-ezviz #253](https://github.com/RenierM26/ha-ezviz/pull/253).
It must qualify this **published** SDK release and update its exact dependency
profile/checks separately. This release does not merge, deploy or change that
integration, nor qualify coexistence with HA's stock EZVIZ dependency pin.
The repository's historical pinned-consumer acceptance suite is distinct from
the current migration's 593-test candidate qualification; see [HA status](home-assistant.md).

## Qualification and publication

The merged feature head passed 6,229 SDK tests (91.51% coverage), all 70 focused
contracts from a built wheel, typing/lint/build checks and all nine hosted gates;
Codex review found no issues. Candidate HA 2026.11.0 passed 593 native tests.
The release-preparation head must independently pass its required CI/CodeQL gates.

After merging preparation, run **Release Check** on merged main with
`release-tag=v2.3.0`, inspect checked distributions, then run **Upload Python
Package** once with bare version `2.3.0`. Verify the actual published wheel and
matching GitHub assets before reporting publication complete. No live cloud,
physical device, lock actuation or consumer deployment forms part of qualification.
