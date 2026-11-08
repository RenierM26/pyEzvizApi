# pyEzvizApi 2.0.0 release notes

Prepared from merged main through PR #429 on 2026-11-08. This is release
preparation, not publication or deployment. Check [GitHub releases](https://github.com/RenierM26/pyEzvizApi/releases)
and [PyPI](https://pypi.org/project/pyezvizapi/) for actual availability.
Update the preparation date before publication on a later date.

## Why a major version

The previous published package is 1.0.5.0. Version 2.0 intentionally breaks
obsolete imports and push-registration behavior. New numbering uses three-part
major/minor/patch versions; historical four-part versions remain valid history.

## Upgrade requirements

- Python 3.12 or newer; CI covers 3.12, 3.13 and 3.14.
- Replace removed flat imports using [the compatibility guide](ha-compatibility.md)
  and [module map](module-map.json). The reorganized domain packages are canonical.
  Removed module paths and pickles through those paths intentionally break.
- Replace `EzvizCamera.alarm_detection_sensibility()` with
  `alarm_detection_sensitivity()`. The two redundant streaming legacy facades
  are removed; see the compatibility guide before reusing old stream imports.
- Push uses Paho MQTT 2.0 or newer (a runtime dependency). Follow
  [channel-99 migration](channel99.md): explicitly migrate with
  `EzvizClient.enable_channel99()` and provide a synchronous, durable
  `on_token_updated` callback before authentication. Persist the complete token
  privately, handle MFA, and reauthenticate if the host MAC-derived identity changes.
- Monitor `MQTTClient.raise_if_failed()`; surface fatal persistence/authentication
  errors and keep polling independent of the push worker.
- Optional PyAV-backed media APIs use `pyezvizapi[streaming]`. FFmpeg/ffprobe
  are separate system tools required by specific routes; they are not pip-installed.
  See [media requirements](media.md) and [getting started](getting-started.md).

## Highlights since 1.0.5.0

- Channel-99 LBS/MQTT negotiation, durable credential rotation, reconnection,
  isolated HTTPS refresh and credential-free health diagnostics.
- Bounded typed `poll_devices()` snapshots, detached dictionary adapters,
  per-device health, malformed-device isolation and gateway-linked detectors.
- App-aligned plug channel/firmware semantics and alarm timestamp correction:
  valid UTC epochs survive inconsistent DST-localized companion strings.
- LAN-only `lan rtsp status|enable|disable`, preserving unrelated services and
  verifying configuration read-back. A successful switch does not establish
  that the model/firmware supports an RTSP stream.
- Account-free LAN SD catalogs/downloads and bounded cloud SD catalogs with
  resumable sequential batch downloads and hash-verified receipts. Explicit
  playback timezones handle native selectors without host-local guessing.
- Cloud and authenticated local native media processing, bounded capture and
  cleanup, typed failures, disk-backed staging and atomic SD output publication.
- Domain-oriented package/CLI layout, documented canonical imports, expanded
  offline controls, installed-wheel checks and pinned Home Assistant acceptance.

See [CHANGELOG.md](../CHANGELOG.md) for detailed changes and
[the documentation index](README.md) for task-specific guides.

## Home Assistant coordination

Installing this library does not upgrade any integration or dependency pin.
The pinned custom cloud consumer passes the documented offline acceptance
boundary, but its legacy push startup still lacks migration and durable token
storage. Official HA core, the custom cloud integration and the experimental
native integration are separate consumers. Consult [current HA status](home-assistant.md)
before recommending deployment. Import compatibility and synthetic ingestion do
not establish live RTSP, broker delivery or production player support.

## Known limitations and validation boundaries

- Historical X80 wheel validation on 2026-10-09 was mixed (sparse cloud video
  and local decoder diagnostics); it is not a current-head readiness result.
  Later development evidence is pinned to its own source/device/bounds. This
  preparation does not repeat live captures or claim all models are qualified.
- Long-duration stream/audio soak, outage/phone coexistence and model-specific
  media behavior require separate qualification. Offline checks do not establish
  continuous live stability; native HA/player examples remain development tools.
- String-only alarm timestamps with fixed offsets cannot identify a DST timezone.
  SD playback requires the correct explicit camera timezone; ambiguous DST ranges
  are rejected rather than guessed from the host.
- Protocol crypto and intentional native cleanup findings have a separate
  [CodeQL triage](codeql-triage.md). Inspect the exact release head's security
  and quality results; do not infer approval from historical green checks.

## Review and publication workflow

1. Verify this PR's exact-head CI, documentation, CodeQL and non-publishing
   **Release Check**, including built-wheel smoke and version `2.0.0` metadata.
2. Review/merge this preparation PR and verify merged-main checks. Run
   **Release Check** on main with proposed `release-tag=v2.0.0`; it creates no tag.
3. Reassess live/soak limitations and obtain explicit owner approval for
   publication. Updating this preparation PR does not grant that approval.
4. Run **Upload Python Package** on intended merged main with bare
   `version=2.0.0`. It validates/builds, publishes through PyPI trusted publishing,
   then creates GitHub tag/release `v2.0.0`. Do not separately pre-create the tag
   or run duplicate publication paths. See [release procedure](releases.md).
5. Verify PyPI artifacts, tag/release commit and downstream migration. The upload
   workflow generates a generic body plus GitHub notes; curate these release
   notes into the release description when publication is authorized.

Do not rerun **Prepare Release** for this PR. It only moves Unreleased entries
and requires the requested version to already match `pyproject.toml`; it does
not perform this migration/documentation work. The dated 2.0.0 section is already
prepared, so a rerun on this branch rejects a duplicate section.
