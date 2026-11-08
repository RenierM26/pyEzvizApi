# Documentation

These guides track current `main`, not necessarily the latest PyPI package.
Use the documentation at a matching release tag for a released installation.
See [release availability](releases.md#source-state-is-not-a-published-release).

## Start by task

| Task | Guide |
| --- | --- |
| Install, authenticate or fix a token/CLI problem | [Getting started](getting-started.md) |
| Read gateway-linked contact, water and siren sensor status | [Detectors](detectors.md) |
| Call the synchronous client from Python | [Python API](python-api.md) |
| List devices, control a camera or inspect recordings | [CLI](cli.md) |
| Migrate push and persist its credentials | [Channel-99](channel99.md) |
| Choose RTSP, finite saves or native stream APIs | [Media paths](media.md) |
| Check what actually works with Home Assistant | [Current HA status](home-assistant.md) |
| Replace removed flat imports | [Compatibility](ha-compatibility.md) |
| Contribute, test or publish | [Contributing](../CONTRIBUTING.md), [releases](releases.md) |

## Current user guides

- [Cloud-mediated SD-card playback](cloud-sd-playback.md)
- [LAN-only SD-card downloads](lan-sd-playback.md)

- [Getting started](getting-started.md)
- [Python client usage](python-api.md)
- [Command-line guide](cli.md)
- [Channel-99 push transport and migration](channel99.md)
- [Media paths and their requirements](media.md)
- [Saving images and finite clips](media-saving.md)
- [Home Assistant consumers and current status](home-assistant.md)
- [HA compatibility boundary](ha-compatibility.md)

## Technical and maintainer references

- [Advanced stream CLI](stream-cli.md)
- [Streaming architecture and compatibility](streaming.md)
- [Home Assistant integration contract](home-assistant-contract.md)
- [Code map](code-map.md)
- [Bootstrap deadlines and pagelist progress](bootstrap-and-pagination.md)
- [Channel, codec and clock namespaces](channel-codec-clock-contracts.md)
- [Utility contracts](utility-contracts.md)
- [HPD7 gate/door unlock routing (issue #268)](hpd7-unlock-routing.md)
- [Regression controls from Home Assistant logs](ha-observed-error-regressions.md)
- [CodeQL triage — 2026-11-08](codeql-triage.md)
- [Releases and versioning](releases.md)
- [Repository Watch Agent](repo-watch-agent.md)

## Development media and protocol guides

These are specialist APIs, experiments and validation workflows in this source
tree, not the default installation or a production HA/player feature list.
Their recorded runs apply to the stated inputs, versions and commits. A decoded
sample, host submission or source-review patch is not live frontend/physical
A/V acceptance. Check each guide's optional dependencies and explicit bounds.

- [Local AAC decoder adapter (development only)](app-aac-decode.md)
- [Experimental PCM output backend (development only)](app-pcm-playback.md)
- [Bounded app-profile playback simulator (development only)](app-playback-simulator.md)
- [Scheduled paired-video artifact (development only)](app-scheduled-video.md)
- [Experimental app-compatible HEVC/AAC timing](app-timing.md)
- [Local paired HEVC decode adapter (development only)](app-video-decode.md)
- [Two-lens video staging (development only)](app-video-pairing.md)
- [Explicit local paired-video preview (development only)](app-video-preview.md)
- [Automatic-stream termination and ownership](automatic-stream-outcomes.md)
- [Experimental continuous compressed reference preview](compressed-reference-preview.md)
- [Offline decoder backend counts](decoder-backend-diagnostics.md)
- [Native EZVIZ media: Home Assistant consumer architecture](ha-consumer-architecture.md)
- [Temporary Home Assistant native delivery validation](ha-native-integration.md)
- [Camera capabilities and Home Assistant delivery](ha-streaming-plan.md)
- [Local HA validation artifacts, not a production release](ha-validation-release.md)
- [Reference-assisted live native A/V handoff (development only)](live-native-av.md)
- [Scheduled audio-gap output boundary](local-av-audio-gap-output.md)
- [Offline whole-block audio-gap planning](local-av-audio-gaps.md)
- [Rolling bounded recorded A/V playback (development only)](local-av-bounded-playback.md)
- [Guarded capture-prefix output (development only)](local-av-capture-playback.md)
- [Guarded capture → clear chunks (development only)](local-av-capture-prefix.md)
- [Guarded capture → online preparation (development only)](local-av-capture-preparation.md)
- [Single-pass chunk-fed A/V preparation (development only)](local-av-chunked.md)
- [Bounded decrypted packet chunks (development only)](local-av-decrypted-chunks.md)
- [Bounded incremental standalone A/V decode (development only)](local-av-incremental.md)
- [Attended direct-LAN development command](local-av-lan-playback.md)
- [Single-pass online-policy recorded output (development only)](local-av-online-playback.md)
- [Online A/V policy preparation (development only)](local-av-online-policy.md)
- [Standalone local A/V host submissions (development only)](local-av-playback.md)
- [Single-demand prepared-source pull boundary (development only)](local-av-pull.md)
- [Guarded media runtime preflight (development only)](local-av-runtime.md)
- [Split lens uploads and preparation timing (development only)](local-av-split-upload.md)
- [Two-minute recorded playback control](local-av-sustained-playback.md)
- [Standalone local A/V timeline (development only)](local-av-timeline.md)
- [Advanced media source and clock recipes](media-advanced.md)
- [Generation-specific native completion receipts](native-completion-receipts.md)
- [Continuous native MPEG-PS stream boundary](native-ha-stream.md)
- [Native input/render pixel audit (development only)](native-pixel-crop-audit.md)
- [Scheduled native-snapshot video (development only)](native-scheduled-video.md)
- [Experimental declared-output native session](native-shared-session.md)
- [Paced native snapshot preview (development only)](native-video-preview.md)
- [Playback timing: verified app probes and PR policy](playback-timing.md)
- [Build-gated reference producer and bounded software benchmark](reference-stream-producer.md)

## Historical plans and qualification evidence

These pages preserve pinned checkpoints, superseded decomposition plans and
external source proposals. They are not current import contracts, universal
installation recipes, an unimplemented backlog, or evidence of deployment.
Paths are retained so existing links and source-review bundles remain usable.

- [Finite HLS/WebRTC source-review bundle](consumer-runtime-review/README.md)
- [Automatic receiver and authenticated client qualification](consumer-runtime-review/automatic-client-qualification.md)
- [Independent HLS startup under the optional native Opus profile](consumer-runtime-review/hls-independent-fallback.md)
- [Bounded late WebRTC repair — follow-up to PR397](consumer-runtime-review/transport-recovery.md)
- [HA full development qualification and finite publication fixes](ha-development-qualification.md)
- [FFmpeg source-build validation boundary](ha-ffmpeg-source-build-validation.md)
- [Finite HLS completion: separate host review candidate](ha-finite-completion-proposal.md)
- [Delivered HLS clocks and finite-tail boundary](ha-finite-hls-review.md)
- [Initial source-clock preservation: external review proposals](ha-initial-source-clock-review.md)
- [Isolated HA consumer topology qualification](ha-topology-qualification.md)
- [Upstream HA stream compatibility and review boundary](ha-upstream-stream-compatibility.md)
- [EZVIZ WebRTC audio queue correction and remaining startup gates — 2026-11-02](ha-webrtc-audio-qualification.md)
- [Maintenance implementation plan](maintenance-plan.md)
- [Implementation responsibilities after the maintenance extraction](module-responsibilities.md)
- [Package layout migration (historical PR #413 plan)](package-layout-migration.md)

## Repository documentation

- [Project overview](../README.md), [changelog](../CHANGELOG.md),
  [contributing](../CONTRIBUTING.md), [support](../SUPPORT.md),
  [security](../SECURITY.md) and [license](../LICENSE.md).
- [Actual custom HA consumer acceptance](../examples/ha_ezviz/README.md).
- [Library package map](../pyezvizapi/README.md),
  [test layout](../tests/README.md),
  [APK research tooling](../tools/apk-re/README.md) and
  [Android sidecars](../tools/apk-re/sidecars/README.md).
- Package-local READMEs describe ownership under
  [_shared](../pyezvizapi/_shared/README.md),
  [_typing](../pyezvizapi/_typing/README.md),
  [cli](../pyezvizapi/cli/README.md),
  [cloud](../pyezvizapi/cloud/README.md),
  [devices](../pyezvizapi/devices/README.md),
  [push](../pyezvizapi/push/README.md),
  [streaming](../pyezvizapi/streaming/README.md),
  [streaming/local](../pyezvizapi/streaming/local/README.md),
  [streaming/local/hcnetsdk](../pyezvizapi/streaming/local/hcnetsdk/README.md).

## Keeping the docs current

Run `python tools/check_documentation.py` from the repository root. It validates
local Markdown targets/heading anchors and parses documented `pyezvizapi` CLI
examples without logging in or running any command. It also checks that the
changelog has one exact Unreleased section. External URLs and live behavior are
not established by that check. See [contributing](../CONTRIBUTING.md) for the
separate offline test and HA acceptance environments.

- [Stored SD catalog and batch download](recording-catalog.md) — query intervals, download over LAN/cloud, and resume.
