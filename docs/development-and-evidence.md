# Development guides and historical evidence

[Documentation index](README.md) · [Media paths](media.md)

## Development media and protocol guides

Start with the [advanced stream CLI](stream-cli.md), [streaming reference](streaming.md),
or [channel, codec, and clock contracts](channel-codec-clock-contracts.md).

These are specialist APIs, experiments and validation workflows in this source
tree, not the default installation or a production HA/player feature list.
Their recorded runs apply to the stated inputs, versions and commits. A decoded
sample, host submission or source-review patch is not live frontend/physical
A/V acceptance. Check each guide's optional dependencies and explicit bounds.

### Diagnose or hand off a live stream

- [Automatic-stream termination and ownership](automatic-stream-outcomes.md)
- [Reference-assisted live native A/V handoff](live-native-av.md)
- [Generation-specific native completion receipts](native-completion-receipts.md)
- [Continuous native MPEG-PS stream boundary](native-ha-stream.md)
- [Experimental declared-output native session](native-shared-session.md)
- [Advanced media source and clock recipes](media-advanced.md)
- [Playback timing: verified app probes and PR policy](playback-timing.md)
- [Build-gated reference producer and bounded software benchmark](reference-stream-producer.md)

### Decode, pair, and preview media

- [Local AAC decoder adapter](app-aac-decode.md)
- [Experimental PCM output backend](app-pcm-playback.md)
- [Bounded app-profile playback simulator](app-playback-simulator.md)
- [Scheduled paired-video artifact](app-scheduled-video.md)
- [Experimental app-compatible HEVC/AAC timing](app-timing.md)
- [Local paired HEVC decode adapter](app-video-decode.md)
- [Two-lens video staging](app-video-pairing.md)
- [Explicit local paired-video preview](app-video-preview.md)
- [Experimental continuous compressed reference preview](compressed-reference-preview.md)
- [Offline decoder backend counts](decoder-backend-diagnostics.md)
- [Native input/render pixel audit](native-pixel-crop-audit.md)
- [Scheduled native-snapshot video](native-scheduled-video.md)
- [Paced native snapshot preview](native-video-preview.md)

### Prepare or play back local A/V

- [Scheduled audio-gap output boundary](local-av-audio-gap-output.md)
- [Offline whole-block audio-gap planning](local-av-audio-gaps.md)
- [Rolling bounded recorded A/V playback](local-av-bounded-playback.md)
- [Guarded capture-prefix output](local-av-capture-playback.md)
- [Guarded capture → clear chunks](local-av-capture-prefix.md)
- [Guarded capture → online preparation](local-av-capture-preparation.md)
- [Single-pass chunk-fed A/V preparation](local-av-chunked.md)
- [Bounded decrypted packet chunks](local-av-decrypted-chunks.md)
- [Bounded incremental standalone A/V decode](local-av-incremental.md)
- [Attended direct-LAN development command](local-av-lan-playback.md)
- [Single-pass online-policy recorded output](local-av-online-playback.md)
- [Online A/V policy preparation](local-av-online-policy.md)
- [Standalone local A/V host submissions](local-av-playback.md)
- [Single-demand prepared-source pull boundary](local-av-pull.md)
- [Guarded media runtime preflight](local-av-runtime.md)
- [Split lens uploads and preparation timing](local-av-split-upload.md)
- [Two-minute recorded playback control](local-av-sustained-playback.md)
- [Standalone local A/V timeline](local-av-timeline.md)

### Validate native media with Home Assistant

- [Native EZVIZ media: Home Assistant consumer architecture](ha-consumer-architecture.md)
- [Temporary Home Assistant native delivery validation](ha-native-integration.md)
- [Camera capabilities and Home Assistant delivery](ha-streaming-plan.md)
- [Local HA validation artifacts, not a production release](ha-validation-release.md)

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
- [CodeQL triage — 2026-11-08](codeql-triage.md)
- [Maintenance implementation plan](maintenance-plan.md)
- [Implementation responsibilities after the maintenance extraction](module-responsibilities.md)
- [Package layout migration (historical PR #413 plan)](package-layout-migration.md)

## Research tooling

- [APK research tooling](../tools/apk-re/README.md)
- [Android sidecars](../tools/apk-re/sidecars/README.md)
