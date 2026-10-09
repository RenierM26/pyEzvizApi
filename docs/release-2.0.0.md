# pyEzvizApi 2.0.0 release preparation

Status: prepared for review, not tagged or published. The changelog date is the
preparation date; update it if publication happens on a later date.

## Why a major version

The previous published package is 1.0.5.0. The legacy push-registration path has
been removed, and existing push integrations need an explicit storage/authentication
migration. A major version makes this incompatible change visible to dependency
consumers. It also returns new release numbering to the standard three-part
major/minor/patch form; historical four-part tags remain unchanged.

## Upgrade requirements

- Python 3.12 or newer; CI covers 3.12, 3.13, and 3.14.
- Push reception needs Paho MQTT 2.0 or newer, included in package dependencies.
- Follow the [channel-99 migration guide](channel99.md): use
  `EzvizClient.enable_channel99()` for migration and provide a synchronous,
  durable `on_token_updated` callback before authentication. Persist the whole
  token privately, not just the push fields. Handle MFA when requested.
- Saved push credentials belong to the host MAC-derived feature code. A changed
  host/container MAC requires a fresh login; do not reuse the old push identity.
- Monitor `MQTTClient.raise_if_failed()` and surface fatal persistence or
  authentication errors. Keep polling independent of the push worker.
- Streaming remux operations require FFmpeg on PATH. Ambiguous timed decrypted
  cloud MPEG-PS captures additionally require ffprobe for completeness validation.
  Neither binary is installed by this Python package.

Home Assistant integrations must coordinate worker-thread storage with the event
loop without blocking that loop. This package release does not itself migrate
Home Assistant integration storage or update its dependency pin.

## Highlights since 1.0.5.0

- Android channel-99 LBS/MQTT negotiation, durable credential rotation,
  reconnection, isolated HTTPS refresh, and credential-free health diagnostics.
- Cloud MPEG-PS, MPEG-TS, and RTP/IDMX exports through dump, clip-save, and proxy
  paths; metadata-owned codec/payload routing and descriptor-backed AAC-LC.
- Authenticated local ECDH preview and HCNetSDK command-port streaming, automatic
  header detection, clean-window recovery, and shared bounded FFmpeg cleanup.
- Typed clip configuration with compatibility aliases for earlier stream imports.
- Typed no-media/incomplete-media failures and explicit ambiguity handling for
  bounded captures. Capture/remux failures preserve existing bounded cloud file
  destinations. Final filesystem writes are not atomic rollback operations.
- Trace-backed HCNetSDK control/configuration/ability helpers and HP7 chime APIs.
- CAS framing/bootstrap compatibility, retained MFA codes on region redirects,
  and non-UTF-8 RTSP authentication response handling.

See [CHANGELOG.md](../CHANGELOG.md) for the detailed change list and
[streaming.md](streaming.md) for supported formats and capture semantics.

## Known limitations, not release claims

- Intermittent C8W cloud upstream delivery remains unresolved. Increasing a bound
  does not guarantee media; unavailable captures return `no_media` (proxy 502).
- Residual Gate HEVC reference/PPS warnings need full-clip follow-up. A short clean
  decode is not proof of full-duration integrity.
- C6CN and Husky Air ECDH behavior and the C1C direct-local HEVC path remain
  device-specific investigation items; other transports may work on those models.
- Long-duration stream/audio soak and extended push-outage/phone-coexistence
  validation remain outstanding. Offline gates and bounded live smoke are not a
  continuous-stability sign-off.
- Export supports H.264/HEVC video and metadata-backed AAC-LC. Recognizing another
  advertised codec does not mean it can be exported; unsupported audio remains
  video-only. Channel-level encrypted VTM payloads are not supported.

## Review and publication workflow

1. Review/merge the release-preparation PR and verify CI and CodeQL on merged main.
2. Run **Release Check** on main with `release-tag=v2.0.0`; inspect its wheel/sdist
   artifacts and wheel-install smoke results. This checks a proposed tag string
   without creating that tag or publishing anything.
3. Obtain explicit owner approval to publish/tag. This preparation does not grant
   that approval. Reassess the known limitations before calling the release ready.
4. After approval, run **Upload Python Package** on the intended merged main commit
   with bare `version=2.0.0`. The existing workflow builds/checks the distributions,
   smoke-tests the wheel, publishes through PyPI trusted publishing, and only then
   creates GitHub release/tag `v2.0.0`. Do not create a separate tag/release first.
5. Verify the PyPI version, artifact contents, GitHub tag/release commit, and
   downstream integration migration. Use these notes for the GitHub release body
   after publishing; the current workflow otherwise emits a generic body.

The **Prepare Release** workflow is not needed for this PR: the version bump and
dated changelog section are already prepared. Running it again for 2.0.0 would
correctly reject the duplicate release section.
