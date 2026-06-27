# Changelog

All notable changes to this project should be documented in this file.

This project follows [Semantic Versioning](https://semver.org/) for published releases.

## Unreleased

### Added

- Added HCNetSDK `NET_DVR_STDXMLConfig` request-shape helpers and local EZVIZ ISAPI builders for `servicesSwitch`, `connectMode`, and `netConfigAndVoiceFileUpload`.
- Added HCNetSDK local PTZ and preset request-shape helpers based on the EZVIZ Android `ptzControlLan` mappings.
- Added HCNetSDK `NET_DVR_GetDeviceAbility` request-shape helpers, EZVIZ LAN ability XML builders, and PTZ ability parsing.
- Added HCNetSDK local device soft/hardware and playback-conversion ability request/parsing helpers.
- Added HCNetSDK `NET_DVR_GetDVRConfig` / `NET_DVR_SetDVRConfig` request-shape helpers for local Wi-Fi, EZVIZ access-domain, audio, video-coding, video-effect, WDR/backlight, day/night, image/OSD, disk, and user-password settings.
- Added HCNetSDK `NET_DVR_FormatDisk`, `NET_DVR_GetFormatProgress`, and `NET_DVR_CloseFormatHandle` request-shape helpers for local SD-card format flows.
- Added offline SADP activation and network-parameter request/result helpers for EZVIZ LAN batch flows.
- Added HCNetSDK `NET_DVR_SetupAlarmChan_V30` / `V41`, `NET_DVR_CloseAlarmChan_V30`, and `NET_DVR_SetSDKLocalCfg` request-shape helpers.
- Added offline HCNetSDK lifecycle/error/version/logout helpers and SADP discovery/logging/V40 network-edit request-shape helpers.
- Added offline HCNetSDK `NET_DVR_FindFile_V30`, `NET_DVR_FindNextFile_V30`, and `NET_DVR_FindClose_V30` request-shape helpers for LAN playback file search.
- Added offline HCNetSDK playback-by-time, playback-control, capture, and local file-download request-shape helpers for LAN playback flows.
- Added offline HCNetSDK playback callback and playback secret-key request-shape helpers for LAN playback flows.
- Added direct EZVIZ LAN `servicesSwitch` setter helpers for changing individual local switches such as `web` while preserving the rest of the current state.
- Added a pure-Python HCNetSDK command-port control client for generated login/control calls, including `NET_DVR_GetDeviceAbility` execution without native HCNetSDK libraries, trace-backed `NET_DVR_STDXMLConfig` execution, and `servicesSwitch` GET/state/SET helpers that preserve existing switch fields before PUT.
- Added trace-backed pure-Python `NET_DVR_GetDVRConfig` command-port helpers for binary config reads, including the app-observed `GET_HD_CFG`/`NET_DVR_HDCFG`, Wi-Fi AP-list, and camera-parameter `NET_DVR_CAMERAPARAMCFG` paths.
- Added trace-backed pure-Python DVR config reads/parsers for Wi-Fi connection status, audio input, audio output volume, video compression, and image/OSD picture config.
- Added compatibility-preserving native accessors for all traced `NET_DVR_COMPRESSION_INFO_V30` blocks and `NET_DVR_PICCFG` video/image/OSD fields.
- Added the sidecar-traced read-only `NET_DVR_PICCFG_V30` command-port alias and a legacy picture-config client convenience method.
- Added pure-Python client convenience methods for trace-backed DVR config reads that return typed parser results directly.
- Added a typed pure-Python `NET_DVR_HDCFG` parser and client convenience method for traced local storage config reads.
- Expanded the traced `NET_DVR_HDCFG` parser with decoded disk-table entries and malformed table validation.
- Accepted live command-port size-word variants across traced size-prefixed DVR config parsers, and decoded binary IPv4 fields in traced `NET_DVR_NETCFG_V30` responses.
- Expanded the traced `NET_DVR_CAMERAPARAMCFG` parser with the remaining video-effect bytes exposed by the native structure.
- Added compatibility-preserving `NET_DVR_CAMERAPARAMCFG` accessors for traced WDR, day/night, and backlight fields.
- Added the trace-backed command-port mapping for read-only `NET_DVR_WIFI_CFG` reads, plus a non-secret summary helper that avoids decoding credential-bearing fields.
- Added trace-backed command-port mappings for read-only network and record-schedule DVR config reads.
- Added trace-backed command-port mappings for read-only time, NTP, and device V40 DVR config reads.
- Added typed pure-Python parsers and convenience reads for traced DVR time, NTP, and device V40 config.
- Added a typed pure-Python parser and convenience read for traced DVR network config.
- Added a typed pure-Python parser and convenience read for traced DVR record schedule config.
- Added a trace-backed command-port mapping for read-only EZVIZ access DVR config reads, plus a non-secret summary helper that avoids decoding access/security strings.
- Added binary-confirmed command-port mapping plus decoded and summary helpers for `NET_DVR_USER_V30` user/password/right-table reads; decoded password bytes are hidden from default object reprs.

### Fixed

- Fixed direct-local SDK CAS bootstrapping for HP7/CP7-style devices by adding
  app-style P2P session registration before local-sdk CAS lookups, with opt-out
  switches for diagnostics.
- Fixed direct-local SDK CAS lookups against EZVIZ CAS endpoints that present
  expired public TLS certificates by matching the app's pinned-certificate
  behavior for the CAS socket only.

- Fixed the DVR config sidecar to exit nonzero on failed `NET_DVR_GetDVRConfig` reads before emitting output buffers.

## v1.0.5.0 - 2026-06-20

### Added

- Added direct-local SDK streaming support for cached local-SDK credentials, including CAS probing, stream bootstrap, and FFmpeg remuxing for local live-view captures.
- Added local IDMX HEVC stream handling for encrypted EZVIZ local payloads, converting media-wrapper frames to Annex B and decrypting encrypted HEVC NAL prefixes for `--decrypt-video` captures.
- Added an HCNetSDK command-port multi-socket plan backend for native-style port-8000 flows that open short control sockets before the media socket.
- Added native-Python HCNetSDK command-port login frame generation, RSA challenge decoding, login proof generation, and login-session parsing with the follow-up command auth seed.
- Added native-Python HCNetSDK command-port auth word generation, complete `0x63` control-frame generation, and reusable control-template extraction for post-login port-8000 commands.
- Added generated HCNetSDK command-port multi-socket save support, including fresh login, session-relative plan rendering, and CLI JSON loading via `--hcnetsdk-command-generated-plan-file`.
- Added built-in `app-lan-live-view` HCNetSDK command-port native-plan support for channel 1, exposed through `hcnetsdk_command_port_native_lan_live_view_plan()` and `--hcnetsdk-command-native-plan app-lan-live-view`, so app-observed LAN preview captures no longer require a separate generated-plan JSON file.
- Added a generated-plan `body_tail_transform=play_login_today` option for refreshing captured native `0x111040` play-login date words during live command-port rendering.
- Added offline `stream hcnetsdk-command-plan-generate` support to convert concrete port-8000 socket plan JSON into reusable generated-plan JSON.
- Added sanitized command-port exchange metadata, bounded command-body tail word samples, media-socket keepalive timing, sampled packet timings/hashes, and bounded IDMX/H.264 frame-shape summaries with RTP-like sequence/timestamp continuity to local stream metadata output and `save clip --hcnetsdk-command-metadata-output` for generated-plan diagnostics.
- Added sanitized H.264 Annex-B NAL-unit and IDR-window summarizers, plus an offline `stream h264-annexb-summary` CLI, for comparing native player dumps with generated command-port diagnostics without storing media contents.
- Added offline `stream hcnetsdk-command-dump-summary` support for summarizing Frida command-frame, inbound-media, and PlayM4 input dump artifacts without printing frame bodies or credentials.
- Added optional IDR-window FFmpeg decode checks to `stream hcnetsdk-command-dump-summary` so native command-port dumps can show startup corruption and later clean windows directly.
- Added `tools/apk-re/bin/hcnetsdk-command-live-check`, an owner-run port-8000 compatibility matrix runner that loads ignored inventory secrets, runs the built-in native LAN live-view plan, validates MPEG-TS output with FFprobe, and writes per-camera verdicts without exposing passwords, serials, or encryption keys.
- Added `EZVIZ_FRIDA_WITH_STREAM_TRANSFORM=1` support to the command-shape Frida runner so command-port and PlayM4 input artifacts can be captured in one native session.
- Added `EZVIZ_HCNETSDK_FORCE_PREVIEW_AFTER_LOGIN=1` for Frida command-shape diagnostics that need to route a LAN login into the native preview activity.
- Added Frida command-shape runner env injection for target and dump settings, and fixed TCP-shape fingerprint logging on Frida runtimes without `Uint8Array.slice()`.
- Added an experimental `read_first_media_immediately` command-plan flag for HCNetSDK startup-order diagnostics.
- Added an experimental `delay_after_commands_seconds` command-plan field for matching native HCNetSDK command-port startup pacing during diagnostics.
- Added an experimental `keepalive_initial_delay_seconds` command-plan field for matching native HCNetSDK media-socket keepalive pacing during diagnostics.
- Added `--hcnetsdk-h264-skip-initial-idr-windows` to drop corrupt startup IDR windows before remuxing clear H.264 IDMX command-port captures.
- Added `--hcnetsdk-h264-trim-to-clean-idr-window` to decode-check sampled startup IDR windows and remux clear H.264 IDMX command-port captures from the first clean window.
- Added `--hcnetsdk-h264-clean-idr-preroll-seconds` to overcapture before clean-IDR trimming so generated command-port clips can keep more requested clean duration after startup corruption is discarded.
- Added `--hcnetsdk-h264-clean-idr-max-windows` to raise the clean-IDR decode-check search limit for long unstable command-port startups.
- Added `--hcnetsdk-h264-wait-for-clean-idr-window` and `--hcnetsdk-h264-clean-idr-wait-seconds` to discard corrupt H.264 IDMX startup media before starting the requested capture duration.
- Added generic `--hcnetsdk-video-*` clean-window aliases so H.264 and HEVC command-port captures can use the same recovery options.
- Added regression coverage for RTP dump decryption when `--decrypt-video` is used with explicit encrypted-header codec modes.

### Changed

- Refreshed CAS service metadata only for CLI CAS flows and preserved cached-session reuse behind stricter `sysConf` checks.
- Updated RTP stream dumping so user-selected decrypt-codec modes control the decrypt offset while transport detection still drives RTP depacketizing and remuxing.
- Bumped `requests` from 2.33.1 to 2.34.2.

### Fixed

- Fixed cloud and direct-local stream timeout handling so unreachable/offline cameras raise clear `DeviceException` errors instead of leaking raw timeouts.
- Fixed direct-local encrypted-header decryption to preserve PES boundaries and avoid H.264/HEVC RTP payload overlap during stream remuxing.
- Fixed HCNetSDK command-port media framing by parsing port-8000 `$` length words as little-endian total frame lengths, and added clear H.264 IDMX remuxing for those media packets.
- Fixed generated HCNetSDK command-port `0x63` control bodies to serialize the login session id in native network order, matching auth-word generation and avoiding no-body `0x1e` responses.
- Fixed bounded local-stream capture duration accounting so generated-login/bootstrap latency does not reduce the requested media capture window.
- Fixed HCNetSDK command-port response reads to tolerate native short no-body ack headers used during play-login draining.
- Documented and regression-tested the stable generated HCNetSDK media-step shape: plan JSON media sockets default to leaving the native `0x30000` IMKH reply on the media socket as prefix data instead of consuming it as a control response.
- Fixed clear H.264 IDMX extraction to require the native RTP payload type 96 before treating IDMX bodies as H.264 NAL/FU-A media, leaving 104/112 startup prelude records out of the Annex-B remux even when their bytes look video-shaped.
- Documented the practical generated-plan capture recipe for warning-free native-style command-port H.264 remuxes: preserve the media-prefix behavior, refresh play-login date words, and skip the first startup IDR window.
- Fixed Frida command-shape TCP fingerprint helpers to avoid global-name collisions when the stream-transform hook is loaded in the same session.
- Improved HCNetSDK command-port multi-socket errors with socket-step, frame, command id, and first-media context.
- Preserved partial HCNetSDK command-port bootstrap metadata when the media socket resets before the first packet.
- Fixed partial CAS probe writes and base64 local-SDK CAS key handling.
- Fixed HCNetSDK command-port HEVC remuxing by preserving IDMX packet boundaries, handling direct/RTP/HRUDP media wrappers, carrying HEVC parameter sets into clean IRAP probes, and remuxing raw HEVC with an explicit input rate.
- Fixed `ptz_control_coordinates()` to use the app-matched `PTZManualCtrl/CtrlPTZ3DPosition` IoT action endpoint with `positionPoint.x/y`, restoring y-axis tilt coordinate moves.
- Fixed PTZ coordinate validation to reject negative coordinate values and omitted zoom hints from point moves so focus/zoom metadata is left unchanged.

## v1.0.4.9 - 2026-05-10

### Added

- Added cloud stream bootstrap helpers for VTM pagelist metadata, VTDU token retrieval, VTM/VTDU packet framing, `ysproto` URL handling, limited stream protobuf parsing, RTP payload extraction, and transport detection.
- Added VTM server public-key extraction plus native VTDU protobuf helpers for `GetVtduInfo`, `StartStream`, `PeerStream`, and `StopStream` stream-control messages.
- Added a sanitized VTM trace harness and CLI command for live stream diagnostics without exposing packet bodies, tokens, or keys.
- Added experimental VTM stream dump/proxy CLI commands and README usage for writing VLC-friendly one-minute MPEG-TS captures by default, raw payload dumps on request, or serving a local FFmpeg-remuxed MPEG-TS URL.
- Added Hikvision/EZVIZ MPEG-PS video payload decryption for `stream dump --decrypt-video` and `stream proxy --decrypt-video`, covering battery-camera streams that keep the VTM channel clear but encrypt HEVC/H.264 NAL bodies.
- Added cloud video list/detail client helpers plus `cloud_videos` and `cloud_video_download` CLI commands for exploring and saving EZVIZ cloud clip media when the API returns a direct HTTP(S) URL.
- Added `get_camera_ticket_info()` for the `/v3/cameras/ticketInfo` ticket used by the native cloud-storage download path.
- Added pure-Python cloud `.tmp` PS/NAL decryption through `cloud_video_decrypt`.
- Added pure-Python EZVIZ cloud replay download support for regular cloud-storage `streamUrl` clips, so `cloud_video_download` can fetch encrypted `.tmp` bytes without Android tooling and decrypt them locally.
- Added SD-card playback record helpers plus the `sdcard_videos` CLI for probing the EZVIZ app's v2/common/intelligent record-list endpoints.
- Added alarm image download/decrypt helper support for EZVIZ/Hik encrypted snapshot payloads.

### Changed

- Updated CI, CodeQL, and Dependency Review pull-request path filters so tests-only changes trigger the required checks, and excluded the captured pagelist fixture from Codespell because it preserves upstream cloud/device strings verbatim.

### Fixed

- Fixed VTM tracing to parse delayed `StreamInfoRsp` packets after earlier control packets so redirects are still followed.
- Fixed encrypted alarm image detection to search the full payload for the encryption marker before deciding whether to decrypt.
- Fixed VTDU token lookup when EZVIZ service URLs return a null `authAddr` by deriving the auth host from `api_url`.
- Fixed `--decrypt-codec h264` to remain the backwards-compatible clear-header H.264 mode, with `h264-encrypted-header` for H.264 streams whose NAL header is encrypted.

## v1.0.4.8 - 2026-05-03

### Added

- Added sanitized full pagelist fixture coverage for `get_device_infos()` and `load_devices(refresh=False)` so the parser is tested against a realistic cloud response without live EZVIZ credentials.

### Changed

- Updated remote unlock to prefer terminal-derived bind codes from the EZVIZ terminals API while preserving legacy bind-code fallback behavior.

### Fixed

- Fixed `set_floodlight_brightness()` to accept `luminance=100`, matching the documented 1-100 range and allowing Home Assistant brightness sliders to reach full brightness/color night-vision mode.

## v1.0.4.7 - 2026-04-27

### Added

- Added manual release dispatch to the trusted PyPI publish workflow so releases can be published by running a workflow with the requested version.
- Added `codespell`, `pip-audit`, and Pyright checks to CI for extra spelling, dependency vulnerability, and static typing coverage.

### Changed

- Widened camera key/auth verification-code argument typing to accept string codes from Home Assistant forms without forcing callers to cast.
- Reworked device wrapper construction through a dedicated factory to remove client/device module import cycles while preserving existing wrapper behavior.
- Lazy-load top-level `pyezvizapi` package exports to reduce eager import graph pressure while keeping convenient imports such as `from pyezvizapi import EzvizClient`.
- Tightened `EzvizClient` JSON payload typing with a shared `JsonDict` alias and fixed Pyright-reported optional-token and MQTT-client typing issues.
- Updated release automation so the prepare step opens a changelog PR and the publish step validates, builds, smoke-tests, uploads to PyPI, and creates the GitHub release.

### Removed

- Removed the superseded manual-release workflow in favor of the trusted PyPI publish workflow dispatch path.

## v1.0.4.6 - 2026-04-27

### Added

- Modern package build checks in CI, including wheel install, CLI smoke tests, and supported Python version matrix coverage.
- Offline tests for utility helpers, feature parsing, device parsing, MQTT decoding, pagelist pagination, HTTP helpers, auth/token lifecycle behavior, camera/light/smart-plug status helpers, alarm parsing, CLI command dispatch, load-device aggregation, unified-message request building, device add/security flows, devconfig/network helpers, IoT feature/action helpers, device maintenance/admin helpers, voice/whistle/chime helpers, PTZ/panoramic helpers, camera key/2FA flows, managed-device/status/P2P helpers, time-plan/search helpers, lower-tail client helpers, CAS helpers, RTSP helpers, and MQTT demo tooling.
- PEP 561 `py.typed` marker so downstream type checkers can consume inline package types.
- Example wrappers for MQTT listening and RTSP authentication testing.

### Changed

- Added CI coverage reporting, coverage XML artifacts, and a conservative 85% coverage floor.
- Added CI `pip check` validation for both editable development installs and built-wheel smoke-test installs.
- Added release workflow wheel smoke testing with `pip check` and CLI help checks before PyPI publishing.
- Added a manual release-check workflow for dry-run package builds, optional tag/version verification, wheel smoke testing, and artifact upload before publishing.
- Added CodeQL security-and-quality scanning for Python on relevant pull requests, pushes, scheduled runs, and manual dispatch.
- Added Dependency Review checks for dependency and workflow changes, failing high-severity vulnerable dependency updates before merge.
- Documented the development validation workflow, artifact cleanup commands, and offline-test policy in the README.
- Added contributor, support, security, PR checklist, and issue-template documentation for safer reports and easier maintenance.
- Added editor and Git line-ending defaults, plus Ruff cache ignores, to reduce generated-artifact and formatting drift.
- Added package metadata links for documentation and changelog discoverability on PyPI.
- Added Home Assistant integration contract documentation for stable APIs, status payloads, auth exceptions, MQTT behavior, and release coordination.
- Limited alarm prefetching to camera devices so smart-plug/socket serials are not queried as camera alarm targets.
- Added PyPI keywords and Trove classifiers for supported Python versions, typed-package status, Home Assistant/EZVIZ discovery, and CLI/library usage.
- Consolidated package metadata into `pyproject.toml` while keeping `setup.py` as a compatibility shim.
- Restored the installed `pyezvizapi` console script via `project.scripts`.
- Replaced CLI table rendering dependency on pandas with a small stdlib formatter.

### Removed

- Removed pandas from the runtime dependency set.

## Release checklist

Before publishing a release:

1. Bump `project.version` in `pyproject.toml`.
2. Move relevant entries from `Unreleased` to a dated version section by running **Prepare Release** with the bare version and merging the generated changelog PR.
3. Ensure CI is green on `main`.
4. Run **Upload Python Package** manually with the same bare version.
5. Confirm the workflow publishes to PyPI and creates the matching GitHub release/tag.
