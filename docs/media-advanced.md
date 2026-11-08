# Advanced media source and clock recipes

[Documentation index](README.md) · [Basic media saving](media-saving.md)

These specialist recipes retain the former README's native-source details.
Variables such as `client`, `device_snapshot` and parsed clocks/frames are
application-provided inputs, not complete standalone programs. Use the current
[Python client guide](python-api.md) for authentication and cleanup. Model-specific
observations and recorded outcomes are evidence for those inputs, not universal
streaming, app-parity or synchronization guarantees.

## Experimental native clock profiles

For bounded H9c native captures, an **experimental opt-in** preserves the
observed shared 90 kHz video / 16 kHz AAC epoch instead of independently
zeroing both tracks:

```python
from pyezvizapi import LocalSdkClipSource

options = ClipOptions(
    source=LocalSdkClipSource(),  # Uses native TCP.
    capture=CaptureLimits(duration_seconds=20),
    mux=MediaMuxOptions(output_format="mpegts", native_shared_clock=True),
)
result = client.save_clip_with_options("ABC123", "h9c.ts", options)
```

This also supports an explicit `HcNetSdkCommandPortClipSource`. Defaults remain
unchanged. The mode requires real RTP timestamps and source-timestamped AAC;
incompatible origins (more than one second apart), missing timing, unsupported
sample rates, synthetic cadence, and encrypted startup trimming fail explicitly.
Cloud, automatic fallback, ECDH and UDP capture are not supported by this mode.
A nearby clock origin alone does not prove a shared epoch: enable it only for
an independently validated native source. It preserves frames and received
clock gaps without a fixed correction, resampling, or synthesized silence.
The retained H9c clap test recovered about 128 ms of received clock offset,
but residual physical audio lag remains; this is **not a lip-sync guarantee**.
High-level captures are staged so timing failures leave the destination intact.

The long-form API also accepts `save_clip(..., native_shared_clock=True)`, and
CLI users can pass `save clip --native-shared-clock`. Unsupported CLI combinations
are rejected before login. Shared mode rejects multiple accepted AAC/video clock
sources rather than selecting the first plausible origin.

The app's verified capability **915** enables automatic smoothing only when its
integer value is **1**; it is not a clock-alignment capability. Inspect supplied
metadata offline without changing playback or contacting a device:

```python
from pyezvizapi import inspect_app_playback_support, probe_native_rtp_clock

support = inspect_app_playback_support(device_snapshot)
# support.auto_smooth_play is True/False, or None for unavailable metadata.
clock = probe_native_rtp_clock(first_video_timestamp, parsed_aac_stream)
# candidate_offsets_90khz may be present; shared_epoch_verified is always False.
```

The traced H9c app uses MPEG-PS and subsequently rebases each track separately.
Its speaker/display buffering is not copied into file timestamps. Defaults keep
independent native origins and received gaps; this opt-in is not an app-player
replica. See [verified playback probes and conditions](playback-timing.md).

The original `save_clip(...)` keywords and imports from `pyezvizapi.streaming.cloud.protocol` or
`pyezvizapi.streaming.local.session` remain compatible. New lower-level code should import
from canonical `streaming.cloud`, `streaming.local` and `streaming.media`
owners according to responsibility.
See [`docs/streaming.md`](streaming.md) for the source conformance matrix,
lifecycle/output semantics, compatibility boundaries, golden fixtures, and
offline/live validation procedure.

For a read-only inventory across explicitly supplied cameras/channels, use
`pyezvizapi-capabilities private-inventory.json`. Its report separates configured
and advertised capabilities from optional saved-sample codec/decode evidence;
it never starts previews or claims Home Assistant compatibility. See the
[HA capability and delivery plan](ha-streaming-plan.md) for the inventory
schema, finite headless track-copy API and remaining continuous-adapter work.

The optional `pyezvizapi[streaming]` extra adds a
[continuous native PS source owner](native-ha-stream.md) with per-session
PES-ID selection, incremental decryption, bounded output credit and async
cancellation. It is a library boundary for an HA-hosted route, not a standalone
server or a completed HA integration.

Use `source="hcnetsdk-command-port"`, `host="192.0.2.10"`, `command_port=8000`,
and `hcnetsdk_command_frames=(...)` when an integration already has the complete
full-local HCNetSDK port-8000 command bootstrap frames. For native-style flows
that use several short command sockets before the media socket, pass
`hcnetsdk_command_plan=HcNetSdkCommandPortMultiSocketPlan(...)` or use the CLI
`--hcnetsdk-command-plan-file` JSON form with socket `steps`/`sockets`. If the
frames were captured on another device, pass `hcnetsdk_local_ip` or
`--hcnetsdk-local-ip` so the encoded client LAN IP word is patched for the
current host. Both helpers accept a local path or a binary file object and
return a small result dict with the output name, byte count, content type, and
source metadata.

Lower-level command-port callers can use `HcNetSdkCommandPortClient.login()` to
generate the reboot-safe port-8000 RSA/challenge login sequence directly. The
returned `HcNetSdkCommandPortLoginSession` exposes the 4-byte session id, device
serial, decrypted challenge, password seed, and follow-up command auth seed from
the second login response header. Use `hcnetsdk_command_port_auth_word()` with
that session id, auth seed, decrypted challenge, command id, and the native
addend/counter value to generate post-login command header auth words, or
`hcnetsdk_command_port_control_frame()` to build a complete `0x63` post-login
control frame when the command-specific body tail is known. The helper keeps
the login session id in the same network order in both the `0x63` control body
and auth-word generation. Use
`hcnetsdk_command_port_control_template_from_frame()` to strip a captured or
generated `0x63` frame down to the reusable command id/body tail before
rebuilding it with fresh session values. A set of those templates can be grouped
as `HcNetSdkCommandPortGeneratedSocketStep` /
`HcNetSdkCommandPortGeneratedMultiSocketPlan` and rendered into a concrete
`HcNetSdkCommandPortMultiSocketPlan` after a fresh login. If you already have a
concrete plan, `hcnetsdk_command_port_generated_plan_from_socket_plan()` can
extract a generated template plan from it and infer session-relative addend
deltas when the original auth seed and challenge key are supplied. The offline
CLI helper `pyezvizapi stream hcnetsdk-command-plan-generate --input plan.json`
performs the same conversion for JSON plan files and can write directly to a
generated-plan file for later live runs. The clip
helpers can consume a generated plan directly with
`hcnetsdk_command_generated_plan` plus `hcnetsdk_command_password`, or the CLI
equivalents `--hcnetsdk-command-generated-plan-file` and
`--hcnetsdk-command-password`; this runs a fresh command-port login and renders
the session-relative templates before opening the native-style media sockets.
For the app-observed LAN preview sequence, callers can skip the JSON plan file
and use `hcnetsdk_command_port_native_lan_live_view_plan()` directly, or pass
`--hcnetsdk-command-native-plan app-lan-live-view` in the CLI.
Generated-plan JSON templates may set
`"body_tail_transform": "play_login_today"` on the native `0x111040`
play-login template to refresh the captured date words to the current local
date before rendering the frame.
For the native-style EZVIZ HCNetSDK media step (`0x30000`), plan JSON defaults
to not reading a control response from the media socket. Native leaves the
64-byte `IMKH` reply on the media socket and treats it as prefix before the
first `$` media frame; consuming it as a control response can produce a stream
that reaches media but fails to settle like the app. Set `"read_responses":
true`/`"response_reads": 1` only when deliberately running a diagnostic variant.
For generated plans captured from the native LAN preview path, the practical
CLI shape is:

```bash
pyezvizapi --json save clip \
  --source hcnetsdk-command-port \
  --serial ABC123 \
  --host 192.0.2.10 \
  --output front.ts \
  --duration 20 \
  --hcnetsdk-command-native-plan app-lan-live-view \
  --hcnetsdk-command-password "$EZVIZ_LAN_PASSWORD" \
  --hcnetsdk-local-ip 192.0.2.20
```

The command-port password is the device login password; on some cameras it
differs from the cloud video-encryption key. For finite-duration clear captures
using a generated LAN plan, the library automatically waits (up to 60 seconds
by default) for the first decodable H.264 IDR or HEVC IRAP window before
starting the requested clip duration. Use
`--hcnetsdk-video-no-wait-for-clean-window` to disable this behavior.
The typed `save_clip_with_options` API makes the same choice when `ClipOptions`
leaves `mux` unset; an explicit `MediaMuxOptions` retains its selected behavior.

The built-in `app-lan-live-view` plan currently supports `--channel 1` only
because the app-observed command tails include channel-1 fields. It keeps the
media step on the native-prefix behavior above, refreshes native `0x111040`
play-login date words at render time, sends bounded `0x30006` media keepalives,
and issues the app-observed `0x90100` I-frame request after the media socket is
open.
Use `--hcnetsdk-command-metadata-output` during command-port saves to write a
sanitized JSON summary of command ids, response lengths/header fields, and
first-media shape for diagnostics without storing frame bodies or credentials.
For command frames, it also reports bounded nonzero 32-bit samples from the
command-specific body tail while skipping the session-bound client IP/session
prefix. When metadata output is enabled, the save path also records packet
counts plus elapsed timing, lengths, and SHA-256 hashes for a bounded sample of
media packets, along with a bounded IDMX/H.264 frame-shape summary that reports
counts, NAL/FU-A types, RTP-like sequence/timestamp continuity, and hashes
without storing media bytes. Media-socket keepalive send attempts are recorded
as bounded command id/timing/success metadata when a plan includes keepalives.
For owner-run live compatibility checks across multiple cameras,
`tools/apk-re/bin/hcnetsdk-command-live-check` wraps the same native-plan save
path, validates each MPEG-TS output with FFprobe, and writes a sanitized matrix
report. Pass inventory through `EZVIZ_CAMERA_INVENTORY_JSON` or an ignored
`.env` file, and provide host overrides when mDNS resolution is not enough:

```bash
tools/apk-re/bin/hcnetsdk-command-live-check \
  --inventory-file ../secrets/ezviz-camera-inventory.env \
  --host SERIAL_ALIAS=192.0.2.10 \
  --duration 8s
```

The tool skips battery and out-of-use cameras by default, keeps passwords,
camera serials, and encryption keys out of dry-run/report output and artifact
filenames, and classifies common failure stages such as host resolution,
bootstrap/login, missing media packets, unreadable media, or playable MPEG-TS.
After FFprobe accepts a capture, the live-check wrapper also runs FFmpeg with
error-level logging to catch decoder-visible corruption. A clean decode reports
`playable_mpegts`; a nonzero decode exit reports `decode_failed`; zero-exit
stderr on non-H.264 streams reports `decode_warnings`. Zero-exit H.264 stderr is
kept as `playable_mpegts_with_h264_decode_warnings` because some H.264 command-
port sessions can still produce nonfatal decoder chatter around otherwise
playable output. Clean-window recovery should normally drive current H.264
captures back to plain `playable_mpegts`.
Add `--save-sampled-packets` when a matrix run should retain a bounded
raw-dump-compatible `.sampled-packets.bin` sidecar next to each capture attempt.
The sidecar is diagnostic context from packets observed by the metadata
recorder, not a byte-for-byte source map for the final MPEG-TS. Clean-IDR/IRAP
recovery, warning recovery, duration cutoffs, and trim/preroll options can make
the sidecar include packets that are not present in the final remuxed clip, or
omit packets after the configured sample byte/frame limits are reached.
For offline Frida artifacts, the `hcnetsdk-command-dump-summary` stream helper
can summarize dumped
`ezviz-hcnetsdk-command-frame-*.bin` files and raw
`ezviz-hcnetsdk-inbound-media-*.bin` media dumps. The output includes command
counts, bounded command-body samples, scanned command-port media-frame counts,
and the same bounded IDMX/H.264 frame-shape metadata used by live command-port
capture diagnostics.
When collecting a fresh Frida command-shape trace, set
`EZVIZ_FRIDA_WITH_STREAM_TRANSFORM=1` on
`tools/apk-re/frida/run-ezviz-hcnetsdk-command-shape-hook` to load the
stream-transform hook in the same Frida session. This captures command frames,
raw command-port inbound media, and PlayM4 input dumps from the same native run
so their sanitized summaries can be compared directly. The same runner accepts
`EZVIZ_HCNETSDK_TARGET_SERIAL`, `EZVIZ_HCNETSDK_TARGET_IP`,
`EZVIZ_HCNETSDK_TARGET_PORT`, `EZVIZ_HCNETSDK_TARGET_PASSWORD`,
`EZVIZ_HCNETSDK_DUMP_COMMAND_FRAMES`,
`EZVIZ_HCNETSDK_COMMAND_DUMP_DIR`,
`EZVIZ_HCNETSDK_DUMP_INBOUND_MEDIA_CHUNKS`,
`EZVIZ_HCNETSDK_INBOUND_MEDIA_DUMP_DIR`, and
`EZVIZ_HCNETSDK_INBOUND_MEDIA_DUMP_MAX_BYTES` to inject the target and dump
settings before the hook loads. `EZVIZ_HCNETSDK_TARGET_PASSWORD` is only used
inside the Frida-triggered app process when the app has no saved LAN password
for the target serial; the hook logs only the password length. For
LAN-device-list diagnostics,
`EZVIZ_HCNETSDK_FORCE_PREVIEW_AFTER_LOGIN=1` can additionally route a successful
LAN login into the native preview activity so command-port media and PlayM4
input hooks fire without manual tablet interaction.
For read-only local settings diagnostics, set
`EZVIZ_HCNETSDK_DVR_CONFIG_PROBES` to a comma-separated list of
`dwCommand:channel:outSize` entries such as `305:-1:65536,1067:1:65536`. After
the target LAN login succeeds, the hook calls native `NET_DVR_GetDVRConfig` for
each entry so the existing command-frame dump can capture the real command-port
shape. Only use this for GET-style probes; setter flows should be traced through
manual app actions.
If a command-port camera emits corrupt startup video refreshes before stabilizing,
`--hcnetsdk-h264-skip-initial-idr-windows N` can drop the first `N`
IDR-started H.264 windows before remuxing clear IDMX media. Native HCNetSDK
startup traces can include non-video IDMX prelude records on RTP payload types
104/112 before clear H.264 starts on payload type 96, followed by a large
explicit keyframe request. When FFmpeg reports warnings only in that first real
IDR window, `--hcnetsdk-h264-skip-initial-idr-windows 1` mirrors the practical
native-player tolerance and yields a warning-free remux once a later IDR is
available. For a more robust startup workaround,
`--hcnetsdk-video-trim-to-clean-window` samples H.264 IDR or HEVC IRAP windows
with FFmpeg and remuxes from the first one that decodes without video errors.
Because the output begins at the selected clean window, the resulting clip can
be shorter than the requested capture duration. Add
`--hcnetsdk-video-clean-window-preroll-seconds N` with the trim option to
overcapture for up to `N` extra seconds before trimming; this gives generated
command-port sessions time to stabilize while preserving more of the requested
clean clip. Use `--hcnetsdk-video-clean-window-max-windows N` when long
unstable starts need more than the default 32 video windows checked.
If you need to preserve the requested clip duration instead of trimming after
capture on other plans, use `--hcnetsdk-video-wait-for-clean-window`; this
discards startup media until a decodable H.264 IDR or HEVC IRAP window is found,
then starts the requested duration window. Bound that pre-capture wait with
`--hcnetsdk-video-clean-window-wait-seconds N`. The older
`--hcnetsdk-h264-*clean-idr*` names remain accepted as compatibility aliases.
If a camera does not supply a decodable refresh window before the bounded
startup deadline, the save fails instead of publishing a misleading clip.

Descriptor-backed native clear **AV** captures retain received RTP video cadence
and clear AAC timestamps, including automatic clean-window wait/trim. The selected
clean video is matched back to its source packets; audio from discarded startup
and the following picture is excluded. AAC gaps are retained without synthesizing
silence. Unsupported legacy clocks keep their existing video-only fallback.
Whole-suffix decode checks use a bounded input-size-scaled budget for long clips;
small startup probes remain short. `hcnetsdk_video_wait_for_clean_window=False`
passed to `save_clip()` still disables startup filtering and does not promise a
clean startup. Track origins are independently zeroed; absolute AV synchronization
is not inferred without RTCP. Native SDK untrimmed captures also retain source RTP
gaps after decryption.
Neither route infers absolute inter-track synchronization without RTCP.

Experimental plan JSON can set
`read_first_media_immediately` on the media socket step to drain one media
packet before later short command sockets, which is useful when comparing native
startup timing. Plan steps can also set `delay_after_commands_seconds` to keep a
socket open briefly after its command/response exchange before the next step is
run; this is intended for matching native command-port startup pacing during
diagnostics. Media steps with keepalive templates can set
`keepalive_initial_delay_seconds` to override the default first-keepalive delay;
use `0.0` to send the first keepalive immediately, matching native HCNetSDK
startup traces.
For native player dumps that are already H.264 Annex-B bytes,
`summarize_h264_annexb_units()` reports the same kind of bounded NAL-unit
length/type/hash metadata without printing media contents.
`summarize_h264_annexb_idr_windows()` additionally reports IDR-started GOP
window offsets, lengths, and hashes. The CLI can run the same offline diagnostic
without cloud credentials:

```bash
pyezvizapi stream h264-annexb-summary \
  --input native-addtovideodata.h264 \
  --decode-idr-windows
```

The optional decode check feeds each sampled IDR-started window to FFmpeg and
records only the return code and bounded stderr lines. The same bounded decode
check is available for native command-port dump folders:

```bash
pyezvizapi stream hcnetsdk-command-dump-summary \
  --command-frame-dir native-dumps/command \
  --inbound-media-file native-dumps/command/ezviz-hcnetsdk-inbound-media-fd116.bin \
  --playm4-input-dir native-dumps/playm4 \
  --decode-idr-windows
```

Native stream-transform hook labels that already contain Annex-B chunks can be
summarized through the same helper. For example, Gadget traces that include
`PlayCtrl.IDMXAESDecryptFrame` before/after dumps can check the post-decrypt
buffers without concatenating or printing media bytes:

```bash
pyezvizapi stream hcnetsdk-command-dump-summary \
  --native-annexb-dir native-dumps/ezviz-hook \
  --native-annexb-label playctrl-idmx-aes-frame-after \
  --decode-idr-windows
```

The helper auto-detects H.264 vs HEVC for these native Annex-B chunks. It reports
both aggregate IRAP/IDR windows and per-chunk decode samples, because some native
Frida labels are snapshot buffers rather than one linear elementary stream.

Command payload templates still vary by native call, so callers remain
responsible for supplying the correct generated template plan.

