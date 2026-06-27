# Ezviz PyPi

![Upload Python Package](https://github.com/RenierM26/pyEzvizApi/workflows/Upload%20Python%20Package/badge.svg)
[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20me%20a%20coffee-renierm-yellow?logo=buymeacoffee)](https://www.buymeacoffee.com/renierm)

## Overview

Pilot your Ezviz cameras (and light bulbs) with this module. It is used by:

- The official Ezviz integration in Home Assistant
- The EZVIZ (Beta) custom integration for Home Assistant

You can also use it directly from the command line for quick checks and scripting.

## Features

- Inspect device and connection status in table or JSON form
- Control cameras: PTZ, privacy/sleep/audio/IR/state LEDs, alarm settings
- Control light bulbs: toggle, status, brightness and color temperature
- Dump raw pagelist and device infos JSON for exploration/debugging
- Reuse a saved session token (no credentials needed after first login)

## Install

From PyPI:

```bash
pip install pyezvizapi
```

After installation, a `pyezvizapi` command is available on your PATH.

### Dependencies (development/local usage)

If you are running from a clone of this repository or using the helper scripts directly, ensure these packages are available:

```bash
pip install requests paho-mqtt pycryptodome
```

## Quick Start

```bash
# See available commands and options
pyezvizapi --help

# First-time login and save token for reuse
pyezvizapi -u YOUR_EZVIZ_USERNAME -p YOUR_EZVIZ_PASSWORD --save-token devices status

# Subsequent runs can reuse the saved token (no credentials needed)
pyezvizapi devices status --json
```

## CLI Authentication

- Username/password: `-u/--username` and `-p/--password`
- Token file: `--token-file` (defaults to `ezviz_token.json` in the current directory)
- Save token: `--save-token` writes the current token after login
- Saved token precedence: if `--token-file` contains a session token, the CLI reuses
  it even when username/password are also supplied. This preserves MFA/elevated
  session state; a fresh credential login may require MFA again.
- MFA: The CLI prompts for a code if required by your account
- Region: `-r/--region` overrides the default region (`apiieu.ezvizlife.com`)

Examples:

```bash
# First-time login and save token locally
pyezvizapi -u YOUR_EZVIZ_USERNAME -p YOUR_EZVIZ_PASSWORD --save-token devices status

# Reuse saved token (no credentials)
pyezvizapi devices status --json
```

## Output Modes

- Default: human-readable tables (for list/status views)
- JSON: add `--json` for easy parsing and editor-friendly exploration

## CLI Commands

All commands are subcommands of the module runner:

```bash
pyezvizapi <command> [options]
```

### save

Person-friendly media save commands for scripts and Home Assistant
`shell_command` usage. These write to local filesystem paths and print a small
JSON result when `--json` is used.

```bash
# Save a short direct-local live clip. MPEG-TS uses FFmpeg remuxing with copy.
pyezvizapi --token-file ezviz_token.json --json save clip \
  --serial ABC123 --channel 1 --duration 10s \
  --output /config/www/ezviz/front.ts

# Save a direct-local encrypted battery-camera clip.
pyezvizapi --token-file ezviz_token.json --json save clip \
  --serial ABC123 --duration 10s --decrypt-video \
  --output /config/www/ezviz/front.ts

# Save from the full local HCNetSDK command-port media path on port 8000.
pyezvizapi --token-file ezviz_token.json --json save clip \
  --source hcnetsdk-command-port --serial ABC123 --host 192.0.2.10 \
  --hcnetsdk-command-frames-file /config/ezviz/ABC123-port8000-frames.json \
  --duration 10s --output /config/www/ezviz/front.ts

# Trigger a snapshot and save the returned image locally.
pyezvizapi --token-file ezviz_token.json --json save image \
  --serial ABC123 --channel 1 \
  --output /config/www/ezviz/front.jpg

# Save a known alarm/snapshot image URL without triggering a new capture.
pyezvizapi --token-file ezviz_token.json --json save image \
  --serial ABC123 --image-url "https://..." \
  --output /config/www/ezviz/alarm.jpg
```

`save clip` uses the direct-local `9010/9020` SDK path and fetches the LAN
endpoint/CAS tuple from the authenticated client by default. Use
`--source hcnetsdk-command-port` for the full local port-8000 media path when
you have the complete HCNetSDK bootstrap command frames from a trusted local
implementation; the release package consumes those frames and keeps APK/Frida
tooling under `tools/apk-re`. `save image` triggers the camera capture endpoint
unless `--image-url` is supplied, then downloads and decrypts EZVIZ encrypted
image payloads when needed.

Integrations can use the same behavior directly from `client.py` without
shelling out:

```python
result = client.save_clip(
    "ABC123",
    "/config/www/ezviz/front.ts",
    duration_seconds=10,
    source="local-sdk",
)

image = client.save_image(
    "ABC123",
    "/config/www/ezviz/front.jpg",
    channel=1,
)
```

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
  --hcnetsdk-local-ip 192.0.2.20 \
  --hcnetsdk-h264-skip-initial-idr-windows 1
```

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
capture, use `--hcnetsdk-video-wait-for-clean-window`; this discards startup
media until a decodable H.264 IDR or HEVC IRAP window is found, then starts the
requested duration window. Bound that pre-capture wait with
`--hcnetsdk-video-clean-window-wait-seconds N`. The older
`--hcnetsdk-h264-*clean-idr*` names remain accepted as compatibility aliases.
Some cameras expose very sparse or persistently corrupt refresh windows on
generated command-port sessions even after the media socket remains stable; in
that case use the native-prefix media plan above for a playable remux and keep
clean-window wait as a diagnostic.
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

### devices

- Actions: `device`, `status`, `switch`, `connection`
- Examples:

```bash
# Table view
pyezvizapi devices status

# JSON view
pyezvizapi devices status --json
```

Sample table columns include:

```
name | status | device_category | device_sub_category | sleep | privacy | audio | ir_led | state_led | local_ip | local_rtsp_port | battery_level | alarm_schedules_enabled | alarm_notify | Motion_Trigger
```

The CLI also computes a `switch_flags` map for each device (all switch states by name, e.g. `privacy`, `sleep`, `sound`, `infrared_light`, `light`, etc.).

### stream

Experimental VTM cloud stream helpers. Packet tracing prints sanitized metadata only. Dumping writes VLC-friendly MPEG-TS by default using FFmpeg `-c copy` remuxing only, with `--format raw` available for unchanged VTM payloads. Encrypted packets fail unless `--allow-encrypted` is set. Some battery cameras keep the VTM channel unencrypted but encrypt the video NAL payloads inside MPEG-PS; use `--decrypt-video` to decrypt those HEVC/H.264 NAL payloads with the camera encrypt key before writing or remuxing.

```bash
# Inspect stream packet metadata without printing media bytes
pyezvizapi stream trace --serial ABC123 --channel 1 --max-packets 20 --json-lines

# Dump a VLC-playable MPEG-TS capture to a file
pyezvizapi stream dump --serial ABC123 --channel 1 --duration 1m --output stream.ts

# Decrypt encrypted battery-camera HEVC video while dumping
pyezvizapi stream dump --serial ABC123 --channel 1 --duration 30s --decrypt-video --output stream.ts

# Pipe raw MPEG-PS payloads directly into FFmpeg and remux to MPEG-TS
pyezvizapi stream dump --serial ABC123 --channel 1 --format raw | \
  ffmpeg -f mpeg -i pipe:0 -c copy -f mpegts stream.ts

# Serve a local MPEG-TS URL for Home Assistant/FFmpeg clients
pyezvizapi stream proxy --serial ABC123 --channel 1 --listen-port 8558

# Serve a decrypted local MPEG-TS URL for encrypted battery cameras
pyezvizapi stream proxy --serial ABC123 --channel 1 --decrypt-video --listen-port 8558
```

The dump command captures one minute by default. Use `--duration 30s`, `--duration 2min`, or `--duration 0` for unlimited capture; `--max-packets` can still be used as an additional stop limit. MPEG-TS output requires FFmpeg and remuxes the camera payload with codec copy only; it does not transcode video or audio. The proxy serves `http://<host>:8558/<serial>.ts` by default. Each HTTP client opens a fresh VTM stream and remuxes it through FFmpeg. Keep the proxy bound to loopback unless you put it behind an authenticated reverse proxy or otherwise restrict access; the stream URL is not authenticated by `pyezvizapi`.

Direct-local SDK streaming is also available for devices that expose the local
`9010/9020` SDK setup. Authenticated clients can fetch the LAN endpoint, CAS
local-control tuple, and camera media decrypt key explicitly:

```bash
pyezvizapi --token-file ezviz_token.json stream local-sdk-keys \
  --serial ABC123456
```

That command intentionally prints secrets for setup/debug use. For normal
streaming, prefer fetching CAS directly with `--fetch-cas` and let
`--decrypt-video` retrieve the media key from the authenticated client. You can
also save that JSON to a protected file and pass it back with
`--credentials-file`, supply values for one run, or use
`EZVIZ_LOCAL_OPERATION_CODE` and `EZVIZ_LOCAL_CAS_KEY`:

The Python implementation matches the normal app live-view wire shape: local
SDK frames are `32-byte header + AES-CBC/PKCS#5 body + 32-byte ASCII MD5
ciphertext trailer`, then the `9020` stream port emits `$` interleaved RTP carrying
MPEG-PS payloads.

```bash
pyezvizapi stream local-sdk-dump \
  --credentials-file local-sdk-credentials.json \
  --decrypt-video --decrypt-codec encrypted-header \
  --format mpegts --output local.ts \
  --metadata-output local.metadata.json
```

```bash
pyezvizapi stream local-sdk-dump \
  --host 192.0.2.10 --serial ABC123456 \
  --operation-code "$EZVIZ_LOCAL_OPERATION_CODE" \
  --cas-key "$EZVIZ_LOCAL_CAS_KEY" \
  --media-key-hex "$EZVIZ_LOCAL_MEDIA_KEY_HEX" \
  --decrypt-video --decrypt-codec hevc-encrypted-header \
  --inner-address 192.0.2.20 --inner-port 9020 \
  --format mpegts --output local.ts \
  --metadata-output local.metadata.json
```

If your token contains CAS service metadata, `--fetch-cas` can fetch the
operation-code/key tuple through authenticated EZVIZ CAS instead of requiring
those two values on the command line. When `--decrypt-video` is used without
`--media-key` or `--media-key-hex`, the CLI fetches the camera media key with
the authenticated client:

```bash
pyezvizapi --token-file ezviz_token.json stream local-sdk-dump \
  --host 192.0.2.10 --serial ABC123456 --fetch-cas \
  --inner-address 192.0.2.20 --inner-port 9020 \
  --format mpegts --output local.ts
```

Use `--cas-serial` when the cloud CAS lookup needs a different serial form
than the local SDK IV/device serial used for the stream setup. The default
local-sdk helpers also perform the app-style P2P session registration before
querying CAS, which is required by some doorbell devices before
`getDevOperationCode` returns a session. Use `--no-p2p-register`, or pass
`register_p2p_session=False` to the library helpers, only when you have already
registered the session or are intentionally testing the raw CAS behavior. The
explicit `EzvizClient.register_p2p_session()` helper is available for
integrations that want to control this step themselves. EZVIZ CAS endpoints can
serve expired public TLS certificates while app clients continue to use the
endpoint, so this library tolerates WebPKI expiry for the low-level CAS socket
only after a normal verified TLS handshake fails specifically because the
certificate has expired, and it still checks that the expired peer certificate
is valid for the CAS hostname before sending CAS data. Use
`EzvizCAS(..., verify_tls_certificate=True)` when diagnosing strict TLS
verification against the CAS endpoint. The default
`--receiver-shape app` uses the self-closing attribute XML seen in normal EZVIZ
live-view traces; use `--receiver-shape structured` when you need the older
nested `NatAddress`/`InnerAddress` receiver XML shape.
The local SDK client binds the command socket source port to the advertised
receiver port before connecting to the camera command port, matching the
normal app's `bind(0.0.0.0:<ReceiverInfo Port>) -> connect(<camera>:9010)`
sequence.
For encrypted local media, `--media-key` accepts printable media keys and
`--media-key-hex`/`EZVIZ_LOCAL_MEDIA_KEY_HEX` accepts binary native media keys
encoded as hex. This media key is separate from the CAS key used for the
local-SDK control-channel envelope.
The `--credentials-file` form accepts the JSON shape printed by
`local-sdk-keys`: `serial`, `endpoint.host`, `endpoint.command_port`,
`endpoint.stream_port`, `cas.operation_code`, `cas.key`, `cas.encrypt_type`, and
optional `media_key` or `media_key_hex`. Explicit CLI arguments override matching
credential-file fields.
The optional metadata JSON contains only non-secret response commands, statuses,
body classifications, XML tag names, and first-media shape; it deliberately does
not include request bodies, keys, operation codes, UUIDs, timestamps, or payload
bytes.

Library callers that just want bytes can use
`copy_local_sdk_stream_from_client(client, serial, output, ...)`. It fetches the
LAN endpoint and CAS tuple, opens the local `9010/9020` stream, optionally fetches
the media decrypt key when `decrypt_video=True`, and writes either `mpegps` or
`mpegts` output before closing the sockets. Lower-level callers can still use
`open_local_sdk_stream_from_client()` with
`copy_local_stream_to_mpegps()`/`copy_local_stream_to_mpegts()` for clear local
media, or `copy_local_stream_to_decrypted_mpegps()` /
`copy_local_stream_to_decrypted_mpegts()` for encrypted local media. Decrypting
captures must use a bounded `duration_seconds` or `max_packets` value; the decrypt
transform buffers MPEG-PS data so it can handle NALs split across local RTP
packets.

This is separate from the proprietary HCNetSDK command protocol on port `8000`.
`pyezvizapi` includes native-Python framing/remux primitives for caller-supplied
command-port frames, including the port-8000 `$` media length format and clear
H.264 IDMX payloads. The person-facing `save clip --source
hcnetsdk-command-port` wrapper can consume those complete command frames and
write a local MPEG-TS clip. The generated command-port login helper covers the
initial RSA/challenge session setup and exposes the native command auth seed;
`hcnetsdk_command_port_auth_word()` covers the native post-login command-word
transform, and `hcnetsdk_command_port_control_frame()` wraps that transform into
a complete `0x63` control frame for callers that already know the command body
tail. `hcnetsdk_command_port_control_template_from_frame()` extracts reusable
control templates from captured/generated frames while dropping session-bound
client IP and session-id fields.

Native PlayCtrl traces can also show `IDMXAESDecryptFrame` decrypting complete
assembled H.264 frames inside the app. That native AES boundary is currently a
reverse-engineering parity target, not a requirement for the generated
command-port capture path above: the cameras validated so far expose clear
H.264 or HEVC IDMX payloads on the Python command-port path, and forcing AES
there corrupts clear H.264. Keep PlayCtrl AES-boundary work scoped to future app
parity or encrypted command-port evidence, with fresh Frida before/after dumps
and packet sidecars as inputs, rather than mixing it into the clear remux
recovery path.

### cloud_videos

Fetch cloud clip descriptors used by the EZVIZ app download path. The returned metadata can include `seqId`, `storageVersion`, `fileSize`, `crypt`, `keyChecksum`, and the native SDK `streamUrl` host/port.

```bash
# List recent cloud clips
pyezvizapi cloud_videos --serial ABC123 --channel 1 --limit 10

# Hydrate details and emit JSON for further investigation
pyezvizapi --json cloud_videos --serial ABC123 --channel 1 --limit 5 --details

# Download a cloud clip. Direct HTTP(S) URLs are saved as-is; native streamUrl
# clips are fetched through the pure-Python cloud replay protocol and decrypted.
pyezvizapi cloud_video_download --serial ABC123 --channel 1 --seq-id 12345 \
  --output clip.ps --encrypted-output clip.tmp

# Decrypt a previously captured native .tmp file locally in Python
pyezvizapi cloud_video_decrypt --serial ABC123 --input clip.tmp --output clip.ps
```

Some cloud clips only expose the EZVIZ native SDK `streamUrl` host/port in `videoDetails`. For regular cloud-storage clips, `cloud_video_download` now fetches `/v3/cameras/ticketInfo`, downloads the encrypted cloud replay `.tmp` stream over TLS, and applies the local Python PS/NAL decrypt transform. `--encrypted-output` keeps the encrypted `.tmp` for comparison.

`cloud_video_decrypt` is the pure-Python transform step for captured cloud `.tmp` files. Prefer `--serial` so `pyezvizapi` fetches the camera encrypt key without putting it in shell history; `--key` is available for offline/manual experiments. By default, `--decrypt-codec auto` detects HEVC, H.264 with an encrypted NAL header, or H.264 with a clear one-byte NAL header. You can still force `--decrypt-codec hevc`, `--decrypt-codec h264`, `--decrypt-codec h264-clear-header`, or `--decrypt-codec h264-encrypted-header` for manual experiments. `h264` remains the backwards-compatible alias for clear-header H.264.

### sdcard_videos

Fetch SD-card playback record descriptors using the same record-list endpoints exposed by the EZVIZ app.

```bash
# List recent SD-card playback records
pyezvizapi sdcard_videos --serial ABC123 --channel 1 \
  --start-time "2026-05-10T21:50:00" --stop-time "2026-05-10T21:55:00"

# Try the app's common/intelligent record endpoints when the default v2 path is empty
pyezvizapi --json sdcard_videos --serial ABC123 --source common \
  --start-time "2026-05-10T21:50:00" --stop-time "2026-05-10T21:55:00"
```

SD-card records are descriptors for native playback/download. The public API does not currently expose a direct HTTP media URL for every record; use `stream dump` for live VTM capture or `cloud_video_download` when cloud `videoDetails` includes an HTTP(S) URL.

### camera

Requires `--serial`.

- Actions: `status`, `move`, `move_coords`, `unlock-door`, `unlock-gate`, `switch`, `alarm`, `select`
- Examples:

```bash
# Camera status
pyezvizapi camera --serial ABC123 status

# PTZ move
pyezvizapi camera --serial ABC123 move --direction up --speed 5

# Move by coordinates
pyezvizapi camera --serial ABC123 move_coords --x 0.4 --y 0.6

# Switch setters
pyezvizapi camera --serial ABC123 switch --switch privacy --enable 1

# Alarm settings (push notify, sound level, do-not-disturb)
pyezvizapi camera --serial ABC123 alarm --notify 1 --sound 2 --do_not_disturb 0

# Battery camera work mode
pyezvizapi camera --serial ABC123 select --battery_work_mode POWER_SAVE
```

### devices_light

- Actions: `status`
- Example:

```bash
pyezvizapi devices_light status
```

### home_defence_mode

Set global defence mode for the account/home.

```bash
pyezvizapi home_defence_mode --mode HOME_MODE
```

### mqtt

Connect to Ezviz MQTT push notifications using the current session token. Use `--debug` to see connection details.

```bash
pyezvizapi mqtt
```

#### MQTT push test script (standalone)

For quick experimentation, a small helper script is included which can use a saved token file or prompt for credentials with MFA and save the session token:

```bash
# With a previously saved token file
python examples/mqtt_listener.py --token-file ezviz_token.json

# Interactive login, then save token for next time
python examples/mqtt_listener.py --save-token

# Explicit credentials (not recommended for shared terminals)
python examples/mqtt_listener.py -u USER -p PASS --save-token
```

### pagelist

Dump the complete raw pagelist JSON. Great for exploring unknown fields in an editor (e.g. Notepad++).

```bash
pyezvizapi pagelist > pagelist.json
```

### device_infos

Dump the processed device infos mapping (what the integration consumes). Optionally filter to one serial:

```bash
# All devices
pyezvizapi device_infos > device_infos.json

# Single device
pyezvizapi device_infos --serial ABC123 > ABC123.json
```

## Remote door and gate unlock (CS-HPD7)

```bash
pyezvizapi camera --serial BAXXXXXXX-BAYYYYYYY unlock-door
pyezvizapi camera --serial BAXXXXXXX-BAYYYYYYY unlock-gate
```

## RTSP authentication test (Basic → Digest)

Validate RTSP credentials by issuing a DESCRIBE request. Falls back from Basic to Digest auth automatically.

```bash
python examples/rtsp_auth_test.py <IP> <USER> <PASS> --uri /Streaming/Channels/101
```

On success, the script prints a confirmation. On failure it raises one of:

- `InvalidHost`: Hostname/IP or port issue
- `AuthTestResultFailed`: Invalid credentials

## Development

Install the project with development dependencies:

```bash
python -m pip install -U pip wheel
python -m pip install -e .[dev]
```

Run the same local validation used by CI:

```bash
ruff check .
codespell pyezvizapi tests README.md pyproject.toml .github
pip-audit --progress-spinner off
mypy --install-types --non-interactive .
pyright pyezvizapi
pytest --cov=pyezvizapi --cov-report=term-missing --cov-report=xml --cov-fail-under=85
python -m build
twine check dist/*
python -m pip check
```

Run style fixes where possible:

```bash
ruff check --fix .
```

Before committing, remove generated artifacts so they do not leak into PRs:

```bash
rm -rf dist build *.egg-info .coverage coverage.xml .pytest_cache .mypy_cache .ruff_cache
find . -type d -name __pycache__ -prune -exec rm -rf {} +
```

Tests should be offline by default. Do not add tests that require EZVIZ credentials,
real cameras, cloud calls, or live network access. Prefer small fixtures and fakes for
request builders, status parsing, MQTT payload handling, and Home Assistant integration
contracts.

## Side Notes

There is no official API documentation. Much of this is inferred from Ezviz mobile app behavior (Android/iOS). Some regions operate on separate endpoints; US example: `apiius.ezvizlife.com`.

Example:

```bash
pyezvizapi -u username@domain.com -p PASS@123 -r apius.ezvizlife.com devices status
```

For advanced troubleshooting or new feature research, MITM proxy tools like mitmproxy/Charles/Fiddler can be used to inspect traffic from the app (see community guides for SSL unpinning and WSA usage).

## Contributing

Contributions are welcome — the API surface is large and there are many improvements possible.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for development setup, local validation, offline-test expectations, and cleanup guidance before opening a PR.

For questions, bug reports, and feature requests, see [`SUPPORT.md`](SUPPORT.md) for what to include and what not to post publicly.

For changes that affect Home Assistant integrations, see [`docs/home-assistant-contract.md`](docs/home-assistant-contract.md) before renaming methods, changing status keys, or altering auth/MQTT behavior.

For vulnerability reports or security-sensitive behavior, see [`SECURITY.md`](SECURITY.md). Please do not post credentials, MFA codes, tokens, or private camera URLs in public issues.

## Versioning

We follow SemVer when publishing the library. See `CHANGELOG.md` and repository tags for released versions.

Release tags should match the package version in `pyproject.toml` using the form `v<version>` (for example, `v1.0.4.7`). The PyPI publish workflow validates this before uploading distributions.

Recommended release flow:

1. Bump `project.version` in `pyproject.toml` and update `CHANGELOG.md` under `Unreleased` during normal PR work.
2. Run **Prepare Release** with the bare version, then review and merge the generated changelog PR.
3. Run **Upload Python Package** manually with the same bare version. That workflow validates the version, builds and smoke-tests the wheel/CLI, publishes to PyPI, then creates the matching GitHub release/tag.

## License

Apache 2.0 — see `LICENSE.md`.

---

Draft versions: 0.0.x
