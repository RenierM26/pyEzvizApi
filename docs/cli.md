# Command-line guide

[Documentation index](README.md) · [Getting started](getting-started.md)

Global options go **before** the command: `pyezvizapi --json devices status`,
not `pyezvizapi devices status --json`. Subcommand options go after their
command, such as `camera --serial CAMERA_SERIAL status`.

Use `pyezvizapi --help`, `pyezvizapi camera --help`, and
`pyezvizapi stream local-sdk-dump --help` for the installed version's full flags.
`python -m pyezvizapi` is an equivalent entry point.

## Login verification

The CLI keeps verification codes as strings, including leading zeros. Select
SMS with global `--mfa-channel sms` (or email with `--mfa-channel email`). If the
server does not return the bound contact, provide `--mfa-account` explicitly.
The login username is not used to guess the verification channel. Example:

```bash
pyezvizapi -u YOUR_USERNAME -p YOUR_PASSWORD --mfa-channel sms --save-token devices status
```

These options also apply to `mqtt` profile migration. A successful code request
is not proof of delivery. CAPTCHA, terminal management, region selection and
security-contact flows require recovery in the EZVIZ app; the CLI does not loop
or send extra codes for them. See [login recovery](auth/login-recovery.md).

## Command families

| Command | Purpose |
| --- | --- |
| `devices`, `device_infos`, `pagelist` | Account inventory and status; raw output can contain private data |
| `camera`, `light`, `devices_light`, `home_defence_mode` | Device status and controls; support depends on model/account |
| `unifiedmsg` | Unified alarm/message listing |
| `cloud_videos`, `sdcard_videos` | Recording descriptors, not a universal playable URL |
| `recordings list`, `recordings download` | [SD recording catalog and resumable batch downloads](recording-catalog.md) |
| `cloud_video_download`, `cloud_video_decrypt` | Cloud replay download and offline decryption |
| `save clip`, `save image` | [Finite clips and images](media-saving.md) |
| `stream` | [Specialist stream transport/debug commands](stream-cli.md) |
| `mqtt` | [Channel-99 push and token migration](channel99.md) |
| `lan rtsp` | Read/enable/disable the LAN RTSP service; no account login |
| `lan ptz` | Pan or tilt for a bounded time, then stop; no account login |
| `pyezvizapi-capabilities` | Explicit offline capability inventory; see [media paths](media.md) |

The sections below use synthetic serials/paths. Control examples perform real
operations if run with your own credentials; they are not validation commands.
Default output is human-readable where supported; `--json` requests structured
output, but command results and error handling remain command-specific.

### Unified alarm history

`unifiedmsg` fetches one page of alarm messages. Omit `--serials` to query all
devices, or pass a comma-separated list. The default limit is 20 (maximum 50).
`--date` takes `YYYYMMDD` and defaults to today's date in the CLI process's
local timezone, not the account or camera timezone.

```bash
pyezvizapi --json unifiedmsg --serials CAMERA_SERIAL --date 20261126 --limit 20
pyezvizapi --json unifiedmsg --serials CAMERA_SERIAL --date 20261126 --limit 20 --end-time RAW_TIME
```

Omit `--end-time` to start with the newest messages for the query. For the next
page, keep the filters and date the same and replace `RAW_TIME` with the last
row's raw `time` value, unchanged. Do not use `msgId` or the formatted time shown
in the table. A timestamp cursor is not a guarantee of exhaustive history when
multiple messages share a timestamp at a page boundary.

Global `--json` emits an array of message rows (or `[]`), not the full API
response. `--urls-only` prints a serial and media URL per message that has one,
even if `--json` is also set.

The CLI uses the default subtype `92`. For custom subtype filters, the full
response, or direct HTTP requests, see the
[Unified message list API reference](unified-message-list.md).

Latest-alarm polling is separate from history paging. When the first result
doesn't include a camera, polling can issue fresh queries scoped to the missing
cameras rather than treating an older history page as authoritative. The result
is the newest matching alarm returned by EZVIZ at poll time.

### lan rtsp

Use the camera's current **local device password**, not an EZVIZ account password.
The command uses the existing pure-Python HCNetSDK command-port implementation;
it does not read account token files, contact the cloud, load native libraries,
probe other ports, or change SDK/web/UPnP switches. The local SDK command port
(normally 8000) must already be reachable. No automatic port-opening fallback is
attempted if it is closed.

```bash
pyezvizapi lan rtsp status --host 192.0.2.10 --serial CAMERA_SERIAL \
  --lan-password-file /private/device-password
pyezvizapi lan rtsp enable --host 192.0.2.10 --serial CAMERA_SERIAL \
  --lan-password-file /private/device-password
# Use disable instead of enable to turn RTSP off.
```

Keep the password file private. Optional `--command-port`, `--lan-username`,
`--local-ip` and a finite positive per-socket `--timeout` configure the local SDK
connection. Each SDK request can use multiple socket operations; this is not a
whole-command deadline. These commands always emit JSON and exit nonzero on
failure. `status` is read-only; enable/disable are idempotent. An absent or unknown
RTSP switch is rejected before writing. A change preserves the fetched payload,
updates only `rtsp`, requires an application-level success response, then reads
the switch back. Avoid concurrent configuration changes from another client.

Success (`verified: "configuration"`) confirms the switch value, **not** an RTSP
listener, authenticated stream, or Home Assistant playback. Firmware without
RTSP support cannot gain it through this switch. A camera may restart network
services during a change; if the acknowledgment or read-back fails, the result
is `outcome: "unknown"`, not proof of rollback. The command does not retry writes.
Wait for services to recover and use `status` to determine the effective state.
Issue [#345](https://github.com/RenierM26/pyEzvizApi/issues/345) contains
@cgaspard3333's C3X firmware-specific hardware observations; other models require
their own qualification.

Library callers can use the existing canonical public SDK entry point directly:

```python
from pyezvizapi.streaming.local.hcnetsdk.api import (
    HcNetSdkLanEndpoint,
    HcNetSdkPurePythonClient,
)

sdk = HcNetSdkPurePythonClient(
    HcNetSdkLanEndpoint(serial="CAMERA_SERIAL", host="192.0.2.10"),
    device_password,  # application-owned local credential
    timeout=10.0,
)
state = sdk.services_switch_state()  # read-only
# Explicit mutation (only when requested by your user):
# response = sdk.services_switch_set(state.raw, rtsp=1)
# Check response.succeeded AND response.json()["statusCode"] == 1, then read back.
```

The low-level API remains unchanged; consumers own validation, errors and
read-back. Run these blocking SDK operations off an async event loop. Old flat
`pyezvizapi.hcnetsdk` imports have been removed; see [compatibility changes](ha-compatibility.md).

### lan service

Read or update a named local service switch with the same endpoint and password
options as `lan rtsp`. The CLI updates only the requested switch and verifies
it by reading it back. These are local services, not EZVIZ numbered cloud
switches.

```bash
pyezvizapi lan service hiksdk status --host 192.0.2.10 --serial CAMERA_SERIAL \
  --lan-password-file /private/device-password
pyezvizapi lan service web disable --host 192.0.2.10 --serial CAMERA_SERIAL \
  --lan-password-file /private/device-password
```

Both `web` and `hiksdk` take `status`, `enable` or `disable`. Setting
`hiksdk` to disabled can close the very command port used for read-back or
re-enabling. If the port closes, verification can fail with an unknown outcome;
the CLI does not retry. Use an independent recovery path (such as the EZVIZ app)
if you intend to disable local SDK access.

### lan wdr

Read channel 1's local WDR and backlight mode without making a change:

```bash
pyezvizapi lan wdr status --host 192.0.2.10 --serial CAMERA_SERIAL \
  --lan-password-file /private/device-password
```

The command uses `HcNetSdkPurePythonClient.camera_param_config()`. It returns the
firmware's raw `wdr_enabled` and `backlight_mode` values, with `null` for an
omitted field. It reports an error if neither field is present. A returned field
does not by itself establish capability support or parity with cloud switch
604.

Use `lan wdr enable` or `lan wdr disable` with the same connection options.
The SDK method `set_camera_wdr(enabled)` requires the native 152-byte layout
and a binary starting value. It preserves backlight mode and the other bytes
in the outgoing configuration, sends at most one write, and verifies the full
configuration by reading back. Native setting writes through a single SDK
client are serialized from the initial read through verification. This does
not coordinate different clients or protect a service-switch payload that
the caller read separately. Avoid concurrent configuration changes from
another client.
If verification fails, read status before retrying. Writes were verified on
an H9c; other models are unverified.

SDK callers can use `set_camera_video_effect(effect, level)` for brightness,
contrast, sharpness or saturation, and `set_camera_day_night_mode(mode)` for
the numeric native mode. Read the current values via `camera_param_config()`.
The day/night writer preserves the existing schedule and is not the numbered
cloud IR switch.

SDK callers can also use `set_audio_input_volume(volume)` and
`set_audio_output_volume(volume)` (integer 0-100). Each updates only its own
configuration and verifies it by reading back. On the H9c, a change addressed
to channel 1 was also visible when reading channel 2. These setters are not
per-lens controls.

For legacy picture configuration, use `osd_visible()` and
`set_osd_visible(visible)`. These use the legacy wire field rather than the
V40 picture model's OSD offset. The H9c shares OSD visibility across both
reported channels; this is not a per-lens control.

`set_camera_mirror_mode(mode)` updates the default camera’s native mirror
configuration. Modes are numeric (0-3); this does not set the cloud ImageFlip
property. On H9c the configuration was verified, not the rendered orientation
or which physical lens changes.

### lan ptz

Moves the camera over the local command port with the same credentials and
connection options as `lan rtsp`. It sends one start, waits `--duration` seconds
(default 0.5, at most 5), then sends the stop. The stop is sent even if the start
fails or the command is interrupted, and is retried once after an error or a
missing acknowledgment. The start is never retried.

The duration counts from the moment the start frame is written, not from its
acknowledgment, and the wait for that acknowledgment ends at the same deadline.
If the camera answers late or not at all, the stop still goes out on time. Each
stop attempt, login included, must finish within `--timeout`, so in the worst
case the motor runs for `--duration` plus one `--timeout`. A stop attempt that
fails before its frame is written is retried once, which can add one more
`--timeout`. A start that gets no acknowledgment is closed with a TCP reset, so
a start packet lost on the network is not retransmitted after the stop. Each
frame still uses its own login, the only pattern tested on hardware; reusing
the start's session for the stop was not verified.

```bash
pyezvizapi lan ptz left --host 192.0.2.10 --serial CAMERA_SERIAL \
  --lan-password-file /private/device-password
pyezvizapi lan ptz up --duration 1 --speed 4 --host 192.0.2.10 --serial CAMERA_SERIAL \
  --lan-password-file /private/device-password
```

Directions are `up`, `down`, `left` and `right`. `--speed` is 1-7 (default 4; only 4 tested) and
`--channel` defaults to 1. Output is JSON. Success (`verified: "acknowledgment"`)
means the camera acknowledged both frames, **not** that the motor moved; check the
picture if it matters. On failure, `start` and `stop` say what happened to each
frame: `not-sent`, `unacknowledged` (written, no acknowledgment) or
`acknowledged`. Do not run it while another client is moving the camera.

On the wire this is `NET_DVR_PTZControlWithSpeed_Other` as command-port id
`0x00030203`. The body tail is channel, command and speed as big-endian 32-bit
words, with the command signed: a stop has no separate flag and is sent as
`-(command + 1)`, so left (23) stops with -24. The values were observed on a
CS-C6N-R101-1G2WF; other models need their own check.

```python
import time

from pyezvizapi.streaming.local.hcnetsdk.api import (
    EZVIZ_LAN_PTZ_ACTION_STOP,
    EzvizPtzCommand,
    HcNetSdkLanEndpoint,
    HcNetSdkPurePythonClient,
)

sdk = HcNetSdkPurePythonClient(
    HcNetSdkLanEndpoint(serial="CAMERA_SERIAL", host="192.0.2.10"),
    device_password,
    timeout=10.0,
)
sent = []
try:
    sdk.ptz_control(
        EzvizPtzCommand.LEFT,
        speed=4,
        ack_timeout=0.5,  # wait for the reply no longer than the move itself
        on_sent=lambda: sent.append(time.monotonic()),
    )
    ...  # sleep until sent[0] + 0.5
finally:
    sdk.ptz_control(EzvizPtzCommand.LEFT, action=EZVIZ_LAN_PTZ_ACTION_STOP, speed=4)
```

`on_sent` runs as soon as the frame is written, which is when the motor can
start. `ack_timeout` bounds the wait for the reply from that moment and raises
`EzvizLocalSdkDeadlineExpired` when it runs out. `deadline` (a
`time.monotonic()` value) bounds the whole call, login included; the CLI passes
`time.monotonic() + timeout` for each stop attempt.

`hcnetsdk_ptz_control_command_port_template(request)` builds the same frame from
an `ezviz_lan_ptz_control_request` for callers that run templates themselves.

### devices

- Actions: `device`, `status`, `switch`, `connection`
- Examples:

```bash
# Table view
pyezvizapi devices status

# JSON view
pyezvizapi --json devices status
```

Sample table columns include:

```
name | status | device_category | device_sub_category | sleep | privacy | audio | ir_led | state_led | local_ip | local_rtsp_port | battery_level | alarm_schedules_enabled | alarm_notify | Motion_Trigger
```

The CLI also computes a `switch_flags` map for each device (all switch states by name, e.g. `privacy`, `sleep`, `sound`, `infrared_light`, `light`, etc.).

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

SD-card records are descriptors for native playback/download. Use
[`save clip --source cloud-playback`](cloud-sd-playback.md) to download an explicit
SD recording range through VTM. The public API does not currently expose a direct HTTP media URL for every record; use `stream dump` for live VTM capture or `cloud_video_download` when cloud `videoDetails` includes an HTTP(S) URL.

### camera

Requires `--serial`.

- Actions: `status`, `move`, `move_coords`, `unlock-door`, `unlock-gate`, `switch`, `alarm`, `select`
- Examples:

```bash
# Camera status
pyezvizapi camera --serial ABC123 status

# PTZ move
pyezvizapi camera --serial ABC123 move --direction up --speed 5
# Or target the camera’s reported cloud playback channel:
pyezvizapi camera --serial ABC123 move --direction up --channel 2

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

Receive channel-99 push notifications. Old web-profile logins require credential/MFA migration; tokens and push keys are saved privately throughout the connection. See the [migration guide](channel99.md).

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

# Token saving is mandatory for channel-99; --save-token remains a compatibility flag.
```

### pagelist

Dump the merged account inventory JSON for the SDK's standard set of
[pagelist sections](pagelist-api.md). It fetches all pages for that query,
not every possible section. The raw output can contain private routing
metadata and credentials; keep it local or redact it before sharing.

```bash
pyezvizapi pagelist > pagelist.json
```

### device_infos

Dump the processed device infos mapping (what the integration consumes).
With `--serial`, the SDK attempts a single-device resource request and
[falls back to account inventory](pagelist-api.md#choose-an-sdk-or-cli-view)
when needed:

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

Authentication success does not establish audio/video capture integrity. In
tested EZVIZ RTSP AAC sessions, FFmpeg stream-copy capture can discard all audio
at startup; `-copyinkf:a` retains those audio packets
without changing timestamps or weakening the video keyframe gate. Verify full
audio decoding as well as video; an AAC stream listed with zero sample rate or
channels is not evidence of usable audio.

For multi-lens H9c offline selection and retained-wire RTSP AV checks, see
[the streaming guide](streaming.md#multi-lens-offline-selection-and-h9c-validation).
Those RTSP checks preserve source cadence but do not prove absolute lip-sync
when camera clock-origin metadata is inconsistent and sender reports are absent.

