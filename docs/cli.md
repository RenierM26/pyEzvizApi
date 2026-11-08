# Command-line guide

[Documentation index](README.md) · [Getting started](getting-started.md)

Global options go **before** the command: `pyezvizapi --json devices status`,
not `pyezvizapi devices status --json`. Subcommand options go after their
command, such as `camera --serial CAMERA_SERIAL status`.

Use `pyezvizapi --help`, `pyezvizapi camera --help`, and
`pyezvizapi stream local-sdk-dump --help` for the installed version's full flags.
`python -m pyezvizapi` is an equivalent entry point.

## Command families

| Command | Purpose |
| --- | --- |
| `devices`, `device_infos`, `pagelist` | Account inventory and status; raw output can contain private data |
| `camera`, `light`, `devices_light`, `home_defence_mode` | Device status and controls; support depends on model/account |
| `unifiedmsg` | Unified alarm/message listing |
| `cloud_videos`, `sdcard_videos` | Recording descriptors, not a universal playable URL |
| `cloud_video_download`, `cloud_video_decrypt` | Cloud replay download and offline decryption |
| `save clip`, `save image` | [Finite clips and images](media-saving.md) |
| `stream` | [Specialist stream transport/debug commands](stream-cli.md) |
| `mqtt` | [Channel-99 push and token migration](channel99.md) |
| `lan rtsp` | Read/enable/disable the LAN RTSP service; no account login |
| `pyezvizapi-capabilities` | Explicit offline capability inventory; see [media paths](media.md) |

The sections below use synthetic serials/paths. Control examples perform real
operations if run with your own credentials; they are not validation commands.
Default output is human-readable where supported; `--json` requests structured
output, but command results and error handling remain command-specific.

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

