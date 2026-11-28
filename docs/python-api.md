# Python client usage

[Documentation index](README.md) · [Getting started](getting-started.md)

`EzvizClient` signs in to the EZVIZ consumer cloud using an EZVIZ account
or a saved SDK token. It is not a client for the EZVIZ Open Platform
app-key/access-token API. These examples track `main`; use the matching
[release tag](https://github.com/RenierM26/pyEzvizApi/releases) for an installed version.

- [Sign in and read camera status](#authenticate-and-read-status)
- [Save and restore credentials](#reuse-and-persist-the-complete-token)
- [Choose an inventory or history API](#devicestatus-apis)
- [Handle failures and manage the client lifetime](#errors-and-client-lifetime)
- [Find device controls, push, and media APIs](#controls-push-and-media)

## Authenticate and read status

This interactive example contacts EZVIZ. It polls once without fetching camera
alarm history, then selects only camera states from that snapshot. An unknown
`online` value (`None`) is not the same as offline.

```python
from getpass import getpass

from pyezvizapi.client import EzvizClient
from pyezvizapi.devices.snapshot import DevicePollOptions
from pyezvizapi.exceptions import EzvizAuthVerificationCode

client = EzvizClient(account=input("EZVIZ account: "), password=getpass())
try:
    try:
        client.login()
    except EzvizAuthVerificationCode as challenge:
        if challenge.reason != "verification_required" or not challenge.code_sent:
            raise  # Use the relevant recovery flow rather than retrying blindly.
        client.login(sms_code=getpass("MFA code: ").strip())

    snapshot = client.poll_devices(DevicePollOptions(include_camera_alarms=False))
    for serial, camera in snapshot.select("camera").items():
        health = snapshot.health[serial]
        if health.present and health.current:
            print("Camera online:", camera.online)
finally:
    client.close_session()
```

- The initial MFA channel defaults to email. `sms_code` is the submission
  argument for the selected delivery method, including email. Keep it as text
  so leading zeros survive. `code_sent` means the server accepted a code
  request, not that the message arrived. See [login recovery](auth/login-recovery.md)
  for contact selection, `request_mfa=False`, explicit resend, and human CAPTCHA.
- For a fresh login, `url=` takes the regional **host name**, not a full URL;
  the default is `apiieu.ezvizlife.com`. Do not use it to reroute an existing
  token. Password login uses v6 by default; only select `login_api="v5"`
  when the account's region is independently known to require it.

## Reuse and persist the complete token

After the first successful login, save `client.export_token()` into a
private, application-owned store. For a standalone file, use
`save_private_token(str(path), client.export_token())` before closing the client.
The parent directory must already exist and be private. Do not put tokens in
source control, logs, or world-readable directories.

On subsequent runs, restore the **whole** token and install a synchronous
callback to persist rotation. This example expects the file to exist and
assumes the same default installation identity on the same host:

```python
import json
from pathlib import Path

from pyezvizapi.client import EzvizClient
from pyezvizapi.cloud.token_store import save_private_token

path = Path("ezviz_token.json")  # Use a private, stable path in production.
saved_token = json.loads(path.read_text(encoding="utf-8"))

def persist(snapshot):
    save_private_token(str(path), snapshot)

client = EzvizClient(token=saved_token, on_token_updated=persist)
try:
    client.login()
    snapshot = client.poll_devices()
finally:
    client.close_session()
```

A saved session ID **and** refresh ID take the refresh path first. If refresh
raises `EzvizAuthTokenExpired`, a client with account credentials can attempt
password login; a token-only client needs caller-managed reauthentication.
For containers or hosts with changing MAC addresses, use a
[persisted installation identity](auth/persisted-client-identity.md) and pass the
same `feature_code=` on restore.

Treat the dictionary passed as `token=` as owned by that client. Use
`export_token()` for a detached snapshot, rather than mutating or sharing the
input or the return value of `login()`. The callback also receives a detached
snapshot. Do not share one mutable token across clients or let stale copies
overwrite rotated credentials. Push requires durable persistence **before**
the callback returns; see [channel-99 lifecycle](channel99.md#receiving-events).

## Device/status APIs

| Use case | API | Return shape and I/O |
| --- | --- | --- |
| Periodic polling for multiple device families | `poll_devices(options=None)` | One [typed snapshot](device_inventory.md) from a bounded acquisition, which may paginate and fetch alarms. |
| Reuse the last published snapshot | `device_snapshot`, then `select(kind)` or `as_dict(kind)` | Property is `None` before the first successful poll. Selectors do no I/O; `as_dict` returns detached compatibility data. |
| Keep an existing dictionary-based consumer working | `load_devices(refresh=True)` or `load_cameras`, `load_detectors`, `load_light_bulbs`, `load_smart_plugs` | Serial-keyed status dictionaries. Each family call fetches inventory; `refresh=False` skips camera alarm enrichment, **not** inventory fetch. Legacy maps can retain stale entries. |
| Inspect one device or the processed inventory | `get_device_infos(serial=None)` / `get_device_records(serial=None)` | A mapping keyed by serial when omitted; a single projected dictionary or `EzvizDeviceRecord` when found by serial, or `{}` when not found. A scoped lookup can fall back to account pagelist. |
| Inspect reported resources or validate raw device rows | `get_page_list()` / `get_device(strict=True)` | Merged [pagelist sections](pagelist-api.md) or just the device rows with strict row and final-page validation. |
| Query alarm/message history | `get_device_messages_list(...)` | One raw [UnifiedMsg page](unified-message-list.md), not live motion state, and not automatically paginated. |

Use one `poll_devices()` call per update cycle and select all needed families
from it instead of polling each family separately. A successful poll can still
retain stale device states; check `snapshot.health[serial]` for `present` and
`current`. A failed poll raises and leaves the previous snapshot in place.
Treat both cases explicitly when deciding what is available. For polls that
exclude alarms, alarm-derived fields such as camera motion are unknown.

## Errors and client lifetime

The SDK is synchronous. In async applications, run blocking SDK operations
in an executor, coordinate one poll at a time per client, and wait for
outstanding work before cleanup. Cancelling an async waiter does not stop the
worker. The constructor's HTTP timeout is not a deadline for all operations;
`DevicePollOptions.timeout` bounds a whole poll, including its inventory lock
and optional alarm/history reads. See [polling details](device_inventory.md#ownership-and-freshness).

| Failure | Handle it as |
| --- | --- |
| `EzvizAuthVerificationCode` or other `EzvizLoginError` | Inspect `reason` and follow [login recovery](auth/login-recovery.md#stable-error-categories). Catch the verification subtype first if you handle it separately. |
| `EzvizAuthTokenExpired` | Restore the matching installation identity if applicable, or reauthenticate; do not blindly reuse rejected credentials. |
| SDK `HTTPError`, other `PyEzvizError`, Requests transport errors, or `TimeoutError` | Keep HTTP, API payload rejection, transport, and bounded timeout failures distinct. Not every transport exception subclasses `PyEzvizError`. Inspect the endpoint-specific contract before retrying; a timed-out write may already have reached the device or service. |

`close_session()` closes and recreates local HTTP session state without
removing the stored credentials. `logout()` is a remote session operation,
not the normal cleanup for a reusable token. If you own a push worker, stop
it before closing HTTP state; close any open media context separately.
Do not log raw tokens, device records, alarm payloads or signed URLs.

## Controls, push, and media

Start with the feature guide for the target device and channel. A device
serial, a resource ID, and a channel number are not interchangeable. Missing
reported state does not prove a feature is off or unsupported. A successful
write response is not proof of physical completion; use the documented
readback where available.

| Task | Guide |
| --- | --- |
| Move or zoom a camera, use saved viewpoints, manage patrol, or download a saved panorama | [Cloud PTZ](ptz-app-controls.md) |
| Identify a lens, route point movement, or choose a capture channel | [Camera channels](camera-channels.md), [point PTZ](ptz-point-control.md) |
| Change camera switches, AI detection, or image settings | [Switches](device-switches.md), [AI detection](ai-detection.md), [image controls](image-controls.md) |
| Read or set recording schedules, patrol, privacy masks, or audio | [Camera app controls](camera-app-controls.md) |
| Upload, list, or delete custom alarm recordings | [Custom alarm recordings](camera-app-controls.md#list-and-delete-custom-alarm-recordings) |
| Receive background events rather than poll history | [Channel-99 push](channel99.md), including migration, callback persistence, `raise_if_failed()`, and shutdown |
| Trigger or save a snapshot, or save a bounded clip | [Saving media](media-saving.md): `capture_picture` triggers capture and returns an API payload; `save_image`, `save_clip`, and `save_clip_with_options` write media to an output. |
| Select a streaming or recording route | [Media paths](media.md) and [streaming reference](streaming.md). `open_stream` returns a lazy packet-stream context, not a player URL or a decoded frame API. |

## Camera encryption keys

Use `client.get_cam_key(serial)` for one camera. For multiple cameras,
`client.get_device_list_encrypt_key(area_id, form_data)` is the low-level
helper for the Android app's batch request. Pass the account's area ID,
not a camera's location ID. The Android form contains:

- `deviceSerialList`: one comma-separated string with a trailing comma
  (for example, `CAM1,CAM2,`), not repeated `serial` fields.
- `checkcode` and `msgType`: the verification code and message type for
  the EZVIZ verification flow. The helper does not request a code.

The helper returns the raw response, including `responseDetail` when present.
The app reads that field as a map keyed by camera serial. Handle missing entries
individually rather than assuming every requested camera returned a key. Never
log verification codes or the response. The batch format was traced in Android
and tested offline; it has not been verified against the live service.

## Imports and media

Use `pyezvizapi.client`, `pyezvizapi.devices.*`, `pyezvizapi.cloud.*`,
`pyezvizapi.push.*` and `pyezvizapi.streaming.*` canonical owners for new code.
Package-level lazy exports remain available. Only four narrow legacy shims are
retained for the pinned HA consumer; see [compatibility](ha-compatibility.md).
See [media dependencies](media.md#install-only-the-selected-dependencies)
before installing optional extras or system tools.
