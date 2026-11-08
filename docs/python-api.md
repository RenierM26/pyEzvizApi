# Python client usage

[Documentation index](README.md) · [Getting started](getting-started.md)

The cloud client is synchronous. In async applications, run login, polling,
controls and cleanup in the application's executor; do not call them directly
on an event loop. Home Assistant owns its own executor and storage lifecycle.

## Authenticate and read status

This example is interactive and contacts EZVIZ. Credentials are read rather than
embedded in source; the returned status and token can contain private data.

```python
from getpass import getpass

from pyezvizapi.client import EzvizClient
from pyezvizapi.exceptions import EzvizAuthVerificationCode

client = EzvizClient(account=input("EZVIZ account: "), password=getpass())
try:
    try:
        client.login()
    except EzvizAuthVerificationCode:
        client.login(sms_code=int(input("MFA code: ")))
    cameras = client.load_cameras()
    # Consume cameras without logging private identifiers or URLs.
finally:
    client.close_session()
```

`close_session()` closes/recreates HTTP session state; it is not a push-worker
shutdown method or account logout. Stop an owned push client separately before
closing HTTP state. Device operations may fetch fresh data; they are not pure
accessors simply because they return a dictionary.

## Reuse and persist the complete token

```python
import json
from pathlib import Path

from pyezvizapi.client import EzvizClient
from pyezvizapi.cloud.token_store import save_private_token

path = Path("ezviz_token.json")  # Choose a private application-owned path.
saved_token = json.loads(path.read_text())

def persist(snapshot):
    save_private_token(str(path), snapshot)

client = EzvizClient(token=saved_token, on_token_updated=persist)
try:
    client.login()
    persist(client.export_token())
    cameras = client.load_cameras()
finally:
    client.close_session()
```

The file must already exist in this reuse example. `export_token()` returns a
separate deep snapshot; persist all fields, not only session/refresh strings.
The CLI storage helper is suitable for standalone files; HA integrations must
implement storage appropriate to HA. In channel-99 use, the callback runs on a
worker and must not return before durable storage completes. Do not introduce
an event-loop/worker deadlock. See [channel-99](channel99.md) for migration,
first-device recovery and shutdown semantics.

## Device/status APIs

| Method | Result/use |
| --- | --- |
| `load_cameras(refresh=True)` | Camera-like status mappings keyed by serial |
| `load_light_bulbs(refresh=True)` | Lighting status mappings |
| `load_smart_plugs(refresh=True)` | Smart-plug status mappings |
| `load_devices(refresh=True)` | Combined supported device mappings |
| `get_device_infos(serial=None)` | Raw normalized sections for exploration |
| `get_device_records(serial=None)` | Typed device records |
| `export_token()` | Deep snapshot for secure persistence |

Raw fields can change upstream. See the [HA contract](home-assistant-contract.md)
for status keys, device routing and exception categories. Controls such as
`set_camera_defence(serial, enable)` can affect real devices; an accepted API
response does not establish physical completion.

## Imports and media

Use `pyezvizapi.client`, `pyezvizapi.devices.*`, `pyezvizapi.cloud.*`,
`pyezvizapi.push.*` and `pyezvizapi.streaming.*` canonical owners for new code.
Package-level lazy exports remain available. Only four narrow legacy shims are
retained for the pinned HA consumer; see [compatibility](ha-compatibility.md).

For `save_clip`, `save_clip_with_options`, `save_image` and source-specific
requirements, see [media saving](media-saving.md) and the [streaming reference](streaming.md).
