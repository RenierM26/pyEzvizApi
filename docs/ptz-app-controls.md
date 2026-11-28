# Cloud PTZ and the EZVIZ Android app

These controls are model-, permission-, and channel-dependent. Camera movement,
preset recall, calibration and panorama capture can physically move the camera.
There is no automatic fallback to another lens or from cloud to LAN.

| Control | SDK surface |
| --- | --- |
| Directional movement and optical zoom commands | `EzvizClient.ptz_control(command, serial, action, speed=5, channel=1)` |
| Point at a position in the image | [Point PTZ](ptz-point-control.md) |
| Saved viewpoints | `list_ptz_presets`, `goto_ptz_preset`, `create_ptz_preset`, `rename_ptz_preset`, `delete_ptz_preset` in `pyezvizapi.devices.ptz` |
| Patrol sequence | `get_patrol_path`, `create_patrol_path`, `set_patrol_path`, `delete_patrol_path` in `pyezvizapi.devices.app_controls` |
| Save a patrol point | `pyezvizapi.devices.ptz.save_patrol_point` |
| Panorama capture and status | `resolve_panorama_capture_route`, `start_panorama_capture`, `get_panorama_info`, `start_device_panorama_capture`, and `get_stored_panorama` in `pyezvizapi.devices.ptz` |
| Download a finished device-wide panorama | `pyezvizapi.devices.ptz.download_saved_panorama` |
| Panorama movement and mark reset | `move_to_panorama_point` and `reset_panorama_mark` in `pyezvizapi.devices.ptz` |
| Patrol schedule, homing preset, calibration | [Camera app controls](camera-app-controls.md) |
| Human/subject tracking and linked-lens behavior | [AI detection and tracking](ai-detection.md) |

## Direction and zoom

The direct cloud form includes `channelNo`, `command`, `action`, `speed`, `uuid`,
and the current Unix time in milliseconds. The UUID is 32 hex characters
without hyphens. Channel 1 remains the default for
existing callers. Use the device's reported playback channel, not a guessed
resource name. Android maps the cardinal and supported diagonal commands
(`UPLEFT`, `UPRIGHT`, `DOWNLEFT`, `DOWNRIGHT`) and optical zoom
(`ZOOMIN`, `ZOOMOUT`) to the same transport. Neither a PTZ flag nor a
successful HTTP response proves the lens supports a given command.

This low-level method sends **one** request: pair `START` with `STOP` for
continuous controls. `EzvizCamera.move()` retains its existing immediate
start/stop behavior and accepts an optional `channel=` for both requests.
The cloud CLI accepts the same route via `camera move --channel`. Local
HCNetSDK controls are separate.

## Saved viewpoints and patrol points are different

- The saved-viewpoint list returns Android's raw `data` rows, or an empty
  list on a successful response with no rows. Use the row's
  `subSerial`, `channelNo` and `index` for recall, rename or deletion. Recall
  and deletion post `GOTO_PRESET` and `CLE_PRESET` respectively to
  `/api/device/preset/config`.
- Saved-viewpoint creation uploads a JPEG of the current view as multipart
  `Filedata`. Rename preserves the caller-supplied `picUrl`; both return the
  cloud's `Preset` object. The SDK does not acquire or decrypt the JPEG.
- `save_patrol_point` uses the app's device-level channel-0 route and a
  different multipart field, `filedata`. It returns the point ID used in a
  patrol sequence, e.g. `{"type": 1, "presetID": point_id}`. Do not substitute
  a saved-viewpoint index. The path and the patrol schedule are separate.
  Deleting the preset path is not the app's separate bulk point-reset action.

## Panorama capture

Call `resolve_panorama_capture_route(page_list, serial, channel=channel)`
with a fresh `client.get_page_list()` snapshot and a reported
[`CameraChannel`](camera-channels.md). The resolver is read-only and does not
send commands. Android uses these checks:

1. **Relay:** `deviceInfos.supportExt["913"] == 1` takes precedence. The
   app uses relay transfer and processing; the SDK does not implement that workflow.
2. **Resource:** Match `PRODUCTS_INFO` by the device's exact `deviceType` and
   firmware `version`. If its profile declares
   `Panorama.TriggerPanoramicCapture` for the selected `resourceIdentifier`
   and `localIndex`, call `start_panorama_capture(client, serial, channel=channel)`
   and poll `get_panorama_info` with the same route. It returns raw `data`
   (including `percent` and `picInfoList` when present).
3. **Device:** Without that definition, the app's fullscreen PTZ flag
   (`supportExt["81"] == 1`) advertises the older panorama UI. Call
   `start_device_panorama_capture(client, serial)` and poll
   `get_stored_panorama(client, serial)`. The device-wide request takes only
   the serial and does not select a lens; the read returns raw `picInfo`
   (including `progress` and `levelPicInfoList` when present).

A missing product profile is not proof that the action is absent. The SDK
resolver raises rather than guessing on missing routing metadata. For
combined playback, Android checks the selected resource's feature definition
first, then substitutes the combined view's PTZ channel number for the
resource request index. The resolver does not infer that combined-playback
mapping from ordinary inventory.

Capture acknowledgment is not completion. Check for image records as well
as 100% progress. The capture helpers do not download, decrypt, upload, or
stitch tiles. V3 requests require `meta.code=200`; a successful HTTP status
or a legacy success code cannot override a V3 error. The SDK does not switch
routes after an error. The legacy `create_panoramic` and `return_panoramic`
client methods are unchanged.

`move_to_panorama_point` takes normalized coordinates (0–1) on the panorama
image, not the live image. Pass a `CameraChannel` for the resource-scoped
`RotateFixpoint` action, or omit it to explicitly use the legacy device-wide
route. `reset_panorama_mark` sends Android's device-wide mark-type 3
operation; other mark types are not exposed.

## Download a finished panorama

Android downloads the temporary tiles, sorts them by index, stitches them
on-device, and uploads the result to `POST /v3/panoramicDevices/pics/upload`.
Find the finished image in a fresh pagelist at `STATUS[serial].levelPicUrl`,
not in the progress response. It can be available while progress is 100%
and the tile list is empty.

```python
from pathlib import Path

from pyezvizapi.devices.ptz import download_saved_panorama

jpeg = download_saved_panorama(client, serial)
if jpeg is not None:
    Path("panorama.jpg").write_bytes(jpeg)
```

The helper only reads and downloads: it will not move the camera, stitch
tiles, or upload an image. It returns `None` when there is no saved URL;
unsupported URLs and failed or non-JPEG downloads raise `PyEzvizError`.
The bounded HTTPS request sends no SDK credentials and follows no redirects.

## Evidence and limits

Compared against Android **7.4.1.0421 (1676)** and the `RevisionSetting`
bundle **5.0.0.22639082**. Relevant sources: `DeviceControlApi` and
`PtzController` for movement; `PresetFragment`, `DeviceDataRemoteEzviz` and
`RestfulUtils` for viewpoints; `RevisionSetting` cruise editor for points and
paths; `PanoramaViewHelperNew`, `PanoramicApiNew` and
`PanoramicRemoteEzvizNew` for panorama capture and metadata.

The handset's PTZ settings showed Human Tracking, Automatic Patrolling,
PTZ Position Calibration and PTZ Preset. That confirms visibility for the
observed setup, not support across all cameras. Request tests use offline
prepared HTTP requests. The only live camera operation reported here is the
panorama capture below. App-specific timed/group PTZ, relay panorama processing and the
bulk patrol-point reset are not covered by the new helpers.

Scope selection was traced through `PlayDataInfo.supportPanoramaModeNew`,
`PlayDataInfo.supportPtzPanorama`, `FeatureModel.haveFeatureDef` and
`PanoramaServiceImpl`. The retained and live H9c pagelist profiles have no
`TriggerPanoramicCapture` definition for either video resource and has the
device-wide PTZ flag. A read-only live inventory check resolved both lenses
to device scope. On the tested H9c, the resource capture was rejected
(code 2009); the device-wide request progressed from 0 to 100% and returned
12 image records. A later read returned 100% with no image records. On a
separate app-initiated capture, the handset uploaded the stitched panorama.
A fresh SDK inventory lookup returned its URL, and the downloaded 3936 × 300
JPEG decoded successfully.
