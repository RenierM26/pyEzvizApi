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
| Resource-scoped panorama | `start_panorama_capture` and `get_panorama_info` in `pyezvizapi.devices.ptz` |
| Patrol schedule, homing preset, calibration | [Camera app controls](camera-app-controls.md) |
| Human/subject tracking and linked-lens behavior | [AI detection and tracking](ai-detection.md) |

## Direction and zoom

The direct cloud form includes `channelNo`, `command`, `action`, `speed`, `uuid`,
and the current Unix time in milliseconds. Channel 1 remains the default for
existing callers. Use the device's reported playback channel, not a guessed
resource name. Android maps the cardinal and supported diagonal commands
(`UPLEFT`, `UPRIGHT`, `DOWNLEFT`, `DOWNRIGHT`) and optical zoom
(`ZOOMIN`, `ZOOMOUT`) to the same transport. Neither a PTZ flag nor a
successful HTTP response proves the lens supports a given command.

This low-level method sends **one** request: pair `START` with `STOP` for
continuous controls. `EzvizCamera.move()` retains its existing immediate
start/stop behavior. Local HCNetSDK controls are separate.

## Saved viewpoints and patrol points are different

- The saved-viewpoint list returns Android's raw `data` rows. Use the row's
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

The resource-scoped, non-relay app route takes an explicit
[`CameraChannel`](camera-channels.md). Starting a capture does not wait for
completion. `get_panorama_info` reads the raw `data` object (including
`percent` and `picInfoList` when present) without downloading, decrypting,
uploading or stitching media. The legacy `create_panoramic` and
`return_panoramic` client methods are unchanged; the SDK does not silently
switch between panorama variants.

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
prepared HTTP requests. No live camera movement or setting changes were
performed. App-specific timed/group PTZ, relay panorama processing and the
bulk patrol-point reset are not covered by the new helpers.
