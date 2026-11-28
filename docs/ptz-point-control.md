# Point-based PTZ control

`EzvizClient.ptz_control_coordinates(serial, x_axis, y_axis, *,
resource_identifier="Video_1", local_index="1", max_retries=0)` sends one
cloud IoT action. `EzvizCamera.move_coordinates(x, y)` uses those route defaults.

Coordinates are finite numbers in **0–1**, inclusive, in the app's image plane:
`(0, 0)` is top-left, `(1, 1)` bottom-right and `(0.5, 0.5)` the center.
They are not absolute pan/tilt angles, degrees or physical position feedback.
Repeated calls do not promise that the camera reaches an identical world angle.
Image orientation, model behavior, permission and point-PTZ support still matter.

For patrol paths, patrol schedules, homing presets, and calibration, see
[camera app controls](camera-app-controls.md). These are separate from point movement.

## Request contract

- PUT `/v3/iot-feature/action/<serial>/<resource>/<index>/PTZManualCtrl/CtrlPTZ3DPosition`
- `positionCtrlType: "point"`
- `zoomType: "zoomIn"`
- `positionPoint: {x: <x>, y: <y>}`
- `positionRect: {height: 1.0, width: 1.0, x: 0.0, y: 0.0}`

The rectangle and zoom field match the app's point model; this is not an exposed
rectangle-zoom API. No retries, timed directional movement or alternative-route
fallback are added. Vendor rejection raises an SDK error rather than success.
Boolean/non-numeric inputs are rejected before transport.

The app has two routes for this action: direct tapping uses `Video_1/1`; point
confirmation uses the selected player's resource identifier and local index.
Pass an explicitly known route for that selected resource. Do not manufacture a
resource name from a channel number or substitute the intercom relay namespace.

## Retained app verification

Static verification used retained Android **com.ezviz 7.4.1.0421, code 1676**, not
an assertion about the latest Android/iOS app. APK SHA256:
`90d1007934e7878f44b3e1f94b65ccd2d0a29f967b23882cd54c9e5e815fd663`.

| Source | Evidence |
| --- | --- |
| `CtrlPTZ3DPositionParam` constructor; matching classes22 smali | Point, zoomIn and full-unit rectangle; non-transient fields serialize through default Gson |
| `DevicePhysicalModelApi.putAction`, repository/remote forwarding and `RetrofitFactory` | PUT route and complete object as JSON body |
| `YsLiveOperationPresenter.d3` / direct-tap callback | Fixed `Video_1/1` route |
| `YsLiveOperationPresenter.v` / point confirmation | Selected resource/index and clamped 0–1 coordinates |
| classes19 `y6` motion handler | X/width, Y/height without inversion |
| `DeviceMapSupport` and `PlayDataInfo` | Exact support flag 586 for manual/direct control; 724 for point-locate UI, with further player-mode conditions |

Ordinary directional PTZ flags alone do not establish point-control support.
The missing `zoomType` in SDK 2.5.0 is a confirmed app-contract mismatch, **not**
a demonstrated cause of a physical camera failure. Offline request/response tests
establish payload construction and error handling, not mechanical positioning.
No app source, credentials, real device records or private media are published.
