# AI detection and tracking settings

EZVIZ uses several independent settings families. A control labeled “Human
Detection” in the app is not necessarily the same setting as People switch
200 or the `app_human_detect` intelligent app. Available controls depend on
model, firmware, video resource, operating mode and sometimes service plan.

## SDK coverage

| Setting | Where to look | SDK support and limits |
| --- | --- | --- |
| Motion defence / arming | `STATUS.globalStatus` and defence capability | `set_camera_defence`; arming does not choose a detection algorithm. |
| Legacy PIR, human shape or image change mode | `STATUS.optionals.Alarm_DetectHumanCar` | `set_alarm_detect_human_car`; `AlarmDetectHumanCar` describes values 5, 1 and 3 respectively. |
| Advanced detection mode | `STATUS.optionals.Alarm_AdvancedDetect` | `set_alarm_advanced_detect`; do not reuse the legacy mode values without checking the device. |
| Sensitivity and subtype/channel-specific algorithm values | `STATUS.optionals.AlgorithmInfo` and model-specific reads | `get_motion_detect_sensitivity`, `get_motion_detect_sensitivity_dp1s`, `set_detection_sensitivity`, and `set_algorithm_param` cover different request shapes. |
| Dedicated People switch | `SWITCH`, type 200 | `set_people_detection(..., channel_no=...)`; distinct from intelligent-app installation and human/loitering parameters. |
| Intelligent-app installation/removal | `FEATURE_INFO` → `IntelligentAPP.DownloadedAPP` | `set_intelligent_app_state` / `manage_intelligent_app`; pass the exact supported app name and resource ID, especially on multi-channel devices. |
| Intelligent-app property and detection area | App-specific property path and encoded value | `devices.tracking.set_intelligent_app_config` sends the action, but does not infer a property path or encode a region. |
| Per-app auto tracking | `/PTZTrace/AutoTraceSwitch/prop` on a supported enabled app | `devices.tracking.set_app_auto_tracking`; pass the actual resource route when not Video/1. It does not change the camera-wide tracking switch, zoom, or linked tracking. |

The SDK recognizes the names `app_human_detect`, `app_car_detect`,
`app_video_change`, and `app_wave_recognize` (human shape, vehicle, image
change, and gesture). Those names are not an exhaustive device capability
list. To discover the app ID for a property update, inspect the original
`APPID` on the chosen resource; `iter_intelligent_apps` returns base names
and is not a source for a versioned property-write ID.

## Per-app actions and evidence

Android's `AlarmDetectAreaSettingPresenter.saveAlarmAreaWithAppId` resolves
the selected channel to a resource identifier and local index, then sends
`IntelligentAPP.ModifyAppFunctionCfgs` with a `configLists` entry containing
`appId`, `path`, and a string `payload`. The area editor encodes the region
before sending it. Keep that encoded string as-is; do not substitute generic
polygon JSON or a boolean. The SDK helper follows that envelope; the tests
verify serialization offline, not camera acceptance.

For an enabled app that advertises tracking, call
`set_app_auto_tracking(client, serial, app_id, True,
resource_identifier=identifier, local_index=index)`. Both route values are
strings. For another app property, use `set_intelligent_app_config` only
when the exact property path and wire value are known for the selected
resource. The legacy install/remove route uses an opaque `resourceId`
instead; these identifiers are not interchangeable.

## Settings without a verified writer

The Pagelist fixture and schemas include `HumanDetectionSwitch`,
`LongStayTime`, `HumanDetectionParam`, `VehicleTraceSwitch`,
`BodyDetectTimeInterval`, `ROI`, and `sound_detect_type`. Their presence
does not establish a write route or allowed values. The Android area action
does not establish a universal region encoder. Dedicated pet, package, face,
or sound-classification setters are not mapped by this audit. A message
filter only selects events already reported by EZVIZ; it cannot enable any
of those features. See the [Pagelist field map](pagelist-state.md) and
[Unified message list filters](unified-message-list.md).
