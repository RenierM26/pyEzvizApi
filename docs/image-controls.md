# Camera image controls

Check the model, firmware, ownership and selected resource before writing.
A Pagelist field or capability is evidence for discovery, not proof that a
particular write works. Legacy channel numbers, IoT resource identifiers and
local indices, and native LAN channels are separate routing inputs.

| Control | SDK route | Limits |
| --- | --- | --- |
| Color and saturation presets | `get_display_mode`, `set_display_mode`, devconfig `display_mode` | Android's graphics presenters and the SDK send an object with `mode` on channel 1. The direct getter returns 1–3 or `None` when the response doesn't contain a recognized preset. This is not a saturation slider. |
| Individual brightness, contrast, saturation and sharpness | Native LAN `set_camera_video_effect(effect, level)` | Sets one level (0–100) on the default camera configuration and verifies it by reading back. See the [LAN SDK notes](cli.md#lan-wdr). No equivalent cloud setter was established in this audit. |
| Backlight region compensation | `get_backlight_compensation`, `set_backlight_compensation` | Android's advanced graphics presenter uses channel 1. It preserves the reported `mode`; disabling also preserves `position`. Not image rotation. |
| Color, black-and-white and smart night vision | `set_night_vision_settings`, devconfig `NightVision_Model` | Sends `graphicType`, `luminance`, and `duration` on channel 1. The legacy `set_night_vision_mode` still sends only the first two. |
| Day/night filter and sensitivity | `devices.settings.reported_cloud_day_night_settings`, `set_cloud_day_night_settings`; native LAN `set_camera_day_night_mode` | Legacy cloud ICR, IoT black-and-white mode, and native LAN are separate contracts. |
| Enhanced infrared and forced day/night | `devices.settings.get_black_and_white_mode`, `set_black_and_white_mode` | Only on the app branch advertising `FillLight.BlackAndWhiteCfg`. |
| Anti-banding, low-light enhancement, adaptive night vision | `devices.settings.get_image_switch`, `set_image_switch` | Boolean properties on the app's `Video/1` route. Require the exact product-profile property. |
| Wide dynamic range | `devices.settings.get_iot_wdr_settings`, `set_iot_wdr_enabled`, `set_iot_wdr_level`; native LAN `set_camera_wdr` | The IoT setter reads the current property on the same local index. The binary LAN setting and cloud switch are not equivalent to the IoT level control. |
| Orientation | `device_mirror`, `flip_image`, `set_image_flip_iot` | Legacy mirror/toggle and IoT enabled-state routes differ. Do not retry a toggle merely because readback is unavailable. |
| On-screen overlay | `set_camera_osd` | Overlay controls are separate from color presets and rotation. |
| Lens defog | `set_lens_defog_mode` | IoT `Video/LensCleaning.DefogCfg`; match the reported local index and check mode support. |

## Legacy cloud request shapes

These examples describe the Android 7.4.1 request paths, cross-checked in
the newer retained build. They are not a compatibility guarantee for every
device. The writes use `PUT /v3/devconfig/v1/keyValue/{deviceSerial}/{channelNo}/op`,
but Android uses different parameter locations for the two controls.

### Backlight compensation

The advanced graphics presenter reads `inverse_mode` on channel 1
(`get_dev_config(serial, 1, "inverse_mode")` in the SDK) and writes it using
form fields `key` and `value`. The SDK's `set_dev_config_kv` sends a mapping
as JSON in the `value` field.

The object has integer fields `mode`, `enable`, and `position`. Android
preserves the reported mode (automatic = 0, manual = 1) and sets
`enable` to 0 or 1. When disabling it also preserves the reported position.
The manual region choices are 1 = up, 2 = down, 3 = left, 4 = right, 5 = center.
The app prompts for a region rather than writing an enabled manual mode with
no selection. The SDK getter returns `mode`, `enabled`, and `position`, or
`None` for an unrecognized response. Call `set_backlight_compensation(serial,
enabled, position=...)` to update the switch; it reads the current settings
first and refuses to write if the response is unusable. Supply a position only
when enabling manual compensation. With no position supplied the setter keeps
the reported one.

### Night vision

The Android night-vision and graphics screens send `NightVision_Model` with
`graphicType`, `luminance`, and `duration` together on channel 1, using
query parameters `key` and `value`. When changing luminance alone, the UI
passes the current mode and duration. The SDK's `set_device_key_value`
matches that transport and takes a JSON string as `value`.
`set_night_vision_settings(serial, mode, luminance, duration)` builds this
complete request without guessing missing values. To read reported values,
pass the camera snapshot to `devices.features.reported_night_vision_settings`.
It returns `mode`, `luminance`, and `duration`, with `None` for unknown fields.

The existing `set_night_vision_mode` helper instead uses the form variant
and sends only mode and luminance. Whether omitting duration preserves or
resets it is not established. The `devices.features.night_vision_payload`
helper is consumer policy, not a wire specification: it normalizes values by
mode. Do not assume its defaults are the current settings on a camera.

### Day/night filter (legacy ICR)

The Android React Native graphics screen reads `STATUS.optionals.device_ICR_DSS`.
The mode picker sends both `mode` (0 automatic, 1 daytime, 2 nighttime) and
`sensitivity` (1 low, 2 medium, 3 high) through the query-based devconfig PUT
on the screen's legacy channel, even when only one value changes.
`reported_cloud_day_night_settings` reads the snapshot without inventing
defaults. `set_cloud_day_night_settings` requires both values and defaults to
legacy channel 1. Use this helper only for the legacy branches and values
above. The app's separate enhanced-infrared branch can also pass mode 3 to
its sensitivity screen; the legacy SDK helper deliberately does not cover
that combination.

## IoT graphics properties

The Android 7.4.1.0421 `RevisionSetting` bundle (5.0.0.22639082) verifies these
routes in `graphicSettingViewModel.js`, `graphicSettingNightVM.js`, and the
graphics view's callbacks. The app checks the product profile for each
`Video/1` function point before exposing it. The SDK does not infer support
from Pagelist data or fall back to a different route on rejection.

| `ImageSwitch` choice | Domain/property |
| --- | --- |
| `ANTI_BANDING` | `ImageExposure/AntiBandingParams` |
| `LOW_LIGHT_ENHANCEMENT` | `ImageEnhance/LowLightImageEnhanceCfg` |
| `ADAPTIVE_NIGHT_VISION` | `FillLight/NightVisionAdaptMode` |

The app's GET reads `data.enabled`. The SDK returns `True`, `False`, or
`None` for an absent or unrecognized value; an API failure still raises.
The PUT sends `{"value":{"enabled":true}}` (or `false`) to the same route.
Anti-banding is an on/off control here, not a 50/60 Hz selector. The separate
low-light switch is not legacy `NightVision_Model.graphicType=5`.

`FillLight/BlackAndWhiteCfg` is another `Video/1` property. On the matching
black-and-white picker branch, the app reads `data.mode` and sends
`{"value":{"mode":N}}`: 0 infrared, 1 forced daytime, 2 forced nighttime,
3 enhanced infrared. The IoT SDK getter reports only those recognized modes.
It is not a synonym for legacy ICR or the LAN day/night control.

`get_iot_wdr_settings` reads the same property as the two WDR setters,
`Video/{local_index}/ImageBacklight/WDR`, and reports `enabled` and
`level` without defaults. Neither the getter nor the setters substitute
the cloud switch, LAN setting, or another index if that read fails.

`get_night_fill_light_mode` and `set_night_fill_light_mode` cover the
separate super-night fill-light picker. The app requires super-night mode,
the `Video/1/SupplementLightMgr/ImageSupplementLightModeSwitchParams`
profile property, and the matching support token in `814`:

| Token | Picker choice | `enabled` | `supplementLightSwitchMode` |
| --- | --- | --- | --- |
| `1` | `OFF` | false | `irLight` |
| `2` | `INFRARED` | true | `irLight` |
| `4` | `SMART` | true | `eventIntelligence` |

The old binary `set_intelligent_fill_light` can send off or smart but not
infrared; it is unchanged. The new setter does not switch the camera to
super-night mode.

## Other gaps and evidence

- **Wide angle:** The Android player reads `ImageAdjustment.WideAngleMode`
  on the selected resource and local index. It treats `value.type == 1`
  as active and uses it to adjust playback zoom behavior. That read path
  does not establish how to persist a camera setting.
- **Multi-camera color balance:** The fixture reports
  `Video.ImageAdjust.MultiCameraColorBalanceSwitch.enabled`, but the traced
  graphics paths did not establish an app writer or its resource scope.
- **Cloud image adjustments:** `image_para`, `Auto_night_vision`, and the
  generic `ICR` field appear in inventory, but this audit did not establish
  cloud setters for those fields or for the independent LAN video effects.
  Cloud display presets are not independent sliders.

See the [Pagelist field map](pagelist-state.md) for device capability gates
and the [LAN WDR command](cli.md#lan-wdr) for the separate native backlight
contract. For hardware validation, record the original value, read back on
the same route after any authorized test write, and restore the original.
