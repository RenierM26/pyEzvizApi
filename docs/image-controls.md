# Camera image controls

Check the model, firmware, ownership and selected resource before writing.
A Pagelist field or capability is evidence for discovery, not proof that a
particular write works. Legacy channel numbers, IoT resource identifiers and
local indices, and native LAN channels are separate routing inputs.

| Control | SDK route | Limits |
| --- | --- | --- |
| Color and saturation presets | `set_display_mode`, devconfig `display_mode` | Android's graphics presenters and the SDK send an object with `mode` on channel 1. This is a preset, not a saturation slider. |
| Backlight region compensation | `set_dev_config_kv`, key `inverse_mode` | Android's advanced graphics presenter uses channel 1. It preserves the reported `mode`; disabling also preserves `position`. Not image rotation. No named SDK setter. |
| Color, black-and-white and smart night vision | `set_night_vision_mode`, devconfig `NightVision_Model` | The helper sends `graphicType` and `luminance` on channel 1. Unlike the traced Android request, the helper omits duration. See the query-based alternative below. |
| Day/night filter and sensitivity | Cloud `device_ICR_DSS` via `set_dev_config_kv`; native LAN `set_camera_day_night_mode` | These are different contracts. Don't map cloud values to native values without checking the model. |
| Wide dynamic range | `devices.settings.set_iot_wdr_enabled`, `set_iot_wdr_level`; native LAN `set_camera_wdr` | The IoT setter reads the current property on the same local index. The binary LAN setting and cloud switch are not equivalent to the IoT level control. |
| Orientation | `device_mirror`, `flip_image`, `set_image_flip_iot` | Legacy mirror/toggle and IoT enabled-state routes differ. Do not retry a toggle merely because readback is unavailable. |
| On-screen overlay | `set_camera_osd` | Overlay controls are separate from color presets and rotation. |
| Lens defog | `set_lens_defog_mode` | IoT `Video/LensCleaning.DefogCfg`; match the reported local index and check mode support. |

## Legacy cloud request shapes

These examples describe the Android 7.4.1 request paths, cross-checked in
the newer retained build. They are not a compatibility guarantee for every
device. Both writes use `PUT /v3/devconfig/v1/keyValue/{deviceSerial}/{channelNo}/op`,
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
no selection. There is no dedicated SDK writer; use the generic form helper
only with known values for the device.

### Night vision

The Android night-vision and graphics screens send `NightVision_Model` with
`graphicType`, `luminance`, and `duration` together on channel 1, using
query parameters `key` and `value`. When changing luminance alone, the UI
passes the current mode and duration. The SDK's `set_device_key_value`
matches that transport and takes a JSON string as `value`.

The existing `set_night_vision_mode` helper instead uses the form variant
and sends only mode and luminance. Whether omitting duration preserves or
resets it is not established. The `devices.features.night_vision_payload`
helper is consumer policy, not a wire specification: it normalizes values by
mode. Do not assume its defaults are the current settings on a camera.

## Other gaps and evidence

- **Wide angle:** The Android player reads `ImageAdjustment.WideAngleMode`
  on the selected resource and local index. It treats `value.type == 1`
  as active and uses it to adjust playback zoom behavior. That read path
  does not establish how to persist a camera setting.
- **Anti-banding, low-light enhancement, and multi-camera color balance:**
  The Pagelist fixture advertises `AntiBandingParams`,
  `LowLightImageEnhanceCfg`, and `MultiCameraColorBalanceSwitch`, but this
  trace did not confirm the writer, valid values, or accepted resource scope.
- **Individual image sliders:** `image_para`, `Auto_night_vision`, and the
  generic `ICR` field appear in inventory. This audit did not establish
  setters for those fields or for independent brightness, contrast,
  saturation, or sharpness. Display presets are not evidence of slider support.

See the [Pagelist field map](pagelist-state.md) for device capability gates
and the [LAN WDR command](cli.md#lan-wdr) for the separate native backlight
contract. For hardware validation, record the original value, read back on
the same route after any authorized test write, and restore the original.
