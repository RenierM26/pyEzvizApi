# Camera controls traced from the EZVIZ app

Use `pyezvizapi.devices.app_controls` with an authenticated `EzvizClient`.
Check the device's product profile or the matching owner-account app control
before issuing requests. The SDK does not probe other resources or fall back
to another lens when a request fails.

## Coverage at a glance

| Control | SDK coverage | Evidence |
| --- | --- | --- |
| Smart Compression and model-specific IoT properties and switches below | Read/write | Android trace and offline HTTP tests |
| Sleep and patrol schedules, patrol paths | Read/replace | Android trace and offline HTTP tests; controls seen in the H9c app |
| PTZ calibration | Action only | Android trace and offline HTTP tests; control seen in the H9c app |
| Privacy mask and PIR grid | Read/replace | Android trace and offline HTTP tests |
| Legacy motion area | Read only | Android trace and offline HTTP test; no verified write contract |
| Recording schedules and storage allocation | Read only | Existing SDK readers; no verified write contract for these properties |
| Custom alarm sound | Select an existing voice; read selection from refreshed inventory | Android trace and offline tests |
| Cloud SD formatting | Erase action and progress reader | Android trace and offline HTTP tests |

Seeing a control in the app is not proof that the SDK command works on
hardware. The commands added here have not been live-write verified.

## Read settings on the exact camera resource

After [signing in](python-api.md#authenticate-and-read-status), use the
camera's current inventory to resolve the resource key. Select the key for
your intended lens from the reported list; don't infer it from RTSP or from
the order of the lenses in the app.

```python
from pyezvizapi.devices.app_controls import get_patrol_path
from pyezvizapi.devices.channels import camera_channels, resolve_camera_channel

# client is an authenticated EzvizClient; serial identifies your camera.
camera = client.get_device_infos(serial)
resource_keys = [channel.key for channel in camera_channels(camera)]
resource_key = input(f"Select a reported PTZ resource {resource_keys}: ").strip()
channel = resolve_camera_channel(camera, resource_key)

# Only call this if the chosen resource supports patrol.
path = get_patrol_path(client, serial, channel=channel)
```

An unavailable key raises rather than selecting a different lens. The
patrol reader uses an HTTP PUT because the app models it as a read action;
it does not edit the path or move the camera.

**Before writing:** Read and retain the current configuration before
replacing a schedule, patrol sequence, mask, or PIR grid. Calibration can
physically move the camera. SD formatting erases recordings and is not
part of a routine validation run.

## Recording and maintenance

- **Smart Compression:** `get_smart_recording_compression` reads
  `Video/1/RecordStorage/RecordCompressionParams`; the setter writes
  `{"value":{"enabled":true}}` (or false). A missing or non-boolean flag is
  unknown. This setting doesn't change the recording mode or pre-roll.
- **Cloud SD formatting:** `format_cloud_sd_card(..., disk=1, confirm=True)`
  erases the selected disk. Confirm the disk number from storage status first.
  It sends one format request; don't repeat it automatically after a timeout.
  Use `get_cloud_sd_format_progress` to read the device-level progress object.
  These are separate from the local HCNetSDK format commands.
- **PTZ calibration:** `calibrate_ptz` can move the camera. It sends system
  operation 4 with zero delay, not a reboot. Not all models expose the action.

## Schedules and patrol

- `get_camera_plan` and `set_camera_plan` use the Android base timer editor,
  `/v3/devconfig/v2/base/plan`, on channel 0. `CameraPlan.SLEEP` is type 4
  and `CameraPlan.PATROL` is type 14. GET returns the device's
  `timingPlanVos`; PUT replaces the schedule using up to four **wire-format**
  slots in `timingPlanQos`, with the next-day flag enabled. Pass slots in the
  device format, not localized weekdays or raw UI indices; the two app editors
  don't map weekdays the same way. Read the current plan before editing it.
  This is not the SDK's older `/v3/devconfig/v2/plan` route.
- `get_patrol_path` reads path 1 with the `PTZPreset.GetPTZPatrolPath` action.
  `set_patrol_path` modifies that existing path with
  `PTZPreset.ModifyPTZPatrolPath`. Pass the exact `CameraChannel` and the
  device's existing point objects in the desired order. This does not
  create or delete patrol paths or capture new points. Patrol time and
  the patrol path are separate settings.

## Privacy, detection and sound

- `get_privacy_mask` reads the legacy `pri_cover_area` devconfig object.
  `set_privacy_mask` replaces the mask with up to four rectangles, specified
  as `(left, top, right, bottom)` on the app's integer 0–1000 grid. An empty
  sequence clears the mask. This is not camera sleep or an AI detection fence.
- `get_pir_detection_grid` and `set_pir_detection_grid` use the PIR
  **sub-device serial** and explicit channel. The setter checks the current
  grid's dimensions before writing. Cells are integer 0 or 1.
- `get_legacy_motion_area` reads the channel's legacy motion area. There is
  no universal detection-area setter; PIR, plate, and legacy motion areas
  are different contracts.
- `set_custom_alarm_sound` selects an existing voice ID from
  `get_voice_info`. It uses sound type 3 and does not change the older
  `alarm_sound` API. `reported_custom_alarm_sound` reads the selected ID from
  the refreshed Pagelist STATUS; it returns `None` outside custom mode or
  when no valid ID is reported.

## Model-specific IoT property access

Use `get_app_property(client, serial, CameraAppProperty.X)` to read the
app's configuration object, and `set_app_property` to send the configuration
object for that model. The setter wraps it in `{"value": ...}`. Pass the
property configuration, not the HTTP response or an already-wrapped value.
The routes below are fixed to those traced in the app; do not assume they
apply to a second lens. This API does not guess picker values or validate
model-specific schemas.

| Property | App route | Configuration note |
| --- | --- | --- |
| `HOMING_PRESET` | `Video/1/PTZMaintenance/HomingPresetCfg` | App sends boolean `enabled`. |
| `PLATE_REGION` | `Video/1/MotorVehiclesAnalysis/PlateRecognitionCfg` | App saves `plateRecognitionList` with normalized polygon coordinates, not a PIR matrix. |
| `MICROPHONE_AUTO_GAIN` | `Video/1/AudioMgr/MicAdaptive` | App sends boolean `gainEnabled`. |
| `PROMPT_TONE_VOLUME` | `global/0/SoundSetting/PromptToneVolume` | Separate from alarm and LAN audio-output volume. |
| `VOICE_STYLE` | `Video/1/SoundSetting/VoiceStyle` | App sends a model-supported `mode`. |
| `VEHICLE_TRACKING` | `Video/1/VehicleDetections/VehicleTraceSwitch` | App sends boolean `enabled`. |
| `WAKEUP_STRATEGY` | `Video/1/EnergySaving/WakeupStrategyCfg` | Model-specific battery wake-up configuration. |
| `ENERGY_MODE` | `Video/1/EnergySaving/EnergyModeCfg` | App sends `energyMode`; distinct from the legacy battery work mode. |
| `TIME_LAPSE` | `Video/1/BatCustomSpecial/TimeLapseMode` | Interval changes preserve the current `enable` value. |

## Additional model-gated switches

Use `get_camera_app_switch` and `set_camera_app_switch` with these
`CameraAppProperty` values. The read returns `None` for a missing or
non-boolean flag. Check the exact property in the product profile first.

| Property | App route | Write behavior |
| --- | --- | --- |
| `ELECTRONIC_STABILIZATION` | `Video/1/ImageEnhance/EIS` | Preserves reported EIS mode and level; refuses to write if the current flag is unknown. |
| `HORIZON_ENHANCEMENT` | `Video/1/ImageEnhance/HorizonEnhancement` | Preserves the reported level and other fields. |
| `RADAR_INTERFERENCE_SUPPRESSION` | `Video/1/SensorLight/RadarFMCfg` | Writes only `enabled`; the app exposes this in supported battery-doorbell wake-up settings. |
| `NIGHTTIME_PROMPT` | `global/0/SoundSetting/PromptParam` | Writes `enabled` with `mode: "nighttime"`; separate from the mute schedule. |

The request shapes were traced in Android 7.4.1.0421
(`RevisionSetting` 5.0.0.22639082, `RevisionFunctionSetting` 5.0.0.22396515,
`RevisionAlgorithmSetting` 5.0.0.22635469, and `ModulePIRSetting`
5.0.0.22203298). Patrol, Sleep Plan and calibration were also observed in
the H9c owner-account UI. Prepared HTTP requests are tested offline; no
live writes were performed. Recording schedule/allocation writers and the
deferred [image controls](image-controls.md) are not implemented here.
