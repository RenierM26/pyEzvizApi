# Pagelist state, capabilities, and setters

`EzvizClient.get_page_list()` returns the merged pages from the authenticated
cloud inventory endpoint `GET /v3/userdevices/v1/resources/pagelist`.
It is a snapshot of reported metadata, state, and routing, not a complete
schema or a list of supported writes. Use `get_device_infos()` for the
per-serial projection or `get_device_records()` for typed records with a raw
mapping of that projection. The projection is not lossless: for example it
selects one resource ID for several legacy sections and omits some raw sections.

| Source | Meaning |
| --- | --- |
| `deviceInfos`, `resourceInfos` | Identity, device-level metadata, channel/resource routing, and capability declarations. |
| `SWITCH` | Numbered state rows, with scope where reported. The convenience boolean map loses row detail and can collapse multiple channels. |
| `STATUS`, `STATUS.optionals` | Runtime state and named settings. Optionals can be JSON-encoded; decode before testing for presence. |
| `FEATURE_INFO`, `FEATURE` | Named features and resource-specific data. Keep the resource and local index with the value; a helper selecting the first resource is not a per-lens selector. |
| `TIME_PLAN`, `NODISTURB`, `VIDEO_QUALITY` | Schedules, notification suppression, and reported video options. These are not numbered switches. |
| `CLOUD`, `VTM`, `P2P`, `CHANNEL`, `CONNECTION`, `WIFI`, `QOS`, `KMS` | Service, connection, stream, network, and key-management metadata. Presence does not advertise a matching setter. |
| `DETECTOR`, `CUSTOM_TAG`, `UPGRADE`, `PRODUCTS_INFO`, `SIM_CARD`, `MULTI_UPGRADE_EXT` | Peripheral, annotation, firmware, product, and cellular data. Use the raw response for sections not preserved by the per-device projection. |

**Gate controls independently of reading state.** Require a valid observed
value and route when a supported control depends on them. Apply the
feature-specific `deviceInfos.supportExt` predicate, then any model, channel,
ownership or sharing, online, and permission conditions established by the
app or integration. Normalize string/numeric values; some keys are modes or
lists, not booleans. Missing state is unknown, not off. Do not use a numeric
switch ID as a capability key. Re-read after a write when confirming device
state; a successful request or optimistic cache update is not read-back.

## Numbered switches

See the [switch matrix](device-switches.md#android-switch-ids) for all Android
IDs and the [additional SDK IDs](device-switches.md#additional-sdk-switch-ids).
Its setter column distinguishes an observed app or integration route from a
generic SDK method that merely accepts an ID. `switch_status` coerces its
input to boolean and delegates to `set_switch` (v3, with legacy fallback).
Do not use it for a nonbinary mode or to infer that an enum-only entry is writable.

## Named state with an identified writer

Paths below are relative to the per-device mapping unless noted. “HA” labels
companion integration policy, not a universal vendor rule. “Observed” is a
conservative presence check; where no capability predicate is verified, it
does not authorize a generic key/value write.

| State | Writer | Gate or qualification |
| --- | --- | --- |
| `STATUS.isEncrypt` | `set_video_enc` | HA: Encrypt `9`; honor account and device prerequisites. |
| `STATUS.globalStatus` | `set_camera_defence` for the defence action | HA pairs the control with Defence `1`. Global status is an aggregate, not proof of per-channel arming. |
| `STATUS.alarmSoundMode` | `alarm_sound` | HA: Talk `2`; this is a mode, not switch 1. |
| `deviceInfos.offlineNotify` | `set_offline_notification` | Device notification setting; distinct from channel switch 26. No universal numeric gate verified. |
| `NODISTURB.alarmEnable`, `callingEnable` | `do_not_disturb` / `set_answer_call` only where their notification contract matches | These raw fields describe suppression; the camera projection inverts them for push notifications. Verify the matching control, not the raw boolean alone. |
| `TIME_PLAN` | `set_time_plan_infos` | Match the plan type and resource; a returned plan is not a general scheduling capability. |
| `STATUS.optionals.AlgorithmInfo` | `set_algorithm_param`, or `set_detection_sensitivity` for its separate sensitivity contract | HA: `504` plus matching subtype/channel for PIR/human algorithm settings; `61` and matching subtype or model-specific condition for sensitivity. |
| `STATUS.optionals.Alarm_DetectHumanCar` | `set_alarm_detect_human_car`; deprecated `set_detection_mode` is an alias for this legacy writer only | HA uses capability `224`. The alias does not select the advanced route. |
| `STATUS.optionals.Alarm_AdvancedDetect` | `set_alarm_advanced_detect` (call explicitly for the advanced variant) | HA uses capability `534` with work-mode context. Do not assume the legacy and advanced mode values are interchangeable. |
| `STATUS.optionals.batteryCameraWorkMode` | `set_battery_camera_work_mode` | HA: `502` or `687`, with distinct mode families. |
| `STATUS.optionals.NightVision_Model` | `set_night_vision_mode`; channel-aware `set_dev_config_kv` path for luminance or duration | HA: `274` for smart night vision, `353` for duration, and `688` mode-token checks for variants. Preserve sibling fields when updating a complete config. |
| `STATUS.optionals.device_ICR_DSS` | HA uses `set_dev_config_kv` with the ICR object | HA requires the reported object and checks sensitivity presence for the sensitivity control. A separate native LAN day/night mode setter does not prove cloud-key parity. |
| `STATUS.optionals.display_mode`, `inverse_mode` | `set_display_mode` or the traced `set_device_config_by_key` variants | HA uses BackLight `303`; display style and backlight-region mode are separate. |
| `STATUS.optionals.IndicatorLight` | `set_device_key_value` (Android daylight-mode picker) | App: `331 = 1`, valid reported mode, switch 3 on. See the follow-up trace below. |
| `STATUS.optionals.OSD` | `set_camera_osd` | HA: OSD `153`. The native legacy OSD setter is a different route. |
| `STATUS.optionals.Alarm_Light.luminance` | `set_floodlight_brightness` | Match the supported floodlight model/route; lamp brightness, IR brightness, and warning lights are not interchangeable. |
| `STATUS.optionals.ChimeMusic` | Device helpers `set_alarm_volume`, `set_intercom_chime` | Alarm volume helper checks DeviceRing `185` and a valid reported value; intercom helper checks device category and reported field. |
| `STATUS.optionals.CustomVoice_Volume` | Device audio helpers `set_alarm_voice_volume`, `set_microphone_volume` | Alarm voice volume uses ChangeVolume `203 = 1`; mic gain requires a valid reported field (HA also gates on AudioOnoff `63`). They are not chime volume. |
| `FEATURE_INFO.…Video.SupplementLightMgr.ImageSupplementLightModeSwitchParams` | `set_intelligent_fill_light` | HA: `688` with the reported property. Not IR switch 10 or a verified port-8000 route. |
| `FEATURE_INFO.…Video.LensCleaning.DefogCfg` | `set_lens_defog_mode` | HA requires token `6` in capability `688` and a nonempty reported defog mode. See the route details below. |
| `FEATURE_INFO.…Video.VideoAdjustment.ImageFlip` | `set_image_flip_iot` | Android checks the feature definition and resource. Not equivalent to native mirror-mode numbers. |
| `FEATURE_INFO.…NetworkSecurityProtection.PortSecurity` | `set_port_security` | Gate on the specific reported client mode or port, not merely on the parent domain. |
| `FEATURE_INFO.…Video.LightCtrl.NightLightEnable` | Intercom helper `set_label_light` | Requires intercom category `BDoorBell`, a usable video resource/local index, and a reported boolean value (or a value that can be interpreted as boolean). If that route is unavailable, the helper accepts one usable observed switch `611` row as a legacy fallback; it does not retry via `611` after a rejected IoT write. |
| `FEATURE_INFO.…IntelligentAPP.DownloadedAPP` | `set_intelligent_app_state` | Match a reported app identity and its supported action; an installed-app list is not proof every app can be toggled. |
| `FEATURE_INFO.…Video.PTZMasterSlaveTrace.LinkedTrackingAdvancedCfg` | Companion `set_linked_tracking_takeover` via the SDK IoT route | HA: `715` and eligible routing. Not the generic tracking switch or native linked-lens calibration. |
| `deviceInfos.name`, firmware upgrade state | `update_device_name`, `upgrade_device` | Metadata and update actions, not toggles. The update action is not a way to set reported progress/version fields. |

## Maintenance actions and lens controls

Pagelist can report a capability or progress without providing a setting to
write back. Treat reboot, upgrade, and format as actions, not switches.

| Action | State and gate | SDK route and limits |
| --- | --- | --- |
| Reboot | Android's player exposes reboot support when `452 = 1`. The settings action blocks when sleep switch 21 is on and asks for confirmation. | `reboot_camera` uses the cloud device-operation route. Its defaults (`oper=1`, `delay=1`) match the traced settings action. Success means the request was accepted, not that the device has returned online. The firmware's advertised `SystemMaintenance.SystemReboot` action does not establish a LAN route or a per-lens reboot. |
| Lens defogging | `FEATURE_INFO` reports `LensCleaning.DefogCfg` on a video resource. HA requires `688` containing token `6` and a nonempty reported `defogMode`. | `set_lens_defog_mode` sends a cloud IoT feature update to resource `Video`, with a supplied local index. Auto sends `enabled=true, defogMode=auto`; on sends `true, open`; off sends `false, auto`. The helper used by HA uses the client's default index rather than deriving it from the record. Neither the response tuple nor the helper's cache update establishes fresh device read-back. No equivalent LAN setter was verified. |
| Firmware upgrade | `UPGRADE.isNeedUpgrade` reports availability; `STATUS.upgradeStatus` and `upgradeProcess` report progress. Capability `10` is named Upgrade; its presence alone is not an update offer or a verified app visibility rule. | `upgrade_device` initiates the cloud upgrade on the device-level `/0/upgrade` route. Use fresh firmware status to observe progression and completion. The account auto-upgrade preference (`get_autoupgrade_switch` / `set_autoupgrade_switch`) is separate. |
| Disk status and format | Pagelist reports `diskNum`, `diskState`, `diskStatus`, and optionals such as `diskCapacity` and `diskHealth`. Capability `4` is named Disk, not a sufficient format gate. | `get_storage_status` reads cloud storage status; `hd_config` reads native LAN disk configuration. Android's LAN module starts formatting with `NET_DVR_FormatDisk` and checks progress by handle. The SDK models start, progress, and close requests; these are not a high-level LAN format executor. The advertised IoT `HDD.FormatHDD` is a separate action, not a write to disk status. |

Trace sources: Android `PlayDataInfo.supportReboot`,
`DeviceSettingActivity.onClickRebootDeviceView` / `rebootDevice`, and
`EZRNLanDevModule` disk formatting; SDK [cloud controls](../pyezvizapi/cloud/operations/controls.py),
[firmware status](../pyezvizapi/devices/firmware.py),
[lens helpers](../pyezvizapi/devices/lens.py), and
[native configuration](../pyezvizapi/streaming/local/hcnetsdk/api.py).

## Evidence and gaps

The inventory below is bounded by the checked-in pagelist fixture and current
SDK readers. A field marked **unmapped** was observed but is not paired with
a verified setter and gate in this audit. This is not a claim that the SDK
lacks every possible route: generic key/value and IoT methods exist, and an
app action may live outside pagelist. Do not promote an unmapped row to a
control without tracing the actual write payload, scope, and capability check.

### SDK helpers for app settings

Import `pyezvizapi.devices.settings` to use these helpers with an existing
`EzvizClient`. They validate inputs and the fetched state needed for a write.
Callers must apply the capability, product-profile, ownership, and device
conditions documented below before offering a control. These helpers do not
select another route on failure and a successful write is not read-back.

- `set_recording_mode` takes a `RecordingMode` and a legacy channel number
  (default 1). Use the existing switch 29 route for devices that only expose
  binary recording. `set_recording_pre_roll`, `set_recording_pre_roll_fps`,
  and `set_supplemental_event_recording` use an IoT local index (default `"1"`).
- `set_indicator_daylight_mode` takes an `IndicatorDaylightMode` and writes
  channel 1. `set_indicator_night_mode` writes the separate global property.
- `set_iot_wdr_enabled` preserves the fetched level. `set_iot_wdr_level`
  accepts integer levels from 0 to 100 while WDR is enabled (the Android
  slider uses steps of 10). Both use the same video local index to read
  and write.

### Follow-up trace: recording, indicator, speaker, and WDR

The retained Android 7.4.1.0421 asset split contains the React Native
`RevisionSetting` bundle (version `5.0.0.22639082`); the Java paths below
were checked in the retained 7.6.1 decompile. These are static traces, not
live device tests. Channel numbers on legacy calls and IoT local indexes
are separate namespaces; a request scope does not prove independent lens state.

Two SDK transports already cover the traced cloud writes:

- **Key/value:** `set_device_key_value(serial, channel, key, value)` sends
  `PUT /v3/devconfig/v1/keyValue/{serial}/{channel}/op` with query parameters
  `key` and `value`. Pass a serialized JSON string for these objects. The
  generic `get_dev_config` sends GET with `key` on the same path; that is not
  evidence that a particular screen reads that key live.
- **IoT:** `get_device_feature_value` issues GET and `set_iot_feature` issues
  PUT to `/v3/iot-feature/feature/{serial}/{resource}/{localIndex}/{domain}/{property}`.
  The app reads `data` from GET and sends the JSON body `{"value": {...}}`
  for these PUTs. The SDK sends the body supplied by the caller, so include
  the envelope and pass the local index explicitly, especially for `global/0`.
  Neither transport enforces these features' UI gates.

#### Recording: numeric mode, IoT mode, and switch 29

- **`STATUS.optionals.Record_Mode`:** The revised SD-card screen reads
  `statusInfo.optionals.Record_Mode` as an object or JSON string and uses
  its numeric `mode`. `recordModeView.js` writes key `Record_Mode` with
  `{"mode": N}` through the query-based key/value route at the screen's
  `base.channelNo` (initialized to 1), not at an IoT resource index. The
  parent requires a working disk (`diskState` contains `0`) and support
  for at least one of `88`, `219`, or `793` via the bundle's
  `getBoolSupport`. The key/value branch uses `793` first, otherwise `219`. With `219`, the choices are event `0`,
  all-day `1`, and stop `2`. With `793`, its comma-separated tokens
  `1`, `2`, and `4` advertise event `0`, all-day `1`, and AOV `4`,
  respectively. If `687` contains `8` per the app's string check,
  battery work modes `3` and `4` disable event, and all-day/AOV require
  work modes `2`/`7` respectively. An enabled advertised
  `Video/1/BatCustomSpecial/TimeLapseMode` also disables these choices.
  The fixture only reports numeric mode `0`; the other values come from
  the app picker. Use the SDK's `set_recording_mode` helper for this route.
- **`FEATURE_INFO.1.Video.RecordStorage.RecordMode`:** The revised SD-card
  screen reads/writes `Video/1/RecordStorage/RecordMode` via IoT. It matches
  the product profile's resource, index, domain, and property schema and
  requires `schema.properties.recordMode.enum` to include `preRolling`
  for the pre-roll control. GET reads `recordMode` and
  `preRecordParams.fps` (UI default 2). The toggle copies the last
  fetched object and replaces `recordMode` with `preRolling` or `event`.
  Enabling is blocked in battery saving mode `3`; the first-enable
  explainer is a separate UI step. The 2/4 fps picker also requires the
  profile's `preRecordParams` schema field and pre-roll on; it copies
  the outer object and replaces `preRecordParams` with `{"fps": 2}` or
  `{"fps": 4}`. A separate recording enhancement control reads the
  same route when `775 = 1`. It additionally requires the page's
  record-mode gate and event mode (with `219` or `615`, numeric mode
  `0` or `3`; otherwise, with `88`, switch 29 off). It reads
  `eventRecordParams.suppleRecordEnabled` and `suppleRecordStorage`
  and sends `{"value":{"recordMode":"event","eventRecordParams":{"suppleRecordEnabled":<bool>}}}`;
  it does not send the storage count. The Java player's separate
  `supportStreamStateChange` reads the current playback resource/local
  index's schema for `preRolling`; it is not a write. The SDK's pre-roll and supplemental event recording helpers implement these writes.
- **Binary alternative:** When neither numeric-mode branch applies, the
  revised screen uses switch 29 with `88`: on is all-day, off is event
  recording. Its shared switch action sends
  `PUT /v3/devices/{serial}/{channel}/{enable}/29/switchStatus`, with
  channel 0 for owned devices and 1 for shared devices as classified by
  the bundle. Java `StorageStateActivity` instead requires disk support
  (`4 != 0`), normal disk state, and `88 = 1`; it writes
  `PUT /v3/devices/{serial}/switch` with query parameters
  `channelNo=1`, `enable=0|1`, and `switchType=29` (SDK `device_switch`).
  HA requires the `88` key and switch-row presence with SDK
  `switch_status` (default channel 0, v3 path and legacy POST fallback).
  The Java player's broader `isLocalSupportChangeRecordMode` predicate
  (disk count > 0, one of `88/219/615 = 1`, disk state containing `0`)
  is not the switch-29 gate or a LAN write. SDK `record_config_v30` is a
  separate native recording-config read, not a setter for either named mode.

#### Indicator: daylight picker and global night mode

- **`STATUS.optionals.IndicatorLight`:** Java
  `DeviceSettingActivity` parses `mode` from the optionals JSON. The
  picker requires `331 = 1`, mode not `-1`, and switch 3 on.
  It writes channel 1 via `set_device_key_value`, key `IndicatorLight`,
  value `{"enable":1,"mode":N}` (`0` daytime only, `1` always on).
  Use `set_indicator_daylight_mode`; `switch_device_state_led` is the
  separate binary switch 3 control.
- **`FEATURE_INFO.0.global.IndicatorLight.IndicatorLightCfg`:** In
  `lightSettingViewModel.js`, the ordinary status-light branch requires
  switch 3 present and on, no `242` doorbell-indicator support, no
  CatEye category, and for DB2C only, the app's doorbell-online check.
  The night-mode row also requires the product profile function point
  `global/0/IndicatorLight/IndicatorLightCfg`. The app seeds from cached
  feature state, then GETs that exact property; the toggle uses the
  object's `enabled` and PUTs `{"value":{"enabled":<bool>,"mode":"nightMode"}}`.
  It sends `nightMode` even when disabling, not `lightKeepOn` as seen
  in the fixture. This is a device-global IoT write, not the channel-1
  daylight key or the separate doorbell/intercom light control. Use `set_indicator_night_mode` for this route.

#### Speaker configuration

`STATUS.optionals.SpeakerConfig` is a per-device pagelist optionals
string with `RingSwitch`, `RingIndex`, `IntelligentSwitch`, and
`IntelligentIndex` all `-1` in the fixture. The raw optionals are
available through the SDK inventory, but no setting-specific app read,
write payload, write scope, or feature gate was identified in the
retained Java and bundled React Native settings. Do not treat `-1` as
off or use the generic key/value route on this basis.

Existing controls are for different settings. The app's
`soundSelect.js` reads/writes `device_bell` with `Type`, `Volume`,
and `CustomRingIndex`, not `SpeakerConfig.RingIndex`. The SDK's cloud
audio helpers use the gated `ChimeMusic` / `CustomVoice_Volume` contracts
listed above. Native `audioout_volume` (3237, default channel 1) and
`set_audio_output_volume` (3238, fixed channel 1, integer 0–100, expected
68-byte layout and read-back) address only `NET_DVR_AUDIOOUT_VOLUME`.
No dedicated or verified generic setter for `SpeakerConfig` itself was found.

#### WDR: IoT level, cloud switch, and LAN byte

- **`FEATURE_INFO.1.Video.ImageBacklight.WDR`:**
  The graphics view model adds WDR only for owned devices.
  `graphicSettingDynamicVM.js` requires `getBoolSupport(273)` (value
  2 changes the label to digital WDR) and the product profile function
  point `Video/1/ImageBacklight/WDR`. It GETs that property and reads
  `hdrSwitchEnabled` (`open` means on) and `WDRLevel1`. Once loaded,
  the toggle sends both fields, preserving the level and changing
  `hdrSwitchEnabled` to `open` or `close`. The level slider is visible
  only when on (0–100, step 10); the PUT sends
  `{"value":{"hdrSwitchEnabled":"open","WDRLevel1":<level>}}`. The SDK provides `set_iot_wdr_enabled` and `set_iot_wdr_level`.
- **Binary alternative:** With `273` but no matching function point,
  the same app screen reads switch 604 and calls its v3 switch action
  at channel 0 (the graphics view is owner-only for this row). A connected
  `HomeKitAccess.HomeKitAccessParam.accessStatus` blocks that fallback
  action, not the traced IoT branch. An IoT read failure shows retry;
  it does not select switch 604. HA independently requires the `273` key
  and switch-row presence and uses the default SDK channel 0.
- **Native LAN alternative:** The app's `EZRNLanDevModule` requires a
  LAN device/session and a readable camera parameter struct; it uses
  HCNetSDK 1067/1068 with SDK channel selector `-1` and updates both
  `byWDREnabled` and `byBacklightMode`. The SDK's executable
  `camera_param_config` and `set_camera_wdr` (also `lan wdr`) use the
  default camera configuration: read exposed as channel 1, write
  dispatch `0x111095` without a channel argument. The setter accepts
  only a boolean and requires the 152-byte layout and a starting byte
  of 0 or 1 at offset 52. It preserves other bytes, including backlight
  mode and WDR levels, and checks the full read-back. This native gate
  is not cloud capability `273`, and neither this LAN path nor switch
  604 establishes synchronization with the IoT property.

Bundle source anchors: `pages/storage/SDCard/{sdCardList,recordModeView,recordEnhance}.js`,
`pages/light/lightSettingViewModel.js`,
`pages/graphic/viewModels/graphicSettingDynamicVM.js`,
`actions/{baseAction,IOTFeatureAction}.js`, and `custom/deviceUtils.js`.
SDK references: [inventory assembly](../pyezvizapi/cloud/operations/devices.py),
[cloud controls](../pyezvizapi/cloud/operations/controls.py),
[native configuration](../pyezvizapi/streaming/local/hcnetsdk/api.py),
and the [pagelist fixture](../tests/fixtures/page_list_response.json).

### Fixture coverage: status optionals

- **Mapped above:** `Alarm_AdvancedDetect`, `Alarm_DetectHumanCar`, `Alarm_Light`, `AlgorithmInfo`, `ChimeMusic`, `CustomVoice_Volume`, `NightVision_Model`, `OSD`, `Record_Mode`, `batteryCameraWorkMode`, `device_ICR_DSS`, `device_bell`, `display_mode`, `inverse_mode`, `IndicatorLight`.
- **Reported telemetry or metadata; no setter inferred:** `4G_Info`, `Battery_WorkStatus`, `DB_Chime_ConnInfo`, `OnlineStatus`, `Route_LinkageStatus`, `StorageFirstRecordTime`, `cloudChannelList`, `diskCapacity`, `diskCid`, `diskHealth`, `hfullViewURL`, `kms_version`, `lastUpgradeTime`, `latestUnbandTime`, `latestUnbindTime`, `networkingMode`, `powerRemaining`, `powerStatus`, `powerType`, `superState`, `updateCode`, `updateProcessExtend`, `wanIp`.
- **Unmapped setting or ambiguous field:** `Alarm_Interval`, `Auto_night_vision`, `BodyDetectTimeInterval`, `CustomVoice`, `ICR`, `OneClickMute`, `PresetEffect`, `ROI`, `RecordCoverStorage`, `Remind_Way`, `SpeakerConfig`, `Temperature_Threshold`, `daylightSavingTime`, `device_auto_rouse`, `device_screen_lightness`, `device_screen_overtime`, `device_static_DNS`, `device_video_time`, `device_wifi_mode`, `gesture_remind_type`, `image_para`, `language`, `lightcamera_delay_off`, `preset`, `pri_cover_area`, `returnToPoint`, `sound_detect_type`, `talkMode`, `talk_speaker_volume`, `timeFormat`, `timeZone`, `tzCode`, `video_para`, `voiceIndex`.

### Fixture coverage: feature domains

Each row lists the property names observed for that resource/domain in the
fixture. Only the properties with a traced writer above are mapped. Generic
IoT methods alone do not qualify a property.

| Resource/domain | Observed properties |
| --- | --- |
| `DoorLock.DoorLockMgr` | `MessagePlanCfg`, `WeatherReminderPlan` |
| `DoorLock.LensPrivacyCover` | `LensPrivacyCoverModeParams` |
| `DoorLock.LightCtrl` | `NightLightCfg` (writer unverified; distinct from `Video.LightCtrl.NightLightEnable`) |
| `DoorLock.RGBLightCtrl` | `ProjectionLampCfg` |
| `DoorLock.SensorLight` | `RadarFMCfg` |
| `Video.AudioMgr` | `AudioSourceEnhancement`, `DirectionalPickup`, `MicAdaptive` |
| `Video.BatCustomSpecial` | `WorkRecordMode` |
| `Video.BatteryMgr` | `BatteryStatus` |
| `Video.CallSignalMgr` | `CallParams` |
| `Video.CloudStorage` | `CloudBackupUploadRule`, `CloudTriggerRule`, `CloudTriggerStatus` |
| `Video.DisplayScreen` | `BrithtnessCfg` |
| `Video.EZLink` | `LocalLink`, `SceneLink` |
| `Video.EnergySaving` | `EnergyModeCfg`, `HardwareEnergySaving`, `WakeupStrategyCfg` |
| `Video.FaceContrast` | `StrangerDetectionCfg` |
| `Video.FillLight` | `NightVisionAdaptMode` |
| `Video.FoVMgr` | `FoVCfg` |
| `Video.HDD` | `HDDRecordEncCfg`, `HDDStatusList`, `HDDWorkMode` |
| `Video.HomeKitAccess` | `HomeKitAccessParam` |
| `Video.HumanDetection` | `HumanDetectionSwitch`, `LongStayTime` |
| `Video.ImageAdjust` | `MultiCameraColorBalanceSwitch` |
| `Video.ImageAdjustment` | `WideAngleMode` |
| `Video.ImageBacklight` | [`WDR`](#wdr-iot-level-cloud-switch-and-lan-byte) |
| `Video.ImageEnhance` | `LowLightImageEnhanceCfg` |
| `Video.ImageExposure` | `AntiBandingParams` |
| `Video.InfoMgr` | `DeviceLongitudeLatitude` |
| `Video.IntelligentAPP` | `DownloadedAPP`, `DynamicReservedResource` |
| `Video.KeypadMgr` | `KeypadLinkageParam` |
| `Video.LaserMgr` | `LaserLinkSwitch`, `LaserSwitch` |
| `Video.LensCleaning` | `DefogCfg` |
| `Video.LightControl` | `Lightness` |
| `Video.LightCtrl` | `ColorTemperature`, `NightLightEnable` |
| `Video.Loitering` | `LoiteringEnable` |
| `Video.Microphone` | `MicrophoneVolume` |
| `Video.MotorVehiclesAnalysis` | `PlateRecognitionCfg` |
| `Video.NetworkSecurityProtection` | `PortSecurity` |
| `Video.NoiseSense` | `NoiseDetectionParams` |
| `Video.PTZMaintenance` | `HomingPreset` |
| `Video.PTZManualCtrl` | `HighPrecisionPTZCtrlAbsolute`, `ZoomLevelRange` |
| `Video.PTZMasterSlaveTrace` | `LinkedTrackingAdvancedCfg` |
| `Video.PTZPreset` | `AutoCruisingParams` |
| `Video.PTZTrace` | `AutoTraceParams` |
| `Video.Parking` | `ParkingRuleParams` |
| `Video.PetInteraction` | `LaserFunnyPetMode`, `PetVoiceBroadcastCfg` |
| `Video.PowerMgr` | `BatteryDetails` |
| `Video.RGBLightCtrl` | `RGBLightEnable` |
| `Video.RecordStorage` | `RecordCompressionParams`, [`RecordMode`](#recording-numeric-mode-iot-mode-and-switch-29) |
| `Video.SensorLight` | `RadarFMCfg` |
| `Video.SoundSetting` | `MuteEnabled`, `MutePlan`, `RingtonesList`, `SoundPlan` |
| `Video.SupplementLightMgr` | `ImageSupplementLightEventIntelligenceModeParams`, `ImageSupplementLightModeSwitchParams` |
| `Video.SweeperMgr` | `VoiceAssistantCfg` |
| `Video.SystemMaintenance` | `NetworkStatus` |
| `Video.TimingRecord` | `ScheduleRecordParams` |
| `Video.VehicleDetections` | `VehicleTraceSwitch` |
| `Video.VehicleMatch` | `VehicleMatchParams` |
| `Video.VideoAdjustment` | `ImageFlip`, `ImageShowCfg` |
| `Video.VideoMotionDetection` | `VMDCfg` |
| `Video.WifiStatus` | `NetStatus` |
| `Video.WirelessDial` | `DialLinkStatusList`, `DialSMSAutoSwitchParams` |
| `Video.WirelessRouterMgr` | `MeshTopologySwitch` |
| `global.DeviceAuth` | `DevceAuthRelatedRule` |
| `global.EZLink` | `LocalLink`, `SceneLink` |
| `global.EventSubscription` | `DefencePlan` |
| `global.HumanDetection` | `HumanDetectionParam` |
| `global.IndicatorLight` | [`IndicatorLightCfg`](#indicator-daylight-picker-and-global-night-mode) |
| `global.IntelligentAPP` | `DownloadedAPP`, `DynamicReservedResource` |
| `global.KeyMgr` | `CardKeyInfo` |
| `global.LightCtrl` | `Brightness` |
| `global.LocationMgr` | `LocateCfg` |
| `global.PTZPreset` | `AutoCruisingParams` |
| `global.SensorLight` | `AmbientLightEnabled` |
| `global.SoundSetting` | `PromptParam`, `PromptToneVolume` |
| `global.VehicleDetections` | `VehicleDecetionBasicParam` |
| `global.VideoAdjustment` | `ImageFlip`, `ImageShowCfg` |
| `global.WarningLightMgr` | `WarningLightStatus` |
