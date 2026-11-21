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

### Follow-up trace: recording, indicator, speaker, and WDR

- **Recording:** Android's storage screen changes numbered switch 29 for
  all-day versus activity recording, under the disk and capability gates in
  the [switch matrix](device-switches.md). Separately, the player reads the
  selected resource's `RecordStorage.RecordMode.schema.properties.recordMode.enum`
  to check for `preRolling` support. This is a schema check, not proof of a
  write route or an alias for `STATUS.optionals.Record_Mode`.
- **Indicator:** Android's daylight-mode picker reads `IndicatorLight.mode`
  and requires `331 = 1`, a reported mode other than the missing sentinel
  `-1`, and switch 3 on. The picker sends channel 1, key `IndicatorLight`,
  and a JSON string containing `enable: 1` and the selected numeric `mode`
  through the same key/value route exposed by `set_device_key_value`.
  There is no dedicated SDK mode setter. This does not establish a writer
  for the separate IoT `IndicatorLightCfg` property.
- **Speaker:** The fixture's `SpeakerConfig` contains `RingSwitch`,
  `RingIndex`, `IntelligentSwitch`, and `IntelligentIndex`, all reported as
  `-1` in the observed records. This is not volume state. Neither the
  LAN speaker-volume setter nor the cloud volume helpers establish a writer
  for this object. The reader, setter, and capability gate remain unmapped.
- **WDR:** Cloud switch 604 has an HA route gated by `273` and switch
  presence. Native LAN WDR updates a camera configuration structure.
  Neither route establishes how to write the separate pagelist feature
  `Video.ImageBacklight.WDR` or which models use it interchangeably.

Sources: [inventory assembly](../pyezvizapi/cloud/operations/devices.py),
[record model](../pyezvizapi/models.py), [feature readers](../pyezvizapi/devices/features.py),
[cloud controls](../pyezvizapi/cloud/operations/controls.py), the
[pagelist fixture](../tests/fixtures/page_list_response.json), and the retained
Android trace and companion definitions identified in the [switch reference](device-switches.md).

### Fixture coverage: status optionals

- **Mapped above:** `Alarm_AdvancedDetect`, `Alarm_DetectHumanCar`, `Alarm_Light`, `AlgorithmInfo`, `ChimeMusic`, `CustomVoice_Volume`, `NightVision_Model`, `OSD`, `batteryCameraWorkMode`, `device_ICR_DSS`, `display_mode`, `inverse_mode`, `IndicatorLight`.
- **Reported telemetry or metadata; no setter inferred:** `4G_Info`, `Battery_WorkStatus`, `DB_Chime_ConnInfo`, `OnlineStatus`, `Route_LinkageStatus`, `StorageFirstRecordTime`, `cloudChannelList`, `diskCapacity`, `diskCid`, `diskHealth`, `hfullViewURL`, `kms_version`, `lastUpgradeTime`, `latestUnbandTime`, `latestUnbindTime`, `networkingMode`, `powerRemaining`, `powerStatus`, `powerType`, `superState`, `updateCode`, `updateProcessExtend`, `wanIp`.
- **Unmapped setting or ambiguous field:** `Alarm_Interval`, `Auto_night_vision`, `BodyDetectTimeInterval`, `CustomVoice`, `ICR`, `OneClickMute`, `PresetEffect`, `ROI`, `RecordCoverStorage`, `Record_Mode`, `Remind_Way`, `SpeakerConfig`, `Temperature_Threshold`, `daylightSavingTime`, `device_auto_rouse`, `device_bell`, `device_screen_lightness`, `device_screen_overtime`, `device_static_DNS`, `device_video_time`, `device_wifi_mode`, `gesture_remind_type`, `image_para`, `language`, `lightcamera_delay_off`, `preset`, `pri_cover_area`, `returnToPoint`, `sound_detect_type`, `talkMode`, `talk_speaker_volume`, `timeFormat`, `timeZone`, `tzCode`, `video_para`, `voiceIndex`.

### Fixture coverage: feature domains

Each row exhausts the property names observed for that resource/domain in the
fixture. A property is unmapped unless linked to an identified writer above.
Generic IoT methods alone do not qualify it.

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
| `Video.ImageBacklight` | `WDR` |
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
| `Video.RecordStorage` | `RecordCompressionParams`, `RecordMode` |
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
| `global.IndicatorLight` | `IndicatorLightCfg` |
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
