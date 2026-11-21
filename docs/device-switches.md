# EZVIZ device switches

Static reference for the retained EZVIZ Android 7.6.1 app. The inventory below
covers **all 42 members** of the app's `DeviceSwitchType` enum, plus three
additional IDs exposed by the SDK. This is not a claim that the enum enumerates
every internal settings endpoint, or that each mapped switch works on every model.

A switch ID identifies a state or setting. A `supportExt` key identifies a
capability, and its value may be an enum rather than a boolean. For example,
switch 303 is an alarm light, but capability key 303 is backlight support.
A missing switch entry is not an observed off state. A capability alone does
not establish a writable switch, a per-lens route, or current availability.

## Android switch IDs

**App** means the switch and capability are linked by an observed Android
call path. **HA** describes the companion integration's existing association,
not a verified Android UI predicate. **Unverified** means no switch-to-flag
relationship was established in this trace; it does not mean unsupported.

| ID | Android name | Support evidence and conditions |
| ---: | --- | --- |
| 1 | ALARM_TONE | HA: `7` AlarmVoice; app alert settings also inspect its mode value and ActiveDefense `96`. |
| 2 | STREAM_ADAPTIVE | Unverified. |
| 3 | LIGHT | App: doorbell uses `242 = 1` and online; indicator daylight options separately inspect `331` and this switch's state. Not a universal gate. |
| 4 | INTELLIGENT_ANALYSIS | Unverified. |
| 5 | LOG_UPLOAD | Unverified. |
| 6 | DEFENCE_PLAN | App: `3` DefencePlan plus device-specific checks in DetectionAlertActivity; state also used by the safe-mode plan UI. |
| 7 | PRIVACY | App: detail adapters check `40 = 1` together with switch state. |
| 8 | SOUND_LOCALIZATION | App: `25 = 1` SSL in DetectionAlertActivity. |
| 9 | CRUISE | Unverified; distinct from cruise tracking. |
| 10 | INFRARED_LIGHT | App: CameraSettingActivity requires `48 = 1` and camera channel information. |
| 11 | WIFI | Unverified. |
| 12 | WIFI_MARKETING | Unverified. |
| 13 | WIFI_LIGHT | Unverified; HA checks for the switch entry. |
| 14 | PLUG | App: home-card toggle requires a non-null switch state; updates cached state on success. No numeric capability gate established for this handler. |
| 21 | SLEEP | App: home settings menu requires `62 = 1`, online status and sleep permission for a shared device. |
| 22 | SOUND | App: doorbell microphone setting requires `63 = 1` and online. |
| 23 | BABY_CARE | Unverified. |
| 24 | LOGO | Unverified; do not equate with SDK switch 702. |
| 25 | MOBILE_TRACKING | HA: `73` IntelligentTrack; distinct from switches 650 and 701. |
| 26 | CHANNELOFFLINE | App: toggles offline notifications for the selected camera channel, defaulting to 1. HA associates `70` ChannelOffline; Android visibility predicate unverified. |
| 29 | ALL_DAY_VIDEO | App: normal-disk storage view uses `88 = 1`; switch on means all-day recording, off means activity recording. |
| 32 | AUTO_SLEEP | App: if `144 = 1` and this switch is off, both live and playback keep-alive helpers return disabled. Settings asks for confirmation before switching it off. |
| 34 | ROAMING_STATUS | App operator settings read and change this state via a dedicated presenter action; specific support key unverified. |
| 35 | DEVICE_4G | App operator settings read and change this state via a dedicated presenter action; specific support key unverified. |
| 37 | ALARM_REMIND_MODE | Unverified. |
| 39 | OUTDOOR_RINGING_SOUND | App: doorbell requires `164 = 1` BellSet and online. |
| 40 | INTELLIGENT_PQ_SWITCH | App settings toggle this switch using the selected camera channel, or channel 1 when none is selected. The app defines IntelligentPQSwitch capability `366`, but the display predicate was not established. |
| 41 | DEVICE_HUMAN_RELATE_LIGHT | App: LightSettingActivity selects this ID when `297 = 3`. |
| 101 | DOORBELL_TALK | App: `101 = 1` and online gate the chime calling UI, but that UI reads calling state from alarm no-disturb data. Do not assume it writes switch 101. |
| 200 | HUMAN_INTELLIGENT_DETECTION | App sends switch 200 with the selected channel in DetectionPeopleSettingActivity. Its sensitivity controls separately require `61 = 1` and detection on; that is not the gate for switch 200 itself. |
| 301 | LIGHT_FLICKER | App: DetectionAlertActivity uses `301 > 0` and switch state for its summary. HA associates `96` ActiveDefense; the checks are not equivalent. |
| 303 | ALARM_LIGHT | App: LightSettingActivity selects this ID when `297 = 2`; `113` AlarmLight exists but is not the selector in this branch. |
| 305 | ALARM_LIGHT_RELEVANCE | App: LightSettingActivity selects this ID when `297 = 1`. |
| 306 | TAMPER_ALARM | App: toggles tamper alarm using the selected camera channel, or 1 by default. HA associates `327` TamperAlarm; Android visibility predicate unverified. |
| 451 | DETECTION_TYPE | App treats this as a detection mode in SelectDetectionTypeActivity; switch capability predicate unverified. |
| 458 | REMOTE_UNLOCK | App enum ID; RemoteUnlock capability `648` is not proof that a generic switch controls unlocking. |
| 600 | OUTLET_RECOVER | App: outlet power-loss recovery setting, separate from plug power (14). The off-to-on path asks for confirmation. HA associates `189` PoweroffRecovery; Android visibility predicate unverified. |
| 611 | CHIME_INDICATOR_LIGHT | App: the observed ChimeSettingActivity branch uses `185 = 1` DeviceRing and online, despite the separate ChimeIndicatorLight capability `186`. |
| 650 | TRACKING | App: PlayDataInfo reads state separately from `198 = 1` HumanTrack support. |
| 651 | CRUISE_TRACKING | App: PlayDataInfo reads state separately from `197 = 1` CruiseTracking support. |
| 700 | PARTIAL_IMAGE_OPTIMIZE | App: PlayDataInfo requires `221 = 1`, switch on, and a non-shared device. |
| 701 | FEATURE_TRACKING | App: PlayDataInfo reads state separately from `321 = 1` FeatureTrack support. |

## Additional SDK switch IDs

| ID | SDK name | Evidence |
| ---: | --- | --- |
| 604 | WIDE_DYNAMIC_RANGE | HA: `273` WideDynamicRange. Not in the traced Android enum. |
| 617 | DISTORTION_CORRECTION | HA: `490` DistortionCorrection. Not in the traced Android enum. |
| 702 | LOGO_WATERMARK | HA: switch-entry presence. SDK lists capability `632` LogoWatermark separately; Android switch gate unverified. |

## Other capabilities used by these screens

| Key | Verified app use |
| ---: | --- |
| 61 | Sensitivity adjustment in the people-detection screen; does not replace switch 200. |
| 219 | Stop-recording support. One of the alternatives in the player’s local record-mode eligibility check. |
| 615 | Partial-area recording support. Another alternative in that player check. |

`PlayDataInfo.isLocalSupportChangeRecordMode` checks for at least one disk,
at least one of `88`, `219`, or `615` equal to 1, and acceptable disk status.
This broader player predicate is not the storage screen’s switch-29 gate.

## Gaps that remain

- The Android capability getters establish numeric keys, but do not by
  themselves prove when a control is shown. For switches 26, 40, 306 and 600,
  the settings handlers are confirmed; the visibility predicates are not.
- A handler passing a camera channel does not prove that firmware stores
  independent state for each lens.
- No reliable capability link was established for enum-only entries such as
  stream adaptive (2), log upload (5), or baby care (23). Do not infer one
  from matching IDs or similar names.

## Source trail

- Android: `com.ezviz.devicemgr.model.filter.DeviceSwitchType` (wire IDs, not
  declaration ordinals); `com.ezviz.devicemgr.model.ability.DeviceMapSupport`
  (numeric capability getters).
- Android: `DoorBellSettingActivity`, `ChimeSettingActivity`,
  `CameraSettingActivity`, `DetectionAlertActivity`, `LightSettingActivity`,
  `DeviceSettingActivity`, `BasestationDetailAdapter` and
  `PlayDataInfo`, `ResourceModel.switchPlug`, `ResourceSettingMenuDialog.initSleepSwitch`,
  `StorageStateActivity`, `DetectionPeopleSettingActivity`, and
  `EZDeviceInfoExt.getKeepAlive` / `isPlaybackKeepAlive` (state reads and contextual gates).
- SDK: [constants](../pyezvizapi/constants.py), especially `DeviceSwitchType`
  and `SupportExt`. HA associations come from the companion
  `ha-ezviz` switch definitions and are not vendor rules.

No live settings were changed to qualify this reference.

## LAN controls

The local command port does not take cloud switch IDs. It exposes named
`web` and `hiksdk` service settings and a separate channel 1 imaging
configuration read. See [LAN service controls](cli.md#lan-service) and
[WDR status](cli.md#lan-wdr). A local WDR read is not evidence that it
corresponds to cloud switch 604 on every device.
