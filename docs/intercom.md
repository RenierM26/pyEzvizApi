# Non-streaming video intercom support

The intercom helpers are application-independent. They do not start a preview,
change encryption, enrol credentials, answer a call or infer physical door state.

## Discovery and identity

`poll_devices()` now includes advertised `DBScreen` indoor monitors as
`MonitorState` (`kind="monitor"`). Monitors retain their own vendor serial and
reported metadata/optionals; they never receive camera RTSP defaults or camera
alarm requests. Legacy `load_cameras()` does not return monitors.

`BDoorBell` remains a camera for compatibility. Intercom chime/relay helpers
require enabled local lock/gate capability **662 == 1**; ordinary doorbells do
not acquire the intercom's 0–7 volume scale. A monitor's category is sufficient
for its observed chime settings. No model-name inference or composite-serial
splitting creates indoor monitors or topology relationships.

`intercom_relays(data)` returns door/gate targets only when a single advertised
`Video` resource has a valid local index. Missing/ambiguous routes remain unknown.
The cloud/composite serial is preserved. These controls do not implement linked
locks, CAS identities or LAN camera-module routing.

## Commands and observed settings

```python
from pyezvizapi.devices.intercom import (
    chime_value, intercom_relays, set_intercom_chime, unlock_intercom,
)

# `data` is the selected device's detached, current snapshot dictionary.
relays = intercom_relays(data)
volume = chime_value(data, "volume")
# Explicit user commands only:
# unlock_intercom(client, serial, "door", data)
# set_intercom_chime(client, serial, "doorbell_enable", False, data)
```

- Door is relay 2; gate is relay 1. Exactly one command is sent to the selected
  relay. API rejection propagates; the other relay is never a fallback.
- `set_intercom_chime` patches a complete detached `ChimeMusic` object, preserving
  sibling/unknown fields. It refuses missing settings rather than filling default
  values. Booleans must be booleans; volume is an integer 0–7.
- `doorbell` and `pir` ringtone IDs can be set to caller-known nonnegative integer
  IDs. There is **no universal confirmed ringtone catalogue or maximum** here.
- Applications must serialize compound writes and preserve accepted siblings when
  the vendor's next poll is stale. Helpers neither cache accepted commands nor
  advertise them as confirmed state.
- `label_light_value` / `set_label_light` select the routed
  `LightCtrl/NightLightEnable` boolean property when reported; otherwise an
  observed legacy switch 611. They do not walk unrelated resource trees or try
  another route after a rejected write. Account write permissions still apply.

## Events

`normalize_intercom_event` accepts unified messages, legacy alarm records and
already-decoded MQTT pushes. Its frozen `IntercomEvent` contains only serial,
message identity, numeric type, UTC timestamp (or unknown), channel and a qualified
unlock method. It does not contain image URLs, credentials, card names or raw data.

Currently qualified types:

| Code | Type | Evidence |
| --- | --- | --- |
| 2701 | `ring` | Retained official Android `AlarmType.DOORBELL_RING` |
| 10242 | `lock_unlocked` | Published real HP7 legacy/unified records |

Only `customerType=Card` → `rfid` and `Monitor` → `monitor` are currently
qualified. Other methods remain `None`, not text-matched guesses. This does not
identify a specific person/card, establish a gate event code or distinguish two
household call buttons. Unknown codes are not classified from translated titles.

Unified-message `time` takes precedence over conflicting `ext.alarmStartTime`.
Naive push time strings require an explicitly supplied timezone; otherwise
`occurred_at` is unknown. Events without stable message IDs are not invented.
Known ringing/unlock codes no longer activate the SDK's legacy motion projection.

Opt into bounded recent history with
`DevicePollOptions(include_intercom_events=True)`. This adds at most one request
for 50 recent messages, after device rendering, under a sub-budget capped at two
seconds and one quarter of the remaining overall poll budget. Non-auth history
errors leave device inventory usable and set `intercom_events_current=False` plus
a safe exception class. Explicit SDK auth exceptions still propagate.

Consumers own deduplication, first-window suppression, clock/freshness policy and
reconnect handling. The window is **not lossless backfill** after outages/high
traffic, and this is not a local-only event transport. Existing poll defaults and
positional arguments are unchanged.

## Provenance and remaining acceptance

Protocol findings are corroborated by retained EZVIZ Android 7.4.1.0421
(versionCode 1676), particularly `PlayDataInfo.supportLocalLockGate` and
`BasePlayerOperationPresenter` local relay actions. Chime field names also occur
in the app's `ChimeMusic` model. No proprietary app source or credentials are
included in this repository.

[Bobsilvio/ezviz_hp7](https://github.com/Bobsilvio/ezviz_hp7) provides useful
hardware reports and the nameplate-light property schema
([issue 34](https://github.com/Bobsilvio/ezviz_hp7/issues/34)).
[Issue 32](https://github.com/Bobsilvio/ezviz_hp7/issues/32) supplies numeric unlock
records and documents the missing event-to-card identity link. The SDK's existing
unlock routing has a successful HPD7 report in
[issue 432](https://github.com/RenierM26/pyEzvizApi/issues/432).

New helpers are verified with offline synthetic tests, not new hardware commands.
Additional firmware/account validation is still needed. Streaming, talkback,
answer/hangup, arbitrary feature writes and credential management are separate work.
