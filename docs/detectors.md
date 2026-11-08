# Read-only Zigbee detector support

Development-branch support for EZVIZ gateway-linked devices whose pagelist
category is `Detector`, including T2C contacts, T10C water-leak sensors and T9C
sirens. This is sensor status acquisition, not subscription cloud storage,
local Zigbee communication, alarm control or Home Assistant entity setup.

## Python API

```python
from pyezvizapi import EzvizDetector

# `client` is an already configured EzvizClient.
detectors = client.load_detectors(refresh=False)
for serial, status in detectors.items():
    print(serial, status["battery_level"], status["door_status"])

# Optional direct wrapper. Without device_obj this fetches device info once.
status = EzvizDetector(client, "DEVICE_SERIAL").status()
```

The canonical implementation is `pyezvizapi.devices.detector.EzvizDetector`;
the package-root import has the same identity. `load_devices()` now includes
detectors in its combined result. `load_cameras()` still returns cameras only;
detectors are excluded from camera status processing and camera alarm prefetch.
Consumers that assume every device is a camera should use `load_cameras()`.

`load_detectors(refresh=...)` follows the existing light/plug convenience-loader
contract by calling `load_devices(refresh=...)`. In a mixed inventory,
`refresh=True` can refresh camera alarms, but no detector-specific requests or
writes are added. `refresh=False` avoids those camera refreshes. Existing
inventory cache retention rules are unchanged.

## Status fields

| Family | Output fields |
| --- | --- |
| Common | `serial`, `name`, `version`, `status`, category/sub-category, firmware/upgrade metadata, `supportExt`, `optionals`, empty `switches` |
| Battery | `battery_level` from `BatteryInfo.SurplusPower`, falling back to `PowerMgr.SurplusPower` when missing/null |
| T2C contact | `door_status`, open/closed remind and gateway-alarm settings, `door_open_detection_time` |
| T10C water | `water_leak_status` |
| T9C siren | `siren_work_state`, alarm volume/duration, tamper and motion settings |
| Radio/power | `zigbee_signal`, `power_mode` |

Properties are read from `FEATURE_INFO[serial]["0"]["global"]` in the pagelist
(or `FEATURE_INFO["0"]["global"]` in an individual device record). Integer local
index `0` is also accepted for Python mappings; a valid string-index mapping
wins when both exist. Other channels are not guessed or merged.

Device property values are **raw**, not inferred booleans: numeric/string enums
must be interpreted against the particular product/firmware schema. Zero and
false remain zero and false. Missing or malformed intermediate objects produce
`None` for affected fields, not a fabricated closed/dry/inactive state. Unsupported
property families also remain `None`. Reads do not mutate the source payload.
No siren triggering, arming, disarming or other controls are exposed here.

## Verification and provenance

This implementation carries forward **Simone Rescio (@srescio)**'s
[PR #99](https://github.com/RenierM26/pyEzvizApi/pull/99), commit
[`6722e27`](https://github.com/srescio/pyEzvizApi/commit/6722e27cebe1562e70f223d5c034c4e082fe7b2a).
The original author reported live verification with six T2C, two T10C and one T9C
on an A3 gateway. Field names above originate from that proposal. Attribution is
also retained in the implementation and co-author commit trailer.

The official Android app **7.6.1.0824** was independently inspected:

- `EZDeviceCategory` declares the exact `Detector` category.
- `DeviceListResp.FEATURE_INFO` is a serial-indexed map, separate from legacy
  `DETECTOR` data and legacy A1 detector endpoints.
- `Utils.loadRespToDeviceInfoExt` selects the serial's feature map and stores it
  as `FeatureInfo3.featureJson` without converting the property values.
- `FeatureModel.Factory` uses runtime `ProductInfo.profile` definitions;
  `FeatureModel.update` traverses local index, resource category, domain and
  property. Model-specific definitions are dynamic, not a hard-coded Java list.
- Flutter's bundled string table also contains `SurplusPower` and `ZigbeeSignal`;
  those names alone do not independently establish every device's leaf schema.

Tests use explicitly **synthetic**, PR99-shaped contact/water/siren fixtures and
exercise partial/malformed payloads, raw zero/false values, inventory routing,
privacy-safe failure isolation, exports and real pinned HA consumer paths.
The per-device leaf schema is based on the original author's reported live work;
this change does **not** independently requalify physical T2C/T10C/T9C hardware,
all firmware variants, or live state changes. No credentials, captured sensor
payloads, APK files or decompiled proprietary source are published with the PR.

HA consumers still need separate detector sensor/binary-sensor entity support;
this library change does not install those platforms or modify a running HA system.
