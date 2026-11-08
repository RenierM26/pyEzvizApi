# Polling an inventory for Home Assistant

`EzvizClient.poll_devices()` acquires one device-record inventory for cameras,
detectors, lights and plugs. Selectors are in-memory views, not new cloud calls:

```python
from pyezvizapi import DevicePollOptions, EzvizClient

client = EzvizClient(token=saved_token)
# Run login and polling in an executor when called from an async application.
client.login()
snapshot = client.poll_devices(DevicePollOptions(timeout=20))
cameras = snapshot.as_dict("camera")  # detached legacy-shaped dictionaries
for serial, detector in snapshot.select("detector").items():
    health = snapshot.health[serial]
    if health.present and health.current and detector.online is True:
        print(detector.battery_level)
client.close_session()
```

## Ownership and freshness

- The timeout is a **total** budget, including the inventory lock, HTTP requests,
  authentication retries and optional camera alarm reads. It reuses the existing
  scoped HTTP budget/worker, not one replacement thread per timeout. As with any
  Python deadline, arbitrary caller-supplied blocking hooks cannot be interrupted.
- Inventory acquisition may paginate internally. "One inventory" is not a promise
  of one HTTP request. `max_devices` rejects over-budget returned inventories;
  the existing page-list implementation supplies its own page bounds.
- A global acquisition/budget failure raises and leaves `client.device_snapshot`
  unchanged. A malformed supported device is isolated: siblings can remain current.
- Known failed, disappeared or newly unsupported devices are retained with
  `current=False`; `present` distinguishes omission from rendering failure.
  `last_success` belongs to that device, not the latest whole-account request.
- Snapshot values are recursively immutable. `as_dict()` returns an independent
  deep compatibility copy. `select()` returns a new mapping of immutable states.
- `device_snapshot`, `select()` and `as_dict()` do not use the network. Legacy
  `load_devices()`/`load_cameras()`/family loaders retain their historical semantics
  and caches; the new API does not change them.

## Typed states and unknowns

`CameraState`, `DetectorState`, `LightState` and `PlugState` inherit `DeviceState`.
`online` recognizes only device connectivity codes 1/2, otherwise `None`; the
separate alarm-defence `STATUS.globalStatus` is never a connectivity fallback.
`battery_level` accepts integer percentages 0–100 (including numeric strings),
not arbitrary truthiness or guessed scales. Light/plug `is_on` recognizes only
boolean or integer/string 0/1. A missing property remains unknown.

`DeviceCapabilities.has(name)` reports `True` for an observed property and `None`
for absence. It does **not** claim absent hardware is unsupported, nor grant
actuator permission. Observation uses conservative source-property paths, not synthesized wrapper
defaults; present-but-null known properties are still observed.

Detector contact/water/siren codes remain available as raw diagnostics. No
model-specific binary enum has been qualified here: `door_open` and `water_leak`
remain `None`. `verified_booleans` supports an explicitly qualified consumer
policy; polling does not infer such a policy from raw codes.

Only cameras enter alarm discovery. With `include_camera_alarms=False`, camera
alarm-derived values (including motion) are explicitly unknown; they do not
pretend the device is clear. Non-camera families never acquire camera alarms.

## HA integration pattern

One coordinator calls `poll_devices()` in HA's executor. It should require both
whole-poll success and per-device current/present health before declaring entities
available. Share the one snapshot across platforms, retaining stable serial-based
registry IDs when a device is temporarily omitted. A timed-out async waiter must
retain the still-running worker and not launch overlapping replacement work.

Push is a separate optional lifecycle. Use credential-backed `enable_channel99()`
for migration, an acknowledged durable `on_token_updated` callback, and the push
client's `raise_if_failed()` monitor. Never reinterpret legacy tokens by changing
a header, or acknowledge a merely queued config-entry save as durable persistence.
