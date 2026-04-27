# Home Assistant integration contract

`pyezvizapi` is used by both the Home Assistant core EZVIZ integration and the
`ha-ezviz` custom integration. This page documents the library behavior that
those integrations should be able to rely on when upgrading versions.

The EZVIZ cloud API is reverse-engineered and response shapes can drift. The
intent of this contract is not to freeze every raw field forever, but to keep
common integration-facing behavior stable and make breaking changes deliberate.

## Stability levels

### Stable public API

Treat these as public integration APIs. Changing their names, argument meanings,
return type category, or exception semantics should be considered breaking.

- `EzvizClient(...)`
- `EzvizClient.login(...)`
- `EzvizClient.export_token()`
- `EzvizClient.close_session()`
- `EzvizClient.load_cameras(refresh=True)`
- `EzvizClient.load_light_bulbs(refresh=True)`
- `EzvizClient.load_smart_plugs(refresh=True)`
- `EzvizClient.load_devices(refresh=True)`
- `EzvizClient.get_device_infos(serial=None)`
- `EzvizClient.get_device_records(serial=None)`
- `EzvizClient.get_mqtt_client(...)`
- `EzvizCamera.status(...)`
- `EzvizLightBulb.status()`
- `EzvizSmartPlug.status()`
- constants/enums imported by integrations, especially `DeviceSwitchType`,
  `SupportExt`, `DefenseModeType`, `SoundMode`, and option enums used by select
  and number entities.

### Raw passthrough API

`get_device_infos()` intentionally exposes much of the raw pagelist payload.
Integrations may inspect this for feature discovery, but raw nested EZVIZ fields
can appear, disappear, or change shape when EZVIZ changes its backend.

When adding new integration features, prefer wrapping raw-field interpretation in
small helpers under `pyezvizapi.feature` or typed records under
`pyezvizapi.models` instead of duplicating fragile parsing in Home Assistant
entity platforms.

## Device selection behavior

`load_devices(refresh=True)` and the typed record helpers should continue to:

- key devices by EZVIZ device serial;
- route camera-like categories to camera status handling;
- route `lighting` devices to light-bulb handling;
- route `Socket` devices to smart-plug handling;
- skip unsupported `COMMON` devices unless they are Hikvision-linked devices;
- avoid removing previously loaded device keys during a refresh, because the
  cloud may transiently omit devices.

## Expected status keys

The status dictionaries returned by `load_cameras()`, `load_light_bulbs()`, and
`load_smart_plugs()` are consumed by entity platforms. Existing keys should not
be renamed or removed without a deprecation cycle.

Common camera keys currently relied on by integrations include, but are not
limited to:

- `name`
- `status`
- `device_category`
- `device_sub_category`
- `local_ip`
- `local_rtsp_port`
- `battery_level`
- `sleep`
- `privacy`
- `audio`
- `ir_led`
- `state_led`
- `alarm_schedules_enabled`
- `alarm_notify`
- `Motion_Trigger`
- `switch_flags`

Common light/smart-plug keys include:

- `name`
- `status`
- `device_category`
- `device_sub_category`
- `local_ip`
- `is_on`
- `brightness` / `color_temperature` where supported

New keys are safe to add. Prefer adding keys over changing the meaning of
existing keys.

## Auth and token behavior

Integrations should be able to persist and reuse `EzvizClient.export_token()`.
The token dictionary may contain additional fields over time, but these fields
should remain stable when present:

- `session_id`
- `rf_session_id`
- `username`
- `api_url`
- `service_urls`

Expected auth exceptions:

- `EzvizAuthVerificationCode` means MFA is required and the integration should
  ask for a verification code.
- `EzvizAuthTokenExpired` means a stored token can no longer be refreshed and
  reauthentication is required.
- `PyEzvizError` is used for API-level errors that are not specific auth flow
  states.
- `HTTPError` wraps HTTP status failures from `requests`.
- `InvalidURL` indicates connection/proxy/endpoint URL failures.

## MQTT push behavior

`MQTTClient.decode_mqtt_message()` should continue to:

- accept UTF-8 JSON bytes;
- parse comma-separated `ext` strings into named fields;
- coerce known numeric `ext` fields to integers when possible;
- preserve unknown/top-level message fields;
- raise `PyEzvizError` for malformed JSON.

`messages_by_device` stores the most recent decoded payload per device serial
using bounded LRU-like behavior.

## Deprecation guidance

For behavior used by Home Assistant integrations:

1. Add the replacement behavior first.
2. Keep the old key/method working for at least one published minor release when
   practical.
3. Document the change in `CHANGELOG.md` under `Unreleased`.
4. Add or update an offline test that captures the expected contract.
5. Coordinate version bumps in Home Assistant core/custom integrations after the
   PyPI release is available.

## Release coordination checklist

When publishing a `pyezvizapi` release intended for Home Assistant consumption:

1. Confirm CI is green on `main`, including Ruff, codespell, dependency audit,
   mypy, Pyright, tests, package build, metadata checks, and wheel smoke tests.
2. Confirm `CHANGELOG.md` summarizes integration-facing changes.
3. Run **Prepare Release** with the bare version and merge the generated
   changelog PR.
4. Run **Upload Python Package** manually with the same bare version so the
   trusted publish workflow validates, builds, smoke-tests, uploads to PyPI, and
   creates the matching GitHub release/tag.
5. Smoke-test installation in a clean environment.
6. Update `requirements` pins in the custom integration first when appropriate.
7. For Home Assistant core, open/update the dependency bump PR with a concise
   list of integration-facing changes and relevant test coverage.
