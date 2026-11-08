# Pinned ha-ezviz consumer acceptance

These tests execute the **unmodified** `RenierM26/ha-ezviz` consumer at
`aa37ffa0349d26bcc7ba262c9ad90f50d904b4af` with the library under test and
stock Home Assistant 2026.10.4. They do not install the consumer manifest's
old `pyezvizapi==1.0.5.0` requirement over the library under review.

CI fetches that exact commit separately. Locally, in Python 3.14:

```sh
python -m venv /tmp/ha-consumer
/tmp/ha-consumer/bin/pip install -e . -r examples/home_assistant/requirements-test.txt
git clone https://github.com/RenierM26/ha-ezviz /tmp/ha-ezviz-source
git -C /tmp/ha-ezviz-source checkout aa37ffa0349d26bcc7ba262c9ad90f50d904b4af
HA_EZVIZ_SOURCE=/tmp/ha-ezviz-source /tmp/ha-consumer/bin/python -m pytest examples/ha_ezviz/tests -o asyncio_mode=auto
```

The source must be tracked-clean and match the pin. Runtime and HA remain
optional library dependencies; these acceptance tests are not in the default
`tests/` collection. The existing consumer's minimal-HA push lifecycle tests can
also be run separately at `tests/test_push_lifecycle.py` in its checkout.

## Verified offline boundaries

- All 50 distinct library imports in consumer source resolve.
- Real account setup/first refresh/unload, with synthetic login and HTTP replies.
- Real `load_cameras` → device parsing/status → coordinator → camera setup.
- Camera motion controls reach real library PUT construction (HTTP stub only).
- RTSP source URL and image request delegation (FFmpeg stub, no playback).
- Auth/HTTP polling error translation and subsequent recovery.
- Actual MQTT factory, synthetic message-to-HA coordinator handoff, stop and
  ignored late callbacks (broker connect/stop stubbed in this positive case).
- Real legacy push startup rejection and independent polling/unload recovery.
- Real channel-99 startup rejection without a durable persistence callback.

## Finding: push migration is still required

The current consumer passes only session/refresh/API/username fields when
constructing `EzvizClient`. It neither enables channel-99 nor installs
`on_token_updated`. Actual `MQTTClient.connect()` therefore rejects the legacy
profile. Even a migrated profile needs the persistence callback before startup.
The optional-push retry wrapper keeps polling available, but retrying does not
satisfy those prerequisites. A positive callback-injection test is **not** proof
of live push delivery.

A separate integration change must persist the complete token (including channel-99
credentials), migrate explicitly with `enable_channel99`, and provide a worker-safe
callback that waits for durable HA storage before returning. Do not merely set a
profile flag, swallow the error or weaken the library's persistence requirement.
Also surface `raise_if_failed()`/diagnostics so fatal background failures trigger
recovery rather than appearing connected indefinitely. The installed manifest
must subsequently be updated to the intended released library version.

No production HA installation, credential migration, camera control, live stream,
or broker connection is performed here. Actual RTSP playback, audible audio and
live broker delivery remain unverified.
