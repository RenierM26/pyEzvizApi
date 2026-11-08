# Code map

Start here when changing the library. Paths below are relative to `pyezvizapi/`.

**Domain packages own implementations.** The only legacy forwarding modules
are `feature`, `mqtt`, `utils` and `test_cam_rtsp`, retained for `ha-ezviz`.
They explicitly re-export only the integration's imported names; they are not
module-identity aliases or private monkeypatch surfaces. Use canonical modules
for new code and test hooks. See [HA compatibility](ha-compatibility.md) and
`docs/module-map.json` for removed-path replacements.

| Change | Implementation |
| --- | --- |
| Cloud login and token persistence | `cloud/auth.py; cloud/token.py; cloud/token_store.py` |
| HTTP, deadlines and pagination | `cloud/transport.py; cloud/budget.py; cloud/deadline.py; cloud/pagination.py` |
| Device status and feature routing | `devices/camera.py; devices/factory.py; devices/features.py` |
| Public client operations | `client.py → cloud/operations/{inventory,devices,controls,settings,intercom,recordings,capture}.py` |
| MQTT and channel-99 push | `push/mqtt.py; push/longlink/` |
| CLI flags and command dispatch | `cli/arguments.py; cli/main.py; cli/commands/` |
| Cloud stream negotiation/framing | `streaming/cloud/bootstrap.py; streaming/cloud/protocol.py` |
| Local SDK sessions and socket ownership | `streaming/local/session.py; streaming/local/ecdh.py` |
| SDK configuration/discovery/authentication | `streaming/local/hcnetsdk/{configuration,discovery,authentication}.py` |
| SDK models and wire serialization | `streaming/local/hcnetsdk/protocol_types/` (independent values, models and codecs) |
| Local capture, decode windows and payload routing | `streaming/local/{capture,windows,payloads,diagnostics}.py` |
| RTP, MPEG-PS, clocks and remux | `streaming/media/` |
| Streaming source selection and bounded sessions | `streaming/{selection,discovery,capture,native_session,native_stream}.py` |
| Small shared conversion/time/crypto/DNS helpers | `_shared/` |

## Where new code belongs

- Cloud account/device endpoint work: `cloud/` or the relevant client operation
  family. `client.py` retains public methods and auth/transport ownership.
- Device-specific status/payload interpretation: `devices/`.
- Push: `push/`. Cloud API transport and push reconnect lifetime are separate.
- Encoded media, local/cloud streaming or timing: `streaming/`, with transport
  ownership separate from pure parsing and mux helpers.
- CLI: `cli/commands/<family>.py`; flags live in `cli/arguments.py`, common
  authentication/output/session lifetime stays in `cli/main.py`.
- Shared helpers need at least two real consumers and one clear responsibility;
  `_shared` is not a catch-all for code without an owner.

## Compatibility and hook ownership

`EzvizClient` methods delegate without changing signatures. Extracted command
and operation implementations receive their existing runtime hooks through an
explicit `_owner` context argument from the public wrapper. This preserves late monkeypatches rather
than copying bindings into a second module. Do not replace this with a dynamic
module proxy, silently copy hooks, or widen transport/media budgets during moves.

SDK protocol implementations are dependency-closed under `protocol_types/`;
`protocol.py` and the former `models_*` modules only compose compatibility
exports. Static-only nominal interfaces live in `_typing/*.pyi`, are included
in the wheel, and are never imported at runtime. This keeps precise annotations
without an implementation importing its runtime owner back.

Root `__init__.py` keeps its existing lazy exports. Media/HA are not imported as
a side effect of package discovery. Removed flat paths no longer support imports or historical pickles.
Canonical classes remain pickleable under their domain module names.

## Tests

`tests/{cloud,devices,push,streaming,cli,shared,compat}` mirrors the implementation.
`tests/tools` covers developer/qualification tools, not production library APIs.
Fixtures stay under `tests/fixtures`. `tests/_paths.py` resolves shared fixture,
repository and cross-test helper paths independently of package depth.

Run all tests with `python -m pytest`; select a domain with, for example,
`python -m pytest tests/push`. The CI discovery check supports nested tests.

See [migration stages and constraints](package-layout-migration.md).
