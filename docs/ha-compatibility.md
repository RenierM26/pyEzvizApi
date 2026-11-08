# HA compatibility boundary

Compatibility is scoped to [ha-ezviz](https://github.com/RenierM26/ha-ezviz)
at commit `aa37ffa0349d26bcc7ba262c9ad90f50d904b4af`. The exact integration import contract is
recorded in [ha-compatibility.json](ha-compatibility.json).

| Retained path | Canonical owner | Export count |
| --- | --- | --- |
| `pyezvizapi.feature` | `pyezvizapi.devices.features` | 23 |
| `pyezvizapi.mqtt` | `pyezvizapi.push.mqtt` | 1 |
| `pyezvizapi.utils` | `pyezvizapi._shared.utils` | 6 |
| `pyezvizapi.test_cam_rtsp` | `pyezvizapi.streaming.rtsp_compat` | 1 |

These are explicit, typed re-exports, not module-object replacements. Unrelated
imports and private hooks are not supported through these paths. Test or patch
the canonical owner. `EzvizClient`, constants, exceptions, models and root lazy
public symbol exports remain available. Client method names and status keys
are unchanged by the alias cleanup. This is an **import** contract, not a
push/runtime compatibility claim: the pinned consumer still needs the
[channel-99 migration](home-assistant.md#custom-cloud-integration-qualification).

## Intentional breaking changes

66 unused flat forwarding modules are removed. See `historical_relocations` in
[module-map.json](module-map.json) for the complete old-to-new mapping. For example:

```python
from pyezvizapi.streaming.native_stream import NativeMpegTsStream
from pyezvizapi.streaming.local.hcnetsdk.api import HcNetSdkCommandPortClient
from pyezvizapi.devices.camera import EzvizCamera
```

Use canonical paths for new development. Pickles referring to removed flat module
paths are no longer supported; canonical class round trips remain supported.
The old full-namespace snapshot is deliberately retired, not treated as a new
compatibility requirement.

Console entry points and `python -m pyezvizapi` remain supported. The equivalent
module commands now use `python -m pyezvizapi.cli.capabilities` and
`python -m pyezvizapi.cli.mqtt_listener`. Import CLI helpers from `cli.main`,
not `__main__`. No version bump, release or production deployment is performed
by this cleanup.

The unused `streaming.cloud.legacy` and `streaming.local.legacy` facades are
also removed. `EzvizCamera.alarm_detection_sensibility()` is removed in favor
of `alarm_detection_sensitivity()`; the CLI now calls the canonical method.
