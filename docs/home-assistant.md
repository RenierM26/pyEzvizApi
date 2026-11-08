# Home Assistant consumers and current status

[Documentation index](README.md) · [Integration API contract](home-assistant-contract.md)

There are three distinct consumers. Installing this library does not install,
upgrade or migrate any of them.

| Consumer | Role | Current boundary |
| --- | --- | --- |
| HA core `ezviz` | Official cloud integration, with HA's own dependency pin | Validate the exact HA version/source before a dependency bump; not covered by the custom integration's import snapshot |
| `RenierM26/ha-ezviz` / `ezviz_cloud` | Separate custom cloud integration | Pinned-source offline acceptance; channel-99 push migration still required |
| Repository `ezviz_native` example | Isolated native media validation integration | Development/test example, not a released cloud replacement or upstream HA feature |

## Custom cloud integration qualification

The [acceptance suite](../examples/ha_ezviz/README.md) pins unmodified `ha-ezviz`
commit `aa37ffa0349d26bcc7ba262c9ad90f50d904b4af`. It verifies 50 imported symbols,
actual cloud parsing/coordinator/camera setup, account setup/unload, motion-control
request construction, RTSP source/image delegation, error recovery and synthetic
push callback handoff against real HA 2026.10.4. Network/FFmpeg boundaries are
stubbed where stated. Those checks do not prove live RTSP playback or broker delivery.

**Push does not yet work with that consumer and current library behavior.** The
consumer reconstructs a legacy token and supplies neither `enable_channel99()`
migration nor the required durable `on_token_updated` callback. Real startup
rejects both missing prerequisites; retries alone cannot repair them. Polling
remains independent and the failure is contained.

The integration must persist the complete token, migrate explicitly, provide a
worker-safe durable save callback, and monitor fatal push-worker health. Its
manifest must later pin the intended published library version. Do not weaken
library persistence requirements to make the old startup appear successful.
See [channel-99 migration](channel99.md) and the
[consumer finding](../examples/ha_ezviz/README.md#finding-push-migration-is-still-required).

## Import compatibility is not full runtime compatibility

Four [legacy paths](ha-compatibility.md) retain only symbols used by that pinned
consumer. Import success does not cover future consumers, every HA core version,
push lifecycle, native media support or live delivery. New code should use
canonical imports. Removed flat paths and historical pickle names intentionally break.

## Native validation and source-review proposals

Start with [native HA validation](ha-native-integration.md) for the isolated
example, and [the continuous owner API](native-ha-stream.md) for library-only use.
Its fixtures can exercise real HA ingestion while remaining offline.

The [consumer-runtime review bundle](consumer-runtime-review/README.md) and older
HA qualification pages retain pinned source patches and evidence. They are not
upstream-merged HA/Pion/relay features, supported installation instructions, or
proof that a running system has those patches. Use the
[documentation index](README.md#historical-plans-and-qualification-evidence) to
find these records without treating them as current product status.
