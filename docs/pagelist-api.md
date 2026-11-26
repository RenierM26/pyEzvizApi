# Pagelist API

Pagelist reads device inventory and the current state reported by the EZVIZ
consumer cloud. It is not an alarm-history endpoint; use the
[Unified message list API](unified-message-list.md) for events.

## HTTP request

`GET https://<regional-api-host>/v3/userdevices/v1/resources/pagelist` with no body.
Use the regional `api_url` and authenticated session/client identity from
[EZVIZ sign-in](python-api.md#authenticate-and-read-status), not an EZVIZ Open
Platform access token.

| Query parameter | SDK default | Meaning |
| --- | --- | --- |
| `groupId` | `-1` | Group selector. `-1` is what the SDK sends for account inventory; `get_page_list()` does not expose group selection. |
| `limit` | `30` | Requested page size. The SDK's internal helper requires a positive integer; this does not establish a server maximum. |
| `offset` | `0` | Start at zero. When `page.hasNext` is true, the SDK advances by the requested `limit`, not by the number of rows in any section. |
| `filter` | See below | Comma-separated section names, not device serials or alarm types. |

For example, request connection metadata and switch state:

```http
GET /v3/userdevices/v1/resources/pagelist?groupId=-1&limit=30&offset=0&filter=CONNECTION%2CSWITCH
```

## Known section filters

These are the sections requested by the SDK's standard inventory read, not
a complete vendor registry. `get_page_list()` and `pyezvizapi pagelist` both
use this fixed set; neither accepts a custom filter or returns every possible
section. The raw HTTP API lets you request a smaller set.

| Purpose | Section selectors |
| --- | --- |
| Runtime state and settings | `STATUS`, `SWITCH`, `TIME_PLAN`, `NODISTURB`, `VIDEO_QUALITY` |
| Network and streaming | `CONNECTION`, `WIFI`, `CLOUD`, `CHANNEL`, `VTM`, `P2P`, `QOS`, `KMS` |
| Capabilities and peripherals | `FEATURE`, `FEATURE_INFO`, `DETECTOR`, `SIM_CARD` |
| Product and firmware metadata | `CUSTOM_TAG`, `PRODUCTS_INFO`, `UPGRADE`, `MULTI_UPGRADE_EXT` |

## Response and pagination

Check the HTTP status and `meta.code` (`200` on success). The SDK also
recognizes legacy `resultCode: 0`. Typical responses contain:

- `deviceInfos`: device rows identified by `deviceSerial`.
- `resourceInfos`: resource rows linking `deviceSerial` to `resourceId`, with
  resource type and local index where reported. A device can have more than
  one resource; a serial, resource ID, and channel/index are not interchangeable.
- Requested sections: commonly keyed maps. For example, `STATUS` and `SWITCH`
  are keyed by serial; `CLOUD`, `VTM`, `CHANNEL`, and `VIDEO_QUALITY` use
  resource IDs. Do not join every section by the same key. An absent field
  is not proof that a feature is off, unsupported, or writable.
- `page`: `hasNext` controls continuation. A response can also include
  `limit`, `offset`, and `totalResults`; don't infer completion from a
  section's row count or treat `totalResults` as a count for every section.

If `page.hasNext` is true (the SDK also accepts integer `1`), repeat the query
with the same group, filter, and limit, but advance the offset to `30`, then
`60`, and so on. Explicit `false` or `0` stops paging. The default SDK collector
also stops when the flag is absent; absence alone is not proof of completeness.
`get_device(strict=True)` is the stricter option for the `CLOUD` device list:
it requires an explicit valid flag and validates device rows on every page.

`get_page_list()` returns one merged JSON object, not individual HTTP pages.
For consistent shapes, lists concatenate in page order, maps merge
recursively, and conflicting scalar values from later pages win. This does not
deduplicate list rows. Because `page` is merged too, it is not a per-page log.
The SDK rejects repeated pages and caps collection at 1,000 pages; see
[pagination safeguards](bootstrap-and-pagination.md) for details.

## Device categories and types

Look for `deviceCategory` in each `deviceInfos` row. It is a
case-sensitive product family, not a pagelist `filter` value.
`deviceSubCategory` is a narrower product label (for example, `H9c`
or `EB3` in the fixture); `deviceType` is a separate model/type field.
`resourceInfos[].resourceType` describes a resource, not the device family.
Keep these values separate and preserve unfamiliar values as reported.

| `deviceCategory` | Current SDK inventory routing |
| --- | --- |
| `IPC`, `BatteryCamera`, `BDoorBell`, `CatEye` | Camera-family view, including video doorbells and peephole cameras. |
| `XVR`, `IGateWay` | Currently routed through the camera-family view; this does not guarantee every camera operation works. |
| `COMMON` | Camera-family fallback only when the device row has a truthy `hik` marker. |
| `DBScreen` | Intercom monitor, distinct from `BDoorBell` and the app's separate `SCREEN` category. |
| `lighting`, `Socket`, `Detector` | Light, plug and detector views respectively. |

The Android app defines more category strings than the SDK's family
loaders recognize. Examples below are from `EZDeviceCategory` and
`YSDeviceCategory` in the app, not a list of live-verified values or a
claim of SDK control support:

- Recorders and video hardware: `DVR`, `DVRWifi`, `NVR`, `VideoBox`, `NAS`.
- Door and security accessories: `DBChime`, `Wireless Doorbell`, `DoorLock`,
  `VideoLock`, `AlarmBox`, `SecurityLamp`.
- Networking and other products: `Router`, `RouterW3`, `RouterW5`, `RouterW5C`,
  `SCREEN`, `Switch`, `ICurtain`, `PetFeeder`, `SweepingRobot`, `MowingRobot`.

Inspect unknown categories with `get_page_list()` or `get_device_records()`
rather than relying on the family loaders to return them. Category alone
does not establish streaming, alarm, or control capability.

## Choose an SDK or CLI view

- `get_page_list()` / [`pyezvizapi pagelist`](cli.md#pagelist): merged sections
  with device and resource rows. Use this for resource-level diagnostics.
- `get_device()` and `get_switch()`: narrower reads that return `deviceInfos`
  and `SWITCH` respectively, rather than the full response.
- `get_device_infos()` / [`pyezvizapi device_infos`](cli.md#device_infos):
  processed per-serial view. It normalizes some fields and is not a lossless
  copy of the resource-level response.
- `get_device_infos(serial)` attempts the separate
  `GET /v3/userdevices/v1/resources/{serial}` route with only `filter` in the
  query. If that route is unsupported or returns an unsuitable response (for
  example, missing or ambiguous resource rows), the SDK uses account
  pagelist and selects the serial locally. If no matching row is found,
  it returns `{}`.

See [pagelist state](pagelist-state.md) for field meanings and capability
checks. Never publish raw captures: they can contain device identifiers, LAN
addresses, stream URLs, and key material. Redact them before sharing.
