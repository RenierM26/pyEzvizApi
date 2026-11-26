# Unified message list API

Use UnifiedMsg to read alarm history and build custom queries for your EZVIZ
account. This reference describes the consumer cloud API used by pyEzvizApi,
not the EZVIZ Open Platform. It is read-only and returns one page per call.

## HTTP request

`GET https://<regional-api-host>/v3/unifiedmsg/list` with no request body.

Use the API host returned by EZVIZ sign-in (`api_url` in the SDK's exported
token) and the authenticated account's session and client identity headers.
`sessionId` is the account session credential, not an Open Platform access
token. For a direct HTTP client, reuse the headers associated with that
session; a bare unauthenticated GET will not work. For Python, prefer
[signing in with the SDK](python-api.md), which manages the host, headers, and
session recovery. Never log or share session headers or exported tokens.

| Query parameter | SDK argument | Value and behavior |
| --- | --- | --- |
| `serials` | `serials` | One serial or comma-separated serials without spaces. Omit for account-wide results. The SDK omits `None` and `""`. |
| `stype` | `s_type` | Message category or comma-separated categories without spaces. The SDK sends `92` by default, for `None`, or for an empty iterable. An explicit `""` omits the parameter; that is not the same as the SDK default. |
| `limit` | `limit` | Requested maximum rows per page. The SDK defaults to 20 and clamps numeric input to 1–50; input it cannot convert to an integer falls back to 20. |
| `date` | `date` | Day selector in `YYYYMMDD` form, e.g. `20261126`. The SDK accepts a string, `datetime.date`, or `datetime.datetime` and defaults to the calling process's local date; it does not convert timezones. Pass `""` to omit the day selector, as the SDK does for recent-alarm polling. An omitted date is not a request for unlimited history. |
| `endTime` | `end_time` | Send an empty value for the newest page. For the next page, send the last row's raw `time` value unchanged. The SDK serializes `None` as the empty value and accepts string or integer cursors. |

Example request target for person and vehicle alerts from two devices (shown
with the commas URL-encoded):

```http
GET /v3/unifiedmsg/list?serials=CAMERA_A%2CCAMERA_B&stype=2403%2C2404&limit=20&date=20261126&endTime=
```

## Filter values

These values are for the **request** parameter `stype`. The `subType`
and `ext.alarmType` in a **response** classify an individual message;
they need not match the category code used to request it. Do not assume
that every observed alarm type can be sent back as a query filter.

| `stype` | Selection | Evidence |
| --- | --- | --- |
| `92` | Broad alarm feed | Android Message Center default and SDK default (`UnifiedMessageSubtype.ALL_ALARMS`); exercised live on the SDK route. |
| `2401` | Alarm category | Android Message Center's selectable alarm category (`MessageFilterType.FILTER_TYPE_ALL_ALARM`); distinct from the default query value `92`. |
| `2402` | Motion | Android Message Center; `MessageFilterType.FILTER_TYPE_MOTION`. |
| `2403` | Person | Android Message Center; `MessageFilterType.FILTER_TYPE_PERSON`. |
| `2404` | Vehicle | Android Message Center; `MessageFilterType.FILTER_TYPE_VEHICLE`. |
| `2405` | Sound | Android Message Center; `MessageFilterType.FILTER_TYPE_SOUND`. |
| `2101` | System messages | Android Message Center; `MessageFilterType.FILTER_TYPE_SYSTEM_MESSAGE`. These messages need not have a camera serial. |
| `2701` | Doorbell ring | Known ring subtype; SDK intercom history requests `92,2701` ([intercom reference](intercom.md)). |
| `9904,2701` | App playback subtype bundle | App playback default represented by `UnifiedMessageSubtype.DEFAULT_APP_SUBTYPE`; not the SDK or Message Center default. |

The app builds a comma-separated list for multiple selections. The
Message Center in Android 7.6.1 sends those categories to
`GET /v3/unifiedmsg/list/v2`, using the same five query fields and the
same timestamp cursor. The SDK uses `/v3/unifiedmsg/list`, also used by
Android 7.4.1 playback, and does not expose a route switch. A live comparison
matched the two routes for the default feed and next page, not for every
individual filter. Validate narrower categories against known events on your
device and region before relying on them. This is a list of known filters,
not a complete vendor registry.

## Response

The SDK returns the full decoded JSON object, not just the rows. Example
with synthetic values:

```json
{
  "meta": {"code": 200},
  "hasNext": true,
  "failureSubTypes": [],
  "noMessageAbility": false,
  "message": [
    {
      "msgId": "example-message-1",
      "deviceSerial": "DOORBELL_A",
      "channel": 1,
      "subType": 2701,
      "time": 1795672800000,
      "title": "Doorbell ring",
      "ext": {"alarmType": 2701}
    }
  ]
}
```

| Field | How to use it |
| --- | --- |
| `meta.code` | Check the application status as well as the HTTP status. Success is `200`; the SDK also recognizes legacy `resultCode: 0`. The SDK raises on unsuccessful API status rather than returning an empty list. |
| `message` | Array of message objects, newest first in observed replies. SDK consumers also recognize `messages`. Treat missing or malformed rows as an unexpected response, not as proof of no events. |
| `hasNext` | Boolean continuation flag when present. Explicit `false` ends paging; absent is not proof that the result is complete. |
| `failureSubTypes`, `noMessageAbility` | A nonempty failed-subtype list or a true no-message-capability flag can indicate a partial or unavailable feed, even on a successful response. |
| `range`, `size`, `timestamp` | Additional metadata in the app response model; don't use these fields as the page cursor or assume `size` is an account-wide total. |
| `msgId`, `deviceSerial`, `channel` | Message ID for deduplication, source device, and channel when supplied. For device events, keep the serial alongside the ID. |
| `time`, `timeStr`, `ext.alarmStartTime` | Use raw `time` for paging. The other fields are display/source timestamps and may not agree with it. |
| `subType`, `ext.alarmType` | Message subtype and alarm code. Treat them as separate fields; values can differ and may be missing. For example, the app recognizes a ring from `subType=2701` when `ext.alarmType` is zero. |
| `title`, `detail` | Display text, potentially localized. Avoid classifying alerts by text. |
| `pic`, `defaultPic`, `ext.pics`, `picCrypt`, `picChecksum` | Optional image URLs, alternate images (semicolon-separated in `ext.pics`), and image metadata. URLs may change or contain signed parameters; don't use them as event IDs or include them in logs. |

## Python example: query and fetch the next page

Pass an authenticated `EzvizClient` to this function. Use `.value` when
passing `MessageFilterType` members; the method also accepts integer codes,
a CSV string, or an iterable of strings and integers. The CLI uses the default
filter and [outputs only the rows](cli.md#unified-alarm-history).

```python
from datetime import date

from pyezvizapi.client import EzvizClient
from pyezvizapi.constants import MessageFilterType


def person_and_vehicle_pages(client: EzvizClient, serial: str) -> list[dict]:
    query = {
        "serials": serial,
        "s_type": [
            MessageFilterType.FILTER_TYPE_PERSON.value,
            MessageFilterType.FILTER_TYPE_VEHICLE.value,
        ],
        "date": date.today(),
        "limit": 20,
    }
    first = client.get_device_messages_list(**query)
    pages = [first]
    rows = first.get("message")
    if not isinstance(rows, list):
        rows = first.get("messages")
    if first.get("hasNext") is True and isinstance(rows, list) and rows:
        last = rows[-1]
        cursor = last.get("time") if isinstance(last, dict) else None
        if type(cursor) is int or (isinstance(cursor, str) and cursor):
            pages.append(client.get_device_messages_list(**query, end_time=cursor))
    return pages
```

`max_retries` is an SDK-only transport option (default 0, maximum 3),
not an HTTP query parameter.

When looping through history, keep the serials, category filter, date, and
limit fixed. Bound the loop and stop on an empty page, an explicit
`hasNext: false`, a missing cursor, or a cursor that stops advancing.
Deduplicate repeated rows by message ID (and device serial when available).
The server's timestamp-only cursor can skip tied messages at a page boundary.
Do not substitute `msgId`, a formatted timestamp, or a rescaled epoch.
An invalid cursor can return HTTP 400. To query a different day, start again
with an empty cursor.

## Latest alarm vs. history

For the latest matching alarm on one device, send a fresh, serial-filtered
request with an empty cursor. For several devices, a page can be dominated by
one busy camera. A device missing from that page may still have an alarm:
re-query the missing devices with a fresh cursor rather than treating a match
on an older history page as their latest. The SDK uses this strategy for its
latest-alarm polling. Results cover messages visible to the cloud at request
time; they are neither a real-time push stream nor a lossless archive.
