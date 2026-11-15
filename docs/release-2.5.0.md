# pyEzvizApi 2.5.0 release notes

Prepared from merged main through [#444](https://github.com/RenierM26/pyEzvizApi/pull/444)
on 2026-11-15. Check [GitHub](https://github.com/RenierM26/pyEzvizApi/releases/tag/v2.5.0)
and [PyPI](https://pypi.org/project/pyezvizapi/2.5.0/) for publication status.

## Intercom APIs and notification fixes

- Advertised `DBScreen` monitors are independent non-camera inventory devices.
- Capability-qualified relay helpers preserve the selected `Video` resource and
  index: door 2, gate 1, with no cross-relay fallback or inferred physical state.
- Complete chime updates preserve siblings and unknown fields. The app-backed
  volume ranges are DBScreen 0–7 and outdoor BDoorBell 0–100; relay capability
  does not choose the volume scale. Nameplate-light helpers use reported routes.
- Typed events normalize evidenced ring 2701 and unlock 10242, including the
  unified alarm subtype fallback. Recent intercom history is opt-in, bounded
  and best-effort, with non-auth failures isolated from inventory polling.
- Channel-99 preserves `customerType`/`subType`, distinguishes family-14 calls
  and JSON controls from camera alarms, and tolerates malformed notifications.

See [intercom contracts and evidence](intercom.md) for exact qualification rules.

## Compatibility notes

No existing public method signatures or APIs were removed. Python 3.12+ remains
required. Consumers upgrading from 1.x must also follow [2.0 migration](release-2.0.0.md).
Three behavior changes may require downstream adjustments:

1. Known ring/unlock events no longer activate motion. Automations relying on
   their former motion misclassification must use the corresponding event instead.
2. Family-14 calls and unknown CSV families no longer receive camera-alarm fields
   such as `alert_type_code` or `msgId`. Raw push consumers must branch by layout
   instead of assuming every notification is an alarm. Standard family-1 legacy
   aliases, including `resource_type` and `sequence_number`, remain available.
3. `poll_devices()` can return `kind="monitor"`. Exhaustive device-kind consumers
   must accommodate it. `load_cameras()` continues to exclude monitors.

Authentication, push handshake/credentials/subscription/acknowledgements and
existing positional polling arguments are unchanged. History stays opt-in.

## Qualification and limits

The reviewed feature head passed 6,559 tests with 91.68% coverage, 123 installed-
wheel tests and all nine hosted checks. The release-preparation head must pass
its own CI, CodeQL quality gate and Release Check before publication.

Offline app evidence and synthetic encrypted frames do not establish live HP7
push delivery or the semantics of binary mobile notifications. Streaming,
answer/hangup, talkback, credential enrolment and unverified household/gate event
codes are outside this release. No account or device changes are made by release
qualification.

The companion [ha-ezviz #261](https://github.com/RenierM26/ha-ezviz/pull/261) must
qualify the published 2.5.0 wheel separately; this SDK release alone does not
merge or deploy the HA integration.
