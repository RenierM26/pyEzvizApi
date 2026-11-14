# pyEzvizApi 2.2.0

Minor release requested by the maintainer, following 2.1.0. The only SDK code
change is [#436](https://github.com/RenierM26/pyEzvizApi/pull/436).

## Switch fallback HTTP diagnostics

When the modern PUT switch endpoint and legacy POST fallback both fail, preserve
the primary SDK error's original explicit requests cause. Consumers can now read
the first request's HTTP status instead of receiving an empty SDK HTTPError with
its cause erased. This affects switch-backed actions such as floodlights, camera
switches and plug power.

Mixed statuses keep the primary request's meaning: PUT 403 / POST 504 remains
HTTP 403; PUT 504 / POST 403 remains HTTP 504. Do not follow implicit fallback
context to infer the primary status. API errors without explicit causes, legacy
fallback success and rejected-command cache behavior remain unchanged.

This improves reporting, not permissions or command routing. It does not make
rejected actions succeed, prove a device is shared, bypass sharing restrictions,
start reauthentication, change endpoints or add retries. No new required API,
configuration migration or dependency is introduced. Python 3.12+ remains required.
The existing [2.1.0 adoption guidance](release-2.1.0.md) still applies.

## Qualification

The fix was qualified with six real SDK transport-boundary controls, including
four primary/fallback HTTP status pairs, API failure and legacy success. The
four primary-cause controls fail before the fix and pass after it. Full SDK
qualification passed 6,150 tests with 91.82% coverage, plus Ruff, formatting,
mypy, Pyright, Codespell, build and Twine checks.

The corrected built wheel passed real HA error classification for 403/403,
504/504, 403/504 and 504/403, and 432 native tests on each of HA 2026.10.4,
HA 2026.11.0 and local Core dev. These are offline controls with synthetic
transport, not live cloud/device or physical-operation qualification.

Updating the SDK alone does not change Home Assistant integration dependency
requirements. Coordinate consumer adoption separately; no HA deployment is part
of this SDK release. Publication is verified separately from this source preparation.
