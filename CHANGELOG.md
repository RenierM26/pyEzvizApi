# Changelog

All notable changes to this project should be documented in this file.

This project follows [Semantic Versioning](https://semver.org/) for published releases.

## Unreleased

### Added

- Added cloud stream bootstrap helpers for VTM pagelist metadata, VTDU token retrieval, VTM/VTDU packet framing, `ysproto` URL handling, limited stream protobuf parsing, RTP payload extraction, and transport detection.
- Added sanitized full pagelist fixture coverage for `get_device_infos()` and `load_devices(refresh=False)` so the parser is tested against a realistic cloud response without live EZVIZ credentials.

### Changed

- Updated remote unlock to prefer terminal-derived bind codes from the EZVIZ terminals API while preserving legacy bind-code fallback behavior.
- Updated CI, CodeQL, and Dependency Review pull-request path filters so tests-only changes trigger the required checks, and excluded the captured pagelist fixture from Codespell because it preserves upstream cloud/device strings verbatim.

### Fixed

- Fixed `set_floodlight_brightness()` to accept `luminance=100`, matching the documented 1-100 range and allowing Home Assistant brightness sliders to reach full brightness/color night-vision mode.

## v1.0.4.7 - 2026-04-27

### Added

- Added manual release dispatch to the trusted PyPI publish workflow so releases can be published by running a workflow with the requested version.
- Added `codespell`, `pip-audit`, and Pyright checks to CI for extra spelling, dependency vulnerability, and static typing coverage.

### Changed

- Widened camera key/auth verification-code argument typing to accept string codes from Home Assistant forms without forcing callers to cast.
- Reworked device wrapper construction through a dedicated factory to remove client/device module import cycles while preserving existing wrapper behavior.
- Lazy-load top-level `pyezvizapi` package exports to reduce eager import graph pressure while keeping convenient imports such as `from pyezvizapi import EzvizClient`.
- Tightened `EzvizClient` JSON payload typing with a shared `JsonDict` alias and fixed Pyright-reported optional-token and MQTT-client typing issues.
- Updated release automation so the prepare step opens a changelog PR and the publish step validates, builds, smoke-tests, uploads to PyPI, and creates the GitHub release.

### Removed

- Removed the superseded manual-release workflow in favor of the trusted PyPI publish workflow dispatch path.

## v1.0.4.6 - 2026-04-27

### Added

- Modern package build checks in CI, including wheel install, CLI smoke tests, and supported Python version matrix coverage.
- Offline tests for utility helpers, feature parsing, device parsing, MQTT decoding, pagelist pagination, HTTP helpers, auth/token lifecycle behavior, camera/light/smart-plug status helpers, alarm parsing, CLI command dispatch, load-device aggregation, unified-message request building, device add/security flows, devconfig/network helpers, IoT feature/action helpers, device maintenance/admin helpers, voice/whistle/chime helpers, PTZ/panoramic helpers, camera key/2FA flows, managed-device/status/P2P helpers, time-plan/search helpers, lower-tail client helpers, CAS helpers, RTSP helpers, and MQTT demo tooling.
- PEP 561 `py.typed` marker so downstream type checkers can consume inline package types.
- Example wrappers for MQTT listening and RTSP authentication testing.

### Changed

- Added CI coverage reporting, coverage XML artifacts, and a conservative 85% coverage floor.
- Added CI `pip check` validation for both editable development installs and built-wheel smoke-test installs.
- Added release workflow wheel smoke testing with `pip check` and CLI help checks before PyPI publishing.
- Added a manual release-check workflow for dry-run package builds, optional tag/version verification, wheel smoke testing, and artifact upload before publishing.
- Added CodeQL security-and-quality scanning for Python on relevant pull requests, pushes, scheduled runs, and manual dispatch.
- Added Dependency Review checks for dependency and workflow changes, failing high-severity vulnerable dependency updates before merge.
- Documented the development validation workflow, artifact cleanup commands, and offline-test policy in the README.
- Added contributor, support, security, PR checklist, and issue-template documentation for safer reports and easier maintenance.
- Added editor and Git line-ending defaults, plus Ruff cache ignores, to reduce generated-artifact and formatting drift.
- Added package metadata links for documentation and changelog discoverability on PyPI.
- Added Home Assistant integration contract documentation for stable APIs, status payloads, auth exceptions, MQTT behavior, and release coordination.
- Limited alarm prefetching to camera devices so smart-plug/socket serials are not queried as camera alarm targets.
- Added PyPI keywords and Trove classifiers for supported Python versions, typed-package status, Home Assistant/EZVIZ discovery, and CLI/library usage.
- Consolidated package metadata into `pyproject.toml` while keeping `setup.py` as a compatibility shim.
- Restored the installed `pyezvizapi` console script via `project.scripts`.
- Replaced CLI table rendering dependency on pandas with a small stdlib formatter.

### Removed

- Removed pandas from the runtime dependency set.

## Release checklist

Before publishing a release:

1. Bump `project.version` in `pyproject.toml`.
2. Move relevant entries from `Unreleased` to a dated version section by running **Prepare Release** with the bare version and merging the generated changelog PR.
3. Ensure CI is green on `main`.
4. Run **Upload Python Package** manually with the same bare version.
5. Confirm the workflow publishes to PyPI and creates the matching GitHub release/tag.
