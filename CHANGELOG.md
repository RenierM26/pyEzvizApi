# Changelog

All notable changes to this project should be documented in this file.

This project follows [Semantic Versioning](https://semver.org/) for published releases.

## Unreleased

### Added

- Modern package build checks in CI, including wheel install, CLI smoke tests, and supported Python version matrix coverage.
- Offline tests for utility helpers, feature parsing, device parsing, MQTT decoding, pagelist pagination, HTTP helpers, auth/token lifecycle behavior, camera/light/smart-plug status helpers, alarm parsing, CLI command dispatch, load-device aggregation, unified-message request building, device add/security flows, devconfig/network helpers, IoT feature/action helpers, device maintenance/admin helpers, voice/whistle/chime helpers, PTZ/panoramic helpers, camera key/2FA flows, managed-device/status/P2P helpers, time-plan/search helpers, lower-tail client helpers, CAS helpers, RTSP helpers, and MQTT demo tooling.
- PEP 561 `py.typed` marker so downstream type checkers can consume inline package types.
- Example wrappers for MQTT listening and RTSP authentication testing.

### Changed

- Added CI coverage reporting, coverage XML artifacts, and a conservative 85% coverage floor.
- Added CI `pip check` validation for both editable development installs and built-wheel smoke-test installs.
- Added release workflow wheel smoke testing with `pip check` and CLI help checks before PyPI publishing.
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

1. Move relevant entries from `Unreleased` to a dated version section.
2. Bump `project.version` in `pyproject.toml`.
3. Ensure CI is green on `main`.
4. Create a GitHub release whose tag matches `v<pyproject version>`.
5. Confirm the PyPI publish workflow completes successfully.
