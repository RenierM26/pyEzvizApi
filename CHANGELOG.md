# Changelog

All notable changes to this project should be documented in this file.

This project follows [Semantic Versioning](https://semver.org/) for published releases.

## Unreleased

### Added

- Modern package build checks in CI, including wheel install, CLI smoke tests, and supported Python version matrix coverage.
- Offline tests for utility helpers, feature parsing, device parsing, MQTT decoding, pagelist pagination, HTTP helpers, auth/token lifecycle behavior, camera/light/smart-plug status helpers, alarm parsing, and CLI command dispatch.
- PEP 561 `py.typed` marker so downstream type checkers can consume inline package types.
- Example wrappers for MQTT listening and RTSP authentication testing.

### Changed

- Added Home Assistant integration contract documentation for stable APIs, status payloads, auth exceptions, MQTT behavior, and release coordination.
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
