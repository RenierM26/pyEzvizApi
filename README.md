# pyEzvizApi

[![CI](https://github.com/RenierM26/pyEzvizApi/actions/workflows/ci.yaml/badge.svg)](https://github.com/RenierM26/pyEzvizApi/actions/workflows/ci.yaml)
[![PyPI](https://img.shields.io/pypi/v/pyezvizapi)](https://pypi.org/project/pyezvizapi/)
[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20me%20a%20coffee-renierm-yellow?logo=buymeacoffee)](https://www.buymeacoffee.com/renierm)

A Python client and CLI for the reverse-engineered EZVIZ cloud API, device
controls, channel-99 push and optional local/cloud media processing.

**These docs track `main`, including unreleased changes.** A PyPI installation
may not contain every API described here. Match documentation to your installed
release tag, or use a source checkout for current development. See the
[changelog](https://github.com/RenierM26/pyEzvizApi/blob/main/CHANGELOG.md), especially the removed import paths and push migration.

## Preparing 2.1.0

Version 2.1.0 adds opt-in persisted installation identities and corrects
multi-resource intercom relay routing. See the [2.1.0 release notes](docs/release-2.1.0.md)
for consumer adoption and qualification limits. Preparation is not publication;
check the PyPI badge or GitHub releases for actual availability.

## Upgrading to 2.0

Version 2.0 removes obsolete flat imports and legacy push registration. Review
the [release and migration notes](https://github.com/RenierM26/pyEzvizApi/blob/main/docs/release-2.0.0.md)
before upgrading. Push consumers need explicit channel-99 migration and durable
complete-token storage; polling remains independent of push. Updating this library
does not migrate Home Assistant integrations or change their dependency pins.

## Install

Python **3.12 or newer** is required for the library.

```bash
python -m pip install pyezvizapi
# Optional PyAV-backed streaming APIs:
python -m pip install 'pyezvizapi[streaming]'
```

FFmpeg/FFprobe are separate system programs used by specific media paths, not
installed by pip. Home Assistant and development-player dependencies are not
required for ordinary library use.

## Quick start

```bash
pyezvizapi --help
# First login; replace placeholders. Passwords passed as arguments may be
# visible in shell history/process listings. Prefer saved tokens for reuse.
pyezvizapi -u YOUR_USERNAME -p YOUR_PASSWORD --save-token devices status
# Global flags precede the command:
pyezvizapi --token-file ezviz_token.json --json devices status
```

The CLI prompts for MFA when required. Protect the complete token file; do not
commit it. See [getting started](https://github.com/RenierM26/pyEzvizApi/blob/main/docs/getting-started.md) for region selection,
token precedence, source installation and authentication troubleshooting.

## What is available?

| Area | Start here |
| --- | --- |
| Python account/device client | [Python API guide](https://github.com/RenierM26/pyEzvizApi/blob/main/docs/python-api.md) |
| Read-only T2C/T10C/T9C detector status | [Detector guide](https://github.com/RenierM26/pyEzvizApi/blob/main/docs/detectors.md) |
| CLI inventory, status and controls | [Command-line guide](https://github.com/RenierM26/pyEzvizApi/blob/main/docs/cli.md) |
| Push notifications | [Channel-99 migration and lifecycle](https://github.com/RenierM26/pyEzvizApi/blob/main/docs/channel99.md) |
| Images, finite clips and stream paths | [Media guide](https://github.com/RenierM26/pyEzvizApi/blob/main/docs/media.md) |
| Home Assistant consumers and known gaps | [HA integration status](https://github.com/RenierM26/pyEzvizApi/blob/main/docs/home-assistant.md) |
| Canonical imports and breaking alias removals | [Compatibility guide](https://github.com/RenierM26/pyEzvizApi/blob/main/docs/ha-compatibility.md) |
| All guides, technical references and research | [Documentation index](https://github.com/RenierM26/pyEzvizApi/blob/main/docs/README.md) |

Device controls and stream support depend on model, firmware, region and account
permissions. A command's API success is not proof of physical device action.
Decoded samples and offline tests are not proof of live HA/browser playback.

## Home Assistant

The cloud client is consumed by HA's EZVIZ integration and the `ha-ezviz` custom
integration; they have separate dependency pins and release cycles. The current
`ha-ezviz` consumer needs **channel-99 migration and durable token persistence**
before push can work with this branch. Polling is independent of push.

The native HA example is an isolated validation integration, not a released
replacement for either cloud integration. See [HA status](https://github.com/RenierM26/pyEzvizApi/blob/main/docs/home-assistant.md)
for tested boundaries and remaining live acceptance work.

## Development and support

- [Contributing](https://github.com/RenierM26/pyEzvizApi/blob/main/CONTRIBUTING.md): environment setup and offline checks.
- [Code map](https://github.com/RenierM26/pyEzvizApi/blob/main/docs/code-map.md): implementation ownership.
- [Release procedure](https://github.com/RenierM26/pyEzvizApi/blob/main/docs/releases.md): version, changelog and publish workflow.
- [Support](https://github.com/RenierM26/pyEzvizApi/blob/main/SUPPORT.md): reproducible bug reports and troubleshooting.
- [Security](https://github.com/RenierM26/pyEzvizApi/blob/main/SECURITY.md): private reporting and protocol limitations.

Apache-2.0; see [LICENSE](https://github.com/RenierM26/pyEzvizApi/blob/main/LICENSE).

[Support the maintainer](https://www.buymeacoffee.com/renierm).

### Shared device inventory

For one bounded refresh shared across HA platforms, immutable typed states and
per-device freshness, see [Device inventory](docs/device_inventory.md). Existing
family loaders remain compatible.

### Stable identities for container applications (2.1.0+)

Applications can opt into a persisted per-client `feature_code` instead of the
legacy MAC-derived identity. Persist it before first login and provide the same
value when restoring saved credentials; the SDK never silently adopts a token's
identity or changes process-wide defaults. See
[persisted installation identities](docs/auth/persisted-client-identity.md) for
ownership, migration, validation and consumer-release requirements.
