# pyEzvizApi

[![CI](https://github.com/RenierM26/pyEzvizApi/actions/workflows/ci.yaml/badge.svg)](https://github.com/RenierM26/pyEzvizApi/actions/workflows/ci.yaml)
[![PyPI](https://img.shields.io/pypi/v/pyezvizapi)](https://pypi.org/project/pyezvizapi/)
[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20me%20a%20coffee-renierm-yellow?logo=buymeacoffee)](https://www.buymeacoffee.com/renierm)

An unofficial Python client and command-line tool for EZVIZ device inventory,
status and controls, channel-99 push notifications, and local/cloud media.

## Install and get started

Requires Python **3.12 or newer**.

```bash
python -m pip install pyezvizapi
pyezvizapi --help
```

Follow [Getting started](https://github.com/RenierM26/pyEzvizApi/blob/main/docs/getting-started.md) to sign in, list your
devices, and reuse a private token file. It also lists optional image and
streaming dependencies.

**The linked guides track `main` and may describe unreleased changes.** If you
installed from PyPI, use the docs at your installed version's
[release tag](https://github.com/RenierM26/pyEzvizApi/releases). See the [changelog](https://github.com/RenierM26/pyEzvizApi/blob/main/CHANGELOG.md)
for changes and upgrade notes.

## Where to go next

- [Python API](https://github.com/RenierM26/pyEzvizApi/blob/main/docs/python-api.md) — authenticate, persist tokens, poll typed device state, and find control and media APIs.
- [CLI guide](https://github.com/RenierM26/pyEzvizApi/blob/main/docs/cli.md) — list devices, inspect recordings, and control supported cameras.
- [Media guide](https://github.com/RenierM26/pyEzvizApi/blob/main/docs/media.md) — choose a path for live streams, images, and recordings.
- [Home Assistant](https://github.com/RenierM26/pyEzvizApi/blob/main/docs/home-assistant.md) — check what each integration supports.
  Installing the library does not upgrade or migrate an integration.
- [Documentation index](https://github.com/RenierM26/pyEzvizApi/blob/main/docs/README.md) — find device-specific guides, push
  migration instructions, developer references, and historical validation.

Device controls and media support depend on model, firmware, region, and
account permissions. An accepted API request does not prove that a physical
action completed.

## Development and support

[Contributing](https://github.com/RenierM26/pyEzvizApi/blob/main/CONTRIBUTING.md) · [Support](https://github.com/RenierM26/pyEzvizApi/blob/main/SUPPORT.md) ·
[Security](https://github.com/RenierM26/pyEzvizApi/blob/main/SECURITY.md) · [Apache-2.0 license](https://github.com/RenierM26/pyEzvizApi/blob/main/LICENSE)
