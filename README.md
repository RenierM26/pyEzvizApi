# Ezviz PyPi

![Upload Python Package](https://github.com/RenierM26/pyEzvizApi/workflows/Upload%20Python%20Package/badge.svg)
[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20me%20a%20coffee-renierm-yellow?logo=buymeacoffee)](https://www.buymeacoffee.com/renierm)

## Overview

Pilot your Ezviz cameras (and light bulbs) with this module. It is used by:

- The official Ezviz integration in Home Assistant
- The EZVIZ (Beta) custom integration for Home Assistant

You can also use it directly from the command line for quick checks and scripting.

## Features

- Inspect device and connection status in table or JSON form
- Control cameras: PTZ, privacy/sleep/audio/IR/state LEDs, alarm settings
- Control light bulbs: toggle, status, brightness and color temperature
- Dump raw pagelist and device infos JSON for exploration/debugging
- Reuse a saved session token (no credentials needed after first login)

## Install

From PyPI:

```bash
pip install pyezvizapi
```

After installation, a `pyezvizapi` command is available on your PATH.

### Dependencies (development/local usage)

If you are running from a clone of this repository or using the helper scripts directly, ensure these packages are available:

```bash
pip install requests paho-mqtt pycryptodome
```

## Quick Start

```bash
# See available commands and options
pyezvizapi --help

# First-time login and save token for reuse
pyezvizapi -u YOUR_EZVIZ_USERNAME -p YOUR_EZVIZ_PASSWORD --save-token devices status

# Subsequent runs can reuse the saved token (no credentials needed)
pyezvizapi devices status --json
```

## CLI Authentication

- Username/password: `-u/--username` and `-p/--password`
- Token file: `--token-file` (defaults to `ezviz_token.json` in the current directory)
- Save token: `--save-token` writes the current token after login
- MFA: The CLI prompts for a code if required by your account
- Region: `-r/--region` overrides the default region (`apiieu.ezvizlife.com`)

Examples:

```bash
# First-time login and save token locally
pyezvizapi -u YOUR_EZVIZ_USERNAME -p YOUR_EZVIZ_PASSWORD --save-token devices status

# Reuse saved token (no credentials)
pyezvizapi devices status --json
```

## Output Modes

- Default: human-readable tables (for list/status views)
- JSON: add `--json` for easy parsing and editor-friendly exploration

## CLI Commands

All commands are subcommands of the module runner:

```bash
pyezvizapi <command> [options]
```

### devices

- Actions: `device`, `status`, `switch`, `connection`
- Examples:

```bash
# Table view
pyezvizapi devices status

# JSON view
pyezvizapi devices status --json
```

Sample table columns include:

```
name | status | device_category | device_sub_category | sleep | privacy | audio | ir_led | state_led | local_ip | local_rtsp_port | battery_level | alarm_schedules_enabled | alarm_notify | Motion_Trigger
```

The CLI also computes a `switch_flags` map for each device (all switch states by name, e.g. `privacy`, `sleep`, `sound`, `infrared_light`, `light`, etc.).

### stream

Experimental VTM cloud stream helpers. Packet tracing prints sanitized metadata only. Dumping writes VLC-friendly MPEG-TS by default using FFmpeg `-c copy` remuxing only, with `--format raw` available for unchanged VTM payloads. Encrypted packets fail unless `--allow-encrypted` is set. Some battery cameras keep the VTM channel unencrypted but encrypt the video NAL payloads inside MPEG-PS; use `--decrypt-video` to decrypt those HEVC/H.264 NAL payloads with the camera encrypt key before writing or remuxing.

```bash
# Inspect stream packet metadata without printing media bytes
pyezvizapi stream trace --serial ABC123 --channel 1 --max-packets 20 --json-lines

# Dump a VLC-playable MPEG-TS capture to a file
pyezvizapi stream dump --serial ABC123 --channel 1 --duration 1m --output stream.ts

# Decrypt encrypted battery-camera HEVC video while dumping
pyezvizapi stream dump --serial ABC123 --channel 1 --duration 30s --decrypt-video --output stream.ts

# Pipe raw MPEG-PS payloads directly into FFmpeg and remux to MPEG-TS
pyezvizapi stream dump --serial ABC123 --channel 1 --format raw | \
  ffmpeg -f mpeg -i pipe:0 -c copy -f mpegts stream.ts

# Serve a local MPEG-TS URL for Home Assistant/FFmpeg clients
pyezvizapi stream proxy --serial ABC123 --channel 1 --listen-port 8558

# Serve a decrypted local MPEG-TS URL for encrypted battery cameras
pyezvizapi stream proxy --serial ABC123 --channel 1 --decrypt-video --listen-port 8558
```

The dump command captures one minute by default. Use `--duration 30s`, `--duration 2min`, or `--duration 0` for unlimited capture; `--max-packets` can still be used as an additional stop limit. MPEG-TS output requires FFmpeg and remuxes the camera payload with codec copy only; it does not transcode video or audio. The proxy serves `http://<host>:8558/<serial>.ts` by default. Each HTTP client opens a fresh VTM stream and remuxes it through FFmpeg. Keep the proxy bound to loopback unless you put it behind an authenticated reverse proxy or otherwise restrict access; the stream URL is not authenticated by `pyezvizapi`.

### cloud_videos

Fetch cloud clip descriptors used by the EZVIZ app download path. The returned metadata can include `seqId`, `storageVersion`, `fileSize`, `crypt`, `keyChecksum`, and the native SDK `streamUrl` host/port.

```bash
# List recent cloud clips
pyezvizapi cloud_videos --serial ABC123 --channel 1 --limit 10

# Hydrate details and emit JSON for further investigation
pyezvizapi --json cloud_videos --serial ABC123 --channel 1 --limit 5 --details

# Download a cloud clip. Direct HTTP(S) URLs are saved as-is; native streamUrl
# clips are fetched through the pure-Python cloud replay protocol and decrypted.
pyezvizapi cloud_video_download --serial ABC123 --channel 1 --seq-id 12345 \
  --output clip.ps --encrypted-output clip.tmp

# Drive the native EZVIZ app SDK path through ADB + Frida when only streamUrl is exposed
pyezvizapi cloud_video_native_download --serial ABC123 --channel 1 --seq-id 12345 \
  --output clip.ps --encrypted-output clip.tmp --adb-serial 192.168.1.56:41653

# Decrypt a previously captured native .tmp file locally in Python
pyezvizapi cloud_video_decrypt --serial ABC123 --input clip.tmp --output clip.ps
```

Some cloud clips only expose the EZVIZ native SDK `streamUrl` host/port in `videoDetails`. For regular cloud-storage clips, `cloud_video_download` now fetches `/v3/cameras/ticketInfo`, downloads the encrypted cloud replay `.tmp` stream over TLS, and applies the local Python PS/NAL decrypt transform. `--encrypted-output` keeps the encrypted `.tmp` for comparison.

`cloud_video_native_download` remains as an investigation bridge for comparing against the Android SDK. It requires a gadget-loaded EZVIZ Android app reachable by ADB and Frida, fetches `/v3/cameras/ticketInfo` plus the camera verification key through `pyezvizapi`, then asks the app to run `EZStreamClient.startDownloadFromCloud(...)`. By default it pulls the encrypted `.tmp` and runs the PS/NAL decrypt locally in Python; use `--transform native` to fall back to Android `TransformUtils.trans(...)`.

`cloud_video_decrypt` is the pure-Python transform step for native cloud `.tmp` files. Prefer `--serial` so `pyezvizapi` fetches the camera encrypt key without putting it in shell history; `--key` is available for offline/manual experiments.

### sdcard_videos

Fetch SD-card playback record descriptors using the same record-list endpoints exposed by the EZVIZ app.

```bash
# List recent SD-card playback records
pyezvizapi sdcard_videos --serial ABC123 --channel 1 \
  --start-time "2026-05-10T21:50:00" --stop-time "2026-05-10T21:55:00"

# Try the app's common/intelligent record endpoints when the default v2 path is empty
pyezvizapi --json sdcard_videos --serial ABC123 --source common \
  --start-time "2026-05-10T21:50:00" --stop-time "2026-05-10T21:55:00"
```

SD-card records are descriptors for native playback/download. The public API does not currently expose a direct HTTP media URL for every record; use `stream dump` for live VTM capture or `cloud_video_download` when cloud `videoDetails` includes an HTTP(S) URL.

### camera

Requires `--serial`.

- Actions: `status`, `move`, `move_coords`, `unlock-door`, `unlock-gate`, `switch`, `alarm`, `select`
- Examples:

```bash
# Camera status
pyezvizapi camera --serial ABC123 status

# PTZ move
pyezvizapi camera --serial ABC123 move --direction up --speed 5

# Move by coordinates
pyezvizapi camera --serial ABC123 move_coords --x 0.4 --y 0.6

# Switch setters
pyezvizapi camera --serial ABC123 switch --switch privacy --enable 1

# Alarm settings (push notify, sound level, do-not-disturb)
pyezvizapi camera --serial ABC123 alarm --notify 1 --sound 2 --do_not_disturb 0

# Battery camera work mode
pyezvizapi camera --serial ABC123 select --battery_work_mode POWER_SAVE
```

### devices_light

- Actions: `status`
- Example:

```bash
pyezvizapi devices_light status
```

### home_defence_mode

Set global defence mode for the account/home.

```bash
pyezvizapi home_defence_mode --mode HOME_MODE
```

### mqtt

Connect to Ezviz MQTT push notifications using the current session token. Use `--debug` to see connection details.

```bash
pyezvizapi mqtt
```

#### MQTT push test script (standalone)

For quick experimentation, a small helper script is included which can use a saved token file or prompt for credentials with MFA and save the session token:

```bash
# With a previously saved token file
python examples/mqtt_listener.py --token-file ezviz_token.json

# Interactive login, then save token for next time
python examples/mqtt_listener.py --save-token

# Explicit credentials (not recommended for shared terminals)
python examples/mqtt_listener.py -u USER -p PASS --save-token
```

### pagelist

Dump the complete raw pagelist JSON. Great for exploring unknown fields in an editor (e.g. Notepad++).

```bash
pyezvizapi pagelist > pagelist.json
```

### device_infos

Dump the processed device infos mapping (what the integration consumes). Optionally filter to one serial:

```bash
# All devices
pyezvizapi device_infos > device_infos.json

# Single device
pyezvizapi device_infos --serial ABC123 > ABC123.json
```

## Remote door and gate unlock (CS-HPD7)

```bash
pyezvizapi camera --serial BAXXXXXXX-BAYYYYYYY unlock-door
pyezvizapi camera --serial BAXXXXXXX-BAYYYYYYY unlock-gate
```

## RTSP authentication test (Basic → Digest)

Validate RTSP credentials by issuing a DESCRIBE request. Falls back from Basic to Digest auth automatically.

```bash
python examples/rtsp_auth_test.py <IP> <USER> <PASS> --uri /Streaming/Channels/101
```

On success, the script prints a confirmation. On failure it raises one of:

- `InvalidHost`: Hostname/IP or port issue
- `AuthTestResultFailed`: Invalid credentials

## Development

Install the project with development dependencies:

```bash
python -m pip install -U pip wheel
python -m pip install -e .[dev]
```

Run the same local validation used by CI:

```bash
ruff check .
codespell pyezvizapi tests README.md pyproject.toml .github
pip-audit --progress-spinner off
mypy --install-types --non-interactive .
pyright pyezvizapi
pytest --cov=pyezvizapi --cov-report=term-missing --cov-report=xml --cov-fail-under=85
python -m build
twine check dist/*
python -m pip check
```

Run style fixes where possible:

```bash
ruff check --fix .
```

Before committing, remove generated artifacts so they do not leak into PRs:

```bash
rm -rf dist build *.egg-info .coverage coverage.xml .pytest_cache .mypy_cache .ruff_cache
find . -type d -name __pycache__ -prune -exec rm -rf {} +
```

Tests should be offline by default. Do not add tests that require EZVIZ credentials,
real cameras, cloud calls, or live network access. Prefer small fixtures and fakes for
request builders, status parsing, MQTT payload handling, and Home Assistant integration
contracts.

## Side Notes

There is no official API documentation. Much of this is based on reverse-engineering the Ezviz mobile app (Android/iOS). Some regions operate on separate endpoints; US example: `apiius.ezvizlife.com`.

Example:

```bash
pyezvizapi -u username@domain.com -p PASS@123 -r apius.ezvizlife.com devices status
```

For advanced troubleshooting or new feature research, MITM proxy tools like mitmproxy/Charles/Fiddler can be used to inspect traffic from the app (see community guides for SSL unpinning and WSA usage).

## Contributing

Contributions are welcome — the API surface is large and there are many improvements possible.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for development setup, local validation, offline-test expectations, and cleanup guidance before opening a PR.

For questions, bug reports, and feature requests, see [`SUPPORT.md`](SUPPORT.md) for what to include and what not to post publicly.

For changes that affect Home Assistant integrations, see [`docs/home-assistant-contract.md`](docs/home-assistant-contract.md) before renaming methods, changing status keys, or altering auth/MQTT behavior.

For vulnerability reports or security-sensitive behavior, see [`SECURITY.md`](SECURITY.md). Please do not post credentials, MFA codes, tokens, or private camera URLs in public issues.

## Versioning

We follow SemVer when publishing the library. See `CHANGELOG.md` and repository tags for released versions.

Release tags should match the package version in `pyproject.toml` using the form `v<version>` (for example, `v1.0.4.7`). The PyPI publish workflow validates this before uploading distributions.

Recommended release flow:

1. Bump `project.version` in `pyproject.toml` and update `CHANGELOG.md` under `Unreleased` during normal PR work.
2. Run **Prepare Release** with the bare version, then review and merge the generated changelog PR.
3. Run **Upload Python Package** manually with the same bare version. That workflow validates the version, builds and smoke-tests the wheel/CLI, publishes to PyPI, then creates the matching GitHub release/tag.

## License

Apache 2.0 — see `LICENSE.md`.

---

Draft versions: 0.0.x
