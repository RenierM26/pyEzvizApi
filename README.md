# Ezviz PyPi

![Upload Python Package](https://github.com/RenierM26/pyEzvizApi/workflows/Upload%20Python%20Package/badge.svg)

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
pip install requests paho-mqtt pycryptodome pandas
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
python config/custom_components/ezviz_cloud/pyezvizapi/test_mqtt.py --token-file ezviz_token.json

# Interactive login, then save token for next time
python config/custom_components/ezviz_cloud/pyezvizapi/test_mqtt.py --save-token

# Explicit credentials (not recommended for shared terminals)
python config/custom_components/ezviz_cloud/pyezvizapi/test_mqtt.py -u USER -p PASS --save-token
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
python -c "from config.custom_components.ezviz_cloud.pyezvizapi.test_cam_rtsp import TestRTSPAuth as T; T('<IP>', '<USER>', '<PASS>', '/Streaming/Channels/101').main()"
```

On success, the script prints a confirmation. On failure it raises one of:

- `InvalidHost`: Hostname/IP or port issue
- `AuthTestResultFailed`: Invalid credentials

## Development

Please format with Ruff and check typing with mypy.

```bash
ruff check .
mypy config/custom_components/ezviz_cloud/pyezvizapi
```

Run style fixes where possible:

```bash
ruff check --fix config/custom_components/ezviz_cloud/pyezvizapi
```

Run tests with tox:

```bash
tox
```

## Side Notes

There is no official API documentation. Much of this is based on reverse-engineering the Ezviz mobile app (Android/iOS). Some regions operate on separate endpoints; US example: `apiius.ezvizlife.com`.

Example:

```bash
pyezvizapi -u username@domain.com -p PASS@123 -r apius.ezvizlife.com devices status
```

For advanced troubleshooting or new feature research, MITM proxy tools like mitmproxy/Charles/Fiddler can be used to inspect traffic from the app (see community guides for SSL unpinning and WSA usage).

## Contributing

Contributions are welcome — the API surface is large and there are many improvements possible.

## Versioning

We follow SemVer when publishing the library. See repository tags for released versions.

## License

Apache 2.0 — see `LICENSE.md`.

---

Draft versions: 0.0.x