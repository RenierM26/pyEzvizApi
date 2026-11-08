# Getting started

[Documentation index](README.md)

## Choose a release or a source checkout

The library requires Python 3.12+. Current `main` includes unreleased changes;
its package version alone does not identify a development checkout. Record
`git rev-parse HEAD` as well as `python -m pip show pyezvizapi` when reporting it.
For a released installation, read the docs at the matching GitHub tag.

```bash
python -m venv .venv
# POSIX shells; Windows PowerShell: .venv\Scripts\Activate.ps1
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install pyezvizapi
```

To work on current main instead:

```bash
git clone https://github.com/RenierM26/pyEzvizApi.git
cd pyEzvizApi
python -m pip install -e '.[dev,streaming]'
```

Declare dependencies through the project metadata, not a hand-maintained list of
requests/Paho/crypto packages. The `streaming` extra adds PyAV 19.x. FFmpeg and
FFprobe are system dependencies for the paths that invoke them; see [media](media.md).

## CLI login and status

```bash
pyezvizapi -u YOUR_USERNAME -p YOUR_PASSWORD --save-token devices status
pyezvizapi --token-file ezviz_token.json --json devices status
pyezvizapi --token-file ezviz_token.json --json device_infos --serial CAMERA_SERIAL
```

Global flags precede the command. Credentials in arguments can appear in shell
history and process listings; do not use real credentials in shared examples.
The first command may request an MFA code interactively. Python applications
should handle `EzvizAuthVerificationCode`; see [Python usage](python-api.md).

## Token and region rules

- The default token file is `ezviz_token.json` in the current working directory.
  Use an explicit private path for scheduled jobs so their working directory
  does not select a different account accidentally.
- A loaded token containing `session_id` takes precedence over supplied
  username/password. Use a distinct token-file path for an intentional fresh
  login; do not overwrite a working MFA/elevated token casually.
- `--save-token` enables ordinary CLI token persistence. `mqtt` always installs
  durable persistence; channel-99 tokens also persist rotation on other commands
  without `--save-token`.
- CLI token writes are atomic and owner-only where supported. Protect the parent
  directory and use appropriate host permissions/ACLs; exported tokens contain secrets.
- The default region is `apiieu.ezvizlife.com`. Set `-r/--region` before the command
  for your account's API host when needed. A saved token retains its own API
  routing; a region flag is not an account migration tool.
- Push migration requires account credentials/MFA, the complete persisted token
  and host-consistent `FEATURE_CODE`; see [channel-99](channel99.md).

## Common problems

| Symptom | Check |
| --- | --- |
| `unrecognized arguments: --json` | Move global options before the command |
| `Provide --token-file ... or --username/--password` | Correct token path, current directory and credentials |
| Existing token still used after changing credentials | Loaded session-token precedence; choose a different private token path |
| Auth expiry or MFA request | Preserve the error category; reauthenticate or request MFA, rather than retrying blindly |
| Push asks for `enable_channel99()` | Legacy profile must migrate; polling can remain available |
| Push asks for `on_token_updated` | Install a synchronous durable whole-token save callback |
| Removed module import fails | Use the [canonical replacement](ha-compatibility.md), not a new shim |
| FFmpeg/PyAV missing | Install only the dependencies required by the selected [media path](media.md) |

Raw pagelist/device-info output and debug logs can identify accounts and cameras.
Redact before posting a [support report](../SUPPORT.md).
