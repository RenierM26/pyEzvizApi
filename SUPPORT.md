# Support

For questions, bugs, and feature requests, please use GitHub issues.

## Before opening an issue

Please check:

- your installed release/commit and its matching docs; main may be unreleased;
- existing open and closed issues;
- [getting started](docs/getting-started.md) and the [CLI guide](docs/cli.md);
- [`docs/home-assistant-contract.md`](docs/home-assistant-contract.md) for Home Assistant integration-facing behavior;
- [`SECURITY.md`](SECURITY.md) for vulnerability or security-sensitive reports.

Check [common problems](docs/getting-started.md#common-problems) and
[HA consumer status](docs/home-assistant.md) before treating import success or
optional-push retries as proof of complete integration compatibility.

## What to include

Good reports usually include:

- `pyEzvizApi` version or commit;
- Python version;
- EZVIZ region/endpoint if known;
- device category/model/firmware if relevant;
- whether this affects the CLI, MQTT, Home Assistant core EZVIZ, or the `ha-ezviz` custom integration;
- a minimal command, snippet, fixture, or redacted payload that reproduces the issue;
- relevant logs or tracebacks with secrets removed.

## What not to post publicly

Do not post:

- EZVIZ usernames, passwords, MFA codes, session tokens, or cookies;
- private RTSP URLs;
- private camera URLs, LAN hostnames, or IPs if they identify your home network;
- raw payloads containing account, home, camera, or location identifiers.

If a report needs sensitive details to explain safely, follow [`SECURITY.md`](SECURITY.md) instead of opening a public issue.
