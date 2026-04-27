# Support

For questions, bugs, and feature requests, please use GitHub issues.

## Before opening an issue

Please check:

- the latest release and current `main` branch behavior;
- existing open and closed issues;
- [`README.md`](README.md) for CLI examples and development notes;
- [`docs/home-assistant-contract.md`](docs/home-assistant-contract.md) for Home Assistant integration-facing behavior;
- [`SECURITY.md`](SECURITY.md) for vulnerability or security-sensitive reports.

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
