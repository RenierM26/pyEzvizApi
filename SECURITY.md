# Security Policy

## Reporting a vulnerability

Please do **not** open a public issue with secrets or sensitive camera details.

If you believe you found a security problem in `pyEzvizApi`, open a private security advisory on GitHub if available, or contact the maintainer privately before posting details publicly.

Include enough information to reproduce or understand the issue, but redact:

- EZVIZ usernames, passwords, MFA codes, session tokens, and cookies
- camera serial numbers if you consider them private
- private RTSP URLs, LAN IPs, and hostnames
- raw payload fields that identify your home, cameras, or account

## Supported versions

Security fixes are expected to target the latest released version and the current `main` branch.

## Safe reproduction notes

Whenever possible, provide an offline reproduction using fixtures, mocked responses, or redacted payloads. Avoid test cases that require real EZVIZ credentials, cameras, cloud calls, or live network access.

For Home Assistant or custom integration compatibility concerns, note the integration and version involved, and describe whether the behavior affects authentication, MQTT push handling, status payloads, or device controls.

## Vendor protocol constraints

Some camera wire formats require legacy MD5/AES-ECB operations. They are not
password-storage recommendations or suitable primitives for new application
crypto. The [per-alert CodeQL ledger](docs/codeql-triage.md) records accepted
interoperability constraints separately from false positives and test fixtures.
A dismissed alert is not a repaired cryptographic weakness. Queries and quality
gates remain enabled; new findings require their own review.
