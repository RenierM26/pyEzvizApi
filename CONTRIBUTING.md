# Contributing

Thanks for helping improve `pyEzvizApi`.

This project is used directly by Home Assistant integrations, so small, well-tested changes are easier to review and safer to release.

## Development setup

```bash
python -m pip install -U pip wheel
python -m pip install -e .[dev]
```

## Local validation

Before opening a pull request, run the same checks used by CI:

```bash
ruff check .
mypy --install-types --non-interactive .
pytest --cov=pyezvizapi --cov-report=term-missing --cov-report=xml --cov-fail-under=85
python -m build
twine check dist/*
python -m pip check
```

If you only need a quick test loop while developing, `pytest -q` is fine, but run the full validation before submitting.

## Test expectations

Tests should be offline by default. Do not add tests that require:

- EZVIZ usernames, passwords, MFA codes, tokens, or cookies
- real cameras, plugs, bulbs, or account devices
- EZVIZ cloud calls or other live network access
- private RTSP URLs, LAN IPs, or hostnames

Prefer fixtures, fakes, and small request-builder/status-parser tests. Redact any payload samples before committing them.

## Home Assistant compatibility

Before changing public method names, status keys, auth exceptions, MQTT behavior, or device-control semantics, read [`docs/home-assistant-contract.md`](docs/home-assistant-contract.md).

If a change could affect Home Assistant core EZVIZ or the `ha-ezviz` custom integration, call that out in the PR body and include compatibility-focused tests where practical.

## Cleanup before commit

Remove generated artifacts before committing:

```bash
rm -rf dist build *.egg-info .coverage coverage.xml .pytest_cache .mypy_cache .ruff_cache
find . -type d -name __pycache__ -prune -exec rm -rf {} +
```

Keep PRs focused. A small bug fix, helper test, or documentation improvement is better than a broad mixed change.
