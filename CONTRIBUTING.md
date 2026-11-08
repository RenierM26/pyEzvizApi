# Contributing

Use small, reviewable changes and offline regression evidence. Start with the
[code map](docs/code-map.md), [documentation index](docs/README.md) and
[HA contract](docs/home-assistant-contract.md) when changing public behavior.

## Development environment

The library supports Python 3.12+. Use a fresh virtual environment at the
repository root and install project metadata rather than a partial dependency list.

```bash
python -m venv .venv
. .venv/bin/activate
# Windows PowerShell activation: .venv\Scripts\Activate.ps1
python -m pip install --upgrade pip wheel
python -m pip install -e '.[dev,streaming]'
```

The `streaming` extra installs PyAV. Install FFmpeg/FFprobe separately for media
controls. Platform-specific player/Android tooling is not part of ordinary
library development; use its specialist guide only when working on that path.

## Local validation

```bash
ruff check .
ruff format --check pyezvizapi
codespell pyezvizapi tests README.md pyproject.toml .github --skip tests/fixtures/page_list_response.json
pip-audit --progress-spinner off
mypy --install-types --non-interactive .
pyright pyezvizapi
python -m pytest --cov=pyezvizapi --cov-report=term-missing --cov-report=xml --cov-fail-under=85
python tools/check_documentation.py
python -m build
twine check dist/*
python -m pip check
```

`python -m pytest tests/push -q` is an example quick loop; the default collection
is under `tests/`. Run affected controls plus the full required checks before
submitting behavior changes. Use `ruff format pyezvizapi` for the package's
100-character style. Lint and format checks are separate.

CI definitions in [.github/workflows/ci.yaml](.github/workflows/ci.yaml) remain
authoritative for matrix versions and checks. CodeQL analysis and the separate
CodeQL quality gate are distinct results; known protocol constraints are
[documented individually](docs/codeql-triage.md), not a reason to disable a rule.

## Real HA acceptance (separate environment)

Use Python 3.14 and a separate environment so HA's dependency pins do not change
the ordinary library runtime:

```bash
python3.14 -m venv /tmp/ezviz-ha-tests
/tmp/ezviz-ha-tests/bin/pip install -e . -r examples/ha_ezviz/requirements-test.txt
/tmp/ezviz-ha-tests/bin/python -m pytest examples/home_assistant/tests -o asyncio_mode=auto
/tmp/ezviz-ha-tests/bin/python -m mypy --config-file examples/home_assistant/mypy.ini examples/home_assistant/custom_components/ezviz_native
```

For the **actual custom cloud consumer**, additionally follow the pinned-checkout
instructions in [examples/ha_ezviz](examples/ha_ezviz/README.md). Its FFmpeg
integration dependency must be declared explicitly; the bare HA wheel does not
install every platform's requirements. Keep real startup-precondition checks
separate from tests with a stubbed broker or FFmpeg process.

## Regression and documentation expectations

- Tests must not require accounts, MFA codes, physical cameras, cloud access or
  private endpoints. Use synthetic fixtures, loopback-only controls and fakes.
- Document new imports/CLI flags beside their canonical owner. Validate examples
  offline; never execute control/media commands against real devices as a docs check.
- State whether a guide is current user guidance, a development-only workflow,
  or pinned historical evidence. Keep research records accessible without making
  them the installation path. Add new guides to [the index](docs/README.md).
- Call out changes to imports, client methods, status keys, auth categories,
  token persistence and push lifetimes; an import probe is not full HA acceptance.
- Do not embed credentials or real payload identifiers in code, logs or screenshots.

## Before opening a PR

Inspect `git status --short` and `git diff --check`. Stage only intended files;
do not bulk-delete every cache/build directory or untracked file in a shared
checkout. Use a disposable environment/build directory for clean packaging.
Do not commit generated credentials, captures, local environments or build output.

Use the PR template to report scope, commands actually run, results, skipped
controls and unverified live behavior. Merge, release and deployment are separate
from preparing a PR; see the [release procedure](docs/releases.md).
