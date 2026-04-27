## Summary

- 

## Validation

Please check the commands that were run locally:

- [ ] `ruff check .`
- [ ] `codespell pyezvizapi tests README.md pyproject.toml .github`
- [ ] `pip-audit --progress-spinner off`
- [ ] `mypy --install-types --non-interactive .`
- [ ] `pyright pyezvizapi`
- [ ] `pytest --cov=pyezvizapi --cov-report=term-missing --cov-report=xml --cov-fail-under=85`
- [ ] `python -m build`
- [ ] `twine check dist/*`
- [ ] `python -m pip check`

## Compatibility

- [ ] Tests are offline and do not require EZVIZ credentials, real cameras, cloud calls, or live network access.
- [ ] Home Assistant / custom integration behavior is preserved, or the intended compatibility impact is described above.
- [ ] Generated artifacts were removed before commit (`dist`, `build`, `*.egg-info`, caches, coverage files).
