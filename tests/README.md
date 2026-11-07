# Regression tests

Tests mirror library domains: `cloud`, `devices`, `push`, `streaming`, `cli`,
`shared`, and `compat`. Developer/qualification scripts are under `tools`.

Run all tests with `python -m pytest`, or a family with
`python -m pytest tests/cloud`. Fixtures stay in `fixtures/`. Use `ROOT`,
`FIXTURES` and `test_path()` from `tests._paths` rather than assuming a test's
parent directory. Existing synthetic/offline controls remain offline.
