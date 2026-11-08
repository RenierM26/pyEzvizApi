# Releases and versioning

[Documentation index](README.md) · [Contributing](../CONTRIBUTING.md)

## Source state is not a published release

`main` can contain unreleased work even when `pyproject.toml` still has the last
published version. A merged PR, green CI, a local wheel or a validation ZIP does
not publish PyPI artifacts or update a Home Assistant dependency pin.

Historical releases use PEP 440-compatible four-component versions such as
`1.0.5.0`. The prepared **2.0.0** release begins three-component major/minor/patch
numbering; see [its upgrade notes](release-2.0.0.md). Treat import removals,
auth/push migrations and status-contract changes as breaking changes regardless
of the numeric spelling. Document them before selecting the next release version.

## Prepare, review, publish

These steps publish externally only when a maintainer deliberately runs them.

1. Review current main and [Unreleased](../CHANGELOG.md#unreleased), including
   removed aliases, channel-99 migration and downstream HA acceptance. Confirm
   the exact release commit's required checks and the separate CodeQL quality gate.
2. Set `project.version` in `pyproject.toml` to the intended **new** version.
   Keep one exact `## Unreleased` heading until release preparation.
3. Run **Prepare Release** with the bare matching version (no leading `v`).
   It moves that section into a dated `## v<version> - YYYY-MM-DD` entry and
   opens a changelog PR. A manually prepared version/changelog/migration PR
   (such as #298 for 2.0.0) replaces this step; do not create a duplicate.
   Review and merge the preparation PR; no PyPI upload occurs here.
   Run **Release Check** on merged main with the proposed `release-tag`
   (for example `v2.0.0`) and inspect its checked distributions before publication.
4. Run **Upload Python Package** manually with the same bare version. It rejects
   reused tags/releases, validates metadata, builds and smoke-tests distributions,
   publishes through trusted publishing, and creates the matching GitHub tag/release.
   The tag is `v<version>`. Do not use an existing version or bypass safeguards.
5. Verify the actual published distribution in a clean environment and coordinate
   HA/custom-integration dependency pins separately. Read the
   [HA status and migration gaps](home-assistant.md) before recommending an upgrade.

The publish workflow also supports the repository's `release: published`
trigger; do not run both paths for the same version as independent publish attempts.
See the [prepare workflow](../.github/workflows/prepare-release.yml) and
[publish workflow](../.github/workflows/python-publish.yml) for authoritative inputs.

## Local package validation (no publishing)

```bash
python -m build
twine check dist/*
```

Use a clean build output directory when inspecting the intended wheel. Do not
reuse an old artifact just because its version text matches. Record the source
commit and wheel hash for consumer qualification. See
[development setup](../CONTRIBUTING.md) for checks and optional HA environments.
