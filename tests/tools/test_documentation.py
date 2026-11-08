"""Regression controls for documentation drift, with no example execution."""

import importlib.util
from pathlib import Path

from tests._paths import ROOT

spec = importlib.util.spec_from_file_location(
    "check_documentation", ROOT / "tools/check_documentation.py"
)
assert spec is not None and spec.loader is not None
documentation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(documentation)
check = documentation.check


def test_rejects_old_readme_global_flag_placement_and_duplicate_unreleased(tmp_path: Path):
    (tmp_path / "README.md").write_text("```bash\npyezvizapi devices status --json\n```\n")
    (tmp_path / "CHANGELOG.md").write_text(
        "## Unreleased — compatibility cleanup\n\n## Unreleased\n"
    )
    errors, _, _ = check(tmp_path, cli=True)
    assert any("arguments rejected" in error for error in errors)
    assert any("one exact" in error for error in errors)


def test_checks_local_file_and_duplicate_heading_fragments_without_parsing_code(tmp_path: Path):
    (tmp_path / "README.md").write_text(
        "# Guide\n## Same\n## Same\n[ok](#same-1)\n[bad](#same-2)\n"
        "[missing](missing.md)\n"
        "[absolute ok](https://github.com/RenierM26/pyEzvizApi/blob/main/README.md#same-1)\n"
        "[absolute missing](https://github.com/RenierM26/pyEzvizApi/blob/main/gone.md)\n"
        "```python\nitem[0](not_a_link)\n```\n"
    )
    errors, _, _ = check(tmp_path, cli=False)
    assert len(errors) == 3
    assert any("missing target missing.md" in error for error in errors)
    assert any("missing heading #same-2" in error for error in errors)


def test_parses_multiline_control_example_but_never_executes_it(tmp_path: Path, monkeypatch):
    from pyezvizapi import client  # noqa: PLC0415

    def forbidden(*args, **kwargs):
        raise AssertionError("Documentation check must not construct a client")

    monkeypatch.setattr(client, "EzvizClient", forbidden)
    (tmp_path / "README.md").write_text(
        "```bash\npyezvizapi --token-file secret.json camera \\\n"
        " --serial CAMERA_SERIAL unlock-door\n```\n"
    )
    errors, _, commands = check(tmp_path, cli=True)
    assert not errors
    assert commands == 1
