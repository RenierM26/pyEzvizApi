"""Legacy aliases, mutation hooks and pickle paths survive the package migration."""
import importlib
import json
import pickle

import pytest

from tests._paths import ROOT

MODULE_MAP = json.loads((ROOT / "docs/module-map.json").read_text())["legacy_to_implementation"]


@pytest.mark.parametrize(("legacy", "canonical"), MODULE_MAP.items())
def test_legacy_path_is_the_canonical_module_and_patches_share_one_owner(monkeypatch, legacy, canonical):
    old = importlib.import_module(f"pyezvizapi.{legacy}")
    new = importlib.import_module(f"pyezvizapi.{canonical}")
    assert old is new
    marker = object()
    monkeypatch.setattr(old, "_layout_probe", marker, raising=False)
    assert new._layout_probe is marker  # noqa: SLF001 -- deliberate alias mutation probe


@pytest.mark.parametrize(
    ("module", "name"),
    [
        ("pyezvizapi.hcnetsdk", "HcNetSdkTime"),
        ("pyezvizapi._hcnetsdk_protocol", "HcNetSdkTime"),
        ("pyezvizapi.hcnetsdk", "EzvizLanPictureConfig"),
        ("pyezvizapi.camera", "EzvizCamera"),
        ("pyezvizapi.local_stream", "EzvizLocalStreamPacket"),
        ("pyezvizapi.media", "CaptureLimits"),
    ],
)
def test_historical_pickle_global_and_new_pickle_resolve_to_the_same_class(module, name):
    current = getattr(importlib.import_module(module), name)
    legacy_pickle = f"c{module}\n{name}\n.".encode("ascii")
    assert pickle.loads(legacy_pickle) is current
    assert pickle.loads(pickle.dumps(current)) is current


COLD_IMPORTS = sorted(
    ".".join(path.relative_to(ROOT).with_suffix("").parts)
    for path in (ROOT / "pyezvizapi").rglob("*.py")
    if "as _owner_types" in path.read_text()
    or path.name.startswith("models_")
    or path.as_posix().endswith("hcnetsdk/constants.py")
)


@pytest.mark.parametrize("module_name", COLD_IMPORTS)
def test_implementation_can_be_imported_first_in_a_fresh_interpreter(tmp_path, module_name):
    """No compatibility owner may depend on a half-defined implementation."""
    import subprocess  # noqa: PLC0415 -- test-only subprocess control
    import sys  # noqa: PLC0415 -- test-only interpreter selection

    script = (
        "import importlib, sys; "
        f"sys.path.insert(0, {str(ROOT)!r}); "
        f"importlib.import_module({module_name!r})"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-c", script],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0, result.stderr
