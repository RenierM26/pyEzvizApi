"""Only HA-required compatibility imports survive; canonical modules import cold."""
import importlib
import json
import pickle

import pytest

from tests._paths import ROOT

MODULE_MAP = json.loads((ROOT / "docs/module-map.json").read_text())["legacy_to_implementation"]


@pytest.mark.parametrize(("legacy", "canonical"), MODULE_MAP.items())
def test_ha_compatibility_exports_have_canonical_identity(legacy, canonical):
    old = importlib.import_module(f"pyezvizapi.{legacy}")
    new = importlib.import_module(f"pyezvizapi.{canonical}")
    assert set(old.__all__) == set(CONTRACT["imports"][f"pyezvizapi.{legacy}"])
    for name in old.__all__:
        assert getattr(old, name) is getattr(new, name)


CONTRACT = json.loads((ROOT / "docs/ha-compatibility.json").read_text())


@pytest.mark.parametrize(("module", "names"), CONTRACT["imports"].items())
def test_pinned_ha_consumer_imports_resolve(module, names):
    owner = importlib.import_module(module)
    for name in names:
        assert getattr(owner, name) is not None


@pytest.mark.parametrize("module", CONTRACT["removed_modules"])
def test_unused_flat_compatibility_modules_are_not_shipped(module):
    assert not (ROOT / "pyezvizapi" / f"{module}.py").exists()
    assert importlib.util.find_spec(f"pyezvizapi.{module}") is None


@pytest.mark.parametrize(
    ("module", "name"),
    [
        ("pyezvizapi.streaming.local.hcnetsdk.protocol", "HcNetSdkTime"),
        ("pyezvizapi.streaming.local.hcnetsdk.api", "EzvizLanPictureConfig"),
        ("pyezvizapi.devices.camera", "EzvizCamera"),
        ("pyezvizapi.streaming.media.models", "CaptureLimits"),
    ],
)
def test_canonical_classes_remain_pickleable(module, name):
    current = getattr(importlib.import_module(module), name)
    assert pickle.loads(pickle.dumps(current)) is current


COLD_IMPORTS = sorted(
    ".".join(path.relative_to(ROOT).with_suffix("").parts)
    for path in (ROOT / "pyezvizapi").rglob("*.py")
    if path.parent != ROOT / "pyezvizapi" and path.name != "__init__.py"
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
