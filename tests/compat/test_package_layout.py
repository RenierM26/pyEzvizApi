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
