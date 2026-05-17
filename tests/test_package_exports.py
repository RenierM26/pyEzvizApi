from __future__ import annotations

import pyezvizapi


def test_package_all_exports_resolve() -> None:
    missing = []
    for name in pyezvizapi.__all__:
        try:
            getattr(pyezvizapi, name)
        except AttributeError:
            missing.append(name)

    assert missing == []


def test_dir_includes_lazy_exports() -> None:
    exported = set(pyezvizapi.__all__)
    visible = set(dir(pyezvizapi))

    assert exported <= visible
