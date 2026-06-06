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


def test_command_port_helpers_are_runtime_exports() -> None:
    expected = {
        "HcNetSdkCommandPortClient",
        "HcNetSdkCommandPortExchange",
        "HcNetSdkCommandPortMediaStream",
        "HcNetSdkCommandPortStreamBootstrap",
        "open_hcnetsdk_command_port_stream",
        "read_hcnetsdk_command_port_interleaved_frame_after_prefix",
        "read_hcnetsdk_tcp_frame",
    }

    assert expected <= set(pyezvizapi.__all__)
    for name in expected:
        assert getattr(pyezvizapi, name) is not None


def test_dir_includes_lazy_exports() -> None:
    exported = set(pyezvizapi.__all__)
    visible = set(dir(pyezvizapi))

    assert exported <= visible
