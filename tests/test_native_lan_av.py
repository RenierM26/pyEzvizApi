"""Protocol-specific defaults and received clear AV preservation."""

from __future__ import annotations

import io
from typing import Any

import pytest

from pyezvizapi import EzvizClient
from pyezvizapi.hcnetsdk import HcNetSdkLanEndpoint
from pyezvizapi.local_stream_transport import (
    HcNetSdkCommandPortGeneratedMultiSocketPlan,
    hcnetsdk_command_port_native_lan_live_view_plan,
)


@pytest.mark.parametrize(("native", "override", "expected"), [(True, None, 8000), (True, 8001, 8001), (False, None, None)])
def test_only_builtin_native_plan_selects_its_protocol_port(monkeypatch: Any, native: bool, override: int | None, expected: int | None) -> None:
    client = EzvizClient()
    ports: list[int | None] = []

    def endpoint(_serial: str, *, host: str | None, command_port: int | None) -> HcNetSdkLanEndpoint:
        ports.append(command_port)
        return HcNetSdkLanEndpoint("TESTCAM", "192.0.2.10", command_port=command_port or 9010)

    def stop_before_network(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("endpoint captured")

    monkeypatch.setattr(client, "_hcnetsdk_command_port_endpoint", endpoint)
    monkeypatch.setattr(client, "_open_hcnetsdk_command_port_clip_stream", stop_before_network)
    plan = hcnetsdk_command_port_native_lan_live_view_plan() if native else HcNetSdkCommandPortGeneratedMultiSocketPlan(())
    with pytest.raises(RuntimeError, match="endpoint captured"):
        client.save_clip("TESTCAM", io.BytesIO(), source="hcnetsdk-command-port", output_format="mpegts",
            duration_seconds=20, command_port=override, hcnetsdk_command_generated_plan=plan,
            hcnetsdk_command_password="synthetic-password")
    assert ports == [expected]
