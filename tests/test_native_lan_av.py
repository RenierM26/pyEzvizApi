"""Protocol-specific defaults and received clear AV preservation."""

from __future__ import annotations

import io
import subprocess
from types import SimpleNamespace
from typing import Any

import pytest

from pyezvizapi import EzvizClient, _local_stream
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


def test_native_clear_capture_does_not_run_whole_clip_suffix_decode(monkeypatch: Any) -> None:
    descriptor = b"\x42\x0e" + b"\0" * 11 + (6000 << 1).to_bytes(3, "big")
    metadata = b"\x90\x70\0\0" + b"\0" * 4 + b"\x55\x66\x77\x88\0\x02\0\x04" + descriptor
    video = b"\x80\xe0\0\x01\0\0\x23\x28\x55\x66\x77\x88\x65\x80frame"

    def forbidden_legacy_decode(*_args: Any, **_kwargs: Any) -> Any:
        pytest.fail("Native timing must not decode/trim the full capture with a fixed ten-second budget")

    def remux(_path: str, **options: Any) -> subprocess.Popen[bytes]:
        assert options["input_format"] == "mpeg"
        assert options["preserve_timestamps"] is True
        return subprocess.Popen(["cat"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    class Stream:
        def iter_packets(self, **_kwargs: Any) -> Any:
            return iter([SimpleNamespace(body=metadata), SimpleNamespace(body=video)])

    monkeypatch.setattr(_local_stream, "_idmx_local_packets_to_annexb_with_codec", forbidden_legacy_decode)
    monkeypatch.setattr(_local_stream, "open_mpegts_remux_process", remux)
    output = io.BytesIO()
    _local_stream.copy_local_stream_to_mpegts(Stream(), output, max_packets=2)
    frame_payload = b"\x65\x80frame"
    assert frame_payload in output.getvalue()


def test_native_wrapper_uses_advertised_fractional_period_once_per_picture() -> None:
    units = (b"\x67parameters", b"\x68parameters", b"\x65\x80slice", b"\x65\x40slice2", b"\x41\x80next")
    # Wrapper ticks advance by one, not the standard 90 kHz clock.
    assert _local_stream._native_wrapper_video_timestamps(units, [10, 10, 10, 10, 11], "h264", "30000/1001") == [0, 0, 0, 0, 3003]  # noqa: SLF001
