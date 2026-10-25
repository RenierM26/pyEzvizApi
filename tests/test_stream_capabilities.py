"""Fleet isolation, evidence separation, privacy and CLI preflight contracts."""

from dataclasses import replace
import json
from pathlib import Path

import pytest
from test_local_stream_details import ABILITY, config_bytes, wire  # noqa: F401

from pyezvizapi import capabilities_cli, stream_capabilities as capabilities
from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.hcnetsdk import (
    HcNetSdkLanEndpoint,
    HcNetSdkLoginCandidate,
    HcNetSdkStreamDetails,
    discover_hcnetsdk_stream_details_for_login,
    ezviz_lan_audio_video_compress_info,
    ezviz_lan_compression_config,
)
from pyezvizapi.stream_capabilities import (
    StreamCapabilityTarget,
    StreamSampleEvidence,
    probe_stream_capabilities,
)


def target(alias="camera-a", channel=2):
    return StreamCapabilityTarget(
        alias,
        HcNetSdkLanEndpoint("PRIVATE-SERIAL", "192.0.2.10"),
        HcNetSdkLoginCandidate("admin", "private-password", 8000, "NET_DVR_Login_V30"),
        channel,
    )


def details():
    return HcNetSdkStreamDetails(
        2,
        ezviz_lan_compression_config(config_bytes()),
        ezviz_lan_audio_video_compress_info(ABILITY),
        "PRIVATE-RETURNED-SERIAL",
    )


def test_inventory_preserves_resolution_associations_and_removes_identity(monkeypatch):
    calls = []

    def query(endpoint, login, **kwargs):
        calls.append((endpoint, login, kwargs))
        return details()

    monkeypatch.setattr(capabilities, "discover_hcnetsdk_stream_details_for_login", query)
    report = probe_stream_capabilities([target()], timeout=3)
    entry = report["targets"][0]
    assert entry["metadata_status"] == "advertised"
    assert entry["samples"] == [] and entry["ha_verified"] is False
    assert report["live_acquisition"] is False
    resolutions = entry["configuration"]["capabilities"]["video_channels"][0]["main_stream"][
        "resolutions"
    ]
    assert [(r["width"], r["frame_rate_codes"], r["bitrate_min"]) for r in resolutions] == [
        (1920, (14, 17), 32),
        (1280, (17,), 64),
    ]
    assert entry["configuration"]["main_configured_media"]["width"] == 1920
    assert entry["advertised_codecs"]["video"][0]["choices"] == [
        {"native_code": 1, "codec": "h264"},
        {"native_code": 10, "codec": "hevc"},
    ]
    assert len(calls) == 1
    assert calls[0][2] == {"channel": 2, "timeout": 3, "tls_context": None}
    serialized = json.dumps(report)
    for private in ("PRIVATE", "192.0.2.10", "private-password", "admin"):
        assert private not in serialized
        assert private not in repr(target())


def test_fleet_uses_existing_bounded_native_wire_queries(monkeypatch, request):
    wire_session = request.getfixturevalue("wire")

    def query(endpoint, login, **kwargs):
        return discover_hcnetsdk_stream_details_for_login(
            endpoint,
            login,
            socket_factory=wire_session.factory,
            rsa_key=wire_session.key,
            monotonic=lambda: wire_session.clock[0],
            **kwargs,
        )

    monkeypatch.setattr(capabilities, "discover_hcnetsdk_stream_details_for_login", query)
    result = probe_stream_capabilities([target()])
    assert result["targets"][0]["metadata_status"] == "advertised"
    assert len(wire_session.calls) == 3  # One login, GET1040, ability8. No preview.
    assert all(sock.closed for sock in wire_session.sockets)


def test_failed_camera_does_not_hide_fleet_or_saved_sample(monkeypatch):
    calls = []

    def query(endpoint, login, **kwargs):
        calls.append(kwargs["channel"])
        if kwargs["channel"] == 1:
            raise PyEzvizError("private-password at PRIVATE-SERIAL 192.0.2.10")
        return replace(details(), capabilities_error=23)

    monkeypatch.setattr(capabilities, "discover_hcnetsdk_stream_details_for_login", query)
    monkeypatch.setattr(
        capabilities, "inspect_media_sample", lambda *_a, **_kw: {"status": "observed"}
    )
    report = probe_stream_capabilities(
        [target(channel=1), target(channel=2)],
        samples=[StreamSampleEvidence("camera-a", 1, "unknown", b"clear-sample")],
    )
    first, second = report["targets"]
    assert calls == [1, 2]
    assert first["metadata_status"] == "unknown" and first["error_type"] == "PyEzvizError"
    assert first["samples"] == [
        {"profile": "unknown", "association": "caller_supplied", "status": "observed"}
    ]
    assert second["metadata_status"] == "configured"
    assert second["configuration"]["capabilities_error"] == 23
    assert "private-password" not in json.dumps(report)


@pytest.mark.parametrize("timeout", [0, -1, float("inf"), float("nan"), True, 31])
def test_invalid_timeout_precedes_network(monkeypatch, timeout):
    monkeypatch.setattr(
        capabilities,
        "discover_hcnetsdk_stream_details_for_login",
        lambda *_a, **_kw: pytest.fail("network"),
    )
    with pytest.raises(ValueError):
        probe_stream_capabilities([target()], timeout=timeout)


@pytest.mark.parametrize(
    "samples",
    [
        [StreamSampleEvidence("unknown", 2, "main", b"x")],
        [StreamSampleEvidence("camera-a", 2, "main", b"x")] * 2,
        [StreamSampleEvidence("camera-a", 2, "sub", b"")],
    ],
)
def test_invalid_sample_precedes_network(monkeypatch, samples):
    monkeypatch.setattr(
        capabilities,
        "discover_hcnetsdk_stream_details_for_login",
        lambda *_a, **_kw: pytest.fail("network"),
    )
    with pytest.raises(ValueError):
        probe_stream_capabilities([target()], samples=samples)


@pytest.mark.parametrize("targets", [[], [target()] * 2, [target()] * 65])
def test_invalid_fleet_precedes_network(targets):
    with pytest.raises(ValueError):
        probe_stream_capabilities(targets)


def test_batch_byte_budget_precedes_network(monkeypatch):
    monkeypatch.setattr(capabilities, "MAX_FLEET_SAMPLE_BYTES", 4)
    with pytest.raises(ValueError, match="64 MiB"):
        probe_stream_capabilities(
            [target()], samples=[StreamSampleEvidence("camera-a", 2, "main", b"12345")]
        )


def test_advertised_audio_namespace_unknown_and_non_enumerated_ids(monkeypatch):
    ability = ABILITY.replace(b"1,10", b"1,10,999,1~3").replace(
        b"</AudioVideoCompressInfo>",
        b"<AudioCompressInfo><Audio><ChannelList><ChannelEntry><ChannelNumber>2</ChannelNumber>"
        b"<MainAudioEncodeType><Range>1,7</Range></MainAudioEncodeType>"
        b"<SubAudioEncodeType><Range>G.711</Range></SubAudioEncodeType>"
        b"</ChannelEntry></ChannelList></Audio></AudioCompressInfo></AudioVideoCompressInfo>",
    )
    snapshot = replace(details(), capabilities=ezviz_lan_audio_video_compress_info(ability))
    monkeypatch.setattr(
        capabilities, "discover_hcnetsdk_stream_details_for_login", lambda *_a, **_kw: snapshot
    )
    offers = probe_stream_capabilities([target()])["targets"][0]["advertised_codecs"]
    assert offers["video"][0]["choices"][-2] == {"native_code": 999, "codec": None}
    assert offers["video"][0]["choices"][-1] == {
        "native_code": None,
        "codec": None,
        "advertised_value": "1~3",
    }
    assert offers["audio"][0]["main"] == [
        {"native_code": 1, "codec": "pcm_mulaw"},
        {"native_code": 7, "codec": "aac"},
    ]
    assert offers["audio"][0]["sub"] == [
        {"native_code": None, "codec": None, "advertised_value": "G.711"}
    ]


@pytest.mark.parametrize("channel", [True, 0, 256, 1.5])
def test_invalid_configuration_channels(channel):
    with pytest.raises(ValueError):
        target(channel=channel)
    with pytest.raises(ValueError):
        StreamSampleEvidence("camera-a", channel, "main", b"x")


@pytest.mark.parametrize(
    "changes",
    [
        {"port": 0},
        {"port": True},
        {"api": "guess"},
        {"https": True},
        {"https": "false"},
        {"password": ""},
    ],
)
def test_explicit_login_preflight(changes):
    with pytest.raises(ValueError):
        replace(target(), login=replace(target().login, **changes))


def test_keyboard_interrupt_propagates(monkeypatch):
    def interrupted(*_a, **_kw):
        raise KeyboardInterrupt

    monkeypatch.setattr(capabilities, "discover_hcnetsdk_stream_details_for_login", interrupted)
    with pytest.raises(KeyboardInterrupt):
        probe_stream_capabilities([target()])


def inventory(tmp_path: Path) -> Path:
    path = tmp_path / "inventory.json"
    path.write_text(
        json.dumps(
            [
                {
                    "alias": "camera-a",
                    "serial": "PRIVATE-SERIAL",
                    "host": "192.0.2.10",
                    "channel": 2,
                    "login": {
                        "username": "admin",
                        "password_env": "TEST_CAMERA_PASSWORD",
                        "port": 8000,
                        "api": "NET_DVR_Login_V30",
                        "https": False,
                    },
                    "samples": [{"path": "saved.ps", "profile": "unknown"}],
                }
            ]
        )
    )
    (tmp_path / "saved.ps").write_bytes(b"saved-clear-media")
    return path


def test_cli_reads_explicit_env_secret_and_relative_sample(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("TEST_CAMERA_PASSWORD", "never-print-this")
    monkeypatch.setattr(
        capabilities, "discover_hcnetsdk_stream_details_for_login", lambda *_a, **_kw: details()
    )
    monkeypatch.setattr(
        capabilities, "inspect_media_sample", lambda *_a, **_kw: {"status": "unknown"}
    )
    assert capabilities_cli.main([str(inventory(tmp_path))]) == 0
    output = capsys.readouterr()
    assert not output.err
    assert json.loads(output.out)["targets"][0]["metadata_status"] == "advertised"
    assert "never-print-this" not in output.out
    assert "PRIVATE-SERIAL" not in output.out


def test_cli_preflight_failure_redacts_missing_environment_variable(monkeypatch, tmp_path, capsys):
    monkeypatch.delenv("TEST_CAMERA_PASSWORD", raising=False)
    assert capabilities_cli.main([str(inventory(tmp_path))]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert json.loads(output.err) == {"status": "invalid_inventory", "error_type": "KeyError"}


def test_cli_failed_metadata_exit_status(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("TEST_CAMERA_PASSWORD", "private-password")

    def rejected(*_a, **_kw):
        raise ConnectionError("192.0.2.10")

    monkeypatch.setattr(capabilities, "discover_hcnetsdk_stream_details_for_login", rejected)
    assert capabilities_cli.main([str(inventory(tmp_path))]) == 1
    assert "192.0.2.10" not in capsys.readouterr().out
