from __future__ import annotations

import argparse
import importlib.util
import io
import json
from pathlib import Path
import sys
from typing import Any, BinaryIO, ClassVar, cast

from cli_fakes import (
    FakeClient as _FakeClient,
    install_fake_camera as _install_fake_camera,
    install_fake_client as _install_fake_client,
    token_file as _token_file,
)

import pyezvizapi.__main__ as cli_module
from pyezvizapi.exceptions import EzvizAuthVerificationCode, PyEzvizError
from pyezvizapi.stream import VtmChannel, VtmPacket

MPEGTS_PAYLOAD = b"mpegts"
CLOUD_VIDEO_PAYLOAD = b"cloud-video-bytes"
NATIVE_ENCRYPTED_PAYLOAD = b"encrypted"
NATIVE_TRANSFORMED_PAYLOAD = b"decrypted"

_format_cell = cli_module._format_cell  # noqa: SLF001
_write_table = cli_module._write_table  # noqa: SLF001


def test_cli_imports_without_pandas_installed() -> None:
    assert importlib.util.find_spec("pandas") is None


def test_format_cell_handles_common_table_values() -> None:
    assert _format_cell(None) == ""
    assert _format_cell(True) == "True"
    assert _format_cell({"b": 2, "a": 1}) == '{"a": 1, "b": 2}'


def test_write_table_outputs_fixed_width_rows(capsys) -> None:
    _write_table(
        [
            {"serial": "ABC", "name": "Front", "online": True},
            {"serial": "XYZ", "name": None, "online": False},
        ],
        ["serial", "name", "online"],
    )

    output = capsys.readouterr().out
    assert "serial" in output
    assert "ABC" in output
    assert "Front" in output
    assert "XYZ" in output
    assert "False" in output


def test_main_requires_existing_token_or_credentials(tmp_path, caplog) -> None:
    missing_token = tmp_path / "missing-token.json"

    assert cli_module.main(["--token-file", str(missing_token), "device_infos"]) == 2

    assert "Provide --token-file" in caplog.text


def test_main_uses_existing_token_file_without_login(monkeypatch, tmp_path, capsys) -> None:
    fake_client = _install_fake_client(monkeypatch)
    token_file = tmp_path / "token.json"
    token_file.write_text(
        json.dumps({"session_id": "saved-session", "api_url": "apiieu.ezvizlife.com"}),
        encoding="utf-8",
    )

    assert (
        cli_module.main(["--token-file", str(token_file), "device_infos", "--serial", "CAM123"])
        == 0
    )

    client = fake_client.instances[0]
    assert client.account is None
    assert client.password is None
    assert client.token == {"session_id": "saved-session", "api_url": "apiieu.ezvizlife.com"}
    assert client.login_calls == []
    assert client.closed is True
    assert json.loads(capsys.readouterr().out) == {"deviceInfos": {"name": "Front"}}


def test_main_logs_in_with_credentials_and_saves_token(monkeypatch, tmp_path) -> None:
    fake_client = _install_fake_client(monkeypatch)
    token_file = tmp_path / "saved-token.json"

    assert (
        cli_module.main(
            [
                "--username",
                "user@example.test",
                "--password",
                "secret",
                "--region",
                "apiieu.ezvizlife.com",
                "--token-file",
                str(token_file),
                "--save-token",
                "device_infos",
            ]
        )
        == 0
    )

    client = fake_client.instances[0]
    assert client.login_calls == [None]
    assert client.closed is True
    assert json.loads(token_file.read_text(encoding="utf-8")) == {
        "session_id": "new-session",
        "api_url": "apiieu.ezvizlife.com",
    }


def test_main_prompts_for_mfa_code_and_retries_login(monkeypatch, tmp_path) -> None:
    class MfaClient(_FakeClient):
        def login(self, sms_code: int | None = None) -> None:
            self.login_calls.append(sms_code)
            if sms_code is None:
                raise EzvizAuthVerificationCode("MFA required")

    MfaClient.instances = []
    monkeypatch.setattr(cli_module, "EzvizClient", MfaClient)
    monkeypatch.setattr("builtins.input", lambda _prompt: "123456")
    token_file = tmp_path / "unused-token.json"

    assert (
        cli_module.main(
            [
                "--username",
                "user@example.test",
                "--password",
                "secret",
                "--token-file",
                str(token_file),
                "device_infos",
            ]
        )
        == 0
    )

    client = MfaClient.instances[0]
    assert client.login_calls == [None, 123456]
    assert client.closed is True


def test_unifiedmsg_json_outputs_messages(monkeypatch, tmp_path, capsys) -> None:
    class UnifiedClient(_FakeClient):
        def get_device_messages_list(
            self,
            *,
            serials: str | None = None,
            limit: int = 20,
            date: str | None = None,
            end_time: str = "",
        ) -> dict[str, Any]:
            self.request = {
                "serials": serials,
                "limit": limit,
                "date": date,
                "end_time": end_time,
            }
            return {
                "message": [
                    {
                        "deviceSerial": "CAM123",
                        "timeStr": "2026-04-27 08:00:00",
                        "subType": "motion",
                        "title": "Motion detected",
                    }
                ]
            }

    UnifiedClient.instances = []
    monkeypatch.setattr(cli_module, "EzvizClient", UnifiedClient)
    token_file = tmp_path / "token.json"
    token_file.write_text(json.dumps({"session_id": "saved"}), encoding="utf-8")

    assert (
        cli_module.main(
            [
                "--token-file",
                str(token_file),
                "--json",
                "unifiedmsg",
                "--serials",
                "CAM123",
                "--limit",
                "5",
                "--date",
                "20260427",
                "--end-time",
                "cursor-1",
            ]
        )
        == 0
    )

    client = cast(UnifiedClient, UnifiedClient.instances[0])
    assert client.request == {
        "serials": "CAM123",
        "limit": 5,
        "date": "20260427",
        "end_time": "cursor-1",
    }
    assert json.loads(capsys.readouterr().out) == [
        {
            "deviceSerial": "CAM123",
            "timeStr": "2026-04-27 08:00:00",
            "subType": "motion",
            "title": "Motion detected",
        }
    ]


def test_unifiedmsg_urls_only_extracts_media_urls(monkeypatch, tmp_path, capsys) -> None:
    class UnifiedClient(_FakeClient):
        def get_device_messages_list(self, **_kwargs: Any) -> dict[str, Any]:
            return {
                "messages": [
                    {"deviceSerial": "CAM1", "pic": "https://example.test/pic.jpg"},
                    {
                        "deviceSerial": "CAM2",
                        "defaultPic": "https://example.test/default.jpg",
                    },
                    {
                        "deviceSerial": "CAM3",
                        "ext": {
                            "pics": "https://example.test/first.jpg;https://example.test/second.jpg"
                        },
                    },
                    {"deviceSerial": "CAM4"},
                    "not-a-message",
                ]
            }

    UnifiedClient.instances = []
    monkeypatch.setattr(cli_module, "EzvizClient", UnifiedClient)
    token_file = tmp_path / "token.json"
    token_file.write_text(json.dumps({"session_id": "saved"}), encoding="utf-8")

    assert cli_module.main(["--token-file", str(token_file), "unifiedmsg", "--urls-only"]) == 0

    assert capsys.readouterr().out.splitlines() == [
        "CAM1: https://example.test/pic.jpg",
        "CAM2: https://example.test/default.jpg",
        "CAM3: https://example.test/first.jpg",
    ]


def test_cloud_videos_json_fetches_details(monkeypatch, tmp_path, capsys) -> None:
    fake_client = _install_fake_client(monkeypatch)
    token_file = tmp_path / "token.json"
    token_file.write_text(json.dumps({"session_id": "saved"}), encoding="utf-8")

    assert (
        cli_module.main(
            [
                "--token-file",
                str(token_file),
                "--json",
                "cloud_videos",
                "--serial",
                "CAM123",
                "--channel",
                "2",
                "--limit",
                "5",
                "--video-type",
                "-1",
                "--support-multi-channel-shared-service",
                "1",
                "--details",
            ]
        )
        == 0
    )

    client = fake_client.instances[0]
    assert client.cloud_videos_request == {
        "serial": "CAM123",
        "channel": 2,
        "limit": 5,
        "video_type": -1,
        "support_multi_channel_shared_service": 1,
        "max_retries": 0,
    }
    assert client.cloud_video_details_request["serial"] == "CAM123"
    assert client.cloud_video_details_request["support_multi_channel_shared_service"] == 1
    assert json.loads(capsys.readouterr().out)[0]["seqId"] == 12345


def test_sdcard_videos_json_uses_v2_endpoint(monkeypatch, tmp_path, capsys) -> None:
    fake_client = _install_fake_client(monkeypatch)
    token_file = tmp_path / "token.json"
    token_file.write_text(json.dumps({"session_id": "saved"}), encoding="utf-8")

    assert (
        cli_module.main(
            [
                "--token-file",
                str(token_file),
                "--json",
                "sdcard_videos",
                "--serial",
                "CAM123",
                "--channel",
                "2",
                "--start-time",
                "2026-05-10T21:50:00",
                "--stop-time",
                "2026-05-10T21:51:00",
                "--size",
                "5",
                "--sort-by",
                "1",
                "--require-label",
                "1",
            ]
        )
        == 0
    )

    client = fake_client.instances[0]
    assert client.sdcard_videos_request == {
        "source": "v2",
        "serial": "CAM123",
        "channel": 2,
        "start_time": "2026-05-10T21:50:00",
        "stop_time": "2026-05-10T21:51:00",
        "size": 5,
        "sort_by": 1,
        "require_label": 1,
        "max_retries": 0,
    }
    assert json.loads(capsys.readouterr().out)[0]["path"] == "/sd/record/clip.ps"


def test_sdcard_videos_common_passes_channel_serial(monkeypatch, tmp_path) -> None:
    fake_client = _install_fake_client(monkeypatch)
    token_file = tmp_path / "token.json"
    token_file.write_text(json.dumps({"session_id": "saved"}), encoding="utf-8")

    assert (
        cli_module.main(
            [
                "--token-file",
                str(token_file),
                "sdcard_videos",
                "--serial",
                "CAM123",
                "--source",
                "common",
                "--channel-serial",
                "CHAN123",
                "--start-time",
                "2026-05-10T21:50:00",
                "--stop-time",
                "2026-05-10T21:51:00",
                "--record-type",
                "2",
                "--version",
                "3",
            ]
        )
        == 0
    )

    assert fake_client.instances[0].sdcard_videos_request == {
        "source": "common",
        "serial": "CAM123",
        "channel": 1,
        "start_time": "2026-05-10T21:50:00",
        "stop_time": "2026-05-10T21:51:00",
        "channel_serial": "CHAN123",
        "record_type": 2,
        "size": 20,
        "version": 3,
        "max_retries": 0,
    }


def test_first_record_list_decodes_ezviz_compressed_records() -> None:
    payload = {
        "records": (
            "eJyLrubi5FRyUrLiVDIyMDLTNTDVNbAMMTK0MjWwMjBQ0gHJumKXNYfIhlQWpAIV"
            "GIA5QanFIMVKMI4RmMfFWRsLAPZWE10="
        )
    }

    assert cli_module._first_record_list(payload) == [  # noqa: SLF001
        {
            "B": "2026-05-09T21:50:00",
            "E": "2026-05-09T21:50:07",
            "Type": 0,
            "Res": "",
            "Res2": "",
        }
    ]


def test_cloud_videos_table_output(monkeypatch, tmp_path, capsys) -> None:
    _install_fake_client(monkeypatch)
    token_file = tmp_path / "token.json"
    token_file.write_text(json.dumps({"session_id": "saved"}), encoding="utf-8")

    assert (
        cli_module.main(
            [
                "--token-file",
                str(token_file),
                "cloud_videos",
                "--serial",
                "CAM123",
            ]
        )
        == 0
    )

    output = capsys.readouterr().out
    assert "seqId" in output
    assert "12345" in output
    assert "streamUrl" in output


def test_cloud_video_download_writes_selected_clip(monkeypatch, tmp_path, capsys) -> None:
    fake_client = _install_fake_client(monkeypatch)
    token_file = tmp_path / "token.json"
    token_file.write_text(json.dumps({"session_id": "saved"}), encoding="utf-8")
    output = tmp_path / "downloads" / "clip.ps"

    assert (
        cli_module.main(
            [
                "--token-file",
                str(token_file),
                "--json",
                "cloud_video_download",
                "--serial",
                "CAM123",
                "--channel",
                "2",
                "--seq-id",
                "12345",
                "--output",
                str(output),
                "--support-multi-channel-shared-service",
                "1",
            ]
        )
        == 0
    )

    client = fake_client.instances[0]
    assert output.read_bytes() == CLOUD_VIDEO_PAYLOAD
    assert client.cloud_video_details_request["videos"][0]["seqId"] == 12345
    assert client.cloud_video_download_request["video"]["seqId"] == 12345
    assert json.loads(capsys.readouterr().out) == {
        "bytes": 17,
        "encrypted_output": None,
        "output": str(output),
        "seqId": 12345,
        "transform": "direct",
    }


def test_cloud_video_download_handles_native_stream_url(
    monkeypatch,
    tmp_path,
    capsys,
) -> None:
    fake_client = _install_fake_client(monkeypatch)
    token_file = tmp_path / "token.json"
    token_file.write_text(json.dumps({"session_id": "saved"}), encoding="utf-8")
    output = tmp_path / "downloads" / "clip.ps"
    encrypted_output = tmp_path / "downloads" / "clip.tmp"
    replay_calls: list[dict[str, Any]] = []
    decrypt_calls: list[dict[str, Any]] = []

    def fake_direct_download(self: _FakeClient, video: dict[str, Any], **_: Any) -> bytes:
        self.cloud_video_download_request = {"video": video}
        raise PyEzvizError("native streamUrl requires cloud replay protocol")

    def fake_replay(**kwargs: Any) -> bytes:
        replay_calls.append(kwargs)
        return NATIVE_ENCRYPTED_PAYLOAD

    def fake_decrypt(data: bytes, key: str) -> bytes:
        decrypt_calls.append({"data": data, "key": key})
        return NATIVE_TRANSFORMED_PAYLOAD

    monkeypatch.setattr(_FakeClient, "download_cloud_video", fake_direct_download)
    monkeypatch.setattr(cli_module, "download_ezviz_cloud_replay", fake_replay)
    monkeypatch.setattr(cli_module, "decrypt_hikvision_ps_video", fake_decrypt)

    assert (
        cli_module.main(
            [
                "--token-file",
                str(token_file),
                "--json",
                "cloud_video_download",
                "--serial",
                "CAM123",
                "--channel",
                "2",
                "--seq-id",
                "12345",
                "--output",
                str(output),
                "--encrypted-output",
                str(encrypted_output),
                "--timeout",
                "12",
            ]
        )
        == 0
    )

    client = fake_client.instances[0]
    assert output.read_bytes() == NATIVE_TRANSFORMED_PAYLOAD
    assert encrypted_output.read_bytes() == NATIVE_ENCRYPTED_PAYLOAD
    assert client.camera_ticket_info_request["serial"] == "CAM123"
    assert client.cam_key_request == {"serial": "CAM123", "max_retries": 1}
    assert replay_calls == [
        {
            "stream_url": "hweustreamer.ezvizlife.com:32723",
            "ticket": "ticket-value",
            "serial": "CAM123",
            "channel": 2,
            "seq_id": 12345,
            "begin_cas": "20260509T215000Z",
            "end_cas": "20260509T215010Z",
            "storage_version": 2,
            "video_type": 2,
            "file_size": len(NATIVE_ENCRYPTED_PAYLOAD),
            "timeout": 12,
        }
    ]
    assert decrypt_calls == [{"data": NATIVE_ENCRYPTED_PAYLOAD, "key": "camera-secret"}]
    assert json.loads(capsys.readouterr().out) == {
        "bytes": len(NATIVE_TRANSFORMED_PAYLOAD),
        "encrypted_output": str(encrypted_output),
        "output": str(output),
        "seqId": 12345,
        "transform": "cloud_replay_python",
    }


def test_cloud_video_native_download_drives_adb_and_frida(
    monkeypatch,
    tmp_path,
    capsys,
) -> None:
    fake_client = _install_fake_client(monkeypatch)
    token_file = tmp_path / "token.json"
    token_file.write_text(json.dumps({"session_id": "saved"}), encoding="utf-8")
    output = tmp_path / "downloads" / "clip.ps"
    encrypted_output = tmp_path / "downloads" / "clip.tmp"
    pushed_payloads: list[dict[str, Any]] = []
    commands: list[list[str]] = []
    decrypt_calls: list[dict[str, Any]] = []

    def fake_run(
        command: list[str],
        *,
        check: bool,
        capture_output: bool,
        text: bool,
        timeout: float,
    ) -> cli_module.subprocess.CompletedProcess[str]:
        commands.append(command)
        assert check is True
        assert capture_output is True
        assert text is True
        assert timeout > 0

        if command[0] == "adb" and "push" in command:
            pushed_payloads.append(json.loads(Path(command[-2]).read_text(encoding="utf-8")))
        if command[0] == "adb" and "pull" in command:
            destination = Path(command[-1])
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(
                NATIVE_ENCRYPTED_PAYLOAD
                if destination.suffix == ".tmp"
                else NATIVE_TRANSFORMED_PAYLOAD
            )
        return cli_module.subprocess.CompletedProcess(command, 0, "", "")

    def fake_decrypt(data: bytes, key: str) -> bytes:
        decrypt_calls.append({"data": data, "key": key})
        return NATIVE_TRANSFORMED_PAYLOAD

    monkeypatch.setattr(cli_module.subprocess, "run", fake_run)
    monkeypatch.setattr(cli_module, "decrypt_hikvision_ps_video", fake_decrypt)

    assert (
        cli_module.main(
            [
                "--token-file",
                str(token_file),
                "--json",
                "cloud_video_native_download",
                "--serial",
                "CAM123",
                "--channel",
                "2",
                "--seq-id",
                "12345",
                "--output",
                str(output),
                "--encrypted-output",
                str(encrypted_output),
                "--adb-serial",
                "adb-1",
                "--frida-host",
                "127.0.0.1:27046",
                "--support-multi-channel-shared-service",
                "1",
                "--output-name",
                "unit-output",
            ]
        )
        == 0
    )

    client = fake_client.instances[0]
    assert client.camera_ticket_info_request == {
        "serial": "CAM123",
        "channel": 2,
        "support_multi_channel_shared_service": 1,
        "max_retries": 0,
    }
    assert client.cam_key_request == {"serial": "CAM123", "max_retries": 1}
    assert output.read_bytes() == NATIVE_TRANSFORMED_PAYLOAD
    assert encrypted_output.read_bytes() == NATIVE_ENCRYPTED_PAYLOAD
    assert decrypt_calls == [{"data": NATIVE_ENCRYPTED_PAYLOAD, "key": "camera-secret"}]
    assert len(pushed_payloads) == 1
    assert pushed_payloads[0]["ticket"] == "ticket-value"
    assert "secretKey" not in pushed_payloads[0]

    frida_commands = [command for command in commands if command[0] == "frida"]
    assert len(frida_commands) == 1
    assert all("-H" in command and "127.0.0.1:27046" in command for command in frida_commands)
    assert any(command[:4] == ["adb", "-s", "adb-1", "push"] for command in commands)
    assert any(command[:4] == ["adb", "-s", "adb-1", "pull"] for command in commands)

    assert json.loads(capsys.readouterr().out) == {
        "encrypted_output": str(encrypted_output),
        "output": str(output),
        "secretKey": "<redacted>",
        "seqId": 12345,
        "streamUrl": "hweustreamer.ezvizlife.com:32723",
        "ticket": "<redacted>",
        "transform": "python",
    }


def test_cloud_video_decrypt_uses_camera_key(monkeypatch, tmp_path, capsys) -> None:
    fake_client = _install_fake_client(monkeypatch)
    token_file = tmp_path / "token.json"
    token_file.write_text(json.dumps({"session_id": "saved"}), encoding="utf-8")
    input_path = tmp_path / "clip.tmp"
    output_path = tmp_path / "clip.ps"
    input_path.write_bytes(NATIVE_ENCRYPTED_PAYLOAD)
    decrypt_calls: list[dict[str, Any]] = []

    def fake_decrypt(data: bytes, key: str) -> bytes:
        decrypt_calls.append({"data": data, "key": key})
        return NATIVE_TRANSFORMED_PAYLOAD

    monkeypatch.setattr(cli_module, "decrypt_hikvision_ps_video", fake_decrypt)

    assert (
        cli_module.main(
            [
                "--token-file",
                str(token_file),
                "--json",
                "cloud_video_decrypt",
                "--input",
                str(input_path),
                "--output",
                str(output_path),
                "--serial",
                "CAM123",
            ]
        )
        == 0
    )

    client = fake_client.instances[0]
    assert client.cam_key_request == {"serial": "CAM123", "max_retries": 1}
    assert decrypt_calls == [{"data": NATIVE_ENCRYPTED_PAYLOAD, "key": "camera-secret"}]
    assert output_path.read_bytes() == NATIVE_TRANSFORMED_PAYLOAD
    assert json.loads(capsys.readouterr().out) == {
        "bytes": len(NATIVE_TRANSFORMED_PAYLOAD),
        "input": str(input_path),
        "output": str(output_path),
    }


def test_cloud_video_decrypt_can_use_explicit_key_without_login(
    monkeypatch,
    tmp_path,
    capsys,
) -> None:
    input_path = tmp_path / "clip.tmp"
    output_path = tmp_path / "clip.ps"
    input_path.write_bytes(NATIVE_ENCRYPTED_PAYLOAD)
    decrypt_calls: list[dict[str, Any]] = []

    def fake_decrypt(data: bytes, key: str) -> bytes:
        decrypt_calls.append({"data": data, "key": key})
        return NATIVE_TRANSFORMED_PAYLOAD

    monkeypatch.setattr(cli_module, "decrypt_hikvision_ps_video", fake_decrypt)

    assert (
        cli_module.main(
            [
                "--json",
                "cloud_video_decrypt",
                "--input",
                str(input_path),
                "--output",
                str(output_path),
                "--key",
                "manual-key",
            ]
        )
        == 0
    )

    assert decrypt_calls == [{"data": NATIVE_ENCRYPTED_PAYLOAD, "key": "manual-key"}]
    assert output_path.read_bytes() == NATIVE_TRANSFORMED_PAYLOAD
    assert json.loads(capsys.readouterr().out)["bytes"] == len(NATIVE_TRANSFORMED_PAYLOAD)


def test_cloud_video_decrypt_rejects_missing_key(monkeypatch, tmp_path) -> None:
    _install_fake_client(monkeypatch)
    token_file = tmp_path / "token.json"
    token_file.write_text(json.dumps({"session_id": "saved"}), encoding="utf-8")
    input_path = tmp_path / "clip.tmp"
    output_path = tmp_path / "clip.ps"
    input_path.write_bytes(NATIVE_ENCRYPTED_PAYLOAD)

    assert (
        cli_module.main(
            [
                "--token-file",
                str(token_file),
                "cloud_video_decrypt",
                "--input",
                str(input_path),
                "--output",
                str(output_path),
            ]
        )
        == 1
    )


def test_stream_trace_outputs_sanitized_json_lines(monkeypatch, tmp_path, capsys) -> None:
    fake_client = _install_fake_client(monkeypatch)

    class FakeEvent:
        def __init__(self, index: int, encrypted: bool) -> None:
            self.index = index
            self.encrypted = encrypted

        def as_dict(self) -> dict[str, Any]:
            return {
                "index": self.index,
                "channel": 11 if self.encrypted else 0,
                "channel_name": "ENCRYPTED_STREAM" if self.encrypted else "MESSAGE",
                "length": 12,
                "sequence": self.index + 7,
                "message_code": 330 if self.encrypted else 316,
                "message_name": "STREAM_VTMSTREAM_ECDH_NOTIFY"
                if self.encrypted
                else "STREAMINFO_RSP",
                "encrypted": self.encrypted,
                "transport": "UNKNOWN",
            }

    class FakeStream:
        def __init__(self) -> None:
            self.closed = False

        def __enter__(self) -> FakeStream:
            return self

        def __exit__(self, *_exc_info: object) -> None:
            self.closed = True

        def trace_packets(self, *, max_packets: int) -> list[FakeEvent]:
            assert max_packets == 2
            return [FakeEvent(0, False), FakeEvent(1, True)]

    calls: list[dict[str, Any]] = []
    fake_stream = FakeStream()

    def fake_open_cloud_stream(client: Any, serial: str, **kwargs: Any) -> FakeStream:
        calls.append({"client": client, "serial": serial, **kwargs})
        return fake_stream

    monkeypatch.setattr(cli_module, "open_cloud_stream", fake_open_cloud_stream)

    assert (
        cli_module.main(
            [
                "--token-file",
                _token_file(tmp_path),
                "stream",
                "trace",
                "--serial",
                "CAM123",
                "--channel",
                "2",
                "--max-packets",
                "2",
                "--timeout",
                "3",
                "--no-refresh-vtm",
                "--json-lines",
            ]
        )
        == 0
    )

    client = fake_client.instances[0]
    assert calls == [
        {
            "client": client,
            "serial": "CAM123",
            "channel": 2,
            "client_type": 9,
            "token_index": 0,
            "refresh_vtm": False,
            "timeout": 3.0,
        }
    ]
    assert client.closed is True
    assert fake_stream.closed is True
    output = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert output[0]["message_name"] == "STREAMINFO_RSP"
    assert output[1]["encrypted"] is True
    assert "body" not in output[1]


def test_stream_dump_writes_payload_bytes_to_file(monkeypatch, tmp_path) -> None:
    fake_client = _install_fake_client(monkeypatch)
    expected_payload = b"abcdef"

    class FakeStream:
        def __init__(self) -> None:
            self.closed = False
            self.started = False

        def __enter__(self) -> FakeStream:
            return self

        def __exit__(self, *_exc_info: object) -> None:
            self.closed = True

        def start(self) -> None:
            self.started = True

        def iter_packets(self, *, max_packets: int | None = None) -> list[VtmPacket]:
            assert self.started is True
            assert max_packets == 2
            return [
                VtmPacket(
                    channel=VtmChannel.STREAM,
                    length=3,
                    sequence=1,
                    message_code=0,
                    body=b"abc",
                ),
                VtmPacket(
                    channel=VtmChannel.STREAM,
                    length=3,
                    sequence=2,
                    message_code=0,
                    body=b"def",
                ),
            ]

    calls: list[dict[str, Any]] = []
    fake_stream = FakeStream()

    def fake_open_cloud_stream(client: Any, serial: str, **kwargs: Any) -> FakeStream:
        calls.append({"client": client, "serial": serial, **kwargs})
        return fake_stream

    monkeypatch.setattr(cli_module, "open_cloud_stream", fake_open_cloud_stream)
    output_file = tmp_path / "stream.bin"

    assert (
        cli_module.main(
            [
                "--token-file",
                _token_file(tmp_path),
                "stream",
                "dump",
                "--serial",
                "CAM123",
                "--channel",
                "2",
                "--max-packets",
                "2",
                "--timeout",
                "3",
                "--no-refresh-vtm",
                "--output",
                str(output_file),
                "--format",
                "raw",
            ]
        )
        == 0
    )

    client = fake_client.instances[0]
    assert calls == [
        {
            "client": client,
            "serial": "CAM123",
            "channel": 2,
            "client_type": 9,
            "token_index": 0,
            "refresh_vtm": False,
            "timeout": 3.0,
        }
    ]
    assert client.closed is True
    assert fake_stream.closed is True
    assert output_file.read_bytes() == expected_payload


def test_stream_dump_defaults_to_mpegts_remux(monkeypatch, tmp_path) -> None:
    _install_fake_client(monkeypatch)
    expected_payload = b"mpegts"

    class FakeStream:
        def __enter__(self) -> FakeStream:
            return self

        def __exit__(self, *_exc_info: object) -> None:
            return None

        def start(self) -> None:
            return None

    calls: list[dict[str, Any]] = []

    def fake_remux(
        stream: FakeStream,
        output: BinaryIO,
        *,
        ffmpeg_path: str,
        max_packets: int | None,
        duration_seconds: float | None,
        allow_encrypted: bool,
    ) -> None:
        calls.append(
            {
                "stream": stream,
                "ffmpeg_path": ffmpeg_path,
                "max_packets": max_packets,
                "duration_seconds": duration_seconds,
                "allow_encrypted": allow_encrypted,
            }
        )
        output.write(expected_payload)

    monkeypatch.setattr(
        cli_module,
        "open_cloud_stream",
        lambda *_args, **_kwargs: FakeStream(),
    )
    monkeypatch.setattr(cli_module, "_remux_stream_payloads_to_mpegts", fake_remux)
    output_file = tmp_path / "stream.ts"

    assert (
        cli_module.main(
            [
                "--token-file",
                _token_file(tmp_path),
                "stream",
                "dump",
                "--serial",
                "CAM123",
                "--duration",
                "2min",
                "--ffmpeg-path",
                "ffmpeg-custom",
                "--output",
                str(output_file),
            ]
        )
        == 0
    )

    assert len(calls) == 1
    assert calls[0]["ffmpeg_path"] == "ffmpeg-custom"
    assert calls[0]["max_packets"] is None
    assert calls[0]["duration_seconds"] == cli_module._parse_duration_seconds("2min")  # noqa: SLF001
    assert calls[0]["allow_encrypted"] is False
    assert output_file.read_bytes() == expected_payload


def test_stream_dump_can_decrypt_before_mpegts_remux(monkeypatch, tmp_path) -> None:
    class EncryptKeyClient(_FakeClient):
        def get_cam_key(self, serial: str, *, max_retries: int = 0) -> str:
            assert serial == "CAM123"
            assert max_retries == 1
            return "camera-key"

    _install_fake_client(monkeypatch, EncryptKeyClient)

    class FakeStream:
        def __enter__(self) -> FakeStream:
            return self

        def __exit__(self, *_exc_info: object) -> None:
            return None

        def start(self) -> None:
            return None

        def iter_packets(self, *, max_packets: int | None = None) -> list[VtmPacket]:
            assert max_packets == 1
            return [
                VtmPacket(
                    channel=VtmChannel.STREAM,
                    length=9,
                    sequence=1,
                    message_code=0,
                    body=b"encrypted",
                )
            ]

    monkeypatch.setattr(
        cli_module,
        "open_cloud_stream",
        lambda *_args, **_kwargs: FakeStream(),
    )

    decrypt_calls: list[dict[str, Any]] = []

    def fake_decrypt(data: bytes, key: str, *, nalu_header_size: int) -> bytes:
        decrypt_calls.append({"data": data, "key": key, "nalu_header_size": nalu_header_size})
        return b"decrypted"

    remux_calls: list[dict[str, Any]] = []

    def fake_remux(data: bytes, output: BinaryIO, *, ffmpeg_path: str) -> None:
        remux_calls.append({"data": data, "ffmpeg_path": ffmpeg_path})
        output.write(MPEGTS_PAYLOAD)

    monkeypatch.setattr(cli_module, "decrypt_hikvision_ps_video", fake_decrypt)
    monkeypatch.setattr(cli_module, "_remux_mpegps_bytes_to_mpegts", fake_remux)
    output_file = tmp_path / "stream.ts"

    assert (
        cli_module.main(
            [
                "--token-file",
                _token_file(tmp_path),
                "stream",
                "dump",
                "--serial",
                "CAM123",
                "--max-packets",
                "1",
                "--duration",
                "0",
                "--decrypt-video",
                "--output",
                str(output_file),
            ]
        )
        == 0
    )

    assert decrypt_calls == [{"data": b"encrypted", "key": "camera-key", "nalu_header_size": 2}]
    assert remux_calls == [{"data": b"decrypted", "ffmpeg_path": "ffmpeg"}]
    assert output_file.read_bytes() == MPEGTS_PAYLOAD


def test_parse_stream_dump_duration_units() -> None:
    cases = {
        "30": 30.0,
        "30s": 30.0,
        "1m": 60.0,
        "2min": 120.0,
    }
    for value, expected in cases.items():
        assert cli_module._parse_duration_seconds(value) == expected  # noqa: SLF001
    assert cli_module._parse_duration_seconds("0") is None  # noqa: SLF001


def test_write_stream_payloads_stops_after_duration() -> None:
    expected_payload = b"abc"

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[VtmPacket]:
            assert max_packets is None
            return [
                VtmPacket(
                    channel=VtmChannel.STREAM,
                    length=3,
                    sequence=1,
                    message_code=0,
                    body=b"abc",
                ),
                VtmPacket(
                    channel=VtmChannel.STREAM,
                    length=3,
                    sequence=2,
                    message_code=0,
                    body=b"def",
                ),
            ]

    times = iter([100.0, 100.5, 101.5])
    output = io.BytesIO()

    cli_module._write_stream_payloads(  # noqa: SLF001
        FakeStream(),
        output,
        max_packets=None,
        duration_seconds=1.0,
        allow_encrypted=False,
        monotonic=lambda: next(times),
    )

    assert output.getvalue() == expected_payload


def test_stream_dump_rejects_encrypted_packets_by_default(monkeypatch, tmp_path, caplog) -> None:
    _install_fake_client(monkeypatch)

    class FakeStream:
        def __enter__(self) -> FakeStream:
            return self

        def __exit__(self, *_exc_info: object) -> None:
            return None

        def start(self) -> None:
            return None

        def iter_packets(self, *, max_packets: int | None = None) -> list[VtmPacket]:
            return [
                VtmPacket(
                    channel=VtmChannel.ENCRYPTED_STREAM,
                    length=6,
                    sequence=1,
                    message_code=0,
                    body=b"secret",
                )
            ]

    monkeypatch.setattr(
        cli_module,
        "open_cloud_stream",
        lambda *_args, **_kwargs: FakeStream(),
    )

    assert (
        cli_module.main(
            [
                "--token-file",
                _token_file(tmp_path),
                "stream",
                "dump",
                "--serial",
                "CAM123",
                "--max-packets",
                "1",
                "--output",
                str(tmp_path / "stream.bin"),
                "--format",
                "raw",
            ]
        )
        == 1
    )

    assert "media decryption is not implemented" in caplog.text


def test_remux_stream_payloads_to_mpegts_pipes_payloads(tmp_path) -> None:
    expected_payload = b"abcdef"
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\nimport sys\nsys.stdout.buffer.write(sys.stdin.buffer.read())\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[VtmPacket]:
            assert max_packets == 2
            return [
                VtmPacket(
                    channel=VtmChannel.STREAM,
                    length=3,
                    sequence=1,
                    message_code=0,
                    body=b"abc",
                ),
                VtmPacket(
                    channel=VtmChannel.STREAM,
                    length=3,
                    sequence=2,
                    message_code=0,
                    body=b"def",
                ),
            ]

    output = io.BytesIO()

    cli_module._remux_stream_payloads_to_mpegts(  # noqa: SLF001
        FakeStream(),
        output,
        ffmpeg_path=str(fake_ffmpeg),
        max_packets=2,
        duration_seconds=None,
        allow_encrypted=False,
    )

    assert output.getvalue() == expected_payload


def test_remux_stream_payloads_to_mpegts_wraps_ffmpeg_launch_failure() -> None:
    output = io.BytesIO()

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[VtmPacket]:
            return []

    try:
        cli_module._remux_stream_payloads_to_mpegts(  # noqa: SLF001
            FakeStream(),
            output,
            ffmpeg_path="/does/not/exist/ffmpeg",
            max_packets=2,
            duration_seconds=None,
            allow_encrypted=False,
        )
    except PyEzvizError as err:
        assert "Could not launch FFmpeg" in str(err)
        assert "/does/not/exist/ffmpeg" in str(err)
    else:
        raise AssertionError("Expected PyEzvizError")


def test_stream_proxy_dispatches_blocking_proxy(monkeypatch, tmp_path) -> None:
    fake_client = _install_fake_client(monkeypatch)
    calls: list[dict[str, Any]] = []

    def fake_serve_stream_proxy(args: Any, client: _FakeClient) -> None:
        calls.append(
            {
                "client": client,
                "serial": args.serial,
                "channel": args.channel,
                "listen_host": args.listen_host,
                "listen_port": args.listen_port,
                "path": args.path,
                "ffmpeg_path": args.ffmpeg_path,
                "refresh_vtm": not args.no_refresh_vtm,
                "decrypt_video": args.decrypt_video,
                "decrypt_codec": args.decrypt_codec,
                "max_packets": args.max_packets,
            }
        )

    monkeypatch.setattr(cli_module, "_serve_stream_proxy", fake_serve_stream_proxy)

    assert (
        cli_module.main(
            [
                "--token-file",
                _token_file(tmp_path),
                "stream",
                "proxy",
                "--serial",
                "CAM123",
                "--channel",
                "2",
                "--listen-host",
                "0.0.0.0",
                "--listen-port",
                "8559",
                "--path",
                "/camera.ts",
                "--ffmpeg-path",
                sys.executable,
                "--decrypt-video",
                "--max-packets",
                "4",
                "--no-refresh-vtm",
            ]
        )
        == 0
    )

    client = fake_client.instances[0]
    assert calls == [
        {
            "client": client,
            "serial": "CAM123",
            "channel": 2,
            "listen_host": "0.0.0.0",
            "listen_port": 8559,
            "path": "/camera.ts",
            "ffmpeg_path": sys.executable,
            "refresh_vtm": False,
            "decrypt_video": True,
            "decrypt_codec": "hevc",
            "max_packets": 4,
        }
    ]
    assert client.closed is True


def test_stream_proxy_path_defaults_to_serial() -> None:
    assert cli_module._normalize_stream_proxy_path(None, "CAM123") == "/CAM123.ts"  # noqa: SLF001
    assert cli_module._normalize_stream_proxy_path("camera.ts", "CAM123") == "/camera.ts"  # noqa: SLF001


def test_stream_proxy_sends_error_when_ffmpeg_fails_before_headers(monkeypatch) -> None:
    class FakeStream:
        def __enter__(self) -> FakeStream:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def start(self) -> None:
            return None

    class FakeHandler:
        path = "/CAM123.ts"
        wfile = io.BytesIO()
        close_connection = False

        def __init__(self) -> None:
            self.responses: list[int] = []
            self.errors: list[tuple[int, str]] = []

        def send_response(self, code: int) -> None:
            self.responses.append(code)

        def send_header(self, _key: str, _value: str) -> None:
            return None

        def end_headers(self) -> None:
            return None

        def send_error(self, code: int, message: str) -> None:
            self.errors.append((code, message))

    config = cli_module.StreamProxyConfig(
        serial="CAM123",
        channel=1,
        client_type=1,
        token_index=0,
        refresh_vtm=True,
        timeout=None,
        path="/CAM123.ts",
        ffmpeg_path="/does/not/exist/ffmpeg",
        allow_encrypted=False,
        decrypt_video=False,
        decrypt_codec="hevc",
        max_packets=None,
    )

    monkeypatch.setattr(cli_module, "open_cloud_stream", lambda *_args, **_kwargs: FakeStream())
    monkeypatch.setattr(
        cli_module,
        "_open_mpegts_remux_process",
        lambda _path: (_ for _ in ()).throw(PyEzvizError("Could not launch FFmpeg")),
    )

    handler = FakeHandler()
    cli_module._handle_stream_proxy_get(cast(Any, handler), config, cast(Any, object()))  # noqa: SLF001

    assert handler.responses == []
    assert handler.errors == [(502, "Could not launch FFmpeg")]


def test_stream_proxy_can_decrypt_payloads_before_remux(monkeypatch) -> None:
    class FakeStream:
        def __enter__(self) -> FakeStream:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def start(self) -> None:
            return None

    class FakeClient:
        def get_cam_key(self, serial: str, *, max_retries: int = 0) -> str:
            assert serial == "CAM123"
            assert max_retries == 1
            return "camera-key"

    class FakeHandler:
        path = "/CAM123.ts"
        wfile = io.BytesIO()
        close_connection = False

        def __init__(self) -> None:
            self.responses: list[int] = []
            self.errors: list[tuple[int, str]] = []

        def send_response(self, code: int) -> None:
            self.responses.append(code)

        def send_header(self, _key: str, _value: str) -> None:
            return None

        def end_headers(self) -> None:
            return None

        def send_error(self, code: int, message: str) -> None:
            self.errors.append((code, message))

    config = cli_module.StreamProxyConfig(
        serial="CAM123",
        channel=1,
        client_type=1,
        token_index=0,
        refresh_vtm=True,
        timeout=None,
        path="/CAM123.ts",
        ffmpeg_path="ffmpeg",
        allow_encrypted=False,
        decrypt_video=True,
        decrypt_codec="hevc",
        max_packets=None,
    )
    decrypt_calls: list[dict[str, Any]] = []

    def fake_decrypt(data: bytes, key: str, *, nalu_header_size: int) -> bytes:
        decrypt_calls.append({"data": data, "key": key, "nalu_header_size": nalu_header_size})
        return b"decrypted"

    copy_calls: list[bytes] = []

    def fake_copy_stream_payloads_to_mpegts(*_args: Any, **kwargs: Any) -> None:
        copy_calls.append(kwargs["transform_payload"](b"encrypted"))

    monkeypatch.setattr(cli_module, "open_cloud_stream", lambda *_args, **_kwargs: FakeStream())
    monkeypatch.setattr(cli_module, "_open_mpegts_remux_process", lambda _path: object())
    monkeypatch.setattr(cli_module, "decrypt_hikvision_ps_video", fake_decrypt)
    monkeypatch.setattr(cli_module, "_copy_stream_payloads_to_mpegts", fake_copy_stream_payloads_to_mpegts)

    handler = FakeHandler()
    cli_module._handle_stream_proxy_get(cast(Any, handler), config, cast(Any, FakeClient()))  # noqa: SLF001

    assert handler.responses == [200]
    assert handler.errors == []
    assert decrypt_calls == [{"data": b"encrypted", "key": "camera-key", "nalu_header_size": 2}]
    assert copy_calls == [b"decrypted"]


def test_stream_proxy_wraps_bind_failure(monkeypatch) -> None:
    def fake_server(*_args: object, **_kwargs: object) -> None:
        raise OSError("Address already in use")

    monkeypatch.setattr(cli_module, "StreamProxyHTTPServer", fake_server)

    args = argparse.Namespace(
        serial="CAM123",
        channel=1,
        client_type=1,
        token_index=0,
        no_refresh_vtm=False,
        timeout=None,
        path=None,
        ffmpeg_path="ffmpeg",
        allow_encrypted=False,
        decrypt_video=False,
        decrypt_codec="hevc",
        max_packets=None,
        listen_host="127.0.0.1",
        listen_port=8558,
    )

    try:
        cli_module._serve_stream_proxy(args, cast(Any, object()))  # noqa: SLF001
    except PyEzvizError as err:
        message = str(err)
        assert "Could not bind stream proxy to 127.0.0.1:8558" in message
        assert "Address already in use" in message
    else:
        raise AssertionError("Expected PyEzvizError")


def test_stream_proxy_server_does_not_block_on_active_stream_threads() -> None:
    assert cli_module.StreamProxyHTTPServer.daemon_threads is True
    assert cli_module.StreamProxyHTTPServer.block_on_close is False


def test_unifiedmsg_table_output_handles_empty_response(monkeypatch, tmp_path, capsys) -> None:
    class UnifiedClient(_FakeClient):
        def get_device_messages_list(self, **_kwargs: Any) -> dict[str, Any]:
            return {"messages": []}

    UnifiedClient.instances = []
    monkeypatch.setattr(cli_module, "EzvizClient", UnifiedClient)
    token_file = tmp_path / "token.json"
    token_file.write_text(json.dumps({"session_id": "saved"}), encoding="utf-8")

    assert cli_module.main(["--token-file", str(token_file), "unifiedmsg"]) == 0

    assert capsys.readouterr().out == "No unified messages returned.\n"


def test_devices_status_table_expands_switch_flags(monkeypatch, tmp_path, capsys) -> None:
    class DevicesClient(_FakeClient):
        def load_cameras(self, *, refresh: bool = True) -> dict[str, dict[str, Any]]:
            self.refresh = refresh
            return {
                "CAM123": {
                    "name": "Front Door",
                    "status": 1,
                    "device_category": "camera",
                    "device_sub_category": "doorbell",
                    "local_ip": "192.0.2.10",
                    "local_rtsp_port": "554",
                    "battery_level": 87,
                    "alarm_schedules_enabled": True,
                    "alarm_notify": False,
                    "Motion_Trigger": True,
                    "SWITCH": [
                        {"type": 21, "enable": 1},
                        {"type": 7, "enable": 0},
                        {"type": 22, "enable": True},
                        {"type": 10, "enable": False},
                        {"type": 3, "enable": 1},
                        {"type": "ignored", "enable": 1},
                    ],
                }
            }

    DevicesClient.instances = []
    monkeypatch.setattr(cli_module, "EzvizClient", DevicesClient)
    token_file = tmp_path / "token.json"
    token_file.write_text(json.dumps({"session_id": "saved"}), encoding="utf-8")

    assert (
        cli_module.main(
            [
                "--token-file",
                str(token_file),
                "devices",
                "status",
                "--no-refresh",
            ]
        )
        == 0
    )

    client = cast(DevicesClient, DevicesClient.instances[0])
    assert client.refresh is False
    output = capsys.readouterr().out
    assert "serial" in output
    assert "CAM123" in output
    assert "Front Door" in output
    assert "doorbell" in output
    assert "192.0.2.10" in output
    assert "554" in output
    assert "87" in output
    # Legacy-friendly switch columns should be present in table output.
    assert "True" in output
    assert "False" in output


def test_devices_status_json_preserves_payload_without_table_enrichment(
    monkeypatch, tmp_path, capsys
) -> None:
    class DevicesClient(_FakeClient):
        def load_cameras(self, *, refresh: bool = True) -> dict[str, dict[str, Any]]:
            self.refresh = refresh
            return {
                "CAM123": {
                    "name": "Front Door",
                    "SWITCH": [{"type": 21, "enable": 1}],
                }
            }

    DevicesClient.instances = []
    monkeypatch.setattr(cli_module, "EzvizClient", DevicesClient)
    token_file = tmp_path / "token.json"
    token_file.write_text(json.dumps({"session_id": "saved"}), encoding="utf-8")

    assert (
        cli_module.main(
            [
                "--token-file",
                str(token_file),
                "--json",
                "devices",
                "status",
            ]
        )
        == 0
    )

    client = cast(DevicesClient, DevicesClient.instances[0])
    assert client.refresh is True
    payload = json.loads(capsys.readouterr().out)
    assert payload == {
        "CAM123": {
            "name": "Front Door",
            "SWITCH": [{"type": 21, "enable": 1}],
        }
    }
    assert "switch_flags" not in payload["CAM123"]


def test_devices_light_status_table_forwards_refresh(monkeypatch, tmp_path, capsys) -> None:
    class LightDevicesClient(_FakeClient):
        def load_light_bulbs(self, *, refresh: bool = True) -> dict[str, dict[str, Any]]:
            self.refresh = refresh
            return {
                "LIGHT123": {
                    "name": "Porch Light",
                    "status": 1,
                    "device_category": "lighting",
                    "device_sub_category": "bulb",
                    "local_ip": "192.0.2.50",
                    "productId": "prod-light",
                    "is_on": True,
                    "brightness": 66,
                    "color_temperature": 4200,
                }
            }

    LightDevicesClient.instances = []
    monkeypatch.setattr(cli_module, "EzvizClient", LightDevicesClient)
    token_file = tmp_path / "token.json"
    token_file.write_text(json.dumps({"session_id": "saved"}), encoding="utf-8")

    assert (
        cli_module.main(
            [
                "--token-file",
                str(token_file),
                "devices_light",
                "status",
                "--no-refresh",
            ]
        )
        == 0
    )

    client = cast(LightDevicesClient, LightDevicesClient.instances[0])
    assert client.refresh is False
    output = capsys.readouterr().out
    assert "LIGHT123" in output
    assert "Porch Light" in output
    assert "lighting" in output
    assert "192.0.2.50" in output
    assert "prod-light" in output
    assert "66" in output
    assert "4200" in output


def test_devices_light_status_json_preserves_payload(monkeypatch, tmp_path, capsys) -> None:
    class LightDevicesClient(_FakeClient):
        def load_light_bulbs(self, *, refresh: bool = True) -> dict[str, dict[str, Any]]:
            self.refresh = refresh
            return {"LIGHT123": {"name": "Porch Light", "is_on": True}}

    LightDevicesClient.instances = []
    monkeypatch.setattr(cli_module, "EzvizClient", LightDevicesClient)
    token_file = tmp_path / "token.json"
    token_file.write_text(json.dumps({"session_id": "saved"}), encoding="utf-8")

    assert (
        cli_module.main(
            [
                "--token-file",
                str(token_file),
                "--json",
                "devices_light",
                "status",
            ]
        )
        == 0
    )

    client = cast(LightDevicesClient, LightDevicesClient.instances[0])
    assert client.refresh is True
    assert json.loads(capsys.readouterr().out) == {
        "LIGHT123": {"name": "Porch Light", "is_on": True}
    }


def test_light_status_outputs_json(monkeypatch, tmp_path, capsys) -> None:
    class FakeLightBulb:
        instances: ClassVar[list[FakeLightBulb]] = []

        def __init__(self, client: _FakeClient, serial: str) -> None:
            self.client = client
            self.serial = serial
            self.toggled = False
            self.__class__.instances.append(self)

        def status(self) -> dict[str, Any]:
            return {"serial": self.serial, "name": "Porch Light", "is_on": True}

        def toggle_switch(self) -> None:
            self.toggled = True

    _install_fake_client(monkeypatch)
    FakeLightBulb.instances = []
    monkeypatch.setattr(cli_module, "EzvizLightBulb", FakeLightBulb)
    token_file = tmp_path / "token.json"
    token_file.write_text(json.dumps({"session_id": "saved"}), encoding="utf-8")

    assert (
        cli_module.main(
            [
                "--token-file",
                str(token_file),
                "light",
                "--serial",
                "LIGHT123",
                "status",
            ]
        )
        == 0
    )

    light = FakeLightBulb.instances[0]
    assert light.serial == "LIGHT123"
    assert json.loads(capsys.readouterr().out) == {
        "serial": "LIGHT123",
        "name": "Porch Light",
        "is_on": True,
    }


def test_light_toggle_invokes_light_wrapper(monkeypatch, tmp_path) -> None:
    class FakeLightBulb:
        instances: ClassVar[list[FakeLightBulb]] = []

        def __init__(self, client: _FakeClient, serial: str) -> None:
            self.client = client
            self.serial = serial
            self.toggled = False
            self.__class__.instances.append(self)

        def status(self) -> dict[str, Any]:
            return {}

        def toggle_switch(self) -> None:
            self.toggled = True

    _install_fake_client(monkeypatch)
    FakeLightBulb.instances = []
    monkeypatch.setattr(cli_module, "EzvizLightBulb", FakeLightBulb)
    token_file = tmp_path / "token.json"
    token_file.write_text(json.dumps({"session_id": "saved"}), encoding="utf-8")

    assert (
        cli_module.main(
            [
                "--token-file",
                str(token_file),
                "light",
                "--serial",
                "LIGHT123",
                "toggle",
            ]
        )
        == 0
    )

    light = FakeLightBulb.instances[0]
    assert light.serial == "LIGHT123"
    assert light.toggled is True


def test_camera_status_outputs_json_and_forwards_refresh(monkeypatch, tmp_path, capsys) -> None:
    fake_camera = _install_fake_camera(monkeypatch)

    assert (
        cli_module.main(
            [
                "--token-file",
                _token_file(tmp_path),
                "camera",
                "--serial",
                "CAM123",
                "status",
                "--no-refresh",
            ]
        )
        == 0
    )

    camera = fake_camera.instances[0]
    assert camera.serial == "CAM123"
    assert camera.calls == [("status", (False,))]
    assert json.loads(capsys.readouterr().out) == {
        "serial": "CAM123",
        "name": "Front Door",
        "refresh": False,
    }


def test_camera_move_and_coordinate_commands_dispatch(monkeypatch, tmp_path) -> None:
    fake_camera = _install_fake_camera(monkeypatch)

    assert (
        cli_module.main(
            [
                "--token-file",
                _token_file(tmp_path),
                "camera",
                "--serial",
                "CAM123",
                "move",
                "--direction",
                "left",
                "--speed",
                "7",
            ]
        )
        == 0
    )
    assert fake_camera.instances[-1].calls == [("move", ("left", 7))]

    assert (
        cli_module.main(
            [
                "--token-file",
                _token_file(tmp_path),
                "camera",
                "--serial",
                "CAM123",
                "move_coords",
                "--x",
                "0.25",
                "--y",
                "0.75",
            ]
        )
        == 0
    )
    assert fake_camera.instances[-1].calls == [("move_coordinates", (0.25, 0.75))]


def test_camera_lock_and_switch_commands_dispatch(monkeypatch, tmp_path, capsys) -> None:
    fake_camera = _install_fake_camera(monkeypatch)

    assert (
        cli_module.main(
            ["--token-file", _token_file(tmp_path), "camera", "--serial", "CAM123", "unlock-door"]
        )
        == 0
    )
    assert fake_camera.instances[-1].calls == [("door_unlock", ())]

    assert (
        cli_module.main(
            ["--token-file", _token_file(tmp_path), "camera", "--serial", "CAM123", "unlock-gate"]
        )
        == 0
    )
    assert fake_camera.instances[-1].calls == [("gate_unlock", ())]

    switch_cases = [
        ("ir", "switch_device_ir_led", 0),
        ("state", "switch_device_state_led", 1),
        ("audio", "switch_device_audio", 1),
        ("privacy", "switch_privacy_mode", 1),
        ("sleep", "switch_sleep_mode", 1),
        ("follow_move", "switch_follow_move", 1),
        ("sound_alarm", "switch_sound_alarm", 2),
    ]
    for switch_name, method_name, expected_enable in switch_cases:
        assert (
            cli_module.main(
                [
                    "--token-file",
                    _token_file(tmp_path),
                    "camera",
                    "--serial",
                    "CAM123",
                    "switch",
                    "--switch",
                    switch_name,
                    "--enable",
                    "1" if switch_name != "ir" else "0",
                ]
            )
            == 0
        )
        assert fake_camera.instances[-1].calls == [(method_name, (expected_enable,))]

    assert "1" in capsys.readouterr().out


def test_camera_alarm_and_select_commands_dispatch(monkeypatch, tmp_path) -> None:
    fake_camera = _install_fake_camera(monkeypatch)

    assert (
        cli_module.main(
            [
                "--token-file",
                _token_file(tmp_path),
                "camera",
                "--serial",
                "CAM123",
                "alarm",
                "--sound",
                "1",
                "--notify",
                "0",
                "--sensibility",
                "42",
                "--do_not_disturb",
                "1",
                "--schedule",
                '{"enabled": true}',
            ]
        )
        == 0
    )
    assert fake_camera.instances[-1].calls == [
        ("alarm_sound", (1,)),
        ("alarm_notify", (0,)),
        ("alarm_detection_sensibility", (42,)),
        ("do_not_disturb", (1,)),
        ("change_defence_schedule", ('{"enabled": true}',)),
    ]

    assert (
        cli_module.main(
            [
                "--token-file",
                _token_file(tmp_path),
                "camera",
                "--serial",
                "CAM123",
                "select",
                "--battery_work_mode",
                "POWER_SAVE",
            ]
        )
        == 0
    )
    method_name, args = fake_camera.instances[-1].calls[0]
    assert method_name == "set_battery_camera_work_mode"
    assert args[0].name == "POWER_SAVE"


def test_pagelist_outputs_raw_json(monkeypatch, tmp_path, capsys) -> None:
    class MiscClient(_FakeClient):
        def get_page_list(self) -> dict[str, Any]:
            return {"deviceInfos": [{"deviceSerial": "CAM123"}]}

    MiscClient.instances = []
    monkeypatch.setattr(cli_module, "EzvizClient", MiscClient)

    assert cli_module.main(["--token-file", _token_file(tmp_path), "pagelist"]) == 0

    assert json.loads(capsys.readouterr().out) == {"deviceInfos": [{"deviceSerial": "CAM123"}]}
    assert MiscClient.instances[0].closed is True


def test_device_infos_outputs_all_or_filtered_serial(monkeypatch, tmp_path, capsys) -> None:
    class MiscClient(_FakeClient):
        def get_device_infos(self, serial: str | None = None) -> dict[str, Any]:
            self.requested_serial = serial
            if serial:
                return {"deviceInfos": {"deviceSerial": serial}}
            return {"CAM123": {"deviceInfos": {"name": "Front"}}}

    MiscClient.instances = []
    monkeypatch.setattr(cli_module, "EzvizClient", MiscClient)

    assert cli_module.main(["--token-file", _token_file(tmp_path), "device_infos"]) == 0
    assert json.loads(capsys.readouterr().out) == {"CAM123": {"deviceInfos": {"name": "Front"}}}
    assert cast(MiscClient, MiscClient.instances[-1]).requested_serial is None

    assert (
        cli_module.main(
            [
                "--token-file",
                _token_file(tmp_path),
                "device_infos",
                "--serial",
                "CAM456",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out) == {"deviceInfos": {"deviceSerial": "CAM456"}}
    assert cast(MiscClient, MiscClient.instances[-1]).requested_serial == "CAM456"


def test_home_defence_mode_dispatches_selected_mode(monkeypatch, tmp_path, capsys) -> None:
    class MiscClient(_FakeClient):
        def api_set_defence_mode(self, mode: int) -> dict[str, Any]:
            self.mode = mode
            return {"mode": mode, "result": "ok"}

    MiscClient.instances = []
    monkeypatch.setattr(cli_module, "EzvizClient", MiscClient)

    assert (
        cli_module.main(
            [
                "--token-file",
                _token_file(tmp_path),
                "home_defence_mode",
                "--mode",
                "HOME_MODE",
            ]
        )
        == 0
    )

    client = cast(MiscClient, MiscClient.instances[0])
    assert isinstance(client.mode, int)
    assert json.loads(capsys.readouterr().out) == {"mode": client.mode, "result": "ok"}


def test_home_defence_mode_without_mode_returns_not_implemented(monkeypatch, tmp_path) -> None:
    _install_fake_client(monkeypatch)

    assert cli_module.main(["--token-file", _token_file(tmp_path), "home_defence_mode"]) == 2


def test_pyezviz_error_returns_cli_error(monkeypatch, tmp_path, caplog) -> None:
    class ErrorClient(_FakeClient):
        def get_page_list(self) -> dict[str, Any]:
            raise PyEzvizError("cloud exploded")

    ErrorClient.instances = []
    monkeypatch.setattr(cli_module, "EzvizClient", ErrorClient)

    assert cli_module.main(["--token-file", _token_file(tmp_path), "pagelist"]) == 1

    assert "cloud exploded" in caplog.text
    assert ErrorClient.instances[0].closed is True
