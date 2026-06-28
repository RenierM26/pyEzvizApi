from __future__ import annotations

import argparse
import importlib.util
import io
import json
import sys
from typing import Any, BinaryIO, ClassVar, cast

from cli_fakes import (
    FakeClient as _FakeClient,
    install_fake_camera as _install_fake_camera,
    install_fake_client as _install_fake_client,
    token_file as _token_file,
)

import pyezvizapi.__main__ as cli_module
from pyezvizapi.constants import MAX_RETRIES
from pyezvizapi.exceptions import EzvizAuthVerificationCode, PyEzvizError
from pyezvizapi.hcnetsdk import (
    HcNetSdkCommandPortExchange,
    build_hcnetsdk_tcp_frame,
    hcnetsdk_command_port_control_frame,
    parse_hcnetsdk_tcp_frame,
)
from pyezvizapi.stream import VtmChannel, VtmPacket

MPEGTS_PAYLOAD = b"mpegts"
CLOUD_VIDEO_PAYLOAD = b"cloud-video-bytes"
NATIVE_ENCRYPTED_PAYLOAD = b"encrypted"
NATIVE_TRANSFORMED_PAYLOAD = b"decrypted"
LOCAL_SDK_TEST_PAYLOAD = b"mpeg-ps"
LOCAL_SDK_PRE_START_BODY = b"pre"
LOCAL_SDK_DEFAULT_DURATION = 60.0
HCNETSDK_DEFAULT_SAVE_TIMEOUT = 10.0
HCNETSDK_TEST_SAVE_DURATION = 3.0
HCNETSDK_PLAN_KEEPALIVE_INTERVAL = 2.0
HCNETSDK_PLAN_STEP_DELAY = 0.5
HCNETSDK_CLEAN_IDR_PREROLL_SECONDS = 45.5
HCNETSDK_CLEAN_IDR_MAX_WINDOWS = 64
HCNETSDK_CLEAN_IDR_DEFAULT_WAIT_SECONDS = 60.0
HCNETSDK_CLEAN_IDR_WAIT_SECONDS = 12.5
HCNETSDK_COMMAND_PORT_TEST_KEY_HEX = (
    "3630343531663636393865353862623134313139323936386361333030663431"
)
IMAGE_PAYLOAD = b"jpeg-bytes"
STRUCTURED_RECEIVER_INNER_ADDRESS_XML = b"<InnerAddress>192.0.2.20</InnerAddress>"
STRUCTURED_RECEIVER_INNER_PORT_XML = b"<InnerPort>9020</InnerPort>"
STRUCTURED_RECEIVER_AUTH_XML = b"<Authentication>"
STRUCTURED_RECEIVER_UUID_XML = b"<Uuid>uuid</Uuid>"
STRUCTURED_RECEIVER_TIMESTAMP_XML = b"<Timestamp>123456</Timestamp>"
APP_RECEIVER_INFO_XML_PREFIX = b'<ReceiverInfo Address='

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


def test_main_rejects_token_file_without_session_id(tmp_path, caplog) -> None:
    token_file = tmp_path / "token.json"
    token_file.write_text(
        json.dumps({"session_id": None, "api_url": "apiieu.ezvizlife.com"}),
        encoding="utf-8",
    )

    assert cli_module.main(["--token-file", str(token_file), "device_infos"]) == 2

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


def test_main_prefers_saved_token_when_credentials_are_also_present(
    monkeypatch, tmp_path, capsys
) -> None:
    fake_client = _install_fake_client(monkeypatch)
    token_file = tmp_path / "token.json"
    token_file.write_text(
        json.dumps(
            {
                "session_id": "saved-session",
                "rf_session_id": "saved-refresh",
                "api_url": "apiieu.ezvizlife.com",
            }
        ),
        encoding="utf-8",
    )

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
                "--serial",
                "CAM123",
            ]
        )
        == 0
    )

    client = fake_client.instances[0]
    assert client.login_calls == []
    assert client.closed is True
    assert json.loads(capsys.readouterr().out) == {"deviceInfos": {"name": "Front"}}


def test_main_refreshes_saved_token_for_cas_service_metadata(
    monkeypatch,
    tmp_path,
    capsys,
) -> None:
    class KeyClient(_FakeClient):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            self.device_infos = {
                "CAM123456": {
                    "CONNECTION": {
                        "localIp": "192.0.2.10",
                        "localCmdPort": "9010",
                        "localStreamPort": "9020",
                    }
                }
            }

        def login(self, sms_code: int | None = None) -> None:
            super().login(sms_code)
            self.exported_token = cast(
                dict[str, Any],
                {
                    "session_id": "new-session",
                    "api_url": "apiieu.ezvizlife.com",
                    "service_urls": {
                        "sysConf": [None] * 15 + ["cas.example.test", 443]
                    },
                },
            )

    KeyClient.instances = []
    monkeypatch.setattr(cli_module, "EzvizClient", KeyClient)
    token_file = tmp_path / "token.json"
    token_file.write_text(
        json.dumps(
            {
                "session_id": "saved-session",
                "api_url": "apiieu.ezvizlife.com",
                "service_urls": {"pushAddr": "push.example.test"},
            }
        ),
        encoding="utf-8",
    )
    calls: list[dict[str, Any]] = []

    class FakeCas:
        def __init__(self, token: dict[str, Any]) -> None:
            calls.append({"token": token})

        def cas_get_encryption(self, serial: str) -> dict[str, Any]:
            calls.append({"cas_serial": serial})
            return {
                "Response": {
                    "Session": {
                        "@Key": "1234567890abcdef",
                        "@OperationCode": "0123456",
                        "@EncryptType": "2",
                    }
                }
            }

    monkeypatch.setattr("pyezvizapi.local_stream.EzvizCAS", FakeCas)

    assert (
        cli_module.main(
            [
                "--username",
                "user@example.test",
                "--password",
                "secret",
                "--token-file",
                str(token_file),
                "stream",
                "local-sdk-keys",
                "--serial",
                "CAM123456",
                "--no-media-key",
            ]
        )
        == 0
    )

    client = KeyClient.instances[0]
    assert client.login_calls == [None]
    assert calls[0] == {
        "token": {
            "session_id": "new-session",
            "api_url": "apiieu.ezvizlife.com",
            "service_urls": {"sysConf": [None] * 15 + ["cas.example.test", 443]},
        }
    }
    assert calls[1] == {"cas_serial": "CAM123456"}
    assert json.loads(capsys.readouterr().out)["serial"] == "CAM123456"



def test_main_refreshes_saved_session_for_cas_service_metadata_without_credentials(
    monkeypatch,
    tmp_path,
    capsys,
) -> None:
    class KeyClient(_FakeClient):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            self.device_infos = {
                "CAM123456": {
                    "CONNECTION": {
                        "localIp": "192.0.2.10",
                        "localCmdPort": "9010",
                        "localStreamPort": "9020",
                    }
                }
            }

        def login(self, sms_code: int | None = None) -> None:
            super().login(sms_code)
            self.exported_token = cast(
                dict[str, Any],
                {
                    "session_id": "new-session",
                    "rf_session_id": "new-refresh",
                    "api_url": "apiieu.ezvizlife.com",
                    "service_urls": {
                        "sysConf": [None] * 15 + ["cas.example.test", 443]
                    },
                },
            )

    KeyClient.instances = []
    monkeypatch.setattr(cli_module, "EzvizClient", KeyClient)
    token_file = tmp_path / "token.json"
    token_file.write_text(
        json.dumps(
            {
                "session_id": "saved-session",
                "rf_session_id": "saved-refresh",
                "api_url": "apiieu.ezvizlife.com",
                "service_urls": {"pushAddr": "push.example.test"},
            }
        ),
        encoding="utf-8",
    )
    calls: list[dict[str, Any]] = []

    class FakeCas:
        def __init__(self, token: dict[str, Any]) -> None:
            calls.append({"token": token})

        def cas_get_encryption(self, serial: str) -> dict[str, Any]:
            calls.append({"cas_serial": serial})
            return {
                "Response": {
                    "Session": {
                        "@Key": "1234567890abcdef",
                        "@OperationCode": "0123456",
                        "@EncryptType": "2",
                    }
                }
            }

    monkeypatch.setattr("pyezvizapi.local_stream.EzvizCAS", FakeCas)

    assert (
        cli_module.main(
            [
                "--token-file",
                str(token_file),
                "stream",
                "local-sdk-keys",
                "--serial",
                "CAM123456",
                "--no-media-key",
            ]
        )
        == 0
    )

    client = KeyClient.instances[0]
    assert client.login_calls == [None]
    assert calls[0]["token"]["service_urls"] == {
        "sysConf": [None] * 15 + ["cas.example.test", 443]
    }
    assert calls[1] == {"cas_serial": "CAM123456"}
    assert json.loads(capsys.readouterr().out)["serial"] == "CAM123456"


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

    def fake_decrypt(data: bytes, key: str | bytes, *, nalu_header_size: int | None) -> bytes:
        decrypt_calls.append({"data": data, "key": key, "nalu_header_size": nalu_header_size})
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
    assert decrypt_calls == [
        {"data": NATIVE_ENCRYPTED_PAYLOAD, "key": "camera-secret", "nalu_header_size": None}
    ]
    assert json.loads(capsys.readouterr().out) == {
        "bytes": len(NATIVE_TRANSFORMED_PAYLOAD),
        "encrypted_output": str(encrypted_output),
        "output": str(output),
        "seqId": 12345,
        "transform": "cloud_replay_python",
    }


def test_cloud_video_decrypt_uses_camera_key(monkeypatch, tmp_path, capsys) -> None:
    fake_client = _install_fake_client(monkeypatch)
    token_file = tmp_path / "token.json"
    token_file.write_text(json.dumps({"session_id": "saved"}), encoding="utf-8")
    input_path = tmp_path / "clip.tmp"
    output_path = tmp_path / "clip.ps"
    input_path.write_bytes(NATIVE_ENCRYPTED_PAYLOAD)
    decrypt_calls: list[dict[str, Any]] = []

    def fake_decrypt(data: bytes, key: str, *, nalu_header_size: int | None) -> bytes:
        decrypt_calls.append({"data": data, "key": key, "nalu_header_size": nalu_header_size})
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
    assert decrypt_calls == [
        {"data": NATIVE_ENCRYPTED_PAYLOAD, "key": "camera-secret", "nalu_header_size": None}
    ]
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

    def fake_decrypt(data: bytes, key: str, *, nalu_header_size: int | None) -> bytes:
        decrypt_calls.append({"data": data, "key": key, "nalu_header_size": nalu_header_size})
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
                "--decrypt-codec",
                "h264-encrypted-header",
            ]
        )
        == 0
    )

    assert decrypt_calls == [
        {"data": NATIVE_ENCRYPTED_PAYLOAD, "key": "manual-key", "nalu_header_size": 0}
    ]
    assert output_path.read_bytes() == NATIVE_TRANSFORMED_PAYLOAD
    assert json.loads(capsys.readouterr().out)["bytes"] == len(NATIVE_TRANSFORMED_PAYLOAD)


def test_cloud_video_decrypt_h264_keeps_clear_header_mapping(
    monkeypatch,
    tmp_path,
) -> None:
    input_path = tmp_path / "clip.tmp"
    output_path = tmp_path / "clip.ps"
    input_path.write_bytes(NATIVE_ENCRYPTED_PAYLOAD)
    decrypt_calls: list[dict[str, Any]] = []

    def fake_decrypt(data: bytes, key: str, *, nalu_header_size: int | None) -> bytes:
        decrypt_calls.append({"data": data, "key": key, "nalu_header_size": nalu_header_size})
        return NATIVE_TRANSFORMED_PAYLOAD

    monkeypatch.setattr(cli_module, "decrypt_hikvision_ps_video", fake_decrypt)

    assert (
        cli_module.main(
            [
                "cloud_video_decrypt",
                "--input",
                str(input_path),
                "--output",
                str(output_path),
                "--key",
                "manual-key",
                "--decrypt-codec",
                "h264",
            ]
        )
        == 0
    )

    assert decrypt_calls == [
        {"data": NATIVE_ENCRYPTED_PAYLOAD, "key": "manual-key", "nalu_header_size": 1}
    ]


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


def test_save_clip_uses_direct_local_stream_and_outputs_json(
    monkeypatch,
    tmp_path,
    capsys,
) -> None:
    fake_client = _install_fake_client(monkeypatch)
    output_path = tmp_path / "www" / "front.ts"

    assert (
        cli_module.main(
            [
                "--token-file",
                _token_file(tmp_path),
                "--json",
                "save",
                "clip",
                "--serial",
                "CAM123",
                "--channel",
                "2",
                "--duration",
                "5s",
                "--output",
                str(output_path),
                "--decrypt-video",
                "--decrypt-codec",
                "h264-encrypted-header",
                "--ffmpeg-path",
                "/usr/bin/ffmpeg",
                "--sms-code",
                "123456",
            ]
        )
        == 0
    )

    client = fake_client.instances[0]
    assert client.save_clip_request == {
        "serial": "CAM123",
        "output": str(output_path),
        "source": "local-sdk",
        "output_format": "mpegts",
        "duration_seconds": 5.0,
        "max_packets": None,
        "channel": 2,
        "ffmpeg_path": "/usr/bin/ffmpeg",
        "decrypt_video": True,
        "nalu_header_size": 0,
        "cas_serial": None,
        "register_p2p_session": True,
        "timeout": 10.0,
        "smscode": "123456",
        "host": None,
        "command_port": None,
        "hcnetsdk_command_frames": None,
        "hcnetsdk_command_plan": None,
        "hcnetsdk_command_generated_plan": None,
        "hcnetsdk_command_password": None,
        "hcnetsdk_local_ip": None,
        "hcnetsdk_read_response_after_each": True,
        "hcnetsdk_command_metadata_callback": None,
        "hcnetsdk_h264_skip_initial_idr_windows": 0,
        "hcnetsdk_h264_trim_to_clean_idr_window": False,
        "hcnetsdk_h264_clean_idr_preroll_seconds": 0.0,
        "hcnetsdk_h264_clean_idr_max_windows": 32,
        "hcnetsdk_h264_wait_for_clean_idr_window": False,
        "hcnetsdk_h264_clean_idr_wait_seconds": 60.0,
    }
    assert output_path.read_bytes() == MPEGTS_PAYLOAD
    assert json.loads(capsys.readouterr().out) == {
        "ok": True,
        "kind": "clip",
        "serial": "CAM123",
        "channel": 2,
        "output": str(output_path),
        "bytes": len(MPEGTS_PAYLOAD),
        "source": "local-sdk",
        "format": "mpegts",
        "duration_seconds": 5.0,
        "content_type": "video/mp2t",
    }


def test_save_clip_can_use_local_sdk_ecdh_source(
    monkeypatch,
    tmp_path,
    capsys,
) -> None:
    fake_client = _install_fake_client(monkeypatch)
    output_path = tmp_path / "www" / "front.ps"

    assert (
        cli_module.main(
            [
                "--token-file",
                _token_file(tmp_path),
                "--json",
                "save",
                "clip",
                "--serial",
                "CAM123",
                "--source",
                "local-sdk-ecdh",
                "--format",
                "mpegps",
                "--channel",
                "2",
                "--duration",
                "5s",
                "--max-packets",
                "3",
                "--output",
                str(output_path),
                "--cas-serial",
                "CAMALT",
                "--no-p2p-register",
                "--local-sdk-ecdh-receiver-port",
                "10105",
                "--local-sdk-ecdh-send-init",
                "--local-sdk-ecdh-max-frames",
                "9",
                "--local-sdk-ecdh-max-prefix-bytes",
                "8192",
            ]
        )
        == 0
    )

    client = fake_client.instances[0]
    assert client.save_clip_request["source"] == "local-sdk-ecdh"
    assert client.save_clip_request["output_format"] == "mpegps"
    assert client.save_clip_request["cas_serial"] == "CAMALT"
    assert client.save_clip_request["register_p2p_session"] is False
    assert client.save_clip_request["local_sdk_ecdh_receiver_port"] == 10105
    assert client.save_clip_request["local_sdk_ecdh_send_init"] is True
    assert client.save_clip_request["local_sdk_ecdh_max_frames"] == 9
    assert client.save_clip_request["local_sdk_ecdh_max_prefix_bytes"] == 8192
    assert client.save_clip_request["max_packets"] == 3
    assert output_path.read_bytes() == MPEGTS_PAYLOAD
    assert json.loads(capsys.readouterr().out)["source"] == "local-sdk-ecdh"


def test_save_clip_local_sdk_ecdh_defaults_to_mpegps(
    monkeypatch,
    tmp_path,
) -> None:
    fake_client = _install_fake_client(monkeypatch)
    output_path = tmp_path / "www" / "front.ps"

    assert (
        cli_module.main(
            [
                "--token-file",
                _token_file(tmp_path),
                "save",
                "clip",
                "--serial",
                "CAM123",
                "--source",
                "local-sdk-ecdh",
                "--output",
                str(output_path),
            ]
        )
        == 0
    )

    request = fake_client.instances[0].save_clip_request
    assert request["source"] == "local-sdk-ecdh"
    assert request["output_format"] == "mpegps"


def test_save_clip_can_use_hcnetsdk_command_port_source(
    monkeypatch,
    tmp_path,
    capsys,
) -> None:
    fake_client = _install_fake_client(monkeypatch)
    output_path = tmp_path / "www" / "front.ts"
    frames_path = tmp_path / "frames.json"
    frames_path.write_text(
        json.dumps({"command_frames": [{"frame_hex": "00000010"}, "00000011"]}),
        encoding="utf-8",
    )

    assert (
        cli_module.main(
            [
                "--token-file",
                _token_file(tmp_path),
                "--json",
                "save",
                "clip",
                "--source",
                "hcnetsdk-command-port",
                "--serial",
                "CAM123",
                "--host",
                "192.0.2.10",
                "--command-port",
                "8000",
                "--duration",
                "3s",
                "--max-packets",
                "4",
                "--output",
                str(output_path),
                "--hcnetsdk-command-frames-file",
                str(frames_path),
                "--hcnetsdk-read-responses",
                "true,false",
                "--hcnetsdk-video-wait-for-clean-window",
                "--hcnetsdk-video-clean-window-wait-seconds",
                str(HCNETSDK_CLEAN_IDR_WAIT_SECONDS),
            ]
        )
        == 0
    )

    client = fake_client.instances[0]
    assert client.save_clip_request == {
        "serial": "CAM123",
        "output": str(output_path),
        "source": "hcnetsdk-command-port",
        "output_format": "mpegts",
        "duration_seconds": HCNETSDK_TEST_SAVE_DURATION,
        "max_packets": 4,
        "channel": 1,
        "ffmpeg_path": "ffmpeg",
        "decrypt_video": False,
        "nalu_header_size": 0,
        "cas_serial": None,
        "timeout": HCNETSDK_DEFAULT_SAVE_TIMEOUT,
        "smscode": None,
        "host": "192.0.2.10",
        "command_port": 8000,
        "hcnetsdk_command_frames": (
            bytes.fromhex("00000010"),
            bytes.fromhex("00000011"),
        ),
        "hcnetsdk_command_plan": None,
        "hcnetsdk_command_generated_plan": None,
        "hcnetsdk_command_password": None,
        "hcnetsdk_local_ip": None,
        "hcnetsdk_read_response_after_each": (True, False),
        "hcnetsdk_command_metadata_callback": None,
        "hcnetsdk_h264_skip_initial_idr_windows": 0,
        "hcnetsdk_h264_trim_to_clean_idr_window": False,
        "hcnetsdk_h264_clean_idr_preroll_seconds": 0.0,
        "hcnetsdk_h264_clean_idr_max_windows": 32,
        "hcnetsdk_h264_wait_for_clean_idr_window": True,
        "hcnetsdk_h264_clean_idr_wait_seconds": HCNETSDK_CLEAN_IDR_WAIT_SECONDS,
    }
    assert output_path.read_bytes() == MPEGTS_PAYLOAD
    assert json.loads(capsys.readouterr().out) == {
        "ok": True,
        "kind": "clip",
        "serial": "CAM123",
        "channel": 1,
        "output": str(output_path),
        "bytes": len(MPEGTS_PAYLOAD),
        "source": "hcnetsdk-command-port",
        "format": "mpegts",
        "duration_seconds": HCNETSDK_TEST_SAVE_DURATION,
        "content_type": "video/mp2t",
        "command_port": 8000,
    }


def test_save_clip_command_port_source_does_not_require_cloud_credentials(
    monkeypatch,
    tmp_path,
    capsys,
) -> None:
    fake_client = _install_fake_client(monkeypatch)
    output_path = tmp_path / "www" / "front.ts"
    missing_token = tmp_path / "missing-token.json"

    assert (
        cli_module.main(
            [
                "--token-file",
                str(missing_token),
                "--json",
                "save",
                "clip",
                "--source",
                "hcnetsdk-command-port",
                "--serial",
                "CAM123",
                "--host",
                "192.0.2.10",
                "--output",
                str(output_path),
                "--hcnetsdk-command-frame-hex",
                "00000010",
            ]
        )
        == 0
    )

    client = fake_client.instances[0]
    assert client.account is None
    assert client.password is None
    assert client.token is None
    assert client.login_calls == []
    assert client.closed is True
    assert client.save_clip_request["source"] == "hcnetsdk-command-port"
    assert client.save_clip_request["host"] == "192.0.2.10"
    assert client.save_clip_request["hcnetsdk_command_frames"] == (
        bytes.fromhex("00000010"),
    )
    assert output_path.read_bytes() == MPEGTS_PAYLOAD
    assert json.loads(capsys.readouterr().out)["source"] == "hcnetsdk-command-port"


def test_save_clip_can_use_hcnetsdk_command_port_plan_file(
    monkeypatch,
    tmp_path,
    capsys,
) -> None:
    fake_client = _install_fake_client(monkeypatch)
    output_path = tmp_path / "www" / "front.ts"
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(
        json.dumps(
            {
                "sockets": [
                    {"name": "auth", "frames": ["00000010"]},
                    {
                        "name": "media",
                        "media_socket": True,
                        "frames": ["00000011"],
                        "keepalive_frames": ["00000012"],
                        "keepalive_interval_seconds": HCNETSDK_PLAN_KEEPALIVE_INTERVAL,
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    assert (
        cli_module.main(
            [
                "--token-file",
                _token_file(tmp_path),
                "--json",
                "save",
                "clip",
                "--source",
                "hcnetsdk-command-port",
                "--serial",
                "CAM123",
                "--host",
                "192.0.2.10",
                "--output",
                str(output_path),
                "--hcnetsdk-command-plan-file",
                str(plan_path),
                "--hcnetsdk-local-ip",
                "192.168.1.26",
            ]
        )
        == 0
    )

    request = fake_client.instances[0].save_clip_request
    plan = request["hcnetsdk_command_plan"]
    assert request["hcnetsdk_command_frames"] is None
    assert request["hcnetsdk_command_generated_plan"] is None
    assert request["hcnetsdk_command_password"] is None
    assert request["hcnetsdk_local_ip"] == "192.168.1.26"
    assert request["hcnetsdk_read_response_after_each"] is True
    assert len(plan.steps) == 2
    assert plan.steps[0].name == "auth"
    assert plan.steps[0].command_frames == (bytes.fromhex("00000010"),)
    assert plan.steps[0].read_response_after_each is True
    assert plan.steps[1].media_socket is True
    assert plan.steps[1].read_response_after_each is False
    assert plan.steps[1].response_reads_after_each is None
    assert plan.steps[1].keepalive_frames == (bytes.fromhex("00000012"),)
    assert plan.steps[1].keepalive_interval_seconds == HCNETSDK_PLAN_KEEPALIVE_INTERVAL
    assert output_path.read_bytes() == MPEGTS_PAYLOAD
    assert json.loads(capsys.readouterr().out)["source"] == "hcnetsdk-command-port"


def test_hcnetsdk_command_port_media_plan_can_explicitly_read_response(
    monkeypatch,
    tmp_path,
    capsys,
) -> None:
    fake_client = _install_fake_client(monkeypatch)
    output_path = tmp_path / "www" / "front.ts"
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(
        json.dumps(
            {
                "sockets": [
                    {"name": "auth", "frames": ["00000010"]},
                    {
                        "name": "diagnostic-media",
                        "media_socket": True,
                        "frames": ["00000011"],
                        "read_responses": True,
                        "response_reads": 1,
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    assert (
        cli_module.main(
            [
                "--token-file",
                _token_file(tmp_path),
                "--json",
                "save",
                "clip",
                "--source",
                "hcnetsdk-command-port",
                "--serial",
                "CAM123",
                "--host",
                "192.0.2.10",
                "--output",
                str(output_path),
                "--hcnetsdk-command-plan-file",
                str(plan_path),
            ]
        )
        == 0
    )

    plan = fake_client.instances[0].save_clip_request["hcnetsdk_command_plan"]
    assert plan.steps[1].media_socket is True
    assert plan.steps[1].read_response_after_each is True
    assert plan.steps[1].response_reads_after_each == 1
    assert json.loads(capsys.readouterr().out)["source"] == "hcnetsdk-command-port"


def test_save_clip_can_use_hcnetsdk_command_port_generated_plan_file(
    monkeypatch,
    tmp_path,
    capsys,
) -> None:
    fake_client = _install_fake_client(monkeypatch)
    output_path = tmp_path / "www" / "front.ts"
    metadata_path = tmp_path / "www" / "front.metadata.json"
    plan_path = tmp_path / "generated-plan.json"
    plan_path.write_text(
        json.dumps(
            {
                "steps": [
                    {
                        "name": "control",
                        "templates": [
                            {
                                "command_id": "0x111050",
                                "addend_delta": 2,
                                "body_tail_transform": "play_login_today",
                            },
                        ],
                    },
                    {
                        "name": "media",
                        "media_socket": True,
                        "templates": [
                            {
                                "command_id": "0x30000",
                                "body_tail_hex": "000000010000000000000401",
                                "addend_delta": 3,
                            }
                        ],
                        "read_first_media_immediately": True,
                        "delay_after_commands_seconds": HCNETSDK_PLAN_STEP_DELAY,
                        "keepalive_templates": [
                            {"command_id": "0x30006", "addend_delta": 9}
                        ],
                        "keepalive_interval_seconds": HCNETSDK_PLAN_KEEPALIVE_INTERVAL,
                        "keepalive_initial_delay_seconds": 0.0,
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    assert (
        cli_module.main(
            [
                "--token-file",
                _token_file(tmp_path),
                "--json",
                "save",
                "clip",
                "--source",
                "hcnetsdk-command-port",
                "--serial",
                "CAM123",
                "--host",
                "192.0.2.10",
                "--output",
                str(output_path),
                "--hcnetsdk-command-generated-plan-file",
                str(plan_path),
                "--hcnetsdk-command-password",
                "123456",
                "--hcnetsdk-local-ip",
                "192.168.1.56",
                "--hcnetsdk-h264-skip-initial-idr-windows",
                "2",
                "--hcnetsdk-video-trim-to-clean-window",
                "--hcnetsdk-video-clean-window-preroll-seconds",
                str(HCNETSDK_CLEAN_IDR_PREROLL_SECONDS),
                "--hcnetsdk-video-clean-window-max-windows",
                str(HCNETSDK_CLEAN_IDR_MAX_WINDOWS),
                "--hcnetsdk-command-metadata-output",
                str(metadata_path),
            ]
        )
        == 0
    )

    request = fake_client.instances[0].save_clip_request
    generated_plan = request["hcnetsdk_command_generated_plan"]
    assert request["hcnetsdk_command_frames"] is None
    assert request["hcnetsdk_command_plan"] is None
    assert request["hcnetsdk_command_password"] == "123456"
    assert request["hcnetsdk_local_ip"] == "192.168.1.56"
    assert request["hcnetsdk_h264_skip_initial_idr_windows"] == 2
    assert request["hcnetsdk_h264_trim_to_clean_idr_window"] is True
    assert (
        request["hcnetsdk_h264_clean_idr_preroll_seconds"]
        == HCNETSDK_CLEAN_IDR_PREROLL_SECONDS
    )
    assert (
        request["hcnetsdk_h264_clean_idr_max_windows"]
        == HCNETSDK_CLEAN_IDR_MAX_WINDOWS
    )
    assert request["hcnetsdk_h264_wait_for_clean_idr_window"] is False
    assert (
        request["hcnetsdk_h264_clean_idr_wait_seconds"]
        == HCNETSDK_CLEAN_IDR_DEFAULT_WAIT_SECONDS
    )
    assert callable(request["hcnetsdk_command_metadata_callback"])
    assert len(generated_plan.steps) == 2
    assert generated_plan.steps[0].name == "control"
    assert generated_plan.steps[0].control_templates[0].command_id == 0x111050
    assert generated_plan.steps[0].control_templates[0].addend_delta == 2
    assert (
        generated_plan.steps[0].control_templates[0].body_tail_transform
        == "play_login_today"
    )
    assert generated_plan.steps[1].media_socket is True
    assert generated_plan.steps[1].read_response_after_each is False
    assert generated_plan.steps[1].read_first_media_immediately is True
    assert generated_plan.steps[1].response_reads_after_each is None
    assert (
        generated_plan.steps[1].delay_after_commands_seconds
        == HCNETSDK_PLAN_STEP_DELAY
    )
    assert generated_plan.steps[1].keepalive_initial_delay_seconds == 0.0
    assert generated_plan.steps[1].control_templates[0].body_tail == bytes.fromhex(
        "000000010000000000000401"
    )
    assert generated_plan.steps[1].keepalive_templates[0].command_id == 0x30006
    assert output_path.read_bytes() == MPEGTS_PAYLOAD
    assert json.loads(capsys.readouterr().out)["source"] == "hcnetsdk-command-port"

    request["hcnetsdk_command_metadata_callback"](
        argparse.Namespace(bootstrap=argparse.Namespace(exchanges=(), first_media=None))
    )
    assert json.loads(metadata_path.read_text(encoding="utf-8")) == {
        "bootstrap_complete": True,
        "command_port_exchanges": [],
        "exchanges": {},
    }


def test_save_clip_can_use_hcnetsdk_command_port_native_plan(
    monkeypatch,
    tmp_path,
    capsys,
) -> None:
    fake_client = _install_fake_client(monkeypatch)
    output_path = tmp_path / "www" / "front.ts"

    assert (
        cli_module.main(
            [
                "--token-file",
                _token_file(tmp_path),
                "--json",
                "save",
                "clip",
                "--source",
                "hcnetsdk-command-port",
                "--serial",
                "CAM123",
                "--host",
                "192.0.2.10",
                "--output",
                str(output_path),
                "--hcnetsdk-command-native-plan",
                "app-lan-live-view",
                "--hcnetsdk-command-password",
                "123456",
                "--hcnetsdk-local-ip",
                "192.168.1.56",
            ]
        )
        == 0
    )

    request = fake_client.instances[0].save_clip_request
    generated_plan = request["hcnetsdk_command_generated_plan"]
    assert request["hcnetsdk_command_frames"] is None
    assert request["hcnetsdk_command_plan"] is None
    assert request["hcnetsdk_command_password"] == "123456"
    assert len(generated_plan.steps) == 10
    assert generated_plan.steps[7].name == "play-login"
    assert generated_plan.steps[7].control_templates[0].command_id == 0x111040
    assert generated_plan.steps[7].response_reads_after_each == 1
    assert generated_plan.steps[8].name == "media"
    assert generated_plan.steps[8].media_socket is True
    assert generated_plan.steps[8].read_response_after_each is False
    assert generated_plan.steps[8].control_templates[0].command_id == 0x30000
    assert generated_plan.steps[9].control_templates[0].command_id == 0x90100
    assert output_path.read_bytes() == MPEGTS_PAYLOAD
    assert json.loads(capsys.readouterr().out)["source"] == "hcnetsdk-command-port"


def test_save_clip_native_plan_rejects_non_primary_channel(
    monkeypatch,
    tmp_path,
    caplog,
) -> None:
    fake_client = _install_fake_client(monkeypatch)

    assert (
        cli_module.main(
            [
                "--token-file",
                _token_file(tmp_path),
                "--json",
                "save",
                "clip",
                "--source",
                "hcnetsdk-command-port",
                "--serial",
                "CAM123",
                "--channel",
                "2",
                "--host",
                "192.0.2.10",
                "--output",
                str(tmp_path / "front.ts"),
                "--hcnetsdk-command-native-plan",
                "app-lan-live-view",
                "--hcnetsdk-command-password",
                "123456",
                "--hcnetsdk-local-ip",
                "192.168.1.56",
            ]
        )
        == 1
    )

    assert "supports only --channel 1" in caplog.text
    assert fake_client.instances[0].save_clip_request == {}


def test_hcnetsdk_command_plan_generate_writes_generated_plan_without_login(
    tmp_path,
    capsys,
) -> None:
    key = bytes.fromhex(HCNETSDK_COMMAND_PORT_TEST_KEY_HEX)
    session_id = bytes.fromhex("71f872b7")
    control_frame = hcnetsdk_command_port_control_frame(
        session_id=session_id,
        auth_seed=0x143D7840,
        command_id=0x111050,
        key=key,
        local_ip="172.18.0.3",
        addend=0x71F872B9,
    )
    media_frame = hcnetsdk_command_port_control_frame(
        session_id=session_id,
        auth_seed=0x143D7840,
        command_id=0x30000,
        key=key,
        local_ip="172.18.0.3",
        body_tail=bytes.fromhex("000000010000000000000401"),
        addend=0x71F872BA,
    )
    keepalive_frame = hcnetsdk_command_port_control_frame(
        session_id=session_id,
        auth_seed=0x143D7840,
        command_id=0x30006,
        key=key,
        local_ip="172.18.0.3",
        addend=0x71F872C0,
    )
    plan_path = tmp_path / "concrete-plan.json"
    plan_path.write_text(
        json.dumps(
            {
                "steps": [
                    {"name": "control", "frames": [control_frame.hex()]},
                    {
                        "name": "media",
                        "frames": [media_frame.hex()],
                        "media_socket": True,
                        "read_responses": False,
                        "response_reads": 0,
                        "keepalive_frames": [keepalive_frame.hex()],
                        "keepalive_initial_delay_seconds": 0.0,
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    assert (
        cli_module.main(
            [
                "--token-file",
                str(tmp_path / "missing-token.json"),
                "stream",
                "hcnetsdk-command-plan-generate",
                "--input",
                str(plan_path),
                "--auth-seed",
                "0x143d7840",
                "--key-hex",
                HCNETSDK_COMMAND_PORT_TEST_KEY_HEX,
            ]
        )
        == 0
    )

    output = json.loads(capsys.readouterr().out)
    assert output == {
        "steps": [
            {
                "name": "control",
                "templates": [
                    {
                        "addend_delta": 2,
                        "command_id": "0x111050",
                    }
                ],
            },
            {
                "keepalive_initial_delay_seconds": 0.0,
                "keepalive_templates": [
                    {
                        "addend_delta": 9,
                        "command_id": "0x30006",
                    }
                ],
                "media_socket": True,
                "name": "media",
                "read_responses": False,
                "response_reads": 0,
                "templates": [
                    {
                        "addend_delta": 3,
                        "body_tail_hex": "000000010000000000000401",
                        "command_id": "0x30000",
                    }
                ],
            },
        ]
    }


def test_save_clip_can_use_cloud_source(
    monkeypatch,
    tmp_path,
    capsys,
) -> None:
    fake_client = _install_fake_client(monkeypatch)
    output_path = tmp_path / "www" / "front.ts"

    assert (
        cli_module.main(
            [
                "--token-file",
                _token_file(tmp_path),
                "--json",
                "save",
                "clip",
                "--source",
                "cloud",
                "--serial",
                "CAM123",
                "--channel",
                "2",
                "--duration",
                "3s",
                "--max-packets",
                "4",
                "--output",
                str(output_path),
                "--ffmpeg-path",
                "/usr/bin/ffmpeg",
                "--client-type",
                "7",
                "--token-index",
                "1",
                "--no-refresh-vtm",
            ]
        )
        == 0
    )

    client = fake_client.instances[0]
    assert client.save_clip_request == {
        "serial": "CAM123",
        "output": str(output_path),
        "source": "cloud",
        "output_format": "mpegts",
        "duration_seconds": HCNETSDK_TEST_SAVE_DURATION,
        "max_packets": 4,
        "channel": 2,
        "ffmpeg_path": "/usr/bin/ffmpeg",
        "decrypt_video": False,
        "nalu_header_size": 0,
        "cas_serial": None,
        "timeout": HCNETSDK_DEFAULT_SAVE_TIMEOUT,
        "smscode": None,
        "host": None,
        "command_port": None,
        "hcnetsdk_command_frames": None,
        "hcnetsdk_command_plan": None,
        "hcnetsdk_command_generated_plan": None,
        "hcnetsdk_command_password": None,
        "hcnetsdk_local_ip": None,
        "hcnetsdk_read_response_after_each": True,
        "hcnetsdk_command_metadata_callback": None,
        "hcnetsdk_h264_skip_initial_idr_windows": 0,
        "hcnetsdk_h264_trim_to_clean_idr_window": False,
        "hcnetsdk_h264_clean_idr_preroll_seconds": 0.0,
        "hcnetsdk_h264_clean_idr_max_windows": 32,
        "hcnetsdk_h264_wait_for_clean_idr_window": False,
        "hcnetsdk_h264_clean_idr_wait_seconds": 60.0,
        "cloud_client_type": 7,
        "cloud_token_index": 1,
        "cloud_refresh_vtm": False,
    }
    assert output_path.read_bytes() == MPEGTS_PAYLOAD
    assert json.loads(capsys.readouterr().out) == {
        "ok": True,
        "kind": "clip",
        "serial": "CAM123",
        "channel": 2,
        "output": str(output_path),
        "bytes": len(MPEGTS_PAYLOAD),
        "source": "cloud",
        "format": "mpegts",
        "duration_seconds": HCNETSDK_TEST_SAVE_DURATION,
        "content_type": "video/mp2t",
        "cloud_client_type": 7,
        "cloud_token_index": 1,
        "cloud_refresh_vtm": False,
    }


def test_save_clip_cloud_decrypt_keeps_sms_code_key_lookup(
    monkeypatch,
    tmp_path,
) -> None:
    fake_client = _install_fake_client(monkeypatch)
    output_path = tmp_path / "www" / "front.ts"

    assert (
        cli_module.main(
            [
                "--token-file",
                _token_file(tmp_path),
                "save",
                "clip",
                "--source",
                "cloud",
                "--serial",
                "CAM123",
                "--output",
                str(output_path),
                "--decrypt-video",
                "--sms-code",
                "654321",
            ]
        )
        == 0
    )

    request = fake_client.instances[0].save_clip_request
    assert request["source"] == "cloud"
    assert request["decrypt_video"] is True
    assert request["smscode"] == "654321"
    assert "media_key" not in request


def test_save_image_triggers_capture_and_downloads_url(
    monkeypatch,
    tmp_path,
    capsys,
) -> None:
    fake_client = _install_fake_client(monkeypatch)
    output_path = tmp_path / "snapshots" / "front.jpg"

    assert (
        cli_module.main(
            [
                "--token-file",
                _token_file(tmp_path),
                "--json",
                "save",
                "image",
                "--serial",
                "CAM123",
                "--channel",
                "2",
                "--output",
                str(output_path),
                "--sms-code",
                "654321",
            ]
        )
        == 0
    )

    client = fake_client.instances[0]
    assert client.capture_picture_request == {
        "serial": "CAM123",
        "channel": 2,
        "max_retries": 1,
    }
    assert client.download_alarm_image_request == {
        "image_url": "https://image.example.test/capture.jpg",
        "serial": "CAM123",
        "encryption_key": None,
        "smscode": "654321",
        "decrypt": True,
        "max_retries": 1,
    }
    assert output_path.read_bytes() == IMAGE_PAYLOAD
    assert json.loads(capsys.readouterr().out) == {
        "ok": True,
        "kind": "image",
        "serial": "CAM123",
        "channel": 2,
        "output": str(output_path),
        "bytes": len(IMAGE_PAYLOAD),
        "content_type": "image/jpeg",
        "image_url": "https://image.example.test/capture.jpg",
        "triggered_capture": True,
    }


def test_save_image_can_download_existing_url_without_capture(
    monkeypatch,
    tmp_path,
) -> None:
    fake_client = _install_fake_client(monkeypatch)
    output_path = tmp_path / "alarm.jpg"

    assert (
        cli_module.main(
            [
                "--token-file",
                _token_file(tmp_path),
                "save",
                "image",
                "--serial",
                "CAM123",
                "--output",
                str(output_path),
                "--image-url",
                "https://image.example.test/alarm.jpg",
                "--no-decrypt",
            ]
        )
        == 0
    )

    client = fake_client.instances[0]
    assert client.capture_picture_request == {}
    assert client.download_alarm_image_request["image_url"] == "https://image.example.test/alarm.jpg"
    assert client.download_alarm_image_request["decrypt"] is False


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

    def fake_decrypt(data: bytes, key: str, *, nalu_header_size: int | None) -> bytes:
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

    assert decrypt_calls == [{"data": b"encrypted", "key": "camera-key", "nalu_header_size": None}]
    assert remux_calls == [{"data": b"decrypted", "ffmpeg_path": "ffmpeg"}]
    assert output_file.read_bytes() == MPEGTS_PAYLOAD


def test_stream_dump_can_depacketize_rtp_hevc_before_decrypt_remux(
    monkeypatch,
    tmp_path,
) -> None:
    _install_fake_client(monkeypatch)

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
                    length=15,
                    sequence=1,
                    message_code=0,
                    body=(
                        b"\x80\x60\x00\x01"
                        b"\x00\x00\x00\x01"
                        b"\x00\x00\x00\x02"
                        b"\x40\x01vps"
                    ),
                )
            ]

    monkeypatch.setattr(
        cli_module,
        "open_cloud_stream",
        lambda *_args, **_kwargs: FakeStream(),
    )

    decrypt_calls: list[dict[str, Any]] = []

    def fake_decrypt_annexb(
        client: Any,
        serial: str,
        data: bytes,
        *,
        codec: str,
    ) -> bytes:
        decrypt_calls.append(
            {
                "client": client,
                "serial": serial,
                "data": data,
                "codec": codec,
            }
        )
        return b"decrypted-hevc"

    remux_calls: list[dict[str, Any]] = []

    def fake_remux_elementary(
        data: bytes,
        output: BinaryIO,
        *,
        ffmpeg_path: str,
        codec: str,
    ) -> None:
        remux_calls.append({"data": data, "ffmpeg_path": ffmpeg_path, "codec": codec})
        output.write(MPEGTS_PAYLOAD)

    monkeypatch.setattr(cli_module, "_decrypt_annexb_video_bytes", fake_decrypt_annexb)
    monkeypatch.setattr(
        cli_module,
        "_remux_elementary_video_bytes_to_mpegts",
        fake_remux_elementary,
    )
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

    client = decrypt_calls[0]["client"]
    assert decrypt_calls == [
        {
            "client": client,
            "serial": "CAM123",
            "data": b"\x00\x00\x00\x01\x40\x01vps",
            "codec": "hevc",
        }
    ]
    assert remux_calls == [
        {"data": b"decrypted-hevc", "ffmpeg_path": "ffmpeg", "codec": "hevc"}
    ]
    assert output_file.read_bytes() == MPEGTS_PAYLOAD


def test_stream_dump_detects_h264_non_idr_before_hevc_header_overlap(
    monkeypatch,
    tmp_path,
) -> None:
    _install_fake_client(monkeypatch)

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
                    length=17,
                    sequence=1,
                    message_code=0,
                    body=(
                        b"\x80\x60\x00\x01"
                        b"\x00\x00\x00\x01"
                        b"\x00\x00\x00\x02"
                        b"\x41h264"
                    ),
                )
            ]

    monkeypatch.setattr(
        cli_module,
        "open_cloud_stream",
        lambda *_args, **_kwargs: FakeStream(),
    )
    decrypt_calls: list[dict[str, Any]] = []

    def fake_decrypt_annexb(
        _client: Any,
        _serial: str,
        data: bytes,
        *,
        codec: str,
    ) -> bytes:
        decrypt_calls.append({"data": data, "codec": codec})
        return b"decrypted-h264"

    remux_calls: list[dict[str, Any]] = []

    def fake_remux_elementary(
        data: bytes,
        output: BinaryIO,
        *,
        ffmpeg_path: str,
        codec: str,
    ) -> None:
        remux_calls.append({"data": data, "ffmpeg_path": ffmpeg_path, "codec": codec})
        output.write(MPEGTS_PAYLOAD)

    monkeypatch.setattr(cli_module, "_decrypt_annexb_video_bytes", fake_decrypt_annexb)
    monkeypatch.setattr(
        cli_module,
        "_remux_elementary_video_bytes_to_mpegts",
        fake_remux_elementary,
    )
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

    assert decrypt_calls == [
        {"data": b"\x00\x00\x00\x01\x41h264", "codec": "h264"}
    ]
    assert remux_calls == [
        {"data": b"decrypted-h264", "ffmpeg_path": "ffmpeg", "codec": "h264"}
    ]
    assert output_file.read_bytes() == MPEGTS_PAYLOAD


def test_stream_dump_uses_requested_decrypt_codec_for_rtp_payload(
    monkeypatch,
    tmp_path,
) -> None:
    _install_fake_client(monkeypatch)

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
                    length=17,
                    sequence=1,
                    message_code=0,
                    body=(
                        b"\x80\x60\x00\x01"
                        b"\x00\x00\x00\x01"
                        b"\x00\x00\x00\x02"
                        b"\x41h264"
                    ),
                )
            ]

    monkeypatch.setattr(
        cli_module,
        "open_cloud_stream",
        lambda *_args, **_kwargs: FakeStream(),
    )
    decrypt_calls: list[dict[str, Any]] = []

    def fake_decrypt_annexb(
        _client: Any,
        _serial: str,
        data: bytes,
        *,
        codec: str,
    ) -> bytes:
        decrypt_calls.append({"data": data, "codec": codec})
        return b"decrypted-h264"

    remux_calls: list[dict[str, Any]] = []

    def fake_remux_elementary(
        data: bytes,
        output: BinaryIO,
        *,
        ffmpeg_path: str,
        codec: str,
    ) -> None:
        remux_calls.append({"data": data, "ffmpeg_path": ffmpeg_path, "codec": codec})
        output.write(MPEGTS_PAYLOAD)

    monkeypatch.setattr(cli_module, "_decrypt_annexb_video_bytes", fake_decrypt_annexb)
    monkeypatch.setattr(
        cli_module,
        "_remux_elementary_video_bytes_to_mpegts",
        fake_remux_elementary,
    )
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
                "--decrypt-codec",
                "encrypted-header",
                "--output",
                str(output_file),
            ]
        )
        == 0
    )

    assert decrypt_calls == [
        {"data": b"\x00\x00\x00\x01\x41h264", "codec": "encrypted-header"}
    ]
    assert remux_calls == [
        {"data": b"decrypted-h264", "ffmpeg_path": "ffmpeg", "codec": "h264"}
    ]
    assert output_file.read_bytes() == MPEGTS_PAYLOAD


def test_rtp_payload_video_codec_keeps_h264_slice_bytes_before_hevc_ap_fu() -> None:
    assert cli_module._rtp_payload_video_codec(b"\x61h264") == "h264"  # noqa: SLF001
    assert cli_module._rtp_payload_video_codec(b"\x63h264") == "h264"  # noqa: SLF001
    assert cli_module._rtp_payload_video_codec(b"\x62\x01\x85hevc-fu") == "hevc"  # noqa: SLF001


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
            "decrypt_codec": "auto",
            "max_packets": 4,
        }
    ]
    assert client.closed is True


def test_stream_proxy_path_defaults_to_serial() -> None:
    assert cli_module._normalize_stream_proxy_path(None, "CAM123") == "/CAM123.ts"  # noqa: SLF001
    assert cli_module._normalize_stream_proxy_path("camera.ts", "CAM123") == "/camera.ts"  # noqa: SLF001


def test_local_sdk_dump_runs_without_cloud_auth(monkeypatch, tmp_path) -> None:
    output_path = tmp_path / "local.ps"
    metadata_path = tmp_path / "local.json"
    calls: list[dict[str, Any]] = []

    class FakeLocalStream:
        closed = False

        def __enter__(self) -> FakeLocalStream:
            return self

        def __exit__(self, *_args: object) -> None:
            self.closed = True

    def fake_build(args: Any, client: Any = None) -> FakeLocalStream:
        assert client is None
        calls.append(
            {
                "serial": args.serial,
                "host": args.host,
                "format": args.format,
                "max_packets": args.max_packets,
                "operation_code": args.operation_code,
                "cas_key": args.cas_key,
            }
        )
        return FakeLocalStream()

    def fake_copy(stream: FakeLocalStream, output: BinaryIO, **kwargs: Any) -> None:
        calls.append({"stream": stream, **kwargs})
        output.write(LOCAL_SDK_TEST_PAYLOAD)

    monkeypatch.setattr(cli_module, "_build_local_sdk_cli_stream", fake_build)
    monkeypatch.setattr(cli_module, "copy_local_stream_to_mpegps", fake_copy)

    assert (
        cli_module.main(
            [
                "stream",
                "local-sdk-dump",
                "--host",
                "192.0.2.10",
                "--serial",
                "CAM123456",
                "--operation-code",
                "0123456",
                "--cas-key",
                "1234567890abcdef",
                "--format",
                "mpegps",
                "--max-packets",
                "2",
                "--output",
                str(output_path),
                "--metadata-output",
                str(metadata_path),
            ]
        )
        == 0
    )

    assert calls[0] == {
        "serial": "CAM123456",
        "host": "192.0.2.10",
        "format": "mpegps",
        "max_packets": 2,
        "operation_code": "0123456",
        "cas_key": "1234567890abcdef",
    }
    assert calls[1]["max_packets"] == 2
    assert calls[1]["duration_seconds"] == LOCAL_SDK_DEFAULT_DURATION
    assert output_path.read_bytes() == LOCAL_SDK_TEST_PAYLOAD
    assert json.loads(metadata_path.read_text(encoding="utf-8")) == {
        "bootstrap_complete": False
    }


def test_local_sdk_dump_can_decrypt_mpegps_without_cloud_auth(
    monkeypatch,
    tmp_path,
) -> None:
    output_path = tmp_path / "local.ps"
    copy_calls: list[dict[str, Any]] = []

    class FakeLocalStream:
        bootstrap = None

        def __enter__(self) -> FakeLocalStream:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    def fake_copy(
        stream: FakeLocalStream,
        output: BinaryIO,
        media_key: str | bytes,
        **kwargs: Any,
    ) -> None:
        copy_calls.append({"stream": stream, "media_key": media_key, **kwargs})
        output.write(NATIVE_TRANSFORMED_PAYLOAD)

    monkeypatch.setattr(cli_module, "_build_local_sdk_cli_stream", lambda *_args: FakeLocalStream())
    monkeypatch.setattr(cli_module, "copy_local_stream_to_decrypted_mpegps", fake_copy)

    assert (
        cli_module.main(
            [
                "stream",
                "local-sdk-dump",
                "--host",
                "192.0.2.10",
                "--serial",
                "CAM123456",
                "--operation-code",
                "0123456",
                "--cas-key",
                "1234567890abcdef",
                "--media-key",
                "media-secret",
                "--decrypt-video",
                "--decrypt-codec",
                "h264-encrypted-header",
                "--format",
                "mpegps",
                "--max-packets",
                "1",
                "--output",
                str(output_path),
            ]
        )
        == 0
    )

    assert copy_calls[0]["media_key"] == "media-secret"
    assert copy_calls[0]["nalu_header_size"] == 0
    assert copy_calls[0]["max_packets"] == 1
    assert copy_calls[0]["duration_seconds"] == LOCAL_SDK_DEFAULT_DURATION
    assert output_path.read_bytes() == NATIVE_TRANSFORMED_PAYLOAD


def test_local_sdk_dump_accepts_hex_media_key(
    monkeypatch,
    tmp_path,
) -> None:
    output_path = tmp_path / "local.ps"
    copy_calls: list[dict[str, Any]] = []

    class FakeLocalStream:
        bootstrap = None

        def __enter__(self) -> FakeLocalStream:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    def fake_copy(
        stream: FakeLocalStream,
        output: BinaryIO,
        media_key: str | bytes,
        **kwargs: Any,
    ) -> None:
        copy_calls.append({"stream": stream, "media_key": media_key, **kwargs})
        output.write(NATIVE_TRANSFORMED_PAYLOAD)

    monkeypatch.setattr(cli_module, "_build_local_sdk_cli_stream", lambda *_args: FakeLocalStream())
    monkeypatch.setattr(cli_module, "copy_local_stream_to_decrypted_mpegps", fake_copy)

    assert (
        cli_module.main(
            [
                "stream",
                "local-sdk-dump",
                "--host",
                "192.0.2.10",
                "--serial",
                "CAM123456",
                "--operation-code",
                "0123456",
                "--cas-key",
                "1234567890abcdef",
                "--media-key-hex",
                "000102030405060708090a0b0c0d0e0f",
                "--decrypt-video",
                "--decrypt-codec",
                "hevc-encrypted-header",
                "--format",
                "mpegps",
                "--max-packets",
                "1",
                "--output",
                str(output_path),
            ]
        )
        == 0
    )

    assert copy_calls[0]["media_key"] == bytes(range(16))
    assert copy_calls[0]["nalu_header_size"] == 0
    assert output_path.read_bytes() == NATIVE_TRANSFORMED_PAYLOAD


def test_local_sdk_dump_help_documents_media_key_sources(capsys) -> None:
    try:
        cli_module.main(["stream", "local-sdk-dump", "--help"])
    except SystemExit as err:
        assert err.code == 0

    output = capsys.readouterr().out
    assert "--media-key-hex" in output
    assert "EZVIZ_LOCAL_MEDIA_KEY_HEX" in output
    assert "--credentials-file" in output
    assert "authenticated client" in output


def test_local_sdk_dump_ecdh_uses_ecdh_stream_writer(monkeypatch, tmp_path) -> None:
    output_path = tmp_path / "local_sdk_ecdh.ps"
    calls: list[dict[str, Any]] = []

    class FakeLocalSdkEcdhStream:
        bootstrap = None

        def __enter__(self) -> FakeLocalSdkEcdhStream:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    def fake_build(args: Any, client: Any = None) -> FakeLocalSdkEcdhStream:
        assert client is None
        calls.append(
            {
                "serial": args.serial,
                "host": args.host,
                "receiver_port": args.local_sdk_ecdh_receiver_port,
                "send_init": args.local_sdk_ecdh_send_init,
                "pre_start_sequence": args.pre_start_sequence,
                "preview_sequence": args.preview_sequence,
                "stream_sequence": args.stream_sequence,
                "max_prefix_bytes": args.max_prefix_bytes,
            }
        )
        return FakeLocalSdkEcdhStream()

    def fake_copy(stream: FakeLocalSdkEcdhStream, output: BinaryIO, **kwargs: Any) -> None:
        calls.append({"stream": stream, **kwargs})
        output.write(LOCAL_SDK_TEST_PAYLOAD)

    monkeypatch.setattr(cli_module, "_build_local_sdk_ecdh_cli_stream", fake_build)
    monkeypatch.setattr(cli_module, "copy_local_sdk_ecdh_stream_to_mpegps", fake_copy)

    assert (
        cli_module.main(
            [
                "stream",
                "local-sdk-dump",
                "--local-sdk-ecdh",
                "--host",
                "192.0.2.10",
                "--serial",
                "CAM123456",
                "--operation-code",
                "0123456",
                "--cas-key",
                "1234567890abcdef",
                "--format",
                "mpegps",
                "--max-packets",
                "2",
                "--local-sdk-ecdh-receiver-port",
                "10105",
                "--local-sdk-ecdh-send-init",
                "--pre-start-sequence",
                "27",
                "--preview-sequence",
                "28",
                "--stream-sequence",
                "29",
                "--max-prefix-bytes",
                "8192",
                "--output",
                str(output_path),
            ]
        )
        == 0
    )

    assert calls[0] == {
        "serial": "CAM123456",
        "host": "192.0.2.10",
        "receiver_port": 10105,
        "send_init": True,
        "pre_start_sequence": 27,
        "preview_sequence": 28,
        "stream_sequence": 29,
        "max_prefix_bytes": 8192,
    }
    assert calls[1]["max_packets"] == 2
    assert calls[1]["duration_seconds"] == LOCAL_SDK_DEFAULT_DURATION
    assert output_path.read_bytes() == LOCAL_SDK_TEST_PAYLOAD


def test_local_sdk_dump_ecdh_defaults_to_mpegps(monkeypatch, tmp_path) -> None:
    output_path = tmp_path / "local_sdk_ecdh.ps"
    calls: list[dict[str, Any]] = []

    class FakeLocalSdkEcdhStream:
        bootstrap = None

        def __enter__(self) -> FakeLocalSdkEcdhStream:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    def fake_build(args: Any, client: Any = None) -> FakeLocalSdkEcdhStream:
        assert client is None
        calls.append({"format": args.format})
        return FakeLocalSdkEcdhStream()

    def fake_copy(stream: FakeLocalSdkEcdhStream, output: BinaryIO, **kwargs: Any) -> None:
        calls.append({"stream": stream, **kwargs})
        output.write(LOCAL_SDK_TEST_PAYLOAD)

    monkeypatch.setattr(cli_module, "_build_local_sdk_ecdh_cli_stream", fake_build)
    monkeypatch.setattr(cli_module, "copy_local_sdk_ecdh_stream_to_mpegps", fake_copy)

    assert (
        cli_module.main(
            [
                "stream",
                "local-sdk-dump",
                "--local-sdk-ecdh",
                "--host",
                "192.0.2.10",
                "--serial",
                "CAM123456",
                "--operation-code",
                "0123456",
                "--cas-key",
                "1234567890abcdef",
                "--output",
                str(output_path),
            ]
        )
        == 0
    )

    assert calls[0] == {"format": "mpegps"}
    assert calls[1]["duration_seconds"] == LOCAL_SDK_DEFAULT_DURATION
    assert output_path.read_bytes() == LOCAL_SDK_TEST_PAYLOAD


def test_local_sdk_dump_ecdh_forwards_max_prefix_bytes(monkeypatch, tmp_path) -> None:
    output_path = tmp_path / "local_sdk_ecdh.ps"
    calls: list[dict[str, Any]] = []

    class FakeLocalSdkEcdhStream:
        bootstrap = None

        def __enter__(self) -> FakeLocalSdkEcdhStream:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    def fake_open_local_sdk_ecdh_stream(
        endpoint: Any,
        device_info: Any,
        **kwargs: Any,
    ) -> FakeLocalSdkEcdhStream:
        calls.append(
            {
                "serial": endpoint.serial,
                "host": endpoint.host,
                "operation_code": device_info.operation_code,
                **kwargs,
            }
        )
        return FakeLocalSdkEcdhStream()

    def fake_copy(stream: FakeLocalSdkEcdhStream, output: BinaryIO, **kwargs: Any) -> None:
        calls.append({"stream": stream, **kwargs})
        output.write(LOCAL_SDK_TEST_PAYLOAD)

    monkeypatch.setattr(
        cli_module,
        "open_local_sdk_ecdh_stream",
        fake_open_local_sdk_ecdh_stream,
    )
    monkeypatch.setattr(cli_module, "copy_local_sdk_ecdh_stream_to_mpegps", fake_copy)

    assert (
        cli_module.main(
            [
                "stream",
                "local-sdk-dump",
                "--local-sdk-ecdh",
                "--host",
                "192.0.2.10",
                "--serial",
                "CAM123456",
                "--operation-code",
                "0123456",
                "--cas-key",
                "1234567890abcdef",
                "--pre-start-sequence",
                "27",
                "--preview-sequence",
                "28",
                "--stream-sequence",
                "29",
                "--max-prefix-bytes",
                "8192",
                "--output",
                str(output_path),
            ]
        )
        == 0
    )

    assert calls[0]["serial"] == "CAM123456"
    assert calls[0]["host"] == "192.0.2.10"
    assert calls[0]["operation_code"] == "0123456"
    assert calls[0]["pre_start_sequence"] == 27
    assert calls[0]["preview_sequence"] == 28
    assert calls[0]["stream_setup_sequence"] == 29
    assert calls[0]["max_prefix_bytes"] == 8192
    assert calls[1]["duration_seconds"] == LOCAL_SDK_DEFAULT_DURATION
    assert output_path.read_bytes() == LOCAL_SDK_TEST_PAYLOAD


def test_local_sdk_dump_accepts_credentials_file(monkeypatch, tmp_path) -> None:
    credentials_path = tmp_path / "local-sdk-credentials.json"
    output_path = tmp_path / "local.ps"
    credentials_path.write_text(
        json.dumps(
            {
                "serial": "CAM123456",
                "endpoint": {
                    "host": "192.0.2.10",
                    "command_port": 19010,
                    "stream_port": 19020,
                },
                "cas": {
                    "operation_code": "0123456",
                    "key": "1234567890abcdef",
                    "encrypt_type": 1,
                },
                "media_key_hex": "000102030405060708090a0b0c0d0e0f",
            }
        ),
        encoding="utf-8",
    )
    build_calls: list[dict[str, Any]] = []
    copy_calls: list[dict[str, Any]] = []

    class FakeLocalStream:
        bootstrap = None

        def __enter__(self) -> FakeLocalStream:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    def fake_open_local_sdk_stream(
        endpoint: Any,
        device_info: Any,
        _preview_request: Any,
        **_kwargs: Any,
    ) -> FakeLocalStream:
        build_calls.append(
            {
                "serial": endpoint.serial,
                "host": endpoint.host,
                "command_port": endpoint.command_port,
                "stream_port": endpoint.stream_port,
                "operation_code": device_info.operation_code,
                "cas_key": device_info.key,
                "encrypt_type": device_info.encrypt_type,
            }
        )
        return FakeLocalStream()

    def fake_copy(
        stream: FakeLocalStream,
        output: BinaryIO,
        media_key: str | bytes,
        **kwargs: Any,
    ) -> None:
        copy_calls.append({"stream": stream, "media_key": media_key, **kwargs})
        output.write(NATIVE_TRANSFORMED_PAYLOAD)

    monkeypatch.setattr(cli_module, "open_local_sdk_stream", fake_open_local_sdk_stream)
    monkeypatch.setattr(cli_module, "copy_local_stream_to_decrypted_mpegps", fake_copy)

    assert (
        cli_module.main(
            [
                "stream",
                "local-sdk-dump",
                "--credentials-file",
                str(credentials_path),
                "--decrypt-video",
                "--decrypt-codec",
                "encrypted-header",
                "--format",
                "mpegps",
                "--max-packets",
                "1",
                "--output",
                str(output_path),
            ]
        )
        == 0
    )

    assert build_calls == [
        {
            "serial": "CAM123456",
            "host": "192.0.2.10",
            "command_port": 19010,
            "stream_port": 19020,
            "operation_code": "0123456",
            "cas_key": "1234567890abcdef",
            "encrypt_type": 1,
        }
    ]
    assert copy_calls[0]["media_key"] == bytes(range(16))
    assert copy_calls[0]["nalu_header_size"] == 0
    assert output_path.read_bytes() == NATIVE_TRANSFORMED_PAYLOAD


def test_local_sdk_dump_can_decrypt_before_mpegts_remux(
    monkeypatch,
    tmp_path,
) -> None:
    output_path = tmp_path / "local.ts"
    copy_calls: list[dict[str, Any]] = []

    class FakeLocalStream:
        bootstrap = None

        def __enter__(self) -> FakeLocalStream:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    def fake_environ_get(name: str) -> str | None:
        return {
            "EZVIZ_LOCAL_MEDIA_KEY": "env-media-secret",
        }.get(name)

    def fake_copy(
        stream: FakeLocalStream,
        output: BinaryIO,
        media_key: str | bytes,
        **kwargs: Any,
    ) -> None:
        copy_calls.append({"stream": stream, "media_key": media_key, **kwargs})
        output.write(MPEGTS_PAYLOAD)

    monkeypatch.setattr(cli_module, "_build_local_sdk_cli_stream", lambda *_args: FakeLocalStream())
    monkeypatch.setattr(cli_module, "os_environ_get", fake_environ_get)
    monkeypatch.setattr(cli_module, "copy_local_stream_to_decrypted_mpegts", fake_copy)

    assert (
        cli_module.main(
            [
                "stream",
                "local-sdk-dump",
                "--host",
                "192.0.2.10",
                "--serial",
                "CAM123456",
                "--operation-code",
                "0123456",
                "--cas-key",
                "1234567890abcdef",
                "--decrypt-video",
                "--format",
                "mpegts",
                "--max-packets",
                "1",
                "--output",
                str(output_path),
                "--ffmpeg-path",
                "custom-ffmpeg",
            ]
        )
        == 0
    )

    assert copy_calls[0]["media_key"] == "env-media-secret"
    assert copy_calls[0]["ffmpeg_path"] == "custom-ffmpeg"
    assert copy_calls[0]["nalu_header_size"] is None
    assert copy_calls[0]["max_packets"] == 1
    assert output_path.read_bytes() == MPEGTS_PAYLOAD


def test_local_sdk_dump_fetches_cloud_media_key_with_token(
    monkeypatch,
    tmp_path,
) -> None:
    fake_client = _install_fake_client(monkeypatch)
    output_path = tmp_path / "local.ps"
    build_clients: list[Any] = []
    copy_calls: list[dict[str, Any]] = []

    class FakeLocalStream:
        bootstrap = None

        def __enter__(self) -> FakeLocalStream:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    def fake_build(args: Any, client: Any = None) -> FakeLocalStream:
        build_clients.append(client)
        return FakeLocalStream()

    def fake_copy(
        stream: FakeLocalStream,
        output: BinaryIO,
        media_key: str | bytes,
        **kwargs: Any,
    ) -> None:
        copy_calls.append({"stream": stream, "media_key": media_key, **kwargs})
        output.write(NATIVE_TRANSFORMED_PAYLOAD)

    monkeypatch.setattr(cli_module, "_build_local_sdk_cli_stream", fake_build)
    monkeypatch.setattr(cli_module, "copy_local_stream_to_decrypted_mpegps", fake_copy)

    assert (
        cli_module.main(
            [
                "--token-file",
                _token_file(tmp_path),
                "stream",
                "local-sdk-dump",
                "--host",
                "192.0.2.10",
                "--serial",
                "CAM123456",
                "--operation-code",
                "0123456",
                "--cas-key",
                "1234567890abcdef",
                "--decrypt-video",
                "--format",
                "mpegps",
                "--max-packets",
                "1",
                "--output",
                str(output_path),
            ]
        )
        == 0
    )

    assert build_clients == [fake_client.instances[0]]
    assert fake_client.instances[0].cam_key_request == {
        "serial": "CAM123456",
        "max_retries": 1,
    }
    assert fake_client.instances[0].closed is True
    assert copy_calls[0]["media_key"] == "camera-secret"
    assert output_path.read_bytes() == NATIVE_TRANSFORMED_PAYLOAD


def test_local_sdk_dump_reads_secret_environment_fallbacks(monkeypatch, tmp_path) -> None:
    pre_start = tmp_path / "pre-start.bin"
    pre_start.write_bytes(LOCAL_SDK_PRE_START_BODY)

    def fake_environ_get(name: str) -> str | None:
        return {
            "EZVIZ_LOCAL_OPERATION_CODE": "0123456",
            "EZVIZ_LOCAL_CAS_KEY": "1234567890abcdef",
        }.get(name)

    monkeypatch.setattr(cli_module, "os_environ_get", fake_environ_get)

    stream = cli_module._build_local_sdk_cli_stream(  # noqa: SLF001
        argparse.Namespace(
            host="192.0.2.10",
            serial="CAM123456",
            command_port=9010,
            stream_port=9020,
            channel=1,
            operation_code=None,
            cas_key=None,
            fetch_cas=False,
            encrypt_type=1,
            uuid=None,
            timestamp=None,
            identifier=None,
            nat_address="",
            nat_port=0,
            upnp_address="",
            upnp_port=0,
            inner_address="192.0.2.20",
            inner_port=9020,
            receiver_shape="app",
            receiver_stream_type="MAIN",
            receiver_port=10101,
            receiver_server_type=1,
            receiver_new_stream_type=1,
            receiver_trans_proto="TCP",
            receiver_ex_port=10101,
            auth_biz_code="biz=1",
            auth_interval=180,
            is_encrypt="TRUE",
            udt=None,
            nat=None,
            port_guess_type=None,
            setup_timeout=None,
            heartbeat_interval=None,
            pre_start_body_file=str(pre_start),
            pre_start_sequence=27,
            preview_sequence=28,
            stream_sequence=29,
            stream_rate=1,
            stream_mode=-1,
            socket_timeout=5.0,
            max_prefix_bytes=128,
        )
    )

    assert stream.sdk_client.endpoint.host == "192.0.2.10"
    assert stream.sdk_client.device_info.operation_code == "0123456"
    assert stream.sdk_client.device_info.key == "1234567890abcdef"
    assert stream.pre_start_body == LOCAL_SDK_PRE_START_BODY
    assert stream.max_prefix_bytes == 128
    assert stream.preview_request.receiver_info.port == 10101


def test_local_sdk_dump_can_build_structured_receiver_shape(monkeypatch) -> None:
    def fake_environ_get(name: str) -> str | None:
        return {
            "EZVIZ_LOCAL_OPERATION_CODE": "0123456",
            "EZVIZ_LOCAL_CAS_KEY": "1234567890abcdef",
            "EZVIZ_LOCAL_UUID": "uuid",
            "EZVIZ_LOCAL_TIMESTAMP": "123456",
        }.get(name)

    monkeypatch.setattr(cli_module, "os_environ_get", fake_environ_get)

    stream = cli_module._build_local_sdk_cli_stream(  # noqa: SLF001
        argparse.Namespace(
            host="192.0.2.10",
            serial="CAM123456",
            command_port=9010,
            stream_port=9020,
            channel=1,
            operation_code=None,
            cas_key=None,
            fetch_cas=False,
            encrypt_type=1,
            uuid=None,
            timestamp=None,
            identifier="ident",
            nat_address="192.0.2.10",
            nat_port=9010,
            upnp_address="",
            upnp_port=0,
            inner_address="192.0.2.20",
            inner_port=9020,
            receiver_shape="structured",
            receiver_stream_type="MAIN",
            receiver_port=10101,
            receiver_server_type=1,
            receiver_new_stream_type=1,
            receiver_trans_proto="TCP",
            receiver_ex_port=10101,
            auth_biz_code="biz=1",
            auth_interval=180,
            is_encrypt="TRUE",
            udt=1,
            nat=2,
            port_guess_type=5,
            setup_timeout=30,
            heartbeat_interval=10,
            pre_start_body_file=None,
            pre_start_sequence=27,
            preview_sequence=28,
            stream_sequence=29,
            stream_rate=1,
            stream_mode=-1,
            socket_timeout=5.0,
            max_prefix_bytes=128,
        )
    )

    body = stream.preview_request.to_xml()

    assert STRUCTURED_RECEIVER_INNER_ADDRESS_XML in body
    assert STRUCTURED_RECEIVER_INNER_PORT_XML in body
    assert STRUCTURED_RECEIVER_AUTH_XML in body
    assert STRUCTURED_RECEIVER_UUID_XML in body
    assert STRUCTURED_RECEIVER_TIMESTAMP_XML in body
    assert APP_RECEIVER_INFO_XML_PREFIX not in body


def test_local_sdk_metadata_reports_first_media_payload_length() -> None:
    stream = argparse.Namespace(
        sdk_client=argparse.Namespace(
            endpoint=argparse.Namespace(
                serial="CAM123456",
                host="192.0.2.10",
                command_port=9010,
                stream_port=9020,
            )
        ),
        bootstrap=argparse.Namespace(
            pre_start=None,
            preview=None,
            stream_setup=None,
            first_media=argparse.Namespace(
                prefix=b"abc",
                frame=argparse.Namespace(
                    header=argparse.Namespace(channel=0, payload_length=123),
                    payload=b"123",
                ),
            ),
        ),
        packet_summary={
            "packet_count": 1,
            "sample_limit": 32,
            "samples": [{"index": 0, "length": 123}],
        },
    )

    metadata = cli_module._local_sdk_stream_metadata(stream)  # noqa: SLF001

    assert metadata["packets"] == {
        "packet_count": 1,
        "sample_limit": 32,
        "samples": [{"index": 0, "length": 123}],
    }
    assert metadata["first_media"] == {
        "prefix_length": 3,
        "prefix_sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "channel": 0,
        "payload_length": 123,
        "payload_sha256": (
            "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e"
            "998e86f7f7a27ae3"
        ),
    }


def test_local_sdk_metadata_finalizes_packet_summary_before_serializing() -> None:
    class Stream:
        def __init__(self) -> None:
            self.bootstrap = argparse.Namespace(
                pre_start=None,
                preview=None,
                stream_setup=None,
                first_media=None,
            )
            self.packet_summary = {"packet_count": 1, "samples": []}

        def finalize_packet_summary(self) -> None:
            self.packet_summary["idmx_h264"] = {"looks_like_idmx": True}

    metadata = cli_module._local_sdk_stream_metadata(Stream())  # noqa: SLF001

    assert metadata["packets"] == {
        "packet_count": 1,
        "samples": [],
        "idmx_h264": {"looks_like_idmx": True},
    }


def test_local_sdk_metadata_reports_command_port_exchanges() -> None:
    request = build_hcnetsdk_tcp_frame(
        b"\x01\x02\x03\x04",
        field_4=0x63000000,
        field_8=0x11223344,
        field_12=0x111050,
    )
    request_with_tail = build_hcnetsdk_tcp_frame(
        b"\x03\x00\x12\xac"
        b"\x12\x34\x56\x78"
        b"\x00\x00\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00\x07\xea"
        b"\x00\x00\x00\x05"
        b"\x00\x00\x00\x1f",
        field_4=0x63000000,
        field_8=0x55667788,
        field_12=0x111040,
    )
    response = parse_hcnetsdk_tcp_frame(
        build_hcnetsdk_tcp_frame(
            b"\x1e\xcd\x00\x01accepted-response",
            field_4=0x1ECD,
            field_8=1,
        )
    )
    stream = argparse.Namespace(
        bootstrap=argparse.Namespace(
            exchanges=(
                HcNetSdkCommandPortExchange(request, response),
                HcNetSdkCommandPortExchange(request_with_tail, None),
            ),
            first_media=None,
        ),
    )

    metadata = cli_module._local_sdk_stream_metadata(stream)  # noqa: SLF001

    assert metadata["command_port_exchanges"] == [
        {
            "request_length": 20,
            "request_command_family": 0x63000000,
            "request_auth_word": 0x11223344,
            "request_command_id": 0x111050,
            "response": {
                "total_length": 37,
                "field_4": 0x1ECD,
                "field_8": 1,
                "field_12": 0,
                "body_length": 21,
                "body_prefix_hex": "1ecd000161636365707465642d726573",
                "body_word_samples": [
                    {"offset": 0, "be": 0x1ECD0001},
                    {"offset": 4, "be": 0x61636365},
                    {"offset": 8, "be": 0x70746564},
                    {"offset": 12, "be": 0x2D726573},
                    {"offset": 16, "be": 0x706F6E73},
                ],
            },
        },
        {
            "request_length": 44,
            "request_command_family": 0x63000000,
            "request_auth_word": 0x55667788,
            "request_command_id": 0x111040,
            "request_body_tail_length": 12,
            "request_body_tail_word_samples": [
                {"offset": 0, "be": 0x7EA},
                {"offset": 4, "be": 5},
                {"offset": 8, "be": 0x1F},
            ],
            "response": None,
        },
    ]


def test_h264_annexb_summary_runs_without_credentials(tmp_path, capsys) -> None:
    h264_path = tmp_path / "sample.h264"
    h264_path.write_bytes(
        b"\x00\x00\x00\x01\x67\x4d\x00\x29"
        b"\x00\x00\x00\x01\x68\xee\x38\x80"
        b"\x00\x00\x00\x01\x65idr"
    )
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "sys.stdin.buffer.read()\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)

    assert (
        cli_module.main(
            [
                "--token-file",
                str(tmp_path / "missing.json"),
                "stream",
                "h264-annexb-summary",
                "--input",
                str(h264_path),
                "--max-units",
                "2",
                "--decode-idr-windows",
                "--ffmpeg-path",
                str(fake_ffmpeg),
            ]
        )
        == 0
    )

    output = json.loads(capsys.readouterr().out)
    assert output["units"]["nal_count"] == 3
    assert output["units"]["truncated"] is True
    assert output["idr_windows"]["idr_count"] == 1
    assert output["decode_idr_windows"] == [
        {
            "index": 0,
            "start_code_offset": 0,
            "input_bytes": 24,
            "returncode": 0,
            "decode_clean": True,
            "stderr": [],
        }
    ]


def test_hcnetsdk_command_dump_summary_runs_without_credentials(tmp_path, capsys) -> None:
    command_dir = tmp_path / "dumps"
    command_dir.mkdir()
    command_frame = build_hcnetsdk_tcp_frame(
        b"\xc0\x00\x02\x20\x12\x34\x56\x78" + (b"\x00" * 8) + b"\x00\x00\x04\x01",
        field_4=0x63000000,
        field_8=0x11223344,
        field_12=0x30000,
    )
    (command_dir / "ezviz-hcnetsdk-command-frame-0001-fd4-cmd0x30000.bin").write_bytes(
        command_frame
    )

    idmx_header = b"\x80\x60\x5d\x5c\x7d\x52\x2a\x3e\x55\x66\x77\x88"
    idmx_frames = [
        idmx_header + b"\x67\x4d\x00\x29",
        idmx_header + b"\x68\xee\x38\x80",
        idmx_header + b"\x65idr",
    ]
    media_payload = b"".join(
        len(idmx_frame).to_bytes(4, "little") + idmx_frame
        for idmx_frame in idmx_frames
    )
    media_record = (
        b"$\x00" + (len(media_payload) + 4).to_bytes(2, "little") + media_payload
    )
    inbound_media = tmp_path / "ezviz-hcnetsdk-inbound-media-fd4.bin"
    inbound_media.write_bytes(b"preface" + media_record)
    for index, idmx_frame in enumerate(idmx_frames):
        (command_dir / f"20260613070000-{index:04d}-playm4-input-16.bin").write_bytes(
            idmx_frame
        )
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "sys.stdin.buffer.read()\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)

    assert (
        cli_module.main(
            [
                "--token-file",
                str(tmp_path / "missing.json"),
                "stream",
                "hcnetsdk-command-dump-summary",
                "--command-frame-dir",
                str(command_dir),
                "--inbound-media-file",
                str(inbound_media),
                "--playm4-input-dir",
                str(command_dir),
                "--max-frames",
                "8",
                "--decode-idr-windows",
                "--ffmpeg-path",
                str(fake_ffmpeg),
            ]
        )
        == 0
    )

    output = json.loads(capsys.readouterr().out)
    assert output["command_frames"]["file_count"] == 1
    assert output["command_frames"]["command_counts"] == {"0x30000": 1}
    assert output["command_frames"]["samples"][0]["command_id"] == 0x30000
    assert output["inbound_media"]["frame_count"] == 1
    assert output["inbound_media"]["prefix_bytes"] == 7
    assert output["inbound_media"]["idmx_h264"]["looks_like_idmx"] is True
    assert output["inbound_media"]["idmx_h264"]["h264"]["sps"] == 1
    assert output["inbound_media"]["annexb_idr_windows"]["idr_count"] == 1
    assert output["inbound_media"]["decode_idr_windows"][0]["decode_clean"] is True
    assert output["playm4_input"]["file_count"] == 3
    assert output["playm4_input"]["idmx_h264"]["h264"]["sps"] == 1
    assert output["playm4_input"]["annexb_units"]["h264"]["sps"] == 1
    assert output["playm4_input"]["annexb_idr_windows"]["idr_count"] == 1
    assert output["playm4_input"]["decode_idr_windows"][0]["decode_clean"] is True


def test_hcnetsdk_command_dump_summary_reports_hevc_playm4_input(
    tmp_path,
    capsys,
) -> None:
    dump_dir = tmp_path / "dumps"
    dump_dir.mkdir()
    rtp_header = b"\x80\x60\x5d\x5c\x7d\x52\x2a\x3e\x55\x66\x77\x88"
    hevc_frames = [
        rtp_header + b"\x40\x01vps",
        rtp_header + b"\x42\x01sps",
        rtp_header + b"\x44\x01pps",
        rtp_header + b"\x26\x01idr",
    ]
    for index, idmx_frame in enumerate(hevc_frames):
        (dump_dir / f"20260613070000-{index:04d}-playm4-input-16.bin").write_bytes(
            idmx_frame
        )
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "sys.stdin.buffer.read()\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)

    assert (
        cli_module.main(
            [
                "--token-file",
                str(tmp_path / "missing.json"),
                "stream",
                "hcnetsdk-command-dump-summary",
                "--playm4-input-dir",
                str(dump_dir),
                "--max-frames",
                "8",
                "--decode-idr-windows",
                "--ffmpeg-path",
                str(fake_ffmpeg),
            ]
        )
        == 0
    )

    output = json.loads(capsys.readouterr().out)
    assert output["playm4_input"]["annexb_codec"] == "hevc"
    assert output["playm4_input"]["idmx_h264"]["hevc"]["media"] == 3
    assert output["playm4_input"]["annexb_irap_windows"]["irap_count"] == 1
    assert output["playm4_input"]["decode_irap_windows"][0]["decode_clean"] is True


def test_hcnetsdk_command_dump_summary_reports_native_annexb_label(
    tmp_path,
    capsys,
) -> None:
    dump_dir = tmp_path / "dumps"
    dump_dir.mkdir()
    chunks = [
        (
            b"\x00\x00\x00\x01\x67\x4d\x00\x29"
            + b"\x00\x00\x00\x01\x68\xee\x38\x80"
            + b"\x00\x00\x00\x01\x65idr"
        ),
        b"\x00\x00\x00\x01\x61p",
    ]
    for index, chunk in enumerate(chunks):
        (dump_dir / f"20260613070000-{index:04d}-playctrl-idmx-aes-frame-after-8.bin").write_bytes(
            chunk
        )
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "sys.stdin.buffer.read()\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)

    assert (
        cli_module.main(
            [
                "--token-file",
                str(tmp_path / "missing.json"),
                "stream",
                "hcnetsdk-command-dump-summary",
                "--native-annexb-dir",
                str(dump_dir),
                "--max-frames",
                "8",
                "--decode-idr-windows",
                "--ffmpeg-path",
                str(fake_ffmpeg),
            ]
        )
        == 0
    )

    output = json.loads(capsys.readouterr().out)
    assert output["native_annexb"]["label"] == "playctrl-idmx-aes-frame-after"
    assert output["native_annexb"]["codec"] == "h264"
    assert output["native_annexb"]["requested_codec"] == "auto"
    assert output["native_annexb"]["file_count"] == 2
    assert output["native_annexb"]["annexb_units"]["h264"]["sps"] == 1
    assert output["native_annexb"]["annexb_idr_windows"]["idr_count"] == 1
    assert output["native_annexb"]["decode_idr_windows"][0]["decode_clean"] is True
    assert output["native_annexb"]["decode_chunk_windows"][0]["decode_clean"] is True


def test_hcnetsdk_command_dump_summary_auto_detects_native_hevc(
    tmp_path,
    capsys,
) -> None:
    dump_dir = tmp_path / "dumps"
    dump_dir.mkdir()
    chunks = [
        (
            b"\x00\x00\x00\x01\x40\x01vps"
            + b"\x00\x00\x00\x01\x42\x01sps"
            + b"\x00\x00\x00\x01\x44\x01pps"
        ),
        b"\x00\x00\x00\x01\x26\x01irap",
    ]
    for index, chunk in enumerate(chunks):
        (dump_dir / f"20260613070000-{index:04d}-playctrl-idmx-aes-frame-after-8.bin").write_bytes(
            chunk
        )

    assert (
        cli_module.main(
            [
                "--token-file",
                str(tmp_path / "missing.json"),
                "stream",
                "hcnetsdk-command-dump-summary",
                "--native-annexb-dir",
                str(dump_dir),
                "--max-frames",
                "8",
            ]
        )
        == 0
    )

    output = json.loads(capsys.readouterr().out)
    assert output["native_annexb"]["codec"] == "hevc"
    assert output["native_annexb"]["requested_codec"] == "auto"
    assert output["native_annexb"]["annexb_irap_windows"]["irap_count"] == 1


def test_local_sdk_dump_can_fetch_cas_tuple_with_auth(monkeypatch, tmp_path) -> None:
    fake_client = _install_fake_client(monkeypatch)
    output_path = tmp_path / "local.ps"
    calls: list[dict[str, Any]] = []

    class FakeCas:
        def __init__(self, token: dict[str, Any]) -> None:
            calls.append({"token": token})

        def cas_get_encryption(self, serial: str) -> dict[str, Any]:
            calls.append({"cas_serial": serial})
            return {
                "Response": {
                    "Session": {
                        "@Key": "1234567890abcdef",
                        "@OperationCode": "0123456",
                        "@EncryptType": "2",
                    }
                }
            }

    class FakeLocalStream:
        def __enter__(self) -> FakeLocalStream:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    def fake_open_local_sdk_stream(_endpoint: Any, device_info: Any, _preview_request: Any, **kwargs: Any) -> FakeLocalStream:
        calls.append(
            {
                "operation_code": device_info.operation_code,
                "key": device_info.key,
                "encrypt_type": device_info.encrypt_type,
                "kwargs": kwargs,
            }
        )
        return FakeLocalStream()

    def fake_copy(_stream: FakeLocalStream, output: BinaryIO, **_kwargs: Any) -> None:
        output.write(LOCAL_SDK_TEST_PAYLOAD)

    monkeypatch.setattr(cli_module, "EzvizCAS", FakeCas)
    monkeypatch.setattr(cli_module, "open_local_sdk_stream", fake_open_local_sdk_stream)
    monkeypatch.setattr(cli_module, "copy_local_stream_to_mpegps", fake_copy)

    assert (
        cli_module.main(
            [
                "--token-file",
                _token_file(tmp_path),
                "stream",
                "local-sdk-dump",
                "--host",
                "192.0.2.10",
                "--serial",
                "CAM123456",
                "--fetch-cas",
                "--cas-serial",
                "CS-CAM123456",
                "--format",
                "mpegps",
                "--max-packets",
                "1",
                "--output",
                str(output_path),
            ]
        )
        == 0
    )

    assert fake_client.instances[0].closed is True
    assert calls[1] == {"cas_serial": "CS-CAM123456"}
    assert calls[2]["operation_code"] == "0123456"
    assert calls[2]["key"] == "1234567890abcdef"
    assert calls[2]["encrypt_type"] == 2
    assert output_path.read_bytes() == LOCAL_SDK_TEST_PAYLOAD


def test_local_sdk_dump_fetch_cas_registers_p2p_before_cas(
    monkeypatch,
    tmp_path,
) -> None:
    calls: list[dict[str, Any]] = []

    class RegisteringClient(_FakeClient):
        def register_p2p_session(self, *, max_retries: int = 0) -> dict[str, Any]:
            calls.append({"p2p_register": max_retries})
            return {"meta": {"code": 200}}

    _install_fake_client(monkeypatch, RegisteringClient)
    output_path = tmp_path / "local.ps"

    class FakeCas:
        def __init__(self, token: dict[str, Any]) -> None:
            calls.append({"token": token})

        def cas_get_encryption(self, serial: str) -> dict[str, Any]:
            calls.append({"cas_serial": serial})
            return {
                "Response": {
                    "Session": {
                        "@Key": "1234567890abcdef",
                        "@OperationCode": "0123456",
                        "@EncryptType": "2",
                    }
                }
            }

    class FakeLocalStream:
        def __enter__(self) -> FakeLocalStream:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    def fake_open_local_sdk_stream(
        _endpoint: Any,
        _device_info: Any,
        _preview_request: Any,
        **_kwargs: Any,
    ) -> FakeLocalStream:
        return FakeLocalStream()

    def fake_copy(_stream: FakeLocalStream, output: BinaryIO, **_kwargs: Any) -> None:
        output.write(LOCAL_SDK_TEST_PAYLOAD)

    monkeypatch.setattr(cli_module, "EzvizCAS", FakeCas)
    monkeypatch.setattr(cli_module, "open_local_sdk_stream", fake_open_local_sdk_stream)
    monkeypatch.setattr(cli_module, "copy_local_stream_to_mpegps", fake_copy)

    assert (
        cli_module.main(
            [
                "--token-file",
                _token_file(tmp_path),
                "stream",
                "local-sdk-dump",
                "--host",
                "192.0.2.10",
                "--serial",
                "CAM123456",
                "--fetch-cas",
                "--format",
                "mpegps",
                "--max-packets",
                "1",
                "--output",
                str(output_path),
            ]
        )
        == 0
    )

    assert calls[:3] == [
        {"p2p_register": MAX_RETRIES},
        {"token": {"session_id": "new-session", "api_url": "apiieu.ezvizlife.com"}},
        {"cas_serial": "CAM123456"},
    ]


def test_local_sdk_dump_fetch_cas_uses_credentials_file_serial(
    monkeypatch,
    tmp_path,
) -> None:
    _install_fake_client(monkeypatch)
    credentials_path = tmp_path / "local-sdk-credentials.json"
    output_path = tmp_path / "local.ps"
    credentials_path.write_text(
        json.dumps(
            {
                "serial": "CAM123456",
                "endpoint": {
                    "host": "192.0.2.10",
                    "command_port": 9010,
                    "stream_port": 9020,
                },
            }
        ),
        encoding="utf-8",
    )
    calls: list[dict[str, Any]] = []

    class FakeCas:
        def __init__(self, token: dict[str, Any]) -> None:
            calls.append({"token": token})

        def cas_get_encryption(self, serial: str) -> dict[str, Any]:
            calls.append({"cas_serial": serial})
            return {
                "Response": {
                    "Session": {
                        "@Key": "1234567890abcdef",
                        "@OperationCode": "0123456",
                        "@EncryptType": "2",
                    }
                }
            }

    class FakeLocalStream:
        def __enter__(self) -> FakeLocalStream:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    def fake_open_local_sdk_stream(
        _endpoint: Any,
        device_info: Any,
        _preview_request: Any,
        **_kwargs: Any,
    ) -> FakeLocalStream:
        calls.append(
            {
                "serial": device_info.serial,
                "operation_code": device_info.operation_code,
                "key": device_info.key,
                "encrypt_type": device_info.encrypt_type,
            }
        )
        return FakeLocalStream()

    def fake_copy(_stream: FakeLocalStream, output: BinaryIO, **_kwargs: Any) -> None:
        output.write(LOCAL_SDK_TEST_PAYLOAD)

    monkeypatch.setattr(cli_module, "EzvizCAS", FakeCas)
    monkeypatch.setattr(cli_module, "open_local_sdk_stream", fake_open_local_sdk_stream)
    monkeypatch.setattr(cli_module, "copy_local_stream_to_mpegps", fake_copy)

    assert (
        cli_module.main(
            [
                "--token-file",
                _token_file(tmp_path),
                "stream",
                "local-sdk-dump",
                "--credentials-file",
                str(credentials_path),
                "--fetch-cas",
                "--format",
                "mpegps",
                "--max-packets",
                "1",
                "--output",
                str(output_path),
            ]
        )
        == 0
    )

    assert calls[1] == {"cas_serial": "CAM123456"}
    assert calls[2] == {
        "serial": "CAM123456",
        "operation_code": "0123456",
        "key": "1234567890abcdef",
        "encrypt_type": 2,
    }
    assert output_path.read_bytes() == LOCAL_SDK_TEST_PAYLOAD


def test_local_sdk_keys_fetches_endpoint_cas_and_media_key(
    monkeypatch,
    tmp_path,
    capsys,
) -> None:
    class KeyClient(_FakeClient):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            self.device_infos = {
                "CAM123456": {
                    "CONNECTION": {
                        "localIp": "192.0.2.10",
                        "localCmdPort": "9010",
                        "localStreamPort": "9020",
                    }
                }
            }

    KeyClient.instances = []
    monkeypatch.setattr(cli_module, "EzvizClient", KeyClient)
    token_path = _token_file(tmp_path)
    calls: list[dict[str, Any]] = []

    class FakeCas:
        def __init__(self, token: dict[str, Any]) -> None:
            calls.append({"token": token})

        def cas_get_encryption(self, serial: str) -> dict[str, Any]:
            calls.append({"cas_serial": serial})
            return {
                "Response": {
                    "Session": {
                        "@Key": "1234567890abcdef",
                        "@OperationCode": "0123456",
                        "@EncryptType": "2",
                    }
                }
            }

    monkeypatch.setattr("pyezvizapi.local_stream.EzvizCAS", FakeCas)

    assert (
        cli_module.main(
            [
                "--token-file",
                token_path,
                "stream",
                "local-sdk-keys",
                "--serial",
                "CAM123456",
                "--cas-serial",
                "CS-CAM123456",
            ]
        )
        == 0
    )

    assert KeyClient.instances[0].cam_key_request == {
        "serial": "CAM123456",
        "max_retries": 1,
    }
    assert calls[1] == {"cas_serial": "CS-CAM123456"}
    assert json.loads(capsys.readouterr().out) == {
        "serial": "CAM123456",
        "endpoint": {
            "host": "192.0.2.10",
            "command_port": 9010,
            "stream_port": 9020,
        },
        "cas": {
            "operation_code": "0123456",
            "key": "1234567890abcdef",
            "encrypt_type": 2,
        },
        "media_key": "camera-secret",
    }


def test_local_sdk_keys_can_skip_p2p_register(monkeypatch, tmp_path) -> None:
    calls: list[dict[str, Any]] = []

    class KeyClient(_FakeClient):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            self.device_infos = {
                "CAM123456": {
                    "CONNECTION": {
                        "localIp": "192.0.2.10",
                        "localCmdPort": "9010",
                        "localStreamPort": "9020",
                    }
                }
            }

        def register_p2p_session(self, *, max_retries: int = 0) -> dict[str, Any]:
            calls.append({"p2p_register": max_retries})
            return {"meta": {"code": 200}}

    KeyClient.instances = []
    monkeypatch.setattr(cli_module, "EzvizClient", KeyClient)

    class FakeCas:
        def __init__(self, _token: dict[str, Any]) -> None:
            return None

        def cas_get_encryption(self, serial: str) -> dict[str, Any]:
            calls.append({"cas_serial": serial})
            return {
                "Response": {
                    "Session": {
                        "@Key": "1234567890abcdef",
                        "@OperationCode": "0123456",
                        "@EncryptType": "2",
                    }
                }
            }

    monkeypatch.setattr("pyezvizapi.local_stream.EzvizCAS", FakeCas)

    assert (
        cli_module.main(
            [
                "--token-file",
                _token_file(tmp_path),
                "stream",
                "local-sdk-keys",
                "--serial",
                "CAM123456",
                "--no-media-key",
                "--no-p2p-register",
            ]
        )
        == 0
    )

    assert calls == [{"cas_serial": "CAM123456"}]


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

    def fake_decrypt(data: bytes, key: str, *, nalu_header_size: int | None) -> bytes:
        decrypt_calls.append({"data": data, "key": key, "nalu_header_size": nalu_header_size})
        return b"decrypted"

    copy_calls: list[bytes] = []

    def fake_copy_stream_payloads_to_mpegts(*_args: Any, **kwargs: Any) -> None:
        transform_payload = kwargs["transform_payload"]
        first_video_pes = b"\x00\x00\x01\xe0\x00\x0e\x80\x00\x00encrypted-1"
        second_video_pes = b"\x00\x00\x01\xe0\x00\x0e\x80\x00\x00encrypted-2"
        audio_pes = b"\x00\x00\x01\xc0\x00\x08\x80\x00\x00audio"
        first = transform_payload(first_video_pes)
        second = transform_payload(second_video_pes)
        third = transform_payload(audio_pes)
        tail = transform_payload.flush()
        copy_calls.extend([first, second, third, tail])

    monkeypatch.setattr(cli_module, "open_cloud_stream", lambda *_args, **_kwargs: FakeStream())
    monkeypatch.setattr(cli_module, "_open_mpegts_remux_process", lambda _path: object())
    monkeypatch.setattr(cli_module, "decrypt_hikvision_ps_video", fake_decrypt)
    monkeypatch.setattr(cli_module, "_copy_stream_payloads_to_mpegts", fake_copy_stream_payloads_to_mpegts)

    handler = FakeHandler()
    cli_module._handle_stream_proxy_get(cast(Any, handler), config, cast(Any, FakeClient()))  # noqa: SLF001

    assert handler.responses == [200]
    assert handler.errors == []
    assert decrypt_calls == [
        {
            "data": (
                b"\x00\x00\x01\xe0\x00\x0e\x80\x00\x00encrypted-1"
                b"\x00\x00\x01\xe0\x00\x0e\x80\x00\x00encrypted-2"
                b"\x00\x00\x01\xc0\x00\x08\x80\x00\x00audio"
            ),
            "key": "camera-key",
            "nalu_header_size": 2,
        },
    ]
    assert copy_calls == [b"", b"", b"decrypted", b""]


def test_buffered_stream_decryptor_defers_auto_until_video_nals(monkeypatch) -> None:
    pack_chunk = b"pack"
    video_chunk = b"video"
    next_chunk = b"next"
    detect_calls: list[bytes] = []
    decrypt_calls: list[dict[str, Any]] = []

    def fake_detect(data: bytes, key: str, *, default: int | None = 2) -> int | None:
        assert key == "camera-key"
        assert default is None
        detect_calls.append(data)
        return 0 if data == video_chunk else None

    def fake_decrypt(data: bytes, key: str, *, nalu_header_size: int | None) -> bytes:
        decrypt_calls.append({"data": data, "key": key, "nalu_header_size": nalu_header_size})
        return b"decrypted-" + data

    monkeypatch.setattr(
        cli_module,
        "detect_hikvision_ps_video_nalu_header_size",
        fake_detect,
    )
    monkeypatch.setattr(cli_module, "decrypt_hikvision_ps_video", fake_decrypt)

    decryptor = cli_module._BufferedStreamPayloadDecryptor(  # noqa: SLF001
        "camera-key",
        codec="auto",
    )

    assert decryptor._decrypt_chunk(pack_chunk) == b"decrypted-" + pack_chunk  # noqa: SLF001
    assert decryptor._decrypt_chunk(video_chunk) == b"decrypted-" + video_chunk  # noqa: SLF001
    assert decryptor._decrypt_chunk(next_chunk) == b"decrypted-" + next_chunk  # noqa: SLF001

    assert detect_calls == [pack_chunk, video_chunk]
    assert decrypt_calls == [
        {"data": pack_chunk, "key": "camera-key", "nalu_header_size": 2},
        {"data": video_chunk, "key": "camera-key", "nalu_header_size": 0},
        {"data": next_chunk, "key": "camera-key", "nalu_header_size": 0},
    ]


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
