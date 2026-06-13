from __future__ import annotations

import argparse
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
import json
from pathlib import Path
import sys
from typing import Any


def _load_tool() -> Any:
    path = (
        Path(__file__).resolve().parents[1]
        / "tools"
        / "apk-re"
        / "bin"
        / "hcnetsdk-command-live-check"
    )
    loader = SourceFileLoader("hcnetsdk_command_live_check", str(path))
    spec = spec_from_loader(loader.name, loader)
    assert spec is not None
    module = module_from_spec(spec)
    sys.modules[loader.name] = module
    loader.exec_module(module)
    return module


def test_load_inventory_reads_shell_quoted_env_file(tmp_path: Path) -> None:
    tool = _load_tool()
    inventory = [
        {
            "name": "Camera One",
            "mdns": "SERIAL-ONE",
            "password": "dummy-camera-password-07",
            "enc_key": "dummy-enc-key-01",
            "battery": False,
            "in_use": True,
        },
        {
            "name": "Camera Two",
            "mdns": "SERIAL-TWO",
            "password": "dummy-camera-password-03",
            "enc_key": "dummy-enc-key-02",
            "battery": True,
            "in_use": False,
        },
    ]
    env_file = tmp_path / "inventory.env"
    env_file.write_text(
        "EZVIZ_CAMERA_INVENTORY_JSON="
        + sh_single_quote(json.dumps(inventory))
        + "\n",
        encoding="utf-8",
    )

    items = tool._load_inventory(  # noqa: SLF001
        argparse.Namespace(
            inventory_file=str(env_file),
            inventory_env="EZVIZ_CAMERA_INVENTORY_JSON",
        )
    )

    assert [item.serial for item in items] == ["SERIAL-ONE", "SERIAL-TWO"]
    assert items[0].name == "Camera One"
    assert items[1].enc_key == "dummy-enc-key-02"


def test_filtered_items_skip_unused_and_battery_by_default() -> None:
    tool = _load_tool()
    items = [
        tool.CameraInventoryItem(name="wired", serial="A", password="one"),
        tool.CameraInventoryItem(name="unused", serial="B", password="two", in_use=False),
        tool.CameraInventoryItem(name="battery", serial="C", password="three", battery=True),
    ]

    selected = tool._filtered_items(  # noqa: SLF001
        items,
        serials=[],
        include_unused=False,
        include_battery=False,
        max_cameras=None,
    )

    assert [item.serial for item in selected] == ["A"]


def test_dry_run_redacts_sensitive_camera_fields(tmp_path: Path) -> None:
    tool = _load_tool()
    args = argparse.Namespace(
        python="python",
        command_port="8000",
        channel="1",
        native_plan="app-lan-live-view",
        duration="5s",
        timeout="12",
        ffmpeg_path="ffmpeg",
        local_ip=None,
        decrypt_video=False,
        no_try_enc_key_password=False,
        no_skip_initial_idr=False,
        dry_run=True,
    )
    item = tool.CameraInventoryItem(
        name="Garage",
        serial="SERIAL-GARAGE-01",
        password="dummy-camera-password-01",
        enc_key="dummy-enc-key-03",
    )

    result = tool._check_item(  # noqa: SLF001
        args=args,
        item=item,
        output_dir=tmp_path,
        host="192.0.2.10",
        host_source="override",
        camera_index=1,
    )

    rendered = json.dumps(result)
    assert result["ok"] is None
    assert "<redacted>" in rendered
    assert "dummy-camera-password-01" not in rendered
    assert "SERIAL-GARAGE-01" not in rendered
    assert "dummy-enc-key-03" not in rendered
    assert result["serial"] == "<redacted>"
    assert result["command"][result["command"].index("--serial") + 1] == "<redacted>"
    assert [attempt["credential_source"] for attempt in result["credential_attempts"]] == [
        "inventory_password",
        "encryption_key_password",
    ]
    for attempt in result["credential_attempts"]:
        command = attempt["command"]
        assert command[command.index("--hcnetsdk-command-password") + 1] == "<redacted>"
    assert any(
        value.endswith("camera-01-Garage-encryption_key_password.ts")
        for value in result["credential_attempts"][1]["command"]
    )
    assert "camera-01-Garage" in result["artifacts"]["capture"]


def test_dry_run_redacts_media_key_when_decrypting(tmp_path: Path) -> None:
    tool = _load_tool()
    args = argparse.Namespace(
        python="python",
        command_port="8000",
        channel="1",
        native_plan="app-lan-live-view",
        duration="5s",
        timeout="12",
        ffmpeg_path="ffmpeg",
        local_ip=None,
        decrypt_video=True,
        no_try_enc_key_password=False,
        no_skip_initial_idr=False,
        dry_run=True,
    )
    item = tool.CameraInventoryItem(
        name="Garage",
        serial="SERIAL-GARAGE-01",
        password="dummy-camera-password-01",
        enc_key="dummy-enc-key-03",
    )

    result = tool._check_item(  # noqa: SLF001
        args=args,
        item=item,
        output_dir=tmp_path,
        host="192.0.2.10",
        host_source="override",
        camera_index=1,
    )

    rendered = json.dumps(result)
    assert "--decrypt-video" in result["command"]
    assert result["command"][result["command"].index("--media-key") + 1] == "<redacted>"
    assert len(result["credential_attempts"]) == 2
    assert "dummy-enc-key-03" not in rendered


def test_credential_attempts_can_skip_encryption_key_password() -> None:
    tool = _load_tool()
    args = argparse.Namespace(no_try_enc_key_password=True)
    item = tool.CameraInventoryItem(
        name="Garage",
        serial="SERIAL-GARAGE-01",
        password="dummy-camera-password-01",
        enc_key="dummy-enc-key-03",
    )

    attempts = tool._credential_attempts(args, item)  # noqa: SLF001

    assert attempts == [("inventory_password", "dummy-camera-password-01")]


def test_recursive_redaction_covers_serial_password_and_enc_key() -> None:
    tool = _load_tool()
    item = tool.CameraInventoryItem(
        name="Garage",
        serial="SERIAL-GARAGE-01",
        password="dummy-camera-password-01",
        enc_key="dummy-enc-key-03",
    )

    redacted = tool._redact_sensitive(  # noqa: SLF001
        {
            "stderr": "SERIAL-GARAGE-01 dummy-camera-password-01 dummy-enc-key-03",
            "nested": ["prefix-SERIAL-GARAGE-01"],
        },
        item,
    )

    rendered = json.dumps(redacted)
    assert "SERIAL-GARAGE-01" not in rendered
    assert "dummy-camera-password-01" not in rendered
    assert "dummy-enc-key-03" not in rendered
    assert rendered.count("<redacted>") == 4


def test_diagnose_save_failure_prioritizes_connection_refused(tmp_path: Path) -> None:
    tool = _load_tool()

    diagnosis = tool._diagnose_save_failure(  # noqa: SLF001
        "File local_stream.py, in _login_client\nConnectionRefusedError: [Errno 111] Connection refused\n",
        tmp_path / "missing.metadata.json",
    )

    assert diagnosis == "connection_refused"


def test_diagnose_save_failure_labels_short_idr_capture(tmp_path: Path) -> None:
    tool = _load_tool()

    diagnosis = tool._diagnose_save_failure(  # noqa: SLF001
        "ERROR: H.264 stream did not contain enough IDR windows to skip 1 startup window(s)\n",
        tmp_path / "missing.metadata.json",
    )

    assert diagnosis == "insufficient_idr_windows"


def test_stdout_summary_compacts_packet_metadata() -> None:
    tool = _load_tool()
    summary = {
        "ok": True,
        "results": [
            {
                "ok": True,
                "metadata": {
                    "bootstrap_complete": True,
                    "command_port_exchanges": [{"request_command_id": 1}],
                    "packets": {
                        "packet_count": 2,
                        "last_packet_elapsed_seconds": 1.5,
                        "samples": [{"body_sha256": "x"}],
                        "idmx_h264": {
                            "packet_count": 2,
                            "nal_type_counts": {"1": 1},
                            "rtp_payload_type_counts": {"96": 2},
                            "sequence_gap_count": 0,
                            "invalid_media_marker_count": 0,
                            "samples": [{"body_sha256": "y"}],
                        },
                    },
                },
            }
        ],
    }

    compact = tool._stdout_summary(summary, include_metadata=False)  # noqa: SLF001

    metadata = compact["results"][0]["metadata"]
    assert metadata["command_port_exchange_count"] == 1
    assert metadata["packets"]["packet_count"] == 2
    assert "samples" not in metadata["packets"]
    assert "samples" not in metadata["packets"]["idmx_h264"]


def sh_single_quote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"
