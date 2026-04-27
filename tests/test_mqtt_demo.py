from __future__ import annotations

import base64
import json
from typing import Any

import pyezvizapi.test_mqtt as mqtt_demo


def test_message_handler_appends_json_line(tmp_path, monkeypatch) -> None:
    log_file = tmp_path / "mqtt_messages.jsonl"
    monkeypatch.setattr(mqtt_demo, "LOG_FILE", log_file)

    mqtt_demo.message_handler({"deviceSerial": "CAM123", "alarmType": 10000})

    assert log_file.read_text(encoding="utf-8") == (
        '{"deviceSerial": "CAM123", "alarmType": 10000}\n'
    )


def test_log_raw_payload_records_utf8_and_binary_payloads(tmp_path, monkeypatch) -> None:
    raw_log_file = tmp_path / "mqtt_raw_messages.jsonl"
    timestamps = iter([100.0, 101.0])
    monkeypatch.setattr(mqtt_demo, "RAW_LOG_FILE", raw_log_file)
    monkeypatch.setattr(mqtt_demo.time, "time", lambda: next(timestamps))

    mqtt_demo._log_raw_payload(b"hello")
    mqtt_demo._log_raw_payload(b"\xff\xfe")

    lines = [json.loads(line) for line in raw_log_file.read_text(encoding="utf-8").splitlines()]
    assert lines == [
        {"encoding": "utf-8", "payload": "hello", "timestamp": 100.0},
        {
            "encoding": "base64",
            "payload": base64.b64encode(b"\xff\xfe").decode("ascii"),
            "timestamp": 101.0,
        },
    ]


class _FakePahoClient:
    def __init__(self) -> None:
        self.on_message: Any = None


class _FakeMqttClient:
    def __init__(self) -> None:
        self.mqtt_client = _FakePahoClient()


def test_enable_raw_logging_wraps_original_callback(tmp_path, monkeypatch) -> None:
    raw_log_file = tmp_path / "mqtt_raw_messages.jsonl"
    monkeypatch.setattr(mqtt_demo, "RAW_LOG_FILE", raw_log_file)
    monkeypatch.setattr(mqtt_demo.time, "time", lambda: 123.0)
    mqtt_client = _FakeMqttClient()
    calls: list[bytes] = []

    def original_callback(client: Any, userdata: Any, msg: Any) -> None:
        calls.append(msg.payload)

    mqtt_client.mqtt_client.on_message = original_callback

    mqtt_demo._enable_raw_logging(mqtt_client)  # type: ignore[arg-type]
    first_wrapper = mqtt_client.mqtt_client.on_message
    mqtt_demo._enable_raw_logging(mqtt_client)  # type: ignore[arg-type]

    assert mqtt_client.mqtt_client.on_message is first_wrapper
    first_wrapper(None, None, type("Msg", (), {"payload": b"payload"})())

    assert calls == [b"payload"]
    assert json.loads(raw_log_file.read_text(encoding="utf-8")) == {
        "encoding": "utf-8",
        "payload": "payload",
        "timestamp": 123.0,
    }
