from __future__ import annotations

import pyezvizapi.test_mqtt as mqtt_demo


def test_message_handler_appends_json_line(tmp_path, monkeypatch) -> None:
    log_file = tmp_path / "mqtt_messages.jsonl"
    monkeypatch.setattr(mqtt_demo, "LOG_FILE", log_file)

    mqtt_demo.message_handler({"deviceSerial": "CAM123", "alarmType": 10000})

    assert log_file.read_text(encoding="utf-8") == (
        '{"deviceSerial": "CAM123", "alarmType": 10000}\n'
    )
