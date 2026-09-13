from __future__ import annotations

import json

import pyezvizapi.test_mqtt as mqtt_demo


def test_message_handler_appends_json_line(tmp_path, monkeypatch) -> None:
    log_file = tmp_path / "mqtt_messages.jsonl"
    monkeypatch.setattr(mqtt_demo, "LOG_FILE", log_file)

    mqtt_demo.message_handler({"deviceSerial": "CAM123", "alarmType": 10000})

    assert log_file.read_text(encoding="utf-8") == (
        '{"deviceSerial": "CAM123", "alarmType": 10000}\n'
    )


def test_standalone_listener_handles_mismatched_host_token(tmp_path, caplog):

    path = tmp_path / "token.json"
    path.write_text(json.dumps({"push_profile": "android-channel99",
                                "feature_code": "different-host", "session_id": "saved"}))
    assert mqtt_demo.main(["--token-file", str(path)]) == 1
    assert "host feature code" in caplog.text
    assert "Traceback" not in caplog.text
