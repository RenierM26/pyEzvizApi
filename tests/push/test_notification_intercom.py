"""Synthetic app-shaped notifications through the production channel-99 receiver."""

from datetime import UTC, datetime
import json
from typing import Any
from unittest.mock import patch

import pytest
import requests

from pyezvizapi.devices.intercom_events import normalize_intercom_event
from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.push.mqtt import EXT_FIELD_NAMES, MQTTClient
from pyezvizapi.push.notifications import decode_notification


def alarm(*, code="10242", method="Card", subtype="92"):
    return {"alert": "Ignored translation", "ext": ",".join([
        "1", "2026-11-15 12:40:00", "INTERCOM", "0", code, "", "", "",
        method, "0", "", "0", "", "0", "", "alarm-id", "", "Monitor", "", subtype,
    ])}


@pytest.mark.parametrize(("method", "expected"), [("Card", "rfid"), ("Monitor", "monitor"), ("Future", None)])
def test_actual_csv_to_unlock_normalizer_preserves_method(method, expected):
    decoded = decode_notification(json.dumps(alarm(method=method)).encode())
    event = normalize_intercom_event(decoded, zone=UTC)
    assert event is not None
    assert (event.serial, event.event_id, event.method, event.channel) == ("INTERCOM", "alarm-id", expected, 0)
    assert event.occurred_at == datetime(2026, 11, 15, 12, 40, tzinfo=UTC)
    assert decoded["ext"]["resource_type"] == method  # historical alias remains
    assert decoded["ext"]["sequence_number"] == 92
    assert decoded["ext"]["subType"] == 92


def test_csv_subtype_is_available_without_reinterpreting_unknown_alarm_codes():
    for code in ("0", "99999"):
        payload = decode_notification(json.dumps(alarm(code=code, subtype="2701")).encode())
        event = normalize_intercom_event(payload)
        assert (event is not None) == (code == "0")
        if event is not None:
            assert event.event_type == "ring"
            assert event.method is None
            assert event.occurred_at is None  # no guessed local zone


def test_call_notification_has_separate_identity_and_status_not_false_alarm():
    payload = {"ext": ",".join([
        "14", "2026-11-15+12:40:00", "INTERCOM", "0", "2701", "call-id",
        "1", "image", "0", "checksum", "0", "analysis", "", "Monitor", "", "custom",
    ])}
    decoded = decode_notification(json.dumps(payload).encode())
    ext = decoded["ext"]
    assert ext["channel_type"] == 14
    assert ext["time"] == "2026-11-15 12:40:00"
    assert ext["device_serial"] == "INTERCOM"
    assert ext["calling_type"] == 2701
    assert ext["calling_id"] == "call-id"
    assert ext["calling_status"] == 1
    assert ext["image"] == "image"
    assert ext["custom_info"] == "custom"
    assert "msgId" not in ext and "alert_type_code" not in ext
    assert normalize_intercom_event(decoded) is None


@pytest.mark.parametrize("family", ["2", "3", "4", "10", "13", "15", "unknown"])
def test_other_csv_families_cannot_acquire_alarm_semantics(family):
    raw = alarm(code="2701")["ext"].split(",")
    raw[0] = family
    decoded = decode_notification(json.dumps({"ext": ",".join(raw)}).encode())
    assert "alert_type_code" not in decoded["ext"]
    assert "msgId" not in decoded["ext"]
    assert normalize_intercom_event(decoded) is None


@pytest.mark.parametrize("encoded", [False, True])
def test_json_ext_stays_a_json_object_instead_of_becoming_csv(encoded):
    ext = {"x-type": "devStatus", "version": "v4", "deviceSerial": "INTERCOM", "localIndex": "0", "key": "switch_611", "value": False}
    decoded = decode_notification(json.dumps({"ext": json.dumps(ext) if encoded else ext}).encode())
    assert decoded["ext"] == ext
    assert normalize_intercom_event(decoded) is None


@pytest.mark.parametrize("payload", [b"bad", b"\xff", b"null", b"[]", b"1", b'"str"', b'{"ext":"{bad"}'])
def test_invalid_notification_has_safe_error(payload):
    with pytest.raises(PyEzvizError, match=r"^Unable to decode MQTT message$"):
        decode_notification(payload)


def test_bad_message_does_not_shutdown_or_prevent_the_next_callback():
    seen: list[dict[str, Any]] = []
    client = MQTTClient({"username": "test"}, requests.Session(), on_message_callback=seen.append)
    with patch.object(client, "stop") as stop:
        client._handle_payload(b"\xff")  # noqa: SLF001 -- exercise production receiver boundary
        client._handle_payload(b"[]")  # noqa: SLF001
        client._handle_payload(json.dumps(alarm()).encode())  # noqa: SLF001
        stop.assert_not_called()
    assert len(seen) == 1
    assert list(client.messages_by_device) == ["INTERCOM"]
    event = normalize_intercom_event(seen[0])
    assert event is not None and event.method == "rfid"


def test_mqtt_compatibility_method_delegates_to_pure_decoder():
    client = MQTTClient({"username": "test"}, requests.Session())
    raw = json.dumps(alarm()).encode()
    assert client.decode_mqtt_message(raw) == decode_notification(raw)
    assert EXT_FIELD_NAMES[8] == "resource_type"


def test_json_control_serial_is_cached_but_invalid_serial_cannot_break_receiver():
    seen: list[dict[str, Any]] = []
    client = MQTTClient({"username": "test"}, requests.Session(), on_message_callback=seen.append)
    for serial in ("INTERCOM", ["not-a-serial"]):
        client._handle_payload(json.dumps({"ext": {"x-type": "devStatus", "deviceSerial": serial}}).encode())  # noqa: SLF001
    assert list(client.messages_by_device) == ["INTERCOM"]
    assert len(seen) == 2


@pytest.mark.parametrize("family", [2, 14, "14", True, "bad"])
def test_normalizer_rejects_old_misdecoded_non_alarm_pushes(family):
    assert normalize_intercom_event({"ext": {"channel_type": family, "device_serial": "INTERCOM", "msgId": "not-an-alarm-id", "alert_type_code": 2701}}) is None
