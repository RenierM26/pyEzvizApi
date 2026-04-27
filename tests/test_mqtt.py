from __future__ import annotations

import json
from typing import Any

import pytest
import requests

from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.mqtt import MQTTClient

TOKEN = {
    "username": "ezviz-user",
    "session_id": "session-id",
    "service_urls": {"pushAddr": "push.example.test"},
}


class OfflineMQTTClient(MQTTClient):
    """MQTT client that never calls the EZVIZ stop endpoint in tests."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.stop_called = False

    def stop(self) -> None:
        self.stop_called = True


class DummyMessage:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload


def _client(**kwargs: Any) -> OfflineMQTTClient:
    return OfflineMQTTClient(TOKEN, requests.Session(), **kwargs)


def test_decode_mqtt_message_expands_ext_fields_and_coerces_ints() -> None:
    client = _client()
    raw = {
        "alert": "Motion detected",
        "ext": "1,2026-04-27 07:30:00,CAM123,2,2401,default.jpg,alt1.jpg,alt2.jpg,3,1,file-1,0,checksum,1,metadata,msg-1,image.jpg,Front Door,reserved,42",
    }

    decoded = client.decode_mqtt_message(json.dumps(raw).encode())

    assert decoded["alert"] == "Motion detected"
    assert decoded["ext"] == {
        "channel_type": 1,
        "time": "2026-04-27 07:30:00",
        "device_serial": "CAM123",
        "channel_no": 2,
        "alert_type_code": 2401,
        "default_pic_url": "default.jpg",
        "media_url_alt1": "alt1.jpg",
        "media_url_alt2": "alt2.jpg",
        "resource_type": 3,
        "status_flag": 1,
        "file_id": "file-1",
        "is_encrypted": 0,
        "picChecksum": "checksum",
        "is_dev_video": 1,
        "metadata": "metadata",
        "msgId": "msg-1",
        "image": "image.jpg",
        "device_name": "Front Door",
        "reserved": "reserved",
        "sequence_number": 42,
    }


def test_decode_mqtt_message_fills_missing_ext_fields_with_none() -> None:
    client = _client()
    decoded = client.decode_mqtt_message(b'{"ext": "1,time,CAM123"}')

    assert decoded["ext"]["channel_type"] == 1
    assert decoded["ext"]["time"] == "time"
    assert decoded["ext"]["device_serial"] == "CAM123"
    assert decoded["ext"]["msgId"] is None
    assert decoded["ext"]["sequence_number"] is None


def test_decode_mqtt_message_raises_and_stops_on_malformed_json() -> None:
    client = _client()

    with pytest.raises(PyEzvizError, match="Unable to decode MQTT message"):
        client.decode_mqtt_message(b"not-json")

    assert client.stop_called is True


def test_on_message_caches_by_device_and_invokes_callback() -> None:
    seen: list[dict[str, Any]] = []
    client = _client(on_message_callback=seen.append)
    message = DummyMessage(
        json.dumps({"alert": "Person", "ext": "1,time,CAM123,1,2403"}).encode()
    )

    client._on_message(None, None, message)  # type: ignore[arg-type]

    assert list(client.messages_by_device) == ["CAM123"]
    assert client.messages_by_device["CAM123"]["alert"] == "Person"
    assert seen == [client.messages_by_device["CAM123"]]


def test_message_cache_evicts_oldest_device() -> None:
    client = _client(max_messages=2)

    client._cache_message("A", {"serial": "A"})
    client._cache_message("B", {"serial": "B"})
    client._cache_message("C", {"serial": "C"})

    assert list(client.messages_by_device) == ["B", "C"]

    client._cache_message("B", {"serial": "B", "updated": True})

    assert list(client.messages_by_device) == ["C", "B"]
    assert client.messages_by_device["B"] == {"serial": "B", "updated": True}
