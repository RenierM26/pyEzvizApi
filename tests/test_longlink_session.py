"""MQTT wire profile and delivery semantics, with no external services."""
# ruff: noqa: SLF001

import json
from threading import Event
from unittest.mock import Mock

import paho.mqtt.client as mqtt

from pyezvizapi import _longlink as wire
from pyezvizapi._longlink_auth import PushCredentials
from pyezvizapi._longlink_session import Channel99Session

SERIAL = b"MOBILE:ys7:synthetic-user:synthetic-phone"
KEY = bytes(range(16))


def make_message(topic: str, payload: bytes) -> mqtt.MQTTMessage:
    result = mqtt.MQTTMessage(topic=topic.encode())
    result.payload = payload
    return result


def session(callback: Mock) -> Channel99Session:
    return Channel99Session(
        ("example.invalid", 8777), SERIAL, lambda: "token", {}, lambda state: None, callback
    )


def test_native_connect_profile() -> None:
    credentials = PushCredentials(bytes(range(32)), KEY, KEY, {})
    client = session(Mock())._client(credentials)
    assert client._client_id == credentials.device_id
    assert client._username == SERIAL
    assert client._password is None
    assert client._clean_session is True
    assert len(client._will_topic) == 128
    assert client._will_qos == 1
    assert client._will_retain is True
    will = json.loads(wire.decrypt(KEY, bytes(client._will_payload)))
    assert will["SubSerial"] == SERIAL.decode()


def test_direct_event_delivery_does_not_publish_application_reply() -> None:
    callback = Mock()
    client = Mock()
    body = b'{"ext":"synthetic,1,2,3,4","alert":"test"}'
    metadata = b'{"Seq":42,"CmdVer":"1.0"}'
    message = make_message(
        topic=f"/{SERIAL.decode()}/9000/1",
        payload=wire.encrypt(KEY, len(metadata).to_bytes(2, "big") + metadata + body),
    )
    session(callback)._receive(client, message, KEY)
    callback.assert_called_once_with(body)
    client.publish.assert_not_called()


def test_control_message_changes_keepalive_without_callback() -> None:
    callback = Mock()
    client = Mock()
    meta = b'{"Seq":1,"CmdVer":"1.0"}'
    body = b'{"KeepAlive":{"Interval":60}}'
    message = make_message(
        topic=f"/{SERIAL.decode()}/1000/1",
        payload=wire.encrypt(KEY, len(meta).to_bytes(2, "big") + meta + body),
    )
    session(callback)._receive(client, message, KEY)
    assert client._keepalive == 60
    callback.assert_not_called()
    client.publish.assert_not_called()


def test_stop_during_registration_prevents_later_socket_creation(monkeypatch) -> None:
    connection = session(Mock())
    connection.prepare = connection.close
    create = Mock(side_effect=AssertionError("Must not open socket after stop"))
    monkeypatch.setattr("pyezvizapi._longlink_session.socket.create_connection", create)
    connection.run(Event())
    create.assert_not_called()
