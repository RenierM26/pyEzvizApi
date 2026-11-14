"""Offline contracts for reusable vendor controls and multi-lens images."""

from copy import deepcopy
from io import BytesIO
import json
from struct import pack
from unittest.mock import MagicMock

from PIL import Image
import pytest

from pyezvizapi.devices import audio, controls, images
from pyezvizapi.exceptions import PyEzvizError


def data(config, *, category="IPC", encoded=False):
    return {
        "channelNo": 2,
        "device_category": category,
        "supportExt": {"185": "1", "203": "1"},
        "STATUS": {
            "optionals": {
                "ChimeMusic": json.dumps(config) if encoded else config,
                "CustomVoice_Volume": json.dumps(config) if encoded else config,
            }
        },
    }


@pytest.mark.parametrize("encoded", [False, True])
@pytest.mark.parametrize(
    "setter,field,value",
    [
        (audio.set_alarm_volume, "volume", 22),
        (audio.set_alarm_voice_volume, "volume", 45),
        (audio.set_microphone_volume, "microphone_volume", 30),
    ],
)
def test_writes_preserve_siblings_and_input(encoded, setter, field, value):
    config = {"volume": 60, "microphone_volume": 15, "future": {"opaque": [7]}}
    payload = data(config, encoded=encoded)
    before = deepcopy(payload)
    client = MagicMock()
    setter(client, "CAM", value, payload)
    args = client.set_dev_config_kv.call_args.args
    assert args[:2] == ("CAM", 2)
    assert args[3] == {**config, field: value}
    assert payload == before


@pytest.mark.parametrize("value", [True, float("nan"), float("inf"), -float("inf")])
@pytest.mark.parametrize(
    "setter", [audio.set_alarm_volume, audio.set_alarm_voice_volume, audio.set_microphone_volume]
)
def test_invalid_writes_do_no_io(setter, value):
    client = MagicMock()
    with pytest.raises(PyEzvizError):
        setter(client, "CAM", value, data({"volume": 50, "microphone_volume": 15}))
    client.set_dev_config_kv.assert_not_called()


def test_microphone_does_not_invent_speaker_volume():
    client = MagicMock()
    audio.set_microphone_volume(client, "CAM", 30, data({"microphone_volume": 10, "opaque": 4}))
    assert client.set_dev_config_kv.call_args.args[3] == {"microphone_volume": 30, "opaque": 4}


@pytest.mark.parametrize(
    "flag,expected",
    [(None, False), (True, False), ("0", False), ("1", True), (2, True), ("bad", False)],
)
def test_capabilities_are_not_truthiness(flag, expected):
    payload = data({"volume": 5}, category="DBScreen")
    payload["supportExt"]["185"] = flag
    assert (audio.alarm_volume_getter(payload) == 5) == expected
    assert audio.alarm_volume_max(payload) == 7
    assert controls.SupportExtView({"x": "1, 2,3"}).has("x", ["1,3"])


def test_port_updates_preserve_unknown_fields_and_do_not_mutate_failed_response():
    original = {
        "enabled": True,
        "future": {"x": 1},
        "portSecurityList": [
            {"portNo": 554, "enabled": True, "label": "rtsp"},
            {"portNo": 8000, "enabled": True},
        ],
    }
    client = MagicMock()
    client.get_port_security.return_value = {"value": deepcopy(original)}
    before = deepcopy(client.get_port_security.return_value)
    client.set_port_security.side_effect = PyEzvizError("offline")
    with pytest.raises(PyEzvizError):
        controls.set_port_security_ports(client, "CAM", (554, 80), 0)
    assert client.get_port_security.return_value == before
    sent = client.set_port_security.call_args.args[1]
    assert sent["future"] == original["future"]
    assert sent["portSecurityList"][0] == {"portNo": 554, "enabled": False, "label": "rtsp"}
    assert sent["portSecurityList"][1]["enabled"] is True
    assert sent["portSecurityList"][2] == {"portNo": 80, "enabled": False}


def test_tracking_and_encoded_app_readers():
    payload = {
        "FEATURE_INFO": {
            "9": {
                "Video": {
                    "PTZMasterSlaveTrace": {
                        "LinkedTrackingAdvancedCfg": {"trackingTakeoverEnabled": "1"}
                    },
                    "IntelligentAPP": json.dumps(
                        {"DownloadedAPP": {"APP": [{"APPID": "human$:$version", "enabled": True}]}}
                    ),
                }
            }
        }
    }
    assert controls.linked_tracking_takeover_enabled(payload)
    assert controls.intelligent_app_available(payload, "human")
    assert controls.intelligent_app_enabled(payload, "human")
    client = MagicMock()
    controls.set_linked_tracking_takeover(client, "CAM", False, payload)
    client.set_iot_feature.assert_called_once_with(
        "CAM",
        "Video",
        "1",
        "PTZMasterSlaveTrace",
        "LinkedTrackingAdvancedCfg",
        {"value": {"trackingTakeoverEnabled": False}},
    )


def test_concatenated_and_composite_lenses():
    buf = BytesIO()
    Image.new("RGB", (8, 17), (80, 40, 20)).save(buf, format="JPEG")
    jpeg = buf.getvalue()
    assert images.extract_jpeg_segments(b"prefix" + jpeg + jpeg) == [jpeg, jpeg]
    parts = images.split_composite_image(jpeg, 2)
    sizes = []
    for part in parts:
        with Image.open(BytesIO(part)) as decoded:
            decoded.load()
            sizes.append(decoded.size)
    assert sizes == [(8, 8), (8, 9)]
    assert images.split_composite_image(b"invalid", 2) == [b"invalid"]
    assert images.process_image_bytes(jpeg, None, 1, 2) == jpeg


@pytest.mark.parametrize("cached", [False, True])
@pytest.mark.parametrize("enabled", [False, True])
def test_port_updates_retain_enclosing_enable_and_vendor_fields(cached, enabled):
    raw = {
        "enabled": enabled,
        "value": {
            "portSecurityList": [{"portNo": 554, "enabled": True, "vendor": {"keep": [1]}}],
            "opaque": {"retain": 7},
        },
    }
    client = MagicMock()
    client.get_port_security.return_value = {} if cached else deepcopy(raw)
    cached_data = {
        "CAM": {
            "FEATURE_INFO": {
                "1": {
                    "Video": {
                        "NetworkSecurityProtection": {"PortSecurity": deepcopy(raw)},
                    }
                }
            }
        }
    }
    client.configure_mock(**{"_cameras": cached_data})
    before = deepcopy(cached_data)
    controls.set_port_security_ports(client, "CAM", (554,), 0)
    sent = client.set_port_security.call_args.args[1]
    assert sent == {
        **raw["value"],
        "enabled": enabled,
        "portSecurityList": [
            {"portNo": 554, "enabled": False, "vendor": {"keep": [1]}},
        ],
    }
    assert cached_data == before


def test_inner_port_enable_overrides_enclosing_hint():
    client = MagicMock()
    client.get_port_security.return_value = {
        "enabled": False,
        "value": {
            "enabled": True,
            "portSecurityList": [{"portNo": 554, "enabled": True}],
        },
    }
    controls.set_port_security_ports(client, "CAM", (554,), 0)
    sent = client.set_port_security.call_args.args[1]
    assert sent["enabled"] is True


def jpeg_bytes(size=(16, 17)):
    stream = BytesIO()
    Image.new("RGB", size, (20, 80, 40)).save(stream, format="JPEG")
    return stream.getvalue()


def jpeg_with_exif_thumbnail():
    """Build a valid EXIF IFD1 JPEG thumbnail inside an otherwise valid JPEG."""
    thumbnail = jpeg_bytes((2, 2))
    tiff = (
        b"MM\x00*\x00\x00\x00\x08"
        + pack(">HI", 0, 14)
        + pack(">H", 2)
        + pack(">HHII", 513, 4, 1, 44)
        + pack(">HHII", 514, 4, 1, len(thumbnail))
        + pack(">I", 0)
        + thumbnail
    )
    exif = b"Exif\x00\x00" + tiff
    jpeg = jpeg_bytes()
    return jpeg[:2] + b"\xff\xe1" + pack(">H", len(exif) + 2) + exif + jpeg[2:]


def test_embedded_thumbnail_is_not_a_frame_boundary(monkeypatch):
    jpeg = jpeg_with_exif_thumbnail()
    second = jpeg_bytes((6, 8))
    segments = images.extract_jpeg_segments(b"prefix" + jpeg + second)
    assert segments == [jpeg, second]
    monkeypatch.setattr(images, "decrypt_image", lambda *_: jpeg + second)
    first = images.process_image_bytes(b"encrypted", "key", 1, 2)
    last = images.process_image_bytes(b"encrypted", "key", 2, 2)
    with Image.open(BytesIO(first)) as decoded:
        decoded.load()
        size = decoded.size
    assert size == (16, 17)
    assert last == second


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"not jpeg",
        b"\xff\xd8",
        b"\xff\xd8\xff\xe1\x00",
        b"\xff\xd8\xff\xe1\x00\x01",
        b"\xff\xd8\xff\xe1\xff\xfftruncated",
    ],
)
def test_jpeg_parser_handles_truncated_metadata(payload):
    segments = images.extract_jpeg_segments(payload)
    assert segments == ([payload] if payload.startswith(b"\xff\xd8") else [])
