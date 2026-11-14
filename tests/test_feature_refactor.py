"""Behavior and compatibility contracts for the focused device module refactor."""

from io import BytesIO
import json
from typing import Any
from unittest.mock import MagicMock

from PIL import Image
import pytest

from pyezvizapi.devices import (
    audio,
    capabilities,
    controls,
    features,
    images,
    lens,
    metadata,
    ports,
    tracking,
)
from pyezvizapi.devices._port_payload import reported_port_security


@pytest.mark.parametrize(
    "module,names",
    [
        (capabilities, ("SupportExtView", "support_ext_dict", "support_ext_has")),
        (
            metadata,
            (
                "coerce_int",
                "coerce_bool",
                "wifi_ssid_value",
                "wifi_signal_value",
                "network_type_value",
                "sd_card_capacity_gb",
            ),
        ),
        (ports, ("PortSecurityToggle", "set_port_security_ports")),
        (lens, ("has_lens_defog", "set_lens_defog_option")),
        (
            tracking,
            (
                "ptz_master_slave_trace",
                "ensure_ptz_master_slave_trace",
                "linked_tracking_takeover_enabled",
                "set_linked_tracking_takeover",
                "intelligent_app_value_fn",
                "intelligent_app_method",
                "iter_intelligent_apps",
                "intelligent_app_enabled",
                "intelligent_app_available",
            ),
        ),
    ],
)
def test_existing_imports_are_identical_objects(module, names):
    for name in names:
        assert getattr(controls, name) is getattr(module, name)
        assert name in controls.__all__


@pytest.mark.parametrize(
    "value,expected", [(True, 1), (False, 0), (3.9, 3), (" 42 ", 42), ("no", None), (None, None)]
)
def test_legacy_control_scalar_coercion(value, expected):
    assert controls.coerce_int(value) == expected


@pytest.mark.parametrize("value,error", [(float("nan"), ValueError), (float("inf"), OverflowError)])
def test_control_coercion_keeps_existing_numeric_exceptions(value, error):
    with pytest.raises(error):
        controls.coerce_int(value)


@pytest.mark.parametrize(
    "setter,key,config,value",
    [
        (audio.set_alarm_volume, "ChimeMusic", {"volume": 20}, 30),
        (audio.set_alarm_voice_volume, "CustomVoice_Volume", {"volume": 20}, 30),
        (
            audio.set_microphone_volume,
            "CustomVoice_Volume",
            {"microphone_volume": "20", "future": 7},
            30,
        ),
    ],
)
def test_audio_setters_decode_configuration_once(monkeypatch, setter, key, config, value):
    payload = {"supportExt": {"185": "1", "203": "1"}, "optionals": {key: config}}
    original = audio.optionals_mapping
    reads = []

    def counted(data):
        reads.append(data)
        return original(data)

    monkeypatch.setattr(audio, "optionals_mapping", counted)
    client = MagicMock()
    setter(client, "CAM", value, payload)
    assert len(reads) == 1
    expected = {
        **config,
        "microphone_volume" if setter is audio.set_microphone_volume else "volume": value,
    }
    assert client.set_dev_config_kv.call_args.args[-1] == expected


@pytest.mark.parametrize(
    "value,expected",
    [(True, 1.0), ("20", 20.0), (20.8, 20.0), (None, None), ("bad", None), (101, None)],
)
def test_microphone_reader_preserves_tolerant_read_contract(value, expected):
    assert (
        audio.microphone_volume_getter(
            {"optionals": {"CustomVoice_Volume": {"microphone_volume": value}}}
        )
        == expected
    )


@pytest.mark.parametrize("encoded", [False, True])
def test_port_policies_keep_distinct_output_and_detached_writes(encoded):
    raw: dict[str, Any] = {
        "enabled": False,
        "value": {
            "opaque": {"keep": [1]},
            "portSecurityList": [
                {"portNo": "554", "enabled": 1, "vendor": "x"},
            ],
        },
    }
    payload = json.dumps(raw) if encoded else raw
    normalized = features.normalize_port_security(payload)
    reported = reported_port_security(payload)
    assert normalized == {"enabled": False, "portSecurityList": [{"portNo": 554, "enabled": True}]}
    assert reported == {**raw["value"], "enabled": False}
    reported["opaque"]["keep"].append(2)
    assert raw["value"]["opaque"]["keep"] == [1]


def test_read_wrapper_priority_and_write_insertion_order_remain_distinct():
    payload = {
        "unrelated": {"portSecurityList": [{"portNo": 1}]},
        "value": {"portSecurityList": [{"portNo": 2}]},
    }
    normalized = features.normalize_port_security(payload)
    reported = reported_port_security(payload)
    assert normalized["portSecurityList"][0]["portNo"] == 2
    assert reported["portSecurityList"][0]["portNo"] == 1


def test_invalid_raw_list_stops_its_branch_but_not_siblings():
    payload = {
        "first": {"portSecurityList": [False], "value": {"portSecurityList": [{"portNo": 1}]}},
        "next": {"portSecurityList": [{"portNo": 2}]},
    }
    assert reported_port_security(payload) == payload["next"]
    assert features.normalize_port_security(payload)["portSecurityList"][0]["portNo"] == 1


def test_port_cycles_do_not_mask_a_valid_sibling():
    payload: dict[str, Any] = {}
    payload["cycle"] = payload
    payload["value"] = {"portSecurityList": [{"portNo": 554}]}
    normalized = features.normalize_port_security(payload)
    reported = reported_port_security(payload)
    assert normalized["portSecurityList"][0]["portNo"] == 554
    assert reported == payload["value"]


@pytest.mark.parametrize("fail_save", [False, True])
def test_lens_images_are_closed_even_when_crop_encoding_fails(monkeypatch, fail_save):
    buf = BytesIO()
    Image.new("RGB", (8, 17)).save(buf, format="JPEG")
    closed = []
    original_close, original_save = Image.Image.close, Image.Image.save

    def close(image):
        closed.append(image.size)
        original_close(image)

    def save(image, *args, **kwargs):
        if fail_save:
            raise OSError("encoding failed")
        return original_save(image, *args, **kwargs)

    monkeypatch.setattr(Image.Image, "close", close)
    monkeypatch.setattr(Image.Image, "save", save)
    if fail_save:
        with pytest.raises(OSError, match="encoding failed"):
            images.split_composite_image(buf.getvalue(), 2)
        assert closed == [(8, 8), (8, 17)]
    else:
        output = images.split_composite_image(buf.getvalue(), 2)
        assert len(output) == 2
        assert closed == [(8, 8), (8, 9), (8, 17)]


def test_decoded_empty_branches_do_not_hide_later_encoded_port_objects():
    raw = {"portSecurityList": [{"portNo": 554, "enabled": True}]}
    for _ in range(30):
        payload = {"PortSecurity": json.dumps({"ignored": {}}), "value": json.dumps(raw)}
        normalized = features.normalize_port_security(payload)
        reported = reported_port_security(payload)
        assert normalized == {**raw, "enabled": True}
        assert reported == raw
