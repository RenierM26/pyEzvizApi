from __future__ import annotations

from pyezvizapi.feature import (
    blc_current_value,
    custom_voice_volume_config,
    day_night_mode_value,
    display_mode_value,
    has_algorithm_subtype,
    lens_defog_value,
    night_vision_payload,
    normalize_port_security,
    optionals_mapping,
    port_security_has_port,
    port_security_port_enabled,
    supplement_light_available,
    supplement_light_enabled,
)


def test_optionals_mapping_decodes_supported_locations() -> None:
    assert optionals_mapping({"statusInfo": {"optionals": '{"display_mode": {"mode": 2}}'}}) == {
        "display_mode": {"mode": 2}
    }
    assert optionals_mapping({"STATUS": {"optionals": '{"inverse_mode": {"enable": 1}}'}}) == {
        "inverse_mode": {"enable": 1}
    }


def test_feature_helpers_decode_nested_json_strings() -> None:
    payload = {
        "statusInfo": {
            "optionals": {
                "CustomVoice_Volume": '{"volume": "7", "microphone_volume": 3}',
                "AlgorithmInfo": [
                    {"channel": "1", "SubType": "human", "Value": "1"},
                    {"channel": 2, "SubType": "vehicle", "Value": 0},
                ],
                "display_mode": '{"mode": 3}',
                "inverse_mode": {"enable": 1, "position": 4},
                "device_ICR_DSS": '{"mode": 2, "sensitivity": 3}',
            }
        }
    }

    assert custom_voice_volume_config(payload) == {"volume": 7, "microphone_volume": 3}
    assert has_algorithm_subtype(payload, "human", channel=1) is True
    assert has_algorithm_subtype(payload, "human", channel=2) is False
    assert display_mode_value(payload) == 3
    assert blc_current_value(payload) == 4
    assert day_night_mode_value(payload) == 2


def test_supplement_light_and_defog_helpers() -> None:
    payload = {
        "FEATURE_INFO": {
            "0": {
                "Video": {
                    "SupplementLightMgr": '{"ImageSupplementLightModeSwitchParams": "{\\"enabled\\": \\"true\\"}"}',
                    "LensCleaning": {"DefogCfg": {"enabled": True, "defogMode": "open"}},
                }
            }
        }
    }

    assert supplement_light_available(payload) is True
    assert supplement_light_enabled(payload) is True
    assert lens_defog_value(payload) == 1


def test_port_security_normalization_handles_nested_payloads() -> None:
    payload = {
        "NetworkSecurityProtection": {
            "enabled": True,
            "value": '{"portSecurityList": [{"portNo": "554", "enabled": true}, {"portNo": 8000, "enabled": false}]}',
        }
    }

    assert port_security_has_port(payload, 554) is True
    assert port_security_port_enabled(payload, 554) is True
    assert port_security_port_enabled(payload, 8000) is False

    normalized = normalize_port_security(payload)
    assert normalized["enabled"] is True
    assert normalized["portSecurityList"] == [
        {"portNo": 554, "enabled": True},
        {"portNo": 8000, "enabled": False},
    ]


def test_night_vision_payload_sanitizes_mode_specific_fields() -> None:
    payload = {
        "statusInfo": {
            "optionals": {
                "NightVision_Model": '{"graphicType": "2", "luminance": "10", "duration": "999"}'
            }
        }
    }

    smart = night_vision_payload(payload)
    assert smart["graphicType"] == 2
    assert smart["luminance"] == 20
    assert smart["duration"] == 120

    color = night_vision_payload(payload, mode=1, luminance=5)
    assert color["graphicType"] == 1
    assert color["luminance"] == 20
    assert "duration" not in color
