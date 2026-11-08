from __future__ import annotations

from pyezvizapi.feature import (
    blc_current_value,
    custom_voice_volume_config,
    day_night_mode_value,
    day_night_sensitivity_value,
    device_icr_dss_config,
    display_mode_value,
    get_algorithm_value,
    has_algorithm_subtype,
    has_osd_overlay,
    iter_algorithm_entries,
    iter_channel_algorithm_entries,
    lens_defog_config,
    lens_defog_value,
    night_vision_config,
    night_vision_duration_value,
    night_vision_luminance_value,
    night_vision_mode_value,
    night_vision_payload,
    normalize_port_security,
    optionals_dict,
    optionals_mapping,
    port_security_config,
    port_security_has_port,
    port_security_port_enabled,
    resolve_channel,
    supplement_light_available,
    supplement_light_enabled,
    supplement_light_params,
    support_ext_value,
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


def test_feature_helper_wrappers_and_support_ext_values() -> None:
    payload = {
        "deviceInfos": {"supportExt": {"audio": 1}},
        "statusInfo": {
            "optionals": {
                "AlgorithmInfo": [
                    {"channel": "1", "SubType": "human", "Value": "1"},
                    {"channel": 2, "SubType": "vehicle", "Value": "0"},
                ],
                "device_ICR_DSS": '{"mode": 1, "sensitivity": 3}',
            }
        },
    }

    assert optionals_dict(payload) == optionals_mapping(payload)
    assert list(iter_algorithm_entries(payload)) == [
        {"channel": "1", "SubType": "human", "Value": "1"},
        {"channel": 2, "SubType": "vehicle", "Value": "0"},
    ]
    assert list(iter_channel_algorithm_entries(payload, 2)) == [
        {"channel": 2, "SubType": "vehicle", "Value": "0"}
    ]
    assert get_algorithm_value(payload, "human", 1) == 1
    assert get_algorithm_value(payload, "missing", 1) is None
    assert support_ext_value(payload, "audio") == "1"
    assert support_ext_value(payload, "missing") is None
    assert device_icr_dss_config(payload) == {"mode": 1, "sensitivity": 3}
    assert day_night_sensitivity_value(payload) == 3


def test_supplement_and_defog_configs_return_empty_defaults() -> None:
    assert supplement_light_params({}) == {}
    assert supplement_light_enabled({"FEATURE_INFO": {}}) is False
    assert lens_defog_config({"FEATURE_INFO": {"0": {"Video": {"LensCleaning": "bad"}}}}) == {}
    assert lens_defog_value({"FEATURE_INFO": {"0": {"Video": {"LensCleaning": {"DefogCfg": {"enabled": False}}}}}}) == 2


def test_port_security_config_can_fall_back_to_feature_info() -> None:
    payload = {
        "FEATURE_INFO": {
            "nested": {
                "NetworkSecurityProtection": {
                    "portSecurityList": '[{"portNo": "554", "enabled": true}]'
                }
            }
        }
    }

    assert port_security_config(payload) == {
        "enabled": True,
        "portSecurityList": [{"portNo": 554, "enabled": True}],
    }
    assert port_security_has_port({}, 554) is False
    assert port_security_port_enabled({}, 554) is False


def test_channel_night_vision_and_osd_helpers_return_safe_defaults() -> None:
    assert resolve_channel({"channelNo": "3"}) == 3
    assert resolve_channel({"channel_no": 4}) == 4
    assert resolve_channel({}) == 1

    payload = {"statusInfo": {"optionals": {"NightVision_Model": '{"graphicType": "5"}'}}}
    assert night_vision_config(payload) == {"graphicType": "5"}
    assert night_vision_mode_value(payload) == 5
    assert night_vision_luminance_value(payload) == 40
    assert night_vision_duration_value(payload) == 60
    assert night_vision_mode_value({"NightVision_Model": {"graphicType": 99}}) == 0

    assert has_osd_overlay({"statusInfo": {"optionals": {"OSD": {"name": "Front"}}}}) is True
    assert has_osd_overlay({"statusInfo": {"optionals": {"OSD": [{"name": "  "}, {"name": "Side"}]}}}) is True
    assert has_osd_overlay({"statusInfo": {"optionals": {"OSD": []}}}) is False
