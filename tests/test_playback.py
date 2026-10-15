"""Confirmed app capability conditions, not heuristic lip-sync discovery."""

from dataclasses import asdict
import json

import pytest

from pyezvizapi import inspect_app_playback_support


@pytest.mark.parametrize("support", [{"63": "1", "915": "1"}, {"63": 1, "915": 1}, '{"63":"1","915":"1"}'])
def test_numeric_app_capability_gates(support):
    assert asdict(inspect_app_playback_support({"deviceInfos": {"supportExt": support}})) == {
        "audio_on_off": True, "auto_smooth_play": True,
    }


@pytest.mark.parametrize("value", [None, "", "1,2", "true", True, 1.0, " 1", "1 ", "2147483648", "-2147483649", "2", "0"])
def test_smoothing_requires_integer_one_not_truthy_or_csv(value):
    result = inspect_app_playback_support({"deviceInfos": {"supportExt": {"915": value}}})
    assert result.auto_smooth_play is False


@pytest.mark.parametrize("value", ["+1", "01", "0000000000000000000000001"])
def test_smoothing_uses_integer_parsing_not_string_equality(value):
    assert inspect_app_playback_support({"deviceInfos": {"supportExt": {"915": value}}}).auto_smooth_play is True


@pytest.mark.parametrize("device", [{}, {"deviceInfos": None}, {"deviceInfos": {"supportExt": "bad"}}, {"deviceInfos": {"supportExt": []}}])
def test_unavailable_metadata_is_not_a_negative_probe(device):
    result = inspect_app_playback_support(device)
    assert result.auto_smooth_play is None
    assert result.audio_on_off is None


def test_missing_numeric_flag_has_app_default_and_ignores_other_maps():
    # EZVIZ converter ignores DeviceParam's named feature argument.
    support = {"63": "1", "519": "3"}
    device = {"deviceInfos": {"supportExt": support,
                             "ezDeviceCapability": json.dumps({"915": "1"})},
              "FEATURE": {"support_auto_smooth_play": "1"}}
    result = inspect_app_playback_support(device)
    assert result.audio_on_off is True
    assert result.auto_smooth_play is False
    assert support == {"63": "1", "519": "3"}
