"""Verify defog writes and cache changes target the same video resource."""

from unittest.mock import Mock

import pytest

from pyezvizapi.devices.channels import CameraChannel, CameraChannelError
from pyezvizapi.devices.lens import has_lens_defog, set_lens_defog_option
from pyezvizapi.exceptions import PyEzvizError


def test_explicit_route_updates_only_selected_configuration() -> None:
    client = Mock()
    client.set_lens_defog_mode.return_value = False, "auto"
    other = {"enabled": True, "defogMode": "open"}
    target = other.copy()
    data = {
        "resourceInfos": [
            {"resourceIdentifier": "Video_1", "localIndex": 1},
            {"resourceIdentifier": "Video", "localIndex": 2},
        ],
        "FEATURE_INFO": {
            "1": {"Video": {"LensCleaning": {"DefogCfg": other}}},
            "2": {"Video": {"LensCleaning": {"DefogCfg": target}}},
        },
    }

    channel = CameraChannel("Video", "2")
    assert has_lens_defog(data, channel=channel)
    set_lens_defog_option(client, "CAM123", 2, data, channel=channel)

    client.set_lens_defog_mode.assert_called_once_with("CAM123", 2, local_index="2")
    assert other == {"enabled": True, "defogMode": "open"}
    assert target == {"enabled": False, "defogMode": "auto"}


@pytest.mark.parametrize("channel", [CameraChannel("Video", "2"), CameraChannel("Video_1", "1")])
def test_unproven_route_never_falls_back(channel: CameraChannel) -> None:
    client = Mock()
    data = {"resourceInfos": [{"resourceIdentifier": "Video_1", "localIndex": 1}]}

    assert not has_lens_defog(data, channel=channel)
    with pytest.raises(CameraChannelError, match="unsupported"):
        set_lens_defog_option(client, "CAM123", 2, data, channel=channel)

    client.set_lens_defog_mode.assert_not_called()


def test_rejected_write_does_not_update_cache() -> None:
    client = Mock()
    client.set_lens_defog_mode.side_effect = PyEzvizError("rejected")
    config = {"enabled": True, "defogMode": "open"}
    data = {
        "resourceInfos": [{"resourceIdentifier": "Video", "localIndex": 2}],
        "FEATURE_INFO": {"2": {"Video": {"LensCleaning": {"DefogCfg": config}}}},
    }

    with pytest.raises(PyEzvizError, match="rejected"):
        set_lens_defog_option(client, "CAM123", 2, data, channel=CameraChannel("Video", "2"))

    assert config == {"enabled": True, "defogMode": "open"}
    client.set_lens_defog_mode.assert_called_once_with("CAM123", 2, local_index="2")


def test_legacy_call_preserves_default_scope() -> None:
    client = Mock()
    client.set_lens_defog_mode.return_value = True, "auto"
    config = {"enabled": False, "defogMode": "auto"}
    data = {"FEATURE_INFO": {"1": {"Video": {"LensCleaning": {"DefogCfg": config}}}}}

    set_lens_defog_option(client, "CAM123", 0, data)

    client.set_lens_defog_mode.assert_called_once_with("CAM123", 0)
    assert config["enabled"] is True
