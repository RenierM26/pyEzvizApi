"""Offline tests for the separate doorbell ringtone setting."""

import json
from unittest.mock import Mock

import pytest

from pyezvizapi.devices.audio import set_doorbell_ringtone_volume
from pyezvizapi.exceptions import PyEzvizError


def test_ringtone_volume_preserves_tone_and_custom_slot() -> None:
    client = Mock()
    config = {"Type": 10, "Volume": 4, "CustomRingIndex": 2}
    data = {"supportExt": {"241": "2"}, "STATUS": {"optionals": {"device_bell": config}}}

    set_doorbell_ringtone_volume(client, "TEST", 0, data)

    serial, channel, key, payload = client.set_device_key_value.call_args.args
    assert (serial, channel, key) == ("TEST", 1, "device_bell")
    assert json.loads(payload) == {"Type": 10, "Volume": 0, "CustomRingIndex": 2}
    assert config["Volume"] == 4


@pytest.mark.parametrize("value", [True, -1, 8])
def test_invalid_ringtone_volume_is_rejected(value: int) -> None:
    client = Mock()
    with pytest.raises(PyEzvizError, match="integer from 0 to 7"):
        set_doorbell_ringtone_volume(client, "TEST", value, {})
    client.set_device_key_value.assert_not_called()


def test_volume_does_not_guess_missing_tone() -> None:
    client = Mock()
    data = {"supportExt": {"241": 1}, "optionals": {"device_bell": {"Volume": 4}}}
    with pytest.raises(PyEzvizError, match="usable ringtone configuration"):
        set_doorbell_ringtone_volume(client, "TEST", 3, data)
    client.set_device_key_value.assert_not_called()
