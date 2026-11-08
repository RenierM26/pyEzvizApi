"""App-verified status rules, exercised through real device renderers offline."""

from copy import deepcopy
import json

import pytest

from pyezvizapi import DevicePollOptions, EzvizClient, PlugState
from pyezvizapi.constants import DeviceSwitchType
from pyezvizapi.devices.camera import EzvizCamera
from pyezvizapi.devices.detector import EzvizDetector
from pyezvizapi.devices.light_bulb import EzvizLightBulb
from pyezvizapi.devices.smart_plug import EzvizSmartPlug
from pyezvizapi.models import EzvizDeviceRecord


def payload(category="Socket"):
    return {
        "deviceInfos": {"deviceCategory": category, "status": 1, "supportExt": {}},
        "WIFI": {},
        "STATUS": {},
        "SWITCH": [{"type": 14, "enable": False}],
        "FEATURE": {
            "featureJson": json.dumps(
                {
                    "productId": "synthetic",
                    "featureItemDtos": [{"itemKey": "light_switch", "dataValue": False}],
                }
            )
        },
    }


def render(kind, raw):
    if kind == "camera":
        return EzvizCamera(None, "SYNTHETIC", raw).status(refresh=False)
    classes: dict[str, type[EzvizDetector] | type[EzvizLightBulb] | type[EzvizSmartPlug]] = {
        "detector": EzvizDetector,
        "light": EzvizLightBulb,
        "plug": EzvizSmartPlug,
    }
    return classes[kind](None, "SYNTHETIC", raw).status()


@pytest.mark.parametrize(
    "rows,expected",
    [
        ([{"channelNo": 0, "enable": False}, {"channelNo": 1, "enable": True}], False),
        ([{"channelNo": 1, "enable": True}, {"channelNo": 0, "enable": False}], False),
        ([{"channelNo": 0, "enable": False}, {"channelNo": 0, "enable": True}], False),
        ([{"enable": True}, {"channelNo": 0, "enable": False}], False),
        ([{"channelNo": 0, "enable": False}, {"enable": True}], False),
        ([{"channelNo": 1, "enable": True}, {"enable": False}], False),
        ([{"enable": False}, {"enable": True}], True),
        ([{"channelNo": "0", "enable": False}, {"channelNo": 2, "enable": True}], False),
        ([{"channelNo": 1, "enable": True}], None),
        ([{"channelNo": None, "enable": True}], None),
        ([{"channelNo": False, "enable": True}], None),
    ],
)
def test_plug_channel_selection_in_wrappers_records_and_typed_inventory(
    monkeypatch, rows, expected
):
    raw = payload()
    raw["SWITCH"] = [{"type": DeviceSwitchType.PLUG.value, **row} for row in rows]
    before = deepcopy(raw)
    record = EzvizDeviceRecord.from_api("SYNTHETIC", raw)
    assert record.switches.get(14) is expected
    assert EzvizSmartPlug(None, "SYNTHETIC", raw).status()["is_on"] is expected
    client = EzvizClient()
    try:
        monkeypatch.setattr(client, "get_device_records", lambda _: {"SYNTHETIC": record})
        snap = client.poll_devices(DevicePollOptions(include_camera_alarms=False))
        state = snap.devices["SYNTHETIC"]
        assert isinstance(state, PlugState)
        assert state.is_on is expected
        assert snap.health["SYNTHETIC"].current
        assert raw == before
    finally:
        client.close_session()


@pytest.mark.parametrize("kind", ["camera", "detector", "light", "plug"])
@pytest.mark.parametrize(
    "code,expected",
    [
        (0, False),
        (1, True),
        (2, True),
        (3, True),
        ("2", True),
        (-1, False),
        (None, False),
        (True, False),
        (1.5, False),
        ("bad", False),
    ],
)
def test_firmware_availability_accepts_positive_codes_without_truthiness(kind, code, expected):
    raw = payload()
    raw["UPGRADE"] = {"isNeedUpgrade": code}
    assert render(kind, raw)["upgrade_available"] is expected


@pytest.mark.parametrize("kind", ["camera", "detector", "light", "plug"])
@pytest.mark.parametrize(
    "code,phase,active",
    [
        (0, "upgrading", True),
        (1, "rebooting", True),
        (2, "current", False),
        (3, "failed", False),
        (14, "waiting", True),
        (15, "downloading", True),
        (17, None, False),
        (999, None, False),
        (None, None, False),
        (True, None, False),
        (1.5, None, False),
        ("1", "rebooting", True),
        ("bad", None, False),
    ],
)
def test_firmware_phases_keep_unknowns_and_report_all_active_ui_phases(kind, code, phase, active):
    raw = payload()
    raw["STATUS"] = {"upgradeStatus": code}
    state = render(kind, raw)
    assert state["upgrade_phase"] == phase
    assert state["upgrade_in_progress"] is active
    if type(code) is int:
        assert state["upgrade_status"] == code
    elif code == "1":
        assert state["upgrade_status"] == 1
    else:
        assert state["upgrade_status"] is None
