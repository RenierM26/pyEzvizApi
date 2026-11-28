"""Select EZVIZ panorama scope from reported inventory, without camera I/O."""

import json
from typing import Any

import pytest

from pyezvizapi.devices import panorama
from pyezvizapi.devices.channels import CameraChannel, camera_channels
from pyezvizapi.exceptions import PyEzvizError
from tests._paths import FIXTURES


def _panorama_page() -> dict[str, Any]:
    return {
        "deviceInfos": [
            {
                "deviceSerial": "CAM001",
                "deviceType": "TEST-MODEL",
                "version": "1.0",
                "supportExt": '{"81":"1"}',
            }
        ],
        "resourceInfos": [
            {"deviceSerial": "CAM001", "resourceIdentifier": "Video", "localIndex": "1"},
            {"deviceSerial": "CAM001", "resourceIdentifier": "Video_1", "localIndex": "2"},
        ],
        "PRODUCTS_INFO": {
            "PV(productId=TEST-MODEL, version=1.0)": {
                "profile": {
                    "resources": [
                        {"identifier": "Video", "localIndex": ["1"], "domains": []},
                        {
                            "identifier": "Video_1",
                            "localIndex": [2],
                            "domains": [
                                {
                                    "identifier": "Panorama",
                                    "actions": [{"identifier": "TriggerPanoramicCapture"}],
                                }
                            ],
                        },
                    ]
                }
            }
        },
    }


def test_resolve_panorama_uses_exact_resource_and_local_index() -> None:
    page = _panorama_page()
    device = panorama.resolve_panorama_capture_route(page, "cam001", channel=CameraChannel("Video", "1"))
    resource = panorama.resolve_panorama_capture_route(
        page, "CAM001", channel=CameraChannel("Video_1", "2")
    )
    assert (device, resource) == ("device", "resource")
    profile = next(iter(page["PRODUCTS_INFO"].values()))["profile"]
    profile["resources"][1]["localIndex"] = ["1"]
    wrong_index = panorama.resolve_panorama_capture_route(
        page, "CAM001", channel=CameraChannel("Video_1", "2")
    )
    assert wrong_index == "device"


def test_resolve_panorama_action_does_not_need_fullscreen_ptz_flag() -> None:
    page = _panorama_page()
    page["deviceInfos"][0]["supportExt"] = {}
    selected = panorama.resolve_panorama_capture_route(
        page, "CAM001", channel=CameraChannel("Video_1", "2")
    )
    assert selected == "resource"
    with pytest.raises(PyEzvizError, match="not advertised"):
        panorama.resolve_panorama_capture_route(page, "CAM001", channel=CameraChannel("Video", "1"))


def test_resolve_panorama_relay_takes_precedence_over_cloud_capture() -> None:
    page = _panorama_page()
    page["deviceInfos"][0]["supportExt"] = {"913": "1", "81": 1}
    selected = panorama.resolve_panorama_capture_route(
        page, "CAM001", channel=CameraChannel("Video_1", "2")
    )
    assert selected == "relay"


@pytest.mark.parametrize("field", ["product", "support", "channel", "domains"])
def test_resolve_panorama_missing_or_invalid_metadata_does_not_guess(field: str) -> None:
    page = _panorama_page()
    if field == "product":
        page["deviceInfos"][0]["version"] = "2.0"
    elif field == "support":
        page["deviceInfos"][0]["supportExt"] = "invalid JSON"
    elif field == "channel":
        page["resourceInfos"][1]["deviceSerial"] = "ANOTHER_CAMERA"
    else:
        profile = next(iter(page["PRODUCTS_INFO"].values()))["profile"]
        profile["resources"][1]["domains"][0]["actions"] = {}
    with pytest.raises(PyEzvizError):
        panorama.resolve_panorama_capture_route(page, "CAM001", channel=CameraChannel("Video_1", "2"))


def test_h9c_inventory_selects_device_scope_for_both_lenses() -> None:
    page = json.loads((FIXTURES / "page_list_response.json").read_text(encoding="utf-8"))
    serial = next(
        device["deviceSerial"]
        for device in page["deviceInfos"]
        if device["deviceSubCategory"] == "H9c"
    )
    channels = camera_channels(
        {"resourceInfos": [row for row in page["resourceInfos"] if row["deviceSerial"] == serial]}
    )
    assert len(channels) == 2
    routes = [panorama.resolve_panorama_capture_route(page, serial, channel=ch) for ch in channels]
    assert routes == ["device", "device"]
