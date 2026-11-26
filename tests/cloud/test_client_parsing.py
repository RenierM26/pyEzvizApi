from __future__ import annotations

import json
from typing import Any

import pytest

import pyezvizapi.client as client_module
from pyezvizapi.constants import DeviceCatagories
from pyezvizapi.devices.channels import camera_channels
from tests._paths import FIXTURES

FULL_PAGE_LIST_FIXTURE = FIXTURES / "page_list_response.json"


def _full_page_list_fixture() -> dict[str, Any]:
    return json.loads(FULL_PAGE_LIST_FIXTURE.read_text(encoding="utf-8"))


def _page_list_fixture() -> dict[str, Any]:
    return {
        "deviceInfos": [
            {
                "deviceSerial": "CAM123",
                "name": "Front Camera",
                "deviceCategory": DeviceCatagories.CAMERA_DEVICE_CATEGORY.value,
                "deviceSubCategory": "C3X",
                "status": 1,
                "version": "1.0.0",
                "supportExt": '{"SupportExt": "camera"}',
            },
            {
                "deviceSerial": "LIGHT123",
                "name": "Porch Light",
                "deviceCategory": DeviceCatagories.LIGHTING.value,
                "deviceSubCategory": "bulb",
                "status": 1,
                "supportExt": "{}",
            },
            {
                "deviceSerial": "PLUG123",
                "name": "Heater Plug",
                "deviceCategory": DeviceCatagories.SOCKET.value,
                "deviceSubCategory": "plug",
                "status": 1,
                "supportExt": "{}",
            },
            {
                "deviceSerial": "COMMON123",
                "name": "Unsupported Common Device",
                "deviceCategory": DeviceCatagories.COMMON_DEVICE_CATEGORY.value,
                "status": 1,
                "hik": False,
            },
        ],
        "CLOUD": {
            "res-cam": {"deviceSerial": "CAM123", "cloud": True},
            "res-light": {"deviceSerial": "LIGHT123", "cloud": True},
            "res-plug": {"deviceSerial": "PLUG123", "cloud": True},
        },
        "VTM": {
            "res-cam": {"batteryLevel": 87},
            "res-light": {},
            "res-plug": {},
        },
        "P2P": {"CAM123": {"p2p": True}},
        "CONNECTION": {"CAM123": {"localIp": "192.0.2.10"}},
        "KMS": {"CAM123": {"kms": True}},
        "STATUS": {
            "CAM123": {"globalStatus": 1, "optionals": {"NightVision_Model": "{}"}},
            "LIGHT123": {"globalStatus": 1},
            "PLUG123": {"globalStatus": 1},
        },
        "TIME_PLAN": {"CAM123": {"schedule": True}},
        "CHANNEL": {"res-cam": {"channelNo": 1}},
        "QOS": {"CAM123": {"qos": True}},
        "NODISTURB": {"CAM123": {"enabled": False}},
        "FEATURE": {"CAM123": {"featureJson": "{}"}},
        "UPGRADE": {"CAM123": {"latestVersion": "1.0.1"}},
        "FEATURE_INFO": {"CAM123": {"0": {"Video": {}}}},
        "SWITCH": {"CAM123": [{"type": 7, "enable": 1}]},
        "CUSTOM_TAG": {"CAM123": {"tag": "front"}},
        "VIDEO_QUALITY": {"res-cam": {"quality": "hd"}},
        "resourceInfos": [
            {"deviceSerial": "CAM123", "resourceId": "res-cam"},
            {"deviceSerial": "OTHER", "resourceId": "res-other"},
        ],
        "WIFI": {"CAM123": {"address": "192.0.2.10"}},
    }


def _client_with_fixture(monkeypatch) -> client_module.EzvizClient:
    client = client_module.EzvizClient(
        token={"session_id": "session", "api_url": "apiieu.ezvizlife.com"}
    )
    monkeypatch.setattr(client, "_get_page_list", _page_list_fixture)
    monkeypatch.setattr(client, "_get_device_page", lambda _serial: None)
    return client


def test_get_device_infos_builds_serial_keyed_payloads(monkeypatch) -> None:
    client = _client_with_fixture(monkeypatch)

    devices = client.get_device_infos()

    assert set(devices) == {"CAM123", "LIGHT123", "PLUG123", "COMMON123"}
    camera = devices["CAM123"]
    assert camera["deviceInfos"]["supportExt"] == {"SupportExt": "camera"}
    assert camera["CLOUD"] == {"res-cam": {"deviceSerial": "CAM123", "cloud": True}}
    assert camera["CHANNEL"] == {"res-cam": {"channelNo": 1}}
    assert camera["VIDEO_QUALITY"] == {"res-cam": {"quality": "hd"}}
    assert camera["resourceInfos"] == [
        {"deviceSerial": "CAM123", "resourceId": "res-cam"}
    ]
    assert camera["SWITCH"] == [{"type": 7, "enable": 1}]


def test_get_device_infos_can_filter_to_one_serial(monkeypatch) -> None:
    client = _client_with_fixture(monkeypatch)

    camera = client.get_device_infos("CAM123")

    assert camera["deviceInfos"]["name"] == "Front Camera"
    assert client.get_device_infos("MISSING") == {}


@pytest.mark.parametrize("scenario", ["match", "wrong_serial", "multiple_resources"])
def test_serial_lookup_prefers_scoped_response_and_falls_back(monkeypatch, scenario) -> None:
    client = client_module.EzvizClient()
    page = _page_list_fixture()
    page["deviceInfos"] = [page["deviceInfos"][1 if scenario == "wrong_serial" else 0]]
    if scenario != "multiple_resources":
        page["resourceInfos"] = page["resourceInfos"][:1]
    calls = []

    def request(method, path, **kwargs):
        calls.append((method, path, kwargs["params"]))
        return {"meta": {"code": 200}, **page}

    def inventory():
        assert scenario != "match", "matching direct response must not fetch the full account"
        return _page_list_fixture()

    monkeypatch.setattr(client, "_request_json", request)
    monkeypatch.setattr(client, "_get_page_list", inventory)
    assert client.get_device_infos("CAM123")["deviceInfos"]["deviceSerial"] == "CAM123"
    assert calls[0][:2] == ("GET", "/v3/userdevices/v1/resources/CAM123")
    assert len(calls) == 1


@pytest.mark.parametrize(
    "resources",
    [
        None,
        {},
        [],
        [None],
        [{"deviceSerial": "OTHER", "resourceId": "res-other"}],
        [{"deviceSerial": "CAM123", "resourceId": " "}],
    ],
)
def test_serial_lookup_recovers_missing_resource_metadata(monkeypatch, resources) -> None:
    client = client_module.EzvizClient()
    account = _page_list_fixture()
    account["VTM"] = {"res-cam": {"port": 8554}}
    scoped = {"meta": {"code": 200}, "deviceInfos": account["deviceInfos"][:1]}
    if resources is not None:
        scoped["resourceInfos"] = resources
    monkeypatch.setattr(client, "_request_json", lambda *a, **kw: scoped)
    monkeypatch.setattr(client, "_get_page_list", lambda: account)

    record = client.get_device_records("CAM123")

    assert isinstance(record, client_module.EzvizDeviceRecord)
    assert record.source["resourceInfos"] == account["resourceInfos"][:1]
    assert record.raw["VTM"] == {"res-cam": {"port": 8554}}


def test_serial_lookup_falls_back_to_pagelist_session_recovery(monkeypatch) -> None:
    client = client_module.EzvizClient()
    events = []
    page = {"meta": {"code": 200}, "page": {"hasNext": False}, **_page_list_fixture()}
    scoped_path = "/v3/userdevices/v1/resources/CAM123"
    pagelist_path = "/v3/userdevices/v1/resources/pagelist"

    def request(_method, path, **_kwargs):
        events.append(path)
        if events[-2:] == ["login", pagelist_path]:
            return page
        return {"meta": {"code": 401}}

    monkeypatch.setattr(client, "_request_json", request)
    monkeypatch.setattr(client, "login", lambda: events.append("login"))

    assert client.get_device_infos("CAM123")["deviceInfos"]["deviceSerial"] == "CAM123"
    assert events == [scoped_path, pagelist_path, "login", pagelist_path]


def test_serial_lookup_preserves_channel_resources_without_decoding_other_devices(
    monkeypatch,
) -> None:
    client = _client_with_fixture(monkeypatch)
    page = _page_list_fixture()
    page["CLOUD"] = {
        "res-a": {"deviceSerial": "CAM123", "channelNo": 2},
        **page["CLOUD"],
    }
    page["CLOUD"]["res-cam"]["channelNo"] = 1
    page["CHANNEL"]["res-a"] = {"channelNo": 2}
    secondary = {"deviceSerial": "CAM123", "resourceId": "res-a", "localIndex": 2}
    page["resourceInfos"].insert(0, secondary)
    monkeypatch.setattr(client, "_get_page_list", lambda: page)

    record = client.get_device_records("CAM123")

    assert isinstance(record, client_module.EzvizDeviceRecord)
    assert record.raw["CLOUD"] == {"res-cam": page["CLOUD"]["res-cam"]}
    assert record.raw["resourceInfos"] == [secondary, page["resourceInfos"][1]]
    assert page["deviceInfos"][1]["supportExt"] == "{}"
    assert record.source["CLOUD"] == {
        "res-a": page["CLOUD"]["res-a"],
        "res-cam": page["CLOUD"]["res-cam"],
    }
    assert record.source["CHANNEL"] == page["CHANNEL"]
    assert record.raw["CHANNEL"] == {"res-cam": {"channelNo": 1}}
    assert record.source["deviceInfos"]["supportExt"] == '{"SupportExt": "camera"}'
    assert record.raw["deviceInfos"]["supportExt"] == {"SupportExt": "camera"}
    assert record.source["STATUS"]["optionals"]["NightVision_Model"] == "{}"
    assert record.raw["STATUS"]["optionals"]["NightVision_Model"] == {}
    assert page["STATUS"]["CAM123"]["optionals"]["NightVision_Model"] == "{}"
    assert client.get_device_records("MISSING") == {}


def test_poll_without_products_info_keeps_state_and_channel_routes(monkeypatch) -> None:
    client = _client_with_fixture(monkeypatch)
    page = _full_page_list_fixture()
    options = client_module.DevicePollOptions(include_camera_alarms=False)
    monkeypatch.setattr(client, "_get_page_list", lambda: page)

    def unexpected_switch_parse(_rows):
        raise AssertionError("camera renderer must reuse the record's switch map")

    monkeypatch.setattr("pyezvizapi.devices.camera.switch_values", unexpected_switch_parse)
    full = client.poll_devices(options)
    assert len(full.devices) == len(page["deviceInfos"])
    assert all(health.current for health in full.health.values())

    page.pop("PRODUCTS_INFO")
    reduced = client.poll_devices(options)

    assert reduced.devices == full.devices
    assert {
        serial: camera_channels(values)
        for serial, values in reduced.as_dict("camera").items()
    } == {
        serial: camera_channels(values)
        for serial, values in full.as_dict("camera").items()
    }


def test_full_pagelist_fixture_builds_device_infos(monkeypatch) -> None:
    page_list = _full_page_list_fixture()
    client = client_module.EzvizClient(
        token={"session_id": "session", "api_url": "apiieu.ezvizlife.com"}
    )
    monkeypatch.setattr(client, "_get_page_list", lambda: page_list)

    devices = client.get_device_infos()

    expected_sections = {
        "CHANNEL",
        "CLOUD",
        "CONNECTION",
        "FEATURE_INFO",
        "KMS",
        "P2P",
        "STATUS",
        "SWITCH",
        "VTM",
        "WIFI",
        "deviceInfos",
        "resourceInfos",
    }
    assert expected_sections.issubset(page_list)
    expected_serials = {
        device["deviceSerial"] for device in page_list["deviceInfos"]
    }
    assert set(devices) == expected_serials
    assert devices
    for serial, payload in devices.items():
        assert payload["deviceInfos"]["deviceSerial"] == serial
        assert isinstance(payload["resourceInfos"], list)


def test_full_pagelist_fixture_load_devices_routes_supported_categories(
    monkeypatch,
) -> None:
    page_list = _full_page_list_fixture()
    client = client_module.EzvizClient(
        token={"session_id": "session", "api_url": "apiieu.ezvizlife.com"}
    )
    monkeypatch.setattr(client, "_get_page_list", lambda: page_list)

    calls: list[tuple[str, str]] = []

    def fake_camera_status(
        _client: client_module.EzvizClient,
        serial: str,
        _device_obj: dict[str, Any],
        *,
        refresh: bool,
        latest_alarm: dict[str, Any] | None,
        switches: dict[int, bool] | None = None,
    ) -> dict[str, Any]:
        calls.append(("camera", serial))
        return {
            "kind": "camera",
            "serial": serial,
            "refresh": refresh,
            "latest_alarm": latest_alarm,
        }

    def fake_light_bulb_status(
        _client: client_module.EzvizClient,
        serial: str,
        _device_obj: dict[str, Any],
    ) -> dict[str, Any]:
        calls.append(("light", serial))
        return {"kind": "light", "serial": serial}

    def fake_smart_plug_status(
        _client: client_module.EzvizClient,
        serial: str,
        _device_obj: dict[str, Any],
    ) -> dict[str, Any]:
        calls.append(("plug", serial))
        return {"kind": "plug", "serial": serial}

    monkeypatch.setattr(
        "pyezvizapi.devices.factory.camera_status", fake_camera_status
    )
    monkeypatch.setattr(
        "pyezvizapi.devices.factory.light_bulb_status", fake_light_bulb_status
    )
    monkeypatch.setattr(
        "pyezvizapi.devices.factory.smart_plug_status", fake_smart_plug_status
    )

    loaded = client.load_devices(refresh=False)

    fixture_serials = {device["deviceSerial"] for device in page_list["deviceInfos"]}
    assert loaded
    assert set(loaded).issubset(fixture_serials)
    assert set(loaded) == {serial for _, serial in calls}


def test_load_devices_routes_supported_categories(monkeypatch) -> None:
    client = _client_with_fixture(monkeypatch)

    class FakeCamera:
        def __init__(self, _client: client_module.EzvizClient, serial: str, device_obj: dict[str, Any], *, switches=None) -> None:
            self.serial = serial
            self.device_obj = device_obj

        def status(self, *, refresh: bool = True, latest_alarm: dict[str, Any] | None = None) -> dict[str, Any]:
            return {
                "kind": "camera",
                "serial": self.serial,
                "refresh": refresh,
                "latest_alarm": latest_alarm,
                "name": self.device_obj["deviceInfos"]["name"],
            }

    class FakeLightBulb:
        def __init__(self, _client: client_module.EzvizClient, serial: str, _device_obj: dict[str, Any]) -> None:
            self.serial = serial

        def status(self) -> dict[str, Any]:
            return {"kind": "light", "serial": self.serial}

    class FakeSmartPlug:
        def __init__(self, _client: client_module.EzvizClient, serial: str, _device_obj: dict[str, Any]) -> None:
            self.serial = serial

        def status(self) -> dict[str, Any]:
            return {"kind": "plug", "serial": self.serial}

    monkeypatch.setattr("pyezvizapi.devices.factory.EzvizCamera", FakeCamera)
    monkeypatch.setattr("pyezvizapi.devices.factory.EzvizLightBulb", FakeLightBulb)
    monkeypatch.setattr("pyezvizapi.devices.factory.EzvizSmartPlug", FakeSmartPlug)

    loaded = client.load_devices(refresh=False)

    assert loaded == {
        "CAM123": {
            "kind": "camera",
            "serial": "CAM123",
            "refresh": False,
            "latest_alarm": None,
            "name": "Front Camera",
        },
        "LIGHT123": {"kind": "light", "serial": "LIGHT123"},
        "PLUG123": {"kind": "plug", "serial": "PLUG123"},
    }
    assert "COMMON123" not in loaded


def test_load_light_bulbs_returns_only_light_statuses(monkeypatch) -> None:
    client = _client_with_fixture(monkeypatch)

    class FakeCamera:
        def __init__(self, _client: client_module.EzvizClient, serial: str, _device_obj: dict[str, Any], *, switches=None) -> None:
            self.serial = serial

        def status(self, *, refresh: bool = True, latest_alarm: dict[str, Any] | None = None) -> dict[str, Any]:
            return {"kind": "camera", "serial": self.serial, "refresh": refresh}

    class FakeLightBulb:
        def __init__(self, _client: client_module.EzvizClient, serial: str, device_obj: dict[str, Any]) -> None:
            self.serial = serial
            self.device_obj = device_obj

        def status(self) -> dict[str, Any]:
            return {
                "kind": "light",
                "serial": self.serial,
                "name": self.device_obj["deviceInfos"]["name"],
            }

    class FakeSmartPlug:
        def __init__(self, _client: client_module.EzvizClient, serial: str, _device_obj: dict[str, Any]) -> None:
            self.serial = serial

        def status(self) -> dict[str, Any]:
            return {"kind": "plug", "serial": self.serial}

    monkeypatch.setattr("pyezvizapi.devices.factory.EzvizCamera", FakeCamera)
    monkeypatch.setattr("pyezvizapi.devices.factory.EzvizLightBulb", FakeLightBulb)
    monkeypatch.setattr("pyezvizapi.devices.factory.EzvizSmartPlug", FakeSmartPlug)

    lights = client.load_light_bulbs(refresh=False)

    assert lights == {
        "LIGHT123": {"kind": "light", "serial": "LIGHT123", "name": "Porch Light"}
    }
    assert client._cameras == {"CAM123": {"kind": "camera", "serial": "CAM123", "refresh": False}}
    assert client._smart_plugs == {"PLUG123": {"kind": "plug", "serial": "PLUG123"}}


def test_load_smart_plugs_returns_only_plug_statuses(monkeypatch) -> None:
    client = _client_with_fixture(monkeypatch)

    class FakeCamera:
        def __init__(self, _client: client_module.EzvizClient, serial: str, _device_obj: dict[str, Any], *, switches=None) -> None:
            self.serial = serial

        def status(self, *, refresh: bool = True, latest_alarm: dict[str, Any] | None = None) -> dict[str, Any]:
            return {"kind": "camera", "serial": self.serial, "refresh": refresh}

    class FakeLightBulb:
        def __init__(self, _client: client_module.EzvizClient, serial: str, _device_obj: dict[str, Any]) -> None:
            self.serial = serial

        def status(self) -> dict[str, Any]:
            return {"kind": "light", "serial": self.serial}

    class FakeSmartPlug:
        def __init__(self, _client: client_module.EzvizClient, serial: str, device_obj: dict[str, Any]) -> None:
            self.serial = serial
            self.device_obj = device_obj

        def status(self) -> dict[str, Any]:
            return {
                "kind": "plug",
                "serial": self.serial,
                "name": self.device_obj["deviceInfos"]["name"],
            }

    monkeypatch.setattr("pyezvizapi.devices.factory.EzvizCamera", FakeCamera)
    monkeypatch.setattr("pyezvizapi.devices.factory.EzvizLightBulb", FakeLightBulb)
    monkeypatch.setattr("pyezvizapi.devices.factory.EzvizSmartPlug", FakeSmartPlug)

    plugs = client.load_smart_plugs(refresh=False)

    assert plugs == {
        "PLUG123": {"kind": "plug", "serial": "PLUG123", "name": "Heater Plug"}
    }
    assert client._light_bulbs == {"LIGHT123": {"kind": "light", "serial": "LIGHT123"}}


def test_load_devices_keeps_previous_light_status_when_new_status_fails(monkeypatch, caplog) -> None:
    client = _client_with_fixture(monkeypatch)
    client._light_bulbs["LIGHT123"] = {"kind": "light", "serial": "LIGHT123", "stale": True}

    class FakeCamera:
        def __init__(self, _client: client_module.EzvizClient, serial: str, _device_obj: dict[str, Any], *, switches=None) -> None:
            self.serial = serial

        def status(self, *, refresh: bool = True, latest_alarm: dict[str, Any] | None = None) -> dict[str, Any]:
            return {"kind": "camera", "serial": self.serial}

    class BrokenLightBulb:
        def __init__(self, _client: client_module.EzvizClient, _serial: str, _device_obj: dict[str, Any]) -> None:
            pass

        def status(self) -> dict[str, Any]:
            raise ValueError("bad feature json")

    class FakeSmartPlug:
        def __init__(self, _client: client_module.EzvizClient, serial: str, _device_obj: dict[str, Any]) -> None:
            self.serial = serial

        def status(self) -> dict[str, Any]:
            return {"kind": "plug", "serial": self.serial}

    monkeypatch.setattr("pyezvizapi.devices.factory.EzvizCamera", FakeCamera)
    monkeypatch.setattr("pyezvizapi.devices.factory.EzvizLightBulb", BrokenLightBulb)
    monkeypatch.setattr("pyezvizapi.devices.factory.EzvizSmartPlug", FakeSmartPlug)

    loaded = client.load_devices(refresh=False)

    assert loaded["LIGHT123"] == {"kind": "light", "serial": "LIGHT123", "stale": True}
    assert "Load_device_failed: serial=LIGHT123" in caplog.text


def test_prefetch_latest_camera_alarms_returns_empty_without_serials() -> None:
    client = client_module.EzvizClient(token={"session_id": "session", "api_url": "apiieu.ezvizlife.com"})

    assert client._prefetch_latest_camera_alarms([]) == {}


def test_prefetch_latest_camera_alarms_uses_global_fetch_before_filtered_chunks() -> None:
    client = client_module.EzvizClient(token={"session_id": "session", "api_url": "apiieu.ezvizlife.com"})
    calls: list[dict[str, Any]] = []

    def fake_messages(**kwargs: Any) -> dict[str, Any]:
        calls.append(kwargs)
        if kwargs["serials"] is None:
            return {
                "messages": [
                    {"deviceSerial": "CAM1", "msgId": "global-cam1"},
                    {"deviceSerial": "OTHER", "msgId": "ignored"},
                ],
                "hasNext": False,
            }
        if kwargs["serials"] == "CAM2":
            return {
                "message": [{"deviceSerial": "CAM2", "msgId": "filtered-cam2"}],
                "hasNext": False,
            }
        if kwargs["serials"] == "CAM3":
            return {"message": [], "hasNext": False}
        raise AssertionError(f"unexpected serial filter: {kwargs['serials']}")

    client.get_device_messages_list = fake_messages  # type: ignore[assignment]

    latest = client._prefetch_latest_camera_alarms(["CAM1", "CAM2", "CAM3"], chunk_size=2)

    assert latest == {
        "CAM1": {"deviceSerial": "CAM1", "msgId": "global-cam1"},
        "CAM2": {"deviceSerial": "CAM2", "msgId": "filtered-cam2"},
        "CAM3": None,
    }
    assert calls == [
        {"serials": None, "limit": 50, "date": "", "end_time": "", "max_retries": 1},
        {
            "serials": "CAM2",
            "limit": 50,
            "date": "",
            "end_time": "",
            "max_retries": 1,
        },
        {
            "serials": "CAM3",
            "limit": 50,
            "date": "",
            "end_time": "",
            "max_retries": 1,
        },
    ]


@pytest.mark.parametrize("entrypoint", ["load_devices", "poll_devices"])
@pytest.mark.parametrize("found_in_batch", [True, False])
def test_device_poll_verifies_alarms_hidden_at_page_boundary(
    monkeypatch, entrypoint, found_in_batch
):
    client = _client_with_fixture(monkeypatch)
    cameras = {
        serial: client_module.EzvizDeviceRecord.from_api(
            serial, {"deviceInfos": {"deviceSerial": serial, "deviceCategory": "IPC"}}
        )
        for serial in ("CAM123", "CAM234")
    }
    monkeypatch.setattr(client, "get_device_records", lambda *_: cameras)
    newest = {"deviceSerial": "CAM123", "msgId": "newest", "time": 1795500000200, "sampleName": "Newest"}
    older = {"deviceSerial": "CAM123", "msgId": "older", "time": 1795500000100, "sampleName": "Older"}
    calls = []

    def first_page(serial):
        return {
            "message": [
                {"deviceSerial": serial, "time": 1795500000300},
                *[{"deviceSerial": serial, "time": newest["time"]} for _ in range(49)],
            ],
            "hasNext": True,
        }

    def fake_messages(*, serials=None, limit=20, end_time="", **_kwargs):
        calls.append((serials, limit, end_time))
        if end_time:
            return {"message": [older], "hasNext": False}
        if serials is None:
            return first_page("OTHER")
        if serials == "CAM123,CAM234":
            if found_in_batch:
                return {"message": [newest], "hasNext": False}
            return first_page("CAM234")
        if serials == "CAM123" and limit == 1:
            return {"message": [newest], "hasNext": True}
        if serials == "CAM234":
            return {"message": [], "hasNext": False}
        raise AssertionError(f"unexpected query: {calls[-1]}")

    monkeypatch.setattr(client, "get_device_messages_list", fake_messages)
    result = getattr(client, entrypoint)()
    loaded = result if entrypoint == "load_devices" else result.as_dict()
    assert loaded["CAM123"]["last_alarm_type_name"] == "Newest"
    expected = [(None, 50, ""), ("CAM123,CAM234", 50, "")]
    if not found_in_batch:
        expected.append(("CAM123", 1, ""))
    assert calls == expected


@pytest.mark.parametrize("entrypoint", ["load_devices", "poll_devices"])
@pytest.mark.parametrize(
    ("batch", "needs_fallback"),
    [
        ({"message": [], "hasNext": False}, False),
        ({"message": [{"deviceSerial": "CAM234"}], "hasNext": False}, False),
        ({"message": []}, True),
        ({"hasNext": False}, True),
        ({"message": [None], "hasNext": False}, True),
        ({"message": [{"deviceSerial": "UNEXPECTED"}], "hasNext": False}, True),
        ({"message": [], "hasNext": False, "failureSubTypes": [2]}, True),
        ({"message": [], "hasNext": False, "noMessageAbility": True}, True),
        (None, True),
        ({"message": [], "hasNext": True}, True),
        (
            {"message": [{"deviceSerial": "CAM234", "time": time} for time in (200, 100)], "hasNext": True},
            True,
        ),
    ],
)
def test_device_poll_only_skips_fallback_for_complete_first_page(
    monkeypatch, entrypoint, batch, needs_fallback
):
    client = _client_with_fixture(monkeypatch)
    cameras = {
        serial: client_module.EzvizDeviceRecord.from_api(
            serial, {"deviceInfos": {"deviceSerial": serial, "deviceCategory": "IPC"}}
        )
        for serial in ("CAM123", "CAM234")
    }
    monkeypatch.setattr(client, "get_device_records", lambda *_: cameras)
    calls = []

    def fake_messages(*, serials=None, limit=20, end_time="", **_kwargs):
        calls.append((serials, limit, end_time))
        if serials is None:
            return {"message": [], "hasNext": False}
        if limit == 1:
            return {"message": [], "hasNext": False}
        if end_time:
            # The next page could exclude events with the same boundary timestamp.
            return {"message": [], "hasNext": False}
        if batch is None:
            raise client_module.PyEzvizError("filtered batch failed")
        return batch

    monkeypatch.setattr(client, "get_device_messages_list", fake_messages)
    result = getattr(client, entrypoint)()
    loaded = result if entrypoint == "load_devices" else result.as_dict()
    assert loaded["CAM123"]["last_alarm_type_name"] == "NoAlarm"
    assert loaded["CAM123"]["Motion_Trigger"] is False
    assert calls[:2] == [(None, 50, ""), ("CAM123,CAM234", 50, "")]
    if needs_fallback:
        assert ("CAM123", 1, "") in calls
    else:
        assert len(calls) == 2


def test_prefetch_latest_camera_alarms_tolerates_api_errors() -> None:
    client = client_module.EzvizClient(token={"session_id": "session", "api_url": "apiieu.ezvizlife.com"})

    def fake_messages(**_kwargs: Any) -> dict[str, Any]:
        raise client_module.PyEzvizError("temporary alarm failure")

    client.get_device_messages_list = fake_messages  # type: ignore[assignment]

    assert client._prefetch_latest_camera_alarms(["CAM1"]) == {}


def test_load_devices_passes_prefetched_latest_alarm_to_camera_status(monkeypatch) -> None:
    client = _client_with_fixture(monkeypatch)
    prefetch_calls: list[list[str]] = []

    def fake_prefetch(serials: list[str]) -> dict[str, dict[str, Any]]:
        prefetch_calls.append(list(serials))
        return {"CAM123": {"deviceSerial": "CAM123", "msgId": "alarm-1"}}

    class FakeCamera:
        def __init__(self, _client: client_module.EzvizClient, serial: str, _device_obj: dict[str, Any], *, switches=None) -> None:
            self.serial = serial

        def status(
            self,
            *,
            refresh: bool = True,
            latest_alarm: dict[str, Any] | None = None,
        ) -> dict[str, Any]:
            return {
                "kind": "camera",
                "serial": self.serial,
                "refresh": refresh,
                "latest_alarm": latest_alarm,
            }

    class FakeLightBulb:
        def __init__(self, _client: client_module.EzvizClient, serial: str, _device_obj: dict[str, Any]) -> None:
            self.serial = serial

        def status(self) -> dict[str, Any]:
            return {"kind": "light", "serial": self.serial}

    class FakeSmartPlug:
        def __init__(self, _client: client_module.EzvizClient, serial: str, _device_obj: dict[str, Any]) -> None:
            self.serial = serial

        def status(self) -> dict[str, Any]:
            return {"kind": "plug", "serial": self.serial}

    monkeypatch.setattr(client, "_prefetch_latest_camera_alarms", fake_prefetch)
    monkeypatch.setattr("pyezvizapi.devices.factory.EzvizCamera", FakeCamera)
    monkeypatch.setattr("pyezvizapi.devices.factory.EzvizLightBulb", FakeLightBulb)
    monkeypatch.setattr("pyezvizapi.devices.factory.EzvizSmartPlug", FakeSmartPlug)

    loaded = client.load_devices(refresh=True)

    assert prefetch_calls == [["CAM123"]]
    assert loaded["CAM123"] == {
        "kind": "camera",
        "serial": "CAM123",
        "refresh": True,
        "latest_alarm": {"deviceSerial": "CAM123", "msgId": "alarm-1"},
    }


def test_load_devices_skips_alarm_prefetch_when_refresh_false(monkeypatch) -> None:
    client = _client_with_fixture(monkeypatch)

    def unexpected_prefetch(_serials: list[str]) -> dict[str, dict[str, Any]]:
        raise AssertionError("prefetch should not run when refresh is false")

    class FakeCamera:
        def __init__(self, _client: client_module.EzvizClient, serial: str, _device_obj: dict[str, Any], *, switches=None) -> None:
            self.serial = serial

        def status(
            self,
            *,
            refresh: bool = True,
            latest_alarm: dict[str, Any] | None = None,
        ) -> dict[str, Any]:
            return {
                "kind": "camera",
                "serial": self.serial,
                "refresh": refresh,
                "latest_alarm": latest_alarm,
            }

    class FakeLightBulb:
        def __init__(self, _client: client_module.EzvizClient, serial: str, _device_obj: dict[str, Any]) -> None:
            self.serial = serial

        def status(self) -> dict[str, Any]:
            return {"kind": "light", "serial": self.serial}

    class FakeSmartPlug:
        def __init__(self, _client: client_module.EzvizClient, serial: str, _device_obj: dict[str, Any]) -> None:
            self.serial = serial

        def status(self) -> dict[str, Any]:
            return {"kind": "plug", "serial": self.serial}

    monkeypatch.setattr(client, "_prefetch_latest_camera_alarms", unexpected_prefetch)
    monkeypatch.setattr("pyezvizapi.devices.factory.EzvizCamera", FakeCamera)
    monkeypatch.setattr("pyezvizapi.devices.factory.EzvizLightBulb", FakeLightBulb)
    monkeypatch.setattr("pyezvizapi.devices.factory.EzvizSmartPlug", FakeSmartPlug)

    loaded = client.load_devices(refresh=False)

    assert loaded["CAM123"] == {
        "kind": "camera",
        "serial": "CAM123",
        "refresh": False,
        "latest_alarm": None,
    }
