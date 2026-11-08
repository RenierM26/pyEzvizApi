"""Actual consumer + real HA + actual library, synthetic network boundaries only."""

# ruff: noqa: SLF001 -- acceptance controls inspect explicit worker ownership
from copy import deepcopy
import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

from custom_components.ezviz_cloud import camera, coordinator, mqtt
from custom_components.ezviz_cloud.const import DATA_COORDINATOR, DOMAIN
from homeassistant.config_entries import ConfigEntryState, current_entry
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import UpdateFailed
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry
from tests.cloud.test_client_parsing import _page_list_fixture

from pyezvizapi.client import EzvizClient
from pyezvizapi.exceptions import EzvizAuthTokenExpired, HTTPError


@pytest.fixture
def client(monkeypatch):
    api = EzvizClient(
        token={
            "session_id": "synthetic",
            "api_url": "api.example.invalid",
            "username": "synthetic-user",
        }
    )
    page = _page_list_fixture()
    page["deviceInfos"] = page["deviceInfos"][:1]
    page["CONNECTION"]["CAM123"]["localRtspPort"] = 554
    monkeypatch.setattr(api, "_get_page_list", lambda: deepcopy(page))
    monkeypatch.setattr(api, "get_device_messages_list", lambda **kwargs: {"messages": []})
    yield api
    api.close_session()


async def make_coordinator(hass, client):
    entry = MockConfigEntry(domain=DOMAIN)
    entry.add_to_hass(hass)
    context_token = current_entry.set(entry)
    try:
        result = coordinator.EzvizDataUpdateCoordinator(hass, api=client, api_timeout=2)
    finally:
        current_entry.reset(context_token)
    result.async_set_updated_data(await result._async_update_data())
    return result


async def test_actual_poll_normalization_and_camera_setup(hass, client, monkeypatch):
    data = await make_coordinator(hass, client)
    assert set(data.data) == {"CAM123"}
    assert data.data["CAM123"]["local_ip"] == "192.0.2.10"
    assert data.data["CAM123"]["name"] == "Front Camera"
    hass.data[DOMAIN] = {"entry": {DATA_COORDINATOR: data}}
    entry = MagicMock(entry_id="entry", options={"cameras": {"CAM123": {"enc_key": "synthetic"}}})
    monkeypatch.setattr(camera, "get_ffmpeg_manager", lambda hass: MagicMock())
    monkeypatch.setattr(camera, "async_get_current_platform", MagicMock())
    entities: list[camera.EzvizCamera] = []
    await camera.async_setup_entry(hass, entry, entities.extend)
    assert len(entities) == 1
    entity = entities[0]
    entity.hass = hass
    assert entity.unique_id == "CAM123"
    assert entity.available
    assert (
        await entity.stream_source()
        == "rtsp://admin:synthetic@192.0.2.10:554/Streaming/Channels/102"
    )
    requests = []

    def request(method, url, **kwargs):
        requests.append((method, url, kwargs))
        return {"meta": {"code": 200}}

    monkeypatch.setattr(client, "_request_json", request)
    await hass.async_add_executor_job(entity.enable_motion_detection)
    await hass.async_add_executor_job(entity.disable_motion_detection)
    assert [call[2]["data"]["status"] for call in requests] == [1, 0]
    assert all(call[0] == "PUT" and "CAM123/1" in call[1] for call in requests)
    image = AsyncMock(return_value=b"synthetic jpeg")
    monkeypatch.setattr(camera.ffmpeg, "async_get_image", image)
    assert await entity.async_camera_image(320, 240) == image.return_value
    image.assert_awaited_once_with(hass, await entity.stream_source(), width=320, height=240)


@pytest.mark.parametrize(
    "error, expected",
    [(EzvizAuthTokenExpired(), ConfigEntryAuthFailed), (HTTPError(), UpdateFailed)],
)
async def test_poll_failure_is_translated_and_next_poll_recovers(
    hass, client, monkeypatch, error, expected
):
    data = await make_coordinator(hass, client)
    original = client.load_cameras

    def fail():
        raise error

    monkeypatch.setattr(client, "load_cameras", fail)
    with pytest.raises(expected):
        await data._async_update_data()
    monkeypatch.setattr(client, "load_cameras", original)
    assert "CAM123" in await data._async_update_data()


async def test_actual_push_factory_handoff_and_shutdown(hass, client, monkeypatch):
    data = await make_coordinator(hass, client)
    hass.data[DOMAIN] = {"entry": {DATA_COORDINATOR: data}}
    handler = mqtt.EzvizMqttHandler(hass, client, "entry")
    sdk = client.get_mqtt_client(on_message_callback=handler._on_message)
    assert sdk is client.get_mqtt_client()
    monkeypatch.setattr(sdk, "connect", MagicMock())
    monkeypatch.setattr(sdk, "stop", MagicMock())
    handler.async_start()
    await handler._task
    event: dict[str, Any] = {
        "ext": {
            "device_serial": "CAM123",
            "image": "synthetic-image",
            "time": 123,
            "alert_type_code": 1,
        },
        "alert": "motion",
    }
    await hass.async_add_executor_job(handler._on_message, event)
    await hass.async_block_till_done()
    assert data.data["CAM123"]["Motion_Trigger"] is True
    assert data.data["CAM123"]["last_alarm_pic"] == "synthetic-image"
    await handler.async_stop()
    sdk.stop.assert_called_once()
    late = deepcopy(event)
    late["ext"]["image"] = "late"
    handler._on_message(late)
    await hass.async_block_till_done()
    assert data.data["CAM123"]["last_alarm_pic"] == "synthetic-image"


async def test_unmigrated_consumer_push_is_unavailable_but_polling_survives(hass, client):
    data = await make_coordinator(hass, client)
    hass.data[DOMAIN] = {"entry": {DATA_COORDINATOR: data}}
    handler = mqtt.EzvizMqttHandler(hass, client, "entry")
    # This is the real factory and connect(), not a mocked successful broker.
    with pytest.raises(EzvizAuthTokenExpired, match="enable_channel99"):
        await hass.async_add_executor_job(handler.start)
    handler.async_start()
    for _ in range(5):
        await hass.async_block_till_done()
        if handler._mqtt is None:
            break
    assert "CAM123" in await data._async_update_data()
    await handler.async_stop()
    assert handler._task.done()


async def test_account_setup_and_unload_use_real_polling(hass, client, monkeypatch):
    from custom_components import ezviz_cloud  # noqa: PLC0415
    from custom_components.ezviz_cloud.const import ATTR_TYPE_CLOUD  # noqa: PLC0415
    from homeassistant.const import CONF_TYPE  # noqa: PLC0415

    token = {"session_id": "synthetic", "rf_session_id": "synthetic-refresh"}
    monkeypatch.setattr(client, "login", lambda: token)
    monkeypatch.setattr(ezviz_cloud, "EzvizClient", lambda **kwargs: client)
    monkeypatch.setattr(hass.config_entries, "async_forward_entry_setups", AsyncMock())
    monkeypatch.setattr(hass.config_entries, "async_unload_platforms", AsyncMock(return_value=True))
    monkeypatch.setattr(hass, "http", MagicMock(), raising=False)
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={
            CONF_TYPE: ATTR_TYPE_CLOUD,
            **token,
            "url": "api.example.invalid",
            "user_id": "synthetic-user",
        },
        options={"cameras": {}},
    )
    entry.add_to_hass(hass)
    entry.mock_state(hass, ConfigEntryState.SETUP_IN_PROGRESS)
    context_token = current_entry.set(entry)
    try:
        setup_ok = await ezviz_cloud.async_setup_entry(hass, entry)
        assert setup_ok
    finally:
        current_entry.reset(context_token)
    assert "CAM123" in hass.data[DOMAIN][entry.entry_id][DATA_COORDINATOR].data
    unload_ok = await ezviz_cloud.async_unload_entry(hass, entry)
    assert unload_ok
    assert entry.entry_id not in hass.data[DOMAIN]


def test_all_consumer_library_imports_resolve():
    import ast  # noqa: PLC0415
    from importlib import import_module  # noqa: PLC0415
    from pathlib import Path  # noqa: PLC0415

    import custom_components.ezviz_cloud as consumer  # noqa: PLC0415

    imports = set()
    for path in Path(consumer.__file__).parent.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if (
                isinstance(node, ast.ImportFrom)
                and node.module
                and node.module.startswith("pyezvizapi")
            ):
                for symbol in node.names:
                    assert hasattr(import_module(node.module), symbol.name)
                    imports.add((node.module, symbol.name))
    assert len(imports) == 50


async def test_channel99_requires_persistence_even_after_profile_migration(hass, client):
    from pyezvizapi.push.mqtt import PUSH_PROFILE  # noqa: PLC0415

    # Isolate the second real startup precondition, without reaching network I/O.
    sdk = client.get_mqtt_client()
    sdk._token["push_profile"] = PUSH_PROFILE
    from pyezvizapi.exceptions import PyEzvizError  # noqa: PLC0415

    with pytest.raises(PyEzvizError, match="on_token_updated"):
        await hass.async_add_executor_job(sdk.connect)


async def test_detector_inventory_does_not_create_camera_entities(hass, client, monkeypatch):
    """Run the real pinned coordinator/platform with a mixed sensor inventory."""
    page = client._get_page_list()
    fixture = Path(__file__).resolve().parents[3] / "tests/fixtures/detector_page_list.json"
    sensors = json.loads(fixture.read_text())
    page["deviceInfos"].extend(sensors["deviceInfos"])
    page.setdefault("FEATURE_INFO", {}).update(sensors["FEATURE_INFO"])
    monkeypatch.setattr(client, "_get_page_list", lambda: deepcopy(page))
    data = await make_coordinator(hass, client)
    assert set(data.data) == {"CAM123"}
    detectors = await hass.async_add_executor_job(lambda: client.load_detectors(refresh=False))
    assert set(detectors) == {"CONTACT001", "WATER00001", "SIREN00001"}
    assert detectors["CONTACT001"]["battery_level"] == 0
    assert detectors["WATER00001"]["water_leak_status"] == 0
    assert detectors["SIREN00001"]["siren_tamper_detection"] is False
    hass.data[DOMAIN] = {"entry": {DATA_COORDINATOR: data}}
    entry = MagicMock(entry_id="entry", options={"cameras": {"CAM123": {"enc_key": "synthetic"}}})
    monkeypatch.setattr(camera, "get_ffmpeg_manager", lambda hass: MagicMock())
    monkeypatch.setattr(camera, "async_get_current_platform", MagicMock())
    entities: list[camera.EzvizCamera] = []
    await camera.async_setup_entry(hass, entry, entities.extend)
    assert [entity.unique_id for entity in entities] == ["CAM123"]
