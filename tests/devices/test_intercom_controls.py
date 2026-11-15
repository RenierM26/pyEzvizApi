"""Intercom contracts with synthetic discovery and no network/device commands."""

from copy import deepcopy
from datetime import UTC, datetime
import subprocess
import sys
from unittest.mock import Mock

import pytest

from pyezvizapi import EzvizClient, MonitorState
from pyezvizapi.cloud import deadline
from pyezvizapi.cloud.operations import snapshot as operation
from pyezvizapi.devices.camera import EzvizCamera
from pyezvizapi.devices.intercom import (
    chime_value,
    intercom_relays,
    label_light_value,
    set_intercom_chime,
    set_label_light,
    unlock_intercom,
)
from pyezvizapi.devices.intercom_events import get_intercom_events, normalize_intercom_event
from pyezvizapi.devices.snapshot import DevicePollOptions
from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.models import EzvizDeviceRecord


@pytest.fixture
def data():
    return {
        "deviceInfos": {"deviceCategory": "BDoorBell", "supportExt": {"662": "1"}},
        "resourceInfos": [{"resourceIdentifier": "Video", "localIndex": 0}],
        "STATUS": {"optionals": {"ChimeMusic": {
            "volume": 4, "doorbell_enable": 1, "pir_enable": 0, "doorbell": 2,
            "pir": 3, "future": {"retained": True},
        }}},
    }


@pytest.mark.parametrize(("field", "value"), [("doorbell_enable", False), ("pir_enable", True), ("volume", 7), ("doorbell", 20), ("pir", 0)])
def test_chime_patch_preserves_siblings_and_input(data, field, value):
    original = deepcopy(data)
    client = Mock()
    client.set_dev_config_kv.return_value = True
    assert set_intercom_chime(client, "OPAQUE-COMPOSITE", field, value, data)
    serial, channel, group, payload = client.set_dev_config_kv.call_args.args
    assert (serial, channel, group) == ("OPAQUE-COMPOSITE", 1, "ChimeMusic")
    expected = deepcopy(original["STATUS"]["optionals"]["ChimeMusic"])
    expected[field] = int(value)
    assert payload == expected
    payload["future"]["retained"] = False
    assert data == original


@pytest.mark.parametrize(("field", "value"), [("volume", True), ("volume", -1), ("volume", 101), ("volume", 2.5), ("volume", float("nan")), ("pir_enable", 1), ("doorbell", -1), ("unknown", 0)])
def test_bad_chime_writes_do_not_send(data, field, value):
    client = Mock()
    with pytest.raises(PyEzvizError):
        set_intercom_chime(client, "TEST", field, value, data)
    client.set_dev_config_kv.assert_not_called()


@pytest.mark.parametrize("value", [None, "bad", True, -1, 101])
def test_invalid_volume_is_unknown_not_default(data, value):
    data["STATUS"]["optionals"]["ChimeMusic"]["volume"] = value
    assert chime_value(data, "volume") is None
    with pytest.raises(PyEzvizError):
        set_intercom_chime(Mock(), "TEST", "volume", 1, data)


@pytest.mark.parametrize("flag", [None, "0", "1,2", True, 2, "bad"])
def test_local_unlock_requires_exact_app_capability(data, flag):
    data["deviceInfos"]["supportExt"]["662"] = flag
    assert intercom_relays(data) == ()
    with pytest.raises(PyEzvizError):
        unlock_intercom(Mock(), "TEST", "door", data)


@pytest.mark.parametrize(("relay", "number"), [("door", 2), ("gate", 1)])
def test_unlock_is_exactly_one_correct_relay(data, relay, number):
    client = Mock()
    client.export_token.return_value = {"username": "ACCOUNT"}
    client.remote_unlock.return_value = True
    assert unlock_intercom(client, "TEST", relay, data)
    assert client.remote_unlock.call_count == 1
    assert client.remote_unlock.call_args.args == ("TEST", "ACCOUNT", number)
    assert client.remote_unlock.call_args.kwargs["local_index"] == "0"
    client.remote_unlock.side_effect = PyEzvizError("rejected")
    with pytest.raises(PyEzvizError):
        unlock_intercom(client, "TEST", relay, data)
    assert client.remote_unlock.call_count == 2


@pytest.mark.parametrize("resources", [[], [{"resourceIdentifier": "global", "localIndex": 0}], [{"resourceIdentifier": "Video", "localIndex": True}], [{"resourceIdentifier": "Video", "localIndex": 0}] * 2])
def test_no_guessed_or_ambiguous_unlock_route(data, resources):
    data["resourceInfos"] = resources
    assert intercom_relays(data) == ()


def test_night_light_uses_selected_video_index_not_global_or_611(data):
    data["SWITCH"] = [{"type": 611, "enable": 0}]
    data["FEATURE_INFO"] = {"0": {"Video": {"LightCtrl": {"NightLightEnable": True}}}}
    assert label_light_value(data) is True
    client = Mock()
    assert set_label_light(client, "COMPOSITE", False, data)
    client.set_iot_feature.assert_called_once_with("COMPOSITE", resource_identifier="Video", local_index="0", domain_id="LightCtrl", action_id="NightLightEnable", value={"value": False})
    client.switch_status.assert_not_called()
    client.set_iot_feature.side_effect = PyEzvizError("rejected")
    with pytest.raises(PyEzvizError):
        set_label_light(client, "COMPOSITE", False, data)
    client.switch_status.assert_not_called()


def test_legacy_light_only_when_observed(data):
    assert label_light_value(data) is None
    data["SWITCH"] = [{"type": 611, "enable": 1}]
    client = Mock()
    client.switch_status.return_value = True
    assert set_label_light(client, "TEST", False, data)
    client.switch_status.assert_called_once_with("TEST", 611, False)
    data["deviceInfos"]["deviceCategory"] = "IPC"
    assert label_light_value(data) is None


def test_monitor_inventory_never_calls_camera_or_alarms(monkeypatch):
    client = EzvizClient()
    raw = {"deviceInfos": {"deviceCategory": "DBScreen", "status": 1, "name": "Monitor"}, "STATUS": {"optionals": {"ChimeMusic": {"volume": 2}}}}
    monkeypatch.setattr(client, "get_device_records", lambda _: {"MON": EzvizDeviceRecord.from_api("MON", raw)})
    alarms = Mock(return_value={})
    monkeypatch.setattr(client, "_prefetch_latest_camera_alarms", alarms)
    try:
        snap = client.poll_devices()
        assert isinstance(snap.devices["MON"], MonitorState)
        assert snap.select("camera") == {}
        assert snap.devices["MON"].online is True
        assert chime_value(snap.devices["MON"].as_dict(), "volume") == 2
        alarms.assert_called_once_with([])
        assert "local_rtsp_port" not in snap.devices["MON"].values
    finally:
        client.close_session()


@pytest.mark.parametrize("code", [2701, 10242])
def test_ring_and_unlock_are_not_motion(data, code):
    cam = EzvizCamera(Mock(), "TEST", device_obj=data)
    cam.status(refresh=False, latest_alarm={"alarmType": code, "alarmStartTime": int(datetime.now(UTC).timestamp() * 1000)})
    assert cam.status(refresh=False)["Motion_Trigger"] is False


def test_poll_intercom_history_is_explicitly_opt_in(data, monkeypatch):
    client = EzvizClient()
    record = EzvizDeviceRecord.from_api("TEST", data)
    monkeypatch.setattr(client, "get_device_records", lambda _: {"TEST": record})
    history = Mock(return_value={"message": [{"deviceSerial": "TEST", "msgId": "event", "time": 1794736800000, "ext": {"alarmType": 2701}}]})
    monkeypatch.setattr(client, "get_device_messages_list", history)
    try:
        assert client.poll_devices(DevicePollOptions(include_camera_alarms=False)).intercom_events == ()
        history.assert_not_called()
        snap = client.poll_devices(DevicePollOptions(include_camera_alarms=False, include_intercom_events=True))
        assert snap.intercom_events[0].event_type == "ring"
        assert snap.intercom_events[0].serial == "TEST"
    finally:
        client.close_session()


@pytest.mark.parametrize("kind", ["history", "alarm", "push"])
def test_same_event_normalized_without_image_or_localized_title(kind):
    base = {"deviceSerial": "TEST", "msgId": "same", "time": 1794736800000, "channel": 1, "ext": {"alarmType": 10242, "customerType": "Card", "alarmStartTime": 1}}
    if kind == "alarm":
        base = {"deviceSerial": "TEST", "alarmId": "same", "alarmStartTime": 1794736800000, "channelNo": 1, "alarmType": 10242, "customerType": "Card"}
    elif kind == "push":
        base = {"alert": "INVENTED TRANSLATION", "ext": {"device_serial": "TEST", "msgId": "same", "time": "2026-11-15T12:40:00+00:00", "channel_no": 1, "alert_type_code": 10242}}
    event = normalize_intercom_event(base)
    assert event is not None and event.occurred_at is not None
    assert event.serial == "TEST" and event.event_id == "same"
    assert event.event_type == "lock_unlocked" and event.channel == 1
    assert event.occurred_at.tzinfo == UTC
    assert event.method == (None if kind == "push" else "rfid")


@pytest.mark.parametrize("field", ["deviceSerial", "msgId"])
def test_missing_event_identity_is_not_invented(field):
    payload = {"deviceSerial": "TEST", "msgId": "ID", "alarmType": 2701}
    payload.pop(field)
    assert normalize_intercom_event(payload) is None


@pytest.mark.parametrize("stamp", [True, "bad", -1, 10**30, "2026-11-15 10:00:00"])
def test_unknown_time_does_not_become_utc_or_now(stamp):
    event = normalize_intercom_event({"deviceSerial": "TEST", "msgId": "ID", "alarmType": 2701, "time": stamp})
    assert event is not None
    assert event.occurred_at is None


def test_unknown_methods_and_codes_are_not_translated_or_inferred():
    assert normalize_intercom_event({"deviceSerial": "TEST", "msgId": "ID", "alarmType": 99999, "title": "RFID unlock"}) is None
    event = normalize_intercom_event({"deviceSerial": "TEST", "msgId": "ID", "alarmType": 10242, "customerType": "FutureMethod", "cardName": "Do not infer"})
    assert event is not None
    assert event.method is None
    assert "Do not infer" not in repr(event)


def test_history_filters_foreign_serials_and_validates_shape():
    client = Mock()
    client.get_device_messages_list.return_value = {"message": [None, {"deviceSerial": "FOREIGN", "msgId": "ID", "alarmType": 2701}]}
    assert get_intercom_events(client, ("TEST",)) == ()
    client.get_device_messages_list.return_value = {"message": {}}
    with pytest.raises(PyEzvizError):
        get_intercom_events(client, ("TEST",))
    with pytest.raises(PyEzvizError):
        DevicePollOptions(include_intercom_events=1)  # type: ignore[arg-type]  # invalid runtime input


def test_history_permission_failure_does_not_discard_inventory(data, monkeypatch):
    client = EzvizClient()
    monkeypatch.setattr(client, "get_device_records", lambda _: {"TEST": EzvizDeviceRecord.from_api("TEST", data)})
    monkeypatch.setattr(client, "get_device_messages_list", Mock(side_effect=PyEzvizError("SECRET_RESPONSE")))
    try:
        snap = client.poll_devices(DevicePollOptions(include_camera_alarms=False, include_intercom_events=True))
        assert snap.health["TEST"].current
        assert snap.intercom_events == ()
        assert snap.intercom_events_current is False
        assert snap.intercom_events_error_type == "PyEzvizError"
        assert "SECRET_RESPONSE" not in repr(snap)
    finally:
        client.close_session()


@pytest.mark.parametrize("value", ["0", 0, False, "1", 1, True, "bad", 2, None])
def test_legacy_light_bool_parsing_is_not_truthiness(data, value):
    data["SWITCH"] = [{"type": 611, "enable": value}]
    expected = None if value in ("bad", 2, None) else value in ("1", 1, True)
    assert label_light_value(data) is expected


def test_ordinary_doorbell_chime_is_not_reinterpreted_as_intercom_scale(data):
    data["deviceInfos"]["supportExt"] = {"185": "1"}
    assert chime_value(data, "volume") is None


def test_existing_positional_poll_options_contract():
    options = DevicePollOptions(20, False, 100)
    assert options.max_devices == 100
    assert options.include_camera_alarms is False
    assert options.include_intercom_events is False


def test_history_timeout_has_its_own_short_budget(data, monkeypatch):

    client = EzvizClient()
    records = {"TEST": EzvizDeviceRecord.from_api("TEST", data)}
    clock = [100.0]
    monkeypatch.setattr(operation.time, "monotonic", lambda: clock[0])

    def history(**kwargs):
        remaining = deadline.remaining_request_budget()
        assert remaining == 2
        clock[0] += remaining
        raise TimeoutError("optional request expired")

    monkeypatch.setattr(client, "get_device_messages_list", history)
    try:
        with deadline.request_deadline(120.0, monotonic=lambda: clock[0]):
            events, current, error = operation._events(client, records, DevicePollOptions(include_intercom_events=True))  # noqa: SLF001 -- verify the optional request sub-budget
            assert (events, current, error) == ((), False, "TimeoutError")
            assert deadline.remaining_request_budget() == 18
    finally:
        client.close_session()


@pytest.mark.parametrize("first", ["pyezvizapi.devices.intercom", "pyezvizapi.devices.audio", "pyezvizapi.devices.monitor", "pyezvizapi.cloud.operations.snapshot", "pyezvizapi.client"])
def test_fresh_process_import_order(first):
    """New monitor rendering cannot close a client/audio/intercom import cycle."""
    script = f"import importlib; importlib.import_module({first!r}); from pyezvizapi.devices.intercom import chime_value; from pyezvizapi.devices.monitor import monitor_status; from pyezvizapi.client import EzvizClient"
    subprocess.run([sys.executable, "-c", script], check=True, capture_output=True, timeout=20)


@pytest.mark.parametrize("code", [0, "0", None])
def test_app_unified_ring_subtype_fallback(code):
    event = normalize_intercom_event({"deviceSerial": "TEST", "msgId": "ID", "subType": 2701, "ext": {"alarmType": code}})
    assert event is not None and event.code == 2701
    assert event.event_type == "ring"


@pytest.mark.parametrize("code", [2401, 10242, 99999, True, "bad"])
def test_ring_subtype_never_overrides_nonzero_alarm_type(code):
    event = normalize_intercom_event({"deviceSerial": "TEST", "msgId": "ID", "subType": 2701, "ext": {"alarmType": code}})
    assert (event.code if event is not None else None) == (code if code == 10242 else None)


def test_missing_history_list_is_not_reported_as_current():
    client = Mock()
    client.get_device_messages_list.return_value = {}
    with pytest.raises(PyEzvizError, match="no message list"):
        get_intercom_events(client, ("TEST",))


def test_fractional_capability_is_not_an_enabled_integer(data):
    data["deviceInfos"]["supportExt"]["662"] = 1.0
    assert intercom_relays(data) == ()
    assert chime_value(data, "volume") is None


@pytest.mark.parametrize(("category", "maximum"), [("DBScreen", 7), ("BDoorBell", 100)])
def test_app_category_volume_ranges_apply_to_reads_and_writes(data, category, maximum):
    data["deviceInfos"]["deviceCategory"] = category
    data["STATUS"]["optionals"]["ChimeMusic"]["volume"] = maximum
    assert chime_value(data, "volume") == maximum
    client = Mock()
    assert set_intercom_chime(client, "TEST", "volume", maximum, data)
    client.set_dev_config_kv.assert_called_once()
    with pytest.raises(PyEzvizError):
        set_intercom_chime(client, "TEST", "volume", maximum + 1, data)
    assert client.set_dev_config_kv.call_count == 1
    data["STATUS"]["optionals"]["ChimeMusic"]["volume"] = maximum + 1
    assert chime_value(data, "volume") is None
