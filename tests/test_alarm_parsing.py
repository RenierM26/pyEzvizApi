from __future__ import annotations

import datetime as dt
from typing import cast

from pyezvizapi.camera import DEFAULT_ALARM_IMAGE_URL, EzvizCamera
from pyezvizapi.client import EzvizClient
from pyezvizapi.utils import compute_motion_from_alarm, normalize_alarm_time


def _camera() -> EzvizCamera:
    return EzvizCamera(
        cast(EzvizClient, object()),
        "CAM123",
        device_obj={
            "deviceInfos": {"name": "Front Door"},
            "STATUS": {"optionals": {"timeZone": "UTC+02:00"}},
        },
    )


def test_normalize_unified_message_prefers_first_ext_picture_and_ext_alarm_type() -> None:
    normalized = _camera()._normalize_unified_message(
        {
            "msgId": "message-1",
            "deviceSerial": "CAM123",
            "channel": 1,
            "time": "1770000000000",
            "timeStr": "2026-02-02 10:00:00",
            "title": "Person detected",
            "subType": "fallback-type",
            "ext": {
                "alarmType": "ext-type",
                "pics": "https://example.test/first.jpg;https://example.test/second.jpg",
                "picChecksum": "checksum",
                "picCrypt": "1",
            },
        }
    )

    assert normalized == {
        "alarmId": "message-1",
        "deviceSerial": "CAM123",
        "channel": 1,
        "alarmStartTime": 1770000000000,
        "alarmStartTimeStr": "2026-02-02 10:00:00",
        "alarmTime": 1770000000000,
        "alarmTimeStr": "2026-02-02 10:00:00",
        "picUrl": "https://example.test/first.jpg",
        "picChecksum": "checksum",
        "picCrypt": "1",
        "sampleName": "Person detected",
        "alarmType": "ext-type",
        "msgSource": "unifiedmsg",
        "ext": {
            "alarmType": "ext-type",
            "pics": "https://example.test/first.jpg;https://example.test/second.jpg",
            "picChecksum": "checksum",
            "picCrypt": "1",
        },
    }


def test_normalize_unified_message_falls_back_to_default_image_and_subtype() -> None:
    normalized = _camera()._normalize_unified_message(
        {
            "deviceSerial": "CAM123",
            "time": "not-a-number",
            "detail": "Motion alarm",
            "subType": "motion-type",
        }
    )

    assert normalized["alarmStartTime"] is None
    assert normalized["alarmTime"] is None
    assert normalized["picUrl"] == DEFAULT_ALARM_IMAGE_URL
    assert normalized["sampleName"] == "Motion alarm"
    assert normalized["alarmType"] == "motion-type"
    assert normalized["ext"] == {}


def test_alarm_list_ignores_messages_for_other_devices() -> None:
    camera = _camera()

    class FakeClient:
        def get_device_messages_list(self, **_kwargs) -> dict:
            return {
                "messages": [
                    {"deviceSerial": "OTHER", "time": "1770000000000"},
                ]
            }

    camera._client = cast(EzvizClient, FakeClient())
    camera._alarm_list()

    status = camera.status(refresh=False)
    assert status["Motion_Trigger"] is False
    assert status["Seconds_Last_Trigger"] is None
    assert status["last_alarm_pic"] == DEFAULT_ALARM_IMAGE_URL
    assert status["last_alarm_type_code"] == "0000"
    assert status["last_alarm_type_name"] == "NoAlarm"


def test_normalize_alarm_time_reinterprets_local_clock_epochs_when_string_disagrees() -> None:
    tzinfo = dt.timezone(dt.timedelta(hours=2))
    local_clock = dt.datetime(2026, 2, 2, 10, 0, 0, tzinfo=dt.UTC).timestamp()

    alarm_dt_local, alarm_dt_utc, alarm_str = normalize_alarm_time(
        {
            "alarmTime": int(local_clock * 1000),
            "alarmTimeStr": "2026-02-02 10:00:00",
        },
        tzinfo,
    )

    assert alarm_dt_local == dt.datetime(2026, 2, 2, 10, 0, tzinfo=tzinfo)
    assert alarm_dt_utc == dt.datetime(2026, 2, 2, 8, 0, tzinfo=dt.UTC)
    assert alarm_str == "2026-02-02 10:00:00"


def test_compute_motion_from_alarm_clamps_future_alarm_times() -> None:
    future = dt.datetime.now(tz=dt.UTC) + dt.timedelta(hours=1)

    active, seconds, alarm_str = compute_motion_from_alarm(
        {"alarmTime": int(future.timestamp() * 1000)},
        dt.UTC,
    )

    assert active is False
    assert seconds == 0.0
    assert alarm_str == future.replace(microsecond=0).strftime("%Y-%m-%d %H:%M:%S")
