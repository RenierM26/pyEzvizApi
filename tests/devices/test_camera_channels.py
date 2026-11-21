"""Channel identity and routing are offline and independent of HA/Pillow."""

from copy import deepcopy

import pytest

from pyezvizapi.devices.channels import (
    CameraChannelError,
    alarm_camera_channel,
    camera_channel_notification,
    camera_channels,
    capture_channel_number,
    notification_camera_channel,
    point_ptz_route,
    reported_video_channel_numbers,
    resolve_camera_channel,
    validate_channel_rtsp_path,
)
from pyezvizapi.devices.snapshot import CameraState
from pyezvizapi.exceptions import PyEzvizError


def data():
    return {
        "supportExt": {"724": "1"},
        "resourceInfos": [
            {"resourceIdentifier": "Video_1", "localIndex": 2},
            {"resourceIdentifier": "Video", "localIndex": "1"},
        ],
    }


def test_channel_keys_are_stable_and_snapshot_safe():
    raw = data()
    snapshot = CameraState("synthetic", "camera", raw)
    channels = snapshot.channels
    assert [c.key for c in channels] == ["Video:1", "Video_1:2"]
    raw["resourceInfos"].clear()
    assert snapshot.channels == channels
    reordered = snapshot.as_dict()
    reordered["resourceInfos"].reverse()
    assert camera_channels(reordered) == channels
    assert resolve_camera_channel(reordered, "Video_1:2") == channels[1]
    reordered["resourceInfos"] = [reordered["resourceInfos"][0]]
    with pytest.raises(CameraChannelError):
        resolve_camera_channel(reordered, "Video_1:2")


@pytest.mark.parametrize("index", [None, True, False, -1, 1.0, "../1", "1/action", "01", ""])
def test_bad_indices_never_add_a_channel_or_route(index):
    raw = data()
    raw["resourceInfos"][0]["localIndex"] = index
    assert not camera_channels(raw)
    with pytest.raises(CameraChannelError):
        point_ptz_route(raw, "2")


def test_duplicate_channel_numbers_and_missing_metadata_do_not_guess():
    raw = data()
    raw["resourceInfos"].append({"resourceIdentifier": "Video_9", "localIndex": "2"})
    assert not camera_channels(raw)
    with pytest.raises(CameraChannelError):
        point_ptz_route(raw, "2")
    assert not camera_channels({"supported_channels": 2})


def test_point_routes_keep_direct_and_selected_contracts():
    raw = data()
    with pytest.raises(CameraChannelError, match="selection_required"):
        point_ptz_route(raw)
    assert point_ptz_route(raw, "1") == ("Video", "1")
    assert point_ptz_route(raw, channel_key="Video_1:2") == ("Video_1", "2")
    with pytest.raises(CameraChannelError, match="unavailable"):
        point_ptz_route(raw, "1", channel_key="Video_1:2")
    raw["supportExt"] = {"586": "01"}
    assert point_ptz_route(raw) == ("Video_1", "1")
    assert point_ptz_route(raw, "1") == ("Video_1", "1")
    with pytest.raises(CameraChannelError):
        point_ptz_route(raw, channel_key="Video_1:2")


@pytest.mark.parametrize("flag", [None, True, False, 1.0, "true", "0", 0, 2, []])
def test_generic_or_truthy_flags_are_not_point_support(flag):
    raw = data()
    raw["supportExt"] = {"154": "1", "724": flag}
    with pytest.raises(CameraChannelError, match="unsupported"):
        point_ptz_route(raw, "1")


@pytest.mark.parametrize("index", [None, True, False, "unknown", 3, -1])
def test_unknown_notification_channel_stays_unassigned(index):
    assert (
        notification_camera_channel(data(), {"ext": {"channel_type": 1, "channel_no": index}})
        is None
    )


def test_notification_resolves_explicit_channel_without_mutation():
    raw = data()
    before = deepcopy(raw)
    event = {"ext": {"channel_type": "1", "channel_no": 2}}
    channel = notification_camera_channel(raw, event)
    assert channel is not None and channel.key == "Video_1:2"
    assert raw == before
    event["ext"]["channel_type"] = True
    assert notification_camera_channel(raw, event) is None


@pytest.mark.parametrize(
    "value", [None, 1, "rtsp://user:pass@host/path", "//host/path", "/path\n", "relative"]
)
def test_rtsp_path_does_not_override_host_or_credentials(value):
    with pytest.raises(PyEzvizError):
        validate_channel_rtsp_path(value)


def test_rtsp_paths_are_explicit_not_generated_from_lens_numbers():
    assert validate_channel_rtsp_path("") == ""
    assert (
        validate_channel_rtsp_path("/custom/lens-two?quality=main")
        == "/custom/lens-two?quality=main"
    )


def test_normalized_notifications_do_not_expose_urls_or_infer_motion():
    message = {
        "ext": {
            "channel_type": 1,
            "channel_no": 2,
            "msgId": "synthetic",
            "image": "https://images.example.invalid/private-signed",
            "alert_type_code": True,
            "time": False,
        }
    }
    result = camera_channel_notification(data(), message)
    assert result is not None and result.channel.key == "Video_1:2"
    assert result.image_url is not None and result.image_url.endswith("private-signed")
    assert "private-signed" not in repr(result)
    assert result.code is None and result.source_time is None
    assert result.event_id == "synthetic"


def test_unknown_and_image_less_notifications_remain_honest():
    assert (
        camera_channel_notification(data(), {"ext": {"channel_type": 14, "channel_no": 2}}) is None
    )
    result = camera_channel_notification(data(), {"ext": {"channel_type": 1, "channel_no": 1}})
    assert result is not None and result.event_id is None and result.image_url is None


@pytest.mark.parametrize(
    "index,expected", [(1, "Video:1"), ("2", "Video_1:2"), (None, None), (True, None), (9, None)]
)
def test_alarm_history_uses_only_explicit_reported_channels(index, expected):
    result = alarm_camera_channel(data(), {"channel": index})
    assert (result.key if result is not None else None) == expected


def test_capture_default_and_explicit_channel_are_separate():
    assert capture_channel_number({}) == 1
    assert capture_channel_number(data(), "Video_1:2") == 2
    with pytest.raises(CameraChannelError):
        capture_channel_number(data(), "Video_2:3")


def test_oversized_numeric_channel_is_invalid():
    data = {"resourceInfos": [{"resourceIdentifier": "Video_1", "localIndex": 10**5000}]}
    assert camera_channels(data) == ()
    with pytest.raises(CameraChannelError) as caught:
        resolve_camera_channel(data, "Video_1:1")
    assert caught.value.reason == "invalid"


def test_unnamed_video_is_a_numeric_channel_not_a_named_route():
    info = {
        "resourceInfos": [
            {"resourceType": 0, "localIndex": "0"},
            {"resourceType": 50, "localIndex": "1"},
            {"resourceIdentifier": "Video_1", "localIndex": "2"},
        ]
    }
    assert reported_video_channel_numbers(info) == (1, 2)
    assert [channel.key for channel in camera_channels(info)] == ["Video_1:2"]
    with pytest.raises(CameraChannelError):
        resolve_camera_channel(info, "Video:1")
