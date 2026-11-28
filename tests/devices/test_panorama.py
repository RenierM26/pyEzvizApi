"""Cloud panorama request contracts and bounded downloads."""

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from threading import Event, Thread
from time import monotonic
from urllib.parse import parse_qs, urlsplit

import pytest
import requests

from pyezvizapi.devices import panorama, ptz
from pyezvizapi.devices.channels import CameraChannel
from pyezvizapi.exceptions import PyEzvizError


@pytest.mark.parametrize(
    "name",
    [
        "download_saved_panorama",
        "get_panorama_info",
        "get_stored_panorama",
        "move_to_panorama_point",
        "reset_panorama_mark",
        "resolve_panorama_capture_route",
        "start_device_panorama_capture",
        "start_panorama_capture",
    ],
)
def test_ptz_panorama_imports_remain_compatible(name: str) -> None:
    assert getattr(ptz, name) is getattr(panorama, name)


@pytest.mark.parametrize("operation", ["capture", "move", "reset", "stored"])
def test_v3_panorama_does_not_accept_legacy_success(device_requests, operation) -> None:
    client, sent, replies = device_requests
    ch = CameraChannel("Video_2", "2")
    calls = {
        "capture": lambda: panorama.start_panorama_capture(client, "CAM001", channel=ch),
        "move": lambda: panorama.move_to_panorama_point(client, "CAM001", 0.2, 0.4),
        "reset": lambda: panorama.reset_panorama_mark(client, "CAM001"),
        "stored": lambda: panorama.get_stored_panorama(client, "CAM001"),
    }
    replies.append({"meta": {"code": 2009}, "resultCode": 0, "picInfo": {}})
    with pytest.raises(PyEzvizError, match="2009"):
        calls[operation]()
    assert len(sent) == 1


def test_resource_panorama_wire(device_requests) -> None:
    client, sent, replies = device_requests
    channel = CameraChannel("Video_2", "2")
    info = {"percent": 50, "picInfoList": []}
    replies.extend(
        [{"meta": {"code": 200}}, {"meta": {"code": 200}, "data": info}, {"meta": {"code": 403}}]
    )
    panorama.start_panorama_capture(client, "cam001", channel=channel)
    progress = panorama.get_panorama_info(client, "cam001", channel=channel)
    assert progress == info
    assert sent[0].method == "POST"
    assert urlsplit(sent[0].url).path == "/v3/panoramicDevices/action/pics/collect/CAM001/2"
    assert json.loads(sent[0].body) == {
        "resourceId": "Video_2",
        "domainId": "Panorama",
        "propId": "PanoramicCompPictureInfo",
        "actionId": "TriggerPanoramicCapture",
    }
    assert sent[1].method == "PUT"
    assert urlsplit(sent[1].url).path == (
        "/v3/iot-feature/action/CAM001/Video_2/2/Panorama/QueryPanoramicPicInfo"
    )
    assert json.loads(sent[1].body) == {}
    with pytest.raises(PyEzvizError, match="Could not start panorama"):
        panorama.start_panorama_capture(client, "CAM001", channel=channel)
    assert len(sent) == 3



def test_panorama_interaction_uses_explicit_routes(device_requests) -> None:
    client, sent, replies = device_requests
    replies.extend([{"meta": {"code": 200}}] * 3)
    panorama.move_to_panorama_point(client, "cam001", 0.12556789, 1.0)
    panorama.move_to_panorama_point(
        client, "cam001", 0.12556789, 1.0, channel=CameraChannel("Video_2", "2")
    )
    panorama.reset_panorama_mark(client, "cam001")
    assert [(r.method, urlsplit(r.url).path) for r in sent] == [
        ("POST", "/v3/panoramicDevices/operation"),
        ("PUT", "/v3/iot-feature/action/CAM001/Video_2/2/Panorama/RotateFixpoint"),
        ("PUT", "/v3/panoramicDevices/ptz/coordinate/mark"),
    ]
    assert parse_qs(sent[0].body) == {
        "deviceSerial": ["CAM001"],
        "x": ["0.125568"],
        "y": ["1"],
    }
    assert json.loads(sent[1].body) == {"x": 0.126, "y": 1.0}
    assert parse_qs(sent[2].body, keep_blank_values=True) == {
        "deviceSerial": ["CAM001"],
        "detectorSubSerial": [""],
        "x": [""],
        "y": [""],
        "markType": ["3"],
    }



@pytest.mark.parametrize("axis", [True, -0.1, 1.1, float("nan"), float("inf"), "0.5"])
def test_invalid_panorama_points_stay_offline(device_requests, axis) -> None:
    client, sent, _ = device_requests
    with pytest.raises(ValueError, match="coordinates"):
        panorama.move_to_panorama_point(client, "CAM001", axis, 0.5)
    assert not sent



@pytest.mark.parametrize("channel", [None, CameraChannel("Video_2", "2")])
def test_panorama_move_failure_does_not_try_another_route(device_requests, channel) -> None:
    client, sent, replies = device_requests
    replies.append({"meta": {"code": 403}})
    with pytest.raises(PyEzvizError):
        panorama.move_to_panorama_point(client, "CAM001", 0.25, 0.5, channel=channel)
    assert len(sent) == 1



def test_stored_panorama_reads_empty_record_without_starting_capture(device_requests) -> None:
    client, sent, replies = device_requests
    info = {"progress": 0, "levelPicInfoList": []}
    replies.append({"meta": {"code": 200}, "picInfo": info})
    actual = panorama.get_stored_panorama(client, "cam001")
    assert actual == info
    (request,) = sent
    assert request.method == "GET"
    url = urlsplit(request.url)
    assert url.path == "/v3/panoramicDevices/pics"
    assert parse_qs(url.query) == {"deviceSerial": ["CAM001"]}



@pytest.mark.parametrize("code", [200, 2009])
def test_device_panorama_capture_contract(device_requests, code) -> None:
    client, sent, replies = device_requests
    replies.append({"meta": {"code": code}, "resultCode": 0})
    if code == 200:
        panorama.start_device_panorama_capture(client, "cam001")
    else:
        with pytest.raises(PyEzvizError, match="2009"):
            panorama.start_device_panorama_capture(client, "cam001")
    (request,) = sent
    assert request.method == "POST"
    assert urlsplit(request.url).path == "/v3/panoramicDevices/pics/collect"
    assert parse_qs(request.body) == {"deviceSerial": ["CAM001"]}



@pytest.fixture
def panorama_download(device_requests, monkeypatch):
    client, _, _ = device_requests
    status = {"CAM001": {"levelPicUrl": "https://pmseu1.ezvizlife.com:8444/pic?sig=test"}}
    monkeypatch.setattr(client, "get_page_list", lambda: {"STATUS": status})
    return client, status



def test_download_saved_panorama_isolated_media(panorama_download, monkeypatch) -> None:
    client, _ = panorama_download
    jpeg = b"\xff\xd8\xffsample\xff\xd9"
    calls = []

    def send(session, request, **kwargs):
        calls.append((session.trust_env, request.method, request.url, request.headers, kwargs))
        response = requests.Response()
        response.status_code = 200
        response._content = jpeg  # noqa: SLF001
        response.__dict__["_content_consumed"] = True
        return response

    monkeypatch.setattr(requests.Session, "send", send)
    result = panorama.download_saved_panorama(client, "cam001")
    assert result == jpeg
    [(trust_env, method, url, headers, kwargs)] = calls
    assert not trust_env
    assert method == "GET"
    assert url == "https://pmseu1.ezvizlife.com:8444/pic?sig=test"
    assert not {"authorization", "cookie", "sessionid", "featurecode"} & {
        k.lower() for k in headers
    }
    assert kwargs["allow_redirects"] is False
    assert kwargs["stream"] is True
    assert kwargs["timeout"] == (5, 5)



@pytest.mark.parametrize(
    ("value", "error"),
    [
        (None, None),
        ("", None),
        (123, "Malformed"),
        ("http://pmseu1.ezvizlife.com/pic", "Unsupported"),
        ("https://pmseu1.ezvizlife.com.example.org/pic", "Unsupported"),
        ("https://user@pmseu1.ezvizlife.com/pic", "Unsupported"),
        ("https://pmseu1.ezvizlife.com:81/pic", "Unsupported"),
        ("https://[invalid/pic", "Unsupported"),
    ],
)
def test_download_saved_panorama_does_not_fetch_missing_or_invalid_url(
    panorama_download, monkeypatch, value, error
) -> None:
    client, status = panorama_download
    status["CAM001"]["levelPicUrl"] = value

    def unexpected(*args, **kwargs):
        pytest.fail("Invalid or missing URL reached media transport")

    monkeypatch.setattr(requests.Session, "send", unexpected)
    if error is None:
        result = panorama.download_saved_panorama(client, "CAM001")
        assert result is None
    else:
        with pytest.raises(PyEzvizError, match=error):
            panorama.download_saved_panorama(client, "CAM001")



@pytest.mark.parametrize(
    ("code", "data", "message"),
    [
        (302, b"", "HTTP 302"),
        (403, b"", "HTTP 403"),
        (200, b"<html>", "JPEG"),
        (200, b"\xff\xd8\xffsample\xff\xd9" * 10, "size limit"),
    ],
)
def test_download_saved_panorama_rejects_bad_media(
    panorama_download, monkeypatch, code, data, message
) -> None:
    client, _ = panorama_download
    monkeypatch.setattr(panorama, "_PANORAMA_DOWNLOAD_LIMIT", 64)

    def send(*args, **kwargs):
        response = requests.Response()
        response.status_code = code
        response._content = data  # noqa: SLF001
        response.__dict__["_content_consumed"] = True
        return response

    monkeypatch.setattr(requests.Session, "send", send)
    with pytest.raises(PyEzvizError, match=message):
        panorama.download_saved_panorama(client, "CAM001")



def test_download_saved_panorama_redacts_request_errors(panorama_download, monkeypatch) -> None:
    client, _ = panorama_download

    def send(*args, **kwargs):
        raise requests.ReadTimeout("signed URL must not appear")

    monkeypatch.setattr(requests.Session, "send", send)
    with pytest.raises(PyEzvizError, match=r"^Could not download saved panorama$") as error:
        panorama.download_saved_panorama(client, "CAM001")
    assert error.value.__suppress_context__



def test_download_saved_panorama_stops_a_slow_stream(monkeypatch) -> None:
    sent_body = Event()
    stop = Event()
    disconnected = Event()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Length", "65536")
            self.end_headers()
            try:
                while not stop.is_set():
                    self.wfile.write(b"x")
                    self.wfile.flush()
                    sent_body.set()
                    stop.wait(0.02)
            except (BrokenPipeError, ConnectionResetError):
                disconnected.set()

    with HTTPServer(("127.0.0.1", 0), Handler) as server:
        worker = Thread(target=server.handle_request, daemon=True)
        worker.start()
        monkeypatch.setattr(panorama, "_validate_panorama_url", lambda _: None)
        monkeypatch.setattr(panorama, "_PANORAMA_DOWNLOAD_TIMEOUT", 0.2)
        started = monotonic()
        try:
            with pytest.raises(PyEzvizError, match="exceeded its time limit"):
                panorama._fetch_panorama_jpeg(  # noqa: SLF001
                    f"http://127.0.0.1:{server.server_port}/pic"
                )
            assert monotonic() - started < 1
            assert sent_body.is_set()
            closed = disconnected.wait(1)
            assert closed
        finally:
            stop.set()
            worker.join(timeout=2)
