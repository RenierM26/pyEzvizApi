"""Wire tests for the recorded alarm upload."""

from email import policy
from email.parser import BytesParser
from urllib.parse import urlsplit

import pytest

from pyezvizapi.exceptions import PyEzvizError


def test_custom_alarm_audio_multipart(device_requests) -> None:
    client, sent, replies = device_requests
    audio = b"\xff\x00audio\r\n"
    replies.append({"meta": {"code": 200}, "fileUrl": "https://files.example/recording"})
    assert client.upload_custom_alarm_audio(audio) == "https://files.example/recording"
    (request,) = sent
    assert request.method == "POST"
    url = urlsplit(request.url)
    assert url.path == "/v3/clients/v1/file/upload"
    assert url.query == "bizType=3"
    header = f"Content-Type: {request.headers['Content-Type']}\r\n\r\n".encode()
    body = BytesParser(policy=policy.default).parsebytes(header + request.body)
    (part,) = body.iter_parts()
    assert part.get_param("name", header="Content-Disposition") == "file"
    assert part.get_filename() == "file"
    assert part.get_content_type() == "multipart/form-data"
    assert b"\r\n\r\n" + audio + b"\r\n--" in request.body


@pytest.mark.parametrize("audio", [b"", "text", None])
def test_invalid_audio_sends_nothing(device_requests, audio) -> None:
    client, sent, _ = device_requests
    with pytest.raises(ValueError, match="alarm audio bytes"):
        client.upload_custom_alarm_audio(audio)
    assert not sent


@pytest.mark.parametrize(
    ("reply", "message"),
    [
        ({"meta": {"code": 500}}, "Could not upload"),
        ({"meta": {"code": 200}}, "Missing custom alarm audio file URL"),
    ],
)
def test_audio_upload_errors(device_requests, reply, message) -> None:
    client, sent, replies = device_requests
    replies.append(reply)
    with pytest.raises(PyEzvizError, match=message):
        client.upload_custom_alarm_audio(b"audio")
    assert len(sent) == 1
