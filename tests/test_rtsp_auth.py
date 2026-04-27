from __future__ import annotations

import hashlib

from pyezvizapi.test_cam_rtsp import TestRTSPAuth, genmsg_describe


def test_genmsg_describe_builds_rtsp_describe_request() -> None:
    request = genmsg_describe(
        "rtsp://192.0.2.10/h264",
        3,
        "UnitTest",
        "Basic abc123",
    )

    assert request == (
        "DESCRIBE rtsp://192.0.2.10/h264 RTSP/1.0\r\n"
        "CSeq: 3\r\n"
        "Authorization: Basic abc123\r\n"
        "User-Agent: UnitTest\r\n"
        "Accept: application/sdp\r\n\r\n"
    )


def test_generate_auth_string_builds_digest_response() -> None:
    auth = TestRTSPAuth("192.0.2.10", "user", "pass", "/h264")

    header = auth.generate_auth_string(b"realm-1", "DESCRIBE", "/h264", b"nonce-1")

    ha1 = hashlib.md5(b"user:realm-1:pass").hexdigest()
    ha2 = hashlib.md5(b"DESCRIBE:/h264").hexdigest()
    expected_response = hashlib.md5(f"{ha1}:nonce-1:{ha2}".encode()).hexdigest()
    assert header == (
        'Digest username="user", realm="realm-1", algorithm="MD5", '
        f'nonce="nonce-1", uri="/h264", response="{expected_response}"'
    )
