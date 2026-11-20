"""Loopback response limits: decoded streaming bytes, cleanup and no retries."""
# ruff: noqa: SLF001 -- observe HTTP ownership and ephemeral auth state.

from collections.abc import Iterator
from contextlib import contextmanager, suppress
import gzip
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
import time

import pytest
import requests

from pyezvizapi.client import EzvizClient
from pyezvizapi.cloud import budget as http_budget
from pyezvizapi.cloud.budget import MAX_BOOTSTRAP_BODY_BYTES, budgeted_http_call
from pyezvizapi.cloud.challenges import _CaptchaContext, _CaptchaPurpose
from pyezvizapi.cloud.deadline import request_deadline
from pyezvizapi.exceptions import PyEzvizError

CAPTCHA_LIMIT = 1024 * 1024
READ_CHUNK = 16384
PNG_HEADER = b"\x89PNG\r\n\x1a\n"


@contextmanager
def image_server(body: bytes, framing: str = "length") -> Iterator[tuple[str, list[str]]]:
    """Serve exactly one request, with no external endpoint or credentials."""
    calls: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            calls.append(self.path)
            encoded = gzip.compress(body) if framing == "gzip" else body
            self.send_response(200)
            self.send_header("Set-Cookie", "image-response=accepted")
            if framing == "gzip":
                self.send_header("Content-Encoding", "gzip")
            if framing == "chunked":
                self.send_header("Transfer-Encoding", "chunked")
            else:
                self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            with suppress(BrokenPipeError, ConnectionResetError):
                for offset in range(0, len(encoded), READ_CHUNK):
                    chunk = encoded[offset : offset + READ_CHUNK]
                    if framing == "chunked":
                        self.wfile.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
                    else:
                        self.wfile.write(chunk)
                if framing == "chunked":
                    self.wfile.write(b"0\r\n\r\n")

    server = HTTPServer(("127.0.0.1", 0), Handler)
    server.timeout = 2
    thread = Thread(target=server.handle_request, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/v3/captcha", calls
    finally:
        thread.join(timeout=3)
        server.server_close()
        assert not thread.is_alive()


@pytest.fixture
def observed_transport(monkeypatch):
    """Keep the real requests transport; observe decoded reads and response closure."""
    worker = http_budget._HttpWorker()
    monkeypatch.setattr(http_budget, "_WORKER", worker)
    sizes: list[int] = []
    responses: list[requests.Response] = []
    original = requests.Response.iter_content

    def chunks(response, *args, **kwargs):
        responses.append(response)
        for chunk in original(response, *args, **kwargs):
            sizes.append(len(chunk))
            yield chunk

    monkeypatch.setattr(requests.Response, "iter_content", chunks)
    yield sizes, responses
    if worker._thread is not None:
        worker._thread.join(timeout=2)
    assert worker._thread is None


@pytest.mark.parametrize("framing", ["length", "chunked", "gzip"])
def test_captcha_rejects_during_decoded_stream_and_keeps_session_owned(
    monkeypatch, observed_transport, framing
):
    sizes, responses = observed_transport
    body = PNG_HEADER + b"x" * (2 * CAPTCHA_LIMIT)
    with image_server(body, framing) as (url, calls):
        client = EzvizClient("synthetic-account", "synthetic-password", url="region.example.test")
        client._session.trust_env = False
        monkeypatch.setattr(client, "_url", lambda _: url)
        # A rejected replacement must also revoke the previous answer context.
        previous = client._captcha_state.issue(PNG_HEADER, _CaptchaContext("old", "feature", "synthetic-account", _CaptchaPurpose.LOGIN))
        original_headers = dict(client._session.headers)
        closed_sessions = []
        original_close = requests.Session.close

        def close(session):
            closed_sessions.append(session)
            original_close(session)

        monkeypatch.setattr(requests.Session, "close", close)
        try:
            with pytest.raises(PyEzvizError) as caught:
                client.get_captcha()
            assert sum(sizes) <= CAPTCHA_LIMIT + READ_CHUNK
            assert "byte limit" in str(caught.value)
            assert len(responses) == 1 and responses[0].raw.closed
            assert len(calls) == 1 and "account=synthetic-account" in calls[0]
            assert client._captcha_state.challenge is None
            assert previous is not client._captcha_state.challenge
            assert dict(client._session.headers) == original_headers
            assert not client._session.cookies
            assert not closed_sessions  # Neither caller nor borrowed adapters are closed.
            assert "synthetic-account" not in str(caught.value)
        finally:
            client._session.close()


@pytest.mark.parametrize("framing", ["length", "chunked", "gzip"])
def test_captcha_accepts_exact_decoded_limit(monkeypatch, observed_transport, framing):
    sizes, responses = observed_transport
    body = PNG_HEADER + b"x" * (CAPTCHA_LIMIT - len(PNG_HEADER))
    with image_server(body, framing) as (url, calls):
        client = EzvizClient("synthetic-account", "synthetic-password", url="region.example.test")
        client._session.trust_env = False
        monkeypatch.setattr(client, "_url", lambda _: url)
        try:
            image = client.get_captcha()
            assert image.image == body
            assert sum(sizes) == CAPTCHA_LIMIT
            assert len(responses) == 1 and responses[0].raw.closed
            assert len(calls) == 1
            assert client._session.cookies["image-response"] == "accepted"
        finally:
            client._session.close()


@pytest.mark.parametrize(
    "size, accepted",
    [
        (CAPTCHA_LIMIT + 1, True),
        (MAX_BOOTSTRAP_BODY_BYTES, True),
        (MAX_BOOTSTRAP_BODY_BYTES + 1, False),
    ],
)
def test_other_scoped_calls_keep_eight_mib_limit(observed_transport, size, accepted):
    sizes, responses = observed_transport
    body = b"x" * size
    with image_server(body) as (url, calls), requests.Session() as session:
        session.trust_env = False
        with request_deadline(time.monotonic() + 5):
            if accepted:
                response = budgeted_http_call(session, "get", url=url, timeout=2)
                try:
                    assert response.content == body
                finally:
                    response.close()
            else:
                with pytest.raises(PyEzvizError, match="byte limit"):
                    budgeted_http_call(session, "get", url=url, timeout=2)
        assert len(calls) == 1 and len(responses) == 1
        assert responses[0].raw.closed
        assert sum(sizes) == size
        assert bool(session.cookies) is accepted


@pytest.mark.parametrize("size, accepted", [(CAPTCHA_LIMIT, True), (CAPTCHA_LIMIT + 1, False)])
def test_materialized_transport_honors_per_request_limit(monkeypatch, size, accepted):
    response = requests.Response()
    response.status_code = 200
    response._content = b"x" * size
    response.__dict__["_content_consumed"] = True
    closed = []
    monkeypatch.setattr(response, "close", lambda: closed.append(True))
    calls = []

    def get(session, **kwargs):
        calls.append(kwargs)
        session.cookies.set("worker-cookie", "accepted")
        return response

    monkeypatch.setattr(requests.Session, "get", get)
    with requests.Session() as session, request_deadline(time.monotonic() + 2):
        if accepted:
            result = budgeted_http_call(
                session, "get", max_body_bytes=CAPTCHA_LIMIT, url="https://unused.invalid"
            )
            assert result is response and not closed
            result.close()
        else:
            with pytest.raises(PyEzvizError, match="byte limit"):
                budgeted_http_call(
                    session, "get", max_body_bytes=CAPTCHA_LIMIT, url="https://unused.invalid"
                )
        assert bool(session.cookies) is accepted
        assert closed == [True]
        assert calls == [{"url": "https://unused.invalid", "stream": True}]


@pytest.mark.parametrize("limit", [0, -1, True, 1.5, MAX_BOOTSTRAP_BODY_BYTES + 1])
def test_invalid_limit_rejected_before_transport(monkeypatch, limit):
    def unexpected(*_args, **_kwargs):
        pytest.fail("Invalid limits must not reach the transport")

    monkeypatch.setattr(requests.Session, "get", unexpected)
    with (
        requests.Session() as session,
        request_deadline(time.monotonic() + 2),
        pytest.raises(ValueError, match="positive integer"),
    ):
        budgeted_http_call(session, "get", max_body_bytes=limit, url="https://unused.invalid")


def test_custom_limit_without_deadline_is_not_silently_ignored(monkeypatch):
    def unexpected(*_args, **_kwargs):
        pytest.fail("A custom byte limit requires a scoped deadline")

    monkeypatch.setattr(requests.Session, "get", unexpected)
    with (
        requests.Session() as session,
        pytest.raises(ValueError, match="requires a request deadline"),
    ):
        budgeted_http_call(
            session, "get", max_body_bytes=CAPTCHA_LIMIT, url="https://unused.invalid"
        )
