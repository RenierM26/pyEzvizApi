"""Real loopback deadlines plus bounded worker cancellation/ownership probes."""
# ruff: noqa: SLF001 -- explicit transport/worker ownership regressions.
import gzip
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Event, Thread
import time

import pytest
import requests

from pyezvizapi.cloud import budget as _budget_http
from pyezvizapi.cloud.budget import budgeted_http_call
from pyezvizapi.cloud.deadline import request_deadline

CALLER_RETURN_CEILING_SECONDS = 0.4
EMPTY_JSON = b"{}"


@pytest.fixture
def worker(monkeypatch):
    worker = _budget_http._HttpWorker()
    monkeypatch.setattr(_budget_http, "_WORKER", worker)
    return worker


@pytest.mark.parametrize("phase", ["headers", "body"])
def test_loopback_dribble_does_not_hold_caller_past_deadline(worker, phase):
    stopped = Event()
    disconnected = Event()
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass
        def do_GET(self):
            try:
                if phase == "headers":
                    self.connection.sendall(b"HTTP/1.0 200 ")
                    for byte in b"OK\r\nContent-Length: 2\r\n\r\n{}":
                        self.connection.sendall(bytes([byte]))
                        time.sleep(0.02)
                else:
                    self.send_response(200)
                    self.send_header("Content-Length", "100")
                    self.end_headers()
                    for _ in range(100):
                        self.wfile.write(b"x")
                        self.wfile.flush()
                        time.sleep(0.02)
            except (BrokenPipeError, ConnectionResetError):
                disconnected.set()
            finally:
                stopped.set()
    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.handle_request, daemon=True)
    thread.start()
    session = requests.Session()
    started = time.monotonic()
    try:
        with pytest.raises(TimeoutError), request_deadline(started + 0.12):
            budgeted_http_call(session, "get", url=f"http://127.0.0.1:{server.server_port}", timeout=1)
        elapsed = time.monotonic() - started
        assert elapsed < CALLER_RETURN_CEILING_SECONDS
        assert stopped.wait(2)
        if phase == "body":
            assert disconnected.is_set()
        thread.join(timeout=1)
    finally:
        session.close()
        server.server_close()


def test_stuck_call_does_not_spawn_replacements_or_execute_cancelled_queue(worker, monkeypatch):
    release = Event()
    entered = Event()
    calls = []
    class Response(requests.Response):
        closed = False
        def close(self):
            self.closed = True
            super().close()
    response = Response()
    response._content = b"{}"
    response.status_code = 200
    def get(_self, **_kwargs):
        calls.append(True)
        _self.cookies.set("late-cookie", "discard")
        entered.set()
        release.wait(2)
        return response
    monkeypatch.setattr(requests.Session, "get", get)
    session = requests.Session()
    try:
        for _ in range(2):
            with pytest.raises(TimeoutError), request_deadline(time.monotonic() + 0.05):
                budgeted_http_call(session, "get", url="https://unused.invalid")
        assert entered.is_set()
        same_thread = worker._thread
        with pytest.raises(TimeoutError, match="busy"), request_deadline(time.monotonic() + 0.05):
            budgeted_http_call(session, "get", url="https://unused.invalid")
        assert worker._thread is same_thread
    finally:
        release.set()
        if worker._thread is not None:
            worker._thread.join(timeout=2)
        session.close()
    assert len(calls) == 1 and response.closed
    assert "late-cookie" not in session.cookies
    assert worker._thread is None


def test_worker_does_not_mutate_source_request_state(worker, monkeypatch):
    source = requests.Session()
    source.headers["X-Test"] = "original"
    def get(session, **_kwargs):
        session.headers["X-Test"] = "changed in transport"
        response = requests.Response()
        response.status_code = 200
        response._content = b"{}"
        return response
    monkeypatch.setattr(requests.Session, "get", get)
    try:
        with request_deadline(time.monotonic() + 1):
            response = budgeted_http_call(source, "get", url="https://unused.invalid")
        assert response.content == EMPTY_JSON
        assert source.headers["X-Test"] == "original"
    finally:
        source.close()


@pytest.mark.parametrize("encoded", [False, True])
def test_loopback_success_decodes_body_and_preserves_cookies(worker, encoded):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass
        def do_GET(self):
            body = gzip.compress(EMPTY_JSON) if encoded else EMPTY_JSON
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Set-Cookie", "test-cookie=accepted")
            if encoded:
                self.send_header("Content-Encoding", "gzip")
            self.end_headers()
            self.wfile.write(body)
    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.handle_request, daemon=True)
    thread.start()
    session = requests.Session()
    try:
        with request_deadline(time.monotonic() + 2):
            response = budgeted_http_call(session, "get", url=f"http://127.0.0.1:{server.server_port}", timeout=1)
        assert response.json() == {}
        assert session.cookies["test-cookie"] == "accepted"
    finally:
        session.close()
        thread.join(timeout=2)
        server.server_close()


def test_ordinary_http_preserves_synchronous_behavior(worker, monkeypatch):
    source = requests.Session()
    kwargs_seen = []
    def get(session, **kwargs):
        assert session is source
        kwargs_seen.append(kwargs)
        return requests.Response()
    monkeypatch.setattr(requests.Session, "get", get)
    try:
        budgeted_http_call(source, "get", url="https://unused.invalid")
        assert worker._thread is None
        assert "stream" not in kwargs_seen[0]
    finally:
        source.close()


@pytest.mark.parametrize("expiration", ["Max-Age=0", "Expires=Thu, 01 Jan 1970 00:00:00 GMT"])
def test_loopback_cookie_expiration_removes_only_the_matching_cookie(worker, expiration):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.send_header("Set-Cookie", f"session=; Path=/; {expiration}")
            self.end_headers()
            self.wfile.write(EMPTY_JSON)
    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.handle_request, daemon=True)
    thread.start()
    source = requests.Session()
    source.cookies.set("session", "expired", domain="127.0.0.1", path="/")
    source.cookies.set("session", "other-path", domain="127.0.0.1", path="/other")
    source.cookies.set("session", "other-domain", domain="example.test", path="/")
    try:
        with request_deadline(time.monotonic() + 2):
            response = budgeted_http_call(source, "get", url=f"http://127.0.0.1:{server.server_port}/", timeout=1)
        assert response.json() == {}
        assert source.cookies.get("session", domain="127.0.0.1", path="/") is None
        assert source.cookies.get("session", domain="127.0.0.1", path="/other") == "other-path"
        assert source.cookies.get("session", domain="example.test", path="/") == "other-domain"
    finally:
        source.close()
        thread.join(timeout=2)
        server.server_close()


def test_cookie_delta_preserves_caller_changes_and_applies_replacements(worker, monkeypatch):
    source = requests.Session()
    source.cookies.set("expired", "initial", domain="example.test", path="/")
    source.cookies.set("unchanged", "initial", domain="example.test", path="/")
    source.cookies.set("rotated", "initial", domain="example.test", path="/")
    def get(borrowed, **_kwargs):
        source.cookies.set("expired", "caller-new", domain="example.test", path="/")
        source.cookies.set("unchanged", "caller-new", domain="example.test", path="/")
        source.cookies.set("added-by-caller", "keep", domain="example.test", path="/")
        borrowed.cookies.clear("example.test", "/", "expired")
        borrowed.cookies.set("rotated", "server-new", domain="example.test", path="/")
        borrowed.cookies.set("added-by-server", "keep", domain="example.test", path="/")
        response = requests.Response()
        response.status_code = 200
        response._content = EMPTY_JSON
        return response
    monkeypatch.setattr(requests.Session, "get", get)
    try:
        with request_deadline(time.monotonic() + 1):
            budgeted_http_call(source, "get", url="https://unused.invalid")
        assert source.cookies.get_dict() == {
            "expired": "caller-new", "unchanged": "caller-new", "rotated": "server-new",
            "added-by-caller": "keep", "added-by-server": "keep",
        }
    finally:
        source.close()
