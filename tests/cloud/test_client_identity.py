"""Explicit installation identities through real SDK request/persistence boundaries."""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
from typing import Any
from unittest.mock import Mock
from urllib.parse import parse_qs, urlsplit

import pytest
import requests

from pyezvizapi.client import EzvizClient
from pyezvizapi.cloud.cas import EzvizCAS
from pyezvizapi.constants import ANDROID_PROFILE, FEATURE_CODE, REQUEST_HEADER, WEB_PROFILE
from pyezvizapi.exceptions import EzvizAuthTokenExpired, EzvizAuthVerificationCode, PyEzvizError
from pyezvizapi.push.mqtt import MQTTClient

FIRST = "1" * 32
SECOND = "2" * 32


def saved_token(code: str = FIRST) -> dict[str, Any]:
    """Return a complete synthetic login without real device/account identifiers."""
    return {
        "api_url": "api.example.invalid",
        "username": "internal",
        "user_id": "user",
        "session_id": "session",
        "rf_session_id": "refresh",
        "push_profile": ANDROID_PROFILE.name,
        "feature_code": code,
        "push_state": {"counter": 7},
        "service_urls": {"pushDasDomain": "push.example.invalid", "sysConf": []},
    }


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reject DNS/socket access even when an HTTP or CAS mock is missing."""

    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("Identity controls must not access a live network")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)


@pytest.fixture
def http(monkeypatch: pytest.MonkeyPatch) -> list[requests.PreparedRequest]:
    """Capture real request preparation; only HTTP delivery is synthetic."""
    captured: list[requests.PreparedRequest] = []

    def send(
        _session: requests.Session, request: requests.PreparedRequest, **_kwargs: Any
    ) -> requests.Response:
        captured.append(request)
        assert request.url is not None
        if request.method == "POST":
            data = {
                "meta": {"code": 200},
                "loginSession": {"sessionId": "fresh", "rfSessionId": "fresh-refresh"},
                "loginUser": {"username": "internal", "userId": "user"},
                "loginArea": {"apiDomain": "api.example.invalid"},
            }
        elif request.method == "PUT" and urlsplit(request.url).path == "/v3/push/token":
            data = {"meta": {"code": 200}}
        elif request.method == "PUT":
            data = {
                "meta": {"code": 200},
                "sessionInfo": {"sessionId": "rotated", "refreshSessionId": "rotated-refresh"},
            }
        else:
            data = {
                "meta": {"code": 200},
                "systemConfigInfo": {"pushDasDomain": "push.example.invalid", "sysConf": "|"},
            }
        response = requests.Response()
        response.status_code = 200
        response._content = json.dumps(data).encode()  # noqa: SLF001 - Synthetic HTTP transport boundary.
        response.url = request.url
        return response

    monkeypatch.setattr(requests.Session, "send", send)
    return captured


@pytest.mark.parametrize(
    "identity", ["", "a" * 31, "A" * 32, "g" * 32, "a" * 33, True, 1, b"a" * 32]
)
@pytest.mark.parametrize("kind", ["client", "cas", "push"])
def test_invalid_explicit_identity_fails_before_io(
    monkeypatch: pytest.MonkeyPatch,
    identity: Any,
    kind: str,
) -> None:
    """An invalid setting must not allocate an HTTP client or rewrite its token."""
    token = saved_token()
    before = deepcopy(token)
    allocation = Mock(side_effect=AssertionError("unexpected session allocation"))
    monkeypatch.setattr(requests, "session", allocation)
    with pytest.raises(PyEzvizError, match="32 lowercase hexadecimal"):
        if kind == "client":
            EzvizClient(token=token, feature_code=identity)
        elif kind == "cas":
            EzvizCAS(token, feature_code=identity)
        else:
            MQTTClient(token, Mock(), feature_code=identity)
    allocation.assert_not_called()
    assert token == before


def test_explicit_selection_is_required_and_mismatch_does_not_mutate() -> None:
    """A token must never silently select its own identity or be relabelled."""
    token = saved_token()
    before = deepcopy(token)
    assert FIRST != FEATURE_CODE
    with pytest.raises(EzvizAuthTokenExpired):
        EzvizClient(token=token)
    with pytest.raises(EzvizAuthTokenExpired):
        EzvizClient(token=token, feature_code=SECOND)
    with pytest.raises(EzvizAuthTokenExpired):
        EzvizCAS(token, feature_code=SECOND)
    push = MQTTClient(token, Mock(), feature_code=SECOND, on_token_updated=Mock())
    with pytest.raises(EzvizAuthTokenExpired):
        push.connect()
    assert token == before
    client = EzvizClient(token=token, feature_code=FIRST)
    with pytest.raises(AttributeError):
        object.__setattr__(client, "feature_code", SECOND)
    assert client.export_token() == before
    assert client.feature_code == FIRST
    client.close_session()


@pytest.mark.parametrize("channel99", [False, True])
def test_fresh_login_refresh_and_recreated_session_use_one_identity(
    http: list[requests.PreparedRequest],
    channel99: bool,
) -> None:
    """Fresh credentials and every rotated snapshot retain the selected identity."""
    persisted: list[dict[str, Any]] = []
    client = EzvizClient(
        account="synthetic",
        password="synthetic",
        feature_code=FIRST,
        on_token_updated=persisted.append,
    )
    assert client.feature_code == FIRST  # Available for persistence before login.
    token = client.enable_channel99() if channel99 else client.login()
    assert token["feature_code"] == FIRST
    assert persisted and all(record["feature_code"] == FIRST for record in persisted)
    before = deepcopy(token)
    restored = EzvizClient(
        token=deepcopy(token), feature_code=FIRST, on_token_updated=persisted.append
    )
    restored.login()
    restored.close_session()
    restored.login()
    assert all(request.headers["featureCode"] == FIRST for request in http)
    for request in http:
        if request.method in ("POST", "PUT"):
            body = request.body.decode() if isinstance(request.body, bytes) else request.body
            assert parse_qs(body)["featureCode"] == [FIRST]
    assert restored.export_token()["feature_code"] == FIRST
    assert restored.export_token().get("push_state") == before.get("push_state")
    assert all(record["feature_code"] == FIRST for record in persisted)


def test_mfa_retry_keeps_identity(
    monkeypatch: pytest.MonkeyPatch, http: list[requests.PreparedRequest]
) -> None:
    """The SMS retry must not select a new identity or migrate an old credential."""
    client = EzvizClient(account="synthetic", password="synthetic", feature_code=FIRST)
    original = requests.Session.send
    attempts = 0

    def send(
        session: requests.Session, request: requests.PreparedRequest, **kwargs: Any
    ) -> requests.Response:
        nonlocal attempts
        if request.method == "POST":
            assert request.headers["featureCode"] == FIRST
            assert parse_qs(str(request.body))["featureCode"] == [FIRST]
            attempts += 1
            if attempts == 1:
                response = requests.Response()
                response.status_code = 200
                response._content = b'{"meta":{"code":6002}}'  # noqa: SLF001 - Synthetic MFA response.
                return response
        return original(session, request, **kwargs)

    monkeypatch.setattr(requests.Session, "send", send)
    monkeypatch.setattr(client, "send_mfa_code", Mock())
    with pytest.raises(EzvizAuthVerificationCode):
        client.enable_channel99()
    assert client.feature_code == FIRST
    token = client.enable_channel99(123456)
    assert token["feature_code"] == FIRST
    assert http[0].headers["featureCode"] == FIRST
    assert parse_qs(str(http[0].body))["smsCode"] == ["123456"]


def test_two_clients_do_not_change_globals_or_each_other(
    http: list[requests.PreparedRequest],
) -> None:
    """Interleaved clients retain independent credentials and immutable profiles."""
    profiles = (dict(ANDROID_PROFILE.headers), dict(WEB_PROFILE.headers), dict(REQUEST_HEADER))
    first = EzvizClient(token=saved_token(FIRST), feature_code=FIRST)
    second = EzvizClient(token=saved_token(SECOND), feature_code=SECOND)
    first.login()
    second.login()
    first.close_session()
    first.login()
    assert [request.headers["featureCode"] for request in http] == [FIRST, SECOND, FIRST]
    assert profiles == (
        dict(ANDROID_PROFILE.headers),
        dict(WEB_PROFILE.headers),
        dict(REQUEST_HEADER),
    )
    assert first.feature_code == FIRST
    assert second.feature_code == SECOND
    legacy = EzvizClient()
    assert legacy.feature_code == FEATURE_CODE
    assert legacy.export_token().get("feature_code") is None


def test_prepared_request_gets_current_client_identity(
    http: list[requests.PreparedRequest],
) -> None:
    """A previously prepared request must not reintroduce the global host code."""
    client = EzvizClient(token=saved_token(), feature_code=FIRST)
    request = requests.Request(
        "GET",
        "https://api.example.invalid/retained",
        headers={"featureCode": SECOND, "X-Endpoint": "retained"},
    ).prepare()
    client._send_prepared(request)  # noqa: SLF001 - Exercise the prepared-request authentication boundary.
    assert http[-1].headers["featureCode"] == FIRST
    assert http[-1].headers["X-Endpoint"] == "retained"


def test_push_registration_serial_and_refresh_share_the_client_identity(
    monkeypatch: pytest.MonkeyPatch,
    http: list[requests.PreparedRequest],
) -> None:
    """Use the real cached push factory and channel attempt without a socket."""
    factories: list[Callable[..., Any]] = []

    def worker(factory: Callable[..., Any]) -> Mock:
        factories.append(factory)
        return Mock()

    monkeypatch.setattr("pyezvizapi.push.mqtt.PushWorker", worker)
    client = EzvizClient(token=saved_token(), feature_code=FIRST, on_token_updated=Mock())
    push = client.get_mqtt_client()
    push.connect()
    attempt = factories[0]()
    assert attempt.serial == f"MOBILE:ys7:user:{FIRST}".encode()
    attempt.prepare()
    assert http[-1].headers["featureCode"] == FIRST
    assert urlsplit(str(http[-1].url)).path == "/v3/push/token"
    push.stop()


def test_cas_operation_frames_keep_explicit_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    """Both cloud and local CAS framing must use the selected feature code."""
    frames: list[bytes] = []
    cas = EzvizCAS(saved_token(), feature_code=FIRST)

    def send(payload: bytes, **kwargs: Any) -> Any:
        frames.append(payload)
        raise RuntimeError("stop before IO")

    monkeypatch.setattr(cas, "_send_cas_payload", send)
    monkeypatch.setattr(cas, "_cloud_address", lambda: ("cas.example.invalid", 443))
    with pytest.raises(RuntimeError, match="stop before IO"):
        cas.cas_get_encryption("SYNTHETIC")
    with pytest.raises(RuntimeError, match="stop before IO"):
        cas.probe_local_operation_code("SYNTHETIC", host="192.0.2.1", port=9010)
    assert len(frames) == 2
    assert all(f"<Sign>{FIRST}</Sign>".encode() in frame for frame in frames)


def test_changed_mac_in_fresh_process_can_restore_persisted_identity(tmp_path: Path) -> None:
    """A new interpreter/host code cannot invalidate an explicitly restored ID."""
    path = tmp_path / "token.json"
    script = """
import json, sys, uuid
from pathlib import Path
uuid.getnode = lambda: int(sys.argv[1])
from pyezvizapi.client import EzvizClient
from pyezvizapi.constants import FEATURE_CODE, PROFILE
from pyezvizapi.cloud.token_store import save_private_token
from pyezvizapi.exceptions import EzvizAuthTokenExpired
path = Path(sys.argv[2])
if not path.exists():
    code = EzvizClient().feature_code
    save_private_token(str(path), {"api_url":"api.example.invalid", "username":"internal",
        "user_id":"user", "session_id":"session", "rf_session_id":"refresh",
        "push_profile":PROFILE, "feature_code":code, "push_state":{"counter":7},
        "service_urls":{"pushDasDomain":"push.example.invalid"}})
else:
    token = json.loads(path.read_text())
    try:
        EzvizClient(token=token)
    except EzvizAuthTokenExpired:
        pass
    else:
        raise AssertionError("default host validation must still reject a changed MAC")
    restored = EzvizClient(token=token, feature_code=token["feature_code"])
    assert restored.feature_code != FEATURE_CODE
    assert restored.export_token() == json.loads(path.read_text())
print(json.dumps({"host": FEATURE_CODE, "saved": json.loads(path.read_text())["feature_code"]}))
"""
    env = dict(os.environ)

    def run(mac: int) -> dict[str, str]:
        return json.loads(
            subprocess.check_output(
                [sys.executable, "-c", script, str(mac), str(path)], env=env, text=True
            )
        )

    first = run(0x001122334455)
    content = path.read_bytes()
    second = run(0xAABBCCDDEEFF)
    assert first["host"] != second["host"]
    assert first["saved"] == second["saved"]
    assert path.read_bytes() == content


def test_push_refresh_does_not_fall_back_to_host_identity(
    monkeypatch: pytest.MonkeyPatch,
    http: list[requests.PreparedRequest],
) -> None:
    """A rejected registration must rotate under the same persisted identity."""
    factories: list[Callable[..., Any]] = []

    def worker(factory: Callable[..., Any]) -> Mock:
        factories.append(factory)
        return Mock()

    monkeypatch.setattr("pyezvizapi.push.mqtt.PushWorker", worker)
    original = requests.Session.send
    registrations: list[dict[str, Any]] = []

    def send(
        session: requests.Session, request: requests.PreparedRequest, **kwargs: Any
    ) -> requests.Response:
        if urlsplit(str(request.url)).path == "/v3/push/token":
            registrations.append(dict(request.headers))
            if len(registrations) == 1:
                response = requests.Response()
                response.status_code = 401
                return response
        return original(session, request, **kwargs)

    monkeypatch.setattr(requests.Session, "send", send)
    persisted: list[dict[str, Any]] = []
    client = EzvizClient(token=saved_token(), feature_code=FIRST, on_token_updated=persisted.append)
    push = client.get_mqtt_client()
    push.connect()
    attempt = factories[0]()
    attempt.prepare()
    assert [item["featureCode"] for item in registrations] == [FIRST, FIRST]
    assert [item["sessionId"] for item in registrations] == ["session", "rotated"]
    refresh = next(
        request for request in http if urlsplit(str(request.url)).path != "/v3/push/token"
    )
    assert parse_qs(str(refresh.body))["featureCode"] == [FIRST]
    assert attempt.credentials_input() == "rotated"
    assert persisted and all(record["feature_code"] == FIRST for record in persisted)
    assert client.export_token()["push_state"] == {"counter": 7}
    push.stop()


def test_stale_push_attempt_cannot_cross_identity_boundary(monkeypatch: pytest.MonkeyPatch) -> None:
    """Do not reuse or save an attempt after shared credentials change identity."""
    factories: list[Callable[..., Any]] = []

    def worker(factory: Callable[..., Any]) -> Mock:
        factories.append(factory)
        return Mock()

    monkeypatch.setattr("pyezvizapi.push.mqtt.PushWorker", worker)
    token = saved_token()
    saved = Mock()
    client = EzvizClient(token=token, feature_code=FIRST, on_token_updated=saved)
    push = client.get_mqtt_client()
    push.connect()
    attempt = factories[0]()
    token["feature_code"] = SECOND
    assert attempt.is_current() is False
    with pytest.raises(PyEzvizError, match="credentials changed"):
        attempt.save({"counter": 99})
    with pytest.raises(EzvizAuthTokenExpired):
        factories[0]()
    saved.assert_not_called()
    assert token["push_state"] == {"counter": 7}
    assert token["feature_code"] == SECOND
    push.stop()


@pytest.mark.parametrize("operation", ["key", "encryption", "lock", "unlock"])
def test_identity_bound_device_payloads_never_use_global_identity(
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    """Inspect command serialization only; no device operation is dispatched."""
    client = EzvizClient(token=saved_token(), feature_code=FIRST)
    captured = Mock(side_effect=RuntimeError("stop before IO"))
    monkeypatch.setattr(client, "_request_json", captured)
    with pytest.raises(RuntimeError, match="stop before IO"):
        if operation == "key":
            client.get_cam_key("SYNTHETIC")
        elif operation == "encryption":
            client.set_video_enc("SYNTHETIC")
        elif operation == "lock":
            client.remote_lock("SYNTHETIC", "user", 1)
        else:
            client.remote_unlock("SYNTHETIC", "user", 1, use_terminal_bind=False)
    kwargs = captured.call_args.kwargs
    if operation in ("key", "encryption"):
        assert kwargs["data"]["featureCode"] == FIRST
    else:
        assert kwargs["json_body"]["unLockInfo"]["bindCode"] == f"{FIRST}user"


def test_client_cas_factory_receives_only_opted_in_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The compatibility CAS hook keeps its default shape and forwards explicit IDs."""
    hook = Mock()
    monkeypatch.setattr("pyezvizapi.client.EzvizCAS", hook)
    legacy = EzvizClient(token={"api_url": "api.example.invalid"})
    legacy.set_camera_defence_old("SYNTHETIC", 1)
    assert hook.call_args.kwargs == {}
    explicit = EzvizClient(token=saved_token(), feature_code=FIRST)
    explicit.set_camera_defence_old("SYNTHETIC", 1)
    assert hook.call_args.kwargs == {"feature_code": FIRST}
