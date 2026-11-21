"""One-attempt auxiliary authentication boundaries; no external HTTP."""
# ruff: noqa: SLF001 -- explicit state/response ownership regressions.

from copy import deepcopy
from dataclasses import FrozenInstanceError
import json
from threading import Event, Thread
import time
import traceback

import pytest
import requests

from pyezvizapi.client import EzvizClient
from pyezvizapi.cloud.challenges import _CaptchaContext, _CaptchaPurpose
from pyezvizapi.cloud.login import _MfaChannelPolicy
from pyezvizapi.constants import ANDROID_PROFILE
from pyezvizapi.exceptions import EzvizAuthTokenExpired, HTTPError, PyEzvizError

PNG = b"\x89PNG\r\n\x1a\nimage"
REGION = "region.example.test"


@pytest.fixture
def auxiliary_wire(monkeypatch):
    clients = []

    def make(payload, *, status=200, timeout=1):
        client = EzvizClient("synthetic-account", "synthetic-password", url=REGION, timeout=timeout)
        clients.append(client)
        calls, closed = [], []
        response = requests.Response()
        response.status_code = status
        response._content = (
            payload
            if isinstance(payload, bytes)
            else (b"" if isinstance(payload, Exception) else json.dumps(payload).encode())
        )
        response.__dict__["_content_consumed"] = True
        response.url = "https://region.example.test/private-marker"
        monkeypatch.setattr(response, "close", lambda: closed.append(True))

        def send(_session, request, **options):
            calls.append(request)
            assert options["allow_redirects"] is False
            assert 0 < options["timeout"].total <= timeout
            if isinstance(payload, Exception):
                raise payload
            return response

        monkeypatch.setattr(requests.Session, "send", send)
        return client, calls, closed

    yield make
    for client in clients:
        client._session.close()


def invoke(client, purpose):
    if purpose == "discovery":
        return client.get_mfa_channels("27")
    if purpose == "captcha":
        return client.get_captcha()
    return client.send_mfa_code()


def success(purpose):
    if purpose == "captcha":
        return PNG
    return {"meta": {"code": 200}, "data": {"TERMINAL_BIND": []}}


@pytest.mark.parametrize("purpose", ["discovery", "captcha", "delivery"])
@pytest.mark.parametrize(
    "outcome", ["success", "bad_body", "http_error", "redirect", "timeout", "connection", "request"]
)
def test_auxiliary_requests_close_redact_and_never_retry(auxiliary_wire, purpose, outcome):
    payload = success(purpose)
    status = 200
    expected: type[Exception] = PyEzvizError
    if outcome == "bad_body":
        payload = b"private-marker"
    elif outcome in ("http_error", "redirect"):
        status = 503 if outcome == "http_error" else 307
    elif outcome in ("timeout", "connection", "request"):
        category = {
            "timeout": requests.Timeout,
            "connection": requests.ConnectionError,
            "request": requests.RequestException,
        }[outcome]
        payload = category("https://region.example.test/private-marker")
        expected = category if purpose != "captcha" and outcome != "request" else HTTPError
    client, calls, closed = auxiliary_wire(payload, status=status)
    if outcome == "success":
        invoke(client, purpose)
    else:
        with pytest.raises(expected) as caught:
            invoke(client, purpose)
        assert "private-marker" not in "".join(traceback.format_exception(caught.value))
        assert not client._login_verification.sent
        assert client._captcha_state.challenge is None
    assert len(calls) == 1
    assert closed == ([] if isinstance(payload, Exception) else [True])


@pytest.mark.parametrize("purpose", ["discovery", "captcha", "delivery"])
def test_operation_deadline_includes_token_lock_without_transport(auxiliary_wire, purpose):
    client, calls, closed = auxiliary_wire(success(purpose), timeout=0.05)
    acquired, release = Event(), Event()

    def owner():
        with client._token_lock:
            acquired.set()
            release.wait(2)

    thread = Thread(target=owner, daemon=True)
    thread.start()
    assert acquired.wait(1)
    try:
        with pytest.raises(TimeoutError, match="token lock"):
            invoke(client, purpose)
        assert not calls and not closed
    finally:
        release.set()
        thread.join(timeout=1)
    assert not thread.is_alive()


@pytest.mark.parametrize("purpose", ["discovery", "delivery"])
def test_parsing_cannot_extend_deadline_or_commit_success(auxiliary_wire, monkeypatch, purpose):
    client, calls, closed = auxiliary_wire(success(purpose), timeout=0.05)
    original = client._parse_json

    def slow_parse(response):
        result = original(response)
        time.sleep(0.08)
        return result

    monkeypatch.setattr(client, "_parse_json", slow_parse)
    with pytest.raises(TimeoutError, match="deadline"):
        invoke(client, purpose)
    assert len(calls) == 1 and closed == [True]
    assert not client._login_verification.sent
    assert client._mfa_channel_policy == _MfaChannelPolicy()


def test_policy_is_immutable_and_independent_of_contact_reset(auxiliary_wire):
    client, calls, _ = auxiliary_wire(
        {
            "meta": {"code": 200},
            "data": {"TERMINAL_BIND": [{"channel": 6, "title": "WhatsApp", "order": 0}]},
        }
    )
    client.get_mfa_channels("27")
    policy = client._mfa_channel_policy
    with pytest.raises(FrozenInstanceError):
        policy.region = "another.example.test"
    state = client._login_verification
    state.update({"contactExt": {"phone": "+27000000000"}})
    state.select(6, None, policy=policy, region=REGION)
    state.mark_sent("+27000000000")
    state.update({"contactExt": {"email": "bound@example.test"}})
    assert client._mfa_channel_policy is policy
    assert state.sent and not state.code_sent(client.account)
    assert state.available_channels(REGION, policy) == (3,)
    assert len(calls) == 1


@pytest.mark.parametrize("method", ["login", "enable_channel99"])
@pytest.mark.parametrize("with_image", [False, True])
def test_shared_preflight_rejects_wrong_region_retained_policy_without_mutation(
    auxiliary_wire, method, with_image
):
    client, calls, _ = auxiliary_wire(PNG)
    client._mfa_channel_policy = _MfaChannelPolicy((1, 3, 6), REGION)
    client._select_mfa(6, "+27000000000")
    image = client.get_captcha() if with_image else None
    client._token["api_url"] = "other.example.test"
    before = (
        deepcopy(client._token),
        deepcopy(client._login_verification),
        dict(client._session.headers),
    )
    with pytest.raises(PyEzvizError, match="Discover verification"):
        getattr(client, method)(captcha=image, captcha_code="aB01" if image else None)
    assert len(calls) == int(with_image)
    assert before == (client._token, client._login_verification, dict(client._session.headers))


@pytest.mark.parametrize("method", ["login", "enable_channel99"])
@pytest.mark.parametrize("mutation", ["missing", "different"])
def test_shared_preflight_token_identity_without_image(auxiliary_wire, method, mutation):
    client, calls, _ = auxiliary_wire(PNG)
    client._token.update(
        session_id="old",
        rf_session_id="refresh",
        push_profile=ANDROID_PROFILE.name,
        feature_code=client.feature_code,
    )
    if mutation == "missing":
        client._token.pop("feature_code")
    else:
        client._token["feature_code"] = "2" * 32
    before = deepcopy(client._token), dict(client._session.headers)
    with pytest.raises(EzvizAuthTokenExpired):
        getattr(client, method)()
    assert not calls
    assert before == (client._token, dict(client._session.headers))


def test_typed_context_distinguishes_purpose_and_hides_identity():
    login = _CaptchaContext(REGION, "private-marker", "private-marker", _CaptchaPurpose.LOGIN)
    delivery = _CaptchaContext(
        REGION, "private-marker", "private-marker", _CaptchaPurpose.MFA_DELIVERY, 3
    )
    assert login != delivery
    assert "private-marker" not in repr(login) + repr(delivery)


def test_offline_guard_blocks_lost_instance_mock():
    with (
        requests.Session() as session,
        pytest.raises(AssertionError, match="Unmocked non-loopback"),
    ):
        session.get("https://unmocked.invalid")


def test_captcha_processing_timeout_discards_new_handle(auxiliary_wire, monkeypatch):
    client, calls, closed = auxiliary_wire(PNG, timeout=0.05)
    issue = client._captcha_state.issue

    def slow_issue(image, context):
        handle = issue(image, context)
        time.sleep(0.08)
        return handle

    monkeypatch.setattr(client._captcha_state, "issue", slow_issue)
    with pytest.raises(TimeoutError, match="deadline"):
        client.get_captcha()
    assert len(calls) == 1 and closed == [True]
    assert client._captcha_state.challenge is None
