"""Exercise actual key fetch, RSA envelopes and MFA wire states; no EZVIZ access."""

from __future__ import annotations

import base64
from hashlib import md5
import json
from urllib.parse import parse_qs

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
import pytest
import requests

from pyezvizapi.client import EzvizClient
from pyezvizapi.cloud import auth
from pyezvizapi.cloud.login import LoginVerification
from pyezvizapi.constants import ANDROID_PROFILE
from pyezvizapi.exceptions import (
    EzvizAuthVerificationCode,
    EzvizLoginError,
    PyEzvizError,
)
from tests.conftest import LOGIN_PUBLIC_KEY, decrypt_login_password

OK = {
    "meta": {"code": 200},
    "loginSession": {"sessionId": "synthetic-session", "rfSessionId": "synthetic-refresh"},
    "loginUser": {"username": "synthetic-user", "userId": "synthetic-id"},
    "loginArea": {"apiDomain": "region.example.test"},
}


def response(payload, status=200):
    result = requests.Response()
    result.status_code = status
    result._content = json.dumps(payload).encode()  # noqa: SLF001
    result.__dict__["_content_consumed"] = True
    return result


@pytest.fixture
def wire(monkeypatch):
    """Replace only the HTTP adapter boundary; restore the real public-key helper."""
    monkeypatch.setattr("pyezvizapi.client.fetch_login_public_key", auth.fetch_login_public_key)
    clients = []

    def create(results, *, keys=None, **kwargs):
        client = EzvizClient("synthetic-account", "synthetic-password", url="region.example.test", **kwargs)
        clients.append(client)
        calls = []
        pending = iter(results)
        key_results = iter(keys) if keys is not None else None

        def send(request, **options):
            calls.append(request)
            assert options["allow_redirects"] is False
            assert (options["timeout"].total if hasattr(options["timeout"], "total") else options["timeout"]) > 0
            if request.method == "GET" and request.url.endswith("/publickey"):
                item = next(key_results) if key_results is not None else {"meta": {"code": 200}, "publicKey": LOGIN_PUBLIC_KEY}
            elif request.method in ("POST", "PUT"):
                item = next(pending)
            else:
                pytest.fail(f"Unexpected request: {request.method}")
            if isinstance(item, Exception):
                raise item
            result = item if isinstance(item, requests.Response) else response(item)
            result.request = request
            result.url = request.url
            return result

        monkeypatch.setattr(requests.Session, "send", lambda _session, request, **options: send(request, **options))
        monkeypatch.setattr(client, "get_service_urls", lambda: {})
        return client, calls

    yield create
    for client in clients:
        client._session.close()  # noqa: SLF001


def posts(calls):
    return [parse_qs(call.body, keep_blank_values=True) for call in calls if call.method == "POST"]


@pytest.mark.parametrize("failure", [
    requests.Timeout("offline"), requests.ConnectionError("offline"),
    response({}, 503), response({}, 404), {"meta": {"code": 500}},
    {"meta": {"code": 200}, "publicKey": "not a key"},
])
def test_key_failure_never_submits_legacy_credentials(wire, failure):
    client, calls = wire([], keys=[failure])
    with pytest.raises((requests.RequestException, PyEzvizError)):
        client.login()
    assert len(calls) == 1 and calls[0].method == "GET"
    assert client.export_token()["session_id"] is None


def test_bad_key_json_never_submits_password(wire):
    invalid = response({})
    invalid._content = b"private-payload-not-json"  # noqa: SLF001
    client, calls = wire([], keys=[invalid])
    with pytest.raises(PyEzvizError, match="invalid JSON") as exc:
        client.login()
    assert "private-payload" not in str(exc.value)
    assert len(calls) == 1


@pytest.mark.parametrize("separator", ["\r\n", " ", "\t", "\n"])
def test_key_whitespace_matches_android(wire, separator, monkeypatch):
    monkeypatch.setattr(auth.time, "time", lambda: 1795000000.9)
    wrapped = separator.join(LOGIN_PUBLIC_KEY[i:i+64] for i in range(0, len(LOGIN_PUBLIC_KEY), 64))
    client, calls = wire([OK], keys=[{"meta": {"code": 200}, "publicKey": wrapped}])
    client.login("001234")
    form = posts(calls)[0]
    assert decrypt_login_password(form["password"][0]) == f"{md5(b'synthetic-password').hexdigest()},1795000000"
    assert form["smsCode"] == ["001234"]
    assert calls[1].url.endswith("/login/v6")


def test_valid_non_rsa_key_is_rejected(wire):
    key = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    client, calls = wire([], keys=[{"meta": {"code": 200}, "publicKey": base64.b64encode(key).decode()}])
    with pytest.raises(PyEzvizError, match="not RSA"):
        client.login()
    assert len(calls) == 1


@pytest.mark.parametrize(("code", "reason"), [
    (1011, "verification_incorrect"), (1012, "verification_expired"),
    (1013, "incorrect_username"), (1014, "incorrect_password"),
    (1226, "incorrect_credentials"), (1015, "captcha_required"),
    (1069, "terminal_limit"), (1102, "region_selection_required"),
    (1407, "clock_incorrect"), (1402, "public_key_refresh_required"),
    (1400, "account_locked"), (1041, "verification_rate_limited"),
    (1043, "verification_attempts_exceeded"), (1006, "verification_rate_limited"),
    (1026, "verification_rate_limited"), (9876, "login_failed"),
])
def test_app_error_codes_are_actionable_sanitized_and_not_retried(wire, code, reason):
    client, calls = wire([{"meta": {"code": code, "message": "private-marker"}, "tempToken": "private-marker"}])
    with pytest.raises(EzvizLoginError) as caught:
        client.login("001234")
    assert caught.value.reason == reason and caught.value.code == code
    assert "private-marker" not in str(caught.value) + repr(vars(caught.value))
    assert len(calls) == 2
    assert isinstance(caught.value, EzvizAuthVerificationCode) == (code in (1011, 1012))


@pytest.mark.parametrize(("minutes", "expected"), [(15, 15), (True, None), (-1, None), (0, None), ("15", None), (1.5, None), (None, None), (2**40, None)])
def test_lock_duration_only_retains_valid_metadata(wire, minutes, expected):
    client, calls = wire([{"meta": {"code": 1400}, "lockMinutes": minutes}])
    with pytest.raises(EzvizLoginError) as caught:
        client.login()
    assert caught.value.lock_minutes == expected
    assert len(calls) == 2


@pytest.mark.parametrize("code", ["001234", "000000", 0, 123456])
@pytest.mark.parametrize("channel", [1, 3])
def test_mfa_submission_never_automatically_resends(wire, code, channel):
    client, calls = wire([{"meta": {"code": 6002}}])
    with pytest.raises(EzvizAuthVerificationCode) as caught:
        client.login(code, mfa_channel=channel)
    assert not caught.value.code_sent
    assert len(calls) == 2
    assert posts(calls)[0]["smsCode"] == [str(code)]
    assert posts(calls)[0]["msgType"] == [str(channel)]
    assert posts(calls)[0]["bizType"] == ["TERMINAL_BIND"]


@pytest.mark.parametrize("code", ["", "   ", "12x", "\uff11\uff12\uff13\uff14\uff15\uff16", True, -1, 1.5])
def test_invalid_input_stops_before_any_request(wire, code):
    client, calls = wire([])
    with pytest.raises(PyEzvizError, match="ASCII"):
        client.login(code)
    assert not calls


@pytest.mark.parametrize("channel", [0, 2, 4, 5, 6, 7, True, "1"])
def test_unimplemented_channels_are_not_silently_mapped(wire, channel):
    client, calls = wire([])
    with pytest.raises(PyEzvizError, match="channel"):
        client.login("123456", mfa_channel=channel)
    assert not calls


@pytest.mark.parametrize("channel", [1, 3])
@pytest.mark.parametrize("field", ["loginUser", "contactExt"])
def test_request_uses_selected_server_contact_then_preserves_channel(wire, channel, field):
    info = {"email": "bound@example.test", "phone": "+27000000000"}
    client, calls = wire([{"meta": {"code": 6002}, field: info}, {"meta": {"code": 200}}, OK])
    with pytest.raises(EzvizAuthVerificationCode) as caught:
        client.login(mfa_channel=channel)
    assert caught.value.code_sent and caught.value.available_channels == (1, 3)
    assert posts(calls)[1] == {"from": [info["phone" if channel == 1 else "email"]], "bizType": ["TERMINAL_BIND"], "msgType": [str(channel)], "imageCode": [""]}
    assert calls[2].url.endswith("/users/checkcode/mt/unlogin/v5")
    assert info["phone"] not in repr(caught.value) + repr(vars(caught.value))
    assert "bound@example.test" not in json.dumps(client.export_token())
    client.login("000000")
    assert posts(calls)[2]["msgType"] == [str(channel)]
    assert posts(calls)[2]["smsCode"] == ["000000"]
    assert client._login_verification.contacts == {}  # noqa: SLF001


def test_challenge_request_submit_and_explicit_resend_are_distinct(wire):
    challenge = {"meta": {"code": 6002}, "loginUser": {"email": "bound@example.test"}}
    client, calls = wire([challenge, {"meta": {"code": 200}}, challenge, challenge, {"meta": {"code": 200}}])
    with pytest.raises(EzvizAuthVerificationCode) as caught:
        client.login(request_mfa=False)
    assert not caught.value.code_sent and len(calls) == 2
    client.send_mfa_code()
    with pytest.raises(EzvizAuthVerificationCode):
        client.login("001234")
    with pytest.raises(EzvizAuthVerificationCode):
        client.login()
    assert len(posts(calls)) == 4  # three logins, one code request
    client.send_mfa_code()  # only explicit resend causes another request
    assert len(posts(calls)) == 5


@pytest.mark.parametrize("info", [{"phone": "+27000000000"}, {"email": "a***@example.test"}, {}, None, "bad-data"])
def test_missing_selected_contact_never_uses_unrelated_login_account(wire, info):
    client, calls = wire([{"meta": {"code": 6002}, "loginUser": info}])
    with pytest.raises(EzvizAuthVerificationCode) as caught:
        client.login()
    assert not caught.value.code_sent
    assert len(calls) == 2


def test_security_contact_flow_requires_app_not_legacy_sms_endpoint(wire):
    client, calls = wire([{"meta": {"code": 6002}, "contactExt": {"fuzzyEmail": "b***@example.test", "accessToken": "private-marker", "isSecurityBind": True}}])
    with pytest.raises(EzvizAuthVerificationCode) as caught:
        client.login()
    assert caught.value.reason == "security_verification_required"
    with pytest.raises(EzvizAuthVerificationCode):
        client.send_mfa_code(mfa_account="explicit@example.test")
    assert len(calls) == 2
    assert "private-marker" not in repr(vars(caught.value)) + json.dumps(client.export_token())


@pytest.mark.parametrize("code", [1041, 1043, 1006, 1026])
def test_send_failure_retains_rate_limit_category_and_does_not_retry(wire, code):
    client, calls = wire([{"meta": {"code": code}}])
    with pytest.raises(EzvizLoginError) as caught:
        client.send_mfa_code()
    assert caught.value.code == code and len(calls) == 1
    assert not client._login_verification.sent  # noqa: SLF001


def test_explicit_sms_contact_does_not_change_login_account(wire):
    client, calls = wire([{"meta": {"code": 6002}}, {"meta": {"code": 200}}, OK])
    with pytest.raises(EzvizAuthVerificationCode):
        client.login(mfa_channel=1, mfa_account="+27000000000")
    assert posts(calls)[1]["from"] == ["+27000000000"]
    client.login("001234")
    assert posts(calls)[2]["account"] == ["synthetic-account"]
    assert posts(calls)[2]["msgType"] == ["1"]


def test_region_redirect_encrypts_with_new_region_key_and_keeps_mfa(wire):
    second = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = base64.b64encode(second.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
    client, calls = wire([
        {"meta": {"code": 1100}, "loginArea": {"apiDomain": "other.example.test"}}, OK,
    ], keys=[{"meta": {"code": 200}, "publicKey": LOGIN_PUBLIC_KEY}, {"meta": {"code": 200}, "publicKey": public}])
    client.login("001234", mfa_channel=1, request_mfa=False)
    forms = posts(calls)
    assert calls[2].url == "https://other.example.test/v3/users/publickey"
    assert decrypt_login_password(forms[0]["password"][0]).startswith(md5(b"synthetic-password").hexdigest() + ",")
    assert second.decrypt(base64.b64decode(forms[1]["password"][0]), padding.PKCS1v15()).decode().startswith(md5(b"synthetic-password").hexdigest() + ",")
    assert all(form["smsCode"] == ["001234"] and form["msgType"] == ["1"] for form in forms)


def test_region_loop_has_finite_request_bound(wire):
    client, calls = wire([{"meta": {"code": 1100}, "loginArea": {"apiDomain": "region.example.test"}}] * 3)
    with pytest.raises(EzvizLoginError, match="redirect limit"):
        client.login()
    assert len(calls) == 6


@pytest.mark.parametrize("migrate", [False, True])
def test_refresh_and_channel99_keep_code_channel_and_request_policy(wire, migrate):
    token = {"session_id": "old", "rf_session_id": "old-refresh", "api_url": "region.example.test"}
    if migrate:
        client, calls = wire([OK], token=token)
        client.enable_channel99("001234", mfa_channel=1, request_mfa=False)
    else:
        client, calls = wire([{"meta": {"code": 403}}, OK], token=token)
        client.login("001234", mfa_channel=1, request_mfa=False)
        assert calls[0].method == "PUT"
    form = posts(calls)[0]
    assert form["smsCode"] == ["001234"] and form["msgType"] == ["1"]
    if migrate:
        assert all(form[key] == [value] for key, value in ANDROID_PROFILE.registration.items())
        assert client.export_token()["push_profile"] == "android-channel99"


def test_key_rejection_requires_explicit_retry_and_fetches_fresh_key(wire):
    client, calls = wire([{"meta": {"code": 1402}}, OK])
    with pytest.raises(EzvizLoginError):
        client.login()
    assert len(calls) == 2
    client.login()
    assert len(calls) == 4 and calls[2].url.endswith("/publickey")


def test_mfa_state_repr_does_not_expose_recipients():
    state = LoginVerification(contacts={1: "+27000000000"}, recipient="private@example.test")
    assert "+270" not in repr(state) and "private@" not in repr(state)


@pytest.mark.parametrize("migrate", [False, True])
def test_suppressed_initial_request_survives_refresh_or_profile_migration(wire, migrate):
    token = {"session_id": "old", "rf_session_id": "old-refresh", "api_url": "region.example.test"}
    responses = [{"meta": {"code": 6002}}]
    if not migrate:
        responses.insert(0, {"meta": {"code": 403}})
    client, calls = wire(responses, token=token)
    with pytest.raises(EzvizAuthVerificationCode) as caught:
        if migrate:
            client.enable_channel99(mfa_channel=1, mfa_account="+27000000000", request_mfa=False)
        else:
            client.login(mfa_channel=1, mfa_account="+27000000000", request_mfa=False)
    assert not caught.value.code_sent
    assert len(posts(calls)) == 1


@pytest.mark.parametrize("status", [307, 401, 503])
def test_explicit_mfa_request_does_not_redirect_relogin_or_retry(wire, status):
    reply = response({"meta": {"code": status}}, status=status)
    reply.headers["Location"] = "https://other.example.test/code"
    client, calls = wire([reply])
    with pytest.raises(PyEzvizError):
        client.send_mfa_code()
    assert len(calls) == 1 and calls[0].url.endswith("/sms/nologin/checkcode")


def test_explicit_legacy_api_uses_no_key_fetch_or_hidden_fallback(wire):
    client, calls = wire([{"meta": {"code": 1226}}], login_api="v5")
    with pytest.raises(EzvizLoginError) as caught:
        client.login("001234", mfa_channel=1)
    assert caught.value.reason == "incorrect_credentials"
    assert len(calls) == 1 and calls[0].url.endswith("/login/v5")
    assert posts(calls)[0]["password"] == [md5(b"synthetic-password").hexdigest()]
    assert posts(calls)[0]["smsCode"] == ["001234"]


@pytest.mark.parametrize("channel, recipient", [(1, ""), (1, "   "), (1, False), (1, 123), (True, "other@example.test"), (2, "other@example.test")])
def test_invalid_selection_is_atomic_including_successful_request(channel, recipient):
    from copy import deepcopy  # noqa: PLC0415

    state = LoginVerification(recipient="bound@example.test", contacts={3: "bound@example.test"}, metadata_present=True)
    state.mark_sent("bound@example.test")
    before = deepcopy(state)
    with pytest.raises(PyEzvizError):
        state.select(channel, recipient)
    assert state == before
    assert state.sent and state.code_sent("synthetic-account")


def test_unchanged_selection_preserves_request_and_explicit_change_clears_it():
    state = LoginVerification(recipient="bound@example.test")
    state.mark_sent("bound@example.test")
    state.select(3, "bound@example.test")
    assert state.sent and state.code_sent(None)
    state.select(1, "+27000000000")
    assert state.destination(None) == "+27000000000"
    assert not state.sent and not state.code_sent(None)


@pytest.mark.parametrize("changed", [{"email": "other@example.test"}, {"phone": "+27000000000"}, {"email": "a***@example.test"}, {"accessToken": "private-marker", "isSecurityBind": True}])
def test_changed_contact_never_reports_stale_delivery_or_automatically_resends(wire, changed):
    client, calls = wire([
        {"meta": {"code": 6002}, "loginUser": {"email": "bound@example.test"}},
        {"meta": {"code": 200}},
        {"meta": {"code": 6002}, "loginUser": changed},
    ])
    with pytest.raises(EzvizAuthVerificationCode) as first:
        client.login()
    assert first.value.code_sent
    with pytest.raises(EzvizAuthVerificationCode) as second:
        client.login()
    assert not second.value.code_sent
    assert len(calls) == 5  # two key/login pairs and only the original delivery request
    assert client._login_verification.sent  # noqa: SLF001 - Guard remains against automatic resend.


def test_explicit_resend_updates_delivery_diagnostics_for_current_contact(wire):
    client, calls = wire([
        {"meta": {"code": 6002}, "loginUser": {"email": "bound@example.test"}},
        {"meta": {"code": 200}},
        {"meta": {"code": 6002}, "loginUser": {"email": "other@example.test"}},
        {"meta": {"code": 200}},
    ])
    with pytest.raises(EzvizAuthVerificationCode):
        client.login()
    with pytest.raises(EzvizAuthVerificationCode) as changed:
        client.login()
    assert not changed.value.code_sent
    client.send_mfa_code()
    assert client._login_verification.code_sent(client.account)  # noqa: SLF001
    assert posts(calls)[-1]["from"] == ["other@example.test"]
    assert "other@example.test" not in repr(client._login_verification)  # noqa: SLF001


@pytest.mark.parametrize("code", [6002, 1011, 1012, 1407, 9876])
def test_error_classification_has_no_io_or_state_mutation(wire, monkeypatch, code):
    from copy import deepcopy  # noqa: PLC0415

    client, calls = wire([])
    state = client._login_verification  # noqa: SLF001
    state.update({"loginUser": {"email": "bound@example.test"}})
    state.mark_sent("bound@example.test")
    before = deepcopy(state)
    token = client.export_token()
    monkeypatch.setattr(client, "send_mfa_code", lambda **kw: pytest.fail("classification must not send"))
    result = {"meta": {"code": code}, "loginUser": {"phone": "+27000000000"}}
    for _ in range(2):
        error = client._login_error(result)  # noqa: SLF001
        assert error.code == code
    assert state == before and client.export_token() == token
    assert not calls
    if code in (6002, 1011, 1012):
        assert error.code_sent and error.available_channels == (3,)


def test_two_regional_hops_keep_code_and_refetch_each_key(wire):
    client, calls = wire([
        {"meta": {"code": 1100}, "loginArea": {"apiDomain": "second.example.test"}},
        {"meta": {"code": 1100}, "loginArea": {"apiDomain": "third.example.test"}}, OK,
    ])
    client.login("000000", mfa_channel=1, request_mfa=False)
    assert [call.url.split('/')[2] for call in calls] == ["region.example.test"] * 2 + ["second.example.test"] * 2 + ["third.example.test"] * 2
    assert all(form["smsCode"] == ["000000"] and form["msgType"] == ["1"] for form in posts(calls))
    assert len({form["password"][0] for form in posts(calls)}) == 3  # fresh randomized encryption


@pytest.mark.parametrize("failure", [requests.Timeout("offline"), {"meta": {"code": 200}, "publicKey": "bad-key"}])
def test_second_region_key_failure_never_resubmits_credentials(wire, failure):
    client, calls = wire([
        {"meta": {"code": 1100}, "loginArea": {"apiDomain": "second.example.test"}},
    ], keys=[{"meta": {"code": 200}, "publicKey": LOGIN_PUBLIC_KEY}, failure])
    with pytest.raises((PyEzvizError, requests.Timeout)):
        client.login("001234", mfa_channel=1)
    assert len(calls) == 3 and len(posts(calls)) == 1


@pytest.mark.parametrize("field, token_field", [("contactExt", "accessToken"), ("loginUser", "verifyAccessToken")])
@pytest.mark.parametrize("channel, contact", [(1, {"phone": "+27000000000"}), (3, {"email": "bound@example.test"})])
@pytest.mark.parametrize("security", [{"isSecurityBind": True}, {"token": True}, {"isSecurityBind": True, "token": True}])
def test_security_alternatives_do_not_disable_reported_contacts(wire, field, token_field, channel, contact, security):
    info = {**contact, **security}
    if info.pop("token", False):
        info[token_field] = "private-marker"
    client, calls = wire([
        {"meta": {"code": 6002}, field: info},
        {"meta": {"code": 200}, "smsToken": "private-marker"},
        OK,
    ])
    with pytest.raises(EzvizAuthVerificationCode) as caught:
        client.login(mfa_channel=channel)
    assert caught.value.reason == "verification_required"
    assert caught.value.code_sent and caught.value.available_channels == (channel,)
    assert calls[2].url.endswith("/users/checkcode/mt/unlogin/v5")
    assert posts(calls)[1] == {
        "from": [next(iter(contact.values()))], "bizType": ["TERMINAL_BIND"],
        "msgType": [str(channel)], "imageCode": [""],
    }
    assert "private-marker" not in repr(vars(caught.value)) + repr(client._login_verification) + json.dumps(client.export_token())  # noqa: SLF001
    assert not any("private-marker" in str(form) for form in posts(calls))
    client.login("001234")
    assert posts(calls)[2]["smsCode"] == ["001234"]
    assert posts(calls)[2]["msgType"] == [str(channel)]
    assert client._login_verification.contacts == {}  # noqa: SLF001


@pytest.mark.parametrize("info", [
    {"accessToken": "private-marker"}, {"isSecurityBind": True},
    {"verifyAccessToken": "private-marker", "email": "b***@example.test"},
])
def test_token_only_challenge_cannot_be_bypassed_with_explicit_contact(wire, info):
    client, calls = wire([{"meta": {"code": 6002}, "contactExt": info}])
    with pytest.raises(EzvizAuthVerificationCode) as caught:
        client.login(mfa_account="explicit@example.test")
    assert caught.value.reason == "security_verification_required"
    assert not caught.value.code_sent and not caught.value.available_channels
    with pytest.raises(EzvizAuthVerificationCode):
        client.send_mfa_code()
    assert len(calls) == 2


@pytest.mark.parametrize("code", [1101, 1141, 1041, 1043, 1011, 1012, 9876])
def test_channel_request_errors_stop_before_prompt_or_credential_resubmission(wire, monkeypatch, code):
    from pyezvizapi.cli.auth import login_with_verification  # noqa: PLC0415

    client, calls = wire([
        {"meta": {"code": 6002}, "contactExt": {"email": "bound@example.test", "accessToken": "private-marker"}},
        {"meta": {"code": code, "message": "private-marker"}, "smsToken": "private-marker"},
    ])
    monkeypatch.setattr("builtins.input", lambda _: pytest.fail("No accepted delivery request"))
    with pytest.raises(PyEzvizError) as caught:
        login_with_verification(client.login, mfa_channel="email")
    if code in (1101, 1141):
        assert isinstance(caught.value, EzvizLoginError)
        assert caught.value.reason == "captcha_required"
    assert "private-marker" not in str(caught.value) + repr(vars(caught.value))
    assert len(calls) == 3
    assert not client._login_verification.sent  # noqa: SLF001


@pytest.mark.parametrize("failure", [requests.Timeout("offline"), response({}, 401), response({}, 503), response({}, 307)])
def test_channel_delivery_transport_failure_never_retries_or_falls_back(wire, failure):
    client, calls = wire([
        {"meta": {"code": 6002}, "contactExt": {"email": "bound@example.test", "isSecurityBind": True}}, failure,
    ])
    with pytest.raises((PyEzvizError, requests.RequestException)):
        client.login()
    assert len(calls) == 3 and calls[-1].url.endswith("/users/checkcode/mt/unlogin/v5")
    assert not client._login_verification.sent  # noqa: SLF001


def test_cli_real_client_security_alternatives_request_and_submit_once(wire, monkeypatch):
    from pyezvizapi.cli.auth import login_with_verification  # noqa: PLC0415

    client, calls = wire([
        {"meta": {"code": 6002}, "contactExt": {"email": "bound@example.test", "accessToken": "private-marker", "isSecurityBind": True}},
        {"meta": {"code": 200}}, OK,
    ])
    prompts = []
    def enter_code(prompt):
        prompts.append(prompt)
        return "000000"
    monkeypatch.setattr("builtins.input", enter_code)
    login_with_verification(client.login, mfa_channel="email")
    assert len(prompts) == 1 and len(calls) == 5
    assert posts(calls)[2]["smsCode"] == ["000000"]
    assert len([call for call in calls if call.url.endswith("/checkcode/mt/unlogin/v5")]) == 1


def test_unsupported_selected_channel_does_not_switch_to_reported_phone(wire):
    client, calls = wire([{"meta": {"code": 6002}, "contactExt": {"phone": "+27000000000", "accessToken": "private-marker"}}])
    with pytest.raises(EzvizAuthVerificationCode) as caught:
        client.login(mfa_channel=3)
    assert not caught.value.code_sent and caught.value.available_channels == (1,)
    assert len(calls) == 2


def test_login_user_takes_precedence_over_contact_ext(wire):
    client, calls = wire([{
        "meta": {"code": 6002}, "loginUser": {},
        "contactExt": {"email": "unselected@example.test", "accessToken": "private-marker"},
    }])
    with pytest.raises(EzvizAuthVerificationCode) as caught:
        client.login()
    assert not caught.value.code_sent and not caught.value.available_channels
    assert len(calls) == 2
