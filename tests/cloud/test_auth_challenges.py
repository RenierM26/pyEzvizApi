"""Human CAPTCHA, channel discovery and missing-phone controls; no real network."""
# ruff: noqa: SLF001

import base64
from copy import deepcopy
import json
from urllib.parse import parse_qs

import pytest
import requests

from pyezvizapi.client import EzvizClient
from pyezvizapi.cloud.challenges import CaptchaState, _CaptchaContext, _CaptchaPurpose
from pyezvizapi.cloud.login import _MfaChannelPolicy
from pyezvizapi.constants import ANDROID_PROFILE
from pyezvizapi.exceptions import (
    EzvizAuthTokenExpired,
    EzvizAuthVerificationCode,
    EzvizLoginError,
    PyEzvizError,
)

PNG = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Y9ZQmcAAAAASUVORK5CYII=')
OK = {'meta': {'code': 200}, 'loginSession': {'sessionId': 'session', 'rfSessionId': 'refresh'}, 'loginUser': {'username': 'synthetic', 'userId': 'id'}, 'loginArea': {'apiDomain': 'region.example.test'}}
CONTACT = {'meta': {'code': 6002}, 'contactExt': {'email': 'bound@example.test', 'phone': '+27000000000'}}


@pytest.fixture
def wire(monkeypatch):
    clients = []
    def create(items, **options):
        pending = iter(items)
        calls = []
        def send(session, request, **kwargs):
            calls.append(request)
            assert kwargs['allow_redirects'] is False
            item = next(pending)
            if isinstance(item, Exception):
                raise item
            result = requests.Response()
            result.status_code = 200
            if isinstance(item, tuple):
                result.status_code, item = item
            result._content = item if isinstance(item, bytes) else json.dumps(item).encode()
            result.__dict__["_content_consumed"] = True
            result.url = request.url
            result.request = request
            return result
        monkeypatch.setattr(requests.Session, 'send', send)
        client = EzvizClient('synthetic-account', 'synthetic-password', url='region.example.test', **options)
        clients.append(client)
        monkeypatch.setattr(client, 'get_service_urls', lambda: {})
        return client, calls
    yield create
    for client in clients:
        client._session.close()


def form(call):
    return parse_qs(call.body, keep_blank_values=True)


@pytest.mark.parametrize('channel', [1, 2, 6, 7])
def test_missing_bound_phone_has_actionable_notice_without_delivery(wire, channel):
    client, calls = wire([{'meta': {'code': 6002}, 'loginUser': {'email': 'bound@example.test'}}])
    client._mfa_channel_policy = _MfaChannelPolicy((1, 2, 3, 6, 7), 'region.example.test')
    with pytest.raises(EzvizAuthVerificationCode) as caught:
        client.login(mfa_channel=channel)
    assert caught.value.reason == 'verification_phone_unavailable'
    assert 'phone' in str(caught.value) and 'EZVIZ app' in str(caught.value)
    assert not caught.value.code_sent and caught.value.available_channels == (3,)
    assert len(calls) == 1
    with pytest.raises(EzvizAuthVerificationCode, match='phone'):
        client.send_mfa_code()
    assert len(calls) == 1


@pytest.mark.parametrize('phone', [None, '', 'p***123', '   '])
def test_masked_missing_or_empty_phone_is_not_a_delivery_address(wire, phone):
    client, calls = wire([{'meta': {'code': 6002}, 'contactExt': {'phone': phone}}])
    with pytest.raises(EzvizAuthVerificationCode) as caught:
        client.login(mfa_channel=1)
    assert caught.value.reason == 'verification_phone_unavailable' and len(calls) == 1


def test_channel_discovery_uses_country_business_order_and_unknown_channel(wire):
    client, calls = wire([{'meta': {'code': 200}, 'data': {'OTHER': [{'channel': 2}], 'TERMINAL_BIND': [
        {'channel': 6, 'title': 'WhatsApp', 'order': 2}, {'channel': 1, 'title': 'SMS', 'order': 1},
        {'channel': 99, 'title': 'Future', 'order': 0}, {'channel': 6, 'title': 'duplicate', 'order': 4},
    ]}}])
    channels = client.get_mfa_channels('27')
    assert [(item.channel, item.supported) for item in channels] == [(99, False), (1, True), (6, True)]
    assert calls[0].url == 'https://region.example.test/v3/ezsms/channel/config?countryCode=27'
    assert client._mfa_channel_policy.channels == (1, 3, 6)
    assert 'countryCode' not in json.dumps(client.export_token())


@pytest.mark.parametrize('value', ['', '+27', 'ZA', True, 27, '\uff12\uff17', '1234567'])
def test_bad_country_stops_before_network(wire, value):
    client, calls = wire([])
    with pytest.raises(PyEzvizError, match='Country'):
        client.get_mfa_channels(value)
    assert not calls


@pytest.mark.parametrize('data', [[], {'TERMINAL_BIND': {}}, {'TERMINAL_BIND': [None]}, {'TERMINAL_BIND': [{'channel': True, 'title': 'bad', 'order': 0}]}])
def test_malformed_policy_never_grants_alternate_channels(wire, data):
    client, calls = wire([{'meta': {'code': 200}, 'data': data}])
    with pytest.raises(PyEzvizError):
        client.get_mfa_channels('27')
    with pytest.raises(EzvizLoginError):
        client.login(mfa_channel=6)
    assert len(calls) == 1


@pytest.mark.parametrize('channel, login_channel', [(2, 2), (6, 1), (7, 1)])
def test_advertised_alternative_requests_phone_then_normalizes_login(wire, channel, login_channel):
    client, calls = wire([
        {'meta': {'code': 200}, 'data': {'TERMINAL_BIND': [{'channel': channel, 'title': 'phone method', 'order': 0}]}},
        CONTACT, {'meta': {'code': 200}}, OK,
    ])
    client.get_mfa_channels('27')
    with pytest.raises(EzvizAuthVerificationCode) as caught:
        client.login(mfa_channel=channel)
    assert caught.value.code_sent
    assert form(calls[2])['from'] == ['+27000000000']
    assert form(calls[2])['msgType'] == [str(channel)]
    client.login('001234')
    assert form(calls[3])['msgType'] == [str(login_channel)]
    assert form(calls[3])['smsCode'] == ['001234']


def test_discovery_failure_revokes_prior_extra_channel_and_region_change_requires_rediscovery(wire):
    client, calls = wire([{'meta': {'code': 200}, 'data': {'TERMINAL_BIND': [{'channel': 6, 'title': 'WhatsApp', 'order': 0}]}}, requests.Timeout('offline')])
    client.get_mfa_channels('27')
    with pytest.raises(requests.Timeout):
        client.get_mfa_channels('27')
    with pytest.raises(PyEzvizError):
        client.login(mfa_channel=6)
    assert len(calls) == 2
    client._mfa_channel_policy = _MfaChannelPolicy((1, 3, 6), 'different.example.test')
    with pytest.raises(EzvizLoginError):
        client.login(mfa_channel=6)
    assert len(calls) == 2


@pytest.mark.parametrize('channel', [2, 6, 7])
@pytest.mark.parametrize('operation', ['send_mfa_code', 'login', 'enable_channel99'])
def test_successful_policy_refresh_revokes_retained_channel_before_transport(wire, channel, operation):
    client, calls = wire([
        {'meta': {'code': 200}, 'data': {'TERMINAL_BIND': [{'channel': channel, 'title': 'phone method', 'order': 0}]}},
        CONTACT,
        {'meta': {'code': 200}},
        {'meta': {'code': 200}, 'data': {'TERMINAL_BIND': []}},
    ])
    client.get_mfa_channels('27')
    with pytest.raises(EzvizAuthVerificationCode) as challenge:
        client.login(mfa_channel=channel)
    assert challenge.value.code_sent
    client.get_mfa_channels('27')
    state = client._login_verification
    before = deepcopy(state)
    assert channel not in state.available_channels('region.example.test', client._mfa_channel_policy)
    with pytest.raises(PyEzvizError, match='MFA channel'):
        getattr(client, operation)()
    assert len(calls) == 4
    assert state == before and state.code_sent(client.account)


@pytest.mark.parametrize('channel', [2, 6, 7])
def test_refresh_retaining_selected_channel_allows_explicit_resend(wire, channel):
    policy = {'meta': {'code': 200}, 'data': {'TERMINAL_BIND': [{'channel': channel, 'title': 'phone method', 'order': 0}]}}
    client, calls = wire([policy, CONTACT, {'meta': {'code': 200}}, policy, {'meta': {'code': 200}}])
    client.get_mfa_channels('27')
    with pytest.raises(EzvizAuthVerificationCode):
        client.login(mfa_channel=channel)
    client.get_mfa_channels('27')
    assert client.send_mfa_code()
    assert len(calls) == 5
    assert form(calls[-1])['msgType'] == [str(channel)]


@pytest.mark.parametrize('channel', [1, 3])
def test_withdrawn_selected_channel_can_be_explicitly_changed_to_legacy_method(wire, channel):
    client, calls = wire([
        {'meta': {'code': 200}, 'data': {'TERMINAL_BIND': [{'channel': 6, 'title': 'WhatsApp', 'order': 0}]}},
        CONTACT,
        {'meta': {'code': 200}, 'data': {'TERMINAL_BIND': []}},
        {'meta': {'code': 200}},
    ])
    client.get_mfa_channels('27')
    with pytest.raises(EzvizAuthVerificationCode):
        client.login(mfa_channel=6, request_mfa=False)
    client.get_mfa_channels('27')
    assert client.send_mfa_code(mfa_channel=channel)
    assert len(calls) == 4
    assert form(calls[-1])['msgType'] == [str(channel)]
    assert form(calls[-1])['from'] == ['+27000000000' if channel == 1 else 'bound@example.test']


@pytest.mark.parametrize('migrate', [False, True])
def test_image_login_answer_keeps_otp_and_profile(wire, migrate):
    client, calls = wire([PNG, OK])
    challenge = client.get_captcha()
    method = client.enable_channel99 if migrate else client.login
    method('001234', mfa_channel=1, captcha=challenge, captcha_code='aB01')
    assert 'account=synthetic-account' in calls[0].url and 'featureCode=' in calls[0].url
    assert form(calls[1])['imageCode'] == ['aB01']
    assert form(calls[1])['smsCode'] == ['001234']
    assert form(calls[1])['msgType'] == ['1']
    assert 'aB01' not in repr(challenge) + json.dumps(client.export_token())
    assert client._captcha_state.challenge is None


@pytest.mark.parametrize('method', ['login', 'enable_channel99'])
@pytest.mark.parametrize('identity', ['keep', 'replace', 'remove'])
def test_captcha_reauthentication_validates_caller_owned_token_identity(wire, method, identity):
    token = {
        'api_url': 'region.example.test', 'session_id': 'old-session',
        'rf_session_id': 'old-refresh', 'feature_code': '1' * 32,
        'push_profile': ANDROID_PROFILE.name, 'username': 'synthetic',
        'user_id': 'id', 'push_state': {'counter': 7},
    }
    persisted: list[object] = []
    client, calls = wire([PNG, OK], token=token, feature_code='1' * 32, on_token_updated=persisted.append)
    image = client.get_captcha()
    if identity == 'replace':
        token['feature_code'] = '2' * 32
    elif identity == 'remove':
        token.pop('feature_code')
    before = deepcopy(token)
    headers = dict(client._session.headers)
    if identity == 'keep':
        getattr(client, method)(captcha=image, captcha_code='aB01')
        assert len(calls) == 2 and form(calls[-1])['imageCode'] == ['aB01']
        assert token['feature_code'] == '1' * 32 and token['push_state'] == {'counter': 7}
        assert persisted
    else:
        with pytest.raises(EzvizAuthTokenExpired, match='feature code'):
            getattr(client, method)(captcha=image, captcha_code='aB01')
        assert len(calls) == 1 and token == before
        assert dict(client._session.headers) == headers and not persisted


def test_request_image_is_bound_to_selected_contact_and_only_requests_once(wire):
    client, calls = wire([CONTACT, PNG, {'meta': {'code': 200}}, OK])
    with pytest.raises(EzvizAuthVerificationCode):
        client.login(mfa_channel=1, request_mfa=False)
    image = client.get_captcha(for_mfa=True)
    assert 'account=%2B27000000000' in calls[1].url
    client.send_mfa_code(captcha=image, captcha_code='aB01')
    assert form(calls[2])['imageCode'] == ['aB01']
    assert form(calls[2])['from'] == ['+27000000000']
    client.login('001234')
    assert 'imageCode' not in form(calls[3])
    assert len(calls) == 4


@pytest.mark.parametrize('change', ['cancel', 'refresh', 'region', 'identity', 'contact', 'purpose', 'session'])
def test_stale_or_wrong_context_is_rejected_before_submission(wire, change):
    client, calls = wire([PNG, PNG])
    image = client.get_captcha()
    if change == 'cancel':
        client.cancel_captcha()
    elif change == 'refresh':
        client.get_captcha()
    elif change == 'region':
        client._token['api_url'] = 'other.example.test'
    elif change == 'identity':
        client._feature_code = '0' * 32
    elif change == 'contact':
        client.account = 'another'
    elif change == 'session':
        client.close_session()
    before = len(calls)
    with pytest.raises(EzvizLoginError, match='CAPTCHA'):
        if change == 'purpose':
            client.send_mfa_code(captcha=image, captcha_code='aB01')
        else:
            client.login(captcha=image, captcha_code='aB01')
    assert len(calls) == before


@pytest.mark.parametrize('answer', ['', '123', '12345', ' aB1', '\uff11\uff12\uff13\uff14', True, 1234])
def test_bad_image_answers_never_send_credentials(wire, answer):
    client, calls = wire([PNG])
    image = client.get_captcha()
    with pytest.raises(EzvizLoginError):
        client.login(captcha=image, captcha_code=answer)
    assert len(calls) == 1


def test_timeout_consumes_image_and_prevents_replay(wire):
    client, calls = wire([PNG, requests.Timeout('offline')])
    image = client.get_captcha()
    with pytest.raises(requests.Timeout):
        client.login(captcha=image, captcha_code='aB01')
    with pytest.raises(EzvizLoginError):
        client.login(captcha=image, captcha_code='aB01')
    assert len(calls) == 2


@pytest.mark.parametrize('body', [b'', b'<html>not an image</html>', b'\x89PNG\r\n\x1a\n' + b'x' * (1024 * 1024)])
def test_invalid_image_never_creates_an_answer_context(wire, body):
    client, calls = wire([body])
    with pytest.raises(PyEzvizError):
        client.get_captcha()
    assert client._captcha_state.challenge is None and len(calls) == 1


def test_image_redirect_requires_new_regional_challenge_not_replay(wire):
    client, calls = wire([PNG, {'meta': {'code': 1100}, 'loginArea': {'apiDomain': 'other.example.test'}}])
    image = client.get_captcha()
    with pytest.raises(EzvizLoginError) as caught:
        client.login(captcha=image, captcha_code='aB01')
    assert caught.value.reason == 'captcha_region_changed' and len(calls) == 2
    assert client._captcha_state.challenge is None


def test_challenge_state_repr_and_bad_input_are_nonmutating():
    state = CaptchaState()
    context = _CaptchaContext('region.example.test', 'feature', 'private-contact', _CaptchaPurpose.LOGIN)
    image = state.issue(PNG, context)
    before = deepcopy(state)
    with pytest.raises(EzvizLoginError):
        state.consume(image, 'bad', context)
    assert state.context == before.context and state.challenge is image
    assert 'private-contact' not in repr(state)


@pytest.mark.parametrize('status', [307, 401, 503])
def test_image_http_errors_are_redacted_without_relogin_or_redirect(wire, status):
    client, calls = wire([(status, {'private': 'marker'})])
    with pytest.raises(PyEzvizError) as caught:
        client.get_captcha()
    assert len(calls) == 1 and 'synthetic-account' not in str(caught.value)
    assert client._captcha_state.challenge is None


def test_failed_refresh_discards_old_image_and_redacts_transport_url(wire):
    client, calls = wire([PNG, requests.Timeout('https://region.example.test/captcha?account=private-marker')])
    image = client.get_captcha()
    with pytest.raises(PyEzvizError) as caught:
        client.get_captcha()
    assert 'private-marker' not in str(caught.value)
    with pytest.raises(EzvizLoginError):
        client.login(captcha=image, captcha_code='aB01')
    assert len(calls) == 2


def test_mfa_channel_change_invalidates_contact_image(wire):
    client, calls = wire([CONTACT, PNG])
    with pytest.raises(EzvizAuthVerificationCode):
        client.login(mfa_channel=1, request_mfa=False)
    image = client.get_captcha(for_mfa=True)
    with pytest.raises(EzvizLoginError):
        client.send_mfa_code(mfa_channel=3, captcha=image, captcha_code='aB01')
    assert len(calls) == 2


def test_real_cli_client_image_request_then_otp(monkeypatch, wire):
    from pyezvizapi.cli.auth import login_with_verification  # noqa: PLC0415

    client, calls = wire([CONTACT, {'meta': {'code': 1141}}, PNG, {'meta': {'code': 200}}, OK])
    monkeypatch.setattr('builtins.input', lambda _: '001234')
    login_with_verification(client.login, mfa_channel='sms', fetch_captcha=client.get_captcha, send_mfa=client.send_mfa_code, answer_captcha=lambda _: 'aB01', cancel_captcha=client.cancel_captcha)
    assert len(calls) == 5
    assert form(calls[3])['imageCode'] == ['aB01']
    assert form(calls[4])['smsCode'] == ['001234']
    assert client._captcha_state.challenge is None


@pytest.mark.parametrize('saved_identity', [None, 'previous-web-identity'])
def test_web_profile_captcha_migration_intentionally_replaces_saved_identity(wire, saved_identity):
    token = {'api_url': 'region.example.test', 'session_id': 'web-session', 'rf_session_id': 'web-refresh', 'push_state': {'old': 7}, 'service_urls': {'old': 'discovery'}}
    if saved_identity:
        token['feature_code'] = saved_identity
    client, calls = wire([PNG, OK], token=token)
    image = client.get_captcha()
    client.enable_channel99(captcha=image, captcha_code='aB01')
    assert len(calls) == 2 and form(calls[-1])['imageCode'] == ['aB01']
    assert token['feature_code'] == client.feature_code
    assert token['push_profile'] == ANDROID_PROFILE.name
    assert 'push_state' not in token and token['service_urls'] == {}
    assert token['session_id'] != 'web-session'


def test_successful_login_resets_contacts_without_resetting_regional_policy(wire):
    policy_reply = {'meta': {'code': 200}, 'data': {'TERMINAL_BIND': [{'channel': 6, 'title': 'WhatsApp', 'order': 0}]}}
    client, calls = wire([policy_reply, OK])
    client.get_mfa_channels('27')
    policy = client._mfa_channel_policy
    client._login_verification.update(CONTACT)
    client._login_verification.mark_sent('bound@example.test')
    client.login(mfa_channel=6, request_mfa=False)
    assert client._mfa_channel_policy is policy
    assert not client._login_verification.contacts and not client._login_verification.sent
    assert client._login_verification.channel == 6
    assert len(calls) == 2
