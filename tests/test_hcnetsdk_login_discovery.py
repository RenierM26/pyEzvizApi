"""Explicit native profiles never enumerate credentials or guess HTTP."""

from dataclasses import replace
import ssl
from types import SimpleNamespace

import pytest
from test_local_stream_details import wire  # noqa: F401

from pyezvizapi import hcnetsdk
from pyezvizapi.exceptions import EzvizLocalSdkDeadlineExpired, PyEzvizError
from pyezvizapi.hcnetsdk import HcNetSdkLanEndpoint, HcNetSdkLoginCandidate

TCP_BUDGET = 2.0

def profile(**kwargs):
    return replace(HcNetSdkLoginCandidate("admin", "private-password", 8443, "NET_DVR_Login_V40", True), **kwargs)


def test_explicit_plain_profile_passes_single_credentials(monkeypatch):
    calls = []
    def query(endpoint, password, **kwargs):
        calls.append((endpoint.command_port, password, kwargs["username"]))
        raise PyEzvizError("login failed")
    monkeypatch.setattr(hcnetsdk, "discover_hcnetsdk_stream_details", query)
    with pytest.raises(PyEzvizError, match="login failed"):
        hcnetsdk.discover_hcnetsdk_stream_details_for_login(HcNetSdkLanEndpoint("CAM", "192.0.2.1"), profile(api="NET_DVR_Login_V30", https=False, port=8000))
    assert calls == [(8000, "private-password", "admin")]
    assert "private-password" not in repr(profile())


@pytest.mark.parametrize("kwargs", [{"api": "unknown"}, {"port": 0}, {"port": True}, {"api": "NET_DVR_Login_V30"}])
def test_invalid_profile_has_no_network_io(kwargs):
    with pytest.raises(PyEzvizError):
        hcnetsdk.discover_hcnetsdk_stream_details_for_login(HcNetSdkLanEndpoint("CAM", "192.0.2.1"), profile(**kwargs), socket_factory=lambda *_: pytest.fail("network I/O"))


@pytest.mark.parametrize("elapsed", [1.0, 3.0])
def test_tls_handshake_shares_tcp_budget_and_closes_failures(monkeypatch, elapsed):
    now = [0.0]
    raw = SimpleNamespace(closed=False, timeout=None)
    raw.close = lambda: setattr(raw, "closed", True)
    raw.settimeout = lambda value: setattr(raw, "timeout", value)
    def tcp(address, timeout):
        assert address == ("192.0.2.1", 8443)
        assert timeout == TCP_BUDGET
        now[0] += elapsed
        return raw
    calls = []
    class Context(ssl.SSLContext):
        def wrap_socket(self, sock, server_side=False, do_handshake_on_connect=True, suppress_ragged_eofs=True, server_hostname=None, session=None):
            calls.append(server_hostname)
            raise ssl.SSLError("handshake rejected")
    def query(endpoint, password, **kwargs):
        return kwargs["socket_factory"]((endpoint.host, endpoint.command_port), 2.0)
    monkeypatch.setattr(hcnetsdk, "discover_hcnetsdk_stream_details", query)
    with pytest.raises(ssl.SSLError if elapsed == 1 else EzvizLocalSdkDeadlineExpired):
        hcnetsdk.discover_hcnetsdk_stream_details_for_login(HcNetSdkLanEndpoint("CAM", "192.0.2.1"), profile(), tls_context=Context(ssl.PROTOCOL_TLS_CLIENT), socket_factory=tcp, monotonic=lambda: now[0])
    assert raw.closed
    assert calls == (["192.0.2.1"] if elapsed == 1 else [])
    if elapsed == 1:
        assert raw.timeout == 1.0


@pytest.fixture
def native_wire(request):
    # Reuse the three-socket RSA/config/ability wire fixture, not a fake query.
    return request.getfixturevalue("wire")




def test_tls_native_binary_login_and_queries_use_same_profile(native_wire):
    wrapped = []
    class Context(ssl.SSLContext):
        def wrap_socket(self, sock, server_side=False, do_handshake_on_connect=True, suppress_ragged_eofs=True, server_hostname=None, session=None):
            assert server_hostname == "192.0.2.10"
            wrapped.append(sock)
            return sock
    def tcp(address, timeout):
        assert address == ("192.0.2.10", 8443)
        return native_wire.factory((address[0], 8000), timeout)
    result = hcnetsdk.discover_hcnetsdk_stream_details_for_login(
        HcNetSdkLanEndpoint("CAM123", "192.0.2.10"), profile(),
        channel=2, tls_context=Context(ssl.PROTOCOL_TLS_CLIENT), socket_factory=tcp,
        rsa_key=native_wire.key, monotonic=lambda: native_wire.clock[0],
    )
    assert result.channel == 2
    assert len(wrapped) == 3
    assert all(sock.closed for sock in wrapped)
