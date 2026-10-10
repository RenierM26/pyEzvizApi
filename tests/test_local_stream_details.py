"""Camera-reported discovery, wire commands, association and offline bounds."""
from dataclasses import replace
import json
from types import SimpleNamespace

from Crypto.Cipher import PKCS1_v1_5
import pytest
import requests

from pyezvizapi import HcNetSdkStreamDetails, discover_hcnetsdk_stream_details
from pyezvizapi.exceptions import EzvizLocalSdkDeadlineExpired, PyEzvizError
from pyezvizapi.hcnetsdk import (
    HcNetSdkCommandPortClient,
    HcNetSdkLanEndpoint,
    HcNetSdkPurePythonClient,
    build_hcnetsdk_tcp_frame,
    ezviz_lan_audio_video_compress_info,
    ezviz_lan_compression_config,
    hcnetsdk_command_port_rsa_key,
    parse_hcnetsdk_tcp_frame,
)

ABILITY = b'''<AudioVideoCompressInfo><VideoCompressInfo><ChannelList><ChannelEntry>
<ChannelNumber>2</ChannelNumber><MainChannel><VideoEncodeType><Range>1,10</Range></VideoEncodeType>
<VideoResolutionList><VideoResolutionEntry><Index>27</Index><Name>HD1080P</Name>
<Resolution>1920*1080</Resolution><VideoFrameRate>14,17</VideoFrameRate>
<VideoBitrate><Min>32</Min><Max>2048</Max></VideoBitrate></VideoResolutionEntry>
<VideoResolutionEntry><Index>19</Index><Resolution>1280x720</Resolution>
<VideoFrameRate>17</VideoFrameRate><VideoBitrate><Min>64</Min><Max>4096</Max></VideoBitrate>
</VideoResolutionEntry></VideoResolutionList></MainChannel><SubChannelList><SubChannelEntry>
<index>1</index><VideoResolutionList><VideoResolutionEntry><Index>3</Index>
<Resolution>704*576</Resolution><VideoFrameRate>10</VideoFrameRate></VideoResolutionEntry>
</VideoResolutionList></SubChannelEntry></SubChannelList></ChannelEntry></ChannelList>
</VideoCompressInfo></AudioVideoCompressInfo>'''


def config_bytes() -> bytes:
    raw = bytearray(116)
    raw[:4] = (116).to_bytes(4, "big")
    for offset, resolution in ((4, 27), (88, 3)):
        raw[offset] = 3
        raw[offset + 1] = resolution
        raw[offset + 8:offset + 12] = (14).to_bytes(4, "big")
        raw[offset + 16] = 1
        raw[offset + 17] = 7
    return bytes(raw)


class WireSocket:
    def __init__(self, data: bytes, clock: list[float]):
        self.data = data
        self.clock = clock
        self.sent: list[bytes] = []
        self.closed = False
        self.timeout = 10.0
        self.received = 0
    def recv(self, count):
        self.clock[0] += 0.01
        part, self.data = self.data[:count], self.data[count:]
        self.received += len(part)
        return part
    def sendall(self, data):
        self.sent.append(data)
    def gettimeout(self):
        return self.timeout
    def settimeout(self, value):
        self.timeout = value
    def getsockname(self):
        return ("192.0.2.20", 12345)
    def close(self):
        self.closed = True


@pytest.fixture
def wire():
    # The traced legacy handshake has a fixed 128-byte encrypted challenge.
    # Use the protocol's existing key factory, not a separate test key policy.
    key = hcnetsdk_command_port_rsa_key()
    clock = [10.0]
    first = build_hcnetsdk_tcp_frame(PKCS1_v1_5.new(key.publickey()).encrypt(b"a" * 32) + b"s" * 64)
    second = build_hcnetsdk_tcp_frame(b"\x12\x34\x56\x78CAM123\0", field_4=0x10A24BF1)
    sockets = [WireSocket(first + second, clock),
               WireSocket(build_hcnetsdk_tcp_frame(config_bytes()), clock),
               WireSocket(build_hcnetsdk_tcp_frame(b"\0" + ABILITY + b"\0"), clock)]
    calls: list[float] = []
    def factory(address, timeout):
        assert address == ("192.0.2.10", 8000)
        calls.append(timeout)
        return sockets[len(calls) - 1]
    return SimpleNamespace(key=key, clock=clock, sockets=sockets, calls=calls, factory=factory)


def discover(wire, **kwargs):
    return discover_hcnetsdk_stream_details(HcNetSdkLanEndpoint("CAM123", "192.0.2.10"),
        "supplied-password", channel=kwargs.pop("channel", 2), rsa_key=wire.key, socket_factory=wire.factory,
        monotonic=lambda: wire.clock[0], **kwargs)


def test_full_discovery_reads_only_configuration_and_ability_with_no_cloud(monkeypatch, wire) -> None:
    monkeypatch.setattr(requests.Session, "request", lambda *_a, **_kw: pytest.fail("offline discovery called cloud"))
    result = discover(wire)
    assert isinstance(result, HcNetSdkStreamDetails)
    assert len(wire.calls) == 3
    assert wire.calls[0] > wire.calls[1] > wire.calls[2]
    assert all(s.closed for s in wire.sockets)
    assert len(wire.sockets[0].sent) == 2
    controls = [parse_hcnetsdk_tcp_frame(s.sent[0]) for s in wire.sockets[1:]]
    assert [f.header.field_12 for f in controls] == [0x110040, 0x11000]
    assert controls[1].body[16:20] == (8).to_bytes(4, "big")
    channel_xml = b"<VideoChannelNumber>2</VideoChannelNumber>"
    assert channel_xml in controls[1].body
    assert result.reported_login_serial == "CAM123"
    summary = result.as_dict()
    assert summary["main_resolution"]["width"] == 1920
    assert summary["sub_resolution"]["width"] == 704
    assert summary["main"]["video_frame_rate"] == 14  # native code, not14FPS
    assert summary["observed_media"] is False and summary["transport_protocol"] is None
    text = json.dumps(summary)
    assert "raw" not in text and "supplied-password" not in text
    assert "challenge" not in text and "auth_seed" not in text


def test_resolution_limits_remain_associated_and_unknown_indexes_are_not_guessed() -> None:
    ability = ezviz_lan_audio_video_compress_info(ABILITY)
    profile = ability.video_channels[0].main_stream
    assert profile is not None
    assert profile.frame_rates == (14, 17)
    a, b = profile.resolutions
    assert (a.width, a.height, a.frame_rate_codes, a.bitrate_max) == (1920, 1080, (14, 17), 2048)
    assert (b.width, b.height, b.frame_rate_codes, b.bitrate_max) == (1280, 720, (17,), 4096)
    cfg = bytearray(config_bytes())
    cfg[5] = 99
    result = HcNetSdkStreamDetails(2, ezviz_lan_compression_config(cfg), ability)
    assert result.configured_resolution() is None
    sub = result.configured_resolution(sub_stream=True)
    assert sub is not None and sub.width == 704
    assert replace(result, channel=1).configured_resolution() is None


@pytest.mark.parametrize("dimensions", [b"unknown", b"1920", b"0*1080", b"-1*1080"])
def test_bad_dimensions_preserve_camera_text_without_fabricating_size(dimensions) -> None:
    ability = ezviz_lan_audio_video_compress_info(ABILITY.replace(b"1920*1080", dimensions))
    stream = ability.video_channels[0].main_stream
    assert stream is not None
    resolution = stream.resolutions[0]
    assert resolution.dimensions == dimensions.decode()
    assert resolution.width is None and resolution.height is None


def test_ambiguous_camera_profiles_do_not_resolve_to_arbitrary_dimensions() -> None:
    ability = ezviz_lan_audio_video_compress_info(ABILITY)
    channel = ability.video_channels[0]
    profile = channel.main_stream
    assert profile is not None
    duplicate_resolution = replace(profile, resolutions=(*profile.resolutions, profile.resolutions[0]))
    ambiguous = replace(channel, main_stream=duplicate_resolution, sub_streams=channel.sub_streams * 2)
    result = HcNetSdkStreamDetails(2, ezviz_lan_compression_config(config_bytes()),
                                 replace(ability, video_channels=(ambiguous,)))
    assert result.configured_resolution() is None
    assert result.configured_resolution(sub_stream=True) is None
    assert replace(result, capabilities=replace(ability, video_channels=(channel, channel))).configured_resolution() is None


def test_range_only_bitrate_codes_survive_without_fabricated_bounds() -> None:
    xml = ABILITY.replace(b"<Min>32</Min><Max>2048</Max>", b"<Range>15, 16, 17</Range>")
    xml = xml.replace(b"<Min>64</Min><Max>4096</Max>", b"<Range>20,23</Range>")
    xml = xml.replace(b"</MainChannel>", b"<VideoBitrate><Range>0,15</Range></VideoBitrate></MainChannel>")
    ability = ezviz_lan_audio_video_compress_info(xml)
    profile = ability.video_channels[0].main_stream
    assert profile is not None
    assert profile.bitrate_codes == (0, 15)
    a, b = profile.resolutions
    assert a.bitrate_codes == (15, 16, 17) and b.bitrate_codes == (20, 23)
    assert a.bitrate_min is None and a.bitrate_max is None
    result = HcNetSdkStreamDetails(2, ezviz_lan_compression_config(config_bytes()), ability)
    assert result.as_dict()["main_resolution"]["bitrate_codes"] == (15, 16, 17)


def test_authentication_rejection_does_not_query_retry_or_downgrade(wire) -> None:
    # Replace the entire second response rather than depending on wire length.
    first_length = int.from_bytes(wire.sockets[0].data[:4], "big")
    wire.sockets[0].data = wire.sockets[0].data[:first_length] + build_hcnetsdk_tcp_frame(b"\0" * 4)
    with pytest.raises(PyEzvizError, match="login failed"):
        discover(wire)
    assert len(wire.calls) == 1 and wire.sockets[0].closed


def test_oversized_reply_rejected_before_body_read_and_socket_closed(wire) -> None:
    wire.sockets[1].data = (1_000_000).to_bytes(4, "big") + b"\0" * 12 + b"unread-body"
    with pytest.raises(PyEzvizError, match="frame limit"):
        discover(wire, max_response_bytes=4096)
    assert wire.sockets[1].received == 16
    assert len(wire.calls) == 2
    assert all(s.closed for s in wire.sockets[:2])


def test_discovery_deadline_includes_all_network_reads_and_closes(wire) -> None:
    with pytest.raises(EzvizLocalSdkDeadlineExpired):
        discover(wire, timeout=0.035)
    assert len(wire.calls) == 1 and wire.sockets[0].closed


@pytest.mark.parametrize("kwargs", [{"channel": 0}, {"channel": True}, {"channel": 256},
    {"timeout": 0}, {"timeout": float("inf")}, {"timeout": None}, {"max_response_bytes": 15}])
def test_invalid_discovery_options_fail_before_network(wire, kwargs) -> None:
    with pytest.raises(PyEzvizError):
        discover(wire, **kwargs)
    assert not wire.calls


def test_non_capability_xml_is_not_success(wire) -> None:
    wire.sockets[2].data = build_hcnetsdk_tcp_frame(b"<ResponseStatus><statusCode>4</statusCode></ResponseStatus>")
    with pytest.raises(PyEzvizError, match="did not return"):
        discover(wire)
    assert all(s.closed for s in wire.sockets)


def test_pure_client_discovery_convenience_preserves_inputs(monkeypatch) -> None:
    from pyezvizapi import hcnetsdk  # noqa: PLC0415
    calls = []
    def query(endpoint, password, **kwargs):
        calls.append((endpoint, password, kwargs))
        return "sentinel"
    monkeypatch.setattr(hcnetsdk, "discover_hcnetsdk_stream_details", query)
    endpoint = HcNetSdkLanEndpoint("CAM123", "192.0.2.10")
    client = HcNetSdkPurePythonClient(endpoint, "password", timeout=5)
    assert client.stream_details(2) == "sentinel"
    assert calls[0][0:2] == (endpoint, "password")
    assert calls[0][2]["channel"] == 2 and calls[0][2]["timeout"] == 5


def test_frame_limit_failure_invalidates_attached_transport(wire) -> None:
    sock = wire.sockets[1]
    sock.data = (1000).to_bytes(4, "big") + b"\0" * 12
    client = HcNetSdkCommandPortClient(HcNetSdkLanEndpoint("CAM123", "192.0.2.10"),
                                     socket_factory=lambda *_a: sock)
    with pytest.raises(PyEzvizError, match="frame limit"):
        client.read_tcp_frame(deadline=20, monotonic=lambda: 10, max_frame_bytes=32)
    assert sock.closed and not client.connected
