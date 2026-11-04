"""Joint profile refuses incompatible receivers before any native source path."""
from unittest.mock import AsyncMock, MagicMock, patch

from custom_components.ezviz_native.camera import NativeCamera
from custom_components.ezviz_native.config import load_settings
from custom_components.ezviz_native.entry_runtime import GroupEntry, LensRuntime
from custom_components.ezviz_native.group import GroupRegistry
from custom_components.ezviz_native.webrtc_offer import receives_codec
from homeassistant.components.camera import Camera
import pytest
from test_native_audio_profile import configured, supported_host as supported_host  # noqa: PLC0414
from test_native_integration import data as data  # noqa: PLC0414

from pyezvizapi.client import EzvizClient


def offer(video="H265", audio="opus", video_direction="recvonly", audio_direction="recvonly"):
    return (f"v=0\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\na=rtpmap:96 {video}/90000\r\n"
            f"a={video_direction}\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n"
            f"a=rtpmap:111 {audio}/48000/2\r\na={audio_direction}\r\n")


@pytest.mark.parametrize(("sdp", "expected"), [
    (offer(), True), (offer(video="h265"), True), (offer(video="H264"), False),
    (offer(video_direction="sendrecv"), True),
    (offer(video_direction="sendonly"), False), (offer(video_direction="inactive"), False),
    (offer().replace("m=video 9", "m=video 0"), False),
    (offer().replace("m=video 9", "m=video invalid"), False),
    (offer().replace("m=video 9", "m=video ²"), False),
    (offer().replace("m=video 9", "m=video " + "9" * 5000), False),
    (offer().replace("m=video 9", "m=video 65536"), False),
    (offer().replace("m=video 9", "m=video 65535"), True),
    (offer().replace("m=video 9", "m=video " + "0" * 5000 + "9"), True),
    (offer().replace("SAVPF 96", "SAVPF 97"), False),
    (offer().replace("H265/90000", "H265/48000"), False),
    (offer().replace("m=video", "m=audio"), False),
    (offer().replace("UDP/TLS/RTP/SAVPF", "UDP/DTLS/SCTP"), False),
    ("v=0\r\na=inactive\r\n" + offer().replace("a=recvonly\r\n", ""), False),
    ("v=0\r\na=inactive\r\n" + offer(), True),
    (offer(video="H264") + offer(), True),
    ("v=0\r\na=rtpmap:96 H265/90000\r\n", False),
])
def test_receiving_codec_is_scoped_to_active_media(sdp, expected):
    assert receives_codec(sdp, "video", "H265", 90000) is expected


@pytest.mark.usefixtures("supported_host")
@pytest.mark.parametrize(("sdp", "code"), [
    (offer(video="H264"), "unsupported_video_codec"),
    (offer(video_direction="sendonly"), "unsupported_video_codec"),
    (offer(audio="PCMA"), "unsupported_audio_codec"),
    (offer(audio_direction="inactive"), "unsupported_audio_codec"),
])
async def test_joint_offer_refuses_without_registration_or_acquisition(hass, data, sdp, code):
    registry = GroupRegistry()
    owner = GroupEntry(hass, "entry", "Primary", load_settings(configured(data)),
                       MagicMock(spec=EzvizClient), registry)
    lens = owner.lenses["primary"]
    lens.relay = MagicMock(source=AsyncMock())
    camera = NativeCamera(MagicMock(entry_id="entry", title="Primary", runtime_data=owner), lens)
    camera.hass = hass
    with (patch.object(Camera, "async_handle_async_webrtc_offer", AsyncMock()) as provider,
          patch.object(LensRuntime, "upstream", side_effect=AssertionError("No native URL")),
          patch.object(GroupEntry, "make_source", side_effect=AssertionError("No acquisition"))):
        error = camera.async_validate_webrtc_offer(sdp)
    provider.assert_not_awaited()
    lens.relay.source.assert_not_awaited()
    assert error is not None and error.code == code
    assert type(camera).async_handle_async_webrtc_offer is Camera.async_handle_async_webrtc_offer
    assert owner.group.attempts == 0
    await registry.close(owner.group.identity.physical)


@pytest.mark.usefixtures("supported_host")
@pytest.mark.parametrize("video", ["H265", "H264"])
@pytest.mark.parametrize("bundle_only", [False, True])
async def test_compatible_joint_offer_delegates_to_real_provider_contract(hass, data, video, bundle_only):
    registry = GroupRegistry()
    config = {**configured(data), "video_codec": "hevc" if video == "H265" else "h264"}
    owner = GroupEntry(hass, "entry", "Primary", load_settings(config),
                       MagicMock(spec=EzvizClient), registry)
    camera = NativeCamera(MagicMock(entry_id="entry", title="Primary", runtime_data=owner),
                          owner.lenses["primary"])
    camera.hass = hass
    sdp = bundled_offer(video=video) if bundle_only else offer(video=video)
    assert camera.async_validate_webrtc_offer(sdp) is None
    assert type(camera).async_handle_async_webrtc_offer is Camera.async_handle_async_webrtc_offer
    assert owner.group.attempts == 0
    await registry.close(owner.group.identity.physical)


async def test_legacy_offer_keeps_existing_provider_negotiation(hass, data):
    registry = GroupRegistry()
    config = {**configured(data), "relay_native_opus": False}
    owner = GroupEntry(hass, "entry", "Primary", load_settings(config),
                       MagicMock(spec=EzvizClient), registry)
    camera = NativeCamera(MagicMock(entry_id="entry", title="Primary", runtime_data=owner),
                          owner.lenses["primary"])
    camera.hass = hass
    assert camera.async_validate_webrtc_offer(offer(video="VP8", audio="PCMA")) is None
    assert type(camera).async_handle_async_webrtc_offer is Camera.async_handle_async_webrtc_offer
    assert owner.group.attempts == 0
    await registry.close(owner.group.identity.physical)


def bundled_offer(*, zero_kind="audio", video="H265", group="video audio", bundle_only=True):
    sdp = offer(video=video).replace("v=0\r\n", f"v=0\r\na=group:BUNDLE {group}\r\n")
    for kind, formats in (("video", "96"), ("audio", "111")):
        port = "0" if kind == zero_kind else "9"
        attributes = f"a=mid:{kind}\r\n"
        if kind == zero_kind and bundle_only:
            attributes += "a=bundle-only\r\n"
        sdp = sdp.replace(f"m={kind} 9 UDP/TLS/RTP/SAVPF {formats}\r\n",
                          f"m={kind} {port} UDP/TLS/RTP/SAVPF {formats}\r\n{attributes}")
    return sdp


@pytest.mark.parametrize(("sdp", "kind", "expected"), [
    (bundled_offer(), "audio", True),
    (bundled_offer(zero_kind="video", group="audio video"), "video", True),
    (bundled_offer().replace("m=audio 0", "m=audio 00000"), "audio", True),
    (bundled_offer(bundle_only=False), "audio", False),
    (bundled_offer(group="video"), "audio", False),
    (bundled_offer().replace("a=mid:audio\r\n", ""), "audio", False),
    (bundled_offer().replace("a=mid:audio", "a=mid:elsewhere"), "audio", False),
    (bundled_offer().replace("a=group:BUNDLE video audio\r\n", ""), "audio", False),
    (bundled_offer().replace("a=group:BUNDLE", "a=group:LS"), "audio", False),
    (bundled_offer().replace("a=group:BUNDLE video audio\r\n", "")
     + "a=group:BUNDLE video audio\r\n", "audio", False),
    (bundled_offer().replace("a=mid:audio", "a=sendonly\r\na=mid:audio")
     .replace("a=rtpmap:111 opus/48000/2\r\na=recvonly", "a=rtpmap:111 opus/48000/2"),
     "audio", False),
    (bundled_offer().replace("opus/48000/2", "PCMA/8000"), "audio", False),
])
def test_zero_port_requires_bundle_only_and_session_group_membership(sdp, kind, expected):
    codec, rate = ("opus", 48000) if kind == "audio" else ("H265", 90000)
    assert receives_codec(sdp, kind, codec, rate) is expected
