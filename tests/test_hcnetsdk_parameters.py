"""Native SDK namespaces and ambiguous defaults must not become media guesses."""

from dataclasses import replace

import pytest
from test_local_stream_details import ABILITY, config_bytes

from pyezvizapi.hcnetsdk import (
    HcNetSdkStreamDetails,
    ezviz_lan_audio_video_compress_info,
    ezviz_lan_compression_config,
)
from pyezvizapi.hcnetsdk_parameters import normalize_hcnetsdk_parameters


def profile(**changes):
    values = dict(video_encoding_type=1, audio_encoding_type=7, video_frame_rate=14,
                  video_bitrate=23, audio_sampling_rate=1, format_type=3)
    values.update(changes)
    return normalize_hcnetsdk_parameters(**values)


def test_sdk_video_audio_rate_namespaces_are_independent() -> None:
    p = profile()
    assert (p.video_codec, p.audio_codec, p.frame_rate) == ("h264", "aac", 15)
    assert p.video_bitrate_bps == 2048 * 1024
    assert p.audio_sample_rate == 16000 and p.container == "mpegps"
    assert profile(video_encoding_type=10, audio_encoding_type=1).video_codec == "hevc"
    assert profile(video_encoding_type=10, audio_encoding_type=1).audio_codec == "pcm_mulaw"


@pytest.mark.parametrize(("code", "rate"), [(1, 1 / 16), (2, 1 / 8), (4, 1 / 2),
                                         (12, 16), (14, 15), (31, 24), (32, 48), (33, 8.3)])
def test_native_and_documented_frame_rates(code, rate) -> None:
    p = profile(video_frame_rate=code)
    assert p.frame_rate == rate and p.frame_rate_mode == "specified"


@pytest.mark.parametrize(("code", "mode"), [(0, "full"), (0xFFFFFFFE, "auto"),
                                          (-2, "auto"), (0xFFFFFFFF, "unknown"), (123, "unknown")])
def test_automatic_full_and_unknown_rates_remain_unresolved(code, mode) -> None:
    p = profile(video_frame_rate=code)
    assert p.frame_rate is None and p.frame_rate_mode == mode


def test_explicit_bitrate_is_bits_not_an_index_or_an_auto_sentinel() -> None:
    assert profile(video_bitrate=0x80000000 | 2048000).video_bitrate_bps == 2048000
    assert profile(video_bitrate=0xFFFFFFFE).video_bitrate_bps is None
    assert profile(video_bitrate=0xFFFFFFFF).video_bitrate_bps is None
    assert profile(video_bitrate=0).video_bitrate_bps is None
    assert profile(video_bitrate=123).video_bitrate_bps is None


def test_unknown_and_default_encoding_fields_are_not_inferred() -> None:
    p = profile(video_encoding_type=0xFE, audio_encoding_type=0xFF,
                audio_sampling_rate=0, format_type=0)
    assert p.video_codec is p.audio_codec is p.audio_sample_rate is p.container is None
    assert profile(video_encoding_type=0).video_codec == "private_h264"


def test_snapshot_resolves_camera_dimensions_without_claiming_observed_transport() -> None:
    snapshot = HcNetSdkStreamDetails(2, ezviz_lan_compression_config(config_bytes()),
                                  ezviz_lan_audio_video_compress_info(ABILITY))
    p = snapshot.configured_media()
    assert p is not None
    assert (p.width, p.height, p.frame_rate, p.video_codec, p.audio_codec) == (1920, 1080, 15, "h264", "aac")
    output = snapshot.as_dict()
    assert output["main"]["video_frame_rate"] == 14
    assert output["observed_media"] is False and output["transport_protocol"] is None
    missing = replace(snapshot, channel=1).configured_media()
    assert missing is not None and missing.width is None and missing.height is None
