"""Field-specific HCNetSDK configuration units, never transport inference.

Sources: Hikvision NET_DVR_COMPRESSION_INFO_V30 documentation and the EZVIZ
7.4.1 CQualityMask::GetFrameRateName / StreamPara::GetBitrateValue tables.
These describe configured values, not measurements of a preview session.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

_FRAME_RATES = (None, 1 / 16, 1 / 8, 1 / 4, 1 / 2, 1, 2, 4, 6, 8, 10, 12,
                16, 20, 15, 18, 22, 25, 30, 35, 40, 45, 50, 55, 60, 3, 5, 7,
                9, 100, 120, 24, 48, 8.3)
_VIDEO_BITRATES = (0, 16, 32, 48, 64, 80, 96, 128, 160, 192, 224, 256,
                   320, 384, 448, 512, 640, 768, 896, 1024, 1280, 1536, 1792,
                   2048, 3072, 4096, 8192, 16384)
_VIDEO_ENCODINGS = {0: "private_h264", 1: "h264", 2: "mpeg4", 7: "mjpeg",
                    8: "mpeg2", 9: "svac", 10: "hevc"}
_AUDIO_ENCODINGS = {0: "g722", 1: "pcm_mulaw", 2: "pcm_alaw", 5: "mp2",
                    6: "g726", 7: "aac", 8: "pcm"}
_AUDIO_SAMPLE_RATES = {1: 16000, 2: 32000, 3: 48000, 4: 44100, 5: 8000}
_FORMATS = {1: "elementary", 2: "rtp", 3: "mpegps", 4: "mpegts", 5: "private",
            6: "flv", 7: "asf", 8: "3gp", 9: "rtp_mpegps"}


@dataclass(frozen=True)
class HcNetSdkConfiguredMedia:
    """Normalized camera configuration with unknown/sentinel values retained.

    Native bitrate units use 1024 bits, matching StreamPara, not decimal kbit.
    No field in this model indicates negotiated link/video encryption support.
    """

    video_codec: str | None
    audio_codec: str | None
    frame_rate: float | None
    frame_rate_mode: Literal["specified", "full", "auto", "unknown"]
    video_bitrate_bps: int | None
    audio_sample_rate: int | None
    container: str | None
    width: int | None = None
    height: int | None = None


def normalize_hcnetsdk_parameters(
    *, video_encoding_type: int, audio_encoding_type: int, video_frame_rate: int,
    video_bitrate: int, audio_sampling_rate: int, format_type: int,
    width: int | None = None, height: int | None = None,
) -> HcNetSdkConfiguredMedia:
    """Interpret each SDK namespace separately; preserve unknowns as None."""
    rate_mode: Literal["specified", "full", "auto", "unknown"]
    if video_frame_rate in (-2, 0xFFFFFFFE):
        rate, rate_mode = None, "auto"
    elif video_frame_rate == 0:
        rate, rate_mode = None, "full"
    elif 0 < video_frame_rate < len(_FRAME_RATES):
        rate, rate_mode = _FRAME_RATES[video_frame_rate], "specified"
    else:
        rate, rate_mode = None, "unknown"
    bitrate = None
    if 0 < video_bitrate < len(_VIDEO_BITRATES):
        bitrate = _VIDEO_BITRATES[video_bitrate] * 1024
    elif 0x80000000 < video_bitrate < 0xFFFFFFFE:
        bitrate = video_bitrate & 0x7FFFFFFF
    return HcNetSdkConfiguredMedia(
        video_codec=_VIDEO_ENCODINGS.get(video_encoding_type),
        audio_codec=_AUDIO_ENCODINGS.get(audio_encoding_type),
        frame_rate=rate, frame_rate_mode=rate_mode,
        video_bitrate_bps=bitrate, audio_sample_rate=_AUDIO_SAMPLE_RATES.get(audio_sampling_rate),
        container=_FORMATS.get(format_type), width=width, height=height,
    )
