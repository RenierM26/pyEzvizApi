"""Explicit SD AAC decryption using the existing native media block transform."""

from __future__ import annotations

from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.streaming.cloud.protocol import _mpeg_ps_video_decrypt_ranges, _pes_payload_start
from pyezvizapi.streaming.media.rtp import _decrypt_idmx_aac_access_unit, _rtp_media_aes_key


def decrypt_playback_adts_audio(data: bytes, media_key: str | bytes) -> bytes:
    """Decrypt complete ADTS access units while preserving PS, PTS and headers.

    SD playback can encrypt AAC independently of its video. This transform is
    explicit: never apply it to clear audio just because video needs decryption.
    Complete ADTS frames inside bounded audio PES are supported; fragmented or
    unsupported audio fails rather than publishing an unverified audio prefix.
    """
    output = bytearray(data)
    frames = 0
    aes_key = _rtp_media_aes_key(media_key)
    for packet in _mpeg_ps_video_decrypt_ranges(data):
        if not 0xC0 <= packet.stream_id <= 0xDF:
            continue
        start = _pes_payload_start(data, packet.start)
        if start is None:
            raise PyEzvizError("SD audio has an unsupported PES header")
        while start < packet.end:
            frame_end, header_length = _adts_frame_bounds(data, start, packet.end)
            access_unit_start = start + header_length
            output[access_unit_start:frame_end] = _decrypt_idmx_aac_access_unit(
                data[access_unit_start:frame_end], aes_key
            )
            start = frame_end
            frames += 1
    if not frames:
        raise PyEzvizError("SD audio decryption requested but no complete ADTS frames were found")
    return bytes(output)


def _adts_frame_bounds(data: bytes, start: int, end: int) -> tuple[int, int]:
    header = data[start : min(start + 7, end)]
    if len(header) != 7 or header[0] != 0xFF or header[1] & 0xF6 != 0xF0:
        raise PyEzvizError("SD audio decryption requires complete ADTS-framed AAC")
    header_length = 7 if header[1] & 1 else 9
    length = ((header[3] & 3) << 11) | (header[4] << 3) | (header[5] >> 5)
    if length <= header_length or start + length > end:
        raise PyEzvizError("SD audio ADTS frame is truncated or split across PES packets")
    if (header[2] >> 2) & 15 >= 13 or header[6] & 3:
        raise PyEzvizError("SD audio ADTS format is unsupported")
    return start + length, header_length
