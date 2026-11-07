"""Regression tests for camera preview metadata (not guessed payload routes)."""

import base64
import struct

import pytest

from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.stream_header import parse_ezviz_stream_header, stream_header_from_preview


def header(video=5, audio=0x2001, system=2):
    return b"IMKH" + struct.pack("<IHHHBBII", 0x101, system, video, audio, 1, 16, 16000, 32000) + bytes(16)


def preview(data, length=None):
    encoded = base64.b64encode(data)
    length = len(encoded) if length is None else length
    return b'<Response><StreamHeader Base64Data="' + encoded + b'" Base64Length="' + str(length).encode() + b'"/></Response>\0'


@pytest.mark.parametrize(("code", "codec"), [(5, "hevc"), (0x100, "h264"), (1, "h264"), (99, None)])
def test_native_header_codes_are_not_sdk_configuration_codes(code, codec):
    parsed = stream_header_from_preview(preview(header(video=code)))
    assert parsed is not None
    assert parsed.video_codec == codec
    assert parsed.audio_codec == "aac"
    assert parsed.audio_sample_rate == 16000
    assert parsed.audio_channels == 1
    assert parsed.audio_bits_per_sample == 16
    assert parsed.audio_bitrate_bps == 32000


def test_base64_length_counts_encoded_characters():
    parsed = stream_header_from_preview(preview(header()))
    assert parsed is not None and parsed.version == 0x101
    with pytest.raises(PyEzvizError):
        stream_header_from_preview(preview(header(), length=40))


def test_missing_header_stays_unknown():
    assert stream_header_from_preview(b"<Response><Result>0</Result></Response>") is None


@pytest.mark.parametrize("body", [b"bad XML", b"<Response><StreamHeader/></Response>", b'<Response><StreamHeader Base64Data="!" Base64Length="1"/></Response>', b"<Response><StreamHeader/><StreamHeader/></Response>"])
def test_malformed_header_is_not_silently_guessed(body):
    with pytest.raises(PyEzvizError):
        stream_header_from_preview(body)


@pytest.mark.parametrize("data", [bytes(40), header()[:-1], header()+b"x", b"IMKH"+bytes(36)])
def test_unknown_layout_rejected(data):
    with pytest.raises(PyEzvizError):
        parse_ezviz_stream_header(data)


def test_unknown_audio_and_empty_values_preserved():
    raw = b"IMKH" + struct.pack("<IHHHBBII", 0x101, 123, 999, 999, 0, 0, 0, 0) + bytes(16)
    parsed = parse_ezviz_stream_header(raw)
    assert parsed.system_format_code == 123
    assert parsed.audio_codec is None
    assert parsed.video_codec is None
    assert parsed.audio_sample_rate is None
    assert parsed.audio_bitrate_bps is None
