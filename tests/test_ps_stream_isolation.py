"""Cipher state belongs to a video stream and a validated PES picture epoch."""

import pytest

from pyezvizapi._stream import decrypt_hikvision_ps_video
from pyezvizapi.rtp_timing import _pes

_KEY = "camera-key"
_CLEAR = b"0123456789abcdef"
_CIPHER = bytes.fromhex("34a1119c1a165ddeb3ad0fffba9282ec")
_START = b"\x00\x00\x00\x01"


def pes(stream, payload, pts=None, *, aligned=False):
    if pts is not None:
        packet = bytearray(_pes(pts, stream, payload))
        if aligned:
            packet[6] |= 0x04
        return bytes(packet)
    return (
        b"\x00\x00\x01"
        + bytes((stream,))
        + (len(payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + payload
    )


@pytest.mark.parametrize("pts", [None, 0])
@pytest.mark.parametrize("header_size", [1, 2])
def test_interleaved_video_keeps_partial_aes_blocks_per_stream(pts, header_size):
    first = _START + (b"\x26\x01" if header_size == 2 else b"\x65")
    second = _START + (b"\x40\x01" if header_size == 2 else b"\x67")
    source = (
        pes(0xE0, first + _CIPHER[:7], pts)
        + pes(0xE1, second + _CIPHER, pts)
        + pes(0xE0, _CIPHER[7:], pts)
    )
    expected = (
        pes(0xE0, first + _CLEAR[:7], pts)
        + pes(0xE1, second + _CLEAR, pts)
        + pes(0xE0, _CLEAR[7:], pts)
    )
    assert decrypt_hikvision_ps_video(source, _KEY, nalu_header_size=header_size) == expected


@pytest.mark.parametrize("continuation_pts", [None, 0])
def test_timed_video_keeps_pending_block_across_audio(continuation_pts):
    header = _START + b"\x26\x01"
    audio = pes(0xC0, b"untouched audio", 0)
    source = pes(0xE0, header + _CIPHER[:7], 0) + audio + pes(0xE0, _CIPHER[7:], continuation_pts)
    expected = pes(0xE0, header + _CLEAR[:7], 0) + audio + pes(0xE0, _CLEAR[7:], continuation_pts)
    assert decrypt_hikvision_ps_video(source, _KEY) == expected


@pytest.mark.parametrize("header_size", [1, 2])
def test_new_picture_pts_decrypts_real_parameter_set_after_large_slice(header_size):
    header = _START + (b"\x26\x01" if header_size == 2 else b"\x65")
    parameter = _START + (b"\x40\x01" if header_size == 2 else b"\x67")
    tail = b"clear slice tail"
    source = pes(0xE0, header + _CIPHER * 256 + tail, 0) + pes(
        0xE0, parameter + _CIPHER, 6000, aligned=True
    )
    expected = pes(0xE0, header + _CLEAR * 256 + tail, 0) + pes(
        0xE0, parameter + _CLEAR, 6000, aligned=True
    )
    assert decrypt_hikvision_ps_video(source, _KEY, nalu_header_size=header_size) == expected


@pytest.mark.parametrize("malformed", [False, True])
@pytest.mark.parametrize("aligned", [False, True])
def test_same_picture_or_invalid_pts_preserves_tail_lookalike(malformed, aligned):
    header = _START + b"\x26\x01"
    first_encrypted = pes(0xE0, header + _CIPHER * 256 + b"tail", 0)
    first_clear = pes(0xE0, header + _CLEAR * 256 + b"tail", 0)
    lookalike = bytearray(
        pes(0xE0, _START + b"\x42\x01" + _CIPHER, 6000 if malformed else 0, aligned=aligned)
    )
    if malformed:
        lookalike[9] &= 0xFE  # Invalid PTS marker must not establish a new picture.
    assert decrypt_hikvision_ps_video(first_encrypted + lookalike, _KEY) == first_clear + lookalike


def test_new_pts_can_follow_a_continuation_tail_in_the_same_pes():
    first = _START + b"\x26\x01"
    next_picture = _START + b"\x40\x01"
    source = pes(0xE0, first + _CIPHER[:7], 0) + pes(
        0xE0, _CIPHER[7:] + next_picture + _CIPHER, 6000
    )
    expected = pes(0xE0, first + _CLEAR[:7], 0) + pes(
        0xE0, _CLEAR[7:] + next_picture + _CLEAR, 6000
    )
    assert decrypt_hikvision_ps_video(source, _KEY) == expected


@pytest.mark.parametrize("dts_mode", ["valid", "missing", "marker", "prefix"])
def test_pts_dts_picture_boundaries_require_complete_timestamp_markers(dts_mode):
    header = _START + b"\x26\x01"
    first_encrypted = pes(0xE0, header + _CIPHER * 256 + b"tail", 0)
    first_clear = pes(0xE0, header + _CLEAR * 256 + b"tail", 0)

    def parameter(body):
        packet = bytearray(pes(0xE0, _START + b"\x40\x01" + body, 6000))
        packet[6] |= 0x04
        packet[7] = 0xC0
        packet[9] = (packet[9] & 0x0F) | 0x30
        if dts_mode != "missing":
            dts = bytearray(pes(0xE0, b"", 3000)[9:14])
            dts[0] = (dts[0] & 0x0F) | 0x10
            if dts_mode == "marker":
                dts[2] &= 0xFE
            if dts_mode == "prefix":
                dts[0] |= 0x20
            packet[14:14] = dts
            packet[8] = 10
            packet[4:6] = (len(packet) - 6).to_bytes(2, "big")
        return bytes(packet)

    expected = parameter(_CLEAR if dts_mode == "valid" else _CIPHER)
    assert (
        decrypt_hikvision_ps_video(first_encrypted + parameter(_CIPHER), _KEY)
        == first_clear + expected
    )


@pytest.mark.parametrize(
    "leading_tail,aligned",
    [(b"", False), (b"old-picture-tail", False), (b"old-picture-tail", True)],
)
def test_new_pts_does_not_promote_unaligned_tail_parameter_lookalike(leading_tail, aligned):
    header = _START + b"\x26\x01"
    false_parameter = _START + b"\x42\x01" + _CIPHER
    first_encrypted = pes(0xE0, header + _CIPHER * 256 + b"tail", 0)
    first_clear = pes(0xE0, header + _CLEAR * 256 + b"tail", 0)
    source = first_encrypted + pes(
        0xE0, leading_tail + false_parameter + header + _CIPHER, 6000, aligned=aligned
    )
    expected = first_clear + pes(
        0xE0, leading_tail + false_parameter + header + _CLEAR, 6000, aligned=aligned
    )
    assert decrypt_hikvision_ps_video(source, _KEY) == expected
