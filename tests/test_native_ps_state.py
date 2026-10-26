"""Streaming must match every existing whole-buffer cipher-state oracle."""

from itertools import product

import pytest
import test_ps_stream_isolation as isolation

from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.native_ps import NativePsTransform
from pyezvizapi.rtp_timing import _pack_header

CASES = (
    [
        (
            "test_interleaved_video_keeps_partial_aes_blocks_per_stream",
            dict(pts=pts, header_size=header),
        )
        for pts, header in product((None, 0), (1, 2))
    ]
    + [
        ("test_timed_video_keeps_pending_block_across_audio", dict(continuation_pts=pts))
        for pts in (None, 0)
    ]
    + [
        (
            "test_new_picture_pts_decrypts_real_parameter_set_after_large_slice",
            dict(header_size=header),
        )
        for header in (1, 2)
    ]
    + [
        (
            "test_same_picture_or_invalid_pts_preserves_tail_lookalike",
            dict(malformed=malformed, aligned=aligned),
        )
        for malformed, aligned in product((False, True), repeat=2)
    ]
    + [
        ("test_new_pts_can_follow_a_continuation_tail_in_the_same_pes", {}),
    ]
    + [
        ("test_pts_dts_picture_boundaries_require_complete_timestamp_markers", dict(dts_mode=mode))
        for mode in ("valid", "missing", "marker", "prefix")
    ]
    + [
        (
            "test_new_pts_does_not_promote_unaligned_tail_parameter_lookalike",
            dict(leading_tail=tail, aligned=aligned),
        )
        for tail, aligned in (
            (b"", False),
            (b"old-picture-tail", False),
            (b"old-picture-tail", True),
        )
    ]
)


@pytest.mark.parametrize("size", [1, 7, 65536])
@pytest.mark.parametrize("name,parameters", CASES)
def test_streaming_uses_the_existing_independent_state_oracles(monkeypatch, size, name, parameters):
    def incremental(data, key, *, nalu_header_size=2):
        transform = NativePsTransform(key, nalu_header_size=nalu_header_size)
        try:
            output = b"".join(
                transform.feed(data[offset : offset + size]) for offset in range(0, len(data), size)
            )
            return output + transform.finish()
        finally:
            transform.close()

    monkeypatch.setattr(isolation, "decrypt_hikvision_ps_video", incremental)
    getattr(isolation, name)(**parameters)


@pytest.mark.parametrize("header_size", [1, 2])
def test_encrypted_video_without_audio_releases_pictures_beyond_pending_budget(header_size):
    clear = b"0123456789abcdef"
    cipher = bytes.fromhex("34a1119c1a165ddeb3ad0fffba9282ec")
    header = b"\x00\x00\x00\x01" + (b"\x65" if header_size == 1 else b"\x26\x01")
    tail = b"unchanged-tail" * 4000
    transform = NativePsTransform("camera-key", nalu_header_size=header_size)
    consumed = released = 0
    for index in range(25):
        pack = _pack_header(index * 6000)
        source = pack + isolation.pes(
            0xE0, header + cipher * 256 + tail, index * 6000, aligned=True
        )
        expected = pack + isolation.pes(
            0xE0, header + clear * 256 + tail, index * 6000, aligned=True
        )
        output = transform.feed(source)
        assert output == expected
        consumed += len(source)
        released += len(output)
        assert transform.pending_bytes == 0
    assert consumed == released and consumed > 1024 * 1024
    assert not transform.finish()
    transform.close()


def test_whole_nal_header_encryption_is_explicitly_outside_streaming_scope():
    with pytest.raises(ValueError, match="clear 1- or 2-byte"):
        NativePsTransform("camera-key", nalu_header_size=0)


@pytest.mark.parametrize("header_size", [1, 2])
def test_video_only_short_nals_release_plaintext_remainder_at_next_picture(header_size):
    clear, cipher = b"0123456789abcdef", bytes.fromhex("34a1119c1a165ddeb3ad0fffba9282ec")
    header = b"\x00\x00\x00\x01" + (b"\x65" if header_size == 1 else b"\x26\x01")
    transform = NativePsTransform("camera-key", nalu_header_size=header_size)
    expected = emitted = b""
    for picture in range(10):
        pack = _pack_header(picture * 6000)
        expected += pack + isolation.pes(
            0xE0, header + clear + b"suffix", picture * 6000, aligned=True
        )
        emitted += transform.feed(
            pack + isolation.pes(0xE0, header + cipher + b"suffix", picture * 6000, aligned=True)
        )
        assert expected.startswith(emitted)
        assert len(expected) - len(emitted) <= 15
        assert transform.pending_bytes <= 15
    emitted += transform.finish()
    transform.close()
    assert emitted == expected


def test_finished_transform_cannot_reuse_cipher_state():
    transform = NativePsTransform("camera-key")
    transform.finish()
    with pytest.raises(PyEzvizError, match="closed"):
        transform.feed(b"\x00")
