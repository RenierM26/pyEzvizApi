"""Selected clean-window media must retain matched AAC and source gaps."""

import io
import subprocess
from types import SimpleNamespace

import pytest

from pyezvizapi import _local_stream as local
from pyezvizapi._local_stream import (
    _clear_native_selected_timeline,
    _copy_clear_native_idmx_timed_av,
    _ffmpeg_video_decode_probe_timeout_seconds,
)
from pyezvizapi.exceptions import EzvizUnsupportedMediaError, PyEzvizError
from pyezvizapi.rtp import RtpPacket, decrypt_idmx_aac_packets


@pytest.mark.parametrize("unfinished_metadata", [False, True])
def test_clean_window_excludes_discarded_startup_and_next_picture_audio(unfinished_metadata):
    sps, dirty, first, last, after = (b"\x67sps", b"\x41\x80dirty", b"\x65\x80clean", b"\x41\x80last", b"\x41\x80after")
    units: tuple[bytes, ...] = (sps, dirty, first, last, after)
    timestamps = [0, 0, 9000, 21000, 27000]
    descriptor = b"\x45\x02\x0f\x68\x43\x0a\0\x01\x02\0\xfa\x03\0\0\x03\xff"
    def video(payload, timestamp):
        return RtpPacket(payload, 96, 1, timestamp, 1, True, idmx=True)
    def audio(payload, timestamp):
        return RtpPacket(b"\x00\x10" + (len(payload) << 3).to_bytes(2, "big") + payload, 104, 1, timestamp, 2, True, idmx=True)
    discarded, early, late, beyond = b"discarded", b"first-audio", b"last-audio", b"after"
    packets = [RtpPacket(b"metadata", 112, 0, 0, 1, False, 1, descriptor, True),
        video(sps, 0), video(dirty, 0), audio(discarded, 0),
        video(first, 9000), audio(early, 1024),
        video(last, 21000), audio(late, 3072),
        video(after, 27000), audio(beyond, 4096)]
    selected = b"".join(b"\0\0\0\1" + unit for unit in (sps, first, last))
    if unfinished_metadata:
        sei = b"\x06next-access-unit"
        units = (*units[:4], sei, after)
        timestamps = [*timestamps[:4], 27000, 27000]
        packets.insert(8, video(sei, 27000))
        selected += b"\0\0\0\1" + sei
    retained_units, retained_times, retained_packets, _boundary = _clear_native_selected_timeline(units, timestamps, packets, selected, "h264")
    assert retained_units[:3] == (sps, first, last)
    assert retained_times[:3] == [9000, 9000, 21000]
    result = decrypt_idmx_aac_packets(retained_packets, b"", require_contiguous=False, decrypt_audio=False, preserve_clear_timestamps=True)
    assert result is not None and result.frame_count == 2
    assert [offset for offset, _data in result.timed_segments] == [0, 2048]
    assert discarded not in result.adts and beyond not in result.adts
    assert early in result.adts and late in result.adts


def test_clean_window_rejects_unmatched_video_instead_of_adding_full_audio():
    unit = b"\x65\x80original"
    with pytest.raises(PyEzvizError, match="uniquely matched"):
        _clear_native_selected_timeline((unit,), [0], [], b"\0\0\0\1\x65\x80different", "h264")


def test_full_suffix_decode_budget_scales_beyond_ten_seconds_but_is_bounded():
    assert _ffmpeg_video_decode_probe_timeout_seconds(b"small") == 1
    assert _ffmpeg_video_decode_probe_timeout_seconds(bytes(24_000_000)) == 13
    assert _ffmpeg_video_decode_probe_timeout_seconds(bytes(400_000_000)) == 180


@pytest.mark.parametrize(("dirty_partition", "selected_partition", "marker"), [(False, False, True), (True, False, True), (False, True, True), (True, False, False), (False, False, False), ("mpeg", False, True), ("legacy", False, True), ("other_codec", False, False), ("delayed_route", False, False)])
def test_public_clean_window_wait_retains_only_matched_aac(monkeypatch, dirty_partition, selected_partition, marker):
    def raw(payload, pt, timestamp, sequence, extension=b""):
        header = bytes((0x90 if extension else 0x80, pt | (0x80 if marker else 0)))
        header += sequence.to_bytes(2, "big") + timestamp.to_bytes(4, "big") + b"\x55\x66\x77\x88"
        if extension:
            header += b"\0\2" + (len(extension) // 4).to_bytes(2, "big") + extension
        frame = header + payload
        return len(frame).to_bytes(4, "little") + frame

    descriptor = b"\x42\x0e" + bytes(11) + (6000 << 1).to_bytes(3, "big")
    descriptor += b"\x45\x02\x1b\x60\x45\x02\x0f\x68\x43\x0a\0\x01\x02\0\xfa\x03\0\0\x03\xff"
    descriptor += b"\x45\x02\x24\x61" if dirty_partition == "other_codec" else b""
    descriptor = descriptor.replace(b"\x45\x02\x1b\x60", b"") if dirty_partition == "delayed_route" else descriptor
    video_pt = 110 if dirty_partition == "delayed_route" else 96
    boundary_descriptor = b"\x45\x02\x1b\x6e" if dirty_partition == "delayed_route" else b""
    dirty, clean, last, after = b"\x65\xb8dirty", b"\x65\xb8clean", b"\x41\xb8last", b"\x41\xb8after"
    if not marker and not dirty_partition:
        after = b"\x62\xb8unsupported-next-picture-partition"
    if selected_partition:
        clean = b"\x62\xb8unsupported-selected-partition"
    if dirty_partition in ("other_codec", "delayed_route"):
        pass
    elif dirty_partition == "legacy":
        dirty = b"\x40\x00\x00\x02\x80\x06\x00\x01\x11\x21\x02\x01\x26\x01\x80legacy"
    elif dirty_partition == "mpeg":
        dirty = b"\0\0\1\xb3unsupported-startup-mpeg"
    elif dirty_partition:
        dirty = b"\x62\xb8unsupported-startup-partition"
    discarded, retained, beyond = b"discarded-audio", b"retained-audio", b"beyond-audio"
    def audio(payload):
        return b"\0\x10" + (len(payload) << 3).to_bytes(2, "big") + payload
    payloads = [raw(b"metadata", 112, 0, 0, descriptor),
        raw(dirty, video_pt, 0, 1), raw(audio(discarded), 104, 0, 1),
        raw(clean, video_pt, 6000, 2), raw(audio(retained), 104, 1024, 2),
        raw(last, video_pt, 12000, 3), raw(after, video_pt, 18000, 4, boundary_descriptor), raw(audio(beyond), 104, 2048, 3)]
    if dirty_partition == "other_codec":
        # The other codec's next packet must not close this H.264 interval.
        payloads.insert(6, raw(b"\x26\x01\x80other-route", 97, 18000, 1))
    selected = b"\0\0\0\1" + clean + b"\0\0\0\1" + last
    def collect(packets, **kwargs):
        assert list(packets) == payloads
        return selected, "h264"
    monkeypatch.setattr(local, "collect_idmx_annexb_after_first_clean_video_window", collect)
    def remux(*args, **kwargs):
        assert kwargs["preserve_timestamps"] is True
        return subprocess.Popen(["cat"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    monkeypatch.setattr(local, "open_mpegts_remux_process", remux)
    stream = SimpleNamespace(iter_packets=lambda **kwargs: iter(SimpleNamespace(body=p) for p in payloads))
    output = io.BytesIO()
    if selected_partition:
        with pytest.raises(EzvizUnsupportedMediaError) as caught:
            local.copy_local_stream_to_mpegts(stream, output, duration_seconds=1, h264_wait_for_clean_idr_window=True)
        assert caught.value.reason == "unsupported_h264_data_partition"
        assert not output.getvalue()
        return
    local.copy_local_stream_to_mpegts(stream, output, duration_seconds=1, h264_wait_for_clean_idr_window=True)
    result = output.getvalue()
    video_pes, audio_pes = b"\0\0\1\xe0", b"\0\0\1\xc0"
    assert video_pes in result and audio_pes in result
    assert retained in result and discarded not in result and beyond not in result
    assert clean in result and last in result and dirty not in result and after not in result


def test_clean_window_missing_packet_mapping_is_a_protocol_error():
    unit = b"\x65\x80picture"
    with pytest.raises(PyEzvizError, match="no matching source RTP interval"):
        _clear_native_selected_timeline((unit,), [0], [], b"\0\0\0\1" + unit, "h264")


@pytest.mark.parametrize("future_profile_on_boundary", [False, True])
def test_clean_window_preserves_descriptor_from_discarded_audio(future_profile_on_boundary):
    first, last, after = b"\x65\x80first", b"\x41\x80last", b"\x41\x80after"
    descriptor = b"\x45\x02\x0f\x68\x43\x0a\0\x01\x02\0\xfa\x03\0\0\x03\xff"
    def audio(payload, timestamp, extension=b""):
        return RtpPacket(b"\0\x10" + (len(payload) << 3).to_bytes(2, "big") + payload,
                         104, 1, timestamp, 2, True, 1, extension, True)
    def video(payload, timestamp):
        return RtpPacket(payload, 96, 1, timestamp, 1, True)
    future = bytearray(descriptor)
    future[8] = 3  # stereo
    future[9:12] = bytes((2, 238, 0))  # 48000 Hz
    future_descriptor = bytes(future)
    discarded, retained, beyond = b"startup", b"retained", b"next-picture"
    packets = [audio(discarded, 0, descriptor), video(first, 9000),
               audio(retained, 1024), video(last, 15000),
               RtpPacket(after, 96, 1, 21000, 1, True, 1, future_descriptor if future_profile_on_boundary else b""),
               audio(beyond, 2048, b"" if future_profile_on_boundary else future_descriptor)]
    selected = b"\0\0\0\1" + first + b"\0\0\0\1" + last
    _units, _times, events, _boundary = _clear_native_selected_timeline(
        (first, last, after), [9000, 15000, 21000], packets, selected, "h264")
    result = decrypt_idmx_aac_packets(events, b"", decrypt_audio=False, preserve_clear_timestamps=True)
    assert result is not None and result.frame_count == 1
    assert result.sample_rate == 16000 and result.channels == 1
    assert retained in result.adts and discarded not in result.adts and beyond not in result.adts
    assert events[0].extension_data == descriptor and not events[0].payload


@pytest.mark.parametrize(("next_sequence", "complete"), [(2, True), (3, False)])
def test_boundary_only_successor_proves_continuity_without_decoding_its_media(next_sequence, complete):
    first = b"\x65\xb8selected"
    next_picture = b"\x62\xb8unsupported-next-picture"
    packets = [RtpPacket(first, 96, 1, 0, 1, False),
               RtpPacket(next_picture, 96, next_sequence, 6000, 1, True)]
    units = local.rtp_packets_to_nal_units(packets, codec="h264",
        completed_access_units_only=True, boundary_only_packet_index=1)
    assert units == ((first,) if complete else ())


@pytest.mark.parametrize(("startup_payload_type", "with_descriptor"), [(96, True), (112, True), (112, False)])
def test_discarded_descriptor_does_not_create_loss_on_real_video_ssrc(startup_payload_type, with_descriptor):
    first, last, after = b"\x65\xb8first", b"\x41\xb8last", b"\x41\xb8after"
    descriptor = b"\x45\x02\x0f\x68\x43\x0a\0\x01\x02\0\xfa\x03\0\0\x03\xff"
    packets = [RtpPacket(b"discarded", startup_payload_type, 1, 0, 123, False, 1, descriptor if with_descriptor else b""),
               RtpPacket(first, 96, 3, 9000, 123, False),
               RtpPacket(last, 96, 4, 15000, 123, False),
               RtpPacket(after, 96, 5, 21000, 123, False)]
    selected = b"\0\0\0\1" + first + b"\0\0\0\1" + last
    _units, _times, events, boundary = _clear_native_selected_timeline(
        (first, last, after), [9000, 15000, 21000], packets, selected, "h264")
    if with_descriptor:
        assert events[0].extension_data == descriptor and events[0].ssrc == -1
    else:
        assert events[0].payload == first
    reconstructed = local.rtp_packets_to_nal_units(events, codec="h264",
        completed_access_units_only=True, boundary_only_packet_index=boundary)
    assert reconstructed == (first, last)


def test_selected_legacy_video_preserves_unproven_clock_fallback():
    descriptor = b"\x42\x0e" + bytes(11) + (6000 << 1).to_bytes(3, "big")
    metadata = b"\x90\x70\0\0" + bytes(4) + b"\x55\x66\x77\x88\0\x02\0\x04" + descriptor
    wrapper = b"\x40\x00\x00\x02\x80\x06\x00\x01\x11\x21\x02\x01"
    unit = b"\x26\x01\x80picture"
    legacy = b"\xfa\x90\xe0\0\1" + bytes(4) + b"\x55\x66\x77\x88" + wrapper + unit
    assert not _copy_clear_native_idmx_timed_av([metadata, legacy], None, io.BytesIO(),
        ffmpeg_path="ffmpeg", selected_annexb=b"\0\0\0\1" + unit, selected_codec="hevc")


@pytest.mark.parametrize("other_timestamp", [15000, 18000])
def test_markerless_boundary_ignores_interleaved_other_video_ssrc(other_timestamp):
    first, last, other, after = b"\x65\xb8first", b"\x41\xb8last", b"\x41\xb8other", b"\x41\xb8after"
    packets = [RtpPacket(first, 96, 1, 9000, 123, False),
               RtpPacket(last, 96, 2, 15000, 123, False),
               RtpPacket(other, 96, 1, other_timestamp, 456, False),
               RtpPacket(after, 96, 3, 21000, 123, False)]
    selected = b"\0\0\0\1" + first + b"\0\0\0\1" + last
    _units, _times, events, boundary = _clear_native_selected_timeline(
        (first, last, other, after), [9000, 15000, other_timestamp, 21000], packets, selected, "h264",
        nal_source_keys=[(123, None), (123, None), (456, None), (123, None)])
    assert boundary == 2 and events[boundary].ssrc == 123
    assert all(packet.ssrc != 456 for packet in events)
    reconstructed = local.rtp_packets_to_nal_units(events, codec="h264",
        completed_access_units_only=True, boundary_only_packet_index=boundary)
    assert reconstructed == (first, last)


@pytest.mark.parametrize("complete", [False, True])
def test_nal_source_identity_stays_aligned_when_unfinished_other_source_is_filtered(complete):
    first, other = b"\x65\xb8first", b"\x65\xb8other"
    packets = [RtpPacket(first, 96, 1, 9000, 123, True),
               RtpPacket(other, 96, 1, 9000, 456, False)]
    timestamps: list[int] = []
    sources: list[tuple[int, int | None]] = []
    units = local.rtp_packets_to_nal_units(packets, codec="h264",
        completed_access_units_only=complete, nal_timestamps=timestamps, nal_source_keys=sources)
    assert units == ((first,) if complete else (first, other))
    assert timestamps == ([9000] if complete else [9000, 9000])
    assert sources == ([(123, None)] if complete else [(123, None), (456, None)])


def test_clean_native_window_rejects_mixed_source_picture_identities():
    first, last = b"\x65\xb8first", b"\x41\xb8last"
    selected = b"\0\0\0\1" + first + b"\0\0\0\1" + last
    with pytest.raises(PyEzvizError, match="mixes different source RTP identities"):
        _clear_native_selected_timeline((first, last), [9000, 15000], [], selected, "h264",
            nal_source_keys=[(123, None), (456, None)])


def test_unknown_control_inside_selected_window_keeps_real_sequence_continuity():
    first, last, after = b"\x65\xb8first", b"\x41\xb8last", b"\x41\xb8after"
    control = RtpPacket(b"control", 112, 4, 12000, 123, False)
    packets = [RtpPacket(first, 96, 3, 9000, 123, False), control,
               RtpPacket(last, 96, 5, 15000, 123, False),
               RtpPacket(after, 96, 6, 21000, 123, False)]
    selected = b"\0\0\0\1" + first + b"\0\0\0\1" + last
    _units, _times, events, boundary = _clear_native_selected_timeline(
        (first, last, after), [9000, 15000, 21000], packets, selected, "h264")
    assert control in events
    assert local.rtp_packets_to_nal_units(events, codec="h264", completed_access_units_only=True,
        boundary_only_packet_index=boundary) == (first, last)
