# Runtime hook context is explicit; immutable value types come from dependency leaves.
# ruff: noqa: SLF001
'windows implementation; legacy runtime hooks remain on the owner module.\n\nAccess through _owner is deliberate: callers that patch the compatibility\nmodule must still affect dependent operations. No copied hook snapshots.\n'
from __future__ import annotations

from types import ModuleType as _ModuleType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pyezvizapi.streaming.local.session as _owner_types

def collect_h264_idmx_annexb_after_first_clean_idr_window(packets: _owner_types.Iterable[bytes], *, duration_seconds: float | None, monotonic: _owner_types.Callable[[], float], ffmpeg_path: str, max_windows: int, wait_seconds: float, _owner: _ModuleType) -> bytes:  # noqa: PLR0912, PLR0915 -- explicit runtime context plus retained signature
    """Collect IDMX packets from the first clean IDR window onward.

    This is a streaming-friendly variant of post-capture clean-IDR trimming:
    startup packets may be discarded for up to ``wait_seconds``, and the
    requested ``duration_seconds`` window starts only after a decodable IDR
    window is found.
    """
    if duration_seconds is None:
        raise _owner.PyEzvizError('duration_seconds is required when waiting for clean IDR')
    if wait_seconds < 0:
        raise _owner.PyEzvizError('wait_seconds cannot be negative')
    if max_windows <= 0:
        raise _owner.PyEzvizError('max_windows must be positive')
    wait_deadline = monotonic() + wait_seconds
    capture_deadline: float | None = None
    collected: list[bytes] = []
    packet_times: list[float] = []
    clean_start_offset: int | None = None
    clean_idr_time: float | None = None
    first_decode_error: str | None = None
    final_decode_error: str | None = None
    last_suffix_probe_packet_count = 0
    last_probe = _owner._H264CleanIdrProbeResult(start_offset=None)
    last_clean_probe_packet_count = 0
    for packet in packets:
        now = monotonic()
        if clean_start_offset is None and now >= wait_deadline:
            suffix = _owner._h264_clean_idr_timeout_suffix(first_decode_error=first_decode_error, probe=last_probe)
            raise _owner.PyEzvizError('Timed out waiting for a clean H.264 IDR window' + suffix)
        if clean_start_offset is not None and capture_deadline is not None and (clean_idr_time is not None) and (now >= capture_deadline) and (last_suffix_probe_packet_count == 0):
            deadline_packets = [packet for packet, packet_time in zip(collected, packet_times, strict=True) if packet_time < capture_deadline or packet_time == clean_idr_time]
            deadline_packet_times = packet_times[:len(deadline_packets)]
            annexb = _owner._idmx_local_packets_to_h264_annexb(deadline_packets)
            try:
                return _owner.trim_h264_annexb_to_first_error_free_suffix(annexb[clean_start_offset:], ffmpeg_path=ffmpeg_path, max_windows=max_windows, accept_start_offset=_owner._requested_duration_h264_suffix_predicate(packets=deadline_packets, packet_times=deadline_packet_times, base_offset=clean_start_offset, now=capture_deadline, duration_seconds=duration_seconds))
            except _owner.PyEzvizError as err:
                final_decode_error = final_decode_error or str(err)
                last_suffix_probe_packet_count = len(collected)
        collected.append(packet)
        packet_times.append(now)
        if clean_start_offset is None:
            if not _owner._should_probe_clean_window(packet_count=len(collected), last_probe_packet_count=last_clean_probe_packet_count):
                continue
            last_clean_probe_packet_count = len(collected)
            probe = _owner._try_first_clean_h264_annexb_idr_window_offset(collected, ffmpeg_path=ffmpeg_path, max_windows=max_windows)
            last_probe = probe
            clean_start_offset = probe.start_offset
            if first_decode_error is None and probe.first_decode_error is not None:
                first_decode_error = probe.first_decode_error
            _owner._raise_if_clean_window_probe_exhausted(probe=probe, max_windows=max_windows, first_decode_error=first_decode_error, message='H.264 stream did not contain a clean IDR window')
            if clean_start_offset is not None:
                clean_idr_packet_index = _owner._h264_annexb_packet_index_for_offset(collected, offset=getattr(probe, 'idr_start_offset', None) or clean_start_offset)
                clean_idr_time = packet_times[clean_idr_packet_index]
                capture_deadline = _owner.cast(float, clean_idr_time) + _owner.cast(float, duration_seconds)
            continue
        if capture_deadline is not None and now >= capture_deadline and (len(collected) - last_suffix_probe_packet_count >= _owner._CLEAN_WINDOW_SUFFIX_PROBE_PACKET_INTERVAL):
            annexb = _owner._idmx_local_packets_to_h264_annexb(collected)
            try:
                return _owner.trim_h264_annexb_to_first_error_free_suffix(annexb[clean_start_offset:], ffmpeg_path=ffmpeg_path, max_windows=max_windows, accept_start_offset=_owner._requested_duration_h264_suffix_predicate(packets=collected, packet_times=packet_times, base_offset=clean_start_offset, now=now, duration_seconds=duration_seconds))
            except _owner.PyEzvizError as err:
                final_decode_error = final_decode_error or str(err)
                last_suffix_probe_packet_count = len(collected)
                if now >= capture_deadline + wait_seconds:
                    raise _owner.PyEzvizError('Timed out waiting for a clean final H.264 suffix: ' + str(err)) from err
    if clean_start_offset is None:
        if collected and last_clean_probe_packet_count != len(collected):
            probe = _owner._try_first_clean_h264_annexb_idr_window_offset(collected, ffmpeg_path=ffmpeg_path, max_windows=max_windows)
            last_probe = probe
            clean_start_offset = probe.start_offset
            if first_decode_error is None and probe.first_decode_error is not None:
                first_decode_error = probe.first_decode_error
            _owner._raise_if_clean_window_probe_exhausted(probe=probe, max_windows=max_windows, first_decode_error=first_decode_error, message='H.264 stream did not contain a clean IDR window')
        suffix = _owner._h264_clean_idr_timeout_suffix(first_decode_error=first_decode_error, probe=last_probe)
        if clean_start_offset is None:
            raise _owner.PyEzvizError('H.264 stream ended before a clean IDR window was found' + suffix)
    annexb = _owner._idmx_local_packets_to_h264_annexb(collected)
    try:
        return _owner.trim_h264_annexb_to_first_error_free_suffix(annexb[clean_start_offset:], ffmpeg_path=ffmpeg_path, max_windows=max_windows, accept_start_offset=_owner._requested_duration_h264_suffix_predicate(packets=collected, packet_times=packet_times, base_offset=clean_start_offset, now=packet_times[-1] if packet_times else 0.0, duration_seconds=duration_seconds))
    except _owner.PyEzvizError as err:
        if final_decode_error:
            raise _owner.PyEzvizError(final_decode_error) from err
        raise

def _hevc_prefixed_suffix_accept_start_offset(accept_start_offset: _owner_types.Callable[[int], bool], *, prefix_length: int, _owner: _ModuleType) -> _owner_types.Callable[[int], bool]:
    """Map offsets in a parameter-prefixed HEVC suffix back to the original suffix."""
    if prefix_length <= 0:
        return accept_start_offset

    def accepts(offset: int) -> bool:
        return accept_start_offset(max(0, offset - prefix_length))
    return accepts

def collect_idmx_annexb_after_first_clean_video_window(packets: _owner_types.Iterable[bytes], *, duration_seconds: float | None, monotonic: _owner_types.Callable[[], float], ffmpeg_path: str, max_windows: int, wait_seconds: float, _owner: _ModuleType) -> tuple[bytes, str]:  # noqa: PLR0912, PLR0915 -- explicit runtime context plus retained signature
    """Collect clear IDMX video from the first clean H.264 IDR or HEVC IRAP."""
    if duration_seconds is None:
        raise _owner.PyEzvizError('duration_seconds is required when waiting for clean video')
    if wait_seconds < 0:
        raise _owner.PyEzvizError('wait_seconds cannot be negative')
    if max_windows <= 0:
        raise _owner.PyEzvizError('max_windows must be positive')
    wait_deadline = monotonic() + wait_seconds
    capture_deadline: float | None = None
    collected: list[bytes] = []
    packet_times: list[float] = []
    clean_start_offset: int | None = None
    clean_codec: str | None = None
    clean_prefix = b''
    clean_window_time: float | None = None
    first_decode_error: str | None = None
    final_decode_error: str | None = None
    last_suffix_probe_packet_count = 0
    last_probe = _owner._H264CleanIdrProbeResult(start_offset=None)
    last_clean_probe_packet_count = 0
    for packet in packets:
        now = monotonic()
        if clean_start_offset is None and now >= wait_deadline:
            suffix = _owner._h264_clean_idr_timeout_suffix(first_decode_error=first_decode_error, probe=last_probe)
            raise _owner.PyEzvizError('Timed out waiting for a clean video window' + suffix)
        if clean_start_offset is not None and clean_codec is not None and (capture_deadline is not None) and (clean_window_time is not None) and (now >= capture_deadline) and (last_suffix_probe_packet_count == 0):
            deadline_packets = [packet for packet, packet_time in zip(collected, packet_times, strict=True) if packet_time < capture_deadline or packet_time == clean_window_time]
            if clean_codec == 'h264':
                annexb = _owner._idmx_local_packets_to_h264_annexb(deadline_packets)
                trim = _owner.trim_h264_annexb_to_first_error_free_suffix
            else:
                annexb = _owner._idmx_local_packets_to_hevc_annexb(deadline_packets)
                trim = _owner.trim_hevc_annexb_to_first_error_free_suffix
                annexb = clean_prefix + annexb[clean_start_offset:]
                accept_start_offset = _owner._hevc_prefixed_suffix_accept_start_offset(_owner._requested_duration_idmx_suffix_predicate(packets=deadline_packets, packet_times=packet_times[:len(deadline_packets)], codec=clean_codec, base_offset=clean_start_offset, now=capture_deadline, duration_seconds=duration_seconds), prefix_length=len(clean_prefix))
            if clean_codec == 'h264':
                annexb = annexb[clean_start_offset:]
                accept_start_offset = _owner._requested_duration_idmx_suffix_predicate(packets=deadline_packets, packet_times=packet_times[:len(deadline_packets)], codec=clean_codec, base_offset=clean_start_offset, now=capture_deadline, duration_seconds=duration_seconds)
            try:
                return (trim(annexb, ffmpeg_path=ffmpeg_path, max_windows=max_windows, accept_start_offset=accept_start_offset), clean_codec)
            except _owner.PyEzvizError as err:
                final_decode_error = final_decode_error or str(err)
                last_suffix_probe_packet_count = len(collected)
        collected.append(packet)
        packet_times.append(now)
        if clean_start_offset is None:
            if not _owner._should_probe_clean_window(packet_count=len(collected), last_probe_packet_count=last_clean_probe_packet_count):
                continue
            last_clean_probe_packet_count = len(collected)
            probe_start_offset, probe_codec, probe_decode_error, last_probe = _owner._probe_first_clean_idmx_video_window(collected, ffmpeg_path=ffmpeg_path, max_windows=max_windows)
            if first_decode_error is None and probe_decode_error is not None:
                first_decode_error = probe_decode_error
            _owner._raise_if_clean_window_probe_exhausted(probe=last_probe, max_windows=max_windows, first_decode_error=first_decode_error, message='IDMX stream did not contain a clean video window')
            if probe_start_offset is not None and probe_codec is not None:
                clean_start_offset = probe_start_offset
                clean_codec = probe_codec
                clean_prefix = getattr(last_probe, 'prefix', b'') if probe_codec == 'hevc' else b''
                clean_packet_index = _owner._idmx_annexb_packet_index_for_offset(collected, codec=probe_codec, offset=getattr(last_probe, 'idr_start_offset', None) or clean_start_offset)
                clean_window_time = packet_times[clean_packet_index]
                capture_deadline = _owner.cast(float, clean_window_time) + _owner.cast(float, duration_seconds)
            continue
        if capture_deadline is not None and now >= capture_deadline and (len(collected) - last_suffix_probe_packet_count >= _owner._CLEAN_WINDOW_SUFFIX_PROBE_PACKET_INTERVAL):
            assert clean_codec is not None
            if clean_codec == 'h264':
                annexb = _owner._idmx_local_packets_to_h264_annexb(collected)
                trim = _owner.trim_h264_annexb_to_first_error_free_suffix
            else:
                annexb = _owner._idmx_local_packets_to_hevc_annexb(collected)
                trim = _owner.trim_hevc_annexb_to_first_error_free_suffix
                annexb = clean_prefix + annexb[clean_start_offset:]
                accept_start_offset = _owner._hevc_prefixed_suffix_accept_start_offset(_owner._requested_duration_idmx_suffix_predicate(packets=collected, packet_times=packet_times, codec=clean_codec, base_offset=clean_start_offset, now=now, duration_seconds=duration_seconds), prefix_length=len(clean_prefix))
            if clean_codec == 'h264':
                annexb = annexb[clean_start_offset:]
                accept_start_offset = _owner._requested_duration_idmx_suffix_predicate(packets=collected, packet_times=packet_times, codec=clean_codec, base_offset=clean_start_offset, now=now, duration_seconds=duration_seconds)
            try:
                return (trim(annexb, ffmpeg_path=ffmpeg_path, max_windows=max_windows, accept_start_offset=accept_start_offset), clean_codec)
            except _owner.PyEzvizError as err:
                final_decode_error = final_decode_error or str(err)
                last_suffix_probe_packet_count = len(collected)
                if now >= capture_deadline + wait_seconds:
                    raise _owner.PyEzvizError(f'Timed out waiting for a clean final {clean_codec.upper()} suffix: ' + str(err)) from err
    if clean_start_offset is None or clean_codec is None:
        if collected and last_clean_probe_packet_count != len(collected):
            probe_start_offset, probe_codec, probe_decode_error, last_probe = _owner._probe_first_clean_idmx_video_window(collected, ffmpeg_path=ffmpeg_path, max_windows=max_windows)
            if first_decode_error is None and probe_decode_error is not None:
                first_decode_error = probe_decode_error
            _owner._raise_if_clean_window_probe_exhausted(probe=last_probe, max_windows=max_windows, first_decode_error=first_decode_error, message='IDMX stream did not contain a clean video window')
            if probe_start_offset is not None and probe_codec is not None:
                clean_start_offset = probe_start_offset
                clean_codec = probe_codec
                clean_prefix = getattr(last_probe, 'prefix', b'') if probe_codec == 'hevc' else b''
        suffix = _owner._h264_clean_idr_timeout_suffix(first_decode_error=first_decode_error, probe=last_probe)
        if clean_start_offset is None or clean_codec is None:
            raise _owner.PyEzvizError('IDMX stream ended before a clean video window was found' + suffix)
    if clean_codec == 'h264':
        annexb = _owner._idmx_local_packets_to_h264_annexb(collected)
        annexb = _owner.trim_h264_annexb_to_first_error_free_suffix(annexb[clean_start_offset:], ffmpeg_path=ffmpeg_path, max_windows=max_windows, accept_start_offset=_owner._requested_duration_idmx_suffix_predicate(packets=collected, packet_times=packet_times, codec='h264', base_offset=clean_start_offset, now=packet_times[-1] if packet_times else 0.0, duration_seconds=duration_seconds))
        return (annexb, clean_codec)
    else:
        annexb = _owner._idmx_local_packets_to_hevc_annexb(collected)
        try:
            annexb = _owner.trim_hevc_annexb_to_first_error_free_suffix(clean_prefix + annexb[clean_start_offset:], ffmpeg_path=ffmpeg_path, max_windows=max_windows, accept_start_offset=_owner._hevc_prefixed_suffix_accept_start_offset(_owner._requested_duration_idmx_suffix_predicate(packets=collected, packet_times=packet_times, codec='hevc', base_offset=clean_start_offset, now=packet_times[-1] if packet_times else 0.0, duration_seconds=duration_seconds), prefix_length=len(clean_prefix)))
        except _owner.PyEzvizError as err:
            if final_decode_error:
                raise _owner.PyEzvizError(final_decode_error) from err
            raise
    return (annexb, clean_codec)

def _probe_first_clean_idmx_video_window(packets: list[bytes], *, ffmpeg_path: str, max_windows: int, _owner: _ModuleType) -> tuple[int | None, str | None, str | None, _owner_types._H264CleanIdrProbeResult]:
    h264_probe = _owner._try_first_clean_h264_annexb_idr_window_offset(packets, ffmpeg_path=ffmpeg_path, max_windows=max_windows)
    if h264_probe.start_offset is not None:
        return (h264_probe.start_offset, 'h264', h264_probe.first_decode_error, h264_probe)
    hevc_probe = _owner._try_first_clean_hevc_annexb_irap_window_offset(packets, ffmpeg_path=ffmpeg_path, max_windows=max_windows)
    return (hevc_probe.start_offset, 'hevc' if hevc_probe.start_offset is not None else None, h264_probe.first_decode_error or hevc_probe.first_decode_error, hevc_probe if hevc_probe.nal_count or hevc_probe.idr_count else h264_probe)

def collect_decrypted_h264_idmx_annexb_after_first_clean_idr_window(packets: _owner_types.Iterable[bytes], media_key: str | bytes, *, nalu_header_size: int | None, duration_seconds: float | None, monotonic: _owner_types.Callable[[], float], ffmpeg_path: str, max_windows: int, wait_seconds: float, _owner: _ModuleType) -> bytes:  # noqa: PLR0912, PLR0915 -- explicit runtime context plus retained signature
    """Collect decrypted IDMX H.264 from the first clean IDR window onward."""
    if duration_seconds is None:
        raise _owner.PyEzvizError('duration_seconds is required when waiting for clean IDR')
    if wait_seconds < 0:
        raise _owner.PyEzvizError('wait_seconds cannot be negative')
    if max_windows <= 0:
        raise _owner.PyEzvizError('max_windows must be positive')
    wait_deadline = monotonic() + wait_seconds
    capture_deadline: float | None = None
    collected: list[bytes] = []
    packet_times: list[float] = []
    clean_start_offset: int | None = None
    clean_idr_time: float | None = None
    clean_stream_is_clear = False
    first_decode_error: str | None = None
    final_decode_error: str | None = None
    last_suffix_probe_packet_count = 0
    last_probe = _owner._H264CleanIdrProbeResult(start_offset=None)
    last_clean_probe_packet_count = 0
    for packet in packets:
        now = monotonic()
        if clean_start_offset is None and now >= wait_deadline:
            suffix = _owner._h264_clean_idr_timeout_suffix(first_decode_error=first_decode_error, probe=last_probe)
            raise _owner.PyEzvizError('Timed out waiting for a clean H.264 IDR window' + suffix)
        if clean_start_offset is not None and capture_deadline is not None and (clean_idr_time is not None) and (now >= capture_deadline) and (last_suffix_probe_packet_count == 0):
            deadline_packets = [packet for packet, packet_time in zip(collected, packet_times, strict=True) if packet_time < capture_deadline or packet_time == clean_idr_time]
            if clean_stream_is_clear:
                annexb = _owner._idmx_local_packets_to_h264_annexb(deadline_packets)
            else:
                annexb = _owner._decrypt_idmx_local_packets_to_annexb(deadline_packets, media_key, nalu_header_size=nalu_header_size)
            try:
                return _owner.trim_h264_annexb_to_first_error_free_suffix(annexb[clean_start_offset:], ffmpeg_path=ffmpeg_path, max_windows=max_windows, accept_start_offset=_owner._requested_duration_decrypted_h264_suffix_predicate(packets=deadline_packets, packet_times=packet_times[:len(deadline_packets)], media_key=media_key, nalu_header_size=nalu_header_size, stream_is_clear=clean_stream_is_clear, base_offset=clean_start_offset, now=capture_deadline, duration_seconds=duration_seconds))
            except _owner.PyEzvizError as err:
                final_decode_error = final_decode_error or str(err)
                last_suffix_probe_packet_count = len(collected)
        collected.append(packet)
        packet_times.append(now)
        if clean_start_offset is None:
            if not _owner._should_probe_clean_window(packet_count=len(collected), last_probe_packet_count=last_clean_probe_packet_count):
                continue
            last_clean_probe_packet_count = len(collected)
            clear_probe = _owner._try_first_clean_h264_annexb_idr_window_offset(collected, ffmpeg_path=ffmpeg_path, max_windows=max_windows)
            if clear_probe.start_offset is not None:
                probe = clear_probe
                clean_stream_is_clear = True
            else:
                probe = _owner._try_first_clean_decrypted_h264_annexb_idr_window_offset(collected, media_key, nalu_header_size=nalu_header_size, ffmpeg_path=ffmpeg_path, max_windows=max_windows)
            if first_decode_error is None and clear_probe.first_decode_error is not None:
                first_decode_error = clear_probe.first_decode_error
            if first_decode_error is None and probe.first_decode_error is not None:
                first_decode_error = probe.first_decode_error
            _owner._raise_if_clean_window_probe_exhausted(probe=probe, max_windows=max_windows, first_decode_error=first_decode_error, message='H.264 stream did not contain a clean IDR window')
            last_probe = probe
            clean_start_offset = probe.start_offset
            if clean_start_offset is not None:
                clean_idr_packet_index = _owner._h264_annexb_packet_index_for_offset(collected, offset=probe.idr_start_offset or clean_start_offset) if clean_stream_is_clear else _owner._decrypted_h264_annexb_packet_index_for_offset(collected, media_key, nalu_header_size=nalu_header_size, offset=probe.idr_start_offset or clean_start_offset)
                clean_idr_time = packet_times[clean_idr_packet_index]
                capture_deadline = _owner.cast(float, clean_idr_time) + _owner.cast(float, duration_seconds)
            continue
        if capture_deadline is not None and now >= capture_deadline and (len(collected) - last_suffix_probe_packet_count >= _owner._CLEAN_WINDOW_SUFFIX_PROBE_PACKET_INTERVAL):
            if clean_stream_is_clear:
                annexb = _owner._idmx_local_packets_to_h264_annexb(collected)
            else:
                annexb = _owner._decrypt_idmx_local_packets_to_annexb(collected, media_key, nalu_header_size=nalu_header_size)
            try:
                return _owner.trim_h264_annexb_to_first_error_free_suffix(annexb[clean_start_offset:], ffmpeg_path=ffmpeg_path, max_windows=max_windows, accept_start_offset=_owner._requested_duration_decrypted_h264_suffix_predicate(packets=collected, packet_times=packet_times, media_key=media_key, nalu_header_size=nalu_header_size, stream_is_clear=clean_stream_is_clear, base_offset=clean_start_offset, now=now, duration_seconds=duration_seconds))
            except _owner.PyEzvizError as err:
                final_decode_error = final_decode_error or str(err)
                last_suffix_probe_packet_count = len(collected)
                if now >= capture_deadline + wait_seconds:
                    raise _owner.PyEzvizError('Timed out waiting for a clean final H.264 suffix: ' + str(err)) from err
    if clean_start_offset is None:
        if collected and last_clean_probe_packet_count != len(collected):
            clear_probe = _owner._try_first_clean_h264_annexb_idr_window_offset(collected, ffmpeg_path=ffmpeg_path, max_windows=max_windows)
            if clear_probe.start_offset is not None:
                probe = clear_probe
                clean_stream_is_clear = True
            else:
                probe = _owner._try_first_clean_decrypted_h264_annexb_idr_window_offset(collected, media_key, nalu_header_size=nalu_header_size, ffmpeg_path=ffmpeg_path, max_windows=max_windows)
            if first_decode_error is None and clear_probe.first_decode_error is not None:
                first_decode_error = clear_probe.first_decode_error
            if first_decode_error is None and probe.first_decode_error is not None:
                first_decode_error = probe.first_decode_error
            _owner._raise_if_clean_window_probe_exhausted(probe=probe, max_windows=max_windows, first_decode_error=first_decode_error, message='H.264 stream did not contain a clean IDR window')
            last_probe = probe
            clean_start_offset = probe.start_offset
        suffix = _owner._h264_clean_idr_timeout_suffix(first_decode_error=first_decode_error, probe=last_probe)
        if clean_start_offset is None:
            raise _owner.PyEzvizError('H.264 stream ended before a clean IDR window was found' + suffix)
    if clean_stream_is_clear:
        annexb = _owner._idmx_local_packets_to_h264_annexb(collected)
    else:
        annexb = _owner._decrypt_idmx_local_packets_to_annexb(collected, media_key, nalu_header_size=nalu_header_size)
    try:
        return _owner.trim_h264_annexb_to_first_error_free_suffix(annexb[clean_start_offset:], ffmpeg_path=ffmpeg_path, max_windows=max_windows, accept_start_offset=_owner._requested_duration_decrypted_h264_suffix_predicate(packets=collected, packet_times=packet_times, media_key=media_key, nalu_header_size=nalu_header_size, stream_is_clear=clean_stream_is_clear, base_offset=clean_start_offset, now=packet_times[-1] if packet_times else 0.0, duration_seconds=duration_seconds))
    except _owner.PyEzvizError as err:
        if final_decode_error:
            raise _owner.PyEzvizError(final_decode_error) from err
        raise

def _raise_if_clean_window_probe_exhausted(*, probe: _owner_types._H264CleanIdrProbeResult, max_windows: int, first_decode_error: str | None, message: str, _owner: _ModuleType) -> None:
    """Stop streaming probes once the requested clean-window budget is spent."""
    if getattr(probe, 'start_offset', None) is not None or int(getattr(probe, 'complete_window_count', 0) or 0) < max_windows:
        return
    suffix = _owner._h264_clean_idr_timeout_suffix(first_decode_error=first_decode_error, probe=probe)
    raise _owner.PyEzvizError(message + suffix)

def _should_probe_clean_window(*, packet_count: int, last_probe_packet_count: int, _owner: _ModuleType) -> bool:
    """Avoid rebuilding and decoding the growing packet buffer every packet."""
    if packet_count < _owner._CLEAN_WINDOW_PROBE_THROTTLE_AFTER_PACKETS:
        return True
    return packet_count - last_probe_packet_count >= _owner._CLEAN_WINDOW_PROBE_PACKET_INTERVAL

def _requested_duration_h264_suffix_predicate(*, packets: list[bytes], packet_times: list[float], base_offset: int, now: float, duration_seconds: float, _owner: _ModuleType) -> _owner_types.Callable[[int], bool]:
    """Return a suffix-start guard that preserves useful post-IDR duration."""
    latest_start_time = now - duration_seconds
    packet_end_offsets = _owner._h264_annexb_packet_end_offsets(packets)

    def accept_start_offset(start_offset: int) -> bool:
        if not packet_times:
            return False
        packet_index = _owner.bisect.bisect_right(packet_end_offsets, base_offset + start_offset)
        packet_index = min(packet_index, len(packet_times) - 1)
        return packet_times[packet_index] <= latest_start_time
    return accept_start_offset

def _requested_duration_idmx_suffix_predicate(*, packets: list[bytes], packet_times: list[float], codec: str, base_offset: int, now: float, duration_seconds: float, _owner: _ModuleType) -> _owner_types.Callable[[int], bool]:
    """Return a suffix-start guard for clear H.264/HEVC IDMX Annex-B."""
    latest_start_time = now - duration_seconds
    if codec == 'h264':
        packet_end_offsets = _owner._h264_annexb_packet_end_offsets(packets)
    elif codec == 'hevc':
        packet_end_offsets = _owner._hevc_annexb_packet_end_offsets(packets)
    else:
        packet_end_offsets = []

    def accept_start_offset(start_offset: int) -> bool:
        if not packet_times:
            return False
        packet_index = _owner.bisect.bisect_right(packet_end_offsets, base_offset + start_offset) if packet_end_offsets else max(len(packet_times) - 1, 0)
        packet_index = min(packet_index, len(packet_times) - 1)
        return packet_times[packet_index] <= latest_start_time
    return accept_start_offset

def _requested_duration_decrypted_h264_suffix_predicate(*, packets: list[bytes], packet_times: list[float], media_key: str | bytes, nalu_header_size: int | None, stream_is_clear: bool, base_offset: int, now: float, duration_seconds: float, _owner: _ModuleType) -> _owner_types.Callable[[int], bool]:
    """Return a suffix-start guard for clear-first or encrypted H.264 IDMX."""
    latest_start_time = now - duration_seconds

    def accept_start_offset(start_offset: int) -> bool:
        if stream_is_clear:
            packet_index = _owner._h264_annexb_packet_index_for_offset(packets, offset=base_offset + start_offset)
        else:
            packet_index = _owner._decrypted_h264_annexb_packet_index_for_offset(packets, media_key, nalu_header_size=nalu_header_size, offset=base_offset + start_offset)
        if not packet_times:
            return False
        packet_index = min(packet_index, len(packet_times) - 1)
        return packet_times[packet_index] <= latest_start_time
    return accept_start_offset

def trim_h264_annexb_to_first_clean_idr_window(data: bytes, *, ffmpeg_path: str, max_windows: int, _owner: _ModuleType) -> bytes:
    """Return Annex-B bytes from the first IDR window that decodes cleanly."""
    idr_summary = _owner.summarize_h264_annexb_idr_windows(data, max_windows=max_windows)
    samples = idr_summary.get('samples')
    if not isinstance(samples, list) or not samples:
        raise _owner.PyEzvizError('H.264 stream did not contain IDR windows')
    first_error: str | None = None
    for sample in samples:
        if not isinstance(sample, dict):
            continue
        start_offset = sample.get('start_code_offset')
        if not isinstance(start_offset, int):
            continue
        end_offset = sample.get('end_offset')
        if not isinstance(end_offset, int) or end_offset <= start_offset:
            continue
        window = data[start_offset:end_offset]
        stderr_lines = _owner._ffmpeg_h264_decode_errors(window, ffmpeg_path=ffmpeg_path, accept_success_with_stderr=False)
        if not stderr_lines:
            return data[start_offset:]
        if first_error is None and stderr_lines:
            first_error = stderr_lines[0]
    suffix = f': {first_error}' if first_error else ''
    raise _owner.PyEzvizError('H.264 stream did not contain a clean sampled IDR window' + suffix)

def trim_h264_annexb_to_first_error_free_suffix(data: bytes, *, ffmpeg_path: str, max_windows: int, accept_start_offset: _owner_types.Callable[[int], bool] | None, _owner: _ModuleType) -> bytes:
    """Return the earliest IDR-started suffix that decodes without errors."""
    if not data:
        return data
    initial_errors = _owner._ffmpeg_h264_decode_errors(data, ffmpeg_path=ffmpeg_path, accept_success_with_stderr=False)
    if not initial_errors and (accept_start_offset is None or accept_start_offset(0)):
        return data
    idr_summary = _owner.summarize_h264_annexb_idr_windows(data, max_windows=max_windows)
    samples = idr_summary.get('samples')
    if not isinstance(samples, list) or not samples:
        raise _owner.PyEzvizError('H.264 stream did not contain a clean decodable suffix: ' + (initial_errors[0] if initial_errors else 'clean suffix starts too late for requested duration'))
    first_error = initial_errors[0] if initial_errors else 'clean suffix starts too late for requested duration'
    candidate_samples: list[tuple[dict[str, _owner_types.Any], int]] = []
    for sample in samples[1:]:
        if not isinstance(sample, dict):
            continue
        start_offset = sample.get('start_code_offset')
        if not isinstance(start_offset, int):
            continue
        if accept_start_offset is not None and (not accept_start_offset(start_offset)):
            continue
        candidate_samples.append((sample, start_offset))
    if len(candidate_samples) > _owner._CLEAN_WINDOW_SUFFIX_PROBE_MAX_CANDIDATES:
        candidate_samples = candidate_samples[-_owner._CLEAN_WINDOW_SUFFIX_PROBE_MAX_CANDIDATES:]
    for _sample, start_offset in candidate_samples:
        suffix = data[start_offset:]
        decode_errors = _owner._ffmpeg_h264_decode_errors(suffix, ffmpeg_path=ffmpeg_path, accept_success_with_stderr=False)
        if not decode_errors:
            return suffix
        if not first_error and decode_errors:
            first_error = decode_errors[0]
    raise _owner.PyEzvizError('H.264 stream did not contain a clean decodable suffix: ' + first_error)

def trim_hevc_annexb_to_first_clean_irap_window(data: bytes, *, ffmpeg_path: str, max_windows: int, _owner: _ModuleType) -> bytes:
    """Return Annex-B bytes from the first IRAP window that decodes cleanly."""
    irap_summary = _owner.summarize_hevc_annexb_irap_windows(data, max_windows=max_windows)
    samples = irap_summary.get('samples')
    if not isinstance(samples, list) or not samples:
        raise _owner.PyEzvizError('HEVC stream did not contain IRAP windows')
    first_error: str | None = None
    for sample in samples:
        if not isinstance(sample, dict):
            continue
        start_offset = sample.get('start_code_offset')
        if not isinstance(start_offset, int):
            continue
        end_offset = sample.get('end_offset')
        if not isinstance(end_offset, int) or end_offset <= start_offset:
            continue
        prefix = _owner._hevc_annexb_parameter_prefix_for_suffix(data, start_offset=start_offset, leading_nal_types=sample.get('leading_nal_types'))
        window = prefix + data[start_offset:end_offset]
        stderr_lines = _owner._ffmpeg_hevc_decode_errors(window, ffmpeg_path=ffmpeg_path, accept_success_with_stderr=False)
        if not stderr_lines:
            suffix = prefix + data[start_offset:]
            suffix_errors = _owner._ffmpeg_hevc_decode_errors(suffix, ffmpeg_path=ffmpeg_path, accept_success_with_stderr=False)
            if not suffix_errors:
                return suffix
            if first_error is None:
                first_error = suffix_errors[0]
            continue
        if first_error is None and stderr_lines:
            first_error = stderr_lines[0]
    error_suffix = f': {first_error}' if first_error else ''
    raise _owner.PyEzvizError('HEVC stream did not contain a clean sampled IRAP window' + error_suffix)

def trim_hevc_annexb_to_first_error_free_suffix(data: bytes, *, ffmpeg_path: str, max_windows: int, accept_start_offset: _owner_types.Callable[[int], bool] | None, _owner: _ModuleType) -> bytes:
    """Return the earliest IRAP-started suffix that decodes without errors."""
    if not data:
        return data
    initial_errors = _owner._ffmpeg_hevc_decode_errors(data, ffmpeg_path=ffmpeg_path, accept_success_with_stderr=False)
    if not initial_errors and (accept_start_offset is None or accept_start_offset(0)):
        return data
    irap_summary = _owner.summarize_hevc_annexb_irap_windows(data, max_windows=max_windows)
    samples = irap_summary.get('samples')
    if not isinstance(samples, list) or not samples:
        raise _owner.PyEzvizError('HEVC stream did not contain a clean decodable suffix: ' + (initial_errors[0] if initial_errors else 'clean suffix starts too late for requested duration'))
    first_error = initial_errors[0] if initial_errors else 'clean suffix starts too late for requested duration'
    candidate_samples: list[tuple[dict[str, _owner_types.Any], int]] = []
    for sample in samples[1:]:
        if not isinstance(sample, dict):
            continue
        start_offset = sample.get('start_code_offset')
        if not isinstance(start_offset, int):
            continue
        if accept_start_offset is not None and (not accept_start_offset(start_offset)):
            continue
        candidate_samples.append((sample, start_offset))
    if len(candidate_samples) > _owner._CLEAN_WINDOW_SUFFIX_PROBE_MAX_CANDIDATES:
        candidate_samples = candidate_samples[-_owner._CLEAN_WINDOW_SUFFIX_PROBE_MAX_CANDIDATES:]
    for sample, start_offset in candidate_samples:
        prefix = _owner._hevc_annexb_parameter_prefix_for_suffix(data, start_offset=start_offset, leading_nal_types=sample.get('leading_nal_types'))
        suffix = data[start_offset:]
        decode_errors = _owner._ffmpeg_hevc_decode_errors(prefix + suffix, ffmpeg_path=ffmpeg_path, accept_success_with_stderr=False)
        if not decode_errors:
            return prefix + suffix
        if not first_error and decode_errors:
            first_error = decode_errors[0]
    raise _owner.PyEzvizError('HEVC stream did not contain a clean decodable suffix: ' + first_error)

def _hevc_annexb_parameter_prefix_for_suffix(data: bytes, *, start_offset: int, leading_nal_types: object, _owner: _ModuleType) -> bytes:
    """Return prior VPS/SPS/PPS when a recovered IRAP lacks local parameters."""
    required_types = {32, 33, 34}
    local_types = {item for item in leading_nal_types if isinstance(item, int)} if isinstance(leading_nal_types, list) else set()
    missing_types = required_types - local_types
    if not missing_types:
        return b''
    latest: dict[int, bytes] = {}
    for start_code_offset, nal_start, end in _owner._h264_annexb_nal_spans(data[:start_offset]):
        nal_type = _owner._hevc_nal_type(data[nal_start:end])
        if nal_type in missing_types:
            latest[nal_type] = data[start_code_offset:end]
    if not missing_types.issubset(latest):
        return b''
    return b''.join(latest[nal_type] for nal_type in (32, 33, 34) if nal_type in latest)

def _try_first_clean_h264_annexb_idr_window_offset(packets: list[bytes], *, ffmpeg_path: str, max_windows: int, _owner: _ModuleType) -> _owner_types._H264CleanIdrProbeResult:
    """Return the first clean IDR window offset for partial IDMX packets."""
    try:
        annexb = _owner._idmx_local_packets_to_h264_annexb(packets)
    except _owner.PyEzvizError:
        return _owner._H264CleanIdrProbeResult(start_offset=None)
    return _owner._try_first_clean_h264_annexb_idr_window_offset_from_annexb(annexb, ffmpeg_path=ffmpeg_path, max_windows=max_windows)

def _try_first_clean_decrypted_h264_annexb_idr_window_offset(packets: list[bytes], media_key: str | bytes, *, nalu_header_size: int | None, ffmpeg_path: str, max_windows: int, _owner: _ModuleType) -> _owner_types._H264CleanIdrProbeResult:
    """Return the first clean IDR offset for partial encrypted IDMX packets."""
    try:
        annexb = _owner._decrypt_idmx_local_packets_to_annexb(packets, media_key, nalu_header_size=nalu_header_size)
    except _owner.PyEzvizError:
        return _owner._H264CleanIdrProbeResult(start_offset=None)
    return _owner._try_first_clean_h264_annexb_idr_window_offset_from_annexb(annexb, ffmpeg_path=ffmpeg_path, max_windows=max_windows)

def _try_first_clean_hevc_annexb_irap_window_offset(packets: list[bytes], *, ffmpeg_path: str, max_windows: int, _owner: _ModuleType) -> _owner_types._H264CleanIdrProbeResult:
    """Return the first clean HEVC IRAP window offset for partial IDMX packets."""
    try:
        annexb = _owner._idmx_local_packets_to_hevc_annexb(packets)
    except _owner.PyEzvizError:
        return _owner._H264CleanIdrProbeResult(start_offset=None, codec_name='HEVC', window_name='IRAP')
    irap_summary = _owner.summarize_hevc_annexb_irap_windows(annexb, max_windows=max_windows)
    samples = irap_summary.get('samples')
    if not isinstance(samples, list):
        return _owner._H264CleanIdrProbeResult(start_offset=None, idr_count=int(irap_summary.get('irap_count', 0)), nal_count=int(irap_summary.get('nal_count', 0)), codec_name='HEVC', window_name='IRAP')
    first_decode_error: str | None = None
    complete_window_count = 0
    for sample in samples:
        if not isinstance(sample, dict):
            continue
        end_nal_index = sample.get('end_nal_index')
        if not isinstance(end_nal_index, int) or end_nal_index >= int(irap_summary['nal_count']):
            continue
        start_offset = sample.get('start_code_offset')
        end_offset = sample.get('end_offset')
        if not isinstance(start_offset, int) or not isinstance(end_offset, int) or end_offset <= start_offset:
            continue
        complete_window_count += 1
        prefix = _owner._hevc_annexb_parameter_prefix_for_suffix(annexb, start_offset=start_offset, leading_nal_types=sample.get('leading_nal_types'))
        decode_errors = _owner._ffmpeg_hevc_decode_errors(prefix + annexb[start_offset:end_offset], ffmpeg_path=ffmpeg_path, accept_success_with_stderr=False)
        if not decode_errors:
            return _owner._H264CleanIdrProbeResult(start_offset=start_offset, idr_start_offset=int(sample['irap_start_code_offset']), prefix=prefix, first_decode_error=first_decode_error, idr_count=int(irap_summary.get('irap_count', 0)), sampled_window_count=len(samples), complete_window_count=complete_window_count, nal_count=int(irap_summary.get('nal_count', 0)), codec_name='HEVC', window_name='IRAP')
        if first_decode_error is None:
            first_decode_error = decode_errors[0]
    return _owner._H264CleanIdrProbeResult(start_offset=None, first_decode_error=first_decode_error, idr_count=int(irap_summary.get('irap_count', 0)), sampled_window_count=len(samples), complete_window_count=complete_window_count, nal_count=int(irap_summary.get('nal_count', 0)), codec_name='HEVC', window_name='IRAP')

def _decrypted_h264_annexb_packet_index_for_offset(packets: list[bytes], media_key: str | bytes, *, nalu_header_size: int | None, offset: int, _owner: _ModuleType) -> int:
    """Return the packet index that first contributes the given Annex-B offset."""
    _annexb, spans = _owner._idmx_h264_annexb_packet_spans(packets, media_key, nalu_header_size=nalu_header_size, stream_is_clear=False)
    for span in spans:
        if span[0] <= offset < span[1]:
            return span[2]
    return max(len(packets) - 1, 0)

def _decrypted_hevc_annexb_packet_index_for_offset(packets: list[bytes], media_key: str | bytes, *, offset: int, _owner: _ModuleType) -> int:
    """Return the first packet contributing the HEVC NAL at ``offset``."""
    _annexb, spans = _owner._idmx_hevc_annexb_packet_spans(packets, media_key)
    for span in spans:
        if span[0] <= offset < span[1]:
            return span[2]
    return max(len(packets) - 1, 0)

def _idmx_h264_annexb_packet_spans(packets: list[bytes], media_key: str | bytes, *, nalu_header_size: int | None, stream_is_clear: bool, _owner: _ModuleType) -> tuple[bytes, list[tuple[int, int, int, int, int, int, int]]]:  # noqa: PLR0912, PLR0915 -- explicit runtime context plus retained signature
    """Assemble H.264 while recording each NAL's contributing packet span."""
    output = bytearray()
    spans: list[tuple[int, int, int, int, int, int, int]] = []
    active_fu: _owner_types._RtpFragmentedNal | None = None
    active_start_packet: int | None = None
    active_start_frame: int | None = None
    aes_key = _owner._local_media_aes_key(media_key)
    header_size = _owner.H264_NAL_HEADER_SIZE if nalu_header_size is None else nalu_header_size
    routed_payload_types = _owner._idmx_local_video_payload_types(packets, codec='h264')
    route_epoch_profile = _owner.RtpRouteProfile()
    for packet_index, packet in enumerate(packets):
        for frame_index, frame in enumerate(_owner._iter_idmx_local_packet_frame(packet, video_payload_types=routed_payload_types)):
            frame_header_size = _owner._idmx_local_frame_header_size(frame)
            if frame_header_size is None:
                continue
            rtp_packet = _owner._idmx_local_frame_rtp_packet(frame, frame_header_size)
            if rtp_packet is not None:
                route_epoch_profile.absorb(rtp_packet)
            if rtp_packet is None or rtp_packet.payload_type not in routed_payload_types:
                continue
            body = _owner._idmx_local_frame_media_body(frame, frame_header_size)
            if not _owner._rtp_packet_matches_codec_epoch(route_epoch_profile, rtp_packet, 'h264'):
                continue
            if _owner._looks_like_idmx_h264_fu_a_frame(body):
                is_start = bool(body[1] & 128)
                nal_type = body[1] & 31
                if is_start:
                    active_start_packet = packet_index
                    active_start_frame = frame_index
                nal_start_packet = active_start_packet
                nal_start_frame = active_start_frame
                start_offset = len(output)
                active_fu = _owner._append_idmx_h264_fu_a_payload(output, body, active_fu=active_fu, sequence_number=_owner._idmx_local_frame_sequence_number(frame, frame_header_size), rtp_timestamp=_owner._idmx_local_frame_rtp_timestamp(frame, frame_header_size), aes_key=None if stream_is_clear else aes_key, nalu_header_size=header_size)
                if len(output) > start_offset:
                    spans.append((start_offset, len(output), nal_start_packet if nal_start_packet is not None else packet_index, packet_index, nal_type, nal_start_frame if nal_start_frame is not None else frame_index, frame_index))
                if active_fu is None:
                    active_start_packet = None
                    active_start_frame = None
                continue
            decrypted_body: bytes | None = None
            if not _owner._looks_like_idmx_h264_clear_nal(body):
                if stream_is_clear or header_size != 0 or (not body):
                    continue
                decrypted_body = _owner._decrypt_h264_nal_prefix(body, aes_key, nalu_header_size=header_size)
            active_fu = None
            active_start_packet = None
            active_start_frame = None
            start_offset = len(output)
            if stream_is_clear:
                _owner._append_h264_nal(output, body)
                nal_type = _owner._h264_nal_type(body)
            elif decrypted_body is not None:
                _owner._append_h264_nal(output, decrypted_body)
                nal_type = _owner._h264_nal_type(decrypted_body)
            else:
                _owner._append_decrypted_h264_nal(output, body, aes_key, nalu_header_size=header_size)
                nal_type = _owner._h264_nal_type(body)
            spans.append((start_offset, len(output), packet_index, packet_index, nal_type, frame_index, frame_index))
    return (bytes(output), spans)

def _idmx_hevc_annexb_packet_spans(packets: list[bytes], media_key: str | bytes, *, decrypt_hevc_parameter_sets: bool, _owner: _ModuleType) -> tuple[bytes, list[tuple[int, int, int, int, int, int, int]]]:  # noqa: PLR0912, PLR0915 -- explicit runtime context plus retained signature
    """Assemble decrypted HEVC while recording each NAL's packet span."""
    output = bytearray()
    spans: list[tuple[int, int, int, int, int, int, int]] = []
    active_fu: _owner_types._RtpFragmentedNal | None = None
    active_start_packet: int | None = None
    active_start_frame: int | None = None
    active_end_packet: int | None = None
    active_end_frame: int | None = None
    active_nal_type: int | None = None
    hevc_evidence_seen = False
    aes_key = _owner._local_media_aes_key(media_key)
    routed_payload_types = _owner._idmx_local_video_payload_types(packets, codec='hevc')
    routed_h264_payload_types = _owner._idmx_local_video_payload_types(packets, codec='h264')
    authoritative_hevc_route = bool(routed_payload_types and (not routed_h264_payload_types))
    route_epoch_profile = _owner.RtpRouteProfile()
    for packet_index, packet in enumerate(packets):
        for frame_index, frame in enumerate(_owner._iter_idmx_local_packet_frame(packet, video_payload_types=routed_payload_types)):
            frame_header_size = _owner._idmx_local_frame_header_size(frame)
            if frame_header_size is None:
                continue
            body = _owner._idmx_local_frame_media_body(frame, frame_header_size)
            rtp_packet = _owner._idmx_local_frame_rtp_packet(frame, frame_header_size)
            if rtp_packet is not None:
                route_epoch_profile.absorb(rtp_packet)
            active_route_descriptor = next((descriptor for descriptor in route_epoch_profile.descriptors if rtp_packet is not None and descriptor.payload_type == rtp_packet.payload_type), None)
            routed_transport = bool(rtp_packet is not None and rtp_packet.payload_type in routed_payload_types)
            hevc_epoch_compatible = bool(active_route_descriptor is None or active_route_descriptor.codec == 'hevc')
            conflicting_h264_route = bool(rtp_packet is not None and rtp_packet.payload_type in route_epoch_profile.codec_payload_types('h264'))
            wrapped_media = routed_transport and hevc_epoch_compatible and _owner._looks_like_idmx_hevc_media_frame(body)
            direct_media = routed_transport and hevc_epoch_compatible and (authoritative_hevc_route or hevc_evidence_seen or _owner._looks_like_idmx_hevc_evidence_frame(body)) and _owner._idmx_hevc_direct_frame_matches_route(body, authoritative_hevc=authoritative_hevc_route, conflicting_h264_route=conflicting_h264_route)
            if wrapped_media:
                hevc_evidence_seen = True
                payload = body[_owner.IDMX_HEVC_MEDIA_FRAME_NAL_OFFSET:]
                decrypt_parameter_sets = True
            elif direct_media:
                hevc_evidence_seen = True
                payload = body
                decrypt_parameter_sets = decrypt_hevc_parameter_sets
            else:
                continue
            if len(payload) < _owner.HEVC_NAL_HEADER_SIZE:
                continue
            nal_type = _owner._hevc_nal_type(payload)
            if nal_type == 49 and len(payload) >= 3:
                if payload[2] & 128:
                    active_start_packet = packet_index
                    active_start_frame = frame_index
                    active_nal_type = payload[2] & 63
                nal_start_packet = active_start_packet
                nal_start_frame = active_start_frame
                emitted_nal_type = active_nal_type
            else:
                nal_start_packet = packet_index
                nal_start_frame = frame_index
                emitted_nal_type = nal_type
            start_offset = len(output)
            active_fu = _owner._append_idmx_hevc_media_payload(output, payload, aes_key, active_fu=active_fu, sequence_number=_owner._idmx_local_frame_sequence_number(frame, frame_header_size), rtp_timestamp=_owner._idmx_local_frame_rtp_timestamp(frame, frame_header_size), rtp_marker=_owner._idmx_local_frame_rtp_marker(frame, frame_header_size), decrypt_parameter_sets=decrypt_parameter_sets)
            if nal_type == 49 and active_fu is not None:
                active_end_packet = packet_index
                active_end_frame = frame_index
            if len(output) > start_offset:
                spans.append((start_offset, len(output), nal_start_packet if nal_start_packet is not None else packet_index, packet_index, emitted_nal_type if emitted_nal_type is not None else nal_type, nal_start_frame if nal_start_frame is not None else frame_index, frame_index))
            if active_fu is None:
                active_start_packet = None
                active_start_frame = None
                active_end_packet = None
                active_end_frame = None
                active_nal_type = None
    if active_fu is not None:
        start_offset = len(output)
        _owner._append_decrypted_hevc_nal(output, bytes(active_fu.data), aes_key)
        end_packet = active_end_packet if active_end_packet is not None else max(len(packets) - 1, 0)
        end_frame = active_end_frame if active_end_frame is not None else 0
        spans.append((start_offset, len(output), active_start_packet if active_start_packet is not None else end_packet, end_packet, active_nal_type if active_nal_type is not None else _owner._hevc_nal_type(bytes(active_fu.data)), active_start_frame if active_start_frame is not None else end_frame, end_frame))
    return (bytes(output), spans)

def _idmx_h264_packets_from_selected_annexb(packets: list[bytes], *, full_annexb: bytes, selected_annexb: bytes, media_key: str | bytes, nalu_header_size: int | None, stream_is_clear: bool, _owner: _ModuleType) -> list[bytes]:
    """Return the packet interval contributing selected H.264 VCL NALs."""
    _annexb, spans = _owner._idmx_h264_annexb_packet_spans(packets, media_key, nalu_header_size=nalu_header_size, stream_is_clear=stream_is_clear)
    return _owner._idmx_packets_for_selected_vcl_spans(packets, spans=spans, full_annexb=full_annexb, selected_annexb=selected_annexb, video_input_format='h264')

def _idmx_packet_frame_slice(packet: bytes, start: int, stop: int, *, video_payload_types: frozenset[int], _owner: _ModuleType) -> bytes:
    frames = list(_owner._iter_idmx_local_packet_frame(packet, video_payload_types=video_payload_types))
    if start == 0 and stop == len(frames):
        return packet
    return b''.join(len(frame).to_bytes(4, 'little') + frame for frame in frames[start:stop])

def _idmx_packets_for_selected_vcl_spans(packets: list[bytes], *, spans: list[tuple[int, int, int, int, int, int, int]], full_annexb: bytes, selected_annexb: bytes, video_input_format: str, _owner: _ModuleType) -> list[bytes]:
    """Return packets and aggregate frames bounded by selected VCL NALs."""
    selected_bounds = _owner._annexb_vcl_bounds(selected_annexb, video_input_format=video_input_format)
    if selected_bounds is None:
        raise _owner.PyEzvizError('Trimmed IDMX stream did not include a video frame')
    first_vcl_offset, last_vcl_end = selected_bounds
    retained_tail = selected_annexb[first_vcl_offset:]
    retained_tail_offset = full_annexb.rfind(retained_tail)
    if retained_tail_offset >= 0:
        selected_start = retained_tail_offset
        selected_end = retained_tail_offset + last_vcl_end - first_vcl_offset
    else:
        first_vcl = selected_annexb[first_vcl_offset:last_vcl_end]
        selected_start = full_annexb.rfind(first_vcl)
        selected_end = selected_start + len(first_vcl)
    if selected_start < 0:
        raise _owner.PyEzvizError('Could not align trimmed IDMX video with its RTP packets')
    selected_spans = [span for span in spans if span[0] >= selected_start and span[1] <= selected_end and (1 <= span[4] <= 5 if video_input_format == 'h264' else span[4] <= 31)]
    if not selected_spans:
        raise _owner.PyEzvizError('Could not align trimmed IDMX video with its RTP packets')
    first_span = selected_spans[0]
    last_span = selected_spans[-1]
    start_packet = first_span[2]
    end_packet = last_span[3]
    video_payload_types = _owner._idmx_local_video_payload_types(packets, codec=_owner.cast('_owner_types.RtpVideoCodec', video_input_format))
    if start_packet == end_packet:
        return [_owner._idmx_packet_frame_slice(packets[start_packet], first_span[5], last_span[6] + 1, video_payload_types=video_payload_types)]
    selected_packets = [_owner._idmx_packet_frame_slice(packets[start_packet], first_span[5], len(list(_owner._iter_idmx_local_packet_frame(packets[start_packet], video_payload_types=video_payload_types))), video_payload_types=video_payload_types), *packets[start_packet + 1:end_packet], _owner._idmx_packet_frame_slice(packets[end_packet], 0, last_span[6] + 1, video_payload_types=video_payload_types)]
    return [packet for packet in selected_packets if packet]

def _idmx_packets_from_selected_annexb(packets: list[bytes], *, full_annexb: bytes, selected_annexb: bytes, media_key: str | bytes, nalu_header_size: int | None, video_input_format: str, _owner: _ModuleType) -> list[bytes]:
    """Keep packets from the first selected VCL NAL for aligned audio muxing."""
    if video_input_format == 'h264':
        _annexb, spans = _owner._idmx_h264_annexb_packet_spans(packets, media_key, nalu_header_size=nalu_header_size, stream_is_clear=False)
    else:
        _annexb, spans = _owner._idmx_hevc_annexb_packet_spans(packets, media_key)
    return _owner._idmx_packets_for_selected_vcl_spans(packets, spans=spans, full_annexb=full_annexb, selected_annexb=selected_annexb, video_input_format=video_input_format)

def _h264_annexb_packet_index_for_offset(packets: list[bytes], *, offset: int, _owner: _ModuleType) -> int:
    """Return the packet index that first contributes the clear Annex-B offset."""
    end_offsets = _owner._h264_annexb_packet_end_offsets(packets)
    index = _owner.bisect.bisect_right(end_offsets, offset)
    return min(index, max(len(packets) - 1, 0))

def _hevc_annexb_packet_index_for_offset(packets: list[bytes], *, offset: int, _owner: _ModuleType) -> int:
    """Return the packet index that first contributes the clear HEVC Annex-B offset."""
    end_offsets = _owner._hevc_annexb_packet_end_offsets(packets)
    index = _owner.bisect.bisect_right(end_offsets, offset)
    return min(index, max(len(packets) - 1, 0))

def _idmx_annexb_packet_index_for_offset(packets: list[bytes], *, codec: str, offset: int, _owner: _ModuleType) -> int:
    if codec == 'h264':
        return _owner._h264_annexb_packet_index_for_offset(packets, offset=offset)
    if codec == 'hevc':
        return _owner._hevc_annexb_packet_index_for_offset(packets, offset=offset)
    return max(len(packets) - 1, 0)

def _try_first_clean_h264_annexb_idr_window_offset_from_annexb(annexb: bytes, *, ffmpeg_path: str, max_windows: int, _owner: _ModuleType) -> _owner_types._H264CleanIdrProbeResult:
    """Return the first clean IDR window offset for Annex-B H.264 bytes."""
    idr_summary = _owner.summarize_h264_annexb_idr_windows(annexb, max_windows=max_windows)
    samples = idr_summary.get('samples')
    if not isinstance(samples, list):
        return _owner._H264CleanIdrProbeResult(start_offset=None, idr_count=int(idr_summary.get('idr_count', 0)), nal_count=int(idr_summary.get('nal_count', 0)))
    first_decode_error: str | None = None
    complete_window_count = 0
    for sample in samples:
        if not isinstance(sample, dict):
            continue
        end_nal_index = sample.get('end_nal_index')
        if not isinstance(end_nal_index, int) or end_nal_index >= int(idr_summary['nal_count']):
            continue
        start_offset = sample.get('start_code_offset')
        end_offset = sample.get('end_offset')
        if not isinstance(start_offset, int) or not isinstance(end_offset, int) or end_offset <= start_offset:
            continue
        complete_window_count += 1
        decode_errors = _owner._ffmpeg_h264_decode_errors(annexb[start_offset:end_offset], ffmpeg_path=ffmpeg_path, accept_success_with_stderr=False)
        if not decode_errors:
            return _owner._H264CleanIdrProbeResult(start_offset=start_offset, idr_start_offset=int(sample['idr_start_code_offset']), first_decode_error=first_decode_error, idr_count=int(idr_summary.get('idr_count', 0)), sampled_window_count=len(samples), complete_window_count=complete_window_count, nal_count=int(idr_summary.get('nal_count', 0)))
        if first_decode_error is None:
            first_decode_error = decode_errors[0]
    return _owner._H264CleanIdrProbeResult(start_offset=None, first_decode_error=first_decode_error, idr_count=int(idr_summary.get('idr_count', 0)), sampled_window_count=len(samples), complete_window_count=complete_window_count, nal_count=int(idr_summary.get('nal_count', 0)))

def _ffmpeg_h264_decode_errors(data: bytes, *, ffmpeg_path: str, accept_success_with_stderr: bool, _owner: _ModuleType) -> list[str]:
    lines = _owner._ffmpeg_video_decode_errors(data, ffmpeg_path=ffmpeg_path, input_format='h264', accept_success_with_stderr=accept_success_with_stderr)
    if accept_success_with_stderr:
        return lines
    saw_missing_picture_probe = any('missing picture in access unit' in line or 'no frame!' in line for line in lines)
    return [line for line in lines if 'missing picture in access unit' not in line and 'no frame!' not in line and (not (saw_missing_picture_probe and 'Decoding error: Invalid data found when processing input' in line))]

def _ffmpeg_hevc_decode_errors(data: bytes, *, ffmpeg_path: str, accept_success_with_stderr: bool, _owner: _ModuleType) -> list[str]:
    return _owner._ffmpeg_video_decode_errors(data, ffmpeg_path=ffmpeg_path, input_format='hevc', accept_success_with_stderr=accept_success_with_stderr)

def _ffmpeg_video_decode_errors(data: bytes, *, ffmpeg_path: str, input_format: str, accept_success_with_stderr: bool, _owner: _ModuleType) -> list[str]:
    timeout_seconds = _owner._ffmpeg_video_decode_probe_timeout_seconds(data)
    try:
        completed = _owner.subprocess.run([ffmpeg_path, '-v', 'error', '-f', input_format, '-i', 'pipe:0', '-f', 'null', '-'], input=data, stdout=_owner.subprocess.DEVNULL, stderr=_owner.subprocess.PIPE, check=False, timeout=timeout_seconds)
    except OSError as err:
        raise _owner.PyEzvizError(f'Could not launch FFmpeg at {ffmpeg_path!r}: {err}') from err
    except _owner.subprocess.TimeoutExpired:
        return [f'ffmpeg video decode check timed out after {timeout_seconds}s']
    stderr_text = completed.stderr.decode('utf-8', errors='replace')
    lines = [line for line in stderr_text.splitlines() if line]
    if completed.returncode == 0 and accept_success_with_stderr:
        return []
    if completed.returncode != 0 and (not lines):
        lines.append(f'ffmpeg exited with status {completed.returncode}')
    return lines[:8]

def _ffmpeg_video_decode_probe_timeout_seconds(data: bytes, *, _owner: _ModuleType) -> int:
    """Keep tiny decode probes quick while allowing full suffix checks to finish."""
    extra_seconds = len(data) // _owner._FFMPEG_VIDEO_DECODE_PROBE_BYTES_PER_EXTRA_SECOND
    return min(_owner._FFMPEG_VIDEO_DECODE_PROBE_MAX_TIMEOUT_SECONDS, _owner._FFMPEG_VIDEO_DECODE_PROBE_TIMEOUT_SECONDS + extra_seconds)

def _hevc_annexb_irap_window_start_index(nal_types: list[int], irap_nal_index: int, *, _owner: _ModuleType) -> int:
    start = irap_nal_index
    while start > 0 and nal_types[start - 1] in {32, 33, 34, 35, 39, 40}:
        start -= 1
    return start
