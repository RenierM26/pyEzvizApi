# Runtime hook context is explicit; immutable value types come from dependency leaves.
# ruff: noqa: SLF001
"""capture implementation; legacy runtime hooks remain on the owner module.

Access through _owner is deliberate: callers that patch the compatibility
module must still affect dependent operations. No copied hook snapshots.
"""

from __future__ import annotations

from types import ModuleType as _ModuleType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pyezvizapi._typing.local_stream as _owner_types


def copy_local_stream_to_mpegps(
    stream: _owner_types.Any,
    output: _owner_types.BinaryIO,
    *,
    max_packets: int | None,
    duration_seconds: float | None,
    monotonic: _owner_types.Callable[[], float],
    _owner: _ModuleType,
) -> None:
    """Write local MPEG-PS payloads directly without an FFmpeg subprocess."""
    _owner._write_local_stream_payloads(
        stream,
        output,
        max_packets=max_packets,
        duration_seconds=duration_seconds,
        monotonic=monotonic,
    )


def collect_local_stream_mpegps(
    stream: _owner_types.Any,
    *,
    max_packets: int | None,
    duration_seconds: float | None,
    monotonic: _owner_types.Callable[[], float],
    _owner: _ModuleType,
) -> bytes:
    """Collect bounded local MPEG-PS payloads into memory.

    This is intended for transforms, such as the EZVIZ encrypted-video NAL
    decrypt pass, that need complete MPEG-PS packet context across local RTP
    packet boundaries.
    """
    return b"".join(
        _owner._iter_local_stream_payloads(
            stream, max_packets=max_packets, duration_seconds=duration_seconds, monotonic=monotonic
        )
    )


def copy_local_stream_to_decrypted_mpegps(
    stream: _owner_types.Any,
    output: _owner_types.BinaryIO,
    media_key: str | bytes,
    *,
    nalu_header_size: int | None,
    max_packets: int | None,
    duration_seconds: float | None,
    monotonic: _owner_types.Callable[[], float],
    _owner: _ModuleType,
) -> None:
    """Collect, decrypt and write local MPEG-PS payloads.

    Decryption is deliberately bounded by max_packets or duration_seconds
    because the MPEG-PS/NAL transform is stateful across packet splits and must
    operate on an in-memory capture.
    """
    _owner._require_bounded_decrypt_capture(
        max_packets=max_packets, duration_seconds=duration_seconds
    )
    packets = _owner.collect_local_stream_media_packets(
        stream, max_packets=max_packets, duration_seconds=duration_seconds, monotonic=monotonic
    )
    if _owner._local_stream_packets_are_idmx(packets):
        raise _owner._unsupported_idmx_local_payload_error()
    payload = b"".join(packets)
    output.write(
        _owner.decrypt_hikvision_ps_video(payload, media_key, nalu_header_size=nalu_header_size)
    )
    output.flush()


def copy_local_stream_to_decrypted_mpegts(  # noqa: PLR0912, PLR0913, PLR0915 -- explicit runtime context plus retained signature
    stream: _owner_types.Any,
    output: _owner_types.BinaryIO,
    media_key: str | bytes,
    *,
    ffmpeg_path: str,
    nalu_header_size: int | None,
    max_packets: int | None,
    duration_seconds: float | None,
    monotonic: _owner_types.Callable[[], float],
    h264_skip_initial_idr_windows: int,
    h264_trim_to_clean_idr_window: bool,
    h264_clean_idr_preroll_seconds: float,
    h264_clean_idr_max_windows: int,
    h264_wait_for_clean_idr_window: bool,
    h264_clean_idr_wait_seconds: float,
    decrypt_hevc_parameter_sets: bool,
    native_shared_clock: bool,
    app_relative_clock: bool,
    _owner: _ModuleType,
) -> None:
    """Collect, decrypt, remux and write local MPEG-TS bytes."""
    if app_relative_clock and native_shared_clock:
        raise _owner.PyEzvizError(
            "app_relative_clock and native_shared_clock are mutually exclusive"
        )
    if app_relative_clock and (
        h264_wait_for_clean_idr_window
        or h264_skip_initial_idr_windows
        or h264_trim_to_clean_idr_window
        or h264_clean_idr_preroll_seconds
    ):
        raise _owner.PyEzvizError("app_relative_clock requires full startup without trimming")
    if native_shared_clock and (
        h264_wait_for_clean_idr_window
        or h264_skip_initial_idr_windows
        or h264_trim_to_clean_idr_window
        or h264_clean_idr_preroll_seconds
    ):
        raise _owner.PyEzvizError("native_shared_clock does not support encrypted startup trimming")
    if h264_wait_for_clean_idr_window:
        _, payload_duration_seconds = _owner.h264_clean_idr_capture_budgets(
            duration_seconds=duration_seconds,
            h264_skip_initial_idr_windows=h264_skip_initial_idr_windows,
            h264_trim_to_clean_idr_window=h264_trim_to_clean_idr_window,
            h264_clean_idr_preroll_seconds=h264_clean_idr_preroll_seconds,
            h264_clean_idr_max_windows=h264_clean_idr_max_windows,
            h264_wait_for_clean_idr_window=h264_wait_for_clean_idr_window,
            h264_clean_idr_wait_seconds=h264_clean_idr_wait_seconds,
        )
        _owner._require_bounded_decrypt_capture(
            max_packets=max_packets, duration_seconds=payload_duration_seconds
        )
        payloads = _owner._iter_local_stream_payloads(
            stream,
            max_packets=max_packets,
            duration_seconds=payload_duration_seconds,
            monotonic=monotonic,
        )
        recorded_packets: list[bytes] = []

        def record_payloads() -> _owner_types.Iterator[bytes]:
            for payload in payloads:
                recorded_packets.append(payload)
                yield payload

        annexb = _owner.collect_decrypted_h264_idmx_annexb_after_first_clean_idr_window(
            record_payloads(),
            media_key,
            nalu_header_size=nalu_header_size,
            duration_seconds=duration_seconds,
            monotonic=monotonic,
            ffmpeg_path=ffmpeg_path,
            max_windows=h264_clean_idr_max_windows,
            wait_seconds=h264_clean_idr_wait_seconds,
        )
        full_annexb = _owner._decrypt_idmx_local_packets_to_annexb(
            recorded_packets, media_key, nalu_header_size=nalu_header_size
        )
        stream_is_clear = False
        with _owner.suppress(_owner.PyEzvizError):
            clear_annexb = _owner._idmx_local_packets_to_h264_annexb(recorded_packets)
            if _owner._annexb_contains_selected_vcl(
                clear_annexb, annexb, video_input_format="h264"
            ):
                full_annexb = clear_annexb
                stream_is_clear = True
        selected_packets = _owner._idmx_h264_packets_from_selected_annexb(
            recorded_packets,
            full_annexb=full_annexb,
            selected_annexb=annexb,
            media_key=media_key,
            nalu_header_size=nalu_header_size,
            stream_is_clear=stream_is_clear,
        )
        audio_metadata = _owner._idmx_audio_metadata(recorded_packets, media_key)
        audio_payload_types = _owner._idmx_audio_payload_types(recorded_packets)
        audio = _owner._decrypt_idmx_local_packets_to_adts_aac(
            selected_packets,
            media_key,
            audio_metadata=audio_metadata,
            audio_payload_types=audio_payload_types,
        )
        if native_shared_clock or app_relative_clock:
            raise _owner.PyEzvizError(
                f"{('app_relative_clock' if app_relative_clock else 'native_shared_clock')} requires genuine native RTP AV timing"
            )
        if audio is not None:
            _owner._copy_idmx_audio_video_to_mpegts(
                annexb,
                audio,
                output,
                ffmpeg_path=ffmpeg_path,
                video_input_format="h264",
                video_frame_rate=None,
            )
            return
        process = _owner._open_local_h264_mpegts_remux_process(ffmpeg_path)
        _owner._copy_mpegps_payloads_to_mpegts([annexb], output, process=process)
        return
    capture_duration_seconds, _ = _owner.h264_clean_idr_capture_budgets(
        duration_seconds=duration_seconds,
        h264_skip_initial_idr_windows=h264_skip_initial_idr_windows,
        h264_trim_to_clean_idr_window=h264_trim_to_clean_idr_window,
        h264_clean_idr_preroll_seconds=h264_clean_idr_preroll_seconds,
        h264_clean_idr_max_windows=h264_clean_idr_max_windows,
        h264_wait_for_clean_idr_window=h264_wait_for_clean_idr_window,
        h264_clean_idr_wait_seconds=h264_clean_idr_wait_seconds,
    )
    _owner._require_bounded_decrypt_capture(
        max_packets=max_packets, duration_seconds=capture_duration_seconds
    )
    packets = _owner.collect_local_stream_media_packets(
        stream,
        max_packets=max_packets,
        duration_seconds=capture_duration_seconds,
        monotonic=monotonic,
    )
    if not packets:
        raise _owner.EzvizNoMediaError(
            "EZVIZ local stream supplied no media packets within the capture bound"
        )
    if _owner._local_stream_packets_are_idmx(packets):
        annexb, authoritative_video_codec = _owner._decrypt_idmx_local_packets_to_annexb_with_codec(
            packets,
            media_key,
            nalu_header_size=nalu_header_size,
            decrypt_hevc_parameter_sets=decrypt_hevc_parameter_sets,
        )
        full_annexb = annexb
        if authoritative_video_codec == "h264" or (
            authoritative_video_codec is None and _owner._annexb_has_h264_vcl(annexb)
        ):
            annexb = _owner.skip_h264_annexb_initial_idr_windows(
                annexb, h264_skip_initial_idr_windows
            )
            if h264_trim_to_clean_idr_window or h264_wait_for_clean_idr_window:
                annexb = _owner.trim_h264_annexb_to_first_clean_idr_window(
                    annexb, ffmpeg_path=ffmpeg_path, max_windows=h264_clean_idr_max_windows
                )
            video_input_format = "h264"
            video_frame_rate = None
        elif authoritative_video_codec == "hevc" or _owner._annexb_looks_like_hevc(annexb):
            annexb = _owner.skip_hevc_annexb_initial_irap_windows(
                annexb, h264_skip_initial_idr_windows
            )
            if h264_trim_to_clean_idr_window:
                annexb = _owner.trim_hevc_annexb_to_first_clean_irap_window(
                    annexb, ffmpeg_path=ffmpeg_path, max_windows=h264_clean_idr_max_windows
                )
            video_input_format = "hevc"
            video_frame_rate = _owner._idmx_local_video_frame_rate(packets)
        elif _owner._annexb_looks_like_h264(annexb):
            video_input_format = "h264"
            video_frame_rate = None
        else:
            raise _owner.PyEzvizError("EZVIZ local IDMX stream did not include video frames")
        audio = None
        if _owner._idmx_local_packets_have_aac(packets):
            selected_packets = (
                packets
                if annexb == full_annexb
                else _owner._idmx_packets_from_selected_annexb(
                    packets,
                    full_annexb=full_annexb,
                    selected_annexb=annexb,
                    media_key=media_key,
                    nalu_header_size=nalu_header_size,
                    video_input_format=video_input_format,
                )
            )
            audio = _owner._decrypt_idmx_local_packets_to_adts_aac(
                selected_packets,
                media_key,
                audio_metadata=_owner._idmx_audio_metadata(packets, media_key),
                audio_payload_types=_owner._idmx_audio_payload_types(packets),
                require_contiguous=False,
                allow_timestamp_jitter=True,
            )
        if annexb == full_annexb:
            codec: _owner_types.RtpVideoCodec = "hevc" if video_input_format == "hevc" else "h264"
            if _owner._copy_decrypted_native_idmx_timed_av(
                packets,
                annexb,
                audio,
                output,
                codec=codec,
                ffmpeg_path=ffmpeg_path,
                media_key=media_key,
                nalu_header_size=nalu_header_size,
                decrypt_hevc_parameter_sets=decrypt_hevc_parameter_sets,
                **_owner._native_timing_options(
                    native_shared_clock, app_relative_clock=app_relative_clock
                ),
            ):
                return
        if native_shared_clock or app_relative_clock:
            raise _owner.PyEzvizError(
                f"{('app_relative_clock' if app_relative_clock else 'native_shared_clock')} requires genuine native RTP AV timing"
            )
        if audio is not None:
            _owner._copy_idmx_audio_video_to_mpegts(
                annexb,
                audio,
                output,
                ffmpeg_path=ffmpeg_path,
                video_input_format=video_input_format,
                video_frame_rate=video_frame_rate,
            )
            return
        if video_input_format == "hevc":
            process = _owner._open_local_hevc_mpegts_remux_process(
                ffmpeg_path, frame_rate=video_frame_rate
            )
        else:
            process = _owner._open_local_h264_mpegts_remux_process(ffmpeg_path)
        _owner._copy_mpegps_payloads_to_mpegts([annexb], output, process=process)
        return
    if (
        h264_skip_initial_idr_windows
        or h264_trim_to_clean_idr_window
        or h264_wait_for_clean_idr_window
    ):
        raise _owner.PyEzvizError(
            "H.264 startup trim options require a decrypted H.264 IDMX stream"
        )
    if native_shared_clock or app_relative_clock:
        raise _owner.PyEzvizError(
            f"{('app_relative_clock' if app_relative_clock else 'native_shared_clock')} requires native RTP media, not MPEG-PS"
        )
    decrypted = _owner.decrypt_hikvision_ps_video(
        b"".join(packets), media_key, nalu_header_size=nalu_header_size
    )
    process = _owner._open_local_mpegts_remux_process(ffmpeg_path)
    _owner._copy_mpegps_payloads_to_mpegts([decrypted], output, process=process)


def _require_bounded_decrypt_capture(
    *, max_packets: int | None, duration_seconds: float | None, _owner: _ModuleType
) -> None:
    if not _owner.has_positive_finite_capture_bound(
        max_packets=max_packets, duration_seconds=duration_seconds
    ):
        raise _owner.PyEzvizError(
            "Encrypted local stream decrypt requires a positive finite duration_seconds or max_packets"
        )


def _require_bounded_idmx_capture(
    *, max_packets: int | None, duration_seconds: float | None, _owner: _ModuleType
) -> None:
    if max_packets is None and duration_seconds is None:
        raise _owner.PyEzvizError(
            "EZVIZ local IDMX stream remux requires duration_seconds or max_packets"
        )


def copy_local_stream_to_mpegts(  # noqa: PLR0912, PLR0913, PLR0915 -- explicit runtime context plus retained signature
    stream: _owner_types.Any,
    output: _owner_types.BinaryIO,
    *,
    ffmpeg_path: str,
    max_packets: int | None,
    duration_seconds: float | None,
    monotonic: _owner_types.Callable[[], float],
    h264_skip_initial_idr_windows: int,
    h264_trim_to_clean_idr_window: bool,
    h264_clean_idr_preroll_seconds: float,
    h264_clean_idr_max_windows: int,
    h264_wait_for_clean_idr_window: bool,
    h264_clean_idr_wait_seconds: float,
    native_shared_clock: bool,
    app_relative_clock: bool,
    _owner: _ModuleType,
) -> None:
    """Pipe local media payloads through FFmpeg and write MPEG-TS bytes."""
    if app_relative_clock and native_shared_clock:
        raise _owner.PyEzvizError(
            "app_relative_clock and native_shared_clock are mutually exclusive"
        )
    if app_relative_clock and (
        h264_wait_for_clean_idr_window
        or h264_skip_initial_idr_windows
        or h264_trim_to_clean_idr_window
        or h264_clean_idr_preroll_seconds
    ):
        raise _owner.PyEzvizError("app_relative_clock requires full startup without trimming")
    if native_shared_clock or app_relative_clock:
        _owner._require_bounded_idmx_capture(
            max_packets=max_packets, duration_seconds=duration_seconds
        )
    _, payload_duration_seconds = _owner.h264_clean_idr_capture_budgets(
        duration_seconds=duration_seconds,
        h264_skip_initial_idr_windows=h264_skip_initial_idr_windows,
        h264_trim_to_clean_idr_window=h264_trim_to_clean_idr_window,
        h264_clean_idr_preroll_seconds=h264_clean_idr_preroll_seconds,
        h264_clean_idr_max_windows=h264_clean_idr_max_windows,
        h264_wait_for_clean_idr_window=h264_wait_for_clean_idr_window,
        h264_clean_idr_wait_seconds=h264_clean_idr_wait_seconds,
    )
    payloads = _owner._iter_local_stream_payloads(
        stream,
        max_packets=max_packets,
        duration_seconds=payload_duration_seconds,
        monotonic=monotonic,
    )
    try:
        first_payload = next(payloads)
    except StopIteration:
        raise _owner.PyEzvizError("EZVIZ local stream did not include media payloads") from None
    while _owner._is_ignorable_leading_stream_payload(first_payload):
        try:
            first_payload = next(payloads)
        except StopIteration:
            raise _owner.PyEzvizError("EZVIZ local stream did not include media payloads") from None
    if _owner._looks_like_idmx_local_payload(first_payload):
        _owner._require_bounded_idmx_capture(
            max_packets=max_packets, duration_seconds=duration_seconds
        )
        is_h264_startup_options = bool(
            h264_skip_initial_idr_windows or h264_trim_to_clean_idr_window
        )
        annexb_codec: str | None = None
        annexb_is_h264 = False
        packets: list[bytes] = []
        if h264_wait_for_clean_idr_window:

            def recorded_payloads() -> _owner_types.Iterator[bytes]:
                for payload in _owner.chain((first_payload,), payloads):
                    packets.append(payload)
                    yield payload

            annexb, annexb_codec = _owner.collect_idmx_annexb_after_first_clean_video_window(
                recorded_payloads(),
                duration_seconds=duration_seconds,
                monotonic=monotonic,
                ffmpeg_path=ffmpeg_path,
                max_windows=h264_clean_idr_max_windows,
                wait_seconds=h264_clean_idr_wait_seconds,
            )
            annexb_is_h264 = annexb_codec == "h264"
        else:
            packets = list(_owner.chain((first_payload,), payloads))
            if not is_h264_startup_options:
                audio_metadata = _owner._idmx_audio_descriptor(packets)
                audio = (
                    _owner._decrypt_idmx_local_packets_to_adts_aac(
                        packets,
                        b"",
                        audio_metadata=audio_metadata,
                        require_contiguous=False,
                        decrypt_audio=False,
                        allow_timestamp_jitter=True,
                    )
                    if audio_metadata is not None
                    else None
                )
                if _owner._copy_clear_native_idmx_timed_av(
                    packets,
                    audio,
                    output,
                    ffmpeg_path=ffmpeg_path,
                    **_owner._native_timing_options(
                        native_shared_clock, app_relative_clock=app_relative_clock
                    ),
                ):
                    return
            if is_h264_startup_options:
                annexb, annexb_codec = _owner._idmx_local_packets_to_h264_annexb_with_codec(packets)
                annexb_is_h264 = annexb_codec == "h264"
            else:
                annexb, annexb_codec = _owner._idmx_local_packets_to_annexb_with_codec(packets)
                annexb_is_h264 = annexb_codec == "h264"
        if not annexb_is_h264 and _owner._annexb_looks_like_hevc(annexb):
            if not h264_wait_for_clean_idr_window:
                annexb = _owner.skip_hevc_annexb_initial_irap_windows(
                    annexb, h264_skip_initial_idr_windows
                )
                if h264_trim_to_clean_idr_window:
                    annexb = _owner.trim_hevc_annexb_to_first_clean_irap_window(
                        annexb, ffmpeg_path=ffmpeg_path, max_windows=h264_clean_idr_max_windows
                    )
            video_input_format = "hevc"
            video_frame_rate = (
                None
                if h264_wait_for_clean_idr_window
                else _owner._idmx_local_video_frame_rate(packets)
            )
        else:
            annexb = _owner.skip_h264_annexb_initial_idr_windows(
                annexb, h264_skip_initial_idr_windows
            )
            if h264_trim_to_clean_idr_window:
                annexb = _owner.trim_h264_annexb_to_first_clean_idr_window(
                    annexb, ffmpeg_path=ffmpeg_path, max_windows=h264_clean_idr_max_windows
                )
            video_input_format = "h264"
            video_frame_rate = None
        if (
            is_h264_startup_options or h264_wait_for_clean_idr_window
        ) and _owner._copy_clear_native_idmx_timed_av(
            packets,
            None,
            output,
            ffmpeg_path=ffmpeg_path,
            selected_annexb=annexb,
            selected_codec=_owner.cast("_owner_types.RtpVideoCodec", video_input_format),
            **_owner._native_timing_options(
                native_shared_clock, app_relative_clock=app_relative_clock
            ),
        ):
            return
        if native_shared_clock or app_relative_clock:
            raise _owner.PyEzvizError(
                f"{('app_relative_clock' if app_relative_clock else 'native_shared_clock')} requires genuine native RTP AV timing"
            )
        if not (is_h264_startup_options or h264_wait_for_clean_idr_window):
            audio_metadata = _owner._idmx_audio_descriptor(packets)
            if audio_metadata is not None:
                audio = _owner._decrypt_idmx_local_packets_to_adts_aac(
                    packets,
                    b"",
                    audio_metadata=audio_metadata,
                    require_contiguous=False,
                    decrypt_audio=False,
                    allow_timestamp_jitter=True,
                )
                if audio is not None:
                    _owner._copy_idmx_audio_video_to_mpegts(
                        annexb,
                        audio,
                        output,
                        ffmpeg_path=ffmpeg_path,
                        video_input_format=video_input_format,
                        video_frame_rate=video_frame_rate,
                    )
                    return
        process = (
            _owner._open_local_hevc_mpegts_remux_process(ffmpeg_path, frame_rate=video_frame_rate)
            if video_input_format == "hevc"
            else _owner._open_local_h264_mpegts_remux_process(ffmpeg_path)
        )
        _owner._copy_mpegps_payloads_to_mpegts([annexb], output, process=process)
        return
    if (
        h264_skip_initial_idr_windows
        or h264_trim_to_clean_idr_window
        or h264_wait_for_clean_idr_window
    ):
        raise _owner.PyEzvizError("H.264 startup trim options require a clear H.264 IDMX stream")
    if native_shared_clock or app_relative_clock:
        raise _owner.PyEzvizError(
            f"{('app_relative_clock' if app_relative_clock else 'native_shared_clock')} requires native RTP media, not MPEG-PS"
        )
    if not first_payload.startswith(_owner.MPEG_PS_START_CODE):
        raise _owner.PyEzvizError(
            "Unsupported EZVIZ local stream payload format: expected MPEG-PS payload"
        )
    process = _owner._open_local_mpegts_remux_process(ffmpeg_path)
    _owner._copy_mpegps_payloads_to_mpegts(
        _owner.chain((first_payload,), payloads), output, process=process
    )


def _clear_native_rtp_packets_with_legacy_indices(
    packets: list[bytes], video_types: frozenset[int], *, _owner: _ModuleType
) -> tuple[list[_owner_types.RtpPacket], set[int]]:
    """Separate genuine RTP media clocks from legacy native-body wrappers."""
    rtp_packets: list[_owner_types.RtpPacket] = []
    legacy_video_indices: set[int] = set()
    for frame in _owner._iter_idmx_local_packet_frames(packets):
        header = _owner._idmx_local_frame_header_size(frame)
        if header is not None:
            packet = _owner._idmx_local_frame_rtp_packet(frame, header)
            if packet is not None:
                rtp_packets.append(packet)
                if packet.payload_type in video_types and (
                    not _owner._is_complete_idmx_rtp_frame(frame)
                    or (
                        packet.extension_profile is None
                        and _owner._looks_like_idmx_hevc_media_frame(
                            _owner._idmx_local_frame_media_body(frame, header)
                        )
                    )
                ):
                    legacy_video_indices.add(len(rtp_packets) - 1)
    return (rtp_packets, legacy_video_indices)


def _copy_clear_native_idmx_timed_av(  # noqa: PLR0912 -- explicit runtime context plus retained signature
    packets: list[bytes],
    audio: _owner_types.RtpAacStream | None,
    output: _owner_types.BinaryIO,
    *,
    ffmpeg_path: str,
    selected_annexb: bytes | None,
    selected_codec: _owner_types.RtpVideoCodec | None,
    native_shared_clock: bool,
    app_relative_clock: bool,
    _owner: _ModuleType,
) -> bool:
    """Keep native clear AAC jitter through one timed input, not raw-file probing."""
    if app_relative_clock and selected_annexb is not None:
        raise _owner.PyEzvizError(
            "app_relative_clock requires the complete native startup timeline"
        )
    video_types = _owner._idmx_local_video_payload_types(
        packets, codec="h264"
    ) | _owner._idmx_local_video_payload_types(packets, codec="hevc")
    rtp_packets, legacy_video_indices = _owner._clear_native_rtp_packets_with_legacy_indices(
        packets, video_types
    )
    if legacy_video_indices and selected_annexb is None:
        if native_shared_clock or app_relative_clock:
            raise _owner.PyEzvizError(
                f"{('app_relative_clock' if app_relative_clock else 'native_shared_clock')} requires genuine native RTP video timing"
            )
        return False
    if legacy_video_indices:
        rtp_packets = [
            _owner.replace(packet, payload=b"", payload_type=-1, ssrc=-1)
            if i in legacy_video_indices
            else packet
            for i, packet in enumerate(rtp_packets)
        ]
    advertised_rate = _owner.idmx_video_frame_rate(rtp_packets)
    if advertised_rate is None:
        if native_shared_clock or app_relative_clock:
            raise _owner.PyEzvizError(
                f"{('app_relative_clock' if app_relative_clock else 'native_shared_clock')} requires genuine native RTP video timing"
            )
        return False
    codec = (
        selected_codec
        if selected_annexb is not None and selected_codec is not None
        else _owner.detect_rtp_video_codec(rtp_packets, allow_ezviz_headerless_hevc_fu=True)
    )
    timestamps: list[int] = []
    source_keys: list[_owner_types.RtpSequenceKey] = []
    units = _owner.rtp_packets_to_nal_units(
        rtp_packets,
        codec=codec,
        completed_access_units_only=selected_annexb is None,
        allow_ezviz_headerless_hevc_fu=True,
        nal_timestamps=timestamps,
        nal_source_keys=source_keys,
    )
    if app_relative_clock and len(set(source_keys)) > 1:
        raise _owner.EzvizUnsupportedMediaError(
            "app_relative_clock cannot combine multiple video source clocks",
            source="rtp",
            reason="unsupported_av_clock",
        )
    if (
        (native_shared_clock or app_relative_clock)
        and selected_annexb is None
        and (
            len(
                {
                    source_keys[i]
                    for i, unit in enumerate(units)
                    if _owner.rtp_nal_units_have_vcl((unit,), codec=codec)
                }
            )
            > 1
        )
    ):
        raise _owner.EzvizUnsupportedMediaError(
            f"{('app_relative_clock' if app_relative_clock else 'native_shared_clock')} cannot combine multiple video source clocks",
            source="rtp",
            reason="unsupported_av_clock",
        )
    if not _owner.rtp_nal_units_have_vcl(units, codec=codec):
        if legacy_video_indices:
            return False
        raise _owner.EzvizNoMediaError(
            "Native capture contained no complete video frame; increase the capture duration"
        )
    if selected_annexb is not None:
        try:
            units, timestamps, selected_packets, boundary_index = (
                _owner._clear_native_selected_timeline(
                    units,
                    timestamps,
                    rtp_packets,
                    selected_annexb,
                    codec,
                    video_types=_owner._idmx_local_video_payload_types(packets, codec=codec),
                    nal_source_keys=source_keys,
                )
            )
        except _owner.PyEzvizError:
            if legacy_video_indices:
                return False
            raise
        strict_units = _owner.rtp_packets_to_nal_units(
            selected_packets,
            codec=codec,
            completed_access_units_only=True,
            allow_ezviz_headerless_hevc_fu=True,
            boundary_only_packet_index=boundary_index,
            video_payload_types=_owner._idmx_local_video_payload_types(packets, codec=codec),
        )
        selected_vcl = tuple(
            unit for unit in units if _owner.rtp_nal_units_have_vcl((unit,), codec=codec)
        )
        strict_vcl = tuple(
            unit for unit in strict_units if _owner.rtp_nal_units_have_vcl((unit,), codec=codec)
        )
        if strict_vcl[: len(selected_vcl)] != selected_vcl:
            raise _owner.PyEzvizError("Clean native video contains an incomplete source picture")
        audio = _owner.decrypt_idmx_aac_packets(
            selected_packets,
            b"",
            require_contiguous=False,
            decrypt_audio=False,
            preserve_clear_timestamps=True,
        )
    if app_relative_clock and codec != "hevc":
        raise _owner.PyEzvizError("app_relative_clock currently requires native HEVC")
    payloads = (
        _owner.native_app_timed_payloads(units, timestamps, audio=audio, frame_rate=advertised_rate)
        if app_relative_clock
        else _owner.timed_rtp_mpegps_payloads(
            units, timestamps, codec=codec, audio=audio, shared_clock=native_shared_clock
        )
    )
    first_payload = next(payloads)
    process = _owner.open_mpegts_remux_process(
        ffmpeg_path,
        input_format="mpeg",
        preserve_timestamps=True,
        popen=_owner.subprocess.Popen,
        **_owner._app_remux_options(app_relative_clock),
    )

    def write_input(stdin: _owner_types.BinaryIO) -> None:
        for payload in _owner.chain((first_payload,), payloads):
            stdin.write(payload)

    _owner.copy_remuxed_output(process, output, write_input=write_input)
    return True


def _clear_native_selected_timeline(
    units: tuple[bytes, ...],
    timestamps: list[int],
    packets: list[_owner_types.RtpPacket],
    selected_annexb: bytes,
    codec: _owner_types.RtpVideoCodec,
    *,
    video_types: frozenset[int],
    nal_source_keys: list[_owner_types.RtpSequenceKey] | None,
    _owner: _ModuleType,
) -> tuple[tuple[bytes, ...], list[int], list[_owner_types.RtpPacket], int | None]:
    """Match the decoded clean suffix, retaining audio only inside its wire interval."""
    selected = tuple(
        (
            selected_annexb[start:end]
            for _prefix, start, end in _owner._h264_annexb_nal_spans(selected_annexb)
        )
    )
    first_vcl = next(
        (
            i
            for i, unit in enumerate(selected)
            if _owner.rtp_nal_units_have_vcl((unit,), codec=codec)
        ),
        None,
    )
    if first_vcl is None:
        raise _owner.EzvizNoMediaError("Clean native window contained no complete video picture")
    tail = selected[first_vcl:]
    matches = [
        i for i, unit in enumerate(units) if unit == tail[0] and units[i : i + len(tail)] == tail
    ]
    if len(matches) != 1:
        raise _owner.PyEzvizError(
            "Clean native video cannot be uniquely matched to source RTP timing"
        )
    start = matches[0]
    stop = start + len(tail)
    last_vcl = max(
        i for i in range(start, stop) if _owner.rtp_nal_units_have_vcl((units[i],), codec=codec)
    )
    if nal_source_keys is not None and len(nal_source_keys) != len(units):
        raise _owner.PyEzvizError("Clean native video has no aligned source RTP identities")
    selected_source = None if nal_source_keys is None else nal_source_keys[last_vcl]
    if nal_source_keys is not None and any(
        nal_source_keys[i] != selected_source
        for i in range(start, stop)
        if _owner.rtp_nal_units_have_vcl((units[i],), codec=codec)
    ):
        raise _owner.PyEzvizError("Clean native video mixes different source RTP identities")
    first_packets = [
        i
        for i, packet in enumerate(packets)
        if packet.payload_type in video_types
        and packet.timestamp == timestamps[start]
        and (selected_source is None or _owner._rtp_sequence_key(packet) == selected_source)
    ]
    last_packets = [
        i
        for i, packet in enumerate(packets)
        if packet.payload_type in video_types
        and packet.timestamp == timestamps[last_vcl]
        and (selected_source is None or _owner._rtp_sequence_key(packet) == selected_source)
    ]
    if not first_packets or not last_packets:
        raise _owner.PyEzvizError("Clean native video has no matching source RTP interval")
    first_packet, last_packet = (first_packets[0], last_packets[-1])
    selected_source = _owner._rtp_sequence_key(packets[last_packet])
    end_packet = next(
        (
            i
            for i in range(last_packet + 1, len(packets))
            if packets[i].payload_type in video_types
            and _owner._rtp_sequence_key(packets[i]) == selected_source
        ),
        len(packets),
    )
    selected_packets: list[_owner_types.RtpPacket] = []
    boundary_index: int | None = None
    for i, packet in enumerate(packets[: end_packet + 1]):
        if i == end_packet:
            boundary_index = len(selected_packets)
            selected_packets.append(_owner.replace(packet, extension_data=b""))
        elif first_packet <= i < end_packet and (
            packet.payload_type not in video_types
            or _owner._rtp_sequence_key(packet) == selected_source
        ):
            selected_packets.append(packet)
        elif packet.extension_data:
            selected_packets.append(_owner.replace(packet, payload=b"", payload_type=-1, ssrc=-1))
    prefix = selected[:first_vcl]
    return (
        prefix + tail,
        [timestamps[start]] * len(prefix) + timestamps[start:stop],
        selected_packets,
        boundary_index,
    )


def _copy_decrypted_native_idmx_timed_av(  # noqa: PLR0913 -- explicit runtime context plus retained signature
    packets: list[bytes],
    annexb: bytes,
    audio: _owner_types.RtpAacStream | None,
    output: _owner_types.BinaryIO,
    *,
    codec: _owner_types.RtpVideoCodec,
    ffmpeg_path: str,
    media_key: str | bytes,
    nalu_header_size: int | None,
    decrypt_hevc_parameter_sets: bool,
    native_shared_clock: bool,
    app_relative_clock: bool,
    _owner: _ModuleType,
) -> bool:
    """Use advertised native picture cadence and received AAC sample timestamps."""
    rtp_packets: list[_owner_types.RtpPacket] = []
    for frame in _owner._iter_idmx_local_packet_frames(packets):
        header = _owner._idmx_local_frame_header_size(frame)
        if header is not None:
            packet = _owner._idmx_local_frame_rtp_packet(frame, header)
            if packet is not None:
                rtp_packets.append(packet)
    if native_shared_clock or app_relative_clock:
        video_types = _owner._idmx_local_video_payload_types(packets, codec=codec)
        if (
            len(
                {
                    _owner._rtp_sequence_key(packet)
                    for packet in rtp_packets
                    if packet.payload_type in video_types and packet.payload
                }
            )
            > 1
        ):
            raise _owner.EzvizUnsupportedMediaError(
                f"{('app_relative_clock' if app_relative_clock else 'native_shared_clock')} cannot combine multiple video source clocks",
                source="rtp",
                reason="unsupported_av_clock",
            )
    rate = _owner.idmx_video_frame_rate(rtp_packets)
    if rate is None:
        if native_shared_clock or app_relative_clock:
            raise _owner.PyEzvizError(
                f"{('app_relative_clock' if app_relative_clock else 'native_shared_clock')} requires native video metadata"
            )
        return False
    source_timeline = _owner._native_decrypted_rtp_timeline(
        packets, annexb, codec, media_key, nalu_header_size, decrypt_hevc_parameter_sets
    )
    if (native_shared_clock or app_relative_clock) and source_timeline is None:
        raise _owner.PyEzvizError(
            f"{('app_relative_clock' if app_relative_clock else 'native_shared_clock')} cannot use synthetic video timestamps"
        )
    units, timestamps = (
        source_timeline
        if source_timeline is not None
        else _owner._native_decrypted_picture_timeline(annexb, codec, rate)
    )
    if not _owner.rtp_nal_units_have_vcl(units, codec=codec):
        raise _owner.EzvizNoMediaError("Native decrypted capture contained no video picture")
    if app_relative_clock and codec != "hevc":
        raise _owner.PyEzvizError("app_relative_clock currently requires native HEVC")
    payloads = (
        _owner.native_app_timed_payloads(units, timestamps, audio=audio, frame_rate=rate)
        if app_relative_clock
        else _owner.timed_rtp_mpegps_payloads(
            units, timestamps, codec=codec, audio=audio, shared_clock=native_shared_clock
        )
    )
    first_payload = next(payloads)
    process = _owner.open_mpegts_remux_process(
        ffmpeg_path,
        input_format="mpeg",
        preserve_timestamps=True,
        popen=_owner.subprocess.Popen,
        **_owner._app_remux_options(app_relative_clock),
    )

    def write_input(stdin: _owner_types.BinaryIO) -> None:
        for payload in _owner.chain((first_payload,), payloads):
            stdin.write(payload)

    _owner.copy_remuxed_output(process, output, write_input=write_input)
    return True


def _native_decrypted_rtp_timeline(
    packets: list[bytes],
    annexb: bytes,
    codec: _owner_types.RtpVideoCodec,
    media_key: str | bytes,
    nalu_header_size: int | None,
    decrypt_hevc_parameter_sets: bool,
    *,
    _owner: _ModuleType,
) -> tuple[tuple[bytes, ...], list[int]] | None:
    """Match decrypted NAL spans to their real RTP clocks without renumbering gaps."""
    reconstructed, spans = (
        _owner._idmx_hevc_annexb_packet_spans(
            packets, media_key, decrypt_hevc_parameter_sets=decrypt_hevc_parameter_sets
        )
        if codec == "hevc"
        else _owner._idmx_h264_annexb_packet_spans(
            packets, media_key, nalu_header_size=nalu_header_size, stream_is_clear=False
        )
    )
    if not spans:
        return None
    if reconstructed != annexb:
        raise _owner.PyEzvizError("Native decrypted video cannot be matched to source RTP timing")
    routed_types = _owner._idmx_local_video_payload_types(packets, codec=codec)
    frames: dict[int, list[bytes]] = {}
    timestamps: list[int] = []
    units: list[bytes] = []
    for start, end, packet_index, _end_packet, _nal_type, frame_index, _end_frame in spans:
        if packet_index not in frames:
            frames[packet_index] = list(
                _owner._iter_idmx_local_packet_frame(
                    packets[packet_index], video_payload_types=routed_types
                )
            )
        frame = frames[packet_index][frame_index]
        if not _owner._is_complete_idmx_rtp_frame(frame):
            return None
        header = _owner._idmx_local_frame_header_size(frame)
        packet = _owner._idmx_local_frame_rtp_packet(frame, header) if header is not None else None
        if packet is None:
            raise _owner.PyEzvizError("Native decrypted NAL has no matching RTP packet")
        units.append(reconstructed[start + len(_owner.ANNEX_B_LONG_START_CODE) : end])
        timestamps.append(packet.timestamp)
    return (tuple(units), timestamps)


def _native_decrypted_picture_timeline(
    annexb: bytes, codec: _owner_types.RtpVideoCodec, advertised_rate: str, *, _owner: _ModuleType
) -> tuple[tuple[bytes, ...], list[int]]:
    period = _owner.Fraction(_owner.IDMX_VIDEO_RTP_CLOCK_RATE) / _owner.Fraction(advertised_rate)
    units = tuple(
        (annexb[start:end] for _prefix, start, end in _owner._h264_annexb_nal_spans(annexb))
    )
    timestamps: list[int] = []
    frame_index = -1
    for unit in units:
        if _owner.rtp_nal_units_have_vcl((unit,), codec=codec):
            if _owner._rtp_nal_starts_picture(unit, codec=codec):
                frame_index += 1
            if frame_index < 0:
                raise _owner.PyEzvizError("Native clear timeline begins with an incomplete picture")
        timestamps.append(round(max(0, frame_index) * period))
    return (units, timestamps)


def h264_clean_idr_capture_budgets(
    *,
    duration_seconds: float | None,
    h264_skip_initial_idr_windows: int,
    h264_trim_to_clean_idr_window: bool,
    h264_clean_idr_preroll_seconds: float,
    h264_clean_idr_max_windows: int,
    h264_wait_for_clean_idr_window: bool,
    h264_clean_idr_wait_seconds: float,
    _owner: _ModuleType,
) -> tuple[float | None, float | None]:
    """Validate H.264 trim settings and return capture and payload budgets."""
    if h264_skip_initial_idr_windows < 0:
        raise _owner.PyEzvizError("h264_skip_initial_idr_windows cannot be negative")
    if h264_clean_idr_max_windows <= 0:
        raise _owner.PyEzvizError("h264_clean_idr_max_windows must be positive")
    if h264_clean_idr_preroll_seconds < 0:
        raise _owner.PyEzvizError("h264_clean_idr_preroll_seconds cannot be negative")
    if h264_clean_idr_wait_seconds < 0:
        raise _owner.PyEzvizError("h264_clean_idr_wait_seconds cannot be negative")
    if h264_wait_for_clean_idr_window and duration_seconds is None:
        raise _owner.PyEzvizError("h264_wait_for_clean_idr_window requires duration_seconds")
    if h264_wait_for_clean_idr_window and (
        h264_skip_initial_idr_windows
        or h264_trim_to_clean_idr_window
        or h264_clean_idr_preroll_seconds
    ):
        raise _owner.PyEzvizError(
            "h264_wait_for_clean_idr_window cannot be combined with H.264 startup trim options"
        )
    if h264_clean_idr_preroll_seconds and (not h264_trim_to_clean_idr_window):
        raise _owner.PyEzvizError(
            "h264_clean_idr_preroll_seconds requires h264_trim_to_clean_idr_window"
        )
    if h264_clean_idr_preroll_seconds and duration_seconds is None:
        raise _owner.PyEzvizError("h264_clean_idr_preroll_seconds requires duration_seconds")
    capture_duration_seconds = duration_seconds
    payload_duration_seconds = duration_seconds
    if h264_trim_to_clean_idr_window and h264_clean_idr_preroll_seconds:
        assert duration_seconds is not None
        capture_duration_seconds = _owner._checked_h264_duration_sum(
            duration_seconds, h264_clean_idr_preroll_seconds, context="capture"
        )
        payload_duration_seconds = capture_duration_seconds
    if h264_wait_for_clean_idr_window:
        assert duration_seconds is not None
        payload_duration_seconds = _owner._checked_h264_duration_sum(
            duration_seconds, h264_clean_idr_wait_seconds, context="payload"
        )
    return (capture_duration_seconds, payload_duration_seconds)


def _checked_h264_duration_sum(
    duration_seconds: float, extension_seconds: float, *, context: str, _owner: _ModuleType
) -> float:
    """Add one startup window without allowing deadline overflow."""
    try:
        combined = duration_seconds + extension_seconds
    except OverflowError as err:
        raise _owner.PyEzvizError(f"H.264 clean-IDR {context} duration must be finite") from err
    if not _owner.is_positive_finite_duration_bound(combined):
        raise _owner.PyEzvizError(f"H.264 clean-IDR {context} duration must be finite")
    return combined


def _is_ignorable_leading_stream_payload(payload: bytes, *, _owner: _ModuleType) -> bool:
    """Return True for tiny command-port blips before the first media record."""
    return bool(payload) and len(payload) < len(_owner.MPEG_PS_START_CODE)


def copy_hcnetsdk_real_data_to_mpegts(
    packets: _owner_types.Iterable[_owner_types.HcNetSdkRealDataPacket],
    output: _owner_types.BinaryIO,
    *,
    ffmpeg_path: str,
    _owner: _ModuleType,
) -> None:
    """Remux HCNetSDK real-play MPEG-PS callback packets to MPEG-TS."""
    process = _owner._open_local_mpegts_remux_process(ffmpeg_path)
    _owner._copy_mpegps_payloads_to_mpegts(
        _owner.iter_hcnetsdk_real_data_mpegps(packets), output, process=process
    )
