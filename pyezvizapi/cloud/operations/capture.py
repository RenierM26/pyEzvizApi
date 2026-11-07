# Runtime hook context is explicit; immutable value types come from dependency leaves.
# ruff: noqa: SLF001
'capture implementation; runtime hooks arrive through an explicit owner context.\n\nAccess through _owner is deliberate: callers that patch the compatibility\nmodule must still affect dependent operations. No copied hook snapshots.\n'
from __future__ import annotations

from pathlib import Path as _StaticPath
from types import ModuleType as _ModuleType
from typing import TYPE_CHECKING

from pyezvizapi.streaming.capture import (
    AutoClipSource as _StaticAutoClipSource,
    CloudClipSource as _StaticCloudClipSource,
    HcNetSdkCommandPortClipSource as _StaticHcNetSdkCommandPortClipSource,
    LocalSdkClipSource as _StaticLocalSdkClipSource,
    LocalSdkEcdhClipSource as _StaticLocalSdkEcdhClipSource,
)

if TYPE_CHECKING:
    import pyezvizapi._typing.client as _owner_types
from typing import Literal


def save_clip(self: _owner_types.EzvizClient, serial: str, output: str | _owner_types.Path | _owner_types.BinaryIO, *, source: _owner_types.ClipSource, auto_mode: Literal['auto', 'offline'], auto_device: dict[str, _owner_types.Any] | None, allow_cloud_fallback: bool, local_credentials: _owner_types.EzvizLocalSdkCredentials | None, output_format: _owner_types.ClipOutputFormat | None, duration_seconds: float | None, max_packets: int | None, channel: int | None, ffmpeg_path: str, decrypt_video: bool, media_key: str | bytes | None, nalu_header_size: int | None, cas_serial: str | None, register_p2p_session: bool, p2p_register_max_retries: int, timeout: float | None, smscode: str | int | None, host: str | None, command_port: int | None, hcnetsdk_command_frames: _owner_types.Iterable[bytes] | None, hcnetsdk_command_plan: _owner_types.HcNetSdkCommandPortMultiSocketPlan | None, hcnetsdk_command_generated_plan: _owner_types.HcNetSdkCommandPortGeneratedMultiSocketPlan | None, hcnetsdk_command_password: str | bytes | None, hcnetsdk_local_ip: str | None, hcnetsdk_read_response_after_each: bool | _owner_types.Iterable[bool], hcnetsdk_command_metadata_callback: _owner_types.Callable[[_owner_types.Any], None] | None, hcnetsdk_h264_skip_initial_idr_windows: int, hcnetsdk_h264_trim_to_clean_idr_window: bool, hcnetsdk_h264_clean_idr_preroll_seconds: float, hcnetsdk_h264_clean_idr_max_windows: int, hcnetsdk_h264_wait_for_clean_idr_window: bool | None, hcnetsdk_h264_clean_idr_wait_seconds: float, hcnetsdk_video_trim_to_clean_window: bool | None, hcnetsdk_video_clean_window_preroll_seconds: float | None, hcnetsdk_video_clean_window_max_windows: int | None, hcnetsdk_video_wait_for_clean_window: bool | None, hcnetsdk_video_clean_window_wait_seconds: float | None, cloud_client_type: int, cloud_token_index: int, cloud_refresh_vtm: bool, local_sdk_ecdh_receiver_port: int | None, local_sdk_ecdh_send_init: bool, local_sdk_ecdh_max_prefix_bytes: int, local_sdk_ecdh_max_frames: int | None, native_shared_clock: bool, app_relative_clock: bool, _owner: _ModuleType) -> _owner_types.SaveMediaResult:  # noqa: PLR0913 -- explicit runtime context plus retained signature
    """Save a local camera clip to a path or binary file object.

        ``source="auto"`` selects from pagelist and verifies the stream.
        ``auto_mode="offline"`` requires ``local_credentials`` and forbids
        account discovery/key refresh/cloud fallback.
        ``source="local-sdk"`` uses the direct-local 9010/9020 SDK path.
        ``source="cloud"`` uses the EZVIZ VTM cloud live stream path.
        ``source="hcnetsdk-command-port"`` consumes complete caller-supplied
        port-8000 HCNetSDK bootstrap command frames, then remuxes the command
        port media stream to MPEG-TS.
        When omitted, ``output_format`` defaults to MPEG-PS for clear
        ``source="local-sdk-ecdh"`` captures and MPEG-TS for decrypted ECDH
        or other sources. MPEG-TS accommodates both ECDH MPEG-PS and IDMX/RTP.

        This long-form signature is retained for compatibility. New code can
        group the same settings with :meth:`save_clip_with_options`.

        When ``nalu_header_size`` is omitted, cloud and direct-local decryption
        auto-detect the clear codec header. Other sources retain the legacy
        ``0`` default.
        Passing ``0`` or ``None`` explicitly preserves that exact choice.
        """
    if nalu_header_size is _owner._SOURCE_DEFAULT_NALU_HEADER_SIZE:
        nalu_header_size = None if decrypt_video and source in {'auto', 'cloud', 'local-sdk', 'local-sdk-ecdh'} else 0
    if output_format is None:
        output_format = 'mpegps' if source == 'local-sdk-ecdh' and (not decrypt_video) else 'mpegts'
    mux_options = _owner.MediaMuxOptions(output_format=output_format, ffmpeg_path=ffmpeg_path, native_shared_clock=native_shared_clock, app_relative_clock=app_relative_clock)
    source_options: _owner_types.ClipSourceOptions
    if source == 'auto':
        source_options = _owner.AutoClipSource(mode=auto_mode, device=auto_device, credentials=local_credentials, allow_cloud_fallback=allow_cloud_fallback, timeout=10.0 if timeout is None else timeout, receiver_port=local_sdk_ecdh_receiver_port, smscode=smscode)
    elif source == 'local-sdk':
        source_options = _owner.LocalSdkClipSource(credentials=local_credentials, cas_serial=cas_serial, register_p2p_session=register_p2p_session, p2p_register_max_retries=p2p_register_max_retries, timeout=timeout, smscode=smscode)
    elif source == 'local-sdk-ecdh':
        source_options = _owner.LocalSdkEcdhClipSource(credentials=local_credentials, cas_serial=cas_serial, register_p2p_session=register_p2p_session, p2p_register_max_retries=p2p_register_max_retries, timeout=timeout, smscode=smscode, receiver_port=_owner.LOCAL_SDK_ECDH_DEFAULT_RECEIVER_PORT if local_sdk_ecdh_receiver_port is None else local_sdk_ecdh_receiver_port, send_init=local_sdk_ecdh_send_init, max_prefix_bytes=local_sdk_ecdh_max_prefix_bytes, max_frames=local_sdk_ecdh_max_frames)
    elif source == 'hcnetsdk-command-port':
        trim_to_clean_window = hcnetsdk_h264_trim_to_clean_idr_window if hcnetsdk_video_trim_to_clean_window is None else hcnetsdk_video_trim_to_clean_window
        clean_window_preroll_seconds = hcnetsdk_h264_clean_idr_preroll_seconds if hcnetsdk_video_clean_window_preroll_seconds is None else hcnetsdk_video_clean_window_preroll_seconds
        clean_window_max_windows = hcnetsdk_h264_clean_idr_max_windows if hcnetsdk_video_clean_window_max_windows is None else hcnetsdk_video_clean_window_max_windows
        if hcnetsdk_video_wait_for_clean_window is not None:
            wait_for_clean_window = hcnetsdk_video_wait_for_clean_window
        elif hcnetsdk_h264_wait_for_clean_idr_window is not None:
            wait_for_clean_window = hcnetsdk_h264_wait_for_clean_idr_window
        else:
            wait_for_clean_window = bool(hcnetsdk_command_generated_plan is not None and (not decrypt_video) and (not app_relative_clock) and _owner.is_positive_finite_duration_bound(duration_seconds) and (not hcnetsdk_h264_skip_initial_idr_windows) and (not trim_to_clean_window) and (not clean_window_preroll_seconds))
        clean_window_wait_seconds = hcnetsdk_h264_clean_idr_wait_seconds if hcnetsdk_video_clean_window_wait_seconds is None else hcnetsdk_video_clean_window_wait_seconds
        mux_options = _owner.MediaMuxOptions(output_format=output_format, ffmpeg_path=ffmpeg_path, h264_skip_initial_idr_windows=hcnetsdk_h264_skip_initial_idr_windows, h264_trim_to_clean_idr_window=trim_to_clean_window, h264_clean_idr_preroll_seconds=clean_window_preroll_seconds, h264_clean_idr_max_windows=clean_window_max_windows, h264_wait_for_clean_idr_window=wait_for_clean_window, h264_clean_idr_wait_seconds=clean_window_wait_seconds, native_shared_clock=native_shared_clock, app_relative_clock=app_relative_clock)
        source_options = _owner.HcNetSdkCommandPortClipSource(timeout=timeout, host=host, command_port=command_port, command_frames=hcnetsdk_command_frames, command_plan=hcnetsdk_command_plan, generated_plan=hcnetsdk_command_generated_plan, command_password=hcnetsdk_command_password, local_ip=hcnetsdk_local_ip, read_response_after_each=hcnetsdk_read_response_after_each, metadata_callback=hcnetsdk_command_metadata_callback)
    elif source == 'cloud':
        source_options = _owner.CloudClipSource(timeout=timeout, client_type=cloud_client_type, token_index=cloud_token_index, refresh_vtm=cloud_refresh_vtm, smscode=smscode)
    else:
        raise _owner.PyEzvizError(f'Unsupported clip source: {source}')
    clip_options = _owner.ClipOptions(source=source_options, capture=_owner.CaptureLimits(max_packets=max_packets if max_packets is None or _owner.is_positive_capture_count_bound(max_packets) else None, duration_seconds=duration_seconds if duration_seconds is None or _owner.is_positive_finite_duration_bound(duration_seconds) else None), decode=_owner.MediaDecodeOptions(decrypt_video=decrypt_video, media_key=media_key, nalu_header_size=nalu_header_size), mux=mux_options, channel=channel)
    if (max_packets is not None and (not _owner.is_positive_capture_count_bound(max_packets))) or (duration_seconds is not None and (not _owner.is_positive_finite_duration_bound(duration_seconds))):
        clip_options = _owner._LegacyClipOptions.from_options(clip_options, max_packets=max_packets, duration_seconds=duration_seconds)
    return self.save_clip_with_options(serial, output, clip_options)

def save_clip_with_options(self: _owner_types.EzvizClient, serial: str, output: str | _owner_types.Path | _owner_types.BinaryIO, options: _owner_types.ClipOptions, *, _owner: _ModuleType) -> _owner_types.SaveMediaResult:
    """Save a camera clip from a grouped, typed configuration.

        Explicit native timing captures are staged: unsupported clocks must not
        truncate an existing output or append partial media to a caller buffer.
        """
    mux = options.resolved_mux()
    if not (mux.native_shared_clock or mux.app_relative_clock):
        return self._save_clip_with_options(serial, output, options)
    timing_name = 'app_relative_clock' if mux.app_relative_clock else 'native_shared_clock'
    if not isinstance(options.source, _StaticLocalSdkClipSource | _StaticHcNetSdkCommandPortClipSource):
        raise _owner.PyEzvizError(f'{timing_name} requires an explicit local-sdk or hcnetsdk-command-port source')
    if mux.output_format != 'mpegts':
        raise _owner.PyEzvizError(f'{timing_name} requires MPEG-TS output')
    options.capture.require_bounded('Explicit native timing capture')
    if (mux.app_relative_clock or options.decode.decrypt_video) and (mux.h264_wait_for_clean_idr_window or mux.h264_skip_initial_idr_windows or mux.h264_trim_to_clean_idr_window or mux.h264_clean_idr_preroll_seconds):
        trim_name = 'startup trimming' if mux.app_relative_clock else 'encrypted startup trimming'
        raise _owner.PyEzvizError(f'{timing_name} does not support {trim_name}')
    with _owner.SpooledTemporaryFile(max_size=1024 * 1024, mode='w+b') as staged:
        result = self._save_clip_with_options(serial, _owner.cast('_owner_types.BinaryIO', staged), options)
        size = staged.tell()
        if not size:
            raise _owner.EzvizNoMediaError('Shared native clock capture did not contain media')
        staged.seek(0)
        if isinstance(output, str | _StaticPath):
            _owner._write_staged_clip_path(_owner.cast('_owner_types.BinaryIO', staged), output)
        else:
            _owner.shutil.copyfileobj(staged, output)
        result['output'] = _owner._output_name(output)
        result['bytes'] = size
        result['content_type'] = _owner._content_type_for_output(output, default='video/mp2t')
        return result

def _save_clip_with_options(self: _owner_types.EzvizClient, serial: str, output: str | _owner_types.Path | _owner_types.BinaryIO, options: _owner_types.ClipOptions, *, _owner: _ModuleType) -> _owner_types.SaveMediaResult:
    """Dispatch an already validated/staged typed capture."""
    if options.capture.max_bytes is not None:
        raise _owner.PyEzvizError('save_clip_with_options does not support CaptureLimits.max_bytes')
    if options.decode.decrypt_hevc_parameter_sets and (not (isinstance(options.source, _StaticLocalSdkClipSource | _StaticHcNetSdkCommandPortClipSource) and options.decode.decrypt_video and options.resolved_mux().app_relative_clock)):
        raise _owner.PyEzvizError('save_clip_with_options does not support MediaDecodeOptions.decrypt_hevc_parameter_sets')
    source = options.source
    decode = options.decode
    mux = options.resolved_mux()
    default_mux = _owner.MediaMuxOptions()
    if not isinstance(source, _StaticHcNetSdkCommandPortClipSource) and (mux.h264_skip_initial_idr_windows or mux.h264_trim_to_clean_idr_window or mux.h264_clean_idr_preroll_seconds or (mux.h264_clean_idr_max_windows != default_mux.h264_clean_idr_max_windows) or mux.h264_wait_for_clean_idr_window or (mux.h264_clean_idr_wait_seconds != default_mux.h264_clean_idr_wait_seconds)):
        raise _owner.PyEzvizError('H.264 clean-window mux options require HcNetSdkCommandPortClipSource')
    if isinstance(source, _StaticAutoClipSource):
        return self._save_auto_clip(serial, output, options)
    if isinstance(source, _StaticLocalSdkClipSource):
        return self._save_local_sdk_clip(serial, output, output_format=mux.output_format, duration_seconds=options.duration_seconds, max_packets=options.max_packets, channel=1 if options.channel is None else options.channel, ffmpeg_path=mux.ffmpeg_path, decrypt_video=decode.decrypt_video, media_key=decode.media_key, nalu_header_size=decode.nalu_header_size, cas_serial=source.cas_serial, register_p2p_session=source.register_p2p_session, p2p_register_max_retries=source.p2p_register_max_retries, timeout=source.timeout, smscode=source.smscode, **_owner._credential_options(source.credentials), **_owner._nonempty_packet_options(source.skip_empty_packets), **_owner._receiver_options(source.receiver_port), **_owner._hevc_parameter_options(decode.decrypt_hevc_parameter_sets), **_owner._native_timing_options(mux.native_shared_clock, app_relative_clock=mux.app_relative_clock))
    if isinstance(source, _StaticLocalSdkEcdhClipSource):
        return self._save_local_sdk_ecdh_clip(serial, output, output_format=mux.output_format, duration_seconds=options.duration_seconds, max_packets=options.max_packets, max_frames=source.max_frames, channel=1 if options.channel is None else options.channel, cas_serial=source.cas_serial, register_p2p_session=source.register_p2p_session, p2p_register_max_retries=source.p2p_register_max_retries, timeout=source.timeout, receiver_port=source.receiver_port, send_init=source.send_init, max_prefix_bytes=source.max_prefix_bytes, ffmpeg_path=mux.ffmpeg_path, decrypt_video=decode.decrypt_video, media_key=decode.media_key, nalu_header_size=decode.nalu_header_size, smscode=source.smscode, **_owner._credential_options(source.credentials), **_owner._retry_port_options(source.fresh_retry_port))
    if isinstance(source, _StaticHcNetSdkCommandPortClipSource):
        return self._save_hcnetsdk_command_port_clip(serial, output, output_format=mux.output_format, duration_seconds=options.duration_seconds, max_packets=options.max_packets, channel=1 if options.channel is None else options.channel, ffmpeg_path=mux.ffmpeg_path, decrypt_video=decode.decrypt_video, media_key=decode.media_key, nalu_header_size=decode.nalu_header_size, timeout=source.timeout, host=source.host, command_port=source.command_port, command_frames=source.command_frames, command_plan=source.command_plan, generated_plan=source.generated_plan, command_password=source.command_password, local_ip=source.local_ip, read_response_after_each=source.read_response_after_each, metadata_callback=source.metadata_callback, h264_skip_initial_idr_windows=mux.h264_skip_initial_idr_windows, h264_trim_to_clean_idr_window=mux.h264_trim_to_clean_idr_window, h264_clean_idr_preroll_seconds=mux.h264_clean_idr_preroll_seconds, h264_clean_idr_max_windows=mux.h264_clean_idr_max_windows, h264_wait_for_clean_idr_window=mux.h264_wait_for_clean_idr_window or (options.mux is None and source.generated_plan is not None and (not decode.decrypt_video) and _owner.is_positive_finite_duration_bound(options.duration_seconds)), h264_clean_idr_wait_seconds=mux.h264_clean_idr_wait_seconds, **_owner._hevc_parameter_options(decode.decrypt_hevc_parameter_sets), **_owner._native_timing_options(mux.native_shared_clock, app_relative_clock=mux.app_relative_clock))
    if isinstance(source, _StaticCloudClipSource):
        return self._save_cloud_clip(serial, output, output_format=mux.output_format, duration_seconds=options.duration_seconds, max_packets=options.max_packets, channel=options.channel, ffmpeg_path=mux.ffmpeg_path, decrypt_video=decode.decrypt_video, media_key=decode.media_key, nalu_header_size=decode.nalu_header_size, timeout=source.timeout, client_type=source.client_type, token_index=source.token_index, refresh_vtm=source.refresh_vtm, smscode=source.smscode)
    raise _owner.PyEzvizError(f'Unsupported clip source options: {type(source).__name__}')

def _save_auto_clip(self: _owner_types.EzvizClient, serial: str, output: str | _owner_types.Path | _owner_types.BinaryIO, options: _owner_types.ClipOptions, *, _owner: _ModuleType) -> _owner_types.SaveMediaResult:  # noqa: PLR0912, PLR0915 -- explicit runtime context plus retained signature
    """Stage bounded attempts; only commit a successful selected source."""
    source_options = _owner.cast('_owner_types.AutoClipSource', options.source)
    options.capture.require_bounded('Automatic clip capture')
    discovery_keys: list[str] = []
    source = _owner.select_stream_source(self, serial, source_options, fetch_media_key=options.decode.decrypt_video and options.decode.media_key is None, channel=1 if options.channel is None else options.channel, _discovery_keys=discovery_keys)
    if options.decode.decrypt_video and options.decode.media_key is None and isinstance(source, _StaticLocalSdkClipSource | _StaticLocalSdkEcdhClipSource) and (source.credentials is not None):
        options = _owner.replace(options, decode=_owner.replace(options.decode, media_key=source.credentials.media_key))
    if isinstance(source, _StaticLocalSdkEcdhClipSource) and options.max_packets is not None:
        source = _owner.replace(source, max_frames=options.max_packets + 1024)
    deadline = _owner.time.monotonic() + options.duration_seconds if options.duration_seconds is not None else None
    while True:
        if isinstance(source, _StaticLocalSdkClipSource):
            source = _owner.replace(source, skip_empty_packets=True)
        duration = None if deadline is None else deadline - _owner.time.monotonic()
        if duration is not None and duration <= 0:
            raise _owner.EzvizNoMediaError('Automatic playback exhausted its capture deadline')
        selected_options = _owner.replace(options, source=source, capture=_owner.replace(options.capture, duration_seconds=duration))
        with _owner.SpooledTemporaryFile(max_size=1024 * 1024, mode='w+b') as staged:
            try:
                if isinstance(source, _StaticCloudClipSource):
                    result = self._save_auto_cloud_clip(serial, _owner.cast('_owner_types.BinaryIO', staged), selected_options, deadline)
                else:
                    result = self.save_clip_with_options(serial, _owner.cast('_owner_types.BinaryIO', staged), selected_options)
                size = staged.tell()
                if not size:
                    raise _owner.EzvizNoMediaError('Automatic playback did not contain media')
            except Exception as error:
                if source_options.discovery_cache is not None and discovery_keys and (not isinstance(source, _StaticCloudClipSource)):
                    source_options.discovery_cache.invalidate(discovery_keys[-1])
                fallback = _owner.fallback_stream_source(source, source_options, error) if staged.tell() == 0 else None
                if fallback is None:
                    raise
                source = fallback
                continue
            staged.seek(0)
            if isinstance(output, str | _StaticPath):
                path = _owner.Path(output)
                path.parent.mkdir(parents=True, exist_ok=True)
                temporary = path.with_name(f'.{path.name}.{_owner.uuid4().hex}.tmp')
                try:
                    descriptor = _owner.os.open(temporary, _owner.os.O_WRONLY | _owner.os.O_CREAT | _owner.os.O_EXCL, 384)
                    with _owner.os.fdopen(descriptor, 'wb') as target:
                        _owner.shutil.copyfileobj(staged, target)
                    _owner.os.replace(temporary, path)
                finally:
                    temporary.unlink(missing_ok=True)
            else:
                _owner.shutil.copyfileobj(staged, output)
            result['output'] = _owner._output_name(output)
            result['bytes'] = size
            result['duration_seconds'] = options.duration_seconds
            result['content_type'] = _owner._content_type_for_output(output, default='video/mp2t' if result.get('format') == 'mpegts' else 'video/mpeg')
            return result

def _save_auto_cloud_clip(self: _owner_types.EzvizClient, serial: str, output: _owner_types.BinaryIO, options: _owner_types.ClipOptions, deadline: float | None, *, _owner: _ModuleType) -> _owner_types.SaveMediaResult:
    source = _owner.cast('_owner_types.CloudClipSource', options.source)
    mux = options.resolved_mux()
    decode = options.decode
    return self._save_cloud_clip(serial, output, output_format=mux.output_format, duration_seconds=options.duration_seconds, max_packets=options.max_packets, channel=options.channel, ffmpeg_path=mux.ffmpeg_path, decrypt_video=decode.decrypt_video, media_key=decode.media_key, nalu_header_size=decode.nalu_header_size, timeout=source.timeout, client_type=source.client_type, token_index=source.token_index, refresh_vtm=source.refresh_vtm, smscode=source.smscode, capture_deadline=deadline)

def _save_local_sdk_ecdh_clip(self: _owner_types.EzvizClient, serial: str, output: str | _owner_types.Path | _owner_types.BinaryIO, *, output_format: _owner_types.ClipOutputFormat, duration_seconds: float | None, max_packets: int | None, max_frames: int | None, channel: int, cas_serial: str | None, register_p2p_session: bool, p2p_register_max_retries: int, timeout: float | None, receiver_port: int, send_init: bool, max_prefix_bytes: int, ffmpeg_path: str, decrypt_video: bool, media_key: str | bytes | None, nalu_header_size: int | None, smscode: str | int | None, credentials: _owner_types.EzvizLocalSdkCredentials | None, fresh_retry_port: bool, _owner: _ModuleType) -> _owner_types.SaveMediaResult:  # noqa: PLR0913 -- explicit runtime context plus retained signature
    """Save a clip through the local SDK ECDH stream path."""
    resolved_max_frames = max_frames if max_frames is not None else max_packets
    start_position = None
    if isinstance(output, str | _StaticPath):
        output_path = _owner.Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path = output_path.with_name(f'.{output_path.name}.{_owner.uuid4().hex}.tmp')
        try:
            descriptor = _owner.os.open(temporary_path, _owner.os.O_WRONLY | _owner.os.O_CREAT | _owner.os.O_EXCL, 384)
            with _owner.os.fdopen(descriptor, 'wb') as output_file:
                _owner.copy_local_sdk_ecdh_stream_from_client(self, serial, output_file, cas_serial=cas_serial, channel=channel, receiver_port=receiver_port, send_init=send_init, register_p2p_session=register_p2p_session, p2p_register_max_retries=p2p_register_max_retries, timeout=timeout, max_prefix_bytes=max_prefix_bytes, max_packets=max_packets, max_frames=resolved_max_frames, duration_seconds=duration_seconds, output_format=output_format, decrypt_video=decrypt_video, media_key=media_key, ffmpeg_path=ffmpeg_path, nalu_header_size=nalu_header_size, smscode=smscode, **_owner._credential_options(credentials), **_owner._retry_port_options(fresh_retry_port))
            if temporary_path.stat().st_size == 0:
                raise _owner.EzvizNoMediaError('Local SDK ECDH capture did not contain media')
            _owner.os.replace(temporary_path, output_path)
        finally:
            temporary_path.unlink(missing_ok=True)
    else:
        start_position = _owner._binary_position(output)
        _owner.copy_local_sdk_ecdh_stream_from_client(self, serial, output, cas_serial=cas_serial, channel=channel, receiver_port=receiver_port, send_init=send_init, register_p2p_session=register_p2p_session, p2p_register_max_retries=p2p_register_max_retries, timeout=timeout, max_prefix_bytes=max_prefix_bytes, max_packets=max_packets, max_frames=resolved_max_frames, duration_seconds=duration_seconds, output_format=output_format, decrypt_video=decrypt_video, media_key=media_key, ffmpeg_path=ffmpeg_path, nalu_header_size=nalu_header_size, smscode=smscode, **_owner._credential_options(credentials), **_owner._retry_port_options(fresh_retry_port))
    bytes_written = _owner._bytes_written_to_output(output, start_position=start_position)
    if bytes_written == 0:
        raise _owner.EzvizNoMediaError('Local SDK ECDH capture did not contain media')
    return {'ok': True, 'kind': 'clip', 'serial': serial, 'channel': channel, 'output': _owner._output_name(output), 'bytes': bytes_written, 'source': 'local-sdk-ecdh', 'format': output_format, 'duration_seconds': duration_seconds, 'content_type': _owner._content_type_for_output(output, default='video/mpeg')}

def _save_local_sdk_clip(self: _owner_types.EzvizClient, serial: str, output: str | _owner_types.Path | _owner_types.BinaryIO, *, output_format: _owner_types.ClipOutputFormat, duration_seconds: float | None, max_packets: int | None, channel: int, ffmpeg_path: str, decrypt_video: bool, media_key: str | bytes | None, nalu_header_size: int | None, cas_serial: str | None, register_p2p_session: bool, p2p_register_max_retries: int, timeout: float | None, smscode: str | int | None, credentials: _owner_types.EzvizLocalSdkCredentials | None, receiver_port: int, skip_empty_packets: bool, native_shared_clock: bool, app_relative_clock: bool, decrypt_hevc_parameter_sets: bool, _owner: _ModuleType) -> _owner_types.SaveMediaResult:  # noqa: PLR0913 -- explicit runtime context plus retained signature
    """Save a clip through the direct-local SDK path."""
    start_position = None
    if isinstance(output, str | _StaticPath):
        output_path = _owner.Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open('wb') as output_file:
            _owner.copy_local_sdk_stream_from_client(self, serial, output_file, output_format=output_format, decrypt_video=decrypt_video, media_key=media_key, nalu_header_size=nalu_header_size, channel=channel, cas_serial=cas_serial, register_p2p_session=register_p2p_session, p2p_register_max_retries=p2p_register_max_retries, timeout=timeout, max_packets=max_packets, duration_seconds=duration_seconds, ffmpeg_path=ffmpeg_path, smscode=smscode, **_owner._hevc_parameter_options(decrypt_hevc_parameter_sets), **_owner._native_timing_options(native_shared_clock, app_relative_clock=app_relative_clock), **_owner._credential_options(credentials), **_owner._nonempty_packet_options(skip_empty_packets), **_owner._receiver_options(receiver_port, receiver_ex=True))
    else:
        start_position = _owner._binary_position(output)
        _owner.copy_local_sdk_stream_from_client(self, serial, output, output_format=output_format, decrypt_video=decrypt_video, media_key=media_key, nalu_header_size=nalu_header_size, channel=channel, cas_serial=cas_serial, register_p2p_session=register_p2p_session, p2p_register_max_retries=p2p_register_max_retries, timeout=timeout, max_packets=max_packets, duration_seconds=duration_seconds, ffmpeg_path=ffmpeg_path, smscode=smscode, **_owner._hevc_parameter_options(decrypt_hevc_parameter_sets), **_owner._native_timing_options(native_shared_clock, app_relative_clock=app_relative_clock), **_owner._credential_options(credentials), **_owner._nonempty_packet_options(skip_empty_packets), **_owner._receiver_options(receiver_port, receiver_ex=True))
    return {'ok': True, 'kind': 'clip', 'serial': serial, 'channel': channel, 'output': _owner._output_name(output), 'bytes': _owner._bytes_written_to_output(output, start_position=start_position), 'source': 'local-sdk', 'format': output_format, 'duration_seconds': duration_seconds, 'content_type': _owner._content_type_for_output(output, default='video/mp2t' if output_format == 'mpegts' else 'video/mpeg')}

def _save_hcnetsdk_command_port_clip(self: _owner_types.EzvizClient, serial: str, output: str | _owner_types.Path | _owner_types.BinaryIO, *, output_format: _owner_types.ClipOutputFormat, duration_seconds: float | None, max_packets: int | None, channel: int, ffmpeg_path: str, decrypt_video: bool, media_key: str | bytes | None, nalu_header_size: int | None, timeout: float | None, host: str | None, command_port: int | None, command_frames: _owner_types.Iterable[bytes] | None, command_plan: _owner_types.HcNetSdkCommandPortMultiSocketPlan | None, generated_plan: _owner_types.HcNetSdkCommandPortGeneratedMultiSocketPlan | None, command_password: str | bytes | None, local_ip: str | None, read_response_after_each: bool | _owner_types.Iterable[bool], metadata_callback: _owner_types.Callable[[_owner_types.Any], None] | None, h264_skip_initial_idr_windows: int, h264_trim_to_clean_idr_window: bool, h264_clean_idr_preroll_seconds: float, h264_clean_idr_max_windows: int, h264_wait_for_clean_idr_window: bool, h264_clean_idr_wait_seconds: float, native_shared_clock: bool, app_relative_clock: bool, decrypt_hevc_parameter_sets: bool, _owner: _ModuleType) -> _owner_types.SaveMediaResult:  # noqa: PLR0912, PLR0913 -- explicit runtime context plus retained signature
    """Save a clip through caller-supplied port-8000 HCNetSDK frames."""
    if output_format != 'mpegts':
        raise _owner.PyEzvizError("source='hcnetsdk-command-port' currently writes MPEG-TS only")
    if decrypt_video and media_key is None:
        raise _owner.PyEzvizError("source='hcnetsdk-command-port' decrypt_video requires media_key")
    if decrypt_video:
        _owner.h264_clean_idr_capture_budgets(duration_seconds=duration_seconds, h264_skip_initial_idr_windows=h264_skip_initial_idr_windows, h264_trim_to_clean_idr_window=h264_trim_to_clean_idr_window, h264_clean_idr_preroll_seconds=h264_clean_idr_preroll_seconds, h264_clean_idr_max_windows=h264_clean_idr_max_windows, h264_wait_for_clean_idr_window=h264_wait_for_clean_idr_window, h264_clean_idr_wait_seconds=h264_clean_idr_wait_seconds)
    if decrypt_video and (not _owner.has_positive_finite_capture_bound(max_packets=max_packets, duration_seconds=duration_seconds)):
        raise _owner.PyEzvizError("source='hcnetsdk-command-port' encrypted capture requires a positive finite duration_seconds or max_packets")
    frames = tuple(command_frames or ())
    supplied_modes = sum(bool(mode) for mode in (frames, command_plan is not None, generated_plan is not None))
    if supplied_modes != 1:
        raise _owner.PyEzvizError("source='hcnetsdk-command-port' requires exactly one of hcnetsdk_command_frames, hcnetsdk_command_plan, or hcnetsdk_command_generated_plan")
    if generated_plan is not None and command_password is None:
        raise _owner.PyEzvizError("source='hcnetsdk-command-port' generated plans require hcnetsdk_command_password")
    if command_port is None and generated_plan == _owner.hcnetsdk_command_port_native_lan_live_view_plan():
        command_port = 8000
    endpoint = self._hcnetsdk_command_port_endpoint(serial, host=host, command_port=command_port)
    start_position = None
    if isinstance(output, str | _StaticPath):
        output_path = _owner.Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        stream_context = self._open_hcnetsdk_command_port_clip_stream(endpoint, frames=frames, command_plan=command_plan, generated_plan=generated_plan, command_password=command_password, timeout=timeout, local_ip=local_ip, read_response_after_each=read_response_after_each)
        with stream_context as stream, output_path.open('wb') as output_file:
            metadata_stream = _owner._LocalStreamPacketMetadataRecorder(stream) if metadata_callback is not None else stream
            try:
                if decrypt_video:
                    assert media_key is not None
                    _owner.copy_local_stream_to_decrypted_mpegts(metadata_stream, output_file, media_key, ffmpeg_path=ffmpeg_path, nalu_header_size=nalu_header_size, max_packets=max_packets, duration_seconds=duration_seconds, h264_skip_initial_idr_windows=h264_skip_initial_idr_windows, h264_trim_to_clean_idr_window=h264_trim_to_clean_idr_window, h264_clean_idr_preroll_seconds=h264_clean_idr_preroll_seconds, h264_clean_idr_max_windows=h264_clean_idr_max_windows, h264_wait_for_clean_idr_window=h264_wait_for_clean_idr_window, h264_clean_idr_wait_seconds=h264_clean_idr_wait_seconds, **_owner._hevc_parameter_options(decrypt_hevc_parameter_sets), **_owner._native_timing_options(native_shared_clock, app_relative_clock=app_relative_clock))
                else:
                    _owner.copy_local_stream_to_mpegts(metadata_stream, output_file, ffmpeg_path=ffmpeg_path, max_packets=max_packets, duration_seconds=duration_seconds, h264_skip_initial_idr_windows=h264_skip_initial_idr_windows, h264_trim_to_clean_idr_window=h264_trim_to_clean_idr_window, h264_clean_idr_preroll_seconds=h264_clean_idr_preroll_seconds, h264_clean_idr_max_windows=h264_clean_idr_max_windows, h264_wait_for_clean_idr_window=h264_wait_for_clean_idr_window, h264_clean_idr_wait_seconds=h264_clean_idr_wait_seconds, **_owner._native_timing_options(native_shared_clock, app_relative_clock=app_relative_clock))
            finally:
                if metadata_callback is not None:
                    metadata_callback(metadata_stream)
    else:
        start_position = _owner._binary_position(output)
        stream_context = self._open_hcnetsdk_command_port_clip_stream(endpoint, frames=frames, command_plan=command_plan, generated_plan=generated_plan, command_password=command_password, timeout=timeout, local_ip=local_ip, read_response_after_each=read_response_after_each)
        with stream_context as stream:
            metadata_stream = _owner._LocalStreamPacketMetadataRecorder(stream) if metadata_callback is not None else stream
            try:
                if decrypt_video:
                    assert media_key is not None
                    _owner.copy_local_stream_to_decrypted_mpegts(metadata_stream, output, media_key, ffmpeg_path=ffmpeg_path, nalu_header_size=nalu_header_size, max_packets=max_packets, duration_seconds=duration_seconds, h264_skip_initial_idr_windows=h264_skip_initial_idr_windows, h264_trim_to_clean_idr_window=h264_trim_to_clean_idr_window, h264_clean_idr_preroll_seconds=h264_clean_idr_preroll_seconds, h264_clean_idr_max_windows=h264_clean_idr_max_windows, h264_wait_for_clean_idr_window=h264_wait_for_clean_idr_window, h264_clean_idr_wait_seconds=h264_clean_idr_wait_seconds, **_owner._hevc_parameter_options(decrypt_hevc_parameter_sets), **_owner._native_timing_options(native_shared_clock, app_relative_clock=app_relative_clock))
                else:
                    _owner.copy_local_stream_to_mpegts(metadata_stream, output, ffmpeg_path=ffmpeg_path, max_packets=max_packets, duration_seconds=duration_seconds, h264_skip_initial_idr_windows=h264_skip_initial_idr_windows, h264_trim_to_clean_idr_window=h264_trim_to_clean_idr_window, h264_clean_idr_preroll_seconds=h264_clean_idr_preroll_seconds, h264_clean_idr_max_windows=h264_clean_idr_max_windows, h264_wait_for_clean_idr_window=h264_wait_for_clean_idr_window, h264_clean_idr_wait_seconds=h264_clean_idr_wait_seconds, **_owner._native_timing_options(native_shared_clock, app_relative_clock=app_relative_clock))
            finally:
                if metadata_callback is not None:
                    metadata_callback(metadata_stream)
    return {'ok': True, 'kind': 'clip', 'serial': serial, 'channel': channel, 'output': _owner._output_name(output), 'bytes': _owner._bytes_written_to_output(output, start_position=start_position), 'source': 'hcnetsdk-command-port', 'format': output_format, 'duration_seconds': duration_seconds, 'content_type': _owner._content_type_for_output(output, default='video/mp2t'), 'command_port': endpoint.command_port}

def _open_hcnetsdk_command_port_clip_stream(endpoint: _owner_types.HcNetSdkLanEndpoint, *, frames: tuple[bytes, ...], command_plan: _owner_types.HcNetSdkCommandPortMultiSocketPlan | None, generated_plan: _owner_types.HcNetSdkCommandPortGeneratedMultiSocketPlan | None, command_password: str | bytes | None, timeout: float | None, local_ip: str | None, read_response_after_each: bool | _owner_types.Iterable[bool], _owner: _ModuleType) -> _owner_types.Any:
    """Open the selected HCNetSDK command-port stream mode."""
    if generated_plan is not None and command_password is not None:
        return _owner.open_hcnetsdk_command_port_generated_multi_socket_stream(endpoint, generated_plan, password=command_password, timeout=timeout, local_ip=local_ip)
    if command_plan is not None:
        return _owner.open_hcnetsdk_command_port_multi_socket_stream(endpoint, command_plan, timeout=timeout, local_ip=local_ip)
    return _owner.open_hcnetsdk_command_port_stream(endpoint, frames, timeout=timeout, read_response_after_each=read_response_after_each, local_ip=local_ip)

def _save_cloud_clip(self: _owner_types.EzvizClient, serial: str, output: str | _owner_types.Path | _owner_types.BinaryIO, *, output_format: _owner_types.ClipOutputFormat, duration_seconds: float | None, max_packets: int | None, channel: int | None, ffmpeg_path: str, decrypt_video: bool, media_key: str | bytes | None, nalu_header_size: int | None, timeout: float | None, client_type: int, token_index: int, refresh_vtm: bool, smscode: str | int | None, capture_deadline: float | None, _owner: _ModuleType) -> _owner_types.SaveMediaResult:  # noqa: PLR0913 -- explicit runtime context plus retained signature
    """Save a clip through the EZVIZ VTM cloud live stream path."""
    start_position = None
    staged_size: int | None = None
    deadline_options: dict[str, _owner_types.Any] = {'capture_deadline': capture_deadline} if capture_deadline is not None else {}

    def copy_cloud(output_file: _owner_types.BinaryIO) -> None:
        if output_format == 'mpegts':
            _owner.copy_cloud_stream_to_mpegts(self, serial, output_file, channel=channel, client_type=client_type, token_index=token_index, refresh_vtm=refresh_vtm, timeout=timeout, ffmpeg_path=ffmpeg_path, max_packets=max_packets, duration_seconds=duration_seconds, decrypt_video=decrypt_video, media_key=media_key, nalu_header_size=nalu_header_size, smscode=smscode, **deadline_options)
            return
        _owner.copy_cloud_stream_to_mpegps(self, serial, output_file, channel=channel, client_type=client_type, token_index=token_index, refresh_vtm=refresh_vtm, timeout=timeout, max_packets=max_packets, duration_seconds=duration_seconds, decrypt_video=decrypt_video, media_key=media_key, nalu_header_size=nalu_header_size, smscode=smscode, **deadline_options)
    if decrypt_video and duration_seconds is None and (max_packets is None):
        raise _owner.PyEzvizError('Encrypted cloud stream decrypt requires a positive finite duration_seconds or max_packets')
    if isinstance(output, str | _StaticPath):
        output_path = _owner.Path(output)
        if duration_seconds is None and max_packets is None:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with output_path.open('wb') as output_file:
                counted_output = _owner._CountingBinaryWriter(output_file)
                copy_cloud(_owner.cast('_owner_types.BinaryIO', counted_output))
                staged_size = counted_output.bytes_written
        else:
            with _owner.SpooledTemporaryFile(max_size=8 * 1024 * 1024, mode='w+b') as staging:
                copy_cloud(_owner.cast('_owner_types.BinaryIO', staging))
                staging.seek(0, _owner.os.SEEK_END)
                staged_size = staging.tell()
                if staged_size == 0:
                    raise _owner.EzvizNoMediaError('Cloud stream capture did not contain media')
                staging.seek(0)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                with output_path.open('wb') as output_file:
                    _owner.shutil.copyfileobj(staging, output_file)
    else:
        start_position = _owner._binary_position(output)
        copy_cloud(output)
    bytes_written = staged_size if isinstance(output, str | _StaticPath) else _owner._bytes_written_to_output(output, start_position=start_position)
    if bytes_written == 0:
        raise _owner.EzvizNoMediaError('Cloud stream capture did not contain media')
    return {'ok': True, 'kind': 'clip', 'serial': serial, 'channel': channel, 'output': _owner._output_name(output), 'bytes': bytes_written, 'source': 'cloud', 'format': output_format, 'duration_seconds': duration_seconds, 'content_type': _owner._content_type_for_output(output, default='video/mp2t' if output_format == 'mpegts' else 'video/mpeg'), 'cloud_client_type': client_type, 'cloud_token_index': token_index, 'cloud_refresh_vtm': refresh_vtm}

def _hcnetsdk_command_port_endpoint(self: _owner_types.EzvizClient, serial: str, *, host: str | None, command_port: int | None, _owner: _ModuleType) -> _owner_types.HcNetSdkLanEndpoint:
    """Return a command-port endpoint from overrides or device metadata."""
    if host:
        return _owner.HcNetSdkLanEndpoint(serial=serial, host=host, command_port=command_port or 8000)
    device_info = self.get_device_infos(serial)
    device: dict[str, _owner_types.Any] | None = None
    if isinstance(device_info, dict):
        if isinstance(device_info.get('CONNECTION'), dict):
            device = device_info
        else:
            for value in device_info.values():
                if isinstance(value, dict) and isinstance(value.get('CONNECTION'), dict):
                    device = value
                    break
    if not isinstance(device, dict):
        raise _owner.PyEzvizError('Could not find CONNECTION metadata for HCNetSDK command-port stream; provide host')
    endpoint = _owner.HcNetSdkLanEndpoint.from_connection(serial, device.get('CONNECTION'))
    if command_port is None:
        return endpoint
    return _owner.HcNetSdkLanEndpoint(serial=endpoint.serial, host=endpoint.host, net_host=endpoint.net_host, command_port=command_port, net_command_port=endpoint.net_command_port, stream_port=endpoint.stream_port, net_stream_port=endpoint.net_stream_port, rtsp_port=endpoint.rtsp_port, sdk_tls_port=endpoint.sdk_tls_port)

def save_image(self: _owner_types.EzvizClient, serial: str, output: str | _owner_types.Path | _owner_types.BinaryIO, *, channel: int, image_url: str | None, decrypt: bool, smscode: str | int | None, _owner: _ModuleType) -> _owner_types.SaveMediaResult:
    """Capture or download a camera image to a path or binary file object."""
    capture_response: dict[str, _owner_types.Any] | None = None
    selected_image_url = image_url
    if selected_image_url is None:
        capture_response = self.capture_picture(serial, channel, max_retries=1)
        selected_image_url = _owner._first_image_url(capture_response)
        if selected_image_url is None:
            raise _owner.PyEzvizError('Camera capture response did not include an image URL')
    image_data = self.download_alarm_image(selected_image_url, serial, decrypt=decrypt, smscode=smscode, max_retries=1)
    start_position = None
    if isinstance(output, str | _StaticPath):
        output_path = _owner.Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(image_data)
    else:
        start_position = _owner._binary_position(output)
        output.write(image_data)
        output.flush()
    return {'ok': True, 'kind': 'image', 'serial': serial, 'channel': channel, 'output': _owner._output_name(output), 'bytes': _owner._bytes_written_to_output(output, start_position=start_position), 'content_type': _owner._content_type_for_output(output, default='image/jpeg'), 'image_url': selected_image_url, 'triggered_capture': capture_response is not None}
