"""commands cloud stream implementation; legacy runtime hooks remain on the owner module.

Access through _owner is deliberate: callers that patch the compatibility
module must still affect dependent operations. No copied hook snapshots.
"""
# ruff: noqa: SLF001 -- explicit legacy hook boundary.
from __future__ import annotations

import pyezvizapi.cli.main as _owner

def _collect_stream_payloads(stream: _owner.Any, *, max_packets: int | None, duration_seconds: float | None=None, allow_encrypted: bool, monotonic: _owner.Any=_owner.time.monotonic) -> bytes:
    """Collect VTM stream packet bodies into memory."""
    output = _owner.BytesIO()
    try:
        _owner._write_stream_payloads(stream, output, max_packets=max_packets, duration_seconds=duration_seconds, allow_encrypted=allow_encrypted, monotonic=monotonic)
    except _owner.PyEzvizError as err:
        if output.tell() == 0 or 'VTM socket closed' not in str(err):
            raise
        _owner._LOGGER.warning('%s; using partial captured stream', err)
    return output.getvalue()

def _collect_stream_packets(stream: _owner.Any, *, max_packets: int | None, duration_seconds: float | None=None, first_packet_deadline: float | None=None, allow_encrypted: bool, monotonic: _owner.Any=_owner.time.monotonic) -> list[_owner.Any]:
    """Collect VTM stream packets while preserving packet boundaries."""
    packets: list[_owner.Any] = []
    deadline = None
    if duration_seconds is not None:
        deadline = monotonic() + duration_seconds
    iterator_kwargs: dict[str, _owner.Any] = {'max_packets': max_packets}
    if isinstance(stream, _owner.VtmStreamClient):
        iterator_kwargs.update(duration_seconds=duration_seconds, duration_from_start=True, monotonic=monotonic)
        if first_packet_deadline is not None:
            iterator_kwargs['first_packet_deadline'] = first_packet_deadline
        if duration_seconds is None:
            iterator_kwargs['first_packet_timeout'] = stream.timeout
    try:
        for packet in stream.iter_packets(**iterator_kwargs):
            if deadline is not None and monotonic() >= deadline:
                break
            if packet.encrypted and (not allow_encrypted):
                raise _owner.PyEzvizError('Received encrypted VTM stream packet; media decryption is not implemented')
            packets.append(packet)
    except _owner.PyEzvizError as err:
        if not packets or 'VTM socket closed' not in str(err):
            raise
        _owner._LOGGER.warning('%s; using partial captured stream', err)
    return packets

def _detect_stream_packets_transport(packets: list[_owner.Any]) -> _owner.StreamTransport:
    """Return the first known media transport from collected VTM packets."""
    for packet in packets:
        transport = _owner.detect_transport(packet.body)
        if transport != _owner.StreamTransport.UNKNOWN:
            return transport
    return _owner.StreamTransport.UNKNOWN

def _rtp_payload_video_codec(payload: bytes) -> str | None:
    """Compatibility wrapper for the shared RTP codec detector."""
    return _owner.rtp_payload_video_codec(payload)

def _detect_rtp_video_codec(packets: list[_owner.Any], *, media_key: str | bytes | None=None, decrypt_codec: str='auto') -> str:
    """Detect RTP video codec through the shared parser and router."""

    def decrypted_header(nal_unit: bytes) -> bytes:
        assert media_key is not None
        video_pes = b'\x00\x00\x01\xe0\x00\x00\x80\x00\x00' + b'\x00\x00\x00\x01' + nal_unit
        return _owner.decrypt_hikvision_ps_video(video_pes, media_key, nalu_header_size=0)[13:]
    return _owner.detect_rtp_video_codec(_owner._parse_rtp_packets(packets), video_payload_transform=decrypted_header if media_key is not None and _owner._codec_nalu_header_size(decrypt_codec) == 0 else None, allow_ezviz_headerless_hevc_fu=True)

def _parse_rtp_packets(packets: list[_owner.Any]) -> list[_owner.Any]:
    """Parse valid RTP bodies while ignoring interleaved control data."""
    parsed = []
    for packet in packets:
        try:
            parsed.append(_owner.parse_rtp_packet(packet.body, idmx=True))
        except _owner.PyEzvizError:
            continue
    return parsed

def _rtp_packets_to_annexb(packets: list[_owner.Any], *, codec: str) -> bytes:
    """Convert RTP video through the shared continuity state machine."""
    return b''.join(_owner._rtp_packets_to_annexb_units(packets, codec=codec))

def _rtp_packets_to_annexb_units(packets: list[_owner.Any], *, codec: str, first_slice_key: str | bytes | None=None, decrypt_codec: str='auto') -> tuple[bytes, ...]:
    """Return complete Annex-B units from the shared RTP continuity state machine."""
    if codec not in {'h264', 'hevc'}:
        raise _owner.PyEzvizError(f'Unsupported RTP video codec: {codec}')
    selected_codec = codec if decrypt_codec == 'auto' else decrypt_codec
    header_size = _owner._codec_nalu_header_size(selected_codec)
    if header_size is None:
        header_size = 2 if codec == 'hevc' else 1

    def decrypted_first_slice(nal_unit: bytes) -> bytes:
        assert first_slice_key is not None
        video_pes = b'\x00\x00\x01\xe0\x00\x00\x80\x00\x00' + b'\x00\x00\x00\x01' + nal_unit
        return _owner.decrypt_hikvision_ps_video(video_pes, first_slice_key, nalu_header_size=header_size)[13:]
    parsed = _owner._parse_rtp_packets(packets)
    nal_units = _owner.rtp_packets_to_nal_units(parsed, codec=_owner.cast(_owner.Any, codec), allow_ezviz_headerless_hevc_fu=True, completed_access_units_only=True, first_slice_transform=decrypted_first_slice if first_slice_key is not None and header_size != 0 else None, packet_nal_transform=decrypted_first_slice if first_slice_key is not None and header_size == 0 else None)
    classified_units = tuple((decrypted_first_slice(nal_unit) for nal_unit in nal_units)) if first_slice_key is not None and header_size != 0 else nal_units
    if not _owner.rtp_nal_units_have_vcl(classified_units, codec=_owner.cast(_owner.Any, codec)):
        raise _owner.EzvizNoMediaError('Cloud RTP capture contained no complete video frame; increase the capture duration')
    return tuple((b'\x00\x00\x00\x01' + nal_unit for nal_unit in nal_units))

def _decrypt_annexb_video_bytes(client: _owner.EzvizClient, serial: str, data: bytes, *, codec: str) -> bytes:
    """Decrypt Annex B video NAL payload bytes using the MPEG-PS transform."""
    key = client.get_cam_key(serial, max_retries=1)
    if not key:
        raise _owner.PyEzvizError('Could not get camera encryption key')
    header_size = _owner._codec_nalu_header_size(codec)
    if header_size is None:
        header_size = 2 if codec == 'hevc' else 1
    video_pes = b'\x00\x00\x01\xe0\x00\x00\x80\x00\x00' + data
    return _owner.decrypt_hikvision_ps_video(video_pes, str(key), nalu_header_size=header_size)[9:]

def _decrypt_rtp_annexb_units(client: _owner.EzvizClient, serial: str, units: tuple[bytes, ...], *, detected_codec: str, decrypt_codec: str, media_key: str | bytes | None=None) -> bytes:
    """Decrypt RTP Annex-B units with one camera-key lookup."""
    _mpegps_decryptor, rtp_decryptor = _owner._stream_payload_decryptors(client, serial, codec=decrypt_codec, media_key=media_key)
    return b''.join((rtp_decryptor(unit, detected_codec) for unit in units))

def _remux_elementary_video_bytes_to_mpegts(data: bytes, output: _owner.BinaryIO, *, ffmpeg_path: str, codec: str) -> None:
    """Remux Annex B HEVC/H.264 elementary stream bytes to MPEG-TS."""
    process = _owner._open_mpegts_remux_process(ffmpeg_path, input_format=codec)
    _owner.remux_bytes(process, data, output)

def _decrypt_stream_payload_bytes(client: _owner.EzvizClient, serial: str, data: bytes, *, codec: str, media_key: str | bytes | None=None) -> bytes:
    """Decrypt captured MPEG-PS stream bytes using the camera encrypt key."""
    key = media_key if media_key is not None else client.get_cam_key(serial, max_retries=1)
    if not key:
        raise _owner.PyEzvizError('Could not get camera encryption key')
    return _owner.decrypt_hikvision_ps_video(data, key, nalu_header_size=_owner._codec_nalu_header_size(codec))

def _codec_nalu_header_size(codec: str) -> int | None:
    """Return the Annex B NAL header length preserved by the decrypt transform."""
    if codec == 'auto':
        return None
    if codec == 'hevc':
        return 2
    if codec in {'h264', 'h264-clear-header'}:
        return 1
    if codec in {'hevc-encrypted-header', 'h264-encrypted-header', 'encrypted-header'}:
        return 0
    return 0

def _stream_payload_decryptor(client: _owner.EzvizClient, serial: str, *, codec: str) -> _owner.Callable[[bytes], bytes]:
    """Return a buffered MPEG-PS decryptor using the camera encrypt key."""
    key = client.get_cam_key(serial, max_retries=1)
    if not key:
        raise _owner.PyEzvizError('Could not get camera encryption key')
    return _owner._BufferedStreamPayloadDecryptor(str(key), codec=codec)

def _stream_payload_decryptors(client: _owner.EzvizClient, serial: str, *, codec: str, media_key: str | bytes | None=None) -> tuple[_owner.Callable[[bytes], bytes], _owner.Callable[[bytes, str], bytes]]:
    """Return MPEG-PS and RTP decryptors sharing one camera-key lookup."""
    mpegps_decryptor, rtp_decryptor, _key = _owner._stream_payload_decryptors_with_key(client, serial, codec=codec, media_key=media_key)
    return (mpegps_decryptor, rtp_decryptor)

def _stream_payload_decryptors_with_key(client: _owner.EzvizClient, serial: str, *, codec: str, media_key: str | bytes | None=None) -> tuple[_owner.Callable[[bytes], bytes], _owner.Callable[[bytes, str], bytes], str | bytes]:
    """Return streaming decryptors and their single fetched camera key."""
    key = media_key if media_key is not None else client.get_cam_key(serial, max_retries=1)
    if not key:
        raise _owner.PyEzvizError('Could not get camera encryption key')
    selected_key = key

    def _decrypt_rtp_annexb(data: bytes, detected_codec: str) -> bytes:
        decrypt_codec = detected_codec if codec == 'auto' else codec
        header_size = _owner._codec_nalu_header_size(decrypt_codec)
        if header_size is None:
            header_size = 2 if detected_codec == 'hevc' else 1
        video_pes = b'\x00\x00\x01\xe0\x00\x00\x80\x00\x00' + data
        return _owner.decrypt_hikvision_ps_video(video_pes, selected_key, nalu_header_size=header_size)[9:]
    return (_owner._BufferedStreamPayloadDecryptor(selected_key, codec=codec), _decrypt_rtp_annexb, selected_key)

def _cloud_cli_media_key(args: _owner.argparse.Namespace, client: _owner.EzvizClient) -> str | bytes:
    """Resolve an explicit or cloud camera key without exposing it."""
    explicit_key = _owner._explicit_cloud_cli_media_key(args)
    if explicit_key is not None:
        return explicit_key
    sms_code = getattr(args, 'sms_code', None)
    if sms_code is None:
        cloud_key = client.get_cam_key(args.serial, max_retries=1)
    else:
        cloud_key = client.get_cam_key(args.serial, smscode=sms_code, max_retries=1)
    if not cloud_key:
        raise _owner.PyEzvizError('Could not get camera encryption key')
    return str(cloud_key)

def _explicit_cloud_cli_media_key(args: _owner.argparse.Namespace) -> str | bytes | None:
    """Resolve only a supplied key; proxy cloud lookup happens per request."""
    key = getattr(args, 'media_key', None)
    key_hex = getattr(args, 'media_key_hex', None)
    if key and key_hex:
        raise _owner.PyEzvizError('Provide only one of --media-key or --media-key-hex')
    if key_hex:
        try:
            return bytes.fromhex(key_hex)
        except ValueError as err:
            raise _owner.PyEzvizError('Invalid --media-key-hex') from err
    return str(key) if key else None

def _remux_mpegps_bytes_to_mpegts(data: bytes, output: _owner.BinaryIO, *, ffmpeg_path: str) -> None:
    """Remux in-memory MPEG-PS bytes to MPEG-TS."""
    process = _owner._open_mpegts_remux_process(ffmpeg_path)
    _owner.remux_bytes(process, data, output)

def _remux_stream_payloads_to_mpegts(stream: _owner.Any, output: _owner.BinaryIO, *, ffmpeg_path: str, max_packets: int | None, duration_seconds: float | None=None, first_packet_deadline: float | None=None, allow_encrypted: bool) -> None:
    """Route VTM media to MPEG-TS with optional encrypted-packet passthrough."""
    _owner.copy_cloud_stream_packets_to_mpegts(stream, output, ffmpeg_path=ffmpeg_path, max_packets=max_packets, duration_seconds=duration_seconds, first_packet_deadline=first_packet_deadline, allow_encrypted=allow_encrypted)

def _open_mpegts_remux_process(ffmpeg_path: str, *, input_format: str='mpeg') -> _owner.subprocess.Popen[bytes]:
    """Open an FFmpeg process ready to remux MPEG-PS stdin to MPEG-TS stdout."""
    return _owner.open_mpegts_remux_process(ffmpeg_path, input_format=input_format, popen=_owner.subprocess.Popen)

def _copy_stream_payloads_to_mpegts(stream: _owner.Any, output: _owner.BinaryIO, *, process: _owner.subprocess.Popen[bytes], max_packets: int | None, duration_seconds: float | None=None, allow_encrypted: bool, transform_payload: _owner.Callable[[bytes], bytes] | None=None) -> None:
    """Copy stream payloads through an already-started FFmpeg remuxer."""

    def _write_input(stdin: _owner.BinaryIO) -> None:
        _owner._write_stream_payloads(stream, stdin, max_packets=max_packets, duration_seconds=duration_seconds, allow_encrypted=allow_encrypted, transform_payload=transform_payload, flush_each=True)
    _owner.copy_remuxed_output(process, output, write_input=_write_input, cancel_input=getattr(stream, 'close', None))

def _default_stream_proxy_path(serial: str) -> str:
    """Return the default HTTP path for a camera stream."""
    return f'/{serial}.ts'

def _normalize_stream_proxy_path(path: str | None, serial: str) -> str:
    """Normalize a user-supplied proxy path."""
    if not path:
        return _owner._default_stream_proxy_path(serial)
    return path if path.startswith('/') else f'/{path}'

def _handle_stream_proxy_get(handler: _owner.BaseHTTPRequestHandler, config: _owner.StreamProxyConfig, client: _owner.EzvizClient) -> None:
    """Handle one experimental VTM-to-MPEG-TS HTTP proxy request."""
    if _owner.urlparse(handler.path).path != config.path:
        handler.send_error(404, 'Stream not found')
        return
    response_started = False

    def _start_response() -> None:
        nonlocal response_started
        if response_started:
            return
        handler.send_response(200)
        response_started = True
        handler.send_header('Content-Type', 'video/MP2T')
        handler.send_header('Cache-Control', 'no-store')
        handler.send_header('Connection', 'close')
        handler.end_headers()

    class _LazyProxyOutput:

        def write(self, data: bytes) -> int:
            if data:
                _start_response()
            return handler.wfile.write(data)

        def flush(self) -> None:
            if response_started:
                handler.wfile.flush()
    try:
        media_key = config.media_key
        if config.decrypt_video and media_key is None:
            if config.sms_code is None:
                media_key = client.get_cam_key(config.serial, max_retries=1)
            else:
                media_key = client.get_cam_key(config.serial, smscode=config.sms_code, max_retries=1)
        if config.decrypt_video and (not media_key):
            raise _owner.PyEzvizError('Could not get camera encryption key')
        stream = _owner.open_cloud_stream(client, config.serial, channel=config.channel, client_type=config.client_type, token_index=config.token_index, refresh_vtm=config.refresh_vtm, timeout=config.timeout)
        with _owner._closing_unconnected_cloud_stream(stream):
            startup_deadline = _owner._start_cli_cloud_stream(stream, timeout=config.timeout, duration_seconds=None)
            mpegps_transform = None
            rtp_transform = None
            rtp_audio_key = None
            if config.decrypt_video:
                mpegps_transform, rtp_transform, rtp_audio_key = _owner._stream_payload_decryptors_with_key(client, config.serial, codec=config.decrypt_codec, media_key=media_key)
            _owner.copy_cloud_stream_packets_to_mpegts(stream, _owner.cast(_owner.BinaryIO, _LazyProxyOutput()), ffmpeg_path=config.ffmpeg_path, max_packets=config.max_packets, first_packet_timeout=config.timeout, first_packet_deadline=startup_deadline, allow_encrypted=config.allow_encrypted, mpegps_transform=mpegps_transform, rtp_transform=rtp_transform, rtp_audio_key=rtp_audio_key, startup_timeout_seconds=60.0)
            if not response_started:
                raise _owner.EzvizNoMediaError('Cloud stream proxy supplied no media within the capture bound')
    except (BrokenPipeError, ConnectionResetError):
        _owner._LOGGER.debug('Stream proxy client disconnected')
    except _owner.PyEzvizError as err:
        _owner._LOGGER.error('%s', err)
        if response_started:
            if not handler.wfile.closed:
                handler.close_connection = True
        else:
            handler.send_error(502, str(err))

def _serve_stream_proxy(args: _owner.argparse.Namespace, client: _owner.EzvizClient) -> None:
    """Serve the experimental VTM-to-MPEG-TS HTTP proxy until interrupted."""
    media_key = _owner._explicit_cloud_cli_media_key(args) if args.decrypt_video else None
    config = _owner.StreamProxyConfig(serial=args.serial, channel=args.channel, client_type=args.client_type, token_index=args.token_index, refresh_vtm=not args.no_refresh_vtm, timeout=args.timeout, path=_owner._normalize_stream_proxy_path(args.path, args.serial), ffmpeg_path=args.ffmpeg_path, allow_encrypted=args.allow_encrypted, decrypt_video=args.decrypt_video, decrypt_codec=args.decrypt_codec, max_packets=args.max_packets, media_key=media_key, sms_code=getattr(args, 'sms_code', None))

    class StreamProxyHandler(_owner.BaseHTTPRequestHandler):
        server_version = 'pyezvizapi-stream-proxy/0'

        def do_GET(self) -> None:
            _owner._handle_stream_proxy_get(self, config, client)

        def log_message(self, format: str, *args: _owner.Any) -> None:
            _owner._LOGGER.info('stream proxy: ' + format, *args)
    try:
        server = _owner.StreamProxyHTTPServer((args.listen_host, args.listen_port), StreamProxyHandler)
    except OSError as err:
        raise _owner.PyEzvizError(f'Could not bind stream proxy to {args.listen_host}:{args.listen_port}: {err}') from err
    url = f'http://{args.listen_host}:{args.listen_port}{config.path}'
    _owner._LOGGER.info('Serving VTM stream proxy at %s', url)
    try:
        server.serve_forever()
    finally:
        server.server_close()

def _env_or_arg(args: _owner.argparse.Namespace, attr: str, env_name: str) -> str | None:
    """Return a CLI argument value or matching environment fallback."""
    value = getattr(args, attr, None)
    if value:
        return _owner.cast(str, value)
    env_value = _owner.os_environ_get(env_name)
    return env_value if env_value else None

def os_environ_get(name: str) -> str | None:
    """Small wrapper to make environment fallback easy to patch in tests."""
    return _owner.os.environ.get(name)

def _required_local_sdk_secret(args: _owner.argparse.Namespace, attr: str, env_name: str) -> str:
    """Read a required local-SDK secret without logging or persisting it."""
    value = _owner._env_or_arg(args, attr, env_name)
    if not value:
        raise _owner.PyEzvizError(f"Missing --{attr.replace('_', '-')} or {env_name}")
    return value

def _local_sdk_credentials_file(args: _owner.argparse.Namespace) -> dict[str, _owner.Any]:
    """Read a local-SDK credential bundle without logging secret values."""
    cached = getattr(args, '_local_sdk_credentials_file_data', None)
    if isinstance(cached, dict):
        return cached
    path = getattr(args, 'credentials_file', None)
    if not path:
        return {}
    try:
        data = _owner.json.loads(_owner.Path(path).read_text(encoding='utf-8'))
    except OSError as err:
        raise _owner.PyEzvizError(f'Could not read --credentials-file: {err}') from err
    except _owner.json.JSONDecodeError as err:
        raise _owner.PyEzvizError(f'Invalid --credentials-file JSON: {err}') from err
    if not isinstance(data, dict):
        raise _owner.PyEzvizError('--credentials-file must contain a JSON object')
    vars(args)['_local_sdk_credentials_file_data'] = data
    return data

def _local_sdk_credentials_value(args: _owner.argparse.Namespace, path: tuple[str, ...]) -> _owner.Any:
    """Return a value from the optional local-SDK credential bundle."""
    current: _owner.Any = _owner._local_sdk_credentials_file(args)
    for part in path:
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current
