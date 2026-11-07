"""commands local stream implementation; legacy runtime hooks remain on the owner module.

Access through _owner is deliberate: callers that patch the compatibility
module must still affect dependent operations. No copied hook snapshots.
"""
# ruff: noqa: SLF001 -- explicit legacy hook boundary.
from __future__ import annotations

import pyezvizapi.cli.main as _owner

def _local_sdk_arg_or_credentials(args: _owner.argparse.Namespace, attr: str, path: tuple[str, ...]) -> _owner.Any:
    """Return an explicit CLI value or matching credential-bundle value."""
    value = getattr(args, attr, None)
    if value not in (None, ''):
        return value
    return _owner._local_sdk_credentials_value(args, path)

def _required_local_sdk_arg_or_credentials(args: _owner.argparse.Namespace, attr: str, path: tuple[str, ...]) -> _owner.Any:
    """Return a required direct-local field from args or credentials file."""
    value = _owner._local_sdk_arg_or_credentials(args, attr, path)
    if value in (None, ''):
        option = attr.replace('_', '-')
        raise _owner.PyEzvizError(f'Missing --{option}; provide it explicitly or via --credentials-file')
    return value

def _local_sdk_media_key(args: _owner.argparse.Namespace, client: _owner.EzvizClient | None) -> str | bytes:
    """Read the direct-local media decrypt key without logging or persisting it."""
    key_hex = _owner._env_or_arg(args, 'media_key_hex', 'EZVIZ_LOCAL_MEDIA_KEY_HEX')
    if key_hex:
        try:
            return bytes.fromhex(key_hex)
        except ValueError as err:
            raise _owner.PyEzvizError('Invalid --media-key-hex/EZVIZ_LOCAL_MEDIA_KEY_HEX') from err
    key = _owner._env_or_arg(args, 'media_key', 'EZVIZ_LOCAL_MEDIA_KEY')
    if key:
        return key
    credential_key_hex = _owner._local_sdk_credentials_value(args, ('media_key_hex',))
    if credential_key_hex:
        try:
            return bytes.fromhex(str(credential_key_hex))
        except ValueError as err:
            raise _owner.PyEzvizError('Invalid media_key_hex in --credentials-file') from err
    credential_key = _owner._local_sdk_credentials_value(args, ('media_key',))
    if credential_key:
        return str(credential_key)
    if client is not None:
        serial = str(_owner._required_local_sdk_arg_or_credentials(args, 'serial', ('serial',)))
        sms_code = getattr(args, 'sms_code', None)
        if sms_code is None:
            cloud_key = client.get_cam_key(serial, max_retries=1)
        else:
            cloud_key = client.get_cam_key(serial, smscode=sms_code, max_retries=1)
        if cloud_key:
            return str(cloud_key)
    raise _owner.PyEzvizError('Missing media key for --decrypt-video; provide --media-key, --media-key-hex, EZVIZ_LOCAL_MEDIA_KEY, EZVIZ_LOCAL_MEDIA_KEY_HEX, credentials-file media_key/media_key_hex, or authenticated client access')

def _local_sdk_has_static_media_key(args: _owner.argparse.Namespace) -> bool:
    """Return True when local-sdk-dump can decrypt without cloud key lookup."""
    return bool(_owner._env_or_arg(args, 'media_key_hex', 'EZVIZ_LOCAL_MEDIA_KEY_HEX') or _owner._env_or_arg(args, 'media_key', 'EZVIZ_LOCAL_MEDIA_KEY') or _owner._local_sdk_credentials_value(args, ('media_key_hex',)) or _owner._local_sdk_credentials_value(args, ('media_key',)))

def _read_optional_binary_file(path: str | None) -> bytes | None:
    """Read an optional caller-owned binary body from disk."""
    if not path:
        return None
    return _owner.Path(path).read_bytes()

def _local_sdk_cas_device_info(args: _owner.argparse.Namespace, client: _owner.EzvizClient | None) -> _owner.EzvizCasDeviceInfo:
    """Build local CAS device info from explicit fields or cloud CAS."""
    if args.fetch_cas:
        if client is None:
            raise _owner.PyEzvizError('--fetch-cas requires --token-file or credentials')
        serial = str(_owner._required_local_sdk_arg_or_credentials(args, 'serial', ('serial',)))
        cas_serial = args.cas_serial or serial
        if not args.no_p2p_register:
            register = getattr(client, 'register_p2p_session', None)
            if callable(register):
                register(max_retries=_owner.MAX_RETRIES)
        session = _owner.CasDeviceSession.from_response(_owner.EzvizCAS(client.export_token()).cas_get_encryption(cas_serial))
        return _owner.EzvizCasDeviceInfo(serial=serial, operation_code=session.operation_code, key=session.key, encrypt_type=session.encrypt_type)
    operation_code = _owner._env_or_arg(args, 'operation_code', 'EZVIZ_LOCAL_OPERATION_CODE') or _owner._local_sdk_credentials_value(args, ('cas', 'operation_code'))
    if not operation_code:
        raise _owner.PyEzvizError('Missing --operation-code or EZVIZ_LOCAL_OPERATION_CODE; provide it explicitly or via --credentials-file')
    cas_key = _owner._env_or_arg(args, 'cas_key', 'EZVIZ_LOCAL_CAS_KEY') or _owner._local_sdk_credentials_value(args, ('cas', 'key'))
    if not cas_key:
        raise _owner.PyEzvizError('Missing --cas-key or EZVIZ_LOCAL_CAS_KEY; provide it explicitly or via --credentials-file')
    serial = str(_owner._required_local_sdk_arg_or_credentials(args, 'serial', ('serial',)))
    encrypt_type = _owner._local_sdk_arg_or_credentials(args, 'encrypt_type', ('cas', 'encrypt_type'))
    return _owner.EzvizCasDeviceInfo(serial=serial, operation_code=str(operation_code), key=str(cas_key), encrypt_type=int(encrypt_type))

def _build_local_sdk_cli_stream(args: _owner.argparse.Namespace, client: _owner.EzvizClient | None=None) -> _owner.Any:
    """Build the direct-local SDK stream from explicit CLI/environment fields."""
    device_info = _owner._local_sdk_cas_device_info(args, client)
    host = str(_owner._required_local_sdk_arg_or_credentials(args, 'host', ('endpoint', 'host')))
    endpoint = _owner.HcNetSdkLanEndpoint(serial=device_info.serial, host=host, command_port=int(_owner._local_sdk_arg_or_credentials(args, 'command_port', ('endpoint', 'command_port')) or 9010), stream_port=int(_owner._local_sdk_arg_or_credentials(args, 'stream_port', ('endpoint', 'stream_port')) or 9020))
    preview_request = _owner.EzvizLocalPreviewRequest(operation_code=device_info.operation_code, channel=args.channel, receiver_info=_owner._local_sdk_receiver_info_from_args(args), receiver_info_ex=_owner._local_sdk_receiver_info_ex_from_args(args), authentication=_owner._local_sdk_authentication_from_args(args), is_encrypt=args.is_encrypt, identifier=args.identifier, uuid=_owner._env_or_arg(args, 'uuid', 'EZVIZ_LOCAL_UUID') if args.receiver_shape == 'app' else None, timestamp=_owner._env_or_arg(args, 'timestamp', 'EZVIZ_LOCAL_TIMESTAMP') if args.receiver_shape == 'app' else None, udt=args.udt, nat=args.nat, port_guess_type=args.port_guess_type, timeout=args.setup_timeout, heartbeat_interval=args.heartbeat_interval)
    pre_start_sequence = 27 if args.pre_start_sequence is None else args.pre_start_sequence
    preview_sequence = 28 if args.preview_sequence is None else args.preview_sequence
    stream_setup_sequence = 29 if args.stream_sequence is None else args.stream_sequence
    return _owner.open_local_sdk_stream(endpoint, device_info, preview_request, timeout=args.socket_timeout, pre_start_body=_owner._read_optional_binary_file(args.pre_start_body_file), pre_start_sequence=pre_start_sequence, preview_sequence=preview_sequence, stream_setup_sequence=stream_setup_sequence, stream_rate=args.stream_rate, stream_mode=args.stream_mode, max_prefix_bytes=args.max_prefix_bytes, command_source_port=args.receiver_port if args.receiver_shape == 'app' else None)

def _build_local_sdk_ecdh_cli_stream(args: _owner.argparse.Namespace, client: _owner.EzvizClient | None=None) -> _owner.Any:
    """Build an encrypted local SDK ECDH stream."""
    device_info = _owner._local_sdk_cas_device_info(args, client)
    host = str(_owner._required_local_sdk_arg_or_credentials(args, 'host', ('endpoint', 'host')))
    endpoint = _owner.HcNetSdkLanEndpoint(serial=device_info.serial, host=host, command_port=int(_owner._local_sdk_arg_or_credentials(args, 'command_port', ('endpoint', 'command_port')) or 9010), stream_port=int(_owner._local_sdk_arg_or_credentials(args, 'stream_port', ('endpoint', 'stream_port')) or 9020))
    return _owner.open_local_sdk_ecdh_stream(endpoint, device_info, channel=args.channel, receiver_port=args.local_sdk_ecdh_receiver_port, identifier=args.identifier, uuid=_owner._env_or_arg(args, 'uuid', 'EZVIZ_LOCAL_UUID'), timestamp=_owner._env_or_arg(args, 'timestamp', 'EZVIZ_LOCAL_TIMESTAMP'), send_init=args.local_sdk_ecdh_send_init, pre_start_body=_owner._read_optional_binary_file(args.pre_start_body_file), pre_start_sequence=args.pre_start_sequence, preview_sequence=args.preview_sequence, stream_setup_sequence=args.stream_sequence, stream_rate=args.stream_rate, stream_mode=args.stream_mode, timeout=args.socket_timeout, max_prefix_bytes=args.max_prefix_bytes)

def _local_sdk_receiver_info_from_args(args: _owner.argparse.Namespace) -> _owner.EzvizLocalReceiverInfo | _owner.EzvizLocalReceiverInfoAttrs:
    """Build the requested ReceiverInfo XML shape for local-SDK preview."""
    if args.receiver_shape == 'structured':
        return _owner.EzvizLocalReceiverInfo(nat_address=args.nat_address, nat_port=args.nat_port, upnp_address=args.upnp_address, upnp_port=args.upnp_port, inner_address=args.inner_address, inner_port=args.inner_port, stream_type=args.receiver_stream_type)
    return _owner.EzvizLocalReceiverInfoAttrs(address=args.nat_address, port=args.receiver_port, server_type=args.receiver_server_type, stream_type=args.receiver_stream_type, new_stream_type=args.receiver_new_stream_type, trans_proto=args.receiver_trans_proto)

def _local_sdk_receiver_info_ex_from_args(args: _owner.argparse.Namespace) -> _owner.EzvizLocalReceiverInfoEx | _owner.EzvizLocalReceiverInfoExAttrs:
    """Build the requested ReceiverInfoEx XML shape for local-SDK preview."""
    if args.receiver_shape == 'structured':
        return _owner.EzvizLocalReceiverInfoEx(uuid=_owner._env_or_arg(args, 'uuid', 'EZVIZ_LOCAL_UUID'), timestamp=_owner._env_or_arg(args, 'timestamp', 'EZVIZ_LOCAL_TIMESTAMP'))
    return _owner.EzvizLocalReceiverInfoExAttrs(port=args.receiver_ex_port)

def _local_sdk_authentication_from_args(args: _owner.argparse.Namespace) -> _owner.EzvizLocalAuthenticationAttrs | None:
    """Return app-shaped Authentication only when that XML shape is requested."""
    if args.receiver_shape == 'structured':
        return None
    return _owner.EzvizLocalAuthenticationAttrs(biz_code=args.auth_biz_code, interval=args.auth_interval)

def _handle_local_sdk_stream_dump(args: _owner.argparse.Namespace, client: _owner.EzvizClient | None=None) -> int:
    """Dump direct-local SDK media with caller-supplied local fields."""
    if args.decrypt_video and (not _owner.has_positive_finite_capture_bound(max_packets=args.max_packets, duration_seconds=args.duration)):
        raise _owner.PyEzvizError('--decrypt-video requires a positive finite --duration or --max-packets before opening a local SDK stream')
    if args.format is None:
        args.format = 'mpegps' if args.local_sdk_ecdh and (not args.decrypt_video) else 'mpegts'
    if args.local_sdk_ecdh:
        with _owner._build_local_sdk_ecdh_cli_stream(args, client) as stream:
            if args.output == '-':
                _owner._copy_local_sdk_ecdh_cli_stream(args, client, stream, _owner.sys.stdout.buffer)
            else:
                with _owner.Path(args.output).open('wb') as output:
                    _owner._copy_local_sdk_ecdh_cli_stream(args, client, stream, output)
            _owner._write_local_sdk_metadata_output(args.metadata_output, stream)
        return 0
    with _owner._build_local_sdk_cli_stream(args, client) as stream:
        if args.output == '-':
            if args.decrypt_video and args.format == 'mpegps':
                _owner.copy_local_stream_to_decrypted_mpegps(stream, _owner.sys.stdout.buffer, _owner._local_sdk_media_key(args, client), nalu_header_size=_owner._codec_nalu_header_size(args.decrypt_codec), max_packets=args.max_packets, duration_seconds=args.duration)
            elif args.decrypt_video:
                _owner.copy_local_stream_to_decrypted_mpegts(stream, _owner.sys.stdout.buffer, _owner._local_sdk_media_key(args, client), ffmpeg_path=args.ffmpeg_path, nalu_header_size=_owner._codec_nalu_header_size(args.decrypt_codec), max_packets=args.max_packets, duration_seconds=args.duration)
            elif args.format == 'mpegps':
                _owner.copy_local_stream_to_mpegps(stream, _owner.sys.stdout.buffer, max_packets=args.max_packets, duration_seconds=args.duration)
            else:
                _owner.copy_local_stream_to_mpegts(stream, _owner.sys.stdout.buffer, ffmpeg_path=args.ffmpeg_path, max_packets=args.max_packets, duration_seconds=args.duration)
            _owner._write_local_sdk_metadata_output(args.metadata_output, stream)
            return 0
        with _owner.Path(args.output).open('wb') as output:
            if args.decrypt_video and args.format == 'mpegps':
                _owner.copy_local_stream_to_decrypted_mpegps(stream, output, _owner._local_sdk_media_key(args, client), nalu_header_size=_owner._codec_nalu_header_size(args.decrypt_codec), max_packets=args.max_packets, duration_seconds=args.duration)
            elif args.decrypt_video:
                _owner.copy_local_stream_to_decrypted_mpegts(stream, output, _owner._local_sdk_media_key(args, client), ffmpeg_path=args.ffmpeg_path, nalu_header_size=_owner._codec_nalu_header_size(args.decrypt_codec), max_packets=args.max_packets, duration_seconds=args.duration)
            elif args.format == 'mpegps':
                _owner.copy_local_stream_to_mpegps(stream, output, max_packets=args.max_packets, duration_seconds=args.duration)
            else:
                _owner.copy_local_stream_to_mpegts(stream, output, ffmpeg_path=args.ffmpeg_path, max_packets=args.max_packets, duration_seconds=args.duration)
        _owner._write_local_sdk_metadata_output(args.metadata_output, stream)
    return 0

def _copy_local_sdk_ecdh_cli_stream(args: _owner.argparse.Namespace, client: _owner.EzvizClient | None, stream: _owner.Any, output: _owner.BinaryIO) -> None:
    """Copy one CLI-selected ECDH stream to its requested container."""
    _owner.copy_local_sdk_ecdh_stream_to_media(stream, output, output_format=args.format, decrypt_video=args.decrypt_video, media_key=_owner._local_sdk_media_key(args, client) if args.decrypt_video else None, ffmpeg_path=args.ffmpeg_path, nalu_header_size=_owner._codec_nalu_header_size(args.decrypt_codec), max_packets=args.max_packets, max_frames=args.max_packets, duration_seconds=args.duration)

def _handle_local_sdk_keys(args: _owner.argparse.Namespace, client: _owner.EzvizClient) -> int:
    """Fetch and print direct-local SDK credentials for explicit setup flows."""
    credentials = _owner.get_local_sdk_stream_credentials_from_client(client, args.serial, cas_serial=args.cas_serial, fetch_media_key=not args.no_media_key, register_p2p_session=not args.no_p2p_register, smscode=args.sms_code)
    _owner._write_json(credentials.as_dict(include_media_key=not args.no_media_key))
    return 0

def _handle_h264_annexb_summary(args: _owner.argparse.Namespace) -> int:
    """Summarize a local H.264 Annex-B elementary stream."""
    data = _owner.Path(args.input).read_bytes()
    idr_windows = _owner.summarize_h264_annexb_idr_windows(data, max_windows=args.max_idr_windows)
    summary: dict[str, _owner.Any] = {'input': args.input, 'units': _owner.summarize_h264_annexb_units(data, max_units=args.max_units), 'idr_windows': idr_windows}
    if args.decode_idr_windows:
        summary['decode_idr_windows'] = _owner._decode_h264_annexb_idr_windows(data, idr_windows, ffmpeg_path=args.ffmpeg_path)
    _owner._write_json(summary)
    return 0

def _handle_hcnetsdk_command_dump_summary(args: _owner.argparse.Namespace) -> int:
    """Summarize offline HCNetSDK command-port dump artifacts."""
    if not args.command_frame_dir and (not args.inbound_media_file) and (not args.playm4_input_dir) and (not args.native_annexb_dir):
        raise _owner.PyEzvizError('hcnetsdk-command-dump-summary requires --command-frame-dir or --inbound-media-file or --playm4-input-dir or --native-annexb-dir')
    summary: dict[str, _owner.Any] = {}
    if args.command_frame_dir:
        summary['command_frames'] = _owner._hcnetsdk_command_frame_dump_summary(_owner.Path(args.command_frame_dir), max_frames=args.max_frames)
    if args.inbound_media_file:
        summary['inbound_media'] = _owner._hcnetsdk_inbound_media_dump_summary(_owner.Path(args.inbound_media_file), max_frames=args.max_frames, decode_idr_windows=args.decode_idr_windows, ffmpeg_path=args.ffmpeg_path)
    if args.playm4_input_dir:
        summary['playm4_input'] = _owner._hcnetsdk_playm4_input_dump_summary(_owner.Path(args.playm4_input_dir), max_frames=args.max_frames, decode_idr_windows=args.decode_idr_windows, ffmpeg_path=args.ffmpeg_path)
    if args.native_annexb_dir:
        summary['native_annexb'] = _owner._hcnetsdk_native_annexb_dump_summary(_owner.Path(args.native_annexb_dir), label=args.native_annexb_label, codec=args.native_annexb_codec, max_frames=args.max_frames, decode_idr_windows=args.decode_idr_windows, ffmpeg_path=args.ffmpeg_path)
    _owner._write_json(summary)
    return 0

def _hcnetsdk_command_frame_dump_summary(directory: _owner.Path, *, max_frames: int) -> dict[str, _owner.Any]:
    """Return sanitized metadata for dumped outbound command frames."""
    if max_frames <= 0:
        raise _owner.PyEzvizError('--max-frames must be positive')
    if not directory.is_dir():
        raise _owner.PyEzvizError(f'Command frame dump directory not found: {directory}')
    paths = sorted(directory.rglob('ezviz-hcnetsdk-command-frame-*.bin'))
    samples: list[dict[str, _owner.Any]] = []
    command_counts: dict[str, int] = {}
    parse_errors: list[dict[str, str]] = []
    for path in paths:
        try:
            frame_bytes = path.read_bytes()
            frame = _owner.parse_hcnetsdk_tcp_frame(frame_bytes)
        except (OSError, _owner.PyEzvizError) as err:
            if len(parse_errors) < max_frames:
                parse_errors.append({'path': str(path), 'error': str(err)})
            continue
        command_id = frame.header.field_12 if frame.header.field_4 == _owner.HCNETSDK_COMMAND_PORT_CONTROL_FAMILY else None
        if command_id is not None:
            key = f'0x{command_id:x}'
            command_counts[key] = command_counts.get(key, 0) + 1
        if len(samples) >= max_frames:
            continue
        sample: dict[str, _owner.Any] = {'path': str(path), 'length': len(frame_bytes), 'total_length': frame.header.total_length, 'field_4': frame.header.field_4, 'field_8': frame.header.field_8, 'field_12': frame.header.field_12, 'body_length': len(frame.body), 'body_prefix_hex': frame.body[:16].hex()}
        if command_id is not None:
            sample['command_id'] = command_id
            sample['auth_word'] = frame.header.field_8
            tail = frame.body[16:]
            if tail:
                sample['body_tail_length'] = len(tail)
                sample['body_tail_word_samples'] = _owner._hcnetsdk_command_port_body_tail_word_samples(tail)
        samples.append(sample)
    return {'input': str(directory), 'file_count': len(paths), 'sample_limit': max_frames, 'samples': samples, 'truncated': len(paths) > len(samples), 'command_counts': command_counts, 'parse_errors': parse_errors}

def _hcnetsdk_inbound_media_dump_summary(path: _owner.Path, *, max_frames: int, decode_idr_windows: bool, ffmpeg_path: str) -> dict[str, _owner.Any]:
    """Return sanitized metadata for raw dumped command-port inbound media bytes."""
    if max_frames <= 0:
        raise _owner.PyEzvizError('--max-frames must be positive')
    try:
        data = path.read_bytes()
    except OSError as err:
        raise _owner.PyEzvizError(f'Inbound media dump not found: {path}') from err
    scan = _owner._scan_hcnetsdk_command_port_media_frames(data, max_frames=max_frames)
    summary: dict[str, _owner.Any] = {'input': str(path), 'byte_count': len(data), **scan}
    payloads = scan.get('payloads')
    if isinstance(payloads, list):
        packet_payloads = _owner.cast(list[bytes], payloads)
        summary['idmx_h264'] = _owner.summarize_idmx_h264_local_packets(packet_payloads, max_frames=max_frames)
        _owner._add_hcnetsdk_annexb_dump_summary(summary, packet_payloads, max_frames=max_frames, decode_idr_windows=decode_idr_windows, ffmpeg_path=ffmpeg_path)
        del summary['payloads']
    return summary

def _hcnetsdk_playm4_input_dump_summary(directory: _owner.Path, *, max_frames: int, decode_idr_windows: bool, ffmpeg_path: str) -> dict[str, _owner.Any]:
    """Return sanitized metadata for PlayM4 input dump chunks."""
    if max_frames <= 0:
        raise _owner.PyEzvizError('--max-frames must be positive')
    if not directory.is_dir():
        raise _owner.PyEzvizError(f'PlayM4 input dump directory not found: {directory}')
    paths = sorted(directory.rglob('*-playm4-input-*.bin'))
    packets = [path.read_bytes() for path in paths]
    summary: dict[str, _owner.Any] = {'input': str(directory), 'file_count': len(paths), 'byte_count': sum((len(packet) for packet in packets)), 'idmx_h264': _owner.summarize_idmx_h264_local_packets(packets, max_frames=max_frames)}
    _owner._add_hcnetsdk_annexb_dump_summary(summary, packets, max_frames=max_frames, decode_idr_windows=decode_idr_windows, ffmpeg_path=ffmpeg_path)
    return summary

def _hcnetsdk_native_annexb_dump_summary(directory: _owner.Path, *, label: str, codec: str, max_frames: int, decode_idr_windows: bool, ffmpeg_path: str) -> dict[str, _owner.Any]:
    """Return sanitized metadata for native Annex-B Frida dump chunks."""
    if max_frames <= 0:
        raise _owner.PyEzvizError('--max-frames must be positive')
    if not directory.is_dir():
        raise _owner.PyEzvizError(f'Native Annex-B dump directory not found: {directory}')
    paths = sorted(directory.rglob(f'*-{label}-*.bin'))
    chunks = [path.read_bytes() for path in paths]
    data = b''.join(chunks)
    detected_codec = _owner._detect_native_annexb_codec(data, requested=codec)
    samples = [{'path': str(path), 'size': len(chunk), 'sha256': _owner.hashlib.sha256(chunk).hexdigest()} for path, chunk in zip(paths[:max_frames], chunks[:max_frames], strict=False)]
    summary: dict[str, _owner.Any] = {'input': str(directory), 'label': label, 'codec': detected_codec, 'requested_codec': codec, 'file_count': len(paths), 'byte_count': len(data), 'sample_limit': max_frames, 'samples': samples, 'truncated': len(paths) > len(samples)}
    if detected_codec == 'hevc':
        irap_windows = _owner.summarize_hevc_annexb_irap_windows(data, max_windows=max_frames)
        summary['annexb_irap_windows'] = irap_windows
        if decode_idr_windows:
            summary['decode_irap_windows'] = _owner._decode_annexb_windows(data, irap_windows, ffmpeg_path=ffmpeg_path, input_format='hevc')
            summary['decode_chunk_windows'] = _owner._decode_native_annexb_chunk_windows(paths, codec='hevc', max_windows=max_frames, ffmpeg_path=ffmpeg_path)
        return summary
    idr_windows = _owner.summarize_h264_annexb_idr_windows(data, max_windows=max_frames)
    summary['annexb_units'] = _owner.summarize_h264_annexb_units(data, max_units=max_frames)
    summary['annexb_idr_windows'] = idr_windows
    if decode_idr_windows:
        summary['decode_idr_windows'] = _owner._decode_annexb_windows(data, idr_windows, ffmpeg_path=ffmpeg_path, input_format='h264')
        summary['decode_chunk_windows'] = _owner._decode_native_annexb_chunk_windows(paths, codec='h264', max_windows=max_frames, ffmpeg_path=ffmpeg_path)
    return summary

def _decode_native_annexb_chunk_windows(paths: list[_owner.Path], *, codec: str, max_windows: int, ffmpeg_path: str) -> list[dict[str, _owner.Any]]:
    """Decode sampled IDR/IRAP-bearing native dump chunks independently."""
    results: list[dict[str, _owner.Any]] = []
    for path in paths:
        data = path.read_bytes()
        if codec == 'hevc':
            windows = _owner.summarize_hevc_annexb_irap_windows(data, max_windows=1)
            decoded = _owner._decode_annexb_windows(data, windows, ffmpeg_path=ffmpeg_path, input_format='hevc')
        else:
            windows = _owner.summarize_h264_annexb_idr_windows(data, max_windows=1)
            decoded = _owner._decode_annexb_windows(data, windows, ffmpeg_path=ffmpeg_path, input_format='h264')
        if not decoded:
            continue
        result = {'path': str(path), 'size': len(data), **decoded[0]}
        results.append(result)
        if len(results) >= max_windows:
            break
    return results

def _detect_native_annexb_codec(data: bytes, *, requested: str) -> str:
    """Return the requested or likely codec for Annex-B dump bytes."""
    if requested != 'auto':
        return requested
    h264_score = 0
    hevc_score = 0
    for index, prefix in enumerate(_owner._iter_annexb_nal_prefixes(data)):
        if index >= 256:
            break
        h264_type = prefix[0] & 31
        hevc_type = prefix[0] >> 1 & 63
        if h264_type in {1, 5, 6, 7, 8, 9}:
            h264_score += 2 if h264_type in {5, 7, 8} else 1
        if hevc_type in {32, 33, 34}:
            hevc_score += 3
        elif 16 <= hevc_type <= 23:
            hevc_score += 2
        elif 0 <= hevc_type <= 31:
            hevc_score += 1
    return 'hevc' if hevc_score > h264_score else 'h264'

def _iter_annexb_nal_prefixes(data: bytes) -> _owner.Iterator[bytes]:
    """Yield the first bytes after Annex-B start codes."""
    offset = 0
    while offset < len(data):
        three = data.find(b'\x00\x00\x01', offset)
        four = data.find(b'\x00\x00\x00\x01', offset)
        if three < 0 and four < 0:
            return
        if four >= 0 and (three < 0 or four <= three):
            start_code_offset = four
            start_code_size = 4
        else:
            start_code_offset = three
            start_code_size = 3
        nal_offset = start_code_offset + start_code_size
        if nal_offset < len(data):
            yield data[nal_offset:nal_offset + 2]
        offset = nal_offset + 1

def _add_hcnetsdk_annexb_dump_summary(summary: dict[str, _owner.Any], packets: list[bytes], *, max_frames: int, decode_idr_windows: bool, ffmpeg_path: str) -> None:
    """Attach sanitized reconstructed Annex-B metadata to a dump summary."""
    try:
        annexb, codec = _owner._idmx_local_packets_to_annexb_with_codec(packets)
    except _owner.PyEzvizError as err:
        summary['annexb_error'] = str(err)
        return
    summary['annexb_codec'] = codec
    if codec == 'hevc':
        irap_windows = _owner.summarize_hevc_annexb_irap_windows(annexb, max_windows=max_frames)
        summary['annexb_irap_windows'] = irap_windows
        if decode_idr_windows:
            summary['decode_irap_windows'] = _owner._decode_annexb_windows(annexb, irap_windows, ffmpeg_path=ffmpeg_path, input_format='hevc')
        return
    idr_windows = _owner.summarize_h264_annexb_idr_windows(annexb, max_windows=max_frames)
    summary['annexb_units'] = _owner.summarize_h264_annexb_units(annexb, max_units=max_frames)
    summary['annexb_idr_windows'] = idr_windows
    if decode_idr_windows:
        summary['decode_idr_windows'] = _owner._decode_annexb_windows(annexb, idr_windows, ffmpeg_path=ffmpeg_path, input_format='h264')

def _scan_hcnetsdk_command_port_media_frames(data: bytes, *, max_frames: int) -> dict[str, _owner.Any]:
    """Scan raw command-port bytes for little-endian ``$`` media frames."""
    offset = 0
    payloads: list[bytes] = []
    samples: list[dict[str, _owner.Any]] = []
    prefix_bytes = 0
    invalid_markers = 0
    while offset < len(data):
        marker = data.find(b'$', offset)
        if marker < 0:
            prefix_bytes += len(data) - offset
            break
        prefix_bytes += marker - offset
        if marker + 4 > len(data):
            invalid_markers += 1
            break
        channel = data[marker + 1]
        total_length = int.from_bytes(data[marker + 2:marker + 4], 'little')
        if total_length < 4 or marker + total_length > len(data):
            invalid_markers += 1
            offset = marker + 1
            continue
        payload = data[marker + 4:marker + total_length]
        payloads.append(payload)
        if len(samples) < max_frames:
            samples.append({'index': len(payloads) - 1, 'offset': marker, 'channel': channel, 'total_length': total_length, 'payload_length': len(payload), 'payload_prefix_hex': payload[:16].hex(), 'payload_sha256': _owner.hashlib.sha256(payload).hexdigest()})
        offset = marker + total_length
    return {'frame_count': len(payloads), 'prefix_bytes': prefix_bytes, 'invalid_markers': invalid_markers, 'sample_limit': max_frames, 'samples': samples, 'truncated': len(payloads) > len(samples), 'payloads': payloads}

def _handle_hcnetsdk_command_plan_generate(args: _owner.argparse.Namespace) -> int:
    """Convert concrete port-8000 control frames into generated templates."""
    try:
        data = _owner.json.loads(_owner.Path(args.input).read_text(encoding='utf-8'))
    except _owner.json.JSONDecodeError as err:
        raise _owner.PyEzvizError('Invalid HCNetSDK command plan JSON') from err
    concrete = _owner._hcnetsdk_command_plan_from_json(data)
    auth_seed = None if args.auth_seed is None else _owner._hcnetsdk_int(args.auth_seed)
    key = None if args.key_hex is None else _owner._bytes_from_hex_value(args.key_hex)
    if (auth_seed is None) != (key is None):
        raise _owner.PyEzvizError('--auth-seed and --key-hex must be supplied together')
    generated = _owner.hcnetsdk_command_port_generated_plan_from_socket_plan(concrete, auth_seed=auth_seed, key=key)
    text = _owner.json.dumps(_owner._hcnetsdk_generated_plan_to_json(generated), indent=2, sort_keys=True) + '\n'
    if args.output == '-':
        _owner.sys.stdout.write(text)
    else:
        output_path = _owner.Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(text, encoding='utf-8')
    return 0

def _hcnetsdk_generated_plan_to_json(plan: _owner.HcNetSdkCommandPortGeneratedMultiSocketPlan) -> dict[str, _owner.Any]:
    """Return the public JSON shape for a generated command-port plan."""
    return {'steps': [_owner._hcnetsdk_generated_plan_step_to_json(step) for step in plan.steps]}

def _hcnetsdk_generated_plan_step_to_json(step: _owner.HcNetSdkCommandPortGeneratedSocketStep) -> dict[str, _owner.Any]:
    """Return JSON for one generated command-port socket step."""
    value: dict[str, _owner.Any] = {'templates': [_owner._hcnetsdk_command_template_to_json(template) for template in step.control_templates]}
    if step.name is not None:
        value['name'] = step.name
    if step.read_response_after_each is not True:
        value['read_responses'] = step.read_response_after_each
    if step.response_reads_after_each is not None:
        value['response_reads'] = step.response_reads_after_each
    if step.media_socket:
        value['media_socket'] = True
    if step.read_first_media_immediately:
        value['read_first_media_immediately'] = True
    if step.delay_after_commands_seconds:
        value['delay_after_commands_seconds'] = step.delay_after_commands_seconds
    if step.drain_media_before_next_step_seconds:
        value['drain_media_before_next_step_seconds'] = step.drain_media_before_next_step_seconds
    if step.keepalive_templates:
        value['keepalive_templates'] = [_owner._hcnetsdk_command_template_to_json(template) for template in step.keepalive_templates]
    if step.keepalive_interval_seconds != _owner.HCNETSDK_COMMAND_PLAN_DEFAULT_KEEPALIVE_INTERVAL_SECONDS:
        value['keepalive_interval_seconds'] = step.keepalive_interval_seconds
    if step.keepalive_initial_delay_seconds is not None:
        value['keepalive_initial_delay_seconds'] = step.keepalive_initial_delay_seconds
    return value

def _hcnetsdk_command_template_to_json(template: _owner.HcNetSdkCommandPortControlTemplate) -> dict[str, _owner.Any]:
    """Return JSON for one generated command-port control template."""
    value: dict[str, _owner.Any] = {'command_id': f'0x{template.command_id:x}'}
    if template.name is not None:
        value['name'] = template.name
    if template.body_tail:
        value['body_tail_hex'] = template.body_tail.hex()
    if template.addend is not None:
        value['addend'] = f'0x{template.addend:x}'
    if template.addend_delta is not None:
        value['addend_delta'] = template.addend_delta
    if template.mask_seed != b'\x00' * 6:
        value['mask_seed_hex'] = template.mask_seed.hex()
    if template.body_tail_transform is not None:
        value['body_tail_transform'] = template.body_tail_transform
    return value

def _decode_annexb_windows(data: bytes, window_summary: _owner.Mapping[str, _owner.Any], *, ffmpeg_path: str, input_format: str) -> list[dict[str, _owner.Any]]:
    """Return bounded ffmpeg decode results for sampled Annex-B windows."""
    results: list[dict[str, _owner.Any]] = []
    samples = window_summary.get('samples')
    if not isinstance(samples, list):
        return results
    for sample in samples:
        if not isinstance(sample, _owner.Mapping):
            continue
        start_offset = sample.get('start_code_offset')
        if not isinstance(start_offset, int):
            continue
        cut = data[start_offset:]
        result: dict[str, _owner.Any] = {'index': sample.get('index'), 'start_code_offset': start_offset, 'input_bytes': len(cut)}
        try:
            completed = _owner.subprocess.run([ffmpeg_path, '-v', 'error', '-f', input_format, '-i', 'pipe:0', '-f', 'null', '-'], input=cut, stdout=_owner.subprocess.DEVNULL, stderr=_owner.subprocess.PIPE, check=False, timeout=30)
        except OSError as err:
            raise _owner.PyEzvizError(f'Could not launch FFmpeg at {ffmpeg_path!r}: {err}') from err
        except _owner.subprocess.TimeoutExpired:
            result['returncode'] = None
            result['decode_clean'] = False
            result['stderr'] = ['ffmpeg decode timed out']
            results.append(result)
            continue
        stderr_text = completed.stderr.decode('utf-8', errors='replace')
        stderr_lines = [line for line in stderr_text.splitlines() if line][:8]
        result['returncode'] = completed.returncode
        result['decode_clean'] = completed.returncode == 0 and (not stderr_lines)
        result['stderr'] = stderr_lines
        results.append(result)
    return results

def _decode_h264_annexb_idr_windows(data: bytes, idr_summary: _owner.Mapping[str, _owner.Any], *, ffmpeg_path: str) -> list[dict[str, _owner.Any]]:
    """Return bounded ffmpeg decode results for sampled H.264 IDR windows."""
    return _owner._decode_annexb_windows(data, idr_summary, ffmpeg_path=ffmpeg_path, input_format='h264')

def _write_local_sdk_metadata_output(path: str | None, stream: _owner.Any, *, packet_output_path: str | None=None) -> None:
    """Write safe stream metadata and optional bounded packet samples."""
    metadata = _owner._local_sdk_stream_metadata(stream)
    if packet_output_path:
        _owner._write_hcnetsdk_sampled_packet_output(packet_output_path, stream)
    if path:
        output_path = _owner.Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(_owner.json.dumps(metadata, indent=2, sort_keys=True) + '\n', encoding='utf-8')

def _write_hcnetsdk_sampled_packet_output(path: str, stream: _owner.Any) -> None:
    """Write bounded sampled command-port packets as raw dump-compatible frames."""
    packets = getattr(stream, '_idmx_summary_packets', None)
    if not isinstance(packets, list):
        return
    output_path = _owner.Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open('wb') as output:
        for packet in packets:
            if not isinstance(packet, bytes):
                continue
            output.write(b'$\x00')
            output.write((len(packet) + 4).to_bytes(2, 'little'))
            output.write(packet)

def _local_sdk_stream_metadata(stream: _owner.Any) -> dict[str, _owner.Any]:
    """Return non-secret direct-local SDK bootstrap and media metadata."""
    finalize_packet_summary = getattr(stream, 'finalize_packet_summary', None)
    if callable(finalize_packet_summary):
        finalize_packet_summary()
    bootstrap = getattr(stream, 'bootstrap', None)
    metadata: dict[str, _owner.Any] = {'bootstrap_complete': bootstrap is not None}
    sdk_client = getattr(stream, 'sdk_client', None)
    endpoint = getattr(sdk_client, 'endpoint', None)
    if endpoint is not None:
        metadata['endpoint'] = {'serial': getattr(endpoint, 'serial', None), 'host': getattr(endpoint, 'host', None), 'command_port': getattr(endpoint, 'command_port', None), 'stream_port': getattr(endpoint, 'stream_port', None)}
    if bootstrap is None:
        return metadata
    command_port_exchanges = getattr(bootstrap, 'exchanges', None)
    if command_port_exchanges is not None:
        metadata['command_port_exchanges'] = [_owner._hcnetsdk_command_port_exchange_metadata(exchange) for exchange in command_port_exchanges]
    packet_summary = getattr(stream, 'packet_summary', None)
    if isinstance(packet_summary, dict):
        metadata['packets'] = packet_summary
    keepalive_events = getattr(stream, 'keepalive_events', None)
    if keepalive_events:
        metadata['keepalive_events'] = [{'index': getattr(event, 'index', None), 'command_id': getattr(event, 'command_id', None), 'elapsed_seconds': getattr(event, 'elapsed_seconds', None), 'sent': getattr(event, 'sent', None), 'error': getattr(event, 'error', None)} for event in keepalive_events]
    exchanges: dict[str, _owner.Any] = {}
    for name in ('pre_start', 'preview', 'stream_setup'):
        exchange = getattr(bootstrap, name, None)
        if exchange is None:
            continue
        response = getattr(exchange, 'response', None)
        header = getattr(response, 'header', None)
        body = getattr(response, 'body', b'')
        body_shape = _owner.classify_ezviz_local_sdk_body(body)
        exchanges[name] = {'response_command': getattr(header, 'command', None), 'response_sequence': getattr(header, 'sequence', None), 'response_status': getattr(header, 'status', None), 'response_body_length': getattr(header, 'body_length', None), 'response_body_kind': body_shape.kind, 'response_xml_tags': list(body_shape.xml_tags)}
    metadata['exchanges'] = exchanges
    first_media = getattr(bootstrap, 'first_media', None)
    if first_media is not None:
        frame = first_media.frame
        metadata['first_media'] = {'prefix_length': len(first_media.prefix), 'prefix_sha256': _owner.hashlib.sha256(first_media.prefix).hexdigest(), 'channel': frame.header.channel, 'payload_length': frame.header.payload_length, 'payload_sha256': _owner.hashlib.sha256(frame.payload).hexdigest()}
    return metadata

def _hcnetsdk_command_port_exchange_metadata(exchange: _owner.Any) -> dict[str, _owner.Any]:
    """Return non-secret metadata for one command-port request/response."""
    frame = getattr(exchange, 'request', b'')
    response = getattr(exchange, 'response', None)
    metadata: dict[str, _owner.Any] = {'request_length': len(frame)}
    if len(frame) >= 16:
        metadata['request_command_family'] = int.from_bytes(frame[4:8], 'big')
        metadata['request_auth_word'] = int.from_bytes(frame[8:12], 'big')
        metadata['request_command_id'] = int.from_bytes(frame[12:16], 'big')
    if len(frame) > 32:
        tail = frame[32:]
        metadata['request_body_tail_length'] = len(tail)
        metadata['request_body_tail_word_samples'] = _owner._hcnetsdk_command_port_body_tail_word_samples(tail)
    if response is None:
        metadata['response'] = None
        return metadata
    header = getattr(response, 'header', None)
    body = getattr(response, 'body', b'')
    metadata['response'] = {'total_length': getattr(header, 'total_length', None), 'field_4': getattr(header, 'field_4', None), 'field_8': getattr(header, 'field_8', None), 'field_12': getattr(header, 'field_12', None), 'body_length': len(body), 'body_prefix_hex': body[:16].hex()}
    if body:
        metadata['response']['body_word_samples'] = _owner._hcnetsdk_command_port_body_word_samples(body)
    return metadata

def _hcnetsdk_command_port_body_word_samples(body: bytes, *, max_samples: int=16) -> list[dict[str, int]]:
    """Return bounded nonzero 32-bit body words for diagnostics."""
    samples: list[dict[str, int]] = []
    for offset in range(0, len(body) - 3, 4):
        value = int.from_bytes(body[offset:offset + 4], 'big')
        if value == 0:
            continue
        samples.append({'offset': offset, 'be': value})
        if len(samples) >= max_samples:
            break
    return samples

def _hcnetsdk_command_port_body_tail_word_samples(tail: bytes, *, max_samples: int=16) -> list[dict[str, int]]:
    """Return bounded nonzero 32-bit request-tail words for diagnostics."""
    return _owner._hcnetsdk_command_port_body_word_samples(tail, max_samples=max_samples)

def _handle_stream(args: _owner.argparse.Namespace, client: _owner.EzvizClient) -> int:
    """Handle experimental stream helpers."""
    if args.stream_action not in {'trace', 'dump', 'proxy', 'local-sdk-dump', 'local-sdk-keys', 'h264-annexb-summary', 'hcnetsdk-command-dump-summary', 'hcnetsdk-command-plan-generate'}:
        _owner._LOGGER.error('Action not implemented, try running with -h switch for help')
        return 2
    if args.stream_action == 'hcnetsdk-command-dump-summary':
        return _owner._handle_hcnetsdk_command_dump_summary(args)
    if args.stream_action == 'hcnetsdk-command-plan-generate':
        return _owner._handle_hcnetsdk_command_plan_generate(args)
    if args.stream_action == 'h264-annexb-summary':
        return _owner._handle_h264_annexb_summary(args)
    if args.stream_action == 'local-sdk-keys':
        return _owner._handle_local_sdk_keys(args, client)
    if args.stream_action == 'local-sdk-dump':
        return _owner._handle_local_sdk_stream_dump(args, client)
    if args.stream_action == 'proxy':
        _owner._serve_stream_proxy(args, client)
        return 0
    if args.stream_action == 'dump' and args.decrypt_video and (not _owner.has_positive_finite_capture_bound(max_packets=args.max_packets, duration_seconds=args.duration)):
        raise _owner.PyEzvizError('--decrypt-video requires a positive finite --duration or --max-packets to bound memory use')
    media_key = _owner._cloud_cli_media_key(args, client) if args.stream_action == 'dump' and args.decrypt_video else None
    stream = _owner.open_cloud_stream(client, args.serial, channel=args.channel, client_type=args.client_type, token_index=args.token_index, refresh_vtm=not args.no_refresh_vtm, timeout=args.timeout)
    with _owner._closing_unconnected_cloud_stream(stream):
        if args.stream_action == 'dump':
            startup_deadline = _owner._start_cli_cloud_stream(stream, timeout=args.timeout, duration_seconds=args.duration)
            collected_packets: list[_owner.Any] | None = None
            if args.decrypt_video:
                collected_packets = _owner._collect_stream_packets(stream, max_packets=args.max_packets, duration_seconds=args.duration, first_packet_deadline=startup_deadline, allow_encrypted=args.allow_encrypted)
                transport = _owner._detect_stream_packets_transport(collected_packets)
                if transport == _owner.StreamTransport.RTP:
                    if args.format == 'mpegts' and _owner.cloud_rtp_packets_have_audio(collected_packets):
                        rtp_codec = _owner._detect_rtp_video_codec(collected_packets, media_key=media_key, decrypt_codec=args.decrypt_codec)
                        _owner._rtp_packets_to_annexb_units(collected_packets, codec=rtp_codec, first_slice_key=media_key, decrypt_codec=args.decrypt_codec)
                        assert media_key is not None

                        def _write_rtp_mpegts(selected_output: _owner.BinaryIO) -> None:
                            _owner.copy_decrypted_cloud_stream_packets_to_mpegts(collected_packets, selected_output, ffmpeg_path=args.ffmpeg_path, media_key=media_key, nalu_header_size=_owner._codec_nalu_header_size(args.decrypt_codec), transport=transport)
                        if args.output == '-':
                            _write_rtp_mpegts(_owner.sys.stdout.buffer)
                        else:
                            with _owner.Path(args.output).open('wb') as output:
                                _write_rtp_mpegts(output)
                        return 0
                    rtp_codec = _owner._detect_rtp_video_codec(collected_packets, media_key=media_key, decrypt_codec=args.decrypt_codec)
                    decrypt_codec = rtp_codec if args.decrypt_codec == 'auto' else args.decrypt_codec
                    rtp_units = _owner._rtp_packets_to_annexb_units(collected_packets, codec=rtp_codec, first_slice_key=media_key, decrypt_codec=decrypt_codec)
                    payload = b''.join(rtp_units) if _owner._codec_nalu_header_size(decrypt_codec) == 0 else _owner._decrypt_rtp_annexb_units(client, args.serial, rtp_units, detected_codec=rtp_codec, decrypt_codec=decrypt_codec, media_key=media_key)
                    if args.output == '-':
                        if args.format == 'raw':
                            _owner.sys.stdout.buffer.write(payload)
                            _owner.sys.stdout.buffer.flush()
                        else:
                            _owner._remux_elementary_video_bytes_to_mpegts(payload, _owner.sys.stdout.buffer, ffmpeg_path=args.ffmpeg_path, codec=rtp_codec)
                    else:
                        with _owner.Path(args.output).open('wb') as output:
                            if args.format == 'raw':
                                output.write(payload)
                                output.flush()
                            else:
                                _owner._remux_elementary_video_bytes_to_mpegts(payload, output, ffmpeg_path=args.ffmpeg_path, codec=rtp_codec)
                    return 0
            if args.output == '-':
                if args.decrypt_video:
                    payload = b''.join((packet.body for packet in collected_packets or []))
                    payload = _owner._decrypt_stream_payload_bytes(client, args.serial, payload, codec=args.decrypt_codec, media_key=media_key)
                    if args.format == 'raw':
                        _owner.sys.stdout.buffer.write(payload)
                        _owner.sys.stdout.buffer.flush()
                    else:
                        _owner._remux_mpegps_bytes_to_mpegts(payload, _owner.sys.stdout.buffer, ffmpeg_path=args.ffmpeg_path)
                elif args.format == 'raw':
                    _owner._write_stream_payloads(stream, _owner.sys.stdout.buffer, max_packets=args.max_packets, duration_seconds=args.duration, first_packet_deadline=startup_deadline, allow_encrypted=args.allow_encrypted)
                else:
                    _owner._remux_stream_payloads_to_mpegts(stream, _owner.sys.stdout.buffer, ffmpeg_path=args.ffmpeg_path, max_packets=args.max_packets, duration_seconds=args.duration, first_packet_deadline=startup_deadline, allow_encrypted=args.allow_encrypted)
            else:
                with _owner.Path(args.output).open('wb') as output:
                    if args.decrypt_video:
                        payload = b''.join((packet.body for packet in collected_packets or []))
                        payload = _owner._decrypt_stream_payload_bytes(client, args.serial, payload, codec=args.decrypt_codec, media_key=media_key)
                        if args.format == 'raw':
                            output.write(payload)
                            output.flush()
                        else:
                            _owner._remux_mpegps_bytes_to_mpegts(payload, output, ffmpeg_path=args.ffmpeg_path)
                    elif args.format == 'raw':
                        _owner._write_stream_payloads(stream, output, max_packets=args.max_packets, duration_seconds=args.duration, first_packet_deadline=startup_deadline, allow_encrypted=args.allow_encrypted)
                    else:
                        _owner._remux_stream_payloads_to_mpegts(stream, output, ffmpeg_path=args.ffmpeg_path, max_packets=args.max_packets, duration_seconds=args.duration, first_packet_deadline=startup_deadline, allow_encrypted=args.allow_encrypted)
            return 0
        events = [event.as_dict() for event in stream.trace_packets(max_packets=args.max_packets)]
    if args.json_lines:
        for event in events:
            _owner.sys.stdout.write(_owner.json.dumps(event, sort_keys=True) + '\n')
    else:
        _owner._write_json(events)
    return 0
