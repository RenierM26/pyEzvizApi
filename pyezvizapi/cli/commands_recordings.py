"""commands recordings implementation; legacy runtime hooks remain on the owner module.

Access through _owner is deliberate: callers that patch the compatibility
module must still affect dependent operations. No copied hook snapshots.
"""
# ruff: noqa: SLF001 -- explicit legacy hook boundary.
from __future__ import annotations

import pyezvizapi.cli.main as _owner

def _handle_cloud_videos(args: _owner.argparse.Namespace, client: _owner.EzvizClient) -> int:
    """Fetch cloud video descriptors and optionally hydrate details."""
    response = client.get_cloud_videos(args.serial, args.channel, limit=args.limit, video_type=args.video_type, support_multi_channel_shared_service=args.support_multi_channel_shared_service)
    videos = response.get('videos')
    if not isinstance(videos, list):
        videos = []
    if args.details and videos:
        response = client.get_cloud_video_details(args.serial, args.channel, [video for video in videos if isinstance(video, dict)], support_multi_channel_shared_service=args.support_multi_channel_shared_service)
        videos = response.get('videos')
        if not isinstance(videos, list):
            videos = []
    if args.json:
        _owner._write_json(videos)
        return 0
    rows: list[dict[str, _owner.Any]] = []
    for item in videos:
        if not isinstance(item, dict):
            continue
        rows.append({'seqId': item.get('seqId'), 'startTime': item.get('startTime'), 'stopTime': item.get('stopTime'), 'fileSize': item.get('fileSize'), 'crypt': item.get('crypt'), 'keyChecksum': item.get('keyChecksum') or item.get('checksum'), 'streamUrl': item.get('streamUrl')})
    if rows:
        _owner._write_table(rows, ['seqId', 'startTime', 'stopTime', 'fileSize', 'crypt', 'keyChecksum', 'streamUrl'])
    else:
        _owner.sys.stdout.write('No cloud videos returned.\n')
    return 0

def _handle_cloud_video_download(args: _owner.argparse.Namespace, client: _owner.EzvizClient) -> int:
    """Fetch cloud video details, then download the selected media bytes."""
    response = client.get_cloud_videos(args.serial, args.channel, limit=args.limit, video_type=args.video_type, support_multi_channel_shared_service=args.support_multi_channel_shared_service)
    videos = response.get('videos')
    if not isinstance(videos, list):
        videos = []
    selected = None
    for video in videos:
        if isinstance(video, dict) and str(video.get('seqId')) == str(args.seq_id):
            selected = video
            break
    if selected is None:
        raise _owner.PyEzvizError(f'Cloud video seqId {args.seq_id!r} was not returned')
    details_response = client.get_cloud_video_details(args.serial, args.channel, [selected], support_multi_channel_shared_service=args.support_multi_channel_shared_service)
    details = details_response.get('videos')
    if isinstance(details, list) and details and isinstance(details[0], dict):
        selected = details[0]
    encrypted_output = _owner.Path(args.encrypted_output) if args.encrypted_output else None
    transform = 'direct'
    try:
        data = client.download_cloud_video(selected)
    except _owner.PyEzvizError:
        if not isinstance(selected.get('streamUrl'), str):
            raise
        ticket = _owner._extract_ticket(client.get_camera_ticket_info(args.serial, args.channel, support_multi_channel_shared_service=args.support_multi_channel_shared_service))
        secret_key = client.get_cam_key(args.serial, max_retries=1)
        start_millis = _owner._cloud_video_start_millis(selected)
        stop_millis = start_millis + int(selected.get('videoLong') or 0)
        if stop_millis <= start_millis:
            stop_millis = start_millis + 10000
        encrypted_data = _owner.download_ezviz_cloud_replay(stream_url=selected['streamUrl'], ticket=ticket, serial=args.serial, channel=args.channel, seq_id=selected.get('seqId') or args.seq_id, begin_cas=_owner._cas_time_from_millis(start_millis), end_cas=_owner._cas_time_from_millis(stop_millis), storage_version=int(selected.get('storageVersion') or 2), video_type=int(selected.get('videoType') or args.video_type), file_size=int(selected['fileSize']) if isinstance(selected.get('fileSize'), int | str) and str(selected.get('fileSize')).isdigit() else None, timeout=args.timeout)
        if encrypted_output is not None:
            encrypted_output.parent.mkdir(parents=True, exist_ok=True)
            encrypted_output.write_bytes(encrypted_data)
        data = _owner.decrypt_hikvision_ps_video(encrypted_data, secret_key, nalu_header_size=_owner._codec_nalu_header_size(args.decrypt_codec))
        transform = 'cloud_replay_python'
    output = _owner.Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(data)
    result = {'output': str(output), 'encrypted_output': str(encrypted_output) if encrypted_output else None, 'bytes': len(data), 'seqId': selected.get('seqId'), 'transform': transform}
    if args.json:
        _owner._write_json(result)
    else:
        _owner.sys.stdout.write(f'Wrote {len(data)} bytes to {output}\n')
    return 0

def _select_cloud_video_for_seq_id(client: _owner.EzvizClient, *, serial: str, channel: int, seq_id: str, limit: int, video_type: int, support_multi_channel_shared_service: int) -> dict[str, _owner.Any]:
    """Return a hydrated cloud video descriptor for a selected seqId."""
    response = client.get_cloud_videos(serial, channel, limit=limit, video_type=video_type, support_multi_channel_shared_service=support_multi_channel_shared_service)
    videos = response.get('videos')
    if not isinstance(videos, list):
        videos = []
    selected = None
    for video in videos:
        if isinstance(video, dict) and str(video.get('seqId')) == str(seq_id):
            selected = video
            break
    if selected is None:
        raise _owner.PyEzvizError(f'Cloud video seqId {seq_id!r} was not returned')
    details_response = client.get_cloud_video_details(serial, channel, [selected], support_multi_channel_shared_service=support_multi_channel_shared_service)
    details = details_response.get('videos')
    if isinstance(details, list) and details and isinstance(details[0], dict):
        return _owner.cast(dict[str, _owner.Any], details[0])
    return selected

def _extract_ticket(ticket_response: dict[str, _owner.Any]) -> str:
    """Extract the ticket string from known EZVIZ ticketInfo response shapes."""
    candidates: list[_owner.Any] = [ticket_response.get('ticketInfo')]
    data = ticket_response.get('data')
    if isinstance(data, dict):
        candidates.append(data.get('ticketInfo'))
    for candidate in candidates:
        if isinstance(candidate, dict) and isinstance(candidate.get('ticket'), str):
            return candidate['ticket']
    raise _owner.PyEzvizError('Camera ticket response does not include ticketInfo.ticket')

def _cloud_video_start_millis(video: dict[str, _owner.Any]) -> int:
    """Return cloud clip start time in epoch milliseconds."""
    cover_pic = video.get('coverPic')
    if isinstance(cover_pic, str):
        parsed = _owner.urlparse(cover_pic)
        values = _owner.parse_qs(parsed.query).get('startTime')
        if values:
            with _owner.suppress(ValueError):
                return int(values[0])
    start_time = video.get('startTime')
    if isinstance(start_time, str):
        for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S'):
            with _owner.suppress(ValueError):
                parsed_dt = _owner.dt.datetime.strptime(start_time, fmt).replace(tzinfo=_owner.dt.UTC)
                return int(parsed_dt.timestamp() * 1000)
    raise _owner.PyEzvizError('Cloud video descriptor does not include a usable start time')

def _cas_time_from_millis(value: int) -> str:
    """Format epoch milliseconds as the CAS timestamp string used by the app."""
    return _owner.dt.datetime.fromtimestamp(value / 1000, tz=_owner.dt.UTC).strftime('%Y%m%dT%H%M%SZ')

def _handle_cloud_video_decrypt(args: _owner.argparse.Namespace, client: _owner.EzvizClient | None) -> int:
    """Decrypt a cloud download .tmp file using the Python PS/NAL transform."""
    if bool(args.serial) == bool(args.key):
        raise _owner.PyEzvizError('Provide exactly one of --serial or --key')
    if args.key:
        key = args.key
    else:
        if client is None:
            raise _owner.PyEzvizError('Provide --key or EZVIZ credentials/token for --serial')
        key = client.get_cam_key(args.serial, max_retries=1)
    input_path = _owner.Path(args.input)
    output_path = _owner.Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(_owner.decrypt_hikvision_ps_video(input_path.read_bytes(), key, nalu_header_size=_owner._codec_nalu_header_size(args.decrypt_codec)))
    result = {'input': str(input_path), 'output': str(output_path), 'bytes': output_path.stat().st_size}
    if args.json:
        _owner._write_json(result)
    else:
        _owner.sys.stdout.write(f'Wrote decrypted cloud video to {output_path}\n')
    return 0

def _write_save_result(args: _owner.argparse.Namespace, result: _owner.Mapping[str, _owner.Any]) -> None:
    """Write a human or JSON result for save commands."""
    if args.json:
        _owner._write_json(result)
    else:
        _owner.sys.stdout.write(f"Wrote {result['bytes']} bytes to {result['output']}\n")

def _validate_shared_clip_args(args: _owner.argparse.Namespace) -> None:
    """Reject unsupported clock assertions before account or camera access."""
    if not args.native_shared_clock:
        return
    if args.source not in {'local-sdk', 'hcnetsdk-command-port'} or args.format not in {None, 'mpegts'}:
        raise _owner.PyEzvizError('--native-shared-clock requires explicit native MPEG-TS capture')
    if args.decrypt_video and (args.hcnetsdk_h264_wait_for_clean_idr_window or args.hcnetsdk_h264_skip_initial_idr_windows or args.hcnetsdk_h264_trim_to_clean_idr_window or args.hcnetsdk_h264_clean_idr_preroll_seconds):
        raise _owner.PyEzvizError('--native-shared-clock does not support encrypted startup trimming')

def _handle_save_clip(args: _owner.argparse.Namespace, client: _owner.EzvizClient) -> int:
    """Save a short direct-local camera clip to disk."""
    _owner._validate_shared_clip_args(args)
    if args.channel is None and args.source not in {'cloud', 'auto'}:
        args.channel = 1
    decrypt_codec = args.decrypt_codec or ('auto' if args.decrypt_video and args.source in {'auto', 'cloud', 'local-sdk', 'local-sdk-ecdh'} else 'encrypted-header')
    command_generated_plan = _owner._hcnetsdk_command_generated_plan_from_args(args) if args.source == 'hcnetsdk-command-port' else None
    command_plan = _owner._hcnetsdk_command_plan_from_args(args) if args.source == 'hcnetsdk-command-port' else None
    command_frames = _owner._hcnetsdk_command_frames_from_args(args) if args.source == 'hcnetsdk-command-port' and command_plan is None and (command_generated_plan is None) else None
    read_response_after_each = _owner._hcnetsdk_read_response_policy(args, len(command_frames or ())) if command_frames is not None else True
    hcnetsdk_command_metadata_callback = (lambda stream: _owner._write_local_sdk_metadata_output(args.hcnetsdk_command_metadata_output, stream, packet_output_path=args.hcnetsdk_command_sampled_packets_output)) if args.source == 'hcnetsdk-command-port' and (args.hcnetsdk_command_metadata_output or args.hcnetsdk_command_sampled_packets_output) else None
    output_format = args.format
    if output_format is None:
        output_format = 'mpegps' if args.source == 'local-sdk-ecdh' and (not args.decrypt_video) else 'mpegts'
    save_kwargs: dict[str, _owner.Any] = {'source': args.source, 'output_format': output_format, 'duration_seconds': args.duration, 'max_packets': args.max_packets, 'channel': args.channel, 'ffmpeg_path': args.ffmpeg_path, 'decrypt_video': args.decrypt_video, 'nalu_header_size': _owner._codec_nalu_header_size(decrypt_codec), 'cas_serial': args.cas_serial, 'timeout': args.timeout, 'smscode': args.sms_code, 'host': args.host, 'command_port': args.command_port, 'hcnetsdk_command_frames': command_frames, 'hcnetsdk_command_plan': command_plan, 'hcnetsdk_command_generated_plan': command_generated_plan, 'hcnetsdk_command_password': args.hcnetsdk_command_password, 'hcnetsdk_local_ip': args.hcnetsdk_local_ip, 'hcnetsdk_read_response_after_each': read_response_after_each, 'hcnetsdk_command_metadata_callback': hcnetsdk_command_metadata_callback, 'hcnetsdk_h264_skip_initial_idr_windows': args.hcnetsdk_h264_skip_initial_idr_windows, 'hcnetsdk_h264_trim_to_clean_idr_window': args.hcnetsdk_h264_trim_to_clean_idr_window, 'hcnetsdk_h264_clean_idr_preroll_seconds': args.hcnetsdk_h264_clean_idr_preroll_seconds, 'hcnetsdk_h264_clean_idr_max_windows': args.hcnetsdk_h264_clean_idr_max_windows, 'hcnetsdk_h264_wait_for_clean_idr_window': args.hcnetsdk_h264_wait_for_clean_idr_window, 'hcnetsdk_h264_clean_idr_wait_seconds': args.hcnetsdk_h264_clean_idr_wait_seconds}
    if args.native_shared_clock:
        save_kwargs['native_shared_clock'] = True
    if args.source in {'local-sdk', 'local-sdk-ecdh'}:
        save_kwargs['register_p2p_session'] = not args.no_p2p_register
    if args.source == 'auto':
        save_kwargs['local_sdk_ecdh_receiver_port'] = args.local_sdk_ecdh_receiver_port
    if args.source == 'local-sdk-ecdh':
        save_kwargs.update({'local_sdk_ecdh_receiver_port': _owner.LOCAL_SDK_ECDH_DEFAULT_RECEIVER_PORT if args.local_sdk_ecdh_receiver_port is None else args.local_sdk_ecdh_receiver_port, 'local_sdk_ecdh_send_init': args.local_sdk_ecdh_send_init, 'local_sdk_ecdh_max_prefix_bytes': args.local_sdk_ecdh_max_prefix_bytes, 'local_sdk_ecdh_max_frames': args.local_sdk_ecdh_max_frames})
    if args.source == 'cloud':
        save_kwargs.update({'cloud_client_type': args.client_type, 'cloud_token_index': args.token_index, 'cloud_refresh_vtm': not args.no_refresh_vtm})
    if args.decrypt_video and (args.source == 'hcnetsdk-command-port' or _owner._local_sdk_has_static_media_key(args)):
        save_kwargs['media_key'] = _owner._local_sdk_media_key(args, client)
    result = client.save_clip(args.serial, args.output, **save_kwargs)
    _owner._write_save_result(args, result)
    return 0
