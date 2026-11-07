# Runtime hook context is explicit; immutable value types come from dependency leaves.
# ruff: noqa: SLF001
'recordings command handlers; cli.main passes the retained runtime hooks explicitly.'
from __future__ import annotations

from types import ModuleType as _ModuleType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pyezvizapi.cli.main as _owner_types

def _decode_compressed_record_list(value: str, *, _owner: _ModuleType) -> list[_owner_types.Any]:
    """Decode the app's base64+zlib JSON record-list payload when present."""
    return _owner._REAL_EZVIZ_CLIENT.decode_records_payload(value)

def _first_record_list(payload: _owner_types.Any, *, _owner: _ModuleType) -> list[_owner_types.Any]:
    """Return the first plausible list of record dictionaries from an API response."""
    return _owner._REAL_EZVIZ_CLIENT.extract_record_list(payload)

def _handle_sdcard_videos(args: _owner_types.argparse.Namespace, client: _owner_types.EzvizClient, *, _owner: _ModuleType) -> int:
    """Fetch SD-card playback record descriptors."""
    if args.source == 'legacy':
        channel_serial = args.channel_serial or args.serial
        response = client.search_records(args.serial, args.channel, channel_serial, args.start_time, args.stop_time, size=args.size)
    elif args.source == 'common':
        response = client.search_common_records(args.serial, args.channel, args.start_time, args.stop_time, channel_serial=args.channel_serial, record_type=args.record_type, size=args.size, version=args.version)
    elif args.source == 'intelligent':
        response = client.search_intelligent_records(args.serial, args.channel, args.start_time, args.stop_time, version=args.version, record_filter=args.filter)
    else:
        response = client.search_records_v2(args.serial, args.channel, args.start_time, args.stop_time, size=args.size, sort_by=args.sort_by, require_label=args.require_label)
    records = _owner._first_record_list(response)
    if args.json:
        _owner._write_json(records if records else response)
        return 0
    rows: list[dict[str, _owner_types.Any]] = []
    for item in records:
        if not isinstance(item, dict):
            continue
        rows.append({'begin': item.get('begin') or item.get('B') or item.get('startTime') or item.get('startTimeStr'), 'end': item.get('end') or item.get('E') or item.get('stopTime') or item.get('stopTimeStr'), 'type': item.get('type') or item.get('Type') or item.get('recordType') or item.get('videoType'), 'path': item.get('path') or item.get('filePath') or item.get('fileUrl'), 'cover': item.get('cover') or item.get('coverUrl') or item.get('coverPic')})
    if rows:
        _owner._write_table(rows, ['begin', 'end', 'type', 'path', 'cover'])
    else:
        _owner.sys.stdout.write('No SD-card videos returned.\n')
    return 0

def _handle_cloud_videos(args: _owner_types.argparse.Namespace, client: _owner_types.EzvizClient, *, _owner: _ModuleType) -> int:
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
    rows: list[dict[str, _owner_types.Any]] = []
    for item in videos:
        if not isinstance(item, dict):
            continue
        rows.append({'seqId': item.get('seqId'), 'startTime': item.get('startTime'), 'stopTime': item.get('stopTime'), 'fileSize': item.get('fileSize'), 'crypt': item.get('crypt'), 'keyChecksum': item.get('keyChecksum') or item.get('checksum'), 'streamUrl': item.get('streamUrl')})
    if rows:
        _owner._write_table(rows, ['seqId', 'startTime', 'stopTime', 'fileSize', 'crypt', 'keyChecksum', 'streamUrl'])
    else:
        _owner.sys.stdout.write('No cloud videos returned.\n')
    return 0

def _handle_cloud_video_download(args: _owner_types.argparse.Namespace, client: _owner_types.EzvizClient, *, _owner: _ModuleType) -> int:
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

def _select_cloud_video_for_seq_id(client: _owner_types.EzvizClient, *, serial: str, channel: int, seq_id: str, limit: int, video_type: int, support_multi_channel_shared_service: int, _owner: _ModuleType) -> dict[str, _owner_types.Any]:
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
        return _owner.cast('dict[str, _owner_types.Any]', details[0])
    return selected

def _extract_ticket(ticket_response: dict[str, _owner_types.Any], *, _owner: _ModuleType) -> str:
    """Extract the ticket string from known EZVIZ ticketInfo response shapes."""
    candidates: list[_owner_types.Any] = [ticket_response.get('ticketInfo')]
    data = ticket_response.get('data')
    if isinstance(data, dict):
        candidates.append(data.get('ticketInfo'))
    for candidate in candidates:
        if isinstance(candidate, dict) and isinstance(candidate.get('ticket'), str):
            return candidate['ticket']
    raise _owner.PyEzvizError('Camera ticket response does not include ticketInfo.ticket')

def _cloud_video_start_millis(video: dict[str, _owner_types.Any], *, _owner: _ModuleType) -> int:
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

def _cas_time_from_millis(value: int, *, _owner: _ModuleType) -> str:
    """Format epoch milliseconds as the CAS timestamp string used by the app."""
    return _owner.dt.datetime.fromtimestamp(value / 1000, tz=_owner.dt.UTC).strftime('%Y%m%dT%H%M%SZ')

def _handle_cloud_video_decrypt(args: _owner_types.argparse.Namespace, client: _owner_types.EzvizClient | None, *, _owner: _ModuleType) -> int:
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
