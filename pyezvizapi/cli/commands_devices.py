"""commands devices implementation; legacy runtime hooks remain on the owner module.

Access through _owner is deliberate: callers that patch the compatibility
module must still affect dependent operations. No copied hook snapshots.
"""
# ruff: noqa: SLF001 -- explicit legacy hook boundary.
from __future__ import annotations

import pyezvizapi.cli.main as _owner

def _handle_devices_light(args: _owner.argparse.Namespace, client: _owner.EzvizClient) -> int:
    """Handle `devices_light` subcommands (status)."""
    if args.devices_light_action == 'status':
        data = client.load_light_bulbs(refresh=getattr(args, 'refresh', True))
        if args.json:
            _owner._write_json(data)
        else:
            columns = ['serial', 'name', 'status', 'device_category', 'device_sub_category', 'local_ip', 'productId', 'is_on', 'brightness', 'color_temperature']
            rows = [{'serial': serial, **payload} for serial, payload in data.items() if isinstance(payload, dict)]
            _owner._write_table(rows, columns)
        return 0
    return 2

def _handle_pagelist(client: _owner.EzvizClient) -> int:
    """Output full pagelist (raw JSON) for exploration in editors like Notepad++."""
    data = client.get_page_list()
    _owner._write_json(data)
    return 0

def _handle_device_infos(args: _owner.argparse.Namespace, client: _owner.EzvizClient) -> int:
    """Output device infos mapping (raw JSON), optionally filtered by serial."""
    data = client.get_device_infos(args.serial) if args.serial else client.get_device_infos()
    _owner._write_json(data)
    return 0

def _handle_unifiedmsg(args: _owner.argparse.Namespace, client: _owner.EzvizClient) -> int:
    """Fetch unified message list and optionally dump media URLs."""
    response = client.get_device_messages_list(serials=args.serials, limit=args.limit, date=args.date, end_time=args.end_time or '')
    raw_messages = response.get('message')
    if not isinstance(raw_messages, list):
        raw_messages = response.get('messages')
    if not isinstance(raw_messages, list):
        raw_messages = []
    messages: list[dict[str, _owner.Any]] = [msg for msg in raw_messages if isinstance(msg, dict)]

    def _extract_url(message: dict[str, _owner.Any]) -> str | None:
        url = message.get('pic')
        if not url:
            url = message.get('defaultPic') or message.get('image')
        if not url:
            ext = message.get('ext')
            if isinstance(ext, dict):
                pics = ext.get('pics')
                if isinstance(pics, str) and pics:
                    url = pics.split(';')[0]
        return url
    if args.urls_only:
        for item in messages:
            media_url = _extract_url(item)
            if not media_url:
                continue
            _owner.sys.stdout.write(f"{item.get('deviceSerial', 'unknown')}: {media_url}\n")
        return 0
    if args.json:
        _owner._write_json(messages)
        return 0
    rows: list[dict[str, _owner.Any]] = []
    for item in messages:
        ext = item.get('ext')
        ext_dict = ext if isinstance(ext, dict) else None
        rows.append({'deviceSerial': item.get('deviceSerial'), 'time': item.get('timeStr') or item.get('time'), 'subType': item.get('subType'), 'alarmType': ext_dict.get('alarmType') if ext_dict else None, 'title': item.get('title') or item.get('detail') or (ext_dict or {}).get('alarmName'), 'url': _extract_url(item) or '', 'msgId': item.get('msgId')})
    if rows:
        _owner._write_table(rows, ['deviceSerial', 'time', 'subType', 'alarmType', 'title', 'url', 'msgId'])
    else:
        _owner.sys.stdout.write('No unified messages returned.\n')
    return 0

def _decode_compressed_record_list(value: str) -> list[_owner.Any]:
    """Decode the app's base64+zlib JSON record-list payload when present."""
    return _owner._REAL_EZVIZ_CLIENT.decode_records_payload(value)

def _first_record_list(payload: _owner.Any) -> list[_owner.Any]:
    """Return the first plausible list of record dictionaries from an API response."""
    return _owner._REAL_EZVIZ_CLIENT.extract_record_list(payload)

def _handle_sdcard_videos(args: _owner.argparse.Namespace, client: _owner.EzvizClient) -> int:
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
    rows: list[dict[str, _owner.Any]] = []
    for item in records:
        if not isinstance(item, dict):
            continue
        rows.append({'begin': item.get('begin') or item.get('B') or item.get('startTime') or item.get('startTimeStr'), 'end': item.get('end') or item.get('E') or item.get('stopTime') or item.get('stopTimeStr'), 'type': item.get('type') or item.get('Type') or item.get('recordType') or item.get('videoType'), 'path': item.get('path') or item.get('filePath') or item.get('fileUrl'), 'cover': item.get('cover') or item.get('coverUrl') or item.get('coverPic')})
    if rows:
        _owner._write_table(rows, ['begin', 'end', 'type', 'path', 'cover'])
    else:
        _owner.sys.stdout.write('No SD-card videos returned.\n')
    return 0
