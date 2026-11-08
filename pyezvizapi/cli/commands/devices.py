# Runtime hook context is explicit; immutable value types come from dependency leaves.
# ruff: noqa: SLF001
"devices command handlers; cli.main passes the retained runtime hooks explicitly."

from __future__ import annotations

from types import ModuleType as _ModuleType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pyezvizapi._typing.cli as _owner_types


def _handle_devices_light(
    args: _owner_types.argparse.Namespace, client: _owner_types.EzvizClient, *, _owner: _ModuleType
) -> int:
    """Handle `devices_light` subcommands (status)."""
    if args.devices_light_action == "status":
        data = client.load_light_bulbs(refresh=getattr(args, "refresh", True))
        if args.json:
            _owner._write_json(data)
        else:
            columns = [
                "serial",
                "name",
                "status",
                "device_category",
                "device_sub_category",
                "local_ip",
                "productId",
                "is_on",
                "brightness",
                "color_temperature",
            ]
            rows = [
                {"serial": serial, **payload}
                for serial, payload in data.items()
                if isinstance(payload, dict)
            ]
            _owner._write_table(rows, columns)
        return 0
    return 2


def _handle_pagelist(client: _owner_types.EzvizClient, *, _owner: _ModuleType) -> int:
    """Output full pagelist (raw JSON) for exploration in editors like Notepad++."""
    data = client.get_page_list()
    _owner._write_json(data)
    return 0


def _handle_device_infos(
    args: _owner_types.argparse.Namespace, client: _owner_types.EzvizClient, *, _owner: _ModuleType
) -> int:
    """Output device infos mapping (raw JSON), optionally filtered by serial."""
    data = client.get_device_infos(args.serial) if args.serial else client.get_device_infos()
    _owner._write_json(data)
    return 0


def _handle_unifiedmsg(
    args: _owner_types.argparse.Namespace, client: _owner_types.EzvizClient, *, _owner: _ModuleType
) -> int:
    """Fetch unified message list and optionally dump media URLs."""
    response = client.get_device_messages_list(
        serials=args.serials, limit=args.limit, date=args.date, end_time=args.end_time or ""
    )
    raw_messages = response.get("message")
    if not isinstance(raw_messages, list):
        raw_messages = response.get("messages")
    if not isinstance(raw_messages, list):
        raw_messages = []
    messages: list[dict[str, _owner_types.Any]] = [
        msg for msg in raw_messages if isinstance(msg, dict)
    ]

    def _extract_url(message: dict[str, _owner_types.Any]) -> str | None:
        url = message.get("pic")
        if not url:
            url = message.get("defaultPic") or message.get("image")
        if not url:
            ext = message.get("ext")
            if isinstance(ext, dict):
                pics = ext.get("pics")
                if isinstance(pics, str) and pics:
                    url = pics.split(";")[0]
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
    rows: list[dict[str, _owner_types.Any]] = []
    for item in messages:
        ext = item.get("ext")
        ext_dict = ext if isinstance(ext, dict) else None
        rows.append(
            {
                "deviceSerial": item.get("deviceSerial"),
                "time": item.get("timeStr") or item.get("time"),
                "subType": item.get("subType"),
                "alarmType": ext_dict.get("alarmType") if ext_dict else None,
                "title": item.get("title")
                or item.get("detail")
                or (ext_dict or {}).get("alarmName"),
                "url": _extract_url(item) or "",
                "msgId": item.get("msgId"),
            }
        )
    if rows:
        _owner._write_table(
            rows, ["deviceSerial", "time", "subType", "alarmType", "title", "url", "msgId"]
        )
    else:
        _owner.sys.stdout.write("No unified messages returned.\n")
    return 0


def _handle_light(
    args: _owner_types.argparse.Namespace, client: _owner_types.EzvizClient, *, _owner: _ModuleType
) -> int:
    """Handle `light` subcommands (toggle/status)."""
    light_bulb = _owner.EzvizLightBulb(client, args.serial)
    _owner._LOGGER.debug("Light bulb loaded")
    if args.light_action == "toggle":
        light_bulb.toggle_switch()
        return 0
    if args.light_action == "status":
        _owner._write_json(light_bulb.status())
        return 0
    _owner._LOGGER.error("Action not implemented for light: %s", args.light_action)
    return 2


def _handle_home_defence_mode(
    args: _owner_types.argparse.Namespace, client: _owner_types.EzvizClient, *, _owner: _ModuleType
) -> int:
    """Handle `home_defence_mode` subcommands (set mode)."""
    if args.mode:
        res = client.api_set_defence_mode(getattr(_owner.DefenseModeType, args.mode).value)
        _owner._write_json(res)
        return 0
    return 2


def _handle_camera(
    args: _owner_types.argparse.Namespace, client: _owner_types.EzvizClient, *, _owner: _ModuleType
) -> int:
    """Handle `camera` subcommands (status/move/unlock/switch/alarm/select)."""
    camera = _owner.EzvizCamera(client, args.serial)
    _owner._LOGGER.debug("Camera loaded")
    if args.camera_action == "move":
        camera.move(args.direction, args.speed)
        return 0
    if args.camera_action == "move_coords":
        camera.move_coordinates(args.x, args.y)
        return 0
    if args.camera_action == "status":
        _owner._write_json(camera.status(refresh=getattr(args, "refresh", True)))
        return 0
    if args.camera_action == "unlock-door":
        camera.door_unlock()
        return 0
    if args.camera_action == "unlock-gate":
        camera.gate_unlock()
        return 0
    if args.camera_action == "switch":
        if args.switch == "ir":
            camera.switch_device_ir_led(args.enable)
        elif args.switch == "state":
            _owner.sys.stdout.write(str(args.enable) + "\n")
            camera.switch_device_state_led(args.enable)
        elif args.switch == "audio":
            camera.switch_device_audio(args.enable)
        elif args.switch == "privacy":
            camera.switch_privacy_mode(args.enable)
        elif args.switch == "sleep":
            camera.switch_sleep_mode(args.enable)
        elif args.switch == "follow_move":
            camera.switch_follow_move(args.enable)
        elif args.switch == "sound_alarm":
            camera.switch_sound_alarm(args.enable + 1)
        else:
            _owner._LOGGER.error("Unknown switch: %s", args.switch)
            return 2
        return 0
    if args.camera_action == "alarm":
        if args.sound is not None:
            camera.alarm_sound(args.sound)
        if args.notify is not None:
            camera.alarm_notify(args.notify)
        if args.sensibility is not None:
            camera.alarm_detection_sensitivity(args.sensibility)
        if args.do_not_disturb is not None:
            camera.do_not_disturb(args.do_not_disturb)
        if args.schedule is not None:
            camera.change_defence_schedule(args.schedule)
        return 0
    if args.camera_action == "select":
        if args.battery_work_mode is not None:
            camera.set_battery_camera_work_mode(
                getattr(_owner.BatteryCameraWorkMode, args.battery_work_mode)
            )
            return 0
        return 2
    _owner._LOGGER.error("Action not implemented, try running with -h switch for help")
    return 2
