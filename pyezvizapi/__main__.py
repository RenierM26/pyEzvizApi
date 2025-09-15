"""pyezvizapi command line.

Small utility CLI for testing and scripting Ezviz operations.
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
import sys
from typing import Any, cast

import pandas as pd

from .camera import EzvizCamera
from .client import EzvizClient
from .constants import BatteryCameraWorkMode, DefenseModeType, DeviceSwitchType
from .exceptions import EzvizAuthVerificationCode, PyEzvizError
from .light_bulb import EzvizLightBulb

_LOGGER = logging.getLogger(__name__)


def _setup_logging(debug: bool) -> None:
    """Configure root logger for CLI usage."""
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level, stream=sys.stderr, format="%(levelname)s: %(message)s"
    )
    if debug:
        # Verbose requests logging in debug mode
        requests_log = logging.getLogger("requests.packages.urllib3")
        requests_log.setLevel(logging.DEBUG)
        requests_log.propagate = True


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Build and parse CLI arguments.

    Returns a populated `argparse.Namespace`. Pass `argv` for testing.
    """
    parser = argparse.ArgumentParser(prog="pyezvizapi")
    parser.add_argument("-u", "--username", required=False, help="Ezviz username")
    parser.add_argument("-p", "--password", required=False, help="Ezviz Password")
    parser.add_argument(
        "-r",
        "--region",
        required=False,
        default="apiieu.ezvizlife.com",
        help="Ezviz API region",
    )
    parser.add_argument(
        "--debug", "-d", action="store_true", help="Print debug messages to stderr"
    )
    parser.add_argument(
        "--json", action="store_true", help="Force JSON output when possible"
    )
    parser.add_argument(
        "--token-file",
        type=str,
        default="ezviz_token.json",
        help="Path to JSON token file in the current directory (default: ezviz_token.json)",
    )
    parser.add_argument(
        "--save-token",
        action="store_true",
        help="Save token to --token-file after successful login",
    )

    subparsers = parser.add_subparsers(dest="action")

    parser_device = subparsers.add_parser(
        "devices", help="Play with all devices at once"
    )
    parser_device.add_argument(
        "device_action",
        type=str,
        default="status",
        help="Device action to perform",
        choices=["device", "status", "switch", "connection"],
    )
    parser_device.add_argument(
        "--refresh",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Refresh alarm info before composing status (default: on)",
    )

    parser_device_lights = subparsers.add_parser(
        "devices_light", help="Get all the light bulbs"
    )
    parser_device_lights.add_argument(
        "devices_light_action",
        type=str,
        default="status",
        help="Light bulbs action to perform",
        choices=["status"],
    )
    parser_device_lights.add_argument(
        "--refresh",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Refresh device data before composing status (default: on)",
    )

    parser_light = subparsers.add_parser("light", help="Light actions")
    parser_light.add_argument("--serial", required=True, help="light bulb SERIAL")

    subparsers_light = parser_light.add_subparsers(dest="light_action")
    subparsers_light.add_parser("toggle", help="Toggle the light bulb")
    subparsers_light.add_parser("status", help="Get information about the light bulb")

    parser_home_defence_mode = subparsers.add_parser(
        "home_defence_mode", help="Set home defence mode"
    )

    subparsers.add_parser("mqtt", help="Connect to mqtt push notifications")

    parser_home_defence_mode.add_argument(
        "--mode", required=False, help="Choose mode", choices=["HOME_MODE", "AWAY_MODE"]
    )

    parser_camera = subparsers.add_parser("camera", help="Camera actions")
    parser_camera.add_argument("--serial", required=True, help="camera SERIAL")

    subparsers_camera = parser_camera.add_subparsers(dest="camera_action")

    parser_camera_status = subparsers_camera.add_parser(
        "status", help="Get the status of the camera"
    )
    parser_camera_status.add_argument(
        "--refresh",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Refresh alarm info before composing status (default: on)",
    )
    subparsers_camera.add_parser("unlock-door", help="Unlock the door lock")
    subparsers_camera.add_parser("unlock-gate", help="Unlock the gate lock")
    parser_camera_move = subparsers_camera.add_parser("move", help="Move the camera")
    parser_camera_move.add_argument(
        "--direction",
        required=True,
        help="Direction to move the camera to",
        choices=["up", "down", "right", "left"],
    )
    parser_camera_move.add_argument(
        "--speed",
        required=False,
        help="Speed of the movement",
        default=5,
        type=int,
        choices=range(1, 10),
    )

    parser_camera_move_coords = subparsers_camera.add_parser(
        "move_coords", help="Move the camera to the X,Y coordinates"
    )
    parser_camera_move_coords.add_argument(
        "--x",
        required=True,
        help="The X coordinate to move the camera to",
        type=float,
    )
    parser_camera_move_coords.add_argument(
        "--y",
        required=True,
        help="The Y coordinate to move the camera to",
        type=float,
    )

    parser_camera_switch = subparsers_camera.add_parser(
        "switch", help="Change the status of a switch"
    )
    parser_camera_switch.add_argument(
        "--switch",
        required=True,
        help="Switch to switch",
        choices=[
            "audio",
            "ir",
            "state",
            "privacy",
            "sleep",
            "follow_move",
            "sound_alarm",
        ],
    )
    parser_camera_switch.add_argument(
        "--enable",
        required=False,
        help="Enable (or not)",
        default=1,
        type=int,
        choices=[0, 1],
    )

    parser_camera_alarm = subparsers_camera.add_parser(
        "alarm", help="Configure the camera alarm"
    )
    parser_camera_alarm.add_argument(
        "--notify", required=False, help="Enable (or not)", type=int, choices=[0, 1]
    )
    parser_camera_alarm.add_argument(
        "--sound",
        required=False,
        help="Sound level (2 is silent, 1 intensive, 0 soft)",
        type=int,
        choices=[0, 1, 2],
    )
    parser_camera_alarm.add_argument(
        "--sensibility",
        required=False,
        help="Sensibility level (Non-Cameras = from 1 to 6) or (Cameras = 1 to 100)",
        type=int,
        choices=range(100),
    )
    parser_camera_alarm.add_argument(
        "--do_not_disturb",
        required=False,
        help=(
            "Enable/disable push notifications for motion events. "
            "Some camera models expose this setting in the EZVIZ app, but not all. "
            "Motion alarms are still recorded and available even when push notifications are disabled."
        ),
        default=None,
        type=int,
        choices=[0, 1],
    )
    parser_camera_alarm.add_argument(
        "--schedule", required=False, help="Schedule in json format *test*", type=str
    )

    parser_camera_select = subparsers_camera.add_parser(
        "select",
        help="Change the value of a multi-value option (for on/off value, see 'switch' command)",
    )

    parser_camera_select.add_argument(
        "--battery_work_mode",
        required=False,
        help="Change the work mode for battery powered camera",
        choices=[
            mode.name
            for mode in BatteryCameraWorkMode
            if mode is not BatteryCameraWorkMode.UNKNOWN
        ],
    )

    # Dump full pagelist for exploration
    subparsers.add_parser("pagelist", help="Output full pagelist as JSON")

    # Dump device infos mapping (optionally for a single serial)
    parser_device_infos = subparsers.add_parser(
        "device_infos",
        help="Output device infos (raw JSON), optionally filtered by serial",
    )
    parser_device_infos.add_argument(
        "--serial", required=False, help="Optional serial to filter a single device"
    )

    return parser.parse_args(argv)


def _login(client: EzvizClient) -> None:
    """Login if credentials are configured; skip when only a token is used."""
    if client.account and client.password:
        try:
            client.login()
        except EzvizAuthVerificationCode:
            mfa_code = input("MFA code required, please input MFA code.\n")
            try:
                code_int = int(mfa_code.strip())
            except ValueError:
                code_int = None
            client.login(sms_code=code_int)


def _write_json(obj: Any) -> None:
    """Write an object to stdout as pretty JSON."""
    sys.stdout.write(json.dumps(obj, indent=2) + "\n")


def _write_df(df: pd.DataFrame) -> None:
    """Write a DataFrame to stdout as a formatted table."""
    sys.stdout.write(df.to_string() + "\n")


def _handle_devices(args: argparse.Namespace, client: EzvizClient) -> int:
    """Handle `devices` subcommands (device/status/switch/connection)."""
    if args.device_action == "device":
        _write_json(client.get_device())
        return 0

    if args.device_action == "status":
        data = client.load_cameras(refresh=getattr(args, "refresh", True))
        if args.json:
            _write_json(data)
        else:
            # Enrich with common switch flags when available
            def _flag_from_switch(sw: Any, code: int) -> bool | None:
                # Accept list[{type, enable}] or dict-like {type: enable}
                if isinstance(sw, list):
                    for item in sw:
                        if isinstance(item, dict) and item.get("type") == code:
                            val = item.get("enable")
                            return bool(val) if isinstance(val, (bool, int)) else None
                    return None
                if isinstance(sw, dict):
                    val = sw.get(code) if code in sw else sw.get(str(code))
                    return bool(val) if isinstance(val, (bool, int)) else None
                return None

            for payload in data.values():
                sw = payload.get("SWITCH")
                if sw is None:
                    continue

                # Compute all switch flags present on the device
                flags: dict[str, bool] = {}
                if isinstance(sw, list):
                    for item in sw:
                        if not isinstance(item, dict):
                            continue
                        t = item.get("type")
                        en = item.get("enable")
                        if not isinstance(t, int) or not isinstance(en, (bool, int)):
                            continue
                        try:
                            name = DeviceSwitchType(t).name.lower()
                        except ValueError:
                            name = f"switch_{t}"
                        flags[name] = bool(en)
                elif isinstance(sw, dict):
                    for k, v in sw.items():
                        try:
                            t = int(k)
                        except (TypeError, ValueError):
                            continue
                        if not isinstance(v, (bool, int)):
                            continue
                        try:
                            name = DeviceSwitchType(t).name.lower()
                        except ValueError:
                            name = f"switch_{t}"
                        flags[name] = bool(v)

                if flags:
                    payload["switch_flags"] = flags

                # Keep legacy-friendly individual columns
                payload["sleep"] = flags.get("sleep")
                payload["privacy"] = flags.get("privacy")
                payload["audio"] = flags.get("sound")
                payload["ir_led"] = flags.get("infrared_light")
                payload["state_led"] = flags.get("light")

            df = pd.DataFrame.from_dict(
                data=data,
                orient="index",
                columns=[
                    "name",
                    "status",
                    "device_category",
                    "device_sub_category",
                    "sleep",
                    "privacy",
                    "audio",
                    "ir_led",
                    "state_led",
                    "local_ip",
                    "local_rtsp_port",
                    "battery_level",
                    "alarm_schedules_enabled",
                    "alarm_notify",
                    "Motion_Trigger",
                ],
            )
            _write_df(df)
        return 0

    if args.device_action == "switch":
        _write_json(client.get_switch())
        return 0

    if args.device_action == "connection":
        _write_json(client.get_connection())
        return 0

    _LOGGER.error("Action not implemented: %s", args.device_action)
    return 2


def _handle_devices_light(args: argparse.Namespace, client: EzvizClient) -> int:
    """Handle `devices_light` subcommands (status)."""
    if args.devices_light_action == "status":
        data = client.load_light_bulbs(refresh=getattr(args, "refresh", True))
        if args.json:
            _write_json(data)
        else:
            df = pd.DataFrame.from_dict(
                data=data,
                orient="index",
                columns=[
                    "name",
                    "status",
                    "device_category",
                    "device_sub_category",
                    "local_ip",
                    "productId",
                    "is_on",
                    "brightness",
                    "color_temperature",
                ],
            )
            _write_df(df)
        return 0
    return 2


def _handle_pagelist(client: EzvizClient) -> int:
    """Output full pagelist (raw JSON) for exploration in editors like Notepad++."""
    data = client._get_page_list()  # noqa: SLF001
    _write_json(data)
    return 0


def _handle_device_infos(args: argparse.Namespace, client: EzvizClient) -> int:
    """Output device infos mapping (raw JSON), optionally filtered by serial."""
    data = (
        client.get_device_infos(args.serial)
        if args.serial
        else client.get_device_infos()
    )
    _write_json(data)
    return 0


def _handle_light(args: argparse.Namespace, client: EzvizClient) -> int:
    """Handle `light` subcommands (toggle/status)."""
    light_bulb = EzvizLightBulb(client, args.serial)
    _LOGGER.debug("Light bulb loaded")
    if args.light_action == "toggle":
        light_bulb.toggle_switch()
        return 0
    if args.light_action == "status":
        _write_json(light_bulb.status())
        return 0
    _LOGGER.error("Action not implemented for light: %s", args.light_action)
    return 2


def _handle_home_defence_mode(args: argparse.Namespace, client: EzvizClient) -> int:
    """Handle `home_defence_mode` subcommands (set mode)."""
    if args.mode:
        res = client.api_set_defence_mode(getattr(DefenseModeType, args.mode).value)
        _write_json(res)
        return 0
    return 2


def _handle_mqtt(_: argparse.Namespace, client: EzvizClient) -> int:
    """Connect to MQTT push notifications using current session token."""
    logging.getLogger().setLevel(logging.DEBUG)
    client.login()
    mqtt = client.get_mqtt_client()
    mqtt.connect()
    return 0


def _handle_camera(args: argparse.Namespace, client: EzvizClient) -> int:
    """Handle `camera` subcommands (status/move/unlock/switch/alarm/select)."""
    camera = EzvizCamera(client, args.serial)
    _LOGGER.debug("Camera loaded")

    if args.camera_action == "move":
        camera.move(args.direction, args.speed)
        return 0

    if args.camera_action == "move_coords":
        camera.move_coordinates(args.x, args.y)
        return 0

    if args.camera_action == "status":
        _write_json(camera.status(refresh=getattr(args, "refresh", True)))
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
            sys.stdout.write(str(args.enable) + "\n")
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
            _LOGGER.error("Unknown switch: %s", args.switch)
            return 2
        return 0

    if args.camera_action == "alarm":
        if args.sound is not None:
            camera.alarm_sound(args.sound)
        if args.notify is not None:
            camera.alarm_notify(args.notify)
        if args.sensibility is not None:
            camera.alarm_detection_sensibility(args.sensibility)
        if args.do_not_disturb is not None:
            camera.do_not_disturb(args.do_not_disturb)
        if args.schedule is not None:
            camera.change_defence_schedule(args.schedule)
        return 0

    if args.camera_action == "select":
        if args.battery_work_mode is not None:
            camera.set_battery_camera_work_mode(
                getattr(BatteryCameraWorkMode, args.battery_work_mode)
            )
            return 0
        return 2

    _LOGGER.error("Action not implemented, try running with -h switch for help")
    return 2


def _load_token_file(path: str | None) -> dict[str, Any] | None:
    """Load a token dictionary from `path` if it exists; else return None."""
    if not path:
        return None
    p = Path(path)
    if not p.exists():
        return None
    try:
        return cast(dict[str, Any], json.loads(p.read_text(encoding="utf-8")))
    except (
        OSError,
        json.JSONDecodeError,
    ):  # pragma: no cover - tolerate malformed file
        _LOGGER.warning("Failed to read token file: %s", p)
        return None


def _save_token_file(path: str | None, token: dict[str, Any]) -> None:
    """Persist the token dictionary to `path` in JSON format."""
    if not path:
        return
    p = Path(path)
    try:
        p.write_text(json.dumps(token, indent=2), encoding="utf-8")
        _LOGGER.info("Saved token to %s", p)
    except OSError:  # pragma: no cover - filesystem issues
        _LOGGER.warning("Failed to save token file: %s", p)


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    args = _parse_args(argv)
    _setup_logging(args.debug)

    token = _load_token_file(args.token_file)
    if not token and (not args.username or not args.password):
        _LOGGER.error("Provide --token-file (existing) or --username/--password")
        return 2

    client = EzvizClient(args.username, args.password, args.region, token=token)
    try:
        _login(client)

        if args.action == "devices":
            return _handle_devices(args, client)
        if args.action == "devices_light":
            return _handle_devices_light(args, client)
        if args.action == "light":
            return _handle_light(args, client)
        if args.action == "home_defence_mode":
            return _handle_home_defence_mode(args, client)
        if args.action == "mqtt":
            return _handle_mqtt(args, client)
        if args.action == "camera":
            return _handle_camera(args, client)
        if args.action == "pagelist":
            return _handle_pagelist(client)
        if args.action == "device_infos":
            return _handle_device_infos(args, client)

    except PyEzvizError as exp:
        _LOGGER.error("%s", exp)
        return 1
    except KeyboardInterrupt:
        _LOGGER.error("Interrupted")
        return 130
    else:
        _LOGGER.error("Action not implemented: %s", args.action)
        return 2
    finally:
        if args.save_token and args.token_file:
            _save_token_file(args.token_file, cast(dict[str, Any], client._token))  # noqa: SLF001
        client.close_session()


if __name__ == "__main__":
    sys.exit(main())
