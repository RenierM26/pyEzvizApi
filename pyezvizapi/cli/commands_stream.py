"""commands stream implementation; legacy runtime hooks remain on the owner module.

Access through _owner is deliberate: callers that patch the compatibility
module must still affect dependent operations. No copied hook snapshots.
"""
# ruff: noqa: SLF001 -- explicit legacy hook boundary.
from __future__ import annotations

import pyezvizapi.cli.main as _owner

def _handle_camera(args: _owner.argparse.Namespace, client: _owner.EzvizClient) -> int:
    """Handle `camera` subcommands (status/move/unlock/switch/alarm/select)."""
    camera = _owner.EzvizCamera(client, args.serial)
    _owner._LOGGER.debug('Camera loaded')
    if args.camera_action == 'move':
        camera.move(args.direction, args.speed)
        return 0
    if args.camera_action == 'move_coords':
        camera.move_coordinates(args.x, args.y)
        return 0
    if args.camera_action == 'status':
        _owner._write_json(camera.status(refresh=getattr(args, 'refresh', True)))
        return 0
    if args.camera_action == 'unlock-door':
        camera.door_unlock()
        return 0
    if args.camera_action == 'unlock-gate':
        camera.gate_unlock()
        return 0
    if args.camera_action == 'switch':
        if args.switch == 'ir':
            camera.switch_device_ir_led(args.enable)
        elif args.switch == 'state':
            _owner.sys.stdout.write(str(args.enable) + '\n')
            camera.switch_device_state_led(args.enable)
        elif args.switch == 'audio':
            camera.switch_device_audio(args.enable)
        elif args.switch == 'privacy':
            camera.switch_privacy_mode(args.enable)
        elif args.switch == 'sleep':
            camera.switch_sleep_mode(args.enable)
        elif args.switch == 'follow_move':
            camera.switch_follow_move(args.enable)
        elif args.switch == 'sound_alarm':
            camera.switch_sound_alarm(args.enable + 1)
        else:
            _owner._LOGGER.error('Unknown switch: %s', args.switch)
            return 2
        return 0
    if args.camera_action == 'alarm':
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
    if args.camera_action == 'select':
        if args.battery_work_mode is not None:
            camera.set_battery_camera_work_mode(getattr(_owner.BatteryCameraWorkMode, args.battery_work_mode))
            return 0
        return 2
    _owner._LOGGER.error('Action not implemented, try running with -h switch for help')
    return 2
