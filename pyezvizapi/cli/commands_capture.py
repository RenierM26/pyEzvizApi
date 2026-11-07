"""commands capture implementation; legacy runtime hooks remain on the owner module.

Access through _owner is deliberate: callers that patch the compatibility
module must still affect dependent operations. No copied hook snapshots.
"""
# ruff: noqa: SLF001 -- explicit legacy hook boundary.
from __future__ import annotations

import pyezvizapi.cli.main as _owner

def _hcnetsdk_command_plan_from_args(args: _owner.argparse.Namespace) -> _owner.HcNetSdkCommandPortMultiSocketPlan | None:
    """Load a native-style multi-socket command plan from CLI args."""
    plan_file = getattr(args, 'hcnetsdk_command_plan_file', None)
    if not plan_file:
        return None
    text = _owner.Path(plan_file).read_text(encoding='utf-8')
    try:
        data = _owner.json.loads(text)
    except _owner.json.JSONDecodeError as err:
        raise _owner.PyEzvizError('Invalid HCNetSDK command plan JSON') from err
    return _owner._hcnetsdk_command_plan_from_json(data)

def _hcnetsdk_command_generated_plan_from_args(args: _owner.argparse.Namespace) -> _owner.HcNetSdkCommandPortGeneratedMultiSocketPlan | None:
    """Load a generated multi-socket command plan from CLI args."""
    plan_file = getattr(args, 'hcnetsdk_command_generated_plan_file', None)
    native_plan = getattr(args, 'hcnetsdk_command_native_plan', None)
    if plan_file and native_plan:
        raise _owner.PyEzvizError('Provide only one of --hcnetsdk-command-generated-plan-file or --hcnetsdk-command-native-plan')
    if native_plan:
        if getattr(args, 'channel', 1) != 1:
            raise _owner.PyEzvizError('--hcnetsdk-command-native-plan app-lan-live-view currently supports only --channel 1 because the app-observed command tails contain channel-1 fields')
        return _owner.hcnetsdk_command_port_native_lan_live_view_plan(native_plan)
    if not plan_file:
        return None
    text = _owner.Path(plan_file).read_text(encoding='utf-8')
    try:
        data = _owner.json.loads(text)
    except _owner.json.JSONDecodeError as err:
        raise _owner.PyEzvizError('Invalid HCNetSDK generated command plan JSON') from err
    return _owner._hcnetsdk_command_generated_plan_from_json(data)

def _hcnetsdk_command_plan_from_json(value: _owner.Any) -> _owner.HcNetSdkCommandPortMultiSocketPlan:
    """Build a command-port socket plan from simple JSON shapes."""
    raw_steps: list[_owner.Any] | None
    if isinstance(value, list):
        raw_steps = value
    elif isinstance(value, dict):
        raw_steps = None
        for key in ('socket_plan', 'socketPlan', 'sockets', 'sessions', 'steps'):
            item = value.get(key)
            if isinstance(item, list):
                raw_steps = item
                break
        if raw_steps is None:
            raise _owner.PyEzvizError('HCNetSDK command plan JSON is missing socket steps')
    else:
        raise _owner.PyEzvizError('HCNetSDK command plan JSON must be an object or list')
    steps = tuple((_owner._hcnetsdk_command_plan_step_from_json(item) for item in raw_steps))
    return _owner.HcNetSdkCommandPortMultiSocketPlan(steps=steps)

def _hcnetsdk_command_generated_plan_from_json(value: _owner.Any) -> _owner.HcNetSdkCommandPortGeneratedMultiSocketPlan:
    """Build a generated command-port socket plan from JSON."""
    raw_steps = _owner._hcnetsdk_command_plan_raw_steps(value)
    steps = tuple((_owner._hcnetsdk_command_generated_plan_step_from_json(item) for item in raw_steps))
    return _owner.HcNetSdkCommandPortGeneratedMultiSocketPlan(steps=steps)

def _hcnetsdk_command_plan_raw_steps(value: _owner.Any) -> list[_owner.Any]:
    """Return raw socket step objects from concrete or generated JSON."""
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        for key in ('socket_plan', 'socketPlan', 'sockets', 'sessions', 'steps'):
            item = value.get(key)
            if isinstance(item, list):
                return item
        raise _owner.PyEzvizError('HCNetSDK command plan JSON is missing socket steps')
    raise _owner.PyEzvizError('HCNetSDK command plan JSON must be an object or list')

def _hcnetsdk_command_plan_step_from_json(value: _owner.Any) -> _owner.HcNetSdkCommandPortSocketStep:
    """Build one socket step from a JSON object."""
    if not isinstance(value, dict):
        raise _owner.PyEzvizError('HCNetSDK command plan step must be an object')
    frames = _owner._hcnetsdk_command_plan_frames_from_json(value, ('command_frames', 'commandFrames', 'frames'))
    keepalive_frames = _owner._hcnetsdk_command_plan_frames_from_json(value, ('keepalive_frames', 'keepaliveFrames'), required=False)
    media_socket = _owner._hcnetsdk_command_plan_media_socket(value)
    read_policy = _owner._hcnetsdk_command_plan_read_policy(value, default=not media_socket)
    response_reads = _owner._hcnetsdk_command_plan_response_reads(value)
    read_first_media_immediately = _owner._hcnetsdk_command_plan_immediate_media_read(value)
    delay_after_commands = _owner._hcnetsdk_command_plan_delay_after_commands(value)
    drain_media_before_next = _owner._hcnetsdk_command_plan_drain_media_before_next(value)
    interval = value.get('keepalive_interval_seconds')
    if interval is None:
        interval = value.get('keepaliveIntervalSeconds', 5.0)
    initial_delay = value.get('keepalive_initial_delay_seconds')
    if initial_delay is None:
        initial_delay = value.get('keepaliveInitialDelaySeconds')
    name = value.get('name')
    return _owner.HcNetSdkCommandPortSocketStep(command_frames=frames, read_response_after_each=read_policy, response_reads_after_each=response_reads, media_socket=media_socket, read_first_media_immediately=read_first_media_immediately, delay_after_commands_seconds=delay_after_commands, drain_media_before_next_step_seconds=drain_media_before_next, keepalive_frames=keepalive_frames, keepalive_interval_seconds=float(interval), keepalive_initial_delay_seconds=None if initial_delay is None else float(initial_delay), name=name if isinstance(name, str) else None)

def _hcnetsdk_command_generated_plan_step_from_json(value: _owner.Any) -> _owner.HcNetSdkCommandPortGeneratedSocketStep:
    """Build one generated socket step from a JSON object."""
    if not isinstance(value, dict):
        raise _owner.PyEzvizError('HCNetSDK generated command plan step must be an object')
    templates = _owner._hcnetsdk_command_plan_templates_from_json(value, ('control_templates', 'controlTemplates', 'templates', 'commands'))
    keepalive_templates = _owner._hcnetsdk_command_plan_templates_from_json(value, ('keepalive_templates', 'keepaliveTemplates'), required=False)
    media_socket = _owner._hcnetsdk_command_plan_media_socket(value)
    read_policy = _owner._hcnetsdk_command_plan_read_policy(value, default=not media_socket)
    response_reads = _owner._hcnetsdk_command_plan_response_reads(value)
    read_first_media_immediately = _owner._hcnetsdk_command_plan_immediate_media_read(value)
    delay_after_commands = _owner._hcnetsdk_command_plan_delay_after_commands(value)
    drain_media_before_next = _owner._hcnetsdk_command_plan_drain_media_before_next(value)
    interval = value.get('keepalive_interval_seconds')
    if interval is None:
        interval = value.get('keepaliveIntervalSeconds', 5.0)
    initial_delay = value.get('keepalive_initial_delay_seconds')
    if initial_delay is None:
        initial_delay = value.get('keepaliveInitialDelaySeconds')
    name = value.get('name')
    return _owner.HcNetSdkCommandPortGeneratedSocketStep(control_templates=templates, read_response_after_each=read_policy, response_reads_after_each=response_reads, media_socket=media_socket, read_first_media_immediately=read_first_media_immediately, delay_after_commands_seconds=delay_after_commands, drain_media_before_next_step_seconds=drain_media_before_next, keepalive_templates=keepalive_templates, keepalive_interval_seconds=float(interval), keepalive_initial_delay_seconds=None if initial_delay is None else float(initial_delay), name=name if isinstance(name, str) else None)

def _hcnetsdk_command_plan_templates_from_json(value: _owner.Mapping[str, _owner.Any], keys: tuple[str, ...], *, required: bool=True) -> tuple[_owner.HcNetSdkCommandPortControlTemplate, ...]:
    """Read generated control templates from one command-plan JSON step."""
    for key in keys:
        item = value.get(key)
        if item is not None:
            templates = tuple((_owner._hcnetsdk_command_plan_template_from_json(template) for template in _owner._iter_hcnetsdk_command_template_values(item)))
            if templates or not required:
                return templates
    if required:
        raise _owner.PyEzvizError('HCNetSDK generated command plan step is missing templates')
    return ()

def _iter_hcnetsdk_command_template_values(value: _owner.Any) -> _owner.Iterator[_owner.Any]:
    """Yield generated command template objects from JSON."""
    if isinstance(value, list):
        for item in value:
            yield from _owner._iter_hcnetsdk_command_template_values(item)
        return
    yield value

def _hcnetsdk_command_plan_template_from_json(value: _owner.Any) -> _owner.HcNetSdkCommandPortControlTemplate:
    """Build one generated control template from a JSON object."""
    if not isinstance(value, dict):
        raise _owner.PyEzvizError('HCNetSDK generated command template must be an object')
    command_id = _owner._hcnetsdk_int_required(value, ('command_id', 'commandId', 'command'), 'HCNetSDK generated command template is missing command_id')
    body_tail = _owner._hcnetsdk_bytes_from_json(value, ('body_tail', 'bodyTail', 'body_tail_hex', 'bodyTailHex', 'tail', 'tailHex'))
    addend = _owner._hcnetsdk_optional_int(value, ('addend',))
    addend_delta = _owner._hcnetsdk_optional_int(value, ('addend_delta', 'addendDelta'))
    mask_seed = _owner._hcnetsdk_bytes_from_json(value, ('mask_seed', 'maskSeed', 'mask_seed_hex', 'maskSeedHex'), default=b'\x00' * 6)
    body_tail_transform = value.get('body_tail_transform')
    if body_tail_transform is None:
        body_tail_transform = value.get('bodyTailTransform')
    if body_tail_transform is not None and (not isinstance(body_tail_transform, str)):
        raise _owner.PyEzvizError('HCNetSDK body_tail_transform must be a string')
    name = value.get('name')
    return _owner.HcNetSdkCommandPortControlTemplate(command_id=command_id, body_tail=body_tail, addend=addend, addend_delta=addend_delta, mask_seed=mask_seed, body_tail_transform=body_tail_transform, name=name if isinstance(name, str) else None)

def _hcnetsdk_int_required(value: _owner.Mapping[str, _owner.Any], keys: tuple[str, ...], message: str) -> int:
    """Read a required integer field from a JSON object."""
    for key in keys:
        if key in value:
            return _owner._hcnetsdk_int(value[key])
    raise _owner.PyEzvizError(message)

def _hcnetsdk_optional_int(value: _owner.Mapping[str, _owner.Any], keys: tuple[str, ...]) -> int | None:
    """Read an optional integer field from a JSON object."""
    for key in keys:
        if key in value and value[key] is not None:
            return _owner._hcnetsdk_int(value[key])
    return None

def _hcnetsdk_bytes_from_json(value: _owner.Mapping[str, _owner.Any], keys: tuple[str, ...], *, default: bytes=b'') -> bytes:
    """Read an optional hex byte field from a JSON object."""
    for key in keys:
        item = value.get(key)
        if item is None:
            continue
        if not isinstance(item, str):
            raise _owner.PyEzvizError('HCNetSDK byte fields must be hex strings')
        return _owner._bytes_from_hex_value(item)
    return default

def _hcnetsdk_command_plan_frames_from_json(value: _owner.Mapping[str, _owner.Any], keys: tuple[str, ...], *, required: bool=True) -> tuple[bytes, ...]:
    """Read a frame list from one command-plan JSON step."""
    for key in keys:
        item = value.get(key)
        if item is not None:
            frames = tuple((_owner._bytes_from_hex_value(frame_hex) for frame_hex in _owner._iter_hcnetsdk_command_frame_hex_values(item)))
            if frames or not required:
                return frames
    if required:
        raise _owner.PyEzvizError('HCNetSDK command plan step is missing frames')
    return ()

def _hcnetsdk_command_plan_read_policy(value: _owner.Mapping[str, _owner.Any], *, default: bool=True) -> bool | tuple[bool, ...]:
    """Read the response policy for one command-plan step."""
    raw = value.get('read_response_after_each')
    if raw is None:
        raw = value.get('readResponseAfterEach')
    if raw is None:
        raw = value.get('read_responses')
    if raw is None:
        raw = value.get('readResponses', default)
    if isinstance(raw, list):
        return tuple((_owner._hcnetsdk_bool(raw_value) for raw_value in raw))
    if isinstance(raw, str) and ',' in raw:
        return tuple((_owner._hcnetsdk_bool(part.strip()) for part in raw.split(',') if part.strip()))
    return _owner._hcnetsdk_bool(raw)

def _hcnetsdk_command_plan_response_reads(value: _owner.Mapping[str, _owner.Any]) -> int | tuple[int, ...] | None:
    """Read optional response-frame counts for one command-plan step."""
    raw = value.get('response_reads_after_each')
    if raw is None:
        raw = value.get('responseReadsAfterEach')
    if raw is None:
        raw = value.get('response_reads')
    if raw is None:
        raw = value.get('responseReads')
    if raw is None:
        return None
    if isinstance(raw, list):
        return tuple((_owner._hcnetsdk_int(raw_value) for raw_value in raw))
    if isinstance(raw, str) and ',' in raw:
        return tuple((_owner._hcnetsdk_int(part.strip()) for part in raw.split(',') if part.strip()))
    return _owner._hcnetsdk_int(raw)

def _hcnetsdk_command_plan_media_socket(value: _owner.Mapping[str, _owner.Any]) -> bool:
    """Return whether a command-plan step is the media socket."""
    for key in ('media_socket', 'mediaSocket', 'read_media', 'readMedia', 'media'):
        raw = value.get(key)
        if raw is not None:
            return _owner._hcnetsdk_bool(raw)
    role = value.get('role')
    return isinstance(role, str) and role.lower() in {'media', 'stream'}

def _hcnetsdk_command_plan_immediate_media_read(value: _owner.Mapping[str, _owner.Any]) -> bool:
    """Return whether a media step should read first media before later steps."""
    for key in ('read_first_media_immediately', 'readFirstMediaImmediately', 'read_first_media_before_next_step', 'readFirstMediaBeforeNextStep'):
        raw = value.get(key)
        if raw is not None:
            return _owner._hcnetsdk_bool(raw)
    return False

def _hcnetsdk_command_plan_delay_after_commands(value: _owner.Mapping[str, _owner.Any]) -> float:
    """Return optional pacing delay after one command-plan step."""
    for key in ('delay_after_commands_seconds', 'delayAfterCommandsSeconds', 'delay_after_commands', 'delayAfterCommands'):
        raw = value.get(key)
        if raw is not None:
            delay = float(raw)
            if delay < 0:
                raise _owner.PyEzvizError('HCNetSDK command step delay must be non-negative')
            return delay
    return 0.0

def _hcnetsdk_command_plan_drain_media_before_next(value: _owner.Mapping[str, _owner.Any]) -> float:
    """Return optional media-drain duration before later command-plan steps."""
    for key in ('drain_media_before_next_step_seconds', 'drainMediaBeforeNextStepSeconds', 'drain_media_before_next_step', 'drainMediaBeforeNextStep'):
        raw = value.get(key)
        if raw is not None:
            drain = float(raw)
            if drain < 0:
                raise _owner.PyEzvizError('HCNetSDK command media drain must be non-negative')
            return drain
    return 0.0

def _hcnetsdk_bool(value: _owner.Any) -> bool:
    """Parse permissive boolean values from CLI JSON."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in {0, 1}:
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {'1', 'true', 'yes', 'y'}:
            return True
        if normalized in {'0', 'false', 'no', 'n'}:
            return False
    raise _owner.PyEzvizError('Invalid HCNetSDK boolean value')

def _hcnetsdk_int(value: _owner.Any) -> int:
    """Parse non-negative integer values from CLI JSON."""
    if isinstance(value, bool):
        raise _owner.PyEzvizError('Invalid HCNetSDK integer value')
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip(), 0)
        except ValueError as err:
            with _owner.suppress(ValueError):
                return int(value.strip())
            raise _owner.PyEzvizError('Invalid HCNetSDK integer value') from err
    raise _owner.PyEzvizError('Invalid HCNetSDK integer value')

def _hcnetsdk_command_frames_from_args(args: _owner.argparse.Namespace) -> tuple[bytes, ...]:
    """Load complete command-port frames from CLI hex values or a file."""
    frame_hex_values = list(getattr(args, 'hcnetsdk_command_frame_hex', []) or [])
    frames_file = getattr(args, 'hcnetsdk_command_frames_file', None)
    if frames_file:
        frame_hex_values.extend(_owner._hcnetsdk_command_frame_hex_values_from_file(frames_file))
    frames = tuple((_owner._bytes_from_hex_value(value) for value in frame_hex_values))
    if not frames:
        raise _owner.PyEzvizError('--source hcnetsdk-command-port requires --hcnetsdk-command-frame-hex or --hcnetsdk-command-frames-file')
    return frames

def _hcnetsdk_command_frame_hex_values_from_file(path: str) -> list[str]:
    """Read command-frame hex values from JSON or text."""
    text = _owner.Path(path).read_text(encoding='utf-8')
    try:
        data = _owner.json.loads(text)
    except _owner.json.JSONDecodeError:
        return [line.split('#', 1)[0].strip() for line in text.splitlines() if line.split('#', 1)[0].strip()]
    return list(_owner._iter_hcnetsdk_command_frame_hex_values(data))

def _iter_hcnetsdk_command_frame_hex_values(value: _owner.Any) -> _owner.Iterator[str]:
    """Yield command-frame hex strings from simple JSON shapes."""
    if isinstance(value, str):
        yield value
        return
    if isinstance(value, list):
        for item in value:
            yield from _owner._iter_hcnetsdk_command_frame_hex_values(item)
        return
    if isinstance(value, dict):
        for key in ('hex', 'frame_hex', 'frameHex', 'command_frame_hex', 'commandFrameHex'):
            item = value.get(key)
            if isinstance(item, str):
                yield item
        for key in ('command_frames', 'commandFrames', 'frames'):
            item = value.get(key)
            if isinstance(item, list):
                yield from _owner._iter_hcnetsdk_command_frame_hex_values(item)

def _bytes_from_hex_value(value: str) -> bytes:
    """Decode a user-supplied hex byte string."""
    normalized = value.strip().replace(' ', '').replace(':', '').replace('-', '')
    if normalized.startswith(('0x', '0X')):
        normalized = normalized[2:]
    try:
        return bytes.fromhex(normalized)
    except ValueError as err:
        raise _owner.PyEzvizError('Invalid HCNetSDK command frame hex') from err

def _hcnetsdk_read_response_policy(args: _owner.argparse.Namespace, frame_count: int) -> bool | tuple[bool, ...]:
    """Return response-read policy for command-port bootstrapping."""
    value = getattr(args, 'hcnetsdk_read_responses', None)
    if not value:
        return True
    parts = [part.strip().lower() for part in value.split(',') if part.strip()]
    flags = tuple((part in {'1', 'true', 'yes', 'y'} for part in parts))
    if len(flags) != frame_count:
        raise _owner.PyEzvizError('--hcnetsdk-read-responses must include one boolean per command frame')
    valid_values = {'1', '0', 'true', 'false', 'yes', 'no', 'y', 'n'}
    unknown = [part for part in parts if part not in valid_values]
    if unknown:
        raise _owner.PyEzvizError('Invalid --hcnetsdk-read-responses value')
    return flags

def _handle_save_image(args: _owner.argparse.Namespace, client: _owner.EzvizClient) -> int:
    """Save a camera image to disk, triggering capture when no URL is supplied."""
    result = client.save_image(args.serial, args.output, channel=args.channel, image_url=args.image_url, decrypt=not args.no_decrypt, smscode=args.sms_code)
    _owner._write_save_result(args, result)
    return 0

def _handle_save(args: _owner.argparse.Namespace, client: _owner.EzvizClient) -> int:
    """Handle person-friendly local save commands."""
    if args.save_action == 'clip':
        return _owner._handle_save_clip(args, client)
    if args.save_action == 'image':
        return _owner._handle_save_image(args, client)
    _owner._LOGGER.error('Action not implemented, try running with -h switch for help')
    return 2

def _handle_light(args: _owner.argparse.Namespace, client: _owner.EzvizClient) -> int:
    """Handle `light` subcommands (toggle/status)."""
    light_bulb = _owner.EzvizLightBulb(client, args.serial)
    _owner._LOGGER.debug('Light bulb loaded')
    if args.light_action == 'toggle':
        light_bulb.toggle_switch()
        return 0
    if args.light_action == 'status':
        _owner._write_json(light_bulb.status())
        return 0
    _owner._LOGGER.error('Action not implemented for light: %s', args.light_action)
    return 2

def _handle_home_defence_mode(args: _owner.argparse.Namespace, client: _owner.EzvizClient) -> int:
    """Handle `home_defence_mode` subcommands (set mode)."""
    if args.mode:
        res = client.api_set_defence_mode(getattr(_owner.DefenseModeType, args.mode).value)
        _owner._write_json(res)
        return 0
    return 2

def _handle_mqtt(args: _owner.argparse.Namespace, client: _owner.EzvizClient) -> int:
    """Migrate the login and listen with durable channel-99 token storage."""
    try:
        client.enable_channel99()
    except _owner.EzvizAuthVerificationCode:
        code = input('MFA code required, please input MFA code.\n')
        try:
            sms_code = int(code.strip())
        except ValueError as err:
            raise _owner.PyEzvizError('MFA code must be numeric') from err
        client.enable_channel99(sms_code=sms_code)
    mqtt = client.get_mqtt_client(on_message_callback=_owner._write_json)
    mqtt.connect()
    try:
        while True:
            mqtt.raise_if_failed()
            _owner.time.sleep(1)
    except KeyboardInterrupt:
        return 0
    finally:
        try:
            mqtt.stop()
        except TimeoutError as error:
            raise _owner.PyEzvizError('Push shutdown timed out; cancellation remains signalled') from error

def _write_stream_payloads(stream: _owner.Any, output: _owner.BinaryIO, *, max_packets: int | None, duration_seconds: float | None=None, first_packet_deadline: float | None=None, allow_encrypted: bool, transform_payload: _owner.Callable[[bytes], bytes] | None=None, flush_each: bool=False, monotonic: _owner.Any=_owner.time.monotonic) -> None:
    """Write VTM stream packet bodies to a binary file-like object."""
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
    for packet in stream.iter_packets(**iterator_kwargs):
        if deadline is not None and monotonic() >= deadline:
            break
        if packet.encrypted and (not allow_encrypted):
            raise _owner.PyEzvizError('Received encrypted VTM stream packet; media decryption is not implemented')
        payload = transform_payload(packet.body) if transform_payload else packet.body
        if payload:
            output.write(payload)
        if flush_each:
            output.flush()
    if transform_payload and hasattr(transform_payload, 'flush'):
        tail = transform_payload.flush()
        if tail:
            output.write(tail)
    output.flush()
