# Runtime hooks deliberately resolve through their legacy owner.
# ruff: noqa: SLF001

"""serialization implementation; legacy runtime hooks remain on the owner module.

Access through _owner is deliberate: callers that patch the compatibility
module must still affect dependent operations. No copied hook snapshots.
"""
from __future__ import annotations

import pyezvizapi.streaming.local.hcnetsdk.protocol as _owner


def hcnetsdk_stdxml_response_json(response: _owner.Mapping[str, _owner.Any] | str | bytes) -> dict[str, _owner.Any]:
    """Parse a JSON response returned by EZVIZ local STDXML helpers."""
    if isinstance(response, _owner.Mapping):
        return dict(response)
    try:
        if isinstance(response, bytes):
            response = response.split(b'\x00', 1)[0]
            text = response.decode('utf-8')
        else:
            text = response.split('\x00', 1)[0]
        parsed = _owner.json.loads(text)
    except (UnicodeDecodeError, ValueError) as err:
        raise _owner.PyEzvizError('Invalid HCNetSDK STDXML response JSON') from err
    if not isinstance(parsed, dict):
        raise _owner.PyEzvizError('HCNetSDK STDXML response JSON must be an object')
    return parsed

def _hcnetsdk_compression_info_v30(raw: bytes, offset: int) -> _owner.EzvizLanCompressionInfoV30 | None:
    if len(raw) < offset + _owner.HCNETSDK_COMPRESSION_INFO_V30_SIZE:
        return None
    block = raw[offset:offset + _owner.HCNETSDK_COMPRESSION_INFO_V30_SIZE]
    return _owner.EzvizLanCompressionInfoV30(stream_type=block[0], resolution=block[1], bitrate_type=block[2], picture_quality=block[3], video_bitrate=int.from_bytes(block[4:8], 'big'), video_frame_rate=int.from_bytes(block[8:12], 'big'), i_frame_interval=int.from_bytes(block[12:14], 'big'), interval_bp_frame=block[14], reserved1=block[15], video_encoding_type=block[16], audio_encoding_type=block[17], video_encoding_complexity=block[18], svc_enabled=block[19], format_type=block[20], audio_bitrate=block[21], stream_smoothing=block[22], audio_sampling_rate=block[23], smart_codec=block[24], depth_map_enabled=block[25], average_video_bitrate=int.from_bytes(block[26:28], 'big'), raw=block)

def hcnetsdk_real_data_type_is_media(data_type: int) -> bool:
    """Return whether a real-play callback type can carry media payloads."""
    return data_type in (_owner.HcNetSdkRealDataType.STREAM_DATA, _owner.HcNetSdkRealDataType.AUDIO_STREAM_DATA, _owner.HcNetSdkRealDataType.PRIVATE_DATA)

def hcnetsdk_real_play_request(login_id: int, *, channel_number: int=1, link_mode: int=0, blocked: bool=False, multicast_ip: str='') -> _owner.HcNetSdkRealPlayRequest:
    """Build the APK-observed ``EZ_NET_DVR_RealPlay_V30`` argument model."""
    return _owner.HcNetSdkRealPlayRequest(login_id=login_id, client_info=_owner.HcNetSdkClientInfo(channel=channel_number, link_mode=link_mode, multicast_ip=multicast_ip), blocked=blocked)

def classify_hcnetsdk_real_data_payload(data: bytes) -> str:
    """Classify HCNetSDK callback bytes without decoding or exposing content."""
    if not data:
        return 'empty'
    prefixes = ((_owner.HCNETSDK_MPEG_PS_PACK_HEADER, 'mpeg_ps'), (_owner.HCNETSDK_MPEG_START_CODE_PREFIX, 'mpeg_ps_start'), (bytes((_owner.HCNETSDK_MPEG_TS_SYNC_BYTE,)), 'mpeg_ts'), (_owner.HCNETSDK_HKMI_PREFIX, 'hik_hkmi'), (_owner.HCNETSDK_HIK_PRIVATE_PREFIX, 'hik_private'))
    for prefix, kind in prefixes:
        if data.startswith(prefix):
            return kind
    return 'unknown'

def build_hcnetsdk_tcp_frame(body: bytes=b'', *, field_4: int=0, field_8: int=0, field_12: int=0) -> bytes:
    """Build the generic observed HCNetSDK command-port frame wrapper."""
    header = _owner.HcNetSdkTcpFrameHeader(total_length=_owner.HCNETSDK_TCP_HEADER_LENGTH + len(body), field_4=field_4, field_8=field_8, field_12=field_12)
    return _owner.HcNetSdkTcpFrame(header=header, body=body).to_bytes()

def hcnetsdk_command_port_auth_word(*, session_id: bytes, auth_seed: int, command_id: int, key: bytes, addend: int | None=None, mask_seed: bytes=b'\x00' * _owner.HCNETSDK_COMMAND_PORT_AUTH_MASK_LENGTH) -> int:
    """Return the native HCNetSDK port-8000 post-login command auth word.

    ``session_id`` is the network-order four-byte id returned in the login
    response and reused in command bodies. Native ``libHCCore.so`` reverses it
    into a host-order word before the auth routine, uses the first 16 challenge
    bytes as a four-round AES-128 key, folds the 16-byte result down to one
    little-endian word, then adds the session-derived time/addend word used in
    the command header.
    """
    if len(session_id) != 4:
        raise _owner.PyEzvizError('HCNetSDK command-port session id must be 4 bytes')
    if len(key) < _owner.HCNETSDK_COMMAND_PORT_AUTH_KEY_LENGTH:
        raise _owner.PyEzvizError('HCNetSDK command-port auth key must be at least 16 bytes')
    if len(mask_seed) < _owner.HCNETSDK_COMMAND_PORT_AUTH_MASK_LENGTH:
        raise _owner.PyEzvizError('HCNetSDK command-port auth mask seed must be 6 bytes')
    session_word = int.from_bytes(session_id, 'big')
    input_word = auth_seed + command_id * 2 + _owner._hcnetsdk_command_port_auth_mask(session_word, mask_seed) & 4294967295
    transformed = _owner._hcnetsdk_command_port_four_round_aes(input_word.to_bytes(4, 'little') + b'\x00' * 12, key[:_owner.HCNETSDK_COMMAND_PORT_AUTH_KEY_LENGTH])
    folded = bytes(transformed[index] ^ transformed[index + 4] ^ transformed[index + 8] ^ transformed[index + 12] for index in range(4))
    return int.from_bytes(folded, 'little') + (session_word if addend is None else addend) & 4294967295

def hcnetsdk_command_port_control_frame(*, session_id: bytes, auth_seed: int, command_id: int, key: bytes, local_ip: str, body_tail: bytes=b'', addend: int | None=None, mask_seed: bytes=b'\x00' * _owner.HCNETSDK_COMMAND_PORT_AUTH_MASK_LENGTH) -> bytes:
    """Build one generated post-login HCNetSDK port-8000 control frame.

    The frame body format observed in native traces is the client LAN IPv4 word
    in little-endian byte order, the four-byte network-order login session id,
    eight reserved zero bytes, and then the command-specific tail. The auth word
    uses the same network-order session id returned by login.
    """
    if len(session_id) != 4:
        raise _owner.PyEzvizError('HCNetSDK command-port session id must be 4 bytes')
    body = _owner._hcnetsdk_command_port_local_ip_word(local_ip) + session_id + b'\x00' * 8 + body_tail
    return _owner.build_hcnetsdk_tcp_frame(body, field_4=_owner.HCNETSDK_COMMAND_PORT_CONTROL_FAMILY, field_8=_owner.hcnetsdk_command_port_auth_word(session_id=session_id, auth_seed=auth_seed, command_id=command_id, key=key, addend=addend, mask_seed=mask_seed), field_12=command_id)

def hcnetsdk_command_port_play_login_body_tail_for_today(body_tail: bytes, *, today: _owner.date | None=None) -> bytes:
    """Refresh native play-login date words in a captured ``0x111040`` tail."""
    if len(body_tail) != 148:
        raise _owner.PyEzvizError('HCNetSDK play-login body tail transform requires a 148-byte tail')
    current = today or _owner.date.today()
    patched = bytearray(body_tail)
    values = {36: current.year, 40: current.month, 44: current.day, 60: current.year, 64: current.month, 68: current.day, 72: 23, 76: 59, 80: 59}
    for offset, value in values.items():
        patched[offset:offset + 4] = value.to_bytes(4, 'big')
    return bytes(patched)

def hcnetsdk_command_candidate_role(candidate: int | None) -> str | None:
    """Return the current role label for an observed command candidate.

    The names are trace-derived labels, not a complete HCNetSDK command table.
    They are useful for reducing redacted captures while the underlying
    encrypted request format is still being mapped.
    """
    if candidate == _owner.HCNETSDK_COMMAND_CANDIDATE_SETTINGS_LOGIN:
        return 'settings_login'
    if candidate == _owner.HCNETSDK_COMMAND_CANDIDATE_CONTROL:
        return 'control'
    return None

def ezviz_native_video_level(video_level: int) -> int:
    """Mirror ``Utils.convertVideoLevel()`` before writing ``iVideoLevel``."""
    if video_level == -1:
        return 3
    if video_level == 0:
        return 2
    if video_level == 1:
        return 1
    if video_level == 2:
        return 0
    if video_level == 3:
        return 4
    return 5

def build_ezviz_local_preview_request_body(*, operation_code: str, channel: int, receiver_info: str | _owner.EzvizLocalReceiverInfo | _owner.EzvizLocalReceiverInfoAttrs, receiver_info_ex: str | _owner.EzvizLocalReceiverInfoEx | _owner.EzvizLocalReceiverInfoExAttrs, identifier: str | None=None, is_encrypt: str | int='TRUE', udt: int | None=None, nat: int | None=None, port_guess_type: int | None=None, timeout: int | None=None, heartbeat_interval: int | None=None, authentication: str | _owner.EzvizLocalAuthenticationAttrs | None=None, uuid: str | None=None, timestamp: str | int | None=None, public_key: str | None=None) -> bytes:  # noqa: PLR0913
    """Build the plaintext XML body for the observed 0x2011 request.

    The caller must supply values obtained through their own credential/source
    path. This helper only gives the confirmed tag order and escaping.
    """
    if channel < 0:
        raise _owner.PyEzvizError('EZVIZ local preview channel must be non-negative')
    return _owner._build_local_sdk_request_xml((('OperationCode', operation_code), ('Channel', channel), ('Identifier', identifier), ('ReceiverInfo', receiver_info), ('IsEncrypt', is_encrypt), ('Udt', udt), ('Nat', nat), ('PortGuessType', port_guess_type), ('Timeout', timeout), ('HeartbeatInterval', heartbeat_interval), ('ReceiverInfoEx', receiver_info_ex), ('Authentication', authentication), ('Uuid', uuid), ('Timestamp', timestamp), ('PublicKey', public_key)))

def ezviz_local_sdk_iv(serial: str, operation_code: str) -> bytes:
    """Build the AES-CBC IV used by EZVIZ local-control CAS frames."""
    iv = f'{serial}{operation_code}'.encode('latin1')
    if len(iv) != _owner.EZVIZ_LOCAL_SDK_AES_BLOCK_SIZE:
        raise _owner.PyEzvizError('EZVIZ local SDK IV must be 16 bytes from serial + operation code')
    return iv

def hcnetsdk_command_port_response_payload(response: _owner.HcNetSdkTcpFrame | bytes) -> bytes:
    """Return a textual JSON/XML payload from a command-port response.

    Native command-port responses may include leading binary or NUL padding
    before the string output buffer. Keep the rule intentionally narrow so
    binary command responses remain available to lower-level callers.
    """
    body = response.body if isinstance(response, _owner.HcNetSdkTcpFrame) else response
    if not body:
        return b''
    candidates: list[tuple[int, bytes]] = []
    for marker in (b'<?xml', b'{', b'[', _owner.HCNETSDK_XML_MARKER):
        offset = body.find(marker)
        if offset >= 0:
            candidates.append((offset, body[offset:].split(b'\x00', 1)[0].strip()))
    for _offset, candidate in sorted(candidates, key=lambda item: item[0]):
        if not candidate:
            continue
        if candidate[:1] in {b'{', b'['}:
            try:
                _owner.json.loads(candidate.decode('utf-8'))
            except (UnicodeDecodeError, ValueError):
                continue
            return candidate
        if candidate.startswith(b'<?xml') or (candidate[:1] == _owner.HCNETSDK_XML_MARKER and len(candidate) > 1 and candidate[1:2].isalpha()):
            return candidate
    return body.split(b'\x00', 1)[0].strip()

def _mapping_str(data: _owner.Mapping[str, _owner.Any], key: str) -> str | None:
    value = data.get(key)
    if isinstance(value, str) and value:
        return value
    return None

def _mapping_int(data: _owner.Mapping[str, _owner.Any], key: str, *, default: int | None, zero_is_missing: bool=False) -> int | None:
    value = data.get(key)
    if value is None:
        return default
    if isinstance(value, int):
        return default if zero_is_missing and value == 0 else value
    if isinstance(value, str):
        try:
            int_value = int(value)
        except ValueError:
            return default
        return default if zero_is_missing and int_value == 0 else int_value
    return default

def _stdxml_bytes(label: str, value: str | bytes) -> bytes:
    if isinstance(value, bytes):
        return value
    if not isinstance(value, str):
        raise _owner.PyEzvizError(f'HCNetSDK STDXML {label} must be bytes or string')
    return value.encode('utf-8')

def _optional_native_bytes(label: str, value: str | bytes | None) -> bytes:
    if value is None:
        return b''
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode('utf-8')
    raise _owner.PyEzvizError(f'{label} must be bytes or string')

def _native_secret_key_bytes(label: str, value: str | bytes) -> bytes:
    raw = _owner._optional_native_bytes(label, value)
    if not raw:
        raise _owner.PyEzvizError(f'{label} cannot be empty')
    if len(raw) > 4096:
        raise _owner.PyEzvizError(f'{label} must be at most 4096 bytes')
    return raw

def _native_path_value(label: str, value: str | bytes, *, include_buffers: bool=False) -> str | bytes:
    raw = _owner._optional_native_bytes(f'HCNetSDK {label}', value)
    if not raw:
        raise _owner.PyEzvizError(f'HCNetSDK {label} cannot be empty')
    if _owner.SADP_NUL_BYTE in raw:
        raise _owner.PyEzvizError(f'HCNetSDK {label} cannot contain NUL bytes')
    if include_buffers:
        return raw
    try:
        return raw.decode('utf-8')
    except UnicodeDecodeError as err:
        raise _owner.PyEzvizError(f'HCNetSDK {label} must be UTF-8') from err

def _bounded_bytes(label: str, value: str | bytes, limit: int, *, truncate: bool=False) -> bytes:
    if isinstance(value, bytes):
        raw = value
    elif isinstance(value, str):
        raw = value.encode('utf-8')
    else:
        raise _owner.PyEzvizError(f'EZVIZ LAN {label} must be bytes or string')
    if len(raw) <= limit:
        return raw
    if truncate:
        return raw[:limit]
    raise _owner.PyEzvizError(f'EZVIZ LAN {label} must be at most {limit} bytes')

def _sadp_string_bytes(label: str, value: str | bytes, limit: int, *, allow_empty: bool=False) -> bytes:
    if isinstance(value, bytes):
        raw = value
    elif isinstance(value, str):
        raw = value.encode('utf-8')
    else:
        raise _owner.PyEzvizError(f'SADP {label} must be bytes or string')
    if not raw and (not allow_empty):
        raise _owner.PyEzvizError(f'SADP {label} cannot be empty')
    if len(raw) > limit:
        raise _owner.PyEzvizError(f'SADP {label} must be at most {limit} bytes')
    return raw

def _optional_raw_byte(raw: bytes, offset: int) -> int | None:
    return raw[offset] if len(raw) > offset else None

def _optional_raw_u16_be(raw: bytes, offset: int) -> int | None:
    if len(raw) < offset + 2:
        return None
    return int.from_bytes(raw[offset:offset + 2], 'big')

def _optional_raw_u32_be(raw: bytes, offset: int) -> int | None:
    if len(raw) < offset + 4:
        return None
    return int.from_bytes(raw[offset:offset + 4], 'big')

def _optional_raw_u16_be_pair(raw: bytes, first_offset: int, second_offset: int) -> tuple[int, int] | None:
    first = _owner._optional_raw_u16_be(raw, first_offset)
    second = _owner._optional_raw_u16_be(raw, second_offset)
    if first is None or second is None:
        return None
    return (first, second)

def _optional_raw_byte_triplet(raw: bytes, first_offset: int, second_offset: int, third_offset: int) -> tuple[int, int, int] | None:
    if len(raw) <= max(first_offset, second_offset, third_offset):
        return None
    return (raw[first_offset], raw[second_offset], raw[third_offset])

def _byte_value(label: str, value: int) -> int:
    if not 0 <= value <= 255:
        raise _owner.PyEzvizError(f'EZVIZ LAN {label} must fit in one byte')
    return value

def _word_value(label: str, value: int) -> int:
    if not 0 <= value <= 65535:
        raise _owner.PyEzvizError(f'EZVIZ LAN {label} must fit in one unsigned word')
    return value

def _port_value(label: str, value: int) -> int:
    if not 0 <= value <= 65535:
        raise _owner.PyEzvizError(f'{label} must be between 0 and 65535')
    return value

def _nul_stripped_text(value: str | bytes | None) -> str:
    if value is None:
        return ''
    text = value.decode('utf-8') if isinstance(value, bytes) else value
    return text.replace('\x00', '').strip()

def _device_ability_bytes(label: str, value: str | bytes) -> bytes:
    if isinstance(value, bytes):
        return value
    if not isinstance(value, str):
        raise _owner.PyEzvizError(f'HCNetSDK device ability {label} must be bytes or string')
    return value.encode('utf-8')

def _ability_option_tuple(value: str | None) -> tuple[str, ...]:
    if value is None:
        return ()
    return tuple(option.strip() for option in value.split(',') if option.strip())

def _hcnetsdk_command_port_local_ip_word(local_ip: str) -> bytes:
    try:
        return _owner.ipaddress.IPv4Address(local_ip).packed[::-1]
    except _owner.ipaddress.AddressValueError as err:
        raise _owner.PyEzvizError('HCNetSDK command-port local IP must be an IPv4 address') from err

def _hcnetsdk_command_port_auth_mask(session_word: int, mask_seed: bytes) -> int:
    """Return the small native mask term mixed into command auth input."""
    return sum(mask_seed[index] & (session_word >> 5 * index & 255) for index in range(_owner.HCNETSDK_COMMAND_PORT_AUTH_MASK_LENGTH))

def _hcnetsdk_command_port_four_round_aes(block: bytes, key: bytes) -> bytes:
    """Encrypt one 16-byte block with the SDK's four-round AES-128 variant."""
    if len(block) != 16:
        raise _owner.PyEzvizError('HCNetSDK command-port auth block must be 16 bytes')
    if len(key) != _owner.HCNETSDK_COMMAND_PORT_AUTH_KEY_LENGTH:
        raise _owner.PyEzvizError('HCNetSDK command-port auth key must be 16 bytes')
    round_keys = _owner._hcnetsdk_aes128_round_keys(key, rounds=4)
    state = _owner._hcnetsdk_aes_add_round_key(block, round_keys[0])
    for round_index in range(1, 4):
        state = _owner._hcnetsdk_aes_sub_bytes(state)
        state = _owner._hcnetsdk_aes_shift_rows(state)
        state = _owner._hcnetsdk_aes_mix_columns(state)
        state = _owner._hcnetsdk_aes_add_round_key(state, round_keys[round_index])
    state = _owner._hcnetsdk_aes_sub_bytes(state)
    state = _owner._hcnetsdk_aes_shift_rows(state)
    return _owner._hcnetsdk_aes_add_round_key(state, round_keys[4])

def _hcnetsdk_aes128_round_keys(key: bytes, *, rounds: int) -> tuple[bytes, ...]:
    """Return AES-128 round keys, truncated to the native command-auth rounds."""
    words = [list(key[index:index + 4]) for index in range(0, 16, 4)]
    while len(words) < 4 * (rounds + 1):
        word = words[-1][:]
        if len(words) % 4 == 0:
            word = word[1:] + word[:1]
            word = [_owner._AES_SBOX[item] for item in word]
            word[0] ^= _owner._AES_RCON[len(words) // 4 - 1]
        words.append([left ^ right for left, right in zip(words[-4], word, strict=True)])
    expanded = bytes(item for word in words for item in word)
    return tuple(expanded[index:index + 16] for index in range(0, 16 * (rounds + 1), 16))

def _hcnetsdk_aes_add_round_key(state: bytes, round_key: bytes) -> bytes:
    return bytes((left ^ right for left, right in zip(state, round_key, strict=True)))

def _hcnetsdk_aes_sub_bytes(state: bytes) -> bytes:
    return bytes(_owner._AES_SBOX[item] for item in state)

def _hcnetsdk_aes_shift_rows(state: bytes) -> bytes:
    return bytes((state[0], state[5], state[10], state[15], state[4], state[9], state[14], state[3], state[8], state[13], state[2], state[7], state[12], state[1], state[6], state[11]))

def _hcnetsdk_aes_xtime(value: int) -> int:
    shifted = value << 1
    if value & 128:
        shifted ^= 27
    return shifted & 255

def _hcnetsdk_aes_mix_columns(state: bytes) -> bytes:
    mixed = bytearray()
    for column_index in range(0, 16, 4):
        column = state[column_index:column_index + 4]
        doubled = [_owner._hcnetsdk_aes_xtime(item) for item in column]
        mixed.extend((doubled[0] ^ column[3] ^ column[2] ^ doubled[1] ^ column[1], doubled[1] ^ column[0] ^ column[3] ^ doubled[2] ^ column[2], doubled[2] ^ column[1] ^ column[0] ^ doubled[3] ^ column[3], doubled[3] ^ column[2] ^ column[1] ^ doubled[0] ^ column[0]))
    return bytes(mixed)

def _build_local_sdk_request_xml(fields: tuple[tuple[str, str | int | _owner.EzvizLocalReceiverInfo | _owner.EzvizLocalReceiverInfoAttrs | _owner.EzvizLocalReceiverInfoEx | _owner.EzvizLocalReceiverInfoExAttrs | _owner.EzvizLocalAuthenticationAttrs | None], ...]) -> bytes:
    lines = ['<?xml version="1.0" encoding="utf-8"?>', '<Request>']
    for tag, value in fields:
        if value is None:
            continue
        if isinstance(value, (_owner.EzvizLocalReceiverInfo, _owner.EzvizLocalReceiverInfoAttrs)):
            if tag != 'ReceiverInfo':
                raise _owner.PyEzvizError('Structured receiver info must use ReceiverInfo tag')
            lines.extend(value.xml_lines())
            continue
        if isinstance(value, (_owner.EzvizLocalReceiverInfoEx, _owner.EzvizLocalReceiverInfoExAttrs)):
            if tag != 'ReceiverInfoEx':
                raise _owner.PyEzvizError('Structured receiver info ex must use ReceiverInfoEx tag')
            lines.extend(value.xml_lines())
            continue
        if isinstance(value, _owner.EzvizLocalAuthenticationAttrs):
            if tag != 'Authentication':
                raise _owner.PyEzvizError('Structured authentication must use Authentication tag')
            lines.extend(value.xml_lines())
            continue
        lines.append(f'\t<{tag}>{_owner._xml_escape(str(value))}</{tag}>')
    lines.append('</Request>')
    return ('\n'.join(lines) + '\n').encode('utf-8')

def _xml_escape(value: str) -> str:
    return value.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&apos;')

def _xml_attrs(fields: _owner.Iterable[tuple[str, str | int]]) -> str:
    return ' '.join((f'{tag}="{_owner._xml_escape(str(value))}"' for tag, value in fields))

def _local_sdk_aes_bytes(label: str, value: bytes | str) -> bytes:
    data = value.encode('utf-8') if isinstance(value, str) else value
    if len(data) == _owner.EZVIZ_LOCAL_SDK_AES_BLOCK_SIZE:
        return data
    if isinstance(value, str):
        try:
            decoded = _owner.base64.b64decode(value, validate=True)
        except _owner.binascii.Error:
            decoded = b''
        if len(decoded) == _owner.EZVIZ_LOCAL_SDK_AES_BLOCK_SIZE:
            return decoded
    raise _owner.PyEzvizError(f'EZVIZ local SDK AES {label} must be 16 bytes')
