# Runtime hook context is explicit; immutable value types come from dependency leaves.
# ruff: noqa: SLF001
'discovery implementation; legacy runtime hooks remain on the owner module.\n\nAccess through _owner is deliberate: callers that patch the compatibility\nmodule must still affect dependent operations. No copied hook snapshots.\n'
from __future__ import annotations

from collections.abc import Mapping as _StaticMapping
from types import ModuleType as _ModuleType
from typing import TYPE_CHECKING

from pyezvizapi.streaming.local.hcnetsdk.models_session import (
    EzvizLocalSdkFrame as _StaticEzvizLocalSdkFrame,
)

if TYPE_CHECKING:
    import pyezvizapi.streaming.local.hcnetsdk.api as _owner_types

def classify_lan_ports(endpoint: _owner_types.HcNetSdkLanEndpoint, *, timeout: float | None, socket_factory: _owner_types.SocketFactory, _owner: _ModuleType) -> list[_owner_types.HcNetSdkPortProbe]:
    """Probe advertised LAN ports without authenticating or changing state."""
    ports = [endpoint.sdk_tls_port, endpoint.command_port, endpoint.stream_port, endpoint.rtsp_port]
    seen: set[int] = set()
    results: list[_owner_types.HcNetSdkPortProbe] = []
    for port in ports:
        if port is None or port <= 0 or port in seen:
            continue
        seen.add(port)
        results.append(_owner._probe_port(endpoint.host, port, timeout=timeout, socket_factory=socket_factory))
    return results

def sadp_activate_device_request(serial: str, password: str, *, _owner: _ModuleType) -> _owner_types.SadpActivateDeviceRequest:
    """Return the local SADP device activation request shape."""
    return _owner.SadpActivateDeviceRequest(serial=serial, password=password)

def sadp_device_net_param(*, ipv4_address: str, ipv4_subnet_mask: str, ipv4_gateway: str, dhcp_enabled: int | bool, http_port: int, command_port: int, ipv6_address: str, ipv6_gateway: str, ipv6_mask_len: int, _owner: _ModuleType) -> _owner_types.SadpDeviceNetParam:
    """Return the Android ``SADP_DEV_NET_PARAM`` field-update model."""
    return _owner.SadpDeviceNetParam(ipv4_address=ipv4_address, ipv4_subnet_mask=ipv4_subnet_mask, ipv4_gateway=ipv4_gateway, dhcp_enabled=dhcp_enabled, http_port=http_port, command_port=command_port, ipv6_address=ipv6_address, ipv6_gateway=ipv6_gateway, ipv6_mask_len=ipv6_mask_len)

def sadp_modify_device_net_param_request(mac: str, password: str, net_param: _owner_types.SadpDeviceNetParam, *, _owner: _ModuleType) -> _owner_types.SadpModifyDeviceNetParamRequest:
    """Return the local SADP network-parameter update request shape."""
    return _owner.SadpModifyDeviceNetParamRequest(mac=mac, password=password, net_param=net_param)

def sadp_modify_device_net_param_v40_request(mac: str, password: str, net_param: _owner_types.SadpDeviceNetParam, *, ret_net_param: _owner_types.SadpDeviceRetNetParam | None, _owner: _ModuleType) -> _owner_types.SadpModifyDeviceNetParamV40Request:
    """Return the local SADP V40 network-parameter update request shape."""
    return _owner.SadpModifyDeviceNetParamV40Request(mac=mac, password=password, net_param=net_param, ret_net_param=ret_net_param)

def sadp_get_last_error_request(*, _owner: _ModuleType) -> _owner_types.SadpNoArgRequest:
    """Return the ``SADP_GetLastError`` request shape."""
    return _owner.SadpNoArgRequest(api=_owner.SADP_GET_LAST_ERROR)

def sadp_get_sadp_version_request(*, _owner: _ModuleType) -> _owner_types.SadpNoArgRequest:
    """Return the ``SADP_GetSadpVersion`` request shape."""
    return _owner.SadpNoArgRequest(api=_owner.SADP_GET_VERSION)

def sadp_set_log_to_file_request(log_level: int, log_dir: str | bytes, *, auto_delete: int | bool, _owner: _ModuleType) -> _owner_types.SadpSetLogToFileRequest:
    """Return the ``SADP_SetLogToFile`` request shape."""
    return _owner.SadpSetLogToFileRequest(log_level=log_level, log_dir=log_dir, auto_delete=auto_delete)

def sadp_start_v30_request(*, install_npf: int | bool, callback: str | None, user_data: str | None, _owner: _ModuleType) -> _owner_types.SadpStartRequest:
    """Return the ``SADP_Start_V30`` request shape."""
    return _owner.SadpStartRequest(version=30, install_npf=install_npf, callback=callback, user_data=user_data)

def sadp_start_v40_request(*, install_npf: int | bool, callback: str | None, user_data: str | None, _owner: _ModuleType) -> _owner_types.SadpStartRequest:
    """Return the ``SADP_Start_V40`` request shape."""
    return _owner.SadpStartRequest(version=40, install_npf=install_npf, callback=callback, user_data=user_data)

def sadp_stop_request(*, _owner: _ModuleType) -> _owner_types.SadpNoArgRequest:
    """Return the ``SADP_Stop`` request shape."""
    return _owner.SadpNoArgRequest(api=_owner.SADP_STOP)

def sadp_clearup_request(*, _owner: _ModuleType) -> _owner_types.SadpNoArgRequest:
    """Return the ``SADP_Clearup`` request shape."""
    return _owner.SadpNoArgRequest(api=_owner.SADP_CLEARUP)

def sadp_send_inquiry_request(*, _owner: _ModuleType) -> _owner_types.SadpNoArgRequest:
    """Return the ``SADP_SendInquiry`` request shape."""
    return _owner.SadpNoArgRequest(api=_owner.SADP_SEND_INQUIRY)

def ezviz_lan_sadp_activate_batch_result(serial: str, password: str, *, code: int, error: int, _owner: _ModuleType) -> _owner_types.SadpBatchResult:
    """Return the RN-style result map model for batch SADP activation."""
    return _owner.SadpBatchResult(identifier=serial, password=password, code=code, error=error, identifier_key='serial')

def ezviz_lan_sadp_edit_net_param_batch_result(mac: str, password: str, *, code: int, error: int, _owner: _ModuleType) -> _owner_types.SadpBatchResult:
    """Return the RN-style result map model for batch SADP network edits."""
    return _owner.SadpBatchResult(identifier=mac, password=password, code=code, error=error, identifier_key='mac')

def ezviz_hcnetsdk_local_ability_parse_request(*, enabled: int | bool, _owner: _ModuleType) -> _owner_types.HcNetSdkSetSdkLocalCfgRequest:
    """Return the SDK-local ability parser toggle exposed by the APK."""
    return _owner.hcnetsdk_set_sdk_local_cfg_request(_owner.HcNetSdkLocalCfgType.ABILITY_PARSE, structure='NET_DVR_LOCAL_ABILITY_PARSE_CFG', field_updates={'byEnableAbilityParse': _owner._byte_value('ability parse enabled', int(enabled))}, field_order=_owner.HCNETSDK_LOCAL_ABILITY_PARSE_CFG_FIELD_ORDER)

def classify_hcnetsdk_tcp_payload(data: bytes, *, _owner: _ModuleType) -> _owner_types.HcNetSdkTcpPayloadShape:
    """Classify raw HCNetSDK command-port bytes without decoding secrets.

    Port 8000 traffic is still proprietary. This helper gives future live
    captures a stable Python target by recording byte-shape facts only:
    framing candidates, aggregate byte ratios, XML tag names when present, and
    common length-prefix guesses. It intentionally does not parse credentials.
    """
    length = len(data)
    if length == 0:
        return _owner.HcNetSdkTcpPayloadShape(kind='empty', length=0, printable_ratio=0.0, null_ratio=0.0, high_bit_ratio=0.0, entropy_bits_per_byte=0.0)
    printable = sum(1 for byte in data if 32 <= byte <= 126)
    nulls = data.count(0)
    high_bit = sum(1 for byte in data if byte >= 128)
    xml_offset = _owner._xml_offset(data)
    xml_tags = _owner._xml_tag_names(data[xml_offset:]) if xml_offset is not None else ()
    declared_offset, declared_length = _owner._hcnetsdk_declared_length(data)
    u32be_0 = int.from_bytes(data[:4], 'big') if length >= 4 else None
    u32le_0 = int.from_bytes(data[:4], 'little') if length >= 4 else None
    u32be_4 = int.from_bytes(data[4:8], 'big') if length >= 8 else None
    u32le_4 = int.from_bytes(data[4:8], 'little') if length >= 8 else None
    u32be_8 = int.from_bytes(data[8:12], 'big') if length >= 12 else None
    u32le_8 = int.from_bytes(data[8:12], 'little') if length >= 12 else None
    u32be_12 = int.from_bytes(data[12:16], 'big') if length >= 16 else None
    u32le_12 = int.from_bytes(data[12:16], 'little') if length >= 16 else None
    u16be_0 = int.from_bytes(data[:2], 'big') if length >= 2 else None
    u16le_0 = int.from_bytes(data[:2], 'little') if length >= 2 else None
    return _owner.HcNetSdkTcpPayloadShape(kind=_owner._hcnetsdk_tcp_payload_kind(data, printable_ratio=printable / length, high_bit_ratio=high_bit / length, xml_offset=xml_offset, xml_tags=xml_tags, declared_length_offset=declared_offset), length=length, printable_ratio=printable / length, null_ratio=nulls / length, high_bit_ratio=high_bit / length, entropy_bits_per_byte=_owner._entropy_bits_per_byte(data), u32be_0=u32be_0, u32le_0=u32le_0, u32be_4=u32be_4, u32le_4=u32le_4, u32be_8=u32be_8, u32le_8=u32le_8, u32be_12=u32be_12, u32le_12=u32le_12, u16be_0=u16be_0, u16le_0=u16le_0, declared_length_offset=declared_offset, declared_length=declared_length, xml_offset=xml_offset, xml_tags=xml_tags)

def parse_hcnetsdk_tcp_shape_log_line(line: str, *, _owner: _ModuleType) -> _owner_types.HcNetSdkTcpShapeLogRecord | None:
    """Parse one secret-safe HCNetSDK TCP shape log line.

    These lines contain only metadata, not raw bytes. This parser turns that
    metadata into the same Python shape model used by direct byte
    classification, so captured traces can drive packet-builder tests without
    copying secrets into fixtures.
    """
    match = _owner.re.search('\\[(?:hcnetsdk|native)-(?P<direction>send|recv|read|write)\\]\\s+fd=(?P<fd>-?\\d+)\\s+(?P<host>\\d{1,3}(?:\\.\\d{1,3}){3}):(?P<port>\\d+)\\s+(?P<fields>.*)$', line.strip())
    if not match:
        return None
    fields = _owner._parse_shape_fields(match.group('fields'))
    kind = fields.get('tcpKind')
    length = _owner._parse_int(fields.get('tcpLen'))
    if not kind or length is None:
        return None
    length_candidates = _owner._parse_length_candidates(fields.get('lengthCandidates'))
    declared_offset: int | None = None
    declared_length: int | None = None
    if length_candidates:
        first_name, declared_length = next(iter(length_candidates.items()))
        declared_offset = _owner._parse_length_candidate_offset(first_name)
    return _owner.HcNetSdkTcpShapeLogRecord(direction=match.group('direction'), fd=int(match.group('fd')), host=match.group('host'), port=int(match.group('port')), shape=_owner.HcNetSdkTcpPayloadShape(kind=kind, length=length, printable_ratio=_owner._parse_float(fields.get('printable')) or 0.0, null_ratio=_owner._parse_float(fields.get('nulls')) or 0.0, high_bit_ratio=_owner._parse_float(fields.get('high')) or 0.0, entropy_bits_per_byte=0.0, u32be_0=_owner._parse_int(fields.get('u32be0')), u32le_0=_owner._parse_int(fields.get('u32le0')), u32be_4=_owner._parse_int(fields.get('u32be4')), u32le_4=_owner._parse_int(fields.get('u32le4')), u32be_8=_owner._parse_int(fields.get('u32be8')), u32le_8=_owner._parse_int(fields.get('u32le8')), u32be_12=_owner._parse_int(fields.get('u32be12')), u32le_12=_owner._parse_int(fields.get('u32le12')), u16be_0=_owner._parse_int(fields.get('u16be0')), u16le_0=_owner._parse_int(fields.get('u16le0')), declared_length_offset=declared_offset, declared_length=declared_length), captured_length=_owner._parse_int(fields.get('captured')), fingerprint=fields.get('fp128'), length_candidates=length_candidates)

def parse_hcnetsdk_semantic_log_line(line: str, *, _owner: _ModuleType) -> _owner_types.HcNetSdkSemanticLogEvent | None:
    """Parse one secret-safe HCNetSDK semantic event line."""
    match = _owner.re.search('\\[hcnetsdk-semantic\\]\\s+(?P<body>.*)$', line.strip())
    if not match:
        return None
    body = match.group('body')
    if body.startswith(('waiting for ', 'hooked ', 'native hooks installed ')) or (' hook unavailable ' in body or ' hooks unavailable ' in body):
        return None
    tokens = body.split()
    if not tokens:
        return None
    field_index = next((index for index, token in enumerate(tokens) if '=' in token), len(tokens))
    head = tokens[:field_index]
    fields = _owner._parse_shape_fields(' '.join(tokens[field_index:]))
    phase = head[-1] if head and head[-1] in {'enter', 'leave'} else None
    name_tokens = head[:-1] if phase else head
    if not name_tokens:
        return None
    return _owner.HcNetSdkSemanticLogEvent(name=' '.join(name_tokens), phase=phase, fields=fields)

def summarize_hcnetsdk_command_trace(lines: _owner_types.Iterable[str], *, _owner: _ModuleType) -> _owner_types.HcNetSdkCommandTraceSummary:
    """Summarize one mixed HCNetSDK command-shape/semantic trace.

    This reducer is deliberately conservative: it uses semantic enter/leave
    boundaries to associate redacted write command candidates with
    HCNETUtil.s(...) settings login, leaves all later command candidates in
    followup_commands, and records only boolean proof points for playback
    login, keyframe request, and command-socket media.
    """
    login_commands: list[int] = []
    followup_commands: list[int] = []
    in_settings_login = False
    settings_login_success = False
    play_device_login_success = False
    keyframe_requested = False
    media_on_command_socket = False
    for line in lines:
        record = _owner.parse_hcnetsdk_tcp_shape_log_line(line)
        if record is not None:
            if record.shape.kind == 'interleaved_media':
                media_on_command_socket = True
            command = _owner._hcnetsdk_shape_command_candidate(record)
            if command is not None:
                if in_settings_login:
                    login_commands.append(command)
                else:
                    followup_commands.append(command)
        event = _owner.parse_hcnetsdk_semantic_log_line(line)
        if event is None:
            continue
        if event.name == _owner.EZVIZ_HCNETUTIL_LOGIN_V40:
            if event.phase == 'enter':
                in_settings_login = True
            elif event.phase == 'leave':
                in_settings_login = False
                ret = _owner._event_field_int(event, 'ret')
                settings_login_success = ret is not None and ret >= 0
            continue
        if event.name in {_owner.EZVIZ_DEVICE_INFO_EX_LOGIN_PLAY_DEVICE, _owner.EZVIZ_PLAY_DATA_INFO_LOGIN_PLAY_DEVICE} and event.phase == 'leave':
            ret = _owner._event_field_int(event, 'ret')
            play_device_login_success = ret is not None and ret >= 0
            continue
        if event.name.endswith('NET_DVR_MakeKeyFrame') and event.phase == 'leave':
            keyframe_requested = _owner._event_field_bool(event, 'ret')
    return _owner.HcNetSdkCommandTraceSummary(settings_login_commands=tuple(login_commands), followup_commands=tuple(followup_commands), settings_login_success=settings_login_success, play_device_login_success=play_device_login_success, keyframe_requested=keyframe_requested, media_on_command_socket=media_on_command_socket)

def parse_hcnetsdk_tcp_frame_header(data: bytes, *, _owner: _ModuleType) -> _owner_types.HcNetSdkTcpFrameHeader:
    """Parse the observed 16-byte HCNetSDK command-port frame header."""
    if len(data) < _owner.HCNETSDK_TCP_HEADER_LENGTH:
        raise _owner.PyEzvizError('HCNetSDK TCP frame header is truncated')
    total_length = int.from_bytes(data[0:4], 'big')
    if total_length < _owner.HCNETSDK_TCP_HEADER_LENGTH:
        raise _owner.PyEzvizError('HCNetSDK TCP frame total length is too small')
    return _owner.HcNetSdkTcpFrameHeader(total_length=total_length, field_4=int.from_bytes(data[4:8], 'big'), field_8=int.from_bytes(data[8:12], 'big'), field_12=int.from_bytes(data[12:16], 'big'))

def parse_hcnetsdk_tcp_frame(data: bytes, *, _owner: _ModuleType) -> _owner_types.HcNetSdkTcpFrame:
    """Parse one complete observed HCNetSDK command-port frame."""
    header = _owner.parse_hcnetsdk_tcp_frame_header(data)
    if len(data) < header.total_length:
        raise _owner.PyEzvizError('HCNetSDK TCP frame is truncated')
    return _owner.HcNetSdkTcpFrame(header=header, body=data[_owner.HCNETSDK_TCP_HEADER_LENGTH:header.total_length])

def parse_hcnetsdk_command_port_login_session(first_response: _owner_types.HcNetSdkTcpFrame, second_response: _owner_types.HcNetSdkTcpFrame, *, challenge: bytes, password_seed: bytes, _owner: _ModuleType) -> _owner_types.HcNetSdkCommandPortLoginSession:
    """Parse the successful second command-port login response."""
    if len(second_response.body) < 4 or second_response.body[:4] == _owner.HCNETSDK_COMMAND_PORT_EMPTY_SESSION_ID:
        raise _owner.PyEzvizError('HCNetSDK command-port login failed')
    return _owner.HcNetSdkCommandPortLoginSession(session_id=second_response.body[:4], auth_seed=second_response.header.field_4, serial=second_response.body[4:48].split(b'\x00', 1)[0].decode('ascii', errors='ignore'), first_response=first_response, second_response=second_response, challenge=challenge, password_seed=password_seed)

def parse_ezviz_local_device(data: _owner_types.Mapping[str, _owner_types.Any], *, _owner: _ModuleType) -> _owner_types.EzvizLocalDevice:
    """Parse one EZVIZ ``/v3/devices/loc/list`` local-device record."""
    serial = _owner._mapping_str(data, 'deviceSerial')
    if not serial:
        raise _owner.PyEzvizError('Missing deviceSerial in EZVIZ local-device record')
    content = _owner._parse_local_device_content(data.get('deviceContent'))
    return _owner.EzvizLocalDevice(serial=serial, name=_owner._mapping_str(data, 'deviceName'), model=_owner._mapping_str(data, 'deviceModel'), category=_owner._mapping_str(data, 'category'), device_category=_owner._mapping_str(data, 'deviceCategory'), group_id=_owner._mapping_int(data, 'groupId', default=None), content=content, raw=data)

def parse_sadp_response(data: bytes | str, *, _owner: _ModuleType) -> _owner_types.SadpDeviceInfo:
    """Parse an XML SADP response body into a small field mapping."""
    text = data.decode('utf-8', 'ignore') if isinstance(data, bytes) else data
    start = text.find('<')
    end = text.rfind('>')
    if start == -1 or end == -1 or end <= start:
        raise _owner.PyEzvizError('SADP response does not contain XML')
    root = _owner.ET.fromstring(text[start:end + 1])
    fields: dict[str, str] = {}
    for element in root.iter():
        tag = element.tag.rsplit('}', 1)[-1]
        value = (element.text or '').strip()
        if value:
            fields[tag] = value
    return _owner.SadpDeviceInfo(fields=fields)

def parse_ezviz_local_sdk_frame_header(data: bytes, *, _owner: _ModuleType) -> _owner_types.EzvizLocalSdkFrameHeader:
    """Parse the 32-byte EZVIZ local SDK control header.

    Normal app traces against a directly-owned camera showed this
    framing on both the command port and the stream setup port before XML
    bodies. The helper only parses the non-secret header; callers can decide
    whether retaining any body bytes is appropriate for their workflow.
    """
    if len(data) < _owner.EZVIZ_LOCAL_SDK_HEADER_LENGTH:
        raise _owner.PyEzvizError('EZVIZ local SDK frame header is truncated')
    magic = data[:4]
    if magic != _owner.EZVIZ_LOCAL_SDK_MAGIC:
        raise _owner.PyEzvizError('EZVIZ local SDK frame header has invalid magic')
    return _owner.EzvizLocalSdkFrameHeader(magic=magic, version=int.from_bytes(data[4:8], 'big'), sequence=int.from_bytes(data[8:12], 'big'), marker=int.from_bytes(data[12:16], 'big'), command=int.from_bytes(data[18:20], 'big'), status=int.from_bytes(data[20:24], 'big'), body_length=int.from_bytes(data[24:28], 'big'), reserved=int.from_bytes(data[28:32], 'big'))

def parse_ezviz_local_sdk_frame(data: bytes, *, _owner: _ModuleType) -> _owner_types.EzvizLocalSdkFrame:
    """Parse an EZVIZ local SDK frame and validate its declared body length."""
    header = _owner.parse_ezviz_local_sdk_frame_header(data)
    frame_length = _owner.EZVIZ_LOCAL_SDK_HEADER_LENGTH + header.body_length
    if len(data) < frame_length:
        raise _owner.PyEzvizError('EZVIZ local SDK frame body is truncated')
    return _owner.EzvizLocalSdkFrame(header=header, body=data[_owner.EZVIZ_LOCAL_SDK_HEADER_LENGTH:frame_length], trailer=data[frame_length:])

def parse_ezviz_local_sdk_xml_fields(data: bytes | str | _owner_types.EzvizLocalSdkFrame, *, _owner: _ModuleType) -> dict[str, str]:
    """Parse a local SDK XML body into simple tag text fields."""
    if isinstance(data, _StaticEzvizLocalSdkFrame):
        body: bytes | str = data.body
    else:
        body = data
    text = body.decode('utf-8', 'ignore') if isinstance(body, bytes) else body
    start = text.find('<')
    end = text.rfind('>')
    if start == -1 or end == -1 or end <= start:
        raise _owner.PyEzvizError('EZVIZ local SDK body does not contain XML')
    root = _owner.ET.fromstring(text[start:end + 1])
    fields: dict[str, str] = {}
    for element in root.iter():
        tag = element.tag.rsplit('}', 1)[-1]
        value = (element.text or '').strip()
        if value:
            fields[tag] = value
    return fields

def classify_ezviz_local_sdk_body(data: bytes, *, _owner: _ModuleType) -> _owner_types.EzvizLocalSdkBodyShape:
    """Classify frame body shape without exposing body contents.

    The app trace showed plain XML response bodies, but request bodies
    did not surface XML tags under redacted instrumentation. This helper keeps
    only aggregate properties and tag names, so it is safe to store in notes.
    """
    length = len(data)
    if length == 0:
        return _owner.EzvizLocalSdkBodyShape(kind='empty', length=0, printable_ratio=0.0, null_ratio=0.0, high_bit_ratio=0.0, entropy_bits_per_byte=0.0)
    printable = sum(1 for byte in data if 32 <= byte <= 126)
    nulls = data.count(0)
    high_bit = sum(1 for byte in data if byte >= 128)
    xml_offset = _owner._xml_offset(data)
    xml_tags = _owner._xml_tag_names(data[xml_offset:]) if xml_offset is not None else ()
    if xml_tags and xml_offset == 0:
        kind = 'xml'
    elif xml_tags:
        kind = 'prefixed_xml'
    elif high_bit / length > _owner.EZVIZ_BODY_OPAQUE_HIGH_BIT_THRESHOLD:
        kind = 'opaque_binary'
    elif printable / length > _owner.EZVIZ_BODY_PRINTABLE_THRESHOLD:
        kind = 'printable_non_xml'
    else:
        kind = 'binary'
    return _owner.EzvizLocalSdkBodyShape(kind=kind, length=length, printable_ratio=printable / length, null_ratio=nulls / length, high_bit_ratio=high_bit / length, entropy_bits_per_byte=_owner._entropy_bits_per_byte(data), xml_offset=xml_offset, xml_tags=xml_tags)

def parse_ezviz_interleaved_rtp_frame_header(data: bytes, *, _owner: _ModuleType) -> _owner_types.EzvizInterleavedRtpFrameHeader:
    """Parse the 4-byte interleaved RTP prefix from EZVIZ local media.

    The local stream port emits dollar + channel + big-endian length before an
    RTP payload. The RTP payload then carries MPEG-PS data, often beginning
    with an RTP header followed by the MPEG-PS pack header.
    """
    if len(data) < 4:
        raise _owner.PyEzvizError('EZVIZ interleaved RTP header is truncated')
    if data[0] != _owner.EZVIZ_RTP_INTERLEAVED_MAGIC:
        raise _owner.PyEzvizError('EZVIZ interleaved RTP header has invalid magic')
    return _owner.EzvizInterleavedRtpFrameHeader(channel=data[1], payload_length=int.from_bytes(data[2:4], 'big'))

def _parse_local_device_content(value: _owner_types.Any, *, _owner: _ModuleType) -> _owner_types.EzvizLocalDeviceContent | None:
    if value is None or value == '':
        return None
    if isinstance(value, str):
        try:
            data = _owner.json.loads(value)
        except ValueError as err:
            raise _owner.PyEzvizError('Invalid EZVIZ local deviceContent JSON') from err
    elif isinstance(value, _StaticMapping):
        data = value
    else:
        return None
    return _owner.EzvizLocalDeviceContent(device_ip=_owner._mapping_str(data, 'deviceIP'), device_type=_owner._mapping_int(data, 'deviceType', default=None), device_enc_type=_owner._mapping_int(data, 'deviceEncType', default=None), is_low_power=_owner._mapping_int(data, 'isLowPower', default=None), device_max_act_limit=_owner._mapping_int(data, 'deviceMaxActLimit', default=None), device_sdk_version=_owner._mapping_int(data, 'deviceSdkVersion', default=None), device_rand=_owner._mapping_str(data, 'deviceRand'), device_role_type=_owner._mapping_int(data, 'deviceRoleType', default=None))

def _parse_shape_fields(text: str, *, _owner: _ModuleType) -> dict[str, str]:
    fields: dict[str, str] = {}
    for part in text.split():
        if '=' not in part:
            continue
        key, value = part.split('=', 1)
        fields[key] = value.rstrip(',')
    return fields

def _parse_int(value: str | None, *, _owner: _ModuleType) -> int | None:
    if value is None or value == '':
        return None
    try:
        return int(value, 0)
    except ValueError:
        return None

def _parse_float(value: str | None, *, _owner: _ModuleType) -> float | None:
    if value is None or value == '':
        return None
    try:
        return float(value)
    except ValueError:
        return None

def _parse_length_candidates(value: str | None, *, _owner: _ModuleType) -> dict[str, int]:
    if not value:
        return {}
    candidates: dict[str, int] = {}
    for part in value.split(','):
        if '=' not in part:
            continue
        name, raw = part.split('=', 1)
        parsed = _owner._parse_int(raw)
        if parsed is not None:
            candidates[name] = parsed
    return candidates

def _parse_length_candidate_offset(name: str, *, _owner: _ModuleType) -> int | None:
    match = _owner.re.search('@(\\d+)$', name)
    return int(match.group(1)) if match else None

def _probe_port(host: str, port: int, *, timeout: float | None, socket_factory: _owner_types.SocketFactory, _owner: _ModuleType) -> _owner_types.HcNetSdkPortProbe:
    try:
        sock = socket_factory((host, port), timeout)
    except OSError as err:
        return _owner.HcNetSdkPortProbe(port=port, tcp_open=False, error=f'{type(err).__name__}: {err}')
    passive_bytes = b''
    try:
        if timeout is not None:
            sock.settimeout(min(timeout, 1.0))
        try:
            passive_bytes = sock.recv(32)
        except TimeoutError:
            passive_bytes = b''
    finally:
        sock.close()
    tls_accepted: bool | None = None
    tls_error: str | None = None
    try:
        raw_sock = socket_factory((host, port), timeout)
        context = _owner.ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = _owner.ssl.CERT_NONE
        try:
            if timeout is not None:
                raw_sock.settimeout(timeout)
            tls_sock = context.wrap_socket(raw_sock, server_hostname=host)
            tls_accepted = True
            tls_sock.close()
        except (OSError, _owner.ssl.SSLError) as err:
            raw_sock.close()
            tls_accepted = False
            tls_error = f'{type(err).__name__}: {err}'
    except OSError as err:
        tls_accepted = False
        tls_error = f'{type(err).__name__}: {err}'
    return _owner.HcNetSdkPortProbe(port=port, tcp_open=True, tls_accepted=tls_accepted, passive_bytes=passive_bytes, tls_error=tls_error)

def discover_hcnetsdk_stream_details(endpoint: _owner_types.HcNetSdkLanEndpoint, password: str | bytes, *, channel: int, username: str, local_ip: str | None, timeout: float | None, socket_factory: _owner_types.SocketFactory, rsa_key: _owner_types.Any | None, monotonic: _owner_types.Callable[[], float], max_response_bytes: int, _owner: _ModuleType) -> _owner_types.HcNetSdkStreamDetails:
    """Login once and issue native GET1040 and ability8 queries on fresh sockets.

    Supplied credentials only: never renew or retry authentication. The finite
    network deadline covers login and both reads; RSA generation precedes it.
    Native frame-rate/resolution/codec IDs are preserved, not guessed as FPS or
    encryption protocols. Explicit capability-query rejection retains configuration
    with its raw error code; malformed/authentication/network errors propagate.
    """
    if not isinstance(channel, int) or isinstance(channel, bool) or (not 1 <= channel <= 255):
        raise _owner.PyEzvizError('Stream discovery channel must be between 1 and 255')
    if timeout is None or not _owner.math.isfinite(timeout) or timeout <= 0:
        raise _owner.PyEzvizError('Stream discovery requires a positive finite timeout')
    if not isinstance(max_response_bytes, int) or isinstance(max_response_bytes, bool) or max_response_bytes < 16:
        raise _owner.PyEzvizError('Discovery response limit must include the 16-byte header')
    if not password:
        raise _owner.PyEzvizError('Stream discovery requires supplied local credentials')
    key = rsa_key if rsa_key is not None else _owner.hcnetsdk_command_port_rsa_key()
    deadline = monotonic() + timeout
    with _owner.closing(_owner.HcNetSdkCommandPortClient(endpoint, timeout=timeout, socket_factory=socket_factory)) as client:
        sock = client.connect(deadline=deadline, monotonic=monotonic)
        address = local_ip if local_ip is not None else str(sock.getsockname()[0])
        session = client.login(password=password, username=username, local_ip=address, rsa_key=key, max_frame_bytes=max_response_bytes, deadline=deadline, monotonic=monotonic)
        config_template = _owner.hcnetsdk_dvr_config_command_port_template(_owner.ezviz_lan_video_coding_get_config_request(1, channel))
        ability_template = _owner.hcnetsdk_device_ability_command_port_template(_owner.ezviz_lan_audio_video_compress_info_ability_request(1, channel))
        config = _owner._hcnetsdk_stream_details_query(endpoint, config_template, session, address, timeout, socket_factory, deadline, monotonic, max_response_bytes)
        configuration = _owner.ezviz_lan_compression_config(config.body)
        ability = _owner._hcnetsdk_stream_details_query(endpoint, ability_template, session, address, timeout, socket_factory, deadline, monotonic, max_response_bytes)
        capabilities_error = None
        if not ability.body and ability.header.field_4 == ability.header.field_8 and (ability.header.field_8 not in (0, 1)):
            capabilities_error = ability.header.field_8
            capabilities = _owner.EzvizLanAudioVideoCompressInfo()
        else:
            capabilities = _owner.ezviz_lan_audio_video_compress_info(_owner.hcnetsdk_command_port_response_payload(ability))
            if not capabilities.success:
                raise _owner.PyEzvizError('Camera did not return audio/video compression capabilities')
        if monotonic() >= deadline:
            raise _owner.EzvizLocalSdkDeadlineExpired('Camera stream discovery exhausted its deadline')
        return _owner.HcNetSdkStreamDetails(channel, configuration, capabilities, session.serial, capabilities_error)

def discover_hcnetsdk_stream_details_for_login(endpoint: _owner_types.HcNetSdkLanEndpoint, login: _owner_types.HcNetSdkLoginCandidate, *, tls_context: _owner_types.ssl.SSLContext | None, channel: int, timeout: float, socket_factory: _owner_types.SocketFactory, rsa_key: _owner_types.Any | None, monotonic: _owner_types.Callable[[], float], max_response_bytes: int, _owner: _ModuleType) -> _owner_types.HcNetSdkStreamDetails:
    """Query one explicit native login profile, never enumerate or renew secrets.

    HTTPSV40 means the native binary SDK over TLS, not HTTP/ISAPI. Default TLS
    verifies certificates; private CA/self-signed handling belongs to a supplied
    SSLContext. TCP and TLS handshake share each connection's remaining budget.
    Authentication rejection propagates without a second credential/profile.
    """
    if login.api not in {'NET_DVR_Login_V30', 'NET_DVR_Login_V40'}:
        raise _owner.PyEzvizError('Unsupported native stream discovery login profile')
    if isinstance(login.port, bool) or not 1 <= login.port <= 65535:
        raise _owner.PyEzvizError('Native stream discovery login port is invalid')
    if login.https and login.api != 'NET_DVR_Login_V40':
        raise _owner.PyEzvizError('TLS stream discovery requires the native V40 profile')
    selected_factory = socket_factory
    if login.https:
        context = tls_context if tls_context is not None else _owner.ssl.create_default_context()

        def connect_tls(address: tuple[str, int], budget: float | None) -> _owner_types.Any:
            started = monotonic()
            raw = socket_factory(address, budget)
            try:
                remaining = None if budget is None else budget - (monotonic() - started)
                if remaining is not None and remaining <= 0:
                    raise _owner.EzvizLocalSdkDeadlineExpired('Native discovery TLS deadline exhausted')
                raw.settimeout(remaining)
                return context.wrap_socket(raw, server_hostname=address[0])
            except BaseException:
                raw.close()
                raise
        selected_factory = connect_tls
    elif tls_context is not None:
        raise _owner.PyEzvizError('TLS context supplied for a plain native login profile')
    return _owner.discover_hcnetsdk_stream_details(_owner.replace(endpoint, command_port=login.port), login.password, username=login.username, channel=channel, timeout=timeout, socket_factory=selected_factory, rsa_key=rsa_key, monotonic=monotonic, max_response_bytes=max_response_bytes)
