# Runtime hooks deliberately resolve through their legacy owner.
# ruff: noqa: SLF001
# Model defaults depend only on the SDK constants leaf.
# ruff: noqa: E402, I001, SLF001
from __future__ import annotations
from pyezvizapi.streaming.local.hcnetsdk import constants as _constants
"""models session implementation; legacy runtime hooks remain on the owner module.

Access through _owner is deliberate: callers that patch the compatibility
module must still affect dependent operations. No copied hook snapshots.
"""

@_constants.dataclass(frozen=True)
class HcNetSdkLoginCandidate:
    """One LAN login mode observed in the EZVIZ Android app."""
    username: str
    password: str = _constants.field(repr=False)
    port: int
    api: str
    https: bool = False

@_constants.dataclass(frozen=True)
class HcNetSdkSetSdkLocalCfgRequest:
    """Native ``NET_DVR_SetSDKLocalCfg`` request shape."""
    cfg_type: int
    structure: str
    field_updates: _owner.Mapping[str, _owner.Any] | None = None
    field_order: tuple[str, ...] | None = None
    api: str = _constants.HCNETSDK_SET_SDK_LOCAL_CFG

    def to_native_args_hint(self) -> dict[str, _owner.Any]:
        """Return native argument names for SDK-process local config."""
        if self.cfg_type < 0:
            raise _owner.PyEzvizError('HCNetSDK local config type must be non-negative')
        if not self.structure or any(char.isspace() for char in self.structure):
            raise _owner.PyEzvizError('HCNetSDK local config structure name is invalid')
        if self.api != _owner.HCNETSDK_SET_SDK_LOCAL_CFG:
            raise _owner.PyEzvizError('HCNetSDK local config API is unsupported')
        hint: dict[str, _owner.Any] = {'api': self.api, 'enumType': int(self.cfg_type), 'lpInBuff': f'<{self.structure}>', 'structure': self.structure, 'fieldUpdates': dict(self.field_updates or {})}
        if self.field_order is not None:
            hint['fieldOrder'] = self.field_order
        return hint

@_constants.dataclass(frozen=True)
class HcNetSdkTcpPayloadShape:
    """Secret-safe classification for raw HCNetSDK command-port bytes."""
    kind: str
    length: int
    printable_ratio: float
    null_ratio: float
    high_bit_ratio: float
    entropy_bits_per_byte: float
    u32be_0: int | None = None
    u32le_0: int | None = None
    u32be_4: int | None = None
    u32le_4: int | None = None
    u32be_8: int | None = None
    u32le_8: int | None = None
    u32be_12: int | None = None
    u32le_12: int | None = None
    u16be_0: int | None = None
    u16le_0: int | None = None
    declared_length_offset: int | None = None
    declared_length: int | None = None
    xml_offset: int | None = None
    xml_tags: tuple[str, ...] = ()

@_constants.dataclass(frozen=True)
class HcNetSdkTcpFrameHeader:
    """Observed 16-byte HCNetSDK command-port packet header.

    A direct-local trace showed command replies arriving as a 16-byte header with
    the first big-endian word equal to the total frame length, followed by a
    body read of ``total_length - 16`` bytes. The remaining words are kept as
    opaque fields until more traces prove their semantics.
    """
    total_length: int
    field_4: int
    field_8: int
    field_12: int

    @property
    def body_length(self) -> int:
        """Return body length implied by the observed total-length word."""
        return self.total_length - _owner.HCNETSDK_TCP_HEADER_LENGTH

    def to_bytes(self) -> bytes:
        """Serialize the non-secret header fields using observed endianness."""
        return b''.join((self.total_length.to_bytes(4, 'big'), self.field_4.to_bytes(4, 'big'), self.field_8.to_bytes(4, 'big'), self.field_12.to_bytes(4, 'big')))

@_constants.dataclass(frozen=True)
class HcNetSdkTcpFrame:
    """One complete HCNetSDK command-port frame."""
    header: HcNetSdkTcpFrameHeader
    body: bytes = b''

    def to_bytes(self) -> bytes:
        """Serialize the observed frame header and body."""
        if self.header.body_length != len(self.body):
            raise _owner.PyEzvizError('HCNetSDK TCP frame header/body length mismatch')
        return self.header.to_bytes() + self.body

@_constants.dataclass(frozen=True)
class HcNetSdkCommandPortExchange:
    """One command-port request and its optional response."""
    request: bytes
    response: HcNetSdkTcpFrame | None = None

@_constants.dataclass(frozen=True)
class HcNetSdkCommandPortStreamBootstrap:
    """Result of a command-port stream bootstrap."""
    exchanges: tuple[HcNetSdkCommandPortExchange, ...]
    first_media: EzvizInterleavedRtpFrameWithPrefix | None = None

@_constants.dataclass(frozen=True)
class HcNetSdkCommandPortLoginChallenge:
    """Decoded first-stage command-port login challenge."""
    response: HcNetSdkTcpFrame
    challenge: bytes
    password_seed: bytes

@_constants.dataclass(frozen=True)
class HcNetSdkCommandPortLoginSession:
    """Successful generated port-8000 login session."""
    session_id: bytes
    auth_seed: int
    serial: str
    first_response: HcNetSdkTcpFrame
    second_response: HcNetSdkTcpFrame
    challenge: bytes = b''
    password_seed: bytes = b''

@_constants.dataclass(frozen=True)
class HcNetSdkCommandPortControlResponse:
    """Pure-Python response from one generated command-port control request."""
    login_session: HcNetSdkCommandPortLoginSession
    request: bytes
    response: HcNetSdkTcpFrame

    @property
    def output(self) -> bytes:
        """Return the textual payload carried by the command-port response."""
        return _owner.hcnetsdk_command_port_response_payload(self.response)

    @property
    def text(self) -> str:
        """Decode the textual response payload as UTF-8."""
        return self.output.decode('utf-8')

@_constants.dataclass(frozen=True)
class HcNetSdkCommandPortControlTemplate:
    """Reusable post-login command-port control frame template."""
    command_id: int
    body_tail: bytes = b''
    addend: int | None = None
    addend_delta: int | None = None
    mask_seed: bytes = b'\x00' * _constants.HCNETSDK_COMMAND_PORT_AUTH_MASK_LENGTH
    body_tail_transform: str | None = None
    name: str | None = None

    def __post_init__(self) -> None:
        if self.addend is not None and self.addend_delta is not None:
            raise _owner.PyEzvizError('HCNetSDK command-port template cannot set addend and addend_delta')
        if self.body_tail_transform is not None and self.body_tail_transform != _owner.HCNETSDK_COMMAND_PORT_PLAY_LOGIN_TODAY_TRANSFORM:
            raise _owner.PyEzvizError(f'Unsupported HCNetSDK command-port body_tail_transform: {self.body_tail_transform}')

    def to_frame(self, *, session_id: bytes, auth_seed: int, key: bytes, local_ip: str, addend: int | None=None) -> bytes:
        """Build this template with fresh login/session values."""
        template_addend = self.addend
        if template_addend is None and self.addend_delta is not None:
            template_addend = int.from_bytes(session_id, 'big') + self.addend_delta & 4294967295
        body_tail = self.body_tail
        if self.body_tail_transform == _owner.HCNETSDK_COMMAND_PORT_PLAY_LOGIN_TODAY_TRANSFORM:
            body_tail = _owner.hcnetsdk_command_port_play_login_body_tail_for_today(body_tail)
        return _owner.hcnetsdk_command_port_control_frame(session_id=session_id, auth_seed=auth_seed, command_id=self.command_id, key=key, local_ip=local_ip, body_tail=body_tail, addend=template_addend if addend is None else addend, mask_seed=self.mask_seed)

@_constants.dataclass(frozen=True)
class HcNetSdkTcpFrameShape:
    """One HCNetSDK command-port frame reconstructed from redacted log shapes."""
    direction: str
    fd: int
    host: str
    port: int
    total_length: int
    header_shape: HcNetSdkTcpPayloadShape
    body_shape: HcNetSdkTcpPayloadShape | None = None

    @property
    def body_length(self) -> int:
        """Return body length implied by the observed 16-byte header."""
        return self.total_length - _owner.HCNETSDK_TCP_HEADER_LENGTH

    @property
    def write_command_candidate(self) -> int | None:
        """Return the observed client-write command candidate when present.

        Fresh direct-local traces show HCNetSDK client writes with a big-endian total
        length at offset 0 and a small little-endian word at offset 4. That word
        was 90 for the initial encrypted login exchange and 99 for several
        follow-up capability/control requests. Keep it as a candidate until
        more devices prove the semantics.
        """
        if self.direction not in {'send', 'write'}:
            return None
        return self.header_shape.u32le_4

    @property
    def write_command_role(self) -> str | None:
        """Return the current semantic label for an observed write candidate."""
        return _owner.hcnetsdk_command_candidate_role(self.write_command_candidate)

@_constants.dataclass(frozen=True)
class EzvizLanPlayDeviceLogin:
    """Player-owned HCNetSDK login step used before LAN native preview starts."""
    endpoint: _owner.HcNetSdkLanEndpoint
    check_last_login_status: bool = False
    api: str = _constants.EZVIZ_DEVICE_INFO_EX_LOGIN_PLAY_DEVICE
    facade_api: str = _constants.EZVIZ_PLAY_DATA_INFO_LOGIN_PLAY_DEVICE

    def to_device_param_hint(self) -> dict[str, int | str]:
        """Return the non-secret DeviceParam fields relevant to this login."""
        return {'serial': self.endpoint.serial, 'deviceLocalIp': self.endpoint.host, 'localCmdPort': self.endpoint.command_port, 'localStreamPort': self.endpoint.stream_port or 0}

@_constants.dataclass(frozen=True)
class EzvizLanPreviewPlan:
    """APK-observed LAN preview flow around HCNetSDK login and EZ stream start."""
    login_candidates: tuple[HcNetSdkLoginCandidate, ...]
    live_view: _owner.EzvizLanLiveViewParams
    play_device_login: EzvizLanPlayDeviceLogin | None = None
    create_client_api: str = _constants.EZVIZ_NATIVE_CREATE_CLIENT
    start_preview_api: str = _constants.EZVIZ_NATIVE_START_PREVIEW

    @property
    def real_play_request(self) -> _owner.HcNetSdkRealPlayRequest | None:
        """Return the HCNetSDK real-play call shape once login is available."""
        if self.live_view.netsdk_login_id < 0:
            return None
        return self.live_view.to_real_play_request()

    @property
    def post_start_keyframe_request(self) -> _owner.EzvizLanKeyframeRequest | None:
        """Return the HCNetSDK keyframe request made after native preview start."""
        if self.live_view.netsdk_login_id < 0:
            return None
        channel_number = self.live_view.netsdk_channel_number
        if channel_number is None:
            return None
        if self.live_view.stream_type == 2:
            api = _owner.HCNETSDK_MAKE_KEYFRAME_SUB
        else:
            api = _owner.HCNETSDK_MAKE_KEYFRAME_MAIN
        return _owner.EzvizLanKeyframeRequest(api=api, netsdk_login_id=self.live_view.netsdk_login_id, netsdk_channel_number=channel_number)

    @property
    def post_start_keyframe_api(self) -> str | None:
        """Return the HCNetSDK keyframe API name made after preview start."""
        request = self.post_start_keyframe_request
        return None if request is None else request.api

    def native_call_sequence(self) -> tuple[str, ...]:
        """Return the native call sequence observed for LAN live preview."""
        calls = []
        if self.play_device_login is not None:
            calls.append(self.play_device_login.api)
        calls.extend([self.create_client_api, self.start_preview_api])
        if self.post_start_keyframe_request:
            calls.append(self.post_start_keyframe_request.api)
        return tuple(calls)

@_constants.dataclass(frozen=True)
class EzvizLocalDeviceContent:
    """Decoded ``deviceContent`` for app-managed EZVIZ LAN devices."""
    device_ip: str | None = None
    device_type: int | None = None
    device_enc_type: int | None = None
    is_low_power: int | None = None
    device_max_act_limit: int | None = None
    device_sdk_version: int | None = None
    device_rand: str | None = None
    device_role_type: int | None = None

@_constants.dataclass(frozen=True)
class EzvizLocalDevice:
    """Local-device record shape used by the EZVIZ app and cloud API."""
    serial: str
    name: str | None = None
    model: str | None = None
    category: str | None = None
    device_category: str | None = None
    group_id: int | None = None
    content: EzvizLocalDeviceContent | None = None
    raw: _owner.Mapping[str, _owner.Any] | None = None

    @property
    def endpoint(self) -> _owner.HcNetSdkLanEndpoint | None:
        """Return a minimal HCNetSDK endpoint if the local payload has an IP."""
        if self.content is None or not self.content.device_ip:
            return None
        return _owner.HcNetSdkLanEndpoint(serial=self.serial, host=self.content.device_ip)

@_constants.dataclass(frozen=True)
class EzvizCasDeviceInfo:
    """CAS device-info tuple used by the EZVIZ native direct-local path.

    APK/native tracing showed CasDeviceInfo.key is copied into EZ_DEV_INFO.szKey
    and ultimately used as the AES-128 key for local SDK control frames. The
    direct-local ``9010/9020`` path uses the app-shaped local SDK SSL-like
    IV for control-frame encryption and appends a 32-byte lowercase MD5 hex
    digest of the ciphertext. ``deviceSerial + operationCode`` remains exposed
    for older CAS helpers and compatibility checks.
    """
    serial: str
    operation_code: str
    key: str
    encrypt_type: int | None = None

    @property
    def key_bytes(self) -> bytes:
        """Return the local-control AES key bytes, validating its size."""
        return _owner._local_sdk_aes_bytes('key', self.key)

    @property
    def iv_bytes(self) -> bytes:
        """Return the local-control AES IV bytes derived from CAS metadata."""
        return _owner.ezviz_local_sdk_iv(self.serial, self.operation_code)

@_constants.dataclass(frozen=True)
class HcNetSdkPortProbe:
    """Non-authenticated classification result for one LAN port."""
    port: int
    tcp_open: bool
    tls_accepted: bool | None = None
    passive_bytes: bytes = b''
    error: str | None = None
    tls_error: str | None = None

@_constants.dataclass(frozen=True)
class EzvizLocalSdkFrameHeader:
    """Header for EZVIZ local SDK XML/framed control messages."""
    magic: bytes
    version: int
    sequence: int
    marker: int
    command: int
    status: int
    body_length: int
    reserved: int

@_constants.dataclass(frozen=True)
class EzvizLocalSdkFrame:
    """One EZVIZ local SDK control frame with an optional XML body."""
    header: EzvizLocalSdkFrameHeader
    body: bytes = b''
    trailer: bytes = b''

@_constants.dataclass(frozen=True)
class EzvizLocalSdkBodyShape:
    """Secret-safe body classification for EZVIZ local SDK frames."""
    kind: str
    length: int
    printable_ratio: float
    null_ratio: float
    high_bit_ratio: float
    entropy_bits_per_byte: float
    xml_offset: int | None = None
    xml_tags: tuple[str, ...] = ()

@_constants.dataclass(frozen=True)
class EzvizInterleavedRtpFrameHeader:
    """RTSP-style interleaved RTP frame prefix used on the EZVIZ stream port."""
    channel: int
    payload_length: int

@_constants.dataclass(frozen=True)
class EzvizInterleavedRtpFrame:
    """One interleaved RTP frame read from an EZVIZ local stream socket."""
    header: EzvizInterleavedRtpFrameHeader
    payload: bytes

@_constants.dataclass(frozen=True)
class EzvizInterleavedRtpFrameWithPrefix:
    """First RTP frame plus any binary preface emitted before it."""
    prefix: bytes
    frame: EzvizInterleavedRtpFrame

@_constants.dataclass(frozen=True)
class EzvizLocalSdkExchange:
    """One encrypted local SDK request and parsed response frame."""
    request: bytes
    response: EzvizLocalSdkFrame

@_constants.dataclass(frozen=True)
class EzvizLocalSdkStreamBootstrap:
    """Result of the direct-local preview setup sequence."""
    preview: EzvizLocalSdkExchange
    stream_setup: EzvizLocalSdkExchange
    pre_start: EzvizLocalSdkExchange | None = None
    first_media: EzvizInterleavedRtpFrameWithPrefix | None = None

    @property
    def stream_header(self) -> _owner.EzvizStreamHeader | None:
        """Return camera-negotiated media fields without session/auth data."""
        return _owner.stream_header_from_preview(self.preview.response.body)

@_constants.dataclass(frozen=True)
class EzvizLocalReceiverInfo:
    """Structured receiver fields for the native local preview setup request."""
    nat_address: str = ''
    nat_port: int = 0
    upnp_address: str = ''
    upnp_port: int = 0
    inner_address: str = ''
    inner_port: int = 0
    stream_type: str = 'MAIN'

    def xml_lines(self, *, indent: str='\t') -> tuple[str, ...]:
        """Build the nested ``ReceiverInfo`` XML lines."""
        for name, port_value in (('nat_port', self.nat_port), ('upnp_port', self.upnp_port), ('inner_port', self.inner_port)):
            if port_value < 0:
                raise _owner.PyEzvizError(f'EZVIZ local receiver {name} must be non-negative')
        fields: tuple[tuple[str, str | int | None], ...] = (('NatAddress', self.nat_address), ('NatPort', self.nat_port), ('UPnPAddress', self.upnp_address), ('UPnPPort', self.upnp_port), ('InnerAddress', self.inner_address), ('InnerPort', self.inner_port), ('StreamType', self.stream_type))
        lines = [f'{indent}<ReceiverInfo>']
        for tag, value in fields:
            lines.append(f'{indent}\t<{tag}>{_owner._xml_escape(str(value))}</{tag}>')
        lines.append(f'{indent}</ReceiverInfo>')
        return tuple(lines)

@_constants.dataclass(frozen=True)
class EzvizLocalReceiverInfoEx:
    """Structured extended receiver-auth fields for the local preview request."""
    uuid: str | None = None
    timestamp: str | int | None = None

    def xml_lines(self, *, indent: str='\t') -> tuple[str, ...]:
        """Build the nested ``ReceiverInfoEx`` XML lines."""
        lines = [f'{indent}<ReceiverInfoEx>']
        if self.uuid is not None or self.timestamp is not None:
            lines.append(f'{indent}\t<Authentication>')
            for tag, value in (('Uuid', self.uuid), ('Timestamp', self.timestamp)):
                if value is not None:
                    lines.append(f'{indent}\t\t<{tag}>{_owner._xml_escape(str(value))}</{tag}>')
            lines.append(f'{indent}\t</Authentication>')
        lines.append(f'{indent}</ReceiverInfoEx>')
        return tuple(lines)

@_constants.dataclass(frozen=True)
class EzvizLocalReceiverInfoAttrs:
    """App-shaped ``ReceiverInfo`` attributes for direct-local preview setup."""
    address: str = ''
    port: int = 10101
    server_type: int = 1
    stream_type: str = 'MAIN'
    new_stream_type: int = 1
    trans_proto: str = 'TCP'

    def xml_lines(self, *, indent: str='\t') -> tuple[str, ...]:
        """Build the observed self-closing app ``ReceiverInfo`` tag."""
        if self.port < 0:
            raise _owner.PyEzvizError('EZVIZ local receiver port must be non-negative')
        attrs = (('Address', self.address), ('Port', self.port), ('ServerType', self.server_type), ('StreamType', self.stream_type), ('NewStreamType', self.new_stream_type), ('TransProto', self.trans_proto))
        return (f'{indent}<ReceiverInfo {_owner._xml_attrs(attrs)} />',)

@_constants.dataclass(frozen=True)
class EzvizLocalReceiverInfoExAttrs:
    """App-shaped ``ReceiverInfoEx`` attributes for direct-local preview setup."""
    session_id: str = ''
    port: int = 10101

    def xml_lines(self, *, indent: str='\t') -> tuple[str, ...]:
        """Build the observed self-closing app ``ReceiverInfoEx`` tag."""
        if self.port < 0:
            raise _owner.PyEzvizError('EZVIZ local receiver ex port must be non-negative')
        return (f"{indent}<ReceiverInfoEx {_owner._xml_attrs((('SessionID', self.session_id), ('Port', self.port)))} />",)

@_constants.dataclass(frozen=True)
class EzvizLocalAuthenticationAttrs:
    """App-shaped authentication attributes for direct-local preview setup."""
    ticket: str = ''
    biz_code: str = 'biz=1'
    interval: int = 180

    def xml_lines(self, *, indent: str='\t') -> tuple[str, ...]:
        """Build the observed self-closing app ``Authentication`` tag."""
        if self.interval < 0:
            raise _owner.PyEzvizError('EZVIZ local authentication interval must be non-negative')
        attrs = (('Ticket', self.ticket), ('BizCode', self.biz_code), ('Interval', self.interval))
        return (f'{indent}<Authentication {_owner._xml_attrs(attrs)} />',)

@_constants.dataclass(frozen=True)
class EzvizLocalPreviewRequest:
    """Plaintext field set for the observed 0x2011 preview request."""
    operation_code: str
    channel: int
    receiver_info: str | EzvizLocalReceiverInfo | EzvizLocalReceiverInfoAttrs
    receiver_info_ex: str | EzvizLocalReceiverInfoEx | EzvizLocalReceiverInfoExAttrs
    identifier: str | None = None
    is_encrypt: str | int = 'TRUE'
    udt: int | None = None
    nat: int | None = None
    port_guess_type: int | None = None
    timeout: int | None = None
    heartbeat_interval: int | None = None
    authentication: str | EzvizLocalAuthenticationAttrs | None = None
    uuid: str | None = None
    timestamp: str | int | None = None
    public_key: str | None = None

    def to_xml(self) -> bytes:
        """Build a caller-owned XML body for the encrypted preview request."""
        return _owner.build_ezviz_local_preview_request_body(operation_code=self.operation_code, channel=self.channel, receiver_info=self.receiver_info, receiver_info_ex=self.receiver_info_ex, identifier=self.identifier, is_encrypt=self.is_encrypt, udt=self.udt, nat=self.nat, port_guess_type=self.port_guess_type, timeout=self.timeout, heartbeat_interval=self.heartbeat_interval, authentication=self.authentication, uuid=self.uuid, timestamp=self.timestamp, public_key=self.public_key)

@_constants.dataclass(frozen=True)
class SadpDeviceInfo:
    """Parsed SADP response fields."""
    fields: _owner.Mapping[str, str]

    @property
    def serial(self) -> str | None:
        """Return a likely device serial field if present."""
        return self.fields.get('DeviceSN') or self.fields.get('SerialNO')

    @property
    def ipv4_address(self) -> str | None:
        """Return the SADP IPv4 address field if present."""
        return self.fields.get('IPv4Address') or self.fields.get('IPAddress')

    @property
    def command_port(self) -> int | None:
        """Return the SDK command/server port if SADP reported one."""
        value = self.fields.get('CommandPort') or self.fields.get('DevicePort') or self.fields.get('Port')
        return int(value) if value and value.isdigit() else None

# Late owner reference preserves legacy model hook and annotation resolution.
import pyezvizapi.streaming.local.hcnetsdk.protocol as _owner
