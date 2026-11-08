"""preview protocol values and pure helpers; dependency-closed implementation."""

from __future__ import annotations

from pyezvizapi.streaming.local.hcnetsdk.constants import (
    EZVIZ_DEVICE_INFO_EX_LOGIN_PLAY_DEVICE,
    EZVIZ_LAN_MAIN_VIDEO_LEVEL,
    EZVIZ_NATIVE_CREATE_CLIENT,
    EZVIZ_NATIVE_START_PREVIEW,
    EZVIZ_PLAY_DATA_INFO_LOGIN_PLAY_DEVICE,
    EZVIZ_PREPLAY_SPS_TYPE,
    EZVIZ_STREAM_INHIBIT_LAN,
    EZVIZ_STREAM_SOURCE_LIVE_MINE,
    EZVIZ_STREAM_TIMEOUT_MS,
    HCNETSDK_MAKE_KEYFRAME_MAIN,
    HCNETSDK_MAKE_KEYFRAME_SUB,
    HCNETSDK_REALDATA_CALLBACK_V30,
    HCNETSDK_REALPLAY_V30,
    HCNETSDK_SET_SDK_LOCAL_CFG,
    Any,
    Iterable,
    Mapping,
    PyEzvizError,
    dataclass,
)
from pyezvizapi.streaming.local.hcnetsdk.protocol_types.endpoints import (
    HcNetSdkLanEndpoint,
    HcNetSdkLoginCandidate,
)


@dataclass(frozen=True)
class HcNetSdkSetSdkLocalCfgRequest:
    """Native ``NET_DVR_SetSDKLocalCfg`` request shape."""

    cfg_type: int
    structure: str
    field_updates: Mapping[str, Any] | None = None
    field_order: tuple[str, ...] | None = None
    api: str = HCNETSDK_SET_SDK_LOCAL_CFG

    def to_native_args_hint(self) -> dict[str, Any]:
        """Return native argument names for SDK-process local config."""
        if self.cfg_type < 0:
            raise PyEzvizError("HCNetSDK local config type must be non-negative")
        if not self.structure or any(char.isspace() for char in self.structure):
            raise PyEzvizError("HCNetSDK local config structure name is invalid")
        if self.api != HCNETSDK_SET_SDK_LOCAL_CFG:
            raise PyEzvizError("HCNetSDK local config API is unsupported")
        hint: dict[str, Any] = {
            "api": self.api,
            "enumType": int(self.cfg_type),
            "lpInBuff": f"<{self.structure}>",
            "structure": self.structure,
            "fieldUpdates": dict(self.field_updates or {}),
        }
        if self.field_order is not None:
            hint["fieldOrder"] = self.field_order
        return hint


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


@dataclass(frozen=True)
class HcNetSdkClientInfo:
    """Python model of the Java/native ``NET_DVR_CLIENTINFO`` preview input."""

    channel: int = 1
    link_mode: int = 0
    multicast_ip: str = ""

    def to_native_dict(self) -> dict[str, int | str]:
        """Return the field names from the APK's ``NET_DVR_CLIENTINFO`` class."""
        if self.channel < 0:
            raise PyEzvizError("HCNetSDK client channel must be non-negative")
        if self.link_mode < 0:
            raise PyEzvizError("HCNetSDK client link mode must be non-negative")
        return {
            "lChannel": self.channel,
            "lLinkMode": self.link_mode,
            "sMultiCastIP": self.multicast_ip,
        }


@dataclass(frozen=True)
class HcNetSdkRealPlayRequest:
    """Arguments needed for ``EZ_NET_DVR_RealPlay_V30`` plus callback metadata."""

    login_id: int
    client_info: HcNetSdkClientInfo
    blocked: bool = False
    callback_api: str = HCNETSDK_REALDATA_CALLBACK_V30
    api: str = HCNETSDK_REALPLAY_V30

    def to_native_args_hint(self) -> dict[str, int | str | dict[str, int | str]]:
        """Return a serializable hint for HCNetSDK-compatible real-play calls."""
        if self.login_id < 0:
            raise PyEzvizError("HCNetSDK real-play requires a successful login id")
        return {
            "api": self.api,
            "login_id": self.login_id,
            "client_info": self.client_info.to_native_dict(),
            "callback": self.callback_api,
            "blocked": int(self.blocked),
        }


def hcnetsdk_real_play_request(
    login_id: int,
    *,
    channel_number: int = 1,
    link_mode: int = 0,
    blocked: bool = False,
    multicast_ip: str = "",
) -> HcNetSdkRealPlayRequest:
    """Build the APK-observed ``EZ_NET_DVR_RealPlay_V30`` argument model."""
    return HcNetSdkRealPlayRequest(
        login_id=login_id,
        client_info=HcNetSdkClientInfo(
            channel=channel_number,
            link_mode=link_mode,
            multicast_ip=multicast_ip,
        ),
        blocked=blocked,
    )


@dataclass(frozen=True)
class EzvizLanLiveViewParams:
    """Relevant EZVIZ player init fields for ``PlayerDataType.LAN`` live view."""

    serial: str
    channel_number: int
    channel_serial: str | None = None
    channel_index: str | None = None
    channel_count: int | None = None
    stream_source: int = EZVIZ_STREAM_SOURCE_LIVE_MINE
    stream_type: int = 1
    video_level: int = EZVIZ_LAN_MAIN_VIDEO_LEVEL
    stream_inhibit: int = EZVIZ_STREAM_INHIBIT_LAN
    stream_timeout_ms: int = EZVIZ_STREAM_TIMEOUT_MS
    preplay_sps_type: int = EZVIZ_PREPLAY_SPS_TYPE
    device_ip: str | None = None
    device_local_ip: str | None = None
    device_cmd_port: int | None = None
    device_cmd_local_port: int | None = None
    device_stream_local_port: int | None = None
    device_stream_port: int | None = None
    netsdk_login_id: int = -1
    netsdk_channel_number: int | None = None

    def to_init_param_dict(self) -> dict[str, int | str]:
        """Return the native ``InitParam`` field names observed in the APK."""
        data: dict[str, int | str] = {
            "szDevSerial": self.serial,
            "szChnlSerial": self.channel_serial or self.serial,
            "szChnlIndex": self.channel_index or "",
            "szDevIP": self.device_ip or "",
            "szDevLocalIP": self.device_local_ip or "",
            "iDevCmdPort": self.device_cmd_port or 0,
            "iDevCmdLocalPort": self.device_cmd_local_port or 0,
            "iDevStreamPort": self.device_stream_port or 0,
            "iDevStreamLocalPort": self.device_stream_local_port or 0,
            "iChannelCount": self.channel_count or 0,
            "iP2PSPS": self.preplay_sps_type,
            "iStreamInhibit": self.stream_inhibit,
            "iStreamSource": self.stream_source,
            "iStreamType": self.stream_type,
            "iStreamTimeOut": self.stream_timeout_ms,
            "iVideoLevel": ezviz_native_video_level(self.video_level),
            "iChannelNumber": self.channel_number,
            "iNetSDKUserId": self.netsdk_login_id,
        }
        if self.netsdk_channel_number is not None:
            data["iNetSDKChannelNumber"] = self.netsdk_channel_number
        return data

    def to_real_play_request(
        self,
        *,
        link_mode: int = 0,
        blocked: bool = False,
        multicast_ip: str = "",
    ) -> HcNetSdkRealPlayRequest:
        """Return the direct HCNetSDK ``RealPlay_V30`` request shape."""
        return hcnetsdk_real_play_request(
            self.netsdk_login_id,
            channel_number=self.netsdk_channel_number or self.channel_number,
            link_mode=link_mode,
            blocked=blocked,
            multicast_ip=multicast_ip,
        )


@dataclass(frozen=True)
class EzvizLanKeyframeRequest:
    """HCNetSDK I-frame request made after LAN native preview starts."""

    api: str
    netsdk_login_id: int
    netsdk_channel_number: int


@dataclass(frozen=True)
class EzvizLanPlayDeviceLogin:
    """Player-owned HCNetSDK login step used before LAN native preview starts."""

    endpoint: HcNetSdkLanEndpoint
    check_last_login_status: bool = False
    api: str = EZVIZ_DEVICE_INFO_EX_LOGIN_PLAY_DEVICE
    facade_api: str = EZVIZ_PLAY_DATA_INFO_LOGIN_PLAY_DEVICE

    def to_device_param_hint(self) -> dict[str, int | str]:
        """Return the non-secret DeviceParam fields relevant to this login."""
        return {
            "serial": self.endpoint.serial,
            "deviceLocalIp": self.endpoint.host,
            "localCmdPort": self.endpoint.command_port,
            "localStreamPort": self.endpoint.stream_port or 0,
        }


@dataclass(frozen=True)
class EzvizLanPreviewPlan:
    """APK-observed LAN preview flow around HCNetSDK login and EZ stream start."""

    login_candidates: tuple[HcNetSdkLoginCandidate, ...]
    live_view: EzvizLanLiveViewParams
    play_device_login: EzvizLanPlayDeviceLogin | None = None
    create_client_api: str = EZVIZ_NATIVE_CREATE_CLIENT
    start_preview_api: str = EZVIZ_NATIVE_START_PREVIEW

    @property
    def real_play_request(self) -> HcNetSdkRealPlayRequest | None:
        """Return the HCNetSDK real-play call shape once login is available."""
        if self.live_view.netsdk_login_id < 0:
            return None
        return self.live_view.to_real_play_request()

    @property
    def post_start_keyframe_request(self) -> EzvizLanKeyframeRequest | None:
        """Return the HCNetSDK keyframe request made after native preview start."""
        if self.live_view.netsdk_login_id < 0:
            return None
        channel_number = self.live_view.netsdk_channel_number
        if channel_number is None:
            return None
        if self.live_view.stream_type == 2:
            api = HCNETSDK_MAKE_KEYFRAME_SUB
        else:
            api = HCNETSDK_MAKE_KEYFRAME_MAIN
        return EzvizLanKeyframeRequest(
            api=api,
            netsdk_login_id=self.live_view.netsdk_login_id,
            netsdk_channel_number=channel_number,
        )

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


@dataclass(frozen=True)
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


@dataclass(frozen=True)
class EzvizLocalDevice:
    """Local-device record shape used by the EZVIZ app and cloud API."""

    serial: str
    name: str | None = None
    model: str | None = None
    category: str | None = None
    device_category: str | None = None
    group_id: int | None = None
    content: EzvizLocalDeviceContent | None = None
    raw: Mapping[str, Any] | None = None

    @property
    def endpoint(self) -> HcNetSdkLanEndpoint | None:
        """Return a minimal HCNetSDK endpoint if the local payload has an IP."""
        if self.content is None or not self.content.device_ip:
            return None
        return HcNetSdkLanEndpoint(serial=self.serial, host=self.content.device_ip)


@dataclass(frozen=True)
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


@dataclass(frozen=True)
class EzvizLocalSdkFrame:
    """One EZVIZ local SDK control frame with an optional XML body."""

    header: EzvizLocalSdkFrameHeader
    body: bytes = b""
    trailer: bytes = b""


@dataclass(frozen=True)
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


@dataclass(frozen=True)
class EzvizLocalSdkExchange:
    """One encrypted local SDK request and parsed response frame."""

    request: bytes
    response: EzvizLocalSdkFrame


def _xml_escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


@dataclass(frozen=True)
class EzvizLocalReceiverInfo:
    """Structured receiver fields for the native local preview setup request."""

    nat_address: str = ""
    nat_port: int = 0
    upnp_address: str = ""
    upnp_port: int = 0
    inner_address: str = ""
    inner_port: int = 0
    stream_type: str = "MAIN"

    def xml_lines(self, *, indent: str = "\t") -> tuple[str, ...]:
        """Build the nested ``ReceiverInfo`` XML lines."""
        for name, port_value in (
            ("nat_port", self.nat_port),
            ("upnp_port", self.upnp_port),
            ("inner_port", self.inner_port),
        ):
            if port_value < 0:
                raise PyEzvizError(f"EZVIZ local receiver {name} must be non-negative")
        fields: tuple[tuple[str, str | int | None], ...] = (
            ("NatAddress", self.nat_address),
            ("NatPort", self.nat_port),
            ("UPnPAddress", self.upnp_address),
            ("UPnPPort", self.upnp_port),
            ("InnerAddress", self.inner_address),
            ("InnerPort", self.inner_port),
            ("StreamType", self.stream_type),
        )
        lines = [f"{indent}<ReceiverInfo>"]
        for tag, value in fields:
            lines.append(f"{indent}\t<{tag}>{_xml_escape(str(value))}</{tag}>")
        lines.append(f"{indent}</ReceiverInfo>")
        return tuple(lines)


@dataclass(frozen=True)
class EzvizLocalReceiverInfoEx:
    """Structured extended receiver-auth fields for the local preview request."""

    uuid: str | None = None
    timestamp: str | int | None = None

    def xml_lines(self, *, indent: str = "\t") -> tuple[str, ...]:
        """Build the nested ``ReceiverInfoEx`` XML lines."""
        lines = [f"{indent}<ReceiverInfoEx>"]
        if self.uuid is not None or self.timestamp is not None:
            lines.append(f"{indent}\t<Authentication>")
            for tag, value in (("Uuid", self.uuid), ("Timestamp", self.timestamp)):
                if value is not None:
                    lines.append(f"{indent}\t\t<{tag}>{_xml_escape(str(value))}</{tag}>")
            lines.append(f"{indent}\t</Authentication>")
        lines.append(f"{indent}</ReceiverInfoEx>")
        return tuple(lines)


def _xml_attrs(fields: Iterable[tuple[str, str | int]]) -> str:
    return " ".join(f'{tag}="{_xml_escape(str(value))}"' for tag, value in fields)


@dataclass(frozen=True)
class EzvizLocalReceiverInfoAttrs:
    """App-shaped ``ReceiverInfo`` attributes for direct-local preview setup."""

    address: str = ""
    port: int = 10101
    server_type: int = 1
    stream_type: str = "MAIN"
    new_stream_type: int = 1
    trans_proto: str = "TCP"

    def xml_lines(self, *, indent: str = "\t") -> tuple[str, ...]:
        """Build the observed self-closing app ``ReceiverInfo`` tag."""
        if self.port < 0:
            raise PyEzvizError("EZVIZ local receiver port must be non-negative")
        attrs = (
            ("Address", self.address),
            ("Port", self.port),
            ("ServerType", self.server_type),
            ("StreamType", self.stream_type),
            ("NewStreamType", self.new_stream_type),
            ("TransProto", self.trans_proto),
        )
        return (f"{indent}<ReceiverInfo {_xml_attrs(attrs)} />",)


@dataclass(frozen=True)
class EzvizLocalReceiverInfoExAttrs:
    """App-shaped ``ReceiverInfoEx`` attributes for direct-local preview setup."""

    session_id: str = ""
    port: int = 10101

    def xml_lines(self, *, indent: str = "\t") -> tuple[str, ...]:
        """Build the observed self-closing app ``ReceiverInfoEx`` tag."""
        if self.port < 0:
            raise PyEzvizError("EZVIZ local receiver ex port must be non-negative")
        return (
            f"{indent}<ReceiverInfoEx "
            f"{_xml_attrs((('SessionID', self.session_id), ('Port', self.port)))} />",
        )


@dataclass(frozen=True)
class EzvizLocalAuthenticationAttrs:
    """App-shaped authentication attributes for direct-local preview setup."""

    ticket: str = ""
    biz_code: str = "biz=1"
    interval: int = 180

    def xml_lines(self, *, indent: str = "\t") -> tuple[str, ...]:
        """Build the observed self-closing app ``Authentication`` tag."""
        if self.interval < 0:
            raise PyEzvizError("EZVIZ local authentication interval must be non-negative")
        attrs = (
            ("Ticket", self.ticket),
            ("BizCode", self.biz_code),
            ("Interval", self.interval),
        )
        return (f"{indent}<Authentication {_xml_attrs(attrs)} />",)


def _build_local_sdk_request_xml(
    fields: tuple[
        tuple[
            str,
            str
            | int
            | EzvizLocalReceiverInfo
            | EzvizLocalReceiverInfoAttrs
            | EzvizLocalReceiverInfoEx
            | EzvizLocalReceiverInfoExAttrs
            | EzvizLocalAuthenticationAttrs
            | None,
        ],
        ...,
    ],
) -> bytes:
    lines = ['<?xml version="1.0" encoding="utf-8"?>', "<Request>"]
    for tag, value in fields:
        if value is None:
            continue
        if isinstance(value, (EzvizLocalReceiverInfo, EzvizLocalReceiverInfoAttrs)):
            if tag != "ReceiverInfo":
                raise PyEzvizError("Structured receiver info must use ReceiverInfo tag")
            lines.extend(value.xml_lines())
            continue
        if isinstance(value, (EzvizLocalReceiverInfoEx, EzvizLocalReceiverInfoExAttrs)):
            if tag != "ReceiverInfoEx":
                raise PyEzvizError("Structured receiver info ex must use ReceiverInfoEx tag")
            lines.extend(value.xml_lines())
            continue
        if isinstance(value, EzvizLocalAuthenticationAttrs):
            if tag != "Authentication":
                raise PyEzvizError("Structured authentication must use Authentication tag")
            lines.extend(value.xml_lines())
            continue
        lines.append(f"\t<{tag}>{_xml_escape(str(value))}</{tag}>")
    lines.append("</Request>")
    return ("\n".join(lines) + "\n").encode("utf-8")


def build_ezviz_local_preview_request_body(  # noqa: PLR0913
    *,
    operation_code: str,
    channel: int,
    receiver_info: str | EzvizLocalReceiverInfo | EzvizLocalReceiverInfoAttrs,
    receiver_info_ex: str | EzvizLocalReceiverInfoEx | EzvizLocalReceiverInfoExAttrs,
    identifier: str | None = None,
    is_encrypt: str | int = "TRUE",
    udt: int | None = None,
    nat: int | None = None,
    port_guess_type: int | None = None,
    timeout: int | None = None,
    heartbeat_interval: int | None = None,
    authentication: str | EzvizLocalAuthenticationAttrs | None = None,
    uuid: str | None = None,
    timestamp: str | int | None = None,
    public_key: str | None = None,
) -> bytes:
    """Build the plaintext XML body for the observed 0x2011 request.

    The caller must supply values obtained through their own credential/source
    path. This helper only gives the confirmed tag order and escaping.
    """
    if channel < 0:
        raise PyEzvizError("EZVIZ local preview channel must be non-negative")
    return _build_local_sdk_request_xml(
        (
            ("OperationCode", operation_code),
            ("Channel", channel),
            ("Identifier", identifier),
            ("ReceiverInfo", receiver_info),
            ("IsEncrypt", is_encrypt),
            ("Udt", udt),
            ("Nat", nat),
            ("PortGuessType", port_guess_type),
            ("Timeout", timeout),
            ("HeartbeatInterval", heartbeat_interval),
            ("ReceiverInfoEx", receiver_info_ex),
            ("Authentication", authentication),
            ("Uuid", uuid),
            ("Timestamp", timestamp),
            ("PublicKey", public_key),
        )
    )


@dataclass(frozen=True)
class EzvizLocalPreviewRequest:
    """Plaintext field set for the observed 0x2011 preview request."""

    operation_code: str
    channel: int
    receiver_info: str | EzvizLocalReceiverInfo | EzvizLocalReceiverInfoAttrs
    receiver_info_ex: str | EzvizLocalReceiverInfoEx | EzvizLocalReceiverInfoExAttrs
    identifier: str | None = None
    is_encrypt: str | int = "TRUE"
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
        return build_ezviz_local_preview_request_body(
            operation_code=self.operation_code,
            channel=self.channel,
            receiver_info=self.receiver_info,
            receiver_info_ex=self.receiver_info_ex,
            identifier=self.identifier,
            is_encrypt=self.is_encrypt,
            udt=self.udt,
            nat=self.nat,
            port_guess_type=self.port_guess_type,
            timeout=self.timeout,
            heartbeat_interval=self.heartbeat_interval,
            authentication=self.authentication,
            uuid=self.uuid,
            timestamp=self.timestamp,
            public_key=self.public_key,
        )
