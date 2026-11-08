"""framing protocol values and pure helpers; dependency-closed implementation."""

from __future__ import annotations

from pyezvizapi.streaming.local.hcnetsdk.constants import (
    HCNETSDK_COMMAND_PORT_AUTH_MASK_LENGTH,
    HCNETSDK_COMMAND_PORT_CONTROL_FAMILY,
    HCNETSDK_COMMAND_PORT_PLAY_LOGIN_TODAY_TRANSFORM,
    HCNETSDK_HIK_PRIVATE_PREFIX,
    HCNETSDK_HKMI_PREFIX,
    HCNETSDK_MPEG_PS_PACK_HEADER,
    HCNETSDK_MPEG_START_CODE_PREFIX,
    HCNETSDK_MPEG_TS_SYNC_BYTE,
    HCNETSDK_TCP_HEADER_LENGTH,
    HCNETSDK_XML_MARKER,
    IntEnum,
    Mapping,
    PyEzvizError,
    dataclass,
    date,
    json,
)
from pyezvizapi.streaming.local.hcnetsdk.protocol_types.sdk_requests import (
    hcnetsdk_command_candidate_role,
)
from pyezvizapi.streaming.local.hcnetsdk.protocol_types.wire_crypto import (
    _hcnetsdk_command_port_local_ip_word,
    hcnetsdk_command_port_auth_word,
)


class HcNetSdkRealDataType(IntEnum):
    """HCNetSDK real-play callback data types used by ``RealDataCallBack``."""

    SYSTEM_HEADER = 1
    STREAM_DATA = 2
    AUDIO_STREAM_DATA = 3
    PRIVATE_DATA = 112


def hcnetsdk_real_data_type_is_media(data_type: int) -> bool:
    """Return whether a real-play callback type can carry media payloads."""
    return data_type in (
        HcNetSdkRealDataType.STREAM_DATA,
        HcNetSdkRealDataType.AUDIO_STREAM_DATA,
        HcNetSdkRealDataType.PRIVATE_DATA,
    )


def classify_hcnetsdk_real_data_payload(data: bytes) -> str:
    """Classify HCNetSDK callback bytes without decoding or exposing content."""
    if not data:
        return "empty"
    prefixes = (
        (HCNETSDK_MPEG_PS_PACK_HEADER, "mpeg_ps"),
        (HCNETSDK_MPEG_START_CODE_PREFIX, "mpeg_ps_start"),
        (bytes((HCNETSDK_MPEG_TS_SYNC_BYTE,)), "mpeg_ts"),
        (HCNETSDK_HKMI_PREFIX, "hik_hkmi"),
        (HCNETSDK_HIK_PRIVATE_PREFIX, "hik_private"),
    )
    for prefix, kind in prefixes:
        if data.startswith(prefix):
            return kind
    return "unknown"


@dataclass(frozen=True)
class HcNetSdkRealDataPacket:
    """One packet emitted by an HCNetSDK real-play data callback."""

    real_handle: int
    data_type: int
    body: bytes

    @property
    def is_media(self) -> bool:
        """Return whether this callback packet can carry remuxable media."""
        return hcnetsdk_real_data_type_is_media(self.data_type)

    @property
    def payload_kind(self) -> str:
        """Return a small, non-secret classification of the callback body."""
        return classify_hcnetsdk_real_data_payload(self.body)


@dataclass(frozen=True)
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


@dataclass(frozen=True)
class HcNetSdkTcpShapeLogRecord:
    """One secret-safe HCNetSDK command-port shape log line."""

    direction: str
    fd: int
    host: str
    port: int
    shape: HcNetSdkTcpPayloadShape
    captured_length: int | None = None
    fingerprint: str | None = None
    length_candidates: Mapping[str, int] | None = None


@dataclass(frozen=True)
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
        return self.total_length - HCNETSDK_TCP_HEADER_LENGTH

    def to_bytes(self) -> bytes:
        """Serialize the non-secret header fields using observed endianness."""
        return b"".join(
            (
                self.total_length.to_bytes(4, "big"),
                self.field_4.to_bytes(4, "big"),
                self.field_8.to_bytes(4, "big"),
                self.field_12.to_bytes(4, "big"),
            )
        )


@dataclass(frozen=True)
class HcNetSdkTcpFrame:
    """One complete HCNetSDK command-port frame."""

    header: HcNetSdkTcpFrameHeader
    body: bytes = b""

    def to_bytes(self) -> bytes:
        """Serialize the observed frame header and body."""
        if self.header.body_length != len(self.body):
            raise PyEzvizError("HCNetSDK TCP frame header/body length mismatch")
        return self.header.to_bytes() + self.body


@dataclass(frozen=True)
class HcNetSdkCommandPortExchange:
    """One command-port request and its optional response."""

    request: bytes
    response: HcNetSdkTcpFrame | None = None


@dataclass(frozen=True)
class EzvizInterleavedRtpFrameHeader:
    """RTSP-style interleaved RTP frame prefix used on the EZVIZ stream port."""

    channel: int
    payload_length: int


@dataclass(frozen=True)
class EzvizInterleavedRtpFrame:
    """One interleaved RTP frame read from an EZVIZ local stream socket."""

    header: EzvizInterleavedRtpFrameHeader
    payload: bytes


@dataclass(frozen=True)
class EzvizInterleavedRtpFrameWithPrefix:
    """First RTP frame plus any binary preface emitted before it."""

    prefix: bytes
    frame: EzvizInterleavedRtpFrame


@dataclass(frozen=True)
class HcNetSdkCommandPortStreamBootstrap:
    """Result of a command-port stream bootstrap."""

    exchanges: tuple[HcNetSdkCommandPortExchange, ...]
    first_media: EzvizInterleavedRtpFrameWithPrefix | None = None


@dataclass(frozen=True)
class HcNetSdkCommandPortLoginChallenge:
    """Decoded first-stage command-port login challenge."""

    response: HcNetSdkTcpFrame
    challenge: bytes
    password_seed: bytes


@dataclass(frozen=True)
class HcNetSdkCommandPortLoginSession:
    """Successful generated port-8000 login session."""

    session_id: bytes
    auth_seed: int
    serial: str
    first_response: HcNetSdkTcpFrame
    second_response: HcNetSdkTcpFrame
    challenge: bytes = b""
    password_seed: bytes = b""


def hcnetsdk_command_port_response_payload(
    response: HcNetSdkTcpFrame | bytes,
) -> bytes:
    """Return a textual JSON/XML payload from a command-port response.

    Native command-port responses may include leading binary or NUL padding
    before the string output buffer. Keep the rule intentionally narrow so
    binary command responses remain available to lower-level callers.
    """
    body = response.body if isinstance(response, HcNetSdkTcpFrame) else response
    if not body:
        return b""
    candidates: list[tuple[int, bytes]] = []
    for marker in (b"<?xml", b"{", b"[", HCNETSDK_XML_MARKER):
        offset = body.find(marker)
        if offset >= 0:
            candidates.append((offset, body[offset:].split(b"\x00", 1)[0].strip()))
    for _offset, candidate in sorted(candidates, key=lambda item: item[0]):
        if not candidate:
            continue
        if candidate[:1] in {b"{", b"["}:
            try:
                json.loads(candidate.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                continue
            return candidate
        if candidate.startswith(b"<?xml") or (
            candidate[:1] == HCNETSDK_XML_MARKER and len(candidate) > 1 and candidate[1:2].isalpha()
        ):
            return candidate
    return body.split(b"\x00", 1)[0].strip()


@dataclass(frozen=True)
class HcNetSdkCommandPortControlResponse:
    """Pure-Python response from one generated command-port control request."""

    login_session: HcNetSdkCommandPortLoginSession
    request: bytes
    response: HcNetSdkTcpFrame

    @property
    def output(self) -> bytes:
        """Return the textual payload carried by the command-port response."""
        return hcnetsdk_command_port_response_payload(self.response)

    @property
    def text(self) -> str:
        """Decode the textual response payload as UTF-8."""
        return self.output.decode("utf-8")


def build_hcnetsdk_tcp_frame(
    body: bytes = b"",
    *,
    field_4: int = 0,
    field_8: int = 0,
    field_12: int = 0,
) -> bytes:
    """Build the generic observed HCNetSDK command-port frame wrapper."""
    header = HcNetSdkTcpFrameHeader(
        total_length=HCNETSDK_TCP_HEADER_LENGTH + len(body),
        field_4=field_4,
        field_8=field_8,
        field_12=field_12,
    )
    return HcNetSdkTcpFrame(header=header, body=body).to_bytes()


def hcnetsdk_command_port_control_frame(
    *,
    session_id: bytes,
    auth_seed: int,
    command_id: int,
    key: bytes,
    local_ip: str,
    body_tail: bytes = b"",
    addend: int | None = None,
    mask_seed: bytes = b"\x00" * HCNETSDK_COMMAND_PORT_AUTH_MASK_LENGTH,
) -> bytes:
    """Build one generated post-login HCNetSDK port-8000 control frame.

    The frame body format observed in native traces is the client LAN IPv4 word
    in little-endian byte order, the four-byte network-order login session id,
    eight reserved zero bytes, and then the command-specific tail. The auth word
    uses the same network-order session id returned by login.
    """
    if len(session_id) != 4:
        raise PyEzvizError("HCNetSDK command-port session id must be 4 bytes")
    body = _hcnetsdk_command_port_local_ip_word(local_ip) + session_id + (b"\x00" * 8) + body_tail
    return build_hcnetsdk_tcp_frame(
        body,
        field_4=HCNETSDK_COMMAND_PORT_CONTROL_FAMILY,
        field_8=hcnetsdk_command_port_auth_word(
            session_id=session_id,
            auth_seed=auth_seed,
            command_id=command_id,
            key=key,
            addend=addend,
            mask_seed=mask_seed,
        ),
        field_12=command_id,
    )


def hcnetsdk_command_port_play_login_body_tail_for_today(
    body_tail: bytes,
    *,
    today: date | None = None,
) -> bytes:
    """Refresh native play-login date words in a captured ``0x111040`` tail."""
    if len(body_tail) != 148:
        raise PyEzvizError("HCNetSDK play-login body tail transform requires a 148-byte tail")
    current = today or date.today()
    patched = bytearray(body_tail)
    values = {
        36: current.year,
        40: current.month,
        44: current.day,
        60: current.year,
        64: current.month,
        68: current.day,
        72: 23,
        76: 59,
        80: 59,
    }
    for offset, value in values.items():
        patched[offset : offset + 4] = value.to_bytes(4, "big")
    return bytes(patched)


@dataclass(frozen=True)
class HcNetSdkCommandPortControlTemplate:
    """Reusable post-login command-port control frame template."""

    command_id: int
    body_tail: bytes = b""
    addend: int | None = None
    addend_delta: int | None = None
    mask_seed: bytes = b"\x00" * HCNETSDK_COMMAND_PORT_AUTH_MASK_LENGTH
    body_tail_transform: str | None = None
    name: str | None = None

    def __post_init__(self) -> None:
        if self.addend is not None and self.addend_delta is not None:
            raise PyEzvizError("HCNetSDK command-port template cannot set addend and addend_delta")
        if (
            self.body_tail_transform is not None
            and self.body_tail_transform != HCNETSDK_COMMAND_PORT_PLAY_LOGIN_TODAY_TRANSFORM
        ):
            raise PyEzvizError(
                f"Unsupported HCNetSDK command-port body_tail_transform: {self.body_tail_transform}"
            )

    def to_frame(
        self,
        *,
        session_id: bytes,
        auth_seed: int,
        key: bytes,
        local_ip: str,
        addend: int | None = None,
    ) -> bytes:
        """Build this template with fresh login/session values."""
        template_addend = self.addend
        if template_addend is None and self.addend_delta is not None:
            template_addend = (int.from_bytes(session_id, "big") + self.addend_delta) & 0xFFFFFFFF
        body_tail = self.body_tail
        if self.body_tail_transform == HCNETSDK_COMMAND_PORT_PLAY_LOGIN_TODAY_TRANSFORM:
            body_tail = hcnetsdk_command_port_play_login_body_tail_for_today(body_tail)
        return hcnetsdk_command_port_control_frame(
            session_id=session_id,
            auth_seed=auth_seed,
            command_id=self.command_id,
            key=key,
            local_ip=local_ip,
            body_tail=body_tail,
            addend=template_addend if addend is None else addend,
            mask_seed=self.mask_seed,
        )


@dataclass(frozen=True)
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
        return self.total_length - HCNETSDK_TCP_HEADER_LENGTH

    @property
    def write_command_candidate(self) -> int | None:
        """Return the observed client-write command candidate when present.

        Fresh direct-local traces show HCNetSDK client writes with a big-endian total
        length at offset 0 and a small little-endian word at offset 4. That word
        was 90 for the initial encrypted login exchange and 99 for several
        follow-up capability/control requests. Keep it as a candidate until
        more devices prove the semantics.
        """
        if self.direction not in {"send", "write"}:
            return None
        return self.header_shape.u32le_4

    @property
    def write_command_role(self) -> str | None:
        """Return the current semantic label for an observed write candidate."""
        return hcnetsdk_command_candidate_role(self.write_command_candidate)
