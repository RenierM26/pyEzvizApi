"""endpoints protocol values and pure helpers; dependency-closed implementation."""

from __future__ import annotations

from pyezvizapi.streaming.local.hcnetsdk.constants import (
    HCNETSDK_DEFAULT_RTSP_PORT,
    HCNETSDK_DEFAULT_SERVER_PORT,
    HCNETSDK_DEFAULT_TLS_PORT,
    Any,
    Mapping,
    PyEzvizError,
    dataclass,
    field,
)
from pyezvizapi.streaming.local.hcnetsdk.protocol_types.values import (
    _mapping_int,
    _mapping_str,
)


@dataclass(frozen=True)
class HcNetSdkLanEndpoint:
    """LAN endpoint metadata derived from EZVIZ pagelist ``CONNECTION``."""

    serial: str
    host: str
    net_host: str | None = None
    command_port: int = HCNETSDK_DEFAULT_SERVER_PORT
    net_command_port: int | None = None
    stream_port: int | None = None
    net_stream_port: int | None = None
    rtsp_port: int | None = None
    sdk_tls_port: int = HCNETSDK_DEFAULT_TLS_PORT

    @classmethod
    def from_connection(
        cls,
        serial: str,
        connection: Mapping[str, Any] | None,
    ) -> HcNetSdkLanEndpoint:
        """Build LAN endpoint metadata from a pagelist ``CONNECTION`` mapping."""
        if not connection:
            raise PyEzvizError(f"Missing CONNECTION metadata for {serial}")

        host = connection.get("localIp")
        if not isinstance(host, str) or not host.strip():
            raise PyEzvizError(f"Missing localIp in CONNECTION metadata for {serial}")

        return cls(
            serial=serial,
            host=host.strip(),
            net_host=_mapping_str(connection, "netIp"),
            command_port=_mapping_int(
                connection,
                "localCmdPort",
                default=HCNETSDK_DEFAULT_SERVER_PORT,
            )
            or HCNETSDK_DEFAULT_SERVER_PORT,
            net_command_port=_mapping_int(connection, "netCmdPort", default=None),
            stream_port=_mapping_int(connection, "localStreamPort", default=None),
            net_stream_port=_mapping_int(connection, "netStreamPort", default=None),
            rtsp_port=_mapping_int(
                connection,
                "localRtspPort",
                default=HCNETSDK_DEFAULT_RTSP_PORT,
                zero_is_missing=True,
            ),
        )


@dataclass(frozen=True)
class HcNetSdkLoginCandidate:
    """One LAN login mode observed in the EZVIZ Android app."""

    username: str
    password: str = field(repr=False)
    port: int
    api: str
    https: bool = False


@dataclass(frozen=True)
class HcNetSdkPortProbe:
    """Non-authenticated classification result for one LAN port."""

    port: int
    tcp_open: bool
    tls_accepted: bool | None = None
    passive_bytes: bytes = b""
    error: str | None = None
    tls_error: str | None = None
