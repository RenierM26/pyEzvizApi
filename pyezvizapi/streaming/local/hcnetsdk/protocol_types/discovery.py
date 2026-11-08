"""discovery protocol values and pure helpers; dependency-closed implementation."""

from __future__ import annotations

from pyezvizapi.streaming.local.hcnetsdk.constants import (
    SADP_ACTIVATE_DEVICE,
    SADP_CLEARUP,
    SADP_DEV_NET_PARAM_ANDROID_FIELDS,
    SADP_DEV_NET_PARAM_JNA_FIELD_ORDER,
    SADP_DEV_RET_NET_PARAM_BUFFER_SIZE,
    SADP_DEV_RET_NET_PARAM_FIELD_ORDER,
    SADP_GET_LAST_ERROR,
    SADP_GET_VERSION,
    SADP_MODIFY_DEVICE_NET_PARAM,
    SADP_MODIFY_DEVICE_NET_PARAM_V40,
    SADP_NUL_BYTE,
    SADP_SEND_INQUIRY,
    SADP_SET_LOG_TO_FILE,
    SADP_START_V30,
    SADP_START_V40,
    SADP_STOP,
    Any,
    Mapping,
    PyEzvizError,
    dataclass,
)
from pyezvizapi.streaming.local.hcnetsdk.protocol_types.values import (
    _byte_value,
    _port_value,
)


@dataclass(frozen=True)
class SadpDeviceInfo:
    """Parsed SADP response fields."""

    fields: Mapping[str, str]

    @property
    def serial(self) -> str | None:
        """Return a likely device serial field if present."""
        return self.fields.get("DeviceSN") or self.fields.get("SerialNO")

    @property
    def ipv4_address(self) -> str | None:
        """Return the SADP IPv4 address field if present."""
        return self.fields.get("IPv4Address") or self.fields.get("IPAddress")

    @property
    def command_port(self) -> int | None:
        """Return the SDK command/server port if SADP reported one."""
        value = (
            self.fields.get("CommandPort")
            or self.fields.get("DevicePort")
            or self.fields.get("Port")
        )
        return int(value) if value and value.isdigit() else None


@dataclass(frozen=True)
class SadpActivateDeviceRequest:
    """Android ``SADP_ActivateDevice`` call shape."""

    serial: str
    password: str
    api: str = SADP_ACTIVATE_DEVICE

    def to_native_args_hint(
        self,
        *,
        include_password: bool = False,
    ) -> dict[str, Any]:
        """Return the native argument names for a local SADP bridge."""
        serial = self.serial.strip()
        if not serial:
            raise PyEzvizError("SADP activation serial cannot be empty")
        password = self.password
        if not password:
            raise PyEzvizError("SADP activation password cannot be empty")
        return {
            "api": self.api,
            "serial": serial,
            "password": password if include_password else "<password>",
            "passwordLength": len(password.encode("utf-8")),
            "lastErrorApi": SADP_GET_LAST_ERROR,
        }


def _sadp_string_bytes(
    label: str,
    value: str | bytes,
    limit: int,
    *,
    allow_empty: bool = False,
) -> bytes:
    if isinstance(value, bytes):
        raw = value
    elif isinstance(value, str):
        raw = value.encode("utf-8")
    else:
        raise PyEzvizError(f"SADP {label} must be bytes or string")
    if not raw and not allow_empty:
        raise PyEzvizError(f"SADP {label} cannot be empty")
    if len(raw) > limit:
        raise PyEzvizError(f"SADP {label} must be at most {limit} bytes")
    return raw


@dataclass(frozen=True)
class SadpDeviceNetParam:
    """Android ``SADP_DEV_NET_PARAM`` field updates used by the RN module."""

    ipv4_address: str
    ipv4_subnet_mask: str
    ipv4_gateway: str
    dhcp_enabled: int | bool
    http_port: int
    command_port: int
    ipv6_address: str = ""
    ipv6_gateway: str = ""
    ipv6_mask_len: int = 0

    def to_native_dict(self, *, include_buffers: bool = False) -> dict[str, Any]:
        """Return the Android SADP_DEV_NET_PARAM field values."""
        ipv4_address = _sadp_string_bytes("IPv4 address", self.ipv4_address, 16)
        ipv4_subnet_mask = _sadp_string_bytes("IPv4 subnet mask", self.ipv4_subnet_mask, 16)
        ipv4_gateway = _sadp_string_bytes("IPv4 gateway", self.ipv4_gateway, 16)
        ipv6_address = _sadp_string_bytes("IPv6 address", self.ipv6_address, 128, allow_empty=True)
        ipv6_gateway = _sadp_string_bytes("IPv6 gateway", self.ipv6_gateway, 128, allow_empty=True)
        return {
            "structure": "SADP_DEV_NET_PARAM",
            "androidFields": SADP_DEV_NET_PARAM_ANDROID_FIELDS,
            "jnaFieldOrder": SADP_DEV_NET_PARAM_JNA_FIELD_ORDER,
            "szIPv4Address": (ipv4_address if include_buffers else self.ipv4_address),
            "szIPv4SubnetMask": (ipv4_subnet_mask if include_buffers else self.ipv4_subnet_mask),
            "szIPv4Gateway": (ipv4_gateway if include_buffers else self.ipv4_gateway),
            "szIPv6Address": (ipv6_address if include_buffers else self.ipv6_address),
            "szIPv6Gateway": (ipv6_gateway if include_buffers else self.ipv6_gateway),
            "byDhcpEnabled": _byte_value("SADP DHCP enabled", int(self.dhcp_enabled)),
            "byIPv6MaskLen": _byte_value("SADP IPv6 mask length", self.ipv6_mask_len),
            "wHttpPort": _port_value("SADP HTTP port", self.http_port),
            "wPort": _port_value("SADP command port", self.command_port),
        }


@dataclass(frozen=True)
class SadpModifyDeviceNetParamRequest:
    """Android ``SADP_ModifyDeviceNetParam`` call shape."""

    mac: str
    password: str
    net_param: SadpDeviceNetParam
    api: str = SADP_MODIFY_DEVICE_NET_PARAM

    def to_native_args_hint(
        self,
        *,
        include_password: bool = False,
        include_buffers: bool = False,
    ) -> dict[str, Any]:
        """Return the native argument names for a local SADP bridge."""
        mac = self.mac.strip()
        if not mac:
            raise PyEzvizError("SADP MAC address cannot be empty")
        if not self.password:
            raise PyEzvizError("SADP network password cannot be empty")
        return {
            "api": self.api,
            "mac": mac,
            "password": self.password if include_password else "<password>",
            "passwordLength": len(self.password.encode("utf-8")),
            "netParam": self.net_param.to_native_dict(include_buffers=include_buffers),
            "lastErrorApi": SADP_GET_LAST_ERROR,
        }


@dataclass(frozen=True)
class SadpDeviceRetNetParam:
    """Native ``SADP_DEV_RET_NET_PARAM`` output-buffer shape."""

    retry_modify_time: int | None = None
    surplus_lock_time: int | None = None

    def to_native_dict(self) -> dict[str, Any]:
        """Return the JNA field names for V40 network-edit failure detail."""
        result: dict[str, Any] = {
            "structure": "SADP_DEV_RET_NET_PARAM",
            "fieldOrder": SADP_DEV_RET_NET_PARAM_FIELD_ORDER,
            "dwSize": "sizeof(SADP_DEV_RET_NET_PARAM)",
            "byResLength": 126,
        }
        if self.retry_modify_time is not None:
            result["byRetryModifyTime"] = _byte_value(
                "SADP retry modify time", self.retry_modify_time
            )
        if self.surplus_lock_time is not None:
            result["bySurplusLockTime"] = _byte_value(
                "SADP surplus lock time", self.surplus_lock_time
            )
        return result


@dataclass(frozen=True)
class SadpModifyDeviceNetParamV40Request:
    """Android ``SADP_ModifyDeviceNetParam_V40`` call shape."""

    mac: str
    password: str
    net_param: SadpDeviceNetParam
    ret_net_param: SadpDeviceRetNetParam | None = None
    api: str = SADP_MODIFY_DEVICE_NET_PARAM_V40

    def to_native_args_hint(
        self,
        *,
        include_password: bool = False,
        include_buffers: bool = False,
    ) -> dict[str, Any]:
        """Return the V40 native argument names for a local SADP bridge."""
        mac = self.mac.strip()
        if not mac:
            raise PyEzvizError("SADP MAC address cannot be empty")
        if not self.password:
            raise PyEzvizError("SADP network password cannot be empty")
        if self.api != SADP_MODIFY_DEVICE_NET_PARAM_V40:
            raise PyEzvizError("SADP V40 network-param API is unsupported")
        ret_net_param = self.ret_net_param or SadpDeviceRetNetParam()
        return {
            "api": self.api,
            "mac": mac,
            "password": self.password if include_password else "<password>",
            "passwordLength": len(self.password.encode("utf-8")),
            "netParam": self.net_param.to_native_dict(include_buffers=include_buffers),
            "lpRetNetParam": ret_net_param.to_native_dict(),
            "dwOutBuffSize": SADP_DEV_RET_NET_PARAM_BUFFER_SIZE,
            "lastErrorApi": SADP_GET_LAST_ERROR,
        }


@dataclass(frozen=True)
class SadpNoArgRequest:
    """Native no-argument SADP call shape."""

    api: str

    def to_native_args_hint(self) -> dict[str, Any]:
        """Return the no-argument SADP call name."""
        if self.api not in {
            SADP_GET_LAST_ERROR,
            SADP_GET_VERSION,
            SADP_STOP,
            SADP_CLEARUP,
            SADP_SEND_INQUIRY,
        }:
            raise PyEzvizError("SADP no-argument API is unsupported")
        return {"api": self.api}


@dataclass(frozen=True)
class SadpStartRequest:
    """Native ``SADP_Start_V30`` / ``V40`` call shape."""

    version: int = 40
    install_npf: int | bool = 0
    callback: str | None = None
    user_data: str | None = None

    def to_native_args_hint(self) -> dict[str, Any]:
        """Return native argument names for starting SADP discovery."""
        if self.version not in {30, 40}:
            raise PyEzvizError("SADP start version must be 30 or 40")
        install_npf = _byte_value("SADP install NPF flag", int(self.install_npf))
        if self.version == 30:
            return {
                "api": SADP_START_V30,
                "pDeviceFindCallBack": self.callback or "<DeviceFindCallBack>",
                "bInstallNPF": install_npf,
                "pUserData": self.user_data or "<Pointer.NULL>",
            }
        return {
            "api": SADP_START_V40,
            "pDeviceFindCallBack_v40": (self.callback or "<DeviceFindCallBack_V40>"),
            "bInstallNPF": install_npf,
            "pUserData": self.user_data or "<Pointer.NULL>",
        }


@dataclass(frozen=True)
class SadpSetLogToFileRequest:
    """Native ``SADP_SetLogToFile`` call shape."""

    log_level: int
    log_dir: str | bytes
    auto_delete: int | bool = True
    api: str = SADP_SET_LOG_TO_FILE

    def to_native_args_hint(self, *, include_buffer: bool = False) -> dict[str, Any]:
        """Return native argument names for SADP file logging."""
        if self.api != SADP_SET_LOG_TO_FILE:
            raise PyEzvizError("SADP log API is unsupported")
        if self.log_level < 0:
            raise PyEzvizError("SADP log level must be non-negative")
        log_dir = _sadp_string_bytes("log directory", self.log_dir, 4096)
        if SADP_NUL_BYTE in log_dir:
            raise PyEzvizError("SADP log directory cannot contain NUL bytes")
        return {
            "api": self.api,
            "nLogLevel": self.log_level,
            "strLogDir": (
                log_dir + SADP_NUL_BYTE
                if include_buffer
                else log_dir.decode("utf-8", errors="replace")
            ),
            "bAutoDel": _byte_value("SADP auto-delete flag", int(self.auto_delete)),
        }


@dataclass(frozen=True)
class SadpBatchResult:
    """RN-style batch operation result for SADP activation/network edits."""

    identifier: str
    password: str
    code: int
    error: int
    identifier_key: str

    def to_rn_dict(self, *, include_password: bool = True) -> dict[str, Any]:
        """Return the map pushed into the React Native result array."""
        if self.identifier_key not in {"serial", "mac"}:
            raise PyEzvizError("SADP batch result identifier key is unsupported")
        identifier = self.identifier.strip()
        if not identifier:
            raise PyEzvizError("SADP batch result identifier cannot be empty")
        if not self.password:
            raise PyEzvizError("SADP batch result password cannot be empty")
        return {
            self.identifier_key: identifier,
            "password": self.password if include_password else "<password>",
            "code": self.code,
            "error": self.error,
        }
