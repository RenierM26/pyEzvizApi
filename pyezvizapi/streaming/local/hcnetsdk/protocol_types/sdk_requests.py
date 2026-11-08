"""sdk requests protocol values and pure helpers; dependency-closed implementation."""

from __future__ import annotations

from pyezvizapi.streaming.local.hcnetsdk.constants import (
    EZVIZ_LOCAL_SDK_AES_BLOCK_SIZE,
    HCNETSDK_CLEANUP,
    HCNETSDK_CLOSE_ALARM_CHAN_V30,
    HCNETSDK_COMMAND_CANDIDATE_CONTROL,
    HCNETSDK_COMMAND_CANDIDATE_SETTINGS_LOGIN,
    HCNETSDK_GET_ERROR_MSG,
    HCNETSDK_GET_LAST_ERROR,
    HCNETSDK_GET_SDK_BUILD_VERSION,
    HCNETSDK_GET_SDK_VERSION,
    HCNETSDK_INIT,
    HCNETSDK_LOGOUT_V30,
    HCNETSDK_SET_PLAY_DATA_CALLBACK,
    HCNETSDK_SET_PLAY_DATA_CALLBACK_V40,
    HCNETSDK_SETUP_ALARM_CHAN_V30,
    HCNETSDK_SETUP_ALARM_CHAN_V41,
    HCNETSDK_SETUPALARM_PARAM_FIELD_ORDER,
    Any,
    Mapping,
    PyEzvizError,
    dataclass,
)
from pyezvizapi.streaming.local.hcnetsdk.protocol_types.preview import (
    ezviz_native_video_level,
)
from pyezvizapi.streaming.local.hcnetsdk.protocol_types.values import (
    _byte_value,
    _word_value,
)


@dataclass(frozen=True)
class HcNetSdkSetupAlarmParam:
    """Native ``NET_DVR_SETUPALARM_PARAM`` shape used by alarm V41 setup."""

    level: int = 0
    alarm_info_type: int = 0
    ret_alarm_type_v40: int = 0
    ret_dev_info_version: int = 0
    ret_vqd_alarm_type: int = 0
    face_alarm_detection: int = 0
    support: int = 0
    broken_net_http: int = 0
    task_no: int = 0

    def to_native_dict(self) -> dict[str, Any]:
        """Return the JNA field names and values for V41 alarm setup."""
        return {
            "structure": "NET_DVR_SETUPALARM_PARAM",
            "fieldOrder": HCNETSDK_SETUPALARM_PARAM_FIELD_ORDER,
            "dwSize": "sizeof(NET_DVR_SETUPALARM_PARAM)",
            "byLevel": _byte_value("alarm level", self.level),
            "byAlarmInfoType": _byte_value("alarm info type", self.alarm_info_type),
            "byRetAlarmTypeV40": _byte_value("alarm V40 return type", self.ret_alarm_type_v40),
            "byRetDevInfoVersion": _byte_value(
                "alarm device-info version", self.ret_dev_info_version
            ),
            "byRetVQDAlarmType": _byte_value("alarm VQD return type", self.ret_vqd_alarm_type),
            "byFaceAlarmDetection": _byte_value("face alarm detection", self.face_alarm_detection),
            "bySupport": _byte_value("alarm support", self.support),
            "byBrokenNetHttp": _byte_value("broken-net HTTP", self.broken_net_http),
            "wTaskNo": _word_value("alarm task number", self.task_no),
            "byRes1Length": 6,
        }


@dataclass(frozen=True)
class HcNetSdkSetupAlarmRequest:
    """Native ``NET_DVR_SetupAlarmChan_V30`` / ``V41`` call shape."""

    login_id: int
    setup_param: HcNetSdkSetupAlarmParam | None = None

    def to_native_args_hint(self) -> dict[str, Any]:
        """Return native argument names for setting up an alarm channel."""
        if self.login_id < 0:
            raise PyEzvizError("HCNetSDK alarm setup requires a successful login id")
        if self.setup_param is None:
            return {
                "api": HCNETSDK_SETUP_ALARM_CHAN_V30,
                "lUserID": self.login_id,
                "failureHandle": -1,
            }
        return {
            "api": HCNETSDK_SETUP_ALARM_CHAN_V41,
            "lUserID": self.login_id,
            "lpSetupParam": self.setup_param.to_native_dict(),
            "failureHandle": -1,
        }


@dataclass(frozen=True)
class HcNetSdkCloseAlarmRequest:
    """Native ``NET_DVR_CloseAlarmChan_V30`` call shape."""

    alarm_handle: int
    api: str = HCNETSDK_CLOSE_ALARM_CHAN_V30

    def to_native_args_hint(self) -> dict[str, Any]:
        """Return native argument names for closing an alarm channel."""
        if self.alarm_handle < 0:
            raise PyEzvizError("HCNetSDK alarm handle must be non-negative")
        if self.api != HCNETSDK_CLOSE_ALARM_CHAN_V30:
            raise PyEzvizError("HCNetSDK close-alarm API is unsupported")
        return {
            "api": self.api,
            "lAlarmHandle": self.alarm_handle,
        }


@dataclass(frozen=True)
class EzvizLanIpcFrontParameterRange:
    """One integer range advertised by ``CAMERAPARA`` ability XML."""

    minimum: int = 0
    maximum: int = 0
    default: int | None = None

    @property
    def supported(self) -> bool:
        """Return whether the range has a non-empty max/min span."""
        return self.maximum > self.minimum


@dataclass(frozen=True)
class EzvizLanVideoQuality:
    """LAN quality pair exposed by ``LanItemDataHolder.getVideoQualityInfo()``."""

    stream_type: int
    video_level: int

    @property
    def native_video_level(self) -> int:
        """Return the value written to ``InitParam.iVideoLevel`` by the player."""
        return ezviz_native_video_level(self.video_level)


@dataclass(frozen=True)
class HcNetSdkSemanticLogEvent:
    """One secret-safe semantic HCNetSDK event."""

    name: str
    phase: str | None = None
    fields: Mapping[str, str] | None = None


@dataclass(frozen=True)
class HcNetSdkCommandTraceSummary:
    """Secret-safe summary of one mixed HCNetSDK command-port trace.

    Shape logs intentionally avoid raw payloads. This summary preserves only
    the useful correlation: which command candidates were sent during the
    settings login call, which follow-up command candidates appeared afterward,
    and whether playback/media/keyframe boundaries were observed.
    """

    settings_login_commands: tuple[int, ...] = ()
    followup_commands: tuple[int, ...] = ()
    settings_login_success: bool = False
    play_device_login_success: bool = False
    keyframe_requested: bool = False
    media_on_command_socket: bool = False


def hcnetsdk_command_candidate_role(candidate: int | None) -> str | None:
    """Return the current role label for an observed command candidate.

    The names are trace-derived labels, not a complete HCNetSDK command table.
    They are useful for reducing redacted captures while the underlying
    encrypted request format is still being mapped.
    """
    if candidate == HCNETSDK_COMMAND_CANDIDATE_SETTINGS_LOGIN:
        return "settings_login"
    if candidate == HCNETSDK_COMMAND_CANDIDATE_CONTROL:
        return "control"
    return None


def ezviz_local_sdk_iv(serial: str, operation_code: str) -> bytes:
    """Build the AES-CBC IV used by EZVIZ local-control CAS frames."""
    iv = f"{serial}{operation_code}".encode("latin1")
    if len(iv) != EZVIZ_LOCAL_SDK_AES_BLOCK_SIZE:
        raise PyEzvizError("EZVIZ local SDK IV must be 16 bytes from serial + operation code")
    return iv


@dataclass(frozen=True)
class HcNetSdkNoArgRequest:
    """Native no-argument HCNetSDK call shape."""

    api: str

    def to_native_args_hint(self) -> dict[str, Any]:
        """Return the no-argument native call name."""
        if self.api not in {
            HCNETSDK_CLEANUP,
            HCNETSDK_GET_LAST_ERROR,
            HCNETSDK_GET_SDK_VERSION,
            HCNETSDK_GET_SDK_BUILD_VERSION,
        }:
            raise PyEzvizError("HCNetSDK no-argument API is unsupported")
        return {"api": self.api}


@dataclass(frozen=True)
class HcNetSdkInitRequest:
    """Native ``NET_DVR_Init`` call shape."""

    playctrl_library: str | None = "libPlayCtrl.so"
    api: str = HCNETSDK_INIT

    def to_native_args_hint(self) -> dict[str, Any]:
        """Return native argument names for SDK initialization."""
        if self.api != HCNETSDK_INIT:
            raise PyEzvizError("HCNetSDK init API is unsupported")
        if self.playctrl_library is None:
            return {
                "api": self.api,
                "overload": "android-default-playctrl-library",
            }
        playctrl_library = self.playctrl_library.strip()
        if not playctrl_library or "\x00" in playctrl_library:
            raise PyEzvizError("HCNetSDK PlayCtrl library name is invalid")
        return {
            "api": self.api,
            "sPlayCtrlPath": playctrl_library,
        }


@dataclass(frozen=True)
class HcNetSdkGetErrorMsgRequest:
    """Native ``NET_DVR_GetErrorMsg`` call shape."""

    error_code: int | None = None
    api: str = HCNETSDK_GET_ERROR_MSG

    def to_native_args_hint(self) -> dict[str, Any]:
        """Return native argument names for resolving an HCNetSDK error."""
        if self.api != HCNETSDK_GET_ERROR_MSG:
            raise PyEzvizError("HCNetSDK error-message API is unsupported")
        hint: dict[str, Any] = {
            "api": self.api,
            "pErrorNo": "<INT_PTR>",
        }
        if self.error_code is not None:
            if self.error_code < 0:
                raise PyEzvizError("HCNetSDK error code must be non-negative")
            hint["intPointerValue"] = self.error_code
        return hint


@dataclass(frozen=True)
class HcNetSdkLogoutRequest:
    """Native ``NET_DVR_Logout_V30`` call shape."""

    login_id: int
    api: str = HCNETSDK_LOGOUT_V30

    def to_native_args_hint(self) -> dict[str, Any]:
        """Return native argument names for logging out a local SDK session."""
        if self.login_id < 0:
            raise PyEzvizError("HCNetSDK logout requires a successful login id")
        if self.api != HCNETSDK_LOGOUT_V30:
            raise PyEzvizError("HCNetSDK logout API is unsupported")
        return {
            "api": self.api,
            "lUserID": self.login_id,
        }


@dataclass(frozen=True)
class HcNetSdkPlayDataCallbackRequest:
    """Native ``NET_DVR_SetPlayDataCallBack`` / ``V40`` call shape."""

    play_handle: int
    callback: str | None = None
    user_data: str | int | None = None
    api: str = HCNETSDK_SET_PLAY_DATA_CALLBACK

    @property
    def is_v40(self) -> bool:
        """Return whether this is the V40 callback setter variant."""
        return self.api == HCNETSDK_SET_PLAY_DATA_CALLBACK_V40

    def to_native_args_hint(self) -> dict[str, Any]:
        """Return native argument names for registering playback data callbacks."""
        if self.play_handle < 0:
            raise PyEzvizError("HCNetSDK playback handle must be non-negative")
        if self.api not in {
            HCNETSDK_SET_PLAY_DATA_CALLBACK,
            HCNETSDK_SET_PLAY_DATA_CALLBACK_V40,
        }:
            raise PyEzvizError("HCNetSDK playback data callback API is unsupported")
        if self.is_v40:
            return {
                "api": self.api,
                "lPlayHandle": self.play_handle,
                "fPlayDataCallBack_V40": self.callback or "<PlayDataCallBack_V40>",
                "pUser": self.user_data if self.user_data is not None else None,
                "callbackSignature": (
                    "void(int playHandle, int dataType, byte* buffer, uint length, void* user)"
                ),
            }
        return {
            "api": self.api,
            "lPlayHandle": self.play_handle,
            "fPlayDataCallBack": self.callback or "<PlayDataCallBack>",
            "dwUser": self.user_data if self.user_data is not None else 0,
            "callbackSignature": (
                "void(int playHandle, uint dataType, byte* buffer, uint length, uint user)"
            ),
        }
