"""controls protocol values and pure helpers; dependency-closed implementation."""

from __future__ import annotations

from pyezvizapi.streaming.local.hcnetsdk.constants import (
    EZVIZ_LAN_PTZ_SPEED_DEFAULT,
    HCNETSDK_PTZ_CONTROL_WITH_SPEED_OTHER,
    HCNETSDK_PTZ_PRESET_OTHER,
    PyEzvizError,
    dataclass,
)
from pyezvizapi.streaming.local.hcnetsdk.protocol_types.values import (
    _ability_option_tuple,
)


@dataclass(frozen=True)
class EzvizLanPtzAbility:
    """Parsed PTZ ability values returned by local HCNetSDK ability XML."""

    control_types: str | None = None
    park_action_types: str | None = None
    schedule_task_types: str | None = None
    privacy_mask_enable: bool | None = None
    mirror_range: str | None = None

    @property
    def control_type_options(self) -> tuple[str, ...]:
        """Return comma-separated PTZ control options as a tuple."""
        return _ability_option_tuple(self.control_types)


@dataclass(frozen=True)
class HcNetSdkPtzControlRequest:
    """Native ``NET_DVR_PTZControlWithSpeed_Other`` call shape."""

    login_id: int
    channel: int
    command: int
    stop: int
    speed: int = EZVIZ_LAN_PTZ_SPEED_DEFAULT
    api: str = HCNETSDK_PTZ_CONTROL_WITH_SPEED_OTHER

    def to_native_args_hint(self) -> dict[str, int | str]:
        """Return the native argument names for a local HCNetSDK bridge."""
        if self.login_id < 0:
            raise PyEzvizError("HCNetSDK PTZ control requires a successful login id")
        if self.channel < 0:
            raise PyEzvizError("HCNetSDK PTZ control channel must be non-negative")
        if self.command < 0:
            raise PyEzvizError("HCNetSDK PTZ control command must be non-negative")
        if self.stop not in {0, 1}:
            raise PyEzvizError("HCNetSDK PTZ control stop flag must be 0 or 1")
        if self.speed < 0:
            raise PyEzvizError("HCNetSDK PTZ control speed must be non-negative")
        return {
            "api": self.api,
            "lUserID": self.login_id,
            "lChannel": self.channel,
            "dwPTZCommand": self.command,
            "dwStop": self.stop,
            "dwSpeed": self.speed,
        }


@dataclass(frozen=True)
class HcNetSdkPtzPresetRequest:
    """Native ``NET_DVR_PTZPreset_Other`` call shape."""

    login_id: int
    channel: int
    command: int
    preset_index: int = 0
    api: str = HCNETSDK_PTZ_PRESET_OTHER

    def to_native_args_hint(self) -> dict[str, int | str]:
        """Return the native argument names for a local HCNetSDK bridge."""
        if self.login_id < 0:
            raise PyEzvizError("HCNetSDK PTZ preset requires a successful login id")
        if self.channel < 0:
            raise PyEzvizError("HCNetSDK PTZ preset channel must be non-negative")
        if self.command not in {8, 9, 39}:
            raise PyEzvizError("HCNetSDK PTZ preset command is unsupported")
        if self.preset_index < 0:
            raise PyEzvizError("HCNetSDK PTZ preset index must be non-negative")
        return {
            "api": self.api,
            "lUserID": self.login_id,
            "lChannel": self.channel,
            "dwPTZPresetCmd": self.command,
            "dwPresetIndex": self.preset_index,
        }
