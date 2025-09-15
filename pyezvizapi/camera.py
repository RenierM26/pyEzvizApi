"""pyezvizapi camera api."""

from __future__ import annotations

import datetime
import logging
from typing import TYPE_CHECKING, Any, Literal, TypedDict, cast

from .constants import BatteryCameraWorkMode, DeviceSwitchType, SoundMode
from .exceptions import PyEzvizError
from .models import EzvizDeviceRecord
from .utils import (
    compute_motion_from_alarm,
    fetch_nested_value,
    parse_timezone_value,
    string_to_list,
)

if TYPE_CHECKING:
    from .client import EzvizClient


_LOGGER = logging.getLogger(__name__)


class CameraStatus(TypedDict, total=False):
    """Typed mapping for Ezviz camera status payload."""

    serial: str
    name: str | None
    version: str | None
    upgrade_available: bool
    status: int | None
    device_category: str | None
    device_sub_category: str | None
    upgrade_percent: Any
    upgrade_in_progress: bool
    latest_firmware_info: Any
    alarm_notify: bool
    alarm_schedules_enabled: bool
    alarm_sound_mod: str
    encrypted: bool
    encrypted_pwd_hash: Any
    local_ip: str
    wan_ip: Any
    mac_address: Any
    offline_notify: bool
    last_offline_time: Any
    local_rtsp_port: str
    supported_channels: Any
    battery_level: Any
    PIR_Status: Any
    Motion_Trigger: bool
    Seconds_Last_Trigger: Any
    last_alarm_time: Any
    last_alarm_pic: str
    last_alarm_type_code: str
    last_alarm_type_name: str
    cam_timezone: Any
    push_notify_alarm: bool
    push_notify_call: bool
    alarm_light_luminance: Any
    Alarm_DetectHumanCar: Any
    diskCapacity: Any
    NightVision_Model: Any
    battery_camera_work_mode: Any
    Alarm_AdvancedDetect: Any
    resouceid: Any
    supportExt: Any
    # Backwards-compatibility aliases used by integration layers
    optionals: Any
    switches: dict[int, bool]
    # Note: Top-level pagelist keys like 'WIFI', 'SWITCH', 'STATUS', etc. are
    # merged into the returned dict dynamically in status() to allow consumers
    # to access new data without library changes. We intentionally avoid adding
    # parallel curated aliases like 'wifiInfos', 'switches', or 'optionals'.


class EzvizCamera:
    """Representation of an Ezviz camera device.

    Wraps the Ezviz pagelist/device mapping and surfaces a stable API
    to query status and perform common actions (PTZ, switches, alarm
    settings, etc.). Designed for use in Home Assistant and scripts.
    """

    def __init__(
        self,
        client: EzvizClient,
        serial: str,
        device_obj: EzvizDeviceRecord | dict | None = None,
    ) -> None:
        """Initialize the camera object.

        Raises:
            InvalidURL: If the API endpoint/connection is invalid when fetching device info.
            HTTPError: If the API returns a non-success HTTP status while fetching device info.
            PyEzvizError: On Ezviz API contract errors or decoding failures.
        """
        self._client = client
        self._serial = serial
        self._alarmmotiontrigger: dict[str, Any] = {
            "alarm_trigger_active": False,
            "timepassed": None,
            "last_alarm_time_str": None,
        }
        self._record: EzvizDeviceRecord | None = None

        if device_obj is None:
            self._device = self._client.get_device_infos(self._serial)
        elif isinstance(device_obj, EzvizDeviceRecord):
            # Accept either a typed record or the original dict
            self._record = device_obj
            self._device = dict(device_obj.raw)
        else:
            self._device = device_obj or {}
        self._last_alarm: dict[str, Any] = {}
        self._switch: dict[int, bool] = {}
        if self._record and getattr(self._record, "switches", None):
            self._switch = {int(k): bool(v) for k, v in self._record.switches.items()}
        else:
            switches = self._device.get("SWITCH") or []
            if isinstance(switches, list):
                for item in switches:
                    if not isinstance(item, dict):
                        continue
                    t = item.get("type")
                    en = item.get("enable")
                    if isinstance(t, int) and isinstance(en, (bool, int)):
                        self._switch[t] = bool(en)

    def fetch_key(self, keys: list[Any], default_value: Any = None) -> Any:
        """Fetch dictionary key."""
        return fetch_nested_value(self._device, keys, default_value)

    def _alarm_list(self) -> None:
        """Get last alarm info for this camera's self._serial.

        Raises:
            InvalidURL: If the API endpoint/connection is invalid.
            HTTPError: If the API returns a non-success HTTP status.
            PyEzvizError: On Ezviz API contract errors or decoding failures.
        """
        _alarmlist = self._client.get_alarminfo(self._serial)

        total = fetch_nested_value(_alarmlist, ["page", "totalResults"], 0)
        if total and total > 0:
            self._last_alarm = _alarmlist.get("alarms", [{}])[0]
            _LOGGER.debug(
                "Fetched last alarm for %s: %s", self._serial, self._last_alarm
            )
            self._motion_trigger()
        else:
            _LOGGER.debug("No alarms found for %s", self._serial)

    def _local_ip(self) -> str:
        """Fix empty ip value for certain cameras."""
        wifi = (self._record.wifi if self._record else self._device.get("WIFI")) or {}
        addr = wifi.get("address")
        if isinstance(addr, str) and addr != "0.0.0.0":
            return addr

        # Seems to return none or 0.0.0.0 on some.
        conn = (
            self._record.connection if self._record else self._device.get("CONNECTION")
        ) or {}
        local_ip = conn.get("localIp")
        if isinstance(local_ip, str) and local_ip != "0.0.0.0":
            return local_ip

        return "0.0.0.0"

    def _motion_trigger(self) -> None:
        """Create motion sensor based on last alarm time.

        Prefer numeric epoch fields if available to avoid parsing localized strings.
        """
        tzinfo = self._get_tzinfo()
        active, seconds_out, last_alarm_str = compute_motion_from_alarm(
            self._last_alarm, tzinfo
        )

        self._alarmmotiontrigger = {
            "alarm_trigger_active": active,
            "timepassed": seconds_out,
            "last_alarm_time_str": last_alarm_str,
        }

    def _get_tzinfo(self) -> datetime.tzinfo:
        """Return tzinfo from camera setting if recognizable, else local tzinfo."""
        tz_val = self.fetch_key(["STATUS", "optionals", "timeZone"])
        return parse_timezone_value(tz_val)

    def _is_alarm_schedules_enabled(self) -> bool:
        """Check if alarm schedules enabled."""
        plans = self.fetch_key(["TIME_PLAN"], []) or []
        sched = next(
            (
                item
                for item in plans
                if isinstance(item, dict) and item.get("type") == 2
            ),
            None,
        )
        return bool(sched and sched.get("enable"))

    def status(self, refresh: bool = True) -> CameraStatus:
        """Return the status of the camera.

        refresh: if True, updates alarm info via network before composing status.

        Raises:
            InvalidURL: If the API endpoint/connection is invalid while refreshing.
            HTTPError: If the API returns a non-success HTTP status while refreshing.
            PyEzvizError: On Ezviz API contract errors or decoding failures.
        """
        if refresh:
            self._alarm_list()

        name = (
            self._record.name
            if self._record
            else self.fetch_key(["deviceInfos", "name"])
        )
        version = (
            self._record.version
            if self._record
            else self.fetch_key(["deviceInfos", "version"])
        )
        dev_status = (
            self._record.status
            if self._record
            else self.fetch_key(["deviceInfos", "status"])
        )
        device_category = (
            self._record.device_category
            if self._record
            else self.fetch_key(["deviceInfos", "deviceCategory"])
        )
        device_sub_category = (
            self._record.device_sub_category
            if self._record
            else self.fetch_key(["deviceInfos", "deviceSubCategory"])
        )
        conn = (
            self._record.connection if self._record else self._device.get("CONNECTION")
        ) or {}
        wan_ip = conn.get("netIp") or self.fetch_key(["CONNECTION", "netIp"])

        data: dict[str, Any] = {
            "serial": self._serial,
            "name": name,
            "version": version,
            "upgrade_available": bool(
                self.fetch_key(["UPGRADE", "isNeedUpgrade"]) == 3
            ),
            "status": dev_status,
            "device_category": device_category,
            "device_sub_category": device_sub_category,
            "upgrade_percent": self.fetch_key(["STATUS", "upgradeProcess"]),
            "upgrade_in_progress": bool(
                self.fetch_key(["STATUS", "upgradeStatus"]) == 0
            ),
            "latest_firmware_info": self.fetch_key(["UPGRADE", "upgradePackageInfo"]),
            "alarm_notify": bool(self.fetch_key(["STATUS", "globalStatus"])),
            "alarm_schedules_enabled": self._is_alarm_schedules_enabled(),
            "alarm_sound_mod": SoundMode(
                self.fetch_key(["STATUS", "alarmSoundMode"], -1)
            ).name,
            "encrypted": bool(self.fetch_key(["STATUS", "isEncrypt"])),
            "encrypted_pwd_hash": self.fetch_key(["STATUS", "encryptPwd"]),
            "local_ip": self._local_ip(),
            "wan_ip": wan_ip,
            "supportExt": (
                self._record.support_ext
                if self._record
                else self.fetch_key(
                    ["deviceInfos", "supportExt"]
                )  # convenience top-level
            ),
            # Backwards-compatibility aliases
            "optionals": self.fetch_key(["STATUS", "optionals"]),
            "switches": self._switch,
            "mac_address": self.fetch_key(["deviceInfos", "mac"]),
            "offline_notify": bool(self.fetch_key(["deviceInfos", "offlineNotify"])),
            "last_offline_time": self.fetch_key(["deviceInfos", "offlineTime"]),
            "local_rtsp_port": (
                "554"
                if (port := self.fetch_key(["CONNECTION", "localRtspPort"], "554"))
                in (0, "0", None)
                else str(port)
            ),
            "supported_channels": self.fetch_key(["deviceInfos", "channelNumber"]),
            "battery_level": self.fetch_key(["STATUS", "optionals", "powerRemaining"]),
            "PIR_Status": self.fetch_key(["STATUS", "pirStatus"]),
            "Motion_Trigger": self._alarmmotiontrigger["alarm_trigger_active"],
            "Seconds_Last_Trigger": self._alarmmotiontrigger["timepassed"],
            # Keep last_alarm_time in sync with the time actually used to
            # compute Motion_Trigger/Seconds_Last_Trigger.
            "last_alarm_time": self._alarmmotiontrigger.get("last_alarm_time_str")
            or self._last_alarm.get("alarmStartTimeStr"),
            "last_alarm_pic": self._last_alarm.get(
                "picUrl",
                "https://eustatics.ezvizlife.com/ovs_mall/web/img/index/EZVIZ_logo.png?ver=3007907502",
            ),
            "last_alarm_type_code": self._last_alarm.get("alarmType", "0000"),
            "last_alarm_type_name": self._last_alarm.get("sampleName", "NoAlarm"),
            "cam_timezone": self.fetch_key(["STATUS", "optionals", "timeZone"]),
            "push_notify_alarm": not bool(self.fetch_key(["NODISTURB", "alarmEnable"])),
            "push_notify_call": not bool(
                self.fetch_key(["NODISTURB", "callingEnable"])
            ),
            "alarm_light_luminance": self.fetch_key(
                ["STATUS", "optionals", "Alarm_Light", "luminance"]
            ),
            "Alarm_DetectHumanCar": self.fetch_key(
                ["STATUS", "optionals", "Alarm_DetectHumanCar", "type"]
            ),
            "diskCapacity": string_to_list(
                self.fetch_key(["STATUS", "optionals", "diskCapacity"])
            ),
            "NightVision_Model": self.fetch_key(
                ["STATUS", "optionals", "NightVision_Model"]
            ),
            "battery_camera_work_mode": self.fetch_key(
                ["STATUS", "optionals", "batteryCameraWorkMode"], -1
            ),
            "Alarm_AdvancedDetect": self.fetch_key(
                ["STATUS", "optionals", "Alarm_AdvancedDetect", "type"]
            ),
            "resouceid": self.fetch_key(["resourceInfos", 0, "resourceId"]),
        }

        # Include all top-level keys from the pagelist/device mapping to allow
        # consumers to access new fields without library updates. We do not
        # overwrite curated keys above if there is a name collision.
        source_map = dict(self._record.raw) if self._record else dict(self._device)
        for key, value in source_map.items():
            if key not in data:
                data[key] = value

        return cast(CameraStatus, data)

    # essential_status() was removed in favor of including all top-level
    # pagelist keys directly in status().

    def move(
        self, direction: Literal["right", "left", "down", "up"], speed: int = 5
    ) -> bool:
        """Move camera in a given direction.

        direction: one of "right", "left", "down", "up".
        speed: movement speed, expected range 1..10 (inclusive).

        Raises:
            PyEzvizError: On invalid parameters or API failures.
            InvalidURL: If the API endpoint/connection is invalid.
            HTTPError: If the API returns a non-success HTTP status.
        """
        if speed < 1 or speed > 10:
            raise PyEzvizError(f"Invalid speed: {speed}. Expected 1..10")

        dir_up = direction.upper()
        _LOGGER.debug("PTZ %s at speed %s for %s", dir_up, speed, self._serial)
        # launch the start command
        self._client.ptz_control(dir_up, self._serial, "START", speed)
        # launch the stop command
        self._client.ptz_control(dir_up, self._serial, "STOP", speed)

        return True

    # Public helper to refresh alarms without calling status()
    def refresh_alarms(self) -> None:
        """Refresh last alarm information from the API."""
        self._alarm_list()

    def move_coordinates(self, x_axis: float, y_axis: float) -> bool:
        """Move camera to specified coordinates.

        Raises:
            PyEzvizError: On API failures.
            InvalidURL: If the API endpoint/connection is invalid.
            HTTPError: If the API returns a non-success HTTP status.
        """
        _LOGGER.debug(
            "PTZ move to coordinates x=%s y=%s for %s", x_axis, y_axis, self._serial
        )
        return self._client.ptz_control_coordinates(self._serial, x_axis, y_axis)

    def door_unlock(self) -> bool:
        """Unlock the door lock.

        Raises:
            PyEzvizError: On API failures.
            InvalidURL: If the API endpoint/connection is invalid.
            HTTPError: If the API returns a non-success HTTP status.
        """
        _LOGGER.debug("Remote door unlock for %s", self._serial)
        user = str(getattr(self._client, "_token", {}).get("username", ""))
        return self._client.remote_unlock(self._serial, user, 2)

    def gate_unlock(self) -> bool:
        """Unlock the gate lock.

        Raises:
            PyEzvizError: On API failures.
            InvalidURL: If the API endpoint/connection is invalid.
            HTTPError: If the API returns a non-success HTTP status.
        """
        _LOGGER.debug("Remote gate unlock for %s", self._serial)
        user = str(getattr(self._client, "_token", {}).get("username", ""))
        return self._client.remote_unlock(self._serial, user, 1)

    def alarm_notify(self, enable: bool) -> bool:
        """Enable/Disable camera notification when movement is detected.

        Raises:
            PyEzvizError: On API failures.
            InvalidURL: If the API endpoint/connection is invalid.
            HTTPError: If the API returns a non-success HTTP status.
        """
        _LOGGER.debug("Set alarm notify=%s for %s", enable, self._serial)
        return self._client.set_camera_defence(self._serial, int(enable))

    def alarm_sound(self, sound_type: int) -> bool:
        """Enable/Disable camera sound when movement is detected.

        Raises:
            PyEzvizError: On API failures.
            InvalidURL: If the API endpoint/connection is invalid.
            HTTPError: If the API returns a non-success HTTP status.
        """
        # we force enable = 1 , to make sound...
        _LOGGER.debug("Trigger alarm sound type=%s for %s", sound_type, self._serial)
        return self._client.alarm_sound(self._serial, sound_type, 1)

    def do_not_disturb(self, enable: bool) -> bool:
        """Enable/Disable do not disturb.

        if motion triggers are normally sent to your device as a
        notification, then enabling this feature stops these notification being sent.
        The alarm event is still recorded in the EzViz app as normal.

        Raises:
            PyEzvizError: On API failures.
            InvalidURL: If the API endpoint/connection is invalid.
            HTTPError: If the API returns a non-success HTTP status.
        """
        _LOGGER.debug("Set do_not_disturb=%s for %s", enable, self._serial)
        return self._client.do_not_disturb(self._serial, int(enable))

    def alarm_detection_sensitivity(
        self, sensitivity: int, type_value: int = 0
    ) -> bool:
        """Set motion detection sensitivity.

        sensitivity: device-specific integer scale.
        type_value: optional type selector for devices supporting multiple types.

        Raises:
            PyEzvizError: On API failures.
            InvalidURL: If the API endpoint/connection is invalid.
            HTTPError: If the API returns a non-success HTTP status.
        """
        _LOGGER.debug(
            "Set detection sensitivity=%s type=%s for %s",
            sensitivity,
            type_value,
            self._serial,
        )
        return bool(
            self._client.detection_sensibility(self._serial, sensitivity, type_value)
        )

    # Backwards-compatible alias (deprecated)
    def alarm_detection_sensibility(
        self, sensibility: int, type_value: int = 0
    ) -> bool:
        """Deprecated: use alarm_detection_sensitivity()."""
        return self.alarm_detection_sensitivity(sensibility, type_value)

    # Generic switch helper
    def set_switch(self, switch: DeviceSwitchType, enable: bool = False) -> bool:
        """Set a device switch to enabled/disabled.

        Raises:
            PyEzvizError: On API failures.
            InvalidURL: If the API endpoint/connection is invalid.
            HTTPError: If the API returns a non-success HTTP status.
        """
        _LOGGER.debug("Set switch %s=%s for %s", switch.name, enable, self._serial)
        return self._client.switch_status(self._serial, switch.value, int(enable))

    def switch_device_audio(self, enable: bool = False) -> bool:
        """Switch audio status on a device.

        Raises:
            PyEzvizError, InvalidURL, HTTPError
        """
        return self.set_switch(DeviceSwitchType.SOUND, enable)

    def switch_device_state_led(self, enable: bool = False) -> bool:
        """Switch led status on a device.

        Raises:
            PyEzvizError, InvalidURL, HTTPError
        """
        return self.set_switch(DeviceSwitchType.LIGHT, enable)

    def switch_device_ir_led(self, enable: bool = False) -> bool:
        """Switch ir status on a device.

        Raises:
            PyEzvizError, InvalidURL, HTTPError
        """
        return self.set_switch(DeviceSwitchType.INFRARED_LIGHT, enable)

    def switch_privacy_mode(self, enable: bool = False) -> bool:
        """Switch privacy mode on a device.

        Raises:
            PyEzvizError, InvalidURL, HTTPError
        """
        return self.set_switch(DeviceSwitchType.PRIVACY, enable)

    def switch_sleep_mode(self, enable: bool = False) -> bool:
        """Switch sleep mode on a device.

        Raises:
            PyEzvizError, InvalidURL, HTTPError
        """
        return self.set_switch(DeviceSwitchType.SLEEP, enable)

    def switch_follow_move(self, enable: bool = False) -> bool:
        """Switch follow move.

        Raises:
            PyEzvizError, InvalidURL, HTTPError
        """
        return self.set_switch(DeviceSwitchType.MOBILE_TRACKING, enable)

    def switch_sound_alarm(self, enable: int | bool = False) -> bool:
        """Sound alarm on a device.

        Raises:
            PyEzvizError, InvalidURL, HTTPError
        """
        _LOGGER.debug("Set sound alarm enable=%s for %s", enable, self._serial)
        return self._client.sound_alarm(self._serial, int(enable))

    def change_defence_schedule(self, schedule: str, enable: int = 0) -> bool:
        """Change defence schedule. Requires json formatted schedules.

        Raises:
            PyEzvizError, InvalidURL, HTTPError
        """
        _LOGGER.debug(
            "Change defence schedule enable=%s for %s payload_len=%s",
            enable,
            self._serial,
            len(schedule) if isinstance(schedule, str) else None,
        )
        return self._client.api_set_defence_schedule(self._serial, schedule, enable)

    def set_battery_camera_work_mode(self, work_mode: BatteryCameraWorkMode) -> bool:
        """Change work mode for battery powered camera device.

        Raises:
            PyEzvizError, InvalidURL, HTTPError
        """
        _LOGGER.debug(
            "Set battery camera work mode=%s for %s", work_mode.name, self._serial
        )
        return self._client.set_battery_camera_work_mode(self._serial, work_mode.value)
