"""Protocol for the subset of client methods used by device wrappers."""

from __future__ import annotations

from typing import Any, Protocol


class EzvizClientProtocol(Protocol):
    """Structural client contract consumed by camera/light/plug wrappers."""

    def get_device_infos(self, *args: Any, **kwargs: Any) -> dict[Any, Any]:
        """See :class:`pyezvizapi.client.EzvizClient`."""
        pass
    def get_device_messages_list(self, *args: Any, **kwargs: Any) -> Any:
        """See :class:`pyezvizapi.client.EzvizClient`."""
        pass
    def ptz_control(self, *args: Any, **kwargs: Any) -> Any:
        """See :class:`pyezvizapi.client.EzvizClient`."""
        pass
    def ptz_control_coordinates(self, *args: Any, **kwargs: Any) -> Any:
        """See :class:`pyezvizapi.client.EzvizClient`."""
        pass
    def remote_unlock(self, *args: Any, **kwargs: Any) -> Any:
        """See :class:`pyezvizapi.client.EzvizClient`."""
        pass
    def remote_lock(self, *args: Any, **kwargs: Any) -> Any:
        """See :class:`pyezvizapi.client.EzvizClient`."""
        pass
    def set_camera_defence(self, *args: Any, **kwargs: Any) -> Any:
        """See :class:`pyezvizapi.client.EzvizClient`."""
        pass
    def alarm_sound(self, *args: Any, **kwargs: Any) -> Any:
        """See :class:`pyezvizapi.client.EzvizClient`."""
        pass
    def do_not_disturb(self, *args: Any, **kwargs: Any) -> Any:
        """See :class:`pyezvizapi.client.EzvizClient`."""
        pass
    def detection_sensibility(self, *args: Any, **kwargs: Any) -> Any:
        """See :class:`pyezvizapi.client.EzvizClient`."""
        pass
    def switch_status(self, *args: Any, **kwargs: Any) -> Any:
        """See :class:`pyezvizapi.client.EzvizClient`."""
        pass
    def sound_alarm(self, *args: Any, **kwargs: Any) -> Any:
        """See :class:`pyezvizapi.client.EzvizClient`."""
        pass
    def api_set_defence_schedule(self, *args: Any, **kwargs: Any) -> Any:
        """See :class:`pyezvizapi.client.EzvizClient`."""
        pass
    def set_battery_camera_work_mode(self, *args: Any, **kwargs: Any) -> Any:
        """See :class:`pyezvizapi.client.EzvizClient`."""
        pass
    def set_device_feature_by_key(self, *args: Any, **kwargs: Any) -> Any:
        """See :class:`pyezvizapi.client.EzvizClient`."""
        pass
    def set_switch(self, *args: Any, **kwargs: Any) -> Any:
        """See :class:`pyezvizapi.client.EzvizClient`."""
        pass
