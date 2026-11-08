"""Shared firmware status semantics observed in the native app's update UI."""

from collections.abc import Mapping
from typing import Any, TypedDict

_PHASES = {
    0: "upgrading",
    1: "rebooting",
    2: "current",
    3: "failed",
    14: "waiting",
    15: "downloading",
}
_ACTIVE = frozenset((0, 1, 14, 15))


class FirmwareStatus(TypedDict):
    upgrade_available: bool
    upgrade_in_progress: bool
    upgrade_status: int | None
    upgrade_phase: str | None


def integer_code(value: Any) -> int | None:
    """Accept integer wire codes, not bools or lossy floating-point coercions."""
    if type(value) is int:
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            pass
    return None


def firmware_status(upgrade: Any, status: Any) -> FirmwareStatus:
    """Keep legacy boolean flags and expose the normalized code/known UI phase.

    Unknown or model-specific codes (including 17) retain their numeric value;
    they do not acquire a guessed phase. Availability follows hasUpgrade()>0.
    """
    upgrade = upgrade if isinstance(upgrade, Mapping) else {}
    status = status if isinstance(status, Mapping) else {}
    needed = integer_code(upgrade.get("isNeedUpgrade"))
    code = integer_code(status.get("upgradeStatus"))
    return {
        "upgrade_available": needed is not None and needed > 0,
        "upgrade_in_progress": code in _ACTIVE,
        "upgrade_status": code,
        "upgrade_phase": _PHASES.get(code) if code is not None else None,
    }
