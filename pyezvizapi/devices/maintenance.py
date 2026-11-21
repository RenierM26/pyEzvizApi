"""Classify fresh maintenance observations without issuing device commands."""

from collections.abc import Iterable, Mapping
from typing import Any, Literal

from pyezvizapi.devices.firmware import firmware_status


def reboot_recovery_observed(online_samples: Iterable[bool | None]) -> bool:
    """Detect offline-to-online recovery in ordered, post-request observations.

    Missing observations do not count as offline. Recovery is evidence of
    connectivity returning, not proof that the reboot caused the outage.
    """
    saw_offline = False
    for online in online_samples:
        if online is False:
            saw_offline = True
        elif online is True and saw_offline:
            return True
    return False


def firmware_upgrade_outcome(
    camera_data: Mapping[str, Any],
    *,
    target_version: str,
    previous_version: str,
) -> Literal["pending", "complete", "failed", "unknown"]:
    """Compare a fresh device report with distinct baseline and target versions."""
    info = camera_data.get("deviceInfos")
    version = info.get("version") if isinstance(info, Mapping) else None
    status = firmware_status(camera_data.get("UPGRADE"), camera_data.get("STATUS"))
    if status["upgrade_in_progress"]:
        return "pending"
    if status["upgrade_phase"] == "failed":
        return "failed"
    if (
        status["upgrade_phase"] == "current"
        and target_version.strip()
        and previous_version.strip()
        and target_version != previous_version
        and version == target_version
    ):
        return "complete"
    return "unknown"
