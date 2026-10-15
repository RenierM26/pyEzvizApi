"""Offline advisory playback capabilities from the official app's conditions."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import json
import re
from typing import Any


@dataclass(frozen=True)
class EzvizAppPlaybackSupport:
    """Player support flags, not active sound state or an AV clock contract.

    ``None`` means metadata is unavailable/malformed. A valid map missing 915
    follows the app's disabled default. Smoothing belongs to a live player;
    these flags never authorize a timestamp shift or change a camera setting.
    """

    audio_on_off: bool | None
    auto_smooth_play: bool | None


def _capability_integer(value: object) -> int | None:
    # DeviceParam uses Kotlin toIntOrNull: no whitespace, CSV, floats or bools.
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if -(2**31) <= value < 2**31 else None
    if isinstance(value, str) and re.fullmatch(r"[+-]?[0-9]+", value):
        digits = value.lstrip("+-").lstrip("0")
        if len(digits) > 10:
            return None
        parsed = int(digits or "0") * (-1 if value.startswith("-") else 1)
        return parsed if -(2**31) <= parsed < 2**31 else None
    return None


def inspect_app_playback_support(device: Mapping[str, Any]) -> EzvizAppPlaybackSupport:
    """Inspect supplied device metadata without account/network probes.

    Verified EZVIZ 7.4.1 paths: audio on/off uses supportExt 63; LivePlayCore
    enables smoothing only for DeviceParam support 915 == 1. Its EZVIZ converter
    ignores the named ``support_auto_smooth_play`` fallback and reads numeric
    support. Do not substitute FEATURE or the distinct ezDeviceCapability map.
    Missing/invalid 915 values in an available map are disabled by the app.
    """
    info = device.get("deviceInfos")
    if not isinstance(info, Mapping):
        return EzvizAppPlaybackSupport(None, None)
    support = info.get("supportExt")
    if isinstance(support, str):
        try:
            support = json.loads(support)
        except ValueError:
            return EzvizAppPlaybackSupport(None, None)
    if not isinstance(support, Mapping):
        return EzvizAppPlaybackSupport(None, None)
    audio = _capability_integer(support.get("63"))
    smooth = _capability_integer(support.get("915"))
    return EzvizAppPlaybackSupport(audio == 1, smooth == 1)
