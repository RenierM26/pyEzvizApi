"""EZVIZ capabilities helpers, independent of application lifecycle."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any


class SupportExtView:
    """Lightweight helper for inspecting supportExt capabilities."""

    __slots__ = ("_data",)

    def __init__(self, data: Mapping[str, Any] | None = None) -> None:
        """Store a normalized copy of the provided supportExt mapping."""
        self._data: dict[str, Any] = dict(data) if isinstance(data, Mapping) else {}

    @classmethod
    def from_camera_data(cls, camera_data: Mapping[str, Any]) -> SupportExtView:
        """Build a view from raw camera payload."""

        support_ext = camera_data.get("supportExt")
        if not isinstance(support_ext, Mapping):
            device_infos = camera_data.get("deviceInfos")
            if isinstance(device_infos, Mapping):
                support_ext = device_infos.get("supportExt")
        return cls(support_ext if isinstance(support_ext, Mapping) else None)

    def as_dict(self) -> dict[str, Any]:
        """Return the underlying mapping."""

        return self._data

    def get(self, key: str, default: Any | None = None) -> Any | None:
        """Fetch a raw supportExt value."""

        return self._data.get(key, default)

    @staticmethod
    def _tokens(value: Any) -> set[str]:
        """Return comma-delimited tokens from a raw supportExt value."""
        if value is None:
            return set()
        return {token.strip() for token in str(value).split(",") if token.strip()}

    @staticmethod
    def normalize_values(values: Iterable[str] | None) -> tuple[str, ...]:
        """Normalize candidate values to a tuple of stripped strings."""
        if values is None:
            return ()
        return tuple(stripped for stripped in (str(raw).strip() for raw in values) if stripped)

    @classmethod
    def _values_match(cls, raw_value: Any, expected_values: tuple[str, ...]) -> bool:
        """Return True if ``raw_value`` satisfies normalized candidates."""

        if not expected_values:
            return True

        raw_str = str(raw_value).strip()
        if not raw_str:
            return False

        if raw_str in expected_values:
            return True

        raw_tokens = cls._tokens(raw_value)
        if not raw_tokens:
            raw_tokens = {raw_str}

        for candidate in expected_values:
            candidate_tokens = cls._tokens(candidate)
            if candidate_tokens and candidate_tokens <= raw_tokens:
                return True

        return False

    def match_any(self, keys: Iterable[str], normalized_values: tuple[str, ...]) -> bool:
        """Return True if any key exists (and matches optional values)."""

        for key in keys:
            raw_value = self._data.get(key)
            if raw_value is None:
                continue
            if not normalized_values:
                return True
            if self._values_match(raw_value, normalized_values):
                return True
        return False

    def has(self, key: str, expected_values: Iterable[str] | None = None) -> bool:
        """Check if the given key (and optional values) exist."""

        if not expected_values:
            normalized: tuple[str, ...] = ()
        else:
            normalized = self.normalize_values(expected_values)
            if not normalized:
                return False
        return self.match_any((key,), normalized)


def support_ext_dict(camera_data: dict[str, Any]) -> dict[str, Any]:
    """Return supportExt mapping if present."""

    return SupportExtView.from_camera_data(camera_data).as_dict()


def support_ext_has(
    camera_data: dict[str, Any], key: str, expected_values: list[str] | None = None
) -> bool:
    """Check if supportExt contains the key (and optional values)."""
    view = SupportExtView.from_camera_data(camera_data)
    return view.has(key, expected_values)
