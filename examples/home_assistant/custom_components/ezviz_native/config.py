"""Load supplied local credentials without contacting any camera or account."""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
from pathlib import Path
import re
from typing import Any

from pyezvizapi.hcnetsdk import EzvizCasDeviceInfo, HcNetSdkLanEndpoint
from pyezvizapi.local_stream_transport import EzvizLocalSdkCredentials
from pyezvizapi.native_stream import NativeStreamOptions, NativeTrackSelection


@dataclass(frozen=True)
class LensSettings:
    """An explicit logical child lens, not a discovered ordinal or device id."""

    key: str
    name: str
    selection: NativeTrackSelection


@dataclass(frozen=True, repr=False)
class Settings:
    """Private, fully validated local source settings."""

    credentials: EzvizLocalSdkCredentials
    channel: int
    options: NativeStreamOptions
    nalu_header_size: int
    relay_api_port: int | None = None
    relay_rtsp_port: int = 8554
    relay_source_clock: bool = False
    relay_atomic_ownership: bool = False
    lenses: tuple[LensSettings, ...] = ()
    group_profile: str | None = None
    credential_revision: str | None = None
    relay_native_opus: bool = False
    relay_hls_fallback: bool = False


def integer(value: Any, low: int, high: int) -> int:
    """Reject coercion of booleans/strings and out-of-range source selectors."""
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ValueError("Invalid integer setting")
    return value


def text(value: Any) -> str:
    """Require bounded, nonempty text without normalizing credentials."""
    if not isinstance(value, str) or not value or len(value) > 1024:
        raise ValueError("Invalid text setting")
    return value


def load_settings(data: dict[str, Any]) -> Settings:
    """Read one admin-supplied, bounded credential document; no discovery/login."""
    path = Path(text(data["credentials_path"]))
    if not path.is_absolute():
        raise ValueError("Credential path must be absolute")
    with path.open("rb") as source:
        raw = source.read(65537)
    if not 0 < len(raw) <= 65536:
        raise ValueError("Credential document exceeds limit")
    doc = json.loads(raw)
    serial = text(doc["serial"])
    endpoint, cas = doc["endpoint"], doc["cas"]
    host = str(ipaddress.ip_address(text(endpoint["host"])))
    key = text(cas["key"])
    device = EzvizCasDeviceInfo(serial, text(cas["operation_code"]), key,
                              cas.get("encrypt_type"))
    # Direct-local control validates the AES key here; its SDK-owned SSL IV
    # is independent of the opaque operation code (unlike legacy CAS helpers).
    _ = device.key_bytes
    if "media_key" in doc and "media_key_hex" in doc:
        raise ValueError("Supply exactly one media key representation")
    media_key = (bytes.fromhex(text(doc["media_key_hex"]))
                 if "media_key_hex" in doc else text(doc["media_key"]))
    if not media_key:
        raise ValueError("Missing media key")
    stream_port = endpoint.get("stream_port")
    credentials = EzvizLocalSdkCredentials(
        HcNetSdkLanEndpoint(
            serial=serial, host=host,
            command_port=integer(endpoint.get("command_port", 8000), 1, 65535),
            stream_port=None if stream_port is None else integer(stream_port, 1, 65535),
        ), device, media_key,
    )
    clock = data.get("relay_source_clock", False)
    if not isinstance(clock, bool) or (clock and "relay_api_port" not in data):
        raise ValueError("Source clock requires explicit experimental relay")
    ownership = data.get("relay_atomic_ownership", False)
    if not isinstance(ownership, bool) or (ownership and "relay_api_port" not in data):
        raise ValueError("Atomic ownership requires explicit experimental relay")
    audio = integer(data.get("audio_id", -1), -1, 511)
    primary = NativeTrackSelection(integer(data["video_id"], 0, 511),
                                   None if audio == -1 else audio)
    lenses = load_lenses(data, primary)
    native_opus = data.get("relay_native_opus", False)
    finite_source = data.get("finite_source", False)
    hls_fallback = data.get("relay_hls_fallback", False)
    if not isinstance(hls_fallback, bool) or (hls_fallback and not native_opus):
        raise ValueError("HLS fallback requires an explicit native Opus profile")
    if not isinstance(native_opus, bool) or not isinstance(finite_source, bool):
        raise ValueError("Finite audio profile requires explicit boolean settings")
    if finite_source and not lenses:
        raise ValueError("Finite source delivery requires a grouped public HA contract")
    if native_opus and not (finite_source and clock and ownership and lenses
                            and primary.audio_id is not None
                            and all(lens.selection.audio_id is not None for lens in lenses)):
        raise ValueError("Native Opus requires finite grouped clock/ownership contracts")
    return Settings(
        credentials,
        integer(data["channel"], 0, 255),
        NativeStreamOptions(
            selection=primary,
            video_codec=data["video_codec"],
            finite_source=finite_source,
        ),
        integer(data["nalu_header_size"], 1, 2),
        (integer(data["relay_api_port"], 1, 65535)
         if "relay_api_port" in data else None),
        integer(data.get("relay_rtsp_port", 8554), 1, 65535),
        clock,
        ownership,
        lenses,
        text(data["group_profile"]) if lenses else None,
        text(data["credential_revision"]) if lenses else None,
        native_opus,
        hls_fallback,
    )


def load_lenses(data: dict[str, Any], primary: NativeTrackSelection) -> tuple[LensSettings, ...]:
    """Only explicit extra lenses enable group mode and its stricter relay contract."""
    rows = data.get("lenses", [])
    if not isinstance(rows, list) or len(rows) > 3:
        raise ValueError("Declare at most three child lenses")
    if rows and not (data.get("relay_source_clock") is True
                     and data.get("relay_atomic_ownership") is True
                     and "relay_api_port" in data):
        raise ValueError("Grouped lenses require explicit clock and atomic relay contracts")
    if rows and any(not text(data[field]).strip()
                    for field in ("group_profile", "credential_revision")):
        raise ValueError("Explicit verified profile and credential revision required")
    keys, selections = {"primary"}, {primary}
    result = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("Invalid child lens")
        key, name = text(row["lens_id"]), text(row["name"])
        if (not re.fullmatch(r"[a-z][a-z0-9_]{0,31}", key) or key in keys
                or not name.strip() or len(name) > 96):
            raise ValueError("Supply a unique stable lens key and bounded name")
        audio = integer(row.get("audio_id", -1), -1, 511)
        selection = NativeTrackSelection(integer(row["video_id"], 0, 511),
                                          None if audio == -1 else audio)
        if selection in selections:
            raise ValueError("Declared lenses require distinct track selections")
        result.append(LensSettings(key, name, selection))
        keys.add(key)
        selections.add(selection)
    return tuple(result)
