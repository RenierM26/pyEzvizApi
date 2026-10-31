"""Load supplied local credentials without contacting any camera or account."""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
from pathlib import Path
from typing import Any

from pyezvizapi.hcnetsdk import EzvizCasDeviceInfo, HcNetSdkLanEndpoint
from pyezvizapi.local_stream_transport import EzvizLocalSdkCredentials
from pyezvizapi.native_stream import NativeStreamOptions, NativeTrackSelection


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
    # Validate the existing wire format's key/IV before acquisition.
    _ = device.key_bytes, device.iv_bytes
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
    return Settings(
        credentials,
        integer(data["channel"], 0, 255),
        NativeStreamOptions(
            selection=NativeTrackSelection(integer(data["video_id"], 0, 511),
                                           None if audio == -1 else audio),
            video_codec=data["video_codec"],
        ),
        integer(data["nalu_header_size"], 1, 2),
        (integer(data["relay_api_port"], 1, 65535)
         if "relay_api_port" in data else None),
        integer(data.get("relay_rtsp_port", 8554), 1, 65535),
        clock,
        ownership,
    )
