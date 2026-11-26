"""Bounded iterative pagelist collection; HTTP and token ownership stay outside."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from hashlib import sha256
import json
from typing import Any

from pyezvizapi._shared.utils import deep_merge
from pyezvizapi.exceptions import PyEzvizError

MAX_PAGELIST_PAGES = 1000


def validate_device_inventory_page(payload: dict[str, Any]) -> None:
    """Require explicit pagination and valid serials before merging inventory."""
    page = payload.get("page")
    if (
        not isinstance(page, Mapping)
        or not isinstance(has_next := page.get("hasNext"), (bool, int))
        or has_next not in (False, True)
    ):
        raise PyEzvizError("Device inventory page requires an explicit hasNext flag")

    devices = payload.get("deviceInfos")
    if not isinstance(devices, list) or not all(
        isinstance(device, dict)
        and isinstance(serial := device.get("deviceSerial"), str)
        and serial
        and serial == serial.strip()
        for device in devices
    ):
        raise PyEzvizError("Invalid deviceInfos on inventory page")


def _has_page_flag(payload: dict[str, Any]) -> bool:
    page = payload.get("page")
    return (
        isinstance(page, Mapping)
        and isinstance(flag := page.get("hasNext"), (bool, int))
        and flag in (False, True)
    )


def _inventory_fetch(
    fetch: Callable[[int], dict[str, Any]],
) -> Callable[[int], dict[str, Any]]:
    retry_available = True

    def fetch_page(offset: int) -> dict[str, Any]:
        nonlocal retry_available
        payload = fetch(offset)
        if retry_available and (
            not _has_page_flag(payload)
            or (payload.get("deviceInfos") and "resourceInfos" not in payload)
        ):
            retry_available = False
            payload = fetch(offset)
        if not _has_page_flag(payload):
            raise PyEzvizError("Device inventory page requires an explicit hasNext flag")
        return payload

    return fetch_page


def collect_pagelist(
    fetch: Callable[[int], dict[str, Any]],
    *,
    json_key: str | None,
    limit: int,
    offset: int,
    recover_inventory: bool = False,
) -> Any:
    """Collect at most 1000 progressing pages and retain right-fold merge rules."""
    pages: list[Any] = []
    seen: set[bytes] = set()
    fetch_page = _inventory_fetch(fetch) if recover_inventory else fetch
    for _ in range(MAX_PAGELIST_PAGES):
        payload = fetch_page(offset)
        page = payload.get("page")
        if page is None:
            page = {}
        if not isinstance(page, Mapping):
            raise PyEzvizError("Invalid pagelist page metadata")
        flag = page.get("hasNext", False)
        if not isinstance(flag, (bool, int)) or flag not in (False, True):
            raise PyEzvizError("Invalid pagelist hasNext flag")
        if json_key is not None and json_key not in payload:
            raise PyEzvizError("Pagelist response is missing the requested section")
        data = payload[json_key] if json_key else payload
        if not isinstance(data, (dict, list)):
            raise PyEzvizError("Invalid pagelist data section")
        progress = (
            data
            if json_key
            else {key: value for key, value in payload.items() if key not in {"page", "meta"}}
        )
        if flag and not progress:
            raise PyEzvizError("Pagelist returned an empty non-final page")
        if flag and isinstance(progress, dict) and not any(progress.values()):
            raise PyEzvizError("Pagelist returned an empty non-final page")
        try:
            fingerprint = sha256(
                json.dumps(progress, sort_keys=True, separators=(",", ":")).encode()
            ).digest()
        except (TypeError, ValueError) as err:
            raise PyEzvizError("Invalid pagelist data") from err
        if fingerprint in seen:
            raise PyEzvizError("Pagelist repeated a page without progress")
        seen.add(fingerprint)
        pages.append(data)
        if not flag:
            # deep_merge is not associative for mixed nested value shapes.
            # Match the historical recursive right fold without stack growth.
            result = pages[-1]
            for previous in reversed(pages[:-1]):
                result = deep_merge(previous, result)
            return result
        offset += limit
    raise PyEzvizError("Pagelist exceeded its maximum page count")
