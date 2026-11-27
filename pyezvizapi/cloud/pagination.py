"""Bounded iterative pagelist collection; HTTP and token ownership stay outside."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from hashlib import sha256
import json
import logging
from typing import Any

from pyezvizapi._shared.utils import deep_merge
from pyezvizapi.exceptions import PyEzvizError

MAX_PAGELIST_PAGES = 1000
_LOGGER = logging.getLogger(__name__)
_DEVICE_SECTIONS = frozenset(
    [
        "CLOUD",
        "TIME_PLAN",
        "CONNECTION",
        "SWITCH",
        "STATUS",
        "WIFI",
        "NODISTURB",
        "KMS",
        "P2P",
        "CHANNEL",
        "VTM",
        "DETECTOR",
        "FEATURE",
        "CUSTOM_TAG",
        "UPGRADE",
        "VIDEO_QUALITY",
        "QOS",
        "PRODUCTS_INFO",
        "SIM_CARD",
        "MULTI_UPGRADE_EXT",
        "FEATURE_INFO",
    ]
)


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


def _page_issues(payload: dict[str, Any]) -> tuple[bool, bool]:
    return (
        not _has_page_flag(payload),
        bool(payload.get("deviceInfos")) and "resourceInfos" not in payload,
    )


def _log_inventory_page(
    payload: dict[str, Any], offset: int, phase: str, issues: tuple[bool, bool]
) -> None:
    meta = payload.get("meta")
    more = meta.get("moreInfo") if isinstance(meta, Mapping) else None
    deferred = sorted(_DEVICE_SECTIONS.intersection(more)) if isinstance(more, Mapping) else []
    if not any(issues) and not deferred and phase == "initial":
        return
    devices, resources = payload.get("deviceInfos"), payload.get("resourceInfos")
    _LOGGER.debug(
        "Pagelist page offset=%d phase=%s invalid_has_next=%s missing_resources=%s "
        "device_rows=%s resource_rows=%s deferred_sections=%s",
        offset,
        phase,
        *issues,
        len(devices) if isinstance(devices, list) else None,
        len(resources) if isinstance(resources, list) else None,
        deferred,
    )


def _inventory_fetch(
    fetch: Callable[[int], dict[str, Any]],
) -> Callable[[int], dict[str, Any]]:
    retry_available = True
    pages_checked = 0
    incomplete_pages = 0
    recovered_pages = 0

    def fetch_page(offset: int) -> dict[str, Any]:
        nonlocal retry_available, pages_checked, incomplete_pages, recovered_pages
        payload = fetch(offset)
        issues = _page_issues(payload)
        pages_checked += 1
        incomplete_pages += any(issues)
        if _LOGGER.isEnabledFor(logging.DEBUG):
            _log_inventory_page(payload, offset, "initial", issues)
        if retry_available and any(issues):
            retry_available = False
            try:
                payload = fetch(offset)
            except Exception:
                _LOGGER.debug("Pagelist retry offset=%d outcome=request_failed", offset)
                raise
            issues = _page_issues(payload)
            recovered_pages += not any(issues)
            if _LOGGER.isEnabledFor(logging.DEBUG):
                _log_inventory_page(payload, offset, "retry", issues)
        if issues[0] or not payload["page"]["hasNext"]:
            _LOGGER.debug(
                "Pagelist scan pages_checked=%d incomplete_pages=%d retries_recovered=%d "
                "valid_final_page=%s",
                pages_checked,
                incomplete_pages,
                recovered_pages,
                not issues[0],
            )
        if issues[0]:
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
