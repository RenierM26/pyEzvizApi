"""Bounded iterative pagelist collection; HTTP and token ownership stay outside."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from hashlib import sha256
import json
from typing import Any

from .exceptions import PyEzvizError
from .utils import deep_merge

MAX_PAGELIST_PAGES = 1000


def collect_pagelist(
    fetch: Callable[[int], dict[str, Any]],
    *,
    json_key: str | None,
    limit: int,
    offset: int,
) -> Any:
    """Collect at most 1000 progressing pages and retain right-fold merge rules."""
    pages: list[Any] = []
    seen: set[bytes] = set()
    for _ in range(MAX_PAGELIST_PAGES):
        payload = fetch(offset)
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
        progress = data if json_key else {
            key: value for key, value in payload.items() if key not in {"page", "meta"}
        }
        if flag and not progress:
            raise PyEzvizError("Pagelist returned an empty non-final page")
        if flag and isinstance(progress, dict) and not any(progress.values()):
            raise PyEzvizError("Pagelist returned an empty non-final page")
        try:
            fingerprint = sha256(json.dumps(progress, sort_keys=True, separators=(",", ":")).encode()).digest()
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
