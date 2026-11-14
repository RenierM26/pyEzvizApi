"""Shared traversal with distinct normalized-read and lossless-write policies."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from copy import deepcopy
from itertools import chain
from typing import Any

from pyezvizapi._shared.coercion import coerce_int, decode_json


def _normalize_port_list(value: Any) -> list[dict[str, Any]] | None:
    """Decode a list of port-security entries."""

    value = decode_json(value)
    if not isinstance(value, Iterable):
        return None

    normalized: list[dict[str, Any]] = []
    for raw_entry in value:
        entry = decode_json(raw_entry)
        if not isinstance(entry, Mapping):
            return None
        port = coerce_int(entry.get("portNo"))
        if port is None:
            continue
        normalized.append({"portNo": port, "enabled": bool(entry.get("enabled"))})

    return normalized


def _read_projection(value: Mapping[str, Any], hint: bool | None) -> dict[str, Any] | None:
    ports = _normalize_port_list(value.get("portSecurityList"))
    if ports is None:
        return None
    return {"portSecurityList": ports, "enabled": hint if hint is not None else True}


def _write_projection(value: Mapping[str, Any], hint: bool | None) -> dict[str, Any] | None:
    ports = decode_json(value.get("portSecurityList"))
    if not isinstance(ports, list):
        return None
    decoded = [decode_json(entry) for entry in ports]
    if not all(isinstance(entry, dict) for entry in decoded):
        return {}
    result = {**deepcopy(value), "portSecurityList": deepcopy(decoded)}
    if "enabled" not in result and hint is not None:
        result["enabled"] = hint
    return result


def _is_container(value: Any, preserve_fields: bool) -> bool:
    if preserve_fields:
        return isinstance(value, (dict, list))
    return isinstance(value, (Mapping, Iterable)) and not isinstance(value, (str, bytes, bytearray))


def _find_port_security(payload: Any, *, preserve_fields: bool) -> dict[str, Any]:
    # Retain decoded containers so Python cannot reuse an ID for a later sibling.
    seen: dict[int, Any] = {}
    projection = _write_projection if preserve_fields else _read_projection

    def visit(value: Any, enabled_hint: bool | None = None) -> dict[str, Any]:
        value = decode_json(value)
        if not _is_container(value, preserve_fields):
            return {}
        if id(value) in seen:
            return {}
        seen[id(value)] = value
        children: Iterable[Any]
        if isinstance(value, Mapping):
            if isinstance(value.get("enabled"), bool):
                enabled_hint = value["enabled"]
            result = projection(value, enabled_hint)
            if result is not None:
                return result
            children = value.values()
            if not preserve_fields:
                # Preserve the established read API's wrapper-key precedence.
                preferred = (
                    value[key]
                    for key in ("PortSecurity", "value", "data", "NetworkSecurityProtection")
                    if key in value
                )
                children = chain(preferred, children)
        else:
            children = value
        for child in children:
            if result := visit(child, enabled_hint):
                return result
        return {}

    return visit(payload)


def normalized_port_security(payload: Any) -> dict[str, Any]:
    """Return the legacy normalized read projection, without vendor extensions."""
    return _find_port_security(payload, preserve_fields=False)


def reported_port_security(payload: Any) -> dict[str, Any]:
    """Return a detached full write object, preserving unknown vendor fields."""
    return _find_port_security(payload, preserve_fields=True)
