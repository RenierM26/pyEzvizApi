"""Windows TCP table access isolated from the portable HCNetSDK runtime."""

from __future__ import annotations

import ctypes
import socket
from typing import Any, cast

_TCP_TABLE_OWNER_PID_ALL = 5
_ERROR_INSUFFICIENT_BUFFER = 122
_SourceAddress = tuple[str, int] | tuple[str, int, int, int]


class _Tcp4Row(ctypes.Structure):
    _fields_ = [
        ("state", ctypes.c_uint32),
        ("local_addr", ctypes.c_uint32),
        ("local_port", ctypes.c_uint32),
        ("remote_addr", ctypes.c_uint32),
        ("remote_port", ctypes.c_uint32),
        ("owning_pid", ctypes.c_uint32),
    ]


class _Tcp6Row(ctypes.Structure):
    _fields_ = [
        ("local_addr", ctypes.c_ubyte * 16),
        ("local_scope_id", ctypes.c_uint32),
        ("local_port", ctypes.c_uint32),
        ("remote_addr", ctypes.c_ubyte * 16),
        ("remote_scope_id", ctypes.c_uint32),
        ("remote_port", ctypes.c_uint32),
        ("state", ctypes.c_uint32),
        ("owning_pid", ctypes.c_uint32),
    ]


def tcp_states_for_source(
    source_address: _SourceAddress,
    family: int,
) -> set[int]:
    """Return Windows TCP states matching a source address or wildcard owner."""

    row_type = _Tcp6Row if family == socket.AF_INET6 else _Tcp4Row
    source_host, port = source_address[:2]
    source_scope_id = source_address[3] if len(source_address) == 4 else 0
    source_host, has_zone, zone = source_host.partition("%")
    if family == socket.AF_INET6 and has_zone and source_scope_id == 0:
        try:
            source_scope_id = int(zone)
        except ValueError:
            source_scope_id = socket.if_nametoindex(zone)
    try:
        packed_source_host = socket.inet_pton(family, source_host)
    except OSError:
        resolved_host = str(
            socket.getaddrinfo(
                source_host,
                port,
                family=family,
                type=socket.SOCK_STREAM,
            )[0][4][0]
        )
        packed_source_host = socket.inet_pton(family, resolved_host)
    address_size = 16 if family == socket.AF_INET6 else 4
    address_offset = row_type.local_addr.offset
    wildcard_address = bytes(address_size)
    ctypes_api = cast(Any, ctypes)
    get_table = ctypes_api.windll.iphlpapi.GetExtendedTcpTable
    size = ctypes.c_uint32(0)
    result = get_table(
        None,
        ctypes.byref(size),
        False,
        family,
        _TCP_TABLE_OWNER_PID_ALL,
        0,
    )
    if result not in {0, _ERROR_INSUFFICIENT_BUFFER}:
        raise OSError(result, "GetExtendedTcpTable size query failed")

    while True:
        buffer = ctypes.create_string_buffer(size.value)
        result = get_table(
            buffer,
            ctypes.byref(size),
            False,
            family,
            _TCP_TABLE_OWNER_PID_ALL,
            0,
        )
        if result == 0:
            break
        if result != _ERROR_INSUFFICIENT_BUFFER:
            raise OSError(result, "GetExtendedTcpTable failed")

    dword_size = ctypes.sizeof(ctypes.c_uint32)
    count = int(ctypes.c_uint32.from_buffer_copy(buffer.raw[:dword_size]).value)
    row_size = ctypes.sizeof(row_type)
    states: set[int] = set()
    for index in range(count):
        row = row_type.from_buffer_copy(buffer.raw, dword_size + index * row_size)
        local_port = socket.ntohs(int(row.local_port) & 0xFFFF)
        row_address = bytes(row)[address_offset : address_offset + address_size]
        if local_port != port:
            continue
        if row_address == wildcard_address:
            states.add(int(row.state))
            continue
        if row_address != packed_source_host:
            continue
        if (
            family == socket.AF_INET6
            and source_scope_id != 0
            and int(row.local_scope_id) != source_scope_id
        ):
            continue
        states.add(int(row.state))
    return states
