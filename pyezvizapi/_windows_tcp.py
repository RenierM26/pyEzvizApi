"""Windows TCP table access isolated from the portable HCNetSDK runtime."""

from __future__ import annotations

import ctypes
import socket
from typing import Any, cast

_TCP_TABLE_OWNER_PID_ALL = 5
_ERROR_INSUFFICIENT_BUFFER = 122


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


def tcp_states_for_port(port: int, family: int) -> set[int]:
    """Return Windows TCP owner-table states for a local port and family."""

    row_type = _Tcp6Row if family == socket.AF_INET6 else _Tcp4Row
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
        if local_port == port:
            states.add(int(row.state))
    return states
