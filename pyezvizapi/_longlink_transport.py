"""Bounded synchronous framing for the channel-99 LBS handshake."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import suppress
import socket
import time
from types import TracebackType

MAX_PAYLOAD = 65536
MAX_LENGTH_BYTES = 4


class LbsConnection:
    """Own one handshake socket; every exchange has a total wall-clock deadline.

    DNS/connect is performed by the caller so this codec can also be exercised
    over a socket pair. Closing the connection unblocks an outstanding read.
    """

    def __init__(
        self,
        sock: socket.socket,
        *,
        timeout: float = 10,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if timeout <= 0:
            raise ValueError("Handshake timeout must be positive")
        self.socket = sock
        self.timeout = timeout
        self.clock = clock

    def __enter__(self) -> LbsConnection:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        """Interrupt an outstanding read, then release the owned socket."""
        with suppress(OSError):
            self.socket.shutdown(socket.SHUT_RDWR)
        self.socket.close()

    def _remaining(self, deadline: float) -> None:
        remaining = deadline - self.clock()
        if remaining <= 0:
            raise TimeoutError("Long-link handshake deadline exceeded")
        self.socket.settimeout(remaining)

    def _read(self, size: int, deadline: float) -> bytes:
        result = bytearray()
        while len(result) < size:
            self._remaining(deadline)
            chunk = self.socket.recv(size - len(result))
            if not chunk:
                raise ConnectionError("Long-link peer closed the connection")
            result.extend(chunk)
        return bytes(result)

    def send(self, frame: bytes) -> None:
        """Send a frame that does not expect a response (refresh command 9)."""
        self._remaining(self.clock() + self.timeout)
        self.socket.sendall(frame)

    def exchange(self, frame: bytes) -> tuple[int, bytes]:
        """Send a request and read exactly one bounded response frame."""
        deadline = self.clock() + self.timeout
        self._remaining(deadline)
        self.socket.sendall(frame)
        first = self._read(1, deadline)[0]
        if first & 15:
            raise ValueError("Unexpected LBS header flags")
        length = 0
        for index in range(MAX_LENGTH_BYTES):
            digit = self._read(1, deadline)[0]
            length |= (digit & 127) << (7 * index)
            if length > MAX_PAYLOAD:
                raise ValueError("LBS payload exceeds limit")
            if not digit & 128:
                if index and digit == 0:
                    raise ValueError("Noncanonical LBS length")
                return first >> 4, self._read(length, deadline)
        raise ValueError("Malformed LBS remaining length")
