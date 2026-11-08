"""Bounded handoff credit from output API acknowledgements, never physical playback clocks."""
from __future__ import annotations

import json
import math
import struct
import threading
import time
from typing import Any


class WireRecords:
    """Preserve original header bytes as well as payload; no protocol re-encoding."""
    def __init__(self) -> None:
        self.buffer = bytearray()
        self.row: dict[str, Any] | None = None
        self.extent: int | None = None
        self.bytes = self.records = 0

    def feed(self, data: bytes) -> Any:
        self.bytes += len(data)
        if self.bytes > 128 * 1024 * 1024:
            raise ValueError('credit input byte limit')
        self.buffer.extend(data)
        while True:
            if self.extent is None:
                if len(self.buffer) < 4:
                    return
                size = struct.unpack('!I', self.buffer[:4])[0]
                if not 0 < size <= 8192:
                    raise ValueError('credit header extent')
                if len(self.buffer) < 4 + size:
                    return
                row = json.loads(self.buffer[4:4 + size])
                if (not isinstance(row, dict) or type(row.get('payload_bytes')) is not int
                        or not 0 <= row['payload_bytes'] <= 32 * 1024 * 1024):
                    raise ValueError('credit payload extent')
                self.row, self.extent = row, 4 + size + row['payload_bytes']
            if len(self.buffer) < self.extent:
                return
            if self.records >= 4000:
                raise ValueError('credit record limit')
            raw = bytes(self.buffer[:self.extent])
            del self.buffer[:self.extent]
            row, self.row, self.extent = self.row, None, None
            self.records += 1
            yield row, raw

    def eof(self) -> None:
        if self.buffer or self.extent is not None:
            raise ValueError('credit framing truncated at EOF')


class Credit:
    """One video and four audio offers by default; completed API calls return credit.

    Producer order/bytes/identities are unchanged. Source end is NOT a request to
    wait for or drain outstanding offers; the consumer retains its EOF policy.
    """
    def __init__(self, video: int = 1, audio: int = 4) -> None:
        if (type(video) is not int or not 1 <= video <= 6
                or type(audio) is not int or not 1 <= audio <= 24):
            raise ValueError('credit window bounds')
        self.limits = {'pair': video, 'vqe': audio}
        self.pending: dict[str, set[str]] = {'pair': set(), 'vqe': set()}
        self.offered = {'pair': 0, 'vqe': 0}
        self.acked = {'pair': 0, 'vqe': 0}
        self.peak = {'pair': 0, 'vqe': 0}
        self.audio_seen: set[int] = set()
        self.condition = threading.Condition()
        self.closed = False
        self.error: str | None = None

    def offer(self, row: dict[str, Any], stopped: Any, alive: Any, timeout: float = 12) -> None:
        if not math.isfinite(timeout) or not 0 < timeout <= 12:
            raise ValueError('credit deadline bounds')
        kind = row.get('kind')
        deadline = time.monotonic() + timeout
        with self.condition:
            while True:
                if stopped():
                    raise KeyboardInterrupt('handoff credit cancelled')
                if self.closed or not alive():
                    raise ValueError(self.error or 'output progress closed while offering input')
                if kind not in self.pending or len(self.pending[kind]) < self.limits[kind]:
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('output acknowledgement credit deadline')
                self.condition.wait(min(.02, remaining))
            if kind == 'pair':
                if self.offered[kind] >= 300:
                    raise ValueError('pair credit count limit')
                identity = f'pair:{self.offered[kind] + 1}'
            elif kind == 'vqe':
                if (type(row.get('id')) is not int or row['id'] in self.audio_seen
                        or self.offered[kind] >= 512):
                    raise ValueError('audio credit identity/count')
                identity = f'vqe:{row["id"]}'
                self.audio_seen.add(row['id'])
            else:
                return  # In particular, end never drains or waits for outstanding output.
            self.pending[kind].add(identity)
            self.offered[kind] += 1
            self.peak[kind] = max(self.peak[kind], len(self.pending[kind]))

    def progress(self, row: dict[str, Any]) -> None:
        with self.condition:
            kind = row.get('kind')
            if kind in ('video_ack', 'audio_ack'):
                track = 'pair' if kind == 'video_ack' else 'vqe'
                identity = row.get('pair_id' if track == 'pair' else 'id')
                if not isinstance(identity, str) or identity not in self.pending[track]:
                    raise ValueError('unknown or duplicate output acknowledgement')
                self.pending[track].remove(identity)
                self.acked[track] += 1
                self.condition.notify_all()
            elif kind == 'consumer_result':
                self.closed = True
                self.error = row.get('error')
                self.condition.notify_all()

    def close(self, error: str | None = None) -> None:
        with self.condition:
            self.closed = True
            self.error = self.error or error
            self.condition.notify_all()

    def result(self) -> dict[str, Any]:
        with self.condition:
            return dict(limits=dict(self.limits), offered=dict(self.offered), acknowledged=dict(self.acked),
                        peak=dict(self.peak), pending={k: sorted(v) for k, v in self.pending.items()},
                        closed=self.closed, error=self.error, acknowledgement_is_physical_output=False)
