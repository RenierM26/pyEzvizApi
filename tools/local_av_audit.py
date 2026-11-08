"""Bounded finalized diagnostic tails, not media ownership or output completion."""
from __future__ import annotations

from collections import deque
from fractions import Fraction
import hashlib
import json
from typing import Any

ROW_BYTES = 16384
TAIL_BYTES = 65536


def validate_tail(limit: int | None) -> None:
    if limit is not None and (type(limit) is not int or not 1 <= limit <= 128):
        raise ValueError('diagnostic tail must be an integer in [1, 128]')


def encode(row: dict[str, Any]) -> bytes:
    """Bound JSON structure before serializing; never accept media or objects."""
    remaining = [512, ROW_BYTES]
    def visit(value: Any, depth: int) -> None:
        remaining[0] -= 1
        if depth > 8 or remaining[0] < 0:
            raise ValueError('diagnostic structure bound exceeded')
        if type(value) is dict:
            for key, item in value.items():
                if type(key) is not str or len(key) > 128:
                    raise ValueError('diagnostic keys must be short strings')
                visit(key, depth + 1)
                visit(item, depth + 1)
        elif type(value) is list:
            for item in value:
                visit(item, depth + 1)
        elif type(value) is str:
            remaining[1] -= len(value)
            if len(value) > 4096 or remaining[1] < 0:
                raise ValueError('diagnostic text bound exceeded')
        elif type(value) is int:
            if value.bit_length() > 128:
                raise ValueError('diagnostic integer bound exceeded')
        elif value is not None and type(value) not in (bool, float):
            raise ValueError('diagnostic values must be plain JSON metadata')
    if type(row) is not dict:
        raise ValueError('diagnostic row must be a dictionary')
    visit(row, 0)
    data = json.dumps(row, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')
    if len(data) > ROW_BYTES:
        raise ValueError('diagnostic encoded row bound exceeded')
    return data


class Records:
    """Freeze finalized rows; hash every row, retain only a count/byte-bounded tail.

    One owner appends; result/iteration returns independent JSON snapshots. The
    digest is SHA256(domain + canonical ASCII JSON rows each followed by LF), in
    append order. It covers finalized records, never future or pending work.
    """

    def __init__(self, limit: int) -> None:
        validate_tail(limit)
        if limit is None:
            raise ValueError('explicit diagnostic tail limit required')
        self.limit = limit
        self.rows: Any = deque()
        self.bytes = self.peak_bytes = self.peak_count = self.count = self.evicted = self.total_bytes = 0
        self.digest = hashlib.sha256(b'bounded-finalized-json-v1\n')

    def append(self, row: dict[str, Any]) -> None:
        data = encode(row)  # Validate/freeze before changing any journal state.
        while self.rows and (len(self.rows) >= self.limit or self.bytes + len(data) > TAIL_BYTES):
            self.bytes -= len(self.rows.popleft())
            self.evicted += 1
        self.rows.append(data)
        self.bytes += len(data)
        self.count += 1
        self.total_bytes += len(data)
        self.peak_bytes = max(self.peak_bytes, self.bytes)
        self.peak_count = max(self.peak_count, len(self.rows))
        self.digest.update(data + b'\n')

    def __iter__(self) -> Any:
        return iter([json.loads(row) for row in self.rows])

    def result(self) -> dict[str, Any]:
        return dict(profile='bounded-finalized-json-v1', finalized_records=self.count,
            evicted_records=self.evicted, retained_records=len(self.rows), retained_bytes=self.bytes,
            peak_retained_records=self.peak_count, peak_retained_bytes=self.peak_bytes,
            record_count_limit=self.limit, tail_byte_limit=TAIL_BYTES, row_byte_limit=ROW_BYTES,
            finalized_encoded_bytes=self.total_bytes, finalized_sha256=self.digest.hexdigest(),
            complete_history_retained=self.evicted == 0)


class MediaReceipt:
    """Constant-state acknowledged media/target chains, ordered per track.

    Host service/harvest timestamps are deliberately excluded. A verifier can
    rebuild these rows from independent source decode plus the recorded anchor.
    This fingerprint is not authentication or evidence of physical playback.
    """

    def __init__(self, anchor: int) -> None:
        if type(anchor) is not int or not 0 <= anchor < 2**128:
            raise ValueError('media receipt requires a bounded nonnegative host anchor')
        self.anchor = anchor
        self.counts = dict(video_pair=0, audio_block=0)
        self.bytes = dict(self.counts)
        self.previous: dict[str, Fraction] = {}
        self.digests = {track: hashlib.sha256(b'bounded-output-media-v1\n' + track.encode('ascii') + b'\n')
            for track in self.counts}

    def prepare(self, submission: dict[str, Any], outcome: dict[str, Any]) -> tuple[dict[str, Any], bytes, Fraction]:
        track, name = submission.get('track'), submission.get('id')
        if (track not in self.counts or type(name) is not str or not name
                or submission.get('kind') != 'output_call_submitted'
                or outcome.get('kind') != 'output_call_completed'
                or outcome.get('track') != track or outcome.get('id') != name):
            raise ValueError('media receipt requires a matching completed submission')
        at = submission.get('source_at')
        if (type(at) is not dict or set(at) != {'numerator', 'denominator'}
                or any(type(at[k]) is not int or at[k].bit_length() > 128 for k in at)
                or at['denominator'] <= 0 or at['numerator'] < 0):
            raise ValueError('invalid exact media source target')
        stamp = Fraction(at['numerator'], at['denominator'])
        target = submission.get('target_monotonic_ns')
        expected = self.anchor + stamp.numerator * 1000000000 // stamp.denominator
        if (type(target) is not int or target != expected
                or (track in self.previous and stamp <= self.previous[track])):
            raise ValueError('media target changed or per-track order did not increase')
        ack = outcome.get('acknowledgement')
        size = submission.get('bytes')
        if (type(ack) is not dict or type(size) is not int or not 0 < size <= 67108864
                or type(ack.get('bytes')) is not int or ack['bytes'] != size
                or (track == 'audio_block' and size != 2048)):
            raise ValueError('media acknowledgement extent mismatch')
        fingerprint = ack.get('pixel_sha256' if track == 'video_pair' else 'pcm_sha256')
        if (type(fingerprint) is not str or len(fingerprint) != 64
                or any(c not in '0123456789abcdef' for c in fingerprint)
                or (track == 'video_pair' and (ack.get('kind') != 'presented' or ack.get('pair_id') != name))):
            raise ValueError('media acknowledgement fingerprint or identity mismatch')
        row = dict(track=track, id=name, source_at=dict(numerator=stamp.numerator, denominator=stamp.denominator),
            target_monotonic_ns=target, bytes=size, payload_sha256=fingerprint)
        return row, encode(row), stamp

    def commit(self, prepared: tuple[dict[str, Any], bytes, Fraction]) -> None:
        row, data, stamp = prepared
        track = row['track']
        self.digests[track].update(data + b'\n')
        self.counts[track] += 1
        self.bytes[track] += row['bytes']
        self.previous[track] = stamp

    def append(self, submission: dict[str, Any], outcome: dict[str, Any]) -> None:
        self.commit(self.prepare(submission, outcome))

    def result(self) -> dict[str, Any]:
        return dict(profile='bounded-output-media-v1', host_anchor_monotonic_ns=self.anchor,
            order='strict-source-order-per-track', tracks={track:dict(completed=self.counts[track],
                bytes=self.bytes[track], sha256=self.digests[track].hexdigest()) for track in self.counts})


class Actions:
    """Seal a submission with its outcome only after the output future finishes.

    Mutable submission rows remain with their existing output job, at most one
    per track; never hash a row while its worker can still update start timing.
    Finalized pair order is owner harvest order, not original submission order.
    """

    def __init__(self, limit: int) -> None:
        self.records = Records(limit)
        self.pending: dict[str, Any] = {}
        self.submitted = dict(video_pair=0, audio_block=0)
        self.completed = dict(self.submitted)
        self.failed = dict(self.submitted)
        self.error_count = 0
        self.last_error_type: str | None = None
        self.media: MediaReceipt | None = None

    def set_media_anchor(self, anchor: int) -> None:
        if self.media is not None or any(self.submitted.values()):
            raise ValueError('media anchor must be set once before any submission')
        self.media = MediaReceipt(anchor)

    def append(self, row: dict[str, Any]) -> None:
        track, kind, name = row.get('track'), row.get('kind'), row.get('id')
        if track not in self.submitted or type(name) is not str or not name:
            raise ValueError('unsupported action identity')
        if kind == 'output_call_submitted':
            frozen = encode(row)
            if track in self.pending:
                raise ValueError('action track already pending')
            self.pending[track] = row, frozen
            self.submitted[track] += 1
        elif kind in ('output_call_completed', 'output_call_failed'):
            pending = self.pending.get(track)
            if pending is None or pending[0]['id'] != name:
                raise ValueError('outcome has no matching pending submission')
            try:
                media = self.media.prepare(pending[0], row) if self.media is not None and kind == 'output_call_completed' else None
                self.records.append(dict(submission=pending[0], outcome=row))
                if media is not None:
                    assert self.media is not None
                    self.media.commit(media)
            except Exception as error:
                self.error_count += 1
                self.last_error_type = type(error).__name__
                if kind != 'output_call_failed':
                    raise
                # Parent harvest still propagates the original backend failure.
                # Missing finalized records and error counters invalidate the audit.

            del self.pending[track]
            (self.completed if kind == 'output_call_completed' else self.failed)[track] += 1
        else:
            raise ValueError('unsupported output action kind')

    def tail(self) -> list[dict[str, Any]]:
        return [action for row in self.records for action in (row['submission'], row['outcome'])]

    def result(self) -> dict[str, Any]:
        return dict(**self.records.result(), submitted=dict(self.submitted), completed=dict(self.completed),
            failed=dict(self.failed), pending_submissions=[json.loads(row[1]) for row in self.pending.values()],
            pending_count=len(self.pending), pending_limit=2,
            order='finalized-pairs-in-owner-harvest-order',
            error_count=self.error_count, last_error_type=self.last_error_type,
            media_receipt=None if self.media is None else self.media.result(),
            complete_finalization=not self.pending and not self.error_count and sum(self.submitted.values()) == self.records.count)
