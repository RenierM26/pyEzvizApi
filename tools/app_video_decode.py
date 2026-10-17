"""Development-only local HEVC decode fingerprints and explicit staging-header join.

Optional PyAV; no native arrival inference, pixel output, camera access or pacing.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable
from fractions import Fraction
import hashlib
import json
import os
from pathlib import Path
import runpy
import sys
import time
from typing import Any

# Absolute sibling loading also works when repository-only tools are not installed.
AUDIO = runpy.run_path(str(Path(__file__).with_name('app_aac_decode.py')))
PAIR = runpy.run_path(str(Path(__file__).with_name('app_video_pairing.py')))
MAX_FRAMES = 10_000
MAX_PIXELS = 8_388_608
MAX_TOTAL_PIXELS = 268_435_456
MAX_PACKET_BYTES = 4 * 1024 * 1024
MAX_PACKETS = 100_000
MAX_SECONDS = 60
BINDING = {'decoded_id', 'source_pts', 'time_base_num', 'time_base_den', 'pixel_sha256'}


def fingerprint(frame: Any, stream_index: int, index: int) -> dict[str, Any]:
    """Hash visible Y/U/V rows, excluding decoder allocation/stride padding."""
    if (frame.is_corrupt or frame.format.name != 'yuv420p'
            or type(frame.width) is not int or type(frame.height) is not int
            or not 0 < frame.width <= 4096 or not 0 < frame.height <= 4096
            or frame.width % 2 or frame.height % 2
            or frame.width * frame.height > MAX_PIXELS or len(frame.planes) != 3):
        raise ValueError('requires noncorrupt even-sized yuv420p frames up to 4096 and 8 Mpixels')
    if type(frame.pts) is not int or frame.time_base is None or frame.time_base <= 0:
        raise ValueError('decoded video requires integer PTS and a positive time base')
    exact = frame.pts * Fraction(frame.time_base)
    if not 0 <= exact * 1000 < 2**32:
        raise ValueError('decoded source PTS is outside uint32 milliseconds')
    digest = hashlib.sha256()
    for plane, width, height in zip(frame.planes,
                                   (frame.width, frame.width // 2, frame.width // 2),
                                   (frame.height, frame.height // 2, frame.height // 2), strict=True):
        data = bytes(plane)
        if plane.line_size < width or len(data) < plane.line_size * height:
            raise ValueError('decoded plane has unsupported stride or truncated rows')
        for row in range(height):
            digest.update(data[row * plane.line_size:row * plane.line_size + width])
    return dict(decoded_id=f'video:{stream_index}:{index}', stream_index=stream_index,
                frame_index=index, source_pts=frame.pts,
                time_base_num=frame.time_base.numerator, time_base_den=frame.time_base.denominator,
                width=frame.width, height=frame.height, pixel_format='yuv420p',
                pixel_sha256=digest.hexdigest())


def ignore_pixels(_row: dict[str, Any], _frame: Any) -> None:
    """Default observer retains no pixel reference beyond the current iteration."""


def decode(source: Any, container_format: str, streams: tuple[int, int],
           consume_frame: Callable[[dict[str, Any], Any], None] = ignore_pixels) -> dict[str, Any]:
    """Inspect exactly two selected HEVC tracks; release pixels after hashing."""
    if (len(set(streams)) != 2 or any(type(i) is not int or i < 0 for i in streams)
            or container_format not in AUDIO['FORMATS']):
        raise ValueError('requires two distinct absolute video stream indices and a supported container')
    av = AUDIO['load_av']()
    rows: list[dict[str, Any]] = []
    counts = dict.fromkeys(streams, 0)
    previous: dict[int, Fraction] = {}
    pixels = 0
    started = time.monotonic()
    with av.open(source, format=container_format,
                 options={'protocol_whitelist': 'file,pipe'}) as container:
        selected = [s for s in container.streams if s.index in streams and s.type == 'video']
        if len(selected) != 2:
            raise ValueError('select two existing video tracks')
        for stream in selected:
            codec = stream.codec_context
            if (codec.name != 'hevc' or not 0 < codec.width <= 4096
                    or not 0 < codec.height <= 4096 or codec.width * codec.height > MAX_PIXELS):
                raise ValueError('requires bounded HEVC tracks with declared dimensions')
            codec.thread_count = 1
        for packets, packet in enumerate(container.demux(*selected)):
            if packets >= MAX_PACKETS or time.monotonic() - started > MAX_SECONDS:
                raise ValueError('video packet/session limit exceeded')
            if packet.is_corrupt or packet.size > MAX_PACKET_BYTES:
                raise ValueError('corrupt or oversized encoded video packet')
            for frame in packet.decode():
                if len(rows) >= MAX_FRAMES:
                    raise ValueError('decoded video frame limit exceeded')
                stream_index = packet.stream.index
                row = fingerprint(frame, stream_index, counts[stream_index])
                exact = Fraction(row['source_pts'] * row['time_base_num'], row['time_base_den'])
                if stream_index in previous and exact < previous[stream_index]:
                    raise ValueError('backward decoded presentation time; no clock repair inferred')
                pixels += frame.width * frame.height
                if pixels > MAX_TOTAL_PIXELS:
                    raise ValueError('total decoded pixel limit exceeded')
                previous[stream_index] = exact
                counts[stream_index] += 1
                rows.append(row)
                consume_frame(dict(row), frame)
        if not all(counts.values()):
            raise ValueError('both selected tracks must produce supported pictures')
    return dict(decoded_frames=rows, pyav_version=av.__version__, library_versions=av.library_versions,
                primary_stream=streams[0], secondary_stream=streams[1])


def join_headers(report: dict[str, Any], source: Any) -> dict[str, Any]:
    """Validate explicit source bindings before replay, never derive raw headers from PTS."""
    decoded = {row['decoded_id']: row for row in report['decoded_frames']}
    used: set[str] = set()
    events = []
    bindings = []
    model = PAIR['Pairing']()
    for _ in range(PAIR['MAX_EVENTS'] + 1):
        line = source.readline(PAIR['MAX_LINE'] + 1)
        if not line:
            break
        if len(line) > PAIR['MAX_LINE']:
            raise ValueError('header-map JSONL line limit exceeded')
        event = json.loads(line)
        if not isinstance(event, dict):
            raise ValueError('header-map event must be an object')
        if event.get('kind') == 'lens_picture':
            if not event.keys() >= BINDING:
                raise ValueError('lens offer requires exact decoded-frame binding')
            identity = event['decoded_id']
            if not isinstance(identity, str) or identity not in decoded:
                raise ValueError('unknown decoded picture identity')
            row = decoded[identity]
            for key in BINDING:
                if type(event[key]) is not type(row[key]) or event[key] != row[key]:
                    raise ValueError(f'decoded-frame binding mismatch: {key}')
            lens = event.get('lens')
            expected = report['primary_stream'] if lens == 0 else report['secondary_stream']
            if row['stream_index'] != expected:
                raise ValueError('decoded track does not match the declared lens')
            used.add(identity)
            bindings.append(dict(offer_id=event.get('id'), decoded_id=identity))
            event = {key: value for key, value in event.items() if key not in BINDING}
        model.step(event)
        events.append(event)
    else:
        raise ValueError('header-map event limit exceeded')
    if used != decoded.keys():
        raise ValueError('header map must explicitly account for every decoded picture')
    return dict(events=events, offer_bindings=bindings, pairing=model.result())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('--container', required=True, choices=AUDIO['FORMATS'])
    parser.add_argument('--primary-stream', required=True, type=int)
    parser.add_argument('--secondary-stream', required=True, type=int)
    parser.add_argument('--header-map', type=Path, help='optional explicit JSONL bindings; absent means inspect only')
    args = parser.parse_args()
    try:
        with AUDIO['open_source'](args.source) as source:
            report = decode(source, args.container, (args.primary_stream, args.secondary_stream))
        if args.header_map:
            with AUDIO['open_source'](args.header_map) as headers:
                report.update(join_headers(report, headers))
        report.update(mode='mapped' if args.header_map else 'inspect',
                      arrival_source='caller-header-map-not-host-decode' if args.header_map else None,
                      native_header_provenance_verified=False, physical_lip_sync_measured=False,
                      decoder_buffer_ownership_verified=False)
        fd = sys.stdout.fileno()
        blocking = os.get_blocking(fd)
        try:
            os.set_blocking(fd, False)
            AUDIO['JsonlWriter'](fd).write(report)
        finally:
            os.set_blocking(fd, blocking)
    except (Exception, KeyboardInterrupt) as error:
        print(f'video decode rejected: {type(error).__name__}: {error}', file=sys.stderr)
        return 130 if isinstance(error, KeyboardInterrupt) else 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
