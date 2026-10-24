"""Bounded standalone local HEVC/AAC timeline; no app selections or output devices.

Explicit exact-PTS lens pairing and one shared container clock, not native staging,
VQE or a physical playback scheduler. Requires optional PyAV via existing adapters.
"""

from __future__ import annotations

import argparse
from fractions import Fraction
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import sys
from typing import Any

VIDEO = runpy.run_path(str(Path(__file__).with_name('app_video_decode.py')))
AUDIO = VIDEO['AUDIO']
PCM = runpy.run_path(str(Path(__file__).with_name('app_pcm_playback.py')))
MAX_SPAN = 3600


def exact(row: dict[str, Any]) -> Fraction:
    """Use original integer timing, never float milliseconds or decoded ordinals."""
    values: list[Any] = [row.get(k) for k in ('source_pts', 'time_base_num', 'time_base_den')]
    if (any(type(v) is not int for v in values) or values[0] < 0
            or values[1] <= 0 or values[2] <= 0):
        raise ValueError('requires explicit nonnegative integer PTS and positive time base')
    result = Fraction(values[0] * values[1], values[2])
    if result * 1000 >= 2**32:
        raise ValueError('source time exceeds uint32 milliseconds')
    return result


def rational(value: Fraction) -> dict[str, int]:
    return dict(numerator=value.numerator, denominator=value.denominator)


def index_lenses(video: dict[str, Any]) -> tuple[tuple[int, int], dict[int, dict[Fraction, dict[str, Any]]]]:
    """Index strict per-lens presentation times, not ordinal/native identities."""
    streams = (video['primary_stream'], video['secondary_stream'])
    if (any(type(s) is not int or s < 0 for s in streams) or streams[0] == streams[1]
            or not 0 < len(video['decoded_frames']) <= VIDEO['MAX_FRAMES']):
        raise ValueError('requires distinct video tracks and bounded nonempty decoded tracks')
    lenses: dict[int, dict[Fraction, dict[str, Any]]] = {s: {} for s in streams}
    seen: set[str] = set()
    for row in video['decoded_frames']:
        stream = row['stream_index']
        if type(stream) is not int or stream not in lenses or row['decoded_id'] in seen:
            raise ValueError('unknown video track or duplicate decoded identity')
        seen.add(row['decoded_id'])
        stamp = exact(row)
        track = lenses[stream]
        if track and stamp <= next(reversed(track)):
            raise ValueError('duplicate or backward lens PTS is ambiguous for exact pairing')
        track[stamp] = dict(row)
    if not all(lenses.values()):
        raise ValueError('both lenses must have decoded pictures')
    return streams, lenses


def plan(video: dict[str, Any], audio: list[dict[str, Any]]) -> dict[str, Any]:
    """Pair exact presentation times, retaining unmatched pictures and audio overlap."""
    streams, lenses = index_lenses(video)
    if not 0 < len(audio) <= AUDIO["MAX_BLOCKS"]:
        raise ValueError("requires bounded nonempty audio")
    seen: set[str] = set()
    times = [stamp for track in lenses.values() for stamp in track]
    previous = None
    for row in audio:
        stamp = exact(row)
        if row['id'] in seen or (previous is not None and stamp < previous):
            raise ValueError('duplicate audio identity or backward audio PTS')
        if row.get('samples') != AUDIO['SAMPLES'] or type(row.get('samples')) is not int:
            raise ValueError('requires exactly 1024 decoded audio samples')
        seen.add(row['id'])
        times.append(stamp)
        previous = stamp
    origin = min(times)
    if max(times) - origin > MAX_SPAN:
        raise ValueError('source timeline span exceeds one hour')
    events: list[tuple[Fraction, int, dict[str, Any]]] = []
    paired: set[Fraction] = set()
    for stamp, left in lenses[streams[0]].items():
        right = lenses[streams[1]].get(stamp)
        if right is None:
            continue
        if (left['width'], left['height']) != (right['width'], right['height']):
            raise ValueError('exact-time lens pair has unequal geometry')
        paired.add(stamp)
        events.append((stamp, 0, dict(kind='video_pair', id=f'local-pair:{len(paired)}',
                                      at=rational(stamp - origin), lenses=[left, right])))
    if not paired:
        raise ValueError('no exact-PTS lens pairs; no nearest-time pairing is inferred')
    previous_end = None
    for row in audio:
        stamp = exact(row)
        duration = Fraction(AUDIO['SAMPLES'], AUDIO['SAMPLE_RATE'])
        events.append((stamp, 1, dict(kind='audio_block', at=rational(stamp - origin),
                                      duration=rational(duration),
                                      gap_before=None if previous_end is None else rational(stamp - previous_end),
                                      block=dict(row))))
        previous_end = stamp + duration
    # Stable order at ties: video then audio; equal-time audio retains decode order.
    events.sort(key=lambda event: (event[0], event[1]))
    pending = [row for stream in streams for stamp, row in lenses[stream].items()
               if stamp not in paired]
    return dict(profile='standalone-local-av-timeline-v1',
                pairing='exact-rational-container-pts-not-native-staging',
                clock_assumption='selected-tracks-share-one-container-presentation-clock',
                origin=rational(origin), events=[event[2] for event in events],
                pending_unpaired=pending,
                summary=dict(video_pairs=len(paired), audio_blocks=len(audio),
                             unpaired_pictures=len(pending)),
                output_devices_opened=False, native_selections_used=False,
                native_vqe_used=False, physical_av_sync_measured=False)


class AudioMetadata:
    """Keep bounded decoder provenance, never PCM or packet payloads."""

    def __init__(self) -> None:
        self.frames: list[dict[str, Any]] = []
        self.decoder: dict[str, Any] | None = None
        self.packets = 0

    def write(self, line: str) -> None:
        row = json.loads(line)
        if row['kind'] == 'decoded':
            if len(self.frames) >= AUDIO['MAX_BLOCKS']:
                raise ValueError('audio metadata block limit exceeded')
            self.frames.append(row)
        elif row['kind'] == 'decoder':
            self.decoder = row
        elif row['kind'] == 'packet':
            self.packets += 1

    def flush(self) -> None:
        """The manifest is an in-memory decoder observer, not a file writer."""


class AudioInspector:
    """Verify each emitted block against its immediately preceding decoded record."""

    def __init__(self, metadata: AudioMetadata) -> None:
        self.metadata = metadata
        self.count = 0

    def write(self, row: dict[str, Any]) -> None:
        block = PCM['parse_block'](row)
        if len(self.metadata.frames) != self.count + 1:
            raise ValueError('decoded audio metadata/emission order mismatch')
        record = self.metadata.frames[-1]
        if (block.identity != record['id'] or block.media_ms != record['media_ms']
                or hashlib.sha256(block.pcm).hexdigest() != record['pcm_sha256']):
            raise ValueError('decoded PCM does not match its source metadata')
        self.count += 1


def inspect(path: Path, container: str, streams: tuple[int, int], audio_stream: int) -> dict[str, Any]:
    """Decode one immutable bounded local snapshot twice; all tracks share provenance."""
    if (type(audio_stream) is not int or audio_stream < 0 or audio_stream in streams):
        raise ValueError('select three distinct absolute stream indices')
    with AUDIO['open_source'](path) as source:
        snapshot = source.read()
        if len(snapshot) != source.size:
            raise ValueError('source truncated during snapshot')
    video = VIDEO['decode'](io.BytesIO(snapshot), container, streams)
    metadata = AudioMetadata()
    writer = AudioInspector(metadata)
    count = AUDIO['decode'](io.BytesIO(snapshot), container, audio_stream, writer, metadata)
    if count != writer.count or count != len(metadata.frames):
        raise ValueError('incomplete audio inspection')
    timeline = plan(video, metadata.frames)
    timeline.update(source_sha256=hashlib.sha256(snapshot).hexdigest(), source_bytes=len(snapshot),
                    container=container, primary_stream=streams[0], secondary_stream=streams[1],
                    audio_stream=audio_stream,
                    decoder_versions=dict(video=dict(pyav_version=video['pyav_version'],
                                                     library_versions=video['library_versions']),
                                          audio=metadata.decoder))
    return timeline


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('--container', required=True, choices=AUDIO['FORMATS'])
    parser.add_argument('--primary-stream', required=True, type=int)
    parser.add_argument('--secondary-stream', required=True, type=int)
    parser.add_argument('--audio-stream', required=True, type=int)
    parser.add_argument('--pairing', required=True, choices=['exact-pts'])
    parser.add_argument('--clock', required=True, choices=['container-pts'])
    args = parser.parse_args()
    try:
        report = inspect(args.source, args.container,
                         (args.primary_stream, args.secondary_stream), args.audio_stream)
        blocking = os.get_blocking(sys.stdout.fileno())
        try:
            os.set_blocking(sys.stdout.fileno(), False)
            AUDIO['JsonlWriter'](sys.stdout.fileno()).write(report)
        finally:
            os.set_blocking(sys.stdout.fileno(), blocking)
        return 0
    except (ValueError, OSError, ImportError) as error:
        print(f'timeline failed: {type(error).__name__}: {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
