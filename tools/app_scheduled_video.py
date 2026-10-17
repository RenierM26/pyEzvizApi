"""Lossless local paired-video artifact selected by explicit native-clock replay.

No live source, output device, audio or physical timing claim. Request observation
milliseconds become artifact PTS only under explicit --pts-clock selection.
"""

from __future__ import annotations

import argparse
from fractions import Fraction
import hashlib
import json
import os
from pathlib import Path
import runpy
import sys
import tempfile
import time
from typing import Any

PREVIEW = runpy.run_path(str(Path(__file__).with_name('app_video_preview.py')))
DECODE = PREVIEW['DECODE']
SIM = runpy.run_path(str(Path(__file__).with_name('app_playback_simulator.py')))
ALLOWED = {'lens_picture', 'stage_push', 'video_epoch', 'video_unavailable',
           'video_observed_tick', 'video_display_complete'}
OBSERVED = {'render_admit', 'render_release'}
MAX_OUTPUT_BYTES = 512 * 1024 * 1024
MAX_EXPORT_PIXELS = DECODE['MAX_TOTAL_PIXELS']
MAX_EXPORT_SECONDS = 60


class CoupledReplay:
    """One ordered model stream with optional explicit admission/release boundaries."""

    def __init__(self, report: dict[str, Any], observed_queues: bool = False) -> None:
        self.decoded = {row['decoded_id']: row for row in report['decoded_frames']}
        self.streams = (report['primary_stream'], report['secondary_stream'])
        self.observed_queues = observed_queues
        self.admissions: list[dict[str, Any]] = []
        self.releases: list[dict[str, Any]] = []
        self.staging = DECODE['PAIR']['Pairing']()
        self.scheduler = SIM['ObservedClockReplay']()
        self.bindings: dict[str, str | None] = {}
        self.used: set[str] = set()
        self.selected: list[dict[str, Any]] = []
        self.pending: dict[str, Any] | None = None
        self.events = 0
        self.last_at = 0

    def step(self, event: Any) -> None:
        if self.events >= SIM['MAX_EVENTS']:
            raise ValueError('coupled source event limit exceeded')
        if not isinstance(event, dict) or not isinstance(event.get('kind'), str):
            raise ValueError('coupled source event requires an object and string kind')
        kind = event['kind']
        if kind not in (ALLOWED | OBSERVED if self.observed_queues else ALLOWED):
            raise ValueError('unsupported coupled event; admissions/takes are model-generated')
        at = SIM['integer'](event.get('at_ms'), 'at_ms')
        if at < self.last_at:
            raise ValueError('coupled events must retain nondecreasing observation time')
        before_scheduler = len(self.scheduler.actions)
        if kind in OBSERVED:
            self.queue_event(event)
        elif kind in ('lens_picture', 'stage_push'):
            self.staging_event(event)
        else:
            self.scheduler.step(event)
            for action in self.scheduler.actions[before_scheduler:]:
                if action['kind'] in ('video_drop_oldest', 'video_display_requested'):
                    self.take(action)
                elif action['kind'] == 'video_display_complete':
                    self.complete(action, at)
        expected = [p['id'] for p in self.scheduler.video]
        if self.observed_queues:
            expected = [p['id'] for p in self.releases] + expected + [p['id'] for p in self.admissions]
        if [p['pair_id'] for p in self.staging.render] != expected:
            raise ValueError('staging/scheduler queues diverged')
        self.events += 1
        self.last_at = at

    def staging_event(self, event: dict[str, Any]) -> None:
        before = len(self.staging.actions)
        if event['kind'] == 'lens_picture':
            event, binding = self.bind_picture(event)
            self.staging.step(event)
            self.bindings[binding['offer_id']] = binding['decoded_id']
            if binding['decoded_id'] is not None:
                self.used.add(binding['decoded_id'])
        else:
            self.staging.step(event)
        for action in self.staging.actions[before:]:
            if action['kind'] == 'render_queue_admitted':
                if self.observed_queues:
                    self.admissions.append(action['simulator_event'])
                else:
                    self.scheduler.step(action['simulator_event'])

    def bind_picture(self, event: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        """Source adapter boundary; default remains exact local decoded-frame binding."""
        return DECODE['bind_picture'](event, self.decoded, self.streams)

    def queue_event(self, event: dict[str, Any]) -> None:
        if set(event) != {'kind', 'at_ms', 'id'}:
            raise ValueError('queue boundary requires exactly kind, at_ms and id')
        identity = SIM['identity'](event['id'])
        if event['kind'] == 'render_admit':
            if not self.admissions:
                self.staging_event(dict(kind='stage_push', at_ms=event['at_ms']))
            if not self.admissions or self.admissions[0]['id'] != identity:
                raise ValueError('admission must match the next reserved pair')
            admission = self.admissions.pop(0)
            self.scheduler.step(dict(admission, at_ms=event['at_ms']))
        else:
            if not self.releases or self.releases[0]['id'] != identity:
                raise ValueError('release must match the next selected or dropped pair')
            self.staging.step(dict(kind='render_take', at_ms=event['at_ms']))
            taken = self.staging.actions[-1]
            if taken['kind'] != 'render_queue_taken' or taken['pair']['pair_id'] != identity:
                raise ValueError('release does not match the owned FIFO head')
            self.releases.pop(0)
            if self.pending is not None and self.pending['pair_id'] == identity:
                self.pending['queue_released'] = True

    def complete(self, action: dict[str, Any], at: int) -> None:
        if self.pending is None or self.pending['pair_id'] != action['id']:
            raise ValueError('scheduler completion has no matching selected pixels')
        if self.observed_queues and not self.pending['queue_released']:
            raise ValueError('display completion requires its observed queue release')
        self.selected.append(dict(self.pending, observed_complete_at_ms=at))
        self.pending = None

    def take(self, action: dict[str, Any]) -> None:
        if self.observed_queues:
            index = len(self.releases)
            if index >= len(self.staging.render):
                raise ValueError('scheduler selection has no owned staging pair')
            pair = self.staging.render[index]
            self.releases.append(dict(id=action['id'], reason=action['kind']))
        else:
            self.staging.step(dict(kind='render_take', at_ms=action['at_ms']))
            taken = self.staging.actions[-1]
            if taken['kind'] != 'render_queue_taken':
                raise ValueError('scheduler decision has no staging FIFO ownership')
            pair = taken['pair']
        if pair['pair_id'] != action['id'] or [p['id'] for p in pair['lenses']] != action['lenses']:
            raise ValueError('scheduler identity disagrees with staged pixels')
        if action['kind'] == 'video_display_requested':
            self.pending = dict(pair_id=action['id'],
                offer_ids=action['lenses'], decoded_ids=[self.bindings[p] for p in action['lenses']],
                primary_media_ms=action['media_ms'], request_at_ms=action['at_ms'])
            if self.observed_queues:
                self.pending['queue_released'] = False

    def result(self) -> dict[str, Any]:
        if self.used != self.decoded.keys():
            raise ValueError('unified event map must account for every decoded picture')
        return dict(events=self.events, selected=self.selected, request_pending=self.pending,
                    queue_boundary_mode='observed-commit-boundaries' if self.observed_queues else 'atomic-normalized-events',
                    queue_admissions_pending=[p['id'] for p in self.admissions],
                    queue_releases_pending=list(self.releases),
                    offer_bindings=self.bindings, staging=self.staging.result(), scheduler=self.scheduler.result())


def replay(report: dict[str, Any], source: Any, observed_queues: bool = False) -> dict[str, Any]:
    model = CoupledReplay(report, observed_queues)
    for _ in range(SIM['MAX_EVENTS'] + 1):
        line = source.readline(SIM['MAX_LINE_BYTES'] + 1)
        if not line:
            break
        if len(line) > SIM['MAX_LINE_BYTES']:
            raise ValueError('coupled event line limit exceeded')
        model.step(json.loads(line))
    else:
        raise ValueError('coupled source event limit exceeded')
    return model.result()


def plan_frames(result: dict[str, Any], spool: Any,
                max_pair_pixels: int | None = None) -> tuple[list[dict[str, Any]], int, int]:
    """Only completed requests become artifact frames; timing is not media PTS."""
    plan = result['selected']
    geometry = None
    previous = -1
    pixels = 0
    pair_limit = PREVIEW['MAX_PAIR_PIXELS'] if max_pair_pixels is None else max_pair_pixels
    for pair in plan:
        rows = [spool.records[identity] for identity in pair['decoded_ids']]
        current = (rows[0]['width'], rows[0]['height'])
        if (current != (rows[1]['width'], rows[1]['height'])
                or (geometry is not None and geometry != current)
                or current[0] * 2 * current[1] > pair_limit):
            raise ValueError('requires constant equal lens geometry within paired pixel limit')
        if pair['request_at_ms'] <= previous:
            raise ValueError('artifact request observation PTS must be strictly increasing')
        pixels += current[0] * 2 * current[1]
        if pixels > MAX_EXPORT_PIXELS:
            raise ValueError('total artifact pixel limit exceeded')
        previous = pair['request_at_ms']
        geometry = current
    if not plan or geometry is None:
        raise ValueError('no completed display requests; pending work is not exported')
    return plan, geometry[0], geometry[1]


def video_frame(av: Any, pixels: bytes, width: int, height: int, pts: int) -> Any:
    """Own tightly packed composed pixels in a new host AVFrame, with exact PTS."""
    if len(pixels) != width * height * 3 // 2:
        raise ValueError('composed pixel length mismatch')
    frame = av.VideoFrame(width, height, 'yuv420p')
    offset = 0
    for plane, w, h in zip(frame.planes, (width, width // 2, width // 2),
                           (height, height // 2, height // 2), strict=True):
        data = bytearray(plane.buffer_size)
        for y in range(h):
            data[y * plane.line_size:y * plane.line_size + w] = pixels[offset:offset + w]
            offset += w
        plane.update(data)
    frame.pts, frame.time_base = pts, Fraction(1, 1000)
    return frame


def export(plan: list[dict[str, Any]], spool: Any, width: int, height: int,
           destination: Path, publication: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Publish one complete lossless Matroska file, never replace an existing path."""
    if os.path.lexists(destination):
        raise FileExistsError('scheduled video destination already exists')
    av = DECODE['AUDIO']['load_av']()
    rows = []
    started = time.monotonic()
    with tempfile.NamedTemporaryFile(dir=destination.parent, prefix='.scheduled-', suffix='.mkv') as output:
        with av.open(output, 'w', format='matroska') as container:
            stream = container.add_stream('ffv1')
            stream.width, stream.height, stream.pix_fmt = width * 2, height, 'yuv420p'
            stream.time_base = stream.codec_context.time_base = Fraction(1, 1000)
            stream.codec_context.thread_count = 1
            for pair in plan:
                if time.monotonic() - started > MAX_EXPORT_SECONDS:
                    raise ValueError('artifact encode session limit exceeded')
                left, right = (spool.read(i) for i in pair['decoded_ids'])
                pixels = PREVIEW['compose'](left, right, width, height)
                frame = video_frame(av, pixels, width * 2, height, pair['request_at_ms'])
                for packet in stream.encode(frame):
                    container.mux(packet)
                rows.append(dict(pair, artifact_pts=frame.pts, time_base_num=1, time_base_den=1000,
                                 composed_pixel_sha256=hashlib.sha256(pixels).hexdigest()))
                if output.tell() > MAX_OUTPUT_BYTES:
                    raise ValueError('encoded artifact size limit exceeded')
            for packet in stream.encode():
                container.mux(packet)
        if time.monotonic() - started > MAX_EXPORT_SECONDS:
            raise ValueError('artifact encode session limit exceeded')
        output.flush()
        if os.fstat(output.fileno()).st_size > MAX_OUTPUT_BYTES:
            raise ValueError('encoded artifact size limit exceeded')
        os.fsync(output.fileno())
        os.link(output.name, destination)  # Atomic, exclusive publish; collision never overwrites.
        if publication is not None:
            publication.update(artifact_published=True, artifact_frames=rows)
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('--container', required=True, choices=DECODE['AUDIO']['FORMATS'])
    parser.add_argument('--primary-stream', required=True, type=int)
    parser.add_argument('--secondary-stream', required=True, type=int)
    parser.add_argument('--event-map', required=True, type=Path)
    parser.add_argument('--observed-queues', action='store_true',
                        help='require explicit render admission/release commit observations')
    parser.add_argument('--pts-clock', required=True, choices=('request-observation',))
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--receipt', required=True, type=Path)
    args = parser.parse_args()
    status, code, error = 'completed', 0, None
    evidence: dict[str, Any] = dict(artifact_published=False)
    try:
        with args.receipt.open('x') as receipt:
            try:
                if os.path.lexists(args.output):
                    raise FileExistsError('scheduled video destination already exists')
                with tempfile.TemporaryFile() as temporary:
                    spool = PREVIEW['Spool'](temporary)
                    with DECODE['AUDIO']['open_source'](args.source) as source:
                        report = DECODE['decode'](source, args.container,
                            (args.primary_stream, args.secondary_stream), spool.capture)
                    with DECODE['AUDIO']['open_source'](args.event_map) as events:
                        result = replay(report, events, args.observed_queues)
                    evidence = dict(artifact_published=False, replay=result, decoded_frames=report['decoded_frames'],
                                    decoder=dict(pyav_version=report['pyav_version'],
                                                 library_versions=report['library_versions']))
                    plan, width, height = plan_frames(result, spool)
                    evidence['artifact_frames'] = export(plan, spool, width, height, args.output, evidence)
            except (Exception, KeyboardInterrupt) as failure:
                code = 130 if isinstance(failure, KeyboardInterrupt) else 2
                status = 'cancelled' if code == 130 else 'failed'
                error = f'{type(failure).__name__}: {failure}'
            json.dump(dict(profile='scheduled-paired-video-artifact-v1', status=status, error=error,
                pts_clock='explicit-request-observation-not-native-elapsed-or-source-media',
                codec='lossless-ffv1', layout='side-by-side-not-native-compositor',
                physical_lip_sync_measured=False, native_header_provenance_verified=False,
                artifact_is_physical_display=False, decoder_buffer_ownership_verified=False, **evidence), receipt, sort_keys=True)
            receipt.write('\n')
    except OSError as failure:
        code, error = 2, str(failure)
    if error:
        print(f'scheduled video failed: {error}', file=sys.stderr)
    return code


if __name__ == '__main__':
    raise SystemExit(main())
