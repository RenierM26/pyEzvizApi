"""Export audited native snapshots selected by explicit observed queue/clock events.

Local private snapshots only: no decoder, camera, display, audio or inferred
pairing/timing. Native headers and renderer observations remain caller provenance.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import sys
import tempfile
from typing import Any, BinaryIO

AUDIT = runpy.run_path(str(Path(__file__).with_name('app_native_pixel_audit.py')))
SCHEDULED = runpy.run_path(str(Path(__file__).with_name('app_scheduled_video.py')))
NATIVE_FIELDS = {'sample_id', 'pixel_sha256'}
SpoolBase: Any = SCHEDULED['PREVIEW']['Spool']
ReplayBase: Any = SCHEDULED['CoupledReplay']


class NativeSpool(SpoolBase):
    """Private host copies, indexed by native sample ID, not an invented codec PTS."""

    def capture(self, row: dict[str, Any], data: bytes) -> None:
        if (len(data) != row['width'] * row['visible_height'] * 3 // 2
                or hashlib.sha256(data).hexdigest() != row['canonical_pixel_sha256']):
            raise ValueError('canonical native pixel copy does not match audited fingerprint')
        if self.size + len(data) > AUDIT['MAX_TOTAL_BYTES']:
            raise ValueError('native pixel spool limit exceeded')
        if row['id'] in self.records:
            raise ValueError('duplicate native sample identity')
        offset = self.source.tell()
        if self.source.write(data) != len(data):
            raise ValueError('short native pixel spool write')
        self.records[row['id']] = dict(width=row['width'], height=row['visible_height'],
            pixel_sha256=row['canonical_pixel_sha256'], offset=offset, size=len(data))
        self.size += len(data)


class NativeReplay(ReplayBase):
    """Reuse queue policy, replacing only the exact picture/header binding boundary."""

    def __init__(self, report: dict[str, Any]) -> None:
        # decoded_id is an internal shared-planner key only. No HEVC track, PTS,
        # time base or decoder frame index is created for these native samples.
        super().__init__(dict(decoded_frames=[dict(row, decoded_id=row['id'])
            for row in report['samples']], primary_stream=224, secondary_stream=225),
            observed_queues=True)

    def bind_picture(self, event: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        identity = event.get('sample_id')
        if not isinstance(identity, str) or identity not in self.decoded:
            raise ValueError('unknown native sample identity')
        row = self.decoded[identity]
        expected = dict(lens=row['lens'], raw_time=row['raw_timestamp'],
                        media_ms=row['media_ms'], frame_number=row['frame_index'],
                        pixel_sha256=row['canonical_pixel_sha256'])
        for key, value in expected.items():
            if type(event.get(key)) is not type(value) or event[key] != value:
                raise ValueError(f'native sample binding mismatch: {key}')
        normalized = {k: v for k, v in event.items() if k not in NATIVE_FIELDS}
        return normalized, dict(offer_id=event.get('id'), decoded_id=identity)

    def result(self) -> dict[str, Any]:
        if self.used != self.decoded.keys():
            raise ValueError('event map must account for every audited native sample')
        return super().result()


def replay(report: dict[str, Any], events: BinaryIO) -> dict[str, Any]:
    model = NativeReplay(report)
    sim = SCHEDULED['SIM']
    for _ in range(sim['MAX_EVENTS'] + 1):
        line = events.readline(sim['MAX_LINE_BYTES'] + 1)
        if not line:
            break
        if len(line) > sim['MAX_LINE_BYTES']:
            raise ValueError('native event line limit exceeded')
        model.step(json.loads(line))
    else:
        raise ValueError('native event limit exceeded')
    return model.result()


def receipt_names(value: Any) -> Any:
    """Label shared planner keys as native samples in the public native receipt."""
    if isinstance(value, dict):
        # Offer IDs are opaque user keys, even when named "decoded_ids".
        return {('native_sample_ids' if k == 'decoded_ids' else k):
                v if k == 'offer_bindings' else receipt_names(v) for k, v in value.items()}
    if isinstance(value, list):
        return [receipt_names(v) for v in value]
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input_snapshots', type=Path)
    parser.add_argument('render_snapshots', type=Path)
    parser.add_argument('manifest', type=Path)
    parser.add_argument('--event-map', required=True, type=Path)
    parser.add_argument('--pts-clock', required=True, choices=('request-observation',))
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--receipt', required=True, type=Path)
    args = parser.parse_args()
    code, status, error = 0, 'completed', None
    evidence: dict[str, Any] = dict(artifact_published=False)
    try:
        with args.receipt.open('x') as receipt:
            try:
                if os.path.lexists(args.output):
                    raise FileExistsError('native scheduled video destination already exists')
                with tempfile.TemporaryFile() as temporary:
                    spool = NativeSpool(temporary)
                    with (AUDIT['SOURCE']['open_source'](args.input_snapshots) as source,
                          AUDIT['SOURCE']['open_source'](args.render_snapshots) as rendered,
                          AUDIT['SOURCE']['open_source'](args.manifest) as manifest):
                        report = AUDIT['audit'](source, rendered, manifest,
                                               verify_renderer=True, observer=spool.capture)
                    evidence['native_audit'] = report
                    with AUDIT['SOURCE']['open_source'](args.event_map) as events:
                        result = replay(report, events)
                    evidence['replay'] = result
                    plan, width, height = SCHEDULED['plan_frames'](result, spool)
                    evidence['artifact_frames'] = SCHEDULED['export'](
                        plan, spool, width, height, args.output, evidence)
            except (Exception, KeyboardInterrupt) as failure:
                code = 130 if isinstance(failure, KeyboardInterrupt) else 2
                status = 'cancelled' if code == 130 else 'failed'
                error = f'{type(failure).__name__}: {failure}'
            json.dump(receipt_names(dict(profile='native-scheduled-video-artifact-v1',
                status=status, error=error, source='audited-native-snapshots-not-hevc-decoding',
                provenance='caller-manifests-not-authenticated', codec='lossless-ffv1',
                layout='side-by-side-not-native-compositor',
                pts_clock='explicit-request-observation-not-native-elapsed-or-source-media',
                artifact_is_physical_display=False, physical_lip_sync_measured=False,
                native_header_provenance_verified=False, decoder_buffer_ownership_verified=False,
                **evidence)), receipt, sort_keys=True)
            receipt.write('\n')
    except OSError as failure:
        code, error = 2, str(failure)
    if error:
        print(f'native scheduled video failed: {error}', file=sys.stderr)
    return code


if __name__ == '__main__':
    raise SystemExit(main())
