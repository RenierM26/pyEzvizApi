"""Native snapshots keep exact headers, distinct chroma and observed queue boundaries."""

from fractions import Fraction
import hashlib
import io
import json
from pathlib import Path
import runpy
import shutil
import subprocess
import sys

import pytest

SCRIPT = Path(__file__).parents[1] / 'tools/app_native_scheduled_video.py'
MODULE = runpy.run_path(str(SCRIPT))
AUDIT_TEST = runpy.run_path(str(Path(__file__).with_name('test_app_native_pixel_audit.py')))
SCHEDULE_TEST = runpy.run_path(str(Path(__file__).with_name('test_app_scheduled_video.py')))


def jsonl(rows):
    return io.BytesIO(b''.join((json.dumps(row) + '\n').encode() for row in rows))


def snapshots(count=3):
    rows, inputs, renders = [], b'', b''
    for index in range(count):
        for lens in (1, 0):
            row, source, rendered = AUDIT_TEST['renderer_sample']()
            row.update(id=f'native:{lens}:{index}', input_offset=len(inputs), render_offset=len(renders))
            for key in ('input_header', 'render_header'):
                for offset, value in {1: 224 + lens, 5: index * 66, 7: 3000 + index, 10: index}.items():
                    row[key][offset] = value
            row['renderer_layout'].update(sid=224 + lens, raw_timestamp=3000 + index, frame_index=index)
            # Distinct Y, V, U plus different values on every lens/frame.
            source = bytes((v + index * 7 + lens * 19) % 256 for v in source)
            rendered = source[:48] + source[64:76] + source[80:92]
            row.update(input_sha256=hashlib.sha256(source).hexdigest(),
                       render_sha256=hashlib.sha256(rendered).hexdigest())
            inputs += source
            renders += rendered
            rows.append(row)
    return rows, inputs, renders


def load(rows, inputs, renders, spool=None):
    if spool is None:
        spool = MODULE['NativeSpool'](io.BytesIO())
    report = MODULE['AUDIT']['audit'](io.BytesIO(inputs), io.BytesIO(renders), jsonl(rows),
                                     verify_renderer=True, observer=spool.capture)
    return spool, report


def offers(report):
    return [dict(kind='lens_picture', at_ms=0, id=f'offer:{i}', sample_id=row['id'],
                 lens=row['lens'], raw_time=row['raw_timestamp'], media_ms=row['media_ms'],
                 frame_number=row['frame_index'], pixel_sha256=row['canonical_pixel_sha256'])
            for i, row in enumerate(report['samples'])]


def events(report):
    count = len(report['samples']) // 2
    result = offers(report)
    result.extend(dict(kind='render_admit', at_ms=0, id=f'pair:{i}') for i in range(count))
    result.append(dict(kind='video_epoch', at_ms=0, epoch=0, origin_ms=0))
    for i, (at, elapsed) in enumerate(((70, 50), (155, 116), (400, 250))[:count]):
        result.extend([SCHEDULE_TEST['tick'](i, at, elapsed, count - i, i * 66),
                       dict(kind='render_release', at_ms=at + 1, id=f'pair:{i}'),
                       SCHEDULE_TEST['completion'](i, at + 2, count - i - 1)])
    return result


def test_native_samples_canonical_spool_exact_headers_and_completed_selections():
    rows, inputs, renders = snapshots()
    spool, report = load(rows, inputs, renders)
    for i, row in enumerate(report['samples']):
        native = renders[i * 72:(i + 1) * 72]
        assert spool.read(row['id']) == native[:48] + native[60:] + native[48:60]
    result = MODULE['replay'](report, jsonl(events(report)))
    plan, width, height = MODULE['SCHEDULED']['plan_frames'](result, spool)
    assert (width, height) == (8, 6)
    assert [p['request_at_ms'] for p in plan] == [70, 155, 400]
    assert [p['decoded_ids'] for p in plan] == [[f'native:0:{i}', f'native:1:{i}'] for i in range(3)]
    assert result['queue_boundary_mode'] == 'observed-commit-boundaries'
    assert result['queue_releases_pending'] == []
    public = MODULE['receipt_names'](result)
    assert public['selected'][0]['native_sample_ids'] == ['native:0:0', 'native:1:0']
    assert 'decoded_ids' not in json.dumps(public)


@pytest.mark.parametrize(('key', 'value'), [('sample_id', 'unknown'), ('sample_id', True),
    ('lens', 1), ('raw_time', 9), ('media_ms', 1), ('frame_number', 5),
    ('pixel_sha256', '0' * 64), ('raw_time', True), ('lens', False), ('media_ms', 0.0)])
def test_native_binding_rejects_relabelled_headers_or_pixels(key, value):
    _, report = load(*snapshots(1))
    event = next(e for e in offers(report) if e['lens'] == 0)
    event[key] = value
    with pytest.raises(ValueError, match='native sample'):
        MODULE['replay'](report, jsonl([event]))


@pytest.mark.parametrize('extra', ['decoded_id', 'pts', 'time_base_num', 'stream_index', 'unknown'])
def test_native_event_contract_does_not_accept_codec_fields(extra):
    _, report = load(*snapshots(1))
    event = dict(offers(report)[0], **{extra: 0})
    with pytest.raises(ValueError, match='unsupported event fields'):
        MODULE['replay'](report, jsonl([event]))


def test_accounting_explicit_retries_and_pending_are_not_invented_completion():
    spool, report = load(*snapshots(1))
    with pytest.raises(ValueError, match='every audited'):
        MODULE['replay'](report, jsonl(offers(report)[:1]))
    result = MODULE['replay'](report, jsonl(events(report)[:-2]))
    assert result['request_pending']['pair_id'] == 'pair:0'
    assert result['queue_releases_pending'][0]['id'] == 'pair:0'
    assert not result['selected']
    with pytest.raises(ValueError, match='no completed'):
        MODULE['SCHEDULED']['plan_frames'](result, spool)
    retry = dict(offers(report)[0], id='explicit-retry')
    retried = MODULE['replay'](report, jsonl([*offers(report), retry]))
    assert retried['offer_bindings']['explicit-retry'] == report['samples'][0]['id']


def test_different_native_raw_times_do_not_become_a_pair():
    rows, inputs, renders = snapshots(1)
    rows[1]['input_header'][7] += 1
    rows[1]['render_header'][7] += 1
    rows[1]['renderer_layout']['raw_timestamp'] += 1
    spool, report = load(rows, inputs, renders)
    result = MODULE['replay'](report, jsonl(offers(report)))
    assert result['staging']['summary']['pairs_assembled'] == 0
    with pytest.raises(ValueError, match='no completed'):
        MODULE['SCHEDULED']['plan_frames'](result, spool)


def test_admission_and_release_cannot_be_synthesized_from_snapshot_presence():
    _, report = load(*snapshots(1))
    data = events(report)
    for kind, match in [('render_admit', 'unconsumed head'), ('render_release', 'observed queue release')]:
        with pytest.raises(ValueError, match=match):
            MODULE['replay'](report, jsonl([e for e in data if e['kind'] != kind]))


def test_native_late_drops_consume_same_spool_bound_fifo():
    _, report = load(*snapshots())
    data = events(report)[:10]  # six offers, three admissions, epoch
    data.extend([SCHEDULE_TEST['tick'](0, 300, 300, 3),
                 *[dict(kind='render_release', at_ms=301, id=f'pair:{i}') for i in range(3)],
                 SCHEDULE_TEST['completion'](2, 302, 0)])
    result = MODULE['replay'](report, jsonl(data))
    assert [r['pair_id'] for r in result['selected']] == ['pair:2']
    assert result['scheduler']['summary']['video_dropped'] == 2
    assert result['staging']['summary']['render_taken'] == 3


def test_observer_requires_renderer_binding_and_spool_checks_its_own_copy(monkeypatch):
    rows, inputs, renders = snapshots(1)
    with pytest.raises(ValueError, match='requires renderer'):
        MODULE['AUDIT']['audit'](io.BytesIO(inputs), io.BytesIO(renders), jsonl(rows),
                                 observer=lambda *args: None)
    spool, report = load(rows, inputs, renders)
    row = report['samples'][0]
    data = spool.read(row['id'])
    with pytest.raises(ValueError, match='fingerprint'):
        MODULE['NativeSpool'](io.BytesIO()).capture(row, b'x' * len(data))
    with pytest.raises(ValueError, match='duplicate'):
        spool.capture(row, data)
    monkeypatch.setitem(MODULE['AUDIT'], 'MAX_TOTAL_BYTES', 1)
    with pytest.raises(ValueError, match='spool limit'):
        MODULE['NativeSpool'](io.BytesIO()).capture(row, data)


def cli(tmp_path, rows, inputs, renders, event_rows):
    paths = [tmp_path / n for n in ('input.bin', 'render.bin', 'manifest.jsonl', 'events.jsonl')]
    for path, data in zip(paths, (inputs, renders, jsonl(rows).getvalue(), jsonl(event_rows).getvalue()), strict=True):
        path.write_bytes(data)
    artifact, receipt = tmp_path / 'native.mkv', tmp_path / 'receipt.json'
    cmd = [sys.executable, str(SCRIPT), *map(str, paths[:3]), '--event-map', str(paths[3]),
           '--pts-clock', 'request-observation', '--output', str(artifact), '--receipt', str(receipt)]
    return cmd, artifact, receipt


def test_actual_native_snapshot_ffv1_cli_pixels_and_observation_pts(tmp_path):
    av = pytest.importorskip('av')
    rows, inputs, renders = snapshots()
    spool, report = load(rows, inputs, renders)
    cmd, artifact, receipt = cli(tmp_path, rows, inputs, renders, events(report))
    process = subprocess.run(cmd, capture_output=True, timeout=20, check=False)
    assert process.returncode == 0, process.stderr.decode()
    result = json.loads(receipt.read_text())
    assert result['status'] == 'completed' and result['artifact_published']
    assert result['native_audit']['samples_verified'] == 6
    assert not result['native_header_provenance_verified']
    assert not result['artifact_is_physical_display']
    assert 'decoded_ids' not in receipt.read_text() and 'decoder' not in result
    with av.open(str(artifact)) as container:
        assert container.streams.video[0].codec_context.name == 'ffv1'
        frames = list(container.decode(video=0))
    assert [f.pts * f.time_base for f in frames] == [Fraction(t, 1000) for t in (70, 155, 400)]
    expected = [MODULE['SCHEDULED']['PREVIEW']['compose'](
        spool.read(f'native:0:{i}'), spool.read(f'native:1:{i}'), 8, 6) for i in range(3)]
    assert [MODULE['SCHEDULED']['PREVIEW']['pack'](f) for f in frames] == expected
    assert [r['composed_pixel_sha256'] for r in result['artifact_frames']] == [
        hashlib.sha256(p).hexdigest() for p in expected]
    if shutil.which('ffmpeg'):
        independent = subprocess.run(['ffmpeg', '-v', 'error', '-i', str(artifact),
            '-fps_mode', 'passthrough', '-pix_fmt', 'yuv420p', '-f', 'rawvideo', '-'],
            capture_output=True, timeout=15, check=True).stdout
        assert independent == b''.join(expected)
    if shutil.which('ffprobe'):
        probe = subprocess.run(['ffprobe', '-v', 'error', '-show_frames',
            '-show_entries', 'frame=pts_time', '-of', 'json', str(artifact)],
            capture_output=True, timeout=15, check=True)
        assert [Fraction(f['pts_time']) for f in json.loads(probe.stdout)['frames']] == [
            Fraction(t, 1000) for t in (70, 155, 400)]
    assert not list(tmp_path.glob('.scheduled-*'))


@pytest.mark.parametrize('change', ['trailing', 'bad-last-layout', 'binding', 'uncompleted', 'output-exists'])
def test_cli_validates_whole_source_before_publish_and_preserves_existing_output(tmp_path, change):
    rows, inputs, renders = snapshots(1)
    _, report = load(rows, inputs, renders)
    data = events(report)
    if change == 'trailing':
        renders += b'x'
    elif change == 'bad-last-layout':
        rows[-1]['renderer_layout']['renderer_format'] = 3
    elif change == 'binding':
        data[0]['raw_time'] += 1
    elif change == 'uncompleted':
        data = data[:-1]
    cmd, artifact, receipt = cli(tmp_path, rows, inputs, renders, data)
    if change == 'output-exists':
        artifact.write_bytes(b'keep')
    p = subprocess.run(cmd, capture_output=True, timeout=10, check=False)
    assert p.returncode == 2
    result = json.loads(receipt.read_text())
    assert result['status'] == 'failed' and not result['artifact_published']
    assert artifact.read_text() == 'keep' if change == 'output-exists' else not artifact.exists()
    assert not list(tmp_path.glob('.scheduled-*'))


def test_receipt_collision_preserves_input_and_artifact(tmp_path):
    rows, inputs, renders = snapshots(1)
    _, report = load(rows, inputs, renders)
    cmd, artifact, receipt = cli(tmp_path, rows, inputs, renders, events(report))
    receipt.write_text('keep')
    result = subprocess.run(cmd, capture_output=True, timeout=10, check=False)
    assert result.returncode == 2
    assert receipt.read_text() == 'keep' and not artifact.exists()


def test_native_event_limits_and_invalid_json():
    _, report = load(*snapshots(1))
    for raw in (b'x' * 8193, b'{bad}\n'):
        with pytest.raises(ValueError):
            MODULE['replay'](report, io.BytesIO(raw))
    model = MODULE['NativeReplay'](report)
    model.events = 10_000
    with pytest.raises(ValueError, match='event limit'):
        model.step(dict(kind='stage_push', at_ms=0))


def test_receipt_preserves_opaque_offer_ids_that_resemble_schema_keys():
    result = MODULE['receipt_names'](dict(offer_bindings={
        'decoded_ids': 'native:0', 'native_sample_ids': 'native:1'},
        selected=[dict(decoded_ids=['native:0', 'native:1'])]))
    assert result['offer_bindings'] == {'decoded_ids': 'native:0', 'native_sample_ids': 'native:1'}
    assert result['selected'][0]['native_sample_ids'] == ['native:0', 'native:1']


def test_real_native_lens_geometry_fits_bounded_native_plan_not_old_hevc_default():
    spool = MODULE['NativeSpool'](io.BytesIO())
    spool.records = {identity: dict(width=2880, height=1620) for identity in ('left', 'right')}
    result = dict(selected=[dict(decoded_ids=['left', 'right'], request_at_ms=70)])
    with pytest.raises(ValueError, match='paired pixel limit'):
        MODULE['SCHEDULED']['plan_frames'](result, spool)
    _, width, height = MODULE['SCHEDULED']['plan_frames'](
        result, spool, max_pair_pixels=MODULE['MAX_PAIR_PIXELS'])
    assert (width, height) == (2880, 1620)
    for row in spool.records.values():
        row.update(width=4096, height=4096)
    with pytest.raises(ValueError, match='paired pixel limit'):
        MODULE['SCHEDULED']['plan_frames'](result, spool, max_pair_pixels=MODULE['MAX_PAIR_PIXELS'])


def metadata_offers():
    rows, _, _ = snapshots(2)
    return [dict(kind='lens_picture', at_ms=0, id=f'metadata:{i}', lens=row['input_header'][1] - 224,
                 raw_time=row['input_header'][7], media_ms=row['input_header'][5],
                 frame_number=row['input_header'][10], native_header=row['input_header'])
            for i, row in enumerate(rows[2:])]


def sparse_events(report, complete_metadata=False):
    rows = [*offers(report), *metadata_offers(), dict(kind='render_admit', at_ms=0, id='pair:0'),
            dict(kind='render_admit', at_ms=0, id='pair:1'),
            dict(kind='video_epoch', at_ms=0, epoch=0, origin_ms=0),
            SCHEDULE_TEST['tick'](0, 70, 50, 2, 0),
            dict(kind='render_release', at_ms=71, id='pair:0'),
            SCHEDULE_TEST['completion'](0, 72, 1)]
    if complete_metadata:
        rows.extend([SCHEDULE_TEST['tick'](1, 155, 116, 1, 66),
                     dict(kind='render_release', at_ms=156, id='pair:1'),
                     SCHEDULE_TEST['completion'](1, 157, 0)])
    return rows


def test_metadata_only_opt_in_preserves_unsampled_queue_and_null_pixel_bindings():
    spool, report = load(*snapshots(1))
    data = sparse_events(report)
    with pytest.raises(ValueError, match='explicit opt-in'):
        MODULE['replay'](report, jsonl(data))
    result = MODULE['replay'](report, jsonl(data), allow_metadata_only=True)
    assert len(result['metadata_only_offers']) == 2
    assert result['offer_bindings']['metadata:0'] is None
    assert not result['metadata_only_offers']['metadata:0']['pixels_verified']
    assert result['scheduler']['summary']['video_pending'] == ['pair:1']
    plan, width, height = MODULE['plan_frames'](result, spool)
    assert len(plan) == 1 and (width, height) == (8, 6)
    assert plan[0]['decoded_ids'] == ['native:0:0', 'native:1:0']


@pytest.mark.parametrize(('key', 'value'), [('lens', False), ('raw_time', 0),
    ('media_ms', 0.0), ('frame_number', 7), ('sample_id', 'native:0:0'),
    ('pixel_sha256', '0' * 64), ('id', []), ('native_header', [0] * 49)])
def test_metadata_only_rejects_relabelled_or_mixed_header_contract(key, value):
    _, report = load(*snapshots(1))
    row = dict(metadata_offers()[0], **{key: value})
    with pytest.raises(ValueError):
        MODULE['replay'](report, jsonl([row]), allow_metadata_only=True)


def test_metadata_only_header_is_complete_uint32_geometry_and_offer_identity_is_unique():
    _, report = load(*snapshots(1))
    row = metadata_offers()[0]
    for offset, value in [(0, 0), (1, 226), (37, 3), (10, True)]:
        header = list(row['native_header'])
        header[offset] = value
        with pytest.raises(ValueError):
            MODULE['replay'](report, jsonl([dict(row, native_header=header)]), allow_metadata_only=True)
    with pytest.raises(ValueError, match='unique bounded identity'):
        MODULE['replay'](report, jsonl([row, row]), allow_metadata_only=True)


def test_completed_metadata_only_selection_fails_instead_of_omitting_or_reusing_pixels():
    spool, report = load(*snapshots(1))
    result = MODULE['replay'](report, jsonl(sparse_events(report, True)), allow_metadata_only=True)
    assert len(result['selected']) == 2
    assert result['selected'][1]['decoded_ids'] == [None, None]
    with pytest.raises(ValueError, match='completed selection lacks verified native pixels'):
        MODULE['plan_frames'](result, spool)


@pytest.mark.parametrize('complete_metadata', [False, True])
def test_sparse_cli_exports_bound_completion_only_and_fails_before_publish_for_unbound(tmp_path, complete_metadata):
    if not complete_metadata:
        pytest.importorskip('av')
    rows, inputs, renders = snapshots(1)
    _, report = load(rows, inputs, renders)
    cmd, artifact, receipt = cli(tmp_path, rows, inputs, renders, sparse_events(report, complete_metadata))
    p = subprocess.run([*cmd, '--allow-metadata-only'], capture_output=True, timeout=20, check=False)
    result = json.loads(receipt.read_text())
    assert result['metadata_only_offers_allowed']
    assert result['replay']['offer_bindings']['metadata:0'] is None
    if complete_metadata:
        assert p.returncode == 2 and not artifact.exists()
        assert not result['artifact_published']
        assert 'completed selection lacks verified native pixels' in result['error']
        assert result['replay']['selected'][1]['native_sample_ids'] == [None, None]
    else:
        assert p.returncode == 0 and result['artifact_published']
        assert len(result['artifact_frames']) == 1
        assert result['replay']['scheduler']['summary']['video_pending'] == ['pair:1']
    assert not list(tmp_path.glob('.scheduled-*'))


def test_metadata_offer_ids_are_opaque_in_receipts():
    value = dict(metadata_only_offers={'decoded_ids': dict(native_header=[1], pixels_verified=False)})
    assert MODULE['receipt_names'](value) == value


def test_metadata_only_drop_consumes_fifo_without_requiring_or_exporting_pixels():
    spool, report = load(*snapshots(1))
    metadata = metadata_offers()
    for row in metadata:
        row['media_ms'] = row['native_header'][5] = 0
    rows = [*metadata, *offers(report),
            *[dict(kind='render_admit', at_ms=0, id=f'pair:{i}') for i in range(2)],
            dict(kind='video_epoch', at_ms=0, epoch=0, origin_ms=0),
            SCHEDULE_TEST['tick'](0, 300, 300, 2),
            *[dict(kind='render_release', at_ms=301, id=f'pair:{i}') for i in range(2)],
            SCHEDULE_TEST['completion'](1, 302, 0)]
    result = MODULE['replay'](report, jsonl(rows), allow_metadata_only=True)
    assert result['scheduler']['summary']['video_dropped'] == 1
    assert result['staging']['summary']['render_taken'] == 2
    plan, _, _ = MODULE['plan_frames'](result, spool)
    assert len(plan) == 1 and plan[0]['pair_id'] == 'pair:1'


def test_one_unverified_lens_is_not_filled_from_a_different_sample():
    rows, inputs, renders = snapshots(2)
    spool, report = load(rows[:3], inputs[:3 * 96], renders[:3 * 72])
    data = sparse_events(report, True)
    # sparse_events includes the third audited offer; supply only its missing counterpart.
    data = [e for e in data if e.get('id') != 'metadata:0']
    result = MODULE['replay'](report, jsonl(data), allow_metadata_only=True)
    assert result['selected'][1]['decoded_ids'] == [None, 'native:1:1']
    with pytest.raises(ValueError, match='completed selection lacks verified native pixels'):
        MODULE['plan_frames'](result, spool)
