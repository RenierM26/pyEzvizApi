"""Coupled native-clock selections, lossless pixels, exact artifact PTS and publish safety."""

import hashlib
import io
import json
from pathlib import Path
import runpy
import shutil
import subprocess
import sys

import pytest

SCRIPT = Path(__file__).parents[1] / 'tools/app_scheduled_video.py'
MODULE = runpy.run_path(str(SCRIPT))
DECODE_TEST = runpy.run_path(str(Path(__file__).with_name('test_app_video_decode.py')))


def synthetic(count=3):
    spool = MODULE['PREVIEW']['Spool'](io.BytesIO())
    rows, events = [], []
    for index in range(count):
        for lens in (1, 0):
            frame = DECODE_TEST['frame'](pts=index)
            row = MODULE['DECODE']['fingerprint'](frame, lens, index)
            spool.capture(row, frame)
            rows.append(row)
            events.append(DECODE_TEST['offer'](row, lens, f'{lens}:{index}',
                          raw_time=index, media_ms=index * 66))
    report = dict(decoded_frames=rows, primary_stream=0, secondary_stream=1)
    events.append(dict(kind='video_epoch', at_ms=0, epoch=0, origin_ms=0))
    return spool, report, events


def tick(pair, at, elapsed, depth, media=0):
    return dict(kind='video_observed_tick', at_ms=at, epoch=0, id=f'pair:{pair}',
                relative_ms=media, elapsed_ms=elapsed, depth=depth, speed=1,
                bias_ms=50, interval_ms=66)


def completion(pair, at, depth):
    return dict(kind='video_display_complete', at_ms=at, id=f'pair:{pair}', depth=depth)


def run(report, events):
    return MODULE['replay'](report, DECODE_TEST['header_source'](events))


def test_hold_late_drops_and_display_consume_the_same_staging_fifo():
    _, report, events = synthetic()
    events.extend([tick(0, 0, 0, 3), tick(0, 300, 300, 3), completion(2, 301, 0)])
    result = run(report, events)
    assert [p['pair_id'] for p in result['selected']] == ['pair:2']
    assert result['scheduler']['summary']['video_dropped'] == 2
    assert result['scheduler']['summary']['video_display_completed'] == 1
    assert result['staging']['summary']['render_taken'] == 3
    assert result['staging']['summary']['render_pending'] == []
    assert result['request_pending'] is None


def test_inflight_and_unconsumed_frames_are_not_export_selections():
    spool, report, events = synthetic(2)
    events.append(tick(0, 70, 50, 2))
    result = run(report, events)
    assert result['selected'] == []
    assert result['request_pending']['pair_id'] == 'pair:0'
    assert result['scheduler']['summary']['video_pending'] == ['pair:1']
    assert result['staging']['summary']['render_pending'][0]['pair_id'] == 'pair:1'
    with pytest.raises(ValueError, match='no completed'):
        MODULE['plan_frames'](result, spool)


def test_observation_request_time_not_native_elapsed_media_or_completion():
    spool, report, events = synthetic()
    for index, (at, elapsed) in enumerate(((70, 50), (155, 116), (400, 250))):
        events.extend([tick(index, at, elapsed, 3 - index, index * 66),
                       completion(index, at + 1, 2 - index)])
    result = run(report, events)
    plan, width, height = MODULE['plan_frames'](result, spool)
    assert (width, height) == (4, 4)
    assert [p['request_at_ms'] for p in plan] == [70, 155, 400]
    assert [p['primary_media_ms'] for p in plan] == [0, 66, 132]
    assert [p['observed_complete_at_ms'] for p in plan] == [71, 156, 401]
    assert all(p['offer_ids'][0].startswith('0:') for p in plan)


@pytest.mark.parametrize('event', [None, [], {}, dict(kind=[], at_ms=0),
    dict(kind='render_take', at_ms=0), dict(kind='video_picture', at_ms=0),
    dict(kind='audio_begin', at_ms=0), dict(kind='stage_push', at_ms=True),
    dict(kind='stage_push', at_ms=3_600_001), dict(kind='stage_push', at_ms=0, extra=1)])
def test_unified_map_rejects_synthetic_admissions_audio_unknown_and_invalid_time(event):
    _, report, _ = synthetic(1)
    with pytest.raises(ValueError):
        MODULE['CoupledReplay'](report).step(event)


def test_model_state_and_binding_failures_do_not_become_selected_pixels():
    _, report, events = synthetic(1)
    bad = dict(events[0], pixel_sha256='0' * 64)
    with pytest.raises(ValueError, match='binding mismatch'):
        run(report, [bad])
    with pytest.raises(ValueError, match='every decoded'):
        run(report, events[:1])
    with pytest.raises(ValueError, match='head/depth'):
        run(report, [*events, tick(0, 50, 50, 2)])
    with pytest.raises(ValueError, match='must match'):
        run(report, [*events, completion(0, 50, 0)])
    model = MODULE['CoupledReplay'](report)
    model.step(dict(kind='stage_push', at_ms=2))
    with pytest.raises(ValueError, match='observation time'):
        model.step(events[0])


def test_backpressure_keeps_complete_stage_until_explicit_push():
    _, report, events = synthetic(7)
    # Six admitted pairs and one complete blocked staging node.
    events.extend([tick(0, 50, 50, 6)])
    result = run(report, events)
    assert len(result['staging']['summary']['render_pending']) == 5
    assert len(result['staging']['summary']['staging_pending']) == 1
    # Explicit completion sees post-display depth 5, then stage_push admits pair:6.
    events.extend([completion(0, 51, 5), dict(kind='stage_push', at_ms=52)])
    pushed = run(report, events)
    assert len(pushed['staging']['summary']['render_pending']) == 6
    assert pushed['staging']['summary']['staging_pending'] == []
    assert pushed['scheduler']['summary']['video_pending'][-1] == 'pair:6'


def test_unified_event_and_line_bounds():
    _, report, _ = synthetic(1)
    model = MODULE['CoupledReplay'](report)
    model.events = 10_000
    with pytest.raises(ValueError, match='event limit'):
        model.step(dict(kind='stage_push', at_ms=0))
    for raw in (b' ' * 8193, b'{bad}\n'):
        with pytest.raises(ValueError):
            MODULE['replay'](report, io.BytesIO(raw))


def test_geometry_and_strict_request_pts_reject_before_artifact():
    spool, report, events = synthetic(2)
    events.extend([tick(0, 50, 50, 2), completion(0, 51, 1),
                   tick(1, 116, 116, 1, 66), completion(1, 117, 0)])
    result = run(report, events)
    result['selected'][1]['request_at_ms'] = 50
    with pytest.raises(ValueError, match='strictly increasing'):
        MODULE['plan_frames'](result, spool)
    result['selected'][1]['request_at_ms'] = 116
    spool.records['video:1:1']['height'] = 6
    with pytest.raises(ValueError, match='geometry'):
        MODULE['plan_frames'](result, spool)


def test_real_lossless_variable_pts_artifact_and_cli(tmp_path):
    source = DECODE_TEST['encode_paired_file'](tmp_path)
    av = pytest.importorskip('av')
    decode = MODULE['DECODE']
    with decode['AUDIO']['open_source'](source) as media:
        report = decode['decode'](media, 'matroska', (0, 1))
    events = []
    for index in range(3):
        for lens in (1, 0):
            row = next(r for r in report['decoded_frames']
                       if r['stream_index'] == lens and r['frame_index'] == index)
            events.append(DECODE_TEST['offer'](row, lens, f'{lens}:{index}',
                                              raw_time=index, media_ms=index * 66))
    events.append(dict(kind='video_epoch', at_ms=0, epoch=0, origin_ms=0))
    for i, (at, elapsed) in enumerate(((70, 50), (155, 116), (400, 250))):
        events.extend([tick(i, at, elapsed, 3 - i, i * 66), completion(i, at + 1, 2 - i)])
    event_map = tmp_path / 'events.jsonl'
    event_map.write_bytes(DECODE_TEST['header_source'](events).getvalue())
    artifact, receipt = tmp_path / 'scheduled.mkv', tmp_path / 'receipt.json'
    command = [sys.executable, str(SCRIPT), str(source), '--container', 'matroska',
        '--primary-stream', '0', '--secondary-stream', '1', '--event-map', str(event_map),
        '--pts-clock', 'request-observation', '--output', str(artifact), '--receipt', str(receipt)]
    p = subprocess.run(command, capture_output=True, timeout=20, check=False)
    assert p.returncode == 0, p.stderr.decode()
    result = json.loads(receipt.read_text())
    assert result['status'] == 'completed' and not result['artifact_is_physical_display']
    with av.open(str(artifact)) as container:
        frames = list(container.decode(video=0))
        assert container.streams.video[0].codec_context.name == 'ffv1'
    assert [f.pts * f.time_base * 1000 for f in frames] == [70, 155, 400]
    fingerprints = [decode['fingerprint'](f, 0, i) for i, f in enumerate(frames)]
    expected = [r['composed_pixel_sha256'] for r in result['artifact_frames']]
    assert [r['pixel_sha256'] for r in fingerprints] == expected
    assert all((f.width, f.height) == (128, 48) for f in frames)
    if shutil.which('ffmpeg'):
        raw = subprocess.run(['ffmpeg', '-v', 'error', '-i', str(artifact), '-fps_mode',
            'passthrough', '-f', 'rawvideo', '-pix_fmt', 'yuv420p', '-'],
            capture_output=True, timeout=20, check=False)
        assert raw.returncode == 0, raw.stderr.decode()
        size = 128 * 48 * 3 // 2
        assert len(raw.stdout) == 3 * size
        assert [hashlib.sha256(raw.stdout[i:i + size]).hexdigest()
                for i in range(0, len(raw.stdout), size)] == expected
    if shutil.which('ffprobe'):
        probe = subprocess.run(['ffprobe', '-v', 'error', '-select_streams', 'v:0',
            '-show_entries', 'frame=pts_time', '-of', 'json', str(artifact)],
            capture_output=True, timeout=20, check=False)
        assert probe.returncode == 0
        assert [r['pts_time'] for r in json.loads(probe.stdout)['frames']] == [
            '0.070000', '0.155000', '0.400000']
    # Existing destinations are never replaced, even with a fresh receipt.
    old = artifact.read_bytes()
    command[-1] = str(tmp_path / 'second-receipt.json')
    again = subprocess.run(command, capture_output=True, timeout=20, check=False)
    assert again.returncode == 2 and artifact.read_bytes() == old
    assert not list(tmp_path.glob('.scheduled-*'))


def test_existing_destination_is_never_opened_or_modified(tmp_path):
    destination = tmp_path / 'keep'
    destination.write_text('user data')
    with pytest.raises(FileExistsError):
        MODULE['export']([], None, 4, 4, destination)
    assert destination.read_text() == 'user data'


@pytest.mark.parametrize('mode', ['encode-error', 'cancel', 'collision', 'size', 'deadline'])
def test_failed_export_never_publishes_partial_and_cleans_owned_stage(tmp_path, monkeypatch, mode):
    pytest.importorskip('av')
    spool, report, events = synthetic(1)
    events.extend([tick(0, 50, 50, 1), completion(0, 51, 0)])
    result = run(report, events)
    plan, width, height = MODULE['plan_frames'](result, spool)
    destination = tmp_path / 'scheduled.mkv'
    publication = dict(artifact_published=False)
    globals_ = MODULE['export'].__globals__
    if mode in ('encode-error', 'cancel'):
        def fail(*args):
            if mode == 'cancel':
                raise KeyboardInterrupt
            raise ValueError('injected encoding error')
        monkeypatch.setitem(globals_, 'video_frame', fail)
    if mode == 'collision':
        link = MODULE['os'].link
        def collide(source, target):
            Path(target).write_text('other owner')
            link(source, target)
        monkeypatch.setattr(MODULE['os'], 'link', collide)
    if mode == 'size':
        monkeypatch.setitem(globals_, 'MAX_OUTPUT_BYTES', 0)
    if mode == 'deadline':
        clock = iter((0, 61))
        monkeypatch.setattr(MODULE['time'], 'monotonic', lambda: next(clock))
    with pytest.raises((ValueError, KeyboardInterrupt, FileExistsError)):
        MODULE['export'](plan, spool, width, height, destination, publication)
    if mode == 'collision':
        assert destination.read_text() == 'other owner'
    else:
        assert not destination.exists()
    assert publication['artifact_published'] is False
    assert not list(tmp_path.glob('.scheduled-*'))


def test_repeated_source_offers_cannot_bypass_total_artifact_pixel_budget(monkeypatch):
    spool, report, events = synthetic(1)
    events.extend([tick(0, 50, 50, 1), completion(0, 51, 0)])
    result = run(report, events)
    result['selected'].append(dict(result['selected'][0], pair_id='pair:1', request_at_ms=116))
    monkeypatch.setitem(MODULE['plan_frames'].__globals__, 'MAX_EXPORT_PIXELS', 32)
    with pytest.raises(ValueError, match='total artifact pixel'):
        MODULE['plan_frames'](result, spool)


def test_main_cancelled_export_keeps_verified_replay_and_unpublished_receipt(monkeypatch, tmp_path):
    _, report, events = synthetic(1)
    report.update(pyav_version='test', library_versions={})
    events.extend([tick(0, 50, 50, 1), completion(0, 51, 0)])
    def source(path):
        return DECODE_TEST['header_source'](events) if path.name == 'events' else io.BytesIO(b'x')
    monkeypatch.setitem(MODULE['DECODE']['AUDIO'], 'open_source', source)
    def decode(media, fmt, streams, consume):
        for row in report['decoded_frames']:
            consume(row, DECODE_TEST['frame']())
        return report
    monkeypatch.setitem(MODULE['DECODE'], 'decode', decode)
    def cancel(*args):
        raise KeyboardInterrupt
    monkeypatch.setitem(MODULE['main'].__globals__, 'export', cancel)
    artifact, receipt = tmp_path / 'out.mkv', tmp_path / 'receipt.json'
    monkeypatch.setattr(MODULE['sys'], 'argv', [str(SCRIPT), 'source', '--container', 'matroska',
        '--primary-stream', '0', '--secondary-stream', '1', '--event-map', 'events',
        '--pts-clock', 'request-observation', '--output', str(artifact), '--receipt', str(receipt)])
    assert MODULE['main']() == 130
    result = json.loads(receipt.read_text())
    assert result['status'] == 'cancelled' and not result['artifact_published']
    assert result['replay']['selected'][0]['pair_id'] == 'pair:0'
    assert not artifact.exists()
    # The same receipt cannot be overwritten on another run.
    old = receipt.read_bytes()
    assert MODULE['main']() == 2 and receipt.read_bytes() == old
