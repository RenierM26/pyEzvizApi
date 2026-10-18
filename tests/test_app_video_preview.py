"""Local pixel ownership, explicit queue consumption and nonblocking output lifecycle."""

import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from typing import Any

import pytest

SCRIPT = Path(__file__).parents[1] / 'tools/app_video_preview.py'
MODULE = runpy.run_path(str(SCRIPT))
DECODE_TEST = runpy.run_path(str(Path(__file__).with_name('test_app_video_decode.py')))
pytestmark = pytest.mark.skipif(os.name != 'posix', reason='POSIX preview transport')


def setup_pixels():
    spool = MODULE['Spool'](io.BytesIO())
    for index in (2, 5):
        frame = DECODE_TEST['frame']()
        row = MODULE['DECODE']['fingerprint'](frame, index, 0)
        spool.capture(row, frame)
    report = DECODE_TEST['report']()
    # Both copied frames have source PTS zero; bind the report to those actual records.
    report['decoded_frames'] = list(spool.records.values())
    report.update(pyav_version='test', library_versions={})
    first, second = report['decoded_frames']
    events = [DECODE_TEST['offer'](second, 1, 'right'),
              DECODE_TEST['offer'](first, 0, 'left')]
    return spool, report, events


def mapped_with_take(spool, report, events):
    events = [*events, dict(kind='render_take', at_ms=1)]
    mapped = MODULE['DECODE']['join_headers'](report, DECODE_TEST['header_source'](events))
    plan, width, height = MODULE['plan_pairs'](mapped, spool)
    return mapped, plan, width, height


def test_pixel_ownership_is_a_copy_and_side_by_side_planes_are_exact():
    spool, report, _ = setup_pixels()
    original = spool.read('video:2:0')
    left = bytes(range(24))  # 4x4 Y, 2x2 U, 2x2 V
    right = bytes(range(100, 124))
    paired = MODULE['compose'](left, right, 4, 4)
    expected = bytes([0, 1, 2, 3, 100, 101, 102, 103,
        4, 5, 6, 7, 104, 105, 106, 107, 8, 9, 10, 11, 108, 109, 110, 111,
        12, 13, 14, 15, 112, 113, 114, 115,
        16, 17, 116, 117, 18, 19, 118, 119, 20, 21, 120, 121, 22, 23, 122, 123])
    assert paired == expected
    assert hashlib.sha256(original).hexdigest() == report['decoded_frames'][0]['pixel_sha256']
    for bad_left, bad_right in [(b'x', right), (left, b'x')]:
        with pytest.raises(ValueError, match='lengths'):
            MODULE['compose'](bad_left, bad_right, 4, 4)


def test_copy_rejects_corruption_size_budget_and_duplicate_identity(monkeypatch):
    spool, _, _ = setup_pixels()
    frame = DECODE_TEST['frame']()
    row = MODULE['DECODE']['fingerprint'](frame, 2, 0)
    with pytest.raises(ValueError, match='duplicate'):
        spool.capture(row, frame)
    bad = dict(row, pixel_sha256='0' * 64)
    with pytest.raises(ValueError, match='fingerprint'):
        spool.capture(bad, frame)
    monkeypatch.setitem(MODULE['Spool'].capture.__globals__, 'MAX_SPOOL_BYTES', 0)
    with pytest.raises(ValueError, match='storage'):
        spool.capture(dict(row, decoded_id='new'), frame)


def test_spool_read_rejects_changed_or_truncated_data():
    for data in (b'x' * 100, b'x'):
        spool, _, _ = setup_pixels()
        spool.source = io.BytesIO(data)
        with pytest.raises(ValueError, match='truncated or changed'):
            spool.read('video:2:0')


@pytest.mark.parametrize('disk', [False, True])
def test_interleaved_decoded_capture_and_read_preserves_all_copies(monkeypatch, disk):
    monkeypatch.setitem(MODULE['Spool'].capture.__globals__, 'pack', lambda frame: frame)
    with tempfile.TemporaryFile() if disk else io.BytesIO() as source:
        spool = MODULE['Spool'](source)
        def capture(identity, value):
            data = bytes([value]) * 6
            spool.capture(dict(decoded_id=identity, width=2, height=2,
                               pixel_sha256=hashlib.sha256(data).hexdigest()), data)
        capture('first', 1)
        capture('second', 2)
        assert spool.read('first') == b'\x01' * 6
        capture('third', 3)
        assert spool.read('second') == b'\x02' * 6
        assert spool.read('third') == b'\x03' * 6
        assert spool.read('first') == b'\x01' * 6
        assert spool.size == 18


def test_only_taken_pairs_selected_and_no_implicit_eof_drain():
    spool, report, events = setup_pixels()
    mapped = MODULE['DECODE']['join_headers'](report, DECODE_TEST['header_source'](events))
    with pytest.raises(ValueError, match='consume'):
        MODULE['plan_pairs'](mapped, spool)
    mapped, plan, width, height = mapped_with_take(spool, report, events)
    assert (width, height) == (4, 4)
    assert plan[0]['offer_ids'] == ['left', 'right']
    assert plan[0]['decoded_ids'] == ['video:2:0', 'video:5:0']
    assert plan[0]['observed_take_at_ms'] == 1
    assert mapped['pairing']['summary']['render_taken'] == 1


def test_geometry_changes_or_pair_pixel_budget_reject_before_output(monkeypatch):
    spool, report, events = setup_pixels()
    mapped, _, _, _ = mapped_with_take(spool, report, events)
    spool.records['video:5:0']['height'] = 6
    with pytest.raises(ValueError, match='geometry'):
        MODULE['plan_pairs'](mapped, spool)
    spool.records['video:5:0']['height'] = 4
    monkeypatch.setitem(MODULE['plan_pairs'].__globals__, 'MAX_PAIR_PIXELS', 0)
    with pytest.raises(ValueError, match='geometry'):
        MODULE['plan_pairs'](mapped, spool)


class Backend:
    def __init__(self, writes=None):
        self.output = bytearray()
        self.writes = iter(writes) if writes is not None else None
        self.finished = False
    def alive(self):
        pass
    def write(self, data):
        count = next(self.writes) if self.writes is not None else min(3, len(data))
        if isinstance(count, BaseException):
            raise count
        if type(count) is int and 0 < count <= len(data):
            self.output.extend(data[:count])
        return count
    def finish(self, timeout):
        self.finished = True


def test_partial_writes_preserve_entire_pair_identity_and_pipe_receipt():
    spool, report, events = setup_pixels()
    _, plan, width, height = mapped_with_take(spool, report, events)
    preview = MODULE['Preview'](plan * 2, 15)
    backend = Backend()
    preview.run(spool, backend, width, height, 5)
    expected = MODULE['compose'](spool.read('video:2:0'), spool.read('video:5:0'), 4, 4)
    assert backend.output == expected * 2 and backend.finished
    result = preview.result('completed', None)
    assert result['summary']['pipe_written'] == 2
    assert result['summary']['remaining_pairs'] == []
    assert not result['pipe_completion_is_display']
    assert not result['physical_lip_sync_measured']
    assert not result['decoder_buffer_ownership_verified']
    assert result['actions'][1]['composed_sha256'] == hashlib.sha256(expected).hexdigest()


@pytest.mark.parametrize('failure', [BrokenPipeError(), KeyboardInterrupt(), 0, -1, True, 99999])
def test_failure_retains_partial_pair_not_reported_as_complete(failure):
    spool, report, events = setup_pixels()
    _, plan, width, height = mapped_with_take(spool, report, events)
    preview = MODULE['Preview'](plan, 15)
    with pytest.raises((ValueError, BrokenPipeError, KeyboardInterrupt)):
        preview.run(spool, Backend([2, failure]), width, height, 5)
    result = preview.result('failed', 'test failure')
    assert result['summary']['pipe_written'] == 0
    assert result['summary']['write_pending'] == 'pair:0'
    assert result['summary']['partial_pipe_bytes'] == 2
    assert result['summary']['remaining_pairs'] == ['pair:0']


def test_stall_deadline_is_cooperative_and_does_not_busy_spin(monkeypatch):
    spool, report, events = setup_pixels()
    _, plan, width, height = mapped_with_take(spool, report, events)
    clock = iter((0, 0, 0, 0, 10))
    monkeypatch.setattr(MODULE['time'], 'monotonic', lambda: next(clock))
    sleeps = []
    monkeypatch.setattr(MODULE['select'], 'select', lambda *args: sleeps.append(args[-1]))
    preview = MODULE['Preview'](plan, 15)
    with pytest.raises(ValueError, match='deadline'):
        preview.run(spool, Backend([BlockingIOError()]), width, height, 5)
    assert sleeps == [0.02] and preview.completed == 0


def test_finish_failure_does_not_undo_completed_pipe_writes(monkeypatch):
    spool, report, events = setup_pixels()
    _, plan, width, height = mapped_with_take(spool, report, events)
    backend = Backend()
    def fail(timeout):
        raise ValueError('finish failed')
    monkeypatch.setattr(backend, 'finish', fail)
    preview = MODULE['Preview'](plan, 15)
    with pytest.raises(ValueError, match='finish'):
        preview.run(spool, backend, width, height, 5)
    assert preview.completed == 1 and preview.pending is None


def test_ffplay_command_disables_audio_and_abort_kills_and_reaps(monkeypatch):
    process = SimpleNamespace(stdin=io.BytesIO(), returncode=None)
    process.stdin.fileno = lambda: 1
    calls: list[Any] = []
    def spawn(command, **kwargs):
        calls.append(command)
        return process
    process.poll = lambda: None
    process.terminate = lambda: calls.append('terminate')
    process.kill = lambda: calls.append('kill')
    waits = iter((subprocess.TimeoutExpired('test', 0.5), 0))
    def wait(timeout):
        outcome = next(waits)
        if isinstance(outcome, Exception):
            raise outcome
        calls.append('reaped')
        return outcome
    process.wait = wait
    monkeypatch.setattr(MODULE['subprocess'], 'Popen', spawn)
    monkeypatch.setattr(MODULE['os'], 'set_blocking', lambda *args: None)
    backend = MODULE['Ffplay'](128, 48, 15)
    assert '-an' in calls[0] and '-sn' in calls[0] and '128x48' in calls[0]
    assert calls[0][calls[0].index('-framerate') + 1] == '15'
    backend.abort()
    assert calls[1:] == ['terminate', 'kill', 'reaped'] and process.stdin.closed


def test_existing_receipt_and_missing_play_flag_never_start_output(tmp_path):
    receipt = tmp_path / 'receipt.json'
    receipt.write_text('keep')
    command = [sys.executable, str(SCRIPT), str(tmp_path / 'absent'), '--container', 'matroska',
               '--primary-stream', '0', '--secondary-stream', '1', '--header-map', 'absent',
               '--layout', 'side-by-side', '--fps', '15', '--receipt', str(receipt)]
    for play in ([], ['--play']):
        p = subprocess.run([*command, *play], capture_output=True, timeout=5, check=False)
        assert p.returncode == 2 and not p.stdout
        assert receipt.read_text() == 'keep'


def test_real_ffplay_dummy_video_preview_retains_boundary_pending_pair(tmp_path):
    if not shutil.which('ffplay'):
        pytest.skip('optional real ffplay video transport unavailable')
    source = DECODE_TEST['encode_paired_file'](tmp_path)
    decode = MODULE['DECODE']
    with decode['AUDIO']['open_source'](source) as media:
        report = decode['decode'](media, 'matroska', (0, 1))
    events = []
    for index in range(3):
        for lens in (1, 0):
            row = next(r for r in report['decoded_frames']
                       if r['stream_index'] == lens and r['frame_index'] == index)
            events.append(DECODE_TEST['offer'](row, lens, f'{lens}:{index}', at=index,
                                               raw_time=index, media_ms=index * 66))
        if index < 2:
            events.append(dict(kind='render_take', at_ms=index))
    headers = tmp_path / 'headers.jsonl'
    headers.write_bytes(DECODE_TEST['header_source'](events).getvalue())
    receipt = tmp_path / 'preview.json'
    command = [sys.executable, str(SCRIPT), str(source), '--container', 'matroska',
               '--primary-stream', '0', '--secondary-stream', '1', '--header-map', str(headers),
               '--layout', 'side-by-side', '--fps', '15', '--play', '--receipt', str(receipt)]
    env = dict(os.environ, SDL_VIDEODRIVER='dummy', SDL_AUDIODRIVER='dummy')
    p = subprocess.run(command, env=env, capture_output=True, timeout=20, check=False)
    assert p.returncode == 0, p.stderr.decode()
    result = json.loads(receipt.read_text())
    assert result['status'] == 'completed'
    assert result['summary']['selected_pairs'] == result['summary']['pipe_written'] == 2
    assert len(result['source_pairing']['summary']['render_pending']) == 1
    assert not result['pipe_completion_is_display']
    assert [a['bytes'] for a in result['actions'] if a['kind'].endswith('completed')] == [9216, 9216]
    assert not p.stdout


@pytest.mark.parametrize('mode', ['cancel', 'bad-binding', 'cleanup-failure'])
def test_main_failure_receipts_and_pixel_child_ownership(monkeypatch, tmp_path, mode):
    _, report, events = setup_pixels()
    events.append(dict(kind='render_take', at_ms=1))
    if mode == 'bad-binding':
        events[0]['pixel_sha256'] = '0' * 64
    globals_ = MODULE['main'].__globals__
    opened = []
    real_temporary = MODULE['tempfile'].TemporaryFile
    def temporary():
        f = real_temporary()
        opened.append(f)
        return f
    monkeypatch.setattr(MODULE['tempfile'], 'TemporaryFile', temporary)
    def source(path):
        return DECODE_TEST['header_source'](events) if path.name == 'headers' else io.BytesIO(b'x')
    monkeypatch.setitem(MODULE['AUDIO'], 'open_source', source)
    def decode(media, fmt, streams, consume):
        for row in report['decoded_frames']:
            consume(row, DECODE_TEST['frame']())
        return report
    monkeypatch.setitem(MODULE['DECODE'], 'decode', decode)
    def abort():
        opened.append('aborted')
        if mode == 'cleanup-failure':
            raise OSError('injected cleanup failure')
    backend = SimpleNamespace(abort=abort)
    monkeypatch.setitem(globals_, 'Ffplay', lambda *args: backend)
    def cancel(self, *args):
        if mode == 'cleanup-failure':
            return
        self.pending = self.plan[0]['pair_id']
        self.offset = 3
        raise KeyboardInterrupt
    monkeypatch.setattr(MODULE['Preview'], 'run', cancel)
    receipt = tmp_path / 'receipt.json'
    monkeypatch.setattr(MODULE['sys'], 'argv', [str(SCRIPT), 'source', '--container', 'matroska',
        '--primary-stream', '2', '--secondary-stream', '5', '--header-map', 'headers',
        '--play', '--layout', 'side-by-side', '--fps', '15', '--receipt', str(receipt)])
    assert MODULE['main']() == (130 if mode == 'cancel' else 2)
    result = json.loads(receipt.read_text())
    assert result['status'] == ('cancelled' if mode == 'cancel' else 'failed')
    assert result['summary']['partial_pipe_bytes'] == (3 if mode == 'cancel' else 0)
    assert result['summary']['pipe_written'] == 0
    assert opened[0].closed
    if mode == 'bad-binding':
        assert len(opened) == 1  # Child launch and abort never happened.
        assert 'binding mismatch' in result['error']
    else:
        assert opened[1] == 'aborted'
    if mode == 'cleanup-failure':
        assert 'cleanup failed' in result['error']


def test_captured_pixels_survive_borrowed_frame_mutation():
    picture = DECODE_TEST['frame']()
    row = MODULE['DECODE']['fingerprint'](picture, 0, 0)
    spool = MODULE['Spool'](io.BytesIO())
    spool.capture(row, picture)
    original = spool.read(row['decoded_id'])
    picture.planes[0].data = b'\x00' * len(picture.planes[0].data)
    assert spool.read(row['decoded_id']) == original
    assert MODULE['pack'](picture) != original


@pytest.mark.parametrize('outcome', [1, subprocess.TimeoutExpired('ffplay', 5)])
def test_backend_finish_failures_close_input_without_claiming_display(outcome):
    backend = MODULE['Ffplay'].__new__(MODULE['Ffplay'])
    def wait(timeout):
        if isinstance(outcome, Exception):
            raise outcome
        return outcome
    backend.process = SimpleNamespace(stdin=io.BytesIO(), wait=wait)
    with pytest.raises(ValueError):
        backend.finish(5)
    assert backend.process.stdin.closed


def test_short_temporary_pixel_write_is_not_a_stored_frame():
    spool = MODULE['Spool'](SimpleNamespace(seek=lambda offset, whence: 0,
                                           tell=lambda: 0, write=lambda data: 0))
    picture = DECODE_TEST['frame']()
    row = MODULE['DECODE']['fingerprint'](picture, 0, 0)
    with pytest.raises(ValueError, match='short'):
        spool.capture(row, picture)
    assert spool.size == 0 and not spool.records
