"""Paced native output: explicit host clock, complete pixels and isolated SDL lifecycle."""

import ctypes
import ctypes.util
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import socket
import struct
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

import pytest

SCRIPT = Path(__file__).parents[1] / 'tools/app_native_video_preview.py'
M = runpy.run_path(str(SCRIPT))
SOURCE = runpy.run_path(str(Path(__file__).with_name('test_app_native_scheduled_video.py')))
pytestmark = pytest.mark.skipif(os.name != 'posix', reason='POSIX SDL worker transport')


def setup():
    spool, report = SOURCE['load'](*SOURCE['snapshots']())
    replay = M['NATIVE']['replay'](report, SOURCE['jsonl'](SOURCE['events'](report)))
    plan, width, height = M['NATIVE']['plan_frames'](replay, spool)
    return spool, plan, width, height


MAX_SLEEP = 0.02


class Clock:
    def __init__(self):
        self.now = 1_000_000_000
        self.sleeps = []
    def monotonic_ns(self):
        return self.now
    def sleep(self, duration):
        assert 0 <= duration <= MAX_SLEEP
        self.sleeps.append(duration)
        self.now += round(duration * 1e9)


class Backend:
    def __init__(self, clock, delay=0):
        self.clock, self.delay = clock, delay
        self.calls = []
        self.finished = False
    def alive(self):
        pass
    def present(self, identity, pixels, timeout):
        self.calls.append((identity, bytes(pixels), self.clock.now))
        self.clock.now += self.delay
        return dict(kind='presented', pair_id=identity)
    def finish(self, timeout):
        self.finished = True


def paced(monkeypatch):
    spool, plan, width, height = setup()
    preview = M['PacedPreview'](plan)
    clock = Clock()
    monkeypatch.setitem(preview.run.__globals__, 'time', clock)
    return spool, preview, clock, width, height


def test_request_gaps_use_absolute_anchor_without_fixed_fps_or_accumulated_output_delay(monkeypatch):
    spool, preview, clock, width, height = paced(monkeypatch)
    output = Backend(clock, 20_000_000)
    preview.run(spool, output, width, height, 5, 50)
    assert [c[2] for c in output.calls] == [1_000_000_000, 1_085_000_000, 1_330_000_000]
    assert output.finished and preview.completed == 3 and preview.pending is None
    assert preview.result()['remaining_pairs'] == []
    for pair, (_, pixels, _) in zip(preview.plan, output.calls, strict=True):
        expected = M['NATIVE']['SCHEDULED']['PREVIEW']['compose'](
            *[spool.read(i) for i in pair['decoded_ids']], width, height)
        assert pixels == expected
    starts = preview.actions[::2]
    assert all(a['submission_late_ns'] == 0 for a in starts)
    assert starts[0]['composed_sha256'] == hashlib.sha256(output.calls[0][1]).hexdigest()


def test_large_initial_observation_delay_is_explicitly_anchored_not_slept(monkeypatch):
    spool, preview, clock, width, height = paced(monkeypatch)
    preview.plan = [dict(preview.plan[0], request_at_ms=10350)]
    output = Backend(clock)
    preview.run(spool, output, width, height, 5, 50)
    assert output.calls[0][2] == 1_000_000_000 and not clock.sleeps
    assert preview.plan[0]['request_at_ms'] == 10350


def test_late_output_fails_without_catchup_drop_or_retime(monkeypatch):
    spool, preview, clock, width, height = paced(monkeypatch)
    output = Backend(clock, 200_000_000)
    with pytest.raises(ValueError, match='lateness limit'):
        preview.run(spool, output, width, height, 5, 50)
    assert len(output.calls) == preview.completed == 1
    assert preview.pending == 'pair:1' and not output.finished
    assert preview.result()['remaining_pairs'] == ['pair:1', 'pair:2']
    assert preview.actions[-1]['submission_late_ns'] == 115_000_000


@pytest.mark.parametrize('failure', [ValueError('worker failed'), KeyboardInterrupt()])
def test_unacknowledged_call_remains_pending_and_is_never_reported_complete(monkeypatch, failure):
    spool, preview, clock, width, height = paced(monkeypatch)
    output = Backend(clock)
    def fail(*args):
        raise failure
    monkeypatch.setattr(output, 'present', fail)
    with pytest.raises(type(failure)):
        preview.run(spool, output, width, height, 5, 50)
    assert preview.completed == 0 and preview.pending == 'pair:0'
    assert len(preview.actions) == 1


def test_worker_exit_during_gap_stops_before_next_submission(monkeypatch):
    spool, preview, clock, width, height = paced(monkeypatch)
    output = Backend(clock)
    def fail():
        raise ValueError('worker exited')
    monkeypatch.setattr(output, 'alive', fail)
    with pytest.raises(ValueError, match='exited'):
        preview.run(spool, output, width, height, 5, 50)
    assert len(output.calls) == 1 and preview.pending == 'pair:1'


def test_finish_failure_keeps_acknowledged_calls_complete(monkeypatch):
    spool, preview, clock, width, height = paced(monkeypatch)
    output = Backend(clock)
    def fail(timeout):
        raise ValueError('finish failed')
    monkeypatch.setattr(output, 'finish', fail)
    with pytest.raises(ValueError, match='finish failed'):
        preview.run(spool, output, width, height, 5, 50)
    assert preview.completed == 3 and preview.pending is None


@pytest.mark.parametrize('times', [[], [1, 1], [2, 1], [-1], [True], [0, 60001], list(range(33))])
def test_request_plan_limits_reject_before_output(times):
    with pytest.raises(ValueError):
        M['PacedPreview']([dict(request_at_ms=t) for t in times])


@pytest.mark.parametrize('payload', [struct.pack('!I', 8193), struct.pack('!I', 0),
    struct.pack('!I', 2) + b'[]', struct.pack('!I', 1) + b'x'])
def test_protocol_rejects_oversized_nonobject_or_invalid_messages(payload):
    with pytest.raises(ValueError):
        M['message'](io.BytesIO(payload).read)


@pytest.mark.parametrize(('key', 'value'), [('kind', 'finished'), ('pair_id', 'other'),
    ('bytes', 2), ('pixel_sha256', 'wrong'), ('present_started_ns', True),
    ('present_returned_ns', -1)])
def test_acknowledgement_must_match_exact_pair_pixels_and_host_times(key, value):
    output = M['Output'].__new__(M['Output'])
    output.transfer = lambda *args: b''
    ack = dict(kind='presented', pair_id='pair:0', bytes=3,
               pixel_sha256=hashlib.sha256(b'abc').hexdigest(), present_started_ns=1, present_returned_ns=2)
    output.receive = lambda deadline: dict(ack, **{key: value})
    with pytest.raises(ValueError, match='acknowledgement'):
        output.present('pair:0', b'abc', 5)


def test_worker_protocol_geometry_is_bounded_before_opening_sdl():
    for fd, width, height in [(0, 16, 6), (99, 3, 6), (99, 8192, 4096), (99, 16, 0)]:
        with pytest.raises(ValueError, match='geometry or descriptor'):
            M['worker'](fd, width, height)


def test_stalled_protocol_read_has_deadline_and_cleanup():
    output = M['Output'].__new__(M['Output'])
    output.channel, peer = socket.socketpair()
    output.channel.setblocking(False)
    output.process = None
    try:
        started = time.monotonic()
        with pytest.raises(ValueError, match='deadline'):
            output.transfer(4, started + 0.01)
        assert time.monotonic() - started < 2
    finally:
        output.abort()
        peer.close()


def test_abort_terminates_then_kills_and_reaps_stuck_worker():
    output = M['Output'].__new__(M['Output'])
    calls = []
    def wait(timeout):
        calls.append('wait')
        if calls.count('wait') == 1:
            raise subprocess.TimeoutExpired('SDL', timeout)
        return 0
    output.channel = SimpleNamespace(close=lambda: calls.append('close'))
    output.process = SimpleNamespace(poll=lambda: None, wait=wait,
        terminate=lambda: calls.append('terminate'), kill=lambda: calls.append('kill'))
    output.abort()
    assert calls == ['close', 'terminate', 'wait', 'kill', 'wait']


def command(tmp_path, rows=None, inputs=None, renders=None, events=None):
    if rows is None:
        rows, inputs, renders = SOURCE['snapshots']()
        _, report = SOURCE['load'](rows, inputs, renders)
        events = SOURCE['events'](report)
    old, _, receipt = SOURCE['cli'](tmp_path, rows, inputs, renders, events)
    # Reuse only source/map paths, not artifact-export flags.
    return [sys.executable, str(SCRIPT), *old[2:5], '--event-map', old[6],
            '--play', '--layout', 'side-by-side', '--timing', 'request-observation',
            '--anchor', 'first-request', '--receipt', str(receipt)], receipt


def sdl_available():
    if not ctypes.util.find_library('SDL2-2.0'):
        pytest.skip('optional system SDL2 unavailable')


def test_real_sdl_dummy_cli_needs_no_pyav_and_records_timed_host_acknowledgements(tmp_path):
    sdl_available()
    cmd, receipt = command(tmp_path)
    p = subprocess.run(cmd, env=dict(os.environ, SDL_VIDEODRIVER='dummy'),
                       capture_output=True, timeout=15, check=False)
    assert p.returncode == 0, p.stderr.decode()
    result = json.loads(receipt.read_text())
    assert result['status'] == 'completed' and result['sdl_video_driver'] == 'dummy'
    assert result['output']['completed_host_calls'] == 3
    assert not result['audio_opened'] and not result['host_present_return_is_physical_display']
    assert not result['fixed_fps_used'] and not result['initial_observation_delay_preserved']
    assert 'decoded_ids' not in receipt.read_text()
    starts = result['output']['actions'][::2]
    anchor = result['output']['host_anchor_monotonic_ns']
    assert [a['target_monotonic_ns'] - anchor for a in starts] == [0, 85_000_000, 330_000_000]
    for start, returned in zip(starts, result['output']['actions'][1::2], strict=True):
        ack = returned['acknowledgement']
        assert ack['pixel_sha256'] == start['composed_sha256']
        assert start['target_monotonic_ns'] <= start['submission_monotonic_ns'] <= ack['present_started_ns']
        assert ack['present_returned_ns'] >= ack['present_started_ns']


@pytest.mark.parametrize('change', ['last-layout', 'uncompleted', 'unbound-completion', 'receipt-collision'])
def test_whole_source_plan_and_receipt_validate_before_sdl_start(tmp_path, change):
    rows, inputs, renders = SOURCE['snapshots'](1)
    _, report = SOURCE['load'](rows, inputs, renders)
    events = SOURCE['events'](report)
    if change == 'last-layout':
        rows[-1]['renderer_layout']['renderer_format'] = 3
    elif change == 'uncompleted':
        events = events[:-1]
    elif change == 'unbound-completion':
        events = SOURCE['sparse_events'](report, True)
    cmd, receipt = command(tmp_path, rows, inputs, renders, events)
    if change == 'unbound-completion':
        cmd.append('--allow-metadata-only')
    if change == 'receipt-collision':
        receipt.write_text('keep')
    p = subprocess.run(cmd, env=dict(os.environ, SDL_VIDEODRIVER='nonexistent-rook-driver'),
                       capture_output=True, timeout=10, check=False)
    assert p.returncode == 2
    if change == 'receipt-collision':
        assert receipt.read_text() == 'keep'
    else:
        result = json.loads(receipt.read_text())
        assert result['status'] == 'failed' and 'sdl_video_driver' not in result
        assert result['output'] is None
        assert 'SDL' not in result['error']


def test_sdl_startup_failure_is_reported_and_worker_reaped(tmp_path):
    sdl_available()
    cmd, receipt = command(tmp_path)
    p = subprocess.run(cmd, env=dict(os.environ, SDL_VIDEODRIVER='nonexistent-rook-driver'),
                       capture_output=True, timeout=10, check=False)
    assert p.returncode == 2
    result = json.loads(receipt.read_text())
    assert 'SDL worker' in result['error'] and result['output']['completed_host_calls'] == 0
    assert len(result['output']['remaining_pairs']) == 3


@pytest.mark.parametrize(('option', 'value'), [('--deadline', 'nan'), ('--deadline', 'inf'),
    ('--deadline', '0'), ('--max-late-ms', '0'), ('--max-late-ms', '30001')])
def test_invalid_output_options_fail_before_receipt_or_source_io(tmp_path, option, value):
    cmd, receipt = command(tmp_path)
    p = subprocess.run([*cmd, option, value], capture_output=True, timeout=10, check=False)
    assert p.returncode == 2 and not receipt.exists()


def test_real_surface_close_event_and_pixel_length_are_checked(monkeypatch):
    sdl_available()
    monkeypatch.setenv('SDL_VIDEODRIVER', 'dummy')
    surface = M['SdlSurface'](16, 6)
    try:
        with pytest.raises(ValueError, match='length'):
            surface.present(b'x')
        event = ctypes.create_string_buffer(128)
        ctypes.c_uint32.from_buffer(event).value = 0x100
        surface.lib.SDL_PushEvent.argtypes = [ctypes.c_void_p]
        surface.lib.SDL_PushEvent.restype = ctypes.c_int
        assert surface.lib.SDL_PushEvent(event) == 1
        with pytest.raises(ValueError, match='window closed'):
            surface.present(bytes(144))
    finally:
        surface.close()


def test_final_host_hold_is_explicit_and_does_not_add_source_completions(monkeypatch):
    spool, preview, clock, width, height = paced(monkeypatch)
    output = Backend(clock)
    preview.run(spool, output, width, height, 5, 50, final_hold_ms=500)
    assert preview.completed == len(output.calls) == 3
    assert clock.now == 1_830_000_000 and output.finished
    assert len(preview.actions) == 6


def test_stalled_worker_backpressure_is_bounded_and_process_is_reaped():
    output = M['Output'].__new__(M['Output'])
    output.channel, peer = socket.socketpair()
    output.channel.setblocking(False)
    output.channel.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
    output.process = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'],
        pass_fds=(peer.fileno(),), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    peer.close()
    try:
        with pytest.raises(ValueError, match='deadline'):
            output.present('pair:0', bytes(1024 * 1024), 0.03)
    finally:
        output.abort()
    assert output.process.poll() is not None


def test_real_preview_keeps_unsampled_pending_pair_without_attempting_to_present_it(tmp_path):
    sdl_available()
    rows, inputs, renders = SOURCE['snapshots'](1)
    _, report = SOURCE['load'](rows, inputs, renders)
    cmd, receipt = command(tmp_path, rows, inputs, renders, SOURCE['sparse_events'](report))
    p = subprocess.run([*cmd, '--allow-metadata-only', '--final-hold-ms', '0'],
        env=dict(os.environ, SDL_VIDEODRIVER='dummy'), capture_output=True, timeout=10, check=False)
    assert p.returncode == 0, p.stderr.decode()
    result = json.loads(receipt.read_text())
    assert result['output']['completed_host_calls'] == 1
    assert result['replay']['scheduler']['summary']['video_pending'] == ['pair:1']
    assert result['replay']['offer_bindings']['metadata:0'] is None
    assert len(result['replay']['metadata_only_offers']) == 2


def test_sdl_upload_uses_exact_y_u_v_plane_addresses_and_pitches():
    surface = M['SdlSurface'].__new__(M['SdlSurface'])
    surface.width, surface.height = 8, 6
    surface.texture, surface.renderer = 1, 2
    surface.pump = lambda: None
    calls = []
    pixels = bytes(range(72))
    def update(texture, rect, y, y_pitch, u, u_pitch, v, v_pitch):
        assert texture == 1 and rect is None
        assert (y_pitch, u_pitch, v_pitch) == (8, 4, 4)
        assert ctypes.string_at(y, 48) == pixels[:48]
        assert ctypes.string_at(u, 12) == pixels[48:60]
        assert ctypes.string_at(v, 12) == pixels[60:]
        calls.append('upload')
        return 0
    def draw(name):
        calls.append(name)
        return 0
    surface.lib = SimpleNamespace(SDL_UpdateYUVTexture=update,
        SDL_RenderClear=lambda *args: draw('clear'),
        SDL_RenderCopy=lambda *args: draw('copy'),
        SDL_RenderPresent=lambda *args: calls.append('present'))
    surface.present(pixels)
    assert calls == ['upload', 'clear', 'copy', 'present']


@pytest.mark.parametrize('failure', ['count', 'hash'])
def test_worker_enforces_frame_count_and_payload_hash_before_present(monkeypatch, failure):
    presented = []
    closed = []
    class Surface:
        driver = 'test'
        def __init__(self, width, height):
            pass
        def present(self, pixels):
            presented.append(pixels)
        def pump(self):
            pass
        def close(self):
            closed.append(True)
    monkeypatch.setitem(M['worker'].__globals__, 'SdlSurface', Surface)
    client, child = socket.socketpair()
    client.settimeout(2)
    status = []
    fd = child.detach()
    thread = threading.Thread(target=lambda: status.append(M['worker'](fd, 2, 2)), daemon=True)
    thread.start()
    def read(size):
        data = b''
        while len(data) < size:
            part = client.recv(size - len(data))
            assert part
            data += part
        return data
    try:
        assert M['message'](read)['kind'] == 'ready'
        pixels = bytes(6)
        digest = hashlib.sha256(pixels).hexdigest()
        for index in range(33 if failure == 'count' else 1):
            command_row = dict(kind='frame', pair_id=f'pair:{index}', bytes=6,
                               pixel_sha256='bad' if failure == 'hash' else digest)
            client.sendall(M['packet'](command_row))
            if index < 32:
                client.sendall(pixels)
            ack = M['message'](read)
            if failure == 'hash' or index == 32:
                assert ack['kind'] == 'error'
            else:
                assert ack['kind'] == 'presented'
    finally:
        client.close()
        thread.join(timeout=2)
    assert not thread.is_alive() and status == [2] and closed == [True]
    assert len(presented) == (32 if failure == 'count' else 0)
