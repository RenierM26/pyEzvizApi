"""Offline queue parity, bounded I/O, transport progress and child cleanup."""

import base64
from contextlib import suppress
import json
import os
from pathlib import Path
import runpy
import signal
import subprocess
import sys
import time

import pytest

SCRIPT = Path(__file__).parents[1] / 'tools/app_pcm_playback.py'
MODULE = runpy.run_path(str(SCRIPT))
Block = MODULE['Block']
PcmQueue = MODULE['PcmQueue']
JsonlInput = MODULE['JsonlInput']
Ffplay = MODULE['Ffplay']
run = MODULE['run']
parse_block = MODULE['parse_block']
SIM = runpy.run_path(str(SCRIPT.with_name('app_playback_simulator.py')))
pytestmark = pytest.mark.skipif(os.name != 'posix', reason='POSIX pipe backend')


def block(n):
    return Block(f'b{n}', n * 64, bytes([n % 256]) * 2048)


def row(n=0):
    b = block(n)
    return dict(id=b.identity, media_ms=b.media_ms,
                pcm_s16le_b64=base64.b64encode(b.pcm).decode())


def test_queue_matches_merged_simulator_at_saturation_and_write_boundaries():
    q = PcmQueue()
    sim = SIM['PlaybackSimulator']()
    for n in range(26):
        q.offer(block(n), 0)
        sim.step(dict(kind='audio_enqueue', at_ms=0, id=f'b{n}', media_ms=n * 64))
    assert len(q.ring) == 24 and q.rejected == 2
    q.begin(0)
    sim.step(dict(kind='audio_begin', at_ms=0))
    sim.step(dict(kind='audio_release', at_ms=0, id='b0'))
    assert q.offer(block(26), 0)  # Slot freed before the blocked pipe write.
    assert not q.offer(block(27), 0)
    for n in (26, 27):
        sim.step(dict(kind='audio_enqueue', at_ms=0, id=f'b{n}', media_ms=n * 64))
    q.accept(17, 1)
    assert q.written == 0 and q.offset == 17
    assert q.writing.identity == 'b0'
    q.begin(1)
    assert q.writing.identity == 'b0'  # No next consumer during partial output.
    q.accept(2031, 2)
    sim.step(dict(kind='audio_write_complete', at_ms=2, id='b0', accepted_bytes=2048))
    summary = sim.result()['summary']
    assert [b.identity for b in q.ring] == summary['audio_ring_pending']
    assert q.rejected == summary['audio_rejected'] == 3
    assert q.written == summary['audio_written'] == 1
    while q.pending:
        q.begin(3)
        q.accept(2048, 3)
    completed = [a for a in q.actions if a['kind'] == 'audio_pipe_write_completed']
    assert [a['id'] for a in completed] == [f'b{n}' for n in [*range(24), 26]]
    assert completed[-1]['media_ms'] == 1664  # Gap preserved, not relabeled.


def test_pending_and_partial_summary_never_claims_sound_or_complete_output():
    q = PcmQueue()
    q.offer(block(0), 0)
    q.offer(block(1), 0)
    q.begin(0)
    q.accept(100, 1)
    r = q.result('cancelled', 'interrupted')
    assert r['status'] == 'cancelled'
    assert r['summary'] == dict(offered=2, rejected=0, pipe_written=0,
                                ring_pending=['b1'], write_pending='b0', partial_pipe_bytes=100)
    assert not r['physical_lip_sync_measured']
    assert not r['pipe_completion_is_audible_output']
    assert r['processor'] == 'passthrough-not-vqe'


@pytest.mark.parametrize('count', [0, -1, 2049, True, 1.5])
def test_invalid_transport_progress(count):
    q = PcmQueue()
    with pytest.raises(ValueError):
        q.accept(1, 0)
    q.offer(block(0), 0)
    q.begin(0)
    with pytest.raises(ValueError):
        q.accept(count, 0)


def test_identity_and_total_input_bounds():
    q = PcmQueue()
    q.offer(block(0), 0)
    with pytest.raises(ValueError, match='duplicate'):
        q.offer(block(0), 0)
    q.offered = 10_000
    with pytest.raises(ValueError, match='limit'):
        q.offer(block(1), 0)


@pytest.mark.parametrize('patch', [
    {'id': ''}, {'id': 'x' * 129}, {'id': True}, {'media_ms': True},
    {'media_ms': -1}, {'media_ms': 2**32}, {'pcm_s16le_b64': '!' * 2732},
    {'pcm_s16le_b64': base64.b64encode(b'x' * 2047).decode()},
    {'pcm_s16le_b64': 0}, {'codec': 'aac'},
])
def test_bad_pcm_input_rejected(patch):
    with pytest.raises(ValueError):
        parse_block(dict(row(), **patch))


def test_fragmented_input_and_eof_tail():
    raw = json.dumps(row()).encode()
    source = JsonlInput()
    assert not list(source.feed(raw[:1]))
    assert not list(source.feed(raw[1:-1]))
    assert list(source.feed(raw[-1:] + b'\n')) == [block(0)]
    assert not list(source.feed(raw))
    assert list(source.feed(b'')) == [block(0)]
    assert not list(source.feed(b''))
    with pytest.raises(ValueError, match='line limit'):
        list(JsonlInput().feed(b' ' * 8193))
    with pytest.raises(ValueError, match='line limit'):
        list(JsonlInput().feed(b' ' * 8192 + b'\n'))
    with pytest.raises(ValueError):
        list(JsonlInput().feed(b'\n'))


@pytest.fixture
def child(monkeypatch):
    """Replace ffplay only: use real nonblocking OS pipes without an audio device."""
    original = subprocess.Popen
    processes = []

    def make(program, *args):
        def spawn(command, **options):
            assert command[0] == 'ffplay'
            assert command[-1] == 'pipe:0'
            p = original([sys.executable, '-c', program, *map(str, args)], **options)
            processes.append(p)
            return p
        monkeypatch.setattr(subprocess, 'Popen', spawn)
        return Ffplay()

    yield make
    for p in processes:
        if p.poll() is None:
            p.kill()
        p.wait(timeout=2)


def test_real_pipe_byte_exact_order_eof_and_reap(child, tmp_path):
    output = tmp_path / 'pcm'
    backend = child('import sys; from pathlib import Path; '
                    'Path(sys.argv[1]).write_bytes(sys.stdin.buffer.read())', output)
    source = tmp_path / 'blocks.jsonl'
    source.write_text(''.join(json.dumps(row(n)) + '\n' for n in range(8)))
    q = PcmQueue()
    try:
        with source.open('rb') as f:
            run(q, backend, f.fileno(), 2)
        assert backend.process.poll() == 0
    finally:
        backend.abort()
    assert output.read_bytes() == b''.join(block(n).pcm for n in range(8))
    assert q.written == 8 and not q.pending
    times = [a['at_seconds'] for a in q.actions]
    assert times == sorted(times)


def test_stalled_child_accepts_input_drops_newest_then_times_out(child, tmp_path):
    backend = child('import time; time.sleep(60)')
    source = tmp_path / 'blocks.jsonl'
    source.write_text(''.join(json.dumps(row(n)) + '\n' for n in range(100)))
    q = PcmQueue()
    try:
        with source.open('rb') as f, pytest.raises(ValueError, match='deadline'):
            run(q, backend, f.fileno(), 0.2)
    finally:
        backend.abort()
    assert q.offered == 100  # Input keeps flowing while the output pipe is full.
    assert q.rejected > 0 and len(q.ring) == 24
    assert q.writing is not None
    assert backend.process.poll() is not None
    backend.abort()  # Repeated cleanup is safe.


def test_child_death_and_cancel_retain_pending_and_reap(child, tmp_path, monkeypatch):
    backend = child('import sys; sys.exit(7)')
    backend.process.wait(timeout=2)
    with pytest.raises(ValueError, match='status 7'):
        backend.alive()
    backend.abort()
    backend = child('import time; time.sleep(60)')
    q = PcmQueue()
    q.offer(block(0), 0)
    def interrupt(*args):
        raise KeyboardInterrupt
    monkeypatch.setattr(MODULE['select'], 'select', interrupt)
    try:
        with pytest.raises(KeyboardInterrupt):
            run(q, backend, 0, 1)
    finally:
        backend.abort()
    assert q.result('cancelled')['summary']['ring_pending'] == ['b0']
    assert backend.process.poll() is not None


def test_child_exit_deadline_and_kill_fallback(child):
    backend = child('import signal, sys, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); '
                    'sys.stdin.buffer.read(); time.sleep(60)')
    # EOF proves the child has installed its handler before finish times out.
    with pytest.raises(ValueError, match='drain deadline'):
        backend.finish(0.2)
    backend.abort()
    assert backend.process.poll() is not None


@pytest.mark.parametrize('args', [[], ['--play'], ['--processor', 'passthrough'],
                                   ['--play', '--processor', 'vqe'],
                                   ['--play', '--processor', 'passthrough', '--deadline', 'nan']])
def test_cli_requires_explicit_playback_and_bypass(args):
    p = subprocess.run([sys.executable, str(SCRIPT), *args], input=b'',
                       capture_output=True, timeout=5, check=False)
    assert p.returncode == 2 and not p.stdout


def test_cli_interrupt_reports_cancellation_and_reaps_child(tmp_path):
    executable = tmp_path / 'ffplay'
    pidfile = tmp_path / 'child.pid'
    executable.write_text(f'#!{sys.executable}\n'
                          'import os, time\nfrom pathlib import Path\n'
                          'Path(os.environ["PCM_TEST_PID"]).write_text(str(os.getpid()))\n'
                          'time.sleep(60)\n')
    executable.chmod(0o700)
    environment = {**os.environ, 'PATH': str(tmp_path) + os.pathsep + os.environ['PATH'],
                   'PCM_TEST_PID': str(pidfile)}
    p = subprocess.Popen([sys.executable, str(SCRIPT), '--play', '--processor', 'passthrough'],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         env=environment)
    try:
        deadline = time.monotonic() + 5
        while not pidfile.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert pidfile.exists()
        p.send_signal(signal.SIGINT)
        stdout, _ = p.communicate(timeout=3)
        assert p.returncode == 130
        result = json.loads(stdout)
        assert result['status'] == 'cancelled' and result['error'] == 'interrupted'
        with pytest.raises(ProcessLookupError):
            os.kill(int(pidfile.read_text()), 0)
    finally:
        if p.poll() is None:
            p.kill()
        p.wait(timeout=2)
        if pidfile.exists():
            with suppress(ProcessLookupError):
                os.kill(int(pidfile.read_text()), signal.SIGKILL)


def test_pipe_setup_failure_reaps_spawned_child(monkeypatch):
    processes = []
    original = subprocess.Popen
    def remember(*args, **kwargs):
        p = original([sys.executable, '-c', 'import time; time.sleep(60)'], **kwargs)
        processes.append(p)
        return p
    monkeypatch.setattr(subprocess, 'Popen', remember)
    def fail(*args):
        raise OSError('nonblocking setup failed')
    monkeypatch.setattr(MODULE['os'], 'set_blocking', fail)
    try:
        with pytest.raises(OSError, match='nonblocking setup'):
            Ffplay()
        assert processes and processes[0].poll() is not None
    finally:
        for p in processes:
            if p.poll() is None:
                p.kill()
            p.wait(timeout=2)


@pytest.mark.parametrize('split', [None, 10, -6])
@pytest.mark.parametrize('invalid', [b'{bad}\n', b'{}\n', b' ' * 8193])
def test_valid_prefix_is_admitted_before_later_invalid_record(split, invalid):
    valid = json.dumps(row()).encode() + b'\n'
    raw = valid + invalid
    # Coalesced, fragmented inside the valid row, or near the bad suffix.
    chunks = [raw] if split is None else [raw[:split], raw[split:]]
    source, q = JsonlInput(), PcmQueue()
    with pytest.raises(ValueError):
        for chunk in chunks:
            for parsed in source.feed(chunk):
                q.offer(parsed, 0)
    summary = q.result('failed')['summary']
    assert summary['offered'] == 1
    assert summary['ring_pending'] == ['b0']
    assert q.actions[0]['id'] == 'b0'


def test_run_reports_valid_prefix_when_read_coalesces_bad_line(child, tmp_path):
    backend = child('import sys; sys.stdin.buffer.read()')
    source = tmp_path / 'bad.jsonl'
    source.write_text(json.dumps(row()) + '\n{bad}\n')
    q = PcmQueue()
    try:
        with source.open('rb') as f, pytest.raises(ValueError):
            run(q, backend, f.fileno(), 1)
    finally:
        backend.abort()
    assert q.offered == 1 and q.result('failed')['summary']['ring_pending'] == ['b0']
