"""Separate padding/source targets, complete API acks and retained abort ownership."""
import copy
from fractions import Fraction
import hashlib
import json
import os
from pathlib import Path
import runpy
from threading import Event, Thread

import pytest

M = runpy.run_path(str(Path(__file__).parents[1] / 'tools/local_av_audio_gap_output.py'))
D = Fraction(8, 125)
PCM = bytes([7, 11]) * 1024
LIMITS = dict(max_gap_blocks=1, max_total_gap_blocks=4, max_overlap_ms=1,
    max_phase_ms=1, max_blocks=3000, max_source_span_seconds=120)


def prepared(index, stamp, previous=None):
    at = Fraction(stamp)
    row = dict(id=f'aac:2:{index}', stream_index=2, source_pts=at.numerator,
        time_base_num=1, time_base_den=at.denominator, samples=1024,
        pcm_sha256=hashlib.sha256(PCM).hexdigest())
    return dict(kind='audio_block', source_time=M['GAPS']['rational'](at), block=row,
        duration=M['GAPS']['rational'](D), gap_before=None if previous is None
        else M['GAPS']['rational'](at - previous - D)), (PCM,)


class Clock:
    def __init__(self):
        self.ns = 1000000000
        self.pauses = 0
    def __call__(self):
        return self.ns
    def pause(self, seconds):
        self.ns += round(seconds * 1000000000)
        self.pauses += 1


class Backend:
    def __init__(self, clock):
        self.clock = clock
        self.writes = []
        self.finishes = self.aborts = 0
        self.progress = 2048
        self.block_once = False
    def write(self, data):
        if self.block_once:
            self.block_once = False
            raise BlockingIOError
        count = min(self.progress, len(data))
        self.writes.append((self.clock(), data[:count]))
        return count
    def alive(self):
        pass
    def finish(self, timeout):
        self.finishes += 1
    def abort(self):
        self.aborts += 1


def output(**overrides):
    clock = Clock()
    backend = Backend(clock)
    sink = M['GapOutput'](backend, **dict(dict(origin=dict(numerator=10, denominator=1),
        anchor_ns=clock.ns, limits=LIMITS, timeout=5, max_late_ms=250,
        clock=clock, pause=clock.pause), **overrides))
    return sink, backend, clock


def test_padding_has_its_own_earlier_target_and_original_block_is_unchanged():
    sink, backend, _clock = output()
    first = sink.write(*prepared(0, 10))
    event, payload = prepared(1, 10 + 2 * D, Fraction(10))
    before = copy.deepcopy(event)
    second = sink.write(event, payload)
    sink.finish()
    assert event == before and payload == (PCM,)
    assert backend.writes == [(1000000000, PCM), (1064000000, bytes(2048)), (1128000000, PCM)]
    assert first['padding'] is None
    assert second['padding']['target_monotonic_ns'] == 1064000000
    assert second['source']['target_monotonic_ns'] == 1128000000
    assert second['source']['source'] == {k: v for k, v in event['block'].items()} | dict(bytes=2048)
    r = sink.result()
    assert r['completed'] == r['submitted'] == dict(source=2, padding=1)
    assert r['api_bytes'] == dict(source=4096, padding=2048)
    assert r['peak_owned_bytes'] == 4096 and r['source_byte_limit'] == r['padding_byte_limit'] == 2048
    assert r['outputs_finished'] and r['transport_closed'] and not r['failed']
    assert r['owned_source_bytes'] == r['owned_padding_bytes'] == 0
    assert backend.finishes == 1 and backend.aborts == 0
    # Independently serialize the returned media projection, excluding observed
    # call times, and verify the complete source and separate-padding chains.
    for kind, acks in [('source', [first['source'], second['source']]), ('padding', [second['padding']])]:
        chain = hashlib.sha256((M['PROFILE'] + '\n' + kind + '\n').encode())
        for ack in acks:
            row = {k: v for k, v in ack.items() if k not in ('started_monotonic_ns', 'completed_monotonic_ns')}
            chain.update(json.dumps(row, sort_keys=True, separators=(',', ':')).encode() + b'\n')
        assert r['media_sha256'][kind] == chain.hexdigest()


def test_short_writes_and_backpressure_must_complete_before_an_ack():
    sink, backend, clock = output()
    backend.progress = 127
    backend.block_once = True
    ack = sink.write(*prepared(0, 10))
    assert b''.join(data for _, data in backend.writes) == PCM
    assert ack['source']['bytes'] == 2048 and clock.pauses > 0
    assert sink.result()['completed']['source'] == 1


@pytest.mark.parametrize('progress', [0, -1, True, 2049, 1.0])
def test_invalid_write_progress_fails_without_success_ack(progress):
    sink, backend, _clock = output()
    backend.write = lambda data: progress
    with pytest.raises(ValueError, match='progress'):
        sink.write(*prepared(0, 10))
    r = sink.result()
    assert r['completed']['source'] == 0 and r['failed'] and r['backend_aborted']
    assert r['owned_source_bytes'] == 0 and backend.aborts == 1
    with pytest.raises(ValueError, match='terminal'):
        sink.write(*prepared(0, 10))


def test_no_implicit_rebase_or_late_padding_at_the_next_original_target():
    sink, backend, clock = output(max_late_ms=0)
    sink.write(*prepared(0, 10))
    clock.ns = 1128000000  # Calling only at the next source target is too late.
    with pytest.raises(ValueError, match='lateness'):
        sink.write(*prepared(1, 10 + 2 * D, Fraction(10)))
    assert backend.writes == [(1000000000, PCM)]
    assert sink.result()['completed'] == dict(source=1, padding=0)


def test_lateness_and_wait_deadline_remain_independent():
    sink, backend, clock = output()
    clock.ns += 250000001
    with pytest.raises(ValueError, match='lateness'):
        sink.write(*prepared(0, 10))
    assert not backend.writes
    sink, backend, clock = output(anchor_ns=10000000000, timeout=.1)
    with pytest.raises(TimeoutError, match='target wait'):
        sink.write(*prepared(0, 10))
    assert not backend.writes and clock.ns < 1200000000


def test_write_deadline_retains_partial_failure_separate_from_acknowledged_bytes():
    sink, backend, clock = output(timeout=.1)
    def partial(data):
        if backend.writes:
            raise BlockingIOError
        backend.writes.append((clock(), data[:17]))
        return 17
    backend.write = partial
    with pytest.raises(TimeoutError, match='write deadline'):
        sink.write(*prepared(0, 10))
    r = sink.result()
    assert r['failed_job']['partial_bytes'] == 17 and r['failed_job']['kind'] == 'source'
    assert r['api_bytes']['source'] == r['completed']['source'] == 0
    assert r['owned_source_bytes'] == 0


def test_padding_failure_never_submits_the_associated_original_block():
    sink, backend, _clock = output()
    sink.write(*prepared(0, 10))
    backend.write = lambda data: 0
    with pytest.raises(ValueError, match='progress'):
        sink.write(*prepared(1, 10 + 2 * D, Fraction(10)))
    r = sink.result()
    assert r['submitted'] == dict(source=1, padding=1)
    assert r['completed'] == dict(source=1, padding=0)
    assert r['failed_job']['kind'] == 'padding'
    assert r['owned_source_bytes'] == r['owned_padding_bytes'] == 0


def test_source_failure_after_padding_does_not_claim_source_success():
    sink, backend, _clock = output()
    sink.write(*prepared(0, 10))
    write = backend.write
    def fail_source(data):
        if data == PCM:
            raise OSError('output closed')
        return write(data)
    backend.write = fail_source
    with pytest.raises(OSError):
        sink.write(*prepared(1, 10 + 2 * D, Fraction(10)))
    r = sink.result()
    assert r['completed'] == dict(source=1, padding=1)
    assert r['failed_job']['kind'] == 'source' and not r['outputs_finished']


def test_cancel_before_source_target_after_padding_retains_separate_ack():
    sink, backend, clock = output()
    sink.write(*prepared(0, 10))
    pause = clock.pause
    def cancel_after_padding(seconds):
        if clock.ns >= 1064000000:
            sink.abort()
        pause(seconds)
    sink.pause = cancel_after_padding
    with pytest.raises(InterruptedError):
        sink.write(*prepared(1, 10 + 2 * D, Fraction(10)))
    assert sink.result()['completed'] == dict(source=1, padding=1)
    assert backend.writes[-1] == (1064000000, bytes(2048))
    assert backend.aborts == 1 and not sink.result()['outputs_finished']


def test_abort_does_not_release_a_payload_still_borrowed_by_a_writer():
    sink, backend, _clock = output()
    entered, release = Event(), Event()
    def blocked(data):
        entered.set()
        assert release.wait(2)
        raise BlockingIOError
    backend.write = blocked
    errors = []
    def write():
        try:
            sink.write(*prepared(0, 10))
        except InterruptedError:
            errors.append('cancelled')
    thread = Thread(target=write)
    thread.start()
    try:
        assert entered.wait(2)
        sink.abort()
        assert sink.result()['write_active'] and sink.result()['owned_source_bytes'] == 2048
        with pytest.raises(ValueError, match='already active'):
            sink.write(*prepared(1, 10 + D, Fraction(10)))
        with pytest.raises(ValueError, match='already active'):
            sink.finish()
    finally:
        release.set()
        thread.join(2)
    assert not thread.is_alive() and errors == ['cancelled']
    assert not sink.result()['write_active'] and sink.result()['owned_source_bytes'] == 0


@pytest.mark.parametrize('method', ['finish', 'alive'])
def test_backend_failure_aborts_and_prevents_finish(method):
    sink, backend, _clock = output()
    def fail(*args):
        raise OSError('injected failure')
    setattr(backend, method, fail)
    if method == 'finish':
        sink.write(*prepared(0, 10))
        with pytest.raises(OSError):
            sink.finish()
    else:
        with pytest.raises(OSError):
            sink.write(*prepared(0, 10))
    assert sink.result()['failed'] and backend.aborts == 1
    with pytest.raises(ValueError):
        sink.finish()


def test_abort_error_remains_visible_and_does_not_replace_primary_failure():
    sink, backend, _clock = output()
    backend.write = lambda data: 0
    def fail():
        raise OSError('abort failed')
    backend.abort = fail
    with pytest.raises(ValueError, match='progress'):
        sink.write(*prepared(0, 10))
    assert sink.result()['abort_error_type'] == 'OSError' and not sink.result()['transport_closed']


def test_finished_state_is_unchanged_by_rejected_reuse_and_result_mutation():
    sink, backend, _clock = output()
    sink.write(*prepared(0, 10))
    sink.finish()
    before = sink.result()
    sink.abort()
    with pytest.raises(ValueError):
        sink.write(*prepared(1, 10 + D, Fraction(10)))
    with pytest.raises(ValueError):
        sink.finish()
    assert sink.result() == before
    sink, backend, _clock = output()
    backend.write = lambda data: 0
    with pytest.raises(ValueError):
        sink.write(*prepared(0, 10))
    r = sink.result()
    r['failed_job']['source']['id'] = 'modified'
    assert sink.result()['failed_job']['source']['id'] == 'aac:2:0'


@pytest.mark.parametrize('overrides', [dict(anchor_ns=True), dict(anchor_ns=0), dict(timeout=float('nan')),
    dict(timeout=True), dict(timeout=6), dict(max_late_ms=251), dict(max_late_ms=1.0),
    dict(origin=dict(numerator=-1, denominator=1)), dict(limits=dict(LIMITS, max_gap_blocks=5))])
def test_invalid_constructor_does_not_claim_or_abort_backend(overrides):
    clock = Clock()
    backend = Backend(clock)
    with pytest.raises(ValueError):
        M['GapOutput'](backend, **dict(dict(origin=dict(numerator=0, denominator=1), anchor_ns=clock.ns,
            limits=LIMITS, timeout=5, max_late_ms=250, clock=clock, pause=clock.pause), **overrides))
    assert backend.aborts == backend.finishes == 0 and not backend.writes


def test_source_before_shared_origin_and_invalid_pcm_fail_before_writes():
    for event, payload in [prepared(0, 9), (prepared(0, 10)[0], (b'wrong',))]:
        sink, backend, _clock = output()
        with pytest.raises(ValueError):
            sink.write(event, payload)
        assert not backend.writes and sink.result()['source_gap_plan']['source_blocks_verified'] == 0


def test_cleanup_can_be_retried_without_releasing_a_false_closed_receipt():
    sink, backend, _clock = output()
    def fail():
        raise OSError('abort failed')
    backend.abort = fail
    sink.abort()
    assert not sink.result()['transport_closed']
    backend.abort = lambda: None
    sink.abort()
    r = sink.result()
    assert r['transport_closed'] and r['abort_attempts'] == 2
    assert r['abort_error_type'] == 'OSError'  # Retain the historical failure.


def test_maximum_padding_has_bounded_separate_ownership():
    sink, backend, _clock = output(limits=dict(LIMITS, max_gap_blocks=4))
    sink.write(*prepared(0, 10))
    sink.write(*prepared(1, 10 + 5 * D, Fraction(10)))
    assert sink.result()['peak_owned_bytes'] == 10240
    assert sink.result()['api_bytes'] == dict(source=4096, padding=8192)
    assert b''.join(data for _, data in backend.writes) == PCM + bytes(8192) + PCM


def test_keyboard_interrupt_aborts_owned_transport_and_propagates():
    sink, backend, _clock = output()
    def interrupt(data):
        raise KeyboardInterrupt
    backend.write = interrupt
    with pytest.raises(KeyboardInterrupt):
        sink.write(*prepared(0, 10))
    assert backend.aborts == 1 and sink.result()['last_error_type'] == 'KeyboardInterrupt'


def test_native_nonblocking_pipe_preserves_source_and_separate_zero_bytes():
    sink, backend, _clock = output()
    reader, writer = os.pipe()
    os.set_blocking(writer, False)
    backend.write = lambda data: os.write(writer, data)
    backend.finish = lambda timeout: os.close(writer)
    try:
        sink.write(*prepared(0, 10))
        sink.write(*prepared(1, 10 + 2 * D, Fraction(10)))
        sink.finish()
        assert os.read(reader, 6144) == PCM + bytes(2048) + PCM
        assert not os.read(reader, 1)
    finally:
        os.close(reader)
        if not sink.finished:
            os.close(writer)


def test_partial_writes_use_readonly_views_without_hidden_suffix_copies():
    sink, backend, _clock = output()
    backend.progress = 127
    sink.write(*prepared(0, 10))
    assert all(isinstance(data, memoryview) and data.readonly and data.obj is PCM
               for _, data in backend.writes)
    assert b''.join(data for _, data in backend.writes) == PCM


def test_aborted_drain_cannot_finish_successfully_even_when_backend_returns_normally():
    sink, backend, _clock = output()
    sink.write(*prepared(0, 10))
    entered, release = Event(), Event()
    errors = []
    def blocked_finish(timeout):
        entered.set()
        assert release.wait(2)
        # An aborting backend may have discarded pending output and still return.
    backend.finish = blocked_finish
    def finish():
        try:
            sink.finish()
        except InterruptedError:
            errors.append('cancelled')
    thread = Thread(target=finish)
    thread.start()
    try:
        assert entered.wait(2)
        sink.abort()
        assert sink.result()['cancelled'] and not sink.result()['outputs_finished']
    finally:
        release.set()
        thread.join(2)
    r = sink.result()
    assert not thread.is_alive() and errors == ['cancelled']
    assert r['cancelled'] and r['failed'] and r['transport_closed']
    assert not r['outputs_finished'] and r['last_error_type'] == 'InterruptedError'
    assert backend.aborts == 1


def test_same_thread_backend_drain_cancellation_does_not_deadlock_or_claim_success():
    sink, backend, _clock = output()
    sink.write(*prepared(0, 10))
    backend.finish = lambda timeout: sink.abort()
    with pytest.raises(InterruptedError):
        sink.finish()
    assert sink.result()['cancelled'] and not sink.result()['outputs_finished']
