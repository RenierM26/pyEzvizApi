"""Guarded prefix output requires acquisition policy, output acks and clean drain."""
from concurrent.futures import Future
import copy
import os
from pathlib import Path
import runpy
from types import SimpleNamespace
from typing import Any

import pytest

from pyezvizapi.media import CaptureLimits

M = runpy.run_path(str(Path(__file__).parents[1] / 'tools/local_av_capture_playback.py'))
PREP = M['PREPARE']
OUT = M['OUTPUT']
OLD = runpy.run_path(str(Path(__file__).with_name('test_local_av_online_playback.py')))
OWNER = runpy.run_path(str(Path(__file__).with_name('test_local_av_capture.py')))['Owner']
BackendBase: Any = OLD['BackendBase']
pytestmark = pytest.mark.skipif(not hasattr(os, 'memfd_create'), reason='Linux sealed output')


def arguments(**changes):
    values = dict(primary_stream=0, secondary_stream=2, audio_stream=1,
        audio_overlap_policy='bounded-serial-pcm', max_audio_overlap_ms=1, max_audio_phase_ms=1,
        video_transport='sealed-store', container='mpeg', deadline=5, max_late_ms=250,
        mono_option='channels', play=True, pairing='exact-pts', timing='host-submission',
        layout='side-by-side', processor='passthrough')
    values.update(changes)
    return SimpleNamespace(**values)


class Executor:
    def __init__(self, **_kwargs):
        self.joined = False
    def submit(self, fn, *args):
        future: Future[Any] = Future()
        try:
            future.set_result(fn(*args))
        except Exception as error:
            future.set_exception(error)
        return future
    def shutdown(self, **_kwargs):
        self.joined = True


@pytest.fixture
def rig(tmp_path, monkeypatch):
    raw = OLD['POLICY']['OLD']['TIMELINE_TESTS']['encode_three_track_ps'](tmp_path, audio_jitter=True).read_bytes()
    monkeypatch.setattr(PREP['CAPTURE']['DECRYPT']['Decryptor'], 'decode', lambda _self, chunk: chunk)
    clock = OLD['OLD']['Clock']()
    video, audio = BackendBase(clock), BackendBase(clock)
    titles = []
    def output(*_args, **kwargs):
        titles.append(kwargs.get('title'))
        return video
    monkeypatch.setitem(OUT['CHANNEL'], 'Output', output)
    monkeypatch.setitem(OUT['PLAY']['PCM'], 'Ffplay', lambda **_kwargs: audio)
    namespace = OUT['play_prepared'].__globals__
    scheduler = OUT['Scheduler']
    monkeypatch.setitem(namespace, 'Scheduler', lambda *args: scheduler(*args, clock=clock.read, pause=clock.sleep))
    monkeypatch.setitem(namespace, 'ThreadPoolExecutor', Executor)
    return raw, video, audio, titles


def play(rig, report, *, args=None, **kwargs):
    raw = rig[0]
    owner = OWNER([raw[i:i+1024] for i in range(0, len(raw), 1024)])
    limits = CaptureLimits(max_packets=len(owner.bodies), max_bytes=16777216, duration_seconds=60)
    options = dict(limits=limits, codec='hevc', completion='bounded-prefix')
    options.update(kwargs)
    return owner, lambda: M['capture_playback'](owner, 'camera-key', args or arguments(), report, **options)


def test_success_requires_same_origin_targets_all_calls_and_clean_drains(rig):
    report: dict[str, Any] = {}
    owner, run = play(rig, report)
    run()
    assert owner.closed and report['status'] == 'prefix-output-completed'
    prepared, output = report['preparation'], report['output']
    assert prepared['status'] == 'prepared-prefix-ended'
    assert prepared['accepted_prefix_clear_sha256'] == report['accepted_prefix_clear_sha256']
    assert output['scheduler']['outputs_finished'] and output['scheduler']['completed'] == output['scheduler']['submitted']
    assert rig[1].finished and rig[2].finished and rig[1].aborted and rig[2].aborted
    assert rig[3] == ['Bounded capture prefix (host submissions; not device sync)']
    assert not report['whole_source_complete'] and not report['network_eof_verified']
    assert not report['physical_av_sync_measured']
    scheduler = output['scheduler']
    for action in scheduler['actions']:
        if action['kind'] == 'output_call_submitted':
            offset = OUT['PLAY']['fraction'](action['source_at']) * 1_000_000_000
            assert action['target_monotonic_ns'] == scheduler['host_anchor_monotonic_ns'] + offset.numerator // offset.denominator
    assert not output['lookahead']['owned_ids'] and not output['lookahead']['pending_preparation']


@pytest.mark.parametrize('changes', [dict(play=False), dict(video_transport='socket'), dict(container='auto'),
    dict(primary_stream=1), dict(audio_overlap_policy='guess'), dict(max_late_ms=251), dict(max_late_ms=True),
    dict(deadline=float('nan')), dict(deadline=31), dict(deadline=True), dict(mono_option='guess'),
    dict(pairing='guess'), dict(timing='guess'), dict(layout='guess'), dict(processor='guess')])
def test_invalid_output_options_do_not_claim_capture_or_open_backends(rig, changes):
    report: dict[str, Any] = {'status': 'prefix-output-completed', 'accepted_prefix_clear_sha256': 'stale'}
    owner, run = play(rig, report, args=arguments(**changes))
    with pytest.raises(ValueError):
        run()
    assert not owner.started and not owner.closed and not rig[3]
    assert report['status'] == 'failed' and report['accepted_prefix_clear_sha256'] is None
    assert not report['preparation'] and not report['output']


def test_already_started_capture_is_not_cancelled(rig):
    owner, run = play(rig, {})
    owner.started = True
    with pytest.raises(ValueError, match='pristine'):
        run()
    assert not owner.closed and not rig[3]


def test_output_constructor_failure_closes_active_capture_and_sealed_leases(rig, monkeypatch):
    def fail(**_kwargs):
        raise OSError('audio constructor failed')
    monkeypatch.setitem(OUT['PLAY']['PCM'], 'Ffplay', fail)
    report: dict[str, Any] = {}
    owner, run = play(rig, report)
    with pytest.raises(OSError, match='audio constructor'):
        run()
    assert owner.closed and rig[1].aborted
    assert report['status'] == 'failed' and report['accepted_prefix_clear_sha256'] is None
    assert not report['output']['lookahead']['owned_ids']


def test_unstarted_preparation_is_closed_if_output_setup_fails_before_pull(rig, monkeypatch):
    primary = BrokenPipeError('setup failure')
    def fail(*_args, **_kwargs):
        raise primary
    monkeypatch.setitem(OUT, 'play_prepared', fail)
    report: dict[str, Any] = {}
    owner, run = play(rig, report)
    owner.close_error = True
    with pytest.raises(BrokenPipeError) as caught:
        run()
    assert caught.value is primary and owner.closed and not owner.started
    assert report['cleanup_error_types'] == ['OSError']


@pytest.mark.parametrize('failure', ['capture-end', 'ambiguous-end', 'source', 'output', 'drain', 'cancel'])
def test_late_failures_abort_output_and_never_upgrade_prefix(rig, failure):
    report: dict[str, Any] = {}
    owner, run = play(rig, report, completion='reject' if failure=='capture-end' else 'bounded-prefix')
    if failure == 'ambiguous-end':
        owner.reason = 'upstream_ended'
    if failure == 'source':
        owner.error = BrokenPipeError('source error')
    if failure in ('output', 'drain'):
        def fail(*_args):
            raise OSError('backend failed')
        if failure == 'output':
            rig[1].present = fail
        else:
            rig[2].finish = fail
    if failure == 'cancel':
        def cancel():
            raise KeyboardInterrupt
        rig[1].alive = cancel
    with pytest.raises((ValueError, OSError, KeyboardInterrupt)):
        run()
    assert owner.closed and report['status'] == ('cancelled' if failure=='cancel' else 'failed')
    assert report['accepted_prefix_clear_sha256'] is None
    assert not report['output']['lookahead']['owned_ids']
    assert not any(report['output']['lookahead']['owned_bytes'].values())
    if report['output']['output_devices_opened']:
        assert rig[1].aborted


def test_cleanup_only_error_not_hidden_inside_unrelated_caller_exception(rig):
    def fail():
        raise OSError('cleanup failed')
    rig[1].abort = fail
    report: dict[str, Any] = {}
    owner, run = play(rig, report)
    try:
        raise LookupError('ambient')
    except LookupError:
        with pytest.raises(ValueError, match='cleanup failed'):
            run()
    assert owner.closed and report['status'] == 'failed'
    assert report['accepted_prefix_clear_sha256'] is None and report['output']['cleanup_errors']


@pytest.mark.parametrize('path,value', [
    ('preparation.status', 'running'), ('output.scheduler.outputs_finished', False),
    ('output.scheduler.completed.video_pair', 0), ('output.scheduler.partial_audio_bytes', 1),
    ('output.scheduler.failed', {'video_pair': 'failed'}), ('output.cleanup_errors', ['failed']),
    ('output.lookahead.verified_prepared_source_end', False), ('output.lookahead.pending_preparation', ['pending']),
    ('output.lookahead.owned_bytes.video_pair', 1), ('output.lookahead.offered.audio_block', 0),
])
def test_partial_receipts_cannot_claim_output_completion(rig, path, value):
    report: dict[str, Any] = {}
    _owner, run = play(rig, report)
    run()
    changed = copy.deepcopy(report)
    parts = path.split('.')
    target = changed
    for part in parts[:-1]:
        target = target[part]
    target[parts[-1]] = value
    with pytest.raises(ValueError, match='terminal checks'):
        M['verify_output'](changed['preparation'], changed['output'])


def test_explicit_pes_selection_reaches_output_without_changing_source_indices(rig):
    report: dict[str, Any] = {}
    owner, run = play(rig, report, args=arguments(secondary_stream=1, audio_stream=2),
                      pes_ids=(0xE0, 0xE1, 0xC0))
    run()
    assert owner.closed and report['status'] == 'prefix-output-completed'
    selection = report['preparation']['decode']['track_selection']
    assert selection['video_indices'] == [0, 2] and selection['audio_index'] == 1
    assert report['preparation']['online']['track_selection'] == selection
    assert rig[1].finished and rig[2].finished


def test_missing_pes_identity_fails_before_output_opens(rig):
    report: dict[str, Any] = {}
    owner, run = play(rig, report, pes_ids=(0xE0, 0xEF, 0xC0))
    with pytest.raises(ValueError, match='identity'):
        run()
    assert owner.closed and not rig[3] and report['output']['output_devices_opened'] is False
    assert report['accepted_prefix_clear_sha256'] is None
