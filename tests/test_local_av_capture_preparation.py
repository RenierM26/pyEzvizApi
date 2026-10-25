"""A unified prefix verdict requires every stage and cleanup, never just EOF."""
import copy
import hashlib
from pathlib import Path
import runpy
from typing import Any

import pytest

from pyezvizapi.media import CaptureLimits

M = runpy.run_path(str(Path(__file__).parents[1] / 'tools/local_av_capture_preparation.py'))
C = M['CAPTURE']
OWNER = runpy.run_path(str(Path(__file__).with_name('test_local_av_capture.py')))['Owner']
OLD = runpy.run_path(str(Path(__file__).with_name('test_local_av_incremental.py')))


@pytest.fixture
def source(tmp_path, monkeypatch):
    raw = OLD['TIMELINE_TESTS']['encode_three_track_ps'](tmp_path, audio_jitter=True).read_bytes()
    # Public synthetic clear PS exercises all composition layers without private
    # captures. Existing crypto tests and private retained audits cover AES bytes.
    monkeypatch.setattr(C['DECRYPT']['Decryptor'], 'decode', lambda _self, chunk: chunk)
    return raw


def prepare(raw, report, **kwargs):
    size = 1024
    owner = OWNER([raw[i:i + size] for i in range(0, len(raw), size)])
    defaults = dict(limits=CaptureLimits(max_packets=len(owner.bodies), max_bytes=16777216, duration_seconds=60),
        completion='bounded-prefix', codec='hevc', policy='bounded-serial-pcm', overlap_ms=1, phase_ms=1)
    defaults.update(kwargs)
    return owner, M['iter_capture_preparation'](owner, 'camera-key', (0, 2), 1, report, **defaults)


def fingerprints(events):
    return [(event, tuple(hashlib.sha256(p).hexdigest() for p in parts)) for event, parts in events]


def test_unified_success_matches_independent_snapshot_and_timeline(source):
    report: dict[str, Any] = {}
    owner, iterator = prepare(source, report)
    actual = fingerprints(iterator)
    online: dict[str, Any] = {}
    snapshot = M['CHUNKED']['DECODE']['iter_snapshot'](source, 'mpeg', (0, 2), 1, {})
    expected = fingerprints(M['ONLINE']['iter_online'](snapshot, (0, 2), 1, online,
        policy='bounded-serial-pcm', overlap_ms=1, phase_ms=1))
    assert actual == expected and actual
    assert report['online']['policy'] == online['policy']
    assert report['status'] == 'prepared-prefix-ended' and owner.closed
    assert report['accepted_prefix_clear_sha256'] == hashlib.sha256(source).hexdigest()
    assert not report['whole_source_complete'] and not report['network_eof_verified']
    assert not report['output_devices_opened'] and not report['physical_av_sync_measured']


def test_default_reject_cannot_flush_or_publish_prepared_verdict(source, monkeypatch):
    calls = []
    def forbidden(_self):
        calls.append(True)
        raise AssertionError('forbidden EOF flush')
    monkeypatch.setattr(C['DECRYPT']['Decryptor'], 'finish', forbidden)
    report: dict[str, Any] = {}
    owner, iterator = prepare(source, report, completion='reject')
    with pytest.raises(ValueError):
        list(iterator)
    assert not calls and owner.closed
    assert report['status'] == 'failed' and report['accepted_prefix_clear_sha256'] is None
    assert not report['capture']['decryption']['verified_decryption_end']


@pytest.mark.parametrize('kwargs', [dict(completion='guess'), dict(codec='h264'), dict(policy='guess'),
    dict(overlap_ms=-1), dict(limits=CaptureLimits(max_packets=1))])
def test_invalid_arguments_leave_owner_unclaimed(source, kwargs):
    report: dict[str, Any] = {'accepted_prefix_clear_sha256': 'stale', 'status': 'prepared-prefix-ended'}
    owner, iterator = prepare(source, report, **kwargs)
    with pytest.raises(ValueError):
        next(iterator)
    assert not owner.started and not owner.closed and owner.close_calls == 0
    assert report['status'] == 'failed' and report['accepted_prefix_clear_sha256'] is None
    assert not report['capture'] and not report['decode'] and not report['online']


def test_started_owner_is_not_cancelled(source):
    owner, iterator = prepare(source, {})
    owner.started = True
    with pytest.raises(ValueError, match='pristine'):
        next(iterator)
    assert not owner.closed


def test_early_close_releases_all_layers_without_success(source):
    report: dict[str, Any] = {}
    owner, iterator = prepare(source, report)
    next(iterator)
    pulls = owner.pulls
    iterator.close()
    assert owner.closed and owner.pulls == pulls
    assert report['status'] == 'consumer-closed' and report['accepted_prefix_clear_sha256'] is None
    assert not any(report['online']['policy']['owned_bytes'].values())
    assert report['capture']['decryption']['pending_bytes'] == 0


@pytest.mark.parametrize('stage', ['capture', 'decode', 'online'])
def test_partial_construction_closes_claimed_but_unstarted_owner(source, monkeypatch, stage):
    module, key = {'capture': (C, 'iter_capture_chunks'), 'decode': (M['CHUNKED'], 'iter_chunks'),
        'online': (M['ONLINE'], 'iter_online')}[stage]
    primary = BrokenPipeError('construction failure')
    def fail(*_args, **_kwargs):
        raise primary
    monkeypatch.setitem(module, key, fail)
    report: dict[str, Any] = {}
    owner, iterator = prepare(source, report)
    with pytest.raises(BrokenPipeError) as caught:
        next(iterator)
    assert caught.value is primary and owner.closed and not owner.started
    assert report['status'] == 'failed' and report['accepted_prefix_clear_sha256'] is None


def test_constructor_failure_stays_primary_if_unstarted_owner_cleanup_fails(source, monkeypatch):
    primary = BrokenPipeError('construction failure')
    def fail(*_args, **_kwargs):
        raise primary
    monkeypatch.setitem(M['CHUNKED'], 'iter_chunks', fail)
    report: dict[str, Any] = {}
    owner, iterator = prepare(source, report)
    owner.close_error = True
    with pytest.raises(BrokenPipeError) as caught:
        next(iterator)
    assert caught.value is primary and report['cleanup_error_types'] == ['OSError']


def test_policy_failure_after_prefix_closes_capture(source):
    report: dict[str, Any] = {}
    owner, iterator = prepare(source, report, policy='reject', overlap_ms=None, phase_ms=None)
    with pytest.raises(ValueError, match='overlapping'):
        list(iterator)
    assert owner.closed and report['status'] == 'failed'
    assert report['accepted_prefix_clear_sha256'] is None
    assert not any(report['online']['policy']['owned_bytes'].values())


@pytest.mark.parametrize('path,value', [
    ('capture.status', 'running'), ('capture.capture_end_policy_accepted', False),
    ('capture.decryption.verified_decryption_end', False), ('capture.decryption.pending_bytes', 1),
    ('capture.decryption.complete_clear_sha256', 'wrong'), ('decode.source_sha256', 'wrong'),
    ('decode.status', 'closed-before-eof'), ('decode.cleanup_errors', ['failed']),
    ('decode.input.verified_source_end', False), ('decode.input.pending_bytes', 1),
    ('decode.input.delivered_bytes', 0), ('decode.preparation.pending_pixel_bytes', 1),
    ('online.status', 'failed'), ('online.cleanup_errors', ['failed']),
    ('online.policy.origin', None), ('online.policy.released_prepared_events', 0),
    ('online.policy.owned_bytes.video_pair', 1), ('online.policy.audio_blocks', 0),
])
def test_terminal_evidence_not_status_alone(source, path, value):
    report: dict[str, Any] = {}
    _owner, iterator = prepare(source, report)
    list(iterator)
    receipt = copy.deepcopy(report)
    target = receipt
    parts = path.split('.')
    for part in parts[:-1]:
        target = target[part]
    target[parts[-1]] = value
    with pytest.raises(ValueError, match=r'terminal checks|event accounting'):
        M['verify_completion'](receipt['capture'], receipt['decode'], receipt['online'])


def test_ambiguous_owner_end_fails_without_crypto_eof(source):
    report: dict[str, Any] = {}
    owner, iterator = prepare(source, report)
    owner.reason = 'upstream_ended'
    with pytest.raises(ValueError):
        list(iterator)
    assert owner.closed and report['status'] == 'failed'
    assert not report['capture']['capture_end_policy_accepted']
    assert report['accepted_prefix_clear_sha256'] is None


def test_bad_container_does_not_become_preparation_success(source):
    report: dict[str, Any] = {}
    owner, iterator = prepare(b'not a three-track PS', report)
    av = pytest.importorskip('av')
    with pytest.raises(av.error.FFmpegError):
        list(iterator)
    assert owner.closed and report['status'] == 'failed'
    assert report['accepted_prefix_clear_sha256'] is None


def test_unstarted_cleanup_only_failure_is_not_masked_by_ambient_exception(source, monkeypatch):
    class Empty:
        def __iter__(self):
            return iter(())
        def close(self):
            pass
    monkeypatch.setitem(M['ONLINE'], 'iter_online', lambda *_args, **_kwargs: Empty())
    report: dict[str, Any] = {}
    owner, iterator = prepare(source, report)
    owner.close_error = True
    try:
        raise LookupError('ambient')
    except LookupError:
        with pytest.raises(OSError):
            list(iterator)
    assert owner.closed and report['status'] == 'failed'
    assert report['cleanup_error_types'] == ['OSError']


def test_completed_outer_iterator_still_needs_terminal_stage_evidence(source, monkeypatch):
    def empty(*_args, **_kwargs):
        yield from ()
    monkeypatch.setitem(M['ONLINE'], 'iter_online', empty)
    report: dict[str, Any] = {}
    owner, iterator = prepare(source, report)
    with pytest.raises(ValueError, match='terminal checks'):
        list(iterator)
    assert owner.closed and report['status'] == 'failed'
    assert report['accepted_prefix_clear_sha256'] is None


def test_pes_selection_resolves_in_same_demuxer_and_keeps_source_indices(source):
    expected_report: dict[str, Any] = {}
    _owner, original = prepare(source, expected_report)
    expected = fingerprints(original)
    actual_report: dict[str, Any] = {}
    # Deliberately wrong legacy slots: explicit PES mode resolves before decode
    # and the online policy receives those actual indices before its first offer.
    size = 1024
    owner = OWNER([source[i:i + size] for i in range(0, len(source), size)])
    actual = M['iter_capture_preparation'](owner, 'camera-key', (0, 1), 2, actual_report,
        limits=CaptureLimits(max_packets=len(owner.bodies), max_bytes=16777216, duration_seconds=60),
        completion='bounded-prefix', codec='hevc', policy='bounded-serial-pcm', overlap_ms=1, phase_ms=1,
        pes_ids=(0xE0, 0xE1, 0xC0))
    assert fingerprints(actual) == expected
    selection = actual_report['decode']['track_selection']
    assert selection['video_indices'] == [0, 2] and selection['audio_index'] == 1
    assert actual_report['online']['track_selection'] == selection
    assert actual_report['decode']['preparation'] == expected_report['decode']['preparation']
    assert actual_report['status'] == 'prepared-prefix-ended' and owner.closed


@pytest.mark.parametrize('ids', [(0xE0, 0xE0, 0xC0), (True, 0xE1, 0xC0)])
def test_invalid_pes_selection_does_not_claim_owner(source, ids):
    report: dict[str, Any] = {}
    owner, iterator = prepare(source, report, pes_ids=ids)
    with pytest.raises(ValueError):
        list(iterator)
    assert not owner.started and not owner.closed
    assert report['accepted_prefix_clear_sha256'] is None


def test_missing_selected_pes_closes_capture_without_success(source):
    report: dict[str, Any] = {}
    owner, iterator = prepare(source, report, pes_ids=(0xE0, 0xEF, 0xC0))
    with pytest.raises(ValueError, match='identity'):
        list(iterator)
    assert owner.closed and report['status'] == 'failed'
    assert report['accepted_prefix_clear_sha256'] is None


@pytest.mark.parametrize('order,streams,audio', [((0, 2, 1), (0, 2), 1), ((0, 1, 2), (0, 1), 2)])
def test_actual_ps_discovery_orders_match_independent_absolute_index_control(tmp_path, monkeypatch, order, streams, audio):
    raw = OLD['TIMELINE_TESTS']['encode_three_track_ps'](tmp_path, audio_jitter=True, discovery_order=order).read_bytes()
    monkeypatch.setattr(C['DECRYPT']['Decryptor'], 'decode', lambda _self, chunk: chunk)
    baseline_decode: dict[str, Any] = {}
    baseline_policy: dict[str, Any] = {}
    baseline = M['CHUNKED']['DECODE']['iter_snapshot'](raw, 'mpeg', streams, audio, baseline_decode)
    expected = fingerprints(M['ONLINE']['iter_online'](baseline, streams, audio, baseline_policy,
        policy='bounded-serial-pcm', overlap_ms=1, phase_ms=1))
    report: dict[str, Any] = {}
    owner, events = prepare(raw, report, pes_ids=(0xE0, 0xE1, 0xC0))
    assert fingerprints(events) == expected
    assert report['decode']['track_selection']['video_indices'] == list(streams)
    assert report['decode']['track_selection']['audio_index'] == audio
    assert report['decode']['preparation'] == baseline_decode['preparation']
    assert report['online']['policy'] == baseline_policy['policy']
    assert owner.closed and report['status'] == 'prepared-prefix-ended'


def test_pes_mode_early_close_retains_resolved_diagnostics_and_closes_source(source):
    report: dict[str, Any] = {}
    owner, events = prepare(source, report, pes_ids=(0xE0, 0xE1, 0xC0))
    next(events)
    events.close()
    assert owner.closed and report['status'] == 'consumer-closed'
    assert report['accepted_prefix_clear_sha256'] is None
    assert report['decode']['track_selection'] == report['online']['track_selection']
    assert report['decode']['preparation']
    assert report['decode']['input']['owned_chunk_bytes'] == 0


def test_changed_selection_receipt_cannot_publish_prefix_completion(source):
    report: dict[str, Any] = {}
    _owner, events = prepare(source, report, pes_ids=(0xE0, 0xE1, 0xC0))
    list(events)
    changed = copy.deepcopy(report['online'])
    changed['track_selection']['audio_index'] = 2
    with pytest.raises(ValueError, match='terminal checks'):
        M['verify_completion'](report['capture'], report['decode'], changed)


def test_opt_in_decoder_clock_keeps_source_clock_and_snapshot_media_unchanged(source):
    def wall():
        return 0.0
    report: dict[str, Any] = {}
    owner, iterator = prepare(source, report, monotonic=wall, decoder_deadline_mode='consumer-excluding',
        identity_mode='source-sequence', pes_ids=(0xE0, 0xE1, 0xC0))
    calls = []
    original = owner.iter_media_packets
    def packets(**kwargs):
        calls.append(kwargs)
        yield from original(**kwargs)
    owner.iter_media_packets = packets
    actual = fingerprints(iterator)
    control: dict[str, Any] = {}
    snapshot = M['CHUNKED']['DECODE']['iter_snapshot'](source, 'mpeg', (0, 2), 1, {})
    expected = fingerprints(M['ONLINE']['iter_online'](snapshot, (0, 2), 1, control,
        policy='bounded-serial-pcm', overlap_ms=1, phase_ms=1, identity_mode='source-sequence'))
    assert actual == expected
    assert calls[0]['monotonic'] is wall and calls[0]['limits'].duration_seconds == 60
    assert owner.closed and report['status'] == 'prepared-prefix-ended'
    assert report['decoder_deadline_mode'] == 'consumer-excluding'
    decode = report['decode']
    assert decode['profile'] == 'standalone-chunked-consumer-excluding-v1'
    assert decode['input']['processing_clock']['completed_borrows'] == len(actual)
    assert decode['input']['processing_clock']['borrow_active'] is False
    assert M['verify_completion'](report['capture'], decode, report['online'],
        decoder_deadline_mode='consumer-excluding') == hashlib.sha256(source).hexdigest()
    with pytest.raises(ValueError, match='mode/profile'):
        M['verify_completion'](report['capture'], decode, report['online'])


@pytest.mark.parametrize('mode', [None, False, [], 'active'])
def test_invalid_decoder_clock_mode_does_not_claim_capture(source, mode):
    report: dict[str, Any] = {'decoder_deadline_mode': 'old'}
    owner, iterator = prepare(source, report, decoder_deadline_mode=mode)
    with pytest.raises(ValueError, match='deadline mode'):
        next(iterator)
    assert not owner.started and not owner.closed
    assert report['status'] == 'failed' and report['accepted_prefix_clear_sha256'] is None
    assert 'decoder_deadline_mode' not in report


def test_default_preparation_clears_reused_opt_in_binding(source):
    report: dict[str, Any] = {'decoder_deadline_mode': 'consumer-excluding'}
    _owner, iterator = prepare(source, report)
    list(iterator)
    assert 'decoder_deadline_mode' not in report
    assert report['decode']['profile'] == 'standalone-chunked-preparation-v1'
    assert 'processing_clock' not in report['decode']['input']


def test_decoder_exclusion_does_not_pause_the_active_decryptor_wall_clock(source, monkeypatch):
    now = [0.0]
    def wall():
        return now[0]
    monkeypatch.setattr(M['CHUNKED']['time'], 'monotonic', wall)
    live = []
    original = C['DECRYPT']['Chunks']
    def recorded(*args, **kwargs):
        chunks = original(*args, **kwargs)
        live.append(chunks)
        return chunks
    monkeypatch.setitem(C['DECRYPT'], 'Chunks', recorded)
    # Keep input beyond startup without decoding a repeated source segment.
    raw = source * (1048576 // len(source) + 1)
    report: dict[str, Any] = {}
    owner, iterator = prepare(raw, report, monotonic=wall, decoder_deadline_mode='consumer-excluding')
    next(iterator)
    try:
        assert live and not live[0].completed and owner.pulls < len(owner.bodies)
        assert live[0].clock is wall  # Never substitute the paused decoder clock.
        now[0] = 61
        with pytest.raises(ValueError, match='decrypted source cooperative deadline'):
            live[0].check()
    finally:
        iterator.close()
    assert owner.closed and report['status'] == 'consumer-closed'
    assert report['accepted_prefix_clear_sha256'] is None
    assert not report['decode']['input']['processing_clock']['borrow_active']



def test_reused_preparation_report_clears_nondefault_compressed_byte_binding(source):
    report: dict[str, Any] = {}
    _owner, iterator = prepare(source, report, byte_limit=32 * 1024 * 1024)
    list(iterator)
    assert report['byte_limit'] == 32 * 1024 * 1024
    owner, iterator = prepare(source, report)
    list(iterator)
    assert owner.closed and report['status'] == 'prepared-prefix-ended'
    assert 'byte_limit' not in report and 'byte_limit' not in report['capture']
    assert report['capture']['decryption']['profile'] == 'bounded-decrypted-packet-chunks-v1'
    assert report['decode']['input']['total_byte_limit'] == 16 * 1024 * 1024
