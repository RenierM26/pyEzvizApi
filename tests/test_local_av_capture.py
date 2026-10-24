"""Capture exhaustion must pass policy before the crypto EOF/flush boundary."""
import hashlib
from pathlib import Path
import runpy
from types import SimpleNamespace
from typing import Any

import pytest

from pyezvizapi.media import CaptureLimits

M = runpy.run_path(str(Path(__file__).parents[1] / 'tools/local_av_capture.py'))
CRYPTO = runpy.run_path(str(Path(__file__).with_name('test_local_av_decrypted.py')))


class Owner:
    def __init__(self, bodies, reason='packet_limit', overrides=None, error=None, close_error=False):
        self.bodies = list(bodies)
        self.reason, self.overrides, self.error = reason, overrides or {}, error
        self.close_error = close_error
        self.started = self.closed = self.ended = False
        self.pulls = self.close_calls = self.seen = self.bytes = 0
    @property
    def capture_result(self):
        result: dict[str, Any] = dict(profile='automatic-media-capture-v1', status='stopped' if self.closed else 'running' if self.started else 'not_started',
            owner_closed=self.closed, transport_owned=self.started and not self.closed,
            transport_attempts=int(self.started), transports_opened=int(self.started),
            transports_released=int(self.closed and self.started), startup_in_progress=False,
            transport_closure_verified=self.closed, cleanup_error_types=[], error_type=None,
            stop_reason=self.reason if self.ended else 'consumer_closed' if self.closed else None,
            packets_yielded=self.seen, bytes_yielded=self.bytes, network_eof_verified=False)
        if self.closed:
            result.update(self.overrides)
        return result
    def iter_media_packets(self, **_kwargs):
        self.started = True
        try:
            for body in self.bodies:
                self.pulls += 1
                self.seen += 1
                self.bytes += len(body)
                yield SimpleNamespace(body=body)
            if self.error:
                raise self.error
            self.ended = True
        finally:
            self.closed = True
    def close(self):
        self.close_calls += 1
        self.closed = True
        if self.close_error:
            raise OSError('private cleanup detail')


def setup(reason='packet_limit', size=65536, **kwargs):
    raw, clear = CRYPTO['fixture']()
    bodies = [raw[i:i + size] for i in range(0, len(raw), size)]
    owner = Owner(bodies, reason, **kwargs)
    limits = CaptureLimits(max_packets=len(bodies), max_bytes=16 * 1024 * 1024, duration_seconds=8)
    return owner, limits, clear


@pytest.mark.parametrize('reason', ['packet_limit', 'byte_limit', 'duration_limit', 'upstream_ended', 'consumer_closed'])
def test_default_rejection_never_calls_decryption_flush(monkeypatch, reason):
    owner, limits, _ = setup(reason)
    called = []
    def forbidden(_self):
        called.append(True)
        raise AssertionError('unexpected flush')
    monkeypatch.setattr(M['DECRYPT']['Decryptor'], 'finish', forbidden)
    report: dict[str, Any] = {}
    with pytest.raises(M['CaptureEndRejected']):
        list(M['iter_capture_chunks'](owner, 'camera-key', report, limits=limits, codec='hevc'))
    assert not called and owner.closed and owner.close_calls == 1
    assert report['status'] == 'failed' and not report['capture_end_policy_accepted']
    assert report['decryption']['verified_decryption_end'] is False
    assert report['accepted_prefix_clear_sha256'] is None and not report['whole_source_complete']


@pytest.mark.parametrize('reason', ['packet_limit', 'byte_limit', 'duration_limit'])
@pytest.mark.parametrize('size', [1, 7, 65536])
def test_only_explicit_known_limit_can_finish_bounded_prefix(reason, size):
    owner, limits, clear = setup(reason, size)
    report: dict[str, Any] = {}
    actual = b''.join(M['iter_capture_chunks'](owner, 'camera-key', report, limits=limits, codec='hevc', completion='bounded-prefix'))
    assert actual == clear
    assert report['status'] == 'bounded-prefix-ended' and report['capture_end_policy_accepted']
    assert report['accepted_prefix_clear_sha256'] == hashlib.sha256(clear).hexdigest()
    assert report['decryption']['verified_decryption_end'] and owner.close_calls == 1
    assert not report['whole_source_complete'] and not report['network_eof_verified']
    assert not report['output_devices_opened']


@pytest.mark.parametrize('override', [
    {'status': 'failed'}, {'owner_closed': False}, {'transport_owned': True},
    {'startup_in_progress': True}, {'transport_closure_verified': False},
    {'cleanup_error_types': ['OSError']}, {'error_type': 'TimeoutError'},
    {'transports_opened': 0}, {'transports_released': 0}, {'packets_yielded': 99},
    {'bytes_yielded': 99}, {'profile': 'old-profile'}, {'network_eof_verified': True},
])
def test_invalid_final_receipt_cannot_become_crypto_eof(override):
    owner, limits, _ = setup(overrides=override)
    report: dict[str, Any] = {}
    with pytest.raises(M['CaptureEndRejected']):
        list(M['iter_capture_chunks'](owner, 'camera-key', report, limits=limits, codec='hevc', completion='bounded-prefix'))
    assert report['status'] == 'failed' and not report['decryption']['verified_decryption_end']
    assert owner.closed


@pytest.mark.parametrize('reason', ['upstream_ended', 'consumer_closed', 'timeout', 'error', 'unknown'])
def test_opt_in_does_not_accept_unknown_or_failure_endings(reason):
    owner, limits, _ = setup(reason)
    with pytest.raises(M['CaptureEndRejected']):
        list(M['iter_capture_chunks'](owner, 'camera-key', {}, limits=limits, codec='hevc', completion='bounded-prefix'))
    assert owner.closed


def test_source_error_keeps_primary_through_owner_close_failure():
    primary = BrokenPipeError('private producer error')
    owner, limits, _ = setup(error=primary, close_error=True)
    report: dict[str, Any] = {}
    with pytest.raises(BrokenPipeError) as caught:
        list(M['iter_capture_chunks'](owner, 'camera-key', report, limits=limits, codec='hevc', completion='bounded-prefix'))
    assert caught.value is primary and owner.closed
    assert report['status'] == 'failed' and report['cleanup_error_types'] == ['OSError']
    assert 'private' not in repr(report)


def test_cleanup_only_failure_is_not_masked_by_ambient_caller_exception():
    owner, limits, _ = setup(close_error=True)
    report: dict[str, Any] = {}
    try:
        raise LookupError('ambient')
    except LookupError:
        with pytest.raises(ValueError, match='cleanup'):
            list(M['iter_capture_chunks'](owner, 'camera-key', report, limits=limits, codec='hevc', completion='bounded-prefix'))
    assert report['status'] == 'failed' and report['accepted_prefix_clear_sha256'] is None


def test_invalid_arguments_do_not_consume_or_close_an_unclaimed_owner():
    owner, limits, _ = setup()
    changes_to_try: list[dict[str, Any]] = [dict(completion='guess'), dict(codec='h264'), dict(limits=CaptureLimits(max_packets=1))]
    for changes in changes_to_try:
        kwargs = dict(limits=limits, completion='bounded-prefix', codec='hevc')
        kwargs.update(changes)
        with pytest.raises(ValueError):
            next(M['iter_capture_chunks'](owner, 'camera-key', {}, **kwargs))
    assert not owner.started and not owner.closed


def test_already_started_owner_is_not_claimed_or_cancelled():
    owner, limits, _ = setup()
    owner.started = True
    with pytest.raises(ValueError, match='pristine'):
        next(M['iter_capture_chunks'](owner, 'camera-key', {}, limits=limits, codec='hevc'))
    assert not owner.closed and owner.close_calls == 0


def test_packet_limit_receipt_must_equal_configured_limit():
    owner, limits, _ = setup()
    limits = CaptureLimits(max_packets=2, max_bytes=limits.max_bytes, duration_seconds=8)
    with pytest.raises(M['CaptureEndRejected'], match='configured bounds'):
        list(M['iter_capture_chunks'](owner, 'camera-key', {}, limits=limits, completion='bounded-prefix', codec='hevc'))


def test_early_consumer_close_releases_owner_without_prefetch(monkeypatch):
    monkeypatch.setattr(M['DECRYPT']['Decryptor'], 'feed', lambda _self, data: data)
    owner, limits, _ = setup(size=7)
    report: dict[str, Any] = {}
    iterator = M['iter_capture_chunks'](owner, 'camera-key', report, limits=limits, codec='hevc', completion='bounded-prefix')
    assert next(iterator) and owner.pulls == 1
    iterator.close()
    assert owner.closed and owner.close_calls == 1
    assert report['status'] == 'consumer-closed' and not report['capture_end_policy_accepted']
    assert report['decryption']['pending_bytes'] == 0 and report['accepted_prefix_clear_sha256'] is None


def test_owner_cleanup_state_is_revalidated_after_close(monkeypatch):
    owner, limits, _ = setup()
    original = owner.close
    def close():
        original()
        owner.overrides['status'] = 'failed'
    monkeypatch.setattr(owner, 'close', close)
    report: dict[str, Any] = {}
    with pytest.raises(M['CaptureEndRejected']):
        list(M['iter_capture_chunks'](owner, 'camera-key', report, limits=limits, codec='hevc', completion='bounded-prefix'))
    assert report['status'] == 'failed' and not report['capture_end_policy_accepted']
    assert report['accepted_prefix_clear_sha256'] is None


def test_iterator_construction_error_survives_owner_cleanup_failure(monkeypatch):
    owner, limits, _ = setup(close_error=True)
    primary = BrokenPipeError('private creation error')
    def fail(**_kwargs):
        raise primary
    monkeypatch.setattr(owner, 'iter_media_packets', fail)
    report: dict[str, Any] = {}
    with pytest.raises(BrokenPipeError) as caught:
        next(M['iter_capture_chunks'](owner, 'camera-key', report, limits=limits, codec='hevc'))
    assert caught.value is primary and owner.closed
    assert report['cleanup_error_types'] == ['OSError'] and 'private' not in repr(report)


def test_crypto_failure_is_not_upgraded_to_success_after_capture_policy_accepts():
    owner = Owner([b'not a detected encrypted stream'])
    report: dict[str, Any] = {}
    limits = CaptureLimits(max_packets=1, max_bytes=1024, duration_seconds=8)
    with pytest.raises(ValueError, match='unresolved'):
        list(M['iter_capture_chunks'](owner, 'camera-key', report, limits=limits, completion='bounded-prefix'))
    assert report['capture_end_policy_accepted'] and report['status'] == 'failed'
    assert report['accepted_prefix_clear_sha256'] is None
    assert not report['decryption']['verified_decryption_end']


def test_transform_cleanup_failure_cannot_replace_original_source_error(monkeypatch):
    primary = BrokenPipeError('original producer')
    owner, limits, _ = setup(error=primary)
    def close(_self):
        raise OSError('private transform cleanup')
    monkeypatch.setattr(M['DECRYPT']['Decryptor'], 'close', close)
    report: dict[str, Any] = {}
    with pytest.raises(BrokenPipeError) as caught:
        list(M['iter_capture_chunks'](owner, 'camera-key', report, limits=limits, codec='hevc'))
    assert caught.value is primary and report['error_type'] == 'BrokenPipeError'
    assert report['cleanup_error_types'] == ['OSError']


@pytest.mark.parametrize('override', [{'packets_yielded': True}, {'bytes_yielded': True}, {'transports_released': True}])
def test_boolean_receipt_counters_are_not_valid_integer_accounting(override):
    owner, limits, _ = setup(overrides=override)
    with pytest.raises(M['CaptureEndRejected']):
        list(M['iter_capture_chunks'](owner, 'camera-key', {}, limits=limits, codec='hevc', completion='bounded-prefix'))


def test_reused_report_cannot_retain_prior_run_success_on_invalid_arguments():
    owner, limits, _ = setup()
    report: dict[str, Any] = dict(status='bounded-prefix-ended', accepted_prefix_clear_sha256='stale',
        capture={'status': 'stopped'}, decryption={'verified_decryption_end': True}, error_type='old')
    with pytest.raises(ValueError):
        next(M['iter_capture_chunks'](owner, 'camera-key', report, limits=limits, completion='guess'))
    assert report['status'] == 'failed' and report['error_type'] == 'ValueError'
    assert report['accepted_prefix_clear_sha256'] is report['capture'] is report['decryption'] is None
    assert not owner.started


def test_final_crypto_cleanup_failure_never_publishes_prefix_success(monkeypatch):
    owner, limits, _ = setup()
    def close(_self):
        raise OSError('private transform cleanup')
    monkeypatch.setattr(M['DECRYPT']['Decryptor'], 'close', close)
    report: dict[str, Any] = {}
    with pytest.raises(OSError):
        list(M['iter_capture_chunks'](owner, 'camera-key', report, limits=limits, codec='hevc', completion='bounded-prefix'))
    assert report['status'] == 'failed' and report['error_type'] == 'OSError'
    assert report['accepted_prefix_clear_sha256'] is None
    assert report['cleanup_error_types'] == ['OSError']


@pytest.mark.parametrize('changes', [
    {'max_packets': 100001}, {'max_bytes': 16777217}, {'duration_seconds': 61},
    {'max_packets': True}, {'max_bytes': 1.5}, {'duration_seconds': True},
])
def test_bounds_are_not_silently_clamped_or_claimed(changes):
    owner, _limits, _ = setup()
    values: dict[str, Any] = dict(max_packets=1, max_bytes=1024, duration_seconds=8)
    values.update(changes)
    with pytest.raises(ValueError, match='explicit finite'):
        next(M['iter_capture_chunks'](owner, 'camera-key', {}, limits=CaptureLimits(**values)))
    assert not owner.started and not owner.closed and owner.close_calls == 0
