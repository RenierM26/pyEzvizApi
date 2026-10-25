"""Native protocol independently enforces opt-in sequence IDs before receiving FDs."""
import hashlib
import os
from pathlib import Path
import runpy
import time

import pytest

C = runpy.run_path(str(Path(__file__).parents[1] / 'tools/local_av_frame_channel.py'))
pytestmark = pytest.mark.skipif(not hasattr(os, 'memfd_create'), reason='Linux sealed output')


def test_sequence_worker_keeps_constant_state_through_existing_frame_limit(monkeypatch):
    monkeypatch.setenv('SDL_VIDEODRIVER', 'dummy')
    output = C['Output'](4, 2, 5, 300, identity_mode='source-sequence')
    lease = C['Lease'](bytes(range(12)))
    pid = output.process.pid
    try:
        assert output.identity_receipt is None
        for index in range(1, 301):
            ack = output.present(f'local-pair:{index}', lease, 5)
            assert ack['identity_audit'] == C['identity_audit'](index)
            assert output.process.pid == pid
        output.finish(5)
        assert output.identity_receipt == C['identity_audit'](300)
        assert output.process.returncode == 0
    finally:
        output.abort()
        lease.close()


@pytest.mark.parametrize('identity,accepted', [('local-pair:0', 0), ('local-pair:2', 0),
    ('local-pair:01', 0), ('local-pair:+1', 0), ('local-pair:\uff11', 0), ('other:1', 0),
    ('local-pair:1', 1), ('local-pair:3', 1)])
def test_raw_worker_rejects_noncanonical_sequence_before_requesting_descriptor(monkeypatch, identity, accepted):
    monkeypatch.setenv('SDL_VIDEODRIVER', 'dummy')
    output = C['Output'](4, 2, 5, 3, identity_mode='source-sequence')
    lease = C['Lease'](bytes(range(12)))
    try:
        if accepted:
            output.present('local-pair:1', lease, 5)
        # Bypass host checks. No descriptor follows this metadata; rejection
        # must happen before the worker's five-second descriptor receive wait.
        deadline = time.monotonic() + 2
        output.transfer(C['OUTPUT']['packet'](dict(kind='shared_frame', pair_id=identity,
            offset=0, bytes=12, pixel_sha256=hashlib.sha256(bytes(range(12))).hexdigest())), deadline)
        with pytest.raises(ValueError, match='sequence identity'):
            output.receive(deadline)
        assert output.process.wait(timeout=2) == 2
        assert output.identity_receipt is None
    finally:
        output.abort()
        lease.close()


@pytest.mark.parametrize('audit', [None, {}, {'profile': 'old', 'presented': 3, 'retained_id_count': 0},
    {'profile': 'strict-video-source-sequence-v1', 'presented': True, 'retained_id_count': 0},
    {'profile': 'strict-video-source-sequence-v1', 'presented': 3, 'retained_id_count': False},
    {'profile': 'strict-video-source-sequence-v1', 'presented': 2, 'retained_id_count': 0},
    {'profile': 'strict-video-source-sequence-v1', 'presented': 3, 'retained_id_count': 1},
    {'profile': 'strict-video-source-sequence-v1', 'presented': 3, 'retained_id_count': 0, 'extra': 1}])
def test_identity_audit_rejects_wrong_profile_counts_types_and_extra_fields(audit):
    with pytest.raises(ValueError, match='identity audit'):
        C['verify_identity_audit'](audit, 3)


def test_invalid_mode_cannot_create_native_resources(monkeypatch):
    def forbidden():
        pytest.fail('invalid mode created a socket')
    monkeypatch.setattr(C['socket'], 'socketpair', forbidden)
    with pytest.raises(ValueError, match='identity mode'):
        C['Output'](4, 2, 5, 3, identity_mode='unknown')


@pytest.mark.parametrize('phase', ['ready', 'presented', 'finished'])
def test_host_rejects_worker_audit_downgrade_and_reaps_worker(monkeypatch, phase):
    monkeypatch.setenv('SDL_VIDEODRIVER', 'dummy')
    cls = C['Output']
    receive = cls.receive
    processes = []
    def downgraded(self, deadline):
        processes.append(self.process)
        row = receive(self, deadline)
        if row.get('kind') == phase:
            row.pop('identity_audit', None)
        return row
    monkeypatch.setattr(cls, 'receive', downgraded)
    output = None
    lease = C['Lease'](bytes(range(12)))
    try:
        with pytest.raises(ValueError, match=r'identity audit|finish mismatch'):
            output = cls(4, 2, 5, 3, identity_mode='source-sequence')
            output.present('local-pair:1', lease, 5)
            output.finish(5)
        if output is not None:
            assert output.identity_receipt is None
    finally:
        if output is not None:
            output.abort()
        lease.close()
    assert processes and all(process.poll() is not None for process in processes)


def test_sequence_worker_cannot_exceed_requested_frame_cap(monkeypatch):
    monkeypatch.setenv('SDL_VIDEODRIVER', 'dummy')
    output = C['Output'](4, 2, 5, 1, identity_mode='source-sequence')
    lease = C['Lease'](bytes(range(12)))
    try:
        output.present('local-pair:1', lease, 5)
        deadline = time.monotonic() + 2
        output.transfer(C['OUTPUT']['packet'](dict(kind='shared_frame', pair_id='local-pair:2',
            offset=0, bytes=12, pixel_sha256=hashlib.sha256(bytes(range(12))).hexdigest())), deadline)
        with pytest.raises(ValueError, match='frame limit'):
            output.receive(deadline)
        assert output.process.wait(timeout=2) == 2 and output.identity_receipt is None
    finally:
        output.abort()
        lease.close()


def test_empty_sequence_worker_can_finish_without_claiming_presented_pixels(monkeypatch):
    monkeypatch.setenv('SDL_VIDEODRIVER', 'dummy')
    output = C['Output'](4, 2, 5, 1, identity_mode='source-sequence')
    try:
        output.finish(5)
        assert output.identity_receipt == C['identity_audit'](0) and output.process.returncode == 0
    finally:
        output.abort()
