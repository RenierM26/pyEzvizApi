"""Shared storage retains exact paired bytes and rejects mutable/invalid inputs."""

import ctypes.util
import fcntl
import hashlib
import io
import os
from pathlib import Path
import runpy

import pytest

M = runpy.run_path(str(Path(__file__).parents[1] / 'tools/local_av_playback.py'))
S = M['SHARED']
pytestmark = pytest.mark.skipif(not hasattr(os, 'memfd_create'), reason='Linux sealed memfd')


@pytest.mark.parametrize('order', [('a', 'b', 'c', 'd'), ('d', 'b', 'a', 'c'), ('c', 'a', 'd', 'b')])
def test_precomposition_reorders_exactly_in_original_extent_and_seals(order):
    raw = {name: bytes([i + 1]) * 6 for i, name in enumerate('abcd')}
    events = [dict(kind='video_pair', id=f'p:{i}', lenses=[
        dict(decoded_id=name, width=2, height=2) for name in names])
        for i, names in enumerate(('ab', 'cd'))]
    with S['sealed_file']() as store:
        assets = M['Assets'](store, io.BytesIO())
        for i, name in enumerate(order):
            store.write(raw[name])
            assets.video.records[name] = dict(offset=i * 6, size=6,
                pixel_sha256=hashlib.sha256(raw[name]).hexdigest())
        expected = [assets.load(event) for event in events]
        assets.prepare_shared(dict(events=events))
        assert S['validate_store'](store.fileno()) == 24
        for event, pixels in zip(events, expected, strict=True):
            frame = assets.load(event)
            assert len(frame) == 12 and frame.sha256 == hashlib.sha256(pixels).hexdigest()
            assert os.pread(store.fileno(), len(frame), frame.offset) == pixels
        for operation in (lambda: os.write(store.fileno(), b'x'),
                          lambda: os.ftruncate(store.fileno(), 1),
                          lambda: os.ftruncate(store.fileno(), 25)):
            with pytest.raises(PermissionError):
                operation()


def test_unsealed_store_and_unaccounted_lenses_rejected():
    with S['sealed_file']() as store:
        store.write(bytes(12))
        store.flush()
        with pytest.raises(ValueError, match='sealed'):
            S['validate_store'](store.fileno())
        assets = M['Assets'](store, io.BytesIO())
        assets.video.records['extra'] = dict(offset=0, size=12)
        with pytest.raises(ValueError, match='every lens'):
            assets.prepare_shared(dict(events=[]))


@pytest.mark.parametrize('change', [dict(offset=True), dict(offset=1), dict(offset=-12),
    dict(offset=24), dict(bytes=True), dict(pixel_sha256='bad'), dict(pair_id=''), dict(extra=1)])
def test_untrusted_frame_extent_rejected(change):
    row = dict(kind='shared_frame', pair_id='p:1', offset=0, bytes=12, pixel_sha256='a' * 64)
    row.update(change)
    with pytest.raises(ValueError, match='extent'):
        S['frame_extent'](row, 12, 24)


@pytest.mark.skipif(not ctypes.util.find_library('SDL2-2.0'), reason='SDL2 unavailable')
@pytest.mark.parametrize('bad', [False, True])
def test_real_worker_metadata_only_ack_and_hash_rejection(monkeypatch, bad):
    monkeypatch.setenv('SDL_VIDEODRIVER', 'dummy')
    with S['sealed_file']() as store:
        pixels = bytes(range(12))
        store.write(pixels)
        S['seal'](store)
        output = S['Output'](4, 2, 5, store, 2)
        sent = []
        original = output.transfer
        def transfer(data, deadline):
            if isinstance(data, bytes):
                sent.append(data)
            return original(data, deadline)
        output.transfer = transfer
        try:
            digest = '0' * 64 if bad else hashlib.sha256(pixels).hexdigest()
            frame = S['Frame'](0, len(pixels), digest)
            if bad:
                with pytest.raises(ValueError, match='fingerprint'):
                    output.present('p:1', frame, 5)
            else:
                row = output.present('p:1', frame, 5)
                assert row['bytes'] == 12 and row['pixel_sha256'] == digest
                with pytest.raises(ValueError, match='duplicate'):
                    output.present('p:1', frame, 5)
            assert all(len(data) < 256 and pixels not in data for data in sent)
        finally:
            output.abort()
        assert output.process.poll() is not None


def test_portable_python_without_header_constants_still_enforces_kernel_seals(monkeypatch):
    for name in ('F_ADD_SEALS', 'F_GET_SEALS', 'F_SEAL_SEAL', 'F_SEAL_WRITE',
                 'F_SEAL_GROW', 'F_SEAL_SHRINK'):
        monkeypatch.delattr(fcntl, name, raising=False)
    portable = runpy.run_path(str(Path(__file__).parents[1] / 'tools/local_av_shared_frames.py'))
    with portable['sealed_file']() as store:
        store.write(bytes(12))
        portable['seal'](store)
        assert portable['validate_store'](store.fileno()) == 12
        with pytest.raises(PermissionError):
            os.ftruncate(store.fileno(), 13)
