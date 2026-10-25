"""Byte-exact split texture uploads and canonical paired hashes, not timing repair."""

import ctypes
import ctypes.util
from fractions import Fraction
import hashlib
import os
from pathlib import Path
import runpy
from types import SimpleNamespace

import pytest

BASE = Path(__file__).parents[1]
M = runpy.run_path(str(BASE / 'tools/local_av_bounded_playback.py'))
C = M['CHANNEL']
PREVIEW = M['PLAY']['PREVIEW']
VIDEO = M['DECODE']['VIDEO']
OLD = runpy.run_path(str(Path(__file__).with_name('test_local_av_bounded_playback.py')))
pytestmark = pytest.mark.skipif(not hasattr(os, 'memfd_create'), reason='Linux sealed descriptors')


@pytest.mark.parametrize('width,height', [(2, 2), (4, 6), (64, 48), (1920, 1080)])
def test_split_hash_is_exactly_legacy_canonical_yuv_not_concatenated_lens_hash(width, height):
    size = width * height * 3 // 2
    left, right = bytes(i % 251 for i in range(size)), bytes((i + 99) % 251 for i in range(size))
    expected = PREVIEW['compose'](left, right, width, height)
    with memoryview(left + right) as pixels:
        assert C['paired_digest'](pixels, width * 2, height) == hashlib.sha256(expected).hexdigest()
    lease = C['Lease']((left, right), hashlib.sha256(expected).hexdigest())
    try:
        assert lease.frame.sha256 == hashlib.sha256(left + right).hexdigest()
        assert lease.pair_sha256 == hashlib.sha256(expected).hexdigest()
        assert os.pread(lease.store.fileno(), size * 2, 0) == left + right
    finally:
        lease.close()


@pytest.mark.parametrize('width,height', [(2, 2), (4, 6), (64, 48)])
def test_sdl_partial_texture_updates_reconstruct_every_original_yuv_row(width, height):
    size = width * height * 3 // 2
    left, right = bytes(i % 251 for i in range(size)), bytes((i + 99) % 251 for i in range(size))
    expected = PREVIEW['compose'](left, right, width, height)
    texture = bytearray(size * 2)
    calls = []
    def update(_texture, raw_rect, y, yp, u, up, v, vp):
        rect = ctypes.cast(raw_rect, ctypes.POINTER(C['Rect'])).contents
        calls.append((rect.x, rect.y, rect.w, rect.h))
        offset = 0
        for pointer, pitch, w, h, x in ((y, yp, width, height, rect.x),
                (u, up, width // 2, height // 2, rect.x // 2),
                (v, vp, width // 2, height // 2, rect.x // 2)):
            for row in range(h):
                start = offset + row * w * 2 + x
                texture[start:start + w] = ctypes.string_at(pointer + row * pitch, w)
            offset += w * h * 2
        return 0
    rendered = []
    surface = object.__new__(C['Surface'])
    surface.width, surface.height, surface.texture, surface.renderer = width * 2, height, 1, 1
    surface.pump = lambda: None
    surface.lib = SimpleNamespace(SDL_UpdateYUVTexture=update, SDL_RenderClear=lambda _: 0,
        SDL_RenderCopy=lambda *_: 0, SDL_RenderPresent=lambda _: rendered.append(True))
    with memoryview(bytearray(left + right)) as pixels:
        surface.present_lenses(pixels)
    assert calls == [(0, 0, width, height), (width, 0, width, height)]
    assert texture == expected and rendered == [True]


def test_split_lookahead_does_not_call_owner_compositor_and_holds_same_credit(monkeypatch):
    event, payload = OLD['pair']()
    digest = hashlib.sha256(PREVIEW['compose'](*payload, 2, 2)).hexdigest()
    def forbidden(*_args):
        pytest.fail('full-frame composition still ran during timed preparation')
    monkeypatch.setitem(PREVIEW, 'compose', forbidden)
    assets = M['Lookahead'](OLD['ClosableIterator']([(event, payload)]), [event],
                           'split-upload', {event['id']: digest})
    try:
        pumped = assets.pump()
        assert pumped
        lease = assets.load(event)
        assert lease.layout == 'lens-planar' and lease.pair_sha256 == digest
        assert assets.counts['video_pair'] == 1 and assets.bytes['video_pair'] == 12
        timing = assets.result()['preparation_timings'][0]
        assert timing['id'] == event['id'] and timing['status'] == 'prepared'
        assert all(timing[key] >= 0 for key in ('decode_ns', 'verify_ns', 'prepare_ns'))
        assets.release(event['id'])
        assert lease.store.closed
    finally:
        assets.close()


def test_split_requires_known_preflight_pair_hash_and_reports_failed_stage():
    event, payload = OLD['pair']()
    assets = M['Lookahead'](OLD['ClosableIterator']([(event, payload)]), [event], 'split-upload')
    try:
        with pytest.raises(ValueError, match='preflight canonical'):
            assets.pump()
        timing = assets.result()['preparation_timings'][0]
        assert timing['status'] == 'failed' and timing['phase'] == 'prepare'
    finally:
        assets.close()


@pytest.mark.parametrize('padded', [False, True])
def test_contiguous_fast_path_and_padded_fallback_exclude_all_stride_and_tail_bytes(padded):
    expected = bytearray()
    planes = []
    for width, height, value in ((4, 4, 12), (2, 2, 55), (2, 2, 99)):
        visible = bytes([value]) * width * height
        expected.extend(visible)
        stride = width + 2 if padded else width
        raw = b''.join(visible[row * width:(row + 1) * width] + bytes([238]) * (stride - width)
                       for row in range(height)) + bytes([255]) * 7
        class Plane:
            def __init__(self, data, line_size):
                self.data, self.line_size = data, line_size
            def __bytes__(self):
                return self.data
        planes.append(Plane(raw, stride))
    frame = SimpleNamespace(width=4, height=4, planes=planes, format=SimpleNamespace(name='yuv420p'),
                            pts=90001, time_base=Fraction(1, 90000), is_corrupt=False)
    assert PREVIEW['pack'](frame) == bytes(expected)
    record = VIDEO['fingerprint'](frame, 0, 0)
    assert record['pixel_sha256'] == hashlib.sha256(expected).hexdigest()
    assert record['source_pts'] == 90001 and record['time_base_den'] == 90000


@pytest.mark.parametrize('bad', ['canonical', 'storage'])
def test_split_worker_validation_rejects_either_hash_before_texture_update(bad):
    left, right = bytes(6), bytes([128]) * 6
    digest = hashlib.sha256(PREVIEW['compose'](left, right, 2, 2)).hexdigest()
    lease = C['Lease']((left, right), digest)
    fd = os.dup(lease.store.fileno())
    surface = SimpleNamespace(width=4, height=2,
        present_lenses=lambda _: pytest.fail('invalid pair reached texture upload'))
    try:
        with pytest.raises(ValueError, match='fingerprint'):
            C['present_fd'](fd, 12, '0' * 64 if bad == 'canonical' else digest, surface,
                            '0' * 64 if bad == 'storage' else lease.frame.sha256, 'lens-planar')
        with pytest.raises(OSError):
            os.fstat(fd)
    finally:
        lease.close()


@pytest.mark.parametrize('changes', [dict(layout='unknown'), dict(storage_sha256='bad'),
    dict(bytes=14), dict(offset=1), dict(extra=True)])
def test_split_metadata_rejects_unknown_layout_and_unbounded_or_forged_extent(changes):
    row = dict(kind='shared_frame', pair_id='p:0', offset=0, bytes=12,
               pixel_sha256='a' * 64, layout='lens-planar', storage_sha256='b' * 64)
    row.update(changes)
    with pytest.raises(ValueError):
        C['frame_layout'](row, 12)


@pytest.mark.skipif(not ctypes.util.find_library('SDL2-2.0'), reason='SDL2 unavailable')
def test_real_worker_split_upload_keeps_identical_ack_hash_and_one_persistent_process(monkeypatch):
    monkeypatch.setenv('SDL_VIDEODRIVER', 'dummy')
    output = C['Output'](4, 2, 5, 3)
    process = output.process.pid
    try:
        for index in range(3):
            left, right = bytes([index]) * 6, bytes([index + 90]) * 6
            canonical = hashlib.sha256(PREVIEW['compose'](left, right, 2, 2)).hexdigest()
            lease = C['Lease']((left, right), canonical)
            try:
                ack = output.present(f'p:{index}', lease, 5)
                assert ack['pixel_sha256'] == canonical and ack['bytes'] == 12
                assert output.process.pid == process
            finally:
                lease.close()
        output.finish(5)
    finally:
        output.abort()
    assert output.process.poll() is not None


def test_output_completed_during_preparation_is_harvested_before_next_poll_cycle():
    clock = OLD['OLD']['Clock']()
    events = [OLD['pair'](0), OLD['pair'](1), OLD['block'](0)]
    timeline = dict(events=[dict(events[0][0], at=dict(numerator=0, denominator=1)),
                           dict(events[1][0], at=dict(numerator=1, denominator=100)),
                           dict(events[2][0], at=dict(numerator=1, denominator=200))])
    assets = M['Lookahead'](OLD['ClosableIterator'](events), [event for event, _ in events])
    for _ in events:
        assets.pump()
    original = assets.pump
    delayed = False
    def eof_flush():
        nonlocal delayed
        if not delayed:
            clock.sleep(.020)
            delayed = True
        return original()
    assets.pump = eof_flush
    scheduler = M['Scheduler'](timeline, .5, 250, assets, clock=clock.read, pause=clock.sleep)
    video, audio = OLD['OLD']['Backend'](clock), OLD['OLD']['Backend'](clock)
    try:
        scheduler.run(assets, video, audio, OLD['OLD']['Executor'](clock))
        assert video.calls[1][1] - scheduler.anchor == 20_000_000
        assert scheduler.completed == dict(video_pair=2, audio_block=1)
    finally:
        assets.close()


def test_productive_preparation_does_not_add_a_poll_per_video_and_audio_event():
    """59 ms pair preparation fits 15 Hz; adding two 5 ms polls does not."""
    clock = OLD['OLD']['Clock']()
    events = []
    for index in range(118):
        for event in (OLD['pair'](index), OLD['block'](index)):
            event[0]['at'] = dict(numerator=index, denominator=15)
            events.append(event)
    timeline = dict(events=[event for event, _ in events])
    assets = OLD['lookahead'](events)
    assets.prefill(timeline, 1)
    original = assets.pump
    def prepare_with_measured_cost():
        index = assets.index
        prepared = original()
        if prepared and index < len(events):
            clock.sleep(.059 if events[index][0]['kind'] == 'video_pair' else .0004)
        return prepared
    assets.pump = prepare_with_measured_cost
    scheduler = M['Scheduler'](timeline, .5, 250, assets, clock=clock.read, pause=clock.sleep)
    video, audio = OLD['OLD']['Backend'](clock), OLD['OLD']['Backend'](clock)
    try:
        scheduler.run(assets, video, audio, OLD['OLD']['Executor'](clock))
        assert scheduler.completed == dict(video_pair=118, audio_block=118)
        assert assets.source_end and video.finished and audio.finished
        starts = [a for a in scheduler.actions if a['kind'] == 'output_call_submitted']
        assert max(a['submission_late_ns'] for a in starts) < 70_000_000
        assert not assets.owned
    finally:
        assets.close()
