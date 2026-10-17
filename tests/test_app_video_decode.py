"""Decoded pixel/PTS bindings and explicit two-track staging provenance."""

from fractions import Fraction
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
from types import SimpleNamespace
from typing import Any

import pytest

SCRIPT = Path(__file__).parents[1] / 'tools/app_video_decode.py'
MODULE = runpy.run_path(str(SCRIPT))
pytestmark = pytest.mark.skipif(os.name != 'posix', reason='POSIX local decoder adapter')


class Plane:
    line_size = 8

    def __init__(self, width, height, padding=99):
        self.data = b''.join(bytes([row + 1]) * width + bytes([padding]) * (8 - width)
                             for row in range(height))

    def __bytes__(self):
        return self.data


def frame(**overrides):
    fields = dict(width=4, height=4, format=SimpleNamespace(name='yuv420p'),
                  is_corrupt=False, pts=0, time_base=Fraction(1, 1000),
                  planes=[Plane(4, 4), Plane(2, 2), Plane(2, 2)])
    fields.update(overrides)
    return SimpleNamespace(**fields)


def report():
    return dict(primary_stream=2, secondary_stream=5,
                decoded_frames=[MODULE['fingerprint'](frame(), 2, 0),
                                MODULE['fingerprint'](frame(pts=7), 5, 0)])


def offer(row, lens, identity, at=0, **overrides):
    event = {key: row[key] for key in MODULE['BINDING']}
    event.update(kind='lens_picture', at_ms=at, id=identity, lens=lens,
                 raw_time=42, media_ms=50 + lens, frame_number=9 + lens)
    event.update(overrides)
    return event


def header_source(events):
    return io.BytesIO(b''.join(json.dumps(row).encode() + b'\n' for row in events))


def test_hash_excludes_stride_padding_and_keeps_exact_pts():
    a = MODULE['fingerprint'](frame(pts=1, time_base=Fraction(1, 90000)), 2, 0)
    b = MODULE['fingerprint'](frame(planes=[Plane(4, 4, 0), Plane(2, 2, 0), Plane(2, 2, 0)]), 2, 0)
    assert a['pixel_sha256'] == b['pixel_sha256']
    packed = b'\x01' * 4 + b'\x02' * 4 + b'\x03' * 4 + b'\x04' * 4
    packed += (b'\x01' * 2 + b'\x02' * 2) * 2
    assert a['pixel_sha256'] == hashlib.sha256(packed).hexdigest()
    assert a['source_pts'] == 1 and a['time_base_den'] == 90000
    assert a['decoded_id'] == 'video:2:0'
    changed = Plane(4, 4)
    changed.data = b'\x00' + changed.data[1:]
    c = MODULE['fingerprint'](frame(planes=[changed, Plane(2, 2), Plane(2, 2)]), 2, 0)
    assert c['pixel_sha256'] != a['pixel_sha256']


@pytest.mark.parametrize('bad', [dict(is_corrupt=True), dict(width=3), dict(height=0),
    dict(width=4098), dict(width=4096, height=4096), dict(width=True),
    dict(format=SimpleNamespace(name='yuv420p10le')), dict(planes=[]), dict(pts=None),
    dict(pts=True), dict(pts=-1), dict(pts=2**32), dict(time_base=None),
    dict(time_base=Fraction(0)), dict(time_base=Fraction(-1))])
def test_unsupported_or_unknown_frame_rejected(bad):
    with pytest.raises(ValueError):
        MODULE['fingerprint'](frame(**bad), 0, 0)


def test_truncated_plane_and_invalid_stride_rejected():
    plane = Plane(4, 4)
    plane.data = b'x'
    with pytest.raises(ValueError, match='stride'):
        MODULE['fingerprint'](frame(planes=[plane, Plane(2, 2), Plane(2, 2)]), 0, 0)
    plane.line_size = 1
    plane.data = b'x' * 32
    with pytest.raises(ValueError, match='stride'):
        MODULE['fingerprint'](frame(planes=[plane, Plane(2, 2), Plane(2, 2)]), 0, 0)


def test_header_order_not_decoder_demux_order_and_never_pts_pairing():
    r = report()
    first, second = r['decoded_frames']
    events = [offer(second, 1, 'secondary', at=2), offer(first, 0, 'primary', at=3),
              dict(kind='render_take', at_ms=4)]
    joined = MODULE['join_headers'](r, header_source(events))
    pair = joined['pairing']['actions'][0]['pair']
    assert [x['id'] for x in pair['lenses']] == ['primary', 'secondary']
    assert pair['lenses'][0]['raw_time'] == 42
    assert pair['lenses'][0]['media_ms'] == 50
    assert joined['events'][0]['at_ms'] == 2
    assert not MODULE['BINDING'] & joined['events'][0].keys()
    assert joined['pairing']['summary']['render_taken'] == 1
    assert joined['offer_bindings'] == [dict(offer_id='secondary', decoded_id=second['decoded_id']),
                                      dict(offer_id='primary', decoded_id=first['decoded_id'])]
    # Equal decoded times do not imply a pair; the caller's raw headers govern it.
    events[1]['raw_time'] = 100
    other = MODULE['join_headers'](r, header_source(events))
    assert other['pairing']['summary']['pairs_assembled'] == 0
    assert len(other['pairing']['summary']['staging_pending']) == 2


@pytest.mark.parametrize('field,value', [('decoded_id', 'unknown'), ('source_pts', True),
    ('source_pts', 1), ('time_base_num', 2), ('time_base_den', 10),
    ('pixel_sha256', '0' * 64), ('lens', 1), ('extra', 0)])
def test_binding_mismatch_track_confusion_and_extra_fields_rejected(field, value):
    r = report()
    events = [dict(offer(r['decoded_frames'][0], 0, 'a'), **{field: value}),
              offer(r['decoded_frames'][1], 1, 'b')]
    with pytest.raises(ValueError):
        MODULE['join_headers'](r, header_source(events))


def test_map_coverage_missing_binding_and_explicit_repeat_offers():
    r = report()
    a, b = r['decoded_frames']
    with pytest.raises(ValueError, match='every decoded'):
        MODULE['join_headers'](r, header_source([offer(a, 0, 'a')]))
    missing = offer(a, 0, 'a')
    del missing['pixel_sha256']
    with pytest.raises(ValueError, match='binding'):
        MODULE['join_headers'](r, header_source([missing]))
    joined = MODULE['join_headers'](r, header_source([offer(a, 0, 'a'),
             offer(a, 0, 'explicit-retry'), offer(b, 1, 'b')]))
    assert joined['pairing']['summary']['lens_offered'] == 3
    assert joined['pairing']['summary']['staging_pending'][0]['lenses'][0]['id'] == 'explicit-retry'


@pytest.mark.parametrize('raw', [b'[]\n', b'{bad}\n', b' ' * 8193])
def test_bad_map_json_and_lines(raw):
    with pytest.raises(ValueError):
        MODULE['join_headers'](report(), io.BytesIO(raw))


def fake_container(monkeypatch, *, name='hevc', dimensions=(4, 4), packets=None):
    tracks = [SimpleNamespace(index=i, type='video', codec_context=SimpleNamespace(
              name=name, width=dimensions[0], height=dimensions[1])) for i in (2, 5)]
    def packet(track, frames, **extra):
        return SimpleNamespace(stream=track, is_corrupt=False, size=100,
                               decode=lambda: frames, **extra)
    calls = [packet(tracks[0], [frame()]), packet(tracks[1], []),
             packet(tracks[1], [frame(pts=7)])] if packets is None else packets(tracks, packet)
    class Container:
        streams = tracks
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def demux(self, *selected):
            assert len(selected) == 2
            return iter(calls)
    fake = SimpleNamespace(open=lambda *args, **kwargs: Container(),
                           __version__='test', library_versions={})
    monkeypatch.setitem(MODULE['AUDIO'], 'load_av', lambda: fake)


def test_decoder_flush_attributed_to_its_track_without_native_clock_inference(monkeypatch):
    fake_container(monkeypatch)
    r = MODULE['decode'](None, 'matroska', (2, 5))
    assert [row['stream_index'] for row in r['decoded_frames']] == [2, 5]
    assert r['decoded_frames'][1]['source_pts'] == 7
    assert 'events' not in r


@pytest.mark.parametrize('change', ['codec', 'dimensions', 'missing-track', 'missing-frame',
                                   'backward', 'corrupt', 'packet-limit', 'frame-limit', 'pixel-limit'])
def test_unsupported_decoder_sessions_fail(monkeypatch, change):
    kwargs: dict[str, Any] = {}
    if change == 'codec':
        kwargs['name'] = 'h264'
    if change == 'dimensions':
        kwargs['dimensions'] = (8192, 8192)
    if change == 'missing-frame':
        kwargs['packets'] = lambda tracks, make: [make(tracks[0], [frame()])]
    if change == 'backward':
        kwargs['packets'] = lambda tracks, make: [make(tracks[0], [frame(pts=1), frame()])]
    if change == 'corrupt':
        def corrupt(tracks, make):
            p = make(tracks[0], [])
            p.is_corrupt = True
            return [p]
        kwargs['packets'] = corrupt
    fake_container(monkeypatch, **kwargs)
    if change.endswith('-limit'):
        key = {'packet-limit': 'MAX_PACKETS', 'frame-limit': 'MAX_FRAMES',
               'pixel-limit': 'MAX_TOTAL_PIXELS'}[change]
        MODULE['decode'].__globals__[key] = 0
    try:
        with pytest.raises(ValueError):
            MODULE['decode'](None, 'matroska', (2, 9) if change == 'missing-track' else (2, 5))
    finally:
        for key in ('MAX_PACKETS', 'MAX_FRAMES', 'MAX_TOTAL_PIXELS'):
            MODULE['decode'].__globals__[key] = MODULE[key]


def test_real_two_track_hevc_decode_and_mapped_cli(tmp_path):
    av = pytest.importorskip('av', reason='optional real HEVC integration')
    try:
        av.codec.Codec('libx265', 'w')
    except av.error.FFmpegError:
        pytest.skip('optional HEVC encoder unavailable')
    source = tmp_path / 'paired.mkv'
    with av.open(str(source), 'w', format='matroska') as output:
        tracks = [output.add_stream('libx265', rate=15) for _ in range(2)]
        for track in tracks:
            track.width, track.height, track.pix_fmt = 64, 48, 'yuv420p'
            track.options = {'x265-params': 'pools=none:frame-threads=1:log-level=error',
                             'preset': 'ultrafast'}
        for i in range(3):
            for lens, track in enumerate(tracks):
                picture = av.VideoFrame(64, 48, 'yuv420p')
                for plane in picture.planes:
                    plane.update(bytes([20 + i + 10 * lens]) * plane.buffer_size)
                picture.pts = i
                picture.time_base = Fraction(1, 15)
                for packet in track.encode(picture):
                    output.mux(packet)
        for track in tracks:
            for packet in track.encode():
                output.mux(packet)
    command = [sys.executable, str(SCRIPT), str(source), '--container', 'matroska',
               '--primary-stream', '0', '--secondary-stream', '1']
    inspect = subprocess.run(command, capture_output=True, timeout=20, check=False)
    assert inspect.returncode == 0, inspect.stderr.decode()
    r = json.loads(inspect.stdout)
    assert r['mode'] == 'inspect' and len(r['decoded_frames']) == 6
    assert not r['native_header_provenance_verified']
    if shutil.which('ffmpeg'):
        for lens in (0, 1):
            reference = subprocess.run(['ffmpeg', '-v', 'error', '-i', str(source),
                '-map', f'0:{lens}', '-fps_mode', 'passthrough', '-pix_fmt', 'yuv420p',
                '-f', 'rawvideo', '-'], capture_output=True, timeout=20, check=False)
            assert reference.returncode == 0, reference.stderr.decode()
            size = 64 * 48 * 3 // 2
            assert len(reference.stdout) == size * 3
            hashes = [hashlib.sha256(reference.stdout[i:i + size]).hexdigest()
                      for i in range(0, len(reference.stdout), size)]
            assert hashes == [row['pixel_sha256'] for row in r['decoded_frames']
                              if row['stream_index'] == lens]
    events = []
    for index in range(3):
        for lens in (1, 0):
            row = next(row for row in r['decoded_frames'] if row['stream_index'] == lens
                       and row['frame_index'] == index)
            events.append(offer(row, lens, f'{lens}:{index}', at=index,
                                raw_time=index, media_ms=index * 66))
    headers = tmp_path / 'headers.jsonl'
    headers.write_bytes(header_source(events).getvalue())
    mapped = subprocess.run([*command, '--header-map', str(headers)], capture_output=True,
                            timeout=20, check=False)
    assert mapped.returncode == 0, mapped.stderr.decode()
    result = json.loads(mapped.stdout)
    assert result['pairing']['summary']['render_admitted'] == 3
    assert len(result['pairing']['summary']['render_pending']) == 3
    assert not result['physical_lip_sync_measured']
    events[-1]['pixel_sha256'] = '0' * 64
    headers.write_bytes(header_source(events).getvalue())
    rejected = subprocess.run([*command, '--header-map', str(headers)], capture_output=True,
                              timeout=20, check=False)
    assert rejected.returncode == 2 and not rejected.stdout


@pytest.mark.parametrize('streams', [(2, 2), (-1, 5), (True, 5)])
def test_stream_selection_is_explicit_and_distinct(streams):
    with pytest.raises(ValueError, match='distinct'):
        MODULE['decode'](None, 'matroska', streams)


def test_packet_size_and_cooperative_session_deadline(monkeypatch):
    def oversized(tracks, make):
        p = make(tracks[0], [])
        p.size = 4 * 1024 * 1024 + 1
        return [p]
    fake_container(monkeypatch, packets=oversized)
    with pytest.raises(ValueError, match='oversized'):
        MODULE['decode'](None, 'matroska', (2, 5))
    fake_container(monkeypatch)
    clock = iter((0, 61))
    monkeypatch.setattr(MODULE['time'], 'monotonic', lambda: next(clock))
    with pytest.raises(ValueError, match='session'):
        MODULE['decode'](None, 'matroska', (2, 5))


def test_event_bound_is_not_bypassed_by_control_only_map_tail():
    r = report()
    events = [offer(r['decoded_frames'][0], 0, 'a'),
              offer(r['decoded_frames'][1], 1, 'b')]
    events.extend(dict(kind='stage_push', at_ms=0) for _ in range(9999))
    with pytest.raises(ValueError, match='event limit'):
        MODULE['join_headers'](r, header_source(events))
