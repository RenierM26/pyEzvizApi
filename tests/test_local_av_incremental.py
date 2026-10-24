"""Incremental ownership, exact pairing and fail-closed prefix receipts."""

import base64
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import runpy
import subprocess
import sys
from types import SimpleNamespace
from typing import Any

import pytest

SCRIPT = Path(__file__).parents[1] / 'tools/local_av_incremental.py'
M = runpy.run_path(str(SCRIPT))
G = M['inspect'].__globals__
TIMELINE_TESTS = runpy.run_path(str(Path(__file__).with_name('test_local_av_timeline.py')))


def lens(stream, index=0, pts=90000, den=90000, width=4):
    pixels = bytes([stream + 1]) * (width * 2 * 3 // 2)
    row = dict(decoded_id=f'video:{stream}:{index}', stream_index=stream,
               source_pts=pts, time_base_num=1, time_base_den=den,
               width=width, height=2, pixel_sha256=hashlib.sha256(pixels).hexdigest())
    return row, pixels


@pytest.fixture(autouse=True)
def fake_pack(monkeypatch, request):
    if 'real' not in request.node.name:
        monkeypatch.setitem(M['PREVIEW'], 'pack', lambda frame: frame)


def test_exact_rational_pairing_releases_before_next_offer_and_accepts_geometry_epochs():
    consumed = []
    buffer = M['PairBuffer']((0, 1), lambda event, data: consumed.append((event, data)))
    for index, width in enumerate((4, 2, 4)):
        buffer.offer(*lens(0, index, 90000 + index, width=width))
        buffer.offer(*lens(1, index, 180000 + 2 * index, den=180000, width=width))
        assert buffer.bytes == 0
        assert not any(buffer.pending.values())
    buffer.finish()
    assert buffer.result()['video_pairs_consumed'] == 3
    assert buffer.peak_frames == 2 and buffer.peak_bytes == 24
    assert consumed[0][0]['source_time'] == dict(numerator=1, denominator=1)
    assert consumed[0][1] == (bytes([1]) * 12, bytes([2]) * 12)


@pytest.mark.parametrize('change', ['rounded', 'duplicate', 'backward', 'geometry', 'hash', 'length', 'unknown'])
def test_invalid_offers_never_discard_or_pair_by_ordinal(change):
    buffer = M['PairBuffer']((0, 1))
    buffer.offer(*lens(0))
    row, data = lens(1, pts=90001 if change == 'rounded' else 90000,
                     width=2 if change == 'geometry' else 4)
    if change in ('duplicate', 'backward'):
        row, data = lens(0, 1, pts=90000 if change == 'duplicate' else 89999)
    elif change == 'hash':
        data = bytes(12)
    elif change == 'length':
        data = data[:-1]
    elif change == 'unknown':
        row['stream_index'] = 3
    with pytest.raises(ValueError):
        buffer.offer(row, data)
    assert buffer.pairs == 0 and buffer.bytes >= 12
    assert buffer.result()['pending_unpaired'][0]['decoded_id'] == 'video:0:0'


@pytest.mark.parametrize('bound', ['frames', 'bytes'])
def test_capacity_rejects_before_pixel_copy_not_after_allocation(monkeypatch, bound):
    buffer = M['PairBuffer']((0, 1))
    buffer.offer(*lens(0))
    if bound == 'frames':
        monkeypatch.setitem(G, 'MAX_PENDING_FRAMES', 1)
    else:
        monkeypatch.setitem(G, 'MAX_PENDING_BYTES', 23)
    def forbidden(_frame):
        pytest.fail('capacity was not checked before copying')
    monkeypatch.setitem(M['PREVIEW'], 'pack', forbidden)
    with pytest.raises(ValueError, match='capacity'):
        buffer.offer(*lens(1))
    assert buffer.bytes == 12 and buffer.peak_frames == 1


def test_consumer_exception_keeps_offered_pair_and_stops_before_next_decode():
    buffer: Any = None
    def fail(_event, _data):
        assert buffer.bytes == 24
        raise BrokenPipeError('downstream failed')
    buffer = M['PairBuffer']((0, 1), fail)
    buffer.offer(*lens(0))
    with pytest.raises(BrokenPipeError):
        buffer.offer(*lens(1))
    assert buffer.pairs == 0 and buffer.bytes == 24
    assert len(buffer.result()['pending_unpaired']) == 2
    with pytest.raises(ValueError, match='EOF'):
        buffer.finish()
    with pytest.raises(ValueError, match='exact pair'):
        M['PairBuffer']((0, 1)).finish()


def fake_container(monkeypatch, *, packets=(), codec_change=None):
    closed = []
    streams = []
    for index in range(3):
        codec = SimpleNamespace(name='aac' if index == 2 else 'hevc', profile='LC',
                                sample_rate=16000, layout=SimpleNamespace(name='mono'),
                                width=4, height=2)
        if codec_change:
            codec_change(index, codec)
        streams.append(SimpleNamespace(index=index, type='audio' if index == 2 else 'video',
                                       codec_context=codec))
    class Container:
        def __init__(self):
            self.streams = streams
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            closed.append(True)
        def demux(self, *selected):
            assert len(selected) == 3
            return iter(packets)
    monkeypatch.setitem(M['AUDIO'], 'load_av', lambda: SimpleNamespace(
        open=lambda *_a, **_kw: Container(), __version__='test', library_versions={}))
    monkeypatch.setitem(M['AUDIO'], 'FormatConverter', lambda _av: SimpleNamespace(resample=lambda _: []))
    monkeypatch.setitem(M['AUDIO'], 'FrameAdapter', lambda *_a: SimpleNamespace(
        resampler=SimpleNamespace(resample=lambda _: [])))
    return closed


def packet(stream=0, size=1, corrupt=False, frames=()):
    return SimpleNamespace(stream=SimpleNamespace(index=stream), size=size,
                           is_corrupt=corrupt, decode=lambda: frames)


@pytest.mark.parametrize('change', ['video-codec', 'audio-codec', 'geometry', 'layout'])
def test_unsupported_track_fails_before_decode_and_closes_source(tmp_path, monkeypatch, change):
    source = tmp_path / 'source'
    source.write_bytes(b'test')
    def alter(index, codec):
        if change == 'video-codec' and index == 0:
            codec.name = 'h264'
        elif change == 'audio-codec' and index == 2:
            codec.profile = 'HE'
        elif change == 'geometry' and index == 0:
            codec.width = 4097
        elif change == 'layout' and index == 2:
            codec.layout.name = 'stereo'
    closed = fake_container(monkeypatch, codec_change=alter)
    result: dict[str, Any] = {}
    with pytest.raises(ValueError):
        M['inspect'](source, 'mpeg', (0, 1), 2, report=result)
    assert closed and result['status'] == 'failed'
    assert result['video_pairs_consumed'] == result['audio_blocks_consumed'] == 0


@pytest.mark.parametrize('bad_packet', [packet(corrupt=True), packet(size=4*1024*1024+1),
                                       packet(stream=2, size=8193)])
def test_packet_limits_fail_without_decoding(tmp_path, monkeypatch, bad_packet):
    source = tmp_path / 'source'
    source.write_bytes(b'test')
    closed = fake_container(monkeypatch, packets=[bad_packet])
    result: dict[str, Any] = {}
    with pytest.raises(ValueError, match='packet'):
        M['inspect'](source, 'mpeg', (0, 1), 2, report=result)
    assert closed and result['packets_decoded'] == 0


def test_flush_packets_are_decoded_and_original_failure_preserves_prefix(tmp_path, monkeypatch):
    source = tmp_path / 'source'
    source.write_bytes(b'test')
    packets = [packet(size=0, frames=[b'left']), packet(1, size=0, frames=[b'right'])]
    closed = fake_container(monkeypatch, packets=packets)
    offered = []
    def fingerprint(_frame, stream, index):
        row, data = lens(stream, index)
        offered.append(data)
        return row
    monkeypatch.setitem(M['VIDEO'], 'fingerprint', fingerprint)
    monkeypatch.setitem(M['PREVIEW'], 'pack', lambda _: offered[-1])
    def fail(_event, _data):
        raise BrokenPipeError('sink closed')
    receipt: dict[str, Any] = {}
    with pytest.raises(BrokenPipeError, match='sink closed'):
        M['inspect'](source, 'mpeg', (0, 1), 2, fail, receipt)
    assert closed and receipt['packets_decoded'] == 2
    assert receipt['error'] == 'BrokenPipeError: sink closed'
    assert receipt['video_frames_decoded'] == {0: 1, 1: 1}
    assert receipt['video_offer_in_progress']['stream_index'] == 1
    assert receipt['pending_pixel_bytes'] == 24


@pytest.mark.parametrize('streams,audio_stream', [((0, 0), 2), ((0, 1), 1), ((False, 1), 2), ((0, -1), 2)])
def test_invalid_indices_before_input_read(streams, audio_stream):
    receipt: dict[str, Any] = {}
    with pytest.raises(ValueError, match='distinct'):
        M['inspect'](Path('absent'), 'mpeg', streams, audio_stream, report=receipt)
    assert receipt['status'] == 'failed'


def test_real_one_pass_matches_original_two_pass_timeline_hashes_and_source_times(tmp_path):
    source = TIMELINE_TESTS['encode_three_track_ps'](tmp_path, audio_jitter=True)
    baseline = M['TIMELINE']['inspect'](source, 'mpeg', (0, 2), 1)
    events = []
    def consume(event, data):
        rows = event['lenses'] if event['kind'] == 'video_pair' else [event['block']]
        for row, payload in zip(rows, data, strict=True):
            key = 'pixel_sha256' if event['kind'] == 'video_pair' else 'pcm_sha256'
            assert hashlib.sha256(payload).hexdigest() == row[key]
        events.append(event)
    result = M['inspect'](source, 'mpeg', (0, 2), 1, consume)
    by_id = {e['id'] if e['kind'] == 'video_pair' else e['block']['id']: e for e in events}
    for expected in baseline['events']:
        row = json.loads(json.dumps(expected))
        event = by_id[row.get('id', row.get('block', {}).get('id'))]
        assert Fraction(**event['source_time']) == Fraction(**baseline['origin']) + Fraction(**row.pop('at'))
        actual = dict(event)
        actual.pop('source_time')
        if row['kind'] == 'audio_block':
            row['block'].pop('decoded_monotonic_ns')
            row['block'].pop('packet_index')
        assert actual == row
    assert result['status'] == 'completed'
    assert result['common_origin'] == baseline['origin']
    assert result['pending_pixel_bytes'] == 0 and result['pending_audio'] is None
    assert result['peak_pending_pixel_bytes'] <= 16 * 64 * 48 * 3 // 2
    assert result['video_pairs_consumed'] == baseline['summary']['video_pairs']
    assert result['audio_blocks_consumed'] == baseline['summary']['audio_blocks']
    assert result['source_sha256'] == baseline['source_sha256']


def test_cli_failure_receipt_is_exclusive_and_no_completed_claim(tmp_path):
    receipt = tmp_path / 'result.json'
    command = [sys.executable, str(SCRIPT), str(tmp_path / 'absent'), '--container', 'mpeg',
               '--primary-stream', '0', '--secondary-stream', '1', '--audio-stream', '2',
               '--pairing', 'exact-pts', '--receipt', str(receipt)]
    completed = subprocess.run(command, capture_output=True, timeout=10, check=False)
    assert completed.returncode == 2 and not completed.stdout
    original = receipt.read_bytes()
    assert json.loads(original)['status'] == 'failed'
    completed = subprocess.run(command, capture_output=True, timeout=10, check=False)
    message = b'receipt failed'
    assert completed.returncode == 2 and message in completed.stderr
    assert receipt.read_bytes() == original


def test_audio_offsets_overlap_equal_times_and_hashes_are_preserved_without_policy_repair():
    events = []
    session = M['Session']((0, 1), 2, lambda event, data: events.append((event, data)))
    pcm = bytes(2048)
    adapter = SimpleNamespace(convert=lambda row: (
        dict(id=row['id'], media_ms=row['source_pts'],
             pcm_s16le_b64=base64.b64encode(pcm).decode()), row))
    for index, pts in enumerate((900, 963, 963, 1028)):
        row = dict(id=f'aac:2:{index}', stream_index=2, source_pts=pts,
                   time_base_num=1, time_base_den=1000, decoded_monotonic_ns=10,
                   pcm_sha256=hashlib.sha256(pcm).hexdigest())
        session.audio(row, adapter)
    assert session.audio_count == 4 and session.audio_pending is None
    assert events[0][0]['source_time'] == dict(numerator=9, denominator=10)
    assert [event['gap_before'] for event, _ in events] == [None,
        dict(numerator=-1, denominator=1000), dict(numerator=-8, denominator=125),
        dict(numerator=1, denominator=1000)]
    assert all(data == (pcm,) for _, data in events)
    assert session.result()['common_origin'] is None  # Neither lens has arrived.


def test_audio_downstream_error_records_unacknowledged_block_and_accepted_prefix():
    def consume(event, _data):
        if event['block']['id'] == 'aac:2:1':
            raise TimeoutError('blocked sink')
    session = M['Session']((0, 1), 2, consume)
    pcm = bytes(2048)
    adapter = SimpleNamespace(convert=lambda row: (
        dict(id=row['id'], media_ms=row['source_pts'],
             pcm_s16le_b64=base64.b64encode(pcm).decode()), row))
    def row(index):
        return dict(id=f'aac:2:{index}', stream_index=2, source_pts=index * 64,
                    time_base_num=1, time_base_den=1000, decoded_monotonic_ns=0,
                    pcm_sha256=hashlib.sha256(pcm).hexdigest())
    session.audio(row(0), adapter)
    with pytest.raises(TimeoutError):
        session.audio(row(1), adapter)
    assert session.audio_count == 1
    assert session.result()['pending_audio']['block']['id'] == 'aac:2:1'
    assert session.previous_audio == 0


@pytest.mark.parametrize('limit', ['packets', 'time', 'frames'])
def test_work_limits_keep_failure_receipt_and_close_decoder(tmp_path, monkeypatch, limit):
    source = tmp_path / 'source'
    source.write_bytes(b'test')
    closed = fake_container(monkeypatch, packets=[packet(frames=[b'unused'])])
    key = {'packets': 'MAX_PACKETS', 'time': 'MAX_SECONDS', 'frames': 'MAX_FRAMES'}[limit]
    monkeypatch.setitem(M['VIDEO'], key, -1 if limit == 'time' else 0)
    receipt: dict[str, Any] = {}
    with pytest.raises(ValueError, match='limit'):
        M['inspect'](source, 'mpeg', (0, 1), 2, report=receipt)
    assert closed and receipt['status'] == 'failed'
    assert receipt['video_pairs_consumed'] == 0


def test_cancelled_callback_keeps_prefix_and_scoped_decoder_cleanup(tmp_path, monkeypatch):
    source = tmp_path / 'source'
    source.write_bytes(b'test')
    closed = fake_container(monkeypatch, packets=[packet(frames=[b'left']), packet(1, frames=[b'right'])])
    monkeypatch.setitem(M['VIDEO'], 'fingerprint', lambda _f, s, i: lens(s, i)[0])
    left = b'left'
    monkeypatch.setitem(M['PREVIEW'], 'pack', lambda frame: lens(0 if frame == left else 1)[1])
    def interrupt(_event, _data):
        raise KeyboardInterrupt
    receipt: dict[str, Any] = {}
    with pytest.raises(KeyboardInterrupt):
        M['inspect'](source, 'mpeg', (0, 1), 2, interrupt, receipt)
    assert receipt['status'] == 'cancelled' and closed
    assert receipt['pending_pixel_bytes'] == 24


def test_many_pairs_keep_constant_pending_ownership_not_a_recording_spool():
    buffer = M['PairBuffer']((0, 1))
    for index in range(1000):
        buffer.offer(*lens(0, index, pts=90000 + index))
        buffer.offer(*lens(1, index, pts=90000 + index))
        assert buffer.bytes == 0 and not any(buffer.pending.values())
    buffer.finish()
    assert buffer.pairs == 1000
    assert buffer.peak_frames == 2 and buffer.peak_bytes == 24
    assert len(buffer.previous) == 2
    assert buffer.result()['pending_unpaired'] == []
