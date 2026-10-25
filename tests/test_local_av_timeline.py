"""Standalone source-clock contracts; no proprietary fixtures or device access."""

from fractions import Fraction
import hashlib
import io
import json
from pathlib import Path
import runpy
import shutil
import subprocess
import sys

import pytest

from pyezvizapi.rtp_timing import _mpeg_crc32, _pack_header, _pes

SCRIPT = Path(__file__).parents[1] / 'tools/local_av_timeline.py'
M = runpy.run_path(str(SCRIPT))


def picture(stream, index, pts, num=1, den=90000, width=64):
    return dict(decoded_id=f'video:{stream}:{index}', stream_index=stream,
                source_pts=pts, time_base_num=num, time_base_den=den,
                width=width, height=48, pixel_sha256='a' * 64)


def audio(index, pts, num=1, den=90000):
    return dict(id=f'aac:2:{index}', source_pts=pts, time_base_num=num,
                time_base_den=den, samples=1024, pcm_sha256='b' * 64)


def video(*frames):
    return dict(primary_stream=0, secondary_stream=1, decoded_frames=list(frames))


def rational(row):
    return Fraction(row['numerator'], row['denominator'])


def test_one_common_origin_keeps_original_intertrack_offset_and_forward_gaps():
    start = 6300672604
    result = M['plan'](video(picture(0, 0, start), picture(0, 1, start + 18000),
                             picture(1, 0, start), picture(1, 1, start + 18000)),
                        [audio(0, start + 15332), audio(1, start + 15332 + 11520)])
    assert rational(result['origin']) == Fraction(start, 90000)
    events = result['events']
    assert [e['kind'] for e in events] == ['video_pair', 'audio_block', 'video_pair', 'audio_block']
    assert rational(events[1]['at']) == Fraction(15332, 90000)
    assert rational(events[2]['at']) == Fraction(1, 5)
    assert rational(events[3]['gap_before']) == Fraction(64, 1000)
    assert result['summary'] == dict(video_pairs=2, audio_blocks=2, unpaired_pictures=0)
    assert not result['native_selections_used'] and not result['native_vqe_used']
    assert not result['output_devices_opened'] and not result['physical_av_sync_measured']


def test_exact_rational_equality_not_ticks_ordinals_or_rounded_milliseconds():
    result = M['plan'](video(picture(0, 0, 90001), picture(1, 0, 180002, den=180000),
                             picture(0, 1, 90002), picture(1, 1, 90003)), [audio(0, 90001)])
    assert result['summary']['video_pairs'] == 1
    assert [p['decoded_id'] for p in result['pending_unpaired']] == ['video:0:1', 'video:1:1']
    assert [e['kind'] for e in result['events']] == ['video_pair', 'audio_block']
    with pytest.raises(ValueError, match='no exact-PTS'):
        M['plan'](video(picture(0, 0, 90001), picture(1, 0, 90002)), [audio(0, 90000)])


def test_audio_before_video_equal_times_and_overlap_remain_explicit():
    result = M['plan'](video(picture(0, 0, 90000), picture(1, 0, 90000)),
                       [audio(0, 80000), audio(1, 80000), audio(2, 81000)])
    assert rational(result['origin']) == Fraction(8, 9)
    assert rational(result['events'][-1]['at']) == Fraction(1, 9)
    assert [e['block']['id'] for e in result['events'][:3]] == ['aac:2:0', 'aac:2:1', 'aac:2:2']
    assert rational(result['events'][1]['gap_before']) == -Fraction(64, 1000)


def test_pending_early_picture_stays_in_origin_and_geometry_changes_can_pair():
    v = video(picture(0, 0, 0), picture(0, 1, 1), picture(1, 0, 1),
              picture(0, 2, 2, width=32), picture(1, 1, 2, width=32))
    r = M['plan'](v, [audio(0, 1)])
    assert r['summary']['video_pairs'] == 2 and r['summary']['unpaired_pictures'] == 1
    assert rational(r['events'][0]['at']) == Fraction(1, 90000)
    v['decoded_frames'][-1]['width'] = 64
    with pytest.raises(ValueError, match='unequal geometry'):
        M['plan'](v, [audio(0, 1)])


@pytest.mark.parametrize('field,value', [('source_pts', None), ('source_pts', True),
    ('source_pts', -1), ('time_base_num', 0), ('time_base_den', -1),
    ('time_base_num', True), ('source_pts', 2**32 * 90)])
def test_malformed_source_time_rejected(field, value):
    row = picture(0, 0, 1)
    row[field] = value
    with pytest.raises(ValueError):
        M['exact'](row)


@pytest.mark.parametrize('change', ['duplicate-pts', 'backward-video', 'duplicate-id',
    'unknown-track', 'same-track', 'bool-track', 'empty-video', 'missing-lens',
    'empty-audio', 'backward-audio', 'duplicate-audio', 'samples', 'span'])
def test_ambiguous_or_unsupported_timelines_reject(change):
    v = video(picture(0, 0, 90000), picture(1, 0, 90000))
    a = [audio(0, 90000)]
    if change in ('duplicate-pts', 'backward-video'):
        v['decoded_frames'].append(picture(0, 1, 90000 if change == 'duplicate-pts' else 89999))
    elif change == 'duplicate-id':
        v['decoded_frames'].append(dict(v['decoded_frames'][0]))
    elif change == 'unknown-track':
        v['decoded_frames'][0]['stream_index'] = 3
    elif change == 'same-track':
        v['secondary_stream'] = 0
    elif change == 'bool-track':
        v['primary_stream'] = False
    elif change == 'empty-video':
        v['decoded_frames'] = []
    elif change == 'missing-lens':
        v['decoded_frames'].pop()
    elif change == 'empty-audio':
        a = []
    elif change == 'backward-audio':
        a.append(audio(1, 89999))
    elif change == 'duplicate-audio':
        a.append(dict(a[0]))
    elif change == 'samples':
        a[0]['samples'] = True
    else:
        a.append(audio(1, 90000 + 3601 * 90000))
    with pytest.raises(ValueError):
        M['plan'](v, a)


def test_pcm_observer_checks_payload_identity_and_emission_order():
    manifest = M['AudioMetadata']()
    inspector = M['AudioInspector'](manifest)
    row = dict(id='a', media_ms=0, pcm_s16le_b64='AA' + 'A' * 2729 + '=')
    with pytest.raises(ValueError, match='order'):
        inspector.write(row)
    record = dict(kind='decoded', id='a', media_ms=0,
                  pcm_sha256=hashlib.sha256(bytes(2048)).hexdigest())
    manifest.write(json.dumps(record))
    inspector.write(row)
    assert inspector.count == 1
    record['id'] = 'wrong'
    manifest.frames.append(record)
    with pytest.raises(ValueError, match='does not match'):
        inspector.write(row)


def test_cli_requires_explicit_policy_and_rejects_missing_input_without_success(tmp_path):
    command = [sys.executable, str(SCRIPT), str(tmp_path / 'absent'), '--container', 'mpegts',
               '--primary-stream', '0', '--secondary-stream', '1', '--audio-stream', '2']
    p = subprocess.run(command, capture_output=True, timeout=5, check=False)
    assert p.returncode == 2 and not p.stdout
    p = subprocess.run([*command, '--pairing', 'exact-pts', '--clock', 'container-pts'],
                       capture_output=True, timeout=5, check=False)
    assert p.returncode == 2 and not p.stdout
    message = b'timeline failed'
    assert message in p.stderr


def encode_three_track(tmp_path):
    pytest.importorskip('av')
    if not shutil.which('ffmpeg'):
        pytest.skip('optional synthetic fixture generator unavailable')
    source = tmp_path / 'three.ts'
    command = ['ffmpeg', '-v', 'error', '-f', 'lavfi', '-i',
               'color=size=64x48:rate=15:duration=0.6', '-f', 'lavfi', '-i',
               'color=color=red:size=64x48:rate=15:duration=0.6', '-itsoffset', '0.234355',
               '-f', 'lavfi', '-i', 'sine=sample_rate=16000:duration=0.2',
               '-map', '0:v', '-map', '1:v', '-map', '2:a', '-c:v', 'libx265',
               '-x265-params', 'pools=none:frame-threads=1:log-level=error',
               '-c:a', 'aac', '-ac', '1', '-pes_payload_size', '0', str(source)]
    subprocess.run(command, check=True, capture_output=True, timeout=15)
    return source


def test_optional_real_three_track_container_cli(tmp_path):
    source = encode_three_track(tmp_path)
    p = subprocess.run([sys.executable, str(SCRIPT), str(source), '--container', 'mpegts',
                        '--primary-stream', '0', '--secondary-stream', '1', '--audio-stream', '2',
                        '--pairing', 'exact-pts', '--clock', 'container-pts'],
                       capture_output=True, timeout=15, check=False)
    assert p.returncode == 0, p.stderr.decode()
    result = json.loads(p.stdout)
    assert result['source_sha256'] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert result['summary']['video_pairs'] > 1 and result['summary']['audio_blocks'] > 1
    assert result['summary']['unpaired_pictures'] == 0
    timestamps = [rational(e['at']) for e in result['events']]
    assert timestamps == sorted(timestamps)
    assert not result['output_devices_opened']
    pairs = [e for e in result['events'] if e['kind'] == 'video_pair']
    assert pairs[0]['lenses'][0]['pixel_sha256'] != pairs[0]['lenses'][1]['pixel_sha256']
    audio_events = [e for e in result['events'] if e['kind'] == 'audio_block']
    assert rational(audio_events[0]['at']) > 0



def test_inspection_uses_one_snapshot_even_when_original_changes(tmp_path, monkeypatch):
    source = tmp_path / 'source.ts'
    original = b'bounded original container'
    source.write_bytes(original)
    v = video(picture(0, 0, 90000), picture(1, 0, 90000))
    v.update(pyav_version='test', library_versions={})
    def decode_video(snapshot, container, streams):
        assert snapshot.read() == original and streams == (0, 1)
        source.write_bytes(b'changed after snapshot')
        return v
    def decode_audio(snapshot, container, stream, writer, manifest):
        assert snapshot.read() == original and stream == 2
        record = dict(audio(0, 90000), kind='decoded', media_ms=1000,
                      pcm_sha256=hashlib.sha256(bytes(2048)).hexdigest())
        manifest.write(json.dumps(dict(kind='decoder', pyav_version='test')))
        manifest.write(json.dumps(dict(kind='packet')))
        manifest.write(json.dumps(record))
        manifest.flush()
        writer.write(dict(id=record['id'], media_ms=1000, pcm_s16le_b64='A' * 2731 + '='))
        return 1
    monkeypatch.setitem(M['VIDEO'], 'decode', decode_video)
    monkeypatch.setitem(M['AUDIO'], 'decode', decode_audio)
    r = M['inspect'](source, 'mpegts', (0, 1), 2)
    assert r['source_bytes'] == len(original)
    assert r['source_sha256'] == hashlib.sha256(original).hexdigest()
    assert r['summary'] == dict(video_pairs=1, audio_blocks=1, unpaired_pictures=0)


@pytest.mark.parametrize('audio_stream', [0, 1, True, -1])
def test_conflicting_or_invalid_audio_track_rejected_before_read(audio_stream):
    with pytest.raises(ValueError, match='distinct'):
        M['inspect'](Path('does-not-exist'), 'mpegts', (0, 1), audio_stream)


def test_truncated_snapshot_and_incomplete_audio_fail_closed(tmp_path, monkeypatch):
    class Truncated(io.BytesIO):
        size = 10
    monkeypatch.setitem(M['AUDIO'], 'open_source', lambda path: Truncated(b'short'))
    with pytest.raises(ValueError, match='truncated'):
        M['inspect'](tmp_path / 'unused', 'mpegts', (0, 1), 2)
    Truncated.size = 5
    v = video(picture(0, 0, 1), picture(1, 0, 1))
    monkeypatch.setitem(M['VIDEO'], 'decode', lambda *args: v)
    monkeypatch.setitem(M['AUDIO'], 'decode', lambda *args: 1)
    with pytest.raises(ValueError, match='incomplete'):
        M['inspect'](tmp_path / 'unused', 'mpegts', (0, 1), 2)


def test_bounded_metadata_observer(monkeypatch):
    manifest = M['AudioMetadata']()
    monkeypatch.setitem(M['AUDIO'], 'MAX_BLOCKS', 0)
    with pytest.raises(ValueError, match='limit'):
        manifest.write(json.dumps(dict(kind='decoded')))


def encode_three_track_ps(tmp_path, audio_jitter=False, discovery_order=(0, 2, 1)):
    """Synthetic PS with original TS packet clocks and non-video-first indices."""
    av = pytest.importorskip('av')
    source = encode_three_track(tmp_path)
    with av.open(str(source)) as container:
        packets = [(p.stream.index, p.pts, p.dts, p.time_base, bytes(p))
                   for p in container.demux() if p.size and p.pts is not None]
    # Discover streams in E0, C0, E1 order: absolute indices are not lens ordinals.
    first = [next(i for i, p in enumerate(packets) if p[0] == stream) for stream in discovery_order]
    ordered = [packets[i] for i in first] + [p for i, p in enumerate(packets) if i not in first]
    entries = bytes.fromhex('24e000000fc0000024e10000')
    body = b'\xe0\xff\x00\x00' + len(entries).to_bytes(2, 'big') + entries
    header = b'\x00\x00\x01\xbc' + (len(body) + 4).to_bytes(2, 'big') + body
    mapping = header + _mpeg_crc32(header)
    output = bytearray()
    scr = 0
    audio_count = 0
    for index, pts, dts, base, payload in ordered:
        clock = Fraction(pts) * base * 90000
        decode = Fraction(dts if dts is not None else pts) * base * 90000
        if index == 2:
            if audio_jitter and audio_count == 1:
                clock -= 90
                decode -= 90
            audio_count += 1
        assert clock.denominator == decode.denominator == 1
        scr = max(scr, int(decode))
        sid = (0xE0, 0xE1, 0xC0)[index]
        row = _pes(int(clock), sid, payload)
        if decode != clock:
            pts_bytes = bytes([row[9] | 0x10]) + row[10:14]
            dts_row = _pes(int(decode), sid, b'')
            dts_bytes = bytes([dts_row[9] & ~0x20]) + dts_row[10:14]
            row = (row[:4] + (len(payload) + 13).to_bytes(2, 'big')
                   + b'\x80\xc0\x0a' + pts_bytes + dts_bytes + payload)
        output.extend(_pack_header(scr) + mapping + row)
    result = tmp_path / 'three.ps'
    result.write_bytes(output)
    return result


def test_clear_mpegps_preserves_both_lenses_audio_and_exact_source_clock(tmp_path):
    source = encode_three_track_ps(tmp_path)
    baseline = M['inspect'](tmp_path / 'three.ts', 'mpegts', (0, 1), 2)
    result = M['inspect'](source, 'mpeg', (0, 2), 1)
    assert result['summary'] == baseline['summary']
    assert result['origin'] == baseline['origin']
    assert result['source_sha256'] == hashlib.sha256(source.read_bytes()).hexdigest()
    for actual, expected in zip(result['events'], baseline['events'], strict=True):
        assert actual['kind'] == expected['kind'] and actual['at'] == expected['at']
        if actual['kind'] == 'video_pair':
            assert [p['pixel_sha256'] for p in actual['lenses']] == [p['pixel_sha256'] for p in expected['lenses']]
            assert [p['stream_index'] for p in actual['lenses']] == [0, 2]
        else:
            assert actual['block']['stream_index'] == 1
            for field in ('source_pts', 'time_base_num', 'time_base_den', 'samples', 'pcm_sha256'):
                assert actual['block'][field] == expected['block'][field]
            assert actual['gap_before'] == expected['gap_before']
    p = subprocess.run([sys.executable, str(SCRIPT), str(source), '--container', 'mpeg',
                        '--primary-stream', '0', '--secondary-stream', '2', '--audio-stream', '1',
                        '--pairing', 'exact-pts', '--clock', 'container-pts'],
                       capture_output=True, timeout=15, check=False)
    assert p.returncode == 0, p.stderr.decode()
    assert json.loads(p.stdout)['summary'] == result['summary']
