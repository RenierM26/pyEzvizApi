"""Synthetic decoded timing/format contracts; no media, PyAV or device required."""

from fractions import Fraction
import io
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest

SCRIPT = Path(__file__).parents[1] / 'tools/app_aac_decode.py'
MODULE = runpy.run_path(str(SCRIPT))
Adapter = MODULE['FrameAdapter']
Writer = MODULE['JsonlWriter']
SINK = runpy.run_path(str(SCRIPT.with_name('app_pcm_playback.py')))
pytestmark = pytest.mark.skipif(os.name != 'posix', reason='POSIX local decoder adapter')


def frame(pts=0, time_base=Fraction(1, 16000), **overrides):
    fields = dict(pts=pts, time_base=time_base, sample_rate=16000, samples=1024,
                  layout=SimpleNamespace(name='mono'), format=SimpleNamespace(name='s16'),
                  planes=[b'\x01\x00' * 1024 + b'padding'], is_corrupt=False)
    fields.update(overrides)
    return SimpleNamespace(**fields)


class Convert:
    def resample(self, source):
        return [] if source is None else [source]


def test_exact_pts_source_gaps_and_plane_padding_survive_conversion():
    adapter = Adapter(2, Convert())
    for i, pts in enumerate((1, 1025, 3073)):
        row, meta = adapter.convert(frame(pts))
        b = SINK['parse_block'](row)
        assert b.identity == f'aac:2:{i}'
        assert b.media_ms == pts * 1000 // 16000
        assert b.pcm == b'\x01\x00' * 1024
        assert meta['source_pts'] == pts and meta['time_base_den'] == 16000
        assert meta['decoded_monotonic_ns'] > 0
    assert adapter.previous == Fraction(3073, 16000)


@pytest.mark.parametrize('bad', [
    dict(pts=None), dict(pts=True), dict(pts=-1), dict(time_base=None),
    dict(time_base=Fraction(0)), dict(time_base=Fraction(-1)),
    dict(pts=2**32, time_base=Fraction(1, 1000)), dict(samples=512),
    dict(sample_rate=48000), dict(layout=SimpleNamespace(name='stereo')),
    dict(format=SimpleNamespace(name='s32')), dict(planes=[b'x']), dict(is_corrupt=True),
])
def test_unknown_timing_or_unsupported_decoded_frame_rejected(bad):
    with pytest.raises(ValueError):
        Adapter(0, Convert()).convert(frame(**bad))


def test_timing_regression_and_block_limit_are_not_repaired():
    adapter = Adapter(0, Convert())
    adapter.convert(frame(1024))
    with pytest.raises(ValueError, match='backward'):
        adapter.convert(frame(0))
    assert adapter.count == 1
    adapter.count = 10_000
    with pytest.raises(ValueError, match='limit'):
        adapter.convert(frame(2048))


@pytest.mark.parametrize('outputs', [[], [frame(), frame()], [frame(1)],
                                     [frame(samples=512)]])
def test_resampling_delay_split_or_retiming_rejected(outputs):
    convert = SimpleNamespace(resample=lambda _: outputs)
    with pytest.raises(ValueError, match='conversion'):
        Adapter(0, convert).convert(frame())


def test_local_input_is_regular_bounded_and_does_not_open_a_fifo(tmp_path):
    empty = tmp_path / 'empty'
    empty.touch()
    with pytest.raises(ValueError, match='nonempty regular'):
        MODULE['open_source'](empty)
    fifo = tmp_path / 'fifo'
    os.mkfifo(fifo)
    with pytest.raises(ValueError, match='nonempty regular'):
        MODULE['open_source'](fifo)
    source = tmp_path / 'source'
    content = b'local'
    source.write_bytes(content)
    with MODULE['open_source'](source) as f:
        assert f.read() == content


def test_jsonl_writer_short_progress_and_stall_deadline(monkeypatch):
    output = bytearray()
    def write(fd, data):
        output.extend(data[:3])
        return len(data[:3])
    monkeypatch.setattr(MODULE['os'], 'write', write)
    writer = Writer(1)
    writer.write(dict(id='a'))
    assert json.loads(output) == dict(id='a')
    assert writer.emitted == 1 and writer.partial_bytes == 0
    clock = iter([0, 0, 6])
    monkeypatch.setattr(MODULE['time'], 'monotonic', lambda: next(clock))
    def block(fd, data):
        raise BlockingIOError
    monkeypatch.setattr(MODULE['os'], 'write', block)
    monkeypatch.setattr(MODULE['select'], 'select', lambda *args: None)
    with pytest.raises(ValueError, match='deadline'):
        writer.write(dict(id='b'))
    assert writer.emitted == 1


def test_existing_manifest_is_not_overwritten_and_source_failure_is_reported(tmp_path):
    source = tmp_path / 'absent'
    manifest = tmp_path / 'manifest'
    manifest.write_text('keep')
    command = [sys.executable, str(SCRIPT), str(source), '--container', 'mpegts',
               '--audio-stream', '0', '--manifest', str(manifest)]
    p = subprocess.run(command, capture_output=True, check=False, timeout=5)
    assert p.returncode == 2 and not p.stdout
    assert manifest.read_text() == 'keep'
    command[-1] = str(tmp_path / 'new-manifest')
    p = subprocess.run(command, capture_output=True, check=False, timeout=5)
    assert p.returncode == 2 and not p.stdout
    summary = json.loads(Path(command[-1]).read_text())
    assert summary['status'] == 'failed' and summary['emitted_blocks'] == 0
    assert summary['arrival_source'] == 'host-decode-not-native-arrival'
    assert not summary['physical_lip_sync_measured']


def test_decode_records_prefix_before_later_bad_frame(monkeypatch):
    good, bad = frame(), frame(pts=None)
    codec = SimpleNamespace(name='aac', profile='LC', sample_rate=16000,
                            layout=SimpleNamespace(name='mono'))
    stream = SimpleNamespace(index=2, type='audio', codec_context=codec)
    packet = SimpleNamespace(is_corrupt=False, decode=lambda: [good, bad],
                             pts=0, dts=0, time_base=Fraction(1, 16000), size=128,
                             iter_sidedata=lambda: [])
    class Container:
        def __init__(self):
            self.streams = [stream]
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def demux(self, selected):
            assert selected is stream
            yield packet
    module = SimpleNamespace(__version__='test', library_versions={},
                             open=lambda *args, **kwargs: Container(),
                             AudioResampler=lambda **kwargs: Convert())
    monkeypatch.setitem(MODULE['decode'].__globals__, 'load_av', lambda: module)
    emitted: list[dict[str, object]] = []
    writer = SimpleNamespace(write=emitted.append)
    manifest = io.StringIO()
    with pytest.raises(ValueError, match='PTS'):
        MODULE['decode'](io.BytesIO(), 'mpegts', 2, writer, manifest)
    assert len(emitted) == 1
    entries = [json.loads(s) for s in manifest.getvalue().splitlines()]
    assert [r['kind'] for r in entries] == ['decoder', 'packet', 'decoded', 'emitted']
    assert entries[2]['id'] == emitted[0]['id'] == 'aac:2:0'



def test_priming_skip_is_explicit_even_when_packet_decodes_no_frame():
    class Side(bytes):
        data_type = 'skip_samples'
    side = Side(bytes.fromhex('00040000000000000000'))
    packet = SimpleNamespace(pts=-64, dts=-64, time_base=Fraction(1, 1000),
                             size=200, iter_sidedata=lambda: [side])
    metadata = MODULE['packet_metadata'](packet, 0, 0)
    assert metadata['pts'] == -64 and metadata['decoded_frames'] == 0
    assert metadata['side_data'][0]['skip_start_samples'] == 1024
    assert metadata['side_data'][0]['skip_end_samples'] == 0
    packet.iter_sidedata = lambda: [Side(b'bad')]
    with pytest.raises(ValueError, match='skip_samples'):
        MODULE['packet_metadata'](packet, 0, 0)


@pytest.mark.parametrize('change', ['codec', 'profile', 'rate', 'layout', 'index',
                                    'packet_corrupt', 'packet_size', 'empty'])
def test_decoder_rejects_unsupported_track_and_packet_contract(monkeypatch, change):
    codec = SimpleNamespace(name='aac', profile='LC', sample_rate=16000,
                            layout=SimpleNamespace(name='mono'))
    stream = SimpleNamespace(index=0, type='audio', codec_context=codec)
    packet = SimpleNamespace(size=128, is_corrupt=False, pts=0, dts=0,
                             time_base=Fraction(1, 16000), iter_sidedata=lambda: [],
                             decode=lambda: [frame()])
    if change == 'codec':
        codec.name = 'mp3'
    elif change == 'profile':
        codec.profile = 'HE-AAC'
    elif change == 'rate':
        codec.sample_rate = 48000
    elif change == 'layout':
        codec.layout.name = 'stereo'
    elif change == 'index':
        stream.index = 1
    elif change == 'packet_corrupt':
        packet.is_corrupt = True
    elif change == 'packet_size':
        packet.size = 8193
    else:
        packet.decode = lambda: []
    class Container:
        def __init__(self):
            self.streams = [stream]
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def demux(self, selected):
            yield packet
    av = SimpleNamespace(__version__='test', library_versions={},
                         open=lambda *args, **kwargs: Container(),
                         AudioResampler=lambda **kwargs: Convert())
    monkeypatch.setitem(MODULE['decode'].__globals__, 'load_av', lambda: av)
    with pytest.raises(ValueError):
        MODULE['decode'](io.BytesIO(), 'mpegts', 0, SimpleNamespace(write=lambda row: None),
                         io.StringIO())


def test_optional_real_aac_container_to_sink_contract(tmp_path):
    pytest.importorskip('av')
    if not shutil.which('ffmpeg'):
        pytest.skip('optional FFmpeg synthetic fixture generator is unavailable')
    source = tmp_path / 'synthetic.mkv'
    subprocess.run(['ffmpeg', '-v', 'error', '-f', 'lavfi', '-i',
                    'sine=frequency=440:sample_rate=16000:duration=1', '-ac', '1',
                    '-c:a', 'aac', str(source)], check=True, capture_output=True, timeout=10)
    manifest = tmp_path / 'manifest'
    p = subprocess.run([sys.executable, str(SCRIPT), str(source), '--container', 'matroska',
                        '--audio-stream', '0', '--manifest', str(manifest)],
                       check=False, capture_output=True, timeout=10)
    assert p.returncode == 0, p.stderr.decode()
    rows = [json.loads(line) for line in p.stdout.splitlines()]
    records = [json.loads(line) for line in manifest.read_text().splitlines()]
    assert records[-1]['status'] == 'completed'
    assert len(rows) == records[-1]['emitted_blocks'] > 0
    decoded = [r for r in records if r['kind'] == 'decoded']
    assert [r['id'] for r in rows] == [r['id'] for r in decoded]
    for row, metadata in zip(rows, decoded, strict=True):
        parsed = SINK['parse_block'](row)
        assert len(parsed.pcm) == 2048
        exact_ms = metadata['source_pts'] * Fraction(metadata['time_base_num'],
                                                    metadata['time_base_den']) * 1000
        assert parsed.media_ms == exact_ms.numerator // exact_ms.denominator
