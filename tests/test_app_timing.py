"""Independent native oracles and framing/validation checks for opt-in timing."""
from dataclasses import replace
import importlib
import io
import json
from pathlib import Path

import pytest

from pyezvizapi import (
    AppPlaybackClock,
    AppTimedFrame,
    app_timed_mpegps_payloads,
    copy_app_timed_frames_to_mpegts,
)
from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.remux import ffmpeg_mpegts_command


def frame(source_ms=0, **kwargs):
    return AppTimedFrame(0xC0, 'audio', source_ms, 64, b'payload', **kwargs)


def test_payload_free_native_seek_oracle():
    oracle = json.loads((Path(__file__).parent / 'fixtures/app_timing_oracle.json').read_text())
    checks = 0
    for group in oracle['groups']:
        audio = group['kind'] == 'audio'
        clock = AppPlaybackClock()
        clock.timestamp_ms(AppTimedFrame(0xC0 if audio else 0xE0, 'track', 0, 64 if audio else 66, b'x', None if audio else 0))
        for row in group['rows']:
            source, duration, limit, expected = row[:4]
            clock.max_interval_ms = limit
            current = AppTimedFrame(0xC0 if audio else row[5], 'track', source, duration, b'x', None if audio else row[4])
            assert clock.timestamp_ms(current) == expected
            checks += 1
    assert checks == 4173


@pytest.mark.parametrize('mode,limit', [('live',17000), ('playback',1500)])
def test_exact_threshold_and_excess(mode, limit):
    clock = AppPlaybackClock(mode=mode)
    assert clock.timestamp_ms(frame(100000)) == 0
    assert clock.timestamp_ms(frame(100000 + limit)) == limit
    assert clock.timestamp_ms(frame(100001 + 2*limit)) == limit + 64
    assert clock.timestamp_ms(frame(100000)) == limit + 128


def test_ordinary_gaps_and_record_boundaries_preserve_session():
    clock = AppPlaybackClock()
    assert clock.timestamp_ms(frame(99999)) == 0
    assert clock.timestamp_ms(frame(100127)) == 128
    assert clock.timestamp_ms(frame(100127)) == 128
    payloads = list(app_timed_mpegps_payloads([frame(100255)], clock=clock))
    assert payloads
    assert clock.timestamp_ms(frame(100383)) == 384
    clock.reset()
    assert clock.timestamp_ms(frame(100383)) == 0


def test_paired_lenses_use_source_picture_identity_not_output_time():
    clock = AppPlaybackClock(max_interval_ms=1500)
    first = AppTimedFrame(0xE0, 'paired', 100000, 66, b'hevc', 10)
    assert clock.timestamp_ms(first) == 0
    assert clock.timestamp_ms(replace(first, stream_id=0xE1)) == 0
    assert clock.timestamp_ms(replace(first, source_ms=99999, picture_id=11)) == 66
    assert clock.timestamp_ms(replace(first, stream_id=0xE1, source_ms=99999, picture_id=11)) == 66
    assert clock.timestamp_ms(replace(first, clock_id='different_camera')) == 0


def test_large_access_unit_continuations_share_timestamp():
    current = AppTimedFrame(0xE0, 'video', 1000, 66, b'x'*120001, 1)
    parts = list(app_timed_mpegps_payloads([current], clock=AppPlaybackClock(), audio_stream_id=None))
    assert len(parts) == 3
    pes_start = b'\x00\x00\x01\xe0'
    assert all(pes_start in p for p in parts)
    assert sum(len(p[p.index(b'\x00\x00\x01\xe0')+14:]) for p in parts) == 120001


@pytest.mark.parametrize('changes', [
    {'source_ms':True}, {'source_ms':-1}, {'duration_ms':0}, {'duration_ms':True},
    {'stream_id':0xBD}, {'clock_id':''}, {'data':b''}, {'picture_id':4},
])
def test_invalid_frame_rejected(changes):
    with pytest.raises(PyEzvizError):
        AppPlaybackClock().timestamp_ms(replace(frame(), **changes))


@pytest.mark.parametrize('kwargs', [{'mode':'other'}, {'max_interval_ms':True}, {'max_interval_ms':0}])
def test_invalid_clock_configuration(kwargs):
    with pytest.raises(PyEzvizError):
        AppPlaybackClock(**kwargs)


def test_clock_kind_collision_rejected():
    clock = AppPlaybackClock()
    clock.timestamp_ms(frame())
    with pytest.raises(PyEzvizError):
        clock.timestamp_ms(AppTimedFrame(0xE0, 'audio', 0, 66, b'x', 1))


def test_empty_and_undeclared_stream_fail_before_ffmpeg():
    with pytest.raises(PyEzvizError):
        copy_app_timed_frames_to_mpegts([], io.BytesIO(), clock=AppPlaybackClock(), ffmpeg_path='nonexistent')
    with pytest.raises(PyEzvizError):
        list(app_timed_mpegps_payloads([frame()], clock=AppPlaybackClock(), audio_stream_id=None))


def test_invalid_updated_limit_and_stream_maps():
    clock = AppPlaybackClock()
    with pytest.raises(PyEzvizError):
        clock.max_interval_ms = 0
    for video_ids, audio_id in [((0xE0,0xE0),0xC0), ((),0xC0), ((0xE0,),0xBD)]:
        with pytest.raises(PyEzvizError):
            list(app_timed_mpegps_payloads([frame()], clock=clock, video_stream_ids=video_ids, audio_stream_id=audio_id))
    with pytest.raises(PyEzvizError):
        clock.timestamp_ms(AppTimedFrame(0xE0,'video',0,66,b'x',-1))


def test_map_all_streams_is_explicit_and_single_input():
    command = ffmpeg_mpegts_command('ffmpeg', map_all_streams=True)
    assert command[command.index('-map')+1] == '0'
    assert '-map' not in ffmpeg_mpegts_command('ffmpeg')
    preserved = ffmpeg_mpegts_command('ffmpeg', map_all_streams=True, preserve_timestamps=True)
    assert preserved[preserved.index('-mpegts_copyts')+1] == '1'
    with pytest.raises(PyEzvizError):
        ffmpeg_mpegts_command('ffmpeg', map_all_streams=True, audio_path='audio.aac')


def test_stream_copy_helper_wires_explicit_clock_and_all_tracks(monkeypatch):
    module = importlib.import_module('pyezvizapi.app_timing')
    sentinel = object()
    calls = []
    payload = b'payload'
    transport = b'transport'

    def open_process(path, **kwargs):
        calls.append((path,kwargs))
        return sentinel

    def copy_output(process, output, *, write_input):
        assert process is sentinel
        source = io.BytesIO()
        write_input(source)
        assert payload in source.getvalue()
        output.write(transport)

    monkeypatch.setattr(module,'open_mpegts_remux_process',open_process)
    monkeypatch.setattr(module,'copy_remuxed_output',copy_output)
    sink = io.BytesIO()
    copy_app_timed_frames_to_mpegts([frame()],sink,clock=AppPlaybackClock())
    assert sink.getvalue() == transport
    assert calls[0][1]['preserve_timestamps'] is True
    assert calls[0][1]['map_all_streams'] is True


def test_clip_warmup_must_advance_state_not_just_supply_origin():
    clock = AppPlaybackClock(mode='playback')
    clock.timestamp_ms(frame(100000))
    assert clock.timestamp_ms(frame(104032)) == 64
    clock.reset()
    for offset in range(0,4032,64):
        clock.timestamp_ms(frame(100000+offset))
    assert clock.timestamp_ms(frame(104032)) == 4032


def test_original_arm_boundary_oracle():
    cases = json.loads((Path(__file__).parent/'fixtures/app_timing_boundaries.json').read_text())
    for case in cases:
        audio = case['kind'] == 8193
        clock = AppPlaybackClock(max_interval_ms=case['threshold_ms'])
        duration = case['audio_frame_ms'] if audio else int(1000/case['frame_rate'])
        current = AppTimedFrame(0xC0 if audio else 0xE0,'track',0,duration,b'x',None if audio else 0)
        clock.timestamp_ms(current)
        current = replace(current,source_ms=case['previous_ms'],picture_id=None if audio else 1)
        clock.timestamp_ms(current)
        current = replace(current,source_ms=case['incoming_ms'],picture_id=None if audio else 1 if case['same_picture'] else 2)
        assert clock.timestamp_ms(current) == case['outgoing_ms']
