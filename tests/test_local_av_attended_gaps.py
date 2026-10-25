"""Named finite gap profile, explicit admission and full independent padding audit."""
from pathlib import Path
import runpy
from types import SimpleNamespace
from typing import Any

import pytest

ROOT = Path(__file__).parents[1]
P = runpy.run_path(str(ROOT / 'tools/local_av_lan_profiles.py'))
LAN = runpy.run_path(str(ROOT / 'tools/local_av_lan_playback.py'))
VERIFY = runpy.run_path(str(ROOT / 'tools/local_av_lan_verify.py'))
CAP = runpy.run_path(str(Path(__file__).with_name('test_local_av_capture_playback.py')))
ARGS = runpy.run_path(str(Path(__file__).with_name('test_local_av_lan_playback.py')))
NAME = 'two-minute-gaps'


def test_named_profile_is_fixed_finite_and_cannot_mutate_other_profiles():
    old = P['get']('two-minute')
    gap = P['get'](NAME)
    assert gap['limits'] == old['limits'] and gap['worker_seconds'] == old['worker_seconds']
    assert gap['evidence']['profile'] != old['evidence']['profile']
    limits = gap['options'].pop('gap_limits')
    assert gap['options'] == old['options']
    assert limits == dict(max_gap_blocks=1, max_total_gap_blocks=4, max_overlap_ms=1,
        max_phase_ms=1, max_blocks=3000, max_source_span_seconds=120)
    limits['max_gap_blocks'] = 4
    assert P['get'](NAME)['options']['gap_limits']['max_gap_blocks'] == 1
    assert 'gap_limits' not in P['get']()['options']


@pytest.mark.parametrize('changes', [dict(audio_overlap_policy='reject'), dict(max_audio_overlap_ms=None),
    dict(max_audio_phase_ms=2), dict(max_audio_overlap_ms=True)])
def test_profile_requires_matching_explicit_audio_policy_before_preflight_or_prompt(monkeypatch, tmp_path, changes):
    args = ARGS['args'](tmp_path / 'not-read', capture_profile=NAME,
        audio_overlap_policy='bounded-serial-pcm', max_audio_overlap_ms=1, max_audio_phase_ms=1)
    vars(args).update(changes)
    monkeypatch.setitem(LAN['RUNTIME'], 'run_worker', lambda *_args: pytest.fail('runtime started'))
    with pytest.raises(ValueError):
        LAN['attended'](args, {})


def test_parent_worker_command_preserves_explicit_gap_profile_and_policy(tmp_path):
    args = ARGS['args'](tmp_path / 'private', capture_profile=NAME,
        audio_overlap_policy='bounded-serial-pcm', max_audio_overlap_ms=1, max_audio_phase_ms=1)
    command = LAN['worker_command'](args, 'c' * 64, 'channels', tmp_path / 'receipt')
    assert command[command.index('--capture-profile') + 1] == NAME
    assert command[command.index('--audio-overlap-policy') + 1] == 'bounded-serial-pcm'


@pytest.fixture
def saved_gap(tmp_path, monkeypatch):
    rig = CAP['rig'].__wrapped__(tmp_path, monkeypatch)
    CAP['insert_gap'](monkeypatch)
    report: dict[str, Any] = {}
    owner, session = CAP['session'](rig, report, pes_ids=(224, 225, 192), **P['get'](NAME)['options'])
    session.play()
    assert owner.closed and report['status'] == 'prefix-output-completed'
    report['capture_profile'] = NAME
    report['requested_options'] = dict(P['get'](NAME)['options'], startup_pairing='strict')
    monkeypatch.setattr(VERIFY['DECRYPT']['Decryptor'], 'decode', lambda _self, chunk: chunk)
    # Same synthetic source hole at the independent decoder boundary, not a
    # padding receipt supplied to replay. All payloads remain original PCM.
    original = VERIFY['ONLINE']['CHUNKED']['iter_chunks']
    with monkeypatch.context() as patch:
        patch.setitem(CAP['PREP']['CHUNKED'], 'iter_chunks', original)
        CAP['insert_gap'](patch)
        mapped = CAP['PREP']['CHUNKED']['iter_chunks']
        monkeypatch.setitem(VERIFY['ONLINE']['CHUNKED'], 'iter_chunks', mapped)
    return report, rig[0]


@pytest.mark.parametrize('case', ['good', 'padding-hash', 'source-hash', 'padding-bytes', 'source-count',
    'missing-profile', 'changed-limits', 'origin'])
def test_complete_reconstruction_binds_separate_padding_and_original_media(saved_gap, case):
    pb, raw = saved_gap
    if case == 'padding-hash':
        pb['output']['gap_audio']['media_sha256']['padding'] = '0' * 64
    elif case == 'source-hash':
        pb['output']['gap_audio']['media_sha256']['source'] = '0' * 64
    elif case == 'padding-bytes':
        pb['output']['gap_audio']['api_bytes']['padding'] = 0
    elif case == 'source-count':
        pb['output']['gap_audio']['completed']['source'] -= 1
    elif case == 'missing-profile':
        del pb['capture_profile']
    elif case == 'changed-limits':
        pb['preparation']['audio_gap_limits']['max_gap_blocks'] = 2
    elif case == 'origin':
        pb['preparation']['online']['policy']['origin']['numerator'] += 1
    if case == 'good':
        assert VERIFY['reconstruct'](pb, raw, 'camera-key') == pb['output']['scheduler']['action_audit']['media_receipt']
    else:
        with pytest.raises(ValueError):
            VERIFY['reconstruct'](pb, raw, 'camera-key')


def test_evidence_requires_explicit_same_gap_profile(tmp_path):
    evidence = LAN['EVIDENCE']
    tmp_path.joinpath('packets').mkdir()
    writer = evidence['PacketEvidence'](tmp_path / 'packets', capture_profile=NAME)
    list(writer.retain(packet for packet in [SimpleNamespace(body=b'ciphertext')]))
    summary = writer.finish(dict(config_sha256='c' * 64, package_sha256='a' * 64))
    assert evidence['verify'](tmp_path / 'packets', capture_profile=NAME) == summary
    for other in ['prefix-30s', 'two-minute']:
        with pytest.raises(ValueError):
            evidence['verify'](tmp_path / 'packets', capture_profile=other)


@pytest.mark.parametrize('flag', [None, False, 1, 'true', True])
def test_isolated_worker_projection_requires_explicit_gap_verification(flag):
    old = runpy.run_path(str(Path(__file__).with_name('test_local_av_lan_verify.py')))
    report = old['successful_report'](old['replay'].__wrapped__())
    if flag is not None:
        report['gap_media_verified'] = flag
    if flag is True:
        assert VERIFY['worker_result'](report, capture_profile=NAME) == report
        with pytest.raises(ValueError):
            VERIFY['worker_result'](report)
    else:
        with pytest.raises(ValueError):
            VERIFY['worker_result'](report, capture_profile=NAME)
