"""Bounded guarded-capture prefix output; no client creation or source discovery."""
from __future__ import annotations

import math
from pathlib import Path
import runpy
import time
from typing import Any

from pyezvizapi.media import CaptureLimits

BASE = Path(__file__).parent
PREPARE = runpy.run_path(str(BASE / 'local_av_capture_preparation.py'))
OUTPUT = runpy.run_path(str(BASE / 'local_av_online_playback.py'))


def validate_output(args: Any) -> None:
    """Require explicit unchanged output mode and bounded scheduling options."""
    OUTPUT['validate_output'](args)
    if (args.play is not True or args.pairing != 'exact-pts' or args.timing != 'host-submission'
            or args.layout != 'side-by-side' or args.processor != 'passthrough'
            or args.mono_option not in ('channels', 'ch-layout')
            or isinstance(args.deadline, bool) or not isinstance(args.deadline, int | float)
            or not math.isfinite(args.deadline) or not OUTPUT['PLAY']['MIN_DEADLINE'] <= args.deadline <= 30
            or type(args.max_late_ms) is not int or not 0 <= args.max_late_ms <= 250):
        raise ValueError('capture output requires explicit supported mode, finite deadline and at most 250 ms lateness')


def verify_output(preparation: dict[str, Any], receipt: dict[str, Any]) -> None:
    """Require upstream verdict, every accepted host call and both drains."""
    scheduler = receipt.get('scheduler') or {}
    lookahead = receipt.get('lookahead') or {}
    prepared = preparation.get('decode', {}).get('preparation', {})
    expected = dict(video_pair=prepared.get('video_pairs_consumed'), audio_block=prepared.get('audio_blocks_consumed'))
    if (preparation.get('profile') != 'guarded-capture-online-preparation-v1'
            or preparation.get('status') != 'prepared-prefix-ended'
            or preparation.get('accepted_prefix_clear_sha256') is None
            or receipt.get('profile') != 'bounded-prepared-host-submissions-v1'
            or receipt.get('cleanup_errors') != [] or receipt.get('shutdown_output_error')
            or scheduler.get('outputs_finished') is not True
            or scheduler.get('submitted') != expected or scheduler.get('completed') != expected
            or scheduler.get('active') != {} or scheduler.get('failed') != {}
            or scheduler.get('partial_audio_bytes') != 0
            or scheduler.get('not_submitted') != dict(video_pair=[], audio_block=[])
            or lookahead.get('verified_prepared_source_end') is not True
            or lookahead.get('offered') != expected
            or lookahead.get('owned_ids') != [] or lookahead.get('pending_preparation') != []
            or lookahead.get('queued') != dict(video_pair=[], audio_block=[])
            or lookahead.get('owned_counts') != dict(video_pair=0, audio_block=0)
            or lookahead.get('owned_bytes') != dict(video_pair=0, audio_block=0)):
        raise ValueError('capture prefix output terminal checks failed')
    PREPARE['verify_completion'](preparation['capture'], preparation['decode'], preparation['online'])


def capture_playback(owner: Any, key: str | bytes, args: Any, report: dict[str, Any], *,
        limits: CaptureLimits, completion: str = 'reject', codec: str = 'auto',
        monotonic: Any = time.monotonic, pes_ids: tuple[int, int, int] | None = None) -> None:
    """Own a validated pristine capture; output only its explicitly accepted prefix.

    May acquire a real supplied owner and open output devices when called. This
    is not whole-source preflight: later source/policy failures abort an already
    displayed prefix. Credentials, owner selection and interrupts remain caller
    responsibilities. Completion is host-call/drain evidence, not physical sync.
    """
    preparation: dict[str, Any] = {}
    output: dict[str, Any] = {}
    report.update(profile='guarded-capture-prefix-host-submissions-v1', status='failed', error_type=None,
        preparation=preparation, output=output, cleanup_error_types=[],
        accepted_prefix_clear_sha256=None, completion_policy=completion,
        input_scope='accepted-capture-prefix', whole_source_complete=False, network_eof_verified=False,
        whole_source_preflight=False, physical_av_sync_measured=False,
        pipe_completion_is_audible=False, present_return_is_physical_display=False,
        timing='common-host-submissions-not-device-clock-sync')
    events = None
    claimed = primary = False
    try:
        validate_output(args)
        streams = (args.primary_stream, args.secondary_stream)
        PREPARE['ONLINE']['Policy'](streams, args.audio_stream, args.audio_overlap_policy,
            args.max_audio_overlap_ms, args.max_audio_phase_ms)
        PREPARE['CAPTURE']['validate_arguments'](owner, limits, completion, codec)
        if pes_ids is not None:
            PREPARE['CHUNKED']['TRACKS']['validate_pes_ids'](pes_ids)
        claimed = True
        events = PREPARE['iter_capture_preparation'](owner, key, streams, args.audio_stream, preparation,
            limits=limits, completion=completion, codec=codec, policy=args.audio_overlap_policy,
            overlap_ms=args.max_audio_overlap_ms, phase_ms=args.max_audio_phase_ms, monotonic=monotonic,
            **({} if pes_ids is None else dict(pes_ids=pes_ids)))
        output['profile'] = 'bounded-prepared-host-submissions-v1'
        report['status'] = 'running'
        OUTPUT['play_prepared'](events, args, output, title='Bounded capture prefix (host submissions; not device sync)')
    except BaseException as error:
        primary = True
        report.update(status='cancelled' if isinstance(error, KeyboardInterrupt) else 'failed', error_type=type(error).__name__)
        raise
    finally:
        unstarted_owner = owner if claimed and not preparation else None
        cleanup_error = PREPARE['close_pipeline']((events,), unstarted_owner, report)
        if cleanup_error is not None:
            report['status'] = 'failed'
            if not primary:
                report['error_type'] = type(cleanup_error).__name__
                raise cleanup_error
    try:
        verify_output(preparation, output)
    except Exception as error:
        report.update(status='failed', error_type=type(error).__name__)
        raise
    report.update(status='prefix-output-completed',
        accepted_prefix_clear_sha256=preparation['accepted_prefix_clear_sha256'])
