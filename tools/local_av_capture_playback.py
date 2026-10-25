"""Bounded guarded-capture prefix output; no client creation or source discovery."""
from __future__ import annotations

from copy import copy
import math
from pathlib import Path
import runpy
from threading import Event
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
            or receipt.get('profile') not in ('bounded-prepared-host-submissions-v1', 'bounded-prepared-tail-host-submissions-v1')
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
    if receipt.get('profile') == 'bounded-prepared-tail-host-submissions-v1' or 'action_audit' in scheduler:
        audit = scheduler.get('action_audit') or {}
        timing = lookahead.get('preparation_audit') or {}
        if (audit.get('profile') != 'bounded-finalized-json-v1'
                or timing.get('profile') != 'bounded-finalized-json-v1'
                or audit.get('submitted') != expected or audit.get('completed') != expected
                or audit.get('failed') != dict(video_pair=0, audio_block=0)
                or audit.get('error_count') != 0 or timing.get('error_count') != 0
                or audit.get('complete_finalization') is not True or audit.get('pending_count') != 0
                or audit.get('finalized_records') != sum(expected.values())
                or timing.get('finalized_records') != sum(expected.values())):
            raise ValueError('bounded diagnostics terminal counts failed')
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


class CapturePlayback:
    """Explicit single-use capture session retaining its pull after join failure.

    Construction validates before claiming the supplied pristine capture, starts
    an idle worker but performs no acquisition. Call play once or close explicitly.
    Only the worker closes the preparation iterator; owner.close interrupts active
    transport IO. That hook must be thread-safe and promptly returning, as for
    AutoMediaStream.close. A join timeout does not release this session: retain it
    and call close again once the read/finalizer can finish. No replacement worker
    or concurrent generator close is safe.
    """

    def __init__(self, owner: Any, key: str | bytes, args: Any, report: dict[str, Any], *,
            limits: CaptureLimits, completion: str = 'reject', codec: str = 'auto',
            monotonic: Any = time.monotonic, pes_ids: tuple[int, int, int] | None = None,
            diagnostic_tail: int | None = None) -> None:
        self.args = copy(args)
        self.report = report
        self.used = False
        self._stop = Event()
        self.diagnostic_tail = diagnostic_tail
        preparation: dict[str, Any] = {}
        output: dict[str, Any] = {}
        report.update(profile='guarded-capture-pending-host-submissions-v1' if diagnostic_tail is None
            else 'guarded-capture-pending-tail-host-submissions-v1', status='failed', error_type=None,
            preparation=preparation, output=output, cleanup_error_types=[], source_pull=None, stop_requested=False,
            accepted_prefix_clear_sha256=None, completion_policy=completion,
            input_scope='accepted-capture-prefix', whole_source_complete=False, network_eof_verified=False,
            whole_source_preflight=False, physical_av_sync_measured=False,
            pipe_completion_is_audible=False, present_return_is_physical_display=False,
            timing='common-host-submissions-not-device-clock-sync')
        try:
            OUTPUT['AUDIT']['validate_tail'](diagnostic_tail)
            validate_output(self.args)
            streams = (self.args.primary_stream, self.args.secondary_stream)
            PREPARE['ONLINE']['Policy'](streams, self.args.audio_stream, self.args.audio_overlap_policy,
                self.args.max_audio_overlap_ms, self.args.max_audio_phase_ms)
            PREPARE['CAPTURE']['validate_arguments'](owner, limits, completion, codec)
            if pes_ids is not None:
                PREPARE['CHUNKED']['TRACKS']['validate_pes_ids'](pes_ids)
            if not callable(getattr(owner, 'close', None)):
                raise ValueError('capture requires a thread-safe transport close hook')
            events = PREPARE['iter_capture_preparation'](owner, key, streams, self.args.audio_stream, preparation,
                limits=limits, completion=completion, codec=codec, policy=self.args.audio_overlap_policy,
                overlap_ms=self.args.max_audio_overlap_ms, phase_ms=self.args.max_audio_phase_ms,
                monotonic=monotonic, **({} if pes_ids is None else dict(pes_ids=pes_ids)))
            source = CaptureEvents(events, owner, preparation, report)
            self.pull = OUTPUT['PULL']['PreparedPull'](source, interrupt=owner.close)
        except BaseException as error:
            report['error_type'] = type(error).__name__
            raise
        report['status'] = 'ready'
        report['source_pull'] = self.pull.result()

    def request_stop(self) -> None:
        """Thread-safe request only; play's owner performs interrupt/join/cleanup.

        This never closes an executing iterator, waits for IO or changes a
        completed receipt. Stop is cooperative between existing bounded calls.
        """
        self._stop.set()

    def close(self, timeout: float | None = None) -> None:
        """Cancel/rejoin without ever closing the worker's executing generator."""
        self.used = True
        try:
            self.pull.close(self.args.deadline if timeout is None else timeout)
        except Exception as error:
            self.report.update(status='failed', error_type=type(error).__name__, accepted_prefix_clear_sha256=None)
            self.report['cleanup_error_types'].append(type(error).__name__)
            raise
        finally:
            self.report['source_pull'] = self.pull.result()
        if self.report['status'] == 'ready':
            self.report['status'] = 'consumer-closed'

    def play(self) -> None:
        """Run opt-in pending-input output, then require all terminal evidence."""
        if self.used:
            raise ValueError('capture playback session is single-use')
        self.used = True
        report = self.report
        primary = False
        report['status'] = 'running'
        report['output']['profile'] = 'bounded-prepared-host-submissions-v1'
        try:
            OUTPUT['play_prepared'](self.pull, self.args, report['output'], pending_input=True, stop=self._stop, diagnostic_tail=self.diagnostic_tail,
                title='Bounded capture prefix (host submissions; not device sync)')
        except BaseException as error:
            primary = True
            report.update(status='cancelled' if isinstance(error, (KeyboardInterrupt, OUTPUT['PlaybackStopped'])) else 'failed',
                error_type=type(error).__name__)
            raise
        finally:
            # Output normally closes the pull; an earlier setup failure may not.
            # Do not spend a second join budget here when output already tried.
            state = self.pull.result()
            if not state['consumer_closed']:
                primary_status, primary_type = report['status'], report['error_type']
                try:
                    self.close()
                except Exception:
                    if not primary:
                        raise
                    report.update(status=primary_status, error_type=primary_type)
            report['source_pull'] = self.pull.result()
            report['stop_requested'] = self._stop.is_set()
        try:
            state = report['source_pull']
            if (report['cleanup_error_types'] or state['worker_alive'] or not state['iterator_closed'] or not state['consumer_closed']
                    or not state['source_ended'] or state['outstanding'] or state['abandoned']
                    or state['source_error_type'] or state['close_error_type'] or state['interrupt_error_type']):
                raise ValueError('capture pull terminal checks failed')
            verify_output(report['preparation'], report['output'])
            OUTPUT['check_stop'](self._stop)
        except Exception as error:
            report.update(status='cancelled' if isinstance(error, OUTPUT['PlaybackStopped']) else 'failed',
                error_type=type(error).__name__, stop_requested=self._stop.is_set())
            raise
        report.update(status='prefix-output-completed',
            accepted_prefix_clear_sha256=report['preparation']['accepted_prefix_clear_sha256'])


class CaptureEvents:
    """Worker-owned lazy pipeline with explicit unstarted capture release."""

    def __init__(self, events: Any, owner: Any, preparation: dict[str, Any], report: dict[str, Any]) -> None:
        self.events, self.owner = events, owner
        self.preparation, self.report = preparation, report

    def __iter__(self) -> Any:
        return self

    def __next__(self) -> Any:
        return next(self.events)

    def close(self) -> None:
        owner = self.owner if not self.preparation else None
        error = PREPARE['close_pipeline']((self.events,), owner, self.report)
        if error is not None:
            raise error
        self.events = self.owner = None
