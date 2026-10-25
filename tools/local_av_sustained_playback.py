"""Opt-in two-minute recorded playback control; never camera acquisition.

One persistent decoder, source origin and host anchor; constant-state identities,
two-row diagnostic tails and unchanged resident credits/deadlines. Linux only.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import runpy
import signal
import subprocess
import sys
import tempfile
import time
from typing import Any

BASE = Path(__file__).parent
OUTPUT = runpy.run_path(str(BASE / 'local_av_online_playback.py'))
ONLINE, PLAY = OUTPUT['ONLINE'], OUTPUT['PLAY']
LAN = runpy.run_path(str(BASE / 'local_av_lan_playback.py'))
SPAN = 120
PAIRS = 3000
BYTES = 128 * 1024 * 1024
WALL = 210
MAX_RECEIPT = 2 * 1024 * 1024


def validate(args: Any) -> None:
    OUTPUT['validate_output'](args)
    if (args.container != 'mpeg' or not sys.platform.startswith('linux')
            or re.fullmatch('[a-f0-9]{64}', args.expected_source_sha256) is None):
        raise ValueError('requires Linux, MPEG-PS and an approved recorded-source SHA-256')


def verify(report: dict[str, Any], expected: str) -> None:
    decode, policy, output = (report[name] for name in ('decode', 'policy', 'output'))
    reader = decode['input']
    state, scheduler, credit = policy['policy'], output['scheduler'], output['lookahead']
    pull = report['source_pull']
    counts = scheduler['completed']
    total = sum(counts.values())
    audit = scheduler['action_audit']
    media = audit['media_receipt']
    if (decode['status'] != 'completed' or policy['status'] != 'completed'
            or decode.get('source_sha256') != expected or reader['verified_source_end'] is not True
            or reader['total_byte_limit'] != BYTES or reader['received_bytes'] != reader['delivered_bytes']
            or not 0 < reader['received_bytes'] <= BYTES
            or state.get('source_span_limit_seconds') != SPAN or state.get('pair_limit') != PAIRS
            or output.get('source_span_limit_seconds') != SPAN
            or state['identity_audit']['retained_id_count'] != 0
            or scheduler['submitted'] != scheduler['completed']
            or scheduler['completed'] != state['identity_audit']['accepted']
            or not all(value > 0 for value in scheduler['completed'].values())
            or scheduler['outputs_finished'] is not True or scheduler['active'] or scheduler['failed']
            or scheduler['partial_audio_bytes'] or any(scheduler['not_submitted'].values())
            or credit['verified_prepared_source_end'] is not True
            or credit['owned_ids'] or credit['pending_preparation'] or credit['input_reservation']
            or any(credit['owned_bytes'].values()) or output['cleanup_errors']
            or decode['cleanup_errors'] or policy['cleanup_errors']
            or pull['worker_alive'] or not pull['iterator_closed'] or not pull['source_ended']
            or pull['outstanding'] or pull['abandoned'] or pull['read_active'] or pull['result_ready']
            or pull['requested'] != total + 1 or pull['yielded'] != total or pull['consumed'] != total
            or any(pull[field] is not None for field in ('source_error_type', 'interrupt_error_type', 'close_error_type'))
            or audit['complete_finalization'] is not True or audit['finalized_records'] != total
            or audit['pending_count'] or audit['error_count'] or audit['record_count_limit'] != 2
            or media['host_anchor_monotonic_ns'] != scheduler['host_anchor_monotonic_ns']
            or {track: row['completed'] for track, row in media['tracks'].items()} != counts):
        raise ValueError('sustained recorded terminal accounting failed')
    OUTPUT['CHANNEL']['verify_identity_audit'](output['video_identity_audit'], counts['video_pair'], PAIRS)


def playback(args: Any, report: dict[str, Any]) -> None:
    validate(args)  # Reject unsupported options before claiming a source iterator.
    decode: dict[str, Any] = {}
    policy: dict[str, Any] = {}
    selection: dict[str, Any] = {}
    chunks = ONLINE['CHUNKED']['file_chunks'](args.source, 32768)
    source = ONLINE['CHUNKED']['iter_chunks'](chunks, 'mpeg',
        (args.primary_stream, args.secondary_stream), args.audio_stream, decode,
        max_bytes=BYTES, startup='bounded-mpeg', deadline_mode='consumer-excluding',
        startup_pairing=args.startup_pairing, pes_ids=(0xE0, 0xE1, 0xC0), selection=selection)
    events = ONLINE['iter_online'](source, (args.primary_stream, args.secondary_stream),
        args.audio_stream, policy, policy=args.audio_overlap_policy,
        overlap_ms=args.max_audio_overlap_ms, phase_ms=args.max_audio_phase_ms,
        selection=selection, identity_mode='source-sequence', pair_limit=PAIRS, span_limit=SPAN)
    pull = None
    primary = False
    try:
        pull = OUTPUT['PULL']['PreparedPull'](events, interrupt=lambda: None)
        OUTPUT['play_prepared'](pull, args, report.setdefault('output', {}), pending_input=True,
            diagnostic_tail=2, video_identity_mode='source-sequence', pair_limit=PAIRS, span_limit=SPAN)
    except BaseException:
        primary = True
        raise
    finally:
        report.update(decode=decode, policy=policy)
        if pull is None:
            events.close()
            source.close()
            chunks.close()
        else:
            report['source_pull'] = pull.result()
            # The finite parent owns escalation if a native call cannot join.
            # Do not close a generator executing on the source owner thread.
            if report['source_pull']['worker_alive'] and not primary:
                raise ValueError('sustained recorded source worker is still owned')
    verify(report, args.expected_source_sha256)


class Resources:
    """Sampled, non-atomic process-tree RSS/FD totals, not allocation accounting."""

    def __init__(self) -> None:
        self.started = time.monotonic()
        self.windows: dict[str, dict[str, int]] = {}
        self.missed_process_samples = 0

    def sample(self, root: int) -> None:
        pending = [root]
        seen: set[int] = set()
        rss = descriptors = 0
        while pending:
            pid = pending.pop()
            if pid in seen:
                continue
            if len(seen) >= 16:
                raise ValueError('recorded playback process-tree bound exceeded')
            seen.add(pid)
            try:
                base = Path('/proc') / str(pid)
                resident = int((base / 'statm').read_text().split()[1]) * os.sysconf('SC_PAGE_SIZE')
                descriptors += len(list((base / 'fd').iterdir()))
                children = (base / 'task' / str(pid) / 'children').read_text().split()
                rss += resident
                pending.extend(int(child) for child in children)
            except (FileNotFoundError, ProcessLookupError):
                self.missed_process_samples += 1
        window = str(min(int((time.monotonic() - self.started) // 30), WALL // 30))
        row = self.windows.setdefault(window, dict(samples=0, peak_rss_bytes=0, peak_fd_count=0, peak_process_count=0))
        row['samples'] += 1
        for name, value in (('peak_rss_bytes', rss), ('peak_fd_count', descriptors), ('peak_process_count', len(seen))):
            row[name] = max(row[name], value)

    def result(self) -> dict[str, Any]:
        return dict(scope='sampled-parent-and-descendants-non-atomic-not-native-allocation-bound',
            interval_seconds=.25, window_seconds=30, windows=self.windows,
            missed_process_samples=self.missed_process_samples)


def worker(args: Any) -> int:
    report: dict[str, Any] = dict(profile='two-minute-recorded-host-submissions-v1', status='failed',
        network_acquisition=False, physical_av_sync_measured=False, whole_source_preflight=False,
        source_span_limit_seconds=SPAN, pair_limit=PAIRS, compressed_byte_limit=BYTES,
        expected_source_sha256=args.expected_source_sha256, received_signal=None)
    def stop(number: int, _frame: Any) -> None:
        report['received_signal'] = signal.Signals(number).name
        raise KeyboardInterrupt
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    code = 2
    try:
        playback(args, report)
        report['status'], code = 'completed', 0
    except KeyboardInterrupt:
        report['status'], code = 'cancelled', 130
    except Exception as error:
        report['error_type'] = type(error).__name__
    finally:
        if len(json.dumps(report).encode()) > MAX_RECEIPT:
            report = dict(status='failed', error_type='ReceiptBoundExceeded')
            code = 2
        with args.receipt.open('x') as output:
            json.dump(report, output)
            output.write('\n')
        if (report.get('source_pull') or {}).get('worker_alive'):
            # Flush a failure then let the parent reap the whole process group.
            sys.stdout.flush()
            os._exit(code or 2)
    return code


def worker_command(args: Any, receipt: Path) -> list[str]:
    native = [sys.executable, '-I', str(Path(__file__).resolve()), str(args.source), '--worker', '--play',
        '--receipt', str(receipt), '--expected-source-sha256', args.expected_source_sha256]
    for name in ('container', 'primary_stream', 'secondary_stream', 'audio_stream', 'pairing', 'timing',
                 'layout', 'processor', 'mono_option', 'video_transport', 'audio_overlap_policy',
                 'max_audio_overlap_ms', 'max_audio_phase_ms', 'deadline', 'max_late_ms', 'startup_pairing'):
        value = getattr(args, name)
        if value is not None:
            native.extend(('--' + name.replace('_', '-'), str(value)))
    return native


def supervise(args: Any, report: dict[str, Any]) -> int:  # noqa: PLR0912, PLR0915
    resources = Resources()
    child = None
    code = 2
    with tempfile.TemporaryDirectory(prefix='sustained-recorded-') as temporary:
        result = Path(temporary) / 'worker.json'
        try:
            child = subprocess.Popen(worker_command(args, result),
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=True)
            deadline = time.monotonic() + WALL
            while child.poll() is None:
                resources.sample(os.getpid())
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('recorded playback wall guard exceeded')
                try:
                    code = child.wait(timeout=min(.25, remaining))
                except subprocess.TimeoutExpired:
                    continue
            code = child.returncode
        except KeyboardInterrupt:
            code = 130
        except Exception as error:
            report['error_type'] = type(error).__name__
        finally:
            old_int = signal.signal(signal.SIGINT, signal.SIG_IGN)
            old_term = signal.signal(signal.SIGTERM, signal.SIG_IGN)
            try:
                if child is not None:
                    LAN['reap'](child)
                if result.exists():
                    report['playback'] = json.loads(LAN['read_regular'](result, MAX_RECEIPT))
                resources.sample(os.getpid())
            except Exception as error:
                report['cleanup_error_type'] = type(error).__name__
                if code == 0:
                    code = 2
            report['resources'] = resources.result()
            signal.signal(signal.SIGINT, old_int)
            signal.signal(signal.SIGTERM, old_term)
    if code == 0:
        playback_report = report.get('playback') or {}
        if playback_report.get('status') != 'completed':
            code = 2
        else:
            try:
                verify(playback_report, args.expected_source_sha256)
            except Exception as error:
                report['error_type'] = type(error).__name__
                code = 2
    report['status'] = 'completed' if code == 0 else 'cancelled' if code == 130 else 'failed'
    return code


def main() -> int:
    def configure(parser: Any) -> None:
        parser.add_argument('--expected-source-sha256', required=True)
        parser.add_argument('--startup-pairing', choices=['strict', 'common-keyframe'], default='strict')
        parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    args = PLAY['arguments'](configure)
    os.umask(0o077)
    validate(args)
    if args.worker:
        return worker(args)
    report: dict[str, Any] = dict(profile='supervised-two-minute-recorded-control-v1', status='failed',
        network_acquisition=False, physical_av_sync_measured=False, wall_seconds_limit=WALL)
    def stop(number: int, _frame: Any) -> None:
        report['received_signal'] = signal.Signals(number).name
        raise KeyboardInterrupt
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    with args.receipt.open('x') as output:
        code = supervise(args, report)
        json.dump(report, output, indent=2)
        output.write('\n')
    return code


if __name__ == '__main__':
    raise SystemExit(main())
