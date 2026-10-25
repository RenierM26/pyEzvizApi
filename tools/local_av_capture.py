"""Guard automatic capture exhaustion before decryption flush; no output devices.

The supplied pristine AutoMediaStream is owned once arguments are validated.
No transport is opened by importing this module or constructing a lazy owner.
"""
from __future__ import annotations

from contextlib import suppress
import math
from pathlib import Path
import runpy
import time
from typing import Any

from pyezvizapi.media import CaptureLimits

DECRYPT = runpy.run_path(str(Path(__file__).with_name('local_av_decrypted.py')))
LIMIT_REASONS = {'packet_limit', 'byte_limit', 'duration_limit'}


class CaptureEndRejected(ValueError):
    """A capture ended without permission to finish an accepted bounded prefix."""


def validate_arguments(owner: Any, limits: CaptureLimits, completion: str, codec: str, *, byte_limit: int = 16 * 1024 * 1024) -> None:
    DECRYPT['validate_byte_limit'](byte_limit)
    if completion not in ('reject', 'bounded-prefix') or codec not in ('auto', 'hevc'):
        raise ValueError('invalid capture completion policy or codec')
    if (not isinstance(limits, CaptureLimits)
            or type(limits.max_packets) is not int or not 0 < limits.max_packets <= DECRYPT['MAX_PACKETS']
            or type(limits.max_bytes) is not int or not 0 < limits.max_bytes <= byte_limit
            or isinstance(limits.duration_seconds, bool) or not isinstance(limits.duration_seconds, int | float)
            or not math.isfinite(limits.duration_seconds) or not 0 < limits.duration_seconds <= DECRYPT['MAX_SECONDS']):
        raise ValueError('capture requires explicit finite duration, packet and byte bounds within decryption caps')
    initial = owner.capture_result
    if (initial.get('profile') != 'automatic-media-capture-v1' or initial.get('status') != 'not_started'
            or initial.get('owner_closed') is not False or initial.get('transport_owned') is not False
            or initial.get('transport_attempts') != 0):
        raise ValueError('capture requires a pristine automatic stream owner')


class Bodies:
    """Owned packet iterator; return EOF only after the declared end policy passes."""

    def __init__(self, owner: Any, limits: CaptureLimits, completion: str, report: dict[str, Any], clock: Any) -> None:
        self.owner, self.limits, self.completion, self.report = owner, limits, completion, report
        self.iterator: Any = iter(())
        self.packets = self.bytes = 0
        self.accepted = self.closed = False
        self.failure: BaseException | None = None
        try:
            self.iterator = iter(owner.iter_media_packets(limits=limits, monotonic=clock))
        except BaseException as error:
            self.failure = error
            # Cleanup classes are retained; preserve the constructor failure.
            with suppress(Exception):
                self.close()
            raise

    def __iter__(self) -> Bodies:
        return self

    def validate_end(self) -> None:
        self.accepted = False
        self.report['capture_end_policy_accepted'] = False
        capture = self.owner.capture_result
        self.report['capture'] = capture
        valid = (capture.get('profile') == 'automatic-media-capture-v1'
            and capture.get('status') == 'stopped' and capture.get('owner_closed') is True
            and capture.get('transport_owned') is False and capture.get('startup_in_progress') is False
            and capture.get('transport_closure_verified') is True and not capture.get('cleanup_error_types')
            and capture.get('error_type') is None and capture.get('network_eof_verified') is False
            and type(capture.get('transports_opened')) is int and capture['transports_opened'] > 0
            and type(capture.get('transports_released')) is int
            and capture.get('transports_released') == capture['transports_opened']
            and type(capture.get('packets_yielded')) is int and type(capture.get('bytes_yielded')) is int
            and capture.get('packets_yielded') == self.packets and capture.get('bytes_yielded') == self.bytes)
        if not valid:
            raise CaptureEndRejected('capture terminal accounting or cleanup is invalid')
        reason = capture.get('stop_reason')
        if self.completion != 'bounded-prefix' or reason not in LIMIT_REASONS:
            raise CaptureEndRejected('capture end is not an explicitly accepted bounded prefix')
        packet_limit, byte_limit = self.limits.max_packets, self.limits.max_bytes
        if (packet_limit is None or byte_limit is None or self.packets <= 0
                or self.packets > packet_limit or self.bytes > byte_limit
                or (reason == 'packet_limit' and self.packets != packet_limit)):
            raise CaptureEndRejected('capture end disagrees with configured bounds')
        self.accepted = True
        self.report['capture_end_policy_accepted'] = True

    def __next__(self) -> bytes:
        if self.failure is not None:
            raise CaptureEndRejected('capture packet source previously failed') from self.failure
        if self.accepted:
            raise StopIteration
        if self.closed:
            raise ValueError('capture packet source is closed')
        try:
            try:
                packet = next(self.iterator)
            except StopIteration:
                self.validate_end()  # Rejection is not EOF: decryptor must not flush.
                raise
            body = packet.body
            self.packets += 1
            self.bytes += len(body)
            return body
        except StopIteration:
            raise
        except BaseException as error:
            self.failure = error
            raise

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        errors = self.report['cleanup_error_types']
        close_iterator = getattr(self.iterator, 'close', None)
        for close in (close_iterator, self.owner.close):
            if not callable(close):
                continue
            try:
                close()
            except Exception as error:
                errors.append(type(error).__name__)
        self.report['capture'] = self.owner.capture_result
        if errors:
            raise ValueError('capture owner cleanup failed')


def iter_capture_chunks(owner: Any, key: str | bytes, report: dict[str, Any], *,
        limits: CaptureLimits, completion: str = 'reject', codec: str = 'auto',
        monotonic: Any = time.monotonic, byte_limit: int = 16 * 1024 * 1024) -> Any:
    """Own one pristine capture, never upgrade its local stop to live-source EOF."""
    report.pop('byte_limit', None)
    report.update(profile='guarded-capture-clear-chunks-v1', status='failed', completion_policy=completion,
        input_scope='accepted-capture-prefix', capture_end_policy_accepted=False,
        whole_source_complete=False, network_eof_verified=False, output_devices_opened=False,
        cleanup_error_types=[], accepted_prefix_clear_sha256=None, error_type=None,
        capture=None, decryption=None, limits=None)
    bodies = chunks = None
    primary = cleanup_failed = False
    try:
        validate_arguments(owner, limits, completion, codec, byte_limit=byte_limit)
        report.update({} if byte_limit == DECRYPT['MAX_TOTAL'] else dict(byte_limit=byte_limit))
        report['limits'] = dict(max_packets=limits.max_packets, max_bytes=limits.max_bytes,
            duration_seconds=limits.duration_seconds)
        bodies = Bodies(owner, limits, completion, report, monotonic)
        chunks = DECRYPT['Chunks'](bodies, key, codec=codec, clock=monotonic, byte_limit=byte_limit)
        report['status'] = 'running'
        yield from chunks
    except GeneratorExit:
        primary = True
        report['status'] = 'consumer-closed'
        raise
    except BaseException as error:
        primary = True
        report.update(status='failed', error_type=type(error).__name__)
        raise
    finally:
        try:
            if chunks is not None:
                chunks.close()
            elif bodies is not None:
                bodies.close()
        except Exception as error:
            cleanup_failed = True
            report['status'] = 'failed'
            report['cleanup_error_types'].append(type(error).__name__)
            if not primary:
                report['error_type'] = type(error).__name__
                raise
        finally:
            if chunks is not None:
                report['decryption'] = chunks.result()
            if bodies is not None:
                report['capture'] = owner.capture_result
            if (not primary and not cleanup_failed and chunks is not None and bodies is not None and bodies.accepted
                    and chunks.completed and not chunks.cleanup_errors and not report['cleanup_error_types']):
                try:
                    bodies.validate_end()  # Recheck final cleanup, not an earlier snapshot.
                except Exception as error:
                    report.update(status='failed', error_type=type(error).__name__)
                    raise
                report['status'] = 'bounded-prefix-ended'
                report['accepted_prefix_clear_sha256'] = chunks.clear_hash.hexdigest()
