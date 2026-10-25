"""One accepted-prefix capture/decrypt/decode/policy verdict; no output devices."""
from __future__ import annotations

import hashlib
import math
from pathlib import Path
import runpy
import time
from typing import Any

from pyezvizapi.media import CaptureLimits

BASE = Path(__file__).parent
CAPTURE = runpy.run_path(str(BASE / 'local_av_capture.py'))
ONLINE = runpy.run_path(str(BASE / 'local_av_online.py'))
CHUNKED = ONLINE['CHUNKED']


def verify_clock_snapshot(reader: dict[str, Any], count: int, seconds_limit: int = 60) -> dict[str, Any]:
    """Require completed scalar accounting, not a substitute for source EOF."""
    clock = reader.get('processing_clock') or {}
    numbers: list[Any] = [clock.get(field) for field in ('wall_seconds', 'processing_seconds', 'excluded_consumer_seconds')]
    ready = reader.get('startup_ready_elapsed_seconds')
    if (clock.get('profile') != 'consumer-excluding-monotonic-v1'
            or clock.get('borrow_active') is not False
            or type(clock.get('completed_borrows')) is not int or clock['completed_borrows'] != count
            or any(isinstance(value, bool) or not isinstance(value, int | float)
                or not math.isfinite(value) or value < 0 for value in numbers)
            or not math.isclose(numbers[0], numbers[1] + numbers[2], rel_tol=1e-9, abs_tol=1e-6)
            or type(reader.get('processing_seconds_limit')) is not int
            or reader['processing_seconds_limit'] != seconds_limit
            or numbers[1] > reader['processing_seconds_limit']
            or reader.get('startup_active') is not False
            or reader.get('startup_seconds_limit') != CHUNKED['STARTUP_SECONDS']
            or reader.get('startup_byte_limit') != CHUNKED['STARTUP_BYTES']
            or isinstance(ready, bool) or not isinstance(ready, int | float)
            or not math.isfinite(ready) or not 0 <= ready <= CHUNKED['STARTUP_SECONDS']):
        raise ValueError('capture decoder processing clock accounting failed')
    return clock


def verify_decoder_clock(decode: dict[str, Any], count: int, mode: str, seconds_limit: int = 60) -> None:
    CHUNKED['validate_deadline_mode'](mode)
    if mode == 'wall':
        if (decode.get('profile') != 'standalone-chunked-preparation-v1'
                or any('processing_clock' in (decode.get(name) or {}) for name in ('input', 'input_before_cleanup'))):
            raise ValueError('capture decoder deadline mode/profile mismatch')
        return
    if (decode.get('profile') != 'standalone-chunked-consumer-excluding-v1'
            or (decode.get('startup') or {}).get('mode') != 'bounded-mpeg'):
        raise ValueError('capture decoder deadline mode/profile mismatch')
    before = verify_clock_snapshot(decode.get('input_before_cleanup') or {}, count, seconds_limit)
    after = verify_clock_snapshot(decode.get('input') or {}, count, seconds_limit)
    if (after['wall_seconds'] < before['wall_seconds'] or after['processing_seconds'] < before['processing_seconds']
            or after['excluded_consumer_seconds'] != before['excluded_consumer_seconds']):
        raise ValueError('capture decoder cleanup clock accounting failed')


def verify_byte_budget(capture: dict[str, Any], decode: dict[str, Any], byte_limit: int) -> None:
    """Bind requested byte work independently of time, pending storage and EOF."""
    decrypt = CAPTURE['DECRYPT']
    decrypt['validate_byte_limit'](byte_limit)
    crypto = capture.get('decryption') or {}
    limits = capture.get('limits') or {}
    expected_profile = ('bounded-decrypted-packet-chunks-v1' if byte_limit == decrypt['MAX_TOTAL']
        else 'bounded-decrypted-packet-chunks-v2')
    readers = [decode.get(field) or {} for field in ('input', 'input_before_cleanup')]
    counts = [crypto.get('encrypted_bytes'), crypto.get('clear_bytes_yielded'),
        (capture.get('capture') or {}).get('bytes_yielded'),
        *[reader.get(field) for reader in readers for field in ('received_bytes', 'delivered_bytes')]]
    if (crypto.get('profile') != expected_profile
            or any(type(count) is not int or not 0 < count <= byte_limit for count in counts)
            or type(capture.get('byte_limit', decrypt['MAX_TOTAL'])) is not int
            or capture.get('byte_limit', decrypt['MAX_TOTAL']) != byte_limit
            or type(crypto.get('total_byte_limit')) is not int or crypto['total_byte_limit'] != byte_limit
            or type(limits.get('max_bytes')) is not int or not 0 < limits['max_bytes'] <= byte_limit
            or crypto.get('encrypted_bytes') != (capture.get('capture') or {}).get('bytes_yielded')
            or crypto.get('encrypted_bytes', 0) > limits['max_bytes']
            or type(crypto.get('pending_byte_limit')) is not int
            or crypto['pending_byte_limit'] != decrypt['MAX_PENDING']
            or any(type(row.get('total_byte_limit')) is not int or row['total_byte_limit'] != byte_limit for row in readers)
            or any(row.get('received_bytes') != crypto.get('clear_bytes_yielded')
                or row.get('delivered_bytes') != crypto.get('clear_bytes_yielded')
                or type(row.get('chunk_byte_limit')) is not int or row['chunk_byte_limit'] != CHUNKED['MAX_CHUNK_BYTES']
                or type(row.get('read_byte_limit')) is not int or row['read_byte_limit'] != CHUNKED['MAX_READ_BYTES'] for row in readers)):
        raise ValueError('capture compressed byte budget mismatch')


def startup_fraction(value: Any) -> Any:
    """Reject float/bool/uncanonical receipt times before using exact arithmetic."""
    if (type(value) is not dict or set(value) != {'numerator', 'denominator'}
            or any(type(number) is not int for number in value.values()) or value['denominator'] <= 0):
        raise ValueError('capture startup rational timestamp mismatch')
    result = ONLINE['PLAY']['fraction'](value)
    if CHUNKED['DECODE']['TIMELINE']['rational'](result) != value:
        raise ValueError('capture startup rational timestamp mismatch')
    return result


def verify_startup_pairing(decode: dict[str, Any], online: dict[str, Any], mode: str) -> None:
    """Bind the explicit startup exclusion; never reinterpret a strict receipt."""
    decoder = CHUNKED['DECODE']
    decoder['validate_startup_pairing'](mode)
    prepared = decode.get('preparation') or {}
    audit = prepared.get('startup_alignment')
    if mode == 'strict':
        if 'startup_pairing' in decode or audit is not None:
            raise ValueError('capture startup pairing policy mismatch')
        return
    if (decode.get('startup_pairing') != mode or type(audit) is not dict
            or audit.get('profile') != 'bounded-common-keyframe-startup-v1'
            or audit.get('gate_opened') is not True or audit.get('strict_after_gate') is not True
            or audit.get('native_selection_used') is not False):
        raise ValueError('capture startup pairing policy mismatch')
    selected = audit.get('selected_keyframes')
    excluded = audit.get('excluded_counts')
    counts = prepared.get('video_frames_decoded')
    total = audit.get('excluded_frames')
    size = audit.get('excluded_pixel_bytes')
    digest = audit.get('excluded_metadata_sha256')
    if (type(selected) is not list or len(selected) != 2 or any(type(row) is not dict for row in selected)
            or type(excluded) is not dict or type(counts) is not dict
            or type(total) is not int or not 0 <= total <= decoder['MAX_STARTUP_EXCLUDED']
            or type(size) is not int or not 0 <= size <= total * decoder['VIDEO']['MAX_PIXELS'] * 3 // 2
            or (total == 0) != (size == 0)
            or type(digest) is not str or len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest)
            or (total == 0 and digest != hashlib.sha256(b'bounded-common-keyframe-startup-v1\n').hexdigest())
            or type(audit.get('max_excluded_frames')) is not int
            or audit['max_excluded_frames'] != decoder['MAX_STARTUP_EXCLUDED']
            or audit.get('max_source_span') != dict(numerator=1, denominator=1)):
        raise ValueError('capture startup exclusion accounting failed')
    streams = [row.get('stream_index') for row in selected]
    selection = decode.get('track_selection')
    if (any(type(stream) is not int or stream < 0 for stream in streams) or streams[0] == streams[1]
            or (selection and streams != selection.get('video_indices'))
            or set(excluded) != {str(stream) for stream in streams}
            or {str(stream) for stream in counts} != set(excluded)
            or any(type(value) is not int or value < 0 for value in excluded.values())
            or sum(excluded.values()) != total):
        raise ValueError('capture startup selected tracks mismatch')
    for row, stream in zip(selected, streams, strict=True):
        count = counts.get(stream, counts.get(str(stream)))
        if (row.get('key_frame') is not True
                or row.get('decoded_id') != f'video:{stream}:{excluded[str(stream)]}'
                or type(row.get('frame_index')) is not int or row['frame_index'] != excluded[str(stream)]
                or type(count) is not int or count != prepared['video_pairs_consumed'] + excluded[str(stream)]):
            raise ValueError('capture startup selected frame accounting failed')
    timeline = decoder['TIMELINE']
    stamp = timeline['exact'](selected[0])
    first = (online.get('policy') or {}).get('first_source_times') or {}
    minimum = startup_fraction(audit.get('observed_minimum'))
    maximum = startup_fraction(audit.get('observed_maximum'))
    startup_fraction(audit.get('max_source_span'))
    startup_fraction(audit.get('selected_source_time'))
    if (timeline['exact'](selected[1]) != stamp or audit.get('selected_source_time') != timeline['rational'](stamp)
            or first.get('video_pair') != audit['selected_source_time']
            or not 0 <= minimum <= stamp <= maximum or maximum - minimum > decoder['MAX_STARTUP_SPAN']):
        raise ValueError('capture startup exact timestamp accounting failed')


def verify_completion(capture: dict[str, Any], decode: dict[str, Any], online: dict[str, Any], *,
                      decoder_deadline_mode: str = 'wall', pair_limit: int = 300, byte_limit: int = 16 * 1024 * 1024, startup_pairing: str = 'strict', seconds_limit: int = 60, span_limit: int = 60, gap_limits: dict[str, int] | None = None) -> str:
    """Require independent terminal checks, not merely exhaustion of the wrapper."""
    CAPTURE['DECRYPT']['validate_seconds_limit'](seconds_limit)
    crypto = capture.get('decryption') or {}
    reader = decode.get('input') or {}
    prepared = decode.get('preparation') or {}
    policy = online.get('policy') or {}
    digest = capture.get('accepted_prefix_clear_sha256')
    if (capture.get('profile') != 'guarded-capture-clear-chunks-v1'
            or capture.get('status') != 'bounded-prefix-ended'
            or capture.get('capture_end_policy_accepted') is not True
            or capture.get('whole_source_complete') is not False
            or capture.get('network_eof_verified') is not False
            or capture.get('cleanup_error_types') or capture.get('error_type') is not None
            or crypto.get('profile') not in ('bounded-decrypted-packet-chunks-v1', 'bounded-decrypted-packet-chunks-v2')
            or crypto.get('status') != 'completed' or crypto.get('verified_decryption_end') is not True
            or crypto.get('producer_iterator_exhausted') is not True
            or crypto.get('pending_bytes') != 0 or crypto.get('cleanup_errors')
            or not isinstance(digest, str) or len(digest) != 64
            or digest != crypto.get('complete_clear_sha256')
            or decode.get('status') != 'completed' or decode.get('error') is not None
            or decode.get('cleanup_errors') or digest != decode.get('source_sha256')
            or reader.get('verified_source_end') is not True or reader.get('pending_bytes') != 0
            or reader.get('owned_chunk_bytes') != 0
            or reader.get('received_bytes') != crypto.get('clear_bytes_yielded')
            or reader.get('delivered_bytes') != reader.get('received_bytes')
            or prepared.get('pending_pixel_bytes') != 0 or prepared.get('pending_unpaired')
            or prepared.get('pending_audio') is not None or prepared.get('video_offer_in_progress') is not None
            or decode.get('track_selection') != online.get('track_selection')
            or online.get('profile') not in ('standalone-online-av-policy-v1', 'standalone-online-sequence-av-policy-v1')
            or online.get('status') != 'completed' or online.get('error') is not None
            or online.get('cleanup_errors') or policy.get('origin') is None
            or policy.get('origin') != prepared.get('common_origin')
            or policy.get('owned_counts') != {'video_pair': 0, 'audio_block': 0}
            or policy.get('owned_bytes') != {'video_pair': 0, 'audio_block': 0}):
        raise ValueError('capture preparation terminal checks failed')
    mode = 'source-sequence' if online.get('profile') == 'standalone-online-sequence-av-policy-v1' else 'full-history'
    ONLINE['BOUNDED']['CHANNEL']['validate_pair_limit'](pair_limit, mode)
    if (type(policy.get('pair_limit', 300)) is not int or policy.get('pair_limit', 300) != pair_limit
            or type(prepared.get('video_pairs_consumed')) is not int
            or not 0 < prepared['video_pairs_consumed'] <= pair_limit):
        raise ValueError('capture preparation video pair limit mismatch')
    ONLINE['validate_span_limit'](span_limit, mode)
    if (type(capture.get('seconds_limit', 60)) is not int or capture.get('seconds_limit', 60) != seconds_limit
            or type(crypto.get('wall_seconds_limit', 60)) is not int or crypto.get('wall_seconds_limit', 60) != seconds_limit
            or any((decode.get(name) or {}).get('processing_seconds_limit', 60) != seconds_limit for name in ('input', 'input_before_cleanup'))
            or type(policy.get('source_span_limit_seconds', 60)) is not int or policy.get('source_span_limit_seconds', 60) != span_limit):
        raise ValueError('capture preparation time/span budget mismatch')
    count = policy.get('validated_events')
    if (type(count) is not int or count <= 0
            or count != policy.get('yielded_prepared_events') or count != policy.get('released_prepared_events')
            or not prepared.get('video_pairs_consumed') or not prepared.get('audio_blocks_consumed')
            or count != prepared['video_pairs_consumed'] + prepared['audio_blocks_consumed']
            or policy.get('audio_blocks') != prepared['audio_blocks_consumed']):
        raise ValueError('capture preparation event accounting failed')
    if online['profile'] == 'standalone-online-sequence-av-policy-v1':
        audit = policy.get('identity_audit') or {}
        expected = dict(video_pair=prepared['video_pairs_consumed'], audio_block=prepared['audio_blocks_consumed'])
        selection = online.get('track_selection') or {}
        if (audit.get('profile') != 'strict-source-sequence-v1' or audit.get('accepted') != expected
                or type(audit.get('retained_id_count')) is not int or audit['retained_id_count'] != 0
                or type(audit.get('audio_stream_index')) is not int or audit['audio_stream_index'] < 0
                or (selection and audit['audio_stream_index'] != selection.get('audio_index'))):
            raise ValueError('capture preparation source identity accounting failed')
    contract = policy.get('audio_clock_contract') or {}
    if gap_limits is not None:
        if (ONLINE['GAP']['GAPS']['canonical'](contract.get('limits')) != ONLINE['GAP']['GAPS']['canonical'](gap_limits)
                or contract.get('profile') != ONLINE['GAP']['GAPS']['PROFILE']
                or type(contract.get('source_blocks_verified')) is not int
                or contract['source_blocks_verified'] != prepared['audio_blocks_consumed']
                or contract.get('plan_only') is not True or contract.get('padding_written') is not False):
            raise ValueError('capture gap preparation binding failed')
    elif contract.get('profile') == ONLINE['GAP']['GAPS']['PROFILE']:
        raise ValueError('gap preparation requires explicit limits')
    verify_startup_pairing(decode, online, startup_pairing)
    verify_byte_budget(capture, decode, byte_limit)
    verify_decoder_clock(decode, count, decoder_deadline_mode, seconds_limit)
    return digest


def close_pipeline(iterators: tuple[Any, ...], owner: Any, report: dict[str, Any]) -> Exception | None:
    """Close outer-to-inner, retaining lazy-owner cleanup and the first error."""
    cleanup_error = None
    for iterator in iterators:
        try:
            if iterator is not None:
                iterator.close()
        except Exception as error:
            report['cleanup_error_types'].append(type(error).__name__)
            if cleanup_error is None:
                cleanup_error = error
    # Closing a never-started generator does not execute its finally block.
    if owner is not None:
        try:
            owner.close()
        except Exception as error:
            report['cleanup_error_types'].append(type(error).__name__)
            if cleanup_error is None:
                cleanup_error = error
    return cleanup_error


def bind_options(report: dict[str, Any], decoder_deadline_mode: str, pair_limit: int, byte_limit: int = 16 * 1024 * 1024, startup_pairing: str = 'strict', seconds_limit: int = 60, span_limit: int = 60) -> None:
    for field, value, default in [('decoder_deadline_mode', decoder_deadline_mode, 'wall'), ('pair_limit', pair_limit, 300), ('byte_limit', byte_limit, 16 * 1024 * 1024), ('startup_pairing', startup_pairing, 'strict'), ('seconds_limit', seconds_limit, 60), ('span_limit', span_limit, 60)]:
        report.pop(field, None)
        if value != default:
            report[field] = value


def iter_capture_preparation(owner: Any, key: str | bytes, streams: tuple[int, int],  # noqa: PLR0913, PLR0915
        audio_stream: int, report: dict[str, Any], *, limits: CaptureLimits,
        completion: str = 'reject', codec: str = 'auto', policy: str = 'reject',
        overlap_ms: int | None = None, phase_ms: int | None = None,
        monotonic: Any = time.monotonic, pes_ids: tuple[int, int, int] | None = None,
        identity_mode: str = 'full-history', decoder_deadline_mode: str = 'wall', pair_limit: int = 300, byte_limit: int = 16 * 1024 * 1024, startup_pairing: str = 'strict', seconds_limit: int = 60, span_limit: int = 60, gap_limits: dict[str, int] | None = None) -> Any:
    """Own a validated pristine owner; borrow each prepared event until resumed.

    Exhaust or explicitly close this iterator. A later failure invalidates the
    session verdict, not already borrowed events. No whole-source preflight,
    output acknowledgement, network EOF or physical synchronization is claimed.
    """
    capture: dict[str, Any] = {}
    decode: dict[str, Any] = {}
    online: dict[str, Any] = {}
    bind_options(report, 'wall', 300)
    report.update(profile='guarded-capture-online-preparation-v1', status='failed', error_type=None,
        input_scope='accepted-capture-prefix', completion_policy=completion,
        capture=capture, decode=decode, online=online, cleanup_error_types=[],
        accepted_prefix_clear_sha256=None, whole_source_complete=False, network_eof_verified=False,
        output_devices_opened=False, physical_av_sync_measured=False)
    chunks = events = mapped = None
    claimed = primary = False
    try:
        # Validate downstream policy before transferring ownership or opening IO.
        CHUNKED['validate_deadline_mode'](decoder_deadline_mode)
        CHUNKED['DECODE']['validate_startup_pairing'](startup_pairing)
        ONLINE['Policy'](streams, audio_stream, policy, overlap_ms, phase_ms, identity_mode=identity_mode, pair_limit=pair_limit, span_limit=span_limit, **({} if gap_limits is None else dict(gap_limits=gap_limits)))
        CAPTURE['validate_arguments'](owner, limits, completion, codec, byte_limit=byte_limit, seconds_limit=seconds_limit)
        if pes_ids is not None:
            CHUNKED['TRACKS']['validate_pes_ids'](pes_ids)
        bind_options(report, decoder_deadline_mode, pair_limit, byte_limit, startup_pairing, seconds_limit, span_limit)
        if gap_limits is not None:
            report['audio_gap_limits'] = dict(gap_limits)
        claimed = True
        chunks = CAPTURE['iter_capture_chunks'](owner, key, capture, limits=limits,
            completion=completion, codec=codec, monotonic=monotonic, byte_limit=byte_limit, seconds_limit=seconds_limit)
        selection: dict[str, Any] | None = {} if pes_ids is not None else None
        options = {} if pes_ids is None else dict(pes_ids=pes_ids, selection=selection)
        events = CHUNKED['iter_chunks'](chunks, 'mpeg', streams, audio_stream, decode, startup='bounded-mpeg', max_bytes=byte_limit, startup_pairing=startup_pairing, seconds_limit=seconds_limit,
            **({} if decoder_deadline_mode == 'wall' else dict(deadline_mode=decoder_deadline_mode)), **options)
        mapped = ONLINE['iter_online'](events, streams, audio_stream, online,
            policy=policy, overlap_ms=overlap_ms, phase_ms=phase_ms, identity_mode=identity_mode, pair_limit=pair_limit, span_limit=span_limit, **({} if selection is None else dict(selection=selection)), **({} if gap_limits is None else dict(gap_limits=gap_limits)))
        report['status'] = 'running'
        yield from mapped
    except GeneratorExit:
        primary = True
        report['status'] = 'consumer-closed'
        raise
    except BaseException as error:
        primary = True
        report.update(status='failed', error_type=type(error).__name__)
        raise
    finally:
        unstarted_owner = owner if claimed and capture.get('capture') is None else None
        cleanup_error = close_pipeline((mapped, events, chunks), unstarted_owner, report)
        if cleanup_error is not None:
            report['status'] = 'failed'
            if not primary:
                report['error_type'] = type(cleanup_error).__name__
                raise cleanup_error
    if not primary:
        try:
            digest = verify_completion(capture, decode, online, decoder_deadline_mode=decoder_deadline_mode, pair_limit=pair_limit, byte_limit=byte_limit, startup_pairing=startup_pairing, seconds_limit=seconds_limit, span_limit=span_limit, **({} if gap_limits is None else dict(gap_limits=gap_limits)))
        except Exception as error:
            report.update(status='failed', error_type=type(error).__name__)
            raise
        report.update(status='prepared-prefix-ended', accepted_prefix_clear_sha256=digest)
