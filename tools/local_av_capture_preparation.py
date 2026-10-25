"""One accepted-prefix capture/decrypt/decode/policy verdict; no output devices."""
from __future__ import annotations

from pathlib import Path
import runpy
import time
from typing import Any

from pyezvizapi.media import CaptureLimits

BASE = Path(__file__).parent
CAPTURE = runpy.run_path(str(BASE / 'local_av_capture.py'))
ONLINE = runpy.run_path(str(BASE / 'local_av_online.py'))
CHUNKED = ONLINE['CHUNKED']


def verify_completion(capture: dict[str, Any], decode: dict[str, Any], online: dict[str, Any]) -> str:
    """Require independent terminal checks, not merely exhaustion of the wrapper."""
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
            or crypto.get('profile') != 'bounded-decrypted-packet-chunks-v1'
            or crypto.get('status') != 'completed' or crypto.get('verified_decryption_end') is not True
            or crypto.get('producer_iterator_exhausted') is not True
            or crypto.get('pending_bytes') != 0 or crypto.get('cleanup_errors')
            or not isinstance(digest, str) or len(digest) != 64
            or digest != crypto.get('complete_clear_sha256')
            or decode.get('profile') != 'standalone-chunked-preparation-v1'
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


def iter_capture_preparation(owner: Any, key: str | bytes, streams: tuple[int, int],  # noqa: PLR0913
        audio_stream: int, report: dict[str, Any], *, limits: CaptureLimits,
        completion: str = 'reject', codec: str = 'auto', policy: str = 'reject',
        overlap_ms: int | None = None, phase_ms: int | None = None,
        monotonic: Any = time.monotonic, pes_ids: tuple[int, int, int] | None = None,
        identity_mode: str = 'full-history') -> Any:
    """Own a validated pristine owner; borrow each prepared event until resumed.

    Exhaust or explicitly close this iterator. A later failure invalidates the
    session verdict, not already borrowed events. No whole-source preflight,
    output acknowledgement, network EOF or physical synchronization is claimed.
    """
    capture: dict[str, Any] = {}
    decode: dict[str, Any] = {}
    online: dict[str, Any] = {}
    report.update(profile='guarded-capture-online-preparation-v1', status='failed', error_type=None,
        input_scope='accepted-capture-prefix', completion_policy=completion,
        capture=capture, decode=decode, online=online, cleanup_error_types=[],
        accepted_prefix_clear_sha256=None, whole_source_complete=False, network_eof_verified=False,
        output_devices_opened=False, physical_av_sync_measured=False)
    chunks = events = mapped = None
    claimed = primary = False
    try:
        # Validate downstream policy before transferring ownership or opening IO.
        ONLINE['Policy'](streams, audio_stream, policy, overlap_ms, phase_ms, identity_mode=identity_mode)
        CAPTURE['validate_arguments'](owner, limits, completion, codec)
        if pes_ids is not None:
            CHUNKED['TRACKS']['validate_pes_ids'](pes_ids)
        claimed = True
        chunks = CAPTURE['iter_capture_chunks'](owner, key, capture, limits=limits,
            completion=completion, codec=codec, monotonic=monotonic)
        selection: dict[str, Any] | None = {} if pes_ids is not None else None
        options = {} if pes_ids is None else dict(pes_ids=pes_ids, selection=selection)
        events = CHUNKED['iter_chunks'](chunks, 'mpeg', streams, audio_stream, decode, startup='bounded-mpeg', **options)
        mapped = ONLINE['iter_online'](events, streams, audio_stream, online,
            policy=policy, overlap_ms=overlap_ms, phase_ms=phase_ms, identity_mode=identity_mode, **({} if selection is None else dict(selection=selection)))
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
            digest = verify_completion(capture, decode, online)
        except Exception as error:
            report.update(status='failed', error_type=type(error).__name__)
            raise
        report.update(status='prepared-prefix-ended', accepted_prefix_clear_sha256=digest)
