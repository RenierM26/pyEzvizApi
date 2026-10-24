"""Metadata-only native decoder outcomes; never a decode, retry or output verdict."""
from __future__ import annotations

from typing import Any


def require(value: Any, message: str) -> None:
    if not value:
        raise ValueError(message)


def uint(value: Any, maximum: int, name: str) -> int:
    require(type(value) is int and 0 <= value <= maximum, f'invalid {name}')
    return value


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:  # noqa: PLR0915 - one bounded metadata join
    require(len(rows) <= 20_000, 'native health observation limit')
    inputs: dict[int, dict[str, Any]] = {}
    returns: dict[int, int] = {}
    selections: list[int] = []
    for row in rows:
        kind = row.get('event')
        if kind == 'encoded_video':
            call = uint(row.get('id'), 600, 'native call')
            require(call > 0 and call not in inputs, 'duplicate or zero native input call')
            meta = row.get('meta_words')
            require(isinstance(meta, list) and len(meta) == 58
                    and all(type(n) is int and 0 <= n < 2**32 for n in meta), 'invalid native metadata')
            assert isinstance(meta, list)
            require(meta[10] in (224, 225), 'unsupported native lens')
            inputs[call] = dict(call=call, sid=meta[10], raw=meta[16], frame=meta[19],
                width=meta[12], height=meta[13],
                device_ns=uint(row.get('device_mono_ns'), 2**63 - 1, 'input device time'))
        elif kind == 'encoded_video_return':
            call = uint(row.get('id'), 600, 'native return call')
            result = row.get('result')
            require(call > 0 and call not in returns, 'duplicate or zero native return')
            require(type(result) is int and -(2**31) <= result < 2**31, 'invalid native result')
            assert isinstance(result, int)
            returns[call] = result
        elif kind == 'render_callback':
            selections.append(uint(row.get('device_mono_ns'), 2**63 - 1, 'selection device time'))
    require(set(returns) <= set(inputs), 'native return without captured input')
    tracks = []
    for sid in (224, 225):
        attempts = [inputs[c] for c in sorted(inputs) if inputs[c]['sid'] == sid]
        if not attempts:
            continue
        counts: dict[str, int] = {}
        epochs: list[dict[str, Any]] = []
        rejected_tail: list[dict[str, Any]] = []
        last_accepted = None
        accepted = rejected = pending = 0
        for attempt in attempts:
            call = attempt['call']
            if not epochs or (epochs[-1]['width'], epochs[-1]['height']) != (attempt['width'], attempt['height']):
                epochs.append(dict(width=attempt['width'], height=attempt['height'], first_call=call,
                                   last_call=call, accepted=0, rejected=0, pending=0))
            epoch = epochs[-1]
            epoch['last_call'] = call
            if call not in returns:
                pending += 1
                epoch['pending'] += 1
                continue  # A pending boundary call is neither accepted nor rejected.
            result = returns[call]
            counts[str(result)] = counts.get(str(result), 0) + 1
            observed = dict(attempt, result=result)
            if result == 0:
                accepted += 1
                epoch['accepted'] += 1
                last_accepted = observed
                rejected_tail = []
            else:
                rejected += 1
                epoch['rejected'] += 1
                rejected_tail.append(observed)
        tracks.append(dict(sid=sid, attempts=len(attempts), accepted=accepted, rejected=rejected,
            pending=pending, result_counts=counts, geometry_epochs=epochs,
            last_accepted=last_accepted, trailing_completed_rejections=len(rejected_tail),
            first_trailing_rejection=rejected_tail[0] if rejected_tail else None))
    last_selection = max(selections, default=None)
    last_input = max((r['device_ns'] for r in inputs.values()), default=None)
    return dict(profile='native-decoder-health-v1', metadata_only=True, tracks=tracks,
        paired_selection_count=len(selections), last_selection_device_ns=last_selection,
        last_input_device_ns=last_input, selection_to_input_tail_ns=(max(0, last_input - last_selection)
            if last_selection is not None and last_input is not None else None),
        error_cause_identified=False, physical_output_verified=False)
