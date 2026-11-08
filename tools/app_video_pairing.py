"""Bounded metadata-only two-lens staging model of one observed H9c profile.

No pixels, decoder buffers, camera I/O or physical video output. JSONL events:
lens_picture, stage_push, render_take. Completed pairs can feed the simulator.
"""

from __future__ import annotations

import json
import sys
from typing import Any

MAX_EVENTS = 10_000
MAX_LINE = 8192
MAX_TIME_MS = 3_600_000
STAGE_CAPACITY = 4
RENDER_CAPACITY = 6
NO_MATCH = 0x80000007


def uint(value: Any, name: str, maximum: int = 0xffffffff) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError(f'{name} must be an integer in [0, {maximum}]')
    return value


class Pairing:
    """Separate uncommitted partials, committed staging and render-queue ownership.

    State numbers mirror the retained code: 1 partial, 2 complete, 3 discard-marked.
    Decoder-buffer return attempts are NOT interpreted as unique frame losses.
    """

    def __init__(self) -> None:
        self.stage: list[dict[str, Any]] = []
        self.committed = 0
        self.render: list[dict[str, Any]] = []
        self.actions: list[dict[str, Any]] = []
        self.seen: set[str] = set()
        self.events = self.at = 0
        self.counts = dict.fromkeys(('lens_offered', 'lens_unaccepted', 'lens_orphaned',
                                    'pairs_assembled', 'render_admitted', 'render_taken'), 0)

    def emit(self, kind: str, **fields: Any) -> None:
        self.actions.append(dict(kind=kind, at_ms=self.at, **fields))

    def push(self) -> None:
        """Commit consecutive complete nodes, then transfer complete FIFO heads."""
        while self.committed < len(self.stage) and self.stage[self.committed]['state'] == 2:
            self.committed += 1
        while (self.committed and self.stage[0]['state'] == 2
               and len(self.render) < RENDER_CAPACITY):
            node = self.stage.pop(0)
            self.committed -= 1
            self.render.append(node)
            self.counts['render_admitted'] += 1
            primary, secondary = node['lenses']
            self.emit('render_queue_admitted', pair=node,
                      simulator_event=dict(kind='video_picture', at_ms=self.at,
                                           id=node['pair_id'], media_ms=primary['media_ms'],
                                           lenses=[primary['id'], secondary['id']]))

    def cleanup(self, target: dict[str, Any] | None = None, *, force: bool = False) -> None:
        """Model orphan removal, not real decoder resource-release callbacks."""
        if force:
            if not self.committed and self.stage and self.stage[0]['state'] == 1:
                self.stage[0]['state'] = 3
                self.committed = 1
        elif target is not None:
            while self.committed < len(self.stage):
                node = self.stage[self.committed]
                if (node['state'] != 1
                        or not any(target['lenses'][i] and not node['lenses'][i] for i in range(2))):
                    break
                node['state'] = 3
                self.committed += 1
        while self.committed and self.stage[0]['state'] == 3:
            old = self.stage.pop(0)
            self.committed -= 1
            for lens in old['lenses']:
                if lens is not None:
                    self.counts['lens_orphaned'] += 1
                    self.emit('lens_orphaned', lens=lens)

    def offer(self, lens: dict[str, Any]) -> None:
        self.counts['lens_offered'] += 1
        self.push()
        target = None
        for node in self.stage[self.committed:]:
            if (node['state'] == 1 and node['lenses'][lens['lens']] is None
                    and any(f and f['raw_time'] == lens['raw_time'] for f in node['lenses'])):
                target = node
                break
        if target is None:
            if len(self.stage) >= STAGE_CAPACITY:
                self.cleanup(force=True)
                self.counts['lens_unaccepted'] += 1
                self.emit('lens_input_unaccepted', lens=lens, native_result=NO_MATCH)
                return
            target = dict(state=1, pair_id=None, lenses=[None, None])
            self.stage.append(target)
        target['lenses'][lens['lens']] = lens
        if all(target['lenses']):
            target['state'] = 2
            target['pair_id'] = f"pair:{self.counts['pairs_assembled']}"
            self.counts['pairs_assembled'] += 1
            self.cleanup(target)
        self.push()

    def step(self, event: Any) -> None:
        """Validate normalized metadata before mutating the staging state."""
        if self.events >= MAX_EVENTS:
            raise ValueError('event limit exceeded')
        if not isinstance(event, dict):
            raise ValueError('event must be an object')
        at = uint(event.get('at_ms'), 'at_ms', MAX_TIME_MS)
        if at < self.at:
            raise ValueError('events must be in nondecreasing observation-time order')
        kind = event.get('kind')
        if kind not in ('lens_picture', 'stage_push', 'render_take'):
            raise ValueError('unknown event kind')
        fields = {'id', 'lens', 'raw_time', 'media_ms', 'frame_number'} if kind == 'lens_picture' else set()
        if set(event) != fields | {'kind', 'at_ms'}:
            raise ValueError('missing or unsupported event fields')
        if kind == 'lens_picture':
            identity = event['id']
            if (not isinstance(identity, str) or not 1 <= len(identity) <= 128
                    or identity in self.seen):
                raise ValueError('id must uniquely identify one offer, using 1..128 characters')
            lens: dict[str, Any] = {k: uint(event[k], k, 1 if k == 'lens' else 0xffffffff)
                    for k in fields - {'id'}}
            lens.update(id=identity, stream_id=0xe0 + lens['lens'])
            self.at = at
            self.seen.add(identity)
            self.offer(lens)
        else:
            self.at = at
            if kind == 'stage_push':
                self.push()
            elif self.render:
                node = self.render.pop(0)
                self.counts['render_taken'] += 1
                self.emit('render_queue_taken', pair=node)
            else:
                self.emit('render_queue_empty')
        self.events += 1

    def result(self) -> dict[str, Any]:
        return dict(profile='h9c-two-lens-staging-v1', events=self.events,
                    physical_lip_sync_measured=False, decoder_buffer_ownership_verified=False,
                    actions=self.actions, summary={**self.counts,
                    'committed_staging': self.committed, 'staging_pending': self.stage,
                    'render_pending': self.render})


def main() -> int:
    """Stage metadata output until the entire bounded input validates."""
    model = Pairing()
    try:
        for _ in range(MAX_EVENTS + 1):
            line = sys.stdin.buffer.readline(MAX_LINE + 1)
            if not line:
                break
            if len(line) > MAX_LINE:
                raise ValueError('JSONL line limit exceeded')
            model.step(json.loads(line))
        else:
            raise ValueError('event limit exceeded')
    except (ValueError, UnicodeError, RecursionError) as error:
        print(f'pairing rejected: {error}', file=sys.stderr)
        return 2
    print(json.dumps(model.result(), sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
