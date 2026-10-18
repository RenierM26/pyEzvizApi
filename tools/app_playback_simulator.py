"""Bounded offline model of one observed live-player profile; no media/device I/O.

Run with JSONL on stdin. Input pictures must already be assembled lens pairs with
app-relative timing; PCM blocks are fixed 2048-byte, 16-kHz mono s16 blocks. This
is not a decoder, audio processor, real-time sink or physical AV calibration.
"""

from __future__ import annotations

import argparse
from collections import deque
from dataclasses import dataclass
import json
import struct
import sys
from typing import Any, ClassVar

MAX_EVENTS = 10_000
MAX_LINE_BYTES = 8192
MAX_TIME_MS = 3_600_000
PCM_BYTES = 2048
RING_BYTES = 51_200
VIDEO_NODES = 6


def float32(value: float) -> float:
    """Match the retained ARM single-precision arithmetic."""
    return struct.unpack('<f', struct.pack('<f', value))[0]


@dataclass(frozen=True)
class Decision:
    """Requested actions, not physical presentation."""

    display: bool = False
    drops: int = 0
    sleep_ms: int = 0


@dataclass
class VideoClock:
    """Mode0, smoothing/audio-sync off; frame speed1, independent video timer."""

    node_limit: int = VIDEO_NODES
    speed: float = 1.0
    bias_ms: int = 50
    rebase_pending: bool = True
    origin_ms: int = 0

    def after_display(self, remaining: int) -> None:
        """Use POST-render depth; falling below the threshold does not downshift."""
        if self.bias_ms != 0xffffffff and remaining >= ((self.node_limit - 3) & 0xffffffff):
            self.speed = float32(1.1)

    def unavailable(self, staging_result: int) -> None:
        """Staging success0 does not trigger this reset."""
        if staging_result != 0 and 1 < self.speed < 2:
            self.speed = 1.0
            self.bias_ms = 50
            self.rebase_pending = True

    def rebase(self, picture_ms: int) -> None:
        """Current live mode retains bias50 and leaves the head unconsumed."""
        self.origin_ms = picture_ms
        self.rebase_pending = False

    def decision(self, relative_ms: int, elapsed_ms: int, depth: int,
                 interval_ms: int = 66) -> Decision:
        """Native float32 target and depth-dependent late-frame catch-up."""
        target = min(int(float32(float32((relative_ms + self.bias_ms) & 0xffffffff)
                                 / float32(self.speed))), 0xffffffff)
        difference = ((target - elapsed_ms + 2**31) % 2**32) - 2**31
        if -14 <= difference <= 14:
            return Decision(display=True)
        if difference > 14:
            sleep = (100 if difference > 1000 else 40 if difference > 300
                     else 15 if difference > 100 else 5 if difference >= 21 else 0)
            return Decision(sleep_ms=sleep)
        drops = 0
        if depth >= 2:
            drops = 1 + sum(depth >= k + 2 and difference + k * interval_ms <= -1
                            for k in range(1, 5))
        return Decision(display=True, drops=drops)


def integer(value: Any, name: str, maximum: int = MAX_TIME_MS) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError(f'{name} must be an integer in [0, {maximum}]')
    return value


def identity(value: Any) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 128:
        raise ValueError('id must be a nonempty string of at most 128 characters')
    return value


class PlaybackSimulator:
    """Identity-only explicit event replay; all retained state has fixed bounds.

    Audio begin keeps the ring slot occupied through processing. Release frees
    it and starts an output write; only an explicit completion unblocks the next
    begin. No Android buffer duration or VQE delay is invented. Video input
    overflow is rejected as unsupported, not assigned an unverified loss rule.
    """

    event_fields: ClassVar[dict[str, set[str]]] = {
        'video_picture': {'id', 'media_ms', 'lenses'},
        'video_tick': {'staging_result'},
        'audio_enqueue': {'id', 'media_ms'},
        'audio_begin': set(),
        'audio_release': {'id'},
        'audio_write_complete': {'id', 'accepted_bytes'},
    }

    def __init__(self) -> None:
        self.video: deque[dict[str, Any]] = deque()
        self.audio: deque[str] = deque()
        self.clock = VideoClock()
        self.audio_media: dict[str, int] = {}
        self.last_video_media: int | None = None
        self.processing: str | None = None
        self.writing: str | None = None
        self.timer_at = 0
        self.not_before = 0
        self.last_at = 0
        self.events = 0
        self.seen: set[tuple[str, str]] = set()
        self.actions: list[dict[str, Any]] = []
        self.counts = dict.fromkeys(('video_offered', 'video_displayed', 'video_dropped',
                                    'audio_offered', 'audio_rejected', 'audio_written'), 0)

    def emit(self, kind: str, at: int, **fields: Any) -> None:
        self.actions.append({'kind': kind, 'at_ms': at, **fields})

    def step(self, event: dict[str, Any]) -> None:
        """Consume one event; invalid input terminates the replay."""
        if self.events >= MAX_EVENTS:
            raise ValueError('event limit exceeded')
        if not isinstance(event, dict):
            raise ValueError('event must be an object')
        at = integer(event.get('at_ms'), 'at_ms')
        if at < self.last_at:
            raise ValueError('events must be in nondecreasing at_ms order')
        kind = event.get('kind')
        if not isinstance(kind, str) or kind not in self.event_fields:
            raise ValueError('unknown event kind')
        if set(event) - {'kind', 'at_ms'} - self.event_fields[kind]:
            raise ValueError('unknown event fields')
        if kind in ('video_picture', 'audio_enqueue'):
            self.enqueue(event, at)
        elif kind.startswith('video_'):
            self.video_event(event, at)
        else:
            self.audio_step(event, at)
        self.events += 1
        self.last_at = at

    def enqueue(self, event: dict[str, Any], at: int) -> None:
        kind = event['kind']
        item_id = identity(event.get('id'))
        track = 'video' if kind == 'video_picture' else 'audio'
        if (track, item_id) in self.seen:
            raise ValueError('duplicate track identity')
        if kind == 'video_picture':
            media = integer(event.get('media_ms'), 'media_ms', 0xffffffff)
            if self.last_video_media is not None and media < self.last_video_media:
                raise ValueError('video media time must already be continuity-repaired')
            lenses = event.get('lenses')
            if (not isinstance(lenses, list) or len(lenses) != 2
                    or any(not isinstance(x, str) or not 1 <= len(x) <= 128 for x in lenses)
                    or lenses[0] == lenses[1]):
                raise ValueError('lenses must contain two distinct identities')
            if len(self.video) >= VIDEO_NODES:
                raise ValueError('video overflow policy is unverified; stop replay')
            self.video.append({'id': item_id, 'media_ms': media, 'lenses': list(lenses)})
            self.last_video_media = media
            self.counts['video_offered'] += 1
        else:
            media = integer(event.get('media_ms'), 'media_ms', 0xffffffff)
            self.audio_media[item_id] = media
            self.counts['audio_offered'] += 1
            if (len(self.audio) + 1) * PCM_BYTES >= RING_BYTES:
                self.counts['audio_rejected'] += 1
                self.emit('audio_reject_newest', at, id=item_id, media_ms=self.audio_media[item_id])
            else:
                self.audio.append(item_id)
                self.emit('audio_admitted', at, id=item_id, media_ms=self.audio_media[item_id])
        self.seen.add((track, item_id))

    def audio_step(self, event: dict[str, Any], at: int) -> None:
        kind = event['kind']
        if kind == 'audio_begin':
            if not self.audio or self.processing is not None or self.writing is not None:
                raise ValueError('audio begin requires a queued block and idle consumer')
            self.processing = self.audio[0]
            self.emit('audio_processing', at, id=self.processing, media_ms=self.audio_media[self.processing])
        elif kind == 'audio_release':
            item_id = identity(event.get('id'))
            if item_id != self.processing or self.writing is not None:
                raise ValueError('release must match the processing block')
            self.audio.popleft()
            self.processing = None
            self.writing = item_id
            self.emit('audio_write_started', at, id=item_id, media_ms=self.audio_media[item_id])
        else:
            item_id = identity(event.get('id'))
            if item_id != self.writing:
                raise ValueError('completion must match the active write')
            if type(event.get('accepted_bytes')) is not int or event['accepted_bytes'] != PCM_BYTES:
                raise ValueError('partial/failed output writes are outside this profile')
            self.writing = None
            self.counts['audio_written'] += 1
            self.emit('audio_write_completed', at, id=item_id, media_ms=self.audio_media[item_id])

    def video_event(self, event: dict[str, Any], at: int) -> None:
        """Dispatch the autonomous scheduler event."""
        self.video_tick(event, at)

    def video_tick(self, event: dict[str, Any], at: int) -> None:
        if at < self.not_before:
            raise ValueError('video tick precedes the requested scheduler wake time')
        if not self.video:
            result = event.get('staging_result')
            if type(result) is not int or not -(2**31) <= result < 2**31:
                raise ValueError('empty video tick requires signed staging_result')
            self.clock.unavailable(result)
            self.emit('video_unavailable', at, speed=self.clock.speed,
                      rebase_pending=self.clock.rebase_pending)
            return
        if 'staging_result' in event:
            raise ValueError('staging_result is only valid for an unavailable picture')
        head = self.video[0]
        if self.clock.rebase_pending:
            self.clock.rebase(head['media_ms'])
            self.timer_at = at
            self.emit('video_rebase', at, id=head['id'], origin_ms=self.clock.origin_ms)
            return
        relative = (head['media_ms'] - self.clock.origin_ms) & 0xffffffff
        decision = self.clock.decision(relative, at - self.timer_at, len(self.video))
        for _ in range(decision.drops):
            picture = self.video.popleft()
            self.counts['video_dropped'] += 1
            self.emit('video_drop_oldest', at, **picture)
        if decision.display:
            picture = self.video.popleft()
            self.counts['video_displayed'] += 1
            self.clock.after_display(len(self.video))
            self.emit('video_display_requested', at, **picture, speed=self.clock.speed)
        else:
            self.not_before = at + decision.sleep_ms
            self.emit('video_hold', at, id=head['id'], wake_ms=self.not_before)

    def result(self) -> dict[str, Any]:
        """Return observed model actions and boundary-pending identities."""
        return {'profile': 'observed-h9c-live-v1', 'physical_lip_sync_measured': False,
                'events': self.events, 'actions': self.actions,
                'summary': {**self.counts,
                            'video_pending': [p['id'] for p in self.video],
                            'audio_ring_pending': list(self.audio),
                            'audio_processing': self.processing,
                            'audio_write_pending': self.writing}}


class ObservedClockReplay(PlaybackSimulator):
    """Replay native timer snapshots, never derive elapsed time from callbacks.

    This mode validates explicit epochs, head identity, sampled depth and speed.
    Display completion is separate from selection. An unavailable-head staging
    return can occur after staging has admitted a picture; it is not inferred
    from the current queue depth. Sleep constraints use the native timer domain.
    """

    event_fields: ClassVar[dict[str, set[str]]] = {
        **{k: v for k, v in PlaybackSimulator.event_fields.items() if k != 'video_tick'},
        'video_epoch': {'epoch', 'origin_ms'},
        'video_unavailable': {'staging_result'},
        'video_observed_tick': {'epoch', 'id', 'relative_ms', 'elapsed_ms',
                                'depth', 'speed', 'bias_ms', 'interval_ms'},
        'video_display_complete': {'id', 'depth'},
    }

    def __init__(self) -> None:
        super().__init__()
        self.epoch: int | None = None
        self.elapsed = 0
        self.wake_elapsed = 0
        self.displaying: dict[str, Any] | None = None
        self.completed = 0
        self.interval = 0

    def video_event(self, event: dict[str, Any], at: int) -> None:
        kind = event['kind']
        if kind == 'video_epoch':
            self.start_epoch(event, at)
        elif kind == 'video_unavailable':
            if self.displaying is not None:
                raise ValueError('unavailable event during active display')
            result = event.get('staging_result')
            if type(result) is not int or not -(2**31) <= result < 2**31:
                raise ValueError('unavailable event requires signed staging_result')
            self.clock.unavailable(result)
            self.emit(kind, at, staging_result=result, speed=self.clock.speed,
                      rebase_pending=self.clock.rebase_pending)
        elif kind == 'video_display_complete':
            item_id = identity(event.get('id'))
            if self.displaying is None or item_id != self.displaying['id']:
                raise ValueError('completion must match the active display')
            if integer(event.get('depth'), 'depth', VIDEO_NODES) != len(self.video):
                raise ValueError('post-display depth disagrees with admitted queue')
            self.clock.after_display(len(self.video))
            self.displaying = None
            self.completed += 1
            self.emit(kind, at, id=item_id, speed=self.clock.speed)
        else:
            self.observed_tick(event, at)

    def start_epoch(self, event: dict[str, Any], at: int) -> None:
        epoch = integer(event.get('epoch'), 'epoch', MAX_EVENTS)
        origin = integer(event.get('origin_ms'), 'origin_ms', 0xffffffff)
        expected = 0 if self.epoch is None else self.epoch + 1
        if epoch != expected or not self.clock.rebase_pending or self.displaying is not None:
            raise ValueError('epoch requires a pending rebase and sequential epoch id')
        if not self.video or self.video[0]['media_ms'] != origin:
            raise ValueError('epoch origin must match the unconsumed head')
        self.epoch = epoch
        self.clock.rebase(origin)
        self.elapsed = self.wake_elapsed = 0
        self.emit('video_observed_epoch', at, epoch=epoch, origin_ms=origin)

    def observed_tick(self, event: dict[str, Any], at: int) -> None:
        if self.epoch is None or self.clock.rebase_pending:
            raise ValueError('observed tick requires an established epoch')
        if self.displaying is not None or not self.video:
            raise ValueError('observed tick requires an available head and idle display')
        epoch = integer(event.get('epoch'), 'epoch', MAX_EVENTS)
        elapsed = integer(event.get('elapsed_ms'), 'elapsed_ms', 0xffffffff)
        relative = integer(event.get('relative_ms'), 'relative_ms', 0xffffffff)
        depth = integer(event.get('depth'), 'depth', VIDEO_NODES)
        bias = integer(event.get('bias_ms'), 'bias_ms', 0xffffffff)
        interval = integer(event.get('interval_ms'), 'interval_ms', 66)
        speed = event.get('speed')
        head = self.video[0]
        if epoch != self.epoch or elapsed < max(self.elapsed, self.wake_elapsed):
            raise ValueError('native epoch/timer order or requested sleep violated')
        if identity(event.get('id')) != head['id'] or depth != len(self.video):
            raise ValueError('native head/depth disagrees with admitted queue')
        if relative != ((head['media_ms'] - self.clock.origin_ms) & 0xffffffff):
            raise ValueError('native relative time disagrees with picture origin')
        if (type(speed) not in (int, float) or speed != self.clock.speed
                or bias != self.clock.bias_ms or interval not in (0, 66)
                or (interval == 0 and (self.interval == 66 or head['media_ms'] != 0))):
            raise ValueError('native profile state disagrees with modeled state')
        decision = self.clock.decision(relative, elapsed, depth, interval)
        self.interval = interval
        self.elapsed = elapsed
        self.wake_elapsed = elapsed + decision.sleep_ms
        self.emit('video_observed_decision', at, epoch=epoch, id=head['id'],
                  elapsed_ms=elapsed, display=decision.display,
                  drops=decision.drops, sleep_ms=decision.sleep_ms)
        for _ in range(decision.drops):
            picture = self.video.popleft()
            self.counts['video_dropped'] += 1
            self.emit('video_drop_oldest', at, **picture)
        if decision.display:
            self.displaying = self.video.popleft()
            self.counts['video_displayed'] += 1
            self.emit('video_display_requested', at, **self.displaying)

    def result(self) -> dict[str, Any]:
        """Keep display requests, completions and boundary-pending output distinct."""
        result = super().result()
        result['profile'] = 'observed-h9c-native-clock-replay-v1'
        result['clock_source'] = 'explicit-native-timer-snapshots'
        result['summary'].update(video_display_completed=self.completed,
                                 video_display_pending=self.displaying,
                                 video_epoch=self.epoch)
        return result


def main() -> int:
    """Stage all output until validation succeeds; no partial success JSON."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--observed-clock', action='store_true',
                        help='require explicit native timer epochs and decision snapshots')
    args = parser.parse_args()
    simulator = ObservedClockReplay() if args.observed_clock else PlaybackSimulator()
    try:
        for _ in range(MAX_EVENTS + 1):
            line = sys.stdin.buffer.readline(MAX_LINE_BYTES + 1)
            if not line:
                break
            if len(line) > MAX_LINE_BYTES:
                raise ValueError('JSONL line limit exceeded')
            simulator.step(json.loads(line))
        else:
            raise ValueError('event limit exceeded')
    except (ValueError, UnicodeError, RecursionError) as error:
        print(f'simulation rejected: {error}', file=sys.stderr)
        return 2
    print(json.dumps(simulator.result(), sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
