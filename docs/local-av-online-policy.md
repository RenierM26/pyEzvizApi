# Online A/V policy preparation (development only)

`tools/local_av_online.py` maps chunk-decoder events to one fixed source origin
and validates audio policy incrementally. It does **not** schedule host calls,
open output devices, acquire a camera stream or measure physical A/V sync.
The recorded player keeps its existing whole-source preflight and defaults.

```sh
python tools/local_av_online.py clear.ps \
  --primary-stream 0 --secondary-stream 2 --audio-stream 1 \
  --audio-overlap-policy bounded-serial-pcm \
  --max-audio-overlap-ms 1 --max-audio-phase-ms 1 --receipt new-online.json
```

The CLI reads a regular recorded clear MPEG-PS file through the bounded startup
profile. Inspect absolute stream indices first. Default audio policy is `reject`;
small overlaps require both explicit integer limits as in recorded playback.
Neither mode changes PCM samples or source timing.

## One origin, not a preflight guarantee

The `iter_online` adapter owns a prepared-event iterator from the chunk decoder.
It waits for the first exact video pair and first audio block before choosing
`min(first_video_time, first_audio_time)`. Strictly increasing starts per track
ensure that later events cannot precede this minimum. It then maps every event
with the same exact rational subtraction. Original per-lens/block PTS and time
bases remain unchanged. A later violation fails, never drops or rebases media.
No host anchor or clock correction is introduced.

The initial payload prefix is held under the existing **four video pairs / 64 MiB**
and **32 PCM blocks / 65,536 bytes** limits. All startup rows are checked before
the first mapped row is yielded. Credit remains held through a borrowed yield and
is released only when the consumer resumes or the generator closes. No further
source event is pulled while a mapped prefix row is still borrowed. Missing heads,
excess startup interleave or EOF without both heads fails rather than discarding.

The adapter validates source-stream selections, original PTS agreement, payload
extents and hashes, constant equal bounded geometry, unique bounded identities,
strict source progression, at most 300 pairs and a fixed-origin 60-second span.
It yields in **demux/decode delivery order**, not global presentation order.
A future output owner must keep independent presentation-ordered track queues;
simply submitting these rows sequentially is not an A/V scheduler.

## Shared audio checks across the whole accepted prefix

`AudioClock` in the recorded playback module now implements the same per-block
checks for both whole-recording `audio_contract` and online policy. It checks
strict starts, declared source gaps, overlap and the accumulated phase
`first_audio_time + block_index * 1024/16000 - source_time`. Its state is never
reset on startup completion, another video event or a refill. Positive gaps and
negative overlaps remain original metadata; no silence, gain, normalization,
resampling, timestamp adjustment or implicit block drop is introduced.

The existing whole-recording audio receipt still includes the same block rows.
Online receipts retain summary state plus a hash chain of those same per-block
audit rows, rather than retaining a second full audit-row list. The serial PCM
clock is calculated content timing, not an observed sound-device clock.

Unlike whole-recording preflight, an online validator cannot approve unknown
future media before emitting a valid prefix. A later phase/geometry/span error
therefore fails after earlier preparation was emitted. Consumers must abort
explicitly if this is eventually connected to output. A source failure or early
consumer close retains the accepted-prefix evidence without claiming completion.

## Ownership, evidence and remaining work

Bounds cover adapter-retained payload references, not whole-process memory.
A just-borrowed decoded event exists before its kind/extent is known and is checked
before the adapter retains it. Decoder/native pending frames, producer/decryption
buffers and consumer-held references remain additional. Metadata identity sets are
separately bounded by the 300-pair and existing 10,000-audio-block session limits.
The adapter does not copy pixel/PCM payloads, but rechecks their hashes.

Receipts distinguish validated mapping counts, yielded rows, resumed/released
borrowed preparation rows,
pre/post-cleanup ownership and upstream chunk-decoder/source EOF evidence. None
of these counts acknowledges an output API. Cleanup closes the source iterator,
releases retained bytes and preserves a primary policy error alongside separate
cleanup diagnostics. Callers must close the adapter when abandoning iteration.
A normally exhausted arbitrary prepared iterator establishes only that iterator's
EOF; the CLI's upstream chunk decoder separately verifies original byte-source EOF.

Tests compare one-pass results with full source timeline and audio-policy controls,
including adverse interleave, cumulative phase drift after startup, missing heads,
capacity, malformed payload/timing, later geometry/span errors and early close.
Private retained-source comparisons preserve every original target and pixel/PCM
hash; keys and recordings are not published. No new attended playback test is
required for this policy-only boundary.

Next is a bounded online output owner with a single host anchor, independent
track queues, explicit backpressure and abort/drain behavior, followed by bounded
network/decryption lifecycle integration. The existing recorded player must not
be switched to this adapter without implementing those contracts.

## Opt-in constant-state source identity checks

`iter_online(..., identity_mode='source-sequence')` replaces the policy's two
whole-prefix ID sets with two accepted-event counters. The default remains
`full-history`, which accepts arbitrary nonempty unique event names under the
existing work limits. This option does not evict old IDs from a deduplication
window: it imposes a stricter source contract so old names cannot recur at all.

Video IDs must be exactly `local-pair:1`, `local-pair:2`, ... in per-video
admission order. Audio IDs must be exactly `aac:<selected absolute audio index>:0`,
`aac:<index>:1`, ... in per-audio admission order. These are the chunk decoder's
existing original IDs, not a renumbering performed by the policy. Counters start
at the beginning of this iterator; mid-stream fragments with nonzero initial
indices require the legacy mode or an upstream session starting at its real
beginning. A duplicate, reset, skip, wrong stream, leading zero, sign, alternate
digit spelling or arbitrary ID fails before credit or identity admission. Never
repair or rewrite source names. Different track interleavings do not affect the
independent counters. Explicit PES selection uses the newly resolved absolute
audio index, not the caller's placeholder index.

The opt-in online profile is `standalone-online-sequence-av-policy-v1`. Its
`policy.identity_audit` has profile `strict-source-sequence-v1`, accepted counts
for both tracks, `retained_id_count=0` and the actual `audio_stream_index`.
Counters advance only after the existing payload/PTS/geometry and startup credit
checks have admitted the event. A later timing-policy failure invalidates the
session even if some IDs were admitted; this is not a success/EOF receipt alone.
Source cleanup and borrowed-yield ownership remain unchanged.

The mode is also available through `iter_capture_preparation` and the pending
`CapturePlayback` constructor; it can be combined with `diagnostic_tail=2` for
constant identity metadata plus bounded finalized diagnostics. Capture completion
requires the sequence profile's identity counts to match decoded video/audio
counts, zero retained IDs and (for explicit PES selection) the same audio index.
The recorded CLI, synchronous capture helper and all defaults stay unchanged.

This removes only policy ID-history growth. The existing 300-pair/audio-block
work caps, fixed-origin 60-second output span, chunk byte/count limits, decoder
processing limits, geometry/PCM checks, original source/host timing, lateness,
leases and backend drains are NOT relaxed. Payload queues/native buffers still
have their own bounds; no whole-process RSS or sustained-streaming claim follows.


### Explicit finite pair quota

`Policy(..., pair_limit=N)` and `iter_online(..., pair_limit=N)` retain the default
300-pair ceiling. Explicit source-sequence mode permits a finite integer quota
up to 3,000; legacy full-history mode remains capped at 300. This quota follows
same-container track resolution and appears as `policy.pair_limit` only when
nondefault. It is checked before admission, independently of released resident
credit. Source span, audio block limits and all startup payload credit are
unchanged. See the [composed output budget](local-av-capture-playback.md#explicit-finite-video-pair-budget)
for the additional bounded-diagnostics and native worker requirements.
