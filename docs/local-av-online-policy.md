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
