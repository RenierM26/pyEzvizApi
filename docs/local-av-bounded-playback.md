# Rolling bounded recorded A/V playback (development only)

`tools/local_av_bounded_playback.py` connects the
[incremental decoder](local-av-incremental.md) to a persistent host-submission
scheduler and SDL/ffplay output. It replaces whole-recording pixel retention
with bounded lookahead, **not** the existing tool's defaults. This is recorded
local-file playback, not an independent live camera connector or device-clock sync.

```sh
python tools/local_av_bounded_playback.py clear.ps --container mpeg \
  --primary-stream 0 --secondary-stream 2 --audio-stream 1 \
  --play --pairing exact-pts --timing host-submission \
  --layout side-by-side --processor passthrough \
  --audio-overlap-policy bounded-serial-pcm \
  --max-audio-overlap-ms 1 --max-audio-phase-ms 1 --receipt new-output.json
```

Linux/WSL, existing optional PyAV, SDL2 and ffplay are required. No packages are
installed and no network/camera/app connection is opened. Absolute stream indices
must be inspected; do not assume the audio stream is last. MPEG-TS, Matroska and
clear MPEG-PS are supported. For older ffplay use explicit `--mono-option channels`
instead of default `ch-layout`; no automatic executable/option retry occurs.
The socket/bulk-copy transport is deliberately unsupported in this profile.

## Two passes, one immutable source and one host anchor

1. Read one bounded immutable compressed snapshot (at most 256 MiB).
2. Incrementally decode it once, retaining metadata only. Construct the complete
   exact-rational-PTS timeline; validate constant equal lens geometry, no unmatched
   EOF, at most 300 pairs, at most 60 seconds of event-start span, and the selected
   audio policy **before either output opens**. Optional serial-PCM overlap and
   nominal-phase bounds are evaluated over the entire session, not restarted per
   lookahead refill. The default remains overlap rejection.
3. Decode the same bytes again with persistent codec contexts. Every prepared
   event must equal its preflight metadata, including original PTS/time base and
   decoded fingerprints. Every packed pixel/PCM payload is checked again.
   Preserve compressed prerequisites, reorder handling and EOF flush packets.
4. Prefill bounded lookahead before output startup. Compose each pair and seal
   one Linux memfd for it; do not compose or copy an entire recording's pixels.
5. Open one isolated SDL worker and one ffplay process. Establish one monotonic
   host anchor after their constructors return. Compute every target as
   `anchor + floor((source_time - common_origin)*1e9)` without moving source times.
6. Submit independent single-job video and audio tracks. Decode/prepare at most
   one next event between dispatch opportunities. Missing data, full queues and
   slow outputs never cause hidden drops, segment clock resets or rebases.
7. Return lookahead credit only after successful output acknowledgement; a failed
   job retains its credit until explicit backend abort and lease cleanup.
   Verify actual source EOF, all planned jobs and the explicit audio/video drain
   before declaring success. Keep the last image through audio drain.

Prepared delivery follows demux/decode order; dispatch follows each track's
preflight presentation plan. A source whose initial interleave cannot supply
both track heads within lookahead fails before devices open. Later excessive
interleave, insufficient decode throughput or stalled output can exceed the
unchanged default 250-ms lateness bound and fail. There is no inferred larger
buffer, timeout increase, catch-up timestamp or recovery that silently loses media.

## Ownership and transport

Lookahead credit is capped at **four video pairs / 64 MiB**, and **32 PCM blocks /
65,536 bytes**, including reserved preparation, queued and in-flight output.
A slot is not reused merely because a job was dispatched. Each sealed pair has
one owner-side file lease; the SDL worker receives one descriptor via `SCM_RIGHTS`
and bounded identity/hash/extent metadata, never a full frame over the socket.
It verifies exact size, Linux write/grow/shrink seals and pixel hash, maps the
pair only for the synchronous SDL call, closes its descriptor/mapping, then
acknowledges the exact identity/fingerprint. Duplicate identities, mutable files,
missing/extra descriptors, truncated ancillary data and invalid extents fail.

The decoder's separate pending-lens cap remains 16 pictures / 64 MiB. Its current
borrowed native frame, temporary plane/packed/composed copies, native demux/codec
buffers and consumer-thread stack references are additional. The compressed
snapshot and bounded metadata/receipts are additional too: **64 MiB is not a
whole-process memory claim**. No existing decoder cumulative-pixel cap or recorded
playback spool cap is raised. Total work remains frame/packet/session bounded.

The owner advances the decoder synchronously; there is no background decoder
thread left behind after cancellation. Native demux/decode and callbacks remain
cooperatively bounded, not forcibly interruptible or sandboxed. A slow native call
can delay owner dispatch and trigger lateness failure; audio/video calls already
submitted run independently in at most two executor jobs. Preparation and startup
have finite deadlines; all backend operations and final drain retain `--deadline`
(default five seconds). On failure, owned output children are aborted/reaped and worker jobs
joined before remaining leases close; the decoder iterator is explicitly closed on failure.
Cleanup attempts all owned leases and preserves the primary error. The existing
60-second cooperative decoder-session budget includes time spent waiting during
playback, so a recording near the source-span limit can exceed that separate
processing/session bound; supported input bounds are not a throughput guarantee.

## Raw audio startup and honest timing

The new profile opts into `Ffplay(immediate_raw_probe=True)`: input is already
fully declared signed-16 little-endian, 16-kHz mono, so use `-probesize 32` and
`-analyzeduration 1` (microseconds) instead of accumulating a long raw-input
analysis window. The receipt discloses these fixed settings. Existing ffplay
adapter callers retain their previous defaults. No filters, gain, silence,
resampling, frame dropping, sample edits or timing offsets are introduced.

A retained eight-second test originally completed all host calls but exceeded the
five-second drain budget with the legacy probe settings. The explicit small raw
probe completed the same source and unchanged drain budget. This is a startup
configuration control, **not** a measured audio-device clock or guaranteed startup
latency. Successful raw writes remain pipe acknowledgements, not audibility.
SDL present returns likewise do not establish physical display time. The explicit
serial-PCM phase compromise and all [existing timing limitations](local-av-playback.md)
still apply; neither recorded nor dummy success proves physical A/V sync.

## Receipts and validation

The exclusive receipt contains source hash, preflight timeline and audio contract,
second-pass preparation evidence, one scheduler anchor, every original target and
output acknowledgement, failed/active/unsubmitted work, partial PCM bytes, queue
credit high-water marks, source EOF and pre/post-cleanup ownership. Preparation
counts are not output acknowledgements. A preparation failure or valid consumed
prefix is not completed playback. Exit 0 requires `status=completed` and clean
drains; failure is exit 2 and SIGINT/SIGTERM cancellation exit 130.

Tests cover credit held through in-flight output, long constant lease ownership,
exact second-pass metadata/payload equality, unsupported startup interleave,
missing/extra tails, cancellation/cleanup, absolute targets, independent audio,
slow-track lateness, drain failure, descriptor/hash/seal validation and actual
SDL descriptor delivery. Optional synthetic HEVC/AAC MPEG-PS tests exercise the
real two-pass path and SDL/ffplay dummy drain. No camera credentials or fixtures
are required. Real driver/human observations remain a separate validation step.
