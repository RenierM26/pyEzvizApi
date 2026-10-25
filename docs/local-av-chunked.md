# Single-pass chunk-fed A/V preparation (development only)

`tools/local_av_chunked.py` removes the whole-compressed-snapshot requirement
from the incremental decoder. It accepts a caller-supplied iterator of immutable
**clear container bytes** through a non-seekable reader. The CLI feeds a regular
local recording in chunks; it does not connect to a camera, install packages,
open output devices or provide live playback.

```sh
python tools/local_av_chunked.py clear.ps --container mpeg \
  --primary-stream 0 --secondary-stream 2 --audio-stream 1 \
  --chunk-bytes 32768 --max-bytes 16777216 --receipt new-chunked.json
```

Inspect absolute stream indices first; their order can differ between captures.
Existing optional PyAV is required. The snapshot decoder and recorded playback
retain their existing defaults and full preflight behavior.

## Input ownership and backpressure

The development `iter_chunks(chunks, container_format, streams, audio_stream,
report, max_bytes=...)` generator owns the iterator returned by `iter(chunks)`
and closes it on completion, failure or explicit generator close, if it provides
`close()`. The caller must close the preparation generator when abandoning it.
Configuration is checked before pulling input or opening the decoder.

- One immutable, nonempty chunk is accepted at a time, at most **1 MiB**.
- Each read returns at most **64 KiB**; it may return less than requested.
- No next chunk is pulled until all bytes of the current chunk are delivered.
- There is no seek, replay, background producer, read-all or growing byte queue.
- The default accepted input limit is **16 MiB**; explicit limits must be positive
  integers no larger than the existing 256-MiB local input bound. At most 100,000
  chunks are accepted. A crossing chunk fails before hashing, retaining or
  delivering its bytes; it has already been yielded by the external producer.
- Empty chunks fail, rather than masquerading as a temporary absence of data or
  EOF. Only iterator exhaustion establishes producer EOF. Errors are sticky and
  cannot be retried as clean EOF.

The post-pull deadline check applies to iterator exhaustion as well as yielded
chunks: a producer that returns EOF after the session deadline fails before
verified-source completion or a complete-source receipt can be accepted.

Bounds cover this reader's accepted/owned compressed chunks. The producer's
own allocations, decryption buffers, native PyAV probing/demux/codec buffers,
current borrowed frames, temporary copies and downstream references are
additional. This is not a whole-process memory guarantee. A caller-supplied
producer may itself perform network I/O; this module neither opens nor manages
that connection. Blocking producer/native calls are cooperative, not forcibly
interruptible. Reader checks before/after a pull and existing packet/frame decode
checks share the unchanged 60-second session ceiling; socket deadlines must be
provided separately by a future acquisition owner.

## Decoding and EOF evidence

Both snapshot and chunk-fed generators use the same prepared-event loop:
persistent HEVC/AAC contexts, every selected compressed prerequisite, original
PTS/time bases, exact-rational lens pairing, native EOF flush packets and unchanged
pixel/PCM fingerprints. Existing 16-picture / 64-MiB pending-lens bounds and
packet/frame/session limits remain in force. Preparation yields are in
demux/decode order, not globally sorted presentation order or output acknowledgements.
Audio gaps/overlaps are reported unchanged; this tool does not apply a playback
policy or repair timestamps.

Completion requires successful decoding and producer EOF. If demux ends while
reader bytes or a further producer chunk remain, fail rather than drain and
silently accept an unread tail. Receipts include pre/post-cleanup input ownership,
received/delivered byte counts, accepted chunk count, prefix SHA-256 and verified
producer EOF. `first_event_input` also records input consumed when the first
prepared event becomes available, disclosing native startup read-ahead rather
than implying that a non-seekable reader establishes low-latency startup. The root complete-source SHA-256 is published only after successful
source/decode completion. An early close or producer failure retains prefix and
preparation evidence without claiming whole-source success. Cleanup failures are
reported separately and preserve an earlier decode/producer error.

## Validation and remaining integration

Synthetic three-track MPEG-PS tests fragment input down to single-byte chunks and
compare every prepared event and payload with the snapshot path. Other tests cover
byte/chunk/read limits, immutable ownership, no prefetch, sticky producer failure,
cooperative deadlines, unread tails, exclusive receipts and producer cleanup.
Private retained dual-lens recordings are also compared with their original
snapshot controls, including a packet-fed encrypted/decrypted control. Recordings,
keys and camera identifiers are not published in the repository.

This is a decoder input boundary, **not** a network acquisition API or the rolling
player's input mode. The rolling player still needs a whole-recording metadata
preflight and second decode, so it cannot safely be switched to this generator.
Next integration must explicitly handle online startup/stream discovery, incremental
whole-session audio policy, common-clock origin/lookahead, decryption ownership,
source/end/error signaling and cancellation before claiming live output.
No measured physical A/V synchronization is established here.

## Opt-in bounded MPEG-PS startup

Add `--startup bounded-mpeg` (or `startup='bounded-mpeg'` to `iter_chunks`) to
use an explicit startup profile for clear MPEG-PS. The default remains `default`,
with the previous native probing behavior. Other containers are rejected before
producer iteration in this profile; there is no automatic fallback/retry.

FFmpeg receives `probesize=262144` bytes and `analyzeduration=100000`
microseconds. These are discovery hints, **not hard wall-time or reader-memory
limits**. A smaller 32-KiB probe did not discover the retained sources' HEVC
dimensions and was rejected rather than guessed or retried. Selected tracks still
must declare supported HEVC geometry and AAC-LC/16-kHz/mono parameters.

The reader independently enforces **256 KiB of accepted input and five monotonic
seconds** from reader construction until **both** a first exact video pair and
an audio block are prepared. Neither codec discovery nor an audio event alone
ends this phase. The same budget spans discovery and decoding, without resetting
between tracks or packets. Native CPU work is checked when discovery returns and
when prepared events become available. Producer pulls are checked before and
after, including exhaustion; these checks cannot forcibly interrupt a blocked
producer or native call. Acquisition still needs its own socket cancellation.

A whole immutable chunk that would cross the startup input budget is rejected
before acceptance, hashing or delivery; it is not sliced, silently retried or
accepted against a larger budget. Producers must therefore offer appropriately
bounded chunks (the CLI defaults to 32 KiB). Producer/decryption allocations
remain external, and this does not cap native probing/codec allocations.

After both heads are prepared within budget, only the startup restrictions end;
existing total bytes, chunk count, packet/frame, pending pixels and 60-second
session limits remain. No source targets, pixels, PCM, codec prerequisites or
EOF flushes are dropped or changed. `discovery_input`, `first_event_input` and
`startup_ready_input` distinguish stream discovery, first event and both-track
readiness; the last records elapsed startup seconds. Readiness does not mean
output acknowledgement, physical display/audibility or device-clock sync.

Both retained dual-lens recordings and all eight fragmentation/decryption
controls preserve the snapshot events, original PTS/time bases and pixel/PCM/full
source hashes. The bounded profile makes both heads available before producer
EOF in these controls, with 202,340–229,376 bytes accepted at readiness. This is measured
read-ahead on these recordings, not a universal startup-latency guarantee.
Online source-origin/audio/lookahead policy and network/decryption lifecycle are
still required before connecting live output. The recorded player is unchanged.

## Opt-in consumer-excluding processing deadline

The development `iter_chunks` helper accepts
`deadline_mode='consumer-excluding'`. The default is still `wall`; the CLI,
recorded/snapshot decoders and guarded capture/output adapters are not switched.
The opt-in receipt profile is `standalone-chunked-consumer-excluding-v1`, distinct
from the default chunked profile. Existing capture completion validators do not
automatically accept it; downstream integration must be explicit and separately
validated.

The same 60-second cooperative processing allowance applies to the reader and
persistent demux/decode path. This mode subtracts only the time between yielding
a borrowed prepared event and the consumer resuming, closing or throwing into
that yield. It does not reset the allowance on each event. Source iterator
construction/reads/EOF, native container open/demux/decode/flush/close, preparation
and producer cleanup remain charged. A late producer return, late EOF, native
finalization or cleanup overrun cannot become completed success. Reads while an
explicit borrow is open fail rather than hiding source work in excluded time.

The bounded-MPEG startup byte cap and five-second **wall-clock** startup deadline
remain unchanged, including time a consumer holds the first head before the
other head is ready. Do not use consumer exclusion to defer missing-track startup
indefinitely. All compressed byte/chunk, packet/frame/audio work, pairing, geometry
and resident ownership limits remain unchanged. This is elapsed cooperative
processing time, not CPU time, a watchdog or a way to interrupt blocked native IO.
A caller still owns an independently finite session/cancellation lifecycle.

Opt-in `input.processing_clock` records profile
`consumer-excluding-monotonic-v1`, wall seconds, processing seconds, excluded
consumer seconds, completed borrows and whether a borrow remains active.
`processing_seconds_limit` records the unchanged allowance. The clock stores only
scalar timestamps/counters, not a timing history. Completed borrows count resumed
or closed yields; they are **not** output acknowledgements, successful playback
or independent source EOF. Terminal producer EOF, zero owned input, decoder
completion and cleanup remain separate checks. A failed opt-in receipt has no
successful source hash/byte total, even if a later cleanup timeout invalidates an
otherwise exhausted prefix.

No source PTS, relative/host targets, media bytes or audio policy change. A
simulated 61-second downstream hold can pass this processing boundary without
spending real time; that does not establish long-duration live playback. Capture,
decryption and output still have independent wall-clock/work limits, so this
standalone option does **not** enable sustained or unbounded streaming.
