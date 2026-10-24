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
