# Single-pass online-policy recorded output (development only)

`tools/local_av_online_playback.py` connects the chunk-fed decoder and online
policy adapter to SDL/ffplay output. It reads a **local clear MPEG-PS recording**
once, without a compressed snapshot, whole-source metadata plan or second decode.
It is not a live network connector. Existing recorded-player defaults are unchanged.

```sh
python tools/local_av_online_playback.py clear.ps --container mpeg \
  --primary-stream 0 --secondary-stream 2 --audio-stream 1 \
  --play --pairing exact-pts --timing host-submission \
  --layout side-by-side --processor passthrough \
  --audio-overlap-policy bounded-serial-pcm \
  --max-audio-overlap-ms 1 --max-audio-phase-ms 1 --receipt new-output.json
```

Existing optional PyAV, SDL2, ffplay and Linux/WSL sealed memfds are required.
Inspect absolute stream indices first. The explicit overlap policy, older ffplay
`--mono-option channels`, default five-second backend deadlines and default
250-ms submission-lateness limit have their existing meanings. Socket/bulk-copy
video transport and containers other than clear MPEG-PS are rejected in this profile.

## Startup, queues and one anchor

1. Use the bounded MPEG-PS startup decoder and fixed-origin online policy. Retain
   source PTS/time bases, exact lens pairing and whole-prefix audio phase checks.
   Unknown future violations may fail after a valid prefix has already played;
   there is no whole-recording preflight promise.
2. Prefill independent video/audio queues before opening output devices. Both
   heads are required. Startup may accept the missing track's head even when the
   other track has filled its slots, but never exceeds actual track/byte credit.
3. For each video pair, hash canonical side-by-side Y/U/V rows directly from the
   immutable lens bytes without a full wide-frame allocation. Seal the original
   split lens bytes in one memfd. The worker independently verifies storage and
   canonical hashes, uploads both rectangles and acknowledges the exact identity.
4. Open one persistent SDL worker and one ffplay process, then choose one monotonic
   host anchor. Every target remains `anchor + floor(relative_source_time * 1e9)`.
   Never replace the anchor after a stall or reorder/drop media to catch up.
5. Dispatch at most one video and one audio job independently. The existing
   acknowledgement/abort lease handling releases credit only after successful
   backend acknowledgement, or explicit abort/reap and cleanup on failure.
6. Harvest before and after advancing preparation, dispatch ready track heads,
   and poll only when preparation cannot progress. A source/policy/backend error,
   unsupported interleave or late submission fails instead of silently skipping.
7. Require prepared-iterator exhaustion, upstream decoder/byte-source EOF, all
   accepted output calls and explicit audio/video drains for successful completion.
   Keep the last picture while audio drains. Abort owned outputs, join jobs,
   close upstream generators and release all leases on failure or cancellation.

## Conservative pull credit and memory accounting

Output ownership remains **four pairs / 64 MiB** and **32 PCM blocks / 65,536 bytes**,
including preparation, queued and in-flight output. A dispatched lease still owns
its slot. The next prepared event's kind is unknown without advancing the decoder,
so steady-state pulls require room for both one same-geometry pair and one PCM
block. This is conservative backpressure, not a larger uncredited pending queue.
A burst/interleave that hides a due head behind a full other-track window may
therefore fail the existing lateness bound; not every valid container interleave
is guaranteed to play within these fixed budgets.

The online policy's separately bounded startup payload references, a currently
borrowed event, decoder pending/native buffers, producer/decryption allocations,
transient row views and session-bounded metadata/receipts are additional. A brief
handoff can hold raw lens bytes and their sealed lease together. These limits are
not a whole-process RSS claim. There is no background acquisition/decoder thread.
Native reads/decode and preparation remain cooperative and can delay dispatch;
network integration must provide its own interruptible acquisition lifecycle.

The accepted compressed input is capped at the chunk decoder's default 16 MiB.
The fixed source span remains 60 seconds and 300 pairs. The upstream decoder's
separate 60-second cooperative processing limit includes playback waits and
startup work; a source near the span ceiling can therefore fail that limit. The host loop has a finite
span-plus-backend session guard, tightened to the latest submitted target plus
backend deadline after EOF and final dispatch. Each backend drain retains its own
existing deadline. A failed job keeps lease credit until explicit cleanup.
Cleanup diagnostics do not replace an earlier source/output error; even executor
shutdown failure still attempts source/lease cleanup.

## Evidence and limitations

Receipts separate upstream decode, online policy mapping and actual host-call
submissions/completions, with one anchor, original relative targets, hashes,
partial PCM, failures, queues and pre/post-cleanup ownership. Preparation timings
split upstream pull (including decode/policy), canonical pair hashing and sealed
storage work. On-demand canonical hashing is new timed work relative to the
preflight split-upload player, so its Windows throughput must be verified rather
than inferred from the previous profile's successful test.

Two retained-source SDL/ffplay dummy controls complete 118/123 and 36/36 video/audio
calls, with original pixel/PCM hashes, source origin/targets, upstream EOF and
clean drains. Dummy success is not actual Windows picture/audio output. Tests
exercise absolute targets, independent tracks, full startup interleave, credit
held through async output, source failure after output begins, late output,
drain/cancel, preparation failure, failed executor cleanup and SIGTERM restoration.

No live acquisition, audible playback or measured physical A/V synchronization is
established by this profile's local dummy results. The next validation is attended
recorded Windows output, followed by bounded network/decryption integration.
