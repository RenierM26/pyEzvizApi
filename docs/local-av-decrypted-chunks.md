# Bounded decrypted packet chunks (development only)

`tools/local_av_decrypted.py` adapts an owned iterator of immutable encrypted
MPEG-PS **packet bodies**, not raw socket/RTP envelopes, to clear chunks for
`tools/local_av_chunked.py`. It does not open a socket, discover credentials,
bootstrap a camera, change the legacy CLI decryptor, or open output devices.

Load it with the repository on Python's import path; supply the media key from a
private credential source, not a command-line argument. The development callable
is `iter_decrypted(packets, key, report, codec='auto')`; `hevc` is the only explicit
mode. Pass the returned iterator directly to `iter_chunks(..., startup='bounded-mpeg')`
and close the downstream generator on early consumer exit. The adapter owns the
iterator returned by `iter(packets)`; a future transport owner must separately own
its stream/client context and close the underlying sockets.

## Bounds and semantics

- Before appending, enforce at most1MiB pending encrypted bytes in both modes.
  Validate nonempty immutable packet bodies of at most1MiB. Stop rather than
  discard if either pending ownership,100000 packets or16MiB encrypted input
  would cross its bound. Clear yields separately enforce1MiB chunks/16MiB total.
- Reuse the existing MPEG-PS prefix, mode detection and video-decrypt primitives;
  retain one last incomplete/decryptable tail until producer exhaustion, then
  flush once. Auto mode must be detected, including at EOF; no silent HEVC guess.
  Undetected prefixes fail at the pending cap instead of accumulating indefinitely.
- No prefetch queue: pull only while a clear chunk is unavailable; after yielding
  a nonempty chunk, wait for downstream resume before pulling again. Internal
  source fragments may need bounded coalescing before any decryptable prefix.
- Check the60-second cooperative lifetime before and after producer/decrypt/EOF
  work and after final flush. Downstream waits count toward lifetime. Slow EOF
  cannot turn an expired source into a successfully completed one. Failure is
  sticky; do not retry, flush or claim a complete hash after failure.
- Track encrypted accepted bytes/hash, clear yielded bytes/hash, pending bytes
  and high-water mark independently. Publish complete clear hash only after
  downstream requests final exhaustion. Yield is not a downstream acknowledgement.
- Close owned input and release pending/key references on completion, failure
  and early consumer close. Preserve a primary failure while recording cleanup
  errors; a cleanup-only failure must not report clean success. Dropping the key
  reference is not a secure-memory erasure claim.

The1MiB pending cap is not a total allocation/RSS cap: prefix detection/decryption
uses bounded transient copies, the producer owns its packet allocation, the caller
can retain a yielded chunk, and the decoder/output have separate credit. The
existing256KiB/five-second decoded-startup guard is still separate; pending crypto
input is additional and can fail before all required decoded heads are available.

## Completion is not network EOF

`producer_iterator_exhausted` and `verified_decryption_end` concern only this
supplied finite iterator. `network_eof_verified` stays false: existing transport
iterators can stop on packet, byte or duration limits, so ordinary `StopIteration`
cannot establish protocol EOF or clean live termination. A live owner must carry
an explicit stop reason and use transport-specific socket/deadline controls; this
wrapper cannot interrupt an arbitrary blocking producer or native call. Do not
connect it to output or infer live success solely from these receipts.

Retained encrypted sources are compared at original packet boundaries and fixed
fragment sizes against their independent clear snapshot decode: full clear SHA256,
every stream/PTS/time-base/media hash, event metadata, decoder EOF and ownership.
Tests cover invalid/mutable bodies, no-prefetch, pre-append limits in both modes,
input/output totals, slow pull/EOF/flush, early close and primary/cleanup failure.
No camera or attended Windows test is required for this preparation-only boundary.
