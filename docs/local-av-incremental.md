# Bounded incremental standalone A/V decode (development only)

`tools/local_av_incremental.py` is the next preparation boundary after
[recorded host-submission playback](local-av-playback.md). It consumes one local
immutable source snapshot in **one demux pass**, with persistent HEVC/AAC codec
contexts and synchronous consumer callbacks. It does not open a camera or output
device, schedule playback, or replace the existing recorded playback defaults.

```sh
python tools/local_av_incremental.py clear.ps --container mpeg \
  --primary-stream 0 --secondary-stream 2 --audio-stream 1 \
  --pairing exact-pts --receipt new-incremental.json
```

PyAV is optional and must already be installed. MPEG-TS, Matroska and clear
MPEG-PS are supported. Indices are absolute container indices, not lens ordinals;
inspect them first. Only the existing even-sized YUV420P HEVC and AAC-LC 16-kHz
mono profiles are supported. Nothing is installed and no network fallback exists.

## Ownership and backpressure

The programmatic `inspect(..., consume=callback, report=receipt)` entry point
calls `callback(event, payloads)` synchronously. Video offers contain an exact-PTS
pair's two immutable packed Y/U/V byte strings, in primary/secondary order; audio
offers contain one unchanged 2,048-byte signed-16 PCM block. Every copy is checked
against the decoded fingerprint. Pixel layout excludes decoder stride padding.

A successful callback return acknowledges consumption, not rendering, audibility
or durable storage. No following packet is decoded while it runs, and no executor
backlog is created. The decoder releases its pair references immediately afterward.
Callbacks must finish their use before returning, or explicitly own and separately
bound any retained references: this module cannot bound a consumer's allocations.
A raised callback stops decoding without retry, skipping, dropping or advancing
that offer's consumed count. Its pending identities remain in the failure receipt.
This makes a future bounded output consumer possible without retaining a whole
recording's decoded pixels. It is not that output consumer yet.

The two strictly increasing lens queues match **exact rational container PTS**,
never frame ordinal, rounded milliseconds or nearest timestamps. Different time
bases can represent the same time. Once both queue heads exist, a mismatch is
fatal: neither stream can subsequently supply the missing earlier counterpart
without violating monotonicity. Unequal paired geometry fails. Equal geometry
changes are accepted per pair, without imposing a display-window policy.

All selected encoded packets are decoded, including prerequisite pictures and
EOF flush packets. A persistent decoder is not restarted at each pair, and no
source PTS, samples, compressed bytes or selected frame fingerprints are repaired.
EOF succeeds only with nonempty video/audio and no unmatched lens tail or delayed
format-conversion tail. This is stricter than the general timeline planner, which
can report unmatched pictures without rejecting the whole inspection.

## Clock and receipt contract

Callbacks arrive in **demux/decode order**, not global presentation order. Each
event carries absolute `source_time`, original integer PTS/time base and source
identity. The receipt supplies one `common_origin` only after all three tracks
have produced a supported frame. Audio can precede video; tracks are never
independently zeroed. Exact source audio gaps, overlaps and equal starts remain
visible. This decoder does not apply an audio-output policy: its output must not
be sent blindly to a serial PCM device or treated as a globally sorted schedule.
The existing explicit overlap/phase validation is still needed by an output stage.

Receipts separate decoded video counts from successful consumer returns, pending
pictures, an in-progress video offer, and an unacknowledged audio offer. Video and
audio metadata have independent SHA-256 chains of canonical JSON plus newlines,
in per-track delivery order, updated only after successful consumption. Host
decode timestamps are excluded from the stable metadata hashes. No payloads or
whole-session metadata list are retained. Source SHA-256 and decoder versions
bind the audit to one snapshot. On failure the caller-supplied report retains the
accepted prefix and original error; a prefix is not a completed session.

The CLI default consumer discards each verified payload, opens no output devices,
and writes an exclusive receipt. Exit 0 and `status=completed` establish decode
and callback completion only. Failure is exit 2; KeyboardInterrupt is exit 130
with `status=cancelled`. Existing receipts are never overwritten.

## Bounds and current limitation

Pending copied pixels are capped at **16 pictures and 64 MiB**, including a pair
while its callback runs. Capacity is checked before packing another picture.
The receipt records both high-water marks. One audio block, the current borrowed
decoder frame and temporary plane/packing copies are additional. Native codec
buffers, demux probing and lists returned by PyAV's packet decoder are outside
this copied-pixel accounting; it is not a hard native-memory sandbox.

The immutable compressed snapshot remains bounded at 256 MiB. Existing per-frame
geometry, 10,000 decoded-video-frame, 10,000 audio-block, packet-size, 100,000-packet,
one-hour source-span and 60-second cooperative decode-session limits remain.
Consumer time counts toward that session budget. Native calls and callbacks are
not forcibly interrupted: bounds are checked before/between frames and after the
loop. Failure closes the owned container; this tool creates no output processes.

Unlike the whole-recording decoder, this explicit incremental path has no
**cumulative decoded-pixel** budget: that measure limits total work, not resident
pixel ownership. Total work remains limited by frame/packet/session bounds. No
existing decoder's pixel cap, playback storage cap, lateness tolerance or default
behavior is increased. A retained eight-second dual-1080p source can therefore
be inspected with one pair pending rather than a full decoded recording spool.

Tests cover capacity rejection before copying, backpressure, callback failure and
cancellation, pending tails, rational pairing, duplicate/backward/mismatched PTS,
geometry changes, packet/session/frame limits, unchanged audio overlap metadata,
cleanup and exclusive failure receipts. An optional real synthetic MPEG-PS test
compares every event's timing and pixel/PCM fingerprint with the existing two-pass
planner, including decode reordering, EOF flush and non-video-first stream indices.

Next is a bounded presentation-order lookahead/output owner sharing one persistent
clock and applying the explicit serial-PCM phase contract across the entire
session, followed by acquisition integration. No sustained/live playback or
physical A/V synchronization is claimed by this decode stage.

## Recorded output consumer

The opt-in [rolling playback tool](local-av-bounded-playback.md) now consumes this
stage through `iter_snapshot`. It preflights all metadata, then prepares bounded
lookahead from a second decode of the same immutable bytes. Iterator receipts
count preparation acceptance, not downstream SDL/PCM acknowledgements; closing
before verified EOF reports `closed-before-eof`. Original synchronous `inspect`
callback semantics and the existing recorded playback defaults are unchanged.

The opt-in [chunk-fed preparation boundary](local-av-chunked.md) now supports a
single non-seekable pass without a whole compressed snapshot. It shares this
module's persistent codec/event loop but is not yet connected to rolling output
or network acquisition; the existing snapshot and playback defaults are unchanged.
