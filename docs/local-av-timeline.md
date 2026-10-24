# Standalone local A/V timeline (development only)

`tools/local_av_timeline.py` decodes two explicitly selected HEVC tracks and one
AAC-LC track from **one clear local MPEG-TS or Matroska snapshot**. It produces an
inspectable exact-PTS lens-pairing and shared-source-clock plan. It does not use
the EZVIZ app, hooks, app-selected pairs, caller-provided native headers, staging
queues, native VQE or native scheduler events. Optional PyAV is required; no
production dependency, API or camera connection behavior changes.

This is **not yet a playback/output scheduler**, an independent camera connector,
or a physical A/V synchronization test. It opens no output devices and retains no
pixel or PCM payload in its report. Pairing by container PTS is an explicitly
chosen standalone policy, not a reconstruction of the app's raw-header matching.

## Explicit use

```sh
python tools/local_av_timeline.py clear.ts --container mpegts \
  --primary-stream 0 --secondary-stream 1 --audio-stream 2 \
  --pairing exact-pts --clock container-pts > timeline.json
```

Choose absolute stream indices, not video/audio ordinals. The explicit clock
option asserts that these selected tracks share the container's presentation
clock. The tool cannot establish their physical synchronization or repair a
container assembled from independently zeroed tracks. Input must already be clear;
network/URL/encrypted PS input is unsupported. Media and timing reports stay
private; tests generate synthetic data.

The bounded regular input is read once into a snapshot. Both decoders use that
same immutable byte snapshot, whose SHA-256 and byte count are recorded. Changes
to the path after snapshotting cannot mix two files' clocks or media. Decoder
versions are retained for both stages. Audio emissions are verified against their
immediately preceding decoded identity, PCM hash and millisecond sink metadata;
the plan uses the original **exact** PTS/time base, not that millisecond projection.

## Pairing and common origin

- Require strictly increasing PTS per lens. Equal timestamps are ambiguous for
  exact pairing and reject, even if picture identities differ. Backward timestamps
  also reject; no sorting repairs a per-lens regression.
- Compare rational source times, so `90001/90000` equals `180002/180000`. Different
  times that round to the same millisecond do **not** pair. Frame ordinals, matching
  frame counts or a nearest-time tolerance are not pairing keys.
- Produce `local-pair:N` identities for exact-time matches. Both original decoded
  picture identities, PTS/time bases, geometries and pixel hashes remain attached.
  Equal geometry is required within each pair; both lenses may change geometry
  together between pairs. This is pairing metadata, not composed pixels.
- Report all unmatched pictures in `pending_unpaired`; do not silently discard,
  retry, duplicate or drain them. This offline boundary does not distinguish an
  orphan from a future live match. No exact pairs is an unsupported input failure.
- One origin is the earliest decoded source time across **all three tracks**, even
  unmatched pictures. Every event's `at` is exactly its source time minus that
  same origin. Rational times serialize as integer numerator/denominator objects.
  Neither audio nor video is independently reset to zero.
- Sort events on that common presentation clock, not packet arrival, host decode
  observation, native elapsed readings or frame counter. At an exact tie, video
  precedes audio; equal-time audio retains decode order. This deterministic report
  order is not an assertion about device output ordering or native scheduling.

Each audio event keeps its original identity/metadata/hash, exact 1024/16000-second
duration and `gap_before` relative to the previous block's end. Positive gaps,
negative overlaps and equal starts remain visible. The first gap is null, not
synthesized silence. Samples are not duplicated, dropped, stretched, normalized or
resampled to force continuous output. A future output scheduler must decide how
to handle unsupported overlaps and output-device clocks explicitly.

## Bounds and failures

The original adapters retain their limits: 256 MiB input, at most 10,000 video
pictures / 268,435,456 cumulative luma pixels, 10,000 AAC blocks, 100,000 packets
per decoder, supported formats/geometry and bounded packet sizes. This tool adds a
one-hour span between earliest/latest source start times. Snapshot memory is at
most 256 MiB; decoder allocations and bounded metadata are additional. Pixel and
PCM payloads are released by the existing adapters, not stored in the timeline.
These are application limits, not an FFmpeg sandbox or hard native-call interrupt.

No success JSON is emitted until both decoding stages, PCM identity checks and the
whole timeline validate. Failure returns 2. JSON output uses the existing five-
second nonblocking-write deadline; a failed transport can leave a partial JSON
record and must not be treated as a complete plan. No output device, physical
synchronization, native selections or native VQE success is implied by a valid
plan. No scheduler ticks, native headers or native arrival clocks are fabricated.

## Validation and next boundary

Synthetic tests cover exact rational equality, preserved inter-track offsets,
forward gaps/equal or overlapping audio, ambiguous lens duplicates, per-track
regressions, explicit pending pictures, geometry changes, malformed clocks, limits,
source snapshots despite path mutation, PCM emission provenance and CLI policies.
An optional generated three-track HEVC/AAC MPEG-TS integration exercises the whole
CLI with actual decoding and distinct lens pixels.

A short private retained H9c control yields eight exact-time pairs and five AAC
blocks, with the original audio start offset of `3833/22500` seconds (approximately
170.356 ms) after video. All original packet PTS were separately verified through
the fixture's remux; this is not a new standalone network capture or a universal
camera offset. Original source media remain unchanged/private.

Next: a bounded output scheduler that consumes this standalone clock contract,
handles device backpressure and validates output separately from the plan. Fresh
standalone session/transport/decryption validation and physical A/V measurement
remain separate milestones. The app-reference relay remains available unchanged.


The [bounded host-submission output tool](local-av-playback.md) now consumes this
contract for explicitly opted-in local-file output. Its stricter first profile
rejects pending pictures, audio overlaps and geometry changes before opening
devices. Submission timing is not device-clock synchronization.
