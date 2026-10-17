# Explicit local paired-video preview (development only)

`tools/app_video_preview.py` connects real decoded pixels and the explicit
[header-map staging adapter](app-video-decode.md) to a **side-by-side ffplay preview**.
It is not an app-compatible A/V player, native compositor, live source or physical
synchronization measurement. Production capture/remux and audio are unchanged.

## Run explicitly

Requirements: POSIX, optional PyAV (validated with 19.0.1), and `ffplay` on PATH.
Use the decoder inspection workflow to build an independently identified header
map with exact decoded-frame bindings. The map must explicitly `render_take`
each pair intended for preview. Preview does not consume pending work at EOF.

```sh
python tools/app_video_preview.py paired.mkv --container matroska \
  --primary-stream 0 --secondary-stream 1 --header-map headers.jsonl \
  --play --layout side-by-side --fps 15 --receipt new-preview.json
```

All of `--play`, layout, cadence, header map and a new receipt path are required.
`--fps` is an explicit integer preview cadence (1–60), **not** an inferred native
frame rate or replay of source observation times. Primary/secondary pictures are
placed left/right, with Y/U/V rows concatenated for `yuv420p`. Both lenses and all
selected pairs must have the same even dimensions. No resize, colorspace
conversion, overlays or orientation/layout inference is performed.

`render_take` identifies a queue consumer, not an observed display callback.
Only `render_queue_taken` actions select pixels. Map order selects output order;
`at_ms`, raw picture time, corrected media time and decoder PTS do **not** pace
the preview pipe. The rawvideo ffplay process applies the caller's fixed cadence;
its internal buffering/scheduling is not the native player policy. There are no
speaker samples (`-an`), subtitles (`-sn`), VQE, A/V synchronization or scheduler
drop/tick simulation. Inspect/mapped decoder mode remains available without any
output process.

## Ownership and failure handling

1. Validate bounded local input while decoding both tracks. Copy each validated
   borrowed host frame into one private temporary pixel file; retain exact
   fingerprints and per-track identities, not decoder object references.
2. Validate the **complete** header map, picture coverage, selected pair geometry
   and explicit queue takes before launching ffplay. Wrong bindings or absent
   consumers fail without opening an output process.
3. Read selected pixels back by identity, recheck their hashes, compose one pair
   and retain it until its entire OS pipe write completes. Short writes do not
   advance to the next pair; repeated source offers retain explicit identities.
4. Close input and wait for ffplay on completion. On failure/cancellation, terminate
   the child, escalating to kill and reap after a bounded wait. Close temporary
   storage on success, map rejection, output error and cancellation. No decoded
   pixel file is retained as an artifact.

The source decoder has a new internal `consume_frame(metadata, frame)` observer;
its default retains no pixels. Metadata passed to the observer is a separate dict.
The frame is borrowed only during that call. This permits host pixel copying
without changing the decoder's default inspection/mapping CLI behavior. It is
not a native decoder-buffer return/release callback.

`--deadline` is 0.1–30 seconds (default 5) for each paired pipe write and final
child drain. Nonblocking writes poll after backpressure; interruption is handled
between ordinary operations. A one-hour output-session budget is checked between
writes. Source decode retains its cooperative 60-second packet-boundary budget;
these are not hard interrupts or a resource sandbox around FFmpeg.

Inherited decode/header limits still apply. Temporary copied pixels are capped
at 402,653,184 bytes (268,435,456 luma pixels in `yuv420p`); a composed pair is at
most 8,388,608 luma pixels. There is one pair in flight, no additional producer
ring and no silently synthesized queue admission or EOF drain.

## Receipt semantics

The exclusive JSON receipt is never overwritten. Success, failure and cancellation
record status/error, the planned pairs, completed writes, current pair, accepted
partial byte count and remaining planned pairs. When source-map validation
succeeds, the receipt also includes decoder versions, decoded fingerprints,
offer bindings and the full staging result, including unaccepted/orphaned and
boundary-pending work. Invalid maps need not produce trusted source provenance.
Failure to write the receipt itself is reported on stderr; it is not success.

Each started/completed write retains pair/offer/decoded IDs, original primary
media time and observed consumer time. Completion records include the composed
pixel digest, exact byte length and host monotonic timestamp. A fully written
pair followed by child-drain failure remains **pipe-written**, not displayed.

`pipe_completion_is_display`, `physical_lip_sync_measured`,
`decoder_buffer_ownership_verified` and `native_header_provenance_verified` are
always false. Neither a zero child exit nor a completed pipe write proves which
pixels reached a physical panel. Closing temporary host storage does not prove
Android/native buffer ownership.

Tests cover exact plane composition, independent pixel ownership, changed/short
storage, geometry limits, partial writes, deadlines, broken pipe, cancellation,
child terminate/kill/reap and failure receipts. Optional real integration decodes
a tiny synthetic two-track HEVC clip and uses ffplay with **SDL dummy video/audio
drivers**: two explicitly consumed pairs are pipe-written, one remains queued.
This exercises real output transport, not a visible window or physical display.
Future work remains native-source metadata binding, real scheduler/output
integration and optical/acoustic validation.
