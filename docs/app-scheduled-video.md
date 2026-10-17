# Scheduled paired-video artifact (development only)

`tools/app_scheduled_video.py` couples the [two-lens staging model](app-video-pairing.md)
with the existing **explicit native-clock replay** and real decoded pixels. It
exports completed selections as a lossless FFV1 Matroska artifact. It does not
open a display, speaker or camera and is not a real-time A/V playback backend.
Production capture/remux, audio and simulator policy are unchanged.

## Explicit inputs

Requirements: POSIX hard-link publication, optional PyAV (validated with 19.0.1),
a clear bounded local MPEG-TS/Matroska file with two selected HEVC tracks, and an
independently identified unified event map. Use the
[decoder inspection workflow](app-video-decode.md) to obtain exact picture
fingerprints; it does not reconstruct native raw headers or arrival clocks.

```sh
python tools/app_scheduled_video.py paired.mkv --container matroska \
  --primary-stream 0 --secondary-stream 1 --event-map unified.jsonl \
  --pts-clock request-observation --output new-scheduled.mkv --receipt new-receipt.json
```

The unified JSONL map has one nondecreasing observation clock. Equal observation
times preserve line order. Accepted events are:

- `lens_picture`: the decoder's exact header binding contract (including decoded
  ID, PTS/time base, pixel digest and declared lens). Caller supplies raw pairing
  time, already-repaired media time, frame counter and unique offer identity.
- `stage_push`: explicitly attempt staged-to-render transfer. Consuming a render
  node does not automatically push blocked staging work.
- `video_epoch`, `video_unavailable`, `video_observed_tick`,
  `video_display_complete`: the exact existing
  [native-clock replay contract](app-playback-simulator.md), including independently
  supplied epochs/timer snapshots, head identity, queue depth, speed and bias.

Caller `render_take`, `video_picture`, autonomous `video_tick`, audio events and
unknown fields are rejected. The coupling generates admissions from genuine
assembled staging pairs and queue takes from model-derived drops/selections.
It does not generate native timer ticks, epochs, retries, completions or EOF drains.
Both queue identity lists are checked after every external event. Source order,
not a timestamp sort, determines admission/consumption order.

For example, when a late native-clock tick drops two older queued pairs and
requests the third, all three FIFO nodes are consumed, but only the requested
pair can become an artifact frame. A later matching display-completion event
is required. New admissions while a request is in flight remain separate queue
work; completion uses the observed post-display queue depth for speed adaptation.

Every decoded picture must have at least one explicit offer. Header authentication
is still out of scope: model agreement and matching pixels/PTS do not prove that
the supplied native observations genuinely occurred.

## Artifact timing and pixels

Only requests with explicit matching completions are exported. An in-flight
request at EOF is preserved in the receipt, not silently completed or encoded.
Hold decisions, dropped pictures, unaccepted/orphaned lenses and pending queues
remain in the model ledger. No completed requests means failure with no artifact.

`--pts-clock request-observation` explicitly chooses the request's **observation
`at_ms`** as output PTS, with a 1/1000 time base. This is not native elapsed time,
source media time, the later completion timestamp or a physical display estimate.
Request PTS must be strictly increasing for this artifact profile; duplicate
request timestamps reject rather than silently shift/deduplicate frames. The
first timestamp is retained, not independently re-zeroed. The container's nominal
rate/default duration does not define this variable-PTS sequence or final hold
length. A downstream player can normalize its start time or buffer/drop frames;
this tool does not guarantee wall-clock replay or preserve an initial panel delay.

Primary/secondary visible `yuv420p` rows are composed left/right with no resizing,
colorspace conversion, overlay or inferred native layout. Selected pairs require
constant equal lens dimensions. FFV1 encoding is lossless; the receipt records
expected composed-pixel SHA-256 and exact artifact PTS for each frame. No source
HEVC headers/payloads are copied into the artifact and no audio is muxed.

## Publication, ownership and bounds

Decoded pixels use the preview's bounded private temporary spool, never native
Android buffer ownership. The entire source/map/selection plan validates before
encoding. Matroska is written to a private temporary file in the destination
directory, closed/flushed/fsynced, then published with an exclusive hard link.
Existing files and publish-time collisions are never overwritten. Ordinary
encode/validation/cancellation failures remove owned staging files and do not
publish a partial artifact. A failure after publication (including receipt I/O)
is not an atomic rollback of the already published artifact; publication state
is recorded when available.

Inherited input, per-frame, packet, header-line and source-pixel limits apply.
The unified input and each component independently retain their 10,000-event
bounds; generated admissions/takes count toward their component limits. Total
exported luma pixels are separately capped at 268,435,456, so repeating offers
cannot amplify bounded source pixels into unlimited encoding work. Each composed
pair is at most 8,388,608 luma pixels. Encoded output is checked against 512 MiB
between frames and after mux close; unpublished temporary output can overshoot
by a mux write. The encode session has a cooperative 60-second budget checked
between frames and before publication, not a hard interrupt or FFmpeg sandbox.

The exclusive receipt records status/error, publication state, decoder versions,
source fingerprints/bindings, both model ledgers, completed selection plan and
any boundary-pending request. Failures before map validation need not contain
trusted replay provenance. A completed artifact is **not** a completed physical
display. `artifact_is_physical_display`, `physical_lip_sync_measured`,
`native_header_provenance_verified` and `decoder_buffer_ownership_verified` stay
false. Real-time scheduling/output, authenticated native-source binding and
optical/acoustic validation remain separate work.

## Evidence

Tests exercise hold/late-drop decisions consuming the same staging FIFO, explicit
push under backpressure, in-flight EOF preservation, native-state/binding errors,
source order, limits, strict observation PTS and publish/cancel/collision cleanup.
Actual synthetic two-track HEVC yields a lossless 128x48 paired FFV1 artifact with
PTS **70, 155, 400 ms**, distinct from source media times **0, 66, 132 ms** and native
elapsed/completion readings. PyAV and independent FFprobe verify frame timestamps;
PyAV and FFmpeg rawvideo hashes match the expected composed pixels. These are
synthetic local-media checks, not a fresh native trace or physical display test.
