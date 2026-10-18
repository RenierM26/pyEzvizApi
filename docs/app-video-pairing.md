# Two-lens video staging (development only)

`tools/app_video_pairing.py` models the retained H9c two-lens **metadata staging
lifecycle before scheduling**. It does not decode/compose pixels, own decoder
buffers, open a camera, display video or synchronize a speaker. Production
capture/remux, the existing scheduler simulator and audio tools are unchanged.

```sh
python tools/app_video_pairing.py < lens-events.jsonl > pairing.json
```

This explicit profile has HEVC/native codec 133, two lens slots corresponding to
stream IDs `0xe0`/`0xe1`, non-null/nonempty assigned decoded payloads, four usable
staging positions and six render-queue positions. Pause/frame-skip/single-buffer
special modes and sublist callbacks are outside the model. A source adapter must
validate this profile; zero-valued header fields alone do not identify a control
call or invalid frame.

## Input contract

Every JSONL event requires integer `at_ms` on one nondecreasing observation clock.
Equal times preserve input order. Media time is **not** an arrival clock.

| kind | Additional required fields | Meaning |
|---|---|---|
| `lens_picture` | `id`, `lens`, `raw_time`, `media_ms`, `frame_number` | Offer one already-decoded lens picture |
| `stage_push` | none | Explicitly attempt transfer of completed staging nodes into render-queue space |
| `render_take` | none | Remove one render-queue pair, or record empty; **not a display callback** |

`lens` is integer 0/1; raw/media/frame values are uint32. `id` is a unique offer
identity of 1–128 characters, including unaccepted offers. It is separate from raw
picture time/frame number. An intentional retry must be another explicit event
with a new offer ID; its original source header fields can remain unchanged.
Unknown/missing fields, duplicate offer IDs, unsupported lens values and invalid
observation time reject the entire offline replay with exit 2 and no success JSON.

Limits: 10,000 events, 8,192 bytes per JSONL line, one simulated hour. Identity/action
history is bounded by the event limit. No pixels or media payloads are accepted.
EOF preserves all pending partial/complete/discard-marked staging nodes and queued
pairs; it does not synthesize a drain, retry or orphan cleanup.

## Native matching and lifecycle

- Each input first tries to push completed staged work. Matching searches the
  uncommitted staging positions in order.
- An empty position can accept either lens. A partial node matches only if the
  incoming lens slot is absent and an existing lens's **raw picture time** agrees.
  Corrected media time and frame number are not used by this matching branch.
- Therefore, either arrival order works; raw zero is valid. Equal media times do
  not pair different raw times. Different media times/frame numbers can pair when
  raw time matches. Both original lens headers remain attached to the pair.
- Repeated input for an already-occupied lens does not overwrite that slot. It can
  create another partial node, even with identical raw/frame metadata. The model
  does not deduplicate purported camera retries.
- Completing a later pair can mark earlier incomplete nodes for discard. Only
  discard-marked FIFO heads are removed; complete pairs are preserved. Orphaned
  lens identities are reported separately from scheduler drops.
- Completed consecutive nodes are committed and transferred FIFO while the
  six-pair render queue has space. Staging commit state is retained separately.
- With no match and full staging, native result `0x80000007` is reported for the
  incoming offer. Cleanup may also remove an older partial head. The incoming
  picture is **not automatically retried or queued**. This is not a generic
  drop-newest rule and does not prove what an external decoder caller does next.
- Taking a render pair does not itself push staging. A subsequent explicit push
  or lens input can transfer work. Blocked output and boundary-pending pairs are
  not silently labeled losses.

Output state numbers mirror the native helpers: 1 partial, 2 complete, 3 discard-marked.
`lens_input_unaccepted`, `lens_orphaned`, `render_queue_admitted` and
`render_queue_taken` actions distinguish these outcomes. A generated `pair:N` ID
identifies the assembled pair within this replay; it is not a native app ID.

Example: completing picture 200 discards the earlier unmatched primary 100:

```jsonl
{"kind":"lens_picture","at_ms":0,"id":"main:100","lens":0,"raw_time":100,"media_ms":0,"frame_number":1}
{"kind":"lens_picture","at_ms":1,"id":"main:200","lens":0,"raw_time":200,"media_ms":66,"frame_number":2}
{"kind":"lens_picture","at_ms":2,"id":"second:200","lens":1,"raw_time":200,"media_ms":66,"frame_number":2}
{"kind":"render_take","at_ms":3}
```

## Scheduler integration and ownership limits

Each render admission includes a nested `simulator_event` with the exact
`video_picture` shape accepted by the [scheduler simulator](app-playback-simulator.md).
It carries the pair ID, both offer labels and the **primary** lens's media time.
The complete primary/secondary headers remain separately in `pair.lenses`.

Pairing does not repair continuity or invent scheduler ticks. The downstream
simulator still requires already-repaired, nondecreasing video media times. Do
not sort away source discontinuities or infer native timer readings from PTS.
`render_take` is merely a queue-consumer observation; scheduler policy and output
backpressure/display completion remain separate layers.

The native buffer-return helper can be invoked with reused/stale slot pointers.
Counting all such calls as unique lost lens pictures would be incorrect. The
oracle checks orphan identities at the actual discard-marked staging dequeue,
not raw helper-call counts. `decoder_buffer_ownership_verified` and
`physical_lip_sync_measured` are always false. Real decoder release callbacks,
OpenGL/compositor behavior, pixel composition and physical presentation are not
replicated here.

## Verification

`tests/fixtures/app_pairing_native_oracle.json` contains 26 synthetic cases with 707
normalized events and original-ARM outcomes, no camera/account data or executable
binary. Cases cover reverse arrival, raw/media/frame distinctions, duplicates,
zero raw time, later completion, full staging, explicit retry, repeated wrap and
six-pair output backpressure. Tests compare identities, queues, commit state and
admission/error/discard/consumer outcomes.

A separate private differential audit compared an independent model with the
retained original ARM code after **4,000 state transitions across 50 seeds**, all
matching. Original input/match/fill/copy/cleanup and CDataCtrl/CDataList code ran;
allocator, mutex/log, decoder-buffer-return and sublist dependencies were stubbed.
A render consumer dequeued metadata without any Android renderer. The native
vtable staging target was checked against ELF relocations. The native ring uses
five positions for four usable staging slots; logical capacity is not latency.

These are native-code policy oracles, not fresh live-app or optical/acoustic
measurements. Control-call arguments missing from older traces are not inferred.
A live paired-decoder source adapter and actual video/output lifecycle integration
remain separate work.

## Local decoded source

The optional [local HEVC decoder adapter](app-video-decode.md) fingerprints two
real decoded tracks and validates explicit header bindings before staging.
Original raw pairing headers and arrival order must be supplied; remuxed PTS and
host decode time do not recreate them. It is not a native decoder-buffer owner
or a video output backend.
