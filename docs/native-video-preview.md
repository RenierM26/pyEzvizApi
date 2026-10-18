# Paced native snapshot preview (development only)

`tools/app_native_video_preview.py` sends fully audited native pixels to a bounded
SDL2 video-only worker. It replays **recorded, completed scheduler selections**
with host wall-clock gaps derived from request-observation timestamps. It is not
live camera input, an Android renderer, an audio backend or a physical A/V sync
measurement. Production capture/remux, audio and scheduler policy are unchanged.

```sh
python tools/app_native_video_preview.py input.bin render.bin renderer-map.jsonl \
  --event-map observed-events.jsonl --play --layout side-by-side \
  --timing request-observation --anchor first-request --receipt new-preview.json
```

Requirements: POSIX, Python and an optional **system SDL2 runtime**. No PyAV,
FFmpeg, fixed-FPS encoder or new production Python dependency is required.
Missing/failed SDL initialization produces a failed receipt and reaps the worker.
For headless transport/API verification, set `SDL_VIDEODRIVER=dummy`; this does not
show a visible window or validate a physical display. A real window requires the
caller's working desktop/video environment. The tool does not configure one.

## Validate before opening output

Source snapshots, crop/format-1 renderer manifest, canonical spool hashes and
explicit observed queue/clock events use the same contracts and limits as the
[native scheduled artifact tool](native-scheduled-video.md). The entire input and
selection plan validates before any SDL worker starts. Only selections with a
recorded matching completion can be presented; in-flight/queued/reserved work at
EOF stays in the source receipt. No native completion is invented from an SDL call.

`--allow-metadata-only` optionally retains unsampled native offers under the
existing exact full-header contract. They can explain pending, orphaned, rejected
or dropped work. Both lenses of **every completed selection** still need audited
pixels; otherwise the whole preview fails before opening output. No omitted
unbound completion, duplicate replacement or EOF drain is allowed.

## Explicit host timing

`--anchor first-request` intentionally removes the initial observation-to-first-
request delay. After validation, worker startup and first-pair composition, the
first selected request is anchored to a new host monotonic time. Later targets
are absolute:

```text
host_target = host_anchor + (request_at_ms - first_request_at_ms) × 1,000,000 ns
```

For requests at 70/155/400 ms, targets are 0/85/330 ms from the host anchor. They
are not paced by source media timestamps, native elapsed values, completion times,
a fixed frame rate or the previous host call's return time. Source timestamps are
retained verbatim in the receipt. No speed scaling, timer extrapolation or timing
repair is performed. All source replay occurs offline before host output starts;
this is paced snapshot replay, **not live scheduler/input integration**.

`--max-late-ms` (default 250, range 1..30000) limits how late the host may **submit**
a frame relative to its target. Exceeding it fails; it does not silently drop or
retime a frame. Composition, IPC, worker hashing, SDL conversion and OS scheduling
can introduce additional delay. This is not a bound on physical presentation,
and the SDL call can return after the submission-lateness budget. Recordings made
under instrumentation may themselves have perturbed timing.

`--final-hold-ms` (default 500, range 0..30000) keeps the final texture/window open
for a caller-controlled **host-only** hold before cleanup. It is not a source
frame duration or an additional native completion. Set it to 0 for no final hold.
The window-close event stops output, including while waiting for a later target.
No clock drift correction, optical measurement or source/audio synchronization is
claimed.

## Worker, pixels and deadlines

The worker owns an SDL software renderer and streaming IYUV texture. It initializes
only SDL's video subsystem; it never opens a speaker. The full-resolution canonical
Y/U/V picture is composed left/right with no source resizing. Its texture is shown
in a window capped at 1280 pixels wide with preserved aspect ratio. SDL's YUV/RGB
conversion, scaling and software renderer are **not** the native Android compositor
or proof of RGB/color calibration. Geometry is retained in the receipt.

One private inherited Unix socket connects the parent and worker. Bounded JSON
commands identify the exact pair, expected byte count and canonical composed hash;
the worker receives the complete payload and verifies its hash before updating
SDL. Acknowledgements repeat pair/hash/byte identity and worker monotonic times
before the host present call and after its return. They are not optical/display
feedback. A failed/unacknowledged call remains pending and may already have reached
SDL; it is never counted as acknowledged success or retried automatically.

`--deadline` (default 5, finite range 0.1..30 seconds) bounds worker startup, each
frame's nonblocking IPC/acknowledgement exchange and final shutdown independently.
A stalled native SDL call is isolated in the subprocess; failure/cancellation
closes its socket, terminates it, escalates to kill if needed, and reaps it. Parent
source verification/composition and cleanup are not hard-real-time operations.
Waits poll at most every 20 ms; ordinary process scheduling may add delay.

Additional preview limits: 32 completed requests, strictly increasing request
observations spanning at most 60 seconds, 8 KiB protocol messages, and the inherited
16,777,216 paired-luma-pixel/268,435,456 total selected-pixel caps. Metadata, source
snapshot/spool and queue-event limits remain unchanged. The frame count is an
explicit preview cap, including repeated offers; it is not inferred from snapshot
count. The final hold and operation deadlines are separate from the request span.

## Receipts and evidence

The exclusive receipt is opened before validation and never overwrites an existing
path. It retains full source audit/replay and pending work, the verified plan,
source/request/completion timestamps, host anchor/targets/submissions/lateness,
worker acknowledgement timestamps and hashes, selected SDL driver, output geometry,
completed host-call count and any pending/unattempted pairs. Failed finish/cleanup
does not erase acknowledged earlier calls. Receipt I/O itself is not atomic with
what SDL may already have shown.

`host_present_return_is_physical_display`, `physical_lip_sync_measured`,
`native_header_provenance_verified` and `decoder_buffer_ownership_verified` remain
false. No physical output was tested for this increment. Synthetic distinct-chroma
controls verify exact SDL plane addressing, absolute cadence, late/error/cancel and
IPC lifecycle handling. An actual dummy SDL run of the retained real same-session
5760×1620 native pair acknowledges 13,996,800 bytes with the same canonical hash
previously verified independently through FFmpeg/FFV1. Its concurrent unsampled
pair remains reserved in the source ledger. The dummy worker exits and is reaped.
Neither that run nor synthetic timing tests prove a visible window, native RGB
mapping, physical presentation latency or lip-sync. Live input/output integration
and physical A/V validation remain later work.

For incremental producer-pipe delivery of native selections and actual upstream
VQE output (rather than a fully loaded snapshot plan), see the experimental
[reference-assisted live A/V handoff](live-native-av.md). The reference app remains
required; physical output is a separate validation step.
