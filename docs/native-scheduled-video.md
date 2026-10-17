# Scheduled native-snapshot video (development only)

`tools/app_native_scheduled_video.py` connects the verified
[native crop/renderer boundary](native-pixel-crop-audit.md) to the existing
[observed queue scheduler and lossless artifact exporter](app-scheduled-video.md).
Unlike the HEVC source tool, it uses the actual caller-supplied native input and
render snapshots, not footage from a different session or reconstructed headers.
It opens no camera, display or speaker and changes no production capture/remux.

```sh
python tools/app_native_scheduled_video.py input.bin render.bin renderer-map.jsonl \
  --event-map observed-events.jsonl --pts-clock request-observation \
  --output new-native-scheduled.mkv --receipt new-receipt.json
```

PyAV is optional and required only for FFV1 encoding, not snapshot verification,
binding or scheduler replay. Production dependencies remain unchanged.

## Native source binding

Every snapshot must pass the complete crop audit **and** per-sample format-1
renderer validation. There is no crop-only fallback. A borrowed canonical Y/U/V
copy is handed to a bounded private host spool only after that sample validates;
the entire manifest, byte coverage and event map must validate before encoding
or publication. Failure on a later sample discards the private spool. Spool
writes and subsequent reads check lengths and SHA-256. No Android memory
ownership or decoder-buffer release is implied.

Each `lens_picture` event has exactly these fields:

```json
{"kind":"lens_picture","at_ms":0,"id":"offer:0","sample_id":"sample:0","lens":0,"raw_time":3000,"media_ms":66,"frame_number":1,"pixel_sha256":"..."}
```

`sample_id` selects one audited manifest sample. `pixel_sha256` is its canonical
YUV420P digest. Lens, raw timestamp, media milliseconds and frame number must
equal the audited native descriptor, with exact integer types (not bool/float).
Lens 0 corresponds to native SID 224 and lens 1 to SID 225. No codec stream,
decoded index, PTS or time base is invented; codec-binding fields are rejected.
`id` identifies the unique offer, while explicit retries may reference the same
sample using another offer ID. Every audited sample must have an explicit offer,
even if staging leaves it orphaned, unaccepted or pending.

The two-lens staging model pairs **equal native raw timestamps**, not matching
frame numbers, nearby media times or manifest adjacency. Different raw timestamps
do not form a pair. Geometry is checked before artifact encoding and must remain
constant and equal across selected lenses. Actual output is explicit side-by-side
YUV composition, not a claim about the native Android compositor or RGB calibration.

## Explicit queues and clocks

Only observed-queue mode is supported. Supply `render_admit` and `render_release`
events as well as the existing explicit native epochs, ticks and display
completions. `stage_push` is accepted for explicit staging retries. The contracts
and ordering are exactly those documented for the shared scheduler. Snapshot
presence is not an admission, queue selection is not a release, and release is
not display completion. No timer epochs/ticks, observation arrival times or EOF
drain are synthesized. External `render_take`, `video_picture`, autonomous ticks
and audio events remain unsupported.

Only explicitly completed scheduler requests are encoded. Drops consume the same
bound FIFO without producing frames; in-flight, reserved, staged and queued work
remain separately recorded. An input with no completed requests fails without an
artifact. It does not manufacture a pair or completion to make a preview work.

Artifact PTS are explicitly selected request-observation `at_ms` values at 1/1000,
not native elapsed clock, source media time, completion time or physical display.
They must strictly increase and are not re-zeroed or repaired. Lossless FFV1
Matroska publication, encode deadlines, total pixel/output limits, exclusive
hard-link publication and cleanup reuse the existing scheduled exporter. A
failure after publication is not an atomic rollback with receipt I/O.

## Receipts, bounds and evidence

The exclusive JSON receipt includes the full verified sample audit, both model
ledgers, offer-to-native-sample bindings, pending work, artifact frame selection
and composed-pixel hashes. Shared planner IDs are exposed as `native_sample_ids`,
not decoded HEVC IDs. Opaque offer IDs are retained verbatim.

Inherited source bounds: 32 snapshots, 4096 per dimension, 8,388,608 coded luma
pixels per sample, 256 MiB combined original snapshots, contiguous complete file
coverage, 8 KiB JSONL lines and 10,000 source/model events. The canonical spool
is additionally bounded to 256 MiB. Artifact limits are 8,388,608 paired luma
pixels per frame, 268,435,456 total exported pixels and 512 MiB encoded output;
the 60-second encode budget is cooperative, not a hard FFmpeg interrupt.

Successful replay authenticates neither the manifests nor their joint-session
provenance. Timing/headers/renderer observations remain caller evidence; this
tool cannot detect a caller deliberately joining separately acquired inputs.
`native_header_provenance_verified`, `decoder_buffer_ownership_verified`,
`artifact_is_physical_display` and `physical_lip_sync_measured` stay false.

Synthetic distinct-chroma controls verify the complete native snapshot → crop →
YV12-to-YUV420P → exact header binding → observed queue selection → FFV1 path.
PyAV and independent FFmpeg/FFprobe check lossless pixels and 70/155/400 ms
request-observation PTS. Those are synthetic events, not a live playback result.
The retained two private real lens samples verify canonical spooling but have
different native raw timestamps; they are **not** a pair and were not exported.
Fresh joint-session paired pixels plus clock/queue observations, real-time
output and optical/acoustic validation remain separate work.
