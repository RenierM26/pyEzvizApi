# Local paired HEVC decode adapter (development only)

`tools/app_video_decode.py` decodes two explicitly selected tracks from a **clear
local MPEG-TS or Matroska** file. It fingerprints real decoded pixels and can join
an explicit source-header map to the [two-lens staging model](app-video-pairing.md).
Production capture/remux, audio, scheduler defaults and dependencies are unchanged.

Optional development dependency: `python -m pip install av` (validated with PyAV
19.0.1). There is no camera/network login, decryption, Android decoder integration,
compositor, video window, speaker output or pacing. This adapter releases host
frames after hashing; it does not replicate native decoder-buffer ownership.

## Inspect first

```sh
python tools/app_video_decode.py paired.mkv --container matroska \
  --primary-stream 0 --secondary-stream 1 > decoded.json
```

Indices are absolute container stream indices, not video ordinals. Both selected
tracks must be HEVC with declared dimensions and produce supported frames.
Inspection produces one JSON report, **no staging events**. Each `decoded_frames`
entry includes:

- `decoded_id`: `video:<stream_index>:<per-track-decoded-index>`; a local identity,
  not a native picture counter or pairing key.
- Exact `source_pts`, `time_base_num`, `time_base_den`, dimensions and pixel format.
- `pixel_sha256`: SHA-256 over visible Y, then U, then V rows of decoded `yuv420p`,
  excluding allocation/stride padding. No colorspace conversion is performed.

Decode/demux order is retained in this inspection list. Frames returned during
end-of-track decoder flushing retain their own stream identity. Both tracks need
explicit nonnegative, nondecreasing presentation timestamps (equal PTS is allowed).
Negative/missing/backward times are rejected, not silently repaired.

## Explicit header join

A remux does **not** preserve all native raw picture timestamps, corrected app
clock values, offer identities or queue arrival order. None are reconstructed
from PTS, ordinal, codec cadence or host decode timing. Use an independently
identified source-header map. The tool cannot authenticate those caller assertions;
`native_header_provenance_verified` remains false, even after a successful join.

A header map is JSONL in caller-observed order, using the staging event contract.
Every `lens_picture` additionally requires the five exact binding fields from
inspection: `decoded_id`, `source_pts`, `time_base_num`, `time_base_den`,
`pixel_sha256`. For example (replace the placeholder digest with the real value):

```json
{"kind":"lens_picture","at_ms":12,"id":"offer:0","lens":0,"raw_time":42,"media_ms":0,"frame_number":7,"decoded_id":"video:0:0","source_pts":0,"time_base_num":1,"time_base_den":1000,"pixel_sha256":"<decoded visible-pixel SHA-256>"}
```

```sh
python tools/app_video_decode.py paired.mkv --container matroska \
  --primary-stream 0 --secondary-stream 1 --header-map headers.jsonl > mapped.json
```

The binding checks decoded identity, exact integer PTS/time-base representation,
pixel digest and declared primary/secondary track. It does **not** replace raw or
corrected media headers with decoded PTS. It also does not prove that two files
are from the same camera simply because timestamps match.

Every decoded picture must appear in at least one offer; silently unused decoded
pictures reject the map. Intentional repeated offers can bind the same decoded
picture with distinct offer IDs, as required by staging's explicit retry contract.
`stage_push` and `render_take` have no extra binding fields. Unknown fields, invalid
ordering, omitted bindings and stale/wrong-track/different-pixel bindings reject
the replay. No output JSON is written until all decoding and map validation pass.
A failed output write can still leave a partial JSON transport record; exit 2 is
not a complete success, and output backpressure is bounded to five seconds.

Mapped output includes normalized `events`, the staging `pairing` report and
`offer_bindings` linking each offer ID back to its decoded fingerprint identity.
Its nested `simulator_event` projections can be passed to the scheduler along with
independently observed ticks/elapsed readings. Decoder order is **not** substituted
for map order. Queue consumers and staging pushes are explicit, not invented to
drain the file. EOF preserves pending work. No scheduler ticks are synthesized.

## Limits and scope

- Two selected HEVC tracks; even-sized `yuv420p`, at most 4096 on either dimension
  and 8,388,608 luma pixels per frame. No automatic pixel format conversion.
- Nonempty regular local input at most 256 MiB, fixed to its open-time size even
  if another process appends. Only explicit MPEG-TS/Matroska demuxers are used.
- At most 100,000 packets, 4 MiB per encoded packet, 10,000 decoded frames and
  268,435,456 cumulative decoded luma pixels. One decoder thread per track.
- A 60-second budget is checked between packet decode calls, not a hard interrupt
  or memory sandbox around FFmpeg. Local decode is not a native latency measure.
- Header maps retain staging's 10,000-event / 8,192-byte-line / one-hour bounds;
  metadata and actions are bounded. No media payloads or pixels enter staging.

Unit tests check stride-padding exclusion, exact binding, wrong-track/header
rejection, observed order, retries, coverage and pending work. Optional real-media
integration creates a tiny synthetic two-track HEVC Matroska file, decodes six
pictures, joins reverse-lens offers into three queued pairs and rejects a changed
pixel digest without success output. When FFmpeg is available, all six tightly
packed decoded pixel hashes are also compared with its independent rawvideo output.
This is not app-equivalent decoding, fresh native tracing or physical A/V sync.
