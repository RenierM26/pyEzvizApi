# Native input/render pixel audit (development only)

`tools/app_native_pixel_audit.py` validates a narrow native-buffer boundary,
without playback, PyAV, decoding, device access, or changes to capture/remux.
It accepts two local concatenated snapshot files and a caller-supplied JSONL map:

```sh
python tools/app_native_pixel_audit.py input.bin render.bin crop-map.jsonl
```

Every manifest line describes one input/render sample:

```json
{"id":"sample:0","input_header":[49],"render_header":[49],"input_offset":0,"render_offset":0,"input_sha256":"...","render_sha256":"..."}
```

`[49]` is a placeholder: each header must contain **all 49 uint32 words** from
its 0xc4-byte native descriptor. The tool does not read paths from the manifest.
Offsets must describe contiguous, nonoverlapping coverage of both files in manifest
order. Every byte must be accounted for. IDs must be unique and at most 128 characters.
Hashes must be lowercase SHA-256 digests of each complete original snapshot.

## Supported boundary

This deliberately supports only the observed software two-track header profile:

| Header word | Meaning/constraint |
| --- | --- |
| 0 | Observed value 3 |
| 1 | Lens identifier 224 or 225 |
| 3, 4 | Input width, coded height |
| 5, 7, 10 | Media milliseconds, raw timestamp, frame index; preserved verbatim |
| 33, 34, 35 | Observed values 133, 3, 2 |
| 37, 38 | Coded width and height, equal to input dimensions |
| 39 | Even bottom crop, smaller than coded height (zero allowed) |
| 40, 41, 42 | Left, right and top crop: all zero |

Only render word 4 may change, to coded height minus bottom crop. **Every other
header word must match**, including opaque descriptor fields. Those opaque fields
are not included in the output receipt.

Buffers must have exact planar 4:2:0 byte counts: `width * height * 3 / 2`.
The comparator removes bottom rows independently from luma and both ordered
quarter-size chroma planes, then requires byte equality with the render snapshot.
It does not interchange planes, deinterleave chroma, resize, invent timestamps,
or repair headers. Unsupported cases fail closed.

Bounds: even dimensions up to 4096, at most 8,388,608 coded luma pixels per
snapshot, 32 samples, 8 KiB per manifest line, and 256 MiB combined snapshot bytes.
File opening uses the existing fixed-open-size bounded reader and rejects
nonregular or oversized files. Later file growth cannot extend validated EOF.

## Evidence and limits

The reference Android build's actual `CPostProcess::PostProcess_CropPicture`
was observed changing 2880×1624 input descriptors to 2880×1620 and returning
6,998,400 output bytes. In a separate bounded same-session sample, both lenses'
input and render snapshots pass the exact ordered-plane comparison, including
all header words except height. The native ARM crop routine also matched three
synthetic distinct-plane controls (8×8, 16×12, 32×16 with bottom crops 2, 4, 6);
allocator/logging/memory-copy boundaries were harnessed, not the crop arithmetic.
Private camera pixels and native binaries are not repository fixtures.

**The real sample has uniform 128 chroma. It cannot distinguish U/V order or
planar versus semiplanar interpretation by image bytes alone.** The actual native
crop path and synthetic controls establish the ordered-planar crop operation,
not a colour-label mapping for the real buffer. The receipt therefore uses
`ordered_plane_sha256`, never U/V labels, and in default crop-only mode reports
`chroma_order_verified: false`.

A successful receipt establishes equality under this explicit crop operation and
caller-provided descriptors; it does not authenticate provenance, prove native
memory ownership, cover uncaptured frames, prove physical display, or measure
lip sync. The tool does not play or export these snapshots or substitute footage from
another session. Existing scheduler replay,
HEVC decoding, previews and scheduled export are unchanged.

`tests/fixtures/app_native_crop_oracle.json` stores only the three synthetic
controls' geometry, output lengths and SHA-256 digests from original ARM execution.
The tested library SHA-256 is
`a719ac549516df28345536d7baf1cc22145996949e89f8c7fae2dc73a379cddc`.
Control input planes use `(i*17+3)%256`, `(i*7+51)%256`, `(i*11+149)%256`
respectively. These are arithmetic patterns, not captured imagery.

## Opt-in renderer plane binding

A later combined same-session input/render/renderer trace established that the
observed software path uses **renderer format 1** with YV12 storage (`Y, V, U`).
For each captured lens sample, the renderer input pointer matched the sampled
native node payload and its SID/raw/frame identity matched the saved descriptors.
Three single-channel uploads use offsets `0`, `5*W*H/4`, `W*H`, bound respectively
to `Ytexture`, `Utexture`, `Vtexture` at texture units 0, 1, 2. The observed shader
reads those named samplers as Y, U, V. The grayscale pixels alone still do not
establish this ordering; the renderer path does.

To validate those explicit caller observations and emit canonical **YUV420P**
fingerprints (`Y, U, V`) without outputting or playing pixels:

```sh
python tools/app_native_pixel_audit.py input.bin render.bin renderer-map.jsonl \
  --verify-yv12-renderer
```

Each original sample line must additionally contain a `renderer_layout` object.
This 8×6 example shows its complete required shape (adapt dimensions, offsets,
identity and texture IDs from the actual observations):

```json
{
  "renderer_format": 1, "width": 8, "height": 6,
  "sid": 224, "raw_timestamp": 3000, "frame_index": 1,
  "payload_matches": true,
  "uploads": [
    {"offset": 0, "width": 8, "height": 6, "format": 5, "texture": 1},
    {"offset": 60, "width": 4, "height": 3, "format": 5, "texture": 2},
    {"offset": 48, "width": 4, "height": 3, "format": 5, "texture": 3}
  ],
  "samplers": [
    {"name": "Ytexture", "unit": 0, "texture": 1},
    {"name": "Utexture", "unit": 1, "texture": 2},
    {"name": "Vtexture", "unit": 2, "texture": 3}
  ]
}
```

The format numbers belong to different native APIs: renderer format 1 is not
header word 0 (3), nor single-channel texture upload format (5). Other renderer
formats, mismatched identities, nonmatching payload assertions, different upload
offsets/sizes, missing/extra planes, reused texture IDs or swapped samplers fail.
Texture IDs must be distinct positive uint32 values; bools are not integers here.
Every sample requires observations; no fallback from one lens or frame to another.

Only this opt-in mode sets `chroma_order_verified: true`, with the explicit source
`caller-render-observations-native-format-1-profile`. This means the **provided
observations match the supported native renderer profile**, not that the tool
authenticated their origin. Each sample adds `native_pixel_format: "yvu420p"`,
`canonical_pixel_format: "yuv420p"`, `canonical_pixel_sha256`, and
`canonical_plane_sha256` in Y/U/V order. No timing fields are synthesized.
Crop-only mode does not interpret optional layout fields and emits no canonical
fingerprints. Colour-space/range/transfer calibration and physical display remain
unverified; these hashes do not claim matching RGB appearance on another player.

`tests/fixtures/app_native_texture_oracle.json` retains two synthetic original-ARM
upload-selection controls. On the same binary build, the format-1 branch at
`0x213550` selects offsets `0, 5*N/4, N`; format-3 at `0x21359e` selects
`0, N, 5*N/4` (`N=W*H`). Tests reject the latter as a format-1 observation. The
harness executes only these original selection branches, intercepts upload calls
to record their arguments and hashes, and stops before render-to-target. It is
not a GPU or full-renderer oracle. Shader sampler semantics come from the live
renderer trace, not from helper names or grayscale image guesses.
