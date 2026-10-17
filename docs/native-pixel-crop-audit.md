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
`ordered_plane_sha256`, never U/V labels, and always reports
`chroma_order_verified: false`.

A successful receipt establishes equality under this explicit crop operation and
caller-provided descriptors; it does not authenticate provenance, prove native
memory ownership, cover uncaptured frames, prove physical display, or measure
lip sync. The tool does not turn these snapshots into a colour-correct playback
source or substitute footage from another session. Existing scheduler replay,
HEVC decoding, previews and scheduled export are unchanged.

`tests/fixtures/app_native_crop_oracle.json` stores only the three synthetic
controls' geometry, output lengths and SHA-256 digests from original ARM execution.
The tested library SHA-256 is
`a719ac549516df28345536d7baf1cc22145996949e89f8c7fae2dc73a379cddc`.
Control input planes use `(i*17+3)%256`, `(i*7+51)%256`, `(i*11+149)%256`
respectively. These are arithmetic patterns, not captured imagery.
