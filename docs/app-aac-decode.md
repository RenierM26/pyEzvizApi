# Local AAC decoder adapter (development only)

`tools/app_aac_decode.py` converts an explicitly selected **local AAC-LC audio
track** into the JSONL contract used by the [experimental PCM sink](app-pcm-playback.md).
It is not a camera connector, decryptor, live-source arrival recorder, VQE
replacement or complete audio/video player. Existing capture/remux APIs and
production dependencies are unchanged. Neither development tool is installed in
the wheel.

## Optional setup and use

Requires a POSIX, little-endian host and optional PyAV (verified with 19.0.1):

```sh
python -m pip install 'av>=19,<20'
```

Only explicit `mpegts` and `matroska` demuxers are enabled, using a bounded regular
local file object rather than a URL. Use clear MPEG-TS capture/remux output; raw or
encrypted MPEG-PS is not accepted by this adapter. Inspect the local container to
choose the **absolute stream index**, not the audio-only ordinal, for example:

```sh
ffprobe -v error -show_streams clear.ts
python tools/app_aac_decode.py clear.ts --container mpegts --audio-stream 1 \
  --manifest decode-metadata.jsonl > pcm-blocks.jsonl
```

The manifest must be a **new file**. Existing files are never overwritten. Neither
command opens a speaker. To explicitly connect the decoder to output:

```sh
set -o pipefail
python tools/app_aac_decode.py clear.ts --container mpegts --audio-stream 1 \
  --manifest another-new-manifest.jsonl \
  | python tools/app_pcm_playback.py --play --processor passthrough > playback-result.json
```

For a headless transport test, set `SDL_AUDIODRIVER=dummy` on the sink command.
`pipefail` matters: a producer may fail after emitting a valid prefix while the
sink successfully drains that prefix. Check **both** the decoder manifest's final
summary and the sink result. Missing summary means incomplete decoder provenance.

## Deliberately narrow decoding contract

- AAC-LC only, 16-kHz mono; decoded frames must have 1,024 samples, explicit PTS
  and a positive time base, with supported `fltp` or `s16` format.
- PyAV converts the sample **format only** to packed signed16 PCM at the same
  rate/layout. One source frame must produce one output frame, identical sample
  count and exact source time; unexpected conversion delay/tail is rejected.
- No resampling, time stretching, gain, VQE, fixed offset, gap filling, padding
  synthesis, frame-count-derived clock or automatic clock repair is applied.
- Each output is exactly 2,048 little-endian PCM bytes. AVFrame allocation padding
  is excluded; audio samples themselves are not truncated to change frame size.
- Missing PTS, backward decoded PTS, negative/out-of-range decoded media time,
  corrupt packets/frames and unsupported format changes stop decoding. Equal
  source PTS and forward gaps remain unchanged. Other profiles need separate work.

Output block IDs are deterministic `aac:<stream-index>:<decoded-frame-ordinal>`.
They are not encoded packet numbers. The sink's `media_ms` is the floor of the
source PTS time in milliseconds; the exact original PTS/time base remains in the
manifest, so sub-millisecond provenance is not discarded or replaced by a counter.

## Priming, source time and host observations

The manifest contains:

| kind | Evidence retained |
|---|---|
| `decoder` | PyAV and linked FFmpeg library versions |
| `packet` | Packet index, PTS/DTS, time base, encoded byte count, decoded-frame count and side-data types; `skip_samples` includes leading/trailing sample counts and reasons |
| `decoded` | Block identity, producing packet index, exact source PTS/time base, millisecond sink time, sample count, PCM SHA256 and host `decoded_monotonic_ns` |
| `emitted` | Identity and host `emitted_monotonic_ns` after its entire JSONL record was written |
| `summary` | completed/failed/cancelled status, error, full emitted-record count and partial JSONL byte count |

AAC containers/decoder versions can treat encoder priming differently. A packet
may correctly decode to zero frames because of `skip_samples`; that is not a sink
queue rejection or unexplained disappearance. Partial-frame trimming is outside
this fixed-block contract and is rejected. Negative **packet** PTS can be retained
as priming evidence even though negative **decoded-frame** times are unsupported.
Record the decoder version and skip metadata when comparing another decoder.

`decoded_monotonic_ns` observes host adapter validation/format-conversion completion;
`emitted_monotonic_ns` observes acceptance of the complete JSONL record into the
output pipe/file. Neither is an original app callback, camera/network arrival,
sink admission or hardware presentation time. These timestamps are not substituted
for source PTS. The sink records its own queue observations separately.

A file decodes as fast as output backpressure allows. It does **not** reproduce the
captured live arrival cadence and may burst into/saturate the sink. Source PTS is
metadata, not an instruction to sleep or insert silence. No A/V sync measurement
follows from the pipeline.

## Bounds and partial work

Input is a nonempty regular local file up to 256 MiB. Limits: 100,000 selected
packets, 8,192 encoded bytes per packet, 10,000 decoded blocks and one hour of
packet polling. JSONL output uses nonblocking writes with a five-second deadline
per record. This bounds output backpressure, not time spent inside an individual
FFmpeg/PyAV operation. Native decoder allocations remain owned by PyAV/FFmpeg.

The manifest records a validated decoded block **before** attempting output, then
records `emitted` only after the entire JSONL record is accepted. Failure and
SIGINT retain the earlier valid prefix, including any partial final record count;
there is no rollback of already-emitted audio. Exit codes are 0 completed, 2
failed, 130 SIGINT. No PCM payload is written into the manifest. Keep actual media
and its metadata private; repository tests use synthetic data only.

Tests cover timing/format rejection, exact source gaps and plane padding, delayed
conversion, bounded local inputs, partial/stalled writes, manifest preservation,
partial decoder prefixes and AAC priming metadata. One optional real AAC-container
test runs only when PyAV and FFmpeg are installed; remaining tests need neither.
Physical output, proprietary voice processing, paired-lens video lifecycle and
real live-source arrival integration remain separate work.
