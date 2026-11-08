# Reference-assisted live native A/V handoff (development only)

`tools/app_live_native_av.py` consumes an incremental **live producer pipe**,
validates native paired-picture decisions and forwards verified pixels and actual
native-VQE output to separate host sinks. It does not first load an entire file
or wait for producer EOF. Unlike [paced snapshot replay](native-video-preview.md),
it dispatches as data becomes valid and available, without imposing a second
recorded-timestamp pacing pass.

**The reference Android app remains required.** Native queue/clock observations
and native VQE processing come from that app; this is not an independent camera
connector, decoder, proprietary-VQE port or app-equivalent player. Host video and
audio buffering are additional to the reference pipeline. There is no shared
physical output clock, fixed A/V correction, or automatic lip-sync claim.
Production capture/remux/audio/exporter behavior and dependencies are unchanged.

```sh
producer | python tools/app_live_native_av.py --play \
  --audio observed-native-vqe --clock reference-native-events --eof retain \
  --progress --receipt new-live-receipt.json
```

Requirements: POSIX, optional system SDL2 and ffplay. The producer is deliberately
external and must supply the verified build/profile and a fresh, joint-session
stream, including startup queue/clock state. This CLI does not open a camera,
attach instrumentation, configure a desktop or change speaker settings. The
caller explicitly permits both video and speaker output with `--play`.

## Framing and source contracts

Each record is a four-byte **network-endian unsigned JSON-header length**, the
UTF-8 JSON object, then exactly `payload_bytes` binary bytes. `payload_bytes` is a
required nonnegative integer in the JSON. No base64 or file path from the producer
is followed. Headers are capped at 8 KiB and individual payloads at 32 MiB. The
provided `encode()` helper creates this framing. Valid prefix records are applied
before a later malformed/truncated record fails the session.

There are exactly three record kinds:

### `sample`

Header fields: `kind`, `payload_bytes`, `manifest`. The manifest is one complete
[native crop/renderer audit](native-pixel-crop-audit.md) row, with its own unique
sample ID and both offsets **zero** for this record. Payload is the original coded
input snapshot followed by its cropped render snapshot. Geometry determines their
exact lengths; hashes, complete 49-word headers, ordered crop, format-1 renderer
uploads/samplers and full payload coverage must validate before binding pixels.

Samples may arrive before or after their corresponding metadata offers. The host
binds by equality of the **entire original 49-word input descriptor**, not nearby
timestamps, just frame counters or manifest adjacency. Duplicate descriptors or
sample IDs are rejected as ambiguous. Canonical host pixels stay in the inherited
bounded private spool, not Android-owned buffers. Captures append independently of
the file cursor left by prior output reads, preserving already stored samples
when ingestion and rendering interleave. Source metadata and renderer
claims remain caller evidence, not authenticated provenance.

### `event`

Header fields: `kind`, `payload_bytes: 0`, `event`. `event` is one exact observed-
queue scheduler event accepted by the native scheduled source model. All
`lens_picture` offers use its explicit full-`native_header` metadata-only form;
source sample-ID/codec-field shortcuts are not accepted. Admissions, releases,
epochs, native timer readings, retries, drops and native display completions retain
the same FIFO/identity/depth/state checks. No native clock or completion is
invented from a host output call.

A reference-completed selection becomes host work. Both lenses must resolve to
verified samples before output. Missing samples wait at most `--deadline` while
the source remains open; wrong descriptors never reuse another frame. The bounded
host backlog has six waiting selections plus one active output. Overflow fails
without dropping or silently replacing work. All selected geometry must stay
constant, equal and within the inherited paired/total pixel budgets.

This observes/validates the reference app's selection policy; it does **not**
replace the reference's clock with an autonomous host clock. Source completion and
host SDL call return are separate events in separate clocks. Additional host
latency is expected and must be measured, not assumed to cancel against audio.

### `native_vqe`

Header fields:

- `kind`, `payload_bytes: 6144`, unique `id`, uint32 `input_media_ms`, integer
  `status: 0`.
- Exact format: `sample_rate: 16000`, `channels: 1`, `samples: 1024`,
  `format: "s16le"`.
- `source_input_ns`, `source_output_ns`: ordered, nonnegative integer reference
  monotonic observations less than 2^63. These are not host/physical timestamps.
- `decoded_sha256`, `input_sha256`, `output_sha256`.

Payload contains three consecutive 2,048-byte blocks: corresponding decoded PCM,
actual VQE input, and successful native VQE output. The first two must match
byte-for-byte, and all hashes must match their declared block. A producer must
establish causal correspondence, preserving gaps and rejecting ambiguity; joining
by list index or similar timestamps is not valid. Fresh handle configuration must
establish the required format before collecting buffers.

Only the **third** block is sent to host audio output. No host DSP, passthrough
fallback, resampling, source-time repair, fixed 23-ms shift or invented processing
delay is applied. `input_media_ms` is causal input metadata, **not** the processed
waveform's output timestamp. Output content-time mapping and processor provenance
remain explicitly unverified. The host cannot authenticate a producer claiming
that an arbitrary payload came from native VQE.

A second host sink ring uses the verified strict spare-space rule: 51,200-byte
capacity, at most 24 queued blocks, reject newest, plus one active pipe write.
This ring holds **already processed** native output; it is not the native app's
pre-VQE ring or processing cost/order. Rejected blocks retain their source IDs and
times. No rejected block is automatically retried. Host pipe/ffplay/device buffers
are separate, and pipe acceptance is not audible output.

## Concurrency, EOF and lifecycle

One owner validates source records, manages both policy/host queues and harvests
results. At most one video and one audio job perform I/O on two bounded workers;
slow SDL output does not block ingestion or audio admission. Large source parsing,
hashing and composition still take host CPU time; this is not hard real-time.

`--deadline` is finite 0.1..30 seconds, default 5, for output startup/operations and
waiting for selected pixels. Output subprocesses retain their bounded protocols,
partial-write accounting and terminate/kill/reap cleanup. Source sessions last at
most 60 seconds, with at most 10,000 records, 32 audited samples, 256 MiB total
binary input, 32 host video requests and inherited 16,777,216 paired-luma/
268,435,456 total selected-pixel caps. Original and canonical storage bounds are
separate. Metadata/history remains bounded by the record/event limits.

`--eof retain` means no new queued source/host work starts **after EOF is
observed**. Already-active host operations may finish within their bounded
shutdown deadline. Audio bytes already accepted by ffplay may drain when its pipe
closes; this is not draining the source ring. Reserved/queued/in-flight native
work, waiting completed selections and queued host audio remain in the receipt.
The normal status is `source-ended-pending-retained`, not “all media played”.

Failure or cancellation can occur after real output. There is no rollback of
frames or sound that may already have reached a sink. Unacknowledged work stays
pending and is not retried automatically. Cleanup attempts both sinks even if one
fails, waits for bounded active jobs, and repeats child cleanup after worker exit.

## Receipts, proof and physical validation

The exclusive receipt retains all native model ledgers, audited sample identities,
full descriptor-to-pixel bindings, source VQE call fingerprints/times, host output
requests/acknowledgements, audio ring/drop/partial-write state and source EOF time.
`--progress` emits metadata-only host acknowledgement JSONL on stdout, allowing a
producer to verify output **while its pipe remains open**. Later input failure
retains the earlier output evidence. SDL's dummy driver and ffplay's dummy audio
backend are suitable only for transport/API tests.

Tests exercise real dummy video/audio jobs acknowledged before producer EOF,
independent video/audio backpressure, exact causal hashes and formats, source
clock/queue checks, bounded framing, later-prefix failure and no EOF source drain.
They do not establish a visible window, audible speaker, physical timing,
independent playback implementation or proprietary VQE parity. Fresh reference
capture evidence is recorded separately below.

Physical validation requires a fresh same-session pilot and a working real display
and speaker endpoint, then one external recording of that endpoint's visible and
audible versions of the **same source events**. Wait for a readiness cue before
clapping. Preserve original recording PTS, video-frame contact bounds and audio
onset/sample bounds; account for the recorder's own A/V uncertainty. Report
intervals and missed events, not interpolated exact times. Keep source, native
processing, host-call and physical-output observations distinct. An older clap
trace, host timestamps, dummy output or measured VQE waveform lag cannot substitute
for that recording. No fixed correction follows until this measurement is done.


## Fresh reference-assisted software pilot (2026-10-18)

A bounded fresh Android reference session supplied six audited lens snapshots
(three paired selections), 573 observed source events and 54 uniquely hash-bound
native VQE records to the live host pipe. Both lens images were 2880×1620 after
removing four coded bottom rows; paired host buffers were 5760×1620 YUV420P.
Full original descriptors bound the samples to the observed source selections.
Three video acknowledgements and **27 audio pipe writes preceded source EOF**.
One already-active audio write completed approximately 5.6 ms after EOF, making
28 writes total. The audio receipt retained 13 queued blocks and reported 13
rejected newest offers, with no partial write. No queued source drain was added.

The collector was still active when host output was acknowledged. This establishes
incremental reference-to-host software transport, not an offline-file-only test.
The private source projector emits completed native prefixes; snapshot transfer,
audit and instrumentation add substantial delay and burst audio delivery. It is
**not a sustained real-time cadence or latency result**. The normal terminal status
was `source-ended-pending-retained`, with no error. SDL video and ffplay audio used
dummy drivers. No physical presentation, audible output or lip-sync result is
claimed, and no independent decoder/VQE implementation follows from this pilot.
The Android preview was closed and hooks/forwarding were removed afterward.
Private media and device traces are not included in the repository. Physical
screen/speaker testing is deferred; the software integration can be reviewed
independently.

For the build-gated Android reference producer and bounded cadence/queue/delay
measurements, see [Reference producer benchmark](reference-stream-producer.md).

## Separate compressed-input experiment

[Compressed reference preview](compressed-reference-preview.md) is an opt-in
incremental alternative that transfers accepted HEVC input and samples initial
native pixel parity. It does **not** relax this path's full-snapshot audits or
replay its native scheduler contract. Continuous physical Windows output and
measured A/V synchronization require separate evidence.
