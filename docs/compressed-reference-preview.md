# Experimental continuous compressed reference preview

This **separate opt-in development path** avoids sending full-resolution decoded
pixels for every selected frame. It does not replace the stricter native pixel
snapshot audit or native scheduler replay. It is not an independent EZVIZ client.
The exact-build-gated Android reference app still supplies clear decoder input,
selects the paired video pictures, and performs native VQE processing.

## Source and output

With a caller-owned ADB forward, unlocked reference device and a **fresh preview**
opened only after source stderr announces `READY_FRESH_PREVIEW`:

```sh
python tools/app_compressed_reference_source.py --attach --emit-stream \
  --device DEVICE --frida-endpoint 127.0.0.1:PORT --output PRIVATE_NEW_DIRECTORY \
  --seconds 10 |
python tools/app_compressed_reference_av.py --play \
  --audio observed-native-vqe-output --deadline 10 --progress \
  --receipt NEW_RECEIPT.json
```

The source requires Frida and the existing LZ4 support. The POSIX output requires
optional PyAV (validated with 19.0.1), SDL2 and ffplay. No production package
requirement changes. The output probes the installed raw `s16le` demuxer for
explicit mono support: modern `-ch_layout mono`, or legacy `-channels 1`; unknown
capabilities fail rather than guess. A pipeline supervisor must check **both**
processes and own its preview/forward cleanup. `--session` on the source and
`--expect-session` on the output can bind an exact one-time 32-hex handoff identity;
this is not source authentication. Binary source stdout must not traverse a text
pipeline. Metadata-only `--progress` stdout can be persisted separately.

## Identity and evidence

The ARMv7 source verifies the existing exact ELF SHA-256 profile before attaching
its exported `CHKMultiVDecoder::DecodeFrame` hook. Entry bytes and all 58 native
metadata words are retained before publication. Only the call's own native
return **0** becomes host decoder input. Native rejected attempts remain explicit
diagnostics; a later retry by the app can be accepted, but this tool never retries
or decodes rejected input. Original attempt IDs and consecutive accepted ordinals
are distinct.

Decoder callbacks are asynchronous: an active call/thread is **not** the owner of
the output picture. Native output headers bind by the unique explicit
`(stream ID, raw timestamp, frame ID)` entry tuple. Decoder owner changes,
ambiguous accepted tuples, missing identities, corrupt frames and reordered
HEVC fail closed. Native frame IDs can jump or decrease during an automatic
resolution switch; they are opaque identities, not clocks. Retirement and
selection order use accepted ordinals. PyAV packet PTS/DTS transport only these
identity tokens and are **never source media timestamps**.

The first reference-selected paired checkpoint of **each lens** must pass the existing full native input,
bottom-crop and renderer audit and match canonical host-decoded pixel bytes.
Neither video nor audio starts before both checkpoints pass. Accepted HEVC input can include an unselected single-track startup prefix. Those packets remain decoder dependencies, but their headers are retained as source observations rather than labelled paired output. Only headers referenced by a paired checkpoint or observed paired selection are forwarded; any selected unsupported header still fails the unchanged audit. This establishes
**sampled initial native pixel parity**, not native pixel verification for every
subsequent frame. Later displayed pairs require exact native output/header
geometry and observed reference render selection; native queue scheduling and
clock eligibility are not replayed. Automatic paired geometry changes reopen the
finite SDL worker and are retained as geometry epochs.

Audio contains actual native 16-kHz mono s16le VQE input/output pairs with hashes,
1024 samples and native success status. Only output bytes reach ffplay. There is
no host proprietary VQE implementation, invented decoded-input association,
output content PTS, fixed DSP offset, or claim of physical A/V synchronization.
Audio and video jobs are independent; write/presentation API acknowledgements are
not speaker emissions, screen scan-out or lip-sync measurements.

## Finite ownership and endings

- Source: 1–20 seconds after first input, startup deadline, at most 600 attempts,
  64 MiB compressed input, 2 MiB per packet, 20,000 retained observation rows.
- Output: at most 600 accepted units, 4,000 records, 512 VQE outputs, two decoder
  contexts, 32 delayed identities, 32 copied lens pictures and 192 MiB copied lens
  pixels. Decoder pixel extent is capped before decoding. Composed active output
  and native codec/surface buffers are additional to that copied-lens budget.
- At most six waiting selected pairs plus one active video write; exceeding the
  limit fails without an implicit frame drop. Only demonstrably earlier,
  unselected copied pictures are retired, and that count is not native drop proof.
- Existing audio queue policy remains 24 waiting blocks plus one active write,
  reject newest with explicit accounting; no hidden resampling or catch-up clock.
- Default snapshot SDL limit remains **32**. The continuous caller explicitly
  selects a finite limit up to 300. Existing snapshot defaults are unchanged.
- A source `end` record validates emitted counts and immediately freezes queue
  starts. Active jobs may finish; pending selections/audio remain reported.
  No decoder EOF flush or source-tail drain. EOF without `end`, mismatched counts,
  trailing records and truncated framing fail with the completed prefix retained.
- SIGINT/SIGTERM request owner-loop cancellation; output workers receive bounded
  cleanup and receipts preserve completed, pending and partial-write state.

## Observations (2026-10-18)

A private fresh ten-second reference session produced 187 accepted compressed
units (1,854,812 bytes), **92 selected video pairs and 97 VQE output blocks**.
The initial 2880×1620 pictures of both lenses matched native crop/renderer hashes.
Actual SDL/ffplay **dummy** drivers acknowledged all 92 pairs and 97 PCM blocks
before the source process exited; no audio queue rejections were reported. Copied
lens storage peaked at nine pictures / 62,985,600 bytes. These are local API and
causal incremental-delivery results, **not physical output or latency proof**.

Earlier prototypes exposed rejected native retries and asynchronous callback
association at 1920×1080. Those failed assumptions and failed integrated attempts
were retained privately. Windows WSLg continuous screen/speaker output remains
unverified until its own receipt and human observations are collected. Previously
observed sparse recorded motion and short recorded audio are separate evidence.

## Acknowledgement credit for a bursty handoff

`tools/reference_stream/credit.py` provides optional **transport-side** credit.
It does not change the consumer queue caps. `WireRecords` preserves each complete
original header and payload byte-for-byte across arbitrary input chunks, with
finite header, record, payload and aggregate limits. A relay calls `Credit.offer`
**before** sending each original record and routes consumer progress into
`Credit.progress` from an independent reader. Reserve-before-send prevents an
immediate acknowledgement from racing ahead of its offer.

Default credit permits **one unacknowledged pair and four unacknowledged VQE
blocks**. Only that exact `video_ack` / `audio_ack` identity returns its credit;
unknown, duplicate or replayed acknowledgements fail. A missing acknowledgement
has a bounded deadline; cancellation and failed/closed progress stop further
offers. Audio and video have separate budgets, but an ordered wire can experience
head-of-line backpressure. This is not a native playback timer, source FPS target,
physical presentation acknowledgement, DSP offset or A/V synchronizer.

The end record is not a drain request: it bypasses output credit and does not wait
for pending offers. The consumer still decides what is active or retained at its
own explicit end boundary. Pending credit is reported, never counted as completed
or silently dropped. A relay must still supervise the source, consumer and its
progress reader and compare forwarded bytes/hash against the original wire.

A Windows attempt verified the synthetic transfer and delivered over 28 MB into
real X11 / legacy-mono ffplay output, then failed the unchanged six-pair waiting
limit before the first video acknowledgement (two audio writes completed). This
is **not** a successful continuous physical-output test. A local regression control
reproduced that backlog with a burst source and 0.5-second initial display delay.
The same immutable-chunk/PowerShell/bundled-runtime run with credit completed all
**92 video pairs and 97 audio blocks**, zero audio rejections, exact original wire
hash parity, and peaks of one/four unacknowledged offers. Those regression outputs
used dummy drivers; the corrected physical Windows run remains pending.

### Startup header scope

A later Windows run exposed a native **single-track startup picture** before the
paired stream: header words 33..35 were `[133, 0, 1]`, not the supported paired
`[133, 3, 2]`. It was not referenced by a paired selection. The compressed source
now forwards native decoded headers only when explicitly referenced by a paired
checkpoint/render observation. It keeps all accepted compressed startup packets
for HEVC dependency state and retains all native callback evidence privately.
Selected unsupported headers still reach and fail the unchanged geometry audit;
missing explicit paired headers fail closed. Nothing is relabelled or made valid
by inventing a second track.

The retained failing prefix was reprojected with all seven accepted compressed
inputs preserved, no mislabelled paired header and no output/checkpoint bypass.
A separate fresh-device run through the same immutable publisher, PowerShell
worker, bundled decoder and acknowledgement credit completed **135 video pairs /
137 native VQE writes before source exit**, with no audio rejections. Observed
paired geometry changed from 1920×1080 to 768×432; two native rejected attempts
remained diagnostics. Output drivers were **dummy**, and that fresh run did not
contain the single-track prefix; prefix handling has its separate retained-data
and regression-test evidence. Physical Windows continuous output is still pending.

## First completed Windows physical-video check

The corrected fresh session completed on Ubuntu WSLg with real **X11** output:
**86 paired video calls and 90 native VQE PCM writes**, no errors, rejected audio,
pending blocks or partial writes. Both initial native checkpoints gated output;
observed paired geometry was 2880×1620. The controller conservatively observed
14 video and 16 audio API acknowledgements while the source process was still
running. The immutable stream was 30,323,526 bytes across 197 chunks. Renier
reported that the test completed and **video looked good**, but he heard no sound.
This verifies physical advancing video by human observation, not audible audio
or measured A/V synchronization. It does not establish low-latency playback.

Analysis of exactly the 90 emitted native VQE records (92,160 s16le samples,
5.76 seconds of PCM) found input RMS **−48.76 dBFS**, native output RMS
**−59.74 dBFS**, and output peak **−36.45 dBFS**. Output was not digital silence:
84,572 samples were nonzero; three blocks were all zero. That is consistent with
very quiet, native-processed background sound, but does not prove why no sound was
heard or which physical speaker emitted it. No gain, resampling, PCM substitution
or camera volume/quality control was applied. A deliberate audible source near
the camera is needed for a meaningful physical audio check; A/V sync requires a
separate controlled measurement. Earlier audible short-recording evidence is
separate from this continuous run.

## Batched collector ownership regression

A later Windows clap attempt failed before its first video output with
`owned decoded pixel budget`. The source had emitted a batch of 30 accepted
full-resolution lens inputs ahead of their already-available reference selections.
The unchanged consumer limit failed on input 29, after retaining 28 frames
(195,955,200 pixel bytes). This was a source projection ordering bug, not
evidence of a microphone or Windows speaker failure.

The source now emits ready native headers, parity checkpoints and reference
selections after each accepted input, before advancing through the rest of a
collector batch. Accepted HEVC input order/bytes, native selection order, audio
bytes, rejection diagnostics, checkpoint requirements and all memory/queue caps
are unchanged. Unselected codec prerequisites are still decoded; no selected
pair is discarded to create room. Missing or excessively delayed selection
evidence still fails closed at the existing bounds.

Reprojection of the retained failing capture completed 119 video pairs and
126 audio writes with both native checkpoints verified; copied lens ownership
peaked at three frames / 20,995,200 bytes. A burst replay through the immutable
publisher, PowerShell worker, bundled decoder and acknowledgement credit, with
a simulated 0.5-second cold output startup, completed 119 video pairs and 124
audio writes, with zero rejected blocks and exact wire SHA/count parity. Two
final offered audio blocks remained pending under the existing no-tail-drain
policy. That transport replay used an explicit test end for the retained prefix
and dummy output drivers; it is not a new live capture or physical audio proof.
