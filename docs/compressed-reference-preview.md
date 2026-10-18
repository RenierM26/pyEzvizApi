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

The first picture of **each lens** must pass the existing full native input,
bottom-crop and renderer audit and match canonical host-decoded pixel bytes.
Neither video nor audio starts before both checkpoints pass. This establishes
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
