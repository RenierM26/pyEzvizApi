# Experimental PCM output backend (development only)

`tools/app_pcm_playback.py` feeds decoded PCM to **ffplay** through a nonblocking
pipe. This is a first real output transport, not an app-equivalent player. It has
no camera/network access, decoder, video output, paired-picture assembly, VQE or
physical A/V calibration. It is not installed as a library API or CLI entry point.
Production capture/export/remux paths and dependencies are unchanged.

Requires POSIX Python and an external `ffplay` supporting `-ch_layout mono`
(verified with FFmpeg 7.1.5). Playback requires both explicit options:

```sh
python tools/app_pcm_playback.py --play --processor passthrough < blocks.jsonl > result.json
```

`--play` permits speaker output. `--processor passthrough` explicitly bypasses
EZVIZ's proprietary voice processing. No DSP, gain, denoising, measured 23-ms
content shift, fixed A/V offset or artificial processing delay is applied.
The ffplay audio device and its buffering are controlled by ffplay/SDL, not this
queue. This backend does **not** recreate Android AudioTrack buffering/latency.

## Input and queue behavior

Each JSONL object has exactly three fields:

| Field | Contract |
|---|---|
| `id` | Unique source block identity, 1–128 characters; not reused after rejection |
| `media_ms` | Original uint32 source/app-relative media time, retained even after a drop |
| `pcm_s16le_b64` | Strict base64 encoding of exactly 2,048 decoded PCM bytes: 16-kHz mono signed 16-bit little-endian |

No codec autodetection or conversion is attempted. The producer must supply the
correct decoded format. Do not pipe encoded AAC or a WAV header into this tool.

Input reads and child writes are polled in one owner loop. Observed Python queue
admission time is recorded on a monotonic session clock; source media times are
**not arrival times and do not pace input**. Feeding a file as fast as possible
models a burst, not the original live arrival sequence. There is no automatic
replay of captured arrival times or simulated native timer snapshots here.

The Python ring uses the verified app-profile strict spare-space admission rule:
51,200-byte capacity, admit only if spare space is **greater than** the 2,048-byte
block, hence **24 queued blocks** maximum. Reject newest on saturation. Passthrough
processing is immediate; beginning an output write releases its ring slot. One
additional block may be in flight, and no next write starts before that entire
block is accepted. This is the audio queue policy only, not full player parity.

A short OS pipe write is tracked as partial progress; it is **not** an Android
partial-write emulation. Failed/broken pipes stop the session. Original source IDs
and times remain attached to admitted/rejected/completed actions. Retained PCM
will be contiguous at the output after a rejection, but its source metadata keeps
the gap; the tool never substitutes a continuous source-time counter.

## Bounds, completion and cancellation

- At most 10,000 offered blocks, 8,192 bytes per JSONL line (including newline),
  and one hour of active input/queue polling. The final line may omit its newline.
- Ring holds at most 24 payload blocks, plus one writing block; identity/action
  history is bounded by the block limit. PCM is never copied into result JSON.
- These are **Python-side bounds**. OS pipe and ffplay/SDL buffering are separate
  and are not claimed to have the native app's capacity or timing.
- `--deadline` is 0.1–30 seconds, default 5. It separately bounds a block's pipe
  write, the whole pending-queue drain after input EOF, and ffplay's exit after
  closing its stdin. These budgets do not measure output latency.
- EOF requests a drain of admitted blocks, then closes ffplay stdin and waits for
  a successful exit. SIGINT cancels immediately; pending media is **not** drained.
- On error or cancellation the child is terminated, then killed if necessary,
  and reaped. Exit codes are 0 for completion, 2 for failure, 130 for SIGINT.
  ffplay's own error messages go to stderr.

Final stdout JSON has `status`, `error`, metadata-only `actions` and a `summary`
with offered/rejected counts, full pipe-write completions, pending ring IDs,
in-flight ID and partial pipe-byte count. Unlike offline simulation, playback
cannot be undone: earlier blocks may already have been sent before a later input
error. Failure/cancellation reports retain that partial work rather than emitting
success. Argument errors occur before starting a child and have no result JSON.

A completed pipe write means only bytes accepted into the child pipe. Even a
successful ffplay exit is **not an acoustic measurement** or proof of exact physical
playout. Both `pipe_completion_is_audible_output` and
`physical_lip_sync_measured` are always false. The passthrough processor is always
reported as `passthrough-not-vqe`.

## Headless smoke check

A synthetic silent example, without camera data or a speaker device:

```sh
python - <<'PY' > /tmp/pcm-demo.jsonl
import base64
import json
for i in range(16):
    print(json.dumps({
        'id': f'synthetic:{i}',
        'media_ms': i * 64,
        'pcm_s16le_b64': base64.b64encode(bytes(2048)).decode(),
    }))
PY
SDL_AUDIODRIVER=dummy python tools/app_pcm_playback.py \
  --play --processor passthrough < /tmp/pcm-demo.jsonl
```

Offline tests use synthetic bytes and ordinary child-process pipes, without
ffplay/audio-device dependencies. They compare saturation and write boundaries
with the merged simulator, verify exact FIFO payloads, fragmented JSONL, partial
writes, child death, stalled-output deadlines, EOF, SIGINT and child reaping.

Remaining integration work includes decoded-source arrivals, video/lens lifecycle,
real video output, a deliberate voice-processing replacement and physical
screen-versus-speaker validation. No fixed-offset correction follows from this
transport experiment.
