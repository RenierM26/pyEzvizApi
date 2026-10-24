# Standalone local A/V host submissions (development only)

`tools/local_av_playback.py` connects the [standalone timeline](local-av-timeline.md)
to side-by-side SDL video and unchanged AAC-decoded PCM through ffplay. It requires
no reference app, app-selected pairs, native headers, native scheduler or VQE.
It is an opt-in **recorded local-file** tool, not an independent camera connector.
Production dependencies and APIs are unchanged.

## Explicit use

POSIX, optional PyAV, SDL2 and ffplay must already be installed:

```sh
python tools/local_av_playback.py clear.ts --container mpegts \
  --primary-stream 0 --secondary-stream 1 --audio-stream 2 \
  --play --pairing exact-pts --timing host-submission \
  --layout side-by-side --processor passthrough --receipt new-output.json
```

The source must be a clear local MPEG-TS or Matroska file with two supported HEVC
tracks and one AAC-LC 16-kHz mono track. Indices are absolute container indices.
`--mono-option ch-layout` is the default ffplay channel syntax. For an older ffplay
that supports `-channels 1` instead, use `--mono-option channels`. No executable
fallback, package installation, sandbox change or hidden network access occurs.

For an explicitly nonphysical software output test, set `SDL_VIDEODRIVER=dummy`
and `SDL_AUDIODRIVER=dummy`. Dummy success does not establish a visible picture,
audible sound or physical A/V synchronization.

## What the common clock means

1. Read one bounded immutable source snapshot. Fully decode and validate the
   timeline while retaining verified pixels and PCM in private temporary storage.
2. Reject unmatched pictures, overlapping/equal-start audio, unequal/changing
   paired geometry, more than 300 pairs or source event starts spanning over
   60 seconds **before opening outputs**. These are explicit first-profile limits,
   not silent discards or a change to the more general planner's accepted input.
3. Start the isolated SDL worker and ffplay process. SDL has a ready handshake;
   process creation does **not** prove ffplay's audio device is ready. Set one host
   monotonic anchor only after both constructors return, before any media submission.
4. Compute every target as `anchor + floor(relative_source_seconds * 1e9)` using
   exact rational arithmetic. The original common source origin and inter-track
   offset remain in the receipt. Nanosecond target quantization is less than one
   nanosecond; source PTS/time bases are not modified.
5. At each target, submit a verified composed pair or unchanged 2,048-byte PCM
   block. There are at most two active jobs: one per track, no executor backlog.
   A stalled video backend does not prevent audio submissions. Pixel preparation
   still runs on the owner thread and contributes to measured submission lateness.
6. Bound submission lateness (`--max-late-ms`, default 250, allowed 0–5000) at both
   dispatch and actual worker start. A busy track retains its next source target;
   it does not rebase the clock, silently drop work or create catch-up timestamps.
   Exceeding the budget fails with completed, failed, active and unsubmitted work
   retained in the receipt.

**This is host API submission scheduling, not audio-device-clock synchronization.**
The PCM pipe carries samples without timestamps. Positive source gaps affect
submission targets, but no silence is inserted and ffplay may already have queued
samples: the exact acoustic gap/start offset is therefore not guaranteed. SDL and
ffplay also have independent internal startup, buffering and device latencies.
No fixed correction, gain, resampling, gap filling or timing repair is applied.
The receipt must not be described as measured lip sync or proof that source gaps
were reproduced at the speaker. Overlapping audio is rejected rather than secretly
serialized into a different content clock.

The source need not begin at zero, and audio can precede video. Neither track is
independently zeroed. The last picture remains until the explicit PCM pipe drain
finishes; no synthetic final frame duration or EOF media is added.

## Ownership, bounds and failures

Existing source/decoder bounds remain. Snapshot memory is at most 256 MiB; copied
video storage retains the existing 402,653,184-byte temporary cap. PCM storage is
at most 10,000 × 2,048 bytes. Decoder allocations, bounded metadata and one composed
pair/one PCM job are additional. Pixel and PCM hashes are checked when stored and
read for output; no input media or proprietary native binary is modified.

`--deadline` (finite 0.1–30 seconds, default 5) bounds each backend operation and
final drain. The submission loop also has a last-target-plus-deadline bound.
Preparation/decoder limits remain cooperative, not an FFmpeg memory sandbox or
hard native-call interrupt. Successful EOF waits for all submitted calls and
explicitly finishes audio then video. Partial audio writes stay on the same block
until complete; invalid progress, pipe errors, output death and deadlines fail.

Failure or SIGINT/SIGTERM cancellation signals active jobs, aborts/reaps owned
children and joins the bounded worker operations before temporary storage exits
scope. Cleanup is attempted even after partial output startup. The window title
is scoped to this worker's environment, not a global process-environment change;
existing reference-preview defaults remain unchanged. A failed track must not
hide a completed acknowledgement from the other track. Cleanup diagnostics do
not replace the original failure.

The receipt path is exclusive and never overwritten. Exit 0 plus
`status=completed` means all planned host calls and output drains completed.
Exit 2 is failure; 130 is cancellation. Receipt write failure is itself a command
failure; empty/partial receipts are not success. Completed calls remain recorded
even if a later call or drain fails. Exact source identities/hashes, targets,
worker-start lateness, SDL acknowledgements, PCM hashes/accepted byte counts,
failed/active/unsubmitted IDs and partial PCM byte counts are separate evidence.
Neither an SDL present return nor an OS pipe write is a physical output observation.

## Validation

Synthetic clocks and fake jobs exercise preserved offsets/absolute targets,
independent audio while video stalls, lateness without rebasing/drops, partial and
stalled writes, broken pipes, invalid progress, cancellation, startup cleanup,
primary-error preservation, cross-track acknowledgement retention and final-drain
failure. Optional real integration generates a three-track HEVC/AAC clip and
completes SDL/ffplay dummy output. The existing planner and reference-output tests
continue to cover unchanged defaults.

A private retained H9c control completes eight video API calls and five PCM writes
through real SDL/ffplay dummy outputs, preserving source-derived host targets and
unchanged selected pixels/PCM. No new camera capture, actual human audibility or
physical synchronization claim follows. Source provenance includes the earlier
private recovery/remux audit; this is not fresh independent network capture.
