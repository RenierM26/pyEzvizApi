# Scheduled audio-gap output boundary

`tools/local_av_audio_gap_output.py` adds an **explicit, audio-only development
adapter** around the [whole-block gap planner](local-av-audio-gaps.md). It is not
enabled by default or provided as an installed-library feature. The attended CLI
exposes the enclosing capture API only through a separate named opt-in.
The capture development API has a separate explicit integration described below.
Existing CLI source-phase rejection stays enabled. There is no new camera command.

Unlike the planner alone, this adapter can write separately declared zero PCM to
a caller-supplied nonblocking backend. It preserves every original source block
and source target. It does not identify the cause of a source-clock hole or
recover missing sound. Synthetic padding is never labelled original media.

## Ownership and scheduling contract

The caller explicitly supplies:

- An already opened backend with `write`, `alive`, `finish(timeout)` and bounded,
  idempotent `abort` methods. Writes must be nonblocking, returning the number of
  bytes written or raising `BlockingIOError`, and accept read-only bytes-like
  views without retaining them after return; the existing `Ffplay` backend fits
  this interface. Backend construction and any device opening are caller-owned.
- The **shared A/V source origin**, as a canonical rational, and the existing host
  anchor in monotonic nanoseconds. The adapter does not choose a new origin or
  reset the anchor when a gap occurs.
- All planner limits, a 0.1–5 second operation deadline and an integer 0–250 ms
  submission-lateness limit. No inferred or silently extended limits.

One owner calls `write(event, payload)` **before the earliest target of that
block's padding/source operations**. Concurrent writes and finish are rejected;
there is no executor backlog. The capture API gives this audio owner one of the
existing two output workers and accounts for all credits before forwarding input.

For source starts at 0 and 128 ms, with one 64 ms hole, the operations are:

| Operation | Original clock interval | API submission target |
| --- | --- | --- |
| First original PCM | 0–64 ms | host anchor + 0 ms |
| Separate zero padding | 64–128 ms | host anchor + 64 ms |
| Second original PCM | 128–192 ms | host anchor + 128 ms |

**Do not prepend the padding only when the later original block becomes due.**
That would submit the gap operation late and could make the acoustic gap longer.
The adapter derives both targets directly from the supplied origin/anchor and
retains the normal lateness guard; it does not move either target to make a late
caller succeed. Target waiting and each write have separate finite deadlines.
For a combined job, the verified padding-to-source target interval is intentional
schedule waiting and does not consume the output-progress timeout. Thus a valid
128 ms padding interval can precede source PCM with a 100 ms write deadline.
Only that exact source-derived interval extends the source target-wait allowance;
first/padding target waits, per-write deadlines, cancellation polling and lateness
limits remain unchanged. No arbitrary early call gains a session-length wait.

The adapter holds one original 2048-byte block plus at most four padding blocks
(8192 bytes): at most **10,240 output-owned bytes**, or 4096 bytes for an explicit
single-gap limit of one block. It reserves padding ownership before allocating
zero bytes, verifies every job's actual byte/hash extent, handles partial writes
and returns a job acknowledgement only after all its bytes have been written.
Partial writes use read-only views of the same immutable storage, not growing
suffix copies.
Source credit stays held through both padding and original-block operations.
Caller input, returned acknowledgements, decoder allocations, pipe/device buffers
and any caller-retained history are additional storage, not hidden in this bound.

## Evidence and failure semantics

Source and padding have separate submitted/completed counts, fully acknowledged
API-byte counts and complete canonical media-chain hashes. Each chain includes
its original source-clock interval/identity and exact host target; observation
start/end times are returned separately. `maximum_submission_lateness_ns` is an
observed submission maximum, not a hardware/audio-device clock measurement.
The nested planner result remains a planning receipt; the outer counters are the
separate output evidence.

Invalid input, changed PCM, an unsupported gap, lateness, a write deadline,
invalid progress, backend failure or cancellation makes output terminal and
aborts the owned backend. A partial failed job records its written byte extent
separately; it does not become a complete acknowledgement. Failure after padding
can acknowledge that padding without falsely acknowledging the original block.
The adapter does not call a failed or cancelled prefix completed playback.

`abort()` may be called from another thread. It signals cancellation and aborts
the backend, but **does not release bytes still borrowed by the writer**. The
caller must join that writing thread and check `write_active`, ownership,
transport closure and error fields before declaring cleanup. A failed backend
abort remains visible and can be retried explicitly; the historical error is
retained even after successful closure. `finish()` drains only a valid, idle,
nonempty output and must succeed before `outputs_finished` becomes true. It does
not assert independent source/decoder EOF or network completion.

A complete pipe write is not proof that the device played a sample. Neither the
shared anchor nor successful dummy-output tests establish physical A/V sync.

## Relationship to the official app

The rationale is to separate source timing, content admission, backpressure and
output acknowledgements. Retained observations of one official-app route showed
input-driven PCM queues, `SyncToAudio(0)`, and continuation through source gaps;
there is no basis for calling explicit zero-padding app-equivalent. That route
also rejected incoming blocks under queue pressure. We do not copy dropping,
independent track rebasing or processing changes into the source-preserving path.
This adapter is our explicit timeline-preservation contract, not a claim about
all app versions, devices, settings or acoustic behaviour.

Before enabling a live policy, integrate both gap/source operations with A/V
lookahead and unknown-input reservations, preserve original media and target
chains, verify separate padding bytes, and test cancellation, partial writes,
late preparation, EOF and drain behaviour through the complete saved-source
workflow. No fresh acquisition is required for those offline checks.


## Explicit pending-capture API integration

`local_av_capture_playback.CapturePlayback(..., gap_limits=limits)` opts into
`local_av_audio_gap_av.py`. Importing or constructing the API starts no camera
acquisition. The caller still supplies and owns the pristine transport handle.
Calling `play()` acquires the explicitly supplied finite source. This is not a
new command, automatic camera test, broader camera support claim, or app policy.
The attended Bash/PowerShell launcher exposes a separate explicit
[`two-minute-gaps` profile](local-av-lan-playback.md#explicit-two-minute-bounded-gap-profile); defaults remain unchanged.

All six planner limits are mandatory. For example, with the existing explicit
120-second source-span profile:

```python
limits = dict(max_gap_blocks=1, max_total_gap_blocks=4,
              max_overlap_ms=1, max_phase_ms=1, max_blocks=3000,
              max_source_span_seconds=120)
```

The caller must also choose `identity_mode='source-sequence'`, bounded diagnostic
history (for example `diagnostic_tail=2`), `span_limit=120`, matching
`bounded-serial-pcm` overlap/phase tolerances, and a 0.1–5 second output deadline.
All other capture/decode/output limits and explicit completion policy still
apply. Invalid combinations are rejected before source ownership transfer.
Omitting `gap_limits` keeps the existing strict path.

Before every unknown source read, lookahead reserves one possible original audio
block plus the maximum explicitly allowed padding. Admission recomputes the plan
from immutable source PCM/PTS; the combined event is charged for actual original
plus planned padding bytes. Credit remains held until both jobs complete or the
writer is aborted and joined. Audio limits stay **32 source-event slots and
65,536 charged bytes**, including pending-read reservations, not 32 source blocks
plus an unbounded padding allowance. Receipts report padding-credit and complete
credit peaks separately. Decoder/pipe allocations and bounded hashing scratch
are not included in lookahead payload credit.

The same two output workers handle independent video and audio. Each audio job
submits any padding at its earlier source-derived target, then the untouched
original at its original target. One shared source origin and host anchor remain
fixed. No whole-session retained event list, extra job queue, source rebase,
sample dropping, interpolation, or source PCM replacement is introduced.

The normal compact A/V media receipt hashes **only original** video/PCM and their
original targets. `gap_audio` separately records padding/source API byte counts,
canonical media chains, shared origin/anchor, drain and cleanup state. Successful
capture verification binds this receipt to preparation's complete planner result
and requires complete original and padding acknowledgements, clean source end,
worker join, output drain and zero retained credit. Partial or cancelled sessions
cannot become successful captures merely because an earlier padding job finished.
The standalone adapter's `acquisition_owned` and `av_schedule_owned` flags remain
false: source acquisition and A/V scheduling belong to its enclosing API owner.
