# Scheduled audio-gap output boundary

`tools/local_av_audio_gap_output.py` adds an **explicit, audio-only development
adapter** around the [whole-block gap planner](local-av-audio-gaps.md). It is not
connected to live A/V playback, a new CLI policy, or the installed library.
Existing source-phase rejection stays enabled. There is no new camera command.

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
there is no executor backlog. The future A/V integration must give this audio
owner its own worker and account for all credits before forwarding input.

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
