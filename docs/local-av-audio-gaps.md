# Offline whole-block audio-gap planning

`tools/local_av_audio_gaps.py` is a **development-only planning boundary**, not a
new playback option. It opens no camera, file, pipe or output device and does not
write padding. Existing `reject` and `bounded-serial-pcm` playback policies are
unchanged. Do not increase their phase tolerance to conceal a source-clock hole.

This is the first boundary needed for sustained source-gap handling. Output
integration must separately schedule and acknowledge the declared padding before
this plan can be used by a live policy. It must retain the original media and
host targets, independently audit padding bytes, account for padding ownership
and backpressure, and retain existing cancellation and drain limits. A plan does
not establish EOF, completed playback, physical audibility or A/V synchronization.

The separate [scheduled audio-only output adapter](local-av-audio-gap-output.md)
implements the next ownership/acknowledgement boundary, but is still not connected
to live A/V playback.

## Input and explicit limits

`GapPlanner.offer(event, payload)` accepts one original prepared `audio_block`
event from the existing standalone decoder and its one-element immutable PCM
payload tuple. That decoder's fixed format is 1024 samples of mono signed
16-bit little-endian PCM at 16 kHz: 2048 bytes and 64 ms per source block.
The planner verifies the original PCM hash, canonical per-stream source sequence,
exact integer PTS/time base, prepared source time, duration and declared gap.
This is not an independent decoder or a general codec/sample-rate interface.
It does not infer the requested profile from incoming metadata.

All constructor limits are mandatory integers (not floats or booleans):

| Limit | Permitted range |
| --- | --- |
| `max_gap_blocks` | 0–4 whole blocks per decision |
| `max_total_gap_blocks` | 0–16 whole blocks cumulatively; at least the single-gap limit |
| `max_overlap_ms` | 0–1 ms |
| `max_phase_ms` | 0–1 ms remaining cumulative nominal/source phase |
| `max_blocks` | 1–10,000 original source blocks |
| `max_source_span_seconds` | 1–120 seconds from the first audio source start |

Both padding limits must be zero together to disable padding plans. No constructor
default silently enables padding. A typical narrowly scoped control selects
one block per gap, four cumulative blocks, 1 ms overlap/remaining phase, 3000
source blocks and 120 seconds. The maximum possible padding plan is 16,384
samples / 32,768 bytes (1.024 seconds); no such bytes are written here.

## Decision rule

The nominal start is calculated from the first original audio timestamp, the
number of admitted original blocks and the number of previously planned padding
blocks. It is **not reset after a gap**, at startup, or after each source event.

If the source is ahead by more than the explicit remaining-phase allowance,
the deficit must be an integer number of 64 ms blocks within that same allowance.
The proposed block count must fit both the per-gap and cumulative padding
budgets. Half-block gaps, growing small timestamp drift, backward/equal starts,
stream switches, changed PCM and excess overlap fail closed. The preceding
original gap must agree exactly with the original PTS. A rejection consumes no
identity, digest state or padding credit; a caller may explicitly resubmit a
corrected, otherwise valid event at that same sequence position.

Each decision retains original source metadata/hash/time and describes any
**proposed synthetic zero-filled PCM separately**: count, samples, bytes, exact
source-clock interval and zero-byte hash. It also records the residual nominal
phase. It does not claim the source contains missing samples, recover audio that
was not retained, or identify whether a timestamp hole originated in a camera or
transport. Original samples and timestamps are never changed in place.

For example, a synthetic prefix with starts every 64 ms, followed near 114 seconds
by a start 1 ms early and then a 129 ms interval, has a net one-block hole.
The original 1 ms serial-PCM phase guard still rejects that sequence. An explicit
gap planner can instead describe one 1024-sample/2048-byte zero-padding block,
with zero remaining phase, without enabling or writing that padding.

## State and evidence

`result()` exposes requested limits, source/padding counters, peak gap size,
maximum overlap/residual phase, first/last audio timestamps and a complete
canonical decision-chain SHA-256. It retains no PCM or decision history. Padding
hash calculation uses at most an 8192-byte scratch value; caller-owned input,
returned decisions and any caller-collected history are additional storage.
There is no hidden file, output worker or queue.

Source and decision validation plus hashing complete before scalar admission.
Returned decision/report mutations cannot change committed state. A successful
plan is not a successful output receipt. No source-end or device-clock claim is
made. Public tests use synthetic metadata and PCM only; real captures and private
configuration stay outside this repository.
