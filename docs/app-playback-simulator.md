# Bounded app-profile playback simulator (development only)

This network-free, standard-library tool models the observed H9c live-player
**decision policy**, not its proprietary decoder, VQE, Android output, or physical
lip-sync. It is not installed as a library API or CLI entry point. No capture or
remux code imports it. It never reads credentials, connects to a camera or opens
a speaker/display. Feed metadata only, never camera media.

```sh
python tools/app_playback_simulator.py < events.jsonl > simulation.json
```

The entire input is validated before success JSON is written. Invalid/unsupported
input exits 2 with no partial success JSON. Limits are 10,000 events, 8,192 bytes
per JSONL line, one simulated hour, six queued video pairs, 24 queued audio blocks,
one processing block (still counted in that ring), and one pending output write.
IDs and lens labels are at most 128 characters; all identity history/action storage
is bounded by the event limit. Event times must be nondecreasing integer
milliseconds; equal times preserve input order. EOF does not drain pending work.

## Explicit profile and input contract

Only the observed unit-frame-speed, smoothing-off, audio-sync-off live route is
modeled. Manager video speed adapts between 1 and float32(1.1). The video timer has
a 50-ms scheduling bias; this is **not an AV offset**. PCM is fixed 2,048-byte,
16-kHz mono signed16-bit blocks. Video cadence is 15 fps (native interval 66 ms).

Input video pictures must already be assembled two-lens pairs, with independent
lens labels and continuity-repaired app-relative `media_ms`. The tool does not
infer pairing from equal timestamps, discover source clocks, decrypt, or decode.
Video media times must be nondecreasing; source time and picture identity remain
attached to every rendered/dropped action. Audio `media_ms` can retain gaps; it
is never replaced by a continuous sample counter after a drop.

| kind | Additional required fields | Meaning |
|---|---|---|
| `video_picture` |`id`, `media_ms`, `lenses` (two distinct strings)|Admit one already-assembled picture pair; unsupported queue overflow rejects replay|
| `video_tick` |none if a picture is queued|Ask the video scheduler; initial/recovery rebase leaves the head unconsumed|
| `video_tick` with empty queue|signed32-bit `staging_result`|Explicit unavailable-head/staging outcome; zero is success, nonzero permits the observed reset branch|
| `audio_enqueue` |`id`, `media_ms`|Offer a decoded PCM block; reject newest if insufficient strict spare space|
| `audio_begin` |none|Begin processing the FIFO head, without releasing its ring slot|
| `audio_release` |`id` matching processing block|Processing finished; release the ring slot and begin output write|
| `audio_write_complete` |matching `id`, `accepted_bytes=2048`|Complete the write and unblock the next consumer iteration|

Every event also requires `kind` and `at_ms`. Unknown fields/kinds, duplicate
track IDs, unsupported partial/failed writes and invalid transitions reject the
replay. IDs may be shared across audio/video but not reused within one track.
A requested video wake time must be honored by subsequent ticks. Arrivals and
audio events can still occur while video is held.

Audio processing duration and output blocking are explicit caller events, not
estimated delays. The VQE content shift is **not** automatically added to wall
clock time. `audio_write_completed` means an accepted write, **not audible sound**.
`video_display_requested` is not an optical presentation measurement. The five-node
upstream audio queue, lens assembly and hardware output buffering are intentionally
not synthesized by this simulator.

## Policy modeled

- Audio byte ring: 51,200-byte capacity, strict `spare > block_size`; with 2,048-byte
  blocks, 24 fit. Reject newest input without changing retained FIFO order.
- Video due band: ±14 ms inclusive. Early 15–20 ms returns immediately; progressively
  earlier pictures request 5/15/40/100 ms sleeps. Late pictures can discard up to
  five oldest pairs, depending on initial queue depth and 66-ms frame interval,
  before displaying the retained head.
- Post-display depth >= node_limit−3 selects 1.1×; lower depth preserves speed.
- Unavailable timestamp plus nonzero staging result resets 1<speed<2 to 1, bias 50,
  rebase-pending. The next head establishes a new timer origin but is not consumed.

This supports policy exploration, not an app-equivalent real-time output claim.
No automatic capability selection, inferred silence or timestamp correction is
introduced into recording/export paths.

## Small example

```jsonl
{"kind":"audio_enqueue","at_ms":0,"id":"a0","media_ms":0}
{"kind":"video_picture","at_ms":0,"id":"v0","media_ms":0,"lenses":["main:0","secondary:0"]}
{"kind":"audio_begin","at_ms":0}
{"kind":"video_tick","at_ms":0}
{"kind":"video_tick","at_ms":50}
{"kind":"audio_release","at_ms":70,"id":"a0"}
{"kind":"audio_write_complete","at_ms":130,"id":"a0","accepted_bytes":2048}
```

The output records one video display request, one completed audio write, preserved
media identities and no pending blocks. Those event times are illustrative, not a
latency recommendation. `physical_lip_sync_measured` is always false.

## Verification provenance

`tests/fixtures/app_playback_native_oracle.json` contains **synthetic inputs and
observed native outputs only**, no account/device information or camera media.
It covers 264 actual ARM `VideoPlay` cases, 66 applicable post-render speed cases,
16 unavailable/staging reset cases and two current-profile rebase cases. The
retained PlayCtrl ARMv7 binary SHA256 is recorded in the fixture. Renderer,
node-count, log, mutex, timer and sleep externals were stubbed; reset/rebase native
fragments ran with initialized loop register/stack state. These are native-code
oracles, not a claim to execute Android in Python.

Combined tests additionally cover audio processing/write backpressure, strict
ring admission, composite video catch-up, speed/reset lifecycle, rejection rules
and CLI staging. Private retained traces are validated separately and are never
committed as fixtures. Physical screen-versus-speaker alignment remains a separate
measurement and a real output backend remains out of scope.

## Strict observed-native-clock replay

```sh
python tools/app_playback_simulator.py --observed-clock < observations.jsonl > replay.json
```

This separate mode consumes **native elapsed-timer readings**, not elapsed time
reconstructed from callback timestamps or media PTS. `at_ms` still orders events
on one normalized observation clock, with input order breaking ties; it does not
supply the video's elapsed timer. All original bounds and audio events apply.
Autonomous `video_tick` events are rejected in this mode, and observed-clock
control events are rejected without the flag.

| kind | Required fields beyond `kind`, `at_ms` | Meaning |
|---|---|---|
| `video_picture` | Same as above | Admit a complete paired picture at its observed queue admission |
| `video_epoch` | `epoch`, `origin_ms` | Establish the observed native picture origin, leaving the matching head unconsumed |
| `video_unavailable` | signed32-bit `staging_result` | Supply an observed unavailable-head staging return, including zero returns |
| `video_observed_tick` | `epoch`, `id`, `relative_ms`, `elapsed_ms`, `depth`, `speed`, `bias_ms`, `interval_ms` | Evaluate one native scheduler sample against the currently admitted head and sampled depth |
| `video_display_complete` | `id`, `depth` | Complete the active display call at its post-display queue-depth sample; update adaptive speed |

Epoch IDs start at zero and increase by one. Initial/recovery epoch establishment
requires a pending rebase and an origin matching the queued head. A nonzero
unavailable staging return while speed is between 1 and 2 requests the next rebase.
The unavailable-head observation can precede staging admission: a picture may
already be queued when the staging function returns. Consequently unavailability
is an **explicit input**, not inferred from current queue emptiness. This mode does
not manufacture missing reset/staging observations or initialize itself from an
arbitrary mid-session speed snapshot.

Each tick must match the current epoch, head ID, queue depth, computed relative
picture time, bias and modeled adaptive speed (exact float32 value). Elapsed time
is uint32 milliseconds, nondecreasing within an epoch, and must honor the previous
native-domain requested sleep. Timer wrap within an epoch is unsupported and
rejected. `interval_ms` is the observed 66-ms frame interval, or zero during the
observed startup state at media time zero. Once a 66-ms interval is observed,
returning to zero is rejected. Other intervals/profiles are rejected.

Selection removes dropped pictures and transfers the selected picture to an
explicit in-flight display slot. New admissions and audio events can proceed
while that call is blocked. A new tick, unavailable return or epoch cannot occur
during the active display. Completion must match its ID and the actual retained
post-display queue depth. Only completion updates speed. Output
`video_displayed` counts **requests**, `video_display_completed` counts completed
calls, and `video_display_pending` retains the entire in-flight picture at EOF.
Neither request nor completion proves optical presentation.

For example, these observations request a display even though its callback is
recorded much later: the native elapsed value, not `at_ms`, determines the due band.

```jsonl
{"kind":"video_picture","at_ms":0,"id":"v0","media_ms":0,"lenses":["main:0","secondary:0"]}
{"kind":"video_epoch","at_ms":0,"epoch":0,"origin_ms":0}
{"kind":"video_observed_tick","at_ms":999,"epoch":0,"id":"v0","relative_ms":0,"elapsed_ms":36,"depth":1,"speed":1,"bias_ms":50,"interval_ms":66}
{"kind":"video_display_complete","at_ms":1200,"id":"v0","depth":0}
```

### Adapter requirements

The JSONL interface is a normalized metadata contract, not an importer for
arbitrary app versions. A trace adapter must retain the actual timer value passed
to the scheduler and its picture-origin epoch. Normalize admissions, audio
processing/release/write events, native queue-depth samples and staging returns
using one monotonic observation session, preserving finer-resolution order before
rounding `at_ms`. Never substitute source media timestamps for queue arrivals.
Use the scheduler's initial native queue-depth sample for a decision and its
post-display depth sample for completion. Preserve the passed timer reading even
when its observation timestamp is earlier than that queue-depth sample.

An adapter must verify the supported native profile and pairing, reject hook
errors/missing provenance, and compare decision actions and output identities
with the native observations. Selection's queue transfer is a model boundary,
not a claim that the native dequeue happened at the timer-read instant; reject
traces whose intervening admissions/queue samples cannot be represented by this
contract. Do not infer optical output from render callbacks or silently omit an
in-flight final call. Raw device traces and the build-specific adapter stay
private; committed fixtures/tests are synthetic. This replay mode does not supply
a real-time backend, proprietary VQE replacement or physical AV calibration.

## Experimental real audio transport

A separate [PCM/ffplay backend](app-pcm-playback.md) now exercises real pipe
output with bounded queue admission, backpressure and cancellation. It requires
explicit playback and passthrough selection; it does not provide VQE, video output
or physical sync validation. The simulator itself stays network/media/output-free.
