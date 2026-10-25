# Guarded capture-prefix output (development only)

`tools/local_av_capture_playback.py` connects a supplied pristine
`AutoMediaStream` to [guarded online preparation](local-av-capture-preparation.md)
and the existing [bounded online output scheduler](local-av-online-playback.md).
The recorded CLI remains recorded-only and its defaults are unchanged. This
adapter has no CLI, account-client constructor, credential lookup, automatic
camera selection, retry or new background acquisition thread.

Calling `capture_playback` **can acquire the supplied owner's source and open
output devices**. Importing it or constructing the owner does not. Offline
controls mock acquisition and use dummy SDL/audio; they do not prove live
transport behavior or Windows throughput.

## Callable contract

```python
capture_playback(owner, private_media_key, args, report,
                 limits=CaptureLimits(duration_seconds=8, max_packets=15000,
                                      max_bytes=16 * 1024 * 1024),
                 completion='bounded-prefix', codec='auto')
```

`args` explicitly supplies the existing output options:

- `primary_stream`, `secondary_stream`, `audio_stream`: distinct absolute indices;
- `play=True`, `pairing='exact-pts'`, `timing='host-submission'`,
  `layout='side-by-side'`, `processor='passthrough'`;
- `video_transport='sealed-store'`, `container='mpeg'`;
- `deadline`: finite 0.1–30 seconds; `max_late_ms`: integer 0–250;
- `mono_option`: `ch-layout` or `channels`, according to the actual ffplay runtime;
- `audio_overlap_policy`, `max_audio_overlap_ms`, `max_audio_phase_ms`: the
  unchanged explicit online audio-policy options (default overlap rejection).

These values can be supplied in a namespace; no recorded source path is used.
Keep the key in private storage, not arguments or receipts. This is single-owner
synchronous use; concurrent calls on the supplied owner are unsupported.
Transport selection, fallback and interruptible IO remain that owner's policy.

Invalid output, track, audio-policy, capture-limit or owner arguments leave the
owner unclaimed and output unopened. Once validated, ownership transfers to the
adapter, including failure before the preparation generator's first pull. All
nested generators, preparation workers, output jobs, stores and backends are
closed/joined/aborted on failure, preserving primary exceptions. KeyboardInterrupt
is recorded as cancellation and reraised; caller signal handling remains caller
responsibility. Cleanup-only failure still raises inside an unrelated caller
exception handler. Preparation diagnostics and lease-cleanup handling likewise
use their own operation outcome rather than ambient caller exception state.

## Bounds and source scope

Capture-end completion still defaults to `reject`, so iterator exhaustion does
not silently flush a limited/ambiguous source. Only explicit `bounded-prefix`
permits a clean known local capture-limit end. The decryptor, decoder and policy
must independently accept that prefix; accepting the limit cannot repair a cut
crypto/container tail or bypass a later policy violation.

The shared output path keeps one host anchor after bounded prefill/backend
startup, original relative targets, independent tracks, split sealed lens uploads,
one preparation worker, four-pair/64-MiB and 32-PCM/65,536-byte output credit,
unchanged raw-input probing and explicit audio/video drains. No deadline/buffer
increase, discard, rebase, resampling or gain is introduced. Native decoder,
producer/crypto, policy references and currently borrowed payloads remain
additional to output credit. Cooperative upstream work includes output waits and
can delay dispatch; a finite source is not guaranteed to play within these bounds.

The video window is labeled as a bounded capture prefix, not a recording or a
whole live source. Existing recorded windows retain their prior title.

## Completion and receipts

The profile is `guarded-capture-prefix-host-submissions-v1`. The only successful
status is `prefix-output-completed`, after:

1. The nested `preparation` report reaches `prepared-prefix-ended` with clean
   capture, verified crypto/decode EOF, matching prefix hash/bytes and policy.
2. The nested `output` report confirms every decoded/prepared video/audio event
   was offered, submitted and completed, with no active/failed/partial job.
3. Both outputs explicitly drain, all owned cleanup succeeds and no preparation,
   queue or sealed-store credit remains.

`accepted_prefix_clear_sha256` is published only after those checks. Failed or
cancelled runs retain nested partial receipts but no top-level successful hash.
Output may already have occurred before a later capture/policy/backend failure;
this is not whole-source preflight and a valid displayed prefix does not make the
session successful. Backend initialization/opening is recorded in `output` even
when playback fails later.

`whole_source_complete`, `network_eof_verified`, `whole_source_preflight` and
`physical_av_sync_measured` remain false. PCM pipe completion is not audibility;
SDL present return is not measured physical display time. Successful dummy output
is host-call/drain evidence only, not human picture/audio confirmation. Actual
network acquisition, target-host dependency checks and attended output validation
remain separate work; no Windows bundle or camera test is supplied here.

Use the separate [offline runtime preflight](local-av-runtime.md) with the exact
proposed interpreter and pinned package identity before retained-media/attended
validation. Readiness alone does not establish playback or live acquisition.

## Explicit same-session PES identities

For MPEG-PS sources whose absolute demux indices can change between acquisitions,
opt in with `pes_ids=(0xE0, 0xE1, 0xC0)` on `capture_playback` (or
`iter_capture_preparation`). These are two ordered video PES bytes and one audio
PES byte, not lens ordinals or absolute indices. The existing namespace's track
indices remain syntactically validated, but this explicit mode supersedes them.
Without this keyword, absolute-index selection and all defaults are unchanged.

Resolve only against the active demux container, once, before decoding selected
tracks or offering events to the online policy. FFmpeg's MPEG-PS stream identifiers
are matched exactly as `0x100 | pes_id`; there is no low-byte masking, codec-based
selection, saved-session mapping, second acquisition or inferred fallback. Missing,
duplicate, wrong-type or unsupported-format tracks fail before output opens.
Invalid PES arguments leave the owner unclaimed.

The decoder and online-policy receipts both include `track_selection`: requested
PES IDs, observed demux IDs, types and resolved absolute indices. The original
indices remain in every decoded/prepared event and metadata digest; no stream
renumbering, timestamp rewriting, payload changes or larger startup budget is
introduced. Both selection records must agree for prefix completion. The
selection itself does not verify a whole source or physical lens identity, nor
does it promise that a later truncated capture or output failure will succeed.

## Opt-in pending-input capture session

`CapturePlayback` from the same development helper composes guarded capture with
single-demand source pulling. Existing `capture_playback`, recorded CLI and
launcher defaults remain synchronous and unchanged.

```python
session = helper['CapturePlayback'](
    owner, private_key, args, report, limits=limits,
    completion='bounded-prefix', pes_ids=(0xE0, 0xE1, 0xC0),
)
# Retain this object until its source worker is joined, including on failure.
session.play()
```

Construction validates all options before claiming the pristine supplied owner.
It copies the option namespace and starts one idle source worker, without
acquisition or output. Call `play()` once, or `close()` to release an unstarted
session. The caller supplies its own owner and borrowed client; this helper does
not discover credentials or change transport selection. The owner's `close`
must be a thread-safe, promptly returning IO interrupt, as on `AutoMediaStream`.

Only the source worker calls `next` or `close` on the preparation pipeline.
During active reads, shutdown interrupts the transport first, then joins the
worker within the unchanged `args.deadline`. Arbitrary interrupt-hook duration
is not bounded by the join timeout. The worker also releases a claimed but
never-started capture; closing a lazy generator alone cannot do that. Capture
startup that returns a connection after interruption still requires final
transport release before the source worker can finish.

A timed-out join raises and leaves `session.pull` and its executing source owned.
Do **not** close nested generators, discard the session, start a replacement or
reuse the owner. After the blocked operation can finish, call
`session.close(timeout=...)` again (finite timeout in `(0, 30]` seconds). Recovery
updates `report['source_pull']` but never upgrades a failed playback verdict.
Call close/inspection only after play returns; session control is single-consumer,
not an additional concurrent cancellation API. Caller signal handling is unchanged.

The scheduler reserves one unknown event in both existing track budgets before
each explicit request. Pending reads permit queued dispatch, acknowledgement
harvest and deadline/liveness checks. Original targets, lateness, count/byte caps,
payloads, PES selection, EOF policy and drains are unchanged. No unbounded producer
queue, retry, drop or clock rebase is added. Native/GIL/interrupt stalls can still
prevent timely playback; this is not a hard-real-time guarantee.

The separate profile is `guarded-capture-pending-host-submissions-v1`.
`prefix-output-completed` additionally requires a joined source worker, closed
iterator, verified source end and no outstanding/abandoned result or source,
interrupt or finalizer error. `source_pull` is refreshed on close/rejoin;
`output.lookahead.source_pull` is the output cleanup-time snapshot. Nested partial
receipts remain diagnostic, not independent permission to claim success. The
same accepted-prefix-only and physical-clock limitations above apply. No new
attended Windows run or sustained live-stream claim is supplied by this opt-in
composition alone.

### Application-driven stop

A different thread may call `session.request_stop()` while the playback owner is
inside `play()`. It is idempotent and only sets a thread-safe flag: it neither
closes resources nor waits for IO. Do not call `close()` concurrently with play.
The playback owner observes stop during pending-input prefill, between backend
constructors, before further submissions, after preparation and between drains.
It then aborts output, interrupts active source IO and joins through the same
bounded cleanup path. Existing constructor/native calls and backend drains remain
cooperative; stop is not guaranteed to interrupt those calls immediately.

`play()` raises the helper output dependency's `PlaybackStopped` (a `ValueError`)
and records `status='cancelled'`, `stop_requested=True`, no successful prefix hash.
A previously set flag prevents acquisition and backend construction, while still
releasing the session's claimed unstarted capture on its source worker. An
unrelated failure that is already being propagated retains its original exception.
A cleanup timeout still leaves the pull/session owned for explicit later rejoin;
requesting stop does not mean cleanup has completed. Calls after play has completed
do not rewrite its receipt or reopen it. Requests observed during final cleanup
or verdict verification prevent successful prefix publication.

This remains the same finite opt-in profile, not sustained playback or automatic
reconnect. Synchronous capture/recorded defaults, payloads, timing and limits are
unchanged. The lower-level `play_prepared` also accepts `stop=threading.Event()`
only with explicit `pending_input=True`; invalid stop contracts leave the source
unclaimed. The flag is caller-owned and never set or cleared by output cleanup.

### Bounded finalized diagnostic history

`CapturePlayback(..., diagnostic_tail=16)` opts into bounded diagnostic retention;
`None` preserves all existing receipts and defaults. The explicit limit is1–128
finalized rows/pairs. Compact capture uses
`guarded-capture-pending-tail-host-submissions-v1`; its nested output uses
`bounded-prepared-tail-host-submissions-v1`. Consumers that require every action
must retain the legacy mode rather than interpreting a tail as a full history.

Preparation timings retain at most N finalized rows, and scheduler actions retain
at most N finalized submission/outcome pairs (at most2N flattened action rows).
Each journal is also bounded to65536 encoded bytes, each encoded record to16384;
byte pressure may retain fewer than N rows. Admission bounds JSON depth,nodes,text
and integer size before canonical encoding, rejects non-JSON/media payloads and
nonfinite floats, and fails the session on unsupported diagnostic metadata rather
than silently ignoring it. Bounded encoding scratch is separate from retained
journal bytes, mutable in-flight rows and serialized receipt snapshots.

The scheduler holds at most one pending submission per track under existing output
credit. It seals that submission together with the exact outcome only after the
future is finished, so worker-populated start/lateness fields cannot mutate an
already hashed record. Finalized pairs are ordered by owner harvest, not original
submission order. Incomplete submissions are reported separately using their
immutable original metadata; they are not included in the finalized hash/count.

`action_audit` and `preparation_audit` report full finalized counts, encoded-byte
counts, evictions, retained/peak sizes and `complete_history_retained`. The digest
is SHA256 of ASCII `bounded-finalized-json-v1` plus LF, followed by each finalized
canonical JSON record plus LF. JSON keys are sorted, separators are`,` and`:`,
Unicode is ASCII-escaped and nonfinite numbers rejected. Action records have
`submission` and `outcome` fields. Hashing includes every finalized record even
when its diagnostic tail is later evicted. A prefix digest is not an independent
proof of source EOF, a missing output acknowledgement or physical playback.

Successful compact completion still requires every prepared event to be offered,
submitted and acknowledged, all upstream prefix checks, clean drains, joined source
and zero leases. Full action/preparation counters must agree with those totals;
missing compact audit records fail terminal validation. Stop/failure retain partial
counter/hash evidence without upgrading the verdict.

Only these two diagnostic histories are bounded by this option. Source/policy
identity sets, decoder/session work and transport remain under their existing
finite limits. This does not enable unlimited streaming, raise caps, drop/rebase
media or alter scheduling. Legacy CLI/capture modes are unchanged.

Diagnostic admission failures have separate bounded counters/type diagnostics and
invalidate compact completion. They cannot replace an already propagating
preparation/backend error or skip pending-future, iterator or lease cleanup. A
later valid append cannot erase an earlier diagnostic failure.

### Whole-prefix media and target fingerprints

Compact `action_audit.media_receipt` now contains `bounded-output-media-v1`:
recorded host anchor and,for each track,completed count,total acknowledged payload
bytes and SHA256. This is separate from the observation-dependent diagnostic hash.
It keeps only two hash states,counters and previous exact source targets; it does
not retain another event history. Legacy full-receipt/default paths are unchanged.

Each admitted completed acknowledgement projects exactly these fields:

```json
{"track":"video_pair","id":"local-pair:1","source_at":{"numerator":0,"denominator":1},"target_monotonic_ns":123,"bytes":6220800,"payload_sha256":"<canonical pixel hash>"}
```

The corresponding audio track is `audio_block`,with the original block ID and
PCM hash. Source fractions are reduced exactly;targets must equal the frozen
anchor plus floor(source_at×1000000000). Starts must strictly increase per track.
Acknowledged bytes must equal submitted bytes;audio blocks remain2048bytes. Video
requires the existing `presented` acknowledgement and matching pair ID. Fingerprints
are exactly64 lowercase hexadecimal characters. Raw,mutable or malformed metadata
cannot advance the receipt. Global ID uniqueness remains the upstream policy's
responsibility;this constant-state receipt independently checks per-track order.

Each track starts SHA256 with ASCII `bounded-output-media-v1`,LF,the track name,LF.
Append each projected canonical JSON row followed by LF,using sorted keys,compact
`,`/`:` separators,ASCII Unicode escapes and no nonfinite numbers. Per-track
completion/source order is used;cross-track harvest interleaving has no effect.
Worker start/return times,harvest times,lateness observations and other backend
fields are excluded. Submitted,pending,failed and partially written output is not
counted as completed media. Prepare/validate the projection before diagnostic
admission and commit only after it succeeds,so a rejected diagnostic row cannot
partially commit a media acknowledgement.

An independent verifier decodes the same accepted source prefix,applies the same
explicit track/origin/audio policy,and computes each original ID,relative target,
canonical paired-pixel/PCM hash and payload extent. Using the receipt's recorded
anchor,it reconstructs both complete track chains without needing evicted actions
or host service timestamps. Counts,byte totals and digests must all match. A
changed hash/target/order/extent or omitted event changes this receipt even if the
retained diagnostic tail appears valid. This is a fingerprint comparison,not
cryptographic authentication or a physical display/speaker measurement.

Compact completion requires this media receipt,matching anchor/track counts and
well-formed positive byte totals/hashes,alongside every existing source/prefix/
output/drain/cleanup check. Older compact receipts lacking the new field cannot
establish this stronger media claim. Failed/cancelled sessions retain only partial
completed-media evidence;the hash itself never asserts successful EOF or cleanup.
No existing attended launcher or collector is silently switched to compact mode.

### Opt-in source identity counters

Pass `identity_mode='source-sequence'` to `CapturePlayback` to replace the online
policy's whole-prefix ID sets with strict original source-sequence counters.
See [canonical source IDs, receipts and limits](local-av-online-policy.md#opt-in-constant-state-source-identity-checks).
This composes with the existing `diagnostic_tail` option and explicit same-session
PES selection. No event IDs, media bytes, origin, host targets or scheduling rules
are changed. Invalid options fail before source ownership is transferred.
The sequence policy has its own nested receipt profile and terminal accounting;
legacy/default outer output profiles remain unchanged. Finite capture/decode/work
limits and all source join/cleanup rules remain in force. No attended launcher is
automatically switched, and this does not enable sustained/unbounded streaming.

### Decoder-only consumer wait exclusion

The pending `CapturePlayback` constructor accepts
`decoder_deadline_mode='consumer-excluding'`. It forwards the explicit binding
through capture preparation; see [composition and terminal clock checks](local-av-capture-preparation.md#explicit-decoder-clock-composition).
It can be combined with explicit PES selection, `identity_mode='source-sequence'`
and a compact diagnostic tail. Default wall-clock behavior and outer receipt
profiles remain unchanged; the preparation binding and nested decoder profile
identify the opted-in clock.

This changes only which time is charged to the decoder's processing allowance.
It does not pause capture/decryption wall clocks, change the host anchor or
source targets, relax source/byte/frame limits, alter output lateness or backend
join/drain deadlines, or bypass caller stop. Source interruption and worker join
still precede lease/resource release, including cancellation during output or
drains. Terminal output validation requires the bound decoder clock snapshots
in addition to every existing prefix, media receipt, output and cleanup check.

No attended launcher or existing caller is silently switched to the new option.
This composition does not enable sustained/unbounded playback or establish
physical A/V synchronization.


## Opt-in constant-state SDL worker identities

`CapturePlayback(..., identity_mode='source-sequence')` now also selects strict
sequence validation in the isolated SDL descriptor worker. The lower-level
`play_prepared` API exposes this independently as
`video_identity_mode='source-sequence'`; `local_av_frame_channel.Output` accepts
`identity_mode='source-sequence'`. Defaults, CLI and attended launcher are unchanged.

The worker accepts exactly `local-pair:1`, `local-pair:2`, … using its existing
bounded loop index, without retaining a set of previous IDs. It checks the ID
before requesting a descriptor or presenting pixels. Duplicate, reset, skipped,
noncanonical or wrong-prefix IDs fail; full-history mode retains its original
arbitrary unique ID contract and wire format.

Opt-in ready, presented and finished responses carry an `identity_audit` with
profile `strict-video-source-sequence-v1`, integer `presented` count and
`retained_id_count: 0`. The host checks all three phases. Only a matching final
response plus worker exit zero publishes `Output.identity_receipt`; successful
prepared playback copies it to `output.video_identity_audit`, alongside the
explicit `video_identity_mode` binding. Capture terminal verification requires
this evidence to match completed video output when using sequence mode. It does
not replace source EOF, media hashes, timing, cleanup or audio drain verification.

The default 300-pair work cap, geometry/memory limits, descriptor leases, canonical pixel
hashes, original scheduling targets, 250 ms maximum lateness and all IO/processing
deadlines are unchanged. This removes another growing history, not a playback
quota: it does not enable sustained/unbounded streaming or establish physical
A/V synchronization. No new camera acquisition is needed for this protocol-only
step; retained-source controls use dummy SDL/audio devices.


## Explicit finite video pair budget

`CapturePlayback(..., pair_limit=N)` and lower-level
`play_prepared(..., pair_limit=N)` accept a positive integer video pair quota.
The default remains 300. Values above 300, up to an absolute maximum of 3,000,
require explicit source-sequence identity validation and a non-`None`
`diagnostic_tail`. Invalid quotas, legacy-mode expansion and unbounded diagnostics
are rejected before claiming the capture or prepared iterator. Existing CLIs and
attended launchers are not switched to a larger quota.

For example, development callers can use:

```python
session = CapturePlayback(
    owner, key, args, report,
    limits=limits, completion='bounded-prefix',
    identity_mode='source-sequence', diagnostic_tail=2,
    decoder_deadline_mode='consumer-excluding', pair_limit=900,
)
session.play()
```

Capture preparation and its online policy receive the same explicit quota. The
policy checks it before accepting another pair and preserves it through explicit
same-container PES track resolution. The SDL worker independently enforces the
requested quota. Nondefault worker quotas use
`finite-video-source-sequence-v2` audit messages, including integer `pair_limit`,
at ready/presented/finished; the host rejects downgraded or mismatched evidence.
The default 300-pair sequence mode retains its v1 audit shape. Full-history
workers still reject limits above 300.

Nondefault preparation, policy and output receipts bind `pair_limit`; terminal
verification requires agreement across all stages and a matching clean worker
receipt with no more completed pairs than the quota. Direct
`verify_completion(..., pair_limit=N)` callers must supply the expected quota;
the default verifier cannot silently accept expanded preparation receipts.
Default preparation/output receipt reuse clears previous quota bindings.

This is a total-work allowance, not additional resident credit. Video remains at
four pairs/64 MiB and audio at 32 blocks/64 KiB, with no extra queue or retained ID
history. The 60-second original source span and output session deadline, 250-ms
maximum lateness, all byte/packet/capture/decryption/decoder/startup limits, audio
block quota, canonical hashes, original IDs/targets, no-drop/no-rebase rules and
all joins/EOF/drains remain unchanged. A larger pair quota cannot override an
earlier limit at another stage. In particular, the existing attended capture
still acquires only its configured short prefix; this API does not enable longer
live acquisition or sustained/unbounded playback.


## Explicit finite compressed-byte quota

`CapturePlayback(..., byte_limit=N)` forwards one positive integer quota through
capture argument validation, decryption input/clear output and decoder input.
The default remains 16 MiB; the maximum is 256 MiB, matching the existing decoder
file-size ceiling. `CaptureLimits.max_bytes` must also be explicitly configured
and cannot exceed this quota. A larger compressed-byte allowance does not
implicitly enlarge a smaller capture byte allowance.

Expanded pending playback requires `identity_mode='source-sequence'` and a bounded
`diagnostic_tail`, validated before capture claim. For example:

```python
session = CapturePlayback(
    owner, key, args, report,
    limits=CaptureLimits(max_packets=15_000, max_bytes=32 * 1024 * 1024,
                         duration_seconds=30),
    completion='bounded-prefix', identity_mode='source-sequence',
    diagnostic_tail=2, decoder_deadline_mode='consumer-excluding',
    pair_limit=900, byte_limit=32 * 1024 * 1024,
)
session.play()
```

The nondefault quota is bound in preparation and capture receipts. Decryption
uses profile `bounded-decrypted-packet-chunks-v2` with the exact
`total_byte_limit`; default 16-MiB receipts retain v1. Decoder snapshots before and
after cleanup must carry the same total-byte allowance. Terminal verification
checks quota agreement, integer bounded counts, encrypted bytes against capture
yield accounting, and clear output against both decoder snapshots. Missing,
downgraded or inconsistent evidence cannot publish successful prefix completion.

The fixed 1-MiB crypto pending/chunk bound, decoder 1-MiB chunk/64-KiB read windows,
256-KiB/5-second startup budget, resident output credit, packet/chunk/frame/audio
quotas, 60-second capture/decryption/processing/source-span guards, lateness and
all EOF/drain/join/cleanup rules are unchanged. No read-all or producer queue is
introduced. Default CLIs, attended launcher and capture duration stay unchanged;
this is not longer live acquisition or sustained/unbounded playback.

### Explicit startup subset

`CapturePlayback(..., startup_pairing='common-keyframe')` forwards the separately
[bounded common-keyframe startup policy](local-av-capture-preparation.md#explicit-common-keyframe-startup-opt-in)
through pending input and terminal output validation. It is opt-in; the default
remains strict. Invalid mode values leave acquisition unclaimed. No launcher,
account API, retry, quota, source/output deadline or default is changed. Review
the explicit excluded lead-in audit, not just output completion counts.

## Reusable attended direct-LAN command

For a private local credential file, offline runtime checks and an Enter-gated
fixed 30-second development attempt, see
[the attended LAN command](local-av-lan-playback.md). It reuses the pending capture
adapter without adding production dependencies, account discovery, cloud fallback
or a new default startup/audio policy.


## Explicit bounded source-audio gaps

`CapturePlayback(..., gap_limits=limits)` is a development API opt-in for
separately scheduled whole-block padding. It requires pending input,
source-sequence identities, bounded diagnostics and matching finite source and
jitter limits. See the [complete policy and credit contract](local-av-audio-gap-output.md#explicit-pending-capture-api-integration).
Original source PCM, video and targets remain unchanged; padding has separate
acknowledgements. Omitting this argument preserves the strict source-phase guard.
The attended CLI does not expose this opt-in yet.
