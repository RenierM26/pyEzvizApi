# Experimental declared-output native session

This local spike is not part of draft PR397. The HA validation config flow now
supports explicit physical entries with declared child lenses. It tests the missing source primitive behind the
[consumer architecture](ha-consumer-architecture.md): one physical acquisition,
one incremental decrypt/demux worker, separately selected MPEG-TS lens outputs.
It is not a production session registry. Explicit `late_join=True` now allows
staged activation and explicit replacement of a retired lens while a healthy
sibling keeps the source alive. It does not add arbitrary tracks or reopen a
source. The HA example composes the group controller below for explicit multi-lens
entries; single-lens entries retain their original delivery path.

## Ownership

`NativeMpegTsSession(factory, outputs)` accepts one to four predeclared
`NativeStreamOptions`. The factory remains lazy and is called once. Each output
has a distinct explicit track selection; codec, timeouts and finite/live policy
must match because the source/decrypt context is shared. Mixed H.264/HEVC groups
are deliberately rejected until per-track cipher-header handling is reviewed.

The session is the authoritative source owner. All PyAV source and output mux
contexts run in that one inherited native worker, reusing existing cancellation,
transport interruption and bounded join/recovery. Each requested AAC track is
copied into each output that requests it; it is not divided between subscribers.
Packet descriptors are copied before setting output stream identity; original
PTS/DTS/duration, keyframe/corrupt flags and side data are preserved. Unimplemented
discard/disposable semantics fail rather than being silently lost. No decode,
encode, timestamp repair, audio mixing or media listener is created.

```python
from contextlib import aclosing
import asyncio

from pyezvizapi.native_session import NativeMpegTsSession
from pyezvizapi.native_stream import NativeStreamOptions, NativeTrackSelection

# Illustrative observed IDs for one verified shared source, not universal lenses.
options = tuple(
    NativeStreamOptions(NativeTrackSelection(video_id, 448), "hevc")
    for video_id in (480, 481)
)
session = NativeMpegTsSession(existing_lazy_local_factory, options)

async def deliver(output, response):
    async with output, aclosing(output.async_chunks()) as chunks:
        async for chunk in chunks:
            await response.write(chunk)

async with session:
    await asyncio.gather(*(
        deliver(output, response)
        for output, response in zip(session.outputs, responses, strict=True)
    ))
```

The factory and responses are integration-owned; the library does not discover
credentials, start a server, authorize a preview or construct an HTTP response.
The live client helper's offline/no-cloud policy must also be enforced by any
future session composition helper. `finite_source=True` remains only a supplied
recording assertion; it does not make live transport exhaustion successful EOF.

## Cold membership and limits

In the default fixed-cold mode, declare and consume all intended outputs from
the start, or close unused outputs before starting. An unread/stalled output fails under its bounded backpressure
grace (default 0.1 seconds, configurable up to one second). A failed/closed output
cannot be revived within that acquisition. There is no replay cache, additional
preview, automatic restart or profile change. The opt-in staged activation policy
is separate and described below.

Each output retains the existing four 64 KiB credits. Two declared lens outputs
therefore have 512 KiB of declared queue capacity, the same per-output limits as
two separate owners, but only one source/PS decrypt/read context. One source
packet and current mux packet descriptors remain subject to existing packet
bounds. Muxer/codec/transport internal allocations and caller-held chunks are
not an RSS claim.

A stalled mux write can delay siblings for that output's grace before it is
failed. This is bounded head-of-line backpressure, not hard-real-time scheduling
or zero-delay isolation. The healthy sibling continues with its complete original
media; the failed output is never reported successful while dropping packets.
A declared source EOF can be verified even when output delivery failed: source
completion and each output's completion are different states.

Closing one output releases only that subscription. Closing all outputs, or
explicitly closing the session, interrupts and joins the one physical source.
A failed join retains the session for explicit recovery. Per-output receipts
include a `physical_source` snapshot; their local absence of a worker must not
be mistaken for proof the physical owner joined. Session receipts distinguish
source status, aggregate delivery status (including partial delivery), per-output
counters and final totals. A finished mux with an unread queue is draining;
abandoning that tail is partial delivery, not successful consumption. Per-output peaks are not mislabeled simultaneous
aggregate peaks.

## Opt-in staged activation at an original IDR

`NativeMpegTsSession(..., late_join=True)` retains the declared 1-4 selections
but does not mux or queue an unused output. Calling an output's `start()` or
beginning its read requests that one subscription. Entering the physical session
context alone remains lazy in this mode. The source worker alone owns
all new mux contexts, and no second transport/decrypt/demux is started.

Requests present at the worker's initial output-binding snapshot retain the existing complete cold
prefix, including AAC that demux may surface before the opening video access
unit. Requests observed after that boundary wait for a selected, noncorrupt
keyframe whose Annex-B access unit carries an independently admissible IDR:

- H.264 IDR slices with reference priority and an in-band SPS → PPS → slice
  identifier chain. Partition/extension and non-IDR starts are unsupported.
- HEVC base-layer, temporal-id-zero IDR_W_RADL/IDR_N_LP with in-band VPS → SPS →
  PPS → slice identifiers. CRA/BLA and scalable/temporal variants are unsupported.
- Dependencies must precede the first picture in that same access unit, with
  exactly one first slice and no ambiguous duplicate parameter IDs. Missing or
  mismatched sets do not join. The bounded parser checks dependency identifiers;
  it is not a decoder or a complete codec/parameter-set validator. Complete access
  unit framing remains the demuxer's responsibility.

There is no cached parameter injection or media replay. The late output begins
with that original IDR and retains original encoded bytes and PTS/DTS. Its clock
descriptor is the integral signed 90 kHz presentation reference of that actual
IDR, not a stale source-start origin or a guessed wrap epoch. Unsupported clock
references fail only that output. AAC starts at the first subsequently demuxed
packet with PTS at or after the IDR; earlier-demuxed AAC is not backfilled.
Subsequent leading video with PTS before the IDR fails the subscription instead
of silently dropping a picture while claiming success.

The existing startup timeout bounds waiting for a usable IDR. Timeout/cancel,
unsupported dependencies or finite EOF before admission do not restart the source
or cancel an already requested healthy sibling. Closing the final requested
output stops and joins the physical source even if declared unused lenses remain.
No output handle can reopen after close, and no subscription can activate after
physical EOF. An explicit fresh handle may replace a retired lens as below.

Receipts distinguish unused declared capacity, requested subscriptions, cold/IDR
mode, and exact join reference. `all_outputs_completed` still covers the whole
manifest; `all_requested_outputs_completed` excludes unused outputs. The aggregate
source/session receipt never treats an unconsumed mux tail as completed delivery.
Late AAC has normal decoder priming: encoded suffix parity does not imply the
first decoded block equals a continuously running decoder. Retained controls
compare PCM after the first 1,024 samples and report that priming boundary.

### Generated startup-boundary qualification (2026-11-01)

`tests/test_native_startup_boundaries.py` adds twelve offline encoder-backed
controls, without changing runtime admission. These qualify the native PS → TS
boundary only; they do not certify HA segmentation, MP4 configuration records,
browser decoders or a live camera's parameter-change behavior.

| Generated source | Observed contract |
| --- | --- |
| HEVC open GOP with actual CRA and RASL pictures | Late request never admits CRA, emits no bytes and fails at finite EOF; cold sibling retains every encoded AU, timestamp and decoded picture. |
| HEVC IDR_W_RADL with actual RADL pictures | The self-contained IDR admits; a subsequent picture before its presentation reference fails that subscription, rather than silently dropping it and reporting completion. Cold sibling remains exact. |
| H.264/HEVC long GOP with no later IDR | No late completion or output at EOF. During a blocked worker interval, the reader's startup deadline fails/closes only that handle. It cannot restart itself. |
| Fresh in-band parameters with a resolution change, H.264/HEVC | Native TS preserves original NAL payloads, AAC and PTS/DTS; cold decoding sees both 64×48 and 96×64. A new IDR join decodes the exact new-resolution suffix without cached parameter injection. |
| Same transition across the 33-bit wire boundary | Both fresh late joins and explicit replacement of an already active old mux use the current signed demux reference. Old negative and new positive references stay distinct; no guessed epoch or source reopen. |
| Explicit replacement after a no-IDR timeout | A healthy sibling keeps the one factory/source alive; a fresh subscription joins a later original IDR with new parameters. The failed old handle never acquires completion. |

Video comparisons hash visible decoded YUV bytes, excluding allocation padding,
as well as original non-AUD NAL payloads and exact packet PTS/DTS. AAC checks are
encoded-byte/timestamp comparisons, not a new decoded-PCM or physical-audio
claim. The generated splice deliberately declares a forward interval between
encoder segments, avoiding overlapping independent AAC priming/tails; production
timestamps are not changed. All cases close their source and join the worker.

This does **not** add CRA/leading-picture support, arbitrary parameter-set
validation, seamless HA resolution renegotiation, all wrap epochs or all GOP
layouts. Unsupported late starts still fail closed within the existing reader
startup/finite-EOF rules. Calling `start()` without reading is not an independently
scheduled deadline: the reader owns that timeout. Generated bounded controls do
not establish live pacing, wall-clock soak or every source boundary.

Validation: 89 scoped access/startup/session/replacement tests pass; the full
library suite passes 5,032 tests with 90.38% coverage (105.47 seconds). Ruff,
Mypy (62 library source files), Pyright and scoped spelling checks pass. These
are source-checkout tests, not a new installed-wheel or HA/relay delivery claim.
Runtime library and HA example files remain byte-identical to `72c8a5645a38`;
only tests and documentation change in this checkpoint.

### Explicit replacement without another acquisition

In late mode only, `session.replace_output(previous_handle)` returns a fresh,
lazy handle for that same declared selection. The caller must first close the
previous handle and finish its reader. A requested healthy sibling must still
keep the physical worker alive. The call can wait up to `close_timeout` for the
worker to close the old mux; run it off an event loop. A retirement timeout
retains the previous handle and requires an explicit retry, not a source restart.
Stale handles, active readers, fixed-cold mode, stopped/failed sources and EOF
cannot replace a subscription. Old close calls cannot close a newer generation.

The worker reuses one per-selection context stack, closing its old mux before
opening another. Retired output queues must have no outstanding credits. Neither
mux callbacks nor receipt histories accumulate; only bounded cumulative retired
byte/count counters remain in the owner. Caller-held old handles remain the
caller's responsibility. The active declared queue capacity is unchanged.

The new handle requests no media until read/start, then admits a fresh original
IDR with its own current source clock and AAC cutoff. No old chunks, cached
parameter sets or old source-origin clock are carried forward. Source attempts,
transport, decrypt/demux and selected track declarations remain unchanged.

Receipts expose `subscription_generation` and verified `mux_retired`. Current
`outputs`/`output_totals` are separate from cumulative `retired_output_totals`,
`retired_subscriptions`, failed and partial retired counts. Historical aborted
requested delivery keeps aggregate status partial/failed even if current outputs finish;
`current_requested_outputs_completed` distinguishes successful current delivery
from `all_requested_outputs_completed` across retired generations. Retiring a
never-requested lens does not invent an aborted delivery or fail healthy outputs.

## HA startup boundary found by the spike

Default zero-length video PES can leave the demuxer holding the opening video
AU while surfacing an AAC packet. HA advances to its first video keyframe and
can consume that leading audio before muxing. The retained negative control
lost exactly the first of 1,857 AAC packets in both HA workers even though each
HTTP body contained all packets.

The experimental session uses FFmpeg's `omit_video_pes_length=0` option. Explicit
extents on subsequent complete video PES let the parser release the opening AU
before following AAC, including the retained source with a 117,149-byte opening
keyframe. No payload, timestamp, credits, buffer sizes or HA implementation was
modified. A public wire-format control checks extents on generated small AUs.
This is acceptance for the tested sources, not proof of every large-AU or codec
startup pattern. The original single-output owner's container settings remain
unchanged in PR397; broader/backported startup changes need their own regression.

## Offline evidence

The spike checks generated two-lens sources, common AAC and exact source packet
clocks, lazy factory/demux counts, failed output isolation, closing a sibling,
all-output stop, failed join/recovery, invalid membership/policy, single-slot
async cancellation, keyframe flags and video PES declaration.

Private retained encrypted replay goes through two simultaneous actual HA
2026.10.4 HLS workers using test-only HTTP routes. One source factory, one input
demux, and one decrypt-feed path process both lenses. Both full workers receive
1,783 HEVC pictures / 1,857 AAC packets. Independent original NAL, full pixel,
PCM and clock comparisons pass. Stopping the first HLS worker after 40 pictures
leaves the other complete, without another factory call. All owners close/join.
These are worker-ingestion tests, not frontend, live-camera or physical A/V proof.

## Explicit HA group-controller prototype

`examples/home_assistant/custom_components/ezviz_native/group.py` owns the
physical session separately from per-lens HTTP leases. The `GroupEntry` composition
in `entry_runtime.py` now connects explicit multi-lens config entries, stable child
cameras and one shared Prepare/status UI. No automatic grouping of separate
entries is performed. Both HTTP routes use one integration-wide `Admission`.

- `GroupIdentity` requires an explicit physical selector, verified profile, and
  opaque credential revision. These are caller-supplied identity assertions, not
  automatic verification of a factory or comparison/hashing of camera secrets.
  An existing physical key cannot acquire another profile/revision until closed.
- A declaration copies/freezes one to four compatible output policies without
  starting native transport. Each member has its own random loopback capability.
- Synchronous admission reserves one attempt for the whole physical group. In
  default fixed-cold mode all declared readers must arrive within a bounded cold barrier (default five
  seconds, maximum thirty) before any read starts. A missing/disconnected member
  ends that attempt without starting a source. No manifest is silently shrunk.
  Explicit `declare(..., late_join=True)` starts on the first reader and lets
  subsequent declared readers use the library IDR admission rule without a cold
  barrier. HTTP retries remain blocked after that member's first lease until an
  explicit per-lens preparation authorizes one new subscription.
- The four-active limit counts physical groups, including cold barriers and
  retained failed joins, rather than counting lens requests. When constructed alone this limit is local
  to `GroupRegistry`; the composed `IntegrationRegistry` instead supplies one shared allocator to
  both routes. Separately constructed test registries retain independent budgets.
- Releasing/unloading a running lens closes only its output and revokes its
  capability. Its already-admitted sibling continues. Removing a cold member
  aborts the whole attempt; a detached manifest cannot be prepared again.
- Whole-group `prepare` requires no active leases and confirmed physical cleanup.
  It rotates every capability and constructs a new lazy owner without acquiring.
  Concurrent Prepare requests cannot each create a generation. Changed manifests
  or credential/profile revisions require full close and explicit redeclaration.
- Group shutdown revokes first, cancels HTTP tasks, then joins the physical owner.
  A failed implicit join retains that exact owner and admission slot; handler
  cleanup does not repeat its shutdown budget. Explicit Prepare/close can retry.
  Closing an old group cannot remove a subsequently reassigned member mapping.

HTTP EOF and output closure are not proof all sibling delivery and physical
cleanup finished. Observe the group lease/cleanup state and authoritative source
receipt. The route emits explicit no-retry metadata, preserves the owner-derived
clock descriptor, bounds output writes and closes an incomplete response on error.
The composed entry adds one lazy, atomic/common-clock relay registration per
lens and coordinated provider invalidation. It does not add a player.

Generated-source controls exercise real HA HTTP and two actual HLS workers,
capability revocation, lazy re-arm/reopen, physical admission limits, incomplete
barriers, sibling unload and failed-join retention/recovery. Retained encrypted
replay through this controller again yields complete 1,783-picture / 1,857-AAC
outputs from one factory/demux/decrypt path; stopping one worker leaves its sibling
complete. Payload hashes and complete timestamp vectors equal the prior source
spike's independently decoded NAL/pixel/PCM/clock oracles. This is not supported
browser HEVC playback or a live-camera acceptance claim.

## Config entry and recovery composition

Single-lens configuration remains compatible. To opt into a shared physical
entry, select additional lenses in the user flow and explicitly supply a verified
profile label, opaque credential revision and up to three child mappings. The
primary lens retains its existing entry unique ID. Each child uses a stable
logical key, not a PES ID/ordinal/display name, and shares one HA device with the
primary camera, recovery button and diagnostic sensor. Renaming/reordering a
child does not create a new entity identity. No credentials are discovered or
stored inline in the config entry; the private file remains the source.

Group entries require explicit loopback relay, source-clock and atomic ownership
contracts. Each lens has a distinct lazy relay upstream; stock/unverified relay
contracts do not fall back to direct multi-reader acquisition. Setup, source URL
registration, still images and Prepare do not acquire a preview. Two legacy/group
routes cannot acquire the same physical device/SDK selector concurrently, and the
common four-source limit includes failed joins and cold barriers.

Prepare pauses admission and revokes every lens token before awaiting cleanup.
It serializes against in-flight cached stream creation, refreshes WebRTC providers,
stops HLS/preload and discards cached source URLs. Only joined physical cleanup
and confirmed narrow relay removal allow fresh lazy owners/relay names. Uncertain
registration is explicitly recoverable even before a native attempt; construction
failure after partial re-arm remains paused and retryable. No private HA storage
or config-entry state is changed to make a failed cleanup look successful.

Normal config-entry unload revokes and stops all consumers before dropping client
ownership. If cleanup is uncertain, handles remain retained and HA reports failed
unload. HA 2026.10 does not allow a normal reload retry from that non-recoverable
state: shutdown retries retained cleanup, and restart is required. Do not advertise
ordinary reload as recovery after FAILED_UNLOAD. This differs from in-place
Prepare of an otherwise loaded entry, which can explicitly retry failed joins.

Each lens also exposes **Prepare lens subscription**, available only after that
lens's HTTP lease closes while a sibling remains active. It blocks/revokes only
that member before awaiting provider cleanup, clears its cached HLS stream and
refreshes its WebRTC providers, narrowly removes its old relay registration, and
asks the source worker for a fresh output handle. The sibling's capability,
relay, lease, physical attempt and admission reservation remain unchanged. The
replacement relay stays unregistered and the handle unused until the next
explicit preview. Automatic HTTP/relay retries still cannot obtain another lease.

Failed cleanup retains the blocked member and uncertain relay handles for an
explicit retry. Cancellation during off-loop replacement waits for the result,
retaining a completed-but-unpublished handle rather than losing or automatically
activating it. Whole-group Prepare still requires all viewers closed and handles
recovery after physical EOF; no per-lens operation can resurrect a source.

Actual entry/camera → patched relay RTSP → HA HLS controls preserve complete cold
and original late encoded/decoded suffixes. Source/native HTTP clocks remain
unchanged. RTSP/PyAV uses a common presentation rebase; tested AAC/video phase
difference is -11/240000 seconds (about -45.833 microseconds), within one 16 kHz
AAC timestamp tick (62.5 microseconds), constant without drift. This is not a claim
of identical absolute RTSP timestamps or physical A/V sync.

The later replacement control exposes an additional HLS startup boundary. Native
HTTP PTS/DTS remain exact for every cold/replacement packet, but raw FFmpeg/PyAV
RTSP demux yields no PTS/DTS for its first video packet. A bounded transparent TCP
observer verifies every on-wire RTP timestamp (including that opening video AU)
against the source at its advertised clock rate, with sequence continuity and
sender reports; the timestamp loss occurs at the receiving demux boundary, not
in the source output or the relay's RTP timestamp mapping. HA 2026.10.4 reconstructs
that packet from the second video's DTS minus duration. At the tested replacement
IDR, the source's first interval is 6,002 rather than 6,000 ticks, so HA's first
video PTS/DTS differs by two 90 kHz ticks (22.222 microseconds) from the otherwise
constant source shift. AAC and later video retain constant per-track shifts.
The first A/V phase error is -49/720000 seconds (-68.056 microseconds), outside
the previously tested one-AAC-tick (62.5 microseconds) budget; later phase error
is again -11/240000 seconds. Do not describe this as zero drift/exact startup
clock parity or silently widen that budget. Original payloads/pictures/AAC remain
unchanged. The example does not falsify durations, repair source clocks or patch
HA's worker. An upstream RTSP-demux/HA startup-clock review remains a separate gate. A subsequent
[isolated upstream review](ha-initial-source-clock-review.md) reproduces the parser
byte-offset cause and validates two external proposals without shipping them or
changing this runtime.

## Next integration gates

1. Review this source API separately from PR397's already-reviewed single-output
   contracts. Do not silently replace that PR's head/CI evidence with this spike.
2. Review the new explicit physical-entry composition: verified declarations,
   common admission, stable lens keys and coordinated provider/relay recovery.
   Normal failed unload puts HA into non-recoverable FAILED_UNLOAD; retained
   cleanup is retried at shutdown and HA restart is required, not a private state
   reset. Ordinary session failures use in-place Prepare before entry unload.
3. Review whether to broaden IDR-only admission: CRA/leading pictures remain
   unsupported, with encoder-backed refusal/sibling-isolation controls above.
   Generated parameter changes, no-IDR EOF/deadline recovery and replacement
   across wrap now have native-boundary controls; HA configuration renegotiation,
   other GOP/layout/epoch cases and live behavior remain gates. Arbitrary new
   track selection remains unsupported. Never infer a fixture epoch or acquire
   another camera preview to make a late subscription succeed.
4. Exercise per-lens simultaneous HLS/WebRTC through a supported shared protocol
   boundary, group Prepare/re-arm/unload, credential replacement and TLS topology.
5. Preserve separate maintained-relay, supported-client HEVC and attended
   live/long-run/physical A/V gates. No production configuration changes are made.
