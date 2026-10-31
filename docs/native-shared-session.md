# Experimental declared-output native session

This local spike is not part of draft PR397 and is not wired into the HA
validation config flow. It tests the missing source primitive behind the
[consumer architecture](ha-consumer-architecture.md): one physical acquisition,
one incremental decrypt/demux worker, separately selected MPEG-TS lens outputs.
It is not a production session registry. Explicit `late_join=True` now allows
staged, single-use activation of declared outputs; it does not add arbitrary
tracks, replace finished subscriptions or reopen a source. The HA example has
an explicit, unregistered group controller described below; normal config entries
still use the original per-entry runtime.

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
No output can activate after physical EOF or reopen after close; retry/replacement
requires an explicitly rearmed acquisition.

Receipts distinguish unused declared capacity, requested subscriptions, cold/IDR
mode, and exact join reference. `all_outputs_completed` still covers the whole
manifest; `all_requested_outputs_completed` excludes unused outputs. The aggregate
source/session receipt never treats an unconsumed mux tail as completed delivery.
Late AAC has normal decoder priming: encoded suffix parity does not imply the
first decoded block equals a continuously running decoder. Retained controls
compare PCM after the first 1,024 samples and report that priming boundary.

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
physical session separately from per-lens HTTP leases. It is not registered by
`async_setup_entry`, exposed in the config flow, or connected to the existing
Prepare button. Tests explicitly declare the complete group and register its
separate `GroupStreamView` with isolated HA.

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
  barrier. It still permits only one activation per member in that acquisition.
- The four-active limit counts physical groups, including cold barriers and
  retained failed joins, rather than counting lens requests. This limit is local
  to `GroupRegistry`: the separately registered legacy `Registry` has its own
  counter. Do not enable both as independent production admission authorities;
  production composition needs one integration-wide allocator.
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
It does not implement relay registration, provider invalidation or a new player.

Generated-source controls exercise real HA HTTP and two actual HLS workers,
capability revocation, lazy re-arm/reopen, physical admission limits, incomplete
barriers, sibling unload and failed-join retention/recovery. Retained encrypted
replay through this controller again yields complete 1,783-picture / 1,857-AAC
outputs from one factory/demux/decrypt path; stopping one worker leaves its sibling
complete. Payload hashes and complete timestamp vectors equal the prior source
spike's independently decoded NAL/pixel/PCM/clock oracles. This is not supported
browser HEVC playback or a live-camera acceptance claim.

## Next integration gates

1. Review this source API separately from PR397's already-reviewed single-output
   contracts. Do not silently replace that PR's head/CI evidence with this spike.
2. Compose the explicit group controller into HA entry ownership: verified
   physical/profile/credential declarations, one shared admission allocator,
   group-level recovery UI and stable per-lens entities. The existing per-entry
   Runtime cannot simply treat an output as an independent physical owner.
3. Review and broaden staged IDR admission where needed: CRA/leading-picture,
   parameter changes, long-GOP/no-IDR and wrap/startup boundaries. Arbitrary new
   track selection and repeated subscriptions within an acquisition remain
   unsupported; do not introduce replay/clock guesses or another camera preview.
4. Exercise per-lens simultaneous HLS/WebRTC through a supported shared protocol
   boundary, group Prepare/re-arm/unload, credential replacement and TLS topology.
5. Preserve separate maintained-relay, supported-client HEVC and attended
   live/long-run/physical A/V gates. No production configuration changes are made.
