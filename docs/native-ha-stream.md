# Continuous native MPEG-PS stream boundary

`pyezvizapi.native_stream` is a headless source owner for an HA integration's
future HTTP route. It incrementally frames/decrypts local MPEG-PS and copies one
observed H.264/HEVC track plus optional AAC into MPEG-TS. No decoder, player,
transcoder, listener or account session is created. Install the optional
`pyezvizapi[streaming]` extra (PyAV 19). The inspected upstream HA
[stream manifest](https://github.com/home-assistant/core/blob/dev/homeassistant/components/stream/manifest.json)
pins `av==19.0.0`; this does not establish the installed HA runtime's version.
Importing the library without that extra remains supported; the owned worker
validates the runtime before calling any source factory.

This library alone is **not an HA camera platform or a published live URL**. A
[temporary HA-hosted validation integration](ha-native-integration.md) now
exercises the HTTP/camera/HLS contract in an isolated real HA runtime. The integration-owned route and isolated HA stream/frontend controls are now
implemented; see the [consumer architecture](ha-consumer-architecture.md) for
shared-delivery, supported-client, maintained API and live-acceptance gates. A
temporary custom integration is the test vehicle; shared library code remains
upstream-compatible. No current HA configuration is changed by these APIs.

## Explicit source and track identity

Use supplied local credentials and the existing lazy offline packet source:

```python
from pyezvizapi.clip import AutoClipSource
from pyezvizapi.native_stream import (
    NativeStreamOptions,
    NativeTrackSelection,
    native_mpegts_stream_from_client,
)

source = AutoClipSource(
    mode="offline", credentials=local_credentials, allow_cloud_fallback=False
)
options = NativeStreamOptions(
    # Illustrative observed PES IDs, not universal lens/channel numbers.
    selection=NativeTrackSelection(video_id=0x1E1, audio_id=0x1C0),
    video_codec="hevc",
)
with native_mpegts_stream_from_client(
    client, serial, source=source, options=options, channel=known_preview_channel,
) as stream:
    for chunk in stream:
        output.write(chunk)  # Caller owns output and its write/disconnect policy.
```

The client helper requires offline mode, supplied credentials and disabled
cloud fallback. It uses an explicit media key or the supplied credentials'
media key by default. `decrypt_video=False` is an explicit clear-input assertion;
it is not an automatic downgrade after a key failure. No key discovery,
registration, credential renewal or account call occurs in this helper. The
caller owns `EzvizClient`; only the per-view transport belongs to this stream.

`channel` is an explicit SDK preview selector, not a main/sub configuration
channel mapping. `NativeTrackSelection` uses actual container/PES IDs and
resolves current absolute indices during this session. The saved-sample
inspector now includes the FFprobe `id` field. An ID is not necessarily a lens
ordinal, nor a stable identity across every firmware/profile. Verify the
mapping for each camera/profile. A missing ID, wrong track kind, unresolved
parameters or codec mismatch fails before output; a later ID/codec mutation
also fails. There is no implicit selection of another lens or audio track.

Only local `MediaPacket` sources containing MPEG-PS are accepted. IDMX/RTP,
cloud sources and non-AAC audio need separate tested adapters. Supply
`audio_id=None` to omit audio deliberately; an unsupported requested audio
track is an error, not silently discarded.

## Async delivery and cancellation

An HA route can consume the same source without blocking its event loop:

```python
stream = native_mpegts_stream_from_client(
    client, serial, source=source, options=options, channel=known_preview_channel,
)
async with stream:
    async for chunk in stream.async_chunks():
        await response.write(chunk)  # An integration-owned response, not created here.
```

Use one owner per admitted upstream ingest, not one owner per frontend viewer.
The integration/delivery layer owns downstream fan-out; never race readers of
this destructive output queue. Await backpressure rather than collecting chunks. A cancelled async read is shielded while transport cancellation runs;
the bridge then retrieves the outstanding executor read before returning. A
second cancellation does not abandon already-owned cleanup. Explicitly close
the generator when ending it early, or exit the async context. The integration
must close owners on disconnect/unload and handle socket write deadlines.

The worker alone closes its iterator. Consumer cancellation calls the source
owner's interruptible `close`, never `generator.close` while `next` is running.
There is one shared finite shutdown deadline for the canceller and mux worker.
A noncooperative factory/read/close reports a timeout and retains the owner;
it is not a successful cleanup. Recover the source, then retry `close` and
check the receipt. A failed close callback does not claim `source_closed=True`.
Primary stream failure and cleanup error types remain separately visible.
Automatic context/generator exit does not repeat a failed shutdown budget;
explicit `close`/`aclose` is the recovery action after the source is repaired.

## Bounds and timestamp policy

- Startup defaults to 20s, input-idle reads to 10s, shutdown to 5s; configurable
  budgets must be positive, finite and at most 30s. Session duration/total bytes
  have **no implicit 30s/120s capture cap**.
- One input packet, retained PS continuation, clear read buffer and individual
  mux write are each capped at 1 MiB. Bounds precede append/copy. Pending video
  cipher state belongs to each PES video ID and timed picture, including
  partial AES blocks across intervening audio/other-lens packets. Only bytes at
  or after unresolved cipher positions remain buffered; completed video-only
  pictures release without waiting for an audio packet. This uses the same
  state machine as whole-buffer decryption. Untimed legacy non-video resets
  remain unchanged. Streaming supports clear 1-/2-byte NAL headers; encrypted
  whole-NAL-header mode (`nalu_header_size=0`) is explicitly rejected before
  acquiring a source, rather than claiming an untested streaming cipher mode.
- Four output credits reserve at most four 64 KiB chunks. Credit returns only
  when a chunk leaves the owned queue or abort discards it. The async consumer
  may additionally hold its currently yielded chunk.
- Libav probing is limited to 1 MiB / five media seconds / 64 streams.
  Output uses a 1us interleave delta and strictly advancing per-track DTS, so a
  missing selected track cannot accumulate seconds of packets in the mux queue.
  Actual PyAV/transport internal allocations and caller-held bytes are outside
  the managed-buffer counters; these counters are not an RSS guarantee.
- Encoded source NALs, AAC and original rational timestamps are copied. PTS can
  reorder for B-frames; per-track DTS must advance. Missing/repeated/backward
  DTS fails rather than inventing timestamps. MPEG-TS may insert access-unit
  delimiters/rescale its time base; verify original non-delimiter NALs and source
  clocks independently. No silence, gain, resampling, lens pairing, trimming or
  discontinuity repair is performed. Received audio gaps/overlaps stay visible.

`read()` returns at most 64 KiB. Empty bytes mean verified finite recording
completion only. Unexpected live source exhaustion is an error, not EOF, and
does not flush buffered encrypted tails. `finite_source=True` is only for
caller-attested recorded fixtures; the client helper refuses it for a live
transport. An explicitly finite recording still rejects a partial final PS
packet. Cancellation discards pending input without a tail flush.

## Evidence and remaining validation

`receipt` exposes constant-sized counters/peaks, current ownership, input/clear
prefix hashes, selected track identities and separate cleanup errors. Live
snapshots can span concurrent operations; final ownership is authoritative
after joining. Prefix hashes alone do not certify whole-source completion.
`finite_source_end` is separate, and `ha_verified` remains false.
`output_bytes` counts published queue bytes, not HTTP/device acknowledgement;
`read_output_bytes` counts bytes returned to the caller and
`discarded_output_bytes` counts abort disposal. Final published bytes equal
read plus discarded bytes when owned output is zero. The HTTP consumer must
separately report its own writes; these are not audibility or physical playback.

Public controls cover H.264/AAC and HEVC/AAC copies, source-clock gaps/jitter,
changed discovery order, blocked source/output, async cancellation, partial
construction, recovery after failed joins and a virtual three-minute source.
The virtual duration test runs faster than real time; it is not a sustained
network/camera test. Retained encrypted two-minute H9c replay is checked against
an independent clear recording and selected output NAL/pixel/PCM/clock oracles.

Actual HA ingestion/frontend compatibility (including browser-dependent HEVC),
live long-run/concurrent-camera behavior, reconnects, other formats/profiles
and physical A/V synchronization still require their own evidence. The existing
player and attended launchers are unchanged.


## Owner-published common clock

`source_clock` is absent before startup and is frozen once the first selected
packet is ready. `NativeSourceClock.origin_90k` is the demuxer's signed
presentation origin in exact 90 kHz ticks, never capture UTC.
`mpegts_origin_90k` is its exact 33-bit MPEG-TS wire residue. Consumers of a
wire-clock declaration must use that property, not assume the demuxer returns
nonnegative timestamps near wrap. This does not modify packets, repair DTS,
infer how many capture wraps occurred, or prove downstream synchronization.
The descriptor is absent for a missing/nonintegral/out-of-domain reference.
Existing discontinuity checks and bounded output ownership are unchanged.

See [HA consumer architecture](ha-consumer-architecture.md) for the recommended
library/integration/relay split and staged production gates.
