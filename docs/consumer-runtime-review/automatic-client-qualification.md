# Automatic receiver and authenticated client qualification

> **Pinned historical evidence / proposal.** Retained for its recorded revisions and
> reproducibility, not current installation or deployment status. Start with the
> [documentation index](../README.md) and [current HA status](../home-assistant.md).


Main-based follow-up to merged PR399 (`9a4fbe8`). These are **isolated source
proposals**, not dependency releases, a supported HA deployment or permission to
replace managed HA/relay binaries. No production/account/camera changes or new
live acquisition were used. See [exact source manifests](qualification.json).

## Corrections

### Automatic RTX reads and normal feedback

The old Pion receiver polls a separate 50-packet repair queue before blocking on
primary RTP. Repair-only traffic cannot wake that primary read, and restored RTX
bypasses the original RTP interceptor chain. The default loss tracker therefore
continues requesting already repaired originals. Fresh sender-side RTX sequence
numbers from PR399 are necessary but do not correct these receiver defects.

The Pion proposal uses the pinned SRTP dependency's existing `SetRTX`,
`NextStream` and `SourceReader` APIs. Primary and repair retain independent crypto,
replay state and existing per-SSRC buffers. One application pull owner consumes
either stream. Repairs traverse their own interceptors, restore negotiated APT,
OSN and original SSRC, then traverse the original stream's interceptor chain.
Cached wire-header attributes are cloned/refreshed, not mutated or discarded.
Deadline, close, RID/RSID association and original header extensions/padding are
covered. No extra forwarding goroutine/queue or larger media/cache/replay/socket
budget is introduced. Custom `BufferFactory` retains its legacy path; the new
pull-path guarantee is not claimed for that path.

A receiver's **default interceptor** generates feedback. A test-only output gate
delays those generated NACKs to a declared primary frontier; it does not invent
missing-packet inventories or call `WriteRTCP` with synthetic NACKs. Sixteen
controls cover H.264 baseline/constrained/high and H.265: late 74-original loss
with one lost repair, repair-only terminal traffic, early no-RTX recovery, and
unchanged late no-RTX anti-replay rejection. The unchanged receiver fails seven
controls, including all four repair-only controls; the proposal passes all 16.
A separate real-SRTP control pulls 100 repairs without a 50-packet forwarding cap.

### Provider-preserving codec preflight

The explicit joint profile rejects receivers without the configured H.264/H.265
video and Opus audio before source access. SDP media scope, rejected ports,
listed payloads, receive direction and clock rate are checked. This is a
non-acquiring preflight, not a replacement for the provider's full SDP parser.
Legacy profiles defer unchanged to provider negotiation.

An exploratory offer-handler override failed a real HA browser run: HA correctly
classified that override as a native signaling implementation and stopped
selecting go2rtc. The final proposal adds public
`Camera.async_validate_webrtc_offer`, called by the existing provider-backed
base handler. The example overrides only this callback. It neither changes
private HA provider flags nor implements its own signaling/candidate lifecycle.
Incomplete hosts reject before registration/acquisition; the public completion
API, validation hook and source-clock contract must all be present.

The example has 42 SDP/profile controls and two additional missing-hook host
controls. Three source-side camera tests cover rejection, provider delegation
and the default no-op. Actual authenticated HA WebSocket commands independently
exercise both refusals and compatible offers in the browser lab.

### Finite native-input probe startup

The authenticated browser exposed a separate five-second input probe stall.
Source iteration was already paced; relay probing and native Opus output were
prompt once data reached them. PyAV's extended native stream/rate analysis withheld the
opening, then delivered it in a burst. It was not a missing RTP sequence.

Only explicitly caller-attested `finite_source=True` owners use minimal positive
analysis duration (one source microsecond, not a wall timeout) and `fpsprobesize=0`.
Disabling FPS probing alone still fails all four held-tail controls. The existing 1 MiB probe, 64-stream cap,
startup/idle timeouts, source/queue bounds and packet/codec/clock validation stay
unchanged. Continuous sources retain their original analysis policy. There is
no `nobuffer` discard, padding, timestamp rebasing, inferred source clock or
reacquisition. Four deterministic single/grouped, video/audio-first held-tail
controls fail on unchanged code and pass with the fix; full AAC payloads and
original track clocks remain exact after the tail is released.

### Closed server-WebSocket heartbeat

The real HA browser test completed media but failed clean teardown against
unchanged aiohttp 3.14.5. Late parser notifications/deferred heartbeat resets
could recreate a timer on an already closed server WebSocket. The small aiohttp
proposal ignores those callbacks after closure; active-heartbeat behavior stays
covered. Two closed controls fail on unchanged code; all four active/closed
controls pass with the proposal. The browser lab then passes including teardown.
It uses an isolated package overlay with the same installed Cython extensions;
no managed or installed package was edited. Full aiohttp/platform CI is not
claimed. The changelog's provisional `0` must be replaced with an actual upstream
issue/PR number before submission.

## Retained-media acceptance

The earlier automatic-feedback LL/non-LL runs pass all six independent HLS,
WebRTC and Opus/source-clock audits: one owner/demux, 8,840 decrypt callbacks,
complete 1,783 HEVC + 1,857 AAC HLS samples per lens, all 1,873 original non-AUD
HEVC NALs and 5,943 emitted Opus packets per WebRTC lens, including the tail.
Each received Opus stream decodes 5,705,280 nonzero 48 kHz samples. Every injected
74-original pre-SRTP loss and one lost repair is recorded; normal NACK inventory
converges 74 → 1. Cross-track/lens RTCP mapping stays within 21 microseconds.

Final retained rerun after the finite-probe change: **both LL/non-LL pass all
six independent audits**, including exact opening/tail payloads and timestamps.
RTCP mapping spread is 20.694/20.811 microseconds. Earlier
failures are retained, not erased by passing reruns. Qualification is bounded to
these tested cases; arbitrary overload, expired repair caches, unsupported
custom buffers or frame-perfect browser display are not promised.

## Authenticated supported-browser smoke test

A real isolated HA instance registers both camera entities with the public
provider API. A non-admin HA test user authenticates over HTTPS/WebSocket, gets
states, sends offers and trickled candidates, and receives real HA session,
answer and candidate events. Incompatible video/audio offers are rejected
without source acquisition. Missing HTTP credentials, invalid WebSocket tokens,
missing lab control authorization and forwarded-IP attempts at raw native routes
are rejected. The generated clear H.264/16 kHz AAC fixture uses an explicitly
clear test transform; this is not a cryptographic-source qualification.

Managed Linux Chromium 153 decodes 120 H.264 frames from each lens and nonzero
Opus audio, with zero reported RTP loss. Moving/non-black pixels are sampled in
the rendering page; displayed callbacks and decoded frames are reported
separately. The selected clean run presents 120/107 callbacks, not a claim that
every decoded frame was visually displayed. Audio analysis is deliberately
silent, so this is not physical audibility or A/V synchronization acceptance.

The browser pins only the ephemeral certificate's SPKI in its isolated launch;
an independent client verifies the test CA and hostname. This is encrypted,
authenticated protocol-path evidence, **not** publicly trusted browser PKI,
production proxy/topology certification or an official HA frontend test. No raw
credentials, SDP, media, private certificates or browser tokens are published.

The managed browser reports neither H.265 WebRTC nor HEVC MP4 decoding. A
stream-copied retained HEVC/AAC clip was presented privately in the requesting
viewer's chat widget, but **no viewer playback report has been received**. Actual
HEVC client playback remains pending; hosting a widget is not playback proof.

## Reproduce source checks / upstream handoff

Apply each cumulative patch to its own exact public base in [the bundle table](README.md).
Run `git apply --check` first. Do not apply it on top of an earlier prototype.
The manifest identifies every changed path and resulting SHA-256. No `go.mod`
replacement, private build path, binaries, SDK or media is published.

For the paired Go proposals, use Go 1.26 and fresh sibling `go2rtc` and `pion`
source trees, then create a workspace in their parent:

```sh
go work init ./go2rtc ./pion
cd pion
go test -p 2 -race -vet=off . \
  -run 'TestRTPPull|TestRTPReceiver|TestPeerConnection_Simulcast_RTX|Test_PeerConnection_RTX_E2E' -count=1
cd ../go2rtc
go build -p 2 -buildvcs=false .
go test -p 2 -race -vet=off ./pkg/webrtc ./pkg/rtsp ./pkg/mpegts ./internal/streams ./pkg/h265 \
  -run 'TestNative|TestRTX|TestSource|TestOwned|TestFinite|TestNoReconnect|TestAggregation|TestMalformedAggregation' -count=1
```

These are selected race checks, not full upstream CI. A full local Pion run
fails `TestICEGatherer_RelayAcceptanceMinWait` in its existing vnet/TURN/ICE wait;
the exact unchanged dependency-graph baseline reproduces that same timeout.
The unchanged go2rtc core `StripUserinfo` test compilation problem also remains
documented. Neither failure is suppressed or called green.

For the public HA source proposal, use HA's Python 3.14 development environment:

```sh
uv run --no-sync pytest tests/components/stream tests/components/camera/test_webrtc_validation.py
```

Stream controls remain the earlier 158-test checkpoint; the three camera controls
are new. Scoped example checks use actual HA types; full HA repository/platform
CI and a supported core integration are not claimed.

For aiohttp, follow its pinned `AGENTS.md`/dev setup, with compiled extensions
installed, and run `pytest tests/test_websocket_closed_heartbeat.py`. Maintain its
MIT/Apache notices and replace the provisional changelog number. Any later
upstream submission must start as draft and requires the operator's human review
before leaving draft; no upstream PR has been submitted here. FFmpeg's existing
source/FATE package is unchanged; its full external-sample/platform CI remains a
maintainer gate. This bundle is review input, not a maintained dependency fork.

Current local repository checkpoint: 5,056 library tests, 90.39% coverage;
226 example tests including eight separately enabled real-relay controls; library
mypy (243 files), actual-HA mypy (15), Pyright, Ruff and spelling checks pass.
Exact-head hosted checks and review closure are recorded on PR400, not inferred
from these local results. Physical HEVC/audio/A/V, attended battery/live tests,
long-run stability and maintained upstream releases remain separate gates.

## Codex follow-up: zero-port bundle-only offers

RFC 8843 section 6 distinguishes a rejected zero-port media section from a
`bundle-only` member using its group's transport. The preflight now accepts
zero-port members only with a media MID, its `bundle-only` marker and matching
session-level BUNDLE membership. Missing/unlisted MIDs, media-level group
lookalikes, ordinary rejected sections, unsupported codecs and non-receiving
directions remain refused. Full transport/SDP validity remains with the provider.
Five compatible controls fail before this correction; all 42 SDP/profile
controls and all 226 example tests pass afterward, including real-provider
contract delegation for both H.264/H.265 with bundle-only Opus audio. No media,
source-clock, source proposal or resource-bound behavior changes in this fix.
