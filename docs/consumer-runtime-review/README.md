# Finite HLS/WebRTC source-review bundle

This review includes **source proposals, not installed dependencies**. They close
local finite-recording startup, AAC-to-Opus attachment, delivery and clock gaps.
Stock HA/go2rtc/FFmpeg do not acquire these guarantees from installing pyezvizapi.
Do not replace a managed HA component or relay binary with this bundle.

## Review bases

| Proposal | Public source base | Contents |
| --- | --- | --- |
| [go2rtc](go2rtc-native-consumer.patch) | AlexxIT/go2rtc `7c05066c90ab6ad1fccb506d5f0408aa31ebe60f` (1.9.15) | Cumulative Go runtime/tests: source clocks, finite EOF, no retry, atomic runtime ownership, HEVC AP correction, bounded native queues, explicit joint Opus profile, RTCP mapping, NACK feedback and negotiated RTX repair |
| [HA stream](home-assistant-finite-stream.patch) | home-assistant/core `357cae5c598dfcd7a0ea7dc5b1facccd4ec6037b` (2026.10.4) | Cumulative stream component/tests: initial clocks, owner-confirmed finite completion, publication/revocation, bounded AAC-first startup and declared AAC filtering |
| [FFmpeg](ffmpeg-parser-source-and-fate.patch) | FFmpeg `946fcce07b6dcd0331c8cc609192aeff5e1924f8` (`n9.0.2`) | Unknown parser byte-position initialization and generated AAC FATE regression |

Upstream licenses remain applicable: go2rtc MIT, HA Apache-2.0, and FFmpeg's
applicable source licenses/build configuration. The patches retain source notices.
They are review inputs for their respective maintainers, not upstream submissions,
releases or a commitment to maintain a bundled fork. Human review and current
upstream/platform checks remain required. No binaries, SDK, media, keys, source
URLs, private certificates or account details are included.

## Explicit profile and unchanged defaults

The example's validated config data may opt in with `finite_source: true` and
`relay_native_opus: true`, alongside explicit grouped lenses, source-clock and
atomic-ownership flags. Both new values default to false. These are **isolated
finite-source validation settings**, not a new live-camera recording API or a
normal UI deployment flow. Tests supply a retained finite owner. A live transport
ending unexpectedly is still not successful recording completion.

The joint profile additionally requires:

- The public HA `source-access-units-v1` completion API and explicit initial-clock
  preservation; unsupported hosts reject before native acquisition.
- Negotiated relay `native-opus-source-clock-v1`, source-clock, no-retry and
  `runtime-token-v1` features before registration/acquisition. No silent fallback.
- Linux with an explicitly available local FFmpeg/libopus encoder and the
  verified 16 kHz mono AAC-LC configuration `1408`. Other profiles fail closed.
- WebRTC senders ready before this finite joint source flows. Late viewers do
  not receive an invented/replayed prefix. Supporting arbitrary late joint joins
  is a separate policy, not an automatic reacquisition.

The original video and AAC go unchanged to HLS. Only the declared WebRTC audio
branch is lossy AAC-to-Opus conversion; HEVC is not transcoded. A bounded pipe
carries original AAC bytes and exact 33-bit PTS to the producer-owned converter,
which is admitted before media starts. Its MPEG-TS Opus parser retains every
packet, including the final PES. Normal codec priming and packetization are
measured, not padded away. An extra internal epoch permits negative Opus priming
near zero while preserving the original 33-bit wire residue.

One opaque acquisition clock domain joins both lenses. In-process opaque RTSP
references carry owned source metadata through the relay's own hops; unknown
references reject. Sender Reports preserve actual NTP send time (and RTT
semantics) while projecting RTP from one source-presentation mapping. This does
not change RTP media timestamps or recover camera UTC. Native RTCP readers
service the existing NACK cache and are joined on close; no cache/queue/socket
limits are raised. Overflow fails the affected native viewer, never silently
reports successful complete delivery. Legacy behavior stays separate.

HA finite startup peeks/retains at most the existing 20-packet audio prefix and
rejects a missing/non-key opening video packet. Declared finite AAC always uses
`aac_adtstoasc`, including when the probe prefix contains only video. The
explicit source-clock path uses HA's existing outer source-open timeout rather
than an incompatible shorter nested RTSP timeout; legacy RTSP stays at 5 seconds.

## Reproduce source checks

Use fresh checkouts at the exact bases above. Apply each patch only in its own
isolated source tree, with `git apply --check /absolute/path/to/patch` followed by
`git apply /absolute/path/to/patch`. These are cumulative patches, not additions
to the earlier private prototypes. Apply-check and resulting source hashes were
verified against the public bases; [provenance](qualification.json) records hashes.

For go2rtc, with Go and FFmpeg/libopus installed:

```sh
go test -p 2 -race -vet=off ./pkg/webrtc ./pkg/rtsp ./pkg/mpegts ./internal/streams \
  -run 'TestNative|TestRTX|TestSource|TestOwned|TestFinite|TestNoReconnect'
go test -p 2 -race -vet=off ./pkg/h265 \
  -run 'TestAggregation|TestMalformedAggregation'
```

The first command is deliberately **selected tests**, not full dependency CI.
The unchanged base's full core tests reference missing `StripUserinfo`; existing
vet warnings and broader baseline RTSP/streams failures are not hidden by the
selection. The core queue controls were also run with every actual core runtime
Go file plus `sender_timeout_test.go`, excluding that broken baseline test file.

For HA, follow its `script/setup` development instructions and use its configured
Python 3.14 environment:

```sh
uv run --no-sync pytest tests/components/stream
```

The extracted combined component suite passes **158 tests**. Its new deterministic
controls include 0/1/2/19/20 audio-prefix packets, legacy trimming, over-limit and
non-key rejection, AAC filter selection without consuming probe packets, and the
explicit versus legacy RTSP open budget. Changed source/test Ruff and scoped
checks are separate from maintainers' full CI. Existing recorder Ruff findings
are unchanged baseline, not fixed by unrelated edits here.

For the FFmpeg patch, configure a normal isolated source build with AAC parser
support, build, then run `make fate-parser-timestamp`. The generated regression
fails on the unchanged source and passes with the patch. The prior local
`fate-libavcodec` run passed 24 targets; full external-sample FATE/platform CI is
not claimed. The retained HA qualification used unmodified PyAV 19.0.0 rebuilt
against those source-built FFmpeg 9.0.2 libraries, with no preload/interposer and
unchanged HA dependency pins. No machine-local wheel is published here.

## Evidence and limits

Final slower retained-source runs exercise real HA HLS workers and go2rtc WebRTC
providers concurrently, both lenses, LL-HLS and non-LL, through a hostname-verified
non-loopback test-CA HLS edge. Per run:

- One physical acquisition, one demux/decrypt owner; 8,840 decrypt callbacks.
- Each HLS lens: all 1,783 HEVC samples and all 1,857 original AAC packets,
  including opening and terminal samples; deterministic component controls
  separately force the bounded audio-first opening.
- Each WebRTC lens: all 1,873 original ordered non-AUD HEVC NALs and all 5,943
  converter-emitted Opus packets, with exact packet identity/source-clock mapping.
- Converter input contains all 1,857 original AAC packets with exact PTS. Decoded
  received Opus has 5,705,280 samples at 48 kHz with nonzero audio; this is not
  lossless AAC PCM parity or physical sound output.
- A UDP RTP datagram is deliberately dropped **before SRTP**; normal NACK feedback
  recovers it. Offline sequence reconstruction verifies recovery, not immediate
  display of the recovered frame by a browser. Dropping after `ReadRTP` is not a
  valid retransmission test because SRTP anti-replay rejects an already-seen copy.
- Cross-track/cross-lens Sender Report mapping is within 21 microseconds, inside
  one 48 kHz tick and the unchanged one-16-kHz-tick source alignment budget.
- Terminal retries cannot acquire again; active Prepare refuses; explicit lazy
  Prepare/revision reload preserve identities and revoke old capabilities.
  Unload joins ownership, restores admission to zero and removes only owned state.

Library validation: **5,032 tests**, **90.37% coverage**; example: **161 tests** plus
**8 optional real-relay tests** enabled separately. Ruff, codespell, mypy, Pyright,
actual-HA mypy and dependency/package checks are reported independently in PR397.
Historical failing runs are retained privately, not erased by passing reruns.
One repeat concurrent with broad repository checks retained complete HLS/Opus
but lost 74 primary video RTP packets (sequences 95–168) despite RTCP feedback.
That failed stress audit is not called fixed: its overload/cache-recovery cause
is not fully localized. It bounds the packet-perfect qualification to the tested
workload and remains a transport-load/recovery gate. No queue/cache/socket budget
or parity tolerance was increased to conceal it.

Still outside this software qualification: actual HEVC browser/frontend and
physical A/V acceptance, real deployment proxy/auth/WebSocket behavior, attended
live/battery tests, long-run stability, arbitrary source profiles, maintained
upstream dependency releases and a supported core-HA integration. The test edge
is not production TLS topology certification. No production/camera changes,
merge or release are implied. Ready-for-review status is not deployment or
release approval.

## Review follow-up: host negotiation before either consumer

Native joint-profile source selection now checks the exact public HA contract
marker, count constructor and Stream prepare/confirm/cancel methods before
creating any upstream/relay URL. The same preflight guards cached HLS creation,
so direct WebRTC cannot bypass host negotiation or consume a one-shot attempt on
an unsupported host. Complete hosts still allow WebRTC without first creating
HLS. Twelve incomplete-host regression cases fail before the fix and pass after
it; all 182 example tests (including the eight real-relay cases) pass locally.
The earlier 169-test and media qualification records above remain their original
checkpoint; this guard changes admission, not media bytes/clocks or queue limits.

The ready-triggered CodeQL quality gate also identified state-changing test calls
inside assertions, protocol/cancellation expression statements, undocumented
expected-exception handlers, inherited completion-identity reassignments and an
explicit-close test. Operations now execute before pure assertions; protocol
stubs raise explicitly; cancellation waits retain their result; expected handler
behavior is documented; subscriptions receive their private physical/subscription
identity at base construction; and the owner test uses its context manager. The
security-and-quality query suite is unchanged, with no suppressions added. The
full library suite passes 5,032 tests at 90.39% coverage; HA remains 182 tests.

A later Codex review corrected emulation-prevention validation at the 256-byte
NAL prefix boundary: one following byte is checked in the original view, but is
not copied into or consumed by identifier parsing. Nine added controls cover all
valid lookahead values, invalid/missing tails and valid H.264/HEVC SEI admission.
The existing generated startup/replacement controls remain intact.

The supervised recorded-playback resource sampler now treats confirmed zombie,
dead or vanished descendants as explicitly missed non-atomic samples. It yields
and retries at most once on a transient descendant-access race; persistent active
process and root permission errors still fail. Seven new real-process/controlled
race cases cover these boundaries; media/resource caps and the wall guard are
unchanged. Full local follow-up validation passes 5,048 tests at 90.38% coverage.

## Review follow-up: terminal master-playlist waiter

A master-playlist request already waiting for its first segment now rechecks
completed media after `recv()` returns false on terminal completion. Atomic
publication followed by `finish()` must return the completed playlist, not 404.
Six deterministic LL/non-LL controls latch the waiter before publication:
completed media returns 200; empty completion and cleanup still return 404.
The two media cases fail on the previous proposal; all six pass with this guard.
Generic receiver end semantics and acquisition/buffering limits are unchanged.
The cumulative patch was re-extracted and apply-checked at the same public base;
this proposal-only follow-up does not claim a new retained playback run.

## Follow-up: bounded late RTX recovery

The [transport-recovery report](transport-recovery.md) distinguishes original
same-SSRC repairs from negotiated RTX. The cumulative relay proposal registers
RTX for each supported video profile and assigns an independent RTX sequence at
actual transmission, without modifying cached headers, original media identities
or source clocks. It adds no media queue or larger cache/replay/socket allowance.
Generated controls cover all four profiles, 74 lost originals, delayed feedback,
a lost repair, legacy early recovery, unchanged replay rejection and cache expiry.
The dedicated Consumer Runtime Review workflow now applies and hashes the public
source proposal before building/running these selected race checks. This is
review-proposal CI, not an upstream dependency release or installed HA change.
