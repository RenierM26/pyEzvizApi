# EZVIZ WebRTC audio queue correction and remaining startup gates — 2026-11-02

> **Pinned historical evidence / proposal.** Retained for its recorded revisions and
> reproducibility, not current installation or deployment status. Start with the
> [documentation index](README.md) and [current HA status](home-assistant.md).


> Historical checkpoint: the [current finite joint-delivery review](consumer-runtime-review/README.md)
> supersedes its unresolved software-startup/audio/clock status and PR-head claims.

## Result

A real silent WebRTC audio-loss bug is corrected in a separate local relay experiment. Both final paced LL-HLS and non-LL runs receive **every Opus packet emitted by FFmpeg**, byte-identically and with unchanged RTP timestamp references. Both final HLS runs retain every source HEVC/AAC sample and their existing timing budget.

**This is not complete cold-start audiovisual qualification.** AAC preceding converter attachment is still omitted. An earlier non-LL run also lost its first two HLS AAC samples and correctly failed completion; its root cause remains unlocalized. The traced passing rerun does not erase that failure. Common-clock/RTCP alignment and supported-client/physical playback remain open.

Production, live cameras/accounts, browser policy, remote Windows clients and [draft PR397](https://github.com/RenierM26/pyEzvizApi/pull/397) are unchanged. No push, merge, release, global dependency installation or upstream submission was made.

## Four distinct effects

1. **Silent internal queue hole:** transparent RTSP capture shows the original relay received 5,866 emitted Opus packets but delivered 5,681. Encoded packet indices 128–312 were missing: 185 packets, about 3.7 seconds. First and final emitted packets arrived. Receiver RTP sequences appeared contiguous because WebRTC rewrote sequence numbers after the internal loss. Sequence continuity alone was misleading.
2. **Late converter attachment:** FFmpeg joined after HLS started. Final runs omit 20–24 initial AAC samples before conversion. This earlier interval is not reconstructed or backfilled.
3. **Probe discard:** the default FFmpeg `nobuffer` profile discarded one admitted AAC probe packet. An explicit owned-relay input profile retains it, using `-flags low_delay -probesize 32 -analyzeduration 1` without `nobuffer`. This is restricted to fully described native audio RTSP SDP, not a generic default for unknown feeds.
4. **Separate burst UDP loss:** accelerated instrumented replay produced visible receiver RTP sequence gaps despite zero relay queue drops. Positive controls pace each original retained callback at 6.5 ms, without changing encrypted bytes or media clocks. No socket/media queue was enlarged. This is a paced offline workload, not live-source pacing certification.

## Bounded correction

Only passive WebRTC consumers anchored by an explicitly declared one-shot native track opt in. The existing consumer-ready hook defers producer startup until peer connection and sender start. Original queue capacities remain unchanged, including the 128-packet audio queue.

Full input may wait up to 100 ms while releasing the queue mutex so Start/Close can proceed. Deadline expiry latches `native_delivery_failed`, cancels deferred startup and closes the affected peer asynchronously with a failure receipt. It cannot silently drop input and report clean success. Healthy siblings are not deliberately cancelled. Legacy and active/backchannel policy are unchanged.

No encoded payload, timestamp, resampler or padding rule changes. Converted Opus does **not** inherit an invented native source clock. Audio-only conversion without a declaring native track remains outside this mixed-camera qualification.

## Final observed controls

| Check | LL-HLS | Non-LL, input-order traced |
| --- | --- | --- |
| Real HA-provider test | Pass, 71.79 s | Pass, 71.47 s |
| Native factory / demux / decrypt feeds | 1 / 1 / 8,840 | 1 / 1 / 8,840 |
| HLS per lens | 1,783 HEVC / 1,857 AAC | 1,783 HEVC / 1,857 AAC |
| HTTPS parts per lens | 134 | 30 |
| Original non-AUD WebRTC HEVC NALs per lens | 1,873 / 1,873 | 1,873 / 1,873 |
| Emitted / received Opus, primary | 5,866 / 5,866 | 5,879 / 5,879 |
| Emitted / received Opus, secondary | 5,869 / 5,869 | 5,876 / 5,876 |
| Encoded Opus prefix / internal / tail loss | Zero | Zero |
| Earlier source AAC omitted before conversion | 24 / 23 samples | 20 / 21 samples |

Every received Opus payload matches an original emitted packet, with zero RTP timestamp-reference delta modulo 32 bits. FFmpeg trace counts equal captured AAC input counts, including the first probe packet. Standard Opus priming begins at −2.5 ms and ordinary packetization remains. This is not AAC PCM parity or end-to-end phase proof.

Both final HTTPS HLS sample/box/NAL/AAC audits pass. PTS/DTS references remain intact, with source A/V phase error −11/240000 seconds inside the unchanged 1/16000-second (62.5 µs) budget. No timeline normalization or added buffering hides loss.

Lifecycle controls pass: Prepare is refused with active readers; terminal offers/HLS restart cannot acquire again; explicit Prepare and actual credential/revision reload stay lazy, revoke old capabilities and preserve entity/device identity. Unload returns admission to zero. Source worker and cancellation join; receivers and relay exit zero; no matching owned relay, receiver or FFmpeg trace process remains. The ephemeral writable provider config is removed.

TLS remains a non-loopback, hostname-verifying test-CA HLS-only proxy. Both native capabilities are denied even with forwarded-IP spoofing. This is not production Caddy/auth/WebSocket qualification.

## Retained failure: startup remains open

Earlier `nonll-validated1` received every original WebRTC NAL and every emitted Opus packet, but primary HLS muxed AAC interval 2–1856: 1,855 rather than 1,857 samples, without internal or tail loss. HA rejected completion with `Finite receiving access-unit counts do not match source completion`, then removed the failed provider. The missing endpoint was a consequence, **not an established idle-timeout harness bug**.

The following run added transparent worker-input order/identity tracing and passed with all 1,857 AAC samples per lens. No runtime correction was made between runs. Therefore startup remains scheduling-sensitive/unlocalized; a passing rerun is not a fix. Next trace the admission/RTSP track setup, probe/demux output and HA first-keyframe boundary, then add a deterministic failing control. Do not raise acquisition counts, replay history, queue sizes or timestamp tolerance to conceal it.

## Tests and exact review identities

Six new WebRTC and three new core tests cover deferred start, cancellation/interleavings, legacy controls, explicit overflow failure, original-capacity waiting and close safety. Full WebRTC package race tests pass. Thirty-two targeted top-level race tests pass across WebRTC, RTSP, streams and H265; the three core tests pass separately against every actual core runtime Go file.

This is **not full Go CI**. Baseline `core_test.go` references missing `StripUserinfo`, so the full core suite cannot compile. Existing vet warnings (unkeyed RTCPFeedback and unreachable code) reproduce on the unchanged base. Earlier broader RTSP/streams baseline failures remain separate. No full library/HA suite or memory-heavy monolithic HA linter was rerun for this relay/docs milestone.

The source-only patch was extracted and applied to its exact base; all seven modified source hashes match. WebRTC race tests pass again in that extracted checkout (1.031 s), as do all three selected core tests (1.020 s). The helper explicitly labels its selected-test boundary.

- Relay base: `83ea2e26c45886490ebb64d200984934cd6f22a5`.
- Separate local relay fix: `8c5b186e1d881ef366fe902455a5954a6c704558`.
- Final binary SHA-256: `e660c5f9b5e5170906f6a01c9bc550a0909c076d2edc084eeffebe883698d1f9`.
- Build: `CGO_ENABLED=0 GOMAXPROCS=2 go build -p 2 -buildvcs=false -trimpath`.
- Library and HA example runtime remain byte-identical to `72c8a5645a38ea20b8426bfd734d42fc47455c25`; the prior 5,032-test result is historical, not rerun here.
- Stable draft PR397 remains `7a78541c7a44f41c73b9bbb82da3506a330e4715`.

## Next gates, in order

1. Reproduce and fix intermittent HLS initial-AAC loss. Separately define whether late WebRTC joins intentionally receive a suffix or require an explicitly new source generation; do not silently replay history.
2. Establish AAC-to-Opus common-clock/RTCP alignment and priming/packetization semantics without invented native-clock inheritance or duration padding.
3. Supported HEVC HA frontend/audio/fallback, real proxy/auth/WS, long-run topology, maintained dependency and human/current-dev/platform review.
4. Only then an attended battery-camera/physical audio/A/V trial. Old Windows probe cleanup remains unknown and was not retried.

Keep pyezvizapi headless. HA owns entities, capabilities, admission and source generations. Shared restreaming owns fan-out; HA stream/FFmpeg/client playback remain separate consumers. Private relay contracts must not become an unreviewed default library dependency.

Previous milestone: [simultaneous HLS/WebRTC and HEVC RTP fix](https://bookstack.home.moor.co.za/books/home-infrastructure/page/ezviz-simultaneous-ha-hlswebrtc-and-hevc-rtp-fix-2026-11-01).

Private evidence: `private-tools/ezviz-ha-relay/20261102-webrtc-audio/`. Review files exclude captures, native keys/capabilities, SDK, TLS/ICE private material and binaries.
