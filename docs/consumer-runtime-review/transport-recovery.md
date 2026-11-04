# Bounded late WebRTC repair — follow-up to PR397

## Scope

PR397 was merged at `e231e42800effaca989671c027b5dac9ec236ce3`.
This follow-up changes the cumulative **source-only relay proposal**, not the
Python library API, a managed HA installation or a deployed relay. It adds
negotiated video RTX and regression/CI evidence for a previously unqualified
late-repair boundary. Original video/AAC bytes, source timestamps, source owners,
queue/socket/cache limits and anti-replay protection remain unchanged.

## What the retained failure established

The earlier concurrent-host-load run missed primary-video RTP sequences 95–168,
74 datagrams. Its peer negotiated NACK but not RTX. The source and HLS/Opus
branches remained complete. Pion's default primary SRTP replay window is 64
packets; its default responder cache is 1,024 packets. A repair can therefore
remain cached but be inadmissible on the old primary stream after later traffic
has advanced the replay window. Counting incoming RTCP packets does not prove
that a repair reached a media consumer.

This is a demonstrated recovery limitation, not proof of the precise OS/CPU
cause of the original datagram loss. That historical failed audit remains valid.

## Source correction

- Register an associated `video/rtx` codec for all existing video profiles:
  H.264 baseline, constrained baseline and high, plus H.265. A peer must offer
  the association; an offer without RTX keeps its previous negotiation path.
- Use Pion's existing NACK cache, RTX payload wrapping, OSN restoration and SRTP.
  RTX has an independent SSRC and transport sequence space, rather than weakening
  replay checks on the original stream.
- Assign each RTX transport sequence at actual transmission. The pinned Pion
  responder retains an RTX header in its cache; reusing that sequence on a later
  repair can itself be rejected after the RTX replay window advances. A small
  writer interceptor clones the cached header and serializes sequence assignment
  plus write. It does not change the original media sequence, payload, marker,
  source timestamp or cached object, and creates no asynchronous media queue.
- Preserve writer errors and primary/no-RTX pass-through behavior. No cache,
  repair queue, socket, source queue or replay window is enlarged.

## Generated controls and reproducibility

Apply `go2rtc-native-consumer.patch` to the documented public relay base and
verify `qualification.json` hashes. Then run:

```sh
go test -p 2 -race -vet=off ./pkg/webrtc \
  -run 'TestNativeRecoveryLateFeedback|TestRTXSequence' -count=1
```

Sixteen real loopback SRTP/RTCP cases cover the four video profiles:

| Control, per profile | Expected result |
| --- | --- |
| Lose 74 originals; delay first NACK until primary sequence 256; also lose the first RTX repair before SRTP | Recover every original identity/payload through negotiated RTX |
| No RTX; request 16 losses at primary sequence 32 | Existing early same-SSRC recovery still works |
| No RTX; request the 74 losses at sequence 256 | Old packets remain rejected by unchanged SRTP replay protection |
| RTX offered; first request after sequence 1,200 | Evicted originals remain unavailable; the cache stays bounded |

The four late-positive cases fail against the original negotiation and fail
again with RTX negotiated but cached transport sequences reused. All sixteen
pass with both corrections. Three additional tests cover immutable cached
headers and unchanged media through an entire 16-bit sequence wrap, concurrent
resends, primary/no-RTX pass-through and writer-error preservation.

The selected source-review race suite passes **95 leaf tests across five
packages**. The new Consumer Runtime Review workflow applies the proposal to its
pinned public base, verifies all 50 extracted source hashes, builds it and runs
that selected suite. This is not full upstream Go/platform CI: the documented
unchanged baseline `StripUserinfo` test compile failure and vet/broader-suite
limitations are not hidden by calling the selected checks a full test run.

## Receiver contract and limits

The generated peer delays feedback deliberately and derives subsequent NACKs
from restored original identities. Ordinary media continues while its bounded
repair queue is consumed. It does not add artificial media to a retained replay.

A separate exploratory stock-Pion peer exposed an additional receiver behavior:
its automatic generator can continue requesting already-repaired originals,
while its 50-packet repair queue can discard part of a burst. A successful manual
feedback control is not evidence that this stock automatic generator, a browser
or a frontend handles every burst. That exploratory failure is retained, not
relabeled as a passing client qualification. The maintained receiver API is used
for decoding/restoration and RTCP; the manual feedback schedule is an explicit
fault-injection test contract, not a replacement client implementation.

Retained-topology results are recorded separately after independent payload,
clock, HLS and lifecycle audits. Generated test success alone is not a retained
media or physical playback result.

## Gates still separate from this PR

- Arbitrary host overload, burst patterns, feedback delay, cache expiry, terminal
  loss and client repair-queue behavior beyond the qualified controls.
- Stock automatic-Pion feedback and real HEVC browser/frontend acceptance.
- Physical audibility/A/V synchronization, attended finite live and battery/soak
  checks, with a fresh bounded acquisition only when explicitly authorized.
- Actual production proxy/auth/WebSocket topology; a test-CA HLS edge is not it.
- Maintainers' review, full platform/FATE checks and maintained upstream
  HA/go2rtc/FFmpeg/PyAV releases. Source proposals are not installed dependencies.

No release, deployment, camera/account change or repeat remote Windows probe is
part of this follow-up.
