# Automatic receiver and authenticated client qualification

This is the main-based follow-up to merged PR399 (`9a4fbe8`). Work stays in
isolated source proposals and retained/generated media; no production deployment,
account/camera change or new live acquisition is authorized by this work.

## Acceptance work in this PR

1. Replace explicit fault-injection NACK generation with the receiver's default
   automatic feedback. Reproduce and correct loss-tracker visibility of restored
   RTX and repair-only reads; retain cache/replay/buffer bounds and no-RTX controls.
2. Exercise actual HA authentication and WebSocket signaling through an isolated
   verified TLS edge. Test browser negotiation, decoded media and A/V timing on
   supported paths, and explicit unsupported-HEVC behavior without transcoding.
3. Package isolated upstream source changes, generated regressions and exact
   provenance with maintainer-facing commands. Maintainer acceptance/releases and
   physical audibility/A/V remain separate from software qualification.

## Initial observations

- The pinned Pion SRTP dependency already exposes `SetRTX`, `NextStream` and
  `SourceReader`: primary and repair SSRCs retain independent crypto/replay state
  and existing buffers while one pull owner can consume either stream. No extra
  forwarding queue is required to integrate repairs before normal interceptors.
- The current WebRTC reader instead polls a separate 50-packet repair queue before
  a blocking primary read; restored packets bypass the original RTP interceptor
  chain. Both automatic feedback state and repair-only wakeup need regression
  coverage, including ownership, deadlines, shutdown and simulcast association.
- The available managed Chromium 153 reports H.264 and Opus, but no H.265 WebRTC
  codec or HEVC MP4 support. This is an observed client limitation, not permission
  to add an implicit video transcode or claim retained HEVC browser playback.

Implementation, exact-head checks and final evidence will replace the work-in-
progress status before this PR is marked ready. Earlier failures stay recorded.
