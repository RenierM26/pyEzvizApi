# Initial source-clock preservation: external review proposals

This is an isolated follow-up to the [shared session spike](native-shared-session.md).
It changes no pyezvizapi runtime and is not a shipping HA/FFmpeg workaround.
Production, live cameras and the existing draft PR397 are unchanged.

## Root cause and independent boundaries

On the pinned PyAV19 / FFmpeg9.0.2 receiver, the first RTSP video packet has an
unknown byte position (`-1`). `av_parser_parse2` initializes its internal byte
cursor from that value. The initial timestamp lookup then misses the supplied
first timestamp. A direct public-parser control reproduces this with generated
HEVC, H.264 and AAC, arbitrary signed timestamps, known/unknown byte positions,
and complete/fragmented input, without any camera or network.

A narrow FFmpeg review patch normalizes an **unknown internal byte cursor** to
zero. It does not change the packet's unknown file-position metadata, supplied
PTS/DTS, known nonnegative positions, media bytes or source epoch. A process-local,
version/ABI-restricted diagnostic models that initialization change and verifies
that the actual pinned receiver exposes the first video PTS/DTS again.

Separately, HA2026.10.4 unconditionally recalculates the first keyframe's PTS/DTS
from the next video packet minus nominal duration. Thus restoring the receiver
alone is insufficient: HA still changes the first timestamp in the observed
variable-first-interval source.

## Proposed HA contract, not a current option

An external HA review patch adds an opt-in `preserve_initial_timestamps=False`
worker policy. It is deliberately independent of EZVIZ and the FFmpeg proposal:

- Default mode keeps existing first-frame reconstruction and missing-DTS repair.
- Explicit preservation requires initial PTS and DTS and retains both independently,
  including zero/negative values. Missing clocks fail closed, not inferred.
- The policy is internal to HA, not an unknown FFmpeg flag or a source-URL trick.
- Reject simultaneous wall-clock replacement. Retain the policy when HLS inputs
  choose non-LL-HLS timing defaults.

It is not available in the installed HA release. Do not add this flag to the
current validation integration, monkeypatch shared workers from pyezvizapi, or
preload a diagnostic into production. Any future consumer must negotiate/use a
maintained supported host contract and retain compatibility when it is absent.

## Verification and limits

The isolated final run passes 79 controls: 54 generated-data parser cases,
18 new HA policy controls, four extracted existing upstream startup regressions,
two actual RTSP-to-HLS policy/compatibility cases, and one normal config-entry /
camera / actual relay / native shared-source replacement case. This is not the
complete upstream HA suite or a full patched FFmpeg build/FATE run.

The standalone generated reproducer is extracted from its review archive and
passes all 54 cases in both stock-behavior and candidate modes. The candidate
uses a child-process-only diagnostic interposer, not rebuilt/installed FFmpeg.

For the retained replacement IDR, the source's first interval is 6,002 ticks while
nominal duration is 6,000. The stock path changes the first video time by two
90 kHz ticks. The combined proposals preserve every initial/later raw-demux and HA HLS-mux-input
PTS/DTS, including the original first interval. The measured A/V phase is a
constant -11/240000 seconds (about -45.833 microseconds) from the first picture
onward, within the existing 62.5-microsecond AAC tick budget. The stock path's
first-picture -68.056-microsecond error remains a failing control.

One factory, one input demux and 8,840 decrypt feeds still supply the complete
1,783-video / 1,857-AAC primary and the complete replacement suffix of
1,663-video / 1,731-AAC packets. Native HTTP TS and encoded output files match
prior independent source/picture/PCM oracles exactly. Wire timestamps and RTP
sequence continuity remain exact. No source timestamp, duration, media byte,
backpressure limit, synchronization budget or acquisition policy is changed.

Actual delivered fMP4/HLS sample times and browser presentation were not observed
in this pass. These are content/mux-input clock results, not capture UTC, physical A/V sync,
audible output, browser HEVC acceptance or battery/live-camera readiness.

A [subsequent delivered-HLS audit](ha-finite-hls-review.md) verifies HTTP-served
sample clocks and encoded payloads, exposes a separate final-fragment loss, and
tests a private finite-completion-gated drain diagnostic. The original 79-check
result above remains a mux-input milestone, not evidence of complete HLS delivery.

## Structure and next gates

Keep the library source owner, subscription generations, HA policy and optional
relay as separate lifetimes/contracts. The library must not grow global FFmpeg
or HA monkeypatches to conceal a host startup issue.

Review and test the two external patches through maintained upstream builds and
CI/platform coverage before treating the stock-host startup gate as closed.
Then repeat actual stable-entity frontend HLS/WebRTC and supported HEVC-client
acceptance, plus the remaining startup/wrap/topology/attended-live gates. The
existing single-output draft PR397 and the unpublished shared-lens spike remain
separate review scopes.
