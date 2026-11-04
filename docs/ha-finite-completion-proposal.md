# Finite HLS completion: separate host review candidate

This follows the [delivered-HLS boundary audit](ha-finite-hls-review.md). It is
an isolated external HA proposal, not installed HA support or a pyezvizapi runtime
change. The existing draft PR397 and validated library wheel remain unchanged.

## Proposed public host API

```python
from homeassistant.components.stream import FiniteSourceCounts

handle = stream.async_prepare_finite_source()  # Before ingestion, once per Stream.
# After authoritative, joined, generation-matching source/subscription completion:
accepted = stream.async_confirm_finite_source(
    handle,
    FiniteSourceCounts(video=owner_video_units, audio=owner_audio_units),
)
```

The handle is an immutable identity without controller mutators. A foreign/stale
handle, contradictory repeated counts or confirmation after cancellation/failure
is refused. Repeated identical confirmation is idempotent. Only a new `Stream`
can prepare another generation; source updates cannot rearm an existing one.

Confirmation is a trusted integration assertion, not proof derived by HA from
transport EOF. The receiver separately requires EOF, complete initial/sample
clocks and an exact per-track access-unit count match. Without that count check,
even a successfully completed owner could precede a cleanly truncated relay EOF.
The adapter must establish one-to-one access-unit correspondence through the
container/relay; incompatible packetization must fail, not guess or widen counts.

## Terminal transaction and lifetime

1. The declared finite stream has one worker attempt. Legacy undeclared streams
   keep their existing retry policy.
2. At receiving EOF, await independent owner confirmation for at most five
   seconds. Confirmation may precede or follow that EOF.
3. Verify source counts and terminal metadata. This initial proposal is limited
   to HLS, no B frames and known positive terminal durations. Refuse missing,
   reordered/non-monotonic timestamps and silent validator discards.
4. Close the mux into its existing memory buffer. Derive final duration metadata
   from observed source-sample ends, without making an AVPacket or modifying any
   media timestamp, payload, queue limit or acquisition policy.
5. On the event loop, recheck the generation and publication state, append actual
   buffered fragment bytes, then mark the provider complete. There is no await
   between the publication check and terminal marker.
6. Keep the existing bounded HLS provider/token until idle expiry or explicit
   stop. Final playlists contain `EXT-X-ENDLIST` and no preload hint. Blocking
   reloads wake; out-of-range terminal parts do not wait for nonexistent media.
   Master/init/playlist/segment/part requests cannot start another worker.

Cancellation revokes pending publication before awaited teardown. Source errors,
unconfirmed EOF, clean truncation/count mismatch, publication errors and stale
generations do not produce successful terminal playlists. Finite expiry also
cleans up if preload was enabled; preload cannot authorize another ingest.

## Validation and evidence boundary

- Final candidate: `435082eb86ed3f9d83ecad4186eecf1255bad262`, based on the
  separate startup-preservation proposal `9352788559271633b2a06dc293ff39a4869366d3`.
- 84 local checks pass in 36.29 seconds: lifecycle/receipt/error controls, previous
  startup regressions and two actual native entry/camera/relay paths for LL-HLS
  and non-LL HLS. Four existing HTTPException-return deprecation warnings remain.
- Both modes deliver primary 1783 video / 1857 AAC and replacement 1663 / 1731.
  Independent MP4-box and PyAV audits agree on every HTTP sample's clock and
  payload; normalized video/config/AAC match the native source. A/V phase remains
  -11/240000 seconds within the unchanged 1/16000-second budget.
- Each native case uses one factory, one input demux and 8840 decrypt feeds.
  The stopped secondary remains partial/unconfirmed. Physical owners join,
  admission returns to zero and the owned relay exits cleanly; unrelated relay
  state/configuration survives.
- The sanitized archive's patches apply to a fresh exact HA baseline. All ten
  resulting stream Python files match the candidate. Its 32 generic regression
  cases pass again from the applied/extracted source (overlapping the 84 checks,
  not 32 additional behaviors). Configured lint adds no diagnostics; two baseline
  datetime-alias diagnostics remain. This is not full HA upstream CI or FATE.

The receiver tests still use the previous child-only diagnostic FFmpeg parser
proposal. Installed HA's nine stream Python files and all 62 validated library
wheel payloads are unchanged. No preload is installed globally. Browser
presentation, HEVC-client acceptance and physical A/V are not established here.

## Remaining library/adapter contract

The native acceptance supplies counts using private audit instrumentation at the
existing owner's successful per-output mux boundary. It does not start another
demux, infer counts from HA, or load fixture counts into the integration. However,
current public pyezvizapi receipts do **not** expose these counters. Do not ship
that instrumentation as an integration workaround.

The next library proposal should publish immutable, bounded per-subscription
completion metadata: accepted selected video/audio access-unit counts, logical
track identities and subscription/source generation, only after authoritative
source completion and joined cleanup. A partial/failed/retired subscription must
not become complete because a sibling succeeds. Increment counters after accepted
muxing; retain failed-cleanup handles and existing admission/backpressure limits.

The HA adapter then checks the current physical owner, exact output handle,
subscription generation and capability generation plus completed/empty/joined
receipts, and confirms the host handle with those published counts. The library
must remain independent of HA, HLS, relay processes and receipt polling policy.

A subsequent [library receipt and normal adapter implementation](native-completion-receipts.md)
now provides immutable owner-derived counts on the isolated shared-lens branch.
It replaces the private source-count feed in normal camera/provider acceptance;
the earlier 84-check result above remains the historical host-proposal milestone.

This closes the tested host terminal-protocol gap as a review candidate, not a
stock-host release gate. Maintained library receipts/adapter wiring, upstream
FFmpeg build/FATE and HA/platform acceptance remain before normal frontend/HEVC,
broader startup/wrap/topology and scoped attended-live/physical-A/V/soak trials.
