# Delivered HLS clocks and finite-tail boundary

> **Pinned historical evidence / proposal.** Retained for its recorded revisions and
> reproducibility, not current installation or deployment status. Start with the
> [documentation index](README.md) and [current HA status](home-assistant.md).


This retained-recording investigation changes no library or integration runtime.
It follows the [external startup-clock proposals](ha-initial-source-clock-review.md).
The stock-host gate remains open: the receiver still needs maintained FFmpeg/HA
support for those proposals, not a production preload or monkeypatch.

Both runs below use the previous private receiver/startup proposals. "Default
close" means HA's unmodified close behavior within that candidate environment,
not an end-to-end pass on stock HA/FFmpeg.

## Observe delivery, not only mux ingestion

An actual isolated HA2026.10.4 config-entry/camera/relay path serves its HLS init
and part responses over loopback HTTP. Every observed published part is fetched
and compared byte-for-byte. A separate MP4 box reader resolves track timescales,
`tfhd`, `tfdt`, `trun`, sample extents and `mdat` payloads; PyAV independently
agrees on all sample PTS/DTS, durations and payload hashes.

All delivered PTS/DTS equal mux ingestion, including the first replacement frame.
The original first 6,002-tick interval survives. All delivered video NALs match
the native TS prefix after accounting for AUD delimiters and parameter sets
moved unchanged into `hvcC`; AAC payloads match after ADTS header removal.
The source-derived A/V phase remains -11/240000 seconds, within the unchanged
1/16000-second budget, on all three observed subscriptions.

Sample duration fields are not claimed identical to the input's nominal duration:
the MP4 muxer derives many durations from adjacent DTS. This does not change
the observed sample PTS/DTS. Browser scheduling and physical A/V remain separate.

## A newly observed EOF gap

| Subscription | HA mux input video/AAC | Default HTTP HLS video/AAC | Missing tail |
| --- | --- | --- | --- |
| Complete primary | 1783 / 1857 | 1778 / 1851 | 5 / 6 |
| Explicitly stopped secondary | 51 / 52 | 42 / 42 | Partial by cancellation |
| Complete replacement | 1663 / 1731 | 1658 / 1725 | 5 / 6 |

HA's muxer closes its output container and memory file without publishing the
last buffered fragment bytes. Thus native/source completion and mux-input
completeness are not HLS-delivery completion. The default-close negative control
remains a failed complete-delivery gate, even though its delivered prefix is exact.

## Private finite-tail diagnostic

A test-only close diagnostic admits publication only with a receiving
`StreamEndedError`, the matching native subscription's completed/joined/empty
receipt, and its physical source's verified finite/completed/closed/joined receipt
without media or cleanup errors. Explicit stop, partial, failed, unjoined and
uncertain receipts are refused. Sixteen admission controls pass.

The diagnostic publishes the actual remaining fMP4 bytes. Its duration metadata
comes from the observed final source-sample ends; it adds no AVPacket, padding,
transcoding, source retry or timestamp adjustment. It is intentionally limited
to the retained no-B-frame fixture with known positive terminal durations.

Both complete outputs then deliver every sample: primary 1783 / 1857 and
replacement 1663 / 1731, with exact source-derived clocks and encoded payloads.
The stopped subscription still delivers only 42 / 42 and remains partial.
The final diagnostic repeat admits two complete outputs, refuses the cancelled
output, and preserves one factory, one demux and 8840 decrypt feeds. Physical
cleanup joins, admission returns to zero, and the owned relay exits cleanly.

This is not a maintained host patch or a production completion bridge. It runs
only inside the isolated acceptance observer; installed HA and the validation
integration are unchanged. A source's EOF by itself is insufficient permission
to finalize a live, failed or truncated stream.

## Optimal next host contract

Keep completion at its owning boundary:

1. The library publishes authoritative physical-source and generation-specific
   subscription receipts; it does not import HA or manipulate HLS.
2. The integration correlates those receipts with the active ingest generation
   and receiving EOF. It must distinguish clean finite completion, cancellation,
   transport/parser failure and stale completion, without authorizing acquisition.
3. A maintained HA stream API owns terminal fragment publication, idempotent
   finalization, provider retention/draining, and terminal playlist signaling.
4. HLS consumers fetch the remaining advertised parts/segments and observe an
   `EXT-X-ENDLIST` only after successful complete publication. Terminal requests
   must not restart ingestion. WebRTC teardown remains a separate lifecycle.

The diagnostic's final HTTP playlists still have preload hints and no
`EXT-X-ENDLIST`. Full finite-HLS protocol completion is therefore not passed.
Review cancellation/EOF races, failures during final publication, stale
generations, terminal playlist requests and supported LL/non-LL behavior before
turning this diagnostic into an upstream implementation.

A [subsequent host API review candidate](ha-finite-completion-proposal.md) now
exercises generation-bound authorization, expected source access-unit counts,
terminal publication/ENDLIST, retention and no-restart behavior through both HLS
modes. Its source-count feed is still private audit instrumentation; a maintained
library completion receipt and normal adapter wiring remain release prerequisites.

No public PR/head update, release, production change or live-camera test was made.
The existing single-output draft PR397 remains separate from this unpublished
shared-lens spike and the external FFmpeg/HA review proposals.
