# FFmpeg source-build validation boundary

The parser-startup fix has now been tested with actual source-built FFmpeg 9.0.2
and PyAV 19.0.0, not the diagnostic preload. This is local dependency review
material, not maintained release support or a new requirement silently added to
pyezvizapi. Library runtime remains commit `72c8a5645a38`; PR #397 is unchanged.

## Observed checks

- Official release archive, release signature using the FFmpeg website key, and
  affected parser file matched against tag `n9.0.2` commit
  `946fcce07b6dcd0331c8cc609192aeff5e1924f8`.
- Unmodified source reproduces the unknown-initial-position timestamp loss.
- Both stock-control and fixed-source generated matrices: 54 cases pass each;
  the control deliberately expects the first timestamp to be lost at position -1.
- Fixed source: 24 selected libavcodec FATE targets pass, including a new AAC
  parser timestamp/position/fragmentation regression with 18 combinations.
- Source-built PyAV19 uses all seven libraries from the patched prefix. Native
  versions and all 163 named HA dependency pins match the baseline.
- Normal installed public adapter: actual LL-HLS and non-LL HLS delivery both
  pass without preload (37.27s, four pre-existing aiohttp warnings).
- Independent HTTP fMP4 box/sample, PyAV, encoded payload, source-clock and RTP
  audits pass. Full primary1783HEVC/1857AAC and replacement1663HEVC/1731AAC;
  stopped sibling stays partial. A/V phase remains -11/240000 seconds, within
  the unchanged 1/16000-second budget. One acquisition/demux per case, joined
  cleanup, terminal no-restart and no remaining owned relay processes.
- 99 additional host controls pass. Two older private-bridge cases in that
  invocation are not normal public-adapter acceptance evidence.

## Consumer ownership and remaining gates

Keep the proprietary native acquisition/decrypt/demux owner and immutable public
completion receipts in the headless library. Keep config-entry admission,
subscription generations and explicit recovery in the HA integration. Keep
standard fan-out plus negotiated clock/no-retry/atomic registry contracts in the
relay. The receiving HA stream must own validated finite-tail publication and
terminal playlists; the frontend must own codec selection and visible terminal
behavior. Do not recreate source counts in the receiver or repair clocks in the
adapter.

This software-only Linux x86-64 build disables x86 assembly because nasm is
absent. Its local PyAV wheel has an absolute RPATH and is not portable. Selected
FATE is not full external-sample FATE, full HA CI, platform/hardware/performance
coverage, an official-wheel comparison, frontend HEVC playback or physical
synchronization proof.

Still required: maintained FFmpeg/PyAV packaging, maintained HA startup and
versioned finite-completion API support, maintained relay contracts, real
HEVC-capable HA frontend acceptance, and a separately bounded attended hardware
trial. Stock HA/go2rtc is not certified by these proposed-contract tests. Do not
install the local libraries globally or expand the existing draft PR implicitly.

[Full findings and generated-only source review package](https://bookstack.home.moor.co.za/books/home-infrastructure/page/ezviz-real-ffmpeg-source-build-validation-2026-11-01).

## Upstream HA component-suite follow-up

[HA stream compatibility and review boundary](ha-upstream-stream-compatibility.md)
now records exact-release baseline/candidate80case parity, the133case combined
component suite and a separately applicable98case clock-policy proposal. Full
HA development/pre-commit/platform CI and maintained release support remain open.
