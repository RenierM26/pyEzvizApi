> **Later audio correction:** [WebRTC queue and startup qualification](ha-webrtc-audio-qualification.md) fixes a silent internal Opus hole, retains late-attachment limits and records a separate intermittent HLS initial-AAC failure. The historical results below are unchanged.

# Isolated HA consumer topology qualification

## Tested boundary

The normal example entry/cameras use the real HA2026.10.4 go2rtc WebRTC
provider, two concurrent HLS workers and two independent Pion WebRTC receivers.
Each of the final LL-HLS and non-LL cases passes with one native factory, one
input demux and 8,840 decrypt feeds. Both lenses deliver all 1,783 HEVC pictures
and 1,857 encoded AAC samples through HLS. Independent actual HTTPS fMP4
box/sample/NAL/AAC/clock audits pass, retaining the -11/240000-second A/V phase
inside the unchanged 1/16000-second budget.

WebRTC receives all 1,873 original non-AUD HEVC NALs per lens in order, including
parameter sets, with contiguous RTP sequences and unchanged video timestamp
references modulo 32 bits. HA's standard provider explicitly uses FFmpeg to
convert AAC to Opus: received Opus packets decode to nonzero 48-kHz audio.
This is not AAC PCM parity, complete audio-tail equivalence, WebRTC A/V phase,
a browser decoder result, hardware playback or physical synchronization.

The audio limit is observable, not merely untested: final WebRTC receivers
decode 5,632–5,655 Opus packets (112.64–113.10 seconds at 48 kHz), shorter than
the full source's nominal 118.848 seconds of AAC. Received RTP sequences are
contiguous, but that does not establish complete audio delivery before/after
codec attachment. First/last source-to-Opus coverage and A/V alignment through
the standard transcoder remain explicit gates; do not label this complete
WebRTC audiovisual playback.

Final cases pass in 51.10 seconds total. Each refuses whole-group Prepare while
readers are active; after EOF, repeated WebRTC offers fail without acquisition
and HLS cannot restart its completed worker. Explicit whole-group Prepare
closes provider sessions, stops/culls HLS caches and revokes both old native
URLs. Actual credential material plus its revision reload without a new preview,
while camera unique IDs/entity IDs/device association remain stable. Unload
returns common admission to zero. Every source joins; the relay and receivers
exit zero; no matching owned FFmpeg, relay or receiver process remains.

## HEVC AP relay correction

The extra RTSP → HA-provider → WebRTC hop exposed a relay depayloading bug.
Four primary-lens RFC7798 aggregation packets were treated as encoded NALs and
fragmented into nested AP-in-FU payloads; packet-count success missed it.

The separate local relay revision `83ea2e26c45886490ebb64d200984934cd6f22a5`
adds AP member validation and original-NAL depayloading before MTU repacketizing.
Malformed aggregation discards that pending AU through its marker. Nonzero
negotiated DONL remains unsupported; it is not guessed. Four new regression
groups fail before the fix and pass afterward, including twelve malformed AP
variants. The entire H265 package and 24 targeted top-level race checks pass.
Broader pkg/rtsp and internal/streams runs reproduce existing baseline failures
(TestMissedControl panic and TestRecursion/TestTempate); full Go CI is not green.

The earlier relay `feea11a` and historical artifacts are unchanged. The final
binary is built separately with buildvcs disabled and explicit commit/source/
binary hashes: Go's worktree discovery embedded the ancestor workspace revision
in the preliminary build. No relay binary is installed globally or deployed.

## Configuration and TLS model

HA's provider uses the standard writable stream-registration API and adds its
own camera-name/Opus child streams. File-backed launch changes that provider
configuration. Raw-config-only launch rejects that API; it is not a supported
substitute for HA's writable configuration.

Use an owned ephemeral writable provider config initialized from an unchanged
base. Verify native HTTP capabilities and camera keys are absent, terminate the
owned relay and remove its temporary config. HA-owned child registration names
may remain in runtime inventory after Prepare, but have no readers and refer to
revoked upstream names; the native adapter removes only its own atomic names.
Do not delete unrelated or provider-owned registrations by guessed prefix.

The test uses a non-loopback, test-CA-verified TLS edge forwarding HLS to HA's
loopback HTTP listener. Unknown-CA clients are rejected, hostname checks stay on,
and both native route prefixes are denied even with a valid capability and
spoofed forwarded IP, before acquisition. Direct HA TLS remains unsupported by
the example. This model is not production Caddy/auth/WebSocket/reverse-proxy
acceptance and does not alter DNS, certificates or a production listener.

## Review and remaining gates

Keep the headless library, HA entity/admission owner, shared restream adapter,
HA stream workers and client decoder responsibilities separate. This checkpoint
changes only relay AP handling plus pyezvizapi documentation; the library and HA
example runtime remain identical to `72c8a5645a38` and retain the earlier
5,032-test result. No new library wheel or production readiness is claimed.

Remain open: maintained dependency/relay contracts and human/current-dev/platform
review; supported HEVC HA frontend/audio/fallback; real deployment proxy/auth/WS
and lifecycle/error/long-run topologies; other GOP/layout/epoch cases; attended
battery-camera, physical audio and A/V checks. Draft PR397 stays at7a78541,
production/live accounts/browser policy stay unchanged, and the old Windows
probe cleanup remains unknown and was not rerun.
