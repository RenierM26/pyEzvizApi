# Independent HLS startup under the optional native Opus profile

> **Pinned historical evidence / proposal.** Retained for its recorded revisions and
> reproducibility, not current installation or deployment status. Start with the
> [documentation index](../README.md) and [current HA status](../home-assistant.md).


This is an isolated source proposal, not a dependency release or production
installation. The library remains headless; HA stays optional. Existing RTSP,
continuous-source behavior and strict `opus-source-clock-v1` remain unchanged.

## Failure and policy

An HEVC-file-capable browser need not negotiate H.265 over WebRTC. In the strict
joint profile, a refused WebRTC offer leaves the native Opus producer waiting for
its AV readiness gate. HLS then receives no initial media, although it needs only
the original HEVC/AAC. The original readiness regression fails twice before the
correction; cancellation remains a separate control.

The new **explicitly enabled** policy freezes the media plan at producer start:

- If an Opus receiver has already been selected, preserve the existing joint
  readiness, converter, original AAC HLS and source-clock behavior. Readiness,
  encoder or consumer failures do not trigger a downgrade or retry.
- Otherwise, start HLS-only without waiting for WebRTC or starting a converter.
  Original AAC and video packets still traverse their normal receivers unchanged.
- Once HLS-only has begun, refuse a later Opus request before adding its receiver.
  A scoped terminal error crosses the internal RTSP boundary and aborts partial
  AV admission; it must not select the provider's alternative FFmpeg producer.
  Roll back only the refused consumer, keeping active HLS readers alive.

There is no prefix replay, reacquisition, inferred clock, video transcode,
post-failure fallback, extra media queue or larger resource/time budget. A joint
receiver must be selected before source start. A browser arriving later can use
HLS; this does not promise arbitrary late finite WebRTC joins.

## Cancellation review follow-up

Recheck cancellation after acquiring the admission lock. A start that checked
cancellation before waiting could otherwise freeze an HLS-only plan after Stop
cancelled it. A deterministic offline control holds admission, observes the
initial context check, cancels the source, then releases admission. It fails on
the original PR head and passes after this correction under the race detector.

## Hosted Paho compatibility follow-up

Hosted checks install Paho 2.2, while the earlier local environment used 2.1.
Snapshot a received MQTT payload to immutable bytes only after the existing
64 KiB guard, so both documented payload types reach the envelope decoder with
the same bounded contract. Initialize the ping-deadline test clock before
constructing the Paho client instead of assigning a removed incoming-time field.
Offline controls cover both dependency versions, bytearray event delivery and
rejection of oversized mutable payloads before copying. Wire formats, negotiated
keepalive values and the payload limit are unchanged.

## Opt-in and negotiation

The example config data adds `relay_hls_fallback: true`, **default false**, only
alongside the already explicit finite grouped `relay_native_opus: true` profile.
All existing source-clock, ownership, track and host checks remain required.
This is validation config data, not a new supported live-camera UI workflow.

Before registration, the example requires both `native-opus-source-clock-v1` and
`native-opus-hls-fallback-v1` in the relay's non-acquiring capability manifest.
The source response then declares `opus-source-clock-hls-fallback-v1` rather
than reinterpreting the original strict profile. Old relays fail closed before
acquisition; unsupported settings and incomplete profiles are rejected.

## Validation and boundaries

See [the evidence summary](hls-fallback-evidence.json) for this head's checks.
The cumulative Go proposal still applies to the public base recorded in
[qualification.json](qualification.json); its exact paths and hashes are checked
after extraction. Python unit controls cover explicit opt-in, host/profile
requirements and rejection of relays missing the new feature before mutation.
Go controls cover immediate HLS admission, cancellation, original packet/clock
preservation, no hidden downgrade after an admitted joint failure, late-Opus
refusal, partial-consumer rollback, healthy siblings and the scoped RTSP error.

Private retained-source checks exercise real HA HLS-only and joint HLS/WebRTC,
each with LL-HLS enabled and disabled. They also exercise late joint refusal,
finite completion, explicit recovery, credential/revision reload, URL revocation,
stable entity identities and cleanup. No real camera acquisition or production
configuration is involved; captures, credentials and private URLs are excluded
from this bundle.

The owner's earlier Windows Edge HLS picture/audio pass was on an explicitly
HLS-only lab, not this new policy. This source change needs current upstream,
platform and requesting-browser qualification before deployment. H.265 WebRTC
remains unsupported in that tested Edge session; physical A/V synchronization
and live/battery/soak acceptance remain separate gates.

## Independent review correction

Failed RTSP admission now detaches partial tracks without closing the transport
before the scoped 409 response. The RTSP caller owns response/transport teardown.
The client treats the frozen profile as terminal even with backchannel enabled;
it closes the failed connection without a second DESCRIBE or producer fallback.
Real loopback server/client controls cover both backchannel modes, no alternative
producer selection and preservation of the healthy HLS sibling. A setup-state
transport control verifies detached tracks, response delivery, then closure.
