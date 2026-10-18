# Playback timing: verified app probes and PR policy

This is a source-backed design boundary, not a firmware lip-sync fix. Evidence
comes from the retained EZVIZ Android 7.4.1.0421 ARMv7 build and two bounded Nokia
T20 H9c runtime startups. The app's proprietary renderer is not part of this
Python library.

## Replanned scope

1. Preserve independent native track origins and received clock gaps by default.
2. Inspect supplied app capability metadata offline; never discover an AV offset
   from a sound or smoothing flag.
3. Expose a payload-free native RTP clock assessment. Nearby origins remain a
   candidate requiring an independently verified shared epoch, not detection.
4. Keep native shared-clock preservation experimental, explicit, bounded and
   source-scoped. Reject multiple accepted clock sources and invalid combinations.
5. Support the same opt-in through typed options, long-form API and CLI; stage
   high-level output so clock failures cannot replace existing clips.

No fixed 128/200/300 ms correction, resampling, invented silence, camera-setting
change, renderer-buffer replication, automatic capability-based clock selection,
or new network probe is introduced.

## Confirmed probes and conditions

| App path | Confirmed condition | Library behavior |
|---|---|---|
| DeviceParam.getSupportAutoSmoothPlay | Numeric support 915, parsed with toIntOrNull; missing/invalid becomes 0 | Offline advisory inspection; only integer 1 enables the flag |
| PlayDataInfoToDeviceConverter.convert.getSupport | Delegates to getSupportStr(id); ignores named key | Do not use FEATURE.support_auto_smooth_play or ezDeviceCapability as substitutes for supportExt |
| LivePlayCore.createEzMediaPlayer | Calls enableSmoothPlay only for support 915 == 1 | Never infer a shared clock or adjust file timestamps from this flag |
| EZMediaBase.enableSmoothPlay / startPlayer | Sets flag at 0xdc; guarded startup calls SetAutoSmoothPlay(port,1,0) | Smoothing belongs to the live renderer, not this file remuxer |
| PlayDataInfo.isOnSound | Uses support 63 == 1 and the SOUND switch | Report audio-toggle support only, not current sound state or clock evidence |
| Native demux audio descriptors | Codec/sample-rate/channel information controls AAC interpretation and cadence | Existing descriptor-backed AAC parsing; clock probe uses the actual parsed sample rate |
| EZMediaBase.startPlayer | Display buffer is applied only when configured; global base time only when supplied | No buffer capacity or calendar timestamp becomes an inferred physical AV correction |
| Multi-track player startup | Native stream-header interpretation and requested display/stream count choose the route | Do not choose routes from a camera marketing/model name or smoothing capability |
| SyncToAudio startup on observed H9c | Explicit 0; timestamp-gated AudioPlay branch requires 1 | No claim of enabled audio-master synchronization |

The inspected H9c snapshot has support 63=1 and lacks 915. No explicit smoothing
call was observed in traced startup, consistent with this app condition. This
is not proof about other models, firmware, builds or player routes.

## Source clocks versus presentation clocks

The observed app route uses MPEG-PS with a common source clock. Inside the player,
audio and video subsequently rebase independently. Two startups had source audio
minus video origins of +149 ms and +75 ms, while both presentation-stage relative
origins began at zero. This is a variable startup boundary, not a fixed offset.
Raw buffer forwarding alone therefore does not prove unchanged cross-track
origins through the proprietary player.

The Android speaker queue also varies. AudioTrack capacity, accepted-write minus
playback-head count, hardware-reported frame position and actual acoustic output
are different measurements. Likewise a six-slot display buffer is capacity, not
a measured delay. Neither renderer capacity nor a roughly 0.2 s instrumented
speaker-queue estimate is copied into MPEG-TS PTS.

## Offline API

```python
from dataclasses import asdict
from pyezvizapi import inspect_app_playback_support, probe_native_rtp_clock

support = inspect_app_playback_support(device_snapshot)
print(asdict(support))

# parsed_aac_stream comes from descriptor-backed AAC parsing, not raw PCM.
clock = probe_native_rtp_clock(first_video_timestamp, parsed_aac_stream)
print(asdict(clock))
```

Unavailable/malformed support metadata returns unknown flags. An available map
missing 915 follows the app's disabled default. Boolean/CSV/float/whitespace values
are not treated as integer 1. Accepted integer metadata and numeric strings are
handled without fetching credentials or account/device data. The helper reports
support, not a setting to enable on the camera.

Clock assessment reports missing timing, unsupported sample rates, incompatible
origins and multiple accepted AAC source clocks. A candidate reports offsets in
90 kHz ticks and **shared_epoch_verified=False**. Supplying matching-looking
origins or smoothing capability 915 does not authenticate a shared epoch.

## Explicit experimental capture

```python
client.save_clip(
    serial,
    output,
    source="local-sdk",
    duration_seconds=20,
    native_shared_clock=True,
)
```

Equivalent typed option: `MediaMuxOptions(native_shared_clock=True)`. Equivalent
CLI: `save clip --native-shared-clock`. Only explicit local SDK/native TCP and
HCNetSDK command-port MPEG-TS sources qualify. Cloud/automatic fallback/ECDH,
plain UDP, MPEG-PS input, missing genuine video/audio timing, and encrypted
startup trimming are not silently treated as shared native RTP.

The current hypothesis is restricted to 90 kHz video and 16 kHz AAC with unsigned
32-bit timestamps. Wrap-aware integer arithmetic and a one-second plausibility
bound reject observed incompatible origins, but the bound is not proof. Multiple
accepted audio/video clock sources cannot be combined merely because their first
origins are close. Discarded metadata/invalid packets do not count as AAC sources.

Existing cloud MPEG-PS/TS and native defaults remain unchanged. The app's PS
renderer path must not be confused with the opt-in native RTP hypothesis. Media
integrity, received cadence and physical lip-sync are separate claims; the latter
still requires a same-event waveform/visual comparison with proper gap mapping.

## Provenance

Inspected symbols/classes: DeviceParam, PlayDataInfoToDeviceConverter,
PlayDataInfo, LivePlayCore, EZMediaBase, IDMXPSDemux, CIDMXManager, CAudioPlay and
CMPManager. Native enableSmoothPlay at 0x2afc9c writes 1 to offset 0xdc; the
corresponding startup call at 0x2ad82e passes (1,0). Source inspection used Thumb
decoding and ELF/vtable relocation information, not cached ARM disassembly of
Thumb functions. Runtime timing used bounded metadata hooks; a Java-hook ANR run
was excluded and native-only confirmation was used.

Retained native binary SHA256:

- ezstreamclient: 184f8eb8ce29a2f4ce5c6a915dd9f5649907f55e410a92c6a3db8b414f665f6b
- PlayCtrl: a719ac549516df28345536d7baf1cc22145996949e89f8c7fae2dc73a379cddc

## Development-only policy simulator

The repository also provides an explicit, bounded
[app-profile playback simulator](app-playback-simulator.md). It replays metadata
and queue/output events offline; it is not installed as a library API and is not
used by any capture/remux path. Its optional loss policy must never be applied
silently to recording exports, and its output is not a physical lip-sync claim.
