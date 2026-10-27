# Camera capabilities and Home Assistant delivery

Home Assistant consumption is the product. The development player is a
diagnostic harness, not a dependency of the integration or evidence that HA
can play a camera. Implement the library boundary first, then a temporary
custom integration for validation, and upstream the validated behavior.

## Delivery milestones

1. **Implemented: evidence inventory.** Read-only fleet configuration/ability
   queries, optional inspection and full decode of saved clear samples, and an
   explicit bounded acquisition helper around the existing typed clip API.
   Query every *supplied* camera/configuration channel, not a port/channel scan.
2. **Implemented: finite encoded output boundary.** Select an observed video
   stream and optional AAC stream, copying to a staged MPEG-TS response without
   the player, re-encoding, lens composition, silence or timestamp repair.
   This establishes a testable headless boundary, **not continuous streaming**.
3. **Library boundary implemented: continuous native PS source adapter.** See
   [native HA stream boundary](native-ha-stream.md) for the optional PyAV owner,
   current-session PES-ID selection, bounded output credits and async cancellation.
   Incremental decrypt,
   demux and selected-track remux from a context-managed SDK source. Bound
   queues, startup and shutdown, cancel blocked reads when HA disconnects, and
   retain each lens as a separate source. An HA-hosted endpoint should own the
   route/authentication and source lifetime; do not start an unauthenticated
   external listener or put camera credentials in published URLs. Existing
   experimental cloud HTTP proxy is not a validated native H9c adapter.
4. **Next: HA-hosted route and integration acceptance.** Temporary custom integration using HA's stream
   pipeline, followed by upstream changes and a released dependency. The
   current upstream EZVIZ camera still returns RTSP URLs. Native SDK packets or
   successful FFmpeg decode alone do not satisfy that URL contract.

## Evidence, not one supported boolean

| Evidence | API/report | Meaning and limits |
| --- | --- | --- |
| Configured | `configuration.main/sub_configured_media` | Current normalized camera settings; native numeric IDs retained separately |
| Advertised | `configuration.capabilities` | Camera-reported profiles with each resolution's associated FPS/bitrate constraints; never a Cartesian product |
| Negotiated | Existing `probe_local_stream`, `AutoMediaStream.discovery` | Protocol/header only; separate from codec decode or HA playback |
| Observed | `samples[].tracks` | Per-input stream codec, dimensions, pixel format, rate, audio parameters and time base |
| Decoded | `samples[].decode_status` | Optional complete FFmpeg decode of this finite sample, not physical A/V sync or sustained support |
| HA verified | `ha_verified` remains false | Requires real integration/HA frontend evidence, never inferred by these probes |

Authentication failure, timeout, no media, malformed response and explicit
ability rejection remain unknown or partially configured. They do not mean
the camera is permanently unsupported. One failed target does not hide the
remaining fleet. No authentication retry, credential guessing, configuration
change, cloud discovery, implicit preview or intentional wake command occurs in
the inventory query. It still contacts each supplied camera's command port.

`advertised_codecs` also names enumerated SDK video/audio codec IDs, retaining
unknown codes as null. These are separate offers, not an assertion that every
video/audio/resolution combination is valid. Non-enumerated range syntax is
preserved in the original configuration rather than guessed or expanded.

Main/sub configuration channels are **not** preview quality selectors. The
caller must supply known mappings when acquiring samples. A label of `unknown`
is preferable to claiming a preview channel is a main/sub stream. Samples are
caller-attested associations, not authenticated identity matches with the
metadata-query session. A sample is not evidence for all advertised codecs.

## Run a fleet inventory

Install the package (FFprobe/FFmpeg are needed only for media inspection/output).
Create a private JSON list. Password values are environment-only; no account
client or cloud session is needed:

```json
[
  {
    "alias": "camera-a",
    "serial": "SUPPLIED_DEVICE_SERIAL",
    "host": "192.0.2.10",
    "channel": 1,
    "login": {
      "username": "admin",
      "password_env": "CAMERA_A_PASSWORD",
      "port": 8000,
      "api": "NET_DVR_Login_V30",
      "https": false
    },
    "samples": [{"profile": "unknown", "path": "saved-clear.ps"}]
  }
]
```

Omit `samples` for metadata-only discovery. Select the known native login
profile explicitly, not a loop over possible passwords. For TLS use V40 and
the correct TLS port. Default certificate verification is retained; API users
can supply a private-CA `SSLContext` on each target. The CLI does not disable
verification or accept arbitrary FFmpeg arguments.

```sh
pyezvizapi-capabilities private-inventory.json --decode-samples > capabilities.json
# Equivalent before installing the new console script:
python -m pyezvizapi.capabilities_cli private-inventory.json
```

Exit 0: all metadata queries completed (including partial ability rejection).
Exit 1: one or more metadata queries unknown. Exit 2: invalid inventory/preflight.
Inspect sample status/decode status independently; metadata success does not
assert playback success. Reports omit reported serial, address, credentials,
media bodies, tags and diagnostic error text. Aliases are caller-controlled:
choose non-identifying aliases before sharing reports. Keep inventories and
clear media private. Reports contain sample hashes and camera capability data.

At most 64 explicit targets per batch, sequential acquisition-free queries,
at most 30 seconds per query. Each saved sample is 1 byte–16 MiB, at most 64
tracks, with a separate finite FFprobe/FFmpeg deadline and a 64 MiB combined
sample budget per batch. Timeouts are per phase,
not a single wall-clock deadline for the whole fleet. FFmpeg protocol whitelist
allows only the supplied pipe: playlists cannot fetch network/local resources.

## Explicit acquisition and headless sample output

`capture_media_sample(client, serial, options)` invokes the existing
`save_clip_with_options` only when explicitly called. Require both 1–4096
packets and a duration up to 30s. Supply known source credentials and channel;
for LAN choose local options with registration/fallback disabled. The output
byte cap is 16 MiB; it is **not** an encrypted transport/intermediate-memory
bound. The typed clip API does not currently accept transport byte bounds.
Do not use this helper to claim sustained or fleet-wide preview validation.

```python
from pyezvizapi.stream_sample import (
    EncodedTrackSelection,
    inspect_media_sample,
    remux_media_sample,
)

evidence = inspect_media_sample(clear_sample, decode=True)
# Use actual absolute indices from evidence; never assume the first two tracks
# are the two physical lenses. Audio omission is explicit.
mpegts_response = remux_media_sample(
    clear_sample, EncodedTrackSelection(video=0, audio=2)
)
```

MPEG-TS output accepts observed H.264/HEVC plus optional AAC only. Other audio
codecs require a separately tested adapter or explicit transcoding policy;
they are not silently dropped. FFmpeg stream copy retains encoded source NALs
and source time; container time-base rescaling and inserted access-unit delimiters
are expected. Whole video packet hashes may therefore differ: verify all original
non-delimiter NAL bytes and per-picture timing independently, not just decode
success. Output is staged,
bounded to 32 MiB and returned only after success. No worker thread, source or
listener remains. Caller owns any subsequent HTTP write. This finite utility
is not a remedy for continuous SDK demux/decrypt lifecycle requirements.

## Acceptance matrix before enabling native SDK delivery in HA

- One row per camera, configuration channel, observed profile, transport and
  encoded track/lens. Cover advertised-but-not-tested profiles separately.
- Independent compressed-packet hashes and PTS/duration equivalence before and
  after remux; no unintended lens/audio omission or re-encoding.
- Actual HA stream ingestion and frontend playback for H.264/AAC and HEVC/AAC;
  browser-dependent HEVC support explicitly recorded. Other codecs stay unknown
  until tested, even when FFmpeg can decode them.
- Startup, consumer disconnect, cancellation, source failure and integration
  unload close all transports/processes and leave bounded queues empty.
- Sustained sessions beyond two minutes, reconnect/discontinuity and multi-camera
  concurrency; battery/privacy/offline outcomes without automatic wake/fallback.
- No physical A/V synchronization claim from visual listening, software PTS
  alignment, a dummy sink or decode success.

The existing attended H9c two-minute test is useful per-camera evidence. It
does not certify other models, substreams, indefinite operation or HA playback.
