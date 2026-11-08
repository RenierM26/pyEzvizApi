# Saving images and finite clips

[Documentation index](README.md) · [Getting started](getting-started.md)

These examples describe current `main`; check the [changelog](../CHANGELOG.md)
for release availability. Install FFmpeg for remuxing and the `streaming` extra
for PyAV-based APIs. The commands below acquire media or trigger snapshots;
they are not read-only capability inspection. Replace all example identifiers.

## CLI and Python capture APIs

Person-friendly media save commands for scripts and Home Assistant
`shell_command` usage. These write to local filesystem paths and print a small
JSON result when `--json` is used.

```bash
# Save a short direct-local live clip. MPEG-TS uses FFmpeg remuxing with copy.
pyezvizapi --json --token-file ezviz_token.json save clip \
  --serial ABC123 --channel 1 --duration 10s \
  --output /config/www/ezviz/front.ts

# Save a direct-local encrypted battery-camera clip.
pyezvizapi --json --token-file ezviz_token.json save clip \
  --serial ABC123 --duration 10s --decrypt-video \
  --output /config/www/ezviz/front.ts

# Decrypted direct-local clips auto-detect whether the codec header is clear.
# Use --decrypt-codec encrypted-header only for a device known to encrypt it.

# Cloud save auto-selects the first VTM resource unless --channel is given.
# This matters on multi-lens cameras whose first resource is channel 0.

# Save from the full local HCNetSDK command-port media path on port 8000.
pyezvizapi --json --token-file ezviz_token.json save clip \
  --source hcnetsdk-command-port --serial ABC123 --host 192.0.2.10 \
  --hcnetsdk-command-frames-file /config/ezviz/ABC123-port8000-frames.json \
  --duration 10s --output /config/www/ezviz/front.ts

# Trigger a snapshot and save the returned image locally.
pyezvizapi --json --token-file ezviz_token.json save image \
  --serial ABC123 --channel 1 \
  --output /config/www/ezviz/front.jpg

# Save a known alarm/snapshot image URL without triggering a new capture.
pyezvizapi --json --token-file ezviz_token.json save image \
  --serial ABC123 --image-url "https://..." \
  --output /config/www/ezviz/alarm.jpg
```

Timed decrypted MPEG-PS cloud captures of at least eight seconds raise
`EzvizIncompleteMediaError` (`reason="incomplete_media"`) when their video
timestamp span is less than half the requested duration. Packet-capped captures
are exempt. The exception exposes `source`, `requested_duration_seconds`, and
either `observed_pts_span_seconds` or `observed_video_duration_seconds` for a
caller to retry or choose another source. When PES timestamps cannot establish
a span (for example, only one PTS), `ffprobe` checks a private staged clip
before publication; that binary is required for these ambiguous captures.
Bounded cloud file saves stage the capture privately before opening the
destination, so capture/remux failures preserve an existing file. Successful
publication writes through the destination path, retaining its ownership,
ACLs, and usual umask behavior; a final filesystem write failure is not an
atomic rollback. An explicitly unbounded cloud save writes directly to its
destination as media arrives; interruption can leave a partial clip.

`save clip` uses the direct-local `9010/9020` SDK path and fetches the LAN
endpoint/CAS tuple from the authenticated client by default. Use
`--source hcnetsdk-command-port` for the full local port-8000 media path when
you have the complete HCNetSDK bootstrap command frames from a trusted local
implementation; the release package consumes those frames and keeps APK/Frida
tooling under `tools/apk-re`. `save image` triggers the camera capture endpoint
unless `--image-url` is supplied, then downloads and decrypts EZVIZ encrypted
image payloads when needed.

Integrations can use the same behavior directly from `client.py` without
shelling out:

```python
result = client.save_clip(
    "ABC123",
    "/config/www/ezviz/front.ts",
    duration_seconds=10,
    source="local-sdk",
)

image = client.save_image(
    "ABC123",
    "/config/www/ezviz/front.jpg",
    channel=1,
)
```

For integrations with several stream modes, use the typed configuration API so
source-specific connection settings stay separate from capture, decode, and mux
settings:

```python
from pyezvizapi import (
    CaptureLimits,
    ClipOptions,
    CloudClipSource,
    MediaDecodeOptions,
    MediaMuxOptions,
)

result = client.save_clip_with_options(
    "ABC123",
    "/config/www/ezviz/front.ts",
    ClipOptions(
        source=CloudClipSource(client_type=9, refresh_vtm=True),
        capture=CaptureLimits(duration_seconds=10),
        decode=MediaDecodeOptions(decrypt_video=False),
        mux=MediaMuxOptions(output_format="mpegts"),
        channel=1,
    ),
)
```

## Advanced sources and clocks

For shared/app-relative clocks, explicit command-port bootstrap templates,
capability inspection and native reference tooling, see
[advanced media recipes](media-advanced.md). These require source-specific
metadata; they are not defaults for an ordinary clip save.
