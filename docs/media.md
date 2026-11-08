# Media paths and their requirements

[Documentation index](README.md)

Choose a path by the output you need. A descriptor, authenticated socket or
successful remux is not evidence of HA/browser playback or audible audio.

| Goal | Path | Extra requirements / boundary |
| --- | --- | --- |
| Existing HA camera playback | Consumer's RTSP URL → HA stream/FFmpeg | Device RTSP support, correct credentials and reachable LAN endpoint; [HA status](home-assistant.md) |
| Save an image or bounded clip | CLI `save` or `EzvizClient.save_*` | Credentials/keys and source support; FFmpeg for remux, sometimes FFprobe; [saving guide](media-saving.md) |
| LAN-only SD-card recording download | `save clip --source local-playback` | Explicit IP, device password and UTC range; no account/cloud; [LAN SD downloads](lan-sd-playback.md) |
| Camera SD-card recording download | `save clip --source cloud-playback` | Explicit UTC range, MPEG-PS, byte/time budgets; [SD playback](cloud-sd-playback.md) |
| Cloud replay download | `cloud_video_download` | Account recording access and ticket/replay metadata; [CLI](cli.md#cloud_videos) |
| Inspect VTM/local transports | `stream trace`, `dump`, `proxy`, local SDK commands | Specialist/debug workflow, source-specific credentials, finite limits; [stream CLI](stream-cli.md) |
| Continuous native MPEG-PS owner | `NativeMpegTsStream` | `pyezvizapi[streaming]` / PyAV 19.x and an explicit supported source/track selection; [API](native-ha-stream.md) |
| Native stream inside HA | Isolated `ezviz_native` validation example | Real HA/PyAV test environment and explicit configuration; not the cloud integration; [validation](ha-native-integration.md) |
| Inspect configured capabilities offline | `pyezvizapi-capabilities` | Explicit inventory/optional saved samples; does not acquire a stream; [capability schema](ha-streaming-plan.md) |
| Compare native player behavior | Developer playback/decoder tools | Separate platform-specific software; [specialist guides](README.md#development-media-and-protocol-guides), not runtime library dependencies |

## Install only the selected dependencies

```bash
python -m pip install 'pyezvizapi[streaming]'
ffmpeg -version
ffprobe -version
```

Pip does not install FFmpeg/FFprobe. PyAV-backed APIs and subprocess-remux paths
are different: having one does not prove the other is available. The pure Python
cloud/device client does not require HA, PyAV, Android binaries or a desktop player.
The HA validation environment has its own Python 3.14 and dependency pins.

## Choose explicit bounds and keep original clocks

Prefer finite packet/byte/duration limits. Encrypted capture, mux, cleanup and
publication rules differ by source; read the [conformance/lifecycle reference](streaming.md)
before implementing retries. Missing audio metadata must not be replaced with
assumed cadence. Experimental shared/app-relative clocks require explicit input
evidence and are not general lip-sync corrections.

The `stream proxy` command creates a server; it is not an installation recipe for
production HA ingress. The native HA example uses HA's existing server with its
own admission/authentication boundary. Do not conflate these two topologies.

Protocol crypto is dictated by vendor compatibility. Its
[documented limitations](codeql-triage.md) are not removed by decoding successfully.
