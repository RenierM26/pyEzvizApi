# Streaming architecture and compatibility

This document describes the supported cloud and local media paths, their shared
contracts, and the validation procedure used before changing stream code.

## Module ownership

New code should import from the focused module that owns the behavior:

- `stream_transport`: VTM/VTDU discovery, framing, keepalives, cloud packet
  sources, and cloud replay transport.
- `stream_media`: MPEG-PS transport detection, prefix parsing, and Hikvision
  video decryption.
- `local_stream_transport`: local SDK and HCNetSDK command-port sessions,
  bootstrap plans, receiver sockets, keepalives, and local packet sources.
- `local_stream_media`: local MPEG/IDMX transforms, codec routing, clean
  IDR/IRAP selection, diagnostics, and remux entry points.
- `local_stream_ecdh`: ECDH handshake, key derivation, encrypted packet
  decoding, and the ECDH packet source.
- `media`: transport-neutral `MediaPacket`, `CaptureLimits`, decode/mux options,
  and packet-source adapters.
- `remux`: FFmpeg process construction, bounded stderr capture, cancellation,
  and terminate/kill cleanup.
- `clip`: grouped public source and clip configuration objects.

`pyezvizapi.stream` and `pyezvizapi.local_stream` are compatibility aliases for
older imports. They remain supported, but new lower-level integrations should
use the focused modules above.

## Conformance matrix

| Source | Wire packet | Normalized source | Startup in duration | Native payload | Typical output |
| --- | --- | --- | --- | --- | --- |
| Cloud VTM | `VtmPacket` | `cloud_vtm` | Yes | MPEG-PS | MPEG-PS or remuxed MPEG-TS |
| Local SDK | `EzvizLocalStreamPacket` | `local_sdk` | When startup preparation is available | MPEG-PS | MPEG-PS or remuxed MPEG-TS |
| Local SDK ECDH | `EzvizLocalSdkEcdhStreamPacket` | `local_ecdh` | Supported by the ECDH stream | MPEG-PS or IDMX/RTP | MPEG-PS for PS; decrypted MPEG-TS for IDMX/RTP |
| HCNetSDK command port | `EzvizLocalStreamPacket` | `local_sdk` | Yes for generated/multi-socket streams | IDMX/RTP or MPEG-PS | Remuxed MPEG-TS |

All adapters preserve the packet body and attach immutable transport-neutral
metadata. `CaptureLimits.max_packets`, `duration_seconds`, and `max_bytes` are
applied by the shared adapter contract. A packet that would cross `max_bytes`
is not emitted.

## Capture and lifecycle semantics

- Deadlines include bootstrap/startup for sources that advertise
  startup-aware iteration. Socket reads and keepalive writes are bounded by the
  same capture deadline.
- A deadline interruption invalidates a partially consumed transport when it
  cannot safely resume at a packet boundary.
- Packet and byte limits commit a yielded packet before stopping, so reusing a
  source cannot replay the last packet.
- Background keepalive failures invalidate the owning media client. Shutdown
  interrupts an in-flight keepalive before joining its worker.
- FFmpeg stdin, stdout, and stderr are coordinated. Consumer disconnects,
  blocked writers, launch failures, and nonzero exits terminate the process and
  preserve bounded diagnostic stderr.
- Decryption paths must be bounded. Unbounded encrypted capture is rejected
  before network or FFmpeg work begins.
- Descriptor-free IDMX AAC stays video-only. Packet cadence is not sufficient
  evidence for a reliable sample-rate guess.

## Public clip configuration

Prefer `EzvizClient.save_clip_with_options()` for new integrations:

```python
from pyezvizapi import (
    CaptureLimits,
    ClipOptions,
    LocalSdkClipSource,
    MediaDecodeOptions,
    MediaMuxOptions,
)

options = ClipOptions(
    source=LocalSdkClipSource(timeout=10.0),
    capture=CaptureLimits(duration_seconds=10.0),
    decode=MediaDecodeOptions(decrypt_video=False),
    mux=MediaMuxOptions(output_format="mpegts"),
    channel=1,
)
result = client.save_clip_with_options("ABC123", "front.ts", options)
```

Available source configurations are `LocalSdkClipSource`,
`LocalSdkEcdhClipSource`, `HcNetSdkCommandPortClipSource`, and
`CloudClipSource`. Capture, decode, and mux settings are deliberately separate
so unsupported combinations can fail before opening a connection.

The long `save_clip(...)` signature still delegates to the typed API. It also
preserves historically accepted zero and non-finite capture values for callers
that depended on the old loop behavior. New code should use valid positive,
finite `CaptureLimits` values instead.

## Transport limitations

- Cloud streaming depends on the VTM/VTDU endpoint returned for the account and
  camera region. Encrypted VTM channel packets are rejected until a supported
  channel-level decryptor exists.
- Direct local SDK streaming requires LAN endpoint and CAS data and may require
  P2P registration before CAS lookup.
- ECDH local streaming requires the native `0x43` metadata descriptor for AAC.
  Without it, capture intentionally remains video-only.
- The built-in HCNetSDK `app-lan-live-view` plan currently supports channel 1.
  Other channels require verified command templates.
- Command-port IDMX can carry H.264, HEVC, fragmented RTP, aggregate records,
  and AAC. Codec routing requires positive evidence and drops incomplete or
  discontinuous fragment chains rather than emitting corrupt NAL units.
- AES-ECB appears in fixed media-prefix transforms because the camera protocol
  mandates it. These helpers are compatibility decoders, not general-purpose
  cryptographic APIs.

## Golden fixtures

`tests/fixtures/stream/` contains small reviewable hexadecimal fixtures:

- `mpeg_ps_h264.hex`: synthetic MPEG-2 pack, bounded H.264 video PES, and a
  bounded audio PES that closes the trailing video run.
- `x80_idmx_hevc.hex`: synthetic X80-shaped length-prefixed IDMX/RTP records
  containing HEVC VPS, SPS, and IDR units.

The bytes are constructed fixtures, not camera captures. They contain no
serials, host addresses, credentials, media keys, or device-derived timestamps.
Tests pin their decoded length and SHA-256 digest, then exercise transport
detection, MPEG prefix parsing, IDMX routing, Annex-B reconstruction, packet
metadata, and cross-source byte limits.

## Validation

Offline validation is mandatory and requires no camera or EZVIZ account:

```bash
ruff check .
codespell pyezvizapi tests docs README.md pyproject.toml
mypy --install-types --non-interactive .
pyright pyezvizapi
pytest --cov=pyezvizapi --cov-report=term-missing --cov-fail-under=85
pip-audit --progress-spinner off
python -m build
twine check dist/*
python -m pip check
```

When an owner-provided inventory and LAN access are available, run the bounded
command-port matrix without printing secrets:

```bash
tools/apk-re/bin/hcnetsdk-command-live-check \
  --inventory-file ../secrets/ezviz-camera-inventory.env \
  --duration 8s
```

Some cameras, including tested X80 firmware, reject the HCNetSDK command-port
login while supporting the encrypted local SDK. Validate that path separately
with an owner-provided token and serial:

```bash
python -m pyezvizapi \
  --token-file /path/to/ezviz_token.json \
  --json save clip \
  --serial '<camera-serial>' \
  --source local-sdk-ecdh \
  --output /tmp/x80-smoke.ts \
  --duration 8s \
  --timeout 12 \
  --format mpegts \
  --decrypt-video
ffprobe -v error -show_streams /tmp/x80-smoke.ts
ffmpeg -v warning -i /tmp/x80-smoke.ts -f null -
```

At least one transport supported by the target camera must produce a playable
FFprobe result and a clean FFmpeg decode. A command-port login rejection is not
an ECDH failure and should be recorded as a transport limitation. Use
`--save-sampled-packets` only when bounded diagnostic sidecars are needed;
inspect and sanitize any sidecar before sharing it. Never commit live captures,
inventory files, serials, passwords, tokens, or media keys. If live hardware is
unavailable, record the live check as skipped; offline golden-fixture
conformance remains required.
