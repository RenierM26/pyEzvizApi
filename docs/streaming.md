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
| Cloud VTM | `VtmPacket` | `cloud_vtm` | Yes | MPEG-PS, MPEG-TS, or RTP/IDMX | MPEG-PS for PS; pass-through/remuxed MPEG-TS for TS/RTP |
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
- Decryption paths that collect encrypted input before transforming it must be
  bounded. They reject unsafe capture limits before network or FFmpeg work
  begins. The HTTP proxy decrypts incrementally instead of buffering a capture.
- Descriptor-backed IDMX AAC uses the native sample rate and channel count and
  is retained in decrypted local and cloud RTP MPEG-TS output. Descriptor-free
  IDMX AAC stays video-only because packet cadence is not sufficient evidence
  for a reliable sample-rate guess.

### RTP/IDMX codec detection

Codec routing follows the metadata-first behavior of the official EZVIZ
Android app. Native IDMX descriptor `0x45` advertises a stream type and RTP
payload type; `pyezvizapi` uses that route before inspecting media bytes.
Descriptors may arrive after the first packets. Streaming exports retain an
evolving route profile until media dispatch begins; compatible repeats are
accepted, while a later payload-owner or codec mutation fails explicitly before
the affected packet reaches a depacketizer. Descriptor-free payload type 96
keeps its legacy H.264/HEVC probing behavior.
Descriptor `0x43` supplies audio parameters such as sample rate and channels,
but does not identify the codec by itself. When `0x45` is absent, the shared
RTP layer recognizes the official app's static payload families, rejects known
MPEG-2/MPEG-4 start codes by name, and only uses NAL-shape probing for the
remaining H.264/HEVC candidates on shared payload type 96.

The codec inventory was verified against EZVIZ Android 7.6.1.0824, signed by
`CN=hikvision` (certificate SHA-256
`45e984f72060dc783490c3905c7efae87397e79fcb033c4e0c54c7acc061e2c5`).
Its native RTP/IDMX tables cover:

- video: H.264, HEVC/H.265, MPEG-2, MPEG-4, MJPEG, SVAC, and a private `VID4`
  family;
- audio: MPEG audio, AAC, AAC-LD, PCM, G.711 A-law/μ-law, G.722, G.723,
  G.726, G.729, and Opus;
- static RTP payload families: video 26/32/96/99, audio
  0/4/8/11/14/18/98/100/102/103/104/115, and metadata 112.

Current media export remains intentionally narrower: H.264 and HEVC video,
plus descriptor-backed AAC-LC audio. Other advertised video codecs are now
reported by name instead of being guessed as HEVC. Other audio codecs are
classified correctly but remain video-only until a tested depacketizer and
FFmpeg input contract are added for each format.

The app's codec table includes Opus (`0x3002`, static RTP payload type 115),
but its `0x45` stream-type table does not define an Opus entry. Unknown `0x45`
stream types are therefore preserved as unknown routes: their payload types
cannot be mistaken for fallback video or audio while remaining safe for future
codec support.

Sanitized local IDMX summaries include an `rtp_profile` with codec, media kind,
payload type, observed SSRC, and authoritative sample-rate/channel metadata.
They never include packet bodies, media keys, credentials, or device identity.
Descriptor-free static audio is named only where the official RTP/app mapping
is unambiguous; dynamic and private ownership remains visible as `unknown`.

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

The long `save_clip(...)` signature still delegates to the typed API. For
non-decrypting captures it preserves historically accepted zero and non-finite
capture values for callers that depended on the old loop behavior. Decrypting
captures reject those unsafe values and require at least one positive finite
bound before network work. New code should use valid positive, finite
`CaptureLimits` values instead.

## Transport limitations

- Cloud streaming depends on the VTM/VTDU endpoint returned for the account and
  camera region. Encrypted VTM channel packets are rejected until a supported
  channel-level decryptor exists.
- Cloud RTP/IDMX video is depacketized as H.264 or HEVC before MPEG-TS remuxing.
  With `decrypt_video` enabled, supported RFC 3640 AAC is decrypted with the
  same camera media key and retained when the native `0x43` descriptor provides
  authoritative sample-rate/channel metadata. Bounded captures remux buffered
  elementary streams; the HTTP proxy uses a bounded loopback-only second FFmpeg
  input. Raw output remains available for packet-exact diagnostics. An RTP or
  MPEG-TS cloud stream cannot be requested as MPEG-PS because doing so would
  mislabel its bytes.
- Packets explicitly marked by the native IDMX transport parser and using the fixed `0x55667788` source marker have per-payload-type
  sequence counters. Ordinary RTP sources retain SSRC-wide counters, even if
  their SSRC happens to have that same value. Local
  one-byte-prefixed RTP records are normalized with their extensions and padding
  before media reassembly; padding is never part of the encrypted NAL. Native
  HEVC media wrappers use encoded SPS/VUI timing rather than a forced RTP-clock
  frame-rate estimate.
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

## Bounded local protocol probing

```python
profile = client.probe_local_stream(serial, duration_seconds=10)
# protocol: ecdh / legacy_rtp_ps / unknown / no_data
# recommended_source: local-sdk-ecdh / local-sdk / None
```

The probe observes an ECDH-requested local session. `ecdh` requires verified
native handshake authentication, not just a matching magic byte. Repeated,
parseable RTP packets with recognized PS starts on one route identify
`legacy_rtp_ps`; duplicates, SSRC alone, RTP version bits, and Annex-B lookalikes
do not establish that result. The source recommendation is explicit: neither
this probe nor an explicitly selected ECDH source silently downgrades transport.
Authentication/network errors propagate. An ECDH capture receiving established
legacy framing raises `EzvizUnsupportedMediaError` with `source="local-sdk-ecdh"`
and `reason="protocol_mismatch"`, recommending direct-local with the current key.
Genuine silence still yields the existing no-media outcome.

Credential discovery precedes the probe's finite stream deadline. Local
bootstrap and reads share that deadline; frame and byte-processing limits also
apply. A received frame crossing the byte budget is counted but not decoded;
at most one complete interleaved frame may cross the receive-byte budget.
Sockets close on every exit. The returned dictionary contains only protocol,
source recommendation, authenticated-ECDH flag, and received frame/byte counts;
no payloads, peer identifiers, session keys, or camera credentials are included.
This is protocol detection, **not** codec/media-key/playback certification or a
permanent model-capability cache. Validate actual video and audio with the
selected source and current media key. The official app's ability to play a
camera does not prove it used ECDH rather than a different supported transport.
