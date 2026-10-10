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
  for a reliable sample-rate guess. Bounded IDMX captures retain positive AAC
  timestamp gaps in local concat timelines instead of dropping the entire audio
  track. Received access units remain unchanged; missing units are not filled
  with generated silence. Reordered or invalid audio clocks are not accepted
  as forward gaps. Incremental proxy audio continuity is a separate limitation.

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

Available source configurations are `AutoClipSource`, `LocalSdkClipSource`,
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
  HEVC media wrappers use the advertised `0x42` video descriptor frame period
  when present, retaining exact rational rates. Reserved or invalid periods do
  not establish timing; without that descriptor, encoded SPS/VUI timing remains
  the fallback rather than a forced wrapper RTP-clock estimate. Later valid metadata corrects startup
  placeholders, as for AAC metadata. Bounded elementary-stream remuxing uses
  that advertised rate; it does not certify arbitrary variable-frame-rate input.
- Direct local SDK streaming requires LAN endpoint and CAS data and may require
  P2P registration before CAS lookup.
- ECDH IDMX/RTP streaming requires the native `0x43` metadata descriptor for
  AAC. Without it, capture intentionally remains video-only. MPEG-PS audio
  instead carries its own PES/ADTS framing.
- Authenticated ECDH MPEG-PS may still contain media-key-encrypted video,
  including SPS/VPS bytes. Bounded captures with `decrypt_video=True` and a
  media key retain PS from its first pack boundary for the inner AES transform,
  rather than waiting for a keyframe visible before that transform. Unknown
  media, failed transport authentication and missing capture bounds still fail;
  clear captures retain their existing keyframe gate.
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

## Automatic playback and fully offline operation

New Home Assistant-style callers can request automatic protocol/transport
selection rather than maintaining camera-model tables:

```python
result = client.save_clip(
    serial, "preview.ts", source="auto", decrypt_video=True,
    duration_seconds=10,
)
# result["source"] names the transport that actually succeeded.
```

Auto reads the per-device pagelist metadata once, prefers the advertised LAN
endpoint, and uses `deviceInfos.supportExt["519"]` to select ECDH for owned live
view when member `1` is present. The official app's `DeviceParam` and
`InitParamCreator.createDeviceCamera` use this membership check; values such as
`2,3` or `11` are not interchangeable with `1`. Missing 519 in an otherwise
populated support map selects legacy local streaming. Missing/malformed maps
or parent-device metadata are treated as unknown, not as proof of support.
Unknown profiles start with ECDH and verify the actual stream. Confirmed legacy
RTP/PS switches to legacy using the same credentials, without a separate probe
session. Codec routing still uses the stream descriptors described above.
Channel and mux choices remain caller-controlled; this does not change camera
quality, encryption, privacy, or other device settings.

`AutoClipSource(device=cached_device_info)` reuses the integration's per-device
`get_device_infos()` snapshot instead of fetching pagelist again. Automatic mode
may still acquire CAS credentials/register P2P and fetch a media key when
requested decryption needs one. Missing LAN metadata or a pre-output connection
failure can select cloud. Set `allow_cloud_fallback=False` to disable that
fallback; this alone **does not** prohibit cloud credential discovery.
Authentication/MFA/HMAC, unsupported codec, configuration, and silent no-media
errors are not disguised by fallback. A premature ECDH close retries the tested
rate-0 variant before cloud. Auto defaults to a fresh local source port for
each stream, allowing concurrent cameras without a shared fixed-port collision.
Automatic protocol retries and live rate retries also choose fresh ports to avoid
rebinding the previous connection during TCP TIME_WAIT. `AutoClipSource` accepts
an explicit `receiver_port` for the initial attempt when required.
Once bytes or packets have been emitted there is no
source switching. Auto clips stage their finite captures privately, preserving
an existing destination on a failed attempt. Transport startup and fallback
share the capture duration budget; account discovery happens before that budget.
Legacy explicit sources and their defaults are unchanged.

### Offline means no cloud calls

Use `AutoClipSource(mode="offline", credentials=...)` with explicit LAN
connection and CAS control credentials, plus the media key for video decryption:

```python
from pyezvizapi import (
    AutoClipSource, CaptureLimits, ClipOptions, EzvizClient,
    MediaDecodeOptions,
)
from pyezvizapi.hcnetsdk import EzvizCasDeviceInfo, HcNetSdkLanEndpoint
from pyezvizapi.local_stream_transport import EzvizLocalSdkCredentials

credentials = EzvizLocalSdkCredentials(
    endpoint=HcNetSdkLanEndpoint(
        serial=serial, host=lan_ip, command_port=9010, stream_port=9020,
    ),
    device_info=EzvizCasDeviceInfo(
        serial=serial, operation_code=operation_code, key=control_key,
    ),
    media_key=media_key,
)
source = AutoClipSource(
    mode="offline", credentials=credentials,
    device=cached_device_info,  # optional; no metadata request if omitted
)
local_client = EzvizClient()  # no login or cloud token needed
result = local_client.save_clip_with_options(
    serial, "offline.ts",
    ClipOptions(source=source, capture=CaptureLimits(duration_seconds=10),
                decode=MediaDecodeOptions(decrypt_video=True)),
)
```

This policy does not call pagelist, CAS, account login, P2P registration, or key
retrieval, and never falls back to cloud. Supplied credentials must match the
requested camera. Missing or device-rejected credentials fail locally; they are
not silently renewed. Obtain/export required credentials during provisioning,
protect any stored keys, and supply the camera's actual LAN ports. Offline is a
connection policy, not a promise that firmware never expires stored credentials.
Explicit `LocalSdkClipSource(credentials=...)` and
`LocalSdkEcdhClipSource(credentials=...)` also bypass discovery. Existing
caller-supplied HCNetSDK command-port plans remain available for that offline
native LAN path. The existing CLI `stream local-dump --credentials-file ...`
continues to work without account login; `save clip --source auto` is the online
automatic convenience command.

### Live integration packet interface

```python
with client.open_stream(serial) as stream:  # defaults to automatic selection
    for packet in stream.iter_media_packets():
        consume_packet(packet)
    selected_source = stream.source_kind
```

Pass `source=source` from the offline example to apply the same cloud-free policy
here. Optional `CaptureLimits` apply packet, byte, and duration bounds, including
startup and retries after account discovery. Always close the context on consumer
disconnect; explicit `close()` cancels the active transport. Iteration is
single-use and does not reopen a closed stream. This API yields normalized
transport packets, not a ready-to-play URL or video-decrypted/remuxed output.
An integration must apply the existing media transforms/mux layer before serving
video. ECDH transport authentication/decryption remains automatic inside the
transport; video AES decryption is separate. The existing bounded
`probe_local_stream()` remains a diagnostic tool, not a required pre-play step.

Automatic saved ECDH clips keep emitted `max_packets` separate from encrypted
input frames: packet-bounded attempts allow up to `max_packets + 1024` input
frames for handshake, descriptors and protocol detection. This remains a finite
input allowance; duration-bounded attempts also retain their shared deadline.
Existing explicit ECDH source frame-limit behavior is unchanged.

Automatic legacy LAN clips likewise count nonempty media packets, skipping empty
leading records within a finite `max_packets + 1024` input allowance. The local
capture duration includes startup. Existing explicit-source defaults are unchanged.

Automatic live legacy streams use the same nonempty-packet accounting and bounded
input allowance. Empty-only input fails as no media, not a successful live packet.

Automatic cloud bootstrap includes metadata/key requests and token-lock waits in
the remaining capture budget, without changing the client's default timeout.
Byte-only automatic live captures also cap negotiation/empty input at
`max_bytes + 1024` frames (or the tighter packet bound when both are supplied).
Duration-only live capture retains its shared deadline.

## Camera-reported local stream details

For compatible cameras, the pure-Python HCNetSDK command-port API can ask the
camera for both its configured main/sub streams and its supported profiles.
This follows the native app's `NET_DVR_GetDVRConfig` command 1040
(`NET_DVR_COMPRESSIONCFG_V30`) and `NET_DVR_GetDeviceAbility` type 8
(`AudioVideoCompressInfo`). It starts no preview and changes no settings.

```python
from pyezvizapi import HcNetSdkLanEndpoint, discover_hcnetsdk_stream_details

endpoint = HcNetSdkLanEndpoint(serial=serial, host=lan_ip, command_port=8000)
details = discover_hcnetsdk_stream_details(
    endpoint, local_password, channel=1, timeout=10,
)
main_resolution = details.configured_resolution()
sub_resolution = details.configured_resolution(sub_stream=True)
summary = details.as_dict()
```

An existing `HcNetSdkPurePythonClient` also exposes `stream_details(channel=1)`.
Both paths use supplied LAN login credentials only. Those credentials are not
necessarily interchangeable with CAS credentials. The app can use the original
sticker verification code or the current user-defined encryption password for
local login; supply the known current value explicitly. Do not substitute a
CAS operation key or a derived AES key, or enumerate passwords automatically.
There are no cloud calls, credential renewal, authentication retries, or cloud
fallbacks. Login failure is not evidence that a camera lacks the capability.
The login connection stays open while both authenticated queries run: newer
cameras invalidate the session when that connection closes. The finite network
timeout covers one login and both read-only queries;
local RSA generation precedes it. Replies have a configurable size limit
(`max_response_bytes`, default 512 KiB, including the frame header).

| Evidence | Meaning |
| --- | --- |
| `configuration` / `main` / `sub` | Camera-reported configuration, not decoded media |
| `capabilities` | Supported profiles, with per-resolution dimensions and limits |
| `capabilities_error` | Raw device rejection code when ranges could not be retrieved; `None` on success |
| `configured_resolution()` | Configuration index resolved against this camera's own capability list |
| Stream descriptors / decoded media | What an actual preview session emits |
| Encryption negotiation | Independent evidence needed to select legacy versus ECDH |

Native codec, frame-rate and bitrate fields remain SDK codes. A frame-rate code
of 14 does **not** mean 14 fps. Resolution dimensions come from the camera XML,
not a guessed index table; unknown or ambiguous associations return `None`.
A complete header-only rejection of the optional capability query retains the
confirmed configuration and exposes `capabilities_error`; it is not evidence
that the camera supports no profiles. Dimensions/ranges remain unknown. Empty
success, malformed responses, login failure and network timeouts still raise.

Fixed bitrate choices advertised as `VideoBitrate/Range` are preserved as
`bitrate_codes`, including when a camera supplies no custom `Min`/`Max` bounds.
`reported_login_serial` is the native hardware/model identity string and need
not equal the short camera serial used in `endpoint`. `as_dict()` omits raw
reply bodies and authentication material, but includes this reported identity.

These queries do not establish ECDH support. A codec or resolution alone cannot
choose the encryption protocol. Automatic playback keeps its existing
metadata/negotiation policy; this explicit discovery API does not introduce an
extra password login or cloud dependency into the strict offline path.


### Normalized configuration and negotiated session headers

`details.configured_media()` (and `sub_stream=True`) returns configured codec,
frame rate, bitrate in bits/second, audio sample rate and camera-associated
resolution. Raw SDK codes remain intact. Native code 14 maps to 15 fps; code 0
means full 25/30 rate without choosing either, and automatic/unknown values remain
`None`. Bitrate units follow the native 1024 conversion. Configuration is not
proof of emitted media, and never selects link encryption.

A successful local preview returns `bootstrap.stream_header`: a sanitized
`EzvizStreamHeader` from the camera's 40-byte PlayM4 header. The parser keeps
this namespace separate from SDK configuration and RTP payload IDs. It exposes
negotiated video/audio codecs and audio parameters, but not session IDs, keys,
video dimensions/FPS that the header does not provide, or guessed encryption.
Absent headers return `None`; malformed or unsupported layouts raise
`PyEzvizError` when explicitly inspected. Optional metadata failure does not
prevent otherwise playable automatic live streams.

```python
from pyezvizapi import AutoClipSource, CaptureLimits, LocalStreamDiscoveryCache

cache = LocalStreamDiscoveryCache(ttl=300, max_entries=32)
source = AutoClipSource(
    mode="offline", credentials=local_credentials,
    discovery_cache=cache, discovery_generation="configuration-v1",
)
with client.open_stream(serial, source=source) as stream:
    for packet in stream.iter_media_packets(limits=CaptureLimits(duration_seconds=30)):
        consume(packet)
        # stream.discovery contains fresh negotiated metadata, not decoded proof.
```

The cache belongs to the caller and stores no authentication material. Identity
is hashed from endpoint, channel, credentials, cached device metadata and the
caller's generation. A successful emitted local input can reuse its transport
choice on the next live open, avoiding repeated protocol mismatches. Every new
session still authenticates and parses a fresh header. TTL expiry, changed
identity/generation, explicit `cache.invalidate()`, or transport failure force
fresh selection. Reads never extend TTL. No source switch occurs after output.
Malformed optional headers are not cached. Full offline policy remains enforced.
Clip capture may use a matching cached hint, but does not populate the live cache.
After camera configuration changes, invalidate the cache or advance its generation.

### Explicit native LAN authentication profiles

```python
from pyezvizapi import discover_hcnetsdk_stream_details_for_login, ezviz_lan_login_candidates

# Select one profile using known device/scan information; do not loop passwords.
profile = ezviz_lan_login_candidates(local_password)[0]
details = discover_hcnetsdk_stream_details_for_login(
    endpoint, profile, tls_context=trusted_camera_ssl_context, timeout=10,
)
```

The TLS V40 profile carries the native binary command protocol, not an HTTP GET.
Default TLS verifies the camera certificate using system trust; private CA trust
can be provided through an `SSLContext`. TCP connect and TLS handshake share
one remaining deadline, followed by login/config/ability queries in the same
total budget. Plain V30 and derived `EZ_LOCAL_USER` profiles are explicit choices.
Only the selected supplied credential is attempted, with no profile/password
fallback, cloud retrieval or renewal. Login rejection does not imply unsupported
stream capabilities. Cameras accepting TLS but rejecting the available LAN
credential still need the correct app/local password for configuration queries;
CAS-authorized preview headers remain an independent discovery source.

### Owned local preview cleanup

Structured local SDK previews remember only their accepted positive session.
Closing releases that session using the native stop request on a fresh command
connection, then drains the stopped media socket before closing it. Cleanup is
best-effort and bounded by one two-second deadline and a 4 MiB drain limit; it
never calls the cloud or retries credentials. Explicit `stop_preview()` exposes
stop errors to low-level callers. Raw caller-supplied setup bodies do not grant
stop authority. The stop envelope shares command 0x2013 with ECDH pre-start, but
uses the owned session rather than a wildcard initialization body. A media socket
with an interrupted partial frame is removed from parsing and retained only for
this bounded teardown. Further reads on that client are rejected rather than
opening an unrelated socket. Consuming an explicit stop also makes the client
terminal, including when the stop fails; callers must close it before reopening.

### Native clear LAN preview

The built-in `app-lan-live-view` command plan selects its observed HCNetSDK port
8000 when no command-port override is supplied. The API's `CONNECTION.command_port`
can instead name the separate EZVIZ CAS service at9010; it is not a native preview
endpoint. Explicit ports and caller-supplied custom plans retain their behavior.
Use the camera's current native login key, not a stale saved password.

Clear native IDMX captures use the advertised HEVC period and retain descriptor-
backed, well-framed RFC3640 AAC even when individual audio packets have no encrypted
IDMX extension. Clear input bypasses AES explicitly. Received AAC timestamp gaps
and jitter are retained; no silence or guessed timestamps are added. Undescribed
plain RTP is not inferred as AAC. Encrypted IDMX eligibility stays unchanged.
Startup-trim/wait modes do not add clear audio without evidence for matching the
selected video interval. The built-in app-observed native plan remains a single-
channel plan, not a way to force a second lens.
