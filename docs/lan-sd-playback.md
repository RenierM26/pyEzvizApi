# LAN-only SD-card recording downloads

[Documentation index](README.md) · [Media paths](media.md)

Download a selected historical interval directly from the camera's SD card over
its HCNetSDK TCP command port (normally **8000**). This is not a recording of
live preview, a cloud subscription download, or the VTM relay path.

The path uses pure Python. It does **not** need an EZVIZ account token, cloud
record-list queries, CAS lookup, the Android app, or vendor SDK binaries. It
never falls back to cloud and does not change camera settings. You must supply
an explicit camera IPv4 address, full device serial, device username/password,
and an interval known to contain footage. Only that credential is tried.

## CLI

Store the device password in a private file. A single trailing LF/CRLF is
removed; other password bytes are preserved. Do not put credentials in shared
scripts or shell history. The device/LAN password can differ from both the
account password and the media-encryption key.

```bash
pyezvizapi --json save clip \
  --source local-playback --host 192.0.2.10 --serial C12345678 \
  --lan-password-file /private/camera-password \
  --begin-time 20261108T081522Z --end-time 20261108T081542Z \
  --playback-timezone Africa/Johannesburg \
  --channel 1 --output sd-recording.ps
```

The example IP/serial are placeholders. Replace them with your camera's values.
No `--token-file`, account username/password or MFA is required. `--lan-username`
defaults to `admin`; `--command-port` defaults to 8000. The existing
`--hcnetsdk-command-password` also works, but exposes the secret in process
arguments. Do not supply both password sources.

Input times are **UTC**. `--playback-timezone` explicitly projects those times
into the camera's wall clock; it defaults to UTC, never the host's timezone.
Ambiguous DST selections and offset transitions are rejected. Native LAN channel
numbers are one-based; do not copy VTM channel `0` into this API.

An omitted duration downloads the full selected range (maximum 24 hours).
`--duration 10s` limits the selected end, not the wall-clock transfer time. A
range must select whole seconds. `--timeout` is the socket idle limit;
`--playback-transfer-timeout` is the shared bootstrap/transfer/logout budget
(default 60 seconds), checked across socket reads, not reset per packet.
`--playback-max-bytes` defaults to 128 MiB and includes download-block framing.
No packet-count truncation, cloud decryption, clock rewriting or MPEG-TS output
is accepted on this route. The output is the native MPEG-PS recording with its
40-byte vendor stream header, without re-encoding.

## Python, without constructing an account client

```python
from pyezvizapi import HcNetSdkLanEndpoint, download_lan_sd_recording

result = download_lan_sd_recording(
    HcNetSdkLanEndpoint(serial="C12345678", host="192.0.2.10"),
    b"DEVICE_PASSWORD",  # load from private storage
    "sd-recording.ps",
    "20261108T081522Z",
    "20261108T081542Z",
    timezone="Africa/Johannesburg",
    channel=1,
    max_bytes=16 * 1024 * 1024,
    transfer_timeout=30,
)
```

Existing client callers can use grouped options; the account client is not
consulted for LAN discovery, authentication or key lookup:

```python
from pyezvizapi import ClipOptions, EzvizClient, LocalPlaybackClipSource

client = EzvizClient()
try:
    result = client.save_clip_with_options(
        "C12345678",
        "sd-recording.ps",
        ClipOptions(
            source=LocalPlaybackClipSource(
                "20261108T081522Z", "20261108T081542Z",
                host="192.0.2.10", password=b"DEVICE_PASSWORD",
                timezone="Africa/Johannesburg",
            ),
            channel=1,
        ),
    )
finally:
    client.close_session()
```

The long-form `client.save_clip(source="local-playback", ...)` is also supported
with `host`, `hcnetsdk_command_password`, `command_port`, and
`local_playback_begin_time` / `local_playback_end_time` /
`local_playback_timezone` / `local_playback_username` /
`local_playback_max_bytes` / `local_playback_transfer_timeout`.

## Completion, ownership and limits

- A fresh RSA/challenge login verifies the supplied serial against the native
  device-serial suffix. Selection and start share one fresh data connection;
  logout uses a separate authenticated control connection. Every owned socket
  closes on success or failure. Numeric selection refusals are retained in
  `LanPlaybackError.result_code`; no universal cause is inferred.
- Completion requires the native end marker, contiguous complete MPEG-PS
  framing and sufficient continuous video PTS span for the requested duration.
  TCP EOF, an idle timeout or a successfully received prefix is not success.
  Sparse/event-only ranges may be rejected; choose a continuous recording.
- The camera's advertised file size is a hint, not an exact output count. The
  tested SDK itself writes fewer bytes than that field. Actual accepted wire
  bytes are counted independently; no declared size is used for allocation.
- Media spools to private temporary storage above 1 MiB. Final framing/PTS
  validation reads a complete **byte-bounded** snapshot, not constant-memory
  decoding. Publication copies in bounded chunks. Paths are replaced atomically
  only after validation and acknowledged logout; failures preserve an existing
  file. Caller-owned binary writers receive only validated bytes but cannot
  roll back their own final write/flush failure.
- An expired deadline or failed connection can prevent acknowledged logout;
  failure remains visible and all client sockets close. This is not proof of
  immediate camera-side session retirement. Key generation is local CPU work;
  an expired budget is checked before networking starts.
- Record search/listing is not implemented here. There is no automatic lookup
  or substitution of another interval, username, credential or route.

## Protocol evidence and qualification

The normal installed Android HCNetSDK was used only as a private protocol
reference. `NET_DVR_GetFileByTime` followed by `NET_DVR_PlayBackControl(PLAYSTART)`
uses command `0x30102` (one channel, two network-order six-word times, download
flags) and `0x30103` (zero start offset). `PackVodSendData` in `libHCPlayBack.so`
corroborates the time/flag layout. Response blocks are network-order length/type:
19 metadata, 20 media, 21 terminal. The tested metadata carries duration/frame
hints and a 40-byte `IMKH` stream header. Other header layouts fail explicitly.

On 2026-11-08, the retained H9c channel-1 native SDK download and a pure-Python
prototype produced **byte-identical 2,018,048-byte files** for a selected
20-second recording. FFprobe identified 1920×1080 HEVC plus mono 16 kHz AAC;
FFmpeg decoded both without errors. This local channel has one video track;
the separate cloud route's two-lens result is not a claim for LAN channel 1.
A clean installed wheel subsequently passed three sequential downloads
(API / account-free CLI / API), each byte-identical to that native file. Every
run used three camera-port connections, made zero HTTP requests under a
reject-all HTTP guard, observed the native end marker and acknowledged logout.
Each decoded 300 HEVC frames and 331 AAC frames with no FFprobe/FFmpeg errors.
PyAV was absent from the wheel runtime. This does not establish a long soak or
frame-exact trimming: the selected 20-second interval spans 21.0667 seconds of
video PTS.
Other models/channels, physical playback/audibility, absent/corrupt intervals,
and HA/frontend integration are not qualified by that result. Raw protocol
captures, passwords and recordings remain private.
