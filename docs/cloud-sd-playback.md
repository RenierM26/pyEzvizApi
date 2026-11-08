# Cloud-mediated SD-card playback

[Documentation index](README.md) · [Media paths](media.md)

Download a recording time range from a camera's **SD card through EZVIZ's VTM
relay**. This is not cloud-subscription storage (`cloud_video_download`), a live
preview, a local RTSP recording URL or a new HA playback interface. The camera
must be online and have SD footage for the selected range.

This feature builds on **Alejandro Dirgan (@adirgan)**'s
[original PR #266](https://github.com/RenierM26/pyEzvizApi/pull/266), including
his playback selector and observed channel-2 media behavior. It has been adapted
to the current capture API, deadlines and publication contracts. It is unreleased
until included in a published version; use the matching source checkout/docs.

## CLI

First list known SD recording descriptors using [the recording commands](cli.md#sdcard_videos),
then select a short range. Times below are synthetic **UTC** values in native
`YYYYMMDDTHHMMSSZ` format. Convert an account/camera-local wall time explicitly;
the library does not infer a timezone or reinterpret a local time ending in `Z`.

```bash
pyezvizapi --token-file ezviz_token.json --json save clip \
  --source cloud-playback --serial CAMERA_SERIAL --channel 1 \
  --begin-time 20261108T120000Z --end-time 20261108T120020Z \
  --decrypt-video --format mpegps --output sd-clip.ps
```

Omit `--decrypt-video` for clear media. When decrypting, the default automatically
selects the clear NAL-header convention; an explicit `--decrypt-codec` remains an
override. VTM transport-level encrypted packets are a separate unsupported mode
and fail rather than publishing only the clear prefix.

- The default is the **whole begin/end range**, not the live save's ten-second
  default. `--duration 10s` explicitly shortens the media-time selection; it is
  not a ten-second wall-clock download timer.
- MPEG-PS is the default and currently supported output. Optional remuxing after
  validation is separate, e.g. `ffmpeg -i sd-clip.ps -c copy sd-clip.mp4`.
- `--lid` supplies the optional native playback label/session selector when
  known. Do not fabricate one or publish credential-bearing native URLs.
- Channel zero is preserved when explicitly selected or reported by VTM resource
  metadata. A packet's VTM channel `0x02` is not camera/lens channel 2.
- `--playback-max-bytes` defaults to 128 MiB and
  `--playback-transfer-timeout` to 60 seconds including key/bootstrap work.
  `--timeout` controls socket inactivity. Bounds must be positive and finite.
- A begin/end range must be ordered, valid UTC and no longer than 24 hours. This
  is a selector bound, not a promise that a 24-hour file fits the default budgets.

## Python

Create/authenticate an `EzvizClient` using the [Python guide](python-api.md).
Then use the convenience API:

```python
result = client.save_clip(
    "CAMERA_SERIAL", "sd-clip.ps", source="cloud-playback",
    cloud_playback_begin_time="20261108T120000Z",
    cloud_playback_end_time="20261108T120020Z",
    channel=1, decrypt_video=True,
)
```

Or group source/transfer settings explicitly:

```python
from pyezvizapi import CloudPlaybackClipSource, ClipOptions, MediaDecodeOptions

result = client.save_clip_with_options(
    "CAMERA_SERIAL", "sd-clip.ps",
    ClipOptions(
        source=CloudPlaybackClipSource(
            "20261108T120000Z", "20261108T120020Z",
            max_bytes=128 * 1024 * 1024, transfer_timeout=60,
        ),
        decode=MediaDecodeOptions(decrypt_video=True, nalu_header_size=None),
        channel=1,
    ),
)
```

Existing live/local capture defaults are unchanged. For SD playback an omitted
capture duration selects the whole range, whereas an explicit ten seconds really
selects ten seconds. `CaptureLimits.max_packets` intentionally permits a partial
sample; inspect `range_complete` instead of calling a packet-capped sample a
whole-range download. `CaptureLimits.max_bytes` can lower the source byte budget.

Lower-level helpers live in `pyezvizapi.streaming.cloud.playback` and are also
lazy root exports: `build_vtm_playback_url`, `get_cloud_playback_stream_info`,
`open_cloud_playback_stream` and `copy_cloud_playback_to_mpegps`.

## Completion and failure semantics

Capture/validation failures do not truncate an existing path or append a prefix
to a caller buffer. Output is published only after validation/decryption; a final
filesystem/write failure is not an atomic rollback. Downloads are bounded in
memory by the configured byte limit; choose smaller limits for constrained hosts.

A clean peer EOF or idle timeout **alone is not completion**. Full-range saves
require a continuous clear PES video-PTS span covering the selected duration
within 5%, capped at one second of frame/startup tolerance. PTS resets or gaps over
one second are ambiguous and fail verification. This is media-span verification,
not proof of exact absolute recording time, every picture being decodable,
frame-exact trim, or physical A/V synchronization. Sparse/event-only recordings
may require selecting an actual continuous record or taking an explicitly partial
packet sample instead of claiming a complete broad time window.

The result includes `begin_time`, effective `end_time`, `bytes`,
`observed_pts_span_seconds`, `range_complete` and `completion_reason`. Empty,
short, malformed, over-budget or unsupported encrypted transport output fails.
A truncated VTM header/body is not treated as clean EOF. No automatic source
fallback, unlimited retries, timestamp repair, preview or camera control occurs.

## Protocol evidence

The SDK's `libezstreamclient.so` contains `/playback?` and the native `begin`,
`end`, `serial`, `lid`, `rnd` and `etp` selector strings. Its exported
`StreamInfoReq::kTimeoutFieldNumber` is **8**: the contributed value `10` is a
server request timeout, not a playback stream-type identifier. Playback uses its
URL mode and known packet channel independently; default live request bytes and
live channel filtering remain unchanged.

Synthetic transport tests cover channel zero, full versus explicitly shortened
ranges, incomplete/empty/truncated input, encrypted packets after clear media,
limits, output preservation and separation from live playback. Actual-device
qualification must additionally decode both video and audio and record the
selected model/source/commit; synthetic PTS coverage is not live playback proof.
