# Camera channels and multi-lens applications

This is an **unreleased additive API**, planned for SDK 2.6.0. No publication,
device-control test or Home Assistant deployment is implied by this change.

## Immutable inventory, no implicit I/O

`pyezvizapi.devices.channels.camera_channels(data)` and `CameraState.channels`
return frozen `CameraChannel` values from reported Video resources. A channel's
`key` contains its resource identifier and local index; it survives list
reordering and does not renumber when another lens disappears. A channel count
alone does not manufacture resources. Malformed or conflicting metadata discovers
no channels; `resolve_camera_channel(data, key)` raises a structured
`CameraChannelError` if a command target is not currently unambiguous.

These APIs have no Home Assistant dependency, Pillow import, session, task, poll,
retry, state overlay or network side effect. Applications retain their existing
account/session and worker lifetime ownership. Shared device settings remain
shared unless their individual protocol contract establishes channel scope.

## Command routing

`point_ptz_route(data, lens="auto", channel_key=None)` owns the app-backed
support586 direct `Video_1/1` versus support724 selected-resource contract.
Explicit channel targets reject a conflicting legacy lens choice. Capability
flags are device hints, not a guarantee that every physical lens can move.
Errors expose a finite `reason`, without raw device data or URLs, so applications
can translate them rather than parsing vendor error messages.

`capture_channel_number(data, channel_key)` preserves the legacy capture default
or resolves an explicit target. `CameraChannel.channel_no` exposes the reported
local index for the existing
`capture_picture(serial, channel)` API. It is not an RTSP channel formula.
`validate_channel_rtsp_path` accepts explicitly configured absolute paths, not
complete URLs/credentials/host overrides. No stream path is inferred from a
resource name, array position or count. Fixed/moving and upper/lower lens labels
are deliberately not guessed.

## Images and notifications

The optional `devices.images.process_channel_images` API decodes one payload
once and returns bytes keyed by stable channel identity. Channel-indexed image
records are matched by their explicit IDs, independent of record order.
Missing channels are omitted, never replaced with the last available image.
An unindexed multi-lens image is not assigned by guessing. A sole unindexed
image can be assigned to an explicitly known source channel (a targeted capture
or channel-tagged notification), or a camera's sole reported channel.
The older positional/stacked `process_image_bytes` API is unchanged for existing
applications; its compatibility behavior is not evidence of independent feeds.

`camera_channel_notification(data, decoded_notification)` normalizes only
explicitly reported alarm channels. Missing/foreign channels remain unknown;
call/control notifications are not relabeled as camera alarms.
`alarm_camera_channel` applies the same explicit-channel rule to normalized
alarm history, without assigning unknown-channel history to every lens. A normalized
notification represents receipt, not inferred persistent motion, recording or detection
state. Signed image URLs are excluded from its repr. Applications own bounded
deduplication and event delivery, not another SDK background consumer.

## Provenance and limits

Retained Android 7.4.1.0421 / code1676: `PlayDataInfo.getPlayChannelNo`,
`getLocalIndex`, `getLocalIndexNew`, and `ResourceInfoMgr.getResourceInfo` resolve
selected play channels through the reported local index/resource repository.
The earlier point-action verification established the distinct direct586 and
selected724 routes. Existing image-envelope fixtures establish explicit image
record channel IDs. No latest-app, iOS, physical lens mapping, independent RTSP
feed, per-lens setting or universal model/firmware support is claimed.

All new regressions use synthetic metadata, JPEGs and protocol envelopes offline.
Model-specific stream/capture/physical-movement qualification remains separate.
