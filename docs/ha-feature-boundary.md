# Reusable device controls for application consumers

These public modules have no Home Assistant dependency:

- `pyezvizapi.devices.audio`: chime (`alarm_volume_getter`, `alarm_volume_max`,
  `set_alarm_volume`), alarm voice (`alarm_voice_volume_getter`,
  `set_alarm_voice_volume`) and microphone (`microphone_volume_getter`,
  `set_microphone_volume`) rules. Setters take `(client, serial, value, camera_data)`.
  Call them with the latest reported device snapshot, serialized with refreshes
  and other commands. They are synchronous; async consumers must use a worker.
- `pyezvizapi.devices.controls`: `SupportExtView`, feature readers, intelligent-app
  helpers, linked-tracking commands and `set_port_security_ports(client, serial,
  ports, enable)`. The latter fetches fresh port configuration, preserves reported
  fields and changes only requested port enable flags. Cached fallback and empty
  payload synthesis retain the prior HA behavior when the server returns no usable
  configuration. Transport errors propagate rather than becoming successful writes.
- `pyezvizapi.devices.images`: `process_image_bytes`, `extract_jpeg_segments` and
  `split_composite_image`. Install `pyezvizapi[images]` for Pillow. Processing is
  synchronous/CPU-bound. It does not fetch URLs, cache credentials or own entities.

Audio keeps app-backed capability/range rules: DBScreen chime is 0–7, other chime
sliders 0–100; voice writes accept 10–100 and a reported zero remains readable.
Microphone writes now retain **all** reported sibling fields, including unknown
vendor extensions, and never invent a missing speaker-volume setting. Missing
microphone configuration and non-finite writes raise `PyEzvizError` before I/O.
This is an intentional correction to HA's former two-field/default-100 payload.

Images retain no-password passthrough, concatenated JPEG selection, vertically
stacked lens splitting and undecodable-image passthrough. Unlike HA's old module,
the SDK does not set Pillow's process-global truncated-image flag. Undecodable
composites return their original bytes rather than changing global decoder policy.

Applications continue to own executor selection, lifecycle, command serialization,
refresh/caching policy, entity IDs, config flows, translations and persistence.
The helpers do not perform live validation or imply new model discovery support.
