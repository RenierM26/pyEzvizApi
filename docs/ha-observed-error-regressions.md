# Regression controls from Home Assistant logs

A read-only HA log investigation on 2026-11-07 found recurring
`Load_device_failed: ... code=load_error msg=` warnings, alarm-status polling
failures caused by `requests.ConnectionError`, and separate integration warnings.
Raw logs and identifiers are private; tests contain synthetic inputs only.

## Library fix

Device status assembly catches errors per camera/light/plug, preserving the
existing partial-load behavior and cached states. Previously an exception
without a message (for example `HTTPError()`) produced an empty `msg=`, hiding
what failed. Conversely, exceptions with messages could dump raw values.

The warning now reports the status-factory stage and exception class. It keeps
the existing serial and error-code fields but never interpolates exception text.
This improves diagnosis; it does **not** identify the historical empty warning's
exception class retrospectively or cure the underlying cloud failure.

## Network failure contract

Offline tests inject the observed connection-reset pattern at the requests
session boundary. They establish that:

- A failed group-defence GET is surfaced, not silently reported successful.
- A transport reset does not trigger reauthentication or implicit retries.
- A subsequent explicit poll can recover using the same client.
- An unlock PUT is sent only once after a reset: the server may have applied it
  before the connection failed, so automatic replay is unsafe.

These transport controls pass on the baseline. The six diagnostic/redaction
cases failed before the logging change and pass after it. No blanket retry or
public exception-type changes are introduced.

## Separate Home Assistant integration findings

The observed consumer is `custom_components.ezviz_cloud`, whose manifest pins
`pyezvizapi==1.0.5.0`, not the currently merged source tree. Its alarm entity
only catches `PyEzvizError` in `update`, while Requests connection errors are a
different exception family. Expected transport failures should be handled at
the consumer boundary with explicit unavailable/recovery semantics; this change
does not deploy or modify that consumer.

A missing API encryption hash is logged as a changed encryption key; absence
is not evidence of a change. Also, MQTT device lookup still uses deprecated
`device_registry.async_get_device`, which the HA warning says will stop working
in 2027.8. These are integration follow-ups, not pyEzvizApi parser defects.
Missing RTSP passwords and an image HTTP 500 are not sufficient evidence for a
library code fix. No missing credentials were guessed or changed.
