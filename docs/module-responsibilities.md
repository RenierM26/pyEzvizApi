# Implementation responsibilities after the maintenance extraction

| Responsibility | Implementation | Compatibility boundary |
| --- | --- | --- |
| Tolerant conversion, mapping traversal, alarms/time, image envelope | `_coercion`, `_mapping`, `_alarm_time`, `_image_crypto` | Public `utils` helper imports remain the implementation objects; private image calls retain named compatibility wrappers. |
| JSON objects, API codes and credential-safe descriptions | `_api_response` | `EzvizClient` keeps its private static parsing hooks and owns endpoint decisions. |
| Pagelist accumulation/progress | `_pagelist` | Client owns requests, re-login and token persistence. |
| Scoped HTTP scheduling/body ownership | `_budget_http`, `_http_transport` | No new ordinary-request worker or adapter-pool ownership. |
| SDK value models, requests, pure serialization | `_hcnetsdk_protocol` | Public `hcnetsdk` objects remain aliases; network clients retain socket/Windows binding ownership. |
| Pure local packet parsing/window metadata | `_local_stream_packets` | Existing local-stream aliases remain. Hook-dependent routing/capture helpers stay at the old boundary. |
| Declarative command builders | `_cli_arguments` | `_parse_args` and duration helper imports stay available through `__main__`; handlers still own authentication and output. |
| Small device sections | `_device_payload` | Camera, light and plug wrappers keep status keys, state, feature overrides and control behavior; no new base class. |
| Shared DNS scheduling/lifetime | `_resolver` | HCNetSDK translates deadline/busy errors into its existing categories; ordinary unbounded resolution stays synchronous. |
| RTSP credential probe | `rtsp_auth` | `test_cam_rtsp` remains an identity-preserving compatibility shim. |

This is an incremental decomposition, not a claim that all four large modules
have disappeared. Capture/remux ownership and legacy monkeypatch hooks are not
moved merely for a smaller line count. In particular, a trial local-packet move
broke the mixed-source-clock rejection probe because it bypassed patched legacy
routing helpers; those helpers were retained. The regression stays unchanged.
Further transport/handler separation must use explicit dependency boundaries and
repeat the existing cancellation, source-clock, offline-policy and import tests.
No module-forwarding magic or replacement media implementation is introduced.

## Resolver ownership

The default resolver is one lazy shared service: at most one active platform
resolution and one queued job. Timed-out queued requests do not execute, and idle
workers exit. An owned `BoundedResolver` can be injected at the internal DNS
boundary for benches/tests. Its bounded `close(wait_seconds=...)` cancels waiting
callers and queued work, then reports whether the worker actually exited. It
cannot kill a stuck system `getaddrinfo`; `False` is not treated as successful
shutdown and no replacement worker is started for that stuck owner. The caller
owns a resolver it creates; it must not close the process-wide default on behalf
of another camera. Unscoped `timeout=None` resolution remains synchronous on its
caller and is not an asynchronously owned worker job.
