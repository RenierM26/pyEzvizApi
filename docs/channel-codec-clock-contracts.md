# Channel, codec and clock namespaces

These identifiers can have the same integer representation without having the
same meaning. Keep the endpoint/transport namespace with each value; do not run
them through a universal coercion, channel resolver or codec table.

| Namespace | Owner / evidence | Contract |
| --- | --- | --- |
| Preview channel | `ClipOptions.channel`, `select_stream_source` | Explicit source selection; zero and one are distinct and use distinct discovery keys. Do not apply devconfig defaulting. |
| Configuration channel | `feature.resolve_channel`, devconfig APIs | Historical default is one. The integer-zero versus string-zero coercion difference is retained pending endpoint evidence, **not** declared a general zero-based lens convention. |
| Lens / PES stream / descriptor route | IDMX/RTP/PES parsing and consumer qualification | Lens identity comes from evidenced route/stream descriptors. A preview channel, PES byte, SSRC or dynamic RTP payload type is not an interchangeable lens number. |
| SDK configuration codec | `hcnetsdk_parameters` | Field-specific SDK codes (for example video 0 = private H.264, 1 = H.264, 7 = MJPEG). Configuration is not negotiated stream proof. |
| Negotiated PlayM4 codec | `stream_header` | Header-specific codes (for example 1 = H.264, 5 = HEVC). Keep separate from SDK configuration and RTP PT numbers. |
| RTP payload type | `rtp` route descriptors | Dynamic PT identifies a negotiated route; 96/97 alone do not prove a codec or physical lens. |
| Source clock | Native RTP/PES timing and consumer source-clock contract | Preserve genuine source timestamps and their rate/domain. Video RTP/PES commonly uses 90 kHz; audio follows its advertised sample rate. Equal rates do not prove equal epochs. |
| Display/configured cadence | SDK metadata / image-window inspection | Configured FPS and frame counts do not establish wall-clock alignment or physical A/V sync. |

Offline source selection with supplied credentials and cached metadata must not
call cloud/account methods, acquire SDK sockets, register/wake a device or begin
media. A discovery-cache hit is a transport hint, not an authentication or decode
bypass. Negative selection tests install acquisition stubs and separate preview
channels without any actual camera connection.

No runtime integer wrappers or blanket `NewType` conversion are imposed on the
existing public API in this maintenance slice. Narrow types may be introduced
at new boundaries when their unit and provenance can be enforced end to end.
