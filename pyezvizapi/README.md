# Finding library code

Start with [the code map](../docs/code-map.md).

| Directory | Responsibility |
| --- | --- |
| `cloud/` | Authentication, HTTP, pagination and client operation families |
| `devices/` | Camera, lighting, plugs, features and status factories |
| `push/` | MQTT and channel-99 long-link sessions |
| `streaming/` | Local/cloud transports, capture and media processing |
| `cli/` | Argument schema, command handlers and executable entry points |
| `_shared/` | Narrow shared conversion, time, crypto and DNS helpers |

Only `feature`, `mqtt`, `utils` and `test_cam_rtsp` retain HA-required legacy exports.
Do not add new implementations to those aliases. `client.py` remains the public
client boundary, and `__init__.py` retains lazy package-level exports.
