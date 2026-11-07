# HCNetSDK responsibilities

| Location | Responsibility |
| --- | --- |
| `api.py`, `requests.py`, `authentication.py`, `configuration.py`, `discovery.py` | Public compatibility, transport/session ownership and operation families |
| `protocol.py` | Compatibility composition of pure protocol exports |
| `protocol_types/values.py`, `endpoints.py` | Field validation and endpoint values |
| `protocol_types/configuration.py`, `sdk_requests.py` | Configuration, capability and shared request values |
| `protocol_types/framing.py`, `wire_crypto.py` | Pure wire codecs; existing proprietary algorithms unchanged |
| `protocol_types/playback.py`, `preview.py`, `preview_bootstrap.py` | Playback and local-preview values and serialization |
| `protocol_types/controls.py`, `discovery.py` | Control and discovery request values, not network execution |

Protocol leaves have an acyclic dependency graph and never import `api.py` or
`protocol.py` back. The original flat public modules and named private helpers
retain their compatibility aliases; redundant interim facades are removed.
Mutable operational hooks still use explicit owner context; pure value
definitions do not need that owner.
