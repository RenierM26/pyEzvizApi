# CodeQL triage — 2026-11-08

Reviewed against merged library `7ffec8d` (PR #414). The 16 open alerts
are dispositioned individually, **not fixed by replacing camera wire algorithms**.
No query, path, severity, workflow or quality gate is disabled. GitHub alert
state is authoritative; inline `codeql`/`lgtm` comments do not close these alerts.

## Alert ledger

Numbers link to this repository's Security → Code scanning alerts.

| Alerts | Disposition | Evidence and reason |
| --- | --- | --- |
| [2880](https://github.com/RenierM26/pyEzvizApi/security/code-scanning/2880) | False positive (exposure) | `fresh_local_sdk_receiver_port` briefly binds IPv4 wildcard **without listen/connect**, then closes. It must match the external SDK's bind scope. `tests/streaming/test_stream_selection.py::test_fresh_sdk_port_matches_wildcard_scope_without_listening` fails if listen/connect is attempted and verifies closure. This does not excuse any future listener. |
| [1502](https://github.com/RenierM26/pyEzvizApi/security/code-scanning/1502), [1503](https://github.com/RenierM26/pyEzvizApi/security/code-scanning/1503), [1504](https://github.com/RenierM26/pyEzvizApi/security/code-scanning/1504), [1505](https://github.com/RenierM26/pyEzvizApi/security/code-scanning/1505) | False positive (intentional ownership boundaries) | Native worker/cleanup catches preserve the primary failure, retain cleanup failures, publish completion and release ownership. Narrowing to `Exception` loses cancellation/process-control failures. `tests/streaming/test_native_stream.py` tests KeyboardInterrupt, SystemExit, GeneratorExit, CancelledError, a custom BaseException, primary+cleanup failures, interrupted reads and iterator construction. They are not general application-level blanket catches. |
| [425](https://github.com/RenierM26/pyEzvizApi/security/code-scanning/425) | Won't fix — protocol limitation | AES-ECB unwraps the camera's 32-byte ECDH session key. Input/key lengths are checked; replacing ECB locally cannot interoperate. Synthetic handshake/session tests in `tests/streaming/local/test_local_stream_ecdh.py` verify this wire contract and authenticated decoding. |
| [428](https://github.com/RenierM26/pyEzvizApi/security/code-scanning/428), [429](https://github.com/RenierM26/pyEzvizApi/security/code-scanning/429), [430](https://github.com/RenierM26/pyEzvizApi/security/code-scanning/430), [431](https://github.com/RenierM26/pyEzvizApi/security/code-scanning/431), [432](https://github.com/RenierM26/pyEzvizApi/security/code-scanning/432), [2879](https://github.com/RenierM26/pyEzvizApi/security/code-scanning/2879) | Won't fix — protocol limitation | AES-ECB decodes the vendor's encrypted media blocks/prefixes, including IDMX AAC. Existing known-byte, chunk-boundary and malformed-input controls in `tests/streaming/media/` and stream conformance tests enforce the format. This is not an endorsement of ECB for new encryption or proof of media authenticity. |
| [422](https://github.com/RenierM26/pyEzvizApi/security/code-scanning/422) | Won't fix — protocol limitation | Channel-99 shared-key derivation uses the vendor's exact MD5 chain. `tests/fixtures/longlink_native.json` and `tests/push/test_longlink*.py` compare synthetic native-reference outputs. A different hash/KDF cannot interoperate. TLS/HMAC do not make the derivation cryptographically modern. |
| [423](https://github.com/RenierM26/pyEzvizApi/security/code-scanning/423) | Won't fix — protocol limitation | Legacy RTSP Digest MD5 (RFC 2069), not a stored-password hash. RTSP auth tests verify challenge/response and bounded socket ownership. A local KDF replacement would break authentication; this does not claim plaintext RTSP is confidential. |
| [424](https://github.com/RenierM26/pyEzvizApi/security/code-scanning/424), [434](https://github.com/RenierM26/pyEzvizApi/security/code-scanning/434) | Used in tests | Synthetic HCNetSDK password derivation and ECDH encryption fixture generation; no account password/key or production password storage. These deliberately reproduce the legacy camera protocol. |

## Scope and reconsideration

Nine runtime crypto findings are accepted interoperability constraints, not false
positives or repaired vulnerabilities. Two additional crypto findings are test
fixtures. Five findings concern deliberate non-exposure/exception boundaries.
Reopen the corresponding alert if a supported modern wire protocol becomes
available, these helpers become general-purpose crypto, the reservation begins
listening, or cleanup stops propagating/recording errors. New unrelated findings
remain actionable; do not dismiss future alerts by rule name alone.


## SD helper extraction (PR #419)

Alert [2882](https://github.com/RenierM26/pyEzvizApi/security/code-scanning/2882)
is the relocated IDMX AAC decrypt call from accepted alert 2879, now in
`streaming/media/crypto.py::decrypt_aac_access_unit`. The body is AST-identical
apart from its name; no key, cipher, mode or transform changed. Apply the same
previously accepted **won't fix — vendor protocol limitation** disposition, not
a false-positive or security-fix claim. The new SD caller uses that same native
block format. Known-byte AAC controls and retained recording wheel decoding
verify interoperability; neither authenticates ciphertext nor modernizes ECB.
