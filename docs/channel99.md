# Channel-99 push transport and migration

The current library implements the Android channel-99 long-link transport. It still uses
MQTT after an LBS authentication/key-negotiation exchange; it does not use FCM or
require Android/Google services on the receiving Linux machine.

The obsolete HTTP-registration push transport has been removed. This is a
migration, not a drop-in change for existing Home Assistant storage code.
Unmigrated tokens fail with a migration instruction; they are never sent to the
old registration endpoint. Existing polling/API operations remain available.

The pinned `ha-ezviz` consumer has not implemented these prerequisites; see
[HA consumer status](home-assistant.md). CLI migration does not migrate HA storage.

## Migrating a login

A web-profile session cannot simply be reused with different HTTP headers.
Construct `EzvizClient` with the account credentials and call
`enable_channel99()`. If EZVIZ requires MFA, handle the existing authentication
exception/verification flow and retry with `sms_code`. Do not put passwords or
verification codes in logs.

Provide `on_token_updated=save_token` when constructing `EzvizClient`. This
synchronous callback saves rotated credentials **before** subsequent service
discovery, so a discovery outage cannot lose a successful token refresh.

Persist the complete returned token securely. It contains the Android profile,
stable feature code, user ID, and refresh credentials. On subsequent starts,
pass the saved token and the same durable callback to `EzvizClient`, then call
`login()` to refresh. If you configured an explicit installation identity, pass
that same identity when restoring the token.

### CLI storage and reuse

The `mqtt` command installs durable storage before login and migrates directly
with `enable_channel99()`, prompting for MFA when required. Its default token
file is `ezviz_token.json`, used for both loading and saving. All CLI token
writes use atomic owner-only files; a write failure stops the operation.
Other CLI commands also persist credential rotation when loading a channel-99
token, even without `--save-token`.

`export_token()` returns a deep snapshot, so changing nested push state in the
export does not change the live client. Resetting the HTTP session with
`close_session()` retains the Android profile for subsequent login/refresh.

### Feature-code identity

By default the SDK uses the legacy MAC-derived `FEATURE_CODE`. Python
applications can select a [persisted installation identity](auth/persisted-client-identity.md)
with `EzvizClient(..., feature_code=...)`. Login, refresh, push, and CAS use the
selected identity. The SDK does not silently adopt the identity from a token.

A missing or mismatched identity marker on a channel-99 token raises
`EzvizAuthTokenExpired`. Restore the identity originally selected for that
installation, or start a fresh login and channel-99 migration under the intended
identity. Do not copy push keys or relabel old credentials.

Login and its factory-created push client share a credential lock: token
mutation, snapshot creation and persistence are serialized. The handshake keeps
its working state separate until it is committed through the saver. Do not
create independent clients sharing the same mutable token/storage without
providing equivalent external coordination.

## Background failures and recovery

Call `push.raise_if_failed()` periodically while listening (the bundled CLI
listeners do this). Storage callback failures stop the worker permanently with
`EzvizTokenPersistenceError`, a subclass of `EzvizPushFatalError`; incomplete
first-device creation and unrecoverable authentication also stop with a fatal
error. These failures are logged without credential-bearing exception details.
Fix storage or reauthenticate/recover the saved state before constructing a new
push client. A failed worker cannot silently be restarted, and `stop()` still
cleans up normally. In Home Assistant, check this method from the integration's
health/update path and surface the failure; do not block the event loop.

A rejected push registration (HTTP or metadata 401/403) attempts one HTTPS
refresh through an isolated client, durably saves the rotated token, and retries
registration. This works for push-only clients without polling. Rejected refresh
credentials require reauthentication rather than endless reconnect attempts.
Transient network failures retain the normal reconnect behavior.

## Receiving events

```python
# This is an application-provided synchronous, durable save operation.
# The supplied snapshot contains secrets; store it privately and atomically.
def save_token(snapshot):
    application_token_store.save(snapshot)

client = EzvizClient(token=saved_token, on_token_updated=save_token)
push = client.get_mqtt_client(on_message_callback=handle_decoded_event)
push.connect()
# ... application continues polling independently ...
push.stop()
```

`connect()` starts a background worker; it does not mean the broker has accepted
the connection. Polling must remain independent of push availability. The
callback payload and `messages_by_device` cache use the notification decoder
described below.

`on_token_updated` is the single persistence callback. Set it on `EzvizClient`;
`get_mqtt_client()` passes it to the push transport automatically. When constructing
`MQTTClient` directly, supply the same callback name there. It is mandatory for
push reception and receives a deep snapshot of
the **whole token**, not just push fields. It runs on the worker thread and must
not return until storage succeeds. In Home Assistant, marshal storage work onto
the event loop and wait for completion from the worker; never block HA's event
loop waiting on that same worker. Login-time token saving alone is insufficient:
new push keys arrive after login.

A failed save aborts connection establishment. An interrupted first-device
creation is not automatically repeated because the server may already have
allocated an identity. Preserve the pending state for recovery.

## Lifecycle and current limits

- Reconnects negotiate a fresh session key through LBS, rather than reconnecting
  Paho with a stale session key.
- HTTPS token rotation triggers existing-device authentication, retaining the
  saved push-device ID.
- Direct JSON notifications (domain 9000, command 1) are delivered without an
  application reply. Live testing found that publishing the native-style XML
  reply to `/9000/2` causes an immediate broker disconnect. Paho still handles
  MQTT-level acknowledgements according to the incoming message QoS.
- Native binary-message acknowledgement helpers remain experimental; their live
  broker behavior is not validated by the direct JSON notification tests.
- `stop()` interrupts active socket reads and retry waits. Pending DNS/HTTP/TCP
  establishment can exceed the five-second join deadline; in that case it raises
  `TimeoutError` while cancellation remains signalled. Outside its own callback thread, it does not report successful shutdown
  while its worker is known to be running. DNS timing is OS-dependent.
- Callbacks run on the worker thread. Calling `stop()` from the message callback
  does not join its own thread.
- Binary mobile event variants are understood at the framing level but not yet
  exposed through the legacy decoded notification interface.
- Server status10 (invalid master key) clears only that key, persists the recovery
  state, and reauthenticates the existing device on the next connection. Other
  errors do not trigger this fallback.
- Phone coexistence and extended outage testing remain release-validation work.

No Android binaries, account data, captured live payloads, or research emulator
code are included in the library or its portable tests.

## Implementation boundaries

- `cloud/auth.py` owns the shared HTTPS refresh operation. Both public login and
  background push use it; MQTT does not instantiate another `EzvizClient`.
  Callers keep ownership of the credential lock, durable-save callback and
  HTTP transport. Background requests copy mutable request state but borrow
  the caller's adapters, preserving proxy/certificate/TLS configuration.
- `cloud/token.py` contains the persisted token schema and boundary validators.
  Historical `ClientToken`, `EzvizToken` and `ServiceUrls` imports remain
  available. Partial login tokens still require runtime validation before push.
- `push/longlink/codec.py` implements only EZVIZ wire encoding and cryptography. PKCS#7
  padding uses `cryptography`; the fixed IV and native key derivation remain
  protocol requirements, verified against synthetic native vectors.
- `push/paho.py` isolates Paho 2.x's private runtime keepalive field. There is no
  public setter; a compatibility test verifies actual ping scheduling. Paho
  automatic reconnect is intentionally not used because each reconnect must
  first negotiate fresh EZVIZ keys through LBS.

These internal refactors do not change public callbacks, token file format,
lifecycle, or direct-event delivery behavior.


### Migration and persistence ordering

`enable_channel99()` holds the shared credential lock through migration and
login, including MFA requests. Exports, factory creation, polling and logout
cannot observe a partially installed profile. If MFA or login fails, no legacy
session header, discovery or push identity is retained under the Android profile.

Push state is staged in a detached snapshot and published to the live token only
after the persistence callback succeeds. Failure before AUTH-III allocation leaves
fresh in-memory state retryable after storage repair. Once the pending-creation
marker is committed, failure to save returned device keys leaves that marker in
place: automatic retries must not allocate another device. This differs from
HTTPS token rotation, where the server has already rotated the credentials and
the new credentials must remain in memory even if their save fails.

### Broker setup failures

The worker surfaces permanent MQTT CONNACK refusals (invalid identity,
credentials, authorization or protocol negotiation) through `raise_if_failed()`.
An explicit SUBACK refusal of the single event topic is also fatal: MQTT 3.1.1
provides no more specific reason for that refusal. Callers should inspect account
permissions/configuration rather than silently retrying the same subscription.
Server-unavailable responses and transport failures remain retryable. Missing
CONNACK/SUBACK responses time out after 30 seconds of broker setup and retry with
fresh LBS credentials. Only a matching successful SUBACK marks the session ready;
late callbacks during shutdown cannot restore readiness or deliver messages.
Numeric broker reasons are retained for diagnostics, and transport cleanup errors
cannot replace an already-recorded permanent refusal.

## Notification decoding

`push.notifications` is a pure, credential-free decoder. The historical
`MQTTClient.decode_mqtt_message` method delegates to it; decoding no longer stops
the connection on a malformed notification. Invalid JSON, UTF-8 and non-object
roots raise a safe `PyEzvizError`; the payload handler discards that notification
without shutting down the worker. Framing/broker failures retain their own
transport recovery policy.

The retained Android 7.4.1 push parser distinguishes these ext layouts:

| ext format | Decoding |
| --- | --- |
| CSV family 1 | Existing alarm fields, plus customerType from slot 8 and subType from slot 19 (zero-based) |
| CSV family 14 | Calling time/serial/channel, calling_type, calling_id, calling_status, image/crypt/checksum and optional analysis/custom fields |
| JSON object or JSON-encoded object | Retained as an object; control x-type values are not translated into alarms |
| Other CSV family | channel_type and opaque raw_fields; no invented camera-alarm identity/code |

Existing family-1 field aliases `resource_type` and `sequence_number` and the
`EXT_FIELD_NAMES` tuple remain available. Their historical names do **not**
establish their protocol meaning. The new aliases allow
`normalize_intercom_event` to retain qualified unlock methods and ring subtypes.
Call IDs are not alarm message IDs, and call type/status are not alarm codes.
Family-14 notifications reach callbacks/cache but do not automatically produce a
ring event or imply supported answer/hangup controls. Unknown call status values
remain numeric and uninterpreted. Unknown CSV layouts intentionally no longer
receive the incorrect family-1 schema.

Offline synthetic encrypted `/9000/1` frames exercise framing, decryption,
notification decoding, cache, callback and intercom normalization together. They
also verify that direct notifications publish no application reply. These tests
are **not** a live HP7 ring/unlock delivery test. The LBS handshake, feature-code
identity, credential persistence, subscriptions and acknowledgement policy are
unchanged. Native binary mobile messages are still framing-only and are not
exposed by the decoded notification interface; their event semantics require
separate evidence before implementation.
