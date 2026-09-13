# Channel-99 push transport and migration

This branch implements the Android channel-99 long-link transport. It still uses
MQTT after an LBS authentication/key-negotiation exchange; it does not use FCM or
require Android/Google services on the receiving Linux machine.

The obsolete HTTP-registration push transport has been removed. This is a
migration, not a drop-in change for existing Home Assistant storage code.
Unmigrated tokens fail with a migration instruction; they are never sent to the
old registration endpoint. Existing polling/API operations remain available.

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
stable feature code, user ID and refresh credentials. Subsequent starts can use
`EzvizClient(token=saved_token)` and the existing `login()` refresh method. Save
the resulting token after refresh, too.

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

Keep the existing host-based calculation: `FEATURE_CODE` is the MD5 of the
colon-separated MAC address returned by `uuid.getnode()`. Channel-99 does not
introduce a random UUID, a separate installation ID, or another identity file.
Clients on the same host can share this feature code; per-installation uniqueness
is not required.

Always use `FEATURE_CODE` for login, refresh, push and CAS. Values stored in a
token never override it. The existing `feature_code` token field is only a marker
of the host identity used at login.

If a saved channel-99 token's marker is missing or differs from `FEATURE_CODE`,
the client raises `EzvizAuthTokenExpired` before using those credentials. Create
a fresh client with account credentials and no old token, call
`enable_channel99()` (including MFA if required), and replace the saved token.
Old push-device keys must not be reused with a changed host identity. This means
a container MAC change requires reauthentication; no UUID or fallback identity
is introduced.

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
callback payload and `messages_by_device` cache use the existing decoder.

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
- Direct notification acknowledgements are QoS 0. A local send is not proof the
  server processed the acknowledgement; there is no PUBACK for QoS 0.
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
