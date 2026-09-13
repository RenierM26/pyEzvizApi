# Channel-99 push transport (validation preview)

This branch implements the Android channel-99 long-link transport. It still uses
MQTT after an LBS authentication/key-negotiation exchange; it does not use FCM or
require Android/Google services on the receiving Linux machine.

The legacy transport remains selected for existing tokens during validation.
This preview is not yet the default replacement. Short live runs and forced
reconnects work, but sustained stability and all native event variants are not
fully verified.

## Migrating a login

A web-profile session cannot simply be reused with different HTTP headers.
Construct `EzvizClient` with the account credentials and call
`enable_channel99()`. If EZVIZ requires MFA, handle the existing authentication
exception/verification flow and retry with `sms_code`. Do not put passwords or
verification codes in logs.

Persist the complete returned token securely. It contains the Android profile,
stable feature code, user ID and refresh credentials. Subsequent starts can use
`EzvizClient(token=saved_token)` and the existing `login()` refresh method. Save
the resulting token after refresh, too.

Do not copy a phone's feature code or push-device identity. Each independent
installation must use its own persisted identity.

## Receiving events

```python
client = EzvizClient(token=saved_token)

# This is an application-provided synchronous, durable save operation.
# The supplied snapshot contains secrets; store it privately and atomically.
def save_token(snapshot):
    application_token_store.save(snapshot)

push = client.get_mqtt_client(
    on_message_callback=handle_decoded_event,
    on_state_changed=save_token,
)
push.connect()
# ... application continues polling independently ...
push.stop()
```

`connect()` starts a background worker; it does not mean the broker has accepted
the connection. Polling must remain independent of push availability. The
callback payload and `messages_by_device` cache use the existing decoder.

`on_state_changed` is mandatory for channel-99 and receives a deep snapshot of
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
- Cached-key rejection recovery without an HTTPS token change, phone coexistence,
  and extended outage testing remain validation work before default replacement.

No Android binaries, account data, captured live payloads, or research emulator
code are included in the library or its portable tests.
