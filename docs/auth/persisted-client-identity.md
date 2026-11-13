# Persisted installation identities (unreleased)

`EzvizClient(..., feature_code=...)` lets an application choose a stable identity
instead of binding a login to the container's current MAC address. This is an
opt-in API addition; it is not available in the published 2.0.0 release.

## Application ownership

The application must create and durably save its installation identity **before
the first login**, and supply the same value on subsequent starts, MFA retries,
reauthentication and credential restoration. A random `uuid.uuid4().hex` is a
suitable new value. Identity creation must be serialized by the application so
two first-start workers cannot independently register different identities.

The SDK does not choose a filesystem path, read an environment variable or change
module globals. Use the application's normal private, atomic persistent store
(for example, Home Assistant's Store on the persistent configuration volume).
Persist the complete token and push state through `on_token_updated` as before.
The identity is available as the read-only `client.feature_code` property even
before login; it is an installation identifier, not an authentication credential.

```python
from pyezvizapi import EzvizClient

# Loaded from this installation's trusted persistent application store.
identity = saved_installation["feature_code"]

client = EzvizClient(
    account=username,
    password=password,
    feature_code=identity,
    on_token_updated=save_complete_token,
)
client.enable_channel99()  # May require a normal MFA retry.
```

On restoration, select the same identity explicitly:

```python
client = EzvizClient(
    token=saved_token,
    feature_code=saved_installation["feature_code"],
    on_token_updated=save_complete_token,
)
client.login()
```

The names `saved_installation`, `saved_token` and `save_complete_token` above are
application-owned storage, not SDK storage APIs. Never generate a new identity on
every process start. Losing the persistent identity is not repaired by changing
an existing token's `feature_code`.

## Existing installations

The current token format already contains the `feature_code` used for login. An
application that has not registered a separate persistent identity can explicitly
adopt that code from its **trusted** saved token, persist that choice, and pass it
as `feature_code=`. This preserves the credential binding; do not rewrite old
credentials or transplant push state onto an unrelated new identity.

An application with existing accounts registered under different identities can
retain identities per account. Moving them all to one new installation identity
requires fresh authentication for accounts whose token binding differs.

A container recreation with the same persistent identity and saved credentials
no longer depends on the new container MAC. Independent installations should
create independent identities and logins. Do not concurrently run cloned token
and channel-99 replay state in two deployments. Token expiry, revocation and MFA
requirements still apply; a stable identity does not make credentials immortal.

## Validation and compatibility

- Explicit values must be exactly 32 lowercase hexadecimal characters. Malformed
  values raise `PyEzvizError` before allocating client-owned network resources.
- A channel-99 token must match the **selected** identity. Mismatches still raise
  `EzvizAuthTokenExpired`; the SDK does not relabel credentials or erase push state.
- Omitting the argument preserves the historical MAC-based behavior, including
  rejection of saved channel-99 credentials from another host. Tokens never
  implicitly override the caller's identity selection.
- HTTP profile headers, login/refresh payloads, prepared requests, session
  recreation, push registration/subserials, CAS signatures and identity-bound
  device payloads use the selected identity. Immutable profile defaults and the
  exported legacy `FEATURE_CODE` constant are not changed.
- SDK-owned MQTT/CAS clients inherit non-default identities. Direct users of
  `MQTTClient` or `EzvizCAS` must pass the matching `feature_code=` too. Legacy
  child-factory call shapes are retained when the selected code is the default.
- This PR does not opt the CLI or Home Assistant into persisted identities, bump
  their dependency requirements, publish a release, or change the token format.
  Those consumers must deliberately adopt this API after a compatible SDK release.

## Qualification

Offline controls use synthetic accounts and captured real request preparation,
not live EZVIZ calls. They cover explicit/malformed/mismatched selection, default
compatibility, login/MFA/refresh, independent clients, recreated HTTP transports,
push registration/refresh and stale attempts, CAS framing, device payloads and
atomic token restoration in fresh Python processes with different MAC identities.
Physical devices, live cloud acceptance and actual container restart/soak remain
separate integration qualification work.
