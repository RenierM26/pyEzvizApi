# Authentication, MFA and login recovery

This guide tracks **unreleased main**, including the follow-up to PR #450.
Refresh-token behavior, feature-code identity and token persistence contracts
are unchanged. See [persisted client identity](persisted-client-identity.md).

## Password login and compatibility

The default password path fetches the region's X.509 RSA key at
`GET /v3/users/publickey` and posts PKCS#1 v1.5 encrypted `MD5(password),epoch`
to `/v3/users/login/v6`. Only ASCII space, tab, CR and LF are removed from key
Base64 before strict decoding; a non-RSA/invalid key still fails.

**A key-fetch timeout, HTTP failure or invalid key stops the attempt.** No
credential request is sent and no v5 fallback can mask the failure as a wrong
password. Transport exceptions retain their existing requests/HTTP error types;
key-content errors remain `PyEzvizError`. Do not replace working credentials on
these failures. For a region **independently known** to require v5, explicitly
construct `EzvizClient(account, password, login_api="v5")`; this skips key fetch.
There is no automatic API-version discovery or downgrade. The app uses regional
rollout configuration, not key availability, to select its old API.

Regional `1100` redirects refetch the new region's key and preserve verification
fields, with at most two redirects per password attempt. Codes, credentials,
key rejection and lockouts are not automatically retried. Raw `1226` indicates
incorrect account/password; it does not identify why a server rejected them.

## MFA challenge, request, submission and resend

`login` and `enable_channel99` accept these keyword-only options:

- `mfa_channel=1` for SMS or `3` for email. Omission uses the selected channel
  on this client, initially email for backwards compatibility. No inference
  from whether the login username looks like an email or phone number.
- `mfa_account="BOUND_CONTACT"` explicitly selects a bound delivery contact,
  not a different login account. Otherwise use the selected `loginUser` or
  `contactExt` phone/email reported by the server. Masked/missing contacts are
  not substituted with the original login account when metadata is present.
- `request_mfa=False` suppresses the historical initial automatic code request.

`login(sms_code="001234")` preserves zeros. Legacy integer callers still work,
but lost zeros cannot be reconstructed; no padding is guessed. `"000000"` and
integer `0` are submitted, not mistaken for an absent code. Empty, non-ASCII,
boolean and non-digit codes fail before network access. SMS/email are the only
implemented channels; voice, third-party and security-contact flows are not
silently mapped to email/SMS.

A `6002` challenge raises `EzvizAuthVerificationCode`. Without a supplied code,
the default behavior requests one **once** when a usable contact is available.
Further challenges do not automatically resend. With a supplied code, a `6002`
response **never sends another code**. `1011`/`1012` distinguish incorrect and
expired codes and do not trigger delivery. Callers decide whether to retry or
explicitly resend, respecting rate/attempt limits.

```python
from pyezvizapi.client import EzvizClient
from pyezvizapi.exceptions import EzvizAuthVerificationCode

client = EzvizClient("YOUR_USERNAME", "YOUR_PASSWORD")
try:
    client.login(mfa_channel=1, request_mfa=False)
except EzvizAuthVerificationCode as challenge:
    # Inspect challenge.reason and challenge.available_channels first.
    # For a supported SMS contact, request only after the user chooses it:
    client.send_mfa_code(mfa_channel=1, mfa_account="BOUND_PHONE")
    client.login(sms_code="001234", mfa_channel=1)
```

The example performs real authentication/delivery if run with real credentials.
It is not a validation script or an automatic retry recipe. Security verification
must instead be completed in the app.

`send_mfa_code(...)` is an **explicit request/resend**, even if one was already
requested. It uses `from=selected_contact`, `bizType=TERMINAL_BIND`, without
401 re-login recursion. A successful response confirms request acceptance, not
physical delivery. When a legacy challenge includes **no** contact metadata,
the old default-email `from=login_account` request remains for compatibility;
SMS needs a returned phone or an explicit `mfa_account`. No timers, backoff
values or supported-channel policy are invented from the presence of contacts.

Contacts and caller-selected recipients are ephemeral client state, omitted
from repr, errors and exported tokens; they are cleared after successful login.
The selected channel stays on that client, but is not persisted in tokens.
When constructing a new client, select it again. `available_channels` on a
challenge reports available contact fields, not a server guarantee of support.
`code_sent` means a request succeeded, not that a message was received.

## Stable error categories

`EzvizLoginError` subclasses `PyEzvizError`; existing broad exception handlers
continue to work. Read its `reason`, `code` and optional `lock_minutes` instead
of parsing messages. `EzvizAuthVerificationCode` remains catch-compatible and
adds these attributes plus `code_sent` and `available_channels`. Incorrect and
expired code errors now also use this verification subtype. Callers must inspect
`reason` before deciding to display an MFA form or request a code.

| Raw cloud code | Stable reason | Caller action |
| --- | --- | --- |
| `1013`, `1014`, `1226` | `incorrect_username`, `incorrect_password`, `incorrect_credentials` | Review credentials; no blind retry |
| `6002` | `verification_required` | Select contact, request if needed, submit code |
| `1011`, `1012` | `verification_incorrect`, `verification_expired` | Correct code or explicitly request another |
| `1041`, `1006`, `1026` | `verification_rate_limited` | Wait; no invented retry-after duration |
| `1043` | `verification_attempts_exceeded` | Stop retrying SMS verification |
| `1407` | `clock_incorrect` | Correct host system time |
| `1402` | `public_key_refresh_required` | Explicit retry fetches a fresh key |
| `1400` | `account_locked` | Wait; use validated `lock_minutes` when present |
| `1015` | `captcha_required` | Complete image/CAPTCHA recovery in the app |
| `1069` | `terminal_limit` | Manage registered terminals in the app |
| `1102` | `region_selection_required` | Complete account-region selection in the app |

A security-bound/verification-token contact challenge is surfaced as
`security_verification_required`; the legacy checkcode endpoint is not used for
that unsupported flow. Missing selected contacts produce an unsent challenge
or `verification_contact_required` from an explicit request. Unknown codes use
`login_failed`. Server messages, temporary/access tokens and contact values are
not copied into exceptions. Lock minutes must be a positive signed-32-bit JSON
integer; malformed/string/boolean values are ignored, not guessed.

### Home Assistant boundary

This is an SDK change, not a HA config-flow rewrite or dependency release.
Existing consumers catching `PyEzvizError` still work, but need to use `reason`
to display clock/CAPTCHA/terminal/region recovery instead of generic auth errors.
Consumers must keep MFA input as text; a consumer that converts it to an integer
will still lose zeros before calling this library. Selected channels must be
passed explicitly by the consumer. No production HA installation is upgraded.

## App evidence and qualification limits

Static reference: retained EZVIZ Android **7.4.1.0421**, version code **1676**,
APK SHA256 `90d1007934e7878f44b3e1f94b65ccd2d0a29f967b23882cd54c9e5e815fd663`.
Relevant Java owners/methods:

- `com.ezviz.util.UserPwdEncryptUtils`: RSA PKCS#1 v1.5, digest/epoch.
- `com.videogo.pre.data.user.impl.UserRemoteDataSource.login`: v6 request fields.
- `com.ezviz.login.newlogin.LoginTaskHelper.handleLoginFail`: recovery categories;
  `showCheckVerifyCode`: selected channel and terminal binding.
- `com.ezviz.login.VerifyCodeActivity`: `1015` leads to image verification, not
  simply a terminal-binding SMS code.
- `com.ezviz.verify.VerifyDialogHelper`: incorrect/expired code and request limits.
- `com.ezviz.verify.channel.VerifyChannelType`: SMS 1/email 3.
- `com.videogo.pre.http.bean.user.LoginV3Resp.getLoginUser`: contactExt fallback.
- `com.videogo.pre.http.api.v3.UserApi.getServiceCheckCode`: `from`/`bizType`.

The Android callback maps these raw codes to app codes by adding 100000.
SDK errors use the **raw** code. Offline tests use synthetic RSA keys and block
real transport, including separate regional keys, actual prepared forms,
clock/key/lockout/rate-limit responses, zero-prefixed codes and request counts.
They do not establish current 7.6/iOS behavior, v5/v6 acceptance for every region,
real message delivery, live account lock recovery or actual UI rendering.
