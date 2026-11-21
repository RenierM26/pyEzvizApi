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

- `mfa_channel=1` for SMS or `3` for email. Voice `2`, WhatsApp `6` and Zalo `7`
  require an explicit successful `get_mfa_channels(country_code)` call advertising
  that method for `TERMINAL_BIND` in the current API region. Omission uses the selected channel
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
boolean and non-digit codes fail before network access. SMS/email remain the backwards-compatible
methods. Other supported phone delivery methods are explicitly server-gated;
terminal approval and security-question flows remain app-required. A reported email/phone stays
usable when the same challenge also advertises security alternatives.

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
It is not a validation script or an automatic retry recipe. Challenges with only
terminal/security alternatives (no usable email/phone) still require the app.

`send_mfa_code(...)` is an **explicit request/resend**, even if one was already
requested. For metadata-backed contacts it uses the retained app's
`POST /v3/users/checkcode/mt/unlogin/v5` with `from=selected_contact`,
`bizType=TERMINAL_BIND`, selected delivery `msgType` and empty `imageCode` unless the human answered a CAPTCHA.
This is the code-request API's v5 suffix, not a downgrade from password login/v6.
It does not send contactExt access tokens as email addresses or session headers.
There is no 401 re-login recursion, redirect following, endpoint fallback or retry.
A successful response confirms request acceptance, not physical delivery.
When a legacy challenge includes **no** contact metadata, the old
`POST /v3/sms/nologin/checkcode` default-email `from=login_account` request
remains for compatibility;
SMS needs a returned phone or an explicit `mfa_account`. SMS and other phone
methods without a usable destination raise `verification_phone_unavailable` with
instructions to link/verify a phone in the app or choose email. A missing or
masked phone is not proof that no phone is linked; already-linked users should
retry login to refresh the reported contacts. No email fallback or message is
sent on that error. No timers, backoff values or channel policy are invented
from the presence of contacts.

Contacts and caller-selected recipients are ephemeral client state, omitted
from repr, errors and exported tokens; they are cleared after successful login.
The selected channel stays on that client, but is not persisted in tokens.
When constructing a new client, select it again. `available_channels` on a
challenge reports available contact fields, not a server guarantee of support.
`code_sent` means a request succeeded for the **currently selected channel and
contact**, not that a message was received. If the server changes or removes an
automatically selected contact, a previous request no longer counts as delivery
for the new contact. An explicit caller-selected recipient remains selected.
That metadata change does not automatically send another message: callers must
explicitly request/resend. Invalid channel/recipient selections leave all prior
selection and successful-request state unchanged.

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
| `1015` | `captcha_required` | Fetch an image and submit the human answer |
| login `1101` | `captcha_incorrect` | Fetch a new image; no automatic retry |
| request `1101` / `1141` | `captcha_required` | Fetch a contact-bound image before explicitly requesting delivery |
| missing phone | `verification_phone_unavailable` | Link/verify a phone, refresh login contacts or select email |
| `1069` | `terminal_limit` | Manage registered terminals in the app |
| `1102` | `region_selection_required` | Complete account-region selection in the app |

`contactExt.accessToken` (normalized by the app as `verifyAccessToken`) and
`isSecurityBind` advertise alternative terminal/security verification choices.
They do **not** veto email/SMS when usable contacts are present. Earlier main
incorrectly blocked these ordinary channels. No temporary access token is stored
or needed for their request/submission. A challenge with security alternatives
but **no** usable email/phone remains app-required (`security_verification_required`,
or `verification_phone_unavailable` when a phone method was selected) and never
falls back to the login account, even with an explicit recipient override.
Request-side `1101`/`1141` mean image/CAPTCHA recovery is required; they are
`captcha_required`, not incorrect SMS/email codes. Login-side `1101` is
`captcha_incorrect` and requires a freshly fetched image. No automatic solving,
blind retries or CAPTCHA bypass is attempted.
Missing selected contacts produce an unsent challenge
or `verification_contact_required` from an explicit request. Unknown codes use
`login_failed`. Server messages, temporary/access tokens and contact values are
not copied into exceptions. Lock minutes must be a positive signed-32-bit JSON
integer; malformed/string/boolean values are ignored, not guessed.

## Human-completed image CAPTCHA

Login `1015` and MFA-request `1101`/`1141` can be resumed with an image answer:

```python
challenge = client.get_captcha()  # Login account + persistent feature identity
# Display challenge.image using challenge.content_type; ask the human to read it.
client.login(captcha=challenge, captcha_code="aB01")
```

For a CAPTCHA raised while requesting a delivery code, use the selected contact:

```python
challenge = client.get_captcha(for_mfa=True)
client.send_mfa_code(captcha=challenge, captcha_code="aB01")
# Only after the request is accepted, ask for the received SMS/email/etc. code.
client.login(sms_code="001234")
```

The four-character image answer is distinct from the MFA code. It preserves case
and leading zeros. Challenge handles are ephemeral and client-owned; neither
images, answers nor contact context go into exported tokens or repr. A new fetch,
local `cancel_captcha()`, session replacement, or successful login invalidates
the previous handle. Submission checks region, feature identity, account/contact
and login-vs-delivery purpose. Switching a delivery channel also invalidates its
context. The handle is consumed before transport, including on a timeout; retry
requires an explicit new image. A regional redirect while submitting an image
stops with `captcha_region_changed` instead of replaying the answer elsewhere.
Expiry is server-owned; no undocumented lifetime is invented.

Image fetch uses `GET /v3/captcha` with the app's `account`/`featureCode` binding,
no redirects, a bounded HTTP deadline and a 1 MiB decoded supported-image limit.
The worker enforces this per request while streaming, including gzip/chunked
responses: it stops at the first excess chunk (at most one 16 KiB chunk is read
past the limit and is not retained). Exactly 1 MiB remains accepted. This is
limit hardening compared with buffering up to the shared 8 MiB bootstrap cap
before rejection; other scoped HTTP calls keep that 8 MiB cap. Rejection closes
the response without retrying, accepting its cookies or creating an answer handle;
it does not close the caller-owned session. PNG,
JPEG and GIF signatures are accepted, not HTML or arbitrary URLs. A non-image
response stops with app-recovery guidance; it is not treated as a browser token.

### Auxiliary request deadlines and cleanup

Channel discovery, image fetch and code requests each use one total client
`timeout` budget, including token-lock contention, connection/DNS and decoded-body
reads. An enclosing request deadline can shorten this budget, never extend it.
Response processing counts against it: synchronous parsing is not preempted, but
an expired deadline rejects the result before reporting a successful request or
installing a channel grant. An image issued during expired processing is discarded.
All acquired responses are closed on success, HTTP rejection, parsing failure or
cancellation; borrowed adapters and the caller's session remain caller-owned.

This is explicit deadline/redaction hardening, not behavior-neutral extraction.
Non-2xx statuses (including redirects) fail without following, refreshing login,
retrying or selecting another delivery method. Discovery and code requests retain
Requests timeout/connection exception families with redacted messages; CAPTCHA
retains SDK `HTTPError` transport failures. Total-budget exhaustion raises
`TimeoutError`. A timed-out code request may have reached the server: do not infer
non-delivery or retry automatically. No new automatic delivery is introduced.

Normal login and push migration share channel/region, CAPTCHA-context and saved
identity preflight. Fresh web-to-Android migration still intentionally replaces a
legacy identity; existing Android tokens must match the caller's selected feature
identity. Immutable regional channel policy is independent of contact/request
state, so contact resets cannot grant a withdrawn method or erase a regional grant.
Private typed CAPTCHA contexts distinguish login from delivery. CLI transitions
move only from initial login to an optional login image, then an optional OTP;
a delivery image proceeds directly to OTP. There is no retry edge from submitted OTP.

Both CLI login and MQTT migration show a private temporary image file path and
accept a human answer. The file is removed on answer/cancellation. There is at
most one login image, one delivery image and one OTP submission per invocation;
wrong/expired submitted codes or repeated image requirements stop. Ctrl-C cancels.
For a headless machine, display the returned image through the consumer UI instead.
The SDK does not open a browser, run remote JavaScript, OCR or solve the image.

The retained app restricts its browser/token human-verification v2 choice to
registration/password recovery (`RegistLineAuthManager.getRemoteCaptcha2Enable`).
Those account-recovery businesses are not implemented here; they must not be
substituted for this image-based login/`TERMINAL_BIND` contract.

## Explicit regional delivery discovery

```python
channels = client.get_mfa_channels("27")  # Telephone country prefix, not "ZA"
# Inspect each channel.channel, channel.title, channel.order and channel.supported.
# Choose a server-advertised method with a usable bound contact, never the first blindly.
client.login(mfa_channel=6)  # WhatsApp, only if advertised in this region
```

Discovery performs one read-only `GET /v3/ezsms/channel/config?countryCode=27`,
selects only `data.TERMINAL_BIND`, and preserves the app's ascending `order`.
Unknown channel codes are returned as unsupported and cannot be selected. Null or
absent policy does not enable alternate methods. Refreshing discovery revokes
grants for methods no longer advertised; a failed refresh revokes all prior
alternate-method grants. A retained selection is revalidated even when
`mfa_channel` is omitted, before login, push migration or a delivery request
makes a network call. Choose an available method explicitly or rediscover
support; no fallback is selected automatically. Policy is in-memory and
region-bound, not automatically fetched per command or persisted in tokens.
Phone contacts and policy are independent requirements; a region offering
WhatsApp does not prove that the account has a usable phone. SMS/email retain
the app-compatible legacy availability path when no policy is available.

Requests use selected delivery `msgType` 1/2/3/6/7. Matching the app's login
callback, WhatsApp/Zalo code submission uses login `msgType=1`; voice stays `2`.
Changing methods is explicit, with no fallback or automatic resend. The CLI
accepts `--mfa-channel sms|email|voice|whatsapp|zalo`; alternate methods additionally
need `--mfa-country-code 27` for discovery. No country is guessed from a username.
`available_channels` reports ordinary usable contacts plus discovered phone
methods for the current region, rather than every enum value in the app.

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
- `com.ezviz.verify.VerifyUtils.getSupportFlow`: email/phone eligibility is
  independent of the terminal/security alternatives.
- `com.ezviz.accountmgt.view.BaseVerifyCodeView`: email/SMS choose contact values;
  only terminal verification uses `verifyAccessToken`. `isIdentify` excludes
  `TERMINAL_BIND`, so it follows `VerifyAccountImgDialogUtil.getVerifyCodeOld`.
- `com.ezviz.verify.VerifyAccountImgDialogUtil.getUnLoginVerifyCode` and
  `com.videogo.pre.http.api.v3.UserApi.getUnLoginCheckCodeV5`: channel-aware
  unlogin endpoint/form, request-side image challenge codes `1101`/`1141`.
- `com.ezviz.task.LoginCtrl.loadImageCode` / `VerifyAccountPresenter`: CAPTCHA bytes
  fetched with account and featureCode; `UserRemoteDataSource.login` carries imageCode.
- `com.ezviz.humanmachine.RegistLineAuthManager.getRemoteCaptcha2Enable`: browser
  v2 selection restricted to registration/password recovery, not TERMINAL_BIND.
- `com.ezviz.verify.channel.VerifyChannelConfigManager` / `ChannelItemBean`:
  telephone countryCode, data keyed by business, channel/title/order and sorting.
- `LoginTaskHelper.showCheckVerifyCode`: third-party delivery normalizes to SMS
  msgType for login; this is not a request to send another SMS.
- `com.videogo.pre.http.api.v3.UserApi.getServiceCheckCode`: deprecated legacy
  `from`/`bizType` endpoint retained for metadata-free backwards compatibility.

The Android callback maps these raw codes to app codes by adding 100000.
SDK errors use the **raw** code. Offline tests use synthetic RSA keys and block
real transport, including separate regional keys, actual prepared forms,
clock/key/lockout/rate-limit responses, zero-prefixed codes and request counts.
They do not establish current 7.6/iOS behavior, v5/v6 acceptance for every region,
real message delivery, live account lock recovery or actual UI rendering.

## Explicit login host lookup

Use the offline Android 7.6.1 catalog snapshot to show named regions. Let the
user choose their account's registered region, then pass its internal ID to the
host resolver. The ID is not a country code or dialing prefix:

```python
from pyezvizapi import EzvizClient
from pyezvizapi.cloud.region import list_login_areas, resolve_login_host

area = next(area for area in list_login_areas() if area.name == "South Africa")
host = resolve_login_host(area.area_id)
client = EzvizClient(account, password, url=host)
```

The lookup sends only the area ID to the global EZVIZ endpoint, requires no
account or token, and does not modify an existing client. Russia uses the
app’s dedicated host without a lookup. The bundled catalog is a versioned
snapshot, not a live list of account eligibility. A successful response
does not prove that the area belongs to an account; EZVIZ may return its
global host even for unknown IDs. This is opt-in: the default host and normal
`1100` redirect handling are unchanged. For `1102`, finish selection in the
EZVIZ app: the forced region picker saves the region on the account, which
this read-only lookup does not do.
