# Temporary Home Assistant native delivery validation

Home Assistant consumption is the product; the player is not required. The
example under `examples/home_assistant/custom_components/ezviz_native` connects
one explicitly configured video track and optional AAC track to HA's own
HTTP server, `Camera.stream_source()` and stream/HLS pipeline. It does not
replace the official `ezviz` or existing `ezviz_cloud` integration.

**This is an isolated validation integration, not a released dependency or
upstream HA feature.** It has been tested against HA 2026.10.4 / Python 3.14 /
PyAV 19.0.0, including Python 3.14.8 and 3.14.9 cancellation controls. Other HA versions, browser playback and live-camera operation need
separate evidence. The shared `pyezvizapi.native_stream` API remains independent
of HA. This example is not included in the library wheel.

## Delivery and authorization

- Setup reads an operator-supplied local credential document off the event loop;
  no account login, registration, discovery, preview or capability query occurs.
  Configure each already-observed camera/channel/profile/lens explicitly. There
  is no automatic fleet acquisition or guessed main/sub selector.
- `stream_source()` returns an HTTP URL on HA's existing IPv4 loopback listener.
  The request must have **both** a loopback **socket peer** and a random 256-bit
  per-entry capability. Forwarded headers and HA bearer auth alone do not grant
  this internal source access. Unknown/missing/wrong capabilities fail before
  constructing a source. Camera credentials never appear in URLs.
- The capability is a credential too: do not publish it or log source URLs. HA's
  stream redactor recognizes the `auth` query key. Capabilities rotate on
  reload/unload and are not persisted or included in integration diagnostics.
- This validation topology requires HA to listen on `127.0.0.1` or `0.0.0.0`
  **without direct HTTP TLS**; a separate HTTPS reverse proxy is fine. Direct-TLS
  or non-loopback-only HA listeners fail setup, rather than disabling TLS
  verification. No external listener/port or firewall change is introduced.
- Each entry admits one native owner; at most four owners run across entries.
  HA's own stream provider handles downstream viewer fan-out. Additional native
  ingests receive 429, not an implicit second camera preview.
- The live helper supplies local credentials, forbids cloud fallback and does
  not treat transport exhaustion as finite EOF. An acquired MPEG-PS source must
  match the configured current-session PES IDs, codec and parameters. H.264/HEVC
  plus optional AAC are the current explicit boundary. Other codecs/formats
  remain unknown; audio omission requires `audio_id=-1`.
- Shielded executor tasks carry failures as result values; the owning consumer
  re-raises them only after retrieval. This avoids Python 3.14.8 reporting
  already-owned cancellation failures as unhandled shield errors. Repeated
  cancellation still joins cleanup.
- HTTP writes are awaited with a 10-second deadline and no body accumulation.
  Disconnect cancellation closes and joins the owned generator/transport/mux
  worker. The route explicitly closes its async generator even if a response
  write fails. Failed live input aborts the HTTP body, never a successful EOF.
- Unload revokes admission first, cancels delivery, joins native ownership, then
  removes HA providers/timers/worker and the entry. Timed-out owners remain
  registered for explicit recovery, block new previews, and cause unload to
  return false. One failed shutdown budget is not retried implicitly in the
  same unload call. Retrying unload after transport recovery is explicit.
- A HA stream worker may reconnect after an input failure, and HA preloading or
  an active viewer may keep a source open. That is HA behavior, not evidence
  that a battery camera can be safely polled indefinitely. Leave preloading off
  during attended validation; unload the test entry to revoke its source.

## Prepare an attended installation

No installation/restart or new acquisition is performed by the repository tests.
Before testing on a running HA instance, retain a backup of existing custom
components/configuration and use a deliberately selected camera/profile.

1. Build/install the exact reviewed library wheel in the HA Python environment.
   This temporary example intentionally has `requirements: []`: it must not
   download a released library lacking the new APIs or override HA's PyAV pin.
   On managed HA installs, use an isolated development instance/image with the
   reviewed wheel; an ad-hoc container pip install is not a durable deployment.
2. Copy the `ezviz_native` directory to HA's `custom_components/` and restart that
   **test** instance. This adds a new domain and does not migrate existing entries.
3. Put an existing supplied local credential JSON file on the HA filesystem,
   accessible only to the HA service. Do not use the non-secret exchange share
   for credentials. The bounded document uses the library credential export
   shape (illustrative placeholders, not new discovery instructions):

   ```json
   {
     "serial": "SUPPLIED_SERIAL",
     "endpoint": {"host": "192.0.2.10", "command_port": 8000, "stream_port": 9020},
     "cas": {"operation_code": "SUPPLIED_OPERATION", "key": "SUPPLIED_LOCAL_KEY"},
     "media_key": "SUPPLIED_VIDEO_KEY"
   }
   ```

   `stream_port` is optional. `media_key_hex` is the alternative byte-key
   representation; do not supply both key representations. Read at most 64 KiB;
   the endpoint must be an IP literal. No credentials are copied into HA config
   entries; only the absolute private file path and explicit selectors are stored.
4. In **Settings → Devices & Services → Add Integration**, choose **EZVIZ Native
   (validation)**. Supply the private path, known SDK preview channel, observed
   decimal PES IDs and codec. Common H9c observations were video 480/481 and
   AAC 448, but those are not universal IDs or lens ordinals. Add a separate
   entry for another lens. NAL clear-header sizes are 1 for H.264 and 2 for HEVC.
5. Setup and still-image requests do not preview the camera. Opening the camera
   stream in HA is the acquisition action. Attend that test and unload afterward.
   Do not publish the internal source URL. Download integration diagnostics for
   sanitized source/HTTP counters if the test fails.

The example has no snapshot implementation, transcoding, silence insertion,
clock repair, automatic codec fallback, profile switching or automatic probes.
Configure known supported streams; do not reinterpret auth/no-data as unsupported.

## Reproduce isolated tests

Use a separate Python 3.14 environment; do not install HA in the library's ordinary
3.12/3.13 development environment:

```sh
python3.14 -m venv .ha-venv
.ha-venv/bin/pip install -e . -r examples/home_assistant/requirements-test.txt
.ha-venv/bin/python -m pytest examples/home_assistant/tests -o asyncio_mode=auto
.ha-venv/bin/python -m mypy --config-file examples/home_assistant/mypy.ini \
  examples/home_assistant/custom_components/ezviz_native
```

FFmpeg is required for encoded-media fixtures. The Python TurboJPEG wrapper is
installed with HA, but no native image decode/snapshot is used by these controls.
The separate CI
job pins HA 2026.10.4, real HTTP/config flow/camera classes and PyAV 19.0.0;
no fake HA modules substitute for those contracts. It exercises H.264/AAC and
HEVC/AAC ingestion into HA-generated HLS, exact finite MPEG-TS HTTP delivery,
authorization/admission, disconnect/startup/write/source failures, failed joins
and explicit recovery, integration unload and HA provider timer cleanup.

Retained encrypted-source HTTP replay is private evidence, not CI media. Recorded
fixtures explicitly assert finite EOF; production live sources cannot do so.
HTTP writes prove bytes handed to the socket API, not browser rendering,
audibility, physical A/V synchronization or long-running network stability.

## Remaining acceptance and upstream work

- Actual HA frontend playback for each camera/profile/lens and browser codec
  combination; HEVC support is browser-dependent. Successful HLS generation is
  not browser certification, and software timestamps are not physical A/V sync.
- Attended live startup/stop, longer/concurrent sessions, battery/privacy/offline
  outcomes and reconnect/discontinuity behavior. No new acquisition is required
  merely to retrieve or recheck retained evidence.
- A released shared dependency and upstream HA integration changes using this
  lifecycle contract; then replace the temporary test integration. Do not turn
  inventory/advertised/configured/observed/decoded evidence into `ha_verified`
  without actual acceptance results. Current diagnostics keep frontend verification
  false rather than inferring it from HTTP/HLS success.

## Opt-in shared RTSP relay (isolated validation)

**Stock relay acceptance blocked:** retained/generated testing of go2rtc 1.9.15 → RTSP →
PyAV 19.0.0 shows different per-track PTS shifts and lost relative A/V timing.
The delivered encoded windows match, but that is not full recording, decoder
startup or common-clock parity. First video timestamps are missing and cold
joins can omit reference pictures. Do not use this adapter for live validation
or make it the default on the strength of earlier browser playback. The direct
PyAV → HA HLS path remains the timestamp-preserving baseline. Fix/validate
common-clock signalling and cold-join dependencies before using the stock relay.

The follow-up sections below describe a separate patched-relay prototype, not
a change in stock support. Offline clock/media, mixed H.264 frontend and explicit
session recovery controls pass there; released dependency support, HEVC client
playback and live acceptance remain open.


The direct URL remains the default. HA may start HLS and WebRTC readers at the
same time; the direct one-reader native route rejects the second reader with
429. An opt-in standard go2rtc REST adapter registers a separate random upstream
and returns its RTSP URL to HA. go2rtc supplies fan-out; native ownership limits
remain unchanged.

Supply optional `relay_api_port` (for example 1984) and `relay_rtsp_port`
(default 8554) in the config flow. Omitting the API port selects direct delivery.
Both endpoints are fixed to IPv4 `127.0.0.1`. The operator must provision a
compatible same-network-namespace go2rtc with loopback-only HTTP and RTSP
listeners. Do not expose these listeners to the LAN. The adapter does not
start/reconfigure HA's managed server, weaken authentication, discover sockets
or use private HA go2rtc objects. HTTP basic auth, remote endpoints and
Unix-socket-only API deployments are not supported.

Registration occurs on first `stream_source()`, not setup, and is serialized
across cold callers. It uses go2rtc 1.9.15's **runtime-only PATCH**, not PUT
(which persists the capability URL). The random upstream name is independent
from HA's consumer alias. No preload or probe is requested. API/RTSP inventory
remains private because it can contain the internal HTTP capability.

Relay validation permits **one native acquisition attempt per entry reload**.
EOF, disconnect and failed startup all consume the attempt; further authorized
requests get 503 before another owner is constructed. Active concurrent readers
still get 429. Failed joins retain their owner. Explicit successful unload/reload
creates a new capability, relay name and attempt allowance. This is a restrictive
validation control, not production reconnection/backoff or a session duration
cap. Keep preload off; unload explicitly to stop active readers. Diagnostics
report attempts and rejected retries without URLs or credentials.

Unload revokes admission and joins native ownership before deleting only the
adapter's random stream. Uncertain registration and failed deletion retain
ownership for explicit recovery. go2rtc DELETE may report config-save failure
after removing runtime state; GET confirms absence before accepting that outcome.
DELETE can rewrite the config file, but PATCH never persists the capability.
Process death is not graceful cleanup: reload revokes old native tokens, and
stale relay state may need operator cleanup. A go2rtc restart needs entry reload.

Offline controls use real HA classes and HTTP, concurrent REST requests, cancelled
registration, collisions, failed cleanup/recovery, invalid ports and native
EOF/startup retry rejection. Optional actual-binary check:

```sh
GO2RTC_TEST_BINARY=/path/to/reviewed/go2rtc .ha-venv/bin/python -m pytest \
  examples/home_assistant/tests -o asyncio_mode=auto
```

Without that variable the real-server contract is skipped. Tested with go2rtc
1.9.15; no new dependency is added (aiohttp is already provided by HA).
For a different relay binary, retained encoded payload/rational-clock parity
and full frontend acceptance must be repeated before live testing. The later
results below apply only to their reviewed patched relay, not stock 1.9.15. No silent
transcoding, clock repair or browser codec-policy change is introduced.

### Isolated sender-report follow-up

A local go2rtc v1.9.15 prototype with explicit consumer `?source_clock=1` restores
relative A/V timing to within one 16 kHz RTP tick on the generated/retained
fixtures. It adds compound RTCP Sender Reports/shared CNAME without rewriting
RTP media. This is not a released or supported go2rtc option, and this example
does not enable it. Cold-join dependencies, missing initial video timestamps,
finite EOF, wrap/discontinuity recovery and an explicit upstream common-origin
clock contract remain unresolved. The existing experimental warning still
applies; do not replace HA's managed binary or infer live readiness.

### Controlled closure of the remaining delivery gaps

The subsequent isolated go2rtc prototype defers fresh producer start until PLAY
and gates first audio on the opening video parser boundary (HEVC first complete
AU; H.264 next distinct original timestamp/AU as detailed below). Existing queue
caps are unchanged; overflow fails the connection. Explicit finite input flushes
only complete PES at clean TS EOF, drains senders, emits BYE and retains completed
state to prevent input retries. Truncation/transport failures remain failures.
The example declares `X-Stream-Finite` from the source options (live by default).

Authoritative source-origin declarations support full 33-bit PES clocks, integer
RTP conversion and epoch/wrap lifting. Invalid origins, backward/excessive jumps
and bounded queue overflow reject/close rather than repair timestamps. The test
harness supplies the origin metadata; trusted live metadata export and an
upstream-supported interface/release are still required.

Two repeated real-HA-worker runs recover every picture and AAC packet in all
three fixtures, with exact independent decoded pictures/PCM and valid first
muxer timestamps. HA's existing initial-keyframe timestamp handling is unchanged;
raw PyAV's missing first timestamp is not fixed. This is worker/muxer-input
acceptance, not frontend, late-join, concurrency or live-camera certification.
All existing experimental/default warnings still apply to stock delivery.

### Owner-derived clock metadata and concurrent-worker prototype (2026-10-31)

The optional library owner now exposes an immutable `source_clock` descriptor
once its first selected, timestamped MPEG-PS packet is ready. Its integer
`origin_90k` is shared-container presentation time, **not camera UTC**. The
existing incremental demux/mux path supplies it before any output chunk; it
performs no extra preview, source read, timestamp rounding, media rewrite or
buffer expansion. Non-integral, negative or out-of-33-bit origins leave the
optional descriptor absent rather than guessing an epoch. The admitted HTTP
route exports it as `X-Stream-Clock-Origin-90k` before preparing its response.

`relay_source_clock` defaults to **false**. Enabling it requires a relay API port
and the separately patched, isolated go2rtc source-clock build; it is not an
assertion of compatibility with stock go2rtc. The relay then returns
`?source_clock=trusted`, with no caller-supplied timestamp. The prototype binds
receivers to one producer-owned clock descriptor, rejects missing/mixed-domain
metadata, and uses the producer's atomic current source position when a late
viewer attaches. Transcoded/unrelated receivers do not inherit the assertion.
The earlier explicit-origin query remains a diagnostic control, not the adapter
path. Upstream API/dependency release and production deployment are outstanding.

Controlled offline checks include two cold and one late HA stream worker on each
of the H.264/AAC and retained HEVC/AAC fixtures, all sharing one native acquisition
per fixture. Cold workers retain the full media; late workers retain a contiguous
suffix starting at an original random-access picture. Late AAC decoder warm-up
is not full PCM parity: original AAC bytes and source timing remain unchanged,
with the independently decoded matching PCM suffix reported separately.

Real-process race instrumentation exposed shared audio marker mutation,
unsynchronized PLAY-state reads, and receiver attach/detach traversal (including
EOF shutdown). The prototype fixes input immutability, adds an opt-in PLAY-ready
barrier, and snapshots topology under the attach/detach lock without holding it
while invoking child handlers. Sender queue sizes and native acquisition limits
are unchanged. Full frontend/mixed HLS-WebRTC, slow-reader isolation and live
camera acceptance remain separate gates; selected race tests are not a claim
that the dependency's full unchanged baseline test suite passes.

### One-shot acquisition terminal state (2026-10-31)

Relay-mode HTTP responses now explicitly declare `X-Stream-Retry: never`;
direct delivery declares `default`. The experimental go2rtc MPEG-TS producer
preserves this policy across source failure, cancellation, and stop-before-PLAY,
retaining a terminal acquisition tombstone until fresh registration. This is
independent of `X-Stream-Finite`: a transport error remains a failed stream,
never a successful finite EOF. Undeclared producers retain default reconnect
behavior. The pinned stock relay ignores this private header, so the HA-side
one-attempt guard remains mandatory regardless of dependency support.

Real race-instrumented boundary tests exercise stalled RTSP readers alongside
healthy HA workers, abrupt source failure after media begins, and final-reader
disconnect while native input is idle. Retained media and source ownership must
be checked independently: disconnection of a stalled viewer is not proof that
the healthy viewer received every original picture/audio packet, and a failed
source must not send a success BYE or trigger a new native acquisition.

### Explicit session recovery and HA state (2026-10-31)

Relay entries expose a configuration-category **Prepare new session** button.
It is unavailable until the admitted one-shot attempt has ended and its native
owner has joined. Pressing it reloads the entry: revoke the old capability, stop
old HA outputs, remove only the owned relay source, and create fresh lazy
runtime/registration state. It does not itself acquire a preview. Close existing viewers before preparing,
then open the camera afterward to consume the new allowance; a still-open live
card can itself request playback immediately after reload. Concurrent presses, active
acquisitions and unjoined cleanup cannot silently grant another allowance.
Direct mode is unchanged and does not expose this one-shot recovery button.

Camera attributes describe `validation_session` (`ready`, `streaming`, `ended`,
`failed`, `cleanup_pending`, `closing`), `prepare_new_session_required`, admitted
attempt count and the configured observed codec. They do not infer browser
codec support. Exhausted entries return no source URL, so a new playback request
cannot revive an exhausted registration. Source errors and aborted acquisitions
make the camera unavailable and refresh HA's provider selection through its
public API. Aborted delivery also stops the independent native HLS retry worker,
disables its preload, and blocks cached HLS stream creation after exhaustion.
Clean finite completion does not immediately tear down accepted
last packets still draining downstream; the native HA stream lifecycle remains
in charge of those outputs. Existing final camera capability APIs are unchanged.

The patched relay now preserves an explicitly declared one-shot acquisition
policy across an RTSP DESCRIBE response as `X-Stream-Retry: never`; the receiving
patched RTSP producer retains that policy. Immutable source-policy metadata is
separate from clock metadata and successful EOF. Undeclared RTSP sources keep
the existing reconnect defaults. Other clients may ignore this private header;
this remains a prototype dependency contract, not a supported released API or
a guarantee that every frontend/FFmpeg retry loop is suppressed.

A relay-only diagnostic enum sensor keeps the same session state and recovery
guidance visible even when HA hides attributes on an unavailable camera. Its
HEVC playback requirement describes the configured codec, not detected client
support. Status changes use HA dispatcher subscriptions with entity-removal
unsubscription; no polling or additional acquisition is needed.

### H.264 parser-boundary startup guard

An intermittent cold-worker failure retained all 600 H.264 pictures but only
935 of 939 AAC packets. Wire inspection placed the four opening audio packets
between the first and second video access units: flushing one AU is not proof
that FFmpeg has published its first parsed video packet. The opted-in writer
now releases audio after the next original H.264 video timestamp/AU completes,
using existing queues and unchanged media timestamps/payloads. A finite source
containing only one H.264 AU fails closed rather than claiming complete delivery.
This is a constrained prototype policy; it is not generic arbitrary-short-stream
support. HEVC keeps its existing first-complete-AU gate.

### Relay restart and removal preflight

Before removal, compare the observed registration with its original runtime-only
upstream capability. An absent registration after relay restart is already
removed. API failure, observed reassignment, redacted/unknown inventory and
multiple producers retain explicit unload-recovery state without DELETE.
The inventory request does not create a consumer or acquire a camera.

This preflight is not atomic ownership: stock go2rtc has no conditional DELETE,
and active producer URLs can describe cached connections rather than current
configured sources. Concurrent writers and authoritative registration identity
require an upstream conditional-removal/generation contract before claiming
race-free cleanup. Do not interpret a matching inventory URL as a lease.

A forced relay crash during actual HA HLS is tested offline: native ownership
joins, aborted HLS output stops, relay restart alone does not reacquire, and
explicit Prepare/reopen yields exactly one fresh owner and original media.
The prior entry capability is revoked. This is explicit recovery, not seamless
automatic reconnect or unattended battery-camera acceptance.

### Native timestamp startup limits

Actual native-owner metadata and HA workers preserve the generated source at
ordinary origin, earliest audio timestamp zero, and across a 32-bit RTP video
wrap. Cold workers retain complete encoded pictures/AAC and independently
decoded video/PCM; corresponding A/V offset error is at most one 16 kHz tick.
Late AAC decoder priming remains a separately measured suffix condition.

Starting the native MPEG-PS source immediately before its 33-bit timestamp wrap
can make PyAV expose negative initial timestamps. The current unsigned trusted
clock declaration is then absent; the relay refuses playback without another
native acquisition. An earlier diagnostic test that supplies a known origin
does not establish this real metadata path. Negative-leading startup also
has a retained fail-closed control. No modulo guess, timeline repair or fixture
origin injection is applied. Native startup near this boundary and arbitrary
long-running live epochs remain open acceptance/design gates.
