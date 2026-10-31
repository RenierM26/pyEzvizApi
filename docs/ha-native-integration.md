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

**Acceptance blocked:** retained/generated testing of go2rtc 1.9.15 → RTSP →
PyAV 19.0.0 shows different per-track PTS shifts and lost relative A/V timing.
The delivered encoded windows match, but that is not full recording, decoder
startup or common-clock parity. First video timestamps are missing and cold
joins can omit reference pictures. Do not use this adapter for live validation
or make it the default on the strength of earlier browser playback. The direct
PyAV → HA HLS path remains the timestamp-preserving baseline. Fix/validate
common-clock signalling and cold-join dependencies before frontend/live work.


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
Retained encoded payload/rational-clock parity through RTSP and full frontend
acceptance with this adapter remain required before live testing. Earlier
prototype results are not evidence for this implementation. No silent
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
