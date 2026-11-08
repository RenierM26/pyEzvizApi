# Advanced stream CLI

[Documentation index](README.md) · [CLI guide](cli.md)

These are specialist transport/debug commands, not a production HA integration.
Use explicit finite limits, your own selected device, and private output paths.
For ordinary file saves, start with [media saving](media-saving.md).

## Commands and transport behavior

Experimental VTM cloud stream helpers. Packet tracing prints sanitized metadata only. Dumping writes VLC-friendly MPEG-TS by default using FFmpeg `-c copy` remuxing only, with `--format raw` available for unchanged, transport-dependent VTM payloads. The default path detects MPEG-PS, MPEG-TS, and RTP/IDMX video; RTP H.264/HEVC is depacketized before remuxing. Encrypted packets fail unless `--allow-encrypted` is set. Some battery cameras keep the VTM channel unencrypted but encrypt media payloads inside MPEG-PS or RTP; use `--decrypt-video` to decrypt HEVC/H.264 and retain descriptor-backed AAC-LC in MPEG-TS output.

```bash
# Inspect stream packet metadata without printing media bytes
pyezvizapi stream trace --serial ABC123 --channel 1 --max-packets 20 --json-lines

# Dump a VLC-playable MPEG-TS capture to a file
pyezvizapi stream dump --serial ABC123 --channel 1 --duration 1m --output stream.ts

# Decrypt battery-camera HEVC plus descriptor-backed AAC while dumping
pyezvizapi stream dump --serial ABC123 --channel 1 --duration 30s --decrypt-video --output stream.ts

# Pipe the transport-aware MPEG-TS output to another FFmpeg process
pyezvizapi stream dump --serial ABC123 --channel 1 --output - | \
  ffmpeg -f mpegts -i pipe:0 -c copy stream.ts

# Serve a local MPEG-TS URL for Home Assistant/FFmpeg clients
pyezvizapi stream proxy --serial ABC123 --channel 1 --listen-port 8558

# Serve a decrypted MPEG-TS URL with supported AAC for encrypted battery cameras
pyezvizapi stream proxy --serial ABC123 --channel 1 --decrypt-video --listen-port 8558
```

The dump command captures one minute by default. Use `--duration 30s`, `--duration 2min`, or `--duration 0` for unlimited capture; `--max-packets` can still be used as an additional stop limit. MPEG-TS output requires FFmpeg and remuxes the camera payload with codec copy only; it does not transcode video or audio. `--format raw` is for protocol diagnostics: its bytes may be MPEG-PS, MPEG-TS, or RTP/IDMX, so do not force FFmpeg's `-f mpeg` unless tracing confirmed MPEG-PS. Decrypted cloud RTP MPEG-TS retains RFC 3640 AAC-LC when the native `0x43` descriptor provides authoritative audio metadata; unsupported or descriptor-free audio remains video-only. The proxy serves `http://<host>:8558/<serial>.ts` by default. Each HTTP client opens a fresh VTM stream and remuxes it through FFmpeg. Keep the proxy bound to loopback unless you put it behind an authenticated reverse proxy or otherwise restrict access; the stream URL is not authenticated by `pyezvizapi`.

Direct-local SDK streaming is also available for devices that expose the local
`9010/9020` SDK setup. Authenticated clients can fetch the LAN endpoint, CAS
local-control tuple, and camera media decrypt key explicitly:

```bash
pyezvizapi --token-file ezviz_token.json stream local-sdk-keys \
  --serial ABC123456
```

That command intentionally prints secrets for setup/debug use. For normal
streaming, prefer fetching CAS directly with `--fetch-cas` and let
`--decrypt-video` retrieve the media key from the authenticated client. You can
also save that JSON to a protected file and pass it back with
`--credentials-file`, supply values for one run, or use
`EZVIZ_LOCAL_OPERATION_CODE` and `EZVIZ_LOCAL_CAS_KEY`:

The Python implementation matches the normal app live-view wire shape: local
SDK frames are `32-byte header + AES-CBC/PKCS#5 body + 32-byte ASCII MD5
ciphertext trailer`, then the `9020` stream port emits `$` interleaved RTP carrying
MPEG-PS payloads.

```bash
pyezvizapi stream local-sdk-dump \
  --credentials-file local-sdk-credentials.json \
  --decrypt-video --decrypt-codec encrypted-header \
  --format mpegts --output local.ts \
  --metadata-output local.metadata.json
```

```bash
pyezvizapi stream local-sdk-dump \
  --host 192.0.2.10 --serial ABC123456 \
  --operation-code "$EZVIZ_LOCAL_OPERATION_CODE" \
  --cas-key "$EZVIZ_LOCAL_CAS_KEY" \
  --media-key-hex "$EZVIZ_LOCAL_MEDIA_KEY_HEX" \
  --decrypt-video --decrypt-codec hevc-encrypted-header \
  --inner-address 192.0.2.20 --inner-port 9020 \
  --format mpegts --output local.ts \
  --metadata-output local.metadata.json
```

If your token contains CAS service metadata, `--fetch-cas` can fetch the
operation-code/key tuple through authenticated EZVIZ CAS instead of requiring
those two values on the command line. When `--decrypt-video` is used without
`--media-key` or `--media-key-hex`, the CLI fetches the camera media key with
the authenticated client:

```bash
pyezvizapi --token-file ezviz_token.json stream local-sdk-dump \
  --host 192.0.2.10 --serial ABC123456 --fetch-cas \
  --inner-address 192.0.2.20 --inner-port 9020 \
  --format mpegts --output local.ts
```

Use `--cas-serial` when the cloud CAS lookup needs a different serial form
than the local SDK IV/device serial used for the stream setup. The default
local-sdk helpers also perform the app-style P2P session registration before
querying CAS, which is required by some doorbell devices before
`getDevOperationCode` returns a session. Use `--no-p2p-register`, or pass
`register_p2p_session=False` to the library helpers, only when you have already
registered the session or are intentionally testing the raw CAS behavior. The
explicit `EzvizClient.register_p2p_session()` helper is available for
integrations that want to control this step themselves. EZVIZ CAS endpoints can
serve expired public TLS certificates while app clients continue to use the
endpoint, so this library tolerates WebPKI expiry for the low-level CAS socket
only after a normal verified TLS handshake fails specifically because the
certificate has expired, and it still checks that the expired peer certificate
is valid for the CAS hostname before sending CAS data. Use
`EzvizCAS(..., verify_tls_certificate=True)` when diagnosing strict TLS
verification against the CAS endpoint. The default
`--receiver-shape app` uses the self-closing attribute XML seen in normal EZVIZ
live-view traces; use `--receiver-shape structured` when you need the older
nested `NatAddress`/`InnerAddress` receiver XML shape.
The local SDK client binds the command socket source port to the advertised
receiver port before connecting to the camera command port, matching the
normal app's `bind(0.0.0.0:<ReceiverInfo Port>) -> connect(<camera>:9010)`
sequence.
For encrypted local media, `--media-key` accepts printable media keys and
`--media-key-hex`/`EZVIZ_LOCAL_MEDIA_KEY_HEX` accepts binary native media keys
encoded as hex. This media key is separate from the CAS key used for the
local-SDK control-channel envelope.
The `--credentials-file` form accepts the JSON shape printed by
`local-sdk-keys`: `serial`, `endpoint.host`, `endpoint.command_port`,
`endpoint.stream_port`, `cas.operation_code`, `cas.key`, `cas.encrypt_type`, and
optional `media_key` or `media_key_hex`. Explicit CLI arguments override matching
credential-file fields.
The optional metadata JSON contains only non-secret response commands, statuses,
body classifications, XML tag names, and first-media shape; it deliberately does
not include request bodies, keys, operation codes, UUIDs, timestamps, or payload
bytes.

Library callers that just want bytes can use
`copy_local_sdk_stream_from_client(client, serial, output, ...)`. It fetches the
LAN endpoint and CAS tuple, opens the local `9010/9020` stream, optionally fetches
the media decrypt key when `decrypt_video=True`, and writes either `mpegps` or
`mpegts` output before closing the sockets. Lower-level callers can still use
`open_local_sdk_stream_from_client()` with
`copy_local_stream_to_mpegps()`/`copy_local_stream_to_mpegts()` for clear local
media, or `copy_local_stream_to_decrypted_mpegps()` /
`copy_local_stream_to_decrypted_mpegts()` for encrypted local media. Decrypting
captures must use a bounded `duration_seconds` or `max_packets` value; the decrypt
transform buffers MPEG-PS data so it can handle NALs split across local RTP
packets.

This is separate from the proprietary HCNetSDK command protocol on port `8000`.
`pyezvizapi` includes native-Python framing/remux primitives for caller-supplied
command-port frames, including the port-8000 `$` media length format and clear
H.264 IDMX payloads. The person-facing `save clip --source
hcnetsdk-command-port` wrapper can consume those complete command frames and
write a local MPEG-TS clip. The generated command-port login helper covers the
initial RSA/challenge session setup and exposes the native command auth seed;
`hcnetsdk_command_port_auth_word()` covers the native post-login command-word
transform, and `hcnetsdk_command_port_control_frame()` wraps that transform into
a complete `0x63` control frame for callers that already know the command body
tail. `hcnetsdk_command_port_control_template_from_frame()` extracts reusable
control templates from captured/generated frames while dropping session-bound
client IP and session-id fields.

Native PlayCtrl traces can also show `IDMXAESDecryptFrame` decrypting complete
assembled H.264 frames inside the app. That native AES boundary is currently a
reverse-engineering parity target, not a requirement for the generated
command-port capture path above: the cameras validated so far expose clear
H.264 or HEVC IDMX payloads on the Python command-port path, and forcing AES
there corrupts clear H.264. Keep PlayCtrl AES-boundary work scoped to future app
parity or encrypted command-port evidence, with fresh Frida before/after dumps
and packet sidecars as inputs, rather than mixing it into the clear remux
recovery path.

