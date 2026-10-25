# Attended direct-LAN development command

`tools/local_av_lan_playback.py` makes the verified bounded dual-lens LAN path
repeatable without a private runner, camera app, account login or cloud fallback.
It remains a development tool, not a production API or unbounded player. It needs
the existing installed package and optional PyAV/SDL2/ffplay dependencies on
Linux/WSL. It installs nothing and changes no firewall or sandbox settings.

## Run

Use the installed-package fingerprint approved for your checkout/runtime, as
reported by [offline runtime preflight](local-av-runtime.md). Invoke with that
same interpreter; do not substitute a package version for its source fingerprint.

```sh
python tools/local_av_lan_playback.py \
  --private-config /local/path/camera.json \
  --expected-package-sha256 EXPECTED_SOURCE_SHA256 \
  --receipt new-lan-result.json \
  --startup-pairing common-keyframe \
  --audio-overlap-policy bounded-serial-pcm \
  --max-audio-overlap-ms 1 --max-audio-phase-ms 1 \
  --play
```

The command validates output/audio options, runs the isolated offline preflight,
checks the private configuration, then waits for **Enter** before one live attempt.
EOF/Ctrl-C before Enter cancels without acquisition. The receipt must be a new
file; an existing receipt is never overwritten. Failed/cancelled runs also write
a bounded receipt when possible. No secret value is passed in command arguments.

This fixed profile requests channel 0 and explicit MPEG-PS E0/E1/C0 identities,
resolved against each active container. Limits are 30 seconds / 15,000 packets /
32 MiB / 900 pairs. It uses two finalized diagnostic rows per journal, strict
source-sequence identities, one pending source read, consumer-excluding decoder
accounting and the existing resident/startup/lateness/EOF/drain guards. The parent
bounds worker orchestration separately (70 seconds, then bounded TERM/KILL
escalation); this does not enlarge source/output deadlines.

`--startup-pairing` defaults to `strict`. The example explicitly enables the
[common-keyframe startup subset](local-av-capture-preparation.md#explicit-common-keyframe-startup-opt-in):
at most 16 earlier unmatched video pictures within one second of observed source
span, before the first equal-PTS pair with both keyframe flags. All audio is kept,
and all pairing after the gate remains strict. Audio overlap defaults to rejection;
the example explicitly permits the already declared 1-ms serial-PCM compromise.
No gain, resampling, target shift, native VQE or device synchronization is added.

## Private configuration

Supply the existing `EzvizLocalSdkCredentials.as_dict(include_media_key=True)`
string-key shape, with optional already-known `device` metadata for source
selection. No command fetches or renews missing credentials. Do not put this file
in the repository, a shared handoff folder or a command-line argument value.
The argument above is only its local **path**.

```json
{
  "serial": "YOUR_SERIAL",
  "endpoint": {"host": "YOUR_LAN_HOST", "command_port": 8000, "stream_port": 8000},
  "cas": {"operation_code": "YOUR_EXISTING_CODE", "key": "YOUR_EXISTING_CAS_KEY"},
  "media_key": "YOUR_EXISTING_MEDIA_KEY",
  "device": {}
}
```

Use actual exported CAS encodings; do not replace them with a concatenated legacy
IV. `encrypt_type` may also be present under `cas`. Both ports must be explicit.
The file must be a regular, non-symlink file of at most 64 KiB. It is read once
per validation and its hash is bound between parent and worker, so a changed file
fails before opening the source. Keep OS access permissions private. Unlike a
one-time handoff attachment, this reusable configuration is **not deleted**.

## Receipt and ownership

The parent profile is `attended-direct-lan-prefix-v1`. It includes the isolated
preflight, configuration hash, stage/status, worker reaping and nested capture
receipt; it never includes configuration contents. Only all nested terminal checks
and a zero worker exit permit `completed`. No account client is constructed: the
source has explicit local credentials, offline selection and no cloud fallback.
The supplied device metadata still determines the existing local SDK variant;
this command does not invent a new connection/discovery policy.

SIGTERM becomes a cancellation exception so the source owner can interrupt IO,
join its worker, abort/drain outputs and finalize evidence. If joining still fails,
retain ownership until a failed worker receipt is flushed and the worker process
exits; do not finalize an executing decoder from the parent. The parent reaps its
child and retains available partial diagnostics after timeout/cancellation without
replacing the primary failure with a secondary cleanup error.

Nested diagnostics are bounded and checked for known private values before being
written. If the file changes/disappears or diagnostic safety cannot be established,
the receipt omits diagnostics and cannot claim success. The command emits only
status/error classes, not raw exception text. It does not collect encrypted packet
evidence or publish a Windows bundle: a caller needing independent source
comparison must retain that evidence separately, as in the attended handoff.

Completion is an accepted bounded prefix, not network/whole-source EOF. SDL/PCM
acknowledgements and clean drains are not physical display timing or audibility.
Human video/audio observations and measured physical A/V synchronization remain
separate evidence. Imports, help, failed readiness and cancellation before Enter
must not acquire a camera. Internal worker switches are not a separate public API.
