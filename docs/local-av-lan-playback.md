# Attended direct-LAN development command

`tools/local_av_lan_playback.py` makes the verified bounded dual-lens LAN path
repeatable without a private runner, camera app, account login or cloud fallback.
It remains a development tool, not a production API or unbounded player. It needs
the existing installed package and optional PyAV/SDL2/ffplay dependencies on
Linux/WSL. It installs nothing and changes no firewall or sandbox settings.

## One-command session (Linux/WSL)

To capture, retain encrypted evidence and verify saved media in one invocation,
run this entrypoint from a complete repository checkout in a Linux/WSL terminal:

```sh
bash tools/local_av_lan_session.sh \
  --python /path/to/installed/runtime/bin/python3.12 \
  --results new-session-directory \
  --private-config /local/path/camera.json \
  --expected-package-sha256 EXPECTED_SOURCE_SHA256 \
  --startup-pairing common-keyframe \
  --audio-overlap-policy bounded-serial-pcm \
  --max-audio-overlap-ms 1 --max-audio-phase-ms 1 \
  --play
```

Use an absolute executable interpreter path whose installed package matches the
approved source fingerprint. Bash and the already configured Linux/WSL display,
audio and optional native dependencies are required. This entrypoint installs
nothing, configures no display/firewall, fetches no credentials and is not a
standalone Windows bundle. Run `--help` for its finite option list.

The results directory must be new; it is created with mode 0700. The workflow
runs the existing attended command, preserving its offline checks and **one Enter
prompt before acquisition**. After successful capture it runs the existing
isolated offline verifier against those saved files, without starting the camera
again. The directory contains:

- `capture.json`: the unchanged attended parent/worker receipt.
- `packets/`: bounded encrypted bodies, index and manifest.
- `verification.json`: the independent media-chain comparison result.

Only zero exits from both commands produce the final session-completed message.
A failed/cancelled capture never starts verification. A verification failure
preserves the successful capture receipt and source evidence; it does not retry
or upgrade either verdict. All partial results are kept for diagnosis. The
configuration is read in place, never copied or removed.

Ctrl-C/SIGTERM is forwarded to the active Python command and the workflow waits
for its owned step to finish cleanup before returning cancellation. Each Python
command retains its own existing worker timeout and process-group escalation;
the wrapper changes no media, startup, wall-time or ownership budget. No phase
runs concurrently and no extra camera attempt is armed. Keep results private.

Startup/audio policies still default to strict/reject. The example opts into the
same bounded common-keyframe and 1-ms serial-PCM policies described below. The
wrapper rejects unknown, duplicate, abbreviated and workflow-managed/internal
options before starting; output paths are owned by the workflow. Individual
commands remain available for separate capture or offline diagnosis.

## Run

Use the installed-package fingerprint approved for your checkout/runtime, as
reported by [offline runtime preflight](local-av-runtime.md). Invoke with that
same interpreter; do not substitute a package version for its source fingerprint.

```sh
python tools/local_av_lan_playback.py \
  --private-config /local/path/camera.json \
  --expected-package-sha256 EXPECTED_SOURCE_SHA256 \
  --receipt new-lan-result.json \
  --packet-evidence new-private-evidence-directory \
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

`--packet-evidence` is optional; omit it to retain only the receipt. Its directory
must not already exist. It is reserved before Enter, with mode 0700; cancellation
before acquisition can leave an empty directory. No existing files are overwritten.

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
child and kills any surviving members of its inherited output process group, even
when the worker already exited or exited promptly after TERM. It retains available partial diagnostics after timeout/cancellation without
replacing the primary failure with a secondary cleanup error.

Nested diagnostics are bounded and checked for known private values before being
written. If the file changes/disappears or diagnostic safety cannot be established,
the receipt omits diagnostics and cannot claim success. The command emits only
status/error classes, not raw exception text. It does not publish a Windows bundle.

## Optional encrypted packet evidence

The optional evidence directory contains only `packet-bodies.bin`,
`packet-index.json` and a last-published `manifest.json`. Original media bodies are
retained before decryption, in source order, with contiguous extents and SHA-256
for each packet and the concatenated bodies. Transport/login metadata, private
configuration and decryption keys are not stored. Keep these files private:
encrypted camera content remains sensitive, and this is not a sanitized public
fixture or a self-decrypting bundle.

Retention has separate fixed storage bounds: 15,000 packets / 32 MiB of bodies,
a 3-MiB index, and a 4-KiB manifest. It does not increase source or copied-pixel
budgets. Files use exclusive creation and mode 0600. A write/storage error fails
the attempt rather than silently disabling evidence. These synchronous bounded
writes run on the source worker; a slow filesystem still faces existing deadlines.

After the source joins, closed bodies and the index are flushed before the
manifest is published. An unjoined worker never publishes a manifest. Abrupt
termination or writer failure can leave partial files; do not treat them as
complete evidence without checking integrity. Even verifiable files after a
late storage/flush error do not turn a failed attempt into successful playback.
A joined source/playback failure may still retain a stable diagnostic prefix.
The playback receipt remains failed: a finalized evidence set is not an accepted
media prefix. Successful attended completion also requires the parent to verify
the files against the worker summary, configuration/package binding and actual
source packet/byte counters.

Check a finalized set offline, with no camera, package dependencies or key:

```sh
python -I tools/local_av_packet_evidence.py --verify new-private-evidence-directory
```

The checker bounds reads, rejects symlinks/special files and verifies index hash,
every extent and packet hash, total count/extent, and concatenated digest. It
reports `integrity-verified` or exits 2 with `invalid-or-incomplete`. Hashes detect
corruption, not authenticity: an attacker can replace a manifest and its data.
This checker does **not** decrypt/decode, authenticate a receipt, compare selected
pixels/PCM, establish clean capture EOF, or prove physical playback/synchronization.
Those are separate source/media and output checks; retain the receipt alongside
the evidence for diagnosis.

Completion is an accepted bounded prefix, not network/whole-source EOF. SDL/PCM
acknowledgements and clean drains are not physical display timing or audibility.
Human video/audio observations and measured physical A/V synchronization remain
separate evidence. Imports, help, failed readiness and cancellation before Enter
must not acquire a camera. Internal worker switches are not a separate public API.

## Offline decoded-media comparison

After a successful attended run with packet evidence, use the **same installed
package/runtime and private configuration** to compare its complete saved source
with the receipt. This command makes no camera/account calls and opens no SDL,
audio or other output devices:

```sh
python -I tools/local_av_lan_verify.py \
  --private-config /local/path/camera.json \
  --receipt new-lan-result.json \
  --packet-evidence new-private-evidence-directory \
  --result new-media-verification.json
```

The result must be a new file (exclusive mode 0600). The configuration is only
read, never copied or removed. Failure/cancellation emits a constant status, not
raw decoder exceptions or private configuration. A zero exit and
`source-media-verified` mean all these checks passed:

- Bounded encrypted evidence integrity and parent/worker/source counter bindings;
  current installed-package fingerprint and configuration hash match the receipt.
- The original attempt is already successful, with joined source ownership,
  accepted-prefix preparation, every recorded output call and clean drains.
- An immutable replay snapshot still matches the verified encrypted digest.
  Decryption finishes and matches the accepted clear-prefix digest.
- Same-container E0/E1/C0 track resolution, original decoded metadata, declared
  startup subset (when enabled), common origin and audio clock policy match.
- Independently reconstructed full per-track media chains match every selected
  pair/PCM block's identity, canonical payload hash, extent, source target and
  original anchor-derived host target. Canonical paired Y/U/V rows are hashed,
  not concatenated raw lens buffers. Retained acknowledgement rows also match.

The verifier streams bounded decryption/decode from a snapshot of at most 32 MiB
of ciphertext; it does not write plaintext or build an unbounded media history.
It retains existing native decode/startup/ownership and 900-pair/10,000-audio-block
work guards. The public CLI runs verification in one isolated worker under a
separate 70-second wall limit, followed by bounded TERM (10 seconds) / KILL
(3 seconds) escalation. It reaps the worker and kills surviving group members
even after normal leader exit. This orchestration limit does not enlarge native
media/startup guards or any playback deadline. Ctrl-C/SIGTERM cancel the worker;
failed, timed-out, unreaped or malformed worker results cannot publish success.
The internal `verify()` function still has cooperative native guards, not its
own process watchdog; hidden worker switches are not a public bypass API.
Failed/cancelled or unsupported receipts are rejected, not upgraded by a later
replay. Their stable packet evidence can still be checked with the integrity-only
checker and used separately for diagnosis.

Media-chain construction and paired-pixel hashing are independent of the output
receipt builder. The existing decoder and policy implementation are shared with
playback: this is **not a separate decoder implementation** or proof that an
unsigned receipt is authentic. It reconstructs full source/media chains even when
only two diagnostic records remain, but does not reconstruct evicted service,
harvest or lateness observations. Matching host targets does not measure physical
display/audio clocks, audible sound, sustained live transport, or network EOF.
No new acquisition is needed to run this check.
