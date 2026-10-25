# Two-minute recorded playback control

This development profile exercises a persistent decoder and host scheduler beyond
the older 60-second source/scheduler ceilings. It reads a local decrypted MPEG-PS
recording, never starts a camera and accepts no credentials. It is not sustained
live acquisition, a reconnect policy, a general camera player or physical A/V
synchronization measurement. The attended LAN tool defaults to a 30-second profile;
its separate [explicit two-minute profile](local-av-lan-playback.md#explicit-two-minute-live-profile)
has its own acquisition, crypto, evidence and supervision bounds.

## Run

Use the existing installed Linux/WSL runtime with PyAV, SDL2 and ffplay. Supply an
approved SHA-256 for the entire source, not a digest copied from an unknown file.
Run with dummy SDL video/audio drivers only for explicitly nonphysical controls;
otherwise retain the configured display/audio environment.

```sh
python -I tools/local_av_sustained_playback.py recorded.ps \
  --container mpeg --primary-stream 0 --secondary-stream 2 --audio-stream 1 \
  --expected-source-sha256 APPROVED_SOURCE_SHA256 \
  --play --pairing exact-pts --timing host-submission \
  --layout side-by-side --processor passthrough \
  --audio-overlap-policy bounded-serial-pcm \
  --max-audio-overlap-ms 1 --max-audio-phase-ms 1 \
  --receipt new-sustained-result.json
```

The stream indices are initial distinct selectors; E0/E1/C0 identities are
resolved again in the same active MPEG-PS container. Both HEVC lenses and 16-kHz
mono, 1024-sample AAC blocks remain required. Strict startup and rejection of
overlapping audio remain defaults; the example explicitly opts into the existing
1-ms serial-PCM compromise. `--startup-pairing common-keyframe` optionally enables
the existing bounded initial subset; post-start pairing stays strict.

One source origin and one host anchor are preserved for the whole recording. No
timestamp rebasing, looping, dropping, gain, silence or resampling is added.
Source SHA-256 is verified at terminal completion: this is an online control,
not whole-source preflight, so an altered or invalid later source can fail after
an already displayed prefix. Keep the original recording unchanged.

## Independent limits

| Limit | This explicit profile |
| --- | --- |
| Relative source event-start span | At most 120 seconds |
| Video pairs | At most 3,000, strict constant-state source identities |
| Total compressed input | At most 128 MiB; streamed, not copied into a full snapshot |
| Copied video lookahead | Unchanged: 4 pairs / 64 MiB, including in-flight leases |
| PCM lookahead | Unchanged: 32 blocks / 65,536 bytes |
| Unknown pending input | One alternative event, reserved in both track credits |
| Diagnostic history | Two finalized records per journal; full-prefix hash chains |
| Reader startup | Unchanged: 5 seconds / 256 KiB through both track heads |
| Decoder processing | Unchanged: 60 charged seconds, excluding explicit consumer borrows |
| Per-call and lateness defaults | Unchanged: 5 seconds / 250 ms |
| Scheduler wall guard | 120-second source window plus per-call timeout |
| Separate native-process supervisor | 210 seconds, then existing TERM10/KILL3 cleanup |

Other packet, frame, geometry and audio limits remain unchanged. A high-frame-rate
file may reach its pair ceiling before 120 seconds; a shorter recording can
complete successfully, so a completed receipt alone does not prove two minutes.
Check the original source timestamps, elapsed playback and event counts.

The old policy/scheduler defaults remain 60 seconds. A larger source window is
explicit, finite and requires source-sequence identities; output additionally
requires the owned pending-input path and bounded diagnostics. This profile does
not increase the decryptor, live capture or encrypted-evidence quotas.

## Results and cancellation

The new private receipt contains the worker verdict, decoder/policy results,
constant-state native-worker identity audit, full-prefix acknowledged media and
original-target hashes, EOF/drain/ownership checks and sampled resource windows.
Completion requires source digest/EOF, every accepted event acknowledged, clean
output drains and a joined/closed source owner. Cancellation is not successful
EOF. Partial diagnostics remain available on failure when the worker can flush.

The foreground supervisor samples its process tree every 250 ms and retains at
most eight 30-second summary windows. RSS/FD totals are non-atomic observations;
they include sampled native descendants, are not exact allocation peaks and do
not prove an allocation bound. Examine warm-up versus later windows together
with the explicit resident-credit peaks. Process churn can miss a sample.

Click the terminal before Ctrl-C; a focused video window does not produce a
console interrupt. SIGINT and SIGTERM have explicit handlers even if SIGINT was
inherited ignored. The source owner closes the iterator; the consumer never
closes an executing generator. Local file/native reads have no separate IO
interrupt hook. If native work cannot join, the worker flushes a failed/cancelled
receipt and the parent reaps its process group. A separate wall guard handles a
native call that never returns. No automatic retry or network acquisition occurs.

The longer live profile still needs attended camera validation; this recorded
control cannot substitute for it. Other cameras, codecs, qualities and channels
are separate coverage.
