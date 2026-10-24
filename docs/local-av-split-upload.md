# Split lens uploads and preparation timing (development only)

The [rolling recorded player](local-av-bounded-playback.md) has an explicit
`--composition split-upload` mode. The default remains `python` composition.
No camera connector, new dependency or device-clock synchronization is introduced.

```sh
python tools/local_av_bounded_playback.py clear.ps --container mpeg \
  --primary-stream 0 --secondary-stream 2 --audio-stream 1 \
  --play --pairing exact-pts --timing host-submission \
  --layout side-by-side --processor passthrough --composition split-upload \
  --audio-overlap-policy bounded-serial-pcm \
  --max-audio-overlap-ms 1 --max-audio-phase-ms 1 --receipt new-output.json
```

## Why this mode exists

A real Windows rolling run completed29pairs/32PCMblocks and then exceeded the
unchanged250ms host-submission lateness budget. SDL present took about3.7ms;
start-to-present-return about17.4ms median. The owner recorded completion a further
58.6ms later (median), while pair lateness accumulated. Queued pairs were still
available. Those receipts implicate synchronous owner preparation/dispatch
throughput, not a stalled SDL present; they do not identify one measured CPU
substep because the old receipt had no preparation-stage timings.

The new mode removes timed owner-side construction of a wide YUV byte string.
The complete preflight still composes and hashes each pair before outputs open,
retaining only its canonical fingerprint. During rolling output, verified packed
left/right lens bytes are written consecutively into one sealed lease. The
isolated worker maps that layout and uploads the two halves into two even-aligned
rectangles of the same wide IYUV texture, then renders/presents once. It does not
reformat, rescale, swap planes/lenses, crop, mix or change the existing display
layout. Internal copy/upload representation changes, not selected pixels.

## Two fingerprints, unchanged output evidence

The split IPC message explicitly declares `layout=lens-planar` and carries:

- `storage_sha256`: the sealed file's left-bytes followed by right-bytes hash.
- `pixel_sha256`: the original canonical side-by-side Y/U/V row hash, calculated
  during preflight from the actual selected pixels.

The worker verifies descriptor count, seals, exact extent and storage hash. It
then hashes the canonical interleaved row sequence directly from mapped views,
without allocating a full composed frame, and compares the preflight fingerprint
before any texture upload. It closes its mapping/fd before acknowledging. The
acknowledged `pixel_sha256` therefore remains byte-for-byte comparable with
previous composed uploads; it is not replaced by the different storage-layout
hash or merely echoed without verification. Source per-lens hashes and PCM hashes
remain unchanged. The old IPC schema and composed worker path remain supported;
unknown layouts/extra fields are rejected rather than guessed.

The visible-plane packer/fingerprinter also handles genuinely contiguous planes
in bulk, excluding allocation tails. Padded strides retain row-by-row handling.
This removes avoidable small Python row operations and lets large hash/native
operations release the GIL, without including padding or changing any fingerprint.
The owner harvests calls completed during preparation before its next redispatch,
rather than imposing an extra poll cycle despite an already available result.

## Receipt and bounds

The receipt declares `composition`, `pair_pixel_sha256` preflight fingerprints
and bounded `preparation_timings`: each event identity/kind, monotonic start/end,
`decode_ns`, `verify_ns`, `prepare_ns`, final phase and prepared/failed status.
Decode includes advancing the persistent codecs to the next matched event;
verification binds its metadata/payload to preflight; preparation includes the
lease write/seal/hash (and Python composition in the default mode). These are
host diagnostic intervals, not source timestamps or physical output times.

The same raw pixel byte count is sealed in either representation. Four-pair/64MiB
video credit,32-block audio credit, separate decoder limits, source snapshot cap,
no-drop/no-rebase rules, explicit serial-PCM policy and default250ms lateness/five
second backend deadlines remain unchanged. Failed jobs keep credit until abort;
owned mappings/leases are not overwritten early. No disk cache, pixel eviction,
implicit renderer/transport fallback or timeout increase hides slow preparation.

This is a candidate throughput improvement, not a Windows performance guarantee.
Slow native calls or host resource contention can still fail the unchanged limits.
Dummy-output success must be followed by a fresh attended Windows receipt before
claiming recovery there. Neither successful API calls nor the new diagnostic
intervals measure visible presentation, audibility or physical A/V synchronization.

## Tests

Tests reconstruct every Y/U/V texture row from actual partial-upload pointers,
rectangles and pitches and compare it with the legacy compositor. They verify
contiguous and padded planes including trailing allocation bytes, canonical vs
storage fingerprints, changed hashes/metadata rejection, no owner compositor in
the timed split path, stage diagnostics, persistent real SDL dummy output and
immediate harvesting of calls completed during preparation. Both recorded modes
also run the real synthetic PS/AAC/SDL/ffplay drain integration when available.
Private retained source runs additionally compare every composed-pair/PCM output
hash and original target against independently audited source controls.
