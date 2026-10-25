# Guarded capture-prefix output (development only)

`tools/local_av_capture_playback.py` connects a supplied pristine
`AutoMediaStream` to [guarded online preparation](local-av-capture-preparation.md)
and the existing [bounded online output scheduler](local-av-online-playback.md).
The recorded CLI remains recorded-only and its defaults are unchanged. This
adapter has no CLI, account-client constructor, credential lookup, automatic
camera selection, retry or new background acquisition thread.

Calling `capture_playback` **can acquire the supplied owner's source and open
output devices**. Importing it or constructing the owner does not. Offline
controls mock acquisition and use dummy SDL/audio; they do not prove live
transport behavior or Windows throughput.

## Callable contract

```python
capture_playback(owner, private_media_key, args, report,
                 limits=CaptureLimits(duration_seconds=8, max_packets=15000,
                                      max_bytes=16 * 1024 * 1024),
                 completion='bounded-prefix', codec='auto')
```

`args` explicitly supplies the existing output options:

- `primary_stream`, `secondary_stream`, `audio_stream`: distinct absolute indices;
- `play=True`, `pairing='exact-pts'`, `timing='host-submission'`,
  `layout='side-by-side'`, `processor='passthrough'`;
- `video_transport='sealed-store'`, `container='mpeg'`;
- `deadline`: finite 0.1–30 seconds; `max_late_ms`: integer 0–250;
- `mono_option`: `ch-layout` or `channels`, according to the actual ffplay runtime;
- `audio_overlap_policy`, `max_audio_overlap_ms`, `max_audio_phase_ms`: the
  unchanged explicit online audio-policy options (default overlap rejection).

These values can be supplied in a namespace; no recorded source path is used.
Keep the key in private storage, not arguments or receipts. This is single-owner
synchronous use; concurrent calls on the supplied owner are unsupported.
Transport selection, fallback and interruptible IO remain that owner's policy.

Invalid output, track, audio-policy, capture-limit or owner arguments leave the
owner unclaimed and output unopened. Once validated, ownership transfers to the
adapter, including failure before the preparation generator's first pull. All
nested generators, preparation workers, output jobs, stores and backends are
closed/joined/aborted on failure, preserving primary exceptions. KeyboardInterrupt
is recorded as cancellation and reraised; caller signal handling remains caller
responsibility. Cleanup-only failure still raises inside an unrelated caller
exception handler. Preparation diagnostics and lease-cleanup handling likewise
use their own operation outcome rather than ambient caller exception state.

## Bounds and source scope

Capture-end completion still defaults to `reject`, so iterator exhaustion does
not silently flush a limited/ambiguous source. Only explicit `bounded-prefix`
permits a clean known local capture-limit end. The decryptor, decoder and policy
must independently accept that prefix; accepting the limit cannot repair a cut
crypto/container tail or bypass a later policy violation.

The shared output path keeps one host anchor after bounded prefill/backend
startup, original relative targets, independent tracks, split sealed lens uploads,
one preparation worker, four-pair/64-MiB and 32-PCM/65,536-byte output credit,
unchanged raw-input probing and explicit audio/video drains. No deadline/buffer
increase, discard, rebase, resampling or gain is introduced. Native decoder,
producer/crypto, policy references and currently borrowed payloads remain
additional to output credit. Cooperative upstream work includes output waits and
can delay dispatch; a finite source is not guaranteed to play within these bounds.

The video window is labeled as a bounded capture prefix, not a recording or a
whole live source. Existing recorded windows retain their prior title.

## Completion and receipts

The profile is `guarded-capture-prefix-host-submissions-v1`. The only successful
status is `prefix-output-completed`, after:

1. The nested `preparation` report reaches `prepared-prefix-ended` with clean
   capture, verified crypto/decode EOF, matching prefix hash/bytes and policy.
2. The nested `output` report confirms every decoded/prepared video/audio event
   was offered, submitted and completed, with no active/failed/partial job.
3. Both outputs explicitly drain, all owned cleanup succeeds and no preparation,
   queue or sealed-store credit remains.

`accepted_prefix_clear_sha256` is published only after those checks. Failed or
cancelled runs retain nested partial receipts but no top-level successful hash.
Output may already have occurred before a later capture/policy/backend failure;
this is not whole-source preflight and a valid displayed prefix does not make the
session successful. Backend initialization/opening is recorded in `output` even
when playback fails later.

`whole_source_complete`, `network_eof_verified`, `whole_source_preflight` and
`physical_av_sync_measured` remain false. PCM pipe completion is not audibility;
SDL present return is not measured physical display time. Successful dummy output
is host-call/drain evidence only, not human picture/audio confirmation. Actual
network acquisition, target-host dependency checks and attended output validation
remain separate work; no Windows bundle or camera test is supplied here.

Use the separate [offline runtime preflight](local-av-runtime.md) with the exact
proposed interpreter and pinned package identity before retained-media/attended
validation. Readiness alone does not establish playback or live acquisition.

## Explicit same-session PES identities

For MPEG-PS sources whose absolute demux indices can change between acquisitions,
opt in with `pes_ids=(0xE0, 0xE1, 0xC0)` on `capture_playback` (or
`iter_capture_preparation`). These are two ordered video PES bytes and one audio
PES byte, not lens ordinals or absolute indices. The existing namespace's track
indices remain syntactically validated, but this explicit mode supersedes them.
Without this keyword, absolute-index selection and all defaults are unchanged.

Resolve only against the active demux container, once, before decoding selected
tracks or offering events to the online policy. FFmpeg's MPEG-PS stream identifiers
are matched exactly as `0x100 | pes_id`; there is no low-byte masking, codec-based
selection, saved-session mapping, second acquisition or inferred fallback. Missing,
duplicate, wrong-type or unsupported-format tracks fail before output opens.
Invalid PES arguments leave the owner unclaimed.

The decoder and online-policy receipts both include `track_selection`: requested
PES IDs, observed demux IDs, types and resolved absolute indices. The original
indices remain in every decoded/prepared event and metadata digest; no stream
renumbering, timestamp rewriting, payload changes or larger startup budget is
introduced. Both selection records must agree for prefix completion. The
selection itself does not verify a whole source or physical lens identity, nor
does it promise that a later truncated capture or output failure will succeed.
