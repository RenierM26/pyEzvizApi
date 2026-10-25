# Guarded capture → online preparation (development only)

`tools/local_av_capture_preparation.py` composes the existing capture-end guard,
bounded decryption, non-seekable MPEG-PS decoder and online relative-time policy.
It accepts a supplied pristine `AutoMediaStream`; importing it opens no transport.
Iterating a real owner acquires that owner's configured source. This development
step adds no player, camera selector, credential lookup or output devices and
changes no legacy playback/decryption defaults.

```python
prepared = iter_capture_preparation(
    owner, private_media_key, (primary_stream, secondary_stream), audio_stream,
    report, limits=CaptureLimits(duration_seconds=8, max_packets=15000,
                                 max_bytes=16 * 1024 * 1024),
    completion='bounded-prefix', codec='auto',
    policy='bounded-serial-pcm', overlap_ms=1, phase_ms=1,
)
try:
    for event, payload in prepared:
        consume_synchronously(event, payload)
finally:
    prepared.close()
```

The supplied media key stays out of command arguments and receipts. Stream
indices are explicit absolute indices, not inferred lens ordering. The audio
policy in this example is an explicit nominal serial-PCM compromise; defaults
still reject overlap. No samples, pixels, source PTS, relative targets, bounds,
codec prerequisites or deadlines are changed. Geometry must remain constant
within the existing online profile. [Capture policy](local-av-capture-prefix.md)
and [online policy](local-av-online-policy.md) retain their independent constraints.

## Ownership

All stream, audio-policy, capture-limit and capture-owner arguments are checked
before ownership transfers. Invalid arguments and already-started owners are not
cancelled. After validation the adapter owns the pristine capture, including when
construction fails before the first packet pull. Downstream iterators close
outer-to-inner on failure and consumer close, including unstarted lazy generators.
Use one owner from one thread; concurrent use after transfer is not supported.

Each yielded event/payload borrows existing decoder/policy credit until the next
resume or explicit close. There is no prefetch queue, new thread, full-source
snapshot or output acknowledgement. A downstream consumer retaining payloads
beyond that borrowing period owns those additional allocations. Native decoder
allocations remain additional to the existing bounded copied-byte accounting.

Primary errors and `GeneratorExit` survive cleanup errors. Cleanup-only errors
raise even inside an unrelated caller `except` block; the chunk and online
wrappers now track their own primary exceptions explicitly rather than consulting
ambient caller exception state. Stopping without exhausting/closing the iterator
does not establish completion or release resources deterministically.

## One verdict, independent evidence

The report profile is `guarded-capture-online-preparation-v1`. Its only successful
status is **`prepared-prefix-ended`**, published after all owned cleanup and
terminal checks:

- `capture`: explicit bounded-prefix end accepted under known local limits,
  clean final owner/transport accounting, verified crypto end and no pending bytes;
- `decode`: actual decoder/source exhaustion, no unread compressed tail, no
  unpaired pictures or pending PCM, and the same clear-prefix hash/byte count;
- `online`: both heads, fixed common origin, valid policy, matching decoded/event
  counts, all yielded credit released and zero owned bytes;
- no nested cleanup errors or incomplete stage.

`accepted_prefix_clear_sha256` is published only on that successful verdict. It
fingerprints exactly this accepted finite capture prefix, **not the whole live
source**. `whole_source_complete`, `network_eof_verified`, `output_devices_opened`
and `physical_av_sync_measured` are always false. Nested finite-iterator EOF/hash
fields retain their narrower stage meanings. The full separate stage receipts
remain available for diagnosis rather than being collapsed into one status.

Capture completion defaults to `reject`: even a local limit raises before crypto
flush. Only explicit `bounded-prefix` permits a clean known capture-limit end;
ambiguous upstream ending, cancellation, transport faults, cut/invalid media,
policy faults and cleanup failures cannot become a successful preparation.

Events can be borrowed before a later fault, so failure does not retract an
already consumed prefix. `consumer-closed` is not success. Even success makes no
whole-source preflight, audible audio, rendered picture, output scheduling or
physical A/V synchronization claim. Source/crypto/decode cooperative deadlines
still include downstream waits. This is not a live-output or Windows-runtime
handoff; those need their own dependency checks, output/drain receipts and
attended validation.

For the separate development output adapter, see
[guarded capture-prefix output](local-av-capture-playback.md). It retains this
prefix-only scope and requires independent output acknowledgements/drains.

Pass the optional `pes_ids=(0xE0, 0xE1, 0xC0)` keyword to resolve explicit ordered
MPEG-PS video/video/audio identities in this same acquisition, before decode and
online-policy offers. See [the capture output selection contract](local-av-capture-playback.md#explicit-same-session-pes-identities).
Absolute-index mode remains the default; PES mode records the actual unmodified
indices in both decoder and online-policy selection receipts.

The development iterator also accepts `identity_mode='source-sequence'` to check
the chunk decoder's original contiguous pair/audio IDs with counters instead of
session ID sets. See [identity contract and retained limits](local-av-online-policy.md#opt-in-constant-state-source-identity-checks).
Invalid modes are rejected before claiming the supplied capture owner. Sequence
completion additionally requires identity counts and resolved audio index to
agree with upstream decode; this does not replace the other prefix/EOF checks.

## Explicit decoder clock composition

`iter_capture_preparation(..., decoder_deadline_mode='consumer-excluding')`
composes the [consumer-excluding decoder deadline](local-av-chunked.md#opt-in-consumer-excluding-processing-deadline)
without changing the source's clock. The default is still `wall`; recorded CLI
and synchronous output defaults remain unchanged. The option is validated before
claiming the supplied capture owner, and the opt-in preparation receipt binds
`decoder_deadline_mode` to the distinct nested decoder profile.

Only the chunk reader and persistent decoder use the consumer-excluding clock.
The exact original `monotonic` callable and `CaptureLimits` still go to the
capture owner and decryptor. Capture duration and the decryptor's existing
60-second **wall** guard are not paused, replaced or extended. Active decryption
can therefore still expire while the downstream decoder excludes that same
consumer wait. Source EOF, crypto flush and final cleanup must independently
succeed before the prefix verdict. This is not a whole-pipeline relaxed deadline.

Successful opt-in completion requires both pre-cleanup and final reader clock
snapshots: the correct profile, finite nonnegative wall/processing/excluded
seconds with consistent totals, processing time within the unchanged allowance,
zero active borrow and exactly the decoded video-plus-audio borrow count.
Cleanup cannot move the clock backwards or exclude additional consumer time.
The bounded-MPEG startup mode, five-second wall startup and startup byte cap must
also agree. Clock counters do not replace producer/decode/prepared EOF, source
identity, metadata, origin, ownership or cleanup checks. A new decoder profile
without the explicit mode binding is rejected by the default verifier.

`verify_completion(..., decoder_deadline_mode='consumer-excluding')` is required
when independently validating these opt-in stage receipts. Preparation and
pending output forward that binding themselves. The source is still a finite,
explicitly accepted capture prefix, not network EOF or sustained streaming.
