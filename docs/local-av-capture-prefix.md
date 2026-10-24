# Guarded capture → clear chunks (development only)

`tools/local_av_capture.py` joins a supplied pristine `AutoMediaStream` owner to
bounded MPEG-PS video decryption. It does not create an account client, discover
credentials, select a camera automatically or open output devices. Iterating a
real supplied owner will acquire its configured transport; importing this module
or constructing the lazy owner does not. The offline tests use mocked transports.
Legacy save/decrypt and recorded-playback defaults are unchanged.

Load the tool in a project environment and use:

```python
limits = CaptureLimits(duration_seconds=8, max_packets=15000, max_bytes=16 * 1024 * 1024)
chunks = iter_capture_chunks(owner, private_media_key, report, limits=limits,
                             completion='bounded-prefix', codec='auto')
```

Keep keys in private credential storage, not shell arguments or receipts. The
callable requires explicit positive integer packet/byte bounds within the
existing100000-packet/16MiB decryption caps, and a finite duration at most60seconds.
There is no silent clamp, buffer increase, retry or whole-source snapshot. Auto
and explicit HEVC reuse the existing1MiB pending/chunk guard. Invalid arguments
or an already consumed/closed owner are rejected before ownership is claimed;
do not use the owner concurrently after transferring it to this adapter.

## End policy comes before crypto EOF

| Policy | Capture outcome | Behavior |
| --- | --- | --- |
| `reject` (default) | Any iterator end | Raise `CaptureEndRejected`; no final crypto flush and no complete prefix hash. |
| `bounded-prefix` | Clean `packet_limit`, `byte_limit` or `duration_limit` | Permit final crypto flush for exactly the captured prefix. |
| Either | Ambiguous `upstream_ended`, cancellation, timeout/error, invalid counters or failed/in-flight cleanup | Reject/fail; never manufacture crypto EOF from it. |

The guard verifies the automatic-capture profile, terminal status, actual passed
packet/byte counts, configured limits, owner closure, startup quiescence and final
transport releases. Packet-limit count must equal the configured limit. The owner
excludes a crossing-byte packet; this adapter never adds it back. Caller-owned
`EzvizClient` stays borrowed; transport selection and fallback policy remain the
supplied owner's responsibility.

The packet iterator is exhausted/finalized before its terminal receipt is read.
A rejected end raises instead of returning `StopIteration`, preventing the
bounded decryptor from flushing a possibly cut or ambiguous tail. The final
capture snapshot is revalidated after cleanup, not trusted from an earlier pass.
Decryption errors still fail after a valid capture end was allowed. An explicit
prefix policy cannot make malformed crypto/container/decoder tails valid.

## Receipt scope

Profile: `guarded-capture-clear-chunks-v1`. Success is specifically
`status='bounded-prefix-ended'`, not whole/live source completion. The report
retains separate `capture` and `decryption` receipts and records:

- `input_scope='accepted-capture-prefix'`, selected bounds and completion policy;
- whether the capture-end policy passed, plus sanitized error/cleanup class names;
- `accepted_prefix_clear_sha256` only after final consumer exhaustion and clean
  cleanup; it fingerprints the accepted prefix, not the whole live source;
- `whole_source_complete=False`, `network_eof_verified=False` and
  `output_devices_opened=False` in every outcome.

The nested decryption receipt's complete hash/EOF likewise describes the
accepted finite iterator only. Crypto completion is not decoder EOF or a valid
playback plan. Passing chunks to `local_av_chunked.iter_chunks` preserves its
independent startup, decoder/pixel ownership and final source checks; require its
successful result too, and keep its source hash scoped to this captured prefix.
No decoded picture/audio or physical synchronization follows from this report.

## Ownership and failure

After argument validation, the adapter owns the pristine stream and its packet
iterator, closing both on completion, failure or explicit consumer close. Close
this generator/downstream owner on early exit. A currently borrowed clear chunk
and producer/native allocations are additional to crypto's pending-byte cap.
There is no prefetch queue or new background worker.

Primary producer/crypto errors and `GeneratorExit` remain primary through cleanup
failures. Cleanup-only failure still raises inside an unrelated caller `except`
block; primary-error state is explicit. This also corrects the older standalone
`iter_decrypted` wrapper's ambient-exception inference without changing its
normal output. Cleanup/key references are released; secure erasure is not claimed.

Already-yielded chunks cannot be withdrawn if a later source/policy error occurs;
this is online accepted-prefix processing, not whole-source preflight. Source,
startup/decode and crypto deadlines remain cooperative, with downstream waits
counting toward their existing budgets. Actual interruptible IO belongs to the
automatic transport. This PR does not integrate live playback or publish a Windows
bundle; that runtime's library dependencies still need exact-interpreter checks
before an integrated attended test.
