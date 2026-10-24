# Automatic-stream termination and ownership

`EzvizClient.open_stream()` still returns the same lazy `AutoMediaStream` with
unchanged transport selection, fallback-before-first-media and one capture
budget. Its new `capture_result` property returns a sanitized, detached snapshot
of accounting; reading or mutating a snapshot does not advance the stream.

```python
from contextlib import closing
from pyezvizapi.media import CaptureLimits

with client.open_stream(serial, source=source_options) as stream:
    with closing(stream.iter_media_packets(limits=CaptureLimits(duration_seconds=8))) as packets:
        for packet in packets:
            consume(packet)  # Existing media bytes/metadata, not decrypted here.
result = stream.capture_result
```

Close the packet iterator explicitly on an early break; the context-manager
transport close can interrupt active supported socket reads, but cannot close a
Python generator while another thread is executing it. Resume/join that reader
and let its owner execute the iterator finalizer. There is no new producer worker,
queue, changed timeout, retry-after-output, video decryptor or playback integration.

## Result contract

Profile: `automatic-media-capture-v1`. `status` is `not_started`, `running`,
`stopped` or `failed`. Normal `stopped` is a capture outcome, not verified media,
network EOF, decoder EOF or playback success. `stop_reason` retains the first
known local stopping cause:

| Reason | Meaning |
| --- | --- |
| `packet_limit` | The owner's yielded nonempty packet count reached its limit. No extra packet is pulled to establish this. |
| `byte_limit` | The next normalized packet would cross the byte limit; it is not yielded. |
| `duration_limit` | The owner's shared capture budget expired; a late-returning packet is not yielded. |
| `upstream_ended` | The adapter stopped without a more specific observable cause. This includes unreported lower-layer bounds; it is not protocol EOF. |
| `consumer_closed` | Explicit close or generator cancellation; no new successful termination is invented. |
| `closed_before_start` | Owner closed without discovery or transport startup. |
| `timeout` | An uncaught `TimeoutError` or local SDK deadline exception; the original exception still propagates. |
| `error` | Another uncaught selection, startup or read error; the original exception still propagates. |

`error_type` and `cleanup_error_types` contain class names only, not exception
messages, addresses, media, credentials or account metadata. A cleanup-only error
raises `PyEzvizError`; it cannot report clean capture success. Cleanup errors never
replace a primary producer/startup error or `GeneratorExit`. When a stopping cause
was already known, it stays recorded even if subsequent cleanup makes status
`failed`. The original exception chain remains available to the caller, separately
from this sanitized snapshot.

Counters distinguish yielded packets/bytes, transport-open attempts, acquired
transports and close attempts/successes. Yield accounting occurs before handing
the packet to the caller; it does not acknowledge downstream use. The byte limit
is enforced by this owner instead of being hidden by adapter exhaustion; no
crossing packet is emitted. Existing raw input-frame limits still bound empty
or non-media input before normalized output. Ambiguous lower-layer exhaustion
remains `upstream_ended` rather than an inferred count/timeout cause.

`owner_closed` records that close was requested; `transport_owned` records only
the currently attached transport. `transport_closure_verified` additionally
requires successful final release for every acquired transport and no startup in
progress; a failed close
must not be read as verified cleanup just because the handle was detached. This
is a local method-return acknowledgement, not proof of peer-side state or OS
behavior after a broken/custom closer. `transports_released` counts final releases,
while `transport_close_successes` also counts successful interrupt-close calls.
There is no implicit retry of a failed final close.

During startup, `close()` first interrupts the attached transport but retains its
ownership lease: a blocked socket factory may still attach a new socket after
that close returns. `startup_in_progress` remains true, release is unverified,
and the reader performs a serialized final close after startup returns or raises.
Consequently a cancelled-startup transport can have two close attempts: interrupt
then final release. Both are serialized outside the state lock, and only the final
successful close releases ownership. Normal established transports close once.

Cleanup receives an explicit primary-stream-error flag from generator scopes or
the context manager's exception arguments. Public `close()` has no primary stream
error merely because it is called inside the caller's unrelated `except` block;
a cleanup-only failure there must still raise.

The caller's `EzvizClient` is **borrowed**, not closed by this stream owner
(`caller_client_owned=False`). The acquired transport owns its underlying SDK,
command or cloud socket/client resources and receives one final close per attempt
(plus a possible in-startup cancellation interrupt).
The normalized packet iterator is explicitly closed, when supported, before
transport closure; finalizers run on completion, local limits, failure and early
consumer close. A transport factory that raises before returning remains
responsible for cleaning its own partial construction, as before.

`network_eof_verified` is always false. In particular, do not feed an ordinary
limited iterator's exhaustion into a decoder as evidence of complete live media.
A future acquisition/decryption owner must carry this stop reason alongside the
crypto/decoder EOF reports and choose an explicit accepted-prefix/abort policy.
No live-camera or physical A/V claim follows from offline lifecycle tests.
