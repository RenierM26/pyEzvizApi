# Single-demand prepared-source pull boundary (development only)

`tools/local_av_pull.py` isolates `next` and `close` for a supplied iterator on
one worker. It is an independently tested building block for moving cooperative
network/decode pulls off the output scheduler's owner thread. **Recorded CLI and capture-output adapter defaults remain synchronous.** The
output helper now exposes an explicit opt-in pending-input integration below.
Existing limits, targets and default source preparation are unchanged.

The caller supplies the iterator and its thread-safe, promptly returning
`interrupt` hook. Creating the worker does not request data. No credentials,
account clients, source selection, automatic retries, acquisition thread pool or
output devices are created by this module. A supplied iterator can acquire a
source when explicitly pulled; the helper does not make arbitrary native code
or blocking input safely interruptible.

## Demand and borrowed ownership

1. Reserve capacity for the next unknown event before calling `request()`.
   The helper allows exactly one outstanding request/result. It adds no hidden
   lookahead queue, but does not itself reserve the output scheduler's credit.
2. Call `poll()` from the consumer owner thread. `(False, None)` means not ready;
   `(True, value)` transfers the exact returned object, including a possible
   `None` value. Pending polling never waits for the source read. Duplicate
   requests and polling without a request fail instead of advancing the source.
3. Accept the borrowed event into downstream ownership before the next request.
   The upstream iterator remains suspended at its yield until that explicit
   request or shutdown. There is no copy, reorder, timestamp repair, discard or
   implicit repeated pull.
4. Source exceptions, including cancellation exceptions, are reraised by poll
   after iterator cleanup. EOF is exposed as `StopIteration` only after successful
   source close. A source-close failure cannot masquerade as clean EOF or replace
   an earlier source exception.
5. Always call `close(join_timeout)` even after EOF. It stops new requests,
   invokes the interrupt hook at most once if a read is active, and joins the
   worker before releasing an unconsumed result. Only the worker closes the
   iterator; it is never closed concurrently with executing `next`. The only
   exception is failed worker construction, which closes the claimed iterator
   on the constructing thread and preserves the original start error.

The join timeout must be finite and in `(0, 30]` seconds. It bounds the join,
**not arbitrary execution inside the supplied cancellation hook**. If the worker
cannot be joined, close raises `PullCleanupError` and retains its pending source
ownership; it does not claim success, force-close an executing generator, or
start a replacement. The worker is a daemon only to avoid an uninterruptible
third-party iterator preventing interpreter exit; daemon status is not cleanup.
The caller must retain the owner and join it later after its underlying IO is
interrupted, or use a separately bounded process controller. Repeated close does
not repeat the interrupt hook or double-release a completed result. Successful
shutdown also releases the owned iterator and cancellation-hook references, so a
bound method cannot keep the closed source and its buffers alive.

`result()` reports requested/yielded/consumed counts, unconsumed results abandoned
by explicit shutdown, outstanding/read/result state, source/error/close state
and worker liveness. Error diagnostics contain exception types, not exception
messages or credential contents. Consumer cancellation can abandon one already
returned borrow; that is an abort receipt, never successful whole-source output.

## Validation and next integration boundary

Offline tests cover strict single demand, identity/order, borrowed-yield lifetime,
nonblocking polling under a stalled source, sole-thread iterator use, interrupt
and join, timeout with retained ownership, repeated cleanup, source exceptions,
failed close, invalid bounds and failed thread construction. These tests do not
establish network continuity, playback throughput, audibility or physical sync.

## Opt-in pending-input output

The development output helper `tools/local_av_online_playback.py` accepts a
caller-retained, pristine `PreparedPull` instead of an ordinary iterator only
when `pending_input=True` is explicit. Use the helper's exported `PULL` module
(the tools load their dependencies with `runpy`):

```python
output = runpy.run_path("tools/local_av_online_playback.py")
# Validate transport/output arguments and source policy before claiming input.
pull = output["PULL"]["PreparedPull"](prepared_events, interrupt=interrupt_source)
try:
    output["play_prepared"](pull, args, receipt, pending_input=True)
finally:
    pull.close(args.deadline)
```

The caller supplies the actual thread-safe, promptly returning source interrupt,
not `prepared_events.close`. It must retain `pull` if either cleanup attempt times
out, interrupt the underlying IO and rejoin later. Never close nested generators
on the consumer thread, start replacement acquisition or claim clean termination
while `worker_alive` remains true. An already requested/closed owner or invalid
join timeout is rejected before playback claims ownership. Do not pass this owner
through the capture adapter: its existing outer generator-cleanup contract is
synchronous and unchanged. This API alone enables neither a live launcher nor
sustained network streaming.

Before every unknown request, output reserves **one possible event in each
track** within existing four-video/32-audio slots and byte budgets, including
preparing, queued and in-flight output. Before geometry is known it reserves the
full video byte budget conservatively; afterwards it reserves one unchanged
pair extent. Audio reserves the existing maximum block extent. These are
alternative capacity reservations, not two additional copied events. Exactly
one request/result can be outstanding; successful acceptance converts reservation
to actual ownership without another source pull. EOF releases the reservation
only after source finalization; failed acceptance/cleanup retains it until abort.

`pump()` returns promptly for pending input so the scheduler continues independent
backend liveness checks, queued dispatch, acknowledgement harvest and deadlines.
It preserves the single host anchor, exact original media targets, lateness and
session deadlines. No retries, drops, rebases or hidden queues are added. A source
that resumes too late still fails the original lateness limit. Prefill runs before
the host anchor with a finite deadline. If the other initial head would require
pulling past a full unknown-track reservation, opt-in prefill fails before opening
output devices; it deliberately does not use legacy startup's inspection bypass.

The receipt adds `pending_input`, `source_pull`, `input_reservation` and
`peak_credit_counts`/`peak_credit_bytes`. Credit peaks include unknown reservations;
`peak_owned_*` still measures actual accepted output ownership. `pull_ns` in this
mode measures request-to-owner-poll elapsed time, **not isolated worker decode or
network service time**. Successful source EOF does not establish completed output;
all output calls, drains and cleanup must still finish. Timed-out source cleanup
is a failure with retained ownership, never a successful output receipt.

Offline regression cases cover stalled reads with queued/in-flight output,
acknowledgement release, held credit, prefill timeout/capacity, original-target
lateness, source/backend failure and cancellation, failed finalizers and retained
ownership/rejoin. Retained-source dummy-output checks compare exact pixels, PCM,
metadata, origin and absolute-target offsets. None establishes physical playback,
network continuity, audibility or measured A/V synchronization.
