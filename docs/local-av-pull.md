# Single-demand prepared-source pull boundary (development only)

`tools/local_av_pull.py` isolates `next` and `close` for a supplied iterator on
one worker. It is an independently tested building block for moving cooperative
network/decode pulls off the output scheduler's owner thread. **It is not wired
into the recorded CLI or capture-output adapter.** Existing output defaults,
limits, scheduling and single-threaded source preparation are unchanged.

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
not repeat the interrupt hook or double-release a completed result.

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

Before enabling this in output, reserve the unknown pull within the existing
video/audio credit; distinguish pending input from EOF; keep one host anchor,
original targets, existing lateness/deadline limits and independent output
harvesting. Abort the actual source before joining the pull worker, and do not
close its nested generators concurrently. Validate delayed source reads during
queued/in-flight output, failure and cancellation with retained media before any
attended live test. No automatic reconnect or new streaming-success claim is
introduced by this boundary.
