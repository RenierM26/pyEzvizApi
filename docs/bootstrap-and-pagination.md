# Bootstrap deadlines and pagelist progress

Ordinary HTTP requests retain their synchronous behavior and configured timeout.
Only requests inside `request_deadline` use the bounded bootstrap transport.

A scoped call uses a detached copy of request state and borrows the caller's
adapters; it does not close their pools. One lazy process-wide worker runs at
most one job with one queued job. Queue saturation fails promptly. Idle workers
exit. Expired queued jobs never acquire transport, and late responses are closed.
Token changes and persistence stay with the caller under its existing lock;
successful response cookie additions, replacements and deletions are committed
by the caller, not the worker. Cookie deltas are scoped by domain/path/name;
unchanged cookies and unrelated caller-side edits are retained. Cancelled or
failed jobs never commit cookie changes.

The caller's wait is bounded even when system DNS or a server's slow headers/body
ignore socket inactivity totals. Once a standard requests/urllib3 response socket
is available, cancellation interrupts it and the worker closes the response.
A blocked platform resolver or custom response hook cannot be forcibly killed:
it may occupy the single worker until it returns. **No replacement workers are
spawned**; further scoped calls are bounded/fast-failing rather than accumulating
threads. Other ordinary requests are unaffected. This is caller-return and
resource-bounding, not a promise that platform DNS cancellation exists.

Scoped response bodies are decoded using requests, capped at 8 MiB, and returned
materialized for existing JSON/auth callers. Unsupported non-interruptible custom
streaming adapters fail closed; already-materialized responses remain supported.
The socket access needed for cancellation is isolated in one adapter function
and exercised by real loopback tests. Existing Basic/Digest RTSP probing uses a
separate socket I/O budget and does not inherit this HTTP transport.

Pagelist collection validates positive integer page size and non-negative offset,
rejects malformed metadata/data and repeated/non-progressing pages, and caps a
collection at 1000 pages. A page failure raises rather than silently returning a
partial device list. Authentication retry/persistence ownership stays in the
client. The final merge is an iterative **right fold**, preserving the historical
recursive result even for mixed nested value shapes; naive left-fold accumulation
would change that contract.
