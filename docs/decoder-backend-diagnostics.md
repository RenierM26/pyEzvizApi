# Offline decoder backend counts

This developer-only audit counts observed software-decoder API returns per
**native input attempt and codec context**. It does not decode media, attach to
an app, retry a rejected input, change camera settings or produce physical output.
Node.js is required for the offline command, not for the Python library.

```sh
node tools/app_decoder_backend_counts.cjs /path/to/private/events.jsonl
```

The input is the metadata-only raw-event format containing `encoded_video`,
`software_backend_return` and `encoded_video_return` records. Other metadata
events are ignored. Each backend return must match an open input by attempt ID,
lens ID, raw identity and frame identity. Duplicate inputs, orphan or late
returns, mismatched identities, invalid integer results and mixed raw/aggregated
native-return rows fail the command without a successful JSON report.

Output contains one summary per captured attempt. Native results remain separate
from backend counts: zero backend calls is not a successful decode; a backend
return of zero is not a decoded-frame count or proof of output. An input without
an outer native return remains pending with `native_result: null`, even if some
backend calls returned. Capture completeness cannot be established from these
events alone; retain the original observer receipt and its saturation status.
Counts deliberately omit the ordering and timestamps of individual backend
calls, so they cannot identify a failing branch or establish call-level timing.

## Bounded observer accumulator

`tools/reference_stream/backend-counts.js` supplies `decoderBackendCounts()` for
an exact-profile, separately approved private observer. It has no native hooks or
device access. Load the helper before the observer and allocate one instance per
native input attempt. Capture the owning attempt at backend entry, then call
`record(codecContext, signedResult)` at backend return. Do not choose the owner
again at return: nested calls and other threads may have changed active state.

Put `snapshot()` in the corresponding outer native-return record as
`backend_summary`, instead of emitting a row for every backend call. At a bounded
stop, retain separate snapshots for unfinished attempts and label them incomplete.
`valid` means the accumulator has not failed validation, **not** that the native
attempt, capture, transition or playback completed.

Limits are 600 input attempts for the offline audit, 20,000 input rows and 8,192
bytes per JSONL line (including newline). Each accumulator permits at most 4,096
returns, eight codec contexts and 16 distinct statuses per context. An overflow
throws, preserves only its existing prefix and permanently marks the accumulator
invalid; further recording throws. The observer must stop and report the error,
not silently discard a status. These limits do not change media or output caps.

## Saved-capture validation

An offline callback simulation of the private observer, checked against
independent Python counters, retained all 1,229 raw backend returns across 309
input attempts: 308 completed, one pending. Two observed returns belong to that
pending attempt. All original input metadata, native results and 153 paired
selection headers retained their sequence. Event rows fell from 2,000 to 771;
the pending summary is carried separately in the stop receipt.

The **original capture remains saturated and partial**. The simulation neither
extends its coverage nor establishes how the lighter observer behaves on a live
device. Synthetic callback controls also cover nested attempts, overlapping
threads, unowned backend calls and an attempt with no backend return.

The intermittent second-lens recovery fault remains unexplained. The next native
experiment needs a freshly verified, unlocked reference device and a bounded
controller using the normal exported API hooks, not the discarded inline probe.
No new native execution, physical audibility or A/V synchronization result is
claimed here. Captures, exact-build instrumentation and proprietary binaries stay
private; no instrumentation is enabled in the production/default source.
