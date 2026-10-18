# Build-gated reference producer and bounded software benchmark

`tools/app_reference_stream.py` promotes the earlier private live-pilot scripts
into a reproducible **development-only** producer. It attaches to an already
available Frida Gadget, checks the original ELF files behind the loaded modules,
then installs the supported native entry/exit observers. It does not open a
camera, unlock a device, enable audio, change quality/settings or configure ADB
forwarding. The Android app remains the camera connector, decoder and VQE engine.
Production APIs, capture/remux and installed package dependencies are unchanged.

## Prerequisites and invocation

Use a private, authorized Android test device with the reference app and Gadget
already installed. Optional host research dependencies are Frida's Python module,
ADB, SDL2 and ffplay. Frida is deliberately not an installed library dependency.
The host must be POSIX. Inspect the screen and close any previous preview before
starting; unlock the device manually if needed. Warm/load the reference native
libraries first if they are not already present, then close that preview.

The only accepted profile is ARMv7 / four-byte pointers with these **exact** ELF
SHA-256 fingerprints (not an app-version-string check):

| Module | SHA-256 |
| --- | --- |
| `libPlayCtrl.so` | `a719ac549516df28345536d7baf1cc22145996949e89f8c7fae2dc73a379cddc` |
| `libezstreamclient.so` | `184f8eb8ce29a2f4ce5c6a915dd9f5649907f55e410a92c6a3db8b414f665f6b` |

Loaded APK paths are discovered from the attached process. The producer checks
bounded APK/member sizes, pulls the APK into temporary storage, verifies both ELF
hashes, deletes the temporary APK and only then loads the observer script. Other
builds fail closed. This is a reproducibility guard, not authenticated device or
processor provenance. The hook's offsets/caller checks must not be reused for a
different build merely by editing the expected hashes.

Example, with the actual serial supplied by the operator:

```sh
adb -s "$ANDROID_SERIAL" forward tcp:27049 tcp:27046
python tools/app_reference_stream.py --attach --dummy-host \
  --device "$ANDROID_SERIAL" --frida-endpoint 127.0.0.1:27049 \
  --output /private/new-reference-run --seconds 25 --pairs 8
```

Wait for `READY`, then start a **fresh** camera preview. A session already playing
when hooks attach lacks startup queue/handle observations and is not a substitute.
The tool always selects dummy SDL video and ffplay audio drivers; there is no
screen/speaker output option. The optional `--sink-deadline` is finite 0.1..10 seconds (default five), passed
explicitly to host output operations/drain; host termination remains bounded. A
larger value does not change source-ring EOF retention or prove lower latency.
Keep failed default-deadline observations when comparing runs; do not relabel
them as successful because an extended-deadline run finishes.

After it exits, close the preview and remove the
caller-owned forwarding:

```sh
adb -s "$ANDROID_SERIAL" forward --remove tcp:27049
```

No PIN or camera credentials are arguments. New output directories/files are
exclusive and private (umask 077). They contain private pictures/audio and must
not be committed or attached to a public issue.

## Bounded source and explicit omissions

A run permits at most 15 seconds of preview startup after readiness, then at most
35 seconds of media observation from the first decoded-picture callback on the
host clock. Idle manual-start delay does not consume the media window. Source
startup, media duration and pair-count stops are reported separately. Limits are
20,000 metadata rows, eight
selected paired snapshots, 240 MiB of transferred video and 8 MiB of audio.
Original input snapshot staging holds at most 24 lens buffers, each at most
12 MiB; eviction is logged. The callback owner flushes binary data before
publishing its offset/hash metadata. There is no full-file reload/poll loop.

The producer forwards **contiguous validated completed prefixes**, not arbitrary
sampled frames. Full 49-word descriptors, actual admission/release/completion
observations, renderer uploads/samplers and blob hashes feed the existing host
validator. A missing paired snapshot waits; it is never replaced or silently
skipped. Changed emitted prefixes, ambiguous admitted identities, unsupported
clock configuration, drops/copy-render paths and collector errors fail closed.
The current projector deliberately does not cover every native playback mode.

Audio requires a unique preceding decoded-buffer hash matching the actual VQE
input and a successful corresponding output call. Ambiguous identical buffers
remain unforwarded; there is no index/timestamp-based guessed association. The
report counts observed decoded/VQE output blocks and unforwarded VQE outputs.
Those omissions are **not** host-ring rejection and must not be interpreted as
lossless audio coverage. Improve causal queue instrumentation before claiming
complete audio transport across repeated/silent buffers.

The source remains open while the host acknowledges output. Nonblocking pipe
writes and progress reads have bounded deadlines and preserve evidence. Audio is
given a turn before each large pair, but a framed binary snapshot cannot be
interleaved with audio halfway through that record. Snapshot copy, audit and
transport can therefore cause substantial delay/bursts. The host retains its
existing byte/sample/event/queue limits; this tool does not relax them for a
longer benchmark. Eight full-resolution pairs cost about 224 MB on the wire, so
this is a **bounded observation**, not an unlimited continuous player.

At the time/pair limit the producer freezes/unloads its observers and closes the
host pipe without draining unforwarded observations. Queued/active host state is
recorded using the existing retain-at-EOF policy. Active I/O may complete after
EOF; reports count only acknowledgements strictly before EOF as live-prefix
proof. Source callbacks that were observed but not forwarded remain distinct
from the validated host prefix. Failure/cancellation can follow earlier output;
inspect `live-receipt.json`, not just the producer exit code. Cleanup attempts
observer unload, probe unload, detach, terminate/kill/reap and file closure even
when an earlier cleanup step fails. The tool does not close the Android preview.

## Reading the measurement artifacts

- `benchmark.json`: exact build profile, stop reason, coverage counts, device
  render cadence, host video/audio acknowledgement intervals, pending-queue peak,
  host rejections/retention/partial bytes and pre-EOF acknowledgement counts.
- `events.jsonl` and binary blobs: private original observations and verified data.
- `live-source.bin`: only bytes successfully accepted by the host pipe. A failed
  record may leave this artifact ending mid-header/payload; no unsent tail is
  written ahead of the pipe.
- `host-progress.jsonl`, `host-stderr.log`, `live-receipt.json`: host output evidence
  and native model state, including effects retained after later failures.

Collector callback-to-write-completion delays and pipe-write durations use the
**same host monotonic clock**. They are not device-to-host end-to-end latency.
Device and host cadence are reported separately; cross-device transport delay is
`null` because their clocks are not synchronized. Device timestamps, source media
time, host ingestion and physical presentation are not interchangeable.

`requested_host_video_span_reached` merely compares first/last host video
acknowledgements with the requested duration. A large span does not prove stable
cadence, low latency or no loss; `sustained_realtime_verified` remains false. The
benchmark must report failure to sustain real-time, short coverage and omissions
as results rather than extrapolating from a few frames. Physical A/V validation
is separate and remains deferred.

## Bounded hardware observations (2026-10-18)

The supported build passed its actual ELF checks in fresh reference sessions.
The final synchronized-start run stopped at the eight-pair limit with a ten-second
sink deadline: 16 audited lens snapshots, 729 projected source events, eight
paired video and 87 audio acknowledgements strictly before EOF. All captured
pairs were forwarded. Host audio peak pending (including active) was 18, with
zero host rejection, retention or partial bytes at termination. Source observation
included 164 decoded audio blocks / 148 VQE outputs; **61 VQE outputs were not
forwarded** (the count includes unresolved correspondence or observations outside
the emitted prefix, not just host-ring rejection).

Source video media times were 0/67/133/200/267/333/400/467 ms. Host video
acknowledgements spanned **13.087 seconds**, with 1.630–2.206-second intervals.
The native observer recorded 156 render callbacks spanning 14.827 seconds; these
are not all forwarded host frames. Maximum collector-callback-to-write-completion
delay was 1.415 seconds and maximum pipe-write duration 49.6 ms. These observations
do not isolate a single performance cause: snapshot copy, instrumentation, audit,
transfer and source-projection overhead all contribute. The requested 25-second
host span was not reached. No real-time or physical A/V result follows.

An earlier five-second-deadline run reached eight video / 146 audio writes before
EOF but **failed shutdown** because ffplay did not drain accepted bytes within
that deadline (five host newest-offer rejections). That failure is retained as a
result, not reclassified using the later run. Another attempt timed out without
observing startup; its report correctly records zero live output. Final cleanup
closed the preview, unloaded hooks, detached the session, removed caller-owned
forwarding and left no host output workers. Private evidence is retained locally,
not shipped with this repository.

## Stage profiling and lossless transfer comparison

Stage profiling is now collected on every development run. `stage_profile` keeps
separate **device**, **collector**, **producer** and **host-output** clock owners.
The device measures input/render snapshot copying, SHA-256 and send-call duration;
compressed send-call duration **includes** compression. The host separates
collector decompression/hash/persistence, blob reading/hash/manifest construction,
event projection, native sample audit, spool read/composition, output startup,
present calls and backend shutdown. `source_pipe_stages` groups completed source
pipe writes by record kind. `host_audio_received_to_write_complete_ms` measures
host-admission-to-pipe-ack residence only; rejected/unforwarded audio is counted
separately, not assigned a fabricated latency. Startup/shutdown spans are present
in new receipts; earlier profiling pilots predate those extra spans.

Host profiles retain at most 20,000 spans each, with explicit `omitted` counts.
Summaries provide count, bytes, failed spans, total/max and nearest-rank p50/p95.
Nested/overlapping spans must **not** be summed as end-to-end latency. A device
`send` return measures only the local call, not delivery from Frida's asynchronous
transport queue. Cross-device one-way delay remains unknown. The historical
`collector_received_ns` stamp is published after payload verification/persistence;
collector callback processing has its own measured span.

`--transport raw` remains the default. Optional `--transport zlib` (level one) or
`--transport lz4` compresses only the original/rendered pixel messages between
Gadget and the collector. The codecs use Android system `libz.so` or `liblz4.so`
exports, not offsets in an unverified app library. LZ4 additionally requires host
system **liblz4** with `LZ4_decompress_safe`; it fails before attach if unavailable.
No Python/package dependency is added. Both codec modes fall back to raw for an
individual snapshot if compression would not shrink it. A selected codec failing
to load/run is an error, not an implicit change of the run's configuration.

Compression is lossless transport, **not** a reduced verification mode. The host
bounds compressed input and decompressed output, rejects malformed/truncated or
trailing data, verifies the original full-buffer SHA-256, persists original bytes,
and performs the unchanged full-header/crop/renderer audits. The byte budgets
still charge **uncompressed** pixels. No frame skipping, downscaling, timestamp
retiming, guessed audio association or EOF drain is introduced. The host live
source protocol and `live-source.bin` remain uncompressed; partial-write evidence
still contains only the prefix actually accepted by the pipe.

Run otherwise-identical fresh sessions into distinct private directories, changing
only `--transport`. Then compare the two reports:

```sh
python tools/reference_stream/compare.py \
  /private/raw-run/benchmark.json /private/lz4-run/benchmark.json \
  > /private/comparison.json
```

The comparison preserves failed outcomes and reports missing/mismatched settings,
including audited geometry and media times. The app may vary initial resolution
between fresh previews without the tool changing a setting. Different geometry
must not be presented as a transport speedup. Even matching settings represent
**different live media**, not identical-payload trials or a causal latency result.
`collector_transport_bytes` counts actual binary callback bytes (including audio);
`collector_payload_bytes` counts verified, persisted decompressed bytes. Neither
includes Frida framing/metadata or network-level overhead.

### Measured comparison (2026-10-18)

A profiling baseline at 2880×1620 visible resolution acknowledged eight pairs over
14.967 s. Sixteen host sample audits totalled 376 ms, composition 104 ms and
present calls 200 ms. Device snapshot hashes totalled 2.877 s; local send calls
returned much earlier than host delivery. These measurements rule out host audit
and presentation as the dominant measured cost; they do not directly time the
asynchronous transfer queue.

| Transport/run | Visible lens size | Video/audio pre-EOF | Host video ack span | Binary callback bytes |
| --- | --- | --- | --- | --- |
| raw profiling baseline | 2880×1620 | 8 / 91 | 14.967 s | 225,466,368 |
| zlib | 2880×1620 | 8 / 15 | 11.390 s | 118,834,590 |
| LZ4 first attempt | 1920×1080 | 0 / 0 | failed queue-depth validation | 15,511,290 |
| LZ4 lower-resolution observation | 1920×1080 | 8 / 26 | 5.341 s | 56,743,806 |
| raw matched-settings observation | 2880×1620 | 8 / 93 | 15.832 s | 225,603,584 |
| LZ4 matched-settings observation | 2880×1620 | 8 / 122 | 13.696 s | 141,834,606 |

The final two runs have matching profile, sink deadline, requested window, sample
count, geometry and media times (0/67/134/200/267/334/400/467 ms). LZ4 reduced actual
binary callback bytes by **37.1%** and observed acknowledgement span by **13.5%**.
Those are descriptive comparisons of different captures, not general performance
or audio-quality guarantees. Pixel bytes before compression remain 224,225,280 in
both. Full-resolution LZ4 compression took 2.340 s total; zlib took 8.638 s in its
run. Native hashing and compression still block observer callbacks and perturb
playback. Raw is retained as the baseline; compressed modes are opt-in experiments.

Final LZ4 host audio peak pending was 14, with zero host rejection/retention/partial
bytes; 132 VQE outputs were observed and **10 were unforwarded**. The matched raw
run had peak 25, two host rejections and 110 unforwarded VQE outputs. These counts
have different native source populations and do not prove complete audio coverage.
The failed queue-depth attempt remains a failure; validation was not relaxed.

467 ms of source video still takes 13.696 s of host acknowledgement span. The
requested 25-second span was not reached. This is **not real-time playback**, and
it does not establish improvement over every earlier run (PR335's single final
observation was 13.087 s). Dummy output only; physical A/V testing stays deferred.
EOF/shutdown, source ownership and audio correspondence policy are unchanged.

## Identical-payload host replay (offline)

To separate host codec/collector cost from changing live camera content, replay
an existing private capture without opening the camera or attaching hooks:

```sh
python tools/reference_stream/replay.py /private/reference-run \
  /private/new-host-replay --repeats 3
```

The output directory must not exist. `replay.json` preserves each trial, its
failure, completed snapshot prefix, byte counts and same-host stage timings.
Optional system liblz4 is required for successful LZ4 trials; unavailable/failed
codecs are recorded as failures while the other trials continue. Exit status is
nonzero if any trial fails. A corrupt source fails before trials begin. Invalid
arguments or an existing output directory fail before writing a receipt.

All trials use the **same ordered original input and rendered snapshots** from
`events.jsonl`, not the earlier compressed wire packets. Every original payload
is size/SHA-256 verified before the experiment and again when read for each
trial. This verifies payload integrity only; replay does not rerun the native
crop/renderer/scheduler audit or authenticate the source. The report records a
corpus fingerprint for local experiment matching; keep it private with the
capture. Audio and unrelated metadata are not replayed. Bounds are 20,000 events,
32 MiB event JSON, 64 KiB per line, 32 snapshots, 12 MiB per snapshot, 240 MiB total
pixels and one to five repetitions. Only one snapshot is processed at a time.

The host applies raw, zlib level one and native system LZ4 compression, retaining
the same per-payload raw fallback policy as the producer. Every result passes
through the **real collector**, including bounded decompression, original hash
verification and buffered persistence. Temporary private blob/event files are
removed after each trial; only the report remains. The experiment does not
modify source files. New output directories are mode 0700; the CLI sets umask 077.

Codec order rotates each repetition. This exposes order variation but does not
eliminate cache, CPU scheduling or filesystem effects. Source read/hash time is
reported separately from host encoding. Collector callback time includes its
nested decompress/hash/write stages: **do not sum overlapping stages**. Writes
use flush, not fsync; this is not cold-cache or durable-storage benchmarking.
Raw encoding is effectively a no-op and its tiny duration is not a throughput
measurement. Host liblz4/zlib versions, memory copies and CPU differ from Android.

### Full-resolution same-corpus observation (2026-10-18)

Three trials per codec replayed the same 32 snapshots / 224,225,280 bytes from the
previous full-resolution LZ4 capture. All nine trials verified all 32 snapshots;
no raw fallbacks occurred. Times below are medians of per-trial stage totals,
not per-frame times. Binary bytes exclude metadata/framing and audio.

| Host codec | Binary bytes per trial | Host encode total | Collector callback total |
| --- | --- | --- | --- |
| raw | 224,225,280 | 0.068 ms (no-op) | 138.822 ms |
| zlib level 1 | 115,007,144 | 2,040.548 ms | 760.635 ms |
| LZ4 | 139,893,441 | 283.024 ms | 220.607 ms |

Collector decompression medians were 606.230 ms for zlib and 78.231 ms for LZ4;
collector hashing was about 90–92 ms across codecs. LZ4's binary payloads were
37.6% smaller than raw on this exact corpus, with additional host CPU cost. This
supports keeping raw as the baseline and using LZ4 for further device/transport
experiments. It does **not** identify the unmeasured asynchronous Frida/network
queue as the cause of the live delay or establish an Android optimization.

This tool measures neither Android encode/instrumentation nor Frida/network
transport, event projection, playback pacing, SDL/ffplay output or physical A/V.
Do not compare these host-only stage totals directly with the earlier live
acknowledgement spans. The real-time bottleneck remains unresolved; physical A/V
testing remains deferred.

## Opt-in asynchronous snapshot acknowledgement measurement

Add `--transport-acks` to a normal producer invocation to measure a **round trip**
for each original/rendered snapshot. This is disabled by default: acknowledgements
add messages and callback work and can perturb the instrumented run. Compare only
runs with matching options; do not silently mix enabled and disabled observations.

The device assigns a monotonically increasing snapshot ID and records its clock
immediately before `send()` (after copy/hash/compression). After bounded inflate,
original-byte SHA-256 verification, binary write/flush and metadata write/flush,
the collector posts that ID back to the script. The device records the callback
on its own monotonic clock. `benchmark.json.transport_acknowledgements` contains:

- `device.sent`: at most 32 small descriptors with device send-start, send-return
  and acknowledgement timestamps; **no payload buffers** are retained here.
- `device.pending_ids`: requests with no observed callback when source freezes.
  A missing device finish summary means pending state is **unknown**, not empty.
- `device_round_trips`: summaries of observed device-clock round trips; matching
  `transport_ack` records remain in the private event log.
- `host_posts`: callback-entry, persistence-completion, post-start and post-return
  timestamps on the **host** clock. Failed post attempts retain their verified
  prefix and `successful=false`; post return alone does not prove device receipt.

The round trip includes outbound Frida queueing/transport, collector processing,
reverse transport and device JavaScript callback scheduling. It excludes earlier
copy/hash/compression and later producer projection/audit/output. It cannot isolate
one of those costs, cannot be halved into one-way delay and is not physical latency.
No host timestamp is subtracted from a device timestamp. Persistence means buffered
write/flush, **not fsync**. The `send()` return is retained separately from receipt.

There is no wait, retry, throttle, credit protocol, payload dropping or relaxed
verification. Existing byte/sample/event limits and EOF retention are unchanged.
At source freeze the helper takes its pending snapshot and ignores later callbacks;
it does not drain transport or delay EOF to manufacture complete acknowledgement
coverage. Unknown/duplicate callbacks fail closed. Raw, zlib and LZ4 share the same
post-verification acknowledgement boundary. This is diagnostic instrumentation,
not a transport optimization or a real-time playback result.

### Synthetic device-transport observation (2026-10-18)

A private transport-only harness exercised the **same helper and real collector**
on the connected ARM Android Gadget, with no native hooks, camera preview,
producer projector or host output backend. It generated deterministic raw bytes
once, hashed them once before timing, then emitted a single synchronous RPC burst.
This intentionally permits queued transport and callback scheduling contention;
it does not reproduce live renderer pacing or compare codecs.

All eight 2,048-byte messages were verified and acknowledged: local send calls
totalled 3.34 ms; first-send-to-last-ack spanned 33.14 ms. A separate burst of
32 messages of 7,007,040 bytes (224,225,280 bytes total) was also fully verified and
acknowledged with zero pending IDs. Local send calls totalled **1.015 seconds**,
while first-send-to-last-ack spanned **25.303 seconds** on the device clock. Device
per-snapshot RTT p50/p95/max were 12.338/23.709/24.311 seconds. Host callback work
(including acknowledgement posts) totalled 176 ms, including 109 ms hashing and
60 ms buffered payload persistence; those nested costs are not additive.

This exposes substantial queued/asynchronous delay outside the measured local
send calls and collector work **in this burst experiment**. It does not separate
network throughput, Frida serialization/queues and device callback scheduling,
and is not a causal explanation of every earlier live run. No throughput or
real-time improvement was implemented. The harness unloaded/detached and removed
its caller-owned forwarding; the tablet remained on its launcher. Only aggregate
results are public; private binary logs remain local. Physical A/V remains deferred.

## Controlled synthetic device codec/transport probe

`tools/reference_stream/device_probe.py` is a separate, development-only POSIX
experiment. It attaches to an **already available** ARMv7 Gadget through a
caller-owned forward; close the camera preview first. It never launches/unlocks
apps, installs hooks, reads app-native offsets/media, opens cameras or starts
output backends. Since it calls only system codec/clock exports and generates its
own bytes, it does not require or claim the live producer's exact app ELF profile.
The ARMv7 four-byte `size_t` ABI is still required for the shared codec wrapper.
Optional host Frida and system liblz4 remain research dependencies only.

```sh
python tools/reference_stream/device_probe.py \
  --endpoint 127.0.0.1:27049 --output /private/new-device-probe \
  --pattern mixed-v1 --size 7007040 --count 32 --repeats 3 --timeout 60
```

Forwarding and preview state remain caller-owned; remove the forward afterwards.
The output directory must be new. The CLI uses umask 077 and an exclusive mode-0700
directory. Per-trial temporary pixel/config/log files are removed after collection;
`probe.json` retains measurements and failure evidence, not synthetic binary copies.

### What stays identical

The host and device independently generate and SHA-256 check the same deterministic
buffer: a fixed-seed unsigned 32-bit LCG, with `mixed-v1` replacing every third
4 KiB block with a striped pattern. `striped-v1` uses only stripes and `noise-v1`
uses only the LCG's high byte. These are **synthetic compressibility controls, not
camera frames**. One generated buffer is repeated within each burst; no generation
or initial hash cost is counted inside the device burst. All codecs and repetitions
use the same pattern, size, count and host-expected hash. The seed and recurrence
are versioned in the generator source; host/device byte identity is also tested.

Each trial creates a fresh hook-free script and sends a single synchronous RPC
burst through the **same `snapshot-codec.js` and `transport-ack.js` helpers used by
the live producer**. Raw, zlib level one and LZ4 default are tried with rotating
first-codec order, one to three repetitions (at most nine trials). Compression still
falls back to raw if it would not shrink the buffer. The real collector verifies
and flushes original bytes before posting IDs; additionally the probe checks each
message against the host-generated synthetic identity. These records have no native
headers and do not enter the projector/crop audit; passing this probe is not native
audit proof. Both standalone and batched
acknowledgement metadata are accepted only for a successfully posted, unique ID.

### Bounds, failures and interpretation

Each trial permits at most 32 messages, 12 MiB per message and 240 MiB uncompressed
total. `--timeout` must be finite 5..60 seconds and includes attach/setup/generation,
not just the burst. Every trial runs in a separate process group with a parent
watchdog: interrupt, terminate and kill/reap fallbacks bound cleanup. A scoped
supervisor SIGINT/SIGTERM handler is installed before child creation and records a stop
request without interrupting process-handle ownership. Finite waits observe the
request and run the same bounded cleanup/cancel-prefix path; the prior handler is
restored after the trial. This also covers Ctrl-C or SIGTERM received while launching the
isolated child, not only during its steady-state wait. A timeout
aborts the remaining matrix rather than starting another potentially contaminated
trial. Normal codec failures remain failed results and other codecs can still run.
Cancellation stops the experiment and retains completed results plus the current
worker's available verified-prefix checkpoint.

The collector atomically checkpoints verified-prefix counts, host post attempts
and observed device round trips while the worker runs. If it dies without a final
receipt, those counts survive; absent device finish data means pending state is
**unknown**, not zero. A final device receipt preserves pending IDs, per-send
start/return/ack timestamps, burst start/return and per-message compression spans.
Host collector spans remain on the host clock. A post return is not device receipt.
Failed/partial results are never relabelled successful to complete the matrix.

The synthetic worker deliberately waits for its finite acknowledgement set (or
its deadline); this is **not the live producer's EOF policy**, which still freezes
without draining. Device callbacks can queue behind the synchronous burst and
compression. Round trips and nested spans cannot be summed into physical latency,
and RTT must not be halved or combined with host-clock timestamps. Buffered flush
is not fsync. Rotating order exposes but does not eliminate cache, thermal,
CPU-load and network variation; it is not randomization. These measurements can
compare identical-byte configurations, not isolate every network/Frida/scheduling
cost, prove representative camera compression or establish real-time playback.

### Identical-byte Android comparison (2026-10-18)

On the connected ARMv7 Gadget, three rotated trials per codec each verified and
acknowledged all 32 messages, with zero pending IDs. Each message repeated the same
host/device-verified `mixed-v1` buffer of 7,007,040 bytes: 224,225,280 original bytes
per trial. Median **device burst-start to last acknowledgement**, including device
compression but excluding generation/initial hash, was:

| Codec | Binary bytes per trial | Median burst-to-ack | Median compression wrapper spans |
| --- | ---: | ---: | ---: |
| raw | 224,225,280 | 21.148 s | 0 s |
| zlib level one | 151,469,216 | 17.590 s | 16.462 s |
| LZ4 default | 154,705,664 | 14.955 s | 2.952 s |

Compression spans include allocation/input-copy/output-copy, not only the native
codec call; compression, transport and acknowledgements overlap. Do not sum these
columns. The raw trial times were 21.148/20.474/21.193 s, zlib
18.474/17.590/17.554 s and LZ4 15.446/14.955/14.828 s. LZ4 used **31.0% fewer binary
bytes**, with a **29.3% lower median observed burst-to-ack span** than raw in this
specific rotated experiment. These are descriptive controlled-synthetic results,
not representative camera compression, an isolated network speed or a demonstrated
live playback improvement. Defaults remain unchanged.

A separate two-message, 9,000-byte `noise-v1` control verified raw fallback for both
compressed codecs; all three control trials passed. The successful small mixed
control also passed all codecs. An earlier small-control attempt exposed the
standalone-acknowledgement collector issue and is retained as failed evidence; the
fix and regression tests preceded the full comparison. No native hooks, camera
preview or physical output were used. Scripts unloaded/detached, forwarding was
removed and the tablet remained at its launcher. Physical A/V remains deferred.
