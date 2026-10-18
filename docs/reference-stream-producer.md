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
