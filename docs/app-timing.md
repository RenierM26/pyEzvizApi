# Experimental app-compatible HEVC/AAC timing

This is an **explicit parsed-frame API**, not a new `save_clip` flag or automatic
capture policy. Existing transport/remux defaults and `native_shared_clock` are
unchanged. Arbitrary RTP epochs, encrypted PS, and media decoding are not accepted
or inferred by this API.

## Use

```python
from pyezvizapi import AppPlaybackClock, copy_app_timed_frames_to_mpegts

clock = AppPlaybackClock(mode="playback")
# clear_frames is caller-parsed HEVC access units and ADTS AAC frames,
# each represented by AppTimedFrame with unwrapped integer source milliseconds.
with open("app-relative.ts", "wb") as output:
    copy_app_timed_frames_to_mpegts(
        clear_frames, output, clock=clock,
        video_stream_ids=(0xE0, 0xE1), audio_stream_id=0xC0,
    )
```

`AppTimedFrame` fields:

- `stream_id`: declared HEVC video PES ID or AAC audio PES ID.
- `clock_id`: explicit playback clock identity. Audio/video must differ.
- `source_ms`: unwrapped integer timestamp from the identified source parser.
- `duration_ms`: metadata AAC frame duration; video floor(1000 / frame rate).
- `data`: one clear encoded access unit, including Annex-B HEVC or ADTS AAC framing.
- `picture_id`: optional original source-picture identity, not the rewritten output
  time. Paired lenses may deliberately share a video clock and picture identity.
  Never share these across unrelated camera sources with coincident timestamps.

Callers own parsing, decryption, startup selection, codec verification and source
counter conversion/unwrapping. The helper does not certify that arbitrary bytes
are valid HEVC/AAC. A clock profile is not a substitute for these contracts.

## Clock behavior

1. The first accepted frame establishes each track's origin.
2. Candidate time is source time minus that retained origin.
3. Backward candidates or jumps **greater than** the configured limit advance the
   previous output by one frame duration. Equality and ordinary gaps remain.
4. A paired picture reuses the cached corrected video timestamp rather than
   advancing once per lens. This is opt-in via explicit source identity.
5. Retain the clock through seeks and file/record boundaries. `clock.reset()` is
   for a new playback session, not every UI/native decoder reset.

Observed profile defaults are 17000 ms for live and 1500 ms for playback; these
are not universal firmware constants. Supply or update `max_interval_ms` when
using an explicitly supported configuration. No fixed 138 ms AV correction, VQE,
wall-clock synchronization, drift correction, frame dropping or silence is added.

To start recording later, consume the earlier startup frames using
`clock.timestamp_ms(frame)` **before** passing the selected later frames to the
remux helper. Do not feed the same selected frame twice. The mux helper preserves
session-relative times; it does not re-zero each track at the file cut. The PS
iterator is also exposed as `app_timed_mpegps_payloads` for explicit downstream use.

Source-preserving archival timelines and app-compatible playback are different
policies. This profile is not proof of physical screen/speaker synchronization.

## Evidence and boundaries

A payload-free sanitized oracle checks 4173 state transitions from native live/SD
playback and two seeks, including paired-lens reuse and configured repair. Eleven
pre-codec warmup observations are intentionally excluded. Original-ARM offline
boundary controls independently verified strict threshold comparisons and frame
steps. Tests also exercise invalid inputs and PES continuation framing.

The observed scope is HEVC/AAC from an H9c path in the official app. Other codecs,
cloud seek, raw counter wrap conversion, missing-source transitions and native
reset modes beyond the observed UI seek path require separate validation. The
package does not include private camera footage, credentials or native binaries.

The draft parsed-frame entry point intentionally avoids claiming end-to-end
transport integration. Follow-up capture integration must carry pre-selection
origins and stable source/picture identity, rather than rebasing the first packets
remaining after trimming. This must be established per transport before wiring a
high-level capture flag.

## Private real-media integration check

A retained SD clap export supplied clear encoded payloads. Original source epochs
and pre-recording warmup metadata came from the native trace. The continuous
clip was restored to source-picture delivery order before calling the frame API;
sorting across seek epochs is not supported. Both lenses and AAC were remuxed
without re-encoding. All 835 decoded video presentation timestamps and 437 AAC
packet timestamps match the reference exactly; all decoded frame/sample hashes
also match. Two initial missing-reference warnings are inherited from the
reference boundary, not new errors. No private payloads are in this repository.

This checks the parsed-frame remux path, **not** direct decryption of the retained
raw encrypted live stream or automatic transport selection. The earlier raw-live
video extraction issue is not fixed by this timing feature.
