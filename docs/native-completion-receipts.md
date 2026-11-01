# Generation-specific native completion receipts

This is part of the unpublished shared-lens spike, not the unchanged draft PR397.
It supplies the library boundary needed by the separate
[finite HLS host proposal](ha-finite-completion-proposal.md).

## Public library surface

```python
from pyezvizapi.native_completion import NativeMediaCompletion

result: NativeMediaCompletion | None = output.completion
if result is not None:
    print(result.source_generation, result.subscription_generation)
    print(result.video_units, result.audio_units)
```

`NativeMediaCompletion` and each `NativeTrackCompletion` are frozen, slotted
snapshots. The tuple of tracks contains original container track ID, demux index,
kind, codec and accepted access-unit count. `source_generation` is an opaque
owner-local identity, not a camera ID, credential, capability or capture UTC.
The source generation is available before acquisition and shared by its declared
outputs; replacement outputs increment their subscription generation without
changing the physical source generation. A different owner has a different identity.

Counters advance at the existing owner's successful selected-packet mux boundary.
They count selected encoded PyAV packets, not input transport packets, TS chunks,
decoded pictures or HTTP writes. A host adapter must establish one-to-one access
unit correspondence through the selected container/relay before using these as
receiving access-unit counts. No second demux, fixture-derived expectation,
decoder, media cache or acquisition is introduced.

## Completion is stricter than source EOF

`completion` is `None` until all of these hold:

- The authoritative physical source verified its declared finite end and joined
  its worker/canceller with successful source and iterator cleanup.
- This exact subscription completed without error or shutdown timeout.
- Every published output byte was read, no credits/queued bytes remain, and no
  output bytes were abandoned/discarded.
- Every explicitly selected track has accepted media. Explicit video-only output
  has zero audio units; requested-but-missing audio is not silently successful.

The property is a nonblocking snapshot: it never waits, joins, repairs, retries,
opens a source or authorizes a new session. A successful immutable result remains
historical completion metadata after a normal fully-read close, not permission to
restart. The physical multi-output session itself always returns `None`; query
its declared outputs rather than confusing aggregate status with delivery.

Cancellation, unread/draining output, failed source/mux/cleanup, uncertain join,
retired partial subscriptions and never-requested lenses cannot inherit a
sibling's successful completion. Replacement counts start at zero and refer to
that replacement's actual original-IDR suffix. Owners retain only bounded
per-track counters/current snapshots, not growing retired packet histories.

The existing JSON-safe diagnostic receipt now includes detached
`accepted_access_units`, `source_generation` and `subscription_generation` fields.
Diagnostic counts may be partial and are not a substitute for the typed
`completion` property. Mutating a diagnostic receipt cannot change owner track
identity or the immutable completion snapshot.

## Normal HA adapter, negotiated host boundary

For explicit finite **group/lens** recordings only, the validation camera can
attach `GroupFiniteDelivery` to its normal `async_create_stream` result. It requires
the host's exact `FINITE_SOURCE_COMPLETION_CONTRACT == "source-access-units-v1"`,
count type, prepare/confirm methods and synchronous revoke method. Stock HA and
live-source behavior remain unchanged when this experimental contract is absent.
That compatibility path is not certified complete finite-HLS delivery.

The adapter binds the physical owner object, exact output handle, source and
subscription generation and lens capability generation. Its sole background
observer reads public completion snapshots; it does not inspect raw private
library counters, count HA input or reconstruct success from receipt dictionaries.
After the host is active, it confirms the host handle with the snapshot's counts.
The host independently checks receiving EOF and counts, publishes its buffered
fragment, then ENDLIST. An early clean relay EOF is therefore not owner completion.

Before awaited provider teardown/rearm, the adapter synchronously revokes host
publication and then joins its own observer task. It does not own/join the native
source; existing group/admission lifecycle remains authoritative. A stale source,
output, generation or capability never confirms an old host handle.

There is no current live or single-entry finite-host certification. The generic
single-output library exposes completion metadata too, but this host adapter is
scoped to the tested explicit physical group/lens composition. No unnegotiated
FFmpeg option, private HA monkeypatch or implicit fallback acquisition is added.

## Acceptance and remaining gates

Run library lifecycle tests, the complete library suite and the extracted-wheel
HA validation suite after this runtime change. Repeat actual normal config-entry /
camera / relay LL-HLS and non-LL HLS using only installed public library metadata
and the extracted normal adapter. Independently audit HTTP fragment sample clocks,
counts and NAL/config/AAC bytes against retained source oracles, preserving the
one-source/demux acquisition budget and cancelled-subscription history.

The host API, first-clock policy and FFmpeg parser fix remain separate review
proposals requiring maintained source/FATE/HA/platform acceptance. The native
recording tests do not establish browser rendering, supported-client HEVC,
physical A/V, live/battery behavior, broader startup/IRAP/wrap/topology or soak.

### Recorded acceptance milestone

The committed runtime/package snapshot is `72c8a5645a38ea20b8426bfd734d42fc47455c25`.
Its complete library suite passes 5020 checks in 102.35 seconds with 90.39%
coverage. Static validation passes Ruff, library/HA mypy, Pyright and Twine.
The wheel/HA zip are built from that clean commit; this pass makes no repeated
build/reproducibility claim.

Installed-wheel/extracted-adapter verification passes 149 HA checks plus eight
optional real-relay checks, and 131 installed native-library checks: 288 distinct
checks across those runs. The first HA collection attempt lacked a copied
generated-fixture helper; it was corrected in the isolated harness, not production
code. All 163 named HA dependency pins and nine installed HA stream files remain
unchanged. A fresh Python3.12 base-wheel environment verifies lazy completion
without PyAV or HA installed.

Two additional actual normal camera/provider tests, LL-HLS and non-LL HLS, pass
using the installed wheel, extracted normal adapter and versioned host proposal
`808667ef4ce79df0a794120294bed061d0f929b8`. No private source-count wrapper or
second demux supplies their authorization. Each uses one factory, one input demux
and 8840 decrypt feeds. Public completion counts match every delivered primary
1783-video/1857-AAC and replacement 1663/1731 sample. The stopped subscription
has no completion snapshot and remains partial.

Independent source, wire and MP4-box/PyAV audits preserve all delivered PTS/DTS,
video NAL/config and AAC bytes. A/V phase remains -11/240000 seconds within the
unchanged 1/16000-second budget. Both final playlists have ENDLIST/no preload
hint, terminal requests keep worker attempts at one, physical cleanup joins,
admission returns to zero and owned relay processes exit. These real-path tests
still need the child-only diagnostic parser proposal; they are not stock-host
or maintained FFmpeg-build certification. The separate host contract/revocation
controls pass 85 checks.

The remaining host-contract delta adds an explicit version marker and a public
synchronous revoke call, closing the await-before-cancellation race for normal
integration teardown. Stable-entity browser HLS/WebRTC and supported HEVC-client
acceptance, maintained upstream/platform integration and broader live/physical
gates remain next. No library PR/head push, release or deployment was made.
