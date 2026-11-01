# HA full development qualification and finite publication fixes

The separate host review now has complete local script/setup environments, not
just runtime overlays. Both full HA2026.10.4 baseline/candidate checkouts use
Python3.14.9 and1691identical unique installed package versions. Build tools for
one native development dependency were extracted locally; no global install,
Python dependency skip or production change was used.

## Development findings

The earlier133-case runtime/component review missed four Mypy errors and a
Pylint warning. The updated host proposal:

- Tracks Segment publication independently of provider iterable truthiness.
  Empty iterators can publish once; removed providers cannot authorize a second
  publication. Existing live provider collections retain their behavior.
- Rejects unknown terminal duration explicitly before end arithmetic/publication.
- Keeps the reentrant callback state recheck in a separately locked helper.
- Accurately types optional durations and native AVRational/Fraction metadata;
  no packet clock or payload is converted.
- Uses two narrow, justified Pylint suppressions for demonstrated BytesIO.closed
  descriptor/Cython-export inference limitations, not global disabled rules.

Three new cases reproduce failures before the fix; a fourth verifies callback
revocation. Runtime core.py, finite.py and worker.py now differ from808667e;
previous host hashes must not be reused. Library runtime72c8a5645a38, the rebuilt
FFmpeg and relayfeea11a remain unchanged. PR397 is not expanded or pushed.

## Evidence and limits

- Baseline80stream tests, scoped Mypy9files and source/tests Pylint pass.
- Candidate137stream tests, scoped Mypy10files and source/tests Pylint pass.
- All13CI-style general/security/generator hooks pass. Mypy/Pylint are explicitly
  skipped in that hook stage and run separately on the changed stream component,
  matching CI's partial-integration structure.
- Literal baseline all-files Mypy fails on an existing explicit .py/.pyi duplicate;
  monolithic Pylint18821files was stopped before exhausting this VM's memory.
  Full-repository type/lint and platform CI are not claimed. Do not repeat that
  unbounded scan on the shared VM as a substitute for the scoped comparison.
- Exact extracted patches/helper pass98clock-only,137combined and57source-binding
  cases; those57overlap137. All20resulting source/test hashes match.
- Renewed no-preload normal-entry LL/nonLL HLS2cases pass37.99s with4existing
  aiohttp warnings. One source/demux and8840decrypt feeds per case; complete
  primary1783HEVC/1857AAC and replacement1663/1731, stopped sibling partial.
  Independent HTTP/sample/clock/NAL/AAC/RTP audits pass, A/V phase-11/240000s
  within unchanged1/16000s. ENDLIST/no hint/no restart, joined/admission0/relay0
  and no owned relay remaining pass. No live-camera test was run.

Still required: human/current-dev review, maintainers' full CI/platform gates,
maintained FFmpeg/PyAV/HA/relay support, real HEVC frontend, broader source/topology
and separately bounded attended hardware/physical A/V acceptance. These remain
uncommitted host review inputs; no upstream issue, PR or comment was submitted.

[Findings and updated source-only review package](https://bookstack.home.moor.co.za/books/home-infrastructure/page/ezviz-full-development-checks-and-publication-fixes-2026-11-01).
