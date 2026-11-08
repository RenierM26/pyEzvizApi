# Guarded media runtime preflight (development only)

`tools/local_av_runtime.py` checks the proposed Linux/WSL interpreter before a
retained-media control or attended handoff. It does not acquire a camera, contact
an account service, initialize SDL, open output devices or install packages.
Neither importing nor running it performs live playback.

```sh
/path/to/proposed/runtime/bin/python3.12 -I tools/local_av_runtime.py \
  --expected-package-sha256 EXPECTED_SOURCE_DIGEST \
  --receipt fresh-preflight.json
```

Generate the expected digest from the clean source checkout during packaging,
not by trusting whatever package the target interpreter happens to import:

```python
from pathlib import Path
import runpy
probe = runpy.run_path('tools/local_av_runtime.py')
expected = probe['package_fingerprint'](Path('pyezvizapi'))
```

The fingerprint binds sorted relative Python-source filenames, each file's
SHA-256 and `py.typed`, with finite file/byte bounds and no symlinks or bytecode.
It identifies package source, not just a shared version string. It is not a
complete distribution/bundle signature. Continue verifying the archive manifest,
all tool/runtime files and expected source commit independently. Do not derive
the expected digest from a stale editable installation.

## Checks and scope

The supervisor starts the same executable with `-I`; environment/user-site/CWD
imports cannot silently provide missing library dependencies. Isolated mode
still uses the interpreter's installed site-packages, including installed `.pth`
configuration. This is an identity/dependency check, not a Python security sandbox.

The worker requires Linux/WSL, isolated Python >=3.12, matching installed package
source, and actual imports/distribution metadata for requests, XML, AES,
cryptography, MQTT and PyAV. It checks HEVC/AAC decoding and MPEG-PS demuxer
availability, imports the guarded tool graph, decrypts a small public synthetic
fixture using a public test key, and creates/verifies/closes a 12-byte sealed
memfd using the actual kernel seals. It loads SDL and resolves required symbols
without calling initialization. It queries ffplay's raw-s16le help (not playback)
and detects its actual explicit mono-input option rather than assuming Windows
and the validation host use the same option.

The report records the interpreter/isolation, package and entrypoint identities,
distribution/native-library versions, synthetic crypto hash, sealed-store cleanup,
SDL library and raw-input capability. Failure records the stage and error class,
plus a sanitized missing module name where available; it does not echo exception
messages, credentials or source media. Failed identity/import checks stop before
later capabilities are probed. The synthetic key is not a camera credential.

The receipt is exclusive-create. The whole worker has a finite timeout (default
15 seconds, configurable >0..30); its process group is killed and its worker reaped on return,
failure, timeout or cancellation, including owned helper processes. ffplay's help
query has a separate 3-second bound. Worker result size/profile/identity/exit
status are checked before acceptance. Import/native work is isolated from the
supervisor but is not a throughput or process-RSS guarantee.

Success is only `ready-for-offline-control` under profile
`guarded-media-runtime-preflight-v1`. `network_acquisition`,
`output_devices_opened` and `physical_av_sync_measured` remain false. Missing
modules, an unexpected installed checkout, absent codecs/seals/SDL/PCM support,
worker failure or timeout cannot yield readiness.

## Before an attended test

Build the project wheel and resolve its full declared dependencies into a fresh
isolated staging runtime, retaining package metadata and pinned file manifests.
Keep the original runtime and operator machine unchanged; do not disable package
manager protections or install at operator-test startup. Use supported explicit
packaging targets or a separately managed build environment. Check dependency
consistency using that interpreter, then run this preflight with `-I` and the
expected checkout digest. Extract and repeat against the final staged archive.

After readiness, still decode/replay the retained source with that exact runtime
and compare original PTS, all pixel/PCM hashes, targets, accepted-prefix status,
EOF/drains and ownership with the independent control. A working import is not
sustained output, valid live acquisition, real Windows picture/audio or measured
physical synchronization. Keep real-device validation separate from dummy output.
The next Windows handoff must bind this receipt, source/commit, dependencies and
output result in a fresh session; this PR does not publish a launcher or start a
camera.
