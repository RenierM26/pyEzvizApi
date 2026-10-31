# Local HA validation artifacts, not a production release

The temporary `ezviz_native` integration is distributed separately from the
library wheel. It does not replace official HA integrations or HA's managed
relay. Retained-media tests do not authorize a camera acquisition.

## Build a reviewable snapshot

Commit or isolate repository changes first. With Python 3.12+ and `uv` installed,
run from the checkout (choose a new output directory outside it):

```sh
python tools/build_ha_validation.py --output /tmp/ezviz-validation-build
```

The builder uses only the clean Git HEAD, not ignored/untracked credential or
capture files. It builds a wheel and sdist with setuptools 80.9.0 / wheel 0.45.1,
sets `SOURCE_DATE_EPOCH` to the commit time, and assigns a local-only version
`<project-version>+ha.relay.g<commit>`. The repository version is not changed.
It also creates a sorted, fixed-timestamp zip containing the tracked integration
Python/JSON files under `custom_components/ezviz_native/` and its license.

`manifest.json` records the exact commit, version, build-backend constraints,
sizes and SHA-256 digests. No relay binary, credential, retained capture or
installation action is included. Build logs and the verification results should
be kept alongside the manifest. Rebuild into a second directory to compare
artifact hashes; this does not assert that dependency resolution is permanently
reproducible or that a different build toolchain will emit identical bytes.

## Verify the installed wheel, not checkout imports

Create a fresh base environment and install the exact wheel with dependencies.
It must not contain Home Assistant or PyAV:

```sh
uv venv --python 3.12 /tmp/ezviz-wheel-smoke
uv pip install --python /tmp/ezviz-wheel-smoke/bin/python /tmp/ezviz-validation-build/dist/*.whl
uv pip check --python /tmp/ezviz-wheel-smoke/bin/python
/tmp/ezviz-wheel-smoke/bin/python -I tools/check_installed_native_wheel.py
/tmp/ezviz-wheel-smoke/bin/python -I -m pyezvizapi --help
/tmp/ezviz-wheel-smoke/bin/pyezvizapi --help
```

The offline check requires imports to resolve within that environment, verifies
the typing marker and native clock/owner API, and closes a lazy owner without
calling its source factory. No HA/PyAV eager import is permitted. The normal CI,
manual release check and publish build use this check; running the script does
not publish a release. Save the installed dependency versions as separate
environment evidence, because base runtime requirements are not a lockfile.

For the streaming extra, validate the exact wheel against the target HA/PyAV
pins in an isolated environment. Do not force-install incompatible versions or
silently alter HA's dependency constraints. Extract the integration zip into an
isolated test configuration and run the real HA integration tests against those
extracted files plus the installed wheel. Source-checkout tests alone do not
prove that artifacts contain the required runtime files.

## Relay dependency and release gates

Stock go2rtc 1.9.15 does not implement the private source-clock, finite-EOF and
one-shot policy APIs used by the reviewed local relay prototype. A local binary
build is not an upstream-supported dependency. Keep the relay source commit,
patch series, Go toolchain, binary digest and exact default/opt-in race and media
test receipts separate from the Python artifact manifest. Do not replace HA's
managed binary as a packaging step.

Before upstream release or live deployment, resolve maintained API/dependency
ownership, supported-client HEVC video playback, broader live clock/network and
restart conditions, and separately scoped finite attended camera/physical A/V
acceptance. Explicit session re-arm is not seamless automatic reconnect. Failed
sources must remain failures; clean finite EOF must retain all accepted media.
No codec conversion, timestamp repair, queue increase or new camera acquisition
is justified merely to make packaging checks pass.
