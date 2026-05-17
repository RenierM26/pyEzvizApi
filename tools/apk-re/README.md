# APK reverse engineering lab for pyEzvizApi

Reusable Docker tooling for decompiling and inspecting the EZVIZ Android APK while keeping generated artifacts out of the source tree.

## Layout

- `discovery/apk/in/` — put APK files here.
- `discovery/apk/out/` — decompiled output and reports land here.
- `discovery/apk/work/` — scratch space.
- `tools/apk-re/Dockerfile` — reverse-engineering image.
- `tools/apk-re/apk-re-build` — build the image.
- `tools/apk-re/apk-re-decompile` — decompile one APK.
- `tools/apk-re/apk-re-shell` — open an interactive shell in the toolkit.

## Included tools

Java/APK:

- `apktool` for resources + smali
- `jadx` for Java/Kotlin decompilation
- `aapt`, `apksigner`, `zipalign`
- `androguard` Python package

Native `.so` libraries:

- `file`, `readelf`, `nm`, `objdump`/`llvm-objdump`
- cross-binutils for common Android ABIs
- `gdb-multiarch`, `strace`, `ltrace`
- `lief`, `capstone`, `keystone-engine`
- `strings`, `ripgrep`, `yara`, `jq`
- Frida hook templates under `tools/apk-re/frida/` for live app tracing

## Usage

From the repository root:

```bash
# Build the image once
./tools/apk-re/apk-re-build

# Copy/drop an APK into discovery/apk/in/, then decompile it
./tools/apk-re/apk-re-decompile discovery/apk/in/ezviz.apk ezviz-current

# Start an interactive lab shell
./tools/apk-re/apk-re-shell
```

After decompilation, start with:

```text
discovery/apk/out/<name>/reports/apk-summary.md
discovery/apk/out/<name>/reports/native-libraries.md
```

Useful searches:

```bash
rg -n "sign|signature|token|nonce|encrypt|decrypt|lapp|api/" discovery/apk/out/ezviz-current/jadx discovery/apk/out/ezviz-current/apktool
rg -n "pyezviz|ezviz|hik|lapp|auth|accessToken" discovery/apk/out/ezviz-current
```

Generate a Retrofit endpoint inventory from JADX output:

```bash
./tools/apk-re/apk-re-shell extract-retrofit-endpoints \
  discovery/apk/out/ezviz-current/jadx/sources \
  --known-api pyezvizapi/api_endpoints.py \
  --output discovery/apk/out/ezviz-current/reports/retrofit-endpoints.md
```

Inspect one extracted native library:

```bash
./tools/apk-re/apk-re-shell inspect-so discovery/apk/out/ezviz-current/libs/arm64-v8a/libSomething.so
```

The generated `*.strings.txt`, `*.symbols.txt`, and `disassembly.txt` files are often the fastest way to locate JNI bridges, signing logic, crypto constants, endpoint strings, and protocol names.

Trace the official app's encrypted stream path with Frida:

```bash
./tools/apk-re/frida/run-ezviz-stream-hook
```

By default the wrapper attaches to the USB Frida device (`frida -U`). For a
network Frida server, pass the host:

```bash
EZVIZ_FRIDA_HOST=192.0.2.56:27042 ./tools/apk-re/frida/run-ezviz-stream-hook
```

Check target readiness before capture:

```bash
./tools/apk-re/frida/check-ezviz-frida-target 192.0.2.56
```

After reproducing live view in the EZVIZ app, pull the bounded binary samples:

```bash
./tools/apk-re/frida/pull-ezviz-hook-dumps com.ezviz /tmp/ezviz-hook-dumps
```

The stream transform hook logs `setSecretKey` calls, `PlayM4`/`SystemTransform`
input boundaries, and the native `IDMXAESDecryptFrame` /
`IDMXAESDEcrpytFrameCom` before/after buffers. It writes bounded binary samples
under the EZVIZ app external files directory so raw `pyezvizapi` captures can be
compared with the official native transform path. Key material is redacted by
default in the hook logs.

Summarize native before/after transform pairs:

```bash
./tools/apk-re/frida/compare-idmx-dumps /tmp/ezviz-hook-dumps
```

Trigger a cloud-storage clip download through the gadget-loaded app:

```bash
./tools/apk-re/bin/cloud-video-native-download \
  --token-file ../secrets/ezviz_token.json \
  --serial BB5130008 --channel 1 --seq-id 9713217646 \
  --output discovery/cloud-captures/clip.ps \
  --encrypted-output discovery/cloud-captures/clip.tmp \
  --adb-serial 192.0.2.56:41653 \
  --frida-host 127.0.0.1:27046
```

This diagnostic wrapper prepares the temporary JSON handoff, verifies the pulled
`.tmp` size against `fileSize`, and removes the temporary handoff from the
device. By default it uses the local Python PS/NAL transform after the app
downloads the encrypted bytes. To compare Android `TransformUtils.trans(...)`,
add `--transform native`.

For lower-level manual experiments, the input JSON contains the clip descriptor
and `/v3/cameras/ticketInfo` ticket. Do not commit it. The script writes
`<outputName>.tmp` under the EZVIZ app external files directory:

```bash
adb -s 192.0.2.56:41653 push /tmp/ezviz-cloud-download-input.json \
  /sdcard/Android/data/com.ezviz/files/ezviz-cloud-download-input.json
frida -H 127.0.0.1:27046 -n Gadget \
  -l tools/apk-re/frida/ezviz-trigger-cloud-download.js
```

To run the app's PS transform/decrypt step manually, add the camera secret as
`secretKey` in the same temporary JSON and run:

```bash
frida -H 127.0.0.1:27046 -n Gadget \
  -l tools/apk-re/frida/ezviz-transform-cloud-download.js
```

## Notes

- APKs and decompile output are ignored by git.
- The wrapper runs the container as the current user so output files are editable from the host.
- The container is non-privileged and mounts only this repository at `/work`.
