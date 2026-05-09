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

## Notes

- APKs and decompile output are ignored by git.
- The wrapper runs the container as the current user so output files are editable from the host.
- The container is non-privileged and mounts only this repository at `/work`.
