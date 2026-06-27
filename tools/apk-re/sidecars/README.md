# Android HCNetSDK sidecars

This folder contains source/reference material for tiny `app_process32` probes
used during owner-run EZVIZ Android tracing.

## DVR Config Probe

`DvrConfigProbe.java` logs in through the EZVIZ app's `HCNETUtil.s(...)`, calls
read-only `NET_DVR_GetDVRConfig`, and prints the returned raw buffer as hex unless
the launcher is run with `--no-dump-output`. Command `1006`
(`NET_DVR_USER_V30`) is handled through the app's neutral `NET_DVR_Login_V30`
and object-style `NET_DVR_GetDVRConfig` path so it matches the RN password
update flow without dumping user-table contents. The
checked-in smali source under `smali/` is the buildable version used by the
current APK reverse-engineering image, because that image has apktool/smali but
not `javac`/`d8`.

Build the generated DEX with:

```bash
tools/apk-re/bin/build-dvr-config-sidecar
```

The generated `dvr-config-sidecar.dex` is ignored by git.

The runtime launcher is:

```bash
tools/apk-re/bin/hcnetsdk-dvr-config-sidecar \
  --adb-serial 192.0.2.56:36191 \
  --target-ip 192.0.2.30 \
  --password "$EZVIZ_PASSWORD" \
  --command 1067 \
  --channel 1 \
  --out-size 512
```

For command-port frame capture, route the sidecar through the included reverse
proxy:

```bash
tools/apk-re/bin/hcnetsdk-dvr-config-sidecar \
  --adb-serial 192.0.2.56:36191 \
  --target-ip 192.0.2.30 \
  --password "$EZVIZ_PASSWORD" \
  --command 1067 \
  --channel 1 \
  --out-size 512 \
  --proxy-target 192.0.2.30:8000
```

For potentially sensitive config buffers, suppress the returned buffer and log
only client-to-server proxy frames:

```bash
tools/apk-re/bin/hcnetsdk-dvr-config-sidecar \
  --adb-serial 192.0.2.56:36191 \
  --target-ip 192.0.2.30 \
  --password "$EZVIZ_PASSWORD" \
  --command 307 \
  --channel -1 \
  --out-size 1024 \
  --no-dump-output \
  --proxy-target 192.0.2.30:8000 \
  --proxy-log-directions c2s
```

The launcher stages the DEX and the EZVIZ `armeabi-v7a` native libraries under
`/data/local/tmp/ezviz-dvr-config-sidecar`, then runs:

```text
/system/bin/app_process32 /system/bin DvrConfigProbe ...
```

If `tools/apk-re/sidecars/dvr-config-sidecar.dex` has not been built yet, the
launcher falls back to the known-good scratch DEX at
`tmp/dvr-config-probe-outs8-fixed.dex` when present. Keep generated DEX files
out of normal commits unless there is a deliberate reason to publish one.
