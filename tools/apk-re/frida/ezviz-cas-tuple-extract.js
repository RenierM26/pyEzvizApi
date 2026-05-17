"use strict";

/*
 * Extract the app's CasDeviceInfo tuple for one device serial.
 *
 * This is intentionally opt-in because it prints credential material needed by
 * the standalone local-SDK probe. Use only on an operator-owned test device.
 */

const TARGET_SERIAL_VALUE = "FAKE001";

function s(value) {
  try {
    return value === null || value === undefined ? "" : value.toString();
  } catch (e) {
    return "<toString:" + e + ">";
  }
}

function tupleFromCasInfo(info) {
  if (!info) return null;
  return {
    deviceSerial: s(info.getDeviceSerial()),
    operationCode: s(info.getOperationCode()),
    key: s(info.getKey()),
    encryptType: Number(s(info.getEncryptType())),
  };
}

function emit(result) {
  console.log("[cas-tuple-json] " + JSON.stringify(result));
}

function tryDecodeFromHolder(serial) {
  const GlobalHolder = Java.use("com.ezplayer.common.GlobalHolder");
  const CasDeviceInfo = Java.use("com.ezplayer.param.model.internal.CasDeviceInfo");
  const holder = GlobalHolder.INSTANCE ? GlobalHolder.INSTANCE.value : GlobalHolder;
  const store = holder.getCasDeviceInfos();
  if (!store) return { ok: false, source: "GlobalHolder.getCasDeviceInfos", error: "null store" };

  const overloads = store.decodeParcelable ? store.decodeParcelable.overloads : [];
  for (let i = 0; i < overloads.length; i++) {
    const ov = overloads[i];
    try {
      if (ov.argumentTypes.length >= 2) {
        const ret = ov.call(store, serial, CasDeviceInfo.class);
        if (ret) {
          const info = Java.cast(ret, CasDeviceInfo);
          return { ok: true, source: "GlobalHolder.MMKV.decodeParcelable", tuple: tupleFromCasInfo(info) };
        }
      }
    } catch (e) {
      // Try the next overload.
    }
  }
  return { ok: false, source: "GlobalHolder.MMKV.decodeParcelable", error: "no tuple for serial" };
}

function installDecodeHook(serial) {
  const MMKV = Java.use("com.tencent.mmkv.MMKV");
  const CasDeviceInfo = Java.use("com.ezplayer.param.model.internal.CasDeviceInfo");
  MMKV.decodeParcelable.overloads.forEach(function(ov) {
    ov.implementation = function() {
      const args = [].slice.call(arguments);
      const key = args.length > 0 ? s(args[0]) : "";
      const klass = args.length > 1 ? s(args[1]) : "";
      const ret = ov.apply(this, args);
      if (ret && key === serial && klass.indexOf("CasDeviceInfo") >= 0) {
        const info = Java.cast(ret, CasDeviceInfo);
        emit({ ok: true, source: "MMKV.decodeParcelable hook", tuple: tupleFromCasInfo(info) });
      }
      return ret;
    };
  });
}

Java.perform(function() {
  try {
    emit(tryDecodeFromHolder(TARGET_SERIAL_VALUE));
  } catch (e) {
    emit({ ok: false, source: "direct", error: s(e) });
  }
  try {
    installDecodeHook(TARGET_SERIAL_VALUE);
    console.log("[cas-tuple] decode hook installed for serial=" + TARGET_SERIAL_VALUE);
  } catch (e) {
    console.log("[cas-tuple] decode hook failed " + e);
  }
});
