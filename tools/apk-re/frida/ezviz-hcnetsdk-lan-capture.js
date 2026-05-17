"use strict";

/*
 * Trace and opportunistically record EZVIZ LAN/HCNetSDK live preview.
 *
 * Attach through the embedded gadget:
 *   frida -H 127.0.0.1:27046 -n Gadget -l tools/apk-re/frida/ezviz-hcnetsdk-lan-capture.js
 *
 * Then start live view in the app. When the app creates a local/LAN stream
 * client and starts preview, this asks the native SDK to record a short clip
 * into /sdcard/Download for pulling back with adb.
 */

const RECORD_MS = 30000;
const handleInfo = new Map();
const activeRecordings = new Set();

function nowTag() {
  return new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 15);
}

function safeString(value) {
  if (value === null || value === undefined) {
    return "";
  }
  try {
    return value.toString();
  } catch (err) {
    return `<toString failed: ${err}>`;
  }
}

function fieldValue(obj, name) {
  try {
    const field = obj[name];
    if (field === undefined || field === null) {
      return "";
    }
    return safeString(field.value);
  } catch (err) {
    return `<${name} failed: ${err}>`;
  }
}

function intField(obj, name) {
  const value = fieldValue(obj, name);
  const parsed = parseInt(value, 10);
  return Number.isNaN(parsed) ? 0 : parsed;
}

function describeInitParam(param) {
  return [
    `source=${fieldValue(param, "iStreamSource")}`,
    `dev=${fieldValue(param, "szDevSerial")}`,
    `channel=${fieldValue(param, "iChannelNumber")}`,
    `netSdkChannel=${fieldValue(param, "iNetSDKChannelNumber")}`,
    `netSdkUser=${fieldValue(param, "iNetSDKUserId")}`,
    `local=${fieldValue(param, "szDevLocalIP")}:${fieldValue(param, "iDevCmdLocalPort")}/${fieldValue(param, "iDevStreamLocalPort")}`,
    `remote=${fieldValue(param, "szDevIP")}:${fieldValue(param, "iDevCmdPort")}/${fieldValue(param, "iDevStreamPort")}`,
    `streamType=${fieldValue(param, "iStreamType")}`,
    `videoLevel=${fieldValue(param, "iVideoLevel")}`,
    `inhibit=${fieldValue(param, "iStreamInhibit")}`,
  ].join(" ");
}

function looksLan(param) {
  return (
    fieldValue(param, "szDevLocalIP").length > 0 ||
    intField(param, "iDevCmdLocalPort") > 0 ||
    intField(param, "iDevStreamLocalPort") > 0 ||
    intField(param, "iNetSDKUserId") >= 0
  );
}

function installJavaHooks() {
  Java.perform(() => {
    const Throwable = Java.use("java.lang.Throwable");
    const Log = Java.use("android.util.Log");

    function stackTrace() {
      return Log.getStackTraceString(Throwable.$new());
    }

    try {
      const Debug = Java.use("android.os.Debug");
      Debug.isDebuggerConnected.implementation = function () {
        console.log("[activity-debug] Debug.isDebuggerConnected -> false");
        return false;
      };
      Debug.waitingForDebugger.implementation = function () {
        console.log("[activity-debug] Debug.waitingForDebugger -> false");
        return false;
      };
    } catch (err) {
      console.log(`[activity-debug] Debug hook unavailable: ${err}`);
    }

    try {
      const Activity = Java.use("android.app.Activity");
      Activity.finish.overload().implementation = function () {
        console.log(`[activity-debug] finish ${this.getClass().getName()}\n${stackTrace()}`);
        return Activity.finish.overload().call(this);
      };
      Activity.finish.overload("int").implementation = function (finishTask) {
        console.log(`[activity-debug] finish ${this.getClass().getName()} finishTask=${finishTask}\n${stackTrace()}`);
        return Activity.finish.overload("int").call(this, finishTask);
      };
      Activity.moveTaskToBack.implementation = function (nonRoot) {
        console.log(`[activity-debug] moveTaskToBack ${this.getClass().getName()} nonRoot=${nonRoot}\n${stackTrace()}`);
        return this.moveTaskToBack(nonRoot);
      };
    } catch (err) {
      console.log(`[activity-debug] Activity hook unavailable: ${err}`);
    }

    try {
      const LoadingActivity = Java.use("com.ezviz.main.LoadingActivity");
      LoadingActivity.finish.implementation = function () {
        console.log(`[activity-debug] suppress LoadingActivity.finish\n${stackTrace()}`);
      };
      LoadingActivity.onCreate.implementation = function (bundle) {
        console.log("[activity-debug] LoadingActivity.onCreate");
        return this.onCreate(bundle);
      };
      LoadingActivity.onResume.implementation = function () {
        console.log("[activity-debug] LoadingActivity.onResume");
        return this.onResume();
      };
      LoadingActivity.onDestroy.implementation = function () {
        console.log(`[activity-debug] LoadingActivity.onDestroy\n${stackTrace()}`);
        return this.onDestroy();
      };
    } catch (err) {
      console.log(`[activity-debug] LoadingActivity hook unavailable: ${err}`);
    }

    const NativeApi = Java.use("com.ez.stream.NativeApi");

    const createClient = NativeApi.createClient.overload("com.ez.stream.InitParam");
    createClient.implementation = function (param) {
      const desc = describeInitParam(param);
      console.log(`[lan] NativeApi.createClient ${desc}`);
      const handle = createClient.call(this, param);
      const key = handle.toString();
      handleInfo.set(key, {
        desc,
        lan: looksLan(param),
        serial: fieldValue(param, "szDevSerial"),
        channel: fieldValue(param, "iChannelNumber"),
      });
      console.log(`[lan] NativeApi.createClient ret=${key} lan=${handleInfo.get(key).lan}`);
      return handle;
    };

    const startPreview = NativeApi.startPreview.overload("long");
    startPreview.implementation = function (handle) {
      const key = handle.toString();
      const info = handleInfo.get(key);
      console.log(`[lan] NativeApi.startPreview handle=${key} info=${info ? info.desc : "<unknown>"}`);
      const ret = startPreview.call(this, handle);
      console.log(`[lan] NativeApi.startPreview ret=${ret} handle=${key}`);

      if (ret === 0 && info && info.lan && !activeRecordings.has(key)) {
        activeRecordings.add(key);
        const serial = (info.serial || "unknown").replace(/[^A-Za-z0-9_.-]/g, "_");
        const channel = (info.channel || "0").replace(/[^A-Za-z0-9_.-]/g, "_");
        const path = `/sdcard/Download/ezviz-hcnetsdk-lan-${serial}-ch${channel}-${nowTag()}.mp4`;
        try {
          const recordRet = NativeApi.startRecord.overload("long", "java.lang.String", "int").call(this, handle, path, 0);
          console.log(`[lan-record] start ret=${recordRet} path=${path}`);
        } catch (err) {
          console.log(`[lan-record] start failed handle=${key} err=${err}`);
          activeRecordings.delete(key);
          return ret;
        }

        setTimeout(() => {
          Java.perform(() => {
            try {
              NativeApi.stopRecord.overload("long", "int").call(NativeApi, handle, 0);
              console.log(`[lan-record] stop handle=${key} path=${path}`);
            } catch (err) {
              console.log(`[lan-record] stop failed handle=${key} err=${err}`);
            } finally {
              activeRecordings.delete(key);
            }
          });
        }, RECORD_MS);
      }
      return ret;
    };

    const startRecord = NativeApi.startRecord.overload("long", "java.lang.String", "int");
    startRecord.implementation = function (handle, path, mode) {
      console.log(`[record] NativeApi.startRecord handle=${handle} path=${path} mode=${mode}`);
      const ret = startRecord.call(this, handle, path, mode);
      console.log(`[record] NativeApi.startRecord ret=${ret}`);
      return ret;
    };

    const stopRecord = NativeApi.stopRecord.overload("long", "int");
    stopRecord.implementation = function (handle, mode) {
      console.log(`[record] NativeApi.stopRecord handle=${handle} mode=${mode}`);
      return stopRecord.call(this, handle, mode);
    };

    try {
      const DeviceInfoEx = Java.use("com.videogo.device.DeviceInfoEx");
      const login = DeviceInfoEx.sdkLoginV40.overload(
        "java.lang.String",
        "int",
        "java.lang.String",
        "java.lang.String",
        "com.videogo.hcnetsdk.jna.HCNetSDKByJNA$NET_DVR_DEVICEINFO_V40",
      );
      login.implementation = function (ip, port, user, pwd, info) {
        console.log(`[lan-login] sdkLoginV40 ip=${ip}:${port} user=${user} pwdLen=${safeString(pwd).length}`);
        const ret = login.call(this, ip, port, user, pwd, info);
        console.log(`[lan-login] sdkLoginV40 ret=${ret}`);
        return ret;
      };
    } catch (err) {
      console.log(`[lan] DeviceInfoEx hook unavailable: ${err}`);
    }

    console.log(`[lan] HCNetSDK LAN capture hooks installed; recordMs=${RECORD_MS}`);
  });
}

setImmediate(installJavaHooks);
