/*
 * EZVIZ/Hikvision stream transform tracing.
 *
 * Usage:
 *   frida -U -f com.ezviz -l tools/apk-re/frida/ezviz-stream-transform-hook.js --no-pause
 *
 * Device flags:
 *   /data/local/tmp/ezviz-native-only.flag  skip Java hooks for fragile live-preview runs
 *
 * This script is intentionally diagnostic-only. It logs redacted secret-key
 * call metadata and dumps small samples around the native demux/decrypt boundary so an
 * encrypted VTM/MPEG-PS packet can be compared with PlayCtrl/SystemTransform
 * output from the official SDK path.
 */

"use strict";

const DUMP_LIMIT = 256 * 1024;
const CALLBACK_DUMP_LIMIT = 64 * 1024;
const JAVA_DECODE_DUMP_LIMIT = 512 * 1024;
const HEX_LIMIT = 64;
const MAX_DUMPS_PER_LABEL = deviceFlagExists("/data/local/tmp/ezviz-deep-idmx-dump.flag") ? 512 : 24;
const NATIVE_ONLY = deviceFlagExists("/data/local/tmp/ezviz-native-only.flag");
const LOG_SECRET_VALUES = false;
const installed = new Set();
const installedJavaDecodeClasses = new Set();
const installedJavaStreamClasses = new Set();
let dumpDir = "/sdcard/Download/ezviz-hook";
if (NATIVE_ONLY) {
  dumpDir = "/storage/emulated/0/Android/data/com.ezviz/files/ezviz-hook";
}
let dumpSeq = 0;
const dumpCounts = {};
const logCounts = {};

function shouldLog(label, limit) {
  const current = logCounts[label] || 0;
  logCounts[label] = current + 1;
  return current < limit;
}

function deviceFlagExists(path) {
  try {
    const file = new File(path, "rb");
    file.close();
    return true;
  } catch (_) {
    return false;
  }
}

function nowTag() {
  return new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14);
}

function bytesToHex(ptr, len) {
  if (ptr.isNull() || len <= 0) {
    return "";
  }
  try {
    const data = new Uint8Array(ptr.readByteArray(Math.min(len, HEX_LIMIT)));
    return Array.from(data)
      .map((byte) => leftPad(byte.toString(16), 2, "0"))
      .join(" ");
  } catch (err) {
    return `<read-failed ${err}>`;
  }
}

function leftPad(value, width, fill) {
  let text = String(value);
  while (text.length < width) {
    text = fill + text;
  }
  return text;
}

function secretBytes(ptr, len) {
  if (ptr.isNull()) {
    return "<null>";
  }
  if (!LOG_SECRET_VALUES) {
    return `<redacted len=${len}>`;
  }
  return bytesToHex(ptr, len);
}

function nativeSecretBytes(ptr, lenArg) {
  let len = 0;
  try {
    len = lenArg.toInt32();
  } catch (_) {
    return `<redacted ptr=${ptr} len=<invalid>>`;
  }
  if (len <= 0 || len > 4096) {
    return `<redacted ptr=${ptr} len=${len}>`;
  }
  return secretBytes(ptr, len);
}

function secretCString(ptr) {
  if (ptr.isNull()) {
    return "<null>";
  }
  if (!LOG_SECRET_VALUES) {
    return "<redacted cstring>";
  }
  return asCString(ptr);
}

function secretJavaString(jstr) {
  if (jstr.isNull()) {
    return "<null>";
  }
  if (!LOG_SECRET_VALUES) {
    return "<redacted jstring>";
  }
  return javaString(jstr);
}

function dumpBytes(label, ptr, len) {
  if (ptr.isNull() || len <= 0) {
    return;
  }
  dumpCounts[label] = dumpCounts[label] || 0;
  if (dumpCounts[label] >= MAX_DUMPS_PER_LABEL) {
    return;
  }
  dumpCounts[label] += 1;
  const capped = Math.min(len, DUMP_LIMIT);
  const safeLabel = label.replace(/[^A-Za-z0-9_.-]+/g, "-");
  const path = `${dumpDir}/${nowTag()}-${leftPad(dumpSeq++, 4, "0")}-${safeLabel}-${capped}.bin`;
  try {
    const file = new File(path, "wb");
    file.write(ptr.readByteArray(capped));
    file.flush();
    file.close();
    console.log(`[dump] ${label} count=${dumpCounts[label]} len=${len} saved=${capped} path=${path}`);
  } catch (err) {
    console.log(`[dump-failed] ${label} len=${len} path=${path} err=${err}`);
  }
}

function asCString(ptr) {
  if (ptr.isNull()) {
    return "<null>";
  }
  try {
    return ptr.readCString();
  } catch (err) {
    return `<non-cstring ${ptr}>`;
  }
}

function javaString(jstr) {
  if (jstr.isNull()) {
    return "<null>";
  }
  try {
    return Java.vm.getEnv().getStringUtfChars(jstr, null).readCString();
  } catch (err) {
    return `<jstring ${jstr}>`;
  }
}

function safeJavaValue(value) {
  if (value === null || value === undefined) {
    return "<null>";
  }
  try {
    return value.toString();
  } catch (err) {
    return `<toString-failed ${err}>`;
  }
}

function safeJavaClassName(value) {
  if (value === null || value === undefined) {
    return "<null>";
  }
  try {
    return value.getClass().getName().toString();
  } catch (err) {
    return `<class-failed ${err}>`;
  }
}

function dumpJavaByteArray(label, value, len) {
  if (value === null || value === undefined || len <= 0) {
    return;
  }
  dumpCounts[label] = dumpCounts[label] || 0;
  if (dumpCounts[label] >= MAX_DUMPS_PER_LABEL) {
    return;
  }
  const arrayLen = value.length || 0;
  const capped = Math.min(len, arrayLen, JAVA_DECODE_DUMP_LIMIT);
  if (capped <= 0) {
    return;
  }
  const bytes = new Uint8Array(capped);
  for (let i = 0; i < capped; i++) {
    bytes[i] = value[i] & 0xff;
  }
  dumpCounts[label] += 1;
  const path = `${dumpDir}/${nowTag()}-${leftPad(dumpSeq++, 4, "0")}-${label}-${capped}.bin`;
  try {
    const file = new File(path, "wb");
    file.write(bytes.buffer);
    file.flush();
    file.close();
    console.log(`[dump] ${label} count=${dumpCounts[label]} len=${len} saved=${capped} path=${path}`);
  } catch (err) {
    console.log(`[dump-failed] ${label} len=${len} path=${path} err=${err}`);
  }
}

function describeJavaMethodArg(value) {
  if (value === null || value === undefined) {
    return "<null>";
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  if (typeof value === "string") {
    return `<string len=${value.length}>`;
  }
  const className = safeJavaClassName(value);
  if (className === "[B") {
    return `byte[] len=${value.length || 0}`;
  }
  if (className === "java.lang.String") {
    return `<java-string len=${safeJavaValue(value).length}>`;
  }
  if (className === "<null>") {
    return "<null>";
  }
  return `<${className}>`;
}

function dumpFirstJavaByteArrayArg(label, argsLike) {
  for (let i = 0; i < argsLike.length; i++) {
    const value = argsLike[i];
    if (value === null || value === undefined) {
      continue;
    }
    let className = "";
    try {
      className = safeJavaClassName(value);
    } catch (_) {
      className = "";
    }
    if (className !== "[B") {
      continue;
    }
    let len = value.length || 0;
    if (i + 1 < argsLike.length) {
      const nextLen = Number(argsLike[i + 1]);
      if (Number.isFinite(nextLen) && nextLen > 0) {
        len = Math.min(len, nextLen);
      }
    }
    dumpJavaByteArray(label, value, len);
    return;
  }
}

function fieldValue(obj, name) {
  try {
    const field = obj[name];
    if (field === undefined || field === null) {
      return "<missing>";
    }
    return safeJavaValue(field.value);
  } catch (err) {
    return `<field-failed ${name} ${err}>`;
  }
}

function redactedField(obj, name) {
  const value = fieldValue(obj, name);
  if (value === "<missing>" || value === "<null>" || value === "") {
    return value;
  }
  return `<redacted len=${value.length}>`;
}

function describeDownloadCloudParam(param) {
  if (param === null || param === undefined) {
    return "<null>";
  }
  return [
    `server=${fieldValue(param, "szServerIP")}:${fieldValue(param, "iServerPort")}`,
    `camera=${fieldValue(param, "szCamera")}`,
    `fileId=${fieldValue(param, "szFileID")}`,
    `begin=${fieldValue(param, "szBeginTime")}`,
    `end=${fieldValue(param, "szEndTime")}`,
    `bus=${fieldValue(param, "iBusType")}`,
    `playType=${fieldValue(param, "iPlayType")}`,
    `fileType=${fieldValue(param, "iFileType")}`,
    `streamType=${fieldValue(param, "iStreamType")}`,
    `frontType=${fieldValue(param, "iFrontType")}`,
    `videoType=${fieldValue(param, "iVideoType")}`,
    `storageVersion=${fieldValue(param, "iStorageVersion")}`,
    `channel=${fieldValue(param, "iChannelNumber")}`,
    `interlace=${fieldValue(param, "iInterlaceFlag")}`,
    `ticket=${redactedField(param, "szTicketToken")}`,
    `clientSession=${redactedField(param, "szClientSession")}`,
    `auth=${redactedField(param, "szAuthorization")}`,
  ].join(" ");
}

function describeInitParam(param) {
  if (param === null || param === undefined) {
    return "<null>";
  }
  return [
    `server=${fieldValue(param, "szServerIP")}:${fieldValue(param, "iServerPort")}`,
    `camera=${fieldValue(param, "szCamera")}`,
    `device=${fieldValue(param, "szDeviceSerial")}`,
    `begin=${fieldValue(param, "szStartTime")}`,
    `end=${fieldValue(param, "szStopTime")}`,
    `channel=${fieldValue(param, "iChannelNumber")}`,
    `streamType=${fieldValue(param, "iStreamType")}`,
    `playType=${fieldValue(param, "iPlayType")}`,
    `ticket=${redactedField(param, "szTicketToken")}`,
    `clientSession=${redactedField(param, "szClientSession")}`,
  ].join(" ");
}

function hookExport(moduleName, exportName, callbacks) {
  const key = `${moduleName}!${exportName}`;
  if (installed.has(key)) {
    return;
  }
  let ptr = null;
  if (typeof Module.findExportByName === "function") {
    ptr = Module.findExportByName(moduleName, exportName);
  } else {
    try {
      ptr = Process.getModuleByName(moduleName).findExportByName(exportName);
    } catch (err) {
      ptr = null;
    }
  }
  if (ptr === null) {
    return;
  }
  try {
    Interceptor.attach(ptr, callbacks);
  } catch (err) {
    console.log(`[warn] hook failed ${key} @ ${ptr}: ${err}`);
    installed.add(key);
    return;
  }
  installed.add(key);
  console.log(`[hook] ${key} @ ${ptr}`);
}

function hookCallbackPointer(label, cbPtr, dumpArgIndex, lenArgIndex) {
  if (cbPtr === null || cbPtr === undefined || cbPtr.isNull()) {
    return;
  }
  const key = `callback:${label}:${cbPtr}`;
  if (installed.has(key)) {
    return;
  }
  try {
    Interceptor.attach(cbPtr, {
      onEnter(args) {
        if (!shouldLog(key, 64)) {
          return;
        }
        const parts = [];
        for (let i = 0; i < 6; i++) {
          parts.push(`arg${i}=${args[i]}`);
        }
        console.log(`[cb-call] ${label} ${parts.join(" ")}`);
        if (dumpArgIndex === null || dumpArgIndex === undefined) {
          return;
        }
        let len = 128;
        if (lenArgIndex !== null && lenArgIndex !== undefined) {
          try {
            len = Math.max(args[lenArgIndex].toInt32(), 0);
          } catch (_) {
            len = 128;
          }
        }
        if (!args[dumpArgIndex].isNull() && len > 0) {
          const format = describeDecodedFrameSize(len);
          if (format !== null) {
            console.log(`[cb-call] ${label} arg${lenArgIndex}DecodedFrame=${format}`);
          }
          const savedLen = Math.min(len, CALLBACK_DUMP_LIMIT);
          console.log(`[cb-call] ${label} arg${dumpArgIndex}Head=${bytesToHex(args[dumpArgIndex], len)}`);
          dumpBytes(`callback-${label}`, args[dumpArgIndex], savedLen);
        }
      },
    });
    installed.add(key);
    console.log(`[hook] callback ${label} @ ${cbPtr}`);
  } catch (err) {
    console.log(`[warn] callback hook failed label=${label} ptr=${cbPtr}: ${err}`);
  }
}

function hookPointerDataFunction(moduleName, exportName, label, dumpArgIndex, lenArgIndex, logLimit) {
  hookExport(moduleName, exportName, {
    onEnter(args) {
      this.label = label;
      if (!shouldLog(`[native] ${label}`, logLimit || 128)) {
        return;
      }
      const parts = [`this=${args[0]}`];
      if (label.indexOf("ProcessLostPacket") !== -1) {
        parts.push(`lost=${args[1].toInt32()}`);
      }
      if (dumpArgIndex !== null && dumpArgIndex !== undefined) {
        let len = 256;
        if (lenArgIndex !== null && lenArgIndex !== undefined) {
          try {
            len = Math.max(args[lenArgIndex].toInt32(), 0);
          } catch (_) {
            len = 256;
          }
        }
        parts.push(`arg${dumpArgIndex}=${args[dumpArgIndex]}`);
        parts.push(`len=${len}`);
        if (!args[dumpArgIndex].isNull() && len > 0) {
          parts.push(`head=${bytesToHex(args[dumpArgIndex], len)}`);
          dumpBytes(
            label.replace(/[^A-Za-z0-9_.-]+/g, "-"),
            args[dumpArgIndex],
            Math.min(len, CALLBACK_DUMP_LIMIT),
          );
        }
      }
      console.log(`[native] ${label} ${parts.join(" ")}`);
    },
    onLeave(retval) {
      if (shouldLog(`[native] ${label}:ret`, logLimit || 128)) {
        console.log(`[native] ${label} ret=${retval.toInt32()}`);
      }
    },
  });
}

function retString(retval) {
  try {
    return `${retval} int=${retval.toInt32()}`;
  } catch (_) {
    return String(retval);
  }
}

function hookArgTraceFunction(moduleName, exportName, label, argCount, logLimit) {
  hookExport(moduleName, exportName, {
    onEnter(args) {
      if (!shouldLog(`[native] ${label}`, logLimit || 64)) {
        return;
      }
      const parts = [];
      for (let i = 0; i < argCount; i++) {
        parts.push(`arg${i}=${args[i]}`);
      }
      console.log(`[native] ${label} ${parts.join(" ")}`);
    },
    onLeave(retval) {
      if (shouldLog(`[native] ${label}:ret`, logLimit || 64)) {
        console.log(`[native] ${label} ret=${retString(retval)}`);
      }
    },
  });
}

function hookCallbackSetter(moduleName, exportName, label, cbIndex, dumpArgIndex, lenArgIndex, logLimit) {
  hookExport(moduleName, exportName, {
    onEnter(args) {
      if (shouldLog(`[cb] ${label}`, logLimit || 64)) {
        console.log(
          `[cb] ${label} handle=${args[0]} cb=${args[cbIndex]} user=${args[2]} extra=${args[3]}`,
        );
      }
      hookCallbackPointer(label, args[cbIndex], dumpArgIndex, lenArgIndex);
    },
    onLeave(retval) {
      if (shouldLog(`[cb] ${label}:ret`, logLimit || 64)) {
        console.log(`[cb] ${label} ret=${retString(retval)}`);
      }
    },
  });
}

function hookLoggingCallbackSetter(moduleName, exportName, label, cbIndex, logLimit) {
  hookExport(moduleName, exportName, {
    onEnter(args) {
      if (shouldLog(`[cb] ${label}`, logLimit || 64)) {
        console.log(
          `[cb] ${label} handle=${args[0]} cb=${args[cbIndex]} user=${args[2]} extra=${args[3]}`,
        );
      }
      hookLoggingCallbackPointer(label, args[cbIndex], logLimit || 64);
    },
    onLeave(retval) {
      if (shouldLog(`[cb] ${label}:ret`, logLimit || 64)) {
        console.log(`[cb] ${label} ret=${retString(retval)}`);
      }
    },
  });
}

function parseOutputDataInfoCandidate(infoPtr, offset, detail) {
  const dataPtr = infoPtr.readPointer();
  const len = infoPtr.add(offset).readU32();
  if (dataPtr.isNull() || len <= 0 || len > 16 * 1024 * 1024) {
    return null;
  }
  const result = {
    dataPtr,
    len,
    layout: `ptr${offset}`,
    type: detail ? infoPtr.add(offset + 4).readU16() : infoPtr.add(offset + 4).readU32(),
  };
  if (detail) {
    result.frame = infoPtr.add(offset + 6).readU16();
    result.ts = infoPtr.add(offset + 8).readU32();
    result.mark = infoPtr.add(offset + 16).readU16();
    result.ver = infoPtr.add(offset + 18).readU16();
  } else {
    result.flag = infoPtr.add(offset + 8).readU32();
  }
  return result;
}

function parseOutputDataInfo(infoPtr, detail) {
  const offsets = [];
  [Process.pointerSize, 4].forEach((offset) => {
    if (!offsets.includes(offset)) {
      offsets.push(offset);
    }
  });
  for (const offset of offsets) {
    try {
      const candidate = parseOutputDataInfoCandidate(infoPtr, offset, detail);
      if (candidate !== null) {
        return candidate;
      }
    } catch (_) {
      // Try the next ABI layout candidate.
    }
  }
  return {
    dataPtr: infoPtr.readPointer(),
    len: 0,
    layout: "unknown",
    type: null,
  };
}

function dumpOutputDataInfo(label, infoPtr, detail, logLimit) {
  if (infoPtr === null || infoPtr === undefined || infoPtr.isNull()) {
    return;
  }
  const logLabel = `[out] ${label}`;
  if (!shouldLog(logLabel, logLimit || 128)) {
    return;
  }
  try {
    const parsed = parseOutputDataInfo(infoPtr, detail);
    const dataPtr = parsed.dataPtr;
    const len = parsed.len;
    const fields = [`info=${infoPtr}`, `layout=${parsed.layout}`, `data=${dataPtr}`, `len=${len}`];
    if (detail) {
      fields.push(`type=${parsed.type}`);
      fields.push(`frame=${parsed.frame}`);
      fields.push(`ts=${parsed.ts}`);
      fields.push(`mark=${parsed.mark}`);
      fields.push(`ver=${parsed.ver}`);
    } else {
      fields.push(`type=${parsed.type}`);
      fields.push(`flag=${parsed.flag}`);
    }
    if (!dataPtr.isNull() && len > 0) {
      fields.push(`head=${bytesToHex(dataPtr, len)}`);
      dumpBytes(
        label.replace(/[^A-Za-z0-9_.-]+/g, "-"),
        dataPtr,
        Math.min(len, CALLBACK_DUMP_LIMIT),
      );
    }
    console.log(`${logLabel} ${fields.join(" ")}`);
  } catch (err) {
    console.log(`${logLabel} parse-failed info=${infoPtr} err=${err}`);
  }
}

function hookOutputDataInfoFunction(moduleName, exportName, label, detail, logLimit) {
  hookExport(moduleName, exportName, {
    onEnter(args) {
      dumpOutputDataInfo(label, args[0], detail, logLimit);
    },
  });
}

function hookOutputDataInfoArgFunction(moduleName, exportName, label, infoArgIndex, detail, logLimit) {
  hookExport(moduleName, exportName, {
    onEnter(args) {
      dumpOutputDataInfo(label, args[infoArgIndex], detail, logLimit);
    },
  });
}

function hookOutputDataInfoCallbackPointer(label, cbPtr, detail) {
  if (cbPtr === null || cbPtr === undefined || cbPtr.isNull()) {
    return;
  }
  const key = `output-info-callback:${label}:${cbPtr}`;
  if (installed.has(key)) {
    return;
  }
  try {
    Interceptor.attach(cbPtr, {
      onEnter(args) {
        dumpOutputDataInfo(`callback-${label}`, args[0], detail, 128);
      },
    });
    installed.add(key);
    console.log(`[hook] output-info callback ${label} @ ${cbPtr}`);
  } catch (err) {
    console.log(`[warn] output-info callback hook failed label=${label} ptr=${cbPtr}: ${err}`);
  }
}

function hookLoggingCallbackPointer(label, cbPtr, logLimit) {
  if (cbPtr === null || cbPtr === undefined || cbPtr.isNull()) {
    return;
  }
  const key = `logging-callback:${label}:${cbPtr}`;
  if (installed.has(key)) {
    return;
  }
  try {
    Interceptor.attach(cbPtr, {
      onEnter(args) {
        if (!shouldLog(key, logLimit || 64)) {
          return;
        }
        const parts = [];
        for (let i = 0; i < 6; i++) {
          parts.push(`arg${i}=${args[i]}`);
        }
        console.log(`[cb-call] ${label} ${parts.join(" ")}`);
      },
    });
    installed.add(key);
    console.log(`[hook] logging callback ${label} @ ${cbPtr}`);
  } catch (err) {
    console.log(`[warn] logging callback hook failed label=${label} ptr=${cbPtr}: ${err}`);
  }
}

function describeDecodedFrameSize(len) {
  const commonYuv420Sizes = {
    460800: "640x480-yuv420",
    1382400: "1280x720-yuv420",
    3110400: "1920x1080-yuv420",
    4147200: "2560x1080-yuv420",
    6220800: "2560x1440-yuv420",
    12441600: "3840x2160-yuv420",
  };
  return commonYuv420Sizes[len] || null;
}

function installNativeHooks() {
  hookExport("libezstreamclient.so", "Java_com_ez_stream_NativeApi_setSecretKey", {
    onEnter(args) {
      // JNI: JNIEnv*, object/class, native handle/player, jstring key in current builds.
      console.log(`[key] NativeApi.setSecretKey handle=${args[2]} key=${secretJavaString(args[3])}`);
    },
  });

  hookExport("libezstreamclient.so", "_Z21ezplayer_setSecretKeyPvNSt6__ndk112basic_stringIcNS0_11char_traitsIcEENS0_9allocatorIcEEEE", {
    onEnter(args) {
      console.log(`[key] ezplayer_setSecretKey player=${args[0]} std_string=${args[1]}`);
    },
  });

  hookExport("libezstreamclient.so", "_ZN11CRecvClient13SetEncryptKeyEPKc", {
    onEnter(args) {
      console.log(`[key] CRecvClient::SetEncryptKey this=${args[0]} key=${secretCString(args[1])}`);
    },
  });

  [
    ["Java_com_ez_stream_NativeApi_createClient", "NativeApi.createClient", 3],
    ["Java_com_ez_stream_NativeApi_createClientWithUrl", "NativeApi.createClientWithUrl", 3],
    ["Java_com_ez_stream_NativeApi_createPreviewHandle", "NativeApi.createPreviewHandle", 3],
    ["Java_com_ez_stream_NativeApi_createPreviewHandleWithUrl", "NativeApi.createPreviewHandleWithUrl", 3],
    ["Java_com_ez_stream_NativeApi_destroyHandle", "NativeApi.destroyHandle", 3],
    ["Java_com_ez_stream_NativeApi_setCallback", "NativeApi.setCallback", 4],
    ["Java_com_ez_stream_NativeApi_setDataCallback2Java", "NativeApi.setDataCallback2Java", 4],
    ["Java_com_ez_stream_NativeApi_startPreview", "NativeApi.startPreview", 8],
    ["Java_com_ez_stream_NativeApi_start", "NativeApi.start", 5],
    ["Java_com_ez_stream_NativeApi_startPlayback__JLjava_lang_String_2Ljava_lang_String_2Ljava_lang_String_2", "NativeApi.startPlayback(strings)", 6],
    ["Java_com_ez_stream_NativeApi_startPlayback__JLjava_util_List_2", "NativeApi.startPlayback(list)", 4],
    ["Java_com_ez_stream_NativeApi_startPreconnect", "NativeApi.startPreconnect", 3],
    ["Java_com_ez_stream_NativeApi_stopPreview", "NativeApi.stopPreview", 4],
    ["Java_com_ez_stream_NativeApi_setPlayPort", "NativeApi.setPlayPort", 4],
    ["Java_com_ez_stream_NativeApi_setMediaCallback", "NativeApi.setMediaCallback", 5],
    ["Java_com_ez_stream_NativeApi_setStreamDataCallback", "NativeApi.setStreamDataCallback", 5],
    ["Java_com_ez_stream_NativeApi_setStreamSaveDebugPath", "NativeApi.setStreamSaveDebugPath", 5],
    ["Java_com_ez_stream_NativeApi_setPlaybackConvert", "NativeApi.setPlaybackConvert", 6],
    ["Java_com_ez_stream_NativeApi_setMediaPlaybackConvert", "NativeApi.setMediaPlaybackConvert", 6],
    ["Java_com_ez_stream_NativeApi_inputData2Cloud", "NativeApi.inputData2Cloud", 5],
    ["Java_com_ez_stream_NativeApi_inputVoiceTalkData", "NativeApi.inputVoiceTalkData", 6],
  ].forEach(([name, label, argCount]) => {
    hookArgTraceFunction("libezstreamclient.so", name, label, argCount, 64);
  });

  [
    ["_Z27ezplayer_createPreviewMediaP10INIT_PARAM", "ezplayer_createPreviewMedia(INIT_PARAM*)", 1],
    ["_Z27ezplayer_createPreviewMediaRKNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEE", "ezplayer_createPreviewMedia(string)", 1],
    ["_Z14ezplayer_startPv", "ezplayer_start", 1],
    ["_Z21ezstream_startPreviewPv", "ezstream_startPreview", 1],
    ["_Z31ezplayer_setStreamSaveDebugPathPvRKNSt6__ndk112basic_stringIcNS0_11char_traitsIcEENS0_9allocatorIcEEEE", "ezplayer_setStreamSaveDebugPath", 2],
    ["_Z22ezplayer_refreshPlayerPvjb", "ezplayer_refreshPlayer", 3],
    ["_Z34ezplayer_getHCNetSDKPlaybackHandlePv", "ezplayer_getHCNetSDKPlaybackHandle", 1],
    ["_ZN2bp13BPMediaPlayer4PlayEPKc", "BPMediaPlayer::Play", 2],
    ["_ZN2bp17BPMediaDecoder_FF9OpenInputEPKc", "BPMediaDecoder_FF::OpenInput", 2],
  ].forEach(([name, label, argCount]) => {
    hookArgTraceFunction("libezstreamclient.so", name, label, argCount, 64);
    hookArgTraceFunction("libBPlayer.so", name, label, argCount, 64);
  });

  hookExport("libezstreamclient.so", "_Z24ezplayer_setDataCallbackPvPFviPciS_ES_", {
    onEnter(args) {
      console.log(`[cb] ezplayer_setDataCallback player=${args[0]} cb=${args[1]} user=${args[2]}`);
      hookCallbackPointer("ezplayer-setDataCallback", args[1], 1, 2);
    },
    onLeave(retval) {
      console.log(`[cb] ezplayer_setDataCallback ret=${retString(retval)}`);
    },
  });

  hookExport("libezstreamclient.so", "_Z32ezplayer_setPLAYM4DecodeCallbackPvPFvPciP13EZ_FRAME_INFOP21EZ_PLAYM4_SYSTEM_TIMES_ES_", {
    onEnter(args) {
      console.log(`[cb] ezplayer_setPLAYM4DecodeCallback player=${args[0]} cb=${args[1]}`);
      hookCallbackPointer("ezplayer-PLAYM4DecodeCallback", args[1], 0, 1);
    },
    onLeave(retval) {
      console.log(`[cb] ezplayer_setPLAYM4DecodeCallback ret=${retString(retval)}`);
    },
  });

  [
    ["_ZN13ez_stream_sdk11EZMediaBase15setDataCallbackEPFviPciPvES2_", "EZMediaBase::setDataCallback", 1, 1, 2],
    ["_ZN13ez_stream_sdk11EZMediaBase17setDecodeCallbackEPFvPciP13EZ_FRAME_INFOP21EZ_PLAYM4_SYSTEM_TIMEPvES6_", "EZMediaBase::setDecodeCallback", 1, 0, 1],
  ].forEach(([name, label, cbIndex, dumpArgIndex, lenArgIndex]) => {
    hookExport("libezstreamclient.so", name, {
      onEnter(args) {
        console.log(`[cb] ${label} this=${args[0]} cb=${args[cbIndex]} user=${args[2]}`);
        hookCallbackPointer(label, args[cbIndex], dumpArgIndex, lenArgIndex);
      },
      onLeave(retval) {
        console.log(`[cb] ${label} ret=${retString(retval)}`);
      },
    });
  });

  [
    ["_ZN13ez_stream_sdk11EZMediaBase9inputDataEPhi", "EZMediaBase::inputData", 1, 2],
    ["_ZN13ez_stream_sdk11EZMediaBase14saveDataHeaderEPKhj", "EZMediaBase::saveDataHeader", 1, 2],
    ["_ZN13ez_stream_sdk11EZMediaBase14saveStreamDataEPKci", "EZMediaBase::saveStreamData", 1, 2],
    ["_ZN13ez_stream_sdk11EZMediaBase19onDataCallbackMediaEPviPaii", "EZMediaBase::onDataCallbackMedia", 3, 4],
    ["_ZN11CRecvClient13SetStreamHeadEPci", "CRecvClient::SetStreamHead", 1, 2],
    ["_Z19onMediaDataCallbackiPciPv", "onMediaDataCallback", 1, 2],
    ["_Z23onMediaDataSizeCallbackiPciPv", "onMediaDataSizeCallback", 1, 2],
  ].forEach(([name, label, dumpArgIndex, lenArgIndex]) => {
    hookPointerDataFunction("libezstreamclient.so", name, `ezstreamclient.${label}`, dumpArgIndex, lenArgIndex);
  });

  hookExport("libezstreamclient.so", "_Z14eztrans_createPhjPKc17EZ_TRANSFORM_TYPEPPvPFvjS_jjS3_ES3_", {
    onEnter(args) {
      const len = args[1].toInt32();
      console.log(`[eztrans] eztrans_create header=${args[0]} len=${len} type=${args[3].toInt32()} out=${args[4]} cb=${args[5]} user=${args[6]}`);
      dumpBytes("eztrans-create-head", args[0], len);
      hookCallbackPointer("eztrans-create-output", args[5], 1, 2);
    },
    onLeave(retval) {
      console.log(`[eztrans] eztrans_create ret=${retString(retval)}`);
    },
  });

  hookPointerDataFunction("libezstreamclient.so", "_Z13eztrans_inputPviPhj", "eztrans_input", 2, 3);

  [
    ["_Z17eztrans_create_exPKc17EZ_TRANSFORM_TYPEPPv", "eztrans_create_ex", 3],
    ["_Z16eztrans_start_exPv", "eztrans_start_ex", 1],
    ["_Z13eztrans_startPvPKcS1_", "eztrans_start", 3],
    ["_Z14eztrans_setKeyPvNSt6__ndk112basic_stringIcNS0_11char_traitsIcEENS0_9allocatorIcEEEE", "eztrans_setKey", 2],
  ].forEach(([name, label, argCount]) => {
    hookArgTraceFunction("libezstreamclient.so", name, label, argCount, 64);
  });

  [
    ["Java_com_hikvision_packagetransform_PackageTransform_startTransform", "PackageTransform.startTransform", 9],
    ["Java_com_hikvision_packagetransform_PackageTransform_startTransformSimple", "PackageTransform.startTransformSimple", 7],
    ["Java_com_hikvision_packagetransform_PackageTransform_startRealTimeTransform", "PackageTransform.startRealTimeTransform", 8],
    ["Java_com_hikvision_packagetransform_PackageTransform_startRealTimeTransformTS", "PackageTransform.startRealTimeTransformTS", 8],
    ["CreateHandle", "PackageTransform.CreateHandle", 1],
    ["ReadRtpPacket", "PackageTransform.ReadRtpPacket", 2],
    ["ReadRawData", "PackageTransform.ReadRawData", 0],
    ["TransLoop", "PackageTransform.TransLoop", 1],
    ["TransLoopRealTime", "PackageTransform.TransLoopRealTime", 5],
    ["TransLoopRealTimeTS", "PackageTransform.TransLoopRealTimeTS", 5],
    ["SetCallback", "PackageTransform.SetCallback", 2],
    ["SetGlobalTime", "PackageTransform.SetGlobalTime", 1],
    ["SetOption", "PackageTransform.SetOption", 1],
    ["WaitComplete", "PackageTransform.WaitComplete", 0],
  ].forEach(([name, label, argCount]) => {
    hookArgTraceFunction("libPackageTransform.so", name, label, argCount, 64);
  });

  hookExport("libPackageTransform.so", "Java_com_hikvision_packagetransform_PackageTransform_inputData", {
    onEnter(args) {
      console.log(`[package-transform] PackageTransform.inputData jbuf=${args[2]} len=${args[3].toInt32()}`);
    },
    onLeave(retval) {
      console.log(`[package-transform] PackageTransform.inputData ret=${retString(retval)}`);
    },
  });

  hookOutputDataInfoFunction("libPackageTransform.so", "STOutputCbf", "PackageTransform.STOutputCbf", false, 128);
  hookOutputDataInfoFunction("libPackageTransform.so", "STOutputCbf2", "PackageTransform.STOutputCbf2", true, 128);
  hookOutputDataInfoFunction("libPackageTransform.so", "STDetailCbf", "PackageTransform.STDetailCbf", true, 128);

  [
    ["NPQ_InputData", "NPQ_InputData", 1, 2],
    ["NPQ_InputRawData", "NPQ_InputRawData", 1, 2],
  ].forEach(([name, label, dumpArgIndex, lenArgIndex]) => {
    hookPointerDataFunction("libNPQos.so", name, label, dumpArgIndex, lenArgIndex, 128);
  });

  [
    ["NPQ_Create", "NPQ_Create", 1],
    ["NPQ_Start", "NPQ_Start", 1],
    ["NPQ_Stop", "NPQ_Stop", 1],
    ["NPQ_Destroy", "NPQ_Destroy", 1],
    ["NPQ_SetNotifyParam", "NPQ_SetNotifyParam", 2],
    ["NPQ_SetParam", "NPQ_SetParam", 3],
    ["NPQ_SetMediaDelay", "NPQ_SetMediaDelay", 2],
    ["NPQ_SetState", "NPQ_SetState", 2],
  ].forEach(([name, label, argCount]) => {
    hookArgTraceFunction("libNPQos.so", name, label, argCount, 64);
  });

  [
    ["NPQ_RegisterDataCallBack", "NPQ_RegisterDataCallBack", 1, 2, 3],
    ["NPQ_RegisterRecoveriedDataCallBack", "NPQ_RegisterRecoveriedDataCallBack", 1, 2, 3],
    ["NPQ_RegisterDataInfoCallBack", "NPQ_RegisterDataInfoCallBack", 1, 2, 3],
    ["NPQ_RegisterAudioDecFun", "NPQ_RegisterAudioDecFun", 1, 2, 3],
  ].forEach(([name, label, cbIndex, dumpArgIndex, lenArgIndex]) => {
    hookCallbackSetter("libNPQos.so", name, label, cbIndex, dumpArgIndex, lenArgIndex, 64);
  });

  [
    ["NPC_InputData", "NPC_InputData", 2, 3],
    ["_ZN8NPStream9InputDataE13NPC_DATA_TYPEPhj", "NPStream::InputData", 2, 3],
    ["_ZN10INetStream9InputDataEjPhj", "INetStream::InputData", 2, 3],
    ["_ZN10RTMPStream9InputDataEjPhj", "RTMPStream::InputData", 2, 3],
    ["_ZN11RTMPSession9InputDataEPhj", "RTMPSession::InputData", 1, 2],
    ["_ZN15RTMPPushSession9InputDataEPhj", "RTMPPushSession::InputData", 1, 2],
    ["_ZN8MmshData9InputDataEPhj", "MmshData::InputData", 1, 2],
  ].forEach(([name, label, dumpArgIndex, lenArgIndex]) => {
    hookPointerDataFunction("libNPClient.so", name, label, dumpArgIndex, lenArgIndex, 128);
  });

  [
    ["NPC_SetMsgCallBack", "NPC_SetMsgCallBack", 1, 2, 3],
    ["_ZN8NPStream14SetMsgCallBackEPFviiPhjPvES1_", "NPStream::SetMsgCallBack", 1, 2, 3],
  ].forEach(([name, label, cbIndex, dumpArgIndex, lenArgIndex]) => {
    hookCallbackSetter("libNPClient.so", name, label, cbIndex, dumpArgIndex, lenArgIndex, 64);
  });

  [
    ["NPC_SetTransmitMode", "NPC_SetTransmitMode", 3],
    ["NPC_SetTransmitMode_Ex", "NPC_SetTransmitMode_Ex", 2],
    ["NPC_SetPullStreamType", "NPC_SetPullStreamType", 2],
    ["NPC_SetStreamInfo", "NPC_SetStreamInfo", 2],
    ["_ZN8NPStream4OpenEPFviiPhjPvES1_y", "NPStream::Open", 3],
    ["_ZN8NPStream5CloseEv", "NPStream::Close", 1],
  ].forEach(([name, label, argCount]) => {
    hookArgTraceFunction("libNPClient.so", name, label, argCount, 64);
  });

  [
    ["_Z14NPCMsgCallBackiiPhjPv", "HIK_NPCClient.NPCMsgCallBack", 2, 3],
    ["_Z15NPCDataCallBackiiPhjPv", "HIK_NPCClient.NPCDataCallBack", 2, 3],
  ].forEach(([name, label, dumpArgIndex, lenArgIndex]) => {
    hookPointerDataFunction("libHIK_NPCClient.so", name, label, dumpArgIndex, lenArgIndex, 128);
  });

  [
    ["Java_org_hik_np_NPClient_NPCCreate", "NPClient.NPCCreate", 4],
    ["Java_org_hik_np_NPClient_NPCOpen", "NPClient.NPCOpen", 5],
    ["Java_org_hik_np_NPClient_NPCOpenEx", "NPClient.NPCOpenEx", 6],
    ["Java_org_hik_np_NPClient_NPCSetMsgCallBack", "NPClient.NPCSetMsgCallBack", 5],
    ["Java_org_hik_np_NPClient_NPCSetTransmitMode", "NPClient.NPCSetTransmitMode", 5],
  ].forEach(([name, label, argCount]) => {
    hookArgTraceFunction("libHIK_NPCClient.so", name, label, argCount, 64);
  });

  hookExport("libPlayCtrl.so", "PlayM4_SetSecretKey", {
    onEnter(args) {
      // long port, long keyType, char *key, long keyLen.
      console.log(
        `[key] PlayM4_SetSecretKey port=${args[0].toInt32()} type=${args[1].toInt32()} key=${secretBytes(args[2], args[3].toInt32())}`,
      );
    },
    onLeave(retval) {
      console.log(`[key] PlayM4_SetSecretKey ret=${retval.toInt32()}`);
    },
  });

  hookExport("libPlayCtrl.so", "PlayM4_SetStreamOpenMode", {
    onEnter(args) {
      // long port, unsigned int mode. Live preview uses this before raw InputData.
      console.log(`[playm4] PlayM4_SetStreamOpenMode port=${args[0].toInt32()} mode=${args[1].toInt32()}`);
    },
    onLeave(retval) {
      console.log(`[playm4] PlayM4_SetStreamOpenMode ret=${retval.toInt32()}`);
    },
  });

  hookExport("libPlayCtrl.so", "PlayM4_OpenStream", {
    onEnter(args) {
      // long port, unsigned char *fileHeadBuf, unsigned int size, unsigned int poolSize.
      const len = args[2].toInt32();
      console.log(
        `[playm4] PlayM4_OpenStream port=${args[0].toInt32()} len=${len} pool=${args[3].toInt32()} head=${bytesToHex(args[1], len)}`,
      );
      dumpBytes("playm4-open-stream-head", args[1], len);
    },
    onLeave(retval) {
      console.log(`[playm4] PlayM4_OpenStream ret=${retval.toInt32()}`);
    },
  });

  hookExport("libPlayCtrl.so", "PlayM4_CloseStream", {
    onEnter(args) {
      console.log(`[playm4] PlayM4_CloseStream port=${args[0].toInt32()}`);
    },
    onLeave(retval) {
      console.log(`[playm4] PlayM4_CloseStream ret=${retval.toInt32()}`);
    },
  });

  hookExport("libPlayCtrl.so", "PlayM4_SkipErrorData", {
    onEnter(args) {
      console.log(`[playm4] PlayM4_SkipErrorData port=${args[0].toInt32()} skip=${args[1].toInt32()}`);
    },
    onLeave(retval) {
      console.log(`[playm4] PlayM4_SkipErrorData ret=${retval.toInt32()}`);
    },
  });

  [
    ["_ZN13ez_stream_sdk11EZMediaBase11startPlayerEv", "EZMediaBase::startPlayer"],
    ["_ZN13ez_stream_sdk14EZMediaPreview11startPlayerEv", "EZMediaPreview::startPlayer"],
    ["_ZN13ez_stream_sdk15EZMediaPlayback11startPlayerEv", "EZMediaPlayback::startPlayer"],
    ["_ZN13ez_stream_sdk17EZMediaPlaybackEx11startPlayerEv", "EZMediaPlaybackEx::startPlayer"],
  ].forEach(([name, label]) => {
    hookExport("libezstreamclient.so", name, {
      onEnter(args) {
        console.log(`[player] ${label} this=${args[0]}`);
      },
      onLeave(retval) {
        console.log(`[player] ${label} ret=${retval.toInt32()}`);
      },
    });
  });

  hookExport("libPlayCtrl.so", "IDMX_SetDecrptKey", {
    onEnter(args) {
      console.log(`[key] PlayCtrl.IDMX_SetDecrptKey args=${args[0]} ${args[1]} ${args[2]}`);
    },
    onLeave(retval) {
      console.log(`[key] PlayCtrl.IDMX_SetDecrptKey ret=${retval.toInt32()}`);
    },
  });

  hookExport("libPlayCtrl.so", "_ZN12CIDMXManager12SetDecrptKeyEPci15_IDMX_KEY_TYPE_", {
    onEnter(args) {
      const len = args[2].toInt32();
      console.log(
        `[key] PlayCtrl.CIDMXManager::SetDecrptKey this=${args[0]} key=${secretBytes(args[1], len)} type=${args[3].toInt32()}`,
      );
    },
  });

  hookExport("libSystemTransform.so", "SYSTRANS_SetEncryptKey", {
    onEnter(args) {
      // void *handle, enum encryptType, char *key, uint keyLen.
      console.log(
        `[key] SYSTRANS_SetEncryptKey handle=${args[0]} type=${args[1].toInt32()} key=${secretBytes(args[2], args[3].toInt32())}`,
      );
    },
    onLeave(retval) {
      console.log(`[key] SYSTRANS_SetEncryptKey ret=${retval.toInt32()}`);
    },
  });

  hookExport("libSystemTransform.so", "_ZN15CTransformProxy13SetEncryptKeyE17_ST_ENCRYPT_TYPE_Pcj", {
    onEnter(args) {
      console.log(
        `[key] CTransformProxy::SetEncryptKey this=${args[0]} type=${args[1].toInt32()} key=${secretBytes(args[2], args[3].toInt32())}`,
      );
    },
    onLeave(retval) {
      console.log(`[key] CTransformProxy::SetEncryptKey ret=${retString(retval)}`);
    },
  });

  [
    ["SYSTRANS_Create", "SYSTRANS_Create", 1],
    ["SYSTRANS_CreateEx", "SYSTRANS_CreateEx", 1],
    ["SYSTRANS_OpenStreamAdvanced", "SYSTRANS_OpenStreamAdvanced", 4],
    ["SYSTRANS_Start", "SYSTRANS_Start", 3],
    ["SYSTRANS_Stop", "SYSTRANS_Stop", 1],
    ["SYSTRANS_StreamEnd", "SYSTRANS_StreamEnd", 2],
    ["SYSTRANS_SkipErrorData", "SYSTRANS_SkipErrorData", 2],
    ["SYSTRANS_Release", "SYSTRANS_Release", 1],
    ["SYSTRANS_InputCustomStream", "SYSTRANS_InputCustomStream", 2],
    ["IDMX_CreateHandle", "IDMX_CreateHandle", 1],
    ["IDMX_OutputData", "IDMX_OutputData", 2],
  ].forEach(([name, label, argCount]) => {
    hookArgTraceFunction("libSystemTransform.so", name, label, argCount, 64);
  });

  [
    ["SYSTRANS_RegisterOutputDataCallBack", "SYSTRANS_RegisterOutputDataCallBack", false],
    ["SYSTRANS_RegisterOutputDataCallBackEx", "SYSTRANS_RegisterOutputDataCallBackEx", false],
    ["SYSTRANS_RegisterDetailDataCallBack", "SYSTRANS_RegisterDetailDataCallBack", true],
  ].forEach(([name, label, detail]) => {
    hookExport("libSystemTransform.so", name, {
      onEnter(args) {
        console.log(`[cb] ${label} handle=${args[0]} cb=${args[1]} user=${args[2]}`);
        hookOutputDataInfoCallbackPointer(label, args[1], detail);
      },
      onLeave(retval) {
        console.log(`[cb] ${label} ret=${retString(retval)}`);
      },
    });
  });

  [
    ["SYSTRANS_RegisterStreamInforCB", "SYSTRANS_RegisterStreamInforCB"],
    ["SYSTRANS_RegisterPackInfoCallBack", "SYSTRANS_RegisterPackInfoCallBack"],
  ].forEach(([name, label]) => {
    hookExport("libSystemTransform.so", name, {
      onEnter(args) {
        console.log(`[cb] ${label} handle=${args[0]} cb=${args[1]} user=${args[2]}`);
        hookLoggingCallbackPointer(label, args[1], 64);
      },
      onLeave(retval) {
        console.log(`[cb] ${label} ret=${retString(retval)}`);
      },
    });
  });

  [
    ["_ZN15CTransformProxy26RegisterOutputDataCallBackEPFvP15OUTPUTDATA_INFOPvES2_", "CTransformProxy::RegisterOutputDataCallBack(output,void*)", false],
    ["_ZN15CTransformProxy26RegisterOutputDataCallBackEPFvP15OUTPUTDATA_INFOmEm", "CTransformProxy::RegisterOutputDataCallBack(output,ulong)", false],
    ["_ZN15CTransformProxy26RegisterOutputDataCallBackEPFvP18_DETAIL_DATA_INFO_PvES2_", "CTransformProxy::RegisterOutputDataCallBack(detail)", true],
    ["_ZN10CMXManager26RegisterOutputDataCallBackEPFvP15OUTPUTDATA_INFOPvES2_", "CMXManager::RegisterOutputDataCallBack(output,void*)", false],
    ["_ZN10CMXManager26RegisterOutputDataCallBackEPFvP15OUTPUTDATA_INFOmEm", "CMXManager::RegisterOutputDataCallBack(output,ulong)", false],
    ["_ZN10CMXManager22RegisterDetailCallBackEPFvP18_DETAIL_DATA_INFO_PvES2_", "CMXManager::RegisterDetailCallBack", true],
    ["_ZN11CDMXManager26RegisterOutputDataCallBackEPFvP15OUTPUTDATA_INFOPvES2_", "CDMXManager::RegisterOutputDataCallBack", false],
    ["_ZN11CDMXManager22RegisterDetailCallBackEPFvP18_DETAIL_DATA_INFO_PvES2_", "CDMXManager::RegisterDetailCallBack", true],
    ["_ZN6CError26RegisterOutputDataCallBackEPFvP15OUTPUTDATA_INFOPvES2_", "CError::RegisterOutputDataCallBack(output,void*)", false],
    ["_ZN6CError26RegisterOutputDataCallBackEPFvP15OUTPUTDATA_INFOmEm", "CError::RegisterOutputDataCallBack(output,ulong)", false],
    ["_ZN6CError22RegisterDetailCallBackEPFvP18_DETAIL_DATA_INFO_PvES2_", "CError::RegisterDetailCallBack", true],
  ].forEach(([name, label, detail]) => {
    hookExport("libSystemTransform.so", name, {
      onEnter(args) {
        console.log(`[cb] ${label} this=${args[0]} cb=${args[1]} user=${args[2]}`);
        hookOutputDataInfoCallbackPointer(label, args[1], detail);
      },
    });
  });

  [
    ["_ZN15CTransformProxy21RegisterStreamInforCBEPFvP15_ST_ERROR_INFO_PvES2_", "CTransformProxy::RegisterStreamInforCB"],
    ["_ZN15CTransformProxy24RegisterPackInfoCallBackEPFvP12ST_PACK_INFOPvES2_", "CTransformProxy::RegisterPackInfoCallBack"],
    ["_ZN10CMXManager24RegisterPackInfoCallBackEPFvP12ST_PACK_INFOPvES2_", "CMXManager::RegisterPackInfoCallBack"],
    ["_ZN6CError21RegisterErrorCallBackEPFvP15_ST_ERROR_INFO_PvES2_", "CError::RegisterErrorCallBack"],
  ].forEach(([name, label]) => {
    hookExport("libSystemTransform.so", name, {
      onEnter(args) {
        console.log(`[cb] ${label} this=${args[0]} cb=${args[1]} user=${args[2]}`);
        hookLoggingCallbackPointer(label, args[1], 64);
      },
    });
  });

  [
    ["_ZN10CMXManager13SetEncryptKeyE17_ST_ENCRYPT_TYPE_Pcj", "CMXManager::SetEncryptKey", 2, 3],
    ["_ZN11CDMXManager13SetDecryptKeyE17_ST_ENCRYPT_TYPE_Pcj", "CDMXManager::SetDecryptKey", 2, 3],
    ["_ZN12CIMuxManager13SetEncryptKeyEPhj", "CIMuxManager::SetEncryptKey", 1, 2],
  ].forEach(([name, label, keyArgIndex, lenArgIndex]) => {
    hookExport("libSystemTransform.so", name, {
      onEnter(args) {
        const len = args[lenArgIndex].toInt32();
        console.log(`[key] ${label} this=${args[0]} key=${secretBytes(args[keyArgIndex], len)}`);
      },
      onLeave(retval) {
        console.log(`[key] ${label} ret=${retString(retval)}`);
      },
    });
  });

  hookExport("libSystemTransform.so", "SYSTRANS_InputData", {
    onEnter(args) {
      // void *handle, DATA_TYPE type, unsigned char *data, uint len.
      const len = args[3].toInt32();
      console.log(`[in] SYSTRANS_InputData handle=${args[0]} type=${args[1].toInt32()} len=${len} head=${bytesToHex(args[2], len)}`);
      dumpBytes("systrans-input", args[2], len);
    },
  });

  hookExport("libSystemTransform.so", "SYSTRANS_InputPrivateData", {
    onEnter(args) {
      // void *handle, uint type, uint subType, unsigned char *data, uint len.
      const len = args[4].toInt32();
      console.log(`[in] SYSTRANS_InputPrivateData handle=${args[0]} type=${args[1].toInt32()} subType=${args[2].toInt32()} len=${len} head=${bytesToHex(args[3], len)}`);
      dumpBytes("systrans-private-input", args[3], len);
    },
  });

  hookExport("libSystemTransform.so", "IDMX_InputData", {
    onEnter(args) {
      // Lower-level demux input: handle, data, len, consumed/flags ptr.
      const len = args[2].toInt32();
      console.log(`[in] IDMX_InputData handle=${args[0]} len=${len} head=${bytesToHex(args[1], len)}`);
      dumpBytes("idmx-input", args[1], len);
    },
  });

  hookExport("libPlayCtrl.so", "IDMX_InputData", {
    onEnter(args) {
      const len = args[2].toInt32();
      console.log(`[in] PlayCtrl.IDMX_InputData handle=${args[0]} len=${len} head=${bytesToHex(args[1], len)}`);
      dumpBytes("playctrl-idmx-input", args[1], len);
    },
  });

  hookExport("libSystemTransform.so", "_Z19IDMXAESDecryptFramePhjjjS_", {
    onEnter(args) {
      // unsigned char *data, uint len, uint frameType, uint encryptType, unsigned char *key.
      this.data = args[0];
      this.len = args[1].toInt32();
      console.log(
        `[aes] IDMXAESDecryptFrame len=${this.len} frameType=${args[2].toInt32()} encryptType=${args[3].toInt32()} key=${secretBytes(args[4], 32)}`,
      );
      dumpBytes("idmx-aes-frame-before", this.data, this.len);
    },
    onLeave(retval) {
      console.log(`[aes] IDMXAESDecryptFrame ret=${retval.toInt32()}`);
      dumpBytes("idmx-aes-frame-after", this.data, this.len);
    },
  });

  hookExport("libSystemTransform.so", "_Z22IDMXAESDEcrpytFrameComPhjjjS_", {
    onEnter(args) {
      // unsigned char *data, uint len, uint frameType, uint encryptType, unsigned char *key.
      this.data = args[0];
      this.len = args[1].toInt32();
      console.log(
        `[aes] IDMXAESDEcrpytFrameCom len=${this.len} frameType=${args[2].toInt32()} encryptType=${args[3].toInt32()} key=${secretBytes(args[4], 32)}`,
      );
      dumpBytes("idmx-aes-frame-com-before", this.data, this.len);
    },
    onLeave(retval) {
      console.log(`[aes] IDMXAESDEcrpytFrameCom ret=${retval.toInt32()}`);
      dumpBytes("idmx-aes-frame-com-after", this.data, this.len);
    },
  });

  hookExport("libSystemTransform.so", "_Z23IDMXProcessEncryptFramePhjjP15_IDMX_AES_NALU_", {
    onEnter(args) {
      // unsigned char *data, uint len, uint naluCount, _IDMX_AES_NALU_ *entries.
      this.data = args[0];
      this.len = args[1].toInt32();
      console.log(
        `[aes] IDMXProcessEncryptFrame len=${this.len} naluCount=${args[2].toInt32()} entries=${args[3]}`,
      );
      dumpBytes("idmx-process-encrypt-before", this.data, this.len);
    },
    onLeave(retval) {
      console.log(`[aes] IDMXProcessEncryptFrame ret=${retval.toInt32()}`);
      dumpBytes("idmx-process-encrypt-after", this.data, this.len);
    },
  });

  hookExport("libPlayCtrl.so", "_Z19IDMXAESDecryptFramePhjjjS_P29_IDMX_ENCRYPT_LEN_FRAME_INFO_", {
    onEnter(args) {
      this.data = args[0];
      this.len = args[1].toInt32();
      console.log(
        `[aes] PlayCtrl.IDMXAESDecryptFrame len=${this.len} frameType=${args[2].toInt32()} encryptType=${args[3].toInt32()} key=${secretBytes(args[4], 32)} encLenInfo=${args[5]}`,
      );
      dumpBytes("playctrl-idmx-aes-frame-before", this.data, this.len);
    },
    onLeave(retval) {
      console.log(`[aes] PlayCtrl.IDMXAESDecryptFrame ret=${retval.toInt32()}`);
      dumpBytes("playctrl-idmx-aes-frame-after", this.data, this.len);
    },
  });

  hookExport("libPlayCtrl.so", "_Z22IDMXAESDEcrpytFrameComPhjjjS_", {
    onEnter(args) {
      this.data = args[0];
      this.len = args[1].toInt32();
      console.log(
        `[aes] PlayCtrl.IDMXAESDEcrpytFrameCom len=${this.len} frameType=${args[2].toInt32()} encryptType=${args[3].toInt32()} key=${secretBytes(args[4], 32)}`,
      );
      dumpBytes("playctrl-idmx-aes-frame-com-before", this.data, this.len);
    },
    onLeave(retval) {
      console.log(`[aes] PlayCtrl.IDMXAESDEcrpytFrameCom ret=${retval.toInt32()}`);
      dumpBytes("playctrl-idmx-aes-frame-com-after", this.data, this.len);
    },
  });

  hookExport("libPlayCtrl.so", "_Z23IDMXProcessEncryptFramePhjjP15_IDMX_AES_NALU_", {
    onEnter(args) {
      this.data = args[0];
      this.len = args[1].toInt32();
      console.log(
        `[aes] PlayCtrl.IDMXProcessEncryptFrame len=${this.len} naluCount=${args[2].toInt32()} entries=${args[3]}`,
      );
      dumpBytes("playctrl-idmx-process-encrypt-before", this.data, this.len);
    },
    onLeave(retval) {
      console.log(`[aes] PlayCtrl.IDMXProcessEncryptFrame ret=${retval.toInt32()}`);
      dumpBytes("playctrl-idmx-process-encrypt-after", this.data, this.len);
    },
  });

  hookExport("libPlayCtrl.so", "PlayM4_InputData", {
    onEnter(args) {
      // long port, unsigned char *buf, unsigned int size.
      const len = args[2].toInt32();
      console.log(`[in] PlayM4_InputData port=${args[0].toInt32()} len=${len} head=${bytesToHex(args[1], len)}`);
      dumpBytes("playm4-input", args[1], len);
    },
  });

  [
    ["_ZN12IDMXRTPDemux9InputDataEPhjPj", "IDMXRTPDemux::InputData", 1, 2],
    ["_ZN12IDMXRTPDemux14ProcessPayloadEP18_RTP_DEMUX_OUTPUT_", "IDMXRTPDemux::ProcessPayload", 1, null],
    ["_ZN12IDMXRTPDemux10OutputDataEP18_IDMX_PACKET_INFO_", "IDMXRTPDemux::OutputData", 1, null],
    ["_ZN12IDMXRTPDemux11AddFuPacketEPhjS0_j", "IDMXRTPDemux::AddFuPacket", 1, 2],
    ["_ZN12IDMXRTPDemux17ProcessLostPacketEj", "IDMXRTPDemux::ProcessLostPacket", null, null],
    ["_ZN14IDMXRTPJTDemux9InputDataEPhjPj", "IDMXRTPJTDemux::InputData", 1, 2],
    ["_ZN14IDMXRTPJTDemux14ProcessPayloadEP20_RTPJT_DEMUX_OUTPUT_", "IDMXRTPJTDemux::ProcessPayload", 1, null],
    ["_ZN14IDMXRTPJTDemux10OutputDataEP18_IDMX_PACKET_INFO_", "IDMXRTPJTDemux::OutputData", 1, null],
    ["_ZN14IDMXRTPJTDemux15AddToVideoFrameEPhj", "IDMXRTPJTDemux::AddToVideoFrame", 1, 2],
    ["_ZN14IDMXRTPJTDemux15AddToAudioFrameEPhj", "IDMXRTPJTDemux::AddToAudioFrame", 1, 2],
    ["_ZN12IDMXRawDemux9InputDataEPhjPj", "IDMXRawDemux::InputData", 1, 2],
    ["_ZN12IDMXRawDemux12ProcessFrameEPhj", "IDMXRawDemux::ProcessFrame", 1, 2],
    ["_ZN12IDMXRawDemux10OutputDataEP18_IDMX_PACKET_INFO_", "IDMXRawDemux::OutputData", 1, null],
    ["_ZN12IDMXRawDemux15AddToVideoFrameEPhj", "IDMXRawDemux::AddToVideoFrame", 1, 2],
    ["_ZN11IDMXTSDemux9InputDataEPhjPj", "IDMXTSDemux::InputData", 1, 2],
    ["_ZN11IDMXTSDemux14ProcessPayloadEP20_MPEG2_DEMUX_OUTPUT_", "IDMXTSDemux::ProcessPayload", 1, null],
    ["_ZN11IDMXTSDemux19ProcessPayloadMultiEP20_MPEG2_DEMUX_OUTPUT_", "IDMXTSDemux::ProcessPayloadMulti", 1, null],
    ["_ZN11IDMXTSDemux10OutputDataEP18_IDMX_PACKET_INFO_", "IDMXTSDemux::OutputData", 1, null],
    ["_ZN11IDMXTSDemux10AddToFrameEPhj", "IDMXTSDemux::AddToFrame", 1, 2],
    ["_ZN11IDMXTSDemux12AddToAPFrameEPhj", "IDMXTSDemux::AddToAPFrame", 1, 2],
    ["_ZN11IDMXTSDemux14AddToDataFrameEPhj", "IDMXTSDemux::AddToDataFrame", 1, 2],
  ].forEach(([name, label, dumpArgIndex, lenArgIndex]) => {
    hookPointerDataFunction("libPlayCtrl.so", name, `PlayCtrl.${label}`, dumpArgIndex, lenArgIndex);
    hookPointerDataFunction("libSystemTransform.so", name, `SystemTransform.${label}`, dumpArgIndex, lenArgIndex);
  });

  [
    ["_ZN12CIDMXManager9InputDataEPhjPj", "CIDMXManager::InputData", 1, 2],
    ["_ZN12CIDMXManager10OutputDataEP16_IDMX_FRMAE_INFO", "CIDMXManager::OutputData", 1, null],
    ["_ZN12CIDMXManager17ProcessCodecFrameEPhjj", "CIDMXManager::ProcessCodecFrame", 1, 2],
    ["_ZN12CIDMXManager17GetVideoFrameInfoEP18_IDMX_PACKET_INFO_", "CIDMXManager::GetVideoFrameInfo", 1, null],
    ["_ZN11CDMXManager9InputDataE9DATA_TYPEPhj", "CDMXManager::InputData", 2, 3],
    ["_ZN11CDMXManager14ParseRtpPacketEPhj", "CDMXManager::ParseRtpPacket", 1, 2],
    ["_ZN11CDMXManager17ProcessVideoFrameEP16_IDMX_FRMAE_INFO", "CDMXManager::ProcessVideoFrame", 1, null],
    ["_ZN11CDMXManager12ProcessFrameEP16_IDMX_FRMAE_INFO", "CDMXManager::ProcessFrame", 1, null],
    ["_ZN11CDMXManager11ParseStreamEv", "CDMXManager::ParseStream", null, null],
    ["_ZN11CDMXManager12PushFileDataEv", "CDMXManager::PushFileData", null, null],
    ["_ZN10CMXManager9InputDataEPhjP13ST_FRAME_INFO", "CMXManager::InputData", 1, 2],
    ["_ZN10CMXManager16InputPrivateDataEjjPhj", "CMXManager::InputPrivateData", 3, 4],
    ["_ZN10CMXManager12ProcessFrameEPhjP13ST_FRAME_INFO", "CMXManager::ProcessFrame", 1, 2],
    ["_ZN10CMXManager17InputCustomStreamEP21_ST_CUSTOM_DATA_INFO_", "CMXManager::InputCustomStream", 1, null],
    ["_ZN10CMXManager10OutputDataEP15_MX_OUTPUT_BUF_P17_MX_OUTPUT_PARAM_P13ST_FRAME_INFO", "CMXManager::OutputData", null, null],
    ["_ZN12CIMuxManager9InputDataEP16_MX_INPUT_PARAM_Phj", "CIMuxManager::InputData", 2, 3],
    ["_ZN12CIMuxManager10OutputDataEP17_MX_OUTPUT_PARAM_PPhPj", "CIMuxManager::OutputData", null, null],
    ["IMUX_InputData", "IMUX_InputData", 2, 3],
    ["IMUX_OutputData", "IMUX_OutputData", null, null],
    ["_ZN11CDMXManager13SkipErrorDataEi", "CDMXManager::SkipErrorData", null, null],
    ["_ZN11CDMXManager9StreamEndEj", "CDMXManager::StreamEnd", null, null],
    ["_ZN15CTransformProxy9InputDataE9DATA_TYPEPhj", "CTransformProxy::InputData", 2, 3],
    ["_ZN15CTransformProxy16InputPrivateDataEjjPhj", "CTransformProxy::InputPrivateData", 3, 4],
    ["_ZN15CTransformProxy8RawDemuxE9DATA_TYPEPhj", "CTransformProxy::RawDemux", 2, 3],
    ["_ZN15CTransformProxy17InputCustomStreamEP21_ST_CUSTOM_DATA_INFO_", "CTransformProxy::InputCustomStream", 1, null],
    ["_ZN15CTransformProxy13SkipErrorDataEi", "CTransformProxy::SkipErrorData", null, null],
    ["_ZN15CTransformProxy9StreamEndEj", "CTransformProxy::StreamEnd", null, null],
    ["_ZN15CTransformProxy14AnalyzeSrcInfoEP14SYS_TRANS_PARA", "CTransformProxy::AnalyzeSrcInfo", null, null],
    ["_ZN15CTransformProxy9InitDemuxEP14SYS_TRANS_PARA", "CTransformProxy::InitDemux", null, null],
  ].forEach(([name, label, dumpArgIndex, lenArgIndex]) => {
    hookPointerDataFunction("libSystemTransform.so", name, `SystemTransform.${label}`, dumpArgIndex, lenArgIndex);
  });

  [
    ["_ZN6NetSDK11CPreviewMgr6CreateEiPK19NET_DVR_PREVIEWINFOPFvijPhjPvES5_j", "CPreviewMgr::Create(preview)", 3, 2, 3],
    ["_ZN6NetSDK11CPreviewMgr6CreateEiPK27NET_DVR_PREVIEWINFO_SPECIALPFvijPhjPvES5_", "CPreviewMgr::Create(special)", 3, 2, 3],
    ["_ZN6NetSDK15CPreviewSession19SetRealDataCallBackEPFvijPhjjEj", "CPreviewSession::SetRealDataCallBack", 1, 2, 3],
    ["_ZN6NetSDK15CPreviewSession21SetRealDataCallBackExEPFvijPhjPvES2_", "CPreviewSession::SetRealDataCallBackEx", 1, 2, 3],
    ["_ZN6NetSDK15CPreviewSession23SetStandardDataCallBackEPFvijPhjjEj", "CPreviewSession::SetStandardDataCallBack", 1, 2, 3],
    ["_ZN6NetSDK15CPreviewSession25SetStandardDataCallBackExEPFvijPhjPvES2_", "CPreviewSession::SetStandardDataCallBackEx", 1, 2, 3],
    ["_ZN6NetSDK15CPreviewSession26SetTransparentDataCallBackEPFvijPhjPvES2_", "CPreviewSession::SetTransparentDataCallBack", 1, 2, 3],
    ["_ZN6NetSDK15CPreviewSession13SetESCallBackEPFvijPhjPvES2_", "CPreviewSession::SetESCallBack", 1, 2, 3],
  ].forEach(([name, label, cbIndex, dumpArgIndex, lenArgIndex]) => {
    hookExport("libHCPreview.so", name, {
      onEnter(args) {
        console.log(`[cb] ${label} this=${args[0]} cb=${args[cbIndex]} user=${args[cbIndex + 1]}`);
        hookCallbackPointer(label, args[cbIndex], dumpArgIndex, lenArgIndex);
      },
      onLeave(retval) {
        console.log(`[cb] ${label} ret=${retString(retval)}`);
      },
    });
  });

  hookExport("libHCPreview.so", "_ZN6NetSDK15CPreviewSession21SetESRealPlayCallBackEPFviP25tagNET_DVR_PACKET_INFO_EXPvES3_", {
    onEnter(args) {
      console.log(`[cb] CPreviewSession::SetESRealPlayCallBack this=${args[0]} cb=${args[1]} user=${args[2]}`);
      hookLoggingCallbackPointer("CPreviewSession::SetESRealPlayCallBack", args[1], 64);
    },
    onLeave(retval) {
      console.log(`[cb] CPreviewSession::SetESRealPlayCallBack ret=${retString(retval)}`);
    },
  });

  [
    ["_ZN6NetSDK14CGetStreamBase13GetStreamDataEPvPKvjj", "CGetStreamBase::GetStreamData", 2, 3],
    ["_ZN6NetSDK14CGetStreamBase11ProcTcpDataEPKvjj", "CGetStreamBase::ProcTcpData", 1, 2],
    ["_ZN6NetSDK14CGetStreamBase15PushConvertDataEPKvjjj", "CGetStreamBase::PushConvertData", 1, 2],
    ["_ZN6NetSDK14CGetStreamBase17GetStreamDataTypeEPKvjj", "CGetStreamBase::GetStreamDataType", 1, 2],
    ["_ZN6NetSDK14CGetStreamBase16IsNeedUseConvertEj", "CGetStreamBase::IsNeedUseConvert", null, null],
    ["_ZN6NetSDK13CUserCallBack25InputDefaultDataToConvertEPKvjj", "CUserCallBack::InputDefaultDataToConvert", 1, 2],
    ["_ZN6NetSDK13CUserCallBack12GetStreamHikEPKvjj", "CUserCallBack::GetStreamHik", 1, 2],
    ["_ZN6NetSDK13CUserCallBack12GetStreamSTDEPKvjj", "CUserCallBack::GetStreamSTD", 1, 2],
    ["_ZN6NetSDK13CUserCallBack15GetStreamV30HikEPKvjj", "CUserCallBack::GetStreamV30Hik", 1, 2],
    ["_ZN6NetSDK13CGetTCPStream17ProRTPOverTCPDataEPvPKvjj", "CGetTCPStream::ProRTPOverTCPData", 2, 3],
    ["_ZNK11CQosOperate9AddPacketEiPhj", "CQosOperate::AddPacket", 2, 3],
    ["_ZN6NetSDK15CGetHRUDPStream16ProcessTCPDataCBEPvPKvjj", "CGetHRUDPStream::ProcessTCPDataCB", 2, 3],
    ["_ZN6NetSDK15CGetHRUDPStream16CopyTCPDataToBufEPKvj", "CGetHRUDPStream::CopyTCPDataToBuf", 1, 2],
    ["_ZN6NetSDK15CGetHRUDPStream17SortAndSaveByNodeEPKhjjj", "CGetHRUDPStream::SortAndSaveByNode", 1, 2],
    ["_ZN6NetSDK15CGetHRUDPStream11SortAndSaveEPKhjjj", "CGetHRUDPStream::SortAndSave", 1, 2],
    ["_ZN6NetSDK15CGetHRUDPStream19InsertAtAllocatePosEPhPKhjjj", "CGetHRUDPStream::InsertAtAllocatePos", 2, 3],
    ["_ZN6NetSDK13CGetNPQStream15NpqDataCallBackEiiPhjPv", "CGetNPQStream::NpqDataCallBack", 3, 4],
    ["_ZN6NetSDK13CGetNPQStream14ProcStreamDataEPKvj", "CGetNPQStream::ProcStreamData", 1, 2],
    ["_ZN6NetSDK14CGetPushStream13QosPacketSendEiPhjPv", "CGetPushStream::QosPacketSend", 2, 3],
    ["_ZN6NetSDK14CGetPushStream12QosPacketRawEiPhjPv", "CGetPushStream::QosPacketRaw", 2, 3],
    ["_ZN6NetSDK14CGetPushStream16RecvDataCallBackEPvPKvjj", "CGetPushStream::RecvDataCallBack", 2, 3],
    ["_ZN6NetSDK14CGetPushStream11SendCommandEjPKvj", "CGetPushStream::SendCommand", 2, 3],
    ["_ZN6NetSDK14CGetRTSPStream13ProcessRTPMsgEPvPKvj", "CGetRTSPStream::ProcessRTPMsg", 2, 3],
    ["_ZN6NetSDK14CGetRTSPStream15ParseRecvExDataEPKhj", "CGetRTSPStream::ParseRecvExData", 1, 2],
    ["_ZN6NetSDK14CGetRTSPStream11NpqCallbackEiiPhjPv", "CGetRTSPStream::NpqCallback", 3, 4],
    ["_ZN6NetSDK14CGetRTSPStream14ProcessRTPDataEPviPKvjj", "CGetRTSPStream::ProcessRTPData", 3, 4],
    ["_ZN6NetSDK14CGetRTSPStream19ProcessRTPDataNoNpqEPviPKvjj", "CGetRTSPStream::ProcessRTPDataNoNpq", 3, 4],
    ["_ZN6NetSDK14CGetStreamBase13GetStreamDataEPvPKvjj", "CGetStreamBase::GetStreamData", 2, 3],
    ["_ZN6NetSDK14CGetStreamBase11ProcTcpDataEPKvjj", "CGetStreamBase::ProcTcpData", 1, 2],
    ["_ZN6NetSDK14CGetStreamBase15PushConvertDataEPKvjjj", "CGetStreamBase::PushConvertData", 1, 2],
    ["_ZN6NetSDK14CPreviewPlayer15PlayerGetStreamEPKvjjPv", "CPreviewPlayer::PlayerGetStream", 1, 2],
    ["_ZN6NetSDK14CPreviewPlayer17InputDataToPlayerEPvj", "CPreviewPlayer::InputDataToPlayer", 1, 2],
    ["_ZN6NetSDK14CPreviewPlayer14ProccessStreamEPKvjj", "CPreviewPlayer::ProccessStream", 1, 2],
    ["_ZN6NetSDK13CUserCallBack11GetStreamTPEPKvjj", "CUserCallBack::GetStreamTP", 1, 2],
    ["_ZN6NetSDK13CUserCallBack12GetStreamHikEPKvjj", "CUserCallBack::GetStreamHik", 1, 2],
    ["_ZN6NetSDK13CUserCallBack12GetStreamSTDEPKvjj", "CUserCallBack::GetStreamSTD", 1, 2],
    ["_ZN6NetSDK13CUserCallBack15GetStreamV30HikEPKvjj", "CUserCallBack::GetStreamV30Hik", 1, 2],
    ["_ZN6NetSDK13CUserCallBack11UserGetESCBEPKvjjPv", "CUserCallBack::UserGetESCB", 1, 2],
    ["_ZN6NetSDK13CUserCallBack15UserGetStreamTPEPKvjjPv", "CUserCallBack::UserGetStreamTP", 1, 2],
    ["_ZN6NetSDK13CUserCallBack16UserGetStreamHikEPKvjjPv", "CUserCallBack::UserGetStreamHik", 1, 2],
    ["_ZN6NetSDK13CUserCallBack16UserGetStreamSTDEPKvjjPv", "CUserCallBack::UserGetStreamSTD", 1, 2],
    ["_ZN6NetSDK13CUserCallBack19UserGetStreamV30HikEPKvjjPv", "CUserCallBack::UserGetStreamV30Hik", 1, 2],
    ["_ZN6NetSDK13CUserCallBack15InputDataToFileEPvjj", "CUserCallBack::InputDataToFile", 1, 2],
    ["_ZN6NetSDK13CUserCallBack25InputDefaultDataToConvertEPKvjj", "CUserCallBack::InputDefaultDataToConvert", 1, 2],
    ["_ZN6NetSDK13CUserCallBack15WriteDataToFileEPvj", "CUserCallBack::WriteDataToFile", 1, 2],
    ["_ZN6NetSDK13CUserCallBack15UserWriteFileCBEPKvjjPv", "CUserCallBack::UserWriteFileCB", 1, 2],
    ["_ZN6NetSDK15CGetHRUDPStream17CallbackVedioDataEPKhjjj", "CGetHRUDPStream::CallbackVedioData", 1, 2],
    ["_ZN6NetSDK14CGetStreamBase21PushDateToGetStreamCBEPKvjjj", "CGetStreamBase::PushDateToGetStreamCB", 1, 2],
    ["_ZN6NetSDK14CGetStreamBase33PushDateToGetStreamCB_WithoutLockEPKvjjj", "CGetStreamBase::PushDateToGetStreamCB_WithoutLock", 1, 2],
    ["_ZN6NetSDK15CGetHRUDPStream21PushDateToGetStreamCBEPKvjjj", "CGetHRUDPStream::PushDateToGetStreamCB", 1, 2],
    ["_ZN6NetSDK13CGetNPQStream21PushDateToGetStreamCBEPKvjjj", "CGetNPQStream::PushDateToGetStreamCB", 1, 2],
  ].forEach(([name, label, dumpArgIndex, lenArgIndex]) => {
    hookPointerDataFunction("libHCPreview.so", name, `HCPreview.${label}`, dumpArgIndex, lenArgIndex);
  });

  hookExport("libHCPreview.so", "_ZNK11CQosOperate15SetCbForRawDataEiPFviPhjPvES1_", {
    onEnter(args) {
      console.log(`[cb] CQosOperate::SetCbForRawData this=${args[0]} type=${args[1].toInt32()} cb=${args[2]} user=${args[3]}`);
      hookCallbackPointer("CQosOperate::SetCbForRawData", args[2], 1, 2);
    },
    onLeave(retval) {
      console.log(`[cb] CQosOperate::SetCbForRawData ret=${retString(retval)}`);
    },
  });

  [
    ["_ZN6NetSDK14CGetStreamBase20SysTransDataCallBackEPK15OUTPUTDATA_INFOPv", "CGetStreamBase::SysTransDataCallBack"],
    ["_ZN6NetSDK13CUserCallBack20SysTransDataCallBackEPK15OUTPUTDATA_INFOPv", "CUserCallBack::SysTransDataCallBack"],
  ].forEach(([name, label]) => {
    hookExport("libHCPreview.so", name, {
      onEnter(args) {
        dumpOutputDataInfo(`HCPreview.${label}`, args[1], false, 128);
      },
    });
  });

  [
    ["COM_SetRealDataCallBack", "COM_SetRealDataCallBack", 1, 2, 3],
    ["COM_SetRealDataCallBackEx", "COM_SetRealDataCallBackEx", 1, 2, 3],
    ["COM_SetStandardDataCallBack", "COM_SetStandardDataCallBack", 1, 2, 3],
    ["COM_SetStandardDataCallBackEx", "COM_SetStandardDataCallBackEx", 1, 2, 3],
    ["COM_SetTransparentDataCallBack", "COM_SetTransparentDataCallBack", 1, 2, 3],
    ["COM_SetESCallBack", "COM_SetESCallBack", 1, 2, 3],
  ].forEach(([name, label, cbIndex, dumpArgIndex, lenArgIndex]) => {
    hookExport("libHCPreview.so", name, {
      onEnter(args) {
        console.log(`[cb] ${label} handle=${args[0]} cb=${args[cbIndex]} user=${args[2]} extra=${args[3]}`);
        hookCallbackPointer(label, args[cbIndex], dumpArgIndex, lenArgIndex);
      },
      onLeave(retval) {
        console.log(`[cb] ${label} ret=${retString(retval)}`);
      },
    });
  });

  hookExport("libHCPreview.so", "COM_SetESRealPlayCallBack", {
    onEnter(args) {
      console.log(`[cb] COM_SetESRealPlayCallBack handle=${args[0]} cb=${args[1]} user=${args[2]} extra=${args[3]}`);
      hookLoggingCallbackPointer("COM_SetESRealPlayCallBack", args[1], 64);
    },
    onLeave(retval) {
      console.log(`[cb] COM_SetESRealPlayCallBack ret=${retString(retval)}`);
    },
  });

  [
    ["COM_StartRealPlay", "COM_StartRealPlay"],
    ["COM_StopRealPlay", "COM_StopRealPlay"],
    ["COM_GetRealPlaySock", "COM_GetRealPlaySock"],
  ].forEach(([name, label]) => {
    hookExport("libHCPreview.so", name, {
      onEnter(args) {
        if (shouldLog(`[hcpreview] ${label}`, 64)) {
          console.log(`[hcpreview] ${label} args=${args[0]} ${args[1]} ${args[2]} ${args[3]}`);
        }
      },
      onLeave(retval) {
        if (shouldLog(`[hcpreview] ${label}:ret`, 64)) {
          console.log(`[hcpreview] ${label} ret=${retval.toInt32()}`);
        }
      },
    });
  });

  hookExport("libHCPreview.so", "COM_SetRealPlaySecretKey", {
    onEnter(args) {
      console.log(
        `[key] COM_SetRealPlaySecretKey handle=${args[0]} type=${args[1].toInt32()} key=${nativeSecretBytes(args[2], args[3])}`,
      );
    },
    onLeave(retval) {
      console.log(`[key] COM_SetRealPlaySecretKey ret=${retString(retval)}`);
    },
  });

  [
    ["NET_DVR_RealPlay", "NET_DVR_RealPlay", 3],
    ["NET_DVR_RealPlay_V30", "NET_DVR_RealPlay_V30", 4],
    ["NET_DVR_RealPlay_V40", "NET_DVR_RealPlay_V40", 4],
    ["NET_DVR_MakeKeyFrame", "NET_DVR_MakeKeyFrame", 2],
    ["NET_DVR_MakeKeyFrameSub", "NET_DVR_MakeKeyFrameSub", 3],
    ["NET_DVR_ZeroMakeKeyFrame", "NET_DVR_ZeroMakeKeyFrame", 2],
    ["NET_DVR_StartRecvNakedDataListen", "NET_DVR_StartRecvNakedDataListen", 2],
    ["NET_DVR_StopRecvNakedDataListen", "NET_DVR_StopRecvNakedDataListen", 1],
    ["NET_DVR_PicViewRequest", "NET_DVR_PicViewRequest", 2],
    ["COM_StartRecvNakedDataListen", "COM_StartRecvNakedDataListen", 2],
    ["COM_PicViewRequest", "COM_PicViewRequest", 2],
  ].forEach(([name, label, argCount]) => {
    const moduleName = name.startsWith("COM_") ? (name.indexOf("PicView") !== -1 ? "libHCDisplay.so" : "libHCAlarm.so") : "libhcnetsdk.so";
    hookArgTraceFunction(moduleName, name, label, argCount, 64);
  });

  [
    ["libhcnetsdk.so", "NET_DVR_MatrixSendData", "NET_DVR_MatrixSendData", 1, 2],
    ["libhcnetsdk.so", "NET_DVR_TransCodeInputData", "NET_DVR_TransCodeInputData", 1, 2],
    ["libHCDisplay.so", "COM_MatrixSendData", "COM_MatrixSendData", 1, 2],
    ["libHCDisplay.so", "COM_TransCodeInputData", "COM_TransCodeInputData", 1, 2],
    [
      "libHCAlarm.so",
      "_ZNK6NetSDK19CAlarmListenSession16ProcessNakedDataEPcjP10HPR_ADDR_Ti",
      "CAlarmListenSession::ProcessNakedData",
      1,
      2,
    ],
    [
      "libHCAlarm.so",
      "_ZN6NetSDK19CAlarmListenSession21RecvNakedDataCallBackEP10HPR_ADDR_TPvPKvjjij",
      "CAlarmListenSession::RecvNakedDataCallBack",
      3,
      4,
    ],
    ["libHCPlayBack.so", "_ZN6NetSDK14CFormatSession16RecvDataCallBackEPvPKvjj", "CFormatSession::RecvDataCallBack", 2, 3],
    ["libHCPlayBack.so", "_ZN6NetSDK11CVOD3GPFile20InputDataToSplitFileEPvjj", "CVOD3GPFile::InputDataToSplitFile", 1, 2],
    ["libHCPlayBack.so", "_ZN6NetSDK12CVODFileBase15InputDataToFileEPvji", "CVODFileBase::InputDataToFile", 1, 2],
    ["libHCPlayBack.so", "_ZN6NetSDK11CVOD3GPFile18StreamCallbackCoreEjPKvjPv", "CVOD3GPFile::StreamCallbackCore", 2, 3],
    ["libHCPlayBack.so", "_ZN6NetSDK8CVODFile20InputDataToSplitFileEPvjj", "CVODFile::InputDataToSplitFile", 1, 2],
    ["libHCPlayBack.so", "_ZN6NetSDK8CVODFile18StreamCallbackCoreEjPKvjPv", "CVODFile::StreamCallbackCore", 2, 3],
    ["libHCPlayBack.so", "_ZN6NetSDK12CVODFileBase14StreamCallbackEjPKvjPv", "CVODFileBase::StreamCallback", 2, 3],
    ["libHCPlayBack.so", "_ZN6NetSDK10CVODPlayer17InputDataToPlayerEPvjj", "CVODPlayer::InputDataToPlayer", 1, 2],
    ["libHCPlayBack.so", "_ZN6NetSDK10CVODPlayer14StreamCallbackEjPKvjPv", "CVODPlayer::StreamCallback", 2, 3],
    ["libHCPlayBack.so", "_ZN6NetSDK10CVODUserCB14StreamCallbackEjPKvjPv", "CVODUserCB::StreamCallback", 2, 3],
    ["libHCPlayBack.so", "_ZN6NetSDK20CVODHikClusterStream23ClusterRecvDataCallBackEPvPKvjj", "CVODHikClusterStream::ClusterRecvDataCallBack", 2, 3],
    ["libHCPlayBack.so", "_ZN6NetSDK14CVODStreamBase16RecvDataCallBackEPvPKvjj", "CVODStreamBase::RecvDataCallBack", 2, 3],
    ["libHCPlayBack.so", "_ZN6NetSDK15CVODISAPIStream14ProcessRTPDataEPviPKvjj", "CVODISAPIStream::ProcessRTPData", 3, 4],
    ["libHCPlayBack.so", "_ZN6NetSDK13CVODNPQStream15NpqDataCallBackEiiPhjPv", "CVODNPQStream::NpqDataCallBack", 3, 4],
    ["libHCPlayBack.so", "_ZN6NetSDK13CVODNPQStream19UDPRecvDataCallBackEPvPKvjj", "CVODNPQStream::UDPRecvDataCallBack", 2, 3],
    ["libHCDisplay.so", "_ZN6NetSDK21CPassiveDecodeSession15ParseRecvExDataEPhj", "CPassiveDecodeSession::ParseRecvExData", 1, 2],
    ["libHCDisplay.so", "_ZN6NetSDK21CPassiveDecodeSession16RecvDataCallBackEPvPKvjj", "CPassiveDecodeSession::RecvDataCallBack", 2, 3],
    ["libHCDisplay.so", "_ZN6NetSDK20CPassiveTransSession16RecvDataCallBackEPvPKvjj", "CPassiveTransSession::RecvDataCallBack", 2, 3],
    ["libHCDisplay.so", "_ZN6NetSDK20CPassiveTransSession11ProcTcpDataEjPKvj", "CPassiveTransSession::ProcTcpData", 2, 3],
    ["libHCDisplay.so", "_ZN6NetSDK20CPassiveTransSession19InputDataToCallBackEjPvj", "CPassiveTransSession::InputDataToCallBack", 2, 3],
    ["libHCDisplay.so", "_ZN6NetSDK20CPassiveTransSession15UdpDataCallBackEPvPKvjj", "CPassiveTransSession::UdpDataCallBack", 2, 3],
    ["libHCDisplay.so", "_ZN6NetSDK17CPicScreenSession21ScreenPicRecvCallBackEPvPKvjj", "CPicScreenSession::ScreenPicRecvCallBack", 2, 3],
    ["libHCCore.so", "_ZN6NetSDK12CAnalyzeData9InputDataEPhj", "CAnalyzeData::InputData", 1, 2],
    ["libHCCore.so", "_ZN6NetSDK13CNpqInterface9InputDataEiPhj", "CNpqInterface::InputData", 2, 3],
    ["libHCCore.so", "_ZN17IHardDecodePlayer9InputDataEPvj", "IHardDecodePlayer::InputData", 1, 2],
    ["libHCCore.so", "_ZN17ISoftDecodePlayer9InputDataEPvj", "ISoftDecodePlayer::InputData", 1, 2],
    ["libHCCore.so", "_ZN17ISoftDecodePlayer11DecCallBackEiPciP9frameinfoii", "ISoftDecodePlayer::DecCallBack", 2, 3],
    ["libHCCore.so", "_ZN17ISoftDecodePlayer15DisplayCallBackEiPciiiiii", "ISoftDecodePlayer::DisplayCallBack", 2, 3],
    ["libHCCore.so", "_ZN6NetSDK14CStreamConvert9InputDataEPvj", "CStreamConvert::InputData", 1, 2],
  ].forEach(([moduleName, name, label, dumpArgIndex, lenArgIndex]) => {
    hookPointerDataFunction(moduleName, name, label, dumpArgIndex, lenArgIndex, 128);
  });

  [
    ["libHCPlayBack.so", "_ZN6NetSDK11CVOD3GPFile20SysTransDataCallBackEPK15OUTPUTDATA_INFOPv", "CVOD3GPFile::SysTransDataCallBack"],
    ["libHCPlayBack.so", "_ZN6NetSDK14CVODStreamBase20SysTransDataCallBackEPK15OUTPUTDATA_INFOPv", "CVODStreamBase::SysTransDataCallBack"],
  ].forEach(([moduleName, name, label]) => {
    hookOutputDataInfoArgFunction(moduleName, name, label, 1, false, 128);
  });

  hookExport("libHCCore.so", "_ZN6NetSDK14CStreamConvert15SetDataCallBackEPFvPK15OUTPUTDATA_INFOPvES4_", {
    onEnter(args) {
      console.log(`[cb] CStreamConvert::SetDataCallBack this=${args[0]} cb=${args[1]} user=${args[2]}`);
      hookOutputDataInfoCallbackPointer("CStreamConvert::SetDataCallBack", args[1], false);
    },
    onLeave(retval) {
      console.log(`[cb] CStreamConvert::SetDataCallBack ret=${retString(retval)}`);
    },
  });

  [
    [
      "libhcnetsdk.so",
      "NET_DVR_SetNakedDataRecvCallBack",
      "NET_DVR_SetNakedDataRecvCallBack",
      1,
      2,
      3,
    ],
    ["libHCAlarm.so", "COM_SetNakedDataRecvCallBack", "COM_SetNakedDataRecvCallBack", 1, 2, 3],
    ["libhcnetsdk.so", "NET_DVR_SetPicViewDataCallBack", "NET_DVR_SetPicViewDataCallBack", 1, 2, 3],
    ["libHCDisplay.so", "COM_SetPicViewDataCallBack", "COM_SetPicViewDataCallBack", 1, 2, 3],
    ["libhcnetsdk.so", "NET_DVR_SetPlayDataCallBack", "NET_DVR_SetPlayDataCallBack", 1, 2, 3],
    ["libhcnetsdk.so", "NET_DVR_SetPlayDataCallBack_V40", "NET_DVR_SetPlayDataCallBack_V40", 1, 2, 3],
    ["libHCPlayBack.so", "COM_SetPlayDataCallBack", "COM_SetPlayDataCallBack", 1, 2, 3],
    ["libHCPlayBack.so", "COM_SetPlayDataCallBack_V40", "COM_SetPlayDataCallBack_V40", 1, 2, 3],
    [
      "libezstreamclient.so",
      "_ZN13ez_stream_sdk30EZ_NET_DVR_SetPlayDataCallBackEiPFvijPhjjEj",
      "ez_stream_sdk::EZ_NET_DVR_SetPlayDataCallBack",
      1,
      2,
      3,
    ],
    [
      "libezstreamclient.so",
      "_ZN13ez_stream_sdk34EZ_NET_DVR_SetPlayDataCallBack_V40EiPFviiPhjPvES1_",
      "ez_stream_sdk::EZ_NET_DVR_SetPlayDataCallBack_V40",
      1,
      2,
      3,
    ],
  ].forEach(([moduleName, name, label, cbIndex, dumpArgIndex, lenArgIndex]) => {
    hookCallbackSetter(moduleName, name, label, cbIndex, dumpArgIndex, lenArgIndex, 64);
  });

  [
    ["libhcnetsdk.so", "NET_DVR_SetPreviewResponseCallBack", "NET_DVR_SetPreviewResponseCallBack", 1],
    ["libhcnetsdk.so", "NET_DVR_SetPlaybackResponseCallBack", "NET_DVR_SetPlaybackResponseCallBack", 1],
    ["libhcnetsdk.so", "NET_DVR_SetPicViewResponseCallBack", "NET_DVR_SetPicViewResponseCallBack", 1],
    ["libHCCore.so", "COM_SetPreviewResponseCallBack", "COM_SetPreviewResponseCallBack", 1],
    ["libHCCore.so", "COM_SetPlaybackResponseCallBack", "COM_SetPlaybackResponseCallBack", 1],
    ["libHCCore.so", "COM_SetPicViewResponseCallBack", "COM_SetPicViewResponseCallBack", 1],
    ["libhcnetsdk.so", "NET_DVR_SetPlayBackESCallBack", "NET_DVR_SetPlayBackESCallBack", 1],
    ["libHCPlayBack.so", "COM_SetPlayESCallBack", "COM_SetPlayESCallBack", 1],
  ].forEach(([moduleName, name, label, cbIndex]) => {
    hookLoggingCallbackSetter(moduleName, name, label, cbIndex, 64);
  });

  [
    ["libhcnetsdk.so", "NET_DVR_SetSDKSecretKey", "NET_DVR_SetSDKSecretKey"],
    ["libHCCore.so", "COM_SetStreamSecretKey", "COM_SetStreamSecretKey"],
  ].forEach(([moduleName, name, label]) => {
    hookExport(moduleName, name, {
      onEnter(args) {
        console.log(`[key] ${label} handle=${args[0]} key=${secretBytes(args[1], 16)} extra=${args[2]} ${args[3]}`);
      },
      onLeave(retval) {
        console.log(`[key] ${label} ret=${retString(retval)}`);
      },
    });
  });

  [
    ["NET_DVR_SetRealPlaySecretKey", "NET_DVR_SetRealPlaySecretKey"],
    ["NET_DVR_SetPlayBackSecretKey", "NET_DVR_SetPlayBackSecretKey"],
  ].forEach(([name, label]) => {
    hookExport("libhcnetsdk.so", name, {
      onEnter(args) {
        console.log(
          `[key] ${label} handle=${args[0]} type=${args[1].toInt32()} key=${nativeSecretBytes(args[2], args[3])}`,
        );
      },
      onLeave(retval) {
        console.log(`[key] ${label} ret=${retString(retval)}`);
      },
    });
  });

  hookExport("libHCPlayBack.so", "COM_SetPlayBackSecretKey", {
    onEnter(args) {
      console.log(
        `[key] COM_SetPlayBackSecretKey handle=${args[0]} type=${args[1].toInt32()} key=${nativeSecretBytes(args[2], args[3])}`,
      );
    },
    onLeave(retval) {
      console.log(`[key] COM_SetPlayBackSecretKey ret=${retString(retval)}`);
    },
  });

  [
    ["NET_DVR_SetRealDataCallBack", "NET_DVR_SetRealDataCallBack"],
    ["NET_DVR_SetRealDataCallBackEx", "NET_DVR_SetRealDataCallBackEx"],
    ["NET_DVR_SetStandardDataCallBack", "NET_DVR_SetStandardDataCallBack"],
    ["NET_DVR_SetStandardDataCallBackEx", "NET_DVR_SetStandardDataCallBackEx"],
    ["NET_DVR_SetTransparentDataCallBack", "NET_DVR_SetTransparentDataCallBack"],
    ["NET_DVR_SetESCallBack", "NET_DVR_SetESCallBack"],
  ].forEach(([name, label]) => {
    hookExport("libhcnetsdk.so", name, {
      onEnter(args) {
        console.log(`[cb] ${label} handle=${args[0]} cb=${args[1]} user=${args[2]} extra=${args[3]}`);
        hookCallbackPointer(label, args[1], 2, 3);
      },
      onLeave(retval) {
        console.log(`[cb] ${label} ret=${retString(retval)}`);
      },
    });
  });

  hookExport("libhcnetsdk.so", "NET_DVR_SetESRealPlayCallBack", {
    onEnter(args) {
      console.log(`[cb] NET_DVR_SetESRealPlayCallBack handle=${args[0]} cb=${args[1]} user=${args[2]} extra=${args[3]}`);
      hookLoggingCallbackPointer("NET_DVR_SetESRealPlayCallBack", args[1], 64);
    },
    onLeave(retval) {
      console.log(`[cb] NET_DVR_SetESRealPlayCallBack ret=${retString(retval)}`);
    },
  });

  hookExport("libPlayCtrl.so", "PlayM4_SetDecodeCallBack", {
    onEnter(args) {
      console.log(`[cb] PlayM4_SetDecodeCallBack port=${args[0].toInt32()} cb=${args[1]}`);
    },
  });

  hookExport("libPlayCtrl.so", "PlayM4_SetDecodeCallback", {
    onEnter(args) {
      console.log(`[cb] PlayM4_SetDecodeCallback port=${args[0].toInt32()} cb=${args[1]}`);
    },
  });

  [
    ["PlayM4_SetDecCallBack", "[cb] PlayM4_SetDecCallBack", 1, 1, 2],
    ["PlayM4_SetDecCallBackMend", "[cb] PlayM4_SetDecCallBackMend", 1, 1, 2],
    ["PlayM4_RegisterDecCallBack", "[cb] PlayM4_RegisterDecCallBack", 1, 1, 2],
    ["PlayM4_RegisterStreamCallBack", "[cb] PlayM4_RegisterStreamCallBack", 1, 1, 2],
    ["PlayM4_SetDisplayCallBack", "[cb] PlayM4_SetDisplayCallBack", 1, null, null],
    ["PlayM4_SetDisplayCallBackEx", "[cb] PlayM4_SetDisplayCallBackEx", 1, null, null],
    ["PlayM4_RegisterDisplayCallBackEx", "[cb] PlayM4_RegisterDisplayCallBackEx", 1, null, null],
    ["PlayM4_RegisterDisplayCallBackExAfter", "[cb] PlayM4_RegisterDisplayCallBackExAfter", 1, null, null],
    ["PlayM4_RegisterDisplayProcessBufOutsideCallBack", "[cb] PlayM4_RegisterDisplayProcessBufOutsideCallBack", 1, null, null],
    ["PlayM4_RegisterVideoFrameCallBack", "[cb] PlayM4_RegisterVideoFrameCallBack", 1, 0, null],
    ["PlayM4_SetTextureProcessCallback", "[cb] PlayM4_SetTextureProcessCallback", 1, null, null],
  ].forEach(([name, label, cbIndex, dumpArgIndex, lenArgIndex]) => {
    hookExport("libPlayCtrl.so", name, {
      onEnter(args) {
        console.log(`${label} port=${args[0].toInt32()} cb=${args[cbIndex]}`);
        hookCallbackPointer(label.replace(/^\[cb\] /, ""), args[cbIndex], dumpArgIndex, lenArgIndex);
      },
      onLeave(retval) {
        console.log(`${label} ret=${retval.toInt32()}`);
      },
    });
  });

  [
    ["_Z23PlayM4_SetDecCallBackExiPFviPciP10FRAME_INFOPvS2_ES_i", "[cb] PlayM4_SetDecCallBackEx", 1],
    ["_Z27PlayM4_SetDecCallBackExMendiPFviPciP10FRAME_INFOPvS2_ES_iS2_", "[cb] PlayM4_SetDecCallBackExMend", 1],
    ["_Z24PlayM4_SetDisplayInnerCBiPFvP14DISPLAY_INFOEXEPv", "[cb] PlayM4_SetDisplayInnerCB", 1],
    ["_Z15VideoFrameCBFunP17PLAYM4_FRAME_INFOP18PLAYM4_SYSTEM_TIMEi", "[frame-cb] VideoFrameCBFun", null],
  ].forEach(([name, label, cbIndex]) => {
    hookExport("libPlayCtrl.so", name, {
      onEnter(args) {
        if (cbIndex === null) {
          if (shouldLog(label, 64)) {
            const frameInfo = args[0];
            console.log(`${label} frameInfo=${frameInfo} sysTime=${args[1]} arg2=${args[2].toInt32()}`);
            if (!frameInfo.isNull()) {
              console.log(`${label} frameInfoHead=${bytesToHex(frameInfo, 64)}`);
            }
          }
          return;
        }
        console.log(`${label} port=${args[0].toInt32()} cb=${args[cbIndex]}`);
        hookCallbackPointer(label.replace(/^\[cb\] /, ""), args[cbIndex], 1, 2);
      },
      onLeave(retval) {
        if (cbIndex !== null) {
          console.log(`${label} ret=${retval.toInt32()}`);
        }
      },
    });
  });

  [
    ["H264D_process_callback", "[decode] H264D_process_callback"],
    ["H264_DecodeOneFrame", "[decode] H264_DecodeOneFrame"],
    ["H264_GetDisplayFrame", "[decode] H264_GetDisplayFrame"],
    ["AVC_DecodeOneFrame", "[decode] AVC_DecodeOneFrame"],
    ["AVC_SetPostDecodeCallBack", "[cb] AVC_SetPostDecodeCallBack"],
    ["HEVCDEC_SetPostDecodeCallBack", "[cb] HEVCDEC_SetPostDecodeCallBack"],
  ].forEach(([name, label]) => {
    hookExport("libPlayCtrl.so", name, {
      onEnter(args) {
        if (shouldLog(label, 64)) {
          console.log(`${label} args=${args[0]} ${args[1]} ${args[2]} ${args[3]}`);
        }
        if (label.indexOf("SetPostDecodeCallBack") !== -1) {
          hookCallbackPointer(label.replace(/^\[cb\] /, ""), args[1], null, null);
        }
      },
      onLeave(retval) {
        if (shouldLog(`${label}:ret`, 64)) {
          console.log(`${label} ret=${retval}`);
        }
      },
    });
  });

  [
    "Java_org_MediaPlayer_PlayM4_Player_SetDecodeCallback",
    "Java_org_MediaPlayer_PlayM4_Player_SetDecodeCallbackEx",
    "Java_org_MediaPlayer_PlayM4_Player_SetDisplayCallback",
    "Java_org_MediaPlayer_PlayM4_Player_SetDisplayCallbackEx",
    "Java_org_MediaPlayer_PlayM4_Player_SetVideoFrameCB",
  ].forEach((name) => {
    hookExport("libPlayCtrl.so", name, {
      onEnter(args) {
        console.log(`[jni-cb] ${name} port=${args[2].toInt32()} cb=${args[3]}`);
      },
      onLeave(retval) {
        console.log(`[jni-cb] ${name} ret=${retval.toInt32()}`);
      },
    });
  });
}

function installJavaHooks() {
  Java.perform(() => {
    const app = Java.use("android.app.ActivityThread").currentApplication();
    if (app) {
      const baseDir = app.getExternalFilesDir(null) || app.getFilesDir();
      const file = Java.use("java.io.File").$new(baseDir, "ezviz-hook");
      file.mkdirs();
      dumpDir = file.getAbsolutePath().toString();
      console.log(`[init] dumpDir=${dumpDir}`);
    }

    function hookJavaMethodGroup(className, classLabel, methodNames, dumpByteArrays) {
      try {
        const Klass = Java.use(className);
        let hooked = 0;
        for (const methodName of methodNames) {
          if (Klass[methodName] === undefined) {
            continue;
          }
          for (const overload of Klass[methodName].overloads) {
            const argSig = overload.argumentTypes
              ? overload.argumentTypes.map((type) => type.className).join(",")
              : "?";
            overload.implementation = function () {
              const parts = [];
              for (let i = 0; i < arguments.length; i++) {
                parts.push(`arg${i}=${describeJavaMethodArg(arguments[i])}`);
              }
              console.log(`[java] ${classLabel}.${methodName}(${argSig}) ${parts.join(" ")}`);
              if (dumpByteArrays) {
                dumpFirstJavaByteArrayArg(`java-${classLabel}-${methodName}`.replace(/[^A-Za-z0-9_.-]+/g, "-"), arguments);
              }
              const ret = overload.apply(this, arguments);
              console.log(`[java] ${classLabel}.${methodName} ret=${describeJavaMethodArg(ret)}`);
              return ret;
            };
            hooked += 1;
          }
        }
        if (hooked > 0) {
          console.log(`[hook] Java ${classLabel} method-group overloads=${hooked}`);
        }
      } catch (err) {
        console.log(`[warn] Java ${classLabel} method-group unavailable: ${err}`);
      }
    }

    function hookJavaStreamCallbackClass(className, sourceLabel) {
      if (!className || className.startsWith("<") || installedJavaStreamClasses.has(className)) {
        return;
      }
      try {
        const CallbackClass = Java.use(className);
        let hooked = 0;
        [
          "onDataCallBack",
          "onDataListener",
          "onOutputData",
          "onConvertData",
          "onDataOutput",
          "onRespData",
          "onDataRefresh",
          "onMessageCallBack",
          "onStatisticsCallBack",
          "onNPCData",
          "onNPCMsg",
        ].forEach((methodName) => {
          if (CallbackClass[methodName] === undefined) {
            return;
          }
          for (const overload of CallbackClass[methodName].overloads) {
            const argSig = overload.argumentTypes
              ? overload.argumentTypes.map((type) => type.className).join(",")
              : "?";
            overload.implementation = function () {
              const parts = [];
              for (let i = 0; i < arguments.length; i++) {
                parts.push(`arg${i}=${describeJavaMethodArg(arguments[i])}`);
              }
              console.log(`[java-cb] ${className}.${methodName} source=${sourceLabel}(${argSig}) ${parts.join(" ")}`);
              dumpFirstJavaByteArrayArg(`java-cb-${className}-${methodName}`.replace(/[^A-Za-z0-9_.-]+/g, "-"), arguments);
              const ret = overload.apply(this, arguments);
              console.log(`[java-cb] ${className}.${methodName} ret=${describeJavaMethodArg(ret)}`);
              return ret;
            };
            hooked += 1;
          }
        });
        if (hooked > 0) {
          installedJavaStreamClasses.add(className);
          console.log(`[hook] Java stream callback ${className} overloads=${hooked} source=${sourceLabel}`);
        }
      } catch (err) {
        console.log(`[warn] Java stream callback hook unavailable class=${className}: ${err}`);
      }
    }

    function hookJavaCallbackRegistration(Klass, classLabel, methodName, cbArgIndex) {
      if (Klass[methodName] === undefined) {
        return;
      }
      let hooked = 0;
      for (const overload of Klass[methodName].overloads) {
        const argSig = overload.argumentTypes
          ? overload.argumentTypes.map((type) => type.className).join(",")
          : "?";
        overload.implementation = function () {
          const callbackObj = arguments[cbArgIndex];
          const callbackClass = safeJavaClassName(callbackObj);
          console.log(`[java-cb-reg] ${classLabel}.${methodName}(${argSig}) cb=${callbackClass}`);
          hookJavaStreamCallbackClass(callbackClass, `${classLabel}.${methodName}`);
          dumpFirstJavaByteArrayArg(`java-reg-${classLabel}-${methodName}`.replace(/[^A-Za-z0-9_.-]+/g, "-"), arguments);
          const ret = overload.apply(this, arguments);
          console.log(`[java-cb-reg] ${classLabel}.${methodName} ret=${describeJavaMethodArg(ret)}`);
          return ret;
        };
        hooked += 1;
      }
      if (hooked > 0) {
        console.log(`[hook] Java callback registration ${classLabel}.${methodName} overloads=${hooked}`);
      }
    }

    hookJavaMethodGroup("com.ez.stream.NativeApi", "NativeApi", [
      "createClient",
      "createClientWithUrl",
      "createPreviewHandle",
      "createPreviewHandleWithUrl",
      "destroyHandle",
      "setCallback",
      "setDataCallback2Java",
      "setPlayPort",
      "setSecretKey",
      "startPreview",
      "start",
      "startPlayback",
      "startPreconnect",
      "stopPreview",
      "stop",
      "setMediaCallback",
      "setStreamDataCallback",
      "setStreamSaveDebugPath",
      "setPlaybackConvert",
      "setMediaPlaybackConvert",
      "refreshPlayer",
      "forceIFrame",
    ], false);

    hookJavaMethodGroup("com.ez.stream.NativeApi", "NativeApi.byte-input", [
      "inputData2Cloud",
      "inputVoiceTalkData",
    ], true);

    hookJavaMethodGroup("com.hikvision.packagetransform.PackageTransform", "PackageTransform", [
      "startTransform",
      "startTransformSimple",
      "startRealTimeTransform",
      "startRealTimeTransformTS",
      "inputData",
    ], true);

    hookJavaMethodGroup("com.ez.player.EZMediaPlayer", "EZMediaPlayer", [
      "onDataListener",
      "onDataRefresh",
      "onDelayListener",
      "onErrorListener",
      "onInfoListener",
      "setOnStreamDataListener",
      "start",
      "setSecretKey",
    ], true);

    hookJavaMethodGroup("com.ez.stream.EZStreamClient", "EZStreamClient", [
      "setCallback",
      "setDataCallback2Java",
      "setPlaybackConvert",
      "startPreview",
      "startPlayback",
    ], true);

    hookJavaMethodGroup("com.ez.stream.SystemTransform", "SystemTransform", [
      "create",
      "createEx",
      "inputData",
      "setEncryptKey",
      "start",
      "startEx",
      "stop",
      "release",
    ], true);

    try {
      const NativeApi = Java.use("com.ez.stream.NativeApi");
      hookJavaCallbackRegistration(NativeApi, "NativeApi", "setCallback", 1);
      hookJavaCallbackRegistration(NativeApi, "NativeApi", "setStreamDataCallback", 1);
      hookJavaCallbackRegistration(NativeApi, "NativeApi", "setMediaCallback", 1);
      hookJavaCallbackRegistration(NativeApi, "NativeApi", "setDownloadCallback", 1);
      hookJavaCallbackRegistration(NativeApi, "NativeApi", "setDisplayCallback", 1);
      hookJavaCallbackRegistration(NativeApi, "NativeApi", "setRenderCallback", 1);
      hookJavaCallbackRegistration(NativeApi, "NativeApi", "setRenderFrameInfoCallback", 1);
    } catch (err) {
      console.log(`[warn] Java NativeApi callback registration hooks unavailable: ${err}`);
    }

    try {
      const EZStreamClient = Java.use("com.ez.stream.EZStreamClient");
      hookJavaCallbackRegistration(EZStreamClient, "EZStreamClient", "setCallback", 0);
      hookJavaCallbackRegistration(EZStreamClient, "EZStreamClient", "setStreamDataCallback", 0);
      hookJavaCallbackRegistration(EZStreamClient, "EZStreamClient", "setMediaCallback", 0);
    } catch (err) {
      console.log(`[warn] Java EZStreamClient callback registration hooks unavailable: ${err}`);
    }

    try {
      const EZMediaPlayer = Java.use("com.ez.player.EZMediaPlayer");
      hookJavaCallbackRegistration(EZMediaPlayer, "EZMediaPlayer", "setOnStreamDataListener", 0);
    } catch (err) {
      console.log(`[warn] Java EZMediaPlayer stream listener hook unavailable: ${err}`);
    }

    try {
      const SystemTransform = Java.use("com.ez.stream.SystemTransform");
      hookJavaCallbackRegistration(SystemTransform, "SystemTransform", "create", 4);
    } catch (err) {
      console.log(`[warn] Java SystemTransform callback registration hook unavailable: ${err}`);
    }

    try {
      const NPClient = Java.use("org.hik.np.NPClient");
      hookJavaCallbackRegistration(NPClient, "NPClient", "NPCOpen", 1);
      hookJavaCallbackRegistration(NPClient, "NPClient", "NPCOpenEx", 1);
      hookJavaCallbackRegistration(NPClient, "NPClient", "NPCSetMsgCallBack", 1);
    } catch (err) {
      console.log(`[warn] Java NPClient callback registration hooks unavailable: ${err}`);
    }

    try {
      const NativeApi = Java.use("com.ez.stream.NativeApi");
      for (const overload of NativeApi.setSecretKey.overloads) {
        overload.implementation = function () {
          console.log(`[java-key] NativeApi.setSecretKey argc=${arguments.length}`);
          return overload.apply(this, arguments);
        };
      }
      console.log("[hook] Java com.ez.stream.NativeApi.setSecretKey");
    } catch (err) {
      console.log(`[warn] Java NativeApi hook unavailable: ${err}`);
    }

    try {
      const NativeApi = Java.use("com.ez.stream.NativeApi");
      for (const overload of NativeApi.startDownloadFromCloud.overloads) {
        overload.implementation = function () {
          console.log(`[download-cloud] NativeApi.startDownloadFromCloud handle=${arguments[0]} ${describeDownloadCloudParam(arguments[1])}`);
          const ret = overload.apply(this, arguments);
          console.log(`[download-cloud] NativeApi.startDownloadFromCloud ret=${ret}`);
          return ret;
        };
      }
      for (const overload of NativeApi.createDownloadClient.overloads) {
        overload.implementation = function () {
          console.log(`[download-local] NativeApi.createDownloadClient ${describeInitParam(arguments[0])} tmp=${safeJavaValue(arguments[1])}`);
          const ret = overload.apply(this, arguments);
          console.log(`[download-local] NativeApi.createDownloadClient ret=${ret}`);
          return ret;
        };
      }
      for (const overload of NativeApi.startDownload.overloads) {
        overload.implementation = function () {
          console.log(`[download-local] NativeApi.startDownload handle=${arguments[0]}`);
          const ret = overload.apply(this, arguments);
          console.log(`[download-local] NativeApi.startDownload ret=${ret}`);
          return ret;
        };
      }
      console.log("[hook] Java com.ez.stream.NativeApi download methods");
    } catch (err) {
      console.log(`[warn] Java NativeApi download hooks unavailable: ${err}`);
    }

    try {
      const EZStreamClient = Java.use("com.ez.stream.EZStreamClient");
      for (const overload of EZStreamClient.startDownloadFromCloud.overloads) {
        overload.implementation = function () {
          console.log(`[download-cloud] EZStreamClient.startDownloadFromCloud ${describeDownloadCloudParam(arguments[0])}`);
          const ret = overload.apply(this, arguments);
          console.log(`[download-cloud] EZStreamClient.startDownloadFromCloud ret=${ret}`);
          return ret;
        };
      }
      console.log("[hook] Java com.ez.stream.EZStreamClient.startDownloadFromCloud");
    } catch (err) {
      console.log(`[warn] Java EZStreamClient hook unavailable: ${err}`);
    }

    try {
      const TransformUtils = Java.use("com.ezplayer.utils.TransformUtils");
      for (const overload of TransformUtils.trans.overloads) {
        overload.implementation = function () {
          console.log(
            `[transform] TransformUtils.trans format=${safeJavaValue(arguments[0])} src=${safeJavaValue(arguments[1])} dst=${safeJavaValue(arguments[2])} secret=${arguments[3] ? `<redacted len=${safeJavaValue(arguments[3]).length}>` : "<null>"} streamState=${arguments[4]} streamId=${arguments[5]} deleteSrc=${arguments[6]}`,
          );
          const ret = overload.apply(this, arguments);
          console.log(`[transform] TransformUtils.trans ret=${ret}`);
          return ret;
        };
      }
      console.log("[hook] Java com.ezplayer.utils.TransformUtils.trans");
    } catch (err) {
      console.log(`[warn] Java TransformUtils hook unavailable: ${err}`);
    }

    try {
      const GlobalHolder = Java.use("com.ezplayer.common.GlobalHolder");
      for (const overload of GlobalHolder.getCloudPlaybackTicket.overloads) {
        overload.implementation = function () {
          const business = safeJavaValue(arguments[1]);
          const serial = safeJavaValue(arguments[2]);
          const channel = safeJavaValue(arguments[3]);
          const inviter = safeJavaValue(arguments[4]);
          const refresh = safeJavaValue(arguments[5]);
          const ret = overload.apply(this, arguments);
          console.log(
            `[ticket] GlobalHolder.getCloudPlaybackTicket business=${business} serial=${serial} channel=${channel} inviter=${inviter} refresh=${refresh} ret=${ret ? `<redacted len=${safeJavaValue(ret).length}>` : "<null>"}`,
          );
          return ret;
        };
      }
      console.log("[hook] Java com.ezplayer.common.GlobalHolder.getCloudPlaybackTicket");
    } catch (err) {
      console.log(`[warn] Java GlobalHolder ticket hook unavailable: ${err}`);
    }

    try {
      const Player = Java.use("org.MediaPlayer.PlayM4.Player");
      for (const overload of Player.SetSecretKey.overloads) {
        overload.implementation = function () {
          console.log(`[java-key] Player.SetSecretKey argc=${arguments.length}`);
          return overload.apply(this, arguments);
        };
      }
      console.log("[hook] Java org.MediaPlayer.PlayM4.Player.SetSecretKey");
    } catch (err) {
      console.log(`[warn] Java PlayM4 hook unavailable: ${err}`);
    }

    try {
      const Player = Java.use("org.MediaPlayer.PlayM4.Player");
      if (Player.setStreamOpenMode !== undefined) {
        for (const overload of Player.setStreamOpenMode.overloads) {
          overload.implementation = function () {
            console.log(`[java-playm4] Player.setStreamOpenMode port=${arguments[0]} mode=${arguments[1]}`);
            const ret = overload.apply(this, arguments);
            console.log(`[java-playm4] Player.setStreamOpenMode ret=${ret}`);
            return ret;
          };
        }
      }
      if (Player.openStream !== undefined) {
        for (const overload of Player.openStream.overloads) {
          overload.implementation = function () {
            const data = arguments[1];
            const len = Number(arguments[2]) || (data ? data.length : 0);
            console.log(
              `[java-playm4] Player.openStream port=${arguments[0]} len=${len} pool=${arguments[3]} dataLen=${data ? data.length : 0}`,
            );
            dumpJavaByteArray("java-playm4-open-stream-head", data, len);
            const ret = overload.apply(this, arguments);
            console.log(`[java-playm4] Player.openStream ret=${ret}`);
            return ret;
          };
        }
      }
      if (Player.openStreamAdvanced !== undefined) {
        for (const overload of Player.openStreamAdvanced.overloads) {
          overload.implementation = function () {
            const data = arguments[3];
            const len = data ? data.length : 0;
            console.log(
              `[java-playm4] Player.openStreamAdvanced port=${arguments[0]} mode=${arguments[1]} session=${safeJavaValue(arguments[2])} dataLen=${len} pool=${arguments[4]}`,
            );
            dumpJavaByteArray("java-playm4-open-stream-advanced-head", data, len);
            const ret = overload.apply(this, arguments);
            console.log(`[java-playm4] Player.openStreamAdvanced ret=${ret}`);
            return ret;
          };
        }
      }
      if (Player.inputData !== undefined) {
        for (const overload of Player.inputData.overloads) {
          overload.implementation = function () {
            const data = arguments[1];
            const len = Number(arguments[2]) || (data ? data.length : 0);
            if (shouldLog("[java-playm4] Player.inputData", 256)) {
              console.log(`[java-playm4] Player.inputData port=${arguments[0]} len=${len} dataLen=${data ? data.length : 0}`);
              dumpJavaByteArray("java-playm4-input", data, len);
            }
            const ret = overload.apply(this, arguments);
            if (shouldLog("[java-playm4] Player.inputData:ret", 256)) {
              console.log(`[java-playm4] Player.inputData ret=${ret}`);
            }
            return ret;
          };
        }
      }
      console.log("[hook] Java org.MediaPlayer.PlayM4.Player stream input/open methods");
    } catch (err) {
      console.log(`[warn] Java PlayM4 stream input hooks unavailable: ${err}`);
    }

    function hookJavaDecodeCallbackClass(className) {
      if (!className || className.startsWith("<") || installedJavaDecodeClasses.has(className)) {
        return;
      }
      try {
        const CallbackClass = Java.use(className);
        let hooked = false;
        if (CallbackClass.onDecode !== undefined) {
          for (const overload of CallbackClass.onDecode.overloads) {
            overload.implementation = function () {
              const port = arguments[0];
              const data = arguments[1];
              const len = Number(arguments[2]) || (data ? data.length : 0);
              const meta = [];
              for (let i = 2; i < arguments.length; i++) {
                meta.push(safeJavaValue(arguments[i]));
              }
              console.log(`[decode-java] ${className}.onDecode port=${port} meta=${meta.join(",")} dataLen=${data ? data.length : 0}`);
              dumpJavaByteArray("java-decode", data, len);
              return overload.apply(this, arguments);
            };
          }
          hooked = true;
        }
        if (CallbackClass.onDecodeEx !== undefined) {
          for (const overload of CallbackClass.onDecodeEx.overloads) {
            overload.implementation = function () {
              const port = arguments[0];
              const data = arguments[1];
              const len = Number(arguments[2]) || (data ? data.length : 0);
              const meta = [];
              for (let i = 2; i < arguments.length; i++) {
                meta.push(safeJavaValue(arguments[i]));
              }
              console.log(`[decode-java] ${className}.onDecodeEx port=${port} meta=${meta.join(",")} dataLen=${data ? data.length : 0}`);
              dumpJavaByteArray("java-decode-ex", data, len);
              return overload.apply(this, arguments);
            };
          }
          hooked = true;
        }
        if (hooked) {
          installedJavaDecodeClasses.add(className);
          console.log(`[hook] Java decode callback ${className}`);
        }
      } catch (err) {
        console.log(`[warn] Java decode callback hook unavailable class=${className}: ${err}`);
      }
    }

    function hookJavaDisplayCallbackClass(className) {
      if (!className || className.startsWith("<") || installedJavaDecodeClasses.has("display:" + className)) {
        return;
      }
      try {
        const CallbackClass = Java.use(className);
        let hooked = false;
        if (CallbackClass.onDisplay !== undefined) {
          for (const overload of CallbackClass.onDisplay.overloads) {
            overload.implementation = function () {
              const port = arguments[0];
              const data = arguments[1];
              const len = Number(arguments[2]) || (data ? data.length : 0);
              const meta = [];
              for (let i = 2; i < arguments.length; i++) {
                meta.push(safeJavaValue(arguments[i]));
              }
              console.log(`[display-java] ${className}.onDisplay port=${port} meta=${meta.join(",")} dataLen=${data ? data.length : 0}`);
              dumpJavaByteArray("java-display", data, len);
              return overload.apply(this, arguments);
            };
          }
          hooked = true;
        }
        if (CallbackClass.onDisplayEx !== undefined) {
          for (const overload of CallbackClass.onDisplayEx.overloads) {
            overload.implementation = function () {
              const port = arguments[0];
              const data = arguments[1];
              const len = Number(arguments[2]) || (data ? data.length : 0);
              const meta = [];
              for (let i = 2; i < arguments.length; i++) {
                meta.push(safeJavaValue(arguments[i]));
              }
              console.log(`[display-java] ${className}.onDisplayEx port=${port} meta=${meta.join(",")} dataLen=${data ? data.length : 0}`);
              dumpJavaByteArray("java-display-ex", data, len);
              return overload.apply(this, arguments);
            };
          }
          hooked = true;
        }
        if (CallbackClass.onVideoFrame !== undefined) {
          for (const overload of CallbackClass.onVideoFrame.overloads) {
            overload.implementation = function () {
              const port = arguments[0];
              const data = arguments[1];
              const len = Number(arguments[2]) || (data ? data.length : 0);
              const meta = [];
              for (let i = 2; i < arguments.length; i++) {
                meta.push(safeJavaValue(arguments[i]));
              }
              console.log(`[display-java] ${className}.onVideoFrame port=${port} meta=${meta.join(",")} dataLen=${data ? data.length : 0}`);
              dumpJavaByteArray("java-video-frame", data, len);
              return overload.apply(this, arguments);
            };
          }
          hooked = true;
        }
        if (CallbackClass.onHWVideoFrame !== undefined) {
          for (const overload of CallbackClass.onHWVideoFrame.overloads) {
            overload.implementation = function () {
              const meta = [];
              for (let i = 0; i < arguments.length; i++) {
                meta.push(safeJavaValue(arguments[i]));
              }
              console.log(`[display-java] ${className}.onHWVideoFrame meta=${meta.join(",")}`);
              return overload.apply(this, arguments);
            };
          }
          hooked = true;
        }
        if (hooked) {
          installedJavaDecodeClasses.add("display:" + className);
          console.log(`[hook] Java display callback ${className}`);
        }
      } catch (err) {
        console.log(`[warn] Java display callback hook unavailable class=${className}: ${err}`);
      }
    }

    try {
      const Player = Java.use("org.MediaPlayer.PlayM4.Player");
      if (Player.setDecodeCB !== undefined) {
        for (const overload of Player.setDecodeCB.overloads) {
          overload.implementation = function () {
            const className = safeJavaClassName(arguments[1]);
            console.log(`[decode-cb] Player.setDecodeCB port=${arguments[0]} cb=${className}`);
            hookJavaDecodeCallbackClass(className);
            const ret = overload.apply(this, arguments);
            console.log(`[decode-cb] Player.setDecodeCB ret=${ret}`);
            return ret;
          };
        }
      }
      if (Player.setDecodeCBEx !== undefined) {
        for (const overload of Player.setDecodeCBEx.overloads) {
          overload.implementation = function () {
            const className = safeJavaClassName(arguments[1]);
            console.log(`[decode-cb] Player.setDecodeCBEx port=${arguments[0]} cb=${className}`);
            hookJavaDecodeCallbackClass(className);
            const ret = overload.apply(this, arguments);
            console.log(`[decode-cb] Player.setDecodeCBEx ret=${ret}`);
            return ret;
          };
        }
      }
      if (Player.setStreamCB !== undefined) {
        for (const overload of Player.setStreamCB.overloads) {
          overload.implementation = function () {
            const className = safeJavaClassName(arguments[1]);
            console.log(
              `[decode-cb] Player.setStreamCB port=${arguments[0]} cb=${className} args=${safeJavaValue(arguments[2])},${safeJavaValue(arguments[3])},${safeJavaValue(arguments[4])}`,
            );
            hookJavaDecodeCallbackClass(className);
            const ret = overload.apply(this, arguments);
            console.log(`[decode-cb] Player.setStreamCB ret=${ret}`);
            return ret;
          };
        }
      }
      if (Player.setDisplayCB !== undefined) {
        for (const overload of Player.setDisplayCB.overloads) {
          overload.implementation = function () {
            const className = safeJavaClassName(arguments[1]);
            console.log(`[display-cb] Player.setDisplayCB port=${arguments[0]} cb=${className}`);
            hookJavaDisplayCallbackClass(className);
            const ret = overload.apply(this, arguments);
            console.log(`[display-cb] Player.setDisplayCB ret=${ret}`);
            return ret;
          };
        }
      }
      if (Player.setDisplayCBEx !== undefined) {
        for (const overload of Player.setDisplayCBEx.overloads) {
          overload.implementation = function () {
            const className = safeJavaClassName(arguments[1]);
            console.log(`[display-cb] Player.setDisplayCBEx port=${arguments[0]} cb=${className}`);
            hookJavaDisplayCallbackClass(className);
            const ret = overload.apply(this, arguments);
            console.log(`[display-cb] Player.setDisplayCBEx ret=${ret}`);
            return ret;
          };
        }
      }
      if (Player.setVideoFrameCB !== undefined) {
        for (const overload of Player.setVideoFrameCB.overloads) {
          overload.implementation = function () {
            const className = safeJavaClassName(arguments[1]);
            console.log(`[display-cb] Player.setVideoFrameCB port=${arguments[0]} cb=${className}`);
            hookJavaDisplayCallbackClass(className);
            const ret = overload.apply(this, arguments);
            console.log(`[display-cb] Player.setVideoFrameCB ret=${ret}`);
            return ret;
          };
        }
      }
      console.log("[hook] Java PlayM4 decode/display callback registration");
    } catch (err) {
      console.log(`[warn] Java PlayM4 decode registration hook unavailable: ${err}`);
    }

    try {
      const loaded = Java.enumerateLoadedClassesSync();
      for (const className of loaded) {
        if (className.indexOf("DecodeCB") !== -1 || className.indexOf("PlayerDecode") !== -1) {
          hookJavaDecodeCallbackClass(className);
        }
        if (
          className.indexOf("DisplayCB") !== -1
          || className.indexOf("PlayerDisplay") !== -1
          || className.indexOf("VideoFrameCB") !== -1
          || className.indexOf("PlayerVideoFrame") !== -1
          || className.indexOf("com.hikvision.playerlibrary.") === 0
          || className.indexOf("HikPreviewPlayer") !== -1
          || className.indexOf("HikPreviewMultiChannelPlayer") !== -1
          || className.indexOf("HikRecordPlayer") !== -1
        ) {
          hookJavaDisplayCallbackClass(className);
        }
      }
    } catch (err) {
      console.log(`[warn] Java loaded decode callback enumeration failed: ${err}`);
    }
  });
}

installNativeHooks();
if (NATIVE_ONLY) {
  console.log(`[init] native-only mode enabled dumpDir=${dumpDir}`);
} else {
  setImmediate(installJavaHooks);
}
setInterval(installNativeHooks, 1000);
