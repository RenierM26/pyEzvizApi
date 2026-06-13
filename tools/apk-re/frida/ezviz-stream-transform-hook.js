/*
 * EZVIZ/Hikvision stream transform tracing.
 *
 * Usage:
 *   frida -U -f com.ezviz -l tools/apk-re/frida/ezviz-stream-transform-hook.js --no-pause
 *
 * This script is intentionally diagnostic-only. It logs stream secret-key calls
 * and dumps small samples around the native demux/decrypt boundary so an
 * encrypted VTM/MPEG-PS packet can be compared with PlayCtrl/SystemTransform
 * output from the official SDK path.
 */

"use strict";

const DUMP_LIMIT = 256 * 1024;
const JAVA_DECODE_DUMP_LIMIT = 512 * 1024;
const HEX_LIMIT = 64;
const MAX_DUMPS_PER_LABEL = deviceFlagExists("/data/local/tmp/ezviz-deep-idmx-dump.flag") ? 512 : 24;
const LOG_SECRET_VALUES = false;
const DUMP_SECRET_KEYS_RAW = deviceFlagExists("/data/local/tmp/ezviz-dump-media-keys.flag");
const installed = new Set();
const installedJavaDecodeClasses = new Set();
let dumpDir = "/sdcard/Download/ezviz-hook";
let dumpSeq = 0;
const dumpCounts = {};

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

function fingerprintBytes(ptr, len) {
  if (ptr.isNull() || len <= 0) {
    return "<none>";
  }
  try {
    const data = new Uint8Array(ptr.readByteArray(len));
    let hash = 2166136261;
    for (let i = 0; i < data.length; i++) {
      hash ^= data[i];
      hash = imul32(hash, 16777619) >>> 0;
    }
    return "fnv32=" + leftPad(hash.toString(16), 8, "0");
  } catch (err) {
    return "<fingerprint-failed " + err + ">";
  }
}

function imul32(a, b) {
  if (typeof Math.imul === "function") {
    return Math.imul(a, b);
  }
  const ah = (a >>> 16) & 0xffff;
  const al = a & 0xffff;
  const bh = (b >>> 16) & 0xffff;
  const bl = b & 0xffff;
  return ((al * bl) + (((ah * bl + al * bh) << 16) >>> 0)) | 0;
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
    return `<redacted len=${len} ${fingerprintBytes(ptr, len)}>`;
  }
  return bytesToHex(ptr, len);
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
  const path = `${dumpDir}/${nowTag()}-${leftPad(dumpSeq++, 4, "0")}-${label}-${capped}.bin`;
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
  Interceptor.attach(ptr, callbacks);
  installed.add(key);
  console.log(`[hook] ${key} @ ${ptr}`);
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

  hookExport("libPlayCtrl.so", "PlayM4_SetSecretKey", {
    onEnter(args) {
      // long port, long keyType, char *key, long keyLen.
      if (DUMP_SECRET_KEYS_RAW) {
        dumpBytes("secret-playm4-key", args[2], args[3].toInt32());
      }
      console.log(
        `[key] PlayM4_SetSecretKey port=${args[0].toInt32()} type=${args[1].toInt32()} key=${secretBytes(args[2], args[3].toInt32())}`,
      );
    },
    onLeave(retval) {
      console.log(`[key] PlayM4_SetSecretKey ret=${retval.toInt32()}`);
    },
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
      if (DUMP_SECRET_KEYS_RAW) {
        dumpBytes("secret-playctrl-cidmx-key", args[1], len);
      }
      console.log(
        `[key] PlayCtrl.CIDMXManager::SetDecrptKey this=${args[0]} key=${secretBytes(args[1], len)} type=${args[3].toInt32()}`,
      );
    },
  });

  hookExport("libSystemTransform.so", "SYSTRANS_SetEncryptKey", {
    onEnter(args) {
      // void *handle, enum encryptType, char *key, uint keyLen.
      if (DUMP_SECRET_KEYS_RAW) {
        dumpBytes("secret-systrans-key", args[2], args[3].toInt32());
      }
      console.log(
        `[key] SYSTRANS_SetEncryptKey handle=${args[0]} type=${args[1].toInt32()} key=${secretBytes(args[2], args[3].toInt32())}`,
      );
    },
    onLeave(retval) {
      console.log(`[key] SYSTRANS_SetEncryptKey ret=${retval.toInt32()}`);
    },
  });

  hookExport("libSystemTransform.so", "SYSTRANS_InputData", {
    onEnter(args) {
      // void *handle, DATA_TYPE type, unsigned char *data, uint len.
      const len = args[3].toInt32();
      console.log(`[in] SYSTRANS_InputData handle=${args[0]} type=${args[1].toInt32()} len=${len} head=${bytesToHex(args[2], len)}`);
      dumpBytes("systrans-input", args[2], len);
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
setImmediate(installJavaHooks);
setInterval(installNativeHooks, 1000);
