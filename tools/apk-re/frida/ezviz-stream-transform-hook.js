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
const HEX_LIMIT = 64;
const MAX_DUMPS_PER_LABEL = 24;
const LOG_SECRET_VALUES = false;
const installed = new Set();
let dumpDir = "/sdcard/Download/ezviz-hook";
let dumpSeq = 0;
const dumpCounts = {};

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
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join(" ");
  } catch (err) {
    return `<read-failed ${err}>`;
  }
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
  const path = `${dumpDir}/${nowTag()}-${String(dumpSeq++).padStart(4, "0")}-${label}-${capped}.bin`;
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
      console.log(
        `[key] PlayM4_SetSecretKey port=${args[0].toInt32()} type=${args[1].toInt32()} key=${secretBytes(args[2], args[3].toInt32())}`,
      );
    },
    onLeave(retval) {
      console.log(`[key] PlayM4_SetSecretKey ret=${retval.toInt32()}`);
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
  });
}

installNativeHooks();
setImmediate(installJavaHooks);
setInterval(installNativeHooks, 1000);
