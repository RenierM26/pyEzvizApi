"use strict";

/*
 * Narrow HCNetSDK LAN media hook.
 *
 * Goal: classify the data boundary between HCNetSDK port 8000 and the EZVIZ
 * player without dumping video, passwords, or device secrets. Logs are limited
 * to handles, data types, lengths, and short byte-shape summaries.
 */

const MAX_HEAD = 32;
const hookedLabels = {};

function findNative(name) {
  if (typeof Module.findGlobalExportByName === "function") {
    return Module.findGlobalExportByName(name);
  }
  return Module.findExportByName(null, name);
}

function hex(bytes) {
  return Array.prototype.map.call(bytes, function(b) {
    return ("0" + (b & 0xff).toString(16)).slice(-2);
  }).join("");
}

function bytesAt(ptr, len) {
  if (!ptr || ptr.isNull() || len <= 0) return new Uint8Array([]);
  const size = Math.min(len, MAX_HEAD);
  try {
    return new Uint8Array(ptr.readByteArray(size));
  } catch (e) {
    return new Uint8Array([]);
  }
}

function bodyShape(ptr, len) {
  const head = bytesAt(ptr, len);
  let kind = "binary";
  if (head.length >= 4 && head[0] === 0x00 && head[1] === 0x00 && head[2] === 0x01 && head[3] === 0xba) {
    kind = "mpeg_ps_pack";
  } else if (head.length >= 4 && head[0] === 0x00 && head[1] === 0x00 && head[2] === 0x01) {
    kind = "mpeg_ps_start";
  } else if (head.length >= 4 && head[0] === 0x48 && head[1] === 0x4b && head[2] === 0x4d && head[3] === 0x49) {
    kind = "hik_hkmi";
  } else if (head.length >= 4 && head[0] === 0x40 && head[1] === 0x40 && head[2] === 0x40 && head[3] === 0x40) {
    kind = "hik_private";
  } else if (head.length >= 1 && head[0] === 0x47) {
    kind = "mpeg_ts";
  }
  return " len=" + len + " kind=" + kind + " head=" + hex(head);
}

function hookExport(label, symbol, callbacks) {
  if (hookedLabels[label]) return 0;
  const ptr = findNative(symbol);
  if (!ptr) {
    return 0;
  }
  Interceptor.attach(ptr, callbacks);
  hookedLabels[label] = true;
  console.log("[hcmedia] hooked " + label + " @" + ptr);
  return 1;
}

function installNativeHooks() {
  let installed = 0;

  installed += hookExport(
    "EZ_NET_DVR_RealPlay_V30",
    "_ZN13ez_stream_sdk23EZ_NET_DVR_RealPlay_V30EiP18NET_DVR_CLIENTINFOPFviiPhjPvES3_i",
    {
      onEnter(args) {
        this.userId = args[0].toInt32();
        this.clientInfo = args[1];
        this.blocked = args[4].toInt32();
        console.log("[hcmedia] RealPlay_V30 enter userId=" + this.userId
          + " clientInfo=" + this.clientInfo
          + " cb=" + args[2]
          + " user=" + args[3]
          + " blocked=" + this.blocked);
      },
      onLeave(retval) {
        console.log("[hcmedia] RealPlay_V30 leave realHandle=" + retval.toInt32()
          + " userId=" + this.userId);
      },
    }
  );

  installed += hookExport(
    "HCNetSDKClient.sRealDataCallBack_V30",
    "_ZN13ez_stream_sdk14HCNetSDKClient21sRealDataCallBack_V30EiiPhjPv",
    {
      onEnter(args) {
        const realHandle = args[0].toInt32();
        const dataType = args[1].toInt32();
        const len = args[3].toUInt32();
        console.log("[hcmedia] sRealDataCallBack_V30 realHandle=" + realHandle
          + " dataType=" + dataType
          + bodyShape(args[2], len)
          + " user=" + args[4]);
      },
    }
  );

  installed += hookExport(
    "PlayM4_InputData",
    "PlayM4_InputData",
    {
      onEnter(args) {
        const port = args[0].toInt32();
        const len = args[2].toUInt32();
        console.log("[hcmedia] PlayM4_InputData port=" + port + bodyShape(args[1], len));
      },
      onLeave(retval) {
        console.log("[hcmedia] PlayM4_InputData leave ret=" + retval.toInt32());
      },
    }
  );

  installed += hookExport(
    "ezplayer.setDataCallback",
    "_Z24ezplayer_setDataCallbackPvPFviPciS_ES_",
    {
      onEnter(args) {
        console.log("[hcmedia] ezplayer_setDataCallback media=" + args[0]
          + " cb=" + args[1] + " user=" + args[2]);
      },
    }
  );

  installed += hookExport(
    "NativeApi.startPreview",
    "Java_com_ez_stream_NativeApi_startPreview",
    {
      onEnter(args) {
        console.log("[hcmedia] NativeApi.startPreview handle=" + args[2]);
      },
      onLeave(retval) {
        console.log("[hcmedia] NativeApi.startPreview leave ret=" + retval.toInt32());
      },
    }
  );

  console.log("[hcmedia] native hooks installed count=" + installed);
}

function retryNativeHooks() {
  let attempts = 0;
  const timer = setInterval(function() {
    attempts += 1;
    installNativeHooks();
    if (attempts >= 30) {
      clearInterval(timer);
    }
  }, 2000);
}

function installJavaHooks() {
  Java.perform(function() {
    try {
      const H = Java.use("com.neutral.netsdk.HCNetSDK");
      ["NET_DVR_MakeKeyFrame", "NET_DVR_MakeKeyFrameSub"].forEach(function(name) {
        H[name].overloads.forEach(function(ov) {
          ov.implementation = function() {
            const args = [].slice.call(arguments);
            console.log("[hcmedia] Java HCNetSDK." + name + " enter loginId=" + args[0] + " channel=" + args[1]);
            const ret = ov.apply(this, args);
            console.log("[hcmedia] Java HCNetSDK." + name + " leave ret=" + ret);
            return ret;
          };
        });
      });
    } catch (e) {
      console.log("[hcmedia] Java HCNetSDK hooks unavailable " + e);
    }
  });
}

setImmediate(function() {
  installNativeHooks();
  retryNativeHooks();
  if (Java.available) installJavaHooks();
});
