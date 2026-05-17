"use strict";

/*
 * Minimal HCNetSDK command-port shape capture for a LAN path.
 *
 * This intentionally avoids the broad native symbol hooks. It records only
 * command-port metadata for 8000/8443: byte ratios, small fingerprints, and
 * header/length candidates. It never prints raw payload bytes, passwords, or
 * XML values.
 */

const TARGET_SERIAL = "CS-CV310-A0-1B2WFR0120200927CCRRFAKE001";
const TARGET_IP = "192.0.2.47";
const TARGET_PORT = 8000;
const FIRST_TRIGGER_DELAY_MS = 5000;
const JAVA_RETRY_DELAY_MS = 1000;
const MAX_JAVA_ATTEMPTS = 30;
const RETRY_DELAY_MS = 3000;
const MAX_TRIGGER_ATTEMPTS = 20;
const MAX_PAYLOAD_LOGS_PER_DIRECTION = 24;
const MAX_CAPTURE_BYTES = 512;
const MAX_FINGERPRINT_BYTES = 128;

const fdPeers = new Map();
const fdLogged = new Map();
const hookedSemanticLabels = {};
const missingExportLabels = {};

const NATIVE_EXPORT_MODULES = [
  null,
  "libHCCore.so",
  "libhcnetsdk.so",
  "libezstreamclient.so",
];

function findExport(name) {
  if (Module.findGlobalExportByName) {
    const globalPtr = Module.findGlobalExportByName(name);
    if (globalPtr) return globalPtr;
  }
  for (let i = 0; i < NATIVE_EXPORT_MODULES.length; i++) {
    const moduleName = NATIVE_EXPORT_MODULES[i];
    try {
      const ptr = Module.findExportByName(moduleName, name);
      if (ptr) return ptr;
    } catch (e) {
      // Some Frida builds throw when a named module is not loaded yet.
    }
  }
  return null;
}

function hookExport(label, symbol, callbacks) {
  if (hookedSemanticLabels[label]) return 0;
  const ptr = findExport(symbol);
  if (!ptr) {
    if (!missingExportLabels[label]) {
      missingExportLabels[label] = true;
      console.log("[hcnetsdk-semantic] waiting for " + label + " symbol=" + symbol);
    }
    return 0;
  }
  Interceptor.attach(ptr, callbacks);
  hookedSemanticLabels[label] = true;
  console.log("[hcnetsdk-semantic] hooked " + label + " @" + ptr);
  return 1;
}

function readClientInfoShape(ptr) {
  if (!ptr || ptr.isNull()) return " clientInfo=<null>";
  try {
    return " clientInfo=" + ptr
      + " channel=" + ptr.readS32()
      + " linkMode=" + ptr.add(4).readS32();
  } catch (e) {
    return " clientInfo=<shape-failed:" + e + ">";
  }
}

function argWord(args, index) {
  try {
    return args[index].toInt32();
  } catch (e) {
    return "<arg" + index + ":" + e + ">";
  }
}

function argPtr(args, index) {
  try {
    return String(args[index]);
  } catch (e) {
    return "<arg" + index + ":" + e + ">";
  }
}

function ptrLenShape(label, ptr, len) {
  if (!ptr || ptr.isNull()) return " " + label + "=<null>";
  if (typeof len !== "number") return " " + label + "Len=<unknown> shape=skipped";
  if (len <= 0 || len > 65536) return " " + label + "Len=" + len + " shape=skipped";
  return " " + label + tcpPayloadShape(ptr, len);
}

function simpleCommandArgs(prefix, args, ptrIndex, lenIndex) {
  return prefix
    + " arg0=" + argWord(args, 0)
    + " arg1=" + argWord(args, 1)
    + " arg2=" + argPtr(args, 2)
    + " arg3=" + argWord(args, 3)
    + (ptrIndex >= 4 ? " arg4=" + argPtr(args, 4) : "")
    + (lenIndex >= 4 ? " arg" + lenIndex + "=" + argWord(args, lenIndex) : "")
    + ptrLenShape("in", args[ptrIndex], argWord(args, lenIndex));
}

function u16be(bytes, off) {
  return (bytes[off] << 8) + bytes[off + 1];
}

function u16le(bytes, off) {
  return bytes[off] + (bytes[off + 1] << 8);
}

function u32be(bytes, off) {
  return ((bytes[off] << 24) >>> 0)
    + (bytes[off + 1] << 16)
    + (bytes[off + 2] << 8)
    + bytes[off + 3];
}

function u32le(bytes, off) {
  return bytes[off]
    + (bytes[off + 1] << 8)
    + (bytes[off + 2] << 16)
    + ((bytes[off + 3] << 24) >>> 0);
}

function fingerprintBytes(bytes) {
  let h = 2166136261;
  for (let i = 0; i < bytes.length; i++) {
    h ^= bytes[i];
    h = Math.imul(h, 16777619) >>> 0;
  }
  return bytes.length + ":" + h.toString(16).padStart(8, "0");
}

function readSockaddr(addr, len) {
  if (addr.isNull() || len < 8) return null;
  const family = addr.readU16();
  if (family !== 2) return null; // AF_INET
  const port = (addr.add(2).readU8() << 8) | addr.add(3).readU8();
  const host = [0, 1, 2, 3].map(function(i) {
    return addr.add(4 + i).readU8();
  }).join(".");
  return { family, host, port };
}

function isHcNetSdkPeer(peer) {
  return peer && [8000, 8443].indexOf(peer.port) !== -1
    && /^(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)/.test(peer.host);
}

function plausibleLengths(bytes, totalLen) {
  const parts = [];
  [0, 2, 4, 8, 12, 16, 20, 24].forEach(function(off) {
    if (bytes.length < off + 4) return;
    const be = u32be(bytes, off);
    const le = u32le(bytes, off);
    if (be > 0 && be <= totalLen + 4096) parts.push("u32be@" + off + "=" + be);
    if (le > 0 && le <= totalLen + 4096 && le !== be) parts.push("u32le@" + off + "=" + le);
  });
  return parts.join(",");
}

function payloadKind(bytes, printableRatio, highRatio) {
  if (bytes.length >= 5 && [20, 21, 22, 23].indexOf(bytes[0]) !== -1 && bytes[1] === 3 && bytes[2] <= 4) {
    return "tls_record";
  }
  if (bytes.length >= 4 && bytes[0] === 0x24) {
    return "interleaved_media";
  }
  if (bytes.length >= 4 && bytes[0] === 0x48 && bytes[1] === 0x54 && bytes[2] === 0x54 && bytes[3] === 0x50) {
    return "http";
  }
  if (bytes.length >= 4 && bytes[0] === 0x48 && bytes[1] === 0x4b && bytes[2] === 0x4d && bytes[3] === 0x49) {
    return "hik_hkmi";
  }
  if (bytes.length >= 4 && bytes[0] === 0x40 && bytes[1] === 0x40 && bytes[2] === 0x40 && bytes[3] === 0x40) {
    return "hik_private";
  }
  if (bytes.length >= 4 && bytes[0] === 0x00 && bytes[1] === 0x00 && bytes[2] === 0x01 && bytes[3] === 0xba) {
    return "mpeg_ps";
  }
  if (highRatio > 0.25) return "opaque_binary";
  if (printableRatio > 0.75) return "printable_non_xml";
  return "binary";
}

function tcpPayloadShape(ptr, len) {
  if (ptr.isNull() || len <= 0) return " tcpKind=empty tcpLen=" + Math.max(0, len);
  try {
    const captured = Math.min(len, MAX_CAPTURE_BYTES);
    const raw = ptr.readByteArray(captured);
    if (!raw) return " tcpKind=unreadable tcpLen=" + len;
    const bytes = new Uint8Array(raw);
    let printable = 0;
    let nul = 0;
    let high = 0;
    for (let i = 0; i < bytes.length; i++) {
      const b = bytes[i];
      if (b >= 0x20 && b <= 0x7e) printable++;
      if (b === 0) nul++;
      if (b >= 0x80) high++;
    }
    const printableRatio = bytes.length ? printable / bytes.length : 0;
    const highRatio = bytes.length ? high / bytes.length : 0;
    const fpBytes = Array.prototype.slice.call(bytes.slice(0, MAX_FINGERPRINT_BYTES));
    const lengths = plausibleLengths(bytes, len);
    return " tcpKind=" + payloadKind(bytes, printableRatio, highRatio)
      + " tcpLen=" + len
      + " captured=" + bytes.length
      + " fp128=" + fingerprintBytes(fpBytes)
      + " printable=" + printableRatio.toFixed(2)
      + " nulls=" + (bytes.length ? (nul / bytes.length).toFixed(2) : "0.00")
      + " high=" + highRatio.toFixed(2)
      + (bytes.length >= 2 ? " u16be0=0x" + u16be(bytes, 0).toString(16) : "")
      + (bytes.length >= 2 ? " u16le0=0x" + u16le(bytes, 0).toString(16) : "")
      + (bytes.length >= 4 ? " u32be0=0x" + u32be(bytes, 0).toString(16) : "")
      + (bytes.length >= 4 ? " u32le0=0x" + u32le(bytes, 0).toString(16) : "")
      + (bytes.length >= 8 ? " u32be4=0x" + u32be(bytes, 4).toString(16) : "")
      + (bytes.length >= 8 ? " u32le4=0x" + u32le(bytes, 4).toString(16) : "")
      + (bytes.length >= 12 ? " u32be8=0x" + u32be(bytes, 8).toString(16) : "")
      + (bytes.length >= 12 ? " u32le8=0x" + u32le(bytes, 8).toString(16) : "")
      + (bytes.length >= 16 ? " u32be12=0x" + u32be(bytes, 12).toString(16) : "")
      + (bytes.length >= 16 ? " u32le12=0x" + u32le(bytes, 12).toString(16) : "")
      + (lengths ? " lengthCandidates=" + lengths : "");
  } catch (e) {
    return " tcpShape=<failed:" + e + ">";
  }
}

function logFdData(kind, fd, buf, len) {
  const peer = fdPeers.get(fd);
  if (!isHcNetSdkPeer(peer) || len <= 0) return;
  const key = kind + ":" + fd;
  const count = fdLogged.get(key) || 0;
  if (count >= MAX_PAYLOAD_LOGS_PER_DIRECTION) return;
  fdLogged.set(key, count + 1);
  console.log("[hcnetsdk-" + kind + "] fd=" + fd + " " + peer.host + ":" + peer.port + tcpPayloadShape(buf, len));
}

function installSocketHooks() {
  const connectPtr = findExport("connect");
  if (connectPtr) {
    Interceptor.attach(connectPtr, {
      onEnter(args) {
        this.fd = args[0].toInt32();
        this.peer = readSockaddr(args[1], args[2].toInt32());
      },
      onLeave(retval) {
        if (!isHcNetSdkPeer(this.peer)) return;
        fdPeers.set(this.fd, this.peer);
        console.log("[hcnetsdk-connect] fd=" + this.fd + " " + this.peer.host + ":" + this.peer.port + " ret=" + retval.toInt32());
      },
    });
  } else {
    console.log("[hcnetsdk-connect] connect export not found");
  }

  ["close", "shutdown"].forEach(function(name) {
    const ptr = findExport(name);
    if (!ptr) return;
    Interceptor.attach(ptr, {
      onEnter(args) {
        const fd = args[0].toInt32();
        const peer = fdPeers.get(fd);
        if (peer) console.log("[hcnetsdk-" + name + "] fd=" + fd + " " + peer.host + ":" + peer.port);
        fdPeers.delete(fd);
      },
    });
  });

  [["send", 1, 2], ["write", 1, 2]].forEach(function(spec) {
    const ptr = findExport(spec[0]);
    if (!ptr) return;
    Interceptor.attach(ptr, {
      onEnter(args) {
        logFdData(spec[0], args[0].toInt32(), args[spec[1]], args[spec[2]].toInt32());
      },
    });
  });

  [["recv", 1], ["read", 1]].forEach(function(spec) {
    const ptr = findExport(spec[0]);
    if (!ptr) return;
    Interceptor.attach(ptr, {
      onEnter(args) {
        this.fd = args[0].toInt32();
        this.buf = args[spec[1]];
      },
      onLeave(retval) {
        logFdData(spec[0], this.fd, this.buf, retval.toInt32());
      },
    });
  });

  console.log("[hcnetsdk-command] socket hooks installed");
}

function installNativeSemanticHooks() {
  let installed = 0;

  installed += hookExport(
    "EZ_NET_DVR_RealPlay_V30",
    "_ZN13ez_stream_sdk23EZ_NET_DVR_RealPlay_V30EiP18NET_DVR_CLIENTINFOPFviiPhjPvES3_i",
    {
      onEnter(args) {
        this.userId = args[0].toInt32();
        this.blocked = args[4].toInt32();
        console.log("[hcnetsdk-semantic] RealPlay_V30 enter userId=" + this.userId
          + readClientInfoShape(args[1])
          + " cb=" + args[2]
          + " user=" + args[3]
          + " blocked=" + this.blocked);
      },
      onLeave(retval) {
        console.log("[hcnetsdk-semantic] RealPlay_V30 leave userId=" + this.userId
          + " realHandle=" + retval.toInt32());
      },
    }
  );

  installed += hookExport(
    "HCNetSDKClient.sRealDataCallBack_V30",
    "_ZN13ez_stream_sdk14HCNetSDKClient21sRealDataCallBack_V30EiiPhjPv",
    {
      onEnter(args) {
        const len = args[3].toUInt32();
        console.log("[hcnetsdk-semantic] RealDataCallback realHandle=" + args[0].toInt32()
          + " dataType=" + args[1].toInt32()
          + " len=" + len
          + " user=" + args[4]);
      },
    }
  );

  installed += hookExport(
    "NativeApi.startPreview",
    "Java_com_ez_stream_NativeApi_startPreview",
    {
      onEnter(args) {
        console.log("[hcnetsdk-semantic] NativeApi.startPreview handle=" + args[2]);
      },
      onLeave(retval) {
        console.log("[hcnetsdk-semantic] NativeApi.startPreview leave ret=" + retval.toInt32());
      },
    }
  );

  installed += hookExport(
    "Core_SimpleCommandToDvr",
    "Core_SimpleCommandToDvr",
    {
      onEnter(args) {
        console.log(simpleCommandArgs("[hcnetsdk-semantic] Core_SimpleCommandToDvr enter", args, 2, 3));
      },
      onLeave(retval) {
        console.log("[hcnetsdk-semantic] Core_SimpleCommandToDvr leave ret=" + retval.toInt32());
      },
    }
  );

  installed += hookExport(
    "Core_SimpleCommandToDvr_WithoutRecv",
    "Core_SimpleCommandToDvr_WithoutRecv",
    {
      onEnter(args) {
        console.log(simpleCommandArgs("[hcnetsdk-semantic] Core_SimpleCommandToDvr_WithoutRecv enter", args, 2, 3));
      },
      onLeave(retval) {
        console.log("[hcnetsdk-semantic] Core_SimpleCommandToDvr_WithoutRecv leave ret=" + retval.toInt32());
      },
    }
  );

  installed += hookExport(
    "Core_SimpleCommandToDvrEx",
    "Core_SimpleCommandToDvrEx",
    {
      onEnter(args) {
        console.log("[hcnetsdk-semantic] Core_SimpleCommandToDvrEx enter"
          + " arg0=" + argWord(args, 0)
          + " arg1=" + argWord(args, 1)
          + " arg2=" + argPtr(args, 2)
          + " arg3=" + argWord(args, 3)
          + " arg4=" + argWord(args, 4)
          + ptrLenShape("in", args[2], argWord(args, 3)));
      },
      onLeave(retval) {
        console.log("[hcnetsdk-semantic] Core_SimpleCommandToDvrEx leave ret=" + retval.toInt32());
      },
    }
  );

  installed += hookExport(
    "Core_SimpleSTDCommandToDVR",
    "Core_SimpleSTDCommandToDVR",
    {
      onEnter(args) {
        console.log("[hcnetsdk-semantic] Core_SimpleSTDCommandToDVR enter"
          + " arg0=" + argWord(args, 0)
          + " arg1=" + argWord(args, 1)
          + " arg2=" + argWord(args, 2)
          + " arg3=" + argPtr(args, 3)
          + " arg4=" + argWord(args, 4)
          + ptrLenShape("in", args[3], argWord(args, 4)));
      },
      onLeave(retval) {
        console.log("[hcnetsdk-semantic] Core_SimpleSTDCommandToDVR leave ret=" + retval.toInt32());
      },
    }
  );

  installed += hookExport(
    "Core_SimpleEncrypt",
    "Core_SimpleEncrypt",
    {
      onEnter(args) {
        console.log("[hcnetsdk-semantic] Core_SimpleEncrypt enter"
          + " arg0=" + argPtr(args, 0)
          + " arg1=" + argWord(args, 1)
          + " arg2=" + argPtr(args, 2)
          + " arg3=" + argWord(args, 3)
          + ptrLenShape("in", args[0], argWord(args, 1)));
      },
      onLeave(retval) {
        console.log("[hcnetsdk-semantic] Core_SimpleEncrypt leave ret=" + retval.toInt32());
      },
    }
  );

  installed += hookExport(
    "Interim_SimpleCommandToDvrEx",
    "_ZN6NetSDK28Interim_SimpleCommandToDvrExEijPvjjRS0_RjP21tagSimpleCmdToDevCond",
    {
      onEnter(args) {
        console.log("[hcnetsdk-semantic] Interim_SimpleCommandToDvrEx enter"
          + " userId=" + argWord(args, 0)
          + " command=" + argWord(args, 1)
          + " inPtr=" + argPtr(args, 2)
          + " inLen=" + argWord(args, 3)
          + " aux=" + argWord(args, 4)
          + ptrLenShape("in", args[2], argWord(args, 3)));
      },
      onLeave(retval) {
        console.log("[hcnetsdk-semantic] Interim_SimpleCommandToDvrEx leave ret=" + retval.toInt32());
      },
    }
  );

  installed += hookExport(
    "Interim_SimpleCommandToDvrByMuxUser",
    "_ZN6NetSDK35Interim_SimpleCommandToDvrByMuxUserEijPvjRS0_RjP21tagSimpleCmdToDevCond",
    {
      onEnter(args) {
        console.log("[hcnetsdk-semantic] Interim_SimpleCommandToDvrByMuxUser enter"
          + " userId=" + argWord(args, 0)
          + " command=" + argWord(args, 1)
          + " inPtr=" + argPtr(args, 2)
          + " inLen=" + argWord(args, 3)
          + ptrLenShape("in", args[2], argWord(args, 3)));
      },
      onLeave(retval) {
        console.log("[hcnetsdk-semantic] Interim_SimpleCommandToDvrByMuxUser leave ret=" + retval.toInt32());
      },
    }
  );

  if (installed > 0) {
    console.log("[hcnetsdk-semantic] native hooks installed count=" + installed);
  }
}

function retryNativeSemanticHooks() {
  let attempts = 0;
  const timer = setInterval(function() {
    attempts += 1;
    installNativeSemanticHooks();
    if (attempts >= 30) clearInterval(timer);
  }, 2000);
}

function currentActivityOrApplication() {
  try {
    const ActivityThread = Java.use("android.app.ActivityThread");
    const app = ActivityThread.currentApplication();
    if (app) return app;
  } catch (e) {
    console.log("[hcnetsdk-command] currentApplication failed " + e);
  }
  return null;
}

function openLanDeviceList() {
  Java.scheduleOnMainThread(function() {
    try {
      const Intent = Java.use("android.content.Intent");
      const Target = Java.use("com.videogo.add.landevice.LanDeviceListActivity");
      const Context = Java.use("android.content.Context");
      const context = currentActivityOrApplication();
      if (!context) {
        console.log("[hcnetsdk-command] no context for LanDeviceListActivity");
        return;
      }
      const intent = Intent.$new(context, Target.class);
      if (!Java.cast(context, Context).getClass().getName().endsWith("Activity")) {
        intent.addFlags(0x10000000);
      }
      context.startActivity(intent);
      console.log("[hcnetsdk-command] started LanDeviceListActivity context=" + context.getClass().getName());
    } catch (e) {
      console.log("[hcnetsdk-command] start LanDeviceListActivity failed " + e);
    }
  });
}

function triggerLanLogin(activity) {
  const LanDeviceInfo = Java.use("com.videogo.device.LanDeviceInfo");
  const DevPwdUtil = Java.use("com.videogo.util.DevPwdUtil");
  const device = LanDeviceInfo.$new();
  const pwd = DevPwdUtil.c(TARGET_SERIAL);

  device.setSzSerialNO(TARGET_SERIAL);
  device.setSzIPv4Address(TARGET_IP);
  device.setDwPort(TARGET_PORT);
  device.setDwSDKOverTLSPort(0);
  device.setLoginName("admin");
  device.setLoginPwd(pwd);
  device.setByActivated(1);
  device.setByEZVIZCode(1);

  console.log("[hcnetsdk-command] trigger target " + TARGET_IP + ":" + TARGET_PORT + " pwdLen=" + String(pwd).length);
  activity.M0(device);
}

function installJavaSemanticHooks() {
  try {
    const DeviceInfoEx = Java.use("com.videogo.device.DeviceInfoEx");
    const loginPlayDevice = DeviceInfoEx.loginPlayDevice.overloads;
    loginPlayDevice.forEach(function(ov) {
      ov.implementation = function() {
        const args = [].slice.call(arguments);
        console.log("[hcnetsdk-semantic] DeviceInfoEx.loginPlayDevice enter argc=" + args.length
          + (args.length > 1 ? " checkLastLoginStatus=" + args[1] : ""));
        const ret = ov.apply(this, args);
        console.log("[hcnetsdk-semantic] DeviceInfoEx.loginPlayDevice leave ret=" + ret);
        return ret;
      };
    });
  } catch (e) {
    console.log("[hcnetsdk-semantic] DeviceInfoEx.loginPlayDevice hook unavailable " + e);
  }

  try {
    const HCNetUtil = Java.use("com.videogo.add.device.HCNETUtil");
    HCNetUtil.s.overloads.forEach(function(ov) {
      ov.implementation = function() {
        const args = [].slice.call(arguments);
        console.log("[hcnetsdk-semantic] HCNETUtil.s enter ip=" + args[0]
          + " port=" + args[1]
          + " user=" + args[2]
          + " pwdLen=" + String(args[3]).length);
        const ret = ov.apply(this, args);
        console.log("[hcnetsdk-semantic] HCNETUtil.s leave ret=" + ret);
        return ret;
      };
    });
  } catch (e) {
    console.log("[hcnetsdk-semantic] HCNETUtil.s hook unavailable " + e);
  }

  try {
    const H = Java.use("com.videogo.hcnetsdk.HCNetSDKManage");
    ["NET_DVR_Login_V40", "NET_DVR_Login_V30"].forEach(function(name) {
      if (!H[name]) return;
      H[name].overloads.forEach(function(ov) {
        ov.implementation = function() {
          const args = [].slice.call(arguments);
          console.log("[hcnetsdk-semantic] Java HCNetSDKManage." + name
            + " enter ip=" + args[0]
            + " port=" + args[1]
            + " user=" + args[2]
            + " pwdLen=" + String(args[3]).length);
          const ret = ov.apply(this, args);
          console.log("[hcnetsdk-semantic] Java HCNetSDKManage." + name + " leave ret=" + ret);
          return ret;
        };
      });
    });
  } catch (e) {
    console.log("[hcnetsdk-semantic] Java HCNetSDKManage login hooks unavailable " + e);
  }

  try {
    const H = Java.use("com.neutral.netsdk.HCNetSDK");
    ["NET_DVR_MakeKeyFrame", "NET_DVR_MakeKeyFrameSub"].forEach(function(name) {
      H[name].overloads.forEach(function(ov) {
        ov.implementation = function() {
          const args = [].slice.call(arguments);
          console.log("[hcnetsdk-semantic] Java HCNetSDK." + name
            + " enter loginId=" + args[0]
            + " channel=" + args[1]);
          const ret = ov.apply(this, args);
          console.log("[hcnetsdk-semantic] Java HCNetSDK." + name + " leave ret=" + ret);
          return ret;
        };
      });
    });
  } catch (e) {
    console.log("[hcnetsdk-semantic] Java HCNetSDK keyframe hooks unavailable " + e);
  }
}

function tryTrigger(attempt) {
  Java.scheduleOnMainThread(function() {
    let called = false;
    Java.choose("com.videogo.add.landevice.LanDeviceListActivity", {
      onMatch(activity) {
        if (called) return;
        called = true;
        triggerLanLogin(activity);
      },
      onComplete() {
        if (called) return;
        if (attempt >= MAX_TRIGGER_ATTEMPTS) {
          console.log("[hcnetsdk-command] LanDeviceListActivity not found after attempts=" + attempt);
          return;
        }
        setTimeout(function() {
          tryTrigger(attempt + 1);
        }, RETRY_DELAY_MS);
      },
    });
  });
}

function installJavaTriggerWhenReady(attempt) {
  if (typeof Java !== "undefined" && Java.available) {
    Java.perform(function() {
      console.log("[hcnetsdk-command] Java runtime available attempt=" + attempt);
      installJavaSemanticHooks();
      setTimeout(openLanDeviceList, 1000);
      setTimeout(function() {
        tryTrigger(1);
      }, FIRST_TRIGGER_DELAY_MS);
    });
    return;
  }
  if (attempt >= MAX_JAVA_ATTEMPTS) {
    console.log("[hcnetsdk-command] Java runtime unavailable after attempts=" + attempt + "; socket hooks only");
    return;
  }
  setTimeout(function() {
    installJavaTriggerWhenReady(attempt + 1);
  }, JAVA_RETRY_DELAY_MS);
}

installSocketHooks();
installNativeSemanticHooks();
retryNativeSemanticHooks();
installJavaTriggerWhenReady(1);
