"use strict";

/*
 * Minimal HCNetSDK command-port shape capture for a LAN path.
 *
 * This intentionally avoids the broad native symbol hooks. It records only
 * command-port metadata for 8000/8443: byte ratios, small fingerprints, and
 * header/length candidates. It never prints raw payload bytes, passwords, or
 * XML values.
 */

const PARAMETERS = (
  typeof globalThis !== "undefined" && globalThis.__EZVIZ_HCNETSDK_TARGET
) ? globalThis.__EZVIZ_HCNETSDK_TARGET : {};
const TARGET_SERIAL = PARAMETERS.targetSerial || "CS-CV310-A0-1B2WFR0120200927CCRRFAKE001";
const TARGET_IP = PARAMETERS.targetIp || "192.0.2.47";
const TARGET_PORT = PARAMETERS.targetPort || 8000;
const ENABLE_TARGET_TRIGGER = PARAMETERS.enableTargetTrigger !== false;
const FIRST_TRIGGER_DELAY_MS = 5000;
const JAVA_RETRY_DELAY_MS = 1000;
const MAX_JAVA_ATTEMPTS = 30;
const RETRY_DELAY_MS = 3000;
const MAX_TRIGGER_ATTEMPTS = 20;
const FORCE_PREVIEW_RETRY_DELAY_MS = 2000;
const MAX_FORCE_PREVIEW_ATTEMPTS = 20;
const MAX_PAYLOAD_LOGS_PER_DIRECTION = 24;
const MAX_CAPTURE_BYTES = 512;
const MAX_FINGERPRINT_BYTES = 128;
const MAX_NATIVE_STREAM_LOGS_PER_LABEL = 32;

const fdPeers = new Map();
const fdLogged = new Map();
const mediaCommandFds = new Set();
const inboundMediaDumpState = new Map();
const nativeStreamLogged = new Map();
const hookedSemanticLabels = {};
const missingExportLabels = {};
let commandFrameDumpSeq = 0;
let latestTargetLoginId = null;
let dvrConfigProbesStarted = false;

const HCCORE_SEND_PRO_DATA_OFFSET = 0x0006bb4d;
const HCCORE_PRO_SEND_PRO_DATA_WITH_RECV_OFFSET = 0x0006bef3;
const HCPREVIEW_COM_START_REAL_PLAY_OFFSET = 0x00011593;
const HCPREVIEW_COM_START_REAL_PLAY_SPECIAL_OFFSET = 0x000116bd;
const HCPREVIEW_COM_PREVIEW_REQUEST_OFFSET = 0x0001523d;
const HCPREVIEW_COM_MAKE_KEY_FRAME_OFFSET = 0x000117e1;
const HCPREVIEW_COM_MAKE_KEY_FRAME_SUB_OFFSET = 0x00011861;
const HCPREVIEW_COM_SET_REAL_PLAY_SECRET_KEY_OFFSET = 0x000156f7;
const HCPREVIEW_HIK_DEV_PREVIEW_OFFSET = 0x0001dff5;
const HCPREVIEW_PRO_SEND_HEARTBEAT_OFFSET = 0x0001dea1;
const HCPREVIEW_CONVERT_IFRAME_CTRL_OFFSET = 0x0001635b;
const HCPREVIEW_PREVIEW_MGR_CREATE_PREVIEWINFO_OFFSET = 0x0001bb31;
const HCPREVIEW_PREVIEW_MGR_CREATE_SPECIAL_OFFSET = 0x0001bc05;
const HCPREVIEW_PREVIEW_MGR_CREATE_INTERNAL_OFFSET = 0x0001bd69;
const HCPREVIEW_STREAM_BASE_CONSTRUCTOR_OFFSET = 0x00019e3d;
const HCPREVIEW_STREAM_BASE_START_OFFSET = 0x00019b6b;
const HCPREVIEW_STREAM_BASE_SET_SESSION_INDEX_OFFSET = 0x00019b45;
const HCPREVIEW_STREAM_BASE_SET_EX_WORK_PARAM_OFFSET = 0x00019b6f;
const HCPREVIEW_STREAM_BASE_SET_METADATA_FLAG_OFFSET = 0x00019b73;
const HCPREVIEW_STREAM_BASE_REGISTER_HEARTBEAT_PROXY_OFFSET = 0x00019d49;
const HCPREVIEW_STREAM_BASE_REGISTER_GET_STREAM_CB_OFFSET = 0x0001aec1;
const HCPREVIEW_STREAM_BASE_GET_STREAM_DATA_TYPE_OFFSET = 0x00019c45;
const HCPREVIEW_STREAM_BASE_PROC_TCP_DATA_OFFSET = 0x0001a5ad;
const HCPREVIEW_STREAM_BASE_IS_NEED_USE_CONVERT_OFFSET = 0x0001a2f5;
const HCPREVIEW_STREAM_BASE_CREATE_STREAM_CONVERT_OFFSET = 0x0001a321;
const HCPREVIEW_STREAM_BASE_SYS_TRANS_DATA_CALLBACK_OFFSET = 0x0001a465;
const HCPREVIEW_STREAM_BASE_PUSH_CONVERT_DATA_OFFSET = 0x0001a403;
const HCPREVIEW_STREAM_BASE_PUSH_DATA_TO_CB_WITHOUT_LOCK_OFFSET = 0x0001abad;
const HCPREVIEW_STREAM_BASE_PUSH_DATA_TO_CB_OFFSET = 0x0001ad31;
const HCPREVIEW_TCP_PRO_RTP_OVER_TCP_DATA_OFFSET = 0x0001afbd;
const HCPREVIEW_STREAM_BASE_SET_ZERO_CHAN_OFFSET = 0x0001a7c1;
const HCPREVIEW_GET_STREAM_SET_IP_CHANNEL_OFFSET = 0x0001a79d;
const HCPREVIEW_TCP_CONSTRUCTOR_OFFSET = 0x0001b04d;
const HCPREVIEW_TCP_LINK_TO_DVR_OFFSET = 0x0001b095;
const HCPREVIEW_TCP_STREAM_START_OFFSET = 0x0001b361;
const HCPREVIEW_PREVIEW_PLAYER_SET_IP_CHANNEL_OFFSET = 0x0001c323;
const HCPREVIEW_PREVIEW_PLAYER_OPEN_PLAYER_OFFSET = 0x0001c345;
const HCPREVIEW_PREVIEW_PLAYER_PROCESS_STREAM_OFFSET = 0x0001c5f9;
const HCPREVIEW_PREVIEW_PLAYER_CREATE_PLAYER_OFFSET = 0x0001c971;
const HCPREVIEW_PREVIEW_PLAYER_INIT_OFFSET = 0x0001ca69;
const HCPREVIEW_PREVIEW_SESSION_CREATE_GET_STREAM_OFFSET = 0x0001cbb1;
const HCPREVIEW_PREVIEW_SESSION_GET_STREAM_PACKET_TYPE_OFFSET = 0x0001cb59;
const HCPREVIEW_PREVIEW_SESSION_REGISTER_GET_STREAM_CB_OFFSET = 0x0001cebd;
const HCPREVIEW_PREVIEW_SESSION_JUDGE_SUPPORT_RTSP_OFFSET = 0x0001cf29;
const HCPREVIEW_PREVIEW_SESSION_GET_RTSP_TYPE_OFFSET = 0x0001cfe1;
const HCPREVIEW_PREVIEW_SESSION_ADJUST_PROTO_TYPE_OFFSET = 0x0001d029;
const HCPREVIEW_PREVIEW_SESSION_STREAM_GETTER_START_WORK_OFFSET = 0x0001d241;
const HCPREVIEW_PREVIEW_SESSION_INIT_PLAYER_OFFSET = 0x0001d33d;
const HCPREVIEW_PREVIEW_SESSION_PREPARE_RESOURCE_OFFSET = 0x0001d385;
const HCPREVIEW_PREVIEW_SESSION_ALL_RESOURCE_START_WORK_OFFSET = 0x0001d479;
const HCPREVIEW_PREVIEW_SESSION_WAIT_FOR_RESULT_OFFSET = 0x0001d551;
const HCPREVIEW_PREVIEW_SESSION_START_OFFSET = 0x0001d5cd;
const HCPREVIEW_USER_CALLBACK_SET_SESSION_ID_OFFSET = 0x0001e5f1;
const HCPREVIEW_USER_CALLBACK_SET_IP_CHANNEL_OFFSET = 0x0001e5f5;
const HCPREVIEW_USER_CALLBACK_SET_REAL_CB_OFFSET = 0x0001ea3d;
const HCPREVIEW_USER_CALLBACK_SET_REAL_CB_V30_OFFSET = 0x0001ea89;
const MAX_WORD_SAMPLE_BYTES = 0x100;

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

function nativeCodeAddress(base, offset) {
  const address = base.add(offset);
  if (Process.arch === "arm" && (offset & 1) === 0) {
    return address.or(1);
  }
  return address;
}

function findModuleBase(moduleName) {
  try {
    const base = Module.findBaseAddress(moduleName);
    if (base) return base;
  } catch (e) {
    // Fall back to enumerateModules below.
  }
  try {
    const modules = Process.enumerateModules();
    for (let i = 0; i < modules.length; i++) {
      if (modules[i].name === moduleName) return modules[i].base;
    }
  } catch (e) {
    // Ignore and let the caller retry later.
  }
  return null;
}

function hookModuleOffset(label, moduleName, offset, callbacks) {
  if (hookedSemanticLabels[label]) return 0;
  const base = findModuleBase(moduleName);
  if (!base) {
    const key = label + ":offset";
    if (!missingExportLabels[key]) {
      missingExportLabels[key] = true;
      console.log("[hcnetsdk-semantic] waiting for " + label
        + " module=" + moduleName
        + " offset=0x" + offset.toString(16));
    }
    return 0;
  }
  const ptr = nativeCodeAddress(base, offset);
  Interceptor.attach(ptr, callbacks);
  hookedSemanticLabels[label] = true;
  console.log("[hcnetsdk-semantic] hooked " + label
    + " @" + ptr
    + " module=" + moduleName
    + " offset=0x" + offset.toString(16));
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

function safeReadU8(ptrValue, offset) {
  try {
    if (!ptrValue || ptrValue.isNull()) return "null";
    return String(ptrValue.add(offset).readU8());
  } catch (e) {
    return "err:" + e;
  }
}

function safeReadU32(ptrValue, offset) {
  try {
    if (!ptrValue || ptrValue.isNull()) return "null";
    return String(ptrValue.add(offset).readU32());
  } catch (e) {
    return "err:" + e;
  }
}

function safeReadU32Hex(ptrValue, offset) {
  try {
    if (!ptrValue || ptrValue.isNull()) return "null";
    return "0x" + commandLeftPad(ptrValue.add(offset).readU32().toString(16), 8, "0");
  } catch (e) {
    return "err:" + e;
  }
}

function commandLeftPad(value, width, fill) {
  let text = String(value);
  while (text.length < width) {
    text = fill + text;
  }
  return text;
}

function safeReadPtr(ptrValue, offset) {
  try {
    if (!ptrValue || ptrValue.isNull()) return "null";
    return String(ptrValue.add(offset).readPointer());
  } catch (e) {
    return "err:" + e;
  }
}

function safeReadPtrValue(ptrValue, offset) {
  try {
    if (!ptrValue || ptrValue.isNull()) return null;
    return ptrValue.add(offset).readPointer();
  } catch (e) {
    return null;
  }
}

function safeReadCStringSnippet(ptrValue, maxLen) {
  try {
    if (!ptrValue || ptrValue.isNull()) return "<null>";
    const value = ptrValue.readCString(maxLen);
    if (value === null) return "<null>";
    if (!/^[\x20-\x7e]*$/.test(value)) return "<nonprintable>";
    return value;
  } catch (e) {
    return "<err:" + e + ">";
  }
}

function wordSamplesShape(label, ptrValue, byteLen) {
  if (!ptrValue || ptrValue.isNull()) return " " + label + "=<null>";
  const sampleBytes = Math.min(byteLen, MAX_WORD_SAMPLE_BYTES);
  if (sampleBytes <= 0) return " " + label + "Words=<skipped>";
  let parts = " " + label + "Ptr=" + ptrValue + " " + label + "Words=";
  for (let off = 0; off + 4 <= sampleBytes; off += 4) {
    if (off > 0) parts += ",";
    parts += "0x" + off.toString(16) + ":" + safeReadU32Hex(ptrValue, off);
  }
  return parts;
}

function nonzeroWordSamplesShape(label, ptrValue, byteLen, maxWords) {
  if (!ptrValue || ptrValue.isNull()) return " " + label + "Nonzero=<null>";
  const sampleBytes = Math.min(byteLen, MAX_WORD_SAMPLE_BYTES);
  if (sampleBytes <= 0) return " " + label + "Nonzero=<skipped>";
  let parts = " " + label + "Nonzero=";
  let count = 0;
  for (let off = 0; off + 4 <= sampleBytes; off += 4) {
    const value = safeReadU32Hex(ptrValue, off);
    if (value === "0x00000000") continue;
    if (count > 0) parts += ",";
    parts += "0x" + off.toString(16) + ":" + value;
    count += 1;
    if (count >= maxWords) break;
  }
  if (count === 0) parts += "<none>";
  return parts;
}

function smallCommandBodyShape(packNeedPtr) {
  const seq = Number(safeReadU32(packNeedPtr, 0x00));
  const bodyPtr = safeReadPtrValue(packNeedPtr, 0x134);
  const bodyLen = Number(safeReadU32(packNeedPtr, 0x13c));
  if (!bodyPtr || bodyLen <= 0 || bodyLen > 16) return " smallBodyLen=" + bodyLen;
  let parts = " smallBodySeq=0x" + seq.toString(16) + " smallBodyLen=" + bodyLen;
  for (let off = 0; off + 4 <= bodyLen; off += 4) {
    parts += " smallBodyU32le" + off + "=" + safeReadU32(bodyPtr, off);
  }
  return parts;
}

function proPackNeedShape(ptrValue) {
  if (!ptrValue || ptrValue.isNull()) return " packNeedShape=<null>";
  return " packNeedSeq=" + safeReadU32(ptrValue, 0x00)
    + " packNeedSelector=" + safeReadU32(ptrValue, 0x04)
    + " packNeedWord08=" + safeReadU32(ptrValue, 0x08)
    + " packNeedWord0c=" + safeReadU32(ptrValue, 0x0c)
    + " packNeedBodyPtr=" + safeReadPtr(ptrValue, 0x134)
    + " packNeedBodyLenA=" + safeReadU32(ptrValue, 0x138)
    + " packNeedBodyLenB=" + safeReadU32(ptrValue, 0x13c)
    + " packNeedBodyLenExt=" + safeReadU32(ptrValue, 0x140)
    + " packNeedStreamId=" + safeReadU32(ptrValue, 0x148)
    + " packNeedExtended=" + safeReadU8(ptrValue, 0x130)
    + " packNeedOptA=" + safeReadU8(ptrValue, 0x173)
    + " packNeedOptB=" + safeReadU8(ptrValue, 0x174)
    + smallCommandBodyShape(ptrValue);
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

function readU32BE(ptrValue, offset) {
  return ((ptrValue.add(offset).readU8() << 24) >>> 0)
    + (ptrValue.add(offset + 1).readU8() << 16)
    + (ptrValue.add(offset + 2).readU8() << 8)
    + ptrValue.add(offset + 3).readU8();
}

function commandFingerprintBytes(bytes) {
  let h = 2166136261;
  for (let i = 0; i < bytes.length; i++) {
    h ^= bytes[i];
    h = commandImul32(h, 16777619) >>> 0;
  }
  return bytes.length + ":" + commandLeftPad(h.toString(16), 8, "0");
}

function commandImul32(a, b) {
  if (typeof Math.imul === "function") {
    return Math.imul(a, b);
  }
  const ah = (a >>> 16) & 0xffff;
  const al = a & 0xffff;
  const bh = (b >>> 16) & 0xffff;
  const bl = b & 0xffff;
  return ((al * bl) + (((ah * bl + al * bh) << 16) >>> 0)) | 0;
}

function currentParameters() {
  return (
    typeof globalThis !== "undefined" && globalThis.__EZVIZ_HCNETSDK_TARGET
  ) ? globalThis.__EZVIZ_HCNETSDK_TARGET : {};
}

function commandFrameDumpDirectory() {
  const latest = currentParameters();
  if (!latest.dumpCommandFrames) return null;
  return latest.commandFrameDumpDir || "/sdcard/Download";
}

function inboundMediaDumpDirectory() {
  const latest = currentParameters();
  if (!latest.dumpInboundMediaChunks) return null;
  return latest.inboundMediaDumpDir || latest.commandFrameDumpDir || "/sdcard/Download";
}

function inboundMediaDumpMaxBytes() {
  const latest = currentParameters();
  return latest.inboundMediaDumpMaxBytes || (8 * 1024 * 1024);
}

function ensureDumpDirectory(path) {
  if (!path) return false;
  if (typeof Java === "undefined" || !Java.available) return true;
  let ok = false;
  try {
    const createDir = function() {
      const FileCls = Java.use("java.io.File");
      const dir = FileCls.$new(path);
      ok = dir.exists() || dir.mkdirs();
    };
    if (typeof Java.performNow === "function") {
      Java.performNow(createDir);
    } else {
      Java.perform(createDir);
      ok = true;
    }
  } catch (e) {
    console.log("[hcnetsdk-dump-failed] mkdir path=" + path + " err=" + e);
    return false;
  }
  return ok;
}

function forcePreviewAfterLoginEnabled() {
  const latest = currentParameters();
  return latest.forcePreviewAfterLogin === true;
}

function dumpOutboundCommandFrame(kind, fd, ptr, len) {
  const dumpDir = commandFrameDumpDirectory();
  if (!dumpDir || kind !== "send" || !ptr || ptr.isNull() || len < 16) return;
  if (!ensureDumpDirectory(dumpDir)) return;
  try {
    const family = ptr.add(4).readU8();
    if (family !== 0x63) return;
    const commandId = readU32BE(ptr, 12);
    if (commandId === 0x30000) {
      mediaCommandFds.add(fd);
      console.log("[hcnetsdk-dump] media-fd fd=" + fd + " command=0x30000");
    }
    const seq = commandLeftPad(commandFrameDumpSeq++, 4, "0");
    const path = dumpDir + "/ezviz-hcnetsdk-command-frame-"
      + seq + "-fd" + fd + "-cmd0x" + commandId.toString(16) + ".bin";
    const file = new File(path, "wb");
    try {
      file.write(ptr.readByteArray(len));
    } finally {
      file.close();
    }
    console.log("[hcnetsdk-dump] command-frame kind=" + kind
      + " fd=" + fd
      + " command=0x" + commandId.toString(16)
      + " len=" + len
      + " path=" + path);
  } catch (e) {
    console.log("[hcnetsdk-dump-failed] command-frame kind=" + kind
      + " fd=" + fd
      + " len=" + len
      + " err=" + e);
  }
}

function dumpInboundMediaChunk(kind, fd, ptr, len) {
  const dumpDir = inboundMediaDumpDirectory();
  if (!dumpDir || (kind !== "recv" && kind !== "read")) return;
  if (!mediaCommandFds.has(fd) || !ptr || ptr.isNull() || len <= 0) return;
  if (!ensureDumpDirectory(dumpDir)) return;
  try {
    let state = inboundMediaDumpState.get(fd);
    if (!state) {
      const path = dumpDir + "/ezviz-hcnetsdk-inbound-media-fd" + fd + ".bin";
      state = { path: path, bytes: 0, chunks: 0 };
      inboundMediaDumpState.set(fd, state);
      console.log("[hcnetsdk-dump] inbound-media start fd=" + fd + " path=" + path);
    }
    const maxBytes = inboundMediaDumpMaxBytes();
    if (state.bytes >= maxBytes) return;
    const toWrite = Math.min(len, maxBytes - state.bytes);
    const file = new File(state.path, "ab");
    try {
      file.write(ptr.readByteArray(toWrite));
    } finally {
      file.close();
    }
    state.bytes += toWrite;
    state.chunks += 1;
    if (state.chunks <= 8 || state.bytes >= maxBytes) {
      console.log("[hcnetsdk-dump] inbound-media chunk fd=" + fd
        + " chunk=" + state.chunks
        + " wrote=" + toWrite
        + " total=" + state.bytes);
    }
  } catch (e) {
    console.log("[hcnetsdk-dump-failed] inbound-media kind=" + kind
      + " fd=" + fd
      + " len=" + len
      + " err=" + e);
  }
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
    const fpBytes = [];
    const fpLen = Math.min(bytes.length, MAX_FINGERPRINT_BYTES);
    for (let i = 0; i < fpLen; i++) fpBytes.push(bytes[i]);
    const lengths = plausibleLengths(bytes, len);
    return " tcpKind=" + payloadKind(bytes, printableRatio, highRatio)
      + " tcpLen=" + len
      + " captured=" + bytes.length
      + " fp128=" + commandFingerprintBytes(fpBytes)
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
    return " tcpShape=<failed:" + (e && e.stack ? e.stack : e) + ">";
  }
}

function logFdData(kind, fd, buf, len) {
  const peer = fdPeers.get(fd);
  if (!isHcNetSdkPeer(peer) || len <= 0) return;
  dumpOutboundCommandFrame(kind, fd, buf, len);
  dumpInboundMediaChunk(kind, fd, buf, len);
  const key = kind + ":" + fd;
  const count = fdLogged.get(key) || 0;
  if (count >= MAX_PAYLOAD_LOGS_PER_DIRECTION) return;
  fdLogged.set(key, count + 1);
  console.log("[hcnetsdk-" + kind + "] fd=" + fd + " " + peer.host + ":" + peer.port + tcpPayloadShape(buf, len));
}

function shouldLogNativeStream(label) {
  const count = nativeStreamLogged.get(label) || 0;
  if (count >= MAX_NATIVE_STREAM_LOGS_PER_LABEL) return false;
  nativeStreamLogged.set(label, count + 1);
  return true;
}

function nativeStreamDataShape(label, ptrValue, lenValue) {
  return ptrLenShape(label, ptrValue, lenValue);
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

  const proSendProDataWithRecvCallbacks = {
    onEnter(args) {
      console.log("[hcnetsdk-semantic] PRO_SendProDataWithRecv enter"
        + " sysFunc=" + argPtr(args, 0)
        + " link=" + argPtr(args, 1)
        + " packNeed=" + argPtr(args, 2)
        + " recvInfo=" + argPtr(args, 3)
        + proPackNeedShape(args[2]));
    },
    onLeave(retval) {
      console.log("[hcnetsdk-semantic] PRO_SendProDataWithRecv leave ret=" + retval.toInt32());
    },
  };

  installed += hookExport(
    "PRO_SendProDataWithRecv",
    "PRO_SendProDataWithRecv",
    proSendProDataWithRecvCallbacks
  );
  installed += hookModuleOffset(
    "PRO_SendProDataWithRecv",
    "libHCCore.so",
    HCCORE_PRO_SEND_PRO_DATA_WITH_RECV_OFFSET,
    proSendProDataWithRecvCallbacks
  );

  const sendProDataCallbacks = {
    onEnter(args) {
      console.log("[hcnetsdk-semantic] SendProData enter"
        + " sysFunc=" + argPtr(args, 0)
        + " link=" + argPtr(args, 1)
        + " packNeed=" + argPtr(args, 2)
        + proPackNeedShape(args[2]));
    },
    onLeave(retval) {
      console.log("[hcnetsdk-semantic] SendProData leave ret=" + retval.toInt32());
    },
  };

  installed += hookExport(
    "SendProData",
    "_Z11SendProDataPK17tagProSysFunctionPvPK14tagProPackNeed",
    sendProDataCallbacks
  );
  installed += hookModuleOffset(
    "SendProData",
    "libHCCore.so",
    HCCORE_SEND_PRO_DATA_OFFSET,
    sendProDataCallbacks
  );

  ["Core_GetStreamInfo", "Core_SupportSDKPreview", "Core_GetStreamPort"].forEach(function(symbol) {
    installed += hookExport(
      symbol,
      symbol,
      {
        onEnter(args) {
          this.arg0 = args[0];
          this.arg1 = args[1];
          this.arg2 = args[2];
          this.arg3 = args[3];
          console.log("[hcnetsdk-semantic] " + symbol + " enter"
            + " arg0=" + argWord(args, 0)
            + " arg1=" + argPtr(args, 1)
            + " arg2=" + argPtr(args, 2)
            + " arg3=" + argWord(args, 3)
            + wordSamplesShape("arg1", args[1], 0x80)
            + nonzeroWordSamplesShape("arg2", args[2], 0x80, 12));
        },
        onLeave(retval) {
          console.log("[hcnetsdk-semantic] " + symbol + " leave"
            + " ret=" + retval.toInt32()
            + " arg0=" + this.arg0
            + " arg1=" + this.arg1
            + " arg2=" + this.arg2
            + " arg3=" + this.arg3
            + wordSamplesShape("arg1After", this.arg1, 0x80)
            + nonzeroWordSamplesShape("arg2After", this.arg2, 0x80, 12));
        },
      }
    );
  });

  const hikDevPreviewCallbacks = {
    onEnter(args) {
      this.inPtr = args[0];
      this.outPtr = args[1];
      this.netInfoPtr = args[2];
      console.log("[hcnetsdk-semantic] HikDevPreview enter"
        + " in=" + argPtr(args, 0)
        + " out=" + argPtr(args, 1)
        + " netInfo=" + argPtr(args, 2)
        + wordSamplesShape("previewIn", args[0], 0xc0)
        + wordSamplesShape("subsystemNetInfo", args[2], 0x80));
    },
    onLeave(retval) {
      console.log("[hcnetsdk-semantic] HikDevPreview leave ret=" + retval.toInt32()
        + wordSamplesShape("previewOut", this.outPtr, 0x80));
    },
  };

  installed += hookExport(
    "HikDevPreview",
    "_Z13HikDevPreviewPK15tagPreviewDevInP16tagPreviewDevOutP20tagSUBSYSTEM_NETINFO",
    hikDevPreviewCallbacks
  );
  installed += hookModuleOffset(
    "HikDevPreview",
    "libHCPreview.so",
    HCPREVIEW_HIK_DEV_PREVIEW_OFFSET,
    hikDevPreviewCallbacks
  );

  const comStartRealPlayCallbacks = {
    onEnter(args) {
      this.arg0 = args[0];
      this.previewInfoPtr = args[1];
      console.log("[hcnetsdk-semantic] COM_StartRealPlay enter"
        + " arg0=" + argWord(args, 0)
        + " previewInfo=" + argPtr(args, 1)
        + " cb=" + argPtr(args, 2)
        + " user=" + argPtr(args, 3)
        + " blocked=" + argWord(args, 4)
        + wordSamplesShape("previewInfo", args[1], 0xc0));
    },
    onLeave(retval) {
      console.log("[hcnetsdk-semantic] COM_StartRealPlay leave"
        + " arg0=" + this.arg0
        + " ret=" + retval.toInt32());
    },
  };

  installed += hookExport(
    "COM_StartRealPlay",
    "COM_StartRealPlay",
    comStartRealPlayCallbacks
  );
  installed += hookModuleOffset(
    "COM_StartRealPlay",
    "libHCPreview.so",
    HCPREVIEW_COM_START_REAL_PLAY_OFFSET,
    comStartRealPlayCallbacks
  );

  installed += hookModuleOffset(
    "COM_StartRealPlaySpecial",
    "libHCPreview.so",
    HCPREVIEW_COM_START_REAL_PLAY_SPECIAL_OFFSET,
    {
      onEnter(args) {
        console.log("[hcnetsdk-semantic] COM_StartRealPlaySpecial enter"
          + " arg0=" + argWord(args, 0)
          + " previewInfo=" + argPtr(args, 1)
          + " cb=" + argPtr(args, 2)
          + " user=" + argPtr(args, 3)
          + " blocked=" + argWord(args, 4)
          + wordSamplesShape("previewInfo", args[1], 0xc0));
      },
      onLeave(retval) {
        console.log("[hcnetsdk-semantic] COM_StartRealPlaySpecial leave ret=" + retval.toInt32());
      },
    }
  );

  installed += hookModuleOffset(
    "COM_PreviewRequest",
    "libHCPreview.so",
    HCPREVIEW_COM_PREVIEW_REQUEST_OFFSET,
    {
      onEnter(args) {
        console.log("[hcnetsdk-semantic] COM_PreviewRequest enter"
          + " arg0=" + argWord(args, 0)
          + " arg1=" + argPtr(args, 1)
          + " arg2=" + argPtr(args, 2)
          + " arg3=" + argWord(args, 3)
          + wordSamplesShape("previewRequestArg1", args[1], 0x80)
          + wordSamplesShape("previewRequestArg2", args[2], 0x80));
      },
      onLeave(retval) {
        console.log("[hcnetsdk-semantic] COM_PreviewRequest leave ret=" + retval.toInt32());
      },
    }
  );

  [
    ["NET_DVR_MakeKeyFrame", "NET_DVR_MakeKeyFrame"],
    ["NET_DVR_MakeKeyFrameSub", "NET_DVR_MakeKeyFrameSub"],
  ].forEach(function(spec) {
    installed += hookExport(
      spec[0],
      spec[1],
      {
        onEnter(args) {
          this.userId = argWord(args, 0);
          this.channel = argWord(args, 1);
          console.log("[hcnetsdk-semantic] " + spec[0] + " enter"
            + " userId=" + this.userId
            + " channel=" + this.channel);
        },
        onLeave(retval) {
          console.log("[hcnetsdk-semantic] " + spec[0] + " leave"
            + " userId=" + this.userId
            + " channel=" + this.channel
            + " ret=" + retval.toInt32());
        },
      }
    );
  });

  [
    ["COM_MakeKeyFrame", HCPREVIEW_COM_MAKE_KEY_FRAME_OFFSET],
    ["COM_MakeKeyFrameSub", HCPREVIEW_COM_MAKE_KEY_FRAME_SUB_OFFSET],
  ].forEach(function(spec) {
    installed += hookModuleOffset(
      spec[0],
      "libHCPreview.so",
      spec[1],
      {
        onEnter(args) {
          this.realHandle = argWord(args, 0);
          this.channel = argWord(args, 1);
          console.log("[hcnetsdk-semantic] " + spec[0] + " enter"
            + " realHandle=" + this.realHandle
            + " channel=" + this.channel);
        },
        onLeave(retval) {
          console.log("[hcnetsdk-semantic] " + spec[0] + " leave"
            + " realHandle=" + this.realHandle
            + " channel=" + this.channel
            + " ret=" + retval.toInt32());
        },
      }
    );
  });

  installed += hookModuleOffset(
    "ConvertIFrameCtrl",
    "libHCPreview.so",
    HCPREVIEW_CONVERT_IFRAME_CTRL_OFFSET,
    {
      onEnter(args) {
        this.inPtr = args[0];
        this.outPtr = args[1];
        this.len = argWord(args, 2);
        console.log("[hcnetsdk-semantic] ConvertIFrameCtrl enter"
          + " in=" + argPtr(args, 0)
          + " out=" + argPtr(args, 1)
          + " len=" + this.len
          + wordSamplesShape("iframeIn", args[0], Math.min(this.len, 0x40)));
      },
      onLeave(retval) {
        console.log("[hcnetsdk-semantic] ConvertIFrameCtrl leave"
          + " len=" + this.len
          + " ret=" + retval.toInt32()
          + wordSamplesShape("iframeOut", this.outPtr, Math.min(this.len, 0x40)));
      },
    }
  );

  installed += hookModuleOffset(
    "COM_SetRealPlaySecretKey",
    "libHCPreview.so",
    HCPREVIEW_COM_SET_REAL_PLAY_SECRET_KEY_OFFSET,
    {
      onEnter(args) {
        console.log("[hcnetsdk-semantic] COM_SetRealPlaySecretKey enter"
          + " realHandle=" + argWord(args, 0)
          + " keyType=" + argWord(args, 1)
          + " keyPtr=" + argPtr(args, 2)
          + " keyLen=" + argWord(args, 3));
      },
      onLeave(retval) {
        console.log("[hcnetsdk-semantic] COM_SetRealPlaySecretKey leave ret=" + retval.toInt32());
      },
    }
  );

  [
    ["CPreviewMgr.CreatePreviewInfo", HCPREVIEW_PREVIEW_MGR_CREATE_PREVIEWINFO_OFFSET],
    ["CPreviewMgr.CreateSpecial", HCPREVIEW_PREVIEW_MGR_CREATE_SPECIAL_OFFSET],
    ["CPreviewMgr.CreateInternal", HCPREVIEW_PREVIEW_MGR_CREATE_INTERNAL_OFFSET],
  ].forEach(function(spec) {
    installed += hookModuleOffset(
      spec[0],
      "libHCPreview.so",
      spec[1],
      {
        onEnter(args) {
          this.thisPtr = args[0];
          this.previewPtr = args[2];
          this.outHandlePtr = args[2];
          if (spec[0] === "CPreviewMgr.CreateInternal") {
            this.previewPtr = args[1];
            this.outHandlePtr = args[2];
          }
          console.log("[hcnetsdk-semantic] " + spec[0] + " enter"
            + " this=" + argPtr(args, 0)
            + " arg1=" + argWord(args, 1)
            + " arg2=" + argPtr(args, 2)
            + " arg3=" + argPtr(args, 3)
            + " arg4=" + argWord(args, 4)
            + " arg5=" + argPtr(args, 5)
            + " arg6=" + argWord(args, 6)
            + wordSamplesShape("previewCreateInput", this.previewPtr, 0xc0));
        },
        onLeave(retval) {
          console.log("[hcnetsdk-semantic] " + spec[0] + " leave"
            + " this=" + this.thisPtr
            + " ret=" + retval.toInt32()
            + wordSamplesShape("previewCreateInputAfter", this.previewPtr, 0xc0)
            + nonzeroWordSamplesShape("outHandleAfter", this.outHandlePtr, 0x20, 8));
        },
      }
    );
  });

  [
    ["CPreviewSession.GetStreamPacketType", HCPREVIEW_PREVIEW_SESSION_GET_STREAM_PACKET_TYPE_OFFSET],
    ["CPreviewSession.JudgeSupportRtsp", HCPREVIEW_PREVIEW_SESSION_JUDGE_SUPPORT_RTSP_OFFSET],
    ["CPreviewSession.GetRTSPType", HCPREVIEW_PREVIEW_SESSION_GET_RTSP_TYPE_OFFSET],
    ["CPreviewSession.AdjustProtoType", HCPREVIEW_PREVIEW_SESSION_ADJUST_PROTO_TYPE_OFFSET],
  ].forEach(function(spec) {
    installed += hookModuleOffset(
      spec[0],
      "libHCPreview.so",
      spec[1],
      {
        onEnter(args) {
          this.thisPtr = args[0];
          console.log("[hcnetsdk-semantic] " + spec[0] + " enter"
            + " this=" + argPtr(args, 0)
            + " arg1=" + argWord(args, 1)
            + wordSamplesShape("previewSession", args[0], 0x140)
            + nonzeroWordSamplesShape("previewSessionSparse", args[0], 0x140, 24));
        },
        onLeave(retval) {
          console.log("[hcnetsdk-semantic] " + spec[0] + " leave"
            + " this=" + this.thisPtr
            + " ret=" + retval.toInt32()
            + wordSamplesShape("previewSession", this.thisPtr, 0x140)
            + nonzeroWordSamplesShape("previewSessionSparse", this.thisPtr, 0x140, 24));
        },
      }
    );
  });

  [
    ["CPreviewSession.CreateGetStream", HCPREVIEW_PREVIEW_SESSION_CREATE_GET_STREAM_OFFSET],
    ["CPreviewSession.RegisterGetStreamCB", HCPREVIEW_PREVIEW_SESSION_REGISTER_GET_STREAM_CB_OFFSET],
    ["CPreviewSession.StreamGetterStartWork", HCPREVIEW_PREVIEW_SESSION_STREAM_GETTER_START_WORK_OFFSET],
    ["CPreviewSession.InitPlayer", HCPREVIEW_PREVIEW_SESSION_INIT_PLAYER_OFFSET],
    ["CPreviewSession.PrepareResource", HCPREVIEW_PREVIEW_SESSION_PREPARE_RESOURCE_OFFSET],
    ["CPreviewSession.AllResourceStarWork", HCPREVIEW_PREVIEW_SESSION_ALL_RESOURCE_START_WORK_OFFSET],
    ["CPreviewSession.WaitForResult", HCPREVIEW_PREVIEW_SESSION_WAIT_FOR_RESULT_OFFSET],
    ["CPreviewSession.Start", HCPREVIEW_PREVIEW_SESSION_START_OFFSET],
  ].forEach(function(spec) {
    installed += hookModuleOffset(
      spec[0],
      "libHCPreview.so",
      spec[1],
      {
        onEnter(args) {
          this.thisPtr = args[0];
          console.log("[hcnetsdk-semantic] " + spec[0] + " enter"
            + " this=" + argPtr(args, 0)
            + wordSamplesShape("previewSession", args[0], 0x140));
        },
        onLeave(retval) {
          console.log("[hcnetsdk-semantic] " + spec[0] + " leave"
            + " this=" + this.thisPtr
            + " ret=" + retval.toInt32()
            + wordSamplesShape("previewSession", this.thisPtr, 0x140));
        },
      }
    );
  });

  [
    ["CPreviewPlayer.OpenPlayer", HCPREVIEW_PREVIEW_PLAYER_OPEN_PLAYER_OFFSET],
    ["CPreviewPlayer.CreatePlayer", HCPREVIEW_PREVIEW_PLAYER_CREATE_PLAYER_OFFSET],
  ].forEach(function(spec) {
    installed += hookModuleOffset(
      spec[0],
      "libHCPreview.so",
      spec[1],
      {
        onEnter(args) {
          this.thisPtr = args[0];
          console.log("[hcnetsdk-semantic] " + spec[0] + " enter"
            + " this=" + argPtr(args, 0)
            + wordSamplesShape("previewPlayer", args[0], 0x100));
        },
        onLeave(retval) {
          console.log("[hcnetsdk-semantic] " + spec[0] + " leave"
            + " this=" + this.thisPtr
            + " ret=" + retval.toInt32()
            + wordSamplesShape("previewPlayer", this.thisPtr, 0x100));
        },
      }
    );
  });

  installed += hookModuleOffset(
    "CPreviewPlayer.Init",
    "libHCPreview.so",
    HCPREVIEW_PREVIEW_PLAYER_INIT_OFFSET,
    {
      onEnter(args) {
        this.thisPtr = args[0];
        console.log("[hcnetsdk-semantic] CPreviewPlayer.Init enter"
          + " this=" + argPtr(args, 0)
          + " hwnd=" + argPtr(args, 1)
          + " arg2=" + argWord(args, 2)
          + " arg3=" + argWord(args, 3)
          + " arg4=" + argWord(args, 4)
          + " arg5=" + argWord(args, 5)
          + wordSamplesShape("previewPlayer", args[0], 0x100));
      },
      onLeave(retval) {
        console.log("[hcnetsdk-semantic] CPreviewPlayer.Init leave"
          + " this=" + this.thisPtr
          + " ret=" + retval.toInt32()
          + wordSamplesShape("previewPlayer", this.thisPtr, 0x100));
      },
    }
  );

  installed += hookModuleOffset(
    "CPreviewPlayer.ProccessStream",
    "libHCPreview.so",
    HCPREVIEW_PREVIEW_PLAYER_PROCESS_STREAM_OFFSET,
    {
      onEnter(args) {
        if (!shouldLogNativeStream("CPreviewPlayer.ProccessStream")) return;
        const len = argWord(args, 2);
        const dataType = argWord(args, 3);
        console.log("[hcnetsdk-semantic] CPreviewPlayer.ProccessStream enter"
          + " this=" + argPtr(args, 0)
          + " dataType=" + dataType
          + " dataLen=" + len
          + nativeStreamDataShape("playerData", args[1], len));
      },
    }
  );

  installed += hookModuleOffset(
    "PRO_SendHeartbeat",
    "libHCPreview.so",
    HCPREVIEW_PRO_SEND_HEARTBEAT_OFFSET,
    {
      onEnter(args) {
        console.log("[hcnetsdk-semantic] PRO_SendHeartbeat enter"
          + " heartbeatIn=" + argPtr(args, 0)
          + wordSamplesShape("heartbeatIn", args[0], 0x80));
      },
      onLeave(retval) {
        console.log("[hcnetsdk-semantic] PRO_SendHeartbeat leave ret=" + retval.toInt32());
      },
    }
  );

  installed += hookModuleOffset(
    "CGetStreamBase.Ctor",
    "libHCPreview.so",
    HCPREVIEW_STREAM_BASE_CONSTRUCTOR_OFFSET,
    {
      onEnter(args) {
        this.thisPtr = args[0];
        console.log("[hcnetsdk-semantic] CGetStreamBase.Ctor enter"
          + " this=" + argPtr(args, 0)
          + " userIndex=" + argWord(args, 1));
      },
      onLeave() {
        console.log("[hcnetsdk-semantic] CGetStreamBase.Ctor leave"
          + " this=" + this.thisPtr
          + wordSamplesShape("getStreamBase", this.thisPtr, 0x100));
      },
    }
  );

  installed += hookModuleOffset(
    "CGetTCPStream.Ctor",
    "libHCPreview.so",
    HCPREVIEW_TCP_CONSTRUCTOR_OFFSET,
    {
      onEnter(args) {
        this.thisPtr = args[0];
        console.log("[hcnetsdk-semantic] CGetTCPStream.Ctor enter"
          + " this=" + argPtr(args, 0)
          + " arg1=" + argWord(args, 1)
          + " arg2=" + argWord(args, 2));
      },
      onLeave() {
        console.log("[hcnetsdk-semantic] CGetTCPStream.Ctor leave"
          + " this=" + this.thisPtr
          + wordSamplesShape("tcpStream", this.thisPtr, 0x100));
      },
    }
  );

  installed += hookModuleOffset(
    "CGetStreamBase.RegisterToHeartbeatProxy",
    "libHCPreview.so",
    HCPREVIEW_STREAM_BASE_REGISTER_HEARTBEAT_PROXY_OFFSET,
    {
      onEnter(args) {
        console.log("[hcnetsdk-semantic] CGetStreamBase.RegisterToHeartbeatProxy enter"
          + " this=" + argPtr(args, 0)
          + wordSamplesShape("getStreamBase", args[0], 0x100));
      },
      onLeave(retval) {
        console.log("[hcnetsdk-semantic] CGetStreamBase.RegisterToHeartbeatProxy leave ret=" + retval.toInt32());
      },
    }
  );

  installed += hookModuleOffset(
    "CGetStreamBase.RegisterGetStreamCB",
    "libHCPreview.so",
    HCPREVIEW_STREAM_BASE_REGISTER_GET_STREAM_CB_OFFSET,
    {
      onEnter(args) {
        console.log("[hcnetsdk-semantic] CGetStreamBase.RegisterGetStreamCB enter"
          + " this=" + argPtr(args, 0)
          + " cbInfo=" + argPtr(args, 1)
          + wordSamplesShape("cbInfo", args[1], 0x80));
      },
      onLeave(retval) {
        console.log("[hcnetsdk-semantic] CGetStreamBase.RegisterGetStreamCB leave ret=" + retval.toInt32());
      },
    }
  );

  installed += hookModuleOffset(
    "CGetStreamBase.IsNeedUseConvert",
    "libHCPreview.so",
    HCPREVIEW_STREAM_BASE_IS_NEED_USE_CONVERT_OFFSET,
    {
      onEnter(args) {
        this.thisPtr = args[0];
        this.dataType = argWord(args, 1);
        console.log("[hcnetsdk-semantic] CGetStreamBase.IsNeedUseConvert enter"
          + " this=" + argPtr(args, 0)
          + " dataType=" + this.dataType
          + wordSamplesShape("getStreamBase", args[0], 0x100));
      },
      onLeave(retval) {
        console.log("[hcnetsdk-semantic] CGetStreamBase.IsNeedUseConvert leave"
          + " this=" + this.thisPtr
          + " dataType=" + this.dataType
          + " ret=" + retval.toInt32());
      },
    }
  );

  installed += hookModuleOffset(
    "CGetStreamBase.CreateStreamConvert",
    "libHCPreview.so",
    HCPREVIEW_STREAM_BASE_CREATE_STREAM_CONVERT_OFFSET,
    {
      onEnter(args) {
        this.thisPtr = args[0];
        console.log("[hcnetsdk-semantic] CGetStreamBase.CreateStreamConvert enter"
          + " this=" + argPtr(args, 0)
          + wordSamplesShape("getStreamBase", args[0], 0x100));
      },
      onLeave(retval) {
        console.log("[hcnetsdk-semantic] CGetStreamBase.CreateStreamConvert leave"
          + " this=" + this.thisPtr
          + " ret=" + retval.toInt32()
          + wordSamplesShape("getStreamBase", this.thisPtr, 0x100));
      },
    }
  );

  installed += hookModuleOffset(
    "CGetStreamBase.SysTransDataCallBack",
    "libHCPreview.so",
    HCPREVIEW_STREAM_BASE_SYS_TRANS_DATA_CALLBACK_OFFSET,
    {
      onEnter(args) {
        if (!shouldLogNativeStream("CGetStreamBase.SysTransDataCallBack")) return;
        console.log("[hcnetsdk-semantic] CGetStreamBase.SysTransDataCallBack enter"
          + " outputInfo=" + argPtr(args, 0)
          + " user=" + argPtr(args, 1)
          + wordSamplesShape("outputInfo", args[0], 0x80));
      },
    }
  );

  installed += hookModuleOffset(
    "CGetStreamBase.GetStreamDataType",
    "libHCPreview.so",
    HCPREVIEW_STREAM_BASE_GET_STREAM_DATA_TYPE_OFFSET,
    {
      onEnter(args) {
        this.shouldLog = shouldLogNativeStream("CGetStreamBase.GetStreamDataType");
        if (!this.shouldLog) return;
        this.thisPtr = args[0];
        this.dataType = argWord(args, 2);
        this.len = argWord(args, 3);
        console.log("[hcnetsdk-semantic] CGetStreamBase.GetStreamDataType enter"
          + " this=" + argPtr(args, 0)
          + " dataType=" + this.dataType
          + " dataLen=" + this.len
          + nativeStreamDataShape("streamData", args[1], this.len));
      },
      onLeave(retval) {
        if (!this.shouldLog) return;
        console.log("[hcnetsdk-semantic] CGetStreamBase.GetStreamDataType leave"
          + " this=" + this.thisPtr
          + " dataType=" + this.dataType
          + " dataLen=" + this.len
          + " ret=" + retval.toInt32());
      },
    }
  );

  installed += hookModuleOffset(
    "CGetStreamBase.ProcTcpData",
    "libHCPreview.so",
    HCPREVIEW_STREAM_BASE_PROC_TCP_DATA_OFFSET,
    {
      onEnter(args) {
        this.shouldLog = shouldLogNativeStream("CGetStreamBase.ProcTcpData");
        if (!this.shouldLog) return;
        this.thisPtr = args[0];
        this.len = argWord(args, 2);
        this.status = argWord(args, 3);
        console.log("[hcnetsdk-semantic] CGetStreamBase.ProcTcpData enter"
          + " this=" + argPtr(args, 0)
          + " len=" + this.len
          + " status=" + this.status
          + nativeStreamDataShape("tcpData", args[1], this.len));
      },
      onLeave(retval) {
        if (!this.shouldLog) return;
        console.log("[hcnetsdk-semantic] CGetStreamBase.ProcTcpData leave"
          + " this=" + this.thisPtr
          + " len=" + this.len
          + " status=" + this.status
          + " ret=" + retval.toInt32());
      },
    }
  );

  installed += hookModuleOffset(
    "CGetStreamBase.PushConvertData",
    "libHCPreview.so",
    HCPREVIEW_STREAM_BASE_PUSH_CONVERT_DATA_OFFSET,
    {
      onEnter(args) {
        if (!shouldLogNativeStream("CGetStreamBase.PushConvertData")) return;
        const dataType = argWord(args, 2);
        const len = argWord(args, 3);
        console.log("[hcnetsdk-semantic] CGetStreamBase.PushConvertData enter"
          + " this=" + argPtr(args, 0)
          + " dataType=" + dataType
          + " dataLen=" + len
          + " status=" + argWord(args, 4)
          + nativeStreamDataShape("convertData", args[1], len));
      },
    }
  );

  installed += hookModuleOffset(
    "CGetStreamBase.PushDateToGetStreamCB_WithoutLock",
    "libHCPreview.so",
    HCPREVIEW_STREAM_BASE_PUSH_DATA_TO_CB_WITHOUT_LOCK_OFFSET,
    {
      onEnter(args) {
        if (!shouldLogNativeStream("CGetStreamBase.PushDateToGetStreamCB_WithoutLock")) return;
        const dataType = argWord(args, 2);
        const len = argWord(args, 3);
        console.log("[hcnetsdk-semantic] CGetStreamBase.PushDateToGetStreamCB_WithoutLock enter"
          + " this=" + argPtr(args, 0)
          + " dataType=" + dataType
          + " dataLen=" + len
          + " status=" + argWord(args, 4)
          + nativeStreamDataShape("callbackData", args[1], len));
      },
    }
  );

  installed += hookModuleOffset(
    "CGetStreamBase.PushDateToGetStreamCB",
    "libHCPreview.so",
    HCPREVIEW_STREAM_BASE_PUSH_DATA_TO_CB_OFFSET,
    {
      onEnter(args) {
        if (!shouldLogNativeStream("CGetStreamBase.PushDateToGetStreamCB")) return;
        const dataType = argWord(args, 2);
        const len = argWord(args, 3);
        console.log("[hcnetsdk-semantic] CGetStreamBase.PushDateToGetStreamCB enter"
          + " this=" + argPtr(args, 0)
          + " dataType=" + dataType
          + " dataLen=" + len
          + " status=" + argWord(args, 4)
          + nativeStreamDataShape("callbackData", args[1], len));
      },
    }
  );

  installed += hookModuleOffset(
    "CGetTCPStream.ProRTPOverTCPData",
    "libHCPreview.so",
    HCPREVIEW_TCP_PRO_RTP_OVER_TCP_DATA_OFFSET,
    {
      onEnter(args) {
        this.shouldLog = shouldLogNativeStream("CGetTCPStream.ProRTPOverTCPData");
        if (!this.shouldLog) return;
        this.thisPtr = args[0];
        this.word2 = argWord(args, 2);
        this.word3 = argWord(args, 3);
        this.word4 = argWord(args, 4);
        console.log("[hcnetsdk-semantic] CGetTCPStream.ProRTPOverTCPData enter"
          + " this=" + argPtr(args, 0)
          + " arg1=" + argPtr(args, 1)
          + " arg2=" + argPtr(args, 2)
          + " arg3=" + argPtr(args, 3)
          + " arg4=" + argPtr(args, 4)
          + " word2=" + this.word2
          + " word3=" + this.word3
          + " word4=" + this.word4);
      },
      onLeave(retval) {
        if (!this.shouldLog) return;
        console.log("[hcnetsdk-semantic] CGetTCPStream.ProRTPOverTCPData leave"
          + " this=" + this.thisPtr
          + " word2=" + this.word2
          + " word3=" + this.word3
          + " word4=" + this.word4
          + " ret=" + retval.toInt32());
      },
    }
  );

  installed += hookModuleOffset(
    "CGetStreamBase.SetIPAndChannel",
    "libHCPreview.so",
    HCPREVIEW_GET_STREAM_SET_IP_CHANNEL_OFFSET,
    {
      onEnter(args) {
        console.log("[hcnetsdk-semantic] CGetStreamBase.SetIPAndChannel enter"
          + " this=" + argPtr(args, 0)
          + " ip=" + safeReadCStringSnippet(args[1], 64)
          + " channel=" + argWord(args, 2)
          + " streamType=" + argWord(args, 3)
          + wordSamplesShape("getStreamBase", args[0], 0x80));
      },
    }
  );

  installed += hookModuleOffset(
    "CPreviewPlayer.SetIPAndChannel",
    "libHCPreview.so",
    HCPREVIEW_PREVIEW_PLAYER_SET_IP_CHANNEL_OFFSET,
    {
      onEnter(args) {
        console.log("[hcnetsdk-semantic] CPreviewPlayer.SetIPAndChannel enter"
          + " this=" + argPtr(args, 0)
          + " ip=" + safeReadCStringSnippet(args[1], 64)
          + " channel=" + argWord(args, 2)
          + wordSamplesShape("previewPlayer", args[0], 0x80));
      },
    }
  );

  installed += hookModuleOffset(
    "CUserCallBack.SetIPAndChannel",
    "libHCPreview.so",
    HCPREVIEW_USER_CALLBACK_SET_IP_CHANNEL_OFFSET,
    {
      onEnter(args) {
        console.log("[hcnetsdk-semantic] CUserCallBack.SetIPAndChannel enter"
          + " this=" + argPtr(args, 0)
          + " ip=" + safeReadCStringSnippet(args[1], 64)
          + " channel=" + argWord(args, 2)
          + wordSamplesShape("userCallBack", args[0], 0x80));
      },
    }
  );

  installed += hookModuleOffset(
    "CUserCallBack.SetRealCB",
    "libHCPreview.so",
    HCPREVIEW_USER_CALLBACK_SET_REAL_CB_OFFSET,
    {
      onEnter(args) {
        console.log("[hcnetsdk-semantic] CUserCallBack.SetRealCB enter"
          + " this=" + argPtr(args, 0)
          + " cb=" + argPtr(args, 1)
          + " user=" + argPtr(args, 2)
          + " streamMode=" + argWord(args, 3));
      },
    }
  );

  installed += hookModuleOffset(
    "CUserCallBack.SetRealCBV30",
    "libHCPreview.so",
    HCPREVIEW_USER_CALLBACK_SET_REAL_CB_V30_OFFSET,
    {
      onEnter(args) {
        console.log("[hcnetsdk-semantic] CUserCallBack.SetRealCBV30 enter"
          + " this=" + argPtr(args, 0)
          + " cb=" + argPtr(args, 1)
          + " user=" + argPtr(args, 2));
      },
    }
  );

  installed += hookModuleOffset(
    "CGetTCPStream.LinkToDvr",
    "libHCPreview.so",
    HCPREVIEW_TCP_LINK_TO_DVR_OFFSET,
    {
      onEnter(args) {
        console.log("[hcnetsdk-semantic] CGetTCPStream.LinkToDvr enter"
          + " this=" + argPtr(args, 0)
          + wordSamplesShape("tcpStream", args[0], 0x100));
      },
      onLeave(retval) {
        console.log("[hcnetsdk-semantic] CGetTCPStream.LinkToDvr leave ret=" + retval.toInt32());
      },
    }
  );

  installed += hookModuleOffset(
    "CGetTCPStream.Start",
    "libHCPreview.so",
    HCPREVIEW_TCP_STREAM_START_OFFSET,
    {
      onEnter(args) {
        console.log("[hcnetsdk-semantic] CGetTCPStream.Start enter"
          + " this=" + argPtr(args, 0)
          + " user=" + argPtr(args, 1)
          + wordSamplesShape("tcpStream", args[0], 0x100));
      },
      onLeave(retval) {
        console.log("[hcnetsdk-semantic] CGetTCPStream.Start leave ret=" + retval.toInt32());
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

function targetConfig() {
  const latest = (
    typeof globalThis !== "undefined" && globalThis.__EZVIZ_HCNETSDK_TARGET
  ) ? globalThis.__EZVIZ_HCNETSDK_TARGET : {};
  return {
    serial: latest.targetSerial || TARGET_SERIAL,
    ip: latest.targetIp || TARGET_IP,
    port: latest.targetPort || TARGET_PORT,
    password: latest.targetPassword,
    dvrConfigProbes: latest.dvrConfigProbes || "",
  };
}

function parseDvrConfigProbeList(value) {
  if (typeof value !== "string" || value.length === 0) return [];
  return value.split(",").map(function(item) {
    const parts = item.split(":");
    const command = parseInt(parts[0], 10);
    const channel = parts.length > 1 && parts[1] !== "" ? parseInt(parts[1], 10) : -1;
    const outSize = parts.length > 2 && parts[2] !== "" ? parseInt(parts[2], 10) : 65536;
    if (!Number.isFinite(command) || command < 0) return null;
    if (!Number.isFinite(channel)) return null;
    if (!Number.isFinite(outSize) || outSize <= 0 || outSize > 1048576) return null;
    return { command: command, channel: channel, outSize: outSize };
  }).filter(function(item) {
    return item !== null;
  });
}

function scheduleDvrConfigProbes(loginId) {
  if (Number(loginId) < 0) return;
  if (dvrConfigProbesStarted) return;
  const target = targetConfig();
  const probes = parseDvrConfigProbeList(target.dvrConfigProbes);
  if (probes.length === 0) return;
  dvrConfigProbesStarted = true;
  setTimeout(function() {
    runDvrConfigProbes(loginId, probes);
  }, 750);
}

function runDvrConfigProbes(loginId, probes) {
  const ptr = findExport("NET_DVR_GetDVRConfig");
  if (!ptr) {
    console.log("[hcnetsdk-probe] NET_DVR_GetDVRConfig export unavailable");
    return;
  }
  const getDvrConfig = new NativeFunction(
    ptr,
    "int",
    ["int", "uint", "int", "pointer", "uint", "pointer"]
  );
  probes.forEach(function(probe) {
    const out = Memory.alloc(probe.outSize);
    const returned = Memory.alloc(4);
    returned.writeU32(0);
    console.log("[hcnetsdk-probe] NET_DVR_GetDVRConfig enter"
      + " loginId=" + loginId
      + " command=" + probe.command
      + " channel=" + probe.channel
      + " outSize=" + probe.outSize);
    let ret = 0;
    try {
      ret = getDvrConfig(loginId, probe.command, probe.channel, out, probe.outSize, returned);
    } catch (e) {
      console.log("[hcnetsdk-probe] NET_DVR_GetDVRConfig threw"
        + " command=" + probe.command
        + " error=" + e);
      return;
    }
    let returnedSize = 0;
    try {
      returnedSize = returned.readU32();
    } catch (e) {
      returnedSize = 0;
    }
    console.log("[hcnetsdk-probe] NET_DVR_GetDVRConfig leave"
      + " command=" + probe.command
      + " channel=" + probe.channel
      + " ret=" + ret
      + " returned=" + returnedSize
      + ptrLenShape("out", out, Math.min(returnedSize, 256)));
  });
}

function triggerLanLogin(activity) {
  const LanDeviceInfo = Java.use("com.videogo.device.LanDeviceInfo");
  const DevPwdUtil = Java.use("com.videogo.util.DevPwdUtil");
  const target = targetConfig();
  const device = LanDeviceInfo.$new();
  const pwd = (
    typeof target.password === "string"
      ? target.password
      : DevPwdUtil.c(target.serial)
  );

  device.setSzSerialNO(target.serial);
  device.setSzIPv4Address(target.ip);
  device.setDwPort(target.port);
  device.setDwSDKOverTLSPort(0);
  device.setLoginName("admin");
  device.setLoginPwd(pwd);
  device.setByActivated(1);
  device.setByEZVIZCode(1);
  device.setByChanNum(1);
  device.setByIPChanNum(0);
  device.setByStartChan(1);
  device.setByStartDChan(1);

  console.log("[hcnetsdk-command] trigger target " + target.ip + ":" + target.port + " pwdLen=" + String(pwd).length);
  activity.M0(device);
  if (forcePreviewAfterLoginEnabled()) {
    schedulePreviewAfterLogin(activity, device, target, 1);
  }
}

function schedulePreviewAfterLogin(activity, device, target, attempt) {
  setTimeout(function() {
    Java.scheduleOnMainThread(function() {
      let loginId = -1;
      try {
        loginId = device.getLoginId();
      } catch (e) {
        console.log("[hcnetsdk-command] read loginId failed " + e);
      }
      if (loginId < 0 && latestTargetLoginId !== null && latestTargetLoginId >= 0) {
        loginId = latestTargetLoginId;
        try {
          if (device.setLoginId) {
            device.setLoginId(loginId);
          } else if (device.setLoginID) {
            device.setLoginID(loginId);
          }
        } catch (e) {
          console.log("[hcnetsdk-command] write loginId failed " + e);
        }
      }
      if (loginId < 0 && attempt < MAX_FORCE_PREVIEW_ATTEMPTS) {
        console.log("[hcnetsdk-command] waiting for LAN login target="
          + target.serial + " attempt=" + attempt + " loginId=" + loginId);
        schedulePreviewAfterLogin(activity, device, target, attempt + 1);
        return;
      }
      if (loginId < 0) {
        console.log("[hcnetsdk-command] forcing preview with unresolved loginId="
          + loginId + " after attempts=" + attempt);
      }
      try {
        console.log("[hcnetsdk-command] forcing LanDeviceListActivity.z0 target="
          + target.serial + " channel=1 loginId=" + loginId);
        activity.z0(device);
      } catch (e) {
        console.log("[hcnetsdk-command] force z0 failed " + e);
      }
      try {
        const PreviewBackNavigation = Java.use("com.ezviz.playerbus_ezviz.xroute.PreviewBackNavigation");
        const nav = PreviewBackNavigation.$new();
        console.log("[hcnetsdk-command] forcing PreviewBackNavigation.startLanVideoPlay target="
          + target.serial + " channel=1 loginId=" + loginId);
        nav.startLanVideoPlay(activity, target.serial, 1, loginId, "");
      } catch (e) {
        console.log("[hcnetsdk-command] force startLanVideoPlay failed " + e);
      }
    });
  }, FORCE_PREVIEW_RETRY_DELAY_MS);
}

function installJavaSemanticHooks() {
  try {
    const LanDeviceListActivity = Java.use("com.videogo.add.landevice.LanDeviceListActivity");
    LanDeviceListActivity.M0.overloads.forEach(function(ov) {
      ov.implementation = function() {
        const ret = ov.apply(this, arguments);
        console.log("[hcnetsdk-semantic] LanDeviceListActivity.M0 leave");
        return ret;
      };
    });
    LanDeviceListActivity.z0.overloads.forEach(function(ov) {
      ov.implementation = function() {
        const device = arguments[0];
        console.log("[hcnetsdk-semantic] LanDeviceListActivity.z0 enter serial="
          + device.getSzSerialNO()
          + " loginId=" + device.getLoginId()
          + " byChanNum=" + device.getByChanNum()
          + " byIPChanNum=" + device.getByIPChanNum()
          + " byStartChan=" + device.getByStartChan()
          + " byStartDChan=" + device.getByStartDChan());
        const ret = ov.apply(this, arguments);
        console.log("[hcnetsdk-semantic] LanDeviceListActivity.z0 leave");
        return ret;
      };
    });
  } catch (e) {
    console.log("[hcnetsdk-semantic] LanDeviceListActivity hooks unavailable " + e);
  }

  try {
    const ActivityUtil = Java.use("com.videogo.util.ActivityUtil");
    ActivityUtil.b.overloads.forEach(function(ov) {
      ov.implementation = function() {
        const args = [].slice.call(arguments);
        console.log("[hcnetsdk-semantic] ActivityUtil.b enter channel="
          + args[0] + " serial=" + args[1] + " ssid=" + args[2]);
        const ret = ov.apply(this, args);
        console.log("[hcnetsdk-semantic] ActivityUtil.b leave");
        return ret;
      };
    });
  } catch (e) {
    console.log("[hcnetsdk-semantic] ActivityUtil.b hook unavailable " + e);
  }

  try {
    const PreviewBackNavigation = Java.use("com.ezviz.playerbus_ezviz.xroute.PreviewBackNavigation");
    PreviewBackNavigation.startLanVideoPlay.overloads.forEach(function(ov) {
      ov.implementation = function() {
        const args = [].slice.call(arguments);
        console.log("[hcnetsdk-semantic] PreviewBackNavigation.startLanVideoPlay enter"
          + " activity=" + safeJavaClassName(args[0])
          + " serial=" + args[1]
          + " channel=" + args[2]
          + " lanUserId=" + args[3]
          + " ssid=" + args[4]);
        const ret = ov.apply(this, args);
        console.log("[hcnetsdk-semantic] PreviewBackNavigation.startLanVideoPlay leave");
        return ret;
      };
    });
  } catch (e) {
    console.log("[hcnetsdk-semantic] PreviewBackNavigation hook unavailable " + e);
  }

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
        const target = targetConfig();
        if (String(args[0]) === String(target.ip) && Number(args[1]) === Number(target.port)) {
          latestTargetLoginId = ret;
          console.log("[hcnetsdk-command] remembered target loginId=" + ret);
          scheduleDvrConfigProbes(ret);
        }
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
      if (!ENABLE_TARGET_TRIGGER) {
        console.log("[hcnetsdk-command] target trigger disabled by parameters");
        return;
      }
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
