"use strict";

const envRecordMs = Number.parseInt(
  (typeof Process !== "undefined" && Process.env && Process.env.EZVIZ_RECORD_MS) || "",
  10,
);
const RECORD_MS = Number.isFinite(envRecordMs) && envRecordMs > 0 ? envRecordMs : 30000;
function deviceFlagExists(path) {
  try {
    const f = new File(path, "r");
    f.close();
    return true;
  } catch (e) {
    return false;
  }
}
const DUMP_LOCAL_AES_RAW = (
  (typeof Process !== "undefined"
    && Process.env
    && Process.env.EZVIZ_DUMP_LOCAL_AES_RAW === "1")
  || deviceFlagExists("/data/local/tmp/ezviz-dump-local-aes-raw.flag")
);
const handleInfo = new Map();
const activeRecordings = new Set();
const fdPeers = new Map();
const fdLocalAddrs = new Map();
const fdLogged = new Map();
const secretFingerprints = new Map();
const objectIds = new Map();
const keyIds = new Map();
const aesContextKeys = new Map();
const threadState = new Map();
let nextObjectId = 1;
let nextKeyId = 1;
let nativeSymbolHooksInstalled = false;
let nativeCheckpointHooksInstalled = false;

function tag(){ return new Date().toISOString().replace(/[-:.TZ]/g,"").slice(0,15); }
function s(v){ try { return (v === null || v === undefined) ? "" : v.toString(); } catch(e){ return `<toString:${e}>`; } }
function fv(o,n){ try { let f=o[n]; if (f===undefined||f===null) return ""; return s(f.value); } catch(e){ return ""; } }
function desc(p){
  if (!p) return "<null>";
  let parts = [
    `source=${fv(p,"iStreamSource")}`,
    `dev=${fv(p,"szDevSerial")}`,
    `chan=${fv(p,"iChannelNumber")}`,
    `netUid=${fv(p,"iNetSDKUserId")}`,
    `local=${fv(p,"szDevLocalIP")}:${fv(p,"iDevCmdLocalPort")}/${fv(p,"iDevStreamLocalPort")}`,
    `remote=${fv(p,"szDevIP")}:${fv(p,"iDevCmdPort")}/${fv(p,"iDevStreamPort")}`,
    `streamType=${fv(p,"iStreamType")}`,
    `videoLevel=${fv(p,"iVideoLevel")}`,
    `vtm=${fv(p,"szVTMDomain")}:${fv(p,"iVTMPort")}`,
    `secretLen=${fv(p,"szSecretKey").length}`,
  ];
  return parts.join(" ");
}
function lanish(d){ return /192\.168\.|local=.+:[1-9]|netUid=[0-9]/.test(d); }
function remember(h, name, p){ let key=s(h); let d=desc(p); handleInfo.set(key,{name,d,lan:lanish(d),serial:fv(p,"szDevSerial"),chan:fv(p,"iChannelNumber")}); console.log(`[broad] ${name} ret=${key} lan=${handleInfo.get(key).lan} ${d}`); }
function shouldLogPeer(peer){
  return true;
}
function isLocalEzvizPeer(peer) {
  return peer && /^(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)/.test(peer.host) && [8000, 8443, 9010, 9020].indexOf(peer.port) !== -1;
}
function isHcNetSdkPeer(peer) {
  return peer && [8000, 8443].indexOf(peer.port) !== -1;
}
function shouldLogLocalSockaddr(addr) {
  return addr && (
    addr.port === 0
    || addr.port === 10101
    || addr.port === 10103
    || addr.port === 10105
    || [8000, 8443, 9010, 9020].indexOf(addr.port) !== -1
    || /^(0\.0\.0\.0|127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)/.test(addr.host)
  );
}
function hexPreview(ptr, len) {
  const n = Math.min(len, 32);
  if (ptr.isNull() || n <= 0) return "";
  try {
    const bytes = ptr.readByteArray(n);
    if (!bytes) return "";
    return Array.prototype.map.call(new Uint8Array(bytes), function(b) {
      return ("0" + b.toString(16)).slice(-2);
    }).join(" ");
  } catch (e) {
    return "<hex-failed:" + e + ">";
  }
}
function u32be(bytes, off) {
  return ((bytes[off] << 24) >>> 0) + (bytes[off + 1] << 16) + (bytes[off + 2] << 8) + bytes[off + 3];
}
function u16be(bytes, off) {
  return (bytes[off] << 8) + bytes[off + 1];
}
function safeAscii(bytes) {
  return Array.prototype.map.call(bytes, function(b) {
    return (b >= 0x20 && b <= 0x7e) ? String.fromCharCode(b) : " ";
  }).join("");
}
function xmlTagShape(text) {
  const tags = [];
  const seen = {};
  const re = /<\/?([A-Za-z_][A-Za-z0-9_.:-]*)\b[^>]*>/g;
  let m;
  while ((m = re.exec(text)) !== null && tags.length < 24) {
    const tag = m[1];
    if (!seen[tag]) {
      seen[tag] = true;
      tags.push(tag);
    }
  }
  return tags.join(",");
}
function xmlTagValueShape(text) {
  const parts = [];
  const seen = {};
  const re = /<([A-Za-z_][A-Za-z0-9_.:-]*)\b[^>]*>([^<]*)<\/\1>/g;
  let m;
  while ((m = re.exec(text)) !== null && parts.length < 24) {
    const tag = m[1];
    if (seen[tag]) continue;
    seen[tag] = true;
    const value = m[2] || "";
    let printable = 0;
    for (let i = 0; i < value.length; i++) {
      const code = value.charCodeAt(i);
      if (code >= 0x20 && code <= 0x7e) printable++;
    }
    const match = secretMatch(value);
    parts.push(tag + "Len=" + value.length
      + "/p" + (value.length ? (printable / value.length).toFixed(2) : "0.00")
      + (match !== "new" && match !== "none" ? "/match=" + match : ""));
  }
  return parts.join(",");
}
function xmlSafeSelectedValues(text) {
  const allowed = {
    Channel: true,
    Identifier: true,
    NatAddress: true,
    NatPort: true,
    UPnPAddress: true,
    UPnPPort: true,
    InnerAddress: true,
    InnerPort: true,
    StreamType: true,
    IsEncrypt: true,
    Udt: true,
    Nat: true,
    PortGuessType: true,
    Timeout: true,
    HeartbeatInterval: true,
    Uuid: true,
    Timestamp: true,
    Session: true,
    Rate: true,
    Mode: true,
    Result: true,
    StreamHeader: true,
  };
  const parts = [];
  const seen = {};
  function decodeXmlEntities(value) {
    return value
      .replace(/&lt;/g, "<")
      .replace(/&gt;/g, ">")
      .replace(/&amp;/g, "&")
      .replace(/&quot;/g, '"')
      .replace(/&apos;/g, "'");
  }
  function addValue(tag, value) {
    if (!allowed[tag] || seen[tag]) return;
    seen[tag] = true;
    if (value.length > 128) {
      parts.push(tag + "=<len-" + value.length + ">");
    } else {
      parts.push(tag + "=" + JSON.stringify(value));
    }
  }
  function scan(source, depth) {
    if (depth > 2 || !source) return;
    const re = /<([A-Za-z_][A-Za-z0-9_.:-]*)\b[^>]*>([^<]*)<\/\1>/g;
    let m;
    while ((m = re.exec(source)) !== null && parts.length < 32) {
      const tag = m[1];
      const value = m[2] || "";
      addValue(tag, value);
      if ((tag === "ReceiverInfo" || tag === "ReceiverInfoEx") && value.indexOf("&lt;") >= 0) {
        scan(decodeXmlEntities(value), depth + 1);
      }
    }
  }
  const blockRe = /<(ReceiverInfo|ReceiverInfoEx)\b[^>]*>([\s\S]*?)<\/\1>/g;
  let block;
  while ((block = blockRe.exec(text)) !== null && parts.length < 32) {
    const inner = block[2] || "";
    if (inner.indexOf("&lt;") >= 0) scan(decodeXmlEntities(inner), 1);
    else scan(inner, 1);
  }
  scan(text, 0);
  return parts.join(",");
}
function xmlReceiverBlockShape(text) {
  const blockRe = /<ReceiverInfo\b[^>]*>([\s\S]*?)<\/ReceiverInfo>/;
  const match = blockRe.exec(text);
  if (!match) {
    const idx = text.indexOf("ReceiverInfo");
    if (idx < 0) return "";
    const around = text.slice(Math.max(0, idx - 2), Math.min(text.length, idx + 320)).replace(/\s+/g, " ").trim();
    return " receiverInfoAround=" + JSON.stringify(around);
  }
  let value = match[1] || "";
  value = value
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'");
  value = value.replace(/\s+/g, " ").trim();
  if (!value) return " receiverInfoBlock=<empty>";
  if (value.length > 512) {
    return " receiverInfoBlock=" + JSON.stringify(value.slice(0, 512)) + "...<len-" + value.length + ">";
  }
  return " receiverInfoBlock=" + JSON.stringify(value);
}
function bodyShape(bytes, off, len) {
  if (len <= 0 || off >= bytes.length) return " bodyKind=empty bodyLen=" + Math.max(0, len);
  const end = Math.min(bytes.length, off + len);
  const captured = Math.max(0, end - off);
  let printable = 0, nul = 0, high = 0;
  for (let i = off; i < end; i++) {
    const b = bytes[i];
    if (b >= 0x20 && b <= 0x7e) printable++;
    if (b === 0) nul++;
    if (b >= 0x80) high++;
  }
  const bodyText = captured ? safeAscii(bytes.slice(off, end)) : "";
  const xmlRel = bodyText.indexOf("<");
  const tags = xmlRel >= 0 ? xmlTagShape(bodyText.slice(xmlRel)) : "";
  const valueLens = tags ? xmlTagValueShape(bodyText.slice(xmlRel)) : "";
  const safeValues = tags ? xmlSafeSelectedValues(bodyText.slice(xmlRel)) : "";
  const receiverBlock = tags ? xmlReceiverBlockShape(bodyText.slice(xmlRel)) : "";
  let kind = "binary";
  if (captured === 0) kind = "empty";
  else if (tags && xmlRel === 0) kind = "xml";
  else if (tags) kind = "prefixed_xml";
  else if (high / captured > 0.25) kind = "opaque_binary";
  else if (printable / captured > 0.75) kind = "printable_non_xml";
  return " bodyKind=" + kind
    + " bodyLen=" + len
    + " capturedBody=" + captured
    + " printable=" + (captured ? (printable / captured).toFixed(2) : "0.00")
    + " nulls=" + (captured ? (nul / captured).toFixed(2) : "0.00")
    + " high=" + (captured ? (high / captured).toFixed(2) : "0.00")
    + (tags ? " xmlOffset=" + xmlRel + " tags=" + tags : "")
    + (valueLens ? " valueLens=" + valueLens : "")
    + (safeValues ? " safeValues=" + safeValues : "")
    + receiverBlock;
}
function cstrShape(label, ptr, maxLen) {
  const value = boundedCString(ptr, maxLen || 4096);
  if (value === null) return " " + label + "=<unreadable>";
  let printable = 0, nul = 0, high = 0;
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i) & 0xff;
    if (code >= 0x20 && code <= 0x7e) printable++;
    if (code === 0) nul++;
    if (code >= 0x80) high++;
  }
  const tags = value.indexOf("<") >= 0 ? xmlTagShape(value) : "";
  const valueLens = tags ? xmlTagValueShape(value) : "";
  const safeValues = tags ? xmlSafeSelectedValues(value) : "";
  const receiverBlock = tags ? xmlReceiverBlockShape(value) : "";
  return " " + label + "Len=" + value.length
    + " printable=" + (value.length ? (printable / value.length).toFixed(2) : "0.00")
    + " nulls=" + (value.length ? (nul / value.length).toFixed(2) : "0.00")
    + " high=" + (value.length ? (high / value.length).toFixed(2) : "0.00")
    + " match=" + secretMatch(value)
    + (tags ? " tags=" + tags : "")
    + (valueLens ? " valueLens=" + valueLens : "")
    + (safeValues ? " safeValues=" + safeValues : "")
    + receiverBlock;
}
function argInt(args, idx) {
  try {
    return args[idx].toInt32();
  } catch (e) {
    return "<arg" + idx + "-failed:" + e + ">";
  }
}
function libcppStringShape(label, ptr) {
  if (!ptr || ptr.isNull()) return " " + label + "=<null>";
  try {
    const marker = ptr.readU8();
    const isLong = (marker & 1) === 1;
    const len = isLong ? ptr.add(4).readU32() : (marker >>> 1);
    const dataPtr = isLong ? ptr.add(8).readPointer() : ptr.add(1);
    return cstrShape(label, dataPtr, Math.min(len + 1, 512))
      + " " + label + "Mode=" + (isLong ? "long" : "short")
      + " " + label + "DeclaredLen=" + len;
  } catch (e) {
    return " " + label + "=<std-string-failed:" + e + ">";
  }
}
function libcppStringValue(ptr, maxLen) {
  if (!ptr || ptr.isNull()) return null;
  try {
    const marker = ptr.readU8();
    const isLong = (marker & 1) === 1;
    const len = isLong ? ptr.add(4).readU32() : (marker >>> 1);
    if (len > (maxLen || 4096)) return null;
    const dataPtr = isLong ? ptr.add(8).readPointer() : ptr.add(1);
    const raw = dataPtr.readByteArray(len);
    if (!raw) return null;
    return Array.prototype.map.call(new Uint8Array(raw), function(b) {
      return String.fromCharCode(b);
    }).join("");
  } catch (e) {
    return null;
  }
}
function rememberLibcppString(label, ptr, maxLen) {
  const value = libcppStringValue(ptr, maxLen || 4096);
  return value ? rememberSecret(label, value) : "";
}
function libcppStringBinaryShape(label, ptr, maxLen) {
  const value = libcppStringValue(ptr, maxLen || 4096);
  if (value === null) return " " + label + "Value=<unreadable>";
  const bytes = asciiBytes(value);
  let printable = 0, nul = 0, high = 0;
  bytes.forEach(function(b) {
    if (b >= 0x20 && b <= 0x7e) printable++;
    if (b === 0) nul++;
    if (b >= 0x80) high++;
  });
  return " " + label + "ValueBytes=" + bytes.length
    + " keyId=" + (keyIds.get(fingerprintBytes(bytes)) || "new")
    + " printable=" + (bytes.length ? (printable / bytes.length).toFixed(2) : "0.00")
    + " nulls=" + (bytes.length ? (nul / bytes.length).toFixed(2) : "0.00")
    + " high=" + (bytes.length ? (high / bytes.length).toFixed(2) : "0.00")
    + " match=" + secretMatch(value);
}
function sameLibcppStringFingerprint(label, a, b, maxLen) {
  const av = libcppStringValue(a, maxLen || 4096);
  const bv = libcppStringValue(b, maxLen || 4096);
  if (av === null || bv === null) return " " + label + "=unknown";
  return " " + label + "=" + (fingerprintString(av) === fingerprintString(bv) ? "yes" : "no")
    + " aLen=" + av.length + " bLen=" + bv.length;
}
function globalInfoClientKeyShape(label, sretPtr, selfPtr, offset, rememberLabel) {
  let extra = "";
  try {
    extra += pointerShape("sret", sretPtr)
      + libcppStringShape("sretStdString", sretPtr)
      + libcppStringBinaryShape("sretStdString", sretPtr, 4096);
    extra += rememberLibcppString(rememberLabel, sretPtr, 4096);
  } catch (e) {
    extra += " sretShape=<failed:" + e + ">";
  }
  try {
    const fieldPtr = selfPtr.add(offset);
    extra += pointerShape("field", fieldPtr)
      + libcppStringShape("fieldStdString", fieldPtr)
      + libcppStringBinaryShape("fieldStdString", fieldPtr, 4096)
      + sameLibcppStringFingerprint("sretFieldValueMatch", sretPtr, fieldPtr, 4096);
  } catch (e) {
    extra += " fieldShape=<failed:" + e + ">";
  }
  return " clientKeyKind=" + label + extra;
}
function isNonNullPointer(ptr) {
  try {
    return !!ptr && typeof ptr.isNull === "function" && !ptr.isNull();
  } catch (e) {
    return false;
  }
}
function setupReqParamShape(ptr) {
  if (!ptr || ptr.isNull()) return " setupParam=<null>";
  try {
    return " setupParam=" + ptr
      + libcppStringShape("natAddress", ptr)
      + " natPort=" + ptr.add(0x0c).readS32()
      + libcppStringShape("upnpAddress", ptr.add(0x10))
      + " upnpPort=" + ptr.add(0x1c).readS32()
      + libcppStringShape("innerAddress", ptr.add(0x20))
      + " innerPort=" + ptr.add(0x2c).readS32()
      + " udt=" + ptr.add(0x30).readS32()
      + libcppStringShape("identifier", ptr.add(0x34))
      + " natFlag=" + ptr.add(0x40).readU8()
      + " udtFlag=" + ptr.add(0x44).readS32()
      + " portGuessType=" + ptr.add(0x4c).readS32()
      + " timeout=" + ptr.add(0x50).readS32()
      + " heartbeatInterval=" + ptr.add(0x54).readS32();
  } catch (e) {
    return " setupParam=<shape-failed:" + e + ">";
  }
}
function localFrameShape(ptr, len) {
  if (ptr.isNull() || len < 32) return "";
  try {
    const n = Math.min(len, 4096);
    const raw = ptr.readByteArray(n);
    if (!raw) return "";
    const bytes = new Uint8Array(raw);
    if (bytes[0] !== 0x9e || bytes[1] !== 0xba || bytes[2] !== 0xac || bytes[3] !== 0xe9) return "";
    const seq = u32be(bytes, 8);
    const command = u16be(bytes, 18);
    const status = u32be(bytes, 20);
    const bodyLen = u32be(bytes, 24);
    const capturedBody = Math.max(0, Math.min(bodyLen, n - 32));
    return " frame=cmd=0x" + command.toString(16) + " seq=" + seq + " status=0x" + status.toString(16) + bodyShape(bytes, 32, capturedBody || bodyLen);
  } catch (e) {
    return " frame=<shape-failed:" + e + ">";
  }
}
function byteFingerprint(ptr, len) {
  if (ptr.isNull() || len <= 0) return "0:0";
  try {
    const n = Math.min(len, 128);
    const raw = ptr.readByteArray(n);
    if (!raw) return "0:0";
    return fingerprintBytes(Array.prototype.slice.call(new Uint8Array(raw)));
  } catch (e) {
    return "<fp-failed:" + e + ">";
  }
}
function hexBytes(ptr, len) {
  try {
    if (!ptr || ptr.isNull() || len <= 0) return "";
    const raw = ptr.readByteArray(len);
    if (!raw) return "";
    return Array.prototype.slice.call(new Uint8Array(raw)).map(function(b) {
      return ("0" + b.toString(16)).slice(-2);
    }).join("");
  } catch (e) {
    return "";
  }
}
function tcpPayloadShape(ptr, len) {
  if (ptr.isNull() || len <= 0) return " tcpKind=empty tcpLen=" + Math.max(0, len);
  try {
    const n = Math.min(len, 512);
    const raw = ptr.readByteArray(n);
    if (!raw) return " tcpKind=unreadable tcpLen=" + len;
    const bytes = new Uint8Array(raw);
    let printable = 0, nul = 0, high = 0;
    for (let i = 0; i < bytes.length; i++) {
      const b = bytes[i];
      if (b >= 0x20 && b <= 0x7e) printable++;
      if (b === 0) nul++;
      if (b >= 0x80) high++;
    }
    let kind = "binary";
    if (bytes.length >= 5 && [20, 21, 22, 23].indexOf(bytes[0]) !== -1 && bytes[1] === 3 && bytes[2] <= 4) {
      kind = "tls_record";
    } else if (bytes.length >= 4 && bytes[0] === 0x48 && bytes[1] === 0x54 && bytes[2] === 0x54 && bytes[3] === 0x50) {
      kind = "http";
    } else if (bytes.length >= 4 && bytes[0] === 0x48 && bytes[1] === 0x4b && bytes[2] === 0x4d && bytes[3] === 0x49) {
      kind = "hik_hkmi";
    } else if (bytes.length >= 4 && bytes[0] === 0x40 && bytes[1] === 0x40 && bytes[2] === 0x40 && bytes[3] === 0x40) {
      kind = "hik_private";
    } else if (bytes.length >= 4 && bytes[0] === 0x9e && bytes[1] === 0xba && bytes[2] === 0xac && bytes[3] === 0xe9) {
      kind = "ezviz_local_sdk_frame";
    } else if (high / bytes.length > 0.25) {
      kind = "opaque_binary";
    } else if (printable / bytes.length > 0.75) {
      kind = "printable_non_xml";
    }
    const u32be0 = bytes.length >= 4 ? u32be(bytes, 0) : -1;
    const u16be0 = bytes.length >= 2 ? u16be(bytes, 0) : -1;
    return " tcpKind=" + kind
      + " tcpLen=" + len
      + " captured=" + bytes.length
      + " fp128=" + byteFingerprint(ptr, len)
      + " printable=" + (bytes.length ? (printable / bytes.length).toFixed(2) : "0.00")
      + " nulls=" + (bytes.length ? (nul / bytes.length).toFixed(2) : "0.00")
      + " high=" + (bytes.length ? (high / bytes.length).toFixed(2) : "0.00")
      + (u16be0 >= 0 ? " u16be0=0x" + u16be0.toString(16) : "")
      + (u32be0 >= 0 ? " u32be0=0x" + u32be0.toString(16) : "");
  } catch (e) {
    return " tcpShape=<failed:" + e + ">";
  }
}
function xmlChunkShape(ptr, len) {
  if (ptr.isNull() || len < 5) return "";
  try {
    const n = Math.min(len, 4096);
    const raw = ptr.readByteArray(n);
    if (!raw) return "";
    const bytes = new Uint8Array(raw);
    const text = safeAscii(bytes);
    if (text.indexOf("<") === -1 || text.indexOf(">") === -1) return "";
    const tags = xmlTagShape(text);
    return tags ? " xmlChunkLen=" + len + " tags=" + tags : "";
  } catch (e) {
    return " xmlChunk=<shape-failed:" + e + ">";
  }
}
function logFdData(kind, fd, buf, len) {
  const peer = fdPeers.get(fd);
  if (!isLocalEzvizPeer(peer) || len <= 0) return;
  if (DUMP_LOCAL_AES_RAW && kind === "send" && len > 0 && len <= 2048 && !buf.isNull()) {
    try {
      const n = Math.min(len, 2048);
      console.log("[local-frame-raw-json] " + JSON.stringify({
        fd: fd,
        peer: peer.host + ":" + peer.port,
        len: len,
        frameHex: hexBytes(buf, n),
        shape: localFrameShape(buf, len),
      }));
    } catch (e) {
      console.log("[local-frame-raw-json] " + JSON.stringify({ error: String(e) }));
    }
  }
  const key = kind + ":" + fd;
  const count = fdLogged.get(key) || 0;
  if (count >= 6) return;
  fdLogged.set(key, count + 1);
  if (isHcNetSdkPeer(peer)) {
    console.log("[native-" + kind + "] fd=" + fd + " " + peer.host + ":" + peer.port + tcpPayloadShape(buf, len));
    return;
  }
  console.log("[native-" + kind + "] fd=" + fd + " " + peer.host + ":" + peer.port + " len=" + len + " head=" + hexPreview(buf, len) + localFrameShape(buf, len) + xmlChunkShape(buf, len));
}
function readSockaddr(addr, len){
  if (addr.isNull() || len < 8) return null;
  const family = addr.readU16();
  if (family !== 2) return null; // AF_INET
  const port = (addr.add(2).readU8() << 8) | addr.add(3).readU8();
  const host = [0,1,2,3].map(function(i){ return addr.add(4 + i).readU8(); }).join(".");
  return {family, host, port};
}
function cstrLen(ptr) {
  if (!ptr || ptr.isNull()) return -1;
  try {
    return ptr.readCString().length;
  } catch (e) {
    return -2;
  }
}
function boundedCString(ptr, maxLen) {
  if (!ptr || ptr.isNull()) return null;
  try {
    const raw = ptr.readByteArray(maxLen);
    if (!raw) return null;
    const bytes = new Uint8Array(raw);
    let end = 0;
    while (end < bytes.length && bytes[end] !== 0) end++;
    return Array.prototype.map.call(bytes.slice(0, end), function(b) {
      return String.fromCharCode(b);
    }).join("");
  } catch (e) {
    return null;
  }
}
function fingerprintString(value) {
  // Non-cryptographic in-memory equality marker. It is never printed.
  let h = 2166136261;
  for (let i = 0; i < value.length; i++) {
    h ^= value.charCodeAt(i) & 0xff;
    h = Math.imul(h, 16777619) >>> 0;
  }
  return value.length + ":" + h.toString(16);
}
function fingerprintBytes(bytes) {
  let h = 2166136261;
  for (let i = 0; i < bytes.length; i++) {
    h ^= bytes[i];
    h = Math.imul(h, 16777619) >>> 0;
  }
  return bytes.length + ":" + h.toString(16);
}
function objectLabel(prefix, ptr) {
  if (!ptr || ptr.isNull()) return prefix + "=<null>";
  const key = ptr.toString();
  let id = objectIds.get(key);
  if (!id) {
    id = prefix + nextObjectId++;
    objectIds.set(key, id);
  }
  return id;
}
function currentThreadKey() {
  try { return Process.getCurrentThreadId().toString(); } catch (e) { return "main"; }
}
function pushThreadState(kind, data) {
  const key = currentThreadKey();
  const stack = threadState.get(key) || [];
  stack.push(Object.assign({kind: kind}, data || {}));
  threadState.set(key, stack);
}
function popThreadState(kind) {
  const key = currentThreadKey();
  const stack = threadState.get(key) || [];
  for (let i = stack.length - 1; i >= 0; i--) {
    if (!kind || stack[i].kind === kind) {
      const item = stack.splice(i, 1)[0];
      threadState.set(key, stack);
      return item;
    }
  }
  return null;
}
function peekThreadState(kind) {
  const stack = threadState.get(currentThreadKey()) || [];
  for (let i = stack.length - 1; i >= 0; i--) {
    if (!kind || stack[i].kind === kind) return stack[i];
  }
  return null;
}
function asciiBytes(value) {
  const bytes = [];
  for (let i = 0; i < value.length; i++) bytes.push(value.charCodeAt(i) & 0xff);
  return bytes;
}
function zpad16(bytes) {
  const out = bytes.slice(0, 16);
  while (out.length < 16) out.push(0);
  return out;
}
function rememberSecret(label, value) {
  if (!value) return "";
  const fp = fingerprintString(value);
  secretFingerprints.set(label, fp);
  const ascii = asciiBytes(value);
  secretFingerprints.set(label + ":ascii", fingerprintBytes(ascii));
  secretFingerprints.set(label + ":zpad16", fingerprintBytes(zpad16(ascii)));
  return " " + label + "Len=" + value.length;
}
function javaSecretStringShape(label, value, rememberLabel) {
  if (value === null || value === undefined) return " " + label + "=<null>";
  const str = s(value);
  let printable = 0;
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);
    if (code >= 0x20 && code <= 0x7e) printable++;
  }
  const remembered = rememberLabel ? rememberSecret(rememberLabel, str) : "";
  return " " + label + "Len=" + str.length
    + " printable=" + (str.length ? (printable / str.length).toFixed(2) : "0.00")
    + " match=" + secretMatch(str)
    + remembered;
}
function casInfoShape(info, source) {
  if (!info) return " source=" + source + " cas=<null>";
  let serial = "<unknown>";
  let operationCode = null;
  let key = null;
  let encryptType = "<unknown>";
  try { serial = s(info.getDeviceSerial()); } catch (e) { serial = "<serial-failed:" + e + ">"; }
  try { operationCode = info.getOperationCode(); } catch (e) { operationCode = null; }
  try { key = info.getKey(); } catch (e) { key = null; }
  try { encryptType = s(info.getEncryptType()); } catch (e) { encryptType = "<encrypt-type-failed:" + e + ">"; }
  const opLen = operationCode === null || operationCode === undefined ? 0 : s(operationCode).length;
  const serialLen = serial.indexOf("<") === 0 ? 0 : serial.length;
  return " source=" + source
    + " serial=" + serial
    + javaSecretStringShape("operationCode", operationCode, "casOp:" + serial)
    + javaSecretStringShape("key", key, "casKey:" + serial)
    + " encryptType=" + encryptType
    + " ivLen=" + (serialLen + opLen);
}
function stDevInfoShape(info, source) {
  if (!info) return " source=" + source + " stDevInfo=<null>";
  let serial = "<unknown>";
  let operationCode = null;
  let key = null;
  let encryptType = "<unknown>";
  try { serial = s(info.szDevSerial.value !== undefined ? info.szDevSerial.value : info.szDevSerial); } catch (e) { serial = "<serial-failed:" + e + ">"; }
  try { operationCode = info.szOperationCode.value !== undefined ? info.szOperationCode.value : info.szOperationCode; } catch (e) { operationCode = null; }
  try { key = info.szKey.value !== undefined ? info.szKey.value : info.szKey; } catch (e) { key = null; }
  try { encryptType = s(info.enEncryptType.value !== undefined ? info.enEncryptType.value : info.enEncryptType); } catch (e) { encryptType = "<encrypt-type-failed:" + e + ">"; }
  const opLen = operationCode === null || operationCode === undefined ? 0 : s(operationCode).length;
  const serialLen = serial.indexOf("<") === 0 ? 0 : serial.length;
  return " source=" + source
    + " serial=" + serial
    + javaSecretStringShape("operationCode", operationCode, "casStOp:" + serial)
    + javaSecretStringShape("key", key, "casStKey:" + serial)
    + " encryptType=" + encryptType
    + " ivLen=" + (serialLen + opLen);
}
function secretMatch(value) {
  if (!value) return "none";
  const fp = fingerprintString(value);
  const matches = [];
  secretFingerprints.forEach(function(stored, label) {
    if (stored === fp) matches.push(label);
  });
  return matches.length ? matches.join("|") : "new";
}
function secretShape(label, ptr) {
  const value = boundedCString(ptr, 128);
  if (value === null) return " " + label + "=<unreadable>";
  let printable = 0;
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code >= 0x20 && code <= 0x7e) printable++;
  }
  return " " + label + "Len=" + value.length
    + " printable=" + (value.length ? (printable / value.length).toFixed(2) : "0.00")
    + " match=" + secretMatch(value);
}
function secretBinaryShape(label, ptr, len) {
  const info = secretBinaryInfo(ptr, len);
  return info.text.replace("{label}", label);
}
function secretBinaryInfo(ptr, len) {
  if (!ptr || ptr.isNull()) return {fp: null, keyId: null, text: " {label}=<null>"};
  try {
    const raw = ptr.readByteArray(len);
    if (!raw) return {fp: null, keyId: null, text: " {label}=<unreadable>"};
    const bytes = Array.prototype.slice.call(new Uint8Array(raw));
    let printable = 0, nul = 0, high = 0;
    bytes.forEach(function(b) {
      if (b >= 0x20 && b <= 0x7e) printable++;
      if (b === 0) nul++;
      if (b >= 0x80) high++;
    });
    const fp = fingerprintBytes(bytes);
    const keyId = keyIds.get(fp) || ("K" + nextKeyId++);
    keyIds.set(fp, keyId);
    const matches = [];
    secretFingerprints.forEach(function(stored, storedLabel) {
      if (stored === fp) matches.push(storedLabel);
    });
    return {
      fp: fp,
      keyId: keyId,
      hex: DUMP_LOCAL_AES_RAW ? bytes.map(function(b) {
        return ("0" + b.toString(16)).slice(-2);
      }).join("") : "",
      text: " {label}Bytes=" + len
      + " keyId=" + keyId
      + " printable=" + (printable / len).toFixed(2)
      + " nulls=" + (nul / len).toFixed(2)
      + " high=" + (high / len).toFixed(2)
      + " match=" + (matches.length ? matches.join("|") : "new")
    };
  } catch (e) {
    return {fp: null, keyId: null, text: " {label}=<binary-failed:" + e + ">"};
  }
}
function rememberAesContext(ctx, keyInfo, bits, op) {
  if (!ctx || ctx.isNull() || !keyInfo || !keyInfo.fp) return "";
  const ctxKey = ctx.toString();
  const label = objectLabel("aesctx", ctx);
  aesContextKeys.set(ctxKey, {
    keyId: keyInfo.keyId,
    fp: keyInfo.fp,
    hex: keyInfo.hex || "",
    bits: bits,
    op: op
  });
  return " ctx=" + label + " keyId=" + keyInfo.keyId + " bits=" + bits + " op=" + op;
}
function aesContextShape(ctx) {
  if (!ctx || ctx.isNull()) return " ctx=<null>";
  const label = objectLabel("aesctx", ctx);
  const known = aesContextKeys.get(ctx.toString());
  return " ctx=" + label + (known ? " keyId=" + known.keyId + " bits=" + known.bits + " op=" + known.op : " keyId=<unknown>");
}
function aesContextInfo(ctx) {
  if (!ctx || ctx.isNull()) return null;
  return aesContextKeys.get(ctx.toString()) || null;
}
function scanPointerForFingerprint(label, ptr, fp, maxBytes) {
  if (!ptr || ptr.isNull() || !fp) return "";
  try {
    const n = Math.min(maxBytes, 1024);
    const raw = ptr.readByteArray(n);
    if (!raw) return "";
    const bytes = Array.prototype.slice.call(new Uint8Array(raw));
    const offsets = [];
    for (let off = 0; off + 16 <= bytes.length; off += 4) {
      if (fingerprintBytes(bytes.slice(off, off + 16)) === fp) offsets.push(off);
      if (offsets.length >= 8) break;
    }
    return offsets.length ? " " + label + "KeyOffsets=" + offsets.join(",") : "";
  } catch (e) {
    return " " + label + "Scan=<failed:" + e + ">";
  }
}
function samePointer(label, a, b) {
  if (!a || !b || a.isNull() || b.isNull()) return " " + label + "=no";
  return " " + label + "=" + (a.equals(b) ? "yes" : "no") + " delta=" + a.sub(b);
}
function sameBinaryFingerprint(label, a, b, len) {
  const ai = secretBinaryInfo(a, len);
  const bi = secretBinaryInfo(b, len);
  if (!ai.fp || !bi.fp) return " " + label + "=unknown";
  return " " + label + "=" + (ai.fp === bi.fp ? "yes" : "no")
    + " aKeyId=" + ai.keyId + " bKeyId=" + bi.keyId;
}
function streamInfoInitShape(label, ptr) {
  if (!ptr || ptr.isNull()) return " " + label + "=<null>";
  // CCtrlClient::Init receives ST_STREAM_INFO by value on the stack. Static
  // Thumb analysis shows Init copies stack+0x158 into CCtrlClient+0x50.
  return " " + label + "=" + objectLabel(label, ptr)
    + secretBinaryShape("stackPlus0x158", ptr.add(0x158), 16)
    + secretShape("stackPlus0x158String", ptr.add(0x158));
}
function streamInfoPointerShape(label, ptr) {
  if (!ptr || ptr.isNull()) return " " + label + "=<null>";
  return " " + label + "=" + objectLabel(label, ptr)
    + secretBinaryShape("plus0x158", ptr.add(0x158), 16)
    + secretShape("plus0x158String", ptr.add(0x158));
}
function pointerShape(label, ptr) {
  if (!ptr || ptr.isNull()) return " " + label + "=<null>";
  try {
    const raw = ptr.readByteArray(96);
    if (!raw) return " " + label + "=<unreadable>";
    const bytes = new Uint8Array(raw);
    let printable = 0, nul = 0, high = 0;
    for (let i = 0; i < bytes.length; i++) {
      const b = bytes[i];
      if (b >= 0x20 && b <= 0x7e) printable++;
      if (b === 0) nul++;
      if (b >= 0x80) high++;
    }
    const words = [];
    for (let off = 0; off < 32; off += 4) {
      words.push("w" + off + "=" + u32be(bytes, off).toString(16));
    }
    return " " + label + "=" + objectLabel(label, ptr)
      + " printable=" + (printable / bytes.length).toFixed(2)
      + " nulls=" + (nul / bytes.length).toFixed(2)
      + " high=" + (high / bytes.length).toFixed(2)
      + " " + words.join(",");
  } catch (e) {
    return " " + label + "=<shape-failed:" + e + ">";
  }
}
function backtraceShape(context) {
  try {
    return Thread.backtrace(context, Backtracer.ACCURATE).slice(0, 10).map(function(addr) {
      const sym = DebugSymbol.fromAddress(addr);
      let mod = null;
      try { mod = Process.findModuleByAddress(addr); } catch (e) { mod = null; }
      const off = mod ? addr.sub(mod.base) : ptr(0);
      const name = sym && sym.name ? sym.name : "?";
      const moduleName = mod ? mod.name : "?";
      return moduleName + "+0x" + off.toString(16) + ":" + name;
    }).join(" <- ");
  } catch (e) {
    return "<backtrace-failed:" + e + ">";
  }
}
function installNativeSymbolShapeHooks(){
  if (nativeSymbolHooksInstalled) return;
  const findExport = Module.findGlobalExportByName
    ? function(name) { return Module.findGlobalExportByName(name); }
    : function(name) { return Module.findExportByName(null, name); };
  function findNative(name) {
    let ptr = null;
    try { ptr = findExport(name); } catch (e) { ptr = null; }
    if (ptr) return ptr;
    try {
      const module = Process.getModuleByName("libezstreamclient.so");
      if (module && module.findExportByName) return module.findExportByName(name);
    } catch (e) {}
    try {
      const module = Process.getModuleByName("libezstreamclient.so");
      const matches = module.enumerateExports().filter(function(e) { return e.name === name; });
      if (matches.length) return matches[0].address;
    } catch (e) {}
    return null;
  }
  let installed = 0;
  const chipCreateReq = "_ZN11CChipParser22CreateDirectConnectReqEPcPKcPS0_iS2_iS2_";
  const chipPtr = findNative(chipCreateReq);
  if (chipPtr) {
    installed++;
    Interceptor.attach(chipPtr, {
      onEnter(args) {
        this.outBuf = args[1];
        console.log("[native-symbol] CChipParser.CreateDirectConnectReq enter"
          + " this=" + args[0]
          + " outBuf=" + args[1]
          + cstrShape("clientId", args[2], 2048)
          + " signList=" + args[3]
          + " signCount=" + argInt(args, 4)
          + cstrShape("singleSign", args[5], 2048)
          + " business=" + argInt(args, 6)
          + cstrShape("url", args[7], 2048)
          + " bt=" + backtraceShape(this.context));
      },
      onLeave(retval) {
        let outShape = "";
        try {
          if (this.outBuf && !this.outBuf.isNull()) {
            outShape = cstrShape("out", this.outBuf, 4096);
          }
        } catch (e) {
          outShape = " out=<read-failed:" + e + ">";
        }
        console.log("[native-symbol] CChipParser.CreateDirectConnectReq ret=" + retval.toInt32() + outShape);
      }
    });
  } else {
    console.log("[native-symbol] CChipParser.CreateDirectConnectReq export not found");
  }
  const setupReq = "_ZN11CChipParser28CreateSetupRealtimeStreamReqEPcPKciibRK24CTRL_P2P_SETUP_REQ_PARAM";
  const setupReqPtr = findNative(setupReq);
  if (setupReqPtr) {
    installed++;
    Interceptor.attach(setupReqPtr, {
      onEnter(args) {
        this.outBuf = args[1];
        console.log("[native-symbol] CChipParser.CreateSetupRealtimeStreamReq enter"
          + " this=" + args[0]
          + " outBuf=" + args[1]
          + cstrShape("operationCode", args[2], 128)
          + " channel=" + argInt(args, 3)
          + " streamType=" + argInt(args, 4)
          + " isEncrypt=" + argInt(args, 5)
          + setupReqParamShape(args[6])
          + " bt=" + backtraceShape(this.context));
      },
      onLeave(retval) {
        let outShape = "";
        try {
          if (this.outBuf && !this.outBuf.isNull()) {
            outShape = cstrShape("out", this.outBuf, 4096);
          }
        } catch (e) {
          outShape = " out=<read-failed:" + e + ">";
        }
        console.log("[native-symbol] CChipParser.CreateSetupRealtimeStreamReq ret=" + retval.toInt32() + outShape);
      }
    });
  } else {
    console.log("[native-symbol] CChipParser.CreateSetupRealtimeStreamReq export not found");
  }
  [
    ["EcdhEncrypt.enc", "_ZN11EcdhEncrypt3encEPKciRNSt6__ndk112basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEE"],
    ["EcdhEncrypt.dec", "_ZN11EcdhEncrypt3decEPKciRNSt6__ndk112basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEE"],
    ["BavEcdhEncrypt.enc", "_ZN14BavEcdhEncrypt3encEPKciRNSt6__ndk112basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEE"],
    ["BavEcdhEncrypt.dec", "_ZN14BavEcdhEncrypt3decEPKciRNSt6__ndk112basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEE"],
  ].forEach(function(spec) {
    const ptr = findNative(spec[1]);
    if (!ptr) {
      console.log("[native-symbol] " + spec[0] + " export not found");
      return;
    }
    installed++;
    Interceptor.attach(ptr, {
      onEnter(args) {
        const len = args[2].toInt32();
        console.log("[native-symbol] " + spec[0] + " enter inputLen=" + len + (len > 0 ? bodyShape(new Uint8Array(args[1].readByteArray(Math.min(len, 1024))), 0, Math.min(len, 1024)) : ""));
      },
      onLeave(retval) {
        console.log("[native-symbol] " + spec[0] + " ret=" + retval.toInt32());
      }
    });
  });
  [
    ["CMbedtlsClient.Ctor", "_ZN14CMbedtlsClientC1Ev", "mbed"],
    ["CMbedtlsClient.CreateCtx", "_ZN14CMbedtlsClient9CreateCtxEv", "mbed"],
    ["CMbedtlsClient.Connect", "_ZN14CMbedtlsClient7ConnectEPKcS1_i", "mbed"],
    ["CMbedtlsClient.TCPConnect", "_ZN14CMbedtlsClient10TCPConnectEPKcjbii", "mbed"],
    ["CMbedtlsClient.BindSSL", "_ZN14CMbedtlsClient7BindSSLEPKcS1_i", "mbed"],
    ["ssl_tcp_parser.Ctor", "_ZN14ssl_tcp_parserC1Ev", "parser"],
    ["ssl_tcp_parser.GenerateSSLPacket", "_ZN14ssl_tcp_parser17GenerateSSLPacketEPcPiPKciP16MBEDTLS_MSG_INFO", "parser"],
    ["CCtrlClient.Ctor", "_ZN11CCtrlClientC1Ev", "ctrl"],
    ["CCtrlClient.Init", "_ZN11CCtrlClient4InitEiPFiiPviS0_S0_S0_S0_EPFiiS0_iPciiES0_i14ST_STREAM_INFOt", "ctrl"],
    ["DirectClient.Ctor", "_ZN13ez_stream_sdk12DirectClientC1EPNS_15EZClientManagerEP10INIT_PARAMPNS_19EZStreamClientProxyE16_tagCLIENT_TYPES", "direct"],
    ["DirectClient.init", "_ZN13ez_stream_sdk12DirectClient4initEv", "direct"],
    ["EZMediaBase.setSecretKey", "_ZN13ez_stream_sdk11EZMediaBase12setSecretKeyENSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE", "media"],
    ["EZMediaBase.getSecretKey", "_ZN13ez_stream_sdk11EZMediaBase12getSecretKeyERNSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE", "media"],
  ].forEach(function(spec) {
    const ptr = findNative(spec[1]);
    if (!ptr) {
      console.log("[native-object] " + spec[0] + " export not found");
      return;
    }
    installed++;
    Interceptor.attach(ptr, {
      onEnter(args) {
        this.obj = objectLabel(spec[2], args[0]);
        let extra = "";
        if (spec[0] === "ssl_tcp_parser.GenerateSSLPacket") {
          try {
            const inputLen = args[4].toInt32();
            pushThreadState("generatePacket", {obj: this.obj, ptr: args[0], out: args[1], outLenPtr: args[2], input: args[3], msgInfo: args[5], len: inputLen});
            extra = " inputLen=" + inputLen
              + pointerShape("out", args[1])
              + pointerShape("outLenPtr", args[2])
              + pointerShape("input", args[3])
              + pointerShape("msgInfo", args[5])
              + (inputLen > 0 && !args[3].isNull() ? bodyShape(new Uint8Array(args[3].readByteArray(Math.min(inputLen, 1024))), 0, Math.min(inputLen, 1024)) : "");
          } catch (e) {
            extra = " generateShape=<failed:" + e + ">";
          }
        } else if (spec[0] === "CCtrlClient.Init") {
          try {
            this.ctrlPtr = args[0];
            this.initStreamInfo = this.context.sp.add(8);
            extra = " initMode=" + args[1].toInt32()
              + streamInfoInitShape("initStreamInfo", this.initStreamInfo);
          } catch (e) {
            extra = " initShape=<failed:" + e + ">";
          }
        }
        console.log("[native-object] " + spec[0] + " enter obj=" + this.obj + extra);
      },
      onLeave(retval) {
        if (spec[0] === "ssl_tcp_parser.GenerateSSLPacket") popThreadState("generatePacket");
        let extra = "";
        if (spec[0] === "CCtrlClient.Init") {
          try {
            const ctrlKey = this.ctrlPtr.add(0x50);
            extra = secretBinaryShape("ctrlPlus0x50", ctrlKey, 16)
              + (this.initStreamInfo ? sameBinaryFingerprint("ctrlPlus0x50MatchesInitStack", this.initStreamInfo.add(0x158), ctrlKey, 16) : "");
          } catch (e) {
            extra = " initLeaveShape=<failed:" + e + ">";
          }
        }
        console.log("[native-object] " + spec[0] + " leave obj=" + this.obj + " ret=" + retval + extra);
      }
    });
  });
  [
    ["ezstream_startPreview", "_Z21ezstream_startPreviewPv"],
    ["DirectClient.startPreview", "_ZN13ez_stream_sdk12DirectClient12startPreviewEv"],
    ["HCNetSDKClient.startPreview", "_ZN13ez_stream_sdk14HCNetSDKClient12startPreviewEv"],
    ["EZStreamClientProxy.startPreview", "_ZN13ez_stream_sdk19EZStreamClientProxy12startPreviewEv"],
    ["CCtrlClient.CtrlSendPlay", "_ZN11CCtrlClient12CtrlSendPlayEv"],
    ["CCtrlClient.SendInviteStream", "_ZN11CCtrlClient16SendInviteStreamEPciP14ST_STREAM_INFO"],
    ["CCtrlClient.SendRequest", "_ZN11CCtrlClient11SendRequestEv"],
  ].forEach(function(spec) {
    const ptr = findNative(spec[1]);
    if (!ptr) {
      console.log("[native-symbol] " + spec[0] + " export not found");
      return;
    }
    installed++;
    Interceptor.attach(ptr, {
      onEnter(args) {
        this.obj = objectLabel(spec[0].split(".")[0].toLowerCase(), args[0]);
        let extra = "";
        if (spec[0] === "CCtrlClient.SendInviteStream") {
          const reqLen = argInt(args, 2);
          const streamInfo = args[3];
          pushThreadState("sendInviteStream", {
            obj: this.obj,
            ptr: args[0],
            req: args[1],
            reqLen: reqLen,
            streamInfo: streamInfo
          });
          extra = " reqPtr=" + args[1]
            + " reqLen=" + reqLen
            + (reqLen > 0 && !args[1].isNull() ? bodyShape(new Uint8Array(args[1].readByteArray(Math.min(reqLen, 1024))), 0, Math.min(reqLen, 1024)) : "")
            + streamInfoPointerShape("streamInfo", streamInfo)
            + " bt=" + backtraceShape(this.context);
        }
        if (spec[0] === "CCtrlClient.SendRequest") pushThreadState("ctrlSendRequest", {obj: this.obj, ptr: args[0]});
        console.log("[native-symbol] " + spec[0] + " enter obj=" + this.obj + extra);
      },
      onLeave(retval) {
        if (spec[0] === "CCtrlClient.SendInviteStream") popThreadState("sendInviteStream");
        if (spec[0] === "CCtrlClient.SendRequest") popThreadState("ctrlSendRequest");
        console.log("[native-symbol] " + spec[0] + " leave obj=" + this.obj + " ret=" + retval);
      }
    });
  });
  const tcpSendWaitPtr = findNative("_ZN14CMbedtlsClient11TCPSendWaitEiPKcS1_iiPcPiS3_i");
  if (tcpSendWaitPtr) {
    installed++;
    Interceptor.attach(tcpSendWaitPtr, {
      onEnter(args) {
        this.obj = objectLabel("mbed", args[0]);
        const lenA = args[4].toInt32();
        const lenB = args[5].toInt32();
        const tailLen = args[9].toInt32();
        pushThreadState("tcpSendWait", {
          obj: this.obj,
          ptr: args[0],
          inA: args[2],
          inB: args[3],
          out: args[6],
          outLenPtr: args[7],
          tail: args[8],
          lenA: lenA,
          lenB: lenB,
          tailLen: tailLen
        });
        console.log("[native-symbol] CMbedtlsClient.TCPSendWait enter obj=" + this.obj
          + " mode=" + args[1].toInt32()
          + " lenA=" + lenA + (lenA > 0 && !args[2].isNull() ? bodyShape(new Uint8Array(args[2].readByteArray(Math.min(lenA, 1024))), 0, Math.min(lenA, 1024)) : "")
          + " lenB=" + lenB + (lenB > 0 && !args[3].isNull() ? bodyShape(new Uint8Array(args[3].readByteArray(Math.min(lenB, 1024))), 0, Math.min(lenB, 1024)) : "")
          + " tailLen=" + tailLen
          + pointerShape("out", args[6])
          + pointerShape("outLenPtr", args[7])
          + pointerShape("tail", args[8]));
      },
      onLeave(retval) {
        popThreadState("tcpSendWait");
        console.log("[native-symbol] CMbedtlsClient.TCPSendWait leave obj=" + this.obj + " ret=" + retval);
      }
    });
  } else {
    console.log("[native-symbol] CMbedtlsClient.TCPSendWait export not found");
  }
  const getDevInfoPtr = findNative("_ZN13ez_stream_sdk15EZClientManager10getDevInfoERKNSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEER11ST_DEV_INFO");
  if (getDevInfoPtr) {
    installed++;
    Interceptor.attach(getDevInfoPtr, {
      onEnter(args) {
        this.devInfo = args[2];
        console.log("[native-symbol] EZClientManager.getDevInfo enter outDevInfo=" + objectLabel("devInfo", this.devInfo));
      },
      onLeave(retval) {
        console.log("[native-symbol] EZClientManager.getDevInfo leave ret=" + retval.toInt32()
          + secretBinaryShape("outDevInfoPlus0xc0", this.devInfo.add(0xc0), 16)
          + secretShape("outDevInfoPlus0xc0String", this.devInfo.add(0xc0)));
      }
    });
  } else {
    console.log("[native-symbol] EZClientManager.getDevInfo export not found");
  }
  const getCasStreamInfoPtr = findNative("_ZN13ez_stream_sdk9CasClient17getCASStreamInforEP11ST_DEV_INFOP10INIT_PARAMR14ST_STREAM_INFO16_tagCLIENT_TYPES");
  if (getCasStreamInfoPtr) {
    installed++;
    Interceptor.attach(getCasStreamInfoPtr, {
      onEnter(args) {
        this.devInfo = args[0];
        this.initParam = args[1];
        this.streamInfo = args[2];
        console.log("[native-symbol] CasClient.getCASStreamInfor enter"
          + " devInfo=" + objectLabel("devInfo", this.devInfo)
          + " streamInfo=" + objectLabel("streamInfo", this.streamInfo)
          + " clientType=" + args[3].toInt32()
          + secretBinaryShape("devInfoPlus0xc0", this.devInfo.add(0xc0), 16)
          + secretShape("devInfoPlus0xc0String", this.devInfo.add(0xc0)));
      },
      onLeave(retval) {
        console.log("[native-symbol] CasClient.getCASStreamInfor leave ret=" + retval.toInt32()
          + secretBinaryShape("streamInfoPlus0x158", this.streamInfo.add(0x158), 16)
          + sameBinaryFingerprint("streamInfoPlus0x158MatchesDevInfoPlus0xc0", this.streamInfo.add(0x158), this.devInfo.add(0xc0), 16));
      }
    });
  } else {
    console.log("[native-symbol] CasClient.getCASStreamInfor export not found");
  }
  [
    ["ssl_tcp_parser.SetEncryptType", "_ZN14ssl_tcp_parser14SetEncryptTypeE15tag_ENCYPT_MODE"],
    ["ssl_tcp_parser.GetEncryptMsg", "_ZN14ssl_tcp_parser13GetEncryptMsgEv"],
    ["ssl_tcp_parser.GetMsgTailReq", "_ZN14ssl_tcp_parser13GetMsgTailReqEv"],
    ["ssl_tcp_parser.GetRspXmlLen", "_ZN14ssl_tcp_parser12GetRspXmlLenEv"],
  ].forEach(function(spec) {
    const ptr = findNative(spec[1]);
    if (!ptr) {
      console.log("[native-symbol] " + spec[0] + " export not found");
      return;
    }
    installed++;
    try {
    Interceptor.attach(ptr, {
      onEnter(args) {
        this.obj = objectLabel("parser", args[0]);
        if (spec[0] === "ssl_tcp_parser.SetEncryptType") {
          console.log("[native-symbol] " + spec[0] + " obj=" + this.obj + " mode=" + args[1].toInt32());
        } else {
          console.log("[native-symbol] " + spec[0] + " enter obj=" + this.obj);
        }
      },
      onLeave(retval) {
        console.log("[native-symbol] " + spec[0] + " leave obj=" + this.obj + " ret=" + retval);
      }
    });
    } catch (e) {
      console.log("[native-symbol] " + spec[0] + " hook failed " + e);
    }
  });
  [
    ["CCtrlClient.CtrlSendSetup", "_ZN11CCtrlClient13CtrlSendSetupEPciS0_iS0_iRi", [[1,2],[3,4],[5,6]]],
    ["CRecvClient.SendTCPCtrlReq", "_ZN11CRecvClient14SendTCPCtrlReqEPKci", [[1,2]]],
    ["CRecvClient.SendUDPCtrlReq", "_ZN11CRecvClient14SendUDPCtrlReqEPKci", [[1,2]]],
    ["CMbedtlsClient.TCPSendMsg", "_ZN14CMbedtlsClient10TCPSendMsgEPcij", [[1,2]]],
    ["CMbedtlsClient.TCPSendSSLMsg", "_ZN14CMbedtlsClient13TCPSendSSLMsgEPKcjP16MBEDTLS_MSG_INFOS3_S1_bii", [[1,2]]],
    ["ssl_tcp_parser.EncryptMsg", "_ZN14ssl_tcp_parser10EncryptMsgEPKcS1_i15tag_ENCYPT_MODE", [[1,3]]],
  ].forEach(function(spec) {
    const ptr = findNative(spec[1]);
    if (!ptr) {
      console.log("[native-symbol] " + spec[0] + " export not found");
      return;
    }
    installed++;
    Interceptor.attach(ptr, {
      onEnter(args) {
        this.obj = objectLabel(spec[0].split(".")[0].toLowerCase(), args[0]);
        let parts = [];
        spec[2].forEach(function(pair, idx) {
          try {
            const len = args[pair[1]].toInt32();
            const ptrArg = args[pair[0]];
            parts.push("buf" + idx + "Len=" + len + (len > 0 && !ptrArg.isNull() ? bodyShape(new Uint8Array(ptrArg.readByteArray(Math.min(len, 1024))), 0, Math.min(len, 1024)) : ""));
          } catch (e) {
            parts.push("buf" + idx + "=<failed:" + e + ">");
          }
        });
        if (spec[0] === "ssl_tcp_parser.EncryptMsg") {
          pushThreadState("encrypt", {obj: this.obj, ptr: args[0], src: args[1], dst: args[2], len: args[3].toInt32()});
        } else if (spec[0] === "CMbedtlsClient.TCPSendSSLMsg") {
          pushThreadState("sslSend", {obj: this.obj, ptr: args[0], msgInfo1: args[3], msgInfo2: args[4], aux: args[5]});
          parts.push(pointerShape("msgInfo1", args[3]));
          parts.push(pointerShape("msgInfo2", args[4]));
          parts.push("auxLen=" + cstrLen(args[5]) + secretBinaryShape("aux16", args[5], 16));
          parts.push("bt=" + backtraceShape(this.context));
        }
        console.log("[native-symbol] " + spec[0] + " enter obj=" + this.obj + " " + parts.join(" "));
      },
      onLeave(retval) {
        if (spec[0] === "ssl_tcp_parser.EncryptMsg") popThreadState("encrypt");
        if (spec[0] === "CMbedtlsClient.TCPSendSSLMsg") popThreadState("sslSend");
        console.log("[native-symbol] " + spec[0] + " leave obj=" + this.obj + " ret=" + retval);
      }
    });
  });
  [
    ["CRecvClient.SetEncryptKey", "_ZN11CRecvClient13SetEncryptKeyEPKc", 1],
    ["CRecvClient.SetDevSerial", "_ZN11CRecvClient12SetDevSerialEPKc", 1],
  ].forEach(function(spec) {
    const ptr = findNative(spec[1]);
    if (!ptr) {
      console.log("[native-symbol] " + spec[0] + " export not found");
      return;
    }
    installed++;
    Interceptor.attach(ptr, {
      onEnter(args) {
        this.obj = objectLabel("recv", args[0]);
        const label = spec[0] === "CRecvClient.SetEncryptKey" ? "recvEncryptKey" : "devSerial";
        if (label === "recvEncryptKey") {
          const value = boundedCString(args[spec[2]], 128);
          console.log("[native-symbol] " + spec[0] + " enter obj=" + this.obj
            + secretShape("key", args[spec[2]])
            + (value ? rememberSecret("recvEncryptKey", value) : ""));
        } else {
          console.log("[native-symbol] " + spec[0] + " enter obj=" + this.obj + " len=" + cstrLen(args[spec[2]]));
        }
      },
      onLeave(retval) {
        console.log("[native-symbol] " + spec[0] + " leave obj=" + this.obj + " ret=" + retval);
      }
    });
  });
  [
    ["SendDataToDev", "_Z13SendDataToDevPKciS0_iiS0_PcPii", [
      [0, 0], [1, -1], [2, 0], [3, -1], [4, -1], [5, 16], [6, 0], [7, 0], [8, -1]
    ]],
    ["SendTransferDataToCAS", "_Z21SendTransferDataToCASPKciS0_iiS0_S0_S0_PcPiS0_ib", [
      [0, 0], [1, -1], [2, 0], [3, -1], [4, -1], [5, 0], [6, 16], [7, 0], [8, 0], [9, 0], [10, -1], [11, -1]
    ]],
    ["multi_sslconn_send_msg", "multi_sslconn_send_msg", [[0, 1], [2, 0], [3, 0], [4, 16]]],
    ["CASClient_GetDevPermanentKey", "CASClient_GetDevPermanentKey", [[0, 0], [1, 0], [2, 0], [3, 0]]],
    ["CGlobalInfo.SetClientPublicAndPrivateKey", "_ZN11CGlobalInfo28SetClientPublicAndPrivateKeyEP20ST_ECDH_ENCRYPT_INFO", [[1, 0]]],
    ["CGlobalInfo.GetClientPublicKey", "_ZN11CGlobalInfo18GetClientPublicKeyEv", []],
    ["CGlobalInfo.GetClientPrivateKey", "_ZN11CGlobalInfo19GetClientPrivateKeyEv", []],
    ["CGlobalInfo.GetClientId", "_ZN11CGlobalInfo11GetClientIdEv", []],
    ["CGlobalInfo.GetAppLocalIP", "_ZN11CGlobalInfo13GetAppLocalIPEv", []],
    ["CGlobalInfo.GetCntNatIp", "_ZN11CGlobalInfo11GetCntNatIpEPc", [[1, 0]]],
    ["CGlobalInfo.GetCntNatPort", "_ZN11CGlobalInfo13GetCntNatPortEv", []],
    ["CGlobalInfo.BorrowBasePort", "_ZN11CGlobalInfo14BorrowBasePortEv", []],
    ["CGlobalInfo.ReturnBasePort", "_ZN11CGlobalInfo14ReturnBasePortEi", [[1, -1]]],
    ["ECDHCryption_SetPBKeyAndPRKey", "ECDHCryption_SetPBKeyAndPRKey", [[0, 0], [1, 0], [2, 0]]],
    ["ECDHCryption_SetSessionEncKey", "ECDHCryption_SetSessionEncKey", [[0, 0], [1, 0], [2, 0]]],
    ["ECDHCryption_SaveMTKey", "ECDHCryption_SaveMTKey", [[0, 0], [1, 0], [2, 0]]],
    ["ECDHCryption_GetMTKey", "ECDHCryption_GetMTKey", [[0, 0], [1, 0], [2, 0]]],
    ["ECDHCryption_GenerateSessionKey", "ECDHCryption_GenerateSessionKey", [[0, 0], [1, 0], [2, 0], [3, 0]]],
    ["ECDHCryption_GenerateMasterKey", "ECDHCryption_GenerateMasterKey", [[0, 0], [1, 0], [2, 0], [3, 0]]],
  ].forEach(function(spec) {
    const ptr = findNative(spec[1]);
    if (!ptr) {
      console.log("[native-symbol] " + spec[0] + " export not found");
      return;
    }
    installed++;
    Interceptor.attach(ptr, {
      onEnter(args) {
        this.label = spec[0];
        this.arg0 = args[0];
        this.arg1 = args[1];
        const parts = [];
        const bt = backtraceShape(this.context);
        if (spec[0] === "CGlobalInfo.GetClientId" && bt.indexOf("SendKeeplive") >= 0) {
          this.skipLog = true;
          return;
        }
        spec[2].forEach(function(pair, idx) {
          const argIndex = pair[0];
          const fixedLen = pair[1];
          try {
            if (fixedLen > 0) {
              parts.push(secretBinaryShape("arg" + argIndex, args[argIndex], fixedLen));
            } else if (fixedLen < 0) {
              parts.push(" arg" + argIndex + "=" + args[argIndex].toInt32());
            } else {
              parts.push(pointerShape("arg" + argIndex, args[argIndex]));
            }
          } catch (e) {
            parts.push(" arg" + argIndex + "=<failed:" + e + ">");
          }
        });
        if (spec[0] === "SendDataToDev") {
          const ctrl = peekThreadState("ctrlSendRequest");
          if (ctrl) {
            const keyPtr = ctrl.ptr.add(0x50);
            parts.push(" ctrl=" + ctrl.obj);
            parts.push(samePointer("arg5IsCtrlPlus0x50", args[5], keyPtr));
            parts.push(secretBinaryShape("ctrlPlus0x50", keyPtr, 16));
          }
          const invite = peekThreadState("sendInviteStream");
          if (invite) {
            parts.push(" invite=" + invite.obj);
            parts.push(samePointer("arg2IsInviteReq", args[2], invite.req));
            parts.push(" inviteReqLen=" + invite.reqLen);
            parts.push(streamInfoPointerShape("inviteStreamInfo", invite.streamInfo));
          }
        }
        console.log("[native-keypath] " + spec[0] + " enter " + parts.join(" ") + " bt=" + bt);
      },
      onLeave(retval) {
        if (this.skipLog) return;
        let extra = "";
        try {
          if (spec[0] === "CGlobalInfo.GetClientPublicKey") {
            extra = globalInfoClientKeyShape("public", this.arg0, this.arg1, 0x19c, "clientPublicKey");
          } else if (spec[0] === "CGlobalInfo.GetClientPrivateKey") {
            extra = globalInfoClientKeyShape("private", this.arg0, this.arg1, 0x1a8, "clientPrivateKey");
          } else if (isNonNullPointer(retval) && spec[0].indexOf("GetClient") >= 0) extra = pointerShape("ret", retval) + cstrShape("retString", retval, 4096) + libcppStringShape("retStdString", retval);
          else if (isNonNullPointer(retval) && spec[0] === "CGlobalInfo.GetAppLocalIP") extra = pointerShape("ret", retval) + cstrShape("retString", retval, 256) + libcppStringShape("retStdString", retval);
          else extra = " ret=" + retval;
        } catch (e) {
          extra = " ret=<failed:" + e + ">";
        }
        console.log("[native-keypath] " + this.label + " leave" + extra);
      }
    });
  });
  [
    ["Encrypt.enc.string", "_ZN7Encrypt3encERKNSt6__ndk112basic_stringIcNS0_11char_traitsIcEENS0_9allocatorIcEEEERS6_"],
    ["Encrypt.dec.string", "_ZN7Encrypt3decERKNSt6__ndk112basic_stringIcNS0_11char_traitsIcEENS0_9allocatorIcEEEERS6_"],
    ["Aes128CbcEncrypt_PKCS5", "_Z22Aes128CbcEncrypt_PKCS5RNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEPKc"],
    ["Aes128CbcDecrypt_PKCS5", "_Z22Aes128CbcDecrypt_PKCS5RNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEPKc"],
    ["EcdhEncrypt.init", "_ZN11EcdhEncrypt4initERKNSt6__ndk112basic_stringIcNS0_11char_traitsIcEENS0_9allocatorIcEEEES8_"],
  ].forEach(function(spec) {
    const ptr = findNative(spec[1]);
    if (!ptr) {
      console.log("[native-symbol] " + spec[0] + " export not found");
      return;
    }
    installed++;
    Interceptor.attach(ptr, {
      onEnter(args) {
        const enc = peekThreadState("encrypt");
        let suffix = "";
        if (spec[0].indexOf("Aes128Cbc") === 0) {
          const info = secretBinaryInfo(args[1], 16);
          const sslSend = peekThreadState("sslSend");
          const generated = peekThreadState("generatePacket");
          const tcpSendWait = peekThreadState("tcpSendWait");
          suffix = info.text.replace("{label}", "aux16")
            + (enc ? scanPointerForFingerprint("parserObj", enc.ptr, info.fp, 768) : "")
            + (sslSend ? scanPointerForFingerprint("mbedObj", sslSend.ptr, info.fp, 768) + scanPointerForFingerprint("msgInfo1", sslSend.msgInfo1, info.fp, 512) + scanPointerForFingerprint("msgInfo2", sslSend.msgInfo2, info.fp, 512) + scanPointerForFingerprint("aux", sslSend.aux, info.fp, 160) : "")
            + (tcpSendWait ? scanPointerForFingerprint("waitMbedObj", tcpSendWait.ptr, info.fp, 768) + scanPointerForFingerprint("waitInA", tcpSendWait.inA, info.fp, Math.min(tcpSendWait.lenA, 1024)) + scanPointerForFingerprint("waitInB", tcpSendWait.inB, info.fp, Math.min(tcpSendWait.lenB, 1024)) + scanPointerForFingerprint("waitOut", tcpSendWait.out, info.fp, 512) + scanPointerForFingerprint("waitTail", tcpSendWait.tail, info.fp, Math.min(tcpSendWait.tailLen, 512)) : "")
            + (generated ? scanPointerForFingerprint("genParserObj", generated.ptr, info.fp, 768) + scanPointerForFingerprint("genOut", generated.out, info.fp, 512) + scanPointerForFingerprint("genInput", generated.input, info.fp, 512) + scanPointerForFingerprint("genMsgInfo", generated.msgInfo, info.fp, 512) : "")
            + " bt=" + backtraceShape(this.context);
        }
        console.log("[native-symbol] " + spec[0] + " enter" + (enc ? " parser=" + enc.obj + " plainLen=" + enc.len : "") + suffix);
      },
      onLeave(retval) {
        console.log("[native-symbol] " + spec[0] + " leave ret=" + retval);
      }
    });
  });
  [
    ["mbedtls_aes_setkey_enc", "enc"],
    ["mbedtls_aes_setkey_dec", "dec"],
  ].forEach(function(spec) {
    const ptr = findNative(spec[0]);
    if (!ptr) {
      console.log("[native-symbol] " + spec[0] + " export not found");
      return;
    }
    installed++;
    Interceptor.attach(ptr, {
      onEnter(args) {
        this.logged = false;
        if (!peekThreadState("encrypt")) return;
        this.logged = true;
        const bits = args[2].toInt32();
        const keyLen = Math.max(0, Math.min(64, Math.floor(bits / 8)));
        const keyInfo = secretBinaryInfo(args[1], keyLen);
        console.log("[native-symbol] " + spec[0] + " enter"
          + rememberAesContext(args[0], keyInfo, bits, spec[1])
          + keyInfo.text.replace("{label}", "key"));
      },
      onLeave(retval) {
        if (!this.logged) return;
        console.log("[native-symbol] " + spec[0] + " leave ret=" + retval.toInt32());
      }
    });
  });
  const aesCbcPtr = findNative("mbedtls_aes_crypt_cbc");
  if (aesCbcPtr) {
    installed++;
    Interceptor.attach(aesCbcPtr, {
      onEnter(args) {
        this.logged = false;
        const enc = peekThreadState("encrypt");
        if (!enc) return;
        this.logged = true;
        const mode = args[1].toInt32();
        const len = args[2].toInt32();
        const ivInfo = secretBinaryInfo(args[3], 16);
        if (DUMP_LOCAL_AES_RAW && mode === 1 && len > 0 && len <= 1024 && !args[4].isNull()) {
          try {
            const bytes = new Uint8Array(args[4].readByteArray(Math.min(len, 1024)));
            const shape = bodyShape(bytes, 0, bytes.length);
            if (shape.indexOf("tags=Request,") >= 0) {
              const ctxInfo = aesContextInfo(args[0]) || {};
              console.log("[local-aes-raw-json] " + JSON.stringify({
                keyId: ctxInfo.keyId || "",
                keyHex: ctxInfo.hex || "",
                ivHex: hexBytes(args[3], 16),
                len: len,
                inputHex: hexBytes(args[4], len),
                shape: shape,
              }));
            }
          } catch (e) {
            console.log("[local-aes-raw-json] " + JSON.stringify({ error: String(e) }));
          }
        }
        const generated = peekThreadState("generatePacket");
        const tcpSendWait = peekThreadState("tcpSendWait");
        console.log("[native-symbol] mbedtls_aes_crypt_cbc enter"
          + aesContextShape(args[0])
          + " mode=" + mode
          + " len=" + len
          + ivInfo.text.replace("{label}", "iv")
          + (len > 0 && !args[4].isNull() ? bodyShape(new Uint8Array(args[4].readByteArray(Math.min(len, 1024))), 0, Math.min(len, 1024)) : "")
          + (enc ? " parser=" + enc.obj : "")
          + (generated ? " generated=" + generated.obj : "")
          + (tcpSendWait ? " tcpSendWait=" + tcpSendWait.obj : ""));
      },
      onLeave(retval) {
        if (!this.logged) return;
        console.log("[native-symbol] mbedtls_aes_crypt_cbc leave ret=" + retval.toInt32());
      }
    });
  } else {
    console.log("[native-symbol] mbedtls_aes_crypt_cbc export not found");
  }
  if (installed) {
    nativeSymbolHooksInstalled = true;
    console.log("[native-symbol] installed count=" + installed);
  } else {
    console.log("[native-symbol] no symbol hooks installed yet");
  }
}
function installNativeSocketHooks(){
  const findExport = Module.findGlobalExportByName
    ? function(name) { return Module.findGlobalExportByName(name); }
    : function(name) { return Module.findExportByName(null, name); };
  const connectPtr = findExport("connect");
  if (connectPtr) {
    Interceptor.attach(connectPtr, {
      onEnter(args) {
        this.fd = args[0].toInt32();
        this.peer = readSockaddr(args[1], args[2].toInt32());
      },
      onLeave(retval) {
        if (!this.peer || !shouldLogPeer(this.peer)) return;
        const ret = retval.toInt32();
        fdPeers.set(this.fd, this.peer);
        console.log(`[native-connect] fd=${this.fd} ${this.peer.host}:${this.peer.port} ret=${ret}`);
      }
    });
  } else {
    console.log("[native-connect] connect export not found");
  }

  const bindPtr = findExport("bind");
  if (bindPtr) {
    Interceptor.attach(bindPtr, {
      onEnter(args) {
        this.fd = args[0].toInt32();
        this.addr = readSockaddr(args[1], args[2].toInt32());
      },
      onLeave(retval) {
        if (!shouldLogLocalSockaddr(this.addr)) return;
        fdLocalAddrs.set(this.fd, this.addr);
        console.log("[native-bind] fd=" + this.fd + " " + this.addr.host + ":" + this.addr.port + " ret=" + retval.toInt32());
      }
    });
  } else {
    console.log("[native-bind] bind export not found");
  }

  const listenPtr = findExport("listen");
  if (listenPtr) {
    Interceptor.attach(listenPtr, {
      onEnter(args) {
        this.fd = args[0].toInt32();
        this.backlog = args[1].toInt32();
      },
      onLeave(retval) {
        const addr = fdLocalAddrs.get(this.fd);
        if (!shouldLogLocalSockaddr(addr)) return;
        console.log("[native-listen] fd=" + this.fd + " " + addr.host + ":" + addr.port + " backlog=" + this.backlog + " ret=" + retval.toInt32());
      }
    });
  } else {
    console.log("[native-listen] listen export not found");
  }

  ["accept", "accept4"].forEach(function(name) {
    const ptr = findExport(name);
    if (!ptr) return;
    Interceptor.attach(ptr, {
      onEnter(args) {
        this.fd = args[0].toInt32();
        this.addrPtr = args[1];
        this.addrLenPtr = args[2];
      },
      onLeave(retval) {
        const local = fdLocalAddrs.get(this.fd);
        const newFd = retval.toInt32();
        let peer = null;
        try {
          if (newFd >= 0 && this.addrPtr && !this.addrPtr.isNull() && this.addrLenPtr && !this.addrLenPtr.isNull()) {
            peer = readSockaddr(this.addrPtr, this.addrLenPtr.readS32());
          }
        } catch (e) {
          peer = null;
        }
        if (!shouldLogLocalSockaddr(local) && !shouldLogLocalSockaddr(peer)) return;
        if (peer && newFd >= 0) fdPeers.set(newFd, peer);
        const localText = local ? local.host + ":" + local.port : "<unknown>";
        const peerText = peer ? peer.host + ":" + peer.port : "<unknown>";
        console.log("[native-" + name + "] fd=" + this.fd + " local=" + localText + " newFd=" + newFd + " peer=" + peerText);
      }
    });
  });

  ["close", "shutdown"].forEach(function(name) {
    const ptr = findExport(name);
    if (!ptr) return;
    Interceptor.attach(ptr, {
      onEnter(args) {
        const fd = args[0].toInt32();
        const peer = fdPeers.get(fd);
        if (peer) console.log(`[native-${name}] fd=${fd} ${peer.host}:${peer.port}`);
        fdPeers.delete(fd);
      }
    });
  });
  [
    ["send", 1, 2],
    ["write", 1, 2],
  ].forEach(function(spec) {
    const ptr = findExport(spec[0]);
    if (!ptr) return;
    Interceptor.attach(ptr, {
      onEnter(args) {
        logFdData(spec[0], args[0].toInt32(), args[spec[1]], args[spec[2]].toInt32());
      }
    });
  });
  [
    ["recv", 1],
    ["read", 1],
  ].forEach(function(spec) {
    const ptr = findExport(spec[0]);
    if (!ptr) return;
    Interceptor.attach(ptr, {
      onEnter(args) {
        this.fd = args[0].toInt32();
        this.buf = args[spec[1]];
      },
      onLeave(retval) {
        logFdData(spec[0], this.fd, this.buf, retval.toInt32());
      }
    });
  });
  console.log("[native-connect] hooks installed");
}
function installNativeAddressCheckpoints() {
  if (nativeCheckpointHooksInstalled) return;
  let module = null;
  try { module = Process.getModuleByName("libezstreamclient.so"); } catch (e) { module = null; }
  if (!module) return;
  [
    ["invite.afterInitZero", 0x31c6b4],
    ["invite.afterBaseInfoCopies", 0x31c770],
    ["invite.afterEcdhCandidate", 0x31c7ba],
    ["invite.beforeBuildInvite", 0x31c81c],
    ["invite.afterBuildInvite", 0x31c824],
  ].forEach(function(spec) {
    try {
      Interceptor.attach(module.base.add(spec[1]).or(1), {
        onEnter(args) {
          const ctrl = this.context.r6;
          if (!ctrl || ctrl.isNull()) return;
          console.log("[native-checkpoint] " + spec[0]
            + " ctrl=" + objectLabel("ctrl", ctrl)
            + secretBinaryShape("ctrlPlus0x50", ctrl.add(0x50), 16));
        }
      });
    } catch (e) {
      console.log("[native-checkpoint] " + spec[0] + " hook failed " + e);
    }
  });
  nativeCheckpointHooksInstalled = true;
  console.log("[native-checkpoint] hooks installed");
}
installNativeSymbolShapeHooks();
setTimeout(installNativeSymbolShapeHooks, 3000);
// Address checkpoints are intentionally not auto-installed: attaching to
// interior Thumb instructions is useful for short probes but can destabilize
// the app. Call installNativeAddressCheckpoints() manually when needed.
function maybeRecord(NativeApi, h, why){
  let key=s(h), info=handleInfo.get(key);
  console.log(`[broad] ${why} handle=${key} info=${info?info.d:"<unknown>"}`);
  if (!activeRecordings.has(key) && info) {
    activeRecordings.add(key);
    let serial=(info.serial||"unknown").replace(/[^A-Za-z0-9_.-]/g,"_");
    let chan=(info.chan||"0").replace(/[^A-Za-z0-9_.-]/g,"_");
    let path=`/sdcard/Download/ezviz-broad-${serial}-ch${chan}-${tag()}.mp4`;
    try { let r=NativeApi.startRecord.overload("long","java.lang.String","int").call(NativeApi,h,path,0); console.log(`[broad-record] start ret=${r} path=${path}`); }
    catch(e){ console.log(`[broad-record] start failed ${e}`); activeRecordings.delete(key); return; }
    setTimeout(function(){ Java.perform(function(){ try{ NativeApi.stopRecord.overload("long","int").call(NativeApi,h,0); console.log(`[broad-record] stop handle=${key} path=${path}`); } catch(e){ console.log(`[broad-record] stop failed ${e}`); } activeRecordings.delete(key); }); }, RECORD_MS);
  }
}
function installJavaCasHooks() {
  try {
    const CasDeviceInfo = Java.use("com.ezplayer.param.model.internal.CasDeviceInfo");
    ["toEZDevInfoByReference", "toSTDevInfo"].forEach(function(name) {
      if (!CasDeviceInfo[name]) return;
      CasDeviceInfo[name].overloads.forEach(function(ov) {
        ov.implementation = function() {
          console.log("[java-cas] CasDeviceInfo." + name + " enter" + casInfoShape(this, name));
          const ret = ov.apply(this, arguments);
          console.log("[java-cas] CasDeviceInfo." + name + " ret=" + (ret ? "<non-null>" : "<null>"));
          return ret;
        };
      });
    });
  } catch (e) {
    console.log("[java-cas] CasDeviceInfo hook unavailable " + e);
  }
  try {
    const GlobalHolder = Java.use("com.ezplayer.common.GlobalHolder");
    GlobalHolder.getCasDeviceInfos.overloads.forEach(function(ov) {
      ov.implementation = function() {
        const ret = ov.apply(this, arguments);
        console.log("[java-cas] GlobalHolder.getCasDeviceInfos ret=" + (ret ? s(ret.$className || ret.getClass && ret.getClass()) : "<null>"));
        return ret;
      };
    });
  } catch (e) {
    console.log("[java-cas] GlobalHolder hook unavailable " + e);
  }
  try {
    const MMKV = Java.use("com.tencent.mmkv.MMKV");
    MMKV.decodeParcelable.overloads.forEach(function(ov) {
      ov.implementation = function() {
        const args = [].slice.call(arguments);
        const key = args.length > 0 ? s(args[0]) : "";
        const klass = args.length > 1 ? s(args[1]) : "";
        const ret = ov.apply(this, args);
        if (klass.indexOf("CasDeviceInfo") >= 0 || (ret && s(ret.$className).indexOf("CasDeviceInfo") >= 0)) {
          let shaped = null;
          try { shaped = ret ? Java.cast(ret, Java.use("com.ezplayer.param.model.internal.CasDeviceInfo")) : null; } catch (e) { shaped = ret; }
          console.log("[java-cas] MMKV.decodeParcelable key=" + key + " class=" + klass + (ret ? casInfoShape(shaped, "mmkv") : " cas=<null>"));
        }
        return ret;
      };
    });
    if (MMKV.encode) {
      MMKV.encode.overloads.forEach(function(ov) {
        ov.implementation = function() {
          const args = [].slice.call(arguments);
          const key = args.length > 0 ? s(args[0]) : "";
          const value = args.length > 1 ? args[1] : null;
          if (value && s(value.$className).indexOf("CasDeviceInfo") >= 0) {
            console.log("[java-cas] MMKV.encode key=" + key + casInfoShape(value, "mmkv-encode"));
          }
          return ov.apply(this, args);
        };
      });
    }
  } catch (e) {
    console.log("[java-cas] MMKV hook unavailable " + e);
  }
  try {
    const CASClient = Java.use("com.hc.CASClient.CASClient");
    CASClient.getDevOperationCodeEx.overloads.forEach(function(ov) {
      ov.implementation = function() {
        const args = [].slice.call(arguments);
        const server = args[0];
        const serials = args[3];
        const count = args[4];
        let serialShape = "<unreadable>";
        try { serialShape = serials ? Java.array("java.lang.String", serials).join(",") : "<null>"; } catch (e) { serialShape = "<array-failed:" + e + ">"; }
        console.log("[java-cas] CASClient.getDevOperationCodeEx enter"
          + " server=" + (server ? s(server.szServerIP.value || server.szServerIP) + ":" + s(server.nServerPort.value || server.nServerPort) : "<null>")
          + " sessionLen=" + s(args[1]).length
          + " hardwareLen=" + s(args[2]).length
          + " serials=" + serialShape
          + " count=" + count);
        const ret = ov.apply(this, args);
        let listShape = "";
        try {
          const list = args[5];
          const size = list ? list.size() : 0;
          const parts = [];
          for (let i = 0; i < size && i < 4; i++) parts.push(stDevInfoShape(list.get(i), "cas-list-" + i));
          listShape = " listSize=" + size + (parts.length ? " " + parts.join(" ") : "");
        } catch (e) {
          listShape = " list=<failed:" + e + ">";
        }
        console.log("[java-cas] CASClient.getDevOperationCodeEx leave ret=" + ret + listShape);
        return ret;
      };
    });
  } catch (e) {
    console.log("[java-cas] CASClient hook unavailable " + e);
  }
  try {
    const CasUtils = Java.use("com.ezplayer.utils.CasUtils");
    if (CasUtils.getDevOperationCode) {
      CasUtils.getDevOperationCode.overloads.forEach(function(ov) {
        ov.implementation = function() {
          const args = [].slice.call(arguments);
          let serial = "<unknown>";
          try { serial = s(args[0].getDeviceSerial()); } catch (e) {}
          console.log("[java-cas] CasUtils.getDevOperationCode enter serial=" + serial + " sessionLen=" + s(args[1]).length);
          const ret = ov.apply(this, args);
          console.log("[java-cas] CasUtils.getDevOperationCode leave" + casInfoShape(ret, "cas-utils"));
          return ret;
        };
      });
    }
  } catch (e) {
    console.log("[java-cas] CasUtils hook unavailable " + e);
  }
}
function lanDeviceShape(device) {
  if (!device) return " lanDevice=<null>";
  const parts = [];
  try { parts.push("serial=" + s(device.getSzSerialNO())); } catch (e) { parts.push("serial=<failed:" + e + ">"); }
  try { parts.push("ip=" + s(device.getSzIPv4Address())); } catch (e) { parts.push("ip=<failed:" + e + ">"); }
  try { parts.push("port=" + s(device.getDwPort())); } catch (e) { parts.push("port=<failed:" + e + ">"); }
  try { parts.push("tlsPort=" + s(device.getDwSDKOverTLSPort())); } catch (e) {}
  try { parts.push("user=" + s(device.getLoginName())); } catch (e) { parts.push("user=<failed:" + e + ">"); }
  try {
    const serial = s(device.getSzSerialNO());
    const pwd = s(device.getLoginPwd());
    parts.push("pwdLen=" + pwd.length + rememberSecret("lanPwd:" + serial, pwd));
  } catch (e) {
    parts.push("pwd=<failed:" + e + ">");
  }
  try { parts.push("loginId=" + s(device.getLoginId())); } catch (e) {}
  return " lanDevice={" + parts.join(" ") + "}";
}
function hookAllOverloads(label, klass, method, before, after) {
  if (!klass || !klass[method]) return;
  klass[method].overloads.forEach(function(ov) {
    ov.implementation = function() {
      const args = [].slice.call(arguments);
      let state = null;
      try { state = before ? before.call(this, args, ov) : null; } catch (e) { console.log(label + " before failed " + e); }
      const ret = ov.apply(this, args);
      try { if (after) after.call(this, args, ret, state, ov); } catch (e) { console.log(label + " after failed " + e); }
      return ret;
    };
  });
}
function installJavaLanHooks() {
  try {
    const LanDeviceInfo = Java.use("com.videogo.device.LanDeviceInfo");
    ["setLoginName", "setLoginPwd", "setSzIPv4Address", "setDwPort", "setSzSerialNO"].forEach(function(name) {
      hookAllOverloads("[java-lan] LanDeviceInfo." + name, LanDeviceInfo, name, function(args) {
        let valueShape = "";
        if (name === "setLoginPwd") {
          valueShape = " pwdLen=" + s(args[0]).length + rememberSecret("lanSetPwd", s(args[0]));
        } else {
          valueShape = " value=" + s(args[0]);
        }
        console.log("[java-lan] LanDeviceInfo." + name + " enter" + valueShape);
      }, function() {
        console.log("[java-lan] LanDeviceInfo." + name + " leave" + lanDeviceShape(this));
      });
    });
  } catch (e) {
    console.log("[java-lan] LanDeviceInfo hook unavailable " + e);
  }
  try {
    const DeviceInfoEx = Java.use("com.videogo.device.DeviceInfoEx");
    hookAllOverloads("[java-lan] DeviceInfoEx.setLandevice", DeviceInfoEx, "setLandevice", function(args) {
      let serial = "<unknown>";
      try { serial = s(this.getDeviceSerial()); } catch (e) {}
      console.log("[java-lan] DeviceInfoEx.setLandevice enter deviceSerial=" + serial + lanDeviceShape(args[0]));
    });
    hookAllOverloads("[java-lan] DeviceInfoEx.loginDevice", DeviceInfoEx, "loginDevice", function(args) {
      let serial = "<unknown>";
      try { serial = s(this.getDeviceSerial()); } catch (e) {}
      console.log("[java-lan] DeviceInfoEx.loginDevice enter deviceSerial=" + serial + " verifyLen=" + (args.length ? s(args[0]).length : 0) + (args.length ? rememberSecret("loginVerify:" + serial, s(args[0])) : "") + lanDeviceShape(this.getLandevice()));
    }, function(args, ret) {
      let serial = "<unknown>";
      try { serial = s(this.getDeviceSerial()); } catch (e) {}
      console.log("[java-lan] DeviceInfoEx.loginDevice leave deviceSerial=" + serial + " ret=" + ret + " loginId=" + s(this.getLoginID()) + lanDeviceShape(this.getLandevice()));
    });
    hookAllOverloads("[java-lan] DeviceInfoEx.loginPlayDevice", DeviceInfoEx, "loginPlayDevice", function(args) {
      let serial = "<unknown>";
      try { serial = s(this.getDeviceSerial()); } catch (e) {}
      console.log("[java-lan] DeviceInfoEx.loginPlayDevice enter deviceSerial=" + serial + " checkLast=" + (args.length > 1 ? s(args[1]) : "") + lanDeviceShape(this.getLandevice()));
    }, function(args, ret) {
      let serial = "<unknown>";
      try { serial = s(this.getDeviceSerial()); } catch (e) {}
      console.log("[java-lan] DeviceInfoEx.loginPlayDevice leave deviceSerial=" + serial + " ret=" + ret + " loginId=" + s(this.getLoginID()));
    });
  } catch (e) {
    console.log("[java-lan] DeviceInfoEx hook unavailable " + e);
  }
  try {
    const H = Java.use("com.videogo.hcnetsdk.HCNetSDKManage");
    hookAllOverloads("[java-lan] HCNetSDKManage.NET_DVR_Login_V30", H, "NET_DVR_Login_V30", function(args) {
      console.log("[java-lan] HCNetSDKManage.NET_DVR_Login_V30 enter ip=" + s(args[0])
        + " port=" + s(args[1])
        + " user=" + s(args[2])
        + " pwdLen=" + s(args[3]).length
        + rememberSecret("hcnetsdkPwd:" + s(args[0]) + ":" + s(args[2]), s(args[3]))
        + " match=" + secretMatch(s(args[3])));
    }, function(args, ret) {
      console.log("[java-lan] HCNetSDKManage.NET_DVR_Login_V30 leave ip=" + s(args[0]) + " user=" + s(args[2]) + " ret=" + ret);
    });
    ["NET_DVR_MakeKeyFrame", "NET_DVR_MakeKeyFrameSub"].forEach(function(name) {
      hookAllOverloads("[java-lan] HCNetSDKManage." + name, H, name, function(args) {
        console.log("[java-lan] HCNetSDKManage." + name + " enter args=" + args.map(function(a){ return s(a); }).join("|"));
      }, function(args, ret) {
        console.log("[java-lan] HCNetSDKManage." + name + " leave ret=" + ret);
      });
    });
  } catch (e) {
    console.log("[java-lan] HCNetSDKManage hook unavailable " + e);
  }
}
installNativeSocketHooks();
setImmediate(function(){ Java.perform(function(){
  installJavaCasHooks();
  installJavaLanHooks();
  const NativeApi=Java.use("com.ez.stream.NativeApi");
  ["createClient","createCloudHandle","createCloudHandleEx","createPreviewHandle","createPlaybackHandle","createPlaybackHandleEx","createDownloadClient","createTimelapseDownloadClient"].forEach(function(name){
    if (!NativeApi[name]) return;
    NativeApi[name].overloads.forEach(function(ov){
      ov.implementation=function(){ let args=[].slice.call(arguments); let initArg=args.length && args[0] && fv(args[0],"szDevSerial"); console.log(`[broad] ${name} args=`+(initArg ? desc(args[0]) : args.map(function(a){return s(a)}).join(" | "))); let ret=ov.apply(this,args); if(initArg) remember(ret,name,args[0]); else console.log(`[broad] ${name} ret=${ret}`); return ret; };
    });
  });
  ["start","startPreview","startPlayback","updateParam","updateInitParam","setSecretKey","setClientECDHKey","generateECDHKey","getUUID","enableStreamClientCMDEcdh","enableTTSCMDEcdh","enableStreamClientETP","setStreamStrategy","setTokens","setStreamDataCallback","setCallback","setMediaCallback"].forEach(function(name){
    if (!NativeApi[name]) return;
    NativeApi[name].overloads.forEach(function(ov){
	      ov.implementation=function(){ let args=[].slice.call(arguments); if(name==='setSecretKey'&&args.length>1) rememberSecret("javaSecretKey", s(args[1])); console.log(`[broad] ${name} args=`+args.map(function(a,i){ if(name==='setSecretKey'&&i===1) return `<redacted-len-${s(a).length}>`; if(name==='setClientECDHKey') return `<ecdh-arg-${i}-redacted-type-${a === null || a === undefined ? "null" : a.$className || typeof a}>`; if(name==='setTokens') return '<tokens-redacted>'; if((name==='updateParam'||name==='updateInitParam')&&a&&fv(a,"szDevSerial")) return desc(a); return s(a); }).join(" | ")); let ret=ov.apply(this,args); console.log(`[broad] ${name} ret=${name==='generateECDHKey'||name==='getUUID'?'<redacted-len-'+s(ret).length+'>':ret}`); if((name==='start'||name==='startPreview') && args.length) maybeRecord(NativeApi,args[0],name); return ret; };
    });
  });
  try{
    const D=Java.use("com.videogo.device.DeviceInfoEx");
    D.sdkLoginV40.overloads.forEach(function(ov){ ov.implementation=function(){ let args=[].slice.call(arguments); console.log(`[broad-login] DeviceInfoEx.sdkLoginV40 ip=${args[0]} port=${args[1]} user=${args[2]} pwdLen=${s(args[3]).length}`); let r=ov.apply(this,args); console.log(`[broad-login] DeviceInfoEx.sdkLoginV40 ret=${r}`); return r; }; });
  } catch(e){ console.log(`[broad-login] DeviceInfoEx unavailable ${e}`); }
  try{
    const H=Java.use("com.neutral.netsdk.HCNetSDK");
    H.NET_DVR_Login_V30.overloads.forEach(function(ov){ ov.implementation=function(){ let args=[].slice.call(arguments); console.log(`[broad-login] NET_DVR_Login_V30 ip=${args[0]} port=${args[1]} user=${args[2]} pwdLen=${s(args[3]).length}`); let r=ov.apply(this,args); console.log(`[broad-login] NET_DVR_Login_V30 ret=${r}`); return r; }; });
  } catch(e){ console.log(`[broad-login] neutral HCNet unavailable ${e}`); }
  console.log(`[broad] hooks installed recordMs=${RECORD_MS}`);
}); });
