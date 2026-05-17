"use strict";

/*
 * Invoke CASClient.getDevOperationCodeEx and classify the native wire payloads
 * around that call. Logs are intentionally shape-only: no session IDs,
 * hardware codes, operation codes, keys, or raw XML values.
 */

const TARGET_SERIAL_VALUE = "FAKE001";
const TARGET_CAS_HOST = "eucas.ezvizlife.com";
const TARGET_CAS_PORT = 6500;

const fdPeers = new Map();
const logCounts = new Map();
let oracleActive = false;
let getpeernameFn = null;

function s(value) {
  try {
    return value === null || value === undefined ? "" : value.toString();
  } catch (e) {
    return "<toString:" + e + ">";
  }
}

function emit(obj) {
  console.log("[cas-wire-json] " + JSON.stringify(obj));
}

function u16be(bytes, off) {
  return (bytes[off] << 8) + bytes[off + 1];
}

function u32be(bytes, off) {
  return ((bytes[off] << 24) >>> 0) + (bytes[off + 1] << 16) + (bytes[off + 2] << 8) + bytes[off + 3];
}

function hex(bytes) {
  return Array.prototype.map.call(bytes, function(b) {
    return ("0" + b.toString(16)).slice(-2);
  }).join(" ");
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
  while ((m = re.exec(text)) !== null && tags.length < 32) {
    const tag = m[1];
    if (!seen[tag]) {
      seen[tag] = true;
      tags.push(tag);
    }
  }
  return tags.join(",");
}

function xmlValueShape(text) {
  const parts = [];
  const seen = {};
  const re = /<([A-Za-z_][A-Za-z0-9_.:-]*)\b[^>]*>([^<]*)<\/\1>/g;
  let m;
  while ((m = re.exec(text)) !== null && parts.length < 32) {
    const tag = m[1];
    if (seen[tag]) continue;
    seen[tag] = true;
    const value = m[2] || "";
    let printable = 0;
    for (let i = 0; i < value.length; i++) {
      const c = value.charCodeAt(i);
      if (c >= 0x20 && c <= 0x7e) printable++;
    }
    parts.push(tag + "Len=" + value.length + "/p" + (value.length ? (printable / value.length).toFixed(2) : "0.00"));
  }
  return parts.join(",");
}

function payloadShape(ptr, len) {
  if (!ptr || ptr.isNull() || len <= 0) return { kind: "empty", len: len };
  const n = Math.min(len, 4096);
  const raw = ptr.readByteArray(n);
  if (!raw) return { kind: "unreadable", len: len };
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
  } else if (bytes.length >= 4 && bytes[0] === 0x9e && bytes[1] === 0xba && bytes[2] === 0xac && bytes[3] === 0xe9) {
    kind = "cas_frame";
  } else if (bytes.length >= 4 && bytes[0] === 0x48 && bytes[1] === 0x54 && bytes[2] === 0x54 && bytes[3] === 0x50) {
    kind = "http";
  } else if (printable / bytes.length > 0.80) {
    kind = "printable";
  } else if (high / bytes.length > 0.25) {
    kind = "opaque";
  }
  const text = safeAscii(bytes);
  const xmlOffset = text.indexOf("<");
  const tags = xmlOffset >= 0 ? xmlTagShape(text.slice(xmlOffset)) : "";
  const values = tags ? xmlValueShape(text.slice(xmlOffset)) : "";
  const out = {
    kind: kind,
    len: len,
    captured: bytes.length,
    head32: hex(bytes.slice(0, Math.min(32, bytes.length))),
    printable: bytes.length ? Number((printable / bytes.length).toFixed(2)) : 0,
    nulls: bytes.length ? Number((nul / bytes.length).toFixed(2)) : 0,
    high: bytes.length ? Number((high / bytes.length).toFixed(2)) : 0,
  };
  if (bytes.length >= 32 && kind === "cas_frame") {
    out.version = hex(bytes.slice(4, 8));
    out.sequence = u32be(bytes, 8);
    out.reserved = u32be(bytes, 12);
    out.commandU32 = u32be(bytes, 16);
    out.commandU16 = u16be(bytes, 18);
    out.flags = u32be(bytes, 20);
    out.bodySizeHint = u32be(bytes, 24);
    out.tailSizeHint = u32be(bytes, 28);
  }
  if (tags) {
    out.xmlOffset = xmlOffset;
    out.tags = tags;
    out.valueLens = values;
  }
  return out;
}

function readSockaddr(addr, len) {
  if (!addr || addr.isNull() || len < 8) return null;
  const family = addr.readU16();
  if (family !== 2) return null;
  const port = (addr.add(2).readU8() << 8) | addr.add(3).readU8();
  const host = [0, 1, 2, 3].map(function(i) { return addr.add(4 + i).readU8(); }).join(".");
  return { host: host, port: port };
}

function shouldLog(kind, peer) {
  if (!oracleActive && (!peer || peer.port !== TARGET_CAS_PORT)) return false;
  const key = kind + ":" + (peer ? peer.host + ":" + peer.port : "active");
  const count = logCounts.get(key) || 0;
  if (count >= 12) return false;
  logCounts.set(key, count + 1);
  return true;
}

function findGlobalExport(name) {
  if (typeof Module.findGlobalExportByName === "function") {
    const ptr = Module.findGlobalExportByName(name);
    if (ptr) return ptr;
  }
  if (typeof Module.findExportByName === "function") {
    const ptr = Module.findExportByName(null, name);
    if (ptr) return ptr;
  }
  const modules = ["libssl.so", "libsslPrivate.so", "libmbedtls.so", "libc.so"];
  for (const moduleName of modules) {
    try {
      const module = Process.getModuleByName(moduleName);
      if (module && typeof module.findExportByName === "function") {
        const ptr = module.findExportByName(name);
        if (ptr) return ptr;
      }
    } catch (e) {
      // Module is not loaded yet.
    }
  }
  return null;
}

function peerForFd(fd) {
  const cached = fdPeers.get(fd);
  if (cached) return cached;
  if (!getpeernameFn) return null;
  try {
    const addr = Memory.alloc(32);
    const lenPtr = Memory.alloc(4);
    lenPtr.writeU32(32);
    const ret = getpeernameFn(fd, addr, lenPtr);
    if (ret !== 0) return null;
    const peer = readSockaddr(addr, lenPtr.readU32());
    if (peer) fdPeers.set(fd, peer);
    return peer;
  } catch (e) {
    return null;
  }
}

function hookNative() {
  const getpeernamePtr = findGlobalExport("getpeername");
  if (getpeernamePtr) {
    getpeernameFn = new NativeFunction(getpeernamePtr, "int", ["int", "pointer", "pointer"]);
  }
  const connectPtr = findGlobalExport("connect");
  if (connectPtr) {
    Interceptor.attach(connectPtr, {
      onEnter(args) {
        this.fd = args[0].toInt32();
        this.peer = readSockaddr(args[1], args[2].toInt32());
      },
      onLeave(retval) {
        if (retval.toInt32() === 0 && this.peer) {
          fdPeers.set(this.fd, this.peer);
          if (this.peer.port === TARGET_CAS_PORT) emit({ event: "connect", fd: this.fd, peer: this.peer });
        }
      },
    });
  }

  [["send", 1, 2], ["write", 1, 2]].forEach(function(spec) {
    const ptr = findGlobalExport(spec[0]);
    if (!ptr) return;
    Interceptor.attach(ptr, {
      onEnter(args) {
        const fd = args[0].toInt32();
        const peer = peerForFd(fd);
        const len = args[spec[2]].toInt32();
        if (shouldLog(spec[0], peer)) emit({ event: spec[0], fd: fd, peer: peer || null, shape: payloadShape(args[spec[1]], len) });
      },
    });
  });

  [["recv", 1, 2], ["read", 1, 2]].forEach(function(spec) {
    const ptr = findGlobalExport(spec[0]);
    if (!ptr) return;
    Interceptor.attach(ptr, {
      onEnter(args) {
        this.fd = args[0].toInt32();
        this.buf = args[spec[1]];
        this.peer = peerForFd(this.fd);
      },
      onLeave(retval) {
        const len = retval.toInt32();
        if (len > 0 && shouldLog(spec[0], this.peer)) emit({ event: spec[0], fd: this.fd, peer: this.peer || null, shape: payloadShape(this.buf, len) });
      },
    });
  });

  const sslGetFd = findGlobalExport("SSL_get_fd");
  [["SSL_write", 1, 2], ["SSL_read", 1, 2], ["mbedtls_ssl_write", 1, 2], ["mbedtls_ssl_read", 1, 2]].forEach(function(spec) {
    const ptr = findGlobalExport(spec[0]);
    if (!ptr) return;
    Interceptor.attach(ptr, {
      onEnter(args) {
        this.ssl = args[0];
        this.buf = args[spec[1]];
        this.len = args[spec[2]].toInt32();
      },
      onLeave(retval) {
        let fd = null;
        let peer = null;
        if (sslGetFd && spec[0].indexOf("SSL_") === 0) {
          try {
            fd = new NativeFunction(sslGetFd, "int", ["pointer"])(this.ssl);
            peer = fdPeers.get(fd);
          } catch (e) {
            fd = null;
          }
        }
        const actualLen = spec[0].indexOf("_read") >= 0 ? retval.toInt32() : this.len;
        if (actualLen > 0 && shouldLog(spec[0], peer)) emit({ event: spec[0], fd: fd, peer: peer || null, shape: payloadShape(this.buf, actualLen) });
      },
    });
    emit({ event: "hooked", symbol: spec[0] });
  });
}

function shape(label, value) {
  const text = s(value);
  let printable = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c >= 0x20 && c <= 0x7e) printable++;
  }
  return label + "Len=" + text.length + " printable=" + (text.length ? (printable / text.length).toFixed(2) : "0.00");
}

function fieldValue(obj, name) {
  try {
    const field = obj[name];
    if (field === null || field === undefined) return null;
    if (field.value !== undefined) return field.value;
    return field;
  } catch (e) {
    return null;
  }
}

function devInfoShape(info, STDevInfo) {
  if (!info) return { present: false };
  let castInfo = info;
  try { castInfo = Java.cast(info, STDevInfo); } catch (e) { castInfo = info; }
  return {
    present: true,
    serial: s(fieldValue(castInfo, "szDevSerial")),
    operationCodeLen: s(fieldValue(castInfo, "szOperationCode")).length,
    keyLen: s(fieldValue(castInfo, "szKey")).length,
    encryptType: Number(s(fieldValue(castInfo, "enEncryptType"))),
  };
}

function resolveHost(host) {
  const InetAddress = Java.use("java.net.InetAddress");
  return s(InetAddress.getByName(host).getHostAddress());
}

function invokeOracle() {
  Java.perform(function() {
    try {
      const GlobalHolder = Java.use("com.ezplayer.common.GlobalHolder");
      const CASClient = Java.use("com.hc.CASClient.CASClient");
      const STServerInfo = Java.use("com.hc.CASClient.ST_SERVER_INFO");
      const STDevInfo = Java.use("com.hc.CASClient.ST_DEV_INFO");
      const ArrayList = Java.use("java.util.ArrayList");
      const StringArray = Java.array("java.lang.String", [TARGET_SERIAL_VALUE]);

      const globalParam = GlobalHolder.INSTANCE.value.getGlobalParam();
      const sessionId = globalParam.getSessionId();
      const hardwareCode = globalParam.getHardwareCode();
      const server = STServerInfo.$new();
      server.szServerIP.value = resolveHost(TARGET_CAS_HOST);
      server.nServerPort.value = TARGET_CAS_PORT;
      const out = ArrayList.$new();
      const client = CASClient.getInstance();

      emit({ event: "oracle-enter", serial: TARGET_SERIAL_VALUE, session: shape("session", sessionId), hardware: shape("hardware", hardwareCode), server: server.szServerIP.value + ":" + TARGET_CAS_PORT });
      oracleActive = true;
      const ok = client.getDevOperationCodeEx(server, sessionId, hardwareCode, StringArray, 1, out);
      oracleActive = false;
      emit({ event: "oracle-leave", ok: !!ok, lastError: client.getLastError(), outSize: out.size(), first: devInfoShape(out.size() > 0 ? out.get(0) : null, STDevInfo) });
    } catch (e) {
      oracleActive = false;
      emit({ event: "oracle-error", error: s(e), stack: e && e.stack ? s(e.stack) : "" });
    }
  });
}

hookNative();
setTimeout(invokeOracle, 500);
