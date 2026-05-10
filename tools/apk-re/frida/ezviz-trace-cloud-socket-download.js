/*
 * Trace the EZVIZ native cloud-download socket path while triggering one
 * DownloadCloudParam download through the in-app SDK.
 *
 * Input is read from the app external-files JSON, matching
 * ezviz-trigger-cloud-download.js. Binary samples are written under:
 *
 *   /sdcard/Android/data/com.ezviz/files/ezviz-cloud-socket-trace/
 */

"use strict";

const INPUT_NAME = "ezviz-cloud-download-input.json";
const RUN_MS = 25000;
const RUN_ID = Date.now();
const DUMP_LIMIT = 64 * 1024;
const HEX_LIMIT = 96;
const MAX_DUMPS_PER_LABEL = 64;

const installed = new Set();
const dumpCounts = {};
const protoStackByThread = {};
let dumpDir = "/sdcard/Download/ezviz-cloud-socket-trace";
let dumpSeq = 0;

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

function dumpPointerCandidates(label, base, len) {
  if (base.isNull()) {
    return;
  }
  const seen = new Set();
  for (let offset = 0; offset < Math.min(len, 160); offset += Process.pointerSize) {
    try {
      const ptr = base.add(offset).readPointer();
      const key = ptr.toString();
      if (ptr.isNull() || seen.has(key)) {
        continue;
      }
      seen.add(key);
      const text = ptr.readUtf8String(160);
      if (typeof text === "string" && /<|>|xml|Cloud|cloud|Command|Session|SubSerial|FileInfo/.test(text)) {
        console.log(`[ptr-candidate] ${label}+${offset} ptr=${ptr} text=${redactXmlToken(text)}`);
        dumpBytes(`${label}-ptr-${offset}`, ptr, 4096);
      }
    } catch (err) {
      // Most words are not readable pointers.
    }
  }
}

function threadKey() {
  try {
    return String(Process.getCurrentThreadId());
  } catch (err) {
    return "unknown";
  }
}

function activeProto() {
  const stack = protoStackByThread[threadKey()] || [];
  return stack.length ? stack[stack.length - 1] : null;
}

function pushProto(name, selfPtr) {
  const key = threadKey();
  protoStackByThread[key] = protoStackByThread[key] || [];
  protoStackByThread[key].push({ name, selfPtr });
  console.log(`[proto] enter ${name} this=${selfPtr}`);
  dumpBytes(`proto-object-${name}`, selfPtr, 384);
}

function popProto() {
  const key = threadKey();
  const stack = protoStackByThread[key] || [];
  const ctx = stack.pop();
  if (ctx) {
    console.log(`[proto] leave ${ctx.name} this=${ctx.selfPtr}`);
  }
}

function readStdString(strPtr) {
  if (strPtr.isNull()) {
    return "<null>";
  }

  const candidates = [];
  try {
    const first = strPtr.readU8();
    if ((first & 1) === 0) {
      const len = first >> 1;
      if (len >= 0 && len < 4096) {
        candidates.push(strPtr.add(1).readUtf8String(len));
      }
    }
  } catch (err) {
    // Try the long layouts below.
  }

  for (const layout of [
    { size: 4, ptr: 8 },
    { size: 8, ptr: 4 },
  ]) {
    try {
      const len = strPtr.add(layout.size).readU32();
      const data = strPtr.add(layout.ptr).readPointer();
      if (len > 0 && len < 1024 * 1024 && !data.isNull()) {
        candidates.push(data.readUtf8String(Math.min(len, 4096)));
      }
    } catch (err) {
      // Keep trying alternate layouts.
    }
  }

  try {
    const data = strPtr.readPointer();
    if (!data.isNull()) {
      const value = data.readUtf8String(4096);
      if (typeof value === "string" && value.length > 0) {
        candidates.push(value);
      }
    }
  } catch (err) {
    // Some builds use inline string storage instead.
  }

  for (const value of candidates) {
    if (typeof value === "string" && value.length > 0) {
      return value;
    }
  }
  return "<unreadable>";
}

function redactProtoField(ctx, field, value) {
  if (ctx.name === "PeerStreamReq" && field === 5) {
    return `<token len=${String(value).length}>`;
  }
  if (ctx.name === "StartPlayBackReq" && (field === 9 || field === 10 || field === 11)) {
    return `<sensitive len=${String(value).length}>`;
  }
  return value;
}

function redactXmlToken(value) {
  return String(value).replace(/<Token>[^<]*<\/Token>/g, (match) => {
    const token = match.slice("<Token>".length, -"</Token>".length);
    return `<Token><redacted len=${token.length}></Token>`;
  });
}

function readText(path) {
  const FileCls = Java.use("java.io.File");
  const FileInputStream = Java.use("java.io.FileInputStream");
  const ByteArrayOutputStream = Java.use("java.io.ByteArrayOutputStream");
  const buffer = Java.array("byte", Array(4096).fill(0));
  const input = FileInputStream.$new(FileCls.$new(path));
  const output = ByteArrayOutputStream.$new();
  try {
    while (true) {
      const n = input.read(buffer);
      if (n <= 0) {
        break;
      }
      output.write(buffer, 0, n);
    }
    return output.toString("UTF-8").toString();
  } finally {
    input.close();
    output.close();
  }
}

function jsonString(obj, key, fallback) {
  if (!obj.has(key) || obj.isNull(key)) {
    return fallback;
  }
  return obj.getString(key);
}

function jsonInt(obj, key, fallback) {
  if (!obj.has(key) || obj.isNull(key)) {
    return fallback;
  }
  return obj.getInt(key);
}

function jsonLong(obj, key, fallback) {
  if (!obj.has(key) || obj.isNull(key)) {
    return fallback;
  }
  return obj.getLong(key);
}

function formatCasTime(ms) {
  const Locale = Java.use("java.util.Locale");
  const DateCls = Java.use("java.util.Date");
  const SimpleDateFormat = Java.use("java.text.SimpleDateFormat");
  const formatter = SimpleDateFormat.$new("yyyyMMdd'T'HHmmss'Z'", Locale.US.value);
  return formatter.format(DateCls.$new(ms)).toString();
}

function ensureDir(base, child) {
  const FileCls = Java.use("java.io.File");
  const dir = FileCls.$new(base, child);
  dir.mkdirs();
  return dir;
}

function hookFunction(address, name, spec) {
  if (address === null || address.isNull() || installed.has(name)) {
    return;
  }
  installed.add(name);
  Interceptor.attach(address, spec);
  console.log(`[hook] ${name} @ ${address}`);
}

function findExport(moduleName, exportName) {
  if (typeof Module.findExportByName === "function") {
    return Module.findExportByName(moduleName, exportName);
  }
  try {
    return Process.getModuleByName(moduleName).findExportByName(exportName);
  } catch (err) {
    return null;
  }
}

function findGlobalExport(exportName) {
  if (typeof Module.findGlobalExportByName === "function") {
    return Module.findGlobalExportByName(exportName);
  }
  for (const module of Process.enumerateModules()) {
    try {
      for (const exp of module.enumerateExports()) {
        if (exp.name === exportName) {
          return exp.address;
        }
      }
    } catch (err) {
      // Keep searching other modules.
    }
  }
  return null;
}

function hookExport(moduleName, exportName, specFactory) {
  const module = Process.findModuleByName(moduleName);
  if (!module) {
    return;
  }
  const found = module.enumerateExports().find((exp) => exp.name === exportName);
  if (!found) {
    return;
  }
  hookFunction(found.address, `${moduleName}!${exportName}`, specFactory(found.name));
}

function hookExportExact(moduleName, exportName, label, specFactory) {
  const module = Process.findModuleByName(moduleName);
  if (!module) {
    return;
  }
  const found = module.enumerateExports().find((exp) => exp.name === exportName);
  if (!found || found.type !== "function") {
    return;
  }
  hookFunction(found.address, `${moduleName}!${label}`, specFactory(found.name));
}

function hookSymbolBySubstr(moduleName, needle, specFactory) {
  const module = Process.findModuleByName(moduleName);
  if (!module) {
    return;
  }
  for (const exp of module.enumerateExports()) {
    if (exp.type === "function" && exp.name.indexOf(needle) !== -1) {
      hookFunction(exp.address, `${moduleName}!${exp.name}`, specFactory(exp.name));
    }
  }
}

function hookLibcIo() {
  const libc = Process.findModuleByName("libc.so");
  if (!libc) {
    return;
  }
  for (const name of ["connect", "send", "recv", "sendto", "recvfrom"]) {
    const addr = findExport("libc.so", name);
    if (addr === null) {
      continue;
    }
    hookFunction(addr, `libc.so!${name}`, {
      onEnter(args) {
        this.name = name;
        this.fd = args[0].toInt32();
        if (name === "send") {
          const len = args[2].toInt32 ? args[2].toInt32() : args[2].toUInt32();
          console.log(`[sock] ${name} fd=${this.fd} len=${len} hex=${bytesToHex(args[1], len)}`);
          dumpBytes(`libc-${name}`, args[1], len);
        } else if (name === "sendto") {
          const len = args[2].toInt32 ? args[2].toInt32() : args[2].toUInt32();
          console.log(`[sock] ${name} fd=${this.fd} len=${len} hex=${bytesToHex(args[1], len)}`);
          dumpBytes(`libc-${name}`, args[1], len);
        } else if (name === "recv" || name === "recvfrom") {
          this.buf = args[1];
        } else if (name === "connect") {
          console.log(`[sock] connect fd=${this.fd}`);
        }
      },
      onLeave(retval) {
        if ((this.name === "recv" || this.name === "recvfrom") && retval.toInt32() > 0) {
          const len = retval.toInt32();
          console.log(`[sock] ${this.name} fd=${this.fd} ret=${len} hex=${bytesToHex(this.buf, len)}`);
          dumpBytes(`libc-${this.name}`, this.buf, len);
        }
      },
    });
  }
}

function hookMbedtlsIo() {
  for (const name of ["mbedtls_ssl_write", "mbedtls_ssl_read", "mbedtls_net_send", "mbedtls_net_recv", "mbedtls_net_recv_timeout"]) {
    const addr = findExport("libmbedtls.so", name) || findGlobalExport(name);
    if (addr === null) {
      continue;
    }
    hookFunction(addr, `global!${name}`, {
      onEnter(args) {
        this.name = name;
        if (name === "mbedtls_ssl_write" || name === "mbedtls_net_send") {
          const len = args[2].toInt32();
          console.log(`[tls] ${name} len=${len} hex=${bytesToHex(args[1], len)}`);
          dumpBytes(name, args[1], len);
        } else {
          this.buf = args[1];
        }
      },
      onLeave(retval) {
        if ((this.name === "mbedtls_ssl_read" || this.name === "mbedtls_net_recv" || this.name === "mbedtls_net_recv_timeout") && retval.toInt32() > 0) {
          const len = retval.toInt32();
          console.log(`[tls] ${this.name} ret=${len} hex=${bytesToHex(this.buf, len)}`);
          dumpBytes(this.name, this.buf, len);
        }
      },
    });
  }
}

function hookHprIo() {
  for (const name of ["HPR_Send", "HPR_Sendn", "HPR_SendTo", "HPR_Recv", "HPR_Recvn", "HPR_RecvFrom"]) {
    const addr = findExport("libhpr.so", name) || findGlobalExport(name);
    if (addr === null) {
      continue;
    }
    hookFunction(addr, `libhpr.so!${name}`, {
      onEnter(args) {
        this.name = name;
        this.fd = args[0].toInt32();
        if (name === "HPR_Send" || name === "HPR_Sendn" || name === "HPR_SendTo") {
          const len = args[2].toInt32();
          console.log(`[hpr] ${name} fd=${this.fd} len=${len} hex=${bytesToHex(args[1], len)}`);
          dumpBytes(`hpr-${name}`, args[1], len);
        } else {
          this.buf = args[1];
        }
      },
      onLeave(retval) {
        if ((this.name === "HPR_Recv" || this.name === "HPR_Recvn" || this.name === "HPR_RecvFrom") && retval.toInt32() > 0) {
          const len = retval.toInt32();
          console.log(`[hpr] ${this.name} fd=${this.fd} ret=${len} hex=${bytesToHex(this.buf, len)}`);
          dumpBytes(`hpr-${this.name}`, this.buf, len);
        }
      },
    });
  }
}

function hookEzstreamCloud() {
  hookSymbolBySubstr("libezstreamclient.so", "SendTransferDataToCAS", (name) => ({
    onEnter(args) {
      this.out = args[8];
      console.log(
        `[cas] ${name} arg0=${args[0]} arg1=${args[1].toInt32()} arg2=${args[2]} arg3=${args[3].toInt32()} arg4=${args[4].toInt32()} arg10=${args[10]} arg11=${args[11].toInt32()} arg12=${args[12].toInt32()}`,
      );
      dumpBytes("cas-send-transfer-a0", args[0], args[1].toInt32());
      dumpBytes("cas-send-transfer-a2", args[2], args[3].toInt32());
    },
    onLeave(retval) {
      console.log(`[cas] ${name} ret=${retval.toInt32()}`);
    },
  }));
  hookSymbolBySubstr("libezstreamclient.so", "SendDataToCAS", (name) => ({
    onEnter(args) {
      console.log(
        `[cas] ${name} arg0=${args[0]} arg1=${args[1].toInt32()} arg2=${args[2]} arg3=${args[3].toInt32()} arg4=${args[4].toInt32()}`,
      );
      dumpBytes("cas-send-data-a0", args[0], args[1].toInt32());
      dumpBytes("cas-send-data-a2", args[2], args[3].toInt32());
    },
    onLeave(retval) {
      console.log(`[cas] ${name} ret=${retval.toInt32()}`);
    },
  }));
  hookSymbolBySubstr("libezstreamclient.so", "CASClient_CloudDownloadStart", (name) => ({
    onEnter(args) {
      console.log(`[cas] ${name} args=${args[0]} ${args[1]} ${args[2]} ${args[3]}`);
    },
    onLeave(retval) {
      console.log(`[cas] ${name} ret=${retval.toInt32()}`);
    },
  }));
  hookSymbolBySubstr("libezstreamclient.so", "ezstream_startDownloadFromCloud", (name) => ({
    onEnter(args) {
      console.log(`[ezstream] ${name} client=${args[0]} param=${args[1]}`);
    },
    onLeave(retval) {
      console.log(`[ezstream] ${name} ret=${retval.toInt32()}`);
    },
  }));
  hookSymbolBySubstr("libezstreamclient.so", "_ZN7sockets4send", (name) => ({
    onEnter(args) {
      const len = args[2].toInt32();
      console.log(`[sock-wrap] ${name} fd=${args[0].toInt32()} len=${len} hex=${bytesToHex(args[1], len)}`);
      dumpBytes("wrap-sockets-send", args[1], len);
    },
    onLeave(retval) {
      console.log(`[sock-wrap] ${name} ret=${retval.toInt32()}`);
    },
  }));
  hookSymbolBySubstr("libezstreamclient.so", "_ZN7sockets4recv", (name) => ({
    onEnter(args) {
      this.buf = args[1];
    },
    onLeave(retval) {
      if (retval.toInt32() > 0) {
        const len = retval.toInt32();
        console.log(`[sock-wrap] ${name} ret=${len} hex=${bytesToHex(this.buf, len)}`);
        dumpBytes("wrap-sockets-recv", this.buf, len);
      }
    },
  }));
  hookSymbolBySubstr("libezstreamclient.so", "_ZN13TcpConnection4send", (name) => ({
    onEnter(args) {
      const len = args[2].toInt32();
      console.log(`[tcp] ${name} len=${len} hex=${bytesToHex(args[1], len)}`);
      dumpBytes("tcp-connection-send", args[1], len);
    },
    onLeave(retval) {
      console.log(`[tcp] ${name} ret=${retval.toInt32()}`);
    },
  }));
  hookSymbolBySubstr("libezstreamclient.so", "_ZN15CTransferClient14CloudPlayStart", (name) => ({
    onEnter(args) {
      console.log(`[transfer] ${name} this=${args[0]} serverInfo=${args[1]} cloudInfo=${args[2]}`);
      dumpBytes("transfer-cloudplay-server-info", args[1], 128);
      dumpBytes("transfer-cloudplay-info", args[2], 512);
    },
    onLeave(retval) {
      console.log(`[transfer] ${name} ret=${retval.toInt32()}`);
    },
  }));
  hookSymbolBySubstr("libezstreamclient.so", "_ZN15CTransferClient16CloudReplayStart", (name) => ({
    onEnter(args) {
      console.log(`[transfer] ${name} this=${args[0]} serverInfo=${args[1]} replayInfo=${args[2]}`);
      dumpBytes("transfer-cloudreplay-server-info", args[1], 128);
      dumpBytes("transfer-cloudreplay-info", args[2], 512);
    },
    onLeave(retval) {
      console.log(`[transfer] ${name} ret=${retval.toInt32()}`);
    },
  }));
  hookSymbolBySubstr("libezstreamclient.so", "CASClient_CloudReplayStart", (name) => ({
    onEnter(args) {
      console.log(`[cas] ${name} args=${args[0]} ${args[1]} ${args[2]} ${args[3]}`);
    },
    onLeave(retval) {
      console.log(`[cas] ${name} ret=${retval.toInt32()}`);
    },
  }));
  hookSymbolBySubstr("libezstreamclient.so", "_ZN11CRecvClient18OpenCloudStreamReq", (name) => ({
    onEnter(args) {
      console.log(`[recv-client] ${name} this=${args[0]} cloudInfo=${args[1]}`);
      dumpBytes("recv-open-cloud-info", args[1], 512);
    },
    onLeave(retval) {
      console.log(`[recv-client] ${name} ret=${retval.toInt32()}`);
    },
  }));
  hookSymbolBySubstr("libezstreamclient.so", "_ZN11CRecvClient14SendTCPCtrlReq", (name) => ({
    onEnter(args) {
      const len = args[2].toInt32();
      console.log(`[recv-client] ${name} len=${len} text=${args[1].readUtf8String(Math.min(len, 4096))}`);
      dumpBytes("recv-send-tcp-ctrl", args[1], len);
    },
    onLeave(retval) {
      console.log(`[recv-client] ${name} ret=${retval.toInt32()}`);
    },
  }));
  hookSymbolBySubstr("libezstreamclient.so", "_ZN11CRecvClient14SendUDPCtrlReq", (name) => ({
    onEnter(args) {
      const len = args[2].toInt32();
      console.log(`[recv-client] ${name} len=${len} text=${args[1].readUtf8String(Math.min(len, 4096))}`);
      dumpBytes("recv-send-udp-ctrl", args[1], len);
    },
    onLeave(retval) {
      console.log(`[recv-client] ${name} ret=${retval.toInt32()}`);
    },
  }));
  hookSymbolBySubstr("libezstreamclient.so", "_ZN11CRecvClient7SendMsgEiPKcib", (name) => ({
    onEnter(args) {
      const cmd = args[1].toInt32();
      const len = args[3].toInt32();
      console.log(
        `[recv-client] ${name} this=${args[0]} cmd=${cmd} len=${len} reliable=${args[4].toInt32()} text=${redactXmlToken(args[2].readUtf8String(Math.min(len, 4096)))}`,
      );
      dumpBytes("recv-client-sendmsg", args[2], len);
    },
    onLeave(retval) {
      console.log(`[recv-client] ${name} ret=${retval.toInt32()}`);
    },
  }));
  hookSymbolBySubstr("libezstreamclient.so", "_ZN11CRecvClient11RecvOnePack", (name) => ({
    onEnter(args) {
      this.buf = args[1];
      this.lenPtr = args[2];
      this.cmdPtr = args[3];
    },
    onLeave(retval) {
      if (retval.toInt32() < 0) {
        return;
      }
      let len = 0;
      let cmd = 0;
      try {
        len = this.lenPtr.readS32();
        cmd = this.cmdPtr.readS32();
      } catch (err) {
        return;
      }
      if (len > 0) {
        console.log(`[recv-client] ${name} ret=${retval.toInt32()} cmd=${cmd} len=${len} hex=${bytesToHex(this.buf, len)}`);
        dumpBytes("recv-client-recv-one-pack", this.buf, len);
      }
    },
  }));
  hookSymbolBySubstr("libezstreamclient.so", "_ZN11CRecvClient14RecvTCPCtrlRsp", (name) => ({
    onEnter(args) {
      const len = args[2].toInt32();
      console.log(`[recv-client] ${name} len=${len} text=${redactXmlToken(args[1].readUtf8String(Math.min(len, 4096)))}`);
      dumpBytes("recv-client-tcp-ctrl-rsp", args[1], len);
    },
    onLeave(retval) {
      console.log(`[recv-client] ${name} ret=${retval.toInt32()}`);
    },
  }));
  hookSymbolBySubstr("libezstreamclient.so", "_ZN11CRecvClient22ProcOpenCloudStreamRsp", (name) => ({
    onEnter(args) {
      console.log(`[recv-client] ${name} this=${args[0]}`);
    },
    onLeave(retval) {
      console.log(`[recv-client] ${name} ret=${retval.toInt32()}`);
    },
  }));
  for (const [label, symbol] of [
    [
      "CChipParser::CreateReadFromCloudCenterReq",
      "_ZN11CChipParser28CreateReadFromCloudCenterReqERNSt6__ndk112basic_stringIcNS0_11char_traitsIcEENS0_9allocatorIcEEEE19ST_CLOUDREPLAY_INFO",
    ],
    [
      "CJsonParser::CreateReadFromCloudCenterReq",
      "_ZN11CJsonParser28CreateReadFromCloudCenterReqERNSt6__ndk112basic_stringIcNS0_11char_traitsIcEENS0_9allocatorIcEEEE17ST_CLOUDPLAY_INFO",
    ],
  ]) {
    hookExportExact("libezstreamclient.so", symbol, label, () => ({
      onEnter(args) {
        this.out = args[1];
        this.info = args[2];
        console.log(`[cloud-parser] ${label} this=${args[0]} out=${this.out} info=${this.info}`);
        dumpBytes(`cloud-parser-info-${label.split("::")[0]}`, this.info, 512);
      },
      onLeave(retval) {
        dumpBytes(`cloud-parser-out-${label.split("::")[0]}`, this.out, Math.max(retval.toInt32(), 768));
        dumpPointerCandidates(`cloud-parser-out-${label.split("::")[0]}`, this.out, 160);
        console.log(`[cloud-parser] ${label} ret=${retval.toInt32()} out=${redactXmlToken(readStdString(this.out))}`);
      },
    }));
  }
  hookExportExact(
    "libezstreamclient.so",
    "_ZN11CChipParser27ParseReadFromCloudCenterRspEPKcRi",
    "CChipParser::ParseReadFromCloudCenterRsp",
    () => ({
      onEnter(args) {
        console.log(`[cloud-parser] CChipParser::ParseReadFromCloudCenterRsp text=${redactXmlToken(args[1].readUtf8String(4096))}`);
        dumpBytes("cloud-parser-read-rsp", args[1], 4096);
      },
      onLeave(retval) {
        console.log(`[cloud-parser] CChipParser::ParseReadFromCloudCenterRsp ret=${retval.toInt32()}`);
      },
    }),
  );
  hookSymbolBySubstr("libezstreamclient.so", "_ZN11CloudClient16StartCloudReplay", (name) => ({
    onEnter(args) {
      console.log(
        `[cloud-client] ${name} this=${args[0]} session=${args[1]} sessionLen=${args[2].toInt32()} info=${args[3]} arg4=${args[4].toInt32()}`,
      );
      dumpBytes("cloud-client-session", args[1], args[2].toInt32());
      dumpBytes("cloud-client-info", args[3], 512);
    },
    onLeave(retval) {
      console.log(`[cloud-client] ${name} ret=${retval.toInt32()}`);
    },
  }));
}

function hookStreamProtocolProtobuf() {
  const protoSerializers = [
    ["PeerStreamReq", "_ZNK3hik2ys14streamprotocol13PeerStreamReq24SerializeWithCachedSizesEPN6google8protobuf2io17CodedOutputStreamE"],
    ["StreamInfoReq", "_ZNK3hik2ys14streamprotocol13StreamInfoReq24SerializeWithCachedSizesEPN6google8protobuf2io17CodedOutputStreamE"],
    ["StartPlayBackReq", "_ZNK3hik2ys14streamprotocol16StartPlayBackReq24SerializeWithCachedSizesEPN6google8protobuf2io17CodedOutputStreamE"],
    ["GetPlayBackVtduInfoReq", "_ZNK3hik2ys14streamprotocol22GetPlayBackVtduInfoReq24SerializeWithCachedSizesEPN6google8protobuf2io17CodedOutputStreamE"],
  ];
  for (const [label, symbol] of protoSerializers) {
    hookExportExact("libezstreamclient.so", symbol, `${label}::SerializeWithCachedSizes`, () => ({
      onEnter(args) {
        pushProto(label, args[0]);
      },
      onLeave() {
        popProto();
      },
    }));
  }

  hookExportExact(
    "libezstreamclient.so",
    "_ZN6google8protobuf8internal14WireFormatLite11WriteStringEiRKNSt6__ndk112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEPNS0_2io17CodedOutputStreamE",
    "WireFormatLite::WriteString",
    () => ({
      onEnter(args) {
        const ctx = activeProto();
        if (!ctx) {
          return;
        }
        const field = args[0].toInt32();
        const raw = readStdString(args[1]);
        console.log(`[proto-field] ${ctx.name}.${field}=string ${redactProtoField(ctx, field, raw)}`);
      },
    }),
  );
  hookExportExact(
    "libezstreamclient.so",
    "_ZN6google8protobuf8internal14WireFormatLite23WriteStringMaybeAliasedEiRKNSt6__ndk112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEPNS0_2io17CodedOutputStreamE",
    "WireFormatLite::WriteStringMaybeAliased",
    () => ({
      onEnter(args) {
        const ctx = activeProto();
        if (!ctx) {
          return;
        }
        const field = args[0].toInt32();
        const raw = readStdString(args[1]);
        console.log(`[proto-field] ${ctx.name}.${field}=string ${redactProtoField(ctx, field, raw)}`);
      },
    }),
  );
  for (const [label, symbol] of [
    ["WireFormatLite::WriteInt32", "_ZN6google8protobuf8internal14WireFormatLite10WriteInt32EiiPNS0_2io17CodedOutputStreamE"],
    ["WireFormatLite::WriteUInt32", "_ZN6google8protobuf8internal14WireFormatLite11WriteUInt32EijPNS0_2io17CodedOutputStreamE"],
    ["WireFormatLite::WriteBool", "_ZN6google8protobuf8internal14WireFormatLite9WriteBoolEibPNS0_2io17CodedOutputStreamE"],
  ]) {
    hookExportExact("libezstreamclient.so", symbol, label, () => ({
      onEnter(args) {
        const ctx = activeProto();
        if (!ctx) {
          return;
        }
        console.log(`[proto-field] ${ctx.name}.${args[0].toInt32()}=varint ${args[1].toInt32()}`);
      },
    }));
  }
}

function hookSrtIo() {
  for (const name of ["srt_sendmsg", "srt_recvmsg"]) {
    const addr = findGlobalExport(name);
    if (addr === null) {
      continue;
    }
    hookFunction(addr, `global!${name}`, {
      onEnter(args) {
        this.name = name;
        if (name === "srt_sendmsg") {
          const len = args[2].toInt32();
          console.log(`[srt] ${name} fd=${args[0].toInt32()} len=${len} hex=${bytesToHex(args[1], len)}`);
          dumpBytes(name, args[1], len);
        } else {
          this.buf = args[1];
        }
      },
      onLeave(retval) {
        if (this.name === "srt_recvmsg" && retval.toInt32() > 0) {
          const len = retval.toInt32();
          console.log(`[srt] ${this.name} ret=${len} hex=${bytesToHex(this.buf, len)}`);
          dumpBytes(this.name, this.buf, len);
        }
      },
    });
  }
}

function installHooks() {
  hookLibcIo();
  hookMbedtlsIo();
  hookHprIo();
  hookSrtIo();
  hookEzstreamCloud();
  hookStreamProtocolProtobuf();
}

Java.perform(() => {
  const JSONObject = Java.use("org.json.JSONObject");
  const ActivityThread = Java.use("android.app.ActivityThread");
  const EZStreamClientManager = Java.use("com.ez.stream.EZStreamClientManager");
  const DownloadCloudParam = Java.use("com.ez.stream.DownloadCloudParam");
  const EZStreamCallback = Java.use("com.ez.stream.EZStreamCallback");
  const FileCls = Java.use("java.io.File");
  const BufferedOutputStream = Java.use("java.io.BufferedOutputStream");
  const FileOutputStream = Java.use("java.io.FileOutputStream");
  const Thread = Java.use("java.lang.Thread");

  const app = ActivityThread.currentApplication();
  if (!app) {
    throw new Error("currentApplication is null");
  }

  dumpDir = ensureDir(app.getExternalFilesDir(null), "ezviz-cloud-socket-trace").getAbsolutePath().toString();
  installHooks();
  setInterval(installHooks, 1000);

  const inputFile = FileCls.$new(app.getExternalFilesDir(null), INPUT_NAME);
  const input = JSONObject.$new(readText(inputFile.getAbsolutePath().toString()));
  const video = input.getJSONObject("video");
  const serial = jsonString(input, "serial", video.optString("devSerial"));
  const channel = jsonInt(input, "channel", video.optInt("channelNo", 1));
  const ticket = jsonString(input, "ticket", "");
  const outputName = jsonString(input, "outputName", `cloud-${serial}-${video.getLong("seqId")}`);

  const streamUrl = video.getString("streamUrl").toString();
  const streamParts = streamUrl.split(":");
  const server = jsonString(video, "alternateIp", streamParts[0]);
  const port = streamParts.length > 1 ? parseInt(streamParts[1], 10) : 0;
  const startMillis = jsonLong(input, "startMillis", 0);
  const stopMillis = jsonLong(input, "stopMillis", startMillis + jsonLong(video, "videoLong", 0));
  const outDir = ensureDir(app.getExternalFilesDir(null), "ezviz-direct-download");
  const tmpFile = FileCls.$new(outDir, `${outputName}.tmp`);

  let stream = null;
  let total = 0;
  const Callback = Java.registerClass({
    name: `com.openclaw.EzvizCloudTraceDownloadCallback${RUN_ID}`,
    implements: [EZStreamCallback],
    methods: {
      onDataCallBack(dataType, data, len) {
        console.log(`[direct-download] data type=${dataType} len=${len}`);
        if ((dataType === 1 || dataType === 2) && data !== null && len > 0) {
          if (stream === null) {
            stream = BufferedOutputStream.$new(FileOutputStream.$new(tmpFile));
            console.log(`[direct-download] writing tmp=${tmpFile.getAbsolutePath()}`);
          }
          stream.write(data, 0, len);
          total += len;
        } else if (dataType === 100) {
          if (stream !== null) {
            stream.flush();
            stream.close();
            stream = null;
          }
          console.log(`[direct-download] end total=${total} tmp=${tmpFile.getAbsolutePath()}`);
        }
      },
      onMessageCallBack(msg, result) {
        console.log(`[direct-download] message msg=${msg} result=${result}`);
      },
      onStatisticsCallBack(statisticsType, statistics) {
        console.log(`[direct-download] statistics type=${statisticsType} value=${statistics}`);
      },
    },
  });

  const manager = EZStreamClientManager.create.overload("android.content.Context").call(EZStreamClientManager, app);
  if (manager === null) {
    throw new Error("EZStreamClientManager.create returned null");
  }
  const client = manager.createCASClient();
  if (client === null) {
    throw new Error("createCASClient returned null");
  }
  client.setCallback(Callback.$new());

  const param = DownloadCloudParam.$new();
  param.iFileType.value = jsonInt(video, "fileType", 1);
  param.iStreamType.value = 0;
  param.iPlayType.value = 2;
  param.szAuthorization.value = "";
  param.szFileID.value = String(video.getLong("seqId"));
  param.iFrontType.value = 2;
  param.iVideoType.value = jsonInt(video, "videoType", 2);
  param.iStorageVersion.value = jsonInt(video, "storageVersion", 1);
  param.szBeginTime.value = input.has("beginCas") ? input.getString("beginCas") : formatCasTime(startMillis);
  param.szEndTime.value = input.has("endCas") ? input.getString("endCas") : formatCasTime(stopMillis);
  param.szServerIP.value = server;
  param.iServerPort.value = port;
  param.szCamera.value = `${serial}_${channel}`;
  param.szClientSession.value = "";
  param.szTicketToken.value = ticket;
  param.iBusType.value = 2;
  param.iChannelNumber.value = channel;
  param.iPlaySpeed.value = 0;
  param.iInterlaceFlag.value = 0;

  console.log(
    `[direct-download] start server=${server}:${port} camera=${param.szCamera.value} fileId=${param.szFileID.value} begin=${param.szBeginTime.value} end=${param.szEndTime.value} ticketLen=${ticket.length} dumpDir=${dumpDir}`,
  );
  const ret = client.startDownloadFromCloud(param);
  console.log(`[direct-download] startDownloadFromCloud ret=${ret}`);

  Thread.$new(
    Java.registerClass({
      name: `com.openclaw.EzvizCloudTraceDownloadStopper${RUN_ID}`,
      implements: [Java.use("java.lang.Runnable")],
      methods: {
        run() {
          Thread.sleep(RUN_MS);
          try {
            client.stopDownloadFromCloud();
          } catch (err) {
            console.log(`[direct-download] stop failed ${err}`);
          }
          try {
            client.release();
          } catch (err) {
            console.log(`[direct-download] release failed ${err}`);
          }
          if (stream !== null) {
            stream.flush();
            stream.close();
            stream = null;
          }
          console.log(`[direct-download] done total=${total} tmp=${tmpFile.getAbsolutePath()}`);
        },
      },
    }).$new(),
  ).start();
});
