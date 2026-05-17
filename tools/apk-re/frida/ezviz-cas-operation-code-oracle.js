"use strict";

/*
 * Invoke the app's native CAS getDevOperationCodeEx path for one serial and
 * print only non-secret shapes. This tells us which inputs the app uses without
 * exposing session IDs, hardware codes, operation codes, or keys.
 */

const TARGET_SERIAL_VALUE = "FAKE001";

function s(value) {
  try {
    return value === null || value === undefined ? "" : value.toString();
  } catch (e) {
    return "<toString:" + e + ">";
  }
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

function sha256Prefix(value) {
  try {
    const MessageDigest = Java.use("java.security.MessageDigest");
    const StringCls = Java.use("java.lang.String");
    const digest = MessageDigest.getInstance("SHA-256");
    const bytes = StringCls.$new(s(value)).getBytes("UTF-8");
    const out = digest.digest(bytes);
    let hex = "";
    for (let i = 0; i < out.length && i < 6; i++) {
      const b = out[i] & 0xff;
      hex += ("0" + b.toString(16)).slice(-2);
    }
    return hex;
  } catch (e) {
    return "";
  }
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
  try {
    castInfo = Java.cast(info, STDevInfo);
  } catch (e) {
    castInfo = info;
  }
  const serial = fieldValue(castInfo, "szDevSerial");
  const operationCode = fieldValue(castInfo, "szOperationCode");
  const key = fieldValue(castInfo, "szKey");
  const encryptType = fieldValue(castInfo, "enEncryptType");
  return {
    present: true,
    className: s(castInfo.$className || info.$className || info.getClass()),
    serial: s(serial),
    operationCodeLen: s(operationCode).length,
    keyLen: s(key).length,
    encryptType: Number(s(encryptType)),
  };
}

function emit(obj) {
  console.log("[cas-oracle-json] " + JSON.stringify(obj));
}

function firstCallable(obj, names) {
  for (const name of names) {
    try {
      if (typeof obj[name] === "function") {
        return { name: name, value: obj[name]() };
      }
    } catch (e) {
      return { name: name, error: s(e) };
    }
  }
  return { name: null, error: "no callable candidate" };
}

function resolveHost(host) {
  try {
    const InetAddress = Java.use("java.net.InetAddress");
    return s(InetAddress.getByName(host).getHostAddress());
  } catch (e) {
    return host;
  }
}

Java.perform(function() {
  try {
    const GlobalHolder = Java.use("com.ezplayer.common.GlobalHolder");
    const CASClient = Java.use("com.hc.CASClient.CASClient");
    const STServerInfo = Java.use("com.hc.CASClient.ST_SERVER_INFO");
    const STDevInfo = Java.use("com.hc.CASClient.ST_DEV_INFO");
    const ArrayList = Java.use("java.util.ArrayList");
    const StringArray = Java.array("java.lang.String", [TARGET_SERIAL_VALUE]);

    const holder = GlobalHolder.INSTANCE.value;
    const globalParam = holder.getGlobalParam();
    const session = firstCallable(globalParam, [
      "getSessionId",
      "getSessionId$library_fullRelease",
      "getSessionId$library_fullRelease$default",
    ]);
    if (session.error) {
      throw new Error("could not obtain session id via " + session.name + ": " + session.error);
    }
    const sessionId = session.value;
    const hardwareCode = globalParam.getHardwareCode();
    const serviceHost = "eucas.ezvizlife.com";
    const serviceIp = resolveHost(serviceHost);

    const server = STServerInfo.$new();
    server.szServerIP.value = serviceIp;
    server.nServerPort.value = 6500;

    const out = ArrayList.$new();
    const client = CASClient.getInstance();
    const ok = client.getDevOperationCodeEx(server, sessionId, hardwareCode, StringArray, 1, out);
    let first = null;
    if (out.size() > 0) first = out.get(0);
    emit({
      ok: !!ok,
      lastError: client.getLastError(),
      serial: TARGET_SERIAL_VALUE,
      serverHost: serviceHost,
      serverIp: s(serviceIp),
      serverPort: 6500,
      sessionMethod: session.name,
      session: shape("session", sessionId),
      sessionSha256Prefix: sha256Prefix(sessionId),
      hardware: shape("hardware", hardwareCode),
      hardwareSha256Prefix: sha256Prefix(hardwareCode),
      outSize: out.size(),
      first: devInfoShape(first, STDevInfo),
    });
  } catch (e) {
    emit({ ok: false, error: s(e), stack: e && e.stack ? s(e.stack) : "" });
  }
});
