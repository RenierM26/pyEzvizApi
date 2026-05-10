/*
 * Run EZVIZ TransformUtils.trans(TransFormat.PS, ...) for a captured
 * cloud-download .tmp file. Input is read from the app external-files JSON:
 *   /sdcard/Android/data/com.ezviz/files/ezviz-cloud-download-input.json
 *
 * Expected fields: outputName, secretKey.
 */

"use strict";

const INPUT_NAME = "ezviz-cloud-download-input.json";

function readText(path) {
  const File = Java.use("java.io.File");
  const FileInputStream = Java.use("java.io.FileInputStream");
  const ByteArrayOutputStream = Java.use("java.io.ByteArrayOutputStream");
  const buffer = Java.array("byte", Array(4096).fill(0));
  const input = FileInputStream.$new(File.$new(path));
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

function ensureDir(base, child) {
  const File = Java.use("java.io.File");
  const dir = File.$new(base, child);
  dir.mkdirs();
  return dir;
}

Java.perform(() => {
  const JSONObject = Java.use("org.json.JSONObject");
  const ActivityThread = Java.use("android.app.ActivityThread");
  const TransformUtils = Java.use("com.ezplayer.utils.TransformUtils");
  const TransFormat = Java.use("com.ezplayer.stream.TransFormat");
  const File = Java.use("java.io.File");

  const app = ActivityThread.currentApplication();
  if (!app) {
    throw new Error("currentApplication is null");
  }
  const inputFile = File.$new(app.getExternalFilesDir(null), INPUT_NAME);
  const input = JSONObject.$new(readText(inputFile.getAbsolutePath().toString()));
  const outputName = input.getString("outputName").toString();
  const secretKey = input.getString("secretKey").toString();
  const outDir = ensureDir(app.getExternalFilesDir(null), "ezviz-direct-download");
  const src = File.$new(outDir, `${outputName}.tmp`).getAbsolutePath().toString();
  const dst = File.$new(outDir, `${outputName}.ps`).getAbsolutePath().toString();
  let transform = null;
  try {
    transform = TransformUtils.INSTANCE.value;
  } catch (err) {
    transform = null;
  }
  if (transform === null) {
    transform = TransformUtils.$new();
  }

  console.log(`[direct-transform] src=${src} dst=${dst} secretLen=${secretKey.length}`);
  const ret = transform.trans(TransFormat.valueOf("PS"), src, dst, secretKey, false, -1, false, null);
  console.log(`[direct-transform] ret=${ret} dst=${dst}`);
});
