/*
 * Trigger a single EZVIZ cloud-storage download through the in-app native SDK.
 *
 * Input is read from the app external-files ezviz-cloud-download-input.json so
 * tickets/secrets do not need to be embedded in this script. Expected fields:
 * serial, channel, ticket, video, startMillis, stopMillis, outputName.
 */

"use strict";

const INPUT_NAME = "ezviz-cloud-download-input.json";
const RUN_MS = 25000;
const RUN_ID = Date.now();

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
  const Date = Java.use("java.util.Date");
  const SimpleDateFormat = Java.use("java.text.SimpleDateFormat");
  const formatter = SimpleDateFormat.$new("yyyyMMdd'T'HHmmss'Z'", Locale.US.value);
  return formatter.format(Date.$new(ms)).toString();
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
  const EZStreamClientManager = Java.use("com.ez.stream.EZStreamClientManager");
  const DownloadCloudParam = Java.use("com.ez.stream.DownloadCloudParam");
  const EZStreamCallback = Java.use("com.ez.stream.EZStreamCallback");
  const File = Java.use("java.io.File");
  const BufferedOutputStream = Java.use("java.io.BufferedOutputStream");
  const FileOutputStream = Java.use("java.io.FileOutputStream");
  const Thread = Java.use("java.lang.Thread");

  const app = ActivityThread.currentApplication();
  if (!app) {
    throw new Error("currentApplication is null");
  }

  const inputFile = File.$new(app.getExternalFilesDir(null), INPUT_NAME);
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
  const tmpFile = File.$new(outDir, `${outputName}.tmp`);

  let stream = null;
  let total = 0;
  const Callback = Java.registerClass({
    name: `com.openclaw.EzvizCloudDownloadCallback${RUN_ID}`,
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
    `[direct-download] start server=${server}:${port} camera=${param.szCamera.value} fileId=${param.szFileID.value} begin=${param.szBeginTime.value} end=${param.szEndTime.value} ticketLen=${ticket.length}`,
  );
  const ret = client.startDownloadFromCloud(param);
  console.log(`[direct-download] startDownloadFromCloud ret=${ret}`);

  Thread.$new(
    Java.registerClass({
      name: `com.openclaw.EzvizCloudDownloadStopper${RUN_ID}`,
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
