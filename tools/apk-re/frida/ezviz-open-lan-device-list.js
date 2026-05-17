"use strict";

/*
 * Internal EZVIZ LAN Live View navigator.
 *
 * Android blocks shell-launched entry into these non-exported activities. This
 * helper runs inside the EZVIZ process and starts the LAN device list with the
 * app's own current Activity context. It does not inspect credentials or device
 * fields; pair it with ezviz-lan-settings-capture.js when capture is needed.
 */

function log(message) {
  console.log("[lan-open] " + message);
}

function startActivity(activity, targetClassName) {
  const Intent = Java.use("android.content.Intent");
  const Target = Java.use(targetClassName);
  const intent = Intent.$new(activity, Target.class);
  if (!Java.cast(activity, Java.use("android.content.Context")).getClass().getName().endsWith("Activity")) {
    intent.addFlags(0x10000000);
  }
  activity.startActivity(intent);
}

function currentActivity() {
  try {
    const CurrentActivity = Java.use("defpackage.ro");
    const activity = CurrentActivity.b();
    if (activity) return activity;
  } catch (e) {
    log("ro.b failed " + e);
  }

  const ActivityThread = Java.use("android.app.ActivityThread");
  const app = ActivityThread.currentApplication();
  if (!app) return null;
  return app;
}

Java.perform(function() {
  Java.scheduleOnMainThread(function() {
    try {
      const activity = currentActivity();
      if (!activity) {
        log("no Activity/application context available");
        return;
      }
      log("context=" + activity.getClass().getName());
      startActivity(activity, "com.videogo.add.landevice.LanDeviceListActivity");
      log("started LanDeviceListActivity");
    } catch (e) {
      log("start failed " + e);
    }
  });
});
