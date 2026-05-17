"use strict";

/*
 * Trigger the LAN Live View login path for a discovered camera.
 *
 * This constructs the same LanDeviceInfo shape the SADP list produced and lets
 * LanDeviceListActivity.M0(...) call the presenter. The password is read by the
 * app's own DevPwdUtil store and is never printed.
 */

const TARGET_SERIAL = "CS-CV310-A0-1B2WFR0120200927CCRRFAKE001";
const TARGET_IP = "192.0.2.47";
const FIRST_DELAY_MS = 5000;
const RETRY_DELAY_MS = 3000;
const MAX_ATTEMPTS = 20;

function log(message) {
  console.log("[lan-trigger] " + message);
}

function trigger(activity) {
  const LanDeviceInfo = Java.use("com.videogo.device.LanDeviceInfo");
  const DevPwdUtil = Java.use("com.videogo.util.DevPwdUtil");
  const device = LanDeviceInfo.$new();
  const pwd = DevPwdUtil.c(TARGET_SERIAL);

  device.setSzSerialNO(TARGET_SERIAL);
  device.setSzIPv4Address(TARGET_IP);
  device.setDwPort(8000);
  device.setDwSDKOverTLSPort(0);
  device.setLoginName("admin");
  device.setLoginPwd(pwd);
  device.setByActivated(1);
  device.setByEZVIZCode(1);

  log("calling M0 serial=" + TARGET_SERIAL + " ip=" + TARGET_IP + ":8000 pwdLen=" + String(pwd).length);
  activity.M0(device);
}

function tryTrigger(attempt) {
  Java.scheduleOnMainThread(function() {
    let called = false;
    Java.choose("com.videogo.add.landevice.LanDeviceListActivity", {
      onMatch: function(activity) {
        if (called) return;
        called = true;
        trigger(activity);
      },
      onComplete: function() {
        if (called) return;
        if (attempt >= MAX_ATTEMPTS) {
          log("LanDeviceListActivity instance not found after attempts=" + attempt);
          return;
        }
        log("LanDeviceListActivity instance not found attempt=" + attempt);
        setTimeout(function() {
          tryTrigger(attempt + 1);
        }, RETRY_DELAY_MS);
      },
    });
  });
}

Java.perform(function() {
  setTimeout(function() {
    tryTrigger(1);
  }, FIRST_DELAY_MS);
});
