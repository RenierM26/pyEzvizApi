"use strict";

/*
 * Narrow EZVIZ LAN Live View settings hook.
 *
 * This deliberately avoids the broad native/local-stream hooks that can make a
 * late attach heavy. It captures only the settings-screen credential flow:
 *
 * - DevPwdUtil LAN password load/save/clear
 * - AddMD5Util.a(...) fallback derivation shape
 * - LanDeviceListPresenter.o(...) candidate path flags
 * - HCNETUtil.s(...) login attempts
 * - HCNETUtil.d/c(...) servicesSwitch read/write
 *
 * Passwords are never printed. Logs include only lengths and in-memory equality
 * labels, enough to prove value flow without preserving credentials.
 */

const rememberedSecrets = {};

function s(value) {
  if (value === null || value === undefined) return "";
  try {
    return String(value);
  } catch (e) {
    return "<string-failed:" + e + ">";
  }
}

function rememberSecret(label, value) {
  const text = s(value);
  if (!text) return "";
  rememberedSecrets[label] = text;
  return " remembered=" + label;
}

function secretMatch(value) {
  const text = s(value);
  if (!text) return "none";
  const labels = [];
  Object.keys(rememberedSecrets).forEach(function(label) {
    if (rememberedSecrets[label] === text) labels.push(label);
  });
  return labels.length ? labels.join("|") : "none";
}

function boolShape(value) {
  if (value === null || value === undefined) return "<null>";
  try {
    if (value.booleanValue) return String(value.booleanValue());
  } catch (e) {}
  return s(value);
}

function fieldValue(obj, name) {
  try {
    const field = obj[name];
    if (field === undefined || field === null) return "";
    return s(field.value);
  } catch (e) {
    return "<" + name + " failed:" + e + ">";
  }
}

function describeInitParam(param) {
  if (!param) return "<null>";
  return [
    "source=" + fieldValue(param, "iStreamSource"),
    "dev=" + fieldValue(param, "szDevSerial"),
    "channel=" + fieldValue(param, "iChannelNumber"),
    "netSdkChannel=" + fieldValue(param, "iNetSDKChannelNumber"),
    "netSdkUser=" + fieldValue(param, "iNetSDKUserId"),
    "local=" + fieldValue(param, "szDevLocalIP") + ":" + fieldValue(param, "iDevCmdLocalPort") + "/" + fieldValue(param, "iDevStreamLocalPort"),
    "remote=" + fieldValue(param, "szDevIP") + ":" + fieldValue(param, "iDevCmdPort") + "/" + fieldValue(param, "iDevStreamPort"),
    "streamType=" + fieldValue(param, "iStreamType"),
    "videoLevel=" + fieldValue(param, "iVideoLevel"),
    "inhibit=" + fieldValue(param, "iStreamInhibit"),
  ].join(" ");
}

function hookAllOverloads(label, klass, method, before, after) {
  if (!klass || !klass[method]) {
    console.log(label + " unavailable");
    return;
  }
  klass[method].overloads.forEach(function(ov) {
    ov.implementation = function() {
      const args = [].slice.call(arguments);
      let state = null;
      try {
        if (before) state = before.call(this, args, ov);
      } catch (e) {
        console.log(label + " before failed " + e);
      }
      const ret = ov.apply(this, args);
      try {
        if (after) after.call(this, args, ret, state, ov);
      } catch (e) {
        console.log(label + " after failed " + e);
      }
      return ret;
    };
  });
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
    parts.push("pwdLen=" + pwd.length + rememberSecret("lanDevicePwd:" + serial, pwd));
  } catch (e) {
    parts.push("pwd=<failed:" + e + ">");
  }
  try { parts.push("loginId=" + s(device.getLoginId())); } catch (e) {}
  return " lanDevice={" + parts.join(" ") + "}";
}

function servicesSwitchShape(obj) {
  if (!obj) return " servicesSwitch=<null>";
  try {
    const services = obj.optJSONObject("servicesSwitch");
    if (!services) return " servicesSwitch=<missing>";
    const hiksdk = services.has("hiksdk") ? services.opt("hiksdk") : "<missing>";
    const web = services.has("web") ? services.opt("web") : "<missing>";
    return " servicesSwitch={hiksdk=" + s(hiksdk) + " web=" + s(web) + "}";
  } catch (e) {
    return " servicesSwitch=<shape-failed:" + e + ">";
  }
}

function deviceInfoExShape(obj) {
  if (!obj) return " deviceInfoEx=<null>";
  const parts = [];
  try { parts.push("serial=" + s(obj.getDeviceSerial())); } catch (e) { parts.push("serial=<failed:" + e + ">"); }
  try { parts.push("loginId=" + s(obj.getLoginID())); } catch (e) { parts.push("loginId=<failed:" + e + ">"); }
  try { parts.push("local=" + s(obj.isLocalDevice())); } catch (e) {}
  try { parts.push("lastLogin=" + s(obj.getLastLoginStatus())); } catch (e) {}
  try {
    const LanDeviceInfo = Java.use("com.videogo.device.LanDeviceInfo");
    const field = obj.class.getDeclaredField("landevice");
    field.setAccessible(true);
    const rawLanDevice = field.get(obj);
    parts.push(lanDeviceShape(rawLanDevice ? Java.cast(rawLanDevice, LanDeviceInfo) : null));
  } catch (e) {
    parts.push("lanDevice=<unavailable:" + e + ">");
  }
  return " deviceInfoEx={" + parts.join(" ") + "}";
}

function installHooks() {
  Java.perform(function() {
    try {
      const DevPwdUtil = Java.use("com.videogo.util.DevPwdUtil");
      hookAllOverloads("[lan-settings] DevPwdUtil.c", DevPwdUtil, "c", function(args) {
        console.log("[lan-settings] DevPwdUtil.c enter serial=" + s(args[0]));
      }, function(args, ret) {
        const pwd = s(ret);
        console.log("[lan-settings] DevPwdUtil.c leave serial=" + s(args[0])
          + " pwdLen=" + pwd.length
          + rememberSecret("devPwdStore:" + s(args[0]), pwd));
      });
      hookAllOverloads("[lan-settings] DevPwdUtil.j", DevPwdUtil, "j", function(args) {
        const pwd = s(args[1]);
        console.log("[lan-settings] DevPwdUtil.j enter serial=" + s(args[0])
          + " pwdLen=" + pwd.length
          + " match=" + secretMatch(pwd)
          + rememberSecret("devPwdSave:" + s(args[0]), pwd));
      });
      hookAllOverloads("[lan-settings] DevPwdUtil.h", DevPwdUtil, "h", function(args) {
        console.log("[lan-settings] DevPwdUtil.h enter serial=" + s(args[0]));
      });
    } catch (e) {
      console.log("[lan-settings] DevPwdUtil hooks unavailable " + e);
    }

    try {
      const AddMD5Util = Java.use("com.videogo.util.AddMD5Util");
      hookAllOverloads("[lan-settings] AddMD5Util.a", AddMD5Util, "a", function(args) {
        const pwd = s(args[0]);
        console.log("[lan-settings] AddMD5Util.a enter inputLen=" + pwd.length
          + " match=" + secretMatch(pwd));
      }, function(args, ret) {
        const derived = s(ret);
        console.log("[lan-settings] AddMD5Util.a leave outputLen=" + derived.length
          + rememberSecret("addMd5:" + s(args[0]).length, derived));
      });
    } catch (e) {
      console.log("[lan-settings] AddMD5Util hook unavailable " + e);
    }

    try {
      const LanDeviceInfo = Java.use("com.videogo.device.LanDeviceInfo");
      ["setLoginName", "setLoginPwd", "setSzIPv4Address", "setDwPort", "setSzSerialNO"].forEach(function(name) {
        hookAllOverloads("[lan-settings] LanDeviceInfo." + name, LanDeviceInfo, name, function(args) {
          if (name === "setLoginPwd") {
            const pwd = s(args[0]);
            console.log("[lan-settings] LanDeviceInfo." + name + " enter pwdLen=" + pwd.length
              + " match=" + secretMatch(pwd)
              + rememberSecret("lanInfoSetPwd", pwd));
          } else {
            console.log("[lan-settings] LanDeviceInfo." + name + " enter value=" + s(args[0]));
          }
        }, function() {
          console.log("[lan-settings] LanDeviceInfo." + name + " leave" + lanDeviceShape(this));
        });
      });
    } catch (e) {
      console.log("[lan-settings] LanDeviceInfo hooks unavailable " + e);
    }

    try {
      const Presenter = Java.use("com.videogo.add.landevice.LanDeviceListPresenter");
      hookAllOverloads("[lan-settings] LanDeviceListPresenter.o", Presenter, "o", function(args) {
        const pwd = s(args[2]);
        console.log("[lan-settings] LanDeviceListPresenter.o enter"
          + lanDeviceShape(args[0])
          + " user=" + s(args[1])
          + " pwdLen=" + pwd.length
          + " pwdMatch=" + secretMatch(pwd)
          + rememberSecret("presenterPwd", pwd)
          + " loginWith8443=" + boolShape(args[3])
          + " isOpen8000=" + boolShape(args[4]));
      });
      hookAllOverloads("[lan-settings] LanDeviceListPresenter.j", Presenter, "j", function(args) {
        console.log("[lan-settings] LanDeviceListPresenter.j enter deviceInfoEx=" + s(args[0]));
      });
    } catch (e) {
      console.log("[lan-settings] LanDeviceListPresenter hook unavailable " + e);
    }

    try {
      const Activity = Java.use("com.videogo.add.landevice.LanDeviceListActivity");
      hookAllOverloads("[lan-settings] LanDeviceListActivity.J", Activity, "J", function(args) {
        const pwd = s(args[2]);
        console.log("[lan-settings] LanDeviceListActivity.J enter loginId=" + s(args[1])
          + " pwdLen=" + pwd.length
          + " pwdMatch=" + secretMatch(pwd));
      });
      hookAllOverloads("[lan-settings] LanDeviceListActivity.M0", Activity, "M0", function(args) {
        console.log("[lan-settings] LanDeviceListActivity.M0 enter" + lanDeviceShape(args[0]));
      });
      hookAllOverloads("[lan-settings] LanDeviceListActivity.q", Activity, "q", function(args) {
        console.log("[lan-settings] LanDeviceListActivity.q enter errorCode=" + s(args[0]));
      });
      hookAllOverloads("[lan-settings] LanDeviceListActivity.searchDevice", Activity, "searchDevice", function() {
        console.log("[lan-settings] LanDeviceListActivity.searchDevice enter");
      });
    } catch (e) {
      console.log("[lan-settings] LanDeviceListActivity hook unavailable " + e);
    }

    try {
      const LanDeviceManage = Java.use("com.videogo.device.LanDeviceManage");
      hookAllOverloads("[lan-settings] LanDeviceManage.addDevice", LanDeviceManage, "addDevice", function(args) {
        console.log("[lan-settings] LanDeviceManage.addDevice enter" + lanDeviceShape(args[0]));
      });
      hookAllOverloads("[lan-settings] LanDeviceManage.addDeviceManual", LanDeviceManage, "addDeviceManual", function(args) {
        console.log("[lan-settings] LanDeviceManage.addDeviceManual enter" + lanDeviceShape(args[0]));
      });
      hookAllOverloads("[lan-settings] LanDeviceManage.updateDevice", LanDeviceManage, "updateDevice", function(args) {
        console.log("[lan-settings] LanDeviceManage.updateDevice enter loginId=" + s(args[1]));
      }, function(args, ret) {
        console.log("[lan-settings] LanDeviceManage.updateDevice leave" + lanDeviceShape(ret));
      });
    } catch (e) {
      console.log("[lan-settings] LanDeviceManage hooks unavailable " + e);
    }

    try {
      const DeviceInfoEx = Java.use("com.videogo.device.DeviceInfoEx");
      hookAllOverloads("[lan-settings] DeviceInfoEx.setLoginID", DeviceInfoEx, "setLoginID", function(args) {
        console.log("[lan-settings] DeviceInfoEx.setLoginID enter loginId=" + s(args[0])
          + deviceInfoExShape(this));
      }, function() {
        console.log("[lan-settings] DeviceInfoEx.setLoginID leave" + deviceInfoExShape(this));
      });
      hookAllOverloads("[lan-settings] DeviceInfoEx.loginPlayDevice", DeviceInfoEx, "loginPlayDevice", function(args) {
        console.log("[lan-settings] DeviceInfoEx.loginPlayDevice enter"
          + " caller=" + s(args[0])
          + " checkLastLoginStatus=" + boolShape(args[1])
          + deviceInfoExShape(this));
      }, function(args, ret) {
        console.log("[lan-settings] DeviceInfoEx.loginPlayDevice leave ret=" + s(ret)
          + deviceInfoExShape(this));
      });
      hookAllOverloads("[lan-settings] DeviceInfoEx.loginDevice", DeviceInfoEx, "loginDevice", function(args) {
        const verifyCode = args.length > 0 ? s(args[0]) : "";
        console.log("[lan-settings] DeviceInfoEx.loginDevice enter"
          + " verifyCodeLen=" + verifyCode.length
          + " verifyCodeMatch=" + secretMatch(verifyCode)
          + deviceInfoExShape(this));
      }, function(args, ret) {
        console.log("[lan-settings] DeviceInfoEx.loginDevice leave ret=" + s(ret)
          + deviceInfoExShape(this));
      });
      hookAllOverloads("[lan-settings] DeviceInfoEx.logoutPlayDevice", DeviceInfoEx, "logoutPlayDevice", function(args) {
        console.log("[lan-settings] DeviceInfoEx.logoutPlayDevice enter caller=" + s(args[0])
          + deviceInfoExShape(this));
      });
    } catch (e) {
      console.log("[lan-settings] DeviceInfoEx hooks unavailable " + e);
    }

    try {
      const ActivityUtil = Java.use("com.videogo.util.ActivityUtil");
      hookAllOverloads("[lan-settings] ActivityUtil.b", ActivityUtil, "b", function(args) {
        console.log("[lan-settings] ActivityUtil.b enter channel=" + s(args[0])
          + " serial=" + s(args[1])
          + " ssid=" + s(args[2]));
      });
    } catch (e) {
      console.log("[lan-settings] ActivityUtil hook unavailable " + e);
    }

    try {
      const PreviewBackNavigation = Java.use("com.ezviz.playerbus_ezviz.xroute.PreviewBackNavigation");
      hookAllOverloads("[lan-settings] PreviewBackNavigation.startLanVideoPlay", PreviewBackNavigation, "startLanVideoPlay", function(args) {
        console.log("[lan-settings] PreviewBackNavigation.startLanVideoPlay enter"
          + " serial=" + s(args[1])
          + " channel=" + s(args[2])
          + " lanUserId=" + s(args[3])
          + " ssid=" + s(args[4]));
      });
    } catch (e) {
      console.log("[lan-settings] PreviewBackNavigation hook unavailable " + e);
    }

    try {
      const VideoPlayStaticInfo = Java.use("com.videogo.baseplay.data.VideoPlayStaticInfo");
      ["setLanPlay", "setEzlinkPlay", "setLanLoginId", "setSsid"].forEach(function(name) {
        hookAllOverloads("[lan-settings] VideoPlayStaticInfo." + name, VideoPlayStaticInfo, name, function(args) {
          console.log("[lan-settings] VideoPlayStaticInfo." + name + " enter value=" + s(args[0]));
        });
      });
    } catch (e) {
      console.log("[lan-settings] VideoPlayStaticInfo hook unavailable " + e);
    }

    try {
      const NativeApi = Java.use("com.ez.stream.NativeApi");
      hookAllOverloads("[lan-settings] NativeApi.createClient", NativeApi, "createClient", function(args) {
        console.log("[lan-settings] NativeApi.createClient enter " + describeInitParam(args[0]));
      }, function(args, ret) {
        console.log("[lan-settings] NativeApi.createClient leave handle=" + s(ret));
      });
      hookAllOverloads("[lan-settings] NativeApi.startPreview", NativeApi, "startPreview", function(args) {
        console.log("[lan-settings] NativeApi.startPreview enter handle=" + s(args[0]));
      }, function(args, ret) {
        console.log("[lan-settings] NativeApi.startPreview leave ret=" + s(ret) + " handle=" + s(args[0]));
      });
      hookAllOverloads("[lan-settings] NativeApi.updateParam", NativeApi, "updateParam", function(args) {
        console.log("[lan-settings] NativeApi.updateParam enter handle=" + s(args[0]) + " " + describeInitParam(args[1]));
      }, function(args, ret) {
        console.log("[lan-settings] NativeApi.updateParam leave ret=" + s(ret) + " handle=" + s(args[0]));
      });
    } catch (e) {
      console.log("[lan-settings] NativeApi hook unavailable " + e);
    }

    try {
      const HCNetSDK = Java.use("com.neutral.netsdk.HCNetSDK");
      ["NET_DVR_MakeKeyFrame", "NET_DVR_MakeKeyFrameSub"].forEach(function(name) {
        hookAllOverloads("[lan-settings] HCNetSDK." + name, HCNetSDK, name, function(args) {
          console.log("[lan-settings] HCNetSDK." + name + " enter loginId=" + s(args[0]) + " channel=" + s(args[1]));
        }, function(args, ret) {
          console.log("[lan-settings] HCNetSDK." + name + " leave ret=" + s(ret)
            + " loginId=" + s(args[0]) + " channel=" + s(args[1]));
        });
      });
    } catch (e) {
      console.log("[lan-settings] HCNetSDK keyframe hooks unavailable " + e);
    }

    try {
      const HCNETUtil = Java.use("com.videogo.add.device.HCNETUtil");
      hookAllOverloads("[lan-settings] HCNETUtil.s", HCNETUtil, "s", function(args) {
        const pwd = s(args[3]);
        console.log("[lan-settings] HCNETUtil.s login enter ip=" + s(args[0])
          + " port=" + s(args[1])
          + " user=" + s(args[2])
          + " pwdLen=" + pwd.length
          + " pwdMatch=" + secretMatch(pwd)
          + rememberSecret("hcnetLogin:" + s(args[0]) + ":" + s(args[2]), pwd));
      }, function(args, ret) {
        console.log("[lan-settings] HCNETUtil.s login leave ip=" + s(args[0])
          + " port=" + s(args[1])
          + " user=" + s(args[2])
          + " ret=" + ret);
      });
      hookAllOverloads("[lan-settings] HCNETUtil.d", HCNETUtil, "d", function(args) {
        console.log("[lan-settings] HCNETUtil.d get enter loginId=" + s(args[0])
          + " command=" + s(args[1]).replace(/\r/g, "\\r").replace(/\n/g, "\\n"));
      }, function(args, ret) {
        const body = s(ret);
        const isServices = body.indexOf("servicesSwitch") >= 0;
        console.log("[lan-settings] HCNETUtil.d get leave len=" + body.length
          + " hasServicesSwitch=" + isServices);
      });
      hookAllOverloads("[lan-settings] HCNETUtil.c", HCNETUtil, "c", function(args) {
        console.log("[lan-settings] HCNETUtil.c put enter loginId=" + s(args[0])
          + servicesSwitchShape(args[1]));
      });
    } catch (e) {
      console.log("[lan-settings] HCNETUtil hooks unavailable " + e);
    }

    console.log("[lan-settings] hooks installed");
  });
}

setImmediate(installHooks);
