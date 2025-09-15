"""Constants and enums used by the Ezviz Cloud API wrapper.

Includes default timeouts, request headers used to emulate the mobile
client, and a large collection of enums that map integers/strings from
the Ezviz API to descriptive names.
"""

from enum import Enum, unique

from .utils import generate_unique_code

FEATURE_CODE = generate_unique_code()
XOR_KEY = b"\x0c\x0eJ^X\x15@Rr"
DEFAULT_TIMEOUT = 25
MAX_RETRIES = 3
REQUEST_HEADER = {
    "featureCode": FEATURE_CODE,
    "clientType": "3",
    "osVersion": "",
    "clientVersion": "",
    "netType": "WIFI",
    "customno": "1000001",
    "ssid": "",
    "clientNo": "web_site",
    "appId": "ys7",
    "language": "en_GB",
    "lang": "en",
    "sessionId": "",
    "User-Agent": "okhttp/3.12.1",
}  # Standard android header.
MQTT_APP_KEY = "4c6b3cc2-b5eb-4813-a592-612c1374c1fe"
APP_SECRET = "17454517-cc1c-42b3-a845-99b4a15dd3e6"


@unique
class MessageFilterType(Enum):
    """Message filter types for unified list."""

    FILTER_TYPE_MOTION = 2402
    FILTER_TYPE_PERSON = 2403
    FILTER_TYPE_VEHICLE = 2404
    FILTER_TYPE_SOUND = 2405
    FILTER_TYPE_ALL_ALARM = 2401
    FILTER_TYPE_SYSTEM_MESSAGE = 2101


@unique
class DeviceSwitchType(Enum):
    """Device switch name and number."""

    ALARM_TONE = 1
    STREAM_ADAPTIVE = 2
    LIGHT = 3
    INTELLIGENT_ANALYSIS = 4
    LOG_UPLOAD = 5
    DEFENCE_PLAN = 6
    PRIVACY = 7
    SOUND_LOCALIZATION = 8
    CRUISE = 9
    INFRARED_LIGHT = 10
    WIFI = 11
    WIFI_MARKETING = 12
    WIFI_LIGHT = 13
    PLUG = 14
    SLEEP = 21
    SOUND = 22
    BABY_CARE = 23
    LOGO = 24
    MOBILE_TRACKING = 25
    CHANNELOFFLINE = 26
    ALL_DAY_VIDEO = 29
    AUTO_SLEEP = 32
    ROAMING_STATUS = 34
    DEVICE_4G = 35
    ALARM_REMIND_MODE = 37
    OUTDOOR_RINGING_SOUND = 39
    INTELLIGENT_PQ_SWITCH = 40
    DOORBELL_TALK = 101
    HUMAN_INTELLIGENT_DETECTION = 200
    LIGHT_FLICKER = 301
    ALARM_LIGHT = 303
    ALARM_LIGHT_RELEVANCE = 305
    DEVICE_HUMAN_RELATE_LIGHT = 41
    TAMPER_ALARM = 306
    DETECTION_TYPE = 451
    OUTLET_RECOVER = 600
    CHIME_INDICATOR_LIGHT = 611
    TRACKING = 650
    CRUISE_TRACKING = 651
    PARTIAL_IMAGE_OPTIMIZE = 700
    FEATURE_TRACKING = 701


@unique
class SupportExt(Enum):
    """Supported device extensions."""

    SupportAHeadWakeupWifi = 696
    SupportAITag = 522
    SupportAbsenceReminder = 181
    SupportActiveDefense = 96
    SupportAddAfterGuide = 737
    SupportAddDelDetector = 19
    SupportAddSmartChildDev = 156
    SupportAlarmInterval = 406
    SupportAlarmLight = 113
    SupportAlarmVoice = 7
    SupportAlertDelaySetup = 383
    SupportAlertTone = 215
    SupportAntiOpen = 213
    SupportApMode = 106
    SupportAssociateDoorlockOnline = 415
    SupportAudioCollect = 165
    SupportAudioConfigApn = 695
    SupportAudioOnoff = 63
    SupportAutoAdjust = 45
    SupportAutoOffline = 8
    SupportAutoSleep = 144
    SupportBackLight = 303
    SupportBackendLinkIpcStream = 596
    SupportBatteryDeviceP2p = 336
    SupportBatteryManage = 119
    SupportBatteryNonPerOperateP2p = 417
    SupportBatteryNumber = 322
    SupportBellSet = 164
    SupportBleConfigApn = 759
    SupportBluetooth = 58
    SupportBlutoothWifiConfig = 710
    SupportBodyFaceFilter = 318
    SupportBodyFaceMarker = 319
    SupportCall = 191
    SupportCapture = 14
    SupportChanType = 52
    SupportChangeSafePasswd = 15
    SupportChangeVoice = 481
    SupportChangeVolume = 203
    SupportChannelOffline = 70
    SupportChannelTalk = 192
    SupportChime = 115
    SupportChimeDoorbellAutolink = 334
    SupportChimeIndicatorLight = 186
    SupportCloseInfraredLight = 48
    SupportCloud = 11
    SupportCloudVersion = 12
    SupportConcealResource = 286
    SupportCorrelationAlarm = 387
    SupportCruiseTraking = 197
    SupportCustomVoice = 92
    SupportCustomVoicePlan = 222
    SupportDayNightSwitch = 238
    SupportDdns = 175
    SupportDecivePowerMessage = 218
    SupportDecouplingAlarmVoice = 473
    SupportDefaultVoice = 202
    SupportDefence = 1
    SupportDefencePlan = 3
    SupportDelayLocalRecord = 636
    SupportDetectHumanCar = 224
    SupportDetectMoveHumanCar = 302
    SupportDevOfflineAlarm = 450
    SupportDeviceAutoVideoLevel = 729
    SupportDeviceEmptyPasswordSetting = 609
    SupportDeviceGetAccountPermission = 568
    SupportDeviceIntrusionDetection = 385
    SupportDeviceLinkDevice = 593
    SupportDeviceLocation = 745
    SupportDevicePermissionType = 659
    SupportDeviceRevisionSetting = 499
    SupportDeviceRfSignalReport = 325
    SupportDeviceRing = 185
    SupportDeviceTransboundaryDetection = 386
    SupportDevicelog = 216
    SupportDisk = 4
    SupportDiskBlackList = 367
    SupportDistributionNetworkBetweenDevice = 420
    SupportDisturbMode = 217
    SupportDisturbNewMode = 292
    SupportDoorCallPlayBack = 545
    SupportDoorCallQuickReply = 544
    SupportDoorLookStateShow = 690
    SupportDoorbellIndicatorLight = 242
    SupportDoorbellTalk = 101
    SupportEcdhV2 = 519
    SupportEmojiInteraction = 573
    SupportEnStandard = 235
    SupportEncrypt = 9
    SupportEnterCardDetail = 779
    SupportEventVideo = 393
    SupportExtremePowerSaving = 827
    SupportEzvizChime = 380
    SupportFaceFrameMark = 196
    SupportFeatureTrack = 321
    SupportFecCeilingCorrectType = 312
    SupportFecDeskTopCorrectType = 666
    SupportFecWallCorrectType = 313
    SupportFilter = 360
    SupportFishEye = 91
    SupportFlashLamp = 496
    SupportFlowStatistics = 53
    SupportFocusAdjust = 817
    SupportFullDayRecord = 88
    SupportFullScreenPtz = 81
    SupportGetDeviceAuthCode = 492
    SupportHorizontalPanoramic = 95
    SupportHostScreen = 240
    SupportIndicatorBrightness = 188
    SupportIndicatorLightDay = 331
    SupportIntellectualHumanFace = 351
    SupportIntelligentNightVisionDuration = 353
    SupportIntelligentPQSwitch = 366
    SupportIntelligentTrack = 73
    SupportInterconnectionDbChime = 550
    SupportIpcLink = 20
    SupportIsapi = 145
    SupportKeyFocus = 74
    SupportKindsP2pMode = 566
    SupportLANPort = 769
    SupportLanguage = 47
    SupportLaserPtCtrl = 640
    SupportLightAbilityRemind = 301
    SupportLightRelate = 297
    SupportLocalConnect = 507
    SupportLocalLockGate = 662
    SupportLockConfigWay = 679
    SupportMessage = 6
    SupportMicroVolumnSet = 77
    SupportMicroscope = 60
    SupportModifyChanName = 49
    SupportModifyDetectorguard = 23
    SupportModifyDetectorname = 21
    SupportMore = 54
    SupportMotionDetection = 97
    SupportMultiChannelFlip = 732
    SupportMultiChannelSharedService = 720
    SupportMultiChannelType = 719
    SupportMultiScreen = 17
    SupportMultiSubsys = 255
    SupportMultilensPlay = 665
    SupportMusic = 67
    SupportMusicPlay = 602
    SupportNatPass = 84
    SupportNeedOpenMode = 754
    SupportNetProtect = 290
    SupportNewSearchRecords = 256
    SupportNewTalk = 87
    SupportNewWorkMode = 687
    SupportNightVisionMode = 206
    SupportNoencriptViaAntProxy = 79
    SupportNvrEncrypt = 465
    SupportOneClickReset = 738
    SupportOneKeyPatrol = 571
    SupportOpticalZoom = 644
    SupportOsd = 153
    SupportPaging = 249
    SupportPanoramaPicListSize = 731
    SupportPartAreaRecord = 615
    SupportPartialImageOptimize = 221
    SupportPetHomeCharge = 805
    SupportPetPlayPath = 801
    SupportPetTalkChangeVoice = 639
    SupportPicInPic = 460
    SupportPirDetect = 100
    SupportPirSetting = 118
    SupportPlaybackAsyn = 375
    SupportPlaybackMaxSpeed = 610
    SupportPlaybackPiP = 645
    SupportPlaybackQualityChange = 200
    SupportPlaybackSmallSpeed = 585
    SupportPointLocateView = 724
    SupportPoundSignShow = 699
    SupportPoweroffRecovery = 189
    SupportPreP2P = 59
    SupportPreset = 34
    SupportPresetAlarm = 72
    SupportPreviewCorrectionInOldWay = 581
    SupportPreviewNoPlayback = 780
    SupportProtectionMode = 64
    SupportPtz = 154
    SupportPtz45Degree = 32
    SupportPtzCenterMirror = 37
    SupportPtzCommonCruise = 35
    SupportPtzFigureCruise = 36
    SupportPtzFocus = 99
    SupportPtzHorizontal360 = 199
    SupportPtzLeftRight = 31
    SupportPtzLeftRightMirror = 38
    SupportPtzManualCtrl = 586
    SupportPtzModel = 50
    SupportPtzNew = 605
    SupportPtzPrivacy = 40
    SupportPtzTopBottom = 30
    SupportPtzTopBottomMirror = 39
    SupportPtzZoom = 33
    SupportPtzcmdViaP2pv3 = 169
    SupportQosTalkVersion = 287
    SupportQualityDisable = 660
    SupportQuickplayWay = 149
    SupportRateLimit = 65
    SupportRebootDevice = 452
    SupportRegularBrightnessPlan = 384
    SupportRelatedDevice = 26
    SupportRelatedStorage = 27
    SupportRelationCamera = 117
    SupportRemindAudition = 434
    SupportRemoteAuthRandcode = 28
    SupportRemoteControl = 800
    SupportRemoteOpenDoor = 592
    SupportRemoteQuiet = 55
    SupportRemoteUnlock = 648
    SupportReplayChanNums = 94
    SupportReplayDownload = 260
    SupportReplaySpeed = 68
    SupportResolution = 16
    SupportRestartTime = 103
    SupportReverseDirect = 69
    SupportRingingSoundSelect = 241
    SupportSafeModePlan = 22
    SupportSdCover = 483
    SupportSdHideRecord = 600
    SupportSdkTransport = 29
    SupportSeekPlayback = 257
    SupportSensibilityAdjust = 61
    SupportServerSideEncryption = 261
    SupportSetWireioType = 205
    SupportSignalAsyn = 183
    SupportSignalCheck = 535
    SupportSimCard = 194
    SupportSleep = 62
    SupportSmartBodyDetect = 244
    SupportSmartNightVision = 274
    SupportSoundLightAlarm = 214
    SupportSsl = 25
    SupportStopRecordVideo = 219
    SupportSwitchLog = 187
    SupportSwitchTalkmode = 170
    SupportTalk = 2
    SupportTalkType = 51
    SupportTalkVolumeAdj = 455
    SupportTamperAlarm = 327
    SupportTearFilm = 454
    SupportTemperatureAlarm = 76
    SupportTextToVoice = 574
    SupportTimeSchedulePlan = 209
    SupportTimezone = 46
    SupportTipsVoice = 625
    SupportTracking = 198
    SupportTvEntranceOff = 578
    SupportUnLock = 78
    SupportUnbind = 44
    SupportUpgrade = 10
    SupportUploadCloudFile = 18
    SupportVerticalPanoramic = 112
    SupportVideoJoint = 782
    SupportVideoJointLineType = 787
    SupportVideoMeeting = 818
    SupportVideoMeetingEncodeType = 864
    SupportVideoMeetingScreenShare = 867
    SupportVolumnSet = 75
    SupportWeixin = 24
    SupportWifi = 13
    SupportWifi24G = 41
    SupportWifi5G = 42
    SupportWifiLock = 541
    SupportWifiManager = 239
    SupportWifiPortal = 43
    SupportWindowPtzSlider = 802
    SupportWorkModeList = 502
    SupportSensitiveUnderDefenceType = 444
    SupportDefenceTypeFull = 534
    SupportDetectAreaUnderDefencetype = 504


@unique
class SoundMode(Enum):
    """Alarm sound level description."""

    SILENT = 2
    SOFT = 0
    INTENSE = 1
    CUSTOM = 3
    PLAN = 4
    UNKNOWN = -1


@unique
class DefenseModeType(Enum):
    """Defense mode name and number."""

    HOME_MODE = 1
    AWAY_MODE = 2
    SLEEP_MODE = 3
    UNSET_MODE = 0


@unique
class AlarmDetectHumanCar(Enum):
    """Detection modes for cameras that support AlarmDetectHumanCar."""

    DETECTION_MODE_HUMAN_SHAPE = 1
    DETECTION_MODE_PIR = 5
    DETECTION_MODE_IMAGE_CHANGE = 3


@unique
class IntelligentDetectionSmartApp(Enum):
    """Intelligent detection modes for cameras using smart apps."""

    app_human_detect = 1
    app_video_change = 4
    app_car_detect = 2
    app_wave_recognize = 64


@unique
class NightVisionMode(Enum):
    """Intelligent detection modes."""

    NIGHT_VISION_COLOUR = 1
    NIGHT_VISION_B_W = 0
    NIGHT_VISION_SMART = 2


@unique
class DisplayMode(Enum):
    """Display modes or image styles."""

    DISPLAY_MODE_ORIGINAL = 1
    DISPLAY_MODE_SOFT = 2
    DISPLAY_MODE_VIVID = 3


@unique
class BatteryCameraWorkMode(Enum):
    """Battery camera work modes."""

    UNKNOWN = -1
    POWER_SAVE = 0
    HIGH_PERFORMANCE = 1
    PLUGGED_IN = 2
    SUPER_POWER_SAVE = 3
    CUSTOM = 4
    HYBERNATE = 5  # not sure


@unique
class BatteryCameraNewWorkMode(Enum):
    """New battery camera work modes."""

    UNKNOWN = -1
    STANDARD = 1
    PLUGGED_IN = 2
    SUPER_POWER_SAVE = 3
    CUSTOM = 4
    ALWAYS_ON_VIDEO = 7


class DeviceCatagories(Enum):
    """Supported device categories."""

    COMMON_DEVICE_CATEGORY = "COMMON"
    CAMERA_DEVICE_CATEGORY = "IPC"
    BATTERY_CAMERA_DEVICE_CATEGORY = "BatteryCamera"
    DOORBELL_DEVICE_CATEGORY = "BDoorBell"
    BASE_STATION_DEVICE_CATEGORY = "XVR"
    CAT_EYE_CATEGORY = "CatEye"
    LIGHTING = "lighting"
    W2H_BASE_STATION_DEVICE_CATEGORY = "IGateWay"
