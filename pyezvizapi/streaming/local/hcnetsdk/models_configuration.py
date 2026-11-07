# Retained private compatibility exports are explicit object aliases.
"""Compatibility exports; implementations are dependency-closed protocol_types modules."""

from pyezvizapi.streaming.local.hcnetsdk.protocol_types import (
    configuration as _configuration,
    controls as _controls,
    discovery as _discovery,
    framing as _framing,
    preview as _preview,
    sdk_requests as _sdk_requests,
)

HcNetSdkStdXmlConfigRequest = _configuration.HcNetSdkStdXmlConfigRequest
HcNetSdkStdXmlConfigResponse = _configuration.HcNetSdkStdXmlConfigResponse
EzvizLanServicesSwitchState = _configuration.EzvizLanServicesSwitchState
EzvizLanWifiApInfo = _configuration.EzvizLanWifiApInfo
EzvizLanHdDiskConfig = _configuration.EzvizLanHdDiskConfig
EzvizLanHdConfig = _configuration.EzvizLanHdConfig
EzvizLanNtpConfig = _configuration.EzvizLanNtpConfig
EzvizLanNetInterfaceConfig = _configuration.EzvizLanNetInterfaceConfig
EzvizLanNetConfigV30 = _configuration.EzvizLanNetConfigV30
EzvizLanDvrConfigSummary = _configuration.EzvizLanDvrConfigSummary
EzvizLanEzvizAccessConfig = _configuration.EzvizLanEzvizAccessConfig
EzvizLanUserConfigV30Entry = _configuration.EzvizLanUserConfigV30Entry
EzvizLanUserConfigV30 = _configuration.EzvizLanUserConfigV30
EzvizLanDeviceConfigV40 = _configuration.EzvizLanDeviceConfigV40
EzvizLanRecordDayConfig = _configuration.EzvizLanRecordDayConfig
EzvizLanRecordScheduleSegment = _configuration.EzvizLanRecordScheduleSegment
EzvizLanRecordConfigV30 = _configuration.EzvizLanRecordConfigV30
EzvizLanCameraParamConfig = _configuration.EzvizLanCameraParamConfig
EzvizLanWifiConnectStatus = _configuration.EzvizLanWifiConnectStatus
EzvizLanAudioInputParam = _configuration.EzvizLanAudioInputParam
EzvizLanAudioOutputVolume = _configuration.EzvizLanAudioOutputVolume
EzvizLanCompressionInfoV30 = _configuration.EzvizLanCompressionInfoV30
EzvizLanCompressionConfig = _configuration.EzvizLanCompressionConfig
EzvizLanPictureConfig = _configuration.EzvizLanPictureConfig
HcNetSdkDvrConfigRequest = _configuration.HcNetSdkDvrConfigRequest
HcNetSdkFormatDiskRequest = _configuration.HcNetSdkFormatDiskRequest
HcNetSdkFormatProgressRequest = _configuration.HcNetSdkFormatProgressRequest
HcNetSdkCloseFormatHandleRequest = _configuration.HcNetSdkCloseFormatHandleRequest

HcNetSdkSetupAlarmParam = _sdk_requests.HcNetSdkSetupAlarmParam
EzvizLanSdFormatProgress = _configuration.EzvizLanSdFormatProgress
HcNetSdkDeviceAbilityRequest = _configuration.HcNetSdkDeviceAbilityRequest

EzvizLanPtzAbility = _controls.EzvizLanPtzAbility
EzvizLanAccessProtocolAbility = _configuration.EzvizLanAccessProtocolAbility
EzvizLanVideoPicAbility = _configuration.EzvizLanVideoPicAbility
EzvizLanIpcFrontParameterRange = _sdk_requests.EzvizLanIpcFrontParameterRange
EzvizLanIpcFrontParameterAbility = _configuration.EzvizLanIpcFrontParameterAbility
EzvizLanAudioVideoCompressStream = _configuration.EzvizLanAudioVideoCompressStream
EzvizLanAudioVideoCompressVideoChannel = _configuration.EzvizLanAudioVideoCompressVideoChannel
EzvizLanAudioVideoCompressAudioChannel = _configuration.EzvizLanAudioVideoCompressAudioChannel
EzvizLanAudioVideoCompressVoiceTalkChannel = _configuration.EzvizLanAudioVideoCompressVoiceTalkChannel
EzvizLanAudioVideoCompressInfo = _configuration.EzvizLanAudioVideoCompressInfo
EzvizLanDeviceSoftHardwareAbility = _configuration.EzvizLanDeviceSoftHardwareAbility
EzvizLanPlaybackConvertAbility = _configuration.EzvizLanPlaybackConvertAbility

EzvizLanLiveViewParams = _preview.EzvizLanLiveViewParams

HcNetSdkTcpShapeLogRecord = _framing.HcNetSdkTcpShapeLogRecord

SadpDeviceNetParam = _discovery.SadpDeviceNetParam
SadpModifyDeviceNetParamRequest = _discovery.SadpModifyDeviceNetParamRequest
SadpDeviceRetNetParam = _discovery.SadpDeviceRetNetParam
SadpModifyDeviceNetParamV40Request = _discovery.SadpModifyDeviceNetParamV40Request

__all__ = ['EzvizLanAccessProtocolAbility', 'EzvizLanAudioInputParam', 'EzvizLanAudioOutputVolume', 'EzvizLanAudioVideoCompressAudioChannel', 'EzvizLanAudioVideoCompressInfo', 'EzvizLanAudioVideoCompressStream', 'EzvizLanAudioVideoCompressVideoChannel', 'EzvizLanAudioVideoCompressVoiceTalkChannel', 'EzvizLanCameraParamConfig', 'EzvizLanCompressionConfig', 'EzvizLanCompressionInfoV30', 'EzvizLanDeviceConfigV40', 'EzvizLanDeviceSoftHardwareAbility', 'EzvizLanDvrConfigSummary', 'EzvizLanEzvizAccessConfig', 'EzvizLanHdConfig', 'EzvizLanHdDiskConfig', 'EzvizLanIpcFrontParameterAbility', 'EzvizLanIpcFrontParameterRange', 'EzvizLanLiveViewParams', 'EzvizLanNetConfigV30', 'EzvizLanNetInterfaceConfig', 'EzvizLanNtpConfig', 'EzvizLanPictureConfig', 'EzvizLanPlaybackConvertAbility', 'EzvizLanPtzAbility', 'EzvizLanRecordConfigV30', 'EzvizLanRecordDayConfig', 'EzvizLanRecordScheduleSegment', 'EzvizLanSdFormatProgress', 'EzvizLanServicesSwitchState', 'EzvizLanUserConfigV30', 'EzvizLanUserConfigV30Entry', 'EzvizLanVideoPicAbility', 'EzvizLanWifiApInfo', 'EzvizLanWifiConnectStatus', 'HcNetSdkCloseFormatHandleRequest', 'HcNetSdkDeviceAbilityRequest', 'HcNetSdkDvrConfigRequest', 'HcNetSdkFormatDiskRequest', 'HcNetSdkFormatProgressRequest', 'HcNetSdkSetupAlarmParam', 'HcNetSdkStdXmlConfigRequest', 'HcNetSdkStdXmlConfigResponse', 'HcNetSdkTcpShapeLogRecord', 'SadpDeviceNetParam', 'SadpDeviceRetNetParam', 'SadpModifyDeviceNetParamRequest', 'SadpModifyDeviceNetParamV40Request']
