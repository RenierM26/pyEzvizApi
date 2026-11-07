# Retained private compatibility exports are explicit object aliases.
"""Compatibility exports; implementations are dependency-closed protocol_types modules."""

from pyezvizapi.streaming.local.hcnetsdk.protocol_types import (
    configuration as _configuration,
    controls as _controls,
    discovery as _discovery,
    endpoints as _endpoints,
    framing as _framing,
    playback as _playback,
    preview as _preview,
    sdk_requests as _sdk_requests,
)

HcNetSdkRealDataType = _framing.HcNetSdkRealDataType

HcNetSdkLanEndpoint = _endpoints.HcNetSdkLanEndpoint

HcNetSdkSetupAlarmRequest = _sdk_requests.HcNetSdkSetupAlarmRequest
HcNetSdkCloseAlarmRequest = _sdk_requests.HcNetSdkCloseAlarmRequest

EzvizLanVideoResolution = _configuration.EzvizLanVideoResolution
HcNetSdkStreamDetails = _configuration.HcNetSdkStreamDetails

EzvizLanPlaybackConvertResolution = _playback.EzvizLanPlaybackConvertResolution

HcNetSdkPtzControlRequest = _controls.HcNetSdkPtzControlRequest
HcNetSdkPtzPresetRequest = _controls.HcNetSdkPtzPresetRequest
EzvizLanPlaybackIntent = _playback.EzvizLanPlaybackIntent
EzvizLanVideoQuality = _sdk_requests.EzvizLanVideoQuality

EzvizLanKeyframeRequest = _preview.EzvizLanKeyframeRequest
HcNetSdkRealDataPacket = _framing.HcNetSdkRealDataPacket
HcNetSdkSemanticLogEvent = _sdk_requests.HcNetSdkSemanticLogEvent
HcNetSdkCommandTraceSummary = _sdk_requests.HcNetSdkCommandTraceSummary
HcNetSdkClientInfo = _preview.HcNetSdkClientInfo
HcNetSdkRealPlayRequest = _preview.HcNetSdkRealPlayRequest
EzvizLanPlaybackPath = _playback.EzvizLanPlaybackPath
HcNetSdkNoArgRequest = _sdk_requests.HcNetSdkNoArgRequest
HcNetSdkInitRequest = _sdk_requests.HcNetSdkInitRequest
HcNetSdkSetConnectTimeRequest = _playback.HcNetSdkSetConnectTimeRequest
HcNetSdkGetErrorMsgRequest = _sdk_requests.HcNetSdkGetErrorMsgRequest
HcNetSdkLogoutRequest = _sdk_requests.HcNetSdkLogoutRequest
HcNetSdkTime = _playback.HcNetSdkTime
HcNetSdkFileCond = _playback.HcNetSdkFileCond
HcNetSdkFindFileRequest = _playback.HcNetSdkFindFileRequest
HcNetSdkFindDataV30 = _playback.HcNetSdkFindDataV30
HcNetSdkFindNextFileRequest = _playback.HcNetSdkFindNextFileRequest
HcNetSdkFindCloseRequest = _playback.HcNetSdkFindCloseRequest
HcNetSdkPlayCond = _playback.HcNetSdkPlayCond
HcNetSdkPlayBackByTimeRequest = _playback.HcNetSdkPlayBackByTimeRequest
HcNetSdkPlayBackControlRequest = _playback.HcNetSdkPlayBackControlRequest
HcNetSdkStopPlayBackRequest = _playback.HcNetSdkStopPlayBackRequest
HcNetSdkPlayBackCaptureFileRequest = _playback.HcNetSdkPlayBackCaptureFileRequest
HcNetSdkPlayDataCallbackRequest = _sdk_requests.HcNetSdkPlayDataCallbackRequest
HcNetSdkPlaybackCallbackRequest = _playback.HcNetSdkPlaybackCallbackRequest
HcNetSdkPlayBackSecretKeyRequest = _playback.HcNetSdkPlayBackSecretKeyRequest
HcNetSdkGetFileByNameRequest = _playback.HcNetSdkGetFileByNameRequest
HcNetSdkGetFileByTimeRequest = _playback.HcNetSdkGetFileByTimeRequest
HcNetSdkStopGetFileRequest = _playback.HcNetSdkStopGetFileRequest
HcNetSdkGetDownloadPosRequest = _playback.HcNetSdkGetDownloadPosRequest

SadpActivateDeviceRequest = _discovery.SadpActivateDeviceRequest
SadpNoArgRequest = _discovery.SadpNoArgRequest
SadpStartRequest = _discovery.SadpStartRequest
SadpSetLogToFileRequest = _discovery.SadpSetLogToFileRequest
SadpBatchResult = _discovery.SadpBatchResult

__all__ = ['EzvizLanKeyframeRequest', 'EzvizLanPlaybackConvertResolution', 'EzvizLanPlaybackIntent', 'EzvizLanPlaybackPath', 'EzvizLanVideoQuality', 'EzvizLanVideoResolution', 'HcNetSdkClientInfo', 'HcNetSdkCloseAlarmRequest', 'HcNetSdkCommandTraceSummary', 'HcNetSdkFileCond', 'HcNetSdkFindCloseRequest', 'HcNetSdkFindDataV30', 'HcNetSdkFindFileRequest', 'HcNetSdkFindNextFileRequest', 'HcNetSdkGetDownloadPosRequest', 'HcNetSdkGetErrorMsgRequest', 'HcNetSdkGetFileByNameRequest', 'HcNetSdkGetFileByTimeRequest', 'HcNetSdkInitRequest', 'HcNetSdkLanEndpoint', 'HcNetSdkLogoutRequest', 'HcNetSdkNoArgRequest', 'HcNetSdkPlayBackByTimeRequest', 'HcNetSdkPlayBackCaptureFileRequest', 'HcNetSdkPlayBackControlRequest', 'HcNetSdkPlayBackSecretKeyRequest', 'HcNetSdkPlayCond', 'HcNetSdkPlayDataCallbackRequest', 'HcNetSdkPlaybackCallbackRequest', 'HcNetSdkPtzControlRequest', 'HcNetSdkPtzPresetRequest', 'HcNetSdkRealDataPacket', 'HcNetSdkRealDataType', 'HcNetSdkRealPlayRequest', 'HcNetSdkSemanticLogEvent', 'HcNetSdkSetConnectTimeRequest', 'HcNetSdkSetupAlarmRequest', 'HcNetSdkStopGetFileRequest', 'HcNetSdkStopPlayBackRequest', 'HcNetSdkStreamDetails', 'HcNetSdkTime', 'SadpActivateDeviceRequest', 'SadpBatchResult', 'SadpNoArgRequest', 'SadpSetLogToFileRequest', 'SadpStartRequest']
