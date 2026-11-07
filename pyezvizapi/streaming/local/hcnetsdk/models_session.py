# Retained private compatibility exports are explicit object aliases.
"""Compatibility exports; implementations are dependency-closed protocol_types modules."""

from pyezvizapi.streaming.local.hcnetsdk.protocol_types import (
    discovery as _discovery,
    endpoints as _endpoints,
    framing as _framing,
    preview as _preview,
    preview_bootstrap as _preview_bootstrap,
)

HcNetSdkLoginCandidate = _endpoints.HcNetSdkLoginCandidate

HcNetSdkSetSdkLocalCfgRequest = _preview.HcNetSdkSetSdkLocalCfgRequest

HcNetSdkTcpPayloadShape = _framing.HcNetSdkTcpPayloadShape
HcNetSdkTcpFrameHeader = _framing.HcNetSdkTcpFrameHeader
HcNetSdkTcpFrame = _framing.HcNetSdkTcpFrame
HcNetSdkCommandPortExchange = _framing.HcNetSdkCommandPortExchange
HcNetSdkCommandPortStreamBootstrap = _framing.HcNetSdkCommandPortStreamBootstrap
HcNetSdkCommandPortLoginChallenge = _framing.HcNetSdkCommandPortLoginChallenge
HcNetSdkCommandPortLoginSession = _framing.HcNetSdkCommandPortLoginSession
HcNetSdkCommandPortControlResponse = _framing.HcNetSdkCommandPortControlResponse
HcNetSdkCommandPortControlTemplate = _framing.HcNetSdkCommandPortControlTemplate
HcNetSdkTcpFrameShape = _framing.HcNetSdkTcpFrameShape
EzvizLanPlayDeviceLogin = _preview.EzvizLanPlayDeviceLogin
EzvizLanPreviewPlan = _preview.EzvizLanPreviewPlan
EzvizLocalDeviceContent = _preview.EzvizLocalDeviceContent
EzvizLocalDevice = _preview.EzvizLocalDevice

EzvizCasDeviceInfo = _preview_bootstrap.EzvizCasDeviceInfo
HcNetSdkPortProbe = _endpoints.HcNetSdkPortProbe
EzvizLocalSdkFrameHeader = _preview.EzvizLocalSdkFrameHeader
EzvizLocalSdkFrame = _preview.EzvizLocalSdkFrame
EzvizLocalSdkBodyShape = _preview.EzvizLocalSdkBodyShape
EzvizInterleavedRtpFrameHeader = _framing.EzvizInterleavedRtpFrameHeader
EzvizInterleavedRtpFrame = _framing.EzvizInterleavedRtpFrame
EzvizInterleavedRtpFrameWithPrefix = _framing.EzvizInterleavedRtpFrameWithPrefix
EzvizLocalSdkExchange = _preview.EzvizLocalSdkExchange
EzvizLocalSdkStreamBootstrap = _preview_bootstrap.EzvizLocalSdkStreamBootstrap
EzvizLocalReceiverInfo = _preview.EzvizLocalReceiverInfo
EzvizLocalReceiverInfoEx = _preview.EzvizLocalReceiverInfoEx
EzvizLocalReceiverInfoAttrs = _preview.EzvizLocalReceiverInfoAttrs
EzvizLocalReceiverInfoExAttrs = _preview.EzvizLocalReceiverInfoExAttrs
EzvizLocalAuthenticationAttrs = _preview.EzvizLocalAuthenticationAttrs
EzvizLocalPreviewRequest = _preview.EzvizLocalPreviewRequest

SadpDeviceInfo = _discovery.SadpDeviceInfo

__all__ = ['EzvizCasDeviceInfo', 'EzvizInterleavedRtpFrame', 'EzvizInterleavedRtpFrameHeader', 'EzvizInterleavedRtpFrameWithPrefix', 'EzvizLanPlayDeviceLogin', 'EzvizLanPreviewPlan', 'EzvizLocalAuthenticationAttrs', 'EzvizLocalDevice', 'EzvizLocalDeviceContent', 'EzvizLocalPreviewRequest', 'EzvizLocalReceiverInfo', 'EzvizLocalReceiverInfoAttrs', 'EzvizLocalReceiverInfoEx', 'EzvizLocalReceiverInfoExAttrs', 'EzvizLocalSdkBodyShape', 'EzvizLocalSdkExchange', 'EzvizLocalSdkFrame', 'EzvizLocalSdkFrameHeader', 'EzvizLocalSdkStreamBootstrap', 'HcNetSdkCommandPortControlResponse', 'HcNetSdkCommandPortControlTemplate', 'HcNetSdkCommandPortExchange', 'HcNetSdkCommandPortLoginChallenge', 'HcNetSdkCommandPortLoginSession', 'HcNetSdkCommandPortStreamBootstrap', 'HcNetSdkLoginCandidate', 'HcNetSdkPortProbe', 'HcNetSdkSetSdkLocalCfgRequest', 'HcNetSdkTcpFrame', 'HcNetSdkTcpFrameHeader', 'HcNetSdkTcpFrameShape', 'HcNetSdkTcpPayloadShape', 'SadpDeviceInfo']
