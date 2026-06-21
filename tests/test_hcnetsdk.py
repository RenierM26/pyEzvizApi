from __future__ import annotations

from collections.abc import Callable
import ctypes
from datetime import date, datetime
import hashlib
import hmac
from typing import Any

from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
import pytest

from pyezvizapi.exceptions import DeviceException, PyEzvizError
from pyezvizapi.hcnetsdk import (
    EZVIZ_CAS_PTZ_COMMAND_MAP,
    EZVIZ_DEVICE_INFO_EX_LOGIN_PLAY_DEVICE,
    EZVIZ_HCNETUTIL_LOGIN_V40,
    EZVIZ_LAN_ACTIVITY_CHANNEL_HANDOFF,
    EZVIZ_LAN_MAIN_STREAM_TYPE,
    EZVIZ_LAN_MAIN_VIDEO_LEVEL,
    EZVIZ_LAN_PLAYBACK_VIDEO_TYPE_MAP,
    EZVIZ_LAN_PTZ_ACTION_RESET,
    EZVIZ_LAN_PTZ_ACTION_START,
    EZVIZ_LAN_PTZ_ACTION_STOP,
    EZVIZ_LAN_PTZ_COMMAND_MAP,
    EZVIZ_LAN_PTZ_PRESET_COMMANDS,
    EZVIZ_LAN_PTZ_SPEED_DEFAULT,
    EZVIZ_LAN_SUB_STREAM_TYPE,
    EZVIZ_LAN_SUB_VIDEO_LEVEL,
    EZVIZ_LOCAL_SDK_PRE_START_COMMAND,
    EZVIZ_LOCAL_SDK_PREVIEW_COMMAND,
    EZVIZ_LOCAL_SDK_STREAM_SETUP_COMMAND,
    EZVIZ_PLAY_DATA_INFO_LOGIN_PLAY_DEVICE,
    EZVIZ_PLAYER_EXTRA_CHANNEL_NO,
    EZVIZ_PLAYER_EXTRA_DEVICE_ID,
    EZVIZ_PLAYER_EXTRA_LAN_FLAG,
    EZVIZ_PLAYER_EXTRA_LAN_USERID,
    EZVIZ_PLAYER_EXTRA_WIFI_SSID,
    EZVIZ_PLAYER_LAN_FLAG_HCNETSDK,
    EZVIZ_PREPLAY_SPS_TYPE,
    EZVIZ_PREVIEW_BACK_START_LAN_VIDEO_PLAY,
    EZVIZ_STREAM_INHIBIT_LAN,
    EZVIZ_STREAM_SOURCE_LIVE_MINE,
    EZVIZ_STREAM_TIMEOUT_MS,
    HCNETSDK_CLEANUP,
    HCNETSDK_CLOSE_ALARM_CHAN_V30,
    HCNETSDK_CLOSE_FORMAT_HANDLE,
    HCNETSDK_COMMAND_CANDIDATE_CONTROL,
    HCNETSDK_COMMAND_CANDIDATE_SETTINGS_LOGIN,
    HCNETSDK_DEFAULT_RTSP_PORT,
    HCNETSDK_DEFAULT_SERVER_PORT,
    HCNETSDK_DEFAULT_TLS_PORT,
    HCNETSDK_DEVICE_ABILITY_BUFFER_TOO_SMALL_ERROR,
    HCNETSDK_DEVICE_ABILITY_DEFAULT_OUTPUT_BUFFER_SIZE,
    HCNETSDK_DEVICE_ABILITY_RETRY_OUTPUT_BUFFER_SIZE,
    HCNETSDK_DEVICE_ABILITY_RN_OUTPUT_BUFFER_SIZE,
    HCNETSDK_EZVIZ_CONNECT_MODE_PUT,
    HCNETSDK_EZVIZ_DEFAULT_USERNAME,
    HCNETSDK_EZVIZ_LAN_PASSWORD_KEY_PREFIX,
    HCNETSDK_EZVIZ_LAN_PASSWORD_PREF_SUFFIX,
    HCNETSDK_EZVIZ_LOCAL_USERNAME,
    HCNETSDK_EZVIZ_NET_CONFIG_UPLOAD_PUT,
    HCNETSDK_EZVIZ_SERVICES_SWITCH_GET,
    HCNETSDK_EZVIZ_SERVICES_SWITCH_PUT,
    HCNETSDK_EZVIZ_SETTINGS_ACCOUNT_PASSWORD_ERROR,
    HCNETSDK_EZVIZ_SETTINGS_ACCOUNT_PASSWORD_LOCKED_ERROR,
    HCNETSDK_EZVIZ_SETTINGS_ERROR_BASE,
    HCNETSDK_FILECOND_FIELD_ORDER,
    HCNETSDK_FIND_CLOSE_V30,
    HCNETSDK_FIND_FILE_FAILED,
    HCNETSDK_FIND_FILE_V30,
    HCNETSDK_FIND_NEXT_FILE_EXCEPTION,
    HCNETSDK_FIND_NEXT_FILE_IS_FINDING,
    HCNETSDK_FIND_NEXT_FILE_NO_FILE,
    HCNETSDK_FIND_NEXT_FILE_NO_MORE_FILE,
    HCNETSDK_FIND_NEXT_FILE_SUCCESS,
    HCNETSDK_FIND_NEXT_FILE_V30,
    HCNETSDK_FINDDATA_V30_FIELD_ORDER,
    HCNETSDK_FORMAT_DISK,
    HCNETSDK_GET_DEVICE_ABILITY,
    HCNETSDK_GET_DOWNLOAD_POS,
    HCNETSDK_GET_DVR_CONFIG,
    HCNETSDK_GET_ERROR_MSG,
    HCNETSDK_GET_FILE_BY_NAME,
    HCNETSDK_GET_FILE_BY_TIME,
    HCNETSDK_GET_FILE_FAILED,
    HCNETSDK_GET_FORMAT_PROGRESS,
    HCNETSDK_GET_LAST_ERROR,
    HCNETSDK_GET_SDK_BUILD_VERSION,
    HCNETSDK_GET_SDK_VERSION,
    HCNETSDK_INIT,
    HCNETSDK_LOCAL_ABILITY_PARSE_CFG_FIELD_ORDER,
    HCNETSDK_LOCAL_PTZ_CFG_FIELD_ORDER,
    HCNETSDK_LOGIN_V40,
    HCNETSDK_LOGOUT_V30,
    HCNETSDK_MAKE_KEYFRAME_MAIN,
    HCNETSDK_MAKE_KEYFRAME_SUB,
    HCNETSDK_PLAY_CONVERT,
    HCNETSDK_PLAYAUDIOVOLUME,
    HCNETSDK_PLAYBACK_BY_TIME_V40,
    HCNETSDK_PLAYBACK_CAPTURE_FILE,
    HCNETSDK_PLAYBACK_CONTROL_V40,
    HCNETSDK_PLAYBACK_FAILED,
    HCNETSDK_PLAYBACK_FILE_TYPE_ALL,
    HCNETSDK_PLAYBACK_LOCK_STATE_ALL,
    HCNETSDK_PLAYCOND_FIELD_ORDER,
    HCNETSDK_PLAYFAST,
    HCNETSDK_PLAYPAUSE,
    HCNETSDK_PLAYRESTART,
    HCNETSDK_PLAYSLOW,
    HCNETSDK_PLAYSTART,
    HCNETSDK_PLAYSTARTAUDIO,
    HCNETSDK_PLAYSTOPAUDIO,
    HCNETSDK_PTZ_CONTROL_WITH_SPEED_OTHER,
    HCNETSDK_PTZ_PRESET_OTHER,
    HCNETSDK_REALDATA_CALLBACK_V30,
    HCNETSDK_REALPLAY_V30,
    HCNETSDK_SECRET_KEY_TYPE_AES,
    HCNETSDK_SET_CONNECT_TIME,
    HCNETSDK_SET_DVR_CONFIG,
    HCNETSDK_SET_PLAY_DATA_CALLBACK,
    HCNETSDK_SET_PLAY_DATA_CALLBACK_V40,
    HCNETSDK_SET_PLAYBACK_ES_CALLBACK,
    HCNETSDK_SET_PLAYBACK_RESPONSE_CALLBACK,
    HCNETSDK_SET_PLAYBACK_SECRET_KEY,
    HCNETSDK_SET_SDK_LOCAL_CFG,
    HCNETSDK_SET_TRANS_TYPE,
    HCNETSDK_SETUP_ALARM_CHAN_V30,
    HCNETSDK_SETUP_ALARM_CHAN_V41,
    HCNETSDK_SETUPALARM_PARAM_FIELD_ORDER,
    HCNETSDK_STDXML_ANDROID_REQUEST_BUFFER_SIZE,
    HCNETSDK_STDXML_COMMAND_PORT_COMMAND_ID,
    HCNETSDK_STDXML_COMMAND_PORT_EXTRA_RESERVED_SIZE,
    HCNETSDK_STDXML_COMMAND_PORT_FLAGS,
    HCNETSDK_STDXML_COMMAND_PORT_PREFIX_SIZE,
    HCNETSDK_STDXML_CONFIG,
    HCNETSDK_STDXML_DEFAULT_OUTPUT_BUFFER_SIZE,
    HCNETSDK_STDXML_DEFAULT_STATUS_BUFFER_SIZE,
    HCNETSDK_STDXML_INPUT_FIELD_ORDER,
    HCNETSDK_STDXML_OUTPUT_FIELD_ORDER,
    HCNETSDK_STOP_GET_FILE,
    HCNETSDK_STOP_PLAYBACK,
    HCNETSDK_TCP_HEADER_LENGTH,
    HCNETSDK_TIME_FIELD_ORDER,
    SADP_ACTIVATE_DEVICE,
    SADP_CLEARUP,
    SADP_DEV_NET_PARAM_ANDROID_FIELDS,
    SADP_DEV_NET_PARAM_JNA_FIELD_ORDER,
    SADP_DEV_RET_NET_PARAM_BUFFER_SIZE,
    SADP_DEV_RET_NET_PARAM_FIELD_ORDER,
    SADP_GET_LAST_ERROR,
    SADP_GET_VERSION,
    SADP_MODIFY_DEVICE_NET_PARAM,
    SADP_MODIFY_DEVICE_NET_PARAM_V40,
    SADP_SEND_INQUIRY,
    SADP_SET_LOG_TO_FILE,
    SADP_START_V30,
    SADP_START_V40,
    SADP_STOP,
    EzvizCasDeviceInfo,
    EzvizLanSdFormatProgress,
    EzvizLocalPreviewRequest,
    EzvizLocalReceiverInfo,
    EzvizLocalReceiverInfoEx,
    EzvizLocalSdkClient,
    EzvizPtzCommand,
    HcNetSdkAbility,
    HcNetSdkClientInfo,
    HcNetSdkCloseAlarmRequest,
    HcNetSdkCloseFormatHandleRequest,
    HcNetSdkCommandPortClient,
    HcNetSdkCommandPortControlResponse,
    HcNetSdkCommandPortControlTemplate,
    HcNetSdkCommandPortLoginSession,
    HcNetSdkDeviceAbilityRequest,
    HcNetSdkDvrCommand,
    HcNetSdkDvrConfigRequest,
    HcNetSdkFileCond,
    HcNetSdkFindCloseRequest,
    HcNetSdkFindDataV30,
    HcNetSdkFindFileRequest,
    HcNetSdkFindNextFileRequest,
    HcNetSdkFormatDiskRequest,
    HcNetSdkFormatProgressRequest,
    HcNetSdkGetDownloadPosRequest,
    HcNetSdkGetErrorMsgRequest,
    HcNetSdkGetFileByNameRequest,
    HcNetSdkGetFileByTimeRequest,
    HcNetSdkInitRequest,
    HcNetSdkLanEndpoint,
    HcNetSdkLocalCfgType,
    HcNetSdkLogoutRequest,
    HcNetSdkNativeLoginSession,
    HcNetSdkNativeStdXmlClient,
    HcNetSdkNoArgRequest,
    HcNetSdkPlayBackByTimeRequest,
    HcNetSdkPlaybackCallbackRequest,
    HcNetSdkPlayBackCaptureFileRequest,
    HcNetSdkPlaybackControlCommand,
    HcNetSdkPlayBackControlRequest,
    HcNetSdkPlayBackSecretKeyRequest,
    HcNetSdkPlayCond,
    HcNetSdkPlayDataCallbackRequest,
    HcNetSdkPtzCommand,
    HcNetSdkPtzControlRequest,
    HcNetSdkPtzPresetCommand,
    HcNetSdkPtzPresetRequest,
    HcNetSdkPurePythonClient,
    HcNetSdkRealDataPacket,
    HcNetSdkRealDataType,
    HcNetSdkSetConnectTimeRequest,
    HcNetSdkSetSdkLocalCfgRequest,
    HcNetSdkSetupAlarmParam,
    HcNetSdkSetupAlarmRequest,
    HcNetSdkStdXmlConfigResponse,
    HcNetSdkStopGetFileRequest,
    HcNetSdkStopPlayBackRequest,
    HcNetSdkTime,
    SadpActivateDeviceRequest,
    SadpBatchResult,
    SadpDeviceNetParam,
    SadpDeviceRetNetParam,
    SadpModifyDeviceNetParamRequest,
    SadpModifyDeviceNetParamV40Request,
    SadpNoArgRequest,
    SadpSetLogToFileRequest,
    SadpStartRequest,
    build_encrypted_ezviz_local_sdk_frame,
    build_ezviz_cas_encrypted_local_sdk_frame,
    build_ezviz_cas_ssl_local_sdk_frame,
    build_ezviz_interleaved_rtp_frame_header,
    build_ezviz_local_preview_request_body,
    build_ezviz_local_sdk_frame,
    build_ezviz_local_sdk_frame_header,
    build_ezviz_local_sdk_ssl_frame,
    build_ezviz_local_stream_setup_request_body,
    build_hcnetsdk_tcp_frame,
    classify_ezviz_local_sdk_body,
    classify_hcnetsdk_real_data_payload,
    classify_hcnetsdk_tcp_payload,
    decrypt_ezviz_local_sdk_body_aes_cbc,
    encrypt_ezviz_local_sdk_body_aes_cbc,
    ezviz_cas_ptz_command,
    ezviz_hcnetsdk_local_ability_parse_request,
    ezviz_hcnetsdk_local_ptz_without_recv_request,
    ezviz_lan_access_protocol_ability_input,
    ezviz_lan_access_protocol_ability_request,
    ezviz_lan_audio_input_get_config_request,
    ezviz_lan_audio_video_compress_info_ability_request,
    ezviz_lan_audio_video_compress_info_input,
    ezviz_lan_audio_volume_update_requests,
    ezviz_lan_audioout_volume_get_config_request,
    ezviz_lan_backlight_wdr_get_config_request,
    ezviz_lan_backlight_wdr_update_request,
    ezviz_lan_complete_playback_path,
    ezviz_lan_connect_mode_payload,
    ezviz_lan_connect_mode_put_config,
    ezviz_lan_connect_mode_put_request,
    ezviz_lan_day_night_get_config_request,
    ezviz_lan_day_night_update_request,
    ezviz_lan_ezviz_access_get_config_request,
    ezviz_lan_ezviz_access_replacement_domain,
    ezviz_lan_ezviz_access_replacement_domain_request,
    ezviz_lan_ezviz_access_set_domain_request,
    ezviz_lan_hd_config_request,
    ezviz_lan_image_display_param_ability_input,
    ezviz_lan_image_display_param_ability_request,
    ezviz_lan_ipc_front_parameter_ability_request,
    ezviz_lan_live_view_params,
    ezviz_lan_local_user_password,
    ezviz_lan_login_candidates,
    ezviz_lan_net_config_and_voice_upload_payload,
    ezviz_lan_net_config_and_voice_upload_put_config,
    ezviz_lan_net_config_and_voice_upload_put_request,
    ezviz_lan_password_store_key,
    ezviz_lan_password_store_name,
    ezviz_lan_pic_config_get_request,
    ezviz_lan_pic_config_update_request,
    ezviz_lan_play_device_login,
    ezviz_lan_play_device_login_succeeded,
    ezviz_lan_playback_condition,
    ezviz_lan_playback_convert_ability,
    ezviz_lan_playback_file_search_condition,
    ezviz_lan_playback_intent,
    ezviz_lan_playback_video_type,
    ezviz_lan_preview_plan,
    ezviz_lan_ptz_ability,
    ezviz_lan_ptz_ability_input,
    ezviz_lan_ptz_ability_request,
    ezviz_lan_ptz_control_request,
    ezviz_lan_ptz_is_preset_command,
    ezviz_lan_ptz_native_command,
    ezviz_lan_ptz_preset_request,
    ezviz_lan_ptz_request,
    ezviz_lan_record_ability_request,
    ezviz_lan_rn_device_ability_request,
    ezviz_lan_sadp_activate_batch_result,
    ezviz_lan_sadp_edit_net_param_batch_result,
    ezviz_lan_sd_format_close_request,
    ezviz_lan_sd_format_progress_request,
    ezviz_lan_sd_format_progress_result,
    ezviz_lan_sd_format_start_request,
    ezviz_lan_services_switch_get_command_port,
    ezviz_lan_services_switch_get_config,
    ezviz_lan_services_switch_get_native,
    ezviz_lan_services_switch_get_request,
    ezviz_lan_services_switch_payload,
    ezviz_lan_services_switch_put_config,
    ezviz_lan_services_switch_put_request,
    ezviz_lan_services_switch_set_command_port,
    ezviz_lan_services_switch_set_config,
    ezviz_lan_services_switch_set_native,
    ezviz_lan_services_switch_set_payload,
    ezviz_lan_services_switch_state,
    ezviz_lan_services_switch_state_command_port,
    ezviz_lan_services_switch_state_native,
    ezviz_lan_services_switch_succeeded,
    ezviz_lan_services_switch_update_config,
    ezviz_lan_settings_channel_number,
    ezviz_lan_settings_error_clears_password,
    ezviz_lan_settings_error_code,
    ezviz_lan_settings_login_candidates,
    ezviz_lan_settings_login_succeeded,
    ezviz_lan_settings_updates_services_switch,
    ezviz_lan_soft_hardware_ability,
    ezviz_lan_soft_hardware_ability_request,
    ezviz_lan_user_password_get_config_request,
    ezviz_lan_user_password_update_request,
    ezviz_lan_video_coding_get_config_request,
    ezviz_lan_video_coding_update_request,
    ezviz_lan_video_effect_get_config_request,
    ezviz_lan_video_effect_update_request,
    ezviz_lan_video_pic_ability_input,
    ezviz_lan_video_pic_ability_request,
    ezviz_lan_video_qualities,
    ezviz_lan_wifi_ap_info_list_request,
    ezviz_lan_wifi_connect_status_request,
    ezviz_lan_wifi_get_config_request,
    ezviz_lan_wifi_set_config_request,
    ezviz_lan_wifi_station_patch,
    ezviz_lan_wifi_work_mode_update_request,
    ezviz_local_sdk_iv,
    ezviz_local_sdk_ssl_iv,
    ezviz_native_video_level,
    hcnetsdk_cleanup_native,
    hcnetsdk_cleanup_request,
    hcnetsdk_close_alarm_request,
    hcnetsdk_command_candidate_role,
    hcnetsdk_command_port_auth_word,
    hcnetsdk_command_port_control_frame,
    hcnetsdk_command_port_control_template_from_frame,
    hcnetsdk_command_port_execute_template,
    hcnetsdk_command_port_login_proof,
    hcnetsdk_command_port_login_proof_frame,
    hcnetsdk_command_port_login_request_frame,
    hcnetsdk_command_port_password_digest,
    hcnetsdk_command_port_play_login_body_tail_for_today,
    hcnetsdk_command_port_response_payload,
    hcnetsdk_device_ability_command_port_body_tail,
    hcnetsdk_device_ability_command_port_template,
    hcnetsdk_device_ability_request,
    hcnetsdk_device_ability_xml,
    hcnetsdk_dvr_config_command_port_template,
    hcnetsdk_dvr_config_get_request,
    hcnetsdk_dvr_config_set_request,
    hcnetsdk_file_search_condition,
    hcnetsdk_find_close_v30_request,
    hcnetsdk_find_file_v30_request,
    hcnetsdk_find_next_file_status,
    hcnetsdk_find_next_file_v30_request,
    hcnetsdk_get_device_ability_command_port,
    hcnetsdk_get_download_pos_request,
    hcnetsdk_get_dvr_config_command_port,
    hcnetsdk_get_error_msg_request,
    hcnetsdk_get_file_by_name_request,
    hcnetsdk_get_file_by_time_request,
    hcnetsdk_get_last_error_request,
    hcnetsdk_get_sdk_build_version_request,
    hcnetsdk_get_sdk_version_request,
    hcnetsdk_init_native,
    hcnetsdk_init_request,
    hcnetsdk_login_v40_native,
    hcnetsdk_logout_native,
    hcnetsdk_logout_v30_request,
    hcnetsdk_playback_by_time_v40_request,
    hcnetsdk_playback_capture_file_request,
    hcnetsdk_playback_condition,
    hcnetsdk_playback_control_v40_request,
    hcnetsdk_real_data_type_is_media,
    hcnetsdk_real_play_request,
    hcnetsdk_set_connect_time_request,
    hcnetsdk_set_play_data_callback_request,
    hcnetsdk_set_play_data_callback_v40_request,
    hcnetsdk_set_playback_es_callback_request,
    hcnetsdk_set_playback_response_callback_request,
    hcnetsdk_set_playback_secret_key_request,
    hcnetsdk_set_sdk_local_cfg_request,
    hcnetsdk_setup_alarm_v30_request,
    hcnetsdk_setup_alarm_v41_request,
    hcnetsdk_stdxml_config_command_port_body_tail,
    hcnetsdk_stdxml_config_command_port_from_trace,
    hcnetsdk_stdxml_config_command_port_template,
    hcnetsdk_stdxml_config_native,
    hcnetsdk_stdxml_config_request,
    hcnetsdk_stdxml_isapi_command_port,
    hcnetsdk_stdxml_isapi_request,
    hcnetsdk_stdxml_response_json,
    hcnetsdk_stop_get_file_request,
    hcnetsdk_stop_playback_request,
    hcnetsdk_time,
    hcnetsdk_time_from_datetime,
    iter_hcnetsdk_real_data_mpegps,
    iter_hcnetsdk_tcp_frame_shapes,
    parse_ezviz_interleaved_rtp_frame_header,
    parse_ezviz_local_device,
    parse_ezviz_local_sdk_frame,
    parse_ezviz_local_sdk_frame_header,
    parse_ezviz_local_sdk_xml_fields,
    parse_hcnetsdk_semantic_log_line,
    parse_hcnetsdk_tcp_frame,
    parse_hcnetsdk_tcp_frame_header,
    parse_hcnetsdk_tcp_shape_log_line,
    parse_sadp_response,
    read_ezviz_interleaved_rtp_frame,
    read_ezviz_interleaved_rtp_frame_after_prefix,
    read_ezviz_local_sdk_frame,
    read_hcnetsdk_command_port_interleaved_frame_after_prefix,
    read_hcnetsdk_tcp_frame,
    sadp_activate_device_request,
    sadp_clearup_request,
    sadp_device_net_param,
    sadp_get_last_error_request,
    sadp_get_sadp_version_request,
    sadp_modify_device_net_param_request,
    sadp_modify_device_net_param_v40_request,
    sadp_send_inquiry_request,
    sadp_set_log_to_file_request,
    sadp_start_v30_request,
    sadp_start_v40_request,
    sadp_stop_request,
    summarize_hcnetsdk_command_trace,
)

LOCAL_SDK_TEST_KEY = b"1234567890abcdef"
LOCAL_SDK_TEST_IV = b"CAM1234560123456"
LOCAL_SDK_SSL_IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
LOCAL_SDK_RESPONSE_TRAILER = b"0" * 32
HCNETSDK_TCP_MIN_PRINTABLE_RATIO = 0.5
HCNETSDK_TCP_LOG_PRINTABLE_RATIO = 0.21
HCNETSDK_TCP_LOG_NULL_RATIO = 0.10
HCNETSDK_TCP_LOG_HIGH_BIT_RATIO = 0.48
HCNETSDK_TCP_TEST_BODY = b"payload"
HCNETSDK_COMMAND_PORT_TEST_SESSION_ID = b"\x12\x34\x56\x78"
HCNETSDK_COMMAND_PORT_TEST_BODY_TAIL = b"\x00\x00\x00\x01"
HCNETSDK_COMMAND_PORT_TEST_TIMEOUT = 3.0
STDXML_EMPTY_BUFFER = b""
STDXML_TEST_REQUEST = b"GET /ISAPI/Test?format=json\r\n"
STDXML_TEST_INPUT_BUFFER = b"body"
STDXML_TEST_OUTPUT = b'{"servicesSwitch":{"web":1}}'
STDXML_TEST_STATUS = b'{"statusCode":1}'
COMMAND_PORT_DEFAULT_TIMEOUT = 10.0
COMMAND_PORT_EMPTY_OUTPUT = b""
COMMAND_PORT_JSON_STATUS_OUTPUT = b'{"statusCode":1}'
COMMAND_PORT_BASIC_ABILITY_OUTPUT = b"<BasicCapability/>"
COMMAND_PORT_RECORD_ABILITY_OUTPUT = b"<RecordAbility/>"
COMMAND_PORT_HD_CONFIG_OUTPUT = b"\x00\x00\x12\x98"
COMMAND_PORT_EMPTY_BODY_TAIL = b""
COMMAND_PORT_TRACE_BODY_TAIL = b"trace-tail"
DEVICE_ABILITY_EMPTY_BUFFER = b""
EXPECTED_TEST_WIFI_SSID_BYTES = b"Test WiFi"
EXPECTED_EZVIZ_RU_DOMAIN_BYTES = b"api.ezvizru.com"
EXPECTED_PTZ_ABILITY_XML = (
    b'<PTZAbility version="2.0"><channelNO>1</channelNO></PTZAbility>'
)
EXPECTED_AUDIO_VIDEO_COMPRESS_INFO_XML = (
    b"<AudioVideoCompressInfo><VideoChannelNumber>2</VideoChannelNumber>"
    b"</AudioVideoCompressInfo>"
)
EXPECTED_IMAGE_DISPLAY_PARAM_ABILITY_XML = (
    b'<ImageDisplayParamAbility version="2.0"><channelNO>3</channelNO>'
    b"</ImageDisplayParamAbility>"
)
EXPECTED_VIDEO_PIC_ABILITY_XML = (
    b'<VideoPicAbility version="2.0"><channelNO>4</channelNO></VideoPicAbility>'
)
EXPECTED_ACCESS_PROTOCOL_ABILITY_XML = (
    b'<AccessProtocolAbility version="2.0"><channelNO>0xff</channelNO>'
    b"</AccessProtocolAbility>"
)
SADP_TEST_IPV4_ADDRESS = "192.0.2.10"
EXPECTED_SADP_LOG_DIR_BUFFER = b"/tmp/sadp/\x00"
EXPECTED_PLAYBACK_FIND_FILE_NAME = b"record001.mp4"
EXPECTED_PLAYBACK_STREAM_ID = b"stream-id"
EXPECTED_PLAYBACK_CONTROL_IN_BUFFER = b"\x00\x00\x00\x00"
EXPECTED_PLAYBACK_CAPTURE_FILE_NAME = b"/tmp/snap.jpg"
EXPECTED_PLAYBACK_SECRET_KEY = b"playback-secret"
STREAM_SETUP_BODY = b"<Request><Session>1</Session></Request>"
EXPECTED_PREVIEW_XML = (
    b'<?xml version="1.0" encoding="utf-8"?>\n'
    b"<Request>\n"
    b"\t<OperationCode>op&amp;code</OperationCode>\n"
    b"\t<Channel>1</Channel>\n"
    b"\t<ReceiverInfo>receiver&lt;info&gt;</ReceiverInfo>\n"
    b"\t<IsEncrypt>TRUE</IsEncrypt>\n"
    b"\t<ReceiverInfoEx>receiver-ex</ReceiverInfoEx>\n"
    b"\t<Authentication>auth</Authentication>\n"
    b"\t<Uuid>uuid</Uuid>\n"
    b"\t<Timestamp>123456</Timestamp>\n"
    b"</Request>\n"
)
EXPECTED_STRUCTURED_PREVIEW_XML = (
    b'<?xml version="1.0" encoding="utf-8"?>\n'
    b"<Request>\n"
    b"\t<OperationCode>op</OperationCode>\n"
    b"\t<Channel>1</Channel>\n"
    b"\t<Identifier>ident</Identifier>\n"
    b"\t<ReceiverInfo>\n"
        b"\t\t<NatAddress>192.0.2.10</NatAddress>\n"
    b"\t\t<NatPort>9010</NatPort>\n"
    b"\t\t<UPnPAddress></UPnPAddress>\n"
    b"\t\t<UPnPPort>0</UPnPPort>\n"
        b"\t\t<InnerAddress>192.0.2.20</InnerAddress>\n"
    b"\t\t<InnerPort>9020</InnerPort>\n"
    b"\t\t<StreamType>MAIN</StreamType>\n"
    b"\t</ReceiverInfo>\n"
    b"\t<IsEncrypt>TRUE</IsEncrypt>\n"
    b"\t<Udt>1</Udt>\n"
    b"\t<Nat>2</Nat>\n"
    b"\t<PortGuessType>5</PortGuessType>\n"
    b"\t<Timeout>30</Timeout>\n"
    b"\t<HeartbeatInterval>10</HeartbeatInterval>\n"
    b"\t<ReceiverInfoEx>receiver-ex</ReceiverInfoEx>\n"
    b"</Request>\n"
)
EXPECTED_STRUCTURED_PREVIEW_EX_XML = (
    b'<?xml version="1.0" encoding="utf-8"?>\n'
    b"<Request>\n"
    b"\t<OperationCode>op</OperationCode>\n"
    b"\t<Channel>1</Channel>\n"
    b"\t<ReceiverInfo>receiver</ReceiverInfo>\n"
    b"\t<IsEncrypt>TRUE</IsEncrypt>\n"
    b"\t<ReceiverInfoEx>\n"
    b"\t\t<Authentication>\n"
    b"\t\t\t<Uuid>uuid</Uuid>\n"
    b"\t\t\t<Timestamp>123456</Timestamp>\n"
    b"\t\t</Authentication>\n"
    b"\t</ReceiverInfoEx>\n"
    b"</Request>\n"
)
EXPECTED_STREAM_SETUP_XML = (
    b'<?xml version="1.0" encoding="utf-8"?>\n'
    b"<Request>\n"
    b"\t<Session>1</Session>\n"
    b"\t<Rate>0</Rate>\n"
    b"\t<Mode>1</Mode>\n"
    b"</Request>\n"
)


def _ctypes_array_text(array: Any) -> str:
    return bytes(array).split(b"\x00", 1)[0].decode("utf-8")


class _FakeNativeHcNetSdk:
    def __init__(
        self,
        outputs: list[bytes] | None = None,
        *,
        stdxml_succeeds: bool = True,
        login_id: int = 42,
        last_error: int = 0,
    ) -> None:
        self.outputs = list(outputs or [])
        self.stdxml_succeeds = stdxml_succeeds
        self.login_id = login_id
        self.last_error = last_error
        self.initialized = False
        self.cleaned_up = False
        self.logged_out: list[int] = []
        self.logins: list[dict[str, object]] = []
        self.requests: list[bytes] = []
        self.input_buffers: list[bytes] = []

    def NET_DVR_Init(self) -> bool:
        self.initialized = True
        return True

    def NET_DVR_Cleanup(self) -> bool:
        self.cleaned_up = True
        return True

    def NET_DVR_GetLastError(self) -> int:
        return self.last_error

    def NET_DVR_Login_V40(self, login_info_ptr: Any, device_info_ptr: Any) -> int:
        login_info = login_info_ptr.contents
        device_info = device_info_ptr.contents
        self.logins.append(
            {
                "host": _ctypes_array_text(login_info.sDeviceAddress),
                "username": _ctypes_array_text(login_info.sUserName),
                "password": _ctypes_array_text(login_info.sPassword),
                "port": login_info.wPort,
                "https": login_info.byHttps,
            }
        )
        if self.login_id < 0:
            return self.login_id
        serial = b"SN123456789"
        for index, value in enumerate(serial):
            device_info.struDeviceV30.sSerialNumber[index] = value
        return self.login_id

    def NET_DVR_Logout_V30(self, login_id: int) -> bool:
        self.logged_out.append(login_id)
        return True

    def NET_DVR_STDXMLConfig(
        self,
        login_id: int,
        input_ptr: Any,
        output_ptr: Any,
    ) -> bool:
        assert login_id == 42
        input_struct = input_ptr.contents
        output_struct = output_ptr.contents
        self.requests.append(
            ctypes.string_at(
                input_struct.lpRequestUrl,
                input_struct.dwRequestUrlLen,
            )
        )
        if input_struct.lpInBuffer:
            self.input_buffers.append(
                ctypes.string_at(
                    input_struct.lpInBuffer,
                    input_struct.dwInBufferSize,
                )
            )
        else:
            self.input_buffers.append(b"")
        if not self.stdxml_succeeds:
            return False

        output = self.outputs.pop(0) if self.outputs else STDXML_TEST_STATUS
        if output_struct.lpOutBuffer:
            ctypes.memmove(
                output_struct.lpOutBuffer,
                output,
                min(len(output), output_struct.dwOutBufferSize),
            )
            output_struct.dwReturnedXMLSize = min(
                len(output),
                output_struct.dwOutBufferSize,
            )
        status = STDXML_TEST_STATUS
        if output_struct.lpStatusBuffer:
            ctypes.memmove(
                output_struct.lpStatusBuffer,
                status,
                min(len(status), output_struct.dwStatusSize),
            )
        return True


def test_lan_endpoint_from_connection_uses_ezviz_ports() -> None:
    endpoint = HcNetSdkLanEndpoint.from_connection(
        "CAM123",
        {
            "localIp": " 192.0.2.10 ",
            "localCmdPort": "9010",
            "localStreamPort": 9020,
            "netIp": "203.0.113.10",
            "netCmdPort": 8010,
            "netStreamPort": 9030,
            "localRtspPort": 0,
        },
    )

    assert endpoint.serial == "CAM123"
    assert endpoint.host == "192.0.2.10"
    assert endpoint.net_host == "203.0.113.10"
    assert endpoint.command_port == 9010
    assert endpoint.net_command_port == 8010
    assert endpoint.stream_port == 9020
    assert endpoint.net_stream_port == 9030
    assert endpoint.rtsp_port == HCNETSDK_DEFAULT_RTSP_PORT
    assert endpoint.sdk_tls_port == HCNETSDK_DEFAULT_TLS_PORT


def test_lan_endpoint_from_connection_defaults_command_port() -> None:
    endpoint = HcNetSdkLanEndpoint.from_connection(
        "CAM123",
        {"localIp": "192.0.2.10"},
    )

    assert endpoint.command_port == HCNETSDK_DEFAULT_SERVER_PORT


def test_lan_endpoint_requires_local_ip() -> None:
    with pytest.raises(PyEzvizError, match="localIp"):
        HcNetSdkLanEndpoint.from_connection("CAM123", {"localCmdPort": 9010})


def test_parse_sadp_response_extracts_common_fields() -> None:
    info = parse_sadp_response(
        b"\x00\x00<ProbeMatch>"
        b"<DeviceSN>CAM123456</DeviceSN>"
        b"<IPv4Address>192.0.2.10</IPv4Address>"
        b"<CommandPort>9010</CommandPort>"
        b"</ProbeMatch>\x00"
    )

    assert info.serial == "CAM123456"
    assert info.ipv4_address == "192.0.2.10"
    assert info.command_port == 9010


def test_parse_sadp_response_rejects_non_xml() -> None:
    with pytest.raises(PyEzvizError, match="XML"):
        parse_sadp_response(b"not xml")


def test_sadp_activation_request_shape_matches_rn_batch_activation() -> None:
    request = sadp_activate_device_request(" CAM123456 ", "secret")

    assert SADP_ACTIVATE_DEVICE == "SADP_ActivateDevice"
    assert SADP_GET_LAST_ERROR == "SADP_GetLastError"
    assert request == SadpActivateDeviceRequest(
        serial=" CAM123456 ",
        password="secret",
    )
    assert request.to_native_args_hint() == {
        "api": SADP_ACTIVATE_DEVICE,
        "serial": "CAM123456",
        "password": "<password>",
        "passwordLength": 6,
        "lastErrorApi": SADP_GET_LAST_ERROR,
    }
    assert request.to_native_args_hint(include_password=True)["password"] == "secret"

    with pytest.raises(PyEzvizError, match="serial"):
        sadp_activate_device_request(" ", "secret").to_native_args_hint()
    with pytest.raises(PyEzvizError, match="password"):
        sadp_activate_device_request("CAM123456", "").to_native_args_hint()


def test_sadp_network_param_request_shape_matches_rn_batch_edit() -> None:
    net_param = sadp_device_net_param(
        ipv4_address=SADP_TEST_IPV4_ADDRESS,
        ipv4_subnet_mask="255.255.255.0",
        ipv4_gateway="192.0.2.1",
        dhcp_enabled=True,
        http_port=80,
        command_port=8000,
        ipv6_mask_len=64,
    )
    request = sadp_modify_device_net_param_request(
        "00:11:22:33:44:55",
        "secret",
        net_param,
    )

    assert SADP_MODIFY_DEVICE_NET_PARAM == "SADP_ModifyDeviceNetParam"
    assert SADP_DEV_NET_PARAM_ANDROID_FIELDS == (
        "szIPv4Address",
        "szIPv4SubnetMask",
        "szIPv4Gateway",
        "szIPv6Address",
        "szIPv6Gateway",
        "byDhcpEnabled",
        "byIPv6MaskLen",
        "wHttpPort",
        "wPort",
        "byRes",
    )
    assert SADP_DEV_NET_PARAM_JNA_FIELD_ORDER == (
        "szIPv4Address",
        "szIPv4SubNetMask",
        "szIPv4Gateway",
        "szIPv6Address",
        "szIPv6Gateway",
        "wPort",
        "byIPv6MaskLen",
        "byDhcpEnable",
        "wHttpPort",
        "dwSDKOverTLSPort",
        "byRes",
    )
    assert net_param == SadpDeviceNetParam(
        ipv4_address=SADP_TEST_IPV4_ADDRESS,
        ipv4_subnet_mask="255.255.255.0",
        ipv4_gateway="192.0.2.1",
        dhcp_enabled=True,
        http_port=80,
        command_port=8000,
        ipv6_mask_len=64,
    )
    assert net_param.to_native_dict() == {
        "structure": "SADP_DEV_NET_PARAM",
        "androidFields": SADP_DEV_NET_PARAM_ANDROID_FIELDS,
        "jnaFieldOrder": SADP_DEV_NET_PARAM_JNA_FIELD_ORDER,
        "szIPv4Address": SADP_TEST_IPV4_ADDRESS,
        "szIPv4SubnetMask": "255.255.255.0",
        "szIPv4Gateway": "192.0.2.1",
        "szIPv6Address": "",
        "szIPv6Gateway": "",
        "byDhcpEnabled": 1,
        "byIPv6MaskLen": 64,
        "wHttpPort": 80,
        "wPort": 8000,
    }
    assert net_param.to_native_dict(include_buffers=True)["szIPv4Address"] == (
        SADP_TEST_IPV4_ADDRESS.encode()
    )
    assert request == SadpModifyDeviceNetParamRequest(
        mac="00:11:22:33:44:55",
        password="secret",
        net_param=net_param,
    )
    assert request.to_native_args_hint() == {
        "api": SADP_MODIFY_DEVICE_NET_PARAM,
        "mac": "00:11:22:33:44:55",
        "password": "<password>",
        "passwordLength": 6,
        "netParam": net_param.to_native_dict(),
        "lastErrorApi": SADP_GET_LAST_ERROR,
    }
    assert request.to_native_args_hint(include_password=True)["password"] == "secret"


def test_hcnetsdk_lifecycle_error_and_version_request_shapes() -> None:
    init = hcnetsdk_init_request()
    cleanup = hcnetsdk_cleanup_request()
    connect = hcnetsdk_set_connect_time_request()
    last_error = hcnetsdk_get_last_error_request()
    error_msg = hcnetsdk_get_error_msg_request(23)
    sdk_version = hcnetsdk_get_sdk_version_request()
    sdk_build_version = hcnetsdk_get_sdk_build_version_request()
    logout = hcnetsdk_logout_v30_request(42)

    assert HCNETSDK_INIT == "NET_DVR_Init"
    assert HCNETSDK_CLEANUP == "NET_DVR_Cleanup"
    assert HCNETSDK_SET_CONNECT_TIME == "NET_DVR_SetConnectTime"
    assert HCNETSDK_GET_LAST_ERROR == "NET_DVR_GetLastError"
    assert HCNETSDK_GET_ERROR_MSG == "NET_DVR_GetErrorMsg"
    assert HCNETSDK_GET_SDK_VERSION == "NET_DVR_GetSDKVersion"
    assert HCNETSDK_GET_SDK_BUILD_VERSION == "NET_DVR_GetSDKBuildVersion"
    assert HCNETSDK_LOGIN_V40 == "NET_DVR_Login_V40"
    assert HCNETSDK_LOGOUT_V30 == "NET_DVR_Logout_V30"
    assert HCNETSDK_STDXML_CONFIG == "NET_DVR_STDXMLConfig"
    assert init == HcNetSdkInitRequest()
    assert init.to_native_args_hint() == {
        "api": HCNETSDK_INIT,
        "sPlayCtrlPath": "libPlayCtrl.so",
    }
    assert hcnetsdk_init_request(None).to_native_args_hint() == {
        "api": HCNETSDK_INIT,
        "overload": "android-default-playctrl-library",
    }
    assert cleanup == HcNetSdkNoArgRequest(api=HCNETSDK_CLEANUP)
    assert cleanup.to_native_args_hint() == {"api": HCNETSDK_CLEANUP}
    assert connect == HcNetSdkSetConnectTimeRequest(connect_time_ms=5000)
    assert connect.to_native_args_hint() == {
        "api": HCNETSDK_SET_CONNECT_TIME,
        "dwWaitTime": 5000,
    }
    assert last_error.to_native_args_hint() == {"api": HCNETSDK_GET_LAST_ERROR}
    assert error_msg == HcNetSdkGetErrorMsgRequest(error_code=23)
    assert error_msg.to_native_args_hint() == {
        "api": HCNETSDK_GET_ERROR_MSG,
        "pErrorNo": "<INT_PTR>",
        "intPointerValue": 23,
    }
    assert sdk_version.to_native_args_hint() == {"api": HCNETSDK_GET_SDK_VERSION}
    assert sdk_build_version.to_native_args_hint() == {
        "api": HCNETSDK_GET_SDK_BUILD_VERSION,
    }
    assert logout == HcNetSdkLogoutRequest(login_id=42)
    assert logout.to_native_args_hint() == {
        "api": HCNETSDK_LOGOUT_V30,
        "lUserID": 42,
    }

    with pytest.raises(PyEzvizError, match="library name"):
        hcnetsdk_init_request("\x00").to_native_args_hint()
    with pytest.raises(PyEzvizError, match="connect time"):
        hcnetsdk_set_connect_time_request(-1).to_native_args_hint()
    with pytest.raises(PyEzvizError, match="error code"):
        hcnetsdk_get_error_msg_request(-1).to_native_args_hint()
    with pytest.raises(PyEzvizError, match="successful login"):
        hcnetsdk_logout_v30_request(-1).to_native_args_hint()
    with pytest.raises(PyEzvizError, match="unsupported"):
        HcNetSdkNoArgRequest(api=HCNETSDK_INIT).to_native_args_hint()


def test_hcnetsdk_playback_file_search_shapes_match_apk_surface() -> None:
    start_time = hcnetsdk_time(2026, 6, 20, hour=8, minute=30, second=15)
    stop_time = hcnetsdk_time_from_datetime(datetime(2026, 6, 20, 9, 45, 30))
    condition = ezviz_lan_playback_file_search_condition(
        1,
        start_time,
        stop_time,
    )
    find_request = hcnetsdk_find_file_v30_request(42, condition)
    find_data = HcNetSdkFindDataV30(
        file_name="record001.mp4",
        start_time=start_time,
        stop_time=stop_time,
        file_size=1234,
        card_number="card",
        locked=1,
        file_type=0x1D,
    )
    next_request = hcnetsdk_find_next_file_v30_request(
        1001,
        find_data=find_data,
    )
    close_request = hcnetsdk_find_close_v30_request(1001)

    assert HCNETSDK_FIND_FILE_V30 == "NET_DVR_FindFile_V30"
    assert HCNETSDK_FIND_NEXT_FILE_V30 == "NET_DVR_FindNextFile_V30"
    assert HCNETSDK_FIND_CLOSE_V30 == "NET_DVR_FindClose_V30"
    assert HCNETSDK_FIND_FILE_FAILED == -1
    assert HCNETSDK_PLAYBACK_FILE_TYPE_ALL == 255
    assert HCNETSDK_PLAYBACK_LOCK_STATE_ALL == 255
    assert HCNETSDK_TIME_FIELD_ORDER == (
        "dwYear",
        "dwMonth",
        "dwDay",
        "dwHour",
        "dwMinute",
        "dwSecond",
    )
    assert start_time == HcNetSdkTime(
        year=2026,
        month=6,
        day=20,
        hour=8,
        minute=30,
        second=15,
    )
    assert start_time.to_native_dict() == {
        "structure": "NET_DVR_TIME",
        "fieldOrder": HCNETSDK_TIME_FIELD_ORDER,
        "dwYear": 2026,
        "dwMonth": 6,
        "dwDay": 20,
        "dwHour": 8,
        "dwMinute": 30,
        "dwSecond": 15,
    }
    assert hcnetsdk_file_search_condition(
        1,
        date(2026, 6, 20),
        date(2026, 6, 20),
    ).stop_time == HcNetSdkTime(2026, 6, 20, 23, 59, 59)
    assert condition == HcNetSdkFileCond(
        channel=1,
        start_time=start_time,
        stop_time=stop_time,
    )
    assert condition.to_native_dict() == {
        "structure": "NET_DVR_FILECOND",
        "fieldOrder": HCNETSDK_FILECOND_FIELD_ORDER,
        "lChannel": 1,
        "dwFileType": 255,
        "dwIsLocked": 255,
        "dwUseCardNo": 0,
        "sCardNumber": "",
        "sCardNumberBufferSize": 32,
        "struStartTime": start_time.to_native_dict(),
        "struStopTime": stop_time.to_native_dict(),
    }
    assert find_request == HcNetSdkFindFileRequest(
        login_id=42,
        file_cond=condition,
    )
    assert find_request.to_native_args_hint() == {
        "api": HCNETSDK_FIND_FILE_V30,
        "lUserID": 42,
        "lpFindCond": condition.to_native_dict(),
        "failureHandle": HCNETSDK_FIND_FILE_FAILED,
    }
    assert find_data.to_native_dict() == {
        "structure": "NET_DVR_FINDDATA_V30",
        "fieldOrder": HCNETSDK_FINDDATA_V30_FIELD_ORDER,
        "sFileName": "record001.mp4",
        "sFileNameBufferSize": 100,
        "struStartTime": start_time.to_native_dict(),
        "struStopTime": stop_time.to_native_dict(),
        "dwFileSize": 1234,
        "sCardNum": "card",
        "sCardNumBufferSize": 32,
        "byLocked": 1,
        "byFileType": 29,
        "byResLength": 2,
    }
    assert find_data.to_native_dict(include_buffers=True)["sFileName"] == (
        EXPECTED_PLAYBACK_FIND_FILE_NAME
    )
    assert next_request == HcNetSdkFindNextFileRequest(
        find_handle=1001,
        find_data=find_data,
    )
    assert next_request.to_native_args_hint() == {
        "api": HCNETSDK_FIND_NEXT_FILE_V30,
        "lFindHandle": 1001,
        "lpFindData": find_data.to_native_dict(),
    }
    assert close_request == HcNetSdkFindCloseRequest(find_handle=1001)
    assert close_request.to_native_args_hint() == {
        "api": HCNETSDK_FIND_CLOSE_V30,
        "lFindHandle": 1001,
    }

    with pytest.raises(PyEzvizError, match="month"):
        HcNetSdkTime(2026, 13, 20).to_native_dict()
    with pytest.raises(PyEzvizError, match="channel"):
        hcnetsdk_file_search_condition(-1, start_time, stop_time).to_native_dict()
    with pytest.raises(PyEzvizError, match="successful login"):
        hcnetsdk_find_file_v30_request(-1, condition).to_native_args_hint()
    with pytest.raises(PyEzvizError, match="find handle"):
        hcnetsdk_find_next_file_v30_request(-1).to_native_args_hint()
    with pytest.raises(PyEzvizError, match="find handle"):
        hcnetsdk_find_close_v30_request(-1).to_native_args_hint()
    with pytest.raises(PyEzvizError, match="file name"):
        HcNetSdkFindDataV30(file_name=b"x" * 101).to_native_dict()
    with pytest.raises(PyEzvizError, match="one byte"):
        HcNetSdkFindDataV30(file_type=300).to_native_dict()


def test_hcnetsdk_find_next_status_and_playback_type_mapping() -> None:
    assert HCNETSDK_FIND_NEXT_FILE_SUCCESS == 1000
    assert HCNETSDK_FIND_NEXT_FILE_NO_FILE == 1001
    assert HCNETSDK_FIND_NEXT_FILE_IS_FINDING == 1002
    assert HCNETSDK_FIND_NEXT_FILE_NO_MORE_FILE == 1003
    assert HCNETSDK_FIND_NEXT_FILE_EXCEPTION == 1004
    assert hcnetsdk_find_next_file_status(1000) == "file"
    assert hcnetsdk_find_next_file_status(1001) == "no_file"
    assert hcnetsdk_find_next_file_status(1002) == "finding"
    assert hcnetsdk_find_next_file_status(1003) == "no_more_file"
    assert hcnetsdk_find_next_file_status(1004) == "exception"
    assert hcnetsdk_find_next_file_status(42) == "unknown"
    assert EZVIZ_LAN_PLAYBACK_VIDEO_TYPE_MAP == {
        0x00: 1,
        0x1D: 8,
        0x20: 9,
        0x21: 10,
    }
    assert ezviz_lan_playback_video_type(0x00) == 1
    assert ezviz_lan_playback_video_type(0x1D) == 8
    assert ezviz_lan_playback_video_type(0x20) == 9
    assert ezviz_lan_playback_video_type(0x21) == 10
    assert ezviz_lan_playback_video_type(0x7F) == 0


def test_hcnetsdk_playback_by_time_control_and_stop_shapes() -> None:
    start_time = hcnetsdk_time(2026, 6, 20, hour=10, minute=15, second=30)
    stop_time = hcnetsdk_time(2026, 6, 20, hour=10, minute=20, second=30)
    condition = ezviz_lan_playback_condition(
        1,
        start_time,
        stop_time,
        stream_type=1,
    )
    generic_condition = hcnetsdk_playback_condition(
        2,
        date(2026, 6, 20),
        date(2026, 6, 20),
        draw_frame=1,
        stream_type=2,
        stream_id=EXPECTED_PLAYBACK_STREAM_ID,
    )
    playback = hcnetsdk_playback_by_time_v40_request(42, condition)
    control = hcnetsdk_playback_control_v40_request(
        1001,
        HcNetSdkPlaybackControlCommand.SET_TRANS_TYPE,
        in_buffer=EXPECTED_PLAYBACK_CONTROL_IN_BUFFER,
        out_buffer_size=4,
    )
    stop = hcnetsdk_stop_playback_request(1001)
    capture = hcnetsdk_playback_capture_file_request(1001, "/tmp/snap.jpg")

    assert HCNETSDK_PLAYBACK_BY_TIME_V40 == "NET_DVR_PlayBackByTime_V40"
    assert HCNETSDK_PLAYBACK_CONTROL_V40 == "NET_DVR_PlayBackControl_V40"
    assert HCNETSDK_STOP_PLAYBACK == "NET_DVR_StopPlayBack"
    assert HCNETSDK_PLAYBACK_CAPTURE_FILE == "NET_DVR_PlayBackCaptureFile"
    assert HCNETSDK_PLAYBACK_FAILED == -1
    assert HcNetSdkPlaybackControlCommand.START == HCNETSDK_PLAYSTART == 1
    assert HcNetSdkPlaybackControlCommand.PAUSE == HCNETSDK_PLAYPAUSE == 3
    assert HcNetSdkPlaybackControlCommand.RESTART == HCNETSDK_PLAYRESTART == 4
    assert HcNetSdkPlaybackControlCommand.FAST == HCNETSDK_PLAYFAST == 5
    assert HcNetSdkPlaybackControlCommand.SLOW == HCNETSDK_PLAYSLOW == 6
    assert (
        HcNetSdkPlaybackControlCommand.START_AUDIO
        == HCNETSDK_PLAYSTARTAUDIO
        == 9
    )
    assert (
        HcNetSdkPlaybackControlCommand.STOP_AUDIO
        == HCNETSDK_PLAYSTOPAUDIO
        == 10
    )
    assert (
        HcNetSdkPlaybackControlCommand.AUDIO_VOLUME
        == HCNETSDK_PLAYAUDIOVOLUME
        == 11
    )
    assert (
        HcNetSdkPlaybackControlCommand.SET_TRANS_TYPE
        == HCNETSDK_SET_TRANS_TYPE
        == 32
    )
    assert HcNetSdkPlaybackControlCommand.PLAY_CONVERT == HCNETSDK_PLAY_CONVERT == 33
    assert condition == HcNetSdkPlayCond(
        channel=1,
        start_time=start_time,
        stop_time=stop_time,
        stream_type=1,
    )
    assert condition.to_native_dict() == {
        "structure": "NET_DVR_PLAYCOND",
        "fieldOrder": HCNETSDK_PLAYCOND_FIELD_ORDER,
        "dwChannel": 1,
        "struStartTime": start_time.to_native_dict(),
        "struStopTime": stop_time.to_native_dict(),
        "byDrawFrame": 0,
        "byStreamType": 1,
        "byStreamID": "",
        "byStreamIDBufferSize": 32,
        "byResLength": 30,
    }
    assert generic_condition.stop_time == HcNetSdkTime(2026, 6, 20, 23, 59, 59)
    assert generic_condition.to_native_dict()["byStreamID"] == "stream-id"
    assert generic_condition.to_native_dict(include_buffers=True)["byStreamID"] == (
        EXPECTED_PLAYBACK_STREAM_ID
    )
    assert playback == HcNetSdkPlayBackByTimeRequest(
        login_id=42,
        play_cond=condition,
    )
    assert playback.to_native_args_hint() == {
        "api": HCNETSDK_PLAYBACK_BY_TIME_V40,
        "lUserID": 42,
        "lpPlayCond": condition.to_native_dict(),
        "failureHandle": HCNETSDK_PLAYBACK_FAILED,
    }
    assert control == HcNetSdkPlayBackControlRequest(
        play_handle=1001,
        command=HcNetSdkPlaybackControlCommand.SET_TRANS_TYPE,
        in_buffer=EXPECTED_PLAYBACK_CONTROL_IN_BUFFER,
        out_buffer_size=4,
    )
    assert control.to_native_args_hint() == {
        "api": HCNETSDK_PLAYBACK_CONTROL_V40,
        "lPlayHandle": 1001,
        "dwControlCode": 32,
        "lpInBuffer": "<input-buffer>",
        "dwInLen": 4,
        "lpOutBuffer": "<output-buffer>",
        "dwOutLen": 4,
        "lpOutLen": "<DWORD_PTR>",
    }
    assert control.to_native_args_hint(include_buffers=True)["lpInBuffer"] == (
        EXPECTED_PLAYBACK_CONTROL_IN_BUFFER
    )
    assert stop == HcNetSdkStopPlayBackRequest(play_handle=1001)
    assert stop.to_native_args_hint() == {
        "api": HCNETSDK_STOP_PLAYBACK,
        "lPlayHandle": 1001,
    }
    assert capture == HcNetSdkPlayBackCaptureFileRequest(
        play_handle=1001,
        saved_file_name="/tmp/snap.jpg",
    )
    assert capture.to_native_args_hint() == {
        "api": HCNETSDK_PLAYBACK_CAPTURE_FILE,
        "lPlayHandle": 1001,
        "sFileName": "/tmp/snap.jpg",
    }
    assert capture.to_native_args_hint(include_buffers=True)["sFileName"] == (
        EXPECTED_PLAYBACK_CAPTURE_FILE_NAME
    )

    with pytest.raises(PyEzvizError, match="stream id"):
        hcnetsdk_playback_condition(
            1,
            start_time,
            stop_time,
            stream_id=b"x" * 33,
        ).to_native_dict()
    with pytest.raises(PyEzvizError, match="successful login"):
        hcnetsdk_playback_by_time_v40_request(-1, condition).to_native_args_hint()
    with pytest.raises(PyEzvizError, match="playback handle"):
        hcnetsdk_playback_control_v40_request(-1, 1).to_native_args_hint()
    with pytest.raises(PyEzvizError, match="output size"):
        hcnetsdk_playback_control_v40_request(
            1,
            1,
            out_buffer_size=-1,
        ).to_native_args_hint()
    with pytest.raises(PyEzvizError, match="NUL"):
        hcnetsdk_playback_capture_file_request(1, "bad\x00path").to_native_args_hint()


def test_hcnetsdk_playback_callback_and_secret_key_shapes() -> None:
    callback = hcnetsdk_set_play_data_callback_request(
        1001,
        callback="play_cb",
        user_data=7,
    )
    callback_v40 = hcnetsdk_set_play_data_callback_v40_request(
        1001,
        callback="play_cb_v40",
        user_data="ctx",
    )
    response_callback = hcnetsdk_set_playback_response_callback_request(1001)
    es_callback = hcnetsdk_set_playback_es_callback_request(
        1001,
        callback="es_cb",
    )
    secret_key = hcnetsdk_set_playback_secret_key_request(
        1001,
        EXPECTED_PLAYBACK_SECRET_KEY,
    )

    assert HCNETSDK_SET_PLAY_DATA_CALLBACK == "NET_DVR_SetPlayDataCallBack"
    assert HCNETSDK_SET_PLAY_DATA_CALLBACK_V40 == "NET_DVR_SetPlayDataCallBack_V40"
    assert (
        HCNETSDK_SET_PLAYBACK_RESPONSE_CALLBACK
        == "NET_DVR_SetPlaybackResponseCallBack"
    )
    assert HCNETSDK_SET_PLAYBACK_ES_CALLBACK == "NET_DVR_SetPlayBackESCallBack"
    assert HCNETSDK_SET_PLAYBACK_SECRET_KEY == "NET_DVR_SetPlayBackSecretKey"
    assert HCNETSDK_SECRET_KEY_TYPE_AES == 1
    assert callback == HcNetSdkPlayDataCallbackRequest(
        play_handle=1001,
        callback="play_cb",
        user_data=7,
    )
    assert callback.to_native_args_hint() == {
        "api": HCNETSDK_SET_PLAY_DATA_CALLBACK,
        "lPlayHandle": 1001,
        "fPlayDataCallBack": "play_cb",
        "dwUser": 7,
        "callbackSignature": (
            "void(int playHandle, uint dataType, byte* buffer, "
            "uint length, uint user)"
        ),
    }
    assert callback_v40 == HcNetSdkPlayDataCallbackRequest(
        play_handle=1001,
        callback="play_cb_v40",
        user_data="ctx",
        api=HCNETSDK_SET_PLAY_DATA_CALLBACK_V40,
    )
    assert callback_v40.is_v40 is True
    assert callback_v40.to_native_args_hint() == {
        "api": HCNETSDK_SET_PLAY_DATA_CALLBACK_V40,
        "lPlayHandle": 1001,
        "fPlayDataCallBack_V40": "play_cb_v40",
        "pUser": "ctx",
        "callbackSignature": (
            "void(int playHandle, int dataType, byte* buffer, "
            "uint length, void* user)"
        ),
    }
    assert response_callback == HcNetSdkPlaybackCallbackRequest(
        play_handle=1001,
    )
    assert response_callback.to_native_args_hint() == {
        "api": HCNETSDK_SET_PLAYBACK_RESPONSE_CALLBACK,
        "lPlayHandle": 1001,
        "fPlaybackResponseCallBack": "<PlaybackResponseCallBack>",
        "pUser": None,
    }
    assert es_callback == HcNetSdkPlaybackCallbackRequest(
        play_handle=1001,
        callback="es_cb",
        api=HCNETSDK_SET_PLAYBACK_ES_CALLBACK,
    )
    assert es_callback.to_native_args_hint() == {
        "api": HCNETSDK_SET_PLAYBACK_ES_CALLBACK,
        "lPlayHandle": 1001,
        "fPlayBackESCallBack": "es_cb",
        "pUser": None,
    }
    assert secret_key == HcNetSdkPlayBackSecretKeyRequest(
        play_handle=1001,
        secret_key=EXPECTED_PLAYBACK_SECRET_KEY,
    )
    assert secret_key.to_native_args_hint() == {
        "api": HCNETSDK_SET_PLAYBACK_SECRET_KEY,
        "lPlayHandle": 1001,
        "dwSecretKeyType": HCNETSDK_SECRET_KEY_TYPE_AES,
        "pSecretKey": "<secret-key>",
        "dwSecretKeyLen": len(EXPECTED_PLAYBACK_SECRET_KEY),
    }
    assert secret_key.to_native_args_hint(include_secret=True)["pSecretKey"] == (
        EXPECTED_PLAYBACK_SECRET_KEY
    )

    with pytest.raises(PyEzvizError, match="playback handle"):
        hcnetsdk_set_play_data_callback_request(-1).to_native_args_hint()
    with pytest.raises(PyEzvizError, match="playback handle"):
        hcnetsdk_set_playback_response_callback_request(-1).to_native_args_hint()
    with pytest.raises(PyEzvizError, match="secret-key type"):
        hcnetsdk_set_playback_secret_key_request(
            1001,
            EXPECTED_PLAYBACK_SECRET_KEY,
            secret_key_type=-1,
        ).to_native_args_hint()
    with pytest.raises(PyEzvizError, match="cannot be empty"):
        hcnetsdk_set_playback_secret_key_request(1001, b"").to_native_args_hint()
    with pytest.raises(PyEzvizError, match="unsupported"):
        HcNetSdkPlayDataCallbackRequest(1001, api="bad").to_native_args_hint()
    with pytest.raises(PyEzvizError, match="unsupported"):
        HcNetSdkPlaybackCallbackRequest(1001, api="bad").to_native_args_hint()


def test_hcnetsdk_playback_download_request_shapes() -> None:
    start_time = hcnetsdk_time(2026, 6, 20, hour=11, minute=0)
    stop_time = hcnetsdk_time(2026, 6, 20, hour=11, minute=5)
    name_download = hcnetsdk_get_file_by_name_request(
        42,
        "record001.mp4",
        "/tmp/record001.mp4",
    )
    time_download = hcnetsdk_get_file_by_time_request(
        42,
        1,
        start_time,
        stop_time,
        "/tmp/time.mp4",
    )
    stop_download = hcnetsdk_stop_get_file_request(2002)
    progress = hcnetsdk_get_download_pos_request(2002)

    assert HCNETSDK_GET_FILE_BY_NAME == "NET_DVR_GetFileByName"
    assert HCNETSDK_GET_FILE_BY_TIME == "NET_DVR_GetFileByTime"
    assert HCNETSDK_STOP_GET_FILE == "NET_DVR_StopGetFile"
    assert HCNETSDK_GET_DOWNLOAD_POS == "NET_DVR_GetDownloadPos"
    assert HCNETSDK_GET_FILE_FAILED == -1
    assert name_download == HcNetSdkGetFileByNameRequest(
        login_id=42,
        dvr_file_name="record001.mp4",
        saved_file_name="/tmp/record001.mp4",
    )
    assert name_download.to_native_args_hint() == {
        "api": HCNETSDK_GET_FILE_BY_NAME,
        "lUserID": 42,
        "sDVRFileName": "record001.mp4",
        "sSavedFileName": "/tmp/record001.mp4",
        "failureHandle": HCNETSDK_GET_FILE_FAILED,
    }
    assert name_download.to_native_args_hint(include_buffers=True)[
        "sDVRFileName"
    ] == EXPECTED_PLAYBACK_FIND_FILE_NAME
    assert time_download == HcNetSdkGetFileByTimeRequest(
        login_id=42,
        channel=1,
        start_time=start_time,
        stop_time=stop_time,
        saved_file_name="/tmp/time.mp4",
    )
    assert time_download.to_native_args_hint() == {
        "api": HCNETSDK_GET_FILE_BY_TIME,
        "lUserID": 42,
        "lChannel": 1,
        "lpStartTime": start_time.to_native_dict(),
        "lpStopTime": stop_time.to_native_dict(),
        "sSavedFileName": "/tmp/time.mp4",
        "failureHandle": HCNETSDK_GET_FILE_FAILED,
    }
    assert hcnetsdk_get_file_by_time_request(
        42,
        1,
        date(2026, 6, 20),
        date(2026, 6, 20),
        "/tmp/day.mp4",
    ).stop_time == HcNetSdkTime(2026, 6, 20, 23, 59, 59)
    assert stop_download == HcNetSdkStopGetFileRequest(file_handle=2002)
    assert stop_download.to_native_args_hint() == {
        "api": HCNETSDK_STOP_GET_FILE,
        "lFileHandle": 2002,
    }
    assert progress == HcNetSdkGetDownloadPosRequest(file_handle=2002)
    assert progress.to_native_args_hint() == {
        "api": HCNETSDK_GET_DOWNLOAD_POS,
        "lFileHandle": 2002,
    }

    with pytest.raises(PyEzvizError, match="successful login"):
        hcnetsdk_get_file_by_name_request(
            -1,
            "record001.mp4",
            "/tmp/out.mp4",
        ).to_native_args_hint()
    with pytest.raises(PyEzvizError, match="cannot be empty"):
        hcnetsdk_get_file_by_name_request(
            42,
            "",
            "/tmp/out.mp4",
        ).to_native_args_hint()
    with pytest.raises(PyEzvizError, match="channel"):
        hcnetsdk_get_file_by_time_request(
            42,
            -1,
            start_time,
            stop_time,
            "/tmp/out.mp4",
        ).to_native_args_hint()
    with pytest.raises(PyEzvizError, match="file handle"):
        hcnetsdk_stop_get_file_request(-1).to_native_args_hint()
    with pytest.raises(PyEzvizError, match="file handle"):
        hcnetsdk_get_download_pos_request(-1).to_native_args_hint()


def test_sadp_lifecycle_log_and_v40_network_request_shapes() -> None:
    net_param = sadp_device_net_param(
        ipv4_address=SADP_TEST_IPV4_ADDRESS,
        ipv4_subnet_mask="255.255.255.0",
        ipv4_gateway="192.0.2.1",
        dhcp_enabled=True,
        http_port=80,
        command_port=8000,
    )
    ret_net_param = SadpDeviceRetNetParam(
        retry_modify_time=2,
        surplus_lock_time=30,
    )
    request = sadp_modify_device_net_param_v40_request(
        "00:11:22:33:44:55",
        "secret",
        net_param,
        ret_net_param=ret_net_param,
    )
    start_v30 = sadp_start_v30_request(
        install_npf=True,
        callback="cb30",
        user_data="ctx",
    )
    start_v40 = sadp_start_v40_request()
    log_request = sadp_set_log_to_file_request(
        3,
        "/tmp/sadp/",
        auto_delete=True,
    )

    assert SADP_MODIFY_DEVICE_NET_PARAM_V40 == "SADP_ModifyDeviceNetParam_V40"
    assert SADP_DEV_RET_NET_PARAM_FIELD_ORDER == (
        "byRetryModifyTime",
        "bySurplusLockTime",
        "byRes",
    )
    assert SADP_DEV_RET_NET_PARAM_BUFFER_SIZE == 128
    assert SADP_GET_VERSION == "SADP_GetSadpVersion"
    assert SADP_SET_LOG_TO_FILE == "SADP_SetLogToFile"
    assert SADP_START_V30 == "SADP_Start_V30"
    assert SADP_START_V40 == "SADP_Start_V40"
    assert SADP_STOP == "SADP_Stop"
    assert SADP_CLEARUP == "SADP_Clearup"
    assert SADP_SEND_INQUIRY == "SADP_SendInquiry"
    assert sadp_get_last_error_request() == SadpNoArgRequest(
        api=SADP_GET_LAST_ERROR
    )
    assert sadp_get_sadp_version_request().to_native_args_hint() == {
        "api": SADP_GET_VERSION,
    }
    assert sadp_stop_request().to_native_args_hint() == {"api": SADP_STOP}
    assert sadp_clearup_request().to_native_args_hint() == {"api": SADP_CLEARUP}
    assert sadp_send_inquiry_request().to_native_args_hint() == {
        "api": SADP_SEND_INQUIRY,
    }
    assert start_v30 == SadpStartRequest(
        version=30,
        install_npf=True,
        callback="cb30",
        user_data="ctx",
    )
    assert start_v30.to_native_args_hint() == {
        "api": SADP_START_V30,
        "pDeviceFindCallBack": "cb30",
        "bInstallNPF": 1,
        "pUserData": "ctx",
    }
    assert start_v40.to_native_args_hint() == {
        "api": SADP_START_V40,
        "pDeviceFindCallBack_v40": "<DeviceFindCallBack_V40>",
        "bInstallNPF": 0,
        "pUserData": "<Pointer.NULL>",
    }
    assert log_request == SadpSetLogToFileRequest(
        log_level=3,
        log_dir="/tmp/sadp/",
        auto_delete=True,
    )
    assert log_request.to_native_args_hint() == {
        "api": SADP_SET_LOG_TO_FILE,
        "nLogLevel": 3,
        "strLogDir": "/tmp/sadp/",
        "bAutoDel": 1,
    }
    assert log_request.to_native_args_hint(include_buffer=True)["strLogDir"] == (
        EXPECTED_SADP_LOG_DIR_BUFFER
    )
    assert ret_net_param.to_native_dict() == {
        "structure": "SADP_DEV_RET_NET_PARAM",
        "fieldOrder": SADP_DEV_RET_NET_PARAM_FIELD_ORDER,
        "dwSize": "sizeof(SADP_DEV_RET_NET_PARAM)",
        "byResLength": 126,
        "byRetryModifyTime": 2,
        "bySurplusLockTime": 30,
    }
    assert request == SadpModifyDeviceNetParamV40Request(
        mac="00:11:22:33:44:55",
        password="secret",
        net_param=net_param,
        ret_net_param=ret_net_param,
    )
    assert request.to_native_args_hint() == {
        "api": SADP_MODIFY_DEVICE_NET_PARAM_V40,
        "mac": "00:11:22:33:44:55",
        "password": "<password>",
        "passwordLength": 6,
        "netParam": net_param.to_native_dict(),
        "lpRetNetParam": ret_net_param.to_native_dict(),
        "dwOutBuffSize": SADP_DEV_RET_NET_PARAM_BUFFER_SIZE,
        "lastErrorApi": SADP_GET_LAST_ERROR,
    }
    assert request.to_native_args_hint(include_password=True)["password"] == "secret"

    with pytest.raises(PyEzvizError, match="30 or 40"):
        SadpStartRequest(version=31).to_native_args_hint()
    with pytest.raises(PyEzvizError, match="log level"):
        sadp_set_log_to_file_request(-1, "/tmp/sadp/").to_native_args_hint()
    with pytest.raises(PyEzvizError, match="one byte"):
        SadpDeviceRetNetParam(retry_modify_time=300).to_native_dict()


def test_sadp_batch_results_match_rn_result_maps() -> None:
    activate = ezviz_lan_sadp_activate_batch_result(
        " CAM123456 ",
        "secret",
        code=0,
        error=0,
    )
    edit = ezviz_lan_sadp_edit_net_param_batch_result(
        "00:11:22:33:44:55",
        "secret",
        code=1,
        error=23,
    )

    assert activate == SadpBatchResult(
        identifier=" CAM123456 ",
        password="secret",
        code=0,
        error=0,
        identifier_key="serial",
    )
    assert activate.to_rn_dict() == {
        "serial": "CAM123456",
        "password": "secret",
        "code": 0,
        "error": 0,
    }
    assert activate.to_rn_dict(include_password=False)["password"] == "<password>"
    assert edit.to_rn_dict() == {
        "mac": "00:11:22:33:44:55",
        "password": "secret",
        "code": 1,
        "error": 23,
    }

    with pytest.raises(PyEzvizError, match="unsupported"):
        SadpBatchResult("CAM123456", "secret", 0, 0, "device").to_rn_dict()
    with pytest.raises(PyEzvizError, match="identifier"):
        SadpBatchResult(" ", "secret", 0, 0, "serial").to_rn_dict()
    with pytest.raises(PyEzvizError, match="password"):
        SadpBatchResult("CAM123456", "", 0, 0, "serial").to_rn_dict()


def test_sadp_network_param_rejects_invalid_fields() -> None:
    def make_net_param(
        *,
        ipv4_address: str = SADP_TEST_IPV4_ADDRESS,
        dhcp_enabled: int | bool = False,
        http_port: int = 80,
    ) -> SadpDeviceNetParam:
        return sadp_device_net_param(
            ipv4_address=ipv4_address,
            ipv4_subnet_mask="255.255.255.0",
            ipv4_gateway="192.0.2.1",
            dhcp_enabled=dhcp_enabled,
            http_port=http_port,
            command_port=8000,
        )

    with pytest.raises(PyEzvizError, match="IPv4 address"):
        make_net_param(ipv4_address="").to_native_dict()
    with pytest.raises(PyEzvizError, match="at most 16 bytes"):
        make_net_param(ipv4_address="12345678901234567").to_native_dict()
    with pytest.raises(PyEzvizError, match="between 0 and 65535"):
        make_net_param(http_port=70000).to_native_dict()
    with pytest.raises(PyEzvizError, match="one byte"):
        make_net_param(dhcp_enabled=300).to_native_dict()
    with pytest.raises(PyEzvizError, match="MAC"):
        sadp_modify_device_net_param_request(
            " ",
            "secret",
            make_net_param(),
        ).to_native_args_hint()
    with pytest.raises(PyEzvizError, match="password"):
        sadp_modify_device_net_param_request(
            "00:11:22:33:44:55",
            "",
            make_net_param(),
        ).to_native_args_hint()


def test_parse_ezviz_local_sdk_frame_header_from_local_trace() -> None:
    header = bytes.fromhex(
        "9e ba ac e9 01 00 00 00 00 00 00 15 00 00 00 00 "
        "00 00 31 05 ff ff ff ff 00 00 00 80 00 00 00 00"
    )

    parsed = parse_ezviz_local_sdk_frame_header(header)

    assert parsed.magic == bytes.fromhex("9e ba ac e9")
    assert parsed.version == 0x01000000
    assert parsed.sequence == 0x15
    assert parsed.marker == 0
    assert parsed.command == 0x3105
    assert parsed.status == 0xFFFFFFFF
    assert parsed.body_length == 0x80
    assert parsed.reserved == 0


def test_build_ezviz_local_sdk_frame_header_matches_local_shape() -> None:
    header = build_ezviz_local_sdk_frame_header(
        command=0x3105,
        body_length=0x80,
        sequence=0x15,
    )

    assert header == bytes.fromhex(
        "9e ba ac e9 01 00 00 00 00 00 00 15 00 00 00 00 "
        "00 00 31 05 ff ff ff ff 00 00 00 80 00 00 00 00"
    )


def test_build_and_parse_ezviz_local_sdk_frame_round_trips_body() -> None:
    body = b"<Request><Channel>1</Channel></Request>"

    frame = build_ezviz_local_sdk_frame(
        command=0x2011,
        body=body,
        sequence=7,
    )

    parsed = parse_ezviz_local_sdk_frame(frame)

    assert parsed.header.command == 0x2011
    assert parsed.header.sequence == 7
    assert parsed.header.body_length == len(parsed.body)
    assert parsed.body == body


def test_encrypt_ezviz_local_sdk_body_aes_cbc_round_trips() -> None:
    key = b"0123456789abcdef"
    iv = b"abcdef0123456789"
    body = b"<Request><Session>7</Session></Request>"

    encrypted = encrypt_ezviz_local_sdk_body_aes_cbc(body, key=key, iv=iv)

    assert len(encrypted) % 16 == 0
    assert encrypted != body
    assert decrypt_ezviz_local_sdk_body_aes_cbc(encrypted, key=key, iv=iv) == body


def test_build_encrypted_ezviz_local_sdk_frame_wraps_encrypted_body() -> None:
    body = b"<Request/>"
    frame = build_encrypted_ezviz_local_sdk_frame(
        command=0x3105,
        body=body,
        key="0123456789abcdef",
        iv="abcdef0123456789",
        sequence=19,
    )

    parsed = parse_ezviz_local_sdk_frame(frame)

    assert parsed.header.command == 0x3105
    assert parsed.header.sequence == 19
    assert parsed.header.body_length == 16
    assert decrypt_ezviz_local_sdk_body_aes_cbc(
        parsed.body,
        key="0123456789abcdef",
        iv="abcdef0123456789",
    ) == body


def test_build_ezviz_local_sdk_ssl_frame_appends_ciphertext_md5_trailer() -> None:
    body = b"<Request/>"
    frame = build_ezviz_local_sdk_ssl_frame(
        command=0x2011,
        body=body,
        key=LOCAL_SDK_TEST_KEY,
        iv=LOCAL_SDK_SSL_IV,
        sequence=16,
    )

    parsed = parse_ezviz_local_sdk_frame(frame)

    assert parsed.header.command == 0x2011
    assert parsed.header.sequence == 16
    assert parsed.header.body_length == 16
    assert parsed.trailer == hashlib.md5(
        parsed.body, usedforsecurity=False
    ).hexdigest().encode("ascii")
    assert len(frame) == 32 + parsed.header.body_length + 32
    assert decrypt_ezviz_local_sdk_body_aes_cbc(
        parsed.body,
        key=LOCAL_SDK_TEST_KEY,
        iv=LOCAL_SDK_SSL_IV,
    ) == body


def test_ezviz_cas_device_info_derives_local_sdk_iv() -> None:
    device_info = EzvizCasDeviceInfo(
        serial="CAM123456",
        operation_code="0123456",
        key="1234567890abcdef",
        encrypt_type=2,
    )

    assert device_info.key_bytes == LOCAL_SDK_TEST_KEY
    assert device_info.iv_bytes == LOCAL_SDK_TEST_IV
    assert ezviz_local_sdk_iv("CAM123456", "0123456") == LOCAL_SDK_TEST_IV


def test_ezviz_cas_device_info_accepts_base64_local_sdk_key() -> None:
    device_info = EzvizCasDeviceInfo(
        serial="CAM123456",
        operation_code="0123456",
        key="MTIzNDU2Nzg5MGFiY2RlZg==",
        encrypt_type=2,
    )

    assert device_info.key_bytes == LOCAL_SDK_TEST_KEY


def test_ezviz_local_sdk_ssl_iv_uses_app_prefix_and_zero_tail() -> None:
    iv = ezviz_local_sdk_ssl_iv()

    assert iv == b"01234567" + bytes(8)


def test_build_ezviz_cas_encrypted_local_sdk_frame_uses_device_info() -> None:
    device_info = EzvizCasDeviceInfo(
        serial="CAM123456",
        operation_code="0123456",
        key="1234567890abcdef",
    )
    body = "<Request><Session>1</Session></Request>"

    frame = build_ezviz_cas_encrypted_local_sdk_frame(
        command=EZVIZ_LOCAL_SDK_STREAM_SETUP_COMMAND,
        body=body,
        device_info=device_info,
        sequence=21,
    )
    parsed = parse_ezviz_local_sdk_frame(frame)

    assert parsed.header.command == EZVIZ_LOCAL_SDK_STREAM_SETUP_COMMAND
    assert parsed.header.sequence == 21
    assert decrypt_ezviz_local_sdk_body_aes_cbc(
        parsed.body,
        key=device_info.key_bytes,
        iv=device_info.iv_bytes,
    ) == body.encode()


def test_build_ezviz_cas_ssl_local_sdk_frame_uses_cas_key_and_md5_trailer() -> None:
    device_info = EzvizCasDeviceInfo(
        serial="CAM123456",
        operation_code="0123456",
        key="1234567890abcdef",
    )
    body = "<Request><Session>1</Session></Request>"

    frame = build_ezviz_cas_ssl_local_sdk_frame(
        command=EZVIZ_LOCAL_SDK_STREAM_SETUP_COMMAND,
        body=body,
        device_info=device_info,
        iv=LOCAL_SDK_SSL_IV,
        sequence=17,
    )
    parsed = parse_ezviz_local_sdk_frame(frame)

    assert parsed.header.command == EZVIZ_LOCAL_SDK_STREAM_SETUP_COMMAND
    assert parsed.header.sequence == 17
    assert parsed.trailer == hashlib.md5(
        parsed.body, usedforsecurity=False
    ).hexdigest().encode("ascii")
    assert decrypt_ezviz_local_sdk_body_aes_cbc(
        parsed.body,
        key=device_info.key_bytes,
        iv=LOCAL_SDK_SSL_IV,
    ) == body.encode()


def test_build_ezviz_local_preview_request_body_uses_observed_tag_order() -> None:
    body = build_ezviz_local_preview_request_body(
        operation_code="op&code",
        channel=1,
        receiver_info="receiver<info>",
        receiver_info_ex="receiver-ex",
        authentication="auth",
        uuid="uuid",
        timestamp=123456,
    )

    assert body == EXPECTED_PREVIEW_XML
    assert classify_ezviz_local_sdk_body(body).xml_tags == (
        "Request",
        "OperationCode",
        "Channel",
        "ReceiverInfo",
        "IsEncrypt",
        "ReceiverInfoEx",
        "Authentication",
        "Uuid",
        "Timestamp",
    )


def test_build_ezviz_local_preview_request_body_supports_structured_receiver_info() -> None:
    body = build_ezviz_local_preview_request_body(
        operation_code="op",
        channel=1,
        identifier="ident",
        receiver_info=EzvizLocalReceiverInfo(
            nat_address="192.0.2.10",
            nat_port=9010,
            upnp_address="",
            upnp_port=0,
            inner_address="192.0.2.20",
            inner_port=9020,
            stream_type="MAIN",
        ),
        receiver_info_ex="receiver-ex",
        udt=1,
        nat=2,
        port_guess_type=5,
        timeout=30,
        heartbeat_interval=10,
    )

    assert body == EXPECTED_STRUCTURED_PREVIEW_XML
    assert classify_ezviz_local_sdk_body(body).xml_tags == (
        "Request",
        "OperationCode",
        "Channel",
        "Identifier",
        "ReceiverInfo",
        "NatAddress",
        "NatPort",
        "UPnPAddress",
        "UPnPPort",
        "InnerAddress",
        "InnerPort",
        "StreamType",
        "IsEncrypt",
        "Udt",
        "Nat",
        "PortGuessType",
        "Timeout",
        "HeartbeatInterval",
        "ReceiverInfoEx",
    )


def test_ezviz_local_receiver_info_rejects_negative_ports() -> None:
    request = EzvizLocalPreviewRequest(
        operation_code="op",
        channel=1,
        receiver_info=EzvizLocalReceiverInfo(nat_port=-1),
        receiver_info_ex="receiver-ex",
    )

    with pytest.raises(PyEzvizError, match="nat_port"):
        request.to_xml()


def test_build_ezviz_local_preview_request_body_supports_structured_receiver_info_ex() -> None:
    body = build_ezviz_local_preview_request_body(
        operation_code="op",
        channel=1,
        receiver_info="receiver",
        receiver_info_ex=EzvizLocalReceiverInfoEx(uuid="uuid", timestamp=123456),
    )

    assert body == EXPECTED_STRUCTURED_PREVIEW_EX_XML
    assert classify_ezviz_local_sdk_body(body).xml_tags == (
        "Request",
        "OperationCode",
        "Channel",
        "ReceiverInfo",
        "IsEncrypt",
        "ReceiverInfoEx",
        "Authentication",
        "Uuid",
        "Timestamp",
    )


def test_ezviz_local_preview_request_to_xml_matches_builder() -> None:
    request = EzvizLocalPreviewRequest(
        operation_code="op",
        channel=2,
        receiver_info="receiver",
        receiver_info_ex="receiver-ex",
    )

    assert request.to_xml() == build_ezviz_local_preview_request_body(
        operation_code="op",
        channel=2,
        receiver_info="receiver",
        receiver_info_ex="receiver-ex",
    )


def test_build_ezviz_local_stream_setup_request_body_uses_observed_shape() -> None:
    body = build_ezviz_local_stream_setup_request_body(session="1", rate=0, mode=1)

    assert body == EXPECTED_STREAM_SETUP_XML
    assert classify_ezviz_local_sdk_body(body).xml_tags == (
        "Request",
        "Session",
        "Rate",
        "Mode",
    )


def test_parse_ezviz_local_sdk_xml_fields_extracts_response_values() -> None:
    frame = build_ezviz_local_sdk_frame(
        command=0x2012,
        body=(
            "<Response><Result>0</Result><Session>765</Session>"
            "<StreamHeader>header</StreamHeader></Response>"
        ),
    )

    fields = parse_ezviz_local_sdk_xml_fields(parse_ezviz_local_sdk_frame(frame))

    assert fields == {
        "Result": "0",
        "Session": "765",
        "StreamHeader": "header",
    }


def test_encrypt_ezviz_local_sdk_body_aes_cbc_rejects_bad_key_length() -> None:
    with pytest.raises(PyEzvizError, match="key"):
        encrypt_ezviz_local_sdk_body_aes_cbc(b"body", key=b"short", iv=b"0" * 16)


def test_ezviz_local_sdk_iv_rejects_bad_length() -> None:
    with pytest.raises(PyEzvizError, match="16 bytes"):
        ezviz_local_sdk_iv("CAM123", "short")


def test_read_ezviz_local_sdk_frame_handles_fragmented_socket_reads() -> None:
    body = b"<Response/>"
    frame = build_ezviz_local_sdk_frame(command=0x2012, body=body)
    sock = _FragmentedSocket([frame[:5], frame[5:33], frame[33:]])

    parsed = read_ezviz_local_sdk_frame(sock)

    assert parsed.header.command == 0x2012
    assert parsed.body == body


def test_classify_ezviz_local_sdk_body_detects_xml_tags_only() -> None:
    shape = classify_ezviz_local_sdk_body(
        b'<?xml version="1.0"?><Response><Result>0</Result></Response>'
    )

    assert shape.kind == "xml"
    assert shape.length > 0
    assert shape.xml_offset == 0
    assert shape.xml_tags == ("Response", "Result")
    assert shape.printable_ratio == 1.0


def test_classify_ezviz_local_sdk_body_detects_prefixed_xml() -> None:
    shape = classify_ezviz_local_sdk_body(
        b"\x01\x02\x00\x00<?xml version=\"1.0\"?><Response/>"
    )

    assert shape.kind == "prefixed_xml"
    assert shape.xml_offset == 4
    assert shape.xml_tags == ("Response",)


def test_classify_ezviz_local_sdk_body_detects_opaque_binary() -> None:
    shape = classify_ezviz_local_sdk_body(bytes(range(128, 256)))

    assert shape.kind == "opaque_binary"
    assert shape.xml_offset is None
    assert shape.xml_tags == ()
    assert shape.high_bit_ratio == 1.0


def test_classify_ezviz_local_sdk_body_detects_empty_body() -> None:
    shape = classify_ezviz_local_sdk_body(b"")

    assert shape.kind == "empty"
    assert shape.length == 0
    assert shape.entropy_bits_per_byte == 0.0


def test_classify_hcnetsdk_tcp_payload_detects_tls_records() -> None:
    shape = classify_hcnetsdk_tcp_payload(bytes.fromhex("16 03 01 00 04 01 02 03 04"))

    assert shape.kind == "tls_record"
    assert shape.length == 9
    assert shape.u16be_0 == 0x1603
    assert shape.u32be_0 == 0x16030100


def test_classify_hcnetsdk_tcp_payload_detects_length_prefixed_binary() -> None:
    payload = len(b"\x00\x00\x00\x0cabcdefgh").to_bytes(4, "big") + b"abcdefgh"

    shape = classify_hcnetsdk_tcp_payload(payload)

    assert shape.kind == "length_prefixed_binary"
    assert shape.declared_length_offset == 0
    assert shape.declared_length == len(payload)
    assert shape.u32be_0 == len(payload)
    assert shape.u32be_4 == int.from_bytes(b"abcd", "big")
    assert shape.u32le_4 == int.from_bytes(b"abcd", "little")
    assert shape.printable_ratio > HCNETSDK_TCP_MIN_PRINTABLE_RATIO


def test_classify_hcnetsdk_tcp_payload_detects_local_sdk_frame() -> None:
    frame = build_ezviz_local_sdk_frame(command=EZVIZ_LOCAL_SDK_PREVIEW_COMMAND)

    shape = classify_hcnetsdk_tcp_payload(frame)

    assert shape.kind == "ezviz_local_sdk_frame"
    assert shape.u32be_0 == 0x9EBAACE9


def test_parse_hcnetsdk_tcp_shape_log_line_from_narrow_hook() -> None:
    line = (
        "[hcnetsdk-send] fd=42 192.0.2.10:8000 "
        "tcpKind=opaque_binary tcpLen=84 captured=84 fp128=84:0123abcd "
        f"printable={HCNETSDK_TCP_LOG_PRINTABLE_RATIO} "
        f"nulls={HCNETSDK_TCP_LOG_NULL_RATIO} "
        f"high={HCNETSDK_TCP_LOG_HIGH_BIT_RATIO} "
        "u16be0=0x1234 u16le0=0x3412 u32be0=0x12345678 u32le0=0x78563412 "
        "u32be4=0x00000054 u32le4=0x54000000 "
        "u32be8=0x00000001 u32le8=0x01000000 "
        "u32be12=0x00000100 u32le12=0x00010000 "
        "lengthCandidates=u32be@4=84,u16le@12=80"
    )

    record = parse_hcnetsdk_tcp_shape_log_line(line)

    assert record is not None
    assert record.direction == "send"
    assert record.fd == 42
    assert record.host == "192.0.2.10"
    assert record.port == 8000
    assert record.shape.kind == "opaque_binary"
    assert record.shape.length == 84
    assert record.shape.printable_ratio == HCNETSDK_TCP_LOG_PRINTABLE_RATIO
    assert record.shape.null_ratio == HCNETSDK_TCP_LOG_NULL_RATIO
    assert record.shape.high_bit_ratio == HCNETSDK_TCP_LOG_HIGH_BIT_RATIO
    assert record.shape.u16be_0 == 0x1234
    assert record.shape.u16le_0 == 0x3412
    assert record.shape.u32be_0 == 0x12345678
    assert record.shape.u32le_0 == 0x78563412
    assert record.shape.u32be_4 == 84
    assert record.shape.u32le_4 == 0x54000000
    assert record.shape.u32be_8 == 1
    assert record.shape.u32le_8 == 0x01000000
    assert record.shape.u32be_12 == 256
    assert record.shape.u32le_12 == 0x00010000
    assert record.shape.declared_length_offset == 4
    assert record.shape.declared_length == 84
    assert record.captured_length == 84
    assert record.fingerprint == "84:0123abcd"
    assert record.length_candidates == {"u32be@4": 84, "u16le@12": 80}


def test_parse_hcnetsdk_tcp_shape_log_line_ignores_other_lines() -> None:
    assert parse_hcnetsdk_tcp_shape_log_line("[hcnetsdk-connect] fd=1 ret=0") is None


def test_parse_hcnetsdk_semantic_log_line_from_login_event() -> None:
    event = parse_hcnetsdk_semantic_log_line(
        "[hcnetsdk-semantic] HCNETUtil.s enter "
        "ip=192.0.2.10 port=8000 user=admin pwdLen=6"
    )

    assert event is not None
    assert event.name == "HCNETUtil.s"
    assert event.phase == "enter"
    assert event.fields == {
        "ip": "192.0.2.10",
        "port": "8000",
        "user": "admin",
        "pwdLen": "6",
    }


def test_parse_hcnetsdk_semantic_log_line_from_keyframe_event() -> None:
    event = parse_hcnetsdk_semantic_log_line(
        "[hcnetsdk-semantic] Java HCNetSDK.NET_DVR_MakeKeyFrame leave ret=true"
    )

    assert event is not None
    assert event.name == "Java HCNetSDK.NET_DVR_MakeKeyFrame"
    assert event.phase == "leave"
    assert event.fields == {"ret": "true"}


def test_parse_hcnetsdk_semantic_log_line_ignores_other_lines() -> None:
    assert parse_hcnetsdk_semantic_log_line("[hcnetsdk-send] fd=1") is None
    assert (
        parse_hcnetsdk_semantic_log_line(
            "[hcnetsdk-semantic] waiting for Core_SimpleCommandToDvr "
            "symbol=Core_SimpleCommandToDvr"
        )
        is None
    )
    assert (
        parse_hcnetsdk_semantic_log_line(
            "[hcnetsdk-semantic] Java HCNetSDK login hooks unavailable "
            "TypeError: cannot read property 'overloads' of undefined"
        )
        is None
    )


def test_summarize_hcnetsdk_command_trace_correlates_semantic_boundaries() -> None:
    summary = summarize_hcnetsdk_command_trace(
        [
            (
                "[hcnetsdk-semantic] HCNETUtil.s enter "
                "ip=192.0.2.10 port=8000 user=admin pwdLen=6"
            ),
            (
                "[hcnetsdk-send] fd=296 192.0.2.10:8000 "
                "tcpKind=opaque_binary tcpLen=224 captured=224 fp128=128:93276c8d "
                "printable=0.28 nulls=0.30 high=0.30 "
                "u32be0=0xe0 u32le0=0xe0000000 "
                "u32be4=0x5a000000 u32le4=0x5a "
                "lengthCandidates=u32be@0=224,u32le@4=90"
            ),
            (
                "[hcnetsdk-send] fd=296 192.0.2.10:8000 "
                "tcpKind=binary tcpLen=84 captured=84 fp128=84:b0b0718e "
                "printable=0.24 nulls=0.46 high=0.19 "
                "u32be0=0x54 u32le0=0x54000000 "
                "u32be4=0x5a000000 u32le4=0x5a "
                "lengthCandidates=u32be@0=84,u32le@4=90"
            ),
            "[hcnetsdk-semantic] HCNETUtil.s leave ret=0",
            (
                "[hcnetsdk-send] fd=231 192.0.2.10:8000 "
                "tcpKind=binary tcpLen=36 captured=36 fp128=36:11b54ed7 "
                "printable=0.11 nulls=0.53 high=0.14 "
                "u32be0=0x24 u32le0=0x24000000 "
                "u32be4=0x63000000 u32le4=0x63 "
                "lengthCandidates=u32be@0=36,u32le@4=99"
            ),
            (
                "[hcnetsdk-recv] fd=240 192.0.2.10:8000 "
                "tcpKind=interleaved_media tcpLen=1448 captured=512 "
                "fp128=128:abc printable=0.20 nulls=0.10 high=0.50 "
                "u32be0=0x24000000 u32le0=0x24"
            ),
            "[hcnetsdk-semantic] DeviceInfoEx.loginPlayDevice leave ret=0",
            "[hcnetsdk-semantic] Java HCNetSDK.NET_DVR_MakeKeyFrame leave ret=true",
        ]
    )

    assert summary.settings_login_commands == (90, 90)
    assert summary.followup_commands == (99,)
    assert summary.settings_login_success is True
    assert summary.play_device_login_success is True
    assert summary.keyframe_requested is True
    assert summary.media_on_command_socket is True


def test_iter_hcnetsdk_tcp_frame_shapes_pairs_split_response() -> None:
    lines = [
        (
            "[hcnetsdk-recv] fd=250 192.0.2.10:8000 "
            "tcpKind=binary tcpLen=16 captured=16 fp128=16:ae3f80bf "
            "printable=0.25 nulls=0.56 high=0.06 "
            "u32be0=0xd0 u32le0=0xd0000000 "
            "u32be4=0x00000001 u32le4=0x01000000 "
            "u32be8=0x00000001 u32le8=0x01000000 "
            "u32be12=0x00000000 u32le12=0x00000000 "
            "lengthCandidates=u32be@0=208"
        ),
        (
            "[hcnetsdk-recv] fd=250 192.0.2.10:8000 "
            "tcpKind=opaque_binary tcpLen=192 captured=192 fp128=128:60a94981 "
            "printable=0.59 nulls=0.01 high=0.33 "
            "u32be0=0x2cf7bfa5 u32le0=0xa5bff72c"
        ),
    ]
    records = [parse_hcnetsdk_tcp_shape_log_line(line) for line in lines]

    frames = list(iter_hcnetsdk_tcp_frame_shapes(record for record in records if record))

    assert len(frames) == 1
    assert frames[0].direction == "recv"
    assert frames[0].fd == 250
    assert frames[0].total_length == 208
    assert frames[0].body_length == 192
    assert frames[0].header_shape.u32be_4 == 1
    assert frames[0].header_shape.u32be_8 == 1
    assert frames[0].body_shape is not None
    assert frames[0].body_shape.kind == "opaque_binary"
    assert frames[0].body_shape.length == 192


def test_iter_hcnetsdk_tcp_frame_shapes_yields_whole_write_shape() -> None:
    record = parse_hcnetsdk_tcp_shape_log_line(
        "[hcnetsdk-send] fd=250 192.0.2.10:8000 "
        "tcpKind=opaque_binary tcpLen=224 captured=224 fp128=128:93276c8d "
        "printable=0.28 nulls=0.30 high=0.30 "
        "u32be0=0xe0 u32le0=0xe0000000 "
        "u32be4=0x5a000000 u32le4=0x0000005a "
        "u32be8=0x00000000 u32le8=0x00000000 "
        "u32be12=0x00000100 u32le12=0x00010000 "
        "lengthCandidates=u32be@0=224,u32le@4=90,u32le@12=256"
    )

    frames = list(iter_hcnetsdk_tcp_frame_shapes([record] if record else []))

    assert len(frames) == 1
    assert frames[0].direction == "send"
    assert frames[0].total_length == 224
    assert frames[0].body_length == 208
    assert frames[0].header_shape.u32le_4 == 90
    assert frames[0].write_command_candidate == 90
    assert frames[0].header_shape.u32be_12 == 256
    assert frames[0].body_shape is None
    assert frames[0].write_command_role == "settings_login"


def test_hcnetsdk_command_candidate_role_labels_observed_values() -> None:
    assert (
        hcnetsdk_command_candidate_role(HCNETSDK_COMMAND_CANDIDATE_SETTINGS_LOGIN)
        == "settings_login"
    )
    assert hcnetsdk_command_candidate_role(HCNETSDK_COMMAND_CANDIDATE_CONTROL) == "control"
    assert hcnetsdk_command_candidate_role(None) is None
    assert hcnetsdk_command_candidate_role(12345) is None


def test_iter_hcnetsdk_tcp_frame_shapes_uses_header_word_when_candidate_missing() -> None:
    records = [
        parse_hcnetsdk_tcp_shape_log_line(
            "[hcnetsdk-recv] fd=266 192.0.2.10:8000 "
            "tcpKind=binary tcpLen=16 captured=16 fp128=16:fa807bfd "
            "printable=0.00 nulls=0.75 high=0.13 "
            "u32be0=0x12a8 u32le0=0xa8120000 "
            "u32be4=0x000000ab u32le4=0xab000000 "
            "u32be8=0x00000001 u32le8=0x01000000 "
            "u32be12=0x00000000 u32le12=0x00000000 "
            "lengthCandidates=u32be@4=171,u32be@8=1"
        ),
        parse_hcnetsdk_tcp_shape_log_line(
            "[hcnetsdk-recv] fd=266 192.0.2.10:8000 "
            "tcpKind=binary tcpLen=4760 captured=512 fp128=128:c849f99f "
            "printable=0.00 nulls=1.00 high=0.00 "
            "u32be0=0x1298 u32le0=0x98120000 "
            "lengthCandidates=u32be@0=4760"
        ),
    ]

    frames = list(iter_hcnetsdk_tcp_frame_shapes(record for record in records if record))

    assert len(frames) == 1
    assert frames[0].total_length == 4776
    assert frames[0].body_length == 4760
    assert frames[0].header_shape.u32be_4 == 171
    assert frames[0].write_command_candidate is None
    assert frames[0].body_shape is not None
    assert frames[0].body_shape.length == 4760


def test_iter_hcnetsdk_tcp_frame_shapes_skips_body_like_recv_record() -> None:
    record = parse_hcnetsdk_tcp_shape_log_line(
        "[hcnetsdk-recv] fd=266 192.0.2.10:8000 "
        "tcpKind=binary tcpLen=4760 captured=512 fp128=128:c849f99f "
        "printable=0.00 nulls=1.00 high=0.00 "
        "u32be0=0x1298 u32le0=0x98120000 "
        "lengthCandidates=u32be@0=4760"
    )

    frames = list(iter_hcnetsdk_tcp_frame_shapes([record] if record else []))

    assert frames == []


def test_parse_hcnetsdk_tcp_frame_header_matches_split_response() -> None:
    header = parse_hcnetsdk_tcp_frame_header(
        bytes.fromhex("00 00 00 d0 00 00 00 01 00 00 00 01 00 00 00 00")
    )

    assert HCNETSDK_TCP_HEADER_LENGTH == 16
    assert header.total_length == 208
    assert header.body_length == 192
    assert header.field_4 == 1
    assert header.field_8 == 1
    assert header.field_12 == 0


def test_parse_hcnetsdk_tcp_frame_round_trips_generic_wrapper() -> None:
    frame_bytes = build_hcnetsdk_tcp_frame(
        HCNETSDK_TCP_TEST_BODY, field_4=99, field_8=1
    )

    frame = parse_hcnetsdk_tcp_frame(frame_bytes)

    assert frame.header.total_length == HCNETSDK_TCP_HEADER_LENGTH + len(
        HCNETSDK_TCP_TEST_BODY
    )
    assert frame.header.field_4 == 99
    assert frame.header.field_8 == 1
    assert frame.header.field_12 == 0
    assert frame.body == HCNETSDK_TCP_TEST_BODY
    assert frame.to_bytes() == frame_bytes


def test_read_hcnetsdk_tcp_frame_tolerates_native_short_ack() -> None:
    sock = _FakeSocket([bytes.fromhex("0000000800000019000000080000001a")])

    frame = read_hcnetsdk_tcp_frame(sock)

    assert frame.header.total_length == HCNETSDK_TCP_HEADER_LENGTH
    assert frame.header.field_4 == 25
    assert frame.header.field_8 == 8
    assert frame.header.field_12 == 26
    assert not frame.body


def test_parse_hcnetsdk_tcp_frame_rejects_truncated_body() -> None:
    with pytest.raises(PyEzvizError, match="truncated"):
        parse_hcnetsdk_tcp_frame(bytes.fromhex("00 00 00 20") + (b"\x00" * 12))


def test_classify_hcnetsdk_tcp_payload_detects_interleaved_media() -> None:
    shape = classify_hcnetsdk_tcp_payload(bytes.fromhex("24 00 00 01 80"))

    assert shape.kind == "interleaved_media"
    assert shape.u16be_0 == 0x2400


def test_parse_hcnetsdk_tcp_shape_log_line_from_media_trace() -> None:
    line = (
        "[hcnetsdk-recv] fd=240 192.0.2.10:8000 "
        "tcpKind=interleaved_media tcpLen=7988 captured=512 fp128=128:1aeb56e5 "
        "printable=0.37 nulls=0.02 high=0.46 "
        "u16be0=0x2400 u16le0=0x24 u32be0=0x24000001 u32le0=0x1000024"
    )

    record = parse_hcnetsdk_tcp_shape_log_line(line)

    assert record is not None
    assert record.direction == "recv"
    assert record.fd == 240
    assert record.shape.kind == "interleaved_media"
    assert record.shape.length == 7988
    assert record.captured_length == 512
    assert record.fingerprint == "128:1aeb56e5"
    assert record.shape.u16be_0 == 0x2400


def test_parse_ezviz_local_sdk_frame_header_rejects_bad_magic() -> None:
    with pytest.raises(PyEzvizError, match="magic"):
        parse_ezviz_local_sdk_frame_header(b"bad" + (b"x" * 29))


def test_parse_ezviz_interleaved_rtp_frame_header_from_local_trace() -> None:
    parsed = parse_ezviz_interleaved_rtp_frame_header(bytes.fromhex("24 00 05 86"))

    assert parsed.channel == 0
    assert parsed.payload_length == 1414


def test_build_ezviz_interleaved_rtp_frame_header_round_trips() -> None:
    header = build_ezviz_interleaved_rtp_frame_header(
        channel=2,
        payload_length=188,
    )

    parsed = parse_ezviz_interleaved_rtp_frame_header(header)

    assert header == bytes.fromhex("24 02 00 bc")
    assert parsed.channel == 2
    assert parsed.payload_length == 188


def test_read_ezviz_interleaved_rtp_frame_handles_fragmented_socket_reads() -> None:
    payload = b"rtp!"
    sock = _FragmentedSocket(
        [
            bytes.fromhex("24"),
            bytes.fromhex("00 00"),
            bytes.fromhex("04"),
            payload[:2],
            payload[2:],
        ]
    )

    frame = read_ezviz_interleaved_rtp_frame(sock)

    assert frame.header.channel == 0
    assert frame.header.payload_length == 4
    assert frame.payload == payload


def test_read_ezviz_interleaved_rtp_frame_timeout_raises_device_exception() -> None:
    class TimeoutSocket:
        def recv(self, length: int) -> bytes:
            raise TimeoutError

    with pytest.raises(DeviceException, match="offline or unreachable"):
        read_ezviz_interleaved_rtp_frame(TimeoutSocket())


def test_read_ezviz_interleaved_rtp_frame_after_prefix_keeps_local_preface() -> None:
    prefix = bytes.fromhex(
        "01 00 01 01 00 28 00 00 00 00 27 29 45 38 37 32"
    )
    payload = b"rtp-payload"
    sock = _FragmentedSocket(
        [
            prefix[:3],
            prefix[3:],
            bytes.fromhex("24 00"),
            len(payload).to_bytes(2, "big"),
            payload,
        ]
    )

    read = read_ezviz_interleaved_rtp_frame_after_prefix(sock)

    assert read.prefix == prefix
    assert read.frame.header.channel == 0
    assert read.frame.header.payload_length == len(payload)
    assert read.frame.payload == payload


def test_read_ezviz_interleaved_rtp_frame_after_prefix_rejects_long_preface() -> None:
    sock = _FragmentedSocket([b"abcdef"])

    with pytest.raises(PyEzvizError, match="prefix exceeded"):
        read_ezviz_interleaved_rtp_frame_after_prefix(sock, max_prefix_bytes=3)


def test_read_hcnetsdk_command_port_interleaved_frame_uses_total_length() -> None:
    prefix = b"preface"
    payload = b"a" * 1460
    next_payload = b"next"
    sock = _FragmentedSocket(
        [
            prefix,
            bytes.fromhex("24 00 b8 05"),
            payload,
            bytes.fromhex("24 00 08 00"),
            next_payload,
        ]
    )

    first = read_hcnetsdk_command_port_interleaved_frame_after_prefix(sock)
    second = read_hcnetsdk_command_port_interleaved_frame_after_prefix(sock)

    assert first.prefix == prefix
    assert first.frame.header.channel == 0
    assert first.frame.header.payload_length == len(payload)
    assert first.frame.payload == payload
    assert not second.prefix
    assert second.frame.header.payload_length == len(next_payload)
    assert second.frame.payload == next_payload


def test_read_hcnetsdk_command_port_interleaved_frame_rejects_short_length() -> None:
    sock = _FragmentedSocket([bytes.fromhex("24 00 03 00")])

    with pytest.raises(PyEzvizError, match="length is invalid"):
        read_hcnetsdk_command_port_interleaved_frame_after_prefix(sock)


def test_hcnetsdk_command_port_login_request_matches_native_trace() -> None:
    public_der = bytes.fromhex(
        "30818902818100d2e10c644ddf15515e457d2f76992d96c23c964f1175bffcb8ae7"
        "e3a73f59b05a49e7fe2d8d32362a7804dac6e1f4312805be654faed038f93570"
        "ecdedfe530f75ce05821d529f4cbc41b458f5bb507c074f140ca0515d29b2bf"
        "75d686d9e056ca6a877277bf4d5b02a71f90b6947b5bee494ca921aed4fc20"
        "eba27b55a26db70203010001"
    )

    frame = hcnetsdk_command_port_login_request_frame(
        public_der,
        username="admin",
        local_ip="192.0.2.56",
    )

    assert frame == bytes.fromhex(
        "000000e05a000000000000000001000005013d4b00000001380200c00000000000006f0061"
        "646d696e000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000030818902818100d2e10c644ddf15515e457d2f76992d96c23c964f"
        "1175bffcb8ae7e3a73f59b05a49e7fe2d8d32362a7804dac6e1f4312805be654faed038f93"
        "570ecdedfe530f75ce05821d529f4cbc41b458f5bb507c074f140ca0515d29b2bf75d686d9"
        "e056ca6a877277bf4d5b02a71f90b6947b5bee494ca921aed4fc20eba27b55a26db7020301"
        "0001"
    )


def test_hcnetsdk_command_port_login_proof_uses_native_digest_branches() -> None:
    seed = b"s" * 64
    challenge = b"0123456789abcdef0123456789abcdef"

    digest = hcnetsdk_command_port_password_digest("admin", b"123456", seed)
    primary, secondary = hcnetsdk_command_port_login_proof(
        "admin",
        b"123456",
        challenge,
        seed,
    )

    # These expected values mirror the device's native command-port handshake.
    assert digest == hashlib.sha256(  # codeql[py/weak-sensitive-data-hashing]
        b"admin" + seed + b"123456"
    ).hexdigest().encode()
    assert primary == hmac.new(  # codeql[py/weak-sensitive-data-hashing,py/weak-cryptographic-algorithm]
        challenge,
        b"admin",
        hashlib.md5,
    ).digest()
    assert secondary == hmac.new(  # codeql[py/weak-sensitive-data-hashing,py/weak-cryptographic-algorithm]
        challenge,
        digest,
        hashlib.md5,
    ).digest()


def test_hcnetsdk_command_port_login_proof_frame_shape() -> None:
    seed = b"s" * 64
    challenge = b"0123456789abcdef0123456789abcdef"

    frame = hcnetsdk_command_port_login_proof_frame(
        username="admin",
        password=b"123456",
        challenge=challenge,
        password_seed=seed,
        local_ip="192.0.2.56",
    )
    parsed = parse_hcnetsdk_tcp_frame(frame)
    primary, secondary = hcnetsdk_command_port_login_proof(
        "admin",
        b"123456",
        challenge,
        seed,
    )

    assert parsed.header.total_length == 84
    assert parsed.header.field_4 == 0x5A000000
    assert parsed.header.field_12 == 0x00010000
    assert parsed.body[:20] == bytes.fromhex("05013d4b00000001380200c00000000000006f00")
    assert parsed.body[20:36] == primary
    assert parsed.body[36:52] == b"\x00" * 16
    assert parsed.body[52:68] == secondary


def test_hcnetsdk_command_port_auth_word_matches_native_trace_vectors() -> None:
    session_id = bytes.fromhex("71f872b7")
    auth_seed = 0x143D7840
    key = bytes.fromhex(
        "3630343531663636393865353862623134313139323936386361333030663431"
    )

    assert (
        hcnetsdk_command_port_auth_word(
            session_id=session_id,
            auth_seed=auth_seed,
            command_id=0x11000,
            key=key,
        )
        == 0x8AA5DD6C
    )
    assert (
        hcnetsdk_command_port_auth_word(
            session_id=session_id,
            auth_seed=auth_seed,
            command_id=0x111050,
            key=key,
            addend=0x71F872B9,
        )
        == 0xBBD883CC
    )
    assert (
        hcnetsdk_command_port_auth_word(
            session_id=session_id,
            auth_seed=auth_seed,
            command_id=0x30000,
            key=key,
            addend=0x71F872BC,
        )
        == 0x6207A7FB
    )


def test_hcnetsdk_command_port_auth_word_includes_native_mask_seed() -> None:
    session_id = bytes.fromhex("71f872b7")
    auth_seed = 0x143D7840
    key = bytes.fromhex(
        "3630343531663636393865353862623134313139323936386361333030663431"
    )

    assert (
        hcnetsdk_command_port_auth_word(
            session_id=session_id,
            auth_seed=auth_seed,
            command_id=0x11000,
            key=key,
            mask_seed=b"\x01\x02\x03\x04\x05\x06",
        )
        != 0x8AA5DD6C
    )


def test_hcnetsdk_command_port_control_frame_builds_native_post_login_header() -> None:
    key = bytes.fromhex(
        "3630343531663636393865353862623134313139323936386361333030663431"
    )

    frame = hcnetsdk_command_port_control_frame(
        session_id=bytes.fromhex("71f872b7"),
        auth_seed=0x143D7840,
        command_id=0x111050,
        key=key,
        local_ip="172.18.0.3",
        addend=0x71F872B9,
    )

    assert frame == bytes.fromhex(
        "0000002063000000bbd883cc00111050030012ac71f872b70000000000000000"
    )


def test_hcnetsdk_command_port_control_frame_appends_command_tail() -> None:
    key = bytes.fromhex(
        "3630343531663636393865353862623134313139323936386361333030663431"
    )

    frame = hcnetsdk_command_port_control_frame(
        session_id=HCNETSDK_COMMAND_PORT_TEST_SESSION_ID,
        auth_seed=0x143D7840,
        command_id=0x11000,
        key=key,
        local_ip="192.0.2.56",
        body_tail=HCNETSDK_COMMAND_PORT_TEST_BODY_TAIL,
    )
    parsed = parse_hcnetsdk_tcp_frame(frame)

    assert parsed.header.field_4 == 0x63000000
    assert parsed.header.field_12 == 0x11000
    assert parsed.body == bytes.fromhex(
        "380200c012345678000000000000000000000001"
    )


def test_hcnetsdk_command_port_control_template_strips_session_bound_fields() -> None:
    key = bytes.fromhex(
        "3630343531663636393865353862623134313139323936386361333030663431"
    )
    first_frame = hcnetsdk_command_port_control_frame(
        session_id=bytes.fromhex("71f872b7"),
        auth_seed=0x143D7840,
        command_id=0x11000,
        key=key,
        local_ip="192.0.2.56",
        body_tail=HCNETSDK_COMMAND_PORT_TEST_BODY_TAIL,
    )
    second_frame = hcnetsdk_command_port_control_frame(
        session_id=HCNETSDK_COMMAND_PORT_TEST_SESSION_ID,
        auth_seed=0x143D7840,
        command_id=0x11000,
        key=key,
        local_ip="192.0.2.44",
        body_tail=HCNETSDK_COMMAND_PORT_TEST_BODY_TAIL,
    )

    first_template = hcnetsdk_command_port_control_template_from_frame(
        first_frame,
        name="capability",
    )
    second_template = hcnetsdk_command_port_control_template_from_frame(second_frame)

    assert isinstance(first_template, HcNetSdkCommandPortControlTemplate)
    assert first_template.name == "capability"
    assert first_template.command_id == 0x11000
    assert first_template.body_tail == HCNETSDK_COMMAND_PORT_TEST_BODY_TAIL
    assert first_template.body_tail == second_template.body_tail


def test_hcnetsdk_command_port_control_template_rebuilds_native_frame() -> None:
    key = bytes.fromhex(
        "3630343531663636393865353862623134313139323936386361333030663431"
    )
    template = hcnetsdk_command_port_control_template_from_frame(
        bytes.fromhex(
            "0000002063000000bbd883cc00111050030012ac71f872b70000000000000000"
        ),
        addend=0x71F872B9,
    )

    assert template.to_frame(
        session_id=bytes.fromhex("71f872b7"),
        auth_seed=0x143D7840,
        key=key,
        local_ip="172.18.0.3",
    ) == bytes.fromhex(
        "0000002063000000bbd883cc00111050030012ac71f872b70000000000000000"
    )


def test_hcnetsdk_command_port_control_template_infers_session_relative_addend() -> None:
    key = bytes.fromhex(
        "3630343531663636393865353862623134313139323936386361333030663431"
    )
    template = hcnetsdk_command_port_control_template_from_frame(
        bytes.fromhex(
            "0000002063000000bbd883cc00111050030012ac71f872b70000000000000000"
        ),
        auth_seed=0x143D7840,
        key=key,
    )
    new_session_id = bytes.fromhex("12345678")

    assert template.addend_delta == 2
    assert template.to_frame(
        session_id=new_session_id,
        auth_seed=0x143D7840,
        key=key,
        local_ip="192.0.2.56",
    ) == hcnetsdk_command_port_control_frame(
        session_id=new_session_id,
        auth_seed=0x143D7840,
        command_id=0x111050,
        key=key,
        local_ip="192.0.2.56",
        addend=0x1234567A,
    )


def test_hcnetsdk_command_port_control_template_can_refresh_play_login_date() -> None:
    stale_tail = bytearray(148)
    stale_tail[36:48] = bytes.fromhex("000007ea000000050000001f")
    stale_tail[60:84] = bytes.fromhex(
        "000007ea000000050000001f000000120000002200000038"
    )

    patched = hcnetsdk_command_port_play_login_body_tail_for_today(
        bytes(stale_tail),
        today=date(2026, 6, 13),
    )

    assert patched[36:48] == bytes.fromhex("000007ea000000060000000d")
    assert patched[60:84] == bytes.fromhex(
        "000007ea000000060000000d000000170000003b0000003b"
    )


def test_hcnetsdk_command_port_control_template_renders_dynamic_play_login_tail() -> None:
    key = bytes.fromhex(
        "3630343531663636393865353862623134313139323936386361333030663431"
    )
    stale_tail = bytearray(148)
    stale_tail[36:48] = bytes.fromhex("000007ea000000050000001f")
    stale_tail[60:84] = bytes.fromhex(
        "000007ea000000050000001f000000120000002200000038"
    )
    template = HcNetSdkCommandPortControlTemplate(
        command_id=0x111040,
        body_tail=bytes(stale_tail),
        addend_delta=4,
        body_tail_transform="play_login_today",
    )

    parsed = parse_hcnetsdk_tcp_frame(
        template.to_frame(
            session_id=bytes.fromhex("12345678"),
            auth_seed=0x143D7840,
            key=key,
            local_ip="192.0.2.56",
        )
    )

    today = date.today()
    assert parsed.body[16 + 36 : 16 + 48] == (
        today.year.to_bytes(4, "big")
        + today.month.to_bytes(4, "big")
        + today.day.to_bytes(4, "big")
    )
    assert parsed.body[16 + 72 : 16 + 84] == bytes.fromhex(
        "000000170000003b0000003b"
    )


def test_hcnetsdk_command_port_control_template_rejects_conflicting_addends() -> None:
    with pytest.raises(PyEzvizError, match="addend"):
        HcNetSdkCommandPortControlTemplate(
            command_id=0x11000,
            addend=1,
            addend_delta=2,
        )


def test_hcnetsdk_command_port_control_template_rejects_non_control_frame() -> None:
    with pytest.raises(PyEzvizError, match="0x63"):
        hcnetsdk_command_port_control_template_from_frame(
            build_hcnetsdk_tcp_frame(b"\x00" * 16, field_4=0x5A000000)
        )


def test_hcnetsdk_command_port_client_runs_generated_login() -> None:
    rsa_key = RSA.generate(1024)
    challenge = b"0123456789abcdef0123456789abcdef"
    seed = b"s" * 64
    encrypted_challenge = PKCS1_v1_5.new(rsa_key.publickey()).encrypt(challenge)
    first_response = build_hcnetsdk_tcp_frame(encrypted_challenge + seed)
    second_response_body = (
        HCNETSDK_COMMAND_PORT_TEST_SESSION_ID
        + b"CS-CV310-A0-1B2WFR0120200927CCRRE87288805\x00"
    )
    second_response = build_hcnetsdk_tcp_frame(
        second_response_body,
        field_4=0x10A24BF1,
    )
    sock = _FakeSocket([first_response, second_response])

    def socket_factory(address: tuple[str, int], timeout: float | None) -> _FakeSocket:
        assert address == ("192.0.2.10", 8000)
        assert timeout == HCNETSDK_COMMAND_PORT_TEST_TIMEOUT
        return sock

    client = HcNetSdkCommandPortClient(
        HcNetSdkLanEndpoint(serial="CAM123", host="192.0.2.10"),
        timeout=HCNETSDK_COMMAND_PORT_TEST_TIMEOUT,
        socket_factory=socket_factory,
    )

    session = client.login(
        password=b"123456",
        local_ip="192.0.2.56",
        rsa_key=rsa_key,
    )

    assert isinstance(session, HcNetSdkCommandPortLoginSession)
    assert session.session_id == HCNETSDK_COMMAND_PORT_TEST_SESSION_ID
    assert session.auth_seed == 0x10A24BF1
    assert session.serial == "CS-CV310-A0-1B2WFR0120200927CCRRE87288805"
    assert session.challenge == challenge
    assert session.password_seed == seed
    assert len(sock.sent) == 2
    assert parse_hcnetsdk_tcp_frame(sock.sent[0]).header.total_length == 224
    assert parse_hcnetsdk_tcp_frame(sock.sent[1]).header.total_length == 84


def test_hcnetsdk_device_ability_command_port_template_matches_native_tail() -> None:
    request = ezviz_lan_audio_video_compress_info_ability_request(42, 1)
    template = hcnetsdk_device_ability_command_port_template(request)

    assert hcnetsdk_device_ability_command_port_body_tail(request) == (
        int(HcNetSdkAbility.DEVICE_ENCODE_ALL_V20).to_bytes(4, "big")
        + ezviz_lan_audio_video_compress_info_input(1)
    )
    assert template.command_id == 0x11000
    assert template.addend_delta == 0
    assert template.name == HCNETSDK_GET_DEVICE_ABILITY
    assert template.body_tail.startswith(bytes.fromhex("00000008"))


def test_hcnetsdk_command_port_response_payload_strips_text_padding() -> None:
    empty_response = build_hcnetsdk_tcp_frame(b"\x00\x00ignored\x00")
    json_response = build_hcnetsdk_tcp_frame(b"\x00\x00{\"statusCode\":1}\x00tail")
    xml_response = build_hcnetsdk_tcp_frame(b"\x00\xff<BasicCapability/>\x00")

    assert hcnetsdk_command_port_response_payload(empty_response) == (
        COMMAND_PORT_EMPTY_OUTPUT
    )
    assert hcnetsdk_command_port_response_payload(json_response) == (
        COMMAND_PORT_JSON_STATUS_OUTPUT
    )
    assert hcnetsdk_command_port_response_payload(xml_response) == (
        COMMAND_PORT_BASIC_ABILITY_OUTPUT
    )


def test_hcnetsdk_command_port_execute_template_uses_fresh_control_socket() -> None:
    rsa_key = RSA.generate(1024)
    challenge = b"0123456789abcdef0123456789abcdef"
    seed = b"s" * 64
    first_response = build_hcnetsdk_tcp_frame(
        PKCS1_v1_5.new(rsa_key.publickey()).encrypt(challenge) + seed
    )
    second_response = build_hcnetsdk_tcp_frame(
        HCNETSDK_COMMAND_PORT_TEST_SESSION_ID + b"CAM123\x00",
        field_4=0x10A24BF1,
    )
    output = b"<BasicCapability><SDNum>1</SDNum></BasicCapability>"
    command_response = build_hcnetsdk_tcp_frame(b"\x00\x00" + output + b"\x00")
    login_sock = _FakeSocket([first_response, second_response])
    control_sock = _FakeSocket([command_response])
    sockets = [login_sock, control_sock]

    def socket_factory(address: tuple[str, int], timeout: float | None) -> _FakeSocket:
        assert address == ("192.0.2.10", 8000)
        assert timeout == HCNETSDK_COMMAND_PORT_TEST_TIMEOUT
        return sockets.pop(0)

    request = ezviz_lan_record_ability_request(42)
    response = hcnetsdk_command_port_execute_template(
        HcNetSdkLanEndpoint(serial="CAM123", host="192.0.2.10"),
        b"123456",
        hcnetsdk_device_ability_command_port_template(request),
        local_ip="192.0.2.56",
        timeout=HCNETSDK_COMMAND_PORT_TEST_TIMEOUT,
        socket_factory=socket_factory,
        rsa_key=rsa_key,
    )
    sent_control = parse_hcnetsdk_tcp_frame(control_sock.sent[0])

    assert isinstance(response, HcNetSdkCommandPortControlResponse)
    assert response.output == output
    assert response.text == output.decode()
    assert len(login_sock.sent) == 2
    assert len(control_sock.sent) == 1
    assert login_sock.closed is True
    assert control_sock.closed is True
    assert sent_control.header.field_12 == 0x11000
    assert sent_control.body[16:] == hcnetsdk_device_ability_command_port_body_tail(
        request
    )


def test_hcnetsdk_get_device_ability_command_port_wraps_executor() -> None:
    rsa_key = RSA.generate(1024)
    challenge = b"0123456789abcdef0123456789abcdef"
    seed = b"s" * 64
    sockets = [
        _FakeSocket(
            [
                build_hcnetsdk_tcp_frame(
                    PKCS1_v1_5.new(rsa_key.publickey()).encrypt(challenge) + seed
                ),
                build_hcnetsdk_tcp_frame(
                    HCNETSDK_COMMAND_PORT_TEST_SESSION_ID + b"CAM123\x00",
                    field_4=0x10A24BF1,
                ),
            ]
        ),
        _FakeSocket([build_hcnetsdk_tcp_frame(COMMAND_PORT_RECORD_ABILITY_OUTPUT)]),
    ]

    def socket_factory(address: tuple[str, int], timeout: float | None) -> _FakeSocket:
        assert address == ("192.0.2.10", 8000)
        assert timeout == COMMAND_PORT_DEFAULT_TIMEOUT
        return sockets.pop(0)

    output = hcnetsdk_get_device_ability_command_port(
        HcNetSdkLanEndpoint(serial="CAM123", host="192.0.2.10"),
        b"123456",
        ezviz_lan_record_ability_request(42),
        local_ip="192.0.2.56",
        socket_factory=socket_factory,
        rsa_key=rsa_key,
    )

    assert output == COMMAND_PORT_RECORD_ABILITY_OUTPUT


def test_hcnetsdk_pure_python_client_wraps_device_ability_and_stdxml() -> None:
    rsa_key = RSA.generate(1024)
    challenge = b"0123456789abcdef0123456789abcdef"
    seed = b"s" * 64
    first_login_response = build_hcnetsdk_tcp_frame(
        PKCS1_v1_5.new(rsa_key.publickey()).encrypt(challenge) + seed
    )
    second_login_response = build_hcnetsdk_tcp_frame(
        HCNETSDK_COMMAND_PORT_TEST_SESSION_ID + b"CAM123\x00",
        field_4=0x10A24BF1,
    )
    sockets = [
        _FakeSocket([first_login_response, second_login_response]),
        _FakeSocket([build_hcnetsdk_tcp_frame(b"\x00<RecordAbility/>")]),
        _FakeSocket([first_login_response, second_login_response]),
        _FakeSocket([build_hcnetsdk_tcp_frame(b"\x00\x00\x12\x98")]),
        _FakeSocket([first_login_response, second_login_response]),
        _FakeSocket([build_hcnetsdk_tcp_frame(b'{"servicesSwitch":{"web":1}}')]),
    ]

    def socket_factory(address: tuple[str, int], timeout: float | None) -> _FakeSocket:
        assert address == ("192.0.2.10", 8000)
        assert timeout == COMMAND_PORT_DEFAULT_TIMEOUT
        return sockets.pop(0)

    endpoint = HcNetSdkLanEndpoint(serial="CAM123", host="192.0.2.10")
    client = HcNetSdkPurePythonClient(
        endpoint,
        b"123456",
        local_ip="192.0.2.56",
        socket_factory=socket_factory,
        rsa_key=rsa_key,
    )
    stdxml_request = ezviz_lan_services_switch_get_config()
    stdxml_template = hcnetsdk_stdxml_config_command_port_template(
        stdxml_request,
        command_id=0x12345,
        body_prefix=b"TRACE:",
    )

    assert client.device_ability(ezviz_lan_record_ability_request(42)) == (
        COMMAND_PORT_RECORD_ABILITY_OUTPUT
    )
    assert client.dvr_config(ezviz_lan_hd_config_request(42)) == (
        COMMAND_PORT_HD_CONFIG_OUTPUT
    )
    stdxml_response = client.stdxml_config(stdxml_request, stdxml_template)
    assert stdxml_response == HcNetSdkStdXmlConfigResponse(
        succeeded=True,
        output=b'{"servicesSwitch":{"web":1}}',
        returned_xml_size=len(b'{"servicesSwitch":{"web":1}}'),
    )
    assert stdxml_response.json() == {"servicesSwitch": {"web": 1}}


def test_hcnetsdk_stdxml_config_command_port_body_tail_matches_native_trace() -> None:
    request = hcnetsdk_stdxml_config_request(HCNETSDK_EZVIZ_SERVICES_SWITCH_GET)
    request_bytes = HCNETSDK_EZVIZ_SERVICES_SWITCH_GET.encode()

    tail = hcnetsdk_stdxml_config_command_port_body_tail(request)

    assert tail == b"".join(
        (
            b"\x00" * HCNETSDK_STDXML_COMMAND_PORT_EXTRA_RESERVED_SIZE,
            (
                HCNETSDK_STDXML_COMMAND_PORT_PREFIX_SIZE + len(request_bytes)
            ).to_bytes(4, "big"),
            len(request_bytes).to_bytes(4, "big"),
            HCNETSDK_STDXML_COMMAND_PORT_FLAGS,
            request_bytes,
        )
    )


def test_hcnetsdk_stdxml_config_command_port_template_uses_native_trace() -> None:
    request = hcnetsdk_stdxml_config_request(STDXML_TEST_REQUEST)
    template = hcnetsdk_stdxml_config_command_port_template(
        request,
        name="stdxml",
    )
    traced_template = hcnetsdk_stdxml_config_command_port_template(
        request,
        command_id=0x22222,
        body_prefix=b"PREFIX:",
        name="explicit-trace",
    )

    assert template.command_id == HCNETSDK_STDXML_COMMAND_PORT_COMMAND_ID
    assert template.name == "stdxml"
    assert template.body_tail == hcnetsdk_stdxml_config_command_port_body_tail(
        request
    )
    assert traced_template.command_id == 0x22222
    assert traced_template.name == "explicit-trace"
    assert traced_template.body_tail == b"PREFIX:" + STDXML_TEST_REQUEST
    with pytest.raises(PyEzvizError, match="command id"):
        hcnetsdk_stdxml_config_command_port_template(request, command_id=-1)


def test_hcnetsdk_stdxml_config_command_port_from_trace_builds_template() -> None:
    rsa_key = RSA.generate(1024)
    challenge = b"0123456789abcdef0123456789abcdef"
    seed = b"s" * 64
    login_sock = _FakeSocket(
        [
            build_hcnetsdk_tcp_frame(
                PKCS1_v1_5.new(rsa_key.publickey()).encrypt(challenge) + seed
            ),
            build_hcnetsdk_tcp_frame(
                HCNETSDK_COMMAND_PORT_TEST_SESSION_ID + b"CAM123\x00",
                field_4=0x10A24BF1,
            ),
        ]
    )
    control_sock = _FakeSocket([build_hcnetsdk_tcp_frame(STDXML_TEST_STATUS)])
    sockets = [login_sock, control_sock]

    def socket_factory(address: tuple[str, int], timeout: float | None) -> _FakeSocket:
        assert address == ("192.0.2.10", 8000)
        assert timeout == COMMAND_PORT_DEFAULT_TIMEOUT
        return sockets.pop(0)

    response = hcnetsdk_stdxml_config_command_port_from_trace(
        HcNetSdkLanEndpoint(serial="CAM123", host="192.0.2.10"),
        b"123456",
        STDXML_TEST_REQUEST,
        local_ip="192.0.2.56",
        socket_factory=socket_factory,
        rsa_key=rsa_key,
    )
    sent_control = parse_hcnetsdk_tcp_frame(control_sock.sent[0])

    assert response.succeeded is True
    assert response.json() == {"statusCode": 1}
    assert sent_control.header.field_12 == HCNETSDK_STDXML_COMMAND_PORT_COMMAND_ID
    assert sent_control.body[16:] == hcnetsdk_stdxml_config_command_port_body_tail(
        STDXML_TEST_REQUEST
    )


def test_hcnetsdk_stdxml_isapi_command_port_builds_generic_requests() -> None:
    rsa_key = RSA.generate(1024)
    challenge = b"0123456789abcdef0123456789abcdef"
    seed = b"s" * 64
    get_output = b'{"enabled":true}'
    put_status = b'{"statusCode":1}'

    def login_socket() -> _FakeSocket:
        return _FakeSocket(
            [
                build_hcnetsdk_tcp_frame(
                    PKCS1_v1_5.new(rsa_key.publickey()).encrypt(challenge) + seed
                ),
                build_hcnetsdk_tcp_frame(
                    HCNETSDK_COMMAND_PORT_TEST_SESSION_ID + b"CAM123\x00",
                    field_4=0x10A24BF1,
                ),
            ]
        )

    control_get = _FakeSocket([build_hcnetsdk_tcp_frame(get_output)])
    control_put = _FakeSocket([build_hcnetsdk_tcp_frame(put_status)])
    sockets = [login_socket(), control_get, login_socket(), control_put]

    def socket_factory(address: tuple[str, int], timeout: float | None) -> _FakeSocket:
        assert address == ("192.0.2.10", 8000)
        assert timeout == COMMAND_PORT_DEFAULT_TIMEOUT
        return sockets.pop(0)

    endpoint = HcNetSdkLanEndpoint(serial="CAM123", host="192.0.2.10")
    get_response = hcnetsdk_stdxml_isapi_command_port(
        endpoint,
        b"123456",
        "GET",
        "/ISAPI/System/example?format=json",
        local_ip="192.0.2.56",
        socket_factory=socket_factory,
        rsa_key=rsa_key,
    )
    put_response = hcnetsdk_stdxml_isapi_command_port(
        endpoint,
        b"123456",
        "PUT",
        "/ISAPI/System/example?format=json",
        {"enabled": False},
        local_ip="192.0.2.56",
        socket_factory=socket_factory,
        rsa_key=rsa_key,
    )

    expected_get = hcnetsdk_stdxml_config_command_port_body_tail(
        "GET /ISAPI/System/example?format=json\r\n"
    )
    expected_put = hcnetsdk_stdxml_config_command_port_body_tail(
        'PUT /ISAPI/System/example?format=json\r\n{"enabled":false}\r\n'
    )

    assert get_response.output == get_output
    assert put_response.json() == {"statusCode": 1}
    assert parse_hcnetsdk_tcp_frame(control_get.sent[0]).body[16:] == expected_get
    assert parse_hcnetsdk_tcp_frame(control_put.sent[0]).body[16:] == expected_put


def test_ezviz_lan_services_switch_command_port_helpers_preserve_values() -> None:
    rsa_key = RSA.generate(1024)
    challenge = b"0123456789abcdef0123456789abcdef"
    seed = b"s" * 64
    current = b'{"servicesSwitch":{"rtsp":1,"upnp":1,"web":0,"hiksdk":1}}'
    status = b'{"statusCode":1}'

    def login_socket() -> _FakeSocket:
        return _FakeSocket(
            [
                build_hcnetsdk_tcp_frame(
                    PKCS1_v1_5.new(rsa_key.publickey()).encrypt(challenge) + seed
                ),
                build_hcnetsdk_tcp_frame(
                    HCNETSDK_COMMAND_PORT_TEST_SESSION_ID + b"CAM123\x00",
                    field_4=0x10A24BF1,
                ),
            ]
        )

    control_get = _FakeSocket([build_hcnetsdk_tcp_frame(current)])
    control_state = _FakeSocket([build_hcnetsdk_tcp_frame(current)])
    control_set_get = _FakeSocket([build_hcnetsdk_tcp_frame(current)])
    control_set_put = _FakeSocket([build_hcnetsdk_tcp_frame(status)])
    sockets = [
        login_socket(),
        control_get,
        login_socket(),
        control_state,
        login_socket(),
        control_set_get,
        login_socket(),
        control_set_put,
    ]

    def socket_factory(address: tuple[str, int], timeout: float | None) -> _FakeSocket:
        assert address == ("192.0.2.10", 8000)
        assert timeout == COMMAND_PORT_DEFAULT_TIMEOUT
        return sockets.pop(0)

    endpoint = HcNetSdkLanEndpoint(serial="CAM123", host="192.0.2.10")
    raw_response = ezviz_lan_services_switch_get_command_port(
        endpoint,
        b"123456",
        local_ip="192.0.2.56",
        socket_factory=socket_factory,
        rsa_key=rsa_key,
    )
    state = ezviz_lan_services_switch_state_command_port(
        endpoint,
        b"123456",
        local_ip="192.0.2.56",
        socket_factory=socket_factory,
        rsa_key=rsa_key,
    )
    set_response = ezviz_lan_services_switch_set_command_port(
        endpoint,
        b"123456",
        local_ip="192.0.2.56",
        socket_factory=socket_factory,
        rsa_key=rsa_key,
        web=True,
    )

    expected_get = hcnetsdk_stdxml_config_command_port_body_tail(
        HCNETSDK_EZVIZ_SERVICES_SWITCH_GET
    )
    expected_put = hcnetsdk_stdxml_config_command_port_body_tail(
        HCNETSDK_EZVIZ_SERVICES_SWITCH_PUT
        + '{"servicesSwitch":{"rtsp":1,"upnp":1,"web":1,"hiksdk":1}}'
        + "\r\n"
    )
    sent_get = parse_hcnetsdk_tcp_frame(control_get.sent[0])
    sent_state = parse_hcnetsdk_tcp_frame(control_state.sent[0])
    sent_set_get = parse_hcnetsdk_tcp_frame(control_set_get.sent[0])
    sent_set_put = parse_hcnetsdk_tcp_frame(control_set_put.sent[0])

    assert raw_response.output == current
    assert state.web == 0
    assert state.rtsp == 1
    assert set_response.succeeded is True
    assert set_response.json() == {"statusCode": 1}
    assert sent_get.header.field_12 == HCNETSDK_STDXML_COMMAND_PORT_COMMAND_ID
    assert sent_state.header.field_12 == HCNETSDK_STDXML_COMMAND_PORT_COMMAND_ID
    assert sent_set_get.header.field_12 == HCNETSDK_STDXML_COMMAND_PORT_COMMAND_ID
    assert sent_set_put.header.field_12 == HCNETSDK_STDXML_COMMAND_PORT_COMMAND_ID
    assert sent_get.body[16:] == expected_get
    assert sent_state.body[16:] == expected_get
    assert sent_set_get.body[16:] == expected_get
    assert sent_set_put.body[16:] == expected_put


def test_hcnetsdk_pure_python_client_services_switch_methods() -> None:
    rsa_key = RSA.generate(1024)
    challenge = b"0123456789abcdef0123456789abcdef"
    seed = b"s" * 64
    current = b'{"servicesSwitch":{"rtsp":1,"upnp":1,"web":0,"hiksdk":1}}'
    status = b'{"statusCode":1}'

    def login_socket() -> _FakeSocket:
        return _FakeSocket(
            [
                build_hcnetsdk_tcp_frame(
                    PKCS1_v1_5.new(rsa_key.publickey()).encrypt(challenge) + seed
                ),
                build_hcnetsdk_tcp_frame(
                    HCNETSDK_COMMAND_PORT_TEST_SESSION_ID + b"CAM123\x00",
                    field_4=0x10A24BF1,
                ),
            ]
        )

    control_state = _FakeSocket([build_hcnetsdk_tcp_frame(current)])
    control_set = _FakeSocket([build_hcnetsdk_tcp_frame(status)])
    control_isapi = _FakeSocket([build_hcnetsdk_tcp_frame(b'{"statusCode":1}')])
    sockets = [
        login_socket(),
        control_state,
        login_socket(),
        control_set,
        login_socket(),
        control_isapi,
    ]

    def socket_factory(address: tuple[str, int], timeout: float | None) -> _FakeSocket:
        assert address == ("192.0.2.10", 8000)
        assert timeout == COMMAND_PORT_DEFAULT_TIMEOUT
        return sockets.pop(0)

    client = HcNetSdkPurePythonClient(
        HcNetSdkLanEndpoint(serial="CAM123", host="192.0.2.10"),
        b"123456",
        local_ip="192.0.2.56",
        socket_factory=socket_factory,
        rsa_key=rsa_key,
    )
    state = client.services_switch_state()
    response = client.services_switch_set(
        {"servicesSwitch": {"rtsp": 1, "upnp": 1, "web": 0, "hiksdk": 1}},
        web=True,
    )
    isapi_response = client.stdxml_isapi_request(
        "PUT",
        "/ISAPI/System/example?format=json",
        {"enabled": True},
    )

    expected_get = hcnetsdk_stdxml_config_command_port_body_tail(
        HCNETSDK_EZVIZ_SERVICES_SWITCH_GET
    )
    expected_put = hcnetsdk_stdxml_config_command_port_body_tail(
        HCNETSDK_EZVIZ_SERVICES_SWITCH_PUT
        + '{"servicesSwitch":{"rtsp":1,"upnp":1,"web":1,"hiksdk":1}}'
        + "\r\n"
    )

    assert state.web == 0
    assert response.json() == {"statusCode": 1}
    assert isapi_response.json() == {"statusCode": 1}
    assert parse_hcnetsdk_tcp_frame(control_state.sent[0]).body[16:] == expected_get
    assert parse_hcnetsdk_tcp_frame(control_set.sent[0]).body[16:] == expected_put
    assert parse_hcnetsdk_tcp_frame(control_isapi.sent[0]).body[16:] == (
        hcnetsdk_stdxml_config_command_port_body_tail(
            'PUT /ISAPI/System/example?format=json\r\n{"enabled":true}\r\n'
        )
    )


def test_hcnetsdk_command_port_client_bootstraps_first_media() -> None:
    expected_timeout = 3.0
    request_1 = build_hcnetsdk_tcp_frame(b"login-1", field_4=90)
    request_2 = build_hcnetsdk_tcp_frame(b"play", field_4=99)
    response_1 = build_hcnetsdk_tcp_frame(b"ok-1", field_4=1)
    response_2 = build_hcnetsdk_tcp_frame(b"ok-2", field_4=1)
    prefix = b"preface"
    media_payload = b"\x80\x60\x00\x01" + (b"\x00" * 8) + b"\x00\x00\x01\xbaabc"
    media_frame = (
        prefix
        + b"\x24\x00"
        + (len(media_payload) + 4).to_bytes(2, "little")
        + media_payload
    )
    sock = _FakeSocket([response_1, response_2, media_frame])

    def socket_factory(address: tuple[str, int], timeout: float | None) -> _FakeSocket:
        assert address == ("192.0.2.10", 8000)
        assert timeout == expected_timeout
        return sock

    client = HcNetSdkCommandPortClient(
        HcNetSdkLanEndpoint(serial="CAM123", host="192.0.2.10"),
        timeout=expected_timeout,
        socket_factory=socket_factory,
    )

    bootstrap = client.bootstrap_media_stream(
        [request_1, request_2],
        max_prefix_bytes=16,
    )

    assert sock.sent == [request_1, request_2]
    assert [exchange.response.body for exchange in bootstrap.exchanges if exchange.response] == [
        b"ok-1",
        b"ok-2",
    ]
    assert bootstrap.first_media is not None
    assert bootstrap.first_media.prefix == prefix
    assert bootstrap.first_media.frame.payload == media_payload


def test_ezviz_local_sdk_client_bootstraps_preview_and_first_media() -> None:
    pre_start_response = build_ezviz_local_sdk_frame(
        command=0x2014,
        body="<Response><Result>0</Result></Response>",
    ) + LOCAL_SDK_RESPONSE_TRAILER
    command_response = build_ezviz_local_sdk_frame(
        command=0x2012,
        body="<Response><Result>0</Result><Session>1</Session></Response>",
    ) + LOCAL_SDK_RESPONSE_TRAILER
    stream_response = build_ezviz_local_sdk_frame(
        command=0x3106,
        body="<Response><Result>0</Result></Response>",
    ) + LOCAL_SDK_RESPONSE_TRAILER
    media_prefix = bytes.fromhex("01 00 01 01")
    media_payload = b"rtp-payload"
    command_sock = _FakeSocket([pre_start_response, command_response])
    stream_sock = _FakeSocket(
        [
            stream_response,
            media_prefix,
            bytes.fromhex("24 00"),
            len(media_payload).to_bytes(2, "big"),
            media_payload,
        ]
    )
    connect_calls: list[tuple[tuple[str, int], float | None]] = []

    def socket_factory(address: tuple[str, int], timeout: float | None) -> _FakeSocket:
        connect_calls.append((address, timeout))
        if address[1] == 9010:
            return command_sock
        return stream_sock

    endpoint = HcNetSdkLanEndpoint(
        serial="CAM123456",
        host="192.0.2.10",
        command_port=9010,
        stream_port=9020,
    )
    device_info = EzvizCasDeviceInfo(
        serial="CAM123456",
        operation_code="0123456",
        key="1234567890abcdef",
    )

    with EzvizLocalSdkClient(
        endpoint,
        device_info,
        timeout=3.0,
        socket_factory=socket_factory,
        iv_factory=lambda _size: LOCAL_SDK_SSL_IV,
    ) as client:
        result = client.bootstrap_preview(
            preview_body="<Request><OperationCode>0123456</OperationCode></Request>",
            stream_setup_body=STREAM_SETUP_BODY,
            pre_start_body="<Request/>",
            pre_start_sequence=27,
            preview_sequence=28,
            stream_setup_sequence=29,
            read_first_media=True,
        )

    assert connect_calls == [
        (("192.0.2.10", 9010), 3.0),
        (("192.0.2.10", 9020), 3.0),
    ]
    assert result.pre_start is not None
    assert result.pre_start.response.header.command == 0x2014
    assert result.preview.response.header.command == 0x2012
    assert result.stream_setup.response.header.command == 0x3106
    assert result.first_media is not None
    assert result.first_media.prefix == media_prefix
    assert result.first_media.frame.payload == media_payload

    pre_start_request = parse_ezviz_local_sdk_frame(command_sock.sent[0])
    preview_request = parse_ezviz_local_sdk_frame(command_sock.sent[1])
    stream_request = parse_ezviz_local_sdk_frame(stream_sock.sent[0])
    assert pre_start_request.header.command == EZVIZ_LOCAL_SDK_PRE_START_COMMAND
    assert pre_start_request.header.sequence == 27
    assert preview_request.header.command == EZVIZ_LOCAL_SDK_PREVIEW_COMMAND
    assert preview_request.header.sequence == 28
    assert stream_request.header.command == EZVIZ_LOCAL_SDK_STREAM_SETUP_COMMAND
    assert stream_request.header.sequence == 29
    assert stream_request.trailer == hashlib.md5(
        stream_request.body, usedforsecurity=False
    ).hexdigest().encode("ascii")
    assert decrypt_ezviz_local_sdk_body_aes_cbc(
        stream_request.body,
        key=device_info.key_bytes,
        iv=LOCAL_SDK_SSL_IV,
    ) == STREAM_SETUP_BODY
    assert command_sock.closed is True
    assert stream_sock.closed is True


def test_ezviz_local_sdk_client_builds_stream_setup_from_preview_session() -> None:
    command_response = build_ezviz_local_sdk_frame(
        command=0x2012,
        body="<Response><Result>0</Result><Session>765</Session></Response>",
    ) + LOCAL_SDK_RESPONSE_TRAILER
    stream_response = build_ezviz_local_sdk_frame(
        command=0x3106,
        body="<Response><Result>0</Result></Response>",
    ) + LOCAL_SDK_RESPONSE_TRAILER
    command_sock = _FakeSocket([command_response])
    stream_sock = _FakeSocket([stream_response])

    def socket_factory(address: tuple[str, int], timeout: float | None) -> _FakeSocket:
        return command_sock if address[1] == 9010 else stream_sock

    endpoint = HcNetSdkLanEndpoint(
        serial="CAM123456",
        host="192.0.2.10",
        command_port=9010,
        stream_port=9020,
    )
    device_info = EzvizCasDeviceInfo(
        serial="CAM123456",
        operation_code="0123456",
        key="1234567890abcdef",
    )

    with EzvizLocalSdkClient(
        endpoint,
        device_info,
        socket_factory=socket_factory,
        iv_factory=lambda _size: LOCAL_SDK_SSL_IV,
    ) as client:
        result = client.bootstrap_preview_from_fields(
            preview_request=EzvizLocalPreviewRequest(
                operation_code="0123456",
                channel=1,
                receiver_info="receiver",
                receiver_info_ex="receiver-ex",
            ),
            preview_sequence=31,
            stream_setup_sequence=32,
            stream_rate=2,
            stream_mode=1,
        )

    assert result.pre_start is None
    assert result.preview.response.header.command == 0x2012
    assert result.stream_setup.response.header.command == 0x3106
    stream_request = parse_ezviz_local_sdk_frame(stream_sock.sent[0])
    assert stream_request.header.sequence == 32
    assert decrypt_ezviz_local_sdk_body_aes_cbc(
        stream_request.body,
        key=device_info.key_bytes,
        iv=LOCAL_SDK_SSL_IV,
    ) == build_ezviz_local_stream_setup_request_body(
        session="765",
        rate=2,
        mode=1,
    )


def test_ezviz_local_sdk_client_can_bind_command_source_port() -> None:
    command_response = build_ezviz_local_sdk_frame(
        command=0x2012,
        body="<Response><Result>257</Result></Response>",
    ) + LOCAL_SDK_RESPONSE_TRAILER
    command_sock = _FakeSocket([command_response])
    connect_calls: list[tuple[tuple[str, int], float | None, tuple[str, int] | None]] = []

    def socket_factory(
        address: tuple[str, int],
        timeout: float | None,
        source_address: tuple[str, int] | None = None,
    ) -> _FakeSocket:
        connect_calls.append((address, timeout, source_address))
        return command_sock

    endpoint = HcNetSdkLanEndpoint(
        serial="CAM123456",
        host="192.0.2.10",
        command_port=9010,
        stream_port=9020,
    )
    device_info = EzvizCasDeviceInfo(
        serial="CAM123456",
        operation_code="0123456",
        key="1234567890abcdef",
    )

    with EzvizLocalSdkClient(
        endpoint,
        device_info,
        socket_factory=socket_factory,
        iv_factory=lambda _size: LOCAL_SDK_SSL_IV,
        command_source_port=10103,
    ) as client, pytest.raises(PyEzvizError, match="Result=257"):
        client.bootstrap_preview_from_fields(
            preview_request=EzvizLocalPreviewRequest(
                operation_code="0123456",
                channel=1,
                receiver_info="receiver",
                receiver_info_ex="receiver-ex",
            )
        )

    assert connect_calls == [(("192.0.2.10", 9010), 5.0, ("", 10103))]


def test_ezviz_local_sdk_client_missing_session_reports_result() -> None:
    command_response = build_ezviz_local_sdk_frame(
        command=0x2012,
        body="<Response><Result>257</Result></Response>",
    ) + LOCAL_SDK_RESPONSE_TRAILER
    command_sock = _FakeSocket([command_response])

    endpoint = HcNetSdkLanEndpoint(
        serial="CAM123456",
        host="192.0.2.10",
        command_port=9010,
        stream_port=9020,
    )
    device_info = EzvizCasDeviceInfo(
        serial="CAM123456",
        operation_code="0123456",
        key="1234567890abcdef",
    )

    with EzvizLocalSdkClient(
        endpoint,
        device_info,
        socket_factory=lambda _address, _timeout: command_sock,
        iv_factory=lambda _size: LOCAL_SDK_SSL_IV,
    ) as client, pytest.raises(
        PyEzvizError, match=r"missing Session \(Result=257\)"
    ):
        client.bootstrap_preview_from_fields(
            preview_request=EzvizLocalPreviewRequest(
                operation_code="0123456",
                channel=1,
                receiver_info="receiver",
                receiver_info_ex="receiver-ex",
            ),
        )


def test_apk_observed_command_ids_are_named() -> None:
    assert HcNetSdkDvrCommand.GET_WIFI_CFG == 307
    assert HcNetSdkDvrCommand.SET_WIFI_CFG == 306
    assert HcNetSdkDvrCommand.GET_HD_CFG == 1054
    assert HcNetSdkDvrCommand.GET_CAMERA_PARAM_CFG == 1067
    assert HcNetSdkDvrCommand.GET_COMPRESSION_CFG_V30 == 1040


def test_ezviz_lan_login_candidates_match_apk_order() -> None:
    candidates = ezviz_lan_login_candidates(" ABCDEF ", command_port=9010)

    assert candidates[0].api == "NET_DVR_Login_V40"
    assert candidates[0].username == HCNETSDK_EZVIZ_DEFAULT_USERNAME
    assert candidates[0].password == "ABCDEF"
    assert candidates[0].port == HCNETSDK_DEFAULT_TLS_PORT
    assert candidates[0].https is True

    assert candidates[1].api == "NET_DVR_Login_V30"
    assert candidates[1].username == HCNETSDK_EZVIZ_DEFAULT_USERNAME
    assert candidates[1].password == "ABCDEF"
    assert candidates[1].port == 9010

    assert candidates[2].api == "NET_DVR_Login_V30"
    assert candidates[2].username == HCNETSDK_EZVIZ_LOCAL_USERNAME
    assert candidates[2].password == "22a5028b9808c7bf"
    assert candidates[2].port == 9010


def test_ezviz_lan_settings_login_candidates_can_match_scanned_tls_only_path() -> None:
    candidates = ezviz_lan_settings_login_candidates(
        "ABCDEF",
        command_port=9010,
        login_with_8443=True,
    )

    assert [(candidate.api, candidate.port) for candidate in candidates] == [
        ("NET_DVR_Login_V40", HCNETSDK_DEFAULT_TLS_PORT),
    ]


def test_ezviz_lan_settings_login_candidates_can_skip_tls_for_compatibility() -> None:
    candidates = ezviz_lan_settings_login_candidates(
        "ABCDEF",
        command_port=9010,
        login_with_8443=False,
    )

    assert [(candidate.username, candidate.api, candidate.port) for candidate in candidates] == [
        (HCNETSDK_EZVIZ_DEFAULT_USERNAME, "NET_DVR_Login_V40", 9010),
        (HCNETSDK_EZVIZ_LOCAL_USERNAME, "NET_DVR_Login_V40", 9010),
    ]
    assert [candidate.https for candidate in candidates] == [False, False]


def test_ezviz_lan_settings_login_candidates_try_v40_command_fallback() -> None:
    candidates = ezviz_lan_settings_login_candidates(
        "ABCDEF",
        command_port=9010,
        login_with_8443=None,
    )

    assert [(candidate.api, candidate.port, candidate.https) for candidate in candidates] == [
        ("NET_DVR_Login_V40", HCNETSDK_DEFAULT_TLS_PORT, True),
        ("NET_DVR_Login_V40", 9010, False),
        ("NET_DVR_Login_V40", 9010, False),
    ]


@pytest.mark.parametrize(
    ("login_with_8443", "login_port", "open_8000", "updates"),
    (
        (True, HCNETSDK_DEFAULT_TLS_PORT, True, True),
        (None, HCNETSDK_DEFAULT_TLS_PORT, False, True),
        (False, HCNETSDK_DEFAULT_TLS_PORT, True, False),
        (None, 9010, True, False),
        (True, HCNETSDK_DEFAULT_TLS_PORT, None, False),
    ),
)
def test_ezviz_lan_settings_updates_services_switch_matches_presenter(
    login_with_8443: bool | None,
    login_port: int,
    open_8000: bool | None,
    updates: bool,
) -> None:
    assert (
        ezviz_lan_settings_updates_services_switch(
            login_with_8443=login_with_8443,
            login_port=login_port,
            open_8000=open_8000,
        )
        is updates
    )


def test_ezviz_lan_local_user_password_matches_add_md5_util() -> None:
    assert ezviz_lan_local_user_password("ABCDEF") == "22a5028b9808c7bf"


def test_ezviz_lan_password_store_names_match_dev_pwd_util() -> None:
    assert (
        ezviz_lan_password_store_name(" user123 ")
        == f"user123{HCNETSDK_EZVIZ_LAN_PASSWORD_PREF_SUFFIX}"
    )
    assert (
        ezviz_lan_password_store_key(" CAM123456 ")
        == f"{HCNETSDK_EZVIZ_LAN_PASSWORD_KEY_PREFIX}CAM123456"
    )


@pytest.mark.parametrize(
    ("func", "value"),
    (
        (ezviz_lan_password_store_name, " "),
        (ezviz_lan_password_store_key, ""),
    ),
)
def test_ezviz_lan_password_store_rejects_empty_values(
    func: Callable[[str], str], value: str
) -> None:
    with pytest.raises(PyEzvizError):
        func(value)


def test_hcnetsdk_stdxml_config_request_matches_jna_shape() -> None:
    request = hcnetsdk_stdxml_config_request(HCNETSDK_EZVIZ_SERVICES_SWITCH_GET)
    hint = request.to_native_args_hint()

    assert request.request_bytes == HCNETSDK_EZVIZ_SERVICES_SWITCH_GET.encode()
    assert request.in_buffer_bytes == STDXML_EMPTY_BUFFER
    assert request.android_helper_compatible is True
    assert hint["api"] == "NET_DVR_STDXMLConfig"
    assert hint["input"]["field_order"] == HCNETSDK_STDXML_INPUT_FIELD_ORDER
    assert hint["input"]["dwRequestUrlLen"] == len(request.request_bytes)
    assert hint["input"]["lpRequestUrl"] == "<request-url-buffer>"
    assert hint["input"]["lpInBuffer"] is None
    assert hint["input"]["dwInBufferSize"] == 0
    assert hint["input"]["dwRecvTimeOut"] == 0
    assert hint["input"]["byForceEncrpt"] == 0
    assert hint["input"]["byNumOfMultiPart"] == 0
    assert hint["input"]["byResLength"] == 30
    assert hint["output"]["field_order"] == HCNETSDK_STDXML_OUTPUT_FIELD_ORDER
    assert hint["output"]["dwOutBufferSize"] == HCNETSDK_STDXML_DEFAULT_OUTPUT_BUFFER_SIZE
    assert hint["output"]["dwStatusSize"] == HCNETSDK_STDXML_DEFAULT_STATUS_BUFFER_SIZE
    assert hint["output"]["byResLength"] == 32
    assert HCNETSDK_STDXML_ANDROID_REQUEST_BUFFER_SIZE == 1024


def test_hcnetsdk_stdxml_config_request_can_include_bridge_buffers() -> None:
    request = hcnetsdk_stdxml_config_request(
        STDXML_TEST_REQUEST,
        in_buffer=STDXML_TEST_INPUT_BUFFER,
        recv_timeout=30,
        force_encrypt=1,
        num_of_multi_part=2,
    )

    hint = request.to_native_args_hint(include_buffers=True)

    assert request.android_helper_compatible is False
    assert hint["input"]["lpRequestUrl"] == STDXML_TEST_REQUEST
    assert hint["input"]["lpInBuffer"] == STDXML_TEST_INPUT_BUFFER
    assert hint["input"]["dwInBufferSize"] == 4
    assert hint["input"]["dwRecvTimeOut"] == 30
    assert hint["input"]["byForceEncrpt"] == 1
    assert hint["input"]["byNumOfMultiPart"] == 2


def test_hcnetsdk_stdxml_isapi_request_rejects_invalid_method_or_path() -> None:
    with pytest.raises(PyEzvizError, match="method"):
        hcnetsdk_stdxml_isapi_request("PUT x", "/ISAPI/Test")
    with pytest.raises(PyEzvizError, match="path"):
        hcnetsdk_stdxml_isapi_request("PUT", "ISAPI/Test")


def test_hcnetsdk_stdxml_response_json_accepts_mapping_text_and_bytes() -> None:
    assert hcnetsdk_stdxml_response_json({"statusCode": 1}) == {"statusCode": 1}
    assert hcnetsdk_stdxml_response_json('{"statusCode":1}') == {"statusCode": 1}
    assert hcnetsdk_stdxml_response_json(b'{"statusCode":1}') == {"statusCode": 1}


def test_hcnetsdk_stdxml_response_json_rejects_invalid_payload() -> None:
    with pytest.raises(PyEzvizError, match="JSON"):
        hcnetsdk_stdxml_response_json("not-json")
    with pytest.raises(PyEzvizError, match="object"):
        hcnetsdk_stdxml_response_json("[1]")


def test_hcnetsdk_native_lifecycle_login_and_logout_use_v40_shape() -> None:
    sdk = _FakeNativeHcNetSdk()

    assert hcnetsdk_init_native(sdk) is True
    session = hcnetsdk_login_v40_native(
        sdk,
        "192.0.2.10",
        "secret",
        username=HCNETSDK_EZVIZ_DEFAULT_USERNAME,
        port=HCNETSDK_DEFAULT_TLS_PORT,
        https=True,
    )

    assert sdk.initialized is True
    assert session == HcNetSdkNativeLoginSession(
        login_id=42,
        serial="SN123456789",
        last_error=None,
    )
    assert session.succeeded is True
    assert sdk.logins == [
        {
            "host": "192.0.2.10",
            "username": HCNETSDK_EZVIZ_DEFAULT_USERNAME,
            "password": "secret",
            "port": HCNETSDK_DEFAULT_TLS_PORT,
            "https": 1,
        }
    ]
    assert hcnetsdk_logout_native(sdk, 42) is True
    assert sdk.logged_out == [42]
    assert hcnetsdk_cleanup_native(sdk) is True
    assert sdk.cleaned_up is True


def test_hcnetsdk_native_login_failure_keeps_last_error() -> None:
    sdk = _FakeNativeHcNetSdk(login_id=-1, last_error=29)

    session = hcnetsdk_login_v40_native(sdk, "192.0.2.10", "secret")

    assert session == HcNetSdkNativeLoginSession(
        login_id=-1,
        serial=None,
        last_error=29,
    )
    assert session.succeeded is False


def test_hcnetsdk_stdxml_config_native_passes_buffers_and_returns_json() -> None:
    sdk = _FakeNativeHcNetSdk([STDXML_TEST_OUTPUT])
    request = hcnetsdk_stdxml_config_request(
        STDXML_TEST_REQUEST,
        in_buffer=STDXML_TEST_INPUT_BUFFER,
        output_buffer_size=256,
        status_buffer_size=128,
    )

    response = hcnetsdk_stdxml_config_native(sdk, 42, request)

    assert isinstance(response, HcNetSdkStdXmlConfigResponse)
    assert response.succeeded is True
    assert response.output == STDXML_TEST_OUTPUT
    assert response.text == '{"servicesSwitch":{"web":1}}'
    assert response.status == STDXML_TEST_STATUS
    assert response.status_text == '{"statusCode":1}'
    assert response.returned_xml_size == len(response.output)
    assert response.last_error is None
    assert response.json() == {"servicesSwitch": {"web": 1}}
    assert sdk.requests == [STDXML_TEST_REQUEST]
    assert sdk.input_buffers == [STDXML_TEST_INPUT_BUFFER]


def test_hcnetsdk_stdxml_config_native_failure_keeps_last_error() -> None:
    sdk = _FakeNativeHcNetSdk(stdxml_succeeds=False, last_error=23)

    response = hcnetsdk_stdxml_config_native(sdk, 42, STDXML_TEST_REQUEST)

    assert response == HcNetSdkStdXmlConfigResponse(
        succeeded=False,
        output=b"",
        status=b"",
        returned_xml_size=0,
        last_error=23,
    )


def test_ezviz_lan_services_switch_payload_matches_settings_checkbox() -> None:
    payload = ezviz_lan_services_switch_payload(
        {"servicesSwitch": {"hiksdk": 0, "web": 0, "rtsp": 1}, "other": 2},
        enabled=True,
    )

    assert ezviz_lan_services_switch_get_request() == HCNETSDK_EZVIZ_SERVICES_SWITCH_GET
    assert ezviz_lan_services_switch_get_config().request == (
        HCNETSDK_EZVIZ_SERVICES_SWITCH_GET
    )
    assert HCNETSDK_EZVIZ_SERVICES_SWITCH_GET == (
        "GET /ISAPI/EZVIZ/IPC/System/servicesSwitch?format=json\r\n"
    )
    assert payload == {
        "servicesSwitch": {"hiksdk": 1, "web": 1, "rtsp": 1},
        "other": 2,
    }


def test_ezviz_lan_services_switch_payload_can_disable_missing_block() -> None:
    assert ezviz_lan_services_switch_payload(None, enabled=False) == {
        "servicesSwitch": {"hiksdk": 0, "web": 0},
    }


def test_ezviz_lan_services_switch_put_request_matches_hcnetutil() -> None:
    payload = {"servicesSwitch": {"hiksdk": 1, "web": 1}, "other": 2}

    assert HCNETSDK_EZVIZ_SERVICES_SWITCH_PUT == (
        "PUT /ISAPI/EZVIZ/IPC/System/servicesSwitch?format=json\r\n"
    )
    assert ezviz_lan_services_switch_put_request(payload) == (
        HCNETSDK_EZVIZ_SERVICES_SWITCH_PUT
        + '{"servicesSwitch":{"hiksdk":1,"web":1},"other":2}'
        + "\r\n"
    )
    assert ezviz_lan_services_switch_put_config(payload).request == (
        ezviz_lan_services_switch_put_request(payload)
    )
    assert ezviz_lan_services_switch_update_config(
        {"servicesSwitch": {"hiksdk": 0, "web": 0}},
        enabled=True,
    ).request == ezviz_lan_services_switch_put_request(
        {"servicesSwitch": {"hiksdk": 1, "web": 1}}
    )


def test_ezviz_lan_services_switch_set_payload_updates_named_switches() -> None:
    payload = ezviz_lan_services_switch_set_payload(
        {"servicesSwitch": {"rtsp": 1, "upnp": 1, "web": 0, "hiksdk": 1}},
        web=True,
    )

    assert payload == {"servicesSwitch": {"rtsp": 1, "upnp": 1, "web": 1, "hiksdk": 1}}
    assert ezviz_lan_services_switch_set_config(
        {"servicesSwitch": {"rtsp": 1, "upnp": 1, "web": 0, "hiksdk": 1}},
        web=True,
    ).request == ezviz_lan_services_switch_put_request(payload)


def test_ezviz_lan_services_switch_set_payload_can_set_all_switches() -> None:
    assert ezviz_lan_services_switch_set_payload(
        None,
        hiksdk=True,
        web=True,
        rtsp=False,
        upnp=1,
    ) == {"servicesSwitch": {"hiksdk": 1, "web": 1, "rtsp": 0, "upnp": 1}}


def test_ezviz_lan_services_switch_set_payload_rejects_invalid_values() -> None:
    with pytest.raises(PyEzvizError, match="web"):
        ezviz_lan_services_switch_set_payload(None, web=2)
    with pytest.raises(PyEzvizError, match="rtsp"):
        ezviz_lan_services_switch_set_payload(None, rtsp="1")  # type: ignore[arg-type]


def test_ezviz_lan_services_switch_state_parses_values() -> None:
    state = ezviz_lan_services_switch_state(
        '{"servicesSwitch":{"hiksdk":1,"web":0,"rtsp":1}}'
    )

    assert state.hiksdk == 1
    assert state.hiksdk_enabled is True
    assert state.web == 0
    assert state.web_enabled is False
    assert state.rtsp == 1
    assert state.raw == {"servicesSwitch": {"hiksdk": 1, "web": 0, "rtsp": 1}}


@pytest.mark.parametrize(
    ("response", "succeeded"),
    (
        ({"statusCode": 1}, True),
        ({"statusCode": 0}, False),
        ('{"statusCode":1}', True),
    ),
)
def test_ezviz_lan_services_switch_succeeded_matches_hcnetutil(
    response: dict[str, int] | str, succeeded: bool
) -> None:
    assert ezviz_lan_services_switch_succeeded(response) is succeeded


def test_ezviz_lan_services_switch_succeeded_rejects_invalid_json() -> None:
    with pytest.raises(PyEzvizError):
        ezviz_lan_services_switch_succeeded("not-json")


def test_ezviz_lan_services_switch_native_get_state_and_set_preserves_values() -> None:
    current = b'{"servicesSwitch":{"rtsp":1,"upnp":1,"web":0,"hiksdk":1}}'
    sdk = _FakeNativeHcNetSdk([current, current, current, b'{"statusCode":1}'])

    raw_response = ezviz_lan_services_switch_get_native(sdk, 42)
    state = ezviz_lan_services_switch_state_native(sdk, 42)
    set_response = ezviz_lan_services_switch_set_native(sdk, 42, web=True)

    assert raw_response.output == current
    assert state.web == 0
    assert state.rtsp == 1
    assert state.raw == {
        "servicesSwitch": {"rtsp": 1, "upnp": 1, "web": 0, "hiksdk": 1}
    }
    assert set_response.succeeded is True
    assert set_response.json() == {"statusCode": 1}
    assert sdk.requests == [
        HCNETSDK_EZVIZ_SERVICES_SWITCH_GET.encode(),
        HCNETSDK_EZVIZ_SERVICES_SWITCH_GET.encode(),
        HCNETSDK_EZVIZ_SERVICES_SWITCH_GET.encode(),
        (
            HCNETSDK_EZVIZ_SERVICES_SWITCH_PUT
            + '{"servicesSwitch":{"rtsp":1,"upnp":1,"web":1,"hiksdk":1}}'
            + "\r\n"
        ).encode(),
    ]


def test_hcnetsdk_native_stdxml_client_wraps_common_calls() -> None:
    current = {"servicesSwitch": {"rtsp": 1, "upnp": 1, "web": 0, "hiksdk": 1}}
    sdk = _FakeNativeHcNetSdk([b'{"statusCode":1}'])
    client = HcNetSdkNativeStdXmlClient(sdk)

    assert client.init() is True
    assert client.login_v40("192.0.2.10", "secret").login_id == 42
    response = client.services_switch_set(42, current, web=True)
    assert response.succeeded is True
    assert client.logout(42) is True
    assert client.cleanup() is True
    assert sdk.requests == [
        (
            HCNETSDK_EZVIZ_SERVICES_SWITCH_PUT
            + '{"servicesSwitch":{"rtsp":1,"upnp":1,"web":1,"hiksdk":1}}'
            + "\r\n"
        ).encode()
    ]


def test_ezviz_lan_connect_mode_put_request_matches_leave_local_connect() -> None:
    assert HCNETSDK_EZVIZ_CONNECT_MODE_PUT == (
        "PUT /ISAPI/EZVIZ/IPC/System/Network/connectMode?format=json\r\n"
    )
    assert ezviz_lan_connect_mode_payload() == {"ConnectMode": {"mode": 1}}
    assert ezviz_lan_connect_mode_put_request() == (
        HCNETSDK_EZVIZ_CONNECT_MODE_PUT + '{"ConnectMode":{"mode":1}}' + "\r\n"
    )
    assert ezviz_lan_connect_mode_put_config().request == (
        ezviz_lan_connect_mode_put_request()
    )


def test_ezviz_lan_net_config_upload_request_matches_hcnetutil() -> None:
    payload = ezviz_lan_net_config_and_voice_upload_payload(
        ip="192.0.2.20",
        port=4567,
        bssid="00:11:22:33:44:55",
        ssid="Test WiFi",
        passwd="encrypted-pass",
        security=4,
    )

    assert HCNETSDK_EZVIZ_NET_CONFIG_UPLOAD_PUT == (
        "PUT /ISAPI/EZVIZ/IPC/System/netConfigAndVoiceFileUpload?format=json\r\n"
    )
    assert payload == {
        "NetConfigAndVoiceFileUpload": {
            "ip": "192.0.2.20",
            "port": 4567,
            "bssid": "00:11:22:33:44:55",
            "ssid": "Test WiFi",
            "passwd": "encrypted-pass",
            "security": 4,
        }
    }
    request = ezviz_lan_net_config_and_voice_upload_put_request(
        ip="192.0.2.20",
        port=4567,
        bssid="00:11:22:33:44:55",
        ssid="Test WiFi",
        passwd="encrypted-pass",
        security=4,
    )

    assert request == (
        HCNETSDK_EZVIZ_NET_CONFIG_UPLOAD_PUT
        + '{"NetConfigAndVoiceFileUpload":{"ip":"192.0.2.20","port":4567,'
        + '"bssid":"00:11:22:33:44:55","ssid":"Test WiFi",'
        + '"passwd":"encrypted-pass","security":4}}'
        + "\r\n"
    )
    assert ezviz_lan_net_config_and_voice_upload_put_config(
        ip="192.0.2.20",
        port=4567,
        bssid="00:11:22:33:44:55",
        ssid="Test WiFi",
        passwd="encrypted-pass",
        security=4,
    ).request == request


def test_hcnetsdk_dvr_config_request_models_get_and_set_shapes() -> None:
    get_request = hcnetsdk_dvr_config_get_request(
        42,
        HcNetSdkDvrCommand.GET_WIFI_CFG,
        structure="NET_DVR_WIFI_CFG",
    )
    set_request = hcnetsdk_dvr_config_set_request(
        42,
        HcNetSdkDvrCommand.SET_WIFI_CFG,
        structure="NET_DVR_WIFI_CFG",
        field_updates={"dwMode": 1},
        read_before_write=True,
    )

    assert HCNETSDK_GET_DVR_CONFIG == "NET_DVR_GetDVRConfig"
    assert HCNETSDK_SET_DVR_CONFIG == "NET_DVR_SetDVRConfig"
    assert HcNetSdkDvrCommand.GET_EZVIZ_ACCESS_CFG == 3398
    assert HcNetSdkDvrCommand.SET_EZVIZ_ACCESS_CFG == 3399
    assert get_request == HcNetSdkDvrConfigRequest(
        login_id=42,
        command=HcNetSdkDvrCommand.GET_WIFI_CFG,
        channel=-1,
        structure="NET_DVR_WIFI_CFG",
        api=HCNETSDK_GET_DVR_CONFIG,
    )
    assert get_request.to_native_args_hint() == {
        "api": HCNETSDK_GET_DVR_CONFIG,
        "lUserID": 42,
        "dwCommand": 307,
        "lChannel": -1,
        "structure": "NET_DVR_WIFI_CFG",
        "lpOutBuffer": "<NET_DVR_WIFI_CFG>",
        "dwOutBufferSize": "sizeof(NET_DVR_WIFI_CFG)",
        "lpBytesReturned": "<bytes-returned>",
    }
    assert set_request.to_native_args_hint() == {
        "api": HCNETSDK_SET_DVR_CONFIG,
        "lUserID": 42,
        "dwCommand": 306,
        "lChannel": -1,
        "structure": "NET_DVR_WIFI_CFG",
        "lpInBuffer": "<NET_DVR_WIFI_CFG>",
        "dwInBufferSize": "sizeof(NET_DVR_WIFI_CFG)",
        "fieldUpdates": {"dwMode": 1},
        "readBeforeWrite": True,
    }


def test_hcnetsdk_dvr_config_command_port_template_uses_traced_hd_config() -> None:
    request = ezviz_lan_hd_config_request(42)
    template = hcnetsdk_dvr_config_command_port_template(request)
    explicit = hcnetsdk_dvr_config_command_port_template(
        ezviz_lan_wifi_ap_info_list_request(42),
        command_id=0x123456,
        body_tail=COMMAND_PORT_TRACE_BODY_TAIL,
    )

    assert template.command_id == 0x111050
    assert template.body_tail == COMMAND_PORT_EMPTY_BODY_TAIL
    assert template.name == "NET_DVR_GetDVRConfig:1054"
    assert explicit.command_id == 0x123456
    assert explicit.body_tail == COMMAND_PORT_TRACE_BODY_TAIL


def test_hcnetsdk_dvr_config_command_port_template_rejects_untraced_or_set() -> None:
    with pytest.raises(PyEzvizError, match="command-port id is unknown"):
        hcnetsdk_dvr_config_command_port_template(
            ezviz_lan_wifi_ap_info_list_request(42)
        )

    with pytest.raises(PyEzvizError, match="GET only"):
        hcnetsdk_dvr_config_command_port_template(
            ezviz_lan_wifi_set_config_request(42, ssid="Test")
        )


def test_hcnetsdk_get_dvr_config_command_port_returns_binary_body() -> None:
    rsa_key = RSA.generate(1024)
    challenge = b"0123456789abcdef0123456789abcdef"
    seed = b"s" * 64
    hd_config_body = b"\x00\x00\x12\x98" + (b"\x00" * 4756)
    sockets = [
        _FakeSocket(
            [
                build_hcnetsdk_tcp_frame(
                    PKCS1_v1_5.new(rsa_key.publickey()).encrypt(challenge) + seed
                ),
                build_hcnetsdk_tcp_frame(
                    HCNETSDK_COMMAND_PORT_TEST_SESSION_ID + b"CAM123\x00",
                    field_4=0x10A24BF1,
                ),
            ]
        ),
        _FakeSocket([build_hcnetsdk_tcp_frame(hd_config_body)]),
    ]

    def socket_factory(address: tuple[str, int], timeout: float | None) -> _FakeSocket:
        assert address == ("192.0.2.10", 8000)
        assert timeout == COMMAND_PORT_DEFAULT_TIMEOUT
        return sockets.pop(0)

    output = hcnetsdk_get_dvr_config_command_port(
        HcNetSdkLanEndpoint(serial="CAM123", host="192.0.2.10"),
        b"123456",
        ezviz_lan_hd_config_request(42),
        local_ip="192.0.2.56",
        socket_factory=socket_factory,
        rsa_key=rsa_key,
    )

    assert output == hd_config_body


def test_ezviz_lan_wifi_request_shapes_match_apk_setters() -> None:
    patch = ezviz_lan_wifi_station_patch(
        ssid=b"abcdefghijklmnopqrstuvwxyz0123456789",
        password="secret",
        mac="00:11:22:33:44:55",
    )
    request = ezviz_lan_wifi_set_config_request(
        42,
        ssid="Test WiFi",
        password="secret",
        mac="00:11:22:33:44:55",
    )
    hint = request.to_native_args_hint()

    assert patch == {
        "dwMode": 0,
        "sEssid": b"abcdefghijklmnopqrstuvwxyz012345",
        "sEssidLength": 32,
        "dwSecurity": 4,
        "struEtherNet.byMACAddr": b"\x00\x11\x22\x33\x44\x55",
        "wpa_psk.dwKeyLength": 6,
        "wpa_psk.byKeyType": 0,
        "wpa_psk.sKeyInfo": "<password-bytes>",
        "wpa_psk.sKeyInfoLength": 6,
    }
    assert ezviz_lan_wifi_get_config_request(42).to_native_args_hint()[
        "dwCommand"
    ] == HcNetSdkDvrCommand.GET_WIFI_CFG
    assert ezviz_lan_wifi_ap_info_list_request(42).to_native_args_hint()[
        "structure"
    ] == "NET_DVR_AP_INFO_LIST"
    assert ezviz_lan_wifi_connect_status_request(42).to_native_args_hint() == {
        "api": HCNETSDK_GET_DVR_CONFIG,
        "lUserID": 42,
        "dwCommand": 310,
        "lChannel": 0,
        "structure": "NET_DVR_WIFI_CONNECT_STATUS",
        "lpOutBuffer": "<NET_DVR_WIFI_CONNECT_STATUS>",
        "dwOutBufferSize": "sizeof(NET_DVR_WIFI_CONNECT_STATUS)",
        "lpBytesReturned": "<bytes-returned>",
    }
    assert hint["dwCommand"] == HcNetSdkDvrCommand.SET_WIFI_CFG
    assert hint["readBeforeWrite"] is True
    assert hint["fieldUpdates"]["sEssid"] == EXPECTED_TEST_WIFI_SSID_BYTES
    assert hint["fieldUpdates"]["wpa_psk.sKeyInfo"] == "<password-bytes>"
    assert ezviz_lan_wifi_work_mode_update_request(42, 1).to_native_args_hint()[
        "fieldUpdates"
    ] == {"dwMode": 1}


def test_ezviz_lan_wifi_request_rejects_overlong_or_invalid_inputs() -> None:
    with pytest.raises(PyEzvizError, match="password"):
        ezviz_lan_wifi_station_patch(ssid="ssid", password=b"x" * 64)
    with pytest.raises(PyEzvizError, match="MAC"):
        ezviz_lan_wifi_station_patch(ssid="ssid", mac="00:11")
    with pytest.raises(PyEzvizError, match="successful login"):
        HcNetSdkDvrConfigRequest(
            login_id=-1,
            command=HcNetSdkDvrCommand.GET_WIFI_CFG,
            channel=-1,
            structure="NET_DVR_WIFI_CFG",
            api=HCNETSDK_GET_DVR_CONFIG,
        ).to_native_args_hint()


def test_ezviz_lan_ezviz_access_request_matches_local_add_rewrite() -> None:
    get_request = ezviz_lan_ezviz_access_get_config_request(42)
    set_request = ezviz_lan_ezviz_access_set_domain_request(
        42,
        "dev.ezvizru.com",
    )
    replacement_request = ezviz_lan_ezviz_access_replacement_domain_request(
        42,
        b"api.ezvizlife.com\x00\x00",
    )

    assert ezviz_lan_ezviz_access_replacement_domain(
        b"api.ezvizlife.com\x00"
    ) == "api.ezvizru.com"
    assert ezviz_lan_ezviz_access_replacement_domain(None) == "dev.ezvizru.com"
    assert get_request.to_native_args_hint()["dwCommand"] == 3398
    assert get_request.to_native_args_hint()["lChannel"] == 1
    assert set_request.to_native_args_hint()["fieldUpdates"] == {
        "byDomainName": b"dev.ezvizru.com",
        "byDomainNameLength": 15,
    }
    assert replacement_request.to_native_args_hint()["fieldUpdates"][
        "byDomainName"
    ] == EXPECTED_EZVIZ_RU_DOMAIN_BYTES


def test_ezviz_lan_audio_video_and_picture_request_shapes() -> None:
    audio_input = ezviz_lan_audio_input_get_config_request(42, 1)
    audio_output = ezviz_lan_audioout_volume_get_config_request(42, 1)
    input_volume, output_volume = ezviz_lan_audio_volume_update_requests(
        42,
        1,
        input_volume=7,
        output_volume=8,
    )
    video_get = ezviz_lan_video_coding_get_config_request(42, 2)
    video_set = ezviz_lan_video_coding_update_request(
        42,
        2,
        video_encoding_type=1,
        video_frame_rate=25,
        video_bitrate=96,
    )
    pic_get = ezviz_lan_pic_config_get_request(42, 3)
    pic_set = ezviz_lan_pic_config_update_request(
        42,
        3,
        show_osd=1,
        channel_name="Example Camera With A Very Long Name",
    )

    assert audio_input.to_native_args_hint()["dwCommand"] == 3201
    assert audio_output.to_native_args_hint()["dwCommand"] == 3237
    assert input_volume.to_native_args_hint()["fieldUpdates"] == {"byVolume": 7}
    assert output_volume.to_native_args_hint()["fieldUpdates"] == {
        "byAudioOutVolume": 8
    }
    assert video_get.to_native_args_hint()["structure"] == "NET_DVR_COMPRESSIONCFG_V30"
    assert video_set.to_native_args_hint()["fieldUpdates"] == {
        "struNormHighRecordPara.byVideoEncType": 1,
        "struNormHighRecordPara.dwVideoFrameRate": 25,
        "struNormHighRecordPara.dwVideoBitrate": 96,
    }
    assert pic_get.to_native_args_hint()["dwCommand"] == 6179
    assert pic_set.to_native_args_hint()["fieldUpdates"] == {
        "dwShowOsd": 1,
        "sChanName": b"Example Camera With A Very Long ",
        "sChanNameLength": 32,
    }
    with pytest.raises(PyEzvizError, match="one byte"):
        ezviz_lan_audio_volume_update_requests(42, 1, input_volume=300, output_volume=8)


def test_ezviz_lan_storage_format_request_shapes_match_rn_module() -> None:
    hd_config = ezviz_lan_hd_config_request(42)
    start = ezviz_lan_sd_format_start_request(42, 0)
    progress = ezviz_lan_sd_format_progress_request(1001)
    close = ezviz_lan_sd_format_close_request(1001)

    assert HCNETSDK_FORMAT_DISK == "NET_DVR_FormatDisk"
    assert HCNETSDK_GET_FORMAT_PROGRESS == "NET_DVR_GetFormatProgress"
    assert HCNETSDK_CLOSE_FORMAT_HANDLE == "NET_DVR_CloseFormatHandle"
    assert hd_config.to_native_args_hint() == {
        "api": HCNETSDK_GET_DVR_CONFIG,
        "lUserID": 42,
        "dwCommand": 1054,
        "lChannel": -1,
        "structure": "NET_DVR_HDCFG",
        "lpOutBuffer": "<NET_DVR_HDCFG>",
        "dwOutBufferSize": "sizeof(NET_DVR_HDCFG)",
        "lpBytesReturned": "<bytes-returned>",
    }
    assert start == HcNetSdkFormatDiskRequest(login_id=42, disk_number=0)
    assert start.to_native_args_hint() == {
        "api": HCNETSDK_FORMAT_DISK,
        "lUserID": 42,
        "lDiskNumber": 0,
        "failureHandle": -1,
    }
    assert progress == HcNetSdkFormatProgressRequest(format_handle=1001)
    assert progress.to_native_args_hint() == {
        "api": HCNETSDK_GET_FORMAT_PROGRESS,
        "lFormatHandle": 1001,
        "pCurrentFormatDisk": "<IntByReference>",
        "pCurrentDiskPos": "<IntByReference>",
        "pFormatStatic": "<IntByReference>",
    }
    assert close == HcNetSdkCloseFormatHandleRequest(format_handle=1001)
    assert close.to_native_args_hint() == {
        "api": HCNETSDK_CLOSE_FORMAT_HANDLE,
        "lFormatHandle": 1001,
    }

    assert ezviz_lan_sd_format_progress_result(
        native_succeeded=True,
        current_disk=0,
        current_disk_position=27,
        status=0,
    ) == EzvizLanSdFormatProgress(
        code=0,
        current_disk=0,
        progress=27,
        status=0,
        done=False,
    )
    assert ezviz_lan_sd_format_progress_result(
        native_succeeded=True,
        current_disk=0,
        current_disk_position=91,
        status=1,
    ) == EzvizLanSdFormatProgress(
        code=0,
        current_disk=0,
        progress=100,
        status=1,
        done=True,
    )
    assert ezviz_lan_sd_format_progress_result(
        native_succeeded=True,
        status=7,
        last_error=0,
    ).code == -1
    assert ezviz_lan_sd_format_progress_result(
        native_succeeded=False,
        last_error=23,
    ).code == 23
    with pytest.raises(PyEzvizError, match="disk number"):
        ezviz_lan_sd_format_start_request(42, -1).to_native_args_hint()
    with pytest.raises(PyEzvizError, match="format handle"):
        ezviz_lan_sd_format_progress_request(-1).to_native_args_hint()


def test_hcnetsdk_alarm_request_shapes_match_jna_surface() -> None:
    legacy = hcnetsdk_setup_alarm_v30_request(42)
    modern = hcnetsdk_setup_alarm_v41_request(
        42,
        level=1,
        alarm_info_type=1,
        ret_alarm_type_v40=1,
        ret_dev_info_version=1,
        ret_vqd_alarm_type=0,
        face_alarm_detection=1,
        support=2,
        broken_net_http=0,
        task_no=7,
    )
    close = hcnetsdk_close_alarm_request(1001)

    assert HCNETSDK_SETUP_ALARM_CHAN_V30 == "NET_DVR_SetupAlarmChan_V30"
    assert HCNETSDK_SETUP_ALARM_CHAN_V41 == "NET_DVR_SetupAlarmChan_V41"
    assert HCNETSDK_CLOSE_ALARM_CHAN_V30 == "NET_DVR_CloseAlarmChan_V30"
    assert legacy == HcNetSdkSetupAlarmRequest(login_id=42)
    assert legacy.to_native_args_hint() == {
        "api": HCNETSDK_SETUP_ALARM_CHAN_V30,
        "lUserID": 42,
        "failureHandle": -1,
    }
    assert modern.to_native_args_hint() == {
        "api": HCNETSDK_SETUP_ALARM_CHAN_V41,
        "lUserID": 42,
        "lpSetupParam": {
            "structure": "NET_DVR_SETUPALARM_PARAM",
            "fieldOrder": HCNETSDK_SETUPALARM_PARAM_FIELD_ORDER,
            "dwSize": "sizeof(NET_DVR_SETUPALARM_PARAM)",
            "byLevel": 1,
            "byAlarmInfoType": 1,
            "byRetAlarmTypeV40": 1,
            "byRetDevInfoVersion": 1,
            "byRetVQDAlarmType": 0,
            "byFaceAlarmDetection": 1,
            "bySupport": 2,
            "byBrokenNetHttp": 0,
            "wTaskNo": 7,
            "byRes1Length": 6,
        },
        "failureHandle": -1,
    }
    assert close == HcNetSdkCloseAlarmRequest(alarm_handle=1001)
    assert close.to_native_args_hint() == {
        "api": HCNETSDK_CLOSE_ALARM_CHAN_V30,
        "lAlarmHandle": 1001,
    }
    with pytest.raises(PyEzvizError, match="successful login"):
        hcnetsdk_setup_alarm_v30_request(-1).to_native_args_hint()
    with pytest.raises(PyEzvizError, match="unsigned word"):
        HcNetSdkSetupAlarmParam(task_no=65_536).to_native_dict()
    with pytest.raises(PyEzvizError, match="alarm handle"):
        hcnetsdk_close_alarm_request(-1).to_native_args_hint()


def test_hcnetsdk_set_sdk_local_cfg_shapes_match_jna_surface() -> None:
    generic = hcnetsdk_set_sdk_local_cfg_request(
        HcNetSdkLocalCfgType.MEM_POOL,
        structure="NET_DVR_LOCAL_MEM_POOL_CFG",
        field_updates={"dwAlarmMaxBlockNum": 32},
    )
    ability_parse = ezviz_hcnetsdk_local_ability_parse_request(enabled=True)
    ptz_without_recv = ezviz_hcnetsdk_local_ptz_without_recv_request(
        without_recv=False
    )

    assert HCNETSDK_SET_SDK_LOCAL_CFG == "NET_DVR_SetSDKLocalCfg"
    assert HcNetSdkLocalCfgType.TCP_PORT_BIND == 0
    assert HcNetSdkLocalCfgType.ABILITY_PARSE == 4
    assert HcNetSdkLocalCfgType.LOG == 15
    assert HcNetSdkLocalCfgType.PTZ == 18
    assert generic == HcNetSdkSetSdkLocalCfgRequest(
        cfg_type=HcNetSdkLocalCfgType.MEM_POOL,
        structure="NET_DVR_LOCAL_MEM_POOL_CFG",
        field_updates={"dwAlarmMaxBlockNum": 32},
    )
    assert generic.to_native_args_hint() == {
        "api": HCNETSDK_SET_SDK_LOCAL_CFG,
        "enumType": 2,
        "lpInBuff": "<NET_DVR_LOCAL_MEM_POOL_CFG>",
        "structure": "NET_DVR_LOCAL_MEM_POOL_CFG",
        "fieldUpdates": {"dwAlarmMaxBlockNum": 32},
    }
    assert ability_parse.to_native_args_hint() == {
        "api": HCNETSDK_SET_SDK_LOCAL_CFG,
        "enumType": 4,
        "lpInBuff": "<NET_DVR_LOCAL_ABILITY_PARSE_CFG>",
        "structure": "NET_DVR_LOCAL_ABILITY_PARSE_CFG",
        "fieldUpdates": {"byEnableAbilityParse": 1},
        "fieldOrder": HCNETSDK_LOCAL_ABILITY_PARSE_CFG_FIELD_ORDER,
    }
    assert ptz_without_recv.to_native_args_hint() == {
        "api": HCNETSDK_SET_SDK_LOCAL_CFG,
        "enumType": 18,
        "lpInBuff": "<NET_DVR_LOCAL_PTZ_CFG>",
        "structure": "NET_DVR_LOCAL_PTZ_CFG",
        "fieldUpdates": {"byWithoutRecv": 0},
        "fieldOrder": HCNETSDK_LOCAL_PTZ_CFG_FIELD_ORDER,
    }
    with pytest.raises(PyEzvizError, match="config type"):
        hcnetsdk_set_sdk_local_cfg_request(
            -1,
            structure="NET_DVR_LOCAL_MEM_POOL_CFG",
        ).to_native_args_hint()
    with pytest.raises(PyEzvizError, match="one byte"):
        ezviz_hcnetsdk_local_ability_parse_request(enabled=300)


def test_ezviz_lan_user_password_and_video_effect_request_shapes() -> None:
    password_get = ezviz_lan_user_password_get_config_request(42)
    password_set = ezviz_lan_user_password_update_request(42, "newpass")
    video_get = ezviz_lan_video_effect_get_config_request(42)
    video_set = ezviz_lan_video_effect_update_request(
        42,
        brightness=1,
        contrast=2,
        saturation=3,
        sharpness=4,
    )

    assert password_get.to_native_args_hint()["dwCommand"] == 1006
    assert password_get.to_native_args_hint()["structure"] == "NET_DVR_USER_V30"
    assert password_set.to_native_args_hint()["dwCommand"] == 1007
    assert password_set.to_native_args_hint()["readBeforeWrite"] is True
    assert password_set.to_native_args_hint()["fieldUpdates"] == {
        "struUser[0].sPassword": "<password-bytes>",
        "struUser[0].sPasswordLength": 7,
        "struUser[0].sPasswordZeroFill": 16,
    }
    assert video_get.to_native_args_hint()["dwCommand"] == 1067
    assert video_get.to_native_args_hint()["structure"] == "NET_DVR_CAMERAPARAMCFG"
    assert video_set.to_native_args_hint()["dwCommand"] == 1068
    assert video_set.to_native_args_hint()["fieldUpdates"] == {
        "struVideoEffect.byBrightnessLevel": 1,
        "struVideoEffect.byContrastLevel": 2,
        "struVideoEffect.bySaturationLevel": 3,
        "struVideoEffect.bySharpnessLevel": 4,
    }
    with pytest.raises(PyEzvizError, match="password"):
        ezviz_lan_user_password_update_request(42, "")
    with pytest.raises(PyEzvizError, match="password"):
        ezviz_lan_user_password_update_request(42, b"x" * 17)
    with pytest.raises(PyEzvizError, match="one byte"):
        ezviz_lan_video_effect_update_request(
            42,
            brightness=1,
            contrast=2,
            saturation=3,
            sharpness=256,
        )


def test_ezviz_lan_backlight_wdr_and_day_night_request_shapes() -> None:
    backlight_get = ezviz_lan_backlight_wdr_get_config_request(42)
    backlight_set = ezviz_lan_backlight_wdr_update_request(
        42,
        wdr_enabled=1,
        backlight_mode=2,
    )
    day_night_get = ezviz_lan_day_night_get_config_request(42)
    day_night_set = ezviz_lan_day_night_update_request(
        42,
        day_night_filter_type=1,
        begin_time=7,
        begin_time_min=30,
        begin_time_sec=15,
        end_time=18,
        end_time_min=45,
        end_time_sec=20,
        night_to_day_filter_level=4,
    )

    assert backlight_get.to_native_args_hint()["dwCommand"] == 1067
    assert day_night_get.to_native_args_hint()["structure"] == "NET_DVR_CAMERAPARAMCFG"
    assert backlight_set.to_native_args_hint()["fieldUpdates"] == {
        "struWdr.byWDREnabled": 1,
        "struBackLight.byBacklightMode": 2,
    }
    assert day_night_set.to_native_args_hint()["fieldUpdates"] == {
        "struDayNight.byDayNightFilterType": 1,
        "struDayNight.byBeginTime": 7,
        "struDayNight.byBeginTimeMin": 30,
        "struDayNight.byBeginTimeSec": 15,
        "struDayNight.byEndTime": 18,
        "struDayNight.byEndTimeMin": 45,
        "struDayNight.byEndTimeSec": 20,
        "struDayNight.byNightToDayFilterLevel": 4,
    }
    with pytest.raises(PyEzvizError, match="one byte"):
        ezviz_lan_backlight_wdr_update_request(
            42,
            wdr_enabled=256,
            backlight_mode=2,
        )
    with pytest.raises(PyEzvizError, match="one byte"):
        ezviz_lan_day_night_update_request(
            42,
            day_night_filter_type=1,
            begin_time=7,
            begin_time_min=30,
            begin_time_sec=15,
            end_time=18,
            end_time_min=45,
            end_time_sec=20,
            night_to_day_filter_level=300,
        )


def test_ezviz_lan_rn_ability_request_shapes_use_observed_buffers() -> None:
    rn_request = ezviz_lan_rn_device_ability_request(
        42,
        HcNetSdkAbility.IPC_FRONT_PARAMETER,
    )
    image_request = ezviz_lan_image_display_param_ability_request(42, 3)
    video_pic_request = ezviz_lan_video_pic_ability_request(42, 4)
    av_request = ezviz_lan_audio_video_compress_info_ability_request(42, 2)
    access_request = ezviz_lan_access_protocol_ability_request(42)
    record_request = ezviz_lan_record_ability_request(42)

    assert rn_request.output_buffer_size == HCNETSDK_DEVICE_ABILITY_RN_OUTPUT_BUFFER_SIZE
    assert rn_request.retry_output_buffer_size is None
    assert image_request.output_buffer_size == HCNETSDK_DEVICE_ABILITY_RN_OUTPUT_BUFFER_SIZE
    assert image_request.in_buffer_bytes == EXPECTED_IMAGE_DISPLAY_PARAM_ABILITY_XML
    assert video_pic_request.ability_type == 14
    assert video_pic_request.in_buffer_bytes == EXPECTED_VIDEO_PIC_ABILITY_XML
    assert av_request.ability_type == HcNetSdkAbility.DEVICE_ENCODE_ALL_V20
    assert av_request.in_buffer_bytes == EXPECTED_AUDIO_VIDEO_COMPRESS_INFO_XML
    assert access_request.in_buffer_bytes == EXPECTED_ACCESS_PROTOCOL_ABILITY_XML
    assert record_request.in_buffer_bytes.startswith(b"<RecordAbility")


def test_hcnetsdk_device_ability_request_matches_device_ability_request() -> None:
    in_buffer = ezviz_lan_ptz_ability_input(1)
    request = hcnetsdk_device_ability_request(
        42,
        HcNetSdkAbility.DEVICE_ABILITY_INFO,
        in_buffer=in_buffer,
    )
    hint = request.to_native_args_hint()

    assert HCNETSDK_GET_DEVICE_ABILITY == "NET_DVR_GetDeviceAbility"
    assert HCNETSDK_DEVICE_ABILITY_DEFAULT_OUTPUT_BUFFER_SIZE == 65_536
    assert HCNETSDK_DEVICE_ABILITY_RETRY_OUTPUT_BUFFER_SIZE == 524_288
    assert HCNETSDK_DEVICE_ABILITY_RN_OUTPUT_BUFFER_SIZE == 2_097_152
    assert HCNETSDK_DEVICE_ABILITY_BUFFER_TOO_SMALL_ERROR == 331_001
    assert request == HcNetSdkDeviceAbilityRequest(
        login_id=42,
        ability_type=HcNetSdkAbility.DEVICE_ABILITY_INFO,
        in_buffer=in_buffer,
    )
    assert request.in_buffer_bytes == in_buffer
    assert hint == {
        "api": HCNETSDK_GET_DEVICE_ABILITY,
        "lUserID": 42,
        "dwAbilityType": 17,
        "pInBuf": "<input-buffer>",
        "dwInLength": len(in_buffer),
        "pOutBuf": "<output-buffer>",
        "dwOutLength": HCNETSDK_DEVICE_ABILITY_DEFAULT_OUTPUT_BUFFER_SIZE,
        "retryOnError": HCNETSDK_DEVICE_ABILITY_BUFFER_TOO_SMALL_ERROR,
        "retryDwOutLength": HCNETSDK_DEVICE_ABILITY_RETRY_OUTPUT_BUFFER_SIZE,
    }
    assert request.to_native_args_hint(include_buffers=True)["pInBuf"] == in_buffer


def test_hcnetsdk_device_ability_xml_builders_match_apk_shapes() -> None:
    assert hcnetsdk_device_ability_xml("PTZAbility", channel=1) == (
        EXPECTED_PTZ_ABILITY_XML
    )
    assert ezviz_lan_ptz_ability_input(1) == EXPECTED_PTZ_ABILITY_XML
    assert ezviz_lan_audio_video_compress_info_input(2) == (
        EXPECTED_AUDIO_VIDEO_COMPRESS_INFO_XML
    )
    assert ezviz_lan_image_display_param_ability_input(3) == (
        EXPECTED_IMAGE_DISPLAY_PARAM_ABILITY_XML
    )
    assert ezviz_lan_video_pic_ability_input(4) == EXPECTED_VIDEO_PIC_ABILITY_XML
    assert ezviz_lan_access_protocol_ability_input() == (
        EXPECTED_ACCESS_PROTOCOL_ABILITY_XML
    )


def test_ezviz_lan_soft_hardware_ability_request_matches_helper() -> None:
    request = ezviz_lan_soft_hardware_ability_request(42)

    assert HcNetSdkAbility.DEVICE_SOFT_HARDWARE == 1
    assert HcNetSdkAbility.DEVICE_ENCODE_ALL_V20 == 8
    assert HcNetSdkAbility.DEVICE_VIDEOPIC == 14
    assert request.ability_type == HcNetSdkAbility.DEVICE_SOFT_HARDWARE
    assert request.in_buffer_bytes == DEVICE_ABILITY_EMPTY_BUFFER
    assert request.to_native_args_hint()["dwAbilityType"] == 1


def test_ezviz_lan_soft_hardware_ability_parses_device_ability_fields() -> None:
    ability = ezviz_lan_soft_hardware_ability(
        b"\x00<DeviceAbility>"
        b"<SoftwareCapability>"
        b"<MaxPreviewNum>4</MaxPreviewNum>"
        b"<PtzSupport>1</PtzSupport>"
        b"<isSupportLoginTiming>true</isSupportLoginTiming>"
        b"</SoftwareCapability>"
        b"<HardwareCapability>"
        b"<SDNum>1</SDNum>"
        b"<HardDiskNum>2</HardDiskNum>"
        b"</HardwareCapability>"
        b"</DeviceAbility>\x00"
    )

    assert ability.success is True
    assert ability.max_preview_num == 4
    assert ability.ptz_support == 1
    assert ability.ptz_supported is True
    assert ability.support_timing is True
    assert ability.sd_num == 1
    assert ability.hard_disk_num == 2


def test_ezviz_lan_soft_hardware_ability_uses_app_defaults() -> None:
    ability = ezviz_lan_soft_hardware_ability(
        "<DeviceAbility><SoftwareCapability>"
        "<MaxPreviewNum>bad</MaxPreviewNum>"
        "</SoftwareCapability></DeviceAbility>"
    )

    assert ability.success is False
    assert ability.has_software_capability is True
    assert ability.has_hardware_capability is False
    assert ability.max_preview_num == 0
    assert ability.support_timing is False


def test_ezviz_lan_playback_convert_ability_parses_record_ability() -> None:
    ability = ezviz_lan_playback_convert_ability(
        b"<RecordAbility><PlayConvert><VideoResolutionList>"
        b"<VideoResolutionEntry>"
        b"<Index>2</Index>"
        b"<Name>ignored</Name>"
        b"<Resolution><Min>1</Min><Max>99</Max></Resolution>"
        b"<VideoFrameRate>10,15,25</VideoFrameRate>"
        b"<VideoBitrate><Range>6,7,19</Range></VideoBitrate>"
        b"</VideoResolutionEntry>"
        b"<VideoResolutionEntry>"
        b"<Index>5</Index>"
        b"<VideoFrameRate>bad,30</VideoFrameRate>"
        b"<VideoBitrate><Range>10,,11</Range></VideoBitrate>"
        b"</VideoResolutionEntry>"
        b"</VideoResolutionList></PlayConvert></RecordAbility>"
    )

    assert ability.success is True
    assert len(ability.resolutions) == 2
    assert ability.resolutions[0].index == 2
    assert ability.resolutions[0].frame_rates == (10, 15, 25)
    assert ability.resolutions[0].bitrates == (6, 7, 19)
    assert ability.resolutions[1].frame_rates == (30,)
    assert ability.resolutions[1].bitrates == (10, 11)


def test_ezviz_lan_device_ability_parsers_reject_invalid_xml() -> None:
    with pytest.raises(PyEzvizError, match="soft/hardware"):
        ezviz_lan_soft_hardware_ability("<DeviceAbility>")
    with pytest.raises(PyEzvizError, match="playback"):
        ezviz_lan_playback_convert_ability("<RecordAbility>")


def test_ezviz_lan_ptz_ability_request_and_ipc_front_parameter_request() -> None:
    ptz_request = ezviz_lan_ptz_ability_request(42, 1)
    front_request = ezviz_lan_ipc_front_parameter_ability_request(42)

    assert ptz_request.ability_type == HcNetSdkAbility.DEVICE_ABILITY_INFO
    assert ptz_request.in_buffer_bytes == ezviz_lan_ptz_ability_input(1)
    assert front_request.ability_type == HcNetSdkAbility.IPC_FRONT_PARAMETER
    assert front_request.in_buffer_bytes == DEVICE_ABILITY_EMPTY_BUFFER
    assert front_request.to_native_args_hint()["dwInLength"] == 0


def test_ezviz_lan_ptz_ability_parses_handler_fields() -> None:
    ability = ezviz_lan_ptz_ability(
        b"\x00<PTZAbility>"
        b'<controlType opt="UP,DOWN,LEFT"/>'
        b'<ParkAction><actionType opt="preset,cruise"/></ParkAction>'
        b'<SchduleTask><actionType opt="task1,task2"/></SchduleTask>'
        b'<globalEnable opt="true"/>'
        b"<Mirror><Range>0,1,2</Range></Mirror>"
        b"</PTZAbility>\x00"
    )

    assert ability.control_types == "UP,DOWN,LEFT"
    assert ability.control_type_options == ("UP", "DOWN", "LEFT")
    assert ability.park_action_types == "preset,cruise"
    assert ability.schedule_task_types == "task1,task2"
    assert ability.privacy_mask_enable is True
    assert ability.mirror_range == "0,1,2"


def test_ezviz_lan_ptz_ability_rejects_invalid_xml() -> None:
    with pytest.raises(PyEzvizError, match="XML"):
        ezviz_lan_ptz_ability("<PTZAbility>")
    with pytest.raises(PyEzvizError, match="XML name"):
        hcnetsdk_device_ability_xml("Bad Root")
    with pytest.raises(PyEzvizError, match="retry buffer"):
        HcNetSdkDeviceAbilityRequest(
            login_id=42,
            ability_type=17,
            output_buffer_size=10,
            retry_output_buffer_size=1,
        ).to_native_args_hint()


def test_ezviz_ptz_command_mappings_match_player_constants() -> None:
    assert EZVIZ_LAN_PTZ_SPEED_DEFAULT == 5
    assert EZVIZ_LAN_PTZ_ACTION_START == 10
    assert EZVIZ_LAN_PTZ_ACTION_STOP == 11
    assert EZVIZ_LAN_PTZ_ACTION_RESET == 101
    assert EZVIZ_LAN_PTZ_COMMAND_MAP == {
        0: 21,
        1: 22,
        2: 23,
        3: 24,
        5: 11,
        6: 12,
        7: 8,
        8: 9,
        9: 39,
        10: 0,
        11: 1,
    }
    assert {7, 8, 9} == EZVIZ_LAN_PTZ_PRESET_COMMANDS
    assert EZVIZ_CAS_PTZ_COMMAND_MAP[EzvizPtzCommand.UP] == "UP"
    assert ezviz_cas_ptz_command(EzvizPtzCommand.DOWN_RIGHT) == "DOWNRIGHT"
    assert ezviz_cas_ptz_command(EzvizPtzCommand.FLIP) == ""
    assert ezviz_lan_ptz_native_command(EzvizPtzCommand.UP) == (
        HcNetSdkPtzCommand.TILT_UP
    )
    assert ezviz_lan_ptz_native_command(EzvizPtzCommand.ZOOM_OUT) == (
        HcNetSdkPtzCommand.ZOOM_OUT
    )
    assert ezviz_lan_ptz_native_command(EzvizPtzCommand.ACTION_START) == 0
    assert ezviz_lan_ptz_native_command(EzvizPtzCommand.ACTION_STOP) == 1


def test_ezviz_lan_ptz_control_request_matches_ptz_control_lan() -> None:
    request = ezviz_lan_ptz_control_request(
        42,
        1,
        EzvizPtzCommand.LEFT,
        action=EzvizPtzCommand.ACTION_STOP,
        speed=3,
    )

    assert request == HcNetSdkPtzControlRequest(
        login_id=42,
        channel=1,
        command=HcNetSdkPtzCommand.PAN_LEFT,
        stop=1,
        speed=3,
    )
    assert request.to_native_args_hint() == {
        "api": HCNETSDK_PTZ_CONTROL_WITH_SPEED_OTHER,
        "lUserID": 42,
        "lChannel": 1,
        "dwPTZCommand": 23,
        "dwStop": 1,
        "dwSpeed": 3,
    }
    assert ezviz_lan_ptz_request(
        42,
        1,
        EzvizPtzCommand.RIGHT,
        action=EzvizPtzCommand.ACTION_START,
    ).to_native_args_hint() == {
        "api": HCNETSDK_PTZ_CONTROL_WITH_SPEED_OTHER,
        "lUserID": 42,
        "lChannel": 1,
        "dwPTZCommand": 24,
        "dwStop": 0,
        "dwSpeed": EZVIZ_LAN_PTZ_SPEED_DEFAULT,
    }


def test_ezviz_lan_ptz_preset_request_matches_ptz_control_lan_branch() -> None:
    request = ezviz_lan_ptz_preset_request(
        42,
        1,
        EzvizPtzCommand.GOTO_PRESET,
        preset_index=0,
    )

    assert ezviz_lan_ptz_is_preset_command(EzvizPtzCommand.GOTO_PRESET) is True
    assert ezviz_lan_ptz_is_preset_command(EzvizPtzCommand.UP) is False
    assert request == HcNetSdkPtzPresetRequest(
        login_id=42,
        channel=1,
        command=HcNetSdkPtzPresetCommand.GOTO_PRESET,
        preset_index=0,
    )
    assert request.to_native_args_hint() == {
        "api": HCNETSDK_PTZ_PRESET_OTHER,
        "lUserID": 42,
        "lChannel": 1,
        "dwPTZPresetCmd": 39,
        "dwPresetIndex": 0,
    }
    assert ezviz_lan_ptz_request(
        42,
        1,
        EzvizPtzCommand.SET_PRESET,
    ).to_native_args_hint() == {
        "api": HCNETSDK_PTZ_PRESET_OTHER,
        "lUserID": 42,
        "lChannel": 1,
        "dwPTZPresetCmd": 8,
        "dwPresetIndex": 0,
    }


def test_ezviz_lan_ptz_rejects_unsupported_or_invalid_values() -> None:
    with pytest.raises(PyEzvizError, match="Unsupported"):
        ezviz_lan_ptz_native_command(EzvizPtzCommand.DOWN_RIGHT)
    with pytest.raises(PyEzvizError, match="preset"):
        ezviz_lan_ptz_control_request(42, 1, EzvizPtzCommand.SET_PRESET)
    with pytest.raises(PyEzvizError, match="not a preset"):
        ezviz_lan_ptz_preset_request(42, 1, EzvizPtzCommand.UP)
    with pytest.raises(PyEzvizError, match="stop flag"):
        HcNetSdkPtzControlRequest(42, 1, 21, 2).to_native_args_hint()
    with pytest.raises(PyEzvizError, match="preset index"):
        HcNetSdkPtzPresetRequest(42, 1, 39, -1).to_native_args_hint()


def test_ezviz_lan_settings_error_code_matches_presenter_offset() -> None:
    assert HCNETSDK_EZVIZ_SETTINGS_ERROR_BASE == 0x50910
    assert ezviz_lan_settings_error_code(1) == 0x50911
    assert ezviz_lan_settings_error_code(1100) == 0x50D5C


def test_ezviz_lan_settings_error_clears_password_for_account_errors() -> None:
    assert (
        ezviz_lan_settings_error_clears_password(
            HCNETSDK_EZVIZ_SETTINGS_ACCOUNT_PASSWORD_ERROR
        )
        is True
    )
    assert (
        ezviz_lan_settings_error_clears_password(
            HCNETSDK_EZVIZ_SETTINGS_ACCOUNT_PASSWORD_LOCKED_ERROR
        )
        is True
    )
    assert ezviz_lan_settings_error_clears_password(0x50912) is False


def test_ezviz_lan_settings_login_succeeded_accepts_zero_login_id() -> None:
    assert ezviz_lan_settings_login_succeeded(0) is True
    assert ezviz_lan_settings_login_succeeded(42) is True
    assert ezviz_lan_settings_login_succeeded(-1) is False


def test_ezviz_lan_play_device_login_models_player_owned_login() -> None:
    endpoint = HcNetSdkLanEndpoint(
        serial="CAM123",
        host="192.0.2.10",
        command_port=8000,
        stream_port=9020,
    )

    login = ezviz_lan_play_device_login(endpoint)

    assert login.api == EZVIZ_DEVICE_INFO_EX_LOGIN_PLAY_DEVICE
    assert login.facade_api == EZVIZ_PLAY_DATA_INFO_LOGIN_PLAY_DEVICE
    assert login.check_last_login_status is False
    assert login.to_device_param_hint() == {
        "serial": "CAM123",
        "deviceLocalIp": "192.0.2.10",
        "localCmdPort": 8000,
        "localStreamPort": 9020,
    }
    assert ezviz_lan_play_device_login_succeeded(0) is True
    assert ezviz_lan_play_device_login_succeeded(-1) is False


def test_hcnetsdk_real_data_payload_classification() -> None:
    assert classify_hcnetsdk_real_data_payload(b"\x00\x00\x01\xbaabc") == "mpeg_ps"
    assert classify_hcnetsdk_real_data_payload(b"\x00\x00\x01\xe0abc") == "mpeg_ps_start"
    assert classify_hcnetsdk_real_data_payload(b"Gabc") == "mpeg_ts"
    assert classify_hcnetsdk_real_data_payload(b"HKMIabc") == "hik_hkmi"
    assert classify_hcnetsdk_real_data_payload(b"@@@@abc") == "hik_private"
    assert classify_hcnetsdk_real_data_payload(b"") == "empty"
    assert classify_hcnetsdk_real_data_payload(b"abc") == "unknown"


def test_hcnetsdk_real_data_media_type_detection() -> None:
    assert hcnetsdk_real_data_type_is_media(HcNetSdkRealDataType.STREAM_DATA) is True
    assert hcnetsdk_real_data_type_is_media(HcNetSdkRealDataType.SYSTEM_HEADER) is False


def test_hcnetsdk_real_play_request_matches_v30_client_info_shape() -> None:
    request = hcnetsdk_real_play_request(
        7,
        channel_number=2,
        link_mode=1,
        blocked=True,
        multicast_ip="239.0.0.1",
    )

    assert request.api == HCNETSDK_REALPLAY_V30
    assert request.callback_api == HCNETSDK_REALDATA_CALLBACK_V30
    assert request.client_info.to_native_dict() == {
        "lChannel": 2,
        "lLinkMode": 1,
        "sMultiCastIP": "239.0.0.1",
    }
    assert request.to_native_args_hint() == {
        "api": HCNETSDK_REALPLAY_V30,
        "login_id": 7,
        "client_info": {
            "lChannel": 2,
            "lLinkMode": 1,
            "sMultiCastIP": "239.0.0.1",
        },
        "callback": HCNETSDK_REALDATA_CALLBACK_V30,
        "blocked": 1,
    }


def test_hcnetsdk_real_play_request_rejects_failed_login() -> None:
    request = hcnetsdk_real_play_request(-1)

    with pytest.raises(PyEzvizError, match="successful login id"):
        request.to_native_args_hint()


def test_hcnetsdk_client_info_rejects_negative_channel() -> None:
    with pytest.raises(PyEzvizError, match="channel"):
        HcNetSdkClientInfo(channel=-1).to_native_dict()


def test_iter_hcnetsdk_real_data_mpegps_filters_callback_packets() -> None:
    packets = [
        HcNetSdkRealDataPacket(1, HcNetSdkRealDataType.SYSTEM_HEADER, b"syshead"),
        HcNetSdkRealDataPacket(1, HcNetSdkRealDataType.STREAM_DATA, b"\x00\x00\x01\xbaabc"),
        HcNetSdkRealDataPacket(1, HcNetSdkRealDataType.AUDIO_STREAM_DATA, b"opaque"),
        HcNetSdkRealDataPacket(1, 999, b"\x00\x00\x01\xbadef"),
    ]

    assert list(iter_hcnetsdk_real_data_mpegps(packets)) == [b"\x00\x00\x01\xbaabc"]


def test_ezviz_lan_settings_channel_number_matches_activity_handoff() -> None:
    assert (
        ezviz_lan_settings_channel_number(
            analog_channel_count=1,
            digital_channel_count=0,
            analog_start_channel=1,
            digital_start_channel=33,
        )
        == 1
    )
    assert (
        ezviz_lan_settings_channel_number(
            analog_channel_count=0,
            digital_channel_count=1,
            analog_start_channel=1,
            digital_start_channel=33,
        )
        == 33
    )


@pytest.mark.parametrize(
    ("analog_channel_count", "digital_channel_count"),
    (
        (0, 0),
        (1, 1),
    ),
)
def test_ezviz_lan_settings_channel_number_rejects_non_single_preview(
    analog_channel_count: int, digital_channel_count: int
) -> None:
    with pytest.raises(PyEzvizError, match="one channel"):
        ezviz_lan_settings_channel_number(
            analog_channel_count=analog_channel_count,
            digital_channel_count=digital_channel_count,
            analog_start_channel=1,
            digital_start_channel=33,
        )


def test_ezviz_lan_playback_intent_matches_preview_back_navigation() -> None:
    intent = ezviz_lan_playback_intent(
        " CS-CV310-A0-1B2WFR0120200927CCRRTEST123456 ",
        channel_number=1,
        netsdk_login_id=0,
        ssid=None,
    )

    assert intent.to_extra_dict() == {
        EZVIZ_PLAYER_EXTRA_DEVICE_ID: "CS-CV310-A0-1B2WFR0120200927CCRRTEST123456",
        EZVIZ_PLAYER_EXTRA_CHANNEL_NO: 1,
        EZVIZ_PLAYER_EXTRA_LAN_FLAG: EZVIZ_PLAYER_LAN_FLAG_HCNETSDK,
        EZVIZ_PLAYER_EXTRA_LAN_USERID: -1,
        EZVIZ_PLAYER_EXTRA_WIFI_SSID: "",
    }


def test_ezviz_lan_playback_intent_can_forward_explicit_lan_user_id() -> None:
    intent = ezviz_lan_playback_intent(
        "CAM123",
        channel_number=1,
        netsdk_login_id=0,
        ssid="123",
    )

    assert intent.to_extra_dict()[EZVIZ_PLAYER_EXTRA_LAN_USERID] == 123
    assert intent.to_extra_dict()[EZVIZ_PLAYER_EXTRA_WIFI_SSID] == "123"


def test_ezviz_lan_playback_intent_rejects_failed_login_id() -> None:
    with pytest.raises(PyEzvizError, match="successful login id"):
        ezviz_lan_playback_intent("CAM123", channel_number=1, netsdk_login_id=-1)


def test_parse_ezviz_local_device_decodes_device_content() -> None:
    device = parse_ezviz_local_device(
        {
            "deviceSerial": "CAM123",
            "deviceName": "Test Camera",
            "deviceModel": "C8C",
            "category": "IPC",
            "deviceCategory": "IPC",
            "groupId": "-1",
            "deviceContent": (
                '{"deviceIP":"192.0.2.44","deviceType":1,'
                '"deviceEncType":2,"isLowPower":0,'
                '"deviceMaxActLimit":30,"deviceSdkVersion":4,'
                '"deviceRand":"abc","deviceRoleType":5}'
            ),
        }
    )

    assert device.serial == "CAM123"
    assert device.name == "Test Camera"
    assert device.group_id == -1
    assert device.content is not None
    assert device.content.device_ip == "192.0.2.44"
    assert device.content.device_enc_type == 2
    assert device.endpoint is not None
    assert device.endpoint.host == "192.0.2.44"


def test_ezviz_lan_live_view_params_match_player_lan_shape() -> None:
    endpoint = HcNetSdkLanEndpoint(
        serial="CAM123",
        host="192.0.2.10",
        net_host="203.0.113.10",
        command_port=9010,
        net_command_port=8010,
        stream_port=9020,
        net_stream_port=9030,
    )

    params = ezviz_lan_live_view_params(
        endpoint,
        channel_number=2,
        channel_serial="CAM123-CH2",
        channel_index="2",
        channel_count=4,
        netsdk_login_id=42,
    )

    assert params.channel_serial == "CAM123-CH2"
    assert params.channel_index == "2"
    assert params.channel_count == 4
    assert params.preplay_sps_type == EZVIZ_PREPLAY_SPS_TYPE
    assert params.stream_source == EZVIZ_STREAM_SOURCE_LIVE_MINE
    assert params.stream_inhibit == EZVIZ_STREAM_INHIBIT_LAN
    assert params.stream_timeout_ms == EZVIZ_STREAM_TIMEOUT_MS
    assert params.stream_type == 1
    assert params.video_level == EZVIZ_LAN_MAIN_VIDEO_LEVEL
    assert params.device_ip == "203.0.113.10"
    assert params.device_local_ip == "192.0.2.10"
    assert params.device_cmd_port == 8010
    assert params.device_cmd_local_port == 9010
    assert params.device_stream_local_port == 9020
    assert params.device_stream_port == 9030
    assert params.netsdk_login_id == 42
    assert params.netsdk_channel_number == 2
    assert params.to_init_param_dict() == {
        "szDevSerial": "CAM123",
        "szChnlSerial": "CAM123-CH2",
        "szChnlIndex": "2",
        "szDevIP": "203.0.113.10",
        "szDevLocalIP": "192.0.2.10",
        "iDevCmdPort": 8010,
        "iDevCmdLocalPort": 9010,
        "iDevStreamPort": 9030,
        "iDevStreamLocalPort": 9020,
        "iChannelCount": 4,
        "iP2PSPS": EZVIZ_PREPLAY_SPS_TYPE,
        "iStreamInhibit": EZVIZ_STREAM_INHIBIT_LAN,
        "iStreamSource": EZVIZ_STREAM_SOURCE_LIVE_MINE,
        "iStreamType": 1,
        "iStreamTimeOut": EZVIZ_STREAM_TIMEOUT_MS,
        "iVideoLevel": 0,
        "iChannelNumber": 2,
        "iNetSDKUserId": 42,
        "iNetSDKChannelNumber": 2,
    }


def test_ezviz_lan_preview_plan_matches_native_call_sequence() -> None:
    endpoint = HcNetSdkLanEndpoint(
        serial="CAM123",
        host="192.0.2.10",
        command_port=9010,
        stream_port=9020,
    )

    plan = ezviz_lan_preview_plan(
        endpoint,
        "ABCDEF",
        channel_number=1,
        stream_type=1,
        netsdk_login_id=7,
    )

    assert plan.login_candidates[0].api == "NET_DVR_Login_V40"
    assert plan.login_candidates[0].port == HCNETSDK_DEFAULT_TLS_PORT
    assert plan.login_candidates[1].port == 9010
    assert plan.live_view.to_init_param_dict()["iNetSDKUserId"] == 7
    assert plan.post_start_keyframe_api == HCNETSDK_MAKE_KEYFRAME_MAIN
    assert plan.post_start_keyframe_request is not None
    assert plan.post_start_keyframe_request.api == HCNETSDK_MAKE_KEYFRAME_MAIN
    assert plan.post_start_keyframe_request.netsdk_login_id == 7
    assert plan.post_start_keyframe_request.netsdk_channel_number == 1
    assert plan.real_play_request is not None
    assert plan.real_play_request.to_native_args_hint()["login_id"] == 7
    assert plan.real_play_request.client_info.to_native_dict()["lChannel"] == 1
    assert plan.play_device_login is not None
    assert plan.play_device_login.api == EZVIZ_DEVICE_INFO_EX_LOGIN_PLAY_DEVICE
    assert plan.native_call_sequence() == (
        EZVIZ_DEVICE_INFO_EX_LOGIN_PLAY_DEVICE,
        "NativeApi.createClient",
        "NativeApi.startPreview",
        HCNETSDK_MAKE_KEYFRAME_MAIN,
    )


def test_ezviz_lan_complete_playback_path_models_app_flow() -> None:
    endpoint = HcNetSdkLanEndpoint(
        serial="CS-CV310-A0-1B2WFR0120200927CCRRTEST123456",
        host="192.0.2.10",
        command_port=8000,
        stream_port=0,
    )

    path = ezviz_lan_complete_playback_path(
        endpoint,
        "ABCDEF",
        settings_login_id=0,
        play_device_login_id=7,
        analog_channel_count=1,
        digital_channel_count=0,
        analog_start_channel=1,
        digital_start_channel=33,
        stream_type=EZVIZ_LAN_MAIN_STREAM_TYPE,
    )

    assert path.settings_login_candidates[0].api == "NET_DVR_Login_V40"
    assert path.settings_login_candidates[0].https is True
    assert path.settings_login_candidates[1].port == 8000
    assert path.settings_login_id == 0
    assert path.channel_number == 1
    assert path.playback_intent.to_extra_dict() == {
        EZVIZ_PLAYER_EXTRA_DEVICE_ID: "CS-CV310-A0-1B2WFR0120200927CCRRTEST123456",
        EZVIZ_PLAYER_EXTRA_CHANNEL_NO: 1,
        EZVIZ_PLAYER_EXTRA_LAN_FLAG: EZVIZ_PLAYER_LAN_FLAG_HCNETSDK,
        EZVIZ_PLAYER_EXTRA_LAN_USERID: -1,
        EZVIZ_PLAYER_EXTRA_WIFI_SSID: "",
    }
    assert path.play_device_login_id == 7
    assert path.live_view.to_init_param_dict()["iNetSDKUserId"] == 7
    assert path.live_view.to_init_param_dict()["iNetSDKChannelNumber"] == 1
    assert path.post_start_keyframe_request is not None
    assert path.post_start_keyframe_request.api == HCNETSDK_MAKE_KEYFRAME_MAIN
    assert path.call_sequence() == (
        EZVIZ_HCNETUTIL_LOGIN_V40,
        EZVIZ_LAN_ACTIVITY_CHANNEL_HANDOFF,
        EZVIZ_PREVIEW_BACK_START_LAN_VIDEO_PLAY,
        EZVIZ_DEVICE_INFO_EX_LOGIN_PLAY_DEVICE,
        "NativeApi.createClient",
        "NativeApi.startPreview",
        HCNETSDK_MAKE_KEYFRAME_MAIN,
    )


def test_ezviz_lan_complete_playback_path_requires_play_device_login() -> None:
    endpoint = HcNetSdkLanEndpoint(serial="CAM123", host="192.0.2.10")

    with pytest.raises(PyEzvizError, match="play-device login"):
        ezviz_lan_complete_playback_path(
            endpoint,
            "ABCDEF",
            settings_login_id=0,
            play_device_login_id=-1,
            analog_channel_count=1,
            digital_channel_count=0,
            analog_start_channel=1,
            digital_start_channel=33,
        )


def test_ezviz_lan_preview_plan_forwards_channel_identity() -> None:
    endpoint = HcNetSdkLanEndpoint(serial="CAM123", host="192.0.2.10")

    plan = ezviz_lan_preview_plan(
        endpoint,
        "ABCDEF",
        channel_number=3,
        channel_serial="CAM123-CH3",
        channel_index="3",
        channel_count=4,
    )

    init_param = plan.live_view.to_init_param_dict()
    assert init_param["szChnlSerial"] == "CAM123-CH3"
    assert init_param["szChnlIndex"] == "3"
    assert init_param["iChannelCount"] == 4
    assert init_param["iP2PSPS"] == EZVIZ_PREPLAY_SPS_TYPE


def test_ezviz_lan_video_qualities_match_lan_item_holder() -> None:
    qualities = ezviz_lan_video_qualities()

    assert qualities[0].stream_type == EZVIZ_LAN_MAIN_STREAM_TYPE
    assert qualities[0].video_level == EZVIZ_LAN_MAIN_VIDEO_LEVEL
    assert qualities[0].native_video_level == 0
    assert qualities[1].stream_type == EZVIZ_LAN_SUB_STREAM_TYPE
    assert qualities[1].video_level == EZVIZ_LAN_SUB_VIDEO_LEVEL
    assert qualities[1].native_video_level == 2


def test_ezviz_native_video_level_matches_player_conversion() -> None:
    assert ezviz_native_video_level(-1) == 3
    assert ezviz_native_video_level(0) == 2
    assert ezviz_native_video_level(1) == 1
    assert ezviz_native_video_level(2) == 0
    assert ezviz_native_video_level(3) == 4
    assert ezviz_native_video_level(4) == 5


def test_ezviz_lan_preview_plan_uses_sub_keyframe_for_sub_stream() -> None:
    endpoint = HcNetSdkLanEndpoint(serial="CAM123", host="192.0.2.10")

    plan = ezviz_lan_preview_plan(
        endpoint,
        "ABCDEF",
        stream_type=2,
        netsdk_login_id=7,
    )

    assert plan.post_start_keyframe_api == HCNETSDK_MAKE_KEYFRAME_SUB
    assert plan.post_start_keyframe_request is not None
    assert plan.post_start_keyframe_request.netsdk_login_id == 7
    assert plan.post_start_keyframe_request.netsdk_channel_number == 1
    assert plan.live_view.video_level == EZVIZ_LAN_SUB_VIDEO_LEVEL
    assert plan.live_view.to_init_param_dict()["iVideoLevel"] == 2


def test_ezviz_lan_preview_plan_allows_explicit_video_level() -> None:
    endpoint = HcNetSdkLanEndpoint(serial="CAM123", host="192.0.2.10")

    plan = ezviz_lan_preview_plan(
        endpoint,
        "ABCDEF",
        stream_type=2,
        video_level=3,
    )

    assert plan.live_view.video_level == 3
    assert plan.live_view.to_init_param_dict()["iVideoLevel"] == 4


def test_ezviz_lan_preview_plan_skips_keyframe_without_login_id() -> None:
    endpoint = HcNetSdkLanEndpoint(serial="CAM123", host="192.0.2.10")

    plan = ezviz_lan_preview_plan(endpoint, "ABCDEF")

    assert plan.post_start_keyframe_api is None
    assert plan.real_play_request is None
    assert plan.native_call_sequence() == (
        EZVIZ_DEVICE_INFO_EX_LOGIN_PLAY_DEVICE,
        "NativeApi.createClient",
        "NativeApi.startPreview",
    )


class _FragmentedSocket:
    def __init__(self, chunks: list[bytes]) -> None:
        self._buffer = b"".join(chunks)

    def recv(self, length: int) -> bytes:
        chunk = self._buffer[:length]
        self._buffer = self._buffer[length:]
        return chunk


class _FakeSocket(_FragmentedSocket):
    def __init__(self, chunks: list[bytes]) -> None:
        super().__init__(chunks)
        self.sent: list[bytes] = []
        self.closed = False

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def close(self) -> None:
        self.closed = True
