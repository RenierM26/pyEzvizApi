"""playback protocol values and pure helpers; dependency-closed implementation."""

from __future__ import annotations

from pyezvizapi.streaming.local.hcnetsdk.constants import (
    EZVIZ_HCNETUTIL_LOGIN_V40,
    EZVIZ_LAN_ACTIVITY_CHANNEL_HANDOFF,
    EZVIZ_NATIVE_CREATE_CLIENT,
    EZVIZ_NATIVE_START_PREVIEW,
    EZVIZ_PLAYER_EXTRA_CHANNEL_NO,
    EZVIZ_PLAYER_EXTRA_DEVICE_ID,
    EZVIZ_PLAYER_EXTRA_LAN_FLAG,
    EZVIZ_PLAYER_EXTRA_LAN_USERID,
    EZVIZ_PLAYER_EXTRA_WIFI_SSID,
    EZVIZ_PLAYER_LAN_FLAG_HCNETSDK,
    EZVIZ_PREVIEW_BACK_START_LAN_VIDEO_PLAY,
    HCNETSDK_FILECOND_FIELD_ORDER,
    HCNETSDK_FIND_CLOSE_V30,
    HCNETSDK_FIND_FILE_FAILED,
    HCNETSDK_FIND_FILE_V30,
    HCNETSDK_FIND_NEXT_FILE_V30,
    HCNETSDK_FINDDATA_V30_FIELD_ORDER,
    HCNETSDK_GET_DOWNLOAD_POS,
    HCNETSDK_GET_FILE_BY_NAME,
    HCNETSDK_GET_FILE_BY_TIME,
    HCNETSDK_GET_FILE_FAILED,
    HCNETSDK_PLAYBACK_BY_TIME_V40,
    HCNETSDK_PLAYBACK_CAPTURE_FILE,
    HCNETSDK_PLAYBACK_CONTROL_V40,
    HCNETSDK_PLAYBACK_FAILED,
    HCNETSDK_PLAYBACK_FILE_TYPE_ALL,
    HCNETSDK_PLAYBACK_LOCK_STATE_ALL,
    HCNETSDK_PLAYCOND_FIELD_ORDER,
    HCNETSDK_SECRET_KEY_TYPE_AES,
    HCNETSDK_SET_CONNECT_TIME,
    HCNETSDK_SET_PLAYBACK_ES_CALLBACK,
    HCNETSDK_SET_PLAYBACK_RESPONSE_CALLBACK,
    HCNETSDK_SET_PLAYBACK_SECRET_KEY,
    HCNETSDK_STOP_GET_FILE,
    HCNETSDK_STOP_PLAYBACK,
    HCNETSDK_TIME_FIELD_ORDER,
    Any,
    PyEzvizError,
    dataclass,
    date,
    datetime,
)
from pyezvizapi.streaming.local.hcnetsdk.protocol_types.endpoints import (
    HcNetSdkLoginCandidate,
)
from pyezvizapi.streaming.local.hcnetsdk.protocol_types.preview import (
    EzvizLanKeyframeRequest,
    EzvizLanLiveViewParams,
    EzvizLanPlayDeviceLogin,
    EzvizLanPreviewPlan,
)
from pyezvizapi.streaming.local.hcnetsdk.protocol_types.values import (
    _bounded_bytes,
    _byte_value,
    _native_path_value,
    _native_secret_key_bytes,
    _nul_stripped_text,
    _optional_native_bytes,
)


@dataclass(frozen=True)
class EzvizLanPlaybackConvertResolution:
    """One playback conversion resolution entry from ``RecordAbility`` XML."""

    index: int
    frame_rates: tuple[int, ...] = ()
    bitrates: tuple[int, ...] = ()


@dataclass(frozen=True)
class EzvizLanPlaybackIntent:
    """Intent extras used to hand a LAN HCNetSDK login to the player UI."""

    serial: str
    channel_number: int
    lan_user_id: int = -1
    ssid: str = ""
    lan_flag: int = EZVIZ_PLAYER_LAN_FLAG_HCNETSDK

    def to_extra_dict(self) -> dict[str, int | str]:
        """Return the exact extras written by startLanVideoPlay(...)."""
        return {
            EZVIZ_PLAYER_EXTRA_DEVICE_ID: self.serial,
            EZVIZ_PLAYER_EXTRA_CHANNEL_NO: self.channel_number,
            EZVIZ_PLAYER_EXTRA_LAN_FLAG: self.lan_flag,
            EZVIZ_PLAYER_EXTRA_LAN_USERID: self.lan_user_id,
            EZVIZ_PLAYER_EXTRA_WIFI_SSID: self.ssid,
        }


@dataclass(frozen=True)
class EzvizLanPlaybackPath:
    """Complete LAN Live View path observed in the EZVIZ Android app."""

    settings_login_candidates: tuple[HcNetSdkLoginCandidate, ...]
    settings_login_id: int
    channel_number: int
    playback_intent: EzvizLanPlaybackIntent
    play_device_login: EzvizLanPlayDeviceLogin
    play_device_login_id: int
    live_view: EzvizLanLiveViewParams
    create_client_api: str = EZVIZ_NATIVE_CREATE_CLIENT
    start_preview_api: str = EZVIZ_NATIVE_START_PREVIEW

    @property
    def post_start_keyframe_request(self) -> EzvizLanKeyframeRequest | None:
        """Return the keyframe request made after native preview starts."""
        return EzvizLanPreviewPlan(
            login_candidates=self.settings_login_candidates,
            live_view=self.live_view,
            play_device_login=self.play_device_login,
            create_client_api=self.create_client_api,
            start_preview_api=self.start_preview_api,
        ).post_start_keyframe_request

    def call_sequence(self) -> tuple[str, ...]:
        """Return the app-level calls needed for a complete LAN playback start."""
        calls = [
            EZVIZ_HCNETUTIL_LOGIN_V40,
            EZVIZ_LAN_ACTIVITY_CHANNEL_HANDOFF,
            EZVIZ_PREVIEW_BACK_START_LAN_VIDEO_PLAY,
            self.play_device_login.api,
            self.create_client_api,
            self.start_preview_api,
        ]
        if self.post_start_keyframe_request is not None:
            calls.append(self.post_start_keyframe_request.api)
        return tuple(calls)


@dataclass(frozen=True)
class HcNetSdkSetConnectTimeRequest:
    """Native ``NET_DVR_SetConnectTime`` call shape used by the APK."""

    connect_time_ms: int = 5000
    retry_count: int = 3
    api: str = HCNETSDK_SET_CONNECT_TIME

    def to_native_args_hint(self) -> dict[str, Any]:
        """Return native argument names for setting SDK connect timeout."""
        if self.connect_time_ms < 0:
            raise PyEzvizError("HCNetSDK connect time must be non-negative")
        if self.retry_count < 0:
            raise PyEzvizError("HCNetSDK connect retry count must be non-negative")
        if self.api != HCNETSDK_SET_CONNECT_TIME:
            raise PyEzvizError("HCNetSDK connect-time API is unsupported")
        return {
            "api": self.api,
            "dwWaitTime": self.connect_time_ms,
            "dwTryTimes": self.retry_count,
        }


@dataclass(frozen=True)
class HcNetSdkTime:
    """Native ``NET_DVR_TIME`` field set."""

    year: int
    month: int
    day: int
    hour: int = 0
    minute: int = 0
    second: int = 0

    @classmethod
    def from_datetime(cls, value: datetime) -> HcNetSdkTime:
        """Build a native time from a Python ``datetime``."""
        return cls(
            year=value.year,
            month=value.month,
            day=value.day,
            hour=value.hour,
            minute=value.minute,
            second=value.second,
        )

    @classmethod
    def from_date(cls, value: date, *, end_of_day: bool = False) -> HcNetSdkTime:
        """Build a native day boundary from a Python ``date``."""
        return cls(
            year=value.year,
            month=value.month,
            day=value.day,
            hour=23 if end_of_day else 0,
            minute=59 if end_of_day else 0,
            second=59 if end_of_day else 0,
        )

    def to_native_dict(self) -> dict[str, Any]:
        """Return the Java ``NET_DVR_TIME`` field names and values."""
        if self.year < 0:
            raise PyEzvizError("HCNetSDK time year must be non-negative")
        if not 1 <= self.month <= 12:
            raise PyEzvizError("HCNetSDK time month must be between 1 and 12")
        if not 1 <= self.day <= 31:
            raise PyEzvizError("HCNetSDK time day must be between 1 and 31")
        if not 0 <= self.hour <= 23:
            raise PyEzvizError("HCNetSDK time hour must be between 0 and 23")
        if not 0 <= self.minute <= 59:
            raise PyEzvizError("HCNetSDK time minute must be between 0 and 59")
        if not 0 <= self.second <= 59:
            raise PyEzvizError("HCNetSDK time second must be between 0 and 59")
        return {
            "structure": "NET_DVR_TIME",
            "fieldOrder": HCNETSDK_TIME_FIELD_ORDER,
            "dwYear": self.year,
            "dwMonth": self.month,
            "dwDay": self.day,
            "dwHour": self.hour,
            "dwMinute": self.minute,
            "dwSecond": self.second,
        }


@dataclass(frozen=True)
class HcNetSdkFileCond:
    """Native ``NET_DVR_FILECOND`` search condition used by LAN playback."""

    channel: int
    start_time: HcNetSdkTime
    stop_time: HcNetSdkTime
    file_type: int = HCNETSDK_PLAYBACK_FILE_TYPE_ALL
    is_locked: int = HCNETSDK_PLAYBACK_LOCK_STATE_ALL
    use_card_no: int = 0
    card_number: str | bytes = b""

    def to_native_dict(self, *, include_buffers: bool = False) -> dict[str, Any]:
        """Return the Java ``NET_DVR_FILECOND`` field shape."""
        if self.channel < 0:
            raise PyEzvizError("HCNetSDK file search channel must be non-negative")
        if self.file_type < 0:
            raise PyEzvizError("HCNetSDK file search file type must be non-negative")
        if self.is_locked < 0:
            raise PyEzvizError("HCNetSDK file search lock state must be non-negative")
        if self.use_card_no < 0:
            raise PyEzvizError("HCNetSDK file search card flag must be non-negative")
        card_number = _bounded_bytes(
            "HCNetSDK file search card number",
            self.card_number,
            32,
        )
        return {
            "structure": "NET_DVR_FILECOND",
            "fieldOrder": HCNETSDK_FILECOND_FIELD_ORDER,
            "lChannel": self.channel,
            "dwFileType": self.file_type,
            "dwIsLocked": self.is_locked,
            "dwUseCardNo": self.use_card_no,
            "sCardNumber": (card_number if include_buffers else _nul_stripped_text(card_number)),
            "sCardNumberBufferSize": 32,
            "struStartTime": self.start_time.to_native_dict(),
            "struStopTime": self.stop_time.to_native_dict(),
        }


@dataclass(frozen=True)
class HcNetSdkFindFileRequest:
    """Native ``NET_DVR_FindFile_V30`` call shape."""

    login_id: int
    file_cond: HcNetSdkFileCond
    api: str = HCNETSDK_FIND_FILE_V30

    def to_native_args_hint(
        self,
        *,
        include_buffers: bool = False,
    ) -> dict[str, Any]:
        """Return native argument names for starting playback file search."""
        if self.login_id < 0:
            raise PyEzvizError("HCNetSDK file search requires a successful login id")
        if self.api != HCNETSDK_FIND_FILE_V30:
            raise PyEzvizError("HCNetSDK find-file API is unsupported")
        return {
            "api": self.api,
            "lUserID": self.login_id,
            "lpFindCond": self.file_cond.to_native_dict(include_buffers=include_buffers),
            "failureHandle": HCNETSDK_FIND_FILE_FAILED,
        }


@dataclass(frozen=True)
class HcNetSdkFindDataV30:
    """Native ``NET_DVR_FINDDATA_V30`` output-buffer shape."""

    file_name: str | bytes = b""
    start_time: HcNetSdkTime | None = None
    stop_time: HcNetSdkTime | None = None
    file_size: int = 0
    card_number: str | bytes = b""
    locked: int = 0
    file_type: int = 0

    def to_native_dict(self, *, include_buffers: bool = False) -> dict[str, Any]:
        """Return the Java ``NET_DVR_FINDDATA_V30`` field shape."""
        if self.file_size < 0:
            raise PyEzvizError("HCNetSDK find data file size must be non-negative")
        file_name = _bounded_bytes(
            "HCNetSDK find data file name",
            self.file_name,
            100,
        )
        card_number = _bounded_bytes(
            "HCNetSDK find data card number",
            self.card_number,
            32,
        )
        return {
            "structure": "NET_DVR_FINDDATA_V30",
            "fieldOrder": HCNETSDK_FINDDATA_V30_FIELD_ORDER,
            "sFileName": (file_name if include_buffers else _nul_stripped_text(file_name)),
            "sFileNameBufferSize": 100,
            "struStartTime": (self.start_time or HcNetSdkTime(0, 1, 1)).to_native_dict(),
            "struStopTime": (self.stop_time or HcNetSdkTime(0, 1, 1)).to_native_dict(),
            "dwFileSize": self.file_size,
            "sCardNum": (card_number if include_buffers else _nul_stripped_text(card_number)),
            "sCardNumBufferSize": 32,
            "byLocked": _byte_value("find data locked", self.locked),
            "byFileType": _byte_value("find data file type", self.file_type),
            "byResLength": 2,
        }


@dataclass(frozen=True)
class HcNetSdkFindNextFileRequest:
    """Native ``NET_DVR_FindNextFile_V30`` call shape."""

    find_handle: int
    find_data: HcNetSdkFindDataV30 | None = None
    api: str = HCNETSDK_FIND_NEXT_FILE_V30

    def to_native_args_hint(
        self,
        *,
        include_buffers: bool = False,
    ) -> dict[str, Any]:
        """Return native argument names for polling playback file search."""
        if self.find_handle < 0:
            raise PyEzvizError("HCNetSDK find handle must be non-negative")
        if self.api != HCNETSDK_FIND_NEXT_FILE_V30:
            raise PyEzvizError("HCNetSDK find-next-file API is unsupported")
        find_data = self.find_data or HcNetSdkFindDataV30()
        return {
            "api": self.api,
            "lFindHandle": self.find_handle,
            "lpFindData": find_data.to_native_dict(include_buffers=include_buffers),
        }


@dataclass(frozen=True)
class HcNetSdkFindCloseRequest:
    """Native ``NET_DVR_FindClose_V30`` call shape."""

    find_handle: int
    api: str = HCNETSDK_FIND_CLOSE_V30

    def to_native_args_hint(self) -> dict[str, Any]:
        """Return native argument names for closing a playback file search."""
        if self.find_handle < 0:
            raise PyEzvizError("HCNetSDK find handle must be non-negative")
        if self.api != HCNETSDK_FIND_CLOSE_V30:
            raise PyEzvizError("HCNetSDK find-close API is unsupported")
        return {
            "api": self.api,
            "lFindHandle": self.find_handle,
        }


@dataclass(frozen=True)
class HcNetSdkPlayCond:
    """Native ``NET_DVR_PLAYCOND`` time-playback condition."""

    channel: int
    start_time: HcNetSdkTime
    stop_time: HcNetSdkTime
    draw_frame: int = 0
    stream_type: int = 0
    stream_id: str | bytes = b""

    def to_native_dict(self, *, include_buffers: bool = False) -> dict[str, Any]:
        """Return the Java ``NET_DVR_PLAYCOND`` field shape."""
        if self.channel < 0:
            raise PyEzvizError("HCNetSDK playback channel must be non-negative")
        stream_id = _bounded_bytes(
            "HCNetSDK playback stream id",
            self.stream_id,
            32,
        )
        return {
            "structure": "NET_DVR_PLAYCOND",
            "fieldOrder": HCNETSDK_PLAYCOND_FIELD_ORDER,
            "dwChannel": self.channel,
            "struStartTime": self.start_time.to_native_dict(),
            "struStopTime": self.stop_time.to_native_dict(),
            "byDrawFrame": _byte_value("playback draw-frame flag", self.draw_frame),
            "byStreamType": _byte_value("playback stream type", self.stream_type),
            "byStreamID": (stream_id if include_buffers else _nul_stripped_text(stream_id)),
            "byStreamIDBufferSize": 32,
            "byResLength": 30,
        }


@dataclass(frozen=True)
class HcNetSdkPlayBackByTimeRequest:
    """Native ``NET_DVR_PlayBackByTime_V40`` call shape."""

    login_id: int
    play_cond: HcNetSdkPlayCond
    api: str = HCNETSDK_PLAYBACK_BY_TIME_V40

    def to_native_args_hint(
        self,
        *,
        include_buffers: bool = False,
    ) -> dict[str, Any]:
        """Return native argument names for time-based playback start."""
        if self.login_id < 0:
            raise PyEzvizError("HCNetSDK playback requires a successful login id")
        if self.api != HCNETSDK_PLAYBACK_BY_TIME_V40:
            raise PyEzvizError("HCNetSDK playback-by-time API is unsupported")
        return {
            "api": self.api,
            "lUserID": self.login_id,
            "lpPlayCond": self.play_cond.to_native_dict(include_buffers=include_buffers),
            "failureHandle": HCNETSDK_PLAYBACK_FAILED,
        }


@dataclass(frozen=True)
class HcNetSdkPlayBackControlRequest:
    """Native ``NET_DVR_PlayBackControl_V40`` call shape."""

    play_handle: int
    command: int
    in_buffer: str | bytes | None = None
    out_buffer_size: int = 0
    api: str = HCNETSDK_PLAYBACK_CONTROL_V40

    def to_native_args_hint(
        self,
        *,
        include_buffers: bool = False,
    ) -> dict[str, Any]:
        """Return native argument names for playback control."""
        if self.play_handle < 0:
            raise PyEzvizError("HCNetSDK playback handle must be non-negative")
        if self.command < 0:
            raise PyEzvizError("HCNetSDK playback control command must be non-negative")
        if self.out_buffer_size < 0:
            raise PyEzvizError("HCNetSDK playback output size must be non-negative")
        if self.api != HCNETSDK_PLAYBACK_CONTROL_V40:
            raise PyEzvizError("HCNetSDK playback-control API is unsupported")
        in_buffer = _optional_native_bytes(
            "HCNetSDK playback control input buffer",
            self.in_buffer,
        )
        return {
            "api": self.api,
            "lPlayHandle": self.play_handle,
            "dwControlCode": int(self.command),
            "lpInBuffer": (
                in_buffer
                if include_buffers and in_buffer
                else ("<input-buffer>" if in_buffer else None)
            ),
            "dwInLen": len(in_buffer),
            "lpOutBuffer": "<output-buffer>" if self.out_buffer_size else None,
            "dwOutLen": self.out_buffer_size,
            "lpOutLen": "<DWORD_PTR>" if self.out_buffer_size else None,
        }


@dataclass(frozen=True)
class HcNetSdkStopPlayBackRequest:
    """Native ``NET_DVR_StopPlayBack`` call shape."""

    play_handle: int
    api: str = HCNETSDK_STOP_PLAYBACK

    def to_native_args_hint(self) -> dict[str, Any]:
        """Return native argument names for stopping playback."""
        if self.play_handle < 0:
            raise PyEzvizError("HCNetSDK playback handle must be non-negative")
        if self.api != HCNETSDK_STOP_PLAYBACK:
            raise PyEzvizError("HCNetSDK stop-playback API is unsupported")
        return {
            "api": self.api,
            "lPlayHandle": self.play_handle,
        }


@dataclass(frozen=True)
class HcNetSdkPlayBackCaptureFileRequest:
    """Native ``NET_DVR_PlayBackCaptureFile`` call shape."""

    play_handle: int
    saved_file_name: str | bytes
    api: str = HCNETSDK_PLAYBACK_CAPTURE_FILE

    def to_native_args_hint(
        self,
        *,
        include_buffers: bool = False,
    ) -> dict[str, Any]:
        """Return native argument names for a playback snapshot."""
        if self.play_handle < 0:
            raise PyEzvizError("HCNetSDK playback handle must be non-negative")
        if self.api != HCNETSDK_PLAYBACK_CAPTURE_FILE:
            raise PyEzvizError("HCNetSDK playback-capture API is unsupported")
        return {
            "api": self.api,
            "lPlayHandle": self.play_handle,
            "sFileName": _native_path_value(
                "playback capture file name",
                self.saved_file_name,
                include_buffers=include_buffers,
            ),
        }


@dataclass(frozen=True)
class HcNetSdkPlaybackCallbackRequest:
    """Native playback response / elementary-stream callback setter shape."""

    play_handle: int
    callback: str | None = None
    user_data: str | int | None = None
    api: str = HCNETSDK_SET_PLAYBACK_RESPONSE_CALLBACK

    def to_native_args_hint(self) -> dict[str, Any]:
        """Return native argument names for playback callback registration."""
        if self.play_handle < 0:
            raise PyEzvizError("HCNetSDK playback handle must be non-negative")
        callback_names = {
            HCNETSDK_SET_PLAYBACK_RESPONSE_CALLBACK: (
                "fPlaybackResponseCallBack",
                "<PlaybackResponseCallBack>",
            ),
            HCNETSDK_SET_PLAYBACK_ES_CALLBACK: (
                "fPlayBackESCallBack",
                "<PlayBackESCallBack>",
            ),
        }
        if self.api not in callback_names:
            raise PyEzvizError("HCNetSDK playback callback API is unsupported")
        arg_name, placeholder = callback_names[self.api]
        return {
            "api": self.api,
            "lPlayHandle": self.play_handle,
            arg_name: self.callback or placeholder,
            "pUser": self.user_data if self.user_data is not None else None,
        }


@dataclass(frozen=True)
class HcNetSdkPlayBackSecretKeyRequest:
    """Native ``NET_DVR_SetPlayBackSecretKey`` call shape."""

    play_handle: int
    secret_key: str | bytes
    secret_key_type: int = HCNETSDK_SECRET_KEY_TYPE_AES
    api: str = HCNETSDK_SET_PLAYBACK_SECRET_KEY

    def to_native_args_hint(
        self,
        *,
        include_secret: bool = False,
    ) -> dict[str, Any]:
        """Return native argument names for setting a playback stream key."""
        if self.play_handle < 0:
            raise PyEzvizError("HCNetSDK playback handle must be non-negative")
        if self.secret_key_type < 0:
            raise PyEzvizError("HCNetSDK playback secret-key type must be non-negative")
        if self.api != HCNETSDK_SET_PLAYBACK_SECRET_KEY:
            raise PyEzvizError("HCNetSDK playback secret-key API is unsupported")
        secret_key = _native_secret_key_bytes(
            "HCNetSDK playback secret key",
            self.secret_key,
        )
        return {
            "api": self.api,
            "lPlayHandle": self.play_handle,
            "dwSecretKeyType": self.secret_key_type,
            "pSecretKey": secret_key if include_secret else "<secret-key>",
            "dwSecretKeyLen": len(secret_key),
        }


@dataclass(frozen=True)
class HcNetSdkGetFileByNameRequest:
    """Native ``NET_DVR_GetFileByName`` download-start call shape."""

    login_id: int
    dvr_file_name: str | bytes
    saved_file_name: str | bytes
    api: str = HCNETSDK_GET_FILE_BY_NAME

    def to_native_args_hint(
        self,
        *,
        include_buffers: bool = False,
    ) -> dict[str, Any]:
        """Return native argument names for file-name based download."""
        if self.login_id < 0:
            raise PyEzvizError("HCNetSDK file download requires a successful login id")
        if self.api != HCNETSDK_GET_FILE_BY_NAME:
            raise PyEzvizError("HCNetSDK get-file-by-name API is unsupported")
        return {
            "api": self.api,
            "lUserID": self.login_id,
            "sDVRFileName": _native_path_value(
                "DVR file name",
                self.dvr_file_name,
                include_buffers=include_buffers,
            ),
            "sSavedFileName": _native_path_value(
                "saved file name",
                self.saved_file_name,
                include_buffers=include_buffers,
            ),
            "failureHandle": HCNETSDK_GET_FILE_FAILED,
        }


@dataclass(frozen=True)
class HcNetSdkGetFileByTimeRequest:
    """Native ``NET_DVR_GetFileByTime`` download-start call shape."""

    login_id: int
    channel: int
    start_time: HcNetSdkTime
    stop_time: HcNetSdkTime
    saved_file_name: str | bytes
    api: str = HCNETSDK_GET_FILE_BY_TIME

    def to_native_args_hint(
        self,
        *,
        include_buffers: bool = False,
    ) -> dict[str, Any]:
        """Return native argument names for time-based download."""
        if self.login_id < 0:
            raise PyEzvizError("HCNetSDK file download requires a successful login id")
        if self.channel < 0:
            raise PyEzvizError("HCNetSDK file download channel must be non-negative")
        if self.api != HCNETSDK_GET_FILE_BY_TIME:
            raise PyEzvizError("HCNetSDK get-file-by-time API is unsupported")
        return {
            "api": self.api,
            "lUserID": self.login_id,
            "lChannel": self.channel,
            "lpStartTime": self.start_time.to_native_dict(),
            "lpStopTime": self.stop_time.to_native_dict(),
            "sSavedFileName": _native_path_value(
                "saved file name",
                self.saved_file_name,
                include_buffers=include_buffers,
            ),
            "failureHandle": HCNETSDK_GET_FILE_FAILED,
        }


@dataclass(frozen=True)
class HcNetSdkStopGetFileRequest:
    """Native ``NET_DVR_StopGetFile`` call shape."""

    file_handle: int
    api: str = HCNETSDK_STOP_GET_FILE

    def to_native_args_hint(self) -> dict[str, Any]:
        """Return native argument names for stopping a file download."""
        if self.file_handle < 0:
            raise PyEzvizError("HCNetSDK file handle must be non-negative")
        if self.api != HCNETSDK_STOP_GET_FILE:
            raise PyEzvizError("HCNetSDK stop-get-file API is unsupported")
        return {
            "api": self.api,
            "lFileHandle": self.file_handle,
        }


@dataclass(frozen=True)
class HcNetSdkGetDownloadPosRequest:
    """Native ``NET_DVR_GetDownloadPos`` call shape."""

    file_handle: int
    api: str = HCNETSDK_GET_DOWNLOAD_POS

    def to_native_args_hint(self) -> dict[str, Any]:
        """Return native argument names for polling download progress."""
        if self.file_handle < 0:
            raise PyEzvizError("HCNetSDK file handle must be non-negative")
        if self.api != HCNETSDK_GET_DOWNLOAD_POS:
            raise PyEzvizError("HCNetSDK get-download-position API is unsupported")
        return {
            "api": self.api,
            "lFileHandle": self.file_handle,
        }
