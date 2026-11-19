"""Custom exceptions raised by the Ezviz Cloud API wrapper."""


class PyEzvizError(Exception):
    """Base exception for all Ezviz API related errors."""


class UnsupportedRtpVideoCodecError(PyEzvizError):
    """Raised when IDMX metadata identifies an unsupported RTP video codec."""


class EzvizUnsupportedMediaError(PyEzvizError):
    """Authenticated stream data is not a media format this source can decode.

    ``reason`` is stable for callers deciding whether to try another stream
    source; the message remains suitable for CLI diagnostics.
    """

    def __init__(self, message: str, *, source: str, reason: str) -> None:
        super().__init__(message)
        self.source = source
        self.reason = reason


class EzvizNoMediaError(PyEzvizError):
    """A bounded preview completed without usable media."""

    reason = "no_media"


class EzvizIncompleteMediaError(PyEzvizError):
    """A timed capture had too little video timestamp coverage."""

    reason = "incomplete_media"

    def __init__(
        self,
        *,
        source: str,
        requested_duration_seconds: float,
        observed_pts_span_seconds: float | None = None,
        observed_video_duration_seconds: float | None = None,
    ) -> None:
        self.source = source
        self.requested_duration_seconds = requested_duration_seconds
        self.observed_pts_span_seconds = observed_pts_span_seconds
        self.observed_video_duration_seconds = observed_video_duration_seconds
        if observed_video_duration_seconds is not None:
            observed_text = f"video duration {observed_video_duration_seconds:.2f}s"
        elif observed_pts_span_seconds is not None:
            observed_text = f"PES timestamp span {observed_pts_span_seconds:.2f}s"
        else:
            raise ValueError("An observed media duration or PTS span is required")
        super().__init__(
            f"{source} video is incomplete: {observed_text} "
            f"of {requested_duration_seconds:.2f}s requested"
        )


class InvalidURL(PyEzvizError):
    """Raised when a request fails due to an invalid URL or proxy settings."""


class HTTPError(PyEzvizError):
    """Raised when a non-success HTTP status code is returned by the API."""


class InvalidHost(PyEzvizError):
    """Raised when a hostname/IP is invalid or a TCP connection fails."""


class AuthTestResultFailed(PyEzvizError):
    """Raised by RTSP auth test helpers if credentials are invalid."""


class EzvizAuthTokenExpired(PyEzvizError):
    """Raised when a stored session token is no longer valid (expired/revoked)."""


class EzvizLoginError(PyEzvizError):
    """Actionable login failure; no raw response or contact information is retained.

    ``reason`` is stable for callers. ``code`` is the raw cloud meta.code, not
    Android's code + 100000. Recovery is caller-owned; never blindly retry.
    """

    def __init__(
        self,
        message: str,
        *,
        reason: str,
        code: int | None = None,
        lock_minutes: int | None = None,
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.code = code
        self.lock_minutes = lock_minutes


class EzvizAuthVerificationCode(EzvizLoginError):
    """Login needs a code. Existing catches/zero-argument construction still work.

    ``code_sent`` only confirms a successful request, not actual delivery.
    ``available_channels`` lists reported SMS (1)/email (3) contacts, not policy.
    """

    def __init__(
        self,
        message: str = "MFA verification required",
        *,
        reason: str = "verification_required",
        code: int | None = None,
        code_sent: bool = False,
        available_channels: tuple[int, ...] = (),
    ) -> None:
        super().__init__(message, reason=reason, code=code)
        self.code_sent = code_sent
        self.available_channels = available_channels


class DeviceException(PyEzvizError):
    """Raised when the physical device reports network or operational issues."""


class EzvizLocalSdkDeadlineExpired(DeviceException):
    """Raised when a bounded local SDK frame read reaches its total deadline."""


class EzvizLocalSdkStreamClosed(DeviceException):
    """Raised when a local SDK socket closes mid-frame."""


class EzvizPushFatalError(PyEzvizError):
    """Push stopped and requires caller intervention before a new client is started."""


class EzvizTokenPersistenceError(EzvizPushFatalError):
    """Rotating push credentials could not be saved durably."""


class EzvizPlaybackNegotiationError(PyEzvizError):
    """Relay refused SD playback; the numeric result does not identify its cause.

    No automatic retry is implied, including for the observed result 6520.
    No credential-bearing URL or response payload is retained.
    """

    reason = "playback_negotiation_failed"
    source = "cloud-playback"

    def __init__(self, result_code: int) -> None:
        self.result_code = result_code
        super().__init__(f"SD playback negotiation failed with result {result_code}")
