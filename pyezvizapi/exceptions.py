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
    """A bounded preview completed without any media packets."""

    reason = "no_media"


class EzvizIncompleteMediaError(PyEzvizError):
    """A timed capture had too little video timestamp coverage."""

    reason = "incomplete_media"

    def __init__(
        self,
        *,
        source: str,
        requested_duration_seconds: float,
        observed_pts_span_seconds: float,
    ) -> None:
        self.source = source
        self.requested_duration_seconds = requested_duration_seconds
        self.observed_pts_span_seconds = observed_pts_span_seconds
        super().__init__(
            f"{source} video is incomplete: PES timestamp span "
            f"{observed_pts_span_seconds:.2f}s of {requested_duration_seconds:.2f}s requested"
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


class EzvizAuthVerificationCode(PyEzvizError):
    """Raised when a login or action requires an MFA (verification) code."""


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
