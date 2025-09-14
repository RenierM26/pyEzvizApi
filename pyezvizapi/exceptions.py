"""Custom exceptions raised by the Ezviz Cloud API wrapper."""


class PyEzvizError(Exception):
    """Base exception for all Ezviz API related errors."""


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
