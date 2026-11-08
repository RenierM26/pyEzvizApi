"""preview bootstrap protocol values and pure helpers; dependency-closed implementation."""

from __future__ import annotations

from pyezvizapi.streaming.local.hcnetsdk.constants import (
    EzvizStreamHeader,
    dataclass,
    stream_header_from_preview,
)
from pyezvizapi.streaming.local.hcnetsdk.protocol_types.framing import (
    EzvizInterleavedRtpFrameWithPrefix,
)
from pyezvizapi.streaming.local.hcnetsdk.protocol_types.preview import (
    EzvizLocalSdkExchange,
)
from pyezvizapi.streaming.local.hcnetsdk.protocol_types.sdk_requests import (
    ezviz_local_sdk_iv,
)
from pyezvizapi.streaming.local.hcnetsdk.protocol_types.wire_crypto import (
    _local_sdk_aes_bytes,
)


@dataclass(frozen=True)
class EzvizCasDeviceInfo:
    """CAS device-info tuple used by the EZVIZ native direct-local path.

    APK/native tracing showed CasDeviceInfo.key is copied into EZ_DEV_INFO.szKey
    and ultimately used as the AES-128 key for local SDK control frames. The
    direct-local ``9010/9020`` path uses the app-shaped local SDK SSL-like
    IV for control-frame encryption and appends a 32-byte lowercase MD5 hex
    digest of the ciphertext. ``deviceSerial + operationCode`` remains exposed
    for older CAS helpers and compatibility checks.
    """

    serial: str
    operation_code: str
    key: str
    encrypt_type: int | None = None

    @property
    def key_bytes(self) -> bytes:
        """Return the local-control AES key bytes, validating its size."""
        return _local_sdk_aes_bytes("key", self.key)

    @property
    def iv_bytes(self) -> bytes:
        """Return the local-control AES IV bytes derived from CAS metadata."""
        return ezviz_local_sdk_iv(self.serial, self.operation_code)


@dataclass(frozen=True)
class EzvizLocalSdkStreamBootstrap:
    """Result of the direct-local preview setup sequence."""

    preview: EzvizLocalSdkExchange
    stream_setup: EzvizLocalSdkExchange
    pre_start: EzvizLocalSdkExchange | None = None
    first_media: EzvizInterleavedRtpFrameWithPrefix | None = None

    @property
    def stream_header(self) -> EzvizStreamHeader | None:
        """Return camera-negotiated media fields without session/auth data."""
        return stream_header_from_preview(self.preview.response.body)
