"""pyezvizapi CAS API Functions."""

from __future__ import annotations

from dataclasses import dataclass
import datetime as dt
from io import BytesIO
import ipaddress
from itertools import cycle
import logging
import random
import socket
import ssl
import struct
from typing import Any, cast
from xml.parsers.expat import ExpatError

from Crypto.Cipher import AES
from cryptography import x509
import xmltodict

from .constants import FEATURE_CODE, XOR_KEY
from .exceptions import InvalidHost, PyEzvizError

_LOGGER = logging.getLogger(__name__)

CAS_FRAME_MAGIC = b"\x9e\xba\xac\xe9"
CAS_FRAME_HEADER_SIZE = 32
CAS_RESPONSE_DIGEST_SIZE = 32
CAS_RANDOM_TRAILER_SIZE = 64
CAS_OPERATION_CODE_RANDOM_TRAILER_SIZE = 32
CAS_SOCKET_TIMEOUT = 10.0

CAS_VERSION_MARKER = b"\x01\x00\x00\x00"
CAS_COMMAND_GET_OPERATION_CODE = 0x2001
CAS_COMMAND_VERIFY = 0x2005
CAS_COMMAND_DEVICE_MESSAGE = 0x300F
CAS_ANDROID_CLIENT_TYPE = 3
CAS_TLS_CIPHERS = (
    "DEFAULT:!aNULL:!eNULL:!MD5:!3DES:!DES:!RC4:!IDEA:!SEED:!aDSS:!SRP:!PSK"
)
CAS_CERT_HAS_EXPIRED_VERIFY_CODE = 10


@dataclass(frozen=True)
class CasFrameHeader:
    """Observed CAS frame header.

    CAS uses the same 32 byte envelope size as the cloud replay code, but the
    version marker is byte-swapped compared with that path. Keep it as raw bytes
    until more captures explain the first word definitively.
    """

    version_marker: bytes
    sequence: int
    reserved: int
    command: int
    flags: int
    body_size_hint: int
    tail_size_hint: int

    @classmethod
    def parse(cls, payload: bytes) -> CasFrameHeader:
        """Parse the first CAS frame header from payload bytes."""
        if len(payload) < CAS_FRAME_HEADER_SIZE:
            raise ValueError("CAS frame is shorter than the 32 byte header")
        if payload[:4] != CAS_FRAME_MAGIC:
            raise ValueError("Invalid CAS frame magic")
        sequence, reserved, command, flags, body_size_hint, tail_size_hint = (
            struct.unpack(">IIIIII", payload[8:CAS_FRAME_HEADER_SIZE])
        )
        return cls(
            version_marker=payload[4:8],
            sequence=sequence,
            reserved=reserved,
            command=command,
            flags=flags,
            body_size_hint=body_size_hint,
            tail_size_hint=tail_size_hint,
        )


def _cas_frame_header(
    *,
    sequence: int,
    command: int,
    body_size_hint: int,
    flags: int = 0,
    tail_size_hint: int = 0,
) -> bytes:
    """Build the observed CAS header without hiding still-unknown fields."""
    return (
        CAS_FRAME_MAGIC
        + CAS_VERSION_MARKER
        + struct.pack(
            ">IIIIII",
            sequence,
            0,
            command,
            flags,
            body_size_hint,
            tail_size_hint,
        )
    )


def _random_hex_trailer(size: int = CAS_RANDOM_TRAILER_SIZE) -> bytes:
    """Return the random ASCII hex trailer sent after CAS requests."""
    rand_hex_str = f"{random.randrange(10**80):064x}"[:size]
    return rand_hex_str.encode("latin1")


def _cas_tls_context(*, verify_certificate: bool = True) -> ssl.SSLContext:
    """Return the legacy TLS context accepted by the CAS cloud endpoint."""
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers(CAS_TLS_CIPHERS)
    if not verify_certificate:
        # EZVIZ app clients tolerate expired CAS WebPKI certificates. Python's
        # SSL layer cannot ignore only expiry, so this context is used only after
        # a normal verified handshake has failed specifically for expiry.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def _is_certificate_expired_error(err: ssl.SSLCertVerificationError) -> bool:
    """Return True when OpenSSL rejected the peer only for expiry."""
    verify_code = getattr(err, "verify_code", None)
    if verify_code == CAS_CERT_HAS_EXPIRED_VERIFY_CODE:
        return True
    verify_message = str(getattr(err, "verify_message", "") or err)
    return "certificate has expired" in verify_message.lower()


def _certificate_not_valid_after(cert: x509.Certificate) -> dt.datetime:
    """Return the certificate notAfter timestamp as timezone-aware UTC."""
    not_valid_after_utc = getattr(cert, "not_valid_after_utc", None)
    if isinstance(not_valid_after_utc, dt.datetime):
        return not_valid_after_utc
    return cert.not_valid_after.replace(tzinfo=dt.UTC)


def _normalize_dns_name(host: str) -> str:
    """Return an ASCII DNS name suitable for certificate matching."""
    return host.rstrip(".").encode("idna").decode("ascii").lower()


def _dns_name_matches(pattern: str, host: str) -> bool:
    """Return True when a certificate DNS SAN matches a host."""
    pattern = _normalize_dns_name(pattern)
    host = _normalize_dns_name(host)
    if "*" not in pattern:
        return pattern == host
    if pattern.count("*") != 1 or not pattern.startswith("*."):
        return False
    suffix = pattern[1:]
    return host.endswith(suffix) and host.count(".") == pattern.count(".")


def _certificate_matches_host(cert: x509.Certificate, host: str) -> bool:
    """Return True when the certificate SAN matches the requested host."""
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    try:
        host_ip = ipaddress.ip_address(host)
    except ValueError:
        host_ip = None
    if host_ip is not None:
        return any(
            ip_address == host_ip for ip_address in san.get_values_for_type(x509.IPAddress)
        )
    return any(
        _dns_name_matches(dns_name, host)
        for dns_name in san.get_values_for_type(x509.DNSName)
    )


def _verify_expired_cas_certificate_hostname(sock: ssl.SSLSocket, *, host: str) -> None:
    """Verify the expired CAS peer certificate is issued for the requested host."""
    cert_der = sock.getpeercert(binary_form=True)
    if not cert_der:
        raise PyEzvizError("CAS TLS peer did not present a certificate")

    try:
        cert = x509.load_der_x509_certificate(cert_der)
        if _certificate_not_valid_after(cert) >= dt.datetime.now(dt.UTC):
            raise PyEzvizError(
                "CAS TLS expiry fallback received a non-expired certificate"
            )
        if not _certificate_matches_host(cert, host):
            raise ssl.CertificateError("CAS TLS certificate hostname mismatch")
    except PyEzvizError:
        raise
    except (UnicodeError, ssl.CertificateError, ValueError, x509.ExtensionNotFound) as err:
        raise PyEzvizError(
            f"CAS TLS certificate is not valid for {host}"
        ) from err


def _send_all(sock: Any, payload: bytes) -> None:
    """Send the complete CAS frame over socket-like transports."""
    sendall = getattr(sock, "sendall", None)
    if callable(sendall):
        sendall(payload)
        return

    sent = 0
    while sent < len(payload):
        count = sock.send(payload[sent:])
        if count <= 0:
            raise PyEzvizError("Socket closed before CAS frame was sent")
        sent += count


def _recv_exact(sock: Any, size: int) -> bytes:
    """Read exactly size bytes from a socket-like transport."""
    chunks: list[bytes] = []
    remaining = size
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise PyEzvizError("Socket closed before CAS response was complete")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _recv_cas_frame(sock: Any) -> bytes:
    """Read one complete framed CAS response."""
    header_bytes = _recv_exact(sock, CAS_FRAME_HEADER_SIZE)
    try:
        header = CasFrameHeader.parse(header_bytes)
    except ValueError as err:
        raise PyEzvizError("CAS response frame header is invalid") from err
    tail_size = header.tail_size_hint or CAS_RESPONSE_DIGEST_SIZE
    return header_bytes + _recv_exact(sock, header.body_size_hint + tail_size)


def _cas_response_body(response_bytes: bytes, *, context: str) -> bytes:
    """Return the body declared by a CAS response frame header."""
    try:
        header = CasFrameHeader.parse(response_bytes)
    except ValueError as err:
        raise PyEzvizError(f"CAS {context} response frame header is invalid") from err
    body_start = CAS_FRAME_HEADER_SIZE
    body_end = body_start + header.body_size_hint
    body = response_bytes[body_start:body_end]
    if len(body) != header.body_size_hint:
        raise PyEzvizError(f"CAS {context} response frame body is incomplete")
    return body


def xor_enc_dec(msg: bytes, xor_key: bytes = XOR_KEY) -> bytes:
    """XOR encode/decode bytes with the given key."""
    with BytesIO(msg) as stream:
        return bytes(a ^ b for a, b in zip(stream.read(), cycle(xor_key)))


@dataclass(frozen=True)
class CasDeviceSession:
    """Per-device CAS credentials returned by getDevOperationCodeEx."""

    key: str
    operation_code: str
    encrypt_type: int | None = None

    @classmethod
    def from_response(cls, response: dict[str, Any]) -> CasDeviceSession:
        """Build a session from the XML response dict returned by CAS."""
        response_body = response.get("Response")
        if not isinstance(response_body, dict):
            raise PyEzvizError("CAS get-encryption response is missing Response")
        session = response_body.get("Session")
        if not isinstance(session, dict):
            result = response_body.get("Result")
            limit = response_body.get("Limit")
            details = []
            if result is not None:
                details.append(f"Result={result}")
            if limit is not None:
                details.append(f"Limit={limit}")
            suffix = f" ({', '.join(details)})" if details else ""
            raise PyEzvizError(
                "CAS get-encryption response is missing Session" + suffix
            )
        encrypt_type_raw = session.get("@EncryptType") or session.get("@encryptType")
        if encrypt_type_raw is not None:
            encrypt_type = int(encrypt_type_raw)
        elif session.get("@Algorithm") == "AES128":
            encrypt_type = 1
        else:
            encrypt_type = None
        return cls(
            key=cast(str, session["@Key"]),
            operation_code=cast(str, session["@OperationCode"]),
            encrypt_type=encrypt_type,
        )


@dataclass(frozen=True)
class CasTransportResult:
    """Raw response from one CAS transport attempt."""

    host: str
    port: int
    used_tls: bool
    response: bytes


def _build_operation_code_request(
    *,
    session_id: str | None,
    devserial: str,
    hardware_code: str = FEATURE_CODE,
    client_type: int = CAS_ANDROID_CLIENT_TYPE,
) -> bytes:
    """Build the observed get-operation-code CAS request."""
    body = (
        b'<?xml version="1.0" encoding="utf-8"?>\n<Request>\n\t'
        + (
            f"<ClientID>{session_id}</ClientID>"
            f"\n\t<Sign>{hardware_code}</Sign>\n\t"
            f"<DevSerial>{devserial}</DevSerial>"
            f"\n\t<ClientType>{client_type}</ClientType>\n</Request>\n"
        ).encode("latin1")
    )
    return (
        _cas_frame_header(
            sequence=5,
            command=CAS_COMMAND_GET_OPERATION_CODE,
            body_size_hint=len(body),
        )
        + body
        + _random_hex_trailer(CAS_OPERATION_CODE_RANDOM_TRAILER_SIZE)
    )


def _build_defence_plaintext(
    *,
    serial: str,
    operation_code: str,
    enable: int,
) -> bytes:
    """Build the encrypted inner devDefence XML body."""
    xor_cam_serial = xor_enc_dec(serial.encode("latin1"))
    return (
        f'{xor_cam_serial.decode()}2+,*xdv.0" '
        f'encoding="utf-8"?>\n'
        f"<Request>\n"
        f"\t<OperationCode>{operation_code}</OperationCode>\n"
        f'\t<Defence Type="Global" Status="{enable}" Actor="V" Channel="0" />\n'
        f"</Request>\n"
        f"\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"
    ).encode("latin1")


def _build_defence_request(
    *,
    session_id: str | None,
    serial: str,
    device_session: CasDeviceSession,
    enable: int,
    client_type: int = CAS_ANDROID_CLIENT_TYPE,
) -> bytes:
    """Build the observed devDefence CAS request."""
    payload = (
        _cas_frame_header(
            sequence=0x14,
            command=CAS_COMMAND_VERIFY,
            body_size_hint=0x02D0,
            tail_size_hint=0x01E0,
        )
        + b'<?xml version="1.0" encoding="utf-8"?>\n<Request>\n\t'
        + (
            f'<Verify ClientSession="{session_id}" '
            f'ToDevice="{serial}" ClientType="{client_type}" />\n\t'
            f'<Message Length="240" />\n</Request>\n'
        ).encode("latin1")
        + _cas_frame_header(
            sequence=0x13,
            command=CAS_COMMAND_DEVICE_MESSAGE,
            flags=0xFFFFFFFF,
            body_size_hint=0xB0,
        )
    )

    cipher = AES.new(
        device_session.key.encode("latin1"),
        AES.MODE_CBC,
        f"{serial}{device_session.operation_code}".encode("latin1"),
    )
    return (
        payload
        + cipher.encrypt(
            _build_defence_plaintext(
                serial=serial,
                operation_code=device_session.operation_code,
                enable=enable,
            )
        )
        + _random_hex_trailer()
    )


class EzvizCAS:
    """Ezviz CAS server client."""

    def __init__(
        self,
        token: dict[str, Any] | None,
        *,
        client_type: int = CAS_ANDROID_CLIENT_TYPE,
        verify_tls_certificate: bool = False,
    ) -> None:
        """Initialize the client object."""
        self._session = None
        self._client_type = client_type
        self._verify_tls_certificate = verify_tls_certificate
        self._token: dict[str, Any] = token or {
            "session_id": None,
            "rf_session_id": None,
            "username": None,
            "api_url": "apiieu.ezvizlife.com",
        }
        if not token or "service_urls" not in token:
            raise PyEzvizError(
                "Missing service_urls in token; call EzvizClient.login() first"
            )
        self._service_urls: dict[str, Any] = token["service_urls"]

    def _cloud_address(self) -> tuple[str, int]:
        """Return the configured CAS cloud endpoint."""
        host = cast(str, self._service_urls["sysConf"][15])
        port = cast(int, self._service_urls["sysConf"][16])
        return host, port

    def _hardware_code(self) -> str:
        """Return the app-style hardware/feature code used to mint CAS tuples."""
        return cast(
            str,
            self._token.get("hardware_code")
            or self._token.get("feature_code")
            or self._token.get("featureCode")
            or FEATURE_CODE,
        )

    def _send_cas_payload(
        self,
        payload: bytes,
        *,
        host: str,
        port: int,
        use_tls: bool,
        recv_size: int = 1024,
        expect_frame: bool = True,
    ) -> CasTransportResult:
        """Send raw CAS bytes over either the cloud TLS or experimental LAN path."""
        sock: Any | None = None
        try:
            sock = socket.create_connection((host, port))
            if hasattr(sock, "settimeout"):
                sock.settimeout(CAS_SOCKET_TIMEOUT)
            if use_tls:
                try:
                    sock = _cas_tls_context().wrap_socket(
                        sock,
                        server_hostname=host,
                    )
                except ssl.SSLCertVerificationError as err:
                    if self._verify_tls_certificate or not _is_certificate_expired_error(
                        err
                    ):
                        raise
                    sock.close()
                    sock = socket.create_connection((host, port))
                    if hasattr(sock, "settimeout"):
                        sock.settimeout(CAS_SOCKET_TIMEOUT)
                    sock = _cas_tls_context(verify_certificate=False).wrap_socket(
                        sock,
                        server_hostname=host,
                    )
                    _verify_expired_cas_certificate_hostname(sock, host=host)
                if hasattr(sock, "settimeout"):
                    sock.settimeout(CAS_SOCKET_TIMEOUT)

            _send_all(sock, payload)
            response_bytes = (
                _recv_cas_frame(sock) if expect_frame else sock.recv(recv_size)
            )
        except TimeoutError as err:
            raise PyEzvizError("Timed out waiting for CAS response") from err
        except ConnectionResetError as err:
            raise PyEzvizError("CAS transport connection was reset") from err
        except (socket.gaierror, ConnectionRefusedError) as err:
            raise InvalidHost("Invalid IP or Hostname") from err
        except ssl.SSLError as err:
            raise PyEzvizError("CAS TLS handshake failed") from err
        finally:
            if sock is not None:
                sock.close()

        return CasTransportResult(
            host=host,
            port=port,
            used_tls=use_tls,
            response=response_bytes,
        )

    def cas_get_encryption(self, devserial: str) -> dict[str, Any]:
        """Fetch encryption code from EZVIZ CAS server."""
        host, port = self._cloud_address()
        result = self._send_cas_payload(
            _build_operation_code_request(
                session_id=cast(str | None, self._token["session_id"]),
                devserial=devserial,
                hardware_code=self._hardware_code(),
                client_type=self._client_type,
            ),
            host=host,
            port=port,
            use_tls=True,
        )
        response_bytes = result.response
        _LOGGER.debug("Get Encryption Key: %r", response_bytes)

        # Trim the framed header/tail and convert XML to dict.
        body = _cas_response_body(response_bytes, context="get-encryption")
        if not body:
            raise PyEzvizError("CAS get-encryption response did not contain an XML body")
        try:
            doc = xmltodict.parse(body)
        except ExpatError as err:
            raise PyEzvizError("Could not parse CAS get-encryption XML response") from err
        return cast(dict[str, Any], doc)

    def probe_local_operation_code(
        self,
        devserial: str,
        *,
        host: str,
        port: int,
    ) -> CasTransportResult:
        """Probe whether a LAN command port accepts the cloud CAS query frame."""
        return self._send_cas_payload(
            _build_operation_code_request(
                session_id=cast(str | None, self._token["session_id"]),
                devserial=devserial,
                hardware_code=self._hardware_code(),
                client_type=self._client_type,
            ),
            host=host,
            port=port,
            use_tls=False,
            expect_frame=False,
        )

    def set_camera_defence_state(self, serial: str, enable: int = 1) -> bool:
        """Enable alarm notifications."""
        device_session = CasDeviceSession.from_response(self.cas_get_encryption(serial))
        host, port = self._cloud_address()
        result = self._send_cas_payload(
            _build_defence_request(
                session_id=cast(str | None, self._token["session_id"]),
                serial=serial,
                device_session=device_session,
                enable=enable,
                client_type=self._client_type,
            ),
            host=host,
            port=port,
            use_tls=True,
        )
        _LOGGER.debug("Set camera response: %r", result.response)

        return True
