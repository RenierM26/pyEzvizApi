"""pyezvizapi CAS API Functions."""

from __future__ import annotations

from dataclasses import dataclass
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
from urllib3.util.ssl_match_hostname import CertificateError, match_hostname
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
CAS_TLS_CIPHERS = (
    "DEFAULT:!aNULL:!eNULL:!MD5:!3DES:!DES:!RC4:!IDEA:!SEED:!aDSS:!SRP:!PSK"
)

CAS_CERT_SUBJECT_ALT_NAME_OID = "2.5.29.17"
CAS_CERT_COMMON_NAME_OID = "2.5.4.3"


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


def _cas_tls_context(*, verify_certificate: bool = False) -> ssl.SSLContext:
    """Return the legacy TLS context accepted by the CAS cloud endpoint."""
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers(CAS_TLS_CIPHERS)
    if not verify_certificate:
        # EZVIZ app clients tolerate expired CAS WebPKI certificates. Python's
        # SSL layer cannot ignore only expiry, so use a scoped relaxed context
        # and verify the peer certificate hostname manually after the handshake.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def _read_der_tlv(data: bytes, offset: int = 0) -> tuple[int, bytes, int]:
    """Read one definite-length DER TLV item."""
    if offset >= len(data):
        raise ValueError("DER item is truncated")
    tag = data[offset]
    offset += 1
    if offset >= len(data):
        raise ValueError("DER length is truncated")
    first_length = data[offset]
    offset += 1
    if first_length & 0x80:
        length_size = first_length & 0x7F
        if length_size == 0:
            raise ValueError("DER indefinite lengths are not supported")
        if offset + length_size > len(data):
            raise ValueError("DER long-form length is truncated")
        length = int.from_bytes(data[offset : offset + length_size], "big")
        offset += length_size
    else:
        length = first_length
    end = offset + length
    if end > len(data):
        raise ValueError("DER value is truncated")
    return tag, data[offset:end], end


def _iter_der(data: bytes) -> list[tuple[int, bytes]]:
    """Return all DER TLV children from a constructed value."""
    children: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(data):
        tag, value, offset = _read_der_tlv(data, offset)
        children.append((tag, value))
    return children


def _decode_der_oid(value: bytes) -> str:
    """Decode a DER object identifier."""
    if not value:
        raise ValueError("DER object identifier is empty")
    subidentifiers: list[int] = []
    current = 0
    for byte in value:
        current = (current << 7) | (byte & 0x7F)
        if not byte & 0x80:
            subidentifiers.append(current)
            current = 0
    if current or value[-1] & 0x80:
        raise ValueError("DER object identifier is truncated")
    first = subidentifiers[0]
    if first < 40:
        parts = [0, first]
    elif first < 80:
        parts = [1, first - 40]
    else:
        parts = [2, first - 80]
    parts.extend(subidentifiers[1:])
    return ".".join(str(part) for part in parts)


def _decode_der_string(tag: int, value: bytes) -> str | None:
    """Decode common X.509 name string encodings."""
    if tag in {0x12, 0x13, 0x16}:
        return value.decode("ascii", errors="strict")
    if tag == 0x0C:
        return value.decode("utf-8", errors="strict")
    if tag == 0x14:
        return value.decode("latin1", errors="strict")
    if tag == 0x1E:
        return value.decode("utf-16-be", errors="strict")
    if tag == 0x1C:
        return value.decode("utf-32-be", errors="strict")
    return None


@dataclass(frozen=True)
class _CertificateNames:
    dns_names: tuple[str, ...]
    ip_addresses: tuple[str, ...]
    common_names: tuple[str, ...]


def _cas_certificate_names(cert_der: bytes) -> _CertificateNames:
    """Extract X.509 DNS/IP subjectAltName values and CN fallback names."""
    cert_tag, cert_value, cert_end = _read_der_tlv(cert_der)
    if cert_tag != 0x30 or cert_end != len(cert_der):
        raise ValueError("CAS TLS peer certificate is not a DER sequence")
    tbs_tag, tbs_value, _ = _read_der_tlv(cert_value)
    if tbs_tag != 0x30:
        raise ValueError("CAS TLS peer certificate has no TBSCertificate sequence")

    tbs_fields = _iter_der(tbs_value)
    field_index = 1 if tbs_fields and tbs_fields[0][0] == 0xA0 else 0
    if len(tbs_fields) < field_index + 6:
        raise ValueError("CAS TLS peer certificate TBSCertificate is incomplete")

    subject = tbs_fields[field_index + 4][1]
    common_names = _x509_common_names(subject)
    dns_names: list[str] = []
    ip_addresses: list[str] = []
    for tag, value in tbs_fields[field_index + 6 :]:
        if tag != 0xA3:
            continue
        dns_names, ip_addresses = _x509_subject_alt_names(value)
        break
    return _CertificateNames(
        dns_names=tuple(dns_names),
        ip_addresses=tuple(ip_addresses),
        common_names=tuple(common_names),
    )


def _x509_common_names(subject: bytes) -> list[str]:
    """Return subject commonName values from an X.509 Name."""
    common_names: list[str] = []
    for rdn_tag, rdn_value in _iter_der(subject):
        if rdn_tag != 0x31:
            continue
        for attr_tag, attr_value in _iter_der(rdn_value):
            if attr_tag != 0x30:
                continue
            attr_offset = 0
            oid_tag, oid_value, attr_offset = _read_der_tlv(attr_value, attr_offset)
            if oid_tag != 0x06 or _decode_der_oid(oid_value) != CAS_CERT_COMMON_NAME_OID:
                continue
            value_tag, value, _ = _read_der_tlv(attr_value, attr_offset)
            decoded = _decode_der_string(value_tag, value)
            if decoded:
                common_names.append(decoded)
    return common_names


def _x509_subject_alt_names(extension_wrapper: bytes) -> tuple[list[str], list[str]]:
    """Return DNS and IP SAN values from an X.509 extensions wrapper."""
    extensions_tag, extensions_value, extensions_end = _read_der_tlv(extension_wrapper)
    if extensions_tag != 0x30 or extensions_end != len(extension_wrapper):
        return [], []
    for extension_tag, extension_value in _iter_der(extensions_value):
        if extension_tag != 0x30:
            continue
        fields = _iter_der(extension_value)
        if len(fields) < 2 or fields[0][0] != 0x06:
            continue
        if _decode_der_oid(fields[0][1]) != CAS_CERT_SUBJECT_ALT_NAME_OID:
            continue
        value_fields = fields[2:] if len(fields) > 2 and fields[1][0] == 0x01 else fields[1:]
        if not value_fields or value_fields[0][0] != 0x04:
            continue
        names_tag, names_value, names_end = _read_der_tlv(value_fields[0][1])
        if names_tag != 0x30 or names_end != len(value_fields[0][1]):
            continue
        dns_names: list[str] = []
        ip_addresses: list[str] = []
        for name_tag, name_value in _iter_der(names_value):
            if name_tag == 0x82:
                dns_names.append(name_value.decode("ascii", errors="strict"))
            elif name_tag == 0x87:
                ip_addresses.append(str(ipaddress.ip_address(name_value)))
        return dns_names, ip_addresses
    return [], []


def _verify_cas_certificate_hostname(sock: ssl.SSLSocket, *, host: str) -> None:
    """Verify the CAS peer certificate names against the selected host."""
    cert = sock.getpeercert(binary_form=True)
    if not cert:
        raise PyEzvizError("CAS TLS peer did not present a certificate")
    try:
        names = _cas_certificate_names(cert)
    except ValueError as err:
        raise PyEzvizError("Could not parse CAS TLS peer certificate") from err

    decoded_cert: dict[str, Any] = {
        "subjectAltName": tuple(
            [("DNS", dns_name) for dns_name in names.dns_names]
            + [("IP Address", ip_address) for ip_address in names.ip_addresses]
        ),
        "subject": tuple((("commonName", common_name),) for common_name in names.common_names),
    }
    try:
        match_hostname(cast(Any, decoded_cert), host, hostname_checks_common_name=True)
    except (CertificateError, ValueError) as err:
        raise PyEzvizError(f"CAS TLS certificate hostname mismatch for {host}") from err


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
) -> bytes:
    """Build the observed get-operation-code CAS request."""
    body = (
        b'<?xml version="1.0" encoding="utf-8"?>\n<Request>\n\t'
        + (
            f"<ClientID>{session_id}</ClientID>"
            f"\n\t<Sign>{hardware_code}</Sign>\n\t"
            f"<DevSerial>{devserial}</DevSerial>"
            f"\n\t<ClientType>0</ClientType>\n</Request>\n"
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
            f'ToDevice="{serial}" ClientType="0" />\n\t'
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
        verify_tls_certificate: bool = False,
    ) -> None:
        """Initialize the client object."""
        self._session = None
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
    ) -> CasTransportResult:
        """Send raw CAS bytes over either the cloud TLS or experimental LAN path."""
        sock: Any | None = None
        try:
            sock = socket.create_connection((host, port))
            if hasattr(sock, "settimeout"):
                sock.settimeout(CAS_SOCKET_TIMEOUT)
            if use_tls:
                sock = _cas_tls_context(
                    verify_certificate=self._verify_tls_certificate
                ).wrap_socket(sock, server_hostname=host)
                if not self._verify_tls_certificate:
                    _verify_cas_certificate_hostname(sock, host=host)
                if hasattr(sock, "settimeout"):
                    sock.settimeout(CAS_SOCKET_TIMEOUT)

            _send_all(sock, payload)
            response_bytes = sock.recv(recv_size)
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
            ),
            host=host,
            port=port,
            use_tls=True,
        )
        response_bytes = result.response
        _LOGGER.debug("Get Encryption Key: %r", response_bytes)

        # Trim header, digest and convert xml to dict.
        body = response_bytes[CAS_FRAME_HEADER_SIZE:-CAS_RESPONSE_DIGEST_SIZE]
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
            ),
            host=host,
            port=port,
            use_tls=False,
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
            ),
            host=host,
            port=port,
            use_tls=True,
        )
        _LOGGER.debug("Set camera response: %r", result.response)

        return True
