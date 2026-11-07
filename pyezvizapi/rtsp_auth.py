"""Bounded RTSP authentication probe with deterministic socket ownership."""

from __future__ import annotations

import base64
import hashlib
import logging
import re
import socket
import time
from typing import TypedDict

from requests.utils import parse_dict_header

from .exceptions import AuthTestResultFailed, InvalidHost
from .media import is_positive_finite_duration_bound

_LOGGER = logging.getLogger(__name__)
_HEADER_END = b"\r\n\r\n"

__test__ = False


def _decode_response(msg: bytes) -> str:
    """Decode an RTSP reply without failing on non-UTF-8 bytes.

    RTSP headers are ASCII, but some cameras send bytes such as 0xFF
    after them. latin-1 maps every byte to one character, so offsets
    found in the text also index the raw bytes.
    """
    return msg.decode("latin-1")


def _unfold_header_lines(lines: list[str]) -> list[str]:
    """Unfold RTSP/1.0 continuation lines within the bounded header block."""
    fields: list[list[str]] = []
    for line in lines:
        if line.startswith((" ", "\t")):
            if not fields:
                raise AuthTestResultFailed("Invalid RTSP response header continuation")
            fields[-1].append(line.lstrip(" \t"))
        else:
            fields.append([line])
    return [" ".join(parts) for parts in fields]


def genmsg_describe(url: str, seq: int, user_agent: str, auth_seq: str) -> str:
    """Generate RTSP DESCRIBE request message."""
    msg_ret = f"DESCRIBE {url} RTSP/1.0\r\n"
    msg_ret += f"CSeq: {seq}\r\n"
    msg_ret += f"Authorization: {auth_seq}\r\n"
    msg_ret += f"User-Agent: {user_agent}\r\n"
    msg_ret += "Accept: application/sdp\r\n\r\n"
    return msg_ret


class RTSPDetails(TypedDict):
    """Typed structure for RTSP test parameters."""

    bufLen: int
    defaultServerIp: str
    defaultServerPort: int
    defaultTestUri: str
    defaultUserAgent: str
    defaultUsername: str | None
    defaultPassword: str | None


class TestRTSPAuth:
    """Test RTSP credentials against an RTSP server."""

    __test__ = False

    _rtsp_details: RTSPDetails

    def __init__(
        self,
        ip_addr: str,
        username: str | None = None,
        password: str | None = None,
        test_uri: str = "",
        *,
        timeout: float = 25.0,
    ) -> None:
        """Initialize RTSP credential test."""
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not is_positive_finite_duration_bound(timeout):
            raise ValueError("RTSP timeout must be a positive finite number")
        self._timeout = timeout
        self._rtsp_details = RTSPDetails(
            bufLen=1024,
            defaultServerIp=ip_addr,
            defaultServerPort=554,
            defaultTestUri=test_uri,
            defaultUserAgent="RTSP Client",
            defaultUsername=username,
            defaultPassword=password,
        )

    def generate_auth_string(
        self, realm: bytes, method: str, uri: str, nonce: bytes
    ) -> str:
        """Generate the HTTP Digest Authorization header value."""
        # Legacy RTSP Digest requires MD5 on the wire (RFC 2069); this is not
        # password storage and cannot be replaced with a different KDF locally.
        m_1 = hashlib.md5(
            f"{self._rtsp_details['defaultUsername']}:{realm.decode()}:{self._rtsp_details['defaultPassword']}".encode()
        ).hexdigest()
        m_2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
        response = hashlib.md5(f"{m_1}:{nonce.decode()}:{m_2}".encode()).hexdigest()

        return (
            "Digest "
            f'username="{self._rtsp_details["defaultUsername"]}", '
            f'realm="{realm.decode()}", '
            'algorithm="MD5", '
            f'nonce="{nonce.decode()}", '
            f'uri="{uri}", '
            f'response="{response}"'
        )

    @staticmethod
    def _set_remaining_timeout(session: socket.socket, deadline: float) -> None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AuthTestResultFailed("RTSP authentication deadline exceeded")
        session.settimeout(remaining)

    def _read_response(
        self, session: socket.socket, deadline: float, seq: int
    ) -> tuple[int, dict[str, list[str]]]:
        """Read a complete bounded header/body; TCP recv boundaries are not frames."""
        header_limit = 65536
        body_limit = 1024 * 1024
        data = bytearray()
        while _HEADER_END not in data:
            if len(data) >= header_limit:
                raise AuthTestResultFailed("RTSP response headers too large")
            self._set_remaining_timeout(session, deadline)
            chunk = session.recv(min(self._rtsp_details["bufLen"], header_limit - len(data)))
            if not chunk:
                raise AuthTestResultFailed("Incomplete RTSP response headers")
            data.extend(chunk)
        header, body = bytes(data).split(_HEADER_END, 1)
        lines = _decode_response(header).split("\r\n")
        status = re.fullmatch(r"RTSP/1\.0 (\d{3})(?: .*)?", lines[0])
        if status is None:
            raise AuthTestResultFailed("Invalid RTSP response status")
        headers: dict[str, list[str]] = {}
        for line in _unfold_header_lines(lines[1:]):
            key, separator, value = line.partition(":")
            if not separator:
                raise AuthTestResultFailed("Invalid RTSP response header")
            headers.setdefault(key.strip().lower(), []).append(value.strip())
        cseq = headers.get("cseq")
        if cseq is not None and cseq != [str(seq)]:
            raise AuthTestResultFailed("RTSP response CSeq mismatch")
        lengths = headers.get("content-length", ["0"])
        try:
            if len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdigit():
                raise ValueError
            length = int(lengths[0])
        except ValueError as err:
            raise AuthTestResultFailed("Invalid RTSP Content-Length") from err
        if length > body_limit:
            raise AuthTestResultFailed("RTSP response body too large")
        received = len(body)
        while received < length:
            self._set_remaining_timeout(session, deadline)
            chunk = session.recv(min(self._rtsp_details["bufLen"], length - received))
            if not chunk:
                raise AuthTestResultFailed("Incomplete RTSP response body")
            received += len(chunk)
        return int(status[1]), headers

    def main(self) -> None:
        """Try Basic, then the legacy MD5 Digest exchange within one I/O budget.

        This probe does not start media. System hostname resolution is separate
        from socket I/O; use a numeric address if a strict DNS bound is needed.
        """
        deadline = time.monotonic() + self._timeout
        session = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self._set_remaining_timeout(session, deadline)
            try:
                session.connect((self._rtsp_details["defaultServerIp"], self._rtsp_details["defaultServerPort"]))
            except TimeoutError as err:
                raise AuthTestResultFailed("Invalid ip or camera hibernating") from err
            except (socket.gaierror, ConnectionRefusedError) as err:
                raise InvalidHost("Invalid IP or Hostname") from err
            url = "rtsp://" + self._rtsp_details["defaultServerIp"] + self._rtsp_details["defaultTestUri"]
            auth = "Basic " + base64.b64encode(
                f"{self._rtsp_details['defaultUsername']}:{self._rtsp_details['defaultPassword']}".encode("ascii")
            ).decode()
            for seq in (1, 2):
                describe = genmsg_describe(url, seq, self._rtsp_details["defaultUserAgent"], auth)
                self._set_remaining_timeout(session, deadline)
                session.sendall(describe.encode())
                code, headers = self._read_response(session, deadline, seq)
                _LOGGER.debug("RTSP DESCRIBE response: code=%s", code)
                if code == 200:
                    return
                if code != 401:
                    break
                if seq == 2:
                    raise AuthTestResultFailed("Credentials not valid!!")
                challenge = next((value[7:] for value in headers.get("www-authenticate", []) if value.lower().startswith("digest ")), None)
                values = parse_dict_header(challenge) if challenge is not None else {}
                realm, nonce = values.get("realm"), values.get("nonce")
                if realm is None or not nonce:
                    raise AuthTestResultFailed("Invalid RTSP Digest challenge")
                auth = self.generate_auth_string(realm.encode("latin-1"), "DESCRIBE", self._rtsp_details["defaultTestUri"], nonce.encode("latin-1"))
            raise AuthTestResultFailed("RTSP DESCRIBE did not return 200 OK")
        except (TimeoutError, ConnectionError) as err:
            raise AuthTestResultFailed("RTSP authentication I/O failed or timed out") from err
        finally:
            session.close()
