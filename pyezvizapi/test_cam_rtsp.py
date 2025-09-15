"""Test camera RTSP authentication."""

from __future__ import annotations

import base64
import hashlib
import socket
from typing import TypedDict

from .exceptions import AuthTestResultFailed, InvalidHost


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

    _rtsp_details: RTSPDetails

    def __init__(
        self,
        ip_addr: str,
        username: str | None = None,
        password: str | None = None,
        test_uri: str = "",
    ) -> None:
        """Initialize RTSP credential test."""
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

    def main(self) -> None:
        """Open RTSP socket, try Basic and then Digest auth for DESCRIBE."""
        session: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            session.connect(
                (
                    self._rtsp_details["defaultServerIp"],
                    self._rtsp_details["defaultServerPort"],
                )
            )
        except TimeoutError as err:
            raise AuthTestResultFailed("Invalid ip or camera hibernating") from err
        except (socket.gaierror, ConnectionRefusedError) as err:
            raise InvalidHost("Invalid IP or Hostname") from err

        seq: int = 1

        url: str = (
            "rtsp://"
            + self._rtsp_details["defaultServerIp"]
            + self._rtsp_details["defaultTestUri"]
        )

        # Basic Authorization header
        auth_b64: bytes = base64.b64encode(
            f"{self._rtsp_details['defaultUsername']}:{self._rtsp_details['defaultPassword']}".encode(
                "ascii"
            )
        )
        auth_seq: str = "Basic " + auth_b64.decode()

        describe = genmsg_describe(
            url, seq, self._rtsp_details["defaultUserAgent"], auth_seq
        )
        print(describe)
        session.send(describe.encode())
        msg1: bytes = session.recv(self._rtsp_details["bufLen"])
        seq += 1

        decoded = msg1.decode()
        if "200 OK" in decoded:
            print(f"Basic auth result: {decoded}")
            print("Basic Auth test passed. Credentials Valid!")
            return

        if "Unauthorized" in decoded:
            # Basic failed, do new DESCRIBE with digest authentication.
            start = decoded.find("realm")
            begin = decoded.find('"', start)
            end = decoded.find('"', begin + 1)
            realm: bytes = msg1[begin + 1 : end]

            start = decoded.find("nonce")
            begin = decoded.find('"', start)
            end = decoded.find('"', begin + 1)
            nonce: bytes = msg1[begin + 1 : end]

            auth_seq = self.generate_auth_string(
                realm, "DESCRIBE", self._rtsp_details["defaultTestUri"], nonce
            )

            describe = genmsg_describe(
                url, seq, self._rtsp_details["defaultUserAgent"], auth_seq
            )
            print(describe)
            session.send(describe.encode())
            msg1 = session.recv(self._rtsp_details["bufLen"])
            decoded = msg1.decode()
            print(f"Digest auth result: {decoded}")

            if "200 OK" in decoded:
                print("Digest Auth test Passed. Credentials Valid!")
                return

            if "401 Unauthorized" in decoded:
                raise AuthTestResultFailed("Credentials not valid!!")

        print("Basic Auth test passed. Credentials Valid!")


# ruff: noqa: T201
