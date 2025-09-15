"""pyezvizapi CAS API Functions."""

from __future__ import annotations

from io import BytesIO
from itertools import cycle
import logging
import random
import socket
import ssl
from typing import Any, cast

from Crypto.Cipher import AES
import xmltodict

from .constants import FEATURE_CODE, XOR_KEY
from .exceptions import InvalidHost, PyEzvizError

_LOGGER = logging.getLogger(__name__)


def xor_enc_dec(msg: bytes, xor_key: bytes = XOR_KEY) -> bytes:
    """XOR encode/decode bytes with the given key."""
    with BytesIO(msg) as stream:
        return bytes(a ^ b for a, b in zip(stream.read(), cycle(xor_key)))


class EzvizCAS:
    """Ezviz CAS server client."""

    def __init__(self, token: dict[str, Any] | None) -> None:
        """Initialize the client object."""
        self._session = None
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

    def cas_get_encryption(self, devserial: str) -> dict[str, Any]:
        """Fetch encryption code from EZVIZ CAS server."""
        # Random hex 64 characters long.
        rand_hex_str = f"{random.randrange(10**80):064x}"[:64]

        payload = (
            f"\x9e\xba\xac\xe9\x01\x00\x00\x00\x00\x00"
            f"\x00\x02"  # Check or order?
            f"\x00\x00\x00\x00\x00\x00 "
            f"\x01"  # Check or order?
            f"\x00\x00\x00\x00\x00\x00\x02\t\x00\x00\x00\x00"
            f'<?xml version="1.0" encoding="utf-8"?>\n<Request>\n\t'
            f"<ClientID>{self._token['session_id']}</ClientID>"
            f"\n\t<Sign>{FEATURE_CODE}</Sign>\n\t"
            f"<DevSerial>{devserial}</DevSerial>"
            f"\n\t<ClientType>0</ClientType>\n</Request>\n"
        ).encode("latin1")

        payload_end_padding = rand_hex_str.encode("latin1")

        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        context.set_ciphers(
            "DEFAULT:!aNULL:!eNULL:!MD5:!3DES:!DES:!RC4:!IDEA:!SEED:!aDSS:!SRP:!PSK"
        )

        # Create a TCP/IP socket
        host = cast(str, self._service_urls["sysConf"][15])
        port = cast(int, self._service_urls["sysConf"][16])
        my_socket = socket.create_connection((host, port))
        my_socket = context.wrap_socket(
            my_socket, server_hostname=self._service_urls["sysConf"][15]
        )

        # Get CAS Encryption Key
        try:
            my_socket.send(payload + payload_end_padding)
            response_bytes = my_socket.recv(1024)
            _LOGGER.debug("Get Encryption Key: %r", response_bytes)
        except (socket.gaierror, ConnectionRefusedError) as err:
            raise InvalidHost("Invalid IP or Hostname") from err
        finally:
            my_socket.close()

        # Trim header, tail and convert xml to dict.
        body = response_bytes[32:-32]
        doc = xmltodict.parse(body)
        return cast(dict[str, Any], doc)

    def set_camera_defence_state(self, serial: str, enable: int = 1) -> bool:
        """Enable alarm notifications."""
        # Random hex 64 characters long.
        rand_hex_str = f"{random.randrange(10**80):064x}"[:64]

        payload = (
            f"\x9e\xba\xac\xe9\x01\x00\x00\x00\x00\x00"
            f"\x00\x14"  # Check or order?
            f"\x00\x00\x00\x00\x00\x00 "
            f"\x05"
            f"\x00\x00\x00\x00\x00\x00\x02\xd0\x00\x00\x01\xe0"
            f'<?xml version="1.0" encoding="utf-8"?>\n<Request>\n\t'
            f'<Verify ClientSession="{self._token["session_id"]}" '
            f'ToDevice="{serial}" ClientType="0" />\n\t'
            f'<Message Length="240" />\n</Request>\n'
            f"\x9e\xba\xac\xe9\x01\x00\x00\x00\x00\x00"
            f"\x00\x13"
            f"\x00\x00\x00\x00\x00\x000\x0f\xff\xff\xff\xff"
            f"\x00\x00\x00\xb0\x00\x00\x00\x00"
        ).encode("latin1")

        payload_end_padding = rand_hex_str.encode("latin1")

        # xor camera serial
        xor_cam_serial = xor_enc_dec(serial.encode("latin1"))

        defence_msg_string = (
            f'{xor_cam_serial.decode()}2+,*xdv.0" '
            f'encoding="utf-8"?>\n'
            f"<Request>\n"
            f"\t<OperationCode>ABCDEFG</OperationCode>\n"
            f'\t<Defence Type="Global" Status="{enable}" Actor="V" Channel="0" />\n'
            f"</Request>\n"
            f"\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"
        ).encode("latin1")

        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        context.set_ciphers(
            "DEFAULT:!aNULL:!eNULL:!MD5:!3DES:!DES:!RC4:!IDEA:!SEED:!aDSS:!SRP:!PSK"
        )

        # Create a TCP/IP socket
        host = cast(str, self._service_urls["sysConf"][15])
        port = cast(int, self._service_urls["sysConf"][16])
        my_socket = socket.create_connection((host, port))
        my_socket = context.wrap_socket(
            my_socket, server_hostname=self._service_urls["sysConf"][15]
        )

        cas_client = self.cas_get_encryption(serial)

        aes_key = cas_client["Response"]["Session"]["@Key"].encode("latin1")
        iv_value = (
            f"{serial}{cas_client['Response']['Session']['@OperationCode']}".encode(
                "latin1"
            )
        )

        # Message encryption
        cipher = AES.new(aes_key, AES.MODE_CBC, iv_value)

        try:
            enc_bytes = cipher.encrypt(defence_msg_string)
            my_socket.send(payload + enc_bytes + payload_end_padding)
            _LOGGER.debug("Set camera response: %r", my_socket.recv())
        except (socket.gaierror, ConnectionRefusedError) as err:
            raise InvalidHost("Invalid IP or Hostname") from err
        finally:
            my_socket.close()

        return True
