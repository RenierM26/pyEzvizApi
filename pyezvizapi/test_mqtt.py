"""MQTT test module.

Run a simple MQTT listener using either a saved token file
(`--token-file ezviz_token.json`) or by prompting for username/password
with MFA similar to the main CLI.
"""

from __future__ import annotations

import argparse
from getpass import getpass
import json
import logging
from pathlib import Path
import sys
import time
from typing import Any, cast

from ._token_store import save_private_token
from .client import EzvizClient
from .exceptions import EzvizAuthVerificationCode, PyEzvizError

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
_LOGGER = logging.getLogger(__name__)

LOG_FILE = Path("mqtt_messages.jsonl")  # JSON Lines format


def message_handler(msg: dict[str, Any]) -> None:
    """Handle new MQTT messages by printing and saving them to a file."""
    _LOGGER.info("📩 New MQTT message: %s", msg)
    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(msg, ensure_ascii=False) + "\n")


def _load_token_file(path: str | None) -> dict[str, Any] | None:
    if not path:
        return None
    p = Path(path)
    if not p.exists():
        return None
    try:
        return cast(dict[str, Any], json.loads(p.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError):
        _LOGGER.warning("Failed to read token file: %s", p)
        return None


def _save_token_file(path: str | None, token: dict[str, Any]) -> None:
    if not path:
        raise ValueError("Channel-99 requires a token-file path")
    save_private_token(path, token)


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    """Parse standalone listener arguments."""
    parser = argparse.ArgumentParser(prog="test_mqtt")
    parser.add_argument("-u", "--username", required=False, help="Ezviz username")
    parser.add_argument("-p", "--password", required=False, help="Ezviz password")
    parser.add_argument(
        "-r",
        "--region",
        required=False,
        default="apiieu.ezvizlife.com",
        help="Ezviz API region",
    )
    parser.add_argument(
        "--token-file",
        type=str,
        default="ezviz_token.json",
        help="Path to JSON token file (default: ezviz_token.json)",
    )
    parser.add_argument(
        "--save-token",
        action="store_true",
        help="Compatibility flag: tokens are now always saved for channel-99",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Entry point for testing MQTT messages."""
    args = _parse_args(argv)
    token = _load_token_file(args.token_file)

    username = args.username
    password = args.password

    # If no token and missing username/password, prompt interactively
    if (not token or token.get("push_profile") != "android-channel99") and (not username or not password):
        _LOGGER.info("No token found. Please enter Ezviz credentials")
        username = username or input("Username: ")
        password = password or getpass("Password: ")

    client = None
    mqtt_client = None
    shutdown_failed = False
    try:
        client = EzvizClient(
            username, password, args.region, token=token,
            on_token_updated=lambda snapshot: _save_token_file(args.token_file, snapshot),
        )
        try:
            client.enable_channel99()
        except EzvizAuthVerificationCode:
            mfa_code = input("MFA code required, please input MFA code.\n")
            try:
                code_int = int(mfa_code.strip())
            except ValueError:
                code_int = None
            client.enable_channel99(sms_code=code_int)

        mqtt_client = client.get_mqtt_client(on_message_callback=message_handler)
        mqtt_client.connect()
        _LOGGER.info("Listening for MQTT messages... (Ctrl+C to quit)")
        while True:
            mqtt_client.raise_if_failed()
            time.sleep(1)
    except (PyEzvizError, OSError) as error:
        _LOGGER.error("Listener failed: %s", error)
        return 1
    except KeyboardInterrupt:
        _LOGGER.info("Stopping listener (keyboard interrupt)")
    finally:
        try:
            if mqtt_client is not None:
                mqtt_client.stop()
        except TimeoutError:
            shutdown_failed = True
            _LOGGER.error("Push shutdown timed out; cancellation remains signalled")
        finally:
            if client is not None:
                client.close_session()
        _LOGGER.info("Listener stopped")

    return 1 if shutdown_failed else 0


if __name__ == "__main__":
    sys.exit(main())
