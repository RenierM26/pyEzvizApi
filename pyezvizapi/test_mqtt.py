"""MQTT test module.

Run a simple MQTT listener using either a saved token file
(`--token-file ezviz_token.json`) or by prompting for username/password
with MFA similar to the main CLI.
"""

from __future__ import annotations

import argparse
import base64
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
from .mqtt import MQTTClient

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
_LOGGER = logging.getLogger(__name__)

LOG_FILE = Path("mqtt_messages.jsonl")  # JSON Lines format
RAW_LOG_FILE = Path("mqtt_raw_messages.jsonl")


def message_handler(msg: dict[str, Any]) -> None:
    """Handle new MQTT messages by printing and saving them to a file."""
    _LOGGER.info("📩 New MQTT message: %s", msg)
    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(msg, ensure_ascii=False) + "\n")


def _log_raw_payload(payload: bytes) -> None:
    """Persist the raw MQTT payload to a log file for debugging."""
    entry: dict[str, Any]
    try:
        decoded = payload.decode("utf-8")
        entry = {"encoding": "utf-8", "payload": decoded}
    except UnicodeDecodeError:
        entry = {
            "encoding": "base64",
            "payload": base64.b64encode(payload).decode("ascii"),
        }

    entry["timestamp"] = time.time()
    _LOGGER.info("🧾 Raw MQTT payload (%s): %s", entry["encoding"], entry["payload"])
    with RAW_LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def _enable_raw_logging(mqtt_client: MQTTClient) -> None:
    """Wrap the internal paho-mqtt callback to capture raw payloads."""
    if getattr(mqtt_client, "_raw_logging_enabled", False):
        return
    paho_client = getattr(mqtt_client, "mqtt_client", None)
    if paho_client is None:
        _LOGGER.warning("Unable to enable raw logging: MQTT client not configured yet")
        return

    original_on_message = paho_client.on_message

    def _raw_logging_wrapper(client: Any, userdata: Any, msg: Any) -> None:
        _log_raw_payload(getattr(msg, "payload", b""))
        if original_on_message:
            original_on_message(client, userdata, msg)

    paho_client.on_message = _raw_logging_wrapper
    mqtt_client._raw_logging_enabled = True  # type: ignore[attr-defined]


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


def main(argv: list[str] | None = None) -> int:
    """Entry point for testing MQTT messages."""
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
    args = parser.parse_args(argv)

    token = _load_token_file(args.token_file)

    username = args.username
    password = args.password

    # If no token and missing username/password, prompt interactively
    if (not token or token.get("push_profile") != "android-channel99") and (not username or not password):
        _LOGGER.info("No token found. Please enter Ezviz credentials")
        if not username:
            username = input("Username: ")
        if not password:
            password = getpass("Password: ")

    client = EzvizClient(username, password, args.region, token=token,
                         on_token_updated=lambda snapshot: _save_token_file(args.token_file, snapshot))

    # Login if we have credentials (to refresh session and populate service URLs)
    if token or (username and password):
        try:
            client.enable_channel99()
        except EzvizAuthVerificationCode:
            mfa_code = input("MFA code required, please input MFA code.\n")
            try:
                code_int = int(mfa_code.strip())
            except ValueError:
                code_int = None
            client.enable_channel99(sms_code=code_int)
        except PyEzvizError as exp:
            _LOGGER.error("Login failed: %s", exp)
            return 1

    # Start MQTT client
    mqtt_client = client.get_mqtt_client(on_message_callback=message_handler)
    mqtt_client.connect()

    try:
        _LOGGER.info("Listening for MQTT messages... (Ctrl+C to quit)")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        _LOGGER.info("Stopping listener (keyboard interrupt)")
    finally:
        mqtt_client.stop()
        _LOGGER.info("Listener stopped")

    if args.save_token and args.token_file:
        _save_token_file(args.token_file, client.export_token())

    return 0


if __name__ == "__main__":
    sys.exit(main())
