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

from .client import EzvizClient
from .exceptions import EzvizAuthVerificationCode, PyEzvizError

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

LOG_FILE = Path("mqtt_messages.jsonl")  # JSON Lines format


def message_handler(msg: dict[str, Any]) -> None:
    """Handle new MQTT messages by printing and saving them to a file."""
    print("📩 New MQTT message:", msg)
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
        logging.getLogger(__name__).warning("Failed to read token file: %s", p)
        return None


def _save_token_file(path: str | None, token: dict[str, Any]) -> None:
    if not path:
        return
    p = Path(path)
    try:
        p.write_text(json.dumps(token, indent=2), encoding="utf-8")
        logging.getLogger(__name__).info("Saved token to %s", p)
    except OSError:
        logging.getLogger(__name__).warning("Failed to save token file: %s", p)


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
        help="Save token to --token-file after successful login",
    )
    args = parser.parse_args(argv)

    token = _load_token_file(args.token_file)

    username = args.username
    password = args.password

    # If no token and missing username/password, prompt interactively
    if not token and (not username or not password):
        print("No token found. Please enter Ezviz credentials.")
        if not username:
            username = input("Username: ")
        if not password:
            password = getpass("Password: ")

    client = EzvizClient(username, password, args.region, token=token)

    # Login if we have credentials (to refresh session and populate service URLs)
    if username and password:
        try:
            client.login()
        except EzvizAuthVerificationCode:
            mfa_code = input("MFA code required, please input MFA code.\n")
            try:
                code_int = int(mfa_code.strip())
            except ValueError:
                code_int = None
            client.login(sms_code=code_int)
        except PyEzvizError as exp:
            print(f"Login failed: {exp}")
            return 1

    # Start MQTT client
    mqtt_client = client.get_mqtt_client(on_message_callback=message_handler)
    mqtt_client.connect()

    try:
        print("Listening for MQTT messages... (Ctrl+C to quit)")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        mqtt_client.stop()
        print("Stopped.")

    if args.save_token and args.token_file:
        _save_token_file(args.token_file, cast(dict[str, Any], client._token))  # noqa: SLF001

    return 0


if __name__ == "__main__":
    sys.exit(main())
# ruff: noqa: T201
