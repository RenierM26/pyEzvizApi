"""MQTT test module."""

from getpass import getpass
import json
import logging
from pathlib import Path
import time
from typing import Any

from .client import EzvizClient  # Your login client
from .mqtt import MQTTClient  # The refactored MQTT class

logging.basicConfig(level=logging.INFO)

LOG_FILE = Path("mqtt_messages.jsonl")  # JSON Lines format


def message_handler(msg: dict[str, Any]) -> None:
    """Handle new MQTT messages by printing and saving them to a file.

    Args:
        msg (Dict[str, Any]): The decoded MQTT message.
    """
    print("📩 New MQTT message:", msg)

    # Append to JSONL file
    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(msg, ensure_ascii=False) + "\n")


def main() -> None:
    """Entry point for testing MQTT messages.

    Prompts for username and password, logs into Ezviz, starts MQTT listener,
    and writes incoming messages to a JSONL file.
    """
    # Prompt for credentials
    username = input("Ezviz username: ")
    password = getpass("Ezviz password: ")

    # Step 1: Log into Ezviz to get a token
    client = EzvizClient(account=username, password=password)
    client.login()

    # Step 2: Start MQTT client
    mqtt_client: MQTTClient = client.get_mqtt_client(
        on_message_callback=message_handler
    )
    mqtt_client.connect()

    try:
        print("Listening for MQTT messages... (Ctrl+C to quit)")
        while True:
            time.sleep(1)  # Keep process alive
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        mqtt_client.stop()
        print("Stopped.")


if __name__ == "__main__":
    main()

