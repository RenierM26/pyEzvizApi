"""Narrow compatibility boundary for the supported Paho MQTT 2.x client."""

from paho.mqtt.client import Client


def set_keepalive(client: Client, interval: int) -> None:
    """Apply EZVIZ's negotiated interval without reconnecting with stale keys.

    Paho 2.x exposes keepalive only at connect(), not as a runtime setter.
    Its loop reads this field for ping scheduling. Keep this dependency here
    and test it when upgrading Paho; automatic Paho reconnect cannot renew LBS.
    """
    client._keepalive = interval  # noqa: SLF001 - no public runtime setter
