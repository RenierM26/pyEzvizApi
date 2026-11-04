"""Validation-only integration constants."""
DOMAIN = "ezviz_native"
PLATFORMS = ["camera", "button", "sensor"]
MAX_ACTIVE = 4
WRITE_TIMEOUT = 10


def status_signal(entry_id: str) -> str:
    """Per-entry dispatcher signal, without source capabilities."""
    return f"{DOMAIN}_status_{entry_id}"
