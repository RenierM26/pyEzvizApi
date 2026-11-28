"""Wire values shared by the cloud client and typed image settings."""

NIGHT_FILL_LIGHT_DOMAIN = "SupplementLightMgr"
NIGHT_FILL_LIGHT_PROPERTY = "ImageSupplementLightModeSwitchParams"


def night_fill_light_payload(enabled: bool, switch_mode: str) -> dict[str, dict[str, bool | str]]:
    """Build the IoT fill-light request body without choosing a resource."""
    return {"value": {"enabled": enabled, "supplementLightSwitchMode": switch_mode}}
