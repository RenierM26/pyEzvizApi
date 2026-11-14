"""Compatibility exports for focused device feature modules.

New consumers may import the canonical modules directly; existing controls imports
retain identical objects and call signatures.
"""

from pyezvizapi.devices.capabilities import (
    SupportExtView,
    support_ext_dict,
    support_ext_has,
)
from pyezvizapi.devices.lens import (
    has_lens_defog,
    set_lens_defog_option,
)
from pyezvizapi.devices.metadata import (
    coerce_bool,
    coerce_int,
    network_type_value,
    sd_card_capacity_gb,
    wifi_signal_value,
    wifi_ssid_value,
)
from pyezvizapi.devices.ports import (
    PortSecurityToggle,
    set_port_security_ports,
)
from pyezvizapi.devices.tracking import (
    ensure_ptz_master_slave_trace,
    intelligent_app_available,
    intelligent_app_enabled,
    intelligent_app_method,
    intelligent_app_value_fn,
    iter_intelligent_apps,
    linked_tracking_takeover_enabled,
    ptz_master_slave_trace,
    set_linked_tracking_takeover,
)

__all__ = [
    "PortSecurityToggle",
    "SupportExtView",
    "coerce_bool",
    "coerce_int",
    "ensure_ptz_master_slave_trace",
    "has_lens_defog",
    "intelligent_app_available",
    "intelligent_app_enabled",
    "intelligent_app_method",
    "intelligent_app_value_fn",
    "iter_intelligent_apps",
    "linked_tracking_takeover_enabled",
    "network_type_value",
    "ptz_master_slave_trace",
    "sd_card_capacity_gb",
    "set_lens_defog_option",
    "set_linked_tracking_takeover",
    "set_port_security_ports",
    "support_ext_dict",
    "support_ext_has",
    "wifi_signal_value",
    "wifi_ssid_value",
]
