# Compatibility aliases are explicit type-checker re-exports.
# ruff: noqa: PLC0414

"""Compatibility alias. Implementation: :mod:`pyezvizapi.devices.features`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.devices import features as _implementation

if TYPE_CHECKING:
    from pyezvizapi.devices.features import (
        WILDCARD_STEP as WILDCARD_STEP,
        Any as Any,
        Iterable as Iterable,
        Iterator as Iterator,
        Mapping as Mapping,
        MutableMapping as MutableMapping,
        _feature_video_section as _feature_video_section,
        _normalize_port_list as _normalize_port_list,
        annotations as annotations,
        blc_current_value as blc_current_value,
        cast as cast,
        coerce_int as coerce_int,
        custom_voice_volume_config as custom_voice_volume_config,
        day_night_mode_value as day_night_mode_value,
        day_night_sensitivity_value as day_night_sensitivity_value,
        decode_json as decode_json,
        device_icr_dss_config as device_icr_dss_config,
        display_mode_value as display_mode_value,
        first_nested as first_nested,
        get_algorithm_value as get_algorithm_value,
        has_algorithm_subtype as has_algorithm_subtype,
        has_osd_overlay as has_osd_overlay,
        iter_algorithm_entries as iter_algorithm_entries,
        iter_channel_algorithm_entries as iter_channel_algorithm_entries,
        lens_defog_config as lens_defog_config,
        lens_defog_value as lens_defog_value,
        night_vision_config as night_vision_config,
        night_vision_duration_value as night_vision_duration_value,
        night_vision_luminance_value as night_vision_luminance_value,
        night_vision_mode_value as night_vision_mode_value,
        night_vision_payload as night_vision_payload,
        normalize_port_security as normalize_port_security,
        optionals_dict as optionals_dict,
        optionals_mapping as optionals_mapping,
        port_security_config as port_security_config,
        port_security_has_port as port_security_has_port,
        port_security_port_enabled as port_security_port_enabled,
        resolve_channel as resolve_channel,
        supplement_light_available as supplement_light_available,
        supplement_light_enabled as supplement_light_enabled,
        supplement_light_params as supplement_light_params,
        support_ext_value as support_ext_value,
    )

sys.modules[__name__] = _implementation
