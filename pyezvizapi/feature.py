# Compatibility export assignments include retained private attributes.
# ruff: noqa: SLF001
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.devices.features`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""

import sys
from typing import TYPE_CHECKING

from pyezvizapi.devices import features as _implementation

if TYPE_CHECKING:
    import pyezvizapi.devices.features as _compat_module_0

    WILDCARD_STEP = _compat_module_0.WILDCARD_STEP
    Any = _compat_module_0.Any
    Iterable = _compat_module_0.Iterable
    Iterator = _compat_module_0.Iterator
    Mapping = _compat_module_0.Mapping
    MutableMapping = _compat_module_0.MutableMapping
    _feature_video_section = _compat_module_0._feature_video_section
    _normalize_port_list = _compat_module_0._normalize_port_list
    annotations = _compat_module_0.annotations
    blc_current_value = _compat_module_0.blc_current_value
    cast = _compat_module_0.cast
    coerce_int = _compat_module_0.coerce_int
    custom_voice_volume_config = _compat_module_0.custom_voice_volume_config
    day_night_mode_value = _compat_module_0.day_night_mode_value
    day_night_sensitivity_value = _compat_module_0.day_night_sensitivity_value
    decode_json = _compat_module_0.decode_json
    device_icr_dss_config = _compat_module_0.device_icr_dss_config
    display_mode_value = _compat_module_0.display_mode_value
    first_nested = _compat_module_0.first_nested
    get_algorithm_value = _compat_module_0.get_algorithm_value
    has_algorithm_subtype = _compat_module_0.has_algorithm_subtype
    has_osd_overlay = _compat_module_0.has_osd_overlay
    iter_algorithm_entries = _compat_module_0.iter_algorithm_entries
    iter_channel_algorithm_entries = _compat_module_0.iter_channel_algorithm_entries
    lens_defog_config = _compat_module_0.lens_defog_config
    lens_defog_value = _compat_module_0.lens_defog_value
    night_vision_config = _compat_module_0.night_vision_config
    night_vision_duration_value = _compat_module_0.night_vision_duration_value
    night_vision_luminance_value = _compat_module_0.night_vision_luminance_value
    night_vision_mode_value = _compat_module_0.night_vision_mode_value
    night_vision_payload = _compat_module_0.night_vision_payload
    normalize_port_security = _compat_module_0.normalize_port_security
    optionals_dict = _compat_module_0.optionals_dict
    optionals_mapping = _compat_module_0.optionals_mapping
    port_security_config = _compat_module_0.port_security_config
    port_security_has_port = _compat_module_0.port_security_has_port
    port_security_port_enabled = _compat_module_0.port_security_port_enabled
    resolve_channel = _compat_module_0.resolve_channel
    supplement_light_available = _compat_module_0.supplement_light_available
    supplement_light_enabled = _compat_module_0.supplement_light_enabled
    supplement_light_params = _compat_module_0.supplement_light_params
    support_ext_value = _compat_module_0.support_ext_value

    def _declare_compatibility_exports(*exports: object) -> None:
        """Declare retained named exports to static analyzers; no runtime import work."""
        if not exports:
            raise AssertionError("compatibility export list must not be empty")

    _declare_compatibility_exports(
        WILDCARD_STEP,
        Any,
        Iterable,
        Iterator,
        Mapping,
        MutableMapping,
        _feature_video_section,
        _normalize_port_list,
        annotations,
        blc_current_value,
        cast,
        coerce_int,
        custom_voice_volume_config,
        day_night_mode_value,
        day_night_sensitivity_value,
        decode_json,
        device_icr_dss_config,
        display_mode_value,
        first_nested,
        get_algorithm_value,
        has_algorithm_subtype,
        has_osd_overlay,
        iter_algorithm_entries,
        iter_channel_algorithm_entries,
        lens_defog_config,
        lens_defog_value,
        night_vision_config,
        night_vision_duration_value,
        night_vision_luminance_value,
        night_vision_mode_value,
        night_vision_payload,
        normalize_port_security,
        optionals_dict,
        optionals_mapping,
        port_security_config,
        port_security_has_port,
        port_security_port_enabled,
        resolve_channel,
        supplement_light_available,
        supplement_light_enabled,
        supplement_light_params,
        support_ext_value,
    )

sys.modules[__name__] = _implementation
