# Retained private compatibility exports are explicit object aliases.
# ruff: noqa: SLF001
"""Compatibility exports; implementations are dependency-closed protocol_types modules."""

from pyezvizapi.streaming.local.hcnetsdk.protocol_types import (
    configuration as _configuration,
    discovery as _discovery,
    framing as _framing,
    preview as _preview,
    sdk_requests as _sdk_requests,
    values as _values,
    wire_crypto as _wire_crypto,
)

hcnetsdk_stdxml_response_json = _configuration.hcnetsdk_stdxml_response_json
_hcnetsdk_compression_info_v30 = _configuration._hcnetsdk_compression_info_v30

hcnetsdk_real_data_type_is_media = _framing.hcnetsdk_real_data_type_is_media

hcnetsdk_real_play_request = _preview.hcnetsdk_real_play_request
classify_hcnetsdk_real_data_payload = _framing.classify_hcnetsdk_real_data_payload
build_hcnetsdk_tcp_frame = _framing.build_hcnetsdk_tcp_frame

hcnetsdk_command_port_auth_word = _wire_crypto.hcnetsdk_command_port_auth_word
hcnetsdk_command_port_control_frame = _framing.hcnetsdk_command_port_control_frame
hcnetsdk_command_port_play_login_body_tail_for_today = _framing.hcnetsdk_command_port_play_login_body_tail_for_today

hcnetsdk_command_candidate_role = _sdk_requests.hcnetsdk_command_candidate_role
ezviz_native_video_level = _preview.ezviz_native_video_level
build_ezviz_local_preview_request_body = _preview.build_ezviz_local_preview_request_body
ezviz_local_sdk_iv = _sdk_requests.ezviz_local_sdk_iv
hcnetsdk_command_port_response_payload = _framing.hcnetsdk_command_port_response_payload

_mapping_str = _values._mapping_str
_mapping_int = _values._mapping_int
_stdxml_bytes = _values._stdxml_bytes
_optional_native_bytes = _values._optional_native_bytes
_native_secret_key_bytes = _values._native_secret_key_bytes
_native_path_value = _values._native_path_value
_bounded_bytes = _values._bounded_bytes

_sadp_string_bytes = _discovery._sadp_string_bytes
_optional_raw_byte = _values._optional_raw_byte
_optional_raw_u16_be = _values._optional_raw_u16_be
_optional_raw_u32_be = _values._optional_raw_u32_be
_optional_raw_u16_be_pair = _values._optional_raw_u16_be_pair
_optional_raw_byte_triplet = _values._optional_raw_byte_triplet
_byte_value = _values._byte_value
_word_value = _values._word_value
_port_value = _values._port_value
_nul_stripped_text = _values._nul_stripped_text
_device_ability_bytes = _values._device_ability_bytes
_ability_option_tuple = _values._ability_option_tuple
_hcnetsdk_command_port_local_ip_word = _wire_crypto._hcnetsdk_command_port_local_ip_word
_hcnetsdk_command_port_auth_mask = _wire_crypto._hcnetsdk_command_port_auth_mask
_hcnetsdk_command_port_four_round_aes = _wire_crypto._hcnetsdk_command_port_four_round_aes
_hcnetsdk_aes128_round_keys = _wire_crypto._hcnetsdk_aes128_round_keys
_hcnetsdk_aes_add_round_key = _wire_crypto._hcnetsdk_aes_add_round_key
_hcnetsdk_aes_sub_bytes = _wire_crypto._hcnetsdk_aes_sub_bytes
_hcnetsdk_aes_shift_rows = _wire_crypto._hcnetsdk_aes_shift_rows
_hcnetsdk_aes_xtime = _wire_crypto._hcnetsdk_aes_xtime
_hcnetsdk_aes_mix_columns = _wire_crypto._hcnetsdk_aes_mix_columns
_build_local_sdk_request_xml = _preview._build_local_sdk_request_xml
_xml_escape = _preview._xml_escape
_xml_attrs = _preview._xml_attrs
_local_sdk_aes_bytes = _wire_crypto._local_sdk_aes_bytes

__all__ = ['build_ezviz_local_preview_request_body', 'build_hcnetsdk_tcp_frame', 'classify_hcnetsdk_real_data_payload', 'ezviz_local_sdk_iv', 'ezviz_native_video_level', 'hcnetsdk_command_candidate_role', 'hcnetsdk_command_port_auth_word', 'hcnetsdk_command_port_control_frame', 'hcnetsdk_command_port_play_login_body_tail_for_today', 'hcnetsdk_command_port_response_payload', 'hcnetsdk_real_data_type_is_media', 'hcnetsdk_real_play_request', 'hcnetsdk_stdxml_response_json']
