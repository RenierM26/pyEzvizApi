# Runtime hook context is explicit; immutable value types come from dependency leaves.
# ruff: noqa: SLF001
'configuration implementation; legacy runtime hooks remain on the owner module.\n\nAccess through _owner is deliberate: callers that patch the compatibility\nmodule must still affect dependent operations. No copied hook snapshots.\n'
from __future__ import annotations

from collections.abc import Mapping as _StaticMapping
from types import ModuleType as _ModuleType
from typing import TYPE_CHECKING

from pyezvizapi.streaming.local.hcnetsdk.models_configuration import (
    HcNetSdkStdXmlConfigRequest as _StaticHcNetSdkStdXmlConfigRequest,
)

if TYPE_CHECKING:
    import pyezvizapi.streaming.local.hcnetsdk.api as _owner_types

def ezviz_lan_settings_updates_services_switch(*, login_with_8443: bool | None, login_port: int, open_8000: bool | None, tls_port: int, _owner: _ModuleType) -> bool:
    """Return whether the settings presenter writes ``servicesSwitch``.

    Smali inspection shows the compatibility checkbox update runs only after a
    successful SDK-over-TLS login attempt. If the TLS attempt is skipped, or if
    the flow falls back to the command-port login, the app does not send the
    ``GET``/``PUT`` servicesSwitch requests.
    """
    return open_8000 is not None and login_with_8443 is not False and (login_port == tls_port)

def hcnetsdk_stdxml_config_request(request: str | bytes, *, in_buffer: str | bytes, recv_timeout: int, force_encrypt: int, num_of_multi_part: int, output_buffer_size: int, status_buffer_size: int, _owner: _ModuleType) -> _owner_types.HcNetSdkStdXmlConfigRequest:
    """Return a ``NET_DVR_STDXMLConfig`` request model."""
    return _owner.HcNetSdkStdXmlConfigRequest(request=request, in_buffer=in_buffer, recv_timeout=recv_timeout, force_encrypt=force_encrypt, num_of_multi_part=num_of_multi_part, output_buffer_size=output_buffer_size, status_buffer_size=status_buffer_size)

def ezviz_lan_services_switch_get_request(*, _owner: _ModuleType) -> str:
    """Return the local ISAPI request used to read ``servicesSwitch``."""
    return _owner.HCNETSDK_EZVIZ_SERVICES_SWITCH_GET

def ezviz_lan_services_switch_get_config(*, _owner: _ModuleType) -> _owner_types.HcNetSdkStdXmlConfigRequest:
    """Return a STDXML request model for reading ``servicesSwitch``."""
    return _owner.hcnetsdk_stdxml_config_request(_owner.ezviz_lan_services_switch_get_request())

def ezviz_lan_services_switch_payload(payload: _owner_types.Mapping[str, _owner_types.Any] | None, *, enabled: bool, _owner: _ModuleType) -> dict[str, _owner_types.Any]:
    """Return the LAN settings servicesSwitch update payload.

    The APK reads GET /ISAPI/EZVIZ/IPC/System/servicesSwitch?format=json,
    mutates servicesSwitch.hiksdk and servicesSwitch.web to the same checkbox
    value, then sends the whole JSON object back through HCNetSDK.
    """
    result: dict[str, _owner_types.Any] = dict(payload or {})
    services = result.get('servicesSwitch')
    services_switch = dict(services) if isinstance(services, _StaticMapping) else {}
    checkbox_value = 1 if enabled else 0
    services_switch['hiksdk'] = checkbox_value
    services_switch['web'] = checkbox_value
    result['servicesSwitch'] = services_switch
    return result

def ezviz_lan_services_switch_set_payload(payload: _owner_types.Mapping[str, _owner_types.Any] | None, *, hiksdk: int | bool | None, web: int | bool | None, rtsp: int | bool | None, upnp: int | bool | None, _owner: _ModuleType) -> dict[str, _owner_types.Any]:
    """Return a ``servicesSwitch`` payload with only named switches changed."""
    result: dict[str, _owner_types.Any] = dict(payload or {})
    services = result.get('servicesSwitch')
    services_switch = dict(services) if isinstance(services, _StaticMapping) else {}
    for key, value in (('hiksdk', hiksdk), ('web', web), ('rtsp', rtsp), ('upnp', upnp)):
        if value is not None:
            services_switch[key] = _owner._services_switch_value(key, value)
    result['servicesSwitch'] = services_switch
    return result

def ezviz_lan_services_switch_put_request(payload: _owner_types.Mapping[str, _owner_types.Any], *, _owner: _ModuleType) -> str:
    """Return the raw ISAPI request string sent by HCNETUtil.c(...)."""
    return _owner.hcnetsdk_stdxml_isapi_request('PUT', '/ISAPI/EZVIZ/IPC/System/servicesSwitch?format=json', payload)

def ezviz_lan_services_switch_put_config(payload: _owner_types.Mapping[str, _owner_types.Any], *, _owner: _ModuleType) -> _owner_types.HcNetSdkStdXmlConfigRequest:
    """Return a STDXML request model for writing ``servicesSwitch``."""
    return _owner.hcnetsdk_stdxml_config_request(_owner.ezviz_lan_services_switch_put_request(payload))

def ezviz_lan_services_switch_update_config(payload: _owner_types.Mapping[str, _owner_types.Any] | None, *, enabled: bool, _owner: _ModuleType) -> _owner_types.HcNetSdkStdXmlConfigRequest:
    """Return a STDXML request model for the app's checkbox update."""
    return _owner.ezviz_lan_services_switch_put_config(_owner.ezviz_lan_services_switch_payload(payload, enabled=enabled))

def ezviz_lan_services_switch_set_config(payload: _owner_types.Mapping[str, _owner_types.Any] | None, *, hiksdk: int | bool | None, web: int | bool | None, rtsp: int | bool | None, upnp: int | bool | None, _owner: _ModuleType) -> _owner_types.HcNetSdkStdXmlConfigRequest:
    """Return a STDXML request model for direct ``servicesSwitch`` updates."""
    return _owner.ezviz_lan_services_switch_put_config(_owner.ezviz_lan_services_switch_set_payload(payload, hiksdk=hiksdk, web=web, rtsp=rtsp, upnp=upnp))

def ezviz_lan_services_switch_state(response: _owner_types.Mapping[str, _owner_types.Any] | str | bytes, *, _owner: _ModuleType) -> _owner_types.EzvizLanServicesSwitchState:
    """Parse ``servicesSwitch`` values from a local ISAPI response."""
    data = _owner.hcnetsdk_stdxml_response_json(response)
    services = data.get('servicesSwitch')
    values = services if isinstance(services, _StaticMapping) else {}
    return _owner.EzvizLanServicesSwitchState(hiksdk=_owner._mapping_int(values, 'hiksdk', default=None), web=_owner._mapping_int(values, 'web', default=None), rtsp=_owner._mapping_int(values, 'rtsp', default=None), raw=data)

def ezviz_lan_services_switch_succeeded(response: _owner_types.Mapping[str, _owner_types.Any] | str | bytes, *, _owner: _ModuleType) -> bool:
    """Return whether HCNETUtil.c(...) would treat a servicesSwitch PUT as OK."""
    data = _owner.hcnetsdk_stdxml_response_json(response)
    return data.get('statusCode') == 1

def ezviz_lan_services_switch_get_command_port(endpoint: _owner_types.HcNetSdkLanEndpoint, password: str | bytes, *, command_id: int, body_prefix: str | bytes | None, addend_delta: int | None, addend: int | None, username: str, local_ip: str | None, timeout: float | None, socket_factory: _owner_types.SocketFactory, rsa_key: _owner_types.Any | None, _owner: _ModuleType) -> _owner_types.HcNetSdkStdXmlConfigResponse:  # noqa: PLR0913 -- explicit runtime context plus retained signature
    """Read ``servicesSwitch`` through traced pure-Python command-port STDXML."""
    return _owner.hcnetsdk_stdxml_config_command_port_from_trace(endpoint, password, _owner.ezviz_lan_services_switch_get_config(), command_id=command_id, body_prefix=body_prefix, addend_delta=addend_delta, addend=addend, name='servicesSwitch GET', username=username, local_ip=local_ip, timeout=timeout, socket_factory=socket_factory, rsa_key=rsa_key)

def ezviz_lan_services_switch_state_command_port(endpoint: _owner_types.HcNetSdkLanEndpoint, password: str | bytes, *, command_id: int, body_prefix: str | bytes | None, addend_delta: int | None, addend: int | None, username: str, local_ip: str | None, timeout: float | None, socket_factory: _owner_types.SocketFactory, rsa_key: _owner_types.Any | None, _owner: _ModuleType) -> _owner_types.EzvizLanServicesSwitchState:  # noqa: PLR0913 -- explicit runtime context plus retained signature
    """Read and parse ``servicesSwitch`` through pure command-port STDXML."""
    response = _owner.ezviz_lan_services_switch_get_command_port(endpoint, password, command_id=command_id, body_prefix=body_prefix, addend_delta=addend_delta, addend=addend, username=username, local_ip=local_ip, timeout=timeout, socket_factory=socket_factory, rsa_key=rsa_key)
    if not response.succeeded:
        raise _owner.PyEzvizError('HCNetSDK command-port servicesSwitch GET failed')
    return _owner.ezviz_lan_services_switch_state(response.output)

def ezviz_lan_services_switch_set_command_port(endpoint: _owner_types.HcNetSdkLanEndpoint, password: str | bytes, current_payload: _owner_types.Mapping[str, _owner_types.Any] | None, *, command_id: int, body_prefix: str | bytes | None, addend_delta: int | None, addend: int | None, username: str, local_ip: str | None, timeout: float | None, socket_factory: _owner_types.SocketFactory, rsa_key: _owner_types.Any | None, hiksdk: int | bool | None, web: int | bool | None, rtsp: int | bool | None, upnp: int | bool | None, _owner: _ModuleType) -> _owner_types.HcNetSdkStdXmlConfigResponse:  # noqa: PLR0913 -- explicit runtime context plus retained signature
    """Set named ``servicesSwitch`` values through pure command-port STDXML.

    When ``current_payload`` is omitted, the device is read first so unspecified
    switches are preserved before the PUT request is sent.
    """
    payload = current_payload
    if payload is None:
        get_response = _owner.ezviz_lan_services_switch_get_command_port(endpoint, password, command_id=command_id, body_prefix=body_prefix, addend_delta=addend_delta, addend=addend, username=username, local_ip=local_ip, timeout=timeout, socket_factory=socket_factory, rsa_key=rsa_key)
        if not get_response.succeeded:
            raise _owner.PyEzvizError('HCNetSDK command-port servicesSwitch GET failed')
        payload = _owner.hcnetsdk_stdxml_response_json(get_response.output)
    return _owner.hcnetsdk_stdxml_config_command_port_from_trace(endpoint, password, _owner.ezviz_lan_services_switch_set_config(payload, hiksdk=hiksdk, web=web, rtsp=rtsp, upnp=upnp), command_id=command_id, body_prefix=body_prefix, addend_delta=addend_delta, addend=addend, name='servicesSwitch PUT', username=username, local_ip=local_ip, timeout=timeout, socket_factory=socket_factory, rsa_key=rsa_key)

def ezviz_lan_connect_mode_put_config(mode: int, *, _owner: _ModuleType) -> _owner_types.HcNetSdkStdXmlConfigRequest:
    """Return a STDXML request model for writing local ``connectMode``."""
    return _owner.hcnetsdk_stdxml_config_request(_owner.ezviz_lan_connect_mode_put_request(mode))

def ezviz_lan_net_config_and_voice_upload_payload(*, ip: str, port: int, bssid: str, ssid: str, passwd: str, security: int, _owner: _ModuleType) -> dict[str, _owner_types.Any]:
    """Return the local add-device Wi-Fi upload payload used by the APK."""
    if port < 0:
        raise _owner.PyEzvizError('EZVIZ LAN net-config port must be non-negative')
    if security < 0:
        raise _owner.PyEzvizError('EZVIZ LAN net-config security must be non-negative')
    return {'NetConfigAndVoiceFileUpload': {'ip': ip, 'port': port, 'bssid': bssid, 'ssid': ssid, 'passwd': passwd, 'security': security}}

def ezviz_lan_net_config_and_voice_upload_put_request(*, ip: str, port: int, bssid: str, ssid: str, passwd: str, security: int, _owner: _ModuleType) -> str:
    """Return the raw local ISAPI net-config upload PUT request."""
    return _owner.hcnetsdk_stdxml_isapi_request('PUT', '/ISAPI/EZVIZ/IPC/System/netConfigAndVoiceFileUpload?format=json', _owner.ezviz_lan_net_config_and_voice_upload_payload(ip=ip, port=port, bssid=bssid, ssid=ssid, passwd=passwd, security=security))

def ezviz_lan_net_config_and_voice_upload_put_config(*, ip: str, port: int, bssid: str, ssid: str, passwd: str, security: int, _owner: _ModuleType) -> _owner_types.HcNetSdkStdXmlConfigRequest:
    """Return a STDXML request model for local net-config upload."""
    return _owner.hcnetsdk_stdxml_config_request(_owner.ezviz_lan_net_config_and_voice_upload_put_request(ip=ip, port=port, bssid=bssid, ssid=ssid, passwd=passwd, security=security))

def hcnetsdk_dvr_config_get_request(login_id: int, command: int, *, channel: int, structure: str, structure_size: int | None, _owner: _ModuleType) -> _owner_types.HcNetSdkDvrConfigRequest:
    """Return a ``NET_DVR_GetDVRConfig`` request model."""
    return _owner.HcNetSdkDvrConfigRequest(login_id=login_id, command=int(command), channel=channel, structure=structure, structure_size=structure_size, api=_owner.HCNETSDK_GET_DVR_CONFIG)

def hcnetsdk_dvr_config_set_request(login_id: int, command: int, *, channel: int, structure: str, structure_size: int | None, field_updates: _owner_types.Mapping[str, _owner_types.Any] | None, read_before_write: bool, _owner: _ModuleType) -> _owner_types.HcNetSdkDvrConfigRequest:
    """Return a ``NET_DVR_SetDVRConfig`` request model."""
    return _owner.HcNetSdkDvrConfigRequest(login_id=login_id, command=int(command), channel=channel, structure=structure, structure_size=structure_size, field_updates=field_updates, read_before_write=read_before_write, api=_owner.HCNETSDK_SET_DVR_CONFIG)

def ezviz_lan_wifi_station_patch(*, ssid: str | bytes, password: str | bytes, mac: str | bytes | None, mode: int, security: int | None, _owner: _ModuleType) -> dict[str, _owner_types.Any]:
    """Return APK-observed ``NET_DVR_WIFI_CFG`` field updates for station Wi-Fi."""
    if mode < 0:
        raise _owner.PyEzvizError('EZVIZ LAN Wi-Fi mode must be non-negative')
    ssid_bytes = _owner._bounded_bytes('Wi-Fi SSID', ssid, 32, truncate=True)
    password_bytes = _owner._bounded_bytes('Wi-Fi password', password, 63)
    wifi_security = (4 if password_bytes else 0) if security is None else security
    if wifi_security < 0:
        raise _owner.PyEzvizError('EZVIZ LAN Wi-Fi security must be non-negative')
    patch: dict[str, _owner_types.Any] = {'dwMode': mode, 'sEssid': ssid_bytes, 'sEssidLength': len(ssid_bytes), 'dwSecurity': wifi_security}
    if mac is not None:
        patch['struEtherNet.byMACAddr'] = _owner._mac_address_bytes(mac)
    if password_bytes:
        patch.update({'wpa_psk.dwKeyLength': len(password_bytes), 'wpa_psk.byKeyType': 0, 'wpa_psk.sKeyInfo': '<password-bytes>', 'wpa_psk.sKeyInfoLength': len(password_bytes)})
    return patch

def ezviz_lan_wifi_get_config_request(login_id: int, *, _owner: _ModuleType) -> _owner_types.HcNetSdkDvrConfigRequest:
    """Return the app's ``NET_DVR_WIFI_CFG`` read request."""
    return _owner.hcnetsdk_dvr_config_get_request(login_id, _owner.HcNetSdkDvrCommand.GET_WIFI_CFG, structure='NET_DVR_WIFI_CFG')

def ezviz_lan_wifi_set_config_request(login_id: int, *, ssid: str | bytes, password: str | bytes, mac: str | bytes | None, mode: int, security: int | None, _owner: _ModuleType) -> _owner_types.HcNetSdkDvrConfigRequest:
    """Return the APK-observed ``NET_DVR_WIFI_CFG`` station update request."""
    return _owner.hcnetsdk_dvr_config_set_request(login_id, _owner.HcNetSdkDvrCommand.SET_WIFI_CFG, structure='NET_DVR_WIFI_CFG', field_updates=_owner.ezviz_lan_wifi_station_patch(ssid=ssid, password=password, mac=mac, mode=mode, security=security), read_before_write=True)

def ezviz_lan_wifi_work_mode_update_request(login_id: int, mode: int, *, _owner: _ModuleType) -> _owner_types.HcNetSdkDvrConfigRequest:
    """Return the RN LAN ``apiSetApWorkModeWithHandle`` request shape."""
    if mode < 0:
        raise _owner.PyEzvizError('EZVIZ LAN Wi-Fi work mode must be non-negative')
    return _owner.hcnetsdk_dvr_config_set_request(login_id, _owner.HcNetSdkDvrCommand.SET_WIFI_CFG, structure='NET_DVR_WIFI_CFG', field_updates={'dwMode': mode}, read_before_write=True)

def ezviz_lan_wifi_ap_info_list_request(login_id: int, *, _owner: _ModuleType) -> _owner_types.HcNetSdkDvrConfigRequest:
    """Return the local Wi-Fi scan ``NET_DVR_AP_INFO_LIST`` request shape."""
    return _owner.hcnetsdk_dvr_config_get_request(login_id, _owner.HcNetSdkDvrCommand.GET_AP_INFO_LIST, structure='NET_DVR_AP_INFO_LIST')

def ezviz_lan_time_get_config_request(login_id: int, *, _owner: _ModuleType) -> _owner_types.HcNetSdkDvrConfigRequest:
    """Return the local ``NET_DVR_TIME`` read request shape."""
    return _owner.hcnetsdk_dvr_config_get_request(login_id, _owner.HcNetSdkDvrCommand.GET_TIME_CFG, structure='NET_DVR_TIME')

def ezviz_lan_ntp_get_config_request(login_id: int, *, _owner: _ModuleType) -> _owner_types.HcNetSdkDvrConfigRequest:
    """Return the local ``NET_DVR_NTPPARA`` read request shape."""
    return _owner.hcnetsdk_dvr_config_get_request(login_id, _owner.HcNetSdkDvrCommand.GET_NTP_CFG, structure='NET_DVR_NTPPARA')

def ezviz_lan_device_config_v40_request(login_id: int, *, _owner: _ModuleType) -> _owner_types.HcNetSdkDvrConfigRequest:
    """Return the local ``NET_DVR_DEVICECFG_V40`` read request shape."""
    return _owner.hcnetsdk_dvr_config_get_request(login_id, _owner.HcNetSdkDvrCommand.GET_DEVICE_CFG_V40, structure='NET_DVR_DEVICECFG_V40')

def ezviz_lan_net_config_v30_request(login_id: int, *, _owner: _ModuleType) -> _owner_types.HcNetSdkDvrConfigRequest:
    """Return the local ``NET_DVR_NETCFG_V30`` read request shape."""
    return _owner.hcnetsdk_dvr_config_get_request(login_id, _owner.HcNetSdkDvrCommand.GET_NET_CFG, structure='NET_DVR_NETCFG_V30')

def ezviz_lan_record_config_v30_request(login_id: int, *, channel: int, _owner: _ModuleType) -> _owner_types.HcNetSdkDvrConfigRequest:
    """Return the local ``NET_DVR_RECORD_V30`` read request shape."""
    return _owner.hcnetsdk_dvr_config_get_request(login_id, _owner.HcNetSdkDvrCommand.GET_RECORD_CFG_V30, channel=channel, structure='NET_DVR_RECORD_V30')

def ezviz_lan_wifi_ap_info_list(data: bytes | bytearray | memoryview, *, _owner: _ModuleType) -> tuple[_owner_types.EzvizLanWifiApInfo, ...]:
    """Parse a ``NET_DVR_AP_INFO_LIST`` buffer returned by the command port."""
    raw = bytes(data)
    if len(raw) < _owner.HCNETSDK_WIFI_AP_INFO_LIST_HEADER_SIZE:
        raise _owner.PyEzvizError('EZVIZ LAN Wi-Fi AP list response is too short')
    _declared_size, effective_size = _owner._hcnetsdk_config_declared_size(raw, 'Wi-Fi AP list')
    count = int.from_bytes(raw[4:8], 'big')
    required_size = _owner.HCNETSDK_WIFI_AP_INFO_LIST_HEADER_SIZE + count * _owner.HCNETSDK_WIFI_AP_INFO_ENTRY_SIZE
    if required_size > effective_size:
        raise _owner.PyEzvizError('EZVIZ LAN Wi-Fi AP list count exceeds response size')
    raw = raw[:effective_size]
    entries: list[_owner_types.EzvizLanWifiApInfo] = []
    offset = _owner.HCNETSDK_WIFI_AP_INFO_LIST_HEADER_SIZE
    for _ in range(count):
        end = offset + _owner.HCNETSDK_WIFI_AP_INFO_ENTRY_SIZE
        if end > len(raw):
            raise _owner.PyEzvizError('EZVIZ LAN Wi-Fi AP entry is truncated')
        entry = raw[offset:end]
        entries.append(_owner.EzvizLanWifiApInfo(ssid=_owner._nul_stripped_text(entry[:_owner.HCNETSDK_WIFI_AP_INFO_SSID_SIZE]), security=int.from_bytes(entry[_owner.HCNETSDK_WIFI_AP_INFO_SSID_SIZE:_owner.HCNETSDK_WIFI_AP_INFO_SSID_SIZE + 4], 'big'), channel=int.from_bytes(entry[_owner.HCNETSDK_WIFI_AP_INFO_SSID_SIZE + 4:_owner.HCNETSDK_WIFI_AP_INFO_SSID_SIZE + 8], 'big'), signal_strength=int.from_bytes(entry[_owner.HCNETSDK_WIFI_AP_INFO_SSID_SIZE + 8:_owner.HCNETSDK_WIFI_AP_INFO_SSID_SIZE + 12], 'big'), extra=int.from_bytes(entry[_owner.HCNETSDK_WIFI_AP_INFO_SSID_SIZE + 12:_owner.HCNETSDK_WIFI_AP_INFO_SSID_SIZE + 16], 'big')))
        offset = end
    return tuple(entries)

def ezviz_lan_time_config(data: bytes | bytearray | memoryview, *, _owner: _ModuleType) -> _owner_types.HcNetSdkTime:
    """Parse a traced ``NET_DVR_TIME`` buffer from command-port output."""
    raw = bytes(data)
    if len(raw) < _owner.HCNETSDK_TIME_CFG_SIZE:
        raise _owner.PyEzvizError('EZVIZ LAN time config response is too short')
    fields = tuple(int.from_bytes(raw[offset:offset + 4], 'big') for offset in range(0, _owner.HCNETSDK_TIME_CFG_SIZE, 4))
    parsed = _owner.HcNetSdkTime(*fields)
    parsed.to_native_dict()
    return parsed

def ezviz_lan_ntp_config(data: bytes | bytearray | memoryview, *, _owner: _ModuleType) -> _owner_types.EzvizLanNtpConfig:
    """Parse known ``NET_DVR_NTPPARA`` fields from command-port output."""
    raw = bytes(data)
    if len(raw) < _owner.HCNETSDK_NTP_CFG_SIZE:
        raise _owner.PyEzvizError('EZVIZ LAN NTP config response is too short')
    raw = raw[:_owner.HCNETSDK_NTP_CFG_SIZE]
    return _owner.EzvizLanNtpConfig(ntp_server=_owner._nul_stripped_text(raw[:_owner.HCNETSDK_NTP_SERVER_SIZE]), interval_minutes=int.from_bytes(raw[_owner.HCNETSDK_NTP_INTERVAL_OFFSET:_owner.HCNETSDK_NTP_INTERVAL_OFFSET + 2], 'big'), enabled=raw[_owner.HCNETSDK_NTP_ENABLE_OFFSET], time_difference_hours=int.from_bytes(raw[_owner.HCNETSDK_NTP_TIME_DIFFERENCE_HOURS_OFFSET:_owner.HCNETSDK_NTP_TIME_DIFFERENCE_HOURS_OFFSET + 1], 'little', signed=True), time_difference_minutes=int.from_bytes(raw[_owner.HCNETSDK_NTP_TIME_DIFFERENCE_MINUTES_OFFSET:_owner.HCNETSDK_NTP_TIME_DIFFERENCE_MINUTES_OFFSET + 1], 'little', signed=True), ntp_port=int.from_bytes(raw[_owner.HCNETSDK_NTP_PORT_OFFSET:_owner.HCNETSDK_NTP_PORT_OFFSET + 2], 'big'), raw=raw)

def ezviz_lan_net_config_v30(data: bytes | bytearray | memoryview, *, _owner: _ModuleType) -> _owner_types.EzvizLanNetConfigV30:
    """Parse non-secret ``NET_DVR_NETCFG_V30`` fields from command-port output."""
    raw = bytes(data)
    if len(raw) < 4:
        raise _owner.PyEzvizError('EZVIZ LAN net config response is too short')
    _declared_size, effective_size = _owner._hcnetsdk_config_declared_size(raw, 'net config')
    raw = raw[:effective_size]
    if len(raw) < _owner.HCNETSDK_NETCFG_V30_MIN_SIZE:
        raise _owner.PyEzvizError('EZVIZ LAN net config declared size is too small')
    ethernet: list[_owner_types.EzvizLanNetInterfaceConfig] = []
    offset = _owner.HCNETSDK_NETCFG_V30_ETHERNET_OFFSET
    for _ in range(_owner.HCNETSDK_NETCFG_V30_ETHERNET_COUNT):
        entry = raw[offset:offset + _owner.HCNETSDK_NETCFG_V30_ETHERNET_SIZE]
        ethernet.append(_owner.EzvizLanNetInterfaceConfig(ip_address=_owner._fixed_ipv4_text(entry[:_owner.HCNETSDK_NETCFG_V30_IP_SIZE]), subnet_mask=_owner._fixed_ipv4_text(entry[_owner.HCNETSDK_NETCFG_V30_IP_SIZE:_owner.HCNETSDK_NETCFG_V30_IP_SIZE * 2]), net_interface=int.from_bytes(entry[_owner.HCNETSDK_NETCFG_V30_ETHERNET_NET_INTERFACE_OFFSET:_owner.HCNETSDK_NETCFG_V30_ETHERNET_NET_INTERFACE_OFFSET + 4], 'big'), port=int.from_bytes(entry[_owner.HCNETSDK_NETCFG_V30_ETHERNET_PORT_OFFSET:_owner.HCNETSDK_NETCFG_V30_ETHERNET_PORT_OFFSET + 2], 'big'), mtu=int.from_bytes(entry[_owner.HCNETSDK_NETCFG_V30_ETHERNET_MTU_OFFSET:_owner.HCNETSDK_NETCFG_V30_ETHERNET_MTU_OFFSET + 2], 'big'), mac_address=_owner._mac_address_text(entry[_owner.HCNETSDK_NETCFG_V30_ETHERNET_MAC_OFFSET:_owner.HCNETSDK_NETCFG_V30_ETHERNET_MAC_OFFSET + 6])))
        offset += _owner.HCNETSDK_NETCFG_V30_ETHERNET_SIZE
    return _owner.EzvizLanNetConfigV30(declared_size=effective_size, ethernet=tuple(ethernet), manage_host_ip=_owner._fixed_ipv4_text(raw[_owner.HCNETSDK_NETCFG_V30_MANAGE_HOST_IP_OFFSET:_owner.HCNETSDK_NETCFG_V30_MANAGE_HOST_IP_OFFSET + _owner.HCNETSDK_NETCFG_V30_IP_SIZE]), manage_host_port=int.from_bytes(raw[_owner.HCNETSDK_NETCFG_V30_MANAGE_HOST_PORT_OFFSET:_owner.HCNETSDK_NETCFG_V30_MANAGE_HOST_PORT_OFFSET + 2], 'big'), ip_server_ip=_owner._fixed_ipv4_text(raw[_owner.HCNETSDK_NETCFG_V30_IP_SERVER_OFFSET:_owner.HCNETSDK_NETCFG_V30_IP_SERVER_OFFSET + _owner.HCNETSDK_NETCFG_V30_IP_SIZE]), multicast_ip=_owner._fixed_ipv4_text(raw[_owner.HCNETSDK_NETCFG_V30_MULTICAST_IP_OFFSET:_owner.HCNETSDK_NETCFG_V30_MULTICAST_IP_OFFSET + _owner.HCNETSDK_NETCFG_V30_IP_SIZE]), gateway_ip=_owner._fixed_ipv4_text(raw[_owner.HCNETSDK_NETCFG_V30_GATEWAY_IP_OFFSET:_owner.HCNETSDK_NETCFG_V30_GATEWAY_IP_OFFSET + _owner.HCNETSDK_NETCFG_V30_IP_SIZE]), nfs_ip=_owner._fixed_ipv4_text(raw[_owner.HCNETSDK_NETCFG_V30_NFS_IP_OFFSET:_owner.HCNETSDK_NETCFG_V30_NFS_IP_OFFSET + _owner.HCNETSDK_NETCFG_V30_IP_SIZE]), raw=raw)

def _hcnetsdk_config_declared_size(raw: bytes, label: str, *, _owner: _ModuleType) -> tuple[int, int]:
    """Return declared/effective size for traced DVR config body variants."""
    declared_size = int.from_bytes(raw[0:4], 'big')
    if declared_size == 0:
        return (declared_size, len(raw))
    if declared_size <= len(raw):
        return (declared_size, declared_size)
    shifted_size = int.from_bytes(raw[0:2], 'big')
    if raw[2:4] == _owner.HCNETSDK_SHIFTED_SIZE_ZERO_SUFFIX and 0 < shifted_size <= len(raw):
        return (shifted_size, shifted_size)
    raise _owner.PyEzvizError(f'EZVIZ LAN {label} response is truncated')

def ezviz_lan_dvr_config_summary(data: bytes | bytearray | memoryview, *, command: int, structure: str, _owner: _ModuleType) -> _owner_types.EzvizLanDvrConfigSummary:
    """Return a non-secret summary for a binary DVR config response."""
    raw = bytes(data)
    if len(raw) < 4:
        raise _owner.PyEzvizError('EZVIZ LAN DVR config response is too short')
    declared_size, effective_size = _owner._hcnetsdk_config_declared_size(raw, 'DVR config')
    if effective_size < 4:
        raise _owner.PyEzvizError('EZVIZ LAN DVR config declared size is too small')
    effective_raw = raw[:effective_size]
    return _owner.EzvizLanDvrConfigSummary(command=int(command), structure=structure, declared_size=declared_size, effective_size=effective_size, raw_length=len(raw), trailing_bytes=len(raw) - effective_size, nonzero_bytes=sum(1 for value in effective_raw if value))

def ezviz_lan_wifi_config_summary(data: bytes | bytearray | memoryview, *, _owner: _ModuleType) -> _owner_types.EzvizLanDvrConfigSummary:
    """Return a non-secret summary of a traced ``NET_DVR_WIFI_CFG`` buffer."""
    return _owner.ezviz_lan_dvr_config_summary(data, command=_owner.HcNetSdkDvrCommand.GET_WIFI_CFG, structure='NET_DVR_WIFI_CFG')

def ezviz_lan_ezviz_access_config_summary(data: bytes | bytearray | memoryview, *, _owner: _ModuleType) -> _owner_types.EzvizLanDvrConfigSummary:
    """Return a non-secret summary of a traced ``NET_DVR_EZVIZ_ACCESS_CFG``."""
    return _owner.ezviz_lan_dvr_config_summary(data, command=_owner.HcNetSdkDvrCommand.GET_EZVIZ_ACCESS_CFG, structure='NET_DVR_EZVIZ_ACCESS_CFG')

def ezviz_lan_ezviz_access_config(data: bytes | bytearray | memoryview, *, _owner: _ModuleType) -> _owner_types.EzvizLanEzvizAccessConfig:
    """Parse redacted ``NET_DVR_EZVIZ_ACCESS_CFG`` fields from command output."""
    raw = bytes(data)
    if len(raw) < 4:
        raise _owner.PyEzvizError('EZVIZ LAN access config response is too short')
    _declared_size, effective_size = _owner._hcnetsdk_config_declared_size(raw, 'EZVIZ access config')
    if effective_size < _owner.HCNETSDK_EZVIZ_ACCESS_CFG_SIZE:
        raise _owner.PyEzvizError('EZVIZ LAN access config declared size is too small')
    effective_raw = raw[:effective_size]
    verification = effective_raw[_owner.HCNETSDK_EZVIZ_ACCESS_CFG_VERIFICATION_OFFSET:_owner.HCNETSDK_EZVIZ_ACCESS_CFG_VERIFICATION_OFFSET + _owner.HCNETSDK_EZVIZ_ACCESS_CFG_VERIFICATION_SIZE]
    return _owner.EzvizLanEzvizAccessConfig(declared_size=effective_size, enabled=effective_raw[_owner.HCNETSDK_EZVIZ_ACCESS_CFG_ENABLE_OFFSET], device_status=effective_raw[_owner.HCNETSDK_EZVIZ_ACCESS_CFG_DEVICE_STATUS_OFFSET], allow_redirect=effective_raw[_owner.HCNETSDK_EZVIZ_ACCESS_CFG_ALLOW_REDIRECT_OFFSET], domain_name=_owner._nul_stripped_text(effective_raw[_owner.HCNETSDK_EZVIZ_ACCESS_CFG_DOMAIN_OFFSET:_owner.HCNETSDK_EZVIZ_ACCESS_CFG_DOMAIN_OFFSET + _owner.HCNETSDK_EZVIZ_ACCESS_CFG_DOMAIN_SIZE]), verification_code_present=any(verification), net_mode=effective_raw[_owner.HCNETSDK_EZVIZ_ACCESS_CFG_NET_MODE_OFFSET], raw_length=len(raw), trailing_bytes=len(raw) - effective_size)

def ezviz_lan_user_config_v30_summary(data: bytes | bytearray | memoryview, *, _owner: _ModuleType) -> _owner_types.EzvizLanDvrConfigSummary:
    """Return a non-secret summary of ``NET_DVR_USER_V30`` config output."""
    return _owner.ezviz_lan_dvr_config_summary(data, command=_owner.HcNetSdkDvrCommand.GET_USER_CFG_V30, structure='NET_DVR_USER_V30')

def ezviz_lan_user_config_v30(data: bytes | bytearray | memoryview, *, _owner: _ModuleType) -> _owner_types.EzvizLanUserConfigV30:
    """Decode a ``NET_DVR_USER_V30`` command-port response.

    The returned object contains usernames, passwords, and rights. Keep live
    outputs local and use synthetic fixtures in public tests/docs.
    """
    raw = bytes(data)
    if len(raw) < 4:
        raise _owner.PyEzvizError('EZVIZ LAN user config response is too short')
    _declared_size, effective_size = _owner._hcnetsdk_config_declared_size(raw, 'user config')
    if effective_size < _owner.HCNETSDK_USER_CFG_V30_MIN_SIZE:
        raise _owner.PyEzvizError('EZVIZ LAN user config declared size is too small')
    if effective_size > _owner.HCNETSDK_USER_CFG_V30_MAX_SIZE:
        raise _owner.PyEzvizError('EZVIZ LAN user config declared size is too large')
    payload_size = effective_size - 4
    if payload_size % _owner.HCNETSDK_USER_CFG_V30_ENTRY_SIZE:
        raise _owner.PyEzvizError('EZVIZ LAN user config entry table is misaligned')
    users = tuple(_owner._ezviz_lan_user_config_v30_entry(raw[4 + index * _owner.HCNETSDK_USER_CFG_V30_ENTRY_SIZE:4 + (index + 1) * _owner.HCNETSDK_USER_CFG_V30_ENTRY_SIZE], index) for index in range(payload_size // _owner.HCNETSDK_USER_CFG_V30_ENTRY_SIZE))
    return _owner.EzvizLanUserConfigV30(declared_size=effective_size, users=users, raw_length=len(raw), trailing_bytes=len(raw) - effective_size)

def _ezviz_lan_user_config_v30_entry(entry: bytes, index: int, *, _owner: _ModuleType) -> _owner_types.EzvizLanUserConfigV30Entry:
    """Parse one fixed-size ``NET_DVR_USER_INFO_V30`` record."""
    offset = 0

    def take(size: int) -> bytes:
        nonlocal offset
        value = entry[offset:offset + size]
        offset += size
        return value
    username = _owner._nul_stripped_text(take(_owner.HCNETSDK_USER_CFG_V30_USERNAME_SIZE))
    password_bytes = _owner._fixed_secret_bytes(take(_owner.HCNETSDK_USER_CFG_V30_PASSWORD_SIZE))
    password = _owner._fixed_secret_text(password_bytes)
    local_rights = _owner._byte_tuple(take(_owner.HCNETSDK_USER_CFG_V30_LOCAL_RIGHT_SIZE))
    remote_rights = _owner._byte_tuple(take(_owner.HCNETSDK_USER_CFG_V30_REMOTE_RIGHT_SIZE))
    net_preview_rights = _owner._byte_tuple(take(_owner.HCNETSDK_USER_CFG_V30_CHANNEL_RIGHT_SIZE))
    local_playback_rights = _owner._byte_tuple(take(_owner.HCNETSDK_USER_CFG_V30_CHANNEL_RIGHT_SIZE))
    net_playback_rights = _owner._byte_tuple(take(_owner.HCNETSDK_USER_CFG_V30_CHANNEL_RIGHT_SIZE))
    local_record_rights = _owner._byte_tuple(take(_owner.HCNETSDK_USER_CFG_V30_CHANNEL_RIGHT_SIZE))
    net_record_rights = _owner._byte_tuple(take(_owner.HCNETSDK_USER_CFG_V30_CHANNEL_RIGHT_SIZE))
    local_ptz_rights = _owner._byte_tuple(take(_owner.HCNETSDK_USER_CFG_V30_CHANNEL_RIGHT_SIZE))
    net_ptz_rights = _owner._byte_tuple(take(_owner.HCNETSDK_USER_CFG_V30_CHANNEL_RIGHT_SIZE))
    local_backup_rights = _owner._byte_tuple(take(_owner.HCNETSDK_USER_CFG_V30_CHANNEL_RIGHT_SIZE))
    user_ipv4 = _owner._fixed_ipv4_text(take(_owner.HCNETSDK_USER_CFG_V30_USER_IP_V4_SIZE))
    user_ipv6 = _owner._fixed_ipv4_text(take(_owner.HCNETSDK_USER_CFG_V30_USER_IP_V6_SIZE))
    mac_address = _owner._mac_address_text(take(_owner.HCNETSDK_USER_CFG_V30_MAC_SIZE))
    priority = take(1)[0]
    reserved = take(_owner.HCNETSDK_USER_CFG_V30_RESERVED_SIZE)
    return _owner.EzvizLanUserConfigV30Entry(index=index, username=username, password=password, password_bytes=password_bytes, local_rights=local_rights, remote_rights=remote_rights, net_preview_rights=net_preview_rights, local_playback_rights=local_playback_rights, net_playback_rights=net_playback_rights, local_record_rights=local_record_rights, net_record_rights=net_record_rights, local_ptz_rights=local_ptz_rights, net_ptz_rights=net_ptz_rights, local_backup_rights=local_backup_rights, user_ipv4=user_ipv4, user_ipv6=user_ipv6, mac_address=mac_address, priority=priority, reserved=reserved)

def ezviz_lan_device_config_v40(data: bytes | bytearray | memoryview, *, _owner: _ModuleType) -> _owner_types.EzvizLanDeviceConfigV40:
    """Parse known ``NET_DVR_DEVICECFG_V40`` fields from command-port output."""
    raw = bytes(data)
    if len(raw) < 4:
        raise _owner.PyEzvizError('EZVIZ LAN device V40 config response is too short')
    _declared_size, effective_size = _owner._hcnetsdk_config_declared_size(raw, 'device V40 config')
    raw = raw[:effective_size]
    if len(raw) < _owner.HCNETSDK_DEVICE_CFG_V40_MIN_SIZE:
        raise _owner.PyEzvizError('EZVIZ LAN device V40 config declared size is too small')

    def u32(offset: int) -> int:
        return int.from_bytes(raw[offset:offset + 4], 'big')
    return _owner.EzvizLanDeviceConfigV40(declared_size=effective_size, device_name=_owner._nul_stripped_text(raw[_owner.HCNETSDK_DEVICE_CFG_V40_NAME_OFFSET:_owner.HCNETSDK_DEVICE_CFG_V40_NAME_OFFSET + _owner.HCNETSDK_DEVICE_CFG_V40_NAME_SIZE]), dvr_id=u32(36), recycle_record=u32(40), serial_number=_owner._nul_stripped_text(raw[_owner.HCNETSDK_DEVICE_CFG_V40_SERIAL_OFFSET:_owner.HCNETSDK_DEVICE_CFG_V40_SERIAL_OFFSET + _owner.HCNETSDK_DEVICE_CFG_V40_SERIAL_SIZE]), software_version=u32(92), software_build_date=u32(96), dsp_software_version=u32(100), dsp_software_build_date=u32(104), panel_version=u32(108), hardware_version=u32(112), alarm_in_port_count=raw[116], alarm_out_port_count=raw[117], rs232_count=raw[118], rs485_count=raw[119], network_port_count=raw[120], disk_control_count=raw[121], disk_count=raw[122], dvr_type=raw[123], channel_count=raw[124], start_channel=raw[125], audio_count=raw[130], ip_channel_count=raw[131], device_type=int.from_bytes(raw[138:140], 'big'), device_type_name=_owner._nul_stripped_text(raw[_owner.HCNETSDK_DEVICE_CFG_V40_TYPE_NAME_OFFSET:_owner.HCNETSDK_DEVICE_CFG_V40_TYPE_NAME_OFFSET + _owner.HCNETSDK_DEVICE_CFG_V40_TYPE_NAME_SIZE]), raw=raw)

def ezviz_lan_record_config_v30(data: bytes | bytearray | memoryview, *, _owner: _ModuleType) -> _owner_types.EzvizLanRecordConfigV30:
    """Parse known ``NET_DVR_RECORD_V30`` fields from command-port output."""
    raw = bytes(data)
    if len(raw) < 4:
        raise _owner.PyEzvizError('EZVIZ LAN record config response is too short')
    _declared_size, effective_size = _owner._hcnetsdk_config_declared_size(raw, 'record config')
    raw = raw[:effective_size]
    if len(raw) < _owner.HCNETSDK_RECORD_CFG_V30_SIZE:
        raise _owner.PyEzvizError('EZVIZ LAN record config declared size is too small')
    all_day: list[_owner_types.EzvizLanRecordDayConfig] = []
    offset = _owner.HCNETSDK_RECORD_CFG_V30_ALL_DAY_OFFSET
    for day_index in range(_owner.HCNETSDK_RECORD_CFG_V30_DAY_COUNT):
        entry = raw[offset:offset + _owner.HCNETSDK_RECORD_CFG_V30_ALL_DAY_SIZE]
        all_day.append(_owner.EzvizLanRecordDayConfig(day_index=day_index, all_day_record=int.from_bytes(entry[0:2], 'big'), record_type=entry[2]))
        offset += _owner.HCNETSDK_RECORD_CFG_V30_ALL_DAY_SIZE
    schedule: list[tuple[_owner_types.EzvizLanRecordScheduleSegment, ...]] = []
    offset = _owner.HCNETSDK_RECORD_CFG_V30_SCHEDULE_OFFSET
    for day_index in range(_owner.HCNETSDK_RECORD_CFG_V30_DAY_COUNT):
        day_segments: list[_owner_types.EzvizLanRecordScheduleSegment] = []
        for segment_index in range(_owner.HCNETSDK_RECORD_CFG_V30_SEGMENTS_PER_DAY):
            entry = raw[offset:offset + _owner.HCNETSDK_RECORD_CFG_V30_SCHEDULE_SIZE]
            day_segments.append(_owner.EzvizLanRecordScheduleSegment(day_index=day_index, segment_index=segment_index, start_hour=entry[0], start_minute=entry[1], stop_hour=entry[2], stop_minute=entry[3], record_type=entry[4]))
            offset += _owner.HCNETSDK_RECORD_CFG_V30_SCHEDULE_SIZE
        schedule.append(tuple(day_segments))
    trailer = _owner.HCNETSDK_RECORD_CFG_V30_TRAILER_OFFSET
    return _owner.EzvizLanRecordConfigV30(declared_size=effective_size, record_enabled=int.from_bytes(raw[4:8], 'big'), all_day=tuple(all_day), schedule=tuple(schedule), record_time=int.from_bytes(raw[trailer:trailer + 4], 'big'), pre_record_time=int.from_bytes(raw[trailer + 4:trailer + 8], 'big'), recorder_duration=int.from_bytes(raw[trailer + 8:trailer + 12], 'big'), redundancy_record=raw[trailer + 12], audio_record=raw[trailer + 13], stream_type=raw[trailer + 14], passback_record=raw[trailer + 15], lock_duration=int.from_bytes(raw[trailer + 16:trailer + 18], 'big'), record_backup=raw[trailer + 18], svc_level=raw[trailer + 19], raw=raw)

def ezviz_lan_hd_config(data: bytes | bytearray | memoryview, *, _owner: _ModuleType) -> _owner_types.EzvizLanHdConfig:
    """Parse known ``NET_DVR_HDCFG`` fields from command-port output."""
    raw = bytes(data)
    if len(raw) < _owner.HCNETSDK_HD_CFG_MIN_SIZE:
        raise _owner.PyEzvizError('EZVIZ LAN HD config response is too short')
    _declared_size, effective_size = _owner._hcnetsdk_config_declared_size(raw, 'HD config')
    raw = raw[:effective_size]
    if len(raw) < _owner.HCNETSDK_HD_CFG_MIN_SIZE:
        raise _owner.PyEzvizError('EZVIZ LAN HD config declared size is too small')
    if len(raw) < _owner.HCNETSDK_HD_CFG_HEADER_SIZE:
        return _owner.EzvizLanHdConfig(declared_size=effective_size, raw=raw)
    disk_count = int.from_bytes(raw[4:8], 'big')
    if disk_count > _owner.HCNETSDK_HD_CFG_DISK_COUNT:
        raise _owner.PyEzvizError('EZVIZ LAN HD config disk count exceeds response capacity')
    required_size = _owner.HCNETSDK_HD_CFG_DISK_OFFSET + disk_count * _owner.HCNETSDK_HD_CFG_DISK_SIZE
    if required_size > len(raw):
        raise _owner.PyEzvizError('EZVIZ LAN HD config disk table is truncated')
    disks = tuple(_owner._ezviz_lan_hd_disk_config(raw[_owner.HCNETSDK_HD_CFG_DISK_OFFSET + index * _owner.HCNETSDK_HD_CFG_DISK_SIZE:_owner.HCNETSDK_HD_CFG_DISK_OFFSET + (index + 1) * _owner.HCNETSDK_HD_CFG_DISK_SIZE]) for index in range(disk_count))
    return _owner.EzvizLanHdConfig(declared_size=effective_size, raw=raw, disk_count=disk_count, disks=disks)

def _ezviz_lan_hd_disk_config(entry: bytes, *, _owner: _ModuleType) -> _owner_types.EzvizLanHdDiskConfig:
    """Parse one fixed-size ``NET_DVR_SINGLE_HD`` record."""

    def u32(offset: int) -> int:
        return int.from_bytes(entry[offset:offset + 4], 'big')
    return _owner.EzvizLanHdDiskConfig(hd_no=u32(_owner.HCNETSDK_HD_CFG_DISK_HD_NO_OFFSET), capacity=u32(_owner.HCNETSDK_HD_CFG_DISK_CAPACITY_OFFSET), free_space=u32(_owner.HCNETSDK_HD_CFG_DISK_FREE_SPACE_OFFSET), status=u32(_owner.HCNETSDK_HD_CFG_DISK_STATUS_OFFSET), attribute=entry[_owner.HCNETSDK_HD_CFG_DISK_ATTR_OFFSET], hd_type=entry[_owner.HCNETSDK_HD_CFG_DISK_TYPE_OFFSET], disk_driver=entry[_owner.HCNETSDK_HD_CFG_DISK_DRIVER_OFFSET], group=u32(_owner.HCNETSDK_HD_CFG_DISK_GROUP_OFFSET), recycling=entry[_owner.HCNETSDK_HD_CFG_DISK_RECYCLING_OFFSET], storage_type=u32(_owner.HCNETSDK_HD_CFG_DISK_STORAGE_TYPE_OFFSET), picture_capacity=u32(_owner.HCNETSDK_HD_CFG_DISK_PICTURE_CAPACITY_OFFSET), free_picture_space=u32(_owner.HCNETSDK_HD_CFG_DISK_FREE_PICTURE_SPACE_OFFSET))

def ezviz_lan_camera_param_config(data: bytes | bytearray | memoryview, *, _owner: _ModuleType) -> _owner_types.EzvizLanCameraParamConfig:
    """Parse known ``NET_DVR_CAMERAPARAMCFG`` fields from command-port output."""
    raw = bytes(data)
    if len(raw) < _owner.HCNETSDK_CAMERA_PARAM_CFG_MIN_SIZE:
        raise _owner.PyEzvizError('EZVIZ LAN camera-param response is too short')
    _declared_size, effective_size = _owner._hcnetsdk_config_declared_size(raw, 'camera-param')
    raw = raw[:effective_size]
    if len(raw) < _owner.HCNETSDK_CAMERA_PARAM_CFG_MIN_SIZE:
        raise _owner.PyEzvizError('EZVIZ LAN camera-param declared size is too small')
    return _owner.EzvizLanCameraParamConfig(declared_size=effective_size, brightness=raw[4], contrast=raw[5], sharpness=raw[6], saturation=raw[7], hue=raw[8], video_effect_enabled=raw[9], light_inhibit_level=raw[10], gray_level=raw[11], raw=raw)

def ezviz_lan_wifi_connect_status(data: bytes | bytearray | memoryview, *, _owner: _ModuleType) -> _owner_types.EzvizLanWifiConnectStatus:
    """Parse known ``NET_DVR_WIFI_CONNECT_STATUS`` fields from command output."""
    raw = bytes(data)
    if len(raw) < _owner.HCNETSDK_WIFI_CONNECT_STATUS_MIN_SIZE:
        raise _owner.PyEzvizError('EZVIZ LAN Wi-Fi status response is too short')
    _declared_size, effective_size = _owner._hcnetsdk_config_declared_size(raw, 'Wi-Fi status')
    raw = raw[:effective_size]
    if len(raw) < _owner.HCNETSDK_WIFI_CONNECT_STATUS_MIN_SIZE:
        raise _owner.PyEzvizError('EZVIZ LAN Wi-Fi status declared size is too small')
    return _owner.EzvizLanWifiConnectStatus(declared_size=effective_size, current_status=raw[4], error_code=int.from_bytes(raw[8:12], 'big') if len(raw) >= 12 else 0, raw=raw)

def ezviz_lan_audio_output_volume(data: bytes | bytearray | memoryview, *, _owner: _ModuleType) -> _owner_types.EzvizLanAudioOutputVolume:
    """Parse known ``NET_DVR_AUDIOOUT_VOLUME`` fields from command output."""
    raw = bytes(data)
    if len(raw) < _owner.HCNETSDK_AUDIOOUT_VOLUME_MIN_SIZE:
        raise _owner.PyEzvizError('EZVIZ LAN audio-output response is too short')
    _declared_size, effective_size = _owner._hcnetsdk_config_declared_size(raw, 'audio-output')
    raw = raw[:effective_size]
    if len(raw) < _owner.HCNETSDK_AUDIOOUT_VOLUME_MIN_SIZE:
        raise _owner.PyEzvizError('EZVIZ LAN audio-output declared size is too small')
    return _owner.EzvizLanAudioOutputVolume(declared_size=effective_size, volume=raw[4], raw=raw)

def ezviz_lan_compression_config(data: bytes | bytearray | memoryview, *, _owner: _ModuleType) -> _owner_types.EzvizLanCompressionConfig:
    """Parse known ``NET_DVR_COMPRESSIONCFG_V30`` fields from command output."""
    raw = bytes(data)
    if len(raw) < _owner.HCNETSDK_COMPRESSION_CFG_MIN_SIZE:
        raise _owner.PyEzvizError('EZVIZ LAN compression response is too short')
    _declared_size, effective_size = _owner._hcnetsdk_config_declared_size(raw, 'compression')
    raw = raw[:effective_size]
    if len(raw) < _owner.HCNETSDK_COMPRESSION_CFG_MIN_SIZE:
        raise _owner.PyEzvizError('EZVIZ LAN compression declared size is too small')
    normal_record = _owner._hcnetsdk_compression_info_v30(raw, _owner.HCNETSDK_COMPRESSION_CFG_NORMAL_OFFSET)
    if normal_record is None:
        raise _owner.PyEzvizError('EZVIZ LAN compression normal block is missing')
    return _owner.EzvizLanCompressionConfig(declared_size=effective_size, stream_type=normal_record.stream_type, resolution=normal_record.resolution, bitrate_type=normal_record.bitrate_type, picture_quality=normal_record.picture_quality, video_bitrate=normal_record.video_bitrate, video_frame_rate=normal_record.video_frame_rate, i_frame_interval=normal_record.i_frame_interval, video_encoding_type=normal_record.video_encoding_type, raw=raw)

def ezviz_lan_picture_config(data: bytes | bytearray | memoryview, *, _owner: _ModuleType) -> _owner_types.EzvizLanPictureConfig:
    """Parse known ``NET_DVR_PICCFG_V40`` fields from command output."""
    raw = bytes(data)
    if len(raw) < _owner.HCNETSDK_PIC_CFG_MIN_SIZE:
        raise _owner.PyEzvizError('EZVIZ LAN picture response is too short')
    _declared_size, effective_size = _owner._hcnetsdk_config_declared_size(raw, 'picture')
    raw = raw[:effective_size]
    if len(raw) < _owner.HCNETSDK_PIC_CFG_MIN_SIZE:
        raise _owner.PyEzvizError('EZVIZ LAN picture declared size is too small')
    return _owner.EzvizLanPictureConfig(declared_size=effective_size, channel_name=_owner._nul_stripped_text(raw[4:4 + _owner.HCNETSDK_PIC_CFG_CHANNEL_NAME_SIZE]), raw=raw)

def ezviz_lan_wifi_connect_status_request(login_id: int, *, channel: int, _owner: _ModuleType) -> _owner_types.HcNetSdkDvrConfigRequest:
    """Return the local Wi-Fi connection status request shape."""
    return _owner.hcnetsdk_dvr_config_get_request(login_id, _owner.HcNetSdkDvrCommand.GET_WIFI_CONNECT_STATUS, channel=channel, structure='NET_DVR_WIFI_CONNECT_STATUS')

def ezviz_lan_ezviz_access_get_config_request(login_id: int, *, _owner: _ModuleType) -> _owner_types.HcNetSdkDvrConfigRequest:
    """Return the local ``NET_DVR_EZVIZ_ACCESS_CFG`` read request shape."""
    return _owner.hcnetsdk_dvr_config_get_request(login_id, _owner.HcNetSdkDvrCommand.GET_EZVIZ_ACCESS_CFG, channel=1, structure='NET_DVR_EZVIZ_ACCESS_CFG')

def ezviz_lan_audio_input_get_config_request(login_id: int, channel: int, *, _owner: _ModuleType) -> _owner_types.HcNetSdkDvrConfigRequest:
    """Return the local audio-input config read request shape."""
    return _owner.hcnetsdk_dvr_config_get_request(login_id, _owner.HcNetSdkDvrCommand.GET_AUDIO_INPUT_PARAM, channel=channel, structure='NET_DVR_AUDIO_INPUT_PARAM')

def ezviz_lan_audioout_volume_get_config_request(login_id: int, channel: int, *, _owner: _ModuleType) -> _owner_types.HcNetSdkDvrConfigRequest:
    """Return the local audio-output volume read request shape."""
    return _owner.hcnetsdk_dvr_config_get_request(login_id, _owner.HcNetSdkDvrCommand.GET_AUDIOOUT_VOLUME, channel=channel, structure='NET_DVR_AUDIOOUT_VOLUME')

def ezviz_lan_audio_volume_update_requests(login_id: int, channel: int, *, input_volume: int, output_volume: int, _owner: _ModuleType) -> tuple[_owner_types.HcNetSdkDvrConfigRequest, _owner_types.HcNetSdkDvrConfigRequest]:
    """Return the two local audio-volume set calls made by the RN wrapper."""
    return (_owner.hcnetsdk_dvr_config_set_request(login_id, _owner.HcNetSdkDvrCommand.SET_AUDIO_INPUT_PARAM, channel=channel, structure='NET_DVR_AUDIO_INPUT_PARAM', field_updates={'byVolume': _owner._byte_value('audio input volume', input_volume)}, read_before_write=True), _owner.hcnetsdk_dvr_config_set_request(login_id, _owner.HcNetSdkDvrCommand.SET_AUDIOOUT_VOLUME, channel=channel, structure='NET_DVR_AUDIOOUT_VOLUME', field_updates={'byAudioOutVolume': _owner._byte_value('audio output volume', output_volume)}, read_before_write=True))

def ezviz_lan_video_coding_get_config_request(login_id: int, channel: int, *, _owner: _ModuleType) -> _owner_types.HcNetSdkDvrConfigRequest:
    """Return the local video-coding config read request shape."""
    return _owner.hcnetsdk_dvr_config_get_request(login_id, _owner.HcNetSdkDvrCommand.GET_COMPRESSION_CFG_V30, channel=channel, structure='NET_DVR_COMPRESSIONCFG_V30')

def ezviz_lan_pic_config_get_request(login_id: int, channel: int, *, _owner: _ModuleType) -> _owner_types.HcNetSdkDvrConfigRequest:
    """Return the local image/OSD config read request shape."""
    return _owner.hcnetsdk_dvr_config_get_request(login_id, _owner.HcNetSdkDvrCommand.GET_PIC_CFG_V40, channel=channel, structure='NET_DVR_PICCFG_V40')

def ezviz_lan_pic_config_v30_get_request(login_id: int, channel: int, *, _owner: _ModuleType) -> _owner_types.HcNetSdkDvrConfigRequest:
    """Return the traced legacy ``NET_DVR_PICCFG_V30`` read request shape."""
    return _owner.hcnetsdk_dvr_config_get_request(login_id, _owner.HcNetSdkDvrCommand.GET_PIC_CFG_V30, channel=channel, structure='NET_DVR_PICCFG_V30')

def ezviz_lan_pic_config_update_request(login_id: int, channel: int, *, show_osd: int | None, channel_name: str | bytes | None, _owner: _ModuleType) -> _owner_types.HcNetSdkDvrConfigRequest:
    """Return the RN LAN image/OSD update request shape."""
    updates: dict[str, _owner_types.Any] = {}
    if show_osd is not None:
        if show_osd < 0:
            raise _owner.PyEzvizError('EZVIZ LAN show_osd must be non-negative')
        updates['dwShowOsd'] = show_osd
    if channel_name is not None:
        name_bytes = _owner._bounded_bytes('channel name', channel_name, 32, truncate=True)
        updates['sChanName'] = name_bytes
        updates['sChanNameLength'] = len(name_bytes)
    return _owner.hcnetsdk_dvr_config_set_request(login_id, _owner.HcNetSdkDvrCommand.SET_PIC_CFG_V40, channel=channel, structure='NET_DVR_PICCFG_V40', field_updates=updates, read_before_write=True)

def ezviz_lan_hd_config_request(login_id: int, *, _owner: _ModuleType) -> _owner_types.HcNetSdkDvrConfigRequest:
    """Return the local storage ``NET_DVR_HDCFG`` read request shape."""
    return _owner.hcnetsdk_dvr_config_get_request(login_id, _owner.HcNetSdkDvrCommand.GET_HD_CFG, structure='NET_DVR_HDCFG')

def ezviz_lan_sd_format_start_request(login_id: int, disk_number: int, *, _owner: _ModuleType) -> _owner_types.HcNetSdkFormatDiskRequest:
    """Return the local SD-card format start request shape."""
    return _owner.HcNetSdkFormatDiskRequest(login_id=login_id, disk_number=disk_number)

def ezviz_lan_sd_format_progress_request(format_handle: int, *, _owner: _ModuleType) -> _owner_types.HcNetSdkFormatProgressRequest:
    """Return the local SD-card format progress request shape."""
    return _owner.HcNetSdkFormatProgressRequest(format_handle=format_handle)

def ezviz_lan_sd_format_close_request(format_handle: int, *, _owner: _ModuleType) -> _owner_types.HcNetSdkCloseFormatHandleRequest:
    """Return the local SD-card format close request shape."""
    return _owner.HcNetSdkCloseFormatHandleRequest(format_handle=format_handle)

def ezviz_lan_sd_format_progress_result(*, native_succeeded: bool, current_disk: int, current_disk_position: int, status: int, last_error: int, _owner: _ModuleType) -> _owner_types.EzvizLanSdFormatProgress:
    """Map native SD format progress references to the RN result semantics."""
    if not native_succeeded:
        return _owner.EzvizLanSdFormatProgress(code=last_error, current_disk=current_disk, progress=None, status=status, done=False)
    if status == 0:
        return _owner.EzvizLanSdFormatProgress(code=0, current_disk=current_disk, progress=current_disk_position, status=status, done=False)
    if status == 1:
        return _owner.EzvizLanSdFormatProgress(code=0, current_disk=current_disk, progress=100, status=status, done=True)
    return _owner.EzvizLanSdFormatProgress(code=last_error or -1, current_disk=current_disk, progress=None, status=status, done=False)

def ezviz_hcnetsdk_local_ptz_without_recv_request(*, without_recv: int | bool, _owner: _ModuleType) -> _owner_types.HcNetSdkSetSdkLocalCfgRequest:
    """Return the SDK-local PTZ no-receive config exposed by the APK."""
    return _owner.hcnetsdk_set_sdk_local_cfg_request(_owner.HcNetSdkLocalCfgType.PTZ, structure='NET_DVR_LOCAL_PTZ_CFG', field_updates={'byWithoutRecv': _owner._byte_value('PTZ without-receive', int(without_recv))}, field_order=_owner.HCNETSDK_LOCAL_PTZ_CFG_FIELD_ORDER)

def ezviz_lan_user_password_get_config_request(login_id: int, *, _owner: _ModuleType) -> _owner_types.HcNetSdkDvrConfigRequest:
    """Return the local ``NET_DVR_USER_V30`` read request shape."""
    return _owner.hcnetsdk_dvr_config_get_request(login_id, _owner.HcNetSdkDvrCommand.GET_USER_CFG_V30, structure='NET_DVR_USER_V30')

def ezviz_lan_video_effect_get_config_request(login_id: int, channel: int, *, _owner: _ModuleType) -> _owner_types.HcNetSdkDvrConfigRequest:
    """Return the local camera video-effect config read request shape."""
    return _owner.hcnetsdk_dvr_config_get_request(login_id, _owner.HcNetSdkDvrCommand.GET_CAMERA_PARAM_CFG, channel=channel, structure='NET_DVR_CAMERAPARAMCFG')

def ezviz_lan_backlight_wdr_get_config_request(login_id: int, channel: int, *, _owner: _ModuleType) -> _owner_types.HcNetSdkDvrConfigRequest:
    """Return the local WDR/backlight config read request shape."""
    return _owner.ezviz_lan_video_effect_get_config_request(login_id, channel=channel)

def ezviz_lan_backlight_wdr_update_request(login_id: int, *, wdr_enabled: int, backlight_mode: int, _owner: _ModuleType) -> _owner_types.HcNetSdkDvrConfigRequest:
    """Return the RN LAN WDR/backlight update request shape."""
    return _owner.hcnetsdk_dvr_config_set_request(login_id, _owner.HcNetSdkDvrCommand.SET_CAMERA_PARAM_CFG, structure='NET_DVR_CAMERAPARAMCFG', field_updates={'struWdr.byWDREnabled': _owner._byte_value('WDR enabled', wdr_enabled), 'struBackLight.byBacklightMode': _owner._byte_value('backlight mode', backlight_mode)}, read_before_write=True)

def ezviz_lan_day_night_get_config_request(login_id: int, channel: int, *, _owner: _ModuleType) -> _owner_types.HcNetSdkDvrConfigRequest:
    """Return the local day/night config read request shape."""
    return _owner.ezviz_lan_video_effect_get_config_request(login_id, channel=channel)

def ezviz_lan_day_night_update_request(login_id: int, *, day_night_filter_type: int, begin_time: int, begin_time_min: int, begin_time_sec: int, end_time: int, end_time_min: int, end_time_sec: int, night_to_day_filter_level: int, _owner: _ModuleType) -> _owner_types.HcNetSdkDvrConfigRequest:
    """Return the RN LAN day/night update request shape."""
    return _owner.hcnetsdk_dvr_config_set_request(login_id, _owner.HcNetSdkDvrCommand.SET_CAMERA_PARAM_CFG, structure='NET_DVR_CAMERAPARAMCFG', field_updates={'struDayNight.byDayNightFilterType': _owner._byte_value('day/night filter type', day_night_filter_type), 'struDayNight.byBeginTime': _owner._byte_value('day/night begin hour', begin_time), 'struDayNight.byBeginTimeMin': _owner._byte_value('day/night begin minute', begin_time_min), 'struDayNight.byBeginTimeSec': _owner._byte_value('day/night begin second', begin_time_sec), 'struDayNight.byEndTime': _owner._byte_value('day/night end hour', end_time), 'struDayNight.byEndTimeMin': _owner._byte_value('day/night end minute', end_time_min), 'struDayNight.byEndTimeSec': _owner._byte_value('day/night end second', end_time_sec), 'struDayNight.byNightToDayFilterLevel': _owner._byte_value('night-to-day filter level', night_to_day_filter_level)}, read_before_write=True)

def hcnetsdk_device_ability_xml(root: str, *, channel: int | str | None, channel_tag: str, version: str | None, _owner: _ModuleType) -> bytes:
    """Return compact XML passed as ``NET_DVR_GetDeviceAbility`` input."""
    element = _owner.ET.Element(_owner._device_ability_xml_name('root', root))
    if version is not None:
        element.set('version', version)
    if channel is not None:
        child = _owner.ET.SubElement(element, _owner._device_ability_xml_name('channel tag', channel_tag))
        child.text = str(channel)
    return _owner.ET.tostring(element, encoding='utf-8', short_empty_elements=True)

def hcnetsdk_device_ability_request(login_id: int, ability_type: int, *, in_buffer: str | bytes | None, output_buffer_size: int, retry_output_buffer_size: int | None, _owner: _ModuleType) -> _owner_types.HcNetSdkDeviceAbilityRequest:
    """Return a ``NET_DVR_GetDeviceAbility`` request model."""
    return _owner.HcNetSdkDeviceAbilityRequest(login_id=login_id, ability_type=int(ability_type), in_buffer=in_buffer, output_buffer_size=output_buffer_size, retry_output_buffer_size=retry_output_buffer_size)

def ezviz_lan_record_ability_input(*, _owner: _ModuleType) -> bytes:
    """Return the playback conversion ability XML used by ``DeviceAbilityHelper``."""
    return _owner.hcnetsdk_device_ability_xml('RecordAbility')

def ezviz_lan_ptz_ability_input(channel: int, *, _owner: _ModuleType) -> bytes:
    """Return the PTZ ability XML used by ``DeviceAbilityHelper.c``."""
    return _owner.hcnetsdk_device_ability_xml('PTZAbility', channel=channel)

def ezviz_lan_image_display_param_ability_input(channel: int, *, _owner: _ModuleType) -> bytes:
    """Return the image-display ability XML used by the RN LAN wrapper.

    Live devices may acknowledge this request with an empty body. The image
    parameter ranges used by the app are available through ``IPC_FRONT_PARAMETER``.
    """
    return _owner.hcnetsdk_device_ability_xml('ImageDisplayParamAbility', channel=channel)

def ezviz_lan_video_pic_ability_input(channel: int, *, _owner: _ModuleType) -> bytes:
    """Return the video-picture ability XML used by the RN LAN wrapper."""
    return _owner.hcnetsdk_device_ability_xml('VideoPicAbility', channel=channel)

def ezviz_lan_access_protocol_ability_input(channel: int | str, *, _owner: _ModuleType) -> bytes:
    """Return the access-protocol ability XML used by local-add setup."""
    return _owner.hcnetsdk_device_ability_xml('AccessProtocolAbility', channel=channel)

def ezviz_lan_rn_device_ability_request(login_id: int, ability_type: int, *, in_buffer: str | bytes | None, _owner: _ModuleType) -> _owner_types.HcNetSdkDeviceAbilityRequest:
    """Return the generic 2 MiB RN LAN ``NET_DVR_GetDeviceAbility`` shape."""
    return _owner.hcnetsdk_device_ability_request(login_id, ability_type, in_buffer=in_buffer, output_buffer_size=_owner.HCNETSDK_DEVICE_ABILITY_RN_OUTPUT_BUFFER_SIZE, retry_output_buffer_size=None)

def ezviz_lan_access_protocol_ability_request(login_id: int, channel: int | str, *, _owner: _ModuleType) -> _owner_types.HcNetSdkDeviceAbilityRequest:
    """Return the access-protocol ability request used by local-add setup."""
    return _owner.hcnetsdk_device_ability_request(login_id, _owner.HcNetSdkAbility.DEVICE_ABILITY_INFO, in_buffer=_owner.ezviz_lan_access_protocol_ability_input(channel))

def ezviz_lan_image_display_param_ability_request(login_id: int, channel: int, *, _owner: _ModuleType) -> _owner_types.HcNetSdkDeviceAbilityRequest:
    """Return the RN LAN image-display ability request shape.

    Prefer ``ezviz_lan_ipc_front_parameter_ability_request`` for a live
    ``CAMERAPARA`` response containing image parameter ranges.
    """
    return _owner.ezviz_lan_rn_device_ability_request(login_id, _owner.HcNetSdkAbility.DEVICE_ABILITY_INFO, in_buffer=_owner.ezviz_lan_image_display_param_ability_input(channel))

def ezviz_lan_video_pic_ability_request(login_id: int, channel: int, *, _owner: _ModuleType) -> _owner_types.HcNetSdkDeviceAbilityRequest:
    """Return the RN LAN video-picture ability request shape."""
    return _owner.ezviz_lan_rn_device_ability_request(login_id, _owner.HcNetSdkAbility.DEVICE_VIDEOPIC, in_buffer=_owner.ezviz_lan_video_pic_ability_input(channel))

def ezviz_lan_audio_video_compress_info_ability_request(login_id: int, channel: int, *, _owner: _ModuleType) -> _owner_types.HcNetSdkDeviceAbilityRequest:
    """Return the stream-config audio/video ability request shape."""
    return _owner.hcnetsdk_device_ability_request(login_id, _owner.HcNetSdkAbility.DEVICE_ENCODE_ALL_V20, in_buffer=_owner.ezviz_lan_audio_video_compress_info_input(channel))

def ezviz_lan_soft_hardware_ability_request(login_id: int, *, _owner: _ModuleType) -> _owner_types.HcNetSdkDeviceAbilityRequest:
    """Return the device software/hardware ability request shape."""
    return _owner.hcnetsdk_device_ability_request(login_id, _owner.HcNetSdkAbility.DEVICE_SOFT_HARDWARE, in_buffer=None)

def ezviz_lan_record_ability_request(login_id: int, *, _owner: _ModuleType) -> _owner_types.HcNetSdkDeviceAbilityRequest:
    """Return the record/playback conversion ability request shape."""
    return _owner.hcnetsdk_device_ability_request(login_id, _owner.HcNetSdkAbility.DEVICE_ABILITY_INFO, in_buffer=_owner.ezviz_lan_record_ability_input())

def ezviz_lan_ptz_ability_request(login_id: int, channel: int, *, _owner: _ModuleType) -> _owner_types.HcNetSdkDeviceAbilityRequest:
    """Return the local PTZ ability request shape used by the Android app."""
    return _owner.hcnetsdk_device_ability_request(login_id, _owner.HcNetSdkAbility.DEVICE_ABILITY_INFO, in_buffer=_owner.ezviz_lan_ptz_ability_input(channel))

def ezviz_lan_ipc_front_parameter_ability_request(login_id: int, *, _owner: _ModuleType) -> _owner_types.HcNetSdkDeviceAbilityRequest:
    """Return the local IPC-front-parameter request used for mirror ability."""
    return _owner.hcnetsdk_device_ability_request(login_id, _owner.HcNetSdkAbility.IPC_FRONT_PARAMETER, in_buffer=None)

def ezviz_lan_ptz_ability(response: str | bytes, *, _owner: _ModuleType) -> _owner_types.EzvizLanPtzAbility:
    """Parse the PTZ ability fields read by EZVIZ's ``PTZAbilityHandler``."""
    try:
        root = _owner.ET.fromstring(_owner._device_ability_response_text(response))
    except _owner.ET.ParseError as err:
        raise _owner.PyEzvizError('Invalid EZVIZ LAN PTZ ability XML') from err
    return _owner.EzvizLanPtzAbility(control_types=_owner._xml_opt_attr(root, 'controlType'), park_action_types=_owner._xml_opt_attr(root, 'actionType', parent='ParkAction'), schedule_task_types=_owner._xml_opt_attr(root, 'actionType', parent='SchduleTask') or _owner._xml_opt_attr(root, 'actionType', parent='ScheduleTask'), privacy_mask_enable=_owner._xml_bool_opt_attr(root, 'globalEnable'), mirror_range=_owner._xml_child_text(root, ('Mirror', 'Range')))

def ezviz_lan_access_protocol_ability(response: str | bytes, *, _owner: _ModuleType) -> _owner_types.EzvizLanAccessProtocolAbility:
    """Parse safe local-add fields from ``AccessProtocolAbility`` XML."""
    try:
        root = _owner.ET.fromstring(_owner._device_ability_response_text(response))
    except _owner.ET.ParseError as err:
        raise _owner.PyEzvizError('Invalid EZVIZ LAN access-protocol ability XML') from err
    return _owner.EzvizLanAccessProtocolAbility(channel_no=_owner._xml_descendant_text(root, 'channelNO'), enable_options=_owner._xml_attr(root, 'enable', 'opt', parent='EzvizParam'), device_status_options=_owner._xml_attr(root, 'deviceStatus', 'opt', parent='EzvizParam'), allow_redirect_options=_owner._xml_attr(root, 'allowRedirect', 'opt', parent='EzvizParam'), domain_length_min=_owner._xml_attr_int(root, 'domainLen', 'min', parent='EzvizParam'), domain_length_max=_owner._xml_attr_int(root, 'domainLen', 'max', parent='EzvizParam'), has_ezviz_param=_owner._xml_has_descendant(root, 'EzvizParam'))

def ezviz_lan_video_pic_ability(response: str | bytes, *, _owner: _ModuleType) -> _owner_types.EzvizLanVideoPicAbility:
    """Parse safe OSD/motion fields from ``VideoPicAbility`` XML."""
    try:
        root = _owner.ET.fromstring(_owner._device_ability_response_text(response))
    except _owner.ET.ParseError as err:
        raise _owner.PyEzvizError('Invalid EZVIZ LAN video-picture ability XML') from err
    return _owner.EzvizLanVideoPicAbility(channel_no=_owner._xml_descendant_text(root, 'channelNO'), channel_name_enabled=_owner._xml_descendant_bool_text(root, 'enabled', parent='ChannelName', default=False), week_enabled=_owner._xml_descendant_bool_text(root, 'enabled', parent='Week'), osd_type_options=_owner._xml_attr(root, 'OSDType', 'opt', parent='OSD'), osd_attribute_options=_owner._xml_attr(root, 'OSDAttrib', 'opt', parent='OSD'), osd_hour_type_options=_owner._xml_attr(root, 'OSDHourType', 'opt', parent='OSD'), motion_region_type_options=_owner._xml_attr(root, 'regionType', 'opt', parent='MotionDetection'), motion_grid_row_granularity=_owner._xml_descendant_int(root, 'rowGranularity', parent='VideoFormatP'), motion_grid_column_granularity=_owner._xml_descendant_int(root, 'columnGranularity', parent='VideoFormatP'))

def ezviz_lan_ipc_front_parameter_ability(response: str | bytes, *, _owner: _ModuleType) -> _owner_types.EzvizLanIpcFrontParameterAbility:
    """Parse safe image/front-parameter ranges from ``CAMERAPARA`` XML."""
    try:
        root = _owner.ET.fromstring(_owner._device_ability_response_text(response))
    except _owner.ET.ParseError as err:
        raise _owner.PyEzvizError('Invalid EZVIZ LAN IPC front-parameter XML') from err
    field_root = _owner._ipc_front_parameter_field_root(root)
    return _owner.EzvizLanIpcFrontParameterAbility(has_camera_para=_owner._xml_local_name(root).lower() == 'camerapara', power_line_frequency_mode_range=_owner._xml_child_text(field_root, ('PowerLineFrequencyMode', 'Range')), white_balance_mode_range=_owner._xml_child_text(field_root, ('WhiteBalance', 'WhiteBalanceMode', 'Range')), exposure_mode_range=_owner._xml_child_text(field_root, ('Exposure', 'ExposureMode', 'Range')), exposure_set_range=_owner._xml_child_text(field_root, ('Exposure', 'ExposureSet', 'Range')), exposure_user_set=_owner._xml_child_int_range(field_root, ('Exposure', 'exposureUSERSET')), gain_level=_owner._xml_child_int_range(field_root, ('GainLevel',)), brightness_level=_owner._xml_child_int_range(field_root, ('BrightnessLevel',)), contrast_level=_owner._xml_child_int_range(field_root, ('ContrastLevel',)), sharpness_level=_owner._xml_child_int_range(field_root, ('SharpnessLevel',)), saturation_level=_owner._xml_child_int_range(field_root, ('SaturationLevel',)), day_night_filter_type_range=_owner._xml_child_text(field_root, ('DayNightFilter', 'DayNightFilterType', 'Range')), switch_schedule_enabled_range=_owner._xml_child_text(field_root, ('DayNightFilter', 'SwitchSchedule', 'SwitchScheduleEnabled', 'Range')), day_to_night_filter_level_range=_owner._xml_child_text(field_root, ('DayNightFilter', 'SwitchSchedule', 'DayToNightFilterLevel', 'Range')), night_to_day_filter_level_range=_owner._xml_child_text(field_root, ('DayNightFilter', 'SwitchSchedule', 'NightToDayFilterLevel', 'Range')), day_night_filter_time=_owner._xml_child_int_range(field_root, ('DayNightFilter', 'SwitchSchedule', 'DayNightFilterTime')), backlight_mode_range=_owner._xml_child_text(field_root, ('Backlight', 'BacklightMode', 'Range')), mirror_range=_owner._xml_child_text(field_root, ('Mirror', 'Range')), digital_noise_reduction_enable_range=_owner._xml_child_text(field_root, ('DigitalNoiseReduction', 'DigitalNoiseReductionEnable', 'Range')), digital_noise_reduction_level=_owner._xml_child_int_range(field_root, ('DigitalNoiseReduction', 'DigitalNoiseReductionLevel')), digital_noise_spectral_level=_owner._xml_child_int_range(field_root, ('DigitalNoiseReduction', 'DigitalNoiseSpectralLevel')), digital_noise_temporal_level=_owner._xml_child_int_range(field_root, ('DigitalNoiseReduction', 'DigitalNoiseTemporalLevel')))

def ezviz_lan_soft_hardware_ability(response: str | bytes, *, _owner: _ModuleType) -> _owner_types.EzvizLanDeviceSoftHardwareAbility:
    """Parse ``DEVICE_SOFTHARDWARE_ABILITY`` fields used by the app."""
    try:
        root = _owner.ET.fromstring(_owner._device_ability_response_text(response))
    except _owner.ET.ParseError as err:
        raise _owner.PyEzvizError('Invalid EZVIZ LAN soft/hardware ability XML') from err
    has_software = _owner._xml_has_descendant(root, 'SoftwareCapability')
    has_hardware = _owner._xml_has_descendant(root, 'HardwareCapability')
    return _owner.EzvizLanDeviceSoftHardwareAbility(max_preview_num=_owner._xml_descendant_int(root, 'MaxPreviewNum', parent='SoftwareCapability'), ptz_support=_owner._xml_descendant_int(root, 'PtzSupport', parent='SoftwareCapability'), support_timing=_owner._xml_descendant_bool_text(root, 'isSupportLoginTiming', parent='SoftwareCapability'), sd_num=_owner._xml_descendant_int(root, 'SDNum', parent='HardwareCapability'), hard_disk_num=_owner._xml_descendant_int(root, 'HardDiskNum', parent='HardwareCapability'), has_software_capability=has_software, has_hardware_capability=has_hardware)

def ezviz_lan_playback_convert_ability(response: str | bytes, *, _owner: _ModuleType) -> _owner_types.EzvizLanPlaybackConvertAbility:
    """Parse playback conversion entries from ``RecordAbility`` XML."""
    try:
        root = _owner.ET.fromstring(_owner._device_ability_response_text(response))
    except _owner.ET.ParseError as err:
        raise _owner.PyEzvizError('Invalid EZVIZ LAN playback ability XML') from err
    resolutions: list[_owner_types.EzvizLanPlaybackConvertResolution] = []
    for entry in root.iter():
        if _owner._xml_local_name(entry).lower() != 'videoresolutionentry':
            continue
        resolutions.append(_owner.EzvizLanPlaybackConvertResolution(index=_owner._xml_descendant_int(entry, 'Index'), frame_rates=_owner._xml_int_csv(_owner._xml_child_text(entry, ('VideoFrameRate',))), bitrates=_owner._xml_int_csv(_owner._xml_child_text(entry, ('VideoBitrate', 'Range')))))
    return _owner.EzvizLanPlaybackConvertAbility(resolutions=tuple(resolutions))

def ezviz_cas_ptz_command(command: int, *, _owner: _ModuleType) -> str:
    """Return the CAS/cloud PTZ command string used by the EZVIZ app."""
    command_id = _owner._ptz_int('EZVIZ PTZ command', command)
    return _owner.EZVIZ_CAS_PTZ_COMMAND_MAP.get(command_id, '')

def ezviz_lan_ptz_native_command(command: int, *, _owner: _ModuleType) -> int:
    """Return the HCNetSDK LAN PTZ value for an EZVIZ app command ID."""
    command_id = _owner._ptz_int('EZVIZ LAN PTZ command', command)
    native = _owner.EZVIZ_LAN_PTZ_COMMAND_MAP.get(command_id)
    if native is None:
        raise _owner.PyEzvizError(f'Unsupported EZVIZ LAN PTZ command: {command_id}')
    return native

def ezviz_lan_ptz_is_preset_command(command: int, *, _owner: _ModuleType) -> bool:
    """Return whether the app routes this PTZ command through the preset API."""
    command_id = _owner._ptz_int('EZVIZ LAN PTZ command', command)
    return command_id in _owner.EZVIZ_LAN_PTZ_PRESET_COMMANDS

def ezviz_lan_ptz_control_request(login_id: int, channel: int, command: int, *, action: int, speed: int, _owner: _ModuleType) -> _owner_types.HcNetSdkPtzControlRequest:
    """Return the APK-observed local PTZ control call for non-preset commands."""
    if _owner.ezviz_lan_ptz_is_preset_command(command):
        raise _owner.PyEzvizError('Use ezviz_lan_ptz_preset_request for preset commands')
    return _owner.HcNetSdkPtzControlRequest(login_id=login_id, channel=channel, command=_owner.ezviz_lan_ptz_native_command(command), stop=_owner.ezviz_lan_ptz_native_command(action), speed=speed)

def ezviz_lan_ptz_preset_request(login_id: int, channel: int, command: int, *, preset_index: int, _owner: _ModuleType) -> _owner_types.HcNetSdkPtzPresetRequest:
    """Return the APK-observed local PTZ preset call shape."""
    if not _owner.ezviz_lan_ptz_is_preset_command(command):
        raise _owner.PyEzvizError('EZVIZ LAN PTZ command is not a preset command')
    return _owner.HcNetSdkPtzPresetRequest(login_id=login_id, channel=channel, command=_owner.ezviz_lan_ptz_native_command(command), preset_index=preset_index)

def ezviz_lan_ptz_request(login_id: int, channel: int, command: int, *, action: int, speed: int, preset_index: int, _owner: _ModuleType) -> _owner_types.HcNetSdkPtzControlRequest | _owner_types.HcNetSdkPtzPresetRequest:
    """Return the same PTZ native-call branch used by ``ptzControlLan``."""
    if _owner.ezviz_lan_ptz_is_preset_command(command):
        return _owner.ezviz_lan_ptz_preset_request(login_id, channel, command, preset_index=preset_index)
    return _owner.ezviz_lan_ptz_control_request(login_id, channel, command, action=action, speed=speed)

def hcnetsdk_device_ability_command_port_body_tail(request: _owner_types.HcNetSdkDeviceAbilityRequest, *, _owner: _ModuleType) -> bytes:
    """Return the pure command-port tail for ``NET_DVR_GetDeviceAbility``."""
    if request.ability_type < 0:
        raise _owner.PyEzvizError('HCNetSDK device ability type must be non-negative')
    return int(request.ability_type).to_bytes(4, 'big') + request.in_buffer_bytes

def hcnetsdk_device_ability_command_port_template(request: _owner_types.HcNetSdkDeviceAbilityRequest, *, addend_delta: int | None, addend: int | None, name: str | None, _owner: _ModuleType) -> _owner_types.HcNetSdkCommandPortControlTemplate:
    """Return a generated command-port template for ``NET_DVR_GetDeviceAbility``."""
    return _owner.HcNetSdkCommandPortControlTemplate(command_id=69632, body_tail=_owner.hcnetsdk_device_ability_command_port_body_tail(request), addend=addend, addend_delta=addend_delta, name=name or _owner.HCNETSDK_GET_DEVICE_ABILITY)

def hcnetsdk_dvr_config_command_port_template(request: _owner_types.HcNetSdkDvrConfigRequest, *, command_id: int | None, body_tail: bytes | None, addend_delta: int | None, addend: int | None, name: str | None, _owner: _ModuleType) -> _owner_types.HcNetSdkCommandPortControlTemplate:
    """Return a traced command-port template for ``NET_DVR_GetDVRConfig``.

    ``NET_DVR_GetDVRConfig`` does not carry the public SDK ``dwCommand`` value
    directly on the wire. Native traces show each config surface dispatching to
    a device-protocol command id, so unknown config commands must be supplied
    explicitly until traced.
    """
    request.to_native_args_hint()
    if request.api != _owner.HCNETSDK_GET_DVR_CONFIG:
        raise _owner.PyEzvizError('Pure command-port DVR config currently supports GET only')
    protocol_command = command_id
    if protocol_command is None:
        protocol_command = _owner.HCNETSDK_DVR_CONFIG_COMMAND_PORT_COMMAND_IDS.get(int(request.command))
    if protocol_command is None:
        raise _owner.PyEzvizError(f'HCNetSDK DVR config command-port id is unknown for dwCommand {int(request.command)}')
    if protocol_command < 0:
        raise _owner.PyEzvizError('HCNetSDK DVR config command-port id must be non-negative')
    command_tail = body_tail
    if command_tail is None:
        command_tail = _owner.hcnetsdk_dvr_config_command_port_body_tail(request)
    return _owner.HcNetSdkCommandPortControlTemplate(command_id=protocol_command, body_tail=command_tail, addend=addend, addend_delta=addend_delta, name=name or f'{_owner.HCNETSDK_GET_DVR_CONFIG}:{int(request.command)}')

def hcnetsdk_dvr_config_command_port_body_tail(request: _owner_types.HcNetSdkDvrConfigRequest, *, _owner: _ModuleType) -> bytes:
    """Return the traced command-port body tail for a DVR config request."""
    if int(request.command) == _owner.HcNetSdkDvrCommand.GET_CAMERA_PARAM_CFG:
        if request.channel != 1:
            raise _owner.PyEzvizError('HCNetSDK camera-param command-port read is traced for channel 1')
        return b''
    if int(request.command) not in _owner.HCNETSDK_DVR_CONFIG_CHANNEL_TAIL_COMMANDS:
        return b''
    if request.channel < 0:
        raise _owner.PyEzvizError('HCNetSDK DVR config command-port channel tail requires a channel')
    if request.channel > 4294967295:
        raise _owner.PyEzvizError('HCNetSDK DVR config command-port channel is too large')
    return int(request.channel).to_bytes(4, 'big')

def hcnetsdk_stdxml_config_command_port_body_tail(request: _owner_types.HcNetSdkStdXmlConfigRequest | str | bytes, *, _owner: _ModuleType) -> bytes:
    """Return the traced command-port tail for ``NET_DVR_STDXMLConfig``.

    A live Android SDK trace showed STDXML using the generated command-port
    control frame with command ``0x117000``, eight extra reserved bytes, a
    twelve-byte request descriptor, and then the request/in-buffer bytes.
    """
    config = request if isinstance(request, _StaticHcNetSdkStdXmlConfigRequest) else _owner.hcnetsdk_stdxml_config_request(request)
    payload = config.request_bytes + config.in_buffer_bytes
    total_length = _owner.HCNETSDK_STDXML_COMMAND_PORT_PREFIX_SIZE + len(payload)
    return b''.join((b'\x00' * _owner.HCNETSDK_STDXML_COMMAND_PORT_EXTRA_RESERVED_SIZE, total_length.to_bytes(4, 'big'), len(config.request_bytes).to_bytes(4, 'big'), _owner.HCNETSDK_STDXML_COMMAND_PORT_FLAGS, payload))

def hcnetsdk_stdxml_config_command_port_template(request: _owner_types.HcNetSdkStdXmlConfigRequest | str | bytes, *, command_id: int, body_prefix: str | bytes | None, addend_delta: int | None, addend: int | None, name: str | None, _owner: _ModuleType) -> _owner_types.HcNetSdkCommandPortControlTemplate:
    """Return a generated command-port template for ``NET_DVR_STDXMLConfig``."""
    config = request if isinstance(request, _StaticHcNetSdkStdXmlConfigRequest) else _owner.hcnetsdk_stdxml_config_request(request)
    if command_id < 0:
        raise _owner.PyEzvizError('HCNetSDK STDXML command id must be non-negative')
    if body_prefix is None:
        body_tail = _owner.hcnetsdk_stdxml_config_command_port_body_tail(config)
    else:
        body_tail = _owner._stdxml_bytes('command-port body prefix', body_prefix)
        body_tail += config.request_bytes
        body_tail += config.in_buffer_bytes
    return _owner.HcNetSdkCommandPortControlTemplate(command_id=command_id, body_tail=body_tail, addend=addend, addend_delta=addend_delta, name=name or _owner.HCNETSDK_STDXML_CONFIG)

def hcnetsdk_get_device_ability_command_port(endpoint: _owner_types.HcNetSdkLanEndpoint, password: str | bytes, request: _owner_types.HcNetSdkDeviceAbilityRequest, *, username: str, local_ip: str | None, timeout: float | None, socket_factory: _owner_types.SocketFactory, rsa_key: _owner_types.Any | None, _owner: _ModuleType) -> bytes:
    """Read ``NET_DVR_GetDeviceAbility`` through the pure command-port path."""
    response = _owner.hcnetsdk_command_port_execute_template(endpoint, password, _owner.hcnetsdk_device_ability_command_port_template(request), username=username, local_ip=local_ip, timeout=timeout, socket_factory=socket_factory, rsa_key=rsa_key)
    return response.output

def hcnetsdk_get_dvr_config_command_port(endpoint: _owner_types.HcNetSdkLanEndpoint, password: str | bytes, request: _owner_types.HcNetSdkDvrConfigRequest, *, command_id: int | None, body_tail: bytes | None, username: str, local_ip: str | None, timeout: float | None, socket_factory: _owner_types.SocketFactory, rsa_key: _owner_types.Any | None, _owner: _ModuleType) -> bytes:
    """Read a traced ``NET_DVR_GetDVRConfig`` output buffer in pure Python."""
    response = _owner.hcnetsdk_command_port_execute_template(endpoint, password, _owner.hcnetsdk_dvr_config_command_port_template(request, command_id=command_id, body_tail=body_tail), username=username, local_ip=local_ip, timeout=timeout, socket_factory=socket_factory, rsa_key=rsa_key)
    return response.response.body

def hcnetsdk_stdxml_config_command_port(endpoint: _owner_types.HcNetSdkLanEndpoint, password: str | bytes, request: _owner_types.HcNetSdkStdXmlConfigRequest | str | bytes, template: _owner_types.HcNetSdkCommandPortControlTemplate, *, username: str, local_ip: str | None, timeout: float | None, socket_factory: _owner_types.SocketFactory, rsa_key: _owner_types.Any | None, _owner: _ModuleType) -> _owner_types.HcNetSdkStdXmlConfigResponse:
    """Execute a traced ``NET_DVR_STDXMLConfig`` command in pure Python."""
    config = request if isinstance(request, _StaticHcNetSdkStdXmlConfigRequest) else _owner.hcnetsdk_stdxml_config_request(request)
    if not config.request_bytes:
        raise _owner.PyEzvizError('HCNetSDK STDXML request must not be empty')
    response = _owner.hcnetsdk_command_port_execute_template(endpoint, password, template, username=username, local_ip=local_ip, timeout=timeout, socket_factory=socket_factory, rsa_key=rsa_key)
    output = response.output
    return _owner.HcNetSdkStdXmlConfigResponse(succeeded=bool(output), output=output, returned_xml_size=len(output))

def hcnetsdk_stdxml_config_command_port_from_trace(endpoint: _owner_types.HcNetSdkLanEndpoint, password: str | bytes, request: _owner_types.HcNetSdkStdXmlConfigRequest | str | bytes, *, command_id: int, body_prefix: str | bytes | None, addend_delta: int | None, addend: int | None, name: str | None, username: str, local_ip: str | None, timeout: float | None, socket_factory: _owner_types.SocketFactory, rsa_key: _owner_types.Any | None, _owner: _ModuleType) -> _owner_types.HcNetSdkStdXmlConfigResponse:  # noqa: PLR0913 -- explicit runtime context plus retained signature
    """Execute traced ``NET_DVR_STDXMLConfig`` through pure command-port IO."""
    config = request if isinstance(request, _StaticHcNetSdkStdXmlConfigRequest) else _owner.hcnetsdk_stdxml_config_request(request)
    template = _owner.hcnetsdk_stdxml_config_command_port_template(config, command_id=command_id, body_prefix=body_prefix, addend_delta=addend_delta, addend=addend, name=name)
    return _owner.hcnetsdk_stdxml_config_command_port(endpoint, password, config, template, username=username, local_ip=local_ip, timeout=timeout, socket_factory=socket_factory, rsa_key=rsa_key)

def _services_switch_value(label: str, value: int | bool, *, _owner: _ModuleType) -> int:
    if not isinstance(value, (bool, int)):
        raise _owner.PyEzvizError(f'EZVIZ LAN servicesSwitch.{label} must be 0 or 1')
    int_value = int(value)
    if int_value not in (0, 1):
        raise _owner.PyEzvizError(f'EZVIZ LAN servicesSwitch.{label} must be 0 or 1')
    return int_value

def _device_ability_response_text(response: str | bytes, *, _owner: _ModuleType) -> str:
    text = response.decode('utf-8') if isinstance(response, bytes) else response
    return text.replace('\x00', '').strip()

def _device_ability_xml_name(label: str, value: str, *, _owner: _ModuleType) -> str:
    if not _owner.re.fullmatch('[A-Za-z_][A-Za-z0-9_.-]*', value):
        raise _owner.PyEzvizError(f'HCNetSDK device ability {label} XML name is invalid')
    return value

def _ptz_int(label: str, value: int, *, _owner: _ModuleType) -> int:
    try:
        return int(value)
    except (TypeError, ValueError) as err:
        raise _owner.PyEzvizError(f'{label} must be an integer') from err
