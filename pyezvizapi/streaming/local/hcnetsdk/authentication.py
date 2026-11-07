# Runtime hooks deliberately resolve through their legacy owner.
# ruff: noqa: SLF001

"""authentication implementation; legacy runtime hooks remain on the owner module.

Access through _owner is deliberate: callers that patch the compatibility
module must still affect dependent operations. No copied hook snapshots.
"""
from __future__ import annotations

import pyezvizapi.streaming.local.hcnetsdk.api as _owner


def ezviz_local_sdk_ssl_iv(size: int=_owner.EZVIZ_LOCAL_SDK_AES_BLOCK_SIZE, *, seed: bytes=_owner.EZVIZ_LOCAL_SDK_SSL_IV_PREFIX) -> bytes:
    """Return the app-shaped IV used for local SDK SSL-like frames.

    EZVIZ traces show the direct-local stack creates one IV per preview setup
    context and reuses it for the ``0x2011`` and ``0x3105`` encrypted frames.
    The IV prefix observed in the app is the ASCII bytes ``01234567`` and the
    remaining AES block bytes are zero. The 32-byte frame trailer is a
    lowercase MD5 hex digest of the encrypted body.
    """
    if size != _owner.EZVIZ_LOCAL_SDK_AES_BLOCK_SIZE:
        raise _owner.PyEzvizError('EZVIZ local SDK SSL IV must be 16 bytes')
    if len(seed) != len(_owner.EZVIZ_LOCAL_SDK_SSL_IV_PREFIX):
        raise _owner.PyEzvizError('EZVIZ local SDK SSL IV seed must be 8 bytes')
    return seed + bytes(size - len(seed))

def ezviz_lan_login_candidates(verification_code: str, *, username: str=_owner.HCNETSDK_EZVIZ_DEFAULT_USERNAME, command_port: int=_owner.HCNETSDK_DEFAULT_SERVER_PORT, tls_port: int=_owner.HCNETSDK_DEFAULT_TLS_PORT) -> list[_owner.HcNetSdkLoginCandidate]:
    """Return EZVIZ app-style HCNetSDK LAN login attempts.

    APK inspection shows LAN login tries HCNetSDK V40 over HTTPS first, then
    classic V30 on the SDK command port, and finally V30 with ``EZ_LOCAL_USER``
    plus the middle 16 hex characters of the MD5 hash of the same device
    verification/activation code.
    """
    code = verification_code.strip()
    if not code:
        raise _owner.PyEzvizError('Missing EZVIZ LAN verification or activation code')
    local_password = _owner.ezviz_lan_local_user_password(code)
    return [_owner.HcNetSdkLoginCandidate(username=username, password=code, port=tls_port, api='NET_DVR_Login_V40', https=True), _owner.HcNetSdkLoginCandidate(username=username, password=code, port=command_port, api='NET_DVR_Login_V30'), _owner.HcNetSdkLoginCandidate(username=_owner.HCNETSDK_EZVIZ_LOCAL_USERNAME, password=local_password, port=command_port, api='NET_DVR_Login_V30')]

def ezviz_lan_local_user_password(password: str) -> str:
    """Return the EZ_LOCAL_USER password derived by AddMD5Util.a(...)."""
    return _owner.hashlib.md5(password.encode('utf-8')).hexdigest()[8:24].lower()

def ezviz_lan_password_store_name(user_id: str) -> str:
    """Return the SharedPreferences name used for LAN Live View passwords."""
    user = user_id.strip()
    if not user:
        raise _owner.PyEzvizError('Missing EZVIZ user id for LAN password store')
    return f'{user}{_owner.HCNETSDK_EZVIZ_LAN_PASSWORD_PREF_SUFFIX}'

def ezviz_lan_password_store_key(serial: str) -> str:
    """Return the SharedPreferences key used for one LAN device password."""
    device_serial = serial.strip()
    if not device_serial:
        raise _owner.PyEzvizError('Missing EZVIZ device serial for LAN password store')
    return f'{_owner.HCNETSDK_EZVIZ_LAN_PASSWORD_KEY_PREFIX}{device_serial}'

def ezviz_lan_settings_login_candidates(verification_code: str, *, username: str=_owner.HCNETSDK_EZVIZ_DEFAULT_USERNAME, command_port: int=_owner.HCNETSDK_DEFAULT_SERVER_PORT, tls_port: int=_owner.HCNETSDK_DEFAULT_TLS_PORT, login_with_8443: bool | None=None) -> list[_owner.HcNetSdkLoginCandidate]:
    """Return the LAN Live View settings-screen login attempts.

    LanDeviceListPresenter.o(...) differs slightly from the older
    DeviceInfoEx.loginLanDevice() helper:

    * scanned devices pass login_with_8443=True when SDK-over-TLS is
      advertised on port 8443, and that path does not fall back to the command
      port after a TLS login failure;
    * manual-add and React Native IP-login paths pass None and try TLS first,
      then the command port, then the EZVIZ local-user MD5 fallback;
    * compatibility mode passes False and skips the TLS attempt.

    The settings presenter calls ``HCNETUtil.s(...)`` for every attempt, so all
    attempts use the V40 login wrapper. Only the 8443 attempt sets the native
    ``byHttps`` flag.
    """
    code = verification_code.strip()
    if not code:
        raise _owner.PyEzvizError('Missing EZVIZ LAN settings password')
    candidates = [_owner.HcNetSdkLoginCandidate(username=username, password=code, port=tls_port, api='NET_DVR_Login_V40', https=True), _owner.HcNetSdkLoginCandidate(username=username, password=code, port=command_port, api='NET_DVR_Login_V40'), _owner.HcNetSdkLoginCandidate(username=_owner.HCNETSDK_EZVIZ_LOCAL_USERNAME, password=_owner.ezviz_lan_local_user_password(code), port=command_port, api='NET_DVR_Login_V40')]
    if login_with_8443 is True:
        return candidates[:1]
    if login_with_8443 is False:
        return candidates[1:]
    return candidates

def ezviz_lan_user_password_update_request(login_id: int, password: str | bytes) -> _owner.HcNetSdkDvrConfigRequest:
    """Return the local admin-user password update request shape."""
    password_bytes = _owner._bounded_bytes('user password', password, 16)
    if not password_bytes:
        raise _owner.PyEzvizError('EZVIZ LAN user password cannot be empty')
    return _owner.hcnetsdk_dvr_config_set_request(login_id, _owner.HcNetSdkDvrCommand.SET_USER_CFG_V30, structure='NET_DVR_USER_V30', field_updates={'struUser[0].sPassword': '<password-bytes>', 'struUser[0].sPasswordLength': len(password_bytes), 'struUser[0].sPasswordZeroFill': 16}, read_before_write=True)

def ezviz_lan_settings_error_clears_password(error_code: int) -> bool:
    """Return whether LanDeviceListActivity.q(...) clears the LAN password."""
    return error_code in (_owner.HCNETSDK_EZVIZ_SETTINGS_ACCOUNT_PASSWORD_ERROR, _owner.HCNETSDK_EZVIZ_SETTINGS_ACCOUNT_PASSWORD_LOCKED_ERROR)

def ezviz_lan_settings_login_succeeded(login_id: int) -> bool:
    """Return whether the settings presenter treats an HCNetSDK login as OK."""
    return login_id >= 0

def ezviz_lan_play_device_login_succeeded(login_id: int) -> bool:
    """Return whether DeviceInfoEx.loginPlayDevice(...) returned a login id."""
    return login_id >= 0

def hcnetsdk_command_port_login_request_frame(public_key_der: bytes, *, username: str=_owner.HCNETSDK_EZVIZ_DEFAULT_USERNAME, local_ip: str) -> bytes:
    """Build the first port-8000 RSA login frame.

    The native SDK sends a PKCS#1 ``RSAPublicKey`` DER blob, not the longer
    SubjectPublicKeyInfo form returned by many RSA exporters.
    """
    body = _owner._hcnetsdk_command_port_login_prefix(local_ip) + _owner._hcnetsdk_command_port_username(username) + public_key_der
    return _owner.build_hcnetsdk_tcp_frame(body, field_4=_owner.HCNETSDK_COMMAND_PORT_LOGIN_FAMILY, field_12=_owner.HCNETSDK_COMMAND_PORT_LOGIN_HEADER_FIELD_12)

def hcnetsdk_command_port_password_digest(username: str, password: str | bytes, password_seed: bytes) -> bytes:
    """Return the native SDK SHA-256 password branch for command-port login.

    This is a device-protocol compatibility digest, not password storage.
    """
    password_bytes = password if isinstance(password, bytes) else password.encode()
    if len(password_seed) != _owner.HCNETSDK_COMMAND_PORT_PASSWORD_SEED_LENGTH:
        raise _owner.PyEzvizError('HCNetSDK command-port password seed must be 64 bytes')
    digest = _owner.hashlib.new('sha256', usedforsecurity=False)
    digest.update(username.encode())
    digest.update(password_seed)
    digest.update(password_bytes)
    return digest.hexdigest().encode()

def hcnetsdk_command_port_login_proof(username: str, password: str | bytes, challenge: bytes, password_seed: bytes) -> tuple[bytes, bytes]:
    """Return the two proof chunks for the second command-port login frame.

    The native device handshake uses MD5 HMAC branches here for compatibility;
    these values are not persisted password hashes.
    """
    challenge = challenge.rstrip(b'\x00')
    if not challenge:
        raise _owner.PyEzvizError('HCNetSDK command-port login challenge is empty')
    password_digest = _owner.hcnetsdk_command_port_password_digest(username, password, password_seed)
    return (_owner._hcnetsdk_command_port_md5_hmac(challenge, username.encode()), _owner._hcnetsdk_command_port_md5_hmac(challenge, password_digest))

def hcnetsdk_command_port_login_proof_frame(*, username: str=_owner.HCNETSDK_EZVIZ_DEFAULT_USERNAME, password: str | bytes, challenge: bytes, password_seed: bytes, local_ip: str) -> bytes:
    """Build the second port-8000 login proof frame."""
    primary, secondary = _owner.hcnetsdk_command_port_login_proof(username, password, challenge, password_seed)
    body = _owner._hcnetsdk_command_port_login_prefix(local_ip) + primary.ljust(_owner.HCNETSDK_COMMAND_PORT_PRIMARY_PROOF_LENGTH, b'\x00') + secondary[:_owner.HCNETSDK_COMMAND_PORT_SECONDARY_PROOF_LENGTH]
    return _owner.build_hcnetsdk_tcp_frame(body, field_4=_owner.HCNETSDK_COMMAND_PORT_LOGIN_FAMILY, field_12=_owner.HCNETSDK_COMMAND_PORT_LOGIN_HEADER_FIELD_12)

def decode_hcnetsdk_command_port_login_challenge(response: _owner.HcNetSdkTcpFrame, rsa_key: _owner.Any) -> _owner.HcNetSdkCommandPortLoginChallenge:
    """Decrypt the first command-port login response with the RSA private key."""
    if len(response.body) < _owner.HCNETSDK_COMMAND_PORT_RSA_BLOCK_LENGTH + _owner.HCNETSDK_COMMAND_PORT_PASSWORD_SEED_LENGTH:
        raise _owner.PyEzvizError('HCNetSDK command-port login challenge response is truncated')
    challenge = _owner.PKCS1_v1_5.new(rsa_key).decrypt(response.body[:_owner.HCNETSDK_COMMAND_PORT_RSA_BLOCK_LENGTH], b'')
    if not challenge:
        raise _owner.PyEzvizError('HCNetSDK command-port RSA challenge decrypt failed')
    return _owner.HcNetSdkCommandPortLoginChallenge(response=response, challenge=challenge.rstrip(b'\x00'), password_seed=response.body[_owner.HCNETSDK_COMMAND_PORT_RSA_BLOCK_LENGTH:_owner.HCNETSDK_COMMAND_PORT_RSA_BLOCK_LENGTH + _owner.HCNETSDK_COMMAND_PORT_PASSWORD_SEED_LENGTH])

def ezviz_lan_play_device_login(endpoint: _owner.HcNetSdkLanEndpoint, *, check_last_login_status: bool=False) -> _owner.EzvizLanPlayDeviceLogin:
    """Build the player-side LAN HCNetSDK login step observed in the APK.

    The settings screen's login id is only a gate for opening the player. The
    player path then calls IPlayDataInfo.loginPlayDevice(...) /
    DeviceInfoEx.loginPlayDevice(...) and uses that returned NetSDK id for
    InitParam.iNetSDKUserId and the later keyframe request.
    """
    if not endpoint.host.strip():
        raise _owner.PyEzvizError('Missing EZVIZ LAN play-device host')
    return _owner.EzvizLanPlayDeviceLogin(endpoint=endpoint, check_last_login_status=check_last_login_status)

def encrypt_ezviz_local_sdk_body_aes_cbc(body: bytes | str, *, key: bytes | str, iv: bytes | str) -> bytes:
    """Encrypt a local SDK control body with AES-CBC/PKCS#5 padding.

    The EZVIZ app's local control frames use AES-CBC with 16-byte block
    padding before wrapping the encrypted bytes in the local SDK frame
    envelope. This helper does not derive or store device secrets; callers
    must supply key and IV bytes from their own credential source.
    """
    body_bytes = body.encode('utf-8') if isinstance(body, str) else body
    return _owner.AES.new(_owner._local_sdk_aes_bytes('key', key), _owner.AES.MODE_CBC, _owner._local_sdk_aes_bytes('IV', iv)).encrypt(_owner._pkcs5_pad(body_bytes))

def decrypt_ezviz_local_sdk_body_aes_cbc(body: bytes, *, key: bytes | str, iv: bytes | str) -> bytes:
    """Decrypt a local SDK AES-CBC/PKCS#5 control body."""
    plain = _owner.AES.new(_owner._local_sdk_aes_bytes('key', key), _owner.AES.MODE_CBC, _owner._local_sdk_aes_bytes('IV', iv)).decrypt(body)
    return _owner._pkcs5_unpad(plain)

def _hcnetsdk_command_port_login_prefix(local_ip: str) -> bytes:
    return _owner.HCNETSDK_COMMAND_PORT_LOGIN_SEED_PREFIX + _owner._hcnetsdk_command_port_local_ip_word(local_ip) + _owner.HCNETSDK_COMMAND_PORT_LOGIN_SEED_SUFFIX
