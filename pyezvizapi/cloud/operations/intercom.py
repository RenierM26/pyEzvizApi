# Runtime hook context is explicit; immutable value types come from dependency leaves.
# ruff: noqa: SLF001
"""intercom implementation; runtime hooks arrive through an explicit owner context.

Access through _owner is deliberate: callers that patch the compatibility
module must still affect dependent operations. No copied hook snapshots.
"""

from __future__ import annotations

from collections.abc import Mapping as _StaticMapping
from types import ModuleType as _ModuleType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pyezvizapi._typing.client as _owner_types


def get_cam_auth_code(
    self: _owner_types.EzvizClient,
    serial: str,
    encrypt_pwd: str | None,
    msg_auth_code: str | int | None,
    sender_type: int,
    max_retries: int,
    *,
    _owner: _ModuleType,
) -> _owner_types.Any:
    """Get Camera auth code. This is the verification code on the camera sticker.

    Args:
        serial (str): The camera serial number.
        encrypt_pwd (str | None): This is always none.
        msg_auth_code (str | int | None): The 2FA code.
        sender_type (int): The sender type. Defaults to 0. Needs to be 3 when returning 2FA code.
        max_retries (int): The maximum number of retries. Defaults to 0.

    Raises:
        PyEzvizError: If the camera auth code cannot be retrieved.
        EzvizAuthVerificationCode: If the operation requires elevation with 2FA.
        DeviceException: If the physical device is not reachable.

    Returns:
        Any: JSON response, filtered to return devAuthCode:
            {
                "devAuthCode": str,     # Device authorization code
                "meta": {
                    "code": int,       # Status code (200 if successful)
                    "message": str,         # Status message in chinese
                    "moreInfo": null or {"INVALID_PARAMETER": str}
                }
            }
    """
    if max_retries > _owner.MAX_RETRIES:
        raise _owner.PyEzvizError("Can't gather proper data. Max retries exceeded.")
    params: dict[str, int | str | None] = {
        "encrptPwd": encrypt_pwd,
        "msgAuthCode": msg_auth_code,
        "senderType": sender_type,
    }
    json_output = self._request_json(
        "GET",
        f"{_owner.API_ENDPOINT_CAM_AUTH_CODE}{serial}",
        params=params,
        retry_401=True,
        max_retries=max_retries,
    )
    if self._meta_code(json_output) == 80000:
        raise _owner.EzvizAuthVerificationCode("Operation requires 2FA check")
    if self._meta_code(json_output) == 2009:
        raise _owner.DeviceException(
            f"Device not reachable: Got {self._response_summary(json_output)}"
        )
    if not self._meta_ok(json_output):
        raise _owner.PyEzvizError(
            f"Could not get camera verification key: Got {self._response_summary(json_output)}"
        )
    return json_output["devAuthCode"]


def get_2fa_check_code(
    self: _owner_types.EzvizClient,
    biz_type: str,
    username: str | None,
    max_retries: int,
    *,
    _owner: _ModuleType,
) -> _owner_types.Any:
    """Initiate 2FA check for sensitive operations. Elevates your session token permission.

    Args:
        biz_type (str): The operation type. (DEVICE_ENCRYPTION | DEVICE_AUTH_CODE)
        username (str): The account username.
        max_retries (int): The maximum number of retries. Defaults to 0.

    Raises:
        PyEzvizError: If the operation fails.

    Returns:
        Any: JSON response with the following structure:
            {
                "meta": {
                    "code": int,       # Status code (200 if successful)
                    "message": str         # Status message in chinese
                    "moreInfo": null
                },
                "contact": {
                    "type": str,   # 2FA code will be sent to this (EMAIL)
                    "fuzzyContact": str     # Destination value (e.g., someone@email.local)
                }
            }
    """
    if max_retries > _owner.MAX_RETRIES:
        raise _owner.PyEzvizError("Can't gather proper data. Max retries exceeded.")
    json_output = self._request_json(
        "POST",
        _owner.API_ENDPOINT_2FA_VALIDATE_POST_AUTH,
        data={"bizType": biz_type, "from": username},
        retry_401=True,
        max_retries=max_retries,
    )
    if not self._meta_ok(json_output):
        raise _owner.PyEzvizError(
            f"Could not request elevated permission: Got {self._response_summary(json_output)})"
        )
    return json_output


def create_panoramic(
    self: _owner_types.EzvizClient, serial: str, max_retries: int, *, _owner: _ModuleType
) -> _owner_types.Any:
    """Create panoramic image."""
    if max_retries > _owner.MAX_RETRIES:
        raise _owner.PyEzvizError("Can't gather proper data. Max retries exceeded.")
    attempts = max(0, max_retries)
    for attempt in range(attempts + 1):
        json_output = self._request_json(
            "POST",
            _owner.API_ENDPOINT_CREATE_PANORAMIC,
            data={"deviceSerial": serial},
            retry_401=True,
            max_retries=0,
        )
        result = str(json_output.get("resultCode"))
        if result == "0":
            return json_output
        if result == "-1" and attempt < attempts:
            _owner._LOGGER.warning(
                "Create panoramic failed on device %s retrying %s/%s", serial, attempt + 1, attempts
            )
            continue
        raise _owner.PyEzvizError(
            f"Could not send command to create panoramic photo: Got {self._response_summary(json_output)})"
        )
    raise _owner.PyEzvizError("Could not send command to create panoramic photo: exceeded retries")


def return_panoramic(
    self: _owner_types.EzvizClient, serial: str, max_retries: int, *, _owner: _ModuleType
) -> _owner_types.Any:
    """Return panoramic image url list."""
    json_output = self._retry_json(
        lambda: self._request_json(
            "POST",
            _owner.API_ENDPOINT_RETURN_PANORAMIC,
            data={"deviceSerial": serial},
            retry_401=True,
            max_retries=0,
        ),
        attempts=max_retries,
        should_retry=lambda p: str(p.get("resultCode")) == "-1",
        log="panoramic_busy_or_unreachable",
        serial=serial,
    )
    if str(json_output.get("resultCode")) != "0":
        raise _owner.PyEzvizError(
            f"Could retrieve panoramic photo: Got {self._response_summary(json_output)})"
        )
    return json_output


def ptz_control_coordinates(
    self: _owner_types.EzvizClient,
    serial: str,
    x_axis: float,
    y_axis: float,
    *,
    resource_identifier: str,
    local_index: str,
    max_retries: int,
    _owner: _ModuleType,
) -> bool:
    """PTZ Coordinate Move."""
    if not 0 <= x_axis <= 1:
        raise _owner.PyEzvizError(
            f"Invalid X coordinate: {x_axis}: Should be between 0 and 1 inclusive"
        )
    if not 0 <= y_axis <= 1:
        raise _owner.PyEzvizError(
            f"Invalid Y coordinate: {y_axis}: Should be between 0 and 1 inclusive"
        )
    json_result = self._iot_request(
        "PUT",
        _owner.API_ENDPOINT_IOT_ACTION,
        serial,
        resource_identifier,
        local_index,
        "PTZManualCtrl",
        "CtrlPTZ3DPosition",
        payload={
            "positionCtrlType": "point",
            "positionPoint": {"x": x_axis, "y": y_axis},
            "positionRect": {"height": 1.0, "width": 1.0, "x": 0.0, "y": 0.0},
        },
        max_retries=max_retries,
        error_message="Could not move PTZ to coordinates",
    )
    _owner._LOGGER.debug(
        "http_debug: serial=%s code=%s msg=%s",
        serial,
        self._meta_code(json_result),
        "ptz_control_coordinates",
    )
    return True


def get_door_lock_users(
    self: _owner_types.EzvizClient, serial: str, *, max_retries: int, _owner: _ModuleType
) -> _owner_types.JsonDict:
    """Retrieve users associated with a door lock device."""
    json_output = self._request_json(
        "GET",
        f"{_owner.API_ENDPOINT_DOORLOCK_USERS}{serial}/users",
        retry_401=True,
        max_retries=max_retries,
    )
    self._ensure_ok(json_output, "Could not get door lock users")
    return json_output


def get_terminals(
    self: _owner_types.EzvizClient,
    *,
    limit: int,
    offset: int,
    max_retries: int,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Retrieve account terminal information."""
    return self._request_json(
        "GET",
        _owner.API_ENDPOINT_TERMINAL_INFO,
        params={"limit": limit, "offset": offset},
        retry_401=True,
        max_retries=max_retries,
    )


def get_latest_terminal_bind(
    self: _owner_types.EzvizClient,
    *,
    limit: int,
    offset: int,
    terminal_name: str | None,
    max_retries: int,
    _owner: _ModuleType,
) -> tuple[str, str]:
    """Return the latest terminal bind code and terminal user name."""
    json_output = self.get_terminals(limit=limit, offset=offset, max_retries=max_retries)
    terminals = json_output.get("terminals")
    if not isinstance(terminals, list) or not terminals:
        raise _owner.PyEzvizError("No terminal information found")
    terminal_items = [
        item
        for item in terminals
        if isinstance(item, _StaticMapping)
        and str(item.get("sign") or "").strip()
        and str(item.get("userId") or "").strip()
    ]
    if not terminal_items:
        raise _owner.PyEzvizError("No terminal bind information found")
    if terminal_name:
        expected_name = terminal_name.casefold()
        terminal_items = [
            item
            for item in terminal_items
            if str(item.get("name") or item.get("terminalName") or "").casefold() == expected_name
        ]
        if not terminal_items:
            raise _owner.PyEzvizError(f"No terminal bind information found for {terminal_name}")
    terminal = max(
        terminal_items,
        key=lambda item: str(item.get("lastModifytime") or item.get("lastModifyTime") or ""),
    )
    sign = str(terminal["sign"]).strip()
    terminal_user_id = str(terminal["userId"]).strip()
    user_name = terminal.get("name") or terminal.get("terminalName") or terminal_user_id
    return (f"{sign}{terminal_user_id}", str(user_name))


def remote_unlock(  # noqa: PLR0913 -- explicit runtime context plus retained signature
    self: _owner_types.EzvizClient,
    serial: str,
    user_id: str,
    lock_no: int,
    *,
    resource_id: str | None,
    local_index: str | int | None,
    stream_token: str | None,
    lock_type: str | None,
    bind_code: str | None,
    terminal_filter_name: str | None,
    use_terminal_bind: bool,
    _owner: _ModuleType,
) -> bool:
    """Sends a remote command to unlock a specific lock.

    Args:
        serial (str): The camera serial.
        user_id (str): The user id.
        lock_no (int): The lock number.
        resource_id (str, optional): Resource identifier reported by the device
            (for example ``Video`` or ``DoorLock``). Defaults to ``"Video"``.
        local_index (str | int, optional): Local channel index for the lock.
            Defaults to ``"1"``.
        stream_token (str, optional): Stream token associated with the lock if
            provided by the API. Defaults to empty string when omitted.
        lock_type (str, optional): Optional lock type hint used by some devices.
        bind_code (str, optional): Explicit bind code. When omitted, the latest
            terminal bind code is used if available, otherwise the legacy
            ``FEATURE_CODE + user_id`` bind code is used.
        terminal_filter_name (str, optional): Terminal name to prefer when
            resolving an implicit bind code. Defaults to ``"Hassio"`` to match
            the library login terminal. Pass ``None`` to use the newest valid
            terminal regardless of name.
        use_terminal_bind (bool): Whether to try terminal-derived bind codes
            before falling back to the legacy bind code.

    Raises:
        PyEzvizError: If max retries are exceeded or if the response indicates failure.
        HTTPError: If an HTTP error occurs (other than a 401, which triggers re-login).

    Returns:
        bool: True if the operation was successful.

    """
    route_resource = resource_id or "Video"
    route_index = str(local_index if local_index is not None else 1)
    effective_bind_code = bind_code
    effective_user_name = user_id
    if effective_bind_code is None and use_terminal_bind:
        try:
            effective_bind_code, effective_user_name = self.get_latest_terminal_bind(
                terminal_name=terminal_filter_name
            )
        except (_owner.requests.RequestException, _owner.HTTPError, _owner.PyEzvizError) as err:
            _owner._LOGGER.debug(
                "Terminal bind unavailable for %s, using legacy bind code: %s", serial, err
            )
    if effective_bind_code is None:
        effective_bind_code = f"{_owner.FEATURE_CODE}{user_id}"
    un_lock_info: dict[str, _owner_types.Any] = {
        "bindCode": effective_bind_code,
        "lockNo": lock_no,
        "streamToken": stream_token or "",
        "userName": effective_user_name,
    }
    if lock_type:
        un_lock_info["type"] = lock_type
    payload = {"unLockInfo": un_lock_info}
    json_result = self._request_json(
        "PUT",
        f"{_owner.API_ENDPOINT_IOT_ACTION}{serial}/{route_resource}/{route_index}{_owner.API_ENDPOINT_REMOTE_UNLOCK}",
        json_body=payload,
        retry_401=True,
        max_retries=0,
    )
    _owner._LOGGER.debug(
        "http_debug: serial=%s code=%s msg=%s",
        serial,
        self._response_code(json_result),
        "remote_unlock",
    )
    self._ensure_ok(json_result, "Could not remotely unlock device")
    return True


def remote_lock(
    self: _owner_types.EzvizClient,
    serial: str,
    user_id: str,
    lock_no: int,
    *,
    resource_id: str | None,
    local_index: str | int | None,
    stream_token: str | None,
    lock_type: str | None,
    _owner: _ModuleType,
) -> bool:
    """Send a remote lock command to a specific lock."""
    route_resource = resource_id or "Video"
    route_index = str(local_index if local_index is not None else 1)
    un_lock_info: dict[str, _owner_types.Any] = {
        "bindCode": f"{_owner.FEATURE_CODE}{user_id}",
        "lockNo": lock_no,
        "streamToken": stream_token or "",
        "userName": user_id,
    }
    if lock_type:
        un_lock_info["type"] = lock_type
    payload = {"unLockInfo": un_lock_info}
    json_result = self._request_json(
        "PUT",
        f"{_owner.API_ENDPOINT_IOT_ACTION}{serial}/{route_resource}/{route_index}{_owner.API_ENDPOINT_REMOTE_LOCK}",
        json_body=payload,
        retry_401=True,
        max_retries=0,
    )
    _owner._LOGGER.debug(
        "http_debug: serial=%s code=%s msg=%s",
        serial,
        self._response_code(json_result),
        "remote_lock",
    )
    self._ensure_ok(json_result, "Could not remotely lock device")
    return True


def get_remote_unbind_progress(
    self: _owner_types.EzvizClient, serial: str, *, max_retries: int, _owner: _ModuleType
) -> _owner_types.JsonDict:
    """Check progress of a remote unbind request."""
    json_output = self._request_json(
        "GET",
        f"{_owner.API_ENDPOINT_REMOTE_UNBIND_PROGRESS}{serial}/progress",
        retry_401=True,
        max_retries=max_retries,
    )
    self._ensure_ok(json_output, "Could not get unbind progress")
    return json_output
