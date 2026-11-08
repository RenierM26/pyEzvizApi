"""Lock actions use the feature namespace, not the resource's opaque id."""

from __future__ import annotations

from typing import Any

import pytest

from pyezvizapi.client import EzvizClient
from pyezvizapi.constants import FEATURE_CODE
from pyezvizapi.devices.camera import EzvizCamera
from pyezvizapi.exceptions import PyEzvizError


@pytest.mark.parametrize("identifier", ["Video", "DoorLock"])
@pytest.mark.parametrize("as_mapping", [False, True])
@pytest.mark.parametrize(
    ("action", "lock_no", "request_name"),
    [
        ("gate_unlock", 1, "RemoteUnlockReq"),
        ("door_unlock", 2, "RemoteUnlockReq"),
        ("gate_lock", 1, "RemoteLockReq"),
        ("door_lock", 2, "RemoteLockReq"),
    ],
)
def test_feature_action_uses_resource_identifier(
    monkeypatch,
    identifier: str,
    as_mapping: bool,
    action: str,
    lock_no: int,
    request_name: str,
) -> None:
    client = EzvizClient(token={"session_id": "session", "api_url": "example.test"})
    resource = {
        "resourceId": "0000000000000000000000000000000d",
        "resourceIdentifier": identifier,
        "localIndex": "0",
    }
    camera = EzvizCamera(
        client,
        "HPD7-TEST",
        device_obj={
            "deviceInfos": {"deviceCategory": "BDoorBell"},
            "resourceInfos": {"resource": resource} if as_mapping else [resource],
        },
    )
    calls: list[tuple[str, str, dict[str, Any]]] = []

    def request(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append((method, path, kwargs))
        return {"meta": {"code": 200}}

    monkeypatch.setattr(client, "_request_json", request)
    monkeypatch.setattr(client, "get_latest_terminal_bind", lambda **kw: ("bind", "user"))
    assert getattr(camera, action)() is True
    assert len(calls) == 1
    method, path, kwargs = calls[0]
    assert method == "PUT"
    assert path == f"/v3/iot-feature/action/HPD7-TEST/{identifier}/0/DoorLockMgr/{request_name}"
    assert kwargs["json_body"] == {
        "unLockInfo": {
            "bindCode": "bind" if action.endswith("_unlock") else FEATURE_CODE,
            "lockNo": lock_no,
            "streamToken": "",
            "userName": "user" if action.endswith("_unlock") else "",
        }
    }


def test_corrected_unlock_route_still_rejects_server_failure(monkeypatch) -> None:
    client = EzvizClient(token={"session_id": "session", "api_url": "example.test"})
    camera = EzvizCamera(
        client,
        "HPD7-TEST",
        device_obj={
            "resourceInfos": [
                {
                    "resourceId": "opaque-id",
                    "resourceIdentifier": "Video",
                    "localIndex": 0,
                }
            ],
        },
    )
    calls = []

    def request(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append(path)
        return {"meta": {"code": 400, "message": "device feature not registered"}}

    monkeypatch.setattr(client, "_request_json", request)
    monkeypatch.setattr(client, "get_latest_terminal_bind", lambda **kw: ("bind", "user"))
    with pytest.raises(PyEzvizError):
        camera.gate_unlock()
    assert calls == ["/v3/iot-feature/action/HPD7-TEST/Video/0/DoorLockMgr/RemoteUnlockReq"]


@pytest.mark.parametrize("identifier", [None, "", 42])
def test_legacy_namespace_in_resource_id_is_preserved(monkeypatch, identifier) -> None:
    client = EzvizClient(token={"session_id": "session", "api_url": "example.test"})
    camera = EzvizCamera(
        client,
        "LEGACY",
        device_obj={
            "resourceInfos": [
                {
                    "resourceId": "DoorLock",
                    "resourceIdentifier": identifier,
                    "localIndex": 2,
                    "streamToken": "existing-token",
                    "type": "lock",
                }
            ],
        },
    )
    calls = []

    def unlock(*args, **kwargs):
        calls.append(kwargs)
        return True

    monkeypatch.setattr(client, "remote_unlock", unlock)
    assert camera.gate_unlock() is True
    assert calls == [
        {
            "resource_id": "DoorLock",
            "local_index": "2",
            "stream_token": "existing-token",
            "lock_type": "lock",
        }
    ]
