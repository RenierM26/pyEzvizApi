"""Intercom relay actions select the Video resource, not pagelist ordering."""

from __future__ import annotations

from collections.abc import Iterator
import importlib
import json
from pathlib import Path
import socket
from typing import Any

import pytest

from pyezvizapi.client import EzvizClient
from pyezvizapi.constants import FEATURE_CODE
from pyezvizapi.devices.camera import EzvizCamera
from pyezvizapi.exceptions import PyEzvizError


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Never allow routing tests to send a physical lock command."""

    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("Intercom routing tests must not access the network")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)


@pytest.fixture
def client() -> Iterator[EzvizClient]:
    """Provide an offline client with a synthetic account session."""
    sdk = EzvizClient(token={"session_id": "session", "api_url": "example.invalid"})
    yield sdk
    sdk.close_session()


def resource(identifier: str, index: int, **extra: Any) -> dict[str, Any]:
    """Build a synthetic discovery resource with a distinct management ID."""
    return {
        "resourceIdentifier": identifier,
        "resourceId": f"opaque-{identifier}-{index}",
        "localIndex": index,
        **extra,
    }


@pytest.mark.parametrize("as_mapping", [False, True])
@pytest.mark.parametrize("video_first", [False, True])
@pytest.mark.parametrize(
    ("action", "lock_no", "request_name"),
    [
        ("gate_unlock", 1, "RemoteUnlockReq"),
        ("door_unlock", 2, "RemoteUnlockReq"),
        ("gate_lock", 1, "RemoteLockReq"),
        ("door_lock", 2, "RemoteLockReq"),
    ],
)
def test_intercom_uses_video_route_independent_of_discovery_order(
    monkeypatch: pytest.MonkeyPatch,
    client: EzvizClient,
    as_mapping: bool,
    video_first: bool,
    action: str,
    lock_no: int,
    request_name: str,
) -> None:
    """Keep the selected resource's channel/token/type and existing bind policy."""
    resources = [
        resource("global", 0, streamToken="wrong-token", type="wrong-type"),
        resource("Video_1", 2),
        resource("Video", 0, streamToken="relay-token", type="relay"),
    ]
    if video_first:
        resources.reverse()
    camera = EzvizCamera(
        client,
        "INTERCOM-TEST",
        device_obj={
            "deviceInfos": {"deviceCategory": "BDoorBell"},
            "resourceInfos": dict(enumerate(resources)) if as_mapping else resources,
            # This config also occurs on ordinary cameras; it does not select
            # an actuator route and must not override the app's Video route.
            "FEATURE_INFO": {"0": {"DoorLock": {"DoorLockMgr": {"MessagePlanCfg": {}}}}},
        },
    )
    calls: list[tuple[str, str, dict[str, Any]]] = []

    def request(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append((method, path, kwargs))
        return {"meta": {"code": 200}}

    monkeypatch.setattr(client, "_request_json", request)
    monkeypatch.setattr(client, "get_latest_terminal_bind", lambda **_kw: ("bind", "user"))
    assert getattr(camera, action)() is True
    assert len(calls) == 1
    method, path, kwargs = calls[0]
    assert method == "PUT"
    assert path == f"/v3/iot-feature/action/INTERCOM-TEST/Video/0/DoorLockMgr/{request_name}"
    assert kwargs["json_body"] == {
        "unLockInfo": {
            "bindCode": "bind" if action.endswith("_unlock") else FEATURE_CODE,
            "lockNo": lock_no,
            "streamToken": "relay-token",
            "userName": "user" if action.endswith("_unlock") else "",
            "type": "relay",
        }
    }


@pytest.mark.parametrize("action", ["gate_unlock", "door_unlock", "gate_lock", "door_lock"])
def test_intercom_rejects_ambiguous_video_routes_before_io(
    monkeypatch: pytest.MonkeyPatch, client: EzvizClient, action: str
) -> None:
    """Do not guess which physical relay to operate when channels conflict."""
    camera = EzvizCamera(
        client,
        "INTERCOM-TEST",
        device_obj={
            "deviceInfos": {"deviceCategory": "BDoorBell"},
            "resourceInfos": [resource("global", 0), resource("Video", 0), resource("Video", 1)],
        },
    )

    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("Ambiguous routing must fail before terminal lookup or action IO")

    monkeypatch.setattr(client, "_request_json", forbidden)
    with pytest.raises(PyEzvizError, match="Ambiguous intercom Video resources"):
        getattr(camera, action)()


@pytest.mark.parametrize("category", [None, "IPC", "BDoorBell"])
def test_other_and_legacy_routes_remain_unchanged(
    monkeypatch: pytest.MonkeyPatch, client: EzvizClient, category: str | None
) -> None:
    """Do not infer linked-lock routes from unrelated DoorLockMgr configuration."""
    resources = [resource("DoorLock", 3, streamToken="lock-token", type="lock")]
    if category != "BDoorBell":
        resources.append(resource("Video", 0))
    camera = EzvizCamera(
        client,
        "LEGACY-TEST",
        device_obj={"deviceInfos": {"deviceCategory": category}, "resourceInfos": resources},
    )
    calls: list[str] = []

    def request(_method: str, path: str, **_kwargs: Any) -> dict[str, Any]:
        calls.append(path)
        return {"meta": {"code": 200}}

    monkeypatch.setattr(client, "_request_json", request)
    monkeypatch.setattr(client, "get_latest_terminal_bind", lambda **_kw: ("bind", "user"))
    assert camera.gate_unlock() is True
    assert calls == ["/v3/iot-feature/action/LEGACY-TEST/DoorLock/3/DoorLockMgr/RemoteUnlockReq"]


@pytest.mark.parametrize("action", ["unlock-door", "unlock-gate"])
@pytest.mark.parametrize("response_code", [200, 400])
def test_cli_discovery_selects_intercom_video_and_preserves_errors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, action: str, response_code: int
) -> None:
    """Exercise real CLI, discovery grouping, camera wrapper and client control."""
    cli = importlib.import_module("pyezvizapi.cli.main")
    token_path = tmp_path / "token.json"
    token_path.write_text(json.dumps({"session_id": "session", "api_url": "example.invalid"}))
    calls: list[tuple[str, str, dict[str, Any]]] = []

    def request(_client: EzvizClient, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append((method, path, kwargs))
        if path.endswith("/pagelist"):
            return {
                "meta": {"code": 200},
                "deviceInfos": [{"deviceSerial": "INTERCOM-TEST", "deviceCategory": "BDoorBell"}],
                "resourceInfos": [
                    {"deviceSerial": "UNRELATED", **resource("Video", 9)},
                    {"deviceSerial": "INTERCOM-TEST", **resource("global", 0)},
                    {"deviceSerial": "INTERCOM-TEST", **resource("Video", 0)},
                ],
            }
        if path == "/v3/terminals":
            return {
                "meta": {"code": 200},
                "terminals": [{"name": "Hassio", "sign": "terminal", "userId": "user"}],
            }
        assert path == "/v3/iot-feature/action/INTERCOM-TEST/Video/0/DoorLockMgr/RemoteUnlockReq"
        return {"meta": {"code": response_code}}

    monkeypatch.setattr(EzvizClient, "_request_json", request)
    exit_code = cli.main(
        ["--token-file", str(token_path), "camera", "--serial", "INTERCOM-TEST", action]
    )
    assert exit_code == (0 if response_code == 200 else 1)
    assert [method for method, _path, _kwargs in calls] == ["GET", "GET", "PUT"]
    assert calls[-1][2]["json_body"] == {
        "unLockInfo": {
            "bindCode": "terminaluser",
            "lockNo": 2 if action == "unlock-door" else 1,
            "streamToken": "",
            "userName": "Hassio",
        }
    }
