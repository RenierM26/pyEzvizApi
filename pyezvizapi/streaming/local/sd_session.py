"""One owned, deadline-bound login lifecycle for native SD operations.

Command sockets remain operation-owned. Cleanup never masks the source error;
normal completion requires an acknowledged logout. No retries or eager connects.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass, replace
from typing import Any, Literal

from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.streaming.local.hcnetsdk.api import (
    HcNetSdkCommandPortClient,
    HcNetSdkCommandPortControlTemplate,
    HcNetSdkLanEndpoint,
)
from pyezvizapi.streaming.local.sd_transport import LanPlaybackError


@dataclass(frozen=True)
class LanSdSession:
    """Authenticated frame context; does not retain a connected socket."""

    client: Callable[[], HcNetSdkCommandPortClient]
    session_id: bytes
    auth_seed: int
    challenge: bytes
    local_ip: str

    def frame(self, command: int, tail: bytes = b"") -> bytes:
        return HcNetSdkCommandPortControlTemplate(command, tail).to_frame(
            session_id=self.session_id,
            auth_seed=self.auth_seed,
            key=self.challenge,
            local_ip=self.local_ip,
        )

    def logout(self, deadline: float, stage: str) -> None:
        with closing(self.client()) as control:
            control.send_command_frame(self.frame(0x10100), deadline=deadline)
            response = control.read_tcp_frame(max_frame_bytes=4096, deadline=deadline)
            if response.header.field_8 != 1:
                raise LanPlaybackError(stage, response.header.field_8)


@contextmanager
def lan_sd_session(
    endpoint: HcNetSdkLanEndpoint,
    password: str | bytes,
    *,
    username: str,
    deadline: float,
    rsa_key: Any,
    client_factory: Callable[[], HcNetSdkCommandPortClient],
    purpose: Literal["playback", "catalog"],
) -> Iterator[LanSdSession]:
    """Log out even after identity refusal, cancellation or operation failure."""
    session = None
    stage = "logout" if purpose == "playback" else "catalog logout"
    identity_error = (
        "LAN SD camera identity differs from supplied serial"
        if purpose == "playback"
        else "LAN catalog identity differs from supplied serial"
    )
    cleanup_note = (
        "LAN SD logout was not acknowledged; owned sockets were closed"
        if purpose == "playback"
        else "LAN catalog logout unacknowledged; owned sockets closed"
    )
    try:
        # __enter__ on the low-level client would connect before login can
        # enforce the shared absolute deadline.
        with closing(client_factory()) as login:
            result = login.login(
                password=password,
                username=username,
                rsa_key=rsa_key,
                max_frame_bytes=4096,
                deadline=deadline,
            )
            session = LanSdSession(
                client_factory,
                result.session_id,
                result.auth_seed,
                result.challenge,
                "",
            )
            session = replace(session, local_ip=str(login.sock.getsockname()[0]))
            if not result.serial.endswith(endpoint.serial):
                raise PyEzvizError(identity_error)
        yield session
    except BaseException as error:
        if session is not None:
            try:
                session.logout(deadline, stage)
            except Exception:
                error.add_note(cleanup_note)
        raise
    else:
        session.logout(deadline, stage)
