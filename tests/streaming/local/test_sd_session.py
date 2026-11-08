"""Both SD operations share cancellation, identity and cleanup ownership."""

from contextlib import closing
from types import SimpleNamespace
from typing import Any, cast

import pytest

from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.streaming.local.sd_session import lan_sd_session
from tests.streaming.local.test_lan_sd_playback import ENDPOINT, Socket


@pytest.mark.parametrize("purpose", ["catalog", "playback"])
@pytest.mark.parametrize("failure", ["identity", "operation", "interrupt", "logout", "address"])
def test_shared_lifecycle_failure_ownership(purpose, failure):
    clients: list[Any] = []
    calls: list[tuple[int | str, float]] = []
    error = KeyboardInterrupt() if failure == "interrupt" else PyEzvizError("source")

    class Client:
        def __init__(self):
            self.sock: Any = Socket(b"")
            self.closed = False
            self.index = len(clients)
            clients.append(self)

        def login(self, **kwargs):
            calls.append(("login", kwargs["deadline"]))
            if failure == "address":
                self.sock.getsockname = lambda: (_ for _ in ()).throw(error)
            return SimpleNamespace(
                session_id=b"1234",
                auth_seed=5,
                challenge=b"synthetic-key-1234",
                serial="WRONG" if failure == "identity" else ENDPOINT.serial,
            )

        def send_command_frame(self, frame, **kwargs):
            calls.append((int.from_bytes(frame[12:16], "big"), kwargs["deadline"]))

        def read_tcp_frame(self, **kwargs):
            if failure == "logout":
                raise error
            return SimpleNamespace(header=SimpleNamespace(field_8=1))

        def close(self):
            self.closed = True

    with (
        pytest.raises(BaseException) as raised,
        lan_sd_session(
            ENDPOINT,
            "synthetic",
            username="admin",
            deadline=123.0,
            rsa_key=object(),
            client_factory=cast(Any, Client),
            purpose=purpose,
        ) as session,
        closing(session.client()),
    ):
        if failure in ("operation", "interrupt"):
            raise error
    assert all(c.closed for c in clients)
    if failure == "identity":
        assert "identity differs" in str(raised.value)
    else:
        assert raised.value is error
    # Address lookup fails after successful login; the owned session must still
    # attempt logout (frame construction can fail with no usable local address).
    assert len(clients) >= 2
    if failure != "address":
        assert (0x10100, 123.0) in calls
