"""Shared offline fixtures for the test suite."""

from __future__ import annotations

import base64
from collections.abc import Iterator

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import pytest

_LOGIN_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
LOGIN_PUBLIC_KEY = base64.b64encode(
    _LOGIN_KEY.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
).decode()


def decrypt_login_password(value: str) -> str:
    """Return the ``digest,epoch`` plaintext of a v6 login password field."""
    return _LOGIN_KEY.decrypt(base64.b64decode(value), padding.PKCS1v15()).decode()


@pytest.fixture(autouse=True)
def offline_login_public_key(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Serve a local RSA key so credential logins never fetch the real one."""
    monkeypatch.setattr(
        "pyezvizapi.client.fetch_login_public_key", lambda *args, **kwargs: LOGIN_PUBLIC_KEY
    )
    yield
