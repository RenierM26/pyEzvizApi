"""Private atomic token storage used by the CLI push listeners."""

import json
import os

import pytest

from pyezvizapi._token_store import save_private_token


def test_token_replacement_is_owner_only(tmp_path):
    target = tmp_path / "token.json"
    target.write_text('{"old":true}')
    target.chmod(0o644)
    save_private_token(str(target), {"synthetic": "new"})
    assert json.loads(target.read_text()) == {"synthetic": "new"}
    if os.name == "posix":
        assert target.stat().st_mode & 0o777 == 0o600
    assert list(tmp_path.iterdir()) == [target]


def test_failed_replace_preserves_old_token_and_propagates(tmp_path, monkeypatch):
    target = tmp_path / "token.json"
    target.write_text('{"old":true}')

    def fail(*args):
        raise OSError("storage failure")

    monkeypatch.setattr("pyezvizapi._token_store.os.replace", fail)
    with pytest.raises(OSError):
        save_private_token(str(target), {"synthetic": "new"})
    assert json.loads(target.read_text()) == {"old": True}
    assert list(tmp_path.iterdir()) == [target]
