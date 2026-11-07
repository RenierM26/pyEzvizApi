"""Atomic owner-only token storage for the command-line listeners."""

import json
import os
from pathlib import Path
import tempfile
from typing import Any


def save_private_token(path: str, token: dict[str, Any]) -> None:
    """Persist or raise; never let push continue after an unnoticed write failure."""
    target = Path(path)
    staged: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=target.parent, prefix=f".{target.name}.", delete=False
        ) as temporary:
            staged = Path(temporary.name)
            json.dump(token, temporary)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(staged, target)
        if os.name == "posix":
            descriptor = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    finally:
        if staged is not None:
            staged.unlink(missing_ok=True)
