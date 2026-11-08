"""One synchronous physical-source budget for every integration delivery route."""
from __future__ import annotations

from .const import MAX_ACTIVE


class Admission:
    """Retain owner identity until its caller proves physical cleanup joined.

    Event-loop only. Retaining the actual owner prevents id reuse/ABA. Physical
    keys are private selectors, never credentials, capabilities or log messages.
    """

    def __init__(self) -> None:
        self._owners: dict[int, tuple[object, str]] = {}

    def reserve(self, owner: object, physical: str) -> bool:
        if id(owner) in self._owners:
            return (self._owners[id(owner)][0] is owner
                    and self._owners[id(owner)][1] == physical)
        if (len(self._owners) >= MAX_ACTIVE
                or any(key == physical for _, key in self._owners.values())):
            return False
        self._owners[id(owner)] = owner, physical
        return True

    def release(self, owner: object) -> None:
        if id(owner) in self._owners and self._owners[id(owner)][0] is owner:
            del self._owners[id(owner)]

    @property
    def active(self) -> int:
        return len(self._owners)
