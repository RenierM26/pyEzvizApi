"""Optional versioned HA finite-source API; no host monkeypatch or extra demux."""
from __future__ import annotations

import asyncio
from collections.abc import Callable
from contextlib import suppress
from typing import Any, Protocol, cast

from homeassistant.components import stream as ha_stream
from homeassistant.components.stream import Stream
from homeassistant.core import HomeAssistant

from .entry_runtime import LensRuntime

CONTRACT = "source-access-units-v1"
_HOST_METHODS = ("async_prepare_finite_source", "async_confirm_finite_source",
                 "async_cancel_finite_source")


def finite_source_host_available() -> bool:
    """Inspect the public host contract without a stream, registration or source."""
    return (getattr(ha_stream, "FINITE_SOURCE_COMPLETION_CONTRACT", None) == CONTRACT
            and callable(getattr(ha_stream, "FiniteSourceCounts", None))
            and all(callable(getattr(Stream, name, None)) for name in _HOST_METHODS))


class _FiniteHost(Protocol):
    """Shape used only after explicit host-version negotiation."""

    @property
    def finite_source_state(self) -> str | None:
        raise NotImplementedError

    def async_prepare_finite_source(self) -> object:
        raise NotImplementedError

    def async_confirm_finite_source(self, handle: object, counts: object) -> bool:
        raise NotImplementedError

    def async_cancel_finite_source(self, handle: object) -> bool:
        raise NotImplementedError


class GroupFiniteDelivery:
    """Bind an explicit finite lens output to exactly one host generation."""

    def __init__(self, hass: HomeAssistant, runtime: LensRuntime, stream: Stream) -> None:
        self.runtime, self.stream = runtime, stream
        self.owner = runtime.group.owner
        self.index = tuple(runtime.group.options).index(runtime.member)
        self.output = self.owner.outputs[self.index]
        self.source_generation = self.output.source_generation
        self.subscription_generation = self.output.subscription_generation
        self.token = runtime.token
        self.revoked = self.confirmed = False
        # Access only after exact public contract negotiation in maybe_finite_delivery.
        self._host = cast(_FiniteHost, stream)
        self.handle = self._host.async_prepare_finite_source()
        self._confirm = self._host.async_confirm_finite_source
        self._cancel = self._host.async_cancel_finite_source
        self._counts = cast(Callable[..., Any], getattr(ha_stream, "FiniteSourceCounts", None))
        self.task = hass.async_create_background_task(self._run(), "EZVIZ finite completion")

    def current(self) -> bool:
        """No await separates this generation check from host confirmation."""
        return (not self.revoked and not self.runtime.closing and not self.runtime.rearming
                and self.runtime.group.owner is self.owner
                and self.owner.outputs[self.index] is self.output
                and self.output.source_generation == self.source_generation
                and self.output.subscription_generation == self.subscription_generation
                and self.runtime.token == self.token)

    async def _run(self) -> None:
        while self._host.finite_source_state in (
            "ready", "active", "waiting_for_confirmation",
        ):
            if not self.current():
                self.revoke()
                return
            completion = self.output.completion
            if completion is not None and self._host.finite_source_state != "ready":
                selection = self.output.options.selection
                expected = {selection.video_id}
                if selection.audio_id is not None:
                    expected.add(selection.audio_id)
                if (completion.source_generation != self.source_generation
                        or completion.subscription_generation != self.subscription_generation
                        or {t.track_id for t in completion.tracks} != expected):
                    self.revoke()
                    return
                self.confirmed = bool(self._confirm(self.handle, self._counts(
                    video=completion.video_units, audio=completion.audio_units,
                )))
                return
            # Read-only bounded snapshots; no join/acquisition/receipt reconstruction.
            await asyncio.sleep(.025)

    def revoke(self) -> None:
        """Revoke host publication synchronously before any awaited teardown."""
        if not self.revoked:
            self.revoked = True
            self._cancel(self.handle)

    async def close(self) -> None:
        """Join the sole integration-owned observer task, never the source here."""
        self.revoke()
        self.task.cancel()
        with suppress(asyncio.CancelledError):
            await self.task


def maybe_finite_delivery(
    hass: HomeAssistant, runtime: LensRuntime, stream: Stream,
) -> GroupFiniteDelivery | None:
    """Keep stock HA and live-source behavior unchanged; no ignored host options."""
    if (not runtime.settings.options.finite_source
            or getattr(ha_stream, "FINITE_SOURCE_COMPLETION_CONTRACT", None) != CONTRACT):
        return None
    if not all(callable(getattr(stream, name, None)) for name in _HOST_METHODS):
        raise RuntimeError("HA finite-source contract is incomplete")
    if not callable(getattr(ha_stream, "FiniteSourceCounts", None)):
        raise RuntimeError("HA finite-source count contract is missing")
    return GroupFiniteDelivery(hass, runtime, stream)
