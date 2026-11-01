"""Host negotiation and generation-bound public completion receipts; no media I/O."""

import asyncio
from dataclasses import dataclass
from types import SimpleNamespace as N

from custom_components.ezviz_native import completion
from custom_components.ezviz_native.completion import CONTRACT, maybe_finite_delivery
import pytest

from pyezvizapi.native_completion import NativeMediaCompletion, NativeTrackCompletion
from pyezvizapi.native_stream import NativeStreamOptions, NativeTrackSelection


@dataclass(frozen=True)
class Counts:
    video: int
    audio: int


class Host:
    finite_source_state = "active"

    def __init__(self):
        self.handle = object()
        self.confirmations = []
        self.cancelled = []

    def async_prepare_finite_source(self):
        return self.handle

    def async_confirm_finite_source(self, handle, counts):
        self.confirmations.append((handle, counts))
        return True

    def async_cancel_finite_source(self, handle):
        self.cancelled.append(handle)
        self.finite_source_state = "cancelled"
        return True


@pytest.fixture
def context(monkeypatch):
    monkeypatch.setattr(
        completion.ha_stream, "FINITE_SOURCE_COMPLETION_CONTRACT", CONTRACT, raising=False
    )
    monkeypatch.setattr(completion.ha_stream, "FiniteSourceCounts", Counts, raising=False)
    options = NativeStreamOptions(NativeTrackSelection(480, 448), "hevc", finite_source=True)
    proof = NativeMediaCompletion(
        "opaque",
        0,
        (
            NativeTrackCompletion(480, 0, "video", "hevc", 10),
            NativeTrackCompletion(448, 1, "audio", "aac", 12),
        ),
    )
    output = N(
        source_generation="opaque", subscription_generation=0, completion=proof, options=options
    )
    owner = N(outputs=[output])
    runtime = N(
        settings=N(options=options),
        member="primary",
        closing=False,
        rearming=False,
        group=N(owner=owner, options={"primary": options}),
        token="capability",
    )
    return runtime, output, Host()


async def test_public_receipt_only_counts_confirm_exact_host_handle(hass, context):
    runtime, _output, host = context
    bridge = maybe_finite_delivery(hass, runtime, host)
    await bridge.task
    assert bridge.confirmed and host.confirmations == [(host.handle, Counts(10, 12))]
    await bridge.close()
    assert host.cancelled == [host.handle]


@pytest.mark.parametrize("version", [None, "unknown", "source-access-units-v2"])
async def test_missing_or_unknown_host_contract_keeps_stock_path(
    hass, context, monkeypatch, version
):
    runtime, _, host = context
    monkeypatch.setattr(completion.ha_stream, "FINITE_SOURCE_COMPLETION_CONTRACT", version)
    assert maybe_finite_delivery(hass, runtime, host) is None
    assert not host.confirmations and not host.cancelled


async def test_live_source_never_enables_finite_host_mode(hass, context):
    runtime, _, host = context
    runtime.settings.options = NativeStreamOptions(NativeTrackSelection(480, 448), "hevc")
    assert maybe_finite_delivery(hass, runtime, host) is None


@pytest.mark.parametrize(
    "method",
    ["async_prepare_finite_source", "async_confirm_finite_source", "async_cancel_finite_source"],
)
async def test_advertised_incomplete_contract_refused(hass, context, method):
    runtime, _, host = context
    setattr(host, method, None)
    with pytest.raises(RuntimeError, match="incomplete"):
        maybe_finite_delivery(hass, runtime, host)


@pytest.mark.parametrize(
    "change", ["owner", "output", "generation", "token", "closing", "rearming"]
)
async def test_stale_or_revoked_generation_never_confirms(hass, context, change):
    runtime, output, host = context
    proof, output.completion = output.completion, None
    bridge = maybe_finite_delivery(hass, runtime, host)
    if change == "owner":
        runtime.group.owner = N(outputs=[output])
    if change == "output":
        runtime.group.owner.outputs[0] = N()
    if change == "generation":
        output.subscription_generation = 1
    if change == "token":
        runtime.token = "new"
    if change == "closing":
        runtime.closing = True
    if change == "rearming":
        runtime.rearming = True
    output.completion = proof
    await bridge.task
    assert not bridge.confirmed and not host.confirmations
    assert host.cancelled == [host.handle]
    await bridge.close()


async def test_no_completion_cannot_authorize_final_media(hass, context):
    runtime, output, host = context
    output.completion = None
    bridge = maybe_finite_delivery(hass, runtime, host)
    await asyncio.sleep(0)
    assert not host.confirmations
    bridge.revoke()  # Must occur synchronously, before close awaits.
    assert host.cancelled == [host.handle]
    output.completion = NativeMediaCompletion("opaque", 0, ())
    await bridge.close()
    assert not host.confirmations


@pytest.mark.parametrize(
    "proof",
    [
        NativeMediaCompletion("foreign", 0, (NativeTrackCompletion(480, 0, "video", "hevc", 10),)),
        NativeMediaCompletion("opaque", 1, (NativeTrackCompletion(480, 0, "video", "hevc", 10),)),
        NativeMediaCompletion("opaque", 0, (NativeTrackCompletion(481, 0, "video", "hevc", 10),)),
    ],
)
async def test_foreign_completion_metadata_is_refused(hass, context, proof):
    runtime, output, host = context
    output.completion = proof
    bridge = maybe_finite_delivery(hass, runtime, host)
    await bridge.task
    assert not host.confirmations and host.cancelled == [host.handle]
    await bridge.close()

async def test_completion_available_before_host_start_waits_for_active(hass, context):
    runtime, _output, host = context
    host.finite_source_state = "ready"
    bridge = maybe_finite_delivery(hass, runtime, host)
    await asyncio.sleep(0)
    assert not host.confirmations
    host.finite_source_state = "active"
    await bridge.task
    assert bridge.confirmed
    await bridge.close()
