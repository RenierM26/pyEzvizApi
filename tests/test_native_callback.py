"""A native backend retry must not replace or print the original source error."""
import asyncio
import threading
import traceback

import pytest
from test_native_stream import Source

from pyezvizapi import native_stream
from pyezvizapi.exceptions import PyEzvizError


def test_callback_failure_is_sticky_sanitized_and_does_not_pull_again():
    error = ValueError("private endpoint and credential detail")

    class Source:
        calls = 0
        closed = False

        def close(self):
            self.closed = True

        def iter_media_packets(self):
            return self

        def __iter__(self):
            return self

        def __next__(self):
            self.calls += 1
            raise error

    source = Source()
    reader = native_stream._PsInput(  # noqa: SLF001 - exercise the C callback contract.
        source, media_key=None, nalu_header_size=2,
        finite_source=False, check_stop=lambda: None,
    )
    try:
        for _attempt in range(3):
            with pytest.raises(PyEzvizError) as caught:
                reader.read(65536)
            assert "private endpoint" not in "".join(traceback.format_exception(caught.value))
            assert reader.failure is error
        assert source.calls == 1
    finally:
        reader.close()
    assert source.closed


def test_owned_async_calls_do_not_report_expected_errors_after_shield_cancellation(monkeypatch):
    """Model 3.14.8's shield logger, even on runtimes where it was removed."""
    original_shield = asyncio.shield
    reports = []

    def reporting_shield(task):
        outer = original_shield(task)

        def check(inner):
            if not inner.cancelled() and inner.exception() is not None:
                reports.append(inner.exception())

        def cancelled(done):
            if done.cancelled() and not task.done():
                task.add_done_callback(check)

        outer.add_done_callback(cancelled)
        return outer

    monkeypatch.setattr(asyncio, "shield", reporting_shield)

    async def scenario():
        entered, release = threading.Event(), threading.Event()
        stream = native_stream.NativeMpegTsStream(
            Source,  # Never opened: test an owned cleanup call's failure.
            native_stream.NativeStreamOptions(native_stream.NativeTrackSelection(480), "hevc"),
        )

        def failed_close():
            entered.set()
            assert release.wait(2)
            raise PyEzvizError("Expected cleanup failure")

        monkeypatch.setattr(stream, "close", failed_close)
        pending = asyncio.create_task(stream.aclose())
        assert await asyncio.to_thread(entered.wait, 2)
        pending.cancel()
        await asyncio.sleep(0)
        release.set()
        with pytest.raises(asyncio.CancelledError):
            result = await asyncio.gather(pending)
            pytest.fail(f"Cancellation lost: {result!r}")
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert not reports

    asyncio.run(scenario())
