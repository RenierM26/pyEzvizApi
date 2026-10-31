"""Experimental fixed-output native session; not an HA registry or late-join API.

A single inherited transport/decrypt/demux worker owns every mux context. Outputs
are declared before start; they have independent stream-copy muxers and existing
four-chunk credits. A stalled output fails, never drops packets while succeeding.
"""
from __future__ import annotations

from collections.abc import Callable
from contextlib import ExitStack, suppress
from dataclasses import replace
from fractions import Fraction
import math
from threading import Lock
import time
from typing import Any

from .exceptions import PyEzvizError
from .native_stream import (
    _POLL_SECONDS,
    NativeMpegTsStream,
    NativePacketStream,
    NativeSourceClock,
    NativeStreamClosed,
    NativeStreamOptions,
    _Cancelled,
    _PsInput,
    _TsOutput,
)


def _no_source() -> NativePacketStream:
    raise RuntimeError("Only the session may construct its native source")


class _SessionOutput(NativeMpegTsStream):
    def __init__(self, session: NativeMpegTsSession, options: NativeStreamOptions) -> None:
        super().__init__(_no_source, options)
        self.session = session

    @property
    def source_clock(self) -> NativeSourceClock | None:
        return self.session.source_clock

    @property
    def accepting(self) -> bool:
        return not self._closed and self._failure is None

    def start(self) -> _SessionOutput:
        if self._closed:
            raise NativeStreamClosed("Session output is closed")
        self.session.start()
        return self

    def bind_tracks(self, incoming: Any) -> list[Any]:
        return self._selected_streams(incoming)

    def _reserve_output_slot(self) -> None:
        deadline = time.monotonic() + self.session.output_timeout
        while not self._output_slots.acquire(timeout=min(_POLL_SECONDS, self.session.output_timeout)):
            self._check_stop()
            if self.session.stop_requested:
                raise _Cancelled
            if time.monotonic() >= deadline:
                raise TimeoutError("Session output exceeded its bounded backpressure grace")

    def publish(self, chunk: bytes) -> None:
        if not self.accepting:
            return
        try:
            self._publish(chunk)
        except TimeoutError as error:
            self.fail_output(error)
        except _Cancelled:
            # Closing this output cannot cancel a healthy sibling's native input.
            return

    def fail_output(self, error: BaseException) -> None:
        if self._failure is None:
            self._failure = error

    def source_finished(self, *, completed: bool, failure: BaseException | None,
                        cleanup_errors: list[str]) -> None:
        if self._failure is None:
            self._failure = failure
        self._cleanup_errors = list(cleanup_errors)
        self._completed = (completed and not self._closed
                           and self._failure is None and not cleanup_errors)
        self._finished.set()

    @property
    def receipt(self) -> dict[str, Any]:
        result = super().receipt
        # A subscription owns no source worker; do not hide the physical owner.
        result["physical_source"] = self.session.physical_receipt
        return result

    def close_local(self) -> None:
        # No worker/transport belongs to an output. This drains only its credits.
        super().close()

    def close(self) -> None:
        self.close_local()
        self.session.stop_when_idle()


class NativeMpegTsSession(NativeMpegTsStream):
    """One explicit local source with 1-4 predeclared cold lens outputs.

    Experimental: no dynamic subscriptions, replay/cache, acquisition registry,
    automatic restart or group credential matching. Always retain/close this
    session as the authoritative physical-source owner, including close failure.
    """

    def __init__(self, source_factory: Callable[[], NativePacketStream],
                 outputs: tuple[NativeStreamOptions, ...], *,
                 media_key: str | bytes | None = None,
                 nalu_header_size: int | None = None, output_timeout: float = 0.1) -> None:
        if (not isinstance(outputs, tuple) or not 1 <= len(outputs) <= 4
                or not all(isinstance(option, NativeStreamOptions) for option in outputs)):
            raise ValueError("Declare one to four native output options")
        if len({option.selection for option in outputs}) != len(outputs):
            raise ValueError("Session outputs must have distinct selections")
        first = outputs[0]
        if any(replace(option, selection=first.selection) != first for option in outputs):
            raise ValueError("Session outputs require common codec, timeouts and EOF policy")
        if (isinstance(output_timeout, bool) or not isinstance(output_timeout, int | float)
                or not math.isfinite(output_timeout) or not 0 < output_timeout <= 1):
            raise ValueError("Output backpressure grace must be finite and at most one second")
        super().__init__(source_factory, first, media_key=media_key,
                         nalu_header_size=nalu_header_size)
        self.output_timeout = float(output_timeout)
        self.outputs = tuple(_SessionOutput(self, option) for option in outputs)
        self._session_close_lock = Lock()

    @property
    def stop_requested(self) -> bool:
        return self._stop.is_set()

    def read(self) -> bytes:
        raise PyEzvizError("Read a declared session output, not the physical owner")

    def stop_when_idle(self) -> None:
        with self._session_close_lock:
            if all(not output.accepting for output in self.outputs):
                # An implicit output exit cannot silently repeat a failed join budget.
                self._check_exit_cleanup()
                self._close_session()

    def close(self) -> None:
        with self._session_close_lock:
            self._close_session()

    def _close_session(self) -> None:
        self._request_stop()
        for output in self.outputs:
            with suppress(PyEzvizError):
                output.close_local()
        super().close()

    def _run(self) -> None:
        try:
            super()._run()
        finally:
            for output in self.outputs:
                output.source_finished(completed=self._completed, failure=self._failure,
                                       cleanup_errors=self._cleanup_errors)

    def _mux_selected(self, av: Any, incoming: Any, reader: _PsInput) -> None:
        with ExitStack() as stack:
            bindings = []
            selected = {}
            for output in self.outputs:
                tracks = output.bind_tracks(incoming)
                selected.update({stream.index: stream for stream in tracks})
                outgoing = stack.enter_context(av.open(
                    _TsOutput(output.publish), mode="w", format="mpegts",
                    options={"mpegts_copyts": "1", "max_delay": "0", "flush_packets": "1",
                             "max_interleave_delta": "1", "avoid_negative_ts": "disabled",
                             # Complete subsequent video PES extents let the
                             # demux parser release the opening AU before AAC.
                             "omit_video_pes_length": "0"},
                ))
                mapping = {stream.index: outgoing.add_stream_from_template(stream)
                           for stream in tracks}
                bindings.append((output, outgoing, mapping))
            self._tracks = [dict(id=s.id, index=s.index, kind=s.type, codec=s.codec_context.name)
                            for s in selected.values()]
            identities = {s.index: (s.id, s.codec_context.name) for s in selected.values()}
            count = 0
            last_dts: dict[int, Fraction] = {}
            for packet in incoming.demux(list(selected.values())):
                self._check_stop()
                if not any(output.accepting for output in self.outputs):
                    self._request_stop()
                    self._check_stop()
                if not packet.size:
                    continue
                self._check_packet_clock(packet, count)
                index = packet.stream.index
                if (packet.stream.id, packet.stream.codec_context.name) != identities[index]:
                    raise PyEzvizError("Session source track identity or codec changed")
                stamp = Fraction(packet.dts) * packet.time_base
                if index in last_dts and stamp <= last_dts[index]:
                    raise PyEzvizError("Session source decode timestamp repeated or moved backwards")
                last_dts[index] = stamp
                for output, outgoing, mapping in bindings:
                    if not output.accepting or index not in mapping:
                        continue
                    # Each muxer owns a new packet descriptor: do not mutate the
                    # source packet/stream when shared audio feeds both lenses.
                    copied = av.Packet(bytes(packet))
                    copied.pts, copied.dts = packet.pts, packet.dts
                    copied.duration, copied.time_base = packet.duration, packet.time_base
                    copied.is_keyframe, copied.is_corrupt = packet.is_keyframe, packet.is_corrupt
                    for side_data in packet.iter_sidedata():
                        copied.set_sidedata(side_data)
                    if packet.is_discard or packet.is_disposable:
                        raise PyEzvizError("Session packet has unimplemented output flag semantics")
                    copied.stream = mapping[index]
                    try:
                        outgoing.mux(copied)
                    except Exception as error:
                        output.fail_output(error)
                count += 1
            if not count or not reader.ended:
                raise PyEzvizError("Session source did not verify finite completion")

    @property
    def physical_receipt(self) -> dict[str, Any]:
        return super().receipt

    @property
    def receipt(self) -> dict[str, Any]:
        result = self.physical_receipt
        outputs = [output.receipt for output in self.outputs]
        counters = ("queued_chunks", "owned_output_chunks", "output_bytes", "read_output_bytes",
                    "discarded_output_bytes", "owned_output_bytes", "queue_capacity_bytes")
        result["output_totals"] = {key: sum(row[key] for row in outputs) for key in counters}
        for key in (*counters, "peak_owned_output_chunks", "peak_owned_output_bytes"):
            result.pop(key)
        result["source_status"] = result["status"]
        if any(row["status"] == "failed" for row in outputs):
            result["status"] = "failed"
        elif result["status"] == "completed" and any(
            row["status"] != "completed" for row in outputs
        ):
            result["status"] = "partial"
        result["outputs"] = outputs
        result["all_outputs_completed"] = all(row["status"] == "completed" for row in outputs)
        result["output_queue_capacity_bytes"] = sum(row["queue_capacity_bytes"] for row in outputs)
        return result
