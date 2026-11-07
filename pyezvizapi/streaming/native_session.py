# Preserve existing compatibility exports and internal owner access.
# ruff: noqa: SLF001
"""Experimental declared-output native session, independent of HA ownership.

A single inherited transport/decrypt/demux worker owns every mux context. Outputs
are declared before start; they have independent stream-copy muxers and existing
four-chunk credits. Optional late activation waits for original self-contained
IDR dependencies. Explicit replacement retires the previous mux on its worker,
without media replay. A stalled output fails, never drops packets while succeeding.
"""

# The physical owner and its private output handles share lifecycle state.
from __future__ import annotations

from collections.abc import Callable
from contextlib import ExitStack, suppress
from dataclasses import dataclass, replace
from fractions import Fraction
import math
from threading import Event, Lock
import time
from typing import Any

from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.streaming.media.access import self_contained_idr
from pyezvizapi.streaming.media.completion import NativeMediaCompletion
from pyezvizapi.streaming.native_stream import (
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
    def __init__(
        self, session: NativeMpegTsSession, options: NativeStreamOptions, generation: int = 0
    ) -> None:
        super().__init__(
            _no_source, options, _completion_identity=(session.source_generation, generation)
        )
        self.session = session
        self._requested = Event()
        self._retired = Event()
        self.generation = generation
        self.join_pts: Fraction | None = None
        self.join_clock: NativeSourceClock | None = None
        self.cold = False

    @property
    def requested(self) -> bool:
        return not self.session.late_join or self._requested.is_set()

    @property
    def source_clock(self) -> NativeSourceClock | None:
        return (
            self.join_clock
            if self.session.late_join and not self.cold
            else self.session.source_clock
        )

    @property
    def accepting(self) -> bool:
        return not self._closed and self._failure is None

    def start(self) -> _SessionOutput:
        self.session._start_output(self)
        return self

    def bind_tracks(self, incoming: Any) -> list[Any]:
        return self._selected_streams(incoming)

    def _reserve_output_slot(self) -> None:
        deadline = time.monotonic() + self.session.output_timeout
        while not self._output_slots.acquire(
            timeout=min(_POLL_SECONDS, self.session.output_timeout)
        ):
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

    def source_finished(
        self, *, completed: bool, failure: BaseException | None, cleanup_errors: list[str]
    ) -> None:
        if self.session.late_join and not self.cold and self.join_pts is None:
            completed = False
            if self.requested and not self._closed and failure is None:
                failure = PyEzvizError("Source ended before a self-contained IDR join")
        if self._failure is None:
            self._failure = failure
        self._cleanup_errors = list(cleanup_errors)
        self._completed = (
            completed and not self._closed and self._failure is None and not cleanup_errors
        )
        self._finished.set()

    @property
    def receipt(self) -> dict[str, Any]:
        result = super().receipt
        # A subscription owns no source worker; do not hide the physical owner.
        result["physical_source"] = self.session.physical_receipt
        result["subscription_generation"] = self.generation
        result["mux_retired"] = self._retired.is_set()
        if self.session.late_join:
            result["subscription_requested"] = self.requested
            result["subscription_mode"] = "cold" if self.cold else "idr"
            result["join_pts"] = str(self.join_pts) if self.join_pts is not None else None
            result["join_origin_90k"] = self.join_clock.origin_90k if self.join_clock else None
            if not self.requested:
                result["status"] = "unused"
        if result["status"] == "completed":
            if result["discarded_output_bytes"]:
                result["status"] = "partial"
            elif result["owned_output_chunks"]:
                result["status"] = "draining"
        return result

    @property
    def completion(self) -> NativeMediaCompletion | None:
        """Require this subscription and its authoritative physical source."""
        receipt = self.receipt
        return self._completion_from_receipts(receipt, receipt["physical_source"])

    def close_local(self) -> None:
        # No worker/transport belongs to an output. This drains only its credits.
        super().close()

    def close(self) -> None:
        self.close_local()
        self.session.stop_when_idle()


@dataclass
class _Binding:
    output: _SessionOutput
    tracks: list[Any]
    muxer: Any
    mapping: dict[int, Any]
    context: ExitStack | None = None


class NativeMpegTsSession(NativeMpegTsStream):
    """One explicit local source with 1-4 predeclared lens outputs.

    Default: fixed cold delivery. Explicit late_join enables activation and
    explicit replacement at original same-AU IDR dependencies, with no replay/cache,
    new track selection, automatic restart or acquisition registry. Always retain
    this authoritative physical owner, including close failure.
    """

    def __init__(
        self,
        source_factory: Callable[[], NativePacketStream],
        outputs: tuple[NativeStreamOptions, ...],
        *,
        media_key: str | bytes | None = None,
        nalu_header_size: int | None = None,
        output_timeout: float = 0.1,
        late_join: bool = False,
    ) -> None:
        if (
            not isinstance(outputs, tuple)
            or not 1 <= len(outputs) <= 4
            or not all(isinstance(option, NativeStreamOptions) for option in outputs)
        ):
            raise ValueError("Declare one to four native output options")
        if len({option.selection for option in outputs}) != len(outputs):
            raise ValueError("Session outputs must have distinct selections")
        first = outputs[0]
        if any(replace(option, selection=first.selection) != first for option in outputs):
            raise ValueError("Session outputs require common codec, timeouts and EOF policy")
        if (
            isinstance(output_timeout, bool)
            or not isinstance(output_timeout, int | float)
            or not math.isfinite(output_timeout)
            or not 0 < output_timeout <= 1
        ):
            raise ValueError("Output backpressure grace must be finite and at most one second")
        if not isinstance(late_join, bool):
            raise ValueError("Late subscription mode must be explicit boolean")
        super().__init__(
            source_factory, first, media_key=media_key, nalu_header_size=nalu_header_size
        )
        self.late_join = late_join
        self.output_timeout = float(output_timeout)
        self.outputs = tuple(_SessionOutput(self, option) for option in outputs)
        self._session_close_lock = Lock()
        self._retired_count = self._retired_failed = self._retired_partial = 0
        self._retired_bytes = {
            key: 0
            for key in (
                "output_bytes",
                "read_output_bytes",
                "discarded_output_bytes",
            )
        }

    def _start_output(self, output: _SessionOutput) -> None:
        with self._session_close_lock:
            if output._closed or output not in self.outputs:
                raise NativeStreamClosed("Session output is closed or superseded")
            if self.late_join and not output.requested:
                if self.source_finished or self.stop_requested:
                    raise NativeStreamClosed("Cannot attach after physical source completion")
                output._requested.set()
            self.start()

    def replace_output(self, previous: NativeMpegTsStream) -> NativeMpegTsStream:
        """Explicitly replace one closed late-mode handle, never its source.

        May wait up to close_timeout for worker-owned mux retirement. Call off an
        event loop. A healthy requested sibling must keep the acquisition alive;
        EOF, cancellation, active/reading outputs and stale handles fail closed.
        The returned handle remains lazy until read/start and always joins at a
        new original IDR. No histories, muxers or queues accumulate per renewal.
        """

        def eligible() -> bool:
            return (
                self.late_join
                and previous in self.outputs
                and previous._closed
                and not previous._read_lock.locked()
                and not self.stop_requested
                and not self.source_finished
                and self._failure is None
                and not self._cleanup_errors
                and self._worker is not None
                and self._worker.is_alive()
                and any(
                    out is not previous and out.requested and out.accepting for out in self.outputs
                )
            )

        with self._session_close_lock:
            if not eligible():
                raise NativeStreamClosed("Replacement requires a retired lens and live sibling")
        assert isinstance(previous, _SessionOutput)
        if not previous._retired.wait(self.options.close_timeout):
            raise PyEzvizError("Lens mux retirement timed out; previous handle retained")
        with self._session_close_lock:
            if not eligible() or previous.receipt["owned_output_chunks"]:
                raise NativeStreamClosed("Lens or physical generation changed during retirement")
            output = _SessionOutput(self, previous.options, previous.generation + 1)
            receipt = previous.receipt
            self._retired_count += 1
            self._retired_failed += (
                receipt["subscription_requested"] and receipt["status"] == "failed"
            )
            self._retired_partial += (
                receipt["subscription_requested"] and receipt["status"] != "completed"
            )
            for key in self._retired_bytes:
                self._retired_bytes[key] += receipt[key]
            self.outputs = tuple(output if out is previous else out for out in self.outputs)
            return output

    def start(self) -> NativeMpegTsSession:
        """Late-mode context entry alone cannot open an idle acquisition."""
        if not self.late_join or any(output.requested for output in self.outputs):
            super().start()
        return self

    @property
    def source_finished(self) -> bool:
        """A completed acquisition never admits another subscription."""
        return self._finished.is_set()

    @property
    def stop_requested(self) -> bool:
        return self._stop.is_set()

    def read(self) -> bytes:
        raise PyEzvizError("Read a declared session output, not the physical owner")

    def stop_when_idle(self) -> None:
        with self._session_close_lock:
            if all(not output.requested or not output.accepting for output in self.outputs):
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
                output.source_finished(
                    completed=self._completed,
                    failure=self._failure,
                    cleanup_errors=self._cleanup_errors,
                )

    def _mux_selected(self, av: Any, incoming: Any, reader: _PsInput) -> None:
        with ExitStack() as stack:
            bindings = []
            selected = {}
            for output in self.outputs:
                tracks = output.bind_tracks(incoming)
                selected.update({stream.index: stream for stream in tracks})
                # Requests present before selected demux begins retain the
                # existing complete cold prefix, including early-demuxed AAC.
                output.cold = self.late_join and output.requested and output.generation == 0
                context = stack.enter_context(ExitStack())
                outgoing, mapping = (
                    (None, {})
                    if self.late_join and not output.cold
                    else self._open_output(
                        av,
                        context,
                        output,
                        tracks,
                    )
                )
                bindings.append(_Binding(output, tracks, outgoing, mapping, context))
            self._tracks = [
                dict(id=s.id, index=s.index, kind=s.type, codec=s.codec_context.name)
                for s in selected.values()
            ]
            identities = {s.index: (s.id, s.codec_context.name) for s in selected.values()}
            count = 0
            last_dts: dict[int, Fraction] = {}
            for packet in incoming.demux(list(selected.values())):
                self._check_stop()
                if not any(output.requested and output.accepting for output in self.outputs):
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
                    raise PyEzvizError(
                        "Session source decode timestamp repeated or moved backwards"
                    )
                last_dts[index] = stamp
                for position, binding in enumerate(bindings):
                    if binding.output._closed and not binding.output._retired.is_set():
                        assert binding.context is not None
                        binding.context.close()  # Only this worker may close a PyAV muxer.
                        binding.muxer, binding.mapping = None, {}
                        binding.output._retired.set()
                    current = self.outputs[position]
                    if current is not binding.output:
                        binding.output = current
                    self._deliver_packet(av, binding.context, binding, packet)
                count += 1
            if not count or not reader.ended:
                raise PyEzvizError("Session source did not verify finite completion")
        for binding in bindings:
            binding.output._retired.set()  # ExitStack verified every mux close.

    def _deliver_packet(
        self, av: Any, stack: ExitStack | None, binding: _Binding, packet: Any
    ) -> None:
        output, outgoing, mapping, tracks = (
            binding.output,
            binding.muxer,
            binding.mapping,
            binding.tracks,
        )
        index = packet.stream.index
        if not output.requested or not output.accepting:
            return
        if self.late_join and outgoing is None:
            if not self._admit_idr(output, packet):
                return
            try:
                assert stack is not None
                outgoing, mapping = self._open_output(av, stack, output, tracks)
            except Exception as error:
                output.fail_output(error)
                return
            binding.muxer, binding.mapping = outgoing, mapping
        if index not in mapping:
            return
        if (
            self.late_join
            and not output.cold
            and output.join_pts is not None
            and Fraction(packet.pts) * packet.time_base < output.join_pts
        ):
            if packet.stream.type == "video":
                output.fail_output(PyEzvizError("Unsupported leading picture after IDR"))
            return  # Never backfill AAC preceding this original RAP.
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
            if output.accepting:
                output._record_access_unit(index)
        except Exception as error:
            output.fail_output(error)

    def _open_output(
        self, av: Any, stack: ExitStack, output: _SessionOutput, tracks: list[Any]
    ) -> tuple[Any, dict[int, Any]]:
        with output._lock:
            output._tracks = [
                dict(
                    id=track.id, index=track.index, kind=track.type, codec=track.codec_context.name
                )
                for track in tracks
            ]
        outgoing = stack.enter_context(
            av.open(
                _TsOutput(output.publish),
                mode="w",
                format="mpegts",
                options={
                    "mpegts_copyts": "1",
                    "max_delay": "0",
                    "flush_packets": "1",
                    "max_interleave_delta": "1",
                    "avoid_negative_ts": "disabled",
                    "omit_video_pes_length": "0",
                },
            )
        )
        return outgoing, {
            stream.index: outgoing.add_stream_from_template(stream) for stream in tracks
        }

    def _admit_idr(self, output: _SessionOutput, packet: Any) -> bool:
        if (
            packet.stream.id != output.options.selection.video_id
            or not packet.is_keyframe
            or packet.is_corrupt
            or not self_contained_idr(bytes(packet), output.options.video_codec)
        ):
            return False
        origin = Fraction(packet.pts) * packet.time_base * 90000
        try:
            if origin.denominator != 1:
                raise ValueError("Nonintegral join origin")
            output.join_clock = NativeSourceClock(int(origin))
            output.join_pts = origin / 90000
        except ValueError as error:
            output.fail_output(error)
            return False
        return True

    @property
    def completion(self) -> NativeMediaCompletion | None:
        """Query a declared output for completion, never the physical aggregate."""
        return None

    @property
    def physical_receipt(self) -> dict[str, Any]:
        return super().receipt

    @property
    def receipt(self) -> dict[str, Any]:
        result = self.physical_receipt
        outputs = [output.receipt for output in self.outputs]
        counters = (
            "queued_chunks",
            "owned_output_chunks",
            "output_bytes",
            "read_output_bytes",
            "discarded_output_bytes",
            "owned_output_bytes",
            "queue_capacity_bytes",
        )
        result["output_totals"] = {key: sum(row[key] for row in outputs) for key in counters}
        for key in (*counters, "peak_owned_output_chunks", "peak_owned_output_bytes"):
            result.pop(key)
        result["source_status"] = result["status"]
        result["retired_subscriptions"] = self._retired_count
        result["retired_failed_subscriptions"] = self._retired_failed
        result["retired_partial_subscriptions"] = self._retired_partial
        result["retired_output_totals"] = dict(self._retired_bytes)
        considered = [row for row in outputs if row.get("subscription_requested", True)]
        if self._retired_failed or any(row["status"] == "failed" for row in considered):
            result["status"] = "failed"
        elif result["status"] == "completed" and (
            self._retired_partial or any(row["status"] != "completed" for row in considered)
        ):
            result["status"] = "partial"
        result["outputs"] = outputs
        result["all_outputs_completed"] = not self._retired_partial and all(
            row["status"] == "completed" for row in outputs
        )
        result["current_requested_outputs_completed"] = bool(considered) and all(
            row["status"] == "completed" for row in considered
        )
        result["all_requested_outputs_completed"] = (
            not self._retired_partial and result["current_requested_outputs_completed"]
        )
        result["output_queue_capacity_bytes"] = sum(row["queue_capacity_bytes"] for row in outputs)
        return result
