"""Bounded identifier-chain checks for self-contained Annex-B IDR admission.

Not a decoder or full parameter-set validator. Only same-access-unit dependencies
are accepted; no cached media/parameters are inserted into an output.
"""

from __future__ import annotations

from collections.abc import Iterator
import re

from pyezvizapi.streaming.media.native_ps import MAX_PENDING_PS_BYTES

_START = re.compile(b"\x00\x00(?:\x00)?\x01")
_PREFIX_BYTES = 256


class _Bits:
    def __init__(self, data: memoryview) -> None:
        raw = bytes(data[:_PREFIX_BYTES])
        self.data = bytearray()
        zeros = 0
        for index, value in enumerate(raw):
            if zeros >= 2 and value == 3:
                # The bounded parse window must not invent EOF in the original NAL.
                if index + 1 == len(data) or data[index + 1] > 3:
                    raise ValueError("Invalid emulation prevention prefix")
                zeros = 0
                continue
            self.data.append(value)
            zeros = zeros + 1 if value == 0 else 0
        self.offset = 0

    def bits(self, count: int) -> int:
        if self.offset + count > len(self.data) * 8:
            raise ValueError("Truncated random-access identifier")
        value = 0
        for _ in range(count):
            value = value * 2 + ((self.data[self.offset // 8] >> (7 - self.offset % 8)) & 1)
            self.offset += 1
        return value

    def unsigned_golomb(self, maximum: int) -> int:
        zeros = 0
        while not self.bits(1):
            zeros += 1
            if zeros > maximum.bit_length():
                raise ValueError("Random-access identifier exceeds codec bounds")
        value = (1 << zeros) - 1 + self.bits(zeros)
        if value > maximum:
            raise ValueError("Random-access identifier exceeds codec bounds")
        return value


def _units(data: bytes) -> Iterator[memoryview]:
    previous = None
    view = memoryview(data)
    for start in _START.finditer(data):
        if previous is None:
            if any(view[: start.start()]):
                raise ValueError("Not Annex B")
        else:
            yield view[previous : start.start()]
        previous = start.end()
    if previous is not None:
        yield view[previous:]


def _hevc_sps(reader: _Bits) -> tuple[int, int]:
    vps = reader.bits(4)
    layers = reader.bits(3)
    if layers > 6:
        raise ValueError("Reserved HEVC sublayer count")
    reader.bits(1)
    reader.bits(96)  # general profile/tier/constraints and level
    flags = [(reader.bits(1), reader.bits(1)) for _ in range(layers)]
    if layers:
        if reader.bits(2 * (8 - layers)):
            raise ValueError("Reserved HEVC sublayer bits")
        for profile, level in flags:
            if profile:
                reader.bits(88)
            if level:
                reader.bits(8)
    return reader.unsigned_golomb(15), vps


def self_contained_idr(data: bytes, codec: str) -> bool:
    """Require matching in-band VPS/SPS/PPS IDs before a complete IDR picture.

    HEVC CRA/BLA, multilayer/temporal variants and H.264 partition/extensions are
    intentionally unsupported. A demux keyframe flag alone is insufficient.
    The source parser remains responsible for complete access-unit framing.
    """
    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_PENDING_PS_BYTES:
        return False
    try:
        return _check_idr(data, codec)
    except (ValueError, IndexError):
        return False


def _check_idr(data: bytes, codec: str) -> bool:  # noqa: PLR0911, PLR0912
    vps: set[int] = set()
    sps: dict[int, int] = {}
    pps: dict[int, int] = {}
    slices = 0
    for nal in _units(data):
        if not nal or nal[0] & 0x80:
            return False
        if codec == "h264":
            kind = nal[0] & 31
            reader = _Bits(nal[1:])
            if kind in {5, 7, 8} and not nal[0] & 0x60:
                return False
            if kind == 7:
                reader.bits(24)
                key = reader.unsigned_golomb(31)
                if slices or key in sps:
                    return False
                sps[key] = 0
            elif kind == 8:
                key, parent = reader.unsigned_golomb(255), reader.unsigned_golomb(31)
                if slices or key in pps or parent not in sps:
                    return False
                pps[key] = parent
            elif kind == 5:
                first, slice_type, key = (
                    reader.unsigned_golomb(65535),
                    reader.unsigned_golomb(9),
                    reader.unsigned_golomb(255),
                )
                if (first == 0) != (slices == 0) or slice_type not in {2, 7} or key not in pps:
                    return False
                slices += 1
            elif kind not in {6, 9, 12}:
                return False
        elif codec == "hevc":
            # Base layer, temporal_id_plus1=1 only. Do not infer dependencies
            # of scalable/multiview or temporal random-access variants.
            if len(nal) < 3 or nal[0] & 1 or nal[1] != 1:
                return False
            kind = (nal[0] >> 1) & 63
            reader = _Bits(nal[2:])
            if kind == 32:
                key = reader.bits(4)
                if slices or key in vps:
                    return False
                vps.add(key)
            elif kind == 33:
                key, parent = _hevc_sps(reader)
                if slices or key in sps or parent not in vps:
                    return False
                sps[key] = parent
            elif kind == 34:
                key, parent = reader.unsigned_golomb(63), reader.unsigned_golomb(15)
                if slices or key in pps or parent not in sps:
                    return False
                pps[key] = parent
            elif kind in {19, 20}:
                first = reader.bits(1)
                reader.bits(1)  # no_output_of_prior_pics_flag
                key = reader.unsigned_golomb(63)
                if bool(first) != (slices == 0) or key not in pps:
                    return False
                slices += 1
            elif kind not in {35, 38, 39, 40}:
                return False
        else:
            return False
    return slices > 0
