"""No decoder/keyframe-flag shortcuts for in-band random-access dependencies."""

import pytest

from pyezvizapi.streaming.media.access import _Bits, _hevc_sps, self_contained_idr
from pyezvizapi.streaming.media.native_ps import MAX_PENDING_PS_BYTES


def unsigned_golomb(value):
    encoded = f"{value + 1:b}"
    return "0" * (len(encoded) - 1) + encoded


def rbsp(bits):
    bits += "1"
    bits += "0" * (-len(bits) % 8)
    raw = int(bits, 2).to_bytes(len(bits) // 8, "big")
    escaped = bytearray()
    zeros = 0
    for value in raw:
        if zeros >= 2 and value <= 3:
            escaped.append(3)
            zeros = 0
        escaped.append(value)
        zeros = zeros + 1 if value == 0 else 0
    return bytes(escaped)


def h264(kind, bits):
    return b"\x00\x00\x01" + bytes([0x60 | kind]) + rbsp(bits)


def hevc(kind, bits, header=1):
    return b"\x00\x00\x00\x01" + bytes([kind << 1, header]) + rbsp(bits)


def chain(codec, *, pps_parent=0, slice_pps=0, first=1, slice_type=2, kind=None):
    if codec == "h264":
        return (h264(7, "0" * 24 + unsigned_golomb(0)) + h264(8, unsigned_golomb(0) + unsigned_golomb(pps_parent))
                + h264(kind or 5, unsigned_golomb(0 if first else 1) + unsigned_golomb(slice_type) + unsigned_golomb(slice_pps)))
    return (hevc(32, "0000") + hevc(33, "00000001" + "0" * 96 + unsigned_golomb(0))
            + hevc(34, unsigned_golomb(0) + unsigned_golomb(pps_parent))
            + hevc(kind or 19, str(first) + "0" + unsigned_golomb(slice_pps)))


@pytest.mark.parametrize("codec", ["h264", "hevc"])
def test_matching_self_contained_identifier_chain(codec):
    assert self_contained_idr(chain(codec), codec)


@pytest.mark.parametrize("codec", ["h264", "hevc"])
@pytest.mark.parametrize("change", [{"pps_parent": 1}, {"slice_pps": 1}, {"first": 0}])
def test_mismatched_or_nonfirst_slice_does_not_join(codec, change):
    assert not self_contained_idr(chain(codec, **change), codec)


@pytest.mark.parametrize("kind", [1, 2, 3, 4, 19, 20, 21])
def test_h264_non_idr_or_partitioned_extensions_are_not_admitted(kind):
    assert not self_contained_idr(chain("h264", kind=kind), "h264")


@pytest.mark.parametrize("kind", [0, 1, 16, 17, 18, 21, 22, 23])
def test_hevc_cra_bla_and_non_idr_are_not_admitted(kind):
    assert not self_contained_idr(chain("hevc", kind=kind if kind else 1), "hevc")


@pytest.mark.parametrize("codec", ["h264", "hevc"])
def test_parameter_sets_must_precede_picture_and_not_be_duplicated(codec):
    data = chain(codec)
    assert not self_contained_idr(data + data, codec)
    first = data.find(b"\x00\x00\x01", 4)
    assert not self_contained_idr(data[first:], codec)
    assert not self_contained_idr(b"bad" + data, codec)
    assert not self_contained_idr(data.replace(b"\x00\x00\x00\x01", b"\x00\x00\x01"), "vp9")


@pytest.mark.parametrize("codec", ["h264", "hevc"])
def test_truncated_headers_and_missing_dependencies_fail_closed(codec):
    data = chain(codec)
    for prefix in (b"", b"\0\0\1", b"\0\0\1\x80", b"\0\0\1\x26\x00", b"no-start"):
        assert not self_contained_idr(prefix, codec)
    assert not self_contained_idr(b"x" * (MAX_PENDING_PS_BYTES + 1), codec)
    assert not self_contained_idr(data[-1:], codec)


@pytest.mark.parametrize("header", [0, 2, 9])
def test_hevc_temporal_or_multilayer_dependencies_not_inferred(header):
    data = chain("hevc").replace(b"\x40\x01", bytes([0x40, header]), 1)
    assert not self_contained_idr(data, "hevc")


def test_exp_golomb_and_emulation_prevention_are_bounded():
    for data in (b"\0\0\3", b"\0\0\3\x04"):
        with pytest.raises(ValueError):
            _Bits(memoryview(data))
    for data in (b"", b"\0" * 256):
        with pytest.raises(ValueError):
            _Bits(memoryview(data)).unsigned_golomb(31)
    with pytest.raises(ValueError):
        _Bits(memoryview(rbsp(unsigned_golomb(32)))).unsigned_golomb(31)
    assert _Bits(memoryview(b"\0\0\3\x01")).bits(24) == 1


def test_hevc_sps_sublayer_profile_bounds():
    # One sublayer with profile and level present; all reserved flags zero.
    bits = "00000011" + "0" * 96 + "11" + "0" * 14 + "0" * 96 + unsigned_golomb(3)
    assert _hevc_sps(_Bits(memoryview(rbsp(bits)))) == (3, 0)
    for bits in ("00001111", "00000011" + "0" * 96 + "00" + "1" * 14):
        with pytest.raises(ValueError):
            _hevc_sps(_Bits(memoryview(rbsp(bits))))



def test_h264_idr_and_parameter_sets_must_have_reference_priority():
    for header in (b"\x67", b"\x68", b"\x65"):
        changed = chain("h264").replace(header, bytes([header[0] & 31]), 1)
        assert not self_contained_idr(changed, "h264")


@pytest.mark.parametrize('following', [0, 1, 2, 3])
def test_emulation_prevention_at_prefix_end_uses_unparsed_lookahead(following):
    prefix = b'\x55' * 253 + b'\x00\x00\x03'
    reader = _Bits(memoryview(prefix + bytes([following]) + b'\x80'))
    assert bytes(reader.data) == prefix[:-1]
    _ = reader.bits(len(reader.data) * 8)
    with pytest.raises(ValueError, match='Truncated'):
        reader.bits(1)  # The validated lookahead must not expand identifier parsing.


@pytest.mark.parametrize('tail', [b'', b'\x04', b'\xff'])
def test_emulation_prevention_at_prefix_end_still_rejects_invalid_tail(tail):
    prefix = b'\x55' * 253 + b'\x00\x00\x03'
    with pytest.raises(ValueError, match='Invalid emulation prevention'):
        _Bits(memoryview(prefix + tail))


@pytest.mark.parametrize('codec', ['h264', 'hevc'])
def test_valid_unregistered_sei_at_prefix_boundary_does_not_block_idr(codec):
    # Type 5 / size 254: 16 UUID bytes and 238 data bytes, then RBSP trailing bits.
    payload = b'\x05\xfe' + b'\x55' * 251 + b'\x00\x00\x03\x01\x80'
    assert len(payload) == 258 and list(payload[255:257]) == [3, 1]
    header = b'\x06' if codec == 'h264' else b'\x4e\x01'
    sei = b'\x00\x00\x00\x01' + header + payload
    assert self_contained_idr(sei + chain(codec), codec)
