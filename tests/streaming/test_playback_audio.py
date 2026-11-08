"""Independent encrypted AAC fixtures for SD playback; no camera data."""

from copy import deepcopy
from io import BytesIO

import pytest

from pyezvizapi.client import EzvizClient
from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.streaming.capture import ClipOptions, CloudPlaybackClipSource
from pyezvizapi.streaming.cloud import playback
from pyezvizapi.streaming.cloud.playback_audio import decrypt_playback_adts_audio
from pyezvizapi.streaming.media.rtp import _aac_adts_header
from tests.streaming.test_stream_transport import _encrypt_hikvision_fixture_blocks

KEY = b"0123456789abcdef"
PACK = b"\x00\x00\x01\xba\x44\x00\x04\x00\x04\x01\x00\x01\xff\xf8"


def frame(clear, crc=False):
    head = bytearray(_aac_adts_header(len(clear) + (2 if crc else 0), 16000, 1))
    if crc:
        head[1] &= 0xFE
        head += b"xx"
    size = len(clear) - len(clear) % 16
    encrypted = _encrypt_hikvision_fixture_blocks(KEY, clear[:size]) + clear[size:]
    return bytes(head) + clear, bytes(head) + encrypted


def pes(payload):
    return b"\x00\x00\x01\xc0" + (3 + len(payload)).to_bytes(2, "big") + b"\x80\x00\x00" + payload


@pytest.mark.parametrize("crc", [False, True])
def test_audio_decrypt_preserves_headers_crc_tails_and_multiple_frames(crc):
    clear, encrypted = frame(bytes(range(57)), crc=crc)
    clear2, encrypted2 = frame(bytes(range(63, 108)), crc=crc)
    source = PACK + pes(encrypted + encrypted2)
    assert decrypt_playback_adts_audio(source, KEY) == PACK + pes(clear + clear2)


@pytest.mark.parametrize("mutate", [lambda data: data[:-1], lambda data: data[2:]])
def test_incomplete_adts_frame_is_rejected_instead_of_silent_prefix(mutate):
    _, encrypted = frame(bytes(range(57)))
    with pytest.raises(PyEzvizError):
        decrypt_playback_adts_audio(PACK + pes(mutate(encrypted)), KEY)


def test_missing_audio_is_not_reported_as_successful_audio_decryption():
    with pytest.raises(PyEzvizError, match="no complete ADTS"):
        decrypt_playback_adts_audio(PACK, KEY)


def test_typed_source_explicit_audio_flag_and_copied_default_range_are_preserved(monkeypatch):
    calls = []

    def copy(client, serial, output, begin, end, **kwargs):
        calls.append(kwargs)
        output.write(b"PS")
        return {"bytes": 2}

    monkeypatch.setattr(playback, "copy_cloud_playback_to_mpegps", copy)
    options = deepcopy(
        ClipOptions(
            source=CloudPlaybackClipSource(
                "20261108T000000Z", "20261108T000020Z", decrypt_audio=True
            )
        )
    )
    client = EzvizClient(token={"session_id": "synthetic", "api_url": "api.example.test"})
    client.save_clip_with_options("CAM123", BytesIO(), options)
    assert calls[0]["decrypt_audio"] is True
    assert calls[0]["duration_seconds"] is None
    client.close_session()
