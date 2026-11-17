"""Select channel-tagged images, never the last available lens as fallback."""

from io import BytesIO
from struct import pack

from PIL import Image

from pyezvizapi.devices.channels import CameraChannel
from pyezvizapi.devices.images import process_channel_images


def jpeg(color):
    with Image.new("RGB", (8, 8), color) as image, BytesIO() as output:
        image.save(output, format="JPEG")
        return output.getvalue()


def indexed(rows):
    return b"mutichhikpic\x81\xfe" + b"".join(
        pack(">HHII", channel, 0xCAFE, 4 + len(body), len(body)) + body for channel, body in rows
    )


def test_channel_ids_not_record_order_or_route_order():
    first, second = jpeg("red"), jpeg("blue")
    channels = (CameraChannel("Video", "1"), CameraChannel("Video_1", "2"))
    result = process_channel_images(indexed([(2, second), (1, first)]), None, channels)
    assert result == {"Video:1": first, "Video_1:2": second}
    assert process_channel_images(indexed([(2, second)]), None, channels) == {"Video_1:2": second}


def test_unindexed_alarm_does_not_invent_a_lens():
    body = jpeg("red")
    channels = (CameraChannel("Video", "1"), CameraChannel("Video_1", "2"))
    assert process_channel_images(body, None, channels) == {}
    assert process_channel_images(body + body, None, channels) == {}
    assert process_channel_images(body, None, channels, source_channel=channels[1]) == {
        "Video_1:2": body
    }
    assert process_channel_images(body, None, channels[:1]) == {"Video:1": body}


def test_zero_based_channel_and_foreign_capture_identity():
    body = jpeg("red")
    channel = CameraChannel("Video", "0")
    assert process_channel_images(indexed([(0, body)]), None, (channel,)) == {"Video:0": body}
    assert (
        process_channel_images(body, None, (channel,), source_channel=CameraChannel("Video_1", "2"))
        == {}
    )
