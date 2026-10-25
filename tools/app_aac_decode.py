"""Development-only local AAC-LC decoder to the explicit PCM sink JSONL contract.

Optional PyAV is required. No camera/network access, VQE, resampling or pacing.
A separate metadata manifest retains exact source PTS and host emission times.
"""

from __future__ import annotations

import argparse
import base64
from fractions import Fraction
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import select
import stat
import struct
import sys
import time
from typing import Any, BinaryIO

SAMPLE_RATE = 16_000
SAMPLES = 1024
PCM_BYTES = 2048
MAX_BLOCKS = 10_000
MAX_PACKETS = 100_000
MAX_PACKET_BYTES = 8192
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_SECONDS = 3600
WRITE_SECONDS = 5
FORMATS = ('mpegts', 'matroska', 'mpeg')


class FormatConverter:
    """Convert samples on an untimed copy; retain the caller's exact source clock."""

    def __init__(self, av: Any) -> None:
        self.av = av
        self.converter = av.AudioResampler(format='s16', layout='mono', rate=SAMPLE_RATE)

    def resample(self, frame: Any) -> list[Any]:
        if frame is None:
            return self.converter.resample(None)
        # AudioResampler otherwise quantizes arbitrary source PTS to 1/sample_rate.
        # Only sample format is changing: its sample clock must not replace the
        # source clock. Do not mutate the borrowed decoder frame or invent PTS.
        untimed = self.av.AudioFrame(format=frame.format.name, layout='mono', samples=SAMPLES)
        untimed.sample_rate = SAMPLE_RATE
        sample_bytes = 4 if frame.format.name == 'fltp' else 2
        raw = bytes(frame.planes[0])[:SAMPLES * sample_bytes]
        if len(raw) != SAMPLES * sample_bytes:
            raise ValueError('decoded PCM plane is truncated')
        untimed.planes[0].update(raw)
        outputs = self.converter.resample(untimed)
        for output in outputs:
            if output.pts is not None:
                raise ValueError('untimed format conversion invented output timing')
            output.time_base = frame.time_base
            output.pts = frame.pts
        return outputs


class FrameAdapter:
    """One verified 1024-sample decoder frame becomes one identified PCM block."""

    def __init__(self, stream_index: int, resampler: Any) -> None:
        self.stream_index = stream_index
        self.resampler = resampler
        self.count = 0
        self.previous: Fraction | None = None

    def convert(self, frame: Any) -> tuple[dict[str, Any], dict[str, Any]]:
        if sys.byteorder != 'little':
            raise ValueError('PCM format conversion currently requires a little-endian host')
        if self.count >= MAX_BLOCKS:
            raise ValueError('decoded block limit exceeded')
        if frame.is_corrupt:
            raise ValueError('corrupt decoded audio frame')
        if (frame.sample_rate != SAMPLE_RATE or frame.layout.name != 'mono'
                or frame.samples != SAMPLES or frame.format.name not in ('fltp', 's16')):
            raise ValueError('requires 1024-sample 16-kHz mono AAC frames (fltp or s16)')
        if type(frame.pts) is not int or frame.time_base is None or frame.time_base <= 0:
            raise ValueError('decoded frame requires explicit PTS and positive time base')
        source_time = frame.pts * Fraction(frame.time_base)
        media_ms = source_time * 1000
        if not 0 <= media_ms < 2**32:
            raise ValueError('source time is outside uint32 milliseconds')
        if self.previous is not None and source_time < self.previous:
            raise ValueError('backward source PTS is unsupported; no clock repair is inferred')
        converted = self.resampler.resample(frame)
        if len(converted) != 1:
            raise ValueError('format conversion must preserve one frame without delay')
        output = converted[0]
        if (output.sample_rate != SAMPLE_RATE or output.layout.name != 'mono'
                or output.samples != SAMPLES or output.format.name != 's16'
                or type(output.pts) is not int or output.time_base is None
                or output.time_base <= 0
                or output.pts * Fraction(output.time_base) != source_time):
            raise ValueError('format conversion changed samples or exact source timing')
        pcm = bytes(output.planes[0])
        if len(pcm) < PCM_BYTES:
            raise ValueError('converted PCM plane is truncated')
        pcm = pcm[:PCM_BYTES]  # AVFrame plane allocation can include alignment padding.
        block_id = f'aac:{self.stream_index}:{self.count}'
        self.count += 1
        self.previous = source_time
        row = dict(id=block_id, media_ms=media_ms.numerator // media_ms.denominator,
                   pcm_s16le_b64=base64.b64encode(pcm).decode('ascii'))
        metadata = dict(kind='decoded', id=block_id, stream_index=self.stream_index,
                        source_pts=frame.pts, time_base_num=frame.time_base.numerator,
                        time_base_den=frame.time_base.denominator, samples=SAMPLES,
                        media_ms=row['media_ms'], pcm_sha256=hashlib.sha256(pcm).hexdigest(),
                        decoded_monotonic_ns=time.monotonic_ns())
        return row, metadata


class BoundedSource(io.RawIOBase):
    """Seekable reader whose EOF remains the validated open-time file size."""

    def __init__(self, source: BinaryIO, size: int) -> None:
        super().__init__()
        self.source = source
        self.size = size

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self.source.tell()

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        if whence == os.SEEK_SET:
            target = offset
        elif whence == os.SEEK_CUR:
            target = self.tell() + offset
        elif whence == os.SEEK_END:
            target = self.size + offset
        else:
            raise ValueError('unsupported seek mode')
        return self.source.seek(target, os.SEEK_SET)

    def read(self, size: int = -1) -> bytes:
        remaining = max(0, self.size - self.tell())
        return self.source.read(remaining if size < 0 else min(size, remaining))

    def readinto(self, buffer: Any) -> int:
        view = memoryview(buffer).cast('B')
        data = self.read(len(view))
        view[:len(data)] = data
        return len(data)

    def close(self) -> None:
        try:
            self.source.close()
        finally:
            super().close()


def open_source(path: Path) -> BoundedSource:
    """Open only a bounded regular local file, never a FIFO/URL/demux playlist."""
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_FILE_BYTES:
            raise ValueError('source must be a nonempty regular file at most 256 MiB')
        return BoundedSource(os.fdopen(fd, 'rb', buffering=0), info.st_size)
    except BaseException:
        os.close(fd)
        raise


class JsonlWriter:
    """Bound output backpressure without inventing media-time arrival pacing."""

    def __init__(self, fd: int) -> None:
        self.fd = fd
        self.partial_bytes = 0
        self.emitted = 0

    def write(self, row: dict[str, Any]) -> None:
        raw = (json.dumps(row, separators=(',', ':')) + '\n').encode()
        self.partial_bytes = 0
        deadline = time.monotonic() + WRITE_SECONDS
        while self.partial_bytes < len(raw):
            if time.monotonic() >= deadline:
                raise ValueError('PCM JSONL output write deadline exceeded')
            try:
                count = os.write(self.fd, raw[self.partial_bytes:])
            except BlockingIOError:
                select.select([], [self.fd], [], 0.02)
            else:
                if count <= 0:
                    raise ValueError('PCM JSONL output made no progress')
                self.partial_bytes += count
        self.emitted += 1
        self.partial_bytes = 0


def load_av() -> Any:
    """Keep optional development dependency out of production imports."""
    try:
        return importlib.import_module('av')
    except ImportError as error:
        raise ImportError('optional PyAV is required: python -m pip install av') from error


def packet_metadata(packet: Any, index: int, decoded_frames: int) -> dict[str, Any]:
    """Retain decoder trimming evidence, not encoded payload or invented loss."""
    sides = []
    for side in packet.iter_sidedata():
        info: dict[str, Any] = dict(type=side.data_type)
        if side.data_type == 'skip_samples':
            raw = bytes(side)
            if len(raw) != 10:
                raise ValueError('unsupported skip_samples side data')
            start, end, start_reason, end_reason = struct.unpack('<IIBB', raw)
            info.update(skip_start_samples=start, skip_end_samples=end,
                        start_reason=start_reason, end_reason=end_reason)
        sides.append(info)
    return dict(kind='packet', packet_index=index, pts=packet.pts, dts=packet.dts,
                time_base_num=packet.time_base.numerator if packet.time_base else None,
                time_base_den=packet.time_base.denominator if packet.time_base else None,
                encoded_bytes=packet.size, side_data=sides, decoded_frames=decoded_frames)


def decode(source: BinaryIO | BoundedSource, container_format: str, stream_index: int,
           writer: JsonlWriter, manifest: Any) -> int:
    """Decode a deliberately selected local track; never derive timing from count."""
    av = load_av()
    started = time.monotonic()
    manifest.write(json.dumps(dict(kind='decoder', pyav_version=av.__version__,
                                   library_versions=av.library_versions)) + '\n')
    manifest.flush()
    with av.open(source, format=container_format,
                 options={'protocol_whitelist': 'file,pipe'}) as container:
        streams = [s for s in container.streams if s.index == stream_index and s.type == 'audio']
        if len(streams) != 1:
            raise ValueError('select one existing absolute audio stream index')
        stream = streams[0]
        codec = stream.codec_context
        if (codec.name != 'aac' or codec.profile != 'LC' or codec.sample_rate != SAMPLE_RATE
                or codec.layout.name != 'mono'):
            raise ValueError('only AAC-LC, 16-kHz mono is supported')
        adapter = FrameAdapter(stream_index, FormatConverter(av))
        for packets, packet in enumerate(container.demux(stream)):
            if packets >= MAX_PACKETS or time.monotonic() - started > MAX_SECONDS:
                raise ValueError('decoder packet/session limit exceeded')
            if packet.size > MAX_PACKET_BYTES:
                raise ValueError('encoded audio packet size limit exceeded')
            if packet.is_corrupt:
                raise ValueError('corrupt encoded audio packet')
            frames = packet.decode()
            manifest.write(json.dumps(packet_metadata(packet, packets, len(frames))) + '\n')
            manifest.flush()
            for frame in frames:
                row, metadata = adapter.convert(frame)
                metadata['packet_index'] = packets
                manifest.write(json.dumps(metadata) + '\n')
                manifest.flush()
                writer.write(row)
                manifest.write(json.dumps(dict(kind='emitted', id=row['id'],
                                               emitted_monotonic_ns=time.monotonic_ns())) + '\n')
                manifest.flush()
        if adapter.resampler.resample(None):
            raise ValueError('unexpected delayed format-conversion tail')
        if not adapter.count:
            raise ValueError('source produced no supported audio frames')
        return adapter.count


def main() -> int:
    """Emit streaming blocks; the exclusive manifest records partial success/failure."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('--container', required=True, choices=FORMATS)
    parser.add_argument('--audio-stream', required=True, type=int,
                        help='absolute container stream index, not audio ordinal')
    parser.add_argument('--manifest', required=True, type=Path,
                        help='new metadata-only JSONL file; existing files are never overwritten')
    args = parser.parse_args()
    code, status, error = 0, 'completed', None
    writer = JsonlWriter(sys.stdout.fileno())
    try:
        with args.manifest.open('x') as manifest:
            blocking = os.get_blocking(writer.fd)
            try:
                os.set_blocking(writer.fd, False)
                with open_source(args.source) as source:
                    decode(source, args.container, args.audio_stream, writer, manifest)
            except KeyboardInterrupt:
                code, status, error = 130, 'cancelled', 'interrupted'
            except Exception as failure:
                code, status, error = 2, 'failed', f'{type(failure).__name__}: {failure}'
            finally:
                os.set_blocking(writer.fd, blocking)
            manifest.write(json.dumps(dict(kind='summary', status=status, error=error,
                                           emitted_blocks=writer.emitted,
                                           partial_jsonl_bytes=writer.partial_bytes,
                                           processor='format-conversion-only-not-vqe',
                                           arrival_source='host-decode-not-native-arrival',
                                           physical_lip_sync_measured=False)) + '\n')
    except OSError as failure:
        code, error = 2, str(failure)
    if error:
        print(f'decode failed: {error}', file=sys.stderr)
    return code


if __name__ == '__main__':
    raise SystemExit(main())
