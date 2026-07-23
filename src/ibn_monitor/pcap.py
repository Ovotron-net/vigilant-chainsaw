from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO

from .decode import MAX_HEADER_BYTES, ObservationContext, decode_observation
from .models import Observation

_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}
_SUPPORTED_DATALINKS = {1, 101, 113, 276}
_MAX_SNAPLEN = 16 * 1024 * 1024


class PcapError(ValueError):
    pass


class _RecordReader:
    def __init__(self, stream: BinaryIO, captured_length: int, wire_length: int):
        self._stream = stream
        self._captured_length = captured_length
        self._cache = bytearray()
        self.wire_length = wire_length

    def prefix(self, length: int) -> bytes:
        target = min(length, self._captured_length, MAX_HEADER_BYTES)
        missing = target - len(self._cache)
        if missing > 0:
            data = self._stream.read(missing)
            if len(data) != missing:
                raise PcapError("truncated packet record")
            self._cache.extend(data)
        return bytes(self._cache[:target])

    def finish(self) -> None:
        remaining = self._captured_length - len(self._cache)
        if remaining:
            self._stream.seek(remaining, 1)


def iter_pcap_stream(
    stream: BinaryIO,
    *,
    context: ObservationContext,
) -> Iterator[Observation]:
    if not hasattr(stream, "seek") or not hasattr(stream, "tell"):
        raise PcapError("pcap stream must be seekable")

    header = stream.read(24)
    if len(header) != 24:
        raise PcapError("truncated pcap global header")
    if header.startswith(b"\x0a\x0d\x0d\x0a"):
        raise PcapError("PCAPNG is not supported")
    magic = header[:4]
    if magic not in _MAGIC:
        raise PcapError("unknown pcap magic")
    endian, fraction_scale = _MAGIC[magic]
    version_major, version_minor, _thiszone, _sigfigs, snaplen, datalink = struct.unpack(
        f"{endian}HHIIII", header[4:]
    )
    if (version_major, version_minor) != (2, 4):
        raise PcapError(f"unsupported pcap version {version_major}.{version_minor}")
    if snaplen <= 0 or snaplen > _MAX_SNAPLEN:
        raise PcapError(f"invalid snaplen {snaplen}")
    if datalink not in _SUPPORTED_DATALINKS:
        raise PcapError(f"unsupported datalink {datalink}")

    while True:
        record_header = stream.read(16)
        if not record_header:
            return
        if len(record_header) != 16:
            raise PcapError("truncated pcap record header")
        seconds, fraction, incl_len, orig_len = struct.unpack(
            f"{endian}IIII", record_header
        )
        if incl_len > snaplen:
            raise PcapError("incl_len exceeds snaplen")
        if orig_len < incl_len:
            raise PcapError("orig_len is less than incl_len")

        record_data_offset = stream.tell()
        stream.seek(0, 2)
        end = stream.tell()
        if record_data_offset + incl_len > end:
            raise PcapError("packet record extends beyond end of file")
        stream.seek(record_data_offset)

        microseconds = fraction // 1000 if fraction_scale == 1_000_000_000 else fraction
        captured_at = datetime.fromtimestamp(seconds + microseconds / 1_000_000, UTC)
        observation_context = replace(context, captured_at=captured_at)
        reader = _RecordReader(stream, incl_len, orig_len)
        try:
            yield decode_observation(reader, datalink, observation_context)
        finally:
            reader.finish()


def iter_pcap_observations(
    path: str | Path,
    *,
    context: ObservationContext,
) -> Iterator[Observation]:
    with Path(path).open("rb") as stream:
        yield from iter_pcap_stream(stream, context=context)
