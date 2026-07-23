"""Staged MSG_PEEK header reader implementing decode.HeaderReader."""

from __future__ import annotations

import contextlib
from datetime import datetime
from typing import Protocol


class SocketLike(Protocol):
    def recv(self, length: int, flags: int = 0) -> bytes: ...


class StagedPeekReader:
    """HeaderReader backed by MSG_PEEK; always consume after a successful peek."""

    def __init__(
        self,
        sock: SocketLike,
        *,
        max_header: int = 512,
        msg_peek: int = 0x02,
        wire_length: int | None = None,
        packet_type: int = 0,
        captured_at: datetime | None = None,
        prefetched: bytes | None = None,
    ) -> None:
        self._sock = sock
        self._max_header = max_header
        self._msg_peek = msg_peek
        self._cache = bytearray()
        self._consumed = False
        self._has_datagram = False
        self.packet_type = packet_type
        self.captured_at = captured_at
        self.wire_length = wire_length or 0
        if prefetched is not None:
            self._cache.extend(prefetched[:max_header])
            self._has_datagram = True
            if wire_length is None:
                self.wire_length = len(prefetched)

    @property
    def has_datagram(self) -> bool:
        return self._has_datagram

    def peek_once(self, length: int | None = None) -> bool:
        """Perform an initial peek. Returns True if a datagram is present."""
        target = min(length or self._max_header, self._max_header)
        data = self._sock.recv(target, self._msg_peek)
        if not data:
            self._has_datagram = False
            return False
        self._cache = bytearray(data)
        self._has_datagram = True
        if self.wire_length == 0:
            self.wire_length = len(data)
        return True

    def prefix(self, length: int) -> bytes:
        if not self._has_datagram:
            return b""
        target = min(length, self._max_header)
        if len(self._cache) < target:
            data = self._sock.recv(target, self._msg_peek)
            if len(data) > len(self._cache):
                self._cache = bytearray(data)
        return bytes(self._cache[:target])

    @property
    def consume_length(self) -> int:
        if not self._has_datagram:
            return 0
        return max(1, min(len(self._cache) or 1, self._max_header))

    def consume(self) -> None:
        if self._consumed or not self._has_datagram:
            self._consumed = True
            return
        length = self.consume_length
        if length:
            with contextlib.suppress(OSError):
                self._sock.recv(length, 0)
        self._consumed = True
