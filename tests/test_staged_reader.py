from ibn_monitor.staged_reader import StagedPeekReader


class FakeSock:
    def __init__(self, payload: bytes):
        self.payload = payload
        self.peeks = 0
        self.consumes = 0

    def recv(self, length: int, flags: int = 0) -> bytes:
        if flags & 0x2:
            self.peeks += 1
            return self.payload[:length]
        self.consumes += 1
        return self.payload[:length]


def test_consume_once_per_successful_peek():
    sock = FakeSock(b"\x00" * 60)
    reader = StagedPeekReader(sock, max_header=512, msg_peek=0x2)
    assert reader.peek_once()
    assert reader.prefix(14) == b"\x00" * 14
    reader.consume()
    reader.consume()  # idempotent
    assert sock.peeks >= 1
    assert sock.consumes == 1
