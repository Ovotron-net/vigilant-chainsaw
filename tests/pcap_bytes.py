import struct


def classic_pcap(records, *, datalink=1, endian="<", nanosecond=False):
    magic = {
        ("<", False): b"\xd4\xc3\xb2\xa1",
        (">", False): b"\xa1\xb2\xc3\xd4",
        ("<", True): b"\x4d\x3c\xb2\xa1",
        (">", True): b"\xa1\xb2\x3c\x4d",
    }[(endian, nanosecond)]
    output = bytearray(magic)
    output.extend(struct.pack(f"{endian}HHIIII", 2, 4, 0, 0, 65535, datalink))
    for seconds, fraction, frame, wire_length in records:
        output.extend(
            struct.pack(
                f"{endian}IIII",
                seconds,
                fraction,
                len(frame),
                wire_length,
            )
        )
        output.extend(frame)
    return bytes(output)
