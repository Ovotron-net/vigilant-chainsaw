from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from ipaddress import ip_address
from typing import Protocol

from .models import FieldPresence, Observation, ObservedDirection

DLT_EN10MB = 1
DLT_RAW = 101
DLT_LINUX_SLL = 113
DLT_LINUX_SLL2 = 276
MAX_HEADER_BYTES = 512
_VLAN_TYPES = {0x8100, 0x88A8, 0x9100}
_IPV6_OPTION_HEADERS = {0, 43, 60, 135}
_IPV6_FRAGMENT = 44
_IPV6_AH = 51
_IPV6_ESP = 50
_IPV6_NO_NEXT = 59
MAX_IPV6_EXTENSIONS = 8


class HeaderReader(Protocol):
    wire_length: int

    def prefix(self, length: int) -> bytes:
        """Return at most length bytes from the record start."""


@dataclass(frozen=True, slots=True)
class ObservationContext:
    captured_at: datetime
    monotonic_at: float | None
    sensor_id: str
    source_generation: str
    capture_point: str
    interface: str | None
    direction: ObservedDirection


class _DecodeFailure(Exception):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def _need(reader: HeaderReader, length: int) -> bytes:
    if length > MAX_HEADER_BYTES:
        raise _DecodeFailure("header_byte_limit")
    data = reader.prefix(length)
    if len(data) < length:
        raise _DecodeFailure("truncated_header")
    return data


def _need_within(
    reader: HeaderReader,
    length: int,
    packet_end: int,
) -> bytes:
    if length > packet_end:
        raise _DecodeFailure("header_exceeds_ip_length")
    return _need(reader, length)


def _link(reader: HeaderReader, datalink: int) -> tuple[int, int]:
    if datalink == DLT_RAW:
        version = _need(reader, 1)[0] >> 4
        return 0, 0x0800 if version == 4 else 0x86DD
    if datalink == DLT_LINUX_SLL:
        data = _need(reader, 16)
        return 16, int.from_bytes(data[14:16], "big")
    if datalink == DLT_LINUX_SLL2:
        data = _need(reader, 20)
        return 20, int.from_bytes(data[0:2], "big")
    if datalink != DLT_EN10MB:
        raise _DecodeFailure("unsupported_datalink")
    data = _need(reader, 14)
    offset = 14
    ethertype = int.from_bytes(data[12:14], "big")
    vlan_depth = 0
    while ethertype in _VLAN_TYPES:
        vlan_depth += 1
        if vlan_depth > 2:
            raise _DecodeFailure("vlan_depth_limit")
        data = _need(reader, offset + 4)
        ethertype = int.from_bytes(data[offset + 2 : offset + 4], "big")
        offset += 4
    return offset, ethertype


def _decode_transport(
    reader: HeaderReader,
    offset: int,
    packet_end: int,
    protocol: str,
    observation: Observation,
) -> Observation:
    if protocol == "tcp":
        data = _need_within(reader, offset + 20, packet_end)
        header_length = (data[offset + 12] >> 4) * 4
        if not 20 <= header_length <= 60:
            raise _DecodeFailure("invalid_tcp_data_offset")
        data = _need_within(reader, offset + header_length, packet_end)
        return replace(
            observation,
            source_port=int.from_bytes(data[offset : offset + 2], "big"),
            destination_port=int.from_bytes(data[offset + 2 : offset + 4], "big"),
            tcp_flags=data[offset + 13],
            fields=(
                observation.fields
                | FieldPresence.SOURCE_PORT
                | FieldPresence.DESTINATION_PORT
                | FieldPresence.TCP_FLAGS
            ),
        )
    if protocol == "udp":
        data = _need_within(reader, offset + 8, packet_end)
        return replace(
            observation,
            source_port=int.from_bytes(data[offset : offset + 2], "big"),
            destination_port=int.from_bytes(data[offset + 2 : offset + 4], "big"),
            fields=(
                observation.fields
                | FieldPresence.SOURCE_PORT
                | FieldPresence.DESTINATION_PORT
            ),
        )
    if protocol == "icmp":
        data = _need_within(reader, offset + 2, packet_end)
        return replace(
            observation,
            icmp_type=data[offset],
            icmp_code=data[offset + 1],
            fields=observation.fields | FieldPresence.ICMP,
        )
    return observation


def _decode_ipv4(
    reader: HeaderReader, offset: int, base: Observation
) -> Observation:
    data = _need(reader, offset + 20)
    version_ihl = data[offset]
    if version_ihl >> 4 != 4:
        raise _DecodeFailure("invalid_ipv4_version")
    ihl = (version_ihl & 0x0F) * 4
    if ihl < 20:
        raise _DecodeFailure("invalid_ipv4_ihl")
    data = _need(reader, offset + ihl)
    total_length = int.from_bytes(data[offset + 2 : offset + 4], "big")
    if total_length < ihl:
        raise _DecodeFailure("invalid_ipv4_total_length")
    packet_end = offset + total_length
    source = ip_address(data[offset + 12 : offset + 16])
    destination = ip_address(data[offset + 16 : offset + 20])
    protocol_number = data[offset + 9]
    fragment = int.from_bytes(data[offset + 6 : offset + 8], "big")
    fields = (
        FieldPresence.IP_VERSION
        | FieldPresence.SOURCE
        | FieldPresence.DESTINATION
        | FieldPresence.PROTOCOL
    )
    protocol = {1: "icmp", 6: "tcp", 17: "udp"}.get(
        protocol_number, f"ip:{protocol_number}"
    )
    partial = replace(
        base,
        ip_version=4,
        source=source,
        destination=destination,
        protocol=protocol,
        fields=fields,
        outcome="complete",
    )
    if fragment & 0x1FFF:
        return replace(
            partial,
            outcome="partial",
            decode_reason="non_initial_fragment",
        )
    try:
        return _decode_transport(
            reader,
            offset + ihl,
            packet_end,
            protocol,
            partial,
        )
    except _DecodeFailure as error:
        return replace(
            partial,
            outcome="partial",
            decode_reason=error.reason,
        )


def _decode_ipv6(
    reader: HeaderReader, offset: int, base: Observation
) -> Observation:
    data = _need(reader, offset + 40)
    if data[offset] >> 4 != 6:
        raise _DecodeFailure("invalid_ipv6_version")
    source = ip_address(data[offset + 8 : offset + 24])
    destination = ip_address(data[offset + 24 : offset + 40])
    payload_length = int.from_bytes(data[offset + 4 : offset + 6], "big")
    next_header = data[offset + 6]
    cursor = offset + 40
    packet_end = cursor + payload_length
    fields = FieldPresence.IP_VERSION | FieldPresence.SOURCE | FieldPresence.DESTINATION
    partial = replace(
        base,
        ip_version=6,
        source=source,
        destination=destination,
        fields=fields,
        outcome="partial",
    )
    if payload_length == 0 and next_header != _IPV6_NO_NEXT:
        return replace(partial, decode_reason="ipv6_jumbogram_unsupported")

    try:
        extension_count = 0
        while next_header in _IPV6_OPTION_HEADERS | {
            _IPV6_FRAGMENT,
            _IPV6_AH,
            _IPV6_ESP,
        }:
            extension_count += 1
            if extension_count > MAX_IPV6_EXTENSIONS:
                return replace(
                    partial,
                    decode_reason="ipv6_extension_count_limit",
                )
            if next_header == _IPV6_ESP:
                return replace(partial, decode_reason="encrypted_esp")
            data = _need_within(reader, cursor + 2, packet_end)
            following = data[cursor]
            if next_header == _IPV6_FRAGMENT:
                data = _need_within(reader, cursor + 8, packet_end)
                fragment = int.from_bytes(data[cursor + 2 : cursor + 4], "big")
                if fragment >> 3:
                    return replace(
                        partial,
                        protocol={6: "tcp", 17: "udp", 58: "icmp"}.get(
                            following, f"ip:{following}"
                        ),
                        fields=fields | FieldPresence.PROTOCOL,
                        decode_reason="non_initial_fragment",
                    )
                header_length = 8
            elif next_header == _IPV6_AH:
                header_length = (data[cursor + 1] + 2) * 4
            else:
                header_length = (data[cursor + 1] + 1) * 8
            _need_within(reader, cursor + header_length, packet_end)
            cursor += header_length
            next_header = following
    except _DecodeFailure as error:
        return replace(partial, decode_reason=error.reason)

    protocol = {6: "tcp", 17: "udp", 58: "icmp"}.get(next_header, f"ip:{next_header}")
    complete = replace(
        partial,
        protocol=protocol,
        fields=fields | FieldPresence.PROTOCOL,
        outcome="complete",
        decode_reason=None,
    )
    if next_header == _IPV6_NO_NEXT:
        return complete
    try:
        return _decode_transport(
            reader,
            cursor,
            packet_end,
            protocol,
            complete,
        )
    except _DecodeFailure as error:
        return replace(
            complete,
            outcome="partial",
            decode_reason=error.reason,
        )


def decode_observation(
    reader: HeaderReader,
    datalink: int,
    context: ObservationContext,
) -> Observation:
    base = Observation(
        captured_at=context.captured_at,
        monotonic_at=context.monotonic_at,
        sensor_id=context.sensor_id,
        source_generation=context.source_generation,
        capture_point=context.capture_point,
        interface=context.interface,
        direction=context.direction,
        wire_length=reader.wire_length,
    )
    try:
        offset, ethertype = _link(reader, datalink)
        if ethertype == 0x0800:
            return _decode_ipv4(reader, offset, base)
        if ethertype == 0x86DD:
            return _decode_ipv6(reader, offset, base)
        return replace(base, decode_reason=f"unsupported_ethertype:{ethertype:#06x}")
    except _DecodeFailure as error:
        return replace(base, decode_reason=error.reason)
