"""Windows host helpers for live raw-IP capture (SIO_RCVALL).

Import only from the Windows live path. No third-party packet libraries.
"""

from __future__ import annotations

import ipaddress
import socket
import sys
from dataclasses import dataclass


def require_windows() -> None:
    if sys.platform != "win32":
        raise RuntimeError("Windows packet helpers require win32")


@dataclass(frozen=True, slots=True)
class AdapterAddress:
    name: str
    friendly_name: str
    ipv4: str
    is_up: bool


def resolve_bind_ipv4(interface: str) -> str:
    """Map policy ``interface`` to an IPv4 address to bind for SIO_RCVALL.

    Accepts:
    - dotted IPv4 literal
    - adapter name / friendly name (case-insensitive substring or exact)
    - ``auto`` / ``*`` / empty → first up non-loopback IPv4
    """
    require_windows()
    text = (interface or "").strip()
    if text and text not in {"auto", "*"}:
        try:
            addr = ipaddress.ip_address(text)
            if addr.version != 4 or addr.is_loopback:
                raise ValueError("bind address must be a non-loopback IPv4")
            return str(addr)
        except ValueError as exc:
            if text.replace(".", "").isdigit() or ":" in text:
                raise ValueError(f"invalid bind address {text!r}") from exc

    adapters = list_ipv4_adapters()
    if not adapters:
        raise RuntimeError("no IPv4 adapters found")

    if not text or text in {"auto", "*"}:
        for adapter in adapters:
            if adapter.is_up and not ipaddress.ip_address(adapter.ipv4).is_loopback:
                return adapter.ipv4
        raise RuntimeError("no up non-loopback IPv4 adapter found")

    needle = text.casefold()
    exact: list[AdapterAddress] = []
    partial: list[AdapterAddress] = []
    for adapter in adapters:
        names = (adapter.name.casefold(), adapter.friendly_name.casefold())
        if needle in names:
            exact.append(adapter)
        elif any(needle in name for name in names):
            partial.append(adapter)
    chosen = exact or partial
    if not chosen:
        known = ", ".join(
            f"{a.friendly_name or a.name}={a.ipv4}" for a in adapters[:12]
        )
        raise RuntimeError(
            f"interface {interface!r} not found among IPv4 adapters "
            f"(try an IPv4 address or name; known: {known})"
        )
    for adapter in chosen:
        if adapter.is_up:
            return adapter.ipv4
    return chosen[0].ipv4


def list_ipv4_adapters() -> list[AdapterAddress]:
    """Best-effort adapter list (IP Helper API, then hostname fallback)."""
    require_windows()
    try:
        return _list_adapters_iphlpapi()
    except OSError:
        return _list_adapters_fallback()


def _list_adapters_fallback() -> list[AdapterAddress]:
    host = socket.gethostname()
    out: list[AdapterAddress] = []
    try:
        for info in socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM):
            ipv4 = info[4][0]
            if ipaddress.ip_address(ipv4).is_loopback:
                continue
            out.append(
                AdapterAddress(
                    name=host,
                    friendly_name=host,
                    ipv4=ipv4,
                    is_up=True,
                )
            )
    except OSError:
        pass
    # Also include primary outbound IP when possible.
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect(("8.8.8.8", 80))
            ipv4 = probe.getsockname()[0]
        finally:
            probe.close()
        if not any(a.ipv4 == ipv4 for a in out):
            out.insert(
                0,
                AdapterAddress(
                    name="primary",
                    friendly_name="primary",
                    ipv4=ipv4,
                    is_up=True,
                ),
            )
    except OSError:
        pass
    return out


def _list_adapters_iphlpapi() -> list[AdapterAddress]:
    """Enumerate IPv4 unicast addresses via GetAdaptersAddresses."""
    import ctypes
    from ctypes import wintypes

    iphlpapi = ctypes.WinDLL("iphlpapi")
    # AF_UNSPEC=0, GAA_FLAG_INCLUDE_PREFIX=0x0010
    AF_UNSPEC = 0
    GAA_FLAG_INCLUDE_PREFIX = 0x0010
    IF_TYPE_SOFTWARE_LOOPBACK = 24
    IF_OPER_STATUS_UP = 1
    buffer_len = wintypes.ULONG(15_000)
    buf = ctypes.create_string_buffer(buffer_len.value)

    class SOCKET_ADDRESS(ctypes.Structure):
        _fields_ = [
            ("lpSockaddr", ctypes.POINTER(ctypes.c_ubyte)),
            ("iSockaddrLength", wintypes.INT),
        ]

    class IP_ADAPTER_UNICAST_ADDRESS(ctypes.Structure):
        pass

    IP_ADAPTER_UNICAST_ADDRESS._fields_ = [
        ("Length", wintypes.ULONG),
        ("Flags", wintypes.DWORD),
        ("Next", ctypes.POINTER(IP_ADAPTER_UNICAST_ADDRESS)),
        ("Address", SOCKET_ADDRESS),
        # remainder unused
    ]

    class IP_ADAPTER_ADDRESSES(ctypes.Structure):
        pass

    IP_ADAPTER_ADDRESSES._fields_ = [
        ("Length", wintypes.ULONG),
        ("IfIndex", wintypes.DWORD),
        ("Next", ctypes.POINTER(IP_ADAPTER_ADDRESSES)),
        ("AdapterName", ctypes.c_char_p),
        ("FirstUnicastAddress", ctypes.POINTER(IP_ADAPTER_UNICAST_ADDRESS)),
        ("FirstAnycastAddress", ctypes.c_void_p),
        ("FirstMulticastAddress", ctypes.c_void_p),
        ("FirstDnsServerAddress", ctypes.c_void_p),
        ("DnsSuffix", wintypes.LPWSTR),
        ("Description", wintypes.LPWSTR),
        ("FriendlyName", wintypes.LPWSTR),
        ("PhysicalAddress", ctypes.c_ubyte * 8),
        ("PhysicalAddressLength", wintypes.ULONG),
        ("Flags", wintypes.ULONG),
        ("Mtu", wintypes.ULONG),
        ("IfType", wintypes.DWORD),
        ("OperStatus", ctypes.c_int),
    ]

    ret = iphlpapi.GetAdaptersAddresses(
        AF_UNSPEC,
        GAA_FLAG_INCLUDE_PREFIX,
        None,
        ctypes.byref(buf),
        ctypes.byref(buffer_len),
    )
    if ret == 111:  # ERROR_BUFFER_OVERFLOW
        buf = ctypes.create_string_buffer(buffer_len.value)
        ret = iphlpapi.GetAdaptersAddresses(
            AF_UNSPEC,
            GAA_FLAG_INCLUDE_PREFIX,
            None,
            ctypes.byref(buf),
            ctypes.byref(buffer_len),
        )
    if ret != 0:
        raise OSError(ret, "GetAdaptersAddresses failed")

    adapters: list[AdapterAddress] = []
    addr = ctypes.cast(buf, ctypes.POINTER(IP_ADAPTER_ADDRESSES))
    while addr:
        rec = addr.contents
        if rec.IfType == IF_TYPE_SOFTWARE_LOOPBACK:
            addr = rec.Next
            continue
        friendly = rec.FriendlyName or ""
        name = (rec.AdapterName or b"").decode("ascii", errors="ignore")
        is_up = rec.OperStatus == IF_OPER_STATUS_UP
        unicast = rec.FirstUnicastAddress
        while unicast:
            sa = unicast.contents.Address
            if sa.iSockaddrLength >= 16 and sa.lpSockaddr:
                family = ctypes.cast(
                    sa.lpSockaddr, ctypes.POINTER(ctypes.c_ushort)
                ).contents.value
                if family == socket.AF_INET:
                    # sockaddr_in: 2 family, 2 port, 4 addr
                    raw = bytes(
                        ctypes.cast(
                            sa.lpSockaddr, ctypes.POINTER(ctypes.c_ubyte * 16)
                        ).contents
                    )
                    ipv4 = socket.inet_ntoa(raw[4:8])
                    if not ipaddress.ip_address(ipv4).is_loopback:
                        adapters.append(
                            AdapterAddress(
                                name=name,
                                friendly_name=friendly,
                                ipv4=ipv4,
                                is_up=is_up,
                            )
                        )
            unicast = unicast.contents.Next
        addr = rec.Next
    return adapters
