"""Platform-aware live ObservationSource factory — the one place the OS is checked."""

from __future__ import annotations

import sys

from .capture import ObservationSource
from .config import ConfigError, PolicyV2Config


def require_live_platform() -> None:
    """Raise ``ConfigError`` unless live capture is supported on this OS."""
    if sys.platform != "win32" and not sys.platform.startswith("linux"):
        raise ConfigError(
            f"live run requires Windows or Linux (got {sys.platform!r}); "
            "use: ibn-monitor replay for offline PCAP"
        )


def build_live_sources(config: PolicyV2Config, *, boot_id: str) -> tuple[ObservationSource, ...]:
    """Return one CaptureSource per capture point with this OS's adapter.

    - win32: raw IPv4 + SIO_RCVALL (``capture_windows``)
    - linux: AF_PACKET + owned cBPF (``capture_afpacket``)
    """
    require_live_platform()
    if sys.platform == "win32":
        from .capture_windows import build_windows_raw_sources

        return build_windows_raw_sources(config, boot_id=boot_id)
    from .capture_afpacket import build_af_packet_sources

    return build_af_packet_sources(config, boot_id=boot_id)
