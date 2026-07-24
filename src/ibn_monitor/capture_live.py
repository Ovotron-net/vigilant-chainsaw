"""Platform-aware live ObservationSource factory."""

from __future__ import annotations

import sys

from .config import PolicyV2Config


def build_live_sources(config: PolicyV2Config, *, boot_id: str):
    """Return live capture adapters for the current OS.

    - win32: raw IPv4 + SIO_RCVALL (``capture_windows``)
    - linux: AF_PACKET (``capture_afpacket``)
    """
    if sys.platform == "win32":
        from .capture_windows import build_windows_raw_sources

        return build_windows_raw_sources(config, boot_id=boot_id)
    if sys.platform.startswith("linux"):
        from .capture_afpacket import build_af_packet_sources

        return build_af_packet_sources(config, boot_id=boot_id)
    raise RuntimeError(
        f"live capture is not supported on platform {sys.platform!r}; "
        "use Windows or Linux, or offline: ibn-monitor replay"
    )
