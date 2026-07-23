"""Privileged AF_PACKET smoke tests (Linux + root only)."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys

import pytest


def _euid() -> int:
    geteuid = getattr(os, "geteuid", None)
    return int(geteuid()) if callable(geteuid) else 1


pytestmark = [
    pytest.mark.linux_raw,
    pytest.mark.skipif(sys.platform != "linux", reason="Linux only"),
    pytest.mark.skipif(_euid() != 0, reason="requires root for netns"),
    pytest.mark.skipif(shutil.which("ip") is None, reason="iproute2 required"),
]


def test_afpacket_source_constructible_on_linux():
    from ibn_monitor.capture_afpacket import AfPacketSource, AfPacketSourceConfig
    from ibn_monitor.config import CapturePointConfig

    src = AfPacketSource(
        AfPacketSourceConfig(
            sensor_id="lab",
            capture_point=CapturePointConfig(
                name="wan",
                interface="lo",
                direction="both",
                promiscuous=False,
            ),
            boot_id="lab-boot",
        )
    )
    assert src.capture_point == "wan"


def test_netns_veth_scaffold():
    """Creates and destroys a netns+veth pair to prove lab tooling works."""
    ns = "ibn-test-ns"
    subprocess.run(["ip", "netns", "del", ns], check=False, capture_output=True)
    subprocess.run(["ip", "netns", "add", ns], check=True)
    try:
        subprocess.run(
            ["ip", "link", "add", "ibn-v0", "type", "veth", "peer", "name", "ibn-v1"],
            check=True,
        )
        subprocess.run(["ip", "link", "set", "ibn-v1", "netns", ns], check=True)
        subprocess.run(["ip", "link", "set", "ibn-v0", "up"], check=True)
        subprocess.run(
            ["ip", "netns", "exec", ns, "ip", "link", "set", "ibn-v1", "up"],
            check=True,
        )
    finally:
        subprocess.run(["ip", "link", "del", "ibn-v0"], check=False, capture_output=True)
        subprocess.run(["ip", "netns", "del", ns], check=False, capture_output=True)
