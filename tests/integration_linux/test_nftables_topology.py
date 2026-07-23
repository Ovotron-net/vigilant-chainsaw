"""Privileged nftables checks for topology-aware artifacts."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
from factories import v2_config

from ibn_monitor.config import ConfigError
from ibn_monitor.enforcement import render_nftables_v2

pytestmark = [
    pytest.mark.linux_raw,
    pytest.mark.skipif(sys.platform != "linux", reason="Linux only"),
    pytest.mark.skipif(shutil.which("nft") is None, reason="nft required"),
]


def test_gateway_artifact_passes_nft_check():
    geteuid = getattr(os, "geteuid", None)
    if not callable(geteuid) or geteuid() != 0:
        pytest.skip("nft --check typically needs privileges")
    artifact = render_nftables_v2(v2_config())
    with tempfile.NamedTemporaryFile("w", suffix=".nft", delete=False) as handle:
        handle.write(artifact)
        path = handle.name
    try:
        subprocess.run(["nft", "--check", "--file", path], check=True, capture_output=True)
    finally:
        Path(path).unlink(missing_ok=True)


def test_mirror_rejected_before_nft():
    from dataclasses import replace

    base = v2_config()
    config = replace(base, sensor=replace(base.sensor, topology="mirror"))
    with pytest.raises(ConfigError, match="mirror"):
        render_nftables_v2(config)
