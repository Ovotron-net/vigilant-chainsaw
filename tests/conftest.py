"""Shared pytest configuration (stdlib-only; no Scapy)."""

from __future__ import annotations

import pytest


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers", "linux_raw: privileged Linux AF_PACKET / netns / nft tests"
    )
    config.addinivalue_line(
        "markers", "linux_perf: long-running Linux performance gate"
    )
