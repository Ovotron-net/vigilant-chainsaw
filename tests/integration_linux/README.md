# Privileged Linux integration tests

These tests exercise AF_PACKET capture and nftables in network namespaces.
They are **skipped by default** on non-Linux hosts and when not explicitly selected.

## Run

```bash
# On a Linux lab host with root or CAP_NET_ADMIN+CAP_NET_RAW:
sudo pytest -m linux_raw -q

# Optional performance gate (long-running):
sudo IBN_PERF_GATE=1 pytest -m linux_perf -q
```

## Prerequisites

- Linux kernel with AF_PACKET
- `ip`, `nft` in PATH
- Permission to create netns / veth
- Package installed: `pip install -e ".[dev]"`

## What is covered (outline)

| Test module | Intent |
|---|---|
| `test_afpacket_netns.py` | veth pair, CAP_NET_RAW capture, establish + observations |
| `test_nftables_topology.py` | gateway/host render check; mirror rejects; apply dry-run |

Implementation may be expanded over time; stubs document the contract even when skipped.
