#!/usr/bin/env python3
from pathlib import Path

from scapy.config import conf

conf.route_autoload = False
conf.route6_autoload = False

from scapy.layers.inet import IP, TCP  # noqa: E402
from scapy.utils import wrpcap  # noqa: E402

packets = [
    IP(src="10.20.5.14", dst="10.50.10.8") / TCP(sport=50000, dport=5432, flags="S"),
    IP(src="10.20.5.14", dst="10.50.10.8") / TCP(sport=50001, dport=443, flags="S"),
]
output = Path("test-traffic.pcap")
wrpcap(str(output), packets)
print(output)
