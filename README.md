# Intent-Based Continuous Traffic Monitor

A deployable Linux network sensor that evaluates captured IP traffic against declarative intent policies. It logs policy violations as JSON Lines, optionally sends webhook notifications, exposes health and Prometheus-compatible metrics, and renders `action=drop` policies into an `nftables` forwarding ruleset.

> Use this software only on networks and systems you own or are explicitly authorized to monitor.

## What it does

- Captures IPv4 and IPv6 metadata continuously with Scapy.
- Evaluates source CIDRs, destination CIDRs, protocol, and destination ports.
- Does **not** store packet payloads.
- Writes rotating structured event logs.
- Sends optional webhook notifications outside the packet-capture thread.
- Deduplicates repeated webhook notifications while retaining local events.
- Exposes `/healthz`, `/readyz`, and `/metrics`.
- Reloads policy rules on `SIGHUP` without restarting capture.
- Processes PCAP files for testing and incident review.
- Generates an `nftables` ruleset from the same policy file.
- Includes unit tests, Docker deployment, systemd deployment, and GitHub Actions CI.

## Architecture

```text
Network interface / PCAP
          |
          v
     Scapy capture
          |
          v
   Packet metadata parser
          |
          v
     Policy engine <------- config/policy.json
          |
     matched rules
          |
          +----> rotating JSONL log
          +----> webhook worker
          +----> metrics and health

config/policy.json ----> nftables renderer ----> gateway enforcement
```

## Requirements

- Linux is recommended for live capture and `nftables` enforcement.
- Python 3.11 or newer.
- `libpcap` for BPF capture filters.
- `CAP_NET_RAW` or root for packet capture.
- `CAP_NET_ADMIN` or root only when applying firewall rules.

## Policy model

The machine-readable schema is available at `config/policy.schema.json`.

The example blocks development traffic to a production PostgreSQL endpoint and alerts on SSH:

```json
{
  "id": "DEV-TO-PROD-DB",
  "description": "Development systems must not connect directly to PostgreSQL in production",
  "enabled": true,
  "source_cidrs": ["10.20.0.0/16"],
  "destination_cidrs": ["10.50.10.8/32"],
  "protocol": "tcp",
  "destination_ports": [5432],
  "severity": "critical",
  "action": "drop"
}
```

`action=alert` is detected and reported only. `action=drop` is detected and reported by the sensor and can also be rendered into the static `nftables` ruleset.

## Local installation

```bash
sudo apt-get update
sudo apt-get install -y python3-venv libpcap0.8 nftables

python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

ibn-monitor validate --config config/policy.json
```

Update `sensor.interface` in `config/policy.json` after identifying the correct interface:

```bash
ip -brief link
```

Start live monitoring:

```bash
sudo .venv/bin/ibn-monitor run --config config/policy.json
```

The log is written to `/var/log/ibn-monitor/events.jsonl` by the example configuration.

## Test a flow without capturing packets

A matching flow returns exit code `2`:

```bash
ibn-monitor check \
  --config config/policy.json \
  --source 10.20.5.14 \
  --destination 10.50.10.8 \
  --protocol tcp \
  --destination-port 5432
```

## PCAP test

```bash
python scripts/generate_test_pcap.py
ibn-monitor run --config config/policy.json --pcap test-traffic.pcap
```

## Webhook notifications

Set the environment variable named by `notifications.webhook_url_env`:

```bash
export IBN_WEBHOOK_URL='https://your-authorized-endpoint.example/events'
sudo --preserve-env=IBN_WEBHOOK_URL .venv/bin/ibn-monitor run --config config/policy.json
```

The receiver gets the same JSON event written locally. Treat webhook URLs as secrets and never commit them.

## Health and metrics

The default health listener binds only to localhost:

```bash
curl http://127.0.0.1:9108/healthz
curl http://127.0.0.1:9108/readyz
curl http://127.0.0.1:9108/metrics
```

## Docker

Docker live capture requires host networking and Linux capabilities:

```bash
mkdir -p data/logs
docker compose up --build -d
docker compose logs -f
```

Keep the health endpoint bound to `127.0.0.1` unless you deliberately protect and expose it.

## systemd

Review the installation script and service hardening settings, then run:

```bash
sudo ./scripts/install-systemd.sh
sudo journalctl -u ibn-monitor -f
```

Reload policy rules after editing `/etc/ibn-monitor/policy.json`:

```bash
sudo systemctl reload ibn-monitor
```

Changes to capture interface, BPF filter, log destination, or health listener require a restart.

## nftables enforcement

Generate and validate the firewall rules before applying them:

```bash
ibn-monitor render-nftables \
  --config config/policy.json \
  --output build/ibn-monitor.nft

sudo nft --check --file build/ibn-monitor.nft
sudo nft --file build/ibn-monitor.nft
sudo nft list table inet ibn_monitor
```

Or use:

```bash
sudo ./scripts/apply-nftables.sh config/policy.json
```

Important deployment notes:

- The generated chain uses the `forward` hook. Deploy it on the gateway or firewall carrying the traffic.
- Validate the rules in a non-production environment first.
- Ensure you have console or out-of-band access before changing a remote firewall.
- The generated rules replace only the `inet ibn_monitor` table, not the rest of the host firewall.
- Persistent loading varies by distribution; integrate the generated ruleset with your platform's normal nftables service.

## Event example

```json
{
  "schema_version": 1,
  "event_id": "9a790d64-b9d4-47e1-89bc-b469b72a3063",
  "event_type": "network_policy_violation",
  "observed_at": "2026-07-17T18:21:44.842911+00:00",
  "rule": {
    "id": "DEV-TO-PROD-DB",
    "description": "Development systems must not connect directly to PostgreSQL in production",
    "severity": "critical",
    "action": "drop"
  },
  "network": {
    "timestamp": "2026-07-17T18:21:44.842911+00:00",
    "interface": "eth0",
    "source": "10.20.5.14",
    "destination": "10.50.10.8",
    "protocol": "tcp",
    "source_port": 50000,
    "destination_port": 5432,
    "packet_length": 40,
    "tcp_flags": "S"
  }
}
```

## GitHub

Create a repository and push this directory:

```bash
git init
git add .
git commit -m "Add intent-based continuous traffic monitor"
git branch -M main
git remote add origin git@github.com:YOUR-USERNAME/ibn-continuous-traffic-monitor.git
git push -u origin main
```

GitHub Actions runs Ruff, the test suite across supported Python versions, and a Docker build. The monitor itself should run on an authorized Linux sensor or gateway, not as a normal GitHub-hosted Actions job.

## Security boundaries

- The monitor observes packet headers and transport metadata, not application payloads.
- A host sensor only sees traffic delivered to or observable by that host. Use a TAP, SPAN/mirror port, gateway, or cloud-native traffic-mirroring feature when broader visibility is required.
- Encrypted traffic still exposes network-layer metadata but not protected application content.
- Detection is not the same as enforcement. Apply the generated firewall rules only after controlled validation.
- Keep the policy file, logs, health endpoint, and webhook receiver access-controlled.
