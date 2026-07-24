# ibn-monitor operator runbook (v2)

## Roles

| Role | Responsibilities | Capabilities |
|---|---|---|
| **Sensor** (`ibn-monitor run`) | Capture, match, journal, notify, probe/ops HTTP | `CAP_NET_RAW` only |
| **Enforcement automation** | Render + apply nftables | `CAP_NET_ADMIN` (separate unit/script) |
| **Operator** | Policy edits, SIGHUP reload, reviews | Config file + journal access |

The sensor **never** applies firewall rules.

## Install (Linux)

```bash
sudo ./scripts/install-systemd.sh
# Policy: /etc/ibn-monitor/policy.v2.json
# Logs:   /var/log/ibn-monitor/
# State:  /var/lib/ibn-monitor/
```

Validate before start:

```bash
ibn-monitor validate --config /etc/ibn-monitor/policy.v2.json --strict
```

## Day-2 operations

### Probe and operations HTTP

Two listeners (v2). Full `/api/state` nested contract:
[ops-state-api.md](ops-state-api.md) · example:
[fixtures/ops-state.example.json](fixtures/ops-state.example.json).

| Endpoint | Port (default) | Meaning |
|---|---|---|
| `GET /healthz` | 9108 (probe) | 200 = process alive (incl. degraded); 500 = worker dead |
| `GET /readyz` | 9108 (probe) | 200 only when `state=ready` |
| `GET /metrics` | 9108 (probe) | Prometheus text |
| `GET /` | 9109 (operations) | Embedded ops dashboard (loopback; tunnel/proxy for remote) |
| `GET /api/state` | 9109 (operations) | Atomic JSON snapshot (`ReadModel.view()`) |

```bash
curl -sS http://127.0.0.1:9108/readyz
curl -sS http://127.0.0.1:9108/metrics | head
curl -sS http://127.0.0.1:9109/api/state | head -c 200
```

### Policy reload (rules only)

```bash
# Edit rules under /etc/ibn-monitor/policy.v2.json
sudo systemctl reload ibn-monitor   # SIGHUP
journalctl -u ibn-monitor -n 50 --no-pager
```

Restart-only settings (sensor topology, capture points, queue sizes, episode timers, journal path, HTTP binds, notification env name) require:

```bash
sudo systemctl restart ibn-monitor
```

### Offline analysis

```bash
python scripts/generate_test_pcap.py
ibn-monitor replay \
  --config config/policy.v2.example.json \
  --pcap test-traffic.pcap \
  --output /tmp/replay.jsonl \
  --summary-output -
```

### Synthetic check

```bash
# exit 0 = clear, 1 = match, 2 = error
ibn-monitor check --config config/policy.v2.example.json \
  --source 10.20.5.14 --destination 10.50.10.8 \
  --protocol tcp --destination-port 5432 --format json
```

## Enforcement workflow

```bash
# 1. Render (unprivileged)
ibn-monitor render-nftables --config /etc/ibn-monitor/policy.v2.json \
  --output /var/lib/ibn-monitor/ibn-monitor.nft

# 2. Apply with backup/check/verify/rollback
sudo /usr/local/sbin/ibn-apply-nftables /etc/ibn-monitor/policy.v2.json
```

Mirror topology **cannot** render nftables (detection only).

## Common incidents

| Symptom | Check | Action |
|---|---|---|
| `/readyz` 503, reason `capture_point_unavailable` | Interface up? `ip link` | Fix link; wait for recovery backoff |
| `app_queue_drops` | Load / rule count / CPU | Reduce traffic mirror span, raise capacity, scale host |
| `kernel_drops` | Socket stats / rcvbuf | Raise rcvbuf, check NIC, consider TPACKET only after design review |
| Journal unhealthy | Disk full / permissions | Free space on journal path; restart after fix |
| Webhook failures | Env URL, TLS, network | Fix `webhook_url_env`; journal remains authoritative |
| Reload failed `restart_required` | Diff non-rule fields | Full restart with intentional config |

## Shutdown

```bash
sudo systemctl stop ibn-monitor   # graceful SIGTERM
# Second signal forces exit (130/143)
```

After unclean stop, next boot journals unclean-boot context via missing `.clean` marker beside the journal file.

## Security notes

- Do not bind **operations** HTTP (`:9109` by default) off-loopback without
  `http.operations.allow_non_loopback=true` **and** an authenticated reverse
  proxy or SSH tunnel. The sensor has no auth on either listener.
- Treat the **probe** listener (`:9108`) the same way if you expose it beyond
  loopback — it is liveness/metrics only, but still process metadata.
- Webhook URLs are HTTPS only (or HTTP loopback with explicit insecure flag).
- Never put secrets in policy JSON; only env var **names**.

See also: [ops-state-api.md](ops-state-api.md) (trust boundary + response shape).
