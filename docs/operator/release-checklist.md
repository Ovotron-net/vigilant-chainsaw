# Release qualification checklist

Use this before tagging a release or promoting a build to production.

## Automated (every PR / release)

```bash
pip install -e ".[dev]"
ruff check .
pytest -q
# Default suite excludes privileged Linux tests
pytest -m "not linux_raw" -q
python scripts/microbench_pipeline.py --write build/microbench.json
ibn-monitor validate --config config/policy.v2.example.json --strict
python scripts/generate_test_pcap.py
ibn-monitor replay --config config/policy.v2.example.json \
  --pcap test-traffic.pcap --output build/replay-v2.jsonl --summary-output -
ibn-monitor render-nftables --config config/policy.v2.example.json \
  --output build/ibn-monitor-v2.nft
python -m pip wheel . --no-deps --wheel-dir build/wheels
# Wheel must contain both schemas:
python -c "import glob,zipfile; z=zipfile.ZipFile(glob.glob('build/wheels/*.whl')[0]); print([n for n in z.namelist() if n.endswith('.schema.json')])"
```

## Property / fuzz (CI-friendly)

```bash
pytest tests/test_decode_fuzz_v2.py tests/test_parity_v2.py -q
```

## Privileged Linux (lab / nightlies)

Requires root or sufficient capabilities, `nft`, and a Linux host:

```bash
pytest -m linux_raw -q
# Optional full gate (reference 2 vCPU / 512 MB):
# IBN_PERF_GATE=1 pytest -m linux_perf -q
```

See `tests/integration_linux/README.md`.

## Manual operator smoke

- [ ] Install unit via `scripts/install-systemd.sh` on a lab host
- [ ] `/healthz` 200, `/readyz` becomes ready after interfaces up
- [ ] Ops dashboard on loopback 9109
- [ ] SIGHUP rule-only reload journals success/noop
- [ ] Non-rule change reload journals `restart_required`
- [ ] `apply-nftables.sh` backs up, checks, applies, lists table
- [ ] Mirror policy `render-nftables` fails closed
- [ ] SIGTERM produces clean journal marker

## Performance gate (reference host)

| Metric | Target |
|---|---|
| Observation rate | ≥ 10 000/s sustained |
| Enabled rules | 100 mixed CIDR/proto/port |
| App queue drops | 0 in steady state |
| p99 episode-start latency | < 1 s |
| Memory | within 512 MB + configured episode/journal bounds |

Failing the gate blocks claiming “production ready” for the `recvmsg` backend; open a design ticket for TPACKET_V3 rather than silent tuning.

## Sign-off

| Check | Owner | Date |
|---|---|---|
| Automated green | | |
| Linux raw green (if shipping live) | | |
| Perf gate (if shipping live at scale) | | |
| Runbook reviewed | | |
