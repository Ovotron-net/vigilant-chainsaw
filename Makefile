.PHONY: install dev test lint validate check docker nftables nftables-v2 validate-v2 replay-v2 microbench release-check test-linux-raw

install:
	python -m pip install .

dev:
	python -m pip install -e ".[dev]"

test:
	pytest

lint:
	ruff check .

validate:
	ibn-monitor validate --config config/policy.json

check:
	ibn-monitor check --config config/policy.v2.example.json \
	  --source 10.20.5.14 --destination 10.50.10.8 --protocol tcp --destination-port 5432

docker:
	docker compose up --build -d

nftables:
	ibn-monitor render-nftables --config config/policy.json --output build/ibn-monitor.nft

nftables-v2:
	ibn-monitor render-nftables --config config/policy.v2.example.json --output build/ibn-monitor-v2.nft

validate-v2:
	ibn-monitor validate --config config/policy.v2.example.json --strict

replay-v2:
	python scripts/generate_test_pcap.py
	ibn-monitor replay --config config/policy.v2.example.json --pcap test-traffic.pcap \
	  --output build/replay-v2.jsonl --summary-output -

microbench:
	python scripts/microbench_pipeline.py --write build/microbench.json

test-linux-raw:
	pytest -m linux_raw -q --no-cov

release-check:
	ruff check .
	pytest -q
	python scripts/microbench_pipeline.py --observations 5000 --write build/microbench.json
	ibn-monitor validate --config config/policy.v2.example.json --strict
	python scripts/generate_test_pcap.py
	ibn-monitor replay --config config/policy.v2.example.json --pcap test-traffic.pcap \
	  --output build/replay-v2.jsonl --summary-output -
	ibn-monitor render-nftables --config config/policy.v2.example.json --output build/ibn-monitor-v2.nft
	python -m pip wheel . --no-deps --wheel-dir build/wheels
