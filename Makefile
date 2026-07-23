.PHONY: install dev test lint validate check pcap docker nftables nftables-v2 validate-v2 replay-v2

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
	ibn-monitor check --config config/policy.json --source 10.20.5.14 --destination 10.50.10.8 --protocol tcp --destination-port 5432

pcap:
	python scripts/generate_test_pcap.py
	ibn-monitor run --config config/policy.json --pcap test-traffic.pcap

docker:
	docker compose up --build -d

nftables:
	ibn-monitor render-nftables --config config/policy.json --output build/ibn-monitor.nft
	sudo nft --check --file build/ibn-monitor.nft

nftables-v2:
	ibn-monitor render-nftables --config config/policy.v2.example.json --output build/ibn-monitor-v2.nft


validate-v2:
	ibn-monitor validate --config config/policy.v2.example.json --strict

replay-v2:
	ibn-monitor replay --config config/policy.v2.example.json --pcap test-traffic.pcap --output build/replay-v2.jsonl --summary-output -
