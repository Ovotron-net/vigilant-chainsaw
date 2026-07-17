.PHONY: install dev test lint validate check pcap docker nftables

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
