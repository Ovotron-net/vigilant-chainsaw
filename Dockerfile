# syntax=docker/dockerfile:1
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# libpcap is not required for AF_PACKET; keep tools light.
RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --shell /usr/sbin/nologin ibn-monitor

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir .

COPY config ./config
RUN mkdir -p /var/log/ibn-monitor /var/lib/ibn-monitor \
    && chown -R ibn-monitor:ibn-monitor /var/log/ibn-monitor /var/lib/ibn-monitor

USER ibn-monitor

# Probe listener default (config/policy.v2.example.json → 9108)
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:9108/healthz', timeout=2)"

ENTRYPOINT ["ibn-monitor"]
CMD ["run", "--config", "/app/config/policy.v2.example.json"]
