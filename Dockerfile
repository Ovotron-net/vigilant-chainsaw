# syntax=docker/dockerfile:1
# ibn-monitor image for Windows Docker Desktop (Linux containers).
# Publish 9108/9109 via compose; do not use host networking on Desktop.

ARG PYTHON_VERSION=3.12

FROM python:${PYTHON_VERSION}-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build

RUN apt-get update \
    && apt-get install --no-install-recommends -y build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN python -m pip install --upgrade pip \
    && python -m pip install --prefix=/install .

FROM python:${PYTHON_VERSION}-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    IBN_CONFIG=/etc/ibn-monitor/policy.v2.json \
    PATH="/usr/local/bin:${PATH}"

LABEL org.opencontainers.image.title="ibn-monitor" \
      org.opencontainers.image.description="Intent-Based Continuous Traffic Monitor (v2) — Docker Desktop / Windows" \
      org.opencontainers.image.licenses="GPL-2.0-only"

WORKDIR /app

RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 950 ibn-monitor \
    && useradd --system --uid 950 --gid ibn-monitor --no-create-home \
        --shell /usr/sbin/nologin ibn-monitor \
    && mkdir -p /etc/ibn-monitor /var/log/ibn-monitor /var/lib/ibn-monitor \
    && chown -R ibn-monitor:ibn-monitor /var/log/ibn-monitor /var/lib/ibn-monitor

COPY --from=builder /install /usr/local

COPY config/policy.v2.docker.json /etc/ibn-monitor/policy.v2.json
COPY config/policy.v2.example.json /app/config/policy.v2.example.json

USER ibn-monitor:ibn-monitor

# Policy binds 0.0.0.0; healthcheck still uses loopback inside the container.
HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:9108/healthz', timeout=2)"

EXPOSE 9108 9109

ENTRYPOINT ["tini", "--", "ibn-monitor"]
CMD ["run", "--config", "/etc/ibn-monitor/policy.v2.json"]
