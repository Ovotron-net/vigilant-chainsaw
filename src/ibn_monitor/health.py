from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .config import HealthConfig
from .dashboard import DASHBOARD_HTML
from .events import Metrics
from .models import Rule

RulesProvider = Callable[[], tuple[Rule, ...]]
EventsProvider = Callable[[], list[dict[str, Any]]]


def _rule_to_dict(rule: Rule) -> dict[str, Any]:
    return {
        "id": rule.id,
        "description": rule.description,
        "enabled": rule.enabled,
        "source_cidrs": [str(network) for network in rule.source_cidrs],
        "destination_cidrs": [str(network) for network in rule.destination_cidrs],
        "protocol": rule.protocol,
        "destination_ports": sorted(rule.destination_ports),
        "severity": rule.severity,
        "action": rule.action,
    }


class HealthServer:
    def __init__(
        self,
        config: HealthConfig,
        metrics: Metrics,
        rules_provider: RulesProvider | None = None,
        events_provider: EventsProvider | None = None,
    ) -> None:
        self._config = config
        self._metrics = metrics
        self._rules_provider = rules_provider
        self._events_provider = events_provider
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int | None:
        """Actual bound port once started (useful when configured with port 0)."""
        return self._server.server_address[1] if self._server else None

    def start(self) -> None:
        if not self._config.enabled:
            return
        metrics = self._metrics
        rules_provider = self._rules_provider
        events_provider = self._events_provider

        class Handler(BaseHTTPRequestHandler):
            server_version = "ibn-monitor/1.0"

            def do_GET(self) -> None:  # noqa: N802
                snapshot = metrics.snapshot()
                if self.path in ("/", "/index.html"):
                    body = DASHBOARD_HTML.encode("utf-8")
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                elif self.path == "/api/state":
                    rules = rules_provider() if rules_provider else ()
                    events = events_provider() if events_provider else []
                    self._json(
                        HTTPStatus.OK,
                        {
                            "metrics": snapshot,
                            "rules": [_rule_to_dict(rule) for rule in rules],
                            "recent_events": events,
                        },
                    )
                elif self.path == "/healthz":
                    self._json(HTTPStatus.OK, {"status": "ok", **snapshot})
                elif self.path == "/readyz":
                    status = HTTPStatus.OK if snapshot["ready"] else HTTPStatus.SERVICE_UNAVAILABLE
                    self._json(status, {"ready": snapshot["ready"]})
                elif self.path == "/metrics":
                    body = _prometheus(snapshot).encode("utf-8")
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Type", "text/plain; version=0.0.4")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

            def _json(self, status: HTTPStatus, payload: dict[str, object]) -> None:
                body = json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: object) -> None:
                return

        self._server = ThreadingHTTPServer((self._config.bind, self._config.port), Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="ibn-health-server",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
        if self._thread:
            self._thread.join(timeout=3)


def _prometheus(snapshot: dict[str, int | float | bool]) -> str:
    uptime = max(0.0, time.time() - float(snapshot["started_at"]))
    lines = [
        "# HELP ibn_monitor_ready Whether the packet monitor is ready.",
        "# TYPE ibn_monitor_ready gauge",
        f'ibn_monitor_ready {1 if snapshot["ready"] else 0}',
        "# HELP ibn_monitor_uptime_seconds Monitor process uptime.",
        "# TYPE ibn_monitor_uptime_seconds gauge",
        f"ibn_monitor_uptime_seconds {uptime:.3f}",
    ]
    counters = (
        "packets_seen",
        "packets_decoded",
        "violations",
        "notifications_sent",
        "notification_failures",
        "notifications_suppressed",
        "notification_queue_dropped",
    )
    for name in counters:
        metric_name = f"ibn_monitor_{name}_total"
        lines.extend(
            [
                f"# TYPE {metric_name} counter",
                f"{metric_name} {int(snapshot[name])}",
            ]
        )
    lines.extend(
        [
            "# TYPE ibn_monitor_last_packet_timestamp_seconds gauge",
            f'ibn_monitor_last_packet_timestamp_seconds {float(snapshot["last_packet_at"]):.3f}',
            "# TYPE ibn_monitor_last_violation_timestamp_seconds gauge",
            "ibn_monitor_last_violation_timestamp_seconds "
            f'{float(snapshot["last_violation_at"]):.3f}',
            "",
        ]
    )
    return "\n".join(lines)
