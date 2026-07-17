from __future__ import annotations

import json
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .config import HealthConfig
from .events import Metrics


class HealthServer:
    def __init__(self, config: HealthConfig, metrics: Metrics) -> None:
        self._config = config
        self._metrics = metrics
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if not self._config.enabled:
            return
        metrics = self._metrics

        class Handler(BaseHTTPRequestHandler):
            server_version = "ibn-monitor/1.0"

            def do_GET(self) -> None:  # noqa: N802
                snapshot = metrics.snapshot()
                if self.path == "/healthz":
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
