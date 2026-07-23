from __future__ import annotations

import json
import logging
import threading
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .config import ListenerV2Config
from .models import OperationalSnapshot

logger = logging.getLogger(__name__)

PROBE_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}


class ProbeServer:
    """Probe listener: /healthz, /readyz, /metrics only."""

    def __init__(
        self,
        config: ListenerV2Config,
        snapshot_provider: Callable[[], OperationalSnapshot],
        metrics_provider: Callable[[], str] | None = None,
    ) -> None:
        self._config = config
        self._snapshot_provider = snapshot_provider
        self._metrics_provider = metrics_provider
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if not self._config.enabled:
            return
        provider = self._snapshot_provider
        metrics_provider = self._metrics_provider

        class Handler(BaseHTTPRequestHandler):
            server_version = "ibn-monitor/2.0"

            def do_GET(self) -> None:  # noqa: N802
                snap = provider()
                if self.path == "/healthz":
                    if "worker_dead" in snap.reasons:
                        self._json(500, {"status": "dead"})
                    else:
                        self._json(200, {"status": "ok", "state": snap.state})
                    return
                if self.path == "/readyz":
                    if snap.ready:
                        self._json(200, {"ready": True, "state": snap.state})
                    else:
                        self._json(
                            503,
                            {
                                "ready": False,
                                "state": snap.state,
                                "reasons": sorted(snap.reasons),
                            },
                        )
                    return
                if self.path == "/metrics":
                    if metrics_provider is None:
                        self._json(404, {"error": "metrics_unavailable"})
                        return
                    body = metrics_provider().encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain; version=0.0.4")
                    self.send_header("Content-Length", str(len(body)))
                    for key, value in PROBE_HEADERS.items():
                        self.send_header(key, value)
                    self.end_headers()
                    self.wfile.write(body)
                    return
                self._json(404, {"error": "not_found"})

            def log_message(self, format: str, *args: object) -> None:  # noqa: A003
                return

            def _json(self, code: int, payload: dict[str, object]) -> None:
                body = json.dumps(payload).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                for key, value in PROBE_HEADERS.items():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(body)

        self._server = ThreadingHTTPServer((self._config.bind, self._config.port), Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever, name="ibn-probe", daemon=True
        )
        self._thread.start()
        logger.info("Probe listening on %s:%s", self._config.bind, self._config.port)

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None
