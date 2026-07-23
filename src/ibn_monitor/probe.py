from __future__ import annotations

import json
import logging
import threading
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .config import ListenerV2Config
from .models import OperationalSnapshot

logger = logging.getLogger(__name__)


class ProbeServer:
    """Minimal loopback probe: /healthz and /readyz only."""

    def __init__(
        self,
        config: ListenerV2Config,
        snapshot_provider: Callable[[], OperationalSnapshot],
    ) -> None:
        self._config = config
        self._snapshot_provider = snapshot_provider
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if not self._config.enabled:
            return
        provider = self._snapshot_provider

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                snap = provider()
                if self.path == "/healthz":
                    if "worker_dead" in snap.reasons:
                        self._respond(500, {"status": "dead"})
                    else:
                        self._respond(200, {"status": "ok"})
                    return
                if self.path == "/readyz":
                    if snap.ready:
                        self._respond(200, {"ready": True})
                    else:
                        self._respond(503, {"ready": False, "state": snap.state})
                    return
                self._respond(404, {"error": "not_found"})

            def log_message(self, format: str, *args: object) -> None:  # noqa: A003
                return

            def _respond(self, code: int, payload: dict[str, object]) -> None:
                body = json.dumps(payload).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
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
