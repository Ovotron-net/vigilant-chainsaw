"""Operations HTTP listener: dashboard + /api/state (loopback by default)."""

from __future__ import annotations

import json
import logging
import threading
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .config import ListenerV2Config
from .dashboard import DASHBOARD_HTML

logger = logging.getLogger(__name__)

SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
        "img-src 'none'; connect-src 'self'; base-uri 'none'; form-action 'none'; "
        "frame-ancestors 'none'"
    ),
}


class OperationsServer:
    def __init__(
        self,
        config: ListenerV2Config,
        state_provider: Callable[[], dict[str, object]],
    ) -> None:
        self._config = config
        self._state_provider = state_provider
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if not self._config.enabled:
            return
        if (
            self._config.bind not in {"127.0.0.1", "::1", "localhost"}
            and not self._config.allow_non_loopback
        ):
            raise RuntimeError(
                "operations HTTP bind is non-loopback without allow_non_loopback"
            )
        provider = self._state_provider

        class Handler(BaseHTTPRequestHandler):
            server_version = "ibn-monitor/2.0"

            def do_GET(self) -> None:  # noqa: N802
                if self.path in {"/", "/index.html"}:
                    body = DASHBOARD_HTML.encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    for key, value in SECURITY_HEADERS.items():
                        self.send_header(key, value)
                    self.end_headers()
                    self.wfile.write(body)
                    return
                if self.path == "/api/state":
                    payload = provider()
                    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    for key, value in SECURITY_HEADERS.items():
                        self.send_header(key, value)
                    self.end_headers()
                    self.wfile.write(body)
                    return
                body = json.dumps({"error": "not_found"}).encode("utf-8")
                self.send_response(404)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                for key, value in SECURITY_HEADERS.items():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: object) -> None:  # noqa: A003
                return

        self._server = ThreadingHTTPServer(
            (self._config.bind, self._config.port), Handler
        )
        self._thread = threading.Thread(
            target=self._server.serve_forever, name="ibn-operations", daemon=True
        )
        self._thread.start()
        logger.info(
            "Operations listening on %s:%s", self._config.bind, self._config.port
        )

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None
