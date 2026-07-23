import json
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from factories import observation, v2_config

from ibn_monitor.capture import MemoryObservationSource
from ibn_monitor.dashboard import DASHBOARD_HTML
from ibn_monitor.evidence_stub import MemoryEvidenceWriter
from ibn_monitor.monitor import LiveMonitor
from ibn_monitor.operations import SECURITY_HEADERS
from ibn_monitor.read_model import ReadModel


def test_read_model_metrics_and_view():
    model = ReadModel(recent_maxlen=2)
    model.set_rules(v2_config().rules)
    text = model.metrics_text()
    assert "ibn_monitor_ready" in text
    assert "ibn_monitor_observations_total" in text
    view = model.view(active_episodes=())
    assert view["totals"]["observations"] == 0
    assert view["rules"]


def test_operations_http_serves_state_and_dashboard():
    state = {"operational": {"ready": True, "state": "ready"}, "totals": {}, "rules": []}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            if self.path == "/api/state":
                body = json.dumps(state).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                for key, value in SECURITY_HEADERS.items():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(body)
            elif self.path == "/":
                body = DASHBOARD_HTML.encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_error(404)

        def log_message(self, *args):
            return

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        port = httpd.server_address[1]
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/state", timeout=2) as resp:
            payload = json.loads(resp.read().decode())
            assert payload["operational"]["ready"] is True
            assert resp.headers.get("X-Content-Type-Options") == "nosniff"
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=2) as resp:
            html = resp.read().decode()
            assert "ibn-monitor" in html
            assert "active_episodes" in html or "/api/state" in html
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_live_monitor_operations_state_includes_episode():
    config = v2_config()
    evidence = MemoryEvidenceWriter()
    source = MemoryObservationSource("wan")
    monitor = LiveMonitor(
        config,
        config_path="config/policy.v2.example.json",
        sources=(source,),
        evidence=evidence,
        boot_id="boot-ops",
        probe_enabled=False,
        operations_enabled=False,
    )
    monitor.start()
    try:
        source.push(observation(capture_point="wan", monotonic_at=time.monotonic()))
        deadline = time.time() + 2
        view: dict = {}
        while time.time() < deadline:
            view = monitor.operations_state()
            if view["totals"]["observations"] >= 1:
                break
            time.sleep(0.05)
        assert view["totals"]["observations"] >= 1
        assert view["operational"]["sensor_id"] == config.sensor.id
        assert any(r["id"] == "DEV-DB" for r in view["rules"])
        metrics = monitor._worker.metrics_text()
        assert "ibn_monitor_observations_total" in metrics
    finally:
        monitor.stop()
