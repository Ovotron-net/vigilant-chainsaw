import threading
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer

from factories import observation, policy_rule

from ibn_monitor.config import NotificationV2Config
from ibn_monitor.episodes import EpisodeSettings, EpisodeTracker
from ibn_monitor.evidence import EvidenceSequencer
from ibn_monitor.notifications_v2 import WebhookV2Notifier, build_v2_notifier


def test_null_notifier_when_env_unset():
    notifier = build_v2_notifier(NotificationV2Config())
    notifier.start()
    tracker = EpisodeTracker(EpisodeSettings(10, 30, 60), id_factory=lambda: "ep")
    transition = tracker.observe(
        policy_rule(), observation(), policy_revision="a" * 64, lifecycle_time=0
    )[0]
    env = EvidenceSequencer("s", "b").wrap_episode(
        transition, emitted_at=datetime(2026, 7, 24, tzinfo=UTC)
    )
    notifier.notify(env)
    notifier.stop()


def test_progress_events_are_not_eligible(monkeypatch):
    monkeypatch.setenv("WH", "https://example.test/hook")
    notifier = WebhookV2Notifier(NotificationV2Config(webhook_url_env="WH", minimum_severity="low"))
    tracker = EpisodeTracker(EpisodeSettings(10, 30, 60), id_factory=lambda: "ep")
    tracker.observe(policy_rule(), observation(), policy_revision="a" * 64, lifecycle_time=0)
    # Keep episode active and hit progress interval without idle close.
    tracker.observe(policy_rule(), observation(), policy_revision="a" * 64, lifecycle_time=40)
    progress = tracker.advance(60)
    assert progress and progress[0].phase == "progress"
    env = EvidenceSequencer("s", "b").wrap_episode(
        progress[0], emitted_at=datetime(2026, 7, 24, tzinfo=UTC)
    )
    notifier.notify(env)
    assert notifier.suppressed == 1


def test_https_url_required(monkeypatch):
    monkeypatch.setenv("WH", "http://example.com/hook")
    try:
        WebhookV2Notifier(NotificationV2Config(webhook_url_env="WH"))
        raised = False
    except ValueError:
        raised = True
    assert raised


def test_null_notifier_reports_zero_stats():
    from ibn_monitor.notifications_v2 import NotifierStats, NullV2Notifier

    assert NullV2Notifier().stats() == NotifierStats()


def test_webhook_rejects_redirect_without_following(monkeypatch):
    paths = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            paths.append(self.path)
            self.send_response(302)
            self.send_header("Location", "/target")
            self.end_headers()

        def do_GET(self):  # noqa: N802
            paths.append(self.path)
            self.send_response(200)
            self.end_headers()

        def log_message(self, _format, *_args):
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("WH", f"http://127.0.0.1:{server.server_port}/hook")
    notifier = WebhookV2Notifier(
        NotificationV2Config(
            webhook_url_env="WH",
            insecure_allow_http_loopback=True,
            max_attempts=1,
        )
    )
    tracker = EpisodeTracker(EpisodeSettings(10, 30, 60), id_factory=lambda: "ep")
    transition = tracker.observe(
        policy_rule(), observation(), policy_revision="a" * 64, lifecycle_time=0
    )[0]
    envelope = EvidenceSequencer("s", "b").wrap_episode(
        transition, emitted_at=datetime(2026, 7, 24, tzinfo=UTC)
    )

    try:
        notifier._deliver(envelope)
    finally:
        server.shutdown()
        thread.join()

    assert paths == ["/hook"]
    assert notifier.failed == 1
