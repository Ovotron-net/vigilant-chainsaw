"""Self-contained HTML dashboard exposing the sensor's underlying state.

The stylesheet follows the Tailwind CSS v4 design-system conventions:
semantic OKLCH design tokens (background/foreground/muted/accent/destructive),
radius and animation tokens, and a class-plus-media dark-mode variant. It is
embedded as plain CSS because the sensor is stdlib-only and ships no Node
build chain.
"""

from __future__ import annotations

DASHBOARD_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ibn-monitor</title>
<style>
/* Design tokens — Tailwind v4 @theme equivalents */
:root {
  --color-background: oklch(100% 0 0);
  --color-foreground: oklch(14.5% 0.025 264);
  --color-card: oklch(100% 0 0);
  --color-card-foreground: oklch(14.5% 0.025 264);
  --color-muted: oklch(96% 0.01 264);
  --color-muted-foreground: oklch(46% 0.02 264);
  --color-border: oklch(91% 0.01 264);
  --color-primary: oklch(14.5% 0.025 264);
  --color-primary-foreground: oklch(98% 0.01 264);
  --color-destructive: oklch(53% 0.22 27);
  --color-destructive-foreground: oklch(98% 0.01 264);
  --color-warning: oklch(70% 0.15 70);
  --color-success: oklch(62% 0.15 150);
  --radius-sm: 0.25rem;
  --radius-md: 0.375rem;
  --radius-lg: 0.5rem;
  --animate-fade-in: fade-in 0.2s ease-out;
}
@media (prefers-color-scheme: dark) {
  :root {
    --color-background: oklch(14.5% 0.025 264);
    --color-foreground: oklch(98% 0.01 264);
    --color-card: oklch(18% 0.025 264);
    --color-card-foreground: oklch(98% 0.01 264);
    --color-muted: oklch(22% 0.02 264);
    --color-muted-foreground: oklch(65% 0.02 264);
    --color-border: oklch(26% 0.02 264);
    --color-primary: oklch(98% 0.01 264);
    --color-primary-foreground: oklch(14.5% 0.025 264);
    --color-destructive: oklch(58% 0.19 27);
  }
}
@keyframes fade-in { from { opacity: 0; } to { opacity: 1; } }

* { box-sizing: border-box; border-color: var(--color-border); }
body {
  margin: 0;
  background: var(--color-background);
  color: var(--color-foreground);
  font: 14px/1.5 ui-sans-serif, system-ui, sans-serif;
  -webkit-font-smoothing: antialiased;
}
main { max-width: 72rem; margin: 0 auto; padding: 1.5rem; }
header { display: flex; align-items: baseline; gap: 0.75rem; margin-bottom: 1.5rem; }
h1 { font-size: 1.25rem; font-weight: 600; margin: 0; }
h2 { font-size: 0.875rem; font-weight: 600; margin: 0 0 0.75rem; color: var(--color-muted-foreground); text-transform: uppercase; letter-spacing: 0.05em; }
.status { font-size: 0.75rem; font-weight: 500; padding: 0.125rem 0.5rem; border-radius: 9999px; }
.status--ok { background: color-mix(in oklch, var(--color-success) 15%, transparent); color: var(--color-success); }
.status--down { background: color-mix(in oklch, var(--color-destructive) 15%, transparent); color: var(--color-destructive); }
.grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(11rem, 1fr)); gap: 0.75rem; margin-bottom: 2rem; }
.card {
  background: var(--color-card);
  color: var(--color-card-foreground);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-lg);
  padding: 0.875rem 1rem;
  animation: var(--animate-fade-in);
}
.card .label { font-size: 0.75rem; color: var(--color-muted-foreground); }
.card .value { font-size: 1.5rem; font-weight: 600; font-variant-numeric: tabular-nums; }
section { margin-bottom: 2rem; }
table { width: 100%; border-collapse: collapse; background: var(--color-card); border: 1px solid var(--color-border); border-radius: var(--radius-lg); overflow: hidden; }
th, td { text-align: left; padding: 0.5rem 0.75rem; border-bottom: 1px solid var(--color-border); }
th { font-size: 0.75rem; color: var(--color-muted-foreground); font-weight: 500; background: var(--color-muted); }
tr:last-child td { border-bottom: none; }
td { font-variant-numeric: tabular-nums; }
code { font: 0.8125rem ui-monospace, monospace; }
.badge { font-size: 0.6875rem; font-weight: 600; padding: 0.125rem 0.4375rem; border-radius: var(--radius-sm); text-transform: uppercase; letter-spacing: 0.03em; }
.badge--low { background: var(--color-muted); color: var(--color-muted-foreground); }
.badge--medium { background: color-mix(in oklch, var(--color-warning) 18%, transparent); color: var(--color-warning); }
.badge--high, .badge--critical { background: color-mix(in oklch, var(--color-destructive) 15%, transparent); color: var(--color-destructive); }
.badge--drop { background: var(--color-primary); color: var(--color-primary-foreground); }
.badge--alert { background: var(--color-muted); color: var(--color-muted-foreground); }
.badge--disabled { background: var(--color-muted); color: var(--color-muted-foreground); opacity: 0.6; }
.empty { color: var(--color-muted-foreground); padding: 1rem 0.75rem; }
footer { font-size: 0.75rem; color: var(--color-muted-foreground); }
</style>
</head>
<body>
<main>
  <header>
    <h1>ibn-monitor</h1>
    <span id="ready" class="status status--down">connecting…</span>
  </header>

  <section>
    <h2>Metrics</h2>
    <div id="metrics" class="grid"></div>
  </section>

  <section>
    <h2>Policy rules</h2>
    <table>
      <thead><tr><th>ID</th><th>Description</th><th>Protocol</th><th>Ports</th><th>Severity</th><th>Action</th></tr></thead>
      <tbody id="rules"><tr><td colspan="6" class="empty">Loading…</td></tr></tbody>
    </table>
  </section>

  <section>
    <h2>Recent violations</h2>
    <table>
      <thead><tr><th>Observed</th><th>Rule</th><th>Severity</th><th>Source</th><th>Destination</th><th>Proto</th><th>Port</th></tr></thead>
      <tbody id="events"><tr><td colspan="7" class="empty">Loading…</td></tr></tbody>
    </table>
  </section>

  <footer>Auto-refreshes every 3 seconds from <code>/api/state</code>.</footer>
</main>
<script>
const COUNTERS = [
  ["packets_seen", "Packets seen"],
  ["packets_decoded", "Packets decoded"],
  ["violations", "Violations"],
  ["notifications_sent", "Webhooks sent"],
  ["notification_failures", "Webhook failures"],
  ["notifications_suppressed", "Suppressed"],
];

function esc(value) {
  return String(value).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[c]);
}

function badge(kind, text) {
  return `<span class="badge badge--${esc(kind)}">${esc(text)}</span>`;
}

function render(state) {
  const ready = document.getElementById("ready");
  ready.textContent = state.metrics.ready ? "ready" : "not ready";
  ready.className = "status " + (state.metrics.ready ? "status--ok" : "status--down");

  document.getElementById("metrics").innerHTML = COUNTERS.map(([key, label]) =>
    `<div class="card"><div class="label">${esc(label)}</div>` +
    `<div class="value">${esc(state.metrics[key])}</div></div>`
  ).join("");

  const rules = state.rules.map((r) => `<tr>
    <td><code>${esc(r.id)}</code></td>
    <td>${esc(r.description)}</td>
    <td>${esc(r.protocol)}</td>
    <td>${esc(r.destination_ports.join(", ") || "any")}</td>
    <td>${badge(r.severity, r.severity)}</td>
    <td>${r.enabled ? badge(r.action, r.action) : badge("disabled", "disabled")}</td>
  </tr>`);
  document.getElementById("rules").innerHTML =
    rules.join("") || '<tr><td colspan="6" class="empty">No rules loaded.</td></tr>';

  const events = state.recent_events.slice().reverse().map((e) => `<tr>
    <td>${esc(e.observed_at)}</td>
    <td><code>${esc(e.rule.id)}</code></td>
    <td>${badge(e.rule.severity, e.rule.severity)}</td>
    <td><code>${esc(e.network.source)}</code></td>
    <td><code>${esc(e.network.destination)}</code></td>
    <td>${esc(e.network.protocol)}</td>
    <td>${esc(e.network.destination_port ?? "—")}</td>
  </tr>`);
  document.getElementById("events").innerHTML =
    events.join("") || '<tr><td colspan="7" class="empty">No violations observed.</td></tr>';
}

async function refresh() {
  try {
    const response = await fetch("/api/state");
    if (response.ok) render(await response.json());
  } catch (error) { /* transient; retried on next tick */ }
}

refresh();
setInterval(refresh, 3000);
</script>
</body>
</html>
"""
