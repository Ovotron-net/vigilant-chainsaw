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
  --color-warning: oklch(51% 0.12 70);
  --color-success: oklch(48% 0.12 150);
  --radius-sm: 0.25rem;
  --radius-md: 0.375rem;
  --radius-lg: 0.5rem;
  --animate-fade-in: fade-in 0.2s ease-out;
  color-scheme: light dark;
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
    --color-destructive: oklch(70% 0.17 27);
    --color-warning: oklch(78% 0.14 70);
    --color-success: oklch(75% 0.15 150);
  }
}
@keyframes fade-in { from { opacity: 0; } to { opacity: 1; } }
@media (prefers-reduced-motion: reduce) {
  * { animation: none !important; transition: none !important; }
}

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
.status--stale { background: color-mix(in oklch, var(--color-warning) 18%, transparent); color: var(--color-warning); }
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
.table-wrap { overflow-x: auto; border: 1px solid var(--color-border); border-radius: var(--radius-lg); background: var(--color-card); }
table { width: 100%; border-collapse: collapse; }
caption { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }
th, td { text-align: left; padding: 0.5rem 0.75rem; border-bottom: 1px solid var(--color-border); white-space: nowrap; }
th { font-size: 0.75rem; color: var(--color-muted-foreground); font-weight: 500; background: var(--color-muted); }
tr:last-child td { border-bottom: none; }
tbody tr { transition: background-color 150ms ease-out; }
tbody tr:hover { background: color-mix(in oklch, var(--color-muted) 55%, transparent); }
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
    <span id="ready" class="status status--down" role="status" aria-live="polite">connecting…</span>
  </header>

  <section aria-labelledby="metrics-heading">
    <h2 id="metrics-heading">Metrics</h2>
    <div id="metrics" class="grid"></div>
  </section>

  <section aria-labelledby="rules-heading">
    <h2 id="rules-heading">Policy rules</h2>
    <div class="table-wrap">
    <table>
      <caption>Loaded v2 policy rules</caption>
      <thead><tr><th scope="col">ID</th><th scope="col">Description</th><th scope="col">Protocol</th><th scope="col">Ports</th><th scope="col">Severity</th><th scope="col">Enforcement</th></tr></thead>
      <tbody id="rules"><tr><td colspan="6" class="empty">Loading…</td></tr></tbody>
    </table>
    </div>
  </section>

  <section aria-labelledby="episodes-heading">
    <h2 id="episodes-heading">Active episodes</h2>
    <div class="table-wrap">
    <table>
      <caption>Active violation episodes (snapshot)</caption>
      <thead><tr><th scope="col">Episode</th><th scope="col">Rule</th><th scope="col">Flow</th><th scope="col">Count</th><th scope="col">Last seen</th></tr></thead>
      <tbody id="episodes"><tr><td colspan="5" class="empty">Loading…</td></tr></tbody>
    </table>
    </div>
  </section>

  <section aria-labelledby="events-heading">
    <h2 id="events-heading">Recent evidence</h2>
    <div class="table-wrap">
    <table>
      <caption>Most recent evidence envelopes</caption>
      <thead><tr><th scope="col">Emitted</th><th scope="col">Type</th><th scope="col">Detail</th><th scope="col">Severity</th></tr></thead>
      <tbody id="events"><tr><td colspan="4" class="empty">Loading…</td></tr></tbody>
    </table>
    </div>
  </section>

  <footer>Auto-refreshes every 3 seconds from <code>/api/state</code> (operations listener).</footer>
</main>
<script>
const COUNTERS = [
  ["observations", "Observations"],
  ["matched_observations", "Matched"],
  ["rule_matches", "Rule matches"],
  ["episodes_started", "Episodes started"],
  ["episodes_closed", "Episodes closed"],
];

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[c]);
}

function badge(kind, text) {
  return `<span class="badge badge--${esc(kind)}">${esc(text)}</span>`;
}

function portsLabel(ports) {
  if (ports === "any" || ports == null) return "any";
  if (Array.isArray(ports)) return ports.join(", ") || "any";
  return String(ports);
}

function render(state) {
  const op = state.operational || {};
  const totals = state.totals || {};
  const ready = document.getElementById("ready");
  const isReady = !!op.ready;
  ready.textContent = op.state || (isReady ? "ready" : "not ready");
  ready.className = "status " + (isReady ? "status--ok" : (op.state === "degraded" ? "status--stale" : "status--down"));

  const fmt = new Intl.NumberFormat();
  const cards = COUNTERS.map(([key, label]) =>
    `<div class="card"><div class="label">${esc(label)}</div>` +
    `<div class="value">${esc(fmt.format(totals[key] || 0))}</div></div>`
  );
  cards.push(
    `<div class="card"><div class="label">Queue</div>` +
    `<div class="value">${esc(op.queue_depth ?? 0)}/${esc(op.queue_capacity ?? 0)}</div></div>`
  );
  cards.push(
    `<div class="card"><div class="label">App drops</div>` +
    `<div class="value">${esc(fmt.format(op.app_queue_drops_total || 0))}</div></div>`
  );
  document.getElementById("metrics").innerHTML = cards.join("");

  const rules = (state.rules || []).map((r) => {
    const match = r.match || {};
    const ports = portsLabel(match.destination_ports);
    const enf = r.enforcement === "nftables_drop_candidate" ? "drop" : "none";
    return `<tr>
      <td><code>${esc(r.id)}</code></td>
      <td>${esc(r.description)}</td>
      <td>${esc(match.protocol || "—")}</td>
      <td>${esc(ports)}</td>
      <td>${badge(r.severity, r.severity)}</td>
      <td>${r.enabled ? badge(enf, enf) : badge("disabled", "disabled")}</td>
    </tr>`;
  });
  document.getElementById("rules").innerHTML =
    rules.join("") || '<tr><td colspan="6" class="empty">No rules loaded.</td></tr>';

  const episodes = (state.active_episodes || []).map((e) => `<tr>
    <td><code>${esc(e.episode_id)}</code></td>
    <td><code>${esc(e.rule_id)}</code></td>
    <td><code>${esc(e.source)} → ${esc(e.destination)}</code> ${esc(e.protocol)}/${esc(e.destination_port ?? "—")}</td>
    <td>${esc(e.observation_count)}</td>
    <td>${esc(e.last_observed_at)}</td>
  </tr>`);
  document.getElementById("episodes").innerHTML =
    episodes.join("") || '<tr><td colspan="5" class="empty">No active episodes.</td></tr>';

  const events = (state.recent_events || []).slice().reverse().map((e) => {
    const p = e.payload || {};
    if (e.event_type === "violation_episode") {
      return `<tr>
        <td>${esc(e.emitted_at)}</td>
        <td>${badge(p.phase || "episode", p.phase || "episode")}</td>
        <td><code>${esc(p.rule?.id)}</code> ${esc(p.flow?.source)} → ${esc(p.flow?.destination)}</td>
        <td>${badge(p.rule?.severity || "low", p.rule?.severity || "—")}</td>
      </tr>`;
    }
    return `<tr>
      <td>${esc(e.emitted_at)}</td>
      <td>${badge("alert", e.event_type || "system")}</td>
      <td><code>${esc(p.name || "—")}</code></td>
      <td>—</td>
    </tr>`;
  });
  document.getElementById("events").innerHTML =
    events.join("") || '<tr><td colspan="4" class="empty">No evidence yet.</td></tr>';
}

async function refresh() {
  const ready = document.getElementById("ready");
  try {
    const response = await fetch("/api/state");
    if (response.ok) render(await response.json());
  } catch (error) {
    ready.textContent = "connection lost";
    ready.className = "status status--stale";
  }
}

refresh();
setInterval(refresh, 3000);
</script>
</body>
</html>
"""
