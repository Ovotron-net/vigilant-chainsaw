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
/* Dark mode artistic design with OKLCH tokens */
:root {
  --color-background: oklch(9% 0.02 264);
  --color-surface: oklch(12% 0.025 264);
  --color-foreground: oklch(96% 0.01 264);
  --color-card: oklch(14% 0.028 265);
  --color-card-border: oklch(22% 0.04 255);
  --color-card-foreground: oklch(95% 0.01 264);
  --color-muted: oklch(24% 0.025 264);
  --color-muted-foreground: oklch(68% 0.015 264);
  --color-border: oklch(20% 0.02 264);
  
  --color-primary: oklch(65% 0.19 280);
  --color-primary-alt: oklch(60% 0.22 285);
  --color-primary-foreground: oklch(98% 0.01 264);
  
  --color-accent: oklch(72% 0.18 60);
  --color-accent-soft: oklch(52% 0.12 45);
  
  --color-destructive: oklch(68% 0.24 27);
  --color-destructive-dark: oklch(45% 0.20 25);
  --color-destructive-foreground: oklch(98% 0.01 264);
  
  --color-warning: oklch(75% 0.16 70);
  --color-warning-dark: oklch(52% 0.12 65);
  
  --color-success: oklch(72% 0.18 155);
  --color-success-dark: oklch(48% 0.14 150);
  
  --radius-sm: 0.375rem;
  --radius-md: 0.5rem;
  --radius-lg: 0.75rem;
  --radius-xl: 1rem;
  
  --glow-sm: 0 0 12px 2px rgba(102, 126, 234, 0.15);
  --glow-md: 0 0 20px 4px rgba(102, 126, 234, 0.2);
  --glow-lg: 0 0 32px 6px rgba(102, 126, 234, 0.25);
  
  color-scheme: dark;
}

@keyframes fade-in {
  from { opacity: 0; transform: translateY(8px); }
  to { opacity: 1; transform: translateY(0); }
}

@keyframes pulse-glow {
  0%, 100% { box-shadow: var(--glow-sm); }
  50% { box-shadow: var(--glow-md); }
}

@keyframes shimmer {
  0% { background-position: -1000px 0; }
  100% { background-position: 1000px 0; }
}

@keyframes slide-down {
  from { opacity: 0; max-height: 0; }
  to { opacity: 1; max-height: 500px; }
}

@media (prefers-reduced-motion: reduce) {
  * { animation: none !important; transition: none !important; }
}
* {
  box-sizing: border-box;
  border-color: var(--color-border);
}

body {
  margin: 0;
  background: linear-gradient(135deg, var(--color-background) 0%, oklch(11% 0.018 250) 100%);
  background-attachment: fixed;
  color: var(--color-foreground);
  font: 14px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}

main {
  max-width: 80rem;
  margin: 0 auto;
  padding: 2rem 1.5rem;
}

header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  margin-bottom: 2.5rem;
  padding-bottom: 1.5rem;
  border-bottom: 1px solid var(--color-border);
}

h1 {
  font-size: 2rem;
  font-weight: 700;
  margin: 0;
  background: linear-gradient(135deg, var(--color-primary) 0%, var(--color-primary-alt) 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  letter-spacing: -0.02em;
}

h2 {
  font-size: 0.875rem;
  font-weight: 700;
  margin: 0 0 1rem;
  color: var(--color-muted-foreground);
  text-transform: uppercase;
  letter-spacing: 0.08em;
  opacity: 0.85;
}

.status {
  font-size: 0.75rem;
  font-weight: 600;
  padding: 0.375rem 0.75rem;
  border-radius: 9999px;
  transition: all 300ms ease-out;
  display: inline-flex;
  align-items: center;
  gap: 0.375rem;
}

.status::before {
  content: '';
  width: 0.375rem;
  height: 0.375rem;
  border-radius: 50%;
  display: inline-block;
}

.status--ok {
  background: color-mix(in oklch, var(--color-success) 20%, transparent);
  color: var(--color-success);
  box-shadow: inset 0 0 8px rgba(114, 184, 141, 0.15);
}

.status--ok::before {
  background: var(--color-success);
  animation: pulse-glow 2s ease-in-out infinite;
}

.status--down {
  background: color-mix(in oklch, var(--color-destructive) 20%, transparent);
  color: var(--color-destructive);
  box-shadow: inset 0 0 8px rgba(173, 109, 91, 0.15);
}

.status--down::before {
  background: var(--color-destructive);
}

.status--stale {
  background: color-mix(in oklch, var(--color-warning) 20%, transparent);
  color: var(--color-warning);
  box-shadow: inset 0 0 8px rgba(191, 144, 0, 0.15);
}

.status--stale::before {
  background: var(--color-warning);
  animation: pulse-glow 1.5s ease-in-out infinite;
}

.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(12rem, 1fr));
  gap: 1rem;
  margin-bottom: 2.5rem;
}

.card {
  background: linear-gradient(135deg, var(--color-card) 0%, oklch(15% 0.03 268) 100%);
  color: var(--color-card-foreground);
  border: 1px solid var(--color-card-border);
  border-radius: var(--radius-xl);
  padding: 1.25rem;
  animation: fade-in 0.5s ease-out backwards;
  transition: all 300ms cubic-bezier(0.4, 0, 0.2, 1);
  position: relative;
  overflow: hidden;
}

.card::before {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 1px;
  background: linear-gradient(90deg, transparent, rgba(102, 126, 234, 0.3), transparent);
}

.card:hover {
  border-color: var(--color-primary);
  box-shadow: 0 8px 24px rgba(102, 126, 234, 0.12), inset 0 1px 0 rgba(255, 255, 255, 0.05);
  transform: translateY(-2px);
}

.card .label {
  font-size: 0.75rem;
  color: var(--color-muted-foreground);
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  margin-bottom: 0.5rem;
  opacity: 0.9;
}

.card .value {
  font-size: 2rem;
  font-weight: 700;
  font-variant-numeric: tabular-nums;
  background: linear-gradient(135deg, var(--color-accent) 0%, var(--color-accent-soft) 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
}

section {
  margin-bottom: 2.5rem;
  animation: fade-in 0.6s ease-out;
}

.table-wrap {
  overflow-x: auto;
  border: 1px solid var(--color-card-border);
  border-radius: var(--radius-lg);
  background: linear-gradient(135deg, var(--color-card) 0%, oklch(13% 0.025 268) 100%);
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.3);
  transition: all 300ms ease-out;
}

.table-wrap:hover {
  box-shadow: 0 8px 24px rgba(102, 126, 234, 0.15);
}

table {
  width: 100%;
  border-collapse: collapse;
}

caption {
  position: absolute;
  width: 1px;
  height: 1px;
  overflow: hidden;
  clip: rect(0 0 0 0);
  white-space: nowrap;
}

th, td {
  text-align: left;
  padding: 0.875rem 1rem;
  border-bottom: 1px solid var(--color-border);
  white-space: nowrap;
}

th {
  font-size: 0.75rem;
  color: var(--color-muted-foreground);
  font-weight: 700;
  background: linear-gradient(90deg, oklch(16% 0.025 265) 0%, oklch(14% 0.02 268) 100%);
  text-transform: uppercase;
  letter-spacing: 0.05em;
  position: sticky;
  top: 0;
  z-index: 10;
}

tr:last-child td {
  border-bottom: none;
}

tbody tr {
  transition: all 200ms cubic-bezier(0.4, 0, 0.2, 1);
}

tbody tr:hover {
  background: linear-gradient(90deg, oklch(18% 0.03 265) 0%, oklch(16% 0.025 268) 100%);
  box-shadow: inset 1px 0 0 0 rgba(102, 126, 234, 0.2);
}

td {
  font-variant-numeric: tabular-nums;
}

code {
  font: 0.75rem ui-monospace, "Fira Code", monospace;
  background: oklch(10% 0.02 264);
  color: var(--color-accent);
  padding: 0.25rem 0.5rem;
  border-radius: var(--radius-sm);
  border: 1px solid oklch(18% 0.02 265);
}

.badge {
  font-size: 0.65rem;
  font-weight: 700;
  padding: 0.25rem 0.5rem;
  border-radius: var(--radius-md);
  text-transform: uppercase;
  letter-spacing: 0.04em;
  display: inline-block;
  transition: all 200ms ease-out;
}

.badge--low {
  background: color-mix(in oklch, var(--color-muted) 40%, transparent);
  color: var(--color-muted-foreground);
  border: 1px solid color-mix(in oklch, var(--color-muted) 60%, transparent);
}

.badge--medium {
  background: color-mix(in oklch, var(--color-warning-dark) 30%, transparent);
  color: var(--color-warning);
  border: 1px solid color-mix(in oklch, var(--color-warning-dark) 50%, transparent);
}

.badge--high,
.badge--critical {
  background: color-mix(in oklch, var(--color-destructive-dark) 30%, transparent);
  color: var(--color-destructive);
  border: 1px solid color-mix(in oklch, var(--color-destructive-dark) 50%, transparent);
  font-weight: 700;
}

.badge--drop {
  background: linear-gradient(135deg, var(--color-primary) 0%, var(--color-primary-alt) 100%);
  color: var(--color-primary-foreground);
  border: none;
  box-shadow: 0 4px 12px rgba(102, 126, 234, 0.3);
}

.badge--drop:hover {
  box-shadow: 0 6px 16px rgba(102, 126, 234, 0.4);
  transform: scale(1.05);
}

.badge--alert {
  background: color-mix(in oklch, var(--color-warning-dark) 25%, transparent);
  color: var(--color-warning);
  border: 1px solid color-mix(in oklch, var(--color-warning-dark) 45%, transparent);
}

.badge--disabled {
  background: var(--color-muted);
  color: var(--color-muted-foreground);
  opacity: 0.5;
  border: 1px solid var(--color-border);
}

.empty {
  color: var(--color-muted-foreground);
  padding: 2rem 1rem;
  text-align: center;
  font-style: italic;
  opacity: 0.7;
}

footer {
  font-size: 0.75rem;
  color: var(--color-muted-foreground);
  text-align: center;
  padding-top: 2rem;
  border-top: 1px solid var(--color-border);
  opacity: 0.8;
}
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
