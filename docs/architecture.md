# Architecture

## Process model

The system runs as **two independent processes** sharing one SQLite database:

```
┌─────────────────────┐        ┌──────────────────┐
│   run_sniffer.py     │        │  run_dashboard.py  │
│  ┌────────────────┐  │        │  ┌─────────────┐  │
│  │ Scapy capture   │  │        │  │ Flask routes │  │
│  └───────┬────────┘  │        │  └──────┬──────┘  │
│          ▼            │        │         ▼          │
│  ┌────────────────┐  │  reads │  ┌─────────────┐  │
│  │ Detection engine │  │ ◄──────┤  │  Templates   │  │
│  └───────┬────────┘  │        │  └─────────────┘  │
│          ▼            │        │                    │
└──────────┼────────────┘        └────────────────────┘
           │ writes
           ▼
    ┌─────────────┐
    │  nids.db     │  (SQLite, WAL mode)
    │  - TrafficLog│
    │  - Alerts    │
    └─────────────┘
```

**Why two processes instead of one Flask app doing everything:**
Scapy's `sniff()` is a blocking loop. Running it inside a Flask
request/worker thread would either block the web server or require
careful threading that adds complexity without benefit at this scale.
Separating them means each has a single responsibility, and it also
maps cleanly onto how you'd deploy this for real — capture typically
needs root/admin privileges and runs as a system service, while the
dashboard doesn't.

SQLite's WAL (write-ahead log) mode is enabled specifically so the
sniffer can write while the dashboard reads concurrently without lock
contention — see `app/database/db.py`.

## Module responsibilities

| Module | Responsibility | Depends on |
|---|---|---|
| `app/capture/sniffer.py` | Capture packets, extract fields, print + log | `database`, `detection` |
| `app/database/db.py` | Connection handling, schema | — |
| `app/database/models.py` | Insert/query functions | `database/db.py` |
| `app/detection/rules.py` | Individual detection rules | `database/models.py` |
| `app/detection/engine.py` | Runs all rules against each packet | `detection/rules.py` |
| `app/dashboard/routes.py` | Flask routes + JSON API | `database/models.py` |

Each layer only talks to the layer directly below it. The dashboard
never touches Scapy; the detection rules never touch Flask. This
matters for testing (you can unit-test `rules.py` with fabricated
`TrafficLog` rows, no live network needed) and for the Major Project
migration below.

## Detection rules (Phase 3)

| Rule | Type | What it checks |
|---|---|---|
| `check_blacklisted_ip` | Metadata | src/dst IP against a static blacklist |
| `check_port_scan` | Behavioral | distinct dst_ports from one src_ip in a time window |
| `check_icmp_flood` | Behavioral | ICMP packet volume from one src_ip in a time window |
| `check_repeated_connections` | Behavioral | repeated attempts to same dst_ip:dst_port |
| `check_payload_signature` | Signature | raw payload bytes against known-malicious patterns |

Every rule is skipped entirely for source IPs in `WHITELISTED_IPS`
(checked once in `detection/engine.py` before any rule runs, so
trusted hosts cost zero DB round-trips).

The first four are traffic-*pattern* based — they never look at packet
contents, only metadata (IPs, ports, protocol, timing, volume).
`check_payload_signature` is the odd one out: it inspects the raw
application-layer payload (via Scapy's `Raw` layer) against a small,
documented list of known-malicious byte patterns in `config.py`
(`PAYLOAD_SIGNATURES`) — SQLi, XSS, directory traversal, and the EICAR
antivirus test string. This mirrors, at a simple level, what tools like
Snort/Suricata do with their signature rulesets.

Payloads are deliberately **not** written to `TrafficLog` — only the
resulting alert is persisted. Matching happens in-memory, per packet,
in `app/capture/sniffer.py::handle_packet`, which builds a separate
`detection_fields` dict (fields + payload) that's passed to the
detection engine but never to `insert_traffic_log()`. This keeps the
DB schema unchanged and avoids storing potentially sensitive payload
data at rest.

## Alert pipeline: severity, cooldown, notification

Every rule calls `insert_alert()` — the single choke point all alerts
pass through (`app/database/models.py`). Three things happen there,
in order:

1. **Cooldown check** — if an alert of the same `alert_type` from the
   same `source_ip` fired within `ALERT_COOLDOWN_SECONDS` (default 30s),
   the new alert is silently dropped. Without this, a sustained port
   scan or flood would write one row per packet and flood the dashboard.
2. **Insert** — the alert row is written, tagged with a `severity`
   (Low/Medium/High/Critical) assigned per-rule in `config.py`.
3. **Notification** — `app/notifications/notifier.py` fires a console
   banner for any alert at or above `NOTIFY_MIN_SEVERITY` (default
   High). Email is wired up but off by default (`EMAIL_NOTIFICATIONS_ENABLED
   = False`) since it needs real SMTP credentials.

Centralizing this in `insert_alert()` rather than repeating
dedup/notify logic in each rule keeps the rules themselves simple —
they just decide *whether* something is suspicious, not what happens
after.

## Dashboard authentication

Single hardcoded session-based login (`app/dashboard/auth.py`) —
deliberately not a full auth library, since a single-operator academic
demo doesn't need multi-user support, and a plain session flag is
easier to explain in a viva. Change `DASHBOARD_USERNAME` /
`DASHBOARD_PASSWORD` / `FLASK_SECRET_KEY` in `config.py` before
presenting this anywhere semi-public — the shipped defaults are
intentionally obvious placeholders.

## Filtering and export

`/api/alerts` and `/api/traffic` accept query params (`severity`,
`alert_type`, `source_ip` / `protocol`) that map directly to `WHERE`
clauses in `models.py`. The Alert History page's filter bar just
appends these as a querystring on each poll — no separate "search"
endpoint needed.

`/export/alerts.csv` and `/export/alerts.pdf` accept the *same* filter
params, so exporting always matches whatever the person is currently
looking at. PDF generation (`app/dashboard/reports.py`) uses reportlab
and is kept separate from the Flask route so it can be tested or
reused outside the web layer.



1. **ML-based detection** — add `app/detection/ml_engine.py` with a
   `predict(fields) -> (label, confidence)` function trained offline
   on NSL-KDD/CICIDS2017. Call it from `detection/engine.py` alongside
   the existing rules; you decide whether ML results feed the same
   `Alerts` table (add `confidence` and `threat_score` columns) or a
   new `MLPredictions` table.

2. **Prevention engine** — add `app/prevention/` with functions that
   shell out to `iptables` (Linux) or `netsh advfirewall` (Windows) to
   block an IP. Trigger it from `detection/engine.py` when an alert's
   severity crosses a threshold. Keep this behind a config flag
   (`AUTO_BLOCK_ENABLED = False` by default) — you don't want to
   accidentally firewall yourself out during a live demo.

3. **Feature engineering for ML** — flow-level features (duration,
   packet count, avg size) need aggregation across multiple
   `TrafficLog` rows per "connection." This is naturally a new module,
   `app/detection/feature_extraction.py`, that queries `TrafficLog`
   and produces the feature vectors the model expects.

4. **Advanced dashboard** — the existing `/api/stats` endpoint pattern
   extends directly: add `/api/predictions` returning ML output, and a
   new template/JS panel consuming it. No changes needed to the
   existing pages.

## Why rule-based detection queries the DB instead of using in-memory state

Each rule (`check_port_scan`, etc.) queries `TrafficLog` for a rolling
time window rather than keeping counters in memory. This is simpler to
reason about and demo (the DB is the single source of truth, and you
can replay/test detection against historical data), at the cost of a
DB round-trip per packet. At high packet rates this becomes a
bottleneck — worth noting as a limitation in your report, with an
in-memory sliding-window (e.g., a `deque` per source IP, evicting
entries older than the window) as the documented future improvement.
