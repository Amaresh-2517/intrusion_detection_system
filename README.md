# NIDS — Network Intrusion Detection System (Minor Project)

Rule-based Network Intrusion Detection System built with Python, Scapy,
SQLite, and Flask. This is the foundational codebase for a later
AI-Based Intrusion Detection and Prevention System (Major Project) —
see `docs/architecture.md` for how the two connect.

## Features

- Live packet capture (Scapy): source/dest IP, ports, protocol, size, timestamp
- SQLite traffic logging (`TrafficLog`, `Alerts` tables)
- Rule-based detection: port scans, ICMP floods, repeated connection attempts,
  blacklisted IPs, and payload signature matching (SQLi/XSS/traversal/EICAR)
- Severity levels (Low/Medium/High/Critical) on every alert
- Alert deduplication (cooldown window) and console/email notifications
  for High+ severity alerts
- Whitelisting to skip detection for trusted IPs
- Flask dashboard: Live Traffic, Alert History, Statistics — with filtering
  and CSV/PDF export
- Session-based dashboard login

## Setup

```bash
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Running

Two processes, run in separate terminals:

```bash
# Terminal 1 — packet capture + detection (needs elevated privileges)
sudo python run_sniffer.py

# Terminal 2 — dashboard
python run_dashboard.py
```

Then open http://127.0.0.1:5000 and sign in with the credentials in
`app/config.py` (`DASHBOARD_USERNAME` / `DASHBOARD_PASSWORD` — change
these before showing this to anyone else).

## Testing

```bash
python -m unittest discover tests -v
```

## Project structure

See `docs/architecture.md` for the full breakdown and the rationale
behind the module boundaries (in particular, why capture/detection and
the dashboard are separate processes sharing one SQLite DB).

## Roadmap

- [x] Phase 1: Packet sniffer
- [x] Phase 2: SQLite logging
- [x] Phase 3: Rule-based detection engine (incl. payload signatures)
- [x] Phase 4: Flask dashboard (auth, filtering, export)
- [x] Severity levels, alert cooldown, notifications, whitelisting
- [x] Unit tests
- [ ] Major Project: ML-based anomaly detection, prevention engine (iptables/firewall), advanced dashboard
# intrusion_detection_system
