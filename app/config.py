"""
Central configuration for the NIDS project.
Keeping thresholds here (instead of hardcoding in detection/rules.py)
means you can tune sensitivity without touching detection logic —
and in the Major Project, these become your baseline before the
ML model takes over anomaly detection.
"""

import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "data", "nids.db")

# --- Capture settings ---
NETWORK_INTERFACE = None  # None = Scapy auto-selects default interface
CAPTURE_FILTER = None     # e.g. "ip" to restrict to IP traffic only

# --- Detection thresholds ---
PORT_SCAN_THRESHOLD = 15          # distinct ports contacted...
PORT_SCAN_WINDOW_SECONDS = 10      # ...within this many seconds

ICMP_FLOOD_THRESHOLD = 50          # ICMP packets...
ICMP_FLOOD_WINDOW_SECONDS = 10     # ...within this many seconds

REPEATED_CONN_THRESHOLD = 20       # connection attempts to same dst_ip/port...
REPEATED_CONN_WINDOW_SECONDS = 15  # ...within this many seconds

BLACKLISTED_IPS = set()
# Populate with known-malicious IPs for testing/demo purposes, e.g.:
#   BLACKLISTED_IPS = {"203.0.113.66", "198.51.100.23"}
# In the Major Project this can be swapped for a live threat-intel feed.

# --- Payload signature detection ---
# Each entry: (signature_name, byte_pattern, severity). Matching is a simple
# case-insensitive substring search against the packet's raw payload —
# this is intentionally the same technique real signature-based engines
# (Snort/Suricata) use at their simplest level, before you get into
# regex/PCRE rules. Kept small and clearly documented since this is a
# teaching project, not a production ruleset — extend cautiously and
# only with well-known, publicly documented patterns.
PAYLOAD_SIGNATURES = [
    ("SQL Injection Attempt", b"' or '1'='1", "High"),
    ("SQL Injection Attempt", b"union select", "High"),
    ("XSS Attempt", b"<script>", "High"),
    ("Command Injection Attempt", b"; cat /etc/passwd", "Critical"),
    ("Directory Traversal Attempt", b"../../../../", "Medium"),
    ("EICAR Test String", b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR", "Critical"),
]

# --- Alert deduplication ---
# Suppress repeated alerts of the same type from the same source within
# this window, so a sustained attack (e.g. a port scan that keeps
# re-triggering every packet) produces one alert, not hundreds.
ALERT_COOLDOWN_SECONDS = 30

# --- Whitelisted IPs ---
# Traffic from these IPs skips all detection rules entirely — use for
# your own gateway/router or trusted hosts to cut noise while testing.
WHITELISTED_IPS = set()
# e.g. WHITELISTED_IPS = {"192.168.1.1"}

# --- Alert severity for behavioral/metadata rules ---
# Centralized here (rather than hardcoded per rule) for the same reason
# thresholds are centralized above — one place to tune without touching
# detection logic.
SEVERITY_PORT_SCAN = "Medium"
SEVERITY_ICMP_FLOOD = "Medium"
SEVERITY_REPEATED_CONN = "Low"
SEVERITY_BLACKLISTED_IP = "Critical"

# --- Notifications ---
# Console banner always fires for High/Critical alerts. Email is opt-in
# and off by default since it needs real SMTP credentials to work —
# flip ENABLED to True and fill in the settings below to use it.
NOTIFY_MIN_SEVERITY = "High"  # one of: Low, Medium, High, Critical
EMAIL_NOTIFICATIONS_ENABLED = False
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USERNAME = ""
SMTP_PASSWORD = ""
ALERT_EMAIL_FROM = ""
ALERT_EMAIL_TO = ""

# --- Dashboard auth ---
# Single hardcoded account, sufficient for an academic demo. Change the
# password before presenting this anywhere semi-public. Session secret
# should be a long random string in any real deployment.
DASHBOARD_USERNAME = "admin"
DASHBOARD_PASSWORD = "changeme123"
FLASK_SECRET_KEY = "dev-secret-key-change-in-production"

# --- Dashboard settings ---
DASHBOARD_HOST = "127.0.0.1"
DASHBOARD_PORT = 5000
DASHBOARD_REFRESH_MS = 5000  # auto-refresh interval on Live Traffic page
