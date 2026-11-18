"""
Phase 4: Flask dashboard.

Read-only against SQLite — the dashboard never writes traffic/alert
data itself, only reads what the sniffer process has logged. JSON API
endpoints back the auto-refreshing frontend (polling, not websockets,
for simplicity — swap in Flask-SocketIO later if you want push updates).

Every page and API route except /login is behind login_required.
"""

import csv
import io
from datetime import datetime

from flask import Blueprint, render_template, jsonify, request, session, redirect, url_for, Response, send_file

from app.database.models import get_recent_traffic, get_recent_alerts, get_stats, get_capture_health
from app.config import DASHBOARD_REFRESH_MS
from app.dashboard.auth import (
    check_credentials, clear_failed_logins, csrf_token, is_safe_redirect,
    login_is_rate_limited, login_required, record_failed_login,
    valid_csrf_token,
)

bp = Blueprint("dashboard", __name__, template_folder="templates", static_folder="static")


# --- Auth ---

@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if not valid_csrf_token(request.form.get("csrf_token")):
            return render_template("login.html", error="Your session expired. Please try again.", csrf_token=csrf_token()), 400

        remote_addr = request.remote_addr or "unknown"
        if login_is_rate_limited(remote_addr):
            return render_template("login.html", error="Too many failed sign-in attempts. Please try again later.", csrf_token=csrf_token()), 429

        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if check_credentials(username, password):
            clear_failed_logins(remote_addr)
            session["logged_in"] = True
            requested_next = request.args.get("next", "")
            next_url = requested_next if is_safe_redirect(requested_next) else url_for("dashboard.live_traffic")
            return redirect(next_url)
        record_failed_login(remote_addr)
        return render_template("login.html", error="Invalid username or password.", csrf_token=csrf_token())
    return render_template("login.html", error=None, csrf_token=csrf_token())


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    if not valid_csrf_token(request.form.get("csrf_token")):
        return "Invalid request.", 400
    session.clear()
    return redirect(url_for("dashboard.login"))


# --- Pages ---

@bp.route("/")
@login_required
def live_traffic():
    return render_template("live_traffic.html", refresh_ms=DASHBOARD_REFRESH_MS)


@bp.route("/alerts")
@login_required
def alert_history():
    return render_template("alerts.html", refresh_ms=DASHBOARD_REFRESH_MS)


@bp.route("/statistics")
@login_required
def statistics():
    return render_template("statistics.html")


# --- JSON API used by the frontend JS ---
# Query params for filtering: /api/traffic?protocol=TCP&src_ip=10.0.0
#                              /api/alerts?severity=High&alert_type=Port+Scan&source_ip=10.0.0

@bp.route("/api/traffic")
@login_required
def api_traffic():
    protocol = request.args.get("protocol") or None
    src_ip = request.args.get("src_ip") or None
    return jsonify(get_recent_traffic(limit=100, protocol=protocol, src_ip=src_ip))


@bp.route("/api/alerts")
@login_required
def api_alerts():
    severity = request.args.get("severity") or None
    alert_type = request.args.get("alert_type") or None
    source_ip = request.args.get("source_ip") or None
    return jsonify(get_recent_alerts(
        limit=100, severity=severity, alert_type=alert_type, source_ip=source_ip
    ))


@bp.route("/api/stats")
@login_required
def api_stats():
    return jsonify(get_stats())


@bp.route("/api/health")
@login_required
def api_health():
    """Expose recent capture activity instead of claiming the engine is always active."""
    return jsonify(get_capture_health())


# --- Export ---
# Export honors the same filter params as /api/alerts so "export what
# I'm currently looking at" works without a separate export UI.

@bp.route("/export/alerts.csv")
@login_required
def export_alerts_csv():
    severity = request.args.get("severity") or None
    alert_type = request.args.get("alert_type") or None
    source_ip = request.args.get("source_ip") or None
    rows = get_recent_alerts(
        limit=1000, severity=severity, alert_type=alert_type, source_ip=source_ip
    )

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=["id", "timestamp", "severity", "alert_type", "source_ip", "description"])
    writer.writeheader()
    for r in rows:
        writer.writerow(r)

    filename = f"nids_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@bp.route("/export/alerts.pdf")
@login_required
def export_alerts_pdf():
    from app.dashboard.reports import build_alert_report_pdf

    severity = request.args.get("severity") or None
    alert_type = request.args.get("alert_type") or None
    source_ip = request.args.get("source_ip") or None
    rows = get_recent_alerts(
        limit=1000, severity=severity, alert_type=alert_type, source_ip=source_ip
    )

    pdf_buffer = build_alert_report_pdf(rows, filters={
        "severity": severity, "alert_type": alert_type, "source_ip": source_ip,
    })
    filename = f"nids_alert_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    return send_file(
        pdf_buffer, mimetype="application/pdf",
        as_attachment=True, download_name=filename,
    )
