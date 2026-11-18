"""
Data-access functions for TrafficLog and Alerts.

Kept as plain functions (not an ORM) intentionally — for an academic
project, raw SQL here is easier to explain in your report/viva than
an ORM abstraction layer, and it's fast enough at this scale.
"""

from app.database.db import get_connection
from app.config import ALERT_COOLDOWN_SECONDS, CAPTURE_HEALTH_STALE_SECONDS
from app.notifications.notifier import notify


def insert_traffic_log(src_ip, dst_ip, protocol, src_port, dst_port, packet_size):
    with get_connection() as conn:
        cur = conn.execute(
            """INSERT INTO TrafficLog (src_ip, dst_ip, protocol, src_port, dst_port, packet_size)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (src_ip, dst_ip, protocol, src_port, dst_port, packet_size),
        )
        return cur.lastrowid


def insert_alert(alert_type, source_ip, description, severity="Medium"):
    """
    Insert an alert, unless an alert of the same type from the same
    source fired within ALERT_COOLDOWN_SECONDS — this is the single
    choke point every detection rule goes through, so deduplication
    and notification live here rather than being repeated in each rule.

    Returns the new row id, or None if suppressed by the cooldown.
    """
    with get_connection() as conn:
        recent_duplicate = conn.execute(
            """SELECT id FROM Alerts
               WHERE alert_type = ? AND source_ip = ?
                 AND timestamp >= datetime('now', ?)
               LIMIT 1""",
            (alert_type, source_ip, f"-{ALERT_COOLDOWN_SECONDS} seconds"),
        ).fetchone()
        if recent_duplicate:
            return None

        cur = conn.execute(
            """INSERT INTO Alerts (alert_type, source_ip, description, severity)
               VALUES (?, ?, ?, ?)""",
            (alert_type, source_ip, description, severity),
        )
        new_id = cur.lastrowid

    notify(alert_type, source_ip, description, severity)
    return new_id


def get_recent_traffic(limit=100, protocol=None, src_ip=None):
    with get_connection() as conn:
        query = "SELECT * FROM TrafficLog WHERE 1=1"
        params = []
        if protocol:
            query += " AND protocol = ?"
            params.append(protocol)
        if src_ip:
            query += " AND src_ip LIKE ?"
            params.append(f"%{src_ip}%")
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]


def get_recent_alerts(limit=100, severity=None, alert_type=None, source_ip=None):
    with get_connection() as conn:
        query = "SELECT * FROM Alerts WHERE 1=1"
        params = []
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if alert_type:
            query += " AND alert_type = ?"
            params.append(alert_type)
        if source_ip:
            query += " AND source_ip LIKE ?"
            params.append(f"%{source_ip}%")
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]


def get_traffic_since(seconds, src_ip=None):
    """Used by detection rules to look back at a rolling time window."""
    with get_connection() as conn:
        if src_ip:
            rows = conn.execute(
                """SELECT * FROM TrafficLog
                   WHERE timestamp >= datetime('now', ?) AND src_ip = ?
                   ORDER BY id DESC""",
                (f"-{seconds} seconds", src_ip),
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT * FROM TrafficLog
                   WHERE timestamp >= datetime('now', ?)
                   ORDER BY id DESC""",
                (f"-{seconds} seconds",),
            ).fetchall()
        return [dict(r) for r in rows]


def get_stats():
    """Aggregate stats for the dashboard Statistics page."""
    with get_connection() as conn:
        total_packets = conn.execute("SELECT COUNT(*) FROM TrafficLog").fetchone()[0]
        total_alerts = conn.execute("SELECT COUNT(*) FROM Alerts").fetchone()[0]

        top_sources = conn.execute(
            """SELECT src_ip, COUNT(*) as count FROM TrafficLog
               GROUP BY src_ip ORDER BY count DESC LIMIT 10"""
        ).fetchall()

        protocol_dist = conn.execute(
            """SELECT protocol, COUNT(*) as count FROM TrafficLog
               GROUP BY protocol ORDER BY count DESC"""
        ).fetchall()

        attack_counts = conn.execute(
            """SELECT alert_type, COUNT(*) as count FROM Alerts
               GROUP BY alert_type ORDER BY count DESC"""
        ).fetchall()

        severity_counts = conn.execute(
            """SELECT severity, COUNT(*) as count FROM Alerts
               GROUP BY severity ORDER BY
                 CASE severity
                   WHEN 'Critical' THEN 0
                   WHEN 'High' THEN 1
                   WHEN 'Medium' THEN 2
                   WHEN 'Low' THEN 3
                   ELSE 4
                 END"""
        ).fetchall()

        return {
            "total_packets": total_packets,
            "total_alerts": total_alerts,
            "top_sources": [dict(r) for r in top_sources],
            "protocol_distribution": [dict(r) for r in protocol_dist],
            "attack_counts": [dict(r) for r in attack_counts],
            "severity_counts": [dict(r) for r in severity_counts],
        }


def get_capture_health():
    """Return a lightweight, DB-backed indication of whether packets are arriving."""
    with get_connection() as conn:
        row = conn.execute(
            """SELECT MAX(timestamp) AS last_packet_timestamp,
                      COUNT(*) AS total_packets,
                      CAST(strftime('%s', 'now') - strftime('%s', MAX(timestamp)) AS INTEGER)
                        AS seconds_since_last_packet
               FROM TrafficLog"""
        ).fetchone()
        health = dict(row)

    age = health["seconds_since_last_packet"]
    if health["total_packets"] == 0:
        status = "waiting"
    elif age is not None and age <= CAPTURE_HEALTH_STALE_SECONDS:
        status = "active"
    else:
        status = "stale"
    return {**health, "status": status}
