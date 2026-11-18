"""
Phase 3: Rule-based intrusion detection.

Each rule function takes the freshly-inserted packet's fields and looks
back at a rolling time window in TrafficLog to decide whether a threshold
was crossed. This "query the DB for recent history" approach is simple
and demo-friendly; if performance becomes an issue at high packet rates,
the natural upgrade is an in-memory sliding-window (e.g. deque per IP)
instead of hitting SQLite on every packet. Worth mentioning as a
"future work" point in your report either way.
"""

from app.config import (
    PORT_SCAN_THRESHOLD, PORT_SCAN_WINDOW_SECONDS,
    ICMP_FLOOD_THRESHOLD, ICMP_FLOOD_WINDOW_SECONDS,
    REPEATED_CONN_THRESHOLD, REPEATED_CONN_WINDOW_SECONDS,
    BLACKLISTED_IPS, PAYLOAD_SIGNATURES,
    SEVERITY_PORT_SCAN, SEVERITY_ICMP_FLOOD,
    SEVERITY_REPEATED_CONN, SEVERITY_BLACKLISTED_IP,
)
from app.database.models import get_traffic_since, insert_alert


def check_port_scan(fields):
    """Flag a source IP contacting many distinct destination ports quickly."""
    src_ip = fields["src_ip"]
    recent = get_traffic_since(PORT_SCAN_WINDOW_SECONDS, src_ip=src_ip)
    distinct_ports = {r["dst_port"] for r in recent if r["dst_port"] is not None}

    if len(distinct_ports) >= PORT_SCAN_THRESHOLD:
        insert_alert(
            alert_type="Port Scan",
            source_ip=src_ip,
            description=(
                f"{src_ip} contacted {len(distinct_ports)} distinct ports "
                f"within {PORT_SCAN_WINDOW_SECONDS}s"
            ),
            severity=SEVERITY_PORT_SCAN,
        )
        return True
    return False


def check_icmp_flood(fields):
    """Flag excessive ICMP traffic from a single source."""
    if fields["protocol"] != "ICMP":
        return False

    src_ip = fields["src_ip"]
    recent = get_traffic_since(ICMP_FLOOD_WINDOW_SECONDS, src_ip=src_ip)
    icmp_count = sum(1 for r in recent if r["protocol"] == "ICMP")

    if icmp_count >= ICMP_FLOOD_THRESHOLD:
        insert_alert(
            alert_type="ICMP Flood",
            source_ip=src_ip,
            description=(
                f"{src_ip} sent {icmp_count} ICMP packets "
                f"within {ICMP_FLOOD_WINDOW_SECONDS}s"
            ),
            severity=SEVERITY_ICMP_FLOOD,
        )
        return True
    return False


def check_repeated_connections(fields):
    """Flag repeated connection attempts to the same destination IP+port."""
    src_ip = fields["src_ip"]
    dst_ip = fields["dst_ip"]
    dst_port = fields["dst_port"]

    recent = get_traffic_since(REPEATED_CONN_WINDOW_SECONDS, src_ip=src_ip)
    matching = [r for r in recent if r["dst_ip"] == dst_ip and r["dst_port"] == dst_port]

    if len(matching) >= REPEATED_CONN_THRESHOLD:
        insert_alert(
            alert_type="Repeated Connection Attempts",
            source_ip=src_ip,
            description=(
                f"{src_ip} made {len(matching)} connection attempts to "
                f"{dst_ip}:{dst_port} within {REPEATED_CONN_WINDOW_SECONDS}s"
            ),
            severity=SEVERITY_REPEATED_CONN,
        )
        return True
    return False


def check_blacklisted_ip(fields):
    """Flag traffic to/from a known-malicious IP."""
    src_ip = fields["src_ip"]
    dst_ip = fields["dst_ip"]

    for ip in (src_ip, dst_ip):
        if ip in BLACKLISTED_IPS:
            insert_alert(
                alert_type="Blacklisted IP",
                source_ip=ip,
                description=f"Traffic involving blacklisted IP {ip}",
                severity=SEVERITY_BLACKLISTED_IP,
            )
            return True
    return False


def check_payload_signature(fields):
    """
    Signature-based detection: scan the raw payload for known-malicious
    byte patterns (see PAYLOAD_SIGNATURES in config.py). This is the
    classic "known attack" complement to the behavioral rules above —
    those catch patterns of traffic, this catches content of traffic.
    """
    payload = fields.get("payload")
    if not payload:
        return False

    payload_lower = payload.lower()
    for sig_name, pattern, severity in PAYLOAD_SIGNATURES:
        if pattern.lower() in payload_lower:
            insert_alert(
                alert_type="Signature Match",
                source_ip=fields["src_ip"],
                description=(
                    f"Payload from {fields['src_ip']} matched signature "
                    f"'{sig_name}'"
                ),
                severity=severity,
            )
            return True
    return False


# Order matters only for readability/debugging here — each rule is independent.
ALL_RULES = [
    check_blacklisted_ip,
    check_port_scan,
    check_icmp_flood,
    check_repeated_connections,
    check_payload_signature,
]
