"""
Detection engine: runs every rule against each new packet event.

This is the single seam you'll extend in the Major Project — add
`from app.detection.ml_engine import predict` and call it alongside
`rule()` below, so rule-based and ML-based detection run side by side
(or the ML score gets attached to the same Alerts row) without
touching the sniffer or the rules themselves.
"""

from app.config import WHITELISTED_IPS
from app.detection.rules import ALL_RULES


def process_packet_event(fields):
    """Run all detection rules against a single packet's extracted fields."""
    if fields.get("src_ip") in WHITELISTED_IPS:
        return []  # trusted host — skip detection entirely, no DB round-trips

    triggered = []
    for rule in ALL_RULES:
        try:
            if rule(fields):
                triggered.append(rule.__name__)
        except Exception as e:
            # A single rule failing shouldn't take down the capture loop.
            print(f"[detection] rule {rule.__name__} raised: {e}")
    return triggered
