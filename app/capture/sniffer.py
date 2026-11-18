"""
Phase 1: Packet capture using Scapy.

Captures live packets, extracts the fields required by the TrafficLog
schema, prints a live console view, and logs each packet to the DB.
Each logged packet is then handed to the detection engine (Phase 3)
so alerts fire in the same pass instead of requiring a second scan.
"""

from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

from app.config import NETWORK_INTERFACE, CAPTURE_FILTER
from app.database.models import insert_traffic_log
from app.detection.engine import process_packet_event


def _extract_fields(packet):
    """Pull the fields we care about out of a Scapy packet, or None if not IP."""
    if not packet.haslayer(IP):
        return None

    ip_layer = packet[IP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    packet_size = len(packet)

    src_port = dst_port = None
    protocol = "OTHER"

    if packet.haslayer(TCP):
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    elif packet.haslayer(ICMP):
        protocol = "ICMP"

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "src_port": src_port,
        "dst_port": dst_port,
        "packet_size": packet_size,
    }


def _extract_payload(packet):
    """
    Raw application-layer bytes, if present. Kept separate from the fields
    dict that goes into TrafficLog — we deliberately don't persist raw
    payloads to the DB (storage bloat, and payloads can contain sensitive
    data). Signature matching happens in-memory, per packet, and only the
    resulting alert (not the payload itself) gets written to the DB.
    """
    if packet.haslayer(Raw):
        try:
            return bytes(packet[Raw].load)
        except Exception:
            return None
    return None


def handle_packet(packet):
    fields = _extract_fields(packet)
    if fields is None:
        return  # skip non-IP traffic (ARP, etc.) for now

    timestamp = datetime.now().strftime("%H:%M:%S")
    print(
        f"[{timestamp}] {fields['protocol']:5s} "
        f"{fields['src_ip']}:{fields['src_port']} -> "
        f"{fields['dst_ip']}:{fields['dst_port']} "
        f"({fields['packet_size']} bytes)"
    )

    insert_traffic_log(**fields)

    # Payload is added only for the in-memory detection pass, never for the DB insert above.
    detection_fields = {**fields, "payload": _extract_payload(packet)}

    # Feed the event into the detection engine immediately —
    # rules like port-scan detection need to see traffic as it arrives.
    process_packet_event(detection_fields)


def start_sniffer():
    print("Starting packet capture... (Ctrl+C to stop)")
    print(f"Interface: {NETWORK_INTERFACE or 'default'} | Filter: {CAPTURE_FILTER or 'none'}\n")
    sniff(
        iface=NETWORK_INTERFACE,
        filter=CAPTURE_FILTER,
        prn=handle_packet,
        store=False,
    )


if __name__ == "__main__":
    start_sniffer()
