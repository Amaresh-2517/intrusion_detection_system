"""
Unit tests for the detection engine and rules.

Uses an isolated temp SQLite file per test (via monkeypatching
app.database.db.DB_PATH) so tests never touch data/nids.db and can
run in any order without interfering with each other.

Run with:
    python -m unittest discover tests
"""

import os
import tempfile
import unittest

from app.database import db as db_module
from app.database.models import insert_traffic_log, get_recent_alerts
from app.detection.engine import process_packet_event
import app.config as config


def make_fields(src_ip="10.0.0.1", dst_ip="10.0.0.2", protocol="TCP",
                 src_port=1234, dst_port=80, packet_size=64):
    return {
        "src_ip": src_ip, "dst_ip": dst_ip, "protocol": protocol,
        "src_port": src_port, "dst_port": dst_port, "packet_size": packet_size,
    }


class DetectionRuleTests(unittest.TestCase):

    def setUp(self):
        # Fresh temp DB per test.
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self._tmp_db_path = path
        self._original_db_path = db_module.DB_PATH
        db_module.DB_PATH = path
        db_module.init_db()

        # Reset mutable config state that tests might touch.
        self._original_blacklist = set(config.BLACKLISTED_IPS)
        self._original_whitelist = set(config.WHITELISTED_IPS)
        config.BLACKLISTED_IPS.clear()
        config.WHITELISTED_IPS.clear()

    def tearDown(self):
        db_module.DB_PATH = self._original_db_path
        os.remove(self._tmp_db_path)
        config.BLACKLISTED_IPS.clear()
        config.BLACKLISTED_IPS.update(self._original_blacklist)
        config.WHITELISTED_IPS.clear()
        config.WHITELISTED_IPS.update(self._original_whitelist)

    def _log_and_detect(self, fields):
        insert_traffic_log(**fields)
        return process_packet_event(fields)

    # --- Port scan ---

    def test_port_scan_triggers_at_threshold(self):
        triggered_any = False
        for port in range(2000, 2000 + config.PORT_SCAN_THRESHOLD + 1):
            fields = make_fields(src_ip="10.0.0.50", dst_port=port)
            triggered = self._log_and_detect(fields)
            if "check_port_scan" in triggered:
                triggered_any = True
        self.assertTrue(triggered_any, "Port scan rule should fire once threshold is crossed")

    def test_port_scan_does_not_trigger_below_threshold(self):
        for port in range(2000, 2000 + config.PORT_SCAN_THRESHOLD - 2):
            fields = make_fields(src_ip="10.0.0.51", dst_port=port)
            triggered = self._log_and_detect(fields)
            self.assertNotIn("check_port_scan", triggered)

    # --- ICMP flood ---

    def test_icmp_flood_triggers(self):
        triggered_any = False
        for i in range(config.ICMP_FLOOD_THRESHOLD + 1):
            fields = make_fields(src_ip="10.0.0.60", protocol="ICMP", src_port=None, dst_port=None)
            triggered = self._log_and_detect(fields)
            if "check_icmp_flood" in triggered:
                triggered_any = True
        self.assertTrue(triggered_any)

    def test_icmp_flood_ignores_non_icmp(self):
        fields = make_fields(src_ip="10.0.0.61", protocol="TCP")
        triggered = self._log_and_detect(fields)
        self.assertNotIn("check_icmp_flood", triggered)

    # --- Repeated connections ---

    def test_repeated_connections_triggers(self):
        triggered_any = False
        for i in range(config.REPEATED_CONN_THRESHOLD + 1):
            fields = make_fields(src_ip="10.0.0.70", dst_ip="10.0.0.2", dst_port=443)
            triggered = self._log_and_detect(fields)
            if "check_repeated_connections" in triggered:
                triggered_any = True
        self.assertTrue(triggered_any)

    # --- Blacklisted IP ---

    def test_blacklisted_ip_triggers(self):
        config.BLACKLISTED_IPS.add("6.6.6.6")
        fields = make_fields(src_ip="6.6.6.6")
        triggered = self._log_and_detect(fields)
        self.assertIn("check_blacklisted_ip", triggered)

    def test_non_blacklisted_ip_does_not_trigger(self):
        config.BLACKLISTED_IPS.add("6.6.6.6")
        fields = make_fields(src_ip="1.2.3.4")
        triggered = self._log_and_detect(fields)
        self.assertNotIn("check_blacklisted_ip", triggered)

    # --- Payload signature ---

    def test_signature_match_triggers_on_sqli(self):
        fields = make_fields(src_ip="10.0.0.80")
        insert_traffic_log(**fields)
        triggered = process_packet_event({**fields, "payload": b"admin' OR '1'='1"})
        self.assertIn("check_payload_signature", triggered)

    def test_signature_match_ignores_benign_payload(self):
        fields = make_fields(src_ip="10.0.0.81")
        insert_traffic_log(**fields)
        triggered = process_packet_event({**fields, "payload": b"GET /index.html HTTP/1.1"})
        self.assertNotIn("check_payload_signature", triggered)

    def test_signature_match_handles_missing_payload(self):
        fields = make_fields(src_ip="10.0.0.82")
        insert_traffic_log(**fields)
        triggered = process_packet_event({**fields, "payload": None})
        self.assertNotIn("check_payload_signature", triggered)

    # --- Alert cooldown ---

    def test_cooldown_deduplicates_repeated_alerts(self):
        config.BLACKLISTED_IPS.add("6.6.6.6")
        for i in range(5):
            fields = make_fields(src_ip="6.6.6.6", src_port=i)
            self._log_and_detect(fields)
        alerts = get_recent_alerts(limit=50)
        blacklist_alerts = [a for a in alerts if a["alert_type"] == "Blacklisted IP"]
        self.assertEqual(len(blacklist_alerts), 1,
                          "Cooldown should suppress duplicate alerts within the window")

    # --- Whitelist ---

    def test_whitelist_skips_all_detection(self):
        config.BLACKLISTED_IPS.add("6.6.6.6")
        config.WHITELISTED_IPS.add("6.6.6.6")
        fields = make_fields(src_ip="6.6.6.6")
        triggered = self._log_and_detect(fields)
        self.assertEqual(triggered, [], "Whitelisted source should skip detection entirely")
        alerts = get_recent_alerts(limit=50)
        self.assertEqual(len(alerts), 0)


if __name__ == "__main__":
    unittest.main()
