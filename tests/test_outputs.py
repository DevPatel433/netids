import json
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from netids.alerts import JsonAlertWriter
from netids.detector import Alert
from netids.metrics import Metrics, start_server


def sample_alert():
    return Alert(kind="port_scan", src="203.0.113.7",
                 detail="20 distinct ports in 60s", timestamp=1700000000.0)


class JsonAlertTests(unittest.TestCase):
    def test_writes_one_json_object_per_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nested" / "alerts.json"
            writer = JsonAlertWriter(str(path), sensor="sensor-1")
            writer.write(sample_alert(), "blocked")
            writer.write(sample_alert(), "dry_run")

            lines = path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 2)
            record = json.loads(lines[0])
            self.assertEqual(record["event"], "alert")
            self.assertEqual(record["kind"], "port_scan")
            self.assertEqual(record["src"], "203.0.113.7")
            self.assertEqual(record["action"], "blocked")
            self.assertEqual(record["sensor"], "sensor-1")
            self.assertTrue(record["timestamp"].startswith("2023-11-14T"))

    def test_disabled_writer_returns_record_without_file(self):
        writer = JsonAlertWriter("", sensor="s")
        record = writer.write(sample_alert(), "dry_run")
        self.assertEqual(record["action"], "dry_run")
        self.assertIsNone(writer.path)


class MetricsTests(unittest.TestCase):
    def test_render_contains_counters(self):
        m = Metrics()
        m.record_syn()
        m.record_syn()
        m.record_ack()
        m.record_alert("port_scan")
        m.record_alert("port_scan")
        m.record_alert("syn_flood")
        m.record_block()
        text = m.render()
        self.assertIn("netids_syn_packets_total 2", text)
        self.assertIn("netids_ack_packets_total 1", text)
        self.assertIn('netids_alerts_total{kind="port_scan"} 2', text)
        self.assertIn('netids_alerts_total{kind="syn_flood"} 1', text)
        self.assertIn("netids_blocks_total 1", text)
        self.assertIn("# TYPE netids_alerts_total counter", text)

    def test_http_endpoint_serves_metrics_and_404s_elsewhere(self):
        m = Metrics()
        m.record_syn()
        server = start_server(m, "127.0.0.1:0")  # port 0 = any free port
        try:
            port = server.server_address[1]
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=5) as resp:
                self.assertEqual(resp.status, 200)
                self.assertIn("netids_syn_packets_total 1", resp.read().decode())

            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/secret", timeout=5)
            self.assertEqual(ctx.exception.code, 404)
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
