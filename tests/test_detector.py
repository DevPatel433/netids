import unittest

from netids.detector import AckEvent, Detector, SynEvent

TARGET = "10.0.0.100"


def syn(src, port, t, dst=TARGET):
    return SynEvent(src=src, dst=dst, dst_port=port, timestamp=t)


def ack(src, port, t, dst=TARGET):
    return AckEvent(src=src, dst=dst, dst_port=port, timestamp=t)


class PortScanTests(unittest.TestCase):
    def test_alerts_at_threshold(self):
        d = Detector(port_scan_unique_ports=20)
        alerts = []
        for port in range(1, 20):
            alerts += d.observe(syn("10.0.0.5", port, port * 0.01))
        self.assertEqual(alerts, [])

        alerts = d.observe(syn("10.0.0.5", 20, 0.5))
        self.assertEqual([a.kind for a in alerts], ["port_scan"])
        self.assertEqual(alerts[0].src, "10.0.0.5")
        self.assertTrue(alerts[0].blockable)

    def test_repeated_hits_on_one_port_are_not_a_scan(self):
        d = Detector(port_scan_unique_ports=5, brute_force_attempts=1000)
        alerts = []
        for i in range(100):
            alerts += d.observe(syn("10.0.0.6", 8080, i * 0.1))
        self.assertEqual(alerts, [])

    def test_slow_scan_outside_window_is_ignored(self):
        d = Detector(window_seconds=60, port_scan_unique_ports=20)
        alerts = []
        for port in range(1, 31):
            alerts += d.observe(syn("10.0.0.7", port, port * 10.0))
        self.assertEqual(alerts, [])


class BruteForceTests(unittest.TestCase):
    def test_brute_force_on_watched_port(self):
        d = Detector(brute_force_attempts=10, watched_ports=[22])
        alerts = []
        for i in range(10):
            alerts += d.observe(syn("192.168.1.9", 22, i * 0.5))
        self.assertEqual([a.kind for a in alerts], ["brute_force"])
        self.assertIn("port 22", alerts[0].detail)

    def test_unwatched_port_does_not_trigger_brute_force(self):
        d = Detector(brute_force_attempts=10, watched_ports=[22])
        alerts = []
        for i in range(50):
            alerts += d.observe(syn("192.168.1.10", 8080, i * 0.1))
        self.assertEqual(alerts, [])


class FloodTests(unittest.TestCase):
    def test_spoofed_syn_flood_is_detected_and_not_blockable(self):
        d = Detector(flood_min_syns=50, flood_max_ack_ratio=0.1)
        alerts = []
        for i in range(50):
            alerts += d.observe(syn(f"198.51.100.{i}", 80, i * 0.01))
        floods = [a for a in alerts if a.kind == "syn_flood"]
        self.assertEqual(len(floods), 1)
        self.assertFalse(floods[0].blockable)
        self.assertEqual(floods[0].src, TARGET)
        self.assertIn("ACK ratio 0.00", floods[0].detail)

    def test_busy_healthy_service_is_not_a_flood(self):
        d = Detector(flood_min_syns=50, flood_max_ack_ratio=0.1)
        alerts = []
        for i in range(60):
            src = f"203.0.113.{i}"
            t = i * 0.01
            alerts += d.observe(syn(src, 443, t))
            d.observe_ack(ack(src, 443, t + 0.001))
        self.assertEqual([a for a in alerts if a.kind == "syn_flood"], [])

    def test_flood_below_minimum_volume_is_ignored(self):
        d = Detector(flood_min_syns=50)
        alerts = []
        for i in range(10):
            alerts += d.observe(syn(f"198.51.100.{i}", 80, i * 0.01))
        self.assertEqual(alerts, [])

    def test_flood_outside_window_does_not_accumulate(self):
        d = Detector(window_seconds=10, flood_min_syns=50)
        alerts = []
        for i in range(60):
            alerts += d.observe(syn(f"198.51.100.{i}", 80, i * 1.0))  # 1 per second
        self.assertEqual([a for a in alerts if a.kind == "syn_flood"], [])


class CooldownTests(unittest.TestCase):
    def test_cooldown_suppresses_repeat_alerts(self):
        d = Detector(port_scan_unique_ports=5, cooldown_seconds=300)
        first = []
        for port in range(1, 6):
            first += d.observe(syn("10.1.1.1", port, 0.0))
        self.assertEqual(len(first), 1)

        during = []
        for port in range(6, 20):
            during += d.observe(syn("10.1.1.1", port, 10.0))
        self.assertEqual(during, [])

        after = []
        for i, port in enumerate(range(100, 106)):
            after += d.observe(syn("10.1.1.1", port, 400.0 + i * 0.1))
        self.assertEqual([a.kind for a in after], ["port_scan"])


class AllowlistTests(unittest.TestCase):
    def test_whitelisted_source_never_alerts(self):
        d = Detector(port_scan_unique_ports=5, whitelist=["10.9.9.9"])
        alerts = []
        for port in range(1, 100):
            alerts += d.observe(syn("10.9.9.9", port, 0.0))
        self.assertEqual(alerts, [])

    def test_cidr_whitelist_covers_the_range(self):
        d = Detector(port_scan_unique_ports=5, whitelist=["10.9.0.0/16"])
        alerts = []
        for port in range(1, 50):
            alerts += d.observe(syn("10.9.200.4", port, 0.0))
        self.assertEqual(alerts, [])

    def test_whitelist_does_not_affect_other_sources(self):
        d = Detector(port_scan_unique_ports=5, whitelist=["10.9.9.9"])
        alerts = []
        for port in range(1, 6):
            alerts += d.observe(syn("10.8.8.8", port, 0.0))
        self.assertEqual([a.src for a in alerts], ["10.8.8.8"])


class PruneTests(unittest.TestCase):
    def test_prune_drops_idle_sources_and_targets(self):
        d = Detector(window_seconds=60, cooldown_seconds=60)
        d.observe(syn("10.2.2.2", 80, 0.0))
        d.observe_ack(ack("10.2.2.2", 80, 0.0))
        d.prune(now=1000.0)
        self.assertEqual(dict(d._history), {})
        self.assertEqual(dict(d._syn_targets), {})
        self.assertEqual(dict(d._ack_targets), {})
        self.assertEqual(d._last_alert, {})


class ValidationTests(unittest.TestCase):
    def test_rejects_bad_window(self):
        with self.assertRaises(ValueError):
            Detector(window_seconds=0)

    def test_rejects_out_of_range_flood_ratio(self):
        with self.assertRaises(ValueError):
            Detector(flood_max_ack_ratio=1.5)
        with self.assertRaises(ValueError):
            Detector(flood_max_ack_ratio=0)


if __name__ == "__main__":
    unittest.main()
