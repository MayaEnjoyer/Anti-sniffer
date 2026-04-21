import unittest

from anti_sniffer.capture import synthetic_outbound_sweep, synthetic_port_scan, synthetic_syn_flood
from anti_sniffer.config import AppConfig, ThresholdConfig
from anti_sniffer.engine import DetectionEngine
from anti_sniffer.models import PacketEvent


class DetectionRuleTests(unittest.TestCase):
    def test_inbound_port_scan_is_detected(self) -> None:
        config = AppConfig(
            thresholds=ThresholdConfig(
                window_seconds=10,
                port_scan_distinct_ports=5,
                port_scan_min_packets=5,
            )
        )
        engine = DetectionEngine(config)

        alerts = []
        for event in synthetic_port_scan(count=6, start_time=1000.0):
            alerts.extend(engine.inspect(event))

        self.assertEqual(1, len(alerts))
        self.assertEqual("inbound_port_scan", alerts[0].rule_id)
        self.assertEqual("high", alerts[0].severity)
        self.assertEqual(5, alerts[0].evidence["distinct_ports"])

    def test_port_scan_cooldown_suppresses_duplicate_alerts(self) -> None:
        config = AppConfig(
            thresholds=ThresholdConfig(
                window_seconds=10,
                cooldown_seconds=30,
                port_scan_distinct_ports=3,
                port_scan_min_packets=3,
            )
        )
        engine = DetectionEngine(config)

        alerts = []
        for event in synthetic_port_scan(count=8, start_time=2000.0):
            alerts.extend(engine.inspect(event))

        self.assertEqual(1, len(alerts))

    def test_syn_flood_is_detected(self) -> None:
        config = AppConfig(thresholds=ThresholdConfig(window_seconds=10, syn_flood_packets=10))
        engine = DetectionEngine(config)

        alerts = []
        for event in synthetic_syn_flood(count=12, start_time=3000.0):
            alerts.extend(engine.inspect(event))

        self.assertEqual(1, len(alerts))
        self.assertEqual("inbound_syn_flood", alerts[0].rule_id)
        self.assertEqual(445, alerts[0].evidence["target_port"])

    def test_icmp_probe_is_detected(self) -> None:
        config = AppConfig(thresholds=ThresholdConfig(window_seconds=10, icmp_probe_packets=4))
        engine = DetectionEngine(config)

        alerts = []
        for index in range(4):
            event = PacketEvent(
                timestamp=4000.0 + index,
                direction="inbound",
                src_ip="203.0.113.44",
                dst_ip="192.168.1.50",
                protocol="ICMP",
                icmp_type=8,
            )
            alerts.extend(engine.inspect(event))

        self.assertEqual(1, len(alerts))
        self.assertEqual("icmp_probe", alerts[0].rule_id)

    def test_outbound_sweep_is_detected(self) -> None:
        config = AppConfig(
            thresholds=ThresholdConfig(
                window_seconds=10,
                outbound_unique_hosts=4,
                outbound_unique_ports=4,
            )
        )
        engine = DetectionEngine(config)

        alerts = []
        for event in synthetic_outbound_sweep(count=5, start_time=5000.0):
            alerts.extend(engine.inspect(event))

        self.assertEqual(1, len(alerts))
        self.assertEqual("outbound_sweep", alerts[0].rule_id)
        self.assertEqual("high", alerts[0].severity)

    def test_trusted_source_is_suppressed(self) -> None:
        config = AppConfig(
            thresholds=ThresholdConfig(
                window_seconds=10,
                port_scan_distinct_ports=3,
                port_scan_min_packets=3,
            )
        )
        config.runtime.trusted_cidrs.append("203.0.113.0/24")
        engine = DetectionEngine(config)

        alerts = []
        for event in synthetic_port_scan(source_ip="203.0.113.10", count=5, start_time=6000.0):
            alerts.extend(engine.inspect(event))

        self.assertEqual([], alerts)


if __name__ == "__main__":
    unittest.main()
