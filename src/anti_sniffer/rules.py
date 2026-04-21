from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Iterable, Protocol

from .config import ThresholdConfig
from .models import Alert, PacketEvent


class Rule(Protocol):
    rule_id: str

    def evaluate(self, event: PacketEvent) -> Alert | None:
        ...


@dataclass(slots=True)
class _RuleState:
    cooldown_seconds: float
    _last_alert: dict[str, float] = field(default_factory=dict)

    def can_emit(self, fingerprint: str, timestamp: float) -> bool:
        previous = self._last_alert.get(fingerprint)
        if previous is not None and timestamp - previous < self.cooldown_seconds:
            return False
        self._last_alert[fingerprint] = timestamp
        return True


class SlidingWindowRule:
    rule_id = "base"

    def __init__(self, thresholds: ThresholdConfig) -> None:
        self.thresholds = thresholds
        self.state = _RuleState(thresholds.cooldown_seconds)

    @staticmethod
    def _trim(events: Deque[PacketEvent], now: float, window_seconds: float) -> None:
        cutoff = now - window_seconds
        while events and events[0].timestamp < cutoff:
            events.popleft()

    def _emit_once(self, alert: Alert) -> Alert | None:
        if self.state.can_emit(alert.fingerprint(), alert.timestamp):
            return alert
        return None


class InboundPortScanRule(SlidingWindowRule):
    rule_id = "inbound_port_scan"

    def __init__(self, thresholds: ThresholdConfig) -> None:
        super().__init__(thresholds)
        self._events_by_source: dict[str, Deque[PacketEvent]] = defaultdict(deque)

    def evaluate(self, event: PacketEvent) -> Alert | None:
        if not event.is_inbound or event.protocol not in {"TCP", "UDP"} or event.dst_port is None:
            return None

        events = self._events_by_source[event.src_ip]
        events.append(event)
        self._trim(events, event.timestamp, self.thresholds.window_seconds)

        ports = {item.dst_port for item in events if item.dst_port is not None}
        syn_count = sum(1 for item in events if item.is_tcp_syn_probe)
        if (
            len(ports) < self.thresholds.port_scan_distinct_ports
            or len(events) < self.thresholds.port_scan_min_packets
        ):
            return None

        severity = "critical" if len(ports) >= self.thresholds.port_scan_distinct_ports * 2 else "high"
        alert = Alert(
            timestamp=event.timestamp,
            severity=severity,
            rule_id=self.rule_id,
            title="Inbound port scan detected",
            description=(
                f"{event.src_ip} touched {len(ports)} local ports in "
                f"{self.thresholds.window_seconds:g}s."
            ),
            source_ip=event.src_ip,
            target_ip=event.dst_ip,
            protocol=event.protocol,
            confidence=0.95 if syn_count else 0.86,
            evidence={
                "window_seconds": self.thresholds.window_seconds,
                "packet_count": len(events),
                "distinct_ports": len(ports),
                "ports_sample": sorted(ports)[:20],
                "tcp_syn_packets": syn_count,
            },
        )
        return self._emit_once(alert)


class InboundSynFloodRule(SlidingWindowRule):
    rule_id = "inbound_syn_flood"

    def __init__(self, thresholds: ThresholdConfig) -> None:
        super().__init__(thresholds)
        self._events_by_flow: dict[tuple[str, str, int], Deque[PacketEvent]] = defaultdict(deque)

    def evaluate(self, event: PacketEvent) -> Alert | None:
        if not event.is_tcp_syn_probe or event.dst_port is None:
            return None

        key = (event.src_ip, event.dst_ip, event.dst_port)
        events = self._events_by_flow[key]
        events.append(event)
        self._trim(events, event.timestamp, self.thresholds.window_seconds)

        if len(events) < self.thresholds.syn_flood_packets:
            return None

        severity = "critical" if len(events) >= self.thresholds.syn_flood_packets * 2 else "high"
        alert = Alert(
            timestamp=event.timestamp,
            severity=severity,
            rule_id=self.rule_id,
            title="SYN flood / aggressive TCP probe detected",
            description=(
                f"{event.src_ip} sent {len(events)} TCP SYN packets to "
                f"{event.dst_ip}:{event.dst_port} in {self.thresholds.window_seconds:g}s."
            ),
            source_ip=event.src_ip,
            target_ip=event.dst_ip,
            protocol="TCP",
            confidence=0.93,
            evidence={
                "window_seconds": self.thresholds.window_seconds,
                "packet_count": len(events),
                "target_port": event.dst_port,
                "tcp_flags": sorted(event.tcp_flags),
            },
        )
        return self._emit_once(alert)


class InboundMassRequestRule(SlidingWindowRule):
    rule_id = "inbound_mass_requests"

    def __init__(self, thresholds: ThresholdConfig) -> None:
        super().__init__(thresholds)
        self._events_by_flow: dict[tuple[str, str, str, int], Deque[PacketEvent]] = defaultdict(deque)

    def evaluate(self, event: PacketEvent) -> Alert | None:
        if not event.is_inbound or event.protocol not in {"TCP", "UDP"} or event.dst_port is None:
            return None

        key = (event.src_ip, event.dst_ip, event.protocol, event.dst_port)
        events = self._events_by_flow[key]
        events.append(event)
        self._trim(events, event.timestamp, self.thresholds.window_seconds)

        if len(events) < self.thresholds.mass_request_packets:
            return None

        severity = "critical" if len(events) >= self.thresholds.mass_request_packets * 2 else "medium"
        alert = Alert(
            timestamp=event.timestamp,
            severity=severity,
            rule_id=self.rule_id,
            title="Inbound request burst detected",
            description=(
                f"{event.src_ip} generated {len(events)} {event.protocol} packets to "
                f"{event.dst_ip}:{event.dst_port} in {self.thresholds.window_seconds:g}s."
            ),
            source_ip=event.src_ip,
            target_ip=event.dst_ip,
            protocol=event.protocol,
            confidence=0.78,
            evidence={
                "window_seconds": self.thresholds.window_seconds,
                "packet_count": len(events),
                "target_port": event.dst_port,
                "average_payload_size": _average_payload_size(events),
            },
        )
        return self._emit_once(alert)


class IcmpProbeRule(SlidingWindowRule):
    rule_id = "icmp_probe"

    def __init__(self, thresholds: ThresholdConfig) -> None:
        super().__init__(thresholds)
        self._events_by_source: dict[str, Deque[PacketEvent]] = defaultdict(deque)

    def evaluate(self, event: PacketEvent) -> Alert | None:
        if not event.is_inbound or event.protocol != "ICMP":
            return None

        events = self._events_by_source[event.src_ip]
        events.append(event)
        self._trim(events, event.timestamp, self.thresholds.window_seconds)

        if len(events) < self.thresholds.icmp_probe_packets:
            return None

        alert = Alert(
            timestamp=event.timestamp,
            severity="medium",
            rule_id=self.rule_id,
            title="ICMP probing detected",
            description=(
                f"{event.src_ip} sent {len(events)} ICMP packets in "
                f"{self.thresholds.window_seconds:g}s."
            ),
            source_ip=event.src_ip,
            target_ip=event.dst_ip,
            protocol="ICMP",
            confidence=0.75,
            evidence={
                "window_seconds": self.thresholds.window_seconds,
                "packet_count": len(events),
                "icmp_types": sorted({item.icmp_type for item in events if item.icmp_type is not None}),
            },
        )
        return self._emit_once(alert)


class OutboundSweepRule(SlidingWindowRule):
    rule_id = "outbound_sweep"

    def __init__(self, thresholds: ThresholdConfig) -> None:
        super().__init__(thresholds)
        self._events_by_source: dict[str, Deque[PacketEvent]] = defaultdict(deque)

    def evaluate(self, event: PacketEvent) -> Alert | None:
        if not event.is_outbound or event.protocol not in {"TCP", "UDP"}:
            return None

        events = self._events_by_source[event.src_ip]
        events.append(event)
        self._trim(events, event.timestamp, self.thresholds.window_seconds)

        hosts = {item.dst_ip for item in events}
        ports = {item.dst_port for item in events if item.dst_port is not None}
        host_hit = len(hosts) >= self.thresholds.outbound_unique_hosts
        port_hit = len(ports) >= self.thresholds.outbound_unique_ports
        if not host_hit and not port_hit:
            return None

        severity = "high" if host_hit and port_hit else "medium"
        alert = Alert(
            timestamp=event.timestamp,
            severity=severity,
            rule_id=self.rule_id,
            title="Outbound scan-like activity detected",
            description=(
                f"Local host {event.src_ip} contacted {len(hosts)} hosts and "
                f"{len(ports)} ports in {self.thresholds.window_seconds:g}s."
            ),
            source_ip=event.src_ip,
            target_ip=event.dst_ip,
            protocol=event.protocol,
            confidence=0.82,
            evidence={
                "dedupe_key": f"{event.src_ip}:outbound_sweep",
                "window_seconds": self.thresholds.window_seconds,
                "packet_count": len(events),
                "distinct_hosts": len(hosts),
                "distinct_ports": len(ports),
                "hosts_sample": sorted(hosts)[:20],
                "ports_sample": sorted(ports)[:20],
            },
        )
        return self._emit_once(alert)


def default_rules(thresholds: ThresholdConfig) -> list[Rule]:
    return [
        InboundPortScanRule(thresholds),
        InboundSynFloodRule(thresholds),
        InboundMassRequestRule(thresholds),
        IcmpProbeRule(thresholds),
        OutboundSweepRule(thresholds),
    ]


def _average_payload_size(events: Iterable[PacketEvent]) -> float:
    values = [event.payload_size for event in events]
    if not values:
        return 0.0
    return round(sum(values) / len(values), 2)
