from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


Severity = str
Direction = str


SEVERITY_RANK: dict[Severity, int] = {
    "low": 10,
    "medium": 20,
    "high": 30,
    "critical": 40,
}


@dataclass(frozen=True, slots=True)
class PacketEvent:
    """Normalized network packet metadata used by detection rules."""

    timestamp: float
    direction: Direction
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: frozenset[str] = field(default_factory=frozenset)
    icmp_type: int | None = None
    payload_size: int = 0
    interface: str | None = None
    summary: str | None = None

    @property
    def is_inbound(self) -> bool:
        return self.direction == "inbound"

    @property
    def is_outbound(self) -> bool:
        return self.direction == "outbound"

    @property
    def is_tcp_syn_probe(self) -> bool:
        return self.protocol == "TCP" and "S" in self.tcp_flags and "A" not in self.tcp_flags

    def remote_ip(self) -> str:
        if self.is_inbound:
            return self.src_ip
        if self.is_outbound:
            return self.dst_ip
        return self.src_ip


@dataclass(slots=True)
class Alert:
    timestamp: float
    severity: Severity
    rule_id: str
    title: str
    description: str
    source_ip: str
    target_ip: str
    protocol: str
    action: str = "alert"
    confidence: float = 0.8
    evidence: dict[str, Any] = field(default_factory=dict)

    @property
    def iso_time(self) -> str:
        return datetime.fromtimestamp(self.timestamp, tz=timezone.utc).isoformat()

    @property
    def severity_rank(self) -> int:
        return SEVERITY_RANK.get(self.severity, 0)

    def fingerprint(self) -> str:
        dedupe_key = self.evidence.get("dedupe_key")
        if dedupe_key:
            return f"{self.rule_id}:{dedupe_key}"
        target_port = self.evidence.get("target_port", "*")
        return f"{self.rule_id}:{self.source_ip}:{self.target_ip}:{self.protocol}:{target_port}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.iso_time,
            "severity": self.severity,
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "source_ip": self.source_ip,
            "target_ip": self.target_ip,
            "protocol": self.protocol,
            "action": self.action,
            "confidence": self.confidence,
            "evidence": self.evidence,
        }


def severity_at_least(actual: Severity, minimum: Severity) -> bool:
    return SEVERITY_RANK.get(actual, 0) >= SEVERITY_RANK.get(minimum, 0)
