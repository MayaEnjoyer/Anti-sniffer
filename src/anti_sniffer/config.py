from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import tomllib


@dataclass(slots=True)
class ThresholdConfig:
    window_seconds: float = 10.0
    cooldown_seconds: float = 30.0
    port_scan_distinct_ports: int = 12
    port_scan_min_packets: int = 16
    syn_flood_packets: int = 80
    mass_request_packets: int = 120
    icmp_probe_packets: int = 20
    outbound_unique_hosts: int = 25
    outbound_unique_ports: int = 30


@dataclass(slots=True)
class IpsConfig:
    enabled: bool = False
    enforce: bool = False
    min_severity: str = "high"
    block_minutes: int = 15
    block_outbound: bool = False


@dataclass(slots=True)
class RuntimeConfig:
    alert_log: str = "logs/anti_sniffer_alerts.jsonl"
    packet_filter: str = "ip or ip6"
    trusted_cidrs: list[str] = field(default_factory=lambda: ["127.0.0.0/8", "::1/128"])
    local_ips: list[str] = field(default_factory=list)


@dataclass(slots=True)
class AppConfig:
    thresholds: ThresholdConfig = field(default_factory=ThresholdConfig)
    ips: IpsConfig = field(default_factory=IpsConfig)
    runtime: RuntimeConfig = field(default_factory=RuntimeConfig)


def _dataclass_from_dict(cls: type[Any], values: dict[str, Any]) -> Any:
    allowed = set(cls.__dataclass_fields__)  # type: ignore[attr-defined]
    return cls(**{key: value for key, value in values.items() if key in allowed})


def load_config(path: str | Path | None = None) -> AppConfig:
    if path is None:
        return AppConfig()

    config_path = Path(path)
    with config_path.open("rb") as file:
        raw = tomllib.load(file)

    return AppConfig(
        thresholds=_dataclass_from_dict(ThresholdConfig, raw.get("thresholds", {})),
        ips=_dataclass_from_dict(IpsConfig, raw.get("ips", {})),
        runtime=_dataclass_from_dict(RuntimeConfig, raw.get("runtime", {})),
    )
