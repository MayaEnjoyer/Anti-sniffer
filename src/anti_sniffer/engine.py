from __future__ import annotations

import ipaddress
from typing import Iterable

from .config import AppConfig
from .models import Alert, PacketEvent
from .rules import Rule, default_rules


class DetectionEngine:
    """Coordinates rule execution and trusted-address suppression."""

    def __init__(self, config: AppConfig, rules: Iterable[Rule] | None = None) -> None:
        self.config = config
        self.rules = list(rules) if rules is not None else default_rules(config.thresholds)
        self._trusted_networks = [
            ipaddress.ip_network(item, strict=False) for item in config.runtime.trusted_cidrs
        ]

    def inspect(self, event: PacketEvent) -> list[Alert]:
        if self._is_trusted(event.remote_ip()):
            return []

        alerts: list[Alert] = []
        for rule in self.rules:
            alert = rule.evaluate(event)
            if alert is not None:
                alerts.append(alert)
        return alerts

    def _is_trusted(self, ip_value: str) -> bool:
        try:
            address = ipaddress.ip_address(ip_value)
        except ValueError:
            return False
        return any(address in network for network in self._trusted_networks)
