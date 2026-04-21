from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import ipaddress
import platform
import subprocess
from typing import Protocol

from .config import IpsConfig
from .models import Alert, severity_at_least


class Blocker(Protocol):
    def block_ip(self, ip_value: str, minutes: int, *, block_outbound: bool = False) -> str:
        ...

    def cleanup_expired(self) -> None:
        ...


class DryRunBlocker:
    def block_ip(self, ip_value: str, minutes: int, *, block_outbound: bool = False) -> str:
        direction = "inbound+outbound" if block_outbound else "inbound"
        return f"dry-run: would block {ip_value} for {minutes} min ({direction})"

    def cleanup_expired(self) -> None:
        return


class WindowsFirewallBlocker:
    RULE_PREFIX = "AntiSniffer_Block"

    def __init__(self) -> None:
        self._blocked: dict[str, tuple[str, datetime]] = {}

    def block_ip(self, ip_value: str, minutes: int, *, block_outbound: bool = False) -> str:
        ipaddress.ip_address(ip_value)
        self.cleanup_expired()
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=minutes)
        directions = ["in"]
        if block_outbound:
            directions.append("out")

        rule_names: list[str] = []
        for direction in directions:
            rule_name = self._rule_name(ip_value, direction)
            command = [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name={rule_name}",
                f"dir={direction}",
                "action=block",
                f"remoteip={ip_value}",
                "profile=any",
                "enable=yes",
            ]
            subprocess.run(command, check=True, capture_output=True, text=True)
            self._blocked[rule_name] = (ip_value, expires_at)
            rule_names.append(rule_name)
        return f"blocked by Windows Firewall until {expires_at.isoformat()} ({', '.join(rule_names)})"

    def cleanup_expired(self) -> None:
        now = datetime.now(timezone.utc)
        expired = [rule_name for rule_name, (_, expires_at) in self._blocked.items() if expires_at <= now]
        for rule_name in expired:
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
                check=False,
                capture_output=True,
                text=True,
            )
            self._blocked.pop(rule_name, None)

    @classmethod
    def _rule_name(cls, ip_value: str, direction: str) -> str:
        safe_ip = ip_value.replace(":", "_").replace(".", "_")
        return f"{cls.RULE_PREFIX}_{safe_ip}_{direction}"


class UnsupportedBlocker:
    def block_ip(self, ip_value: str, minutes: int, *, block_outbound: bool = False) -> str:
        return f"unsupported platform: cannot enforce firewall block for {ip_value}"

    def cleanup_expired(self) -> None:
        return


class ResponseManager:
    def __init__(self, config: IpsConfig, blocker: Blocker | None = None) -> None:
        self.config = config
        self.blocker = blocker if blocker is not None else create_blocker(config)

    def handle(self, alert: Alert) -> Alert:
        self.blocker.cleanup_expired()
        if not self.config.enabled:
            return alert
        if not severity_at_least(alert.severity, self.config.min_severity):
            return alert

        try:
            result = self.blocker.block_ip(
                alert.source_ip,
                self.config.block_minutes,
                block_outbound=self.config.block_outbound,
            )
            return replace(alert, action=result)
        except Exception as exc:
            return replace(alert, action=f"block failed: {exc}")


def create_blocker(config: IpsConfig) -> Blocker:
    if not config.enabled or not config.enforce:
        return DryRunBlocker()
    if platform.system().lower() == "windows":
        return WindowsFirewallBlocker()
    return UnsupportedBlocker()
