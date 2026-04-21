from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Protocol

from .models import Alert


class AlertSink(Protocol):
    def emit(self, alert: Alert) -> None:
        ...


class ConsoleAlertSink:
    COLORS = {
        "low": "\033[36m",
        "medium": "\033[33m",
        "high": "\033[31m",
        "critical": "\033[35m",
    }
    RESET = "\033[0m"

    def __init__(self, *, color: bool = True, stream=None) -> None:
        self.color = color
        self.stream = stream if stream is not None else sys.stdout

    def emit(self, alert: Alert) -> None:
        color = self.COLORS.get(alert.severity, "") if self.color else ""
        reset = self.RESET if color else ""
        evidence = ", ".join(f"{key}={value}" for key, value in alert.evidence.items())
        print(
            f"{color}[{alert.severity.upper()}] {alert.title}{reset}\n"
            f"  Time: {alert.iso_time}\n"
            f"  Source: {alert.source_ip} -> Target: {alert.target_ip} ({alert.protocol})\n"
            f"  Details: {alert.description}\n"
            f"  Action: {alert.action}\n"
            f"  Evidence: {evidence}",
            file=self.stream,
            flush=True,
        )


class JsonlAlertSink:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, alert: Alert) -> None:
        with self.path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(alert.to_dict(), ensure_ascii=False) + "\n")


class AudibleAlertSink:
    def emit(self, alert: Alert) -> None:
        if alert.severity not in {"high", "critical"}:
            return
        try:
            import winsound

            winsound.MessageBeep(winsound.MB_ICONHAND)
        except Exception:
            return


class MultiAlertSink:
    def __init__(self, sinks: list[AlertSink]) -> None:
        self.sinks = sinks

    def emit(self, alert: Alert) -> None:
        for sink in self.sinks:
            sink.emit(alert)
