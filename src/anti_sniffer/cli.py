from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable
from pathlib import Path

from .alerts import AudibleAlertSink, ConsoleAlertSink, JsonlAlertSink, MultiAlertSink
from .capture import (
    CaptureBackendUnavailable,
    ScapyPacketCapture,
    get_local_addresses,
    list_interfaces,
    synthetic_outbound_sweep,
    synthetic_port_scan,
    synthetic_syn_flood,
)
from .config import AppConfig, load_config
from .engine import DetectionEngine
from .models import Alert, PacketEvent
from .response import ResponseManager


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="anti-sniffer",
        description="Real-time IDS/IPS anti-sniffer for detecting scans and traffic bursts.",
    )
    parser.add_argument("--config", default=None, help="Path to TOML config file.")

    subparsers = parser.add_subparsers(dest="command", required=True)

    monitor = subparsers.add_parser("monitor", help="Run live packet monitoring.")
    monitor.add_argument("--interface", "-i", default=None, help="Interface name for Scapy sniffing.")
    monitor.add_argument("--duration", type=float, default=None, help="Stop after N seconds.")
    monitor.add_argument("--local-ip", action="append", default=[], help="Additional local IP address.")
    monitor.add_argument("--filter", default=None, help="BPF packet filter. Defaults to config value.")
    monitor.add_argument("--ips", action="store_true", help="Enable IPS response mode.")
    monitor.add_argument("--enforce", action="store_true", help="Create real firewall block rules.")
    monitor.add_argument("--json", action="store_true", help="Print alerts as JSON instead of text.")
    monitor.add_argument("--no-log", action="store_true", help="Do not write JSONL alert log.")
    monitor.add_argument("--beep", action="store_true", help="Play a Windows alert sound for high severity alerts.")

    simulate = subparsers.add_parser("simulate", help="Run synthetic traffic through the detector.")
    simulate.add_argument(
        "--scenario",
        choices=["port-scan", "syn-flood", "outbound-sweep", "mixed"],
        default="mixed",
    )
    simulate.add_argument("--json", action="store_true", help="Print alerts as JSON.")
    simulate.add_argument("--ips", action="store_true", help="Enable IPS dry-run response mode.")
    simulate.add_argument("--enforce", action="store_true", help="Use real firewall rules with IPS mode.")

    subparsers.add_parser("interfaces", help="List capture interfaces available to Scapy.")
    subparsers.add_parser("self-test", help="Run a quick detector sanity check.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    config = load_config(args.config)

    if args.command == "interfaces":
        return _interfaces()
    if args.command == "monitor":
        return _monitor(args, config)
    if args.command == "simulate":
        return _simulate(args, config)
    if args.command == "self-test":
        return _self_test(config)

    parser.error(f"Unknown command: {args.command}")
    return 2


def _monitor(args: argparse.Namespace, config: AppConfig) -> int:
    if args.ips:
        config.ips.enabled = True
    if args.enforce:
        config.ips.enabled = True
        config.ips.enforce = True

    local_ips = get_local_addresses(config.runtime.local_ips + args.local_ip)
    sink = _build_sink(config, json_output=args.json, no_log=args.no_log, beep=args.beep)
    engine = DetectionEngine(config)
    responder = ResponseManager(config.ips)

    def handle_event(event: PacketEvent) -> None:
        for alert in engine.inspect(event):
            sink.emit(responder.handle(alert))

    capture = ScapyPacketCapture(
        local_ips=local_ips,
        iface=args.interface,
        packet_filter=args.filter or config.runtime.packet_filter,
    )

    _print_monitor_banner(args.interface, local_ips, config, json_output=args.json)
    try:
        capture.run(handle_event, duration=args.duration)
    except CaptureBackendUnavailable as exc:
        print(str(exc), file=sys.stderr)
        return 3
    except PermissionError:
        print("Packet capture requires administrator/root privileges.", file=sys.stderr)
        return 4
    except OSError as exc:
        print(f"Packet capture failed: {exc}", file=sys.stderr)
        return 5
    return 0


def _simulate(args: argparse.Namespace, config: AppConfig) -> int:
    if args.ips:
        config.ips.enabled = True
    if args.enforce:
        config.ips.enabled = True
        config.ips.enforce = True

    sink = JsonStdoutSink() if args.json else ConsoleAlertSink()
    engine = DetectionEngine(config)
    responder = ResponseManager(config.ips)
    count = 0

    for event in _scenario_events(args.scenario):
        for alert in engine.inspect(event):
            sink.emit(responder.handle(alert))
            count += 1

    if not args.json:
        print(f"\nSimulation completed: {count} alert(s) emitted.", flush=True)
    return 0 if count else 1


def _interfaces() -> int:
    try:
        for name in list_interfaces():
            print(name)
    except CaptureBackendUnavailable as exc:
        print(str(exc), file=sys.stderr)
        return 3
    return 0


def _self_test(config: AppConfig) -> int:
    engine = DetectionEngine(config)
    alerts: list[Alert] = []
    for event in synthetic_port_scan(count=max(config.thresholds.port_scan_min_packets, 20)):
        alerts.extend(engine.inspect(event))

    if not alerts:
        print("Self-test failed: port scan was not detected.", file=sys.stderr)
        return 1
    print("Self-test passed: detector emitted alert:")
    print(json.dumps(alerts[0].to_dict(), indent=2, ensure_ascii=False))
    return 0


def _build_sink(config: AppConfig, *, json_output: bool, no_log: bool, beep: bool) -> MultiAlertSink:
    sinks = []
    sinks.append(JsonStdoutSink() if json_output else ConsoleAlertSink())
    if not no_log:
        sinks.append(JsonlAlertSink(Path(config.runtime.alert_log)))
    if beep:
        sinks.append(AudibleAlertSink())
    return MultiAlertSink(sinks)


def _scenario_events(name: str) -> Iterable[PacketEvent]:
    if name == "port-scan":
        return synthetic_port_scan(count=32)
    if name == "syn-flood":
        return synthetic_syn_flood(count=100)
    if name == "outbound-sweep":
        return synthetic_outbound_sweep(count=35)
    return [
        *synthetic_port_scan(count=32, start_time=1_000_000.0),
        *synthetic_syn_flood(count=100, start_time=1_000_020.0),
        *synthetic_outbound_sweep(count=35, start_time=1_000_040.0),
    ]


def _print_monitor_banner(
    interface: str | None,
    local_ips: set[str],
    config: AppConfig,
    *,
    json_output: bool,
) -> None:
    if json_output:
        return
    mode = "IPS enforce" if config.ips.enabled and config.ips.enforce else "IPS dry-run" if config.ips.enabled else "IDS"
    print("Anti-sniffer monitor started")
    print(f"  Mode: {mode}")
    print(f"  Interface: {interface or 'Scapy default'}")
    print(f"  Local IPs: {', '.join(sorted(local_ips))}")
    print(f"  Window: {config.thresholds.window_seconds:g}s")
    print("Press Ctrl+C to stop.\n", flush=True)


class JsonStdoutSink:
    def emit(self, alert: Alert) -> None:
        print(json.dumps(alert.to_dict(), ensure_ascii=False), flush=True)
