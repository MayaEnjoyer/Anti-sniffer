from __future__ import annotations

import socket
import time
import ipaddress
from collections.abc import Callable, Iterator
from dataclasses import dataclass

from .models import PacketEvent


class CaptureBackendUnavailable(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class CaptureInterface:
    display_name: str
    capture_name: str
    description: str
    ipv4: str | None = None


def get_local_addresses(extra: list[str] | None = None) -> set[str]:
    addresses = {"127.0.0.1", "::1"}
    hostname = socket.gethostname()

    try:
        for item in socket.getaddrinfo(hostname, None):
            addresses.add(item[4][0])
    except OSError:
        pass

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            addresses.add(sock.getsockname()[0])
    except OSError:
        pass

    if extra:
        addresses.update(extra)
    return addresses


def list_interfaces() -> list[str]:
    try:
        from scapy.all import get_if_list
    except ImportError as exc:
        raise CaptureBackendUnavailable(
            "Scapy is not installed. Install live capture support with: "
            "python -m pip install -e .[live]"
        ) from exc
    return list(get_if_list())


def list_interface_details() -> list[CaptureInterface]:
    try:
        from scapy.all import get_working_ifaces
    except ImportError as exc:
        raise CaptureBackendUnavailable(
            "Scapy is not installed. Install live capture support with: "
            "python -m pip install -e .[live]"
        ) from exc

    details: list[CaptureInterface] = []
    for iface in get_working_ifaces():
        capture_name = str(getattr(iface, "network_name", "") or getattr(iface, "name", ""))
        description = str(getattr(iface, "description", "") or getattr(iface, "name", "") or capture_name)
        ips = getattr(iface, "ips", {})
        ipv4_values = []
        try:
            ipv4_values = list(ips.get(4, []))
        except AttributeError:
            ipv4_values = []
        ipv4 = ipv4_values[0] if ipv4_values else None
        label = description
        if ipv4:
            label = f"{description}  [{ipv4}]"
        details.append(
            CaptureInterface(
                display_name=label,
                capture_name=capture_name,
                description=description,
                ipv4=ipv4,
            )
        )

    return sorted(details, key=_interface_sort_key)


class ScapyPacketCapture:
    def __init__(
        self,
        *,
        local_ips: set[str],
        iface: str | None = None,
        packet_filter: str = "ip or ip6",
    ) -> None:
        self.local_ips = local_ips
        self.iface = iface
        self.packet_filter = packet_filter

    def run(self, callback: Callable[[PacketEvent], None], *, duration: float | None = None) -> None:
        try:
            from scapy.all import sniff
        except ImportError as exc:
            raise CaptureBackendUnavailable(
                "Scapy is not installed. Install live capture support with: "
                "python -m pip install -e .[live]"
            ) from exc

        stop_at = None if duration is None else time.monotonic() + duration

        def should_stop(_: object) -> bool:
            return stop_at is not None and time.monotonic() >= stop_at

        def on_packet(packet: object) -> None:
            event = packet_to_event(packet, self.local_ips, self.iface)
            if event is not None:
                callback(event)

        sniff(
            iface=self.iface,
            filter=self.packet_filter,
            prn=on_packet,
            store=False,
            stop_filter=should_stop if stop_at is not None else None,
            timeout=duration,
        )


def packet_to_event(packet: object, local_ips: set[str], iface: str | None = None) -> PacketEvent | None:
    try:
        from scapy.layers.inet import ICMP, IP, TCP, UDP
        from scapy.layers.inet6 import IPv6
    except ImportError as exc:
        raise CaptureBackendUnavailable("Scapy is required for packet conversion.") from exc

    src_ip: str | None = None
    dst_ip: str | None = None
    if _has_layer(packet, IP):
        ip_layer = packet[IP]
        src_ip = str(ip_layer.src)
        dst_ip = str(ip_layer.dst)
    elif _has_layer(packet, IPv6):
        ip_layer = packet[IPv6]
        src_ip = str(ip_layer.src)
        dst_ip = str(ip_layer.dst)
    else:
        return None

    direction = "unknown"
    if dst_ip in local_ips and src_ip not in local_ips:
        direction = "inbound"
    elif src_ip in local_ips and dst_ip not in local_ips:
        direction = "outbound"

    timestamp = float(getattr(packet, "time", time.time()))
    payload_size = len(bytes(packet)) if hasattr(packet, "__bytes__") else 0
    summary = packet.summary() if hasattr(packet, "summary") else None

    if _has_layer(packet, TCP):
        tcp = packet[TCP]
        return PacketEvent(
            timestamp=timestamp,
            direction=direction,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol="TCP",
            src_port=int(tcp.sport),
            dst_port=int(tcp.dport),
            tcp_flags=_tcp_flags(int(tcp.flags)),
            payload_size=payload_size,
            interface=iface,
            summary=summary,
        )

    if _has_layer(packet, UDP):
        udp = packet[UDP]
        return PacketEvent(
            timestamp=timestamp,
            direction=direction,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol="UDP",
            src_port=int(udp.sport),
            dst_port=int(udp.dport),
            payload_size=payload_size,
            interface=iface,
            summary=summary,
        )

    if _has_layer(packet, ICMP):
        icmp = packet[ICMP]
        return PacketEvent(
            timestamp=timestamp,
            direction=direction,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol="ICMP",
            icmp_type=int(icmp.type),
            payload_size=payload_size,
            interface=iface,
            summary=summary,
        )

    return PacketEvent(
        timestamp=timestamp,
        direction=direction,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol="OTHER",
        payload_size=payload_size,
        interface=iface,
        summary=summary,
    )


def synthetic_port_scan(
    *,
    source_ip: str = "203.0.113.10",
    target_ip: str = "192.168.1.50",
    start_port: int = 1,
    count: int = 32,
    start_time: float | None = None,
) -> Iterator[PacketEvent]:
    base = time.time() if start_time is None else start_time
    for index in range(count):
        yield PacketEvent(
            timestamp=base + index * 0.1,
            direction="inbound",
            src_ip=source_ip,
            dst_ip=target_ip,
            protocol="TCP",
            src_port=42000 + index,
            dst_port=start_port + index,
            tcp_flags=frozenset({"S"}),
            payload_size=60,
        )


def synthetic_syn_flood(
    *,
    source_ip: str = "198.51.100.77",
    target_ip: str = "192.168.1.50",
    target_port: int = 445,
    count: int = 100,
    start_time: float | None = None,
) -> Iterator[PacketEvent]:
    base = time.time() if start_time is None else start_time
    for index in range(count):
        yield PacketEvent(
            timestamp=base + index * 0.03,
            direction="inbound",
            src_ip=source_ip,
            dst_ip=target_ip,
            protocol="TCP",
            src_port=50000 + (index % 1000),
            dst_port=target_port,
            tcp_flags=frozenset({"S"}),
            payload_size=54,
        )


def synthetic_outbound_sweep(
    *,
    source_ip: str = "192.168.1.50",
    count: int = 35,
    start_time: float | None = None,
) -> Iterator[PacketEvent]:
    base = time.time() if start_time is None else start_time
    for index in range(count):
        yield PacketEvent(
            timestamp=base + index * 0.08,
            direction="outbound",
            src_ip=source_ip,
            dst_ip=f"10.10.0.{index + 1}",
            protocol="TCP",
            src_port=53000 + index,
            dst_port=20 + index,
            tcp_flags=frozenset({"S"}),
            payload_size=60,
        )


def _has_layer(packet: object, layer: object) -> bool:
    try:
        return bool(packet.haslayer(layer))  # type: ignore[attr-defined]
    except AttributeError:
        return False


def _tcp_flags(value: int) -> frozenset[str]:
    mapping = {
        0x01: "F",
        0x02: "S",
        0x04: "R",
        0x08: "P",
        0x10: "A",
        0x20: "U",
        0x40: "E",
        0x80: "C",
    }
    return frozenset(flag for bit, flag in mapping.items() if value & bit)


def _interface_sort_key(item: CaptureInterface) -> tuple[int, str]:
    text = item.display_name.lower()
    if "loopback" in text:
        return (8, text)
    if "wan miniport" in text:
        return (7, text)
    if "wi-fi direct" in text or "bluetooth" in text:
        return (6, text)
    if item.ipv4 and item.ipv4.startswith("169.254."):
        return (5, text)
    if "vpn" in text or "hyper-v" in text or "virtual" in text:
        return (4, text)
    if item.ipv4 and _is_private_ipv4(item.ipv4):
        if "wireless" in text or "wi-fi" in text or "wifi" in text:
            return (0, text)
        if "ethernet" in text or "realtek" in text or "intel" in text:
            return (1, text)
        return (2, text)
    if item.ipv4:
        return (3, text)
    return (9, text)


def _is_private_ipv4(ip_value: str) -> bool:
    try:
        address = ipaddress.ip_address(ip_value)
    except ValueError:
        return False
    return address.version == 4 and address.is_private
