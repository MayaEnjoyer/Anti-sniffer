from __future__ import annotations

import queue
import threading
import time
import tkinter as tk
import sys
from dataclasses import replace
from pathlib import Path
from tkinter import messagebox, ttk

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


APP_TITLE = "Anti-Sniffer IDS/IPS"
CONFIG_PATH = None

PALETTE = {
    "window": "#0a0f16",
    "panel": "#111827",
    "panel_2": "#162033",
    "panel_edge": "#253246",
    "sidebar": "#0d141d",
    "sidebar_panel": "#151f2e",
    "sidebar_text": "#eef5ff",
    "text": "#edf4ff",
    "muted": "#8ea0b6",
    "muted_dark": "#9aacbd",
    "blue": "#2563eb",
    "blue_hover": "#1d4ed8",
    "cyan": "#06b6d4",
    "green": "#0f9f7a",
    "amber": "#d89d22",
    "danger": "#ef4444",
    "critical": "#fb7185",
    "table": "#0f1724",
    "table_alt": "#131d2b",
}


class AntiSnifferApp:
    def __init__(self, root: tk.Tk, config: AppConfig | None = None) -> None:
        self.root = root
        self.config = config if config is not None else _load_default_config()
        self.events: queue.Queue[tuple[str, object]] = queue.Queue()
        self.stop_event = threading.Event()
        self.worker: threading.Thread | None = None
        self.interfaces: list[str] = []

        self.mode_var = tk.StringVar(value="ids")
        self.interface_var = tk.StringVar(value="")
        self.filter_var = tk.StringVar(value=self.config.runtime.packet_filter)
        self.status_var = tk.StringVar(value="Ready")
        self.banner_var = tk.StringVar(value="Ready")
        self.local_ips_var = tk.StringVar(value="")

        self.packet_count = 0
        self.alert_count = 0
        self.high_count = 0
        self.critical_count = 0
        self.mode_buttons: dict[str, tk.Label] = {}

        self._build_window()
        self._refresh_interfaces(silent=True)
        self._refresh_local_ips()
        self._process_queue()

    def run(self) -> None:
        self.root.mainloop()

    def _build_window(self) -> None:
        self.root.title(APP_TITLE)
        self.root.geometry("1240x780")
        self.root.minsize(1120, 700)
        self.root.configure(bg=PALETTE["window"])
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.option_add("*TCombobox*Listbox.background", PALETTE["panel"])
        self.root.option_add("*TCombobox*Listbox.foreground", PALETTE["text"])
        self.root.option_add("*TCombobox*Listbox.selectBackground", PALETTE["blue"])
        self.root.option_add("*TCombobox*Listbox.selectForeground", "#ffffff")

        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure(".", font=("Segoe UI", 10), background=PALETTE["window"], foreground=PALETTE["text"])
        style.configure("Panel.TFrame", background=PALETTE["sidebar"])
        style.configure("PanelBlock.TFrame", background=PALETTE["sidebar_panel"])
        style.configure("Surface.TFrame", background=PALETTE["window"])
        style.configure("Card.TFrame", background=PALETTE["panel"])
        style.configure("Header.TLabel", background=PALETTE["window"], foreground=PALETTE["text"], font=("Segoe UI Semibold", 26))
        style.configure("Subheader.TLabel", background=PALETTE["window"], foreground=PALETTE["muted"], font=("Segoe UI", 10))
        style.configure("PanelTitle.TLabel", background=PALETTE["sidebar"], foreground=PALETTE["sidebar_text"], font=("Segoe UI Semibold", 13))
        style.configure("PanelSubtitle.TLabel", background=PALETTE["sidebar"], foreground=PALETTE["muted_dark"], font=("Segoe UI", 9))
        style.configure("Muted.TLabel", background=PALETTE["sidebar"], foreground=PALETTE["muted_dark"])
        style.configure("MainTitle.TLabel", background=PALETTE["panel"], foreground=PALETTE["text"], font=("Segoe UI Semibold", 13))
        style.configure("MainMuted.TLabel", background=PALETTE["panel"], foreground=PALETTE["muted"], font=("Segoe UI", 9))
        style.configure("TButton", background=PALETTE["panel_2"], foreground=PALETTE["text"], borderwidth=0, focusthickness=0, focuscolor=PALETTE["panel_2"], padding=(14, 9))
        style.map("TButton", background=[("active", "#1d2a3d"), ("disabled", "#111827")], foreground=[("disabled", "#62748a")])
        style.configure("Sidebar.TButton", background="#1a2636", foreground=PALETTE["sidebar_text"], borderwidth=0, padding=(14, 9), focuscolor="#1a2636")
        style.map("Sidebar.TButton", background=[("active", "#22334a"), ("disabled", "#111827")], foreground=[("disabled", "#6b7f94")])
        style.configure("Accent.TButton", background=PALETTE["blue"], foreground="#ffffff", font=("Segoe UI Semibold", 10), focuscolor=PALETTE["blue"])
        style.map("Accent.TButton", background=[("active", PALETTE["blue_hover"]), ("disabled", "#334155")])
        style.configure("Danger.TButton", background=PALETTE["danger"], foreground="#ffffff", font=("Segoe UI Semibold", 10))
        style.map("Danger.TButton", background=[("active", "#dc2626"), ("disabled", "#3d1c24")])
        style.configure("TCombobox", fieldbackground=PALETTE["panel_2"], background=PALETTE["panel_2"], foreground=PALETTE["text"], arrowcolor=PALETTE["muted"], bordercolor=PALETTE["panel_edge"], lightcolor=PALETTE["panel_edge"], darkcolor=PALETTE["panel_edge"], padding=5)
        style.map("TCombobox", fieldbackground=[("readonly", PALETTE["panel_2"])], selectbackground=[("readonly", PALETTE["blue"])], selectforeground=[("readonly", "#ffffff")])
        style.configure("TEntry", fieldbackground=PALETTE["panel_2"], foreground=PALETTE["text"], insertcolor=PALETTE["text"], bordercolor=PALETTE["panel_edge"], lightcolor=PALETTE["panel_edge"], darkcolor=PALETTE["panel_edge"], padding=5)
        style.configure("Treeview", background=PALETTE["table"], fieldbackground=PALETTE["table"], foreground=PALETTE["text"], rowheight=34, borderwidth=0)
        style.configure("Treeview.Heading", background="#1b2738", foreground=PALETTE["text"], relief="flat", font=("Segoe UI Semibold", 10))
        style.map("Treeview", background=[("selected", PALETTE["blue"])], foreground=[("selected", "#ffffff")])

        self.root.columnconfigure(0, minsize=320, weight=0)
        self.root.columnconfigure(1, weight=1)
        self.root.rowconfigure(1, weight=1)

        header = ttk.Frame(self.root, style="Surface.TFrame", padding=(26, 22, 26, 14))
        header.grid(row=0, column=0, columnspan=2, sticky="ew")
        header.columnconfigure(0, weight=1)
        ttk.Label(header, text="Anti-Sniffer Command Center", style="Header.TLabel").grid(row=0, column=0, sticky="w")
        self.status_pill = tk.Label(
            header,
            textvariable=self.status_var,
            bg=PALETTE["panel_2"],
            fg=PALETTE["text"],
            padx=22,
            pady=9,
            font=("Segoe UI Semibold", 10),
            relief="flat",
        )
        self.status_pill.grid(row=0, column=1, sticky="e")

        self._build_sidebar()
        self._build_main_area()

    def _build_sidebar(self) -> None:
        sidebar = ttk.Frame(self.root, style="Panel.TFrame", padding=(22, 20, 22, 18))
        sidebar.grid(row=1, column=0, sticky="nsew", padx=(18, 9), pady=(8, 18))
        sidebar.columnconfigure(0, weight=1)

        ttk.Label(sidebar, text="Control Center", style="PanelTitle.TLabel").grid(row=0, column=0, sticky="w")

        mode_box = tk.Frame(sidebar, bg=PALETTE["sidebar"], highlightthickness=0)
        mode_box.grid(row=1, column=0, sticky="ew", pady=(18, 8))
        mode_box.columnconfigure(0, weight=1)
        for index, (label, value) in enumerate(
            [
                ("IDS MONITOR", "ids"),
                ("IPS DRY-RUN", "ips"),
                ("IPS ENFORCE", "enforce"),
            ]
        ):
            item = tk.Label(
                mode_box,
                text=label,
                anchor="w",
                padx=14,
                pady=10,
                bg=PALETTE["sidebar_panel"],
                fg=PALETTE["muted_dark"],
                font=("Segoe UI Semibold", 9),
                cursor="hand2",
            )
            item.grid(row=index, column=0, sticky="ew", pady=(0 if index == 0 else 7, 0))
            item.bind("<Button-1>", lambda _event, selected=value: self._select_mode(selected))
            item.bind("<Enter>", lambda _event, widget=item: self._hover_mode(widget, True))
            item.bind("<Leave>", lambda _event, widget=item: self._hover_mode(widget, False))
            self.mode_buttons[value] = item
        self._sync_mode_buttons()

        ttk.Label(sidebar, text="Interface", style="Muted.TLabel").grid(row=2, column=0, sticky="w", pady=(16, 5))
        self.interface_box = ttk.Combobox(sidebar, textvariable=self.interface_var, values=[], state="readonly")
        self.interface_box.grid(row=3, column=0, sticky="ew")

        ttk.Label(sidebar, text="Packet filter", style="Muted.TLabel").grid(row=4, column=0, sticky="w", pady=(14, 5))
        ttk.Entry(sidebar, textvariable=self.filter_var).grid(row=5, column=0, sticky="ew")

        button_grid = ttk.Frame(sidebar, style="Panel.TFrame")
        button_grid.grid(row=6, column=0, sticky="ew", pady=(20, 8))
        button_grid.columnconfigure(0, weight=1)
        button_grid.columnconfigure(1, weight=1)
        self.start_button = ttk.Button(button_grid, text="Start", style="Accent.TButton", command=self.start_monitoring)
        self.start_button.grid(row=0, column=0, sticky="ew", padx=(0, 5))
        self.stop_button = ttk.Button(button_grid, text="Stop", style="Danger.TButton", command=self.stop_monitoring, state="disabled")
        self.stop_button.grid(row=0, column=1, sticky="ew", padx=(5, 0))

        ttk.Button(sidebar, text="Demo", style="Sidebar.TButton", command=self.run_demo).grid(row=7, column=0, sticky="ew", pady=(9, 0))
        ttk.Button(sidebar, text="Refresh", style="Sidebar.TButton", command=self._refresh_interfaces).grid(row=8, column=0, sticky="ew", pady=(8, 0))
        ttk.Button(sidebar, text="Clear", style="Sidebar.TButton", command=self.clear_alerts).grid(row=9, column=0, sticky="ew", pady=(8, 0))

        ttk.Label(sidebar, text="Local addresses", style="Muted.TLabel").grid(row=10, column=0, sticky="w", pady=(22, 5))
        tk.Label(
            sidebar,
            textvariable=self.local_ips_var,
            justify="left",
            anchor="nw",
            bg=PALETTE["sidebar_panel"],
            fg=PALETTE["muted_dark"],
            padx=14,
            pady=12,
            height=5,
            wraplength=255,
            font=("Cascadia Mono", 9),
        ).grid(row=11, column=0, sticky="ew")

    def _build_main_area(self) -> None:
        main = ttk.Frame(self.root, style="Surface.TFrame", padding=(0, 0, 18, 18))
        main.grid(row=1, column=1, sticky="nsew", padx=(9, 18), pady=(8, 18))
        main.columnconfigure(0, weight=1)
        main.rowconfigure(2, weight=1)

        self.banner_holder = tk.Frame(
            main,
            bg=PALETTE["panel"],
            highlightbackground=PALETTE["panel_edge"],
            highlightthickness=1,
        )
        self.banner_holder.grid(row=0, column=0, sticky="ew")
        self.banner_holder.columnconfigure(1, weight=1)
        self.banner_stripe = tk.Frame(self.banner_holder, bg=PALETTE["blue"], width=5)
        self.banner_stripe.grid(row=0, column=0, sticky="ns")
        self.banner = tk.Label(
            self.banner_holder,
            textvariable=self.banner_var,
            bg=PALETTE["panel"],
            fg=PALETTE["text"],
            anchor="w",
            padx=18,
            pady=15,
            font=("Segoe UI Semibold", 11),
        )
        self.banner.grid(row=0, column=1, sticky="ew")

        metrics = ttk.Frame(main, style="Surface.TFrame")
        metrics.grid(row=1, column=0, sticky="ew", pady=(16, 16))
        for index in range(4):
            metrics.columnconfigure(index, weight=1)

        self.packet_value = self._metric(metrics, 0, "Packets", "0", "#0f766e")
        self.alert_value = self._metric(metrics, 1, "Alerts", "0", "#ca8a04")
        self.high_value = self._metric(metrics, 2, "High", "0", "#dc2626")
        self.critical_value = self._metric(metrics, 3, "Critical", "0", "#e11d48")

        table_frame = tk.Frame(
            main,
            bg=PALETTE["panel"],
            highlightbackground=PALETTE["panel_edge"],
            highlightthickness=1,
        )
        table_frame.grid(row=2, column=0, sticky="nsew")
        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(1, weight=1)

        table_header = tk.Frame(table_frame, bg=PALETTE["panel"])
        table_header.grid(row=0, column=0, columnspan=2, sticky="ew", padx=16, pady=(14, 8))
        table_header.columnconfigure(0, weight=1)
        tk.Label(
            table_header,
            text="Threat Timeline",
            bg=PALETTE["panel"],
            fg=PALETTE["text"],
            anchor="w",
            font=("Segoe UI Semibold", 13),
        ).grid(row=0, column=0, sticky="w")
        columns = ("time", "severity", "rule", "source", "target", "details", "action")
        self.alert_table = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")
        headings = {
            "time": "Time",
            "severity": "Severity",
            "rule": "Rule",
            "source": "Source",
            "target": "Target",
            "details": "Details",
            "action": "Action",
        }
        widths = {
            "time": 92,
            "severity": 82,
            "rule": 150,
            "source": 130,
            "target": 130,
            "details": 330,
            "action": 230,
        }
        for column in columns:
            self.alert_table.heading(column, text=headings[column])
            self.alert_table.column(column, width=widths[column], minwidth=70, anchor="w")
        self.alert_table.grid(row=1, column=0, sticky="nsew", padx=(16, 0), pady=(0, 16))
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.alert_table.yview)
        scrollbar.grid(row=1, column=1, sticky="ns", padx=(0, 16), pady=(0, 16))
        self.alert_table.configure(yscrollcommand=scrollbar.set)
        self.alert_table.tag_configure("medium", background="#2c2617", foreground="#ffd166")
        self.alert_table.tag_configure("high", background="#311a22", foreground="#ff9a9a")
        self.alert_table.tag_configure("critical", background="#3b1224", foreground="#ff7a9c")

    def _metric(self, parent: ttk.Frame, column: int, label: str, value: str, accent: str) -> tk.Label:
        card = tk.Frame(parent, bg=PALETTE["panel"], highlightbackground=PALETTE["panel_edge"], highlightthickness=1)
        card.grid(row=0, column=column, sticky="ew", padx=(0 if column == 0 else 8, 0))
        card.columnconfigure(0, weight=1)
        tk.Frame(card, height=3, bg=accent).grid(row=0, column=0, sticky="ew")
        tk.Label(card, text=label, bg=PALETTE["panel"], fg=PALETTE["muted"], anchor="w", padx=16, pady=0).grid(
            row=1,
            column=0,
            sticky="ew",
            pady=(12, 0),
        )
        value_label = tk.Label(
            card,
            text=value,
            bg=PALETTE["panel"],
            fg=PALETTE["text"],
            anchor="w",
            padx=16,
            pady=0,
            font=("Segoe UI Semibold", 25),
        )
        value_label.grid(row=2, column=0, sticky="ew", pady=(0, 12))
        return value_label

    def start_monitoring(self) -> None:
        if self.worker and self.worker.is_alive():
            return

        interface = self.interface_var.get().strip()
        if not interface:
            messagebox.showwarning(APP_TITLE, "Select a capture interface first.")
            return

        self.stop_event.clear()
        self._set_running(True)
        self._set_banner("Monitoring", level="ok")

        self.worker = threading.Thread(target=self._live_worker, args=(interface,), daemon=True)
        self.worker.start()

    def stop_monitoring(self) -> None:
        self.stop_event.set()
        self._set_banner("Stopping", level="warn")

    def run_demo(self) -> None:
        if self.worker and self.worker.is_alive():
            messagebox.showinfo(APP_TITLE, "Stop monitoring first.")
            return
        self.stop_event.clear()
        self._set_running(True)
        self._set_banner("Demo running", level="ok")
        self.worker = threading.Thread(target=self._demo_worker, daemon=True)
        self.worker.start()

    def clear_alerts(self) -> None:
        for item in self.alert_table.get_children():
            self.alert_table.delete(item)
        self.alert_count = 0
        self.high_count = 0
        self.critical_count = 0
        self._refresh_metrics()
        self._set_banner("Cleared", level="ok")

    def _select_mode(self, mode: str) -> None:
        self.mode_var.set(mode)
        self._sync_mode_buttons()

    def _sync_mode_buttons(self) -> None:
        selected = self.mode_var.get()
        for mode, widget in self.mode_buttons.items():
            if mode == selected:
                widget.configure(bg=PALETTE["blue"], fg="#ffffff")
            else:
                widget.configure(bg=PALETTE["sidebar_panel"], fg=PALETTE["muted_dark"])

    def _hover_mode(self, widget: tk.Label, active: bool) -> None:
        if widget.cget("bg") == PALETTE["blue"]:
            return
        widget.configure(bg="#1b2a3e" if active else PALETTE["sidebar_panel"])

    def _live_worker(self, interface: str) -> None:
        config = self._runtime_config()
        engine = DetectionEngine(config)
        responder = ResponseManager(config.ips)
        local_ips = get_local_addresses(config.runtime.local_ips)
        capture = ScapyPacketCapture(
            local_ips=local_ips,
            iface=interface,
            packet_filter=self.filter_var.get().strip() or config.runtime.packet_filter,
        )

        def handle_packet(event: PacketEvent) -> None:
            self.events.put(("packet", event))
            for alert in engine.inspect(event):
                self.events.put(("alert", responder.handle(alert)))

        try:
            while not self.stop_event.is_set():
                capture.run(handle_packet, duration=1.0)
        except CaptureBackendUnavailable as exc:
            self.events.put(("error", str(exc)))
        except PermissionError:
            self.events.put(("error", "Packet capture requires administrator privileges."))
        except OSError as exc:
            self.events.put(("error", f"Packet capture failed: {exc}"))
        finally:
            self.events.put(("stopped", None))

    def _demo_worker(self) -> None:
        config = self._runtime_config()
        engine = DetectionEngine(config)
        responder = ResponseManager(config.ips)
        streams = [
            synthetic_port_scan(count=32, start_time=1_000_000.0),
            synthetic_syn_flood(count=100, start_time=1_000_020.0),
            synthetic_outbound_sweep(count=35, start_time=1_000_040.0),
        ]
        try:
            for stream in streams:
                for event in stream:
                    if self.stop_event.is_set():
                        return
                    self.events.put(("packet", event))
                    for alert in engine.inspect(event):
                        self.events.put(("alert", responder.handle(alert)))
                    time.sleep(0.025)
        finally:
            self.events.put(("stopped", None))

    def _process_queue(self) -> None:
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "packet":
                    self.packet_count += 1
                    self._refresh_metrics()
                elif kind == "alert":
                    self._add_alert(payload)  # type: ignore[arg-type]
                elif kind == "error":
                    self._set_banner(str(payload), level="critical")
                    self.status_var.set("Error")
                    self.status_pill.configure(bg=PALETTE["critical"], fg="#ffffff")
                    messagebox.showerror(APP_TITLE, str(payload))
                elif kind == "stopped":
                    self._set_running(False)
                    if self.status_var.get() != "Error":
                        self._set_banner("Stopped", level="warn")
        except queue.Empty:
            pass
        self.root.after(120, self._process_queue)

    def _add_alert(self, alert: Alert) -> None:
        self.alert_count += 1
        if alert.severity == "high":
            self.high_count += 1
        if alert.severity == "critical":
            self.critical_count += 1
        self._refresh_metrics()

        values = (
            alert.iso_time.split("T")[-1].split("+")[0],
            alert.severity.upper(),
            alert.rule_id,
            alert.source_ip,
            alert.target_ip,
            alert.description,
            alert.action,
        )
        item = self.alert_table.insert("", 0, values=values, tags=(alert.severity,))
        self.alert_table.selection_set(item)
        self.alert_table.focus(item)

        if len(self.alert_table.get_children()) > 500:
            self.alert_table.delete(self.alert_table.get_children()[-1])

        if alert.severity in {"high", "critical"}:
            self._set_banner(f"{alert.severity.upper()}: {alert.description}", level="critical")
            self.root.bell()
            self.root.lift()
        else:
            self._set_banner(alert.description, level="warn")

    def _runtime_config(self) -> AppConfig:
        config = replace(self.config)
        config.thresholds = replace(self.config.thresholds)
        config.runtime = replace(self.config.runtime)
        config.ips = replace(self.config.ips)

        mode = self.mode_var.get()
        config.ips.enabled = mode in {"ips", "enforce"}
        config.ips.enforce = mode == "enforce"
        return config

    def _refresh_interfaces(self, silent: bool = False) -> None:
        try:
            self.interfaces = list_interfaces()
        except CaptureBackendUnavailable as exc:
            self.interfaces = []
            if not silent:
                messagebox.showerror(APP_TITLE, str(exc))
            self._set_banner(str(exc), level="critical")
            return

        self.interface_box.configure(values=self.interfaces)
        if self.interfaces and not self.interface_var.get():
            self.interface_var.set(self.interfaces[0])
        self._set_banner(f"Interfaces: {len(self.interfaces)}", level="ok")

    def _refresh_local_ips(self) -> None:
        addresses = sorted(get_local_addresses(self.config.runtime.local_ips))
        self.local_ips_var.set("\n".join(addresses[:8]) if addresses else "No local addresses detected")

    def _refresh_metrics(self) -> None:
        self.packet_value.configure(text=str(self.packet_count))
        self.alert_value.configure(text=str(self.alert_count))
        self.high_value.configure(text=str(self.high_count))
        self.critical_value.configure(text=str(self.critical_count))

    def _set_running(self, running: bool) -> None:
        self.start_button.configure(state="disabled" if running else "normal")
        self.stop_button.configure(state="normal" if running else "disabled")
        self.status_var.set("Monitoring" if running else "Ready")
        self.status_pill.configure(
            bg=PALETTE["blue"] if running else PALETTE["panel_2"],
            fg="#ffffff" if running else PALETTE["text"],
        )

    def _set_banner(self, text: str, *, level: str) -> None:
        colors = {
            "ok": (PALETTE["green"], PALETTE["text"]),
            "warn": (PALETTE["amber"], PALETTE["text"]),
            "critical": (PALETTE["critical"], PALETTE["critical"]),
        }
        stripe, fg = colors[level]
        self.banner_var.set(text)
        self.banner.configure(bg=PALETTE["panel"], fg=fg)
        self.banner_stripe.configure(bg=stripe)
        if level == "critical":
            self.status_var.set("Alert")
            self.status_pill.configure(bg=PALETTE["critical"], fg="#ffffff")

    def _on_close(self) -> None:
        self.stop_event.set()
        self.root.destroy()


def _load_default_config() -> AppConfig:
    config_path = _resource_path(Path("config/default.toml"))
    if config_path.exists():
        return load_config(config_path)
    return load_config(None)


def _resource_path(relative_path: Path) -> Path:
    bundle_root = getattr(sys, "_MEIPASS", None)
    if bundle_root:
        bundled = Path(bundle_root) / relative_path
        if bundled.exists():
            return bundled
    return relative_path


def main() -> None:
    root = tk.Tk()
    app = AntiSnifferApp(root)
    app.run()
