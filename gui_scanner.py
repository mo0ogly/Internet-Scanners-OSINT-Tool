#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Internet Scanners OSINT Tool — Tkinter GUI

Author:  m00gly
License: MIT
Repo:    https://github.com/mo0ogly/Internet-Scanners-OSINT-Tool

Run:  python3 gui_scanner.py
"""

import json
import logging
import os
import threading
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import Any

from gui_common import (
    PAD_X,
    PAD_Y,
    GuiLogger,
    StatusBar,
    ToolTip,
    apply_styles,
    create_menu_bar,
    load_config,
    save_config,
    show_error_threadsafe,
    show_info_threadsafe,
    style_log_widget,
)
from internet_scanner import InternetScannerExtractor


class InternetScannerGUI:
    """Tkinter-based GUI for Internet Scanners OSINT Tool."""

    def __init__(self, master: tk.Tk):
        self.master = master
        self.master.title("Internet Scanners OSINT Tool")
        self.master.minsize(800, 600)
        self.master.geometry("900x650")

        # Cancel support
        self._cancel_event = threading.Event()
        self._running = False

        # Variables
        self.logs_dir_var = tk.StringVar(value="logs/")
        self.results_dir_var = tk.StringVar(value="results/")
        self.json_file_var = tk.StringVar(value="internet_scanners_enriched.json")
        self.csv_file_var = tk.StringVar(value="internet_scanners_enriched.csv")
        self.use_multithread_var = tk.BooleanVar(value=True)
        self.abuseipdb_key_var = tk.StringVar(value="")
        self.enable_abuseipdb_var = tk.BooleanVar(value=False)
        self.throttle_var = tk.DoubleVar(value=0.0)
        self.show_api_key_var = tk.BooleanVar(value=False)
        self.stats_var = tk.StringVar()

        apply_styles(self.master)
        create_menu_bar(self.master, "Internet Scanners OSINT Tool")
        self._create_widgets()
        self._inject_logger()
        self._load_api_key()
        self._bind_shortcuts()

        self.extractor = None

    # ── Widgets ───────────────────────────────────────────────────────────

    def _create_widgets(self) -> None:
        # Notebook
        self.notebook = ttk.Notebook(self.master)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=PAD_X, pady=PAD_Y)

        # Tab 1 — Configuration
        tab_config = ttk.Frame(self.notebook)
        self.notebook.add(tab_config, text="Configuration")
        self._build_config_tab(tab_config)

        # Tab 2 — Logs
        tab_logs = ttk.Frame(self.notebook)
        self.notebook.add(tab_logs, text="Logs")
        self._build_logs_tab(tab_logs)

        # Button bar
        frm_buttons = ttk.Frame(self.master)
        frm_buttons.pack(fill=tk.X, padx=PAD_X, pady=PAD_Y)

        self.btn_update = ttk.Button(frm_buttons, text="Update DB", command=self.start_update)
        self.btn_update.pack(side=tk.LEFT, padx=4)

        self.btn_export = ttk.Button(frm_buttons, text="Export Data", command=self.start_export)
        self.btn_export.pack(side=tk.LEFT, padx=4)

        ttk.Label(frm_buttons, textvariable=self.stats_var, foreground="blue").pack(side=tk.RIGHT, padx=PAD_X)

        # Status bar
        self.status_bar = StatusBar(self.master)
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM, padx=PAD_X, pady=(0, PAD_Y))

    def _build_config_tab(self, parent: ttk.Frame) -> None:
        parent.columnconfigure(1, weight=1)

        row = 0

        # Logs directory
        ttk.Label(parent, text="Logs directory:").grid(row=row, column=0, sticky=tk.W, padx=PAD_X, pady=PAD_Y)
        e_logs = ttk.Entry(parent, textvariable=self.logs_dir_var)
        e_logs.grid(row=row, column=1, sticky=tk.EW, padx=PAD_X, pady=PAD_Y)
        ttk.Button(parent, text="Browse...", command=self._browse_logs_dir).grid(row=row, column=2, padx=PAD_X)
        row += 1

        # Results directory
        ttk.Label(parent, text="Results directory:").grid(row=row, column=0, sticky=tk.W, padx=PAD_X, pady=PAD_Y)
        e_results = ttk.Entry(parent, textvariable=self.results_dir_var)
        e_results.grid(row=row, column=1, sticky=tk.EW, padx=PAD_X, pady=PAD_Y)
        ttk.Button(parent, text="Browse...", command=self._browse_results_dir).grid(row=row, column=2, padx=PAD_X)
        row += 1

        # JSON file
        ttk.Label(parent, text="JSON file name:").grid(row=row, column=0, sticky=tk.W, padx=PAD_X, pady=PAD_Y)
        ttk.Entry(parent, textvariable=self.json_file_var).grid(
            row=row, column=1, columnspan=2, sticky=tk.EW, padx=PAD_X, pady=PAD_Y,
        )
        row += 1

        # CSV file
        ttk.Label(parent, text="CSV file name:").grid(row=row, column=0, sticky=tk.W, padx=PAD_X, pady=PAD_Y)
        ttk.Entry(parent, textvariable=self.csv_file_var).grid(
            row=row, column=1, columnspan=2, sticky=tk.EW, padx=PAD_X, pady=PAD_Y,
        )
        row += 1

        # Multithreading
        ttk.Checkbutton(parent, text="Enable multithreading", variable=self.use_multithread_var).grid(
            row=row, column=0, columnspan=3, sticky=tk.W, padx=PAD_X, pady=PAD_Y,
        )
        row += 1

        # AbuseIPDB enable
        ttk.Checkbutton(parent, text="Enable AbuseIPDB lookups", variable=self.enable_abuseipdb_var).grid(
            row=row, column=0, columnspan=3, sticky=tk.W, padx=PAD_X, pady=PAD_Y,
        )
        row += 1

        # Throttle
        ttk.Label(parent, text="Throttle (s):").grid(row=row, column=0, sticky=tk.W, padx=PAD_X, pady=PAD_Y)
        e_throttle = ttk.Entry(parent, textvariable=self.throttle_var, width=10)
        e_throttle.grid(row=row, column=1, sticky=tk.W, padx=PAD_X, pady=PAD_Y)
        ToolTip(e_throttle, "Delay between AbuseIPDB API calls (0 = no delay)")
        row += 1

        # API Key
        ttk.Label(parent, text="AbuseIPDB API Key:").grid(row=row, column=0, sticky=tk.W, padx=PAD_X, pady=PAD_Y)
        frm_key = ttk.Frame(parent)
        frm_key.grid(row=row, column=1, sticky=tk.EW, padx=PAD_X, pady=PAD_Y)
        frm_key.columnconfigure(0, weight=1)

        self.entry_api_key = ttk.Entry(frm_key, textvariable=self.abuseipdb_key_var, show="*")
        self.entry_api_key.grid(row=0, column=0, sticky=tk.EW)
        ToolTip(self.entry_api_key, "Stored in config/settings.json")

        ttk.Checkbutton(frm_key, text="Show", variable=self.show_api_key_var,
                         command=self._toggle_api_key_visibility).grid(row=0, column=1, padx=(4, 0))

        ttk.Button(parent, text="Save API Key", command=self._save_api_key).grid(
            row=row, column=2, padx=PAD_X, pady=PAD_Y,
        )

    def _build_logs_tab(self, parent: ttk.Frame) -> None:
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(1, weight=1)

        frm_header = ttk.Frame(parent)
        frm_header.grid(row=0, column=0, sticky=tk.EW, padx=PAD_X, pady=PAD_Y)
        ttk.Label(frm_header, text="Logs:").pack(side=tk.LEFT)
        ttk.Button(frm_header, text="Clear Logs", command=self._clear_logs).pack(side=tk.RIGHT)

        self.log_text = scrolledtext.ScrolledText(parent, height=15, state=tk.NORMAL)
        self.log_text.grid(row=1, column=0, sticky="nsew", padx=PAD_X, pady=(0, PAD_Y))
        style_log_widget(self.log_text)

    # ── Shortcuts ─────────────────────────────────────────────────────────

    def _bind_shortcuts(self) -> None:
        self.master.bind("<Control-u>", lambda _e: self.start_update())
        self.master.bind("<Control-e>", lambda _e: self.start_export())
        self.master.bind("<Control-l>", lambda _e: self._clear_logs())
        self.master.bind("<Control-q>", lambda _e: self.master.destroy())
        self.master.bind("<Escape>", lambda _e: self._cancel())

    # ── Browsing ──────────────────────────────────────────────────────────

    def _browse_logs_dir(self) -> None:
        path = filedialog.askdirectory()
        if path:
            self.logs_dir_var.set(path)

    def _browse_results_dir(self) -> None:
        path = filedialog.askdirectory()
        if path:
            self.results_dir_var.set(path)

    # ── API key ───────────────────────────────────────────────────────────

    def _toggle_api_key_visibility(self) -> None:
        self.entry_api_key.configure(show="" if self.show_api_key_var.get() else "*")

    def _save_api_key(self) -> None:
        key = self.abuseipdb_key_var.get().strip()
        if not key:
            messagebox.showwarning("Save Key", "API key is empty.")
            return
        try:
            save_config({"abuseipdb_api_key": key})
            messagebox.showinfo("Save Key", "API key saved in config/settings.json")
        except Exception as e:
            messagebox.showerror("Save Key", f"Error saving key: {e}")

    def _load_api_key(self) -> None:
        data = load_config()
        key = data.get("abuseipdb_api_key", "")
        if key:
            self.abuseipdb_key_var.set(key)
            self.logger.info("Loaded AbuseIPDB API key from config.")

    # ── Logger ────────────────────────────────────────────────────────────

    def _inject_logger(self) -> None:
        self.logger = logging.getLogger("InternetScannerGUI")
        self.logger.setLevel(logging.DEBUG)
        gui_handler = GuiLogger(self.log_text)
        gui_handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s", "%H:%M:%S"))
        self.logger.handlers.clear()
        self.logger.addHandler(gui_handler)

    def _clear_logs(self) -> None:
        self.log_text.delete("1.0", tk.END)

    # ── Validation ────────────────────────────────────────────────────────

    def _validate_inputs(self) -> bool:
        if not self.results_dir_var.get().strip():
            messagebox.showerror("Validation", "Results directory cannot be empty.")
            return False
        try:
            throttle = self.throttle_var.get()
            if throttle < 0:
                messagebox.showerror("Validation", "Throttle must be >= 0.")
                return False
        except tk.TclError:
            messagebox.showerror("Validation", "Throttle must be a number.")
            return False
        if self.enable_abuseipdb_var.get() and not self.abuseipdb_key_var.get().strip():
            messagebox.showerror("Validation", "AbuseIPDB is enabled but API key is empty.")
            return False
        return True

    # ── Button state helpers ──────────────────────────────────────────────

    def _set_running(self, running: bool) -> None:
        self._running = running
        state = tk.DISABLED if running else tk.NORMAL
        self.btn_update.configure(state=state)
        self.btn_export.configure(state=state)

    # ── Cancel ────────────────────────────────────────────────────────────

    def _cancel(self) -> None:
        if self._running:
            self._cancel_event.set()
            self.logger.info("Cancel requested...")

    # ── Operations ────────────────────────────────────────────────────────

    def start_update(self) -> None:
        if self._running or not self._validate_inputs():
            return
        self._cancel_event.clear()
        self._set_running(True)
        self.master.after(0, lambda: self.status_bar.start("Cloning repo & enriching IPs...", self._cancel))
        threading.Thread(target=self._update_repo, daemon=True).start()

    def start_export(self) -> None:
        if self._running or not self._validate_inputs():
            return
        self._cancel_event.clear()
        self._set_running(True)
        self.master.after(0, lambda: self.status_bar.start("Exporting data...", self._cancel))
        threading.Thread(target=self._export_data, daemon=True).start()

    def _create_extractor(self) -> None:
        results_dir = self.results_dir_var.get()
        json_file = self.json_file_var.get()
        csv_file = self.csv_file_var.get()
        use_multithread = self.use_multithread_var.get()
        abuse_key = self.abuseipdb_key_var.get().strip() or None
        enable_abuse = self.enable_abuseipdb_var.get()
        throttle = self.throttle_var.get()

        timestamp = datetime.now().strftime("%Y%m%d_%H%M")
        json_path = os.path.join(results_dir, f"{timestamp}_{json_file}")
        csv_path = os.path.join(results_dir, f"{timestamp}_{csv_file}")

        self.logger.info(f"Creating extractor. AbuseIPDB Enabled: {enable_abuse}. Throttle: {throttle}s")

        self.extractor = InternetScannerExtractor(
            repo_url="https://github.com/MDMCK10/internet-scanners.git",
            repo_path="internet-scanners",
            output_json=json_path,
            output_csv=csv_path,
            abuseipdb_api_key=abuse_key if enable_abuse else None,
            log_level=logging.DEBUG,
            use_multithreading=use_multithread,
            enable_abuseipdb=enable_abuse,
            throttle=throttle,
        )

        self.extractor.logger.handlers.clear()
        gui_handler = GuiLogger(self.log_text)
        gui_handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s", "%H:%M:%S"))
        self.extractor.logger.addHandler(gui_handler)
        self.extractor.logger.setLevel(logging.DEBUG)

    def _update_repo(self) -> None:
        try:
            self._create_extractor()
            if self._cancel_event.is_set():
                return
            self.extractor.git_clone_or_pull()
            if self._cancel_event.is_set():
                return
            data = self.extractor.parse_files()
            if self._cancel_event.is_set():
                return
            self.extractor.save_json(data)
            self.extractor.save_csv(data)
            self.extractor.summarize_stats(data)
            self.master.after(0, self._update_stats, data)
            show_info_threadsafe(self.master, "Export Complete", f"JSON and CSV saved in {self.results_dir_var.get()}")
        except Exception as e:
            show_error_threadsafe(self.master, "Error", f"Update failed: {e}")
        finally:
            self.master.after(0, self._set_running, False)
            self.master.after(0, self.status_bar.stop, "Ready")

    def _export_data(self) -> None:
        try:
            self._create_extractor()
            json_path = self.extractor.output_json
            with open(json_path, encoding="utf-8") as f:
                data = json.load(f)
            self.extractor.save_csv(data)
            self.master.after(0, self._update_stats, data)
            show_info_threadsafe(self.master, "Export Complete", f"CSV saved at:\n{self.extractor.output_csv}")
        except Exception as e:
            show_error_threadsafe(self.master, "Error", f"Export failed: {e}")
        finally:
            self.master.after(0, self._set_running, False)
            self.master.after(0, self.status_bar.stop, "Ready")

    def _update_stats(self, data: list[dict[str, Any]]) -> None:
        total = len(data)
        ipv4_count = sum(1 for item in data if ":" not in item["ip_or_cidr"])
        ipv6_count = total - ipv4_count
        abuse_count = sum(
            1 for item in data
            if item.get("abuseConfidenceScore", 0) and item["abuseConfidenceScore"] > 0
        )
        self.stats_var.set(
            f"Total IPs: {total} | IPv4: {ipv4_count} | IPv6: {ipv6_count} | Reported in AbuseIPDB: {abuse_count}"
        )


def main() -> None:
    root = tk.Tk()
    InternetScannerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
