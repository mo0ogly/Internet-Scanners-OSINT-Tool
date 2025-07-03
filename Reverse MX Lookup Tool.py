#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Reverse MX Lookup Tool (Tkinter GUI)
─────────────────────────────────────────────
Tkinter GUI to perform MX lookups and reverse MX
lookups using various OSINT providers:
- ViewDNS.info (web scraping)
- DomainTools API
- WhoisXML API

───────────────────────────────────────────────────────────────────────────────

 Author: m00gly
 Project: Internet Scanners OSINT Tool
 License: MIT
 Repository: https://github.com/mo0ogly/Internet-Scanners-OSINT-Tool

─────
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, font, simpledialog
import threading
import queue
import requests
import socket
import re
import time
import json
import os
import csv
from typing import List, Optional, Callable, Any
import dns.resolver
from datetime import datetime


CONFIG_DIR = "config"
LOGS_DIR = "logs"
RESULTS_DIR = "results"
CONFIG_PATH = os.path.join(CONFIG_DIR, "settings.json")


def ensure_directories() -> None:
    for path in [CONFIG_DIR, LOGS_DIR, RESULTS_DIR]:
        os.makedirs(path, exist_ok=True)


class GuiLogger:
    """
    Logger handler writing logs into a Tkinter text widget and log file.
    """

    def __init__(self, text_widget: tk.Text, logfile: str) -> None:
        self.text_widget = text_widget
        self.logfile_path = logfile

    def write(self, msg: str) -> None:
        self.text_widget.insert(tk.END, msg)
        self.text_widget.see(tk.END)
        with open(self.logfile_path, "a", encoding="utf-8") as f:
            f.write(msg)

    def flush(self) -> None:
        pass


class ReverseMXProvider:
    """
    Base class for Reverse MX providers.
    """

    def __init__(self, api_key: Optional[str] = None) -> None:
        self.api_key = api_key

    def reverse_mx(self, mx_host: str, logger: Callable[[str], None]) -> List[str]:
        raise NotImplementedError


class ViewDNSProvider(ReverseMXProvider):
    """
    Reverse MX lookup via ViewDNS.info.
    """

    def reverse_mx(self, mx_host: str, logger: Callable[[str], None]) -> List[str]:
        logger(f"Reverse MX lookup via ViewDNS for: {mx_host}\n")
        url = f"https://viewdns.info/reversemx/?host={mx_host}&t=1"
        headers = {
            "User-Agent": "Mozilla/5.0"
        }
        try:
            response = requests.get(url, headers=headers, timeout=15)
            response.raise_for_status()
            domains = re.findall(r'<td>([\w\.\-]+)</td>', response.text)
            filtered = [d for d in domains if '.' in d and not d.lower().startswith("domain")]
            for domain in filtered:
                logger(f"→ {domain}\n")
            return filtered
        except Exception as e:
            logger(f"Error during ViewDNS lookup: {e}\n")
            return []


class DomainToolsProvider(ReverseMXProvider):
    """
    Reverse MX lookup via DomainTools API.
    """

    def reverse_mx(self, mx_host: str, logger: Callable[[str], None]) -> List[str]:
        if not self.api_key:
            logger("DomainTools API key not configured.\n")
            return []
        url = f"https://api.domaintools.com/v1/{mx_host}/reverse-mx"
        params = {"api_key": self.api_key}
        try:
            response = requests.get(url, params=params, timeout=15)
            response.raise_for_status()
            data = response.json()
            domains = data.get("response", {}).get("domains", [])
            for domain in domains:
                logger(f"→ {domain}\n")
            return domains
        except Exception as e:
            logger(f"Error during DomainTools lookup: {e}\n")
            return []


class WhoisXMLProvider(ReverseMXProvider):
    """
    Reverse MX lookup via WhoisXML API.
    """

    def reverse_mx(self, mx_host: str, logger: Callable[[str], None]) -> List[str]:
        if not self.api_key:
            logger("WhoisXML API key not configured.\n")
            return []
        url = "https://reverse-mx.whoisxmlapi.com/api/v1"
        params = {
            "apiKey": self.api_key,
            "mx": mx_host
        }
        try:
            response = requests.get(url, params=params, timeout=15)
            response.raise_for_status()
            data = response.json()
            domains = data.get("domains", [])
            for domain in domains:
                logger(f"→ {domain}\n")
            return domains
        except Exception as e:
            logger(f"Error during WhoisXML lookup: {e}\n")
            return []


class ReverseMXTool:
    """
    Core logic for performing lookups.
    """

    def __init__(self, logger: Callable[[str], None]) -> None:
        self.logger = logger

    def lookup_mx(self, domain: str) -> List[str]:
        self.logger(f"Looking up MX records for: {domain}\n")
        records = []
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            for rdata in answers:
                rec = f"Priority {rdata.preference} → {rdata.exchange.to_text()}"
                self.logger(f"{rec}\n")
                records.append(rec)
        except Exception as e:
            self.logger(f"Error resolving MX: {e}\n")
        return records

    def reverse_mx(self, mx_host: str, provider: ReverseMXProvider) -> List[str]:
        return provider.reverse_mx(mx_host, self.logger)

    def save_csv(self, records: List[str], csv_path: str) -> None:
        os.makedirs(os.path.dirname(csv_path), exist_ok=True)
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Domain"])
            for rec in records:
                writer.writerow([rec])
        self.logger(f"CSV saved: {csv_path}\n")


class ReverseMXGUI:
    """
    Tkinter GUI for the Reverse MX Tool.
    """

    def __init__(self, master: tk.Tk) -> None:
        self.master = master
        self.master.title("Reverse MX Tool")

        ensure_directories()

        # Path for logs
        timestamp = datetime.now().strftime("%Y%m%d_%H%M")
        log_path = os.path.join(LOGS_DIR, f"reverse_mx_{timestamp}.log")

        self.logger = GuiLogger(self._create_log_widget(), log_path).write

        self.queue = queue.Queue()
        self.providers = {
            "ViewDNS": ViewDNSProvider(),
            "DomainTools": DomainToolsProvider(),
            "WhoisXML": WhoisXMLProvider(),
        }

        self._load_api_keys()
        self.tool = ReverseMXTool(logger=self.logger)

        self._create_styles()
        self._create_widgets()

    def _create_styles(self) -> None:
        self.master.configure(bg="#f0f0f5")
        style = ttk.Style()
        style.configure("TLabel", font=("Segoe UI", 10))
        style.configure("TButton", font=("Segoe UI", 10))
        style.configure("TEntry", font=("Segoe UI", 10))
        style.configure("TLabelframe.Label", background="#2c3e50", foreground="white", font=("Segoe UI", 11, "bold"))

    def _create_log_widget(self) -> scrolledtext.ScrolledText:
        log_text = scrolledtext.ScrolledText(self.master, height=20, width=90, background="#1e1e1e", foreground="#d4d4d4", font=("Consolas", 10))
        log_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        return log_text

    def _create_widgets(self) -> None:
        frm_top = ttk.LabelFrame(self.master, text="Options")
        frm_top.pack(fill=tk.X, padx=10, pady=10)

        ttk.Label(frm_top, text="Domain or MX:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.entry_domain = ttk.Entry(frm_top, width=50)
        self.entry_domain.grid(row=0, column=1, padx=5, pady=5)

        self.combo_mode = ttk.Combobox(frm_top, values=["MX Lookup", "Reverse MX"], state="readonly", width=20)
        self.combo_mode.grid(row=0, column=2, padx=5, pady=5)
        self.combo_mode.set("MX Lookup")

        ttk.Label(frm_top, text="Provider:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.combo_provider = ttk.Combobox(frm_top, values=list(self.providers.keys()), state="readonly", width=20)
        self.combo_provider.grid(row=1, column=1, padx=5, pady=5)
        self.combo_provider.set("ViewDNS")

        ttk.Button(frm_top, text="Configure API Key", command=self.configure_api_key).grid(row=1, column=2, padx=5, pady=5)

        self.var_multithread = tk.BooleanVar(value=True)
        ttk.Checkbutton(frm_top, text="Use multithreading", variable=self.var_multithread).grid(
            row=2, column=0, columnspan=3, sticky=tk.W, padx=5, pady=5
        )

        ttk.Button(frm_top, text="Start", command=self.start_process).grid(row=3, column=2, padx=5, pady=5)

        self.stats_var = tk.StringVar()
        ttk.Label(self.master, textvariable=self.stats_var, foreground="blue").pack(anchor=tk.W, padx=10, pady=5)

    def _load_api_keys(self) -> None:
        if os.path.exists(CONFIG_PATH):
            try:
                with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                    data = json.load(f)
                for name, key in data.items():
                    if name in self.providers:
                        self.providers[name].api_key = key
                self.logger("API keys loaded from config.\n")
            except Exception as e:
                self.logger(f"Error loading API keys: {e}\n")

    def configure_api_key(self) -> None:
        provider_name = self.combo_provider.get()
        key = simpledialog.askstring("API Key", f"Enter API key for {provider_name}:", show="*")
        if key:
            provider = self.providers.get(provider_name)
            if provider:
                provider.api_key = key
                self._save_api_keys()
                messagebox.showinfo("Success", f"API key saved for {provider_name}.")

    def _save_api_keys(self) -> None:
        data = {name: p.api_key for name, p in self.providers.items() if p.api_key}
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.chmod(CONFIG_PATH, 0o600)

    def start_process(self) -> None:
        domain = self.entry_domain.get().strip()
        mode = self.combo_mode.get()
        provider_name = self.combo_provider.get()
        provider = self.providers.get(provider_name)

        if not domain:
            messagebox.showerror("Error", "Please enter a domain or MX host.")
            return

        if mode == "Reverse MX" and not provider:
            messagebox.showerror("Error", "Select a valid provider.")
            return

        if self.var_multithread.get():
            threading.Thread(target=self.run_task, args=(domain, mode, provider), daemon=True).start()
        else:
            self.run_task(domain, mode, provider)

    def run_task(self, domain: str, mode: str, provider: Optional[ReverseMXProvider]) -> None:
        records = []

        if mode == "MX Lookup":
            records = self.tool.lookup_mx(domain)
        elif mode == "Reverse MX" and provider:
            records = self.tool.reverse_mx(domain, provider)

        self.stats_var.set(f"Found {len(records)} results.")

        if records and messagebox.askyesno("Export", "Export results to CSV?"):
            filename = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv")],
                initialdir=RESULTS_DIR
            )
            if filename:
                self.tool.save_csv(records, filename)


def main() -> None:
    root = tk.Tk()
    app = ReverseMXGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
