#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
───────────────────────────────────────────────────────────────────────────────
 Internet Scanners OSINT Tool (Tkinter GUI)
───────────────────────────────────────────────────────────────────────────────

 Author: m00gly
 Project: Internet Scanners OSINT Tool
 License: MIT
 Repository: https://github.com/mo0ogly/Internet-Scanners-OSINT-Tool

───────────────────────────────────────────────────────────────────────────────

DESCRIPTION
────────────────────────────────────────────
This is a complete Tkinter-based GUI frontend for the Internet Scanners
OSINT Tool. It is designed to extract and enrich IP addresses from files
hosted in the GitHub repository:

    https://github.com/MDMCK10/internet-scanners

The application allows security researchers and network analysts to
visualize and enrich lists of scanner IP addresses. It offers real-time
logs, configuration of output paths and filenames, and optional integration
with the AbuseIPDB API to check reputation data.

────────────────────────────────────────────

OR DEVELOPERS
────────────────────────────────────────────
Key classes & files:
- `InternetScannerExtractor`: Core class performing all parsing and enrichment
- `InternetScannerGUI`: This Tkinter class for user interaction
- `GuiLogger`: Redirects logs into the Tkinter GUI

Main development features:
- All UI widgets are styled for readability and dark log window
- AbuseIPDB enrichment is optional and can be disabled for privacy or quota limits
- Throttling is configurable to avoid AbuseIPDB rate limits
- Logs directory and output directories can be customized
- JSON and CSV exports are timestamped automatically
- Threaded design to avoid freezing the GUI during long-running tasks

How to extend:
- Add new enrichment services (e.g. Shodan, VirusTotal) by extending
  `InternetScannerExtractor.enrich_ip`
- Integrate further statistics in `update_stats`
- Connect to different repositories by changing `repo_url` and `repo_path`
- Improve error handling and user feedback in GUI

────────────────────────────────────────────

HOW TO RUN
────────────────────────────────────────────
Simply run:

    python3 gui_scanner.py

 
────────────────────────────────────────────

"""


 
import tkinter as tk
from tkinter import scrolledtext, ttk, messagebox, filedialog, font
import threading
import queue
import logging
from typing import List, Dict, Any
from datetime import datetime
import os
import json

from internet_scanner import InternetScannerExtractor


class GuiLogger(logging.Handler):
    """
    Custom logging handler for Tkinter Text widget.
    """

    def __init__(self, text_widget: tk.Text):
        """
        Initialize the handler.

        Args:
            text_widget (tk.Text): Text widget where logs will be displayed.
        """
        super().__init__()
        self.text_widget = text_widget

    def emit(self, record: logging.LogRecord):
        """
        Handle a log record.

        Args:
            record (logging.LogRecord): Log record.
        """
        msg = self.format(record)
        self.text_widget.after(0, self._append, msg)

    def _append(self, msg: str):
        """
        Append a message to the Text widget.

        Args:
            msg (str): Message to append.
        """
        self.text_widget.insert(tk.END, msg + "\n")
        self.text_widget.see(tk.END)


class InternetScannerGUI:
    """
    Tkinter-based GUI for Internet Scanners OSINT Tool.
    """

    def __init__(self, master: tk.Tk):
        """
        Initialize the GUI.

        Args:
            master (tk.Tk): The root Tkinter window.
        """
        self.master = master
        self.master.title("Internet Scanners OSINT Tool")

        self.queue = queue.Queue()

        # Default values
        self.logs_dir_var = tk.StringVar(value="logs/")
        self.results_dir_var = tk.StringVar(value="results/")
        self.json_file_var = tk.StringVar(value="internet_scanners_enriched.json")
        self.csv_file_var = tk.StringVar(value="internet_scanners_enriched.csv")
        self.use_multithread_var = tk.BooleanVar(value=True)
        self.abuseipdb_key_var = tk.StringVar(value="")
        self.enable_abuseipdb_var = tk.BooleanVar(value=False)
        self.throttle_var = tk.DoubleVar(value=0.0)

        self.create_widgets()
        self.inject_logger()
        self.set_styles()
        self.load_api_key()

        self.extractor = None

    def set_styles(self):
        """
        Apply styling to the GUI elements.
        """
        self.master.configure(bg="#f0f0f5")

        style = ttk.Style()
        style.configure("TLabel", font=("Segoe UI", 10))
        style.configure("TButton", font=("Segoe UI", 10))
        style.configure("TEntry", font=("Segoe UI", 10))
        style.configure("TLabelframe.Label", background="#2c3e50", foreground="white",
                        font=("Segoe UI", 11, "bold"))

        log_font = font.Font(family="Consolas", size=10)
        self.log_text.configure(font=log_font, background="#1e1e1e",
                                foreground="#d4d4d4", insertbackground="white")

    def inject_logger(self):
        """
        Configure the logger for GUI display.
        """
        self.logger = logging.getLogger("InternetScannerGUI")
        self.logger.setLevel(logging.DEBUG)

        gui_handler = GuiLogger(self.log_text)
        gui_handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s", "%H:%M:%S"))
        self.logger.handlers.clear()
        self.logger.addHandler(gui_handler)

    def create_widgets(self):
        """
        Create and place all widgets in the GUI.
        """
        frm_paths = ttk.LabelFrame(self.master, text="Paths and Filenames")
        frm_paths.pack(fill=tk.X, padx=10, pady=10)

        # Logs directory
        ttk.Label(frm_paths, text="Logs directory:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Entry(frm_paths, textvariable=self.logs_dir_var, width=50).grid(row=0, column=1, padx=5, pady=2)
        ttk.Button(frm_paths, text="Browse...", command=self.browse_logs_dir).grid(row=0, column=2, padx=5)

        # Results directory
        ttk.Label(frm_paths, text="Results directory:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Entry(frm_paths, textvariable=self.results_dir_var, width=50).grid(row=1, column=1, padx=5, pady=2)
        ttk.Button(frm_paths, text="Browse...", command=self.browse_results_dir).grid(row=1, column=2, padx=5)

        # JSON file
        ttk.Label(frm_paths, text="JSON file name:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Entry(frm_paths, textvariable=self.json_file_var, width=50).grid(row=2, column=1, columnspan=2, padx=5, pady=2)

        # CSV file
        ttk.Label(frm_paths, text="CSV file name:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Entry(frm_paths, textvariable=self.csv_file_var, width=50).grid(row=3, column=1, columnspan=2, padx=5, pady=2)

        # Multithreading checkbox
        ttk.Checkbutton(
            frm_paths,
            text="Enable multithreading",
            variable=self.use_multithread_var
        ).grid(row=4, column=0, columnspan=3, sticky=tk.W, padx=5, pady=5)

        # AbuseIPDB Enable checkbox
        ttk.Checkbutton(
            frm_paths,
            text="Enable AbuseIPDB lookups",
            variable=self.enable_abuseipdb_var
        ).grid(row=5, column=0, columnspan=3, sticky=tk.W, padx=5, pady=5)

        # Throttle delay
        ttk.Label(frm_paths, text="Throttle between AbuseIPDB calls (s):").grid(row=6, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Entry(frm_paths, textvariable=self.throttle_var, width=10).grid(row=6, column=1, sticky=tk.W, padx=5, pady=2)

        # AbuseIPDB API Key
        ttk.Label(frm_paths, text="AbuseIPDB API Key:").grid(row=7, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Entry(frm_paths, textvariable=self.abuseipdb_key_var, width=50, show="*").grid(row=7, column=1, padx=5, pady=2)
        ttk.Button(frm_paths, text="Save API Key", command=self.save_api_key).grid(row=7, column=2, padx=5, pady=2)

        frm_buttons = ttk.Frame(self.master)
        frm_buttons.pack(padx=10, pady=5)

        self.btn_update = ttk.Button(frm_buttons, text="Update DB", command=self.start_update)
        self.btn_update.grid(row=0, column=0, padx=5)

        self.btn_export = ttk.Button(frm_buttons, text="Export Data", command=self.start_export)
        self.btn_export.grid(row=0, column=1, padx=5)

        ttk.Label(self.master, text="Logs:").pack(anchor=tk.W, padx=10)

        self.log_text = scrolledtext.ScrolledText(self.master, height=15, width=100, state=tk.NORMAL)
        self.log_text.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)

        self.stats_var = tk.StringVar()
        ttk.Label(self.master, textvariable=self.stats_var, foreground="blue").pack(anchor=tk.W, padx=10, pady=5)

    def browse_logs_dir(self):
        path = filedialog.askdirectory()
        if path:
            self.logs_dir_var.set(path)

    def browse_results_dir(self):
        path = filedialog.askdirectory()
        if path:
            self.results_dir_var.set(path)

    def save_api_key(self):
        """
        Save the AbuseIPDB API key to a config file.
        """
        key = self.abuseipdb_key_var.get().strip()
        if not key:
            messagebox.showwarning("Save Key", "API key is empty.")
            return

        os.makedirs("config", exist_ok=True)
        config_path = os.path.join("config", "settings.json")

        try:
            with open(config_path, "w", encoding="utf-8") as f:
                json.dump({"abuseipdb_api_key": key}, f, indent=2)
            os.chmod(config_path, 0o600)
            messagebox.showinfo("Save Key", f"API key saved in {config_path}")
        except Exception as e:
            messagebox.showerror("Save Key", f"Error saving key: {e}")

    def load_api_key(self):
        """
        Load the AbuseIPDB API key from config if available.
        """
        config_path = os.path.join("config", "settings.json")
        if os.path.exists(config_path):
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                key = data.get("abuseipdb_api_key", "")
                self.abuseipdb_key_var.set(key)
                self.logger.info("Loaded AbuseIPDB API key from config.")
            except Exception as e:
                self.logger.warning(f"Error loading API key: {e}")

    def start_update(self):
        t = threading.Thread(target=self.update_repo, daemon=True)
        t.start()

    def start_export(self):
        t = threading.Thread(target=self.export_data, daemon=True)
        t.start()

    def create_extractor(self):
        logs_dir = self.logs_dir_var.get()
        results_dir = self.results_dir_var.get()
        json_file = self.json_file_var.get()
        csv_file = self.csv_file_var.get()
        use_multithread = self.use_multithread_var.get()
        abuse_key = self.abuseipdb_key_var.get().strip() or None
        enable_abuse = self.enable_abuseipdb_var.get()
        throttle = self.throttle_var.get()

        timestamp = datetime.now().strftime("%Y%m%d_%H%M")
        json_filename = f"{timestamp}_{json_file}"
        csv_filename = f"{timestamp}_{csv_file}"

        json_path = os.path.join(results_dir, json_filename)
        csv_path = os.path.join(results_dir, csv_filename)

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
            throttle=throttle
        )

        self.extractor.logger.handlers.clear()
        gui_handler = GuiLogger(self.log_text)
        gui_handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s", "%H:%M:%S"))
        self.extractor.logger.addHandler(gui_handler)
        self.extractor.logger.setLevel(logging.DEBUG)

    def update_repo(self):
        self.create_extractor()
        self.extractor.git_clone_or_pull()
        data = self.extractor.parse_files()
        self.extractor.save_json(data)
        self.extractor.save_csv(data)
        self.extractor.summarize_stats(data)
        self.update_stats(data)

        messagebox.showinfo(
            "Export Complete",
            f"JSON and CSV saved in {self.results_dir_var.get()}"
        )

    def export_data(self):
        self.create_extractor()
        try:
            json_path = self.extractor.output_json
            csv_path = self.extractor.output_csv

            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            self.extractor.save_csv(data, csv_path)
            self.update_stats(data)

            messagebox.showinfo(
                "Export Complete",
                f"CSV saved at:\n{csv_path}"
            )

        except Exception as e:
            messagebox.showerror("Error", f"Export failed: {e}")

    def update_stats(self, data: List[Dict[str, Any]]) -> None:
        total = len(data)
        ipv4_count = sum(1 for item in data if ":" not in item["ip_or_cidr"])
        ipv6_count = total - ipv4_count
        abuse_count = sum(
            1 for item in data
            if item.get("abuseConfidenceScore", 0) and item["abuseConfidenceScore"] > 0
        )
        stats_msg = f"Total IPs: {total} | IPv4: {ipv4_count} | IPv6: {ipv6_count} | Reported in AbuseIPDB: {abuse_count}"
        self.stats_var.set(stats_msg)


def main():
    root = tk.Tk()
    app = InternetScannerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
