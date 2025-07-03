#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
──────────────────────────────────────────────
 Reverse MX Lookup Tool - GUI Version
──────────────────────────────────────────────

Author:
    m00gly

Description:
    This graphical user interface (GUI) provides an
    interactive frontend for the Reverse MX Lookup Tool.
    It allows users to easily perform MX lookups and
    reverse MX lookups without needing to type CLI commands.

    The GUI offers:
        - Mode selection (MX Lookup or Reverse MX Lookup)
        - Provider selection for reverse MX lookups
        - Single target entry or selection of a file
        - Multithreading toggle
        - Throttle configuration
        - Live log display
        - CSV export of results
        - Preview of CSV results directly in the interface

Main Features:
    - Two separate result windows:
        • Logs Window for real-time logs
        • Result Preview Window showing CSV content
    - Save and load API configuration for external services
    - Integration with the CLI tool for executing lookups
    - All CLI options are accessible via the GUI
    - Graceful error handling with popups

Usage:
    Run the GUI script directly:

        python3 gui_Reverse_MX_Lookup_Tool.py

    Example workflow:
        - Choose "mx_lookup" or "reverse_mx" from the Mode dropdown
        - Enter a target domain or MX server
        - (Optional) Choose a provider for reverse lookups
        - (Optional) Enable or disable multithreading
        - (Optional) Set throttle between requests
        - Click "Run" to start the lookup
        - View logs in the Logs window
        - Optionally export and preview results as CSV

Dependencies:
    - Python 3.x
    - tkinter (standard library)
    - ttk (standard library)
    - The CLI tool (cli_Reverse_MX_Lookup_Tool.py)
    - Additional libraries used in the CLI tool:
        • requests
        • dns.resolver
        • ipwhois

Logs:
    Logs are displayed in real-time in the GUI and saved
    to a log file (e.g. logs/reverse_mx_tool.log).

"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import subprocess
import threading
import os
import json
from typing import Optional


class ReverseMXGUI:
    def __init__(self, master: tk.Tk):
        self.master = master
        self.master.title("Reverse MX Lookup Tool")

        self._create_styles()
        self._create_widgets()

    def _create_styles(self) -> None:
        self.master.configure(bg="#f0f0f5")
        style = ttk.Style()
        style.configure("TLabel", font=("Segoe UI", 10))
        style.configure("TButton", font=("Segoe UI", 10))
        style.configure("TEntry", font=("Segoe UI", 10))
        style.configure("TLabelframe.Label", background="#2c3e50", foreground="white",
                        font=("Segoe UI", 11, "bold"))

    def _create_widgets(self) -> None:
        """
        Create all widgets for the main GUI window, including:

        - Input fields for lookup mode, target domain or MX host
        - File selector for batch targets file
        - Provider selection for reverse MX lookups
        - Throttle input
        - Multithreading toggle
        - Buttons to:
            - Run the lookup
            - Open the API Settings window
            - Save CSV results
        - Live log display
        - Results preview area

        This method organizes widgets in logical sections and connects them
        to the relevant event handlers.

        The API Settings button allows users to enter or update API keys
        for ViewDNS, DomainTools, and WhoisXML, which are saved in
        config/settings.json.

        """
        # Frame for lookup options
        frm = ttk.LabelFrame(self.master, text="Lookup Options")
        frm.pack(fill=tk.X, padx=10, pady=10)

        # Lookup mode dropdown
        ttk.Label(frm, text="Mode:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.combo_mode = ttk.Combobox(
            frm,
            values=["mx_lookup", "reverse_mx"],
            state="readonly",
            width=20
        )
        self.combo_mode.grid(row=0, column=1, padx=5, pady=5)
        self.combo_mode.set("mx_lookup")

        # Target single entry
        ttk.Label(frm, text="Target (domain or MX host):").grid(
            row=1, column=0, sticky=tk.W, padx=5, pady=5
        )
        self.entry_target = ttk.Entry(frm, width=50)
        self.entry_target.grid(row=1, column=1, padx=5, pady=5)

        # Targets file entry
        ttk.Label(frm, text="Or targets file:").grid(
            row=2, column=0, sticky=tk.W, padx=5, pady=5
        )
        self.entry_targets_file = ttk.Entry(frm, width=50)
        self.entry_targets_file.grid(row=2, column=1, padx=5, pady=5)

        ttk.Button(
            frm,
            text="Browse...",
            command=self.browse_targets_file
        ).grid(row=2, column=2, padx=5, pady=5)

        # Provider dropdown
        ttk.Label(frm, text="Provider:").grid(
            row=3, column=0, sticky=tk.W, padx=5, pady=5
        )
        self.combo_provider = ttk.Combobox(
            frm,
            values=["ViewDNS", "DomainTools", "WhoisXML"],
            state="readonly",
            width=20
        )
        self.combo_provider.grid(row=3, column=1, padx=5, pady=5)
        self.combo_provider.set("ViewDNS")

        # Throttle input
        ttk.Label(frm, text="Throttle (sec):").grid(
            row=4, column=0, sticky=tk.W, padx=5, pady=5
        )
        self.entry_throttle = ttk.Entry(frm, width=10)
        self.entry_throttle.insert(0, "0.0")
        self.entry_throttle.grid(row=4, column=1, padx=5, pady=5, sticky=tk.W)

        # Multithreading checkbox
        self.var_multithread = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            frm,
            text="Use multithreading",
            variable=self.var_multithread
        ).grid(row=5, column=0, columnspan=2, sticky=tk.W, padx=5, pady=5)

        # Run button
        ttk.Button(
            frm,
            text="Run",
            command=self.start_process
        ).grid(row=6, column=1, sticky=tk.E, padx=5, pady=5)

        # API Settings button
        ttk.Button(
            frm,
            text="API Settings",
            command=self.open_settings_window
        ).grid(row=6, column=2, sticky=tk.W, padx=5, pady=5)

        # Logs label
        ttk.Label(self.master, text="Logs:").pack(anchor=tk.W, padx=10)

        # Logs scrolled text
        self.log_text = scrolledtext.ScrolledText(
            self.master,
            height=10,
            width=100,
            background="#1e1e1e",
            foreground="#d4d4d4",
            font=("Consolas", 10)
        )
        self.log_text.pack(padx=10, pady=5, fill=tk.BOTH, expand=False)

        # Results label
        ttk.Label(self.master, text="Results JSON  Preview:").pack(anchor=tk.W, padx=10)

        # Results scrolled text
        self.result_text = scrolledtext.ScrolledText(
            self.master,
            height=12,
            width=100,
            background="#e8e8e8",
            foreground="#333333",
            font=("Consolas", 10)
        )
        self.result_text.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)

        # Save results button
        ttk.Button(
            self.master,
            text="Save Results to CSV",
            command=self.save_results
        ).pack(anchor=tk.E, padx=10, pady=5)

        # Storage for last CSV content
        self.last_csv_content = ""

    def browse_targets_file(self) -> None:
        path = filedialog.askopenfilename(
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if path:
            self.entry_targets_file.delete(0, tk.END)
            self.entry_targets_file.insert(0, path)

    def start_process(self) -> None:
        """
        Builds the CLI command and starts it in a separate thread.
        """
        cli_path = os.path.join(
            os.path.dirname(__file__),
            "cli_Reverse_MX_Lookup_Tool.py"
        )

        if not os.path.exists(cli_path):
            messagebox.showerror("Error", f"CLI script not found:\n{cli_path}")
            return

        args = ["python3", cli_path]

        # Récupère tous les champs
        mode = self.combo_mode.get()
        target = self.entry_target.get().strip()
        targets_file = getattr(self, "entry_targets_file", None)
        targets_file_val = targets_file.get().strip() if targets_file else ""
        provider = self.combo_provider.get()
        throttle = self.entry_throttle.get().strip()

        # Blindage
        if not target and not targets_file_val:
            messagebox.showerror("Error", "Either a single target or a targets file is required.")
            return

        if target and targets_file_val:
            messagebox.showerror("Error", "Do not specify both target and targets file at the same time.")
            return

        # Mode
        args.extend(["--mode", mode])

        # Target ou targets file
        if target:
            args.extend(["--target", target])
        else:
            args.extend(["--targets-file", targets_file_val])

        # Provider (requis en reverse_mx)
        if mode == "reverse_mx":
            if not provider:
                messagebox.showerror("Error", "Provider is required in reverse_mx mode.")
                return
            args.extend(["--provider", provider])

        # Multithread
        if self.var_multithread.get() is False:
            args.append("--no-multithread")

        # Throttle
        if throttle and throttle != "0.0":
            args.extend(["--throttle", throttle])

        # CSV export
        csv_path = None
        if messagebox.askyesno("Export", "Export results to CSV?"):
            csv_path = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv")]
            )
            if csv_path:
                args.extend(["--export-csv", csv_path])

        # Clear previous logs and results
        self.log_text.delete("1.0", tk.END)
        self.result_text.delete("1.0", tk.END)

        # Exécute dans un thread
        threading.Thread(target=self.run_cli, args=(args, csv_path), daemon=True).start()

    
    def browse_targets_file(self):
        path = filedialog.askopenfilename(
            title="Select Targets File",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if path:
            self.entry_targets_file.delete(0, tk.END)
            self.entry_targets_file.insert(0, path)


    def run_cli(self, args: list, csv_path: Optional[str]) -> None:
        """
        Runs the CLI process and updates GUI widgets live.
        """
        try:
            process = subprocess.Popen(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )

            json_output = []
            capture_json = False

            for line in iter(process.stdout.readline, ""):
                line_clean = line.rstrip("\n")
                self.log_text.insert(tk.END, line_clean + "\n")
                self.log_text.see(tk.END)

                # Détecter début JSON si affiché sur stdout
                if line_clean.startswith("["):
                    capture_json = True
                if capture_json:
                    json_output.append(line_clean)

            process.stdout.close()
            process.wait()

            # Si on a un CSV sauvegardé
            if csv_path and os.path.exists(csv_path):
                with open(csv_path, "r", encoding="utf-8") as f:
                    csv_content = f.read()
                    self.result_text.insert(tk.END, csv_content)
                    self.result_text.see(tk.END)
            # Sinon, on essaie d'afficher le JSON collecté
            elif json_output:
                pretty_json = "\n".join(json_output)
                self.result_text.insert(tk.END, pretty_json)
                self.result_text.see(tk.END)
            else:
                self.result_text.insert(tk.END, "⚠️ No results to preview.\n")
                self.result_text.see(tk.END)

        except Exception as e:
            self.log_text.insert(tk.END, f"[ERROR] {str(e)}\n")
            self.log_text.see(tk.END)


    def save_results(self) -> None:
        """
        Save last results preview to a chosen CSV file.
        """
        if not self.last_csv_content:
            messagebox.showwarning("Save", "No data to save yet.")
            return

        save_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")]
        )
        if save_path:
            with open(save_path, "w", encoding="utf-8") as f:
                f.write(self.last_csv_content)
            messagebox.showinfo("Save", f"Results saved to:\n{save_path}")
    def open_settings_window(self):
        """
        Open a popup window to edit API keys.
        """
        settings_win = tk.Toplevel(self.master)
        settings_win.title("API Settings")

        # Champs ViewDNS
        ttk.Label(settings_win, text="ViewDNS API Key:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        entry_viewdns = ttk.Entry(settings_win, width=50)
        entry_viewdns.grid(row=0, column=1, padx=5, pady=5)

        # Champs DomainTools
        ttk.Label(settings_win, text="DomainTools Username:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        entry_dt_user = ttk.Entry(settings_win, width=50)
        entry_dt_user.grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(settings_win, text="DomainTools API Key:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        entry_dt_key = ttk.Entry(settings_win, width=50, show="*")
        entry_dt_key.grid(row=2, column=1, padx=5, pady=5)

        # Champs WhoisXML
        ttk.Label(settings_win, text="WhoisXML API Key:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
        entry_whoisxml = ttk.Entry(settings_win, width=50, show="*")
        entry_whoisxml.grid(row=3, column=1, padx=5, pady=5)

        # Charger valeurs existantes
        config_path = os.path.join("config", "settings.json")
        if os.path.exists(config_path):
            with open(config_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                entry_viewdns.insert(0, data.get("viewdns_api_key", ""))
                entry_dt_user.insert(0, data.get("domaintools_api_user", ""))
                entry_dt_key.insert(0, data.get("domaintools_api_key", ""))
                entry_whoisxml.insert(0, data.get("whoisxml_api_key", ""))

        def save_settings():
            settings = {
                "viewdns_api_key": entry_viewdns.get().strip(),
                "domaintools_api_user": entry_dt_user.get().strip(),
                "domaintools_api_key": entry_dt_key.get().strip(),
                "whoisxml_api_key": entry_whoisxml.get().strip()
            }
            os.makedirs("config", exist_ok=True)
            with open(config_path, "w", encoding="utf-8") as f:
                json.dump(settings, f, indent=4)
            messagebox.showinfo("Settings", "API keys saved successfully.")
            settings_win.destroy()

        ttk.Button(settings_win, text="Save", command=save_settings).grid(
            row=4, column=1, sticky=tk.E, padx=5, pady=10
        )


def main() -> None:
    root = tk.Tk()
    app = ReverseMXGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
