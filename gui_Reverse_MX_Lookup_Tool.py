#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Reverse MX Lookup Tool — Tkinter GUI

Author:  m00gly
License: MIT
Repo:    https://github.com/mo0ogly/Internet-Scanners-OSINT-Tool

Run:  python3 gui_Reverse_MX_Lookup_Tool.py
"""

import os
import subprocess
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

from gui_common import (
    PAD_X,
    PAD_Y,
    StatusBar,
    ToolTip,
    apply_styles,
    create_menu_bar,
    get_mono_font,
    load_config,
    save_config,
    style_log_widget,
)


class ReverseMXGUI:
    def __init__(self, master: tk.Tk):
        self.master = master
        self.master.title("Reverse MX Lookup Tool")
        self.master.minsize(800, 600)
        self.master.geometry("900x650")

        # Cancel / running state
        self._process = None
        self._running = False

        # Variables
        self.var_multithread = tk.BooleanVar(value=True)
        self.show_viewdns_key_var = tk.BooleanVar(value=False)
        self.show_dt_key_var = tk.BooleanVar(value=False)
        self.show_whoisxml_key_var = tk.BooleanVar(value=False)

        # API key variables
        self.viewdns_key_var = tk.StringVar()
        self.dt_user_var = tk.StringVar()
        self.dt_key_var = tk.StringVar()
        self.whoisxml_key_var = tk.StringVar()

        apply_styles(self.master)
        create_menu_bar(self.master, "Reverse MX Lookup Tool")
        self._create_widgets()
        self._load_api_keys()
        self._bind_shortcuts()

    # ── Widgets ───────────────────────────────────────────────────────────

    def _create_widgets(self) -> None:
        # Notebook
        self.notebook = ttk.Notebook(self.master)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=PAD_X, pady=PAD_Y)

        # Tab 1 — Lookup
        tab_lookup = ttk.Frame(self.notebook)
        self.notebook.add(tab_lookup, text="Lookup")
        self._build_lookup_tab(tab_lookup)

        # Tab 2 — Results
        tab_results = ttk.Frame(self.notebook)
        self.notebook.add(tab_results, text="Results")
        self._build_results_tab(tab_results)

        # Tab 3 — API Settings
        tab_api = ttk.Frame(self.notebook)
        self.notebook.add(tab_api, text="API Settings")
        self._build_api_tab(tab_api)

        # Tab 4 — Logs
        tab_logs = ttk.Frame(self.notebook)
        self.notebook.add(tab_logs, text="Logs")
        self._build_logs_tab(tab_logs)

        # Button bar
        frm_buttons = ttk.Frame(self.master)
        frm_buttons.pack(fill=tk.X, padx=PAD_X, pady=PAD_Y)

        self.btn_run = ttk.Button(frm_buttons, text="Run", command=self.start_process)
        self.btn_run.pack(side=tk.LEFT, padx=4)

        # Status bar
        self.status_bar = StatusBar(self.master)
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM, padx=PAD_X, pady=(0, PAD_Y))

    def _build_lookup_tab(self, parent: ttk.Frame) -> None:
        parent.columnconfigure(1, weight=1)

        row = 0

        # Mode
        ttk.Label(parent, text="Mode:").grid(row=row, column=0, sticky=tk.W, padx=PAD_X, pady=PAD_Y)
        self.combo_mode = ttk.Combobox(parent, values=["mx_lookup", "reverse_mx"], state="readonly", width=20)
        self.combo_mode.grid(row=row, column=1, sticky=tk.W, padx=PAD_X, pady=PAD_Y)
        self.combo_mode.set("mx_lookup")
        row += 1

        # Target
        ttk.Label(parent, text="Target (domain or MX host):").grid(
            row=row, column=0, sticky=tk.W, padx=PAD_X, pady=PAD_Y,
        )
        self.entry_target = ttk.Entry(parent)
        self.entry_target.grid(row=row, column=1, sticky=tk.EW, padx=PAD_X, pady=PAD_Y)
        row += 1

        # Targets file
        ttk.Label(parent, text="Or targets file:").grid(row=row, column=0, sticky=tk.W, padx=PAD_X, pady=PAD_Y)
        self.entry_targets_file = ttk.Entry(parent)
        self.entry_targets_file.grid(row=row, column=1, sticky=tk.EW, padx=PAD_X, pady=PAD_Y)
        ttk.Button(parent, text="Browse...", command=self._browse_targets_file).grid(
            row=row, column=2, padx=PAD_X, pady=PAD_Y,
        )
        row += 1

        # Provider
        ttk.Label(parent, text="Provider:").grid(row=row, column=0, sticky=tk.W, padx=PAD_X, pady=PAD_Y)
        self.combo_provider = ttk.Combobox(
            parent, values=["ViewDNS", "DomainTools", "WhoisXML"], state="readonly", width=20,
        )
        self.combo_provider.grid(row=row, column=1, sticky=tk.W, padx=PAD_X, pady=PAD_Y)
        self.combo_provider.set("ViewDNS")
        row += 1

        # Throttle
        ttk.Label(parent, text="Throttle (sec):").grid(row=row, column=0, sticky=tk.W, padx=PAD_X, pady=PAD_Y)
        self.entry_throttle = ttk.Entry(parent, width=10)
        self.entry_throttle.insert(0, "0.0")
        self.entry_throttle.grid(row=row, column=1, sticky=tk.W, padx=PAD_X, pady=PAD_Y)
        ToolTip(self.entry_throttle, "Delay between API calls (0 = no delay)")
        row += 1

        # Multithreading
        ttk.Checkbutton(parent, text="Use multithreading", variable=self.var_multithread).grid(
            row=row, column=0, columnspan=3, sticky=tk.W, padx=PAD_X, pady=PAD_Y,
        )

    def _build_results_tab(self, parent: ttk.Frame) -> None:
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(1, weight=1)

        ttk.Label(parent, text="Results Preview:").grid(row=0, column=0, sticky=tk.W, padx=PAD_X, pady=PAD_Y)

        self.result_text = scrolledtext.ScrolledText(parent, height=12)
        self.result_text.grid(row=1, column=0, sticky="nsew", padx=PAD_X, pady=(0, PAD_Y))
        mono = get_mono_font(10)
        self.result_text.configure(
            font=mono, background="#e8e8e8", foreground="#333333",
            selectbackground="#264f78", selectforeground="#ffffff",
        )

        ttk.Button(parent, text="Save Results to CSV", command=self._save_results).grid(
            row=2, column=0, sticky=tk.E, padx=PAD_X, pady=PAD_Y,
        )

    def _build_api_tab(self, parent: ttk.Frame) -> None:
        parent.columnconfigure(1, weight=1)

        row = 0

        # ViewDNS
        ttk.Label(parent, text="ViewDNS API Key:").grid(row=row, column=0, sticky=tk.W, padx=PAD_X, pady=PAD_Y)
        frm_vd = ttk.Frame(parent)
        frm_vd.grid(row=row, column=1, sticky=tk.EW, padx=PAD_X, pady=PAD_Y)
        frm_vd.columnconfigure(0, weight=1)
        self.entry_viewdns = ttk.Entry(frm_vd, textvariable=self.viewdns_key_var, show="*")
        self.entry_viewdns.grid(row=0, column=0, sticky=tk.EW)
        ToolTip(self.entry_viewdns, "Stored in config/settings.json")
        ttk.Checkbutton(frm_vd, text="Show", variable=self.show_viewdns_key_var,
                         command=lambda: self.entry_viewdns.configure(
                             show="" if self.show_viewdns_key_var.get() else "*")).grid(row=0, column=1, padx=(4, 0))
        row += 1

        # DomainTools user
        ttk.Label(parent, text="DomainTools Username:").grid(row=row, column=0, sticky=tk.W, padx=PAD_X, pady=PAD_Y)
        ttk.Entry(parent, textvariable=self.dt_user_var).grid(
            row=row, column=1, sticky=tk.EW, padx=PAD_X, pady=PAD_Y,
        )
        row += 1

        # DomainTools key
        ttk.Label(parent, text="DomainTools API Key:").grid(row=row, column=0, sticky=tk.W, padx=PAD_X, pady=PAD_Y)
        frm_dt = ttk.Frame(parent)
        frm_dt.grid(row=row, column=1, sticky=tk.EW, padx=PAD_X, pady=PAD_Y)
        frm_dt.columnconfigure(0, weight=1)
        self.entry_dt_key = ttk.Entry(frm_dt, textvariable=self.dt_key_var, show="*")
        self.entry_dt_key.grid(row=0, column=0, sticky=tk.EW)
        ToolTip(self.entry_dt_key, "Stored in config/settings.json")
        ttk.Checkbutton(frm_dt, text="Show", variable=self.show_dt_key_var,
                         command=lambda: self.entry_dt_key.configure(
                             show="" if self.show_dt_key_var.get() else "*")).grid(row=0, column=1, padx=(4, 0))
        row += 1

        # WhoisXML
        ttk.Label(parent, text="WhoisXML API Key:").grid(row=row, column=0, sticky=tk.W, padx=PAD_X, pady=PAD_Y)
        frm_wx = ttk.Frame(parent)
        frm_wx.grid(row=row, column=1, sticky=tk.EW, padx=PAD_X, pady=PAD_Y)
        frm_wx.columnconfigure(0, weight=1)
        self.entry_whoisxml = ttk.Entry(frm_wx, textvariable=self.whoisxml_key_var, show="*")
        self.entry_whoisxml.grid(row=0, column=0, sticky=tk.EW)
        ToolTip(self.entry_whoisxml, "Stored in config/settings.json")
        ttk.Checkbutton(frm_wx, text="Show", variable=self.show_whoisxml_key_var,
                         command=lambda: self.entry_whoisxml.configure(
                             show="" if self.show_whoisxml_key_var.get() else "*")).grid(row=0, column=1, padx=(4, 0))
        row += 1

        # Save button
        ttk.Button(parent, text="Save API Keys", command=self._save_api_keys).grid(
            row=row, column=1, sticky=tk.E, padx=PAD_X, pady=PAD_Y,
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
        self.master.bind("<Control-r>", lambda _e: self.start_process())
        self.master.bind("<Control-s>", lambda _e: self._save_results())
        self.master.bind("<Control-l>", lambda _e: self._clear_logs())
        self.master.bind("<Control-q>", lambda _e: self.master.destroy())
        self.master.bind("<Escape>", lambda _e: self._cancel())

    # ── Browsing ──────────────────────────────────────────────────────────

    def _browse_targets_file(self) -> None:
        path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if path:
            self.entry_targets_file.delete(0, tk.END)
            self.entry_targets_file.insert(0, path)

    # ── API keys ──────────────────────────────────────────────────────────

    def _load_api_keys(self) -> None:
        data = load_config()
        self.viewdns_key_var.set(data.get("viewdns_api_key", ""))
        self.dt_user_var.set(data.get("domaintools_api_user", ""))
        self.dt_key_var.set(data.get("domaintools_api_key", ""))
        self.whoisxml_key_var.set(data.get("whoisxml_api_key", ""))

    def _save_api_keys(self) -> None:
        try:
            save_config({
                "viewdns_api_key": self.viewdns_key_var.get().strip(),
                "domaintools_api_user": self.dt_user_var.get().strip(),
                "domaintools_api_key": self.dt_key_var.get().strip(),
                "whoisxml_api_key": self.whoisxml_key_var.get().strip(),
            })
            messagebox.showinfo("Settings", "API keys saved successfully.")
        except Exception as e:
            messagebox.showerror("Settings", f"Error saving keys: {e}")

    # ── Logs ──────────────────────────────────────────────────────────────

    def _clear_logs(self) -> None:
        self.log_text.delete("1.0", tk.END)

    def _log(self, msg: str) -> None:
        """Thread-safe log append."""
        self.master.after(0, self._log_append, msg)

    def _log_append(self, msg: str) -> None:
        self.log_text.insert(tk.END, msg + "\n")
        self.log_text.see(tk.END)

    # ── Validation ────────────────────────────────────────────────────────

    def _validate_inputs(self) -> bool:
        mode = self.combo_mode.get().strip()
        target = self.entry_target.get().strip()
        targets_file = self.entry_targets_file.get().strip()

        if not mode:
            messagebox.showerror("Validation", "Mode is required.")
            return False
        if not target and not targets_file:
            messagebox.showerror("Validation", "Either a single target or a targets file is required.")
            return False
        if target and targets_file:
            messagebox.showerror("Validation", "Do not specify both a target and a targets file.")
            return False
        if mode == "reverse_mx" and not self.combo_provider.get().strip():
            messagebox.showerror("Validation", "Provider is required in reverse_mx mode.")
            return False

        throttle_str = self.entry_throttle.get().strip()
        try:
            if float(throttle_str) < 0:
                messagebox.showerror("Validation", "Throttle must be >= 0.")
                return False
        except ValueError:
            messagebox.showerror("Validation", "Throttle must be a number.")
            return False

        return True

    # ── Cancel ────────────────────────────────────────────────────────────

    def _cancel(self) -> None:
        if self._process and self._running:
            try:
                self._process.terminate()
            except OSError:
                pass
            self._log("[INFO] Process cancelled by user.")

    # ── Run ───────────────────────────────────────────────────────────────

    def start_process(self) -> None:
        if self._running or not self._validate_inputs():
            return

        base_dir = os.path.dirname(os.path.abspath(__file__))
        cli_path = os.path.join(base_dir, "cli_Reverse_MX_Lookup_Tool.py")

        if not os.path.exists(cli_path):
            messagebox.showerror("Error", f"CLI script not found:\n{cli_path}")
            return

        args = ["python3", cli_path]

        mode = self.combo_mode.get().strip()
        target = self.entry_target.get().strip()
        targets_file = self.entry_targets_file.get().strip()
        provider = self.combo_provider.get().strip()
        throttle = self.entry_throttle.get().strip()

        args.extend(["--mode", mode])

        if target:
            args.extend(["--target", target])
        else:
            args.extend(["--targets-file", targets_file])

        if mode == "reverse_mx":
            args.extend(["--provider", provider])

        if self.var_multithread.get() is False:
            args.append("--no-multithread")

        if throttle and throttle != "0.0":
            args.extend(["--throttle", throttle])

        # Export option — uses --export-csv (the only flag the CLI supports)
        export_path = None
        if messagebox.askyesno("Export", "Export results to CSV?"):
            export_path = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv")],
            )
            if export_path:
                args.extend(["--export-csv", export_path])

        # Clear logs and results
        self.log_text.delete("1.0", tk.END)
        self.result_text.delete("1.0", tk.END)
        self._log(f"[INFO] Launching CLI with command:\n{' '.join(args)}")

        self._set_running(True)
        self.status_bar.start("Running lookup...", self._cancel)

        threading.Thread(target=self._run_cli, args=(args, export_path), daemon=True).start()

    def _set_running(self, running: bool) -> None:
        self._running = running
        self.btn_run.configure(state=tk.DISABLED if running else tk.NORMAL)

    def _run_cli(self, args: list, csv_path: str | None) -> None:
        """Run the CLI process and update GUI widgets live (thread-safe)."""
        try:
            self._process = subprocess.Popen(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )

            json_output: list[str] = []
            capture_json = False

            for line in iter(self._process.stdout.readline, ""):
                line_clean = line.rstrip("\n")
                self._log(line_clean)

                if line_clean.startswith("["):
                    capture_json = True
                if capture_json:
                    json_output.append(line_clean)

            self._process.stdout.close()
            self._process.wait()

            # Populate results preview
            def _fill_results():
                if csv_path and os.path.exists(csv_path):
                    with open(csv_path, encoding="utf-8") as f:
                        self.result_text.insert(tk.END, f.read())
                elif json_output:
                    self.result_text.insert(tk.END, "\n".join(json_output))
                else:
                    self.result_text.insert(tk.END, "No results to preview.\n")
                self.result_text.see(tk.END)
                # Switch to Results tab
                self.notebook.select(1)

            self.master.after(0, _fill_results)

        except Exception as e:
            self._log(f"[ERROR] {e}")
        finally:
            self._process = None
            self.master.after(0, self._set_running, False)
            self.master.after(0, self.status_bar.stop, "Ready")

    # ── Save results ──────────────────────────────────────────────────────

    def _save_results(self) -> None:
        """Save the current results preview text to a CSV file."""
        content = self.result_text.get("1.0", tk.END).strip()
        if not content:
            messagebox.showwarning("Save", "No data to save yet.")
            return

        save_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
        )
        if save_path:
            with open(save_path, "w", encoding="utf-8") as f:
                f.write(content)
            messagebox.showinfo("Save", f"Results saved to:\n{save_path}")


def main() -> None:
    root = tk.Tk()
    ReverseMXGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
