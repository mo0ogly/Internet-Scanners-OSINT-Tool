#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Shared GUI utilities for Internet Scanners OSINT Tool.

Provides cross-platform fonts, styles, logging, thread-safe helpers,
StatusBar, ToolTip, and config management used by both GUIs.
"""

import json
import logging
import os
import platform
import tkinter as tk
from tkinter import font as tkfont
from tkinter import messagebox, ttk

# ─── Constants ───────────────────────────────────────────────────────────────

APP_VERSION = "1.1.0"
APP_AUTHOR = "m00gly"
APP_REPO = "https://github.com/mo0ogly/Internet-Scanners-OSINT-Tool"

PAD_X = 8
PAD_Y = 4

_CONFIG_DIR = "config"
_CONFIG_FILE = "settings.json"

# ─── Cross-platform fonts ────────────────────────────────────────────────────


def _best_available_font(families: list[str], fallback: str) -> str:
    """Return the first available font family, or *fallback*."""
    available = set(tkfont.families())
    for fam in families:
        if fam in available:
            return fam
    return fallback


def get_ui_font(size: int = 10, bold: bool = False) -> tuple:
    """Return a cross-platform proportional font tuple."""
    system = platform.system()
    if system == "Windows":
        candidates = ["Segoe UI", "Calibri", "Helvetica"]
    elif system == "Darwin":
        candidates = ["Helvetica Neue", "Helvetica", "Arial"]
    else:
        candidates = ["DejaVu Sans", "Noto Sans", "Liberation Sans", "Helvetica"]
    family = _best_available_font(candidates, "TkDefaultFont")
    weight = "bold" if bold else "normal"
    return (family, size, weight)


def get_mono_font(size: int = 10) -> tuple:
    """Return a cross-platform monospace font tuple."""
    system = platform.system()
    if system == "Windows":
        candidates = ["Consolas", "Courier New"]
    elif system == "Darwin":
        candidates = ["Menlo", "Monaco", "Courier New"]
    else:
        candidates = ["DejaVu Sans Mono", "Liberation Mono", "Noto Mono", "Courier"]
    family = _best_available_font(candidates, "TkFixedFont")
    return (family, size)


# ─── Styles ──────────────────────────────────────────────────────────────────


def apply_styles(master: tk.Tk) -> None:
    """Apply the shared ttk theme to *master*."""
    master.configure(bg="#f0f0f5")
    style = ttk.Style()
    ui = get_ui_font(10)
    ui_bold = get_ui_font(11, bold=True)
    style.configure("TLabel", font=ui)
    style.configure("TButton", font=ui)
    style.configure("TEntry", font=ui)
    style.configure("TCheckbutton", font=ui)
    style.configure("TLabelframe.Label", background="#2c3e50", foreground="white", font=ui_bold)
    style.configure("TNotebook.Tab", font=ui, padding=[10, 4])


def style_log_widget(widget: tk.Text) -> None:
    """Apply the dark log theme to a Text / ScrolledText widget."""
    mono = get_mono_font(10)
    widget.configure(
        font=mono,
        background="#1e1e1e",
        foreground="#d4d4d4",
        insertbackground="white",
        selectbackground="#264f78",
        selectforeground="#ffffff",
    )


# ─── Config helpers ──────────────────────────────────────────────────────────


def _config_path() -> str:
    base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, _CONFIG_DIR, _CONFIG_FILE)


def load_config() -> dict:
    """Load *config/settings.json*, returning {} on any error."""
    path = _config_path()
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_config(data: dict) -> None:
    """Merge *data* into *config/settings.json* and set chmod 600."""
    path = _config_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    existing = load_config()
    existing.update(data)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(existing, f, indent=2)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass  # Windows may not support chmod


# ─── Thread-safe messagebox wrappers ─────────────────────────────────────────


def show_info_threadsafe(master: tk.Tk, title: str, message: str) -> None:
    """Show an info messagebox on the main thread."""
    master.after(0, lambda: messagebox.showinfo(title, message))


def show_error_threadsafe(master: tk.Tk, title: str, message: str) -> None:
    """Show an error messagebox on the main thread."""
    master.after(0, lambda: messagebox.showerror(title, message))


def show_warning_threadsafe(master: tk.Tk, title: str, message: str) -> None:
    """Show a warning messagebox on the main thread."""
    master.after(0, lambda: messagebox.showwarning(title, message))


# ─── GuiLogger ───────────────────────────────────────────────────────────────


class GuiLogger(logging.Handler):
    """Logging handler that appends messages to a Tkinter Text widget (thread-safe)."""

    def __init__(self, text_widget: tk.Text):
        super().__init__()
        self.text_widget = text_widget

    def emit(self, record: logging.LogRecord) -> None:
        msg = self.format(record)
        self.text_widget.after(0, self._append, msg)

    def _append(self, msg: str) -> None:
        self.text_widget.insert(tk.END, msg + "\n")
        self.text_widget.see(tk.END)


# ─── StatusBar ───────────────────────────────────────────────────────────────


class StatusBar(ttk.Frame):
    """Bottom status bar with label, indeterminate progress bar, and Cancel button."""

    def __init__(self, master: tk.Misc, **kw):
        super().__init__(master, **kw)

        self._status_var = tk.StringVar(value="Ready")
        self._label = ttk.Label(self, textvariable=self._status_var, width=30, anchor=tk.W)
        self._label.pack(side=tk.LEFT, padx=(PAD_X, 4))

        self._progress = ttk.Progressbar(self, mode="indeterminate", length=200)
        self._progress.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)

        self._cancel_btn = ttk.Button(self, text="Cancel", state=tk.DISABLED, command=self._on_cancel)
        self._cancel_btn.pack(side=tk.RIGHT, padx=(4, PAD_X))

        self._cancel_callback = None

    # Public API

    def start(self, message: str = "Working...", cancel_callback=None) -> None:
        """Begin an operation: animate progress bar, set status, enable cancel."""
        self._status_var.set(message)
        self._progress.start(15)
        self._cancel_callback = cancel_callback
        self._cancel_btn.configure(state=tk.NORMAL if cancel_callback else tk.DISABLED)

    def stop(self, message: str = "Ready") -> None:
        """End the current operation."""
        self._progress.stop()
        self._status_var.set(message)
        self._cancel_btn.configure(state=tk.DISABLED)
        self._cancel_callback = None

    def set_status(self, message: str) -> None:
        self._status_var.set(message)

    # Internal

    def _on_cancel(self) -> None:
        if self._cancel_callback:
            self._cancel_callback()
        self.stop("Cancelled")


# ─── ToolTip ─────────────────────────────────────────────────────────────────


class ToolTip:
    """Simple hover tooltip for any Tkinter widget."""

    def __init__(self, widget: tk.Widget, text: str, delay: int = 500):
        self.widget = widget
        self.text = text
        self.delay = delay
        self._tipwindow = None
        self._id_after = None
        widget.bind("<Enter>", self._schedule)
        widget.bind("<Leave>", self._hide)

    def _schedule(self, _event=None) -> None:
        self._id_after = self.widget.after(self.delay, self._show)

    def _show(self) -> None:
        if self._tipwindow:
            return
        x = self.widget.winfo_rootx() + 20
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 4
        tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(
            tw, text=self.text, justify=tk.LEFT,
            background="#ffffe0", foreground="#333333",
            relief=tk.SOLID, borderwidth=1,
            font=get_ui_font(9),
            padx=6, pady=3,
        )
        label.pack()
        self._tipwindow = tw

    def _hide(self, _event=None) -> None:
        if self._id_after:
            self.widget.after_cancel(self._id_after)
            self._id_after = None
        if self._tipwindow:
            self._tipwindow.destroy()
            self._tipwindow = None


# ─── Menu bar helper ─────────────────────────────────────────────────────────


def create_menu_bar(master: tk.Tk, about_title: str) -> tk.Menu:
    """Create a standard menu bar with Help > About."""
    menubar = tk.Menu(master)
    help_menu = tk.Menu(menubar, tearoff=0)

    def _show_about():
        messagebox.showinfo(
            "About",
            f"{about_title}\n\n"
            f"Version: {APP_VERSION}\n"
            f"Author: {APP_AUTHOR}\n"
            f"Repository:\n{APP_REPO}",
        )

    help_menu.add_command(label="About", command=_show_about)
    menubar.add_cascade(label="Help", menu=help_menu)
    master.config(menu=menubar)
    return menubar
