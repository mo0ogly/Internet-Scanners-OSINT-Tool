#!/usr/bin/env python3
"""Interactive menu for Internet Scanners OSINT Tool."""

import os
import subprocess
import sys

BANNER = """
============================================
  Internet Scanners OSINT Tool
============================================
"""


def clear():
    os.system("clear" if os.name != "nt" else "cls")


def pause():
    input("\nPress Enter to continue...")


def prompt(text, default=""):
    if default:
        val = input(f"  {text} [{default}]: ").strip()
        return val if val else default
    return input(f"  {text}: ").strip()


def yes_no(text, default=False):
    hint = "Y/n" if default else "y/N"
    val = input(f"  {text} ({hint}): ").strip().lower()
    if not val:
        return default
    return val in ("y", "yes", "o", "oui")


def _detect_python():
    """Find the best available Python interpreter."""
    for cmd in ("python3.12", "python3.11", "python3.10", "python3.9", "python3"):
        try:
            subprocess.run([cmd, "--version"], capture_output=True, check=True)
            return cmd
        except (FileNotFoundError, subprocess.CalledProcessError):
            continue
    return "python3"


def _has_display():
    """Check if a graphical display is available."""
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def main_menu():
    clear()
    print(BANNER)
    print("  ── CLI ──────────────────────────────────────────────────")
    print("  1) Internet Scanner — from Git repo")
    print("  2) Internet Scanner — from local IP file")
    print("  3) Reverse MX Lookup — MX lookup for a domain")
    print("  4) Reverse MX Lookup — Reverse MX (find domains on a mail server)")
    print()
    if _has_display():
        print("  ── GUI (Tkinter) ────────────────────────────────────────")
        print("  5) Internet Scanner GUI")
        print("  6) Reverse MX Lookup GUI")
        print()
        print("  q) Quit")
        print()
        return input("  Choose [1-6/q]: ").strip()
    else:
        print("  ── GUI ──────────────────────────────────────────────────")
        print("  5) (unavailable — no display detected)")
        print()
        print("  q) Quit")
        print()
        return input("  Choose [1-4/q]: ").strip()


def run_scanner_repo():
    clear()
    print(BANNER)
    print("  -- Internet Scanner (Git Repo) --\n")

    repo_url = prompt("Git repo URL", "https://github.com/MDMCK10/internet-scanners.git")
    multithread = yes_no("Enable multithreading?", default=True)
    enable_abuse = yes_no("Enable AbuseIPDB enrichment?", default=False)

    python = _detect_python()
    cmd = [python, "internet_scanner.py"]

    if repo_url != "https://github.com/MDMCK10/internet-scanners.git":
        cmd.extend(["--repo-url", repo_url])
    if not multithread:
        cmd.append("--no-multithread")
    if enable_abuse:
        cmd.append("--enable-abuseipdb")
        api_key = prompt("AbuseIPDB API key")
        if api_key:
            cmd.extend(["--abuseipdb-api-key", api_key])
        throttle = prompt("Throttle between API calls (seconds)", "1.0")
        cmd.extend(["--throttle", throttle])

    print(f"\n  Running: {' '.join(cmd)}\n")
    subprocess.run(cmd)


def run_scanner_file():
    clear()
    print(BANNER)
    print("  -- Internet Scanner (Local File) --\n")

    input_file = prompt("Path to IP file (one IP per line)")
    if not input_file:
        print("  Error: file path required.")
        return
    if not os.path.isfile(input_file):
        print(f"  Error: file not found: {input_file}")
        return

    multithread = yes_no("Enable multithreading?", default=True)
    enable_abuse = yes_no("Enable AbuseIPDB enrichment?", default=False)

    python = _detect_python()
    cmd = [python, "internet_scanner.py", "--input-file", input_file]

    if not multithread:
        cmd.append("--no-multithread")
    if enable_abuse:
        cmd.append("--enable-abuseipdb")
        api_key = prompt("AbuseIPDB API key")
        if api_key:
            cmd.extend(["--abuseipdb-api-key", api_key])
        throttle = prompt("Throttle between API calls (seconds)", "1.0")
        cmd.extend(["--throttle", throttle])

    print(f"\n  Running: {' '.join(cmd)}\n")
    subprocess.run(cmd)


def run_mx_lookup():
    clear()
    print(BANNER)
    print("  -- MX Lookup --\n")

    target = prompt("Domain to query (e.g. example.com)")
    if not target:
        print("  Error: domain required.")
        return

    python = _detect_python()
    cmd = [python, "cli_Reverse_MX_Lookup_Tool.py", "--mode", "mx_lookup", "--target", target]

    print(f"\n  Running: {' '.join(cmd)}\n")
    subprocess.run(cmd)


def run_reverse_mx():
    clear()
    print(BANNER)
    print("  -- Reverse MX Lookup --\n")

    target = prompt("MX host (e.g. aspmx.l.google.com)")
    if not target:
        print("  Error: MX host required.")
        return

    print("\n  Providers: 1) ViewDNS  2) DomainTools  3) WhoisXML")
    provider_choice = prompt("Choose provider", "1")
    providers = {"1": "ViewDNS", "2": "DomainTools", "3": "WhoisXML"}
    provider = providers.get(provider_choice, "ViewDNS")

    throttle = prompt("Throttle between requests (seconds)", "0.0")
    export = yes_no("Export results to CSV?", default=False)

    python = _detect_python()
    cmd = [
        python, "cli_Reverse_MX_Lookup_Tool.py",
        "--mode", "reverse_mx",
        "--target", target,
        "--provider", provider,
    ]
    if throttle != "0.0":
        cmd.extend(["--throttle", throttle])
    if export:
        csv_path = prompt("CSV output path", "results/reverse_mx.csv")
        cmd.extend(["--export-csv", csv_path])

    print(f"\n  Running: {' '.join(cmd)}\n")
    subprocess.run(cmd)


def run_gui_scanner():
    clear()
    print(BANNER)
    print("  Launching Internet Scanner GUI...\n")
    python = _detect_python()
    subprocess.Popen([python, "gui_scanner.py"])
    print("  GUI window opened. You can close it when done.")


def run_gui_reverse_mx():
    clear()
    print(BANNER)
    print("  Launching Reverse MX Lookup GUI...\n")
    python = _detect_python()
    subprocess.Popen([python, "gui_Reverse_MX_Lookup_Tool.py"])
    print("  GUI window opened. You can close it when done.")


def main():
    if "--help" in sys.argv or "-h" in sys.argv:
        print(BANNER)
        print("  Interactive menu for Internet Scanners OSINT Tool.")
        print("  Run without arguments to start the interactive menu.")
        return

    while True:
        choice = main_menu()

        if choice == "1":
            run_scanner_repo()
            pause()
        elif choice == "2":
            run_scanner_file()
            pause()
        elif choice == "3":
            run_mx_lookup()
            pause()
        elif choice == "4":
            run_reverse_mx()
            pause()
        elif choice == "5":
            if _has_display():
                run_gui_scanner()
                pause()
            else:
                print("\n  No display detected. GUI requires a desktop environment.")
                print("  Run directly: python3 gui_scanner.py")
                pause()
        elif choice == "6":
            if _has_display():
                run_gui_reverse_mx()
                pause()
            else:
                print("\n  No display detected. GUI requires a desktop environment.")
                print("  Run directly: python3 gui_Reverse_MX_Lookup_Tool.py")
                pause()
        elif choice in ("q", "quit", "exit"):
            print("\n  Bye!\n")
            break
        else:
            print("  Invalid choice.")
            pause()


if __name__ == "__main__":
    main()
