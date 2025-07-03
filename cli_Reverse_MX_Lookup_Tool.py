"""
──────────────────────────────────────────────
 Reverse MX Lookup Tool - CLI Version
──────────────────────────────────────────────

Author:
    m00gly

Description:
    This tool performs either MX lookups or reverse MX lookups
    on domains or mail servers. It is designed for cybersecurity
    analysts, researchers, or network engineers who need to
    discover email infrastructure or enumerate domains sharing
    the same mail server.

    There are two primary modes:
        - mx_lookup:
            Queries the DNS MX records for a given domain to find
            the mail servers handling its email.

        - reverse_mx:
            Uses public services (like ViewDNS, DomainTools,
            or WhoisXML) to identify domains that share the
            same mail server (reverse MX search).

Key Features:
    - Single-domain lookups or batch lookups via file
    - Multithreading support for faster processing of many targets
    - Optional throttling between requests to avoid API rate limits
    - CSV export of results
    - Detailed logging of operations

Command-line Arguments:
    --mode {mx_lookup, reverse_mx}
        Select the operation mode.

    --target DOMAIN_OR_MX
        Single domain (for mx_lookup) or mail server (for reverse_mx).

    --targets-file PATH
        Path to a file containing multiple targets, one per line.
        Cannot be used together with --target.

    --provider {ViewDNS, DomainTools, WhoisXML}
        Required for reverse_mx mode. Specifies the online service
        to use for reverse MX lookups.

    --throttle FLOAT
        Delay (in seconds) to wait between requests. Useful to avoid
        rate limiting.

    --no-multithread
        Disables multithreading. Lookups will be performed sequentially.

    --export-csv PATH
        File path for saving results in CSV format.

Examples:
    # Single domain MX lookup:
    python3 cli_Reverse_MX_Lookup_Tool.py \
        --mode mx_lookup \
        --target google.fr

    # Single reverse MX lookup:
    python3 cli_Reverse_MX_Lookup_Tool.py \
        --mode reverse_mx \
        --target aspmx.l.google.com \
        --provider ViewDNS

    # Batch reverse MX lookups from file:
    python3 cli_Reverse_MX_Lookup_Tool.py \
        --mode reverse_mx \
        --targets-file mx_targets.txt \
        --provider DomainTools \
        --throttle 1.0 \
        --export-csv results/reverse_mx.csv

    # Disable multithreading:
    python3 cli_Reverse_MX_Lookup_Tool.py \
        --mode mx_lookup \
        --target example.com \
        --no-multithread

Log Output:
    Logs are written both to the console and to a rotating
    log file (e.g. logs/reverse_mx_tool.log).

"""

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

 
import os
import re
import csv
import json
import logging
import sys
import argparse
import time
from typing import List, Dict, Optional 
from datetime import datetime
import requests
 
 
import dns.resolver
from concurrent.futures import ThreadPoolExecutor
import threading

class ReverseMXLookup:
    """
    Perform MX lookups or Reverse MX lookups.
    """

    def __init__(
        self,
        mode: str,
        target: str,
        provider: Optional[str] = None,
        throttle: float = 0.0,
        multithread: bool = True,
        export_csv: Optional[str] = None
    ):
        
        self.mode = mode
        self.target = target
        self.provider = provider
        self.throttle = throttle
        self.multithread = multithread
        self.export_csv = export_csv
        self.logger = self._setup_logger()
        self.api_keys = self.load_api_keys()

    def _setup_logger(self) -> logging.Logger:
        logger = logging.getLogger("ReverseMXLookup")
        logger.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
        )
        os.makedirs("logs", exist_ok=True)
        fh = logging.FileHandler("logs/reverse_mx_tool.log", encoding="utf-8")
        fh.setFormatter(formatter)
        logger.addHandler(fh)

        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(formatter)
        logger.addHandler(sh)

        return logger

    def run(self) -> List[Dict[str, str]]:
        """
        Main entry point for running lookups.

        Depending on the chosen mode and the number of targets, this method
        runs lookups either in single-threaded or multi-threaded fashion.

        Returns:
            List[Dict[str, str]]: A list of enrichment records collected from lookups.
        """

        self.logger.info(f"Running in mode: {self.mode}")
        self.logger.info(f"Target: {self.target}")
        self.logger.info(f"Provider: {self.provider}")
        self.logger.info(f"Multithreading: {self.multithread}")
        self.logger.info(f"Throttle between requests: {self.throttle}s")

        results = []

        # Validate mode
        if self.mode not in ["mx_lookup", "reverse_mx"]:
            self.logger.error(f"🛑 Unknown mode: {self.mode}. Must be either 'mx_lookup' or 'reverse_mx'.")
            return []

        # Validate target presence
        if not self.target:
            self.logger.error("🛑 No target specified. Exiting run.")
            return []

        # Multi-threaded execution
        if self.multithread and isinstance(self.target, list) and len(self.target) > 1:
            self.logger.info("→ Running multi-threaded lookups.")
            all_records = []

            with ThreadPoolExecutor() as executor:
                futures = []

                for t in self.target:
                    if self.mode == "mx_lookup":
                        futures.append(
                            executor.submit(self._thread_wrapper, self.mx_lookup, t)
                        )
                    elif self.mode == "reverse_mx":
                        futures.append(
                            executor.submit(self._thread_wrapper, self.reverse_mx_lookup, t, self.provider)
                        )

                for future in as_completed(futures):
                    try:
                        records = future.result()
                        if records:
                            all_records.extend(records)
                    except Exception as e:
                        self.logger.exception(f"‼️ Exception raised in thread: {e}")

            results = all_records

        else:
            # Single-threaded, potentially multiple targets
            all_records = []
            target_list = self.target if isinstance(self.target, list) else [self.target]

            for t in target_list:
                self.logger.info(f"→ Processing target: {t}")
                try:
                    if self.mode == "mx_lookup":
                        recs = self.mx_lookup(t)
                    else:
                        recs = self.reverse_mx_lookup(t, self.provider)

                    if recs:
                        all_records.extend(recs)

                except Exception as e:
                    self.logger.exception(f"‼️ Error while processing target {t}: {e}")

            results = all_records

        # Handle CSV export
        if self.export_csv and results:
            self.save_csv(results, self.export_csv)
        else:
            if not self.export_csv:
                self.logger.debug("ℹ️ No CSV export requested.")
            elif not results:
                self.logger.warning("⚠️ No results available to export.")

        return results


    def _thread_wrapper(self, func, *args, **kwargs):
        """
        Wrapper to execute a given function inside a thread, with detailed logging.

        - Logs the thread name and function being called.
        - Logs all arguments passed to the function for traceability.
        - Measures and logs execution time.
        - Catches any exception raised during execution and logs
        the full traceback, ensuring the thread does not silently fail.

        Args:
            func (Callable): The function to execute in the thread.
            *args: Positional arguments for the function.
            **kwargs: Keyword arguments for the function.

        Returns:
            Any: The return value of the function, or None if an exception occurred.
        """
        

        thread_name = threading.current_thread().name
        args_repr = ", ".join(repr(a) for a in args)
        kwargs_repr = ", ".join(f"{k}={v!r}" for k, v in kwargs.items())
        call_signature = f"{func.__name__}({args_repr}"
        if kwargs_repr:
            call_signature += f", {kwargs_repr}"
        call_signature += ")"

        self.logger.debug(
            f"→ [Thread {thread_name}] Starting execution: {call_signature}"
        )

        start_time = time.time()

        try:
            result = func(*args, **kwargs)
            elapsed = time.time() - start_time
            self.logger.debug(
                f"→ [Thread {thread_name}] Finished {func.__name__} in {elapsed:.3f}s"
            )
            return result

        except Exception as e:
            elapsed = time.time() - start_time
            self.logger.exception(
                f"‼️ Exception in thread {thread_name} during {func.__name__} "
                f"after {elapsed:.3f}s: {e}"
            )
            return None

    
    def mx_lookup(self, domain: str) -> List[Dict[str, str]]:
        """
        Perform a standard MX lookup for a domain name, retrieving all mail 
        exchanger hosts (MX records) associated with the domain.

        Args:
            domain (str): The domain to look up (e.g. "google.fr").

        Returns:
            List[Dict[str, str]]: A list of dictionaries, each containing:
                - 'domain': the queried domain
                - 'mx_host': an MX host found for that domain
        """

        result = []

        self.logger.info(f"Starting MX lookup for domain: {domain}")

        try:
            # Perform DNS MX query
            answers = dns.resolver.resolve(domain, 'MX', lifetime=10.0)
            
            if not answers:
                self.logger.warning(f"No MX records found for {domain}.")
            else:
                for rdata in answers:
                    mx_host = str(rdata.exchange).rstrip('.')
                    result.append({
                        "domain": domain,
                        "mx_host": mx_host
                    })
                    self.logger.info(f"Found MX record for {domain}: {mx_host}")

        except dns.resolver.NoAnswer:
            self.logger.warning(f"No MX records found for domain: {domain}.")
        except dns.resolver.NXDOMAIN:
            self.logger.error(f"Domain does not exist: {domain}.")
        except dns.resolver.NoNameservers:
            self.logger.error(f"No name servers available for domain: {domain}.")
        except dns.exception.Timeout:
            self.logger.error(f"DNS query timed out for domain: {domain}.")
        except Exception as e:
            self.logger.exception(f"Unexpected error during MX lookup for {domain}: {e}")

        if self.throttle > 0:
            self.logger.debug(f"Sleeping for throttle of {self.throttle} seconds after MX lookup.")
            time.sleep(self.throttle)

        if not result:
            self.logger.info(f"MX lookup complete for {domain}. No records found.")

        return result
    
    def reverse_mx_lookup(self, mx_host: str, provider: str) -> List[Dict[str, str]]:
        """
        Perform a reverse MX lookup using ViewDNS, DomainTools, or WhoisXML APIs.

        Args:
            mx_host (str): The MX host to look up (e.g. 'aspmx.l.google.com').
            provider (str): The provider to use ('ViewDNS', 'DomainTools', 'WhoisXML').

        Returns:
            List[Dict[str, str]]: List of dictionaries with:
                - 'mx_host': MX host
                - 'domain': domain sharing the same MX

        The method logs all activity, handles network and JSON errors,
        and ensures no exception leaks outside. If the provider or API
        credentials are missing, it logs errors and returns an empty list.
        """
        results = []

        if not provider:
            self.logger.error("Provider is required for reverse MX lookup.")
            return []

        self.logger.info(f"Starting reverse MX lookup via {provider} for host: {mx_host}")

        try:
            if provider == "ViewDNS":
                api_key = self.api_keys.get("viewdns_api_key")
                if not api_key:
                    self.logger.error("Missing ViewDNS API key in config/settings.json.")
                    return []

                url = f"https://api.viewdns.info/reversemx/"
                params = {
                    "host": mx_host,
                    "apikey": api_key,
                    "output": "json"
                }
                response = requests.get(url, params=params, timeout=10)
                response.raise_for_status()
                data = response.json()

                domains = data.get("response", {}).get("domains", [])
                if not isinstance(domains, list):
                    self.logger.error(f"Unexpected JSON structure from ViewDNS for {mx_host}.")
                    return []

                if not domains:
                    self.logger.info(f"No domains found for {mx_host} via ViewDNS.")
                else:
                    for d in domains:
                        results.append({"mx_host": mx_host, "domain": d})
                        self.logger.info(f"ViewDNS found domain: {d}")

            elif provider == "DomainTools":
                user = self.api_keys.get("domaintools_api_user")
                key = self.api_keys.get("domaintools_api_key")
                if not user or not key:
                    self.logger.error("Missing DomainTools API credentials in config/settings.json.")
                    return []

                url = f"https://api.domaintools.com/v1/{mx_host}/reversens"
                response = requests.get(url, auth=(user, key), timeout=10)
                response.raise_for_status()
                data = response.json()

                domains = data.get("response", {}).get("domains", [])
                if not isinstance(domains, list):
                    self.logger.error(f"Unexpected JSON structure from DomainTools for {mx_host}.")
                    return []

                if not domains:
                    self.logger.info(f"No domains found for {mx_host} via DomainTools.")
                else:
                    for d in domains:
                        results.append({"mx_host": mx_host, "domain": d})
                        self.logger.info(f"DomainTools found domain: {d}")

            elif provider == "WhoisXML":
                api_key = self.api_keys.get("whoisxml_api_key")
                if not api_key:
                    self.logger.error("Missing WhoisXML API key in config/settings.json.")
                    return []

                url = "https://reverse-mx.whoisxmlapi.com/api/v1"
                params = {
                    "apiKey": api_key,
                    "mx": mx_host,
                    "outputFormat": "json"
                }
                response = requests.get(url, params=params, timeout=10)
                response.raise_for_status()
                data = response.json()

                domains = data.get("domainsList", [])
                if not isinstance(domains, list):
                    self.logger.error(f"Unexpected JSON structure from WhoisXML for {mx_host}.")
                    return []

                if not domains:
                    self.logger.info(f"No domains found for {mx_host} via WhoisXML.")
                else:
                    for d in domains:
                        results.append({"mx_host": mx_host, "domain": d})
                        self.logger.info(f"WhoisXML found domain: {d}")

            else:
                self.logger.error(f"Provider '{provider}' is not supported.")
                return []

        except requests.HTTPError as e:
            self.logger.error(f"HTTP error for provider {provider} and host {mx_host}: {e}")
        except requests.RequestException as e:
            self.logger.error(f"Network error calling {provider} for {mx_host}: {e}")
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON from {provider} for {mx_host}: {e}")
        except Exception as e:
            self.logger.exception(f"Unexpected error in reverse MX lookup via {provider} for {mx_host}: {e}")

        if self.throttle > 0:
            self.logger.debug(f"Sleeping for throttle of {self.throttle} seconds.")
            time.sleep(self.throttle)

        if not results:
            self.logger.info(f"No results found for reverse MX on {mx_host} with provider {provider}.")

        return results
 
    
    def save_csv(self, data: List[Dict[str, str]], path: str) -> None:
        """
        Save results to a CSV file safely.

        Args:
            data (List[Dict[str, str]]): Data to write.
            path (str): Path to CSV file.

        Returns:
            None
        """
        if not data:
            self.logger.warning("No data to save. CSV export aborted.")
            return

        if not isinstance(data, list) or not all(isinstance(row, dict) for row in data):
            self.logger.error("Data provided to save_csv is not a list of dictionaries.")
            return

        try:
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

            fields = list(data[0].keys())
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fields)
                writer.writeheader()
                writer.writerows(data)

            self.logger.info(f"CSV successfully saved at {path}")

        except PermissionError:
            self.logger.error(f"Permission denied when writing CSV file: {path}")
        except OSError as e:
            self.logger.error(f"OS error while saving CSV file {path}: {e}")
        except Exception as e:
            self.logger.exception(f"Unexpected error while saving CSV file {path}: {e}")

    def load_api_keys(self) -> dict:
        """
        Load API keys from config/settings.json safely.

        The path is resolved relative to the current script location,
        not the current working directory.

        Returns:
            dict: Dictionary with API keys, or empty dict if file
                missing, empty, or malformed.
        """
        try:
            # Résout le chemin absolu du dossier du script
            base_dir = os.path.dirname(os.path.abspath(__file__))
            config_path = os.path.join(base_dir, "config", "settings.json")

            if not os.path.exists(config_path):
                self.logger.warning(f"API config file not found: {config_path}")
                return {}

            if os.path.getsize(config_path) == 0:
                self.logger.warning(f"API config file is empty: {config_path}")
                return {}

            with open(config_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            if not isinstance(data, dict):
                self.logger.error(f"API config JSON must be a dictionary: {config_path}")
                return {}

            return data

        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON in config/settings.json: {e}")
        except PermissionError:
            self.logger.error(f"Permission denied when reading config/settings.json.")
        except OSError as e:
            self.logger.error(f"OS error reading config/settings.json: {e}")
        except Exception as e:
            self.logger.exception(f"Unexpected error reading config/settings.json: {e}")

        return {}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Reverse MX Lookup Tool CLI"
    )

    parser.add_argument("--mode",
                        choices=["mx_lookup", "reverse_mx"],
                        help="Operation mode: mx_lookup or reverse_mx")
    parser.add_argument("--target", help="Domain or MX to query.")
    parser.add_argument("--targets-file",
                        help="File with list of MX hosts or domains (one per line)")
    parser.add_argument("--provider",
                        choices=["ViewDNS", "DomainTools", "WhoisXML"],
                        help="Provider for reverse MX (required for reverse_mx)")
    parser.add_argument("--throttle",
                        type=float,
                        default=0.0,
                        help="Throttle delay between requests in seconds")
    parser.add_argument("--no-multithread",
                        action="store_true",
                        help="Disable multithreading.")
    parser.add_argument("--export-csv",
                        help="Path to CSV file for export.")

    args, unknown = parser.parse_known_args()

    # Blindage
    errors = []
    if not args.mode:
        errors.append("--mode is required.")

    if not args.target and not args.targets_file:
        errors.append("Either --target or --targets-file must be provided.")

    if args.target and args.targets_file:
        errors.append("Do not use --target and --targets-file at the same time.")

    if args.mode == "reverse_mx" and not args.provider:
        errors.append("--provider is required in reverse_mx mode.")

    if errors:
        print("🛑 ERROR: Missing or invalid arguments:")
        for err in errors:
            print("  - " + err)
        print("\nUse --help for usage instructions.")
        sys.exit(1)

    # Préparer la liste des cibles
    targets: List[str] = []
    if args.target:
        targets = [args.target.strip()]
    elif args.targets_file:
        with open(args.targets_file, "r", encoding="utf-8") as f:
            targets = [line.strip() for line in f if line.strip()]

    all_records: List[Dict[str, str]] = []

    for target in targets:
        lookup = ReverseMXLookup(
            mode=args.mode,
            target=target,
            provider=args.provider,
            throttle=args.throttle,
            multithread=not args.no_multithread,
            export_csv=None  # Pas d'export intermédiaire
        )

        records = lookup.run()
        if records:
            all_records.extend(records)

    # Export global
    if args.export_csv and all_records:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M")
        csv_path = f"{timestamp}_{os.path.basename(args.export_csv)}"
        os.makedirs(os.path.dirname(args.export_csv) or ".", exist_ok=True)

        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            fieldnames = list(all_records[0].keys())
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(all_records)

        print(f"✅ All results saved to CSV → {csv_path}")
    elif not all_records:
        print("ℹ️ No results found.")
    else:
        print(json.dumps(all_records, indent=2))



if __name__ == "__main__":
    main()
