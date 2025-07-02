#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
───────────────────────────────────────────────────────────────────────────────
 Internet Scanners OSINT Tool (CLI Version)
───────────────────────────────────────────────────────────────────────────────

 Author: m00gly
 Project: Internet Scanners OSINT Tool
 License: MIT
 Repository: https://github.com/MDMCK10/internet-scanners

───────────────────────────────────────────────────────────────────────────────

DESCRIPTION
────────────────────────────────────────────
This is the Command-Line Interface (CLI) version of the Internet Scanners
OSINT Tool. It automates the extraction and enrichment of IP addresses
found in files hosted in the GitHub repository:

    https://github.com/MDMCK10/internet-scanners

It’s designed for cybersecurity analysts, researchers and developers who
prefer batch-mode operation or integration into larger pipelines.

Features include:
- automatic git clone or pull
- detection of IPv4 and IPv6 addresses
- enrichment via PTR lookups and ASN data
- optional integration with AbuseIPDB for IP reputation
- timestamped JSON and CSV exports
- verbose logs to console and file
- multithreading support

────────────────────────────────────────────

FOR DEVELOPERS
────────────────────────────────────────────
Key components:
- `InternetScannerExtractor`: core class performing repo sync,
  IP extraction, enrichment and exports

Main development features:
- Optional AbuseIPDB enrichment, disabled by default to avoid quota issues
- Throttle parameter to slow down requests and respect API rate limits
- All logs written both to console and scanner.log
- Easy to integrate into larger automated workflows
- Command-line arguments for full customization

How to extend:
- Add other reputation services (e.g. Shodan, VirusTotal) in
  `InternetScannerExtractor.enrich_ip`
- Handle additional file formats for IP parsing
- Add filtering or scoring logic to detect suspicious scanners

────────────────────────────────────────────

HOW TO RUN
────────────────────────────────────────────
Examples:

    # Run with defaults (no AbuseIPDB)
    python3 internet_scanner_cli.py

    # Enable AbuseIPDB lookups
    python3 internet_scanner_cli.py --enable-abuseipdb --abuseipdb-api-key YOUR_KEY

    # Add delay between AbuseIPDB calls
    python3 internet_scanner_cli.py --enable-abuseipdb --throttle 1.0

    # Disable multithreading
    python3 internet_scanner_cli.py --no-multithread

────────────────────────────────────────────

"""


import os
import re
import csv
import json
import socket
import subprocess
import logging
import sys
import argparse
import time
from typing import List, Dict, Optional, Any
from datetime import datetime
import requests
from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError


class InternetScannerExtractor:
    """
    Extracts and enriches IP addresses from internet scanners data.
    """

    IPV4_IPV6_REGEX = re.compile(
        r"(\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b)|"
        r"((?:[a-fA-F0-9]{0,4}:){2,7}[a-fA-F0-9]{0,4}(?:/\d{1,3})?)"
    )

    def __init__(
        self,
        repo_url: str,
        repo_path: str,
        output_json: str,
        output_csv: str,
        abuseipdb_api_key: Optional[str] = None,
        log_level=logging.INFO,
        use_multithreading: bool = True,
        logs_dir: Optional[str] = None,
        results_dir: Optional[str] = None,
        enable_abuseipdb: bool = False,
        throttle: float = 0.0
    ):
        self.repo_url = repo_url
        self.repo_path = repo_path
        self.output_json = output_json
        self.output_csv = output_csv
        self.abuseipdb_api_key = abuseipdb_api_key
        self.use_multithreading = use_multithreading
        self.enable_abuseipdb = enable_abuseipdb
        self.throttle = throttle
        self.logger = self._setup_logger(log_level)
        self.abuseipdb_disabled_due_to_errors = False

    def _setup_logger(self, level: int) -> logging.Logger:
        logger = logging.getLogger("InternetScannerExtractor")
        logger.setLevel(level)

        formatter = logging.Formatter(
            "%(asctime)s | %(levelname)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )

        fh = logging.FileHandler("scanner.log", encoding="utf-8")
        fh.setFormatter(formatter)
        logger.addHandler(fh)

        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(formatter)
        logger.addHandler(ch)

        return logger

    def git_clone_or_pull(self) -> None:
        if os.path.exists(self.repo_path):
            self.logger.info("Updating repo...")
            subprocess.run(["git", "-C", self.repo_path, "pull"], check=True)
        else:
            self.logger.info("Cloning repo...")
            subprocess.run(["git", "clone", self.repo_url], check=True)

    def reverse_dns(self, ip: str) -> Optional[str]:
        try:
            result = socket.gethostbyaddr(ip)
            return result[0]
        except Exception:
            return None

    def abuseipdb_lookup(self, ip: str) -> Dict[str, Any]:
        if not self.enable_abuseipdb:
            self.logger.info(f"AbuseIPDB disabled → skipping for {ip}")
            return {}

        if self.abuseipdb_disabled_due_to_errors:
            self.logger.warning(f"AbuseIPDB lookups disabled due to previous errors.")
            return {}

        if not self.abuseipdb_api_key:
            self.logger.info(f"AbuseIPDB skipped for {ip} (no API key)")
            return {}

        if self.throttle > 0:
            self.logger.debug(f"Sleeping {self.throttle}s before AbuseIPDB call for {ip}")
            time.sleep(self.throttle)

        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Accept": "application/json",
            "Key": self.abuseipdb_api_key
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90
        }

        try:
            response = requests.get(url, headers=headers, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json().get("data", {})
                return {
                    "abuseConfidenceScore": data.get("abuseConfidenceScore"),
                    "totalReports": data.get("totalReports"),
                    "countryCodeAbuseIPDB": data.get("countryCode"),
                    "domainAbuseIPDB": data.get("domain"),
                    "ispAbuseIPDB": data.get("isp"),
                    "lastReportedAt": data.get("lastReportedAt"),
                }
            elif response.status_code == 429:
                self.logger.warning(
                    f"AbuseIPDB returned 429 Too Many Requests for {ip}. "
                    f"Disabling further calls this run."
                )
                self.abuseipdb_disabled_due_to_errors = True
                return {}
            else:
                self.logger.warning(f"AbuseIPDB returned status {response.status_code} for {ip}")
                return {}
        except Exception as e:
            self.logger.error(f"Error contacting AbuseIPDB for {ip}: {e}")
            self.abuseipdb_disabled_due_to_errors = True
            return {}

    def strip_cidr(self, ip_or_cidr: str) -> str:
        return ip_or_cidr.split("/")[0]

    def enrich_ip(self, ip: str) -> Dict[str, Any]:
        ip_clean = self.strip_cidr(ip)
        self.logger.info(f"Enriching IP: {ip_clean}")

        ptr = self.reverse_dns(ip_clean)
        self.logger.info(f"PTR for {ip_clean}: {ptr}")

        enrichment = {
            "ptr_record": ptr
        }

        try:
            obj = IPWhois(ip_clean)
            res = obj.lookup_rdap()
            enrichment.update({
                "asn": res.get("asn"),
                "asn_description": res.get("asn_description"),
                "country": res.get("asn_country_code"),
                "network_name": res.get("network", {}).get("name"),
                "network_cidr": res.get("network", {}).get("cidr"),
            })
        except IPDefinedError:
            enrichment.update({
                "asn": None,
                "asn_description": "Private or reserved",
                "country": None,
                "network_name": None,
                "network_cidr": None,
            })
        except Exception as e:
            self.logger.warning(f"Error enriching {ip} with ipwhois: {e}")
            enrichment.update({
                "asn": None,
                "asn_description": None,
                "country": None,
                "network_name": None,
                "network_cidr": None,
            })

        abuse_data = self.abuseipdb_lookup(ip_clean)
        enrichment.update(abuse_data)

        return enrichment

    def parse_files(self) -> List[Dict[str, Any]]:
        result = []

        for root, _, files in os.walk(self.repo_path):
            for file in files:
                if not file.endswith(('.txt', '.conf', '.inc', '.nft')):
                    continue

                filepath = os.path.join(root, file)
                self.logger.info(f"Processing file: {filepath}")

                owner = None
                ips: List[str] = []

                with open(filepath, "r", encoding="utf-8") as f:
                    lines = f.readlines()

                for line in lines:
                    line = line.strip()
                    m = re.match(r"#\s*(.*)", line)
                    if m:
                        owner = m.group(1).strip()
                        break
                    m2 = re.match(r"define\s+([a-zA-Z0-9_\-]+)", line)
                    if m2 and not owner:
                        owner = m2.group(1).strip()
                        break

                if not owner:
                    owner = file.replace(".txt", "")

                for line in lines:
                    matches = self.IPV4_IPV6_REGEX.findall(line)
                    for match in matches:
                        ip_candidate = match[0] or match[1]
                        if ip_candidate:
                            ips.append(ip_candidate.strip())

                for ip in ips:
                    enrichment = self.enrich_ip(ip)
                    record = {
                        "owner": owner,
                        "ip_or_cidr": ip,
                        **enrichment
                    }
                    result.append(record)

        return result

    def save_json(self, data: List[Dict[str, Any]]) -> None:
        with open(self.output_json, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        self.logger.info(f"JSON saved: {self.output_json}")

    def save_csv(self, data: List[Dict[str, Any]]) -> None:
        if not data:
            return

        fields = list(data[0].keys())
        with open(self.output_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            writer.writerows(data)

        self.logger.info(f"CSV saved: {self.output_csv}")

    def summarize_stats(self, data: List[Dict[str, Any]]) -> None:
        total = len(data)
        ipv4_count = sum(1 for item in data if ":" not in item["ip_or_cidr"])
        ipv6_count = total - ipv4_count
        abuse_count = sum(
            1 for item in data
            if item.get("abuseConfidenceScore", 0) and item["abuseConfidenceScore"] > 0
        )
        self.logger.info(
            f"FINISHED: Total IPs={total}, IPv4={ipv4_count}, "
            f"IPv6={ipv6_count}, Reported in AbuseIPDB={abuse_count}"
        )

    def run(self) -> None:
        self.logger.info(
            f"Running with multithreading: {self.use_multithreading}"
        )
        self.git_clone_or_pull()
        data = self.parse_files()
        self.save_json(data)
        self.save_csv(data)
        self.summarize_stats(data)
        self.logger.info("✅ Extraction and enrichment finished.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Internet Scanners OSINT Tool CLI"
    )
    parser.add_argument("--repo-url", default="https://github.com/MDMCK10/internet-scanners.git")
    parser.add_argument("--repo-path", default="internet-scanners")
    parser.add_argument("--output-json", default="internet_scanners_enriched.json")
    parser.add_argument("--output-csv", default="internet_scanners_enriched.csv")
    parser.add_argument("--abuseipdb-api-key", default=None)
    parser.add_argument("--enable-abuseipdb", action="store_true", help="Enable AbuseIPDB lookups")
    parser.add_argument("--throttle", type=float, default=0.0, help="Delay in seconds between AbuseIPDB lookups")
    parser.add_argument("--no-multithread", action="store_true")

    args = parser.parse_args()

    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    output_json = f"{timestamp}_{args.output_json}"
    output_csv = f"{timestamp}_{args.output_csv}"

    extractor = InternetScannerExtractor(
        repo_url=args.repo_url,
        repo_path=args.repo_path,
        output_json=output_json,
        output_csv=output_csv,
        abuseipdb_api_key=args.abuseipdb_api_key,
        enable_abuseipdb=args.enable_abuseipdb,
        throttle=args.throttle,
        log_level=logging.DEBUG,
        use_multithreading=not args.no_multithread
    )

    extractor.run()
