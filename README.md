# Internet Scanners & Reverse MX — OSINT Toolkit

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)]()
[![CLI + GUI](https://img.shields.io/badge/Interface-CLI%20%2B%20GUI-orange.svg)]()

A Python-based OSINT toolkit for cybersecurity analysts, threat hunters, and network defenders. Two tools in one repository:

1. **Internet Scanners Extractor** — Extract and enrich IP addresses from known internet scanning projects
2. **Reverse MX Lookup Tool** — Discover email infrastructure and enumerate domains sharing mail servers

Both tools are available as CLI (scriptable, batch-friendly) and Tkinter GUI (interactive).

> **Author**: [Fabrice Pizzi](https://github.com/mo0ogly) — Cyber Defense & AI Security Expert

---

## Quick Start

```bash
git clone https://github.com/mo0ogly/Internet-Scanners-OSINT-Tool.git
cd Internet-Scanners-OSINT-Tool
pip install -r requirements.txt
```

---

## Tool 1: Internet Scanners Extractor

Extracts and enriches IP addresses from the [MDMCK10/internet-scanners](https://github.com/MDMCK10/internet-scanners) repository.

### Features

- IPv4 and IPv6 detection from text-based files (.txt, .conf, .nft)
- Reverse DNS (PTR) lookups
- ASN and network enrichment via IPWhois (RDAP)
- Optional [AbuseIPDB](https://www.abuseipdb.com/) integration (reputation score, ISP, country)
- Multithreading support
- Timestamped JSON and CSV exports
- Configurable throttling for API rate limits

### CLI Usage

```bash
# Basic extraction (no AbuseIPDB)
python3 internet_scanner.py

# With AbuseIPDB enrichment
python3 internet_scanner.py \
    --enable-abuseipdb \
    --abuseipdb-api-key YOUR_KEY \
    --throttle 1.0

# Disable multithreading
python3 internet_scanner.py --no-multithread
```

#### CLI Options

| Option | Description | Default |
|--------|-------------|---------|
| `--repo-url` | Git repo URL to clone | MDMCK10/internet-scanners |
| `--repo-path` | Local path for repo clone | `internet-scanners` |
| `--output-json` | JSON output filename | `internet_scanners_enriched.json` |
| `--output-csv` | CSV output filename | `internet_scanners_enriched.csv` |
| `--abuseipdb-api-key` | AbuseIPDB API key | None |
| `--enable-abuseipdb` | Enable AbuseIPDB lookups | Disabled |
| `--throttle` | Delay (seconds) between API calls | 0.0 |
| `--no-multithread` | Disable multithreading | Enabled |

### GUI Usage

```bash
python3 gui_scanner.py
```

![Internet Scanner GUI](docs/screenshot_gui.png)

### Output Example

```json
{
  "owner": "internetresearchproject_v4",
  "ip_or_cidr": "45.33.84.152",
  "ptr_record": "scanner.example.net",
  "asn": "AS63949",
  "asn_description": "Linode, LLC",
  "country": "US",
  "network_name": "LINODE-US",
  "network_cidr": "45.33.64.0/18",
  "abuseConfidenceScore": 0,
  "ispAbuseIPDB": "Linode, LLC"
}
```

---

## Tool 2: Reverse MX Lookup Tool

Analyze email infrastructure by performing MX lookups and reverse MX lookups.

### Features

- **MX Lookup**: Find which mail servers handle a domain's email
- **Reverse MX Lookup**: Discover all domains hosted on the same mail server
- Providers: [ViewDNS.info](https://viewdns.info/), DomainTools, WhoisXML
- Single target or batch file input
- Multithreading for faster processing
- CSV and JSON exports
- API key management via `config/settings.json`

### CLI Usage

```bash
# MX Lookup for a single domain
python3 cli_Reverse_MX_Lookup_Tool.py \
    --mode mx_lookup \
    --target example.com

# Reverse MX Lookup
python3 cli_Reverse_MX_Lookup_Tool.py \
    --mode reverse_mx \
    --target aspmx.l.google.com \
    --provider ViewDNS

# Batch reverse MX from file
python3 cli_Reverse_MX_Lookup_Tool.py \
    --mode reverse_mx \
    --targets-file samples/mx.txt \
    --provider ViewDNS \
    --export-csv output.csv \
    --throttle 1.0
```

#### CLI Options

| Option | Description |
|--------|-------------|
| `--mode` | `mx_lookup` or `reverse_mx` |
| `--target` | Single domain or MX host |
| `--targets-file` | File with targets (one per line) |
| `--provider` | `ViewDNS`, `DomainTools`, or `WhoisXML` (required for reverse_mx) |
| `--throttle` | Delay between requests (seconds) |
| `--no-multithread` | Disable multithreading |
| `--export-csv` | CSV output path |

### GUI Usage

```bash
python3 gui_Reverse_MX_Lookup_Tool.py
```

![Reverse MX GUI](docs/screenshot_gui_2.png)

---

## API Configuration

Store API keys in `config/settings.json`:

```json
{
    "viewdns_api_key": "YOUR_KEY",
    "domaintools_api_user": "YOUR_USER",
    "domaintools_api_key": "YOUR_KEY",
    "whoisxml_api_key": "YOUR_KEY",
    "abuseipdb_api_key": "YOUR_KEY"
}
```

This file is excluded from version control (`.gitignore`).

### AbuseIPDB API Limits

| Plan | Requests/day |
|------|-------------|
| Free | 1,000 |
| Webmaster | 3,000 |

---

## Architecture

```
Internet-Scanners-OSINT-Tool/
│
├── README.md                           ← this file
├── LICENSE                             ← MIT License
├── requirements.txt                    ← Python dependencies
├── .gitignore
│
├── internet_scanner.py                 ← Scanner: core extraction & enrichment engine
├── gui_scanner.py                      ← Scanner: Tkinter GUI
│
├── cli_Reverse_MX_Lookup_Tool.py       ← Reverse MX: CLI entry point
├── gui_Reverse_MX_Lookup_Tool.py       ← Reverse MX: Tkinter GUI
│
├── config/                             ← API keys (git-ignored)
│   └── settings.json
│
├── docs/                               ← Screenshots
│   ├── screenshot_gui.png
│   └── screenshot_gui_2.png
│
├── samples/                            ← Example input files
│   ├── domain.txt
│   └── mx.txt
│
├── results/                            ← Output directory (git-ignored)
│
└── logs/                               ← Log files (git-ignored)
```

### Data Flow — Internet Scanner

```
MDMCK10/internet-scanners (GitHub)
        │
        ▼  git clone / pull
┌──────────────────────────────┐
│  InternetScannerExtractor    │
│  ─────────────────────────── │
│  1. Parse .txt/.conf/.nft    │
│  2. Extract IPv4/IPv6        │
│  3. PTR lookup               │
│  4. ASN enrichment (IPWhois) │
│  5. AbuseIPDB (optional)     │
└──────────┬───────────────────┘
           │
     ┌─────┴─────┐
     ▼           ▼
  JSON/CSV    CLI logs
  exports     or GUI
```

---

## Prerequisites

- Python 3.8+
- Git (for cloning upstream data)
- **Tkinter** (for GUI — install on Linux: `sudo apt install python3-tk`)

```bash
pip install -r requirements.txt
```

---

## Use Cases

- Track known internet scanning infrastructure
- Correlate scanner IPs with ASN owners and ISPs
- Check scanner reputation via AbuseIPDB
- Feed enriched data into SIEMs (Elastic, Splunk)
- Investigate suspicious traffic in network forensics
- Map email infrastructure for domain analysis
- Discover domains sharing mail servers (shared hosting detection)

---

## License

[MIT License](LICENSE)

## Contact

- **Author**: Fabrice Pizzi
- **GitHub**: [@mo0ogly](https://github.com/mo0ogly)
- **LinkedIn**: [linkedin.com/in/fpizzi](https://www.linkedin.com/in/fpizzi/)
