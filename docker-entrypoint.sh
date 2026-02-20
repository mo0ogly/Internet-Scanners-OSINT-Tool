#!/bin/sh
set -e

show_help() {
    echo "============================================"
    echo "  Internet Scanners OSINT Tool (Docker)"
    echo "============================================"
    echo ""
    echo "Usage:"
    echo "  docker run --rm -it -v \"\$(pwd)/results:/app/results\" internet-scanners-osint <command>"
    echo ""
    echo "Commands:"
    echo "  menu             Interactive menu (recommended)"
    echo "  scanner --run    Run Internet Scanner (direct mode)"
    echo "  reverse-mx       Run Reverse MX Lookup Tool (direct mode)"
    echo "  shell            Open an interactive shell"
    echo ""
    echo "Quick start:"
    echo "  docker run --rm -it -v \"\$(pwd)/results:/app/results\" internet-scanners-osint menu"
    echo ""
    echo "Direct mode examples:"
    echo "  # Scanner from Git repo"
    echo "  docker run --rm -v \"\$(pwd)/results:/app/results\" internet-scanners-osint scanner --run"
    echo ""
    echo "  # Scanner from local IP file"
    echo "  docker run --rm -v \"\$(pwd)/results:/app/results\" -v \"\$(pwd)/ips.txt:/app/input.txt\" \\"
    echo "      internet-scanners-osint scanner --run --input-file /app/input.txt"
    echo ""
    echo "  # Scanner with AbuseIPDB"
    echo "  docker run --rm -v \"\$(pwd)/results:/app/results\" internet-scanners-osint scanner --run \\"
    echo "      --enable-abuseipdb --abuseipdb-api-key YOUR_KEY --throttle 1.0"
    echo ""
    echo "  # MX Lookup"
    echo "  docker run --rm internet-scanners-osint reverse-mx --mode mx_lookup --target example.com"
    echo ""
    echo "  # Reverse MX Lookup"
    echo "  docker run --rm internet-scanners-osint reverse-mx --mode reverse_mx \\"
    echo "      --target aspmx.l.google.com --provider ViewDNS"
    echo ""
}

show_scanner_help() {
    echo "============================================"
    echo "  Internet Scanner — Options"
    echo "============================================"
    echo ""
    echo "  Clones a Git repo or reads a local file containing IPs,"
    echo "  extracts IPv4/IPv6, and enriches them (PTR, ASN, AbuseIPDB)."
    echo ""
    echo "Usage:"
    echo "  ... internet-scanners-osint scanner --run [options]"
    echo ""
    echo "Options:"
    echo "  --run                  Required. Confirms you want to start."
    echo "  --repo-url URL         Git repo to clone (default: MDMCK10/internet-scanners)"
    echo "  --input-file PATH      Local file with IPs (one per line), skips git clone"
    echo "  --output-json FILE     JSON output filename"
    echo "  --output-csv FILE      CSV output filename"
    echo "  --enable-abuseipdb     Enable AbuseIPDB lookups"
    echo "  --abuseipdb-api-key K  AbuseIPDB API key"
    echo "  --throttle SECONDS     Delay between API calls (default: 0.0)"
    echo "  --no-multithread       Disable multithreading"
    echo ""
    echo "Tip: use 'menu' for an interactive guided experience."
    echo ""
}

case "${1:-}" in
    menu)
        exec python3 menu.py
        ;;
    scanner)
        shift
        has_run=false
        args=""
        for arg in "$@"; do
            if [ "$arg" = "--run" ]; then
                has_run=true
            else
                args="$args $arg"
            fi
        done
        if [ "$has_run" = false ]; then
            show_scanner_help
            exit 0
        fi
        exec python3 internet_scanner.py $args
        ;;
    reverse-mx)
        shift
        if [ $# -eq 0 ]; then
            exec python3 cli_Reverse_MX_Lookup_Tool.py --help
        fi
        exec python3 cli_Reverse_MX_Lookup_Tool.py "$@"
        ;;
    shell)
        exec /bin/sh
        ;;
    --help|-h|"")
        show_help
        ;;
    *)
        echo "Unknown command: $1"
        echo "Run with --help to see available commands."
        exit 1
        ;;
esac
