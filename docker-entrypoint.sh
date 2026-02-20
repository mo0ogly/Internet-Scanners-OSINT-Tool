#!/bin/sh
set -e

show_help() {
    echo "============================================"
    echo "  Internet Scanners OSINT Tool (Docker)"
    echo "============================================"
    echo ""
    echo "Usage:"
    echo "  docker run --rm -v \"\$(pwd)/results:/app/results\" internet-scanners-osint <command> [options]"
    echo ""
    echo "Commands:"
    echo "  scanner          Run Internet Scanner extraction & enrichment"
    echo "  reverse-mx       Run Reverse MX Lookup Tool"
    echo "  shell            Open an interactive shell"
    echo ""
    echo "Examples:"
    echo "  # Scanner with default repo (MDMCK10/internet-scanners)"
    echo "  docker run --rm -v \"\$(pwd)/results:/app/results\" internet-scanners-osint scanner --run"
    echo ""
    echo "  # Scanner with custom repo"
    echo "  docker run --rm -v \"\$(pwd)/results:/app/results\" internet-scanners-osint scanner --run \\"
    echo "      --repo-url https://github.com/user/repo.git"
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
    echo "  # Interactive shell"
    echo "  docker run --rm -it internet-scanners-osint shell"
    echo ""
}

show_scanner_help() {
    echo "============================================"
    echo "  Internet Scanner — Options"
    echo "============================================"
    echo ""
    echo "  This tool clones a Git repo containing scanner IP lists,"
    echo "  extracts IPv4/IPv6 addresses, and enriches them (PTR, ASN, AbuseIPDB)."
    echo ""
    echo "  Default repo: https://github.com/MDMCK10/internet-scanners.git"
    echo ""
    echo "Usage:"
    echo "  docker run --rm -v \"\$(pwd)/results:/app/results\" internet-scanners-osint scanner --run [options]"
    echo ""
    echo "Options:"
    echo "  --run                  Required. Confirms you want to start the scan."
    echo "  --repo-url URL         Git repo to clone (default: MDMCK10/internet-scanners)"
    echo "  --repo-path PATH       Local path for clone (default: internet-scanners)"
    echo "  --output-json FILE     JSON output filename (default: internet_scanners_enriched.json)"
    echo "  --output-csv FILE      CSV output filename (default: internet_scanners_enriched.csv)"
    echo "  --enable-abuseipdb     Enable AbuseIPDB lookups"
    echo "  --abuseipdb-api-key K  AbuseIPDB API key"
    echo "  --throttle SECONDS     Delay between API calls (default: 0.0)"
    echo "  --no-multithread       Disable multithreading"
    echo ""
}

case "${1:-}" in
    scanner)
        shift
        # Require --run to actually start
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
