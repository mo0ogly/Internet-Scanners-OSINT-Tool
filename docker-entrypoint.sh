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
    echo "  # Scanner (basic)"
    echo "  docker run --rm -v \"\$(pwd)/results:/app/results\" internet-scanners-osint scanner"
    echo ""
    echo "  # Scanner with AbuseIPDB"
    echo "  docker run --rm -v \"\$(pwd)/results:/app/results\" internet-scanners-osint scanner \\"
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

case "${1:-}" in
    scanner)
        shift
        exec python3 internet_scanner.py "$@"
        ;;
    reverse-mx)
        shift
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
