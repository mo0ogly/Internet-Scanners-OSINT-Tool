"""Tests for internet_scanner.py — InternetScannerExtractor."""

import csv
import json
import logging
import os
import sys
from unittest.mock import MagicMock, patch

# Ensure project root is on sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ── strip_cidr ──────────────────────────────────────────────────────────────


def test_strip_cidr_ipv4(mock_extractor):
    assert mock_extractor.strip_cidr("192.168.1.0/24") == "192.168.1.0"


def test_strip_cidr_ipv6(mock_extractor):
    assert mock_extractor.strip_cidr("2001:db8::/32") == "2001:db8::"


def test_strip_cidr_no_cidr(mock_extractor):
    assert mock_extractor.strip_cidr("10.0.0.1") == "10.0.0.1"


# ── reverse_dns ─────────────────────────────────────────────────────────────


def test_reverse_dns_success(mock_extractor):
    with patch("socket.gethostbyaddr", return_value=("host.example.com", [], [])):
        result = mock_extractor.reverse_dns("1.2.3.4")
        assert result == "host.example.com"


def test_reverse_dns_failure(mock_extractor):
    with patch("socket.gethostbyaddr", side_effect=OSError("not found")):
        result = mock_extractor.reverse_dns("1.2.3.4")
        assert result is None


# ── abuseipdb_lookup ────────────────────────────────────────────────────────


def test_abuseipdb_disabled(mock_extractor):
    mock_extractor.enable_abuseipdb = False
    result = mock_extractor.abuseipdb_lookup("1.2.3.4")
    assert result == {}


def test_abuseipdb_no_key(mock_extractor):
    mock_extractor.enable_abuseipdb = True
    mock_extractor.abuseipdb_api_key = None
    result = mock_extractor.abuseipdb_lookup("1.2.3.4")
    assert result == {}


def test_abuseipdb_success(mock_extractor):
    mock_extractor.enable_abuseipdb = True
    mock_extractor.abuseipdb_api_key = "fake-key"

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {
            "abuseConfidenceScore": 75,
            "totalReports": 12,
            "countryCode": "US",
            "domain": "example.com",
            "isp": "TestISP",
            "lastReportedAt": "2025-01-01T00:00:00+00:00",
        }
    }

    with patch("requests.get", return_value=mock_response):
        result = mock_extractor.abuseipdb_lookup("1.2.3.4")
        assert result["abuseConfidenceScore"] == 75
        assert result["totalReports"] == 12
        assert result["ispAbuseIPDB"] == "TestISP"


def test_abuseipdb_rate_limited(mock_extractor):
    mock_extractor.enable_abuseipdb = True
    mock_extractor.abuseipdb_api_key = "fake-key"

    mock_response = MagicMock()
    mock_response.status_code = 429

    with patch("requests.get", return_value=mock_response):
        result = mock_extractor.abuseipdb_lookup("1.2.3.4")
        assert result == {}
        assert mock_extractor.abuseipdb_disabled_due_to_errors is True


# ── enrich_ip ───────────────────────────────────────────────────────────────


def test_enrich_ip_public(mock_extractor):
    mock_whois_result = {
        "asn": "12345",
        "asn_description": "TEST-ASN",
        "asn_country_code": "US",
        "network": {"name": "TESTNET", "cidr": "1.2.3.0/24"},
    }

    with patch("socket.gethostbyaddr", return_value=("ptr.example.com", [], [])), \
         patch("internet_scanner.IPWhois") as MockIPWhois:
        instance = MockIPWhois.return_value
        instance.lookup_rdap.return_value = mock_whois_result
        mock_extractor.enable_abuseipdb = False

        result = mock_extractor.enrich_ip("1.2.3.4")
        assert result["ptr_record"] == "ptr.example.com"
        assert result["asn"] == "12345"
        assert result["country"] == "US"


def test_enrich_ip_private(mock_extractor):
    from ipwhois.exceptions import IPDefinedError

    with patch("socket.gethostbyaddr", side_effect=OSError), \
         patch("internet_scanner.IPWhois") as MockIPWhois:
        instance = MockIPWhois.return_value
        instance.lookup_rdap.side_effect = IPDefinedError("private")
        mock_extractor.enable_abuseipdb = False

        result = mock_extractor.enrich_ip("192.168.1.1")
        assert result["asn_description"] == "Private or reserved"
        assert result["ptr_record"] is None


# ── save_json / save_csv ────────────────────────────────────────────────────


def test_save_json(mock_extractor, sample_ip_data, tmp_output_dir):
    out_path = str(tmp_output_dir / "test_out.json")
    mock_extractor.output_json = out_path
    mock_extractor.save_json(sample_ip_data)

    with open(out_path, "r") as f:
        loaded = json.load(f)
    assert len(loaded) == 3
    assert loaded[0]["ip_or_cidr"] == "192.168.1.1"


def test_save_csv(mock_extractor, sample_ip_data, tmp_output_dir):
    out_path = str(tmp_output_dir / "test_out.csv")
    mock_extractor.output_csv = out_path
    mock_extractor.save_csv(sample_ip_data)

    with open(out_path, "r") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    assert len(rows) == 3
    assert rows[0]["ip_or_cidr"] == "192.168.1.1"


def test_save_csv_empty(mock_extractor, tmp_output_dir):
    out_path = str(tmp_output_dir / "empty.csv")
    mock_extractor.output_csv = out_path
    mock_extractor.save_csv([])
    assert not os.path.exists(out_path)


# ── summarize_stats ─────────────────────────────────────────────────────────


def test_summarize_stats_mixed(mock_extractor, sample_ip_data, caplog):
    with caplog.at_level("INFO", logger=mock_extractor.logger.name):
        mock_extractor.logger.handlers = [logging.StreamHandler()]
        mock_extractor.summarize_stats(sample_ip_data)
    # sample_ip_data: 2 IPv4 (192.168.1.1, 10.0.0.1), 1 IPv6 (2001:db8::1)
    # 1 with abuseConfidenceScore > 0 (score=50)
    assert "Total IPs=3" in caplog.text
    assert "IPv4=2" in caplog.text
    assert "IPv6=1" in caplog.text
    assert "Reported in AbuseIPDB=1" in caplog.text


def test_summarize_stats_empty(mock_extractor, caplog):
    with caplog.at_level("INFO", logger=mock_extractor.logger.name):
        mock_extractor.logger.handlers = [logging.StreamHandler()]
        mock_extractor.summarize_stats([])
    assert "Total IPs=0" in caplog.text


# ── IP regex ────────────────────────────────────────────────────────────────


def test_ip_regex_ipv4(mock_extractor):
    matches = mock_extractor.IPV4_IPV6_REGEX.findall("Server at 192.168.1.1 is up")
    ipv4_matches = [m[0] for m in matches if m[0]]
    assert "192.168.1.1" in ipv4_matches


def test_ip_regex_ipv6(mock_extractor):
    matches = mock_extractor.IPV4_IPV6_REGEX.findall("Host 2001:db8::1 found")
    ipv6_matches = [m[1] for m in matches if m[1]]
    assert any("2001:db8" in m for m in ipv6_matches)
