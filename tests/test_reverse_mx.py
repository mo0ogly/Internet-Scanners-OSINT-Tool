"""Tests for cli_Reverse_MX_Lookup_Tool.py — ReverseMXLookup."""

import csv
import json
import os
import sys
from unittest.mock import MagicMock, patch

# Ensure project root is on sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dns.exception
import dns.resolver


def _make_lookup(**kwargs):
    """Create a ReverseMXLookup with mocked logger and api_keys."""
    defaults = {
        "mode": "mx_lookup",
        "target": "example.com",
        "provider": None,
        "throttle": 0.0,
        "multithread": False,
        "export_csv": None,
    }
    defaults.update(kwargs)

    with patch("cli_Reverse_MX_Lookup_Tool.ReverseMXLookup._setup_logger") as mock_log, \
         patch("cli_Reverse_MX_Lookup_Tool.ReverseMXLookup.load_api_keys") as mock_keys:
        mock_log.return_value = MagicMock()
        mock_keys.return_value = {}

        from cli_Reverse_MX_Lookup_Tool import ReverseMXLookup
        obj = ReverseMXLookup(**defaults)
        return obj


# ── mx_lookup ───────────────────────────────────────────────────────────────


def test_mx_lookup_success():
    lookup = _make_lookup(mode="mx_lookup", target="google.com")

    mock_rdata = MagicMock()
    mock_rdata.exchange = MagicMock()
    mock_rdata.exchange.__str__ = lambda self: "aspmx.l.google.com."

    mock_answers = MagicMock()
    mock_answers.__iter__ = lambda self: iter([mock_rdata])
    mock_answers.__bool__ = lambda self: True

    with patch("dns.resolver.resolve", return_value=mock_answers):
        result = lookup.mx_lookup("google.com")
        assert len(result) == 1
        assert result[0]["domain"] == "google.com"
        assert result[0]["mx_host"] == "aspmx.l.google.com"


def test_mx_lookup_nxdomain():
    lookup = _make_lookup(mode="mx_lookup", target="nonexistent.invalid")

    with patch("dns.resolver.resolve", side_effect=dns.resolver.NXDOMAIN):
        result = lookup.mx_lookup("nonexistent.invalid")
        assert result == []


def test_mx_lookup_timeout():
    lookup = _make_lookup(mode="mx_lookup", target="slow.example.com")

    with patch("dns.resolver.resolve", side_effect=dns.exception.Timeout):
        result = lookup.mx_lookup("slow.example.com")
        assert result == []


# ── reverse_mx_lookup ──────────────────────────────────────────────────────


def test_reverse_mx_viewdns_success():
    lookup = _make_lookup(mode="reverse_mx", target="mx.example.com", provider="ViewDNS")
    lookup.api_keys = {"viewdns_api_key": "fake-key"}

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.raise_for_status = MagicMock()
    mock_response.json.return_value = {
        "response": {"domains": ["example.com", "test.com"]}
    }

    with patch("requests.get", return_value=mock_response):
        result = lookup.reverse_mx_lookup("mx.example.com", "ViewDNS")
        assert len(result) == 2
        assert result[0]["domain"] == "example.com"
        assert result[0]["mx_host"] == "mx.example.com"


def test_reverse_mx_viewdns_no_key():
    lookup = _make_lookup(mode="reverse_mx", target="mx.example.com", provider="ViewDNS")
    lookup.api_keys = {}

    result = lookup.reverse_mx_lookup("mx.example.com", "ViewDNS")
    assert result == []


def test_reverse_mx_viewdns_http_error():
    lookup = _make_lookup(mode="reverse_mx", target="mx.example.com", provider="ViewDNS")
    lookup.api_keys = {"viewdns_api_key": "fake-key"}

    import requests as req
    with patch("requests.get", side_effect=req.HTTPError("500 Server Error")):
        result = lookup.reverse_mx_lookup("mx.example.com", "ViewDNS")
        assert result == []


def test_reverse_mx_domaintools():
    lookup = _make_lookup(mode="reverse_mx", target="mx.example.com", provider="DomainTools")
    lookup.api_keys = {
        "domaintools_api_user": "fake-user",
        "domaintools_api_key": "fake-key",
    }

    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.json.return_value = {
        "response": {"domains": ["domain1.com", "domain2.com"]}
    }

    with patch("requests.get", return_value=mock_response):
        result = lookup.reverse_mx_lookup("mx.example.com", "DomainTools")
        assert len(result) == 2
        assert result[1]["domain"] == "domain2.com"


def test_reverse_mx_whoisxml():
    lookup = _make_lookup(mode="reverse_mx", target="mx.example.com", provider="WhoisXML")
    lookup.api_keys = {"whoisxml_api_key": "fake-key"}

    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.json.return_value = {
        "domainsList": ["alpha.com", "beta.com", "gamma.com"]
    }

    with patch("requests.get", return_value=mock_response):
        result = lookup.reverse_mx_lookup("mx.example.com", "WhoisXML")
        assert len(result) == 3
        assert result[2]["domain"] == "gamma.com"


def test_reverse_mx_invalid_provider():
    lookup = _make_lookup(mode="reverse_mx", target="mx.example.com", provider="FakeProvider")
    result = lookup.reverse_mx_lookup("mx.example.com", "FakeProvider")
    assert result == []


# ── load_api_keys ───────────────────────────────────────────────────────────


def test_load_api_keys_valid(tmp_path):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    settings = config_dir / "settings.json"
    settings.write_text(json.dumps({"viewdns_api_key": "test123"}))

    lookup = _make_lookup()
    lookup.logger = MagicMock()

    with patch("cli_Reverse_MX_Lookup_Tool.os.path.dirname", return_value=str(tmp_path)), \
         patch("cli_Reverse_MX_Lookup_Tool.os.path.abspath", return_value=str(tmp_path / "script.py")):
        result = lookup.load_api_keys()
        assert isinstance(result, dict)
        assert result["viewdns_api_key"] == "test123"


def test_load_api_keys_missing(tmp_path):
    lookup = _make_lookup()
    lookup.logger = MagicMock()

    with patch("cli_Reverse_MX_Lookup_Tool.os.path.dirname", return_value=str(tmp_path)), \
         patch("cli_Reverse_MX_Lookup_Tool.os.path.abspath", return_value=str(tmp_path / "script.py")):
        result = lookup.load_api_keys()
        assert result == {}


def test_load_api_keys_invalid_json(tmp_path):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    settings = config_dir / "settings.json"
    settings.write_text("NOT VALID JSON {{{")

    lookup = _make_lookup()
    lookup.logger = MagicMock()

    with patch("cli_Reverse_MX_Lookup_Tool.os.path.dirname", return_value=str(tmp_path)), \
         patch("cli_Reverse_MX_Lookup_Tool.os.path.abspath", return_value=str(tmp_path / "script.py")):
        result = lookup.load_api_keys()
        assert result == {}


# ── save_csv ────────────────────────────────────────────────────────────────


def test_save_csv_valid(tmp_path):
    lookup = _make_lookup()
    data = [
        {"mx_host": "mx1.example.com", "domain": "example.com"},
        {"mx_host": "mx1.example.com", "domain": "test.com"},
    ]
    csv_path = str(tmp_path / "output.csv")
    lookup.save_csv(data, csv_path)

    with open(csv_path, "r") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    assert len(rows) == 2
    assert rows[0]["domain"] == "example.com"


def test_save_csv_empty(tmp_path):
    lookup = _make_lookup()
    csv_path = str(tmp_path / "empty.csv")
    lookup.save_csv([], csv_path)
    assert not os.path.exists(csv_path)
