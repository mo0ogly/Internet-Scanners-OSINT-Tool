import json
import logging
from unittest.mock import patch

import pytest


@pytest.fixture
def tmp_output_dir(tmp_path):
    """Temporary directory for JSON/CSV output files."""
    return tmp_path


@pytest.fixture
def sample_ip_data():
    """Sample enriched IP data for testing save/summarize functions."""
    return [
        {
            "owner": "TestOwner",
            "ip_or_cidr": "192.168.1.1",
            "ptr_record": "host.example.com",
            "asn": "12345",
            "asn_description": "TEST-ASN",
            "country": "US",
            "network_name": "TESTNET",
            "network_cidr": "192.168.1.0/24",
            "abuseConfidenceScore": 50,
            "totalReports": 10,
        },
        {
            "owner": "TestOwner2",
            "ip_or_cidr": "2001:db8::1",
            "ptr_record": None,
            "asn": "67890",
            "asn_description": "IPV6-ASN",
            "country": "DE",
            "network_name": "IPV6NET",
            "network_cidr": "2001:db8::/32",
            "abuseConfidenceScore": 0,
            "totalReports": 0,
        },
        {
            "owner": "TestOwner3",
            "ip_or_cidr": "10.0.0.1",
            "ptr_record": None,
            "asn": None,
            "asn_description": "Private or reserved",
            "country": None,
            "network_name": None,
            "network_cidr": None,
        },
    ]


@pytest.fixture
def mock_extractor(tmp_output_dir):
    """InternetScannerExtractor with mocked network deps and isolated logger."""
    with patch("internet_scanner.IPWhois"), \
         patch("internet_scanner.socket.gethostbyaddr", return_value=("mock.host.com", [], [])), \
         patch("internet_scanner.requests.get"), \
         patch("os.makedirs"):
        from internet_scanner import InternetScannerExtractor

        ext = InternetScannerExtractor(
            repo_url="https://github.com/test/test.git",
            repo_path=str(tmp_output_dir / "repo"),
            output_json=str(tmp_output_dir / "out.json"),
            output_csv=str(tmp_output_dir / "out.csv"),
            abuseipdb_api_key="fake-key",
            enable_abuseipdb=False,
            use_multithreading=False,
        )
        # Replace logger with a clean one that doesn't write to disk
        ext.logger = logging.getLogger(f"test_{id(ext)}")
        ext.logger.addHandler(logging.NullHandler())
        ext.logger.setLevel(logging.DEBUG)
        yield ext


@pytest.fixture
def sample_config(tmp_path):
    """Temporary settings.json with fake API keys."""
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    config_file = config_dir / "settings.json"
    config_file.write_text(json.dumps({
        "viewdns_api_key": "fake-viewdns-key",
        "domaintools_api_user": "fake-user",
        "domaintools_api_key": "fake-dt-key",
        "whoisxml_api_key": "fake-whoisxml-key",
    }))
    return str(config_file)
