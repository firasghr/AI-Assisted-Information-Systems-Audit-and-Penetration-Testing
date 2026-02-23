"""
test_scanner.py - Unit tests for the Nmap and ZAP scanner modules.

These tests use mocking to avoid requiring real Nmap or ZAP installations
in the test environment.
"""

import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

# Ensure src/scanner is importable
sys.path.insert(0, str(Path(__file__).parent.parent / "src" / "scanner"))

import nmap_scanner
import zap_scanner


# ---------------------------------------------------------------------------
# Nmap Scanner Tests
# ---------------------------------------------------------------------------

class TestNmapScanner(unittest.TestCase):
    """Tests for nmap_scanner.py"""

    def setUp(self):
        """Set up a mock nmap.PortScanner instance."""
        self.mock_nm = MagicMock()

        # Configure mock host data
        host_mock = MagicMock()
        host_mock.state.return_value = "up"
        host_mock.all_protocols.return_value = ["tcp"]
        host_mock.hostnames.return_value = [{"name": "test.local", "type": "PTR"}]
        host_mock.__getitem__ = MagicMock(
            side_effect=lambda proto: {
                22: {
                    "state": "open",
                    "name": "ssh",
                    "product": "OpenSSH",
                    "version": "8.9",
                    "extrainfo": "",
                    "cpe": "cpe:/a:openbsd:openssh:8.9",
                },
                80: {
                    "state": "open",
                    "name": "http",
                    "product": "Apache",
                    "version": "2.4",
                    "extrainfo": "",
                    "cpe": "",
                },
            }
            if proto == "tcp"
            else {}
        )
        host_mock.__contains__ = MagicMock(return_value=True)
        # OS matches
        type(host_mock).__contains__ = PropertyMock(return_value=True)
        host_mock.__class__.__contains__ = lambda self, key: key == "osmatch"
        host_mock.__getitem__.side_effect = None
        host_mock["tcp"] = {
            22: {"state": "open", "name": "ssh", "product": "OpenSSH", "version": "8.9", "extrainfo": "", "cpe": ""},
            80: {"state": "open", "name": "http", "product": "Apache", "version": "2.4", "extrainfo": "", "cpe": ""},
        }
        host_mock["osmatch"] = [{"name": "Linux 5.x", "accuracy": "96"}]
        self.host_mock = host_mock

        self.mock_nm.all_hosts.return_value = ["192.168.1.1"]
        self.mock_nm.__getitem__ = MagicMock(return_value=host_mock)
        self.mock_nm.scaninfo.return_value = {"tcp": {"method": "syn", "services": "1-1024"}}

    def test_scan_raises_value_error_on_empty_target(self):
        """Scan should reject empty targets."""
        with self.assertRaises(ValueError):
            nmap_scanner.scan("")

        with self.assertRaises(ValueError):
            nmap_scanner.scan("   ")

    @patch("nmap_scanner.nmap.PortScanner")
    @patch("nmap_scanner.open", create=True)
    def test_scan_returns_structured_result(self, mock_open, MockPortScanner):
        """Scan should return a dict with required keys."""
        mock_open.return_value.__enter__ = lambda s: s
        mock_open.return_value.__exit__ = MagicMock(return_value=False)
        mock_open.return_value.write = MagicMock()

        MockPortScanner.return_value = self.mock_nm
        self.mock_nm.scan = MagicMock()

        result = nmap_scanner.scan("192.168.1.1", ports="22,80")

        required_keys = [
            "scan_id", "tool", "target", "timestamp",
            "execution_time_seconds", "hosts_scanned", "hosts", "nmap_info",
        ]
        for key in required_keys:
            self.assertIn(key, result)

    @patch("nmap_scanner.nmap.PortScanner")
    def test_scan_raises_on_nmap_error(self, MockPortScanner):
        """Scan should propagate PortScannerError."""
        import nmap
        mock_nm = MagicMock()
        mock_nm.scan.side_effect = nmap.PortScannerError("nmap binary not found")
        MockPortScanner.return_value = mock_nm

        with self.assertRaises(nmap.PortScannerError):
            nmap_scanner.scan("192.168.1.1")

    def test_normalise_host_with_open_ports(self):
        """_normalise_host should return correct structure."""
        # Set up a minimal mock
        nm_mock = MagicMock()
        host_data = {
            "state": "up",
            "tcp": {
                22: {
                    "state": "open", "name": "ssh", "product": "OpenSSH",
                    "version": "8.9", "extrainfo": "", "cpe": ""
                }
            },
            "osmatch": [{"name": "Linux 5.x", "accuracy": "95"}],
        }

        class HostProxy:
            def state(self):
                return "up"
            def all_protocols(self):
                return ["tcp"]
            def hostnames(self):
                return [{"name": "test.local"}]
            def __getitem__(self, key):
                return host_data[key]
            def __contains__(self, key):
                return key in host_data

        nm_mock.__getitem__ = MagicMock(return_value=HostProxy())
        result = nmap_scanner._normalise_host(nm_mock, "192.168.1.1")

        self.assertEqual(result["ip"], "192.168.1.1")
        self.assertIn("ports", result)
        self.assertIn("os_matches", result)
        self.assertIn("hostnames", result)
        self.assertEqual(result["state"], "up")


# ---------------------------------------------------------------------------
# ZAP Scanner Tests
# ---------------------------------------------------------------------------

class TestZapScanner(unittest.TestCase):
    """Tests for zap_scanner.py"""

    def test_scan_raises_value_error_on_empty_target(self):
        """Scan should reject empty target URLs."""
        with self.assertRaises(ValueError):
            zap_scanner.scan("")

        with self.assertRaises(ValueError):
            zap_scanner.scan("   ")

    def test_normalise_alert_high_risk(self):
        """High risk alert should map to 'high' severity."""
        alert = {
            "alert": "SQL Injection",
            "risk": "High",
            "description": "SQL injection found.",
            "url": "http://example.com/login",
            "cweid": "89",
            "confidence": "High",
            "reference": "https://owasp.org\nhttps://cwe.mitre.org/data/definitions/89.html",
            "pluginId": "40018",
            "evidence": "1'",
            "attack": "1'",
            "param": "username",
            "other": "",
            "solution": "Use parameterised queries.",
        }
        result = zap_scanner._normalise_alert(alert)
        self.assertEqual(result["severity"], "high")
        self.assertEqual(result["cwe_id"], 89)
        self.assertEqual(result["name"], "SQL Injection")
        self.assertEqual(len(result["references"]), 2)

    def test_normalise_alert_informational(self):
        """Informational alert should map to 'informational' severity."""
        alert = {
            "alert": "Server Banner",
            "risk": "Informational",
            "description": "Server banner exposed.",
            "url": "http://example.com/",
            "cweid": "",
            "confidence": "High",
            "reference": "",
            "pluginId": "10036",
            "evidence": "nginx/1.18",
            "attack": "",
            "param": "",
            "other": "",
            "solution": "Remove server banner.",
        }
        result = zap_scanner._normalise_alert(alert)
        self.assertEqual(result["severity"], "informational")
        self.assertIsNone(result["cwe_id"])

    def test_normalise_alert_empty_references(self):
        """Alert with no references should return empty references list."""
        alert = {
            "alert": "Test",
            "risk": "Low",
            "description": "",
            "url": "http://example.com",
            "cweid": "",
            "confidence": "Low",
            "reference": "   \n   ",  # whitespace only
            "pluginId": "",
            "evidence": "",
            "attack": "",
            "param": "",
            "other": "",
            "solution": "",
        }
        result = zap_scanner._normalise_alert(alert)
        self.assertEqual(result["references"], [])

    @patch("zap_scanner.ZAPv2")
    def test_scan_raises_connection_error_when_zap_unreachable(self, MockZAP):
        """Scan should raise ConnectionError when ZAP daemon is unreachable."""
        import requests
        mock_zap = MagicMock()
        type(mock_zap.core).version = PropertyMock(
            side_effect=Exception("Connection refused")
        )
        MockZAP.return_value = mock_zap

        with self.assertRaises(requests.exceptions.ConnectionError):
            zap_scanner.scan("http://example.com", zap_base_url="http://localhost:9999")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    unittest.main(verbosity=2)
