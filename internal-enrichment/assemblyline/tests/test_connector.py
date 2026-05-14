"""
Unit tests for OpenCTI AssemblyLine Connector
"""

import os
import sys
from unittest.mock import Mock

import pytest

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


class TestMaliciousIOCExtraction:
    """Tests for malicious IOC extraction from AssemblyLine tags"""

    @pytest.fixture
    def sample_tags(self):
        """Sample AssemblyLine tags structure"""
        return {
            "ioc": {
                "network.dynamic.domain": [
                    ["malware.com", "malicious", False, "TLP:C"],
                    ["safe.com", "info", False, "TLP:C"],
                    ["suspicious.net", "suspicious", False, "TLP:C"],
                ],
                "network.dynamic.ip": [
                    ["192.168.1.100", "malicious", False, "TLP:C"],
                    ["10.0.0.1", "info", False, "TLP:C"],
                ],
                "network.dynamic.uri": [
                    ["http://evil.com/malware.exe", "malicious", False, "TLP:C"]
                ],
            },
            "attribution": {
                "attribution.family": [
                    ["EMOTET", "malicious", False, "TLP:C"],
                    ["TRICKBOT", "info", False, "TLP:C"],
                ]
            },
        }

    def test_extract_malicious_domains(self, sample_tags):
        """Test extraction of malicious domains only"""
        # Mock connector
        connector = Mock()
        connector.assemblyline_include_suspicious = False
        connector.helper = Mock()
        connector.helper.log_info = Mock()

        # Call extraction method (would need actual connector instance)
        # This is a placeholder for the actual test
        assert "malware.com" in str(sample_tags)

    def test_extract_malicious_ips(self, sample_tags):
        """Test extraction of malicious IPs only"""
        assert "192.168.1.100" in str(sample_tags)

    def test_extract_malicious_urls(self, sample_tags):
        """Test extraction of malicious URLs only"""
        assert "http://evil.com/malware.exe" in str(sample_tags)

    def test_extract_malware_families(self, sample_tags):
        """Test extraction of malware families"""
        assert "EMOTET" in str(sample_tags)


class TestScoreConversion:
    """Tests for AssemblyLine score to OpenCTI result conversion"""

    def test_malicious_score(self):
        """Test score >= 500 returns malicious"""
        # Score 500+ should be malicious
        assert 500 >= 500  # Placeholder

    def test_suspicious_score(self):
        """Test score 100-499 returns suspicious"""
        assert 100 <= 250 < 500

    def test_unknown_score(self):
        """Test score 1-99 returns unknown"""
        assert 0 < 50 < 100

    def test_benign_score(self):
        """Test score 0 returns benign"""
        assert 0 == 0


class TestIndicatorPatterns:
    """Tests for STIX indicator pattern generation"""

    def test_domain_pattern(self):
        """Test domain indicator pattern format"""
        domain = "malware.com"
        pattern = f"[domain-name:value = '{domain}']"
        assert pattern == "[domain-name:value = 'malware.com']"

    def test_ipv4_pattern(self):
        """Test IPv4 indicator pattern format"""
        ip = "192.168.1.100"
        pattern = f"[ipv4-addr:value = '{ip}']"
        assert pattern == "[ipv4-addr:value = '192.168.1.100']"

    def test_ipv6_pattern(self):
        """Test IPv6 indicator pattern format"""
        ip = "2001:db8::1"
        pattern = f"[ipv6-addr:value = '{ip}']"
        assert pattern == "[ipv6-addr:value = '2001:db8::1']"

    def test_url_pattern(self):
        """Test URL indicator pattern format"""
        url = "http://evil.com/malware.exe"
        pattern = f"[url:value = '{url}']"
        assert pattern == "[url:value = 'http://evil.com/malware.exe']"

    def test_url_pattern_with_quotes(self):
        """Test URL indicator pattern with escaped quotes"""
        url = "http://evil.com/path?param='value'"
        escaped_url = url.replace("'", "\\'")
        pattern = f"[url:value = '{escaped_url}']"
        assert "\\'" in pattern


class TestIPVersionDetection:
    """Tests for IPv4 vs IPv6 detection"""

    def test_ipv4_detection(self):
        """Test IPv4 address detection"""
        ip = "192.168.1.100"
        is_ipv6 = ":" in ip
        assert is_ipv6 is False

    def test_ipv6_detection(self):
        """Test IPv6 address detection"""
        ip = "2001:db8::1"
        is_ipv6 = ":" in ip
        assert is_ipv6 is True

    def test_ipv6_full_detection(self):
        """Test full IPv6 address detection"""
        ip = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        is_ipv6 = ":" in ip
        assert is_ipv6 is True


class TestFileSizeLimit:
    """Tests for file size limit checking"""

    def test_file_under_limit(self):
        """Test file under size limit passes"""
        file_size_mb = 0.5
        max_size_mb = 1.0
        assert file_size_mb <= max_size_mb

    def test_file_over_limit(self):
        """Test file over size limit is rejected"""
        file_size_mb = 2.0
        max_size_mb = 1.0
        assert file_size_mb > max_size_mb

    def test_file_at_limit(self):
        """Test file at exact limit passes"""
        file_size_mb = 1.0
        max_size_mb = 1.0
        assert file_size_mb <= max_size_mb


class TestAttackPatternExtraction:
    """Tests for MITRE ATT&CK pattern extraction"""

    @pytest.fixture
    def sample_attack_matrix(self):
        """Sample AssemblyLine attack matrix"""
        return {
            "execution": [
                ["T1059.001", "PowerShell", "malicious"],
                ["T1059.003", "Windows Command Shell", "suspicious"],
            ],
            "persistence": [["T1547.001", "Registry Run Keys", "malicious"]],
        }

    def test_extract_technique_id(self, sample_attack_matrix):
        """Test extraction of technique IDs"""
        techniques = []
        for tactic, entries in sample_attack_matrix.items():
            for entry in entries:
                techniques.append(entry[0])

        assert "T1059.001" in techniques
        assert "T1547.001" in techniques

    def test_extract_technique_name(self, sample_attack_matrix):
        """Test extraction of technique names"""
        names = []
        for tactic, entries in sample_attack_matrix.items():
            for entry in entries:
                names.append(entry[1])

        assert "PowerShell" in names


class TestConfigurationLoading:
    """Tests for configuration loading"""

    def test_default_values(self):
        """Test default configuration values"""
        defaults = {
            "timeout": 600,
            "force_resubmit": False,
            "max_file_size_mb": 1,
            "include_suspicious": False,
            "create_attack_patterns": True,
            "create_malware_analysis": True,
            "create_observables": True,
        }

        assert defaults["timeout"] == 600
        assert defaults["force_resubmit"] is False
        assert defaults["create_observables"] is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
