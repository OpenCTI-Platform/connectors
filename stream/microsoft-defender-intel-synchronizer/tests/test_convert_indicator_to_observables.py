import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

# Make src importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))
from microsoft_defender_intel_synchronizer_connector.connector import (
    MicrosoftDefenderIntelSynchronizerConnector,
)


class DummyHelper:
    class connector_logger:
        @staticmethod
        def warning(msg, extra):
            pass


class DummyConfig:
    helper = DummyHelper()


def make_connector():
    c = MicrosoftDefenderIntelSynchronizerConnector.__new__(
        MicrosoftDefenderIntelSynchronizerConnector
    )
    c.config = DummyConfig()
    c.helper = DummyHelper()
    return c


@pytest.mark.parametrize(
    "pattern,expected",
    [
        ("[ipv4-addr:value = '1.2.3.4']", [{"type": "ipv4-addr", "value": "1.2.3.4"}]),
        (
            "[domain-name:value = 'example.com']",
            [{"type": "domain-name", "value": "example.com"}],
        ),
        (
            "[hostname:value = 'host.example.com']",
            [{"type": "domain-name", "value": "host.example.com"}],
        ),
        (
            "[url:value = 'http://test.com/path']",
            [{"type": "url", "value": "http://test.com/path"}],
        ),
        (
            "[file:hashes.'SHA-256' = 'AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899']",
            [
                {
                    "type": "file",
                    "hashes": {
                        "sha256": "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
                    },
                }
            ],
        ),
        (
            "[file:hashes.'SHA-1' = 'AABBCCDDEEFF00112233445566778899AABBCCDD']",
            [
                {
                    "type": "file",
                    "hashes": {"sha1": "aabbccddeeff00112233445566778899aabbccdd"},
                }
            ],
        ),
    ],
)
def test_indicator_pattern_extraction(pattern, expected):
    connector = make_connector()
    node = {
        "entity_type": "indicator",
        "pattern": pattern,
        "valid_until": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
    }
    result = connector._convert_indicator_to_observables(node)
    # Only compare relevant fields
    assert result is not None
    for e in expected:
        found = any(all(k in r and r[k] == v for k, v in e.items()) for r in result)
        assert found, f"Expected {e} in result {result}"


def test_expired_indicator_returns_empty():
    connector = make_connector()
    node = {
        "entity_type": "indicator",
        "pattern": "[ipv4-addr:value = '1.2.3.4']",
        "valid_until": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
    }
    result = connector._convert_indicator_to_observables(node)
    assert result == []


def test_hostname_normalization():
    connector = make_connector()
    node = {
        "entity_type": "indicator",
        "pattern": "",
        "name": "host.example.com",
        "x_opencti_main_observable_type": "hostname",
        "valid_until": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
    }
    result = connector._convert_indicator_to_observables(node)
    assert result is not None
    assert any(
        r["type"] == "domain-name" and r["value"] == "host.example.com" for r in result
    )


def test_missing_pattern_with_name_and_type():
    connector = make_connector()
    node = {
        "entity_type": "indicator",
        "pattern": "",
        "name": "example.com",
        "x_opencti_main_observable_type": "domain-name",
        "valid_until": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
    }
    result = connector._convert_indicator_to_observables(node)
    assert result is not None
    assert any(
        r["type"] == "domain-name" and r["value"] == "example.com" for r in result
    )


def test_observable_node_ipv4():
    connector = make_connector()
    node = {
        "entity_type": "ipv4addr",
        "observable_value": "8.8.8.8",
    }
    result = connector._convert_indicator_to_observables(node)
    assert result != []
    assert any(r["type"] == "ipv4-addr" and r["value"] == "8.8.8.8" for r in result)


def test_missing_type_returns_empty_list():
    connector = make_connector()
    node = {
        "entity_type": "unknown_type",
        "observable_value": "something",
    }
    result = connector._convert_indicator_to_observables(node)
    assert result == []


def test_observable_node_file_hash():
    connector = make_connector()
    node = {
        "entity_type": "hashedobservable",
        "hashes": [
            {
                "algorithm": "sha-256",
                "hash": "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789",
            },
            {
                "algorithm": "sha-1",
                "hash": "ABCDEF0123456789ABCDEF0123456789ABCDEF0123",
            },
        ],
    }
    result = connector._convert_indicator_to_observables(node)
    assert result is not None
    assert any(r["type"] == "file" and "sha256" in r["hashes"] for r in result)
    assert any(r["type"] == "file" and "sha1" in r["hashes"] for r in result)


def test_invalid_domain_skipped():
    connector = make_connector()
    node = {
        "entity_type": "indicator",
        "pattern": "[domain-name:value = '_invalid.example.com']",
        "valid_until": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
    }
    result = connector._convert_indicator_to_observables(node)
    # Should skip invalid domain starting with underscore
    assert result is not None
    assert all(
        r["type"] != "domain-name" or not r["value"].startswith("_") for r in result
    )


def test_invalid_value_returns_none():
    connector = make_connector()
    node = {
        "entity_type": "indicator",
        "pattern": "[domain-name:value = '']",
        "valid_until": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
    }
    result = connector._convert_indicator_to_observables(node)
    assert result is not None
    assert all(r["type"] != "domain-name" or r["value"] != "" for r in result)


def test_indicator_pattern_multiple_domain_values_uses_first_only():
    connector = make_connector()
    node = {
        "entity_type": "indicator",
        "pattern": "[domain-name:value = 'a.example.com'] AND [domain-name:value = 'b.example.com']",
        "valid_until": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
    }
    result = connector._convert_indicator_to_observables(node)
    assert result is not None

    domain_values = [r["value"] for r in result if r.get("type") == "domain-name"]
    assert domain_values == [
        "a.example.com"
    ], f"Expected only first domain match, got {domain_values}"


def test_observable_node_hostname_normalized_to_domain_name():
    connector = make_connector()
    node = {
        "entity_type": "hostname",
        "observable_value": "host.example.com",
    }
    result = connector._convert_indicator_to_observables(node)
    assert result is not None
    assert any(
        r["type"] == "domain-name" and r["value"] == "host.example.com" for r in result
    )


def test_observable_node_invalid_hostname_skipped_when_starts_with_underscore():
    connector = make_connector()
    node = {
        "entity_type": "hostname",
        "observable_value": "_sip._tls.example.com",
    }
    result = connector._convert_indicator_to_observables(node)
    assert result is not None
    assert result == [], f"Expected underscore hostname to be skipped, got {result}"
