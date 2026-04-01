"""Shared pytest fixtures for USTA connector tests."""

# pylint: disable=missing-function-docstring

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from unittest.mock import MagicMock

import pytest


@pytest.fixture
def mock_helper():
    """Create a mock OpenCTIConnectorHelper."""
    helper = MagicMock()
    helper.connect_id = "test-connector-id"
    helper.connect_name = "USTA Test"
    helper.connector_logger = MagicMock()
    helper.get_state = MagicMock(return_value=None)
    helper.set_state = MagicMock()
    helper.api = MagicMock()
    helper.api.work.initiate_work = MagicMock(return_value="test-work-id")
    helper.api.work.to_processed = MagicMock()
    helper.stix2_create_bundle = MagicMock(
        return_value='{"type":"bundle","objects":[]}'
    )
    helper.send_stix2_bundle = MagicMock(return_value=["bundle-1"])
    helper.schedule_process = MagicMock()
    return helper


# ---- Malicious URL fixtures ----


@pytest.fixture
def sample_malicious_url_record():
    return {
        "id": "12345678-1234-1234-1234-123456789012",
        "url": "127.0.0.1:10798",
        "host": "127.0.0.1",
        "is_domain": False,
        "ip_addresses": ["127.0.0.1"],
        "tags": ["Ghost RAT"],
        "valid_from": "2026-01-01T01:05:03.000Z",
        "valid_until": "2027-01-01T01:05:03.000Z",
        "created": "2026-01-01T02:34:54.520Z",
    }


# ---- Phishing Site fixtures ----


@pytest.fixture
def sample_phishing_site_record():
    return {
        "id": 42936,
        "url": "http://phishing.example.com",
        "host": "",
        "is_domain": True,
        "ip_addresses": [],
        "country": "",
        "created": "2015-06-06T08:36:12.950000Z",
    }


# ---- Malware Hash fixtures ----


@pytest.fixture
def sample_malware_hash_record():
    return {
        "id": "12341234-1234-1234-1234-123412341234",
        "hashes": {
            "md5": "1234567890abcdef1234567890abcdef",
            "sha1": "1234567890abcdef1234567890abcdef12345678",
            "sha256": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        },
        "tags": ["CustomMalwareTag"],
        "valid_from": "2026-01-05T06:33:19.637Z",
        "valid_until": "2027-01-05T06:33:19.637Z",
        "created": "2026-01-05T06:20:29.401Z",
    }


# ---- Compromised Credential fixtures ----


@pytest.fixture
def sample_compromised_credential_record():
    return {
        "id": 12345678,
        "status": "open",
        "created": "2026-01-15T13:40:48.983257Z",
        "content_type": "compromised-credentials",
        "company": {"id": 1, "name": "API Integration Demo Company"},
        "content": {
            "username": "username@domain.com",
            "password": "t3stPassw0rd!",
            "password_complexity": {"score": "medium", "length": 8},
            "url": "https://login.domain.com/testing",
            "source": "malware",
            "is_corporate": True,
            "victim_detail": {
                "victim_uid": "12345678-1234-1234-1234-123456123456",
                "username": "username",
                "phone_number": "",
                "country": "Zambia",
                "ip": "10.0.0.1",
                "computer_name": "DESKTOP-TEST",
                "victim_os": "Windows 11",
                "memory": "16 GB",
                "cpu": "Intel(R) Core(TM) i9-0000X CPU @ 0.00GHz",
                "gpu": "",
                "infection_date": "2025-01-15 12:34:00",
                "malware": "TheMalware",
            },
        },
    }


@pytest.fixture
def sample_compromised_credential_no_victim():
    return {
        "id": 12345678,
        "status": "open",
        "created": "2026-01-19T09:46:44.942396Z",
        "content_type": "compromised-credentials",
        "company": {"id": 1, "name": "API Integration Demo Company"},
        "content": {
            "username": "username",
            "password": "thepass",
            "password_complexity": {"score": "weak", "length": 7},
            "url": "http://domain.com",
            "source": "phishing_site",
            "is_corporate": True,
            "victim_detail": None,
        },
    }


# ---- Credit Card fixtures ----


@pytest.fixture
def sample_credit_card_record():
    return {
        "id": 123456,
        "status": "open",
        "created": "2019-03-08T10:17:46.865262Z",
        "content_type": "credit-card",
        "company": {"id": 1, "name": "API Integration Demo Company"},
        "content": {"number": "4242424242424242", "expiration_date": "2026-03-01"},
    }


# ---- Deep Sight fixtures ----


@pytest.fixture
def sample_deep_sight_ticket_record():
    return {
        "id": 12345678,
        "status": "open",
        "status_timestamp": "2026-03-05T07:30:03.581287Z",
        "created": "2026-03-05T07:30:03.581281Z",
        "content_type": "deep-sight",
        "company": {"id": 1, "name": "API Integration Demo Company"},
        "content": {
            "title": "[REGIONAL] Some Ransomware Attack",
            "threat_actors": [
                {
                    "nickname": "CoolGroupName",
                    "real_name": "",
                    "country": "us",
                    "motivations": ["ideological"],
                }
            ],
            "targets": [
                {
                    "name": "SomeOrganization",
                    "risk_score": "medium",
                    "analyst_notes": "<p>SomeOrganization began its operations in 2026.</p>",
                }
            ],
            "detected_platforms": ["sigint"],
            "analyst_notes": "<p>CoolGroupName ransomware group has targeted SomeOrganization.</p>",
            "tlp": "amber",
            "labels": ["ransomware"],
            "report": None,
            "detected_at": "2026-03-05T07:28:00Z",
            "markers": ["regional"],
        },
    }


@pytest.fixture
def sample_deep_sight_ticket_with_report():
    return {
        "id": 12345678,
        "status": "open",
        "created": "2026-02-25T08:36:29.515506Z",
        "content_type": "deep-sight",
        "company": {"id": 1, "name": "API Integration Demo Company"},
        "content": {
            "title": "[REGIONAL] Bank Account Access Method",
            "threat_actors": [
                {
                    "nickname": "MoneyMan",
                    "real_name": "",
                    "country": "xx",
                    "motivations": ["money"],
                }
            ],
            "targets": [],
            "analyst_notes": "<p>A bank account blocking method was found.</p>",
            "tlp": "red",
            "labels": [],
            "report": (
                "https://cdn.example.com/attachments/Report_fdUMjgkC.pdf"
                "?AWSAccessKeyId=EXO&Signature=xxx&Expires=1773736716"
            ),
            "detected_at": "2026-02-25T00:00:00Z",
            "markers": ["regional", "critical"],
        },
    }


@pytest.fixture
def sample_deep_sight_ticket_no_actors_no_targets():
    return {
        "id": 12345678,
        "status": "open",
        "created": "2026-02-12T06:46:07.630858Z",
        "content_type": "deep-sight",
        "company": {"id": 1, "name": "API Integration Demo Company"},
        "content": {
            "title": "[REGIONAL: CRITICAL] Investment Fraud Report",
            "threat_actors": [],
            "targets": [],
            "analyst_notes": "<p>Investment fraud analysis report.</p>",
            "tlp": "amber",
            "labels": [],
            "report": None,
            "detected_at": "2026-02-12T06:38:00Z",
            "markers": [],
        },
    }
