"""Shared pytest fixtures for USTA Prodaft connector tests."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest


@pytest.fixture
def mock_helper():
    """Create a mock OpenCTIConnectorHelper."""
    helper = MagicMock()
    helper.connect_id = "test-connector-id"
    helper.connect_name = "USTA Prodaft Test"
    helper.connector_logger = MagicMock()
    helper.get_state = MagicMock(return_value=None)
    helper.set_state = MagicMock()
    helper.api = MagicMock()
    helper.api.work.initiate_work = MagicMock(return_value="test-work-id")
    helper.api.work.to_processed = MagicMock()
    helper.stix2_create_bundle = MagicMock(return_value='{"type":"bundle","objects":[]}')
    helper.send_stix2_bundle = MagicMock(return_value=["bundle-1"])
    helper.schedule_process = MagicMock()
    return helper


# ---- Malicious URL fixtures ----

@pytest.fixture
def sample_malicious_url_record():
    return {
        "id": "5ee025d3-2f92-422e-8a37-6aa04e4fc2eb",
        "url": "119.206.136.181:10798",
        "host": "119.206.136.181",
        "is_domain": False,
        "ip_addresses": ["119.206.136.181"],
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
        "url": "http://yapikredi.world",
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
        "id": "0120b1c0-8617-4409-b0d7-01819e5b50c7",
        "hashes": {
            "md5": "53947098f8c5cf4c0d833f8072bfcbe3",
            "sha1": "e3b20acda4b6b677b464087d3254f7b4ac030a66",
            "sha256": "bb9c04f1737f431635090ec436ffb5e79b2259f7bbfe2d9c65fb6f3799828ea2",
        },
        "tags": ["Vidar"],
        "valid_from": "2026-01-05T06:33:19.637Z",
        "valid_until": "2027-01-05T06:33:19.637Z",
        "created": "2026-01-05T06:20:29.401Z",
    }


# ---- Compromised Credential fixtures ----

@pytest.fixture
def sample_compromised_credential_record():
    return {
        "id": 11179313,
        "status": "open",
        "created": "2026-01-15T13:40:48.983257Z",
        "content_type": "compromised-credentials",
        "company": {"id": 73, "name": "API Integration Demo Company"},
        "content": {
            "username": "someuser1@ustatest.com",
            "password": "h282002h",
            "password_complexity": {"score": "medium", "length": 8},
            "url": "https://login.ustatest.com/testing",
            "source": "malware",
            "is_corporate": True,
            "victim_detail": {
                "victim_uid": "5a53f18a-5f57-0162-b89f-668403f2ba74",
                "username": "hichu",
                "phone_number": "",
                "country": "Zambia",
                "ip": "165.58.129.65",
                "computer_name": "INFINITY",
                "victim_os": "Windows 11",
                "memory": "16 GB",
                "cpu": "Intel(R) Core(TM) i5-8350U CPU @ 1.70GHz",
                "gpu": "",
                "infection_date": "15.01.2025 12:34:00",
                "malware": "StealC",
            },
        },
    }


@pytest.fixture
def sample_compromised_credential_no_victim():
    return {
        "id": 11185291,
        "status": "open",
        "created": "2026-01-19T09:46:44.942396Z",
        "content_type": "compromised-credentials",
        "company": {"id": 73, "name": "API Integration Demo Company"},
        "content": {
            "username": "omktest3",
            "password": "omkpass",
            "password_complexity": {"score": "weak", "length": 7},
            "url": "http://ustatest.com",
            "source": "phishing_site",
            "is_corporate": True,
            "victim_detail": None,
        },
    }


# ---- Credit Card fixtures ----

@pytest.fixture
def sample_credit_card_record():
    return {
        "id": 591197,
        "status": "open",
        "created": "2019-03-08T10:17:46.865262Z",
        "content_type": "credit-card",
        "company": {"id": 73, "name": "API Integration Demo Company"},
        "content": {"number": "4289691967078106", "expiration_date": "2019-10-01"},
    }
