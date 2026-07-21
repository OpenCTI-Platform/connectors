"""Pytest configuration and shared fixtures for ZeroFox Alerts tests."""

import sys
from pathlib import Path

import pytest

# Add src/ to path so we can import the connector package
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from zerofox_alerts.models import ZerofoxAlert  # noqa: E402


@pytest.fixture
def minimal_alert_data() -> dict:
    """Minimal valid alert dict."""
    return {
        "id": 12345,
        "alert_type": "search_query",
        "status": "open",
        "severity": 2,
        "timestamp": "2025-07-05T12:00:00+00:00",
        "rule_name": "Test Rule",
        "network": "twitter",
        "escalated": False,
        "tags": [],
        "logs": [],
    }


@pytest.fixture
def full_alert_data() -> dict:
    """A complete alert dict with all optional fields populated."""
    return {
        "id": 99999,
        "alert_type": "phishing",
        "status": "open",
        "severity": 3,
        "timestamp": "2025-07-05T12:00:00+00:00",
        "content_created_at": "2025-07-05T11:00:00+00:00",
        "last_modified": "2025-07-05T14:00:00+00:00",
        "rule_name": "Phishing Alert",
        "network": "twitter",
        "notes": "Suspicious activity detected.",
        "escalated": True,
        "tags": ["phishing", "credential_theft"],
        "offending_content_url": "https://evil.example.com/phish",
        "darkweb_term": "leaked credentials for target.com",
        "entity": {"id": 1001, "name": "Filigran Corp"},
        "perpetrator": {
            "name": "evil_actor",
            "display_name": "Evil Actor",
            "url": "https://x.com/evil_actor",
            "timestamp": "2025-07-01T08:00:00+00:00",
        },
        "metadata": {
            "justification": "phishing",
            "alert_reasons": [
                {"value": {"text_content": "URL matches known phishing pattern"}}
            ],
            "occurrences": [{"term": "evil.example.com"}, {"term": "phish.net"}],
            "content_raw_data": {"details": "Full phishing page detected"},
        },
        "logs": [
            {"action": "open", "timestamp": "2025-07-05T12:00:00+00:00"},
            {"action": "escalated", "timestamp": "2025-07-05T13:00:00+00:00"},
        ],
    }


@pytest.fixture
def full_alert(full_alert_data) -> ZerofoxAlert:
    """Parsed ZerofoxAlert model from full data."""
    return ZerofoxAlert.model_validate(full_alert_data)


@pytest.fixture
def minimal_alert(minimal_alert_data) -> ZerofoxAlert:
    """Parsed ZerofoxAlert model from minimal data."""
    return ZerofoxAlert.model_validate(minimal_alert_data)
