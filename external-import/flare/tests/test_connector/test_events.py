import json
from pathlib import Path
from typing import Any

import pytest
from connector.events import (
    LeakedCredentialEvent,
    LookalikeDomainEvent,
    RansomleakEvent,
    StealerLogEvent,
    get_event_from_event_json,
    get_event_title_from_event_type,
    get_incident_type_from_event_type,
)

BASE_DIR = Path(__file__).parent.parent / "test_events"


def _load_json(filename: str) -> dict[str, Any]:
    with (BASE_DIR / filename).open("r", encoding="utf-8") as f:
        return dict(json.load(f))


class TestGetEventFromEventJson:
    def test_stealer_log_from_event(self) -> None:
        activity = _load_json("stealer_log.json")["activity"]
        activity["metadata"]["matched_at"] = "2025-11-04T23:40:00+00:00"
        activity["tenant_metadata"] = {
            "severity": 3,
            "notes": "A note",
        }

        result = get_event_from_event_json(activity)
        assert isinstance(result, StealerLogEvent)

        assert result == StealerLogEvent(
            type="stealer_log",
            uid=activity["data"]["uid"],
            flare_url=activity["data"]["metadata"]["flare_url"],
            created_at=activity["data"]["metadata"]["estimated_created_at"],
            matched_at=activity["metadata"]["matched_at"],
            severity=activity["tenant_metadata"]["severity"],
            notes=activity["tenant_metadata"]["notes"],
            emails=["user@example.com"],
            usernames=["12345"],
            ip_addresses=["127.0.0.1"],
            malware_family="Badboi",
        )

    def test_ransomleak_from_event(self) -> None:
        activity = _load_json("document.json")["activity"]
        activity["metadata"]["matched_at"] = "2025-11-04T23:40:00+00:00"
        activity["tenant_metadata"] = {
            "severity": 3,
            "notes": "A note",
        }

        result = get_event_from_event_json(activity)
        assert isinstance(result, RansomleakEvent)

        assert result == RansomleakEvent(
            type="document",
            uid=activity["data"]["uid"],
            flare_url=activity["data"]["metadata"]["flare_url"],
            created_at=activity["data"]["metadata"]["estimated_created_at"],
            matched_at=activity["metadata"]["matched_at"],
            severity=activity["tenant_metadata"]["severity"],
            notes=activity["tenant_metadata"]["notes"],
            title=activity["data"]["docmeta"]["title"],
            url=activity["data"]["url"],
            victim_name=activity["data"]["victim_metadata"]["name"],
        )

    def test_lookalike_domain_from_event(self) -> None:
        activity = _load_json("domain.json")["activity"]
        activity["metadata"]["matched_at"] = "2025-11-04T23:40:00+00:00"
        activity["tenant_metadata"] = {
            "severity": 3,
            "notes": "A note",
        }

        result = get_event_from_event_json(activity)
        assert isinstance(result, LookalikeDomainEvent)

        assert result == LookalikeDomainEvent(
            type="domain",
            uid=activity["data"]["uid"],
            flare_url=activity["data"]["metadata"]["flare_url"],
            created_at=activity["data"]["metadata"]["estimated_created_at"],
            matched_at=activity["metadata"]["matched_at"],
            severity=activity["tenant_metadata"]["severity"],
            notes=activity["tenant_metadata"]["notes"],
            original_domain="example.com",
            lookalike_domain="examples.com",
        )

    def test_leaked_credentials_from_event(self) -> None:
        activity = _load_json("leak.json")["activity"]
        activity["metadata"]["matched_at"] = "2025-11-04T23:40:00+00:00"
        activity["tenant_metadata"] = {
            "severity": 3,
            "notes": "A note",
        }

        result = get_event_from_event_json(activity)
        assert isinstance(result, LeakedCredentialEvent)

        assert result == LeakedCredentialEvent(
            type="leak",
            uid=activity["data"]["uid"],
            flare_url=activity["data"]["metadata"]["flare_url"],
            created_at=activity["data"]["metadata"]["estimated_created_at"],
            matched_at=activity["metadata"]["matched_at"],
            severity=activity["tenant_metadata"]["severity"],
            notes=activity["tenant_metadata"]["notes"],
            username="example@example.com",
            identity_name="",
        )

    def test_bot_event_returns_stealer_log(self) -> None:
        activity: dict[str, Any] = {
            "data": {
                "uid": "x",
                "index": "bot",
                "metadata": {},
                "features": {},
                "malware_information": {},
            },
            "metadata": {"matched_at": "2025-01-01T00:00:00+00:00"},
            "tenant_metadata": {},
        }
        result = get_event_from_event_json(activity)
        assert isinstance(result, StealerLogEvent)

    def test_unsupported_event_type_raises(self) -> None:
        activity: dict[str, Any] = {
            "data": {
                "uid": "x",
                "index": "paste",
                "metadata": {},
                "features": {},
                "malware_information": {},
            },
            "metadata": {"matched_at": "2025-01-01T00:00:00+00:00"},
            "tenant_metadata": {},
        }
        with pytest.raises(ValueError, match="Unsupported event type"):
            get_event_from_event_json(activity)


class TestBaseEventFromEvent:
    def test_missing_data_dict(self) -> None:
        activity: dict[str, Any] = {
            "data": {"index": "bot"},
            "metadata": {"matched_at": "2025-01-01T00:00:00+00:00"},
            "tenant_metadata": {},
        }
        result = get_event_from_event_json(activity)
        assert result.uid == ""
        assert result.flare_url == ""
        assert result.created_at == ""

    def test_missing_nested_dicts(self) -> None:
        activity: dict[str, Any] = {
            "data": {"index": "bot"},
            "metadata": {},
            "tenant_metadata": {},
        }
        result = get_event_from_event_json(activity)
        assert result.matched_at == ""
        assert result.severity == ""
        assert result.notes == ""


class TestStealerLogFromEvent:
    def test_missing_features_dict(self) -> None:
        activity: dict[str, Any] = {
            "data": {"index": "stealer_log", "uid": "x", "metadata": {}},
            "metadata": {"matched_at": "2025-01-01T00:00:00+00:00"},
            "tenant_metadata": {},
        }
        result = get_event_from_event_json(activity)
        assert isinstance(result, StealerLogEvent)
        assert not result.emails
        assert not result.usernames
        assert not result.ip_addresses

    def test_missing_malware_information(self) -> None:
        activity: dict[str, Any] = {
            "data": {
                "index": "stealer_log",
                "uid": "x",
                "metadata": {},
                "features": {},
            },
            "metadata": {"matched_at": "2025-01-01T00:00:00+00:00"},
            "tenant_metadata": {},
        }
        result = get_event_from_event_json(activity)
        assert isinstance(result, StealerLogEvent)
        assert result.malware_family is None


class TestRansomleakFromEvent:
    def test_victim_metadata_none(self) -> None:
        activity: dict[str, Any] = {
            "data": {
                "index": "ransomleak",
                "uid": "x",
                "metadata": {},
                "url": "http://example.com",
            },
            "metadata": {"matched_at": "2025-01-01T00:00:00+00:00"},
            "tenant_metadata": {},
        }
        result = get_event_from_event_json(activity)
        assert isinstance(result, RansomleakEvent)
        assert result.victim_name is None

    def test_victim_name_falls_back_to_display_name(self) -> None:
        activity: dict[str, Any] = {
            "data": {
                "index": "ransomleak",
                "uid": "x",
                "metadata": {},
                "url": "http://example.com",
                "victim_metadata": {"name": None, "display_name": "Acme Corp"},
            },
            "metadata": {"matched_at": "2025-01-01T00:00:00+00:00"},
            "tenant_metadata": {},
        }
        result = get_event_from_event_json(activity)
        assert isinstance(result, RansomleakEvent)
        assert result.victim_name == "Acme Corp"

    def test_url_falls_back_to_response_url(self) -> None:
        activity: dict[str, Any] = {
            "data": {
                "index": "ransomleak",
                "uid": "x",
                "metadata": {},
                "url": None,
                "response_url": "http://response.example.com",
            },
            "metadata": {"matched_at": "2025-01-01T00:00:00+00:00"},
            "tenant_metadata": {},
        }
        result = get_event_from_event_json(activity)
        assert isinstance(result, RansomleakEvent)
        assert result.url == "http://response.example.com"

    def test_missing_docmeta(self) -> None:
        activity: dict[str, Any] = {
            "data": {
                "index": "ransomleak",
                "uid": "x",
                "metadata": {},
                "url": "http://example.com",
            },
            "metadata": {"matched_at": "2025-01-01T00:00:00+00:00"},
            "tenant_metadata": {},
        }
        result = get_event_from_event_json(activity)
        assert isinstance(result, RansomleakEvent)
        assert result.title == "N/A"


class TestLookalikeDomainFromEvent:
    def test_identifier_domain_empty_list(self) -> None:
        activity: dict[str, Any] = {
            "data": {
                "index": "domain",
                "uid": "x",
                "metadata": {},
                "identifier_domain": [],
                "name": "evil.com",
            },
            "metadata": {"matched_at": "2025-01-01T00:00:00+00:00"},
            "tenant_metadata": {},
        }
        result = get_event_from_event_json(activity)
        assert isinstance(result, LookalikeDomainEvent)
        assert result.original_domain == ""

    def test_identifier_domain_missing(self) -> None:
        activity: dict[str, Any] = {
            "data": {"index": "domain", "uid": "x", "metadata": {}, "name": "evil.com"},
            "metadata": {"matched_at": "2025-01-01T00:00:00+00:00"},
            "tenant_metadata": {},
        }
        result = get_event_from_event_json(activity)
        assert isinstance(result, LookalikeDomainEvent)
        assert result.original_domain == ""


class TestGetIncidentTypeFromEventType:
    def test_bot(self) -> None:
        assert get_incident_type_from_event_type("bot") == "credential-compromise"

    def test_leaked_credential(self) -> None:
        assert (
            get_incident_type_from_event_type("leaked_credential")
            == "credential-compromise"
        )

    def test_lookalike(self) -> None:
        assert get_incident_type_from_event_type("lookalike") == "typosquatting"

    def test_other_type_returns_other(self) -> None:
        assert get_incident_type_from_event_type("paste") == "other"

    def test_invalid_type_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown event_type"):
            get_incident_type_from_event_type("not_a_real_type")


class TestGetEventTitleFromEventType:
    def test_invalid_type_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown event_type"):
            get_event_title_from_event_type("not_a_real_type")

    def test_bot(self) -> None:
        assert get_event_title_from_event_type("bot") == "Infected Device"

    def test_ransomleak(self) -> None:
        assert get_event_title_from_event_type("ransomleak") == "Ransomleak"

    def test_lookalike(self) -> None:
        assert get_event_title_from_event_type("lookalike") == "Lookalike Domain"

