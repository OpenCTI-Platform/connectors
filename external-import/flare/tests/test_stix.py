import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
import stix2
from pycti import Identity as PyctiIdentity

from connector.converter_to_stix import FlareToStixMapper
from connector.events import (
    LeakedCredentialEvent,
    LookalikeDomainEvent,
    RansomleakEvent,
    StealerLogEvent,
)

BASE_DIR = Path(__file__).parent / "test_events"


def _load_json(filename: str) -> dict[str, Any]:
    with (BASE_DIR / filename).open("r", encoding="utf-8") as f:
        data: dict[str, Any] = json.load(f)
        return data


def _make_config(tlp_level: str = "white") -> MagicMock:
    config = MagicMock()
    config.flare_tlp_level = tlp_level
    return config


def _make_mapper(tlp_level: str = "white") -> FlareToStixMapper:
    author = stix2.Identity(
        id=PyctiIdentity.generate_id("Flare", "organization"),
        name="Flare",
        identity_class="organization",
    )
    return FlareToStixMapper(config=_make_config(tlp_level), author_identity=author)


def _make_incident() -> MagicMock:
    incident = MagicMock()
    incident.id = f"incident--{uuid.uuid4()}"
    return incident


def _make_stealer_log(**kwargs: Any) -> StealerLogEvent:
    defaults: dict[str, Any] = {
        "uid": "test-uid",
        "type": "stealer_log",
        "flare_url": "https://app.flare.io/#/test",
        "created_at": "2025-01-01T00:00:00+00:00",
        "matched_at": "2025-01-02T00:00:00+00:00",
        "severity": "high",
        "notes": "",
        "emails": [],
        "usernames": [],
        "ip_addresses": [],
        "malware_family": None,
    }
    defaults.update(kwargs)
    return StealerLogEvent(**defaults)


def _make_leaked_credential(username: str) -> LeakedCredentialEvent:
    return LeakedCredentialEvent(
        uid="test",
        type="leak",
        flare_url="https://app.flare.io/#/test",
        created_at="2025-01-01T00:00:00+00:00",
        matched_at="2025-01-02T00:00:00+00:00",
        severity="medium",
        notes="",
        username=username,
    )


def _make_lookalike_domain(
    original_domain: str = "example.com",
    lookalike_domain: str = "examp1e.com",
) -> LookalikeDomainEvent:
    return LookalikeDomainEvent(
        uid="test",
        type="domain",
        flare_url="https://app.flare.io/#/test",
        created_at="2025-01-01T00:00:00+00:00",
        matched_at="2025-01-02T00:00:00+00:00",
        severity="low",
        notes="",
        original_domain=original_domain,
        lookalike_domain=lookalike_domain,
    )


def _make_ransomleak(url: str | None) -> RansomleakEvent:
    return RansomleakEvent(
        uid="test",
        type="ransomleak",
        flare_url="https://app.flare.io/#/test",
        created_at="2025-01-01T00:00:00+00:00",
        matched_at="2025-01-02T00:00:00+00:00",
        severity="critical",
        notes="",
        title="Test Ransomleak",
        url=url,
        victim_name="ACME Corp",
    )


CREATED_TIME = datetime(2025, 1, 1, tzinfo=timezone.utc)


class TestFlareToStixMapperInit:
    def test_valid_tlp_white(self) -> None:
        assert _make_mapper("white").tlp_level == stix2.TLP_WHITE

    def test_valid_tlp_green(self) -> None:
        assert _make_mapper("green").tlp_level == stix2.TLP_GREEN

    def test_valid_tlp_amber(self) -> None:
        assert _make_mapper("amber").tlp_level == stix2.TLP_AMBER

    def test_valid_tlp_red(self) -> None:
        assert _make_mapper("red").tlp_level == stix2.TLP_RED

    def test_valid_tlp_amber_strict(self) -> None:
        mapper = _make_mapper("amber+strict")
        assert mapper.tlp_level is not None

    def test_invalid_tlp_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid TLP level"):
            _make_mapper("purple")


class TestParseTimestamp:
    mapper: FlareToStixMapper

    def setup_method(self) -> None:
        self.mapper = _make_mapper()

    def test_datetime_passthrough(self) -> None:
        dt = datetime(2025, 1, 1, tzinfo=timezone.utc)
        assert self.mapper.parse_timestamp(dt) == dt

    def test_iso_string(self) -> None:
        result = self.mapper.parse_timestamp("2025-01-01T00:00:00+00:00")
        assert result == datetime(2025, 1, 1, tzinfo=timezone.utc)

    def test_iso_string_with_z_suffix(self) -> None:
        result = self.mapper.parse_timestamp("2025-01-01T00:00:00Z")
        assert result == datetime(2025, 1, 1, tzinfo=timezone.utc)

    def test_invalid_string_returns_utc_now(self) -> None:
        before = datetime.now(timezone.utc)
        result = self.mapper.parse_timestamp("not-a-date")
        after = datetime.now(timezone.utc)
        assert before <= result <= after

    def test_none_returns_utc_now(self) -> None:
        before = datetime.now(timezone.utc)
        result = self.mapper.parse_timestamp(None)
        after = datetime.now(timezone.utc)
        assert before <= result <= after


class TestMapEventToIncident:
    mapper: FlareToStixMapper

    def setup_method(self) -> None:
        self.mapper = _make_mapper()

    def _load_activity(self, filename: str) -> dict[str, Any]:
        activity: dict[str, Any] = _load_json(filename)["activity"]
        activity["metadata"]["matched_at"] = "2025-11-04T23:40:00+00:00"
        activity["tenant_metadata"] = {"severity": "high", "notes": "test note"}
        return activity

    def test_stealer_log_incident(self) -> None:
        incident, _ = self.mapper.map_event_to_incident(
            self._load_activity("stealer_log.json")
        )

        assert isinstance(incident, stix2.Incident)
        assert "Infected Device" in incident.name
        assert incident["incident_type"] == "credential-compromise"
        assert incident["source"] == "Flare"

    def test_leak_incident(self) -> None:
        incident, _ = self.mapper.map_event_to_incident(
            self._load_activity("leak.json")
        )

        assert isinstance(incident, stix2.Incident)
        assert "Leaked Credential" in incident.name
        assert incident["incident_type"] == "credential-compromise"

    def test_domain_incident(self) -> None:
        incident, _ = self.mapper.map_event_to_incident(
            self._load_activity("domain.json")
        )

        assert isinstance(incident, stix2.Incident)
        assert "Lookalike Domain" in incident.name
        assert incident["incident_type"] == "typosquatting"

    def test_document_incident(self) -> None:
        incident, _ = self.mapper.map_event_to_incident(
            self._load_activity("document.json")
        )

        assert isinstance(incident, stix2.Incident)
        assert "Ransomleak" in incident.name
        assert incident["incident_type"] == "ransomware"

    def test_incident_name_includes_uid(self) -> None:
        activity = self._load_activity("stealer_log.json")
        incident, _ = self.mapper.map_event_to_incident(activity)

        assert activity["data"]["uid"] in incident.name

    def test_incident_severity_stored(self) -> None:
        activity = self._load_activity("stealer_log.json")
        incident, _ = self.mapper.map_event_to_incident(activity)

        assert incident["severity"] == "high"

    def test_with_flare_url_has_external_reference(self) -> None:
        activity = self._load_activity("stealer_log.json")
        incident, _ = self.mapper.map_event_to_incident(activity)

        assert len(incident.external_references) == 1
        ref = incident.external_references[0]
        assert ref.source_name == "Flare"
        assert ref.description == "Link to event in Flare platform"

    def test_without_flare_url_has_no_external_reference(self) -> None:
        activity = self._load_activity("stealer_log.json")
        activity["data"]["metadata"]["flare_url"] = ""
        incident, _ = self.mapper.map_event_to_incident(activity)

        assert len(incident.get("external_references", [])) == 0

    def test_returns_observables_and_relations(self) -> None:
        activity = self._load_activity("stealer_log.json")
        _, indicators = self.mapper.map_event_to_incident(activity)

        assert len(indicators) > 0
        relations = [o for o in indicators if isinstance(o, stix2.Relationship)]
        assert len(relations) > 0


class TestCreateIndicatorsStealerLog:
    mapper: FlareToStixMapper
    incident: MagicMock

    def setup_method(self) -> None:
        self.mapper = _make_mapper()
        self.incident = _make_incident()

    def test_emails_create_email_address_observables(self) -> None:
        event = _make_stealer_log(emails=["user@example.com", "other@example.com"])
        result = self.mapper.create_indicators_from_event(
            event, self.incident, CREATED_TIME
        )

        email_obs = [o for o in result if isinstance(o, stix2.EmailAddress)]
        assert {o.value for o in email_obs} == {"user@example.com", "other@example.com"}

    def test_empty_email_strings_are_filtered(self) -> None:
        event = _make_stealer_log(emails=["user@example.com", ""])
        result = self.mapper.create_indicators_from_event(
            event, self.incident, CREATED_TIME
        )

        email_obs = [o for o in result if isinstance(o, stix2.EmailAddress)]
        assert len(email_obs) == 1

    def test_usernames_create_user_account_observables(self) -> None:
        event = _make_stealer_log(usernames=["alice", "bob"])
        result = self.mapper.create_indicators_from_event(
            event, self.incident, CREATED_TIME
        )

        user_obs = [o for o in result if isinstance(o, stix2.UserAccount)]
        assert {o.user_id for o in user_obs} == {"alice", "bob"}

    def test_ip_addresses_create_ipv4_observables(self) -> None:
        event = _make_stealer_log(ip_addresses=["1.2.3.4", "5.6.7.8"])
        result = self.mapper.create_indicators_from_event(
            event, self.incident, CREATED_TIME
        )

        ip_obs = [o for o in result if isinstance(o, stix2.IPv4Address)]
        assert len(ip_obs) == 2

    def test_empty_ip_strings_are_filtered(self) -> None:
        event = _make_stealer_log(ip_addresses=["1.2.3.4", ""])
        result = self.mapper.create_indicators_from_event(
            event, self.incident, CREATED_TIME
        )

        ip_obs = [o for o in result if isinstance(o, stix2.IPv4Address)]
        assert len(ip_obs) == 1

    def test_malware_family_creates_malware_observable(self) -> None:
        event = _make_stealer_log(malware_family="Badboi")
        result = self.mapper.create_indicators_from_event(
            event, self.incident, CREATED_TIME
        )

        malware_obs = [o for o in result if isinstance(o, stix2.Malware)]
        assert len(malware_obs) == 1
        assert malware_obs[0].name == "Badboi"
        assert malware_obs[0].is_family is True

    def test_no_malware_family_no_malware_observable(self) -> None:
        event = _make_stealer_log(malware_family=None)
        result = self.mapper.create_indicators_from_event(
            event, self.incident, CREATED_TIME
        )

        malware_obs = [o for o in result if isinstance(o, stix2.Malware)]
        assert len(malware_obs) == 0

    def test_all_empty_fields_returns_no_observables(self) -> None:
        event = _make_stealer_log()
        result = self.mapper.create_indicators_from_event(
            event, self.incident, CREATED_TIME
        )
        assert not result

    def test_each_observable_has_related_to_relationship(self) -> None:
        event = _make_stealer_log(
            emails=["user@example.com"],
            usernames=["bob"],
            ip_addresses=["1.2.3.4"],
            malware_family="Badboi",
        )
        result = self.mapper.create_indicators_from_event(
            event, self.incident, CREATED_TIME
        )

        non_relations = [o for o in result if not isinstance(o, stix2.Relationship)]
        relations = [o for o in result if isinstance(o, stix2.Relationship)]

        assert len(relations) == len(non_relations)
        for rel in relations:
            assert rel.relationship_type == "related-to"
            assert rel.target_ref == self.incident.id

    def test_relationship_uses_created_time(self) -> None:
        event = _make_stealer_log(emails=["user@example.com"])
        result = self.mapper.create_indicators_from_event(
            event, self.incident, CREATED_TIME
        )

        relations = [o for o in result if isinstance(o, stix2.Relationship)]
        assert relations[0].created == CREATED_TIME


class TestCreateIndicatorsLeakedCredential:
    mapper: FlareToStixMapper
    incident: MagicMock

    def setup_method(self) -> None:
        self.mapper = _make_mapper()
        self.incident = _make_incident()

    def test_email_username_creates_email_address(self) -> None:
        event = _make_leaked_credential("user@example.com")
        result = self.mapper.create_indicators_from_event(
            event, self.incident, CREATED_TIME
        )

        email_obs = [o for o in result if isinstance(o, stix2.EmailAddress)]
        assert len(email_obs) == 1
        assert email_obs[0].value == "user@example.com"

    def test_email_username_does_not_create_user_account(self) -> None:
        event = _make_leaked_credential("user@example.com")
        result = self.mapper.create_indicators_from_event(
            event, self.incident, CREATED_TIME
        )

        user_obs = [o for o in result if isinstance(o, stix2.UserAccount)]
        assert len(user_obs) == 0

    def test_non_email_username_creates_user_account(self) -> None:
        event = _make_leaked_credential("plainusername")
        result = self.mapper.create_indicators_from_event(
            event, self.incident, CREATED_TIME
        )

        user_obs = [o for o in result if isinstance(o, stix2.UserAccount)]
        assert len(user_obs) == 1
        assert user_obs[0].user_id == "plainusername"

    def test_non_email_username_does_not_create_email_address(self) -> None:
        event = _make_leaked_credential("plainusername")
        result = self.mapper.create_indicators_from_event(
            event, self.incident, CREATED_TIME
        )

        email_obs = [o for o in result if isinstance(o, stix2.EmailAddress)]
        assert len(email_obs) == 0

    def test_empty_username_creates_no_observables(self) -> None:
        event = _make_leaked_credential("")
        result = self.mapper.create_indicators_from_event(
            event, self.incident, CREATED_TIME
        )
        assert not result

    def test_observable_has_relationship_to_incident(self) -> None:
        event = _make_leaked_credential("user@example.com")
        result = self.mapper.create_indicators_from_event(
            event, self.incident, CREATED_TIME
        )

        relations = [o for o in result if isinstance(o, stix2.Relationship)]
        assert len(relations) == 1
        assert relations[0].target_ref == self.incident.id


class TestCreateIndicatorsLookalikeDomain:
    mapper: FlareToStixMapper
    incident: MagicMock

    def setup_method(self) -> None:
        self.mapper = _make_mapper()
        self.incident = _make_incident()

    def test_both_domains_create_two_observables(self) -> None:
        event = _make_lookalike_domain("example.com", "examp1e.com")
        result = self.mapper.create_indicators_from_event(
            event, self.incident, CREATED_TIME
        )

        domain_obs = [o for o in result if isinstance(o, stix2.DomainName)]
        assert len(domain_obs) == 2
        assert {o.value for o in domain_obs} == {"example.com", "examp1e.com"}

    def test_empty_original_domain_is_skipped(self) -> None:
        event = _make_lookalike_domain(
            original_domain="", lookalike_domain="examp1e.com"
        )
        result = self.mapper.create_indicators_from_event(
            event, self.incident, CREATED_TIME
        )

        domain_obs = [o for o in result if isinstance(o, stix2.DomainName)]
        assert len(domain_obs) == 1
        assert domain_obs[0].value == "examp1e.com"

    def test_empty_lookalike_domain_is_skipped(self) -> None:
        event = _make_lookalike_domain(
            original_domain="example.com", lookalike_domain=""
        )
        result = self.mapper.create_indicators_from_event(
            event, self.incident, CREATED_TIME
        )

        domain_obs = [o for o in result if isinstance(o, stix2.DomainName)]
        assert len(domain_obs) == 1
        assert domain_obs[0].value == "example.com"

    def test_both_empty_creates_no_observables(self) -> None:
        event = _make_lookalike_domain(original_domain="", lookalike_domain="")
        result = self.mapper.create_indicators_from_event(
            event, self.incident, CREATED_TIME
        )
        assert not result

    def test_each_domain_has_relationship(self) -> None:
        event = _make_lookalike_domain("example.com", "examp1e.com")
        result = self.mapper.create_indicators_from_event(
            event, self.incident, CREATED_TIME
        )

        relations = [o for o in result if isinstance(o, stix2.Relationship)]
        assert len(relations) == 2
        for rel in relations:
            assert rel.target_ref == self.incident.id


class TestCreateIndicatorsRansomleak:
    mapper: FlareToStixMapper
    incident: MagicMock

    def setup_method(self) -> None:
        self.mapper = _make_mapper()
        self.incident = _make_incident()

    def test_url_creates_url_observable(self) -> None:
        event = _make_ransomleak("http://ransomsite.onion/victims/acme")
        result = self.mapper.create_indicators_from_event(
            event, self.incident, CREATED_TIME
        )

        url_obs = [o for o in result if isinstance(o, stix2.URL)]
        assert len(url_obs) == 1
        assert url_obs[0].value == "http://ransomsite.onion/victims/acme"

    def test_none_url_creates_no_observables(self) -> None:
        event = _make_ransomleak(None)
        result = self.mapper.create_indicators_from_event(
            event, self.incident, CREATED_TIME
        )
        assert not result

    def test_url_has_relationship_to_incident(self) -> None:
        event = _make_ransomleak("http://ransomsite.onion/victims/acme")
        result = self.mapper.create_indicators_from_event(
            event, self.incident, CREATED_TIME
        )

        relations = [o for o in result if isinstance(o, stix2.Relationship)]
        assert len(relations) == 1
        assert relations[0].relationship_type == "related-to"
        assert relations[0].target_ref == self.incident.id
