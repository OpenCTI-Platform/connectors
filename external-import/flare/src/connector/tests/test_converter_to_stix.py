import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
import stix2
from connector.converter_to_stix import FlareToStixMapper, Observable, str_to_ip_address
from connector.events import (
    LeakedCredentialEvent,
    LookalikeDomainEvent,
    RansomleakEvent,
    StealerLogEvent,
)
from pycti import Identity as PyctiIdentity

_APPROX_NOW = object()  # sentinel: assert result is approximately datetime.now(utc)

_BASE = dict(
    uid="uid-1",
    flare_url="https://flare.io/event/1",
    created_at="2025-01-01T00:00:00Z",
    matched_at="2025-01-01T00:00:00Z",
    severity="medium",
    notes="",
)

_STEALER_LOG_EVENT = {
    "data": {
        "uid": "uid-1",
        "index": "stealer_log",
        "metadata": {
            "flare_url": "https://flare.io/event/1",
            "estimated_created_at": "2025-01-01T00:00:00Z",
        },
        "features": {
            "emails": ["user@example.com"],
            "usernames": [],
            "ip_addresses": [],
        },
    },
    "metadata": {"matched_at": "2025-01-01T00:00:00Z"},
    "tenant_metadata": {"severity": "medium", "notes": ""},
}


@pytest.fixture
def mock_config() -> MagicMock:
    config = MagicMock()
    config.flare.tlp_level = "white"
    return config


@pytest.fixture
def author() -> stix2.Identity:
    return stix2.Identity(
        id=PyctiIdentity.generate_id("Flare", "organization"),
        name="Flare",
        identity_class="organization",
    )


@pytest.fixture
def mapper(mock_config: MagicMock, author: stix2.Identity) -> FlareToStixMapper:
    return FlareToStixMapper(mock_config, author)


@pytest.fixture
def incident() -> MagicMock:
    mock = MagicMock()
    mock.id = f"incident--{uuid.uuid4()}"
    return mock


def _observables(result: list[Observable]) -> list[Observable]:
    return [x for x in result if not isinstance(x, stix2.Relationship)]


class TestStrToIPAddress:
    def test_returns_ipv4_address(self) -> None:
        assert isinstance(str_to_ip_address("1.2.3.4"), stix2.IPv4Address)

    def test_returns_ipv6_address(self) -> None:
        assert isinstance(str_to_ip_address("2001:db8::1"), stix2.IPv6Address)

    def test_raises_value_error_on_invalid_input(self) -> None:
        with pytest.raises(ValueError):
            str_to_ip_address("not-an-ip")


class TestFlareToStixMapperInit:
    def test_raises_value_error_when_tlp_level_is_none(
        self, author: stix2.Identity
    ) -> None:
        config = MagicMock()
        config.flare.tlp_level = "invalid"
        with pytest.raises(ValueError, match="Invalid TLP level"):
            FlareToStixMapper(config, author)

    def test_successful_init(
        self, mapper: FlareToStixMapper, author: stix2.Identity
    ) -> None:
        assert mapper.tlp_level == stix2.TLP_WHITE
        assert mapper.author is author


class TestMapEventToIncident:
    def test_maps_event_successfully(
        self, mapper: FlareToStixMapper, author: stix2.Identity
    ) -> None:
        incident, related = mapper.map_event_to_incident(_STEALER_LOG_EVENT)

        assert isinstance(incident, stix2.Incident)
        assert incident.name == "Infected Device - uid-1"
        assert incident.created == datetime(2025, 1, 1, tzinfo=timezone.utc)
        assert incident.created_by_ref == author.id
        assert incident.description == ""
        assert incident["incident_type"] == "credential-compromise"
        assert incident["severity"] == "medium"
        assert incident["x_flare_event_id"] == "uid-1"
        assert incident["source"] == "Flare"
        assert stix2.TLP_WHITE.id in incident.object_marking_refs

        ext_ref = incident.external_references[0]
        assert ext_ref.source_name == "Flare"
        assert ext_ref.url == "https://flare.io/event/1"
        assert ext_ref.external_id == "uid-1"

        assert any(
            isinstance(r, stix2.EmailAddress) and r.value == "user@example.com"
            for r in related
        )
        assert any(isinstance(r, stix2.Relationship) for r in related)


class TestParseTimestamp:
    @pytest.mark.parametrize(
        "timestamp, expected",
        [
            pytest.param(
                "2025-01-01T00:00:00Z",
                datetime(2025, 1, 1, tzinfo=timezone.utc),
                id="string",
            ),
            pytest.param(
                datetime(2025, 1, 1, tzinfo=timezone.utc),
                datetime(2025, 1, 1, tzinfo=timezone.utc),
                id="datetime",
            ),
            pytest.param(None, _APPROX_NOW, id="none"),
            pytest.param("", _APPROX_NOW, id="invalid_datetime_string"),
        ],
    )
    def test_handles_datetime_and_str_input(
        self,
        timestamp: str | datetime | None,
        expected: datetime | object,
        mapper: FlareToStixMapper,
    ) -> None:
        result = mapper.parse_timestamp(timestamp)
        assert isinstance(result, datetime)
        if expected is _APPROX_NOW:
            assert abs((result - datetime.now(timezone.utc)).total_seconds()) < 2
        else:
            assert result == expected


class TestCreateIndicatorsFromEvent:
    @pytest.mark.parametrize(
        "event, expected_types",
        [
            pytest.param(
                StealerLogEvent(
                    **_BASE,
                    type="stealer_log",
                    emails=["user@example.com"],
                    usernames=[],
                    ip_addresses=[],
                    malware_family=None,
                ),
                [stix2.EmailAddress],
                id="emails",
            ),
            pytest.param(
                StealerLogEvent(
                    **_BASE,
                    type="stealer_log",
                    emails=[],
                    usernames=["jdoe"],
                    ip_addresses=[],
                    malware_family=None,
                ),
                [stix2.UserAccount],
                id="usernames",
            ),
            pytest.param(
                StealerLogEvent(
                    **_BASE,
                    type="stealer_log",
                    emails=[],
                    usernames=[],
                    ip_addresses=["1.2.3.4"],
                    malware_family=None,
                ),
                [stix2.IPv4Address],
                id="ip_addresses",
            ),
            pytest.param(
                StealerLogEvent(
                    **_BASE,
                    type="stealer_log",
                    emails=[],
                    usernames=[],
                    ip_addresses=[],
                    malware_family="Redline",
                ),
                [stix2.Malware],
                id="malware_family",
            ),
        ],
    )
    def test_stealer_log_events(
        self,
        event: StealerLogEvent,
        expected_types: list[type],
        mapper: FlareToStixMapper,
        incident: MagicMock,
    ) -> None:
        result = mapper.create_indicators_from_event(
            event, incident, datetime.now(timezone.utc)
        )
        assert [type(o) for o in _observables(result)] == expected_types

    @pytest.mark.parametrize(
        "event, expected_types",
        [
            pytest.param(
                LeakedCredentialEvent(
                    **_BASE, type="leaked_credential", username="", identity_name=""
                ),
                [],
                id="no_identity",
            ),
            pytest.param(
                LeakedCredentialEvent(
                    **_BASE,
                    type="leaked_credential",
                    username="user@example.com",
                    identity_name="",
                ),
                [stix2.EmailAddress],
                id="email_identity",
            ),
            pytest.param(
                LeakedCredentialEvent(
                    **_BASE, type="leaked_credential", username="jdoe", identity_name=""
                ),
                [stix2.UserAccount],
                id="username_identity",
            ),
            pytest.param(
                LeakedCredentialEvent(
                    **_BASE,
                    type="leaked_credential",
                    username="",
                    identity_name="fallback@example.com",
                ),
                [stix2.EmailAddress],
                id="identity_name_email_fallback",
            ),
            pytest.param(
                LeakedCredentialEvent(
                    **_BASE,
                    type="leaked_credential",
                    username="",
                    identity_name="fallback_user",
                ),
                [stix2.UserAccount],
                id="identity_name_username_fallback",
            ),
        ],
    )
    def test_leaked_credential_event(
        self,
        event: LeakedCredentialEvent,
        expected_types: list[type],
        mapper: FlareToStixMapper,
        incident: MagicMock,
    ) -> None:
        result = mapper.create_indicators_from_event(
            event, incident, datetime.now(timezone.utc)
        )
        assert [type(o) for o in _observables(result)] == expected_types

    @pytest.mark.parametrize(
        "event, expected_count",
        [
            pytest.param(
                LookalikeDomainEvent(
                    **_BASE,
                    type="domain",
                    original_domain="example.com",
                    lookalike_domain="",
                ),
                1,
                id="original_domain",
            ),
            pytest.param(
                LookalikeDomainEvent(
                    **_BASE,
                    type="domain",
                    original_domain="",
                    lookalike_domain="examp1e.com",
                ),
                1,
                id="lookalike_domain",
            ),
            pytest.param(
                LookalikeDomainEvent(
                    **_BASE, type="domain", original_domain="", lookalike_domain=""
                ),
                0,
                id="no_domain",
            ),
        ],
    )
    def test_lookalike_domain_event(
        self,
        event: LookalikeDomainEvent,
        expected_count: int,
        mapper: FlareToStixMapper,
        incident: MagicMock,
    ) -> None:
        obs = _observables(
            mapper.create_indicators_from_event(
                event, incident, datetime.now(timezone.utc)
            )
        )
        assert len(obs) == expected_count
        assert all(isinstance(o, stix2.DomainName) for o in obs)

    @pytest.mark.parametrize(
        "event, expected_count",
        [
            pytest.param(
                RansomleakEvent(
                    **_BASE,
                    type="ransomleak",
                    title="title",
                    url=None,
                    victim_name=None,
                ),
                0,
                id="no_url",
            ),
            pytest.param(
                RansomleakEvent(
                    **_BASE,
                    type="ransomleak",
                    title="title",
                    url="https://victim.com",
                    victim_name=None,
                ),
                1,
                id="with_url",
            ),
        ],
    )
    def test_ransomleak_event(
        self,
        event: RansomleakEvent,
        expected_count: int,
        mapper: FlareToStixMapper,
        incident: MagicMock,
    ) -> None:
        obs = _observables(
            mapper.create_indicators_from_event(
                event, incident, datetime.now(timezone.utc)
            )
        )
        assert len(obs) == expected_count


class TestRelationships:
    @pytest.mark.parametrize(
        "event",
        [
            pytest.param(
                StealerLogEvent(
                    **_BASE,
                    type="stealer_log",
                    emails=["user@example.com"],
                    usernames=["jdoe"],
                    ip_addresses=[],
                    malware_family=None,
                ),
                id="multiple_observables",
            ),
            pytest.param(
                LookalikeDomainEvent(
                    **_BASE,
                    type="domain",
                    original_domain="example.com",
                    lookalike_domain="examp1e.com",
                ),
                id="two_domains",
            ),
        ],
    )
    def test_one_relationship_per_observable(
        self,
        event: StealerLogEvent | LookalikeDomainEvent,
        mapper: FlareToStixMapper,
        incident: MagicMock,
    ) -> None:
        result = mapper.create_indicators_from_event(
            event, incident, datetime.now(timezone.utc)
        )
        observables = _observables(result)
        relationships = [r for r in result if isinstance(r, stix2.Relationship)]

        assert len(relationships) == len(observables)

    def test_relationship_properties(
        self, mapper: FlareToStixMapper, incident: MagicMock
    ) -> None:
        event = StealerLogEvent(
            **_BASE,
            type="stealer_log",
            emails=["user@example.com"],
            usernames=[],
            ip_addresses=[],
            malware_family=None,
        )
        result = mapper.create_indicators_from_event(
            event, incident, datetime.now(timezone.utc)
        )
        observable = _observables(result)[0]
        (rel,) = [r for r in result if isinstance(r, stix2.Relationship)]

        assert rel.relationship_type == "related-to"
        assert rel.source_ref == observable.id
        assert rel.target_ref == incident.id
        assert stix2.TLP_WHITE.id in rel.object_marking_refs
