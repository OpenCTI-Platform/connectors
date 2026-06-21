from typing import Any

import pytest
from connector.events import (
    EventTypes,
    LeakedCredentialEvent,
    LookalikeDomainEvent,
    RansomleakEvent,
    StealerLogEvent,
    get_event_from_event_json,
    get_event_title_from_event_type,
    get_incident_type_from_event_type,
)


def _make_event(index: str) -> dict[str, Any]:
    return {
        "data": {
            "uid": "uid-1",
            "index": index,
            "metadata": {"estimated_created_at": "2025-01-01T00:00:00Z"},
        },
        "metadata": {"matched_at": "2025-01-01T00:00:00Z"},
        "tenant_metadata": {},
    }


class TestGetIncidentFromEventType:
    def test_raises_value_error_on_invalid_event_type(self) -> None:
        with pytest.raises(ValueError, match="Unknown event_type"):
            get_incident_type_from_event_type("not_a_real_type")

    @pytest.mark.parametrize(
        "event_type, expected_result",
        [
            pytest.param(
                EventTypes.LEAKED_CREDENTIAL,
                "credential-compromise",
                id="leaked_credential",
            ),
            pytest.param(EventTypes.LEAK, "credential-compromise", id="leak"),
            pytest.param(
                EventTypes.STEALER_LOG, "credential-compromise", id="stealer_log"
            ),
            pytest.param(EventTypes.BOT, "credential-compromise", id="bot"),
            pytest.param(EventTypes.RANSOMLEAK, "ransomware", id="ransomleak"),
            pytest.param(EventTypes.DOCUMENT, "ransomware", id="document"),
            pytest.param(EventTypes.DOMAIN, "typosquatting", id="domain"),
            pytest.param(EventTypes.LOOKALIKE, "typosquatting", id="lookalike"),
            pytest.param(EventTypes.WHOIS, "other", id="whois"),
        ],
    )
    def test_returns_expected_event_type(
        self, event_type: str, expected_result: str
    ) -> None:
        assert get_incident_type_from_event_type(event_type) == expected_result


class TestGetEventTitleFromEventType:
    def test_raises_value_error_on_unknown_event_type(self) -> None:
        with pytest.raises(ValueError, match="Unknown event_type"):
            get_event_title_from_event_type("not_a_real_type")

    @pytest.mark.parametrize(
        "event_type", [pytest.param(et, id=et.value) for et in EventTypes]
    )
    def test_parses_event_titles(self, event_type: EventTypes) -> None:
        result = get_event_title_from_event_type(event_type)
        assert isinstance(result, str)
        assert len(result) > 0


class TestGetEventFromEventJSON:
    @pytest.mark.parametrize(
        "event, expected_type",
        [
            pytest.param(
                _make_event("leaked_credential"),
                LeakedCredentialEvent,
                id="leaked_credential",
            ),
            pytest.param(_make_event("leak"), LeakedCredentialEvent, id="leak"),
            pytest.param(_make_event("stealer_log"), StealerLogEvent, id="stealer_log"),
            pytest.param(_make_event("bot"), StealerLogEvent, id="bot"),
            pytest.param(_make_event("domain"), LookalikeDomainEvent, id="domain"),
            pytest.param(_make_event("ransomleak"), RansomleakEvent, id="ransomleak"),
            pytest.param(_make_event("document"), RansomleakEvent, id="document"),
        ],
    )
    def test_returns_expected_event_type(
        self, event: dict[str, Any], expected_type: type
    ) -> None:
        assert isinstance(get_event_from_event_json(event), expected_type)

    def test_raises_value_error_on_unknown_event_type(self) -> None:
        with pytest.raises(ValueError, match="Unsupported event type"):
            get_event_from_event_json(_make_event("not_a_real_type"))
